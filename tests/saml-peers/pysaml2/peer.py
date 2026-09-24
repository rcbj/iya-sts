#!/usr/local/bin/python3
# ===========================================================================
# PYSAML2 AS A SCRIPTED SAML 2.0 SERVICE PROVIDER (#190).
#
# pysaml2 (IdentityPython, Apache-2.0) is a complete SAML 2.0 implementation
# that can be scripted, which is what a browser SP cannot be: this small
# server is an SP built on its Saml2Client that the job drives over HTTP,
# and it sends exactly what the job asks for — every binding, signed or
# unsigned, ForceAuthn and IsPassive, a NameIDPolicy — and the NEGATIVE set
# the refusals in saml/ exist for: a bad signature, a wrong Destination, a
# stale IssueInstant, a replayed ID. What comes back is validated by
# pysaml2's own response parser (signatures, conditions, audience,
# InResponseTo, SubjectConfirmationData), and every verdict and every
# pysaml2 warning goes to its log — the harness's error-and-warning source.
#
#   GET  /health
#   POST /configure     {"idpMetadata": xml, "caPem": pem} — the identity
#                       provider this SP trusts, and the anchor for its SOAP
#                       back channel (artifact resolution)
#   GET  /metadata      this SP's metadata, from its own configuration
#   GET  /login         ?binding=redirect|post &response=post|artifact
#                       [&forceAuthn=1][&isPassive=1][&nameIdFormat=...]
#                       [&unsigned=1]
#                       [&fault=badsig|destination|stale|replay]
#                       — answers the redirect, or the POST form, a browser
#                       would get
#   POST /acs, GET /acs the assertion consumer service (HTTP-POST, and
#                       HTTP-Artifact resolved over SOAP)
#   GET  /last          what the last response came to, as JSON
#   GET  /reset         forget it
#   GET  /logout        SP-initiated Single Logout
#   GET|POST /slo       a LogoutRequest from the identity provider, or its
#                       LogoutResponse to ours
#
# Nothing here is a key: the SP's pair is made at start (entrypoint.sh).
# ===========================================================================
import base64
import datetime
import html
import json
import logging
import os
import re
import threading
import urllib.parse
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import saml2
from saml2 import (BINDING_HTTP_ARTIFACT, BINDING_HTTP_POST,
                   BINDING_HTTP_REDIRECT, BINDING_SOAP)
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.metadata import create_metadata_string
from saml2.saml import NameID

HOST = os.environ.get("SAML_PEER_HOST", "saml-pysaml2")
PORT = int(os.environ.get("SAML_PEER_PORT", "8000"))
BASE = "http://%s:%d" % (HOST, PORT)
STATE_DIR = "/var/lib/pysaml2-peer"
LOG_DIR = "/run/saml-peer-log"
ENTITY_ID = BASE + "/sp"
# Named on every call: pysaml2 7.5 signs a Redirect-binding query string with
# RSA-SHA1 unless told otherwise, which a service refusing SHA-1 refuses.
SIG_ALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
DIGEST_ALG = "http://www.w3.org/2001/04/xmlenc#sha256"

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "pysaml2.log"), level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("peer")

LOCK = threading.Lock()
STATE = {"client": None, "outstanding": {}, "last": None,
         "name_id": None, "last_request": None, "configured": False}


def sp_config(idp_metadata_path, ca_path):
    return {
        "entityid": ENTITY_ID,
        "xmlsec_binary": "/usr/bin/xmlsec1",
        "key_file": os.path.join(STATE_DIR, "sp.key"),
        "cert_file": os.path.join(STATE_DIR, "sp.crt"),
        "encryption_keypairs": [{
            "key_file": os.path.join(STATE_DIR, "sp.key"),
            "cert_file": os.path.join(STATE_DIR, "sp.crt")}],
        "metadata": {"local": [idp_metadata_path]} if idp_metadata_path
                    else {},
        "ca_certs": ca_path,
        "verify_ssl_cert": bool(ca_path),
        "signing_algorithm": SIG_ALG,
        "digest_algorithm": DIGEST_ALG,
        "accepted_time_diff": 60,
        "service": {"sp": {
            "endpoints": {
                "assertion_consumer_service": [
                    (BASE + "/acs", BINDING_HTTP_POST),
                    (BASE + "/acs", BINDING_HTTP_ARTIFACT)],
                "single_logout_service": [
                    (BASE + "/slo", BINDING_HTTP_REDIRECT),
                    (BASE + "/slo", BINDING_HTTP_POST)]},
            "authn_requests_signed": True,
            "logout_requests_signed": True,
            "logout_responses_signed": True,
            "want_assertions_signed": True,
            "want_response_signed": False,
            "allow_unsolicited": True,
            "name_id_format": [
                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"]}},
    }


def build_client(idp_metadata_path=None, ca_path=None):
    conf = SPConfig()
    conf.load(sp_config(idp_metadata_path, ca_path))
    return Saml2Client(config=conf)


def idp_entity(client):
    return list(client.metadata.identity_providers())[0]


def instant(delta_seconds=0):
    t = datetime.datetime.now(datetime.timezone.utc) + \
        datetime.timedelta(seconds=delta_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def redirect_with(client, xml, destination, relay_state, sign):
    info = client.apply_binding(BINDING_HTTP_REDIRECT, xml, destination,
                                relay_state, sign=sign, sigalg=SIG_ALG)
    return dict(info["headers"])["Location"]


def start_login(q):
    client = STATE["client"]
    idp = idp_entity(client)
    binding = BINDING_HTTP_POST if q.get("binding") == "post" \
        else BINDING_HTTP_REDIRECT
    response = BINDING_HTTP_ARTIFACT if q.get("response") == "artifact" \
        else BINDING_HTTP_POST
    fault = q.get("fault", "")
    sign = q.get("unsigned") != "1"
    kwargs = {}
    if q.get("forceAuthn") == "1":
        kwargs["force_authn"] = "true"
    if q.get("isPassive") == "1":
        kwargs["is_passive"] = "true"
    sso = client._sso_location(idp, binding)
    relay = "pysaml2-" + fault if fault else "pysaml2"

    if fault == "replay" and STATE["last_request"]:
        xml, destination = STATE["last_request"]
        log.info("sending a REPLAYED AuthnRequest (a request ID already "
                 "used)")
        return {"redirect": redirect_with(client, xml, destination, relay,
                                          True)}

    if fault or binding == BINDING_HTTP_REDIRECT:
        # Built unsigned, then signed on the query string by the Redirect
        # binding — so a fault can change what the signature covers.
        destination = "https://wrong.example.invalid/sso" \
            if fault == "destination" else sso
        reqid, request = client.create_authn_request(
            destination=destination, binding=response,
            nameid_format=q.get("nameIdFormat"), sign=False,
            sign_alg=SIG_ALG, digest_alg=DIGEST_ALG, **kwargs)
        if fault == "stale":
            request.issue_instant = instant(-3600)
        xml = str(request)
        STATE["outstanding"][reqid] = "/"
        STATE["last_request"] = (xml, sso)
        url = redirect_with(client, xml, sso, relay, sign)
        if fault == "badsig":
            parts = urllib.parse.urlsplit(url)
            params = urllib.parse.parse_qs(parts.query)
            tampered = xml.replace('Version="2.0"',
                                   'Version="2.0" ForceAuthn="true"', 1)
            deflate = zlib.compressobj(9, zlib.DEFLATED, -15)
            raw = deflate.compress(tampered.encode("utf-8")) + \
                deflate.flush()
            params["SAMLRequest"] = [base64.b64encode(raw).decode("ascii")]
            url = parts._replace(query=urllib.parse.urlencode(
                params, doseq=True)).geturl()
        log.info("AuthnRequest %s on HTTP-Redirect (fault=%s, signed=%s, "
                 "response=%s)", reqid, fault or "none", sign, response)
        return {"redirect": url}

    reqid, request = client.create_authn_request(
        destination=sso, binding=response,
        nameid_format=q.get("nameIdFormat"), sign=sign, sign_alg=SIG_ALG,
        digest_alg=DIGEST_ALG, **kwargs)
    xml = str(request)
    STATE["outstanding"][reqid] = "/"
    STATE["last_request"] = (xml, sso)
    info = client.apply_binding(BINDING_HTTP_POST, xml, sso, relay)
    log.info("AuthnRequest %s on HTTP-POST (signed=%s, response=%s)", reqid,
             sign, response)
    return {"form": info["data"]}


def outcome_of(resp, how):
    ava = resp.get_identity() if resp else {}
    subject = resp.get_subject() if resp else None
    session_index = None
    try:
        session_index = resp.assertion.authn_statement[0].session_index
    except Exception as e:  # no AuthnStatement: recorded as None
        log.info("no session index in the assertion: %s", e)
    STATE["name_id"] = subject
    return {"ok": True, "how": how,
            "issuer": resp.issuer() if resp else None,
            "inResponseTo": resp.in_response_to if resp else None,
            "nameId": subject.text if subject else None,
            "nameIdFormat": subject.format if subject else None,
            "sessionIndex": session_index,
            "encrypted": bool(resp and resp.response.encrypted_assertion),
            "attributes": ava}


def receive_response(saml_response, binding, how):
    client = STATE["client"]
    try:
        resp = client.parse_authn_request_response(
            saml_response, binding, outstanding=STATE["outstanding"])
        if resp is None:
            raise ValueError("pysaml2 returned no response")
        out = outcome_of(resp, how)
        log.info("Response accepted (%s): NameID %s from %s", how,
                 out["nameId"], out["issuer"])
    except Exception as e:  # the verdict IS the answer: recorded, not raised
        log.warning("Response REFUSED (%s): %s: %s", how,
                    type(e).__name__, e)
        out = {"ok": False, "how": how,
               "error": "%s: %s" % (type(e).__name__, e)}
    STATE["last"] = out
    return out


def receive_artifact(art):
    client = STATE["client"]
    try:
        soap = client.artifact2message(art, "idpsso", sign=True,
                                       sign_alg=SIG_ALG,
                                       digest_alg=DIGEST_ALG)
        # The ArtifactResponse itself is parsed (and its signature checked)
        # by pysaml2; the Response inside it is then handed over AS IT
        # ARRIVED — re-serializing pysaml2's object would change what the
        # Response's own signature covers.
        client.parse_artifact_resolve_response(soap.text)
        m = re.search(r"<([A-Za-z_][\w.-]*:)?Response\b[\s\S]*?"
                      r"</([A-Za-z_][\w.-]*:)?Response>", soap.text)
        if not m:
            raise ValueError("the ArtifactResponse carries no Response")
        return receive_response(
            base64.b64encode(m.group(0).encode("utf-8")).decode("ascii"),
            BINDING_HTTP_ARTIFACT, "artifact")
    except Exception as e:  # recorded as the verdict
        log.warning("artifact resolution FAILED: %s: %s",
                    type(e).__name__, e)
        STATE["last"] = {"ok": False, "how": "artifact",
                         "error": "%s: %s" % (type(e).__name__, e)}
        return STATE["last"]


class Handler(BaseHTTPRequestHandler):
    def answer(self, code, body, ctype="application/json", headers=None):
        data = body if isinstance(body, bytes) else \
            (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def query(self):
        q = urllib.parse.urlsplit(self.path).query
        return {k: v[0] for k, v in urllib.parse.parse_qs(q).items()}

    def form(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8")
        if self.headers.get("Content-Type", "").startswith(
                "application/json"):
            return json.loads(raw or "{}")
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def route(self):
        return urllib.parse.urlsplit(self.path).path

    def do_GET(self):
        with LOCK:
            self.get()

    def do_POST(self):
        with LOCK:
            self.post()

    def get(self):
        path, q = self.route(), self.query()
        if path == "/health":
            return self.answer(200, {"ok": True})
        if path == "/metadata":
            md = create_metadata_string(None, config=STATE["client"].config)
            md = md.decode("utf-8") if isinstance(md, bytes) else md
            return self.answer(200, md, "application/samlmetadata+xml")
        if path == "/last":
            return self.answer(200, STATE["last"] or {})
        if path == "/reset":
            STATE["last"] = None
            return self.answer(200, {"ok": True})
        if not STATE["configured"]:
            return self.answer(409, {"ok": False,
                                     "error": "not configured"})
        if path == "/login":
            STATE["last"] = None
            started = start_login(q)
            if "redirect" in started:
                return self.answer(302, "", "text/plain",
                                   {"Location": started["redirect"]})
            return self.answer(200, started["form"], "text/html")
        if path == "/acs" and q.get("SAMLart"):
            return self.answer(200, receive_artifact(q["SAMLart"]))
        if path == "/logout":
            client = STATE["client"]
            name_id = STATE["name_id"]
            if name_id is None:
                return self.answer(409, {"ok": False, "error": "no session"})
            result = client.global_logout(name_id, sign=True,
                                          sign_alg=SIG_ALG,
                                          digest_alg=DIGEST_ALG)
            for _idp, (binding, info) in result.items():
                if binding == BINDING_HTTP_REDIRECT:
                    loc = dict(info["headers"])["Location"]
                    return self.answer(302, "", "text/plain",
                                       {"Location": loc})
                return self.answer(200, info["data"], "text/html")
            return self.answer(500, {"ok": False, "error": "no SLO sent"})
        if path == "/slo":
            return self.slo(q, BINDING_HTTP_REDIRECT)
        return self.answer(404, {"ok": False})

    def post(self):
        path = self.route()
        if path == "/configure":
            spec = self.form()
            os.makedirs(STATE_DIR, exist_ok=True)
            md = os.path.join(STATE_DIR, "idp.xml")
            ca = os.path.join(STATE_DIR, "sts-ca.pem")
            with open(md, "w") as f:
                f.write(spec.get("idpMetadata", ""))
            with open(ca, "w") as f:
                f.write(spec.get("caPem", ""))
            try:
                STATE["client"] = build_client(md, ca)
                STATE["configured"] = True
                STATE["outstanding"] = {}
                STATE["name_id"] = None
                STATE["last_request"] = None
                idp = idp_entity(STATE["client"])
                log.info("configured for %s", idp)
                return self.answer(200, {"ok": True, "idp": idp,
                                         "entityId": ENTITY_ID})
            except Exception as e:  # the answer names it
                log.error("configure FAILED: %s: %s", type(e).__name__, e)
                return self.answer(400, {"ok": False, "error": str(e)})
        if path == "/acs":
            f = self.form()
            if f.get("SAMLart"):
                return self.answer(200, receive_artifact(f["SAMLart"]))
            return self.answer(200, receive_response(
                f.get("SAMLResponse", ""), BINDING_HTTP_POST, "post"))
        if path == "/slo":
            return self.slo(self.form(), BINDING_HTTP_POST)
        return self.answer(404, {"ok": False})

    def slo(self, p, binding):
        client = STATE["client"]
        try:
            if p.get("SAMLResponse"):
                resp = client.parse_logout_request_response(
                    p["SAMLResponse"], binding)
                ok = resp is not None and resp.status_ok()
                log.info("LogoutResponse received: %s",
                         "Success" if ok else "not Success")
                STATE["last"] = {"ok": ok, "how": "logout-response"}
                if ok:
                    STATE["name_id"] = None
                return self.answer(200, STATE["last"])
            info = client.handle_logout_request(
                p["SAMLRequest"], STATE["name_id"], binding, sign=True,
                sign_alg=SIG_ALG, digest_alg=DIGEST_ALG,
                relay_state=p.get("RelayState"), sigalg=p.get("SigAlg"),
                signature=p.get("Signature"))
            STATE["name_id"] = None
            STATE["last"] = {"ok": True, "how": "logout-request"}
            log.info("LogoutRequest from the identity provider handled")
            headers = dict(info.get("headers") or [])
            if "Location" in headers:
                return self.answer(302, "", "text/plain",
                                   {"Location": headers["Location"]})
            return self.answer(200, info.get("data", ""), "text/html")
        except Exception as e:  # recorded as the verdict
            log.warning("single logout FAILED: %s: %s", type(e).__name__, e)
            STATE["last"] = {"ok": False, "how": "slo",
                             "error": "%s: %s" % (type(e).__name__, e)}
            return self.answer(400, STATE["last"])

    def log_message(self, fmt, *args):
        logging.getLogger("http").info(fmt % args)


if __name__ == "__main__":
    STATE["client"] = build_client()
    log.info("pysaml2 %s peer on %s", getattr(saml2, "__version__", "?"),
             BASE)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
