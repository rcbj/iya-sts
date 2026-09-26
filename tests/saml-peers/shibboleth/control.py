#!/usr/bin/python3
# ===========================================================================
# THE SHIBBOLETH PEER'S CONTROL SERVER (#189).
#
# The job creates a throwaway realm, so the identity provider this SP has to
# trust does not exist when the container starts: its metadata (one document
# per profile, published for THIS service provider) and the service's TLS
# anchor arrive here, from the job, and shibd is restarted to read them.
#
#   GET  /health       200 once shibd answers its Status handler
#   POST /configure    {"files": {"idp-saml2.xml": ..., "idp-saml11.xml": ...,
#                      "sts-ca.pem": ...}} — written under
#                      /etc/shibboleth/peer, shibd restarted, and the answer
#                      given once it is up again (or why it is not)
#
# Listening on 9090 on the suite's private bridge only. It is a test
# instrument in a test container, and nothing in it is a secret: the files it
# takes are public metadata and a public certificate.
# ===========================================================================
import json
import os
import signal
import subprocess
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PEER_DIR = "/etc/shibboleth/peer"
ALLOWED = ("idp-saml2.xml", "idp-saml11.xml", "sts-ca.pem")
LOG_DIR = "/run/saml-peer-log"


def shibd_pids():
    out = subprocess.run(["pgrep", "-x", "shibd"], capture_output=True,
                         text=True)
    return [int(p) for p in out.stdout.split()]


def start_shibd():
    # -F: stay in the foreground (this process owns it); -f: clear a stale
    # socket a killed daemon left behind.
    with open(os.path.join(LOG_DIR, "shibd.stdout"), "ab") as out:
        subprocess.Popen(["/usr/sbin/shibd", "-F", "-f"], stdout=out,
                         stderr=subprocess.STDOUT, start_new_session=True)


def stop_shibd():
    for pid in shibd_pids():
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError as e:
            print("shibd %d had already gone: %s" % (pid, e), flush=True)
    deadline = time.time() + 20
    while shibd_pids() and time.time() < deadline:
        time.sleep(0.2)
    for pid in shibd_pids():
        os.kill(pid, signal.SIGKILL)


def status():
    try:
        with urllib.request.urlopen(
                "http://127.0.0.1/Shibboleth.sso/Status", timeout=5) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status == 200 and "<OK/>" in body, body[:2000]
    except Exception as e:  # the daemon is not up yet: say so, and retry
        return False, "%s" % e


def wait_up(seconds):
    deadline = time.time() + seconds
    last = ""
    while time.time() < deadline:
        ok, last = status()
        if ok:
            return True, last
        time.sleep(0.5)
    return False, last


class Handler(BaseHTTPRequestHandler):
    def answer(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            ok, detail = status()
            self.answer(200 if ok else 503, {"ok": ok, "status": detail})
            return
        self.answer(404, {"ok": False, "error": "no such path"})

    def do_POST(self):
        if self.path != "/configure":
            self.answer(404, {"ok": False, "error": "no such path"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            spec = json.loads(self.rfile.read(length) or b"{}")
        except ValueError as e:
            self.answer(400, {"ok": False, "error": "not JSON: %s" % e})
            return
        files = spec.get("files") or {}
        unknown = [n for n in files if n not in ALLOWED]
        if unknown:
            self.answer(400, {"ok": False,
                              "error": "unknown file(s) %s" % unknown})
            return
        for name, text in files.items():
            with open(os.path.join(PEER_DIR, name), "w") as f:
                f.write(text)
        stop_shibd()
        start_shibd()
        ok, detail = wait_up(60)
        self.answer(200 if ok else 500, {"ok": ok, "status": detail})

    def log_message(self, fmt, *args):
        print("control: " + (fmt % args), flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9090), Handler).serve_forever()
