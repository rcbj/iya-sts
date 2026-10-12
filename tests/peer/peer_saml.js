// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: tests/peer/peer_saml.js
//
// ===========================================================================
// THE TEST PEER'S THREE BROWSER-PROFILE ROLES (#586): a SAML 2.0 service
// provider (Web Browser SSO on HTTP-POST and HTTP-Artifact), a SAML 1.1
// relying party (Browser/POST and Browser/Artifact) and a WS-Federation 1.2
// passive relying party. They replace `/saml2/sp`, `/saml11/rp` and
// `/wsfed/rp`, the service's own mocks, development only from #585 and
// deleted by #592.
//
// **AN OUTSIDE PARTY, NOT A FRIEND OF THE SERVICE.** What the peer believes
// about the identity provider it reads from the identity provider's own
// PUBLISHED METADATA, over a TLS connection it verifies — the signing
// certificates, nothing else — and it is believed in return only because a
// job registered it as an application, with its entityID, its return
// address and its own signing certificate. `/saml2/sp`'s entityID was
// trusted implicitly (`saml2_sso.ts`, until #592); this one never was.
//
// **EVERY SIGNATURE IS VERIFIED THROUGH THE ATTRIBUTE THE PROFILE NAMES**
// (`ID` for SAML 2.0, `ResponseID` and `AssertionID` for SAML 1.1), and the
// one reference must point at the element the signature sits in — so a
// wrapped document, or a signer that let xml-crypto invent `Id="_0"`, is
// refused rather than believed (`sts_saml11.js` argues the second at
// length).
//
// What each consumer accepted, or refused and why, is RECORDED on the tenant
// for the job to read back (`peer.js`); the browser gets the same verdict
// as JSON.
// ===========================================================================

const nodeCrypto = require("crypto");
const zlib = require("zlib");
const { SignedXml } = require("xml-crypto");
const util = require("./peer_util.js");

const log = util.logger("peer_saml");

const NS_SAMLP2 = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_SAML2 = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_SAMLP1 = "urn:oasis:names:tc:SAML:1.0:protocol";
const NS_SAML1 = "urn:oasis:names:tc:SAML:1.0:assertion";
const NS_SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/";
const BINDING = {
  post: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
  artifact: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
};
const CM_BEARER1 = "urn:oasis:names:tc:SAML:1.0:cm:bearer";
const CM_ARTIFACT1 = "urn:oasis:names:tc:SAML:1.0:cm:artifact";
const SIG_ALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
// How far apart two containers' clocks may be before a condition fails.
const SKEW_MS = 120000;

function samlId() {
  log.debug("Entering samlId().");
  log.debug("Leaving samlId().");
  return "_" + nodeCrypto.randomBytes(16).toString("hex");
}

function escapeXml(text) {
  log.debug("Entering escapeXml().");
  log.debug("Leaving escapeXml().");
  return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ---------------------------------------------------------------------------
// THE IDENTITY PROVIDER'S CERTIFICATES, from its published metadata, per
// tenant and per document. Fetched again once when nothing verifies, which
// is what a relying party does when a key rolls.
// ---------------------------------------------------------------------------
const METADATA_PATH = {
  saml2: "/saml2/metadata",
  saml11: "/saml11/metadata",
  wsfed: "/FederationMetadata/2007-06/FederationMetadata.xml"
};

async function certificatesOf(tenant, kind, fresh) {
  log.debug("Entering certificatesOf(). " + kind);
  tenant.metadataCache = tenant.metadataCache || {};
  if (!fresh && tenant.metadataCache[kind]) {
    log.debug("Leaving certificatesOf(). Cached.");
    return tenant.metadataCache[kind];
  }
  const url = tenant.realmBase + METADATA_PATH[kind];
  const r = await util.outbound("GET", url, { ca: tenant.serviceCaPem });
  if (r.status !== 200) {
    log.debug("Leaving certificatesOf(). " + r.status);
    throw new Error("the identity provider's metadata at " + url +
                    " answered " + r.status);
  }
  const certs = util.certificatesIn(r.text);
  if (!certs.length) {
    log.debug("Leaving certificatesOf(). None.");
    throw new Error("the metadata at " + url + " publishes no certificate");
  }
  tenant.metadataCache[kind] = certs;
  log.debug("Leaving certificatesOf(). " + certs.length);
  return certs;
}

// ---------------------------------------------------------------------------
// ONE ENVELOPED SIGNATURE, ON ONE ELEMENT, THROUGH ITS ID ATTRIBUTE.
// `{ present, ok, why }`. xml-crypto is told the attribute only when it is
// not SAML 2.0's `ID`, which is already on its default list — naming it again
// would add a duplicate and trip the library's wrapping guard on a healthy
// document.
// ---------------------------------------------------------------------------
function verifyWith(xml, element, idAttribute, certs) {
  log.debug("Entering verifyWith(). " + element.localName);
  const sigEl = util.childByLocal(element, "Signature");
  if (!sigEl) {
    log.debug("Leaving verifyWith(). Unsigned.");
    return { present: false, ok: false,
             why: "the " + element.localName + " carries no ds:Signature" };
  }
  const id = element.getAttribute(idAttribute);
  let why = "no certificate in the metadata verifies it";
  for (const cert of certs) {
    try {
      const options = { publicCert: cert };
      if (idAttribute !== "ID") {
        options.idAttribute = idAttribute;
      }
      const sig = new SignedXml(options);
      sig.loadSignature(sigEl);
      const ok = sig.checkSignature(xml);
      const refs = sig.getReferences();
      if (ok && refs.length === 1 && refs[0].uri === "#" + id) {
        log.debug("Leaving verifyWith(). Verified.");
        return { present: true, ok: true, why: "" };
      }
      why = ok ? "the signature's reference (" +
                 refs.map(function (one) {
                   return one.uri;
                 }).join(", ") + ") is not the " + element.localName +
                 "'s own " + idAttribute + " (#" + id + ")"
               : "the signature did not verify";
    } catch (e) {
      log.debug("Caught in verifyWith(): " + ((e && e.message) || e));
      // xml-crypto throws for most failures, and its message — an
      // unresolvable reference, a digest mismatch — is the diagnosis.
      why = e.message;
    }
  }
  log.debug("Leaving verifyWith(). " + why);
  return { present: true, ok: false, why: why };
}

// The same, against the metadata's certificates, re-reading the metadata
// once when nothing it held verified.
async function verifyAgainstMetadata(tenant, kind, xml, element, idAttribute) {
  log.debug("Entering verifyAgainstMetadata(). " + kind);
  let verdict = verifyWith(xml, element, idAttribute,
                           await certificatesOf(tenant, kind, false));
  if (verdict.present && !verdict.ok) {
    verdict = verifyWith(xml, element, idAttribute,
                         await certificatesOf(tenant, kind, true));
  }
  log.debug("Leaving verifyAgainstMetadata(). ok=" + verdict.ok);
  return verdict;
}

// An enveloped signature by this tenant's own key, placed where the schema
// wants it: after Issuer in SAML 2.0, first in a SAML 1.1 Request.
function signEnveloped(tenant, xml, rootLocalName, idAttribute, after) {
  log.debug("Entering signEnveloped(). " + rootLocalName);
  const where = "//*[local-name(.)='" + rootLocalName + "']";
  const sig = new SignedXml({
    privateKey: tenant.signing.privateKeyPem, idAttribute: idAttribute,
    canonicalizationAlgorithm: EXC_C14N, signatureAlgorithm: SIG_ALG
  });
  sig.addReference({
    xpath: where,
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                 EXC_C14N],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256"
  });
  const location = after
    ? { reference: where + "/*[local-name(.)='" + after + "']",
        action: "after" }
    : { reference: where, action: "prepend" };
  sig.computeSignature(xml, { location: location });
  log.debug("Leaving signEnveloped().");
  return sig.getSignedXml();
}

function soap(inner) {
  log.debug("Entering soap().");
  log.debug("Leaving soap().");
  return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
    "<soap:Envelope xmlns:soap=\"" + NS_SOAP11 + "\"><soap:Body>" + inner +
    "</soap:Body></soap:Envelope>";
}

// A condition's time window, with the skew two containers' clocks are
// allowed. `''` when it holds, else what is wrong.
function windowProblem(notBefore, notOnOrAfter, what) {
  log.debug("Entering windowProblem(). " + what);
  const now = Date.now();
  if (notBefore && Date.parse(notBefore) - SKEW_MS > now) {
    log.debug("Leaving windowProblem(). Early.");
    return what + " is not valid before " + notBefore;
  }
  if (notOnOrAfter && Date.parse(notOnOrAfter) + SKEW_MS <= now) {
    log.debug("Leaving windowProblem(). Late.");
    return what + " expired at " + notOnOrAfter;
  }
  log.debug("Leaving windowProblem().");
  return "";
}

// ===========================================================================
// SAML 2.0 — THE SERVICE PROVIDER.
// ===========================================================================

// GET /t/{tenant}/saml2/login?binding=post|artifact&relay=… — the
// SP-initiated start: an AuthnRequest on the HTTP-Redirect binding, signed
// over the query string (saml-bindings-2.0 section 3.4.4.1), asking for the
// Response on the binding named.
function saml2Login(tenant, query) {
  log.debug("Entering saml2Login().");
  const binding = query.get("binding") === "artifact" ? "artifact" : "post";
  const id = samlId();
  const destination = tenant.realmBase + "/saml2/sso";
  const xml = "<samlp:AuthnRequest xmlns:samlp=\"" + NS_SAMLP2 + "\" " +
    "xmlns:saml=\"" + NS_SAML2 + "\" ID=\"" + id + "\" Version=\"2.0\" " +
    "IssueInstant=\"" + new Date().toISOString() + "\" Destination=\"" +
    escapeXml(destination) + "\" AssertionConsumerServiceURL=\"" +
    escapeXml(tenant.urls.saml2Acs) + "\" ProtocolBinding=\"" +
    BINDING[binding] + "\"><saml:Issuer>" + escapeXml(tenant.saml.entityId) +
    "</saml:Issuer></samlp:AuthnRequest>";
  tenant.pending.set(id, { binding: binding, at: Date.now() });
  let q = "SAMLRequest=" + encodeURIComponent(
    zlib.deflateRawSync(Buffer.from(xml, "utf8")).toString("base64"));
  const relay = query.get("relay");
  if (relay) {
    q += "&RelayState=" + encodeURIComponent(relay);
  }
  q += "&SigAlg=" + encodeURIComponent(SIG_ALG);
  const signature = nodeCrypto.sign("RSA-SHA256", Buffer.from(q, "utf8"),
                                    tenant.signing.privateKeyPem);
  q += "&Signature=" + encodeURIComponent(signature.toString("base64"));
  tenant.record("saml2", { ok: true, event: "authn-request", id: id,
                           binding: binding });
  log.debug("Leaving saml2Login().");
  return { status: 302, location: destination + "?" + q, id: id };
}

// What a SAML 2.0 Response says, once its signatures have been judged.
// `{ ok, problems[], … }` — every problem is listed rather than the first.
async function judgeSaml2Response(tenant, xml, binding) {
  log.debug("Entering judgeSaml2Response(). " + binding);
  const doc = util.parseXml(xml);
  const response = doc.documentElement;
  const out = { binding: binding, problems: [] };
  if (!response || response.localName !== "Response" ||
      response.namespaceURI !== NS_SAMLP2) {
    out.problems.push("the message is not a SAML 2.0 samlp:Response");
    log.debug("Leaving judgeSaml2Response(). Not a Response.");
    return out;
  }
  const status = util.firstByLocal(response, "StatusCode");
  out.status = status ? status.getAttribute("Value") : "";
  out.inResponseTo = response.getAttribute("InResponseTo") || null;
  out.destination = response.getAttribute("Destination") || null;
  out.issuer = util.textOf(util.childByLocal(response, "Issuer"));
  if (!/:Success$/.test(out.status)) {
    out.problems.push("the status is " + out.status);
  }
  if (out.destination && out.destination !== tenant.urls.saml2Acs) {
    out.problems.push("Destination is " + out.destination + ", not this " +
                      "assertion consumer service");
  }
  if (out.inResponseTo) {
    const pending = tenant.pending.get(out.inResponseTo);
    out.solicited = !!pending;
    if (!pending) {
      out.problems.push("InResponseTo names " + out.inResponseTo +
                        ", which is no request this provider sent, or " +
                        "one already answered");
    }
  } else {
    out.solicited = false;
  }
  const responseSig = await verifyAgainstMetadata(tenant, "saml2", xml,
                                                  response, "ID");
  out.responseSigned = responseSig.present;
  out.responseSignatureValid = responseSig.ok;
  if (responseSig.present && !responseSig.ok) {
    out.problems.push("the Response's signature: " + responseSig.why);
  }
  const assertion = util.childByLocal(response, "Assertion");
  if (!assertion) {
    out.problems.push(util.childByLocal(response, "EncryptedAssertion")
      ? "the assertion is encrypted, and this provider registered no " +
        "encryption certificate"
      : "the Response carries no Assertion");
    log.debug("Leaving judgeSaml2Response(). No assertion.");
    return out;
  }
  const assertionSig = await verifyAgainstMetadata(tenant, "saml2", xml,
                                                   assertion, "ID");
  out.assertionSigned = assertionSig.present;
  out.assertionSignatureValid = assertionSig.ok;
  if (assertionSig.present && !assertionSig.ok) {
    out.problems.push("the Assertion's signature: " + assertionSig.why);
  }
  if (!responseSig.ok && !assertionSig.ok) {
    out.problems.push("neither the Response nor the Assertion carries a " +
                      "signature that verifies");
  }
  out.assertionIssuer = util.textOf(util.childByLocal(assertion, "Issuer"));
  const subject = util.childByLocal(assertion, "Subject");
  const nameId = util.childByLocal(subject, "NameID");
  out.nameId = util.textOf(nameId);
  out.nameIdFormat = nameId ? nameId.getAttribute("Format") || null : null;
  const conditions = util.childByLocal(assertion, "Conditions");
  if (conditions) {
    const late = windowProblem(conditions.getAttribute("NotBefore"),
                               conditions.getAttribute("NotOnOrAfter"),
                               "the assertion");
    if (late) {
      out.problems.push(late);
    }
  }
  out.audiences = util.allByLocal(conditions, "Audience").map(util.textOf);
  if (out.audiences.indexOf(tenant.saml.entityId) < 0) {
    out.problems.push("the assertion's audience (" +
                      out.audiences.join(", ") + ") does not name this " +
                      "provider, " + tenant.saml.entityId);
  }
  const confirmation = util.firstByLocal(subject, "SubjectConfirmation");
  const data = util.firstByLocal(confirmation, "SubjectConfirmationData");
  out.confirmationMethod = confirmation
    ? confirmation.getAttribute("Method") : null;
  out.recipient = data ? data.getAttribute("Recipient") : null;
  if (out.recipient !== tenant.urls.saml2Acs) {
    out.problems.push("the bearer confirmation's Recipient is " +
                      out.recipient + ", not this assertion consumer " +
                      "service");
  }
  if (data && data.getAttribute("InResponseTo") !== out.inResponseTo &&
      (data.getAttribute("InResponseTo") || out.inResponseTo)) {
    out.problems.push("the confirmation's InResponseTo (" +
                      data.getAttribute("InResponseTo") + ") is not the " +
                      "Response's (" + out.inResponseTo + ")");
  }
  out.attributes = {};
  util.allByLocal(assertion, "Attribute").forEach(function (attribute) {
    out.attributes[attribute.getAttribute("Name")] =
      util.allByLocal(attribute, "AttributeValue").map(util.textOf);
  });
  const authn = util.firstByLocal(assertion, "AuthnContextClassRef");
  out.authnContextClassRef = authn ? util.textOf(authn) : null;
  log.debug("Leaving judgeSaml2Response(). " + out.problems.length +
            " problem(s).");
  return out;
}

// POST /t/{tenant}/saml2/acs (HTTP-POST) and GET …?SAMLart= (HTTP-Artifact).
async function saml2Acs(tenant, method, query, form) {
  log.debug("Entering saml2Acs(). " + method);
  let judged;
  let relay = null;
  if (method === "GET" && query.get("SAMLart")) {
    relay = query.get("RelayState");
    const xml = await resolveSaml2Artifact(tenant, query.get("SAMLart"));
    judged = await judgeSaml2Response(tenant, xml.response, "artifact");
    judged.artifactResponseSigned = xml.signed;
  } else if (method === "POST" && form.SAMLResponse) {
    relay = form.RelayState || null;
    const xml = Buffer.from(form.SAMLResponse, "base64").toString("utf8");
    judged = await judgeSaml2Response(tenant, xml, "post");
  } else {
    log.debug("Leaving saml2Acs(). Nothing to consume.");
    return { status: 400, body: { ok: false, error: "the assertion " +
      "consumer service takes a SAMLResponse (POST) or a SAMLart (GET)" } };
  }
  judged.relayState = relay;
  judged.ok = judged.problems.length === 0;
  // A request is ANSWERED once, by the first Response this provider
  // accepts; a refused one leaves it open, as a forged answer must not be
  // able to use up somebody's sign-in.
  if (judged.ok && judged.inResponseTo) {
    tenant.pending.delete(judged.inResponseTo);
  }
  tenant.record("saml2", Object.assign({ event: "response" }, judged));
  log.debug("Leaving saml2Acs(). ok=" + judged.ok);
  return { status: judged.ok ? 200 : 400, body: judged };
}

// The artifact, resolved at the realm's artifact resolution service over
// SOAP, with an ArtifactResolve signed by this tenant's key — which is what
// the service checks it against (the registered samlSigningCertificate).
async function resolveSaml2Artifact(tenant, artifact) {
  log.debug("Entering resolveSaml2Artifact().");
  const ars = tenant.realmBase + "/saml2/ars/" +
              encodeURIComponent(tenant.saml.entityId);
  const resolve = signEnveloped(tenant,
    "<samlp:ArtifactResolve xmlns:samlp=\"" + NS_SAMLP2 + "\" " +
    "xmlns:saml=\"" + NS_SAML2 + "\" ID=\"" + samlId() + "\" " +
    "Version=\"2.0\" IssueInstant=\"" + new Date().toISOString() + "\" " +
    "Destination=\"" + escapeXml(ars) + "\"><saml:Issuer>" +
    escapeXml(tenant.saml.entityId) + "</saml:Issuer><samlp:Artifact>" +
    escapeXml(artifact) + "</samlp:Artifact></samlp:ArtifactResolve>",
    "ArtifactResolve", "ID", "Issuer");
  const r = await util.outbound("POST", ars, {
    ca: tenant.serviceCaPem, body: soap(resolve),
    headers: { "Content-Type": "text/xml; charset=utf-8",
               SOAPAction: "\"\"" } });
  const doc = util.parseXml(r.text);
  const answer = util.firstByLocal(doc.documentElement, "ArtifactResponse");
  const inner = answer ? util.childByLocal(answer, "Response") : null;
  if (r.status !== 200 || !inner) {
    log.debug("Leaving resolveSaml2Artifact(). " + r.status);
    throw new Error("artifact resolution at " + ars + " answered " +
                    r.status + " with no Response: " + r.text.slice(0, 400));
  }
  const { XMLSerializer } = require("@xmldom/xmldom");
  log.debug("Leaving resolveSaml2Artifact().");
  return { response: new XMLSerializer().serializeToString(inner),
           signed: !!util.childByLocal(answer, "Signature") };
}

// ===========================================================================
// SAML 1.1 — THE RELYING PARTY.
// ===========================================================================
async function judgeSaml11Response(tenant, xml, profile, requestId) {
  log.debug("Entering judgeSaml11Response(). " + profile);
  const doc = util.parseXml(xml);
  const response = profile === "artifact"
    ? util.firstByLocal(doc.documentElement, "Response")
    : doc.documentElement;
  const out = { profile: profile, problems: [] };
  if (!response || response.localName !== "Response" ||
      response.namespaceURI !== NS_SAMLP1) {
    out.problems.push("the message is not a SAML 1.x samlp:Response");
    log.debug("Leaving judgeSaml11Response(). Not a Response.");
    return out;
  }
  const status = util.firstByLocal(response, "StatusCode");
  out.status = status ? status.getAttribute("Value") : "";
  if (!/Success$/.test(out.status)) {
    out.problems.push("the status is " + out.status);
  }
  out.inResponseTo = response.getAttribute("InResponseTo") || null;
  out.recipient = response.getAttribute("Recipient") || null;
  if (profile === "post") {
    // saml-profile-1.1 4.2: there was no request, so nothing to respond to.
    if (out.inResponseTo) {
      out.problems.push("a Browser/POST Response carries InResponseTo (" +
                        out.inResponseTo + "), naming a request nobody " +
                        "sent");
    }
    if (out.recipient !== tenant.urls.saml11Acs) {
      out.problems.push("Recipient is " + out.recipient + ", not this " +
                        "assertion consumer service");
    }
  } else if (out.inResponseTo !== requestId) {
    out.problems.push("the responder's InResponseTo (" + out.inResponseTo +
                      ") is not this relying party's RequestID (" +
                      requestId + ")");
  }
  const responseSig = await verifyAgainstMetadata(tenant, "saml11", xml,
                                                  response, "ResponseID");
  out.responseSigned = responseSig.present;
  out.responseSignatureValid = responseSig.ok;
  if (responseSig.present && !responseSig.ok) {
    out.problems.push("the Response's signature: " + responseSig.why);
  }
  const assertion = util.childByLocal(response, "Assertion");
  if (!assertion || assertion.namespaceURI !== NS_SAML1) {
    out.problems.push("the Response carries no SAML 1.x Assertion");
    log.debug("Leaving judgeSaml11Response(). No assertion.");
    return out;
  }
  const assertionSig = await verifyAgainstMetadata(tenant, "saml11", xml,
                                                   assertion, "AssertionID");
  out.assertionSigned = assertionSig.present;
  out.assertionSignatureValid = assertionSig.ok;
  if (assertionSig.present && !assertionSig.ok) {
    out.problems.push("the Assertion's signature: " + assertionSig.why);
  }
  // Browser/POST is protected by the signature alone (section 4.2.1);
  // Browser/Artifact's assertion arrives over an authenticated back channel,
  // and its signature is a courtesy when present.
  if (profile === "post" && !responseSig.ok && !assertionSig.ok) {
    out.problems.push("neither the Response nor the Assertion carries a " +
                      "signature that verifies");
  }
  out.issuer = assertion.getAttribute("Issuer");
  const conditions = util.childByLocal(assertion, "Conditions");
  if (conditions) {
    const late = windowProblem(conditions.getAttribute("NotBefore"),
                               conditions.getAttribute("NotOnOrAfter"),
                               "the assertion");
    if (late) {
      out.problems.push(late);
    }
  }
  out.audiences = util.allByLocal(conditions, "Audience").map(util.textOf);
  if (out.audiences.length &&
      out.audiences.indexOf(tenant.saml.entityId) < 0) {
    out.problems.push("the assertion's audience (" +
                      out.audiences.join(", ") + ") does not name this " +
                      "relying party, " + tenant.saml.entityId);
  }
  out.nameIdentifier = util.textOf(util.firstByLocal(assertion,
                                                     "NameIdentifier"));
  out.confirmationMethods = util.allByLocal(assertion, "ConfirmationMethod")
    .map(util.textOf);
  const wanted = profile === "post" ? CM_BEARER1 : CM_ARTIFACT1;
  if (out.confirmationMethods.indexOf(wanted) < 0) {
    out.problems.push("the confirmation method is " +
                      out.confirmationMethods.join(", ") + ", where the " +
                      profile + " profile requires " + wanted);
  }
  out.attributes = {};
  util.allByLocal(assertion, "Attribute").forEach(function (attribute) {
    out.attributes[attribute.getAttribute("AttributeName")] =
      util.allByLocal(attribute, "AttributeValue").map(util.textOf);
  });
  log.debug("Leaving judgeSaml11Response(). " + out.problems.length +
            " problem(s).");
  return out;
}

// POST /t/{tenant}/saml11/acs (Browser/POST) and GET …?SAMLart= (Browser/
// Artifact).
async function saml11Acs(tenant, method, query, form) {
  log.debug("Entering saml11Acs(). " + method);
  let judged;
  let target = null;
  if (method === "GET" && query.get("SAMLart")) {
    target = query.get("TARGET");
    const requestId = "_r" + nodeCrypto.randomBytes(12).toString("hex");
    const xml = await resolveSaml11Artifact(tenant, query.getAll("SAMLart"),
                                            requestId);
    judged = await judgeSaml11Response(tenant, xml, "artifact", requestId);
  } else if (method === "POST" && form.SAMLResponse) {
    target = form.TARGET || null;
    const xml = Buffer.from(form.SAMLResponse, "base64").toString("utf8");
    judged = await judgeSaml11Response(tenant, xml, "post", null);
  } else {
    log.debug("Leaving saml11Acs(). Nothing to consume.");
    return { status: 400, body: { ok: false, error: "the assertion " +
      "consumer service takes a SAMLResponse (POST) or a SAMLart (GET)" } };
  }
  judged.target = target;
  judged.ok = judged.problems.length === 0;
  tenant.record("saml11", Object.assign({ event: "response" }, judged));
  log.debug("Leaving saml11Acs(). ok=" + judged.ok);
  return { status: judged.ok ? 200 : 400, body: judged };
}

// saml-bindings-1.1 section 3.1.3: the responder authenticates its
// requester, and a product-mode service does so by an enveloped signature on
// the samlp:Request, checked against the registered samlSigningCertificate.
async function resolveSaml11Artifact(tenant, artifacts, requestId) {
  log.debug("Entering resolveSaml11Artifact().");
  const responder = tenant.realmBase + "/saml11/responder";
  const request = signEnveloped(tenant,
    "<samlp:Request xmlns:samlp=\"" + NS_SAMLP1 + "\" xmlns:saml=\"" +
    NS_SAML1 + "\" RequestID=\"" + requestId + "\" MajorVersion=\"1\" " +
    "MinorVersion=\"1\" IssueInstant=\"" + new Date().toISOString() + "\">" +
    artifacts.map(function (one) {
      return "<samlp:AssertionArtifact>" + escapeXml(one) +
             "</samlp:AssertionArtifact>";
    }).join("") + "</samlp:Request>", "Request", "RequestID", null);
  const r = await util.outbound("POST", responder, {
    ca: tenant.serviceCaPem, body: soap(request),
    headers: { "Content-Type": "text/xml; charset=utf-8",
               SOAPAction: "http://www.oasis-open.org/committees/security" }
  });
  if (r.status !== 200) {
    log.debug("Leaving resolveSaml11Artifact(). " + r.status);
    throw new Error("the SAML 1.1 responder answered " + r.status + ": " +
                    r.text.slice(0, 400));
  }
  log.debug("Leaving resolveSaml11Artifact().");
  return r.text;
}

// ===========================================================================
// WS-FEDERATION 1.2 — THE PASSIVE RELYING PARTY.
// ===========================================================================

// POST /t/{tenant}/wsfed — the sign-in response: `wa=wsignin1.0`, `wresult`
// (a RequestSecurityTokenResponse whose RequestedSecurityToken is a SAML 1.1
// or SAML 2.0 assertion) and `wctx`.
async function wsfedReply(tenant, form) {
  log.debug("Entering wsfedReply().");
  const out = { wa: form.wa || null, wctx: form.wctx || null, problems: [] };
  if (form.wa !== "wsignin1.0" || !form.wresult) {
    out.problems.push("a sign-in response is wa=wsignin1.0 with a wresult");
  } else {
    const doc = util.parseXml(form.wresult);
    const assertion = util.firstByLocal(doc.documentElement, "Assertion");
    const appliesTo = util.firstByLocal(doc.documentElement, "AppliesTo");
    out.appliesTo = appliesTo
      ? util.textOf(util.firstByLocal(appliesTo, "Address")) : null;
    if (!assertion) {
      out.problems.push("the RequestedSecurityToken holds no assertion");
    } else {
      const saml2 = assertion.namespaceURI === NS_SAML2;
      out.tokenType = saml2 ? "saml2" : "saml11";
      const verdict = await verifyAgainstMetadata(tenant, "wsfed",
        form.wresult, assertion, saml2 ? "ID" : "AssertionID");
      out.signatureValid = verdict.ok;
      if (!verdict.ok) {
        out.problems.push("the assertion's signature: " + verdict.why);
      }
      out.issuer = saml2
        ? util.textOf(util.childByLocal(assertion, "Issuer"))
        : assertion.getAttribute("Issuer");
      out.subject = util.textOf(util.firstByLocal(assertion,
        saml2 ? "NameID" : "NameIdentifier"));
      const conditions = util.childByLocal(assertion, "Conditions");
      out.audiences = util.allByLocal(conditions, "Audience")
        .map(util.textOf);
      if (conditions) {
        const late = windowProblem(conditions.getAttribute("NotBefore"),
                                   conditions.getAttribute("NotOnOrAfter"),
                                   "the assertion");
        if (late) {
          out.problems.push(late);
        }
      }
      if (tenant.wsfed.realm &&
          out.audiences.indexOf(tenant.wsfed.realm) < 0) {
        out.problems.push("the assertion's audience (" +
                          out.audiences.join(", ") + ") is not this " +
                          "relying party's realm, " + tenant.wsfed.realm);
      }
    }
  }
  out.ok = out.problems.length === 0;
  tenant.record("wsfed", Object.assign({ event: "signin" }, out));
  log.debug("Leaving wsfedReply(). ok=" + out.ok);
  return { status: out.ok ? 200 : 400, body: out };
}

module.exports = {
  saml2Login: saml2Login,
  saml2Acs: saml2Acs,
  saml11Acs: saml11Acs,
  wsfedReply: wsfedReply,
  // For the in-process test.
  judgeSaml2Response: judgeSaml2Response,
  verifyWith: verifyWith,
  NS_SAMLP2: NS_SAMLP2,
  NS_SAML2: NS_SAML2
};
