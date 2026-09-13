'use strict';
//
// File: sts_pki_distribution_points.js
//
// ===========================================================================
// EVERY REVOCATION ADDRESS EVERY CERTIFICATE NAMES, FOLLOWED AS WRITTEN, IN
// EVERY TRUST REALM (2026-09-13).
//
// **THIS REPOSITORY'S OWN (`local: true`)**, and on the third of
// `tests/CLAUDE.md`'s kinds rather than the first: what it asserts is an
// address a certificate carries, and whether that address answers from where
// the RUNNER stands depends on how the LAUNCHER published this stack's ports.
// No copy over there could hold that.
//
// ---------------------------------------------------------------------------
// WHAT IT FOUND ON THE DAY IT WAS WRITTEN, WHICH IS THE ARGUMENT FOR IT.
//
// `tests/vendored/sts_pki_revocation.js` fetched `/pki/crl/<scope>/<ca>` by
// building the path itself, and `tests/pki_revocation.js` read the addresses
// out of `distributionPoints()` in process. Both were green while every one
// of these was wrong:
//
//   * **THE PORT.** A container listening on 8081 and published on 18081 put
//     `https://localhost:8081/pki/…` in every certificate. Nothing inside a
//     container can see the host side of its port mapping, and no test had
//     ever dialled an address a certificate named.
//   * **THE ADDRESSES WERE https AND ldaps**, which RFC 5280 section 8 says a
//     CA SHOULD NOT write, and the main port's own TLS certificate named its
//     OCSP responder on that very listener.
//   * **THE OCSP ADDRESS WAS A 404.** The `id-ad-ocsp` location is the base of
//     both RFC 6960 transports, and a GET of it — the first thing anybody
//     does with a URL copied out of `openssl x509 -text` — had no route.
//   * **EVERY REALM'S `ldap://` DISTRIBUTION POINT ANSWERED `noSuchObject`**,
//     because the lists were written into whichever realm's store happened to
//     be ambient, and at startup that is none.
//   * **THE PROCESS BRANCH AND THE DEFAULT REALM PUBLISHED TO ONE DN**, so an
//     LDAP fetch of one Intermediate's list returned the other's.
//   * **AND THE DIRECTORY COPY WAS NEVER REFRESHED**, so an hour after start
//     every `ldap://` list was past its `nextUpdate`.
//
// **SO THE RULE HERE IS THAT NOTHING IS REWRITTEN.** No URL is re-based onto
// the address this job was handed, no path is built by hand, no port is
// substituted. A certificate's address that does not answer from here is the
// defect, and a job that "helpfully" fixed the port would be the test that
// kept it hidden.
//
// ---------------------------------------------------------------------------
// WHERE THE CERTIFICATES COME FROM, AND WHY EACH SOURCE.
//
//   * **EVERY TRUST REALM'S PUBLISHED DOCUMENTS** — the JWKS, both SAML
//     metadata documents, the WS-Federation metadata, the WS-Trust STS
//     certificate, the TLS server certificate and the SPIFFE bundle. They are
//     what a relying party actually holds, so they are the certificates whose
//     addresses a relying party actually follows.
//   * **THE CERTIFICATE THE MAIN PORT PRESENTS**, off the handshake rather
//     than off a document about it — `/tls/server-certificate` publishing one
//     leaf and the socket serving another is exactly the drift
//     `tests/worker_server_certificate.js` exists for.
//   * **EVERY AUTHORITY IN `/pki/revocation`**, fetched from its OWN caIssuers
//     address, because a CA certificate names its PARENT's list and is the
//     only certificate that can reach the Root's and the Intermediates'.
//   * **KEY PAIRS ISSUED TO AN APPLICATION AND TO A PERSON**, in a realm this
//     job makes, because `issueSigningKeyPair()` is a second door onto the
//     extensions (`tests/pki_revocation.js` section G records that it named no
//     list at all until 2026-09-12) and those are the one kind of certificate
//     this hierarchy hands to something that is not this service.
//
// ---------------------------------------------------------------------------
// WHAT IS HELD TO THE SPECIFICATIONS, rather than merely fetched.
//
//   * **RFC 5280 section 4.2.1.13 / 4.2.2.1 / 8** — every certificate names a
//     CRL over http and over ldap, an OCSP responder and a caIssuers address,
//     and NO https or ldaps address (section 8: a CA SHOULD NOT); the http
//     addresses are on this service's host, and every one of them answers.
//   * **RFC 5280 section 4.2.2.1** — a caIssuers address answers one DER
//     certificate, `application/pkix-cert`, whose subject is the issuer the
//     certificate names and whose key verifies it.
//   * **RFC 5280 section 5 and 6.3.3** — each CRL, from every scheme: DER,
//     `application/pkix-crl` over HTTP, v2, the inner and outer signature
//     algorithms equal, the issuer byte-equal to the authority's subject, a
//     signature that verifies with that authority's key, `thisUpdate` passed
//     and `nextUpdate` still ahead, the two MUST extensions (the authority key
//     identifier, equal to the authority's subject key identifier, and the CRL
//     number), no empty revokedCertificates sequence, and none of the
//     certificates currently published on it.
//   * **RFC 4516 / RFC 4523** — an `ldap://` address names a base DN and the
//     `certificateRevocationList;binary` attribute, and an ANONYMOUS base
//     search of it returns the DER list.
//   * **RFC 6960** — for every responder and every certificate that names it:
//     a POST with a nonce and a GET of the base64 form, both answering 200
//     `application/ocsp-response`, `successful`, `id-pkix-ocsp-basic`, the
//     CertID echoed byte for byte (SHA-1 and SHA-256 alike), `good`, the
//     nonce echoed (RFC 8954 section 2.1), `thisUpdate`/`nextUpdate` about
//     now, and a signature that verifies with the issuer's key; a serial the
//     authority never issued answers `unknown`; and a GET of the address with
//     no request is a refusal naming the transports, never a 404.
//
// ---------------------------------------------------------------------------
// WHAT IT DOES NOT DO.
//
// It does not verify a signature made with an algorithm node's own crypto
// cannot check (a post-quantum authority, which is not the default), and
// says so in the log for each rather than calling it verified. It follows no
// X509-SVID — the SPIFFE bundle is what a relying party holds, and it names
// the Root. And it leaves the realm it makes behind, per `tests/CLAUDE.md`'s
// *No job removes a realm*.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const tls = require("tls");
const { Command, Option } = require("commander");
const ldapjs = require("ldapjs");
const { usernameFor } = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_pki_distribution_points",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

// A realm of this run's own, for the issued key pairs. `usernameFor()` carries
// the run stamp, so two runs against one long-lived mock never meet.
var REALM = usernameFor("pkidp").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var realmApi = base + "/realm/" + REALM + "/admin-api";
var APPLICATION = "pkidp-app";
var PERSON = usernameFor("pkidpperson");

// The documents a relying party holds a certificate from, per realm. A 404 is
// allowed — SPIFFE is off in a realm by default — and anything else that is
// not a 200 is reported.
const DOCUMENTS = [
  "/oauth2/jwks",
  "/saml2/metadata",
  "/saml11/metadata",
  "/FederationMetadata/2007-06/FederationMetadata.xml",
  "/sts/cert",
  "/tls/server-certificate",
  "/spiffe/bundle"
];

// How far a clock may be from this runner's for `thisUpdate`, `nextUpdate`
// and `producedAt`: the service is in a container on this machine, so a
// minute is generous.
const SKEW_MS = 60 * 1000;

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

// Every failure in a category, listed, rather than the first. A defect in an
// address is usually a defect in every address of that shape, and the list
// is what says which shape.
function noFailures(failures, what) {
  log.debug("Entering noFailures().");
  const shown = failures.slice(0, 25).join("\n  - ");
  assert.strictEqual(failures.length, 0, failures.length + " " + what + ":\n" +
    "  - " + shown + (failures.length > 25
      ? "\n  … and " + (failures.length - 25) + " more" : ""));
  log.debug("Leaving noFailures().");
}

// **`Authorization: none`**, for `sts_pki_revocation.js`'s reason: the
// launchers put an admin token on every fetch this process makes, and a
// revocation address that only answered with one would pass here while every
// relying party in the world was refused.
async function anonymous(url, options) {
  log.debug("Entering anonymous().");
  const opts = Object.assign({ redirect: "manual" }, options || {});
  opts.headers = Object.assign({ Authorization: "none" }, opts.headers || {});
  let r;
  try {
    r = await fetch(url, opts);
  } catch (e) {
    log.debug("Caught in anonymous(): " + ((e && e.message) || e));
    const cause = e && e.cause ? " (" + (e.cause.code || e.cause.message) + ")"
      : "";
    log.debug("Leaving anonymous().");
    return { status: 0, error: String((e && e.message) || e) + cause,
             type: "", bytes: Buffer.alloc(0) };
  }
  const bytes = Buffer.from(await r.arrayBuffer());
  log.debug("Leaving anonymous().");
  return { status: r.status, type: String(r.headers.get("content-type") || ""),
           headers: r.headers, bytes: bytes };
}

async function postJson(url, payload) {
  log.debug("Entering postJson().");
  const r = await fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {})
  });
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in postJson(): " + ((e && e.message) || e));
    body = raw;
  }
  log.debug("Leaving postJson().");
  return { status: r.status, body: body, raw: raw };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// ===========================================================================
// A DER READER AND WRITER, and why this job carries its own.
//
// pkijs builds the CRLs and the OCSP responses this job checks, so reading
// them back with pkijs would be the implementation agreeing with itself —
// `tests/crypto_module.js`'s argument about xml-crypto. What is needed is
// small: walk a TLV tree, read an OID, a time and a few extensions, and write
// one OCSPRequest. A byte slice of every node is kept, because a signature is
// over bytes and a name is compared as bytes.
//
// **NO ENTERING/LEAVING PAIR ON `readTlv()`**, which is the hot-path
// exception the code style names: it is called once per node of every
// certificate, CRL and OCSP response this job reads — tens of thousands of
// times — and a debug line per node would drown the log it exists to make
// readable.
// ===========================================================================
function readTlv(buf, pos) {
  const start = pos;
  const tag = buf[pos++];
  let len = buf[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) {
      len = len * 256 + buf[pos++];
    }
  }
  const end = pos + len;
  if (end > buf.length) {
    throw new Error("a DER length runs past the end of the document");
  }
  const node = { tag: tag, value: buf.subarray(pos, end),
                 raw: buf.subarray(start, end), end: end };
  if (tag & 0x20) {
    node.children = [];
    let p = pos;
    while (p < end) {
      const child = readTlv(buf, p);
      node.children.push(child);
      p = child.end;
    }
  }
  return node;
}

function parseDer(buf) {
  log.debug("Entering parseDer().");
  const node = readTlv(buf, 0);
  if (node.end !== buf.length) {
    throw new Error((buf.length - node.end) + " byte(s) after the outer DER " +
                    "element");
  }
  log.debug("Leaving parseDer().");
  return node;
}

function oidOf(node) {
  log.debug("Entering oidOf().");
  const b = node.value;
  const out = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      out.push(v);
      v = 0;
    }
  }
  log.debug("Leaving oidOf().");
  return out.join(".");
}

function timeOf(node) {
  log.debug("Entering timeOf().");
  const s = node.value.toString("latin1");
  if (node.tag === 0x17) {
    const yy = Number(s.slice(0, 2));
    log.debug("Leaving timeOf().");
    return new Date(Date.UTC(yy >= 50 ? 1900 + yy : 2000 + yy,
      Number(s.slice(2, 4)) - 1, Number(s.slice(4, 6)), Number(s.slice(6, 8)),
      Number(s.slice(8, 10)), Number(s.slice(10, 12))));
  }
  log.debug("Leaving timeOf().");
  return new Date(Date.UTC(Number(s.slice(0, 4)), Number(s.slice(4, 6)) - 1,
    Number(s.slice(6, 8)), Number(s.slice(8, 10)), Number(s.slice(10, 12)),
    Number(s.slice(12, 14))));
}

function extensionsFrom(sequence) {
  log.debug("Entering extensionsFrom().");
  const out = {};
  (sequence.children || []).forEach(function (ext) {
    const last = ext.children[ext.children.length - 1];
    out[oidOf(ext.children[0])] = {
      critical: ext.children.length === 3 && ext.children[1].value[0] !== 0,
      value: last.value
    };
  });
  log.debug("Leaving extensionsFrom().");
  return out;
}

// Every URI GeneralName ([6] IMPLICIT IA5String) under a node.
function urisUnder(node, out) {
  log.debug("Entering urisUnder().");
  const list = out || [];
  if (node.tag === 0x86) {
    list.push(node.value.toString("latin1"));
  }
  (node.children || []).forEach(function (child) {
    urisUnder(child, list);
  });
  log.debug("Leaving urisUnder().");
  return list;
}

function certificateParts(der) {
  log.debug("Entering certificateParts().");
  const cert = parseDer(der);
  const tbs = cert.children[0];
  const i = tbs.children[0].tag === 0xa0 ? 1 : 0;
  const parts = {
    der: der,
    tbsRaw: tbs.raw,
    sigAlg: oidOf(cert.children[1].children[0]),
    signature: cert.children[2].value.subarray(1),
    serial: tbs.children[i].value,
    issuerRaw: tbs.children[i + 2].raw,
    subjectRaw: tbs.children[i + 4].raw,
    spkiKeyBits: tbs.children[i + 5].children[1].value.subarray(1),
    extensions: {}
  };
  tbs.children.slice(i + 6).forEach(function (child) {
    if (child.tag === 0xa3) {
      parts.extensions = extensionsFrom(child.children[0]);
    }
  });
  const x = new nodeCrypto.X509Certificate(der);
  parts.x509 = x;
  parts.subject = x.subject.replace(/\n/g, ", ");
  parts.fingerprint = x.fingerprint256;
  parts.pointers = { crl: [], distributionPoints: 0, ocsp: [], caIssuers: [] };
  const dp = parts.extensions["2.5.29.31"];
  if (dp) {
    const points = parseDer(dp.value);
    parts.pointers.distributionPoints = points.children.length;
    parts.pointers.crl = urisUnder(points);
  }
  const aia = parts.extensions["1.3.6.1.5.5.7.1.1"];
  if (aia) {
    parseDer(aia.value).children.forEach(function (desc) {
      const method = oidOf(desc.children[0]);
      const uris = urisUnder(desc.children[1]);
      if (method === "1.3.6.1.5.5.7.48.1") {
        parts.pointers.ocsp = parts.pointers.ocsp.concat(uris);
      } else if (method === "1.3.6.1.5.5.7.48.2") {
        parts.pointers.caIssuers = parts.pointers.caIssuers.concat(uris);
      }
    });
  }
  const ski = parts.extensions["2.5.29.14"];
  parts.subjectKeyId = ski ? parseDer(ski.value).value : null;
  log.debug("Leaving certificateParts().");
  return parts;
}

function isSelfSigned(parts) {
  log.debug("Entering isSelfSigned().");
  log.debug("Leaving isSelfSigned().");
  return Buffer.compare(parts.issuerRaw, parts.subjectRaw) === 0;
}

// The digest a signature algorithm OID names, for node's `crypto.verify()`.
// `null` for an algorithm node verifies with no digest argument (Ed25519),
// and `undefined` for one this job cannot check — reported, never guessed.
const SIGNATURE_DIGESTS = {
  "1.2.840.113549.1.1.5": "sha1",
  "1.2.840.113549.1.1.11": "sha256",
  "1.2.840.113549.1.1.12": "sha384",
  "1.2.840.113549.1.1.13": "sha512",
  "1.2.840.10045.4.3.2": "sha256",
  "1.2.840.10045.4.3.3": "sha384",
  "1.2.840.10045.4.3.4": "sha512",
  "1.3.101.112": null,
  "1.3.101.113": null
};

var unverifiable = 0;

// Whether `signature` over `data` verifies with `issuer`'s key. Answers true,
// false, or null for an algorithm this job cannot check.
function signatureVerifies(sigAlg, data, signature, issuer) {
  log.debug("Entering signatureVerifies().");
  if (!Object.prototype.hasOwnProperty.call(SIGNATURE_DIGESTS, sigAlg)) {
    unverifiable += 1;
    log.warn("signature algorithm " + sigAlg + " is not one node verifies; " +
             "this signature is reported as NOT CHECKED rather than good.");
    log.debug("Leaving signatureVerifies().");
    return null;
  }
  let answer = false;
  try {
    answer = nodeCrypto.verify(SIGNATURE_DIGESTS[sigAlg], data,
                               issuer.x509.publicKey, signature);
  } catch (e) {
    log.debug("Caught in signatureVerifies(): " + ((e && e.message) || e));
    answer = false;
  }
  log.debug("Leaving signatureVerifies().");
  return answer;
}

// ---------------------------------------------------------------------------
// COLLECTING CERTIFICATES.
// ---------------------------------------------------------------------------
const certificates = new Map();  // fingerprint -> { parts, where: [] }

function remember(der, where) {
  log.debug("Entering remember().");
  let parts;
  try {
    parts = certificateParts(der);
  } catch (e) {
    log.debug("Caught in remember(): " + ((e && e.message) || e));
    log.warn(where + " published something that is not a certificate: " +
             e.message);
    log.debug("Leaving remember().");
    return null;
  }
  const held = certificates.get(parts.fingerprint);
  if (held) {
    held.where.push(where);
    log.debug("Leaving remember().");
    return held.parts;
  }
  certificates.set(parts.fingerprint, { parts: parts, where: [where] });
  log.debug("Leaving remember().");
  return parts;
}

function pemBlocks(text) {
  log.debug("Entering pemBlocks().");
  const out = [];
  const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push(Buffer.from(m[1].replace(/\s+/g, ""), "base64"));
  }
  log.debug("Leaving pemBlocks().");
  return out;
}

function xmlCertificates(text) {
  log.debug("Entering xmlCertificates().");
  const out = [];
  const re = /<(?:[A-Za-z0-9_]+:)?X509Certificate>([^<]+)</g;
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push(Buffer.from(m[1].replace(/\s+/g, ""), "base64"));
  }
  log.debug("Leaving xmlCertificates().");
  return out;
}

function jsonCertificates(value, out) {
  log.debug("Entering jsonCertificates().");
  const list = out || [];
  if (Array.isArray(value)) {
    value.forEach(function (one) {
      jsonCertificates(one, list);
    });
  } else if (value && typeof value === "object") {
    Object.keys(value).forEach(function (key) {
      if (key === "x5c" && Array.isArray(value[key])) {
        value[key].forEach(function (b64) {
          list.push(Buffer.from(String(b64), "base64"));
        });
      } else {
        jsonCertificates(value[key], list);
      }
    });
  }
  log.debug("Leaving jsonCertificates().");
  return list;
}

// The chain the main port presents, off the handshake.
function presentedChain(url) {
  log.debug("Entering presentedChain().");
  const target = new URL(url);
  return new Promise(function (resolve) {
    if (target.protocol !== "https:") {
      log.debug("Leaving presentedChain(). Not TLS.");
      resolve([]);
      return;
    }
    const socket = tls.connect({
      host: target.hostname, port: Number(target.port || 443),
      servername: target.hostname, rejectUnauthorized: false
    }, function () {
      const chain = [];
      let cert = socket.getPeerCertificate(true);
      const seen = new Set();
      while (cert && cert.raw && !seen.has(cert.fingerprint256)) {
        seen.add(cert.fingerprint256);
        chain.push(Buffer.from(cert.raw));
        cert = cert.issuerCertificate;
      }
      socket.end();
      log.debug("Leaving presentedChain(). " + chain.length + " cert(s).");
      resolve(chain);
    });
    socket.on("error", function (e) {
      log.warn("the handshake with " + url + " failed: " + e.message);
      resolve([]);
    });
  });
}

// ---------------------------------------------------------------------------
// LDAP, by the address and nothing else.
// ---------------------------------------------------------------------------
function parseLdapUrl(url) {
  log.debug("Entering parseLdapUrl().");
  const m = /^(ldaps?):\/\/([^/?#]*)\/([^?#]*)\?([^?#]*)/.exec(url);
  if (!m) {
    log.debug("Leaving parseLdapUrl(). Not an RFC 4516 URL with a DN and an " +
              "attribute.");
    return null;
  }
  log.debug("Leaving parseLdapUrl().");
  return { scheme: m[1], hostport: m[2], dn: decodeURIComponent(m[3]),
           attribute: decodeURIComponent(m[4]) };
}

function ldapFetch(url) {
  log.debug("Entering ldapFetch().");
  const parsed = parseLdapUrl(url);
  return new Promise(function (resolve) {
    if (!parsed) {
      resolve({ error: "not an RFC 4516 URL naming a DN and one attribute" });
      return;
    }
    let settled = false;
    function done(answer) {
      if (settled) {
        return;
      }
      settled = true;
      try {
        client.unbind();
      } catch (e) {
        log.debug("Caught in done(): " + ((e && e.message) || e));
      }
      resolve(answer);
    }
    const client = ldapjs.createClient({
      url: parsed.scheme + "://" + parsed.hostport,
      connectTimeout: 5000, timeout: 10000,
      tlsOptions: { servername: parsed.hostport.replace(/:\d+$/, "") }
    });
    client.on("error", function (e) {
      done({ error: "could not connect: " + e.message });
    });
    const timer = setTimeout(function () {
      done({ error: "no answer in 15s" });
    }, 15000);
    // An ANONYMOUS base search. No bind is sent: a CRL is a public document,
    // and a relying party following this address has no credential for this
    // directory.
    client.search(parsed.dn, { scope: "base",
                               attributes: [parsed.attribute] },
    function (err, res) {
      if (err) {
        clearTimeout(timer);
        done({ error: "search refused: " + err.message });
        return;
      }
      const values = [];
      res.on("searchEntry", function (entry) {
        (entry.attributes || []).forEach(function (attribute) {
          if (String(attribute.type).toLowerCase() ===
              parsed.attribute.toLowerCase()) {
            (attribute.buffers || []).forEach(function (b) {
              values.push(Buffer.from(b));
            });
          }
        });
      });
      // A search that ends in a non-success code emits `error` and never
      // `end` — `sts_directory_bulk_load_ldap.js` records that it hung a
      // client once.
      res.on("error", function (e) {
        clearTimeout(timer);
        done({ error: e.name + ": " + e.message });
      });
      res.on("end", function () {
        clearTimeout(timer);
        done({ values: values });
      });
    });
  });
}

// ---------------------------------------------------------------------------
// A CRL, READ AND JUDGED.
// ---------------------------------------------------------------------------
function crlParts(der) {
  log.debug("Entering crlParts().");
  const top = parseDer(der);
  const tbs = top.children[0];
  let i = 0;
  const parts = { tbsRaw: tbs.raw, version: null, revoked: [],
                  revokedPresent: false, extensions: {} };
  parts.outerAlg = oidOf(top.children[1].children[0]);
  parts.signature = top.children[2].value.subarray(1);
  if (tbs.children[0].tag === 0x02) {
    parts.version = tbs.children[0].value[0];
    i = 1;
  }
  parts.innerAlg = oidOf(tbs.children[i].children[0]);
  parts.issuerRaw = tbs.children[i + 1].raw;
  parts.thisUpdate = timeOf(tbs.children[i + 2]);
  parts.thisUpdateTag = tbs.children[i + 2].tag;
  let j = i + 3;
  const maybeNext = tbs.children[j];
  if (maybeNext && (maybeNext.tag === 0x17 || maybeNext.tag === 0x18)) {
    parts.nextUpdate = timeOf(maybeNext);
    parts.nextUpdateTag = maybeNext.tag;
    j += 1;
  }
  for (; j < tbs.children.length; j++) {
    const child = tbs.children[j];
    if (child.tag === 0x30) {
      parts.revokedPresent = true;
      child.children.forEach(function (entry) {
        parts.revoked.push(entry.children[0].value.toString("hex"));
      });
    } else if (child.tag === 0xa0) {
      parts.extensions = extensionsFrom(child.children[0]);
    }
  }
  log.debug("Leaving crlParts().");
  return parts;
}

function serialHex(bytes) {
  log.debug("Entering serialHex().");
  let hex = Buffer.from(bytes).toString("hex");
  while (hex.length > 2 && hex.slice(0, 2) === "00") {
    hex = hex.slice(2);
  }
  log.debug("Leaving serialHex().");
  return hex;
}

// Every RFC 5280 section 5 property this job holds a CRL to. Answers the
// problems as sentences; an empty array is a conforming list.
function judgeCrl(der, issuer, subjects, where) {
  log.debug("Entering judgeCrl().");
  const problems = [];
  let crl;
  try {
    crl = crlParts(der);
  } catch (e) {
    log.debug("Caught in judgeCrl(): " + ((e && e.message) || e));
    log.debug("Leaving judgeCrl().");
    return [where + ": not a DER CRL (" + e.message + ")"];
  }
  const now = Date.now();
  if (crl.version !== 1) {
    problems.push(where + ": version is " + crl.version + ", not v2 (RFC " +
                  "5280 section 5.1.2.1 — a CRL with extensions MUST be v2)");
  }
  if (crl.innerAlg !== crl.outerAlg) {
    problems.push(where + ": the tbsCertList signature algorithm " +
                  crl.innerAlg + " differs from the outer " + crl.outerAlg +
                  " (section 5.1.1.2)");
  }
  if (Buffer.compare(crl.issuerRaw, issuer.subjectRaw) !== 0) {
    problems.push(where + ": the CRL's issuer is not byte-equal to the " +
                  "subject of " + issuer.subject + ", the authority the " +
                  "certificate names (sections 5.1.2.3 and 6.3.3)");
  }
  const verified = signatureVerifies(crl.outerAlg, crl.tbsRaw, crl.signature,
                                     issuer);
  if (verified === false) {
    problems.push(where + ": the signature does not verify with " +
                  issuer.subject + "'s key");
  }
  if (crl.thisUpdate.getTime() > now + SKEW_MS) {
    problems.push(where + ": thisUpdate " + crl.thisUpdate.toISOString() +
                  " is in the future");
  }
  if (!crl.nextUpdate) {
    problems.push(where + ": no nextUpdate (section 5.1.2.5: conforming CRL " +
                  "issuers MUST include it)");
  } else if (crl.nextUpdate.getTime() <= now - SKEW_MS) {
    problems.push(where + ": nextUpdate " + crl.nextUpdate.toISOString() +
                  " has PASSED — section 6.3.3 gives a relying party nothing " +
                  "to conclude from a list past it");
  }
  [["thisUpdate", crl.thisUpdate, crl.thisUpdateTag],
   ["nextUpdate", crl.nextUpdate, crl.nextUpdateTag]].forEach(function (t) {
    if (t[1] && t[1].getUTCFullYear() < 2050 && t[2] !== 0x17) {
      problems.push(where + ": " + t[0] + " before 2050 is not UTCTime " +
                    "(section 5.1.2.4)");
    }
  });
  if (crl.revokedPresent && !crl.revoked.length) {
    problems.push(where + ": an EMPTY revokedCertificates sequence (section " +
                  "5.1.2.6: when there are none the list MUST be absent)");
  }
  const aki = crl.extensions["2.5.29.35"];
  if (!aki) {
    problems.push(where + ": no authorityKeyIdentifier (section 5.2.1: " +
                  "conforming CRL issuers MUST include it)");
  } else if (issuer.subjectKeyId) {
    const keyId = (parseDer(aki.value).children || []).filter(function (c) {
      return c.tag === 0x80;
    })[0];
    if (!keyId || Buffer.compare(keyId.value, issuer.subjectKeyId) !== 0) {
      problems.push(where + ": the authorityKeyIdentifier does not equal " +
                    issuer.subject + "'s subjectKeyIdentifier");
    }
  }
  if (crl.extensions["2.5.29.20"]) {
    crl.number = BigInt("0x" + (parseDer(crl.extensions["2.5.29.20"].value)
      .value.toString("hex") || "0"));
  }
  if (!crl.extensions["2.5.29.20"]) {
    problems.push(where + ": no cRLNumber (section 5.2.3: conforming CRL " +
                  "issuers MUST include it)");
  }
  const idp = crl.extensions["2.5.29.28"];
  if (idp && !idp.critical) {
    problems.push(where + ": an issuingDistributionPoint that is not " +
                  "critical (section 5.2.5: it MUST be)");
  }
  subjects.forEach(function (subject) {
    if (crl.revoked.indexOf(serialHex(subject.serial)) >= 0) {
      problems.push(where + ": lists " + subject.subject + " (serial " +
                    serialHex(subject.serial) + ") as REVOKED, and this " +
                    "service is publishing that certificate right now");
    }
  });
  log.debug("Leaving judgeCrl().");
  return problems;
}

// The cRLNumber and thisUpdate of a list, for section 5.2.3's *if the
// thisUpdate … in the two CRLs are not identical, the CRL numbers MUST be
// different*. Null for bytes that are not a CRL — `judgeCrl()` reports those.
function crlIdentity(der) {
  log.debug("Entering crlIdentity().");
  try {
    const crl = crlParts(der);
    const ext = crl.extensions["2.5.29.20"];
    log.debug("Leaving crlIdentity().");
    return { thisUpdate: crl.thisUpdate.getTime(),
             number: ext ? BigInt("0x" + (parseDer(ext.value).value
               .toString("hex") || "0")) : null };
  } catch (e) {
    log.debug("Caught in crlIdentity(): " + ((e && e.message) || e));
    log.debug("Leaving crlIdentity().");
    return null;
  }
}

// ---------------------------------------------------------------------------
// OCSP.
// ---------------------------------------------------------------------------
function derLength(n) {
  log.debug("Entering derLength().");
  if (n < 128) {
    log.debug("Leaving derLength().");
    return Buffer.from([n]);
  }
  const bytes = [];
  let v = n;
  while (v) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  log.debug("Leaving derLength().");
  return Buffer.from([0x80 | bytes.length].concat(bytes));
}

function tlv(tag, parts) {
  log.debug("Entering tlv().");
  const body = Buffer.concat([].concat(parts));
  log.debug("Leaving tlv().");
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

function oidDer(dotted) {
  log.debug("Entering oidDer().");
  const p = dotted.split(".").map(Number);
  const out = [p[0] * 40 + p[1]];
  p.slice(2).forEach(function (value) {
    const bytes = [value & 0x7f];
    let v = Math.floor(value / 128);
    while (v) {
      bytes.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    Array.prototype.push.apply(out, bytes);
  });
  log.debug("Leaving oidDer().");
  return tlv(0x06, Buffer.from(out));
}

const HASH_OIDS = { sha1: "1.3.14.3.2.26", sha256: "2.16.840.1.101.3.4.2.1" };
const OCSP_NONCE = "1.3.6.1.5.5.7.48.1.2";

// RFC 6960 section 4.1.1's CertID: the hash of the issuer's NAME, the hash of
// the issuer's public key BIT STRING contents, and the serial.
function certIdFor(hash, subject, issuer, serial) {
  log.debug("Entering certIdFor().");
  log.debug("Leaving certIdFor().");
  return tlv(0x30, [
    tlv(0x30, [oidDer(HASH_OIDS[hash]), Buffer.from([0x05, 0x00])]),
    tlv(0x04, nodeCrypto.createHash(hash).update(issuer.subjectRaw).digest()),
    tlv(0x04, nodeCrypto.createHash(hash).update(issuer.spkiKeyBits).digest()),
    tlv(0x02, serial || subject.serial)
  ]);
}

function ocspRequestFor(certId, nonce) {
  log.debug("Entering ocspRequestFor().");
  const tbs = [tlv(0x30, [tlv(0x30, [certId])])];
  if (nonce) {
    tbs.push(tlv(0xa2, [tlv(0x30, [tlv(0x30, [
      oidDer(OCSP_NONCE), tlv(0x04, tlv(0x04, nonce))
    ])])]));
  }
  log.debug("Leaving ocspRequestFor().");
  return tlv(0x30, [tlv(0x30, tbs)]);
}

function ocspResponseParts(der) {
  log.debug("Entering ocspResponseParts().");
  const top = parseDer(der);
  const out = { status: top.children[0].value[0] };
  if (!top.children[1]) {
    log.debug("Leaving ocspResponseParts(). No responseBytes.");
    return out;
  }
  const bytes = top.children[1].children[0];
  out.type = oidOf(bytes.children[0]);
  const basic = parseDer(bytes.children[1].value);
  const data = basic.children[0];
  out.tbsRaw = data.raw;
  out.sigAlg = oidOf(basic.children[1].children[0]);
  out.signature = basic.children[2].value.subarray(1);
  const i = data.children[0].tag === 0xa0 ? 1 : 0;
  out.producedAt = timeOf(data.children[i + 1]);
  // The raw GeneralizedTime strings, for RFC 5019 section 2.2.4's *MUST NOT
  // include fractional seconds*.
  out.timeStrings = [data.children[i + 1].value.toString("latin1")];
  out.single = data.children[i + 2].children.map(function (single) {
    const one = { certIdRaw: single.children[0].raw,
                  statusTag: single.children[1].tag,
                  thisUpdate: timeOf(single.children[2]) };
    out.timeStrings.push(single.children[2].value.toString("latin1"));
    single.children.slice(3).forEach(function (child) {
      if (child.tag === 0xa0) {
        one.nextUpdate = timeOf(child.children[0]);
        out.timeStrings.push(child.children[0].value.toString("latin1"));
      }
    });
    return one;
  });
  out.extensions = {};
  data.children.slice(i + 3).forEach(function (child) {
    if (child.tag === 0xa1) {
      out.extensions = extensionsFrom(child.children[0]);
    }
  });
  log.debug("Leaving ocspResponseParts().");
  return out;
}

// One OCSP exchange, judged. `expect` is `good` or `unknown`.
function judgeOcsp(r, where, certId, issuer, nonce, expect) {
  log.debug("Entering judgeOcsp().");
  const problems = [];
  if (r.status !== 200) {
    log.debug("Leaving judgeOcsp().");
    return [where + ": answered HTTP " + r.status +
            (r.error ? " (" + r.error + ")" : "") + " " +
            r.bytes.toString("utf8").slice(0, 160)];
  }
  if (!/^application\/ocsp-response/.test(r.type)) {
    problems.push(where + ": Content-Type is \"" + r.type + "\", not " +
                  "application/ocsp-response (RFC 6960 appendix A.2)");
  }
  // RFC 5019 section 6.2: an authoritative answer MUST NOT say no-cache or
  // no-store, and one a cache may keep carries max-age, Last-Modified, Expires
  // and an ETag. A nonce-bearing answer belongs to one request, so it is only
  // held to the MUST NOT.
  const cache = String(r.headers.get("cache-control") || "");
  if (expect === "good" && /no-store|no-cache/i.test(cache + " " +
      String(r.headers.get("pragma") || ""))) {
    problems.push(where + ": Cache-Control \"" + cache + "\" on an " +
                  "authoritative answer (RFC 5019 section 6.2 MUST NOT)");
  }
  if (expect === "good" && !nonce) {
    ["last-modified", "expires", "etag"].forEach(function (name) {
      if (!r.headers.get(name)) {
        problems.push(where + ": no " + name + " header (RFC 5019 section " +
                      "6.2)");
      }
    });
    if (!/max-age=\d+/.test(cache)) {
      problems.push(where + ": no max-age in \"" + cache + "\" (RFC 5019 " +
                    "section 6.2)");
    }
  }
  let o;
  try {
    o = ocspResponseParts(r.bytes);
  } catch (e) {
    log.debug("Caught in judgeOcsp(): " + ((e && e.message) || e));
    log.debug("Leaving judgeOcsp().");
    return problems.concat([where + ": not a DER OCSPResponse (" + e.message +
                            ")"]);
  }
  if (o.status !== 0) {
    problems.push(where + ": responseStatus is " + o.status + ", not " +
                  "successful(0)");
    log.debug("Leaving judgeOcsp().");
    return problems;
  }
  (o.timeStrings || []).forEach(function (text) {
    if (!/^\d{14}Z$/.test(text)) {
      problems.push(where + ": the GeneralizedTime \"" + text + "\" is not " +
                    "YYYYMMDDHHMMSSZ — RFC 5019 section 2.2.4: it MUST NOT " +
                    "include fractional seconds, and X.690 section 11.7 " +
                    "forbids trailing zeros in one");
    }
  });
  if (o.type !== "1.3.6.1.5.5.7.48.1.1") {
    problems.push(where + ": responseType " + o.type + " is not " +
                  "id-pkix-ocsp-basic (section 4.2.1)");
  }
  const single = o.single.filter(function (one) {
    return Buffer.compare(one.certIdRaw, certId) === 0;
  })[0];
  if (!single) {
    problems.push(where + ": no SingleResponse echoes the requested CertID " +
                  "byte for byte (section 4.2.1)");
  } else {
    const want = expect === "unknown" ? 0x82 : 0x80;
    if (single.statusTag !== want) {
      problems.push(where + ": certStatus is " +
                    ({ 128: "good", 161: "revoked", 130: "unknown" }
                      [single.statusTag] || single.statusTag) +
                    ", expected " + expect);
    }
    if (single.thisUpdate.getTime() > Date.now() + SKEW_MS) {
      problems.push(where + ": thisUpdate is in the future");
    }
    if (single.nextUpdate &&
        single.nextUpdate.getTime() <= Date.now() - SKEW_MS) {
      problems.push(where + ": nextUpdate has passed");
    }
  }
  if (nonce) {
    const echoed = o.extensions[OCSP_NONCE];
    let value = null;
    try {
      value = echoed ? parseDer(echoed.value).value : null;
    } catch (e) {
      log.debug("Caught in judgeOcsp(): " + ((e && e.message) || e));
      value = null;
    }
    if (!value || Buffer.compare(value, nonce) !== 0) {
      problems.push(where + ": the nonce was not echoed (RFC 6960 section " +
                    "4.4.1, RFC 8954 section 2.1)");
    }
  }
  const verified = signatureVerifies(o.sigAlg, o.tbsRaw, o.signature, issuer);
  if (verified === false) {
    problems.push(where + ": the response signature does not verify with " +
                  issuer.subject + "'s key — this responder signs with the " +
                  "CA itself, so it must (section 4.2.2.2)");
  }
  log.debug("Leaving judgeOcsp().");
  return problems;
}

// ===========================================================================
// THE TEST.
// ===========================================================================
async function test() {
  log.debug("Entering test().");
  const origin = new URL(base).origin;
  const hostname = new URL(base).hostname;
  function plainHttpOnThisHost(url) {
    log.debug("Entering plainHttpOnThisHost().");
    let parsed = null;
    try {
      parsed = new URL(url);
    } catch (e) {
      log.debug("Caught in plainHttpOnThisHost(): " + ((e && e.message) || e));
    }
    log.debug("Leaving plainHttpOnThisHost().");
    return !!parsed && parsed.protocol === "http:" &&
           parsed.hostname === hostname;
  }

  log.info("=== A. every realm, and the index of every authority ===");

  const realmsReply = await anonymous(base + "/realms");
  const realmList = JSON.parse(realmsReply.bytes.toString("utf8"));
  check("GET /realms lists the trust realms this job walks", function () {
    assert.strictEqual(realmsReply.status, 200);
    assert.ok(Array.isArray(realmList.realms) && realmList.realms.length >= 1);
  });

  // The realm the issued key pairs are made in. Made BEFORE the index is read,
  // so its authorities are in it.
  await ok(api + "/realms/create", { id: REALM, name: "PKI distribution " +
                                     "points" }, "created the trust realm");
  await ok(realmApi + "/pki/build", { organisation: "Distribution Points",
                                      country: "US" },
           "built the realm's certificate authority branch");
  await ok(realmApi + "/applications/create",
           { identifier: APPLICATION, protocols: ["oauth2"],
             fields: { oauthClientId: APPLICATION,
                       oauthClientSecret: APPLICATION + "-secret-" + REALM,
                       oauthTokenEndpointAuthMethod: "client_secret_post" } },
           "created an application to issue key pairs to");
  await ok(realmApi + "/users/create",
           { username: PERSON, invent: false,
             attributes: { cn: "PKI " + PERSON, sn: PERSON,
                           givenName: "PKI", displayName: "PKI " + PERSON,
                           mail: PERSON + "@example.test" } },
           "created a person to issue a key pair to");
  const realmIds = realmList.realms.map(function (one) {
    return { id: one.id, prefix: one.pathPrefix || "" };
  });
  if (!realmIds.some(function (one) { return one.id === REALM; })) {
    realmIds.push({ id: REALM, prefix: "/realm/" + REALM });
  }

  const indexReply = await anonymous(base + "/pki/revocation");
  const index = JSON.parse(indexReply.bytes.toString("utf8"));
  check("GET /pki/revocation lists the authorities, " +
        (index.authorities || []).length + " of them", function () {
          assert.strictEqual(indexReply.status, 200);
          assert.ok(index.authorities.length >= 3);
        });

  const httpAddresses = [];
  index.authorities.forEach(function (one) {
    httpAddresses.push([one.scope + "/" + one.ca + " crl.http", one.crl.http]);
    httpAddresses.push([one.scope + "/" + one.ca + " ocsp", one.ocsp]);
    httpAddresses.push([one.scope + "/" + one.ca + " caIssuers",
                        one.caIssuers]);
  });
  check("every revocation address in the index is PLAIN http:// on the host " +
        "the runner reaches this service by (" + hostname + ") — RFC 5280 " +
        "section 8 says a CA SHOULD NOT name https, and a certificate is read " +
        "outside the container, so an address naming anything else answers " +
        "nothing from where it is followed", function () {
          noFailures(httpAddresses.filter(function (pair) {
            return !plainHttpOnThisHost(pair[1]);
          }).map(function (pair) {
            return pair[0] + " is " + pair[1];
          }), "address(es) that are not plain http on " + hostname);
          noFailures(index.authorities.filter(function (one) {
            return one.crl.ldaps !== undefined;
          }).map(function (one) {
            return one.scope + "/" + one.ca + " still lists " + one.crl.ldaps;
          }), "authority(ies) still publishing an ldaps:// address");
        });

  log.info("=== B. every certificate this service publishes ===");

  for (const realm of realmIds) {
    for (const path of DOCUMENTS) {
      const where = (realm.prefix || "") + path;
      const r = await anonymous(base + where);
      if (r.status === 404) {
        continue;
      }
      if (r.status !== 200) {
        log.warn(where + " answered " + r.status + "; its certificates are " +
                 "not followed.");
        continue;
      }
      const text = r.bytes.toString("utf8");
      let found = pemBlocks(text).concat(xmlCertificates(text));
      try {
        found = found.concat(jsonCertificates(JSON.parse(text)));
      } catch (e) {
        log.debug("Caught in test(): " + ((e && e.message) || e) +
                  " (not JSON, which most of these documents are not)");
      }
      found.forEach(function (der) {
        remember(der, where);
      });
    }
  }
  (await presentedChain(base)).forEach(function (der) {
    remember(der, "the TLS handshake on " + origin);
  });

  // An application's JWT and SAML signing key pairs, and a person's.
  await ok(realmApi + "/pki/issue", { identifier: APPLICATION, purpose: "jwt" },
           "issued the application an RFC 7523 key pair");
  await ok(realmApi + "/pki/issue",
           { identifier: APPLICATION, purpose: "saml" },
           "issued the application an RFC 7522 key pair");
  const view = await fetch(realmApi + "/applications?application=" +
                           encodeURIComponent(APPLICATION));
  const viewed = await view.json();
  const fields = ((viewed.application || viewed).fields) || {};
  ["oauthAssertionCertificate", "oauthSamlAssertionCertificate"]
    .forEach(function (name) {
      pemBlocks(String(fields[name] || "")).forEach(function (der) {
        remember(der, REALM + " application " + name);
      });
    });
  const person = await ok(realmApi + "/pki/issue",
                          { target: "person", identifier: PERSON },
                          "issued the person an RFC 7523 key pair");
  pemBlocks(String(person.certificatePem || "")).forEach(function (der) {
    remember(der, REALM + " person " + PERSON);
  });

  // Every authority's own certificate, from its own caIssuers address — the
  // one door to the certificates that name the Root's and an Intermediate's
  // lists.
  const caFetchFailures = [];
  for (const one of index.authorities) {
    const r = await anonymous(one.caIssuers);
    if (r.status === 200) {
      remember(r.bytes, "the caIssuers address of " + one.scope + "/" +
                        one.ca);
    } else {
      caFetchFailures.push(one.caIssuers + " answered " + r.status +
                           (r.error ? " (" + r.error + ")" : ""));
    }
  }
  check("every authority's certificate is reachable at the caIssuers address " +
        "the index publishes for it", function () {
          noFailures(caFetchFailures, "caIssuers address(es) did not answer");
        });

  const all = Array.from(certificates.values()).map(function (held) {
    return held.parts;
  });
  check("certificates were collected from every realm — " + all.length +
        " distinct, across " + realmIds.length + " realm(s)", function () {
          assert.ok(all.length >= realmIds.length,
            "only " + all.length + " certificates were found");
        });

  // The authority behind each certificate: the one whose subject is the
  // certificate's issuer AND whose key verifies it. Names are not unique
  // across a rebuild, so the signature decides.
  const authorities = all.filter(function (parts) {
    return parts.x509.ca;
  });
  function issuerOf(parts) {
    log.debug("Entering issuerOf().");
    const found = authorities.filter(function (candidate) {
      return Buffer.compare(candidate.subjectRaw, parts.issuerRaw) === 0 &&
             parts.x509.verify(candidate.x509.publicKey);
    })[0] || null;
    log.debug("Leaving issuerOf().");
    return found;
  }
  function whereOf(parts) {
    log.debug("Entering whereOf().");
    const held = certificates.get(parts.fingerprint);
    log.debug("Leaving whereOf().");
    return parts.subject + " (from " + held.where[0] +
           (held.where.length > 1 ? " and " + (held.where.length - 1) +
                                    " other place(s)" : "") + ")";
  }

  log.info("=== C. what every certificate names ===");

  const issued = all.filter(function (parts) {
    return !isSelfSigned(parts);
  });
  const orphans = [];
  const pointerProblems = [];
  const byAddress = { crl: new Map(), ocsp: new Map(), caIssuers: new Map() };
  issued.forEach(function (parts) {
    const issuer = issuerOf(parts);
    if (!issuer) {
      orphans.push(whereOf(parts));
      return;
    }
    const p = parts.pointers;
    const schemes = p.crl.map(function (url) {
      return url.split(":")[0];
    });
    if (!p.crl.length || !p.ocsp.length || !p.caIssuers.length) {
      pointerProblems.push(whereOf(parts) + " names " + p.crl.length +
        " CRL, " + p.ocsp.length + " OCSP and " + p.caIssuers.length +
        " caIssuers address(es)");
    }
    ["http", "ldap"].forEach(function (scheme) {
      if (schemes.indexOf(scheme) < 0) {
        pointerProblems.push(whereOf(parts) + " names no " + scheme +
                             " CRL distribution point");
      }
    });
    p.crl.concat(p.ocsp, p.caIssuers).forEach(function (url) {
      if (/^(https|ldaps):/i.test(url)) {
        pointerProblems.push(whereOf(parts) + " names " + url + " — RFC " +
          "5280 section 8: a CA SHOULD NOT include https or ldaps URIs in " +
          "an extension");
      }
    });
    p.crl.forEach(function (url) {
      if (!byAddress.crl.has(url)) {
        byAddress.crl.set(url, { issuer: issuer, subjects: [] });
      }
      const entry = byAddress.crl.get(url);
      if (Buffer.compare(entry.issuer.der, issuer.der) !== 0) {
        pointerProblems.push(url + " is named by certificates of two " +
          "different authorities — " + entry.issuer.subject + " and " +
          issuer.subject + " — and one list can have only one issuer");
      }
      entry.subjects.push(parts);
    });
    p.ocsp.forEach(function (url) {
      const key = url + " " + issuer.fingerprint;
      if (!byAddress.ocsp.has(key)) {
        byAddress.ocsp.set(key, { url: url, issuer: issuer, subjects: [] });
      }
      byAddress.ocsp.get(key).subjects.push(parts);
    });
    p.caIssuers.forEach(function (url) {
      if (!byAddress.caIssuers.has(url)) {
        byAddress.caIssuers.set(url, { issuer: issuer, subjects: [] });
      }
      byAddress.caIssuers.get(url).subjects.push(parts);
    });
  });
  check("every certificate collected chains to an authority this job also " +
        "collected (" + issued.length + " issued certificate(s))", function () {
          noFailures(orphans, "certificate(s) with no authority found");
        });
  check("every issued certificate names a CRL over http AND ldap, an OCSP " +
        "responder and a caIssuers address, and no https or ldaps address " +
        "(RFC 5280 sections 4.2.1.13, 4.2.2.1 and 8)", function () {
          noFailures(pointerProblems, "pointer problem(s)");
        });
  const originProblems = [];
  byAddress.crl.forEach(function (entry, url) {
    if (/^https?:/.test(url) && !plainHttpOnThisHost(url)) {
      originProblems.push(url);
    }
    if (/^ldap:/.test(url)) {
      const parsed = parseLdapUrl(url);
      if (!parsed || parsed.hostport.replace(/:\d+$/, "") !== hostname) {
        originProblems.push(url);
      }
    }
  });
  byAddress.ocsp.forEach(function (entry) {
    if (!plainHttpOnThisHost(entry.url)) {
      originProblems.push(entry.url);
    }
  });
  byAddress.caIssuers.forEach(function (entry, url) {
    if (!plainHttpOnThisHost(url)) {
      originProblems.push(url);
    }
  });
  check("and every address inside every certificate names " + hostname +
        ", the host the runner reaches this service by — whether its PORT " +
        "is the one a client dials is what sections D, E and F find out by " +
        "dialling it", function () {
          noFailures(originProblems, "address(es) naming another host");
        });

  log.info("=== D. every caIssuers address (" + byAddress.caIssuers.size +
           ") ===");

  const caProblems = [];
  for (const [url, entry] of byAddress.caIssuers) {
    const r = await anonymous(url);
    if (r.status !== 200) {
      caProblems.push(url + ": HTTP " + r.status +
                      (r.error ? " (" + r.error + ")" : ""));
      continue;
    }
    if (!/^application\/pkix-cert/.test(r.type)) {
      caProblems.push(url + ": Content-Type \"" + r.type + "\", not " +
                      "application/pkix-cert (RFC 5280 section 4.2.2.1)");
    }
    let served;
    try {
      served = certificateParts(r.bytes);
    } catch (e) {
      log.debug("Caught in test(): " + ((e && e.message) || e));
      caProblems.push(url + ": not one DER certificate (" + e.message + ")");
      continue;
    }
    entry.subjects.forEach(function (subject) {
      if (Buffer.compare(served.subjectRaw, subject.issuerRaw) !== 0 ||
          !subject.x509.verify(served.x509.publicKey)) {
        caProblems.push(url + ": serves " + served.subject + ", which is not " +
                        "the authority that signed " + whereOf(subject));
      }
    });
  }
  check("every caIssuers address answers the DER certificate of the " +
        "authority that signed each certificate naming it", function () {
          noFailures(caProblems, "caIssuers problem(s)");
        });

  log.info("=== E. every CRL distribution point (" + byAddress.crl.size +
           "), in every scheme ===");

  const crlProblems = [];
  const firstSigned = new Map();
  let httpCrls = 0;
  let ldapCrls = 0;
  for (const [url, entry] of byAddress.crl) {
    if (/^https?:/.test(url)) {
      httpCrls += 1;
      const r = await anonymous(url);
      if (r.status !== 200) {
        crlProblems.push(url + ": HTTP " + r.status +
          (r.error ? " (" + r.error + ")" : "") + " " +
          r.bytes.toString("utf8").slice(0, 160));
        continue;
      }
      if (!/^application\/pkix-crl/.test(r.type)) {
        crlProblems.push(url + ": Content-Type \"" + r.type + "\", not " +
                         "application/pkix-crl (RFC 5280 section 4.2.1.13)");
      }
      Array.prototype.push.apply(crlProblems,
        judgeCrl(r.bytes, entry.issuer, entry.subjects, url));
      firstSigned.set(url, crlIdentity(r.bytes));
    } else if (/^ldap:/.test(url)) {
      ldapCrls += 1;
      const parsed = parseLdapUrl(url);
      if (!parsed || !/^certificateRevocationList;binary$/i
          .test(parsed.attribute)) {
        crlProblems.push(url + ": not an RFC 4516 URL naming a DN and " +
                         "certificateRevocationList;binary (RFC 4523 " +
                         "section 2.18, RFC 5280 section 4.2.1.13)");
        continue;
      }
      const fetched = await ldapFetch(url);
      if (fetched.error) {
        crlProblems.push(url + ": " + fetched.error);
        continue;
      }
      if (fetched.values.length !== 1) {
        crlProblems.push(url + ": " + fetched.values.length + " value(s) of " +
                         parsed.attribute + ", not exactly one");
        continue;
      }
      Array.prototype.push.apply(crlProblems,
        judgeCrl(fetched.values[0], entry.issuer, entry.subjects, url));
    } else {
      crlProblems.push(url + ": a scheme this service does not publish");
    }
  }
  // A SECOND SIGNING of every HTTP list, more than a second later, so its
  // thisUpdate differs: section 5.2.3 then requires a different number. Every
  // list here is signed on demand, and until 2026-09-13 two fetches came back
  // as two documents both calling themselves the same number.
  await new Promise(function (resolve) {
    setTimeout(resolve, 1100);
  });
  for (const [url, first] of firstSigned) {
    const again = await anonymous(url);
    const second = again.status === 200 ? crlIdentity(again.bytes) : null;
    if (!first || !second) {
      continue;
    }
    if (second.thisUpdate !== first.thisUpdate &&
        (first.number === null || second.number === null ||
         second.number <= first.number)) {
      crlProblems.push(url + ": signed again with a later thisUpdate and " +
        "cRLNumber " + String(second.number) + " after " +
        String(first.number) + " — RFC 5280 section 5.2.3: the numbers MUST " +
        "differ, and the sequence is monotonically increasing");
    }
  }
  check("every CRL distribution point — " + httpCrls + " over HTTP and " +
        ldapCrls + " over LDAP — answers a current, correctly signed " +
        "RFC 5280 section 5 list from the authority that issued the " +
        "certificates naming it", function () {
          noFailures(crlProblems, "CRL problem(s)");
        });

  log.info("=== F. every OCSP responder, for every certificate naming it ===");

  const ocspProblems = [];
  let exchanges = 0;
  for (const entry of byAddress.ocsp.values()) {
    const bare = await anonymous(entry.url);
    if (bare.status === 404 || bare.status === 0) {
      ocspProblems.push(entry.url + ": a GET of the address as written " +
        "answered " + (bare.status || bare.error) + " — the responder looks " +
        "absent to anybody who follows the certificate");
    } else if (bare.status !== 400 ||
               !/POST/.test(bare.bytes.toString("utf8"))) {
      ocspProblems.push(entry.url + ": a GET with no request answered " +
        bare.status + " rather than a refusal naming the two transports");
    }
    const seenSerials = new Set();
    for (const subject of entry.subjects) {
      const serial = serialHex(subject.serial);
      if (seenSerials.has(serial)) {
        continue;
      }
      seenSerials.add(serial);
      const label = entry.url + " for " + subject.subject;
      const nonce = nodeCrypto.randomBytes(16);
      const sha1Id = certIdFor("sha1", subject, entry.issuer);
      const posted = await anonymous(entry.url, {
        method: "POST", headers: { "Content-Type": "application/ocsp-request" },
        body: ocspRequestFor(sha1Id, nonce)
      });
      exchanges += 1;
      Array.prototype.push.apply(ocspProblems,
        judgeOcsp(posted, label + " (POST, SHA-1)", sha1Id, entry.issuer,
                  nonce, "good"));
      const sha256Id = certIdFor("sha256", subject, entry.issuer);
      const encoded = encodeURIComponent(
        ocspRequestFor(sha256Id, null).toString("base64"));
      const got = await anonymous(entry.url.replace(/\/+$/, "") + "/" +
                                  encoded);
      exchanges += 1;
      Array.prototype.push.apply(ocspProblems,
        judgeOcsp(got, label + " (GET, SHA-256)", sha256Id, entry.issuer,
                  null, "good"));
    }
    // A serial this authority never issued.
    const neverId = certIdFor("sha1", entry.subjects[0], entry.issuer,
                              Buffer.concat([Buffer.from([0x7f]),
                                             nodeCrypto.randomBytes(15)]));
    const never = await anonymous(entry.url, {
      method: "POST", headers: { "Content-Type": "application/ocsp-request" },
      body: ocspRequestFor(neverId, null)
    });
    exchanges += 1;
    Array.prototype.push.apply(ocspProblems,
      judgeOcsp(never, entry.url + " for a serial it never issued", neverId,
                entry.issuer, null, "unknown"));

    // A certificate SOMEBODY ELSE issued: RFC 6960 section 2.3 and RFC 5019
    // section 2.2.3 — `unauthorized`, unsigned, because a signed answer about
    // it could not be verified by anybody.
    const stranger = issued.filter(function (parts) {
      return Buffer.compare(parts.issuerRaw, entry.issuer.subjectRaw) !== 0;
    })[0];
    if (stranger) {
      const strangerIssuer = issuerOf(stranger);
      if (strangerIssuer) {
        const foreignId = certIdFor("sha1", stranger, strangerIssuer);
        const foreign = await anonymous(entry.url, {
          method: "POST",
          headers: { "Content-Type": "application/ocsp-request" },
          body: ocspRequestFor(foreignId, null)
        });
        exchanges += 1;
        let status = null;
        try {
          status = ocspResponseParts(foreign.bytes).status;
        } catch (e) {
          log.debug("Caught in test(): " + ((e && e.message) || e));
        }
        if (foreign.status !== 200 || status !== 6) {
          ocspProblems.push(entry.url + ": a request about " +
            stranger.subject + ", which " + strangerIssuer.subject +
            " issued, answered HTTP " + foreign.status + " responseStatus " +
            status + " — expected unauthorized(6) (RFC 6960 section 2.3)");
        }
      }
    }

    // A nonce of 33 octets: RFC 8954 section 2.1 — malformedRequest.
    const longNonce = await anonymous(entry.url, {
      method: "POST", headers: { "Content-Type": "application/ocsp-request" },
      body: ocspRequestFor(certIdFor("sha1", entry.subjects[0], entry.issuer),
                           nodeCrypto.randomBytes(33))
    });
    exchanges += 1;
    let longStatus = null;
    try {
      longStatus = ocspResponseParts(longNonce.bytes).status;
    } catch (e) {
      log.debug("Caught in test(): " + ((e && e.message) || e));
    }
    if (longNonce.status !== 200 || longStatus !== 1) {
      ocspProblems.push(entry.url + ": a 33-octet nonce answered HTTP " +
        longNonce.status + " responseStatus " + longStatus + " — RFC 8954 " +
        "section 2.1 requires malformedRequest(1)");
    }
  }
  check("every OCSP responder (" + byAddress.ocsp.size + ") answers RFC 6960 " +
        "for every certificate naming it, over POST and GET, with the CertID " +
        "and nonce echoed and a signature from the issuer — " + exchanges +
        " exchange(s) — and a GET of the bare address is a refusal naming " +
        "the transports rather than a 404", function () {
          noFailures(ocspProblems, "OCSP problem(s)");
        });

  log.info("=== G. every authority's own endpoints, named by a certificate " +
           "or not (" + index.authorities.length + ") ===");

  // Sections E and F follow what a CERTIFICATE names, which is what a relying
  // party does — and an authority that has issued nothing this job collected
  // (a realm's SPIFFE CA with no SVID in hand, an Issuing CA nobody has used)
  // is named by no certificate here and would be followed by nobody. Its
  // endpoints are still published, and still the addresses the next
  // certificate it signs will carry, so every one of them is followed too.
  const everyProblems = [];
  for (const one of index.authorities) {
    const label = one.scope + "/" + one.ca;
    const caReply = await anonymous(one.caIssuers);
    let authority = null;
    try {
      authority = caReply.status === 200 ? certificateParts(caReply.bytes)
        : null;
    } catch (e) {
      log.debug("Caught in test(): " + ((e && e.message) || e));
    }
    if (!authority) {
      everyProblems.push(label + ": its own certificate is not at " +
                         one.caIssuers + " (HTTP " + caReply.status + ")");
      continue;
    }
    const http = await anonymous(one.crl.http);
    if (http.status !== 200) {
      everyProblems.push(label + ": " + one.crl.http + " answered HTTP " +
                         http.status);
    } else {
      Array.prototype.push.apply(everyProblems,
        judgeCrl(http.bytes, authority, [], label + " " + one.crl.http));
    }
    const ldap = await ldapFetch(one.crl.ldap);
    if (ldap.error || !ldap.values || ldap.values.length !== 1) {
      everyProblems.push(label + ": " + one.crl.ldap + " — " +
        (ldap.error || (ldap.values || []).length + " value(s)"));
    } else {
      Array.prototype.push.apply(everyProblems,
        judgeCrl(ldap.values[0], authority, [], label + " " + one.crl.ldap));
    }
    const bare = await anonymous(one.ocsp);
    if (bare.status !== 400) {
      everyProblems.push(label + ": a GET of " + one.ocsp + " with no " +
                         "request answered " + (bare.status || bare.error));
    }
    // A serial this authority never issued, so the answer is a SIGNED
    // `unknown` whether or not it has issued anything at all.
    const neverId = certIdFor("sha1", authority, authority,
                              Buffer.concat([Buffer.from([0x7e]),
                                             nodeCrypto.randomBytes(15)]));
    const nonce = nodeCrypto.randomBytes(16);
    const posted = await anonymous(one.ocsp, {
      method: "POST", headers: { "Content-Type": "application/ocsp-request" },
      body: ocspRequestFor(neverId, nonce)
    });
    Array.prototype.push.apply(everyProblems,
      judgeOcsp(posted, label + " " + one.ocsp, neverId, authority, nonce,
                "unknown"));
  }
  check("every authority's CRL over http AND ldap and its OCSP responder " +
        "answer to the specifications — " + index.authorities.length +
        " authority(ies), whether or not a collected certificate names them",
        function () {
          noFailures(everyProblems, "problem(s) at an authority's own " +
                     "endpoints");
        });

  if (unverifiable) {
    log.warn(unverifiable + " signature(s) used an algorithm this job does " +
             "not verify and were NOT counted as verified.");
  }
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_pki_distribution_points")
  .description("Follow every CRL distribution point, OCSP responder and " +
      "caIssuers address named by every certificate this service publishes, " +
      "in every trust realm, EXACTLY AS WRITTEN — no port or host is " +
      "substituted — and hold each answer to RFC 5280, RFC 4516/4523 and " +
      "RFC 6960.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
