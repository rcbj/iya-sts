"use strict";
//
// File: test_crl_host.js
//
// ===========================================================================
// A CRL DISTRIBUTION POINT FOR A CERTIFICATE AUTHORITY A TEST MADE, SERVED BY
// THE TEST ITSELF (#174, 2026-09-23).
//
// **WHY IT EXISTS.** Since #174 a product-mode service refuses, under its
// default hard-fail, a certificate from an authority it does not hold that
// names no CRL and no OCSP responder (`pki.revocationRequireDistributionPoint`
// is `auto`, which is `mode.refusesUnrevocableCertificates()`, STS-PKI-0190):
// nobody could ever revoke such a certificate. Every chain this suite minted
// for a remote PEP, an XACML user, a certificate sign-in or an uploaded
// application key was exactly that — a Root, sometimes an Issuing CA, and a
// leaf, none of them naming a list — so each now names one, and this file is
// what answers at the address it names.
//
// **THE LIST IS A REAL ONE, SIGNED BY THE AUTHORITY IT IS ABOUT.** An empty
// RFC 5280 CRL, v2, with a cRLNumber and the authority key identifier, signed
// with the CA's own key through pkijs (the library `common/vendored/x509.js`
// builds the certificates with, reached through the same install so the Web
// Crypto engine `key_material.js` sets up is the one that signs). The service
// fetches it, verifies it against the issuer it walked to, and answers GOOD —
// which is the path a real private CA with a distribution point takes, rather
// than a setting switched off to let the suite through. **Nothing here is
// committed key material**: the CA is made at run time by whoever calls this,
// and this file only ever holds what it is handed.
//
// **WHERE IT LISTENS.** On 0.0.0.0, an ephemeral port, in the JOB'S process —
// the service dials it back at `OUTBOUND_TEST_HOST` or `GNAP_PUSH_HOST` (the
// runner's name on the compose network, `tests`), which is the address
// `sts_outbound_tls.js` and the GNAP push jobs already stand their listeners
// on, for the same reason. `localhost` when neither is set: a hand run against
// a service on the same host. The server is `unref()`ed, so it never keeps a
// job alive. A job that mints a chain and exits takes its list with it, which
// is right: its certificates are not presented after it has gone.
//
// **A CREDENTIAL THAT OUTLIVES ITS MINTER** — the launcher's remote PEP
// credential, which `tests/tools/pep-credential.js` writes and exits — cannot
// be served from here. That tool writes the lists beside the credential
// instead (`crlFor()` below is what builds them) and the PEP container serves
// them (`xacml-pep/pep.js`, `GET /crl/<name>.crl`).
//
// `local: true` in spirit — LOCAL_HELPERS in MANIFEST.js — because the parent
// project's jobs present no chain to a product-mode service.
// ===========================================================================

const http = require("http");
const path = require("path");
const nodeCrypto = require("crypto");

const log = require("bunyan").createLogger({ name: "test_crl_host",
  level: process.env.LOG_LEVEL || "info" });

const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
// Required for its side effect as well: it installs the Web Crypto engine the
// pkijs below signs with. The same install `x509.js` uses, resolved from the
// vendored directory so that it IS the same instance.
require(path.join(REPO, "common", "vendored", "key_material.js"));
const VENDORED = path.join(REPO, "common", "vendored");
const pkijs = require(require.resolve("pkijs", { paths: [VENDORED] }));
const asn1js = require(require.resolve("asn1js", { paths: [VENDORED] }));

// The name the SERVICE reaches this process by. See the header.
function hostName() {
  log.debug("Entering hostName().");
  log.debug("Leaving hostName().");
  return String(process.env.OUTBOUND_TEST_HOST ||
                process.env.GNAP_PUSH_HOST || "localhost");
}

function arrayBufferOf(buf) {
  log.debug("Entering arrayBufferOf().");
  log.debug("Leaving arrayBufferOf().");
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

function derOfPem(pem) {
  log.debug("Entering derOfPem().");
  const body = String(pem).match(
    /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/);
  if (!body) {
    log.debug("Leaving derOfPem(). No certificate.");
    throw new Error("not a PEM certificate");
  }
  log.debug("Leaving derOfPem().");
  return Buffer.from(body[1].replace(/\s+/g, ""), "base64");
}

// The Web Crypto algorithm for a private key in any PEM spelling (PKCS#8, or
// PKCS#1 as node-forge writes it), and the key as PKCS#8 for importKey().
async function signingKeyOf(privateKeyPem) {
  log.debug("Entering signingKeyOf().");
  const key = nodeCrypto.createPrivateKey(String(privateKeyPem));
  const pkcs8 = key.export({ type: "pkcs8", format: "der" });
  let algorithm;
  if (key.asymmetricKeyType === "rsa") {
    algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  } else if (key.asymmetricKeyType === "ec") {
    const curve = key.asymmetricKeyDetails &&
                  key.asymmetricKeyDetails.namedCurve;
    const named = { prime256v1: "P-256", secp384r1: "P-384",
                    secp521r1: "P-521" }[curve] || "P-256";
    algorithm = { name: "ECDSA", namedCurve: named };
  } else {
    log.debug("Leaving signingKeyOf(). Unsupported.");
    throw new Error("a CRL is signed here with an RSA or EC key, and this " +
                    "is " + key.asymmetricKeyType);
  }
  const imported = await nodeCrypto.webcrypto.subtle.importKey("pkcs8",
    arrayBufferOf(pkcs8), algorithm, false, ["sign"]);
  log.debug("Leaving signingKeyOf().");
  return imported;
}

// AN EMPTY CRL signed by `ca` — `{ pem | certificatePem, privateKeyPem }` —
// fresh for `days` (1 by default). DER bytes.
async function crlFor(ca, options) {
  log.debug("Entering crlFor().");
  const opts = options || {};
  const caPem = ca.pem || ca.certificatePem || ca.certPem || ca.caPem;
  const keyPem = ca.privateKeyPem || ca.privatePem || ca.key || ca.keyPem;
  const issuerCert = pkijs.Certificate.fromBER(arrayBufferOf(derOfPem(caPem)));
  const crl = new pkijs.CertificateRevocationList();
  crl.version = 1;
  crl.issuer = issuerCert.subject;
  const now = Date.now();
  crl.thisUpdate = new pkijs.Time({ type: 0, value: new Date(now - 60000) });
  crl.nextUpdate = new pkijs.Time({ type: 0,
    value: new Date(now + (opts.days || 1) * 24 * 3600 * 1000) });
  const extensions = [
    new pkijs.Extension({ extnID: "2.5.29.20", critical: false,
      extnValue: new asn1js.Integer({ value: 1 }).toBER(false) })
  ];
  const ski = (issuerCert.extensions || []).filter(function (one) {
    return one.extnID === "2.5.29.14";
  })[0];
  if (ski && ski.parsedValue) {
    extensions.push(new pkijs.Extension({ extnID: "2.5.29.35",
      critical: false,
      extnValue: new pkijs.AuthorityKeyIdentifier({
        keyIdentifier: new asn1js.OctetString({
          valueHex: ski.parsedValue.valueBlock.valueHexView })
      }).toSchema().toBER(false) }));
  }
  crl.crlExtensions = new pkijs.Extensions({ extensions: extensions });
  await crl.sign(await signingKeyOf(keyPem), "SHA-256");
  log.debug("Leaving crlFor().");
  return Buffer.from(crl.toSchema(true).toBER(false));
}

// ONE SERVER PER PROCESS, started on first use.
let hostPromise = null;

function crlHost() {
  log.debug("Entering crlHost().");
  if (hostPromise) {
    log.debug("Leaving crlHost(). Already listening.");
    return hostPromise;
  }
  const documents = {};
  const server = http.createServer(function (req, res) {
    const body = documents[String(req.url || "").split("?")[0]];
    if (!body || req.method !== "GET") {
      // error-code: none — a test fixture, not the service
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, { "Content-Type": "application/pkix-crl",
                         "Content-Length": String(body.length) });
    res.end(body);
  });
  hostPromise = new Promise(function (resolve, reject) {
    server.on("error", reject);
    server.listen(0, "0.0.0.0", function () {
      server.unref();
      const name = hostName();
      const base = "http://" + (name.indexOf(":") >= 0 ? "[" + name + "]"
                                                       : name) +
                   ":" + server.address().port;
      log.info("A CRL distribution point for this job's own CAs is " +
               "listening at " + base + ".");
      resolve({
        base: base,
        publish: function (route, der) {
          log.debug("Entering publish(). " + route);
          documents[route] = der;
          log.debug("Leaving publish().");
          return base + route;
        },
        close: function () {
          log.debug("Entering close().");
          server.close();
          log.debug("Leaving close().");
        }
      });
    });
  });
  log.debug("Leaving crlHost().");
  return hostPromise;
}

// A FRESH ADDRESS FOR A LIST NOT YET SIGNED: the child certificate has to name
// the URL before the list exists, which is only an ordering problem because
// the CA signs both. `{ url, publish(ca) }`.
async function reserve(label) {
  log.debug("Entering reserve().");
  const host = await crlHost();
  const route = "/crl/" + String(label || "ca").replace(/[^a-z0-9-]/gi, "-") +
                "-" + nodeCrypto.randomBytes(6).toString("hex") + ".crl";
  log.debug("Leaving reserve().");
  return {
    url: host.base + route,
    publish: async function (ca, options) {
      log.debug("Entering publish().");
      host.publish(route, await crlFor(ca, options));
      log.debug("Leaving publish().");
    }
  };
}

module.exports = {
  hostName: hostName,
  crlFor: crlFor,
  crlHost: crlHost,
  reserve: reserve
};
