"use strict";
//
// File: est_client.js
//
// ===========================================================================
// AN EST CLIENT WRITTEN FROM RFC 7030 AND RFC 8951, WITH NOTHING FROM est/
// (2026-09-13).
//
// `tests/vendored/sts_est_enrollment.js` drives the service's EST server with
// this module, and the value of that job rests on this file being a SECOND
// READING of the RFCs rather than the server's own codec called from a test: a
// certs-only message the server builds and the server's own reader accepts
// proves only that one implementation agrees with itself.
//
// So it requires nothing from `est/`, `common/cert_enrollment.js` or any other
// server module. It uses node's `https` and `crypto`, and — for building a
// PKCS#10 request over a real key pair — the parent project's vendored
// `x509.js` and `key_material.js`, which is the independent PKI code
// `sts_user_credentials.js` builds its certificates with. Everything EST adds
// on the wire is written out below: the DER reader that walks a certs-only
// SignedData, a CSR attributes response and a CRL; the multipart parser; the
// Basic header; and a CSR for a KEY-ENCAPSULATION key, which the vendored
// builder refuses to make (it cannot prove possession) and a /serverkeygen
// TEMPLATE legitimately carries.
// ===========================================================================

const https = require("https");
const http = require("http");
const nodeCrypto = require("crypto");

let log = null;
try {
  log = require("bunyan").createLogger({ name: "est_client",
    level: process.env.LOG_LEVEL || "info" });
} catch (e) {
  // No bunyan (a hand run outside the suite): a console-backed logger of the
  // same shape, so the Entering/Leaving lines still have somewhere to go.
  log = { debug: function () {}, info: console.log, warn: console.warn,
          error: console.error };
  log.debug("Caught loading bunyan: " + ((e && e.message) || e));
}

// ---------------------------------------------------------------------------
// DER, READ AND WRITTEN.
// ---------------------------------------------------------------------------
function readTlv(buf, offset) {
  log.debug("Entering readTlv().");
  if (offset + 2 > buf.length) {
    log.debug("Leaving readTlv(). Truncated.");
    throw new Error("DER truncated at " + offset);
  }
  const tag = buf[offset];
  let length = buf[offset + 1];
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) {
      log.debug("Leaving readTlv(). Unsupported length.");
      throw new Error("unsupported DER length form at " + offset);
    }
    length = 0;
    for (let i = 0; i < count; i++) {
      length = length * 256 + buf[offset + 2 + i];
    }
    header = 2 + count;
  }
  const start = offset + header;
  if (start + length > buf.length) {
    log.debug("Leaving readTlv(). Overruns.");
    throw new Error("DER value overruns its buffer at " + offset);
  }
  log.debug("Leaving readTlv().");
  return { tag: tag, start: start, end: start + length, offset: offset,
           content: buf.slice(start, start + length),
           raw: buf.slice(offset, start + length) };
}

// The children of a constructed value.
function children(buf) {
  log.debug("Entering children().");
  const out = [];
  let at = 0;
  while (at < buf.length) {
    const one = readTlv(buf, at);
    out.push(one);
    at = one.end;
  }
  log.debug("Leaving children(). " + out.length);
  return out;
}

function oidText(content) {
  log.debug("Entering oidText().");
  const arcs = [];
  let value = 0;
  for (let i = 0; i < content.length; i++) {
    value = value * 128 + (content[i] & 0x7f);
    if (!(content[i] & 0x80)) {
      arcs.push(value);
      value = 0;
    }
  }
  const first = Math.min(2, Math.floor(arcs[0] / 40));
  log.debug("Leaving oidText().");
  return [first, arcs[0] - first * 40].concat(arcs.slice(1)).join(".");
}

function lengthBytes(n) {
  log.debug("Entering lengthBytes().");
  if (n < 128) {
    log.debug("Leaving lengthBytes().");
    return Buffer.from([n]);
  }
  const out = [];
  let rest = n;
  while (rest > 0) {
    out.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  }
  log.debug("Leaving lengthBytes().");
  return Buffer.from([0x80 | out.length].concat(out));
}

function tlv(tag, parts) {
  log.debug("Entering tlv().");
  const body = Buffer.concat([].concat(parts).map(function (p) {
    return Buffer.from(p);
  }));
  log.debug("Leaving tlv().");
  return Buffer.concat([Buffer.from([tag]), lengthBytes(body.length), body]);
}

function oidDer(dotted) {
  log.debug("Entering oidDer().");
  const arcs = dotted.split(".").map(Number);
  const bytes = [];
  [arcs[0] * 40 + arcs[1]].concat(arcs.slice(2)).forEach(function (arc) {
    const septets = [arc & 0x7f];
    let rest = Math.floor(arc / 128);
    while (rest > 0) {
      septets.unshift((rest & 0x7f) | 0x80);
      rest = Math.floor(rest / 128);
    }
    septets.forEach(function (s) {
      bytes.push(s);
    });
  });
  log.debug("Leaving oidDer().");
  return tlv(0x06, Buffer.from(bytes));
}

function pemBody(pem) {
  log.debug("Entering pemBody().");
  log.debug("Leaving pemBody().");
  return Buffer.from(String(pem).replace(/-----[^-]+-----/g, "")
    .replace(/\s+/g, ""), "base64");
}

function derToPem(der, label) {
  log.debug("Entering derToPem().");
  const text = Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n")
    .replace(/\n$/, "");
  log.debug("Leaving derToPem().");
  return "-----BEGIN " + label + "-----\n" + text + "\n-----END " + label +
         "-----\n";
}

// ---------------------------------------------------------------------------
// RESPONSE BODIES.
// ---------------------------------------------------------------------------

// RFC 8951: a response body is base64 and a client strips the whitespace.
function base64Body(body) {
  log.debug("Entering base64Body().");
  const text = Buffer.from(body).toString("latin1").replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    log.debug("Leaving base64Body(). Not base64.");
    throw new Error("response body is not base64: " + text.slice(0, 80));
  }
  log.debug("Leaving base64Body().");
  return Buffer.from(text, "base64");
}

// A certs-only CMS message (RFC 5652 section 5, RFC 7030 section 4.1.3) — the
// certificates, each exactly as encoded, as PEM. Throws on anything that is not
// a SignedData with no signer.
function parseCertsOnly(der) {
  log.debug("Entering parseCertsOnly().");
  const contentInfo = readTlv(der, 0);
  const top = children(contentInfo.content);
  if (top[0].tag !== 0x06 || oidText(top[0].content) !==
      "1.2.840.113549.1.7.2") {
    log.debug("Leaving parseCertsOnly(). Not SignedData.");
    throw new Error("not a CMS SignedData");
  }
  const explicit = top[1];
  const signedData = children(readTlv(explicit.content, 0).content);
  let certificates = [];
  let signerInfos = null;
  signedData.forEach(function (field) {
    if (field.tag === 0xa0) {
      certificates = children(field.content).map(function (one) {
        return derToPem(one.raw, "CERTIFICATE");
      });
    }
    if (field.tag === 0x31) {
      signerInfos = children(field.content);
    }
  });
  log.debug("Leaving parseCertsOnly(). " + certificates.length);
  return { version: signedData[0].content[0], certificates: certificates,
           signerCount: signerInfos ? signerInfos.length : -1 };
}

// application/csrattrs (RFC 7030 section 4.5.2): SEQUENCE OF AttrOrOID.
function parseCsrAttrs(der) {
  log.debug("Entering parseCsrAttrs().");
  const out = children(readTlv(der, 0).content).map(function (item) {
    if (item.tag === 0x06) {
      return { oid: oidText(item.content) };
    }
    const parts = children(item.content);
    return { type: oidText(parts[0].content),
             values: children(parts[1].content).map(function (value) {
               return value.tag === 0x06 ? { oid: oidText(value.content) }
                 : { text: value.content.toString("utf8") };
             }) };
  });
  log.debug("Leaving parseCsrAttrs(). " + out.length);
  return out;
}

// The serial numbers a CRL lists (RFC 5280 section 5.1), lower-case hex with no
// leading zeros.
function crlSerials(der) {
  log.debug("Entering crlSerials().");
  const certList = children(readTlv(der, 0).content);
  const tbs = children(certList[0].content);
  let at = 0;
  if (tbs[at].tag === 0x02) {
    at++;
  }
  at += 3; // signature, issuer, thisUpdate
  if (tbs[at] && (tbs[at].tag === 0x17 || tbs[at].tag === 0x18)) {
    at++; // nextUpdate, which is OPTIONAL in the ASN.1
  }
  const serials = [];
  const revoked = tbs[at];
  if (revoked && revoked.tag === 0x30) {
    children(revoked.content).forEach(function (entry) {
      const serial = children(entry.content)[0];
      serials.push(serial.content.toString("hex").replace(/^0+(?=.)/, ""));
    });
  }
  log.debug("Leaving crlSerials(). " + serials.length);
  return serials;
}

// The SubjectPublicKeyInfo algorithm OID of a certificate, read from its DER —
// for a key node cannot parse (ML-KEM).
function certificateKeyOid(pem) {
  log.debug("Entering certificateKeyOid().");
  const tbs = children(children(readTlv(pemBody(pem), 0).content)[0].content);
  const first = tbs[0].tag === 0xa0 ? 1 : 0;
  const spki = children(tbs[first + 5].content);
  log.debug("Leaving certificateKeyOid().");
  return oidText(children(spki[0].content)[0].content);
}

// The algorithm OID in a PKCS#8 PrivateKeyInfo (RFC 5958).
function pkcs8KeyOid(der) {
  log.debug("Entering pkcs8KeyOid().");
  const info = children(readTlv(der, 0).content);
  log.debug("Leaving pkcs8KeyOid().");
  return oidText(children(info[1].content)[0].content);
}

// multipart/mixed (RFC 2046), each part base64 (RFC 8951 section 3.2). Written
// here rather than taken from a library, because the part headers are exactly
// what the RFC clarified and a library that ignored them would hide a server
// that got them wrong.
function parseMultipart(contentType, body) {
  log.debug("Entering parseMultipart().");
  const match = /boundary="?([^";]+)"?/i.exec(String(contentType || ""));
  if (!/^multipart\/mixed/i.test(String(contentType || "")) || !match) {
    log.debug("Leaving parseMultipart(). Not multipart/mixed.");
    throw new Error("not multipart/mixed with a boundary: " + contentType);
  }
  const delimiter = "--" + match[1];
  const text = Buffer.from(body).toString("latin1");
  const pieces = text.split(delimiter);
  const parts = [];
  for (let i = 1; i < pieces.length; i++) {
    const piece = pieces[i];
    if (piece.indexOf("--") === 0) {
      break;
    }
    const split = piece.indexOf("\r\n\r\n");
    const headerText = piece.slice(0, split).replace(/^\r\n/, "");
    const headers = {};
    headerText.split("\r\n").forEach(function (line) {
      const colon = line.indexOf(":");
      if (colon > 0) {
        headers[line.slice(0, colon).trim().toLowerCase()] =
          line.slice(colon + 1).trim();
      }
    });
    parts.push({ headers: headers,
                 der: base64Body(Buffer.from(piece.slice(split + 4),
                                             "latin1")) });
  }
  log.debug("Leaving parseMultipart(). " + parts.length);
  return parts;
}

// ---------------------------------------------------------------------------
// REQUESTS.
// ---------------------------------------------------------------------------

// Base64 of a DER request at 64 characters a line, as an EST client sends it.
function requestBody(der) {
  log.debug("Entering requestBody().");
  log.debug("Leaving requestBody().");
  return Buffer.from(Buffer.from(der).toString("base64")
    .replace(/(.{64})/g, "$1\r\n"), "latin1");
}

function basicHeader(username, password) {
  log.debug("Entering basicHeader().");
  log.debug("Leaving basicHeader().");
  return "Basic " + Buffer.from(username + ":" + password, "utf8")
    .toString("base64");
}

// One request, with its own agent so a client certificate is never reused
// from a pooled connection. The TLS anchor is NODE_EXTRA_CA_CERTS.
//   opts: { method, url, headers, body, basic: [user, pass], key, cert }
function send(opts) {
  log.debug("Entering send(). " + opts.method + " " + opts.url);
  return new Promise(function (resolve, reject) {
    const url = new URL(opts.url);
    const mod = url.protocol === "https:" ? https : http;
    const headers = Object.assign({}, opts.headers || {});
    if (opts.basic) {
      headers.Authorization = basicHeader(opts.basic[0], opts.basic[1]);
    }
    if (opts.body) {
      headers["Content-Length"] = String(Buffer.byteLength(opts.body));
    }
    const agentOptions = { keepAlive: false };
    if (opts.key && opts.cert) {
      agentOptions.key = opts.key;
      agentOptions.cert = opts.cert;
    }
    const request = mod.request(url, {
      method: opts.method,
      headers: headers,
      agent: url.protocol === "https:" ? new https.Agent(agentOptions)
                                       : undefined
    }, function (response) {
      const chunks = [];
      response.on("data", function (chunk) {
        chunks.push(chunk);
      });
      response.on("end", function () {
        resolve({ status: response.statusCode, headers: response.headers,
                  body: Buffer.concat(chunks) });
      });
    });
    request.on("error", reject);
    if (opts.body) {
      request.write(opts.body);
    }
    request.end();
    log.debug("Leaving send(). Sent.");
  });
}

// ---------------------------------------------------------------------------
// A CERTIFICATION REQUEST FOR A KEY-ENCAPSULATION KEY.
//
// RFC 7030 section 4.4.1.1 makes a /serverkeygen request a TEMPLATE whose key
// the server replaces, and RFC 9935 section 7 says an ML-KEM key cannot prove
// possession. So this builds CertificationRequestInfo { 0, subject, the KEM
// SubjectPublicKeyInfo, [0] {} } and signs it with an unrelated EC key: the
// signature is well formed and proves nothing, which is what a template's is.
// ---------------------------------------------------------------------------
function kemTemplateCsr(publicKeyPem, commonName) {
  log.debug("Entering kemTemplateCsr().");
  const name = tlv(0x30, tlv(0x31, tlv(0x30, [oidDer("2.5.4.3"),
    tlv(0x0c, Buffer.from(commonName, "utf8"))])));
  const info = tlv(0x30, [tlv(0x02, Buffer.from([0])), name,
                          pemBody(publicKeyPem), tlv(0xa0, Buffer.alloc(0))]);
  const signer = nodeCrypto.generateKeyPairSync("ec",
                                                { namedCurve: "P-256" });
  const signature = nodeCrypto.sign("sha256", info, signer.privateKey);
  const der = tlv(0x30, [info, tlv(0x30, oidDer("1.2.840.10045.4.3.2")),
    tlv(0x03, Buffer.concat([Buffer.from([0]), signature]))]);
  log.debug("Leaving kemTemplateCsr().");
  return der;
}

module.exports = {
  readTlv: readTlv,
  children: children,
  oidText: oidText,
  pemBody: pemBody,
  derToPem: derToPem,
  base64Body: base64Body,
  parseCertsOnly: parseCertsOnly,
  parseCsrAttrs: parseCsrAttrs,
  crlSerials: crlSerials,
  certificateKeyOid: certificateKeyOid,
  pkcs8KeyOid: pkcs8KeyOid,
  parseMultipart: parseMultipart,
  requestBody: requestBody,
  basicHeader: basicHeader,
  send: send,
  kemTemplateCsr: kemTemplateCsr
};
