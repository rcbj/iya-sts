"use strict";
//
// File: scep_client.js
//
// ---------------------------------------------------------------------------
// A SCEP CLIENT (RFC 8894), WRITTEN FOR THE TESTS AND SHARING NO CODE WITH
// `scep/` OR `common/cert_enrollment.js`.
//
// `tests/vendored/sts_scep_enrollment.js` asserts what mock-sts does over the
// wire, and the property that makes such a job worth running is that the two
// ends of the exchange are INDEPENDENT implementations: a CMS structure built
// and read by one codec verifies perfectly and interoperates with nobody. So
// this file builds a pkiMessage from the RFC with node-forge — the library
// every javascript SCEP client uses — and node's crypto:
//
//   * the PKCS#10 request and the throwaway self-signed signer certificate are
//     forge's (`forge.pki`), so an RSA CSR here is the one a real device sends;
//   * the pkcsPKIEnvelope is forge's `pkcs7.createEnvelopedData()`, RSA
//     PKCS#1 v1.5 key transport, and the reply's envelope is opened with
//     forge's own decrypt;
//   * the SignedData is written by hand with `forge.asn1` and signed with
//     node's `crypto.sign`, because forge's signer cannot carry the SCEP
//     attributes and cannot sign with an ECDSA key — which one negative case
//     needs;
//   * a CertRep is read with `forge.asn1` and its signature checked with node.
//
// The certificate helpers for the EC cases use the vendored parent-project
// encoder (`common/vendored/x509.js`), which is that project's independent PKI
// code and not this service's, as `sts_user_credentials.js` does.
//
// It is a LOCAL HELPER (tests/vendored/MANIFEST.js), owned here.
// ---------------------------------------------------------------------------

const nodeCrypto = require("crypto");
const forge = require("node-forge");

const log = require("bunyan").createLogger({ name: "scep_client",
  level: process.env.LOG_LEVEL || "info" });

const asn1 = forge.asn1;

const OID = {
  data: "1.2.840.113549.1.7.1",
  signedData: "1.2.840.113549.1.7.2",
  envelopedData: "1.2.840.113549.1.7.3",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingTime: "1.2.840.113549.1.9.5",
  challengePassword: "1.2.840.113549.1.9.7",
  sha256: "2.16.840.1.101.3.4.2.1",
  sha512: "2.16.840.1.101.3.4.2.3",
  sha1: "1.3.14.3.2.26",
  rsaEncryption: "1.2.840.113549.1.1.1",
  sha256WithRSA: "1.2.840.113549.1.1.11",
  ecdsaWithSha256: "1.2.840.10045.4.3.2",
  messageType: "2.16.840.1.113733.1.9.2",
  pkiStatus: "2.16.840.1.113733.1.9.3",
  failInfo: "2.16.840.1.113733.1.9.4",
  senderNonce: "2.16.840.1.113733.1.9.5",
  recipientNonce: "2.16.840.1.113733.1.9.6",
  transactionID: "2.16.840.1.113733.1.9.7"
};

const MESSAGE_TYPE = { CertRep: "3", RenewalReq: "17", PKCSReq: "19",
                       CertPoll: "20", GetCert: "21", GetCRL: "22" };

const FAIL_INFO_NAMES = { 0: "badAlg", 1: "badMessageCheck", 2: "badRequest",
                          3: "badTime", 4: "badCertId" };

function bin(buf) {
  log.debug("Entering bin().");
  log.debug("Leaving bin().");
  return Buffer.from(buf).toString("binary");
}

function buf(binary) {
  log.debug("Entering buf().");
  log.debug("Leaving buf().");
  return Buffer.from(binary, "binary");
}

function derOf(node) {
  log.debug("Entering derOf().");
  log.debug("Leaving derOf().");
  return buf(asn1.toDer(node).getBytes());
}

function seq(items) {
  log.debug("Entering seq().");
  log.debug("Leaving seq().");
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, items);
}

function set(items) {
  log.debug("Entering set().");
  log.debug("Leaving set().");
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, items);
}

function oid(value) {
  log.debug("Entering oid().");
  log.debug("Leaving oid().");
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                     asn1.oidToDer(value).getBytes());
}

function octets(bytes) {
  log.debug("Entering octets().");
  log.debug("Leaving octets().");
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                     bin(bytes));
}

function integer(n) {
  log.debug("Entering integer().");
  log.debug("Leaving integer().");
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
                     asn1.integerToDer(n).getBytes());
}

function printable(text) {
  log.debug("Entering printable().");
  log.debug("Leaving printable().");
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.PRINTABLESTRING, false,
                     String(text));
}

function explicit(tag, inner) {
  log.debug("Entering explicit().");
  log.debug("Leaving explicit().");
  return asn1.create(asn1.Class.CONTEXT_SPECIFIC, tag, true, [inner]);
}

function pemBody(pem) {
  log.debug("Entering pemBody().");
  log.debug("Leaving pemBody().");
  return Buffer.from(String(pem).replace(/-----[^-]+-----/g, "")
    .replace(/\s+/g, ""), "base64");
}

// ---------------------------------------------------------------------------
// KEYS, CERTIFICATES, REQUESTS.
// ---------------------------------------------------------------------------
function rsaKey(bits) {
  log.debug("Entering rsaKey().");
  const pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: bits || 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  log.debug("Leaving rsaKey().");
  return { privateKeyPem: pair.privateKey, publicKeyPem: pair.publicKey };
}

// A throwaway self-signed certificate over an RSA key, as RFC 8894 section 2.3
// has a requester make before it holds a certificate.
function selfSigned(key, commonName) {
  log.debug("Entering selfSigned().");
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(key.publicKeyPem);
  cert.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  const attrs = [{ name: "commonName", value: commonName || "scep device" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(forge.pki.privateKeyFromPem(key.privateKeyPem),
            forge.md.sha256.create());
  log.debug("Leaving selfSigned().");
  return forge.pki.certificateToPem(cert);
}

// A PKCS#10 request. `sans` is a list of { type: 'dns'|'uri'|'email'|'ip',
// value }. `challenge` becomes the challengePassword attribute, UTF8String.
function csr(key, options) {
  log.debug("Entering csr().");
  const opts = options || {};
  const request = forge.pki.createCertificationRequest();
  request.publicKey = forge.pki.publicKeyFromPem(key.publicKeyPem);
  request.setSubject([{ name: "commonName",
                        value: opts.commonName || "scep device" }]);
  const attributes = [];
  if (opts.challenge) {
    attributes.push({ name: "challengePassword", value: opts.challenge });
  }
  const types = { email: 1, dns: 2, uri: 6, ip: 7 };
  if ((opts.sans || []).length) {
    attributes.push({ name: "extensionRequest", extensions: [{
      name: "subjectAltName",
      altNames: opts.sans.map(function (one) {
        return one.type === "ip" ? { type: 7, ip: one.value }
                                 : { type: types[one.type], value: one.value };
      })
    }] });
  }
  request.setAttributes(attributes);
  request.sign(forge.pki.privateKeyFromPem(key.privateKeyPem),
               forge.md.sha256.create());
  log.debug("Leaving csr().");
  return buf(asn1.toDer(forge.pki.certificationRequestToAsn1(request))
    .getBytes());
}

// ---------------------------------------------------------------------------
// THE pkcsPKIEnvelope, with forge.
// ---------------------------------------------------------------------------
function envelope(content, recipientPem, cipher) {
  log.debug("Entering envelope().");
  const p7 = forge.pkcs7.createEnvelopedData();
  p7.addRecipient(forge.pki.certificateFromPem(recipientPem));
  p7.content = forge.util.createBuffer(bin(content));
  const algorithm = { aes128: forge.pki.oids["aes128-CBC"],
                      aes256: forge.pki.oids["aes256-CBC"],
                      des3: forge.pki.oids["des-EDE3-CBC"] }[cipher ||
                                                            "aes256"];
  p7.encrypt(undefined, algorithm);
  log.debug("Leaving envelope().");
  return derOf(p7.toAsn1());
}

// ---------------------------------------------------------------------------
// THE pkiMessage SignedData, by hand.
//
//   spec.content          the envelope DER (or any bytes, for a negative)
//   spec.signerCertPem    the certificate that signs, included in the message
//   spec.signerKeyPem     its private key (RSA or EC)
//   spec.messageType      '19', '17', '20', '21', '22' or anything
//   spec.transactionID    text
//   spec.senderNonce      Buffer (16 bytes unless a negative says otherwise)
//   spec.digest           'sha256' (default) | 'sha512' | 'sha1'
//   spec.omitCertificate  leave the signer certificate out
// ---------------------------------------------------------------------------
function signedMessage(spec) {
  log.debug("Entering signedMessage().");
  const digest = spec.digest || "sha256";
  const digestOid = { sha256: OID.sha256, sha512: OID.sha512,
                      sha1: OID.sha1 }[digest];
  const content = Buffer.from(spec.content || Buffer.alloc(0));
  const key = nodeCrypto.createPrivateKey(spec.signerKeyPem);
  const ec = key.asymmetricKeyType === "ec";
  const attrs = [
    seq([oid(OID.contentType), set([oid(OID.data)])]),
    seq([oid(OID.messageDigest), set([octets(nodeCrypto.createHash(digest)
      .update(content).digest())])]),
    seq([oid(OID.messageType), set([printable(spec.messageType)])]),
    seq([oid(OID.transactionID), set([printable(spec.transactionID)])]),
    seq([oid(OID.senderNonce), set([octets(spec.senderNonce ||
                                           nodeCrypto.randomBytes(16))])])
  ].map(derOf).sort(Buffer.compare);
  const attrSet = Buffer.concat([Buffer.from([0x31]), lengthOf(attrs),
                                 Buffer.concat(attrs)]);
  const signature = nodeCrypto.sign(digest, attrSet, key);
  const implicitAttrs = Buffer.from(attrSet);
  implicitAttrs[0] = 0xa0;
  const named = issuerAndSerialParts(spec.signerCertPem);
  const issuerAndSerial = seq([asn1.fromDer(bin(named.issuer)),
                               asn1.fromDer(bin(named.serial))]);
  const signerInfo = seq([
    integer(1),
    issuerAndSerial,
    seq([oid(digestOid)]),
    asn1.fromDer(bin(implicitAttrs)),
    seq(ec ? [oid(OID.ecdsaWithSha256)]
           : [oid(OID.rsaEncryption),
              asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, "")]),
    octets(signature)
  ]);
  const sd = [
    integer(1),
    set([seq([oid(digestOid)])]),
    seq([oid(OID.data), explicit(0, octets(content))])
  ];
  if (!spec.omitCertificate) {
    sd.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true,
      [asn1.fromDer(bin(pemBody(spec.signerCertPem)))]));
  }
  sd.push(set([signerInfo]));
  log.debug("Leaving signedMessage().");
  return derOf(seq([oid(OID.signedData), explicit(0, seq(sd))]));
}

function lengthOf(parts) {
  log.debug("Entering lengthOf().");
  const n = parts.reduce(function (sum, one) { return sum + one.length; }, 0);
  if (n < 128) {
    log.debug("Leaving lengthOf(). Short.");
    return Buffer.from([n]);
  }
  const bytes = [];
  let rest = n;
  while (rest > 0) {
    bytes.unshift(rest & 0xff);
    rest = rest >> 8;
  }
  log.debug("Leaving lengthOf(). Long.");
  return Buffer.from([0x80 | bytes.length].concat(bytes));
}

// The issuer Name and serial INTEGER of a certificate, as the bytes it carries
// — read with the TLV walker below rather than through forge.pki, which reads
// an RSA certificate only and one negative case signs with an EC key.
function issuerAndSerialParts(certPem) {
  log.debug("Entering issuerAndSerialParts().");
  const bytes = pemBody(certPem);
  const tbs = kids(bytes, kids(bytes, tlv(bytes, 0))[0]);
  const at = tbs[0].tag === 0xa0 ? 1 : 0;
  log.debug("Leaving issuerAndSerialParts().");
  return { serial: tbs[at].raw, issuer: tbs[at + 2].raw,
           subject: tbs[at + 4].raw };
}

// IssuerAndSerialNumber / IssuerAndSubject for CertPoll, GetCert and GetCRL.
function issuerAndSerial(certPem) {
  log.debug("Entering issuerAndSerial().");
  const named = issuerAndSerialParts(certPem);
  log.debug("Leaving issuerAndSerial().");
  return derOf(seq([asn1.fromDer(bin(named.issuer)),
                    asn1.fromDer(bin(named.serial))]));
}

function issuerAndSubject(issuerPem, subjectCommonName) {
  log.debug("Entering issuerAndSubject().");
  const issuer = issuerAndSerialParts(issuerPem);
  const subject = forge.pki.createCertificate();
  subject.setSubject([{ name: "commonName", value: subjectCommonName }]);
  log.debug("Leaving issuerAndSubject().");
  return derOf(seq([asn1.fromDer(bin(issuer.subject)),
                    forge.pki.distinguishedNameToAsn1(subject.subject)]));
}

// ---------------------------------------------------------------------------
// READ A REPLY.
//
// **WITH A TLV WALKER OVER THE BYTES, NOT forge's ASN.1 TREE.** forge decodes
// a BIT STRING that looks like DER into children and re-encodes a certificate
// from its own model, so a certificate or a signed-attribute set that passed
// through it comes back as DIFFERENT BYTES — and a signature over the original
// no longer verifies. The first run of the job met exactly that ("the RA is not
// a leaf of the SCEP Issuing CA"). A signature is checked over the bytes that
// arrived, so the bytes are sliced, never rebuilt.
// ---------------------------------------------------------------------------
function tlv(bytes, at) {
  log.debug("Entering tlv().");
  const lead = bytes[at + 1];
  let header = 2;
  let length = lead;
  if (lead === 0x80) {
    log.debug("Leaving tlv(). Indefinite.");
    throw new Error("an indefinite length in a DER reply");
  }
  if (lead > 0x80) {
    const n = lead & 0x7f;
    length = 0;
    for (let i = 0; i < n; i++) {
      length = length * 256 + bytes[at + 2 + i];
    }
    header = 2 + n;
  }
  log.debug("Leaving tlv().");
  return { tag: bytes[at], start: at, header: header,
           end: at + header + length,
           raw: bytes.slice(at, at + header + length),
           value: bytes.slice(at + header, at + header + length) };
}

function kids(bytes, node) {
  log.debug("Entering kids().");
  const out = [];
  let at = node.start + node.header;
  while (at < node.end) {
    const one = tlv(bytes, at);
    out.push(one);
    at = one.end;
  }
  log.debug("Leaving kids().");
  return out;
}

function oidText(value) {
  log.debug("Entering oidText().");
  log.debug("Leaving oidText().");
  return asn1.derToOid(forge.util.createBuffer(bin(value)));
}

function toPem(der) {
  log.debug("Entering toPem().");
  log.debug("Leaving toPem().");
  return "-----BEGIN CERTIFICATE-----\n" +
    Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n")
      .replace(/\n$/, "") + "\n-----END CERTIFICATE-----\n";
}

// The SignedData inside a ContentInfo, as its children.
function signedDataOf(der) {
  log.debug("Entering signedDataOf().");
  const bytes = Buffer.from(der);
  const ci = tlv(bytes, 0);
  const parts = kids(bytes, ci);
  if (oidText(parts[0].value) !== OID.signedData) {
    log.debug("Leaving signedDataOf(). Not SignedData.");
    throw new Error("the reply is not a SignedData");
  }
  const sd = kids(bytes, parts[1])[0];
  log.debug("Leaving signedDataOf().");
  return { bytes: bytes, fields: kids(bytes, sd) };
}

function certsOnly(der) {
  log.debug("Entering certsOnly().");
  const sd = signedDataOf(der);
  const out = { certificates: [], crls: [] };
  sd.fields.forEach(function (node) {
    if (node.tag === 0xa0) {
      kids(sd.bytes, node).forEach(function (one) {
        out.certificates.push(toPem(one.raw));
      });
    }
    if (node.tag === 0xa1) {
      kids(sd.bytes, node).forEach(function (one) {
        out.crls.push(Buffer.from(one.raw));
      });
    }
  });
  log.debug("Leaving certsOnly().");
  return out;
}

// A CertRep: its signed attributes, whether its signature verifies with the
// RA certificate, and its encapsulated content.
function readCertRep(der, raCertPem) {
  log.debug("Entering readCertRep().");
  const sd = signedDataOf(der);
  const bytes = sd.bytes;
  const encap = kids(bytes, sd.fields[2]);
  let content = null;
  if (encap.length > 1) {
    const holder = kids(bytes, encap[1])[0];
    content = holder.tag === 0x24
      ? Buffer.concat(kids(bytes, holder).map(function (one) {
        return one.value;
      }))
      : Buffer.from(holder.value);
  }
  const certificates = [];
  sd.fields.forEach(function (node) {
    if (node.tag === 0xa0) {
      kids(bytes, node).forEach(function (one) {
        certificates.push(toPem(one.raw));
      });
    }
  });
  const si = kids(bytes, kids(bytes, sd.fields[sd.fields.length - 1])[0]);
  const attrsNode = si[3];
  const attrs = {};
  kids(bytes, attrsNode).forEach(function (attr) {
    const pair = kids(bytes, attr);
    const value = kids(bytes, pair[1])[0];
    attrs[oidText(pair[0].value)] = value.tag === 0x04
      ? Buffer.from(value.value) : value.value.toString("latin1");
  });
  const signed = Buffer.from(attrsNode.raw);
  signed[0] = 0x31;
  const signature = Buffer.from(si[5].value);
  const digest = oidText(kids(bytes, si[2])[0].value) === OID.sha512
    ? "sha512" : (oidText(kids(bytes, si[2])[0].value) ===
                  "2.16.840.1.101.3.4.2.2" ? "sha384" : "sha256");
  const verified = raCertPem
    ? nodeCrypto.verify(digest, signed,
                        new nodeCrypto.X509Certificate(raCertPem).publicKey,
                        signature)
    : null;
  const computed = nodeCrypto.createHash(digest)
    .update(content || Buffer.alloc(0)).digest();
  const failInfo = attrs[OID.failInfo];
  log.debug("Leaving readCertRep().");
  return {
    messageType: attrs[OID.messageType],
    pkiStatus: attrs[OID.pkiStatus],
    failInfo: failInfo,
    failInfoName: failInfo === undefined ? null : FAIL_INFO_NAMES[failInfo],
    transactionID: attrs[OID.transactionID],
    senderNonce: attrs[OID.senderNonce],
    recipientNonce: attrs[OID.recipientNonce],
    signatureVerifies: verified,
    digestMatches: !!attrs[OID.messageDigest] &&
                   Buffer.from(attrs[OID.messageDigest]).equals(computed),
    content: content,
    certificates: certificates
  };
}

// Open a SUCCESS reply's envelope with the requester's key.
function openReply(content, key, certPem) {
  log.debug("Entering openReply().");
  const p7 = forge.pkcs7.messageFromAsn1(asn1.fromDer(bin(content)));
  const recipient = p7.findRecipient(forge.pki.certificateFromPem(certPem));
  if (!recipient) {
    log.debug("Leaving openReply(). Not for this certificate.");
    throw new Error("the reply is not encrypted to the requester");
  }
  p7.decrypt(recipient, forge.pki.privateKeyFromPem(key.privateKeyPem));
  log.debug("Leaving openReply().");
  return { inner: buf(p7.content.getBytes()),
           cipher: asn1.derToOid(asn1.fromDer(bin(content)).value[1].value[0]
             .value[2].value[1].value[0].value) };
}

// ---------------------------------------------------------------------------
// HTTP.
// ---------------------------------------------------------------------------
async function http(url, options) {
  log.debug("Entering http().");
  const r = await fetch(url, options || {});
  const body = Buffer.from(await r.arrayBuffer());
  log.debug("Leaving http(). " + r.status);
  return { status: r.status, headers: r.headers, body: body,
           type: String(r.headers.get("content-type") || "") };
}

async function getCaCaps(base) {
  log.debug("Entering getCaCaps().");
  const r = await http(base + "?operation=GetCACaps");
  log.debug("Leaving getCaCaps().");
  return Object.assign(r, { lines: r.body.toString("utf8").split(/\r?\n/)
    .filter(function (one) { return !!one; }) });
}

async function getCaCert(base) {
  log.debug("Entering getCaCert().");
  const r = await http(base + "?operation=GetCACert");
  let parsed = { certificates: [], crls: [] };
  if (r.status === 200) {
    parsed = certsOnly(r.body);
  }
  // The RA certificate is the one whose key may encrypt: keyEncipherment and
  // no CA basic constraint.
  const ra = parsed.certificates.filter(function (pem) {
    const x = new nodeCrypto.X509Certificate(pem);
    return !x.ca;
  })[0] || null;
  log.debug("Leaving getCaCert().");
  return Object.assign(r, { certificates: parsed.certificates, ra: ra });
}

async function pkiOperation(base, der, options) {
  log.debug("Entering pkiOperation().");
  const opts = options || {};
  let r;
  if (opts.get) {
    r = await http(base + "?operation=PKIOperation&message=" +
                   encodeURIComponent(opts.rawMessage !== undefined
                     ? opts.rawMessage : Buffer.from(der).toString("base64")));
  } else {
    r = await http(base + "?operation=PKIOperation", {
      method: "POST",
      headers: { "Content-Type": opts.contentType ||
                                 "application/x-pki-message" },
      body: der
    });
  }
  log.debug("Leaving pkiOperation(). " + r.status);
  return r;
}

module.exports = {
  OID: OID,
  MESSAGE_TYPE: MESSAGE_TYPE,
  FAIL_INFO_NAMES: FAIL_INFO_NAMES,
  rsaKey: rsaKey,
  selfSigned: selfSigned,
  csr: csr,
  envelope: envelope,
  signedMessage: signedMessage,
  issuerAndSerial: issuerAndSerial,
  issuerAndSubject: issuerAndSubject,
  certsOnly: certsOnly,
  readCertRep: readCertRep,
  openReply: openReply,
  http: http,
  getCaCaps: getCaCaps,
  getCaCert: getCaCert,
  pkiOperation: pkiOperation,
  pemBody: pemBody
};
