'use strict';
//
// File: est_codec.js
//
// ---------------------------------------------------------------------------
// THE FOUR WIRE SHAPES EST ADDS, AND NOTHING ELSE (2026-09-13).
//
// RFC 7030 is a thin protocol over three older formats, and RFC 8951 is the
// document that says what "thin" was supposed to mean on the wire. What this
// file encodes and decodes is exactly the part of it that is EST's own:
//
//   * a BODY — base64 of a DER value, with the whitespace RFC 8951 section 3
//     tolerates and nothing else (`decodeBody()`, `base64Lines()`);
//   * a CERTS-ONLY CMS message — a degenerate SignedData with certificates and
//     no signer (RFC 7030 section 4.1.3, RFC 5652 section 5, the "certs-only"
//     smime-type of RFC 8551) — `certsOnly()`;
//   * the CSR ATTRIBUTES response — `SEQUENCE OF AttrOrOID` (RFC 7030 section
//     4.5.2) — `csrAttrs()`;
//   * the SERVER-GENERATED KEY response — `multipart/mixed` with a PKCS#8 part
//     and a certs-only part (RFC 7030 section 4.4.2) — `multipartMixed()`.
//
// **WHAT IS NOT HERE IS THE POINT.** A PKCS#10 request is read by
// `common/cert_enrollment.js`'s `parseCsr()`, which verifies the proof of
// possession; a certificate is built by `common/pki.js`. EST reading a CSR for
// itself would be a second reader with a second idea of what a request asks
// for, and the core exists so there is one.
//
// **THE DER IS WRITTEN BY HAND, AND THAT IS A DECISION.** A certs-only message
// carries certificates VERBATIM: pkijs re-encodes a `Certificate` from its
// parsed fields when it serialises one, and a certificate re-encoded with a
// different length form, or a post-quantum key the library reads as opaque, is
// a certificate whose signature no longer verifies — found by a client, one
// algorithm in a few, with a message about a signature rather than an encoder.
// Four tag-length-value writers and an OID encoder are all four shapes need,
// and every byte of each certificate goes out as the CA signed it.
//
// A LIBRARY (rule 3): it registers no route and requires only `helpers.js`.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const { log } = require('../common/helpers');

// The OIDs this file writes, in one table so the csrattrs response and the
// crypto report read the same numbers.
const OIDS = {
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  extensionRequest: '1.2.840.113549.1.9.14',
  challengePassword: '1.2.840.113549.1.9.7',
  subjectAltName: '2.5.29.17',
  extKeyUsage: '2.5.29.37',
  decryptKeyIdentifier: '1.2.840.113549.1.9.16.2.37',
  asymmetricDecryptKeyIdentifier: '1.2.840.113549.1.9.16.2.54'
};

// The signature algorithms a client may sign its request with, as csrattrs
// names them (RFC 7030 section 4.5.2: "the OID of a signature algorithm"). The
// list is what `parseCsr()` VERIFIES and a sensible client picks from — the
// classical three, Ed25519 and ML-DSA's three parameter sets — not every
// algorithm the vendored encoder knows, because a long list tells a client
// nothing about which to prefer.
const SIGNATURE_ALGORITHMS = [
  { oid: '1.2.840.10045.4.3.2', name: 'ecdsa-with-SHA256' },
  { oid: '1.2.840.10045.4.3.3', name: 'ecdsa-with-SHA384' },
  { oid: '1.2.840.113549.1.1.11', name: 'sha256WithRSAEncryption' },
  { oid: '1.3.101.112', name: 'Ed25519' },
  { oid: '2.16.840.1.101.3.4.3.17', name: 'ML-DSA-44' },
  { oid: '2.16.840.1.101.3.4.3.18', name: 'ML-DSA-65' },
  { oid: '2.16.840.1.101.3.4.3.19', name: 'ML-DSA-87' }
];

// ---------------------------------------------------------------------------
// DER.
// ---------------------------------------------------------------------------
function lengthOctets(length) {
  log.debug("Entering lengthOctets().");
  if (length < 0x80) {
    log.debug("Leaving lengthOctets(). Short form.");
    return Buffer.from([length]);
  }
  const bytes = [];
  let rest = length;
  while (rest > 0) {
    bytes.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  }
  log.debug("Leaving lengthOctets(). Long form.");
  return Buffer.from([0x80 | bytes.length].concat(bytes));
}

function tlv(tag, content) {
  log.debug("Entering tlv(). tag=" + tag);
  const body = Buffer.concat((Array.isArray(content) ? content : [content])
    .map(function (one) {
      return Buffer.from(one);
    }));
  log.debug("Leaving tlv().");
  return Buffer.concat([Buffer.from([tag]), lengthOctets(body.length), body]);
}

function oid(dotted) {
  log.debug("Entering oid(). " + dotted);
  const arcs = String(dotted).split('.').map(function (one) {
    return Number(one);
  });
  if (arcs.length < 2 || arcs.some(function (arc) {
    return !Number.isInteger(arc) || arc < 0;
  })) {
    log.debug("Leaving oid(). Malformed.");
    throw new Error('not an object identifier: ' + dotted);
  }
  const out = [];
  // A hot path: no Entering/Leaving pair, because this runs once per arc of
  // every OID written and a pair per arc would drown the log.
  const push = function push(value) {
    const septets = [value & 0x7f];
    let rest = Math.floor(value / 128);
    while (rest > 0) {
      septets.unshift((rest & 0x7f) | 0x80);
      rest = Math.floor(rest / 128);
    }
    septets.forEach(function (one) {
      out.push(one);
    });
  };
  push(arcs[0] * 40 + arcs[1]);
  arcs.slice(2).forEach(push);
  log.debug("Leaving oid().");
  return tlv(0x06, Buffer.from(out));
}

function utf8String(text) {
  log.debug("Entering utf8String().");
  log.debug("Leaving utf8String().");
  return tlv(0x0c, Buffer.from(String(text), 'utf8'));
}

function pemToDer(pem) {
  log.debug("Entering pemToDer().");
  const body = String(pem || '').replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, '');
  log.debug("Leaving pemToDer().");
  return Buffer.from(body, 'base64');
}

// ---------------------------------------------------------------------------
// A REQUEST BODY. RFC 8951 section 3 settled that EST bodies are base64 and
// that a line break or space inside one is not an error. It did NOT make any
// other byte acceptable, and the lenient reading — node's `Buffer.from(x,
// 'base64')` skipping whatever it does not recognise — is how a body that is
// half a PEM header decodes to a DER value that happens to parse. So: only the
// alphabet, `=` padding at the end, and SP / HTAB / CR / LF anywhere.
// ---------------------------------------------------------------------------
function decodeBody(bytes) {
  log.debug("Entering decodeBody().");
  const text = Buffer.isBuffer(bytes) ? bytes.toString('latin1')
                                      : String(bytes == null ? '' : bytes);
  const compact = text.replace(/[ \t\r\n]+/g, '');
  if (!compact.length) {
    log.debug("Leaving decodeBody(). Empty.");
    return { ok: false, why: 'The request body is empty.' };
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) {
    log.debug("Leaving decodeBody(). Not the alphabet.");
    return { ok: false, why: 'The request body is not base64: it contains a ' +
             'character outside the base64 alphabet, padding and whitespace ' +
             '(RFC 8951 section 3).' };
  }
  if (compact.length % 4 !== 0) {
    log.debug("Leaving decodeBody(). Truncated.");
    return { ok: false, why: 'The request body is not base64: its length is ' +
             'not a multiple of four, so it was cut off or padded wrongly.' };
  }
  const der = Buffer.from(compact, 'base64');
  // Re-encoding catches the one lenient case the pattern above still admits:
  // non-zero bits in the last character before the padding.
  if (der.toString('base64') !== compact) {
    log.debug("Leaving decodeBody(). Not canonical.");
    return { ok: false, why: 'The request body is not canonical base64.' };
  }
  log.debug("Leaving decodeBody(). " + der.length + " byte(s).");
  return { ok: true, der: der };
}

// Base64 at 64 characters a line with CRLF, which is what RFC 2045's
// Content-Transfer-Encoding: base64 and every EST client reads.
function base64Lines(der) {
  log.debug("Entering base64Lines().");
  const text = Buffer.from(der).toString('base64');
  const lines = [];
  for (let i = 0; i < text.length; i += 64) {
    lines.push(text.slice(i, i + 64));
  }
  log.debug("Leaving base64Lines().");
  return lines.join('\r\n') + '\r\n';
}

// ---------------------------------------------------------------------------
// CERTS-ONLY. ContentInfo { signedData, [0] SignedData { version 1,
// digestAlgorithms {}, encapContentInfo { id-data }, certificates [0] {…},
// signerInfos {} } }. Version 1 because nothing in it needs a later one (RFC
// 5652 section 5.1); the certificates go in the order given, leaf-most first,
// because RFC 7030 section 4.1.3 names the CA certificates and nothing requires
// a sort, and a client reading them builds its path from the names.
// ---------------------------------------------------------------------------
function certsOnly(pems) {
  log.debug("Entering certsOnly().");
  const certificates = (pems || []).map(pemToDer).filter(function (der) {
    return der.length > 0;
  });
  const signedData = tlv(0x30, [
    tlv(0x02, Buffer.from([0x01])),
    tlv(0x31, Buffer.alloc(0)),
    tlv(0x30, oid(OIDS.data)),
    tlv(0xa0, certificates),
    tlv(0x31, Buffer.alloc(0))
  ]);
  log.debug("Leaving certsOnly(). " + certificates.length + " certificate(s).");
  return tlv(0x30, [oid(OIDS.signedData), tlv(0xa0, signedData)]);
}

// ---------------------------------------------------------------------------
// CSR ATTRIBUTES. `items` is a list of `{ oid }` (a bare OBJECT IDENTIFIER) or
// `{ type, values }` (an Attribute), where each value is `{ oid }` or
// `{ utf8 }`.
// ---------------------------------------------------------------------------
function csrAttrs(items) {
  log.debug("Entering csrAttrs().");
  const encoded = (items || []).map(function (item) {
    if (item.type) {
      return tlv(0x30, [oid(item.type), tlv(0x31, (item.values || [])
        .map(function (value) {
          return value.oid ? oid(value.oid) : utf8String(value.utf8);
        }))]);
    }
    return oid(item.oid);
  });
  log.debug("Leaving csrAttrs(). " + encoded.length + " item(s).");
  return tlv(0x30, encoded);
}

// ---------------------------------------------------------------------------
// THE SERVER-GENERATED KEY RESPONSE. Each part carries its own Content-Type
// and Content-Transfer-Encoding: base64, which RFC 8951 section 3.2 restored
// after RFC 7030's text had made the header optional in one place and not
// another. The boundary is random so that no base64 line can collide with it
// (none can anyway — a boundary line starts with two hyphens, which the base64
// alphabet does not contain — but a fixed boundary is a fingerprint).
// ---------------------------------------------------------------------------
function multipartMixed(parts) {
  log.debug("Entering multipartMixed().");
  const boundary = 'est-' + nodeCrypto.randomBytes(12).toString('hex');
  const chunks = [];
  (parts || []).forEach(function (part) {
    chunks.push('--' + boundary + '\r\n' +
                'Content-Type: ' + part.contentType + '\r\n' +
                'Content-Transfer-Encoding: base64\r\n\r\n' +
                base64Lines(part.der));
  });
  chunks.push('--' + boundary + '--\r\n');
  log.debug("Leaving multipartMixed(). " + (parts || []).length + " part(s).");
  return { boundary: boundary, body: Buffer.from(chunks.join(''), 'latin1') };
}

module.exports = {
  OIDS: OIDS,
  SIGNATURE_ALGORITHMS: SIGNATURE_ALGORITHMS,
  decodeBody: decodeBody,
  base64Lines: base64Lines,
  certsOnly: certsOnly,
  csrAttrs: csrAttrs,
  multipartMixed: multipartMixed,
  pemToDer: pemToDer,
  oid: oid
};
