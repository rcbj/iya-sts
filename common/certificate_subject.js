'use strict';
//
// File: common/certificate_subject.js
//
// ===========================================================================
// WHAT A CERTIFICATE SAYS ITS SUBJECT IS, AND WHETHER THAT IS WHAT WAS
// REGISTERED — RFC 8705 SECTION 2.1.2 (2026-09-13).
//
// A `tls_client_auth` client registers EXACTLY ONE of five expectations about
// the certificate it will present:
//
//   tls_client_auth_subject_dn   the subject, as an RFC 4514 string
//   tls_client_auth_san_dns      a dNSName subjectAltName
//   tls_client_auth_san_uri      a uniformResourceIdentifier subjectAltName
//   tls_client_auth_san_ip       an iPAddress subjectAltName, v4 or v6
//   tls_client_auth_san_email    an rfc822Name subjectAltName
//
// and the authorization server authenticates the client when the certificate
// on the connection — whose chain has been validated — carries it. This file is
// the reading of both sides and the comparison. `common/applications.js` asks it
// whether a value may be REGISTERED; `oauth-oidc/client_auth.js` asks it whether
// a certificate MATCHES. One reading, because a registration door that accepted
// a spelling the verifier then could not match is a client that registers
// successfully and never authenticates.
//
// ---------------------------------------------------------------------------
// THE DN IS COMPARED AS A NAME AND NOT AS A STRING, AND THAT IS THE FIX.
//
// `client_auth.js` compared `tls_client_auth_subject_dn` to a rendering of the
// certificate's subject by exact string equality until this file existed. Two
// spellings of one DN — `CN=client,O=Acme` and `cn=client, o=Acme`, or `2.5.4.3`
// for `CN`, or a value escaped one way and written another — are one name to
// RFC 4517's distinguishedNameMatch and were two to that comparison, so a
// correctly registered client could fail for a space. `normalDn()` parses RFC
// 4514 — escapes, hex pairs, `#` BER values, multi-valued RDNs — folds each
// attribute type to one name (a short name, its long name and its OID are the
// same type), and compares each value as caseIgnoreMatch does (case-folded,
// NFKC, leading, trailing and repeated inner spaces insignificant), with the
// AVAs of a multi-valued RDN in a fixed order. The RDN SEQUENCE is still
// compared in order: a DN with its RDNs rearranged is a different name.
//
// **WHAT IS NOT DONE, SAID**: attribute-specific matching rules beyond
// caseIgnoreMatch (a `#` BER value is compared as its hex, never decoded), and
// no wildcard in a dNSName — RFC 8705 names a value to expect, not a pattern.
// A URI is compared exactly: RFC 3986 section 6's normalisations are a policy
// this file does not guess at, and an operator who registered one spelling can
// see the one the certificate carries in the refusal.
//
// A LEAF (rule 3): it requires node's `crypto` and `net` and `helpers.js` for the
// logger, and nothing requires it that it requires back.
// ===========================================================================

const nodeCrypto = require('crypto');
const net = require('net');
const { log } = require('./helpers');

// The five registration members, the attribute each is kept in on an
// application entry, and what to call it in a sentence. `MEMBERS` is read by the
// registry (the schema rows, the registration door, the console) and by the
// verifier, so a sixth expectation is one row here.
const MEMBERS = {
  tls_client_auth_subject_dn: { attribute: 'oauthTlsClientAuthSubjectDn',
                                kind: 'dn', label: 'subject DN' },
  tls_client_auth_san_dns: { attribute: 'oauthTlsClientAuthSanDns',
                             kind: 'dns', label: 'dNSName subjectAltName' },
  tls_client_auth_san_uri: { attribute: 'oauthTlsClientAuthSanUri',
                             kind: 'uri',
                             label: 'uniformResourceIdentifier ' +
                                    'subjectAltName' },
  tls_client_auth_san_ip: { attribute: 'oauthTlsClientAuthSanIp',
                            kind: 'ip', label: 'iPAddress subjectAltName' },
  tls_client_auth_san_email: { attribute: 'oauthTlsClientAuthSanEmail',
                               kind: 'email',
                               label: 'rfc822Name subjectAltName' }
};

const MEMBER_NAMES = Object.keys(MEMBERS);

// The longest value a registration may hold for any of the five. A DN or a URI
// longer than this is not one a certificate authority issued.
const MAX_VALUE = 1024;

// ---------------------------------------------------------------------------
// ONE NAME PER ATTRIBUTE TYPE. RFC 4519's short names, their long names and
// their OIDs, plus the four a certificate subject commonly carries that RFC 4514
// section 3 does not list (`emailAddress` from PKCS #9, `serialNumber`, `title`,
// `postalCode`). A type this table does not know is compared as written,
// lower-cased — which is RFC 4512's rule for a descriptor and leaves an OID an
// OID.
// ---------------------------------------------------------------------------
const TYPE_ALIASES = {
  'cn': 'cn', 'commonname': 'cn', '2.5.4.3': 'cn',
  'c': 'c', 'countryname': 'c', '2.5.4.6': 'c',
  'l': 'l', 'localityname': 'l', '2.5.4.7': 'l',
  'st': 'st', 'stateorprovincename': 'st', '2.5.4.8': 'st',
  'street': 'street', 'streetaddress': 'street', '2.5.4.9': 'street',
  'o': 'o', 'organizationname': 'o', '2.5.4.10': 'o',
  'ou': 'ou', 'organizationalunitname': 'ou', '2.5.4.11': 'ou',
  'dc': 'dc', 'domaincomponent': 'dc', '0.9.2342.19200300.100.1.25': 'dc',
  'uid': 'uid', 'userid': 'uid', '0.9.2342.19200300.100.1.1': 'uid',
  'sn': 'sn', 'surname': 'sn', '2.5.4.4': 'sn',
  'givenname': 'givenname', 'gn': 'givenname', '2.5.4.42': 'givenname',
  'title': 'title', '2.5.4.12': 'title',
  'serialnumber': 'serialnumber', '2.5.4.5': 'serialnumber',
  'postalcode': 'postalcode', '2.5.4.17': 'postalcode',
  'dnqualifier': 'dnqualifier', '2.5.4.46': 'dnqualifier',
  'emailaddress': 'emailaddress', 'e': 'emailaddress',
  '1.2.840.113549.1.9.1': 'emailaddress'
};

// ---------------------------------------------------------------------------
// RFC 4514, READ.
//
// `distinguishedName = [ relativeDistinguishedName *( COMMA ... ) ]`, each RDN
// one or more `type=value` joined by `+`. A value escapes `,`, `+`, `"`, `\`,
// `<`, `>`, `;`, a leading `#` or space and a trailing space with a backslash,
// and any octet as a backslash and two hex digits — several of which together
// are UTF-8. A value beginning `#` is the hex of its BER encoding. Answers the
// RDNs leaf first as written, each an array of `{ type, value }`, or null.
// ---------------------------------------------------------------------------
function parseDn(text) {
  log.debug("Entering parseDn().");
  const source = String(text === undefined || text === null ? '' : text);
  const rdns = [];
  let rdn = [];
  let i = 0;
  const unparsed = function (why) {
    log.debug("Entering unparsed().");
    log.debug("Leaving unparsed(). " + why);
    return null;
  };
  while (i <= source.length) {
    // THE TYPE.
    while (source[i] === ' ') {
      i++;
    }
    const typeStart = i;
    while (i < source.length && source[i] !== '=') {
      i++;
    }
    if (i >= source.length) {
      if (!rdns.length && !rdn.length && source.trim() === '') {
        break;
      }
      log.debug("Leaving parseDn(). No '=' in an attribute.");
      return unparsed('no =');
    }
    const type = source.slice(typeStart, i).trim();
    if (!/^([A-Za-z][A-Za-z0-9-]*|[0-9]+(\.[0-9]+)*)$/.test(type)) {
      log.debug("Leaving parseDn(). A malformed attribute type.");
      return unparsed('type');
    }
    i++;
    // THE VALUE.
    while (source[i] === ' ') {
      i++;
    }
    let value = '';
    if (source[i] === '#') {
      const start = i + 1;
      i = start;
      while (i < source.length && /[0-9A-Fa-f]/.test(source[i])) {
        i++;
      }
      const hex = source.slice(start, i);
      if (!hex.length || hex.length % 2) {
        log.debug("Leaving parseDn(). A malformed BER value.");
        return unparsed('ber');
      }
      value = '#' + hex.toLowerCase();
      while (source[i] === ' ') {
        i++;
      }
    } else {
      const bytes = [];
      let trailingSpaces = 0;
      while (i < source.length && source[i] !== ',' && source[i] !== '+') {
        const ch = source[i];
        if (ch === '\\') {
          const next = source[i + 1];
          if (next === undefined) {
            log.debug("Leaving parseDn(). A trailing backslash.");
            return unparsed('escape');
          }
          if (/[0-9A-Fa-f]/.test(next) && /[0-9A-Fa-f]/.test(source[i + 2] ||
                                                             '')) {
            bytes.push(parseInt(source.slice(i + 1, i + 3), 16));
            i += 3;
          } else {
            Buffer.from(next, 'utf8').forEach(function (b) { bytes.push(b); });
            i += 2;
          }
          trailingSpaces = 0;
          continue;
        }
        if (ch === '"' || ch === ';' || ch === '<' || ch === '>') {
          log.debug("Leaving parseDn(). An unescaped special character.");
          return unparsed('special');
        }
        trailingSpaces = ch === ' ' ? trailingSpaces + 1 : 0;
        Buffer.from(ch, 'utf8').forEach(function (b) { bytes.push(b); });
        i++;
      }
      value = Buffer.from(bytes).toString('utf8');
      if (trailingSpaces) {
        value = value.slice(0, value.length - trailingSpaces);
      }
    }
    if (i < source.length && source[i] !== ',' && source[i] !== '+') {
      log.debug("Leaving parseDn(). Text after a BER value.");
      return unparsed('after');
    }
    rdn.push({ type: type, value: value });
    if (source[i] === '+') {
      i++;
      continue;
    }
    rdns.push(rdn);
    rdn = [];
    if (source[i] === ',') {
      i++;
      if (i >= source.length) {
        log.debug("Leaving parseDn(). A trailing comma.");
        return unparsed('comma');
      }
      continue;
    }
    break;
  }
  log.debug("Leaving parseDn(). " + rdns.length + " RDN(s).");
  return rdns;
}

function normalType(type) {
  log.debug("Entering normalType().");
  const lower = String(type).toLowerCase();
  log.debug("Leaving normalType().");
  return TYPE_ALIASES[lower] || lower;
}

// caseIgnoreMatch, as RFC 4518's string preparation approximates it: NFKC,
// case-folded, and space insignificant at the ends and collapsed inside.
function normalValue(value) {
  log.debug("Entering normalValue().");
  const text = String(value);
  if (text[0] === '#') {
    log.debug("Leaving normalValue(). A BER value, compared as its hex.");
    return text.toLowerCase();
  }
  log.debug("Leaving normalValue().");
  return text.normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim();
}

// A DN's comparison key, or null where the text is not a DN. Two DNs are the
// same name when their keys are equal.
function normalDn(text) {
  log.debug("Entering normalDn().");
  const rdns = parseDn(text);
  if (!rdns || !rdns.length) {
    log.debug("Leaving normalDn(). Not a DN.");
    return null;
  }
  const key = JSON.stringify(rdns.map(function (rdn) {
    return rdn.map(function (ava) {
      return [normalType(ava.type), normalValue(ava.value)];
    }).sort(function (a, b) {
      return (a[0] + ' ' + a[1]).localeCompare(b[0] + ' ' + b[1]);
    });
  }));
  log.debug("Leaving normalDn().");
  return key;
}

function escapeValue(value) {
  log.debug("Entering escapeValue().");
  let out = String(value).replace(/([\\,+"<>;=])/g, '\\$1');
  if (out[0] === '#' || out[0] === ' ') {
    out = '\\' + out;
  }
  if (out.length > 1 && out[out.length - 1] === ' ') {
    out = out.slice(0, -1) + '\\ ';
  }
  log.debug("Leaving escapeValue().");
  return out;
}

// ---------------------------------------------------------------------------
// THE CERTIFICATE'S SUBJECT, AS RFC 4514 WRITES IT — leaf first, a multi-valued
// RDN joined with `+`. Built off node's `X509Certificate.subject`, which is one
// RDN per line, most significant first, with the parts of a multi-valued RDN
// joined by " + " and every special character already escaped with a backslash
// the way RFC 2253 does. Each line is read with the same value decoder a
// registered DN goes through, so the two sides of the comparison cannot
// disagree about an escape.
// ---------------------------------------------------------------------------
function subjectOf(x509) {
  log.debug("Entering subjectOf().");
  const lines = String((x509 && x509.subject) || '').split('\n')
    .filter(function (one) { return one.trim() !== ''; });
  const rdns = [];
  for (let n = 0; n < lines.length; n++) {
    // " + " between AVAs; an escaped plus inside a value is "\+".
    const parsed = parseDn(lines[n].replace(/ \+ /g, '+'));
    if (!parsed || parsed.length !== 1) {
      log.debug("Leaving subjectOf(). A line node wrote is not one RDN.");
      return { text: '', rdns: null };
    }
    rdns.push(parsed[0]);
  }
  rdns.reverse();
  const text = rdns.map(function (rdn) {
    return rdn.map(function (ava) {
      return ava.type + '=' + (ava.value[0] === '#' ? ava.value
                                                    : escapeValue(ava.value));
    }).join('+');
  }).join(',');
  log.debug("Leaving subjectOf().");
  return { text: text, rdns: rdns };
}

// ---------------------------------------------------------------------------
// THE SUBJECT ALTERNATIVE NAMES. node writes `X509Certificate.subjectAltName`
// as `Label:value` joined by ", ", and since the escaping change in node 17 a
// value holding a comma, a quote or a control character is written as a JSON
// string. So a split on ", " must skip quoted text, and a quoted value is read
// with JSON.parse. Answers `{ dns, uri, ip, email }`, each a list.
// ---------------------------------------------------------------------------
function subjectAltNamesOf(x509) {
  log.debug("Entering subjectAltNamesOf().");
  const text = String((x509 && x509.subjectAltName) || '');
  const out = { dns: [], uri: [], ip: [], email: [] };
  const parts = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"' && text[i - 1] !== '\\') {
      quoted = !quoted;
    }
    if (!quoted && ch === ',' && text[i + 1] === ' ') {
      parts.push(current);
      current = '';
      i++;
      continue;
    }
    current += ch;
  }
  if (current) {
    parts.push(current);
  }
  const labels = { 'DNS': 'dns', 'URI': 'uri', 'IP Address': 'ip',
                   'email': 'email' };
  parts.forEach(function (part) {
    const colon = part.indexOf(':');
    if (colon < 0) {
      return;
    }
    const kind = labels[part.slice(0, colon)];
    if (!kind) {
      return;
    }
    let value = part.slice(colon + 1);
    if (value[0] === '"') {
      try {
        value = JSON.parse(value);
      } catch (e) {
        log.debug("Caught in subjectAltNamesOf(): " + ((e && e.message) || e));
        return;
      }
    }
    out[kind].push(String(value));
  });
  log.debug("Leaving subjectAltNamesOf().");
  return out;
}

// An IP address as the bytes it stands for, in hex — 8 digits for v4, 32 for
// v6 — so that `2001:db8::1` and `2001:DB8:0:0:0:0:0:1` are one address. '' for
// text that is not one.
function ipKey(text) {
  log.debug("Entering ipKey().");
  const value = String(text || '').trim();
  const family = net.isIP(value);
  if (family === 4) {
    log.debug("Leaving ipKey(). v4.");
    return value.split('.').map(function (octet) {
      return ('0' + Number(octet).toString(16)).slice(-2);
    }).join('');
  }
  if (family !== 6) {
    log.debug("Leaving ipKey(). Not an address.");
    return '';
  }
  let head = value;
  let tailV4 = [];
  const lastColon = value.lastIndexOf(':');
  if (value.indexOf('.', lastColon) > lastColon) {
    const v4 = value.slice(lastColon + 1).split('.').map(Number);
    tailV4 = [((v4[0] << 8) | v4[1]).toString(16),
              ((v4[2] << 8) | v4[3]).toString(16)];
    head = value.slice(0, lastColon + 1) + 'x';
  }
  const halves = head.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const fromParts = function (parts) {
    log.debug("Entering fromParts().");
    const expanded = [];
    parts.forEach(function (one) {
      if (one === 'x') {
        tailV4.forEach(function (group) { expanded.push(group); });
      } else {
        expanded.push(one);
      }
    });
    log.debug("Leaving fromParts().");
    return expanded;
  };
  const l = fromParts(left);
  const r = fromParts(right);
  const missing = 8 - l.length - r.length;
  const groups = l.concat(new Array(halves.length > 1 ? missing : 0)
    .fill('0'), r);
  log.debug("Leaving ipKey(). v6.");
  return groups.map(function (group) {
    return ('0000' + String(group).toLowerCase()).slice(-4);
  }).join('');
}

function dnsKey(text) {
  log.debug("Entering dnsKey().");
  log.debug("Leaving dnsKey().");
  return String(text || '').trim().toLowerCase().replace(/\.$/, '');
}

// RFC 5280 section 7.5: the local part of an rfc822Name is case-SENSITIVE and
// the host is not.
function emailKey(text) {
  log.debug("Entering emailKey().");
  const value = String(text || '').trim();
  const at = value.lastIndexOf('@');
  log.debug("Leaving emailKey().");
  return at < 0 ? value : value.slice(0, at) + '@' +
                          value.slice(at + 1).toLowerCase();
}

// ---------------------------------------------------------------------------
// MAY THIS VALUE BE REGISTERED FOR THIS MEMBER. A sentence naming what is wrong,
// or ''.
// ---------------------------------------------------------------------------
function valueProblem(member, value) {
  log.debug("Entering valueProblem(). member=" + member);
  const row = MEMBERS[member];
  if (!row) {
    log.debug("Leaving valueProblem(). Not a member.");
    return member + ' is not one of RFC 8705 section 2.1.2\'s five ' +
           'certificate subject parameters.';
  }
  if (typeof value !== 'string') {
    log.debug("Leaving valueProblem(). Not a string.");
    return member + ' must be a string, and this gives ' +
           JSON.stringify(value) + '.';
  }
  const text = value.trim();
  if (!text || text.length > MAX_VALUE || /[ -]/.test(text)) {
    log.debug("Leaving valueProblem(). Empty, long or unprintable.");
    return member + ' must be a printable value of 1 to ' + MAX_VALUE +
           ' characters.';
  }
  if (row.kind === 'dn' && !normalDn(text)) {
    log.debug("Leaving valueProblem(). Not a DN.");
    return member + ' "' + text + '" is not a distinguished name in RFC ' +
           '4514 form (for example CN=client,O=Example,C=US; a comma, plus ' +
           'sign, quote, backslash, angle bracket or semicolon inside a value ' +
           'is escaped with a backslash).';
  }
  if (row.kind === 'dns' &&
      !/^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$/
        .test(text)) {
    log.debug("Leaving valueProblem(). Not a host name.");
    return member + ' "' + text + '" is not a DNS host name. A wildcard is ' +
           'not accepted: RFC 8705 names the value a certificate carries, ' +
           'not a pattern.';
  }
  if (row.kind === 'uri') {
    let parsed = null;
    try {
      parsed = new URL(text);
    } catch (e) {
      log.debug("Caught in valueProblem(): " + ((e && e.message) || e));
      parsed = null;
    }
    if (!parsed || /\s/.test(text)) {
      log.debug("Leaving valueProblem(). Not an absolute URI.");
      return member + ' "' + text + '" is not an absolute URI.';
    }
  }
  if (row.kind === 'ip' && !ipKey(text)) {
    log.debug("Leaving valueProblem(). Not an IP address.");
    return member + ' "' + text + '" is not an IPv4 or IPv6 address.';
  }
  if (row.kind === 'email' && !/^[^\s@]+@[^\s@]+$/.test(text)) {
    log.debug("Leaving valueProblem(). Not a mailbox.");
    return member + ' "' + text + '" is not an rfc822Name (local@domain).';
  }
  log.debug("Leaving valueProblem(). Nothing refused.");
  return '';
}

// ---------------------------------------------------------------------------
// WHICH OF THE FIVE A CLIENT REGISTERED, from an object keyed by the MEMBER
// names (a registration document, or `clientConfigOf()`). Answers
// `{ members: [names that carry a value], member, value }` — `member` only when
// there is exactly one.
// ---------------------------------------------------------------------------
function registeredOf(values) {
  log.debug("Entering registeredOf().");
  const source = values || {};
  const members = MEMBER_NAMES.filter(function (name) {
    const value = source[name];
    return value !== undefined && value !== null && String(value).trim() !== '';
  });
  log.debug("Leaving registeredOf(). " + members.length + " registered.");
  return {
    members: members,
    member: members.length === 1 ? members[0] : '',
    value: members.length === 1 ? String(source[members[0]]).trim() : ''
  };
}

// ---------------------------------------------------------------------------
// DOES THE CERTIFICATE CARRY WHAT WAS REGISTERED. `raw` is the DER — what
// `getPeerCertificate().raw` is. Answers `{ ok, presented }`, where `presented`
// is what the certificate carries of that kind, for the refusal to quote.
// ---------------------------------------------------------------------------
function matches(member, registered, raw) {
  log.debug("Entering matches(). member=" + member);
  const row = MEMBERS[member];
  let x509 = null;
  try {
    x509 = new nodeCrypto.X509Certificate(raw);
  } catch (e) {
    log.debug("Caught in matches(): " + ((e && e.message) || e));
    x509 = null;
  }
  if (!row || !x509) {
    log.debug("Leaving matches(). Nothing to compare.");
    return { ok: false, presented: [] };
  }
  if (row.kind === 'dn') {
    const subject = subjectOf(x509);
    const want = normalDn(registered);
    const have = subject.text ? normalDn(subject.text) : null;
    log.debug("Leaving matches(). DN.");
    return { ok: !!want && !!have && want === have,
             presented: subject.text ? [subject.text] : [] };
  }
  const names = subjectAltNamesOf(x509)[row.kind];
  const keyOf = row.kind === 'dns' ? dnsKey
    : (row.kind === 'ip' ? ipKey
      : (row.kind === 'email' ? emailKey
        : function (one) { return String(one); }));
  const want = keyOf(String(registered).trim());
  const ok = !!want && names.some(function (one) {
    return keyOf(one) === want;
  });
  log.debug("Leaving matches(). " + row.kind + " " + ok);
  return { ok: ok, presented: names };
}

module.exports = {
  MEMBERS: MEMBERS,
  MEMBER_NAMES: MEMBER_NAMES,
  parseDn: parseDn,
  normalDn: normalDn,
  subjectOf: subjectOf,
  subjectAltNamesOf: subjectAltNamesOf,
  ipKey: ipKey,
  valueProblem: valueProblem,
  registeredOf: registeredOf,
  matches: matches
};
