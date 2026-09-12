'use strict';
//
// File: pki_revocation.js
//
// ===========================================================================
// REVOCATION: THE REGISTER, THE CRL, AND THE OCSP RESPONDER (2026-09-11).
//
// **THIS REVERSES THE LONGEST-STANDING "DELIBERATELY DOES NOT" ROW THIS
// SERVICE HAD ABOUT CERTIFICATES.** `common/pki.js` said, in as many words and
// on every surface that drew it: *nothing here is revoked, ever — this service
// publishes no CRL and answers no OCSP, so a certificate it issued is good
// until it expires.* Every page repeated it, and the *Take the key pair off*
// control was careful to say it stopped this service ACCEPTING what a key
// signed and did not stop the certificate chaining.
//
// It publishes a CRL and answers OCSP now, per CA, and the sentence that
// replaces the old one is narrower and worth reading twice:
//
//   **A CERTIFICATE THIS SERVICE ISSUED CAN NOW BE REVOKED, AND A RELYING
//   PARTY THAT CHECKS WILL SEE IT. NOTHING MAKES ANYBODY CHECK.**
//
// That is not a quibble. Revocation is a claim the ISSUER publishes and the
// VERIFIER consults, and this service only ever controls the first half — so
// the honest statement of what changed is that the claim is now publishable
// and reachable, not that a revoked certificate stops working. What it buys is
// exactly what a debugging tool is for: a client author can point their stack
// at a real CRL and a real OCSP responder, revoke something, and find out
// whether their stack noticed.
//
// ---------------------------------------------------------------------------
// A CRL PER CA, AND WHY NOT ONE PER REALM.
//
// A CRL is signed BY AN ISSUER and lists serial numbers ISSUED BY THAT ISSUER.
// One CRL per realm would therefore be a document with no valid issuer — the
// realm has three Issuing CAs and an Intermediate, and a serial is only unique
// within one of them. So every CA in the tree has a CRL of its own and an OCSP
// responder of its own, which is also what the request asked for.
//
// **THE ROOT AND THE INTERMEDIATES HAVE ONE TOO**, and they are not decoration:
// an Intermediate revokes Issuing CAs and the Root revokes Intermediates, which
// is what makes `reissue-use-case` and `build-scope` say something a relying
// party can act on rather than leaving the old authority silently valid.
//
// ---------------------------------------------------------------------------
// WHAT IS IN THE REGISTER AND WHAT IS NOT.
//
// One row per revoked certificate: the issuer it was minted by, its serial, the
// moment, and an RFC 5280 reason. **The certificate itself is not kept** — a
// CRL entry is a serial and a date, an OCSP answer is a status, and neither
// needs the document. That also keeps this register small enough to live in the
// same sealed `pki:<scope>` keystore row as the authorities it is about, which
// is `pki.js`'s placement argument applied once more: a second store would be a
// second thing to seal, purge with the realm, and share with a request worker.
//
// A LIBRARY (rule 3): it registers no route. It requires `config`, `pki` and
// the two vendored PKI modules plus pkijs and asn1js; none of them requires it
// back.
// ===========================================================================

const bunyan = require('bunyan');
const nodeCrypto = require('crypto');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
const config = require('./config');

const log = bunyan.createLogger({
  name: 'pki_revocation',
  level: config.value('global.logLevel')
});

const pki = require('./pki');
const keyMaterial = require('./vendored/key_material');
const x509 = require('./vendored/x509');

// ---------------------------------------------------------------------------
// THE RFC 5280 SECTION 5.3.1 REASON CODES.
//
// Written out rather than taken from a library because the VALUE is the wire
// format and the prose is what a console draws — and because two of them are
// traps worth naming where somebody chooses one:
//
//   * `7` is not a reason and never appears: the value is unused in the
//     standard and a CRL carrying it is refused by strict validators.
//   * `removeFromCRL` (8) is only meaningful on a DELTA CRL, which this service
//     does not publish. It is offered nowhere.
//
// `unspecified` (0) is the default, and RFC 5280 says a reason code extension
// with that value SHOULD be omitted — so it is: an entry with no reason is the
// specification's way of saying "no reason given", and writing one out would be
// a CRL that disagrees with the standard about its own default.
// ---------------------------------------------------------------------------
const REASONS = [
  { id: 'unspecified', code: 0,
    what: 'No reason given. RFC 5280 section 5.3.1 says the reason code ' +
          'extension SHOULD be omitted for this value, so an entry revoked ' +
          'this way carries no reason at all — which is what "unspecified" ' +
          'means on the wire.' },
  { id: 'keyCompromise', code: 1,
    what: 'The private key is known or suspected to be in somebody else\'s ' +
          'hands. The one reason that says the certificate was never safe ' +
          'rather than merely no longer wanted.' },
  { id: 'cACompromise', code: 2,
    what: 'The CA\'s own key is compromised. Used on an Intermediate or an ' +
          'Issuing CA, and everything below it should be treated as ' +
          'compromised too.' },
  { id: 'affiliationChanged', code: 3,
    what: 'The subject\'s name or affiliation changed, so the certificate no ' +
          'longer says something true.' },
  { id: 'superseded', code: 4,
    what: 'A replacement was issued. **This is what this service uses when a ' +
          'certificate is rotated or reissued**, which is the commonest entry ' +
          'on any of these lists.' },
  { id: 'cessationOfOperation', code: 5,
    what: 'The subject has stopped doing whatever the certificate was for.' },
  { id: 'certificateHold', code: 6,
    what: 'Temporarily suspended. **The only reason that can be UNDONE** — ' +
          'everything else is permanent, and a validator is entitled to cache ' +
          'a permanent revocation for as long as the CRL says it is fresh.' },
  { id: 'privilegeWithdrawn', code: 9,
    what: 'The subject is no longer entitled to what the certificate asserts.' },
  { id: 'aACompromise', code: 10,
    what: 'An attribute authority\'s key is compromised. Here for ' +
          'completeness: this service issues no attribute certificates.' }
];

const REASON_IDS = REASONS.map(function (one) { return one.id; });

function reason(id) {
  return REASONS.filter(function (one) {
    return one.id === String(id || '');
  })[0] || null;
}

// ---------------------------------------------------------------------------
// EVERY CA IN THE TREE THAT HAS A CRL, WHICH IS EVERY CA IN THE TREE.
//
// `id` is what appears in a URL and in the register, and it is the pair
// (scope, ca) rather than a thumbprint: a thumbprint changes when the
// authority is reissued and the URL in every certificate it ever signed does
// not. So the endpoint outlives the key, which is what a CRL distribution
// point has to do.
// ---------------------------------------------------------------------------
function authorities(scopeIds) {
  log.debug('Entering authorities().');
  const out = [];
  const root = pki.serviceRoot();
  if (root) {
    out.push({ scope: pki.SERVICE_SCOPE, ca: 'root', tier: root,
               label: 'Root CA' });
  }
  (scopeIds || []).forEach(function (scopeId) {
    const scope = pki.describeScope(scopeId);
    if (!scope.built) {
      return;
    }
    const row = pki.rawRowFor(scopeId);
    out.push({ scope: String(scopeId), ca: 'intermediate',
               tier: row.intermediate, label: scope.label + ' Intermediate CA' });
    Object.keys(row.issuing || {}).forEach(function (useCaseId) {
      out.push({ scope: String(scopeId), ca: useCaseId,
                 tier: row.issuing[useCaseId],
                 label: scope.label + ' ' +
                        ((pki.useCase(useCaseId) || {}).label || useCaseId) +
                        ' CA' });
    });
  });
  log.debug('Leaving authorities(). ' + out.length + ' of them.');
  return out;
}

// One authority by (scope, ca), with the signing material. Internal: what
// leaves this module is a CRL or an OCSP response, never a key.
function authorityFor(scopeId, caId) {
  const id = String(caId || '');
  if (id === 'root') {
    const root = pki.serviceRoot();
    return root ? { scope: pki.SERVICE_SCOPE, ca: 'root', tier: root } : null;
  }
  const row = pki.rawRowFor(scopeId);
  if (!row) {
    return null;
  }
  if (id === 'intermediate') {
    return row.intermediate
      ? { scope: String(scopeId), ca: 'intermediate', tier: row.intermediate }
      : null;
  }
  const held = (row.issuing || {})[id];
  return held ? { scope: String(scopeId), ca: id, tier: held } : null;
}

// ---------------------------------------------------------------------------
// THE REGISTER.
//
// `revoked` on the scope's row: `{ '<ca>': [ { serialHex, revokedAt, reason,
// subject, note } ] }`. The Root's list lives on the SERVICE row, which is
// where the Root itself lives.
// ---------------------------------------------------------------------------
function rowFor(scopeId) {
  return pki.rawRowFor(scopeId) || null;
}

function listFor(scopeId, caId) {
  const row = rowFor(scopeId);
  const held = (row && row.revoked) || {};
  return (held[String(caId)] || []).slice();
}

// A serial as this module compares them: lower case, no leading zeros, no
// separators. **A CRL and an OCSP request do not agree about the spelling of a
// serial** — one carries the DER integer and the other a hex string somebody
// typed — so every comparison in this file goes through here. Two spellings of
// one serial is a certificate that is revoked and reports as good.
function normalSerial(text) {
  const hex = String(text || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  const trimmed = hex.replace(/^0+/, '');
  return trimmed || '0';
}

function isRevoked(scopeId, caId, serialHex) {
  const wanted = normalSerial(serialHex);
  return listFor(scopeId, caId).filter(function (one) {
    return normalSerial(one.serialHex) === wanted;
  })[0] || null;
}

// ---------------------------------------------------------------------------
// REVOKE ONE CERTIFICATE.
//
// **IT IS IDEMPOTENT AND THE EARLIER ENTRY WINS.** Revoking twice must not move
// the date: a validator is entitled to act on the first moment it was told
// about, and a second entry that pushed the date forward would be this service
// quietly saying the certificate was valid for longer than it claimed.
// ---------------------------------------------------------------------------
function revoke(scopeId, caId, spec) {
  log.debug('Entering revoke(). scope=' + scopeId + ' ca=' + caId +
            ' serial=' + (spec && spec.serialHex));
  const id = String(scopeId);
  const authority = authorityFor(id, caId);
  if (!authority) {
    log.debug('Leaving revoke(). No such authority.');
    return { ok: false,
             errors: ['There is no "' + caId + '" certificate authority in ' +
                      'that scope, so nothing it issued can be revoked by ' +
                      'it. A revocation is made BY AN ISSUER — a serial is ' +
                      'only unique within one.'] };
  }
  const serialHex = normalSerial((spec || {}).serialHex);
  if (!serialHex || serialHex === '0') {
    log.debug('Leaving revoke(). No serial.');
    return { ok: false,
             errors: ['A revocation names a SERIAL NUMBER. It is the only ' +
                      'thing a CRL entry and an OCSP answer have in common ' +
                      'with the certificate they are about.'] };
  }
  const chosen = reason((spec || {}).reason || 'superseded');
  if (!chosen) {
    log.debug('Leaving revoke(). Unknown reason.');
    return { ok: false,
             errors: ['"' + (spec || {}).reason + '" is not an RFC 5280 ' +
                      'revocation reason. They are ' + REASON_IDS.join(', ') +
                      '.'] };
  }
  const already = isRevoked(id, caId, serialHex);
  if (already) {
    log.debug('Leaving revoke(). Already revoked.');
    return { ok: true, entry: describeEntry(already), already: true,
             why: 'That certificate was already revoked, at ' +
                  already.revokedAt + ', for "' + already.reason + '". The ' +
                  'entry is unchanged: a validator is entitled to act on the ' +
                  'first moment it was told about, and moving the date ' +
                  'forward would be this service saying the certificate was ' +
                  'valid for longer than it claimed.' };
  }
  const entry = {
    serialHex: serialHex,
    revokedAt: new Date().toISOString(),
    reason: chosen.id,
    reasonCode: chosen.code,
    subject: String((spec || {}).subject || ''),
    note: String((spec || {}).note || '')
  };
  const row = rowFor(id);
  if (!row) {
    return { ok: false,
             errors: ['That scope holds no certificate authority.'] };
  }
  row.revoked = Object.assign({}, row.revoked || {});
  row.revoked[String(caId)] = listFor(id, caId).concat([entry]);
  // THE CRL NUMBER MOVES WITH EVERY CHANGE. RFC 5280 section 5.2.3 makes it
  // monotonic per issuer, and a validator uses it to tell a newer list from an
  // older one — so it is bumped HERE, where the list changes, rather than at
  // the moment a CRL is built. Two CRLs with one number and different contents
  // is the ambiguity that field exists to remove.
  row.crlNumbers = Object.assign({}, row.crlNumbers || {});
  row.crlNumbers[String(caId)] = (row.crlNumbers[String(caId)] || 0) + 1;
  pki.saveRow(id, row);
  log.info('pki: certificate ' + serialHex + ' issued by the "' + caId +
           '" authority in "' + (id || 'default') + '" was REVOKED (' +
           chosen.id + '). It is on that authority\'s CRL and its OCSP ' +
           'responder answers `revoked` for it from now on. **NOTHING MAKES ' +
           'A RELYING PARTY CHECK** — what changed is that one which does ' +
           'will see it.');
  publishSoon(id, caId);
  log.debug('Leaving revoke(). Revoked.');
  return { ok: true, entry: describeEntry(entry),
           why: 'That certificate is revoked. It is on the ' + caId +
                ' authority\'s CRL and its OCSP responder answers `revoked` ' +
                'for it. **NOTHING MAKES A RELYING PARTY CHECK** — this ' +
                'service publishes the claim and cannot make anybody consult ' +
                'it, which is true of every certificate authority and is the ' +
                'whole reason a client author would point their stack here.' };
}

// Undo a hold. **ONLY a hold**, because `certificateHold` is the one reason
// RFC 5280 defines as temporary — everything else is permanent, and a
// validator is entitled to cache a permanent revocation for as long as the
// CRL it read says it is fresh, so "unrevoking" one would produce a
// certificate this service calls good and half the world still calls revoked.
function release(scopeId, caId, serialHex) {
  log.debug('Entering release(). serial=' + serialHex);
  const id = String(scopeId);
  const held = isRevoked(id, caId, serialHex);
  if (!held) {
    log.debug('Leaving release(). Not revoked.');
    return { ok: false,
             errors: ['That serial is not on the ' + caId + ' authority\'s ' +
                      'revocation list.'] };
  }
  if (held.reason !== 'certificateHold') {
    log.debug('Leaving release(). Not a hold.');
    return { ok: false,
             errors: ['That certificate was revoked as "' + held.reason +
                      '", which RFC 5280 makes PERMANENT. Only a ' +
                      '`certificateHold` can be released: a validator is ' +
                      'entitled to cache a permanent revocation for as long ' +
                      'as the CRL it read says it is fresh, so undoing one ' +
                      'here would produce a certificate this service calls ' +
                      'good and half the world still calls revoked.'] };
  }
  const row = rowFor(id);
  row.revoked = Object.assign({}, row.revoked || {});
  row.revoked[String(caId)] = listFor(id, caId).filter(function (one) {
    return normalSerial(one.serialHex) !== normalSerial(serialHex);
  });
  row.crlNumbers = Object.assign({}, row.crlNumbers || {});
  row.crlNumbers[String(caId)] = (row.crlNumbers[String(caId)] || 0) + 1;
  pki.saveRow(id, row);
  log.info('pki: the hold on certificate ' + normalSerial(serialHex) +
           ' (' + caId + ', "' + (id || 'default') + '") was RELEASED.');
  publishSoon(id, caId);
  log.debug('Leaving release(). Released.');
  return { ok: true,
           why: 'The hold is released and that certificate is no longer on ' +
                'the CRL. **A validator that cached the earlier list still ' +
                'has it** until that list expires, which is what makes a hold ' +
                'the only reversible reason and still not an instant one.' };
}

function describeEntry(one) {
  if (!one) {
    return null;
  }
  const chosen = reason(one.reason);
  return {
    serialHex: one.serialHex,
    revokedAt: one.revokedAt,
    reason: one.reason,
    reasonCode: one.reasonCode,
    reasonWhat: chosen ? chosen.what : '',
    subject: one.subject || '',
    note: one.note || ''
  };
}

// ---------------------------------------------------------------------------
// WHERE THE LISTS AND THE RESPONDERS ARE, IN THREE SCHEMES.
//
// **THE URL IS BUILT FROM CONFIGURATION AND NOT FROM A REQUEST, AND IT HAS TO
// BE.** These addresses go INSIDE certificates, and a certificate is minted at
// startup before any request exists — so `baseUrlOf(req)` is not available and
// would be the wrong answer anyway: a certificate is a durable document and
// the address in it must not depend on which Host header happened to be on the
// request that triggered the issue.
//
// All three schemes are published for every CA, because the request asked for
// all three and because a client that can reach one and not another is exactly
// what a debugging tool should let somebody discover.
// ---------------------------------------------------------------------------
function httpBase() {
  const set = String(config.value('pki.distributionBaseUrl') || '').trim();
  if (set) {
    return set.replace(/\/+$/, '');
  }
  const host = (config.value('tls.hostnames') || ['localhost'])[0] ||
               'localhost';
  const scheme = config.value('global.https') ? 'https' : 'http';
  return scheme + '://' + host + ':' + config.value('global.port');
}

function ldapHost() {
  const set = String(config.value('pki.distributionLdapHost') || '').trim();
  if (set) {
    return set;
  }
  return (config.value('tls.hostnames') || ['localhost'])[0] || 'localhost';
}

// The path segment a scope goes in. `*service` and `*process` cannot go in a
// URL as they are — a `*` is legal in a path and reads as a wildcard to
// everything that logs one — so they are spelled out.
function scopeSegment(scopeId) {
  const id = String(scopeId);
  if (id === pki.SERVICE_SCOPE) {
    return 'service';
  }
  if (id === pki.PROCESS_SCOPE) {
    return 'process';
  }
  return id || 'default';
}

function scopeFromSegment(segment) {
  const one = String(segment || '');
  if (one === 'service') {
    return pki.SERVICE_SCOPE;
  }
  if (one === 'process') {
    return pki.PROCESS_SCOPE;
  }
  return one === 'default' ? '' : one;
}

// The three CRL addresses for one authority, and the one OCSP address.
//
// **THE LDAP FORM IS RFC 4516's AND THE ATTRIBUTE DESCRIPTION MATTERS.**
// `?certificateRevocationList;binary` is not decoration: RFC 4523 section 4
// says a CRL is carried in that attribute and the `;binary` transfer option is
// what tells the server to send DER rather than a string. An LDAP URI without
// it fetches nothing usable, and the failure is an empty attribute rather than
// an error.
function distributionPoints(scopeId, caId) {
  const segment = scopeSegment(scopeId);
  const file = segment + '/' + String(caId);
  const dn = crlDn(scopeId, caId);
  return {
    http: httpBase() + '/pki/crl/' + file + '.crl',
    ldap: 'ldap://' + ldapHost() + ':' + config.value('ldap.port') + '/' +
          encodeURI(dn) + '?certificateRevocationList;binary',
    ldaps: 'ldaps://' + ldapHost() + ':' + config.value('ldap.tlsPort') + '/' +
           encodeURI(dn) + '?certificateRevocationList;binary',
    ocsp: httpBase() + '/pki/ocsp/' + file,
    caIssuers: httpBase() + '/pki/ca/' + file + '.cer',
    dn: dn
  };
}

// Where a CRL lives in the embedded directory. A container per scope under
// that realm's own subtree, because a CRL belongs to the realm whose authority
// signed it — exactly as `ou=applications` does.
function crlDn(scopeId, caId) {
  const base = directoryBaseFor(scopeId);
  return 'cn=' + String(caId) + ',ou=crl,' + base;
}

// The directory slot, filled by `ldap/ldap_server.js` at its require time. It
// is an inverted hook for rule 3e's reason: only that module can answer what a
// realm's base DN is or write an entry, it is required at 21 so a require the
// other way would drag every `/ldap` route into the router ahead of it, and
// this file is a LEAF that anything may require.
let directory = null;

function setDirectory(hooks) {
  log.debug('Entering setDirectory().');
  if (!hooks || typeof hooks.publishCrl !== 'function' ||
      typeof hooks.baseDnFor !== 'function') {
    log.error('pki_revocation: a directory was offered without both ' +
              'publishCrl() and baseDnFor(). It was REFUSED WHOLE — a ' +
              'half-filled slot would leave the CRLs published over HTTP and ' +
              'silently absent from LDAP, which is the one failure a reader ' +
              'checking three schemes would not think to look for.');
    log.debug('Leaving setDirectory(). Refused.');
    return false;
  }
  directory = hooks;
  log.debug('Leaving setDirectory(). Installed.');
  return true;
}

function directoryBaseFor(scopeId) {
  if (directory) {
    try {
      return directory.baseDnFor(scopeId);
    } catch (e) {
      log.warn('pki_revocation: the directory could not say where the "' +
               scopeId + '" scope lives: ' + e.message);
    }
  }
  // No directory in this process. The DN is still built, because it appears in
  // a URL inside a certificate and that URL has to be stable whether or not
  // this particular process happens to hold a directory.
  const base = config.value('ldap.baseDn');
  const id = String(scopeId);
  if (id === pki.SERVICE_SCOPE || id === pki.PROCESS_SCOPE || !id) {
    return base;
  }
  return 'dc=' + id + ',' + base;
}

module.exports = {
  REASONS: REASONS,
  REASON_IDS: REASON_IDS,
  reason: reason,
  authorities: authorities,
  authorityFor: authorityFor,
  listFor: listFor,
  isRevoked: isRevoked,
  normalSerial: normalSerial,
  revoke: revoke,
  release: release,
  describeEntry: describeEntry,
  distributionPoints: distributionPoints,
  crlDn: crlDn,
  scopeSegment: scopeSegment,
  scopeFromSegment: scopeFromSegment,
  httpBase: httpBase,
  setDirectory: setDirectory,
  directoryBaseFor: directoryBaseFor,
  // Filled in below by the CRL and OCSP halves.
  buildCrl: null,
  answerOcsp: null
};

// ===========================================================================
// THE CRL ITSELF — RFC 5280 section 5, built with pkijs.
//
// **IT IS BUILT ON DEMAND AND NOT CACHED, WHICH IS A DECISION.** A CRL carries
// `thisUpdate` and `nextUpdate`, and a cached document would go on claiming a
// freshness window it no longer has — so the choice is between re-signing on
// every fetch and inventing an invalidation rule. Re-signing is one RSA
// signature over a list that is almost always empty, and this is a mock whose
// CRL is fetched by a person testing their client rather than by the internet.
// ===========================================================================
// **IT RETURNS AN ArrayBuffer AND NOT A Buffer, AND THAT IS NOT A STYLE
// CHOICE.** node allocates small Buffers out of a SHARED POOL, so `buf.buffer`
// is an ArrayBuffer holding other people's bytes with this one somewhere in
// the middle — and `pkijs.Certificate.fromBER(buf)` reads from offset zero of
// that pool. It parses *something*, without error, and what comes back is a
// certificate whose subject and public key belong to whatever was allocated
// before it.
//
// The symptom is as far from the cause as it gets: every OCSP answer came back
// `unknown` with "another issuer", because the issuer-name and issuer-key
// hashes were computed over a certificate nobody had asked about. Both hashes
// matched OpenSSL's perfectly when computed in a probe — which is what took
// the time.
function derFromPem(pem) {
  const buf = Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, ''), 'base64');
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

// pkijs wants a Web Crypto engine. node 18+ has one on the global, which is
// what `common/vendored/key_material.js` already relies on — this is the same
// initialisation, said again here because requiring that module for its side
// effect would be a dependency nobody could see.
(function initEngine() {
  try {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      pkijs.setEngine('webcrypto',
                      new pkijs.CryptoEngine({ name: 'webcrypto',
                                               crypto: crypto }));
    }
  } catch (e) {
    log.error('pki_revocation: the Web Crypto engine could not be installed: ' +
              e.message + '. CRLs and OCSP responses cannot be signed.');
  }
})();

// The signature algorithm identifier for an issuer's key, as pkijs wants it.
// It is derived from the AUTHORITY'S key and not chosen, for the reason
// `common/pki.js` gives about certificates: a document whose declared
// algorithm and actual signature disagree is reported by every validator as a
// bad signature, naming neither.
function signingParamsFor(tier) {
  const desc = keyMaterial.keyAlg(tier.keyAlg) || {};
  const sig = x509.sigAlg(tier.signatureAlg) || {};
  if (desc.kind === 'ec') {
    return { name: 'ECDSA', hash: { name: sig.hash || 'SHA-256' } };
  }
  if (desc.kind === 'okp') {
    return { name: 'Ed25519' };
  }
  if (sig.pss) {
    return { name: 'RSA-PSS', hash: { name: sig.hash || 'SHA-256' },
             saltLength: 32 };
  }
  return { name: 'RSASSA-PKCS1-v1_5', hash: { name: sig.hash || 'SHA-256' } };
}

async function importSigningKey(tier) {
  const desc = keyMaterial.keyAlg(tier.keyAlg);
  const params = signingParamsFor(tier);
  const pkcs8 = derFromPem(tier.privateKeyPem);
  const algorithm = desc && desc.kind === 'ec'
    ? { name: 'ECDSA', namedCurve: desc.curve }
    : (desc && desc.kind === 'okp'
        ? { name: 'Ed25519' }
        : { name: params.name, hash: params.hash });
  return crypto.subtle.importKey('pkcs8', pkcs8, algorithm, false, ['sign']);
}

// How long a CRL claims to be fresh. Short by default and settable, because
// the interesting thing a client author does with this is revoke something and
// watch their stack notice — and a stack that cached a twenty-four hour list
// will not notice for twenty-four hours.
function crlLifetimeMs() {
  return Math.max(60, Number(config.value('pki.crlLifetimeMinutes')) || 60) *
         60000;
}

async function buildCrl(scopeId, caId) {
  log.debug('Entering buildCrl(). scope=' + scopeId + ' ca=' + caId);
  const authority = authorityFor(scopeId, caId);
  if (!authority) {
    log.debug('Leaving buildCrl(). No such authority.');
    return { ok: false,
             errors: ['There is no "' + caId + '" certificate authority in ' +
                      'that scope.'] };
  }
  const tier = authority.tier;
  const issuerCert = pkijs.Certificate.fromBER(derFromPem(tier.certificatePem));
  const crl = new pkijs.CertificateRevocationList();
  crl.version = 1;                       // v2, which is what an extension needs
  crl.issuer = issuerCert.subject;
  const now = new Date();
  crl.thisUpdate = new pkijs.Time({ type: 0, value: now });
  crl.nextUpdate = new pkijs.Time({ type: 0,
                                    value: new Date(now.getTime() +
                                                    crlLifetimeMs()) });

  const entries = listFor(scopeId, caId);
  if (entries.length) {
    crl.revokedCertificates = entries.map(function (one) {
      const revoked = new pkijs.RevokedCertificate();
      revoked.userCertificate = new asn1js.Integer({
        valueHex: serialBytes(one.serialHex)
      });
      revoked.revocationDate = new pkijs.Time({ type: 0,
                                                value: new Date(one.revokedAt) });
      // THE REASON CODE, OMITTED FOR `unspecified` — see the REASONS table.
      if (one.reasonCode) {
        revoked.crlEntryExtensions = new pkijs.Extensions({
          extensions: [new pkijs.Extension({
            extnID: '2.5.29.21',
            critical: false,
            extnValue: new asn1js.Enumerated({ value: one.reasonCode })
              .toBER(false)
          })]
        });
      }
      return revoked;
    });
  }

  // TWO EXTENSIONS, AND BOTH ARE LOAD-BEARING RATHER THAN DECORATION.
  //
  //   * `cRLNumber` (2.5.29.20) is how a validator tells a newer list from an
  //     older one. Without it two lists with different contents are
  //     indistinguishable, and a client that cached the wrong one has no way
  //     to find out.
  //   * `authorityKeyIdentifier` (2.5.29.35) is how it finds the certificate
  //     that signed this list when several share a subject — which is exactly
  //     what happens here every time an authority is reissued.
  const number = ((rowFor(scopeId) || {}).crlNumbers || {})[String(caId)] || 0;
  const extensions = [
    new pkijs.Extension({
      extnID: '2.5.29.20', critical: false,
      extnValue: new asn1js.Integer({ value: number }).toBER(false)
    })
  ];
  const akid = issuerCert.extensions && issuerCert.extensions.filter(
    function (one) { return one.extnID === '2.5.29.14'; })[0];
  if (akid) {
    // The ISSUER's subjectKeyIdentifier becomes this list's
    // authorityKeyIdentifier, which is the same value read from the other end.
    extensions.push(new pkijs.Extension({
      extnID: '2.5.29.35', critical: false,
      extnValue: new asn1js.Sequence({
        value: [new asn1js.Primitive({
          idBlock: { tagClass: 3, tagNumber: 0 },
          valueHex: akid.parsedValue.valueBlock.valueHexView
        })]
      }).toBER(false)
    }));
  }
  crl.crlExtensions = new pkijs.Extensions({ extensions: extensions });

  try {
    const key = await importSigningKey(tier);
    await crl.sign(key, signingParamsFor(tier).hash
      ? signingParamsFor(tier).hash.name : undefined);
  } catch (e) {
    log.error('pki_revocation: the "' + caId + '" CRL in "' +
              (String(scopeId) || 'default') + '" could not be signed: ' +
              e.message);
    log.debug('Leaving buildCrl(). The signature failed.');
    return { ok: false,
             errors: ['That CRL could not be signed: ' + e.message] };
  }
  const der = Buffer.from(crl.toSchema(true).toBER(false));
  log.debug('Leaving buildCrl(). ' + entries.length + ' entry(ies), ' +
            der.length + ' bytes.');
  return { ok: true, der: der, count: entries.length, crlNumber: number,
           thisUpdate: now.toISOString(),
           nextUpdate: new Date(now.getTime() + crlLifetimeMs()).toISOString() };
}

// A serial as DER integer bytes. **A LEADING ZERO IS ADDED WHERE THE TOP BIT
// IS SET**, because a DER INTEGER is signed and a serial with its high bit set
// would otherwise encode as a negative number — which is a different serial,
// and the certificate would be revoked in name only.
function serialBytes(serialHex) {
  let hex = normalSerial(serialHex);
  if (hex.length % 2) {
    hex = '0' + hex;
  }
  const bytes = Buffer.from(hex, 'hex');
  if (bytes[0] & 0x80) {
    return Buffer.concat([Buffer.from([0]), bytes]).buffer.slice(0);
  }
  return bytes.buffer.slice(bytes.byteOffset,
                            bytes.byteOffset + bytes.byteLength);
}

// ---------------------------------------------------------------------------
// PUBLISH ONE AUTHORITY'S CRL INTO THE DIRECTORY, and every authority's at
// startup. Called after every revocation and from `pki.start()`, so the
// `ldap://` addresses in certificates resolve to a list that is current.
//
// **NOT AWAITED BY THE REVOCATION**, which is the same shape as every other
// write-behind in this service: a directory that could not take the entry must
// not be able to fail a revocation, and the register is the truth either way.
// ---------------------------------------------------------------------------
function publishSoon(scopeId, caId) {
  if (!directory) {
    return;
  }
  setImmediate(function () {
    Promise.resolve(buildCrl(scopeId, caId)).then(function (made) {
      if (made.ok) {
        directory.publishCrl(scopeId, caId, made.der);
      }
    }).catch(function (e) {
      log.error('pki_revocation: the "' + caId + '" CRL could not be ' +
                'published into the directory: ' + e.message);
    });
  });
}

async function publishAll(scopeIds) {
  log.debug('Entering publishAll().');
  if (!directory) {
    log.debug('Leaving publishAll(). No directory in this process.');
    return 0;
  }
  const all = authorities(scopeIds);
  let done = 0;
  for (let i = 0; i < all.length; i++) {
    const one = all[i];
    try {
      const made = await buildCrl(one.scope, one.ca);
      if (made.ok && directory.publishCrl(one.scope, one.ca, made.der)) {
        done += 1;
      }
    } catch (e) {
      log.error('pki_revocation: the "' + one.ca + '" CRL of "' +
                (one.scope || 'default') + '" could not be published: ' +
                e.message);
    }
  }
  log.debug('Leaving publishAll(). ' + done + ' published.');
  return done;
}

module.exports.buildCrl = buildCrl;
module.exports.serialBytes = serialBytes;
module.exports.publishSoon = publishSoon;
module.exports.publishAll = publishAll;

// ===========================================================================
// THE OCSP RESPONDER — RFC 6960.
//
// **IT ANSWERS `unknown` FOR A CERTIFICATE IT CANNOT ACCOUNT FOR, AND THAT IS
// THE INTERESTING HALF.** A responder that answered `good` for anything it had
// not heard of would be worse than no responder at all: every certificate in
// the world would come back good, including revoked ones from another issuer.
// So the rule is the specification's — `good` only for a serial this authority
// actually issued and has not revoked, `revoked` for one on its list, and
// `unknown` for everything else.
//
// **THE RESPONSE IS SIGNED BY THE CA ITSELF**, which RFC 6960 section 4.2.2.2
// allows as the first of its three cases ("the CA who issued the certificate in
// question"). A delegated responder certificate — the `id-kp-OCSPSigning` case
// — is the other common arrangement and is deliberately not built: it would
// need its own key, its own certificate and its own `id-pkix-ocsp-nocheck`, and
// what it buys is keeping the CA key off the responder, which is a property a
// mock holding every key in one process cannot have anyway.
// ===========================================================================
function hashAlgorithmName(oid) {
  const known = {
    '1.3.14.3.2.26': 'SHA-1',
    '2.16.840.1.101.3.4.2.1': 'SHA-256',
    '2.16.840.1.101.3.4.2.2': 'SHA-384',
    '2.16.840.1.101.3.4.2.3': 'SHA-512'
  };
  return known[String(oid)] || null;
}

// Whether a CertID in a request is about THIS authority: the hash of the
// issuer's name and the hash of its public key, both under the algorithm the
// REQUESTER chose. Computed rather than compared against a stored value,
// because the requester picks the digest and a responder that only knew SHA-1
// would answer `unknown` to every modern client.
async function certIdMatches(certId, issuerCert) {
  const hash = hashAlgorithmName(certId.hashAlgorithm.algorithmId);
  if (!hash) {
    return false;
  }
  const nameDer = issuerCert.subject.toSchema().toBER(false);
  const keyDer = issuerCert.subjectPublicKeyInfo.subjectPublicKey.valueBlock
    .valueHexView;
  const nameHash = Buffer.from(await crypto.subtle.digest(hash, nameDer));
  const keyHash = Buffer.from(await crypto.subtle.digest(hash, keyDer));
  const gotName = Buffer.from(certId.issuerNameHash.valueBlock.valueHexView);
  const gotKey = Buffer.from(certId.issuerKeyHash.valueBlock.valueHexView);
  return nameHash.equals(gotName) && keyHash.equals(gotKey);
}

function serialOf(certId) {
  return Buffer.from(certId.serialNumber.valueBlock.valueHexView)
    .toString('hex');
}

// The two responses that carry no data, built by hand because pkijs's
// `OCSPResponse` wants a status and nothing else for them. RFC 6960 section
// 4.2.1: `malformedRequest` is 1 and `unauthorized` is 6.
function bareResponse(status) {
  const response = new pkijs.OCSPResponse();
  response.responseStatus.valueBlock.valueDec = status;
  return Buffer.from(response.toSchema(true).toBER(false));
}

async function answerOcsp(scopeId, caId, requestDer) {
  log.debug('Entering answerOcsp(). scope=' + scopeId + ' ca=' + caId);
  const authority = authorityFor(scopeId, caId);
  if (!authority) {
    log.debug('Leaving answerOcsp(). No such authority.');
    // `unauthorized` rather than `unknown`: there is no responder at this
    // address at all, which is a different thing from a responder that has not
    // heard of a certificate.
    return { ok: true, der: bareResponse(6), status: 'unauthorized' };
  }
  let request;
  try {
    request = pkijs.OCSPRequest.fromBER(
      requestDer.buffer.slice(requestDer.byteOffset,
                              requestDer.byteOffset + requestDer.byteLength));
  } catch (e) {
    log.debug('Leaving answerOcsp(). Malformed request.');
    return { ok: true, der: bareResponse(1), status: 'malformedRequest' };
  }
  const tier = authority.tier;
  const issuerCert = pkijs.Certificate.fromBER(derFromPem(tier.certificatePem));
  const wanted = (request.tbsRequest.requestList || []);
  const now = new Date();
  const responses = [];
  const reported = [];
  for (let i = 0; i < wanted.length; i++) {
    const certId = wanted[i].reqCert;
    const single = new pkijs.SingleResponse();
    single.certID = certId;
    single.thisUpdate = now;
    single.nextUpdate = new Date(now.getTime() + crlLifetimeMs());
    const mine = await certIdMatches(certId, issuerCert);
    const serial = serialOf(certId);
    if (!mine) {
      // NOT THIS AUTHORITY'S CERTIFICATE. `unknown`, which is the honest
      // answer and the one the specification asks for — answering `good`
      // would make this responder vouch for every issuer in the world.
      single.certStatus = new asn1js.Primitive({
        idBlock: { tagClass: 3, tagNumber: 2 }, lenBlockLength: 1
      });
      reported.push({ serial: serial, status: 'unknown',
                      why: 'another issuer' });
      responses.push(single);
      continue;
    }
    const revoked = isRevoked(scopeId, caId, serial);
    if (revoked) {
      const info = new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 1 },
        value: [new asn1js.GeneralizedTime({
          valueDate: new Date(revoked.revokedAt)
        })]
      });
      if (revoked.reasonCode) {
        info.valueBlock.value.push(new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 0 },
          value: [new asn1js.Enumerated({ value: revoked.reasonCode })]
        }));
      }
      single.certStatus = info;
      reported.push({ serial: serial, status: 'revoked',
                      reason: revoked.reason });
      responses.push(single);
      continue;
    }
    // **`good` ONLY FOR A SERIAL THIS AUTHORITY REALLY ISSUED.** Anything else
    // is `unknown`: a responder that answered `good` for a certificate it has
    // no record of is a responder that vouches for forgeries.
    if (!issuedHere(scopeId, caId, serial)) {
      single.certStatus = new asn1js.Primitive({
        idBlock: { tagClass: 3, tagNumber: 2 }, lenBlockLength: 1
      });
      reported.push({ serial: serial, status: 'unknown',
                      why: 'no record of that serial' });
      responses.push(single);
      continue;
    }
    single.certStatus = new asn1js.Primitive({
      idBlock: { tagClass: 3, tagNumber: 0 }, lenBlockLength: 1
    });
    reported.push({ serial: serial, status: 'good' });
    responses.push(single);
  }

  const basic = new pkijs.BasicOCSPResponse();
  basic.tbsResponseData.responderID = issuerCert.subject;
  basic.tbsResponseData.producedAt = now;
  basic.tbsResponseData.responses = responses;
  // ---------------------------------------------------------------------
  // THE NONCE, ECHOED BACK (RFC 6960 section 4.4.1).
  //
  // A requester that sends one is asking the responder to prove this answer
  // was produced for THIS request rather than replayed from a cache, and the
  // only way to say so is to copy the value into the response. **A responder
  // that drops it turns every answer into a replayable one**, which is the
  // single most useful thing a nonce prevents — and OpenSSL says so out loud
  // (`WARNING: no nonce in response`), which is how this was noticed.
  //
  // It is copied VERBATIM and never generated: a nonce this service invented
  // would match nothing the requester sent and is worse than none at all.
  // A request without one gets a response without one, which is correct.
  // ---------------------------------------------------------------------
  const asked = request.tbsRequest.requestExtensions || [];
  const nonce = asked.filter(function (one) {
    return one.extnID === '1.3.6.1.5.5.7.48.1.2';
  })[0];
  if (nonce) {
    basic.tbsResponseData.responseExtensions = [new pkijs.Extension({
      extnID: '1.3.6.1.5.5.7.48.1.2',
      critical: false,
      extnValue: nonce.extnValue.valueBlock.valueHexView.slice().buffer
    })];
  }
  // THE CA'S OWN CERTIFICATE TRAVELS WITH THE ANSWER, so a client that has the
  // Root and nothing else can verify the signature without a second fetch.
  basic.certs = [issuerCert];
  try {
    const key = await importSigningKey(tier);
    const params = signingParamsFor(tier);
    await basic.sign(key, params.hash ? params.hash.name : undefined);
  } catch (e) {
    log.error('pki_revocation: an OCSP response from the "' + caId +
              '" authority could not be signed: ' + e.message);
    log.debug('Leaving answerOcsp(). The signature failed.');
    return { ok: true, der: bareResponse(2), status: 'internalError' };
  }
  const response = new pkijs.OCSPResponse();
  response.responseStatus.valueBlock.valueDec = 0;         // successful
  response.responseBytes = new pkijs.ResponseBytes();
  response.responseBytes.responseType = '1.3.6.1.5.5.7.48.1.1';
  response.responseBytes.response = new asn1js.OctetString({
    valueHex: basic.toSchema().toBER(false)
  });
  const der = Buffer.from(response.toSchema(true).toBER(false));
  log.debug('Leaving answerOcsp(). ' + reported.length + ' answer(s).');
  return { ok: true, der: der, status: 'successful', answers: reported };
}

// Did this authority issue that serial? The certificate register knows the
// leaves, and `pki.js`'s own tiers know the authorities — so the two are asked
// in turn, which is also why a certificate removed from the register reports
// `unknown` rather than `good`.
// ---------------------------------------------------------------------------
// WHAT ONE AUTHORITY HAS SIGNED, as rows.
//
// **THIS IS THE ONE DEFINITION AND `issuedHere()` IS A PREDICATE OVER IT**,
// which is the whole reason it was pulled out on 2026-09-11. The revoke pane
// needs the LIST — an operator picks a certificate off it — and the OCSP
// responder needs the QUESTION *did I sign this serial*, and those were about
// to become two readings of the same four stores. Two readings is how a
// responder comes to answer `unknown` about a certificate the console is
// happily offering to revoke.
//
// **FOUR SOURCES, AND THE THREE AFTER THE FIRST ARE WHY IT IS NOT A ONE-LINER.**
// An authority signs AUTHORITIES as well as leaves: an Intermediate issued
// this scope's Issuing CAs and the Root issued every scope's Intermediate.
// Without those two branches a perfectly valid Issuing CA reports `unknown` at
// its own parent's responder — which is the most confusing answer available,
// because the certificate verifies and the responder disowns it. The fourth is
// the object store, where the Certificate & Key Configuration pane's leaves
// live rather than in the certificate register.
// ---------------------------------------------------------------------------
function issuedList(scopeId, caId) {
  log.debug('Entering issuedList(). scope=' + scopeId + ' ca=' + caId);
  const id = String(caId);
  const out = [];
  const seen = Object.create(null);
  function add(serialHex, subject, notAfter, kind, label) {
    const key = normalSerial(serialHex);
    if (!key || key === '0' || seen[key]) {
      return;
    }
    seen[key] = true;
    out.push({ serialHex: key, subject: String(subject || ''),
               notAfter: notAfter || '', kind: kind, label: String(label || ''),
               expired: notAfter
                 ? new Date(notAfter).getTime() < Date.now() : false });
  }

  // 1. The leaves this use case's Issuing CA certified — the signing keys of
  //    this realm, the TLS server certificate, a SPIFFE authority.
  pki.certificatesFor(scopeId, id).forEach(function (one) {
    add(one.serialHex, one.subject, one.notAfter, 'leaf',
        one.label || one.slot || '');
  });

  // 2. An Intermediate signed this scope's Issuing CAs.
  const row = rowFor(scopeId);
  if (id === 'intermediate' && row) {
    Object.keys(row.issuing || {}).forEach(function (useCaseId) {
      const tier = row.issuing[useCaseId];
      add(tier.serialHex, tier.subject, tier.notAfter, 'issuing-ca',
          ((pki.useCase(useCaseId) || {}).label || useCaseId) + ' Issuing CA');
    });
  }

  // 3. The Root signed EVERY scope's Intermediate, which is why this one walks
  //    the scopes rather than this row: the Root belongs to no scope.
  if (id === 'root') {
    pki.knownScopes().concat([pki.PROCESS_SCOPE]).forEach(function (one) {
      const held = pki.rawRowFor(one);
      if (held && held.intermediate) {
        add(held.intermediate.serialHex, held.intermediate.subject,
            held.intermediate.notAfter, 'intermediate-ca',
            (one === pki.PROCESS_SCOPE ? 'process' : (one || 'default')) +
            ' Intermediate CA');
      }
    });
  }

  // 4. And whatever the Certificate & Key Configuration pane issued. Those are
  //    in the OBJECT STORE rather than the certificate register, and an
  //    operator who minted one from this authority expects to be able to
  //    revoke it here.
  pki.objects(scopeId).forEach(function (one) {
    add(one.serialHex, one.subject, one.notAfter, 'object',
        one.label || one.name || '');
  });

  out.sort(function (a, b) {
    return String(a.subject).localeCompare(String(b.subject));
  });
  log.debug('Leaving issuedList(). ' + out.length + ' certificate(s).');
  return out;
}

function issuedHere(scopeId, caId, serialHex) {
  const wanted = normalSerial(serialHex);
  return issuedList(scopeId, caId).some(function (one) {
    return one.serialHex === wanted;
  });
}

module.exports.answerOcsp = answerOcsp;
module.exports.issuedHere = issuedHere;
module.exports.issuedList = issuedList;
