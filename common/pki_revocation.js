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
// For DEFAULT_ID only. `pki.js` requires it already and it requires nothing
// here, so this is a cache hit and closes no cycle.
const realms = require('./realms');
// The error-code registry (a leaf). A refusal returned to a caller carries its
// code non-enumerably, so an OCSP answer or a console reply serialised whole
// never shows it; `pki/pki_service.js` marks its response from `codeOf()`.
const errorCodes = require('./error_codes');
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
          'certificate is rotated or reissued**, which is the commonest ' +
          'entry on any of these lists.' },
  { id: 'cessationOfOperation', code: 5,
    what: 'The subject has stopped doing whatever the certificate was for.' },
  { id: 'certificateHold', code: 6,
    what: 'Temporarily suspended. **The only reason that can be UNDONE** — ' +
          'everything else is permanent, and a validator is entitled to ' +
          'cache a permanent revocation for as long as the CRL says it is ' +
          'fresh.' },
  { id: 'privilegeWithdrawn', code: 9,
    what:
      'The subject is no longer entitled to what the certificate asserts.' },
  { id: 'aACompromise', code: 10,
    what: 'An attribute authority\'s key is compromised. Here for ' +
          'completeness: this service issues no attribute certificates.' }
];

const REASON_IDS = REASONS.map(function (one) { return one.id; });

function reason(id) {
  log.debug("Entering reason().");
  log.debug("Leaving reason().");
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
               tier: row.intermediate,
               label: scope.label + ' Intermediate CA' });
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
  log.debug("Entering authorityFor().");
  const id = String(caId || '');
  if (id === 'root') {
    const root = pki.serviceRoot();
    log.debug("Leaving authorityFor().");
    return root ? { scope: pki.SERVICE_SCOPE, ca: 'root', tier: root } : null;
  }
  const row = pki.rawRowFor(scopeId);
  if (!row) {
    log.debug("Leaving authorityFor().");
    return null;
  }
  if (id === 'intermediate') {
    log.debug("Leaving authorityFor().");
    return row.intermediate
      ? { scope: String(scopeId), ca: 'intermediate', tier: row.intermediate }
      : null;
  }
  const held = (row.issuing || {})[id];
  log.debug("Leaving authorityFor().");
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
  log.debug("Entering rowFor().");
  log.debug("Leaving rowFor().");
  return pki.rawRowFor(scopeId) || null;
}

function listFor(scopeId, caId) {
  log.debug("Entering listFor().");
  const row = rowFor(scopeId);
  const held = (row && row.revoked) || {};
  log.debug("Leaving listFor().");
  return (held[String(caId)] || []).slice();
}

// A serial as this module compares them: lower case, no leading zeros, no
// separators. **A CRL and an OCSP request do not agree about the spelling of a
// serial** — one carries the DER integer and the other a hex string somebody
// typed — so every comparison in this file goes through here. Two spellings of
// one serial is a certificate that is revoked and reports as good.
function normalSerial(text) {
  log.debug("Entering normalSerial().");
  const hex = String(text || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  const trimmed = hex.replace(/^0+/, '');
  log.debug("Leaving normalSerial().");
  return trimmed || '0';
}

function isRevoked(scopeId, caId, serialHex) {
  log.debug("Entering isRevoked().");
  const wanted = normalSerial(serialHex);
  log.debug("Leaving isRevoked().");
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
    return errorCodes.mark({ ok: false,
             errors: ['There is no "' + caId + '" certificate authority in ' +
                      'that scope, so nothing it issued can be revoked by ' +
                      'it. A revocation is made BY AN ISSUER — a serial is ' +
                      'only unique within one.'] }, 'STS-PKI-0055');
  }
  const serialHex = normalSerial((spec || {}).serialHex);
  if (!serialHex || serialHex === '0') {
    log.debug('Leaving revoke(). No serial.');
    return errorCodes.mark({ ok: false,
             errors: ['A revocation names a SERIAL NUMBER. It is the only ' +
                      'thing a CRL entry and an OCSP answer have in common ' +
                      'with the certificate they are about.'] },
                           'STS-PKI-0056');
  }
  const chosen = reason((spec || {}).reason || 'superseded');
  if (!chosen) {
    log.debug('Leaving revoke(). Unknown reason.');
    return errorCodes.mark({ ok: false,
             errors: ['"' + (spec || {}).reason + '" is not an RFC 5280 ' +
                      'revocation reason. They are ' + REASON_IDS.join(', ') +
                      '.'] }, 'STS-PKI-0057');
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
    log.debug("Leaving revoke().");
    return errorCodes.mark({ ok: false,
             errors: ['That scope holds no certificate authority.'] },
                           'STS-PKI-0055');
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
    return errorCodes.mark({ ok: false,
             errors: ['That serial is not on the ' + caId + ' authority\'s ' +
                      'revocation list.'] }, 'STS-PKI-0058');
  }
  if (held.reason !== 'certificateHold') {
    log.debug('Leaving release(). Not a hold.');
    return errorCodes.mark({ ok: false,
             errors: ['That certificate was revoked as "' + held.reason +
                      '", which RFC 5280 makes PERMANENT. Only a ' +
                      '`certificateHold` can be released: a validator is ' +
                      'entitled to cache a permanent revocation for as long ' +
                      'as the CRL it read says it is fresh, so undoing one ' +
                      'here would produce a certificate this service calls ' +
                      'good and half the world still calls revoked.'] },
                           'STS-PKI-0059');
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
                'has it** until that list expires, which is what makes a ' +
                'hold the only reversible reason and still not an instant ' +
                'one.' };
}

function describeEntry(one) {
  log.debug("Entering describeEntry().");
  if (!one) {
    log.debug("Leaving describeEntry().");
    return null;
  }
  const chosen = reason(one.reason);
  log.debug("Leaving describeEntry().");
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
// WHERE THE LISTS AND THE RESPONDERS ARE, IN TWO SCHEMES.
//
// **THE URL IS BUILT FROM CONFIGURATION AND NOT FROM A REQUEST, AND IT HAS TO
// BE.** These addresses go INSIDE certificates, and a certificate is minted at
// startup before any request exists — so `baseUrlOf(req)` is not available and
// would be the wrong answer anyway: a certificate is a durable document and
// the address in it must not depend on which Host header happened to be on the
// request that triggered the issue.
//
// **TWO SCHEMES, http AND ldap, SINCE 2026-09-13 — IT WAS THREE, AND https
// RATHER THAN http.** RFC 5280 section 8: *CAs SHOULD NOT include URIs that
// specify https, ldaps, or similar schemes in extensions*, because a relying
// party that checks revocation before it trusts a connection cannot fetch the
// answer over the connection it is checking — and the main port's own TLS
// certificate named its OCSP responder on that very listener. RFC 5019
// section 5 adds that an OCSP responder MUST support plain HTTP, and RFC 4516
// defines the `ldap` scheme and no other. So the http addresses name
// `pki.httpPort`, a plain listener that answers `/pki/` and nothing else
// (pki/pki_service.js), and `ldaps://` is not written at all; the LDAPS
// listener still serves the same entries to anybody who asks it directly.
//
// **AND THE PORT IS THE ONE A CLIENT DIALS, WHICH IS NOT ALWAYS THE ONE THE
// LISTENER BOUND (2026-09-13).** This read `global.port` unconditionally, so a
// container listening on 8081 and published on host port 18081 put `:8081` in
// every certificate it issued — an address that answered nothing from where
// the certificate was read. Nothing inside a container can see the host side
// of its port mapping, so it is TOLD: `pki.distributionBaseUrl` whole, or
// `pki.distributionPort` beside the derived host. Every compose file here
// passes one of those.
// ---------------------------------------------------------------------------
function httpBase() {
  log.debug("Entering httpBase().");
  const set = String(config.value('pki.distributionBaseUrl') || '').trim();
  if (set) {
    log.debug("Leaving httpBase(). pki.distributionBaseUrl");
    return set.replace(/\/+$/, '');
  }
  const host = (config.value('tls.hostnames') || ['localhost'])[0] ||
               'localhost';
  if (Number(config.value('pki.httpPort')) > 0) {
    log.debug("Leaving httpBase(). The plain-HTTP revocation listener.");
    return 'http://' + host + ':' +
           publishedPort('pki.distributionPort', 'pki.httpPort');
  }
  // No plain listener: the main port, in the scheme it answers in. That is
  // an https address whenever `global.https` is on, which section 8 advises
  // against — and it is still better than naming a port nothing is bound to.
  const scheme = config.value('global.https') ? 'https' : 'http';
  log.debug("Leaving httpBase(). The main port.");
  return scheme + '://' + host + ':' +
         publishedPort('pki.distributionPort', 'global.port');
}

// A published port, or the listener's own where none was named. `port` is 0
// for "not set" and 0 is never a port anybody can dial, so it is the one value
// the fallback may treat as absent — the `0 || n` rule in the root CLAUDE.md is
// about settings where 0 is legal, and here it is not.
function publishedPort(settingKey, listenerKey) {
  log.debug("Entering publishedPort().");
  const named = Number(config.value(settingKey));
  log.debug("Leaving publishedPort().");
  return named > 0 ? named : config.value(listenerKey);
}

function ldapHost() {
  log.debug("Entering ldapHost().");
  const set = String(config.value('pki.distributionLdapHost') || '').trim();
  if (set) {
    log.debug("Leaving ldapHost().");
    return set;
  }
  log.debug("Leaving ldapHost().");
  return (config.value('tls.hostnames') || ['localhost'])[0] || 'localhost';
}

// The path segment a scope goes in. `*service` and `*process` cannot go in a
// URL as they are — a `*` is legal in a path and reads as a wildcard to
// everything that logs one — so they are spelled out.
function scopeSegment(scopeId) {
  log.debug("Entering scopeSegment().");
  const id = String(scopeId);
  if (id === pki.SERVICE_SCOPE) {
    log.debug("Leaving scopeSegment().");
    return 'service';
  }
  if (id === pki.PROCESS_SCOPE) {
    log.debug("Leaving scopeSegment().");
    return 'process';
  }
  log.debug("Leaving scopeSegment().");
  return id || 'default';
}

function scopeFromSegment(segment) {
  log.debug("Entering scopeFromSegment().");
  const one = String(segment || '');
  if (one === 'service') {
    log.debug("Leaving scopeFromSegment().");
    return pki.SERVICE_SCOPE;
  }
  if (one === 'process') {
    log.debug("Leaving scopeFromSegment().");
    return pki.PROCESS_SCOPE;
  }
  log.debug("Leaving scopeFromSegment().");
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
  log.debug("Entering distributionPoints().");
  const segment = scopeSegment(scopeId);
  const file = segment + '/' + String(caId);
  const dn = crlDn(scopeId, caId);
  log.debug("Leaving distributionPoints().");
  return {
    http: httpBase() + '/pki/crl/' + file + '.crl',
    ldap: 'ldap://' + ldapHost() + ':' +
          publishedPort('pki.distributionLdapPort', 'ldap.port') + '/' +
          encodeURI(dn) + '?certificateRevocationList;binary',
    ocsp: httpBase() + '/pki/ocsp/' + file,
    caIssuers: httpBase() + '/pki/ca/' + file + '.cer',
    dn: dn
  };
}

// Where a CRL lives in the embedded directory. A container per scope under
// that realm's own subtree, because a CRL belongs to the realm whose authority
// signed it — exactly as `ou=applications` does.
//
// **THE TWO STARRED SCOPES GET AN `ou` OF THEIR OWN, AND FOR TWO DAYS THEY DID
// NOT (2026-09-13).** Both live in the DEFAULT realm's subtree, because they
// belong to no realm and that is the one subtree every process has — and the
// DN was `cn=<ca>,ou=crl,<default base>` for all three. So the PROCESS branch's
// Intermediate and the default realm's Intermediate, two authorities with two
// keys and two lists, were published to ONE entry, and whichever was written
// last was what the `ldap://` distribution points in BOTH
// authorities' certificates fetched. A relying party following one got a CRL
// signed by a different issuer, which it must reject (RFC 5280 section 6.3.3
// (b)) — so an LDAP revocation check of every TLS certificate this service
// serves failed, with nothing wrong on the HTTP path to compare it with.
//
// **THIS IS THE ONE DN BUILDER.** `ldap/ldap_server.js`'s `publishCrl()` writes
// to the DN this function answers rather than composing its own, because two
// builders is how the certificate's address and the entry's address came to
// agree while both being wrong.
function crlDn(scopeId, caId) {
  log.debug("Entering crlDn().");
  const base = directoryBaseFor(scopeId);
  const id = String(scopeId);
  let branch = '';
  if (id === pki.SERVICE_SCOPE) {
    branch = 'ou=service,';
  } else if (id === pki.PROCESS_SCOPE) {
    branch = 'ou=process,';
  }
  log.debug("Leaving crlDn().");
  return 'cn=' + String(caId) + ',' + branch + 'ou=crl,' + base;
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
    log.error(errorCodes.tag('STS-PKI-0060') + 'pki_revocation: a directory ' +
              'was offered without both publishCrl() and baseDnFor(). It was ' +
              'REFUSED WHOLE — a half-filled slot would leave the CRLs ' +
              'published over HTTP and silently absent from LDAP, which is ' +
              'the one failure a reader checking both schemes would not ' +
              'think to look for.');
    log.debug('Leaving setDirectory(). Refused.');
    return false;
  }
  directory = hooks;
  log.debug('Leaving setDirectory(). Installed.');
  return true;
}

function directoryBaseFor(scopeId) {
  log.debug("Entering directoryBaseFor().");
  if (directory) {
    try {
      log.debug("Leaving directoryBaseFor().");
      return directory.baseDnFor(scopeId);
    } catch (e) {
      log.warn(errorCodes.tag('STS-PKI-0061') + 'pki_revocation: the ' +
                                                'directory could not say ' +
                                                'where the "' +
               scopeId + '" scope lives: ' + e.message);
    }
  }
  // No directory in this process. The DN is still built, because it appears in
  // a URL inside a certificate and that URL has to be stable whether or not
  // this particular process happens to hold a directory.
  const base = config.value('ldap.baseDn');
  const id = String(scopeId);
  // **THE DEFAULT REALM HAS TWO SPELLINGS AND BOTH ARE ITS BASE.** A caller
  // may pass `''` or the id `realmIdOf()` resolves it to, `default`, and until
  // 2026-09-12 only the first was recognised here — so a process holding no
  // directory named `dc=default,<base>` in every default-realm certificate
  // while `ldap_server.js`'s `baseDnFor()`, which publishes the list, answers
  // `<base>`. The URL was stable across processes only when all of them had a
  // directory, which is the one condition this fallback exists for not having.
  if (id === pki.SERVICE_SCOPE || id === pki.PROCESS_SCOPE || !id ||
      id === realms.DEFAULT_ID) {
    log.debug("Leaving directoryBaseFor().");
    return base;
  }
  log.debug("Leaving directoryBaseFor().");
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
  log.debug("Entering derFromPem().");
  const buf = Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, ''), 'base64');
  log.debug("Leaving derFromPem().");
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

// pkijs wants a Web Crypto engine. node 18+ has one on the global, which is
// what `common/vendored/key_material.js` already relies on — this is the same
// initialisation, said again here because requiring that module for its side
// effect would be a dependency nobody could see.
(function initEngine() {
  log.debug("Entering initEngine().");
  try {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      pkijs.setEngine('webcrypto',
                      new pkijs.CryptoEngine({ name: 'webcrypto',
                                               crypto: crypto }));
    }
  } catch (e) {
    log.error(errorCodes.tag('STS-PKI-0062') + 'pki_revocation: the Web ' +
                                               'Crypto engine could not be ' +
                                               'installed: ' +
              e.message + '. CRLs and OCSP responses cannot be signed.');
  }
  log.debug("Leaving initEngine().");
})();

// The signature algorithm identifier for an issuer's key, as pkijs wants it.
// It is derived from the AUTHORITY'S key and not chosen, for the reason
// `common/pki.js` gives about certificates: a document whose declared
// algorithm and actual signature disagree is reported by every validator as a
// bad signature, naming neither.
function signingParamsFor(tier) {
  log.debug("Entering signingParamsFor().");
  const desc = keyMaterial.keyAlg(tier.keyAlg) || {};
  const sig = x509.sigAlg(tier.signatureAlg) || {};
  if (desc.kind === 'ec') {
    log.debug("Leaving signingParamsFor().");
    return { name: 'ECDSA', hash: { name: sig.hash || 'SHA-256' } };
  }
  if (desc.kind === 'okp') {
    log.debug("Leaving signingParamsFor().");
    return { name: 'Ed25519' };
  }
  if (sig.pss) {
    log.debug("Leaving signingParamsFor().");
    return { name: 'RSA-PSS', hash: { name: sig.hash || 'SHA-256' },
             saltLength: 32 };
  }
  log.debug("Leaving signingParamsFor().");
  return { name: 'RSASSA-PKCS1-v1_5', hash: { name: sig.hash || 'SHA-256' } };
}

async function importSigningKey(tier) {
  log.debug("Entering importSigningKey().");
  const desc = keyMaterial.keyAlg(tier.keyAlg);
  const params = signingParamsFor(tier);
  const pkcs8 = derFromPem(tier.privateKeyPem);
  const algorithm = desc && desc.kind === 'ec'
    ? { name: 'ECDSA', namedCurve: desc.curve }
    : (desc && desc.kind === 'okp'
        ? { name: 'Ed25519' }
        : { name: params.name, hash: params.hash });
  log.debug("Leaving importSigningKey().");
  return crypto.subtle.importKey('pkcs8', pkcs8, algorithm, false, ['sign']);
}

// How long a CRL claims to be fresh. Short by default and settable, because
// the interesting thing a client author does with this is revoke something and
// watch their stack notice — and a stack that cached a twenty-four hour list
// will not notice for twenty-four hours.
//
// **THE FLOOR IS THE ROW'S `min: 1` AND NOT A SECOND ONE HERE.** This read
// `Math.max(60, …)`, which silently turned every value from 1 to 59 — all of
// them accepted by `config.js` and drawn on the settings form as in force —
// into an hour. The cases that setting exists for are exactly the short ones.
// ---------------------------------------------------------------------------
// TIMES ARE WHOLE SECONDS, AND A CRL's ARE UTCTime UNTIL 2050 (2026-09-13).
//
// **A JavaScript `Date` carries milliseconds and asn1js WRITES them**, so an
// OCSP answer's `producedAt`, `thisUpdate` and `nextUpdate` went out as
// `20260913102536.003Z`. That is not DER: X.690 section 11.7 says a fraction
// omits trailing zeros, and RFC 5019 section 2.2.4 says an OCSP GeneralizedTime
// MUST NOT carry a fraction at all. OpenSSL reads it anyway, which is how it
// survived; stricter parsers refuse it. The CRL's revocation dates said
// `10:22:37` for a revocation the OCSP answer called `10:22:37.862`, which is
// the same instant stated two ways by one service.
//
// And RFC 5280 section 5.1.2.4 requires UTCTime through 2049 and
// GeneralizedTime from 2050. `type: 0` was written unconditionally, which is
// right until a CRL's nextUpdate crosses the century boundary — at which point
// UTCTime cannot express it at all.
// ---------------------------------------------------------------------------
function wholeSeconds(value) {
  log.debug("Entering wholeSeconds().");
  const ms = new Date(value).getTime();
  log.debug("Leaving wholeSeconds().");
  return new Date(Math.floor(ms / 1000) * 1000);
}

function crlTime(value) {
  log.debug("Entering crlTime().");
  const date = wholeSeconds(value);
  log.debug("Leaving crlTime().");
  return new pkijs.Time({ type: date.getUTCFullYear() < 2050 ? 0 : 1,
                          value: date });
}

function crlLifetimeMs() {
  log.debug("Entering crlLifetimeMs().");
  const minutes = Number(config.value('pki.crlLifetimeMinutes'));
  log.debug("Leaving crlLifetimeMs().");
  return Math.max(1, Number.isFinite(minutes) ? minutes : 60) * 60000;
}

// The last CRL number this process signed, per authority. See `buildCrl()`.
const lastCrlNumbers = new Map();

function crlNumberAt(scopeId, caId, whenMs) {
  log.debug("Entering crlNumberAt().");
  const key = String(scopeId) + '/' + String(caId);
  const previous = lastCrlNumbers.get(key) || 0;
  const number = Math.max(Math.floor(whenMs), previous + 1);
  lastCrlNumbers.set(key, number);
  log.debug("Leaving crlNumberAt().");
  return number;
}

async function buildCrl(scopeId, caId) {
  log.debug('Entering buildCrl(). scope=' + scopeId + ' ca=' + caId);
  const authority = authorityFor(scopeId, caId);
  if (!authority) {
    log.debug('Leaving buildCrl(). No such authority.');
    return errorCodes.mark({ ok: false,
             errors: ['There is no "' + caId + '" certificate authority in ' +
                      'that scope.'] }, 'STS-PKI-0055');
  }
  const tier = authority.tier;
  const issuerCert = pkijs.Certificate.fromBER(derFromPem(tier.certificatePem));
  const crl = new pkijs.CertificateRevocationList();
  crl.version = 1;                       // v2, which is what an extension needs
  crl.issuer = issuerCert.subject;
  const now = wholeSeconds(Date.now());
  crl.thisUpdate = crlTime(now);
  crl.nextUpdate = crlTime(now.getTime() + crlLifetimeMs());

  const entries = listFor(scopeId, caId);
  if (entries.length) {
    crl.revokedCertificates = entries.map(function (one) {
      const revoked = new pkijs.RevokedCertificate();
      revoked.userCertificate = new asn1js.Integer({
        valueHex: serialBytes(one.serialHex)
      });
      revoked.revocationDate = crlTime(one.revokedAt);
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
  //
  // **THE NUMBER CHANGES WITH EVERY SIGNING, AND UNTIL 2026-09-13 IT DID NOT.**
  // It was read from the register, which moved only on a revoke or a release —
  // and this function signs a NEW list, with a new `thisUpdate`, on every
  // fetch. RFC 5280 section 5.2.3 is explicit: *if the thisUpdate … in the two
  // CRLs are not identical, the CRL numbers MUST be different.* Two fetches two
  // seconds apart came back as two documents both calling themselves number 3.
  //
  // So it is `crlNumberAt()`: the signing instant in milliseconds, forced
  // above anything this process has already used for that authority. That is
  // monotonic with no coordination — which a counter in the shared register
  // would need, since several processes sign lists for one authority at once
  // — and it can never go below a number the register-based scheme issued,
  // because that one counted revocations and this one counts milliseconds.
  const number = crlNumberAt(scopeId, caId, Date.now());
  const extensions = [
    new pkijs.Extension({
      extnID: '2.5.29.20', critical: false,
      extnValue: new asn1js.Integer({ value: number }).toBER(false)
    })
  ];
  const akid = issuerCert.extensions && issuerCert.extensions.filter(
    function (one) { return one.extnID === '2.5.29.14'; })[0];
  // The ISSUER's subjectKeyIdentifier becomes this list's
  // authorityKeyIdentifier, which is the same value read from the other end.
  //
  // **AND WHERE THE ISSUER HAS NONE, THE IDENTIFIER IS COMPUTED — IT WAS
  // OMITTED.** RFC 5280 section 5.2.1: *conforming CRL issuers MUST use the key
  // identifier method, and MUST include this extension in all CRLs issued.* A
  // hierarchy built here always carries an SKI, but an authority brought in
  // through `importCa()` need not, and its lists silently lost the one
  // extension that lets a validator find their signer. Section 4.2.1.2's first
  // method is the SHA-1 of the subjectPublicKey BIT STRING's value, which is
  // what an SKI conventionally is.
  const keyIdentifier = akid
    ? Buffer.from(akid.parsedValue.valueBlock.valueHexView)
    : nodeCrypto.createHash('sha1').update(Buffer.from(
      issuerCert.subjectPublicKeyInfo.subjectPublicKey.valueBlock
        .valueHexView)).digest();
  extensions.push(new pkijs.Extension({
    extnID: '2.5.29.35', critical: false,
    extnValue: new asn1js.Sequence({
      value: [new asn1js.Primitive({
        idBlock: { tagClass: 3, tagNumber: 0 },
        valueHex: keyIdentifier
      })]
    }).toBER(false)
  }));
  crl.crlExtensions = new pkijs.Extensions({ extensions: extensions });

  try {
    const key = await importSigningKey(tier);
    await crl.sign(key, signingParamsFor(tier).hash
      ? signingParamsFor(tier).hash.name : undefined);
  } catch (e) {
    log.error(errorCodes.tag('STS-PKI-0063') + 'pki_revocation: the "' + caId +
        '" ' +
        'CRL in "' +
              (String(scopeId) || 'default') + '" could not be signed: ' +
              e.message);
    log.debug('Leaving buildCrl(). The signature failed.');
    return errorCodes.mark({ ok: false,
             errors: ['That CRL could not be signed: ' + e.message] },
                           'STS-PKI-0063');
  }
  const der = Buffer.from(crl.toSchema(true).toBER(false));
  log.debug('Leaving buildCrl(). ' + entries.length + ' entry(ies), ' +
            der.length + ' bytes.');
  return { ok: true, der: der, count: entries.length, crlNumber: number,
           thisUpdate: now.toISOString(),
           nextUpdate: new Date(now.getTime() +
                                crlLifetimeMs()).toISOString() };
}

// A serial as DER integer bytes. **A LEADING ZERO IS ADDED WHERE THE TOP BIT
// IS SET**, because a DER INTEGER is signed and a serial with its high bit set
// would otherwise encode as a negative number — which is a different serial,
// and the certificate would be revoked in name only.
function serialBytes(serialHex) {
  log.debug("Entering serialBytes().");
  let hex = normalSerial(serialHex);
  if (hex.length % 2) {
    hex = '0' + hex;
  }
  const bytes = Buffer.from(hex, 'hex');
  if (bytes[0] & 0x80) {
    log.debug("Leaving serialBytes().");
    return Buffer.concat([Buffer.from([0]), bytes]).buffer.slice(0);
  }
  log.debug("Leaving serialBytes().");
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
  log.debug("Entering publishSoon().");
  if (!directory) {
    log.debug("Leaving publishSoon().");
    return;
  }
  setImmediate(function () {
    Promise.resolve(buildCrl(scopeId, caId)).then(function (made) {
      if (made.ok) {
        directory.publishCrl(scopeId, caId, made.der);
      }
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-PKI-0064') + 'pki_revocation: the "' +
                caId + '" ' +
                'CRL could not be published into the directory: ' + e.message);
    });
  });
  log.debug("Leaving publishSoon().");
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
      log.error(errorCodes.tag('STS-PKI-0064') + 'pki_revocation: the "' +
          one.ca + '" ' +
          'CRL of "' +
                (one.scope || 'default') + '" could not be published: ' +
                e.message);
    }
  }
  log.debug('Leaving publishAll(). ' + done + ' published.');
  return done;
}

// ---------------------------------------------------------------------------
// AND KEEP THEM CURRENT, WHICH NOTHING DID UNTIL 2026-09-13.
//
// A CRL says when it stops being fresh (`nextUpdate`, `pki.crlLifetimeMinutes`
// after it was signed), and RFC 5280 section 6.3.3 tells a relying party that
// a list past its `nextUpdate` does not settle anything. The HTTP distribution
// point signs a new one on every fetch, so it was always current; the
// DIRECTORY copy was written at startup and on a revocation and never again.
// **So an hour after start every `ldap://` distribution point
// in every certificate this service issues served an EXPIRED list**, and a
// branch built after startup — every realm created at runtime — had no entry
// at all until something on it was revoked. Nothing failed here; the failure
// is a relying party's, much later, reported as a revocation check it could
// not complete.
//
// Two mechanisms, and they are two because they answer two different events:
//
//   * **`publishScopeSoon()`**, called by `pki.js`'s `saveRow()` — the one
//     funnel every change to a branch goes through — so a branch built,
//     rebuilt or reissued is in the directory before anybody could have read
//     a certificate naming it. Coalesced per scope, because one build is
//     several saves.
//   * **`keepDirectoryCurrent()`**, a timer at half the lifetime, so a list is
//     replaced long before its `nextUpdate` whatever happened to the branch.
//     Half rather than just under the whole, so a relying party that fetched
//     a moment before the refresh still holds a list with time left on it.
//
// **THE TIMER IS UNREFERENCED** for the reason `keystore.js`'s purge timer is:
// a process holding nothing else must be able to exit, and `npm test` must not
// hang for half an hour because a module it required meant to refresh a CRL.
// ---------------------------------------------------------------------------
const scopesToPublish = new Map();

function publishScopeSoon(scopeId) {
  log.debug("Entering publishScopeSoon().");
  const id = String(scopeId === undefined || scopeId === null ? '' : scopeId);
  if (!directory || scopesToPublish.has(id)) {
    log.debug("Leaving publishScopeSoon(). Nothing to do.");
    return;
  }
  const timer = setTimeout(function () {
    scopesToPublish.delete(id);
    // The Root belongs to every scope's `authorities()` answer, so the
    // SERVICE scope itself is published by naming no branch at all.
    publishAll(id === pki.SERVICE_SCOPE ? [] : [id]).catch(function (e) {
      log.error(errorCodes.tag('STS-PKI-0064') + 'pki_revocation: the CRLs ' +
                'of the "' + (id || 'default') + '" scope could not be ' +
                'published into the directory: ' + ((e && e.message) || e));
    });
  }, 50);
  if (typeof timer.unref === 'function') {
    timer.unref();
  }
  scopesToPublish.set(id, timer);
  log.debug("Leaving publishScopeSoon(). Scheduled.");
}

let refresher = null;

function keepDirectoryCurrent() {
  log.debug("Entering keepDirectoryCurrent().");
  if (refresher || !directory) {
    log.debug("Leaving keepDirectoryCurrent(). Already running, or no " +
              "directory in this process.");
    return false;
  }
  const every = Math.max(60000, Math.floor(crlLifetimeMs() / 2));
  refresher = setInterval(function () {
    publishAll(pki.knownScopes()).catch(function (e) {
      log.error(errorCodes.tag('STS-PKI-0064') + 'pki_revocation: the ' +
                'directory copies of the CRLs could not be refreshed: ' +
                ((e && e.message) || e) + '. An ldap:// distribution point ' +
                'will serve a list past its nextUpdate.');
    });
  }, every);
  if (typeof refresher.unref === 'function') {
    refresher.unref();
  }
  log.debug("Leaving keepDirectoryCurrent(). Every " + every + "ms.");
  return true;
}

module.exports.buildCrl = buildCrl;
module.exports.serialBytes = serialBytes;
module.exports.publishSoon = publishSoon;
module.exports.publishAll = publishAll;
module.exports.publishScopeSoon = publishScopeSoon;
module.exports.keepDirectoryCurrent = keepDirectoryCurrent;

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
  log.debug("Entering hashAlgorithmName().");
  const known = {
    '1.3.14.3.2.26': 'SHA-1',
    '2.16.840.1.101.3.4.2.1': 'SHA-256',
    '2.16.840.1.101.3.4.2.2': 'SHA-384',
    '2.16.840.1.101.3.4.2.3': 'SHA-512'
  };
  log.debug("Leaving hashAlgorithmName().");
  return known[String(oid)] || null;
}

// Whether a CertID in a request is about THIS authority: the hash of the
// issuer's name and the hash of its public key, both under the algorithm the
// REQUESTER chose. Computed rather than compared against a stored value,
// because the requester picks the digest and a responder that only knew SHA-1
// would answer `unknown` to every modern client.
async function certIdMatches(certId, issuerCert) {
  log.debug("Entering certIdMatches().");
  const hash = hashAlgorithmName(certId.hashAlgorithm.algorithmId);
  if (!hash) {
    log.debug("Leaving certIdMatches().");
    return false;
  }
  const nameDer = issuerCert.subject.toSchema().toBER(false);
  const keyDer = issuerCert.subjectPublicKeyInfo.subjectPublicKey.valueBlock
    .valueHexView;
  const nameHash = Buffer.from(await crypto.subtle.digest(hash, nameDer));
  const keyHash = Buffer.from(await crypto.subtle.digest(hash, keyDer));
  const gotName = Buffer.from(certId.issuerNameHash.valueBlock.valueHexView);
  const gotKey = Buffer.from(certId.issuerKeyHash.valueBlock.valueHexView);
  log.debug("Leaving certIdMatches().");
  return nameHash.equals(gotName) && keyHash.equals(gotKey);
}

function serialOf(certId) {
  log.debug("Entering serialOf().");
  log.debug("Leaving serialOf().");
  return Buffer.from(certId.serialNumber.valueBlock.valueHexView)
    .toString('hex');
}

// The two responses that carry no data, built by hand because pkijs's
// `OCSPResponse` wants a status and nothing else for them. RFC 6960 section
// 4.2.1: `malformedRequest` is 1 and `unauthorized` is 6.
function bareResponse(status) {
  log.debug("Entering bareResponse().");
  const response = new pkijs.OCSPResponse();
  response.responseStatus.valueBlock.valueDec = status;
  log.debug("Leaving bareResponse().");
  return Buffer.from(response.toSchema(true).toBER(false));
}

// How many octets a request's nonce is. RFC 8954 section 2.1 makes the
// extension value the DER of `Nonce ::= OCTET STRING (SIZE(1..32))`; a client
// that put the raw octets in without the inner OCTET STRING is answered on
// the size of what it sent, rather than refused for the wrapping.
function nonceSize(extension) {
  log.debug("Entering nonceSize().");
  const bytes = extension.extnValue.valueBlock.valueHexView;
  const parsed = asn1js.fromBER(bytes.slice().buffer);
  if (parsed.offset === bytes.byteLength &&
      parsed.result instanceof asn1js.OctetString) {
    log.debug("Leaving nonceSize().");
    return parsed.result.valueBlock.valueHexView.byteLength;
  }
  log.debug("Leaving nonceSize(). Not wrapped in an OCTET STRING.");
  return bytes.byteLength;
}

async function answerOcsp(scopeId, caId, requestDer) {
  log.debug('Entering answerOcsp(). scope=' + scopeId + ' ca=' + caId);
  const authority = authorityFor(scopeId, caId);
  if (!authority) {
    log.debug('Leaving answerOcsp(). No such authority.');
    // `unauthorized` rather than `unknown`: there is no responder at this
    // address at all, which is a different thing from a responder that has not
    // heard of a certificate.
    return errorCodes.mark({ ok: true, der: bareResponse(6),
                             status: 'unauthorized' }, 'STS-PKI-0065');
  }
  let request;
  try {
    request = pkijs.OCSPRequest.fromBER(
      requestDer.buffer.slice(requestDer.byteOffset,
                              requestDer.byteOffset + requestDer.byteLength));
  } catch (e) {
    log.debug("Caught in answerOcsp(): " + ((e && e.message) || e));
    log.debug('Leaving answerOcsp(). Malformed request.');
    return errorCodes.mark({ ok: true, der: bareResponse(1),
                             status: 'malformedRequest' }, 'STS-PKI-0066');
  }
  const tier = authority.tier;
  const issuerCert = pkijs.Certificate.fromBER(derFromPem(tier.certificatePem));
  const wanted = (request.tbsRequest.requestList || []);
  // ---------------------------------------------------------------------
  // THE NONCE'S SIZE IS CHECKED BEFORE ANYTHING IS ANSWERED (RFC 8954).
  //
  // Section 2.1: *a server MUST reject any OCSP request that has a nonce …
  // of either 0 octets or more than 32 octets with the malformedRequest
  // OCSPResponseStatus.* It was echoed whatever its size, so a request
  // carrying a megabyte-shaped nonce (bounded only by the endpoint's 64KB
  // cap) got it signed back, and an empty one got an empty one.
  // ---------------------------------------------------------------------
  const asked = request.tbsRequest.requestExtensions || [];
  const nonce = asked.filter(function (one) {
    return one.extnID === '1.3.6.1.5.5.7.48.1.2';
  })[0];
  if (nonce) {
    const size = nonceSize(nonce);
    if (size < 1 || size > 32) {
      log.debug('Leaving answerOcsp(). A nonce of ' + size + ' octet(s).');
      return errorCodes.mark({ ok: true, der: bareResponse(1),
                               status: 'malformedRequest' }, 'STS-PKI-0132');
    }
  }
  // WHOLE SECONDS — see `wholeSeconds()`.
  const now = wholeSeconds(Date.now());
  const responses = [];
  const reported = [];
  for (let i = 0; i < wanted.length; i++) {
    const certId = wanted[i].reqCert;
    const single = new pkijs.SingleResponse();
    single.certID = certId;
    single.thisUpdate = now;
    single.nextUpdate = wholeSeconds(now.getTime() + crlLifetimeMs());
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
          valueDate: wholeSeconds(revoked.revokedAt)
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

  // ---------------------------------------------------------------------
  // **NOT ONE OF THESE IS THIS AUTHORITY'S CERTIFICATE: `unauthorized`.**
  //
  // It answered a SIGNED `unknown` for each, which a client cannot verify:
  // RFC 6960 section 2.2 says the signing key MUST belong to the CA that
  // issued the certificate in question (or a responder that CA delegated
  // to), and this CA issued none of them — so OpenSSL reports *missing
  // ocspsigning usage* about an answer nobody could ever have trusted.
  // Section 2.3 and RFC 5019 section 2.2.3 name the answer for a responder
  // that is not authoritative: `unauthorized`, unsigned. A request that
  // mixes this authority's certificates with somebody else's still gets
  // `unknown` for the stranger beside a real answer for the rest.
  // ---------------------------------------------------------------------
  if (wanted.length && reported.every(function (one) {
    return one.why === 'another issuer';
  })) {
    log.debug('Leaving answerOcsp(). Nothing asked about is ours.');
    return errorCodes.mark({ ok: true, der: bareResponse(6),
                             status: 'unauthorized' }, 'STS-PKI-0133');
  }

  const basic = new pkijs.BasicOCSPResponse();
  // **byKey, where it was byName** (RFC 6960 section 4.2.2.3, RFC 5019
  // section 2.2.2 SHOULD): the SHA-1 of the responder's public key. A name is
  // not unique across a rebuild — every reissued authority here keeps its
  // subject — and a key hash is.
  basic.tbsResponseData.responderID = new asn1js.OctetString({
    valueHex: nodeCrypto.createHash('sha1').update(Buffer.from(
      issuerCert.subjectPublicKeyInfo.subjectPublicKey.valueBlock
        .valueHexView)).digest()
  });
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
    log.error(errorCodes.tag('STS-PKI-0067') + 'pki_revocation: an OCSP ' +
                                               'response from the "' + caId +
              '" authority could not be signed: ' + e.message);
    log.debug('Leaving answerOcsp(). The signature failed.');
    return errorCodes.mark({ ok: true, der: bareResponse(2),
                             status: 'internalError' }, 'STS-PKI-0067');
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
  return { ok: true, der: der, status: 'successful', answers: reported,
           // For `pki/pki_service.js`'s RFC 5019 section 6.2 cache headers,
           // which are computed from the same instants the response carries.
           thisUpdate: now.toISOString(),
           nextUpdate: wholeSeconds(now.getTime() +
                                    crlLifetimeMs()).toISOString(),
           nonce: !!nonce };
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
// **FOUR SOURCES, AND THE THREE AFTER THE FIRST ARE WHY IT IS NOT A
// ONE-LINER.** An authority signs AUTHORITIES as well as leaves: an
// Intermediate issued this scope's Issuing CAs and the Root issued every
// scope's Intermediate. Without those two branches a perfectly valid Issuing CA
// reports `unknown` at its own parent's responder — which is the most confusing
// answer available, because the certificate verifies and the responder disowns
// it. The fourth is the object store, where the Certificate & Key Configuration
// pane's leaves live rather than in the certificate register.
// ---------------------------------------------------------------------------
function issuedList(scopeId, caId) {
  log.debug('Entering issuedList(). scope=' + scopeId + ' ca=' + caId);
  const id = String(caId);
  const out = [];
  const seen = Object.create(null);
  function add(serialHex, subject, notAfter, kind, label) {
    log.debug("Entering add().");
    const key = normalSerial(serialHex);
    if (!key || key === '0' || seen[key]) {
      log.debug("Leaving add().");
      return;
    }
    seen[key] = true;
    out.push({ serialHex: key, subject: String(subject || ''),
               notAfter: notAfter || '', kind: kind, label: String(label || ''),
               expired: notAfter
                 ? new Date(notAfter).getTime() < Date.now() : false });
    log.debug("Leaving add().");
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

  // 5. The RFC 7523 / RFC 7522 signing key pairs issued to applications and
  //    people (2026-09-12). Their certificates name this authority's CRL and
  //    OCSP responder, so a responder with no record of them would answer
  //    `unknown` about a certificate that sends a relying party here to ask.
  //    Guarded, because a `pki.js` without the accessor has no such records.
  if (typeof pki.issuedKeyPairsFor === 'function') {
    pki.issuedKeyPairsFor(scopeId, id).forEach(function (one) {
      add(one.serialHex, one.subject, one.notAfter, 'key-pair',
          one.identifier ? (one.subjectKind || 'application') + ' ' +
                           one.identifier + ' (' + (one.purpose || 'jwt') + ')'
                         : '');
    });
  }

  out.sort(function (a, b) {
    return String(a.subject).localeCompare(String(b.subject));
  });
  log.debug('Leaving issuedList(). ' + out.length + ' certificate(s).');
  return out;
}

function issuedHere(scopeId, caId, serialHex) {
  log.debug("Entering issuedHere().");
  const wanted = normalSerial(serialHex);
  log.debug("Leaving issuedHere().");
  return issuedList(scopeId, caId).some(function (one) {
    return one.serialHex === wanted;
  });
}

module.exports.answerOcsp = answerOcsp;
module.exports.issuedHere = issuedHere;
module.exports.issuedList = issuedList;
