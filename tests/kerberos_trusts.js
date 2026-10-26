// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: kerberos_trusts.js
// ===========================================================================
// KERBEROS TRUSTS AS RECORDS, AND THE PATH ACROSS THEM (#430 Phase 1).
//
// A trust is a record per partner under `ou=kerberosTrusts` in the realm's
// own directory subtree (`kerberos/krb5_trusts.ts`), and two trust realms of
// this process may trust each other's Kerberos through a record on each side.
// Driven here through `kdc.handleMessage()` — the door both sockets and
// `/KdcProxy` reach, which ROUTES by the Kerberos realm name — with the local
// client `tests/protocol/krb5_wire.js`, in development mode:
//
//   A. THE STORE: the development trust with PARTNER.COM seeded as a record
//      in the default realm's directory, the trustedDomain mirror an
//      ldapsearch reads, a view that never carries a key, a generated key
//      shown once, and every validation refusal with its own code.
//   B. THE KEY: a password-derived inter-realm key is RFC 3961 string-to-key
//      with RFC 4120 section 4's default salt (`AkrbtgtB`), checked against
//      an independent derivation written here from RFC 3962 — itself checked
//      against RFC 3962 Appendix B first.
//   C. TWO TRUST REALMS, EACH WITH KERBEROS ON FOR A DIFFERENT KERBEROS
//      REALM, PAIRED BY TRUST RECORDS (rcbj's requirement on #430): a
//      referral from one realm's KDC to the other's on the same port, and
//      followed to a service ticket there, in both directions; a disabled
//      trust refused on either side.
//   D. MULTI-HOP through a transitive trust (A → B → C): the service
//      ticket's `transited` names B; the hop limit, a non-transitive trust
//      and a path outside the trust's namespace each refused
//      (KDC_ERR_PATH_NOT_ACCEPTED).
//   E. `transited` ENCODING (RFC 4120 section 3.3.3.2): compression, its
//      reading, the client's and server's realms, and an elided hierarchy.
//   F. THE FOUR RETIRED SETTINGS stop a start, in child processes.
//   G. THE POLICY'S VOCABULARY: the trust facts an exchange question carries
//      across a trust (`xacml/xacml_request.js`), and that a question that
//      crossed none is the request it always was.
//
// IN PROCESS because the trust records, the keys and the tickets have to be
// opened with keys only the inside holds, and because three Kerberos realms
// on one port is a shape no stack in this repository publishes.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const nodeCrypto = require('crypto');
const childProcess = require('child_process');
const config = require('../common/config');
require('../common/app');
require('../ldap/ldap_server');
const realms = require('../common/realms');
const principals = require('../kerberos/krb5_principals.js');
const kdc = require('../kerberos/krb5_kdc.js');
const kcrypto = require('../kerberos/krb5_crypto.js');
const trusts = require('../kerberos/krb5_trusts');
const wire = require('./protocol/krb5_wire.js');
const grants = require('./tools/cross_realm_grants');

const log = require('bunyan').createLogger({ name: 'kerberos_trusts',
  level: process.env.LOG_LEVEL || 'info' });

const msgs = wire.msgs;
const T = {
  label: 'in-process',
  send: function (bytes) {
    log.debug("Entering send().");
    log.debug("Leaving send().");
    return kdc.handleMessage(bytes);
  }
};

const ALPHA = 'ALPHA.TEST';
const BETA = 'BETA.TEST';
const GAMMA = 'GAMMA.TEST';
const SHARED = 'a shared inter-realm trust password';

function errorOf(r) {
  log.debug("Entering errorOf().");
  log.debug("Leaving errorOf().");
  return r && !r.ok && r.error ? r.error : null;
}

function codesOf(answer) {
  log.debug("Entering codesOf().");
  log.debug("Leaving codesOf().");
  return ((answer && answer.errors) || []).map(function (one) {
    return one.code;
  });
}

// Each realm its own domain SID (#430 Phase 2): SID filtering refuses a PAC
// whose logon domain is the receiving realm's own across an external
// boundary (R8), and three realms inheriting one SID would be one domain.
const DOMAIN_SIDS = { 'ALPHA.TEST': 'S-1-5-21-1001-1002-1003',
                      'BETA.TEST': 'S-1-5-21-2001-2002-2003',
                      'GAMMA.TEST': 'S-1-5-21-3001-3002-3003' };

function makeRealm(id, krbRealm) {
  log.debug("Entering makeRealm(). " + id);
  realms.remove(id);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename,
                               overrides: { 'krb5.realm': krbRealm,
                                            'krb5.domainSid':
                                              DOMAIN_SIDS[krbRealm],
                                            'krb5.enabled': 'true' } });
  log.debug("Leaving makeRealm().");
  return made.ok ? made.realm : null;
}

function inRealm(id, fn) {
  log.debug("Entering inRealm(). " + id);
  log.debug("Leaving inRealm().");
  return realms.run(id === 'default' ? realms.DEFAULT_REALM : realms.get(id),
                    fn);
}

async function tgtIn(t, realm, user) {
  log.debug("Entering tgtIn(). " + user + "@" + realm);
  const got = await wire.asExchange(T, realm, user,
    { password: String(config.value('krb5.userPassword')) });
  t.check(!!got.tgt, 'precondition: a TGT for ' + user + '@' + realm,
          JSON.stringify(got.second || got.first));
  log.debug("Leaving tgtIn().");
  return got.tgt;
}

function spn(host) {
  log.debug("Entering spn().");
  log.debug("Leaving spn().");
  return { type: 3, name: ['HTTP', host] };
}

// A ticket's enc-part, opened with its service's key as the service would,
// inside the realm that holds the service.
async function openTicket(realmId, ticket, service) {
  log.debug("Entering openTicket().");
  const part = await inRealm(realmId, async function () {
    const principal = principals.find(service.name);
    const profile = kcrypto.etypeById(ticket.encPart.etype);
    const key = await principals.longTermKey(principal, ticket.encPart.etype);
    return msgs.readEncTicketPart(await profile.decrypt(key,
      kcrypto.KEY_USAGE.KDC_REP_TICKET, ticket.encPart.cipher));
  });
  log.debug("Leaving openTicket().");
  return part;
}

// ---------------------------------------------------------------------------
// AN INDEPENDENT RFC 3962 STRING-TO-KEY for aes256-cts-hmac-sha1-96, from
// node's own PBKDF2 and AES, and the vendored client's n-fold:
// tkey = PBKDF2-HMAC-SHA1(password, salt, iterations, 32), and the key is
// DK(tkey, "kerberos") — AES-ECB of n-fold("kerberos", 128) under tkey, then
// of that block again, concatenated (random-to-key is the identity).
// ---------------------------------------------------------------------------
function independentAes256(password, salt, iterations) {
  log.debug("Entering independentAes256().");
  const tkey = nodeCrypto.pbkdf2Sync(Buffer.from(password, 'utf8'),
    Buffer.from(salt, 'utf8'), iterations, 32, 'sha1');
  const encrypt = function (block) {
    log.debug("Entering encrypt().");
    const cipher = nodeCrypto.createCipheriv('aes-256-ecb', tkey, null);
    cipher.setAutoPadding(false);
    log.debug("Leaving encrypt().");
    return Buffer.concat([cipher.update(block), cipher.final()]);
  };
  const constant = wire.nfold(Buffer.from('kerberos', 'utf8'), 16);
  const first = encrypt(constant);
  const second = encrypt(first);
  log.debug("Leaving independentAes256().");
  return Buffer.concat([first, second]).toString('hex');
}

// ---------------------------------------------------------------------------
// A. THE STORE.
// ---------------------------------------------------------------------------
function storeSection(t) {
  log.debug("Entering storeSection().");
  t.log.info('=== A. trust records: the store and its refusals ===');
  const partner = principals.DEV_PARTNER_REALM;
  const seeded = trusts.get(partner);
  t.check(!!seeded && seeded.outgoing.held && !seeded.incoming.held &&
          seeded.outgoing.source === 'password' &&
          seeded.direction === 'outbound' && seeded.trustDirection === 2,
          'A1. development seeds the trust with ' + partner + ' as a RECORD ' +
          'of the default realm: an outgoing key from a shared password, ' +
          'outbound (it was four settings until #430)',
          JSON.stringify(seeded));
  t.check(!!seeded && seeded.attributes.indexOf('quarantined') !== -1 &&
          seeded.suffixes.join(',') === partner.toLowerCase() &&
          seeded.partnerSid === principals.DEV_PARTNER_DOMAIN_SID,
          'A2. quarantined by default (SID filtering on), routing ' +
          partner.toLowerCase() + ', with the partner\'s own domain SID',
          JSON.stringify(seeded));
  const hooks = trusts.directoryInstalled();
  const rows = hooks ? hooks.listKerberosTrustEntries() : [];
  const row = rows.filter(function (one) {
    return /^cn=PARTNER\.COM,ou=kerberosTrusts,/i.test(one.dn);
  })[0];
  t.check(!!row && (row.attributes.trustpartner || [])[0] === 'partner.com' &&
          (row.attributes.trustdirection || [])[0] === '2' &&
          (row.attributes.trustattributes || [])[0] === '4' &&
          (row.attributes.securityidentifier || [])[0] ===
            principals.DEV_PARTNER_DOMAIN_SID,
          'A3. it is a directory entry under ou=kerberosTrusts, mirroring ' +
          'the trustedDomain object for an ldapsearch: trustPartner, ' +
          'trustDirection 2 (outbound), trustAttributes 0x4 (quarantined), ' +
          'securityIdentifier', JSON.stringify(row ? row.dn : rows));
  t.check(JSON.stringify(trusts.list()).indexOf('inter-realm-trust') === -1,
          'A4. no view of a record carries its key');

  const refusals = [
    [{ partnerRealm: 'not a realm!', outgoing: { password: SHARED } },
     'STS-KRB-0213', 'a partner realm that is not a realm name'],
    [{ partnerRealm: principals.REALM, outgoing: { password: SHARED } },
     'STS-KRB-0214', 'this realm\'s own Kerberos realm'],
    [{ partnerRealm: partner, outgoing: { password: SHARED } },
     'STS-KRB-0215', 'a partner already held'],
    [{ partnerRealm: 'X.TEST', type: 'imaginary', outgoing:
       { password: SHARED } }, 'STS-KRB-0216', 'an unknown type'],
    [{ partnerRealm: 'X.TEST', type: 'trust-realm', partnerTrustRealm:
       'nosuchrealm', outgoing: { password: SHARED } }, 'STS-KRB-0216',
     'a trust-realm partner naming no trust realm'],
    [{ partnerRealm: 'X.TEST', attributes: ['sparkly'], outgoing:
       { password: SHARED } }, 'STS-KRB-0217', 'an attribute outside the set'],
    [{ partnerRealm: 'X.TEST', attributes: ['no-tgt-delegation',
       'enable-tgt-delegation'], outgoing: { password: SHARED } },
     'STS-KRB-0217', 'two attributes that contradict'],
    [{ partnerRealm: 'X.TEST', partnerSid: 'S-1-5-32-544', outgoing:
       { password: SHARED } }, 'STS-KRB-0218', 'a SID that is not a domain\'s'],
    [{ partnerRealm: 'X.TEST', netbiosName: 'MUCH-TOO-LONG-A-NAME',
       outgoing: { password: SHARED } }, 'STS-KRB-0218',
     'a NetBIOS name past fifteen characters'],
    [{ partnerRealm: 'X.TEST', suffixes: ['not a host'], outgoing:
       { password: SHARED } }, 'STS-KRB-0219',
     'a suffix that is not a DNS name'],
    [{ partnerRealm: 'X.TEST', suffixes: [principals.REALM.toLowerCase()],
       outgoing: { password: SHARED } }, 'STS-KRB-0219',
     'this realm\'s own domain as a suffix'],
    [{ partnerRealm: 'X.TEST', enctypes: [999], outgoing:
       { password: SHARED } }, 'STS-KRB-0220', 'an enctype not implemented'],
    [{ partnerRealm: 'X.TEST', outgoing: null, incoming: null },
     'STS-KRB-0221', 'no key at all'],
    [{ partnerRealm: 'X.TEST', outgoing: { password: 'short' } },
     'STS-KRB-0222', 'a trust password too short'],
    [{ partnerRealm: 'X.TEST', outgoing: { something: true } },
     'STS-KRB-0222', 'a key with no source']
  ];
  refusals.forEach(function (row, index) {
    const answer = trusts.add(row[0]);
    t.check(!answer.ok && codesOf(answer).indexOf(row[1]) !== -1,
            'A5.' + (index + 1) + '. refused: ' + row[2] + ' (' + row[1] +
            ')', JSON.stringify(answer.errors || answer));
  });
  t.check(!trusts.get('X.TEST'), 'A6. and nothing refused was written');

  const made = trusts.add({ partnerRealm: 'GEN.TEST', incoming:
                            { generate: true, kvno: 3 },
                            outgoing: null, attributes: [] });
  const shown = made.shown && made.shown.incoming;
  t.check(made.ok && !!shown && Buffer.from(shown['18'], 'base64').length ===
          32 && Buffer.from(shown['17'], 'base64').length === 16,
          'A7. a GENERATED incoming key is shown once, by the act that made ' +
          'it — one per enctype, of each enctype\'s length',
          JSON.stringify(made.errors || Object.keys(shown || {})));
  const view = trusts.get('GEN.TEST');
  t.check(!!view && view.direction === 'inbound' && view.incoming.kvno === 3 &&
          JSON.stringify(view).indexOf(shown ? shown['18'] : '-') === -1,
          'A8. and never again: the view says inbound, kvno 3, and carries ' +
          'no key', JSON.stringify(view));
  const renamed = trusts.update('GEN.TEST', { partnerRealm: 'OTHER.TEST' });
  t.check(!renamed.ok && codesOf(renamed).indexOf('STS-KRB-0213') !== -1,
          'A9. a partner realm cannot be renamed — every key is salted with ' +
          'it', JSON.stringify(renamed.errors));
  const changed = trusts.update('GEN.TEST', { suffixes: ['gen.test',
                                                         'more.gen.test'] });
  t.check(changed.ok && changed.trust.suffixes.length === 2 &&
          changed.trust.incoming.kvno === 3,
          'A10. an update changes what it names and keeps the key it does ' +
          'not', JSON.stringify(changed.errors || changed.trust));
  t.check(trusts.remove('GEN.TEST').ok && !trusts.get('GEN.TEST') &&
          !trusts.remove('GEN.TEST').ok,
          'A11. a record is removed, and removing it twice is refused');
  log.debug("Leaving storeSection().");
}

// ---------------------------------------------------------------------------
// B. THE KEY.
// ---------------------------------------------------------------------------
async function keySection(t) {
  log.debug("Entering keySection().");
  t.log.info('=== B. a password-derived inter-realm key ===');
  t.equal(independentAes256('password', 'ATHENA.MIT.EDUraeburn', 1200),
          '55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a',
          'B1. the independent derivation below is RFC 3962\'s (Appendix B, ' +
          '1200 iterations)');
  const partner = principals.DEV_PARTNER_REALM;
  const trust = principals.find(['krbtgt', partner], principals.REALM);
  t.check(!!trust && trust.salt === principals.REALM + 'krbtgt' + partner,
          'B2. krbtgt/' + partner + '@' + principals.REALM + ' is built from ' +
          'the record, salted with RFC 4120 section 4\'s default: the realm ' +
          'then the name components', JSON.stringify(trust && trust.salt));
  const key = trust ? Buffer.from(await principals.longTermKey(trust, 18))
    .toString('hex') : '';
  t.equal(key, independentAes256('inter-realm-trust-password',
                                 principals.REALM + 'krbtgt' + partner, 4096),
          'B3. and its aes256 key is what a partner KDC derives from the ' +
          'same password, independently');
  t.equal(principals.find(['krbtgt', principals.REALM], partner), null,
          'B4. there is no INCOMING key from ' + partner + ': the record ' +
          'holds the outgoing one only');
  log.debug("Leaving keySection().");
}

// ---------------------------------------------------------------------------
// C. TWO TRUST REALMS, PAIRED.
// ---------------------------------------------------------------------------
async function referralAcross(t, fromRealm, user, toRealmId, host) {
  log.debug("Entering referralAcross().");
  const tgt = await tgtIn(t, fromRealm, user);
  if (!tgt) {
    log.debug("Leaving referralAcross(). No TGT.");
    return null;
  }
  const referral = await wire.tgsExchange(T, tgt, spn(host), fromRealm);
  log.debug("Leaving referralAcross().");
  return { tgt: tgt, referral: referral };
}

async function pairedSection(t) {
  log.debug("Entering pairedSection().");
  t.log.info('=== C. two trust realms, each its own Kerberos realm, ' +
             'paired ===');
  const paired = inRealm('kt-a', function () {
    return trusts.pair('kt-b', { password: SHARED, direction: 'both',
                                 attributes: [] });
  });
  t.check(paired.ok && paired.here.direction === 'bidirectional' &&
          paired.there.direction === 'bidirectional' &&
          paired.here.type === 'trust-realm' &&
          paired.here.partnerTrustRealm === 'kt-b' &&
          paired.there.partnerRealm === ALPHA,
          'C1. pair writes BOTH records in one act, mirrored: each realm ' +
          'holds a bidirectional trust-realm record naming the other',
          JSON.stringify(paired.errors || [paired.here, paired.there]));
  const again = inRealm('kt-a', function () {
    return trusts.pair('kt-b', { password: SHARED });
  });
  t.check(!again.ok && codesOf(again).indexOf('STS-KRB-0215') !== -1,
          'C2. and pairing again is refused, on both sides, writing nothing',
          JSON.stringify(again.errors));

  const there = await referralAcross(t, ALPHA, 'alice', 'kt-b',
                                     'web.beta.test');
  const ref = there && there.referral;
  t.check(!!ref && ref.ok && ref.sname.name.join('/') ===
          'krbtgt/' + BETA && ref.srealm === ALPHA,
          'C3. ' + ALPHA + '\'s KDC REFERS a request for HTTP/web.beta.test: ' +
          'a TGT for krbtgt/' + BETA + '@' + ALPHA + ', sealed in the ' +
          'trust key — routed by the record\'s suffix',
          JSON.stringify(ref && (ref.ok ? [ref.sname, ref.srealm] :
                                 String(ref.error))));
  if (!ref || !ref.ok) {
    log.debug("Leaving pairedSection(). No referral.");
    return;
  }
  const svc = await wire.tgsExchange(T, ref, spn('web.beta.test'), BETA);
  t.check(svc.ok && svc.srealm === BETA && svc.realm === ALPHA &&
          svc.sname.name.join('/') === 'HTTP/web.beta.test',
          'C4. FOLLOWED on the same port: the request names ' + BETA +
          ', is routed to that realm\'s KDC, which opens the referral with ' +
          'its INCOMING key and issues the service ticket for ' +
          'alice@' + ALPHA, JSON.stringify(svc.ok ? [svc.sname, svc.srealm,
                                                     svc.realm] :
                                         String(svc.error)));
  if (svc.ok) {
    t.check(svc.flagNames.indexOf('transited-policy-checked') !== -1,
            'C5. TRANSITED-POLICY-CHECKED: ' + BETA + '\'s KDC checked the ' +
            'path against its record', JSON.stringify(svc.flagNames));
    const part = await openTicket('kt-b', svc.ticket,
                                  spn('web.beta.test'));
    t.check(part.crealm === ALPHA && part.transited.type === 1 &&
            part.transited.contents.length === 0,
            'C6. the service opens it with its own key: client alice@' +
            ALPHA + ', and an EMPTY transited — a direct trust transits ' +
            'nothing (RFC 4120 section 3.3.3.2)',
            JSON.stringify([part.crealm, part.transited.type,
                            part.transited.contents.length]));
  }
  const back = await referralAcross(t, BETA, 'bob', 'kt-a', 'web.alpha.test');
  const backSvc = back && back.referral.ok ?
    await wire.tgsExchange(T, back.referral, spn('web.alpha.test'), ALPHA) :
    null;
  t.check(!!backSvc && backSvc.ok && backSvc.realm === BETA &&
          backSvc.srealm === ALPHA,
          'C7. and the other way round: bob@' + BETA + ' reaches ' +
          'HTTP/web.alpha.test through the same pair',
          JSON.stringify(backSvc && (backSvc.ok ? backSvc.srealm :
                                     String(backSvc.error))));

  // A DISABLED TRUST, on the side that accepts.
  inRealm('kt-b', function () {
    return trusts.setEnabled(ALPHA, false);
  });
  let r = await wire.tgsExchange(T, ref, spn('web.beta.test'), BETA);
  t.check(!!errorOf(r) && errorOf(r).code === 7 &&
          /disabled/.test(errorOf(r).eText),
          'C8. ' + BETA + ' with its trust in ' + ALPHA + ' DISABLED refuses ' +
          'the referral it would have opened, and says why (STS-KRB-0229)',
          String(errorOf(r)));
  inRealm('kt-b', function () {
    return trusts.setEnabled(ALPHA, true);
  });
  // And on the side that refers.
  inRealm('kt-a', function () {
    return trusts.setEnabled(BETA, false);
  });
  const tgt = await tgtIn(t, ALPHA, 'alice');
  r = await wire.tgsExchange(T, tgt, spn('web.beta.test'), ALPHA);
  t.check(!!errorOf(r) && errorOf(r).code === 7,
          'C9. ' + ALPHA + ' with its trust in ' + BETA + ' DISABLED refers ' +
          'nobody there: the service is simply unknown',
          r.ok ? JSON.stringify(r.sname) : String(errorOf(r)));
  inRealm('kt-a', function () {
    return trusts.setEnabled(BETA, true);
  });
  r = await wire.tgsExchange(T, ref, spn('web.beta.test'), BETA);
  t.check(r.ok, 'C10. enabled again, the same referral is honoured — a ' +
          'disabled trust keeps its keys', String(errorOf(r)));
  log.debug("Leaving pairedSection().");
}

// ---------------------------------------------------------------------------
// D. MULTI-HOP.
// ---------------------------------------------------------------------------
async function hopToGamma(t, aliceTgt) {
  log.debug("Entering hopToGamma().");
  const first = await wire.tgsExchange(T, aliceTgt, spn('web.gamma.test'),
                                       ALPHA);
  if (!first.ok) {
    log.debug("Leaving hopToGamma(). The first hop.");
    return { stage: 1, r: first };
  }
  const second = await wire.tgsExchange(T, first, spn('web.gamma.test'),
                                        BETA);
  if (!second.ok) {
    log.debug("Leaving hopToGamma(). The second hop.");
    return { stage: 2, r: second, first: first };
  }
  const third = await wire.tgsExchange(T, second, spn('web.gamma.test'),
                                       GAMMA);
  log.debug("Leaving hopToGamma().");
  return { stage: third.ok ? 0 : 3, r: third, first: first, second: second };
}

function walkSummary(walk) {
  log.debug("Entering walkSummary().");
  log.debug("Leaving walkSummary().");
  return JSON.stringify({ stage: walk.stage, error: String(errorOf(walk.r)) });
}

async function multiHopSection(t) {
  log.debug("Entering multiHopSection().");
  t.log.info('=== D. a path through a transitive trust ===');
  // B and C, paired with GENERATED keys; A refers gamma.test to B, and C
  // accepts alpha.test through B.
  const bc = inRealm('kt-b', function () {
    return trusts.pair('kt-c', { generate: true, direction: 'both',
                                 attributes: ['forest-transitive'],
                                 partnerSuffixes: ['beta.test',
                                                   'alpha.test'] });
  });
  t.check(bc.ok && !!bc.shown && !!bc.shown.outgoing,
          'D1. ' + BETA + ' and ' + GAMMA + ' paired with a GENERATED key ' +
          'set, the same keys written to both records',
          JSON.stringify(bc.errors || []));
  // GAMMA's cross-forest trust with BETA names the trusted forest's domains
  // (forest trust information, [MS-ADTS] 6.1.6.9.3), ALPHA's among them, or
  // SID filtering would refuse ALPHA's people arriving through it.
  const ftInfo = inRealm('kt-c', function () {
    return trusts.update(BETA, { forestTrustInfo: { domains: [
      { sid: DOMAIN_SIDS[BETA], dnsName: 'beta.test', netbiosName: 'BETA' },
      { sid: DOMAIN_SIDS[ALPHA], dnsName: 'alpha.test',
        netbiosName: 'ALPHA' }] } });
  });
  t.check(ftInfo.ok, 'D1b. ' + GAMMA + '\'s record for ' + BETA + ' names ' +
          'the trusted forest\'s domains', JSON.stringify(ftInfo.errors || []));
  const widened = inRealm('kt-a', function () {
    return trusts.update(BETA, { suffixes: ['beta.test', 'gamma.test'] });
  });
  t.check(widened.ok, 'D2. ' + ALPHA + '\'s record for ' + BETA + ' routes ' +
          'gamma.test too — the next hop for a realm behind it',
          JSON.stringify(widened.errors || []));
  const aliceTgt = await tgtIn(t, ALPHA, 'alice');
  let walk = await hopToGamma(t, aliceTgt);
  t.check(walk.stage === 0 && walk.first.sname.name[1] === BETA &&
          walk.second.sname.name[1] === GAMMA &&
          walk.second.srealm === BETA,
          'D3. ' + ALPHA + ' refers to ' + BETA + ', ' + BETA + ' refers on ' +
          'to ' + GAMMA + ', and ' + GAMMA + ' issues the service ticket',
          walkSummary(walk));
  if (walk.stage === 0) {
    const part = await openTicket('kt-c', walk.r.ticket,
                                  spn('web.gamma.test'));
    const decoded = trusts.decodeTransited(part.transited.contents, ALPHA,
                                           GAMMA);
    t.check(part.crealm === ALPHA && part.transited.type === 1 &&
            JSON.stringify(decoded.realms) === JSON.stringify([BETA]),
            'D4. the service ticket\'s transited names ' + BETA + ' — the ' +
            'realm between, and neither the client\'s nor the server\'s ' +
            '(RFC 4120 section 3.3.3.2)',
            JSON.stringify([part.crealm, decoded,
                            Buffer.from(part.transited.contents)
                              .toString()]));
    t.check(walk.r.flagNames.indexOf('transited-policy-checked') !== -1,
            'D5. and TRANSITED-POLICY-CHECKED: ' + GAMMA + ' accepted ' +
            ALPHA + ' through ' + BETA + ' by its record\'s namespace',
            JSON.stringify(walk.r.flagNames));
  }

  // THE HOP LIMIT, on the realm in the middle.
  realms.setOverride('kt-b', 'krb5.maxReferralHops', '1');
  walk = await hopToGamma(t, aliceTgt);
  t.check(walk.stage === 2 && errorOf(walk.r) &&
          errorOf(walk.r).code === 28 &&
          /maxReferralHops/.test(errorOf(walk.r).eText),
          'D6. with krb5.maxReferralHops 1 in ' + BETA + ', the second ' +
          'crossing is refused: KDC_ERR_PATH_NOT_ACCEPTED (STS-KRB-0226)',
          walkSummary(walk));
  realms.clearOverride('kt-b', 'krb5.maxReferralHops');

  // A NON-TRANSITIVE TRUST is not a way through.
  inRealm('kt-b', function () {
    return trusts.update(ALPHA, { attributes: ['non-transitive'] });
  });
  walk = await hopToGamma(t, aliceTgt);
  t.check(walk.stage === 2 && errorOf(walk.r) &&
          errorOf(walk.r).code === 28 &&
          /non-transitive/.test(errorOf(walk.r).eText),
          'D7. ' + BETA + '\'s trust with ' + ALPHA + ' NON-TRANSITIVE: ' +
          ALPHA + '\'s people are not referred onward (STS-KRB-0227)',
          walkSummary(walk));
  const direct = await wire.tgsExchange(T, walk.first || aliceTgt,
                                        spn('web.beta.test'), BETA);
  t.check(direct.ok, 'D8. and still accepts them for its own services',
          String(errorOf(direct)));
  inRealm('kt-b', function () {
    return trusts.update(ALPHA, { attributes: [] });
  });

  // A PATH OUTSIDE THE NAMESPACE the last trust routes.
  inRealm('kt-c', function () {
    return trusts.update(BETA, { suffixes: ['beta.test'] });
  });
  walk = await hopToGamma(t, aliceTgt);
  t.check(walk.stage === 3 && errorOf(walk.r) &&
          errorOf(walk.r).code === 28 && /outside/.test(errorOf(walk.r).eText),
          'D9. ' + GAMMA + ', whose trust with ' + BETA + ' routes ' +
          'beta.test only, refuses alice@' + ALPHA + ' arriving through it: ' +
          'the transited-policy check (STS-KRB-0228)',
          walkSummary(walk));
  log.debug("Leaving multiHopSection().");
}

// ---------------------------------------------------------------------------
// E. TRANSITED ENCODING.
// ---------------------------------------------------------------------------
function transitedSection(t) {
  log.debug("Entering transitedSection().");
  t.log.info('=== E. DOMAIN-X500-COMPRESS ===');
  const text = function (list) {
    log.debug("Entering text().");
    log.debug("Leaving text().");
    return Buffer.from(trusts.encodeTransited(list)).toString('utf8');
  };
  t.equal(text([]), '', 'E1. a direct trust transits nothing: empty');
  t.equal(text(['EXAMPLE.COM', 'CORP.EXAMPLE.COM', 'OTHER.ORG']),
          'EXAMPLE.COM,CORP.,OTHER.ORG',
          'E2. a realm extending the one before it is written as its new ' +
          'labels and a dot');
  t.equal(JSON.stringify(trusts.decodeTransited(Buffer.from(
    'EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.'), 'X', 'Y').realms),
          JSON.stringify(['EDU', 'MIT.EDU', 'ATHENA.MIT.EDU', 'WASHINGTON.EDU',
                          'CS.WASHINGTON.EDU']),
          'E3. RFC 4120 section 3.3.3.2\'s own example reads back');
  const ends = trusts.decodeTransited(Buffer.from(',MID.ORG,'), 'C.ORG',
                                      'S.ORG');
  t.equal(JSON.stringify(ends.realms),
          JSON.stringify(['C.ORG', 'MID.ORG', 'S.ORG']),
          'E4. an empty first and last element stand for the client\'s and ' +
          'the server\'s realms');
  t.check(trusts.decodeTransited(Buffer.from('A.ORG,,B.ORG'), 'C', 'S')
    .elided === true, 'E5. an empty element between two names elides a ' +
          'hierarchy, which the policy check refuses');
  const round = ['EXAMPLE.COM', 'A,B.ORG', 'X\\Y.ORG'];
  t.equal(JSON.stringify(trusts.decodeTransited(trusts.encodeTransited(round),
                                                'C', 'S').realms),
          JSON.stringify(round), 'E6. a comma and a backslash in a name ' +
          'are escaped, and read back');
  log.debug("Leaving transitedSection().");
}

// ---------------------------------------------------------------------------
// F. THE RETIRED SETTINGS.
// ---------------------------------------------------------------------------
function retiredSection(t) {
  log.debug("Entering retiredSection().");
  t.log.info('=== F. the four retired settings stop a start ===');
  const root = path.join(__dirname, '..');
  [['KRB5_TRUSTED_REALM', 'krb5.trustedRealm'],
   ['KRB5_TRUST_PASSWORD', 'krb5.trustPassword'],
   ['KRB5_TRUSTED_DOMAIN_SID', 'krb5.trustedDomainSid'],
   ['KRB5_TRUSTED_KRBTGT_PASSWORD', 'krb5.trustedKrbtgtPassword']]
    .forEach(function (pair, index) {
      const env = Object.assign({}, process.env);
      delete env.CONFIG_FILE;
      env[pair[0]] = 'anything';
      const child = childProcess.spawnSync(process.execPath,
        ['-e', 'require("./common/config")'], { cwd: root, env: env,
                                                 encoding: 'utf8',
                                                 timeout: 60000 });
      t.check(child.status === 1 && /STS-CORE-0105/.test(child.stderr) &&
              child.stderr.indexOf(pair[0]) !== -1 &&
              /#430/.test(child.stderr),
              'F' + (index + 1) + '. ' + pair[0] + ' (' + pair[1] + ') in ' +
              'the environment refuses the start, naming #430\'s trust ' +
              'records', String(child.stderr).slice(0, 300));
    });
  // By NAME: krb5.trustKeyGraceSeconds (#430 Phase 4) is a setting about
  // the records, not one of the four they replaced.
  const retired = ['krb5.trustedRealm', 'krb5.trustPassword',
                   'krb5.trustedDomainSid', 'krb5.trustedKrbtgtPassword'];
  t.check(!config.SETTINGS.some(function (row) {
    return retired.indexOf(row.key) !== -1;
  }), 'F5. and none of the four is a setting any more');
  log.debug("Leaving retiredSection().");
}

// ---------------------------------------------------------------------------
// G. THE POLICY'S VOCABULARY.
// ---------------------------------------------------------------------------
function vocabularySection(t) {
  log.debug("Entering vocabularySection().");
  t.log.info('=== G. the trust facts of an exchange question ===');
  const xacmlRequest = require('../xacml/xacml_request');
  const V = xacmlRequest.VOCABULARY;
  const ids = function (request) {
    log.debug("Entering ids().");
    const out = {};
    request.categories.forEach(function (category) {
      category.attributes.forEach(function (one) {
        out[one.attributeId] = one.values.map(function (v) {
          return v.lexical;
        });
      });
    });
    log.debug("Leaving ids().");
    return out;
  };
  const base = { subject: { id: 'alice' }, actor: { id: 'HTTP/a' },
                 target: { id: 'HTTP/b', count: 1 } };
  const plain = ids(new xacmlRequest.AuthorizationRequest().exchange(base));
  t.check(Object.keys(plain).every(function (id) {
    return !/:(trust-|subject-realm|actor-realm|target-realm)/.test(id);
  }), 'G1. a question that crossed no trust carries none of the new facts',
          JSON.stringify(Object.keys(plain)));
  const across = ids(new xacmlRequest.AuthorizationRequest().exchange(
    Object.assign({}, base, {
      subject: { id: 'alice', realm: ALPHA },
      actor: { id: 'HTTP/a', realm: ALPHA },
      target: { id: 'HTTP/b', count: 1, realm: GAMMA },
      trust: { partner: BETA, type: 'trust-realm', direction: 'bidirectional',
               attributes: ['forest-transitive'], path: [ALPHA, BETA],
               hops: 2 } })));
  t.check(across[V.EXCHANGE_SUBJECT_REALM][0] === ALPHA &&
          across[V.EXCHANGE_ACTOR_REALM][0] === ALPHA &&
          across[V.EXCHANGE_TARGET_REALM][0] === GAMMA &&
          across[V.EXCHANGE_TRUST_PARTNER][0] === BETA &&
          across[V.EXCHANGE_TRUST_TYPE][0] === 'trust-realm' &&
          across[V.EXCHANGE_TRUST_DIRECTION][0] === 'bidirectional' &&
          across[V.EXCHANGE_TRUST_ATTRIBUTE][0] === 'forest-transitive' &&
          across[V.EXCHANGE_TRUST_PATH].join(',') === ALPHA + ',' + BETA &&
          across[V.EXCHANGE_TRUST_HOPS][0] === '2',
          'G2. one across a trust carries the partner, type, direction, ' +
          'attributes, path, hop count and each party\'s Kerberos realm',
          JSON.stringify(across));
  log.debug("Leaving vocabularySection().");
}

async function run(t) {
  log.debug("Entering run().");
  storeSection(t);
  vocabularySection(t);
  await keySection(t);
  transitedSection(t);
  retiredSection(t);
  const a = makeRealm('kt-a', ALPHA);
  const b = makeRealm('kt-b', BETA);
  const c = makeRealm('kt-c', GAMMA);
  t.check(!!a && !!b && !!c, 'precondition: three trust realms, each with ' +
          'Kerberos on for its own Kerberos realm');
  // A principal of another realm holds only what it was granted (#430,
  // rcbj 2026-10-19): each realm admits the other two to its web service.
  if (a && b && c) {
    const admitted = [[a, ALPHA], [b, BETA], [c, GAMMA]].map(function (one) {
      return grants.admitPartners(one[0], Object.keys(DOMAIN_SIDS)
        .filter(function (name) {
          return name !== one[1];
        }).map(function (name) {
          return DOMAIN_SIDS[name];
        }), ['HTTP/web.' + one[1].toLowerCase()], one[1]);
    }).reduce(function (all, some) {
      return all.concat(some);
    }, []);
    t.check(!admitted.length, 'precondition: each realm grants ' +
            grants.ROLE + ' to the others\' Domain Users and Computers and ' +
            'its web service requires it (or EVERYBODY)',
            JSON.stringify(admitted));
  }
  try {
    if (a && b && c) {
      await pairedSection(t);
      await multiHopSection(t);
    }
  } finally {
    ['kt-a', 'kt-b', 'kt-c'].forEach(function (id) {
      realms.remove(id);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kerberos_trusts',
  describe: 'Kerberos trusts as directory records (#430): the store, the ' +
            'password-derived key, two trust realms paired and a referral ' +
            'followed between them, multi-hop with transited, and the ' +
            'retired settings',
  run: run
};
