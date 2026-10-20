// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: kerberos_cross_realm_delegation.js
// ===========================================================================
// DELEGATION ACROSS A KERBEROS TRUST, AND SID FILTERING (#430 Phases 2, 3).
//
// rcbj's requirement: every cross-realm case runs between TRUST REALMS OF
// THIS SERVICE, each with Kerberos on for a different Kerberos realm and
// paired by trust records — ALPHA.TEST (kd-a), BETA.TEST (kd-b) and, for a
// hop and for a third party, GAMMA.TEST (kd-c) — never the PARTNER.COM
// fixture. Driven through `kdc.handleMessage()`, which routes by the realm
// name in each request, with the suite's own client
// (`tests/vendored/krb5_wire.js`):
//
//   S. S4U2SELF across realms ([MS-SFU] 3.1.5.1.1.2, 4.2): forwardable,
//      not forwardable, a protected user, the service not listing the
//      realm (krb5S4uSelfRealm), PA-S4U-X509-USER for a foreign user, and
//      multi-hop through a transitive trust.
//   P. CLASSIC S4U2PROXY across realms: issued only with
//      krb5.crossRealmClassicDelegation on in BOTH realms, each of the four
//      combinations refused at the side whose setting is off (STS-KRB-0232
//      at the front end's realm, STS-KRB-0242 at the target's).
//   XR. A PRINCIPAL OF ANOTHER REALM HOLDS ONLY ITS GRANTS (rcbj,
//      2026-10-19): no EVERYBODY, no ALL_AUTHENTICATED_USERS, so a service
//      requiring only EVERYBODY refuses it; a role granted to its name
//      admits it; a person of the realm itself is unchanged. setUp() admits
//      the partners to the services the other sections reach.
//   R. RESOURCE-BASED S4U2PROXY across realms ([MS-SFU] 3.2.5.2.3): a
//      foreign front end to a local back end and the reverse; non-
//      forwardable evidence, a protected user and an unlisted actor
//      refused; S4U_DELEGATION_INFO's names.
//   X. S4U2SELF THEN S4U2PROXY through the trust, the PAC's delegation
//      chain checked.
//   E. EVIDENCE ACROSS A TRUST IS PAC-VERIFIED with the inter-realm key
//      (CVE-2020-17049 across a trust): the genuine referral verifies, and
//      a PAC forged under another key, a PAC altered after signing, a
//      ticket altered after signing, and evidence with no PAC are refused
//      (STS-KRB-0240).
//   F. A TGT DELEGATED ACROSS A TRUST ([MS-KILE] 3.3.5.7.5): ok-as-delegate
//      with ENABLE_TGT_DELEGATION, NO_TGT_DELEGATION and neither,
//      krb5ForeignTgtDelegation deny narrowing it, a FORWARDED request, and a
//      protected user.
//   T. THE TRUST'S STATE: disabled, a missing incoming key, and the
//      semantics the policy chooses across it.
//   SF-A. a filtered ticket writes ONE audit row, krb5.trust.sid-filtered,
//      naming the trust, the principal and the SIDs, and no info line.
//   SF-R<n>. SID FILTERING, one test per row of kerberos/CLAUDE.md's
//      *SID FILTERING: THE RULES* that can apply here (rows 20, 21 and 23
//      cannot, and say why there), end to end and on PACs as ALPHA would
//      issue them arriving at BETA; and SF-P, product refusing a trust that
//      does not filter SIDs.
//
// IN PROCESS because tickets are opened with keys only the inside holds,
// and three Kerberos realms on one port is a shape no stack here publishes.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
require('../common/app');
require('../ldap/ldap_server');
const realms = require('../common/realms');
const applications = require('../common/applications');
const principals = require('../kerberos/krb5_principals.js');
const kdc = require('../kerberos/krb5_kdc.js');
const kcrypto = require('../kerberos/krb5_crypto.js');
const kpac = require('../kerberos/krb5_pac.js');
const trusts = require('../kerberos/krb5_trusts');
const wire = require('./vendored/krb5_wire.js');
const grants = require('./tools/cross_realm_grants');
// ARMS `issuance_gate.js`'s decider, the PEP the KDC's role question goes
// to. The service always loads it (`common/protocol_stack.ts`, 23c); a test
// process that does not answers every role question "allowed — the XACML
// role subsystem is not loaded", so XR1 and XR5, which assert rcbj's
// explicit-grants-only rule across a trust, passed only when another file
// run in the same process had armed it, and failed in a run of this file
// alone (the memory mode's one job per process).
require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({
  name: 'kerberos_cross_realm_delegation',
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
const IDS = { 'ALPHA.TEST': 'kd-a', 'BETA.TEST': 'kd-b',
              'GAMMA.TEST': 'kd-c' };
const SID = { 'ALPHA.TEST': 'S-1-5-21-1001-1002-1003',
              'BETA.TEST': 'S-1-5-21-2001-2002-2003',
              'GAMMA.TEST': 'S-1-5-21-3001-3002-3003' };
const OTHER_SID = 'S-1-5-21-9001-9002-9003';
const SHARED = 'a shared inter-realm trust password';
// The services each realm admits the others' principals to (setUp()).
const ADMITTED = ['frontend', 'backend', 'rbcd', 'notrusted', 'web'];
const PASSWORDS = { frontend: 'frontend-service-password',
                    notrusted: 'notrusted-service-password',
                    rbcd: 'rbcd-service-password',
                    backend: 'backend-service-password' };

function inRealm(krbRealm, fn) {
  log.debug("Entering inRealm(). " + krbRealm);
  log.debug("Leaving inRealm().");
  return realms.run(realms.get(IDS[krbRealm]), fn);
}

function spn(svc, krbRealm) {
  log.debug("Entering spn().");
  log.debug("Leaving spn().");
  return { type: 3, name: ['HTTP', svc + '.' + krbRealm.toLowerCase()] };
}

function appId(svc, krbRealm) {
  log.debug("Entering appId().");
  log.debug("Leaving appId().");
  return 'HTTP/' + svc + '.' + krbRealm.toLowerCase() + '@' + krbRealm;
}

function errorOf(r) {
  log.debug("Entering errorOf().");
  log.debug("Leaving errorOf().");
  return r && !r.ok && r.error ? r.error : null;
}

function show(r) {
  log.debug("Entering show().");
  log.debug("Leaving show().");
  return r && r.ok ? JSON.stringify({ sname: r.sname, srealm: r.srealm,
                                      client: r.client, realm: r.realm,
                                      flags: r.flagNames })
                   : String(errorOf(r) || r);
}

// Sets, adds or clears an attribute on a service's entry in its realm, the
// realm's delegation seeds written first.
function setApp(krbRealm, svc, attribute, mode, value) {
  log.debug("Entering setApp(). " + attribute);
  const out = inRealm(krbRealm, function () {
    require('../kerberos/krb5_delegation').ensureSeeded();
    return applications.updateApplication(appId(svc, krbRealm), {
      attribute: attribute, mode: mode, value: value,
      actor: 'tests/kerberos_cross_realm_delegation.js' });
  });
  log.debug("Leaving setApp().");
  return out;
}

async function tgtOf(t, krbRealm, name, password) {
  log.debug("Entering tgtOf(). " + name + "@" + krbRealm);
  const got = await wire.asExchange(T, krbRealm, name, { password: password });
  t.check(!!got.tgt, 'precondition: a TGT for ' + name + '@' + krbRealm,
          JSON.stringify(got.second || got.first));
  log.debug("Leaving tgtOf().");
  return got.tgt;
}

function userTgt(t, krbRealm, user) {
  log.debug("Entering userTgt().");
  log.debug("Leaving userTgt().");
  return tgtOf(t, krbRealm, user, String(config.value('krb5.userPassword')));
}

function serviceTgt(t, krbRealm, svc) {
  log.debug("Entering serviceTgt().");
  log.debug("Leaving serviceTgt().");
  return tgtOf(t, krbRealm, 'HTTP/' + svc + '.' + krbRealm.toLowerCase(),
               PASSWORDS[svc]);
}

// S4U2SELF, FOLLOWED: the service asks its own realm and follows every
// referral, sending PA-FOR-USER (or PA-S4U-X509-USER) at each hop, until a
// ticket that is not a referral, or a refusal. Answers the last reply, the
// realms asked in order, and the replies on the way.
async function walkSelf(tgt, home, svc, user, userRealm, x509) {
  log.debug("Entering walkSelf(). " + user + "@" + userRealm);
  const sname = spn(svc, home);
  let current = tgt;
  let realm = home;
  const asked = [];
  const replies = [];
  for (let i = 0; i < 8; i++) {
    asked.push(realm);
    const hopTgt = current;
    const r = await wire.tgsExchange(T, hopTgt, sname, realm, {
      padata: async function (nonce) {
        return [x509 ? await wire.paS4uX509User(hopTgt,
                         { name: user, realm: userRealm, nonce: nonce })
                     : await wire.paForUser(hopTgt, user, userRealm)];
      }
    });
    replies.push(r);
    if (!r.ok || r.sname.name[0] !== 'krbtgt') {
      log.debug("Leaving walkSelf().");
      return { r: r, asked: asked, replies: replies };
    }
    current = r;
    realm = r.sname.name[1];
  }
  log.debug("Leaving walkSelf(). Too many hops.");
  return { r: replies[replies.length - 1], asked: asked, replies: replies };
}

// A ticket's enc-part, opened with its service's key, in the realm that
// holds the service.
async function openTicket(krbRealm, ticket, service) {
  log.debug("Entering openTicket().");
  const part = await inRealm(krbRealm, async function () {
    const principal = principals.find(service.name);
    const profile = kcrypto.etypeById(ticket.encPart.etype);
    const key = await principals.longTermKey(principal, ticket.encPart.etype);
    return msgs.readEncTicketPart(await profile.decrypt(key,
      kcrypto.KEY_USAGE.KDC_REP_TICKET, ticket.encPart.cipher));
  });
  log.debug("Leaving openTicket().");
  return part;
}

function pacOf(part) {
  log.debug("Entering pacOf().");
  const pacs = kpac.findPacs(part.authorizationData || []);
  log.debug("Leaving pacOf().");
  return pacs.length ? kpac.parsePac(pacs[0].bytes) : null;
}

function logonOf(pac) {
  log.debug("Entering logonOf().");
  const b = pac ? kpac.bufferOfType(pac, kpac.TYPE.LOGON_INFO) : null;
  log.debug("Leaving logonOf().");
  return b ? b.parsed : null;
}

function sidsOf(info) {
  log.debug("Entering sidsOf().");
  log.debug("Leaving sidsOf().");
  return ((info && info.extraSids) || []).map(function (one) {
    return one.text;
  });
}

// S4U2Proxy by `tgt` with `evidence` to `target` in `realm`.
function proxy(tgt, evidence, target, realm, rbcd) {
  log.debug("Entering proxy().");
  log.debug("Leaving proxy().");
  return wire.tgsExchange(T, tgt, target, realm, {
    kdcOptions: [msgs.KDC_OPTION.CNAME_IN_ADDL_TKT],
    additionalTickets: [evidence],
    padata: rbcd ? [wire.paPacOptionsRbcd()] : []
  });
}

// S4U2Proxy to a target across a trust, followed: the front end's realm
// refers the evidence, the front end gets its own cross-realm TGT the
// ordinary way, and asks the target's realm with both.
async function proxyAcross(frontTgt, evidence, target, home, there, rbcd) {
  log.debug("Entering proxyAcross().");
  const first = await proxy(frontTgt, evidence, target, home, rbcd);
  if (!first.ok || first.sname.name[0] !== 'krbtgt') {
    log.debug("Leaving proxyAcross(). Not referred.");
    return { first: first, r: first };
  }
  const own = await wire.tgsExchange(T, frontTgt, target, home);
  if (!own.ok) {
    log.debug("Leaving proxyAcross(). No own referral.");
    return { first: first, r: own };
  }
  const r = await proxy(own, first.ticket, target, there, rbcd);
  log.debug("Leaving proxyAcross().");
  return { first: first, own: own, r: r };
}

function delegationInfoOf(part) {
  log.debug("Entering delegationInfoOf().");
  const pac = pacOf(part);
  const entry = pac ? kpac.bufferOfType(pac, kpac.TYPE.DELEGATION_INFO) :
                      null;
  log.debug("Leaving delegationInfoOf().");
  return entry ? entry.parsed : null;
}

// ---------------------------------------------------------------------------
// THE REALMS AND THEIR TRUSTS.
// ---------------------------------------------------------------------------
function setUp(t) {
  log.debug("Entering setUp().");
  [ALPHA, BETA, GAMMA].forEach(function (name) {
    realms.remove(IDS[name]);
    const made = realms.create({ id: IDS[name], name: IDS[name],
      description: 'Created by ' + __filename,
      overrides: { 'krb5.realm': name, 'krb5.domainSid': SID[name],
                   'krb5.enabled': 'true' } });
    t.check(made.ok, 'precondition: trust realm ' + IDS[name] + ' with ' +
            'Kerberos on for ' + name + ' and domain SID ' + SID[name],
            JSON.stringify(made.errors || []));
  });
  const ab = inRealm(ALPHA, function () {
    return trusts.pair(IDS[BETA], { password: SHARED, attributes: [],
      suffixes: ['beta.test', 'gamma.test'] });
  });
  const bc = inRealm(BETA, function () {
    return trusts.pair(IDS[GAMMA], { password: SHARED, attributes: [],
      partnerSuffixes: ['beta.test', 'alpha.test'] });
  });
  t.check(ab.ok && bc.ok, 'precondition: ALPHA <-> BETA and BETA <-> ' +
          'GAMMA paired, external and transitive',
          JSON.stringify((ab.errors || []).concat(bc.errors || [])));
  // A principal of another realm holds only what it was granted (#430,
  // rcbj 2026-10-19): each realm admits the other two to the services
  // these sections reach. Section XR asks the refusal without it.
  const admitted = [ALPHA, BETA, GAMMA].map(function (name) {
    return grants.admitPartners(realms.get(IDS[name]),
      [ALPHA, BETA, GAMMA].filter(function (other) {
        return other !== name;
      }).map(function (other) {
        return SID[other];
      }), ADMITTED.map(function (svc) {
        return 'HTTP/' + svc + '.' + name.toLowerCase();
      }), name);
  }).reduce(function (all, some) {
    return all.concat(some);
  }, []);
  t.check(!admitted.length, 'precondition: each realm grants ' +
          grants.ROLE + ' to the others\' Domain Users and Computers, and ' +
          'its services require it (or EVERYBODY)', JSON.stringify(admitted));
  log.debug("Leaving setUp().");
}

// ---------------------------------------------------------------------------
// S. S4U2SELF ACROSS REALMS.
// ---------------------------------------------------------------------------
async function selfSection(t) {
  log.debug("Entering selfSection().");
  t.log.info('=== S. S4U2Self across realms ===');
  const listed = setApp(ALPHA, 'frontend', 'krb5S4uSelfRealm', 'add', BETA);
  t.check(listed.ok, 'precondition: HTTP/frontend@' + ALPHA + ' lists ' +
          BETA + ' in krb5S4uSelfRealm', JSON.stringify(listed.errors || []));
  const refusedValue = setApp(ALPHA, 'frontend', 'krb5S4uSelfRealm', 'add',
                              'NOWHERE.TEST');
  t.check(!refusedValue.ok &&
          require('../common/error_codes').codeOf(refusedValue) ===
            'STS-REG-0362' &&
          (refusedValue.errors || []).join(' ').indexOf('NOWHERE.TEST') >= 0,
          'S0. a realm no trust accepts is refused at the write ' +
          '(STS-REG-0362)', JSON.stringify(refusedValue.errors || []));
  const front = await serviceTgt(t, ALPHA, 'frontend');
  let w = await walkSelf(front, ALPHA, 'frontend', 'alice', BETA);
  const back = w.replies[1];
  t.check(w.r.ok && w.asked.join('>') === [ALPHA, BETA, ALPHA].join('>') &&
          w.r.client.name.join('/') === 'alice' && w.r.realm === BETA &&
          w.r.flagNames.indexOf('forwardable') >= 0,
          'S1. HTTP/frontend@' + ALPHA + ' gets a FORWARDABLE ticket to ' +
          'itself for alice@' + BETA + ': referred to ' + BETA + ', which ' +
          'answers with a referral carrying alice\'s PAC, and ' + ALPHA +
          ' issues the ticket', show(w.r) + ' via ' + w.asked.join('>'));
  t.check(!!back && back.ok && back.client.name.join('/') ===
          'HTTP/frontend.alpha.test',
          'S1b. the referral from the user\'s realm is the SERVICE\'s ' +
          '(cname), not the user\'s ([MS-SFU] 3.2.5.1.1)', show(back));
  if (w.r.ok) {
    const part = await openTicket(ALPHA, w.r.ticket, spn('frontend', ALPHA));
    const info = logonOf(pacOf(part));
    t.check(!!info && info.logonDomainId && info.logonDomainId.text ===
            SID[BETA] && info.effectiveName === 'alice',
            'S1c. the PAC is the one ' + BETA + ' built: logon domain ' +
            SID[BETA], JSON.stringify(info && [info.effectiveName,
              info.logonDomainId && info.logonDomainId.text]));
  }
  setApp(ALPHA, 'notrusted', 'krb5S4uSelfRealm', 'add', BETA);
  const notTrusted = await serviceTgt(t, ALPHA, 'notrusted');
  w = await walkSelf(notTrusted, ALPHA, 'notrusted', 'alice', BETA);
  t.check(w.r.ok && w.r.flagNames.indexOf('forwardable') < 0,
          'S2. by a service the policy does not allow to impersonate: ' +
          'issued, NOT forwardable', show(w.r));
  w = await walkSelf(front, ALPHA, 'frontend', 'sensitive', BETA);
  t.check(w.r.ok && w.r.flagNames.indexOf('forwardable') < 0 &&
          w.replies[1].ok &&
          w.replies[1].flagNames.indexOf('forwardable') < 0,
          'S3. for a PROTECTED user of ' + BETA + ': ' + BETA + '\'s ' +
          'referral is not forwardable, nor is the ticket', show(w.r));
  const rbcd = await serviceTgt(t, ALPHA, 'rbcd');
  w = await walkSelf(rbcd, ALPHA, 'rbcd', 'alice', BETA);
  t.check(!!errorOf(w.r) && errorOf(w.r).code === 12 &&
          /krb5S4uSelfRealm/.test(errorOf(w.r).eText),
          'S4. a service that does not list ' + BETA + ' is REFUSED: ' +
          'KDC_ERR_POLICY (STS-KRB-0231)', show(w.r));
  w = await walkSelf(front, ALPHA, 'frontend', 'alice', BETA, true);
  t.check(w.r.ok && w.r.client.name.join('/') === 'alice' &&
          w.r.replyPadata.some(function (pa) {
            return pa.type === msgs.PA_TYPE.S4U_X509_USER;
          }),
          'S5. PA-S4U-X509-USER naming alice@' + BETA + ' at every hop: the ' +
          'ticket, and the padata answered in the reply', show(w.r));
  setApp(ALPHA, 'frontend', 'krb5S4uSelfRealm', 'add', GAMMA);
  w = await walkSelf(front, ALPHA, 'frontend', 'alice', GAMMA);
  t.check(w.r.ok && w.asked.join('>') ===
          [ALPHA, BETA, GAMMA, BETA, ALPHA].join('>') &&
          w.r.realm === GAMMA,
          'S6. MULTI-HOP: alice@' + GAMMA + ' through ' + BETA + ' (a ' +
          'transitive trust) — out to the user\'s realm and back',
          show(w.r) + ' via ' + w.asked.join('>'));
  if (w.r.ok) {
    const part = await openTicket(ALPHA, w.r.ticket, spn('frontend', ALPHA));
    const path = trusts.decodeTransited(part.transited.contents, GAMMA,
                                        ALPHA);
    t.check(JSON.stringify(path.realms) === JSON.stringify([BETA]),
            'S6b. its transited is the USER\'s path, ' + GAMMA + ' to ' +
            ALPHA + ': ' + BETA, JSON.stringify(path));
  }
  log.debug("Leaving selfSection().");
}

// ---------------------------------------------------------------------------
// XR. EXPLICIT GRANTS ONLY ACROSS A TRUST (rcbj, 2026-10-19).
// ---------------------------------------------------------------------------
async function grantsSection(t) {
  log.debug("Entering grantsSection().");
  t.log.info('=== XR. a principal of another realm holds only its grants ===');
  const roles = require('../common/roles');
  const closed = spn('closed', BETA);
  const aliceTgt = await userTgt(t, ALPHA, 'alice');
  const referral = await wire.tgsExchange(T, aliceTgt, closed, ALPHA);
  let r = referral.ok ? await wire.tgsExchange(T, referral, closed, BETA)
                      : referral;
  t.check(!!errorOf(r) && errorOf(r).code === 12 &&
          /requires EVERYBODY and "alice@ALPHA\.TEST" holds/.test(
            errorOf(r).eText),
          'XR1. alice@' + ALPHA + ' is REFUSED a ticket to ' + BETA + '\'s ' +
          'HTTP/closed, which requires only EVERYBODY: across a trust she ' +
          'holds neither EVERYBODY nor ALL_AUTHENTICATED_USERS (STS-KRB-0039)',
          show(r));
  const bobTgt = await userTgt(t, BETA, 'bob');
  const local = await wire.tgsExchange(T, bobTgt, closed, BETA);
  t.check(local.ok && local.client.name.join('/') === 'bob',
          'XR2. bob@' + BETA + ', a person of the realm itself, is issued ' +
          'it as before', show(local));
  // AN EXPLICIT GRANT, to her whole name.
  const granted = inRealm(BETA, function () {
    const wrote = roles.write('closed-guests', {
      description: 'Created by ' + __filename,
      users: ['alice@' + ALPHA] });
    const app = 'HTTP/closed.' + BETA.toLowerCase();
    const made = applications.get(app) ? { ok: true }
      : applications.createApplication({
        identifier: app, kind: 'kerberos-service', protocols: ['krb5'],
        fields: { appRequiredRole: ['EVERYBODY', 'closed-guests'] },
        actor: __filename });
    return { ok: !!(wrote && wrote.ok && made && made.ok),
             errors: ((wrote && wrote.errors) || [])
               .concat((made && made.errors) || []) };
  });
  t.check(granted.ok, 'precondition: ' + BETA + ' grants closed-guests to ' +
          'alice@' + ALPHA + ' by name, and HTTP/closed requires it (or ' +
          'EVERYBODY)', JSON.stringify(granted.errors));
  r = referral.ok ? await wire.tgsExchange(T, referral, closed, BETA)
                  : referral;
  t.check(r.ok && r.client.name.join('/') === 'alice' && r.realm === ALPHA,
          'XR3. with the role granted to alice@' + ALPHA + ' by name, ' +
          BETA + ' issues the ticket', show(r));
  const again = await wire.tgsExchange(T, bobTgt, closed, BETA);
  t.check(again.ok, 'XR4. and bob@' + BETA + ' still holds EVERYBODY, so ' +
          'the narrowed service still admits him', show(again));
  const otherTgt = await userTgt(t, ALPHA, 'bob');
  const otherRef = await wire.tgsExchange(T, otherTgt, closed, ALPHA);
  r = otherRef.ok ? await wire.tgsExchange(T, otherRef, closed, BETA)
                  : otherRef;
  t.check(!!errorOf(r) && errorOf(r).code === 12,
          'XR5. while bob@' + ALPHA + ', granted nothing, is still refused ' +
          '— a local bob\'s EVERYBODY is not his', show(r));
  log.debug("Leaving grantsSection().");
}

// ---------------------------------------------------------------------------
// P. CLASSIC S4U2PROXY ACROSS REALMS.
// ---------------------------------------------------------------------------
async function classicSection(t) {
  log.debug("Entering classicSection().");
  t.log.info('=== P. classic constrained delegation across realms ===');
  const front = await serviceTgt(t, ALPHA, 'frontend');
  const self = await walkSelf(front, ALPHA, 'frontend', 'alice', ALPHA);
  t.check(self.r.ok && self.r.flagNames.indexOf('forwardable') >= 0,
          'precondition: forwardable evidence for alice@' + ALPHA,
          show(self.r));
  setApp(ALPHA, 'frontend', 'appAllowedToDelegateTo', 'add',
         appId('backend', BETA));
  // BOTH REALMS MUST TURN IT ON (rcbj, 2026-10-19), and each refuses on its
  // own setting: the front end's realm before it refers the evidence
  // (STS-KRB-0232), the target's realm when the referral arrives
  // (STS-KRB-0242) — every combination, the refusal at the right side.
  const setting = function (krbRealm, on) {
    log.debug("Entering setting(). " + krbRealm + " " + on);
    if (on) {
      realms.setOverride(IDS[krbRealm], 'krb5.crossRealmClassicDelegation',
                         'true');
    } else {
      realms.clearOverride(IDS[krbRealm],
                           'krb5.crossRealmClassicDelegation');
    }
    log.debug("Leaving setting().");
  };
  const combos = [
    { label: 'P1', alpha: false, beta: false },
    { label: 'P1b', alpha: false, beta: true },
    { label: 'P1c', alpha: true, beta: false },
    { label: 'P2', alpha: true, beta: true }];
  for (const c of combos) {
    setting(ALPHA, c.alpha);
    setting(BETA, c.beta);
    const p = await proxyAcross(front, self.r.ticket, spn('backend', BETA),
                                ALPHA, BETA, false);
    const named = c.label + '. krb5.crossRealmClassicDelegation ' +
      (c.alpha ? 'on' : 'off') + ' in ' + ALPHA + ' (the front end\'s), ' +
      (c.beta ? 'on' : 'off') + ' in ' + BETA + ' (the target\'s): ';
    if (!c.alpha) {
      t.check(!p.first.ok && errorOf(p.first).code === 12 &&
              p.first.error.realm === ALPHA &&
              /refused by ALPHA\.TEST, the front end's realm/.test(
                errorOf(p.first).eText),
              named + 'refused by ' + ALPHA + ' before it refers the ' +
              'evidence (STS-KRB-0232)', show(p.first));
    } else if (!c.beta) {
      t.check(p.first.ok && p.first.sname.name[0] === 'krbtgt' &&
              !!errorOf(p.r) && errorOf(p.r).code === 12 &&
              /refused by BETA\.TEST, the target's realm/.test(
                errorOf(p.r).eText),
              named + ALPHA + ' refers the evidence and ' + BETA +
              ' refuses it on its own setting (STS-KRB-0242)',
              show(p.first) + ' / ' + show(p.r));
    } else {
      t.check(p.first.ok && p.first.client.name.join('/') === 'alice' &&
              p.r.ok && p.r.client.name.join('/') === 'alice' &&
              p.r.realm === ALPHA && p.r.srealm === BETA,
              named + ALPHA + ' refers the evidence as a TGT for alice, ' +
              'and ' + BETA + ' issues the ticket to HTTP/backend for ' +
              'alice@' + ALPHA, show(p.first) + ' / ' + show(p.r));
    }
  }
  setting(ALPHA, false);
  setting(BETA, false);
  setApp(ALPHA, 'frontend', 'appAllowedToDelegateTo', 'remove',
         appId('backend', BETA));
  log.debug("Leaving classicSection().");
}

// ---------------------------------------------------------------------------
// R. RESOURCE-BASED S4U2PROXY ACROSS REALMS.
// ---------------------------------------------------------------------------
async function rbcdSection(t) {
  log.debug("Entering rbcdSection().");
  t.log.info('=== R. resource-based delegation across realms ===');
  setApp(BETA, 'rbcd', 'appAllowedToActOnBehalfOf', 'add',
         appId('frontend', ALPHA));
  setApp(BETA, 'rbcd', 'appAllowedToActOnBehalfOf', 'add',
         appId('notrusted', ALPHA));
  const front = await serviceTgt(t, ALPHA, 'frontend');
  const self = await walkSelf(front, ALPHA, 'frontend', 'alice', ALPHA);
  let p = await proxyAcross(front, self.r.ticket, spn('rbcd', BETA), ALPHA,
                            BETA, true);
  t.check(p.r.ok && p.r.client.name.join('/') === 'alice' &&
          p.r.realm === ALPHA,
          'R1. a FOREIGN front end (HTTP/frontend@' + ALPHA + ') to a local ' +
          'back end of ' + BETA + ' that names it SPN@REALM', show(p.r));
  if (p.r.ok) {
    const part = await openTicket(BETA, p.r.ticket, spn('rbcd', BETA));
    const info = delegationInfoOf(part);
    t.check(!!info && info.s4u2proxyTarget === 'HTTP/rbcd.beta.test' &&
            (info.transitedServices || []).indexOf(appId('frontend',
                                                         ALPHA)) >= 0,
            'R6. S4U_DELEGATION_INFO names the target bare and the front ' +
            'end with its realm', JSON.stringify(info));
  }
  setApp(ALPHA, 'rbcd', 'appAllowedToActOnBehalfOf', 'add',
         appId('frontend', BETA));
  const frontB = await serviceTgt(t, BETA, 'frontend');
  const selfB = await walkSelf(frontB, BETA, 'frontend', 'bob', BETA);
  p = await proxyAcross(frontB, selfB.r.ticket, spn('rbcd', ALPHA), BETA,
                        ALPHA, true);
  t.check(p.r.ok && p.r.client.name.join('/') === 'bob' &&
          p.r.realm === BETA && p.r.srealm === ALPHA,
          'R2. the other way: a LOCAL front end of ' + BETA + ' to a back ' +
          'end of ' + ALPHA, show(p.r));
  const notTrusted = await serviceTgt(t, ALPHA, 'notrusted');
  const weak = await walkSelf(notTrusted, ALPHA, 'notrusted', 'alice',
                              ALPHA);
  p = await proxyAcross(notTrusted, weak.r.ticket, spn('rbcd', BETA), ALPHA,
                        BETA, true);
  t.check(!!errorOf(p.r) && errorOf(p.r).code === 13,
          'R3. NON-FORWARDABLE evidence is refused, across realms as ' +
          'within one (STS-KRB-0199)', show(p.r));
  const sensitive = await walkSelf(front, ALPHA, 'frontend', 'sensitive',
                                   ALPHA);
  p = await proxyAcross(front, sensitive.r.ticket, spn('rbcd', BETA), ALPHA,
                        BETA, true);
  t.check(!!errorOf(p.r) && errorOf(p.r).code === 13,
          'R4. a PROTECTED user is refused: their evidence is never ' +
          'forwardable', show(p.r));
  p = await proxyAcross(front, self.r.ticket, spn('backend', BETA), ALPHA,
                        BETA, true);
  t.check(p.first.ok && !!errorOf(p.r) && errorOf(p.r).code === 13 &&
          /appAllowedToActOnBehalfOf/.test(errorOf(p.r).eText),
          'R5. an ACTOR THE TARGET DOES NOT LIST: ' + ALPHA + ' refers it ' +
          '(the target is ' + BETA + '\'s to decide), and ' + BETA +
          ' refuses (STS-KRB-0010)', show(p.r));
  log.debug("Leaving rbcdSection().");
}

// ---------------------------------------------------------------------------
// E. EVIDENCE ACROSS A TRUST IS PAC-VERIFIED.
// ---------------------------------------------------------------------------
// The referred evidence (krbtgt/BETA@ALPHA, the user's) opened and resealed
// with BETA's INCOMING key — the key a forger would need, which is the point:
// only that key's holder could have changed it, so what is tested is that
// the PAC inside is checked with it rather than taken on the seal alone.
async function crossRealmKey(at, from) {
  log.debug("Entering crossRealmKey().");
  const key = await inRealm(at, async function () {
    const principal = principals.find(['krbtgt', at], from);
    return { principal: principal };
  });
  log.debug("Leaving crossRealmKey().");
  return key;
}

async function reseal(at, from, ticket, change) {
  log.debug("Entering reseal().");
  const out = await inRealm(at, async function () {
    const principal = principals.find(['krbtgt', at], from);
    const profile = kcrypto.etypeById(ticket.encPart.etype);
    const key = await principals.longTermKey(principal, ticket.encPart.etype);
    const part = msgs.readEncTicketPart(await profile.decrypt(key,
      kcrypto.KEY_USAGE.KDC_REP_TICKET, ticket.encPart.cipher));
    const changed = await change(part, { etype: ticket.encPart.etype,
                                         key: key });
    // A decoded ticket keeps its DER as `raw`, which the encoder sends as
    // it is; the resealed one is encoded from its fields.
    return { realm: ticket.realm, sname: ticket.sname,
             encPart: Object.assign({}, ticket.encPart, {
               cipher: await profile.encrypt(key,
                 kcrypto.KEY_USAGE.KDC_REP_TICKET,
                 msgs.encEncTicketPart(changed)) }) };
  });
  log.debug("Leaving reseal().");
  return out;
}

async function evidenceSection(t) {
  log.debug("Entering evidenceSection().");
  t.log.info('=== E. evidence across a trust is PAC-verified ===');
  // R1's shape: HTTP/frontend@ALPHA to HTTP/rbcd@BETA, resource-based.
  const front = await serviceTgt(t, ALPHA, 'frontend');
  const self = await walkSelf(front, ALPHA, 'frontend', 'alice', ALPHA);
  const p = await proxyAcross(front, self.r.ticket, spn('rbcd', BETA), ALPHA,
                              BETA, true);
  t.check(p.r.ok, 'precondition: the genuine referred evidence is accepted',
          show(p.r));
  if (!p.own) {
    log.debug("Leaving evidenceSection(). No referral.");
    return;
  }
  const held = await crossRealmKey(BETA, ALPHA);
  t.check(!!held.principal, 'precondition: ' + BETA + ' holds the ' +
          'incoming key krbtgt/' + BETA + '@' + ALPHA, '');
  // E1: the genuine PAC's three signatures verify with that key.
  let genuine = null;
  await reseal(BETA, ALPHA, p.first.ticket, async function (part, key) {
    const pacs = kpac.findPacs(part.authorizationData || []);
    const placeholder = kpac.wrapPacAsAuthorizationData(new Uint8Array([0]));
    const ticketBytes = msgs.encEncTicketPart(Object.assign({}, part, {
      authorizationData: (part.authorizationData || []).map(function (e) {
        return kpac.findPacs([e]).length ? placeholder[0] : e;
      }) }));
    genuine = await kpac.verifySignatures(kpac.parsePac(pacs[0].bytes),
      { serverKey: key, kdcKey: key, ticketBytes: ticketBytes });
    return part;
  });
  const verified = (genuine || []).filter(function (one) {
    return one.verified === true;
  }).map(function (one) { return one.name; });
  t.check(verified.length === 3,
          'E1. the GENUINE referral\'s PAC carries server, KDC and ticket ' +
          'signatures, each made with the inter-realm key — what ' + BETA +
          ' verifies before it accepts the evidence',
          JSON.stringify(verified));
  const refusedAs0240 = function (r) {
    return !!errorOf(r) && errorOf(r).code === 41 &&
      /across the trust was not accepted/.test(errorOf(r).eText);
  };
  // E2: a PAC FORGED under a key that is not the inter-realm key.
  const forged = await reseal(BETA, ALPHA, p.first.ticket,
    async function (part, key) {
      const pacs = kpac.findPacs(part.authorizationData || []);
      const wrong = { etype: key.etype, key: kcrypto.randomBytes(
        kcrypto.etypeById(key.etype).keyBytes) };
      const placeholder = msgs.encEncTicketPart(Object.assign({}, part, {
        authorizationData: kpac.wrapPacAsAuthorizationData(
          new Uint8Array([0])) }));
      return Object.assign({}, part, {
        authorizationData: kpac.wrapPacAsAuthorizationData(
          await kpac.resignPac(pacs[0].bytes, { serverKey: wrong,
            kdcKey: wrong, includeTicketSignature: true,
            includeExtendedKdcSignature: false,
            ticketBytes: placeholder })) });
    });
  let r = await proxy(p.own, forged, spn('rbcd', BETA), BETA, true);
  t.check(refusedAs0240(r),
          'E2. a PAC FORGED under another key is refused KRB_AP_ERR_MODIFIED ' +
          '(STS-KRB-0240)', show(r));
  // E3: the PAC ALTERED after it was signed — the user's name rewritten.
  const altered = await reseal(BETA, ALPHA, p.first.ticket,
    async function (part) {
      const pacs = kpac.findPacs(part.authorizationData || []);
      const bytes = Uint8Array.from(pacs[0].bytes);
      const from = Buffer.from('alice', 'utf16le');
      const at = Buffer.from(bytes).indexOf(from);
      if (at >= 0) {
        bytes[at] = 'b'.charCodeAt(0);
      }
      return Object.assign({}, part, {
        authorizationData: kpac.wrapPacAsAuthorizationData(bytes) });
    });
  r = await proxy(p.own, altered, spn('rbcd', BETA), BETA, true);
  t.check(refusedAs0240(r),
          'E3. a PAC ALTERED after it was signed (its client name ' +
          'rewritten) is refused (STS-KRB-0240)', show(r));
  // E4: the TICKET altered after it was signed — a flag added.
  const flagged = await reseal(BETA, ALPHA, p.first.ticket,
    async function (part) {
      const extra = msgs.TICKET_FLAG.OK_AS_DELEGATE;
      return Object.assign({}, part, { flags: (part.flags || [])
        .filter(function (f) { return f !== extra; }).concat(
          (part.flags || []).indexOf(extra) >= 0 ? [] : [extra]) });
    });
  r = await proxy(p.own, flagged, spn('rbcd', BETA), BETA, true);
  t.check(refusedAs0240(r),
          'E4. the TICKET altered after its PAC was signed (a flag ' +
          'toggled; CVE-2020-17049\'s shape) is refused by the ticket ' +
          'signature (STS-KRB-0240)', show(r));
  // E5: no PAC at all.
  const bare = await reseal(BETA, ALPHA, p.first.ticket,
    async function (part) {
      return Object.assign({}, part, { authorizationData: null });
    });
  r = await proxy(p.own, bare, spn('rbcd', BETA), BETA, true);
  t.check(refusedAs0240(r) && /carries no PAC/.test(errorOf(r).eText),
          'E5. evidence from across a trust with NO PAC is refused ' +
          '(STS-KRB-0240)', show(r));
  // E6: and the genuine one, presented again, still passes.
  r = await proxy(p.own, p.first.ticket, spn('rbcd', BETA), BETA, true);
  t.check(r.ok, 'E6. the GENUINE evidence, presented again, is accepted',
          show(r));
  log.debug("Leaving evidenceSection().");
}

// ---------------------------------------------------------------------------
// X. S4U2SELF, THEN S4U2PROXY, THROUGH THE TRUST.
// ---------------------------------------------------------------------------
async function chainSection(t) {
  log.debug("Entering chainSection().");
  t.log.info('=== X. protocol transition, then constrained delegation, ' +
             'across realms ===');
  // ALPHA reaches GAMMA directly for this section.
  inRealm(ALPHA, function () {
    return trusts.update(BETA, { suffixes: ['beta.test'] });
  });
  const ac = inRealm(ALPHA, function () {
    return trusts.pair(IDS[GAMMA], { password: SHARED, attributes: [] });
  });
  t.check(ac.ok, 'precondition: ALPHA <-> GAMMA paired',
          JSON.stringify(ac.errors || []));
  setApp(GAMMA, 'rbcd', 'appAllowedToActOnBehalfOf', 'add',
         appId('frontend', ALPHA));
  const front = await serviceTgt(t, ALPHA, 'frontend');
  const self = await walkSelf(front, ALPHA, 'frontend', 'alice', BETA);
  t.check(self.r.ok && self.r.flagNames.indexOf('forwardable') >= 0,
          'X1. S4U2Self: HTTP/frontend@' + ALPHA + ' holds a forwardable ' +
          'ticket for alice@' + BETA, show(self.r));
  const p = await proxyAcross(front, self.r.ticket, spn('rbcd', GAMMA),
                              ALPHA, GAMMA, true);
  t.check(p.r.ok && p.r.client.name.join('/') === 'alice' &&
          p.r.realm === BETA && p.r.srealm === GAMMA,
          'X2. then S4U2Proxy, resource-based, to HTTP/rbcd@' + GAMMA + ': ' +
          'a ticket for alice@' + BETA, show(p.r));
  if (p.r.ok) {
    const part = await openTicket(GAMMA, p.r.ticket, spn('rbcd', GAMMA));
    const info = delegationInfoOf(part);
    const logon = logonOf(pacOf(part));
    t.check(!!info && info.s4u2proxyTarget === 'HTTP/rbcd.gamma.test' &&
            JSON.stringify(info.transitedServices) ===
              JSON.stringify([appId('frontend', ALPHA)]) &&
            !!logon && logon.logonDomainId.text === SID[BETA],
            'X3. the PAC\'s delegation chain names the front end with its ' +
            'realm, and the identity is the one ' + BETA + ' built',
            JSON.stringify([info, logon && logon.logonDomainId.text]));
  }
  log.debug("Leaving chainSection().");
}

// ---------------------------------------------------------------------------
// F. A TGT DELEGATED ACROSS A TRUST.
// ---------------------------------------------------------------------------
function bothWays(attributes) {
  log.debug("Entering bothWays().");
  inRealm(ALPHA, function () {
    return trusts.update(BETA, { attributes: attributes });
  });
  inRealm(BETA, function () {
    return trusts.update(ALPHA, { attributes: attributes });
  });
  log.debug("Leaving bothWays().");
}

async function okAsDelegate(t, user) {
  log.debug("Entering okAsDelegate().");
  const tgt = await userTgt(t, ALPHA, user || 'alice');
  const referral = await wire.tgsExchange(T, tgt, spn('web', BETA), ALPHA);
  const svc = referral.ok ? await wire.tgsExchange(T, referral,
    spn('web', BETA), BETA) : referral;
  log.debug("Leaving okAsDelegate().");
  return { referral: referral, svc: svc,
           ok: svc.ok && svc.flagNames.indexOf('ok-as-delegate') >= 0 };
}

async function forwardedSection(t) {
  log.debug("Entering forwardedSection().");
  t.log.info('=== F. a TGT delegated across a trust ===');
  setApp(BETA, 'web', 'krb5TrustedForDelegation', 'set', 'TRUE');
  bothWays(['enable-tgt-delegation']);
  let r = await okAsDelegate(t);
  t.check(r.ok && r.referral.flagNames.indexOf('ok-as-delegate') >= 0,
          'F1. ENABLE_TGT_DELEGATION: the referral carries ok-as-delegate, ' +
          'and so does the ticket of a service trusted for delegation',
          show(r.svc));
  bothWays(['enable-tgt-delegation', 'no-tgt-delegation']);
  bothWays(['no-tgt-delegation']);
  r = await okAsDelegate(t);
  t.check(r.svc.ok && !r.ok,
          'F2. NO_TGT_DELEGATION: no ok-as-delegate', show(r.svc));
  bothWays([]);
  r = await okAsDelegate(t);
  t.check(r.svc.ok && !r.ok,
          'F3. neither bit: no ok-as-delegate — TGT delegation across an ' +
          'organization is off unless enabled', show(r.svc));
  bothWays(['enable-tgt-delegation']);
  setApp(BETA, 'web', 'krb5ForeignTgtDelegation', 'set', 'deny');
  r = await okAsDelegate(t);
  t.check(r.svc.ok && !r.ok && r.referral.flagNames
            .indexOf('ok-as-delegate') >= 0,
          'F4. krb5ForeignTgtDelegation deny NARROWS it: the trust allows ' +
          'it and the service still gets none', show(r.svc));
  setApp(BETA, 'web', 'krb5ForeignTgtDelegation', 'set', 'inherit');
  const tgt = await userTgt(t, ALPHA, 'alice');
  const across = await wire.tgsExchange(T, tgt,
    { type: 2, name: ['krbtgt', BETA] }, ALPHA);
  const forward = function (presented) {
    log.debug("Entering forward().");
    log.debug("Leaving forward().");
    return wire.tgsExchange(T, presented, { type: 2, name: ['krbtgt', BETA] },
                            BETA, { kdcOptions: [msgs.KDC_OPTION.FORWARDED] });
  };
  let f = await forward(across);
  t.check(f.ok && f.flagNames.indexOf('forwarded') >= 0,
          'F5. a FORWARDED TGT across a trust with ENABLE_TGT_DELEGATION',
          show(f));
  bothWays([]);
  f = await forward(across);
  t.check(!!errorOf(f) && errorOf(f).code === 13 &&
          /not forwarded across/.test(errorOf(f).eText),
          'F5b. and refused across one without it (STS-KRB-0233)', show(f));
  bothWays(['enable-tgt-delegation']);
  const sensitive = await userTgt(t, ALPHA, 'sensitive');
  const sAcross = await wire.tgsExchange(T, sensitive,
    { type: 2, name: ['krbtgt', BETA] }, ALPHA);
  f = sAcross.ok ? await forward(sAcross) : sAcross;
  t.check(!!errorOf(f) && errorOf(f).code === 13,
          'F6. a PROTECTED user\'s TGT is never forwarded, across a trust ' +
          'that enables it as anywhere', show(f));
  bothWays([]);
  log.debug("Leaving forwardedSection().");
}

// ---------------------------------------------------------------------------
// T. THE TRUST'S STATE.
// ---------------------------------------------------------------------------
async function stateSection(t) {
  log.debug("Entering stateSection().");
  t.log.info('=== T. the trust\'s state ===');
  const front = await serviceTgt(t, ALPHA, 'frontend');
  inRealm(BETA, function () {
    return trusts.setEnabled(ALPHA, false);
  });
  let w = await walkSelf(front, ALPHA, 'frontend', 'alice', BETA);
  t.check(!!errorOf(w.r) && /disabled/.test(errorOf(w.r).eText),
          'T1. a DISABLED trust: ' + BETA + ' refuses the S4U2Self walk ' +
          'at the first hop', show(w.r));
  inRealm(BETA, function () {
    return trusts.setEnabled(ALPHA, true);
  });
  inRealm(ALPHA, function () {
    return trusts.update(BETA, { incoming: null });
  });
  w = await walkSelf(front, ALPHA, 'frontend', 'alice', BETA);
  t.check(!!errorOf(w.r) && /no incoming key/.test(errorOf(w.r).eText) &&
          w.asked.length === 3,
          'T2. a MISSING INCOMING KEY: ' + ALPHA + ' cannot open ' + BETA +
          '\'s referral back', show(w.r));
  inRealm(ALPHA, function () {
    return trusts.update(BETA, { incoming: { password: SHARED } });
  });
  // The subject's filtered SIDs are what the KDC hands in: her Domain
  // Users, which setUp() granted trust-partners to.
  const delegation = require('../kerberos/krb5_delegation');
  const selfSem = inRealm(ALPHA, function () {
    return delegation.decide({ mechanism: 'self',
      requester: ['HTTP', 'frontend.alpha.test'], subject: ['alice'],
      subjectRealm: BETA, target: ['HTTP', 'frontend.alpha.test'],
      realm: ALPHA, trustPartner: BETA, subjectSids: [SID[BETA] + '-513'] });
  });
  const proxySem = inRealm(BETA, function () {
    return delegation.decide({ mechanism: 'proxy',
      requester: ['HTTP', 'frontend.alpha.test'], requesterRealm: ALPHA,
      subject: ['alice'], subjectRealm: ALPHA,
      target: ['HTTP', 'rbcd.beta.test'], realm: BETA, rbcd: true,
      trustPartner: ALPHA, subjectSids: [SID[ALPHA] + '-513'] });
  });
  const ungranted = inRealm(ALPHA, function () {
    return delegation.decide({ mechanism: 'self',
      requester: ['HTTP', 'frontend.alpha.test'], subject: ['alice'],
      subjectRealm: BETA, target: ['HTTP', 'frontend.alpha.test'],
      realm: ALPHA, trustPartner: BETA, subjectSids: [] });
  });
  t.check(!ungranted.allowed && ungranted.refusal === 'authority',
          'T3b. and with no SID that holds a grant, alice@' + BETA + ' has ' +
          'no authority for HTTP/frontend — EVERYBODY is not hers across a ' +
          'trust', JSON.stringify([ungranted.refusal, ungranted.why]));
  t.check(selfSem.allowed && selfSem.semantics === 'impersonation' &&
          proxySem.allowed && proxySem.semantics === 'delegation',
          'T3. the SEMANTICS the policy chooses across the trust: ' +
          'impersonation for S4U2Self, delegation for S4U2Proxy',
          JSON.stringify([selfSem.semantics, proxySem.semantics,
                          selfSem.why, proxySem.why]));
  log.debug("Leaving stateSection().");
}

// ---------------------------------------------------------------------------
// SF. SID FILTERING, row by row (kerberos/CLAUDE.md, *SID FILTERING: THE
// RULES*). A PAC as ALPHA issues it (logon domain ALPHA's), arriving at
// BETA through BETA's record for ALPHA, whose attributes each row sets.
// ---------------------------------------------------------------------------
async function craftPac(spec) {
  log.debug("Entering craftPac().");
  const key = { etype: 18, key: kcrypto.randomBytes(32) };
  const s = spec || {};
  let bytes = await kpac.buildPac({
    serverKey: key, kdcKey: key,
    logonInfo: {
      logonTime: new Date(), effectiveName: 'alice', userId: 1104,
      primaryGroupId: 513, groups: [{ relativeId: 513 }],
      logonDomainName: 'ALPHA',
      logonDomainId: s.logonDomain || SID[ALPHA],
      extraSids: (s.extraSids || []).map(function (sid) {
        return { sid: sid, attributes: 7 };
      }),
      resourceGroupDomainSid: s.resourceDomain || null,
      resourceGroups: (s.resourceGroups || []).map(function (rid) {
        return { relativeId: rid };
      })
    },
    clientInfo: { name: 'alice', clientId: new Date() },
    clientClaims: s.claims ? { arrays: [{ claims: [
      { id: 'ad://ext/department', type: 3, values: ['sales'] }] }] } : null
  });
  if (s.device) {
    const pac = kpac.parsePac(bytes);
    const entries = pac.buffers.map(function (b) {
      return { type: b.type, bytes: b.bytes };
    }).concat([{ type: kpac.TYPE.DEVICE_INFO,
                 bytes: new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]) }]);
    bytes = kpac.assemblePac(entries).bytes;
  }
  log.debug("Leaving craftPac().");
  return bytes;
}

async function filtered(attributes, spec, extra) {
  log.debug("Entering filtered().");
  const set = inRealm(BETA, function () {
    return trusts.update(ALPHA, Object.assign({ attributes: attributes,
                                                forestTrustInfo: null },
                                              extra || {}));
  });
  if (!set.ok) {
    log.debug("Leaving filtered(). The record was refused.");
    return { setErrors: set.errors };
  }
  const bytes = await craftPac(spec);
  const out = inRealm(BETA, function () {
    return trusts.sidFilter(bytes, ALPHA, SID[BETA]);
  });
  const pac = kpac.parsePac(out.bytes);
  out.sids = sidsOf(logonOf(pac));
  const info = logonOf(pac);
  out.resources = ((info && info.resourceGroups) || []).map(function (g) {
    return g.relativeId;
  });
  out.types = pac.buffers.map(function (b) {
    return b.type;
  });
  log.debug("Leaving filtered().");
  return out;
}

function has(list, value) {
  log.debug("Entering has().");
  log.debug("Leaving has().");
  return (list || []).indexOf(value) >= 0;
}

async function sidFilteringSection(t) {
  log.debug("Entering sidFilteringSection().");
  t.log.info('=== SF. SID filtering, row by row ===');
  const A = SID[ALPHA];
  const B = SID[BETA];
  const C = SID[GAMMA];
  const X = OTHER_SID;
  const show2 = function (r) {
    log.debug("Entering show2().");
    log.debug("Leaving show2().");
    return JSON.stringify({ sids: r.sids, removed: r.removed,
                            refused: r.refused, boundary: r.boundary,
                            resources: r.resources, types: r.types,
                            setErrors: r.setErrors });
  };
  let r = await filtered([], { extraSids: ['S-1-5-11', 'S-1-1-0',
                                           'S-1-5-32-544'] });
  t.check(r.boundary === 'External' && !has(r.sids, 'S-1-5-11') &&
          !has(r.sids, 'S-1-1-0') && !has(r.sids, 'S-1-5-32-544'),
          'SF-R1. AlwaysFilter SIDs never cross', show2(r));
  r = await filtered(['quarantined'], { extraSids: ['S-1-5-1000-5',
    'S-1-5-15', 'S-1-5-21-0-0-0-497', 'S-1-18-1'] });
  t.check(r.boundary === 'QuarantinedExternal' && r.sids.length === 4,
          'SF-R2. NeverFilter SIDs cross even a quarantined boundary ' +
          '(S-1-18-1 among them: an UNCERTAIN row)', show2(r));
  r = await filtered([], { extraSids: ['S-1-5-9'] });
  const edcIn = await filtered(['within-forest'], { extraSids: ['S-1-5-9'] });
  t.check(!has(r.sids, 'S-1-5-9') && has(edcIn.sids, 'S-1-5-9'),
          'SF-R3. Enterprise Domain Controllers is filtered across an ' +
          'external boundary, kept within the forest',
          show2(r) + ' / ' + show2(edcIn));
  r = await filtered([], { extraSids: ['S-1-5-21-5-6', A,
                                       A + '-1104-9'] });
  t.check(r.sids.length === 0,
          'SF-R4. a partially formed SID, a domain\'s own SID and one with ' +
          'too many RIDs never cross', show2(r));
  r = await filtered([], { extraSids: [X + '-512', A + '-512'] });
  t.check(!has(r.sids, X + '-512') && has(r.sids, A + '-512'),
          'SF-R5. a ForestSpecific SID crosses an external boundary only ' +
          'for the trusted domain', show2(r));
  r = await filtered(['within-forest'], { extraSids: [B + '-512'] });
  t.check(!has(r.sids, B + '-512'),
          'SF-R6. this realm\'s own well-known SIDs are filtered at every ' +
          'boundary, within the forest included', show2(r));
  r = await filtered(['within-forest'], { extraSids: [X + '-513'] });
  t.check(!has(r.sids, X + '-513'),
          'SF-R7. a well-known SID of a domain that is not the logon ' +
          'domain is filtered, within the forest too', show2(r));
  r = await filtered([], { logonDomain: B, extraSids: [] });
  t.check(!!r.refused && /R8/.test(r.refused),
          'SF-R8. a PAC whose logon domain is this realm\'s forest, across ' +
          'an external boundary, may not cross', show2(r));
  r = await filtered([], { extraSids: [B + '-1500'] });
  const pim = await filtered(['forest-transitive', 'treat-as-external',
                              'pim-trust'], { extraSids: [B + '-1500'] });
  t.check(!has(r.sids, B + '-1500') && has(pim.sids, B + '-1500') &&
          pim.boundary === 'PrivilegedIdentityManagement',
          'SF-R9. this realm\'s forest\'s SIDs do not come back over an ' +
          'external trust (they do over a PIM one)',
          show2(r) + ' / ' + show2(pim));
  r = await filtered(['quarantined'], { extraSids: [A + '-1500',
                                                    C + '-1500'] });
  t.check(has(r.sids, A + '-1500') && !has(r.sids, C + '-1500'),
          'SF-R10. a quarantined external trust passes only the trusted ' +
          'domain\'s SIDs', show2(r));
  r = await filtered(['within-forest', 'quarantined'],
                     { extraSids: ['S-1-5-9', A + '-1500', C + '-1500'] });
  t.check(r.boundary === 'QuarantinedWithinForest' &&
          has(r.sids, 'S-1-5-9') && has(r.sids, A + '-1500') &&
          !has(r.sids, C + '-1500'),
          'SF-R11. quarantined within the forest: Enterprise Domain ' +
          'Controllers and the trusted domain\'s SIDs only', show2(r));
  r = await filtered(['forest-transitive'],
                     { extraSids: [A + '-1500', C + '-1500', X + '-1500'] },
                     { forestTrustInfo: { domains: [
                       { sid: A, dnsName: 'alpha.test', netbiosName: 'ALPHA' },
                       { sid: C, dnsName: 'gamma.test', netbiosName: 'GAMMA',
                         sidEnabled: false }] } });
  t.check(r.boundary === 'CrossForest' && has(r.sids, A + '-1500') &&
          !has(r.sids, C + '-1500') && !has(r.sids, X + '-1500'),
          'SF-R12. a cross-forest trust passes the forest trust ' +
          'information\'s ENABLED domains only', show2(r));
  r = await filtered(['forest-transitive', 'treat-as-external'],
                     { extraSids: [X + '-1500'] });
  t.check(r.boundary === 'External' && has(r.sids, X + '-1500'),
          'SF-R13. TREAT_AS_EXTERNAL relaxes a cross-forest trust to ' +
          'external: SID history from another forest crosses', show2(r));
  r = await filtered(['forest-transitive', 'treat-as-external', 'pim-trust'],
                     { extraSids: ['S-1-5-9', B + '-1500'] });
  t.check(!has(r.sids, 'S-1-5-9') && has(r.sids, B + '-1500'),
          'SF-R14. a PIM trust lets this forest\'s SIDs back and filters ' +
          'Enterprise Domain Controllers', show2(r));
  r = await filtered([], { extraSids: [X + '-1600'] });
  t.check(has(r.sids, X + '-1600'),
          'SF-R15. an account SID (RID 1000 and above) of another domain ' +
          'is not filtered at an external boundary', show2(r));
  r = await filtered([], { resourceDomain: B, resourceGroups: [1700] });
  const keptRes = await filtered([], { resourceDomain: A,
                                       resourceGroups: [1700] });
  const quarantinedRes = await filtered(['quarantined'],
    { resourceDomain: C, resourceGroups: [1700] });
  t.check(r.resources.length === 0 && keptRes.resources.join() === '1700' &&
          quarantinedRes.resources.length === 0,
          'SF-R16. resource groups cross as the SIDs they are: this ' +
          'realm\'s filtered, the partner\'s kept, a third domain\'s not ' +
          'through a quarantined trust',
          [show2(r), show2(keptRes), show2(quarantinedRes)].join(' / '));
  r = await filtered(['quarantined'], { logonDomain: C });
  const forest = await filtered(['forest-transitive'], { logonDomain: X },
    { forestTrustInfo: { domains: [{ sid: A, dnsName: 'alpha.test',
                                     netbiosName: 'ALPHA' }] } });
  t.check(!!r.refused && /R17/.test(r.refused) && !!forest.refused,
          'SF-R17. a user of a domain the trust does not pass may not ' +
          'cross (quarantined; cross-forest outside the forest trust ' +
          'information) — an UNCERTAIN row', show2(r) + ' / ' + show2(forest));
  r = await filtered([], { device: true });
  t.check(!has(r.types, kpac.TYPE.DEVICE_INFO),
          'SF-R18. PAC_DEVICE_INFO does not cross a trust (dropped: it is ' +
          'not decoded here to be filtered — an UNCERTAIN row)', show2(r));
  r = await filtered([], { claims: true });
  const allowed = await filtered([], { claims: true },
                                 { claimsTransformation: 'allow-all' });
  t.check(!has(r.types, kpac.TYPE.CLIENT_CLAIMS) &&
          has(allowed.types, kpac.TYPE.CLIENT_CLAIMS),
          'SF-R19. claims entering with no transformation policy are ' +
          'dropped ([MS-ADTS] 3.1.1.11.2.11); allow-all keeps them',
          show2(r) + ' / ' + show2(allowed));
  r = await filtered(['within-forest'], { extraSids: [C + '-1500',
                                                      'S-1-5-11'] });
  t.check(r.boundary === 'WithinForest' && has(r.sids, C + '-1500') &&
          !has(r.sids, 'S-1-5-11'),
          'SF-R22. within the forest only AlwaysFilter and DomainSpecific ' +
          'apply', show2(r));
  r = await filtered(['cross-organization'], { extraSids: [] });
  t.check(has(r.sids, 'S-1-5-1000'),
          'SF-R24. a cross-organization trust adds OTHER_ORGANIZATION ' +
          '([MS-KILE] 3.3.5.7.5)', show2(r));
  inRealm(BETA, function () {
    return trusts.update(ALPHA, { attributes: [], forestTrustInfo: null,
                                  claimsTransformation: 'drop-all' });
  });

  // END TO END: alice's PAC from ALPHA, at a service of BETA.
  const audit = require('../common/audit');
  const helpers = require('../common/helpers');
  const filteredRows = function () {
    log.debug("Entering filteredRows().");
    log.debug("Leaving filteredRows().");
    return inRealm(BETA, function () {
      return audit.list().filter(function (row) {
        return row.action === 'krb5.trust.sid-filtered';
      });
    });
  };
  const rowsBefore = filteredRows().length;
  const tgt = await userTgt(t, ALPHA, 'alice');
  const referral = await wire.tgsExchange(T, tgt, spn('web', BETA), ALPHA);
  // THE SERVICE LOG IS WATCHED for the info line sidFilter() used to write.
  const infoLines = [];
  const realInfo = helpers.log.info;
  helpers.log.info = function () {
    const text = Array.prototype.slice.call(arguments).map(String).join(' ');
    if (/SID filtering/i.test(text)) {
      infoLines.push(text);
    }
    return realInfo.apply(helpers.log, arguments);
  };
  let svc;
  try {
    svc = referral.ok ?
      await wire.tgsExchange(T, referral, spn('web', BETA), BETA) : referral;
  } finally {
    helpers.log.info = realInfo;
  }
  const newRows = filteredRows().slice(0, filteredRows().length - rowsBefore);
  const row = newRows[0] || {};
  t.check(newRows.length === 1 && row.target === ALPHA &&
          row.actor === 'alice@' + ALPHA && row.protocol === 'Kerberos' &&
          /S-1-5-11/.test(String((row.detail || {}).removed)) &&
          /S-1-5-11/.test(String(row.summary)) &&
          !/key/i.test(JSON.stringify(row.detail || {})),
          'SF-A. the filtered ticket writes ONE audit row, ' +
          'krb5.trust.sid-filtered, naming the trust (' + ALPHA + '), the ' +
          'principal and the SIDs removed, and no key material',
          JSON.stringify(newRows));
  t.check(svc.ok && infoLines.length === 0,
          'SF-A2. and no info line in the service log', JSON.stringify(
            infoLines));
  if (svc.ok) {
    const part = await openTicket(BETA, svc.ticket, spn('web', BETA));
    const sids = sidsOf(logonOf(pacOf(part)));
    t.check(!has(sids, 'S-1-5-11') && has(sids, 'S-1-18-1'),
            'SF-R1-E2E. end to end: alice@' + ALPHA + '\'s Authenticated ' +
            'Users SID is filtered at ' + BETA + ', the asserted-identity ' +
            'SID kept', JSON.stringify(sids));
  } else {
    t.bad('SF-R1-E2E. no ticket at ' + BETA, show(svc));
  }

  // PRODUCT REFUSES A TRUST THAT DOES NOT FILTER SIDS (decision 4).
  realms.setOverride(IDS[BETA], 'global.mode', 'product');
  let p = await wire.tgsExchange(T, referral, spn('web', BETA), BETA);
  t.check(!!errorOf(p) && /SID filtering off/.test(errorOf(p).eText),
          'SF-P. in product, ' + BETA + ' does not honour its trust with ' +
          ALPHA + ' while it filters no SIDs (STS-KRB-0229)', show(p));
  realms.setOverride(IDS[BETA], 'krb5.requireSidFilteringInProduct',
                     'false');
  p = await wire.tgsExchange(T, referral, spn('web', BETA), BETA);
  t.check(!errorOf(p) || !/SID filtering off/.test(errorOf(p).eText),
          'SF-P2. with krb5.requireSidFilteringInProduct off on the realm, ' +
          'it does', show(p));
  realms.clearOverride(IDS[BETA], 'krb5.requireSidFilteringInProduct');
  realms.clearOverride(IDS[BETA], 'global.mode');
  log.debug("Leaving sidFilteringSection().");
}

async function run(t) {
  log.debug("Entering run().");
  setUp(t);
  try {
    await selfSection(t);
    await classicSection(t);
    await grantsSection(t);
    await rbcdSection(t);
    await forwardedSection(t);
    await stateSection(t);
    await sidFilteringSection(t);
    await chainSection(t);
    await evidenceSection(t);
  } finally {
    [ALPHA, BETA, GAMMA].forEach(function (name) {
      realms.remove(IDS[name]);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kerberos_cross_realm_delegation',
  describe: 'Kerberos delegation across a trust between trust realms of ' +
            'this service (#430): S4U2Self, classic and resource-based ' +
            'S4U2Proxy, the two in a chain, TGT delegation, the trust\'s ' +
            'state, and SID filtering row by row',
  run: run
};
