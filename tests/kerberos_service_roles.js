// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: kerberos_service_roles.js
// ===========================================================================
// A ROLE A KERBEROS SERVICE REQUIRES IS ENFORCED WHICHEVER NAME ITS ENTRY
// HAS (#747, item 2).
//
// A Kerberos service's application entry is named `SPN@REALM` by every door
// that makes one — the Management API's and the console's `create-service`,
// the TGS's own sighting (`applications.seen()`), the delegation seeds — and
// the KDC asked the issuance gate about the bare SPN. `requiredRolesOf()` has
// no realm fallback, so `appRequiredRole` on the entry those doors made was
// never read at the TGS: everybody was issued the ticket. Only an entry an
// operator had named by the bare SPN was enforced, which is why
// `tests/tools/cross_realm_grants.js` wrote every requirement under both
// names until this file existed.
//
// Two trust realms of this service, each with Kerberos on for a Kerberos
// realm of its own (KSA.TEST in ks-a, KSB.TEST in ks-b) and no trust between
// them, driven through `kdc.handleMessage()` with the suite's own client:
//
//   K1. the entry `HTTP/web.ksa.test@KSA.TEST` requires `web-staff`, held
//       by alice: bob is refused the service ticket at the TGS
//       (KDC_ERR_POLICY, the e-text naming the role) and alice is issued it.
//   K2. the entry named by the BARE SPN, `host/ws01.ksa.test`, requires
//       `ws-staff`: refused and issued exactly as before. With an entry
//       under `host/ws01.ksa.test@KSA.TEST` as well, requiring a role nobody
//       holds, the bare one still decides, as it did.
//   K3. ANOTHER REALM'S ENTRY DOES NOT APPLY: ks-b holding an entry named
//       `HTTP/frontend.ksa.test@KSA.TEST` that requires a role nobody holds
//       changes nothing at KSA.TEST; ks-b's own `HTTP/frontend.ksb.test@
//       KSB.TEST` requiring it refuses bob@KSB.TEST.
//   K4. THE AS EXCHANGE: a service ticket asked for at the AS
//       (`kinit -S HTTP/web.ksa.test`) is asked the same question — bob is
//       refused, alice issued — and a TGT is not asked about.
//   K5. UNDER S4U, WHOSE ROLE (#747 item 2): `krb5.s4uRoleSubject`. The
//       development fixtures HTTP/frontend.ksa.test (classic delegation to
//       HTTP/backend.ksa.test, impersonation allowed) and HTTP/rbcd.ksa.test
//       (accepting HTTP/frontend by RBCD) act for alice. Two roles:
//       `front-staff`, held by the front end's own principal name and by
//       nobody else, and `user-staff`, held by alice and not by the front
//       end. For S4U2Self (the requirement on the front end's own entry),
//       classic S4U2Proxy (on the back end's) and RBCD S4U2Proxy (on
//       rbcd's), under each value:
//         user (and the default, unset — rcbj's choice): user-staff
//                  issues, front-staff refuses — alice is asked, and the
//                  ticket issued names her;
//         service:  front-staff issues, user-staff refuses — the
//                  requesting service is asked, as d6ba88e1 did.
//       And under `user` (the default) an ordinary TGS request is unchanged: bob is still
//       refused HTTP/web.ksa.test and alice issued it.
//
// IN PROCESS because two Kerberos realms on one port is a shape no stack
// here publishes, and the refusal's e-text is the KDC's own words.
// INVENTED FIXTURES: the realm ids and names, the domain SIDs, and the roles
// `web-staff`, `ws-staff`, `no-one-holds-this`, `front-staff` and
// `user-staff`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
require('../common/app');
require('../ldap/ldap_server');
const realms = require('../common/realms');
const roles = require('../common/roles');
const applications = require('../common/applications');
const kdc = require('../kerberos/krb5_kdc.js');
const wire = require('./vendored/krb5_wire.js');
// ARMS `issuance_gate.js`'s decider, the PEP the KDC's role question goes
// to; without it every role question is answered "allowed — the XACML role
// subsystem is not loaded" (kerberos_cross_realm_delegation.js says why).
require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({
  name: 'kerberos_service_roles', level: process.env.LOG_LEVEL || 'info' });

const msgs = wire.msgs;
const T = {
  label: 'in-process',
  send: function (bytes) {
    log.debug("Entering send().");
    log.debug("Leaving send().");
    return kdc.handleMessage(bytes);
  }
};

const KSA = 'KSA.TEST';
const KSB = 'KSB.TEST';
const IDS = { 'KSA.TEST': 'ks-a', 'KSB.TEST': 'ks-b' };
const SID = { 'KSA.TEST': 'S-1-5-21-7471-7472-7473',
              'KSB.TEST': 'S-1-5-21-7481-7482-7483' };
const NOBODY = 'no-one-holds-this';

function inRealm(krbRealm, fn) {
  log.debug("Entering inRealm(). " + krbRealm);
  log.debug("Leaving inRealm().");
  return realms.run(realms.get(IDS[krbRealm]), fn);
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
                                      client: r.client, realm: r.realm })
                   : String(errorOf(r) || r);
}

// Whether a reply is the policy refusal: KDC_ERR_POLICY (12), the e-text
// naming the role the service requires.
function refusedFor(r, role) {
  log.debug("Entering refusedFor().");
  const e = errorOf(r);
  log.debug("Leaving refusedFor().");
  return !!e && e.code === 12 && String(e.eText).indexOf(role) >= 0;
}

// A role in a realm, held by the people named.
function grant(krbRealm, role, users) {
  log.debug("Entering grant(). " + role + " in " + krbRealm);
  const wrote = inRealm(krbRealm, function () {
    return roles.write(role, { description: 'Created by ' + __filename,
                               users: users });
  });
  log.debug("Leaving grant().");
  return wrote && wrote.ok ? [] : ['role ' + role + ': ' +
    JSON.stringify((wrote && (wrote.errors || wrote.why)) || '')];
}

// An application entry by exactly this identifier, in this realm, requiring
// exactly these roles: made if it is not there, its requirement replaced if
// it is.
function requireRoles(krbRealm, identifier, required) {
  log.debug("Entering requireRoles(). " + identifier);
  const errors = inRealm(krbRealm, function () {
    if (!applications.get(identifier)) {
      const made = applications.createApplication({
        identifier: identifier, kind: 'kerberos-service',
        protocols: ['krb5'], fields: { appRequiredRole: required },
        actor: __filename });
      return made && made.ok ? [] : [identifier + ': ' +
        JSON.stringify((made && made.errors) || [])];
    }
    const out = [];
    const held = (applications.get(identifier).fields || {}).appRequiredRole;
    (Array.isArray(held) ? held : (held ? [held] : []))
      .forEach(function (value) {
        const removed = applications.updateApplication(identifier, {
          attribute: 'appRequiredRole', mode: 'remove', value: value,
          actor: __filename });
        if (!removed || !removed.ok) {
          out.push(identifier + ' remove ' + value + ': ' +
                   JSON.stringify((removed && removed.errors) || []));
        }
      });
    required.forEach(function (value) {
      const set = applications.updateApplication(identifier, {
        attribute: 'appRequiredRole', mode: 'add', value: value,
        actor: __filename });
      if (!set || !set.ok) {
        out.push(identifier + ' ' + value + ': ' +
                 JSON.stringify((set && set.errors) || []));
      }
    });
    return out;
  });
  log.debug("Leaving requireRoles(). " + errors.length + " error(s).");
  return errors;
}

async function tgtOf(t, krbRealm, user) {
  log.debug("Entering tgtOf(). " + user + "@" + krbRealm);
  const got = await wire.asExchange(T, krbRealm, user,
    { password: String(config.value('krb5.userPassword')) });
  t.check(!!got.tgt, 'precondition: a TGT for ' + user + '@' + krbRealm,
          JSON.stringify(got.second || got.first));
  log.debug("Leaving tgtOf().");
  return got.tgt;
}

function sname(service, host, krbRealm) {
  log.debug("Entering sname().");
  log.debug("Leaving sname().");
  return { type: 3, name: [service, host + '.' + krbRealm.toLowerCase()] };
}

// THE AS EXCHANGE FOR A SERVICE TICKET: the suite's client always asks for
// krbtgt, so this transport re-encodes each AS-REQ with the service's name in
// `sname` — what `kinit -S <service>` sends.
function asFor(service) {
  log.debug("Entering asFor().");
  log.debug("Leaving asFor().");
  return {
    label: 'in-process, sname ' + service.name.join('/'),
    send: function (bytes) {
      log.debug("Entering asFor.send().");
      const req = msgs.readKdcReq(bytes);
      req.reqBody.sname = service;
      // The body's own bytes are what encKdcReq() would send back.
      delete req.reqBody.raw;
      log.debug("Leaving asFor.send().");
      return kdc.handleMessage(msgs.encKdcReq(req));
    }
  };
}

function setUp(t) {
  log.debug("Entering setUp().");
  [KSA, KSB].forEach(function (name) {
    realms.remove(IDS[name]);
    const made = realms.create({ id: IDS[name], name: IDS[name],
      description: 'Created by ' + __filename,
      overrides: { 'krb5.realm': name, 'krb5.domainSid': SID[name],
                   'krb5.enabled': 'true' } });
    t.check(made.ok, 'precondition: trust realm ' + IDS[name] + ' with ' +
            'Kerberos on for ' + name, JSON.stringify(made.errors || []));
  });
  const errors = []
    .concat(grant(KSA, 'web-staff', ['alice']))
    .concat(grant(KSA, 'ws-staff', ['alice']))
    .concat(requireRoles(KSA, 'HTTP/web.ksa.test@' + KSA, ['web-staff']))
    .concat(requireRoles(KSA, 'host/ws01.ksa.test', ['ws-staff']))
    .concat(requireRoles(KSB, 'HTTP/frontend.ksa.test@' + KSA, [NOBODY]))
    .concat(requireRoles(KSB, 'HTTP/frontend.ksb.test@' + KSB, [NOBODY]));
  t.check(!errors.length, 'precondition: the roles and the requirements ' +
          'written', JSON.stringify(errors));
  log.debug("Leaving setUp().");
}

async function tgsSection(t) {
  log.debug("Entering tgsSection().");
  t.log.info('=== K1-K3. the TGS ===');
  const alice = await tgtOf(t, KSA, 'alice');
  const bob = await tgtOf(t, KSA, 'bob');
  const web = sname('HTTP', 'web', KSA);
  let r = await wire.tgsExchange(T, bob, web, KSA);
  t.check(refusedFor(r, 'web-staff'),
          'K1. bob is REFUSED HTTP/web.ksa.test, whose entry HTTP/web.' +
          'ksa.test@' + KSA + ' requires web-staff: KDC_ERR_POLICY ' +
          '(STS-KRB-0039)', show(r));
  r = await wire.tgsExchange(T, alice, web, KSA);
  t.check(r.ok && r.client.name.join('/') === 'alice',
          'K1b. alice, who holds web-staff, is issued it', show(r));

  const ws = sname('host', 'ws01', KSA);
  r = await wire.tgsExchange(T, bob, ws, KSA);
  t.check(refusedFor(r, 'ws-staff'),
          'K2. an entry named by the BARE SPN, host/ws01.ksa.test, ' +
          'requiring ws-staff: bob is refused, as before', show(r));
  r = await wire.tgsExchange(T, alice, ws, KSA);
  t.check(r.ok, 'K2b. and alice is issued it', show(r));
  const both = requireRoles(KSA, 'host/ws01.ksa.test@' + KSA, [NOBODY]);
  t.check(!both.length, 'precondition: host/ws01.ksa.test@' + KSA +
          ' requires ' + NOBODY + ' as well', JSON.stringify(both));
  r = await wire.tgsExchange(T, alice, ws, KSA);
  t.check(r.ok, 'K2c. with an entry under both names, the bare one still ' +
          'decides: alice is issued it', show(r));

  const front = sname('HTTP', 'frontend', KSA);
  r = await wire.tgsExchange(T, bob, front, KSA);
  t.check(r.ok && r.client.name.join('/') === 'bob',
          'K3. ' + IDS[KSB] + '\'s entry named HTTP/frontend.ksa.test@' +
          KSA + ' does not apply in ' + IDS[KSA] + ': bob is issued it',
          show(r));
  const bobB = await tgtOf(t, KSB, 'bob');
  r = await wire.tgsExchange(T, bobB, sname('HTTP', 'frontend', KSB), KSB);
  t.check(refusedFor(r, NOBODY),
          'K3b. ' + IDS[KSB] + '\'s own HTTP/frontend.ksb.test@' + KSB +
          ' requiring ' + NOBODY + ' refuses bob@' + KSB, show(r));
  log.debug("Leaving tgsSection().");
}

async function asSection(t) {
  log.debug("Entering asSection().");
  t.log.info('=== K4. the AS exchange ===');
  const password = String(config.value('krb5.userPassword'));
  const web = sname('HTTP', 'web', KSA);
  let got = await wire.asExchange(asFor(web), KSA, 'bob',
                                  { password: password });
  const e = got.second && got.second.error;
  t.check(!!e && e.code === 12 && String(e.eText).indexOf('web-staff') >= 0,
          'K4. bob is REFUSED HTTP/web.ksa.test asked for at the AS ' +
          '(kinit -S): KDC_ERR_POLICY (STS-KRB-0039)',
          JSON.stringify(got.second || got.first));
  got = await wire.asExchange(asFor(web), KSA, 'alice',
                              { password: password });
  t.check(!!got.tgt && got.tgt.sname.name.join('/') === 'HTTP/web.ksa.test',
          'K4b. alice is issued it at the AS',
          JSON.stringify(got.second || got.first));
  log.debug("Leaving asSection().");
}

// The front end's TGT, from the development fixture's password.
async function frontTgt(t) {
  log.debug("Entering frontTgt().");
  const got = await wire.asExchange(T, KSA, 'HTTP/frontend.ksa.test',
    { password: 'frontend-service-password' });
  t.check(!!got.tgt, 'precondition: a TGT for HTTP/frontend.ksa.test@' + KSA,
          JSON.stringify(got.second || got.first));
  log.debug("Leaving frontTgt().");
  return got.tgt;
}

// S4U2Self by the front end for `user`.
function s4uSelf(tgt, user) {
  log.debug("Entering s4uSelf(). " + user);
  log.debug("Leaving s4uSelf().");
  return wire.tgsExchange(T, tgt, sname('HTTP', 'frontend', KSA), KSA, {
    padata: async function () {
      return [await wire.paForUser(tgt, user, KSA)];
    }
  });
}

// S4U2Proxy by the front end with `evidence` to `target`, classic or RBCD.
function s4uProxy(tgt, evidence, target, rbcd) {
  log.debug("Entering s4uProxy().");
  log.debug("Leaving s4uProxy().");
  return wire.tgsExchange(T, tgt, target, KSA, {
    kdcOptions: [msgs.KDC_OPTION.CNAME_IN_ADDL_TKT],
    additionalTickets: [evidence],
    padata: rbcd ? [wire.paPacOptionsRbcd()] : []
  });
}

function setSubject(value) {
  log.debug("Entering setSubject(). " + value);
  if (value) {
    realms.setOverride(IDS[KSA], 'krb5.s4uRoleSubject', value);
  } else {
    realms.clearOverride(IDS[KSA], 'krb5.s4uRoleSubject');
  }
  log.debug("Leaving setSubject().");
}

async function s4uSection(t) {
  log.debug("Entering s4uSection().");
  t.log.info('=== K5. under S4U, whose role: krb5.s4uRoleSubject ===');
  inRealm(KSA, function () {
    require('../kerberos/krb5_delegation').ensureSeeded();
  });
  const FRONT_ID = 'HTTP/frontend.ksa.test@' + KSA;
  const TARGETS = [
    { label: 'classic S4U2Proxy to HTTP/backend.ksa.test',
      id: 'HTTP/backend.ksa.test@' + KSA, sname: sname('HTTP', 'backend', KSA),
      rbcd: false },
    { label: 'RBCD S4U2Proxy to HTTP/rbcd.ksa.test',
      id: 'HTTP/rbcd.ksa.test@' + KSA, sname: sname('HTTP', 'rbcd', KSA),
      rbcd: true }
  ];
  const errors = []
    .concat(grant(KSA, 'front-staff', ['HTTP/frontend.ksa.test']))
    .concat(grant(KSA, 'user-staff', ['alice']))
    .concat(requireRoles(KSA, FRONT_ID, []))
    .concat(requireRoles(KSA, TARGETS[0].id, []))
    .concat(requireRoles(KSA, TARGETS[1].id, []));
  t.check(!errors.length, 'precondition: front-staff held by the front ' +
          'end, user-staff by alice, nothing required yet',
          JSON.stringify(errors));
  const tgt = await frontTgt(t);
  // The evidence, while the front end's own entry requires nothing.
  const evidence = await s4uSelf(tgt, 'alice');
  t.check(evidence.ok && evidence.client.name.join('/') === 'alice' &&
          (evidence.flagNames || []).indexOf('forwardable') >= 0,
          'precondition: S4U2Self gives the front end a forwardable ticket ' +
          'for alice', show(evidence) + ' ' +
          JSON.stringify(evidence.flagNames || []));
  const cases = [
    { value: '', subject: 'user', holds: 'user-staff',
      lacks: 'front-staff' },
    { value: 'service', subject: 'service', holds: 'front-staff',
      lacks: 'user-staff' },
    { value: 'user', subject: 'user', holds: 'user-staff',
      lacks: 'front-staff' }
  ];
  try {
    for (const c of cases) {
      setSubject(c.value);
      const named = 'krb5.s4uRoleSubject ' + (c.value || 'unset (default)');
      for (const target of TARGETS) {
        let wrote = requireRoles(KSA, target.id, [c.lacks]);
        t.check(!wrote.length, 'precondition: ' + target.id + ' requires ' +
                c.lacks, JSON.stringify(wrote));
        let r = await s4uProxy(tgt, evidence.ticket, target.sname,
                               target.rbcd);
        t.check(refusedFor(r, c.lacks),
                'K5. ' + named + ': ' + target.label + ' for alice, the ' +
                'target requiring ' + c.lacks + ', which the ' +
                (c.subject === 'user' ? 'user' : 'requesting service') +
                ' lacks: KDC_ERR_POLICY (STS-KRB-0039)', show(r));
        wrote = requireRoles(KSA, target.id, [c.holds]);
        t.check(!wrote.length, 'precondition: ' + target.id + ' requires ' +
                c.holds, JSON.stringify(wrote));
        r = await s4uProxy(tgt, evidence.ticket, target.sname, target.rbcd);
        t.check(r.ok && r.client.name.join('/') === 'alice',
                'K5b. ' + named + ': ' + target.label + ', the target ' +
                'requiring ' + c.holds + ', which the ' +
                (c.subject === 'user' ? 'user' : 'requesting service') +
                ' holds: issued, for alice', show(r));
        wrote = requireRoles(KSA, target.id, []);
        t.check(!wrote.length, 'precondition: ' + target.id + ' requires ' +
                'nothing again', JSON.stringify(wrote));
      }
      let wrote = requireRoles(KSA, FRONT_ID, [c.lacks]);
      t.check(!wrote.length, 'precondition: ' + FRONT_ID + ' requires ' +
              c.lacks, JSON.stringify(wrote));
      let r = await s4uSelf(tgt, 'alice');
      t.check(refusedFor(r, c.lacks),
              'K5c. ' + named + ': S4U2Self for alice, the front end\'s ' +
              'own entry requiring ' + c.lacks + ': KDC_ERR_POLICY', show(r));
      wrote = requireRoles(KSA, FRONT_ID, [c.holds]);
      t.check(!wrote.length, 'precondition: ' + FRONT_ID + ' requires ' +
              c.holds, JSON.stringify(wrote));
      r = await s4uSelf(tgt, 'alice');
      t.check(r.ok && r.client.name.join('/') === 'alice',
              'K5d. ' + named + ': S4U2Self for alice, requiring ' +
              c.holds + ': issued', show(r));
      wrote = requireRoles(KSA, FRONT_ID, []);
      t.check(!wrote.length, 'precondition: ' + FRONT_ID + ' requires ' +
              'nothing again', JSON.stringify(wrote));
    }
    setSubject('user');
    const web = sname('HTTP', 'web', KSA);
    let r = await wire.tgsExchange(T, await tgtOf(t, KSA, 'bob'), web, KSA);
    t.check(refusedFor(r, 'web-staff'),
            'K5e. krb5.s4uRoleSubject user leaves an ordinary TGS request ' +
            'alone: bob is still refused HTTP/web.ksa.test', show(r));
    r = await wire.tgsExchange(T, await tgtOf(t, KSA, 'alice'), web, KSA);
    t.check(r.ok, 'K5f. and alice is issued it', show(r));
  } finally {
    setSubject('');
  }
  log.debug("Leaving s4uSection().");
}

async function run(t) {
  log.debug("Entering run().");
  setUp(t);
  try {
    await tgsSection(t);
    await asSection(t);
    await s4uSection(t);
  } finally {
    [KSA, KSB].forEach(function (name) {
      realms.remove(IDS[name]);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kerberos_service_roles',
  describe: 'A role a Kerberos service requires (appRequiredRole) is ' +
            'enforced at the TGS and the AS whether its entry is named ' +
            'SPN@REALM or by the bare SPN, and only in its own realm; ' +
            'under S4U it is asked of the service or the user, as ' +
            'krb5.s4uRoleSubject says (#747)',
  run: run
};
