// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: kerberos_delegation.js
// ===========================================================================
// KERBEROS DELEGATION IS THE ONE DELEGATION POLICY (#186, 2026-10-03).
//
// S4U2Self is an IMPERSONATION by the service of itself, S4U2Proxy (classic
// or resource-based) a DELEGATION by the front end to the back end, and both
// are decided by the issuance policy from the common controls on the
// directory's entries — the same rules WS-Trust and the RFC 8693 token
// exchange are decided by. Driven here through `kdc.handleMessage()` with
// the local client `tests/vendored/krb5_wire.js`, in development mode,
// where the fixture services' rules are SEEDS for their entries:
//
//   A. S4U2SELF: forwardable for a service allowing impersonation, not for
//      one that does not, not for a protected user; PA-S4U-X509-USER by
//      name — answered in the reply — and refused with a bad checksum, the
//      wrong nonce, no user, and a certificate this realm did not issue.
//   B. S4U2PROXY: classic to the back end it names, refused to one it does
//      not (and the refusal names the entries' attributes); resource-based
//      with PA-PAC-OPTIONS and refused without; non-forwardable evidence
//      refused; a FORWARDABLE FLAG SET BY THE REQUESTER on its own evidence
//      (CVE-2020-17049) refused; EVIDENCE FORGED with the requester's key
//      refused; a protected user refused by the policy over resource-based
//      delegation, which needs no forwardable evidence.
//   C. FORWARDED TGTs and ok-as-delegate: a protected user's TGT is not
//      forwardable and cannot be forwarded; krb5TrustedForDelegation puts
//      ok-as-delegate on a service's tickets and its absence does not.
//   D. THE ENTRIES ARE THE TRUTH: the seeds are on them, and an edit to one
//      changes the very next answer; the act is on Monitoring → Delegation
//      and in its picture.
//
// IN PROCESS because the evidence ticket has to be opened and resealed with
// the front end's key, which only the inside holds. Refusals are enforced
// in BOTH modes at the KDC (rcbj, #186), so development is the mode here.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
require('../common/app');
require('../ldap/ldap_server');
const applications = require('../common/applications');
const principals = require('../kerberos/krb5_principals.js');
const kdc = require('../kerberos/krb5_kdc.js');
const kcrypto = require('../kerberos/krb5_crypto.js');
const wire = require('./vendored/krb5_wire.js');

const log = require('bunyan').createLogger({ name: 'kerberos_delegation',
  level: process.env.LOG_LEVEL || 'info' });

const msgs = wire.msgs;
const REALM = principals.REALM;
const DOMAIN = REALM.toLowerCase();
const T = {
  label: 'in-process',
  send: function (bytes) {
    log.debug("Entering send().");
    log.debug("Leaving send().");
    return kdc.handleMessage(bytes);
  }
};

function spn(host) {
  log.debug("Entering spn().");
  log.debug("Leaving spn().");
  return { type: 3, name: ['HTTP', host + '.' + DOMAIN] };
}

async function tgtOf(t, name, password) {
  log.debug("Entering tgtOf(). " + name);
  const got = await wire.asExchange(T, REALM, name, { password: password });
  t.check(!!got.tgt, 'precondition: a TGT for ' + name,
          JSON.stringify(got.second || got.first));
  log.debug("Leaving tgtOf().");
  return got.tgt;
}

// S4U2Self by `tgt` for `user`, by PA-FOR-USER.
function s4u2self(tgt, user) {
  log.debug("Entering s4u2self(). " + user);
  log.debug("Leaving s4u2self().");
  return wire.tgsExchange(T, tgt, tgt.client, REALM, {
    padata: async function () {
      return [await wire.paForUser(tgt, user, REALM)];
    }
  });
}

// S4U2Proxy by `tgt` with `evidence` to `target`.
function s4u2proxy(tgt, evidence, target, rbcd) {
  log.debug("Entering s4u2proxy().");
  log.debug("Leaving s4u2proxy().");
  return wire.tgsExchange(T, tgt, target, REALM, {
    kdcOptions: [msgs.KDC_OPTION.CNAME_IN_ADDL_TKT],
    additionalTickets: [evidence],
    padata: rbcd ? [wire.paPacOptionsRbcd()] : []
  });
}

function forwardable(r) {
  log.debug("Entering forwardable().");
  log.debug("Leaving forwardable().");
  return !!r.ok && r.flagNames.indexOf('forwardable') >= 0;
}

function refused(r, code) {
  log.debug("Entering refused().");
  log.debug("Leaving refused().");
  return !r.ok && r.error && r.error.code === code;
}

// Opens a service ticket with its service's key, lets `change` alter the
// enc-part, and seals it again — what a service holding its own key can do
// to an evidence ticket.
async function resealed(ticket, service, change) {
  log.debug("Entering resealed().");
  const principal = principals.find(service.name, REALM);
  const profile = kcrypto.etypeById(ticket.encPart.etype);
  const key = await principals.longTermKey(principal, ticket.encPart.etype);
  const part = msgs.readEncTicketPart(await profile.decrypt(key,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, ticket.encPart.cipher));
  change(part);
  const cipher = await profile.encrypt(key, kcrypto.KEY_USAGE.KDC_REP_TICKET,
                                       msgs.encEncTicketPart(part));
  // WITHOUT `raw`: the codec sends a parsed ticket's original bytes when it
  // has them, which would be the ticket before the change.
  const out = Object.assign({}, ticket, {
    encPart: Object.assign({}, ticket.encPart, { cipher: cipher }) });
  delete out.raw;
  log.debug("Leaving resealed().");
  return out;
}

async function selfSection(t, tgts) {
  log.debug("Entering selfSection().");
  t.log.info('=== A. S4U2Self ===');
  let r = await s4u2self(tgts.front, 'alice');
  t.check(forwardable(r), 'A1. S4U2Self by a service allowing impersonation ' +
          '(appDelegationSemantics, seeded from the fixture\'s ' +
          'TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION): FORWARDABLE',
          JSON.stringify(r.ok ? r.flagNames : String(r.error)));
  const evidence = r.ticket;
  r = await s4u2self(tgts.notrusted, 'alice');
  t.check(r.ok && !forwardable(r), 'A2. by one that does not: issued, NOT ' +
          'forwardable', JSON.stringify(r.ok ? r.flagNames : String(r.error)));
  const weakEvidence = r.ticket;
  r = await s4u2self(tgts.front, 'sensitive');
  t.check(r.ok && !forwardable(r), 'A3. for a protected user ' +
          '(stsNotDelegated): issued, NOT forwardable',
          JSON.stringify(r.ok ? r.flagNames : String(r.error)));
  const sensitiveEvidence = r.ticket;

  const x509 = function (user, corrupt) {
    log.debug("Entering x509().");
    log.debug("Leaving x509().");
    return wire.tgsExchange(T, tgts.front, tgts.front.client, REALM, {
      padata: async function (nonce) {
        return [await wire.paS4uX509User(tgts.front,
          Object.assign({ nonce: nonce, realm: REALM }, user), corrupt)];
      }
    });
  };
  r = await x509({ name: 'alice' });
  const answered = r.ok && r.replyPadata.some(function (pa) {
    return pa.type === msgs.PA_TYPE.S4U_X509_USER;
  });
  t.check(forwardable(r) && answered && r.client.name.join('/') === 'alice',
          'A4. PA-S4U-X509-USER by name: a forwardable ticket for alice, and ' +
          'the reply carries PA-S4U-X509-USER back', JSON.stringify(r.ok
            ? [r.flagNames, r.replyPadata.map(function (pa) {
              return pa.type;
            })] : String(r.error)));
  r = await x509({ name: 'alice' }, true);
  t.check(refused(r, 41) && /checksum/.test(r.error.eText),
          'A5. a PA-S4U-X509-USER checksum that does not verify: ' +
          'KRB_AP_ERR_MODIFIED (STS-KRB-0171)', String(r.error));
  r = await wire.tgsExchange(T, tgts.front, tgts.front.client, REALM, {
    padata: async function (nonce) {
      return [await wire.paS4uX509User(tgts.front,
        { nonce: nonce + 1, realm: REALM, name: 'alice' })];
    }
  });
  t.check(refused(r, 13) && /nonce/.test(r.error.eText),
          'A6. a nonce that is not the request\'s: KDC_ERR_BADOPTION ' +
          '(STS-KRB-0172)', String(r.error));
  r = await x509({});
  t.check(refused(r, 13) && /names no user/.test(r.error.eText),
          'A7. no name and no certificate: KDC_ERR_BADOPTION (STS-KRB-0175)',
          String(r.error));
  r = await x509({ certificate: new Uint8Array([0x30, 0x03, 0x02, 0x01,
                                                0x01]) });
  t.check(refused(r, 6), 'A8. a certificate this realm did not issue to a ' +
          'person: KDC_ERR_C_PRINCIPAL_UNKNOWN (STS-KRB-0173)',
          String(r.error));
  log.debug("Leaving selfSection().");
  return { evidence: evidence, weakEvidence: weakEvidence,
           sensitiveEvidence: sensitiveEvidence };
}

async function proxySection(t, tgts, ev) {
  log.debug("Entering proxySection().");
  t.log.info('=== B. S4U2Proxy ===');
  let r = await s4u2proxy(tgts.front, ev.evidence, spn('backend'));
  t.check(r.ok && r.client.name.join('/') === 'alice',
          'B1. classic: the front end\'s appAllowedToDelegateTo names the ' +
          'back end — a ticket to it as alice', String(r.error || ''));
  r = await s4u2proxy(tgts.front, ev.evidence, spn('web'));
  t.check(refused(r, 13) && /appAllowedToDelegateTo/.test(r.error.eText),
          'B2. to a back end nothing names: KDC_ERR_BADOPTION, the refusal ' +
          'naming the entries\' attributes (STS-KRB-0010)', String(r.error));
  r = await s4u2proxy(tgts.front, ev.evidence, spn('rbcd'), true);
  t.check(r.ok, 'B3. resource-based: the back end\'s ' +
          'appAllowedToActOnBehalfOf names the front end, with PA-PAC-OPTIONS',
          String(r.error || ''));
  r = await s4u2proxy(tgts.front, ev.evidence, spn('rbcd'), false);
  t.check(refused(r, 13) && /PA-PAC-OPTIONS/.test(r.error.eText),
          'B4. and without PA-PAC-OPTIONS: KDC_ERR_BADOPTION ' +
          '(STS-KRB-0011)', String(r.error));
  r = await s4u2proxy(tgts.notrusted, ev.weakEvidence, spn('backend'));
  t.check(refused(r, 13) && /not forwardable/.test(r.error.eText),
          'B5. classic with evidence that is not forwardable: ' +
          'KDC_ERR_BADOPTION (STS-KRB-0012)', String(r.error));
  // CVE-2020-17049: the requester sets the flag on its own evidence.
  const flipped = await resealed(ev.weakEvidence, spn('notrusted'),
    function (part) {
      if (part.flags.indexOf(msgs.TICKET_FLAG.FORWARDABLE) < 0) {
        part.flags.push(msgs.TICKET_FLAG.FORWARDABLE);
      }
    });
  r = await s4u2proxy(tgts.notrusted, flipped, spn('backend'));
  t.check(refused(r, 41) && /CVE-2020-17049/.test(r.error.eText),
          'B6. evidence whose forwardable flag the requester set itself ' +
          '(Bronze Bit): KRB_AP_ERR_MODIFIED (STS-KRB-0176)', String(r.error));
  // A forged evidence ticket: carol, named by the front end, with no PAC.
  const forged = await resealed(ev.evidence, spn('frontend'), function (part) {
    part.cname = { type: 1, name: ['carol'] };
    part.authorizationData = null;
  });
  r = await s4u2proxy(tgts.front, forged, spn('backend'));
  t.check(refused(r, 41) && /no PAC/.test(r.error.eText),
          'B7. evidence FORGED with the front end\'s own key: refused, ' +
          'nothing this KDC signed says who it is about (STS-KRB-0176)',
          String(r.error));
  r = await s4u2proxy(tgts.front, ev.sensitiveEvidence, spn('rbcd'), true);
  t.check(refused(r, 12) && /protected/.test(r.error.eText),
          'B8. a protected user over resource-based delegation — which needs ' +
          'no forwardable evidence — is refused by the issuance policy: ' +
          'KDC_ERR_POLICY (STS-KRB-0177)', String(r.error));
  log.debug("Leaving proxySection().");
}

async function forwardedSection(t, tgts) {
  log.debug("Entering forwardedSection().");
  t.log.info('=== C. forwarded TGTs and ok-as-delegate ===');
  t.check(tgts.alice.flagNames.indexOf('forwardable') >= 0 &&
          tgts.sensitive.flagNames.indexOf('forwardable') < 0,
          'C1. a protected user\'s TGT is not forwardable; anybody else\'s is',
          JSON.stringify([tgts.alice.flagNames, tgts.sensitive.flagNames]));
  const krbtgt = { type: 2, name: ['krbtgt', REALM] };
  let r = await wire.tgsExchange(T, tgts.alice, krbtgt, REALM,
    { kdcOptions: [msgs.KDC_OPTION.FORWARDED] });
  t.check(r.ok && r.flagNames.indexOf('forwarded') >= 0,
          'C2. alice\'s TGT is forwarded', String(r.error || ''));
  r = await wire.tgsExchange(T, tgts.sensitive, krbtgt, REALM,
    { kdcOptions: [msgs.KDC_OPTION.FORWARDED] });
  t.check(refused(r, 13), 'C3. the protected user\'s cannot be',
          String(r.error));
  r = await wire.tgsExchange(T, tgts.alice, spn('web'), REALM);
  t.check(r.ok && r.flagNames.indexOf('ok-as-delegate') >= 0,
          'C4. a ticket to a service carrying krb5TrustedForDelegation is ' +
          'ok-as-delegate', JSON.stringify(r.ok ? r.flagNames : r.error));
  r = await wire.tgsExchange(T, tgts.alice, spn('backend'), REALM);
  t.check(r.ok && r.flagNames.indexOf('ok-as-delegate') < 0,
          'C5. and to one without it, not — unconstrained delegation is off ' +
          'by default', JSON.stringify(r.ok ? r.flagNames : r.error));
  log.debug("Leaving forwardedSection().");
}

async function entriesSection(t, tgts, ev) {
  log.debug("Entering entriesSection().");
  t.log.info('=== D. the entries are the truth ===');
  const frontId = 'HTTP/frontend.' + DOMAIN + '@' + REALM;
  const backId = 'HTTP/backend.' + DOMAIN + '@' + REALM;
  const front = applications.get(frontId);
  const values = function (row, attribute) {
    log.debug("Entering values().");
    log.debug("Leaving values().");
    return [].concat((row && row.fields && row.fields[attribute]) || []);
  };
  t.check(values(front, 'appAllowedToDelegateTo').indexOf(backId) >= 0 &&
          values(front, 'appDelegationSemantics').indexOf('impersonation') >=
            0 && !!applications.get(backId),
          'D1. the fixture rules are SEEDS on the services\' entries — the ' +
          'back end has an entry too', JSON.stringify(front && front.fields));
  const removed = applications.updateApplication(frontId, {
    attribute: 'appAllowedToDelegateTo', mode: 'remove', value: backId });
  t.check(removed.ok, 'precondition: the rule is removed from the entry',
          JSON.stringify(removed));
  let r = await s4u2proxy(tgts.front, ev.evidence, spn('backend'));
  t.check(refused(r, 13), 'D2. an edit to the entry changes the very next ' +
          'answer: classic to the back end is refused', String(r.error));
  applications.updateApplication(frontId, {
    attribute: 'appAllowedToDelegateTo', mode: 'add', value: backId });
  r = await s4u2proxy(tgts.front, ev.evidence, spn('backend'));
  t.check(r.ok, 'D3. and restoring it allows it again', String(r.error || ''));
  const view = require('../admin-core/admin_views')
    .delegationView({ protocol: 'Kerberos v5' });
  const nodes = [].concat(view.graph.nodes || []);
  t.check(view.filtered.some(function (row) {
    return row.type === 'krb5-s4u2proxy-classic';
  }) && view.filtered.some(function (row) {
    return row.type === 'krb5-s4u2self';
  }) && nodes.some(function (one) {
    return (one.protocols || []).indexOf('Kerberos v5') >= 0 &&
           one.roles.intermediary > 0;
  }) && [].concat(view.graph.edges || []).length > 0,
          'D4. the Kerberos acts are on Monitoring → Delegation and in its ' +
          'picture', view.filtered.length + ' act(s), ' + nodes.length +
          ' node(s)');
  // #186: the CONFIGURED pairs are on the same picture, DASHED until an act
  // has crossed one (relation `may-delegate`, `used`).
  const configured = [].concat(view.graph.edges || []).filter(function (one) {
    return one.relation === 'may-delegate';
  });
  const keyOf = function (id) {
    log.debug("Entering keyOf().");
    log.debug("Leaving keyOf().");
    return require('../common/admin_stats').identityKeyOf(id);
  };
  const pairOf = function (from, to) {
    log.debug("Entering pairOf().");
    log.debug("Leaving pairOf().");
    return configured.filter(function (one) {
      return one.from === keyOf(from) && one.to === keyOf(to);
    })[0] || null;
  };
  const used = pairOf(frontId, backId);
  const unused = pairOf('HTTP/notrusted.' + DOMAIN + '@' + REALM, backId);
  t.check(!!used && used.used === true && !!unused && unused.used === false,
          'D4b. the configured pairs are drawn beside the acts: the one an ' +
          'act crossed solid, the one no act was issued across dashed',
          JSON.stringify(configured.map(function (one) {
            return [one.from, one.to, one.mechanism, one.used];
          })));
  const policy = principals.delegationPolicy();
  t.check(policy.pairs.some(function (one) {
    return one.frontEnd === frontId && one.target === backId &&
           one.attribute === 'appAllowedToDelegateTo';
  }) && policy.pairs.some(function (one) {
    return one.mechanism === 'rbcd' &&
           one.attribute === 'appAllowedToActOnBehalfOf';
  }), 'D5. the KDC\'s policy table is read off the entries',
          JSON.stringify(policy.pairs.map(function (one) {
            return [one.frontEnd, one.target, one.attribute];
          })));
  log.debug("Leaving entriesSection().");
}

async function run(t) {
  log.debug("Entering run().");
  const userPassword = String(config.value('krb5.userPassword'));
  const tgts = {
    front: await tgtOf(t, 'HTTP/frontend.' + DOMAIN,
                       'frontend-service-password'),
    notrusted: await tgtOf(t, 'HTTP/notrusted.' + DOMAIN,
                           'notrusted-service-password'),
    alice: await tgtOf(t, 'alice', userPassword),
    sensitive: await tgtOf(t, 'sensitive', userPassword)
  };
  if (!tgts.front || !tgts.notrusted || !tgts.alice || !tgts.sensitive) {
    log.debug("Leaving run(). No TGTs.");
    return;
  }
  const ev = await selfSection(t, tgts);
  await proxySection(t, tgts, ev);
  await forwardedSection(t, tgts);
  await entriesSection(t, tgts, ev);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kerberos_delegation',
  describe: 'Kerberos S4U2Self, S4U2Proxy, forwarded TGTs and ' +
            'PA-S4U-X509-USER decided by the one delegation policy, over ' +
            'the entries (#186)',
  run: run
};
