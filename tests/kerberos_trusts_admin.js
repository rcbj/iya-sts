// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: kerberos_trusts_admin.js
// ===========================================================================
// THE KERBEROS TRUSTS AS THE CONSOLE AND `/admin-api` MANAGE THEM (#430
// Phase 4).
//
// `admin-core/admin_actions.ts`'s `kerberosTrustsAction()` and
// `admin_views.ts`'s `kerberosTrustsJson()` — the two functions the Trusts
// tab of `/admin/kerberos` and `/admin-api/kerberos/trusts` both go through —
// driven in process, between two trust realms of this service (ALPHA.TEST,
// kta-a; BETA.TEST, kta-b), with the KDC answering through
// `kdc.handleMessage()`:
//
//   A. THE ACTS AND THE VIEW: add with a generated key (shown once, never in
//      the view), the health findings, update, a refused contradiction,
//      disable and enable, an unknown action, remove refused without its
//      confirmation and done with it, and the audit row naming the trust and
//      no key.
//   B. PAIRING: a trust-realm record with no partner record says so in its
//      health; Pair writes the other realm's record in one act, and a
//      ticket crosses; Pair again makes the keys match and creates nothing.
//   C. ROTATION WITH GRACE: a mirrored rotation moves both realms to the
//      next kvno; a referral under the new kvno is accepted, one issued
//      under the old kvno before the rotation is accepted inside
//      krb5.trustKeyGraceSeconds, and refused KRB_AP_ERR_BADKEYVER after.
//   D. WHO MAY: a realm administrator may rotate and remove their realm's
//      trusts and may not pair or rotate both sides
//      (`admin-ui/admin_scope.ts`).
//   E. THE APPLICATION PANEL: a resource-based delegation naming a foreign
//      front end, a classic target in another realm, krb5S4uSelfRealm and
//      TGT delegation, each read against the trusts.
//   F. THE TAB, drawn from the view by `kerberos/web_kerberos_trusts.ts`.
//
// IN PROCESS because tickets are opened with keys only the inside holds, and
// two Kerberos realms on one port is a shape no stack here publishes. The
// same acts over HTTP are `tests/protocol/sts_kerberos_trusts_api.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
require('../common/app');
require('../ldap/ldap_server');
const realms = require('../common/realms');
const audit = require('../common/audit');
const kdc = require('../kerberos/krb5_kdc.js');
const trusts = require('../kerberos/krb5_trusts');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
const adminScope = require('../admin-ui/admin_scope');
const WebKit = require('../admin-ui/web_kit');
const KerberosTrustsPage = require('../kerberos/web_kerberos_trusts');
const wire = require('./protocol/krb5_wire.js');
const grants = require('./tools/cross_realm_grants');

const log = require('bunyan').createLogger({
  name: 'kerberos_trusts_admin',
  level: process.env.LOG_LEVEL || 'info' });

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
const IDS = { 'ALPHA.TEST': 'kta-a', 'BETA.TEST': 'kta-b' };
const SIDS = { 'ALPHA.TEST': 'S-1-5-21-1101-1102-1103',
               'BETA.TEST': 'S-1-5-21-2101-2102-2103' };
const SHARED = 'a shared inter-realm trust password';

function inRealm(krbRealm, fn) {
  log.debug("Entering inRealm(). " + krbRealm);
  log.debug("Leaving inRealm().");
  return realms.run(realms.get(IDS[krbRealm]), fn);
}

function act(krbRealm, body) {
  log.debug("Entering act(). " + body.action);
  log.debug("Leaving act().");
  return inRealm(krbRealm, function () {
    return adminActions.kerberosTrustsAction(body,
      { actor: 'tests/kerberos_trusts_admin.js', via: 'api' });
  });
}

function view(krbRealm, query) {
  log.debug("Entering view().");
  log.debug("Leaving view().");
  return inRealm(krbRealm, function () {
    return adminViews.kerberosTrustsJson({ query: query || {} });
  });
}

function errorOf(r) {
  log.debug("Entering errorOf().");
  log.debug("Leaving errorOf().");
  return r && !r.ok && r.error ? r.error : null;
}

function kinds(row) {
  log.debug("Entering kinds().");
  log.debug("Leaving kinds().");
  return ((row && row.health) || []).map(function (one) {
    return one.kind;
  });
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function tgtIn(t, krbRealm, user) {
  log.debug("Entering tgtIn(). " + user + "@" + krbRealm);
  const got = await wire.asExchange(T, krbRealm, user,
    { password: String(config.value('krb5.userPassword')) });
  t.check(!!got.tgt, 'precondition: a TGT for ' + user + '@' + krbRealm,
          JSON.stringify(got.second || got.first));
  log.debug("Leaving tgtIn().");
  return got.tgt;
}

// ALPHA's referral for a service of BETA: a TGT for krbtgt/BETA@ALPHA.
async function referral(t) {
  log.debug("Entering referral().");
  const tgt = await tgtIn(t, ALPHA, 'alice');
  const r = tgt ? await wire.tgsExchange(T, tgt,
    { type: 3, name: ['HTTP', 'web.beta.test'] }, ALPHA) : null;
  log.debug("Leaving referral().");
  return r;
}

// BETA's service ticket for that referral.
function across(ref) {
  log.debug("Entering across().");
  log.debug("Leaving across().");
  return wire.tgsExchange(T, ref, { type: 3, name: ['HTTP',
                                                    'web.beta.test'] },
                          BETA);
}

function setUp(t) {
  log.debug("Entering setUp().");
  [ALPHA, BETA].forEach(function (name) {
    realms.remove(IDS[name]);
    const made = realms.create({ id: IDS[name], name: IDS[name],
      description: 'Created by ' + __filename,
      overrides: { 'krb5.realm': name, 'krb5.domainSid': SIDS[name],
                   'krb5.enabled': 'true' } });
    t.check(made.ok, 'precondition: trust realm ' + IDS[name] + ' with ' +
            'Kerberos on for ' + name, JSON.stringify(made.errors || []));
  });
  // A principal of another realm holds only what it was granted (#430,
  // rcbj 2026-10-19): BETA admits ALPHA's principals to its web service.
  const admitted = grants.admitPartners(realms.get(IDS[BETA]), [SIDS[ALPHA]],
                                        ['HTTP/web.beta.test'], BETA);
  t.check(!admitted.length, 'precondition: ' + BETA + ' grants ' +
          grants.ROLE + ' to ' + ALPHA + '\'s Domain Users and its web ' +
          'service requires it', JSON.stringify(admitted));
  log.debug("Leaving setUp().");
}

// ---------------------------------------------------------------------------
// A. THE ACTS AND THE VIEW.
// ---------------------------------------------------------------------------
function actsSection(t) {
  log.debug("Entering actsSection().");
  t.log.info('=== A. the acts and the view ===');
  const added = act(ALPHA, { action: 'add', partnerRealm: 'EXT.EXAMPLE',
    direction: 'bidirectional', keySource: 'generate',
    attributes: ['quarantined'], suffixes: 'ext.example, svc.ext.example' });
  const shownKeys = added.ok && added.shown
    ? Object.keys(added.shown.incoming || {}).map(function (etype) {
        return added.shown.incoming[etype];
      }) : [];
  t.check(added.ok && added.trust.partnerRealm === 'EXT.EXAMPLE' &&
          added.trust.direction === 'bidirectional' && shownKeys.length > 0,
          'A1. add with keySource generate writes the record and answers ' +
          'the generated keys ONCE in shown',
          JSON.stringify(added.errors || added.trust));
  const listed = view(ALPHA);
  const row = (listed.trusts || []).filter(function (one) {
    return one.partnerRealm === 'EXT.EXAMPLE';
  })[0];
  const text = JSON.stringify(listed);
  t.check(!!row && row.incoming.held && row.outgoing.held &&
          row.incoming.kvno === 1 && row.incoming.source === 'generated' &&
          shownKeys.every(function (key) {
            return text.indexOf(key) === -1;
          }) && text.indexOf(SHARED) === -1,
          'A2. the view lists it with each key described (held, kvno, ' +
          'source) and carries no key', JSON.stringify(row));
  t.check(!!row && kinds(row).indexOf('incomingHeld') >= 0 &&
          kinds(row).indexOf('routed') >= 0 &&
          kinds(row).indexOf('unfiltered') < 0 &&
          !!row.lastKeyChangeAt && listed.trustsPaging.total >= 1,
          'A3. its health: incoming key held, the suffixes routed, and no ' +
          'quarantine warning; the last key change and the paging are there',
          JSON.stringify(row && row.health));
  let r = act(ALPHA, { action: 'update', partnerRealm: 'EXT.EXAMPLE',
                       attributes: ['non-transitive'] });
  const updated = view(ALPHA, { trust: 'EXT.EXAMPLE' }).trust;
  t.check(r.ok && updated && updated.attributes.join() === 'non-transitive' &&
          kinds(updated).indexOf('unfiltered') >= 0 &&
          updated.incoming.kvno === 1,
          'A4. update changes the attributes and keeps the keys; the ' +
          'drill-down (?trust=) now warns that it is not quarantined',
          JSON.stringify(r.errors || updated));
  r = act(ALPHA, { action: 'update', partnerRealm: 'EXT.EXAMPLE',
                   attributes: ['no-tgt-delegation',
                                'enable-tgt-delegation'] });
  t.check(!r.ok && /cannot both be set/.test((r.errors || []).join(' ')),
          'A5. a contradiction is refused, naming both bits (STS-KRB-0217)',
          JSON.stringify(r.errors));
  r = act(ALPHA, { action: 'disable', partnerRealm: 'EXT.EXAMPLE' });
  const off = view(ALPHA, { trust: 'EXT.EXAMPLE' }).trust;
  t.check(r.ok && off.enabled === false &&
          kinds(off).indexOf('disabled') >= 0 && off.incoming.held,
          'A6. disable turns it off and keeps its keys; health says disabled',
          JSON.stringify(off));
  r = act(ALPHA, { action: 'enable', partnerRealm: 'EXT.EXAMPLE' });
  t.check(r.ok && view(ALPHA, { trust: 'EXT.EXAMPLE' }).trust.enabled,
          'A7. enable turns it back on', JSON.stringify(r.errors || []));
  r = act(ALPHA, { action: 'frobnicate', partnerRealm: 'EXT.EXAMPLE' });
  t.check(!r.ok && /There are seven/.test((r.errors || []).join(' ')),
          'A8. an unknown action is refused naming the seven',
          JSON.stringify(r.errors));
  r = act(ALPHA, { action: 'remove', partnerRealm: 'EXT.EXAMPLE',
                   confirm: 'yes' });
  t.check(!r.ok && !!view(ALPHA, { trust: 'EXT.EXAMPLE' }).trust,
          'A9. remove without the partner realm typed in confirm is ' +
          'refused and removes nothing (STS-ADMIN-0860)',
          JSON.stringify(r.errors));
  r = act(ALPHA, { action: 'remove', partnerRealm: 'EXT.EXAMPLE',
                   confirm: 'EXT.EXAMPLE' });
  const gone = view(ALPHA, { trust: 'EXT.EXAMPLE' });
  t.check(r.ok && !gone.trust && gone.unknownTrust === 'EXT.EXAMPLE',
          'A10. remove with it removes the record; the drill-down then ' +
          'names the trust as unknown', JSON.stringify(gone.unknownTrust));
  // The realm's own audit log: a trust realm's acts are recorded in it.
  const rows = inRealm(ALPHA, function () {
    return audit.list();
  }).filter(function (one) {
    return /^krb5\.trust\./.test(String(one.action || '')) &&
           one.target === 'EXT.EXAMPLE';
  });
  const rowsText = JSON.stringify(rows);
  t.check(rows.length >= 5 && shownKeys.every(function (key) {
    return rowsText.indexOf(key) === -1;
  }), 'A11. every act wrote an audit row naming the trust and carrying ' +
      'no key', rows.length + ' row(s)');
  log.debug("Leaving actsSection().");
}

// ---------------------------------------------------------------------------
// B. PAIRING.
// ---------------------------------------------------------------------------
async function pairSection(t) {
  log.debug("Entering pairSection().");
  t.log.info('=== B. pairing ===');
  let r = act(ALPHA, { action: 'add', partnerRealm: BETA,
    type: 'trust-realm', partnerTrustRealm: IDS[BETA],
    direction: 'bidirectional', keySource: 'password', password: SHARED,
    attributes: ['quarantined'], suffixes: 'beta.test' });
  const lonely = view(ALPHA, { trust: BETA }).trust;
  t.check(r.ok && lonely && kinds(lonely).indexOf('unpaired') >= 0,
          'B1. a trust-realm record whose partner holds none for this ' +
          'realm says so in its health', JSON.stringify(r.errors ||
                                                        lonely.health));
  r = act(ALPHA, { action: 'pair', partnerRealm: BETA });
  const there = view(BETA, { trust: ALPHA }).trust;
  t.check(r.ok && r.created === true && !!there &&
          there.direction === 'bidirectional' &&
          there.incoming.kvno === 1 && there.outgoing.kvno === 1 &&
          kinds(view(ALPHA, { trust: BETA }).trust).indexOf('paired') >= 0,
          'B2. Pair writes the matching record on ' + IDS[BETA] + ' in one ' +
          'act, its keys the other way round; ALPHA\'s health now says ' +
          'paired', JSON.stringify(r.errors || there));
  const ref = await referral(t);
  const svc = ref && ref.ok ? await across(ref) : null;
  t.check(!!svc && svc.ok && svc.client.name.join('/') === 'alice',
          'B3. and a ticket crosses: ' + BETA + ' issues HTTP/web.beta.test ' +
          'to alice@' + ALPHA + ' on ' + ALPHA + '\'s referral',
          JSON.stringify(errorOf(svc) || errorOf(ref)));
  r = act(ALPHA, { action: 'pair', partnerRealm: BETA });
  t.check(r.ok && r.created === false,
          'B4. Pair again makes the keys match and creates nothing',
          JSON.stringify(r.errors || r.created));
  log.debug("Leaving pairSection().");
}

// ---------------------------------------------------------------------------
// C. ROTATION WITH GRACE.
// ---------------------------------------------------------------------------
async function rotationSection(t) {
  log.debug("Entering rotationSection().");
  t.log.info('=== C. rotation with grace ===');
  const before = await referral(t);
  t.check(!!before && before.ok,
          'precondition: a referral issued under kvno 1',
          JSON.stringify(errorOf(before)));
  const r = act(ALPHA, { action: 'rotate-key', partnerRealm: BETA,
                         keySource: 'generate', mirror: true });
  const here = view(ALPHA, { trust: BETA }).trust;
  const there = view(BETA, { trust: ALPHA }).trust;
  t.check(r.ok && !!r.there && !!r.shown &&
          here.incoming.kvno === 2 && here.outgoing.kvno === 2 &&
          there.incoming.kvno === 2 && there.outgoing.kvno === 2 &&
          there.incoming.previous && there.incoming.previous.kvno === 1 &&
          !!there.incoming.previous.acceptedUntil &&
          here.incoming.source === 'generated',
          'C1. a mirrored rotation moves BOTH realms to kvno 2, generated ' +
          'keys shown once, and each keeps incoming kvno 1 for its grace',
          JSON.stringify(r.errors || { here: here.incoming,
                                      there: there.incoming }));
  const after = await referral(t);
  let svc = after && after.ok ? await across(after) : null;
  t.check(!!after && after.ok && after.ticket.encPart.kvno === 2 &&
          !!svc && svc.ok,
          'C2. a referral issued now is under kvno 2, and ' + BETA +
          ' accepts it', JSON.stringify(errorOf(svc) || errorOf(after)));
  svc = await across(before);
  t.check(!!svc && svc.ok,
          'C3. the referral issued under kvno 1 BEFORE the rotation is ' +
          'still accepted inside the grace (by default the ticket lifetime ' +
          'plus the clock skew)', JSON.stringify(errorOf(svc)));
  realms.setOverride(IDS[BETA], 'krb5.trustKeyGraceSeconds', '1');
  await sleep(1600);
  svc = await across(before);
  t.check(!!errorOf(svc) && errorOf(svc).code === 44,
          'C4. past krb5.trustKeyGraceSeconds the kvno-1 referral is ' +
          'refused KRB_AP_ERR_BADKEYVER', JSON.stringify(errorOf(svc) ||
                                                        'accepted'));
  t.check(!view(BETA, { trust: ALPHA }).trust.incoming.previous,
          'C5. and the view no longer lists a previous version', '');
  svc = await across(after);
  t.check(!!svc && svc.ok, 'C6. while the kvno-2 referral is still ' +
          'accepted', JSON.stringify(errorOf(svc)));
  realms.clearOverride(IDS[BETA], 'krb5.trustKeyGraceSeconds');
  const one = act(BETA, { action: 'rotate-key', partnerRealm: ALPHA,
                          side: 'incoming', keySource: 'password',
                          password: 'another shared trust password' });
  t.check(one.ok && !one.there &&
          view(BETA, { trust: ALPHA }).trust.incoming.kvno === 3 &&
          view(ALPHA, { trust: BETA }).trust.outgoing.kvno === 2,
          'C7. without mirror only this realm\'s side moves: ' + BETA +
          '\'s incoming key is kvno 3 and ' + ALPHA + '\'s outgoing is ' +
          'still kvno 2', JSON.stringify(one.errors || []));
  svc = await across(after);
  t.check(!!svc && svc.ok, 'C8. and ' + ALPHA + '\'s kvno-2 referral ' +
          'is still accepted, inside the grace of the version it replaced',
          JSON.stringify(errorOf(svc)));
  const nosource = act(ALPHA, { action: 'rotate-key', partnerRealm: BETA });
  t.check(!nosource.ok, 'C9. a rotation with no key source is refused ' +
          '(STS-KRB-0241)', JSON.stringify(nosource.errors));
  log.debug("Leaving rotationSection().");
}

// ---------------------------------------------------------------------------
// D. WHO MAY.
// ---------------------------------------------------------------------------
function scopeSection(t) {
  log.debug("Entering scopeSection().");
  t.log.info('=== D. who may ===');
  const state = { authority: 'realm', identityRealm: IDS[ALPHA] };
  const refusal = function (body) {
    return adminScope.refusalFor(state, '/admin/kerberos/trusts', body, {});
  };
  t.check(!refusal({ action: 'rotate-key', partnerRealm: BETA }) &&
          !refusal({ action: 'remove', partnerRealm: BETA }) &&
          !refusal({ action: 'add', partnerRealm: 'X.EXAMPLE' }),
          'D1. a realm administrator may add, rotate and remove their ' +
          'realm\'s trusts', '');
  const pair = refusal({ action: 'pair', partnerRealm: BETA });
  const mirrored = refusal({ action: 'rotate-key', partnerRealm: BETA,
                             mirror: true });
  t.check(!!pair && pair.code === 'STS-ADMIN-0787' && !!mirrored &&
          mirrored.code === 'STS-ADMIN-0787',
          'D2. and may not pair, or rotate both sides: each writes the ' +
          'partner trust realm\'s record (STS-ADMIN-0787)',
          JSON.stringify([pair, mirrored]));
  t.check(!adminScope.refusalFor({ authority: 'service' },
                                 '/admin/kerberos/trusts',
                                 { action: 'pair' }, {}),
          'D3. a service administrator may', '');
  log.debug("Leaving scopeSection().");
}

// ---------------------------------------------------------------------------
// E. THE APPLICATION PANEL.
// ---------------------------------------------------------------------------
function panelSection(t) {
  log.debug("Entering panelSection().");
  t.log.info('=== E. the application panel ===');
  const attributes = {
    appAllowedToActOnBehalfOf: ['HTTP/frontend.alpha.test@' + ALPHA,
                                'HTTP/x.nowhere.test@NOWHERE.TEST'],
    appAllowedToDelegateTo: ['HTTP/backend.alpha.test@' + ALPHA],
    krb5S4uSelfRealm: [ALPHA],
    krb5TrustedForDelegation: ['TRUE']
  };
  let a = inRealm(BETA, function () {
    return trusts.applicationAcross(attributes);
  });
  const front = a.frontEnds.filter(function (one) {
    return one.realm === ALPHA;
  })[0];
  const nowhere = a.frontEnds.filter(function (one) {
    return one.realm === 'NOWHERE.TEST';
  })[0];
  t.check(!!front && front.ok && front.path.join() === ALPHA &&
          !!nowhere && !nowhere.ok &&
          nowhere.problems[0].kind === 'missing',
          'E1. a foreign front end through a usable trust is ready, with ' +
          'its path; one from a realm no trust reaches says so',
          JSON.stringify(a.frontEnds));
  t.check(a.targets.length === 1 && a.targets[0].classicRefused &&
          a.targets[0].classicProblems.some(function (one) {
            return one.kind === 'classicOffHere';
          }),
          'E2. a classic target in another realm is flagged refused while ' +
          'krb5.crossRealmClassicDelegation is off', JSON.stringify(a.targets));
  t.check(a.selfRealms.length === 1 && a.selfRealms[0].accepted &&
          a.choices.krb5S4uSelfRealm.indexOf(ALPHA) >= 0,
          'E3. krb5S4uSelfRealm names a realm a trust accepts, and the ' +
          'field\'s choices are the realms the trusts accept',
          JSON.stringify([a.selfRealms, a.choices]));
  t.check(a.tgtDelegation.unconstrained &&
          a.tgtDelegation.trusts.length === 1 &&
          a.tgtDelegation.trusts[0].allowed === false &&
          a.tgtDelegation.trusts[0].delivered === false,
          'E4. trusted for delegation, but the quarantined trust allows no ' +
          'TGT delegation, so none is delivered from ' + ALPHA,
          JSON.stringify(a.tgtDelegation));
  inRealm(BETA, function () {
    return trusts.setEnabled(ALPHA, false);
  });
  a = inRealm(BETA, function () {
    return trusts.applicationAcross(attributes);
  });
  t.check(a.frontEnds[0].problems.some(function (one) {
    return one.kind === 'disabled';
  }), 'E5. with the trust disabled the front end says so',
          JSON.stringify(a.frontEnds[0]));
  inRealm(BETA, function () {
    return trusts.setEnabled(ALPHA, true);
  });
  log.debug("Leaving panelSection().");
}

// ---------------------------------------------------------------------------
// F. THE TAB.
// ---------------------------------------------------------------------------
function tabSection(t) {
  log.debug("Entering tabSection().");
  t.log.info('=== F. the tab ===');
  const json = view(ALPHA, { trust: BETA });
  const html = KerberosTrustsPage.body(WebKit.context({ trust: BETA }, true),
                                       json);
  t.check(html.indexOf('id="kerberos-trusts"') >= 0 &&
          html.indexOf('<code>' + BETA + '</code>') >= 0 &&
          /name="action" value="add"/.test(html) &&
          /name="action" value="update"/.test(html) &&
          /name="action" value="rotate-key"/.test(html) &&
          /name="action" value="remove"/.test(html) &&
          /name="action" value="pair"/.test(html) &&
          /name="action" value="disable"/.test(html) &&
          /action="\/admin\/kerberos\/trusts"/.test(html),
          'F1. the tab draws the table, the drill-down and every control, ' +
          'each posting to /admin/kerberos/trusts', html.length + ' chars');
  const read = KerberosTrustsPage.body(WebKit.context({}, false), json);
  t.check(!/name="action"/.test(read) && /Admin Write/.test(read),
          'F2. without Admin Write it draws no control', '');
  log.debug("Leaving tabSection().");
}

async function run(t) {
  log.debug("Entering run().");
  setUp(t);
  try {
    actsSection(t);
    await pairSection(t);
    await rotationSection(t);
    scopeSection(t);
    panelSection(t);
    tabSection(t);
  } finally {
    [ALPHA, BETA].forEach(function (name) {
      realms.remove(IDS[name]);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kerberos_trusts_admin',
  describe: 'Kerberos trusts as the console and /admin-api manage them ' +
            '(#430 Phase 4): the acts and the view, pairing, rotation with ' +
            'grace, who may, the application panel and the tab',
  run: run
};
