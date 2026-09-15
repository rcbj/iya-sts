'use strict';
//
// File: kerberos_product_mode.js
//
// ===========================================================================
// WHAT THE KERBEROS FAMILY HARD-CODED, AND WHAT IT DOES NOW IN EACH MODE.
//
// An audit on 2026-09-12 found the principal database, the KDC and the
// acceptor carrying literals no mode could reach: seven fixture service
// passwords, a user table with fixed RIDs, delegation rules that were always
// on, RC4 always offered, a kvno of 3 for every account, two ticket lifetimes,
// three buffer caps, a PAC with an invented `passwordLastSet` and `logonCount`,
// an acceptor looking for `krb5.servicePrincipal` while its account was always
// created as `HTTP/web.<domain>`, a `/krb5/principals` that published two
// passwords to anybody, and a replay cache that FORGOT an Authenticator still
// inside its window when it filled up.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, which is the question tests/CLAUDE.md asks first.
//
// Two reasons, and each section says which it rests on.
//
//   * **The principal database is built at REQUIRE TIME, in the mode the
//     process starts in.** No running service can be asked what a product-mode
//     database holds without starting a product-mode service, and the suite's
//     stacks all run development mode. So those sections start a CHILD node
//     process with `STS_MODE=product` and read the database it built — no port,
//     no container.
//   * **The replay-cache defect is unreachable over HTTP in any useful time.**
//     Proving an Authenticator is not evicted takes a cache FULL of in-window
//     entries; over a socket that is ten thousand valid AP-REQs. In process the
//     cap is a runtime setting and the cache is exported, so it takes a
//     hundred.
//
// The AP-REQs below are built here, against the acceptor's own key, with the
// vendored codec — the same shape `tests/vendored/krb5_drive.js` sends — so the
// acceptor runs every one of its checks rather than a stub of them.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: nothing
// here should depend on a developer's exported appconfig.
delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const config = require('../common/config');
const principals = require('../kerberos/krb5_principals.js');
const krb5Service = require('../kerberos/krb5_service.js');
const msgs = require('../kerberos/krb5_messages.js');
const kcrypto = require('../kerberos/krb5_crypto.js');
const gss = require('../kerberos/krb5_gss.js');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'kerberos_product_mode',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// A CHILD PROCESS THAT BUILDS A DATABASE AND REPORTS IT. `env` is layered over
// a clean environment for this service's settings, so a developer's exported
// KRB5_* variables cannot make a section pass for the wrong reason.
// ---------------------------------------------------------------------------
function inAChild(env, body) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'krb5-product-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const script =
    'delete process.env.CONFIG_FILE;' +
    'const p = require(' +
    JSON.stringify(path.join(ROOT, 'kerberos/krb5_principals.js')) +
    ');const ' +
    'report = (function () {' + body + '})();' +
    'require("fs").writeFileSync(' + JSON.stringify(out) + ', ' +
    'JSON.stringify(report));process.exit(0);';
  const result = childProcess.spawnSync(process.execPath, ['-e', script], {
    env: Object.assign(clean, { LOG_LEVEL: 'fatal' }, env),
    encoding: 'utf8', timeout: 60000
  });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child exited before writing one, which is what the
    // refusal sections expect and what every other section reports as a
    // failure through `status` and `stderr` below.
    report = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  log.debug("Leaving inAChild().");
  return { status: result.status, stdout: result.stdout || '',
           stderr: result.stderr || '', report: report };
}

const SUMMARY = 'return { demo: p.seedsDemoPrincipals, served: ' +
  'p.realmsServed(), service: p.serviceAccount(), krbtgt: ' +
  'p.krbtgtUnavailableReason(), etypes: p.KDC_ETYPES, all: ' +
  'p.all().map(function (x) { return { name: x.name.join("/") + "@" + ' +
  'x.realm, password: x.password, salt: x.salt, okAsDelegate: ' +
  'x.okAsDelegate, kvno: x.kvno, etypes: p.supportedEtypes(x), delegateTo: ' +
  'x.allowedToDelegateTo, actOnBehalf: x.allowedToActOnBehalfOf }; }) };';

function names(report) {
  log.debug("Entering names().");
  log.debug("Leaving names().");
  return (report && report.all || []).map(function (one) { return one.name; });
}

// ---------------------------------------------------------------------------
// 1. PRODUCT MODE CREATES NO FIXTURE, AND REFUSES THE PUBLISHED PASSWORDS.
// ---------------------------------------------------------------------------
function productModeHoldsNoFixtures(t) {
  log.debug("Entering productModeHoldsNoFixtures().");
  t.log.info('=== product mode: no fixture accounts, no published passwords ' +
             '===');
  const bare = inAChild({ STS_MODE: 'product' }, SUMMARY);
  t.check(bare.report !== null, 'a product-mode principal database builds',
          'exit ' + bare.status + ': ' + bare.stderr.slice(0, 400));
  if (!bare.report) {
    log.debug("Leaving productModeHoldsNoFixtures().");
    return;
  }
  t.equal(bare.report.all.length, 0,
          'with the shipped krbtgt and service passwords, the database holds ' +
          'NOTHING — both are printed in this repository');
  t.check(/krb5\.krbtgtPassword/.test(bare.report.krbtgt),
          'the krbtgt refusal names the setting that fixes it',
          bare.report.krbtgt);
  t.check(bare.report.service.available === false &&
          /krb5\.servicePassword/.test(bare.report.service.reason),
          'the service account refusal names krb5.servicePassword',
          JSON.stringify(bare.report.service));
  t.check(JSON.stringify(bare.report.served) === JSON.stringify(
      [principals.REALM]),
          'and the trusted realm is not served — its krbtgt, user and trust ' +
          'are fixtures',
          JSON.stringify(bare.report.served));

  const configured = inAChild({ STS_MODE: 'product',
                                KRB5_KRBTGT_PASSWORD: 'not-the-published-one',
                                KRB5_SERVICE_PASSWORD: 'the-keytab-secret',
                                KRB5_SERVICE_SALT: 'EXAMPLE.COMsvc-web' },
                              SUMMARY);
  t.check(configured.report !== null, 'a configured product database builds',
          configured.stderr.slice(0, 400));
  if (!configured.report) {
    log.debug("Leaving productModeHoldsNoFixtures().");
    return;
  }
  t.check(JSON.stringify(names(configured.report)) ===
          JSON.stringify(['krbtgt/' + principals.REALM + '@' + principals.REALM,
                          'HTTP/web.example.com@' + principals.REALM]),
          'with both set it holds krbtgt and the configured service account, ' +
          'and nothing else',
          JSON.stringify(names(configured.report)));
  const web = configured.report.all[1] || {};
  t.check(web.password === 'the-keytab-secret' &&
          web.salt === 'EXAMPLE.COMsvc-web',
          'the service account takes krb5.servicePassword and krb5.serviceSalt',
          JSON.stringify(web));
  t.check(web.okAsDelegate === false,
          'and is NOT flagged ok-as-delegate — that is advice to forward ' +
          'TGTs, and a product deployment says so in its own KDC',
          JSON.stringify(web));
  t.check(configured.report.all.every(function (one) {
    return !one.delegateTo.length && !one.actOnBehalf.length;
  }), 'no delegation rule exists that nobody configured');
  t.check(configured.report.all.every(function (one) {
    return !/-service-password$|machine-account-password/.test(one.password);
  }), 'and no literal fixture password is anywhere in the database');
  log.debug("Leaving productModeHoldsNoFixtures().");
}

// ---------------------------------------------------------------------------
// 2. THE ACCEPTOR'S ACCOUNT IS BUILT FROM krb5.servicePrincipal (all modes).
// ---------------------------------------------------------------------------
function theServiceAccountFollowsTheSetting(t) {
  log.debug("Entering theServiceAccountFollowsTheSetting().");
  t.log.info('=== the acceptor\'s account is made from krb5.servicePrincipal ' +
             '===');
  const moved = inAChild({ KRB5_SERVICE_PRINCIPAL: 'HTTP/sts.example.com' },
                         SUMMARY);
  t.check(moved.report !== null, 'a development database with a renamed SPN ' +
                                 'builds',
          moved.stderr.slice(0, 400));
  if (!moved.report) {
    log.debug("Leaving theServiceAccountFollowsTheSetting().");
    return;
  }
  const account = moved.report.all.filter(function (one) {
    return one.name === 'HTTP/sts.example.com@' + principals.REALM;
  })[0];
  t.check(!!account &&
          account.password === config.value('krb5.servicePassword') &&
          account.salt === principals.REALM + 'HTTPsts',
          'the account the acceptor looks for EXISTS under the configured ' +
          'name — it was always HTTP/web.<domain> whatever the setting said',
          JSON.stringify(account || null));
  t.check(names(moved.report).indexOf('HTTP/web.example.com@' +
                                      principals.REALM) >= 0,
          'and the fixture HTTP/web account is still there in development, ' +
          'so the delegation cases that name it keep working');

  // At the defaults the configured account IS the fixture, field for field.
  const web = principals.find(['HTTP', 'web.example.com']);
  t.check(!!web && web.password === 'service-account-password' &&
          web.salt === principals.REALM + 'HTTPweb' &&
          web.okAsDelegate === true &&
          web.description === 'an HTTP service principal, flagged ' +
                              'ok-as-delegate',
          'at the default settings the account is exactly the fixture it ' +
          'replaced',
          JSON.stringify(web && { password: web.password, salt: web.salt,
                                  okAsDelegate: web.okAsDelegate }));
  t.check(principals.serviceAccount().available === true,
          'and in development the acceptor has its key');
  log.debug("Leaving theServiceAccountFollowsTheSetting().");
}

// ---------------------------------------------------------------------------
// 3. THE ETYPE LIST AND THE KVNO ARE SETTINGS, AND A BAD ETYPE STOPS THE
//    SERVICE.
// ---------------------------------------------------------------------------
function etypesAndKvnoAreSettings(t) {
  log.debug("Entering etypesAndKvnoAreSettings().");
  t.log.info('=== krb5.enctypes and krb5.kvno ===');
  t.check(JSON.stringify(principals.KDC_ETYPES) === JSON.stringify(
      [18, 17, 20, 19, 23]),
          'the default list is the literal it replaced, strongest first',
          JSON.stringify(principals.KDC_ETYPES));
  t.equal(principals.KVNO, 3, 'and the default kvno is 3');
  const parsed = principals.parseEtypes(['18', '18', '23', '99', 'des']);
  t.check(JSON.stringify(parsed.ids) === '[18,23]' &&
          JSON.stringify(parsed.problems) === '["99","des"]',
          'an unimplemented number is a PROBLEM rather than silently ' +
          'dropped, and a repeat is folded', JSON.stringify(parsed));
  t.check(principals.parseEtypes([]).problems.length === 1,
          'an empty list is a problem too — a KDC with no etype answers ' +
          'nobody');

  const refused = inAChild({ KRB5_ENCTYPES: '18,99' }, SUMMARY);
  t.check(refused.status === 1 && refused.report === null &&
          /krb5\.enctypes/.test(refused.stdout + refused.stderr) &&
          /\b99\b/.test(refused.stdout + refused.stderr),
          'a list naming an etype the codec does not implement STOPS the ' +
          'process, naming the setting and the number',
          'exit ' + refused.status);

  const hardened = inAChild({ KRB5_ENCTYPES: '18,17', KRB5_KVNO: '7' },
                            SUMMARY);
  t.check(hardened.report !== null, 'a hardened list builds',
          hardened.stderr.slice(0, 300));
  if (hardened.report) {
    const rc4only = hardened.report.all.filter(function (one) {
      return one.name.indexOf('rc4only@') === 0;
    })[0];
    t.check(!!rc4only && rc4only.etypes.length === 0,
            'with RC4 taken out the rc4only account offers nothing — exactly ' +
            'what a hardened domain does to ' +
            'it', JSON.stringify(rc4only || null));
    t.check(hardened.report.all.every(function (one) {
      return one.kvno === 7;
    }),
            'and krb5.kvno reaches every account');
  }
  log.debug("Leaving etypesAndKvnoAreSettings().");
}

// ---------------------------------------------------------------------------
// 4. AN AUTO-CREATED RID NEVER LANDS ON ONE A RESTORED ACCOUNT HOLDS.
//
// The counter restarted at 5000 in a process whose store came back holding
// 5000 — two accounts, one SID. Its first replacement read one above the
// highest RID in the database, which two PROCESSES could still both read; the
// RID is derived from the name now (see autoRidFor(), and
// tests/kerberos_principal_store.js for the cross-process half). What this
// section keeps is the original regression, restated for the new rule: a
// restored principal is simulated by moving an existing auto-created one onto
// the very slot the next name hashes to, and that next name must probe past it.
// The principal object is the one the store holds, and it is put back
// afterwards.
// ---------------------------------------------------------------------------
function autoRidsDoNotCollide(t) {
  log.debug("Entering autoRidsDoNotCollide().");
  t.log.info('=== an on-demand RID steps past a RID already held ===');
  const suffix = String(process.pid) + Math.random().toString(36).slice(2, 6);
  const first = principals.findOrCreateUser(['rid-probe-a-' + suffix]);
  t.check(!!first && first.pac.rid >= principals.AUTO_RID_BASE &&
          first.pac.rid < principals.AUTO_RID_LIMIT,
          'an account created on demand gets a RID in the on-demand range',
          JSON.stringify(first && first.pac.rid));
  if (!first) {
    log.debug("Leaving autoRidsDoNotCollide().");
    return;
  }
  const was = first.pac.rid;
  const secondName = 'rid-probe-b-' + suffix;
  const slot = principals.autoRidFor([secondName]);
  first.pac.rid = slot;
  try {
    const second = principals.findOrCreateUser([secondName]);
    t.check(!!second && second.pac.rid !== slot,
            'a name whose slot a restored account already holds is NOT given ' +
            'that account\'s ' +
            'RID', JSON.stringify(second && second.pac.rid) + ' vs ' + slot);
    t.equal(second && second.pac.rid,
            slot + 1 === principals.AUTO_RID_LIMIT ? principals.AUTO_RID_BASE :
            slot + 1,
            'it is given the next free slot, which every process holding the ' +
            'same database computes the same way');
  } finally {
    first.pac.rid = was;
  }
  log.debug("Leaving autoRidsDoNotCollide().");
}

// ---------------------------------------------------------------------------
// 5. A FULL REPLAY CACHE REFUSES THE NEXT AUTHENTICATOR AND FORGETS NONE.
// ---------------------------------------------------------------------------
async function apReqFor(clientName, cusec) {
  log.debug("Entering apReqFor().");
  const service = principals.find(['HTTP', 'web.example.com']);
  const etype = 18;
  const profile = kcrypto.etypeById(etype);
  const serviceKey = await principals.longTermKey(service, etype);
  const sessionKey = kcrypto.randomBytes(profile.keyBytes);
  const now = new Date();
  const cname = { type: 1, name: [clientName] };
  const ticketPart = msgs.encEncTicketPart({
    flags: [], key: { etype: etype, key: sessionKey }, crealm: principals.REALM,
    cname: cname, transited: { type: 1, contents: new Uint8Array(0) },
    authtime: now, starttime: now, endtime: new Date(now.getTime() + 3600000)
  });
  const authenticator = msgs.encAuthenticator({
    crealm: principals.REALM, cname: cname, cusec: cusec, ctime: now
  });
  const apReq = msgs.encApReq({
    apOptions: [],
    ticket: { realm: principals.REALM,
              sname: { type: 3, name: ['HTTP', 'web.example.com'] },
              encPart: { etype: etype, kvno: service.kvno,
                         cipher: await profile.encrypt(serviceKey,
                           kcrypto.KEY_USAGE.KDC_REP_TICKET, ticketPart) } },
    authenticator: { etype: etype,
                     cipher: await profile.encrypt(sessionKey,
                       kcrypto.KEY_USAGE.AP_REQ_AUTH, authenticator) }
  });
  log.debug("Leaving apReqFor().");
  return gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, apReq);
}

function replayCheck(result) {
  log.debug("Entering replayCheck().");
  log.debug("Leaving replayCheck().");
  return (result.checks || []).filter(function (c) {
    return c.name === 'not ' + 'a replay';
  })[0];
}

async function aFullReplayCacheForgetsNothing(t) {
  log.debug("Entering aFullReplayCacheForgetsNothing().");
  t.log.info('=== the replay cache refuses rather than evicts ===');
  const cache = krb5Service.replayCache;
  const saved = Array.from(cache.entries());
  cache.clear();
  config.setOverride('krb5.replayCacheMaxEntries', '100');
  try {
    const captured = await apReqFor('replay-victim', 111111);
    const first = await krb5Service.acceptRaw(captured, { record: false });
    t.check(first.ok === true, 'a genuine AP-REQ is accepted',
            JSON.stringify((first.checks || []).filter(
                function (c) { return !c.ok; })));

    // Fill the cache to its cap with Authenticators seen just now — every one
    // still inside the window. The captured one is the OLDEST entry.
    for (let i = 0; cache.size < 100; i++) {
      cache.set('filler/' + i, Date.now());
    }
    const fresh = await apReqFor('replay-attacker', 222222);
    const pushed = await krb5Service.acceptRaw(fresh, { record: false });
    t.check(pushed.ok === false &&
            /maximum of 100 Authenticators, every one still inside the replay window/
              .test(String((replayCheck(pushed) || {}).detail || '')),
            'a new Authenticator arriving at a FULL cache is refused, naming ' +
            'why',
            JSON.stringify(replayCheck(pushed) || pushed.checks));
    t.equal(cache.size, 100, 'and nothing was evicted to make room for it');

    const replayed = await krb5Service.acceptRaw(captured, { record: false });
    const verdict = replayCheck(replayed) || {};
    t.check(replayed.ok === false && /seen before/.test(String(verdict.detail)),
            'THE CAPTURED AP-REQ IS STILL A REPLAY. The old code evicted the ' +
            'oldest entry once the cache passed its cap, so an attacker who ' +
            'could present enough fresh Authenticators could replay a ' +
            'captured one',
            JSON.stringify(verdict));

    // And what the window DOES forget: an entry older than twice the skew.
    cache.clear();
    cache.set('ancient',
              Date.now() - (config.value('krb5.clockSkew') * 2 + 5) * 1000);
    const later = await apReqFor('replay-later', 333333);
    const accepted = await krb5Service.acceptRaw(later, { record: false });
    t.check(accepted.ok === true && !cache.has('ancient'),
            'an entry older than the window IS pruned — the cap is on the ' +
            'window, not on history', JSON.stringify(replayCheck(accepted)));
  } finally {
    config.clearOverride('krb5.replayCacheMaxEntries');
    cache.clear();
    saved.forEach(function (pair) { cache.set(pair[0], pair[1]); });
  }
  log.debug("Leaving aFullReplayCacheForgetsNothing().");
}

// ---------------------------------------------------------------------------
// 6. IN PRODUCT MODE THE ACCEPTOR SAYS WHY IT HOLDS NO KEY.
// ---------------------------------------------------------------------------
function theAcceptorExplainsAMissingAccount(t) {
  log.debug("Entering theAcceptorExplainsAMissingAccount().");
  t.log.info('=== a product acceptor with no key says which setting ===');
  // The acceptor is asynchronous and `inAChild()` reports synchronously, so the
  // refusal is driven in a child of its own that awaits it.
  const out = path.join(os.tmpdir(), 'krb5-acceptor-' + process.pid + '.json');
  const script =
    'delete process.env.CONFIG_FILE;' +
    'const R = ' + JSON.stringify(ROOT) + ';const p = require(R + ' +
    '"/kerberos/krb5_principals.js");const s = require(R + ' +
    '"/kerberos/krb5_service.js");const msgs = require(R + ' +
    '"/kerberos/krb5_messages.js");const gss = require(R + ' +
    '"/kerberos/krb5_gss.js");const junk = new Uint8Array(64);const apReq = ' +
    'msgs.encApReq({ apOptions: [], ticket: { realm: p.REALM, sname: { type: ' +
    '3, name: ["HTTP", "web.example.com"] }, encPart: { etype: 18, kvno: 3, ' +
    'cipher: junk } }, authenticator: { etype: 18, cipher: junk } ' +
    '});s.acceptRaw(gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, apReq), ' +
    '{ record: false }).then(function (r) { ' +
    'require("fs").writeFileSync(' + JSON.stringify(out) +
    ', JSON.stringify(r.checks)); process.exit(0); });';
  const run = childProcess.spawnSync(process.execPath, ['-e', script], {
    env: Object.assign({}, process.env,
                       { STS_MODE: 'product', LOG_LEVEL: 'fatal' }),
    encoding: 'utf8', timeout: 60000
  });
  let checks = null;
  try {
    checks = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in theAcceptorExplainsAMissingAccount(): " +
              ((e && e.message) || e));
    // Not written: the assertion below reports it.
    checks = null;
  }
  t.check(run.status === 0, 'a product-mode acceptor loads',
          String(run.stderr || '').slice(0, 300));
  const forMe = (checks || []).filter(function (c) {
    return c.name === 'the ticket is for this service';
  })[0];
  t.check(!!forMe && forMe.ok === false &&
          /krb5\.servicePassword/.test(forMe.detail),
          'a ticket for the configured SPN is refused with the REASON the ' +
          'account is missing, rather than "this service answers only on ' +
          'example.com"',
          JSON.stringify(forMe || checks));
  log.debug("Leaving theAcceptorExplainsAMissingAccount().");
}

module.exports = {
  name: 'kerberos_product_mode',
  describe: 'the Kerberos literals the 2026-09-12 audit found, in both modes',
  run: async function (t) {
    log.debug("Entering run().");
    productModeHoldsNoFixtures(t);
    theServiceAccountFollowsTheSetting(t);
    etypesAndKvnoAreSettings(t);
    autoRidsDoNotCollide(t);
    await aFullReplayCacheForgetsNothing(t);
    theAcceptorExplainsAMissingAccount(t);
    log.debug("Leaving run().");
  }
};
