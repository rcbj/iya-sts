// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_revocation.js
//
// ===========================================================================
// WHAT ENDS A GNAP GRANT FROM OUTSIDE THE PROTOCOL (#432 phase 2).
//
// `logout/` never named GNAP: a global sign-out, an account disable and an
// administrator's sign-out left every grant and token a person approved live,
// and nothing about an application entry, a device or a received signal
// reached one either. This file drives each of those acts against real
// grants in the real store, with the whole stack loaded:
//
//   A. the inventory lists a person's GNAP grants and Grant Management
//      grants, and `heldIds()` holds them;
//   B. a sign-out of ONE session ends the grant approved on it and not one
//      approved on another session (`endsWithSession`);
//   C. `/admin/sessions`' model lists a GNAP grant as a live row, and its
//      Revoke (a `terminate()` of that row) ends it;
//   D. `revokeGrantsOf()` — what a partner's signal-revoke-grants calls —
//      narrowed to a session ends only what was issued on it; whole, it ends
//      the Grant Management grant and the OAuth tokens too, and leaves the
//      person's sessions; a person holding nothing is NOT signed out (an
//      empty selection must never become a global sign-out);
//   E. a global sign-out ends every grant and token;
//   F. the check at use: a disabled resource owner's token is refused at
//      presentation (STS-GNAP-0734) and its grant at use (STS-GNAP-0730),
//      on a node the disable has not reached (stubbed); and the disable
//      itself ends the grant;
//   G. an application entry's gnapKey REPLACED ends the grants bound to the
//      old key and keeps one bound to a reference the entry still names; the
//      entry DELETED ends the rest; an entry gone is refused at use
//      (STS-GNAP-0731);
//   H. a device marked compromised ends the GNAP grants whose client key is
//      the device's (a JWK, or its certificate over mutual TLS) and revokes
//      the OAuth tokens DPoP-bound to its key or mTLS-bound to its
//      certificate, the binding the token register now records.
//
// In a child process, because it loads the whole protocol stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'gnap_revocation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.GR_ROOT;
  const OUT = process.env.GR_OUT;
  const fs = require('fs');
  const crypto = require('crypto');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const helpers = require(ROOT + '/common/helpers');
    const errorCodes = require(ROOT + '/common/error_codes');
    const stats = require(ROOT + '/common/admin_stats');
    const applications = require(ROOT + '/common/applications');
    const accountState = require(ROOT + '/common/account_state');
    const devices = require(ROOT + '/common/devices');
    const stsCrypto = require(ROOT + '/common/crypto');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const authn = require(ROOT + '/authn/authn');
    const logout = require(ROOT + '/logout/logout');
    const gm = require(ROOT + '/oauth-oidc/grant_management');
    const store = require(ROOT + '/gnap/gnap_store');
    const revocation = require(ROOT + '/gnap/gnap_revocation');
    const rsModule = require(ROOT + '/gnap/gnap_rs');

    const STAMP = crypto.randomBytes(3).toString('hex');
    const ANN = 'gr-ann-' + STAMP;
    const BEN = 'gr-ben-' + STAMP;
    const CAT = 'gr-cat-' + STAMP;
    const CLIENT = 'gr-client-' + STAMP;
    const REFERENCE = 'gr-ref-' + STAMP;
    [ANN, BEN, CAT].forEach(function (name) {
      ldap.createUser(name, { invent: false });
    });
    const subOf = function (name) {
      return String(helpers.subjectForName(name));
    };
    const keyPair = function () {
      const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const jwk = Object.assign(pair.publicKey.export({ format: 'jwk' }),
                                { alg: 'ES256', kid: 'k-' +
                                  crypto.randomBytes(4).toString('hex') });
      return { jwk: jwk, key: { proof: 'httpsig', jwk: jwk } };
    };
    const first = keyPair();
    const made = applications.createApplication({ identifier: CLIENT,
      kind: 'gnap-client', protocols: ['gnap'],
      fields: { gnapKey: JSON.stringify(first.key),
                gnapKeyReference: REFERENCE } });
    note(made.ok, 'setup: the GNAP client entry was created',
         JSON.stringify(made.errors || ''));
    const fakeRes = function () {
      return { headers: {}, setHeader: function (k, v) {
        this.headers[k] = v;
      }, getHeader: function (k) {
        return this.headers[k];
      } };
    };
    const signIn = function (name) {
      return authn.startSession(fakeRes(), name, ['pwd'], '1', 'password',
                                {});
    };
    // A grant approved by `name` on `session`, with one bearer macaroon-format
    // token (no jti in the JWT register, so only GNAP's own record moves).
    const grantFor = function (name, session, key, identifier) {
      const grant = store.newGrant({ state: store.STATE.APPROVED,
        client: { identifier: identifier || CLIENT,
                  key: key === undefined ? first.key : key,
                  proof: 'httpsig' },
        ro: { username: name, sessionId: session ? session.id : null,
              authTime: Math.floor(Date.now() / 1000), amr: ['pwd'],
              acr: '1' },
        grantEndpoint: 'https://sts.test/gnap', as: null });
      const value = 'gnap-token-' + crypto.randomBytes(12).toString('hex');
      const now = Math.floor(Date.now() / 1000);
      const record = store.putToken({ jti: store.handle(16),
        format: 'macaroon', grantId: grant.id, instanceId: grant.client
          .identifier, username: name, sub: subOf(name),
        flags: ['bearer'], key: null, proof: null, aud: [],
        access: [{ type: 'demo', actions: ['read'] }], iat: now, nbf: now,
        exp: now + 3600, revoked: false, createdAt: now }, value);
      grant.tokens = [record.jti];
      store.saveGrant(grant, 'test');
      return { grant: grant, jti: record.jti, value: value };
    };
    const finalized = function (one) {
      const g = store.getGrant(one.grant.id);
      const t = store.tokenByJti(one.jti);
      return !!g && g.state === store.STATE.FINALIZED && !!t && t.revoked;
    };
    const live = function (one) {
      const g = store.getGrant(one.grant.id);
      const t = store.tokenByJti(one.jti);
      return !!g && g.state === store.STATE.APPROVED && !!t && !t.revoked;
    };
    const mintOauth = function (name, typ, session, extra, context) {
      const jti = 'gr-' + typ + '-' + crypto.randomBytes(6).toString('hex');
      const now = Math.floor(Date.now() / 1000);
      helpers.signJwt(Object.assign({ typ: typ, jti: jti, sub: subOf(name),
        username: name, client_id: 'gr-webapp', scope: 'openid', iat: now,
        nbf: now, exp: now + 900 }, extra || {}),
      Object.assign({ sessionId: session ? session.id : '' }, context || {}));
      return jti;
    };
    const keyOf = function (name) {
      return stats.identityKeyOf(name);
    };

    // --- A. the inventory ---------------------------------------------------
    const annSession = signIn(ANN);
    const annOther = signIn(ANN);
    const a1 = grantFor(ANN, annSession);
    const gmId = 'gr-gm-' + STAMP;
    gm.apply({ id: gmId, gen: 1, clientId: 'gr-webapp', sub: subOf(ANN),
               scope: 'openid', action: 'create', createdAt: Date.now() });
    const gmRefresh = mintOauth(ANN, 'Refresh', annSession, {},
                                { grantId: gmId, grantRefresh: true });
    gm.noteIssued(gmId, 1, gmRefresh, 'refresh_token',
                  Math.floor(Date.now() / 1000) + 900);
    const inventory = logout.inventoryFor(keyOf(ANN));
    const family = function (id) {
      return (inventory.families.filter(function (f) {
        return f.id === id;
      })[0] || { rows: [] });
    };
    const held = logout.heldIds(keyOf(ANN));
    note(family('gnap').rows.some(function (r) {
      return r.handle === a1.grant.id && r.sessionId === annSession.id;
    }) && family('oauth-grant').rows.some(function (r) {
      return r.handle === gmId;
    }) && held.indexOf('gnap:' + a1.grant.id) >= 0 &&
         held.indexOf('oauth-grant:' + gmId) >= 0,
         'A1. the inventory lists the person\'s GNAP grant (with the ' +
         'session it was approved on) and their Grant Management grant, ' +
         'and heldIds() holds both',
         JSON.stringify([family('gnap').rows, family('oauth-grant').rows,
                         held]));

    // --- B. a grant ends with the session it was approved on ----------------
    const a2 = grantFor(ANN, annOther);
    logout.terminate(keyOf(ANN), ['session:' + annOther.id],
                     { by: 'a test', initiatingEntity: 'admin' });
    note(finalized(a2) && live(a1) && !!authn.sessionById(annSession.id),
         'B1. ending one session ends the GNAP grant approved on it — not ' +
         'ticked — and leaves the grant approved on another session and that ' +
         'session alone', JSON.stringify([store.getGrant(a2.grant.id).state,
                                          store.getGrant(a1.grant.id).state]));

    // --- C. /admin/sessions' model ----------------------------------------
    const rows = logout.liveSessions().filter(function (r) {
      return r.family === 'gnap' && r.handle === a1.grant.id;
    });
    note(rows.length === 1 && rows[0].key === keyOf(ANN) &&
         rows[0].terminable && rows[0].expiresAt === 0 &&
         /RFC 9635/.test(rows[0].expiryRule || ''),
         'C1. a live GNAP grant is a row of liveSessions(), terminable, ' +
         'with no expiry of its own and the rule that says why',
         JSON.stringify(rows));
    const c1 = grantFor(ANN, annSession);
    logout.terminate(keyOf(ANN), ['gnap:' + c1.grant.id],
                     { by: 'the console at /admin/sessions',
                       initiatingEntity: 'admin' });
    note(finalized(c1) && live(a1) && !!authn.sessionById(annSession.id),
         'C2. its Revoke — terminate() of that one row — ends it and ' +
         'nothing else');

    // --- D. revokeGrantsOf() -------------------------------------------------
    const onOther = mintOauth(ANN, 'Bearer', annOther);
    const narrowed = logout.revokeGrantsOf(keyOf(ANN), {
      by: 'a test', initiatingEntity: 'policy',
      sessionIds: [annSession.id] });
    note(finalized(a1) && stats.isRevoked(gmRefresh) &&
         !stats.isRevoked(onOther) && !!gm.current(gmId) &&
         !!authn.sessionById(annSession.id),
         'D1. narrowed to a session it ends the GNAP grant and the OAuth ' +
         'tokens issued on that session, keeps the Grant Management grant ' +
         '(it records no session) and a token on another session, and ' +
         'ends no session', JSON.stringify(narrowed && narrowed.terminated));
    const d2 = grantFor(ANN, null);
    const whole = logout.revokeGrantsOf(keyOf(ANN), {
      by: 'a test', initiatingEntity: 'policy' });
    note(finalized(d2) && stats.isRevoked(onOther) && !gm.current(gmId) &&
         !!authn.sessionById(annSession.id),
         'D2. whole, it ends every GNAP grant, the Grant Management grant ' +
         'and every OAuth token — and still no session',
         JSON.stringify(whole && whole.terminated));
    const benSession = signIn(BEN);
    const nothing = logout.revokeGrantsOf(keyOf(BEN), { by: 'a test' });
    note(nothing.terminated.length === 0 &&
         !!authn.sessionById(benSession.id),
         'D3. a person holding none of them is NOT signed out — an empty ' +
         'selection never becomes a global sign-out',
         JSON.stringify(nothing));

    // --- E. a global sign-out -----------------------------------------------
    const e1 = grantFor(ANN, annSession);
    const e2 = grantFor(ANN, null);
    logout.terminate(keyOf(ANN), [], { by: 'a test' });
    note(finalized(e1) && finalized(e2),
         'E1. a global sign-out finalizes every GNAP grant the person ' +
         'approved and revokes their tokens');

    // --- F. the check at use, and the disable -------------------------------
    const f1 = grantFor(BEN, benSession);
    const rs = new rsModule.GnapRs(rsModule.GnapRs.defaultDeps());
    const present = function (instance, value) {
      return instance.presentation({ headers: { authorization: 'Bearer ' +
                                                value } });
    };
    const before = present(rs, f1.value);
    const stubbed = new revocation.GnapRevocation(Object.assign(
      revocation.GnapRevocation.defaultDeps(), {
        loadAccountState: function () {
          return { isDisabled: function () {
            return true;
          } };
        } }));
    const lagging = new rsModule.GnapRs(Object.assign(
      rsModule.GnapRs.defaultDeps(), { revocation: stubbed }));
    const refused = present(lagging, f1.value);
    note(before.ok && !refused.ok &&
         errorCodes.codeOf(refused) === 'STS-GNAP-0734' &&
         (stubbed.grantProblem(f1.grant) || {}).code === 'STS-GNAP-0730' &&
         live(f1),
         'F1. on a node the disable has not reached, the token is refused ' +
         'at presentation (STS-GNAP-0734) and the grant at use ' +
         '(STS-GNAP-0730), and nothing is written',
         JSON.stringify([before.ok, refused, stubbed.grantProblem(f1.grant)]));
    const disabled = accountState.setDisabled(BEN, true, { actor: 'a test' });
    const afterDisable = present(rs, f1.value);
    note(disabled.ok && finalized(f1) && !afterDisable.ok,
         'F2. the disable itself ends the grant and its token (through the ' +
         'global sign-out), and the token is refused',
         JSON.stringify([disabled.message, afterDisable]));
    accountState.setDisabled(BEN, false, { actor: 'a test' });

    // --- G. the application entry -------------------------------------------
    const catSession = signIn(CAT);
    const byValue = grantFor(CAT, catSession);
    const byReference = grantFor(CAT, catSession, REFERENCE);
    // A grant rotated (section 6.1.1) onto a key the entry never named, from
    // the one it does.
    const rotated = grantFor(CAT, catSession, keyPair().key);
    rotated.grant.client.keyLineage = [revocation.keyIdentityOf(first.key)];
    store.saveGrant(rotated.grant, 'test: rotated');
    note(revocation.grantProblem(store.getGrant(rotated.grant.id)) === null &&
         revocation.clientProblem(CLIENT, keyPair().key) !== null,
         'G0. a grant rotated onto a new key answers to the key it was ' +
         'rotated from, so a rotation is not a removal — and an unrelated ' +
         'key is refused (STS-GNAP-0731)');
    const second = keyPair();
    const replaced = applications.updateApplication(CLIENT, {
      attribute: 'gnapKey', mode: 'set',
      value: JSON.stringify(second.key), actor: 'a test' });
    note(replaced.ok && finalized(byValue) && live(byReference) &&
         finalized(rotated),
         'G1. the entry\'s gnapKey replaced ends the grant bound to the old ' +
         'key and the one rotated from it, and keeps the one bound to a ' +
         'reference the entry still names',
         JSON.stringify([replaced.errors || replaced.message,
                         store.getGrant(byValue.grant.id).state,
                         store.getGrant(byReference.grant.id).state]));
    const deleted = applications.deleteApplication(CLIENT,
                                                   { actor: 'a test' });
    note(deleted.ok && finalized(byReference),
         'G2. the entry deleted ends the rest of its grants',
         JSON.stringify(deleted.errors || deleted.message));
    const gone = revocation.clientProblem(CLIENT, second.key);
    note(gone && gone.code === 'STS-GNAP-0731',
         'G3. a client whose entry is gone is refused at use (STS-GNAP-0731) ' +
         '— a delete over LDAP, which this service does not observe, included',
         JSON.stringify(gone));

    // --- H. a compromised device --------------------------------------------
    const deviceKey = keyPair();
    const otherApp = 'gr-device-client-' + STAMP;
    applications.createApplication({ identifier: otherApp,
      kind: 'gnap-client', protocols: ['gnap'],
      fields: { gnapKey: JSON.stringify(deviceKey.key) } });
    const device = devices.create({ owner: CAT, label: 'cat laptop ' +
                                    STAMP }, 'a test');
    const added = device.ok ? devices.addKey(device.device.id, {
      kind: 'jwk', value: JSON.stringify(deviceKey.jwk) }, 'a test')
      : { ok: false };
    // And a certificate the device holds, for the mutual-TLS bindings (#432
    // follow-up): a GNAP client proving by mutual TLS with it, and an OAuth
    // token bound to it (RFC 8705 cnf x5t#S256).
    const cert = stsCrypto.selfSignedRsaCertificate({ commonName: 'gr-dev-' +
                                                      STAMP, bits: 2048 });
    const x5t = stsCrypto.certificateThumbprint(cert.certPem);
    const otherCert = stsCrypto.selfSignedRsaCertificate({ commonName:
                                                           'gr-other-' + STAMP,
                                                         bits: 2048 });
    const addedCert = device.ok ? devices.addKey(device.device.id, {
      kind: 'x509', value: cert.certPem }, 'a test') : { ok: false };
    const h1 = grantFor(CAT, null, deviceKey.key, otherApp);
    const hMtls = grantFor(CAT, null, { proof: 'mtls', 'cert#S256': x5t },
                           otherApp);
    const unrelated = grantFor(CAT, null, keyPair().key, otherApp);
    const unrelatedMtls = grantFor(CAT, null, { proof: 'mtls',
      'cert#S256': stsCrypto.certificateThumbprint(otherCert.certPem) },
      otherApp);
    const bound = mintOauth(CAT, 'Bearer', null,
      { cnf: { jkt: stsCrypto.jwkThumbprint(deviceKey.jwk) } });
    const mtlsBound = mintOauth(CAT, 'Bearer', null,
      { cnf: { 'x5t#S256': x5t } });
    const otherMtls = mintOauth(CAT, 'Bearer', null,
      { cnf: { 'x5t#S256': stsCrypto.certificateThumbprint(
        otherCert.certPem) } });
    const recorded = stats.issuedList().filter(function (row) {
      return row.jti === mtlsBound;
    })[0] || {};
    const compromised = device.ok
      ? devices.setStatus(device.device.id, 'compromised', 'a test',
                          'a test') : { ok: false };
    note(recorded.x5t === x5t,
         'H0. the token register records a token\'s mutual-TLS binding ' +
         '(x5t#S256) beside DPoP\'s jkt', JSON.stringify(recorded));
    note(device.ok && added.ok && addedCert.ok && compromised.ok &&
         finalized(h1) && finalized(hMtls) && live(unrelated) &&
         live(unrelatedMtls) && stats.isRevoked(bound) &&
         stats.isRevoked(mtlsBound) && !stats.isRevoked(otherMtls) &&
         compromised.gnapGrantsEnded === 2,
         'H1. a device marked compromised ends the GNAP grants whose client ' +
         'key is the device\'s — by its JWK, and by mutual TLS with its ' +
         'certificate — revokes the OAuth tokens DPoP-bound to its key and ' +
         'bound by mutual TLS to its certificate, and leaves a grant and a ' +
         'token bound to another key or certificate',
         JSON.stringify([device.errors, added.errors, addedCert.errors,
                         compromised]));

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'gnap-revocation-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', GR_ROOT: ROOT, GR_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'gnap_revocation',
  describe: 'what ends a GNAP grant from outside the protocol (#432): the ' +
            'sign-out inventory and its families, a grant ending with its ' +
            'session, /admin/sessions, revokeGrantsOf() narrowed and whole, ' +
            'a global sign-out, the check at use and the disable, the ' +
            'application entry\'s key and deletion, a compromised device',
  run: run
};
