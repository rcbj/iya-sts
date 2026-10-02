// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: client_secret_rotation.js
//
// ===========================================================================
// CLIENT SECRETS: SEVERAL PER APPLICATION, EACH WITH ITS EXPIRY (#49 P5,
// 2026-09-22; records on oauthClientSecret since 2026-10-01).
//
//   A. ROTATE: `rotate-secret` (the console's and `/admin-api`'s one action)
//      adds a new secret and moves the old one's expiry to the end of
//      oauth2.clientSecretOverlapS — both authenticate, the old one reported
//      as the previous secret — where `regenerate-secret` replaces them all.
//   B. THE OVERLAP ENDS: past its expiry the old secret is refused in BOTH
//      modes (STS-OAUTH-0558) before any sweep, and the daily sweep removes
//      it while the new one goes on.
//   C. EXPIRY: an application's ONLY secret past its expiry is REFUSED in
//      product mode (STS-OAUTH-0558) and accepted, and said so, in
//      development; the sweep keeps it, because it is the last one.
//   D. ADD AND REMOVE: a second secret added with a lifetime of its own is
//      the primary, both authenticate, the cap refuses one too many
//      (STS-REG-0208), a remove by id stops one at once, an unknown id is
//      STS-REG-0209, and a bad lifetime STS-REG-0211.
//   E. THE WARNING: the sweep lists a secret expiring within
//      oauth2.clientSecretExpiryWarningDays and an application whose every
//      secret has expired, with an audit row each; the job that runs it is
//      registered.
//   F. SEALED AT REST: where the key-encryption key persists every record
//      is sealed whole on the entry, every reader opens it, and an
//      unrelated edit or a remove leaves the rest sealed — and the
//      registration access token, a federation relationship's client
//      secret and a person's identity verifications are sealed too.
//
// In a child process, with the whole stack. Time is moved by replacing
// Date.now in the child, never by waiting.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'client_secret_rotation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.CS_ROOT;
  const OUT = process.env.CS_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const applications = require(ROOT + '/common/applications');
    const clientAuth = require(ROOT + '/oauth-oidc/client_auth');
    const config = require(ROOT + '/common/config');
    const audit = require(ROOT + '/common/audit');
    const scheduler = require(ROOT + '/cluster/scheduler');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const realNow = Date.now;
    let offsetMs = 0;
    Date.now = function () { return realNow() + offsetMs; };
    const APP = 'cs-rotation-app';
    const S0 = 'cs-rotation-first-secret-0123456789';
    applications.createApplication({ identifier: APP, protocols: ['oauth2'],
      fields: { oauthClientId: APP, oauthClientSecret: S0,
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    const check = function (presented, id) {
      return clientAuth.verify({ method: 'client_secret_basic',
        clientId: id || APP, presentedSecret: presented });
    };
    const secretsOf = function (id) {
      return (applications.clientConfigOf(id || APP) || {})
        .client_secrets || [];
    };

    // --- A. rotate ---------------------------------------------------------
    note((await check(S0)).ok, 'A0. the first secret authenticates');
    note(secretsOf().length === 1 && secretsOf()[0].secret === S0,
         'A0b. a secret written as a bare value is one record',
         JSON.stringify(secretsOf().length));
    const rotated = actions.applicationsAction(
      { action: 'rotate-secret', application: APP }, [], {});
    const reply = rotated && rotated.then ? await rotated : rotated;
    const S1 = reply && reply.clientSecret;
    note(reply && reply.ok && S1 && S1 !== S0 &&
         reply.overlapUntil > Date.now(),
         'A1. rotate-secret mints a new secret and says until when the old ' +
         'one works', JSON.stringify(reply && { ok: reply.ok,
           until: reply.overlapUntil }));
    const held = secretsOf();
    const overlapS = Number(config.value('oauth2.clientSecretOverlapS'));
    note(held.length === 2 && held[0].secret === S1 && held[1].secret === S0 &&
         held[1].expiresAt > 0 &&
         held[1].expiresAt <= Math.floor(Date.now() / 1000) + overlapS,
         'A2. the application holds both, the new one first, the old one ' +
         'expiring when the overlap ends',
         JSON.stringify(held.map(function (one) {
           return { id: one.id, expiresAt: one.expiresAt };
         })));
    note((applications.clientConfigOf(APP) || {}).client_secret === S1,
         'A3. the new secret is the primary — the one this service signs ' +
         'and encrypts with');
    const newOk = await check(S1);
    const oldOk = await check(S0);
    note(newOk.ok && !newOk.previousSecret && oldOk.ok &&
         oldOk.previousSecret === true,
         'A4. inside the overlap BOTH authenticate, the old one reported as ' +
         'the previous secret',
         JSON.stringify({ newOk: newOk, oldOk: oldOk }));

    // --- B. the overlap ends ------------------------------------------------
    // Past the old secret's expiry, and no sweep yet: the TIME alone refuses
    // it, in development too, because it is not the newest.
    offsetMs = (overlapS + 60) * 1000;
    const lapsed = await check(S0);
    note(!lapsed.ok && lapsed.errorCode === 'STS-OAUTH-0558',
         'B0. once the overlap has passed the old secret is refused, before ' +
         'any sweep has removed it', JSON.stringify(lapsed));
    const swept = applications.sweepClientSecrets(Date.now());
    note(swept.cleared.indexOf(APP) >= 0 && secretsOf().length === 1 &&
         secretsOf()[0].secret === S1,
         'B1. the sweep removes the expired secret, the live one beside it ' +
         'staying', JSON.stringify(swept));
    const oldAfter = await check(S0);
    note(!oldAfter.ok && oldAfter.errorCode === 'STS-OAUTH-0020' &&
         (await check(S1)).ok,
         'B2. and the old secret is no secret of this client any more; the ' +
         'new one goes on', JSON.stringify(oldAfter));
    const regen = applications.regenerateClientSecret(APP);
    const S2 = regen.clientSecret;
    note(!(await check(S1)).ok && (await check(S2)).ok &&
         secretsOf().length === 1,
         'B3. regenerate-secret replaces every secret at once');

    // --- C. expiry of the only secret --------------------------------------
    const lifetimeDays =
      Number(config.value('oauth2.clientSecretLifetimeDays'));
    const only = secretsOf()[0];
    // A lifetime of 0 means a regenerated secret never expires; give it one
    // through add-secret and remove the other, so there is an expiry to pass.
    let C_ID = only.id;
    let C_SECRET = S2;
    if (!(lifetimeDays > 0)) {
      const added = applications.addClientSecret(APP, { lifetimeDays: 1 });
      applications.removeClientSecret(APP, { id: only.id });
      C_ID = added.secretId;
      C_SECRET = added.clientSecret;
    }
    const expiresAt = secretsOf()[0].expiresAt;
    offsetMs += (expiresAt - Math.floor(Date.now() / 1000) + 60) * 1000;
    const devExpired = await check(C_SECRET);
    note(devExpired.ok,
         'C1. in DEVELOPMENT an application\'s only secret, expired, is ' +
         'accepted (and logged)', JSON.stringify(devExpired));
    config.setOverride('global.mode', 'product');
    const prodExpired = await check(C_SECRET);
    config.clearOverride('global.mode');
    note(!prodExpired.ok && prodExpired.errorCode === 'STS-OAUTH-0558',
         'C2. in PRODUCT it is refused (STS-OAUTH-0558)',
         JSON.stringify(prodExpired));
    const kept = applications.sweepClientSecrets(Date.now());
    note(kept.expired.indexOf(APP) >= 0 && kept.cleared.indexOf(APP) < 0 &&
         secretsOf().length === 1 && secretsOf()[0].id === C_ID,
         'C3. the sweep reports it expired and keeps it, being the last ' +
         'secret the application holds', JSON.stringify(kept));

    // --- D. add and remove -------------------------------------------------
    const D = 'cs-rotation-several';
    applications.createApplication({ identifier: D, protocols: ['oauth2'],
      fields: { oauthClientId: D } });
    const first = applications.addClientSecret(D, { lifetimeDays: 0,
      description: 'the first' });
    const second = applications.addClientSecret(D, { lifetimeDays: 30 });
    const listed = secretsOf(D);
    const thirtyDays = Math.floor(Date.now() / 1000) + 30 * 86400;
    note(first.ok && second.ok && listed.length === 2 &&
         listed[0].secret === second.clientSecret &&
         listed[1].secret === first.clientSecret &&
         listed[1].expiresAt === 0 &&
         Math.abs(listed[0].expiresAt - thirtyDays) <= 60,
         'D1. two secrets added, the newest first; a lifetime is in DAYS, ' +
         'and 0 never expires', JSON.stringify(listed.map(function (one) {
           return { id: one.id, expiresAt: one.expiresAt };
         })));
    note((await check(first.clientSecret, D)).ok &&
         (await check(second.clientSecret, D)).ok,
         'D2. both authenticate');
    const summaries = applications.clientSecretSummariesOf(
      applications.get(D).fields);
    note(summaries.length === 2 && summaries[0].primary &&
         !summaries[1].primary &&
         summaries.every(function (one) { return !('secret' in one); }) &&
         summaries[1].description === 'the first',
         'D3. the summaries name the primary, carry the description and no ' +
         'secret', JSON.stringify(summaries));
    const max = Number(config.value('oauth2.clientSecretsMax'));
    let capped = null;
    for (let n = 2; n <= max; n += 1) {
      capped = applications.addClientSecret(D, {});
    }
    note(capped && !capped.ok &&
         require(ROOT + '/common/error_codes').codeOf(capped) ===
           'STS-REG-0208' && secretsOf(D).length === max,
         'D4. oauth2.clientSecretsMax refuses one secret too many ' +
         '(STS-REG-0208)', JSON.stringify(capped && capped.errors));
    const removed = applications.removeClientSecret(D,
      { id: second.secretId });
    note(removed.ok && !(await check(second.clientSecret, D)).ok &&
         (await check(first.clientSecret, D)).ok,
         'D5. a secret removed by id stops authenticating at once; another ' +
         'goes on');
    const unknown = applications.removeClientSecret(D, { id: 'cs-nothere' });
    note(!unknown.ok && require(ROOT + '/common/error_codes')
      .codeOf(unknown) === 'STS-REG-0209',
         'D6. an id the application does not hold is refused (STS-REG-0209)');
    const bad = applications.addClientSecret(D, { lifetimeDays: '-5' });
    const tooLong = applications.addClientSecret(D, { lifetimeDays: 731 });
    note(!bad.ok && require(ROOT + '/common/error_codes')
      .codeOf(bad) === 'STS-REG-0211' && !tooLong.ok,
         'D7. a lifetime that is not 0..730 days is refused (STS-REG-0211)');
    const viaAction = actions.applicationsAction(
      { action: 'remove-secret', application: D,
        secret: first.secretId }, [], {});
    const viaReply = viaAction && viaAction.then ? await viaAction : viaAction;
    note(viaReply && viaReply.ok &&
         !(await check(first.clientSecret, D)).ok,
         'D8. the console\'s and /admin-api\'s remove-secret action reaches ' +
         'the same remove', JSON.stringify(viaReply && viaReply.errors));

    // --- E. the warning ----------------------------------------------------
    const OTHER = 'cs-rotation-soon';
    applications.createApplication({ identifier: OTHER, protocols: ['oauth2'],
      fields: { oauthClientId: OTHER } });
    applications.addClientSecret(OTHER, { lifetimeDays: 1 });
    const report = applications.sweepClientSecrets(Date.now());
    note(report.expired.indexOf(APP) >= 0 &&
         report.expiring.indexOf(OTHER) >= 0,
         'E1. the sweep lists the expired application and the one expiring ' +
         'within the warning window', JSON.stringify(report));
    const rows = audit.list();
    note(rows.some(function (r) {
      return r.action === 'application.secret-expired' && r.target === APP;
    }) && rows.some(function (r) {
      return r.action === 'application.secret-expiring' && r.target === OTHER;
    }), 'E2. each with an audit row an administrator can find');
    const job = scheduler.job('oauth2.client-secret-expiry');
    note(job && job.scope === 'realm' && (job.kind || 'cluster') === 'cluster',
         'E3. and the daily job that runs the sweep is registered, per realm');

    // --- F. sealed at rest --------------------------------------------------
    // keys.source=persisted arms a key-encryption key that outlives the
    // process, which is what product mode has; the environment layer because
    // the row is restart-only.
    Date.now = realNow;
    offsetMs = 0;
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const keystore = require(ROOT + '/common/keystore');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-cs-seal-'));
    fs.writeFileSync(path.join(dir, 'kek'),
      require('crypto').randomBytes(32).toString('base64'),
      { encoding: 'utf8', mode: 0o600 });
    const plain = function (id) {
      return [].concat(applications.get(id).attributes.oauthClientSecret || []);
    };
    const SEALED = 'cs-rotation-sealed';
    const SS = 'cs-rotation-sealed-secret-0123456789abcdef';
    applications.createApplication({ identifier: SEALED,
      protocols: ['oauth2'],
      fields: { oauthClientId: SEALED, oauthClientSecret: SS } });
    note(plain(SEALED).length === 1 &&
         !applications.isSealed(plain(SEALED)[0]),
         'F0. in DEVELOPMENT a secret is stored in the clear: the ' +
         'key-encryption key there is ephemeral and the entry outlives it');
    process.env.STS_KEYS_SOURCE = 'persisted';
    process.env.STS_KEYS_KEK_PROVIDER = 'file';
    process.env.STS_KEYS_KEK_FILE = path.join(dir, 'kek');
    keystore.reset();
    keystore.setStore({
      loadKeys: function () { return Promise.resolve([]); },
      saveKeys: function () { return Promise.resolve(); },
      deleteKeys: function () { return Promise.resolve(); }
    });
    await keystore.start();
    note(keystore.persists(), 'F1. the key-encryption key now persists');
    const sealedRegen = applications.regenerateClientSecret(SEALED);
    const sealedAdded = applications.addClientSecret(SEALED,
      { lifetimeDays: 30, description: 'sealed probe' });
    const stored = plain(SEALED);
    note(sealedRegen.ok && sealedAdded.ok && stored.length === 2 &&
         stored.every(applications.isSealed) &&
         stored.every(function (value) {
           return value.indexOf(sealedRegen.clientSecret) < 0 &&
                  value.indexOf(sealedAdded.clientSecret) < 0 &&
                  value.indexOf('sealed probe') < 0;
         }),
         'F2. THE ENTRY HOLDS CIPHERTEXT: every record is sealed whole, ' +
         'secret, id and description alike',
         JSON.stringify(stored.map(function (v) { return v.slice(0, 16); })));
    note((await check(sealedRegen.clientSecret, SEALED)).ok &&
         (await check(sealedAdded.clientSecret, SEALED)).ok &&
         !(await check(SS, SEALED)).ok,
         'F3. both sealed secrets authenticate, and the replaced one does not');
    const viewed = [].concat(
      applications.get(SEALED).fields.oauthClientSecret || []);
    note(viewed.length === 2 && viewed.every(function (value) {
      return !applications.isSealed(value) &&
             JSON.parse(value).secret.length > 0;
    }) && (applications.clientConfigOf(SEALED) || {}).client_secret ===
      sealedAdded.clientSecret,
         'F4. a reader that came through applications.js is handed the ' +
         'records opened, and the primary is the newest');
    applications.updateApplication(SEALED,
      { attribute: 'appName', mode: 'set', value: 'Renamed sealed probe' });
    note(plain(SEALED).every(applications.isSealed),
         'F5. an unrelated edit to the entry leaves the secrets sealed');
    note(applications.removeClientSecret(SEALED,
      { id: sealedRegen.secretId }).ok &&
         plain(SEALED).length === 1 && applications.isSealed(plain(SEALED)[0]),
         'F6. a remove by id finds the sealed record and leaves the rest ' +
         'sealed');
    // THE REGISTRATION ACCESS TOKEN, sealed in setField() and opened by
    // every reader.
    const TOKEN = 'cs-rotation-registration-token-0123456789abcdef';
    applications.updateApplication(SEALED, { attribute:
      'appRegistrationAccessToken', mode: 'set', value: TOKEN });
    const storedToken = String([].concat(applications.get(SEALED)
      .attributes.appRegistrationAccessToken || [])[0] || '');
    note(applications.isSealed(storedToken) && storedToken.indexOf(TOKEN) < 0,
         'F7. the registration access token is sealed on the entry',
         storedToken.slice(0, 16));
    note(applications.get(SEALED).fields.appRegistrationAccessToken ===
           TOKEN &&
         applications.registrationAccessTokenOf(
           applications.get(SEALED).fields) === TOKEN,
         'F8. and opened for the view and for registrationAccessTokenOf()');
    note(applications.revokeRegistrationAccessToken(TOKEN) === SEALED &&
         !applications.get(SEALED).attributes.appRegistrationAccessToken,
         'F9. RFC 7592 section 2: the sealed token is found by the one ' +
         'presented and taken off its entry');

    // A FEDERATION RELATIONSHIP'S CLIENT SECRET.
    const federation = require(ROOT + '/federation/federation');
    const FED = 'cs-rotation-fed';
    const FED_SECRET = 'cs-rotation-federation-secret-0123456789';
    const fedMade = federation.create({ fedId: FED,
      fedRole: 'service-provider', fedProtocol: 'oidc',
      fedPeer: 'https://partner.cs-rotation.example' });
    const fedSet = federation.update(FED, { field: 'fedClientSecret',
                                            value: FED_SECRET });
    const fedStored = String((federation.get(FED) || {}).fedClientSecret || '');
    note(fedMade.ok && fedSet.ok && fedStored.indexOf('sealed:') === 0 &&
         fedStored.indexOf(FED_SECRET) < 0,
         'F10. a federation relationship\'s client secret is sealed on its ' +
         'entry', JSON.stringify({ made: fedMade.errors, set: fedSet.errors,
                                   stored: fedStored.slice(0, 16) }));
    note(federation.clientSecretOf(federation.get(FED)) === FED_SECRET,
         'F11. and clientSecretOf() opens it for the token request');

    // A PERSON'S IDENTITY VERIFICATIONS, under the home cell's key.
    const ldapServer = require(ROOT + '/ldap/ldap_server');
    const credentials = require(ROOT + '/common/credentials');
    const PERSON = 'cs-rotation-ida-person';
    ldapServer.createUser(PERSON, {});
    const IDA = JSON.stringify([{ verification: { trust_framework: 'x' },
      claims: { given_name: 'Ida' }, evidence: 'passport P0123456' }]);
    const idaWritten = credentials.writeIdaVerifications(PERSON, IDA);
    const rawEntry = ldapServer.existingUserEntry(PERSON) || {};
    const rawIda = String([].concat(((rawEntry.attributes || {})
      .stsidaverification) || [])[0] || '');
    note(idaWritten && applications.isSealed(rawIda) &&
         rawIda.indexOf('P0123456') < 0,
         'F12. a person\'s identity verifications are sealed on the entry',
         rawIda.slice(0, 16));
    note(credentials.readIdaVerifications(PERSON) === IDA,
         'F13. and opened for the reader');

    delete process.env.STS_KEYS_SOURCE;
    delete process.env.STS_KEYS_KEK_PROVIDER;
    delete process.env.STS_KEYS_KEK_FILE;
    keystore.reset();
    fs.rmSync(dir, { recursive: true, force: true });

    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'client-secret-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', CS_ROOT: ROOT, CS_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'client_secret_rotation',
  describe: 'several client secrets per application: rotation with an ' +
            'overlap, the overlap ending, expiry refused in product and ' +
            'accepted in development, add, remove and the cap, and the ' +
            'daily sweep of secrets expiring and expired',
  run: run
};
