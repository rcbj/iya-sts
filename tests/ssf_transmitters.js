// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_transmitters.js
//
// ===========================================================================
// A FEDERATION PARTNER'S SHARED SIGNALS (#153, #373, #374), in a child
// process with the whole stack loaded: real federation relationships in the
// real directory, this service's real signal-response policy, block store,
// account lock and subject decision, and a fake partner (its discovery
// document, token endpoint, stream endpoint and poll endpoint), a fake
// session list and a fake sign-out that records what it was asked to end.
//
//   A. the policy: a sign-in partner may end the sessions it started and
//      block and unblock; a signals-only partner may only lift its own
//      lock; either sets a device's compliance; this service's own
//      receivers get none of those;
//   B. discovery: a document naming another issuer is refused; the right
//      one is kept, and no secret is shown; a relationship whose signals
//      are off is refused every act;
//   C. a complex subject's session-revoked ends that one session the
//      partner started, and nothing else;
//   D. a polled account-disabled blocks the partner's sign-ins of the
//      person and ends the rest of its sessions — not a local one, not
//      another partner's — and the account stays enabled; acknowledged next;
//   E. the block refuses the person's federated sign-in through that
//      relationship (STS-FED-0156); its account-enabled lifts it;
//   F. refusals: a replay is not acted on twice; a bad signature is
//      recorded and not acted on (development), refused where signatures
//      are required; the wrong iss and aud are refused;
//   G. an email subject names nobody unless the relationship allows it;
//   H. an `ssf` relationship (#374): service-provider only, its fields its
//      signals alone, offered to no sign-in; its people named by links an
//      administrator writes (iss_sub and opaque); its account-disabled is
//      recorded and does nothing; its device-compliance-change sets the
//      device;
//   I. the push endpoint refuses a header it did not give, and a disabled
//      relationship;
//   J. deleting forgets the stream and lifts the blocks.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'ssf_transmitters',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.FT_ROOT;
  const OUT = process.env.FT_OUT;
  const fs = require('fs');
  const crypto = require('crypto');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const config = require(ROOT + '/common/config');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const pep = require(ROOT + '/xacml/xacml_signal_pep');
    const accountState = require(ROOT + '/common/account_state');
    const federation = require(ROOT + '/federation/federation');
    const fedLinks = require(ROOT + '/federation/federation_links');
    const fedBlocks = require(ROOT + '/federation/federation_blocks');
    const fedSp = require(ROOT + '/federation/federation_sp');
    const module_ = require(ROOT + '/ssf/ssf_transmitters');
    config.setOverride('ssf.actOnSignalsInDevelopment', true);
    const R = pep.RESPONSE;

    // --- A. the policy ------------------------------------------------------
    const reactions = function (event, family, surface, kind) {
      return pep.decide({ event: event, family: family, surface: surface,
                          level: '', kind: kind || '' }).reactions;
    };
    const has = function (list, one) {
      return list.indexOf(one) >= 0;
    };
    const p = 'federation:partner';
    const signIn = {
      revoked: reactions('session-revoked', 'caep', p, 'sign-in'),
      disabled: reactions('account-disabled', 'risc', p, 'sign-in'),
      enabled: reactions('account-enabled', 'risc', p, 'sign-in'),
      device: reactions('device-compliance-change', 'caep', p, 'sign-in')
    };
    const only = {
      disabled: reactions('account-disabled', 'risc', 'federation:mdm',
                          'signals-only'),
      revoked: reactions('session-revoked', 'caep', 'federation:mdm',
                         'signals-only'),
      enabled: reactions('account-enabled', 'risc', 'federation:mdm',
                         'signals-only'),
      device: reactions('device-compliance-change', 'caep', 'federation:mdm',
                        'signals-only')
    };
    const ownConsole = reactions('account-disabled', 'risc', 'admin-console');
    note(has(signIn.revoked, R.END_PARTNER_SESSIONS) &&
         !has(signIn.revoked, R.END_PERSON_SESSIONS) &&
         has(signIn.disabled, R.BLOCK_RELATIONSHIP) &&
         !has(signIn.disabled, R.DISABLE_ACCOUNT) &&
         has(signIn.enabled, R.UNBLOCK_RELATIONSHIP) &&
         has(signIn.device, R.SET_DEVICE_COMPLIANCE),
         'A1. a sign-in partner may end the sessions it started, block and ' +
         'unblock its sign-ins and set a device\'s compliance — and neither ' +
         'end every session nor lock the account',
         JSON.stringify(signIn));
    note(only.disabled.length === 0 && only.revoked.length === 0 &&
         JSON.stringify(only.enabled) ===
           JSON.stringify([R.ENABLE_ACCOUNT]) &&
         JSON.stringify(only.device) ===
           JSON.stringify([R.SET_DEVICE_COMPLIANCE]),
         'A2. a signals-only partner\'s events are recorded and nothing more ' +
         '(#374), but for lifting its own lock and a device\'s compliance',
         JSON.stringify(only));
    note(!has(ownConsole, R.BLOCK_RELATIONSHIP) &&
         !has(ownConsole, R.DISABLE_ACCOUNT) &&
         !has(ownConsole, R.END_PARTNER_SESSIONS),
         'A3. this service\'s own receivers get none of a partner\'s ' +
         'reactions', JSON.stringify(ownConsole));

    // --- the fake partner ----------------------------------------------------
    const ISS = 'https://tx.test/realm/partner';
    const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = Object.assign(pair.publicKey.export({ format: 'jwk' }),
                              { kid: 'tx-1', alg: 'ES256', use: 'sig' });
    const sign = function (claims, over) {
      const header = Object.assign({ alg: 'ES256', kid: 'tx-1',
                                     typ: 'secevent+jwt' }, over || {});
      const input = Buffer.from(JSON.stringify(header)).toString('base64url') +
        '.' + Buffer.from(JSON.stringify(claims)).toString('base64url');
      const sig = crypto.sign('sha256', Buffer.from(input),
        { key: pair.privateKey, dsaEncoding: 'ieee-p1363' });
      return input + '.' + sig.toString('base64url');
    };
    const RISC = 'https://schemas.openid.net/secevent/risc/event-type/';
    const CAEP = 'https://schemas.openid.net/secevent/caep/event-type/';
    const set = function (event, subject, over, payload) {
      const claims = Object.assign({ iss: ISS, aud: 'realm-receiver',
        jti: crypto.randomBytes(8).toString('hex'),
        iat: Math.floor(Date.now() / 1000), sub_id: subject,
        events: {} }, over || {});
      claims.events[(/^(session-revoked|device-)/.test(event) ? CAEP
                                                               : RISC) +
                    event] = payload || {};
      return claims;
    };
    const requests = [];
    const polls = [];
    const doc = { issuer: ISS, jwks_uri: 'https://tx.test/jwks',
      configuration_endpoint: 'https://tx.test/stream',
      status_endpoint: 'https://tx.test/status',
      add_subject_endpoint: 'https://tx.test/subjects/add',
      remove_subject_endpoint: 'https://tx.test/subjects/remove',
      verification_endpoint: 'https://tx.test/verify',
      delivery_methods_supported: ['urn:ietf:rfc:8935',
                                   'urn:ietf:rfc:8936'] };
    let docIssuer = 'https://someone-else.test';
    const answer = function (status, json) {
      return Promise.resolve({ ok: status >= 200 && status < 300,
        status: status, body: Buffer.from(json ? JSON.stringify(json) : ''),
        why: status >= 300 ? 'it answered ' + status : '' });
    };
    const fedHttp = { fetchPublished: function (url, opts) {
      const o = opts || {};
      requests.push({ url: url, method: o.method || 'GET',
                      body: o.body ? JSON.parse(o.body.charAt(0) === '{'
                        ? o.body : '{}') : null,
                      raw: o.body || '',
                      auth: (o.headers || {}).Authorization || '' });
      if (/ssf-configuration/.test(url)) {
        return answer(200, Object.assign({}, doc, { issuer: docIssuer }));
      }
      if (url === 'https://tx.test/token') {
        return answer(200, { access_token: 'tx-token', expires_in: 300 });
      }
      if (url === 'https://tx.test/stream' && o.method === 'POST') {
        return answer(201, { stream_id: 's-1', aud: 'realm-receiver',
          delivery: { method: 'urn:ietf:rfc:8936',
                      endpoint_url: 'https://tx.test/poll' } });
      }
      if (/^https:\/\/tx\.test\/stream\?/.test(url) &&
          o.method === 'DELETE') {
        return answer(204, null);
      }
      if (url === 'https://tx.test/poll') {
        const next = polls.shift() || { sets: {}, moreAvailable: false };
        return answer(200, next);
      }
      return answer(404, { error: 'not here' });
    } };
    const jwks = { ensure: function () {
      return Promise.resolve({ ok: true, jwks: { keys: [jwk] }, why: '' });
    } };
    // The sessions a partner started, and a local one, and another
    // partner's; and a sign-out that records what it is asked to end.
    const sessions = new Map();
    const ended = [];
    const session = function (id, relationship, sid) {
      sessions.set(id, { id: id, user: { username: 'ft-alice' },
        fedPartnerSession: relationship ? { relationship: relationship,
                                            sid: sid } : undefined });
    };
    session('s1', 'partner', 'sid-1');
    session('s2', 'partner', 'sid-2');
    session('s3', '', '');
    session('s4', 'other', 'sid-x');
    const authn = { sessions: sessions, sessionEnded: function (one) {
      return ended.indexOf(one.id) >= 0;
    } };
    const logout = {
      endPartnerSession: function (one) {
        ended.push(one.id);
        return { terminated: [one.id] };
      },
      terminate: function () {
        ended.push('EVERYTHING');
        return { terminated: [] };
      }
    };
    const compliance = [];
    const devices = {
      byId: function (id) {
        return id === 'dev-1' ? { id: 'dev-1' } : null;
      },
      setCompliance: function (id, status) {
        compliance.push(id + '=' + status);
      }
    };
    const deps = Object.assign(module_.SsfTransmitters.defaultDeps(), {
      fedHttp: function () {
        return fedHttp;
      },
      jwks: function () {
        return jwks;
      },
      authn: function () {
        return authn;
      },
      logout: function () {
        return logout;
      },
      devices: function () {
        return devices;
      }
    });
    const rx = new module_.SsfTransmitters(deps);

    // --- the relationship, in the real directory ---------------------------
    ldap.createUser('ft-alice', { invent: false,
      attributes: { mail: 'alice@ft.test' } });
    ldap.createUser('ft-bob', { invent: false });
    const made = federation.create({ fedId: 'partner',
      fedRole: 'service-provider', fedProtocol: 'oidc', fedPeer: ISS });
    const setField = function (id, field, value) {
      return federation.update(id, { field: field, value: value });
    };
    [['fedEnabled', 'TRUE'], ['fedSignalsEnabled', 'TRUE'],
     ['fedSignalsTokenUrl', 'https://tx.test/token'],
     ['fedSignalsClientId', 'realm-receiver'],
     ['fedSignalsClientSecret', 'shh']].forEach(function (one) {
      setField('partner', one[0], one[1]);
    });
    federation.writeFederationLink('ft-alice',
      fedLinks.linkValue('partner', ISS, 'ext-alice'), true, {});
    const rel = function () {
      return federation.get('partner');
    };

    // --- B. discovery ---------------------------------------------------------
    const wrong = await rx.act({ action: 'signals-discover', id: 'partner' },
                               { actor: 'tester' });
    docIssuer = ISS;
    const found = await rx.act({ action: 'signals-discover', id: 'partner' },
                               { actor: 'tester' });
    federation.create({ fedId: 'quiet', fedRole: 'service-provider',
                        fedProtocol: 'oidc', fedPeer: ISS });
    const off = await rx.act({ action: 'signals-discover', id: 'quiet' },
                             { actor: 'tester' });
    note(made.ok && !wrong.ok && found.ok &&
         requests[0].url ===
           'https://tx.test/.well-known/ssf-configuration/realm/partner' &&
         found.signals.credential.secretHeld &&
         JSON.stringify(found).indexOf('shh') < 0 &&
         !off.ok && /fedSignalsEnabled/.test(off.errors[0]),
         'B1. discovery at the inserted path from fedPeer; a document ' +
         'naming another issuer is refused; the secret is held and never ' +
         'shown; a relationship whose signals are off is refused',
         JSON.stringify([made.errors, wrong.errors, found.ok, off.errors]));

    // --- C. a session-revoked naming one session ---------------------------
    const stream = await rx.act({ action: 'signals-create-stream',
                                  id: 'partner' }, { actor: 'tester' });
    const tokenCall = requests.filter(function (r) {
      return r.url === 'https://tx.test/token';
    })[0];
    const revoked = set('session-revoked', { format: 'complex',
      user: { format: 'iss_sub', iss: ISS, sub: 'ext-alice' },
      session: { format: 'opaque', id: 'sid-1' } },
      {}, { initiating_entity: 'user' });
    await rx.receive(rel(), sign(revoked), 'push');
    note(stream.ok && stream.signals.streamId === 's-1' && tokenCall &&
         /client_secret=shh/.test(tokenCall.raw) &&
         JSON.stringify(ended) === JSON.stringify(['s1']),
         'C1. the stream is created with the relationship\'s own signals ' +
         'client; a session-revoked naming one session the partner started ' +
         'ends that one and nothing else', JSON.stringify([stream.errors,
                                                           ended]));

    // --- D. a polled account-disabled ---------------------------------------
    const disabled = set('account-disabled',
                         { format: 'iss_sub', iss: ISS, sub: 'ext-alice' });
    polls.push({ sets: { [disabled.jti]: sign(disabled) },
                 moreAvailable: false });
    const polled = await rx.act({ action: 'signals-poll-now',
                                  id: 'partner' }, { actor: 'tester' });
    const pollCalls = requests.filter(function (r) {
      return r.url === 'https://tx.test/poll';
    });
    note(polled.ok && !!fedBlocks.blockOf('partner', 'ft-alice') &&
         !accountState.isDisabled('ft-alice') &&
         JSON.stringify(ended) === JSON.stringify(['s1', 's2']) &&
         pollCalls.length >= 2 && pollCalls[0].auth === 'Bearer tx-token' &&
         JSON.stringify(pollCalls[1].body.ack) ===
           JSON.stringify([disabled.jti]),
         'D1. a polled account-disabled blocks the partner\'s sign-ins of ' +
         'the linked person and ends the rest of the sessions it started — ' +
         'not the local one, not another partner\'s — leaves the account ' +
         'enabled, and is acknowledged next',
         JSON.stringify([polled, ended, pollCalls.map(function (c) {
           return c.body;
         })]));

    // --- E. the block at sign-in --------------------------------------------
    const signInAs = function () {
      return fedSp.subjectDecision(rel(), { subject: 'ext-alice',
                                            issuer: ISS },
                                   { username: 'ext-alice' });
    };
    const blocked = signInAs();
    await rx.receive(rel(), sign(set('account-enabled',
      { format: 'iss_sub', iss: ISS, sub: 'ext-alice' })), 'push');
    const unblocked = signInAs();
    note(!blocked.ok && blocked.code === 'STS-FED-0156' && unblocked.ok &&
         unblocked.username === 'ft-alice' &&
         !fedBlocks.blockOf('partner', 'ft-alice'),
         'E1. the block refuses the person\'s sign-in through that ' +
         'relationship (STS-FED-0156); the partner\'s account-enabled lifts ' +
         'it', JSON.stringify([blocked, unblocked]));

    // --- F. refusals --------------------------------------------------------
    const again = await rx.receive(rel(), sign(disabled), 'push');
    const tampered = set('account-purged',
                         { format: 'iss_sub', iss: ISS, sub: 'ext-alice' });
    const bad = sign(tampered).slice(0, -6) + 'AAAAAA';
    const devBad = await rx.receive(rel(), bad, 'push');
    const devRow = rx.report({}).received.filter(function (r) {
      return r.jti === tampered.jti;
    })[0];
    config.setOverride('ssf.receiveRequireSignature', true);
    const tampered2 = set('account-purged',
                          { format: 'iss_sub', iss: ISS, sub: 'ext-alice' });
    const strictBad = await rx.receive(rel(),
      sign(tampered2).slice(0, -6) + 'AAAAAA', 'push');
    config.clearOverride('ssf.receiveRequireSignature');
    const wrongIss = await rx.receive(rel(), sign(set(
      'account-purged', { format: 'iss_sub', iss: ISS, sub: 'ext-alice' },
      { iss: 'https://evil.test' })), 'push');
    const wrongAud = await rx.receive(rel(), sign(set(
      'account-purged', { format: 'iss_sub', iss: ISS, sub: 'ext-alice' },
      { aud: 'somebody-else' })), 'push');
    note(again.ok && again.duplicate &&
         devBad.ok && devRow && devRow.verified === false &&
         (devRow.reactions || []).length === 0 &&
         !strictBad.ok && strictBad.err === 'invalid_key' &&
         !wrongIss.ok && wrongIss.err === 'invalid_issuer' &&
         !wrongAud.ok && wrongAud.err === 'invalid_audience',
         'F1. a replay is acknowledged and not acted on; a bad signature ' +
         'is recorded and acted on in no way, and refused where signatures ' +
         'are required; the wrong iss and aud are refused',
         JSON.stringify([again, devBad, devRow, strictBad, wrongIss,
                         wrongAud]));

    // --- G. an email subject ------------------------------------------------
    const byMail = { format: 'email', email: 'alice@ft.test' };
    const refused = rx.personFor(rel(), byMail);
    setField('partner', 'fedSignalEmailMatch', 'TRUE');
    const allowed = rx.personFor(rel(), byMail);
    note(!refused.username && allowed.username === 'ft-alice',
         'G1. an email subject names nobody unless the relationship allows ' +
         'it', JSON.stringify([refused, allowed]));

    // --- H. a signals-only partner (#374) ----------------------------------
    const asIdp = federation.create({ fedId: 'mdm-idp',
      fedRole: 'identity-provider', fedProtocol: 'ssf' });
    const mdm = federation.create({ fedId: 'mdm',
      fedRole: 'service-provider', fedProtocol: 'ssf',
      fedPeer: 'https://mdm.test' });
    setField('mdm', 'fedEnabled', 'TRUE');
    const fields = federation.fieldsForRole('service-provider', 'set', 'ssf')
      .map(function (f) {
        return f.name;
      });
    const signInField = setField('mdm', 'fedSsoUrl', 'https://mdm.test/x');
    federation.writeFederationLink('ft-bob',
      fedLinks.linkValue('mdm', 'https://hr.test', 'emp-7'), true, {});
    federation.writeFederationLink('ft-bob',
      fedLinks.linkValue('mdm', 'opaque', 'badge-9'), true, {});
    const mdmRec = federation.get('mdm');
    const byIssSub = rx.personFor(mdmRec, { format: 'iss_sub',
      iss: 'https://hr.test', sub: 'emp-7' });
    const byOpaque = rx.personFor(mdmRec, { format: 'opaque',
                                            id: 'badge-9' });
    note(!asIdp.ok && mdm.ok && federation.signalsEnabled(mdmRec) &&
         !federation.signsIn(mdmRec) &&
         fields.indexOf('fedSignalsIssuer') >= 0 &&
         fields.indexOf('fedSsoUrl') < 0 && !signInField.ok &&
         federation.signInOptions().every(function (o) {
           return o.id !== 'mdm';
         }) &&
         byIssSub.username === 'ft-bob' && byOpaque.username === 'ft-bob',
         'H1. an ssf relationship is service-provider only, takes its ' +
         'signals fields alone, is offered to no sign-in, and names its ' +
         'people by the iss_sub and opaque links an administrator wrote',
         JSON.stringify([asIdp.errors, signInField.errors, byIssSub,
                         byOpaque]));
    rx['save'](Object.assign(rx.stateOf('mdm'), {
      config: Object.assign({}, doc, { issuer: 'https://mdm.test' }),
      streamAud: ['realm-receiver'], streamId: 'm-1', state: 'streaming' }));
    const mdmSet = function (event, subject, payload) {
      return sign(set(event, subject, { iss: 'https://mdm.test' }, payload));
    };
    const before = ended.length;
    await rx.receive(federation.get('mdm'), mdmSet('account-disabled',
      { format: 'opaque', id: 'badge-9' }), 'push');
    await rx.receive(federation.get('mdm'), mdmSet(
      'device-compliance-change', { format: 'iss_sub',
        iss: 'https://mdm.test', sub: 'dev-1' },
      { current_status: 'not-compliant', previous_status: 'compliant' }),
      'push');
    note(!accountState.isDisabled('ft-bob') &&
         !fedBlocks.blockOf('mdm', 'ft-bob') && ended.length === before &&
         JSON.stringify(compliance) === JSON.stringify(['dev-1=not-compliant']),
         'H2. a signals-only partner\'s account-disabled is recorded and ' +
         'does nothing; its device-compliance-change sets the device',
         JSON.stringify([ended, compliance]));

    // --- I. the push endpoint -----------------------------------------------
    const res = function () {
      return { statusCode: 0, body: null,
        status: function (s) {
          this.statusCode = s;
          return this;
        },
        json: function (b) {
          this.body = b;
          return this;
        },
        end: function () {
          return this;
        },
        set: function () {
          return this;
        },
        setHeader: function () {
          return this;
        },
        locals: {} };
    };
    rx['save'](Object.assign(rx.stateOf('partner'), {
      delivery: 'push', pushSecretDigest:
        module_.SsfTransmitters.digest('Bearer right') }));
    const wrongHeader = res();
    await rx.pushRoute({ params: { id: 'partner' },
                         headers: { authorization: 'Bearer wrong' },
                         body: 'x' }, wrongHeader);
    setField('partner', 'fedEnabled', 'FALSE');
    const disabledRel = res();
    await rx.pushRoute({ params: { id: 'partner' },
                         headers: { authorization: 'Bearer right' },
                         body: 'x' }, disabledRel);
    setField('partner', 'fedEnabled', 'TRUE');
    note(wrongHeader.statusCode === 401 &&
         wrongHeader.body.err === 'authentication_failed' &&
         disabledRel.statusCode === 404,
         'I1. the push endpoint refuses an Authorization header it did not ' +
         'give, and a disabled relationship',
         JSON.stringify([wrongHeader.body, disabledRel.body]));

    // --- J. forgetting ------------------------------------------------------
    fedBlocks.block('partner', 'ft-alice', { event: 'test' });
    const forgot = await rx.forget(rel(), { actor: 'tester' });
    note(forgot.blocks === 1 && !fedBlocks.blockOf('partner', 'ft-alice') &&
         rx.stateOf('partner').state === 'new',
         'J1. forgetting a relationship lifts its blocks and drops its ' +
         'stream state', JSON.stringify(forgot));

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
  const out = path.join(os.tmpdir(), 'ssf-transmitters-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', FT_ROOT: ROOT, FT_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died first; its exit and stderr are below.
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
  name: 'ssf_transmitters',
  describe: 'a federation partner\'s Shared Signals (#153, #373, #374): ' +
            'the policy by relationship kind, discovery, the partner\'s own ' +
            'sessions ended, the sign-in block and its lifting, refusals, ' +
            'the email rule, a signals-only partner, the push endpoint, ' +
            'forgetting',
  run: run
};
