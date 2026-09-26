'use strict';
//
// File: ssf_transmitters.js
//
// ===========================================================================
// THIS REALM AS THE RECEIVER OF A FOREIGN SSF TRANSMITTER (#153,
// 2026-09-26), in a child process with the whole stack loaded: the
// receiver built with a fake transmitter (its discovery document, token
// endpoint, stream endpoint and poll endpoint) and fake federation
// register, and this service's real signal-response policy, sign-out and
// account lock.
//
//   A. the policy: a foreign surface is permitted the three foreign
//      reactions, this service's own receivers none of them;
//   B. registration: a document naming another issuer is refused; the
//      right one is kept, and no secret is shown;
//   C. the stream, and a poll: account-disabled verified, mapped through
//      the relationship's link, the account disabled, acknowledged next;
//   D. refusals: a replay is not acted on twice; a bad signature is
//      recorded and not acted on (development), refused where signatures
//      are required; the wrong iss and aud are refused;
//   E. account-enabled from another transmitter enables nothing; from the
//      one that disabled, it does;
//   F. an email subject names nobody unless the relationship allows it;
//   G. the push endpoint refuses an Authorization header it did not give.
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
    const helpers = require(ROOT + '/common/helpers');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const pep = require(ROOT + '/xacml/xacml_signal_pep');
    const accountState = require(ROOT + '/common/account_state');
    const module_ = require(ROOT + '/ssf/ssf_transmitters');
    config.setOverride('ssf.actOnSignalsInDevelopment', true);

    // --- A. the policy ------------------------------------------------------
    const reactions = function (event, family, surface) {
      return pep.decide({ event: event, family: family, surface: surface,
                          level: '' }).reactions;
    };
    const foreign = reactions('account-disabled', 'risc', 'foreign:tx');
    const ownConsole = reactions('account-disabled', 'risc', 'admin-console');
    note(foreign.indexOf('signal-disable-account') >= 0 &&
         reactions('account-enabled', 'risc', 'foreign:tx')
           .indexOf('signal-enable-account') >= 0 &&
         reactions('session-revoked', 'caep', 'foreign:tx')
           .indexOf('signal-end-person-sessions') >= 0 &&
         ownConsole.indexOf('signal-disable-account') < 0 &&
         ownConsole.indexOf('signal-end-person-sessions') < 0,
         'A1. a foreign surface may end sessions, disable and enable; the ' +
         'console\'s own receiver may do none of those',
         JSON.stringify([foreign, ownConsole]));

    // --- the fake transmitter ------------------------------------------------
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
    const set = function (event, subject, over) {
      const claims = Object.assign({ iss: ISS, aud: 'realm-receiver',
        jti: crypto.randomBytes(8).toString('hex'),
        iat: Math.floor(Date.now() / 1000), sub_id: subject,
        events: {} }, over || {});
      claims.events[RISC + event] = {};
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
      if (url === 'https://tx.test/poll') {
        const next = polls.shift() || { sets: {}, moreAvailable: false };
        return answer(200, next);
      }
      return answer(404, { error: 'not here' });
    } };
    const jwks = { ensure: function () {
      return Promise.resolve({ ok: true, jwks: { keys: [jwk] }, why: '' });
    } };
    const rel = { fedId: 'partner', fedPeer: ISS,
                  fedSignalEmailMatch: 'FALSE' };
    ldap.createUser('ft-alice', { invent: false,
      attributes: { mail: 'alice@ft.test' } });
    const federation = {
      get: function (id) {
        return id === 'partner' ? rel : null;
      },
      peopleLinkedBy: function (value) {
        return value === 'partner ' + ISS + ' ext-alice'
          ? [{ username: 'ft-alice' }] : [];
      },
      peopleByMail: function (mail) {
        return mail === 'alice@ft.test' ? [{ username: 'ft-alice' }] : [];
      },
      boolOf: function (v) {
        return String(v).toUpperCase() === 'TRUE';
      }
    };
    const links = { linkValue: function (f, i, s) {
      return f + ' ' + i + ' ' + s;
    } };
    const deps = Object.assign(module_.SsfTransmitters.defaultDeps(), {
      fedHttp: function () {
        return fedHttp;
      },
      jwks: function () {
        return jwks;
      },
      federation: function () {
        return federation;
      },
      links: function () {
        return links;
      }
    });
    const rx = new module_.SsfTransmitters(deps);

    // --- B. registration ----------------------------------------------------
    const addBody = { action: 'add', id: 'partner', issuer: ISS,
      federationId: 'partner', delivery: 'poll',
      tokenEndpoint: 'https://tx.test/token', clientId: 'realm-receiver',
      clientSecret: 'shh' };
    const wrong = await rx.act(addBody, { actor: 'tester' });
    docIssuer = ISS;
    const added = await rx.act(addBody, { actor: 'tester' });
    note(!wrong.ok && added.ok &&
         requests[0].url ===
           'https://tx.test/.well-known/ssf-configuration/realm/partner' &&
         added.transmitter.credential.secretHeld &&
         JSON.stringify(added).indexOf('shh') < 0,
         'B1. discovery at the inserted path; a document naming another ' +
         'issuer is refused; the secret is held and never shown',
         JSON.stringify([wrong.errors, added.ok]));

    // --- C. the stream, and a poll ------------------------------------------
    const made = await rx.act({ action: 'create-stream', id: 'partner' },
                              { actor: 'tester' });
    const disabled = set('account-disabled',
                         { format: 'iss_sub', iss: ISS, sub: 'ext-alice' });
    polls.push({ sets: { [disabled.jti]: sign(disabled) },
                 moreAvailable: false });
    const polled = await rx.act({ action: 'poll-now', id: 'partner' },
                                { actor: 'tester' });
    const pollCalls = requests.filter(function (r) {
      return r.url === 'https://tx.test/poll';
    });
    note(made.ok && made.transmitter.streamId === 's-1' && polled.ok &&
         accountState.isDisabled('ft-alice') &&
         pollCalls.length >= 2 && pollCalls[0].auth === 'Bearer tx-token' &&
         JSON.stringify(pollCalls[1].body.ack) ===
           JSON.stringify([disabled.jti]),
         'C1. the stream is created; a polled account-disabled about the ' +
         'linked person disables them, and is acknowledged next',
         JSON.stringify([made.ok, polled, pollCalls.map(function (c) {
           return c.body;
         })]));

    // --- D. refusals --------------------------------------------------------
    const record = rx.get('partner');
    const again = await rx.receive(record, sign(disabled), 'push');
    const tampered = set('account-purged',
                         { format: 'iss_sub', iss: ISS, sub: 'ext-alice' });
    const bad = sign(tampered).slice(0, -6) + 'AAAAAA';
    const devBad = await rx.receive(rx.get('partner'), bad, 'push');
    const devRow = rx.report({}).received.filter(function (r) {
      return r.jti === tampered.jti;
    })[0];
    config.setOverride('ssf.receiveRequireSignature', true);
    const tampered2 = set('account-purged',
                          { format: 'iss_sub', iss: ISS, sub: 'ext-alice' });
    const strictBad = await rx.receive(rx.get('partner'),
      sign(tampered2).slice(0, -6) + 'AAAAAA', 'push');
    config.clearOverride('ssf.receiveRequireSignature');
    const wrongIss = await rx.receive(rx.get('partner'), sign(set(
      'account-purged', { format: 'iss_sub', iss: ISS, sub: 'ext-alice' },
      { iss: 'https://evil.test' })), 'push');
    const wrongAud = await rx.receive(rx.get('partner'), sign(set(
      'account-purged', { format: 'iss_sub', iss: ISS, sub: 'ext-alice' },
      { aud: 'somebody-else' })), 'push');
    note(again.ok && again.duplicate &&
         devBad.ok && devRow && devRow.verified === false &&
         (devRow.reactions || []).length === 0 &&
         !strictBad.ok && strictBad.err === 'invalid_key' &&
         !wrongIss.ok && wrongIss.err === 'invalid_issuer' &&
         !wrongAud.ok && wrongAud.err === 'invalid_audience',
         'D1. a replay is acknowledged and not acted on; a bad signature ' +
         'is recorded and acted on in no way, and refused where signatures ' +
         'are required; the wrong iss and aud are refused',
         JSON.stringify([again, devBad, devRow, strictBad, wrongIss,
                         wrongAud]));

    // --- E. account-enabled -------------------------------------------------
    const other = Object.assign({}, rx.get('partner'), { id: 'other' });
    const enableFromOther = set('account-enabled',
                                { format: 'iss_sub', iss: ISS,
                                  sub: 'ext-alice' });
    await rx.receive(other, sign(enableFromOther), 'push');
    const stillDisabled = accountState.isDisabled('ft-alice');
    await rx.receive(rx.get('partner'), sign(set('account-enabled',
      { format: 'iss_sub', iss: ISS, sub: 'ext-alice' })), 'push');
    note(stillDisabled && !accountState.isDisabled('ft-alice'),
         'E1. account-enabled from another transmitter enables nothing; ' +
         'from the one that disabled, it does');

    // --- F. an email subject ------------------------------------------------
    const byMail = { format: 'email', email: 'alice@ft.test' };
    const refused = rx.personFor(rx.get('partner'), byMail);
    rel.fedSignalEmailMatch = 'TRUE';
    const allowed = rx.personFor(rx.get('partner'), byMail);
    note(!refused.username && allowed.username === 'ft-alice',
         'F1. an email subject names nobody unless the relationship allows ' +
         'it', JSON.stringify([refused, allowed]));

    // --- G. the push endpoint -----------------------------------------------
    const pushRecord = Object.assign(rx.get('partner'), {
      delivery: 'push', pushSecretDigest:
        module_.SsfTransmitters.digest('Bearer right') });
    rx['save'](pushRecord);
    const res = { statusCode: 0, body: null,
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
    await rx.pushRoute({ params: { id: 'partner' },
                         headers: { authorization: 'Bearer wrong' },
                         body: 'x' }, res);
    note(res.statusCode === 401 && res.body.err === 'authentication_failed',
         'G1. the push endpoint refuses an Authorization header it did not ' +
         'give', JSON.stringify(res.body));

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
  describe: 'this realm as the receiver of a foreign SSF transmitter ' +
            '(#153): the policy, registration, a stream and a poll, ' +
            'refusals, enable only by the transmitter that disabled, the ' +
            'email subject rule, the push endpoint',
  run: run
};
