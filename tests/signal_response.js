'use strict';
//
// File: signal_response.js
//
// ===========================================================================
// THIS SERVICE'S OWN SURFACES ACTING ON THE SIGNALS THEY RECEIVE (#62,
// 2026-09-22; rcbj: "surfaces act on signals"). The console and the portal
// are registered receivers of this service's own transmitter
// (`ssf/ssf_receivers.ts`); until now they only recorded what arrived.
//
//   A. THE POLICY: the built-in `signal-response` has its two rules, and
//      both shapes survive the XML and ALFA round trips.
//   B. ITS DECISIONS (`xacml/xacml_signal_pep.ts`): session-revoked,
//      credential-change and RISC account-disabled end the receiving
//      surface's sessions; a risk-level-change does at HIGH and not at LOW;
//      session-established and token-claims-change do not.
//   C. THE RECEIVER, with a real signed SET through `accept()`: development
//      observes and ends nothing; `ssf.actOnSignalsInDevelopment` on, the
//      console's own session for the person named is ended — once; an event
//      about somebody else ends nothing; an UNVERIFIED SET is acted on in no
//      way (#117's rule), even while it is accepted; an event the policy does
//      not permit ends nothing.
//   D. A DISABLED POLICY decides nothing, and nothing is ended.
//   F. PRODUCT MODE REFUSES AN UNVERIFIED SET (#117) at the console's
//      receiver and at /ssf/receive, whatever ssf.receiveRequireSignature
//      says; development still accepts one at /ssf/receive and records it.
//
// In a child process, because it loads the whole protocol stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'signal_response',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.SR_ROOT;
  const OUT = process.env.SR_OUT;
  const fs = require('fs');
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
    const authn = require(ROOT + '/authn/authn');
    const receivers = require(ROOT + '/ssf/ssf_receivers');
    const events = require(ROOT + '/ssf/ssf_events');
    const templates = require(ROOT + '/xacml/xacml_templates');
    const xacmlXml = require(ROOT + '/xacml/xacml_xml');
    const alfa = require(ROOT + '/xacml/xacml_alfa');
    const xacmlStore = require(ROOT + '/xacml/xacml_store');
    const pep = require(ROOT + '/xacml/xacml_signal_pep');

    // --- A. the policy ------------------------------------------------------
    const plain = templates.build('signal-response', {},
                                  { name: 'signal-response' });
    const slugs = (plain.policy ? plain.policy.rules : []).map(function (r) {
      return r.id.split(':rule:')[1];
    }).join(',');
    note(slugs === 'end-sessions,end-sessions-on-risk',
         'A1. the built-in policy ends sessions on the listed events and on ' +
         'a risk-level-change to HIGH', slugs);
    let roundTrips = '';
    try {
      xacmlXml.parsePolicy(xacmlXml.writePolicy(plain.policy));
      alfa.parse(alfa.write(plain.policy));
    } catch (e) {
      roundTrips = e.message;
    }
    note(!roundTrips, 'A2. it survives the XML and ALFA round trips',
         roundTrips);

    // --- B. its decisions --------------------------------------------------
    const ends = function (event, family, level) {
      return pep.decide({ event: event, family: family,
                          surface: 'admin-console', level: level || '' })
        .reactions.indexOf('signal-end-sessions') >= 0;
    };
    note(ends('session-revoked', 'caep') &&
         ends('credential-change', 'caep') &&
         ends('account-disabled', 'risc'),
         'B1. session-revoked, credential-change and account-disabled end ' +
         'the receiving surface\'s sessions');
    note(ends('risk-level-change', 'caep', 'HIGH') &&
         !ends('risk-level-change', 'caep', 'LOW') &&
         !ends('risk-level-change', 'caep', ''),
         'B2. a risk-level-change does at HIGH, and not at LOW or with none');
    note(!ends('session-established', 'caep') &&
         !ends('token-claims-change', 'caep'),
         'B3. session-established and token-claims-change end nothing');

    // --- C. the receiver ----------------------------------------------------
    receivers.seedStreams();
    const record = receivers.streamFor('admin-console');
    note(!!record, 'C0. the console has its stream',
         JSON.stringify(receivers.status ? receivers.status() : null));
    ldap.createUser('sr-erin', { invent: false });
    ldap.createUser('sr-frank', { invent: false });
    const erin = String(helpers.subjectForName('sr-erin'));
    const frank = String(helpers.subjectForName('sr-frank'));
    const consoleSession = function (username) {
      const res = { headers: {}, setHeader: function (k, v) {
        this.headers[k] = v;
      } };
      return authn.startRelyingPartySession({ res: res, username: username,
        claims: { sub: String(helpers.subjectForName(username)),
                  preferred_username: username },
        surface: 'admin', label: 'Admin console',
        clientId: 'sts-admin-console', cookie: 'sts_admin' });
    };
    const push = function (short, subjectSub, payload, tamper) {
      const prefix = /^account-|^sessions-revoked|^credential-compromise/
        .test(short) ? events.RISC_PREFIX : events.CAEP_PREFIX;
      const claims = events.buildSet({ uri: prefix + short,
        issuer: record.iss, audience: 'sts-admin-console',
        subject: { format: 'iss_sub', iss: record.iss, sub: subjectSub },
        payload: Object.assign({ event_timestamp:
          Math.floor(Date.now() / 1000) }, payload || {}) });
      let token = events.signSetSync(claims);
      if (tamper) {
        token = token.slice(0, -4) + (token.slice(-4) === 'AAAA' ? 'BBBB'
                                                                  : 'AAAA');
      }
      const req = { headers: {
        authorization: record.delivery.authorization_header,
        'content-type': 'application/secevent+jwt' },
        body: token, res: {} };
      return receivers.accept('admin-console', req);
    };
    const endedOf = function (answer) {
      return ((answer.entry && answer.entry.reactions) || [])
        .reduce(function (n, r) {
          return n + (Number(r.ended) || 0);
        }, 0);
    };

    consoleSession('sr-erin');
    const observed = push('session-revoked', erin);
    note(observed.status === 202 && observed.entry.verified &&
         observed.entry.reactions.length === 1 &&
         observed.entry.reactions[0].observed === true &&
         endedOf(observed) === 0,
         'C1. in development a verified session-revoked is recorded with ' +
         'what the policy permitted, and ends nothing',
         JSON.stringify(observed.entry && observed.entry.reactions));
    config.setOverride('ssf.actOnSignalsInDevelopment', true);
    const taken = push('session-revoked', erin);
    const again = push('session-revoked', erin);
    note(endedOf(taken) === 1 && endedOf(again) === 0,
         'C2. with ssf.actOnSignalsInDevelopment on, the console\'s own ' +
         'session for the person named is ended — once',
         JSON.stringify([taken.entry.reactions, again.entry.reactions]));
    consoleSession('sr-erin');
    const other = push('credential-change', frank);
    note(endedOf(other) === 0 && other.entry.reactions.length === 1,
         'C3. an event about somebody else ends nothing of theirs',
         JSON.stringify(other.entry.reactions));
    const forged = push('session-revoked', erin, {}, true);
    note(forged.status === 202 && forged.entry.verified === false &&
         forged.entry.reactions.length === 0,
         'C4. an UNVERIFIED SET is accepted and recorded (the setting says ' +
         'so) and acted on in no way (#117)',
         JSON.stringify({ status: forged.status,
                          verified: forged.entry.verified,
                          reactions: forged.entry.reactions }));
    const claimsChange = push('token-claims-change', erin,
                              { claims: { role: 'x' } });
    note(claimsChange.entry.reactions.length === 0,
         'C5. an event the policy does not permit ends nothing',
         JSON.stringify(claimsChange.entry.reactions));
    const high = push('risk-level-change', erin, {
      current_level: 'HIGH', previous_level: 'LOW', principal: 'USER' });
    note(endedOf(high) === 1,
         'C6. a risk-level-change to HIGH ends the person\'s console session ' +
         '(the one C3 left standing)', JSON.stringify(high.entry.reactions));

    // --- E. what the event says narrows what it ends (2026-09-23) ----------
    // A console session DERIVED from a named sign-on session, and one that is
    // not; a session-revoked naming that sign-on session ends the first only.
    const derived = function (username, parent) {
      const res = { headers: {}, setHeader: function (k, v) {
        this.headers[k] = v;
      } };
      return authn.startRelyingPartySession({ res: res, username: username,
        parent: parent,
        claims: { sub: String(helpers.subjectForName(username)),
                  preferred_username: username },
        surface: 'admin', label: 'Admin console',
        clientId: 'sts-admin-console', cookie: 'sts_admin' });
    };
    const pushAbout = function (short, subject, payload) {
      const claims = events.buildSet({ uri: events.CAEP_PREFIX + short,
        issuer: record.iss, audience: 'sts-admin-console',
        subject: subject,
        payload: Object.assign({ event_timestamp:
          Math.floor(Date.now() / 1000) }, payload || {}) });
      const req = { headers: {
        authorization: record.delivery.authorization_header,
        'content-type': 'application/secevent+jwt' },
        body: events.signSetSync(claims), res: {} };
      return receivers.accept('admin-console', req);
    };
    const bySession = function (sid) {
      return { format: 'complex',
               user: { format: 'iss_sub', iss: record.iss, sub: erin },
               session: { format: 'opaque', id: sid } };
    };
    // Whatever C and D left of erin's console sessions is ended first.
    push('session-revoked', erin);
    derived('sr-erin', 'sso-parent-1');
    derived('sr-erin', 'sso-parent-2');
    const one = pushAbout('session-revoked', bySession('sso-parent-1'),
                          { initiating_entity: 'user' });
    const two = pushAbout('session-revoked', bySession('sso-parent-1'),
                          { initiating_entity: 'user' });
    note(endedOf(one) === 1 && endedOf(two) === 0,
         'E1. a session-revoked naming a sign-on session ends only the ' +
         'console session derived from it, not the person\'s other one',
         JSON.stringify([one.entry.reactions, two.entry.reactions]));
    const expiry = pushAbout('session-revoked', bySession('sso-parent-2'),
                             { initiating_entity: 'policy' });
    note(endedOf(expiry) === 0 &&
         expiry.entry.reactions.length === 1 &&
         !!expiry.entry.reactions[0].skipped,
         'E2. a session-revoked from an EXPIRY (initiating_entity policy) ' +
         'ends nothing: a renewable session outlives its parent',
         JSON.stringify(expiry.entry.reactions));
    const own = pushAbout('credential-change',
      { format: 'iss_sub', iss: record.iss, sub: erin },
      { initiating_entity: 'user', credential_type: 'password',
        change_type: 'update' });
    note(endedOf(own) === 0 && !!(own.entry.reactions[0] || {}).skipped,
         'E3. the person\'s own credential-change ends nothing',
         JSON.stringify(own.entry.reactions));
    const byAdmin = pushAbout('credential-change',
      { format: 'iss_sub', iss: record.iss, sub: erin },
      { initiating_entity: 'admin', credential_type: 'password',
        change_type: 'update' });
    note(endedOf(byAdmin) === 1,
         'E4. an administrator\'s credential-change still ends the ' +
         'person\'s console session', JSON.stringify(byAdmin.entry.reactions));
    // E5 (2026-09-24): a session begun AFTER the event's second is not
    // about it — delivery is asynchronous, and the person may already have
    // signed in again with the new password. One begun within it is still
    // ended.
    derived('sr-erin', 'sso-parent-3');
    const late = pushAbout('credential-change',
      { format: 'iss_sub', iss: record.iss, sub: erin },
      { initiating_entity: 'admin', credential_type: 'password',
        change_type: 'update',
        event_timestamp: Math.floor(Date.now() / 1000) - 10 });
    const current = pushAbout('credential-change',
      { format: 'iss_sub', iss: record.iss, sub: erin },
      { initiating_entity: 'admin', credential_type: 'password',
        change_type: 'update',
        event_timestamp: Math.floor(Date.now() / 1000) });
    note(endedOf(late) === 0 && endedOf(current) === 1,
         'E5. an administrator\'s credential-change from BEFORE a session ' +
         'began leaves it, and one from the second it began ends it',
         JSON.stringify([late.entry.reactions, current.entry.reactions]));

    // --- D. a disabled policy ----------------------------------------------
    const written = xacmlStore.write('signal-response',
      xacmlXml.writePolicy(plain.policy), { enabled: false });
    consoleSession('sr-erin');
    const refused = push('session-revoked', erin);
    const decided = pep.decide({ event: 'session-revoked', family: 'caep',
                                 surface: 'admin-console', level: '' });
    xacmlStore.remove('signal-response');
    note(written && written.ok && endedOf(refused) === 0 &&
         refused.entry.reactions.length === 0 &&
         /DISABLED/.test(String(decided.why)),
         'D1. a disabled policy decides nothing, and nothing is ended',
         JSON.stringify([written && written.why, decided.why]));
    config.clearOverride('ssf.actOnSignalsInDevelopment');

    // --- F. product refuses an unverified SET (#117) ------------------------
    const http = require('http');
    const app = require(ROOT + '/common/app');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const pushAtReceive = function (token) {
      return new Promise(function (resolve) {
        const req = http.request({ host: '127.0.0.1',
          port: server.address().port, path: '/ssf/receive', method: 'POST',
          headers: { 'content-type': 'application/secevent+jwt',
                     'content-length': Buffer.byteLength(token) } },
        function (res) {
          let text = '';
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            resolve({ status: res.statusCode, text: text });
          });
        });
        req.end(token);
      });
    };
    const forgedToken = function () {
      const claims = events.buildSet({ uri: events.CAEP_PREFIX +
        'session-revoked', issuer: record.iss, audience: 'sts-admin-console',
        subject: { format: 'iss_sub', iss: record.iss, sub: erin },
        payload: { event_timestamp: Math.floor(Date.now() / 1000) } });
      const token = events.signSetSync(claims);
      return token.slice(0, -4) + (token.slice(-4) === 'AAAA' ? 'BBBB'
                                                             : 'AAAA');
    };
    config.setOverride('ssf.receiveRequireSignature', false);
    const devReceive = await pushAtReceive(forgedToken());
    config.setOverride('global.mode', 'product');
    let prodInternal = null;
    let prodReceive = null;
    try {
      prodInternal = push('session-revoked', erin, {}, true);
      prodReceive = await pushAtReceive(forgedToken());
    } finally {
      config.clearOverride('global.mode');
      config.clearOverride('ssf.receiveRequireSignature');
      server.close();
    }
    // Development passes the signature step and RECORDS it; this test's
    // issuer is not the listener's own, so it is then refused for that.
    note(!/invalid_key/.test(devReceive.text) &&
         /has been recorded/.test(devReceive.text),
         'F1. development gets an unverified SET past the signature step at ' +
         '/ssf/receive and records it, as the debugger needs',
         devReceive.status + ' ' + devReceive.text.slice(0, 200));
    note(prodInternal.status === 400 &&
         prodInternal.body.err === 'invalid_key' &&
         prodInternal.entry.reactions.length === 0 &&
         prodReceive.status === 400 && /invalid_key/.test(prodReceive.text),
         'F2. product refuses one at the console\'s receiver and at ' +
         '/ssf/receive with invalid_key, the setting off (#117)',
         JSON.stringify([prodInternal.status, prodReceive.status,
                         prodReceive.text.slice(0, 200)]));

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
  const out = path.join(os.tmpdir(), 'signal-response-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', SR_ROOT: ROOT, SR_OUT: out }),
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
  name: 'signal_response',
  describe: 'this service\'s own surfaces acting on the signals they ' +
            'receive (#62): the signal-response policy and its round trips, ' +
            'its decisions, the console\'s own session ended for the ' +
            'person named — observed in development, once, never for ' +
            'somebody else and never on an unverified SET — and a disabled ' +
            'policy ending nothing',
  run: run
};
