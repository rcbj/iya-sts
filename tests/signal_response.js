// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//   G. WHAT A STATIC SURFACE HOLDS (#1042): a signal revokes the tokens the
//      receiving surface's own client holds for the person — the console's,
//      the portal's, the reports application's — narrowed to a named
//      session and never a token issued after the event; and the reports
//      application is a receiver of its own, its inbox narrowed per person.
//   F. PRODUCT MODE REFUSES AN UNVERIFIED SET (#117) at the console's
//      receiver, whatever ssf.receiveRequireSignature says; and there is no
//      /ssf/receive in either mode (#593 deleted it; Express's own 404).
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
    note(slugs === 'end-sessions,end-sessions-on-risk,' +
                   'partner-end-sessions,partner-block,partner-unblock,' +
                   'partner-revoke-grants,' +
                   'signals-only-enable,device-compliance',
         'A1. the built-in policy ends sessions on the listed events and on ' +
         'a risk-level-change to HIGH; a sign-in partner\'s (#373) end the ' +
         'sessions it started, block and unblock its sign-ins and revoke ' +
         'the person\'s grants and tokens (#432); a ' +
         'signals-only partner\'s (#374) only lift its own lock; and a ' +
         'device\'s compliance is set — the global sign-out and the ' +
         'account lock are permitted by no rule', slugs);
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
      // Taken as the console's poll takes one (#771): the seeded stream is a
      // poll stream, and `acceptPolled()` is the push's checks without the
      // push.
      return receivers.acceptPolled('admin-console', token);
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
      return receivers.acceptPolled('admin-console',
                                    events.signSetSync(claims));
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
    // E4b (2026-10-27): a credential ADDED takes nothing away. A person
    // created with a password and signed in within the same second lost
    // that sign-in to the signal's delivery a moment later (run #4).
    derived('sr-erin', 'sso-parent-2b');
    const added = pushAbout('credential-change',
      { format: 'iss_sub', iss: record.iss, sub: erin },
      { initiating_entity: 'admin', credential_type: 'password',
        change_type: 'create' });
    note(endedOf(added) === 0 && !!(added.entry.reactions[0] || {}).skipped,
         'E4b. a credential an administrator ADDED (change_type create) ' +
         'ends nothing: nothing was taken away',
         JSON.stringify(added.entry.reactions));
    const swept = pushAbout('credential-change',
      { format: 'iss_sub', iss: record.iss, sub: erin },
      { initiating_entity: 'admin', credential_type: 'password',
        change_type: 'update' });
    note(endedOf(swept) === 1,
         'E4c. and the session E4b left standing was there to end: an ' +
         'update by an administrator ends it',
         JSON.stringify(swept.entry.reactions));
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

    // --- G. what a static surface holds: its client's tokens (#1042) ------
    // Since #446 and #568 the console and the portal are static
    // applications holding tokens, and no relying-party session: C and E
    // above drive the debugger-shaped sessions the call still ends. Here a
    // signal revokes the tokens the receiving surface's OWN client holds for
    // the person, and nothing else.
    const stats = require(ROOT + '/common/admin_stats');
    const cryptoNode = require('crypto');
    const token = function (username, clientId, sessionId) {
      const jti = 'sr-' + cryptoNode.randomBytes(8).toString('hex');
      const now = Math.floor(Date.now() / 1000);
      stats.recordJwt({ jti: jti, sub: String(helpers.subjectForName(username)),
        username: username, client_id: clientId, iat: now, exp: now + 3600 },
        '', { kind: 'access_token', sessionId: sessionId || '' });
      return jti;
    };
    const revokedOf = function (answer) {
      return ((answer.entry && answer.entry.reactions) || [])
        .reduce(function (n, r) {
          return n + (Number(r.revoked) || 0);
        }, 0);
    };
    const erinConsole = token('sr-erin', 'sts-admin-console');
    const erinPortal = token('sr-erin', 'sts-user-portal');
    const erinReport = token('sr-erin', 'sts-report');
    const frankConsole = token('sr-frank', 'sts-admin-console');
    const g1 = pushAbout('credential-change',
      { format: 'iss_sub', iss: record.iss, sub: erin },
      { initiating_entity: 'admin', credential_type: 'password',
        change_type: 'update' });
    note(revokedOf(g1) === 1 && stats.isRevoked(erinConsole) &&
         !stats.isRevoked(erinPortal) && !stats.isRevoked(erinReport) &&
         !stats.isRevoked(frankConsole),
         'G1. an administrator\'s credential-change about erin revokes the ' +
         'token the CONSOLE\'s client holds for her, and not her portal or ' +
         'reports token, nor anybody else\'s console token',
         JSON.stringify([g1.entry.reactions, stats.isRevoked(erinConsole),
                         stats.isRevoked(erinPortal),
                         stats.isRevoked(frankConsole)]));
    const g1bToken = token('sr-erin', 'sts-admin-console');
    const g1b = pushAbout('credential-change',
      { format: 'iss_sub', iss: record.iss, sub: erin },
      { initiating_entity: 'admin', credential_type: 'password',
        change_type: 'create' });
    note(revokedOf(g1b) === 0 && !stats.isRevoked(g1bToken),
         'G1b. a credential ADDED (change_type create) revokes no token',
         JSON.stringify(g1b.entry.reactions));
    const g2Token = token('sr-erin', 'sts-admin-console');
    const g2 = pushAbout('credential-change',
      { format: 'iss_sub', iss: record.iss, sub: erin },
      { initiating_entity: 'admin', credential_type: 'password',
        change_type: 'update',
        event_timestamp: Math.floor(Date.now() / 1000) - 10 });
    note(revokedOf(g2) === 0 && !stats.isRevoked(g2Token),
         'G2. a token issued AFTER the event is left alone, as a session ' +
         'begun after it is', JSON.stringify(g2.entry.reactions));
    const inX = token('sr-erin', 'sts-admin-console', 'sso-x');
    const inY = token('sr-erin', 'sts-admin-console', 'sso-y');
    const g3 = pushAbout('session-revoked', bySession('sso-x'),
                         { initiating_entity: 'user' });
    note(stats.isRevoked(inX) && !stats.isRevoked(inY) &&
         !stats.isRevoked(g2Token),
         'G3. a session-revoked naming a sign-on session revokes only the ' +
         'console tokens issued on it',
         JSON.stringify([g3.entry.reactions, stats.isRevoked(inX),
                         stats.isRevoked(inY)]));
    // The reports application, the third receiver (#1042).
    const reportRecord = receivers.streamFor('report');
    note(!!reportRecord &&
         receivers.surfaceOf(receivers.REPORT).audience === 'sts-report',
         'G4. the reports application has a stream of its own, audienced ' +
         'to sts-report', JSON.stringify(reportRecord &&
                                         reportRecord.stream_id));
    const toReport = receivers.acceptPolled('report', events.signSetSync(
      events.buildSet({ uri: events.CAEP_PREFIX + 'credential-change',
        issuer: record.iss, audience: 'sts-report',
        subject: { format: 'iss_sub', iss: record.iss, sub: erin },
        payload: { event_timestamp: Math.floor(Date.now() / 1000),
                   initiating_entity: 'admin', credential_type: 'password',
                   change_type: 'update' } })));
    note(toReport.status === 202 && toReport.entry.verified &&
         revokedOf(toReport) === 1 && stats.isRevoked(erinReport) &&
         !stats.isRevoked(erinPortal),
         'G5. delivered to the reports application, it revokes the token ' +
         'sts-report holds for erin, and not her portal token',
         JSON.stringify([toReport.status, toReport.entry.reactions]));
    note(receivers.listFor('report', {}).length >= 1 &&
         receivers.listFor('report', { person: { username: 'sr-frank',
           sub: frank, mail: '' } }).length === 0 &&
         receivers.listFor('report', { person: { username: 'sr-erin',
           sub: erin, mail: '' } }).length >= 1,
         'G6. the reports inbox holds the signal; narrowed to a person it ' +
         'is shown to erin and not to frank');

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
    // DELETED BY #593: the test peer is that push receiver now, so a SET
    // pushed at /ssf/receive finds an unrouted path in development too.
    const devReceive = await pushAtReceive(forgedToken());
    config.setOverride('global.mode', 'product');
    let prodInternal = null;
    try {
      prodInternal = push('session-revoked', erin, {}, true);
    } finally {
      config.clearOverride('global.mode');
      config.clearOverride('ssf.receiveRequireSignature');
      server.close();
    }
    note(devReceive.status === 404 &&
         /Cannot POST \/ssf\/receive/.test(devReceive.text),
         'F1. there is no /ssf/receive, in development either (#593)',
         devReceive.status + ' ' + devReceive.text.slice(0, 200));
    note(prodInternal.status === 400 &&
         prodInternal.body.err === 'invalid_key' &&
         prodInternal.entry.reactions.length === 0,
         'F2. product refuses one at the console\'s receiver with ' +
         'invalid_key, the setting off (#117)',
         JSON.stringify([prodInternal.status,
                         prodInternal.body && prodInternal.body.err]));

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
