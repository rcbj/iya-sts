'use strict';
//
// File: realm_removal_signals.js
//
// ===========================================================================
// A TRUST REALM IS REMOVED ALOUD (#232, 2026-09-26).
//
// Removing a realm dropped its registry row and purged every store — the
// directory, the sessions, the SSF streams and their queues — and told
// nobody: no RISC `account-purged` for anybody in it, no CAEP
// `session-revoked` and no back-channel Logout Token for a live session, and
// no `stream-updated` to a receiver whose stream vanished. The success message
// also said "Nothing was removed from the shared directory", which the
// directory's own purge contradicts.
//
// `realms.retire()` is the administrator's removal now, and what is asserted
// is what a RECEIVER sees, over a real RFC 8935 push to a listener here:
//
//   A. removing a realm through the console's action sends, before the realm
//      goes, `session-revoked` (initiating_entity admin) for a live session,
//      `account-purged` for the person, and then `stream-updated` with status
//      `disabled` — and the message no longer denies the directory went;
//   B. the wait is BOUNDED by realms.removalDeliveryTimeoutS: a receiver that
//      never answers holds the removal for about that long and no longer, the
//      realm still goes, and what did not settle is reported;
//   C. a poll stream nobody collects from is reported as undelivered;
//   D. a removal that is not the administrator's act — `realms.remove()`
//      alone, which is what a replicated removal on another node runs — sends
//      nothing, because the node that made the act already did.
//
// In a CHILD PROCESS: it loads the whole protocol stack, sets SSF and realm
// settings, and listens on ports.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'realm_removal_signals',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.RRS_ROOT;
  const OUT = process.env.RRS_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };
  const payloadOf = function (jwt) {
    try {
      return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
        .toString('utf8'));
    } catch (e) {
      return { parseError: e.message };
    }
  };

  (async function () {
    const config = require(ROOT + '/common/config');
    [['ssf.enabled', 'true'], ['ssf.pushDelivery', 'true'],
     ['ssf.pushAllowHttp', 'true'], ['ssf.pushTimeoutMs', '20000']]
      .forEach(function (pair) {
      config.setOverride(pair[0], pair[1]);
    });
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const authn = require(ROOT + '/authn/authn');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const events = require(ROOT + '/ssf/ssf_events');
    const adminActions = require(ROOT + '/admin-core/admin_actions');

    // A receiver that records every SET it is pushed, in order.
    const received = [];
    const receiver = http.createServer(function (req, res) {
      let text = '';
      req.on('data', function (c) { text += c; });
      req.on('end', function () {
        received.push({ path: req.url, set: payloadOf(text) });
        res.writeHead(202).end();
      });
    });
    await new Promise(function (r) { receiver.listen(0, '127.0.0.1', r); });
    const rxBase = 'http://127.0.0.1:' + receiver.address().port;
    // And one that never answers.
    const hung = [];
    const silent = http.createServer(function (req) {
      hung.push(req);
    });
    await new Promise(function (r) { silent.listen(0, '127.0.0.1', r); });
    const silentBase = 'http://127.0.0.1:' + silent.address().port;

    const REVOKED = events.CAEP_PREFIX + 'session-revoked';
    const PURGED = events.RISC_PREFIX + 'account-purged';
    const UPDATED = events.SSF_PREFIX + 'stream-updated';

    // A realm with a person holding a live session and a stream about
    // everybody (ssf.defaultSubjects is ALL).
    const setUp = function (id, delivery) {
      const made = realms.create({ id: id, name: id,
                                   description: 'realm_removal_signals.js' });
      if (!made.ok) {
        throw new Error('could not create ' + id + ': ' +
                        (made.errors || []).join(' '));
      }
      return realms.run(made.realm, function () {
        const stream = streams.createStream({
          events_requested: [REVOKED, PURGED, UPDATED],
          delivery: delivery
        }, { issuer: 'https://sts.test/realm/' + id,
             principal: 'rrs-probe-' + id,
             audience: 'https://receiver.test/' + id }).stream;
        ldap.createUser('rrs-alice', { invent: false });
        const session = authn.startSession({ set: function () {},
                                             req: null },
                                           'rrs-alice', ['pwd'], '1',
                                           'OAuth 2.0 / OIDC');
        return { stream: stream, session: session };
      });
    };
    const eventOf = function (one, uri) {
      return ((one.set && one.set.events) || {})[uri] || null;
    };

    // --- A. through the console's action --------------------------------
    const a = setUp('rrs-a', { method: streams.DELIVERY_PUSH,
                               endpoint_url: rxBase + '/a' });
    note(!!a.stream && !!a.session,
         'A0. (a realm with a push stream and a live session)',
         JSON.stringify({ stream: !!a.stream, session: !!a.session }));
    await sleep(300);
    received.length = 0;
    const started = Date.now();
    const removed = await adminActions.realmsAction({ action: 'remove',
                                                      id: 'rrs-a' });
    const tookA = Date.now() - started;
    note(removed && removed.ok && !realms.get('rrs-a'),
         'A1. the console\'s remove answers ok and the realm is gone',
         JSON.stringify(removed && { ok: removed.ok,
                                     errors: removed.errors }));
    const mine = received.filter(function (one) {
      return one.path === '/a';
    });
    const revoked = mine.filter(function (one) {
      return !!eventOf(one, REVOKED);
    });
    note(revoked.length === 1 &&
         eventOf(revoked[0], REVOKED).initiating_entity === 'admin',
         'A2. the receiver was pushed session-revoked for the live session, ' +
         'initiated by an ADMINISTRATOR, before the realm went',
         JSON.stringify(revoked.map(function (one) {
           return eventOf(one, REVOKED);
         })));
    note(mine.some(function (one) {
      return !!eventOf(one, PURGED);
    }), 'A3. and account-purged for the person in its directory',
         JSON.stringify(mine.map(function (one) {
           return Object.keys((one.set && one.set.events) || {});
         })));
    const last = mine[mine.length - 1];
    note(!!last && !!eventOf(last, UPDATED) &&
         eventOf(last, UPDATED).status === 'disabled',
         'A4. and, LAST, stream-updated with status disabled — the stream ' +
         'is told before it stops (SSF 1.0 section 8.1.5)',
         JSON.stringify(last && last.set && last.set.events));
    note(!/Nothing was removed from the shared directory/
           .test(String(removed.message)) &&
         /directory/.test(String(removed.message)),
         'A5. the message no longer denies that the realm\'s directory went ' +
         'with it', String(removed.message));
    note(removed.retirement &&
         (removed.retirement.late || []).length === 0 && tookA < 8000,
         'A6. and nothing was left waiting on a receiver that answered',
         JSON.stringify(removed.retirement) + ' ' + tookA + 'ms');

    // --- B. the wait is bounded ------------------------------------------
    config.setOverride('realms.removalDeliveryTimeoutS', '1');
    setUp('rrs-b', { method: streams.DELIVERY_PUSH,
                     endpoint_url: silentBase + '/b' });
    await sleep(200);
    const startedB = Date.now();
    const retiredB = await realms.retire('rrs-b');
    const tookB = Date.now() - startedB;
    note(retiredB.ok && !realms.get('rrs-b') && tookB < 5000,
         'B1. a receiver that never answers holds the removal for about ' +
         'realms.removalDeliveryTimeoutS (1 s here) and no longer, and the ' +
         'realm still goes', tookB + 'ms');
    const r = retiredB.retirement || {};
    note((r.late || []).length > 0 || (r.undelivered || []).length > 0,
         'B2. and what did not settle is reported (STS-CORE-0120)',
         JSON.stringify(r));
    hung.forEach(function (req) {
      try {
        req.socket.destroy();
      } catch (e) {
        // Already gone.
      }
    });
    config.setOverride('realms.removalDeliveryTimeoutS', '10');

    // --- C. a poll stream nobody collects from ----------------------------
    setUp('rrs-c', { method: 'urn:ietf:rfc:8936' });
    await sleep(200);
    const retiredC = await realms.retire('rrs-c');
    const undeliveredC = ((retiredC.retirement || {}).undelivered || [])
      .reduce(function (n, one) { return n + Number(one.count); }, 0);
    note(retiredC.ok && undeliveredC > 0,
         'C1. SETs on a poll stream nobody collected are counted as ' +
         'undelivered rather than dropped in silence',
         JSON.stringify(retiredC.retirement));

    // --- D. remove() alone says nothing -----------------------------------
    const notices = [];
    authn.setSessionObserver(function (notice) {
      notices.push(notice);
      return null;
    });
    const d = setUp('rrs-d', { method: streams.DELIVERY_PUSH,
                               endpoint_url: rxBase + '/d' });
    notices.length = 0;
    realms.remove('rrs-d');
    await sleep(200);
    note(!realms.get('rrs-d') && notices.filter(function (n) {
      return n.kind === 'revoked' && n.session &&
             n.session.id === d.session.id;
    }).length === 0,
         'D1. (a control: realms.remove() alone — what a replicated ' +
         'removal on another node runs — announces nothing; the node that ' +
         'made the act already did)');

    receiver.close();
    silent.close();
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
  const out = path.join(os.tmpdir(), 'realm-removal-signals-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', RRS_ROOT: ROOT,
                           RRS_OUT: out }),
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
  name: 'realm_removal_signals',
  describe: 'Removing a trust realm (#232): session-revoked, account-purged ' +
            'and stream-updated disabled reach a push receiver before it ' +
            'goes, the wait is bounded by realms.removalDeliveryTimeoutS, an ' +
            'uncollected poll stream is reported, and remove() alone is ' +
            'silent',
  run: run
};
