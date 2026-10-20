// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: spiffe_workload_agent.js
//
// ===========================================================================
// THE WORKLOAD AGENT (#324), IN A CHILD PROCESS.
//
// Product mode does not bind the Workload API on TCP unless the network is
// declared to authenticate callers by source address (#166). On AWS that
// declaration cannot be made honestly, so a workload runs this agent beside
// it: the agent attests with a join token over the SPIRE Server API, which
// is served, and serves the Workload API on a Unix socket. This file is
// that path with no load balancer in it.
//
// The child requires the protocol stack, which is why it is a child
// (`run.js` runs every file in one process). It asserts:
//
//   * product, undeclared, still does not bind the TCP port
//     (STS-SPIFFE-0120), and a port of 0 leaves it off;
//   * an agent whose native module is missing does not serve and does not
//     create the socket (STS-SPIFFE-0148);
//   * a real agent, attested with `issueJoinToken`, hands a workload its
//     own X509-SVID and JWT-SVID and refuses an entry that selects another
//     uid (STS-SPIFFE-0150);
//   * the X509 stream stays open and is written again within half of a
//     four-second SVID;
//   * marking that connection's caller changed makes the next call on the
//     same client PERMISSION_DENIED (STS-SPIFFE-0149). The code is recorded
//     and not sent.
//
// It does not weaken `tests/spiffe_workload_tcp_product.js`. The realm is
// left standing with SPIFFE off, for that file's reason.
// ===========================================================================

const os = require('os');
const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'spiffe_workload_agent',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The child's program. Runs in the child only, which the code style exempts
// from the Entering/Leaving lines; its findings are written to WT_OUT.
function childMain() {
  const ROOT = process.env.WT_ROOT;
  const OUT = process.env.WT_OUT;
  const REALM = 'spiffe-workload-agent';
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const net = require('net');
  const nodeCrypto = require('crypto');
  const findings = [];
  const check = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' :
                      (typeof detail === 'string' ? detail
                                                  : JSON.stringify(detail)) });
  };
  const freePort = function () {
    return new Promise(function (resolve) {
      const probe = net.createServer();
      probe.listen(0, '127.0.0.1', function () {
        const port = probe.address().port;
        probe.close(function () { resolve(port); });
      });
    });
  };
  const connects = function (port) {
    return new Promise(function (resolve) {
      const socket = net.connect(port, '127.0.0.1');
      const timer = setTimeout(function () {
        socket.destroy();
        resolve(false);
      }, 1000);
      socket.on('connect', function () {
        clearTimeout(timer);
        socket.destroy();
        resolve(true);
      });
      socket.on('error', function () {
        clearTimeout(timer);
        resolve(false);
      });
    });
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const errorCodes = require(ROOT + '/common/error_codes');
    const server = require(ROOT + '/spiffe/spiffe_server');
    const auth = require(ROOT + '/spiffe/spiffe_auth');
    const ca = require(ROOT + '/spiffe/spiffe_ca');
    const registry = require(ROOT + '/spiffe/spiffe_registry');
    const api = require(ROOT + '/spiffe/spiffe_api');
    const rpc = require(ROOT + '/spiffe/spiffe_grpc');
    const WorkloadAgent = require(ROOT + '/spiffe/workload_agent');
    const workloadPort = await freePort();
    const serverPort = await freePort();
    const made = realms.get(REALM) ? { ok: true } : realms.create({
      id: REALM, name: REALM, overrides: {
        'spiffe.workloadPort': workloadPort,
        'spiffe.serverPort': serverPort,
        'spiffe.grpcHost': '127.0.0.1',
        'spiffe.workloadSocketEnabled': false,
        'spiffe.serverSocketEnabled': false,
        'spiffe.workloadTcpSourceAuthenticated': false } });
    check(made.ok, 'a realm of this run\'s own',
          (made.errors || []).join(' '));
    const realm = realms.get(REALM);
    const inRealm = function (fn) {
      return realms.run(realm, fn);
    };
    const set = function (key, value) {
      const r = realms.setOverride(REALM, key, value);
      if (!r.ok) {
        throw new Error(key + ': ' + (r.errors || []).join(' '));
      }
    };
    const tcpBinding = function () {
      return (server.bindings().workload || []).filter(function (b) {
        return b.realm === REALM && !b.socket;
      })[0] || null;
    };
    let agent = null;
    let agentDir = '';
    try {
      await server.listen().whenReady;
      set('global.mode', 'product');
      set('spiffe.enabled', true);
      await server.reconcile();
      const bound = tcpBinding();
      const posture = inRealm(function () {
        return auth.workloadTcpPosture();
      });
      check(!!bound && bound.listening === false &&
            errorCodes.codeOf(bound) === 'STS-SPIFFE-0120' &&
            posture && posture.served === false &&
            posture.errorCode === 'STS-SPIFFE-0120',
            'product, undeclared: the Workload API TCP port is not served ' +
            '(STS-SPIFFE-0120)',
            { binding: bound && bound.listening, posture: posture });
      check(!(await connects(workloadPort)),
            'and nothing answers a connection on that port');
      set('spiffe.workloadPort', 0);
      await server.reconcile();
      const off = inRealm(function () {
        return auth.workloadTcpPosture();
      });
      check(off && off.served === false && !off.errorCode,
            'a workload port of 0 is off, with no code', off);

      const missingDir = fs.mkdtempSync(path.join(os.tmpdir(),
                                                  'sts-agent-blind-'));
      const missingSocket = path.join(missingDir, 'api.sock');
      const blind = new WorkloadAgent({
        server: '127.0.0.1:' + serverPort,
        socketPath: missingSocket,
        trustDomain: 'example.org',
        joinToken: 'not-used',
        trustBundlePem: 'unused',
        nativePath: path.join(missingDir, 'no-such.node')
      });
      let blindError = null;
      try {
        await blind.start();
      } catch (e) {
        // Expected: a missing native module fails as STS-SPIFFE-0148.
        blindError = e;
      }
      check(!!blindError && blindError.code === 'STS-SPIFFE-0148' &&
            !fs.existsSync(missingSocket),
            'without the native module the agent does not serve and ' +
            'creates no socket (STS-SPIFFE-0148)',
            blindError && blindError.code);
      try {
        fs.rmSync(missingDir, { recursive: true, force: true });
      } catch (e) {
        // Cleanup must become a finding so the child still writes WT_OUT.
        check(false, 'the unused socket directory was removed', e.message);
      }

      const td = inRealm(function () {
        return ca.trustDomain();
      });
      const pem = inRealm(function () {
        return (ca.state().trustAnchors || []).map(function (anchor) {
          return anchor.certificatePem;
        }).filter(Boolean).join('\n');
      });
      check(!!td && pem.indexOf('BEGIN CERTIFICATE') >= 0,
            'the realm has a trust domain and trust anchors', td);
      const minted = inRealm(function () {
        return api.issueJoinToken({ ttl: 600 });
      });
      check(!!(minted && minted.ok && minted.token && minted.agentSpiffeId),
            'a join token was minted, and its agent id is not the token',
            minted && minted.ok ? minted.agentSpiffeId : minted &&
            minted.message);
      agentDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-agent-'));
      const socketPath = path.join(agentDir, 'api.sock');
      agent = new WorkloadAgent({
        server: '127.0.0.1:' + serverPort,
        socketPath: socketPath,
        trustDomain: td,
        joinToken: minted.token,
        trustBundlePem: pem
      });
      await agent.start();
      check(agent.agentSpiffeId === minted.agentSpiffeId &&
            fs.existsSync(socketPath),
            'the agent attested as the id the token predicted and is ' +
            'listening', agent.agentSpiffeId);
      const selectors = WorkloadAgent.selectorsFor(process.getuid(),
                                                   process.getgid());
      const id = function (suffix) {
        return 'spiffe://' + td + '/probe/' + suffix;
      };
      const parentId = agent.agentSpiffeId;
      const workload = inRealm(function () {
        return registry.createEntry({
          spiffeId: id('workload'), parentId: parentId,
          selectors: selectors, x509SvidTtl: 4, jwtSvidTtl: 60
        }, 'test', td, 'test');
      });
      const otherUid = process.getuid() === 0 ? 1 : 0;
      const other = inRealm(function () {
        return registry.createEntry({
          spiffeId: id('other-uid'), parentId: parentId,
          selectors: [{ type: 'unix', value: 'uid:' + otherUid }]
        }, 'test', td, 'test');
      });
      check(workload.ok && other.ok, 'the workload entry and the other-uid ' +
            'entry were registered under the agent',
            [(workload.errors || []).join(' '),
             (other.errors || []).join(' ')].join(' | '));

      const Client = rpc.grpc.makeGenericClientConstructor(
        rpc.SERVICES.workload, 'SpiffeWorkloadAPI');
      const metadata = new rpc.grpc.Metadata();
      metadata.set(rpc.SECURITY_HEADER, 'true');
      const client = new Client('unix://' + socketPath,
        rpc.grpc.credentials.createInsecure(),
        { 'grpc.use_local_subchannel_pool': 1 });
      const held = await new Promise(function (resolve) {
        const stream = client.FetchX509SVID({}, metadata);
        const messages = [];
        let settled = false;
        let timer = null;
        const finish = function (error) {
          if (settled) {
            return;
          }
          settled = true;
          clearTimeout(timer);
          resolve({ messages: messages, error: error || null,
                    stream: stream });
        };
        timer = setTimeout(function () {
          finish(messages.length >= 2 ? null
            : { code: -1, details: 'no second message within 12s' });
        }, 12000);
        stream.on('data', function (message) {
          messages.push(message);
          if (messages.length >= 2) {
            finish(null);
          }
        });
        stream.on('error', function (error) {
          if (messages.length < 2) {
            finish(error);
          }
        });
      });
      // The JWT calls below each open a connection of their own and close
      // it, and that one becomes latestFacts(). The refusal below is about
      // the connection this client is still holding.
      const heldFacts = agent.latestFacts();
      const first = held.messages[0];
      const svids = (first && first.svids) || [];
      const mine = svids.filter(function (svid) {
        return svid.spiffe_id === id('workload');
      })[0];
      check(!held.error && !!mine &&
            svids.every(function (svid) {
              return svid.spiffe_id !== id('other-uid');
            }),
            'FetchX509SVID answers the workload and not the other uid',
            held.error ? (held.error.code + ' ' + held.error.details)
                       : svids.map(function (svid) {
                         return svid.spiffe_id;
                       }));
      let keyOk = false;
      try {
        nodeCrypto.createPrivateKey({ key: mine.x509_svid_key,
                                     format: 'der', type: 'pkcs8' });
        keyOk = true;
      } catch (e) {
        // A key that will not parse is a failed check, not a thrown child.
        keyOk = false;
      }
      check(keyOk && mine && mine.x509_svid && mine.x509_svid.length > 0,
            'the X509-SVID carries a PKCS#8 key this process can read');
      check(held.messages.length >= 2,
            'the stream was written again within half of the 4s SVID',
            held.error ? (held.error.code + ' ' + held.error.details)
                       : String(held.messages.length));

      const askJwt = function (spiffeId) {
        return new Promise(function (resolve) {
          const one = new Client('unix://' + socketPath,
            rpc.grpc.credentials.createInsecure(),
            { 'grpc.use_local_subchannel_pool': 1 });
          one.FetchJWTSVID({ audience: ['urn:probe:324'],
                             spiffe_id: spiffeId }, metadata,
                           { deadline: Date.now() + 20000 },
                           function (err, reply) {
            one.close();
            if (err) {
              resolve({ ok: false, code: err.code, details: err.details });
              return;
            }
            const row = ((reply && reply.svids) || [])[0] || {};
            resolve({ ok: true, spiffeId: row.spiffe_id,
                      token: row.svid || '' });
          });
        });
      };
      const jwt = await askJwt(id('workload'));
      check(jwt.ok && jwt.spiffeId === id('workload') &&
            String(jwt.token).split('.').length === 3,
            'FetchJWTSVID answers a JWT-SVID for the workload',
            jwt.ok ? jwt.spiffeId : (jwt.code + ' ' + jwt.details));
      const denied = await askJwt(id('other-uid'));
      check(!denied.ok &&
            denied.code === rpc.grpc.status.PERMISSION_DENIED &&
            String(denied.details).indexOf('STS-SPIFFE-') < 0,
            'an entry selecting another uid is PERMISSION_DENIED, and the ' +
            'error code is not sent (STS-SPIFFE-0150)',
            denied.code + ' ' + denied.details);

      agent.callerChanged(heldFacts);
      const changed = await new Promise(function (resolve) {
        client.FetchJWTSVID({ audience: ['urn:probe:324'] }, metadata,
                            { deadline: Date.now() + 10000 },
                            function (err) {
          resolve(err ? { ok: false, code: err.code, details: err.details }
                      : { ok: true });
        });
      });
      check(!changed.ok &&
            changed.code === rpc.grpc.status.PERMISSION_DENIED &&
            /no longer matches/.test(String(changed.details)) &&
            String(changed.details).indexOf('STS-SPIFFE-') < 0,
            'a caller that no longer matches the process that connected ' +
            'is PERMISSION_DENIED on the same connection (STS-SPIFFE-0149)',
            changed.code + ' ' + changed.details);
      try {
        held.stream.cancel();
      } catch (e) {
        // Cancelling the stream must not stop the child writing WT_OUT.
        check(false, 'the held stream could be cancelled', e.message);
      }
      client.close();
    } catch (e) {
      // An unexpected failure is a finding, so WT_OUT is still written.
      check(false, 'the child ran to the end', String(e && e.stack));
    } finally {
      if (agent) {
        try {
          agent.stop();
        } catch (e) {
          // Stopping the agent must not stop the child writing WT_OUT.
          check(false, 'the agent stopped', e.message);
        }
      }
      if (agentDir) {
        try {
          fs.rmSync(agentDir, { recursive: true, force: true });
        } catch (e) {
          // Removing the agent directory must not stop WT_OUT being written.
          check(false, 'the agent directory was removed', e.message);
        }
      }
      try {
        set('spiffe.enabled', false);
        set('global.mode', 'development');
        await server.reconcile();
      } catch (e) {
        // Putting the realm back must not stop the child writing WT_OUT.
        check(false, 'the realm was put back', e.message);
      }
      try {
        server.close();
      } catch (e) {
        // Closing the SPIFFE server must not stop the child writing WT_OUT.
        check(false, 'the SPIFFE server closed', e.message);
      }
    }
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    // An unexpected rejection of the child is a finding. WT_OUT is still
    // written, then the child exits 1 so the parent sees the failure.
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: String(e && e.stack) });
    try {
      fs.writeFileSync(OUT, JSON.stringify(findings));
    } catch (writeError) {
      // The report could not be written; stderr is what the parent sees.
      process.stderr.write(String(writeError && writeError.message) + '\n');
    }
    process.exit(1);
  });
}

function inAChild(t) {
  log.debug('Entering inAChild().');
  const out = path.join(os.tmpdir(), 'spiffe-workload-agent-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const env = Object.assign(clean, {
    LOG_LEVEL: 'fatal', WT_ROOT: ROOT, WT_OUT: out,
    STS_SPIFFE_WORKLOAD_PORT: '0', STS_SPIFFE_SERVER_PORT: '0',
    STS_SPIFFE_WORKLOAD_SOCKET_ENABLED: 'false',
    STS_SPIFFE_SERVER_SOCKET_ENABLED: 'false'
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'],
    { env: env, encoding: 'utf8', timeout: 300000, cwd: ROOT });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug('Caught in inAChild(): ' + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug('Caught in inAChild(): ' + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1500))) {
    log.debug('Leaving inAChild().');
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug('Leaving inAChild().');
}

function run(t) {
  log.debug('Entering run().');
  t.log.info('=== #324: the workload agent serves the Workload API on a ' +
             'Unix socket ===');
  inAChild(t);
  log.debug('Leaving run().');
}

module.exports = {
  name: 'spiffe_workload_agent',
  describe: '#324: a workload agent attests with a join token over the ' +
            'SPIRE Server API and serves the Workload API on a Unix socket ' +
            'where product mode does not bind it on TCP',
  run: run
};
