'use strict';
//
// File: spiffe_workload_attestation.js
//
// ===========================================================================
// WORKLOAD ATTESTATION ON THE WORKLOAD API'S UNIX SOCKET (#40 phase four,
// 2026-09-21).
//
// Two halves:
//
//   1. THE REAL THING. The default realm's Workload API is bound on a Unix
//      socket in this run's own directory, and a CHILD PROCESS — a different
//      pid from this one, which is the whole point — calls
//      `FetchX509Bundles` over it. While the child holds the connection open,
//      the facts this service recorded for it must name the CHILD's pid, its
//      uid and gid, a pidfd, and the `unix` attestor's selectors; a copy of
//      those facts with the start time or the executable's inode changed must
//      read as a different process; and once the child has exited, the facts
//      it left must read as gone. Then the `unix` attestor is made to FAIL
//      (an executable larger than `spiffe.unixWorkloadSizeLimit`), and the
//      child's call must be refused — a workload is never answered on a
//      partial attestation.
//
//      This needs `spiffe/native/peercred.node`, which `build-native.sh`
//      compiles inside the tests image. Its absence is a FAILURE here, not a
//      skip: an image without it serves the socket unattested in development
//      and not at all in product, and nothing else would notice.
//
//   2. THE ATTESTORS, OVER FAKES. SPIRE's containerinfo extractor over cgroup
//      files, the `unix` attestor over a fake /proc and passwd/group files,
//      the `docker` attestor over a fake Engine, the `k8s` attestor over a
//      fake kubelet pod list — each with its refusals beside its acceptance.
// ===========================================================================

const os = require('os');
const path = require('path');
const fs = require('fs');
const childProcess = require('child_process');

const config = require('../common/config');
const realms = require('../common/realms');
const mode = require('../common/mode');
const server = require('../spiffe/spiffe_server');
const peer = require('../spiffe/spiffe_peer');
const table = require('../spiffe/spiffe_workload_attestation');
const unixAttestor = require('../spiffe/spiffe_workload_attestor_unix');
const dockerAttestor = require('../spiffe/spiffe_workload_attestor_docker');
const k8sAttestor = require('../spiffe/spiffe_workload_attestor_k8s');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({
  name: 'spiffe_workload_attestation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-workload-attest-'));
const SOCKET = path.join(WORK, 'public', 'api.sock');

const CONTAINER = 'a'.repeat(64);
const OTHER_CONTAINER = 'b'.repeat(64);
const POD = '11111111-2222-3333-4444-555555555555';

// The socket is bound by a realm of this run's own: the socket rows are
// restart-only for the PROCESS and settable on a REALM (`realmRuntime`).
// Left standing, SPIFFE turned off, for `tests/spiffe_pki.js`'s reason.
const REALM = 'spiffe-workload-attest';

// The Workload API client, as a child program: one FetchX509Bundles over the
// socket, its pid and the outcome on stdout, and then it WAITS — holding the
// connection — until its stdin closes. Runs in the child only, which the code
// style exempts from the Entering/Leaving lines.
function clientProgram(packageRoot, socketPath) {
  const rpc = require(require('path').join(packageRoot,
                                           'spiffe/spiffe_grpc'));
  const client = new (rpc.grpc.makeGenericClientConstructor(
    rpc.SERVICES.workload, 'SpiffeWorkloadAPI'))(
      'unix://' + socketPath, rpc.grpc.credentials.createInsecure());
  const metadata = new rpc.grpc.Metadata();
  metadata.set(rpc.SECURITY_HEADER, 'true');
  const stream = client.FetchX509Bundles({}, metadata);
  let said = false;
  function say(outcome) {
    if (said) {
      return;
    }
    said = true;
    // Marked, because the child's configuration logs its own line to stdout.
    process.stdout.write('RESULT ' +
                         JSON.stringify(Object.assign({ pid: process.pid },
                                                      outcome)) + '\n');
  }
  stream.on('data', function () {
    say({ ok: true });
  });
  stream.on('error', function (err) {
    say({ ok: false, code: err.code, details: err.details });
  });
  process.stdin.on('end', function () {
    process.exit(0);
  });
  process.stdin.resume();
}

// Start the client; resolves { child, outcome } once it has an answer.
function startClient() {
  log.debug("Entering startClient().");
  const script = 'delete process.env.CONFIG_FILE;\n(' +
    clientProgram.toString() + ')(' + JSON.stringify(ROOT) + ', ' +
    JSON.stringify(SOCKET) + ');';
  const env = Object.assign({}, process.env, { LOG_LEVEL: 'fatal' });
  delete env.CONFIG_FILE;
  const child = childProcess.spawn(process.execPath, ['-e', script],
    { cwd: ROOT, env: env, stdio: ['pipe', 'pipe', 'pipe'] });
  log.debug("Leaving startClient().");
  return new Promise(function (resolve) {
    let buffered = '';
    let stderr = '';
    const timer = setTimeout(function () {
      resolve({ child: child, outcome: { ok: false, details: 'timed out; ' +
                                         stderr.slice(-800) } });
    }, 60000);
    child.stderr.on('data', function (chunk) {
      stderr += chunk;
    });
    child.stdout.on('data', function (chunk) {
      buffered += chunk;
      const start = buffered.indexOf('RESULT ');
      const at = start >= 0 ? buffered.indexOf('\n', start) : -1;
      if (at >= 0) {
        clearTimeout(timer);
        let outcome = null;
        try {
          outcome = JSON.parse(buffered.slice(start + 'RESULT '.length, at));
        } catch (e) {
          log.debug("Caught in startClient(): " + ((e && e.message) || e));
          outcome = { ok: false, details: buffered };
        }
        resolve({ child: child, outcome: outcome });
      }
    });
  });
}

// End a client and wait for it to be gone.
function stopClient(child) {
  log.debug("Entering stopClient().");
  log.debug("Leaving stopClient().");
  return new Promise(function (resolve) {
    if (child.exitCode !== null) {
      resolve(undefined);
      return;
    }
    child.on('exit', function () {
      resolve(undefined);
    });
    child.stdin.end();
  });
}

// The facts this service holds for the connection from `pid`, or null.
function factsOfPid(pid) {
  log.debug("Entering factsOfPid().");
  const row = peer.state().connections.filter(function (one) {
    return one.pid === pid;
  })[0];
  log.debug("Leaving factsOfPid().");
  return row ? peer.factsFor(row.tag) : null;
}

function show(value) {
  log.debug("Entering show().");
  log.debug("Leaving show().");
  return JSON.stringify(value);
}

async function realSocket(t) {
  log.debug("Entering realSocket().");
  t.log.info('=== a real connection, from another process ===');
  const availability = peer.availability();
  t.check(availability.available,
          'the native module is built in this image — without it the ' +
          'socket is served unattested in development and not at all in ' +
          'product', availability.problem);
  if (!availability.available) {
    log.debug("Leaving realSocket(). No native module.");
    return;
  }
  const made = realms.get(REALM) ? { ok: true } : realms.create({
    id: REALM, name: REALM, overrides: {
      'spiffe.workloadPort': 0, 'spiffe.serverPort': 0,
      'spiffe.serverSocketEnabled': false,
      'spiffe.workloadSocketEnabled': true,
      'spiffe.workloadSocket': SOCKET } });
  t.check(made.ok, 'a realm of this run\'s own',
          (made.errors || []).join(' '));
  config.setOverride('spiffe.workloadAttestors', 'unix');
  config.setOverride('spiffe.unixDiscoverWorkloadPath', true);
  config.setOverride('spiffe.unixWorkloadSizeLimit', 0);
  try {
    await server.listen().whenReady;
    const on = realms.setOverride(REALM, 'spiffe.enabled', true);
    t.check(on.ok, 'SPIFFE is turned on in it', (on.errors || []).join(' '));
    await server.reconcile();
    const bound = server.bindings();
    const onSocket = ((bound && bound.workload) || []).filter(function (b) {
      return b.address === 'unix://' + SOCKET;
    })[0];
    t.check(!!onSocket && onSocket.listening,
            'the Workload API is bound on its Unix socket', show(bound));

    const first = await startClient();
    t.check(first.outcome.ok, 'the child\'s FetchX509Bundles is answered',
            show(first.outcome));
    const facts = factsOfPid(first.child.pid);
    t.check(!!facts && facts.visible && facts.pidfd >= 0 &&
            facts.uid === process.getuid() && facts.gid === process.getgid(),
            'the kernel names the CHILD — its pid, uid and gid — and a ' +
            'pidfd holds the process', show(facts));
    const values = ((facts && facts.selectors) || []).map(function (s) {
      return s.type + ':' + s.value;
    });
    t.check(values.indexOf('unix:uid:' + process.getuid()) >= 0 &&
            values.indexOf('unix:gid:' + process.getgid()) >= 0 &&
            values.indexOf('unix:path:' +
                           fs.realpathSync(process.execPath)) >= 0 &&
            values.some(function (v) {
              return /^unix:sha256:[0-9a-f]{64}$/.test(v);
            }),
            'the unix attestor gave SPIRE\'s selectors: uid, gid, and the ' +
            'executable\'s path and SHA-256', show(values));
    if (facts) {
      t.equal(peer.stillValid(facts), '',
              'and while the child runs, the connection is still its');
      t.check(/another process/.test(peer.stillValid(
                Object.assign({}, facts, { starttime: '1' }))),
              'a different start time reads as the pid reused by another ' +
              'process');
      t.check(/different program/.test(peer.stillValid(
                Object.assign({}, facts, { exeIno: facts.exeIno + 1 }))),
              'a different executable inode reads as an exec');
    }
    const held = facts ? Object.assign({}, facts) : null;
    await stopClient(first.child);
    if (held) {
      t.check(peer.stillValid(held) !== '',
              'once the child has exited, its facts no longer describe a ' +
              'live process', peer.stillValid(held));
    }
    // Wait for the close to reach this side.
    for (let i = 0; i < 50 && factsOfPid(first.child.pid); i++) {
      await new Promise(function (resolve) {
        setTimeout(resolve, 20);
      });
    }
    t.check(!factsOfPid(first.child.pid),
            'and the connection\'s facts are forgotten when it closes');

    t.log.info('=== an attestor that fails refuses the connection ===');
    config.setOverride('spiffe.unixWorkloadSizeLimit', 1);
    const second = await startClient();
    t.check(!second.outcome.ok && second.outcome.code === 14 &&
            /Workload attestation failed/.test(second.outcome.details || '') &&
            /exceeds size limit/.test(second.outcome.details || ''),
            'an executable over spiffe.unixWorkloadSizeLimit fails the unix ' +
            'attestor, and the call is refused UNAVAILABLE with the reason',
            show(second.outcome));
    await stopClient(second.child);
  } finally {
    realms.setOverride(REALM, 'spiffe.enabled', false);
    await server.reconcile();
    server.close();
    ['spiffe.workloadAttestors', 'spiffe.unixDiscoverWorkloadPath',
     'spiffe.unixWorkloadSizeLimit'].forEach(function (key) {
      config.clearOverride(key);
    });
  }
  log.debug("Leaving realSocket().");
}

// A fake /proc with one process in it.
function fakeProc(pid, cgroup) {
  log.debug("Entering fakeProc().");
  const procRoot = path.join(WORK, 'proc-' + pid);
  fs.mkdirSync(path.join(procRoot, String(pid)), { recursive: true });
  fs.writeFileSync(path.join(procRoot, String(pid), 'status'),
                   'Name:\tapp\nUid:\t1000\t1001\t1001\t1001\n' +
                   'Gid:\t2000\t2001\t2001\t2001\nGroups:\t3000 3001\n');
  fs.writeFileSync(path.join(procRoot, String(pid), 'cgroup'), cgroup || '');
  const exe = path.join(WORK, 'app-binary-' + pid);
  fs.writeFileSync(exe, 'the program');
  fs.symlinkSync(exe, path.join(procRoot, String(pid), 'exe'));
  log.debug("Leaving fakeProc().");
  return { procRoot: procRoot, exe: exe };
}

function attestationTable() {
  log.debug("Entering attestationTable().");
  log.debug("Leaving attestationTable().");
  return new table.WorkloadAttestation(
    table.WorkloadAttestation.defaultDeps());
}

async function fakes(t) {
  log.debug("Entering fakes().");
  const nodeCrypto = require('crypto');
  const workload = attestationTable();

  t.log.info('=== containerinfo ===');
  const docker = fakeProc(101, '0::/system.slice/docker-' + CONTAINER +
                          '.scope\n');
  t.equal(workload.containerInfo(docker.procRoot, 101, false).containerId,
          CONTAINER, 'a docker-<id>.scope cgroup names the container');
  const pod = fakeProc(102, '0::/kubepods.slice/kubepods-burstable.slice/' +
    'kubepods-burstable-pod' + POD.replace(/-/g, '_') + '.slice/' +
    'cri-containerd-' + CONTAINER + '.scope\n');
  t.check(show(workload.containerInfo(pod.procRoot, 102, true)) ===
          show({ podUid: POD, containerId: CONTAINER }),
          'a kubepods cgroup names the pod (underscores read as dashes) and ' +
          'the container', show(workload.containerInfo(pod.procRoot, 102,
                                                       true)));
  const two = fakeProc(103, '1:cpu:/docker/' + CONTAINER + '\n' +
                       '2:memory:/docker/' + OTHER_CONTAINER + '\n');
  let twoThrew = '';
  try {
    workload.containerInfo(two.procRoot, 103, false);
  } catch (e) {
    log.debug("Caught in fakes(): " + ((e && e.message) || e));
    twoThrew = String(e.message);
  }
  t.check(/multiple container IDs/.test(twoThrew),
          'two different container IDs across one process\'s cgroups is ' +
          'an error, as SPIRE\'s extractor', twoThrew);
  const bare = fakeProc(104, '0::/user.slice\n');
  t.equal(workload.containerInfo(bare.procRoot, 104, true).containerId, '',
          'a process in no container has none');

  t.log.info('=== unix ===');
  const passwd = path.join(WORK, 'passwd');
  const group = path.join(WORK, 'group');
  fs.writeFileSync(passwd, 'root:x:0:0::/root:/bin/sh\n' +
                   'app:x:1001:2001::/home/app:/bin/sh\n');
  fs.writeFileSync(group, 'apps:x:2001:\nshared:x:3000:\n');
  const unixDeps = Object.assign(unixAttestor.UnixWorkloadAttestor
    .defaultDeps(), { passwdPath: passwd, groupPath: group });
  const unix = new unixAttestor.UnixWorkloadAttestor(unixDeps);
  config.setOverride('spiffe.unixDiscoverWorkloadPath', true);
  config.setOverride('spiffe.unixWorkloadSizeLimit', 0);
  try {
    const got = await unix.attest({ tag: 't', visible: true, pid: 101,
                                    procRoot: docker.procRoot });
    const digest = nodeCrypto.createHash('sha256').update('the program')
      .digest('hex');
    t.check(show(got) === show(['uid:1001', 'user:app', 'gid:2001',
                                'group:apps', 'supplementary_gid:3000',
                                'supplementary_group:shared',
                                'supplementary_gid:3001', 'path:' + docker.exe,
                                'sha256:' + digest]),
            'the EFFECTIVE uid and gid, their names, each supplementary ' +
            'group, and the executable\'s path and SHA-256', show(got));
    config.setOverride('spiffe.unixWorkloadSizeLimit', -1);
    const noHash = await unix.attest({ tag: 't', visible: true, pid: 101,
                                       procRoot: docker.procRoot });
    t.check(!noHash.some(function (v) {
              return /^sha256:/.test(v);
            }), 'a size limit of -1 hashes nothing', show(noHash));
    config.setOverride('spiffe.unixWorkloadSizeLimit', 3);
    let tooBig = '';
    try {
      await unix.attest({ tag: 't', visible: true, pid: 101,
                          procRoot: docker.procRoot });
    } catch (e) {
      log.debug("Caught in fakes(): " + ((e && e.message) || e));
      tooBig = String(e.message);
    }
    t.check(/exceeds size limit/.test(tooBig),
            'an executable over the limit fails the attestor', tooBig);
  } finally {
    config.clearOverride('spiffe.unixDiscoverWorkloadPath');
    config.clearOverride('spiffe.unixWorkloadSizeLimit');
  }
  const hidden = await unix.attest({ tag: 't', visible: false, pid: 0,
                                     uid: 0, gid: 3000 });
  t.check(show(hidden) === show(['uid:0', 'user:root', 'gid:3000',
                                 'group:shared']),
          'a peer in another pid namespace gets its kernel uid and gid and ' +
          'nothing that needs the process', show(hidden));

  t.log.info('=== docker ===');
  const asked = [];
  const engine = {
    requestLocalSocket: function (socketPath, requestPath) {
      asked.push(socketPath + ' ' + requestPath);
      if (requestPath.indexOf('/containers/' + CONTAINER + '/json') >= 0) {
        return Promise.resolve({ ok: true, status: 200, body: Buffer.from(
          JSON.stringify({ Config: { Labels: { tier: 'web' },
                                     Env: ['MODE=prod'],
                                     Image: 'registry/app:1' } })) });
      }
      if (requestPath.indexOf('/images/') >= 0) {
        return Promise.resolve({ ok: true, status: 200, body: Buffer.from(
          JSON.stringify({ Id: 'sha256:' + 'c'.repeat(64) })) });
      }
      return Promise.resolve({ ok: false, status: 404, why: 'HTTP 404' });
    }
  };
  const dockerDeps = Object.assign(dockerAttestor.DockerWorkloadAttestor
    .defaultDeps(workload.containerInfo.bind(workload)), { outbound: engine });
  const dockerOne = new dockerAttestor.DockerWorkloadAttestor(dockerDeps);
  config.setOverride('spiffe.dockerApiVersion', '1.43');
  try {
    const got = await dockerOne.attest({ tag: 't', visible: true, pid: 101,
                                         procRoot: docker.procRoot });
    t.check(show(got) === show(['label:tier:web', 'env:MODE=prod',
                                'image_id:registry/app:1',
                                'image_config_digest:sha256:' +
                                'c'.repeat(64)]),
            'labels, environment, image and image configuration digest',
            show(got));
    t.check(asked[0] === '/var/run/docker.sock /v1.43/containers/' +
            CONTAINER + '/json',
            'asked of the Engine socket (unix:// stripped) at the ' +
            'configured API version', asked[0]);
    const none = await dockerOne.attest({ tag: 't', visible: true, pid: 104,
                                          procRoot: bare.procRoot });
    t.equal(none.length, 0, 'a process in no container gets no docker ' +
            'selectors — SPIRE\'s empty answer, not an error');
    const gone = fakeProc(105, '0::/docker/' + OTHER_CONTAINER + '\n');
    let unknown = '';
    try {
      await dockerOne.attest({ tag: 't', visible: true, pid: 105,
                               procRoot: gone.procRoot });
    } catch (e) {
      log.debug("Caught in fakes(): " + ((e && e.message) || e));
      unknown = String(e.message);
    }
    t.check(/HTTP 404/.test(unknown),
            'a container the Engine does not know fails the attestor',
            unknown);
  } finally {
    config.clearOverride('spiffe.dockerApiVersion');
  }

  t.log.info('=== k8s ===');
  const podItem = {
    metadata: { name: 'web-0', namespace: 'shop', uid: POD,
                labels: { app: 'web' },
                ownerReferences: [{ kind: 'StatefulSet', name: 'web',
                                    uid: 'owner-uid' }] },
    spec: { serviceAccountName: 'web-sa', nodeName: 'node-1' },
    status: { containerStatuses: [{ name: 'main', image: 'app:1',
                                    imageID: 'app@sha256:1',
                                    containerID: 'containerd://' +
                                                 CONTAINER }] }
  };
  let polls = 0;
  let neverThere = false;
  const dialled = [];
  const kubelet = {
    requestConfigured: function (url, options) {
      dialled.push({ url: url, options: options });
      polls += 1;
      // The first read does not have the container yet, as a kubelet
      // that has not caught up would not.
      const items = polls === 1 || neverThere ? [] : [podItem];
      return Promise.resolve({ ok: true, status: 200,
        body: Buffer.from(JSON.stringify({ items: items })) });
    }
  };
  const k8sDeps = Object.assign(k8sAttestor.K8sWorkloadAttestor.defaultDeps(
    workload.containerInfo.bind(workload)), {
      outbound: kubelet,
      sleep: function () {
        return Promise.resolve();
      } });
  const k8s = new k8sAttestor.K8sWorkloadAttestor(k8sDeps);
  config.setOverride('spiffe.k8sKubeletReadOnlyPort', 10255);
  config.setOverride('spiffe.k8sMaxPollAttempts', 3);
  try {
    const got = await k8s.attest({ tag: 't', visible: true, pid: 102,
                                   procRoot: pod.procRoot });
    ['sa:web-sa', 'ns:shop', 'node-name:node-1', 'pod-uid:' + POD,
     'pod-name:web-0', 'pod-label:app:web', 'pod-owner:StatefulSet:web',
     'container-name:main', 'container-image:app:1',
     'container-image:app@sha256:1'].forEach(function (one) {
      t.check(got.indexOf(one) >= 0, 'k8s selector ' + one, show(got));
    });
    t.check(polls === 2 && dialled[0].url === 'http://127.0.0.1:10255/pods' &&
            dialled[0].options.loopbackPlainHttp === true,
            'a container not yet in the pod list is polled for again, over ' +
            'the read-only port on the loopback address only',
            polls + ' ' + show(dialled[0]));
    neverThere = true;
    config.setOverride('spiffe.k8sMaxPollAttempts', 2);
    let missing = '';
    try {
      await k8s.attest({ tag: 't', visible: true, pid: 102,
                         procRoot: pod.procRoot });
    } catch (e) {
      log.debug("Caught in fakes(): " + ((e && e.message) || e));
      missing = String(e.message);
    }
    neverThere = false;
    t.check(/max poll attempts/.test(missing),
            'a container never found fails once the attempts are spent',
            missing);
    config.clearOverride('spiffe.k8sKubeletReadOnlyPort');
    config.setOverride('spiffe.k8sNodeName', 'node-1');
    dialled.length = 0;
    polls = 1;
    await k8s.attest({ tag: 't', visible: true, pid: 102,
                       procRoot: pod.procRoot });
    t.check(dialled[0].url === 'https://node-1:10250/pods' &&
            !dialled[0].options.chainOnly && !dialled[0].options.skipVerify,
            'with a node name the secure port is dialled by that name and ' +
            'its certificate verified for it', show(dialled[0]));
  } finally {
    ['spiffe.k8sKubeletReadOnlyPort', 'spiffe.k8sMaxPollAttempts',
     'spiffe.k8sNodeName'].forEach(function (key) {
      config.clearOverride(key);
    });
  }

  t.log.info('=== the table ===');
  const failing = attestationTable();
  failing.register({ type: 'unix', verifies: 'x', attest: function () {
    return Promise.reject(new Error('boom'));
  } });
  let failed = '';
  try {
    await failing.attest({ tag: 't' });
  } catch (e) {
    log.debug("Caught in fakes(): " + ((e && e.message) || e));
    failed = String(e.message);
  }
  t.equal(failed, 'the unix workload attestor failed: boom',
          'an attestor that fails fails the attestation, naming itself');
  config.setOverride('spiffe.workloadAttestors', 'unix,nosuch');
  try {
    t.check(show(failing.state().unknownConfigured) === show(['nosuch']),
            'a configured attestor that does not exist is reported, not ' +
            'silently ignored', show(failing.state()));
  } finally {
    config.clearOverride('spiffe.workloadAttestors');
  }
  t.check(mode.requiresWorkloadAttestation() === mode.isProduct() &&
          mode.believesAssertedSelectors() === !mode.isProduct(),
          'product requires attestation and believes no asserted selector');
  log.debug("Leaving fakes().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    await fakes(t);
    await realSocket(t);
  } finally {
    try {
      fs.rmSync(WORK, { recursive: true, force: true });
    } catch (e) {
      // A socket the kernel still holds; a temporary directory left behind
      // is not a failure of anything under test.
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_workload_attestation',
  describe: 'the Workload API\'s Unix socket attests its caller\'s process ' +
            '(unix, docker, k8s) and refuses a connection it cannot',
  run: run
};
