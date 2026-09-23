'use strict';
//
// File: spiffe_attestor_systemd_podman.js
//
// ===========================================================================
// THE `systemd` WORKLOAD ATTESTOR AND THE DOCKER ATTESTOR'S PODMAN SUPPORT
// (#170, 2026-09-23), over fakes.
//
//   1. systemd, over a FAKE D-Bus client handed in through the attestor's
//      `load`: GetUnitByPID for the caller's pid, then the unit's Id and
//      FragmentPath off the object path it answered, as SPIRE's two
//      selectors; nothing for a peer this service cannot see (pid 0 would be
//      "the unit asking", which is this service's own); a refusal naming
//      the package when `dbus-next` is not installed; a refusal when the
//      process is no longer the one that connected by the time systemd
//      answers (the pidfd check SPIRE does not have); and a D-Bus failure.
//   2. Podman, over a fake /proc and a fake Engine that records which
//      socket it was asked on: a `libpod-<id>.scope` cgroup asks the ROOTFUL
//      Podman socket; a rootless one (`user-<uid>.slice`) is not attested at
//      all with `spiffe.dockerUseRootlessPodman` off, and asks the socket the
//      template names for that uid with it on; a template without exactly
//      one %d is refused; a Docker cgroup still asks the Engine.
// ===========================================================================

const os = require('os');
const path = require('path');
const fs = require('fs');

const config = require('../common/config');
const table = require('../spiffe/spiffe_workload_attestation');
const systemdAttestor = require('../spiffe/spiffe_workload_attestor_systemd');
const dockerAttestor = require('../spiffe/spiffe_workload_attestor_docker');

const log = require('bunyan').createLogger({
  name: 'spiffe_attestor_systemd_podman',
  level: process.env.LOG_LEVEL || 'info' });

const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-systemd-podman-'));
const CONTAINER = 'c'.repeat(64);

function show(value) {
  log.debug("Entering show().");
  log.debug("Leaving show().");
  return JSON.stringify(value);
}

// A fake `dbus-next`: a system bus whose systemd answers GetUnitByPID from
// `units` (pid -> { path, id, fragmentPath }), and records what it was asked.
function fakeDbus(units, asked, failProperties) {
  log.debug("Entering fakeDbus().");
  const bus = {
    disconnected: false,
    disconnect: function () {
      bus.disconnected = true;
    },
    getProxyObject: function (name, objectPath) {
      asked.push(name + ' ' + objectPath);
      if (objectPath === '/org/freedesktop/systemd1') {
        return Promise.resolve({ getInterface: function (iface) {
          asked.push(iface);
          return { GetUnitByPID: function (pid) {
            asked.push('GetUnitByPID ' + pid);
            const unit = units[String(pid)];
            return unit ? Promise.resolve(unit.path)
              : Promise.reject(new Error('PID ' + pid + ' does not belong ' +
                                         'to any loaded unit.'));
          } };
        } });
      }
      const unit = Object.keys(units).map(function (k) {
        return units[k];
      }).filter(function (u) {
        return u.path === objectPath;
      })[0];
      return Promise.resolve({ getInterface: function (iface) {
        asked.push(iface);
        return { Get: function (unitIface, property) {
          asked.push('Get ' + unitIface + ' ' + property);
          if (failProperties) {
            return Promise.reject(new Error('no such property'));
          }
          const value = property === 'Id' ? unit.id : unit.fragmentPath;
          return Promise.resolve({ signature: 's', value: value });
        } };
      } });
    }
  };
  log.debug("Leaving fakeDbus().");
  return { systemBus: function () {
    return bus;
  }, bus: bus };
}

async function systemd(t) {
  log.debug("Entering systemd().");
  t.log.info('=== systemd ===');
  const asked = [];
  const units = { '4242': {
    path: '/org/freedesktop/systemd1/unit/web_2eservice',
    id: 'web.service',
    fragmentPath: '/etc/systemd/system/web.service' } };
  let valid = '';
  const dbus = fakeDbus(units, asked, false);
  const attestor = new systemdAttestor.SystemdWorkloadAttestor(Object.assign(
    systemdAttestor.SystemdWorkloadAttestor.defaultDeps(function () {
      return valid;
    }), { load: function (pkg) {
      asked.push('load ' + pkg);
      return dbus;
    } }));
  const facts = { tag: 't', visible: true, pid: 4242 };
  const got = await attestor.attest(facts);
  t.check(show(got) === show(['id:web.service',
                              'fragment_path:/etc/systemd/system/web.service']),
          'SPIRE\'s two selectors, id: and fragment_path:', show(got));
  t.check(asked.indexOf('load dbus-next') >= 0 &&
          asked.indexOf('org.freedesktop.systemd1 /org/freedesktop/systemd1') >=
            0 &&
          asked.indexOf('org.freedesktop.systemd1.Manager') >= 0 &&
          asked.indexOf('GetUnitByPID 4242') >= 0 &&
          asked.indexOf('Get org.freedesktop.systemd1.Unit Id') >= 0 &&
          asked.indexOf('Get org.freedesktop.systemd1.Unit FragmentPath') >= 0,
          'asked GetUnitByPID on the systemd manager, then the unit\'s Id ' +
          'and FragmentPath, over the system bus', show(asked));

  const hidden = await attestor.attest({ tag: 't', visible: false, pid: 0 });
  t.equal(hidden.length, 0, 'a peer in another pid namespace gets no systemd ' +
          'selectors, never the unit of pid 0 (this service\'s own)');

  valid = 'the pid that connected now belongs to another process';
  let changed = '';
  try {
    await attestor.attest(facts);
  } catch (e) {
    log.debug("Caught in systemd(): " + ((e && e.message) || e));
    changed = String(e.message);
  }
  t.check(/process changed while systemd was asked/.test(changed),
          'a process that is no longer the one that connected when systemd ' +
          'answers fails the attestation — the pidfd check', changed);
  valid = '';

  let unknown = '';
  try {
    await attestor.attest({ tag: 't', visible: true, pid: 7 });
  } catch (e) {
    log.debug("Caught in systemd(): " + ((e && e.message) || e));
    unknown = String(e.message);
  }
  t.check(/failed to get unit by pid 7/.test(unknown) &&
          dbus.bus.disconnected,
          'a D-Bus failure fails the attestation and drops the bus', unknown);

  const failing = new systemdAttestor.SystemdWorkloadAttestor(Object.assign(
    systemdAttestor.SystemdWorkloadAttestor.defaultDeps(function () {
      return '';
    }), { load: function () {
      return fakeDbus(units, [], true);
    } }));
  let property = '';
  try {
    await failing.attest(facts);
  } catch (e) {
    log.debug("Caught in systemd(): " + ((e && e.message) || e));
    property = String(e.message);
  }
  t.check(/no such property/.test(property),
          'a unit property that cannot be read fails the attestation',
          property);

  const missing = new systemdAttestor.SystemdWorkloadAttestor(Object.assign(
    systemdAttestor.SystemdWorkloadAttestor.defaultDeps(function () {
      return '';
    }), { load: function () {
      const err = new Error('Cannot find module \'dbus-next\'');
      throw err;
    } }));
  let noPackage = '';
  try {
    await missing.attest(facts);
  } catch (e) {
    log.debug("Caught in systemd(): " + ((e && e.message) || e));
    noPackage = String(e.message);
  }
  t.check(/dbus-next/.test(noPackage) &&
          /npm install dbus-next/.test(noPackage),
          'without the optional D-Bus client the attestation is refused, ' +
          'naming the package', noPackage);
  t.equal(systemdAttestor.DBUS_PACKAGE, 'dbus-next',
          'the package is dbus-next');
  log.debug("Leaving systemd().");
}

// A fake /proc entry whose cgroup file is `cgroup`.
function fakeProc(pid, cgroup) {
  log.debug("Entering fakeProc().");
  const procRoot = path.join(WORK, 'proc-' + pid);
  fs.mkdirSync(path.join(procRoot, String(pid)), { recursive: true });
  fs.writeFileSync(path.join(procRoot, String(pid), 'cgroup'), cgroup);
  log.debug("Leaving fakeProc().");
  return procRoot;
}

async function podman(t) {
  log.debug("Entering podman().");
  t.log.info('=== Podman ===');
  const workload = new table.WorkloadAttestation(
    table.WorkloadAttestation.defaultDeps());
  const asked = [];
  const engine = {
    requestLocalSocket: function (socketPath, requestPath) {
      asked.push(socketPath + ' ' + requestPath);
      if (requestPath.indexOf('/containers/' + CONTAINER + '/json') >= 0) {
        return Promise.resolve({ ok: true, status: 200, body: Buffer.from(
          JSON.stringify({ Config: { Labels: { app: 'pod' }, Env: [],
                                     Image: '' } })) });
      }
      return Promise.resolve({ ok: false, status: 404, why: 'HTTP 404' });
    }
  };
  const attestor = new dockerAttestor.DockerWorkloadAttestor(Object.assign(
    dockerAttestor.DockerWorkloadAttestor.defaultDeps(
      workload.containerInfo.bind(workload),
      workload.cgroupPaths.bind(workload), null), { outbound: engine }));

  const rootful = fakeProc(301, '0::/machine.slice/libpod-' + CONTAINER +
                           '.scope/container\n');
  t.equal(workload.containerInfo(rootful, 301, false).containerId, CONTAINER,
          'the containerinfo extractor reads a libpod-<id>.scope cgroup');
  let got = await attestor.attest({ tag: 't', visible: true, pid: 301,
                                    procRoot: rootful });
  t.check(asked[0] === '/run/podman/podman.sock /containers/' + CONTAINER +
          '/json' && got.indexOf('label:app:pod') >= 0,
          'a rootful Podman container is asked of Podman\'s socket, and the ' +
          'selectors stay docker:', show(asked) + ' ' + show(got));

  const rootless = fakeProc(302, '0::/user.slice/user-1000.slice/' +
    'user@1000.service/user.slice/libpod-' + CONTAINER + '.scope/container\n');
  asked.length = 0;
  got = await attestor.attest({ tag: 't', visible: true, pid: 302,
                                procRoot: rootless });
  t.check(got.length === 0 && asked.length === 0,
          'a rootless Podman container is NOT attested while ' +
          'spiffe.dockerUseRootlessPodman is off — its socket is the ' +
          'caller\'s own', show(asked));

  config.setOverride('spiffe.dockerUseRootlessPodman', true);
  try {
    got = await attestor.attest({ tag: 't', visible: true, pid: 302,
                                  procRoot: rootless });
    t.check(asked[0] === '/run/user/1000/podman/podman.sock /containers/' +
            CONTAINER + '/json' && got.indexOf('label:app:pod') >= 0,
            'with it on, the socket the template names for the cgroup\'s ' +
            'uid is asked', show(asked));
    config.setOverride('spiffe.dockerPodmanSocketPathTemplate',
                       'unix:///run/user/podman.sock');
    let noPlaceholder = '';
    try {
      await attestor.attest({ tag: 't', visible: true, pid: 302,
                              procRoot: rootless });
    } catch (e) {
      log.debug("Caught in podman(): " + ((e && e.message) || e));
      noPlaceholder = String(e.message);
    }
    t.check(/exactly one %d/.test(noPlaceholder),
            'a template without a %d is refused, as SPIRE refuses it',
            noPlaceholder);
    config.setOverride('spiffe.dockerPodmanSocketPathTemplate',
                       'unix:///run/%s/%d.sock');
    let badVerb = '';
    try {
      await attestor.attest({ tag: 't', visible: true, pid: 302,
                              procRoot: rootless });
    } catch (e) {
      log.debug("Caught in podman(): " + ((e && e.message) || e));
      badVerb = String(e.message);
    }
    t.check(/only supports escaped %% or the %d/.test(badVerb),
            'and one with any verb but %d and %%', badVerb);
    t.equal(attestor.fillTemplate('/run/%%/%d.sock', 7), '/run/%/7.sock',
            '%% is a literal percent sign');
  } finally {
    config.clearOverride('spiffe.dockerUseRootlessPodman');
    config.clearOverride('spiffe.dockerPodmanSocketPathTemplate');
  }

  const docker = fakeProc(303, '0::/system.slice/docker-' + CONTAINER +
                          '.scope\n');
  asked.length = 0;
  await attestor.attest({ tag: 't', visible: true, pid: 303,
                          procRoot: docker });
  t.check(asked[0] === '/var/run/docker.sock /containers/' + CONTAINER +
          '/json', 'a Docker container is still asked of the Engine',
          show(asked));
  log.debug("Leaving podman().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    await systemd(t);
    await podman(t);
  } finally {
    try {
      fs.rmSync(WORK, { recursive: true, force: true });
    } catch (e) {
      // A temporary directory left behind is not a failure of anything
      // under test.
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_attestor_systemd_podman',
  describe: 'the systemd workload attestor over a fake D-Bus, pidfd-checked, ' +
            'and the docker attestor\'s rootful and rootless Podman sockets',
  run: run
};
