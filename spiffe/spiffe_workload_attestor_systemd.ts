'use strict';
//
// File: spiffe_workload_attestor_systemd.ts
//
// ---------------------------------------------------------------------------
// THE `systemd` WORKLOAD ATTESTOR (#170, 2026-09-23).
//
// SPIRE's `pkg/agent/plugin/workloadattestor/systemd`, step for step:
//
//   1. systemd is asked over D-Bus which unit holds the caller's process —
//      `org.freedesktop.systemd1.Manager.GetUnitByPID` on
//      `/org/freedesktop/systemd1` of the system bus;
//   2. the unit's `Id` and `FragmentPath` properties
//      (`org.freedesktop.systemd1.Unit`) are read off the object path it
//      answered;
//   3. the selectors are SPIRE's two, spelt as in its source:
//      `id:<unit>` and `fragment_path:<unit file>`.
//
// **THE PID IS PIDFD-CHECKED, WHICH SPIRE'S IS NOT.** GetUnitByPID takes a
// bare number, and a number is a race: the process that connected may exit
// and its pid be reused by a process in another unit between accept and the
// D-Bus answer, and systemd would then name the OTHER unit. So the facts
// `spiffe_peer.ts` took at accept — a pidfd, the start time and the
// executable inode — are asked again AFTER systemd has answered
// (`stillValid()`), and a process that is no longer the one that connected
// fails the attestation (STS-SPIFFE-0125) rather than taking another unit's
// selectors. The pidfd keeps the pid from being REUSED while it is open, so
// the check after is the one that closes the window.
//
// **A PEER THIS SERVICE CANNOT SEE GETS NO systemd SELECTORS.** A caller in
// another pid namespace has pid 0 from SO_PEERCRED, and GetUnitByPID(0) is
// "the unit of the process asking" — this service's own unit. Answering that
// would hand a workload the service's identity, so `facts.visible` false is
// the empty answer, never a question to systemd.
//
// **THE D-BUS CLIENT IS AN OPTIONAL PEER DEPENDENCY** (`dbus-next`), in the
// way `common/secrets.js` holds its SDKs: loaded on first use through
// `load` in the constructor dependencies — which is how the test hands it a
// fake bus — and a realm that names `systemd` without it installed has every
// connection refused with a sentence naming the package (STS-SPIFFE-0124,
// logged once per process), because an attestor that cannot run must fail
// the attestation, never quietly contribute nothing.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
const { log } = helpers;
import errorCodes = require('../common/error_codes');

// The npm package that speaks D-Bus. Named once: it is in the refusal.
const DBUS_PACKAGE = 'dbus-next';

// SPIRE's constants (`systemd_posix.go`).
const SYSTEMD_BUS_NAME = 'org.freedesktop.systemd1';
const SYSTEMD_PATH = '/org/freedesktop/systemd1';
const MANAGER_INTERFACE = 'org.freedesktop.systemd1.Manager';
const UNIT_INTERFACE = 'org.freedesktop.systemd1.Unit';
const PROPERTIES_INTERFACE = 'org.freedesktop.DBus.Properties';

interface SystemdDeps {
  log: typeof log;
  errorCodes: typeof errorCodes;
  // The D-Bus client package, or a throw when it is not installed.
  load(pkg: string): any;
  // `spiffe_peer.ts`'s per-call check: '' when the facts still describe the
  // process holding the connection, otherwise why not.
  stillValid(facts: any): string;
}

class SystemdWorkloadAttestor {
  readonly type = 'systemd';
  readonly verifies = 'The systemd unit that holds the caller\'s process, ' +
    'as systemd reports it over D-Bus: its id and its unit file.';

  // The system bus, opened on first use and kept, as SPIRE keeps its
  // connection; dropped when a call on it fails so the next attestation
  // opens a fresh one.
  private bus: any = null;
  // Whether STS-SPIFFE-0124 has been logged in this process.
  private missingLogged = false;

  constructor(private readonly deps: SystemdDeps) {
    deps.log.debug("Entering SystemdWorkloadAttestor.constructor().");
    deps.log.debug("Leaving SystemdWorkloadAttestor.constructor().");
  }

  static defaultDeps(stillValid: SystemdDeps['stillValid']): SystemdDeps {
    helpers.log.debug("Entering SystemdWorkloadAttestor.defaultDeps().");
    helpers.log.debug("Leaving SystemdWorkloadAttestor.defaultDeps().");
    return {
      log: log, errorCodes: errorCodes, stillValid: stillValid,
      load: function (pkg: string) {
        return require(pkg);
      }
    };
  }

  // The D-Bus package, or a sentence naming it. Asked on every attestation
  // rather than once, so installing it needs no restart.
  client(): { dbus: any; missing: string } {
    const { log, load, errorCodes } = this.deps;
    log.debug("Entering SystemdWorkloadAttestor.client().");
    try {
      const dbus = load(DBUS_PACKAGE);
      log.debug("Leaving SystemdWorkloadAttestor.client().");
      return { dbus: dbus, missing: '' };
    } catch (e) {
      log.debug("Caught in SystemdWorkloadAttestor.client(): " +
                ((e && e.message) || e));
      const why = 'the systemd workload attestor asks systemd over D-Bus ' +
        'with ' + DBUS_PACKAGE + ', which is not installed. It is an ' +
        'optional peer dependency: run `npm install ' + DBUS_PACKAGE +
        '` in this deployment, or take systemd out of ' +
        'spiffe.workloadAttestors';
      if (!this.missingLogged) {
        this.missingLogged = true;
        log.error(errorCodes.tag('STS-SPIFFE-0124') + 'spiffe: ' + why + '.');
      }
      log.debug("Leaving SystemdWorkloadAttestor.client(). Missing.");
      return { dbus: null, missing: why };
    }
  }

  // The system bus, opened once.
  systemBus(dbus: any): any {
    const { log } = this.deps;
    log.debug("Entering SystemdWorkloadAttestor.systemBus().");
    if (!this.bus) {
      this.bus = dbus.systemBus();
    }
    log.debug("Leaving SystemdWorkloadAttestor.systemBus().");
    return this.bus;
  }

  // Forget the bus after a failure; its socket may be the reason.
  dropBus(): void {
    const { log } = this.deps;
    log.debug("Entering SystemdWorkloadAttestor.dropBus().");
    const held = this.bus;
    this.bus = null;
    if (held && typeof held.disconnect === 'function') {
      try {
        held.disconnect();
      } catch (e) {
        // A bus already gone. Nothing depends on the disconnect working.
        log.debug("Caught in SystemdWorkloadAttestor.dropBus(): " +
                  ((e && e.message) || e));
      }
    }
    log.debug("Leaving SystemdWorkloadAttestor.dropBus().");
  }

  // One string property of a unit (SPIRE's getStringProperty()).
  async stringProperty(bus: any, unitPath: string, name: string):
      Promise<string> {
    const { log } = this.deps;
    log.debug("Entering SystemdWorkloadAttestor.stringProperty(). " + name);
    const unit = await bus.getProxyObject(SYSTEMD_BUS_NAME, unitPath);
    const properties = unit.getInterface(PROPERTIES_INTERFACE);
    const variant = await properties.Get(UNIT_INTERFACE, name);
    const value = variant && typeof variant === 'object' && 'value' in variant
      ? variant.value : variant;
    if (typeof value !== 'string') {
      log.debug("Leaving SystemdWorkloadAttestor.stringProperty(). Not a " +
                "string.");
      // error-code: none — reported by the table under STS-SPIFFE-0125
      throw new Error('Returned value for ' + name + ' was not a string');
    }
    log.debug("Leaving SystemdWorkloadAttestor.stringProperty().");
    return value;
  }

  // SPIRE's getSystemdUnitInfo(): the unit's Id and FragmentPath.
  async unitOf(pid: number): Promise<{ id: string; fragmentPath: string }> {
    const { log } = this.deps;
    log.debug("Entering SystemdWorkloadAttestor.unitOf(). pid=" + pid);
    const client = this.client();
    if (client.missing) {
      log.debug("Leaving SystemdWorkloadAttestor.unitOf(). No client.");
      // error-code: none — logged once above as STS-SPIFFE-0124, and every
      // call on the connection is refused under STS-SPIFFE-0111
      throw new Error(client.missing);
    }
    const bus = this.systemBus(client.dbus);
    try {
      const systemd = await bus.getProxyObject(SYSTEMD_BUS_NAME, SYSTEMD_PATH);
      const manager = systemd.getInterface(MANAGER_INTERFACE);
      const unitPath = String(await manager.GetUnitByPID(pid));
      const id = await this.stringProperty(bus, unitPath, 'Id');
      const fragmentPath = await this.stringProperty(bus, unitPath,
                                                     'FragmentPath');
      log.debug("Leaving SystemdWorkloadAttestor.unitOf(). " + id);
      return { id: id, fragmentPath: fragmentPath };
    } catch (e) {
      log.debug("Caught in SystemdWorkloadAttestor.unitOf(): " +
                ((e && e.message) || e));
      this.dropBus();
      log.debug("Leaving SystemdWorkloadAttestor.unitOf(). Failed.");
      // error-code: none — tagged by attest() as STS-SPIFFE-0125
      throw new Error('failed to get unit by pid ' + pid + ': ' +
                      ((e && e.message) || e));
    }
  }

  async attest(facts: any): Promise<string[]> {
    const { log, stillValid, errorCodes } = this.deps;
    log.debug("Entering SystemdWorkloadAttestor.attest(). " + facts.tag);
    if (!facts.visible || !(facts.pid > 0)) {
      log.debug("Leaving SystemdWorkloadAttestor.attest(). Not visible.");
      return [];
    }
    let unit = null;
    try {
      unit = await this.unitOf(facts.pid);
    } catch (e) {
      log.debug("Caught in SystemdWorkloadAttestor.attest(): " +
                ((e && e.message) || e));
      if (!/is not installed/.test(String((e && e.message) || ''))) {
        log.info(errorCodes.tag('STS-SPIFFE-0125') + 'spiffe: systemd could ' +
                 'not name the unit of pid ' + facts.pid + ': ' +
                 ((e && e.message) || e));
      }
      log.debug("Leaving SystemdWorkloadAttestor.attest(). Failed.");
      throw e;
    }
    // THE PIDFD CHECK — see the header. After the answer, not before: the
    // question is whether the process systemd was asked about is still the
    // one that connected.
    const changed = stillValid(facts);
    if (changed) {
      log.info(errorCodes.tag('STS-SPIFFE-0125') + 'spiffe: the systemd ' +
               'unit of pid ' + facts.pid + ' was not believed: ' + changed);
      log.debug("Leaving SystemdWorkloadAttestor.attest(). Changed.");
      // error-code: none — tagged on the line above
      throw new Error('the process changed while systemd was asked about ' +
                      'it: ' + changed);
    }
    log.debug("Leaving SystemdWorkloadAttestor.attest(). " + unit.id);
    return ['id:' + unit.id, 'fragment_path:' + unit.fragmentPath];
  }
}

export = {
  SystemdWorkloadAttestor: SystemdWorkloadAttestor,
  DBUS_PACKAGE: DBUS_PACKAGE
};
