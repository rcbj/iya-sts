'use strict';
//
// File: spiffe_workload_attestation.ts
//
// ---------------------------------------------------------------------------
// THE WORKLOAD ATTESTORS, AS A TABLE (#40 phase four, 2026-09-21).
//
// This service IS the SPIRE agent for its own Workload API, and a SPIRE
// agent attests the workload that connects to it: the kernel names the
// process (`spiffe_peer.ts`), and each workload attestor turns the process
// into selectors — `unix` (who it runs as, what it runs), `docker` (the
// container it is in, Docker's or Podman's), `k8s` (the pod) and `systemd`
// (the unit). rcbj's decision on #40 was the first three; `systemd`, Podman
// and the docker attestor's sigstore checks came with #170 (2026-09-23),
// which also made this table the one a SPIFFE Broker API PROCESS reference
// is attested through (`spiffe_broker.ts`).
//
// **WHEN**: once per CONNECTION, at accept, before gRPC sees it — the
// connection is handed on only when the attestors have answered, so the
// first call never races them — and every call then asks
// `spiffe_peer.stillValid()` whether the process is still the one attested.
// SPIRE attests per call; this attests per connection and REVALIDATES per
// call (the pidfd is alive, the start time and the executable inode are
// unchanged), which refuses the two cases per-call attestation exists for —
// a pid reused by another process, and a process that exec'd something else.
//
// `spiffe.workloadAttestors` (per realm, default `unix`) names the ones that
// run. An attestor that FAILS fails the connection: every call on it is
// refused with the reason, as SPIRE fails the Workload API call — a
// workload is never handed an identity on a partial attestation.
//
// The container and pod IDs come from `containerInfo()` below, which is
// SPIRE's `pkg/common/containerinfo` extractor: the last 64-hex segment of a
// cgroup path is the container, a `pod<uuid>` segment before it the pod, and
// two different answers across a process's cgroups is an error.
// ---------------------------------------------------------------------------

import fs = require('fs');
import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');

type Selector = { type: string; value: string };

interface WorkloadAttestor {
  readonly type: string;
  readonly verifies: string;
  attest(facts: any): Promise<string[]>;
}

interface WorkloadAttestationDeps {
  log: typeof log;
  fs: typeof fs;
  config: typeof config;
}

const CONTAINER_ID = /\b([0-9a-fA-F]{64})\b/;
const POD_UID = /\bpod([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12})\b/;

class WorkloadAttestation {
  private readonly attestors = new Map<string, WorkloadAttestor>();

  constructor(private readonly deps: WorkloadAttestationDeps) {
    deps.log.debug("Entering WorkloadAttestation.constructor().");
    deps.log.debug("Leaving WorkloadAttestation.constructor().");
  }

  static defaultDeps(): WorkloadAttestationDeps {
    helpers.log.debug("Entering WorkloadAttestation.defaultDeps().");
    helpers.log.debug("Leaving WorkloadAttestation.defaultDeps().");
    return { log: log, fs: fs, config: config };
  }

  register(attestor: WorkloadAttestor): void {
    const { log } = this.deps;
    log.debug("Entering WorkloadAttestation.register(). " + attestor.type);
    if (this.attestors.has(attestor.type)) {
      log.debug("Leaving WorkloadAttestation.register(). A duplicate.");
      // error-code: none — a defect in the table's construction
      throw new Error('The workload attestor ' + attestor.type + ' is ' +
                      'registered twice.');
    }
    this.attestors.set(attestor.type, attestor);
    log.debug("Leaving WorkloadAttestation.register().");
  }

  // One registered attestor by type, or null — the Broker API asks the
  // `k8s` one about a pod reference (#170).
  attestor(type: string): any {
    const { log } = this.deps;
    log.debug("Entering WorkloadAttestation.attestor(). " + type);
    log.debug("Leaving WorkloadAttestation.attestor().");
    return this.attestors.get(type) || null;
  }

  configured(): string[] {
    const { log, config } = this.deps;
    log.debug("Entering WorkloadAttestation.configured().");
    const raw = config.value('spiffe.workloadAttestors');
    log.debug("Leaving WorkloadAttestation.configured().");
    return (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one) {
        return String(one).trim();
      }).filter(Boolean);
  }

  enabled(): string[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering WorkloadAttestation.enabled().");
    log.debug("Leaving WorkloadAttestation.enabled().");
    return this.configured().filter(function (type) {
      return self.attestors.has(type);
    });
  }

  // Every enabled attestor over `facts`, in order; the selectors, or a
  // thrown sentence naming the attestor that failed.
  async attest(facts: any): Promise<Selector[]> {
    const { log } = this.deps;
    log.debug("Entering WorkloadAttestation.attest(). " + facts.tag);
    const out: Selector[] = [];
    const types = this.enabled();
    for (let i = 0; i < types.length; i++) {
      let values = [];
      try {
        values = await this.attestors.get(types[i]).attest(facts);
      } catch (e) {
        log.debug("Caught in WorkloadAttestation.attest(): " +
                  ((e && e.message) || e));
        log.debug("Leaving WorkloadAttestation.attest(). " + types[i] +
                  " failed.");
        // error-code: none — recorded on the connection and refused per
        // call under STS-SPIFFE-0111
        throw new Error('the ' + types[i] + ' workload attestor failed: ' +
                        ((e && e.message) || e));
      }
      values.forEach(function (value) {
        out.push({ type: types[i], value: value });
      });
    }
    log.debug("Leaving WorkloadAttestation.attest(). " + out.length +
              " selector(s).");
    return out;
  }

  // SPIRE's containerinfo extractor over `/proc/<pid>/cgroup`: the pod UID
  // (with `withPod`) and the container ID, '' each when there is none.
  // Throws on two different answers.
  containerInfo(procRoot: string, pid: number, withPod: boolean):
      { podUid: string; containerId: string } {
    const { log, fs } = this.deps;
    log.debug("Entering WorkloadAttestation.containerInfo(). pid=" + pid);
    let text = '';
    try {
      text = fs.readFileSync(procRoot + '/' + pid + '/cgroup', 'utf8');
    } catch (e) {
      log.debug("Caught in WorkloadAttestation.containerInfo(): " +
                ((e && e.message) || e));
      log.debug("Leaving WorkloadAttestation.containerInfo(). None.");
      return { podUid: '', containerId: '' };
    }
    let podUid = '';
    let containerId = '';
    const lines = text.split('\n').filter(Boolean);
    for (let l = 0; l < lines.length; l++) {
      const cgroupPath = lines[l].split(':').slice(2).join(':');
      const found = this.extractOne(cgroupPath, withPod);
      if (podUid && !found.podUid) continue;
      if (!podUid && found.podUid) {
        podUid = found.podUid;
        containerId = found.containerId;
      }
      if (found.podUid && podUid && found.podUid !== podUid) {
        log.debug("Leaving WorkloadAttestation.containerInfo(). Two pods.");
        // error-code: none — see attest()
        throw new Error('multiple pod UIDs found ("' + podUid + '", "' +
                        found.podUid + '")');
      }
      if (containerId && found.containerId !== containerId) {
        log.debug("Leaving WorkloadAttestation.containerInfo(). Two " +
                  "containers.");
        // error-code: none — see attest()
        throw new Error('multiple container IDs found ("' + containerId +
                        '", "' + found.containerId + '")');
      }
      containerId = found.containerId;
      podUid = found.podUid;
    }
    log.debug("Leaving WorkloadAttestation.containerInfo().");
    return { podUid: podUid, containerId: containerId };
  }

  // Every cgroup path of a process (the third field of each line of
  // `/proc/<pid>/cgroup`), or [] when the file cannot be read. The docker
  // attestor reads them for SPIRE's Podman detection (#170).
  cgroupPaths(procRoot: string, pid: number): string[] {
    const { log, fs } = this.deps;
    log.debug("Entering WorkloadAttestation.cgroupPaths(). pid=" + pid);
    let text = '';
    try {
      text = fs.readFileSync(procRoot + '/' + pid + '/cgroup', 'utf8');
    } catch (e) {
      log.debug("Caught in WorkloadAttestation.cgroupPaths(): " +
                ((e && e.message) || e));
      log.debug("Leaving WorkloadAttestation.cgroupPaths(). None.");
      return [];
    }
    log.debug("Leaving WorkloadAttestation.cgroupPaths().");
    return text.split('\n').filter(Boolean).map(function (line) {
      return line.split(':').slice(2).join(':');
    });
  }

  // One cgroup path: its container ID, and before it the pod UID.
  extractOne(cgroupPath: string, withPod: boolean):
      { podUid: string; containerId: string } {
    const { log } = this.deps;
    log.debug("Entering WorkloadAttestation.extractOne().");
    const segments = String(cgroupPath || '').split('/');
    let at = segments.length - 1;
    let containerId = '';
    let rest = '';
    for (; at >= 0; at--) {
      const m = CONTAINER_ID.exec(segments[at]);
      if (m) {
        containerId = m[1];
        rest = segments[at].slice(0, m.index);
        break;
      }
    }
    if (!containerId || !withPod) {
      log.debug("Leaving WorkloadAttestation.extractOne().");
      return { podUid: '', containerId: containerId };
    }
    const candidates = [rest].concat(segments.slice(0, at).reverse());
    for (let i = 0; i < candidates.length; i++) {
      const m = POD_UID.exec(candidates[i]);
      if (m) {
        log.debug("Leaving WorkloadAttestation.extractOne(). With a pod.");
        return { podUid: m[1].replace(/_/g, '-'), containerId: containerId };
      }
    }
    log.debug("Leaving WorkloadAttestation.extractOne(). No pod.");
    return { podUid: '', containerId: containerId };
  }

  state() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering WorkloadAttestation.state().");
    const enabled = this.enabled();
    log.debug("Leaving WorkloadAttestation.state().");
    return {
      attestors: Array.from(this.attestors.keys()).sort().map(function (t) {
        return { type: t, enabled: enabled.indexOf(t) >= 0,
                 verifies: self.attestors.get(t).verifies };
      }),
      unknownConfigured: this.configured().filter(function (t) {
        return !self.attestors.has(t);
      })
    };
  }
}

export = {
  WorkloadAttestation: WorkloadAttestation
};
