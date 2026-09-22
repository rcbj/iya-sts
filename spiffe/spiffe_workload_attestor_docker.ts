'use strict';
//
// File: spiffe_workload_attestor_docker.ts
//
// ---------------------------------------------------------------------------
// THE `docker` WORKLOAD ATTESTOR (#40 phase four, 2026-09-21).
//
// SPIRE's `pkg/agent/plugin/workloadattestor/docker`:
//
//   1. The container ID comes from the process's cgroups
//      (`WorkloadAttestation.containerInfo()`, SPIRE's containerinfo
//      extractor). A process in no container, or one this service cannot
//      see (another pid namespace), gets NO docker selectors — SPIRE's empty
//      answer, not an error.
//   2. The Docker Engine API is asked about it over `spiffe.dockerSocketPath`
//      (`/containers/<id>/json`, and `/images/<image>/json` for the image
//      configuration digest), through `federation_http.ts`'s
//      `requestLocalSocket()`, retried as SPIRE's retryer retries.
//   3. Selectors: `label:<k>:<v>` for every label, `env:<K=V>` for every
//      environment entry, `image_id:<the configured image>`, and
//      `image_config_digest:<the image's ID>` when the image inspects.
//
// SPIRE's sigstore image-signature verification and its Podman sockets are
// not here: both are options of SPIRE's plugin beyond what a Docker Engine
// workload needs, and each is recorded on #40 as a follow-up rather than
// half-built.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import outbound = require('../federation/federation_http');

interface DockerDeps {
  log: typeof log;
  config: typeof config;
  outbound: { requestLocalSocket(socketPath: string, path: string,
                                 options?: any): Promise<any> };
  containerInfo(procRoot: string, pid: number, withPod: boolean):
    { podUid: string; containerId: string };
  retries: number;
}

class DockerWorkloadAttestor {
  readonly type = 'docker';
  readonly verifies = 'The Docker container the caller\'s process runs in, ' +
    'as the Docker Engine reports its labels, environment and image.';

  constructor(private readonly deps: DockerDeps) {
    deps.log.debug("Entering DockerWorkloadAttestor.constructor().");
    deps.log.debug("Leaving DockerWorkloadAttestor.constructor().");
  }

  static defaultDeps(containerInfo: DockerDeps['containerInfo']): DockerDeps {
    helpers.log.debug("Entering DockerWorkloadAttestor.defaultDeps().");
    helpers.log.debug("Leaving DockerWorkloadAttestor.defaultDeps().");
    return { log: log, config: config, outbound: outbound,
             containerInfo: containerInfo, retries: 3 };
  }

  // The socket path from `unix:///var/run/docker.sock` or a bare path.
  socketPath(): string {
    const { log, config } = this.deps;
    log.debug("Entering DockerWorkloadAttestor.socketPath().");
    log.debug("Leaving DockerWorkloadAttestor.socketPath().");
    return String(config.value('spiffe.dockerSocketPath') || '')
      .replace(/^unix:\/\//, '');
  }

  // One JSON document from the Engine, retried; throws a sentence.
  async engine(path: string): Promise<any> {
    const { log, config, outbound, retries } = this.deps;
    log.debug("Entering DockerWorkloadAttestor.engine(). " + path);
    const version = String(config.value('spiffe.dockerApiVersion') || '');
    const full = (version ? '/v' + version.replace(/^v/, '') : '') + path;
    let last = null;
    for (let attempt = 0; attempt < retries; attempt++) {
      last = await outbound.requestLocalSocket(this.socketPath(), full);
      if (last.ok) {
        log.debug("Leaving DockerWorkloadAttestor.engine().");
        return JSON.parse(last.body.toString('utf8'));
      }
      if (last.status >= 400 && last.status < 500) break;
    }
    log.debug("Leaving DockerWorkloadAttestor.engine(). Failed.");
    // error-code: none — reported by the table under STS-SPIFFE-0111
    throw new Error('the Docker Engine answered ' + path + ': ' +
                    (last ? last.why : 'nothing'));
  }

  async attest(facts: any): Promise<string[]> {
    const { log, containerInfo } = this.deps;
    log.debug("Entering DockerWorkloadAttestor.attest(). " + facts.tag);
    if (!facts.visible) {
      log.debug("Leaving DockerWorkloadAttestor.attest(). Not visible.");
      return [];
    }
    const info = containerInfo(facts.procRoot, facts.pid, false);
    if (!info.containerId) {
      log.debug("Leaving DockerWorkloadAttestor.attest(). No container.");
      return [];
    }
    const container = await this.engine('/containers/' + info.containerId +
                                        '/json');
    const cfg = (container && container.Config) || {};
    const out = [];
    Object.keys(cfg.Labels || {}).forEach(function (key) {
      out.push('label:' + key + ':' + cfg.Labels[key]);
    });
    (cfg.Env || []).forEach(function (entry) {
      out.push('env:' + entry);
    });
    if (cfg.Image) {
      out.push('image_id:' + cfg.Image);
      try {
        const image = await this.engine('/images/' +
                                        encodeURIComponent(cfg.Image) +
                                        '/json');
        if (image && image.Id) out.push('image_config_digest:' + image.Id);
      } catch (e) {
        // SPIRE adds the digest only when the image inspects, and does not
        // fail the attestation when it does not.
        log.debug("Caught in DockerWorkloadAttestor.attest(): " +
                  ((e && e.message) || e));
      }
    }
    log.debug("Leaving DockerWorkloadAttestor.attest(). " + out.length);
    return out;
  }
}

export = {
  DockerWorkloadAttestor: DockerWorkloadAttestor
};
