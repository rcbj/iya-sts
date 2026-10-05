// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// PODMAN (#170, 2026-09-23), SPIRE's `docker_posix.go`: a cgroup path naming
// `libpod-` or `/libpod/` is a Podman container, and Podman's
// Docker-compatible API is asked instead of the Engine — the rootful socket
// (`spiffe.dockerPodmanSocketPath`), or, when the path also names a
// `user-<uid>.slice`, the ROOTLESS one built from
// `spiffe.dockerPodmanSocketPathTemplate` with that uid — but only with
// `spiffe.dockerUseRootlessPodman` on: off, a rootless container gets NO
// docker selectors (STS-SPIFFE-0142, logged once), because its socket lives
// in the caller's own runtime directory and would answer whatever the caller
// liked. The container ID comes from the same extractor, which already reads
// `libpod-<id>.scope`. The selectors stay `docker:`, as in SPIRE.
//
// SIGSTORE (#170): with `spiffe.dockerSigstoreEnabled` the image must carry
// a cosign signature that verifies (`spiffe_sigstore.ts`), tried against
// each of the image's repository digests in turn as SPIRE does; its
// selectors are SPIRE's `image-signature…` ones. A signature that does not
// verify FAILS the attestation, and with it the connection (UNAVAILABLE) —
// never a missing selector, which is what SPIRE's plugin does too.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import outbound = require('../federation/federation_http');
import errorCodes = require('../common/error_codes');

// SPIRE's Podman matchers (`docker_posix.go`).
const PODMAN_CGROUP = /(?:libpod-|\/libpod\/)/;
const USER_SLICE_UID = /\/user-(\d+)\.slice\//;

interface DockerDeps {
  log: typeof log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  outbound: { requestLocalSocket(socketPath: string, path: string,
                                 options?: any): Promise<any> };
  containerInfo(procRoot: string, pid: number, withPod: boolean):
    { podUid: string; containerId: string };
  cgroupPaths(procRoot: string, pid: number): string[];
  // The sigstore verifier (`spiffe_sigstore.ts`): the image-signature
  // selectors for one repository digest, or a throw.
  sigstore: { verify(repoDigest: string): Promise<string[]> } | null;
  retries: number;
}

/**
 * The `docker` workload attestor: the container the caller's process runs in,
 * as the Docker Engine (or Podman) reports its labels, environment and image.
 *
 * A process in no container, or one this service cannot see, gets no selectors.
 * With `spiffe.dockerSigstoreEnabled` the image's cosign signature must verify.
 */
class DockerWorkloadAttestor {
  /**
   * The workload attestor's name, as `spiffe.workloadAttestors` lists it.
   */
  readonly type = 'docker';
  /**
   * One sentence for `GET /spiffe` and the console: what this attestor
   * verifies.
   */
  readonly verifies = 'The Docker container the caller\'s process runs in, ' +
    'as the Docker Engine reports its labels, environment and image.';

  /**
   * Builds the attestor over its dependencies.
   *
   * @param deps - the logger, configuration, error codes, the local-socket
   *   requester, the container-info and cgroup readers, the sigstore verifier
   *   and the retry count
   */
  constructor(private readonly deps: DockerDeps) {
    deps.log.debug("Entering DockerWorkloadAttestor.constructor().");
    deps.log.debug("Leaving DockerWorkloadAttestor.constructor().");
  }

  /**
   * Returns the dependencies the service runs the attestor with.
   *
   * @param containerInfo - reads the container ID from a process's cgroups
   * @param cgroupPaths - reads a process's cgroup paths, for Podman detection
   * @param sigstore - the image signature verifier
   * @returns the production dependency set
   */
  static defaultDeps(containerInfo: DockerDeps['containerInfo'],
                     cgroupPaths?: DockerDeps['cgroupPaths'],
                     sigstore?: DockerDeps['sigstore']): DockerDeps {
    helpers.log.debug("Entering DockerWorkloadAttestor.defaultDeps().");
    helpers.log.debug("Leaving DockerWorkloadAttestor.defaultDeps().");
    return { log: log, config: config, errorCodes: errorCodes,
             outbound: outbound, containerInfo: containerInfo,
             cgroupPaths: cgroupPaths || function () {
               return [];
             },
             sigstore: sigstore || null, retries: 3 };
  }

  // The socket path from `unix:///var/run/docker.sock` or a bare path.
  /**
   * Returns the Docker Engine's socket path from `spiffe.dockerSocketPath`,
   * given as `unix://…` or a bare path.
   *
   * @returns the socket path
   */
  socketPath(): string {
    const { log, config } = this.deps;
    log.debug("Entering DockerWorkloadAttestor.socketPath().");
    log.debug("Leaving DockerWorkloadAttestor.socketPath().");
    return String(config.value('spiffe.dockerSocketPath') || '')
      .replace(/^unix:\/\//, '');
  }

  // SPIRE's `%d`-and-`%%` template, filled with a uid; throws a sentence on
  // a template with no `%d`, two, or any other verb
  // (validatePodmanSocketPathTemplate()).
  /**
   * Fills SPIRE's `%d`-and-`%%` socket path template with a uid
   * (validatePodmanSocketPathTemplate()).
   *
   * @param template - the template
   * @param uid - the uid to fill in
   * @returns the filled path
   * @throws an Error carrying a sentence for a template with no `%d`, two, or
   *   any other verb
   */
  fillTemplate(template: string, uid: number): string {
    const { log } = this.deps;
    log.debug("Entering DockerWorkloadAttestor.fillTemplate().");
    let out = '';
    let placeholders = 0;
    for (let i = 0; i < template.length; i++) {
      if (template[i] !== '%') {
        out += template[i];
        continue;
      }
      const verb = template[i + 1];
      if (verb === '%') {
        out += '%';
      } else if (verb === 'd') {
        out += String(uid);
        placeholders++;
      } else {
        log.debug("Leaving DockerWorkloadAttestor.fillTemplate(). Bad verb.");
        // error-code: none — reported by the table under STS-SPIFFE-0111
        throw new Error('invalid podman_socket_path_template: template only ' +
                        'supports escaped %% or the %d UID placeholder');
      }
      i++;
    }
    if (placeholders !== 1) {
      log.debug("Leaving DockerWorkloadAttestor.fillTemplate(). Count.");
      // error-code: none — reported by the table under STS-SPIFFE-0111
      throw new Error('invalid podman_socket_path_template: template must ' +
                      'contain exactly one %d UID placeholder');
    }
    log.debug("Leaving DockerWorkloadAttestor.fillTemplate().");
    return out;
  }

  // SPIRE's detectPodmanSocket(): the Podman API socket to ask, '' for the
  // Docker Engine, or null when the workload is a rootless Podman container
  // and rootless Podman is off — then it is not attested by this plugin.
  /**
   * SPIRE's detectPodmanSocket(): which API socket to ask about a container.
   *
   * @param paths - the process's cgroup paths
   * @returns the Podman API socket, '' for the Docker Engine, or null when the
   *   workload is a rootless Podman container and rootless Podman is off
   */
  podmanSocket(paths: string[]): string | null {
    const { log, config, errorCodes } = this.deps;
    log.debug("Entering DockerWorkloadAttestor.podmanSocket().");
    for (let i = 0; i < paths.length; i++) {
      if (!PODMAN_CGROUP.test(paths[i])) continue;
      const user = USER_SLICE_UID.exec(paths[i]);
      if (user) {
        if (!config.value('spiffe.dockerUseRootlessPodman')) {
          if (!ROOTLESS_REFUSED.logged) {
            ROOTLESS_REFUSED.logged = true;
            log.warn(errorCodes.tag('STS-SPIFFE-0142') + 'spiffe: a ' +
                     'rootless Podman workload was not attested by the ' +
                     'docker attestor (' + paths[i] + '): ' +
                     'spiffe.dockerUseRootlessPodman is off, SPIRE\'s rule ' +
                     '— turn it on, and pair its entries with unix:uid or ' +
                     'unix:user selectors. Said once per process.');
          }
          log.debug("Leaving DockerWorkloadAttestor.podmanSocket(). " +
                    "Rootless, off.");
          return null;
        }
        const uid = Number(user[1]);
        if (Number.isInteger(uid) && uid >= 0 && uid <= 4294967295) {
          log.debug("Leaving DockerWorkloadAttestor.podmanSocket(). " +
                    "Rootless.");
          return this.fillTemplate(String(config.value(
            'spiffe.dockerPodmanSocketPathTemplate') || ''), uid);
        }
        log.warn('spiffe: a rootless Podman uid in ' + paths[i] + ' could ' +
                 'not be read, so the rootful Podman socket is asked, as ' +
                 'SPIRE does.');
      }
      log.debug("Leaving DockerWorkloadAttestor.podmanSocket(). Rootful.");
      return String(config.value('spiffe.dockerPodmanSocketPath') || '');
    }
    log.debug("Leaving DockerWorkloadAttestor.podmanSocket(). Docker.");
    return '';
  }

  // One JSON document from the Engine (or Podman), retried; throws a
  // sentence. `socket` is a `unix://` URI or a bare path; empty is the
  // Engine's.
  /**
   * Reads one JSON document from the Docker Engine (or Podman), retried as
   * SPIRE's retryer retries.
   *
   * @param path - the API path
   * @param socket - a `unix://` URI or bare path; empty is the Engine's
   * @returns the parsed document
   * @throws an Error carrying a sentence when the API cannot be read
   */
  async engine(path: string, socket?: string): Promise<any> {
    const { log, config, outbound, retries } = this.deps;
    log.debug("Entering DockerWorkloadAttestor.engine(). " + path);
    const version = String(config.value('spiffe.dockerApiVersion') || '');
    const full = (version ? '/v' + version.replace(/^v/, '') : '') + path;
    const socketPath = socket ? String(socket).replace(/^unix:\/\//, '')
                              : this.socketPath();
    let last = null;
    for (let attempt = 0; attempt < retries; attempt++) {
      last = await outbound.requestLocalSocket(socketPath, full);
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

  /**
   * Attests the caller's container: its labels, environment, image and image
   * configuration digest, and the sigstore selectors when enabled.
   *
   * @param facts - the caller's peer facts from `spiffe_peer.ts`, taken at
   *   accept
   * @returns the `docker` selector values, empty when the process is in no
   *   container or not visible
   */
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
    // PODMAN: which API to ask, or not to attest at all (rootless, off).
    const socket = this.podmanSocket(this.deps.cgroupPaths(facts.procRoot,
                                                           facts.pid));
    if (socket === null) {
      log.debug("Leaving DockerWorkloadAttestor.attest(). Rootless Podman " +
                "is off.");
      return [];
    }
    const container = await this.engine('/containers/' + info.containerId +
                                        '/json', socket);
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
    }
    const sigstoreOn = !!this.deps.config.value('spiffe.dockerSigstoreEnabled');
    // SPIRE inspects the image when it has a name, or when sigstore needs
    // its repository digests; a failed inspect costs the digest selector,
    // and costs the ATTESTATION only when sigstore is on.
    let image = null;
    let inspectProblem = '';
    if (cfg.Image || sigstoreOn) {
      try {
        image = await this.engine('/images/' +
                                  encodeURIComponent(String(cfg.Image || '')) +
                                  '/json', socket);
      } catch (e) {
        log.debug("Caught in DockerWorkloadAttestor.attest(): " +
                  ((e && e.message) || e));
        inspectProblem = String((e && e.message) || e);
      }
    }
    if (image && image.Id) out.push('image_config_digest:' + image.Id);
    if (sigstoreOn) {
      const signed = await this.sigstoreSelectors(String(cfg.Image || ''),
                                                  image, inspectProblem);
      signed.forEach(function (one) {
        out.push(one);
      });
    }
    log.debug("Leaving DockerWorkloadAttestor.attest(). " + out.length);
    return out;
  }

  // SPIRE's sigstore half of Attest(): each repository digest in turn until
  // one verifies; throws a sentence naming every failure when none does.
  /**
   * SPIRE's sigstore half of Attest(): tries each of the image's repository
   * digests in turn until one's signature verifies.
   *
   * @param imageName - the image the container was configured with
   * @param image - the image as the Engine inspected it
   * @param inspectProblem - why the image could not be inspected, or ''
   * @returns the sigstore selector values
   * @throws an Error carrying a sentence naming every failure when none
   *   verifies
   */
  async sigstoreSelectors(imageName: string, image: any,
                          inspectProblem: string): Promise<string[]> {
    const { log, sigstore } = this.deps;
    log.debug("Entering DockerWorkloadAttestor.sigstoreSelectors().");
    if (!sigstore) {
      log.debug("Leaving DockerWorkloadAttestor.sigstoreSelectors(). No " +
                "verifier.");
      // error-code: none — a wiring defect, refused under STS-SPIFFE-0111
      throw new Error('sigstore verification is on and this attestor was ' +
                      'built without a verifier');
    }
    if (!image) {
      log.debug("Leaving DockerWorkloadAttestor.sigstoreSelectors(). No " +
                "image.");
      // error-code: none — refused under STS-SPIFFE-0111
      throw new Error('failed to inspect image "' + imageName + '": ' +
                      inspectProblem);
    }
    const digests = (image.RepoDigests || []).map(String);
    if (!digests.length) {
      log.debug("Leaving DockerWorkloadAttestor.sigstoreSelectors(). No " +
                "digest.");
      // error-code: none — refused under STS-SPIFFE-0111
      throw new Error('sigstore signature verification failed: no repo ' +
                      'digest found for image ' + imageName);
    }
    const errors = [];
    for (let i = 0; i < digests.length; i++) {
      try {
        const selectors = await sigstore.verify(digests[i]);
        log.debug("Leaving DockerWorkloadAttestor.sigstoreSelectors(). " +
                  digests[i]);
        return selectors;
      } catch (e) {
        log.debug("Caught in DockerWorkloadAttestor.sigstoreSelectors(): " +
                  ((e && e.message) || e));
        errors.push('image_id ' + digests[i] + ': ' + ((e && e.message) || e));
      }
    }
    log.debug("Leaving DockerWorkloadAttestor.sigstoreSelectors(). None " +
              "verified.");
    // error-code: none — the verifier tagged each failure's own code; the
    // connection is refused under STS-SPIFFE-0111
    throw new Error('sigstore signature verification failed for image ' +
                    imageName + ': errors: ' + errors.join('; '));
  }
}

// Whether STS-SPIFFE-0142 has been said in this process.
const ROOTLESS_REFUSED = { logged: false };

/**
 * The `docker` workload attestor (#40, #170), after SPIRE's plugin, with Podman
 * and sigstore.
 * @namespace
 */
export = {
  DockerWorkloadAttestor: DockerWorkloadAttestor
};
