'use strict';
//
// File: spiffe_workload_attestor_k8s.ts
//
// ---------------------------------------------------------------------------
// THE `k8s` WORKLOAD ATTESTOR (#40 phase four, 2026-09-21).
//
// SPIRE's `pkg/agent/plugin/workloadattestor/k8s`, attesting by PID:
//
//   1. The pod UID and container ID come from the process's cgroups
//      (SPIRE's containerinfo extractor). No container, or a process this
//      service cannot see, is no k8s selectors — SPIRE's empty answer.
//   2. The kubelet's pod list (`/pods`) is read — the secure port
//      (`spiffe.k8sKubeletSecurePort`, 10250) with the service account token
//      and the kubelet CA, or a client certificate, or anonymously; or the
//      read-only port on 127.0.0.1 — and the pod holding that container is
//      found, polled for up to `spiffe.k8sMaxPollAttempts` times
//      `spiffe.k8sPollRetryIntervalMs`, because a container that has just
//      started may not be in the list yet.
//   3. Selectors: sa, ns, node-name, pod-uid, pod-name, pod-image-count,
//      pod-init-image-count, pod-image, pod-init-image, pod-label,
//      pod-owner, pod-owner-uid; unless
//      `spiffe.k8sDisableContainerSelectors`, container-name and
//      container-image; with `spiffe.k8sEnableNamespaceLabels`, ns-label
//      (from the API server, in-cluster). Two pods holding one container ID
//      is an error, as in SPIRE.
//
// Every request goes through `federation_http.ts`'s `requestConfigured()`:
// the kubelet's URL is the administrator's configuration, and its
// certificate is checked against the kubelet CA — by chain alone when no node
// name is configured, which is SPIRE's rule (a kubelet's certificate names
// the node, not 127.0.0.1). SPIRE's workload broker (`AttestReference`) and
// sigstore verification are follow-ups on #40.
// ---------------------------------------------------------------------------

import fs = require('fs');
import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import outbound = require('../federation/federation_http');

const IN_CLUSTER = '/var/run/secrets/kubernetes.io/serviceaccount';

// SPIRE's defaultSecurePort: where a kubelet serves its authenticated API.
const DEFAULT_SECURE_PORT = 10250;

interface K8sDeps {
  log: typeof log;
  fs: typeof fs;
  env: NodeJS.ProcessEnv;
  config: typeof config;
  outbound: { requestConfigured(url: string, options?: any): Promise<any> };
  containerInfo(procRoot: string, pid: number, withPod: boolean):
    { podUid: string; containerId: string };
  sleep(ms: number): Promise<void>;
}

class K8sWorkloadAttestor {
  readonly type = 'k8s';
  readonly verifies = 'The Kubernetes pod and container the caller\'s ' +
    'process runs in, as the node\'s kubelet reports them.';

  constructor(private readonly deps: K8sDeps) {
    deps.log.debug("Entering K8sWorkloadAttestor.constructor().");
    deps.log.debug("Leaving K8sWorkloadAttestor.constructor().");
  }

  static defaultDeps(containerInfo: K8sDeps['containerInfo']): K8sDeps {
    helpers.log.debug("Entering K8sWorkloadAttestor.defaultDeps().");
    helpers.log.debug("Leaving K8sWorkloadAttestor.defaultDeps().");
    return {
      log: log, fs: fs, env: process.env, config: config, outbound: outbound,
      containerInfo: containerInfo,
      sleep: function (ms) {
        return new Promise(function (resolve) {
          setTimeout(resolve, ms);
        });
      }
    };
  }

  readOptional(path: string): string {
    const { log, fs } = this.deps;
    log.debug("Entering K8sWorkloadAttestor.readOptional(). " + path);
    try {
      const text = fs.readFileSync(path, 'utf8');
      log.debug("Leaving K8sWorkloadAttestor.readOptional().");
      return text;
    } catch (e) {
      log.debug("Caught in K8sWorkloadAttestor.readOptional(): " +
                ((e && e.message) || e));
      log.debug("Leaving K8sWorkloadAttestor.readOptional(). Absent.");
      return '';
    }
  }

  // The kubelet's pod list; throws a sentence.
  async podList(): Promise<any[]> {
    const { log, config, env, outbound } = this.deps;
    log.debug("Entering K8sWorkloadAttestor.podList().");
    const readOnly = Number(config.value('spiffe.k8sKubeletReadOnlyPort'));
    let answer = null;
    if (readOnly) {
      answer = await outbound.requestConfigured('http://127.0.0.1:' +
        readOnly + '/pods', { loopbackPlainHttp: true });
    } else {
      const nodeName = String(config.value('spiffe.k8sNodeName') || '') ||
        String(env[String(config.value('spiffe.k8sNodeNameEnv') ||
                          'MY_NODE_NAME')] || '');
      // 0 is the kubelet's own port, which no kubelet is ever on 0 instead of.
      const port = Number(config.value('spiffe.k8sKubeletSecurePort')) ||
        DEFAULT_SECURE_PORT;
      const headers: Record<string, string> = {};
      const certFile = String(config.value('spiffe.k8sCertificateFile') ||
                              '');
      if (!certFile && !config.value('spiffe.k8sUseAnonymousAuthentication')) {
        const token = this.readOptional(String(
          config.value('spiffe.k8sTokenFile') || IN_CLUSTER + '/token'))
          .trim();
        if (token) headers['Authorization'] = 'Bearer ' + token;
      }
      const skip = !!config.value('spiffe.k8sSkipKubeletVerification');
      answer = await outbound.requestConfigured('https://' +
        (nodeName || '127.0.0.1') + ':' + port + '/pods', {
          headers: headers, skipVerify: skip, chainOnly: !skip && !nodeName,
          ca: skip ? undefined : this.readOptional(String(
            config.value('spiffe.k8sKubeletCaFile') || IN_CLUSTER +
            '/ca.crt')) || undefined,
          cert: certFile ? this.readOptional(certFile) : undefined,
          key: certFile ? this.readOptional(String(
            config.value('spiffe.k8sPrivateKeyFile') || '')) : undefined });
    }
    if (!answer.ok) {
      log.debug("Leaving K8sWorkloadAttestor.podList(). Failed.");
      // error-code: none — reported by the table under STS-SPIFFE-0111
      throw new Error('unable to get pod list from the kubelet: ' +
                      answer.why);
    }
    const parsed = JSON.parse(answer.body.toString('utf8'));
    log.debug("Leaving K8sWorkloadAttestor.podList().");
    return (parsed && parsed.items) || [];
  }

  // A namespace's labels, from the API server in-cluster.
  async namespaceLabels(namespace: string): Promise<Record<string, string>> {
    const { log, env, outbound } = this.deps;
    log.debug("Entering K8sWorkloadAttestor.namespaceLabels(). " + namespace);
    const host = String(env.KUBERNETES_SERVICE_HOST || '');
    if (!host) {
      log.debug("Leaving K8sWorkloadAttestor.namespaceLabels(). Not in a " +
                "cluster.");
      // error-code: none — reported by the table under STS-SPIFFE-0111
      throw new Error('unable to get namespace labels: not running in a ' +
                      'cluster');
    }
    const token = this.readOptional(IN_CLUSTER + '/token').trim();
    const answer = await outbound.requestConfigured('https://' +
      (host.indexOf(':') >= 0 ? '[' + host + ']' : host) + ':' +
      String(env.KUBERNETES_SERVICE_PORT || '443') + '/api/v1/namespaces/' +
      encodeURIComponent(namespace), {
        ca: this.readOptional(IN_CLUSTER + '/ca.crt') || undefined,
        headers: token ? { 'Authorization': 'Bearer ' + token } : {} });
    if (!answer.ok) {
      log.debug("Leaving K8sWorkloadAttestor.namespaceLabels(). Failed.");
      // error-code: none — reported by the table under STS-SPIFFE-0111
      throw new Error('unable to get namespace labels for "' + namespace +
                      '": ' + answer.why);
    }
    log.debug("Leaving K8sWorkloadAttestor.namespaceLabels().");
    return ((JSON.parse(answer.body.toString('utf8')) || {}).metadata || {})
      .labels || {};
  }

  // The status of `containerId` among a pod's containers, or null.
  containerStatus(pod: any, containerId: string): any {
    const { log } = this.deps;
    log.debug("Entering K8sWorkloadAttestor.containerStatus().");
    const status = pod.status || {};
    const all = (status.containerStatuses || [])
      .concat(status.initContainerStatuses || []);
    for (let i = 0; i < all.length; i++) {
      const id = String(all[i].containerID || '');
      // `containerd://<id>` — the id is the URL's host.
      const at = id.indexOf('://');
      if (at >= 0 && id.slice(at + 3) === containerId) {
        log.debug("Leaving K8sWorkloadAttestor.containerStatus(). Found.");
        return all[i];
      }
    }
    log.debug("Leaving K8sWorkloadAttestor.containerStatus().");
    return null;
  }

  // SPIRE's getPodImageIdentifiers(): every image and image ID, once.
  imagesOf(list: any[]): string[] {
    const { log } = this.deps;
    log.debug("Entering K8sWorkloadAttestor.imagesOf().");
    const set = new Set<string>();
    list.forEach(function (one) {
      set.add(String(one.imageID || ''));
      set.add(String(one.image || ''));
    });
    log.debug("Leaving K8sWorkloadAttestor.imagesOf().");
    return Array.from(set);
  }

  // SPIRE's getSelectorValuesFromPodInfo().
  podSelectors(pod: any): string[] {
    const { log } = this.deps;
    log.debug("Entering K8sWorkloadAttestor.podSelectors().");
    const meta = pod.metadata || {};
    const spec = pod.spec || {};
    const status = pod.status || {};
    const containers = status.containerStatuses || [];
    const inits = status.initContainerStatuses || [];
    const out = ['sa:' + (spec.serviceAccountName || ''),
                 'ns:' + (meta.namespace || ''),
                 'node-name:' + (spec.nodeName || ''),
                 'pod-uid:' + (meta.uid || ''),
                 'pod-name:' + (meta.name || ''),
                 'pod-image-count:' + containers.length,
                 'pod-init-image-count:' + inits.length];
    this.imagesOf(containers).forEach(function (image) {
      out.push('pod-image:' + image);
    });
    this.imagesOf(inits).forEach(function (image) {
      out.push('pod-init-image:' + image);
    });
    Object.keys(meta.labels || {}).forEach(function (key) {
      out.push('pod-label:' + key + ':' + meta.labels[key]);
    });
    (meta.ownerReferences || []).forEach(function (owner) {
      out.push('pod-owner:' + owner.kind + ':' + owner.name);
      out.push('pod-owner-uid:' + owner.kind + ':' + owner.uid);
    });
    log.debug("Leaving K8sWorkloadAttestor.podSelectors().");
    return out;
  }

  async attest(facts: any): Promise<string[]> {
    const { log, config, containerInfo, sleep } = this.deps;
    log.debug("Entering K8sWorkloadAttestor.attest(). " + facts.tag);
    if (!facts.visible) {
      log.debug("Leaving K8sWorkloadAttestor.attest(). Not visible.");
      return [];
    }
    const info = containerInfo(facts.procRoot, facts.pid, true);
    if (!info.containerId) {
      log.debug("Leaving K8sWorkloadAttestor.attest(). No container.");
      return [];
    }
    const attempts = Math.max(1, Number(config.value(
      'spiffe.k8sMaxPollAttempts')));
    const interval = Number(config.value('spiffe.k8sPollRetryIntervalMs'));
    const noContainers = !!config.value('spiffe.k8sDisableContainerSelectors');
    for (let attempt = 1; attempt <= attempts; attempt++) {
      const pods = await this.podList();
      let found = null;
      for (let i = 0; i < pods.length; i++) {
        const pod = pods[i];
        if (info.podUid && String((pod.metadata || {}).uid) !== info.podUid) {
          continue;
        }
        const status = this.containerStatus(pod, info.containerId);
        let values = [];
        if (status) {
          values = this.podSelectors(pod);
          if (!noContainers) {
            values.push('container-name:' + status.name);
            this.imagesOf([status]).forEach(function (image) {
              values.push('container-image:' + image);
            });
          }
        } else if (info.podUid && noContainers) {
          values = this.podSelectors(pod);
        }
        if (!values.length) continue;
        if (found) {
          log.debug("Leaving K8sWorkloadAttestor.attest(). Two pods.");
          // error-code: none — reported by the table under STS-SPIFFE-0111
          throw new Error('two pods found with same container Id');
        }
        found = { pod: pod, values: values };
      }
      if (found) {
        if (config.value('spiffe.k8sEnableNamespaceLabels')) {
          const labels = await this.namespaceLabels(String(
            (found.pod.metadata || {}).namespace || ''));
          Object.keys(labels).forEach(function (key) {
            found.values.push('ns-label:' + key + ':' + labels[key]);
          });
        }
        log.debug("Leaving K8sWorkloadAttestor.attest(). " +
                  found.values.length);
        return found.values;
      }
      if (attempt < attempts) await sleep(interval);
    }
    log.debug("Leaving K8sWorkloadAttestor.attest(). Not found.");
    // error-code: none — reported by the table under STS-SPIFFE-0111
    throw new Error('no selectors found after max poll attempts');
  }
}

export = {
  K8sWorkloadAttestor: K8sWorkloadAttestor
};
