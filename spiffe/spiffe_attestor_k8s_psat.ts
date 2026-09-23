'use strict';
//
// File: spiffe_attestor_k8s_psat.ts
//
// ---------------------------------------------------------------------------
// THE `k8s_psat` NODE ATTESTOR — A KUBERNETES PROJECTED SERVICE ACCOUNT TOKEN
// (#40 phase three, 2026-09-21).
//
// SPIRE's `pkg/server/plugin/nodeattestor/k8spsat`, whose client is a
// `spire-agent` running as a DaemonSet pod:
//
//   1. The payload is `{"cluster", "token"}` — the pod's projected service
//      account token, audienced to SPIRE. The cluster must be one the realm
//      names in `spiffe.k8sPsatClusters`.
//   2. The CLUSTER decides the token: a TokenReview to its API server, with
//      the configured audiences. Not authenticated is PERMISSION_DENIED. The
//      username is `system:serviceaccount:<ns>:<sa>`, and `<ns>:<sa>` must
//      be in the cluster's `serviceAccountAllowList`.
//   3. The pod the token is BOUND to (its name and UID in the review's
//      `extra`) is read back, and the pod of that name must still have that
//      UID — a token outliving its pod names a pod that is no longer it. Its
//      node is read for the node's UID and labels.
//   4. The agent is `/spire/agent/k8s_psat/<cluster>/<node UID>` (or
//      `…/pod/<pod UID>` with `usePodUidForAgentId`), with SPIRE's selectors:
//      cluster, agent_ns, agent_sa, agent_pod_name, agent_pod_uid,
//      agent_node_ip, agent_node_name, agent_node_uid, and agent_node_label /
//      agent_pod_label for the allowed keys. Re-attestable.
//
// **THE CREDENTIAL IS A FILE, NEVER A SETTING.** SPIRE reads a kubeconfig; a
// setting here is drawn on the console, so a cluster names `apiServer`, a
// `caFile` and a `tokenFile`, and with no `apiServer` the in-cluster service
// account is used — SPIRE's empty `kube_config_file`. Every request goes
// through `federation/federation_http.ts`'s `requestConfigured()`: the
// administrator's kind of URL, with the kill switch, https, no redirect and
// the cap, and the cluster's own CA as the only roots.
// ---------------------------------------------------------------------------

import fs = require('fs');
import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import spiffeId = require('./spiffe_id');
import rpc = require('./spiffe_grpc');
import outbound = require('../federation/federation_http');

type NodeAttestationContext =
  import('../types/spiffe-attestation').NodeAttestationContext;
type NodeAttestationResult =
  import('../types/spiffe-attestation').NodeAttestationResult;

const DEFAULT_AUDIENCE = ['spire-server'];
const IN_CLUSTER = '/var/run/secrets/kubernetes.io/serviceaccount';

interface K8sPsatDeps {
  log: typeof log;
  fs: typeof fs;
  env: NodeJS.ProcessEnv;
  config: typeof config;
  errorCodes: typeof errorCodes;
  spiffeId: typeof spiffeId;
  rpc: typeof rpc;
  outbound: { requestConfigured(url: string, options?: any): Promise<any> };
}

class K8sPsatAttestor {
  readonly type = 'k8s_psat';
  readonly verifies = 'A projected service account token the cluster\'s ' +
    'own TokenReview authenticates, for an allowed service account, bound ' +
    'to a pod that still exists.';

  constructor(private readonly deps: K8sPsatDeps) {
    deps.log.debug("Entering K8sPsatAttestor.constructor().");
    deps.log.debug("Leaving K8sPsatAttestor.constructor().");
  }

  static defaultDeps(): K8sPsatDeps {
    helpers.log.debug("Entering K8sPsatAttestor.defaultDeps().");
    helpers.log.debug("Leaving K8sPsatAttestor.defaultDeps().");
    return { log: log, fs: fs, env: process.env, config: config,
             errorCodes: errorCodes, spiffeId: spiffeId, rpc: rpc,
             outbound: outbound };
  }

  refuse(call: any, code: string, grpcCode: number, message: string): Error {
    const { log, errorCodes, rpc } = this.deps;
    log.debug("Entering K8sPsatAttestor.refuse(). " + code);
    errorCodes.mark(call, code);
    log.debug("Leaving K8sPsatAttestor.refuse().");
    // error-code: none — the helper's own internals: every caller passes
    // the code, and it is marked on the line above
    return rpc.statusError(grpcCode, message);
  }

  // The realm's clusters, or a sentence saying why they cannot be read.
  clusters(): { clusters: Record<string, any>; problem: string } {
    const { log, config } = this.deps;
    log.debug("Entering K8sPsatAttestor.clusters().");
    const raw = String(config.value('spiffe.k8sPsatClusters') || '').trim();
    if (!raw) {
      log.debug("Leaving K8sPsatAttestor.clusters(). None.");
      return { clusters: {}, problem: 'spiffe.k8sPsatClusters names no ' +
               'cluster' };
    }
    let parsed = null;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      log.debug("Caught in K8sPsatAttestor.clusters(): " +
                ((e && e.message) || e));
      log.debug("Leaving K8sPsatAttestor.clusters(). Not JSON.");
      return { clusters: {}, problem: 'spiffe.k8sPsatClusters is not JSON (' +
               e.message + ')' };
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      log.debug("Leaving K8sPsatAttestor.clusters(). Not an object.");
      return { clusters: {}, problem: 'spiffe.k8sPsatClusters is not an ' +
               'object from cluster name to its configuration' };
    }
    const names = Object.keys(parsed);
    for (let i = 0; i < names.length; i++) {
      const one = parsed[names[i]] || {};
      if (!Array.isArray(one.serviceAccountAllowList) ||
          !one.serviceAccountAllowList.length) {
        log.debug("Leaving K8sPsatAttestor.clusters(). No allow list.");
        return { clusters: {}, problem: 'cluster "' + names[i] + '" ' +
                 'configuration must have at least one service account ' +
                 'allowed' };
      }
    }
    log.debug("Leaving K8sPsatAttestor.clusters(). " + names.length + ".");
    return { clusters: parsed, problem: '' };
  }

  // How to reach one cluster's API server: its URL, its CA and its bearer
  // token, the last two read from FILES. Throws a sentence.
  reach(cluster: any): { base: string; ca: string; token: string } {
    const { log, fs, env } = this.deps;
    log.debug("Entering K8sPsatAttestor.reach().");
    let base = String(cluster.apiServer || '').replace(/\/+$/, '');
    let caFile = String(cluster.caFile || '');
    let tokenFile = String(cluster.tokenFile || '');
    if (!base) {
      // In-cluster, as client-go's rest.InClusterConfig().
      const host = String(env.KUBERNETES_SERVICE_HOST || '');
      const port = String(env.KUBERNETES_SERVICE_PORT || '443');
      if (!host) {
        log.debug("Leaving K8sPsatAttestor.reach(). Not in a cluster.");
        // error-code: none — turned into STS-SPIFFE-0099 by the caller
        throw new Error('no apiServer is configured and this process is ' +
                        'not running in a cluster (KUBERNETES_SERVICE_HOST ' +
                        'is not set)');
      }
      base = 'https://' + (host.indexOf(':') >= 0 ? '[' + host + ']' : host) +
             ':' + port;
      caFile = caFile || IN_CLUSTER + '/ca.crt';
      tokenFile = tokenFile || IN_CLUSTER + '/token';
    }
    const ca = caFile ? fs.readFileSync(caFile, 'utf8') : '';
    const token = tokenFile ? fs.readFileSync(tokenFile, 'utf8').trim() : '';
    log.debug("Leaving K8sPsatAttestor.reach().");
    return { base: base, ca: ca, token: token };
  }

  // One JSON request to the API server; resolves the parsed body or throws a
  // sentence.
  async api(reach: any, method: string, path: string, body?: any):
      Promise<any> {
    const { log, outbound } = this.deps;
    log.debug("Entering K8sPsatAttestor.api(). " + method + " " + path);
    const headers: Record<string, string> = {
      'Accept': 'application/json' };
    if (reach.token) headers['Authorization'] = 'Bearer ' + reach.token;
    if (body) headers['Content-Type'] = 'application/json';
    const answer = await outbound.requestConfigured(reach.base + path, {
      method: method, headers: headers, ca: reach.ca || undefined,
      body: body ? JSON.stringify(body) : undefined });
    if (!answer.ok) {
      log.debug("Leaving K8sPsatAttestor.api(). " + answer.why);
      // error-code: none — turned into STS-SPIFFE-0099 by the caller
      throw new Error(method + ' ' + path + ': ' + answer.why);
    }
    try {
      const parsed = JSON.parse(answer.body.toString('utf8'));
      log.debug("Leaving K8sPsatAttestor.api().");
      return parsed;
    } catch (e) {
      log.debug("Caught in K8sPsatAttestor.api(): " +
                ((e && e.message) || e));
      log.debug("Leaving K8sPsatAttestor.api(). Not JSON.");
      // error-code: none — turned into STS-SPIFFE-0099 by the caller
      throw new Error(method + ' ' + path + ' did not answer JSON');
    }
  }

  async attest(context: NodeAttestationContext):
      Promise<NodeAttestationResult> {
    const { log, spiffeId, rpc } = this.deps;
    log.debug("Entering K8sPsatAttestor.attest().");
    const call = context.call;
    const status = rpc.grpc.status;
    const configured = this.clusters();
    if (configured.problem) {
      log.debug("Leaving K8sPsatAttestor.attest(). Not configured.");
      throw this.refuse(call, 'STS-SPIFFE-0085', status.FAILED_PRECONDITION,
                        'k8s_psat is not configured in this realm: ' +
                        configured.problem + '.');
    }
    // 1. THE PAYLOAD.
    let data = null;
    try {
      data = JSON.parse(Buffer.from(context.payload || []).toString('utf8'));
    } catch (e) {
      log.debug("Caught in K8sPsatAttestor.attest(): " +
                ((e && e.message) || e));
    }
    if (!data || typeof data !== 'object') {
      log.debug("Leaving K8sPsatAttestor.attest(). Unreadable.");
      throw this.refuse(call, 'STS-SPIFFE-0086', status.INVALID_ARGUMENT,
                        'failed to unmarshal data payload');
    }
    const clusterName = String(data.cluster || '');
    const token = String(data.token || '');
    if (!clusterName || !token) {
      log.debug("Leaving K8sPsatAttestor.attest(). Incomplete.");
      throw this.refuse(call, 'STS-SPIFFE-0102', status.INVALID_ARGUMENT,
        'missing ' + (!clusterName ? 'cluster' : 'token') +
        ' in attestation data');
    }
    const cluster = Object.prototype.hasOwnProperty.call(configured.clusters,
                                                         clusterName)
      ? configured.clusters[clusterName] : null;
    if (!cluster) {
      log.debug("Leaving K8sPsatAttestor.attest(). Unknown cluster.");
      throw this.refuse(call, 'STS-SPIFFE-0102', status.INVALID_ARGUMENT,
                        'not configured for cluster "' + clusterName + '"');
    }
    const audience = Array.isArray(cluster.audience) ? cluster.audience
                                                     : DEFAULT_AUDIENCE;
    // 2. THE TOKEN REVIEW.
    let reach = null;
    let review = null;
    try {
      reach = this.reach(cluster);
      review = await this.api(reach, 'POST',
        '/apis/authentication.k8s.io/v1/tokenreviews', {
          apiVersion: 'authentication.k8s.io/v1', kind: 'TokenReview',
          spec: { token: token, audiences: audience } });
    } catch (e) {
      log.debug("Caught in K8sPsatAttestor.attest(): " +
                ((e && e.message) || e));
      log.debug("Leaving K8sPsatAttestor.attest(). No review.");
      throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
        'unable to validate token with TokenReview API for cluster "' +
        clusterName + '": ' + e.message);
    }
    const reviewed = (review && review.status) || {};
    if (reviewed.error) {
      log.debug("Leaving K8sPsatAttestor.attest(). Review error.");
      throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
        'unable to validate token with TokenReview API for cluster "' +
        clusterName + '": service account token validation failed: ' +
        reviewed.error);
    }
    const audiences = Array.isArray(reviewed.audiences) ? reviewed.audiences
                                                        : [];
    if (!reviewed.authenticated || (audience.length && audiences.length &&
        !audiences.some(function (one) {
          return audience.indexOf(one) >= 0;
        }))) {
      log.debug("Leaving K8sPsatAttestor.attest(). Not authenticated.");
      throw this.refuse(call, 'STS-SPIFFE-0100', status.PERMISSION_DENIED,
        'token not authenticated according to TokenReview API for ' +
        'cluster "' + clusterName + '"');
    }
    const user = reviewed.user || {};
    const names = String(user.username || '').split(':');
    if (names.length !== 4 || !names[2] || !names[3]) {
      log.debug("Leaving K8sPsatAttestor.attest(). Bad username.");
      throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
        'failed to parse username from token review status for cluster "' +
        clusterName + '": unexpected username format: ' + user.username);
    }
    const namespace = names[2];
    const serviceAccount = names[3];
    if (cluster.serviceAccountAllowList.indexOf(namespace + ':' +
                                                serviceAccount) < 0) {
      log.debug("Leaving K8sPsatAttestor.attest(). Not allowed.");
      throw this.refuse(call, 'STS-SPIFFE-0101', status.PERMISSION_DENIED,
        '"' + namespace + ':' + serviceAccount + '" is not an allowed ' +
        'service account for cluster "' + clusterName + '"');
    }
    const extra = user.extra || {};
    const podNames = extra['authentication.kubernetes.io/pod-name'] || [];
    const podUids = extra['authentication.kubernetes.io/pod-uid'] || [];
    if (podNames.length !== 1 || !podNames[0] || podUids.length !== 1 ||
        !podUids[0]) {
      log.debug("Leaving K8sPsatAttestor.attest(). Not pod-bound.");
      throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
        'failed to get pod ' + (podNames.length !== 1 || !podNames[0]
          ? 'name' : 'UID') + ' from token review status for cluster "' +
        clusterName + '": the token is not bound to exactly one pod');
    }
    const podName = String(podNames[0]);
    const podUid = String(podUids[0]);
    // 3. THE POD AND ITS NODE.
    let pod = null;
    let node = null;
    try {
      pod = await this.api(reach, 'GET', '/api/v1/namespaces/' +
                           encodeURIComponent(namespace) + '/pods/' +
                           encodeURIComponent(podName));
    } catch (e) {
      log.debug("Caught in K8sPsatAttestor.attest(): " +
                ((e && e.message) || e));
      log.debug("Leaving K8sPsatAttestor.attest(). No pod.");
      throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
        'failed to get pod from k8s API server for cluster "' + clusterName +
        '": ' + e.message);
    }
    if (String(((pod || {}).metadata || {}).uid || '') !== podUid) {
      log.debug("Leaving K8sPsatAttestor.attest(). Pod UID mismatch.");
      throw this.refuse(call, 'STS-SPIFFE-0101', status.PERMISSION_DENIED,
        'pod UID mismatch for pod "' + podName + '" in cluster "' +
        clusterName + '": token bound to pod UID "' + podUid + '"');
    }
    const nodeName = String(((pod || {}).spec || {}).nodeName || '');
    try {
      node = await this.api(reach, 'GET', '/api/v1/nodes/' +
                            encodeURIComponent(nodeName));
    } catch (e) {
      log.debug("Caught in K8sPsatAttestor.attest(): " +
                ((e && e.message) || e));
      log.debug("Leaving K8sPsatAttestor.attest(). No node.");
      throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
        'failed to get node from k8s API server for cluster "' +
        clusterName + '": ' + e.message);
    }
    const nodeUid = String(((node || {}).metadata || {}).uid || '');
    if (!nodeUid) {
      log.debug("Leaving K8sPsatAttestor.attest(). No node UID.");
      throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
        'node UID is empty for cluster "' + clusterName + '"');
    }
    // 4. THE AGENT.
    const selectors = [
      'cluster:' + clusterName, 'agent_ns:' + namespace,
      'agent_sa:' + serviceAccount, 'agent_pod_name:' + podName,
      'agent_pod_uid:' + podUid,
      'agent_node_ip:' + String(((pod || {}).status || {}).hostIP || ''),
      'agent_node_name:' + nodeName, 'agent_node_uid:' + nodeUid
    ];
    const nodeLabels = ((node || {}).metadata || {}).labels || {};
    (cluster.allowedNodeLabelKeys || []).forEach(function (key) {
      if (Object.prototype.hasOwnProperty.call(nodeLabels, key)) {
        selectors.push('agent_node_label:' + key + ':' + nodeLabels[key]);
      }
    });
    const podLabels = ((pod || {}).metadata || {}).labels || {};
    (cluster.allowedPodLabelKeys || []).forEach(function (key) {
      if (Object.prototype.hasOwnProperty.call(podLabels, key)) {
        selectors.push('agent_pod_label:' + key + ':' + podLabels[key]);
      }
    });
    const suffix = cluster.usePodUidForAgentId ? 'pod/' + podUid : nodeUid;
    const agentId = spiffeId.make(context.trustDomain,
      '/spire/agent/k8s_psat/' + clusterName + '/' + suffix);
    if (!spiffeId.parse(agentId).ok) {
      log.debug("Leaving K8sPsatAttestor.attest(). A bad agent id.");
      throw this.refuse(call, 'STS-SPIFFE-0095', status.INTERNAL,
                        'failed to make an agent SPIFFE ID from cluster "' +
                        clusterName + '"');
    }
    log.debug("Leaving K8sPsatAttestor.attest(). " + agentId);
    return {
      agentId: agentId,
      selectors: selectors.map(function (value) {
        return { type: 'k8s_psat', value: value };
      }),
      canReattest: true,
      method: 'agent attestation (k8s_psat)',
      note: 'attested by a projected service account token the "' +
            clusterName + '" cluster authenticated, for pod ' + namespace +
            '/' + podName,
      commit: function () {
        log.debug("Entering commit(). Nothing to spend.");
        log.debug("Leaving commit().");
      },
      release: function () {
        log.debug("Entering release(). Nothing to give back.");
        log.debug("Leaving release().");
      }
    };
  }
}

export = {
  K8sPsatAttestor: K8sPsatAttestor
};
