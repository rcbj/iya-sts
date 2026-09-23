'use strict';
//
// File: spiffe_attestor_gcp_iit.ts
//
// ---------------------------------------------------------------------------
// THE `gcp_iit` NODE ATTESTOR — A GOOGLE COMPUTE ENGINE INSTANCE IDENTITY
// TOKEN (#40 phase three, 2026-09-21).
//
// SPIRE's `pkg/server/plugin/nodeattestor/gcpiit`:
//
//   1. The payload is the instance identity token itself — a JWT the
//      instance's metadata server minted for the audience
//      `spire-gcp-node-attestor`, format=full.
//   2. It is verified, RS256 only, against the certificate Google published
//      under its `kid` (`spiffe.gcpIitCertsUrl`, SPIRE's constant; fetched
//      through `requestConfigured()` and kept until the answer's Expires),
//      by `common/crypto.js`'s `verifyJws()`, and its claims as go-jose
//      validates them: the audience, and exp, nbf and iat with a minute's
//      leeway.
//   3. The project must be in `spiffe.gcpIitProjectIdAllowList`.
//   4. The agent is `spiffe.gcpIitAgentPathTemplate` (default
//      `/{{ .PluginName }}/{{ .ProjectID }}/{{ .InstanceID }}`), with the
//      selectors project-id, zone, instance-name and sa, and — with
//      `spiffe.gcpIitUseInstanceMetadata` — tag:, label: and metadata: from
//      the Compute Engine API (the optional `@google-cloud/compute`, with the
//      application default credentials or `spiffe.gcpIitServiceAccountFile`).
//   5. Trust on first use: an instance's token attests it ONCE, until its
//      agent is deleted.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import spiffeId = require('./spiffe_id');
import rpc = require('./spiffe_grpc');
import agentPath = require('./spiffe_agent_path');
import outbound = require('../federation/federation_http');

type NodeAttestationContext =
  import('../types/spiffe-attestation').NodeAttestationContext;
type NodeAttestationResult =
  import('../types/spiffe-attestation').NodeAttestationResult;

const AUDIENCE = 'spire-gcp-node-attestor';
const DEFAULT_TEMPLATE = '/{{ .PluginName }}/{{ .ProjectID }}/' +
  '{{ .InstanceID }}';
const COMPUTE_PACKAGE = '@google-cloud/compute';
// go-jose's jwt.DefaultLeeway.
const LEEWAY_SECONDS = 60;

interface GcpIitDeps {
  log: typeof log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  stsCrypto: typeof stsCrypto;
  spiffeId: typeof spiffeId;
  rpc: typeof rpc;
  agentPath: typeof agentPath;
  outbound: { requestConfigured(url: string, options?: any): Promise<any> };
  load(pkg: string): any;
  now(): number;
}

class GcpIitAttestor {
  readonly type = 'gcp_iit';
  readonly verifies = 'A Compute Engine instance identity token signed by ' +
    'Google, for an allowed project; once per instance.';
  // Google's certificates by kid, and until when they may be kept.
  private certs: Record<string, string> = {};
  private certsUntil = 0;

  constructor(private readonly deps: GcpIitDeps) {
    deps.log.debug("Entering GcpIitAttestor.constructor().");
    deps.log.debug("Leaving GcpIitAttestor.constructor().");
  }

  static defaultDeps(): GcpIitDeps {
    helpers.log.debug("Entering GcpIitAttestor.defaultDeps().");
    helpers.log.debug("Leaving GcpIitAttestor.defaultDeps().");
    return {
      log: log, config: config, errorCodes: errorCodes,
      stsCrypto: stsCrypto, spiffeId: spiffeId, rpc: rpc,
      agentPath: agentPath, outbound: outbound,
      load: function (pkg) {
        return require(pkg);
      },
      now: function () {
        return Date.now();
      }
    };
  }

  refuse(call: any, code: string, grpcCode: number, message: string): Error {
    const { log, errorCodes, rpc } = this.deps;
    log.debug("Entering GcpIitAttestor.refuse(). " + code);
    errorCodes.mark(call, code);
    log.debug("Leaving GcpIitAttestor.refuse().");
    // error-code: none — the helper's own internals: every caller passes
    // the code, and it is marked on the line above
    return rpc.statusError(grpcCode, message);
  }

  csv(key: string): string[] {
    const { log, config } = this.deps;
    log.debug("Entering GcpIitAttestor.csv(). " + key);
    const raw = config.value(key);
    log.debug("Leaving GcpIitAttestor.csv().");
    return (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one) {
        return String(one).trim();
      }).filter(Boolean);
  }

  // Google's certificates, fetched when none are held or they have expired.
  // Resolves the kid → PEM map, or throws a sentence.
  async googleCertificates(): Promise<Record<string, string>> {
    const { log, config, outbound, now } = this.deps;
    log.debug("Entering GcpIitAttestor.googleCertificates().");
    if (this.certsUntil > now() && Object.keys(this.certs).length) {
      log.debug("Leaving GcpIitAttestor.googleCertificates(). Held.");
      return this.certs;
    }
    const answer = await outbound.requestConfigured(
      String(config.value('spiffe.gcpIitCertsUrl')));
    if (!answer.ok) {
      log.debug("Leaving GcpIitAttestor.googleCertificates(). Failed.");
      // error-code: none — turned into STS-SPIFFE-0099 by the caller
      throw new Error('unexpected answer from the certificate URL: ' +
                      answer.why);
    }
    const parsed = JSON.parse(answer.body.toString('utf8'));
    const held: Record<string, string> = {};
    Object.keys(parsed || {}).forEach(function (kid) {
      held[kid] = String(parsed[kid]);
    });
    this.certs = held;
    const expires = Date.parse(String((answer.headers || {}).expires || ''));
    this.certsUntil = Number.isFinite(expires) ? expires : 0;
    log.debug("Leaving GcpIitAttestor.googleCertificates(). " +
              Object.keys(held).length + " certificate(s).");
    return held;
  }

  // The instance, from the Compute Engine API.
  async instance(identity: any): Promise<any> {
    const { log, config, load } = this.deps;
    log.debug("Entering GcpIitAttestor.instance().");
    const sdk = load(COMPUTE_PACKAGE);
    const file = String(config.value('spiffe.gcpIitServiceAccountFile') ||
                        '');
    const client = new sdk.InstancesClient(file ? { keyFilename: file } : {});
    const answer = await client.get({ project: identity.project_id,
                                      zone: identity.zone,
                                      instance: identity.instance_name });
    log.debug("Leaving GcpIitAttestor.instance().");
    return Array.isArray(answer) ? answer[0] : answer;
  }

  async attest(context: NodeAttestationContext):
      Promise<NodeAttestationResult> {
    const { log, config, stsCrypto, spiffeId, rpc, agentPath, load,
            now } = this.deps;
    log.debug("Entering GcpIitAttestor.attest().");
    const call = context.call;
    const status = rpc.grpc.status;
    const projects = this.csv('spiffe.gcpIitProjectIdAllowList');
    let template = null;
    let problem = projects.length ? '' : 'projectid_allow_list is required ' +
      '(spiffe.gcpIitProjectIdAllowList)';
    if (!problem) {
      try {
        template = new agentPath.AgentPathTemplate(
          String(config.value('spiffe.gcpIitAgentPathTemplate') || '') ||
          DEFAULT_TEMPLATE);
      } catch (e) {
        log.debug("Caught in GcpIitAttestor.attest(): " +
                  ((e && e.message) || e));
        problem = 'spiffe.gcpIitAgentPathTemplate does not parse: ' +
                  e.message;
      }
    }
    const useMetadata = !!config.value('spiffe.gcpIitUseInstanceMetadata');
    if (!problem && useMetadata) {
      try {
        load(COMPUTE_PACKAGE);
      } catch (e) {
        log.debug("Caught in GcpIitAttestor.attest(): " +
                  ((e && e.message) || e));
        throw this.refuse(call, 'STS-SPIFFE-0106', status.FAILED_PRECONDITION,
          'gcp_iit reads the instance with ' + COMPUTE_PACKAGE + ' ' +
          '(spiffe.gcpIitUseInstanceMetadata) and it is not installed. It ' +
          'is an optional peer dependency: run `npm install ' +
          COMPUTE_PACKAGE + '` in this deployment.');
      }
    }
    if (problem) {
      log.debug("Leaving GcpIitAttestor.attest(). Not configured.");
      throw this.refuse(call, 'STS-SPIFFE-0085', status.FAILED_PRECONDITION,
                        'gcp_iit is not configured in this realm: ' +
                        problem + '.');
    }
    // 1–2. THE TOKEN AND ITS SIGNATURE.
    let certs = null;
    try {
      certs = await this.googleCertificates();
    } catch (e) {
      log.debug("Caught in GcpIitAttestor.attest(): " +
                ((e && e.message) || e));
      throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
                        'unable to retrieve Google\'s certificates: ' +
                        e.message);
    }
    const token = Buffer.from(context.payload || []).toString('utf8').trim();
    let header = null;
    try {
      header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url')
        .toString('utf8'));
    } catch (e) {
      log.debug("Caught in GcpIitAttestor.attest(): " +
                ((e && e.message) || e));
    }
    if (!header || token.split('.').length !== 3) {
      log.debug("Leaving GcpIitAttestor.attest(). Not a JWS.");
      throw this.refuse(call, 'STS-SPIFFE-0086', status.INVALID_ARGUMENT,
                        'unable to parse the identity token');
    }
    const candidates = header.kid && certs[header.kid] ? [certs[header.kid]]
      : Object.keys(certs).map(function (kid) {
        return certs[kid];
      });
    let claims = null;
    let failure = 'no certificate verifies it';
    for (let i = 0; i < candidates.length && !claims; i++) {
      try {
        claims = stsCrypto.verifyJws(token, candidates[i], {
          algorithms: ['RS256'], clockTolerance: LEEWAY_SECONDS });
      } catch (e) {
        log.debug("Caught in GcpIitAttestor.attest(): " +
                  ((e && e.message) || e));
        failure = e.message;
        if (/expired|not active/.test(failure)) break;
      }
    }
    if (!claims) {
      log.debug("Leaving GcpIitAttestor.attest(). Did not verify.");
      const expired = /expired|not active/.test(failure);
      throw this.refuse(call, expired ? 'STS-SPIFFE-0108' : 'STS-SPIFFE-0107',
        expired ? status.PERMISSION_DENIED : status.INVALID_ARGUMENT,
        (expired ? 'failed to validate the identity token claims: '
                 : 'failed to validate the identity token signature: ') +
        failure);
    }
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    const nowSeconds = Math.floor(now() / 1000);
    if (audiences.indexOf(AUDIENCE) < 0 || (claims.iat !== undefined &&
        nowSeconds + LEEWAY_SECONDS < Number(claims.iat))) {
      log.debug("Leaving GcpIitAttestor.attest(). Claims.");
      throw this.refuse(call, 'STS-SPIFFE-0108', status.PERMISSION_DENIED,
        'failed to validate the identity token claims: ' +
        (audiences.indexOf(AUDIENCE) < 0
          ? 'invalid audience claim (aud)'
          : 'validation field, token issued in the future (iat)'));
    }
    const engine = ((claims.google || {}).compute_engine) || {};
    // 3. THE PROJECT.
    if (projects.indexOf(String(engine.project_id || '')) < 0) {
      log.debug("Leaving GcpIitAttestor.attest(). Project not allowed.");
      throw this.refuse(call, 'STS-SPIFFE-0108', status.PERMISSION_DENIED,
        'identity token project ID "' + engine.project_id + '" is not in ' +
        'the allow list');
    }
    // 4. THE AGENT.
    let agentId = '';
    try {
      agentId = spiffeId.make(context.trustDomain, '/spire/agent' +
        template.execute({
          PluginName: this.type,
          ServiceAccount: String(claims.email || '').replace(/@/g, '_'),
          ProjectID: String(engine.project_id || ''),
          ProjectNumber: String(engine.project_number || ''),
          Zone: String(engine.zone || ''),
          InstanceID: String(engine.instance_id || ''),
          InstanceName: String(engine.instance_name || ''),
          InstanceCreationTimestamp:
            String(engine.instance_creation_timestamp || '')
        }));
    } catch (e) {
      log.debug("Caught in GcpIitAttestor.attest(): " +
                ((e && e.message) || e));
    }
    if (!agentId || !spiffeId.parse(agentId).ok) {
      log.debug("Leaving GcpIitAttestor.attest(). No agent id.");
      throw this.refuse(call, 'STS-SPIFFE-0095', status.INTERNAL,
                        'failed to create agent ID from the agent path ' +
                        'template');
    }
    const selectors = [
      'project-id:' + String(engine.project_id || ''),
      'zone:' + String(engine.zone || ''),
      'instance-name:' + String(engine.instance_name || ''),
      'sa:' + String(claims.email || '')
    ];
    if (useMetadata) {
      let instance = null;
      try {
        instance = await this.instance(engine);
      } catch (e) {
        log.debug("Caught in GcpIitAttestor.attest(): " +
                  ((e && e.message) || e));
        throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
          'failed to fetch instance metadata: ' + e.message);
      }
      const labelKeys = this.csv('spiffe.gcpIitAllowedLabelKeys');
      const metadataKeys = this.csv('spiffe.gcpIitAllowedMetadataKeys');
      const maxValue = Number(config.value(
        'spiffe.gcpIitMaxMetadataValueSize'));
      ((instance && instance.tags && instance.tags.items) || [])
        .forEach(function (tag) {
          selectors.push('tag:' + tag);
        });
      const labels = (instance && instance.labels) || {};
      labelKeys.forEach(function (key) {
        if (Object.prototype.hasOwnProperty.call(labels, key)) {
          selectors.push('label:' + key + ':' + labels[key]);
        }
      });
      const items = (instance && instance.metadata &&
                     instance.metadata.items) || [];
      for (let i = 0; i < items.length; i++) {
        if (metadataKeys.indexOf(items[i].key) < 0) continue;
        const value = items[i].value === null ||
                      items[i].value === undefined ? ''
                                                   : String(items[i].value);
        if (value.length > maxValue) {
          log.debug("Leaving GcpIitAttestor.attest(). Metadata too long.");
          throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
            'metadata "' + items[i].key + '" exceeded value limit (' +
            value.length + ' > ' + maxValue + ')');
        }
        selectors.push('metadata:' + items[i].key + ':' + value);
      }
    }
    log.debug("Leaving GcpIitAttestor.attest(). " + agentId);
    return {
      agentId: agentId,
      selectors: selectors.map(function (value) {
        return { type: 'gcp_iit', value: value };
      }),
      canReattest: false,
      method: 'agent attestation (gcp_iit)',
      note: 'attested by a Google-signed instance identity token for ' +
            engine.project_id + '/' + engine.instance_name,
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
  GcpIitAttestor: GcpIitAttestor,
  COMPUTE_PACKAGE: COMPUTE_PACKAGE
};
