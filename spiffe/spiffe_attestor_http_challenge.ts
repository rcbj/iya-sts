'use strict';
//
// File: spiffe_attestor_http_challenge.ts
//
// ---------------------------------------------------------------------------
// THE `http_challenge` NODE ATTESTOR (#40 phase three, 2026-09-21) — the one
// attestor that has this server DIAL AN ADDRESS THE CALLER NAMED, admitted by
// rcbj's decision with the bounds below.
//
// SPIRE's `pkg/server/plugin/nodeattestor/httpchallenge`:
//
//   1. The payload is `{"hostname", "agentname", "port"}`: "I am
//      `hostname`, and I am serving on `port`".
//   2. The port must be `spiffe.httpChallengeRequiredPort` when that is set,
//      and below 1024 when `spiffe.httpChallengeAllowNonRootPorts` is off;
//      the agent name `^[a-zA-Z][a-zA-Z0-9-]*$`, at most 32 characters.
//   3. The host name must not be `localhost` and must match one of
//      `spiffe.httpChallengeAllowedDnsPatterns` — **checked before anything
//      resolves or dials it**, and STRICTER THAN SPIRE: an empty list refuses
//      every agent, where SPIRE's allows any name. That is the first bound.
//   4. `spiffe.httpChallengeVerifyClientIp`: the agent's address must be one
//      the host name resolves to.
//   5. THE CHALLENGE: `{"nonce": <base64url of 32 random bytes>}`. The agent
//      serves it at `http://<host>:<port>/.well-known/spiffe/nodeattestor/
//      http_challenge/<agent>/challenge` and answers; this server then GETs
//      that URL through `federation/federation_http.ts`'s
//      `fetchHttpChallenge()` — the kill switch, the internal-address refusal
//      and pinning in product mode, no redirect, 64 bytes, ten seconds — and
//      the body, trimmed, must be the nonce.
//   6. The agent is `/spire/agent/http_challenge/<host>`, with the selector
//      `hostname:<host>`. Trust on first use (`spiffe.httpChallengeTofu`, on)
//      makes it attest once until deleted, as SPIRE's.
//
// **WHAT IT PROVES IS EXACTLY AS STRONG AS THIS NETWORK'S DNS.** The nonce
// coming back from the address the name resolves to says whoever answers
// there controls the port — and with a privileged port, root on that host.
// Somebody who can spoof DNS, sit on the path, or take the port gets the
// identity. That is SPIRE's plugin and it is stated, not improved on.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import dns = require('dns');
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

const AGENT_NAME = /^[a-zA-Z][a-zA-Z0-9-]*$/;

interface HttpChallengeDeps {
  log: typeof log;
  crypto: typeof nodeCrypto;
  lookup(host: string): Promise<string[]>;
  config: typeof config;
  errorCodes: typeof errorCodes;
  spiffeId: typeof spiffeId;
  rpc: typeof rpc;
  outbound: { fetchHttpChallenge(host: string, port: number,
                                 path: string): Promise<any> };
}

class HttpChallengeAttestor {
  readonly type = 'http_challenge';
  readonly verifies = 'A nonce served over HTTP from a host name the realm ' +
    'allows, fetched by this server — as strong as the network\'s DNS.';

  constructor(private readonly deps: HttpChallengeDeps) {
    deps.log.debug("Entering HttpChallengeAttestor.constructor().");
    deps.log.debug("Leaving HttpChallengeAttestor.constructor().");
  }

  static defaultDeps(): HttpChallengeDeps {
    helpers.log.debug("Entering HttpChallengeAttestor.defaultDeps().");
    helpers.log.debug("Leaving HttpChallengeAttestor.defaultDeps().");
    return {
      log: log, crypto: nodeCrypto, config: config, errorCodes: errorCodes,
      spiffeId: spiffeId, rpc: rpc, outbound: outbound,
      lookup: function (host) {
        return dns.promises.lookup(host, { all: true }).then(function (all) {
          return all.map(function (one) {
            return one.address;
          });
        });
      }
    };
  }

  refuse(call: any, code: string, grpcCode: number, message: string): Error {
    const { log, errorCodes, rpc } = this.deps;
    log.debug("Entering HttpChallengeAttestor.refuse(). " + code);
    errorCodes.mark(call, code);
    log.debug("Leaving HttpChallengeAttestor.refuse().");
    // error-code: none — the helper's own internals: every caller passes
    // the code, and it is marked on the line above
    return rpc.statusError(grpcCode, message);
  }

  // The configuration, checked as SPIRE checks it at Configure, or why not.
  settings(): any {
    const { log, config } = this.deps;
    log.debug("Entering HttpChallengeAttestor.settings().");
    const raw = config.value('spiffe.httpChallengeAllowedDnsPatterns');
    const texts = (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one) {
        return String(one).trim();
      }).filter(Boolean);
    const out: any = {
      patterns: [], problem: '',
      requiredPort: Number(config.value('spiffe.httpChallengeRequiredPort')),
      allowNonRootPorts: !!config.value(
        'spiffe.httpChallengeAllowNonRootPorts'),
      tofu: !!config.value('spiffe.httpChallengeTofu'),
      verifyClientIp: !!config.value('spiffe.httpChallengeVerifyClientIp')
    };
    if (!texts.length) {
      out.problem = 'spiffe.httpChallengeAllowedDnsPatterns is empty, and ' +
                    'this server dials no host name nobody allowed';
    }
    texts.forEach(function (text) {
      try {
        out.patterns.push(new RegExp(text));
      } catch (e) {
        log.debug("Caught in HttpChallengeAttestor.settings(): " +
                  ((e && e.message) || e));
        out.problem = out.problem || 'cannot compile allowed_dns_pattern "' +
                      text + '": ' + e.message;
      }
    });
    // SPIRE's rule: trust on first use cannot be turned off while a
    // non-root port could be the one proving the name.
    const mustUseTofu = (out.requiredPort >= 1024) ||
      (!out.requiredPort && out.allowNonRootPorts);
    if (!out.tofu && mustUseTofu) {
      out.problem = out.problem || 'you can not turn off trust on first use ' +
                    '(TOFU) when non-root ports are allowed';
    }
    log.debug("Leaving HttpChallengeAttestor.settings().");
    return out;
  }

  async attest(context: NodeAttestationContext):
      Promise<NodeAttestationResult> {
    const { log, crypto, spiffeId, rpc, outbound, lookup } = this.deps;
    log.debug("Entering HttpChallengeAttestor.attest().");
    const call = context.call;
    const status = rpc.grpc.status;
    const s = this.settings();
    if (s.problem) {
      log.debug("Leaving HttpChallengeAttestor.attest(). Not configured.");
      throw this.refuse(call, 'STS-SPIFFE-0085', status.FAILED_PRECONDITION,
                        'http_challenge is not configured in this realm: ' +
                        s.problem + '.');
    }
    // 1. THE PAYLOAD.
    let data = null;
    try {
      data = JSON.parse(Buffer.from(context.payload || []).toString('utf8'));
    } catch (e) {
      log.debug("Caught in HttpChallengeAttestor.attest(): " +
                ((e && e.message) || e));
    }
    if (!data || typeof data !== 'object') {
      log.debug("Leaving HttpChallengeAttestor.attest(). Unreadable.");
      throw this.refuse(call, 'STS-SPIFFE-0086', status.INVALID_ARGUMENT,
                        'failed to unmarshal data');
    }
    const host = String(data.hostname || '');
    const agentName = String(data.agentname || '');
    const port = Number(data.port);
    // 2. THE PORT AND THE NAME.
    if (s.requiredPort && port !== s.requiredPort) {
      log.debug("Leaving HttpChallengeAttestor.attest(). Wrong port.");
      throw this.refuse(call, 'STS-SPIFFE-0103', status.INVALID_ARGUMENT,
        'port ' + port + ' is not allowed to be used by this server');
    }
    if (!s.allowNonRootPorts && port >= 1024) {
      log.debug("Leaving HttpChallengeAttestor.attest(). Non-root port.");
      throw this.refuse(call, 'STS-SPIFFE-0103', status.INVALID_ARGUMENT,
        'port ' + port + ' is not allowed to be >= 1024');
    }
    if (!AGENT_NAME.test(agentName) || agentName.length > 32) {
      log.debug("Leaving HttpChallengeAttestor.attest(). Agent name.");
      throw this.refuse(call, 'STS-SPIFFE-0103', status.INVALID_ARGUMENT,
                        'agent name is not valid');
    }
    // 3. THE HOST NAME — before anything resolves or dials it.
    if (host === 'localhost') {
      log.debug("Leaving HttpChallengeAttestor.attest(). localhost.");
      throw this.refuse(call, 'STS-SPIFFE-0104', status.PERMISSION_DENIED,
                        'you can not use localhost as a hostname');
    }
    if (!host || host.indexOf('/') >= 0 || host.indexOf(':') >= 0 ||
        !(port > 0 && port < 65536) || !s.patterns.some(function (re) {
          return re.test(host);
        })) {
      log.debug("Leaving HttpChallengeAttestor.attest(). Not allowed.");
      throw this.refuse(call, 'STS-SPIFFE-0104', status.PERMISSION_DENIED,
                        'the requested hostname is not allowed to connect');
    }
    // 4. THE ADDRESS.
    if (s.verifyClientIp) {
      if (!context.clientIp) {
        log.debug("Leaving HttpChallengeAttestor.attest(). No address.");
        throw this.refuse(call, 'STS-SPIFFE-0091', status.INTERNAL,
                          'client IP not available for verification');
      }
      let resolved = [];
      try {
        resolved = await lookup(host);
      } catch (e) {
        log.debug("Caught in HttpChallengeAttestor.attest(): " +
                  ((e && e.message) || e));
        throw this.refuse(call, 'STS-SPIFFE-0091', status.INTERNAL,
          'failed to resolve hostname "' + host + '": ' + e.message);
      }
      if (resolved.indexOf(context.clientIp) < 0) {
        log.debug("Leaving HttpChallengeAttestor.attest(). Address.");
        throw this.refuse(call, 'STS-SPIFFE-0090', status.PERMISSION_DENIED,
          'client IP ' + context.clientIp + ' does not match any address ' +
          'for hostname "' + host + '"');
      }
    }
    // 5. THE CHALLENGE, then the fetch.
    const nonce = crypto.randomBytes(32).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_');
    await context.challenge(Buffer.from(JSON.stringify({ nonce: nonce }),
                                        'utf8'));
    const fetched = await outbound.fetchHttpChallenge(host, port,
      '/.well-known/spiffe/nodeattestor/http_challenge/' + agentName +
      '/challenge');
    if (!fetched.ok || fetched.body.toString('utf8').trim() !== nonce) {
      log.debug("Leaving HttpChallengeAttestor.attest(). No nonce.");
      throw this.refuse(call, 'STS-SPIFFE-0105', status.PERMISSION_DENIED,
        'challenge verification failed: ' + (fetched.ok
          ? 'expected nonce was not found in HTTP response' : fetched.why));
    }
    // 6. THE AGENT.
    const agentId = spiffeId.make(context.trustDomain,
                                  '/spire/agent/http_challenge/' + host);
    if (!spiffeId.parse(agentId).ok) {
      log.debug("Leaving HttpChallengeAttestor.attest(). A bad agent id.");
      throw this.refuse(call, 'STS-SPIFFE-0095', status.INTERNAL,
                        'failed to make spiffe id');
    }
    log.debug("Leaving HttpChallengeAttestor.attest(). " + agentId);
    return {
      agentId: agentId,
      selectors: [{ type: 'http_challenge', value: 'hostname:' + host }],
      canReattest: !s.tofu,
      method: 'agent attestation (http_challenge)',
      note: 'attested by a nonce served from ' + host + ':' + port +
            ', as strong as the network\'s DNS',
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
  HttpChallengeAttestor: HttpChallengeAttestor
};
