'use strict';
//
// File: spiffe_attestor_join_token.ts
//
// ---------------------------------------------------------------------------
// THE `join_token` NODE ATTESTOR (#40, 2026-09-21 — moved here out of
// `AttestAgent`, where it was written on 2026-08-22).
//
// A join token is the one attestation evidence this server ISSUED and can
// therefore verify with nothing outside itself: `CreateJoinToken` minted it,
// it has a lifetime, and it is single use. So it is checked in every mode, and
// the three refusals are kept apart — a token nobody minted (or already
// spent), a token that ran out, and an empty one are three different bugs in a
// client, and one message for all three would send somebody looking in the
// wrong place.
//
// **SPENT ONCE ACROSS THE CLUSTER (2026-09-14, #46).** The store replicates to
// the other nodes a moment after a write, so two AttestAgent calls carrying
// one token at two nodes inside that moment both found it. It is therefore
// CLAIMED here, once every check that refuses without a side effect has
// passed, and the claim lives until the token would have expired plus a
// minute of skew; `commit()` deletes the token once the SVID exists, and
// `release()` gives the claim back when anything after this failed, so the
// token is exactly as spendable as it was.
//
// **THE AGENT ID IS `/spire/agent/join_token/<digest>`, NOT THE TOKEN.** SPIRE
// puts the token itself in the path. This service does not, for the reason
// the store is keyed by a digest (`spiffe/CLAUDE.md`, *JOIN TOKENS ARE PER
// REALM*): an agent's id is written into the directory, the audit log and
// every certificate it holds, and a credential does not belong in any of
// them, spent or not. `agentIdFor()` is the one spelling, used both here and
// by `CreateJoinToken` when it registers the alias a named agent gets.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import helpers = require('../common/helpers');
const { log, nowSec } = helpers;
import errorCodes = require('../common/error_codes');
import spiffeId = require('./spiffe_id');
import rpc = require('./spiffe_grpc');
import claims = require('../cluster/cluster_claims');

type NodeAttestationContext =
  import('../types/spiffe-attestation').NodeAttestationContext;
type NodeAttestationResult =
  import('../types/spiffe-attestation').NodeAttestationResult;

interface JoinTokenAttestorDeps {
  log: typeof log;
  nowSec: typeof nowSec;
  crypto: typeof crypto;
  errorCodes: typeof errorCodes;
  spiffeId: typeof spiffeId;
  rpc: typeof rpc;
  claims: typeof claims;
  // The realm's join tokens, keyed by `keyOf()` — `spiffe_api.ts`'s store,
  // because `CreateJoinToken` writes it.
  tokens: { get(key: string): any; has(key: string): boolean;
            delete(key: string): any };
  keyOf(token: string): string;
}

class JoinTokenAttestor {
  readonly type = 'join_token';
  readonly verifies = 'A token this server minted with CreateJoinToken: ' +
    'unexpired, unspent, and spent once across every node.';

  constructor(private readonly deps: JoinTokenAttestorDeps) {
    deps.log.debug("Entering JoinTokenAttestor.constructor().");
    deps.log.debug("Leaving JoinTokenAttestor.constructor().");
  }

  // The agent a token attests, from the token. See the header for why it is
  // a digest.
  agentIdFor(trustDomain: string, token: string): string {
    const { log, crypto, spiffeId } = this.deps;
    log.debug("Entering JoinTokenAttestor.agentIdFor().");
    const suffix = crypto.createHash('sha256')
      .update('join_token|').update(String(token || '').trim(), 'utf8')
      .digest('hex').slice(0, 32);
    log.debug("Leaving JoinTokenAttestor.agentIdFor().");
    return spiffeId.agentId(trustDomain, 'join_token', suffix);
  }

  async attest(context: NodeAttestationContext):
      Promise<NodeAttestationResult> {
    const { log, nowSec, crypto, errorCodes, rpc, claims, tokens,
            keyOf } = this.deps;
    log.debug("Entering JoinTokenAttestor.attest().");
    const call = context.call;
    const presented = Buffer.from(context.payload || []).toString('utf8')
      .trim();
    if (!presented) {
      log.debug("Leaving JoinTokenAttestor.attest(). Empty.");
      errorCodes.mark(call, 'STS-SPIFFE-0054');
      throw rpc.invalidArgument('A join_token attestation carries the ' +
                                'token as params.data.payload, and ' +
                                'this one is empty.');
    }
    const key = keyOf(presented);
    const held = tokens.get(key);
    if (!held) {
      log.debug("Leaving JoinTokenAttestor.attest(). Not held.");
      errorCodes.mark(call, 'STS-SPIFFE-0055');
      throw rpc.permissionDenied('That join token was not issued by ' +
                                 'this server, or it has already been ' +
                                 'spent — a join token is single-use, ' +
                                 'and the one it attested is ' +
                                 'on /admin/spiffe/agents. Ask ' +
                                 'for a new one with CreateJoinToken.');
    }
    if (held.expiresAt && held.expiresAt < nowSec()) {
      tokens.delete(key);
      log.debug("Leaving JoinTokenAttestor.attest(). Expired.");
      errorCodes.mark(call, 'STS-SPIFFE-0056');
      throw rpc.permissionDenied('That join token expired at ' +
        new Date(held.expiresAt * 1000).toISOString() + '. It has been ' +
        'discarded; ask for another with CreateJoinToken, which takes ' +
        'a ttl.');
    }
    const claimed = await claims.claim({
      scope: 'spiffe.join-token', value: key,
      ttlMs: Math.max(60 * 1000, held.expiresAt
        ? (held.expiresAt - nowSec()) * 1000 + 60 * 1000 : 0)
    });
    if (!claimed.ok && claimed.reason === 'used') {
      log.debug("Leaving JoinTokenAttestor.attest(). Claimed elsewhere.");
      errorCodes.mark(call, 'STS-SPIFFE-0055');
      throw rpc.permissionDenied('That join token was not issued by ' +
                                 'this server, or it has already been ' +
                                 'spent — a join token is ' +
                                 'single-use. Ask for a new ' +
                                 'one with CreateJoinToken.');
    }
    if (!claimed.ok) {
      log.error(errorCodes.tag('STS-SPIFFE-0075') +
                'spiffe: a join token ' +
                'could not be proved unspent (' + claimed.why +
                '); the attestation is refused.');
      log.debug("Leaving JoinTokenAttestor.attest(). No claim.");
      errorCodes.mark(call, 'STS-SPIFFE-0075');
      throw rpc.unavailable('This server could not check the join ' +
                            'token just now. Retry.');
    }
    const handle = claimed.handle;
    let settled = false;
    log.debug("Leaving JoinTokenAttestor.attest(). Verified.");
    return {
      agentId: this.agentIdFor(context.trustDomain, presented),
      // A digest prefix, never the token: somebody holding the token can
      // recognise the agent it attested, and nobody can reconstruct it
      // (2026-09-12).
      selectors: [{ type: 'join_token',
                    value: 'token-sha256:' + crypto.createHash('sha256')
                      .update(presented, 'utf8').digest('hex').slice(0, 16) }],
      // Single use, so an agent that attested with one cannot do it again.
      canReattest: false,
      method: 'agent attestation (join token)',
      note: 'attested with a join token this server minted and has now spent',
      commit: function () {
        log.debug("Entering commit().");
        if (settled) {
          log.debug("Leaving commit(). Already settled.");
          return;
        }
        settled = true;
        if (tokens.has(key)) {
          tokens.delete(key);
          log.info('spiffe: the join token ending ' + presented.slice(-6) +
                   ' has been spent and cannot be used again.');
        }
        log.debug("Leaving commit().");
      },
      release: function () {
        log.debug("Entering release().");
        if (settled) {
          log.debug("Leaving release(). Already settled.");
          return;
        }
        settled = true;
        claims.release(handle);
        log.debug("Leaving release().");
      }
    };
  }
}

export = {
  JoinTokenAttestor: JoinTokenAttestor
};
