'use strict';
//
// File: spiffe_node_attestation.ts
//
// ---------------------------------------------------------------------------
// THE NODE ATTESTORS, AS A TABLE (#40, 2026-09-21).
//
// `Agent.AttestAgent` is how a SPIRE agent joins a trust domain: it names an
// attestation type, sends that type's evidence, and — for some types —
// answers a challenge, and the SERVER decides from what it verified which
// agent this is and what selectors it has. A real SPIRE server does that with
// a node-attestor plugin per type. This file is the plugin table.
//
// **UNTIL THIS FILE EXISTED, EVERY TYPE BUT `join_token` WAS TAKEN ON TRUST.**
// An agent could name any type and send any payload, and it was issued an
// agent SVID under `/spire/agent/<type>/<digest of the payload>` with a
// selector saying `unverified:true` — which the page reported honestly and
// which gave the agent everything beneath that id all the same. That branch is
// gone, in every mode (rcbj, 2026-09-21): a type that is not in this table, or
// that the realm has not turned on in `spiffe.nodeAttestors`, is REFUSED with
// FAILED_PRECONDITION, which is what SPIRE answers for an attestor it has no
// plugin for. `join_token` is still the easy path for development, and it is
// verified — this server minted it. `x509pop`, `sshpop` and `tpm_devid`
// (phase two) prove possession of a key by answering a challenge.
//
// A LIBRARY: it registers no route, requires nothing of this service but the
// logger and the settings, and holds no state but the table. `spiffe_api.ts`
// builds one and registers the attestors, because the join token's store is
// that module's; each later attestor is a class in a
// `spiffe_attestor_<type>.ts` of its own and is registered the same way.
//
// **WHAT AN ATTESTOR MUST NOT DO** is return a selector it did not establish.
// The selector types are SPIRE's own (`x509pop:subject:cn:…`,
// `k8s_psat:agent_ns:…`), and a registration entry written against SPIRE's
// documentation selects on them; one invented here would be a fact that
// entry's author trusted and nobody checked — the `wauth` offence. An attestor
// that cannot establish something THROWS a status error with its code marked,
// and the table has no fallback to catch it with.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');

type NodeAttestor = import('../types/spiffe-attestation').NodeAttestor;

interface NodeAttestationDeps {
  log: typeof log;
  config: typeof config;
}

class NodeAttestation {
  private readonly attestors = new Map<string, NodeAttestor>();

  constructor(private readonly deps: NodeAttestationDeps) {
    deps.log.debug("Entering NodeAttestation.constructor().");
    deps.log.debug("Leaving NodeAttestation.constructor().");
  }

  static defaultDeps(): NodeAttestationDeps {
    helpers.log.debug("Entering NodeAttestation.defaultDeps().");
    helpers.log.debug("Leaving NodeAttestation.defaultDeps().");
    return { log: log, config: config };
  }

  // One attestor per type. A second registration of a type is a defect in
  // whoever built the table — two plugins answering one type would make the
  // answer depend on the order they were registered in — so it throws.
  register(attestor: NodeAttestor): void {
    const { log } = this.deps;
    log.debug("Entering NodeAttestation.register(). type=" + attestor.type);
    if (this.attestors.has(attestor.type)) {
      log.debug("Leaving NodeAttestation.register(). A duplicate.");
      // error-code: none — a defect in the table's construction, thrown at
      // load, never a caller's refusal
      throw new Error('The node attestor ' + attestor.type + ' is ' +
                      'registered twice.');
    }
    this.attestors.set(attestor.type, attestor);
    log.debug("Leaving NodeAttestation.register().");
  }

  // Every type this build can verify, whether or not any realm turned it on.
  known(): string[] {
    const { log } = this.deps;
    log.debug("Entering NodeAttestation.known().");
    log.debug("Leaving NodeAttestation.known().");
    return Array.from(this.attestors.keys()).sort();
  }

  // The types `spiffe.nodeAttestors` names, as written, in the AMBIENT realm
  // — the realm of the socket the call arrived on (`spiffe/CLAUDE.md`).
  configured(): string[] {
    const { log, config } = this.deps;
    log.debug("Entering NodeAttestation.configured().");
    const raw = config.value('spiffe.nodeAttestors');
    log.debug("Leaving NodeAttestation.configured().");
    return (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (type) { return String(type).trim(); })
      .filter(Boolean);
  }

  // What the realm turned on AND this build can verify. A configured name
  // with no attestor behind it is not an error at the setting — the setting
  // is shared by every realm and a typo in one should not stop another — but
  // it is reported by `state()` and can never accept anything.
  enabled(): string[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering NodeAttestation.enabled().");
    log.debug("Leaving NodeAttestation.enabled().");
    return this.configured().filter(function (type) {
      return self.attestors.has(type);
    });
  }

  // The attestor for `type` if this realm accepts it, and null otherwise.
  // The caller refuses on null; there is no default attestor.
  attestorFor(type: string): NodeAttestor | null {
    const { log } = this.deps;
    log.debug("Entering NodeAttestation.attestorFor(). type=" + type);
    if (this.enabled().indexOf(type) < 0) {
      log.debug("Leaving NodeAttestation.attestorFor(). Not accepted here.");
      return null;
    }
    log.debug("Leaving NodeAttestation.attestorFor().");
    return this.attestors.get(type) || null;
  }

  // How long an attestor's challenge waits for its response, in
  // milliseconds — `spiffe.attestationChallengeTimeout`, in seconds.
  challengeTimeoutMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering NodeAttestation.challengeTimeoutMs().");
    log.debug("Leaving NodeAttestation.challengeTimeoutMs().");
    return Number(config.value('spiffe.attestationChallengeTimeout')) * 1000;
  }

  // What the pages draw: every type this build verifies, whether the realm
  // accepts it, and the configured names nothing verifies.
  state() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering NodeAttestation.state().");
    const enabled = this.enabled();
    const unknown = this.configured().filter(function (type) {
      return !self.attestors.has(type);
    });
    log.debug("Leaving NodeAttestation.state().");
    return {
      attestors: this.known().map(function (type) {
        return { type: type, enabled: enabled.indexOf(type) >= 0,
                 verifies: self.attestors.get(type).verifies };
      }),
      unknownConfigured: unknown,
      challengeTimeoutSeconds: this.challengeTimeoutMs() / 1000
    };
  }
}

export = {
  NodeAttestation: NodeAttestation
};
