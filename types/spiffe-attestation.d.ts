// ---------------------------------------------------------------------------
// THE SHAPES OF SPIFFE NODE ATTESTATION (#40, 2026-09-21).
//
// `spiffe/spiffe_node_attestation.ts` holds the table and
// `spiffe/spiffe_api.ts`'s `AttestAgent` runs it; each attestor is a class in
// a `spiffe/spiffe_attestor_<type>.ts` of its own. These are the sentences
// that pass between them, as types.
// ---------------------------------------------------------------------------

// One selector, as the registry and the protobuf both spell it.
export interface Selector {
  type: string;
  value: string;
}

// What an attestor is handed. `challenge()` writes an AttestAgentResponse
// carrying `challenge` and resolves with the `challenge_response` bytes of
// the client's next message; it rejects on the challenge timeout and when the
// client ends or cancels the stream (the error carries `conversation`:
// 'timeout', 'ended', 'cancelled' or 'busy'). `call` is there so an attestor
// can mark its own error code on the line before it throws.
export interface NodeAttestationContext {
  type: string;
  payload: Buffer;
  trustDomain: string;
  // The address the agent connected from, without its port — '' on the Unix
  // socket, which has none. SPIRE's `verify_client_ip` compares it.
  clientIp: string;
  call: any;
  challenge(bytes: Buffer): Promise<Buffer>;
}

// What an attestor answers with, having VERIFIED the evidence. Everything
// here is a fact the attestor established — an attestor that cannot
// establish one throws a status error instead of returning.
export interface NodeAttestationResult {
  // The agent's SPIFFE ID, built by SPIRE's template for this attestor.
  agentId: string;
  // The selectors the attestor derived from what it verified. Never a
  // placeholder and never the evidence itself.
  selectors: Selector[];
  // SPIRE's CanReattest: false for the trust-on-first-use attestors, whose
  // evidence can be presented only once per agent.
  canReattest: boolean;
  // The `method` and `note` of the identity row `recordIdentity()` writes.
  method: string;
  note: string;
  // Called once an SVID has been signed and the agent recorded: the evidence
  // is spent. Called at most once, and never together with `release()`.
  commit(): void;
  // Called when anything after `attest()` failed: whatever `attest()` claimed
  // is given back, so the evidence is exactly as spendable as it was.
  release(): void;
}

export interface NodeAttestor {
  // The attestation type an agent names in `params.data.type`.
  readonly type: string;
  // One sentence for `GET /spiffe` and the console: what it verifies.
  readonly verifies: string;
  attest(context: NodeAttestationContext): Promise<NodeAttestationResult>;
}
