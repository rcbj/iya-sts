// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/spiffe/spire_server.tsp
//
// THE SPIRE SERVER API (#1579): the six services this service serves, their methods and every message of theirs, from `spire/api/server/*/v1/*.proto`.
//
// Converted once from the vendored `spiffe/protos/spire/api/server/*/v1/*.proto` by a script that
// read them with protobufjs, as `spiffe/spiffe_grpc.ts` reads them; written
// by hand since (#1579). Each message is the proto's field for field — its
// number, type, `repeated`, map and oneof — and the comments are the
// proto's. `models/tools/generate.mjs` holds every one of them to the
// vendored file and stops the image build on a difference, so the protos
// stay the specification's text and this states, beside it, what this
// service refuses and answers. `models/spiffe/spiffe.tsp` says how the
// service reads it.

import "../lib/spiffe_lib.tsp";
import "./google.tsp";
import "./spire_types.tsp";
using IyaSts.SpiffeLib;

namespace IyaSts.Spiffe.Server.Entry {
  /**
   * Manages registration entries stored by the SPIRE Server.
   */
  @grpcService(#{
    name: "spire.api.server.entry.v1.Entry",
    surface: "server",
    statuses: #["UNAUTHENTICATED", "PERMISSION_DENIED", "UNAVAILABLE", "UNKNOWN", "INTERNAL"],
    cite: "SPIRE Server API, entry.proto; pkg/server/authpolicy/policy_data.json"
  })
  interface Entry {
    /**
     * Count entries.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    CountEntries(request: CountEntriesRequest): CountEntriesResponse;

    /**
     * Lists entries.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    ListEntries(request: ListEntriesRequest): ListEntriesResponse;

    /**
     * Gets an entry. If the entry does not exist, NOT_FOUND is returned.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["NOT_FOUND"]
    })
    GetEntry(request: GetEntryRequest): IyaSts.Spiffe.SpireTypes.Entry;

    /**
     * Batch creates one or more entries.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    BatchCreateEntry(request: BatchCreateEntryRequest): BatchCreateEntryResponse;

    /**
     * Batch updates one or more entries.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    BatchUpdateEntry(request: BatchUpdateEntryRequest): BatchUpdateEntryResponse;

    /**
     * Batch deletes one or more entries.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    BatchDeleteEntry(request: BatchDeleteEntryRequest): BatchDeleteEntryResponse;

    /**
     * Gets the entries the caller is authorized for.
     *
     * The caller must present an active agent X509-SVID. See the Agent
     * AttestAgent/RenewAgent RPCs.
     */
    @rpc(#{ stream: "unary" })
    GetAuthorizedEntries(request: GetAuthorizedEntriesRequest): GetAuthorizedEntriesResponse;

    /**
     * Syncs authorized entries down to the caller. The caller controls which
     * entries the server sends down full details for. The flow is as follows:
     * 1. Caller opens up sync stream
     * 2. Server determines authorized entries for caller:
     * - If there are less entries than a server-determined page size, go to (5).
     * - Otherwise, go to (3).
     * 3. Server pages entry revisions to the caller (contains the entry ID and
     * revision number). The "more" flag set for all pages but the last so
     * that the caller knows when the server is done.
     * 4. Client determines which entries are new or updated (based on revision
     * number) and asks for them by sending a request with the IDs.
     * 5. Server pages down entries to the caller for each ID identified in (4)
     * or every entry in (2) if the number of entries was less than the
     * server-determined page size. The "more" flag set for all pages but
     * the last so that the caller knows when the server is done.
     * 6. Steps (4) and (5) are repeated until the caller has synced down the
     * details for all new/updated entries and closes the stream.
     */
    @rpc(#{
      stream: "bidi",
      statuses: #["INVALID_ARGUMENT", "RESOURCE_EXHAUSTED"]
    })
    SyncAuthorizedEntries(request: SyncAuthorizedEntriesRequest): SyncAuthorizedEntriesResponse;
  }

  @message("spire.api.server.entry.v1.CountEntriesRequest")
  model CountEntriesRequest {
    /**
     * Filters the entries returned in the response.
     */
    @field(1)
    filter?: CountEntriesRequest_Filter;
  }

  @message("spire.api.server.entry.v1.CountEntriesRequest.Filter")
  model CountEntriesRequest_Filter {
    @field(1)
    by_spiffe_id?: IyaSts.Spiffe.SpireTypes.SPIFFEID;

    @field(2)
    by_parent_id?: IyaSts.Spiffe.SpireTypes.SPIFFEID;

    @field(3)
    by_selectors?: IyaSts.Spiffe.SpireTypes.SelectorMatch;

    @field(4)
    by_federates_with?: IyaSts.Spiffe.SpireTypes.FederatesWithMatch;

    @field(5)
    by_hint?: IyaSts.Spiffe.Google.StringValue;

    @field(6)
    by_downstream?: IyaSts.Spiffe.Google.BoolValue;
  }

  @message("spire.api.server.entry.v1.CountEntriesResponse")
  model CountEntriesResponse {
    @field(1)
    count?: int32;
  }

  @message("spire.api.server.entry.v1.ListEntriesRequest")
  model ListEntriesRequest {
    /**
     * Filters the entries returned in the response.
     */
    @field(1)
    filter?: ListEntriesRequest_Filter;

    /**
     * An output mask indicating the entry fields set in the response.
     */
    @field(2)
    output_mask?: IyaSts.Spiffe.SpireTypes.EntryMask;

    /**
     * The maximum number of results to return. The server may further
     * constrain this value, or if zero, choose its own.
     */
    @field(3)
    page_size?: int32;

    /**
     * The next_page_token value returned from a previous request, if any.
     */
    @field(4)
    page_token?: string;
  }

  @message("spire.api.server.entry.v1.ListEntriesRequest.Filter")
  model ListEntriesRequest_Filter {
    @field(1)
    by_spiffe_id?: IyaSts.Spiffe.SpireTypes.SPIFFEID;

    @field(2)
    by_parent_id?: IyaSts.Spiffe.SpireTypes.SPIFFEID;

    @field(3)
    by_selectors?: IyaSts.Spiffe.SpireTypes.SelectorMatch;

    @field(4)
    by_federates_with?: IyaSts.Spiffe.SpireTypes.FederatesWithMatch;

    @field(5)
    by_hint?: IyaSts.Spiffe.Google.StringValue;

    @field(6)
    by_downstream?: IyaSts.Spiffe.Google.BoolValue;
  }

  @message("spire.api.server.entry.v1.ListEntriesResponse")
  model ListEntriesResponse {
    /**
     * The list of entries.
     */
    @field(1)
    entries?: IyaSts.Spiffe.SpireTypes.Entry[];

    /**
     * The page token for the next request. Empty if there are no more results.
     * This field should be checked by clients even when a page_size was not
     * requested, since the server may choose its own (see page_size).
     */
    @field(2)
    next_page_token?: string;
  }

  @message("spire.api.server.entry.v1.GetEntryRequest")
  model GetEntryRequest {
    /**
     * Required. ID of the entry to get.
     */
    @field(1)
    id?: string;

    /**
     * An output mask indicating the entry fields set in the response.
     */
    @field(2)
    output_mask?: IyaSts.Spiffe.SpireTypes.EntryMask;
  }

  @message("spire.api.server.entry.v1.BatchCreateEntryRequest")
  model BatchCreateEntryRequest {
    /**
     * The entries to be created. If no entry ID is provided, one will be
     * generated.
     */
    @field(1)
    entries?: IyaSts.Spiffe.SpireTypes.Entry[];

    /**
     * An output mask indicating the entry fields set in the response.
     */
    @field(2)
    output_mask?: IyaSts.Spiffe.SpireTypes.EntryMask;
  }

  @message("spire.api.server.entry.v1.BatchCreateEntryResponse")
  model BatchCreateEntryResponse {
    /**
     * Result for each entry in the request (order is maintained).
     */
    @field(1)
    results?: BatchCreateEntryResponse_Result[];
  }

  @message("spire.api.server.entry.v1.BatchCreateEntryResponse.Result")
  model BatchCreateEntryResponse_Result {
    /**
     * The status of creating the entry. If status code will be
     * ALREADY_EXISTS if a similar entry already exists. An entry is
     * similar if it has the same spiffe_id, parent_id, and selectors.
     */
    @field(1)
    status?: IyaSts.Spiffe.SpireTypes.Status;

    /**
     * The entry that was created (.e.g status code is OK) or that already
     * exists (i.e. status code is ALREADY_EXISTS).
     *
     * If the status code is any other value, this field will not be set.
     */
    @field(2)
    entry?: IyaSts.Spiffe.SpireTypes.Entry;
  }

  @message("spire.api.server.entry.v1.BatchUpdateEntryRequest")
  model BatchUpdateEntryRequest {
    /**
     * The entries to be updated.
     */
    @field(1)
    entries?: IyaSts.Spiffe.SpireTypes.Entry[];

    /**
     * An input mask indicating what entry fields should be updated.
     */
    @field(2)
    input_mask?: IyaSts.Spiffe.SpireTypes.EntryMask;

    /**
     * An output mask indicating what entry fields are set in the response.
     */
    @field(3)
    output_mask?: IyaSts.Spiffe.SpireTypes.EntryMask;
  }

  @message("spire.api.server.entry.v1.BatchUpdateEntryResponse")
  model BatchUpdateEntryResponse {
    /**
     * Result for each entry in the request (order is maintained).
     */
    @field(1)
    results?: BatchUpdateEntryResponse_Result[];
  }

  @message("spire.api.server.entry.v1.BatchUpdateEntryResponse.Result")
  model BatchUpdateEntryResponse_Result {
    /**
     * The status of creating the entry.
     */
    @field(1)
    status?: IyaSts.Spiffe.SpireTypes.Status;

    /**
     * The entry that was updated. If the status is OK, it will be the
     * entry that was updated. If the status is any other value, this field
     * will not be set.
     */
    @field(2)
    entry?: IyaSts.Spiffe.SpireTypes.Entry;
  }

  @message("spire.api.server.entry.v1.BatchDeleteEntryRequest")
  model BatchDeleteEntryRequest {
    /**
     * IDs of the entries to delete.
     */
    @field(1)
    ids?: string[];
  }

  @message("spire.api.server.entry.v1.BatchDeleteEntryResponse")
  model BatchDeleteEntryResponse {
    /**
     * Result for each entry ID in the request (order is maintained).
     */
    @field(1)
    results?: BatchDeleteEntryResponse_Result[];
  }

  @message("spire.api.server.entry.v1.BatchDeleteEntryResponse.Result")
  model BatchDeleteEntryResponse_Result {
    /**
     * The status of creating the entry.
     */
    @field(1)
    status?: IyaSts.Spiffe.SpireTypes.Status;

    /**
     * The ID of the entry that was deleted.
     */
    @field(2)
    id?: string;
  }

  @message("spire.api.server.entry.v1.GetAuthorizedEntriesRequest")
  model GetAuthorizedEntriesRequest {
    /**
     * An output mask indicating which fields are set in the response.
     */
    @field(1)
    output_mask?: IyaSts.Spiffe.SpireTypes.EntryMask;
  }

  @message("spire.api.server.entry.v1.GetAuthorizedEntriesResponse")
  model GetAuthorizedEntriesResponse {
    /**
     * The authorized entries.
     */
    @field(1)
    entries?: IyaSts.Spiffe.SpireTypes.Entry[];
  }

  @message("spire.api.server.entry.v1.SyncAuthorizedEntriesRequest")
  model SyncAuthorizedEntriesRequest {
    /**
     * An output mask indicating which fields are set in the response.
     */
    @field(1)
    output_mask?: IyaSts.Spiffe.SpireTypes.EntryMask;

    /**
     * IDs of the entries to fetch in full. Sent by the client in response to
     * a sparse entry.
     */
    @field(2)
    ids?: string[];
  }

  @message("spire.api.server.entry.v1.SyncAuthorizedEntriesResponse")
  model SyncAuthorizedEntriesResponse {
    /**
     * The revisions of the authorized entries. This field is set when the
     * authorized entry list meets or exceeds the server-determined page size.
     * Callers use it to determine which entries are new/updated that they then
     * request on the stream.
     * See SyncAuthorizedEntries for details.
     */
    @field(1)
    entry_revisions?: EntryRevision[];

    /**
     * The authorized entries. This field is set either 1) on the initial
     * response if the number of authorized entries is less than the page size
     * or 2) in response to the caller requesting the entries after determining
     * they need to details based on entry revisions provided in a previous
     * response.
     * See SyncAuthorizedEntries for details.
     */
    @field(2)
    entries?: IyaSts.Spiffe.SpireTypes.Entry[];

    /**
     * Whether there are more entries to sync down in this response phase.
     */
    @field(3)
    more?: boolean;
  }

  @message("spire.api.server.entry.v1.EntryRevision")
  model EntryRevision {
    /**
     * The entry ID.
     */
    @field(1)
    id?: string;

    /**
     * The entry revision number.
     */
    @field(2)
    revision_number?: int64;

    /**
     * When the entry was created (seconds since Unix epoch).
     */
    @field(3)
    created_at?: int64;
  }
}

namespace IyaSts.Spiffe.Server.Agent {
  @grpcService(#{
    name: "spire.api.server.agent.v1.Agent",
    surface: "server",
    statuses: #["UNAUTHENTICATED", "PERMISSION_DENIED", "UNAVAILABLE", "UNKNOWN", "INTERNAL"],
    cite: "SPIRE Server API, agent.proto; pkg/server/authpolicy/policy_data.json"
  })
  interface Agent {
    /**
     * Count agents.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    CountAgents(request: CountAgentsRequest): CountAgentsResponse;

    /**
     * Lists agents.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    ListAgents(request: ListAgentsRequest): ListAgentsResponse;

    /**
     * Gets an agent.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["NOT_FOUND"]
    })
    GetAgent(request: GetAgentRequest): IyaSts.Spiffe.SpireTypes.Agent;

    /**
     * Deletes an agent. The agent can come back into the trust domain through
     * the Issuer AttestAgent RPC.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["NOT_FOUND"]
    })
    DeleteAgent(request: DeleteAgentRequest): IyaSts.Spiffe.Google.Empty;

    /**
     * Bans an agent. This evicts the agent and prevents it from rejoining the
     * trust domain through attestation until the ban is lifted via a call to
     * DeleteAgent.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["NOT_FOUND"]
    })
    BanAgent(request: BanAgentRequest): IyaSts.Spiffe.Google.Empty;

    /**
     * Attests the agent via node attestation, using a bidirectional stream to
     * faciliate attestation methods that require challenge/response.
     *
     * The caller is not authenticated.
     */
    @rpc(#{
      stream: "bidi",
      statuses: #["INVALID_ARGUMENT", "FAILED_PRECONDITION", "DEADLINE_EXCEEDED", "CANCELLED", "PERMISSION_DENIED"]
    })
    AttestAgent(request: AttestAgentRequest): AttestAgentResponse;

    /**
     * Renews the agent and returns a new X509-SVID. The new SVID is not enabled
     * on the server side until its first use.
     *
     * The caller must present an active agent X509-SVID, i.e. the X509-SVID
     * returned by the AttestAgent or the most recent RenewAgent call.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["INVALID_ARGUMENT", "NOT_FOUND", "PERMISSION_DENIED", "UNIMPLEMENTED"]
    })
    RenewAgent(request: RenewAgentRequest): RenewAgentResponse;

    /**
     * Creates an agent join token. The token can be used with `join_token`
     * attestation to join the trust domain.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["INVALID_ARGUMENT", "RESOURCE_EXHAUSTED"]
    })
    CreateJoinToken(request: CreateJoinTokenRequest): IyaSts.Spiffe.SpireTypes.JoinToken;

    /**
     * PostStatus post Agent status, informing what's the current
     * bundle that is being used by the agent.
     *
     * The caller must present an active agent X509-SVID, i.e. the X509-SVID
     * returned by the AttestAgent or the most recent RenewAgent call.
     */
    @rpc(#{ stream: "unary" })
    PostStatus(request: PostStatusRequest): PostStatusResponse;
  }

  @message("spire.api.server.agent.v1.CountAgentsRequest")
  model CountAgentsRequest {
    /**
     * Filters the agents returned by the list operation.
     */
    @field(1)
    filter?: CountAgentsRequest_Filter;
  }

  @message("spire.api.server.agent.v1.CountAgentsRequest.Filter")
  model CountAgentsRequest_Filter {
    /**
     * Filters agents to those matching the attestation type.
     */
    @field(1)
    by_attestation_type?: string;

    /**
     * Filters agents to those satisfying the selector match.
     */
    @field(2)
    by_selector_match?: IyaSts.Spiffe.SpireTypes.SelectorMatch;

    /**
     * Filters agents to those that are banned.
     */
    @field(3)
    by_banned?: IyaSts.Spiffe.Google.BoolValue;

    /**
     * Filters agents that can re-attest.
     */
    @field(4)
    by_can_reattest?: IyaSts.Spiffe.Google.BoolValue;

    /**
     * Filters agents by those expires before.
     */
    @field(5)
    by_expires_before?: string;
  }

  @message("spire.api.server.agent.v1.CountAgentsResponse")
  model CountAgentsResponse {
    @field(1)
    count?: int32;
  }

  @message("spire.api.server.agent.v1.ListAgentsRequest")
  model ListAgentsRequest {
    /**
     * Filters the agents returned by the list operation.
     */
    @field(1)
    filter?: ListAgentsRequest_Filter;

    /**
     * An output mask indicating which agent fields are set in the response.
     */
    @field(2)
    output_mask?: IyaSts.Spiffe.SpireTypes.AgentMask;

    /**
     * The maximum number of results to return. The server may further
     * constrain this value, or if zero, choose its own.
     */
    @field(3)
    page_size?: int32;

    /**
     * The next_page_token value returned from a previous request, if any.
     */
    @field(4)
    page_token?: string;
  }

  @message("spire.api.server.agent.v1.ListAgentsRequest.Filter")
  model ListAgentsRequest_Filter {
    /**
     * Filters agents to those matching the attestation type.
     */
    @field(1)
    by_attestation_type?: string;

    /**
     * Filters agents to those satisfying the selector match.
     */
    @field(2)
    by_selector_match?: IyaSts.Spiffe.SpireTypes.SelectorMatch;

    /**
     * Filters agents to those that are banned.
     */
    @field(3)
    by_banned?: IyaSts.Spiffe.Google.BoolValue;

    /**
     * Filters agents that can re-attest.
     */
    @field(4)
    by_can_reattest?: IyaSts.Spiffe.Google.BoolValue;

    /**
     * Filters agents by those expires before.
     */
    @field(5)
    by_expires_before?: string;
  }

  @message("spire.api.server.agent.v1.ListAgentsResponse")
  model ListAgentsResponse {
    /**
     * The agents.
     */
    @field(1)
    agents?: IyaSts.Spiffe.SpireTypes.Agent[];

    /**
     * The page token for the next request. Empty if there are no more results.
     * This field should be checked by clients even when a page_size was not
     * requested, since the server may choose its own (see page_size).
     */
    @field(2)
    next_page_token?: string;
  }

  @message("spire.api.server.agent.v1.GetAgentRequest")
  model GetAgentRequest {
    /**
     * Required. The SPIFFE ID of the agent.
     */
    @field(1)
    id?: IyaSts.Spiffe.SpireTypes.SPIFFEID;

    /**
     * An output mask indicating which agent fields are set in the response.
     */
    @field(2)
    output_mask?: IyaSts.Spiffe.SpireTypes.AgentMask;
  }

  @message("spire.api.server.agent.v1.DeleteAgentRequest")
  model DeleteAgentRequest {
    /**
     * Required. The SPIFFE ID of the agent.
     */
    @field(1)
    id?: IyaSts.Spiffe.SpireTypes.SPIFFEID;
  }

  @message("spire.api.server.agent.v1.BanAgentRequest")
  model BanAgentRequest {
    /**
     * Required. The SPIFFE ID of the agent.
     */
    @field(1)
    id?: IyaSts.Spiffe.SpireTypes.SPIFFEID;
  }

  @message("spire.api.server.agent.v1.AttestAgentRequest")
  model AttestAgentRequest {
    /**
     * Attestation parameters. These are only sent in the initial request.
     */
    @field(1)
    @oneof("step")
    params?: AttestAgentRequest_Params;

    /**
     * The response to a challenge issued by the attestor. Only sent in
     * response to a challenge received by the issuer.
     */
    @refuse(#{
      when: "unexpected",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0051",
      message: "No attestation challenge is outstanding on this stream, so there is nothing a challenge_response can answer. Send the params step first.",
      cite: "SPIRE Server API, agent.proto AttestAgent"
    })
    @field(2)
    @oneof("step")
    challenge_response?: bytes;
  }

  @message("spire.api.server.agent.v1.AttestAgentRequest.Params")
  model AttestAgentRequest_Params {
    /**
     * Required. The attestation data.
     */
    @field(1)
    data?: IyaSts.Spiffe.SpireTypes.AttestationData;

    /**
     * Required. The X509-SVID parameters.
     */
    @field(2)
    params?: AgentX509SVIDParams;
  }

  @message("spire.api.server.agent.v1.AttestAgentResponse")
  model AttestAgentResponse {
    /**
     * Attestation results. If set, attestation has completed.
     */
    @field(1)
    @oneof("step")
    result?: AttestAgentResponse_Result;

    /**
     * A challenge issued by the attestor. If set, the caller is expected
     * to send another request on the stream with the challenge response.
     */
    @field(2)
    @oneof("step")
    challenge?: bytes;
  }

  @message("spire.api.server.agent.v1.AttestAgentResponse.Result")
  model AttestAgentResponse_Result {
    /**
     * The agent X509-SVID.
     */
    @field(1)
    svid?: IyaSts.Spiffe.SpireTypes.X509SVID;

    /**
     * Whether or not the attested agent can reattest to renew its X509-SVID
     */
    @field(2)
    reattestable?: boolean;
  }

  @message("spire.api.server.agent.v1.RenewAgentRequest")
  model RenewAgentRequest {
    /**
     * Required. Parameters for the X509-SVID.
     */
    @field(1)
    params?: AgentX509SVIDParams;
  }

  @message("spire.api.server.agent.v1.RenewAgentResponse")
  model RenewAgentResponse {
    /**
     * The renewed X509-SVID
     */
    @field(1)
    svid?: IyaSts.Spiffe.SpireTypes.X509SVID;
  }

  @message("spire.api.server.agent.v1.CreateJoinTokenRequest")
  model CreateJoinTokenRequest {
    /**
     * Required. How long until the token expires (in seconds).
     */
    @field(1)
    ttl?: int32;

    /**
     * An optional token value to use for the token. Must be unique. If unset,
     * the server will generate a value.
     */
    @field(2)
    token?: string;

    /**
     * An optional SPIFFE ID to assign to the agent beyond that given by
     * join token attestation. If set, this results in an entry being created
     * that maps the attestation assigned agent ID to this ID.
     */
    @field(3)
    agent_id?: IyaSts.Spiffe.SpireTypes.SPIFFEID;
  }

  @message("spire.api.server.agent.v1.AgentX509SVIDParams")
  model AgentX509SVIDParams {
    /**
     * Required. The ASN.1 DER encoded Certificate Signing Request (CSR). The
     * CSR is only used to convey the public key; other fields in the CSR are
     * ignored. The agent X509-SVID attributes are determined by the server.
     */
    @refuse(#{
      when: "empty",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0053",
      method: "AttestAgent",
      message: "AttestAgent needs a certificate signing request in params.params.csr: the agent keeps its own private key, so there is nothing to issue against without one.",
      cite: "SPIRE Server API, agent.proto AttestAgent"
    })
    @refuse(#{
      when: "empty",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0053",
      method: "RenewAgent",
      message: "RenewAgent needs a certificate signing request in params.csr.",
      cite: "SPIRE Server API, agent.proto RenewAgent"
    })
    @field(1)
    csr?: bytes;
  }

  @message("spire.api.server.agent.v1.PostStatusRequest")
  model PostStatusRequest {
    /**
     * Required. Serial number of the bundle currently being served by the agent
     */
    @field(1)
    current_bundle_serial?: uint64;

    /**
     * Optional. The version of the agent.
     */
    @field(2)
    agent_version?: string;
  }

  @message("spire.api.server.agent.v1.PostStatusResponse")
  model PostStatusResponse {}
}

namespace IyaSts.Spiffe.Server.Bundle {
  @grpcService(#{
    name: "spire.api.server.bundle.v1.Bundle",
    surface: "server",
    statuses: #["UNAUTHENTICATED", "PERMISSION_DENIED", "UNAVAILABLE", "UNKNOWN", "INTERNAL"],
    cite: "SPIRE Server API, bundle.proto; pkg/server/authpolicy/policy_data.json"
  })
  interface Bundle {
    /**
     * Count bundles.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    CountBundles(request: CountBundlesRequest): CountBundlesResponse;

    /**
     * Gets the bundle for the trust domain of the server.
     *
     * The RPC does not require authentication.
     */
    @rpc(#{ stream: "unary" })
    GetBundle(request: GetBundleRequest): IyaSts.Spiffe.SpireTypes.Bundle;

    /**
     * Append to the bundle. Items specified in the bundle in the request are
     * appended to the existing bundle. If the bundle does not exist, NOT_FOUND
     * is returned. This is the only RPC that can be used to update the
     * bundle for the trust domain of the SPIRE server.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["PERMISSION_DENIED"],
      unimplemented: "It would publish an authority this server holds no key for, which every workload in the trust domain would then trust. Rotate instead."
    })
    AppendBundle(request: AppendBundleRequest): IyaSts.Spiffe.SpireTypes.Bundle;

    /**
     * Publishes a downstream JWT authority to the SPIRE server. If the server
     * is itself a downstream server (i.e. configured with an UpstreamAuthority
     * plugin), the JWT authority is published further upstream using the
     * UpstreamAuthority plugin. If the server is not a downstream server, or
     * if the UpstreamAuthority does not support publishing JWT authorities,
     * the server appends the JWT authority to its own bundle.
     *
     * The caller must present a downstream X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["PERMISSION_DENIED"],
      unimplemented: "The same reason as AppendBundle."
    })
    PublishJWTAuthority(request: PublishJWTAuthorityRequest): PublishJWTAuthorityResponse;

    /**
     * Publishes a downstream WIT authority to the SPIRE server. If the server
     * is itself a downstream server (i.e. configured with an UpstreamAuthority
     * plugin), the WIT authority is published further upstream using the
     * UpstreamAuthority plugin. If the server is not a downstream server, or
     * if the UpstreamAuthority does not support publishing WIT authorities,
     * the server appends the WIT authority to its own bundle.
     *
     * The caller must present a downstream X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["UNIMPLEMENTED"],
      unimplemented: "This service issues no WIT-SVIDs."
    })
    PublishWITAuthority(request: PublishWITAuthorityRequest): PublishWITAuthorityResponse;

    /**
     * Lists federated bundles.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    ListFederatedBundles(request: ListFederatedBundlesRequest): ListFederatedBundlesResponse;

    /**
     * Gets a federated bundle. If the bundle does not exist, NOT_FOUND is returned.
     *
     * The caller must be local or present an admin or an active agent X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["NOT_FOUND"]
    })
    GetFederatedBundle(request: GetFederatedBundleRequest): IyaSts.Spiffe.SpireTypes.Bundle;

    /**
     * Batch creates one or more federated bundles.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    BatchCreateFederatedBundle(request: BatchCreateFederatedBundleRequest): BatchCreateFederatedBundleResponse;

    /**
     * Batch updates one or more federated bundles.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    BatchUpdateFederatedBundle(request: BatchUpdateFederatedBundleRequest): BatchUpdateFederatedBundleResponse;

    /**
     * Batch upserts one or more federated bundles.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    BatchSetFederatedBundle(request: BatchSetFederatedBundleRequest): BatchSetFederatedBundleResponse;

    /**
     * Batch deletes one or more federated bundles.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    BatchDeleteFederatedBundle(request: BatchDeleteFederatedBundleRequest): BatchDeleteFederatedBundleResponse;
  }

  @message("spire.api.server.bundle.v1.CountBundlesRequest")
  model CountBundlesRequest {}

  @message("spire.api.server.bundle.v1.CountBundlesResponse")
  model CountBundlesResponse {
    /**
     * The total number of bundles, including the server bundle.
     */
    @field(1)
    count?: int32;
  }

  @message("spire.api.server.bundle.v1.GetBundleRequest")
  model GetBundleRequest {
    /**
     * An output mask indicating which bundle fields are set in the response.
     */
    @field(1)
    output_mask?: IyaSts.Spiffe.SpireTypes.BundleMask;
  }

  @message("spire.api.server.bundle.v1.AppendBundleRequest")
  model AppendBundleRequest {
    /**
     * X.509 authorities to append.
     */
    @field(1)
    x509_authorities?: IyaSts.Spiffe.SpireTypes.X509Certificate[];

    /**
     * JWT authorities to append.
     */
    @field(2)
    jwt_authorities?: IyaSts.Spiffe.SpireTypes.JWTKey[];

    /**
     * An output mask indicating which bundle fields are set in the response.
     */
    @field(3)
    output_mask?: IyaSts.Spiffe.SpireTypes.BundleMask;

    /**
     * WIT authorities to append.
     */
    @field(4)
    wit_authorities?: IyaSts.Spiffe.SpireTypes.WITKey[];
  }

  @message("spire.api.server.bundle.v1.PublishJWTAuthorityRequest")
  model PublishJWTAuthorityRequest {
    /**
     * Required. The JWT authority to publish.
     */
    @field(1)
    jwt_authority?: IyaSts.Spiffe.SpireTypes.JWTKey;
  }

  @message("spire.api.server.bundle.v1.PublishJWTAuthorityResponse")
  model PublishJWTAuthorityResponse {
    /**
     * The JWT authorities for the trust domain.
     */
    @field(1)
    jwt_authorities?: IyaSts.Spiffe.SpireTypes.JWTKey[];
  }

  @message("spire.api.server.bundle.v1.PublishWITAuthorityRequest")
  model PublishWITAuthorityRequest {
    /**
     * Required. The WIT authority to publish.
     */
    @field(1)
    wit_authority?: IyaSts.Spiffe.SpireTypes.WITKey;
  }

  @message("spire.api.server.bundle.v1.PublishWITAuthorityResponse")
  model PublishWITAuthorityResponse {
    /**
     * The WIT authorities for the trust domain.
     */
    @field(1)
    wit_authorities?: IyaSts.Spiffe.SpireTypes.WITKey[];
  }

  @message("spire.api.server.bundle.v1.ListFederatedBundlesRequest")
  model ListFederatedBundlesRequest {
    /**
     * An output mask indicating which bundle fields are set in the response.
     */
    @field(1)
    output_mask?: IyaSts.Spiffe.SpireTypes.BundleMask;

    /**
     * The maximum number of results to return. The server may further
     * constrain this value, or if zero, choose its own.
     */
    @field(2)
    page_size?: int32;

    /**
     * The next_page_token value returned from a previous request, if any.
     */
    @field(3)
    page_token?: string;
  }

  @message("spire.api.server.bundle.v1.ListFederatedBundlesResponse")
  model ListFederatedBundlesResponse {
    /**
     * The bundles.
     */
    @field(1)
    bundles?: IyaSts.Spiffe.SpireTypes.Bundle[];

    /**
     * The page token for the next request. Empty if there are no more results.
     * This field should be checked by clients even when a page_size was not
     * requested, since the server may choose its own (see page_size).
     */
    @field(2)
    next_page_token?: string;
  }

  @message("spire.api.server.bundle.v1.GetFederatedBundleRequest")
  model GetFederatedBundleRequest {
    /**
     * Required. The trust domain name of the bundle (e.g., "example.org").
     */
    @field(1)
    trust_domain?: string;

    /**
     * An output mask indicating which bundle fields are set in the response.
     */
    @field(2)
    output_mask?: IyaSts.Spiffe.SpireTypes.BundleMask;
  }

  @message("spire.api.server.bundle.v1.BatchCreateFederatedBundleRequest")
  model BatchCreateFederatedBundleRequest {
    /**
     * The bundles to be created.
     */
    @field(1)
    bundle?: IyaSts.Spiffe.SpireTypes.Bundle[];

    /**
     * An output mask indicating which bundle fields are set in the response.
     */
    @field(2)
    output_mask?: IyaSts.Spiffe.SpireTypes.BundleMask;
  }

  @message("spire.api.server.bundle.v1.BatchCreateFederatedBundleResponse")
  model BatchCreateFederatedBundleResponse {
    /**
     * Result for each bundle in the request (order is maintained).
     */
    @field(1)
    results?: BatchCreateFederatedBundleResponse_Result[];
  }

  @message("spire.api.server.bundle.v1.BatchCreateFederatedBundleResponse.Result")
  model BatchCreateFederatedBundleResponse_Result {
    /**
     * The status of creating the bundle.
     */
    @field(1)
    status?: IyaSts.Spiffe.SpireTypes.Status;

    /**
     * The bundle that was created. This will be set if the status is OK.
     */
    @field(2)
    bundle?: IyaSts.Spiffe.SpireTypes.Bundle;
  }

  @message("spire.api.server.bundle.v1.BatchUpdateFederatedBundleRequest")
  model BatchUpdateFederatedBundleRequest {
    /**
     * The bundles to be updated.
     */
    @field(1)
    bundle?: IyaSts.Spiffe.SpireTypes.Bundle[];

    /**
     * An input mask indicating which bundle fields should be updated.
     */
    @field(2)
    input_mask?: IyaSts.Spiffe.SpireTypes.BundleMask;

    /**
     * An output mask indicating which bundle fields are set in the response.
     */
    @field(3)
    output_mask?: IyaSts.Spiffe.SpireTypes.BundleMask;
  }

  @message("spire.api.server.bundle.v1.BatchUpdateFederatedBundleResponse")
  model BatchUpdateFederatedBundleResponse {
    /**
     * Result for each bundle in the request (order is maintained).
     */
    @field(1)
    results?: BatchUpdateFederatedBundleResponse_Result[];
  }

  @message("spire.api.server.bundle.v1.BatchUpdateFederatedBundleResponse.Result")
  model BatchUpdateFederatedBundleResponse_Result {
    /**
     * The status of updating the bundle.
     */
    @field(1)
    status?: IyaSts.Spiffe.SpireTypes.Status;

    /**
     * The bundle that was updated. This will be set if the status is OK.
     */
    @field(2)
    bundle?: IyaSts.Spiffe.SpireTypes.Bundle;
  }

  @message("spire.api.server.bundle.v1.BatchSetFederatedBundleRequest")
  model BatchSetFederatedBundleRequest {
    /**
     * The bundles to be upserted.
     */
    @field(1)
    bundle?: IyaSts.Spiffe.SpireTypes.Bundle[];

    /**
     * An output mask indicating which bundle fields are set in the response.
     */
    @field(2)
    output_mask?: IyaSts.Spiffe.SpireTypes.BundleMask;
  }

  @message("spire.api.server.bundle.v1.BatchSetFederatedBundleResponse")
  model BatchSetFederatedBundleResponse {
    /**
     * Result for each bundle in the request (order is maintained).
     */
    @field(1)
    results?: BatchSetFederatedBundleResponse_Result[];
  }

  @message("spire.api.server.bundle.v1.BatchSetFederatedBundleResponse.Result")
  model BatchSetFederatedBundleResponse_Result {
    /**
     * The status of upserting the bundle.
     */
    @field(1)
    status?: IyaSts.Spiffe.SpireTypes.Status;

    /**
     * The bundle that was upserted. This will be set if the status is OK.
     */
    @field(2)
    bundle?: IyaSts.Spiffe.SpireTypes.Bundle;
  }

  @message("spire.api.server.bundle.v1.BatchDeleteFederatedBundleRequest")
  model BatchDeleteFederatedBundleRequest {
    /**
     * The trust domain names (e.g., "example.org") of the bundles to delete.
     */
    @field(1)
    trust_domains?: string[];

    /**
     * The deletion mode selected
     */
    @field(2)
    mode?: BatchDeleteFederatedBundleRequest_Mode;
  }

  /**
   * Mode controls the delete behavior if there are other records
   * associated with the bundle (e.g. registration entries).
   */
  @protoEnum("spire.api.server.bundle.v1.BatchDeleteFederatedBundleRequest.Mode")
  enum BatchDeleteFederatedBundleRequest_Mode {
    /**
     * RESTRICT prevents the bundle from being deleted in the presence of associated entries
     */
    RESTRICT: 0,
    /**
     * DELETE deletes the bundle and associated entries
     */
    DELETE: 1,
    /**
     * DISSOCIATE deletes the bundle and dissociates associated entries
     */
    DISSOCIATE: 2
  }

  @message("spire.api.server.bundle.v1.BatchDeleteFederatedBundleResponse")
  model BatchDeleteFederatedBundleResponse {
    /**
     * Result for each trust domain name in the request (order is maintained).
     */
    @field(1)
    results?: BatchDeleteFederatedBundleResponse_Result[];
  }

  @message("spire.api.server.bundle.v1.BatchDeleteFederatedBundleResponse.Result")
  model BatchDeleteFederatedBundleResponse_Result {
    /**
     * The status of deleting the bundle.
     */
    @field(1)
    status?: IyaSts.Spiffe.SpireTypes.Status;

    /**
     * The trust domain name (e.g., "example.org") of the bundle that was
     * deleted.
     */
    @field(2)
    trust_domain?: string;
  }
}

namespace IyaSts.Spiffe.Server.Svid {
  @grpcService(#{
    name: "spire.api.server.svid.v1.SVID",
    surface: "server",
    statuses: #["UNAUTHENTICATED", "PERMISSION_DENIED", "UNAVAILABLE", "UNKNOWN", "INTERNAL"],
    cite: "SPIRE Server API, svid.proto; pkg/server/authpolicy/policy_data.json"
  })
  interface SVID {
    /**
     * Mints a one-off X509-SVID outside of the normal node/workload
     * registration process.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["INVALID_ARGUMENT"]
    })
    MintX509SVID(request: MintX509SVIDRequest): MintX509SVIDResponse;

    /**
     * Mints a one-off JWT-SVID outside of the normal node/workload
     * registration process.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["INVALID_ARGUMENT"]
    })
    MintJWTSVID(request: MintJWTSVIDRequest): MintJWTSVIDResponse;

    /**
     * Mints a one-off WIT-SVID outside of the normal node/workload
     * registration process.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["INVALID_ARGUMENT", "NOT_FOUND", "PERMISSION_DENIED", "UNIMPLEMENTED"],
      unimplemented: "This service issues no WIT-SVIDs."
    })
    MintWITSVID(request: MintWITSVIDRequest): MintWITSVIDResponse;

    /**
     * Creates one or more X509-SVIDs from registration entries.
     *
     * The caller must present an active agent X509-SVID that is authorized
     * to mint the requested entries. See the Entry GetAuthorizedEntries RPC.
     */
    @rpc(#{ stream: "unary" })
    BatchNewX509SVID(request: BatchNewX509SVIDRequest): BatchNewX509SVIDResponse;

    /**
     * Creates an JWT-SVID from a registration entry.
     *
     * The caller must present an active agent X509-SVID that is authorized
     * to mint the requested entry. See the Entry GetAuthorizedEntries RPC.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["INVALID_ARGUMENT", "NOT_FOUND", "PERMISSION_DENIED"]
    })
    NewJWTSVID(request: NewJWTSVIDRequest): NewJWTSVIDResponse;

    /**
     * Creates one or more WIT-SVIDs from registration entries.
     *
     * The caller must present an active agent X509-SVID that is authorized
     * to mint the requested entries. See the Entry GetAuthorizedEntries/SyncA RPC.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["INVALID_ARGUMENT", "UNIMPLEMENTED"],
      unimplemented: "This service issues no WIT-SVIDs."
    })
    BatchNewWITSVID(request: BatchNewWITSVIDRequest): BatchNewWITSVIDResponse;

    /**
     * Creates an X509 CA certificate appropriate for use by a downstream
     * entity to mint X509-SVIDs.
     *
     * The caller must present a downstream X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    NewDownstreamX509CA(request: NewDownstreamX509CARequest): NewDownstreamX509CAResponse;
  }

  @message("spire.api.server.svid.v1.MintX509SVIDRequest")
  model MintX509SVIDRequest {
    /**
     * Required. ASN.1 DER encoded CSR. The CSR is used to convey the public
     * key and the SPIFFE ID (via the URI SAN). Only one URI SAN can be set.
     * Optionally, the subject and any number of DNS SANs can also be set.
     */
    @refuse(#{
      when: "empty",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0053",
      message: "MintX509SVID takes a certificate signing request; the SPIFFE ID is read from its URI subjectAltName.",
      cite: "SPIRE Server API, svid.proto MintX509SVID"
    })
    @field(1)
    csr?: bytes;

    /**
     * The desired TTL of the X509-SVID, in seconds. The server default will be
     * used if unset. The TTL is advisory only. The actual lifetime of the
     * X509-SVID may be lower depending on the remaining lifetime of the active
     * SPIRE Server CA.
     */
    @field(2)
    ttl?: int32;
  }

  @message("spire.api.server.svid.v1.MintX509SVIDResponse")
  model MintX509SVIDResponse {
    /**
     * The newly issued X509-SVID.
     */
    @field(1)
    svid?: IyaSts.Spiffe.SpireTypes.X509SVID;
  }

  @message("spire.api.server.svid.v1.MintWITSVIDRequest")
  model MintWITSVIDRequest {
    /**
     * Required. SPIFFE ID of the WIT-SVID.
     */
    @field(1)
    id?: IyaSts.Spiffe.SpireTypes.SPIFFEID;

    /**
     * Required. The ASN.1 DER encoded public key.
     */
    @field(2)
    public_key?: bytes;

    /**
     * Desired TTL of the WIT-SVID, in seconds. The server default will be used
     * if unset. The TTL is advisory only. The actual lifetime of the WIT-SVID
     * may be lower depending on the remaining lifetime of the active SPIRE
     * Server CA.
     */
    @field(3)
    ttl?: int32;

    /**
     * Required. The signing algorithm to specify in the key. This must be one
     * of the values supported by the WIT-SVID specification.
     */
    @field(4)
    signing_algorithm?: string;
  }

  @message("spire.api.server.svid.v1.MintWITSVIDResponse")
  model MintWITSVIDResponse {
    /**
     * The newly issued WIT-SVID.
     */
    @field(1)
    svid?: IyaSts.Spiffe.SpireTypes.WITSVID;
  }

  @message("spire.api.server.svid.v1.MintJWTSVIDRequest")
  model MintJWTSVIDRequest {
    /**
     * Required. SPIFFE ID of the JWT-SVID.
     */
    @refuse(#{
      when: "empty",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0065",
      message: "MintJWTSVID needs the SPIFFE ID to mint for, as a trust_domain and a path.",
      cite: "SPIRE Server API, svid.proto MintJWTSVID"
    })
    @field(1)
    id?: IyaSts.Spiffe.SpireTypes.SPIFFEID;

    /**
     * Required. List of audience claims to include in the JWT-SVID. At least one must
     * be set.
     */
    @refuse(#{
      when: "empty",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0027",
      message: "MintJWTSVID requires at least one audience: a JWT-SVID is a bearer credential, and the audience is what stops one being replayed against a different service.",
      cite: "SPIRE Server API, svid.proto MintJWTSVID; JWT-SVID section 3"
    })
    @field(2)
    audience?: string[];

    /**
     * Desired TTL of the JWT-SVID, in seconds. The server default will be used
     * if unset. The TTL is advisory only. The actual lifetime of the JWT-SVID
     * may be lower depending on the remaining lifetime of the active SPIRE
     * Server CA.
     */
    @field(3)
    ttl?: int32;
  }

  @message("spire.api.server.svid.v1.MintJWTSVIDResponse")
  model MintJWTSVIDResponse {
    /**
     * The newly issued JWT-SVID.
     */
    @field(1)
    svid?: IyaSts.Spiffe.SpireTypes.JWTSVID;
  }

  @message("spire.api.server.svid.v1.BatchNewX509SVIDRequest")
  model BatchNewX509SVIDRequest {
    /**
     * Required. One or more X509-SVID parameters for X509-SVID entries to
     * be signed.
     */
    @field(1)
    params?: NewX509SVIDParams[];
  }

  @message("spire.api.server.svid.v1.BatchNewX509SVIDResponse")
  model BatchNewX509SVIDResponse {
    /**
     * Result for each X509-SVID requested (order is maintained).
     */
    @field(1)
    results?: BatchNewX509SVIDResponse_Result[];
  }

  @message("spire.api.server.svid.v1.BatchNewX509SVIDResponse.Result")
  model BatchNewX509SVIDResponse_Result {
    /**
     * The status of creating the X509-SVID.
     */
    @field(1)
    status?: IyaSts.Spiffe.SpireTypes.Status;

    /**
     * The newly created X509-SVID. This will be set if the status is OK.
     */
    @field(2)
    svid?: IyaSts.Spiffe.SpireTypes.X509SVID;
  }

  @message("spire.api.server.svid.v1.NewJWTSVIDRequest")
  model NewJWTSVIDRequest {
    /**
     * Required. The entry ID of the identity being requested.
     */
    @field(1)
    entry_id?: string;

    /**
     * Required. List of audience claims to include in the JWT-SVID. At least
     * one must be set.
     */
    @refuse(#{
      when: "empty",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0027",
      message: "NewJWTSVID requires at least one audience.",
      cite: "SPIRE Server API, svid.proto NewJWTSVID; JWT-SVID section 3"
    })
    @field(2)
    audience?: string[];
  }

  @message("spire.api.server.svid.v1.BatchNewWITSVIDRequest")
  model BatchNewWITSVIDRequest {
    /**
     * Required. One or more WIT-SVID parameters for WIT-SVID entries to
     * be signed.
     */
    @field(1)
    params?: NewWITSVIDParams[];
  }

  @message("spire.api.server.svid.v1.BatchNewWITSVIDResponse")
  model BatchNewWITSVIDResponse {
    /**
     * Result for each WIT-SVID requested (order is maintained).
     */
    @field(1)
    results?: BatchNewWITSVIDResponse_Result[];
  }

  @message("spire.api.server.svid.v1.BatchNewWITSVIDResponse.Result")
  model BatchNewWITSVIDResponse_Result {
    /**
     * The status of creating the WIT-SVID.
     */
    @field(1)
    status?: IyaSts.Spiffe.SpireTypes.Status;

    /**
     * The newly created WIT-SVID. This will be set if the status is OK.
     */
    @field(2)
    svid?: IyaSts.Spiffe.SpireTypes.WITSVID;
  }

  @message("spire.api.server.svid.v1.NewJWTSVIDResponse")
  model NewJWTSVIDResponse {
    /**
     * The newly issued JWT-SVID
     */
    @field(1)
    svid?: IyaSts.Spiffe.SpireTypes.JWTSVID;
  }

  @message("spire.api.server.svid.v1.NewDownstreamX509CARequest")
  model NewDownstreamX509CARequest {
    /**
     * Required. The ASN.1 DER encoded Certificate Signing Request (CSR). The
     * CSR is only used to convey the public key; other fields in the CSR are
     * ignored. The X509-SVID attributes are determined by the downstream entry.
     */
    @field(1)
    csr?: bytes;

    /**
     * Optional. The TTL preferred by the downstream SPIRE Server for the
     * signed intermediate CA. If zero, the upstream SPIRE Server will use its
     * own default.
     */
    @field(2)
    preferred_ttl?: int32;
  }

  @message("spire.api.server.svid.v1.NewDownstreamX509CAResponse")
  model NewDownstreamX509CAResponse {
    /**
     * CA certificate and any intermediates required to form a chain of trust
     * back to the X.509 authorities (DER encoded). The CA certificate is the
     * first.
     */
    @field(1)
    ca_cert_chain?: bytes[];

    /**
     * X.509 authorities (DER encoded).
     */
    @field(2)
    x509_authorities?: bytes[];
  }

  @message("spire.api.server.svid.v1.NewX509SVIDParams")
  model NewX509SVIDParams {
    /**
     * Required. The entry ID for the identity being requested.
     */
    @field(1)
    entry_id?: string;

    /**
     * Required. The ASN.1 DER encoded Certificate Signing Request (CSR). The
     * CSR is only used to convey the public key; other fields in the CSR are
     * ignored. The X509-SVID attributes are determined by the entry.
     */
    @field(2)
    csr?: bytes;
  }

  @message("spire.api.server.svid.v1.NewWITSVIDParams")
  model NewWITSVIDParams {
    /**
     * Required. The entry ID for the identity being requested.
     */
    @field(1)
    entry_id?: string;

    /**
     * Required. The ASN.1 DER encoded public key.
     */
    @field(2)
    public_key?: bytes;

    /**
     * Required. The signing algorithm to specify in the key. This must be one
     * of the values supported by the WIT-SVID specification.
     */
    @field(3)
    signing_algorithm?: string;
  }
}

namespace IyaSts.Spiffe.Server.Trustdomain {
  /**
   * Manages the federation relationships with foreign trust domains.
   */
  @grpcService(#{
    name: "spire.api.server.trustdomain.v1.TrustDomain",
    surface: "server",
    statuses: #["UNAUTHENTICATED", "PERMISSION_DENIED", "UNAVAILABLE", "UNKNOWN", "INTERNAL"],
    cite: "SPIRE Server API, trustdomain.proto; pkg/server/authpolicy/policy_data.json"
  })
  interface TrustDomain {
    /**
     * Lists federation relationships with foreign trust domains.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    ListFederationRelationships(request: ListFederationRelationshipsRequest): ListFederationRelationshipsResponse;

    /**
     * Gets a federation relationship with a foreign trust domain.
     * If there is no federation relationship with the specified
     * trust domain, NOT_FOUND is returned.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["NOT_FOUND"]
    })
    GetFederationRelationship(request: GetFederationRelationshipRequest): IyaSts.Spiffe.SpireTypes.FederationRelationship;

    /**
     * Batch creates one or more federation relationships with
     * foreign trust domains.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    BatchCreateFederationRelationship(request: BatchCreateFederationRelationshipRequest): BatchCreateFederationRelationshipResponse;

    /**
     * Batch updates one or more federation relationships with
     * foreign trust domains.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    BatchUpdateFederationRelationship(request: BatchUpdateFederationRelationshipRequest): BatchUpdateFederationRelationshipResponse;

    /**
     * Batch deletes federation relationships with foreign trust domains.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{ stream: "unary" })
    BatchDeleteFederationRelationship(request: BatchDeleteFederationRelationshipRequest): BatchDeleteFederationRelationshipResponse;

    /**
     * Refreshes the bundle from the specified federated trust domain.
     * If there is not a federation relationship configured with the
     * specified trust domain, NOT_FOUND is returned.
     *
     * The caller must be local or present an admin X509-SVID.
     */
    @rpc(#{
      stream: "unary",
      statuses: #["NOT_FOUND", "UNIMPLEMENTED"],
      unimplemented: "This service records a bundle endpoint URL and never fetches it — the same refusal it gives wreqptr and jwks_uri. Push the bundle in instead."
    })
    RefreshBundle(request: RefreshBundleRequest): IyaSts.Spiffe.Google.Empty;
  }

  @message("spire.api.server.trustdomain.v1.ListFederationRelationshipsRequest")
  model ListFederationRelationshipsRequest {
    /**
     * An output mask indicating which federation replationship fields
     * are set in the response.
     */
    @field(1)
    output_mask?: IyaSts.Spiffe.SpireTypes.FederationRelationshipMask;

    /**
     * The maximum number of results to return. The server may further
     * constrain this value, or if zero, choose its own.
     */
    @field(2)
    page_size?: int32;

    /**
     * The next_page_token value returned from a previous request, if any.
     */
    @field(3)
    page_token?: string;
  }

  @message("spire.api.server.trustdomain.v1.ListFederationRelationshipsResponse")
  model ListFederationRelationshipsResponse {
    /**
     * The federation relationships with foreign trust domains.
     */
    @field(1)
    federation_relationships?: IyaSts.Spiffe.SpireTypes.FederationRelationship[];

    /**
     * The page token for the next request. Empty if there are no more results.
     * This field should be checked by clients even when a page_size was not
     * requested, since the server may choose its own (see page_size).
     */
    @field(2)
    next_page_token?: string;
  }

  @message("spire.api.server.trustdomain.v1.GetFederationRelationshipRequest")
  model GetFederationRelationshipRequest {
    /**
     * Required. The trust domain name of the federation relationship
     * (e.g., "example.org").
     */
    @field(1)
    trust_domain?: string;

    /**
     * An output mask indicating which federation relationship fields
     * are set in the response.
     */
    @field(2)
    output_mask?: IyaSts.Spiffe.SpireTypes.FederationRelationshipMask;
  }

  @message("spire.api.server.trustdomain.v1.BatchCreateFederationRelationshipRequest")
  model BatchCreateFederationRelationshipRequest {
    /**
     * The federation relationships to be created.
     */
    @field(1)
    federation_relationships?: IyaSts.Spiffe.SpireTypes.FederationRelationship[];

    /**
     * An output mask indicating the federation relationship fields set in the response.
     */
    @field(2)
    output_mask?: IyaSts.Spiffe.SpireTypes.FederationRelationshipMask;
  }

  @message("spire.api.server.trustdomain.v1.BatchCreateFederationRelationshipResponse")
  model BatchCreateFederationRelationshipResponse {
    /**
     * Result for each federation relationship in the request (order is maintained).
     */
    @field(1)
    results?: BatchCreateFederationRelationshipResponse_Result[];
  }

  @message("spire.api.server.trustdomain.v1.BatchCreateFederationRelationshipResponse.Result")
  model BatchCreateFederationRelationshipResponse_Result {
    /**
     * The status of creating the federation relationship.
     * Status code will be ALREADY_EXISTS if there is already a
     * federation relationship with the specified trust domain.
     */
    @field(1)
    status?: IyaSts.Spiffe.SpireTypes.Status;

    /**
     * The federation relationship that was created.
     * This will be set if the status is OK.
     */
    @field(2)
    federation_relationship?: IyaSts.Spiffe.SpireTypes.FederationRelationship;
  }

  @message("spire.api.server.trustdomain.v1.BatchUpdateFederationRelationshipRequest")
  model BatchUpdateFederationRelationshipRequest {
    /**
     * The federation relationships to be updated.
     */
    @field(1)
    federation_relationships?: IyaSts.Spiffe.SpireTypes.FederationRelationship[];

    /**
     * An input mask indicating what federation relationship fields should be updated.
     */
    @field(2)
    input_mask?: IyaSts.Spiffe.SpireTypes.FederationRelationshipMask;

    /**
     * An output mask indicating what federation relationship fields are set in the response.
     */
    @field(3)
    output_mask?: IyaSts.Spiffe.SpireTypes.FederationRelationshipMask;
  }

  @message("spire.api.server.trustdomain.v1.BatchUpdateFederationRelationshipResponse")
  model BatchUpdateFederationRelationshipResponse {
    /**
     * Result for each federation relationship in the request (order is maintained).
     */
    @field(1)
    results?: BatchUpdateFederationRelationshipResponse_Result[];
  }

  @message("spire.api.server.trustdomain.v1.BatchUpdateFederationRelationshipResponse.Result")
  model BatchUpdateFederationRelationshipResponse_Result {
    /**
     * The status of updating the federation relationship.
     */
    @field(1)
    status?: IyaSts.Spiffe.SpireTypes.Status;

    /**
     * The federation relationship that was updated.
     * This will be set if the status is OK.
     */
    @field(2)
    federation_relationship?: IyaSts.Spiffe.SpireTypes.FederationRelationship;
  }

  @message("spire.api.server.trustdomain.v1.BatchDeleteFederationRelationshipRequest")
  model BatchDeleteFederationRelationshipRequest {
    /**
     * Required. The trust domain names of the federation relationships
     * to delete.
     */
    @field(1)
    trust_domains?: string[];
  }

  @message("spire.api.server.trustdomain.v1.BatchDeleteFederationRelationshipResponse")
  model BatchDeleteFederationRelationshipResponse {
    /**
     * Result for each trust domain name in the request (order is maintained).
     */
    @field(1)
    results?: BatchDeleteFederationRelationshipResponse_Result[];
  }

  @message("spire.api.server.trustdomain.v1.BatchDeleteFederationRelationshipResponse.Result")
  model BatchDeleteFederationRelationshipResponse_Result {
    /**
     * The status of delating the federation relationship.
     */
    @field(1)
    status?: IyaSts.Spiffe.SpireTypes.Status;

    /**
     * The trust domain name of the federation relationship
     * that was deleted.
     */
    @field(2)
    trust_domain?: string;
  }

  @message("spire.api.server.trustdomain.v1.RefreshBundleRequest")
  model RefreshBundleRequest {
    /**
     * Required. The federated trust domain name of the
     * bundle to refresh (e.g., "example.org").
     */
    @field(1)
    trust_domain?: string;
  }
}

namespace IyaSts.Spiffe.Server.Debug {
  @grpcService(#{
    name: "spire.api.server.debug.v1.Debug",
    surface: "server",
    statuses: #["UNAUTHENTICATED", "PERMISSION_DENIED", "UNAVAILABLE", "UNKNOWN", "INTERNAL"],
    cite: "SPIRE Server API, debug.proto; pkg/server/authpolicy/policy_data.json"
  })
  interface Debug {
    /**
     * Get information about SPIRE server
     */
    @rpc(#{ stream: "unary" })
    GetInfo(request: GetInfoRequest): GetInfoResponse;
  }

  @message("spire.api.server.debug.v1.GetInfoRequest")
  model GetInfoRequest {}

  @message("spire.api.server.debug.v1.GetInfoResponse")
  model GetInfoResponse {
    /**
     * Server SVID chain
     */
    @field(1)
    svid_chain?: GetInfoResponse_Cert[];

    /**
     * Server uptime in seconds
     */
    @field(2)
    uptime?: int32;

    /**
     * Amount of registered agents
     */
    @field(3)
    agents_count?: int32;

    /**
     * Amount of federated bundles
     */
    @field(4)
    federated_bundles_count?: int32;

    /**
     * Amount of registration entries on database
     */
    @field(5)
    entries_count?: int32;
  }

  @message("spire.api.server.debug.v1.GetInfoResponse.Cert")
  model GetInfoResponse_Cert {
    /**
     * Certificate SPIFFE ID
     */
    @field(1)
    id?: IyaSts.Spiffe.SpireTypes.SPIFFEID;

    /**
     * Expiration time
     */
    @field(2)
    expires_at?: int64;

    /**
     * Subject
     */
    @field(3)
    subject?: string;
  }
}
