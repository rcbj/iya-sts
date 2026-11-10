// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/spiffe/spire_types.tsp
//
// THE SPIRE API TYPES (#1579): `spire.api.types`, the messages every SPIRE Server API service shares.
//
// Converted once from the vendored `spiffe/protos/spire/api/types/*.proto` by a script that
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
using IyaSts.SpiffeLib;

namespace IyaSts.Spiffe.SpireTypes {
  @message("spire.api.types.Entry")
  model Entry {
    /**
     * Globally unique ID for the entry.
     */
    @field(1)
    id?: string;

    /**
     * The SPIFFE ID of the identity described by this entry.
     */
    @field(2)
    spiffe_id?: SPIFFEID;

    /**
     * Who the entry is delegated to. If the entry describes a node, this is
     * set to the SPIFFE ID of the SPIRE server of the trust domain (e.g.
     * spiffe://example.org/spire/server). Otherwise, it will be set to a node
     * SPIFFE ID.
     */
    @field(3)
    parent_id?: SPIFFEID;

    /**
     * The selectors which identify which entities match this entry. If this is
     * an entry for a node, these selectors represent selectors produced by
     * node attestation. Otherwise, these selectors represent those produced by
     * workload attestation.
     */
    @field(4)
    selectors?: Selector[];

    /**
     * The time to live for X509-SVID identities issued for this entry (in seconds).
     * Previously called ttl
     */
    @field(5)
    x509_svid_ttl?: int32;

    /**
     * The names of trust domains the identity described by this entry
     * federates with.
     */
    @field(6)
    federates_with?: string[];

    /**
     * Whether or not the identity described by this entry is an administrative
     * workload. Administrative workloads are granted additional access to
     * various managerial server APIs, such as entry registration.
     */
    @field(7)
    admin?: boolean;

    /**
     * Whether or not the identity described by this entry represents a
     * downstream SPIRE server. Downstream SPIRE servers have additional access
     * to various signing APIs, such as those used to sign X.509 CA
     * certificates and publish JWT signing keys.
     */
    @field(8)
    downstream?: boolean;

    /**
     * When the entry expires (seconds since Unix epoch).
     */
    @field(9)
    expires_at?: int64;

    /**
     * A list of DNS names associated with the identity described by this entry.
     */
    @field(10)
    dns_names?: string[];

    /**
     * Revision number is bumped every time the entry is updated
     */
    @field(11)
    revision_number?: int64;

    /**
     * Determines if the issued identity is exportable to a store
     */
    @field(12)
    store_svid?: boolean;

    /**
     * The time to live for JWT-SVID identities issued for this entry (in seconds), overrides ttl if set.
     */
    @field(13)
    jwt_svid_ttl?: int32;

    /**
     * An operator-specified string used to provide guidance on how this
     * identity should be used by a workload when more than one SVID is returned.
     */
    @field(14)
    hint?: string;

    /**
     * When the entry was created (seconds since Unix epoch).
     */
    @field(15)
    created_at?: int64;

    @field(16)
    additional_attributes?: Entry_AdditionalAttributes;
  }

  /**
   * This nested message is reserved to contain a number of optional fields
   * controlling the various aspects of the agent's behaviour with respect to a
   * given registration entry. It serves to enable introducing and testing out new
   * tunables, without having to modify the datastore schema. Over time, some of
   * the fields contained therein may be considered eligible for their dedicated
   * attributes in the datastore.
   */
  @message("spire.api.types.Entry.AdditionalAttributes")
  model Entry_AdditionalAttributes {
    /**
     * Flag indicating whether the agent should prefetch and cache X509 SVID.
     * Can be set to `true` if the workload is unlikely to request an X509 SVID.
     * This is meant to prevent unnecessary effort spent on generating SVIDs of types,
     * which are unlikely to be needed.
     */
    @field(1)
    disable_x509_svid_prefetch?: boolean;

    /**
     * Flag indicating whether SPIRE should include a unique JTI (JWT ID) claim
     * in JWT-SVIDs issued for this entry. When set, each JWT-SVID minted for this
     * entry contains a freshly generated UUID in the `jti` claim, and the agent
     * bypasses its JWT-SVID cache so every request yields a new token. This
     * supports use cases that require per-token uniqueness, such as replay
     * protection or auditing.
     */
    @field(2)
    jwt_svid_include_jti?: boolean;
  }

  /**
   * Field mask for Entry fields
   */
  @message("spire.api.types.EntryMask")
  model EntryMask {
    /**
     * spiffe_id field mask
     */
    @field(2)
    spiffe_id?: boolean;

    /**
     * parent_id field mask
     */
    @field(3)
    parent_id?: boolean;

    /**
     * selectors field mask
     */
    @field(4)
    selectors?: boolean;

    /**
     * x509_svid_ttl field mask
     */
    @field(5)
    x509_svid_ttl?: boolean;

    /**
     * federates_with field mask
     */
    @field(6)
    federates_with?: boolean;

    /**
     * admin field mask
     */
    @field(7)
    admin?: boolean;

    /**
     * downstream field mask
     */
    @field(8)
    downstream?: boolean;

    /**
     * expires_at field mask
     */
    @field(9)
    expires_at?: boolean;

    /**
     * dns_names field mask
     */
    @field(10)
    dns_names?: boolean;

    /**
     * revision_number field mask
     */
    @field(11)
    revision_number?: boolean;

    /**
     * store_svid field mask
     */
    @field(12)
    store_svid?: boolean;

    /**
     * jwt_svid_ttl field mask
     */
    @field(13)
    jwt_svid_ttl?: boolean;

    /**
     * hint field mask
     */
    @field(14)
    hint?: boolean;

    /**
     * created_at field mask
     */
    @field(15)
    created_at?: boolean;

    /**
     * additional_attributes field mask
     */
    @field(16)
    additional_attributes?: boolean;
  }

  @message("spire.api.types.Selector")
  model Selector {
    /**
     * The type of the selector. This is typically the name of the plugin that
     * produces the selector.
     */
    @field(1)
    type?: string;

    /**
     * The value of the selector.
     */
    @field(2)
    value?: string;
  }

  @message("spire.api.types.SelectorMatch")
  model SelectorMatch {
    /**
     * The set of selectors to match on.
     */
    @field(1)
    selectors?: Selector[];

    /**
     * How to match the selectors.
     */
    @field(2)
    match?: SelectorMatch_MatchBehavior;
  }

  @protoEnum("spire.api.types.SelectorMatch.MatchBehavior")
  enum SelectorMatch_MatchBehavior {
    /**
     * Indicates that the selectors in this match are equal to the
     * candidate selectors, independent of ordering.
     * Example:
     * Given:
     * - 'e1 { Selectors: ["a:1", "b:2", "c:3"]}'
     * - 'e2 { Selectors: ["a:1", "b:2"]}'
     * - 'e3 { Selectors: ["a:1"]}'
     * Operation:
     * - MATCH_EXACT ["a:1", "b:2"]
     * Entries that match:
     * - 'e2'
     */
    MATCH_EXACT: 0,
    /**
     * Indicates that all candidates which have a non-empty subset
     * of the provided set of selectors will match.
     * Example:
     * Given:
     * - 'e1 { Selectors: ["a:1", "b:2", "c:3"]}'
     * - 'e2 { Selectors: ["a:1", "b:2"]}'
     * - 'e3 { Selectors: ["a:1"]}'
     * Operation:
     * - MATCH_SUBSET ["a:1"]
     * Entries that match:
     * - 'e1'
     */
    MATCH_SUBSET: 1,
    /**
     * Indicates that all candidates which are a superset
     * of the provided selectors will match.
     * Example:
     * Given:
     * - 'e1 { Selectors: ["a:1", "b:2", "c:3"]}'
     * - 'e2 { Selectors: ["a:1", "b:2"]}'
     * - 'e3 { Selectors: ["a:1"]}'
     * Operation:
     * - MATCH_SUPERSET ["a:1", "b:2"]
     * Entries that match:
     * - 'e1'
     * - 'e2'
     */
    MATCH_SUPERSET: 2,
    /**
     * Indicates that all candidates which have at least one
     * of the provided set of selectors will match.
     * Example:
     * Given:
     * - 'e1 { Selectors: ["a:1", "b:2", "c:3"]}'
     * - 'e2 { Selectors: ["a:1", "b:2"]}'
     * - 'e3 { Selectors: ["a:1"]}'
     * Operation:
     * - MATCH_ANY ["a:1"]
     * Entries that match:
     * - 'e1'
     * - 'e2'
     * - 'e3'
     */
    MATCH_ANY: 3
  }

  /**
   * A SPIFFE ID, consisting of the trust domain name and a path portions of
   * the SPIFFE ID URI.
   */
  @message("spire.api.types.SPIFFEID")
  model SPIFFEID {
    /**
     * Trust domain portion the SPIFFE ID (e.g. "example.org")
     */
    @field(1)
    trust_domain?: string;

    /**
     * The path component of the SPIFFE ID (e.g. "/foo/bar/baz"). The path
     * SHOULD have a leading slash. Consumers MUST normalize the path before
     * making any sort of comparison between IDs.
     */
    @field(2)
    path?: string;
  }

  @message("spire.api.types.FederatesWithMatch")
  model FederatesWithMatch {
    /**
     * The set of trust domain names to match on (e.g., "example.org").
     */
    @field(1)
    trust_domains?: string[];

    /**
     * How to match the trust domains.
     */
    @field(2)
    match?: FederatesWithMatch_MatchBehavior;
  }

  @protoEnum("spire.api.types.FederatesWithMatch.MatchBehavior")
  enum FederatesWithMatch_MatchBehavior {
    /**
     * Indicates that the federated trust domains in this match are
     * equal to the candidate trust domains, independent of ordering.
     * Example:
     * Given:
     * - e1 { FederatesWith: ["spiffe://td1", "spiffe://td2", "spiffe://td3"]}
     * - e2 { FederatesWith: ["spiffe://td1", "spiffe://td2"]}
     * - e3 { FederatesWith: ["spiffe://td1"]}
     * Operation:
     * - MATCH_EXACT ["spiffe://td1", "spiffe://td2"]
     * Entries that match:
     * - 'e2'
     */
    MATCH_EXACT: 0,
    /**
     * Indicates that all candidates which have a non-empty subset
     * of the provided set of trust domains will match.
     * Example:
     * Given:
     * - e1 { FederatesWith: ["spiffe://td1", "spiffe://td2", "spiffe://td3"]}
     * - e2 { FederatesWith: ["spiffe://td1", "spiffe://td2"]}
     * - e3 { FederatesWith: ["spiffe://td1"]}
     * Operation:
     * - MATCH_SUBSET ["spiffe://td1"]
     * Entries that match:
     * - 'e1'
     */
    MATCH_SUBSET: 1,
    /**
     * Indicate that all candidates which are a superset
     * of the provided set of trust domains will match.
     * Example:
     * Given:
     * - e1 { FederatesWith: ["spiffe://td1", "spiffe://td2", "spiffe://td3"]}
     * - e2 { FederatesWith: ["spiffe://td1", "spiffe://td2"]}
     * - e3 { FederatesWith: ["spiffe://td1"]}
     * Operation:
     * - MATCH_SUPERSET ["spiffe://td1", "spiffe://td2"]
     * Entries that match:
     * - 'e1'
     * - 'e2'
     */
    MATCH_SUPERSET: 2,
    /**
     * Indicates that all candidates which have at least one
     * of the provided set of trust domains will match.
     * Example:
     * Given:
     * - e1 { FederatesWith: ["spiffe://td1", "spiffe://td2", "spiffe://td3"]}
     * - e2 { FederatesWith: ["spiffe://td1", "spiffe://td2"]}
     * - e3 { FederatesWith: ["spiffe://td1"]}
     * Operation:
     * - MATCH_ANY ["spiffe://td1"]
     * Entries that match:
     * - 'e1'
     * - 'e2'
     * - 'e3'
     */
    MATCH_ANY: 3
  }

  @message("spire.api.types.Status")
  model Status {
    /**
     * A status code, which should be an enum value of google.rpc.Code.
     */
    @field(1)
    code?: int32;

    /**
     * A developer-facing error message.
     */
    @field(2)
    message?: string;
  }

  @message("spire.api.types.PermissionDeniedDetails")
  model PermissionDeniedDetails {
    @field(1)
    reason?: PermissionDeniedDetails_Reason;
  }

  @protoEnum("spire.api.types.PermissionDeniedDetails.Reason")
  enum PermissionDeniedDetails_Reason {
    /**
     * Reason unknown.
     */
    UNKNOWN: 0,
    /**
     * Agent identity has expired.
     */
    AGENT_EXPIRED: 1,
    /**
     * Identity is not an attested agent.
     */
    AGENT_NOT_ATTESTED: 2,
    /**
     * Identity is not the active agent identity.
     */
    AGENT_NOT_ACTIVE: 3,
    /**
     * Agent has been banned.
     */
    AGENT_BANNED: 4,
    /**
     * Agent attempted to renew SVID, but should reattest instead
     */
    AGENT_MUST_REATTEST: 5
  }

  @message("spire.api.types.Agent")
  model Agent {
    /**
     * Output only. SPIFFE ID of the agent.
     */
    @field(1)
    id?: SPIFFEID;

    /**
     * Output only. The method by which the agent attested.
     */
    @field(2)
    attestation_type?: string;

    /**
     * Output only. The X509-SVID serial number.
     */
    @field(3)
    x509svid_serial_number?: string;

    /**
     * Output only. The X509-SVID expiration (seconds since Unix epoch).
     */
    @field(4)
    x509svid_expires_at?: int64;

    /**
     * Output only. The selectors attributed to the agent during attestation.
     */
    @field(5)
    selectors?: Selector[];

    /**
     * Output only. Whether or not the agent is banned.
     */
    @field(6)
    banned?: boolean;

    /**
     * Output only. Whether or not the agent can re-attest.
     */
    @field(7)
    can_reattest?: boolean;

    /**
     * Output only. Optional. The version of the agent.
     */
    @field(8)
    agent_version?: string;
  }

  @message("spire.api.types.AgentMask")
  model AgentMask {
    /**
     * attestation_type field mask
     */
    @field(2)
    attestation_type?: boolean;

    /**
     * x509svid_serial_number field mask
     */
    @field(3)
    x509svid_serial_number?: boolean;

    /**
     * x509svid_expires_at field mask
     */
    @field(4)
    x509svid_expires_at?: boolean;

    /**
     * selectors field mask
     */
    @field(5)
    selectors?: boolean;

    /**
     * banned field mask
     */
    @field(6)
    banned?: boolean;

    /**
     * can_reattest field mask
     */
    @field(7)
    can_reattest?: boolean;

    /**
     * agent_version field mask
     */
    @field(8)
    agent_version?: boolean;
  }

  @message("spire.api.types.AttestationData")
  model AttestationData {
    /**
     * The type of attestation data. This is typically the name of the plugin
     * that produced that data.
     */
    @refuse(#{
      when: "empty",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0079",
      message: "AttestAgent names its attestor in params.data.type, and this one is empty.",
      cite: "SPIRE Server API, agent.proto AttestAgent"
    })
    @field(1)
    type?: string;

    /**
     * The attestation data payload.
     */
    @field(2)
    payload?: bytes;
  }

  @message("spire.api.types.JoinToken")
  model JoinToken {
    /**
     * The value of the token.
     */
    @field(1)
    value?: string;

    /**
     * The token expiration (seconds since Unix epoch).
     */
    @field(2)
    expires_at?: int64;
  }

  /**
   * X.509 SPIFFE Verifiable Identity Document. It contains the raw X.509
   * certificate data as well as a few denormalized fields for convenience.
   */
  @message("spire.api.types.X509SVID")
  model X509SVID {
    /**
     * Certificate and intermediates required to form a chain of trust back to
     * the X.509 authorities of the trust domain (ASN.1 DER encoded).
     */
    @field(1)
    cert_chain?: bytes[];

    /**
     * SPIFFE ID of the SVID.
     */
    @field(2)
    id?: SPIFFEID;

    /**
     * Expiration timestamp (seconds since Unix epoch).
     */
    @field(3)
    expires_at?: int64;

    /**
     * Optional. An operator-specified string used to provide guidance on how this
     * identity should be used by a workload when more than one SVID is returned.
     * For example, `internal` and `external` to indicate an SVID for internal or
     * external use, respectively.
     */
    @field(4)
    hint?: string;
  }

  @message("spire.api.types.Bundle")
  model Bundle {
    /**
     * The name of the trust domain the bundle belongs to (e.g., "example.org").
     */
    @field(1)
    trust_domain?: string;

    /**
     * X.509 authorities for authenticating X509-SVIDs.
     */
    @field(2)
    x509_authorities?: X509Certificate[];

    /**
     * JWT authorities for authenticating JWT-SVIDs.
     */
    @field(3)
    jwt_authorities?: JWTKey[];

    /**
     * A hint on how often the bundle should be refreshed from the bundle
     * provider, in seconds. Can be zero (meaning no hint available).
     */
    @field(4)
    refresh_hint?: int64;

    /**
     * The sequence number of the bundle.
     */
    @field(5)
    sequence_number?: uint64;

    /**
     * WIT authorities for authenticating WIT-SVIDs.
     */
    @field(6)
    wit_authorities?: WITKey[];
  }

  @message("spire.api.types.X509Certificate")
  model X509Certificate {
    /**
     * The ASN.1 DER encoded bytes of the X.509 certificate.
     */
    @field(1)
    asn1?: bytes;

    /**
     * This authority is no longer secure and must not be used.
     */
    @field(2)
    tainted?: boolean;
  }

  @message("spire.api.types.JWTKey")
  model JWTKey {
    /**
     * The PKIX encoded public key.
     */
    @field(1)
    public_key?: bytes;

    /**
     * The key identifier.
     */
    @field(2)
    key_id?: string;

    /**
     * When the key expires (seconds since Unix epoch). If zero, the key does
     * not expire.
     */
    @field(3)
    expires_at?: int64;

    /**
     * This authority is no longer secure and must not be used
     */
    @field(4)
    tainted?: boolean;
  }

  @message("spire.api.types.WITKey")
  model WITKey {
    /**
     * The PKIX encoded public key.
     */
    @field(1)
    public_key?: bytes;

    /**
     * The key identifier.
     */
    @field(2)
    key_id?: string;

    /**
     * When the key expires (seconds since Unix epoch). If zero, the key does
     * not expire.
     */
    @field(3)
    expires_at?: int64;

    /**
     * This authority is no longer secure and must not be used
     */
    @field(4)
    tainted?: boolean;
  }

  @message("spire.api.types.BundleMask")
  model BundleMask {
    /**
     * x509_authorities field mask.
     */
    @field(2)
    x509_authorities?: boolean;

    /**
     * jwt_authorities field mask.
     */
    @field(3)
    jwt_authorities?: boolean;

    /**
     * refresh_hint field mask.
     */
    @field(4)
    refresh_hint?: boolean;

    /**
     * sequence_number field mask.
     */
    @field(5)
    sequence_number?: boolean;

    /**
     * wit_authorities field mask.
     */
    @field(6)
    wit_authorities?: boolean;
  }

  /**
   * JWT SPIFFE Verifiable Identity Document. It contains the raw JWT token
   * as well as a few denormalized fields for convenience.
   */
  @message("spire.api.types.JWTSVID")
  model JWTSVID {
    /**
     * The serialized JWT token.
     */
    @field(1)
    token?: string;

    /**
     * The SPIFFE ID of the JWT-SVID.
     */
    @field(2)
    id?: SPIFFEID;

    /**
     * Expiration timestamp (seconds since Unix epoch).
     */
    @field(3)
    expires_at?: int64;

    /**
     * Issuance timestamp (seconds since Unix epoch).
     */
    @field(4)
    issued_at?: int64;

    /**
     * Optional. An operator-specified string used to provide guidance on how this
     * identity should be used by a workload when more than one SVID is returned.
     * For example, `internal` and `external` to indicate an SVID for internal or
     * external use, respectively.
     */
    @field(5)
    hint?: string;
  }

  /**
   * WIT SPIFFE Verifiable Identity Document. It contains the raw WIT token
   * as well as a few denormalized fields for convenience.
   */
  @message("spire.api.types.WITSVID")
  model WITSVID {
    /**
     * The serialized WIT token.
     */
    @field(1)
    token?: string;

    /**
     * The SPIFFE ID of the WIT-SVID.
     */
    @field(2)
    id?: SPIFFEID;

    /**
     * Expiration timestamp (seconds since Unix epoch).
     */
    @field(3)
    expires_at?: int64;

    /**
     * Issuance timestamp (seconds since Unix epoch).
     */
    @field(4)
    issued_at?: int64;

    /**
     * Optional. An operator-specified string used to provide guidance on how this
     * identity should be used by a workload when more than one SVID is returned.
     * For example, `internal` and `external` to indicate an SVID for internal or
     * external use, respectively.
     */
    @field(5)
    hint?: string;
  }

  @message("spire.api.types.FederationRelationship")
  model FederationRelationship {
    /**
     * Required. The trust domain name (e.g., "example.org") to federate with.
     */
    @field(1)
    trust_domain?: string;

    /**
     * Required. URL of the SPIFFE bundle endpoint that provides the trust
     * bundle to federate with. Must use the HTTPS protocol.
     */
    @field(2)
    bundle_endpoint_url?: string;

    /**
     * Use Web PKI endpoint profile.
     */
    @field(3)
    @oneof("bundle_endpoint_profile")
    https_web?: HTTPSWebProfile;

    /**
     * Use SPIFFE Authentication endpoint profile.
     */
    @field(4)
    @oneof("bundle_endpoint_profile")
    https_spiffe?: HTTPSSPIFFEProfile;

    /**
     * Optional. The bundle for the trust domain. This field can be used to
     * create or replace the referenced trust domains' bundle when the
     * relationship is created or updated.  When the relationship is retrieved,
     * it will be set to the referenced trust domain's latest bundle (if
     * available). Please note that the `https_spiffe` profile requires an
     * existing trust domain bundle in order to function correctly. The
     * required bundle must match the trust domain specified in the bundle
     * endpoint SPIFFE ID. If the bundle endpoint SPIFFE ID resides in the same
     * trust domain that you're trying to federate with, you may optionally
     * specify that trust domain bundle here. If the bundle endpoint SPIFFE ID
     * _does not_ reside in the same trust domain that you're federating with,
     * please ensure that the trust domain bundle for that trust domain has
     * been configured separately (e.g. configured via another federation
     * relationship or manually set via the Bundle API).
     */
    @field(5)
    trust_domain_bundle?: Bundle;
  }

  @message("spire.api.types.HTTPSSPIFFEProfile")
  model HTTPSSPIFFEProfile {
    /**
     * Required. Specifies the expected SPIFFE ID of the SPIFFE bundle endpoint
     * server.
     */
    @field(1)
    endpoint_spiffe_id?: string;
  }

  @message("spire.api.types.HTTPSWebProfile")
  model HTTPSWebProfile {}

  @message("spire.api.types.FederationRelationshipMask")
  model FederationRelationshipMask {
    /**
     * bundle_endpoint_url field mask.
     */
    @field(1)
    bundle_endpoint_url?: boolean;

    /**
     * bundle_endpoint_profile field mask.
     */
    @field(2)
    bundle_endpoint_profile?: boolean;

    /**
     * trust_domain_bundle field mask.
     */
    @field(3)
    trust_domain_bundle?: boolean;
  }
}
