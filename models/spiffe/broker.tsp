// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/spiffe/broker.tsp
//
// THE SPIFFE BROKER API (#170, #1579): the service, its methods and every message, from `brokerapi.proto`.
//
// Converted once from the vendored `spiffe/protos/brokerapi.proto` by a script that
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

namespace IyaSts.Spiffe.Broker {
  @grpcService(#{
    name: "spiffe.broker.API",
    surface: "broker",
    statuses: #["INVALID_ARGUMENT", "UNAUTHENTICATED", "PERMISSION_DENIED", "NOT_FOUND", "UNAVAILABLE", "UNKNOWN", "INTERNAL"],
    cite: "SPIFFE Broker Endpoint sections 3 to 5 (draft)"
  })
  interface API {
    /**
     * Fetch X.509-SVIDs for all SPIFFE identities the referenced workload is
     * entitled to, as well as related information like trust bundles. As this
     * information changes, subsequent messages will be streamed from the server.
     */
    @rpc(#{ stream: "server" })
    SubscribeToX509SVID(request: SubscribeToX509SVIDRequest): SubscribeToX509SVIDResponse;

    /**
     * Fetch trust bundles of the referenced workload. Useful in situations that
     * only need to validate SVIDs without obtaining an SVID for themself. As this
     * information changes, subsequent messages will be streamed from the server.
     */
    @rpc(#{ stream: "server" })
    SubscribeToX509Bundles(request: SubscribeToX509BundlesRequest): SubscribeToX509BundlesResponse;

    /**
     * Fetch JWT-SVIDs for all SPIFFE identities the referenced workload is
     * entitled to, for the requested audience. If an optional SPIFFE ID is
     * requested, only the JWT-SVID for that SPIFFE ID is returned.
     */
    @rpc(#{ stream: "unary" })
    FetchJWTSVID(request: FetchJWTSVIDRequest): FetchJWTSVIDResponse;

    /**
     * Fetches the JWT bundles, formatted as JWKS documents, keyed by the
     * SPIFFE ID of the trust domain. As this information changes, subsequent
     * messages will be streamed from the server.
     */
    @rpc(#{ stream: "server" })
    SubscribeToJWTBundles(request: SubscribeToJWTBundlesRequest): SubscribeToJWTBundlesResponse;
  }

  /**
   * The WorkloadReference message represents a single reference to a workload.
   * The reference field contains one of the standard reference types or
   * a vendor-specific extension type.
   */
  @message("spiffe.broker.WorkloadReference")
  model WorkloadReference {
    /**
     * Required. The reference to the workload.
     */
    @refuse(#{
      when: "empty",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0136",
      message: "workload reference must be provided",
      errorInfo: "WORKLOAD_REFERENCE_INVALID",
      cite: "SPIFFE Broker API sections 3.1.4 and 4.8"
    })
    @field(1)
    reference?: IyaSts.Spiffe.Google.Any;
  }

  /**
   * The WorkloadPIDReference message conveys a process id reference of a workload
   * running in the same environment.
   */
  @message("spiffe.broker.WorkloadPIDReference")
  model WorkloadPIDReference {
    /**
     * Required. The process id of the workload. MUST be a positive integer.
     * For workloads running inside container runtimes that maintain a separate
     * sandbox (e.g. the `pause` container in containerd or CRI-O), this MUST
     * be the PID of the workload's own process, not the sandbox PID.
     */
    @field(1)
    pid?: int32;
  }

  /**
   * The KubernetesObjectType message identifies the type of a Kubernetes object
   * by its plural name and API group. This avoids ambiguity between plurals that
   * happen to contain dots (e.g., the plural `myresource.example` in the `com`
   * group vs. `myresource` in the `example.com` group) that arises when the
   * `<plural>.<group>` shorthand is parsed as a single string.
   */
  @message("spiffe.broker.KubernetesObjectType")
  model KubernetesObjectType {
    /**
     * Required. The plural name of the Kubernetes resource, as registered with
     * the Kubernetes API server. For example, `pods`, `deployments`, or the
     * plural form declared by a `CustomResourceDefinition`.
     */
    @field(1)
    plural?: string;

    /**
     * Required. The API group of the Kubernetes resource. For non-core
     * resources this is the API group name (e.g., `apps`, `example.com`).
     * For core resources this field MUST be set to the literal string `core`.
     */
    @field(2)
    group?: string;
  }

  /**
   * The KubernetesObjectKey message identifies a specific Kubernetes object
   * within its type by `namespace` and `name`.
   */
  @message("spiffe.broker.KubernetesObjectKey")
  model KubernetesObjectKey {
    /**
     * Optional. The namespace of the referenced Kubernetes object. MUST be set
     * for namespaced resources. MUST be empty when the resource is
     * cluster-scoped.
     */
    @field(1)
    `namespace`?: string;

    /**
     * Required. The name of the referenced Kubernetes object.
     */
    @field(2)
    name?: string;
  }

  /**
   * The KubernetesObjectReference message conveys a reference to an arbitrary
   * Kubernetes object (built-in or custom) by which a workload is identified for
   * the purpose of SVID issuance. The referenced object MUST exist and be accessible
   * at the time of the request.
   *
   * The mapping from a Kubernetes object to a SPIFFE ID is implementation-defined;
   * this specification does not mandate a particular SPIFFE ID format.
   */
  @message("spiffe.broker.KubernetesObjectReference")
  model KubernetesObjectReference {
    /**
     * Required. The type of the referenced Kubernetes object.
     */
    @field(1)
    type?: KubernetesObjectType;

    /**
     * Optional. The namespaced name of the referenced Kubernetes object.
     * At least one of `key` or `uid` MUST be specified.
     */
    @field(2)
    key?: KubernetesObjectKey;

    /**
     * Optional. The UID of the referenced Kubernetes object. MUST be a valid
     * UUID string as assigned by Kubernetes. At least one of `key` or `uid`
     * MUST be specified. When both `key` and `uid` are specified, the server
     * MUST verify that the object resolved by `key` has the specified UID at
     * the time of issuing the SVIDs and MUST return an error otherwise.
     */
    @field(3)
    uid?: string;
  }

  /**
   * The SubscribeToX509SVIDRequest message conveys parameters for requesting an X.509-SVID.
   */
  @message("spiffe.broker.SubscribeToX509SVIDRequest")
  model SubscribeToX509SVIDRequest {
    /**
     * Required. The reference identifying the workload.
     */
    @field(1)
    reference?: WorkloadReference;
  }

  /**
   * The SubscribeToX509SVIDResponse message carries X.509-SVIDs and related information,
   * including a list of bundles the workload may use for federating with foreign
   * trust domains.
   */
  @message("spiffe.broker.SubscribeToX509SVIDResponse")
  model SubscribeToX509SVIDResponse {
    /**
     * Required. A list of X509SVID messages, each of which includes a single
     * X.509-SVID, its private key, and the bundle for the trust domain.
     */
    @field(1)
    svids?: IyaSts.Spiffe.Workload.X509SVID[];

    /**
     * Optional. ASN.1 DER encoded (not PEM) certificate revocation lists.
     */
    @field(2)
    crl?: bytes[];

    /**
     * Optional. CA certificate bundles belonging to foreign trust domains that
     * the workload should trust, keyed by the SPIFFE ID of the foreign trust
     * domain. Bundles are ASN.1 DER encoded (not PEM).
     */
    @field(3)
    federated_bundles?: Record<bytes>;
  }

  /**
   * The X509SVID message carries a single SVID and all associated information,
   * including the X.509 bundle for the trust domain.
   */
  @message("spiffe.broker.X509SVID")
  model X509SVID {
    /**
     * Required. The SPIFFE ID of the SVID in this entry
     */
    @field(1)
    spiffe_id?: string;

    /**
     * Required. ASN.1 DER encoded (not PEM) certificate chain. MAY include
     * intermediates, the leaf certificate (or SVID itself) MUST come first.
     */
    @field(2)
    x509_svid?: bytes;

    /**
     * Required. ASN.1 DER encoded (not PEM) PKCS#8 private key. MUST be unencrypted.
     */
    @field(3)
    x509_svid_key?: bytes;

    /**
     * Required. ASN.1 DER encoded (not PEM) X.509 bundle for the trust domain.
     */
    @field(4)
    bundle?: bytes;

    /**
     * Optional. An operator-specified string used to provide guidance on how this
     * identity should be used by a broker or workload when more than one SVID is
     * returned. For example, `internal` and `external` to indicate an SVID for
     * internal or external use, respectively.
     */
    @field(5)
    hint?: string;
  }

  /**
   * The SubscribeToX509BundlesRequest message conveys parameters for requesting X.509
   * bundles.
   */
  @message("spiffe.broker.SubscribeToX509BundlesRequest")
  model SubscribeToX509BundlesRequest {
    /**
     * Required. The reference identifying the workload.
     */
    @field(1)
    reference?: WorkloadReference;
  }

  /**
   * The SubscribeToX509BundlesResponse message carries a map of trust bundles the workload
   * should trust.
   */
  @message("spiffe.broker.SubscribeToX509BundlesResponse")
  model SubscribeToX509BundlesResponse {
    /**
     * Optional. ASN.1 DER encoded (not PEM) certificate revocation lists.
     */
    @field(1)
    crl?: bytes[];

    /**
     * Required. CA certificate bundles belonging to trust domains that the
     * workload should trust, keyed by the SPIFFE ID of the trust domain.
     * Bundles are ASN.1 DER encoded (not PEM).
     */
    @field(2)
    bundles?: Record<bytes>;
  }

  /**
   * The FetchJWTSVIDRequest message conveys parameters for requesting JWT-SVIDs.
   */
  @message("spiffe.broker.FetchJWTSVIDRequest")
  model FetchJWTSVIDRequest {
    /**
     * Required. The reference identifying the workload.
     */
    @field(1)
    reference?: WorkloadReference;

    /**
     * Required. The audience(s) the workload intends to authenticate against.
     */
    @refuse(#{
      when: "empty",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0027",
      message: "audience must be specified",
      cite: "SPIFFE Broker API section 4.6"
    })
    @field(2)
    audience?: string[];

    /**
     * Optional. The requested SPIFFE ID for the JWT-SVID. If unset, all
     * JWT-SVIDs to which the workload is entitled are requested.
     */
    @refuse(#{
      when: "malformed",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0028",
      message: "invalid requested SPIFFE ID: {reason}",
      cite: "SPIFFE Broker API section 4.6; SPIFFE-ID section 2"
    })
    @field(3)
    spiffe_id?: string;
  }

  /**
   * The FetchJWTSVIDResponse message conveys JWT-SVIDs.
   */
  @message("spiffe.broker.FetchJWTSVIDResponse")
  model FetchJWTSVIDResponse {
    /**
     * Required. The list of returned JWT-SVIDs.
     */
    @field(1)
    svids?: IyaSts.Spiffe.Workload.JWTSVID[];
  }

  /**
   * The JWTSVID message carries the JWT-SVID token and associated metadata.
   */
  @message("spiffe.broker.JWTSVID")
  model JWTSVID {
    /**
     * Required. The SPIFFE ID of the JWT-SVID.
     */
    @field(1)
    spiffe_id?: string;

    /**
     * Required. Encoded JWT using JWS Compact Serialization.
     */
    @field(2)
    svid?: string;

    /**
     * Optional. An operator-specified string used to provide guidance on how this
     * identity should be used by a workload when more than one SVID is returned.
     * For example, `internal` and `external` to indicate an SVID for internal or
     * external use, respectively.
     */
    @field(3)
    hint?: string;
  }

  /**
   * The SubscribeToJWTBundlesRequest message conveys parameters for requesting JWT bundles.
   */
  @message("spiffe.broker.SubscribeToJWTBundlesRequest")
  model SubscribeToJWTBundlesRequest {
    /**
     * Required. The reference identifying the workload.
     */
    @field(1)
    reference?: WorkloadReference;
  }

  /**
   * The SubscribeToJWTBundlesResponse message conveys JWT bundles.
   */
  @message("spiffe.broker.SubscribeToJWTBundlesResponse")
  model SubscribeToJWTBundlesResponse {
    /**
     * Required. JWK encoded JWT bundles, keyed by the SPIFFE ID of the trust
     * domain.
     */
    @field(1)
    bundles?: Record<bytes>;
  }
}
