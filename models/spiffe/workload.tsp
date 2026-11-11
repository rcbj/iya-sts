// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/spiffe/workload.tsp
//
// THE SPIFFE WORKLOAD API (#1579): the service, its methods and every message, from `workloadapi.proto`.
//
// Converted once from the vendored `spiffe/protos/workloadapi.proto` by a script that
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

namespace IyaSts.Spiffe.Workload {
  @grpcService(#{
    name: "SpiffeWorkloadAPI",
    surface: "workload",
    statuses: #["INVALID_ARGUMENT", "PERMISSION_DENIED", "UNAVAILABLE", "UNKNOWN", "INTERNAL"],
    cite: "SPIFFE Workload Endpoint sections 4 and 6; SPIFFE Workload API section 5"
  })
  interface SpiffeWorkloadAPI {
    /**
     * Fetch X.509-SVIDs for all SPIFFE identities the workload is entitled to,
     * as well as related information like trust bundles and CRLs. As this
     * information changes, subsequent messages will be streamed from the
     * server.
     */
    @rpc(#{ stream: "server" })
    FetchX509SVID(request: X509SVIDRequest): X509SVIDResponse;

    /**
     * Fetch trust bundles and CRLs. Useful for clients that only need to
     * validate SVIDs without obtaining an SVID for themself. As this
     * information changes, subsequent messages will be streamed from the
     * server.
     */
    @rpc(#{ stream: "server" })
    FetchX509Bundles(request: X509BundlesRequest): X509BundlesResponse;

    /**
     * Fetch JWT-SVIDs for all SPIFFE identities the workload is entitled to,
     * for the requested audience. If an optional SPIFFE ID is requested, only
     * the JWT-SVID for that SPIFFE ID is returned.
     */
    @rpc(#{ stream: "unary" })
    FetchJWTSVID(request: JWTSVIDRequest): JWTSVIDResponse;

    /**
     * Fetches the JWT bundles, formatted as JWKS documents, keyed by the
     * SPIFFE ID of the trust domain. As this information changes, subsequent
     * messages will be streamed from the server.
     */
    @rpc(#{ stream: "server" })
    FetchJWTBundles(request: JWTBundlesRequest): JWTBundlesResponse;

    /**
     * Validates a JWT-SVID against the requested audience. Returns the SPIFFE
     * ID of the JWT-SVID and JWT claims.
     */
    @rpc(#{ stream: "unary" })
    ValidateJWTSVID(request: ValidateJWTSVIDRequest): ValidateJWTSVIDResponse;

    /**
     * Fetch WIT-SVIDs for all SPIFFE identities the workload is entitled to. If
     * the identities which the workload is entitled to change, or, they are
     * renewed, the server will stream subsequent messages to the client.
     *
     * Must return Unimplemented where Workload API endpoint does not support the
     * WIT-SVID profile.
     */
    @rpc(#{
      stream: "server",
      statuses: #["UNIMPLEMENTED"],
      unimplemented: "This service does not issue WIT-SVIDs."
    })
    FetchWITSVID(request: WITSVIDRequest): WITSVIDResponse;

    /**
     * Fetch trust bundles. Useful for clients that only need to validate SVIDs
     * without obtaining an SVID for themselves. As this information changes,
     * subsequent messages will be streamed from the server.
     *
     * Must return Unimplemented where Workload API endpoint does not support the
     * WIT-SVID profile.
     */
    @rpc(#{
      stream: "server",
      statuses: #["UNIMPLEMENTED"],
      unimplemented: "This service does not issue WIT-SVIDs."
    })
    FetchWITBundles(request: WITBundlesRequest): WITBundlesResponse;
  }

  /**
   * The X509SVIDRequest message conveys parameters for requesting an X.509-SVID.
   * There are currently no request parameters.
   */
  @message("X509SVIDRequest")
  model X509SVIDRequest {}

  /**
   * The X509SVIDResponse message carries X.509-SVIDs and related information,
   * including a set of global CRLs and a list of bundles the workload may use
   * for federating with foreign trust domains.
   */
  @message("X509SVIDResponse")
  model X509SVIDResponse {
    /**
     * Required. A list of X509SVID messages, each of which includes a single
     * X.509-SVID, its private key, and the bundle for the trust domain.
     */
    @field(1)
    svids?: X509SVID[];

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
  @message("X509SVID")
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
     * identity should be used by a workload when more than one SVID is returned.
     * For example, `internal` and `external` to indicate an SVID for internal or
     * external use, respectively.
     */
    @field(5)
    hint?: string;
  }

  /**
   * The X509BundlesRequest message conveys parameters for requesting X.509
   * bundles. There are currently no such parameters.
   */
  @message("X509BundlesRequest")
  model X509BundlesRequest {}

  /**
   * The X509BundlesResponse message carries a set of global CRLs and a map of
   * trust bundles the workload should trust.
   */
  @message("X509BundlesResponse")
  model X509BundlesResponse {
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

  @message("JWTSVIDRequest")
  model JWTSVIDRequest {
    /**
     * Required. The audience(s) the workload intends to authenticate against.
     */
    @refuse(#{
      when: "empty",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0027",
      message: "FetchJWTSVID requires at least one audience. A JWT-SVID is a bearer credential — whoever holds it can present it — so the audience is what stops one issued for service A being replayed against service B. Every conforming Workload API refuses this call without one.",
      cite: "SPIFFE Workload API section 6.2.1; JWT-SVID section 3"
    })
    @field(1)
    audience?: string[];

    /**
     * Optional. The requested SPIFFE ID for the JWT-SVID. If unset, all
     * JWT-SVIDs to which the workload is entitled are requested.
     */
    @refuse(#{
      when: "malformed",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0028",
      message: "spiffe_id: {reason}",
      cite: "SPIFFE Workload API section 6.2.1; SPIFFE-ID section 2"
    })
    @field(2)
    spiffe_id?: string;
  }

  /**
   * The JWTSVIDResponse message conveys JWT-SVIDs.
   */
  @message("JWTSVIDResponse")
  model JWTSVIDResponse {
    /**
     * Required. The list of returned JWT-SVIDs.
     */
    @field(1)
    svids?: JWTSVID[];
  }

  /**
   * The JWTSVID message carries the JWT-SVID token and associated metadata.
   */
  @message("JWTSVID")
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
   * The JWTBundlesRequest message conveys parameters for requesting JWT bundles.
   * There are currently no such parameters.
   */
  @message("JWTBundlesRequest")
  model JWTBundlesRequest {}

  /**
   * The JWTBundlesResponse conveys JWT bundles.
   */
  @message("JWTBundlesResponse")
  model JWTBundlesResponse {
    /**
     * Required. JWK encoded JWT bundles, keyed by the SPIFFE ID of the trust
     * domain.
     */
    @field(1)
    bundles?: Record<bytes>;
  }

  /**
   * The ValidateJWTSVIDRequest message conveys request parameters for
   * JWT-SVID validation.
   */
  @message("ValidateJWTSVIDRequest")
  model ValidateJWTSVIDRequest {
    /**
     * Required. The audience of the validating party. The JWT-SVID must
     * contain an audience claim which contains this value in order to
     * succesfully validate.
     */
    @refuse(#{
      when: "empty",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0032",
      message: "ValidateJWTSVID requires the audience the validating party goes by; a JWT-SVID is only meaningful against one.",
      cite: "SPIFFE Workload API section 6.2.3; JWT-SVID section 3"
    })
    @field(1)
    audience?: string;

    /**
     * Required. The JWT-SVID to validate, encoded using JWS Compact
     * Serialization.
     */
    @refuse(#{
      when: "empty",
      status: "INVALID_ARGUMENT",
      code: "STS-SPIFFE-0031",
      message: "No JWT-SVID was given.",
      cite: "SPIFFE Workload API section 6.2.3"
    })
    @field(2)
    svid?: string;
  }

  /**
   * The ValidateJWTSVIDResponse message conveys the JWT-SVID validation results.
   */
  @message("ValidateJWTSVIDResponse")
  model ValidateJWTSVIDResponse {
    /**
     * Required. The SPIFFE ID of the validated JWT-SVID.
     */
    @field(1)
    spiffe_id?: string;

    /**
     * Required. Claims contained within the payload of the validated JWT-SVID.
     * This includes both SPIFFE-required and non-required claims.
     */
    @field(2)
    claims?: IyaSts.Spiffe.Google.Struct;
  }

  /**
   * The WITSVIDRequest message conveys parameters for requesting a WIT-SVID.
   */
  @message("WITSVIDRequest")
  model WITSVIDRequest {
    /**
     * Optional. The requested SPIFFE ID for the WIT-SVID. If unset, all WIT-SVIDs
     * to which the workload is entitled are requested.
     */
    @field(1)
    spiffe_id?: string;
  }

  /**
   * The WITSVIDResponse message carries WIT-SVIDs.
   */
  @message("WITSVIDResponse")
  model WITSVIDResponse {
    /**
     * Required.
     * A list of WITSVID messages, each of which includes a single WIT-SVID and
     * its private key.
     */
    @field(1)
    svids?: WITSVID[];
  }

  /**
   * The WITSVID message carries a single SVID and all associated information,
   * including the WIT bundle for the trust domain.
   */
  @message("WITSVID")
  model WITSVID {
    /**
     * Required.
     * The SPIFFE ID of the SVID in this entry
     */
    @field(1)
    spiffe_id?: string;

    /**
     * Required.
     * Encoded WIT SVID using compact JWS serialization.
     */
    @field(2)
    wit_svid?: string;

    /**
     * Required.
     * JWK (RFC 7517) encoded private key for the WIT SVID.
     */
    @field(3)
    wit_svid_key?: string;

    /**
     * Optional.
     * An operator-specified string used to provide guidance on how this identity
     * should be used by a workload when more than one SVID is returned.
     * For example, `internal` and `external` to indicate a SVID for internal or
     * external use, respectively.
     */
    @field(4)
    hint?: string;
  }

  /**
   * The WITBundlesRequest message conveys parameters for requesting WIT
   * bundles. There are currently no such parameters.
   */
  @message("WITBundlesRequest")
  model WITBundlesRequest {}

  /**
   * The WITBundlesResponse message carries a map of trust bundles the workload
   * should trust.
   */
  @message("WITBundlesResponse")
  model WITBundlesResponse {
    /**
     * Required.
     * WIT trust bundles belonging to trust domains that the workload should
     * trust, keyed by the SPIFFE ID of the trust domain.
     *
     * Bundles are encoded in JWK set (RFC 7517) format. Each JWK MUST specify the
     * `kid` member with a unique identifier for the key.
     */
    @field(1)
    bundles?: Record<string>;
  }
}
