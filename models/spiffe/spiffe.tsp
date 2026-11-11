// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/spiffe/spiffe.tsp
//
// Written by hand (#1579). THE SPIFFE NAMESPACE OF THE MODEL: what a SPIFFE
// ID is, what an X509-SVID leaf must be, what a trust bundle and a JWT-SVID
// carry, and — in the four files it imports — every message of the
// Workload API, the SPIRE Server API and the Broker API this service
// decodes and answers. `models/tools/generate.mjs` compiles it into
// `models/generated/spiffe.json` during the image build and holds every
// message to the vendored protos; `spiffe/spiffe_model.ts` reads it:
//
//   * `spiffe/spiffe_id.ts` parses a SPIFFE ID by `@idGrammar`;
//   * `spiffe/spiffe_auth.ts` holds a presented X509-SVID to `@svidRules`;
//   * every refusal of a request field — the status, the error code, the
//     sentence — is the field's `@refuse`, asked by `spiffe/spiffe_grpc.ts`'s
//     `refuseField()` where the handler reads that field;
//   * `GET /spiffe` and the console publish each unimplemented method's
//     reason from its `@rpc`;
//   * every answer a handler hands grpc-js — a unary reply, each message of
//     a stream — is held to its response message before protobufjs
//     serialises it, and the status a call ends with to the statuses its
//     service and method declare; a member that would serialise to nothing,
//     a value of the wrong type and an undeclared status are recorded under
//     STS-SPIFFE-0154 / 0155, and the answer is sent unchanged;
//   * the bundle a realm publishes and each JWT-SVID it mints are held to
//     their member sets the same way, and a federated bundle's keys are
//     checked against the `bundle-key-use` registry.
//
// Protobuf decoding stays in code: grpc-js and `@grpc/proto-loader` decode
// the wire with the vendored `.proto` files, which stay verbatim because a
// local edit would give up the wire matching what a real client expects.

import "../lib/spiffe_lib.tsp";
import "./google.tsp";
import "./workload.tsp";
import "./broker.tsp";
import "./spire_types.tsp";
import "./spire_server.tsp";

using IyaSts.SpiffeLib;

namespace IyaSts.Spiffe;

/**
 * A SPIFFE ID: `spiffe://<trust domain><path>`. No userinfo, no port, no
 * query, no fragment, no percent-encoding, no empty and no relative path
 * segment. A trust domain name is lower case: `UPPER.example` is a
 * different identifier from `upper.example`, never another spelling of it.
 */
@idGrammar(#{
  scheme: "spiffe",
  maxBytes: 2048,
  maxTrustDomainBytes: 255,
  trustDomainPattern: "^[a-z0-9.\\-_]+$",
  pathSegmentPattern: "^[a-zA-Z0-9.\\-_]+$",
  reservedPrefix: "/spire",
  cite: "SPIFFE-ID sections 2, 2.1, 2.2 and 2.3"
})
model SpiffeIdGrammar {}

/**
 * An X509-SVID leaf: not a CA, signing with `digitalSignature`, and never
 * `keyCertSign` or `cRLSign`. A presented certificate that breaks one is
 * refused STS-SPIFFE-0144, naming the clause.
 */
@svidRules(#{
  leaf: #[
    #{ fact: "ca", equals: false, problem: "basicConstraints cA is set" },
    #{
      fact: "keyUsage",
      includes: "digitalSignature",
      problem: "its keyUsage does not name digitalSignature"
    },
    #{
      fact: "keyUsage",
      excludes: #["keyCertSign", "cRLSign"],
      problem: "its keyUsage names keyCertSign or cRLSign"
    }
  ],
  cite: "X509-SVID section 4.3"
})
model X509SvidRules {}

/** What a JWK in a SPIFFE bundle is for. A consumer MUST ignore any other. */
@registry(#{
  id: "bundle-key-use",
  cite: "SPIFFE Trust Domain and Bundle section 4.2.2; WIT-SVID section 6"
})
union BundleKeyUse {
  "x509-svid",
  "jwt-svid",
  "wit-svid",
}

/** The `typ` a JWT-SVID's header may carry; this service writes the first. */
@registry(#{ id: "jwt-svid-typ", cite: "JWT-SVID section 2.3" })
union JwtSvidTyp {
  "JWT",
  "JOSE",
}

/**
 * A SPIFFE bundle: a JWK Set with the two SPIFFE parameters. What
 * `GET /spiffe/bundle` answers, and the document a federated bundle is.
 */
@members(#{
  id: "bundle",
  members: "open",
  cite: "SPIFFE Trust Domain and Bundle section 4"
})
model Bundle {
  @member(#{ cite: "SPIFFE Trust Domain and Bundle section 4.1; RFC 7517 section 5" })
  keys: BundleKey[];

  @member(#{ cite: "SPIFFE Trust Domain and Bundle section 4.1.1" })
  spiffe_sequence?: int64;

  @member(#{ cite: "SPIFFE Trust Domain and Bundle section 4.1.2" })
  spiffe_refresh_hint?: int64;
}

/**
 * One key of a bundle. Open: a key carries its key type's own members
 * (`crv`, `x`, `y`; `n`, `e`; a post-quantum key's `pub` and `alg`).
 */
@members(#{
  id: "bundle-key",
  members: "open",
  cite: "SPIFFE Trust Domain and Bundle section 4.2; RFC 7517 section 4"
})
model BundleKey {
  @member(#{ cite: "RFC 7517 section 4.1" })
  kty: string;

  @member(#{ cite: "SPIFFE Trust Domain and Bundle section 4.2.2" })
  use: BundleKeyUse;

  /** A JWT authority's key id, which a JWT-SVID's header names. */
  @member(#{ cite: "SPIFFE Trust Domain and Bundle section 4.2.1" })
  kid?: string;

  /** An X.509 authority's certificate: exactly one. */
  @member(#{ cite: "SPIFFE Trust Domain and Bundle section 4.2.3" })
  x5c?: string[];
}

/** A JWT-SVID's JOSE header, as this service writes it. */
@members(#{
  id: "jwt-svid-header",
  members: "open",
  cite: "JWT-SVID section 2"
})
model JwtSvidHeader {
  @member(#{ cite: "JWT-SVID section 2.1" })
  alg: string;

  @member(#{ cite: "JWT-SVID section 2.2" })
  kid: string;

  @member(#{ cite: "JWT-SVID section 2.3" })
  typ?: JwtSvidTyp;
}

/** A JWT-SVID's claims, as this service mints them. */
@members(#{
  id: "jwt-svid-claims",
  members: "open",
  cite: "JWT-SVID section 3"
})
model JwtSvidClaims {
  /** The SPIFFE ID. */
  @member(#{ cite: "JWT-SVID section 3.1" })
  sub: string;

  /** One audience as a string, several as an array. */
  @member(#{ cite: "JWT-SVID section 3.2; RFC 7519 section 4.1.3" })
  aud: string | string[];

  @member(#{ cite: "JWT-SVID section 3.3" })
  exp: int64;

  @member(#{ cite: "RFC 7519 section 4.1.6" })
  iat?: int64;

  @member(#{ cite: "RFC 7519 section 4.1.7", own: true })
  jti?: string;
}
