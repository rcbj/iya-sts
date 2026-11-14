// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/api/console.tsp
//
// Written by hand (#1390). THE ADMIN CONSOLE API OPENAPI DOCUMENT'S SOURCE:
// `models/tools/generate.mjs` compiles it during the image build, the service
// serves the result and holds every answer to it.
//
// The reasoning below sat beside the code this replaced.
//

import "../lib/api_lib.tsp";
import "./common.tsp";

using IyaSts.ApiLib;
using IyaSts.Api.Common;

@apiDocument(#{
  `x-iya-every-operation`:#[
    #{
      `name`:"DPoP",
      `in`:"header",
      `required`:false,
      `schema`:#{`type`:"string"},
      `description`:"RFC 9449: the proof of possession for a DPoP-bound access token, as `Authorization: DPoP <token>` requires."
    },
    #{
      `name`:"cell",
      `in`:"query",
      `required`:false,
      `schema`:#{`type`:"string"},
      `description`:"The cell to answer this request, where this service runs as several. Ignored in a service that runs as one."
    }
  ],
  `openapi`:"3.1.0",
  `info`:#{
    `title`:"IYA STS admin console operations",
    `version`:"0.0.0",
    `description`:"**These are the admin console's own operations, not the management API.** They exist to draw the static console at /admin — its frame, its drawings and its form helpers — and answer in the shape its pages want, which changes when a page does. They take `admin:console`, issued only to the console's client through the ADMIN_CONSOLE role it confers, and a page that shows realm data takes ADMIN_READ too. Every control the console has is a management operation, described by /admin-api/openapi.json.\n\nThe management API of IYA STS: everything the /admin console shows and everything it can change, over JSON, with no browser.\n\n**Every operation here requires an OAuth 2.0 access token, and this document says which scope each one needs.** Ask this service's own token endpoint for one: `grant_type=client_credentials` as the seeded client `sts-api-client` (its secret is `adminApi.clientSecret`), `scope=admin:read admin:write`, and **`resource=<this server>/admin-api`** — that last parameter is what puts this API in the token's `aud`, and a token audienced at anything else is refused however good it is. A GET needs `admin:read` and everything else needs `admin:write`; they are checked as a XACML access decision against the built-in ADMIN_READ and ADMIN_WRITE roles, so the requirement is stated in the same policy document as every other access decision in this service. **The credential is service-wide**: the token is verified against the DEFAULT realm's key and audienced without a realm prefix wherever it is presented, for the reason the console's two roles are groups in the default realm — a per-realm one would let anybody who can create a realm mint themselves an administrator. A trust realm's own administrators have a narrower token of their own: issued to that realm's `sts-api-client` client, accepted only under `/realm/<id>/admin-api`, and refused every service-wide operation. `adminApi.authRequired` turns this off and restores the open API exactly; what follows is what that means. **AND IT IS STILL WORTH STATING PLAINLY**: a holder of this token can revoke every token this service has issued and change what the next one contains. That is fine on a laptop or a compose network and is not fine on a public address, which was already true of /oauth2/token — it will mint a token for any username asked of it.\n\n**Many operations change what the protocol endpoints do**, rather than only reporting on them; four examples. Revoking a token is the same revocation RFC 7009's /oauth2/revoke performs, so introspection, UserInfo and the refresh grant all honour it immediately. A custom claim reaches every access token, ID Token and SAML assertion issued from then on. The credential claim set reaches every Verifiable Credential AND sweeps the embedded LDAP directory. And the verifier request reaches the dcql_query of the next OID4VP Authorization Request. Nothing already issued ever changes — a signed document cannot be reached into.\n\n**Every operation here mirrors a control on the /admin console and calls the same function behind it.** They are not two implementations of one idea: admin_api.js holds no opinion about what a revocation means that the console does not. The `mirrors` line on each operation says which control it is.\n\nIn the default memory persistence mode all state is in memory and dies with the process; `GET /admin-api/persistence` says what this process writes down.",
    `license`:#{`name`:"MIT"}
  },
  `servers`:#[#{`url`:"/",`description`:"This service."}],
  `tags`:#[
    #{
      `name`:"Service",
      `description`:"What this API is, its document, and the explorer that calls it."
    },
    #{`name`:"Delegation",`description`:""},
    #{`name`:"Federation",`description`:""},
    #{`name`:"Applications",`description`:""},
    #{`name`:"PKI",`description`:""}
  ],
  `security`:#[
    #{`oauth2`:#["admin:console","admin:read","admin:write"]},
    #{`bearerAuth`:#[]}
  ],
  `components`:#{
    `securitySchemes`:#{
      `oauth2`:#{
        `type`:"oauth2",
        `description`:"An access token from this service's own token endpoint. Ask as the seeded client `sts-api-client`, whose secret is the `adminApi.clientSecret` setting, and **send `resource=/admin-api`** with the request: OpenAPI has no field for RFC 8707's resource indicator and it is what puts this API in the token's `aud`, without which every call here is refused 401.",
        `flows`:#{
          `clientCredentials`:#{
            `tokenUrl`:"/oauth2/token",
            `scopes`:#{
              `admin:read`:"Read anything this API exposes (every GET).",
              `admin:write`:"Change anything this API can change (every other method), except a security change.",
              `admin:security`:"A security change, in place of admin:write: a Directory → Policies policy saved, reset or acted on, a policy named on an application, group or person, the Security Administrator's role granted or revoked, and the account of a person who holds it. Issued only to a subject holding SECURITY_ADMIN.",
              `admin:console`:"The admin console's own operations, under /admin-api/console (#454). Issued only to the console's client, sts-admin-console, through the ADMIN_CONSOLE role it confers.",
              `device:compliance`:"Report device compliance through POST /admin-api/device-compliance, and nothing else — the scope an MDM or posture feed holds (#164). Issued only to a client that declares it."
            }
          }
        }
      },
      `bearerAuth`:#{
        `type`:"http",
        `scheme`:"bearer",
        `bearerFormat`:"JWT",
        `description`:"The same token, pasted. Use this when you already hold one — from a launcher's `STS_ADMIN_API_TOKEN`, from the console's API explorer, or from a shell — rather than minting one here."
      }
    }
  },
  `x-iya-doc`:"console"
})
namespace IyaSts.Api.Console {
  

@js(#{
    `description`:"What the console's own action functions return, unchanged. `ok` is true when the operation was applied and false when it was refused; a refusal carries `errors` and is answered with HTTP 400. Successful replies carry `message` — the sentence the console would have shown — plus whatever the action produced: `claims` for a claim set, `selected` for the credential claim set, `requested` for the verifier request, `revoked` for a count.",
    `additionalProperties`:true
  }) @component model `ActionResult` {
    @js(#{`description`:"Whether the operation was applied."}) `ok`: boolean;
    @js(#{
      `description`:"What happened, in the words the console would have used. Present on success."
    }) `message`?: string;
    @js(#{`description`:"Why it was refused. Present when `ok` is false."}) `errors`?: (string)[]
  }

@js(#{
    `description`:"One thing this service issued and still remembers. Claims and facts only: the signed token, the assertion XML and the ticket are deliberately not kept.",
    `patternProperties`:#{
      `^iss$`:#{
        `anyOf`:#[
          #{`type`:"string"},
          #{`type`:"number"},
          #{`type`:"boolean"},
          #{`type`:"null"},
          #{
            `type`:"array",
            `items`:#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"},#{`type`:"boolean"}]}
          }
        ]
      },
      `^audience$`:#{`type`:"string"},
      `^x5t$`:#{`type`:"string"},
      `^x5tSpki$`:#{`type`:"string"},
      `^sessionAuthenticated$`:#{`type`:"boolean"},
      `^grantId$`:#{`type`:"string"},
      `^grantRefresh$`:#{`type`:"boolean"},
      `^order$`:#{`type`:"integer"},
      `^revocationReach$`:#{`type`:"string"},
      `^expiresAt$`:#{`type`:"number"},
      `^subject$`:#{`type`:"string"},
      `^id$`:#{`type`:"string"},
      `^signed$`:#{`type`:"boolean"},
      `^realm$`:#{`type`:"string"},
      `^service$`:#{`type`:"string"},
      `^etype$`:#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]},
      `^claimSet$`:#{`type`:"string"},
      `^pacClaims$`:#{`type`:"number"},
      `^entryId$`:#{`type`:"string"},
      `^serial$`:#{`type`:"string"},
      `^hint$`:#{`type`:"string"},
      `^person$`:#{`type`:"string"},
      `^configId$`:#{`type`:"string"}
    }
  }) @component model `IssuedRecord` {
    @js(#{
      `description`:"token, assertion, ticket or svid: what the `family` filter takes."
    }) `family`?: string;
    @js(#{
      `description`:"access_token, id_token, refresh_token, a SAML assertion version, a Kerberos ticket type or an SVID type."
    }) `kind`?: string;
    @js(#{
      `description`:"valid, expired, revoked, \"not yet valid\" or \"no expiry stated\"."
    }) `state`?: string;
    `jti`?: StringOrNumericOrBooleanEtc3;
    `sub`?: StringOrNumericOrBooleanEtc3;
    `username`?: StringOrNumericOrBooleanEtc3;
    `typ`?: StringOrNumericOrBooleanEtc3;
    `issuedAt`?: numeric;
    `expiresAtMs`?: NullableNumber;
    `revocable`?: boolean;
    `revoked`?: boolean;
    `revokedAt`?: NullableNumber;
    `revokedVia`?: string;
    `sessionId`?: string;
    `setId`?: string;
    `jkt`?: string;
    `grant`?: string;
    `client_id`?: StringOrNumericOrBooleanEtc3;
    `scope`?: StringOrNumericOrBooleanEtc3;
    `identifier`?: StringOrNumericOrBooleanEtc3;
    `length`?: integer;
    `key`?: string;
    `iat`?: numeric;
    `nbf`?: numeric;
    `exp`?: numeric
  }

@js(#{
    `description`:"One custom claim. `nameFormat` applies to the SAML 2.0 set and `namespace` to the SAML 1.1 set; both are ignored by the two JWT sets."
  }) @component model `ClaimEntry` {
    `name`: string;
    @js(#{
      `description`:"May carry a placeholder such as \${username}; `GET /admin-api/claims` lists the ones this service expands."
    }) `value`?: string;
    `nameFormat`?: string;
    `namespace`?: string;
    @js(#{
      `description`:"AN ATTRIBUTE CLAIM (#94), in place of `value`: the directory attribute of the person the artifact is about that the claim carries. Only the directory, never an invented value; absent on the entry, the claim is absent. A secret, a binary value or an attribute this service keeps (sts*, hoba*, app*, pwd*) is refused."
    }) `attribute`?: string;
    @js(#{
      `description`:"An attribute claim: every value (a JSON array; several AttributeValues) rather than the first."
    }) `multi`?: boolean;
    @js(#{
      `description`:"An attribute claim in a JWT or UserInfo set: the JSON type each value becomes (string, number, boolean, json). A value that is not one is left out. Ignored by the SAML sets. In the Kerberos PAC set (#493) EVERY row has one, of string, int64, uint64 and boolean — the PAC claim type."
    }) `type`?: "string" | "number" | "boolean" | "json" | "int64" | "uint64"
  }

@js(#{
    `description`:"What this API is, where its document is, and every operation it offers."
  }) @component model `ApiIndex` {
    `name`?: string;
    @js(#{
      `description`:"M.N.O.<build>: the release the repo-root VERSION file declares, followed by the build number. A stamp written before build numbers returned (#1317) reports the bare M.N.O."
    }) `version`?: string;
    @js(#{
      `description`:"The build number on its own: the UTC build instant as YYYYMMDDHHMMSS, or the BUILD_NUMBER a release build named. Absent on a stamp that carries none."
    }) `build`?: string;
    @js(#{
      `description`:"True when this build was flagged as a release (STS_RELEASE=true) and named its build number."
    }) `release`?: boolean;
    @js(#{
      `description`:"The first twelve characters of the commit this was built from. Absent when the build could not know it."
    }) `commit`?: string;
    @js(#{`description`:"When this build was made. Read it with `stamped`."}) `builtAt`?: string;
    @js(#{
      `description`:"True when this version came off a record written at image build time. False means the process computed its own record at startup, so `builtAt` and the build number are the moment it started."
    }) `stamped`?: boolean;
    @js(#{`description`:"Where the document is."}) `openapi`?: string;
    @js(#{`description`:"Where the explorer is."}) `docs`?: string;
    @js(#{`description`:"Where the console every operation mirrors is."}) `console`?: string;
    @js(#{
      `description`:"Whether this API requires an access token (`adminApi.authRequired`, on by default)."
    }) `protected`?: boolean;
    @js(#{
      `description`:"Every management operation, with the console page it mirrors. The console's own operations are listed by GET /admin-api/console/operations (#454)."
    }) `operations`?: (WithMethodPathOperationIdEtc)[]
  }

@js(#{
    `description`:"What this service is and how much it has done since it started."
  }) @component model `Status` {
    `issuer`?: string;
    `startedAt`?: string;
    `uptimeMs`?: numeric;
    @js(#{`description`:"Endpoint calls served."}) `calls`?: integer;
    `tokensHeld`?: integer;
    @js(#{
      `description`:"True when the token register is read on demand (#820): tokensHeld counts the recent tokens this process holds, not every token issued."
    }) `tokensHeldOnly`?: boolean;
    `tokensRevoked`?: integer;
    @js(#{
      `description`:"Assertions, tickets and credentials: everything that is not a JWT."
    }) `artifactsHeld`?: integer;
    @js(#{`description`:"Browser sign-on sessions really held."}) `signOnSessions`?: integer;
    `usersKnown`?: integer;
    `usersAuthenticatedHere`?: integer;
    @js(#{`description`:"The console pages this API mirrors."}) `pages`?: (string)[]
  }

@js(#{
    `description`:"Everything counted: endpoint calls by matched route and status class, tokens and artifacts by kind, and sessions counted BOTH ways."
  }) @component model `Metrics` {
    @js(#{`description`:"Milliseconds since the epoch."}) `startedAt`?: numeric;
    `startedAtIso`?: string;
    @js(#{
      `description`:"When this snapshot was taken, in milliseconds, so that every age in it can be worked out without trusting the caller's clock."
    }) `now`?: numeric;
    `uptimeMs`?: numeric;
    @js(#{`description`:"The custom claim sets and how many claims each holds."}) `claims`?: (WithIdLabelCountEtc4)[];
    @js(#{`description`:"Endpoint calls, in total and per matched route."}) `calls`?: WithTotalPathsPathsHereEtc8;
    @js(#{`description`:"JWTs by kind, with the state of each."}) `tokens`?: WithHeldHeldOnlyForgottenEtc6;
    `artifacts`?: WithHeldHeldHereForgottenEtc5;
    `users`?: WithKnownCapHeldOnlyEtc7;
    `sessions`?: WithFamiliesDistinctSubjects;
    `signOnSessions`?: WithHeldActiveWindowedEtc5
  }

@js(#{
    `description`:"One live thing: a session, a credential, a relying party, a directory connection, or an artifact that cannot be ended at all.",
    `additionalProperties`:true
  }) @component model `LogoutRow` {
    @js(#{
      `description`:"What `POST /admin-api/logout/end` takes in `select`. It is `<family>:<handle>`, and for a row whose natural key is a CREDENTIAL — an authorization code, a pre-authorized code — the handle is a hash of it and never the value: a code in a reply is a code in a log."
    }) `id`?: string;
    @js(#{`description`:"Which family it belongs to."}) `family`?: string;
    @js(#{`description`:"What it is, in that family's own vocabulary."}) `kind`?: string;
    @js(#{`description`:"The thing itself, for a person."}) `label`?: string;
    @js(#{`description`:"Who issued it, to whom, and what rides on it."}) `detail`?: string;
    @js(#{`description`:"Epoch ms, or 0 where the family cannot say."}) `startedAt`?: integer;
    @js(#{
      `description`:"Epoch ms, or 0 for \"no expiry was stated\" — which is the honest answer for several of these rather than an expiry of now."
    }) `expiresAt`?: integer;
    @js(#{
      `description`:"FALSE means nothing can end it — not this service and not a real one. Nothing consults the issuer when a SAML assertion, a Kerberos service ticket or an X509-SVID is presented, so there is no revocation to perform. `why` says so in a sentence."
    }) `terminable`?: boolean;
    @js(#{
      `description`:"When `terminable` is false, the reason. Empty otherwise."
    }) `why`?: string;
    @js(#{
      `description`:"The browser sign-on session it hangs off, where there is one. Empty is a fact about the row — the direct grants have no session — rather than a gap."
    }) `sessionId`?: string
  }

@js(#{
    `description`:"One family of live things, and the prose saying what a logout does and does not reach in it.",
    `additionalProperties`:true
  }) @component model `LogoutFamily` {
    `id`?: string;
    `label`?: string;
    `protocol`?: string;
    @js(#{
      `description`:"The document this family's behaviour comes from, or a sentence saying there is none to cite — which is the answer for everything that cannot be recalled."
    }) `spec`?: string;
    `what`?: string;
    `terminable`?: boolean;
    @js(#{`description`:"How many are live."}) `held`?: integer;
    @js(#{
      `description`:"How many were held back by `logout.maxRows`. The cap is on what is LISTED and never on what a termination reaches: a global logout still ends every one of them."
    }) `notListed`?: integer;
    @js(#{
      `description`:"Set when this family could not be read. The rest of the reply is unaffected — a family that cannot answer is reported rather than taking the whole inventory down."
    }) `failure`?: string;
    `rows`?: (`LogoutRow`)[]
  }

@js(#{
    `description`:"Every key pair this realm holds, what each is used for, and which can be exported."
  }) @component model `KeyList` {
    `issuer`?: string;
    @js(#{
      `description`:"The signing keys belong to this realm; the TLS key to the process."
    }) `realm`?: string;
    @js(#{
      `description`:"The settings this page draws, described: the same rows GET /config returns, filtered to the ones this page owns."
    }) `settings`?: WithPageDescriptionGroupsEtc15;
    `regeneratedEveryStart`?: boolean;
    `residency`?: WithPersistingRetentionPlaintextTtlSEtc6;
    @js(#{
      `description`:"Every format the exporter knows. What a PARTICULAR key offers is its own `formats`."
    }) `formats`?: (string)[];
    `verifiesCredentials`?: boolean;
    `keys`?: (WithDescriptionIdLabelEtc)[];
    `rotation`?: NullableObject39;
    `warning`?: string
  }

@js(#{
    `description`:"Which key, in which format, under which password.",
    `additionalProperties`:true
  }) @component model `KeyExportRequest` {
    @js(#{`description`:"The `id` from GET /admin-api/keys."}) `key`?: string;
    `format`?: "pem" | "der" | "jwk" | "pkcs12";
    @js(#{
      `description`:"REQUIRED for `pkcs12`. Optional for the other three, where it encrypts the private half — PKCS#8 for PEM and DER, PBES2 as a .jwe for JWK. Empty means the private key comes out in the clear, which is usually what is wanted in development and never anywhere else."
    }) `password`?: string
  }

@component model `KeyExport` {
    `ok`: boolean;
    `message`?: string;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    @js(#{`description`:"One line about what came out."}) `status`?: string;
    @js(#{
      `description`:"True for a post-quantum key, which comes out as its public half."
    }) `publicOnly`?: boolean;
    `files`?: (WithNameMimeBytesEtc)[]
  }

@js(#{
    `description`:"What this service does when it signs, verifies, encrypts or decrypts, for every identity service it advertises. Every algorithm list is READ FROM THE MODULE THAT PERFORMS THE ALGORITHM, so it cannot claim something this service does not do."
  }) @component model `CryptoMetadata` {
    `signaturePolicy`?: WithPqcOnlySurfaces;
    @js(#{`description`:"This service as the request reached it."}) `issuer`?: string;
    @js(#{
      `description`:"The trust realm the key material below belongs to. The ALGORITHM tables are process-wide; the SIGNING KEYS are per realm."
    }) `realm`?: string;
    `generatedAt`?: string;
    @js(#{`description`:"Where all of this happens."}) `oneModule`?: string;
    `drift`?: WithCheckedUndescribedStaleEtc4;
    `keys`?: WithRealmRegeneratedEveryStartSigningEtc9;
    `families`?: (WithNameSignsVerifiesEtc10)[];
    `hashing`?: WithJwsXmlDigestMethodsScimDigestEtc5;
    `signatures`?: WithJwsXmlCanonicalizationEtc5;
    `encryption`?: WithJweXmlKerberosEtc4;
    @js(#{
      `description`:"The one to read before quoting this reply: signatures and key establishment are reported separately, because a signature is checked when it is presented while captured ciphertext can be kept and opened later."
    }) `postQuantum`?: WithAlgorithmsSignaturesKeyEstablishmentEtc4;
    `standards`?: (WithKeyNameSpecsEtc5)[]
  }

@js(#{
    `description`:"Every session this service is holding right now, filtered and paged."
  }) @component model `SessionList` {
    `installed`?: boolean;
    `note`?: string;
    `held`?: numeric;
    `matched`?: numeric;
    `shown`?: numeric;
    `heldByKind`?: Record<numeric>;
    `filter`?: WithQProtocol;
    `protocols`?: (string)[];
    `at`?: numeric;
    `expiryRules`?: Record<string>;
    `sessions`?: (`SessionRow`)[];
    `unauthenticatedHeld`?: numeric;
    `unauthenticatedKept`?: boolean;
    `unauthenticatedSessions`?: (`SessionRow`)[];
    `unauthenticatedPaging`?: WithPagePagesPerPageEtc8;
    `windowed`?: boolean;
    `accountChoices`?: WithEnabledCounts;
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: WithPagePagesPerPageEtc8
  }

@js(#{`description`:"One live session of any kind."}) @component model `SessionRow` {
    `id`?: string;
    `family`?: string;
    `kind`?: string;
    `derivedFrom`?: string;
    `rpClientId`?: string;
    `key`?: string;
    `username`?: string;
    `sub`?: string;
    `protocol`?: string;
    `handle`?: string;
    `sessionId`?: string;
    `startedAt`?: numeric;
    `expiresAt`?: numeric;
    `expiryRule`?: string;
    `amr`?: StringOrString;
    `acr`?: string;
    `deviceBound`?: NullableObject40;
    `carries`?: (string)[];
    `detail`?: string;
    `authenticated`?: boolean;
    `accountSet`?: string;
    `terminable`?: boolean;
    `why`?: string
  }

@js(#{
    `description`:"One OpenID Connect Back-Channel Logout 1.0 delivery: a signed (and, where the client registered it, encrypted) Logout Token this service POSTs to a relying party's registered backchannel_logout_uri when a session it was issued an authorization response on ends. A row of a persisted, replicated store — every node lists every node's — and the token itself is never in a reply.",
    `additionalProperties`:true
  }) @component model `BackchannelDelivery` {
    @js(#{
      `description`:"Derived from the session and the client, so the same delivery planned by two processes is one row. What `retry-backchannel` names."
    }) `id`?: string;
    `realm`?: string;
    @js(#{
      `description`:"The sign-on session whose end it reports — the Logout Token's `sid`."
    }) `sessionId`?: string;
    @js(#{`description`:"The token's `aud`."}) `clientId`?: string;
    `uri`?: string;
    @js(#{
      `description`:"What the client registered as backchannel_logout_session_required. `sid` is sent either way."
    }) `sessionRequired`?: boolean;
    @js(#{
      `description`:"`pending` until it is accepted (`sent`: 200 or 204) or finally fails — refused with 400, refused by the outbound policy, or out of attempts — as a DEAD LETTER (`dead`), which is sent again only by `retry-backchannel`. A sign-out answers BEFORE its deliveries are made, so its own reply says `pending`."
    }) `state`?: "pending" | "sent" | "dead";
    @js(#{
      `description`:"1, and one more for each operator retry; each generation is a new Logout Token."
    }) `generation`?: integer;
    @js(#{`description`:"Attempts recorded in this generation."}) `attempts`?: integer;
    @js(#{
      `description`:"An attempt is claimed and not yet recorded — being sent now, or by a process that died, in which case another takes it over when its lease lapses."
    }) `inFlight`?: boolean;
    @js(#{`description`:"The host and process that last claimed an attempt."}) `holder`?: string;
    @js(#{`description`:"The last HTTP status, or 0 where none came back."}) `status`?: integer;
    @js(#{`description`:"The STS-OAUTH-05xx code of the last failure."}) `errorCode`?: string;
    `why`?: string;
    @js(#{`description`:"Which door ended the session."}) `via`?: string;
    @js(#{
      `description`:"A sign-out (any door, an account disabled included), an expiry, or a relying party forgotten on a session that stays."
    }) `trigger`?: "sign-out" | "expiry" | "forget";
    @js(#{
      `description`:"The JWE alg and enc the token was encrypted with, or empty."
    }) `encrypted`?: string;
    @js(#{`format`:"date-time"}) `queuedAt`?: string;
    @js(#{`description`:"ISO 8601 while pending, else empty."}) `nextAttemptAt`?: string;
    @js(#{`description`:"ISO 8601, or empty before the first."}) `lastAttemptAt`?: string;
    @js(#{`description`:"ISO 8601, or empty while pending."}) `finishedAt`?: string
  }

@js(#{
    `description`:"What this service is still holding for one identity, across every protocol family — or, with no `user`, the list of families a logout reaches.",
    `additionalProperties`:true
  }) @component model `LogoutInventory` {
    @js(#{`description`:"The name that was asked about."}) `user`?: string;
    @js(#{
      `description`:"FALSE with no `user` means this is the family list rather than an identity."
    }) `known`?: boolean;
    @js(#{
      `description`:"The normalised identity key everything is filed under — what folds `alice`, `alice@REALM` and a `urn:` subject into one answer."
    }) `key`?: string;
    @js(#{`description`:"Browser sign-on sessions held."}) `sessions`?: integer;
    @js(#{`description`:"Live items in every family."}) `total`?: integer;
    `listed`?: integer;
    `notListed`?: integer;
    @js(#{`description`:"The `logout.maxRows` cap."}) `maxRows`?: integer;
    @js(#{
      `description`:"Whether the CONSOLE session on the request holds Admin Write. A call carrying only this API's access token has no console session, so this reads false there; what that token may do is decided by its scope at this API's gate."
    }) `canWrite`?: boolean;
    `families`?: (`LogoutFamily`)[];
    @js(#{
      `description`:"The same rows flattened, filtered and paged — which is what the console table shows."
    }) `rows`?: (`LogoutRow`)[];
    @js(#{
      `description`:"The back-channel Logout Token deliveries in this realm, from EVERY node, newest first, with or without `user`, narrowed by `deliveryState` and `deliveryq` and paged by `backchannelDeliveriesPage` — where a delivery a sign-out reported as `pending` is seen to have arrived, and where the dead letters are. Every final outcome is also a `logout.backchannel` audit row."
    }) `backchannelDeliveries`?: (`BackchannelDelivery`)[];
    @js(#{
      `description`:"Where `backchannelDeliveries` came from in the whole list: the page, how many there are, and the 1-based row numbers this page covers. Same member names the flat lists carry at the top level, one level down."
    }) `backchannelDeliveriesPaging`?: WithDescriptionTotalDescriptionEtc12;
    @js(#{
      `description`:"How many deliveries this realm holds in each state.",
      `additionalProperties`:true
    }) `backchannelCounts`?: WithPendingSentDescriptionEtc4;
    @js(#{`description`:"The state asked for, or empty."}) `deliveryState`?: string;
    @js(#{`description`:"The search asked for, or empty."}) `deliveryq`?: string;
    @js(#{
      `description`:"The page these rows are from, CLAMPED — `?page=999` on a two-page list reports 2, which is the page in the reply."
    }) `page`?: integer;
    @js(#{`description`:"How many pages the match has."}) `pages`?: integer;
    @js(#{`description`:"Rows per page, clamped to the cap."}) `perPage`?: integer;
    @js(#{`description`:"1-based and inclusive; 0 when nothing matched."}) `firstRow`?: integer;
    @js(#{`description`:"1-based and inclusive."}) `lastRow`?: integer
  }

@js(#{
    `description`:"Everyone this service has authenticated, united with at most `scanLimit` of the people the directory defines."
  }) @component model `UserList` {
    `known`?: numeric;
    `matched`?: numeric;
    `shown`?: numeric;
    `authenticatedHere`?: numeric;
    `factors`?: WithWithSecondWithTotpWithKeysEtc7;
    `store`?: boolean;
    `scanned`?: numeric;
    `capped`?: boolean;
    `scanLimit`?: numeric;
    `directoryPeople`?: NullableNumber;
    `directoryCounts`?: NullableObject41;
    `directoryCountedAt`?: NullableString;
    `directoryCountsKeptFor`?: NullableNumber;
    `registryCap`?: numeric;
    `filter`?: WithQProtocolFactorEtc4;
    `serviceAccounts`?: numeric;
    `protocols`?: (string)[];
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: WithPagePagesPerPageEtc8;
    `withActiveSession`?: NullableNumber;
    `personFieldCount`?: numeric;
    `newUserContainer`?: string;
    `registryKeeps`?: numeric;
    `users`?: (WithKeyNameFormsEtc22)[]
  }

@js(#{
    `description`:"One identity: the names it has been seen under, how it authenticated, every sign-on session it holds with the tokens issued on each, and its directory entry."
  }) @component model `UserDetail` {
    `known`?: boolean;
    `user`?: WithKeyNameFormsEtc17;
    `subject`?: string;
    `serviceAccount`?: NullableObject43;
    `risk`?: NullableObject44;
    `factors`?: NullableObject45;
    `sessions`?: (WithIdUsernameSubEtc15)[];
    `sessionsPaging`?: WithPagePagesPerPageEtc8;
    `tokensOnEndedSessions`?: (WithStateKeyJtiEtc29)[];
    `tokensOnEndedSessionsPaging`?: WithPagePagesPerPageEtc8;
    `tokensWithNoSession`?: (WithStateKeyJtiEtc29)[];
    `tokensWithNoSessionPaging`?: WithPagePagesPerPageEtc8;
    `artifacts`?: (WithStateKindIssuedAtEtc23)[];
    `artifactsPaging`?: WithPagePagesPerPageEtc8;
    `ldap`?: NullableObject46;
    `credentials`?: WithStorableFoundKeyPairsEtc9;
    `federationLinks`?: (WithLinkRelationshipIssuerEtc5)[];
    `federationLinksPaging`?: WithPagePagesPerPageEtc8;
    `kerberos`?: WithKdcRealmTrustRealmEtc11;
    `attributeEditor`?: NullableObject49;
    `gnapGrants`?: (WithIdStateFinalizationEtc18)[];
    `gnapGrantsPaging`?: NullableObject50;
    `gnapGrantsCells`?: NullableObject51;
    `uma`?: NullableObject52;
    `authenticationEvents`?: (WithSeqOriginAtEtc17)[];
    `authenticationEventsPaging`?: WithPagePagesPerPageEtc8;
    `authenticationEventsMatched`?: numeric;
    `authenticationEventsKnownActors`?: Record<boolean>;
    `authenticationEventsLog`?: WithHeldRecordedDroppedEtc4;
    `page`?: {
      `key`?: string;
      `riskAsked`?: boolean;
      `counts`?: WithLiveTokensValidEtc7;
      `back`?: string;
      `params`?: Record<StringOrNumericOrBooleanEtcOrStringOrNumericOrBooleanEtc>;
      `blocksPerPage`?: numeric;
      `perPage`?: numeric;
      `maxEventsPerUser`?: numeric;
      `directoryLoaded`?: boolean;
      `mfa`?: WithStorableMechTotpEtc15;
      `fieldGroups`?: (WithIdLabelWhatEtc4)[];
      `delegation`?: WithFoundPersonUsernameEtc11;
      `keyPairs`?: WithStorableFoundUsernameEtc10;
      `serviceAccountRules`?: WithRequiresOwnerMaxOwnersDn;
      `serviceProviders`?: (WithFedIdFedPeer)[]
    }
  }

@component model `Saml2ServiceProviderList` {
    `protocolEndpoints`?: (WithNameMethodsUrlEtc6)[];
    `serviceProviders`?: (WithNameAuthenticationsSessionsEtc19)[];
    `paging`?: WithPagePagesPerPageEtc9;
    `unscopedMetadata`?: string;
    `settings`?: WithPageGroupsSettingCountEtc11;
    `artifactsAwaitingResolution`?: numeric;
    `requestsHeldForSignIn`?: numeric;
    `mdqRefused`?: (WithEntityIdWhyFirstAtEtc5)[];
    `mdqRefusedPaging`?: WithPagePagesPerPageEtc9;
    `kind`?: string;
    `found`?: boolean;
    `name`?: string;
    `authentications`?: numeric;
    `assertionConsumerServices`?: (string)[];
    `singleLogoutServices`?: (string)[];
    `nameIdFormats`?: (string)[];
    `responseBindings`?: (string)[];
    `lastRequestSigned`?: boolean;
    `lastRequestVerification`?: WithOutcomeBindingSignatureMethodEtc4;
    `signingCertificate`?: string;
    `signingCertificates`?: (string)[];
    `observedSigningCertificate`?: string;
    `signedRequestsRequired`?: WithRequiredWhy;
    `metadata`?: WithStateStateWhyExpiresAtEtc27;
    `identifier`?: string;
    `slug`?: NullableString;
    `idpEntityId`?: NullableString;
    `metadataUrl`?: string;
    `ssoUrl`?: string;
    `sloUrl`?: string;
    `arsUrl`?: string
  }

@component model `FederationRelationshipList` {
    `relationshipCount`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `ready`?: IntegerOrBoolean;
    `filter`?: WithQRoleCategory;
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `container`?: NullableString;
    `max`?: numeric;
    `settings`?: NullableObject61;
    `roles`?: (WithRoleLabelShortEtc4)[];
    `protocols`?: (WithProtocolLabelFamilyEtc7)[];
    `paths`?: WithBaseLoginAcsEtc18;
    `paging`?: WithPagePagesPerPageEtc8;
    `roleCounts`?: Record<numeric>;
    `categoryCounts`?: Record<numeric>;
    `consumerProviders`?: WithOnCatalogue;
    `enabledNotConfigured`?: integer;
    `authentications`?: integer;
    `relationships`?: (WithIdNameRoleEtc26)[];
    `found`?: boolean;
    `id`?: string;
    `name`?: string;
    `role`?: string;
    `roleLabel`?: string;
    `protocol`?: string;
    `protocolLabel`?: string;
    `peer`?: string;
    `application`?: string;
    `category`?: string;
    `provider`?: StringOrNullOrIdStringLabelStringNoteStringDocsStringRealmOnBoolean;
    `providerLabel`?: string;
    `enabled`?: boolean;
    `missing`?: (string)[];
    `usable`?: boolean;
    `signsIn`?: boolean;
    `signalsEnabled`?: boolean;
    `releases`?: (string)[];
    `mappings`?: (string)[];
    `users`?: integer;
    `lastUser`?: string;
    `lastSeen`?: string;
    `lastError`?: string;
    `lastErrorAt`?: string;
    `dn`?: string;
    `endpoints`?: WithAssertionConsumerServiceLoginMetadataEtc10;
    `fields`?: WithFedIdCnFedNameEtc89;
    `editable`?: (WithNameKindRoleEtc9)[];
    `unmappedAttributes`?: (WithNameRefusedFirstEtc4)[];
    `signals`?: NullableObject62;
    `signalArrivals`?: (WithRelationshipJtiViaEtc15)[];
    `outboundSignals`?: NullableObject63;
    `encryption`?: NullableObject64;
    `clientCertificate`?: NullableFederationClientCertificate;
    `links`?: (WithUsernameDnLinkEtc5)[];
    `linksPaging`?: WithPagePagesPerPageEtc8;
    `setFields`?: (WithNameKindRoleEtc9)[];
    `multiFields`?: (WithNameKindRoleEtc9)[];
    `signalSetFields`?: (WithNameKindRoleEtc9)[];
    `schema`?: (WithNameKindRoleEtc9)[];
    `enumLabels`?: Record<string>;
    `defaultSubjectPolicy`?: string;
    `autocreateDefault`?: boolean;
    `subjectPolicy`?: string;
    `encrypts`?: boolean;
    `base`?: string;
    `loginHref`?: string;
    `metadataUrl`?: string;
    `signOut`?: WithSingleLogoutSignOutCleanupBackchannelLogoutEtc5;
    `protocolEndpoints`?: (WithNameMethodsUrlEtc72)[]
  }

@component model `Saml11RelyingPartyList` {
    `protocolEndpoints`?: (WithNameMethodsUrlEtc6)[];
    `relyingParties`?: (WithNameAuthenticationsSessionsEtc15)[];
    `paging`?: WithPagePagesPerPageEtc9;
    `unscopedMetadata`?: string;
    `settings`?: WithPageGroupsSettingCountEtc11;
    `artifactsAwaitingResolution`?: numeric;
    `assertionsHeldByReference`?: numeric;
    `flowsHeldForSignIn`?: numeric;
    `kind`?: string;
    `registered`?: boolean;
    `identifierLooksGuessed`?: boolean;
    `name`?: string;
    `authentications`?: numeric;
    `assertionConsumerServices`?: (string)[];
    `nameIdFormats`?: (string)[];
    `profiles`?: (string)[];
    `identifier`?: string;
    `slug`?: NullableString;
    `idpProviderId`?: NullableString;
    `metadataUrl`?: string;
    `ssoUrl`?: string;
    `responderUrl`?: string
  }

@component model `SamlIdpInitiatedList` {
    `protocolEndpoints`?: (WithNameMethodsUrlEtc6)[];
    `idpInitiated`?: (WithIdentifierNameEntityIdEtc9)[];
    `idpInitiatedPaging`?: WithPagePagesPerPageEtc82;
    `realmSwitches`?: (WithProtocolLabelSettingEtc5)[]
  }

@component model `AuthorizationServerList` {
    `profileCount`?: integer;
    `shown`?: integer;
    `members`?: (WithNameGroupKindEtc6)[];
    `paging`?: WithPagePagesPerPageEtc8;
    `overrideTotal`?: integer;
    `driftTotal`?: integer;
    `authorizationServers`?: (WithIdLabelDescriptionEtc14)[];
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `id`?: string;
    `label`?: string;
    `description`?: string;
    @js(#{`description`:"The members this server overrides."}) `overrides`?: Record<Shape4>;
    `removed`?: (string)[];
    `changedAt`?: string;
    `memberCount`?: integer;
    `autoCreated`?: boolean;
    `seen`?: numeric;
    `seenAt`?: string;
    `createdAt`?: string;
    `urls`?: WithOauthOidcAuthorizeEtc4;
    `found`?: boolean;
    `drift`?: (WithMemberXFreeFormDescriptionEtc9)[];
    @js(#{
      `x-free-form`:"The RFC 8414 document this server would publish: what this service builds, with the operator's overrides, whose values are any JSON.",
      `description`:"The RFC 8414 document this server would publish: what this service builds, with the operator's overrides, whose values are any JSON."
    }) `capabilities`?: unknown;
    `memberGroups`?: (string)[]
  }

  

@hoisted union ApplicationList_page_h466 {
    integer,
    {
      @js(#{`description`:"What each attribute of the entry is."}) `notes`?: Record<{`text`?: string; `sensitive`?: boolean}>;
      `config`?: WithFieldsDescriptionValuesEtc18;
      `passkeyPolicies`?: WithNamedMissingAppliesEtc6;
      @js(#{`description`:"By protocol."}) `launchUrls`?: Record<{
        `protocol`?: string;
        `label`?: string;
        `url`?: string;
        `enabled`?: boolean;
        `setting`?: string;
        `attribute`?: string;
        `missing`?: (string)[];
        `endpoint`?: NullableString
      }>;
      `cors`?: (WithStoredCanonical)[];
      `accessTypes`?: (WithStoredTypeDescriptionEtc29)[];
      `fga`?: NullableObject68;
      `permissionClaims`?: WithPermissionsStaleCatalogue;
      `grantsUncataloguedAccess`?: boolean;
      `acceptsUnregisteredAddresses`?: boolean;
      `protocolRows`?: (WithIdLabelKindsEtc4)[];
      `editable`?: WithSetMultiMultiAll;
      `did`?: WithDidUrlOkEtc6;
      `credentials`?: WithOauthDeclaredClientSecretPurposesEtc8;
      `signals`?: WithInstalledStreamsSettingsEtc4;
      `softwareStatement`?: WithIssuersUsableKeysKeyProblemsEtc8;
      `roles`?: WithHeldOfferableRequiredEtc4;
      `permissions`?: WithHeldExposesOfferableEtc8;
      `lifetimes`?: WithRowsSkew;
      `claims`?: (WithIdLabelAttributeEtc6)[];
      `claimSelections`?: WithCataloguePreviewSetsEtc4;
      `enrollment`?: WithCredentialsConfig;
      `observed`?: WithPagingShown;
      `warnings`?: (WithAttributeValueReasonEtc5)[];
      `owners`?: (WithDnKindNameEtc4)[];
      `maxOwners`?: numeric;
      `ownership`?: WithKindNameMarkedEtc5;
      `krb5Across`?: NullableObject75
    }
  }

  

@component model `ApplicationList` {
    `applicationCount`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `registered`?: BooleanOrNumeric;
    `filter`?: WithQKindExclude;
    `container`?: NullableString;
    `max`?: NullableNumber;
    `kinds`?: (StringOrKindStringLabelStringWhatString)[];
    `settings`?: NullableObject65;
    `paging`?: WithPagePagesPerPageEtc8;
    @js(#{`description`:"How many applications are of each kind."}) `kindCounts`?: Record<integer>;
    `authentications`?: numeric;
    `protocols`?: (StringOrIdStringLabelStringKindStringKindsStringIdentifierAttributeStringRedirectAttributeStringLogoutAttributeStringDeliveryAttributeStringEventsAttributeStringSecretAttributeStringWhatString)[];
    `applications`?: (WithIdentifierDnLabelDnEtc27)[];
    `page`?: ApplicationList_page_h466;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `identifier`?: string;
    `dnLabel`?: NullableString;
    `dn`?: NullableString;
    `name`?: NullableString;
    `allowedProtocols`?: (string)[];
    `recordedProtocols`?: (string)[];
    `declaredKinds`?: (string)[];
    `registeredBy`?: string;
    `returnAddressesObserved`?: (WithAttributeValueHeldEtc4)[];
    `firstSeen`?: string;
    `lastSeen`?: string;
    `sessions`?: numeric;
    `users`?: numeric;
    `description`?: NullableString;
    `origin`?: NullableString;
    `createdAt`?: NullableString;
    `modifiedAt`?: NullableString;
    `operational`?: (string)[];
    @js(#{`description`:"By attribute name."}) `attributes`?: Record<StringOrNumericOrBooleanEtc4>;
    @js(#{`description`:"By attribute name."}) `fields`?: Record<StringOrNumericOrBooleanEtc3>;
    `found`?: boolean;
    `warnings`?: (WithAttributeValueReasonEtc5)[];
    `attributesShown`?: (WithNameValuesSealedAtRestEtc4)[];
    `attributesPaging`?: WithPagePagesPerPageEtc8;
    `authenticationEvents`?: (WithSeqOriginAtEtc16)[];
    `authenticationEventsPaging`?: WithPagePagesPerPageEtc8;
    `authenticationEventsMatched`?: integer;
    @js(#{`description`:"Which actors have a user page."}) `authenticationEventsKnownActors`?: Record<boolean>;
    `authenticationEventsLog`?: WithHeldRecordedDroppedEtc4;
    `returnAddressesObservedShown`?: (WithAttributeValueHeldEtc4)[];
    `returnAddressesObservedPaging`?: WithPagePagesPerPageEtc8;
    `credentials`?: WithClientSecretKeyPairsCaAvailableEtc8;
    `sharedSignals`?: WithInstalledStreamsSettings;
    `certificateEnrollment`?: WithFamiliesRulesCertificateCapEtc10;
    `customClaims`?: (WithIdLabelAttributeEtc6)[];
    `claimSelections`?: WithCataloguePreviewSetsEtc4;
    `tokenLifetimes`?: WithLifetimesClockSkewS;
    `softwareStatements`?: WithDeclaredIssuersUsableKeysIssuedEtc5;
    `applicationRoles`?: WithHeldOfferableRequiredEtc4;
    `delegatedPermissions`?: WithHeldExposesOfferableEtc5;
    `owners`?: (WithDnKindNameEtc4)[];
    `maxOwners`?: numeric
  }

@js(#{
    `description`:"Every attribute a person may be created with, and the four ways they can be given a way in."
  }) @component model `NewUserForm` {
    `directory`?: boolean;
    `container`?: NullableString;
    `why`?: string;
    `realm`?: WithIdName;
    `mode`?: string;
    `offersExampleData`?: boolean;
    `fields`?: (WithAttributeLabelSchemaEtc5)[];
    `fieldGroups`?: (WithIdLabelWhatEtc4)[];
    `gridFields`?: (WithAttributeLabelGroupEtc8)[];
    `requiredAttributes`?: (string)[];
    `requiredEnforced`?: boolean;
    `credentials`?: (WithIdLabelWhat)[];
    `username`?: string;
    `fieldRows`?: (WithAttributeTypeWhatEtc16)[];
    `longTextAttributes`?: (string)[];
    `mailAvailable`?: boolean;
    `persistence`?: WithPersistsDirectoryMode;
    `defaultCredential`?: string;
    `credential`?: string;
    `passwordPolicy`?: WithProfileEnforcedRules;
    `invented`?: NullableObject76;
    `inventRefused`?: string
  }

@component model `NewApplicationForm` {
    `directory`?: boolean;
    `container`?: NullableString;
    `max`?: NullableNumber;
    `applicationCount`?: integer;
    `realm`?: WithIdName;
    `kinds`?: (WithKindLabelWhat)[];
    `protocols`?: (WithIdLabelKindEtc11)[];
    `declarations`?: (WithAttributeRoleKindEtc8)[];
    `fields`?: (WithAttributeTypeLongEtc19)[];
    `fieldGroups`?: (WithIdLabelFamilies)[];
    `familyChoices`?: (WithIdLabelFamiliesEtc5)[];
    `longTextAttributes`?: (string)[];
    `defaultSecretLifetimeDays`?: numeric;
    `persistence`?: WithPersistsDirectoryMode;
    `resourceMetadataImport`?: WithWellKnownAcceptsNonconformingDialsInternalAddresses;
    `editable`?: (WithNameModeSensitiveEtc4)[]
  }

@js(#{`description`:"Every group the embedded directory holds."}) @component model `GroupList` {
    `baseDn`?: string;
    `usersDn`?: string;
    `groupsDn`?: string;
    `port`?: NullableNumber;
    `listening`?: boolean;
    `listenError`?: NullableString;
    `ldapsPort`?: NullableNumber;
    `ldapsListening`?: boolean;
    `entryCount`?: numeric;
    `groupCount`?: numeric;
    `matched`?: numeric;
    `shown`?: numeric;
    `canWrite`?: boolean;
    `membershipValues`?: numeric;
    `dangling`?: numeric;
    `settings`?: NullableObject77;
    `filter`?: WithQExclude;
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: WithPagePagesPerPageEtc8;
    `adminGroups`?: WithReadWrite;
    `groups`?: (WithDnCnRuleEtc14)[]
  }

@component model `DirectoryEntryList` {
    `baseDn`?: string;
    `count`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `filter`?: WithQOrigin;
    `origins`?: (string)[];
    @js(#{`description`:"A count per name."}) `originCounts`?: Record<numeric>;
    `order`?: string;
    `search`?: NullableObject78;
    `entries`?: (WithDnOriginDescriptionEtc4)[];
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: WithPagePagesPerPageEtc82;
    `directory`?: boolean;
    `message`?: string
  }

@component model `DirectoryApplicationList` {
    `baseDn`?: string;
    `container`?: string;
    `count`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `max`?: integer;
    `filter`?: {`q`?: NullableString};
    `sourceOfTruth`?: string;
    `kinds`?: (WithKindLabelWhat)[];
    `schema`?: WithObjectClassesAttributes;
    `applications`?: (WithIdentifierDnLabelDnEtc26)[];
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: WithPagePagesPerPageEtc82;
    `directory`?: boolean;
    `message`?: string
  }

@component model `DirectoryFederationList` {
    `baseDn`?: string;
    `container`?: string;
    `count`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `max`?: integer;
    `filter`?: {`q`?: NullableString};
    `sourceOfTruth`?: string;
    `roles`?: (WithRoleLabelShortEtc4)[];
    `protocols`?: (WithProtocolLabelFamilyEtc7)[];
    `schema`?: WithObjectClassesAttributes;
    `relationships`?: (WithDnCreatedAtModifiedAtEtc99)[];
    `enabledCount`?: integer;
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: WithPagePagesPerPageEtc82;
    `directory`?: boolean;
    `message`?: string
  }

@component model `DirectorySpiffe` {
    `baseDn`?: string;
    `container`?: string;
    `entriesContainer`?: string;
    `agentsContainer`?: string;
    `entries`?: integer;
    `agents`?: integer;
    `maxEntries`?: integer;
    `maxAgents`?: integer;
    `sourceOfTruth`?: string;
    `editable`?: (string)[];
    `schema`?: WithObjectClassesAttributes;
    `filter`?: WithEntryqAgentq;
    `entriesPaging`?: WithPagePagesPerPageEtc82;
    `agentsPaging`?: WithPagePagesPerPageEtc82;
    `registrationEntries`?: (WithIdDnSpiffeIdEtc24)[];
    `attestedAgents`?: (WithIdDnAttestationTypeEtc13)[];
    `directory`?: boolean;
    `message`?: string
  }

@component model `DirectoryRoleList` {
    `baseDn`?: string;
    `container`?: string;
    `count`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `max`?: integer;
    `filter`?: {`q`?: NullableString};
    `sourceOfTruth`?: string;
    `builtIn`?: (string)[];
    `schema`?: WithObjectClassesAttributes;
    `roles`?: (WithNameDnOriginEtc8)[];
    `builtInCatalogue`?: (WithNameWhat)[];
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: WithPagePagesPerPageEtc82;
    `directory`?: boolean;
    `message`?: string
  }

@component model `DirectoryPolicyList` {
    `baseDn`?: string;
    `container`?: string;
    `count`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `max`?: integer;
    `ownCount`?: integer;
    `applicationCount`?: integer;
    `applicationMax`?: integer;
    `filter`?: {`q`?: NullableString};
    `sourceOfTruth`?: string;
    `schema`?: WithObjectClassesAttributes;
    `policies`?: (WithNameDnOriginEtc8)[];
    `enabledCount`?: integer;
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: WithPagePagesPerPageEtc82;
    `directory`?: boolean;
    `message`?: string
  }

@component model `DirectoryPepList` {
    `baseDn`?: string;
    `container`?: string;
    `count`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `max`?: integer;
    `filter`?: {`q`?: NullableString};
    `sourceOfTruth`?: string;
    `schema`?: WithObjectClassesAttributes;
    `peps`?: (WithNameDnOriginEtc8)[];
    `enabledCount`?: integer;
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: WithPagePagesPerPageEtc82;
    `directory`?: boolean;
    `message`?: string
  }

@component model `DirectoryService` {
    `url`?: string;
    `port`?: NullableInteger;
    `listening`?: boolean;
    `listenError`?: NullableString;
    `baseDn`?: string;
    `usersDn`?: string;
    `groupsDn`?: string;
    `namingContexts`?: (string)[];
    `searchScope`?: string;
    `ldapVersion`?: integer;
    `bindPolicy`?: string;
    `refusedPassword`?: string;
    `schema`?: string;
    `referentialIntegrity`?: boolean;
    `persistence`?: WithModeConfiguredModeEnabledEtc32;
    `tls`?: WithLdapsPortUrlEtc10;
    `autoCreateUsers`?: boolean;
    `autoCreateRule`?: string;
    `authenticationFacts`?: string;
    `enforcedRules`?: (string)[];
    `limits`?: WithMaxEntriesMaxSearchResultsCurrentEntriesEtc4;
    `operations`?: (string)[];
    `specifications`?: (string)[];
    `implementation`?: string;
    `ldapPort`?: NullableInteger;
    `ldapsPort`?: NullableInteger;
    `certificateProvenance`?: NullableString;
    `directory`?: boolean;
    `message`?: string
  }

@js(#{
    `description`:"One group, with the same directory facts the list carries around it."
  }) @component model `GroupDetail` {
    `baseDn`?: string;
    `usersDn`?: string;
    `groupsDn`?: string;
    `port`?: NullableNumber;
    `listening`?: boolean;
    `listenError`?: NullableString;
    `ldapsPort`?: NullableNumber;
    `ldapsListening`?: boolean;
    `entryCount`?: numeric;
    `maxEntries`?: numeric;
    `found`?: boolean;
    `requested`?: string;
    `notAGroup`?: boolean;
    `canWrite`?: boolean;
    `group`?: WithDnCnRuleEtc16;
    `groups`?: (WithDnCnRuleEtc14)[];
    `groupCount`?: numeric;
    `policyReferences`?: (WithAttributeNounChoicesEtc4)[];
    `ownership`?: WithKindNameMarkedEtc5;
    `membersPaging`?: WithPagePagesPerPageEtc8;
    `claimedPaging`?: WithPagePagesPerPageEtc8;
    `known`?: Record<boolean>;
    `adminGroups`?: WithReadWrite
  }

@js(#{
    `description`:"One issuance: everything that came back in a single reply."
  }) @component model `IssuedSet` {
    `setKey`?: string;
    `setId`?: string;
    `grouped`?: boolean;
    `size`?: integer;
    `kinds`?: (string)[];
    `families`?: (string)[];
    `family`?: string;
    `state`?: string;
    @js(#{`description`:"How many members are in each state."}) `states`?: Record<integer>;
    `issuedAt`?: numeric;
    `expiresAtMs`?: numeric;
    `lastExpiresAtMs`?: numeric;
    `username`?: StringOrNumericOrBooleanEtc3;
    `sub`?: StringOrNumericOrBooleanEtc3;
    `client_id`?: StringOrNumericOrBooleanEtc3;
    `audience`?: string;
    `scope`?: StringOrNumericOrBooleanEtc3;
    `sessionId`?: string;
    `sessionAuthenticated`?: boolean;
    `grant`?: string;
    `revocableCount`?: integer;
    `revokedCount`?: integer;
    `members`?: (`IssuedRecord`)[]
  }

@js(#{`$comb`:"oneOf"}) @hoisted union IssuedSetDetail_set_h714 {null, `IssuedSet`}

@component model `IssuedSetDetail` {
    `setKey`?: NullableString;
    `set`?: IssuedSetDetail_set_h714;
    `found`?: boolean;
    `why`?: NullableString
  }

@component model `IssuedList` {
    `held`?: integer;
    `heldSets`?: integer;
    `coverage`?: WithSourceCompleteNewestEtc6;
    `matched`?: integer;
    `matchedCredentials`?: integer;
    `shown`?: integer;
    `shownCredentials`?: integer;
    @js(#{`description`:"Credentials held in each family."}) `heldByFamily`?: Record<integer>;
    `filter`?: WithFamilyKindStateEtc4;
    `families`?: (WithFamilyLabelKindsEtc4)[];
    `revocableKinds`?: (string)[];
    `revokedCount`?: integer;
    `sets`?: (`IssuedSet`)[];
    `issued`?: (`IssuedRecord`)[];
    `paging`?: WithPagePagesPerPageEtc8;
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer
  }

@js(#{
    `description`:"Every setting this service has, grouped by the protocol it belongs to. The same table the /admin/config page renders and the same call it makes, so the console and this API cannot come to describe different sets of settings."
  }) @component model `Config` {
    @js(#{`description`:"The realm this was read in."}) `realm`?: string;
    @js(#{`description`:"The keys that realm holds a value of its own for."}) `realmSettings`?: (string)[];
    `configFile`?: NullableString2;
    @js(#{
      `description`:"The DEFAULT appconfig file, which `configFile` is unioned on top of key by key with the operator's value winning. A setting whose `source` is `defaults` came from here."
    }) `defaultsFile`?: string;
    `settingCount`?: integer;
    @js(#{
      `description`:"How many of them POST /config/set will take. The rest are restart-only and say why in `restartReason`."
    }) `editableCount`?: integer;
    @js(#{
      `description`:"The keys with a runtime override in force. Empty on a freshly started service, and emptied again by POST /config/reset-all."
    }) `overridden`?: (string)[];
    @js(#{
      `description`:"In the order `config.js` declares them, which is the order the console renders its sections."
    }) `groups`?: (WithGroupSettings2)[];
    @js(#{
      `description`:"WHERE EACH GROUP IS EDITED: every group is drawn on the console page for the protocol it configures, so a caller can send a person to the right page. Every one of those forms posts to the same four actions."
    }) `homes`?: (WithGroupPagesDescriptionEtc)[];
    @js(#{
      `description`:"Empty, and reported rather than left implicit. A sentence here means a setting group exists that no console page draws."
    }) `homeProblems`?: (string)[];
    @js(#{
      `description`:"The settings this page draws, described: the same rows GET /config returns, filtered to the ones this page owns."
    }) `settings`?: WithPageDescriptionGroupsEtc15
  }

@js(#{
    `description`:"One console page, and the settings it draws: the same described rows GET /config returns, filtered to the ones that page owns."
  }) @component model `PageSettings` {
    @js(#{`description`:"The console path this mirrors."}) `page`?: string;
    `title`?: string;
    @js(#{`description`:"What the page says the family is, as plain text."}) `what`?: string;
    @js(#{
      `description`:"The caveats the page carries, in order. On these pages the caveats are most of the content: what a family does NOT check is the half a client author cannot read off a protocol trace."
    }) `notes`?: (string)[];
    `links`?: (WithHrefWhat)[];
    @js(#{
      `description`:"The settings this page draws, described: the same rows GET /config returns, filtered to the ones this page owns."
    }) `settings`?: WithPageDescriptionGroupsEtc152;
    @js(#{`description`:"The page's first paragraph, as the console draws it."}) `leadHtml`?: string;
    @js(#{`description`:"The caveats, as the console draws them."}) `alsoHtml`?: (string)[];
    `status`?: WithModeConfiguredModeEnabledEtcOrWithSelfModeWhyEtc
  }

@component model `TokenLifetimes` {
    `lifetimes`?: WithAccessTokenTtlSIdTokenTtlSRefreshTokenTtlSEtc4;
    `settings`?: (WithKeyGroupLabelEtc27)[];
    `tokens`?: WithHeldForgottenCapEtc5;
    `now`?: numeric;
    `context`?: NullableObject93;
    `overridable`?: (WithSettingAttribute)[]
  }

@component model `SamlAssertions` {
    `protocolEndpoints`?: (WithNameMethodsUrlEtc6)[];
    `assertions`?: WithSaml2LifetimeMinSaml11LifetimeMinClockSkewSEtc5;
    `perApplication`?: (WithSettingAttributeProfile)[];
    `settings`?: (WithKeyGroupLabelEtc32)[];
    `assertionsIssued`?: WithHeldForgottenCapEtc4;
    `now`?: numeric;
    `context`?: NullableObject94;
    `rows`?: (WithKeyUnitKindEtc5)[];
    @js(#{`description`:"Each setting in seconds, by key."}) `seconds`?: Record<NullableNumber>
  }

@component model `ClaimSets` {
    `reservedJwtClaims`?: (string)[];
    `placeholders`?: (string)[];
    `attributeCatalogue`?: (WithLdapClaimLabelEtc10)[];
    `precedence`?: string;
    `sets`?: (WithIdLabelClaimsEtc11)[];
    `attributeChoices`?: (WithAttributeFrom)[];
    `preview`?: WithUserDescriptionByLdapEtc13;
    `groups`?: WithEnabledLoadedClaimEtc11;
    `withholding`?: (WithIdNames)[]
  }

@component model `KerberosPacClaims` {
    `protocolEndpoints`?: (WithNameMethodsUrlEtc6)[];
    `enabled`?: boolean;
    `setting`?: string;
    `types`?: (string)[];
    `placeholders`?: (string)[];
    `idFormat`?: string;
    `precedence`?: string;
    `sets`?: (WithIdLabelClaimsEtc4)[];
    `attributeCatalogue`?: (WithLdapClaimLabelEtc10)[];
    `attributeChoices`?: (WithAttributeFrom)[];
    `preview`?: WithUserEntryFoundDescriptionEtc14
  }

@component model `UserInfoClaimSets` {
    `protocolEndpoints`?: (WithNameMethodsUrlEtc6)[];
    `reservedJwtClaims`?: (string)[];
    `claimsRequest`?: WithSupportedMembersMaxClaimsEtc9;
    `request`?: string;
    `inventedEmail`?: NullableString;
    `placeholders`?: (string)[];
    `attributeCatalogue`?: (WithLdapClaimLabelEtc10)[];
    `precedence`?: string;
    `sets`?: (WithIdLabelClaimsEtc11)[];
    `attributeChoices`?: (WithAttributeFrom)[];
    `preview`?: WithUserDescriptionByLdapEtc13;
    `groups`?: WithEnabledLoadedClaimEtc11;
    `withholding`?: (WithIdNames)[]
  }

@component model `SamlAttributeSets` {
    `protocolEndpoints`?: (WithNameMethodsUrlEtc6)[];
    `defaultSaml11Namespace`?: string;
    `placeholders`?: (string)[];
    `attributeCatalogue`?: (WithLdapClaimLabelEtc10)[];
    `precedence`?: string;
    `sets`?: (WithIdLabelClaimsEtc11)[];
    `attributeChoices`?: (WithAttributeFrom)[];
    `preview`?: WithUserDescriptionByLdapEtc13;
    `groups`?: WithEnabledLoadedClaimEtc11;
    `withholding`?: (WithIdNames)[]
  }

  

@component model `CredentialClaims` {
    `selected`?: (string)[];
    `defaults`?: (string)[];
    `ldpOmitted`?: (string)[];
    `attributes`?: (WithLdapClaimLabelEtc7)[];
    `protocolEndpoints`?: (WithNameMethodsUrlEtc6)[];
    `preview`?: WithUserClaims
  }

@component model `VerifierRequest` {
    `protocolEndpoints`?: (WithNameMethodsUrlEtc6)[];
    `requested`?: (string)[];
    `defaults`?: (string)[];
    `format`?: string;
    `formats`?: (WithIdLabelIdentifiedByEtc9)[];
    `ldpOmitted`?: (string)[];
    `catalogue`?: (WithClaimLabelNestedEtc8)[];
    `dcqlQuery`?: WithCredentialsCredentialSets;
    `extras`?: (WithClaimPaths)[];
    `recentVerifications`?: WithVerificationsTotalLimit;
    `startChoices`?: WithFormatByModeEtc6
  }

@component model `Xacml` {
    `xacml`?: boolean;
    `message`?: string;
    `enabled`?: boolean;
    `policies`?: integer;
    `enabledPolicies`?: integer;
    `root`?: NullableString;
    `pipAvailable`?: boolean;
    `settings`?: NullableObject95;
    `protocolEndpoints`?: (WithNameMethodsUrlEtc7)[]
  }

@js(#{
    `description`:"One policy this service decides its OWN boundaries with. Built in and called at decision time rather than stored, so it is not in the repository — a repository entry of the same name overrides it.",
    `additionalProperties`:true
  }) @component model `XacmlServiceOwnPolicy` {
    `key`?: "issuance" | "access";
    `label`?: string;
    @js(#{
      `description`:"The entry name an override must be given for the PEP to pick it up. It is what `setting` says, NOT the template id — those are the same word today and need not be."
    }) `name`?: string;
    @js(#{
      `description`:"The config.js key that names it: `xacml.issuancePolicy` or `xacml.accessPolicy`."
    }) `setting`?: string;
    @js(#{
      `description`:"The template the built-in document is built from, and the one an override should be created from so that the two start identical."
    }) `template`?: string;
    `decides`?: string;
    @js(#{`description`:"Which gate asks it, and from how many sites."}) `asked`?: string;
    @js(#{
      `description`:"Whether a repository entry of that name EXISTS. A separate fact from `builtIn`: \"nobody wrote an override\" and \"somebody wrote one and disabled it\" are opposite situations that `builtIn` alone cannot tell apart."
    }) `entry`?: boolean;
    `enabled`?: NullableBoolean3;
    @js(#{
      `description`:"Whether the BUILT-IN document is what is deciding. A fact about the decision, where `entry` is a fact about the directory."
    }) `builtIn`?: boolean;
    @js(#{
      `description`:"Whether anything is being evaluated at all. False when an override exists and is disabled or will not load — neither policy falls back to the built-in one in that case, because a Disable button that quietly evaluated something else would be a lie."
    }) `ok`?: boolean;
    @js(#{`description`:"Why not, when `ok` is false. Empty otherwise."}) `why`?: string;
    @js(#{
      `description`:"One sentence naming what is deciding right now, which is what the console prints."
    }) `effect`?: string
  }

@component model `XacmlPolicies` {
    `xacml`?: boolean;
    `message`?: string;
    `root`?: NullableString;
    `policies`?: (WithNamePolicyIdKindEtc11)[];
    `applicationPolicies`?: (WithApplicationKnownEnforcedEtc4)[];
    `templates`?: (WithIdLabelBlurbEtc5)[];
    `serviceOwn`?: (WithKeyLabelDecidesEtc15)[];
    `protocolEndpoints`?: (WithNameMethodsUrlEtc7)[]
  }

@component model `XacmlEditor` {
    `xacml`?: boolean;
    `message`?: string;
    `policies`?: (string)[];
    `serviceOwn`?: (WithKeyLabelDecidesEtc15)[];
    `policy`?: NullableObject96;
    `problem`?: NullableString;
    `tree`?: (WithPathDepthKindEtc7)[];
    `menus`?: NullableObject98;
    `problems`?: (NullableString)[];
    `xpathVersionGaps`?: (NullableString)[];
    `document`?: string;
    `alfa`?: NullableString;
    `protocolEndpoints`?: (WithNameMethodsUrlEtc7)[]
  }

@component model `XacmlDecision` {
    `xacml`?: boolean;
    `message`?: string;
    `asked`?: boolean;
    `subject`?: string;
    `action`?: string;
    `resource`?: NullableString;
    `decision`?: string;
    `status`?: NullableObject99;
    `obligations`?: (string)[];
    `advice`?: (string)[];
    `applicablePolicies`?: (StringOrKindStringIdStringVersionString)[];
    `enforcement`?: WithAllowedBiasWhy;
    `enforcements`?: (WithAllowedBiasWhy)[];
    `protocolEndpoints`?: (WithNameMethodsUrlEtc7)[]
  }

@component model `GnapServer` {
    `page`?: string;
    `title`?: string;
    `enabled`?: boolean;
    `specifications`?: (string)[];
    `endpoints`?: WithGrantDiscoveryRsDiscoveryEtc12;
    `capabilities`?: WithGrantRequestEndpointInteractionStartModesSupportedInteractionFinishMethodsSupportedEtc8;
    `authorizationServers`?: (WithIdLabelCapabilities)[];
    `authorizationServersPaging`?: WithPagePagesPerPageEtc8;
    `tokenFormats`?: (string)[];
    `verificationMaterial`?: WithJwtBiscuitZcapEtc6;
    `grants`?: WithStateStatesPagingEtc4;
    `resourceSets`?: WithPagingRows;
    `actions`?: (string)[];
    `settings`?: NullableObject61
  }

@component model `GnapMonitor` {
    `page`?: string;
    `title`?: string;
    `since`?: NullOrStringOrNumeric;
    `events`?: (WithEventCounterLabel)[];
    `totals`?: Record<numeric>;
    `tokensByFormat`?: Record<numeric>;
    `applications`?: integer;
    `paging`?: WithPagePagesPerPageEtc8;
    `rows`?: (WithIdentifierNameKindsEtc12)[]
  }

@component model `XacmlMonitor` {
    `xacml`?: boolean;
    `message`?: string;
    `policies`?: WithTotalEnabledRoot;
    `peps`?: WithEmbeddedRemoteTotal;
    `decisions`?: WithHereRemoteCombined;
    `since`?: string;
    `enabled`?: boolean;
    `remotePepsEnabled`?: boolean;
    `realm`?: WithIdName3;
    `rows`?: (WithIdLabelKindEtc22)[];
    `remoteRows`?: (WithIdLabelKindEtc22)[];
    `elsewhere`?: (WithIdNameCount)[];
    `protocolEndpoints`?: (WithNameMethodsUrlEtc7)[]
  }

@component model `XacmlPeps` {
    `xacml`?: boolean;
    `message`?: string;
    `enabled`?: boolean;
    `syncToken`?: NullableString;
    `staleAfterS`?: numeric;
    `requiresCertificate`?: boolean;
    `notify`?: WithOnAllowedHostsTimeoutMsEtc4;
    `peps`?: (WithNameDnIdentityEtc25)[];
    `elsewhere`?: (WithIdNameCount)[];
    `listenerCertificates`?: WithUseCaseKeyAlgorithmsDefaultKeyAlg;
    `current`?: integer;
    `stale`?: integer;
    `protocolEndpoints`?: (WithNameMethodsUrlEtc7)[]
  }

@component model `Ssf` {
    `installed`?: boolean;
    `enabled`?: boolean;
    `issuer`?: string;
    `metadataUrl`?: string;
    `metadata`?: WithSpecVersionIssuerJwksUriEtc13;
    `signingAlgorithm`?: string;
    `delivery`?: (WithMethodNameWhatEtc4)[];
    `push`?: WithAllowedTransportAllowedHostsEtc6;
    `eventTypes`?: (WithUriNameShortEtc11)[];
    `subjectFormats`?: (WithFormatMembersWhatEtc4)[];
    `complexSubjectMembers`?: (WithNameWhat)[];
    `criticalSubjectMembers`?: (string)[];
    `authentication`?: WithRequiredRealmScopesEtc8;
    `streams`?: (WithStreamIdStatusDeliveryEtc9)[];
    `endpoints`?: (WithMethodPathWhat)[];
    `reachableNegatives`?: (WithWhatAnswer)[];
    `doesNotDo`?: (string)[];
    `streamDetail`?: (WithStreamIdIssAudEtc26)[];
    `deadLetters`?: WithRetentionSMaxPerStreamDeadStreamTimeoutSEtc4;
    `settings`?: NullableObject61;
    `statuses`?: (string)[];
    `streamTotals`?: WithStreamsEnabledDeliveredEtc7;
    `streamFilter`?: NullableString;
    `paging`?: WithStreams;
    `note`?: string;
    `protocolEndpoints`?: (WithNameMethodsUrlEtc72)[]
  }

@component model `CaepApplication` {
    `identifier`?: string;
    `name`?: NullableString;
    `registered`?: boolean;
    `declared`?: boolean;
    `dn`?: string;
    `endpoints`?: (string)[];
    `streams`?: (string)[];
    `streamCount`?: integer;
    `enabled`?: integer;
    `deliveries`?: (string)[];
    `audiences`?: (string)[];
    `takes`?: (string)[];
    `counts`?: Record<numeric>;
    `total`?: integer;
    `sessions`?: integer;
    `accounts`?: integer;
    `queued`?: integer;
    `delivered`?: integer;
    `failed`?: integer;
    `acknowledged`?: integer;
    `receiverErrors`?: integer;
    `lastPushAt`?: NullOrStringOrNumeric;
    `lastPushError`?: NullableString
  }

@component model `Caep` {
    `installed`?: boolean;
    `enabled`?: boolean;
    `note`?: string;
    `autoEmit`?: boolean;
    `autoEmitActs`?: (string)[];
    `omitEventTimestamp`?: boolean;
    `eventTypes`?: (WithUriNameShortEtc11)[];
    `totals`?: Record<numeric>;
    `sessions`?: (WithSessionIdSubUsernameEtc23)[];
    `tracked`?: integer;
    `cap`?: numeric;
    `issuer`?: string;
    `ssfEnabled`?: boolean;
    `applications`?: (WithIdentifierNameRegisteredEtc23)[];
    `streams`?: (WithStreamIdAudStatusEtc6)[];
    `catalogue`?: (WithUriNameShortEtc11)[];
    `settings`?: NullableObject61;
    `filter`?: WithSessionsApplications;
    `paging`?: WithSessionsApplicationsStreamsEtc4;
    `shown`?: WithSessionsApplicationsStreams2;
    `matched`?: WithSessionsApplicationsStreams;
    `streamCounts`?: WithTotalTaking;
    `id`?: string;
    `session`?: NullableObject104;
    `events`?: (WithJtiUriNameEtc6)[]
  }

@component model `Risc` {
    `installed`?: boolean;
    `enabled`?: boolean;
    `note`?: string;
    `autoEmit`?: boolean;
    `autoEmitActs`?: (string)[];
    `honourOptOut`?: boolean;
    `googleSubjectType`?: boolean;
    `subjectFormat`?: string;
    `omitEventTimestamp`?: boolean;
    `eventTypes`?: (WithUriNameShortEtc11)[];
    `optStates`?: (string)[];
    `lifecycleStates`?: (string)[];
    `totals`?: Record<numeric>;
    `accounts`?: (WithAccountIdSubUsernameEtc29)[];
    `tracked`?: integer;
    `cap`?: numeric;
    `issuer`?: string;
    `ssfEnabled`?: boolean;
    `applications`?: (WithIdentifierNameRegisteredEtc23)[];
    `streams`?: (WithStreamIdAudStatusEtc6)[];
    `catalogue`?: (WithUriNameShortEtc11)[];
    `settings`?: NullableObject61;
    `filter`?: WithAccountsApplications;
    `paging`?: WithAccountsApplicationsStreamsEtc4;
    `shown`?: WithAccountsApplicationsStreams2;
    `matched`?: WithAccountsApplicationsStreams;
    `streamCounts`?: WithTotalTaking;
    `id`?: string;
    `account`?: NullableObject105;
    `events`?: (WithJtiUriNameEtc6)[]
  }

@component model `Scim` {
    `protocolEndpoints`?: (WithNameMethodsUrlEtc6)[];
    `installed`?: boolean;
    `enabled`?: boolean;
    `baseUrl`?: NullableString;
    `specifications`?: (string)[];
    `store`?: NullableObject106;
    `identifiers`?: NullableObject107;
    `authentication`?: NullableObject108;
    `endpoints`?: (WithMethodPathWhat)[];
    `doesNotDo`?: (string)[];
    `reachableNegatives`?: (WithWhatAnswer)[];
    `mapping`?: WithUserGroup;
    `counters`?: WithTotalOkFailedEtc13;
    `settings`?: NullableObject109;
    `scimClients`?: NullableObject110
  }

@component model `Signals` {
    `status`?: NullableObject111;
    `received`?: (WithJtiAtTokenDigestEtc21)[];
    `total`?: integer;
    `filter`?: WithReceived;
    `paging`?: WithReceived2
  }

@component model `SsfDeadLetters` {
    `installed`?: boolean;
    `enabled`?: boolean;
    `note`?: string;
    `realm`?: string;
    `generatedAt`?: string;
    `pushDelivery`?: boolean;
    `causes`?: (WithIdLabelCodeEtc5)[];
    `totals`?: WithHeldStreamsHoldingSignedEtc13;
    `timeline`?: WithBucketSWindowSFromEtc7;
    `byCode`?: (WithErrorCodeCountCauseEtc4)[];
    `byStatus`?: (WithStatusCount)[];
    `byEventType`?: (WithTypeNameCount)[];
    `streams`?: (WithStreamIdAudEndpointUrlEtc16)[];
    `letters`?: (WithStreamIdJtiQueuedAtEtc12)[];
    `settings`?: WithRetentionSMaxPerStreamDeadStreamTimeoutSEtc7;
    `process`?: WithPidThreadRoleEtc6;
    `filter`?: WithQStreamCause;
    `matched`?: integer;
    `paging`?: WithLettersStreams
  }

@component model `ScimMonitor` {
    `installed`?: boolean;
    `enabled`?: boolean;
    `baseUrl`?: NullableString;
    `schemes`?: (WithIdTypeCanonicalEtc15)[];
    `authRequired`?: boolean;
    `store`?: NullableObject106;
    `counters`?: WithCallsOkFailedEtc22
  }

@js(#{
    `description`:"One layer of the architecture. Each of the three roles uses this shape and each can be an identity, an application, or BOTH — which is the fact that makes the model protocol-independent rather than a Kerberos model the other two are squeezed into.",
    `additionalProperties`:true
  }) @component model `DelegationParty` {
    @js(#{
      `description`:"The NORMALISED local name, so a party here and a row on /admin-api/users name the same person — `alice`, her `urn:uuid:<entryUUID>` subject and `alice@EXAMPLE.COM` are one identity. Empty where this layer is an application rather than a person, or where nothing named it."
    }) `key`?: string;
    @js(#{
      `description`:"The identity exactly as it arrived, when that differs from `key` — a Kerberos principal, a NameID, a `sub`. Both are carried because the collapse from one to the other is something a reader has to be able to see."
    }) `presented`?: string;
    @js(#{
      `description`:"The application this layer IS — a client_id, an AppliesTo, an SPN, an audience. NOT a promise that an entry exists under ou=applications: that registry holds what this service has been ASKED ABOUT, and a delegation naming something nobody has otherwise mentioned is an ordinary and interesting outcome. Look it up on /admin-api/applications to find out which."
    }) `application`?: string;
    @js(#{
      `description`:"What this party is in THIS act, in the protocol's own words."
    }) `what`?: string
  }

@js(#{
    `description`:"One credential presented or produced. NO CREDENTIAL IS EVER CARRIED — only what kind it was and its identifier, which is the rule the audit log follows and applies here twice over: a delegation is precisely the request that carries two credentials at once.",
    `additionalProperties`:true
  }) @component model `DelegationCredential` {
    @js(#{
      `description`:"`subject_token`, `actor_token`, `access_token`, `Kerberos evidence ticket`, `SAML 2.0 assertion`, `PA-FOR-USER`, and so on."
    }) `kind`?: string;
    @js(#{
      `description`:"A `jti` or an AssertionID. EMPTY for a Kerberos ticket, which genuinely has none in the protocol, and for the WS-Trust JWT, which is signed directly rather than through this service's JWT funnel and so carries no `jti` and is in no register. `note` says which."
    }) `identifier`?: string;
    @js(#{
      `description`:"What is worth knowing about this credential — whether it verified, whether it was forwardable."
    }) `note`?: string
  }

@js(#{
    `description`:"ONE ACT: a single exchange at a single moment in which somebody acted on somebody else's behalf. Not a relationship — the same three parties appearing eleven times is eleven acts, and `chainKey` is what collapses them.",
    `additionalProperties`:true
  }) @component model `DelegationAct` {
    @js(#{
      `description`:"Unique across every process of the service and NEVER REUSED, including across a drop and a restart; rising within each process, not one order across them (#465). The stable name for an act; resume reading by `at`."
    }) `seq`?: integer;
    @js(#{
      `description`:"The process that recorded the act, by its stable origin in the store; empty without a shared store. The tie-break, with `seq`, for two acts in one millisecond."
    }) `origin`?: string;
    @js(#{`description`:"Milliseconds since the epoch."}) `at`?: integer;
    @js(#{`description`:"The family, spelled as /admin-api/users spells it."}) `protocol`?: string;
    @js(#{
      `description`:"The mechanism, as its specification names it. The list's `types` member describes each one."
    }) `type`?: string;
    @js(#{`description`:"That mechanism in words."}) `typeLabel`?: string;
    @js(#{
      `description`:"THE AXIS WORTH READING FIRST. `delegation` means the credential carries the chain and the far end can see who is really asking. `impersonation` means nothing does — so this record is the only place the fact will ever exist."
    }) `mode`?: "impersonation" | "delegation";
    @js(#{`description`:"Where the mechanism is defined."}) `spec`?: string;
    @js(#{
      `description`:"Whether THIS SERVICE decided who may perform the act. True for the three Kerberos S4U mechanisms and false for everything else, which is a real asymmetry rather than an omission — see `authorizedBy`."
    }) `policed`?: boolean;
    `outcome`?: "issued" | "refused";
    `initial`?: `DelegationParty`;
    `intermediary`?: `DelegationParty`;
    `target`?: `DelegationParty`;
    @js(#{
      `description`:"The identity of the CHAIN rather than of the act: the mechanism and the three parties, with the time, the credentials and the OUTCOME left out. Acts sharing one are one edge of the picture — and the outcome is out of it deliberately, so a chain refused nine times and then fixed is one edge that changes rather than two that never meet."
    }) `chainKey`?: string;
    @js(#{
      `description`:"What PERMITTED it: the attribute AND the account it is on, in the KDC's own words — or, for WS-Trust and token exchange (#108), in the delegation policy's; in development, what WOULD have refused it."
    }) `authorizedBy`?: string;
    @js(#{
      `description`:"Why it was REFUSED — the `e-text` of the error the client was sent, not a second wording that could come to disagree with it. Empty on an issued act."
    }) `reason`?: string;
    `consumed`?: (`DelegationCredential`)[];
    `produced`?: (`DelegationCredential`)[];
    @js(#{
      `description`:"The browser sign-on session, where there was one. USUALLY EMPTY, and that is a fact about delegation rather than a gap in the recording: a service asking on somebody's behalf has no browser anywhere in it."
    }) `sessionId`?: string;
    @js(#{`description`:"One sentence of context."}) `note`?: string
  }

@js(#{
    `description`:"One DISTINCT chain among the acts that matched — one edge of the picture. This is the more useful answer to \"what talks to what\".",
    `additionalProperties`:true
  }) @component model `DelegationChain` {
    `chainKey`?: string;
    `protocol`?: string;
    `type`?: string;
    `typeLabel`?: string;
    `mode`?: "impersonation" | "delegation";
    `initial`?: `DelegationParty`;
    `intermediary`?: `DelegationParty`;
    `target`?: `DelegationParty`;
    @js(#{`description`:"How many acts are on this edge."}) `acts`?: integer;
    `issued`?: integer;
    `refused`?: integer;
    `firstAt`?: integer;
    `lastAt`?: integer;
    @js(#{
      `description`:"From the MOST RECENT act on the chain, so an edge that was fixed says how it works now rather than why it used to fail."
    }) `authorizedBy`?: string;
    @js(#{`description`:"Likewise, for a refusal."}) `reason`?: string
  }

@js(#{
    `description`:"WHO MAY DELEGATE TO WHOM, before anybody has tried. KERBEROS ONLY, and that is not an omission: Kerberos is the only family here that polices delegation at all. WS-Trust puts no authorization on OnBehalfOf or ActAs, and RFC 8693 leaves the policy to the authorization server, which this one does not have.",
    `additionalProperties`:true
  }) @component model `DelegationPolicy` {
    @js(#{
      `description`:"One per (front end, target, mechanism). The two mechanisms are in ONE list because the messages and the KDC options are identical and the whole difference is which of the two accounts carries the permission — which is `setOn`."
    }) `pairs`?: (WithMechanismDescriptionTypeEtc)[];
    @js(#{
      `description`:"Principals carrying a flag that changes what delegation can do to them or with them. Two of the three STOP delegation rather than permit it, and one is not a control at all. Listed whether or not a pair names them."
    }) `accounts`?: (WithPrincipalRealmNotDelegatedEtc)[]
  }

@component model `DelegationList` {
    `held`?: integer;
    `heldHere`?: integer;
    `processes`?: integer;
    `recorded`?: integer;
    `dropped`?: integer;
    `maxRecords`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `oldestSeq`?: numeric;
    `newestSeq`?: numeric;
    `byType`?: Record<integer>;
    `byMode`?: Record<integer>;
    `byOutcome`?: Record<integer>;
    `byProtocol`?: Record<integer>;
    `filter`?: WithTypeModeOutcomeEtc5;
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `types`?: (WithTypeProtocolModeEtc7)[];
    `modes`?: (WithModeLabelWhat)[];
    `outcomes`?: (string)[];
    `roles`?: (WithRoleLabelWhat)[];
    `acts`?: (WithSeqOriginAtEtc20)[];
    `chains`?: (WithChainKeyProtocolTypeEtc15)[];
    `applications`?: (WithKeyIdentifierSpellingsEtc13)[];
    `graph`?: WithRealmIssuerNodesEtc13;
    `policy`?: WithPairsAccounts;
    `allowed`?: WithResourcesPermissionsGrantsEtc7;
    `delegationPolicy`?: WithEnforcedAttributesProtectedGroupsEtc9;
    `all`?: integer;
    `paging`?: WithPagePagesPerPageEtc82;
    `delegationPerPage`?: integer;
    `chainPage`?: WithShownPaging8;
    `pairPage`?: WithShownPaging2;
    `flagPage`?: WithShownPaging4;
    `mechanismPage`?: WithShownPaging;
    `applicationChooser`?: WithTotalEntriesSliceEtc5;
    `userChooser`?: WithTotalEntriesSliceEtc5;
    `permissionsView`?: WithRegisterListStateAllApplications;
    `exchangePolicyView`?: WithRegisterPairsIntermediariesEtc4;
    `facts`?: WithUsersAppsNameEtc4
  }

@js(#{
    `description`:"One thing that happened, with the facts of it and no credential of any kind. Written out rather than left open because a caller filtering or alerting on this list needs a name for every field.",
    `additionalProperties`:true
  }) @projects("AuditEvent") @component model `AuditEvent` {
    @js(#{
      `description`:"Unique across every process of the service and NEVER REUSED, including across a drop and a restart; rising within each process, not one order across them (#465). The stable name for an event — a row number would silently mean a different event as soon as the cap discarded anything. Resume reading by `at`."
    }) `seq`?: integer;
    @js(#{
      `description`:"The process that recorded the event, by its stable origin in the store; empty without a shared store."
    }) `origin`?: string;
    @js(#{`description`:"When it happened, in milliseconds since the epoch."}) `at`?: integer;
    @js(#{
      `description`:"Derived from `action` and never set independently, so the two cannot disagree."
    }) `category`?: "authentication" | "session" | "directory" | "admin" | "api" | "application" | "protocol" | "spiffe" | "signals" | "authorization" | "service";
    @js(#{
      `description`:"What happened, from a fixed vocabulary the list's `actions` member enumerates."
    }) `action`?: string;
    @js(#{
      `description`:"A `refused` is this service saying no and working; an `error` is this service failing."
    }) `outcome`?: "success" | "refused" | "error";
    @js(#{
      `description`:"Which failure condition this row is about — `STS-<SUBSYSTEM>-<NNNN>`, listed in docs/error-codes.md — or empty for a row that is not a failure. Every refused or failed request carries one. It is an operator's name for the condition and is never sent to the client whose request produced it."
    }) `errorCode`?: string;
    @js(#{
      `description`:"The NORMALISED local name, so a row here and a row on /admin-api/users name the same person — `alice`, her `urn:uuid:<entryUUID>` subject and `alice@EXAMPLE.COM` are one identity. Empty where nothing named an actor, which an unauthenticated protocol call and an anonymous LDAP bind both are."
    }) `actor`?: string;
    @js(#{
      `description`:"The identity exactly as it was presented, when that differs from `actor` — a bind DN, a Kerberos principal, an X.509 subject. Both are carried because the collapse from one to the other is something an auditor has to be able to see rather than infer."
    }) `actorForm`?: string;
    @js(#{
      `description`:"What it was done to: a DN, a request path, a session id."
    }) `target`?: string;
    @js(#{
      `description`:"The family, where one applies. Free text: the sixteen families here spell themselves differently in the places this is read from, and an enum would be a lookup table that silently drops the seventeenth."
    }) `protocol`?: string;
    @js(#{
      `description`:"How it arrived. `http` the main port; `ldap` and `ldaps` the directory's sockets; `kerberos` the KDC's TCP and UDP 88; `grpc` the SPIFFE Workload API and SPIRE Server API; `tls` a client certificate presented to this service; `console` an act taken on the admin console or `/admin-api` and recorded as that act rather than as the HTTP call. `internal` is something this service did on its own — the directory entry it seeds for somebody who authenticated elsewhere — `none` a session that EXPIRED, which nothing sent, and empty a row whose recording site named no channel. The client's address is `address`."
    }) `channel`?: "http" | "ldap" | "ldaps" | "kerberos" | "grpc" | "tls" | "console" | "internal" | "none" | "";
    @js(#{
      `description`:"The client's IP address (2026-09-18): whoever sent the HTTP request, LDAP operation, Kerberos message or SPIRE Server API call this row came out of — an authentication, a refused sign-in, a consent, a sign-out. Resolved through `global.trustProxy` and `global.trustedProxies` (the right-most `X-Forwarded-For` hop that is not a named proxy) or a PROXY protocol header; behind a proxy with neither set, it is the proxy. Empty for something this service did on its own, or that arrived over a Unix socket."
    }) `address`?: string;
    @js(#{`description`:"One sentence, the same one the console shows."}) `summary`?: string;
    @js(#{
      `description`:"Flat facts about this event, at most twelve keys with each value trimmed. What is in it depends on the action — a modify names the ATTRIBUTES it changed and never their values, a search names how many entries came back, an HTTP row names the route and the elapsed time.",
      `additionalProperties`:true
    }) `detail`?: {}
  }

@js(#{
    `description`:"What happened here, newest first, filtered and paged. HISTORY where the rest of this API is STATE. Resume by `at`, not by `seq` or by `page` (#465)."
  }) @component model `AuditList` {
    @js(#{`description`:"Events currently in the log."}) `held`?: integer;
    @js(#{`description`:"Events recorded since this process started."}) `recorded`?: integer;
    @js(#{`description`:"Events discarded to stay under the cap."}) `dropped`?: integer;
    @js(#{`description`:"The cap: `audit.maxEvents`."}) `maxEvents`?: numeric;
    @js(#{
      `description`:"Whether ordinary protocol endpoint calls are being recorded."
    }) `protocolCalls`?: boolean;
    `matched`?: integer;
    `shown`?: integer;
    `oldestSeq`?: numeric;
    `newestSeq`?: numeric;
    `byCategory`?: Record<numeric>;
    `byOutcome`?: Record<numeric>;
    `byAction`?: Record<numeric>;
    `filter`?: WithCategoryActionOutcomeEtc7;
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `categories`?: (WithCategoryLabelWhat)[];
    `actions`?: (WithActionCategoryLabel)[];
    `outcomes`?: (string)[];
    `events`?: (WithSeqOriginAtEtc172)[];
    @js(#{
      `description`:"Which page of how many, and the query parameter that moves it."
    }) `paging`?: WithPagePagesPerPageEtc8;
    @js(#{`description`:"The actors on this page that are people known here."}) `knownActors`?: Record<boolean>;
    `settings`?: NullableObject113;
    `verifiesCredentials`?: boolean;
    `persisted`?: boolean
  }

@js(#{
    `description`:"A refusal or a failure. The sentence is for a person; no error code is ever in it."
  }) @component model `RefusalFailure2` {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `message`?: string;
    `why`?: string;
    `status`?: integer
  }

@component model `WithPathLabelBlurb` is ({
    `path`?: string;
    `label`?: string;
    `blurb`?: string;
    `hidden`?: boolean;
    `title`?: string;
    `what`?: string
  })[];
  

@component model `WithPathLabelBlurb2` {
    `path`?: string;
    `label`?: string;
    `blurb`?: string;
    `hidden`?: boolean;
    `title`?: string;
    `what`?: string;
    `items`?: `WithPathLabelBlurb`
  }

@component model `WithPathLabelBlurb3` is (`WithPathLabelBlurb2`)[];
  

@component model `WithPathLabelBlurb4` {
    `path`?: string;
    `label`?: string;
    `blurb`?: string;
    `hidden`?: boolean;
    `title`?: string;
    `what`?: string;
    `items`?: `WithPathLabelBlurb3`
  }

@component model `WithTitleWhatItems` is (`WithPathLabelBlurb4`)[];
  

@component model `WithTitleWhatItems2` {`title`?: string; `what`?: string; `items`?: `WithTitleWhatItems`}

@component model `WithLocaleChainCatalog` is (`WithTitleWhatItems2`)[];
  

@component model `WithLocaleChainCatalog2` {
    `locale`?: string;
    `chain`?: (string)[];
    `catalog`?: string;
    `direction`?: "ltr" | "rtl";
    `matched`?: boolean
  }

  

@component model `WithNegotiatedOfferedDescription` {
    `negotiated`?: `WithLocaleChainCatalog2`;
    `offered`?: (WithTagName)[];
    @js(#{`description`:"Each catalog along the chain, by language tag."}) `catalogs`?: Record<ListOfRecordString>;
    @js(#{`description`:"Each static catalog, by language tag."}) `catalogFiles`?: Record<string>
  }

@component model `WithOkErrorsLocale` {`ok`: boolean; `errors`?: (string)[]; `locale`?: `WithNegotiatedOfferedDescription`}

@component model `WithShapeLabelSublabel2` {
    `shape`?: string;
    `label`?: string;
    `sublabel`?: NullableString;
    `identifier`?: NullableString;
    `title`?: string;
    `href`?: NullableString;
    `dashed`?: boolean
  }

@js(#{`description`:"Each node's look, by node id."}) @component model `NodeSLookNodeId` is Record<`WithShapeLabelSublabel2`>;
  

@component model `WithIdKindRealm` {
    `id`?: string;
    `kind`?: string;
    `realm`?: WithIdNameIsDefault;
    `issuer`?: string;
    `roles`?: WithInitialIntermediaryTarget2;
    `acts`?: integer;
    `issued`?: integer;
    `refused`?: integer;
    `key`?: string;
    `presented`?: string;
    `application`?: string;
    `aliases`?: (string)[];
    `what`?: string;
    `protocols`?: (string)[];
    `firstAt`?: numeric;
    `lastAt`?: numeric;
    `selfTarget`?: boolean;
    `chiefRole`?: string;
    `grants`?: integer;
    `exposes`?: integer;
    `dangling`?: integer;
    `credentials`?: integer;
    `flows`?: (string)[];
    `authentications`?: integer;
    `isSubject`?: boolean;
    `isClient`?: boolean;
    `kinds`?: (string)[]
  }

@component model `WithKindCountIdentifiers2` is (`WithIdKindRealm`)[];
  

@component model `WithKindCountIdentifiers3` {
    `kind`?: string;
    `count`?: integer;
    `identifiers`?: (string)[];
    `moreIdentifiers`?: integer;
    `notes`?: (string)[]
  }

@component model `WithIdFromTo4` is (`WithKindCountIdentifiers3`)[];
  

@component model `WithIdFromTo5` is Record<`WithKindCountIdentifiers3`>;
  

@component model `WithIdFromTo6` {
    `id`?: string;
    `from`?: string;
    `to`?: string;
    `fromRole`?: string;
    `toRole`?: string;
    `relation`?: string;
    `skipped`?: (string)[];
    `chainKey`?: string;
    `protocol`?: string;
    `protocols`?: (string)[];
    `type`?: string;
    `typeLabel`?: string;
    `mode`?: string;
    `spec`?: string;
    `policed`?: boolean;
    `subject`?: string;
    `actor`?: string;
    `acts`?: integer;
    `issued`?: integer;
    `refused`?: integer;
    `firstAt`?: numeric;
    `lastAt`?: numeric;
    `authorizedBy`?: string;
    `reason`?: string;
    `consumed`?: `WithIdFromTo4`;
    `produced`?: `WithIdFromTo4`;
    `attribute`?: string;
    `mechanism`?: string;
    `setOn`?: string;
    `used`?: boolean;
    `consumedFold`?: `WithIdFromTo5`;
    `producedFold`?: `WithIdFromTo5`;
    `permissionId`?: string;
    `permissionName`?: string;
    `baseUri`?: string;
    `description`?: string;
    `asked`?: boolean;
    `credentials`?: integer;
    `authentications`?: ({
      `protocol`?: string;
      `method`?: string;
      `count`?: integer;
      `at`?: numeric;
      `lastAt`?: numeric
    })[];
    `audience`?: string;
    `audienceRegistered`?: boolean;
    `permissions`?: (string)[];
    `scopes`?: (string)[]
  }

@component model `WithSeqAtKind3` is (`WithIdFromTo6`)[];
  

@component model `WithSeqAtKind4` {
    `seq`?: numeric;
    `at`?: numeric;
    `kind`?: string;
    `identifier`?: string;
    `note`?: string;
    `protocol`?: string;
    `type`?: string;
    `typeLabel`?: string;
    `mode`?: string;
    `chainKey`?: string;
    `subject`?: string;
    `actor`?: string;
    `target`?: string
  }

@component model `WithTotalEntriesKey` is (`WithSeqAtKind4`)[];
  

@component model `WithTotalEntriesKey2` {
    `total`?: integer;
    `entries`?: ({
      `key`?: string;
      `names`?: (string)[];
      `label`?: string;
      `detail`?: string;
      `href`?: string
    })[];
    `slice`?: WithMatchedFrom;
    `search`?: "contains" | "exact";
    `complete`?: boolean
  }

@component model `WithDescriptionUsersDescription` {
    @js(#{`description`:"Each name in the answer that is a known person."}) `users`?: Record<boolean>;
    @js(#{`description`:"Each name in the answer the registry holds."}) `apps`?: Record<{`name`?: string; `dnLabel`?: string}>
  }

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `application`:#{`type`:"string"},
      `source`:#{`type`:"string"},
      `via`:#{`type`:"string"},
      `configured`:#{`type`:"boolean"},
      `authentications`:#{`type`:"integer"},
      `users`:#{`type`:"integer"},
      `lastUser`:#{`type`:"string"},
      `lastSeen`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model BrokeredUseValue_h1349 {}

@component union `BrokeredUseValue` {BrokeredUseValue_h1349}

@component model `WithApplicationsGrantsLines3` {
    `applications`?: integer;
    `grants`?: integer;
    `lines`?: integer;
    `permissions`?: integer;
    `dangling`?: integer;
    `selfGrants`?: integer;
    `asked`?: integer;
    `unused`?: integer
  }

@component model `WithClientClientNamePermissionId3` {
    `client`?: string;
    `clientName`?: string;
    `permissionId`?: string;
    `resource`?: string;
    `resourceName`?: string;
    `baseUri`?: string;
    `permissionName`?: string;
    `description`?: string;
    `dangling`?: boolean;
    `asked`?: boolean
  }

@component model `WithPagePagesPerPage4` is (`WithClientClientNamePermissionId3`)[];
  

@component model `WithPagePagesPerPage5` {
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `total`?: integer;
    `param`?: NullableString;
    `noun`?: NullableString
  }

@component model `WithResourceResourceNameBaseUri2` {
    `resource`?: string;
    `resourceName`?: string;
    `baseUri`?: string;
    `name`?: string;
    `description`?: string;
    `id`?: NullableString;
    `raw`?: string;
    `grantedTo`?: (WithIdentifierNameAsked)[]
  }

@component model `WithKeyMembersCounts` is (`WithResourceResourceNameBaseUri2`)[];
  

@component model `WithKeyMembersCounts2` {`key`?: string; `members`?: (string)[]; `counts`?: `WithApplicationsGrantsLines3`}

@component model `WithAtFamilyKind2` is (`WithKeyMembersCounts2`)[];
  

@component model `WithAtFamilyKind3` {
    `at`?: numeric;
    `family`?: string;
    `kind`?: string;
    `identifier`?: string;
    `flow`?: string;
    `flowLabel`?: string;
    `flowProtocol`?: string;
    `flowSpec`?: string;
    `flowOidc`?: string;
    `flowStated`?: boolean;
    `holder`?: string;
    `audience`?: string;
    `scope`?: string;
    `issuer`?: string;
    `state`?: NullableString;
    `sessionId`?: string;
    `revocable`?: boolean;
    `revoked`?: boolean;
    `detail`?: string;
    `expiresAtMs`?: numeric
  }

@component model `WithRealmIssuerNodes3` is (`WithAtFamilyKind3`)[];
  

@component model `WithRealmIssuerNodes4` {
    `realm`?: WithIdNameIsDefault;
    `issuer`?: string;
    `nodes`?: `WithKindCountIdentifiers2`;
    `edges`?: `WithSeqAtKind3`;
    `tokens`?: `WithTotalEntriesKey`;
    `tokensLeftOff`?: integer;
    `maxTokenRows`?: integer;
    `acts`?: integer;
    `chains`?: integer;
    `counts`?: WithNodesEdgesGrants;
    `credentials`?: `WithRealmIssuerNodes3`;
    `credentialsOnDelegationLines`?: integer;
    `subject`?: string
  }

@component model `WithNameDescriptionId` {
    `name`?: string;
    `description`?: string;
    `id`?: NullableString;
    `raw`?: string;
    `grantedTo`?: (WithIdentifierNameAsked)[]
  }

@component model `WithIdentifierNameBaseUri` is (`WithNameDescriptionId`)[];
  

@component model `WithIdentifierNameBaseUri2` {
    `identifier`?: string;
    `name`?: string;
    `baseUri`?: string;
    `rawBaseUri`?: string;
    `permissions`?: `WithIdentifierNameBaseUri`;
    `grantsHeld`?: integer
  }

@component model `WithResourcesPermissionsUnidentified` is (`WithIdentifierNameBaseUri2`)[];
  

@component model `WithResourcesPermissionsUnidentified2` {
    `resources`?: integer;
    `permissions`?: integer;
    `unidentified`?: integer;
    `grants`?: integer;
    `dangling`?: integer;
    `unused`?: integer;
    `ungranted`?: integer;
    `clients`?: integer
  }

@component model `WithResourcesPermissionsGrants` {
    `resources`?: `WithResourcesPermissionsUnidentified`;
    `permissions`?: `WithKeyMembersCounts`;
    `grants`?: `WithPagePagesPerPage4`;
    `counts`?: `WithResourcesPermissionsUnidentified2`
  }

@component model `WithKeyMembersGrants` {
    `key`?: string;
    `members`?: (string)[];
    `grants`?: `WithPagePagesPerPage4`;
    `permissions`?: `WithKeyMembersCounts`;
    `counts`?: `WithApplicationsGrantsLines3`
  }

@component model `WithClustersDescriptionMemberOf` is (`WithKeyMembersGrants`)[];
  

@component model `WithClustersDescriptionMemberOf2` {
    `clusters`?: `WithClustersDescriptionMemberOf`;
    @js(#{`description`:"Each application, to its group's key."}) `memberOf`?: Record<string>;
    `counts`?: WithClustersApplicationsLargestEtc5
  }

@component model `WithShownPagingShown` {`shown`?: `WithPagePagesPerPage4`; `paging`?: `WithPagePagesPerPage5`}

@component model `WithShownPagingOnlyWhileOn` {`shown`?: `WithKeyMembersCounts`; `paging`?: `WithPagePagesPerPage5`}

@component model `WithOnlyWhileOnAloneWhileOnKey2` {
    `onlyWhileOn`?: (WithSettingValuesOnEtc4)[];
    `aloneWhileOn`?: (WithSettingValuesOnEtc4)[]
  }

@component model `WithKeyGroupLabel5` {
    `key`?: string;
    `group`?: string;
    `label`?: string;
    `description`?: string;
    `type`?: string;
    `enumValues`?: (string)[];
    `csvValues`?: (string)[];
    `ordered`?: boolean;
    @js(#{`description`:"A sentence per value of the row."}) `csvValueNotes`?: Record<string>;
    `selectAll`?: `WithOnlyWhileOnAloneWhileOnKey2`;
    `min`?: numeric;
    `max`?: numeric;
    `step`?: numeric;
    `value`?: Shape7;
    `text`?: NullableString;
    `source`?: string;
    `editable`?: boolean;
    `restartReason`?: NullableString;
    `editRefusal`?: NullableString;
    `env`?: NullableString;
    `legacyEnv`?: NullOrStringOrString;
    `appconfigPath`?: string;
    `default`?: Shape7;
    `masked`?: boolean;
    `realmSettable`?: boolean;
    `overridden`?: boolean
  }

@component model `WithSeqOriginAt4` {
    `seq`?: numeric;
    `origin`?: NullableString;
    `at`?: numeric;
    `protocol`?: string;
    `type`?: string;
    `typeLabel`?: string;
    `mode`?: string;
    `spec`?: string;
    `policed`?: boolean;
    `outcome`?: string;
    `initial`?: WithKeyPresentedApplicationEtc4;
    `intermediary`?: WithKeyPresentedApplicationEtc4;
    `target`?: WithKeyPresentedApplicationEtc4;
    `authorizedBy`?: string;
    `reason`?: string;
    `consumed`?: (WithKindIdentifierNote)[];
    `produced`?: (WithKindIdentifierNote)[];
    `sessionId`?: string;
    `note`?: string;
    `chainKey`?: string
  }

@component model `WithIdLabelCa2` is (`WithSeqOriginAt4`)[];
  

@component model `WithIdLabelCa3` {
    `id`?: string;
    `label`?: string;
    `ca`?: boolean;
    `selfSigned`?: boolean;
    `years`?: numeric;
    `keyUsage`?: (string)[];
    `extKeyUsage`?: (string)[];
    `pathLen`?: NullableNumber;
    `note`?: string
  }

@component model `WithIdLabelClassical3` is (`WithIdLabelCa3`)[];
  

@component model `WithIdLabelClassical4` is ({
    `id`?: string;
    `label`?: string;
    `classical`?: boolean;
    `families`?: (string)[];
    `note`?: string
  })[];
  

@component model `WithIdLabelFamily` is ({
    `id`?: string;
    `label`?: string;
    `family`?: string;
    `kind`?: string;
    `signs`?: boolean;
    `slow`?: boolean;
    `tlsUsable`?: boolean
  })[];
  

@component model `WithIdLabelSubject2` is ({
    `id`?: string;
    `label`?: string;
    `subject`?: string;
    `keyAlg`?: string;
    `notAfter`?: string;
    `hasAlternativeKey`?: boolean
  })[];
  

@component model `WithIdCaProfile2` {
    `id`?: string;
    `ca`?: boolean;
    `profile`?: NullableString;
    `profileLabel`?: NullableString;
    `subject`?: string;
    `issuerSubject`?: NullableString;
    `issuerId`?: NullableString;
    `selfSigned`?: boolean;
    `serialHex`?: NullableString;
    `keyAlg`?: string;
    `keyAlgLabel`?: NullableString;
    `signatureAlg`?: NullableString;
    `signatureAlgLabel`?: NullableString;
    `pqMode`?: NullableString;
    `altKeyAlg`?: NullableString;
    `altSigned`?: boolean;
    `notBefore`?: NullableString;
    `notAfter`?: NullableString;
    `expired`?: boolean;
    `thumbprint`?: NullableString;
    `createdAt`?: NullOrStringOrNumeric;
    `hasPrivateKey`?: boolean;
    `hasCsr`?: boolean;
    `certificatePem`?: NullableString;
    `csrPem`?: string
  }

@component model `WithFieldsProfilesPqModes3` is (`WithIdCaProfile2`)[];
  

@component model `WithFieldsProfilesPqModes4` {
    `fields`?: (string)[];
    `profiles`?: `WithIdLabelClassical3`;
    `pqModes`?: `WithIdLabelClassical4`;
    `pqMode`?: string;
    `keyAlgorithms`?: `WithIdLabelFamily`;
    `alternativeKeyAlgorithms`?: `WithIdLabelFamily`;
    `signatureAlgorithms`?: ({`id`?: string; `label`?: string; `weak`?: boolean; `kind`?: string})[];
    `signerLabel`?: string;
    `keystoreFormats`?: (string)[];
    `keyUsageBits`?: (WithNameWhat)[];
    `extendedKeyUsages`?: (WithNameOid)[];
    `netscapeTypes`?: ({`name`?: string})[];
    `accessMethods`?: (string)[];
    `dnFields`?: (WithAttrField)[];
    `issuers`?: `WithIdLabelSubject2`;
    `objects`?: `WithFieldsProfilesPqModes3`;
    `maxObjects`?: integer;
    `slowFamilies`?: (string)[];
    @js(#{`description`:"The certificate form, by field name."}) `draft`?: Record<Shape8>
  }

@component model `WithOkErrorsWhy` {
    `ok`: boolean;
    `errors`?: (string)[];
    `why`?: string;
    @js(#{`description`:"The certificate form, by field name."}) `draft`?: Record<Shape8>;
    `algorithm`?: string;
    `workbench`?: `WithFieldsProfilesPqModes4`
  }

@component model `WithOkChangedClientSecret` {
    `ok`: boolean;
    `changed`?: boolean;
    `clientSecret`?: string;
    `message`?: string;
    `errors`?: (string)[]
  }

@js(#{
    `x-free-form`:"The inside of an OpenAPI document (its paths and components): a statement about this API in OpenAPI's own vocabulary, whose every model is stated at the operation it describes.",
    `description`:"The inside of an OpenAPI document (its paths and components): a statement about this API in OpenAPI's own vocabulary, whose every model is stated at the operation it describes."
  }) @component model `InsideOpenAPIDocumentPathsComponents` {}

@endpoint("/admin-api/console/api-explorer",
  "get",
  #{
    `operationId`:"getApiExplorer",
    `summary`:"What the console's API explorer reads, and what you may drive",
    `description`:"The explorer is a page of the ADMIN CONSOLE at `/admin/api-explorer` — it was `/admin-api/docs` until 2026-09-09, when this API began requiring an access token a browser cannot carry. This operation reports where the document is, how many paths and operations it describes, and the audience a token for this API must name. It does NOT repeat the document: `GET /admin-api/openapi.json` is the document.\n\nThe `scope` member is what the CONSOLE SESSION's roles would grant — it is what the page puts in the token it mints for the person reading it, so a reader holding Admin Read alone sees `admin:read` and knows before pressing anything that a write would be refused. **It is EMPTY when this operation is called with an access token rather than read off the page**, which is the ordinary case here: there is no console session on such a request, and reporting the token's own scopes back to the caller that sent them would be telling somebody what they just said.\n\n**Mirrors** `GET /admin/api-explorer` on the admin console.",
    `tags`:#["Service"],
    `responses`:#{
      `200`:#{
        `description`:"Where the explorer reads from, and what the caller may drive.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getApiExplorer`(`responses/200/content/application~1json/schema`: {
    `page`?: string;
    `api`?: string;
    `document`?: string;
    `version`?: string;
    `paths`?: integer;
    `operations`?: integer;
    `scope`?: string;
    `audience`?: NullableString;
    `tokenInReply`?: boolean;
    `who`?: string;
    `realmPrefix`?: string;
    `script`?: string
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `enforced`:#{`type`:"boolean"},
      `available`:#{`type`:"boolean"},
      `session`:#{`type`:"boolean"},
      `username`:#{`type`:"string"},
      `authority`:#{`type`:#["string","null"]},
      `identityRealm`:#{`type`:#["string","null"]},
      `readGroup`:#{`type`:#["string","null"]},
      `writeGroup`:#{`type`:#["string","null"]},
      `read`:#{`type`:"boolean"},
      `write`:#{`type`:"boolean"},
      `security`:#{`type`:"boolean"},
      `roles`:#{`type`:"array",`items`:#{`type`:"string"}},
      `open`:#{`type`:"boolean"},
      `closed`:#{`type`:"boolean"},
      `windowOpens`:#{`type`:"boolean"},
      `empty`:#{`type`:"boolean"},
      `bootstrapPasswordRequired`:#{`type`:"boolean"},
      `bootstrap`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `username`:#{`type`:#["string","null"]},
          `seeded`:#{`type`:"boolean"},
          `claimedAt`:#{`type`:"string"}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_admin_api_console_r200_application_json_gate_h1384 {}

@js(#{
    `items`:#{
      `type`:"object",
      `additionalProperties`:false,
      `properties`:#{
        `id`:#{`type`:"string"},
        `name`:#{`type`:"string"},
        `prefix`:#{`type`:"string"}
      }
    },
    `$types`:#["array","null"]
  }) @hoisted model get_admin_api_console_r200_application_json_realms_h1386 {}

@endpoint("/admin-api/console",
  "get",
  #{
    `operationId`:"getConsoleShell",
    `summary`:"What the console draws around every page, for this caller",
    `description`:"The gate as it stands for the caller and the labels of the roles it names, the trust realm and the realms to choose between, where the realm's root and the user portal are, the console sections the caller may see and every page's label, a realm's removal in progress, what this process runs as, what is persisted, and the build. The static console fetches it once after sign-in. With catalogs=files, the language member names the static catalog files rather than carrying the catalogs.\n\n**Mirrors** `GET /admin` on the admin console.",
    `tags`:#["Service"],
    `responses`:#{
      `200`:#{
        `description`:"The shell answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `parameters`:#[
      #{
        `name`:"catalogs",
        `in`:"query",
        `required`:false,
        `description`:"files: name the static catalog files instead of carrying the catalogs.",
        `schema`:null
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getConsoleShell`(`parameters/0/schema`: "files",
  `responses/200/content/application~1json/schema`: {
    `gate`?: get_admin_api_console_r200_application_json_gate_h1384;
    `navAuthority`?: string;
    @js(#{`description`:"Each role the gate names, by its id."}) `roleLabels`?: Record<string>;
    `realm`?: WithIdName;
    `wsTrustIssuer`?: NullableString;
    `realms`?: get_admin_api_console_r200_application_json_realms_h1386;
    `realmRoot`?: string;
    `portalHref`?: string;
    `sections`?: `WithLocaleChainCatalog`;
    @js(#{`description`:"Every console page's label, by its path."}) `navLabels`?: Record<string>;
    `retiring`?: NullableObject114;
    `runtime`?: {
      `process`?: string;
      `mode`?: string;
      `database`?: string;
      `keyEncryptionKey`?: string;
      `databasePassword`?: string
    };
    `persistence`?: WithEnabledMode;
    `version`?: WithVersionStampedBuildInfo;
    `locale`?: `WithNegotiatedOfferedDescription`
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@endpoint("/admin-api/console/language",
  "post",
  #{
    `operationId`:"setConsoleLanguage",
    `summary`:"Set the language the console is drawn in, for yourself",
    `description`:"Writes the signed-in person's own `preferredLanguage` (RFC 2798), or removes it when `lang` is empty, and answers the console's catalogs in the language now in force. A tag no catalog answers is refused (400, STS-I18N-0008).\n\n**Mirrors** `GET /admin` on the admin console.",
    `tags`:#["Service"],
    `responses`:#{
      `200`:#{
        `description`:"The console's language and catalogs.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The operation was refused; `errors` says why and nothing was handed over.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `requestBody`:#{`required`:false,`content`:#{`application/json`:#{`schema`:null}}},
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `setConsoleLanguage`(@js(#{`$open`:true}) `requestBody/content/application~1json/schema`: {
    @js(#{
      `description`:"A BCP 47 tag a catalog answers, such as `fr-CA`, or empty to follow the browser."
    }) `lang`?: string
  },
  `responses/200/content/application~1json/schema`: `WithOkErrorsLocale`,
  `responses/400/content/application~1json/schema`: `WithOkErrorsLocale`,
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@endpoint("/admin-api/console/delegation/map",
  "get",
  #{
    `operationId`:"getDelegationMap",
    `summary`:"The delegation picture: the graph, each box, the drawing",
    `description`:"The same acts as `GET /admin-api/delegation`, with the time taken out and the parties shared: a party that is the intermediary of six chains is ONE node with six edges. Drawn from everything that MATCHED the filter, not from one page of it.\n\n`nodes` and `edges` are the graph. `looks` says what each node IS, by node id: its label, its shape, the identifier a protocol would present for it, and the console page it links to — which the directory and the application registry decide. `svg` is the drawing, laid out on the server, with its links in it; `drawing` is its size, and says so if the layout failed. `summary` carries the counts by mechanism, kind and outcome that the filter's choices show.\n\nWith `format=svg` the answer is the SVG document alone, with no links in it, as `image/svg+xml`.\n\n**Mirrors** `GET /admin/delegation/map` on the admin console.",
    `tags`:#["Delegation"],
    `responses`:#{
      `200`:#{
        `description`:"The graph, every node's look, the counts and the drawing.",
        `content`:#{`image/svg+xml`:#{`schema`:null},`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `parameters`:#[
      #{
        `name`:"type",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"One mechanism. The reply's `types` member describes each of them, with the specification it comes from and whether this service polices it."
      },
      #{
        `name`:"mode",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The protocol-independent axis: whether what came out carries the chain. ANDed with `type`, so a mode that does not match the mechanism matches nothing."
      },
      #{
        `name`:"outcome",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Two rather than the audit log's three: a delegation is DECIDED rather than performed, so there is no third answer between issuing the credential and refusing to."
      },
      #{
        `name`:"protocol",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The family, spelled as /admin-api/users spells it — `Kerberos v5`, `WS-Trust`, `OAuth 2.0`. Free text rather than an enum, for the reason the audit log's `protocol` is."
      },
      #{
        `name`:"q",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Substring of ANY party of the chain (normalised name, presented form or application) or of either explanation, case-insensitive. One box over six fields, because the fact a caller has names one of them and not which column it is in."
      },
      #{
        `name`:"format",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"`svg` answers the drawing alone, as a document with no links in it. `json`, the default, answers everything."
      },
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of the match to return. CLAMPED rather than refused: a page past the end returns the last one, and the reply says which page it actually is."
      },
      #{
        `name`:"per",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Rows per page. Defaults to 50 and is capped at 300. On a drill-down it is SHARED by every list in the reply, which each carry a page number of their own."
      },
      #{
        `name`:"permq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Part of a permission's resource."
      },
      #{
        `name`:"grantq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Part of a grant's client or resource."
      },
      #{
        `name`:"appq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The application chooser's search."
      },
      #{
        `name`:"userq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The person chooser's search."
      },
      #{
        `name`:"appfrom",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Where the application chooser's page starts."
      },
      #{
        `name`:"userfrom",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Where the person chooser's page starts."
      },
      #{
        `name`:"chainsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `chains` to return, clamped as `page` is."
      },
      #{
        `name`:"permissionsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `permissions` to return, clamped as `page` is."
      },
      #{
        `name`:"grantsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `grants` to return, clamped as `page` is."
      },
      #{
        `name`:"pairsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `pairs` to return, clamped as `page` is."
      },
      #{
        `name`:"flagsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `flags` to return, clamped as `page` is."
      },
      #{
        `name`:"mechanismsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `mechanisms` to return, clamped as `page` is."
      },
      #{
        `name`:"policyPairsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `policyPairs` to return, clamped as `page` is."
      },
      #{
        `name`:"intermediariesPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `intermediaries` to return, clamped as `page` is."
      },
      #{
        `name`:"peoplePage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `people` to return, clamped as `page` is."
      },
      #{
        `name`:"groupsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groups` to return, clamped as `page` is."
      },
      #{
        `name`:"groupGrantsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groupGrants` to return, clamped as `page` is."
      },
      #{
        `name`:"groupPermissionsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groupPermissions` to return, clamped as `page` is."
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getDelegationMap`(`parameters/0/schema`: "krb5-s4u2self" | "krb5-s4u2proxy-classic" | "krb5-s4u2proxy-rbcd" | "krb5-forwarded" | "wstrust-onbehalfof" | "wstrust-actas" | "oauth-impersonation" | "oauth-delegation" | "oauth-assertion-grant" | "oauth-saml-assertion-grant" | "gnap-impersonation" | "gnap-derivation",
  `parameters/1/schema`: "impersonation" | "delegation",
  `parameters/2/schema`: "issued" | "refused",
  `parameters/3/schema`: string,
  `parameters/4/schema`: string,
  `parameters/5/schema`: "json" | "svg",
  @js(#{`minimum`:1}) `parameters/6/schema`: integer,
  @js(#{`minimum`:1,`maximum`:300}) `parameters/7/schema`: integer,
  `parameters/8/schema`: string,
  `parameters/9/schema`: string,
  `parameters/10/schema`: string,
  `parameters/11/schema`: string,
  @js(#{`minimum`:0}) `parameters/12/schema`: integer,
  @js(#{`minimum`:0}) `parameters/13/schema`: integer,
  @js(#{`minimum`:1}) `parameters/14/schema`: integer,
  @js(#{`minimum`:1}) `parameters/15/schema`: integer,
  @js(#{`minimum`:1}) `parameters/16/schema`: integer,
  @js(#{`minimum`:1}) `parameters/17/schema`: integer,
  @js(#{`minimum`:1}) `parameters/18/schema`: integer,
  @js(#{`minimum`:1}) `parameters/19/schema`: integer,
  @js(#{`minimum`:1}) `parameters/20/schema`: integer,
  @js(#{`minimum`:1}) `parameters/21/schema`: integer,
  @js(#{`minimum`:1}) `parameters/22/schema`: integer,
  @js(#{`minimum`:1}) `parameters/23/schema`: integer,
  @js(#{`minimum`:1}) `parameters/24/schema`: integer,
  @js(#{`minimum`:1}) `parameters/25/schema`: integer,
  `responses/200/content/image~1svg+xml/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `drawing`?: WithWidthHeightFailed;
    `looks`?: `NodeSLookNodeId`;
    `label`?: string;
    `svg`?: string;
    `realm`?: WithIdNameIsDefault;
    `issuer`?: string;
    `nodes`?: `WithKindCountIdentifiers2`;
    `edges`?: `WithSeqAtKind3`;
    `tokens`?: `WithTotalEntriesKey`;
    `tokensLeftOff`?: integer;
    `maxTokenRows`?: integer;
    `acts`?: integer;
    `chains`?: integer;
    `filter`?: WithTypeModeOutcomeEtc5;
    `matched`?: integer;
    `held`?: integer;
    `summary`?: {
      `held`?: integer;
      `heldHere`?: integer;
      `processes`?: integer;
      `recorded`?: integer;
      `dropped`?: integer;
      `maxRecords`?: integer;
      `chains`?: integer;
      `oldestSeq`?: numeric;
      `newestSeq`?: numeric;
      @js(#{`description`:"Acts per mechanism."}) `byType`?: Record<integer>;
      @js(#{`description`:"Acts per mode."}) `byMode`?: Record<integer>;
      @js(#{`description`:"Acts per outcome."}) `byOutcome`?: Record<integer>;
      @js(#{`description`:"Acts per protocol."}) `byProtocol`?: Record<integer>
    };
    `all`?: integer;
    `types`?: (WithTypeProtocolModeEtc7)[];
    `modes`?: (WithModeLabelWhat)[];
    `outcomes`?: (string)[];
    `applicationChooser`?: `WithTotalEntriesKey2`;
    `userChooser`?: `WithTotalEntriesKey2`;
    `mapKey`?: string;
    `directoryLoaded`?: boolean;
    `facts`?: `WithDescriptionUsersDescription`
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@endpoint("/admin-api/console/federation/map",
  "get",
  #{
    `operationId`:"getFederationMap",
    `summary`:"This realm's federation relationships, drawn",
    `description`:"Every federation relationship of the trust realm, filtered by `role`, `protocol` and text, as a graph — the partners, this service and the applications behind each relationship — with the relationships and their sign-ins, the drawing (`svg`, laid out on the server, with its links), its size, the filter's vocabulary and the key.\n\nWith `format=svg` the answer is the SVG document alone, with no links in it, as `image/svg+xml`.\n\n**Mirrors** `GET /admin/federation/map` on the admin console.",
    `tags`:#["Federation"],
    `responses`:#{
      `200`:#{
        `description`:"The relationships, the graph and the drawing.",
        `content`:#{`image/svg+xml`:#{`schema`:null},`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `parameters`:#[
      #{
        `name`:"role",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Only relationships in this role."
      },
      #{
        `name`:"protocol",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Only relationships in this protocol."
      },
      #{
        `name`:"q",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Text anywhere in a relationship."
      },
      #{
        `name`:"format",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"`svg` answers the drawing alone, as a document with no links in it. `json`, the default, answers everything."
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getFederationMap`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `parameters/2/schema`: string,
  `parameters/3/schema`: "json" | "svg",
  `responses/200/content/image~1svg+xml/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `realm`?: WithIdNameIsDefault;
    `counts`?: {
      `relationships`?: integer;
      `serviceProvider`?: integer;
      `identityProvider`?: integer;
      `usable`?: integer;
      `applications`?: integer;
      `partners`?: integer;
      `authentications`?: integer
    };
    `filter`?: {`role`?: string; `protocol`?: string; `q`?: string};
    `empty`?: boolean;
    `filtered`?: boolean;
    `relationships`?: ({
      `id`?: string;
      `name`?: string;
      `role`?: string;
      `roleLabel`?: string;
      `protocol`?: string;
      `protocolLabel`?: string;
      `peer`?: string;
      `application`?: string;
      `enabled`?: boolean;
      `ready`?: boolean;
      `missing`?: (string)[];
      `usable`?: boolean;
      `signsIn`?: boolean;
      `signalsEnabled`?: boolean;
      `authentications`?: integer;
      `users`?: integer;
      `lastUser`?: string;
      `lastSeen`?: string;
      `lastError`?: string;
      `lastErrorAt`?: string;
      `mechanism`?: string;
      `mechanismLabel`?: string;
      `mechanismKnown`?: boolean;
      `mechanismConfigured`?: boolean;
      `brokersTo`?: string;
      `brokerUsable`?: boolean;
      `brokerProblem`?: string;
      `brokeredUse`?: `BrokeredUseValue`;
      `releases`?: (string)[];
      `dn`?: string;
      `applications`?: ({
        `application`?: string;
        `source`?: string;
        `via`?: string;
        `configured`?: boolean;
        `authentications`?: integer;
        `users`?: integer;
        `lastUser`?: string;
        `lastSeen`?: string
      })[];
      `applicationCount`?: integer;
      `attributed`?: integer;
      `unattributed`?: integer
    })[];
    `nodes`?: ({
      `id`?: string;
      `kind`?: string;
      `label`?: string;
      `relationships`?: (string)[]
    })[];
    `edges`?: ({
      `id`?: string;
      `from`?: string;
      `to`?: string;
      `relation`?: string;
      `relationship`?: string;
      `brokeredTo`?: string;
      `use`?: `BrokeredUseValue`
    })[];
    `drawing`?: WithWidthHeightFailed;
    `label`?: string;
    `svg`?: string;
    `roles`?: (WithRoleLabelShortEtc4)[];
    `protocols`?: (WithProtocolLabelFamilyEtc7)[];
    `mapKey`?: string
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `key`:#{`type`:"string"},
      `members`:#{`type`:"array",`items`:#{`type`:"string"}},
      `counts`:#{`$ref`:"#/components/schemas/WithApplicationsGrantsLines3"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_admin_api_console_delegation_cluster_r200_application_json_group_h1397 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `key`:#{`type`:"string"},
      `members`:#{`type`:"array",`items`:#{`type`:"string"}},
      `grants`:#{`$ref`:"#/components/schemas/WithPagePagesPerPage4"},
      `permissions`:#{`$ref`:"#/components/schemas/WithKeyMembersCounts"},
      `counts`:#{`$ref`:"#/components/schemas/WithApplicationsGrantsLines3"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_admin_api_console_delegation_cluster_r200_application_json_cluster_h1398 {}

@endpoint("/admin-api/console/delegation/cluster",
  "get",
  #{
    `operationId`:"getDelegationCluster",
    `summary`:"One group of applications joined by permissions, drawn",
    `description`:"The group an application is in — the applications reachable from it by following delegated permissions either way — as `GET /admin-api/permissions/groups?application=` answers it, with the group whole (`cluster`), its grants and permissions paged (`groupGrantsPage`, `groupPermissionsPage`), the graph and, as for `/delegation/map`, `looks`, the drawing (`svg`) and its size. With no application, or one the register does not hold, the groups are paged instead (`groupPage`).\n\nWith `format=svg` the answer is the SVG document alone, with no links in it, as `image/svg+xml`.\n\n**Mirrors** `GET /admin/delegation/cluster` on the admin console.",
    `tags`:#["Delegation"],
    `responses`:#{
      `200`:#{
        `description`:"The group, its pages, the chooser's data and the drawing.",
        `content`:#{`image/svg+xml`:#{`schema`:null},`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `parameters`:#[
      #{
        `name`:"application",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The application's identifier, exactly."
      },
      #{
        `name`:"format",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"`svg` answers the drawing alone, as a document with no links in it. `json`, the default, answers everything."
      },
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of the match to return. CLAMPED rather than refused: a page past the end returns the last one, and the reply says which page it actually is."
      },
      #{
        `name`:"per",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Rows per page. Defaults to 50 and is capped at 300. On a drill-down it is SHARED by every list in the reply, which each carry a page number of their own."
      },
      #{
        `name`:"type",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"One mechanism. The reply's `types` member describes each of them, with the specification it comes from and whether this service polices it."
      },
      #{
        `name`:"mode",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The protocol-independent axis: whether what came out carries the chain. ANDed with `type`, so a mode that does not match the mechanism matches nothing."
      },
      #{
        `name`:"outcome",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Two rather than the audit log's three: a delegation is DECIDED rather than performed, so there is no third answer between issuing the credential and refusing to."
      },
      #{
        `name`:"protocol",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The family, spelled as /admin-api/users spells it — `Kerberos v5`, `WS-Trust`, `OAuth 2.0`. Free text rather than an enum, for the reason the audit log's `protocol` is."
      },
      #{
        `name`:"q",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Substring of ANY party of the chain (normalised name, presented form or application) or of either explanation, case-insensitive. One box over six fields, because the fact a caller has names one of them and not which column it is in."
      },
      #{
        `name`:"permq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Part of a permission's resource."
      },
      #{
        `name`:"grantq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Part of a grant's client or resource."
      },
      #{
        `name`:"appq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The application chooser's search."
      },
      #{
        `name`:"userq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The person chooser's search."
      },
      #{
        `name`:"appfrom",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Where the application chooser's page starts."
      },
      #{
        `name`:"userfrom",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Where the person chooser's page starts."
      },
      #{
        `name`:"chainsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `chains` to return, clamped as `page` is."
      },
      #{
        `name`:"permissionsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `permissions` to return, clamped as `page` is."
      },
      #{
        `name`:"grantsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `grants` to return, clamped as `page` is."
      },
      #{
        `name`:"pairsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `pairs` to return, clamped as `page` is."
      },
      #{
        `name`:"flagsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `flags` to return, clamped as `page` is."
      },
      #{
        `name`:"mechanismsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `mechanisms` to return, clamped as `page` is."
      },
      #{
        `name`:"policyPairsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `policyPairs` to return, clamped as `page` is."
      },
      #{
        `name`:"intermediariesPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `intermediaries` to return, clamped as `page` is."
      },
      #{
        `name`:"peoplePage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `people` to return, clamped as `page` is."
      },
      #{
        `name`:"groupsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groups` to return, clamped as `page` is."
      },
      #{
        `name`:"groupGrantsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groupGrants` to return, clamped as `page` is."
      },
      #{
        `name`:"groupPermissionsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groupPermissions` to return, clamped as `page` is."
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getDelegationCluster`(`parameters/0/schema`: string,
  `parameters/1/schema`: "json" | "svg",
  @js(#{`minimum`:1,`examples`:#[1]}) `parameters/2/schema`: integer,
  @js(#{`minimum`:1,`maximum`:300,`examples`:#[10]}) `parameters/3/schema`: integer,
  `parameters/4/schema`: "krb5-s4u2self" | "krb5-s4u2proxy-classic" | "krb5-s4u2proxy-rbcd" | "krb5-forwarded" | "wstrust-onbehalfof" | "wstrust-actas" | "oauth-impersonation" | "oauth-delegation" | "oauth-assertion-grant" | "oauth-saml-assertion-grant" | "gnap-impersonation" | "gnap-derivation",
  `parameters/5/schema`: "impersonation" | "delegation",
  `parameters/6/schema`: "issued" | "refused",
  `parameters/7/schema`: string,
  `parameters/8/schema`: string,
  `parameters/9/schema`: string,
  `parameters/10/schema`: string,
  `parameters/11/schema`: string,
  `parameters/12/schema`: string,
  @js(#{`minimum`:0}) `parameters/13/schema`: integer,
  @js(#{`minimum`:0}) `parameters/14/schema`: integer,
  @js(#{`minimum`:1}) `parameters/15/schema`: integer,
  @js(#{`minimum`:1}) `parameters/16/schema`: integer,
  @js(#{`minimum`:1}) `parameters/17/schema`: integer,
  @js(#{`minimum`:1}) `parameters/18/schema`: integer,
  @js(#{`minimum`:1}) `parameters/19/schema`: integer,
  @js(#{`minimum`:1}) `parameters/20/schema`: integer,
  @js(#{`minimum`:1}) `parameters/21/schema`: integer,
  @js(#{`minimum`:1}) `parameters/22/schema`: integer,
  @js(#{`minimum`:1}) `parameters/23/schema`: integer,
  @js(#{`minimum`:1}) `parameters/24/schema`: integer,
  @js(#{`minimum`:1}) `parameters/25/schema`: integer,
  @js(#{`minimum`:1}) `parameters/26/schema`: integer,
  `responses/200/content/image~1svg+xml/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `drawing`?: WithWidthHeightFailed;
    `looks`?: `NodeSLookNodeId`;
    `label`?: string;
    `svg`?: string;
    `application`?: NullableString;
    `group`?: get_admin_api_console_delegation_cluster_r200_application_json_group_h1397;
    `grants`?: `WithPagePagesPerPage4`;
    `grantsPaging`?: `WithPagePagesPerPage5`;
    `permissions`?: `WithKeyMembersCounts`;
    `permissionsPaging`?: `WithPagePagesPerPage5`;
    `groups`?: `WithAtFamilyKind2`;
    `counts`?: WithClustersApplicationsLargestEtc5;
    `paging`?: `WithPagePagesPerPage5`;
    `asked`?: string;
    `graph`?: `WithRealmIssuerNodes4`;
    `cluster`?: get_admin_api_console_delegation_cluster_r200_application_json_cluster_h1398;
    `register`?: `WithResourcesPermissionsGrants`;
    `clusters`?: `WithClustersDescriptionMemberOf2`;
    `grantPage`?: `WithShownPagingShown`;
    `permissionPage`?: `WithShownPagingOnlyWhileOn`;
    `groupPage`?: {`shown`?: `WithClustersDescriptionMemberOf`; `paging`?: `WithPagePagesPerPage5`};
    `facts`?: `WithDescriptionUsersDescription`;
    @js(#{`description`:"Each name in the answer the registry holds."}) `apps`?: Record<{`name`?: string; `dnLabel`?: string}>
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@endpoint("/admin-api/console/delegation/allowed",
  "get",
  #{
    `operationId`:"getDelegationAllowed",
    `summary`:"The configured delegated permissions, drawn, and groups",
    `description`:"Every delegated permission somebody configured — a client granted a permission a resource exposes — as a graph with, as for `/delegation/map`, `looks`, the drawing (`svg`) and its size. `groups` are the sets of applications the grants join, paged on `groupsPage` as `GET /admin-api/permissions/groups` summarises them; `shownGroups` are those groups in full and `clusters` all of them, which is what the page's chooser searches.\n\nWith `format=svg` the answer is the SVG document alone, with no links in it, as `image/svg+xml`.\n\n**Mirrors** `GET /admin/delegation/allowed` on the admin console.",
    `tags`:#["Delegation"],
    `responses`:#{
      `200`:#{
        `description`:"The graph, the groups, the register and the drawing.",
        `content`:#{`image/svg+xml`:#{`schema`:null},`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `parameters`:#[
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of the match to return. CLAMPED rather than refused: a page past the end returns the last one, and the reply says which page it actually is."
      },
      #{
        `name`:"per",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Rows per page. Defaults to 50 and is capped at 300. On a drill-down it is SHARED by every list in the reply, which each carry a page number of their own."
      },
      #{
        `name`:"format",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"`svg` answers the drawing alone, as a document with no links in it. `json`, the default, answers everything."
      },
      #{
        `name`:"type",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"One mechanism. The reply's `types` member describes each of them, with the specification it comes from and whether this service polices it."
      },
      #{
        `name`:"mode",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The protocol-independent axis: whether what came out carries the chain. ANDed with `type`, so a mode that does not match the mechanism matches nothing."
      },
      #{
        `name`:"outcome",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Two rather than the audit log's three: a delegation is DECIDED rather than performed, so there is no third answer between issuing the credential and refusing to."
      },
      #{
        `name`:"protocol",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The family, spelled as /admin-api/users spells it — `Kerberos v5`, `WS-Trust`, `OAuth 2.0`. Free text rather than an enum, for the reason the audit log's `protocol` is."
      },
      #{
        `name`:"q",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Substring of ANY party of the chain (normalised name, presented form or application) or of either explanation, case-insensitive. One box over six fields, because the fact a caller has names one of them and not which column it is in."
      },
      #{
        `name`:"permq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Part of a permission's resource."
      },
      #{
        `name`:"grantq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Part of a grant's client or resource."
      },
      #{
        `name`:"appq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The application chooser's search."
      },
      #{
        `name`:"userq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The person chooser's search."
      },
      #{
        `name`:"appfrom",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Where the application chooser's page starts."
      },
      #{
        `name`:"userfrom",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Where the person chooser's page starts."
      },
      #{
        `name`:"chainsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `chains` to return, clamped as `page` is."
      },
      #{
        `name`:"permissionsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `permissions` to return, clamped as `page` is."
      },
      #{
        `name`:"grantsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `grants` to return, clamped as `page` is."
      },
      #{
        `name`:"pairsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `pairs` to return, clamped as `page` is."
      },
      #{
        `name`:"flagsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `flags` to return, clamped as `page` is."
      },
      #{
        `name`:"mechanismsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `mechanisms` to return, clamped as `page` is."
      },
      #{
        `name`:"policyPairsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `policyPairs` to return, clamped as `page` is."
      },
      #{
        `name`:"intermediariesPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `intermediaries` to return, clamped as `page` is."
      },
      #{
        `name`:"peoplePage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `people` to return, clamped as `page` is."
      },
      #{
        `name`:"groupsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groups` to return, clamped as `page` is."
      },
      #{
        `name`:"groupGrantsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groupGrants` to return, clamped as `page` is."
      },
      #{
        `name`:"groupPermissionsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groupPermissions` to return, clamped as `page` is."
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getDelegationAllowed`(@js(#{`minimum`:1,`examples`:#[1]}) `parameters/0/schema`: integer,
  @js(#{`minimum`:1,`maximum`:300,`examples`:#[10]}) `parameters/1/schema`: integer,
  `parameters/2/schema`: "json" | "svg",
  `parameters/3/schema`: "krb5-s4u2self" | "krb5-s4u2proxy-classic" | "krb5-s4u2proxy-rbcd" | "krb5-forwarded" | "wstrust-onbehalfof" | "wstrust-actas" | "oauth-impersonation" | "oauth-delegation" | "oauth-assertion-grant" | "oauth-saml-assertion-grant" | "gnap-impersonation" | "gnap-derivation",
  `parameters/4/schema`: "impersonation" | "delegation",
  `parameters/5/schema`: "issued" | "refused",
  `parameters/6/schema`: string,
  `parameters/7/schema`: string,
  `parameters/8/schema`: string,
  `parameters/9/schema`: string,
  `parameters/10/schema`: string,
  `parameters/11/schema`: string,
  @js(#{`minimum`:0}) `parameters/12/schema`: integer,
  @js(#{`minimum`:0}) `parameters/13/schema`: integer,
  @js(#{`minimum`:1}) `parameters/14/schema`: integer,
  @js(#{`minimum`:1}) `parameters/15/schema`: integer,
  @js(#{`minimum`:1}) `parameters/16/schema`: integer,
  @js(#{`minimum`:1}) `parameters/17/schema`: integer,
  @js(#{`minimum`:1}) `parameters/18/schema`: integer,
  @js(#{`minimum`:1}) `parameters/19/schema`: integer,
  @js(#{`minimum`:1}) `parameters/20/schema`: integer,
  @js(#{`minimum`:1}) `parameters/21/schema`: integer,
  @js(#{`minimum`:1}) `parameters/22/schema`: integer,
  @js(#{`minimum`:1}) `parameters/23/schema`: integer,
  @js(#{`minimum`:1}) `parameters/24/schema`: integer,
  @js(#{`minimum`:1}) `parameters/25/schema`: integer,
  `responses/200/content/image~1svg+xml/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `drawing`?: WithWidthHeightFailed;
    `looks`?: `NodeSLookNodeId`;
    `label`?: string;
    `svg`?: string;
    `graph`?: `WithRealmIssuerNodes4`;
    `counts`?: `WithResourcesPermissionsUnidentified2`;
    `grants`?: `WithPagePagesPerPage4`;
    `groups`?: `WithAtFamilyKind2`;
    `groupCounts`?: WithClustersApplicationsLargestEtc5;
    `groupsPaging`?: `WithPagePagesPerPage5`;
    `register`?: `WithResourcesPermissionsGrants`;
    `clusters`?: `WithClustersDescriptionMemberOf2`;
    `shownGroups`?: `WithClustersDescriptionMemberOf`;
    `facts`?: `WithDescriptionUsersDescription`;
    @js(#{`description`:"Each name in the answer the registry holds."}) `apps`?: Record<{`name`?: string; `dnLabel`?: string}>
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `page`:#{`type`:"string"},
      `groups`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `group`:#{`type`:"string"},
            `settings`:#{`type`:"array",`items`:#{`$ref`:"#/components/schemas/WithKeyGroupLabel5"}}
          }
        }
      },
      `settingCount`:#{`type`:"integer"},
      `editableCount`:#{`type`:"integer"},
      `overridden`:#{`type`:"array",`items`:#{`type`:"string"}},
      `setWith`:#{`type`:"string"},
      `context`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `configFile`:#{`type`:#["string","null"]},
          `defaultsFile`:#{`type`:#["string","null"]},
          `persistsAppconfig`:#{`type`:"boolean"},
          `persistsRealms`:#{`type`:"boolean"},
          `persistenceMode`:#{`type`:"string"},
          `inRealm`:#{`type`:"boolean"},
          `realmId`:#{`type`:"string"}
        }
      },
      `sharedWith`:#{
        `type`:"object",
        `additionalProperties`:#{
          `type`:"array",
          `items`:#{
            `type`:"object",
            `additionalProperties`:false,
            `properties`:#{`path`:#{`type`:"string"},`label`:#{`type`:"string"}}
          }
        },
        `description`:"The other pages a settings group is drawn on."
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_admin_api_console_delegation_settings_r200_application_json_settings_h1402 {}

@endpoint("/admin-api/console/delegation-settings",
  "get",
  #{
    `operationId`:"getDelegationSettings",
    `summary`:"The configured permissions register, as its page shows it",
    `description`:"The delegated permissions register searched and paged as the page shows it — `permq` and `grantq` search the permissions and the grants, `permissionsPage` and `grantsPage` page them (`listState`) — with every application in the registry for the two selects (`allApplications`) and the page's settings block. `allowed` is the register with its filter and paging, as the page answered it before.\n\n**Mirrors** `GET /admin/delegation-settings` on the admin console.",
    `tags`:#["Delegation"],
    `responses`:#{
      `200`:#{
        `description`:"The register, its list state, the applications and the settings block.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `parameters`:#[
      #{
        `name`:"permq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Part of a permission's resource."
      },
      #{
        `name`:"grantq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Part of a grant's client or resource."
      },
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of the match to return. CLAMPED rather than refused: a page past the end returns the last one, and the reply says which page it actually is."
      },
      #{
        `name`:"per",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Rows per page. Defaults to 50 and is capped at 300. On a drill-down it is SHARED by every list in the reply, which each carry a page number of their own."
      },
      #{
        `name`:"type",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"One mechanism. The reply's `types` member describes each of them, with the specification it comes from and whether this service polices it."
      },
      #{
        `name`:"mode",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The protocol-independent axis: whether what came out carries the chain. ANDed with `type`, so a mode that does not match the mechanism matches nothing."
      },
      #{
        `name`:"outcome",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Two rather than the audit log's three: a delegation is DECIDED rather than performed, so there is no third answer between issuing the credential and refusing to."
      },
      #{
        `name`:"protocol",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The family, spelled as /admin-api/users spells it — `Kerberos v5`, `WS-Trust`, `OAuth 2.0`. Free text rather than an enum, for the reason the audit log's `protocol` is."
      },
      #{
        `name`:"q",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Substring of ANY party of the chain (normalised name, presented form or application) or of either explanation, case-insensitive. One box over six fields, because the fact a caller has names one of them and not which column it is in."
      },
      #{
        `name`:"appq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The application chooser's search."
      },
      #{
        `name`:"userq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The person chooser's search."
      },
      #{
        `name`:"appfrom",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Where the application chooser's page starts."
      },
      #{
        `name`:"userfrom",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Where the person chooser's page starts."
      },
      #{
        `name`:"chainsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `chains` to return, clamped as `page` is."
      },
      #{
        `name`:"permissionsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `permissions` to return, clamped as `page` is."
      },
      #{
        `name`:"grantsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `grants` to return, clamped as `page` is."
      },
      #{
        `name`:"pairsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `pairs` to return, clamped as `page` is."
      },
      #{
        `name`:"flagsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `flags` to return, clamped as `page` is."
      },
      #{
        `name`:"mechanismsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `mechanisms` to return, clamped as `page` is."
      },
      #{
        `name`:"policyPairsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `policyPairs` to return, clamped as `page` is."
      },
      #{
        `name`:"intermediariesPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `intermediaries` to return, clamped as `page` is."
      },
      #{
        `name`:"peoplePage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `people` to return, clamped as `page` is."
      },
      #{
        `name`:"groupsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groups` to return, clamped as `page` is."
      },
      #{
        `name`:"groupGrantsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groupGrants` to return, clamped as `page` is."
      },
      #{
        `name`:"groupPermissionsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groupPermissions` to return, clamped as `page` is."
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getDelegationSettings`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  @js(#{`minimum`:1,`examples`:#[1]}) `parameters/2/schema`: integer,
  @js(#{`minimum`:1,`maximum`:300,`examples`:#[10]}) `parameters/3/schema`: integer,
  `parameters/4/schema`: "krb5-s4u2self" | "krb5-s4u2proxy-classic" | "krb5-s4u2proxy-rbcd" | "krb5-forwarded" | "wstrust-onbehalfof" | "wstrust-actas" | "oauth-impersonation" | "oauth-delegation" | "oauth-assertion-grant" | "oauth-saml-assertion-grant" | "gnap-impersonation" | "gnap-derivation",
  `parameters/5/schema`: "impersonation" | "delegation",
  `parameters/6/schema`: "issued" | "refused",
  `parameters/7/schema`: string,
  `parameters/8/schema`: string,
  `parameters/9/schema`: string,
  `parameters/10/schema`: string,
  @js(#{`minimum`:0}) `parameters/11/schema`: integer,
  @js(#{`minimum`:0}) `parameters/12/schema`: integer,
  @js(#{`minimum`:1}) `parameters/13/schema`: integer,
  @js(#{`minimum`:1}) `parameters/14/schema`: integer,
  @js(#{`minimum`:1}) `parameters/15/schema`: integer,
  @js(#{`minimum`:1}) `parameters/16/schema`: integer,
  @js(#{`minimum`:1}) `parameters/17/schema`: integer,
  @js(#{`minimum`:1}) `parameters/18/schema`: integer,
  @js(#{`minimum`:1}) `parameters/19/schema`: integer,
  @js(#{`minimum`:1}) `parameters/20/schema`: integer,
  @js(#{`minimum`:1}) `parameters/21/schema`: integer,
  @js(#{`minimum`:1}) `parameters/22/schema`: integer,
  @js(#{`minimum`:1}) `parameters/23/schema`: integer,
  @js(#{`minimum`:1}) `parameters/24/schema`: integer,
  `responses/200/content/application~1json/schema`: {
    `allowed`?: {
      `resources`?: `WithResourcesPermissionsUnidentified`;
      `permissions`?: `WithKeyMembersCounts`;
      `grants`?: `WithPagePagesPerPage4`;
      `counts`?: `WithResourcesPermissionsUnidentified2`;
      `filter`?: WithPermissionsGrants;
      `paging`?: {`permissions`?: `WithPagePagesPerPage5`; `grants`?: `WithPagePagesPerPage5`}
    };
    `settings`?: get_admin_api_console_delegation_settings_r200_application_json_settings_h1402;
    `register`?: `WithResourcesPermissionsGrants`;
    `listState`?: {
      `permWanted`?: string;
      `grantWanted`?: string;
      `permPage`?: `WithShownPagingOnlyWhileOn`;
      `grantPage`?: `WithShownPagingShown`
    };
    `allApplications`?: (WithIdentifierName)[]
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `chainKey`:#{`type`:"string"},
      `protocol`:#{`type`:"string"},
      `type`:#{`type`:"string"},
      `typeLabel`:#{`type`:"string"},
      `mode`:#{`type`:"string"},
      `initial`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `key`:#{`type`:"string"},
          `presented`:#{`type`:"string"},
          `application`:#{`type`:"string"},
          `what`:#{`type`:"string"}
        }
      },
      `intermediary`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `key`:#{`type`:"string"},
          `presented`:#{`type`:"string"},
          `application`:#{`type`:"string"},
          `what`:#{`type`:"string"}
        }
      },
      `target`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `key`:#{`type`:"string"},
          `presented`:#{`type`:"string"},
          `application`:#{`type`:"string"},
          `what`:#{`type`:"string"}
        }
      },
      `acts`:#{`type`:"integer"},
      `issued`:#{`type`:"integer"},
      `refused`:#{`type`:"integer"},
      `firstAt`:#{`type`:"number"},
      `lastAt`:#{`type`:"number"},
      `authorizedBy`:#{`type`:"string"},
      `reason`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_admin_api_console_delegation_chain_r200_application_json_chain_h1404 {}

@endpoint("/admin-api/console/delegation/chain",
  "get",
  #{
    `operationId`:"getDelegationChain",
    `summary`:"One delegation relationship: its acts, graph and drawing",
    `description`:"One chain — (mechanism, initial identity, intermediary, target) — named by its `chain` key, as `GET /admin-api/delegation` lists them in `chains`. The answer is the chain, every act on it (not paged), the graph of those acts and, as for `/delegation/map`, `looks`, the drawing (`svg`, laid out on the server, with its links) and its size.\n\n**A KEY NO ACT IS HELD UNDER IS NOT AN ERROR**: the store is capped and drops the oldest, so the answer is `found: false` with `maxRecords`.\n\nWith `format=svg` the answer is the SVG document alone, with no links in it, as `image/svg+xml`.\n\n**Mirrors** `GET /admin/delegation/chain` on the admin console.",
    `tags`:#["Delegation"],
    `responses`:#{
      `200`:#{
        `description`:"The chain, its acts, the graph, every node's look and the drawing.",
        `content`:#{`image/svg+xml`:#{`schema`:null},`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `parameters`:#[
      #{
        `name`:"chain",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The chain's key, `chainKey` on a chain of `GET /admin-api/delegation`."
      },
      #{
        `name`:"format",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"`svg` answers the drawing alone, as a document with no links in it. `json`, the default, answers everything."
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getDelegationChain`(`parameters/0/schema`: string,
  `parameters/1/schema`: "json" | "svg",
  `responses/200/content/image~1svg+xml/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `drawing`?: WithWidthHeightFailed;
    `looks`?: `NodeSLookNodeId`;
    `label`?: string;
    `svg`?: string;
    `chain`?: get_admin_api_console_delegation_chain_r200_application_json_chain_h1404;
    `chainKey`?: string;
    `found`?: boolean;
    `acts`?: `WithIdLabelCa2`;
    `graph`?: `WithRealmIssuerNodes4`;
    `held`?: integer;
    `maxRecords`?: integer;
    `mapKey`?: string;
    `facts`?: `WithDescriptionUsersDescription`
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@endpoint("/admin-api/console/dashboard",
  "get",
  #{
    `operationId`:"getConsoleDashboard",
    `summary`:"What the console's front page draws",
    `description`:"The totals `GET /admin-api/status` answers, with the base URL, what is persisted, whether this realm is in development mode and so draws what the console deliberately does not do (`testDouble`) and the console sections the caller may see, which is what `/admin` draws.\n\n**Mirrors** `GET /admin` on the admin console.",
    `tags`:#["Service"],
    `responses`:#{
      `200`:#{
        `description`:"The current totals.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getConsoleDashboard`(`responses/200/content/application~1json/schema`: {
    `issuer`?: NullableString;
    `startedAt`?: string;
    `uptimeMs`?: numeric;
    `calls`?: numeric;
    `tokensHeld`?: numeric;
    `tokensHeldOnly`?: boolean;
    `tokensRevoked`?: numeric;
    `artifactsHeld`?: numeric;
    `signOnSessions`?: numeric;
    `usersKnown`?: numeric;
    `usersAuthenticatedHere`?: numeric;
    `pages`?: (string)[];
    `base`?: string;
    `persistence`?: WithEnabledMode;
    `testDouble`?: boolean;
    `sections`?: `WithLocaleChainCatalog`
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@endpoint("/admin-api/console/applications/new",
  "get",
  #{
    `operationId`:"getConsoleNewApplicationForm",
    `summary`:"Everything the new application form is drawn from",
    `description`:"The vocabulary `GET /admin-api/applications/new` answers, with how the form lays it out: its field groups, the combined protocol choices, the long text fields, the persistence note and the RFC 9728 import tab.\n\n**Mirrors** `GET /admin/applications/new` on the admin console.",
    `tags`:#["Applications"],
    `responses`:#{
      `200`:#{
        `description`:"The two vocabularies, the fields a create may carry, the container and the realm.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getConsoleNewApplicationForm`(`responses/200/content/application~1json/schema`: {
    `directory`?: boolean;
    `container`?: NullableString;
    `max`?: NullableNumber;
    `applicationCount`?: integer;
    `realm`?: WithIdName;
    `kinds`?: (WithKindLabelWhat)[];
    `protocols`?: ({
      `id`?: string;
      `label`?: string;
      `what`?: string;
      `kind`?: string;
      `kinds`?: (string)[];
      `identifierAttribute`?: string;
      `redirectAttribute`?: string;
      `logoutAttribute`?: string;
      `deliveryAttribute`?: string;
      `eventsAttribute`?: string;
      `secretAttribute`?: string
    })[];
    `declarations`?: ({
      `attribute`?: string;
      `role`?: string;
      `kind`?: string;
      `editable`?: Shape9;
      `sensitive`?: boolean;
      `what`?: string;
      `families`?: (WithIdLabel)[];
      `everyFamily`?: boolean
    })[];
    `fields`?: ({
      `attribute`?: string;
      `type`?: string;
      `long`?: boolean;
      `editable`?: Shape9;
      `sensitive`?: boolean;
      `overrides`?: string;
      `choices`?: NullableArray;
      `example`?: NullableString;
      `what`?: string;
      `families`?: (string)[];
      `everyFamily`?: boolean;
      `declaration`?: boolean;
      `primaryName`?: boolean;
      `simple`?: boolean;
      `group`?: string;
      `section`?: string;
      `sectionLabel`?: string;
      `inSimple`?: boolean;
      `described`?: `WithKeyGroupLabel5`
    })[];
    `fieldGroups`?: (WithIdLabelFamilies)[];
    `familyChoices`?: (WithIdLabelFamiliesEtc5)[];
    `longTextAttributes`?: (string)[];
    `defaultSecretLifetimeDays`?: numeric;
    `persistence`?: {
      `persistsDirectory`?: boolean;
      `mode`?: NullableString
    };
    `resourceMetadataImport`?: WithWellKnownAcceptsNonconformingDialsInternalAddresses;
    `editable`?: ({
      `name`?: string;
      `mode`?: Shape9;
      `sensitive`?: boolean;
      `families`?: (string)[]
    })[]
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `key`:#{`type`:"string"},
      `name`:#{`type`:"string"},
      `presented`:#{`type`:"string"},
      `forms`:#{`type`:"array",`items`:#{`type`:"string"}},
      `authenticated`:#{`type`:"boolean"},
      `isClient`:#{`type`:"boolean"},
      `authentications`:#{`type`:"integer"},
      `protocols`:#{`type`:"array",`items`:#{`type`:"string"}},
      `tokens`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `issued`:#{`type`:"integer"},
          `valid`:#{`type`:"integer"},
          `expired`:#{`type`:"integer"},
          `revoked`:#{`type`:"integer"},
          `other`:#{`type`:"integer"}
        }
      },
      `artifacts`:#{`type`:"integer"},
      `lastAt`:#{`type`:"number"},
      `delegated`:#{`type`:"boolean"},
      `acts`:#{`type`:"integer"},
      `issued`:#{`type`:"integer"},
      `refused`:#{`type`:"integer"},
      `chains`:#{`type`:"integer"},
      `roles`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `initial`:#{`type`:"integer"},
          `intermediary`:#{`type`:"integer"},
          `target`:#{`type`:"integer"}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_admin_api_console_delegation_user_r200_application_json_user_h1415 {}

@endpoint("/admin-api/console/delegation/user",
  "get",
  #{
    `operationId`:"getConsoleDelegationUser",
    `summary`:"One person's delegations, drawn",
    `description`:"What `GET /admin-api/delegation/user` answers, with every node's look, the drawing (`svg`) and its size, and the page's chooser, key and facts. With `format=svg` the answer is the SVG document alone, with no links in it, as `image/svg+xml`.\n\n**Mirrors** `GET /admin/delegation/user` on the admin console.",
    `tags`:#["Delegation"],
    `responses`:#{
      `200`:#{
        `description`:"The person, their credentials, flows and acts, the graph, every node's look and the drawing.",
        `content`:#{`image/svg+xml`:#{`schema`:null},`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `parameters`:#[
      #{
        `name`:"user",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The person, under any spelling this service has seen them under."
      },
      #{
        `name`:"format",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"`svg` answers the drawing alone, as a document with no links in it. `json`, the default, answers everything."
      },
      #{
        `name`:"type",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"One mechanism. The reply's `types` member describes each of them, with the specification it comes from and whether this service polices it."
      },
      #{
        `name`:"mode",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The protocol-independent axis: whether what came out carries the chain. ANDed with `type`, so a mode that does not match the mechanism matches nothing."
      },
      #{
        `name`:"outcome",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Two rather than the audit log's three: a delegation is DECIDED rather than performed, so there is no third answer between issuing the credential and refusing to."
      },
      #{
        `name`:"protocol",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The family, spelled as /admin-api/users spells it — `Kerberos v5`, `WS-Trust`, `OAuth 2.0`. Free text rather than an enum, for the reason the audit log's `protocol` is."
      },
      #{
        `name`:"q",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Substring of ANY party of the chain (normalised name, presented form or application) or of either explanation, case-insensitive. One box over six fields, because the fact a caller has names one of them and not which column it is in."
      },
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of the match to return. CLAMPED rather than refused: a page past the end returns the last one, and the reply says which page it actually is."
      },
      #{
        `name`:"per",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Rows per page. Defaults to 50 and is capped at 300. On a drill-down it is SHARED by every list in the reply, which each carry a page number of their own."
      },
      #{
        `name`:"permq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Part of a permission's resource."
      },
      #{
        `name`:"grantq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Part of a grant's client or resource."
      },
      #{
        `name`:"appq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The application chooser's search."
      },
      #{
        `name`:"userq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The person chooser's search."
      },
      #{
        `name`:"appfrom",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Where the application chooser's page starts."
      },
      #{
        `name`:"userfrom",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Where the person chooser's page starts."
      },
      #{
        `name`:"chainsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `chains` to return, clamped as `page` is."
      },
      #{
        `name`:"permissionsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `permissions` to return, clamped as `page` is."
      },
      #{
        `name`:"grantsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `grants` to return, clamped as `page` is."
      },
      #{
        `name`:"pairsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `pairs` to return, clamped as `page` is."
      },
      #{
        `name`:"flagsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `flags` to return, clamped as `page` is."
      },
      #{
        `name`:"mechanismsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `mechanisms` to return, clamped as `page` is."
      },
      #{
        `name`:"policyPairsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `policyPairs` to return, clamped as `page` is."
      },
      #{
        `name`:"intermediariesPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `intermediaries` to return, clamped as `page` is."
      },
      #{
        `name`:"peoplePage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `people` to return, clamped as `page` is."
      },
      #{
        `name`:"groupsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groups` to return, clamped as `page` is."
      },
      #{
        `name`:"groupGrantsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groupGrants` to return, clamped as `page` is."
      },
      #{
        `name`:"groupPermissionsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groupPermissions` to return, clamped as `page` is."
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getConsoleDelegationUser`(@js(#{`examples`:#["alice"]}) `parameters/0/schema`: string,
  @js(#{`examples`:#["json"]}) `parameters/1/schema`: "json" | "svg",
  `parameters/2/schema`: "krb5-s4u2self" | "krb5-s4u2proxy-classic" | "krb5-s4u2proxy-rbcd" | "krb5-forwarded" | "wstrust-onbehalfof" | "wstrust-actas" | "oauth-impersonation" | "oauth-delegation" | "oauth-assertion-grant" | "oauth-saml-assertion-grant" | "gnap-impersonation" | "gnap-derivation",
  `parameters/3/schema`: "impersonation" | "delegation",
  `parameters/4/schema`: "issued" | "refused",
  `parameters/5/schema`: string,
  `parameters/6/schema`: string,
  @js(#{`minimum`:1}) `parameters/7/schema`: integer,
  @js(#{`minimum`:1,`maximum`:300}) `parameters/8/schema`: integer,
  `parameters/9/schema`: string,
  `parameters/10/schema`: string,
  `parameters/11/schema`: string,
  `parameters/12/schema`: string,
  @js(#{`minimum`:0}) `parameters/13/schema`: integer,
  @js(#{`minimum`:0}) `parameters/14/schema`: integer,
  @js(#{`minimum`:1}) `parameters/15/schema`: integer,
  @js(#{`minimum`:1}) `parameters/16/schema`: integer,
  @js(#{`minimum`:1}) `parameters/17/schema`: integer,
  @js(#{`minimum`:1}) `parameters/18/schema`: integer,
  @js(#{`minimum`:1}) `parameters/19/schema`: integer,
  @js(#{`minimum`:1}) `parameters/20/schema`: integer,
  @js(#{`minimum`:1}) `parameters/21/schema`: integer,
  @js(#{`minimum`:1}) `parameters/22/schema`: integer,
  @js(#{`minimum`:1}) `parameters/23/schema`: integer,
  @js(#{`minimum`:1}) `parameters/24/schema`: integer,
  @js(#{`minimum`:1}) `parameters/25/schema`: integer,
  @js(#{`minimum`:1}) `parameters/26/schema`: integer,
  `responses/200/content/image~1svg+xml/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `drawing`?: WithWidthHeightFailed;
    `looks`?: `NodeSLookNodeId`;
    `label`?: string;
    `svg`?: string;
    `user`?: get_admin_api_console_delegation_user_r200_application_json_user_h1415;
    `asked`?: NullableString;
    `key`?: string;
    `credentials`?: `WithRealmIssuerNodes3`;
    `flows`?: ({
      `flow`?: string;
      `protocol`?: string;
      `label`?: string;
      `oidc`?: string;
      `spec`?: string;
      `browser`?: boolean;
      `what`?: string;
      `unknown`?: boolean
    })[];
    `onDelegationLines`?: integer;
    `acts`?: `WithIdLabelCa2`;
    `graph`?: `WithRealmIssuerNodes4`;
    `counts`?: NullableObject115;
    `users`?: ({
      `key`?: string;
      `name`?: string;
      `presented`?: string;
      `forms`?: (string)[];
      `authenticated`?: boolean;
      `isClient`?: boolean;
      `authentications`?: integer;
      `protocols`?: (string)[];
      `tokens`?: WithIssuedValidExpiredEtc52;
      `artifacts`?: integer;
      `lastAt`?: numeric;
      `delegated`?: boolean;
      `acts`?: integer;
      `issued`?: integer;
      `refused`?: integer;
      `chains`?: integer;
      `roles`?: WithInitialIntermediaryTarget2
    })[];
    `usersComplete`?: boolean;
    `chooser`?: `WithTotalEntriesKey2`;
    `mapKey`?: string;
    `facts`?: `WithDescriptionUsersDescription`
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `key`:#{`type`:"string"},
      `identifier`:#{`type`:"string"},
      `spellings`:#{`type`:"array",`items`:#{`type`:"string"}},
      `roles`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `initial`:#{`type`:"integer"},
          `intermediary`:#{`type`:"integer"},
          `target`:#{`type`:"integer"}
        }
      },
      `protocols`:#{`type`:"array",`items`:#{`type`:"string"}},
      `acts`:#{`type`:"integer"},
      `issued`:#{`type`:"integer"},
      `refused`:#{`type`:"integer"},
      `credentials`:#{`type`:"integer"},
      `firstAt`:#{`type`:"number"},
      `lastAt`:#{`type`:"number"},
      `identityKey`:#{`type`:"string"},
      `chains`:#{`type`:"integer"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_admin_api_console_delegation_application_r200_application_json_application_h1419 {}

@endpoint("/admin-api/console/delegation/application",
  "get",
  #{
    `operationId`:"getConsoleDelegationApplication",
    `summary`:"One application's delegations, drawn",
    `description`:"What `GET /admin-api/delegation/application` answers, with every node's look, the drawing (`svg`) and its size, and the page's chooser, key and facts. With `format=svg` the answer is the SVG document alone, with no links in it, as `image/svg+xml`.\n\n**Mirrors** `GET /admin/delegation/application` on the admin console.",
    `tags`:#["Delegation"],
    `responses`:#{
      `200`:#{
        `description`:"The application, its acts, the graph, every node's look and the drawing.",
        `content`:#{`image/svg+xml`:#{`schema`:null},`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `parameters`:#[
      #{
        `name`:"application",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The application, as a protocol presented it or normalised."
      },
      #{
        `name`:"format",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"`svg` answers the drawing alone, as a document with no links in it. `json`, the default, answers everything."
      },
      #{
        `name`:"type",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"One mechanism. The reply's `types` member describes each of them, with the specification it comes from and whether this service polices it."
      },
      #{
        `name`:"mode",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The protocol-independent axis: whether what came out carries the chain. ANDed with `type`, so a mode that does not match the mechanism matches nothing."
      },
      #{
        `name`:"outcome",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Two rather than the audit log's three: a delegation is DECIDED rather than performed, so there is no third answer between issuing the credential and refusing to."
      },
      #{
        `name`:"protocol",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The family, spelled as /admin-api/users spells it — `Kerberos v5`, `WS-Trust`, `OAuth 2.0`. Free text rather than an enum, for the reason the audit log's `protocol` is."
      },
      #{
        `name`:"q",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Substring of ANY party of the chain (normalised name, presented form or application) or of either explanation, case-insensitive. One box over six fields, because the fact a caller has names one of them and not which column it is in."
      },
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of the match to return. CLAMPED rather than refused: a page past the end returns the last one, and the reply says which page it actually is."
      },
      #{
        `name`:"per",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Rows per page. Defaults to 50 and is capped at 300. On a drill-down it is SHARED by every list in the reply, which each carry a page number of their own."
      },
      #{
        `name`:"permq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Part of a permission's resource."
      },
      #{
        `name`:"grantq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Part of a grant's client or resource."
      },
      #{
        `name`:"appq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The application chooser's search."
      },
      #{
        `name`:"userq",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The person chooser's search."
      },
      #{
        `name`:"appfrom",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Where the application chooser's page starts."
      },
      #{
        `name`:"userfrom",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Where the person chooser's page starts."
      },
      #{
        `name`:"chainsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `chains` to return, clamped as `page` is."
      },
      #{
        `name`:"permissionsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `permissions` to return, clamped as `page` is."
      },
      #{
        `name`:"grantsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `grants` to return, clamped as `page` is."
      },
      #{
        `name`:"pairsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `pairs` to return, clamped as `page` is."
      },
      #{
        `name`:"flagsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `flags` to return, clamped as `page` is."
      },
      #{
        `name`:"mechanismsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `mechanisms` to return, clamped as `page` is."
      },
      #{
        `name`:"policyPairsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `policyPairs` to return, clamped as `page` is."
      },
      #{
        `name`:"intermediariesPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `intermediaries` to return, clamped as `page` is."
      },
      #{
        `name`:"peoplePage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `people` to return, clamped as `page` is."
      },
      #{
        `name`:"groupsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groups` to return, clamped as `page` is."
      },
      #{
        `name`:"groupGrantsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groupGrants` to return, clamped as `page` is."
      },
      #{
        `name`:"groupPermissionsPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `groupPermissions` to return, clamped as `page` is."
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getConsoleDelegationApplication`(@js(#{`examples`:#["no-such-application"]}) `parameters/0/schema`: string,
  @js(#{`examples`:#["json"]}) `parameters/1/schema`: "json" | "svg",
  `parameters/2/schema`: "krb5-s4u2self" | "krb5-s4u2proxy-classic" | "krb5-s4u2proxy-rbcd" | "krb5-forwarded" | "wstrust-onbehalfof" | "wstrust-actas" | "oauth-impersonation" | "oauth-delegation" | "oauth-assertion-grant" | "oauth-saml-assertion-grant" | "gnap-impersonation" | "gnap-derivation",
  `parameters/3/schema`: "impersonation" | "delegation",
  `parameters/4/schema`: "issued" | "refused",
  `parameters/5/schema`: string,
  `parameters/6/schema`: string,
  @js(#{`minimum`:1}) `parameters/7/schema`: integer,
  @js(#{`minimum`:1,`maximum`:300}) `parameters/8/schema`: integer,
  `parameters/9/schema`: string,
  `parameters/10/schema`: string,
  `parameters/11/schema`: string,
  `parameters/12/schema`: string,
  @js(#{`minimum`:0}) `parameters/13/schema`: integer,
  @js(#{`minimum`:0}) `parameters/14/schema`: integer,
  @js(#{`minimum`:1}) `parameters/15/schema`: integer,
  @js(#{`minimum`:1}) `parameters/16/schema`: integer,
  @js(#{`minimum`:1}) `parameters/17/schema`: integer,
  @js(#{`minimum`:1}) `parameters/18/schema`: integer,
  @js(#{`minimum`:1}) `parameters/19/schema`: integer,
  @js(#{`minimum`:1}) `parameters/20/schema`: integer,
  @js(#{`minimum`:1}) `parameters/21/schema`: integer,
  @js(#{`minimum`:1}) `parameters/22/schema`: integer,
  @js(#{`minimum`:1}) `parameters/23/schema`: integer,
  @js(#{`minimum`:1}) `parameters/24/schema`: integer,
  @js(#{`minimum`:1}) `parameters/25/schema`: integer,
  @js(#{`minimum`:1}) `parameters/26/schema`: integer,
  `responses/200/content/image~1svg+xml/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `drawing`?: WithWidthHeightFailed;
    `looks`?: `NodeSLookNodeId`;
    `label`?: string;
    `svg`?: string;
    `application`?: get_admin_api_console_delegation_application_r200_application_json_application_h1419;
    `asked`?: NullableString;
    `key`?: string;
    `registered`?: boolean;
    `registeredName`?: string;
    `acts`?: `WithIdLabelCa2`;
    `graph`?: `WithRealmIssuerNodes4`;
    @js(#{`description`:"The roles played, by the act's `seq`."}) `rolesBySeq`?: Record<(string)[]>;
    `applications`?: ({
      `key`?: string;
      `identifier`?: string;
      `spellings`?: (string)[];
      `roles`?: WithInitialIntermediaryTarget2;
      `protocols`?: (string)[];
      `acts`?: integer;
      `issued`?: integer;
      `refused`?: integer;
      `credentials`?: integer;
      `firstAt`?: numeric;
      `lastAt`?: numeric;
      `identityKey`?: string;
      `chains`?: integer
    })[];
    `held`?: integer;
    `maxRecords`?: integer;
    `roles`?: (WithRoleLabelWhat)[];
    `chooser`?: `WithTotalEntriesKey2`;
    `mapKey`?: string;
    `facts`?: `WithDescriptionUsersDescription`
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@endpoint("/admin-api/console/pki/apply-profile",
  "post",
  #{
    `operationId`:"applyPkiProfile",
    `summary`:"Fill the certificate form in from a profile",
    `description`:"Rewrites the twenty-two extension boxes, the default validity and the profile’s Common Name from the profile named in `pki_profile`, and narrows the two algorithm menus to the approach in `pki_pq_mode`. Nothing is issued.\n\n**A COMMON NAME SOMEBODY TYPED IS NEVER OVERWRITTEN** — an empty one, or one still holding ANY profile’s own default, is replaced. Picking Intermediate CA after Root CA would otherwise issue an intermediate called \"RootCA\", which chains correctly and reads as a bug for as long as it takes somebody to notice.\n\nPost the whole form back; anything omitted falls to its default rather than being kept.\n\n**Mirrors** `POST /admin/pki, POST /admin/pki/certificate and POST /admin/pki/person` on the admin console.",
    `tags`:#["PKI"],
    `responses`:#{
      `200`:#{
        `description`:"The form, as it should now be drawn, in `draft`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The operation was refused; `errors` says why and nothing changed.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `requestBody`:#{`required`:false,`content`:#{`application/json`:#{`schema`:null}}},
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `applyPkiProfile`(@js(#{
    `examples`:#[#{`pki_profile`:"tls-server",`pki_pq_mode`:"classical"}],
    `additionalProperties`:true
  }) `requestBody/content/application~1json/schema`: {},
  `responses/200/content/application~1json/schema`: `WithOkErrorsWhy`,
  `responses/400/content/application~1json/schema`: `WithOkErrorsWhy`,
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@endpoint("/admin-api/console/pki/generate-keys",
  "post",
  #{
    `operationId`:"generatePkiKeyPair",
    `summary`:"Generate a key pair into the form without issuing anything",
    `description`:"Puts a fresh pair in `pki_private_key` and `pki_public_key`, in the algorithm named by `pki_key_alg`.\n\n**IT EXISTS BECAUSE GENERATION CAN BE SLOW.** An SLH-DSA pair takes seconds and this process is single-threaded, so making one and then issuing four certificates from it (with `pki_reuse_key`) is the difference between a usable surface and one that stalls the whole service four times over.\n\n**Mirrors** `POST /admin/pki, POST /admin/pki/certificate and POST /admin/pki/person` on the admin console.",
    `tags`:#["PKI"],
    `responses`:#{
      `200`:#{
        `description`:"The form with the new pair in it, in `draft`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The operation was refused; `errors` says why and nothing changed.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `requestBody`:#{`required`:false,`content`:#{`application/json`:#{`schema`:null}}},
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `generatePkiKeyPair`(@js(#{`examples`:#[#{`pki_key_alg`:"ec-p384"}],`additionalProperties`:true}) `requestBody/content/application~1json/schema`: {},
  `responses/200/content/application~1json/schema`: `WithOkErrorsWhy`,
  `responses/400/content/application~1json/schema`: `WithOkErrorsWhy`,
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@endpoint("/admin-api/console/pki/generate-alt-keys",
  "post",
  #{
    `operationId`:"generatePkiAltKeyPair",
    `summary`:"Generate the alternative (hybrid) key pair",
    `description`:"The second key of a hybrid certificate — ITU-T X.509 (2019) clause 9.8’s `subjectAltPublicKeyInfo`. The list is the post-quantum algorithms that can sign, because a hybrid certificate whose second key is also RSA is a certificate signed twice by the same century. Issuing with `pki_pq_mode=hybrid` generates one anyway if the boxes are empty.\n\n**Mirrors** `POST /admin/pki, POST /admin/pki/certificate and POST /admin/pki/person` on the admin console.",
    `tags`:#["PKI"],
    `responses`:#{
      `200`:#{
        `description`:"The form with the alternative pair in it.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The operation was refused; `errors` says why and nothing changed.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `requestBody`:#{`required`:false,`content`:#{`application/json`:#{`schema`:null}}},
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `generatePkiAltKeyPair`(@js(#{
    `examples`:#[#{`pki_alt_key_alg`:"ml-dsa-65"}],
    `additionalProperties`:true
  }) `requestBody/content/application~1json/schema`: {},
  `responses/200/content/application~1json/schema`: `WithOkErrorsWhy`,
  `responses/400/content/application~1json/schema`: `WithOkErrorsWhy`,
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@endpoint("/admin-api/console/pki/use-key",
  "post",
  #{
    `operationId`:"usePkiStoredKey",
    `summary`:"Load a stored object’s key pair back into the form",
    `description`:"What a CA renewing its own certificate does. It ticks `pki_reuse_key` itself, because a pair loaded into the boxes and then silently replaced by a fresh one at the next issue is the most confusing thing this surface could do. Everything else on the form is kept.\n\n**Mirrors** `POST /admin/pki, POST /admin/pki/certificate and POST /admin/pki/person` on the admin console.",
    `tags`:#["PKI"],
    `responses`:#{
      `200`:#{
        `description`:"The form with that key pair in it.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The operation was refused; `errors` says why and nothing changed.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null}}},
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `usePkiStoredKey`(@js(#{
    `examples`:#[#{`objectId`:"ca-1f2e3d4c5b6a7980"}],
    `additionalProperties`:true
  }) `requestBody/content/application~1json/schema`: WithDescriptionObjectId,
  `responses/200/content/application~1json/schema`: `WithOkErrorsWhy`,
  `responses/400/content/application~1json/schema`: `WithOkErrorsWhy`,
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@endpoint("/admin-api/console/applications/generate-secret",
  "post",
  #{
    `operationId`:"generateClientSecret",
    `summary`:"Mint a client secret for an application about to be created, writing nothing",
    `description`:"Mints a secret exactly as `regenerate-secret` and `POST /oauth2/register` do — `oauth2.registeredSecretBytes` random bytes, base64url — and hands it back. **IT NAMES NO APPLICATION AND WRITES NOTHING**: pass the value to `create` in `fields.oauthClientSecret` and it becomes that application's credential, with `oauthTokenEndpointAuthMethod` written as `client_secret_basic` unless `create` names another. The token endpoint accepts the secret by an `Authorization: Basic` header or a `client_secret` form parameter for that method.\n\n**Mirrors** `POST /admin/applications, POST /admin/applications/new, POST /admin/applications/edit and POST /admin/applications/owners` on the admin console.",
    `tags`:#["Applications"],
    `responses`:#{
      `200`:#{
        `description`:"The secret in `clientSecret`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The operation was refused; `errors` says why and nothing changed.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `requestBody`:#{`required`:false,`content`:#{`application/json`:#{`schema`:null}}},
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `generateClientSecret`(@js(#{`examples`:#[#{}]}) `requestBody/content/application~1json/schema`: {},
  `responses/200/content/application~1json/schema`: `WithOkChangedClientSecret`,
  `responses/400/content/application~1json/schema`: `WithOkChangedClientSecret`,
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@endpoint("/admin-api/console/operations",
  "get",
  #{
    `operationId`:"getConsoleOperations",
    `summary`:"Every operation of both kinds, for the console's forms",
    `description`:"Every operation this API registers, management and console alike, with the console control it mirrors and its kind: the table the static console resolves a form to the operation it posts to through. The index, `GET /admin-api`, lists the management operations alone.\n\n**Mirrors** `GET /admin` on the admin console.",
    `tags`:#["Service"],
    `responses`:#{
      `200`:#{
        `description`:"Every operation.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getConsoleOperations`(`responses/200/content/application~1json/schema`: {
    `operations`?: ({
      `method`?: string;
      `path`?: string;
      `operationId`?: string;
      `summary`?: string;
      `mirrors`?: string;
      `kind`?: string;
      `drawnOn`?: (string)[];
      `query`?: (string)[]
    })[]
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  

@js(#{
    `description`:"The scopes a security scheme needs, by the scheme's name."
  }) @hoisted model get_admin_api_console_openapi_json_r200_application_json_security_i_h1421 is Record<(string)[]>;
  

@endpoint("/admin-api/console/openapi.json",
  "get",
  #{
    `operationId`:"getConsoleOpenApi",
    `summary`:"The OpenAPI 3.1 document for the console's operations",
    `description`:"The operations under `/admin-api/console`, built from the same table as `GET /admin-api/openapi.json`, which describes the management operations alone. For maintainers and tests: these answers follow the console's pages and are not a contract.\n\n**Mirrors** `GET /admin/sts-metadata` on the admin console.",
    `tags`:#["Service"],
    `responses`:#{
      `200`:#{
        `description`:"The document.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getConsoleOpenApi`(`responses/200/content/application~1json/schema`: {
    `openapi`: string;
    `info`: {
      `title`?: string;
      `version`?: string;
      `description`?: string;
      `license`?: {`name`?: string}
    };
    `servers`?: ({`url`?: string; `description`?: string})[];
    `tags`?: ({`name`?: string; `description`?: string})[];
    `security`?: (get_admin_api_console_openapi_json_r200_application_json_security_i_h1421)[];
    `paths`: `InsideOpenAPIDocumentPathsComponents`;
    `components`?: `InsideOpenAPIDocumentPathsComponents`
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure2`): void;
  
}
