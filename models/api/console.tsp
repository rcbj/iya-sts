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
    @js(#{`description`:"The custom claim sets and how many claims each holds."}) `claims`?: ({
      `id`?: string;
      `label`?: string;
      `count`?: integer;
      `claims`?: ({
        `name`?: string;
        `value`?: StringOrNumericOrBooleanEtc4;
        `nameFormat`?: string;
        `namespace`?: string;
        `attribute`?: string;
        `multi`?: boolean;
        `type`?: string
      })[]
    })[];
    @js(#{`description`:"Endpoint calls, in total and per matched route."}) `calls`?: {
      `total`?: integer;
      `paths`?: integer;
      `pathsHere`?: integer;
      `pathsElsewhere`?: integer;
      `byStatusClass`?: Record<numeric>;
      `pathsCollapsed`?: integer;
      `healthProbes`?: integer;
      `rows`?: ({
        `method`?: string;
        `path`?: string;
        `matched`?: boolean;
        `count`?: numeric;
        `totalMs`?: numeric;
        `maxMs`?: numeric;
        `lastAt`?: numeric;
        `lastStatus`?: NullableInteger;
        `statuses`?: Record<numeric>
      })[]
    };
    @js(#{`description`:"JWTs by kind, with the state of each."}) `tokens`?: {
      `held`?: integer;
      `heldOnly`?: boolean;
      `forgotten`?: integer;
      `cap`?: integer;
      `revoked`?: integer;
      `byKind`?: ({
        `kind`?: string;
        `issued`?: integer;
        `valid`?: integer;
        `expired`?: integer;
        `revoked`?: integer;
        `notYetValid`?: integer;
        `noExpiry`?: integer;
        `bound`?: integer
      })[]
    };
    `artifacts`?: {
      `held`?: integer;
      `heldHere`?: integer;
      `forgotten`?: integer;
      `cap`?: integer;
      `byKind`?: ({
        `kind`?: string;
        `issued`?: integer;
        `valid`?: integer;
        `expired`?: integer;
        `noExpiry`?: integer
      })[]
    };
    `users`?: {
      `known`?: integer;
      `cap`?: integer;
      `heldOnly`?: boolean;
      `forgotten`?: integer;
      `authenticatedHere`?: integer;
      `clients`?: integer;
      `authentications`?: integer
    };
    `sessions`?: {
      `families`?: ({`family`?: string; `subjects`?: integer; `who`?: (string)[]})[];
      `distinctSubjects`?: integer
    };
    `signOnSessions`?: {
      `held`?: NullableInteger;
      `active`?: NullableInteger;
      `windowed`?: boolean;
      `unread`?: boolean;
      `rows`?: ({
        `id`?: string;
        `username`?: string;
        `sub`?: string;
        `amr`?: string;
        `acr`?: string;
        `startedAt`?: numeric;
        `authTime`?: numeric;
        `authentications`?: integer;
        `expires`?: numeric;
        `expired`?: boolean;
        `wsfedRealms`?: (string)[];
        `deviceBound`?: {
          `bound`?: boolean;
          `alg`?: string;
          `boundAt`?: numeric;
          `refreshes`?: numeric;
          `refreshedAt`?: numeric;
          `fact`?: string;
          `reasons`?: (string)[]
        };
        `accountSet`?: string
      })[]
    }
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
    }) `settings`?: {
      `page`?: string;
      @js(#{`description`:"In the order `config.js` declares them."}) `groups`?: (WithGroupSettings)[];
      `settingCount`?: integer;
      @js(#{`description`:"How many of them can be changed while the service runs."}) `editableCount`?: integer;
      @js(#{`description`:"The keys on this page with a runtime override in force."}) `overridden`?: (string)[];
      @js(#{`description`:"The operation that writes them."}) `setWith`?: string;
      `context`?: {
        `configFile`?: NullableString;
        `defaultsFile`?: string;
        `persistsAppconfig`?: boolean;
        `persistsRealms`?: boolean;
        `persistenceMode`?: string;
        `inRealm`?: boolean;
        `realmId`?: string
      };
      @js(#{`description`:"A group drawn on another page as well, and those pages."}) `sharedWith`?: Record<({`path`?: string; `label`?: NullableString})[]>
    };
    `regeneratedEveryStart`?: boolean;
    `residency`?: {
      `persisting`?: boolean;
      `retention`?: string;
      `plaintextTtlS`?: numeric;
      `note`?: string;
      `realmsHeld`?: (string)[];
      `plaintextHeld`?: (string)[]
    };
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
    `signaturePolicy`?: {
      `pqcOnly`?: boolean;
      `surfaces`?: {
        `jose`?: {
          @js(#{`description`:"The setting holding what this surface signs with."}) `signSetting`?: string;
          @js(#{`description`:"The setting holding what this surface accepts."}) `acceptSetting`?: string;
          `rows`?: ({
            @js(#{`description`:"The algorithm."}) `id`?: string;
            @js(#{`description`:"Its name on this surface."}) `spelling`?: string;
            @js(#{`description`:"pq or composite, or empty for a classical algorithm."}) `pqc`?: string;
            `weak`?: boolean;
            @js(#{`description`:"Whether this realm signs with it now."}) `signs`?: boolean;
            @js(#{`description`:"Why not, or empty."}) `signRefusal`?: string;
            @js(#{`description`:"Whether this realm accepts it now."}) `accepts`?: boolean;
            @js(#{`description`:"Why not, or empty."}) `acceptRefusal`?: string
          })[]
        };
        `httpsig`?: {
          @js(#{`description`:"The setting holding what this surface signs with."}) `signSetting`?: string;
          @js(#{`description`:"The setting holding what this surface accepts."}) `acceptSetting`?: string;
          `rows`?: ({
            @js(#{`description`:"The algorithm."}) `id`?: string;
            @js(#{`description`:"Its name on this surface."}) `spelling`?: string;
            @js(#{`description`:"pq or composite, or empty for a classical algorithm."}) `pqc`?: string;
            `weak`?: boolean;
            @js(#{`description`:"Whether this realm signs with it now."}) `signs`?: boolean;
            @js(#{`description`:"Why not, or empty."}) `signRefusal`?: string;
            @js(#{`description`:"Whether this realm accepts it now."}) `accepts`?: boolean;
            @js(#{`description`:"Why not, or empty."}) `acceptRefusal`?: string
          })[]
        };
        `cose`?: {
          @js(#{`description`:"The setting holding what this surface signs with."}) `signSetting`?: string;
          @js(#{`description`:"The setting holding what this surface accepts."}) `acceptSetting`?: string;
          `rows`?: ({
            @js(#{`description`:"The algorithm."}) `id`?: string;
            @js(#{`description`:"Its name on this surface."}) `spelling`?: string;
            @js(#{`description`:"pq or composite, or empty for a classical algorithm."}) `pqc`?: string;
            `weak`?: boolean;
            @js(#{`description`:"Whether this realm signs with it now."}) `signs`?: boolean;
            @js(#{`description`:"Why not, or empty."}) `signRefusal`?: string;
            @js(#{`description`:"Whether this realm accepts it now."}) `accepts`?: boolean;
            @js(#{`description`:"Why not, or empty."}) `acceptRefusal`?: string
          })[]
        };
        `xml`?: {
          @js(#{`description`:"The setting holding what this surface signs with."}) `signSetting`?: string;
          @js(#{`description`:"The setting holding what this surface accepts."}) `acceptSetting`?: string;
          `rows`?: ({
            @js(#{`description`:"The algorithm."}) `id`?: string;
            @js(#{`description`:"Its name on this surface."}) `spelling`?: string;
            @js(#{`description`:"pq or composite, or empty for a classical algorithm."}) `pqc`?: string;
            `weak`?: boolean;
            @js(#{`description`:"Whether this realm signs with it now."}) `signs`?: boolean;
            @js(#{`description`:"Why not, or empty."}) `signRefusal`?: string;
            @js(#{`description`:"Whether this realm accepts it now."}) `accepts`?: boolean;
            @js(#{`description`:"Why not, or empty."}) `acceptRefusal`?: string
          })[]
        };
        `di`?: {
          @js(#{`description`:"The setting holding what this surface signs with."}) `signSetting`?: string;
          @js(#{`description`:"The setting holding what this surface accepts."}) `acceptSetting`?: string;
          `rows`?: ({
            @js(#{`description`:"The algorithm."}) `id`?: string;
            @js(#{`description`:"Its name on this surface."}) `spelling`?: string;
            @js(#{`description`:"pq or composite, or empty for a classical algorithm."}) `pqc`?: string;
            `weak`?: boolean;
            @js(#{`description`:"Whether this realm signs with it now."}) `signs`?: boolean;
            @js(#{`description`:"Why not, or empty."}) `signRefusal`?: string;
            @js(#{`description`:"Whether this realm accepts it now."}) `accepts`?: boolean;
            @js(#{`description`:"Why not, or empty."}) `acceptRefusal`?: string
          })[]
        };
        `x509`?: {
          @js(#{`description`:"The setting holding what this surface signs with."}) `signSetting`?: string;
          @js(#{`description`:"The setting holding what this surface accepts."}) `acceptSetting`?: string;
          `rows`?: ({
            @js(#{`description`:"The algorithm."}) `id`?: string;
            @js(#{`description`:"Its name on this surface."}) `spelling`?: string;
            @js(#{`description`:"pq or composite, or empty for a classical algorithm."}) `pqc`?: string;
            `weak`?: boolean;
            @js(#{`description`:"Whether this realm signs with it now."}) `signs`?: boolean;
            @js(#{`description`:"Why not, or empty."}) `signRefusal`?: string;
            @js(#{`description`:"Whether this realm accepts it now."}) `accepts`?: boolean;
            @js(#{`description`:"Why not, or empty."}) `acceptRefusal`?: string
          })[]
        }
      }
    };
    @js(#{`description`:"This service as the request reached it."}) `issuer`?: string;
    @js(#{
      `description`:"The trust realm the key material below belongs to. The ALGORITHM tables are process-wide; the SIGNING KEYS are per realm."
    }) `realm`?: string;
    `generatedAt`?: string;
    @js(#{`description`:"Where all of this happens."}) `oneModule`?: string;
    `drift`?: {
      `checked`?: boolean;
      `undescribed`?: (string)[];
      `stale`?: (string)[];
      `envelopes`?: (string)[]
    };
    `keys`?: {
      `realm`?: string;
      `regeneratedEveryStart`?: boolean;
      `signing`?: {
        `kty`?: string;
        `bits`?: integer;
        `alg`?: string;
        `kid`?: string;
        `certificate`?: string;
        `certificateFingerprint`?: NullableString;
        `what`?: string
      };
      `curveKeys`?: ({
        `alg`?: string;
        `kty`?: string;
        `crv`?: string;
        `kid`?: NullableString;
        `certificateFingerprint`?: NullableString
      })[];
      `postQuantum`?: {
        `algorithms`?: (string)[];
        `generated`?: boolean;
        `keys`?: ({
          `alg`?: string;
          `kty`?: string;
          `kid`?: NullableString;
          `certificateFingerprint`?: NullableString
        })[];
        `what`?: string
      };
      `signerGroups`?: {
        `model`?: string;
        `keys`?: ({
          `group`?: string;
          `slot`?: string;
          `alg`?: string;
          `kind`?: NullableString;
          `kid`?: NullableString;
          `pairedSlot`?: NullableString;
          `certificateFingerprint`?: NullableString
        })[]
      };
      `bbs`?: {`cryptosuite`?: string; `curve`?: string; `what`?: string};
      `tls`?: {
        `subject`?: NullableString;
        `names`?: (string)[];
        `fingerprint256`?: NullableString;
        `certificates`?: ({
          `algorithm`?: NullableString;
          `certificateFingerprint`?: NullableString
        })[];
        `notAfter`?: NullableString;
        `perRealm`?: boolean;
        `what`?: string
      };
      `spiffe`?: {
        `enabled`?: boolean;
        `ready`?: boolean;
        `perRealm`?: boolean;
        `trustDomain`?: NullableString;
        `authoritySource`?: string;
        `svidKeyType`?: string;
        `authorityKeyType`?: string;
        `x509KeyType`?: string;
        `jwtKeyType`?: string;
        `x509Authorities`?: integer;
        `authorityFingerprint`?: NullableString;
        `trustAnchors`?: integer;
        `jwtAuthorities`?: integer
      }
    };
    `families`?: ({
      `name`?: string;
      `signs`?: string;
      `verifies`?: string;
      `encrypts`?: string;
      `decrypts`?: string;
      `hashes`?: string;
      `keys`?: string;
      `whatItDoesNot`?: string;
      `envelopes`?: (string)[];
      `algorithms`?: ({
        `what`?: string;
        `values`?: (StringOrNumeric)[];
        `how`?: string
      })[]
    })[];
    `hashing`?: {
      `jws`?: (string)[];
      `xmlDigestMethods`?: ({`uri`?: string; `label`?: string})[];
      `scimDigest`?: ({`token`?: string; `hash`?: string})[];
      `fixed`?: ({`where`?: string; `hash`?: string; `what`?: string})[];
      `weak`?: ({`hash`?: string; `where`?: string; `why`?: string})[]
    };
    `signatures`?: {
      `jws`?: ({
        `alg`?: string;
        `family`?: NullableString;
        `kty`?: string;
        `crv`?: string;
        `hash`?: string;
        `asymmetric`?: boolean;
        `postQuantum`?: boolean;
        `composite`?: boolean;
        `dpop`?: boolean
      })[];
      `xml`?: ({
        `uri`?: string;
        `label`?: string;
        `family`?: NullableString;
        `hash`?: NullableString;
        `keyKind`?: NullableString;
        `verifiedHere`?: boolean;
        `signsWith`?: boolean
      })[];
      `canonicalization`?: ({
        `uri`?: string;
        `label`?: string;
        `exclusive`?: NullableBoolean;
        `comments`?: NullableBoolean;
        `usedHere`?: NullableBoolean
      })[];
      `cose`?: ({`coseAlg`?: integer; `jose`?: string})[];
      `other`?: ({`name`?: string; `what`?: string})[]
    };
    `encryption`?: {
      `jwe`?: {
        `keyManagementOut`?: (string)[];
        `keyManagementIn`?: (string)[];
        `contentEncryption`?: ({
          `enc`?: string;
          `bits`?: numeric;
          `mode`?: string;
          `cekBytes`?: numeric;
          `authenticated`?: boolean;
          `note`?: NullableString
        })[]
      };
      `xml`?: {
        `blockCiphers`?: ({
          `name`?: string;
          `uri`?: string;
          `keyBits`?: numeric;
          `mode`?: string;
          `ivBytes`?: numeric;
          `authenticated`?: boolean
        })[];
        `keyTransports`?: ({`name`?: string; `uri`?: string; `scheme`?: string; `safe`?: boolean})[];
        `configured`?: {
          `blockCipher`?: string;
          `keyTransport`?: string;
          `encryptAssertion`?: boolean;
          `encryptLogoutNameId`?: boolean
        }
      };
      `kerberos`?: {
        `performed`?: ({`id`?: integer; `name`?: string})[];
        `decodeOnly`?: ({`id`?: integer; `name`?: string})[];
        `preference`?: (integer)[]
      };
      `tls`?: {`what`?: string; `sockets`?: (string)[]}
    };
    @js(#{
      `description`:"The one to read before quoting this reply: signatures and key establishment are reported separately, because a signature is checked when it is presented while captured ciphertext can be kept and opened later."
    }) `postQuantum`?: {
      `algorithms`?: {
        `mlDsa`?: (string)[];
        `slhDsa`?: (string)[];
        `composite`?: ({
          `alg`?: string;
          `mlDsa`?: NullableString;
          `traditional`?: NullableString;
          `prehash`?: NullableString;
          `domainSeparator`?: NullableString
        })[];
        `keyType`?: string;
        `what`?: string;
        `independence`?: string
      };
      `signatures`?: ({`surface`?: string; `state`?: string; `how`?: string})[];
      `keyEstablishment`?: {
        `state`?: string;
        `surfaces`?: ({`surface`?: string; `state`?: string; `how`?: string})[];
        `mechanisms`?: (string)[];
        `postQuantum`?: (string)[];
        `hybrid`?: (string)[];
        `drafts`?: {`mlKem`?: string; `hpke`?: string; `hybrid`?: string};
        `what`?: string;
        `whatWouldClose`?: string
      };
      `symmetric`?: {`state`?: string; `strongest`?: string; `what`?: string}
    };
    `standards`?: ({
      `key`?: string;
      `name`?: string;
      `specs`?: (string)[];
      `coverage`?: string;
      `what`?: string
    })[]
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
    `filter`?: {
      `q`?: NullableString;
      `protocol`?: NullableString
    };
    `protocols`?: (string)[];
    `at`?: numeric;
    `expiryRules`?: Record<string>;
    `sessions`?: (`SessionRow`)[];
    `unauthenticatedHeld`?: numeric;
    `unauthenticatedKept`?: boolean;
    `unauthenticatedSessions`?: (`SessionRow`)[];
    `unauthenticatedPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `windowed`?: boolean;
    `accountChoices`?: {`enabled`?: boolean; `counts`?: Record<numeric>};
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    }
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
    }) `backchannelDeliveriesPaging`?: {
      @js(#{
        `description`:"How many there are in all, which is what to page through rather than the length of this array."
      }) `total`?: integer;
      @js(#{
        `description`:"The page these rows are from, CLAMPED — `?page=999` on a two-page list reports 2, which is the page in the reply."
      }) `page`?: integer;
      @js(#{`description`:"How many pages the match has."}) `pages`?: integer;
      @js(#{`description`:"Rows per page, clamped to the cap."}) `perPage`?: integer;
      @js(#{`description`:"1-based and inclusive; 0 when nothing matched."}) `firstRow`?: integer;
      @js(#{`description`:"1-based and inclusive."}) `lastRow`?: integer
    };
    @js(#{
      `description`:"How many deliveries this realm holds in each state.",
      `additionalProperties`:true
    }) `backchannelCounts`?: {
      `pending`?: integer;
      `sent`?: integer;
      @js(#{`description`:"The dead letters."}) `dead`?: integer
    };
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
    `factors`?: {
      `withSecond`?: numeric;
      `withTotp`?: numeric;
      `withKeys`?: numeric;
      `primaryKeys`?: numeric;
      `passwordOnly`?: numeric;
      `unreadable`?: numeric;
      `noCredential`?: numeric
    };
    `store`?: boolean;
    `scanned`?: numeric;
    `capped`?: boolean;
    `scanLimit`?: numeric;
    `directoryPeople`?: NullableNumber;
    `directoryCounts`?: NullableObject41;
    `directoryCountedAt`?: NullableString;
    `directoryCountsKeptFor`?: NullableNumber;
    `registryCap`?: numeric;
    `filter`?: {
      `q`?: NullableString;
      `protocol`?: NullableString;
      `factor`?: NullableString;
      `kind`?: NullableString
    };
    `serviceAccounts`?: numeric;
    `protocols`?: (string)[];
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `withActiveSession`?: NullableNumber;
    `personFieldCount`?: numeric;
    `newUserContainer`?: string;
    `registryKeeps`?: numeric;
    `users`?: ({
      `key`?: string;
      `name`?: string;
      `forms`?: ({`form`?: string; `count`?: numeric})[];
      `realms`?: ({`realm`?: string; `count`?: numeric})[];
      `protocols`?: ({
        `protocol`?: string;
        `count`?: numeric;
        `firstAt`?: numeric;
        `lastAt`?: numeric;
        `methods`?: ({`method`?: string; `count`?: numeric})[]
      })[];
      `authentications`?: numeric;
      `firstAt`?: numeric;
      `lastAt`?: numeric;
      `isClient`?: boolean;
      `authenticated`?: boolean;
      `knownBy`?: string;
      `events`?: ({
        `at`?: numeric;
        `protocol`?: string;
        `method`?: string;
        `presented`?: string;
        `realm`?: string;
        `sub`?: string;
        `address`?: string;
        `client_id`?: string;
        `amr`?: StringOrString;
        `acr`?: string;
        `sessionId`?: string;
        `note`?: string
      })[];
      `eventsForgotten`?: numeric;
      `tokens`?: {
        `issued`?: numeric;
        `valid`?: numeric;
        `expired`?: numeric;
        `revoked`?: numeric;
        `other`?: numeric
      };
      `artifactKinds`?: ({`kind`?: string; `count`?: numeric})[];
      `artifacts`?: numeric;
      `lastActivityAt`?: numeric;
      `factors`?: NullableObject42;
      `inDirectory`?: boolean;
      `serviceAccount`?: boolean;
      `liveSessions`?: NullableNumber;
      `dn`?: string
    })[]
  }

@js(#{
    `description`:"One identity: the names it has been seen under, how it authenticated, every sign-on session it holds with the tokens issued on each, and its directory entry."
  }) @component model `UserDetail` {
    `known`?: boolean;
    `user`?: {
      `key`?: string;
      `name`?: string;
      `forms`?: ({`form`?: string; `count`?: numeric})[];
      `realms`?: ({`realm`?: string; `count`?: numeric})[];
      `protocols`?: ({
        `protocol`?: string;
        `count`?: numeric;
        `firstAt`?: numeric;
        `lastAt`?: numeric;
        `methods`?: ({`method`?: string; `count`?: numeric})[]
      })[];
      `authentications`?: numeric;
      `firstAt`?: numeric;
      `lastAt`?: numeric;
      `isClient`?: boolean;
      `authenticated`?: boolean;
      `knownBy`?: string;
      `events`?: ({
        `at`?: numeric;
        `protocol`?: string;
        `method`?: string;
        `presented`?: string;
        `realm`?: string;
        `sub`?: string;
        `address`?: string;
        `client_id`?: string;
        `amr`?: StringOrString;
        `acr`?: string;
        `sessionId`?: string;
        `note`?: string
      })[];
      `eventsForgotten`?: numeric;
      `tokens`?: {
        `issued`?: numeric;
        `valid`?: numeric;
        `expired`?: numeric;
        `revoked`?: numeric;
        `other`?: numeric
      };
      `artifactKinds`?: ({`kind`?: string; `count`?: numeric})[];
      `artifacts`?: numeric;
      `lastActivityAt`?: numeric
    };
    `subject`?: string;
    `serviceAccount`?: NullableObject43;
    `risk`?: NullableObject44;
    `factors`?: NullableObject45;
    `sessions`?: ({
      `id`?: string;
      `username`?: string;
      `sub`?: string;
      `amr`?: string;
      `acr`?: string;
      `startedAt`?: numeric;
      `authTime`?: numeric;
      `authentications`?: numeric;
      `expires`?: numeric;
      `expired`?: boolean;
      `wsfedRealms`?: (string)[];
      `deviceBound`?: NullableObject40;
      `accountSet`?: string;
      `tokens`?: ({
        `state`?: string;
        `key`?: string;
        `jti`?: string;
        `kind`?: string;
        `typ`?: string;
        `revocable`?: boolean;
        `sub`?: string;
        `iss`?: string;
        `username`?: string;
        `client_id`?: StringOrString;
        `audience`?: string;
        `scope`?: StringOrString;
        `jkt`?: string;
        `x5t`?: string;
        `x5tSpki`?: string;
        `iat`?: numeric;
        `nbf`?: numeric;
        `exp`?: numeric;
        `sessionId`?: string;
        `sessionAuthenticated`?: boolean;
        `setId`?: string;
        `grant`?: string;
        `grantId`?: string;
        `grantRefresh`?: boolean;
        `issuedAt`?: numeric;
        `revoked`?: boolean;
        `revokedAt`?: numeric;
        `revokedVia`?: string;
        `length`?: numeric
      })[];
      `tokensPaging`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      }
    })[];
    `sessionsPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `tokensOnEndedSessions`?: ({
      `state`?: string;
      `key`?: string;
      `jti`?: string;
      `kind`?: string;
      `typ`?: string;
      `revocable`?: boolean;
      `sub`?: string;
      `iss`?: string;
      `username`?: string;
      `client_id`?: StringOrString;
      `audience`?: string;
      `scope`?: StringOrString;
      `jkt`?: string;
      `x5t`?: string;
      `x5tSpki`?: string;
      `iat`?: numeric;
      `nbf`?: numeric;
      `exp`?: numeric;
      `sessionId`?: string;
      `sessionAuthenticated`?: boolean;
      `setId`?: string;
      `grant`?: string;
      `grantId`?: string;
      `grantRefresh`?: boolean;
      `issuedAt`?: numeric;
      `revoked`?: boolean;
      `revokedAt`?: numeric;
      `revokedVia`?: string;
      `length`?: numeric
    })[];
    `tokensOnEndedSessionsPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `tokensWithNoSession`?: ({
      `state`?: string;
      `key`?: string;
      `jti`?: string;
      `kind`?: string;
      `typ`?: string;
      `revocable`?: boolean;
      `sub`?: string;
      `iss`?: string;
      `username`?: string;
      `client_id`?: StringOrString;
      `audience`?: string;
      `scope`?: StringOrString;
      `jkt`?: string;
      `x5t`?: string;
      `x5tSpki`?: string;
      `iat`?: numeric;
      `nbf`?: numeric;
      `exp`?: numeric;
      `sessionId`?: string;
      `sessionAuthenticated`?: boolean;
      `setId`?: string;
      `grant`?: string;
      `grantId`?: string;
      `grantRefresh`?: boolean;
      `issuedAt`?: numeric;
      `revoked`?: boolean;
      `revokedAt`?: numeric;
      `revokedVia`?: string;
      `length`?: numeric
    })[];
    `tokensWithNoSessionPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `artifacts`?: ({
      `state`?: string;
      `kind`?: string;
      `issuedAt`?: numeric;
      `expiresAt`?: NullOrStringOrNumeric;
      `subject`?: string;
      `key`?: string;
      `id`?: string;
      `audience`?: string;
      `signed`?: boolean;
      `revoked`?: boolean;
      `revokedAt`?: numeric;
      `revokedVia`?: string;
      `realm`?: string;
      `service`?: string;
      `etype`?: StringOrNumeric;
      `claimSet`?: string;
      `username`?: string;
      `pacClaims`?: numeric;
      `entryId`?: string;
      `serial`?: string;
      `hint`?: string;
      `person`?: string;
      `configId`?: string
    })[];
    `artifactsPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `ldap`?: NullableObject46;
    `credentials`?: {
      `storable`?: boolean;
      `found`?: boolean;
      `keyPairs`?: ({
        `purpose`?: string;
        `label`?: string;
        `held`?: boolean;
        `keys`?: ({
          `handle`?: string;
          `label`?: string;
          `source`?: string;
          `state`?: string;
          `reason`?: string;
          `revokedAt`?: string;
          `serialHex`?: string;
          `expiresAt`?: string;
          `notAfter`?: string;
          `privateKeyHeld`?: boolean;
          `certificate`?: NullableObject47;
          `chain`?: ({
            `subject`?: string;
            `issuer`?: string;
            `serialHex`?: string;
            `notBefore`?: string;
            `notAfter`?: string;
            `expired`?: boolean;
            `selfSigned`?: boolean;
            `keyType`?: string;
            `thumbprint`?: string;
            `unreadable`?: string
          })[]
        })[];
        `valid`?: numeric;
        `atCap`?: boolean;
        `handleLabel`?: string;
        `issuers`?: (string)[];
        `effectiveIssuers`?: (string)[];
        `attributes`?: {`issuer`?: string; `keys`?: string; `privateKey`?: string}
      })[];
      `maxPerPerson`?: numeric;
      `revocationReasons`?: (string)[];
      `caAvailable`?: boolean;
      `sealsAtRest`?: boolean;
      `selfService`?: boolean;
      `sources`?: (string)[]
    };
    `federationLinks`?: ({
      `link`?: string;
      `relationship`?: string;
      `issuer`?: string;
      `subject`?: string;
      `relationshipExists`?: boolean
    })[];
    `federationLinksPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `kerberos`?: {
      `kdc`?: boolean;
      `realm`?: string;
      `trustRealm`?: string;
      `reason`?: string;
      `productKdc`?: NullableBoolean;
      `personKeys`?: boolean;
      `principal`?: string;
      `nameUsable`?: boolean;
      `person`?: boolean;
      `disabled`?: boolean;
      `keys`?: NullableObject48
    };
    `attributeEditor`?: NullableObject49;
    `gnapGrants`?: ({
      `id`?: string;
      `state`?: string;
      `finalization`?: NullableObject;
      `client`?: NullableString;
      `clientName`?: NullableString;
      `authorizationServer`?: NullableString;
      `createdAt`?: NullableNumber;
      `updatedAt`?: NullableNumber;
      `grantExpiresAt`?: NullableNumber;
      `approvedBy`?: string;
      @js(#{
        `x-free-form`:"An RFC 9635 access right as the client asked for it: a reference string or an object in the access type the resource server defines.",
        `description`:"An RFC 9635 access right as the client asked for it: a reference string or an object in the access type the resource server defines."
      }) `rights`?: unknown;
      `rightsAre`?: string;
      `subjectReleasedAt`?: NullableNumber;
      `derivedFrom`?: NullableString;
      `tokens`?: ({
        `jti`?: string;
        `label`?: NullableString;
        `format`?: string;
        `issuedAt`?: NullableNumber;
        `expiresAt`?: NullableNumber;
        `state`?: string;
        `bearer`?: boolean;
        @js(#{
          `x-free-form`:"An RFC 9635 access right as the client asked for it: a reference string or an object in the access type the resource server defines.",
          `description`:"An RFC 9635 access right as the client asked for it: a reference string or an object in the access type the resource server defines."
        }) `access`?: unknown;
        `revokedWhy`?: NullableString
      })[];
      `revocable`?: boolean
    })[];
    `gnapGrantsPaging`?: NullableObject50;
    `gnapGrantsCells`?: NullableObject51;
    `uma`?: NullableObject52;
    `authenticationEvents`?: ({
      `seq`?: numeric;
      `origin`?: string;
      `at`?: numeric;
      `category`?: string;
      `action`?: string;
      `outcome`?: string;
      `errorCode`?: string;
      `actor`?: string;
      `actorForm`?: string;
      `target`?: string;
      `protocol`?: string;
      `channel`?: string;
      `address`?: string;
      `summary`?: string;
      @js(#{
        `x-free-form`:"What the call site that wrote the audit row chose to record, which differs at each of hundreds of them; the keys and the values are data.",
        `description`:"What the call site that wrote the audit row chose to record, which differs at each of hundreds of them; the keys and the values are data."
      }) `detail`?: unknown
    })[];
    `authenticationEventsPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `authenticationEventsMatched`?: numeric;
    `authenticationEventsKnownActors`?: Record<boolean>;
    `authenticationEventsLog`?: {
      `held`?: numeric;
      `recorded`?: numeric;
      `dropped`?: numeric;
      `maxEvents`?: numeric
    };
    `page`?: {
      `key`?: string;
      `riskAsked`?: boolean;
      `counts`?: {
        `live`?: numeric;
        `tokens`?: numeric;
        `valid`?: numeric;
        `expired`?: numeric;
        `artifacts`?: numeric;
        `ended`?: numeric;
        `sessionless`?: numeric
      };
      `back`?: string;
      `params`?: Record<StringOrNumericOrBooleanEtcOrStringOrNumericOrBooleanEtc>;
      `blocksPerPage`?: numeric;
      `perPage`?: numeric;
      `maxEventsPerUser`?: numeric;
      `directoryLoaded`?: boolean;
      `mfa`?: {
        `storable`?: boolean;
        `mech`?: {
          `username`?: string;
          `password`?: boolean;
          `primaryKeys`?: numeric;
          `mfaKeys`?: numeric;
          `keys`?: ({
            `credentialId`?: string;
            `publicKeyJwk`?: {
              `kty`?: string;
              `crv`?: string;
              `alg`?: string;
              `use`?: string;
              `kid`?: string;
              `x`?: string;
              `y`?: string;
              `n`?: string;
              `e`?: string;
              `pub`?: string;
              `ext`?: boolean;
              `key_ops`?: (string)[]
            };
            `signCount`?: numeric;
            `enrolledAt`?: numeric;
            `lastUsedAt`?: numeric;
            `label`?: string;
            `attachment`?: NullableString;
            `userVerified`?: NullableBoolean;
            `aaguid`?: NullableString;
            `algorithm`?: NameStringCoseAlgNullableNumberTextStringPostQuantumBooleanInsecureBooleanLaneStringOrNullOrString;
            `coseAlg`?: NullableNumber;
            `attestation`?: NullableObject53;
            `backupEligible`?: NullableBoolean;
            `backupState`?: NullableBoolean;
            `transports`?: (string)[];
            `discoverable`?: NullableBoolean;
            `minPinLength`?: NullableNumber;
            `userHandle`?: string;
            `lane`?: string;
            `enrolledBy`?: {`username`?: string; `sub`?: string; `at`?: numeric};
            `provider`?: NullableString;
            `providerSource`?: string;
            `name`?: string;
            `group`?: string;
            `upgradedAt`?: numeric;
            `upgradedTo`?: string;
            `previousAlgorithm`?: string;
            `previousCoseAlg`?: NullableNumber;
            `previousCredentialId`?: string;
            `upgradeMode`?: string;
            `possiblyReplacedBy`?: string;
            `possiblyReplacedAt`?: numeric;
            `policyRefused`?: Record<{`why`?: string; `at`?: numeric}>;
            `attestationRefused`?: {`why`?: string; `at`?: numeric}
          })[];
          `totp`?: boolean;
          `totpUsable`?: boolean;
          `totpDetail`?: NullableObject54;
          `usable`?: boolean;
          `backupCodes`?: NullableObject55;
          `mfaRequired`?: boolean;
          `mailFactor`?: {
            `held`?: string;
            `optedIn`?: string;
            `why`?: string;
            `verified`?: boolean
          };
          `secondFactor`?: NullableString;
          `activated`?: boolean;
          `recoveryAdvised`?: boolean;
          `mfaRequirement`?: {
            `required`?: boolean;
            `byUser`?: boolean;
            `byRealm`?: boolean;
            `byAdministrator`?: boolean;
            `offered`?: boolean;
            `exemptServiceAccount`?: boolean
          };
          `passwordResetLink`?: NullableObject56;
          `disabled`?: boolean
        };
        `totp`?: {
          `enabled`?: boolean;
          `issuer`?: string;
          `digits`?: numeric;
          `period`?: numeric;
          `algorithm`?: string;
          `window`?: numeric;
          `secretBytes`?: numeric;
          `enrolmentTtlMs`?: numeric
        };
        `webauthn`?: {
          `enabled`?: boolean;
          `rpName`?: string;
          `rpId`?: string;
          `algorithms`?: (string)[];
          `attestation`?: string;
          `userVerification`?: string;
          `residentKey`?: string;
          `authenticatorAttachment`?: string;
          `timeoutMs`?: numeric;
          `credProps`?: boolean;
          `minPinLength`?: NullOrBooleanOrNumeric;
          `hints`?: (string)[];
          `maxKeysPerPerson`?: numeric;
          `primaryAllowed`?: boolean;
          `mfaAllowed`?: boolean;
          `usernameless`?: boolean;
          `insecureAlgorithms`?: boolean;
          `pqcOnly`?: boolean;
          `pqcAlongsideClassical`?: boolean
        };
        `recovery`?: {
          `enabled`?: boolean;
          `count`?: numeric;
          `length`?: numeric;
          `groupSize`?: numeric
        };
        `appPasswords`?: {
          `ok`?: boolean;
          `unreadable`?: boolean;
          `passwords`?: ({
            `id`?: string;
            `name`?: string;
            `doors`?: (string)[];
            `doorLabels`?: (string)[];
            `createdAt`?: numeric;
            `createdBy`?: string;
            `lastUsedAt`?: numeric;
            `lastUsedDoor`?: string
          })[];
          `errors`?: (string)[]
        };
        `doors`?: {
          `secondFactor`?: boolean;
          `refused`?: (string)[];
          `accepted`?: (string)[];
          `passwordAloneDoors`?: (string)[];
          `sentence`?: string
        };
        `verifications`?: {
          `user`?: string;
          `trustFrameworks`?: (string)[];
          `evidenceTypes`?: (string)[];
          `documentTypes`?: (string)[];
          `checkMethods`?: (string)[];
          `electronicRecordTypes`?: (string)[];
          `attestationTypes`?: (string)[];
          `verifiableClaims`?: (string)[];
          `verifications`?: ({
            `id`?: string;
            `recorded`?: NullOrStringOrNumeric2;
            `source`?: string;
            `by`?: string;
            @js(#{
              `x-free-form`:"The OpenID Connect for Identity Assurance `verification` element: a caller may post it whole as JSON, and a wallet or a certificate may supply it, so its evidence is that specification's to shape.",
              `description`:"The OpenID Connect for Identity Assurance `verification` element: a caller may post it whole as JSON, and a wallet or a certificate may supply it, so its evidence is that specification's to shape."
            }) `verification`?: unknown;
            @js(#{
              `x-free-form`:"The verified claims and their values, as the OpenID Connect claim each is: a string for most, an object for `address`, a list for `nationalities`.",
              `description`:"The verified claims and their values, as the OpenID Connect claim each is: a string for most, an object for `address`, a list for `nationalities`."
            }) `claims`?: unknown
          })[];
          `page`?: integer;
          `pages`?: integer;
          `perPage`?: integer;
          `total`?: integer;
          `paging`?: {
            `page`?: integer;
            `pages`?: integer;
            `perPage`?: integer;
            `firstRow`?: integer;
            `lastRow`?: integer;
            `total`?: integer;
            `param`?: string;
            `noun`?: string
          }
        };
        `inventsClaimValues`?: boolean;
        `devices`?: {
          `user`?: string;
          `maxPerPerson`?: numeric;
          `devices`?: ({
            `id`?: string;
            `dn`?: string;
            `owner`?: string;
            `ownerKind`?: string;
            `label`?: string;
            `applications`?: (string)[];
            `keys`?: ({
              `id`?: string;
              `kind`?: string;
              `thumbprint`?: string;
              `label`?: string;
              `added`?: NullOrStringOrNumeric;
              `addedBy`?: string;
              `proof`?: string;
              `attestation`?: {
                `level`?: string;
                `format`?: string;
                `summary`?: string;
                `verifiedAt`?: NullOrStringOrNumeric2;
                `chainSerials`?: (string)[];
                `revocation`?: {
                  `status`?: string;
                  `reason`?: string;
                  `serial`?: string;
                  `listVersion`?: string;
                  `checkedAt`?: NullOrStringOrNumeric2;
                  `chainSerials`?: (string)[];
                  `why`?: string
                };
                `freshness`?: {`status`?: string; `detail`?: string}
              };
              @js(#{
                `x-free-form`:"A device key's public material as its kind carries it: a client's JWK, a certificate, or a WebAuthn credential.",
                `description`:"A device key's public material as its kind carries it: a client's JWK, a certificate, or a WebAuthn credential."
              }) `material`?: unknown
            })[];
            `keyKinds`?: (string)[];
            `attestation`?: {
              `level`?: string;
              `format`?: string;
              `summary`?: string;
              `keyId`?: string
            };
            `compliance`?: string;
            `complianceChange`?: NullableObject57;
            `status`?: string;
            `statusChange`?: NullableObject57;
            `riskLevel`?: string;
            `riskChange`?: NullableObject57;
            `platform`?: string;
            `model`?: string;
            `os`?: string;
            `enrolment`?: {
              `method`?: string;
              `at`?: NullOrStringOrNumeric;
              `actor`?: string
            };
            `nativeSso`?: boolean;
            `rememberedBrowser`?: NullableObject58;
            `sessionLive`?: boolean;
            `lastUsed`?: NullOrStringOrNumeric;
            `created`?: NullOrStringOrNumeric
          })[]
        };
        `selfIssued`?: {
          `user`?: string;
          `entryFound`?: boolean;
          `signInEnabled`?: boolean;
          `maxPerPerson`?: numeric;
          `subjectSyntaxTypes`?: (string)[];
          `subjects`?: ({
            `subject`?: string;
            `label`?: string;
            `enrolledAt`?: NullOrStringOrNumeric;
            `by`?: string;
            `proof`?: string;
            `provedAt`?: NullOrStringOrNumeric;
            `keyAlg`?: string;
            `location`?: {`kind`?: string; `value`?: string};
            `preferred`?: boolean;
            `pinnedKeys`?: (string)[]
          })[]
        };
        `publishedDids`?: {
          `user`?: string;
          `entryFound`?: boolean;
          `publishing`?: boolean;
          `custody`?: string;
          `maxPerPerson`?: numeric;
          `dids`?: ({
            `rid`?: string;
            `did`?: string;
            `custody`?: string;
            `documentUrl`?: string;
            `createdAt`?: NullOrStringOrNumeric;
            `by`?: string;
            `state`?: string;
            `deactivated`?: NullOrBooleanOrStringOrAtNullOrStringOrNumeric2ByStringReasonStringViaString;
            `proof`?: string;
            `preferred`?: boolean;
            `currentVersion`?: StringOrNumeric;
            `pending`?: NullableObject59;
            `versions`?: ({
              `versionId`?: StringOrNumeric;
              `created`?: NullOrStringOrNumeric2;
              `change`?: string;
              `keys`?: ({`id`?: string; `kty`?: string; `crv`?: string; `alg`?: string})[];
              `authorizedBy`?: ({
                `kind`?: string;
                `subject`?: string;
                `actor`?: string;
                `at`?: NullOrStringOrNumeric2;
                `keyThumbprint`?: string;
                `versionId`?: StringOrNumeric;
                `transaction`?: string
              })[]
            })[]
          })[]
        };
        `certificates`?: {
          `ok`?: boolean;
          `errors`?: (string)[];
          `user`?: string;
          `dn`?: string;
          `certificates`?: ({
            `sha256`?: string;
            `subject`?: string;
            `issuer`?: string;
            `serialNumber`?: string;
            `notBefore`?: string;
            `notAfter`?: string;
            `expired`?: boolean;
            `readable`?: boolean
          })[];
          `rule`?: string
        };
        `signing`?: {
          `ok`?: boolean;
          `kind`?: string;
          `holder`?: string;
          `implicitName`?: string;
          `certificates`?: ({
            `serialHex`?: string;
            `label`?: string;
            `subject`?: string;
            `keyAlg`?: string;
            `notBefore`?: NullOrStringOrNumeric;
            `notAfter`?: NullOrStringOrNumeric;
            `thumbprint`?: string;
            `state`?: string;
            `reason`?: NullableString;
            `revokedAt`?: NullOrStringOrNumeric;
            `certificatePem`?: string
          })[];
          `active`?: numeric;
          `max`?: numeric;
          `keyAlgorithms`?: (string)[];
          `defaultKeyAlg`?: string;
          `revocationReasons`?: (string)[];
          `passwordMin`?: numeric;
          `caAvailable`?: boolean
        };
        `mail`?: {
          `status`?: {
            `optedIn`?: string;
            `kind`?: string;
            `usable`?: boolean;
            `why`?: string;
            `verified`?: boolean;
            `address`?: string;
            `offered`?: {`code`?: boolean; `link`?: boolean};
            `failures`?: numeric
          };
          `usable`?: boolean;
          `audSubs`?: (string)[]
        }
      };
      `fieldGroups`?: ({
        `id`?: string;
        `label`?: string;
        `what`?: string;
        `attributes`?: (string)[]
      })[];
      `delegation`?: {
        `found`?: boolean;
        `person`?: boolean;
        `username`?: string;
        `dn`?: string;
        `sub`?: string;
        `notDelegated`?: boolean;
        `mayAct`?: string;
        `delegate`?: NullOrStringOrDnStringNameStringKindStringPresentBooleanSubString;
        `semantics`?: (string)[];
        `defaultSemantics`?: string;
        `groups`?: ({`dn`?: string; `cn`?: string})[]
      };
      `keyPairs`?: {
        `storable`?: boolean;
        `found`?: boolean;
        `username`?: string;
        `purposes`?: ({
          `id`?: string;
          `label`?: string;
          `held`?: boolean;
          `keys`?: ({
            `handle`?: string;
            `label`?: string;
            `source`?: string;
            `state`?: string;
            `reason`?: string;
            `revokedAt`?: string;
            `serialHex`?: string;
            `expiresAt`?: string;
            `notAfter`?: string;
            `privateKeyHeld`?: boolean;
            `certificate`?: NullableObject47;
            `chain`?: ({
              `subject`?: string;
              `issuer`?: string;
              `serialHex`?: string;
              `notBefore`?: string;
              `notAfter`?: string;
              `expired`?: boolean;
              `selfSigned`?: boolean;
              `keyType`?: string;
              `thumbprint`?: string;
              `unreadable`?: string
            })[]
          })[];
          `valid`?: numeric;
          `atCap`?: boolean;
          `handleLabel`?: string;
          `issuers`?: (string)[];
          `effectiveIssuers`?: (string)[];
          `attributes`?: {`issuer`?: string; `keys`?: string; `privateKey`?: string}
        })[];
        `ca`?: {
          `available`?: boolean;
          `keyAlg`?: string;
          `leafLifetimeDays`?: numeric;
          `keyAlgorithms`?: ({`id`?: string; `label`?: string; `kind`?: string})[]
        };
        `sealsAtRest`?: boolean;
        `selfService`?: boolean;
        `sources`?: (string)[];
        `maxPerPerson`?: numeric;
        `revocationReasons`?: (string)[]
      };
      `serviceAccountRules`?: {`requiresOwner`?: boolean; `maxOwners`?: numeric; `dn`?: string};
      `serviceProviders`?: ({`fedId`?: string; `fedPeer`?: string})[]
    }
  }

@component model `Saml2ServiceProviderList` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: StringOrString;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `serviceProviders`?: ({
      `name`?: NullableString;
      `authentications`?: numeric;
      `sessions`?: numeric;
      `users`?: numeric;
      `firstSeen`?: string;
      `lastSeen`?: string;
      `assertionConsumerServices`?: (string)[];
      `singleLogoutServices`?: (string)[];
      `nameIdFormats`?: (string)[];
      `responseBindings`?: (string)[];
      `lastRequestSigned`?: boolean;
      `lastRequestVerification`?: string;
      `identifier`?: string;
      `slug`?: NullableString;
      `idpEntityId`?: NullableString;
      `metadataUrl`?: string;
      `ssoUrl`?: string;
      `sloUrl`?: string;
      `arsUrl`?: string
    })[];
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `offset`?: integer;
      `total`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `param`?: NullableString;
      `noun`?: NullableString
    };
    `unscopedMetadata`?: string;
    `settings`?: {
      `page`?: string;
      `groups`?: ({
        `group`?: string;
        `settings`?: ({
          `key`?: string;
          `group`?: string;
          `label`?: string;
          `description`?: string;
          `type`?: string;
          `enumValues`?: (string)[];
          `csvValues`?: (string)[];
          `ordered`?: boolean;
          @js(#{`description`:"The sentence beside each value."}) `csvValueNotes`?: Record<string>;
          @js(#{`description`:"The rules by kind: onlyWhileOn and aloneWhileOn."}) `selectAll`?: Record<({
            `setting`?: string;
            `values`?: (string)[];
            `on`?: boolean;
            `canBeOn`?: boolean
          })[]>;
          `min`?: numeric;
          `max`?: numeric;
          `step`?: numeric;
          `value`?: BooleanOrNumericOrStringEtc;
          `text`?: NullableString;
          `source`?: string;
          `editable`?: boolean;
          `restartReason`?: string;
          `editRefusal`?: string;
          `env`?: NullableString;
          `legacyEnv`?: NullableString;
          `appconfigPath`?: string;
          `default`?: BooleanOrNumericOrStringEtc;
          `masked`?: boolean;
          `realmSettable`?: boolean;
          `overridden`?: boolean
        })[]
      })[];
      `settingCount`?: integer;
      `editableCount`?: integer;
      `overridden`?: (string)[];
      `setWith`?: string;
      `context`?: {
        `configFile`?: NullableString;
        `defaultsFile`?: NullableString;
        `persistsAppconfig`?: boolean;
        `persistsRealms`?: boolean;
        `persistenceMode`?: string;
        `inRealm`?: boolean;
        `realmId`?: NullableString
      };
      @js(#{`description`:"The other pages, by settings group."}) `sharedWith`?: Record<({`path`?: string; `label`?: string})[]>
    };
    `artifactsAwaitingResolution`?: numeric;
    `requestsHeldForSignIn`?: numeric;
    `mdqRefused`?: ({
      `entityId`?: string;
      `why`?: string;
      `firstAt`?: NullableString;
      `lastAt`?: NullableString;
      `count`?: numeric
    })[];
    `mdqRefusedPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `offset`?: integer;
      `total`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `param`?: NullableString;
      `noun`?: NullableString
    };
    `kind`?: string;
    `found`?: boolean;
    `name`?: string;
    `authentications`?: numeric;
    `assertionConsumerServices`?: (string)[];
    `singleLogoutServices`?: (string)[];
    `nameIdFormats`?: (string)[];
    `responseBindings`?: (string)[];
    `lastRequestSigned`?: boolean;
    `lastRequestVerification`?: {
      `outcome`?: string;
      `binding`?: string;
      `signatureMethod`?: string;
      `weak`?: boolean
    };
    `signingCertificate`?: string;
    `signingCertificates`?: (string)[];
    `observedSigningCertificate`?: string;
    `signedRequestsRequired`?: {`required`?: boolean; `why`?: string};
    `metadata`?: {
      `state`?: string;
      `stateWhy`?: string;
      `expiresAt`?: string;
      `staleAt`?: string;
      `refreshable`?: boolean;
      `refresh`?: NullableObject60;
      `refresherEnabled`?: boolean;
      `refresherRunning`?: boolean;
      `trustAnchors`?: numeric;
      `trustAnchorProblems`?: (string)[];
      `mdqUrl`?: string;
      `consumed`?: boolean;
      `consumedAt`?: string;
      `how`?: string;
      `url`?: string;
      `signature`?: string;
      `signingCertificateConfigured`?: boolean;
      `validUntil`?: string;
      `expired`?: boolean;
      `cacheDuration`?: string;
      `authnRequestsSigned`?: boolean;
      `wantAssertionsSigned`?: boolean;
      `wantAssertionsEncrypted`?: boolean;
      `nameIdFormats`?: (string)[];
      `assertionConsumerServices`?: ({
        `index`?: string;
        `isDefault`?: NullableBoolean;
        `binding`?: string;
        `location`?: string
      })[];
      `singleLogoutServices`?: ({`binding`?: string; `location`?: string; `responseLocation`?: string})[];
      `encryptionCertificate`?: boolean
    };
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
    `filter`?: {
      `q`?: NullableString;
      `role`?: NullableString;
      `category`?: NullableString
    };
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `container`?: NullableString;
    `max`?: numeric;
    `settings`?: NullableObject61;
    `roles`?: ({`role`?: string; `label`?: string; `short`?: string; `what`?: string})[];
    `protocols`?: ({
      `protocol`?: string;
      `label`?: string;
      `family`?: string;
      `what`?: string;
      `needs`?: (string)[];
      `spec`?: string;
      `signalsOnly`?: boolean
    })[];
    `paths`?: {
      `base`?: string;
      `login`?: string;
      `acs`?: string;
      `metadata`?: string;
      `link`?: string;
      `notifications`?: string;
      `stepup`?: string;
      `profile`?: string;
      `slo`?: string;
      `backchannelLogout`?: string;
      `frontchannelLogout`?: string;
      `jwks`?: string;
      `atprotoClient`?: string;
      `initiateLogin`?: string;
      `fragmentScript`?: string;
      `requestObject`?: string;
      `webfinger`?: string;
      `signals`?: string
    };
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `roleCounts`?: Record<numeric>;
    `categoryCounts`?: Record<numeric>;
    `consumerProviders`?: {
      `on`?: boolean;
      `catalogue`?: ({
        `id`?: string;
        `label`?: string;
        `protocol`?: string;
        `generic`?: boolean;
        `docs`?: string;
        `note`?: string;
        `defaults`?: Record<string>;
        `needs`?: (string)[];
        `adapters`?: (string)[];
        `subject`?: string;
        `emailVerified`?: string;
        `claims`?: (string)[]
      })[]
    };
    `enabledNotConfigured`?: integer;
    `authentications`?: integer;
    `relationships`?: ({
      `id`?: string;
      `name`?: string;
      `role`?: string;
      `roleLabel`?: string;
      `protocol`?: string;
      `protocolLabel`?: string;
      `peer`?: string;
      `application`?: string;
      `category`?: string;
      `provider`?: string;
      `providerLabel`?: string;
      `enabled`?: boolean;
      `ready`?: boolean;
      `missing`?: (string)[];
      `usable`?: boolean;
      `signsIn`?: boolean;
      `signalsEnabled`?: boolean;
      `releases`?: (string)[];
      `mappings`?: (string)[];
      `authentications`?: integer;
      `users`?: integer;
      `lastUser`?: string;
      `lastSeen`?: string;
      `lastError`?: string;
      `lastErrorAt`?: string;
      `dn`?: string
    })[];
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
    `endpoints`?: {
      `assertionConsumerService`?: string;
      `login`?: string;
      `metadata`?: NullableString;
      `jwks`?: NullableString;
      `initiateLogin`?: NullableString;
      `singleLogout`?: string;
      `signOutCleanup`?: string;
      `backchannelLogout`?: string;
      `frontchannelLogout`?: string;
      `postLogoutRedirect`?: string
    };
    `fields`?: {
      `fedId`?: string;
      `cn`?: string;
      `fedName`?: string;
      `fedRole`?: string;
      `fedProtocol`?: string;
      `fedProvider`?: string;
      `fedPeer`?: string;
      `fedLocalEntityId`?: string;
      `fedEnabled`?: string;
      `fedSsoUrl`?: string;
      `fedTokenUrl`?: string;
      `fedUserinfoUrl`?: string;
      `fedJwksUri`?: string;
      `fedEmailsUrl`?: string;
      `fedJwks`?: string;
      `fedTrustAnchor`?: string;
      `fedSigningCertificate`?: string;
      `fedClientId`?: string;
      `fedClientSecret`?: string;
      `fedResponseMode`?: string;
      `fedTeamId`?: string;
      `fedKeyId`?: string;
      `fedClientSigningKey`?: string;
      `fedTokenAuth`?: string;
      `fedScope`?: string;
      `fedResponseType`?: string;
      `fedIdTokenSignedResponseAlg`?: string;
      `fedUserinfoSignedResponseAlg`?: string;
      `fedRefreshTokens`?: string;
      `fedRefreshEverySeconds`?: string;
      `fedRegister`?: string;
      `fedRegisteredIssuer`?: string;
      `fedRequestObject`?: string;
      `fedRequestObjectSigningAlg`?: string;
      `fedWebFinger`?: string;
      `fedDiscovery`?: string;
      `fedInitiateLogin`?: string;
      `fedBinding`?: string;
      `fedSignRequest`?: string;
      `fedUsernameSource`?: string;
      `fedSubjectClaim`?: string;
      `fedAutocreateUsers`?: string;
      `fedUpdateUserAttributes`?: string;
      `fedProvisionGroups`?: string;
      `fedProvisionCap`?: string;
      `fedProvisionIdleMinutes`?: string;
      `fedSubjectPolicy`?: string;
      `fedSubjectPattern`?: string;
      `fedMayAssertAdministrators`?: string;
      `fedSignalEmailMatch`?: string;
      `fedSignalsEnabled`?: string;
      `fedSignalsIssuer`?: string;
      `fedSignalsDelivery`?: string;
      `fedSignalsTokenUrl`?: string;
      `fedSignalsClientId`?: string;
      `fedSignalsClientSecret`?: string;
      `fedSignalsScope`?: string;
      `fedSignalsBearer`?: string;
      `fedSloUrl`?: string;
      `fedSloBinding`?: string;
      `fedEndSessionUrl`?: string;
      `fedAcceptSignout`?: string;
      `fedRequireSignedLogout`?: string;
      `fedEncryptionKeyType`?: string;
      `fedKeyManagementAlgorithm`?: string;
      `fedContentEncryptionAlgorithm`?: string;
      `fedAllowUnencrypted`?: string;
      `fedAllowUnsolicited`?: string;
      `fedApplication`?: string;
      `fedAuthnMechanism`?: string;
      `fedAuthnRelationship`?: string;
      `fedFirstSeen`?: string;
      `fedLastSeen`?: string;
      `fedAuthentications`?: string;
      `fedUsers`?: string;
      `fedLastUser`?: string;
      `fedLastError`?: string;
      `fedLastErrorAt`?: string;
      `description`?: (string)[];
      `fedAllowedTenants`?: (string)[];
      `fedAuthorizeParams`?: (string)[];
      `fedAttributeMap`?: (string)[];
      `fedSubjectGroup`?: (string)[];
      `fedSubjectDomain`?: (string)[];
      `fedHomeRealmDomain`?: (string)[];
      `fedSignalsEvents`?: (string)[];
      `fedEncryptionKey`?: string;
      `fedRelease`?: (string)[];
      `fedApplicationUse`?: (string)[]
    };
    `editable`?: ({
      `name`?: string;
      `kind`?: string;
      `role`?: string;
      `from`?: string;
      `what`?: string;
      `standard`?: boolean;
      `sensitive`?: boolean;
      `enum`?: (string)[];
      `editable`?: BooleanOrString
    })[];
    `unmappedAttributes`?: ({`name`?: string; `refused`?: string; `first`?: string; `last`?: string})[];
    `signals`?: NullableObject62;
    `signalArrivals`?: ({
      `relationship`?: string;
      `jti`?: string;
      `via`?: string;
      `receivedAt`?: string;
      `verified`?: boolean;
      `refusal`?: string;
      `why`?: string;
      `events`?: (string)[];
      @js(#{
        `x-free-form`:"An RFC 9493 subject identifier as a partner's SET carried it, in whatever format that partner chose.",
        `description`:"An RFC 9493 subject identifier as a partner's SET carried it, in whatever format that partner chose."
      }) `subject`?: unknown;
      `person`?: string;
      `mapping`?: string;
      `reactions`?: ({
        `event`?: string;
        `reaction`?: string;
        `done`?: boolean;
        `skipped`?: string;
        `observed`?: boolean;
        `why`?: string;
        `ended`?: integer;
        `revoked`?: integer;
        `gnapGrants`?: integer;
        `oauthGrants`?: integer;
        `tokens`?: integer;
        `codes`?: integer;
        `status`?: string
      })[];
      `iat`?: numeric
    })[];
    `outboundSignals`?: NullableObject63;
    `encryption`?: NullableObject64;
    `links`?: ({
      `username`?: string;
      `dn`?: string;
      `link`?: string;
      `issuer`?: string;
      `subject`?: string
    })[];
    `linksPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `setFields`?: ({
      `name`?: string;
      `kind`?: string;
      `role`?: string;
      `from`?: string;
      `what`?: string;
      `standard`?: boolean;
      `sensitive`?: boolean;
      `enum`?: (string)[];
      `editable`?: BooleanOrString
    })[];
    `multiFields`?: ({
      `name`?: string;
      `kind`?: string;
      `role`?: string;
      `from`?: string;
      `what`?: string;
      `standard`?: boolean;
      `sensitive`?: boolean;
      `enum`?: (string)[];
      `editable`?: BooleanOrString
    })[];
    `signalSetFields`?: ({
      `name`?: string;
      `kind`?: string;
      `role`?: string;
      `from`?: string;
      `what`?: string;
      `standard`?: boolean;
      `sensitive`?: boolean;
      `enum`?: (string)[];
      `editable`?: BooleanOrString
    })[];
    `schema`?: ({
      `name`?: string;
      `kind`?: string;
      `role`?: string;
      `from`?: string;
      `what`?: string;
      `standard`?: boolean;
      `sensitive`?: boolean;
      `enum`?: (string)[];
      `editable`?: BooleanOrString
    })[];
    `enumLabels`?: Record<string>;
    `defaultSubjectPolicy`?: string;
    `autocreateDefault`?: boolean;
    `subjectPolicy`?: string;
    `encrypts`?: boolean;
    `base`?: string;
    `loginHref`?: string;
    `metadataUrl`?: string;
    `signOut`?: {
      `singleLogout`?: string;
      `signOutCleanup`?: string;
      `backchannelLogout`?: string;
      `frontchannelLogout`?: string;
      `postLogoutRedirect`?: string
    };
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: StringOrString;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean;
      `listening`?: boolean
    })[]
  }

@component model `Saml11RelyingPartyList` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: StringOrString;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `relyingParties`?: ({
      `name`?: NullableString;
      `authentications`?: numeric;
      `sessions`?: numeric;
      `users`?: numeric;
      `firstSeen`?: string;
      `lastSeen`?: string;
      `assertionConsumerServices`?: (string)[];
      `nameIdFormats`?: (string)[];
      `profiles`?: (string)[];
      `identifier`?: string;
      `slug`?: NullableString;
      `idpProviderId`?: NullableString;
      `metadataUrl`?: string;
      `ssoUrl`?: string;
      `responderUrl`?: string
    })[];
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `offset`?: integer;
      `total`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `param`?: NullableString;
      `noun`?: NullableString
    };
    `unscopedMetadata`?: string;
    `settings`?: {
      `page`?: string;
      `groups`?: ({
        `group`?: string;
        `settings`?: ({
          `key`?: string;
          `group`?: string;
          `label`?: string;
          `description`?: string;
          `type`?: string;
          `enumValues`?: (string)[];
          `csvValues`?: (string)[];
          `ordered`?: boolean;
          @js(#{`description`:"The sentence beside each value."}) `csvValueNotes`?: Record<string>;
          @js(#{`description`:"The rules by kind: onlyWhileOn and aloneWhileOn."}) `selectAll`?: Record<({
            `setting`?: string;
            `values`?: (string)[];
            `on`?: boolean;
            `canBeOn`?: boolean
          })[]>;
          `min`?: numeric;
          `max`?: numeric;
          `step`?: numeric;
          `value`?: BooleanOrNumericOrStringEtc;
          `text`?: NullableString;
          `source`?: string;
          `editable`?: boolean;
          `restartReason`?: string;
          `editRefusal`?: string;
          `env`?: NullableString;
          `legacyEnv`?: NullableString;
          `appconfigPath`?: string;
          `default`?: BooleanOrNumericOrStringEtc;
          `masked`?: boolean;
          `realmSettable`?: boolean;
          `overridden`?: boolean
        })[]
      })[];
      `settingCount`?: integer;
      `editableCount`?: integer;
      `overridden`?: (string)[];
      `setWith`?: string;
      `context`?: {
        `configFile`?: NullableString;
        `defaultsFile`?: NullableString;
        `persistsAppconfig`?: boolean;
        `persistsRealms`?: boolean;
        `persistenceMode`?: string;
        `inRealm`?: boolean;
        `realmId`?: NullableString
      };
      @js(#{`description`:"The other pages, by settings group."}) `sharedWith`?: Record<({`path`?: string; `label`?: string})[]>
    };
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
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: StringOrString;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `idpInitiated`?: ({
      `identifier`?: string;
      `name`?: string;
      `entityId`?: string;
      `protocol`?: string;
      `label`?: string;
      `attribute`?: string;
      `launchUrl`?: string;
      `endpoint`?: NullableString;
      `missing`?: (string)[]
    })[];
    `idpInitiatedPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: NullableString;
      `noun`?: NullableString
    };
    `realmSwitches`?: ({
      `protocol`?: string;
      `label`?: string;
      `setting`?: string;
      `attribute`?: string;
      `enabled`?: boolean
    })[]
  }

@component model `AuthorizationServerList` {
    `profileCount`?: integer;
    `shown`?: integer;
    `members`?: ({
      `name`?: string;
      `group`?: string;
      `kind`?: string;
      `what`?: string;
      `enforces`?: string;
      `document`?: string
    })[];
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `overrideTotal`?: integer;
    `driftTotal`?: integer;
    `authorizationServers`?: ({
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
      `urls`?: {
        `oauth`?: string;
        `oidc`?: string;
        `authorize`?: string;
        `token`?: string
      };
      `drift`?: ({
        `member`?: string;
        @js(#{
          `x-free-form`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines.",
          `description`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines."
        }) `published`?: unknown;
        @js(#{
          `x-free-form`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines.",
          `description`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines."
        }) `actual`?: unknown;
        `kind`?: string;
        `what`?: string
      })[]
    })[];
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
    `urls`?: {
      `oauth`?: string;
      `oidc`?: string;
      `authorize`?: string;
      `token`?: string
    };
    `found`?: boolean;
    `drift`?: ({
      `member`?: string;
      @js(#{
        `x-free-form`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines.",
        `description`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines."
      }) `published`?: unknown;
      @js(#{
        `x-free-form`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines.",
        `description`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines."
      }) `actual`?: unknown;
      `kind`?: string;
      `what`?: string
    })[];
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
      `config`?: {
        `fields`?: ({
          `attribute`?: string;
          `type`?: string;
          `long`?: boolean;
          `editable`?: StringOrBoolean;
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
          `described`?: {
            `key`?: string;
            `group`?: string;
            `label`?: string;
            `description`?: string;
            `type`?: string;
            `enumValues`?: (string)[];
            `csvValues`?: (string)[];
            `ordered`?: boolean;
            @js(#{`description`:"The sentence beside each of a list's values."}) `csvValueNotes`?: Record<string>;
            `selectAll`?: {
              `onlyWhileOn`?: ({
                `setting`?: string;
                `values`?: (string)[];
                `on`?: boolean;
                `canBeOn`?: boolean
              })[];
              `aloneWhileOn`?: ({
                `setting`?: string;
                `values`?: (string)[];
                `on`?: boolean;
                `canBeOn`?: boolean
              })[]
            };
            `min`?: numeric;
            `max`?: numeric;
            `step`?: numeric;
            `value`?: StringOrNumericOrBooleanEtc2;
            `text`?: string;
            `source`?: string;
            `editable`?: boolean;
            `restartReason`?: string;
            `editRefusal`?: string;
            `env`?: NullableString;
            `legacyEnv`?: NullableString;
            `appconfigPath`?: string;
            `default`?: StringOrNumericOrBooleanEtc2;
            `masked`?: boolean;
            `realmSettable`?: boolean;
            `overridden`?: boolean
          };
          `inSimple`?: boolean
        })[];
        @js(#{`description`:"Each field's values, by attribute."}) `values`?: Record<(string)[]>;
        `groups`?: ({`id`?: string; `label`?: string; `families`?: (string)[]})[];
        `familyChoices`?: ({
          `id`?: string;
          `label`?: string;
          `families`?: (string)[];
          `kind`?: string;
          `what`?: string
        })[];
        `protocols`?: ({
          `id`?: string;
          `label`?: string;
          `kind`?: string;
          `kinds`?: (string)[];
          `identifierAttribute`?: string;
          `redirectAttribute`?: string;
          `logoutAttribute`?: string;
          `deliveryAttribute`?: string;
          `eventsAttribute`?: string;
          `secretAttribute`?: string;
          `what`?: string
        })[];
        `longTextAttributes`?: (string)[];
        @js(#{`description`:"What each attribute's search looks through."}) `fieldSearches`?: Record<string>;
        `observed`?: {
          `oauthGrantTypeObserved`?: ({`value`?: string; `declared`?: boolean})[];
          `oauthResponseTypeObserved`?: ({`value`?: string; `declared`?: boolean})[];
          `appRedirectUriObserved`?: ({`value`?: string; `declared`?: boolean})[];
          `oauthScope`?: ({`value`?: string; `declared`?: boolean})[];
          `appAuthorizationServer`?: ({`value`?: string; `declared`?: boolean})[];
          `samlNameIdFormat`?: ({`value`?: string; `declared`?: boolean})[];
          `samlResponseBinding`?: ({`value`?: string; `declared`?: boolean})[];
          `samlLastRequest`?: NullableObject66;
          `samlObservedSigningCertificate`?: NullableObject67;
          `oauthAllowedTokenResponseTypes`?: {`enabled`?: (string)[]; `enforced`?: boolean; `waived`?: boolean}
        };
        `derived`?: {
          `oauthAllowedScope`?: ({
            `value`?: string;
            `permission`?: string;
            `api`?: string;
            `apiName`?: string
          })[]
        };
        @js(#{`description`:"By attribute."}) `fieldWarnings`?: Record<({
          `attribute`?: string;
          `value`?: string;
          `reason`?: string;
          `dropped`?: boolean;
          `text`?: string
        })[]>
      };
      `passkeyPolicies`?: {
        `named`?: string;
        `missing`?: boolean;
        `applies`?: string;
        `precedence`?: numeric;
        `groupPolicies`?: integer;
        `link`?: string
      };
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
      `cors`?: ({`stored`?: string; `canonical`?: string})[];
      `accessTypes`?: ({
        `stored`?: string;
        `type`?: string;
        `description`?: string;
        `locations`?: (string)[];
        @js(#{
          `x-free-form`:"The JSON an operator wrote into an access type's definition: a JSON Schema (RFC 9396 leaves a type's fields to its definition), or the definition.",
          `description`:"The JSON an operator wrote into an access type's definition: a JSON Schema (RFC 9396 leaves a type's fields to its definition), or the definition."
        }) `schema`?: unknown;
        `validate`?: null;
        `problem`?: string;
        `actions`?: NullableArray;
        `datatypes`?: NullableArray;
        `privileges`?: NullableArray;
        `required`?: (string)[];
        `interaction`?: string;
        `consentActions`?: (string)[];
        `bearer`?: StringOrNumericOrBooleanEtc4;
        `maxLifetimeS`?: NullableNumber;
        `acr`?: string;
        `derivableFrom`?: (string)[];
        `introspectionClaims`?: (string)[];
        @js(#{
          `x-free-form`:"The JSON an operator wrote into an access type's definition: a JSON Schema (RFC 9396 leaves a type's fields to its definition), or the definition.",
          `description`:"The JSON an operator wrote into an access type's definition: a JSON Schema (RFC 9396 leaves a type's fields to its definition), or the definition."
        }) `limits`?: unknown;
        `validateLimits`?: null;
        `xacml`?: ({
          `path`?: string;
          `attributeId`?: string;
          `category`?: string;
          `dataType`?: string;
          `multiplicity`?: string;
          `description`?: string
        })[];
        `notForPolicy`?: (string)[];
        @js(#{
          `x-free-form`:"The JSON an operator wrote into an access type's definition: a JSON Schema (RFC 9396 leaves a type's fields to its definition), or the definition.",
          `description`:"The JSON an operator wrote into an access type's definition: a JSON Schema (RFC 9396 leaves a type's fields to its definition), or the definition."
        }) `source`?: unknown
      })[];
      `fga`?: NullableObject68;
      `permissionClaims`?: {
        `permissions`?: ({
          `name`?: string;
          `description`?: NullableString;
          `id`?: NullableString;
          `attributes`?: (string)[]
        })[];
        `stale`?: (string)[];
        `catalogue`?: ({`ldap`?: string; `claim`?: string; `label`?: string})[]
      };
      `grantsUncataloguedAccess`?: boolean;
      `acceptsUnregisteredAddresses`?: boolean;
      `protocolRows`?: ({`id`?: string; `label`?: string; `kinds`?: (string)[]; `kind`?: string})[];
      `editable`?: {
        `set`?: ({`name`?: string; `sensitive`?: boolean})[];
        `multi`?: ({`name`?: string; `sensitive`?: boolean})[];
        `multiAll`?: ({`name`?: string; `sensitive`?: boolean})[]
      };
      `did`?: {
        `did`?: NullableString;
        `url`?: string;
        `ok`?: boolean;
        `why`?: string;
        `methods`?: ({
          `kid`?: string;
          `kty`?: string;
          `crv`?: string;
          `alg`?: string;
          `kept`?: boolean
        })[];
        `origins`?: (string)[]
      };
      `credentials`?: {
        `oauthDeclared`?: boolean;
        `clientSecret`?: {
          `held`?: boolean;
          `authMethod`?: string;
          `registered`?: boolean;
          `registrationAccessTokenHeld`?: boolean;
          `expiresAt`?: numeric;
          `secrets`?: ({
            `id`?: string;
            `createdAt`?: numeric;
            `expiresAt`?: numeric;
            `description`?: NullableString;
            `expired`?: boolean;
            `primary`?: boolean
          })[];
          `max`?: numeric;
          `defaultLifetimeDays`?: numeric;
          `overlapS`?: numeric
        };
        `purposes`?: ({
          `label`?: string;
          `held`?: boolean;
          `source`?: string;
          `privateKeyHeld`?: boolean;
          `certificate`?: NullableObject69;
          `chain`?: ({
            `subject`?: string;
            `issuer`?: string;
            `serialHex`?: string;
            `notBefore`?: string;
            `notAfter`?: string;
            `expired`?: boolean;
            `selfSigned`?: boolean;
            `keyType`?: NullableString;
            `thumbprint`?: string;
            `unreadable`?: string
          })[];
          `handle`?: string;
          `handleLabel`?: string;
          `issuers`?: (string)[];
          `attributes`?: {
            `issuer`?: string;
            `certificate`?: string;
            `chain`?: string;
            `privateKey`?: string;
            `handle`?: string;
            `handleLabel`?: string;
            `expires`?: string;
            `source`?: string;
            `jwks`?: string;
            `registered`?: string
          };
          `registered`?: {
            `attribute`?: string;
            `problem`?: string;
            `keys`?: ({
              `kid`?: string;
              `kty`?: string;
              `alg`?: string;
              `use`?: string;
              `certificate`?: NullableObject69
            })[];
            `certificates`?: ({
              `subject`?: string;
              `issuer`?: string;
              `serialHex`?: string;
              `notBefore`?: string;
              `notAfter`?: string;
              `expired`?: boolean;
              `selfSigned`?: boolean;
              `keyType`?: NullableString;
              `thumbprint`?: string;
              `unreadable`?: string
            })[]
          };
          `id`?: string;
          `sealedAtRest`?: boolean;
          `certificatePem`?: string
        })[];
        `ca`?: {
          `available`?: boolean;
          `keyAlg`?: string;
          `keyAlgorithms`?: ({`id`?: string; `label`?: string; `kind`?: string})[];
          `leafLifetimeDays`?: numeric
        };
        `sources`?: (string)[];
        `mtls`?: {
          `certificates`?: ({
            `serialHex`?: string;
            `label`?: NullableString;
            `subject`?: NullableString;
            `keyAlg`?: NullableString;
            `notBefore`?: StringOrNumericOrNull;
            `notAfter`?: StringOrNumericOrNull;
            `thumbprint`?: NullableString;
            `state`?: string;
            `reason`?: NullableString;
            `revokedAt`?: StringOrNumericOrNull;
            `certificatePem`?: NullableString
          })[];
          `active`?: integer;
          `max`?: numeric;
          `keyAlgorithms`?: (string)[];
          `defaultKeyAlg`?: string;
          `revocationReasons`?: (string)[];
          `passwordMin`?: numeric;
          `implicitName`?: string;
          `caAvailable`?: boolean;
          `authMethod`?: string;
          `certificateMethod`?: boolean;
          `subjects`?: ({
            `member`?: string;
            `attribute`?: string;
            `label`?: string;
            `value`?: string
          })[];
          `registeredSubject`?: (string)[];
          `boundTokensAttribute`?: string;
          `boundTokens`?: boolean;
          `adminApiBound`?: boolean;
          `selfSignedThumbprint`?: string;
          `bindingAvailable`?: boolean
        };
        `signing`?: {
          `certificates`?: ({
            `serialHex`?: string;
            `label`?: NullableString;
            `subject`?: NullableString;
            `keyAlg`?: NullableString;
            `notBefore`?: StringOrNumericOrNull;
            `notAfter`?: StringOrNumericOrNull;
            `thumbprint`?: NullableString;
            `state`?: string;
            `reason`?: NullableString;
            `revokedAt`?: StringOrNumericOrNull;
            `certificatePem`?: NullableString
          })[];
          `active`?: integer;
          `max`?: numeric;
          `keyAlgorithms`?: (string)[];
          `defaultKeyAlg`?: string;
          `revocationReasons`?: (string)[];
          `passwordMin`?: numeric;
          `implicitName`?: string;
          `caAvailable`?: boolean;
          `ok`?: boolean;
          `kind`?: string;
          `holder`?: string;
          `wstrustDeclared`?: boolean
        };
        `stored`?: {
          `ok`?: boolean;
          `errors`?: (string)[];
          `application`?: string;
          `dn`?: NullableString;
          `certificates`?: ({
            `sha256`?: string;
            `subject`?: string;
            `issuer`?: string;
            `serialNumber`?: string;
            `notBefore`?: string;
            `notAfter`?: string;
            `expired`?: boolean;
            `readable`?: boolean
          })[];
          `rule`?: string
        }
      };
      `signals`?: {
        `installed`?: boolean;
        `streams`?: ({
          `stream_id`?: string;
          `status`?: string;
          `statusReason`?: NullableString;
          `aud`?: StringOrNumericOrBooleanEtc4;
          `delivery`?: {
            `method`?: string;
            `endpoint_url`?: NullableString
          };
          `events_requested`?: (string)[];
          `events_delivered`?: (string)[];
          `format`?: string;
          `description`?: string;
          `createdBy`?: string;
          `createdAt`?: StringOrNumeric;
          `updatedAt`?: StringOrNumeric;
          `lastPushAt`?: StringOrNumeric;
          `lastPushError`?: string
        })[];
        `settings`?: ({
          `setting`?: string;
          `attribute`?: string;
          `value`?: StringOrNumericOrBooleanEtc2;
          `source`?: string
        })[];
        `json`?: {
          `installed`?: boolean;
          `streams`?: ({
            `stream_id`?: string;
            `status`?: string;
            `statusReason`?: NullableString;
            `aud`?: StringOrNumericOrBooleanEtc4;
            `delivery`?: {
              `method`?: string;
              `endpoint_url`?: NullableString
            };
            `events_requested`?: (string)[];
            `events_delivered`?: (string)[];
            `format`?: string;
            `description`?: string;
            `createdBy`?: string;
            `createdAt`?: StringOrNumeric;
            `updatedAt`?: StringOrNumeric;
            `lastPushAt`?: StringOrNumeric;
            `lastPushError`?: string
          })[];
          `settings`?: ({
            `setting`?: string;
            `attribute`?: string;
            `value`?: StringOrNumericOrBooleanEtc2;
            `source`?: string
          })[]
        }
      };
      `softwareStatement`?: {
        `issuers`?: (string)[];
        `usableKeys`?: integer;
        `keyProblems`?: (StringOrNumericOrBooleanEtc4)[];
        `issuedToken`?: string;
        `issued`?: NullableObject70;
        `registeredWith`?: NullableObject71;
        `settings`?: {
          `requireTrustedIssuer`?: boolean;
          `opensRegistration`?: boolean;
          `required`?: boolean;
          `lifetimeSeconds`?: numeric
        };
        `json`?: {
          `declaredIssuers`?: (string)[];
          `usableKeys`?: integer;
          `issued`?: NullableObject72;
          `registeredWith`?: NullableObject71;
          `settings`?: {
            `requireTrustedIssuer`?: boolean;
            `opensRegistration`?: boolean;
            `required`?: boolean;
            `lifetimeSeconds`?: numeric
          }
        }
      };
      `roles`?: {
        `held`?: ({
          `name`?: string;
          `id`?: string;
          `displayName`?: string;
          `application`?: string;
          `carriedAs`?: string;
          `permissions`?: (string)[]
        })[];
        `offerable`?: (string)[];
        `required`?: ({
          `name`?: string;
          `resolves`?: string;
          `displayName`?: string;
          `role`?: string
        })[];
        `requirable`?: (string)[]
      };
      `permissions`?: {
        `held`?: ({
          `client`?: string;
          `clientName`?: string;
          `permissionId`?: string;
          `resource`?: string;
          `resourceName`?: string;
          `baseUri`?: NullableString;
          `permissionName`?: string;
          `description`?: NullableString;
          `dangling`?: boolean;
          `asked`?: boolean
        })[];
        `exposes`?: ({
          `resource`?: string;
          `resourceName`?: string;
          `baseUri`?: NullableString;
          `name`?: string;
          `description`?: NullableString;
          `id`?: NullableString;
          `raw`?: NullableString;
          `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
        })[];
        `offerable`?: ({
          `resource`?: string;
          `resourceName`?: string;
          `baseUri`?: NullableString;
          `name`?: string;
          `description`?: NullableString;
          `id`?: NullableString;
          `raw`?: NullableString;
          `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
        })[];
        `clients`?: ({`identifier`?: string; `name`?: string})[];
        `heldPage`?: {
          `paging`?: {
            `page`?: integer;
            `perPage`?: integer;
            `pages`?: integer;
            `offset`?: integer;
            `total`?: integer;
            `firstRow`?: integer;
            `lastRow`?: integer;
            `param`?: string;
            `noun`?: string
          };
          `shown`?: ({
            `client`?: string;
            `clientName`?: string;
            `permissionId`?: string;
            `resource`?: string;
            `resourceName`?: string;
            `baseUri`?: NullableString;
            `permissionName`?: string;
            `description`?: NullableString;
            `dangling`?: boolean;
            `asked`?: boolean
          })[]
        };
        `exposedPage`?: {
          `paging`?: {
            `page`?: integer;
            `perPage`?: integer;
            `pages`?: integer;
            `offset`?: integer;
            `total`?: integer;
            `firstRow`?: integer;
            `lastRow`?: integer;
            `param`?: string;
            `noun`?: string
          };
          `shown`?: ({
            `resource`?: string;
            `resourceName`?: string;
            `baseUri`?: NullableString;
            `name`?: string;
            `description`?: NullableString;
            `id`?: NullableString;
            `raw`?: NullableString;
            `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
          })[]
        };
        `grantedOutPage`?: {
          `paging`?: {
            `page`?: integer;
            `perPage`?: integer;
            `pages`?: integer;
            `offset`?: integer;
            `total`?: integer;
            `firstRow`?: integer;
            `lastRow`?: integer;
            `param`?: string;
            `noun`?: string
          };
          `shown`?: ({
            `client`?: string;
            `clientName`?: string;
            `permissionId`?: string;
            `resource`?: string;
            `resourceName`?: string;
            `baseUri`?: NullableString;
            `permissionName`?: string;
            `description`?: NullableString;
            `dangling`?: boolean;
            `asked`?: boolean
          })[]
        };
        `registerPermissions`?: integer
      };
      `lifetimes`?: {
        `rows`?: ({
          `setting`?: string;
          `attribute`?: string;
          `label`?: string;
          `value`?: numeric;
          `realmValue`?: numeric;
          `source`?: string
        })[];
        `skew`?: numeric
      };
      `claims`?: ({
        `id`?: string;
        `label`?: string;
        `attribute`?: string;
        `realm`?: ({
          `name`?: string;
          `value`?: StringOrNumericOrBooleanEtc4;
          `nameFormat`?: string;
          `namespace`?: string;
          `attribute`?: string;
          `multi`?: boolean;
          `type`?: string
        })[];
        `own`?: ({
          `name`?: string;
          `value`?: StringOrNumericOrBooleanEtc4;
          `nameFormat`?: string;
          `namespace`?: string;
          `attribute`?: string;
          `multi`?: boolean;
          `type`?: string
        })[];
        `effective`?: ({
          `name`?: string;
          `value`?: StringOrNumericOrBooleanEtc4;
          `nameFormat`?: string;
          `namespace`?: string;
          `attribute`?: string;
          `multi`?: boolean;
          `type`?: string;
          `source`?: string;
          `replacesRealm`?: boolean
        })[]
      })[];
      `claimSelections`?: {
        `catalogue`?: ({
          `ldap`?: string;
          `claim`?: string;
          `label`?: string;
          `schema`?: string;
          `ldpTerm`?: string;
          `generated`?: boolean
        })[];
        `preview`?: {
          `user`?: string;
          @js(#{`description`:"By lower-cased attribute name."}) `byLdap`?: Record<{
            `ldap`?: string;
            `claim`?: string;
            `value`?: StringOrNumericOrBooleanEtc4;
            `source`?: string;
            `ldpTerm`?: NullableString
          }>;
          `entryFound`?: boolean
        };
        `sets`?: ({
          `id`?: string;
          `label`?: string;
          `attribute`?: string;
          `realm`?: (string)[];
          `own`?: NullableArray;
          `inherited`?: boolean;
          `effective`?: (string)[];
          @js(#{`description`:"The claims, by name."}) `claims`?: Record<StringOrNumericOrBooleanEtc4OrListOfRecordStringOrNumericOrBooleanEtc4>;
          `report`?: ({
            `ldap`?: string;
            `claim`?: string;
            `value`?: StringOrNumericOrBooleanEtc4;
            `source`?: string;
            `ldpTerm`?: NullableString
          })[]
        })[];
        `credential`?: NullableObject73
      };
      `enrollment`?: {
        `credentials`?: {
          `families`?: (string)[];
          `rules`?: ({
            `family`?: string;
            `label`?: string;
            `allowedProfiles`?: (string)[];
            `allowedProfilesSource`?: string;
            `defaultProfile`?: NullableString;
            `defaultProfileSource`?: string;
            `certificateLifetimeDays`?: numeric;
            `certificateLifetimeSource`?: string
          })[];
          `cap`?: {`value`?: numeric; `source`?: string};
          `est`?: NullableObject74;
          `certificates`?: ({
            `serialHex`?: string;
            `family`?: string;
            `profile`?: string;
            `subject`?: string;
            `names`?: (string)[];
            `thumbprint`?: string;
            `keyAlg`?: string;
            `notBefore`?: StringOrNumeric;
            `notAfter`?: StringOrNumeric;
            `issuedAt`?: string;
            `requestedBy`?: NullableObject12;
            `via`?: string;
            `keySource`?: string;
            `replaces`?: NullableString;
            `certificatePem`?: string;
            `chainPem`?: (string)[];
            `device`?: string;
            `attestation`?: StringOrNumericOrBooleanEtc4;
            `revoked`?: {
              `at`?: StringOrNumeric;
              `reason`?: string;
              `by`?: string
            };
            `expired`?: boolean;
            `status`?: string
          })[];
          `paged`?: {
            `paging`?: {
              `page`?: integer;
              `perPage`?: integer;
              `pages`?: integer;
              `offset`?: integer;
              `total`?: integer;
              `firstRow`?: integer;
              `lastRow`?: integer;
              `param`?: string;
              `noun`?: string
            };
            `shown`?: ({
              `serialHex`?: string;
              `family`?: string;
              `profile`?: string;
              `subject`?: string;
              `names`?: (string)[];
              `thumbprint`?: string;
              `keyAlg`?: string;
              `notBefore`?: StringOrNumeric;
              `notAfter`?: StringOrNumeric;
              `issuedAt`?: string;
              `requestedBy`?: NullableObject12;
              `via`?: string;
              `keySource`?: string;
              `replaces`?: NullableString;
              `certificatePem`?: string;
              `chainPem`?: (string)[];
              `device`?: string;
              `attestation`?: StringOrNumericOrBooleanEtc4;
              `revoked`?: {
                `at`?: StringOrNumeric;
                `reason`?: string;
                `by`?: string
              };
              `expired`?: boolean;
              `status`?: string
            })[]
          };
          `eabKeys`?: ({
            `kid`?: string;
            `createdAt`?: StringOrNumeric;
            `expiresAt`?: StringOrNumeric;
            `createdBy`?: NullableString;
            `boundAccount`?: NullableString;
            `boundAt`?: StringOrNumericOrNull;
            `status`?: string
          })[];
          `challenges`?: ({
            `id`?: string;
            `profile`?: NullableString;
            `createdAt`?: StringOrNumeric;
            `expiresAt`?: StringOrNumeric;
            `createdBy`?: NullableString;
            `usedAt`?: StringOrNumericOrNull;
            `status`?: string
          })[];
          `hostNames`?: (string)[];
          `keyAlgorithms`?: (string)[];
          `json`?: {
            `families`?: (string)[];
            `rules`?: ({
              `family`?: string;
              `label`?: string;
              `allowedProfiles`?: (string)[];
              `allowedProfilesSource`?: string;
              `defaultProfile`?: NullableString;
              `defaultProfileSource`?: string;
              `certificateLifetimeDays`?: numeric;
              `certificateLifetimeSource`?: string
            })[];
            `certificateCap`?: {`value`?: numeric; `source`?: string};
            `est`?: NullableObject74;
            `certificates`?: ({
              `serialHex`?: string;
              `family`?: string;
              `profile`?: string;
              `subject`?: string;
              `names`?: (string)[];
              `thumbprint`?: string;
              `keyAlg`?: string;
              `notBefore`?: StringOrNumeric;
              `notAfter`?: StringOrNumeric;
              `issuedAt`?: string;
              `requestedBy`?: NullableObject12;
              `via`?: string;
              `keySource`?: string;
              `replaces`?: NullableString;
              `certificatePem`?: string;
              `chainPem`?: (string)[];
              `device`?: string;
              `attestation`?: StringOrNumericOrBooleanEtc4;
              `revoked`?: {
                `at`?: StringOrNumeric;
                `reason`?: string;
                `by`?: string
              };
              `expired`?: boolean;
              `status`?: string
            })[];
            `certificatesPaging`?: {
              `page`?: integer;
              `pages`?: integer;
              `perPage`?: integer;
              `firstRow`?: integer;
              `lastRow`?: integer;
              `total`?: integer;
              `param`?: string;
              `noun`?: string
            };
            `certificatesTotal`?: integer;
            `eabKeys`?: ({
              `kid`?: string;
              `createdAt`?: StringOrNumeric;
              `expiresAt`?: StringOrNumeric;
              `createdBy`?: NullableString;
              `boundAccount`?: NullableString;
              `boundAt`?: StringOrNumericOrNull;
              `status`?: string
            })[];
            `scepChallenges`?: ({
              `id`?: string;
              `profile`?: NullableString;
              `createdAt`?: StringOrNumeric;
              `expiresAt`?: StringOrNumeric;
              `createdBy`?: NullableString;
              `usedAt`?: StringOrNumericOrNull;
              `status`?: string
            })[];
            `hostNames`?: (string)[]
          }
        };
        `config`?: {
          `families`?: (string)[];
          `rules`?: ({
            `family`?: string;
            `label`?: string;
            `allowedProfiles`?: (string)[];
            `allowedProfilesSource`?: string;
            `defaultProfile`?: NullableString;
            `defaultProfileSource`?: string;
            `certificateLifetimeDays`?: numeric;
            `certificateLifetimeSource`?: string
          })[];
          `cap`?: {`value`?: numeric; `source`?: string};
          `est`?: NullableObject74;
          `certificates`?: ({
            `serialHex`?: string;
            `family`?: string;
            `profile`?: string;
            `subject`?: string;
            `names`?: (string)[];
            `thumbprint`?: string;
            `keyAlg`?: string;
            `notBefore`?: StringOrNumeric;
            `notAfter`?: StringOrNumeric;
            `issuedAt`?: string;
            `requestedBy`?: NullableObject12;
            `via`?: string;
            `keySource`?: string;
            `replaces`?: NullableString;
            `certificatePem`?: string;
            `chainPem`?: (string)[];
            `device`?: string;
            `attestation`?: StringOrNumericOrBooleanEtc4;
            `revoked`?: {
              `at`?: StringOrNumeric;
              `reason`?: string;
              `by`?: string
            };
            `expired`?: boolean;
            `status`?: string
          })[];
          `paged`?: {
            `paging`?: {
              `page`?: integer;
              `perPage`?: integer;
              `pages`?: integer;
              `offset`?: integer;
              `total`?: integer;
              `firstRow`?: integer;
              `lastRow`?: integer;
              `param`?: string;
              `noun`?: string
            };
            `shown`?: ({
              `serialHex`?: string;
              `family`?: string;
              `profile`?: string;
              `subject`?: string;
              `names`?: (string)[];
              `thumbprint`?: string;
              `keyAlg`?: string;
              `notBefore`?: StringOrNumeric;
              `notAfter`?: StringOrNumeric;
              `issuedAt`?: string;
              `requestedBy`?: NullableObject12;
              `via`?: string;
              `keySource`?: string;
              `replaces`?: NullableString;
              `certificatePem`?: string;
              `chainPem`?: (string)[];
              `device`?: string;
              `attestation`?: StringOrNumericOrBooleanEtc4;
              `revoked`?: {
                `at`?: StringOrNumeric;
                `reason`?: string;
                `by`?: string
              };
              `expired`?: boolean;
              `status`?: string
            })[]
          };
          `eabKeys`?: ({
            `kid`?: string;
            `createdAt`?: StringOrNumeric;
            `expiresAt`?: StringOrNumeric;
            `createdBy`?: NullableString;
            `boundAccount`?: NullableString;
            `boundAt`?: StringOrNumericOrNull;
            `status`?: string
          })[];
          `challenges`?: ({
            `id`?: string;
            `profile`?: NullableString;
            `createdAt`?: StringOrNumeric;
            `expiresAt`?: StringOrNumeric;
            `createdBy`?: NullableString;
            `usedAt`?: StringOrNumericOrNull;
            `status`?: string
          })[];
          `hostNames`?: (string)[];
          `keyAlgorithms`?: (string)[];
          `json`?: {
            `families`?: (string)[];
            `rules`?: ({
              `family`?: string;
              `label`?: string;
              `allowedProfiles`?: (string)[];
              `allowedProfilesSource`?: string;
              `defaultProfile`?: NullableString;
              `defaultProfileSource`?: string;
              `certificateLifetimeDays`?: numeric;
              `certificateLifetimeSource`?: string
            })[];
            `certificateCap`?: {`value`?: numeric; `source`?: string};
            `est`?: NullableObject74;
            `certificates`?: ({
              `serialHex`?: string;
              `family`?: string;
              `profile`?: string;
              `subject`?: string;
              `names`?: (string)[];
              `thumbprint`?: string;
              `keyAlg`?: string;
              `notBefore`?: StringOrNumeric;
              `notAfter`?: StringOrNumeric;
              `issuedAt`?: string;
              `requestedBy`?: NullableObject12;
              `via`?: string;
              `keySource`?: string;
              `replaces`?: NullableString;
              `certificatePem`?: string;
              `chainPem`?: (string)[];
              `device`?: string;
              `attestation`?: StringOrNumericOrBooleanEtc4;
              `revoked`?: {
                `at`?: StringOrNumeric;
                `reason`?: string;
                `by`?: string
              };
              `expired`?: boolean;
              `status`?: string
            })[];
            `certificatesPaging`?: {
              `page`?: integer;
              `pages`?: integer;
              `perPage`?: integer;
              `firstRow`?: integer;
              `lastRow`?: integer;
              `total`?: integer;
              `param`?: string;
              `noun`?: string
            };
            `certificatesTotal`?: integer;
            `eabKeys`?: ({
              `kid`?: string;
              `createdAt`?: StringOrNumeric;
              `expiresAt`?: StringOrNumeric;
              `createdBy`?: NullableString;
              `boundAccount`?: NullableString;
              `boundAt`?: StringOrNumericOrNull;
              `status`?: string
            })[];
            `scepChallenges`?: ({
              `id`?: string;
              `profile`?: NullableString;
              `createdAt`?: StringOrNumeric;
              `expiresAt`?: StringOrNumeric;
              `createdBy`?: NullableString;
              `usedAt`?: StringOrNumericOrNull;
              `status`?: string
            })[];
            `hostNames`?: (string)[]
          }
        }
      };
      `observed`?: {
        `paging`?: {
          `page`?: integer;
          `perPage`?: integer;
          `pages`?: integer;
          `offset`?: integer;
          `total`?: integer;
          `firstRow`?: integer;
          `lastRow`?: integer;
          `param`?: string;
          `noun`?: string
        };
        `shown`?: ({
          `attribute`?: string;
          `value`?: string;
          `held`?: boolean;
          `trusted`?: boolean
        })[]
      };
      `warnings`?: ({
        `attribute`?: string;
        `value`?: string;
        `reason`?: string;
        `dropped`?: boolean;
        `text`?: string
      })[];
      `owners`?: ({`dn`?: string; `kind`?: string; `name`?: string; `present`?: boolean})[];
      `maxOwners`?: numeric;
      `ownership`?: {
        `kind`?: string;
        `name`?: string;
        `marked`?: boolean;
        `protected`?: boolean;
        `reasons`?: (string)[]
      };
      `krb5Across`?: NullableObject75
    }
  }

  

@component model `ApplicationList` {
    `applicationCount`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `registered`?: BooleanOrNumeric;
    `filter`?: {
      `q`?: NullableString;
      `kind`?: NullableString;
      `exclude`?: NullableArray
    };
    `container`?: NullableString;
    `max`?: NullableNumber;
    `kinds`?: (StringOrKindStringLabelStringWhatString)[];
    `settings`?: NullableObject65;
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    @js(#{`description`:"How many applications are of each kind."}) `kindCounts`?: Record<integer>;
    `authentications`?: numeric;
    `protocols`?: (StringOrIdStringLabelStringKindStringKindsStringIdentifierAttributeStringRedirectAttributeStringLogoutAttributeStringDeliveryAttributeStringEventsAttributeStringSecretAttributeStringWhatString)[];
    `applications`?: ({
      `identifier`?: string;
      `dnLabel`?: NullableString;
      `dn`?: NullableString;
      `name`?: NullableString;
      `kinds`?: (string)[];
      `protocols`?: (string)[];
      `allowedProtocols`?: (string)[];
      `recordedProtocols`?: (string)[];
      `declaredKinds`?: (string)[];
      `registeredBy`?: string;
      `returnAddressesObserved`?: ({
        `attribute`?: string;
        `value`?: string;
        `held`?: boolean;
        `trusted`?: boolean
      })[];
      `registered`?: boolean;
      `firstSeen`?: string;
      `lastSeen`?: string;
      `authentications`?: numeric;
      `sessions`?: numeric;
      `users`?: numeric;
      `description`?: NullableString;
      `origin`?: NullableString;
      `createdAt`?: NullableString;
      `modifiedAt`?: NullableString;
      `operational`?: (string)[];
      @js(#{`description`:"By attribute name."}) `attributes`?: Record<StringOrNumericOrBooleanEtc4>;
      @js(#{`description`:"By attribute name."}) `fields`?: Record<StringOrNumericOrBooleanEtc4>;
      `secretExpiry`?: {`state`?: string; `at`?: string}
    })[];
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
    `returnAddressesObserved`?: ({
      `attribute`?: string;
      `value`?: string;
      `held`?: boolean;
      `trusted`?: boolean
    })[];
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
    `warnings`?: ({
      `attribute`?: string;
      `value`?: string;
      `reason`?: string;
      `dropped`?: boolean;
      `text`?: string
    })[];
    `attributesShown`?: ({
      `name`?: string;
      `values`?: (StringOrNumericOrBooleanEtc4)[];
      `sealedAtRest`?: boolean;
      `operational`?: boolean
    })[];
    `attributesPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `authenticationEvents`?: ({
      `seq`?: numeric;
      `origin`?: StringOrNumericOrNull;
      `at`?: numeric;
      `category`?: string;
      `action`?: string;
      `outcome`?: string;
      `errorCode`?: string;
      `actor`?: string;
      `actorForm`?: string;
      `target`?: string;
      `protocol`?: string;
      `channel`?: string;
      `address`?: string;
      `summary`?: string;
      @js(#{`description`:"What the event recorded."}) `detail`?: Record<StringOrNumericOrBoolean>
    })[];
    `authenticationEventsPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `authenticationEventsMatched`?: integer;
    @js(#{`description`:"Which actors have a user page."}) `authenticationEventsKnownActors`?: Record<boolean>;
    `authenticationEventsLog`?: {
      `held`?: numeric;
      `recorded`?: numeric;
      `dropped`?: numeric;
      `maxEvents`?: numeric
    };
    `returnAddressesObservedShown`?: ({
      `attribute`?: string;
      `value`?: string;
      `held`?: boolean;
      `trusted`?: boolean
    })[];
    `returnAddressesObservedPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `credentials`?: {
      `clientSecret`?: {
        `held`?: boolean;
        `authMethod`?: string;
        `registered`?: boolean;
        `registrationAccessTokenHeld`?: boolean;
        `expiresAt`?: numeric;
        `secrets`?: ({
          `id`?: string;
          `createdAt`?: numeric;
          `expiresAt`?: numeric;
          `description`?: NullableString;
          `expired`?: boolean;
          `primary`?: boolean
        })[];
        `max`?: numeric
      };
      `keyPairs`?: ({
        `label`?: string;
        `held`?: boolean;
        `source`?: string;
        `privateKeyHeld`?: boolean;
        `certificate`?: NullableObject69;
        `chain`?: ({
          `subject`?: string;
          `issuer`?: string;
          `serialHex`?: string;
          `notBefore`?: string;
          `notAfter`?: string;
          `expired`?: boolean;
          `selfSigned`?: boolean;
          `keyType`?: NullableString;
          `thumbprint`?: string;
          `unreadable`?: string
        })[];
        `handle`?: string;
        `handleLabel`?: string;
        `issuers`?: (string)[];
        `attributes`?: {
          `issuer`?: string;
          `certificate`?: string;
          `chain`?: string;
          `privateKey`?: string;
          `handle`?: string;
          `handleLabel`?: string;
          `expires`?: string;
          `source`?: string;
          `jwks`?: string;
          `registered`?: string
        };
        `registered`?: {
          `attribute`?: string;
          `problem`?: string;
          `keys`?: ({
            `kid`?: string;
            `kty`?: string;
            `alg`?: string;
            `use`?: string;
            `certificate`?: NullableObject69
          })[];
          `certificates`?: ({
            `subject`?: string;
            `issuer`?: string;
            `serialHex`?: string;
            `notBefore`?: string;
            `notAfter`?: string;
            `expired`?: boolean;
            `selfSigned`?: boolean;
            `keyType`?: NullableString;
            `thumbprint`?: string;
            `unreadable`?: string
          })[]
        };
        `purpose`?: string
      })[];
      `caAvailable`?: boolean;
      `oauthDeclared`?: boolean;
      `sources`?: (string)[];
      `mtls`?: {
        `certificates`?: ({
          `serialHex`?: string;
          `label`?: NullableString;
          `subject`?: NullableString;
          `keyAlg`?: NullableString;
          `notBefore`?: StringOrNumericOrNull;
          `notAfter`?: StringOrNumericOrNull;
          `thumbprint`?: NullableString;
          `state`?: string;
          `reason`?: NullableString;
          `revokedAt`?: StringOrNumericOrNull;
          `certificatePem`?: NullableString
        })[];
        `active`?: integer;
        `max`?: numeric;
        `keyAlgorithms`?: (string)[];
        `defaultKeyAlg`?: string;
        `revocationReasons`?: (string)[];
        `passwordMin`?: numeric;
        `implicitName`?: string;
        `caAvailable`?: boolean;
        `authMethod`?: string;
        `certificateMethod`?: boolean;
        `subjects`?: ({
          `member`?: string;
          `attribute`?: string;
          `label`?: string;
          `value`?: string
        })[];
        `registeredSubject`?: (string)[];
        `boundTokensAttribute`?: string;
        `boundTokens`?: boolean;
        `adminApiBound`?: boolean;
        `selfSignedThumbprint`?: string;
        `bindingAvailable`?: boolean
      };
      `signing`?: {
        `certificates`?: ({
          `serialHex`?: string;
          `label`?: NullableString;
          `subject`?: NullableString;
          `keyAlg`?: NullableString;
          `notBefore`?: StringOrNumericOrNull;
          `notAfter`?: StringOrNumericOrNull;
          `thumbprint`?: NullableString;
          `state`?: string;
          `reason`?: NullableString;
          `revokedAt`?: StringOrNumericOrNull;
          `certificatePem`?: NullableString
        })[];
        `active`?: integer;
        `max`?: numeric;
        `keyAlgorithms`?: (string)[];
        `defaultKeyAlg`?: string;
        `revocationReasons`?: (string)[];
        `passwordMin`?: numeric;
        `implicitName`?: string;
        `caAvailable`?: boolean;
        `ok`?: boolean;
        `kind`?: string;
        `holder`?: string;
        `wstrustDeclared`?: boolean
      };
      `stored`?: {
        `ok`?: boolean;
        `errors`?: (string)[];
        `application`?: string;
        `dn`?: NullableString;
        `certificates`?: ({
          `sha256`?: string;
          `subject`?: string;
          `issuer`?: string;
          `serialNumber`?: string;
          `notBefore`?: string;
          `notAfter`?: string;
          `expired`?: boolean;
          `readable`?: boolean
        })[];
        `rule`?: string
      }
    };
    `sharedSignals`?: {
      `installed`?: boolean;
      `streams`?: ({
        `stream_id`?: string;
        `status`?: string;
        `statusReason`?: NullableString;
        `aud`?: StringOrNumericOrBooleanEtc4;
        `delivery`?: {
          `method`?: string;
          `endpoint_url`?: NullableString
        };
        `events_requested`?: (string)[];
        `events_delivered`?: (string)[];
        `format`?: string;
        `description`?: string;
        `createdBy`?: string;
        `createdAt`?: StringOrNumeric;
        `updatedAt`?: StringOrNumeric;
        `lastPushAt`?: StringOrNumeric;
        `lastPushError`?: string
      })[];
      `settings`?: ({
        `setting`?: string;
        `attribute`?: string;
        `value`?: StringOrNumericOrBooleanEtc2;
        `source`?: string
      })[]
    };
    `certificateEnrollment`?: {
      `families`?: (string)[];
      `rules`?: ({
        `family`?: string;
        `label`?: string;
        `allowedProfiles`?: (string)[];
        `allowedProfilesSource`?: string;
        `defaultProfile`?: NullableString;
        `defaultProfileSource`?: string;
        `certificateLifetimeDays`?: numeric;
        `certificateLifetimeSource`?: string
      })[];
      `certificateCap`?: {`value`?: numeric; `source`?: string};
      `est`?: NullableObject74;
      `certificates`?: ({
        `serialHex`?: string;
        `family`?: string;
        `profile`?: string;
        `subject`?: string;
        `names`?: (string)[];
        `thumbprint`?: string;
        `keyAlg`?: string;
        `notBefore`?: StringOrNumeric;
        `notAfter`?: StringOrNumeric;
        `issuedAt`?: string;
        `requestedBy`?: NullableObject12;
        `via`?: string;
        `keySource`?: string;
        `replaces`?: NullableString;
        `certificatePem`?: string;
        `chainPem`?: (string)[];
        `device`?: string;
        `attestation`?: StringOrNumericOrBooleanEtc4;
        `revoked`?: {
          `at`?: StringOrNumeric;
          `reason`?: string;
          `by`?: string
        };
        `expired`?: boolean;
        `status`?: string
      })[];
      `certificatesPaging`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      };
      `certificatesTotal`?: integer;
      `eabKeys`?: ({
        `kid`?: string;
        `createdAt`?: StringOrNumeric;
        `expiresAt`?: StringOrNumeric;
        `createdBy`?: NullableString;
        `boundAccount`?: NullableString;
        `boundAt`?: StringOrNumericOrNull;
        `status`?: string
      })[];
      `scepChallenges`?: ({
        `id`?: string;
        `profile`?: NullableString;
        `createdAt`?: StringOrNumeric;
        `expiresAt`?: StringOrNumeric;
        `createdBy`?: NullableString;
        `usedAt`?: StringOrNumericOrNull;
        `status`?: string
      })[];
      `hostNames`?: (string)[]
    };
    `customClaims`?: ({
      `id`?: string;
      `label`?: string;
      `attribute`?: string;
      `realm`?: ({
        `name`?: string;
        `value`?: StringOrNumericOrBooleanEtc4;
        `nameFormat`?: string;
        `namespace`?: string;
        `attribute`?: string;
        `multi`?: boolean;
        `type`?: string
      })[];
      `own`?: ({
        `name`?: string;
        `value`?: StringOrNumericOrBooleanEtc4;
        `nameFormat`?: string;
        `namespace`?: string;
        `attribute`?: string;
        `multi`?: boolean;
        `type`?: string
      })[];
      `effective`?: ({
        `name`?: string;
        `value`?: StringOrNumericOrBooleanEtc4;
        `nameFormat`?: string;
        `namespace`?: string;
        `attribute`?: string;
        `multi`?: boolean;
        `type`?: string;
        `source`?: string;
        `replacesRealm`?: boolean
      })[]
    })[];
    `claimSelections`?: {
      `catalogue`?: ({
        `ldap`?: string;
        `claim`?: string;
        `label`?: string;
        `schema`?: string;
        `ldpTerm`?: string;
        `generated`?: boolean
      })[];
      `preview`?: {
        `user`?: string;
        @js(#{`description`:"By lower-cased attribute name."}) `byLdap`?: Record<{
          `ldap`?: string;
          `claim`?: string;
          `value`?: StringOrNumericOrBooleanEtc4;
          `source`?: string;
          `ldpTerm`?: NullableString
        }>;
        `entryFound`?: boolean
      };
      `sets`?: ({
        `id`?: string;
        `label`?: string;
        `attribute`?: string;
        `realm`?: (string)[];
        `own`?: NullableArray;
        `inherited`?: boolean;
        `effective`?: (string)[];
        @js(#{`description`:"The claims, by name."}) `claims`?: Record<StringOrNumericOrBooleanEtc4OrListOfRecordStringOrNumericOrBooleanEtc4>;
        `report`?: ({
          `ldap`?: string;
          `claim`?: string;
          `value`?: StringOrNumericOrBooleanEtc4;
          `source`?: string;
          `ldpTerm`?: NullableString
        })[]
      })[];
      `credential`?: NullableObject73
    };
    `tokenLifetimes`?: {
      `lifetimes`?: ({
        `setting`?: string;
        `attribute`?: string;
        `label`?: string;
        `value`?: numeric;
        `realmValue`?: numeric;
        `source`?: string
      })[];
      `clockSkewS`?: numeric
    };
    `softwareStatements`?: {
      `declaredIssuers`?: (string)[];
      `usableKeys`?: integer;
      `issued`?: NullableObject72;
      `registeredWith`?: NullableObject71;
      `settings`?: {
        `requireTrustedIssuer`?: boolean;
        `opensRegistration`?: boolean;
        `required`?: boolean;
        `lifetimeSeconds`?: numeric
      }
    };
    `applicationRoles`?: {
      `held`?: ({
        `name`?: string;
        `id`?: string;
        `displayName`?: string;
        `application`?: string;
        `carriedAs`?: string;
        `permissions`?: (string)[]
      })[];
      `offerable`?: (string)[];
      `required`?: ({
        `name`?: string;
        `resolves`?: string;
        `displayName`?: string;
        `role`?: string
      })[];
      `requirable`?: (string)[]
    };
    `delegatedPermissions`?: {
      `held`?: ({
        `client`?: string;
        `clientName`?: string;
        `permissionId`?: string;
        `resource`?: string;
        `resourceName`?: string;
        `baseUri`?: NullableString;
        `permissionName`?: string;
        `description`?: NullableString;
        `dangling`?: boolean;
        `asked`?: boolean
      })[];
      `exposes`?: ({
        `resource`?: string;
        `resourceName`?: string;
        `baseUri`?: NullableString;
        `name`?: string;
        `description`?: NullableString;
        `id`?: NullableString;
        `raw`?: NullableString;
        `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
      })[];
      `offerable`?: (NullableString)[];
      `grantedOut`?: ({
        `client`?: string;
        `clientName`?: string;
        `permissionId`?: string;
        `resource`?: string;
        `resourceName`?: string;
        `baseUri`?: NullableString;
        `permissionName`?: string;
        `description`?: NullableString;
        `dangling`?: boolean;
        `asked`?: boolean
      })[];
      `paging`?: {
        `held`?: {
          `page`?: integer;
          `pages`?: integer;
          `perPage`?: integer;
          `firstRow`?: integer;
          `lastRow`?: integer;
          `total`?: integer;
          `param`?: string;
          `noun`?: string
        };
        `exposes`?: {
          `page`?: integer;
          `pages`?: integer;
          `perPage`?: integer;
          `firstRow`?: integer;
          `lastRow`?: integer;
          `total`?: integer;
          `param`?: string;
          `noun`?: string
        };
        `grantedOut`?: {
          `page`?: integer;
          `pages`?: integer;
          `perPage`?: integer;
          `firstRow`?: integer;
          `lastRow`?: integer;
          `total`?: integer;
          `param`?: string;
          `noun`?: string
        }
      }
    };
    `owners`?: ({`dn`?: string; `kind`?: string; `name`?: string; `present`?: boolean})[];
    `maxOwners`?: numeric
  }

@js(#{
    `description`:"Every attribute a person may be created with, and the four ways they can be given a way in."
  }) @component model `NewUserForm` {
    `directory`?: boolean;
    `container`?: NullableString;
    `why`?: string;
    `realm`?: {`id`?: string; `name`?: string};
    `mode`?: string;
    `offersExampleData`?: boolean;
    `fields`?: ({
      `attribute`?: string;
      `label`?: string;
      `schema`?: string;
      `claim`?: (string)[];
      `invented`?: boolean
    })[];
    `fieldGroups`?: ({
      `id`?: string;
      `label`?: string;
      `what`?: string;
      `attributes`?: (string)[]
    })[];
    `gridFields`?: ({
      `attribute`?: string;
      `label`?: string;
      `group`?: string;
      `multi`?: boolean;
      `example`?: string;
      `simple`?: boolean;
      `takes`?: string;
      `custom`?: boolean
    })[];
    `requiredAttributes`?: (string)[];
    `requiredEnforced`?: boolean;
    `credentials`?: ({`id`?: string; `label`?: string; `what`?: string})[];
    `username`?: string;
    `fieldRows`?: ({
      `attribute`?: string;
      `type`?: string;
      `what`?: string;
      `example`?: string;
      `forText`?: string;
      `families`?: (string)[];
      `everyFamily`?: boolean;
      `group`?: string;
      `simple`?: boolean;
      `required`?: boolean;
      `label`?: string;
      `schema`?: string;
      `claim`?: (string)[];
      `multi`?: boolean;
      `custom`?: boolean;
      `takes`?: string
    })[];
    `longTextAttributes`?: (string)[];
    `mailAvailable`?: boolean;
    `persistence`?: {`persistsDirectory`?: boolean; `mode`?: string};
    `defaultCredential`?: string;
    `credential`?: string;
    `passwordPolicy`?: {`profile`?: string; `enforced`?: boolean; `rules`?: (string)[]};
    `invented`?: NullableObject76;
    `inventRefused`?: string
  }

@component model `NewApplicationForm` {
    `directory`?: boolean;
    `container`?: NullableString;
    `max`?: NullableNumber;
    `applicationCount`?: integer;
    `realm`?: {`id`?: string; `name`?: string};
    `kinds`?: ({`kind`?: string; `label`?: string; `what`?: string})[];
    `protocols`?: ({
      `id`?: string;
      `label`?: string;
      `kind`?: string;
      `kinds`?: (string)[];
      `identifierAttribute`?: string;
      `redirectAttribute`?: string;
      `logoutAttribute`?: string;
      `deliveryAttribute`?: string;
      `eventsAttribute`?: string;
      `secretAttribute`?: string;
      `what`?: string
    })[];
    `declarations`?: ({
      `attribute`?: string;
      `role`?: string;
      `kind`?: string;
      `editable`?: StringOrBoolean;
      `sensitive`?: boolean;
      `what`?: string;
      `families`?: ({`id`?: string; `label`?: string})[];
      `everyFamily`?: boolean
    })[];
    `fields`?: ({
      `attribute`?: string;
      `type`?: string;
      `long`?: boolean;
      `editable`?: StringOrBoolean;
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
      `described`?: {
        `key`?: string;
        `group`?: string;
        `label`?: string;
        `description`?: string;
        `type`?: string;
        `enumValues`?: (string)[];
        `csvValues`?: (string)[];
        `ordered`?: boolean;
        @js(#{`description`:"The sentence beside each of a list's values."}) `csvValueNotes`?: Record<string>;
        `selectAll`?: {
          `onlyWhileOn`?: ({
            `setting`?: string;
            `values`?: (string)[];
            `on`?: boolean;
            `canBeOn`?: boolean
          })[];
          `aloneWhileOn`?: ({
            `setting`?: string;
            `values`?: (string)[];
            `on`?: boolean;
            `canBeOn`?: boolean
          })[]
        };
        `min`?: numeric;
        `max`?: numeric;
        `step`?: numeric;
        `value`?: StringOrNumericOrBooleanEtc2;
        `text`?: string;
        `source`?: string;
        `editable`?: boolean;
        `restartReason`?: string;
        `editRefusal`?: string;
        `env`?: NullableString;
        `legacyEnv`?: NullableString;
        `appconfigPath`?: string;
        `default`?: StringOrNumericOrBooleanEtc2;
        `masked`?: boolean;
        `realmSettable`?: boolean;
        `overridden`?: boolean
      };
      `inSimple`?: boolean
    })[];
    `fieldGroups`?: ({`id`?: string; `label`?: string; `families`?: (string)[]})[];
    `familyChoices`?: ({
      `id`?: string;
      `label`?: string;
      `families`?: (string)[];
      `kind`?: string;
      `what`?: string
    })[];
    `longTextAttributes`?: (string)[];
    `defaultSecretLifetimeDays`?: numeric;
    `persistence`?: {`persistsDirectory`?: boolean; `mode`?: string};
    `resourceMetadataImport`?: {
      `wellKnown`?: string;
      `acceptsNonconforming`?: boolean;
      `dialsInternalAddresses`?: boolean
    };
    `editable`?: ({
      `name`?: string;
      `mode`?: StringOrBoolean;
      `sensitive`?: boolean;
      `families`?: (string)[]
    })[]
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
    `filter`?: {
      `q`?: NullableString;
      `exclude`?: NullableArray
    };
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `adminGroups`?: {
      `read`?: NullableString;
      `write`?: NullableString
    };
    `groups`?: ({
      `dn`?: string;
      `cn`?: string;
      `rule`?: string;
      `description`?: string;
      `objectClass`?: (string)[];
      `origin`?: string;
      `createdAt`?: NullOrStringOrNumeric;
      `modifiedAt`?: NullOrStringOrNumeric;
      `memberCount`?: numeric;
      `presentCount`?: numeric;
      `danglingCount`?: numeric;
      `claimedCount`?: numeric;
      `ownerCount`?: numeric;
      `attributeCount`?: numeric
    })[]
  }

@component model `DirectoryEntryList` {
    `baseDn`?: string;
    `count`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `filter`?: {
      `q`?: NullableString;
      `origin`?: NullableString
    };
    `origins`?: (string)[];
    @js(#{`description`:"A count per name."}) `originCounts`?: Record<numeric>;
    `order`?: string;
    `search`?: NullableObject78;
    `entries`?: ({
      `dn`?: string;
      `origin`?: string;
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `attributes`?: Record<NullOrStringOrString>
    })[];
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: NullableString;
      `noun`?: NullableString
    };
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
    `kinds`?: ({`kind`?: string; `label`?: string; `what`?: string})[];
    `schema`?: {
      `objectClasses`?: ({
        `name`?: string;
        `what`?: string;
        `where`?: string;
        `standard`?: boolean
      })[];
      `attributes`?: ({
        `name`?: string;
        `what`?: string;
        `kind`?: string;
        `from`?: string;
        `role`?: string;
        `standard`?: boolean;
        `sensitive`?: boolean;
        `secret`?: boolean;
        `identifier`?: boolean;
        `identifierName`?: string;
        `editable`?: BooleanOrString;
        `enum`?: (string)[];
        `families`?: (string)[];
        `familyWhy`?: string;
        `overrides`?: string;
        `strictOverride`?: boolean
      })[]
    };
    `applications`?: ({
      `identifier`?: string;
      `dnLabel`?: NullableString;
      `dn`?: NullableString;
      `name`?: NullableString;
      `kinds`?: (string)[];
      `protocols`?: (string)[];
      `allowedProtocols`?: (string)[];
      `recordedProtocols`?: (string)[];
      `declaredKinds`?: (string)[];
      `registeredBy`?: string;
      `returnAddressesObserved`?: ({
        `attribute`?: string;
        `value`?: string;
        `held`?: boolean;
        `trusted`?: boolean
      })[];
      `registered`?: boolean;
      `firstSeen`?: string;
      `lastSeen`?: string;
      `authentications`?: numeric;
      `sessions`?: numeric;
      `users`?: numeric;
      `description`?: NullableString;
      `origin`?: NullableString;
      `createdAt`?: NullableString;
      `modifiedAt`?: NullableString;
      `operational`?: (string)[];
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `attributes`?: Record<NullOrStringOrString>;
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `fields`?: Record<NullOrStringOrString>
    })[];
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: NullableString;
      `noun`?: NullableString
    };
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
    `roles`?: ({`role`?: string; `label`?: string; `short`?: string; `what`?: string})[];
    `protocols`?: ({
      `protocol`?: string;
      `label`?: string;
      `family`?: string;
      `what`?: string;
      `needs`?: (string)[];
      `spec`?: string;
      `signalsOnly`?: boolean
    })[];
    `schema`?: {
      `objectClasses`?: ({
        `name`?: string;
        `what`?: string;
        `where`?: string;
        `standard`?: boolean
      })[];
      `attributes`?: ({
        `name`?: string;
        `what`?: string;
        `kind`?: string;
        `from`?: string;
        `role`?: string;
        `standard`?: boolean;
        `sensitive`?: boolean;
        `secret`?: boolean;
        `identifier`?: boolean;
        `identifierName`?: string;
        `editable`?: BooleanOrString;
        `enum`?: (string)[];
        `families`?: (string)[];
        `familyWhy`?: string;
        `overrides`?: string;
        `strictOverride`?: boolean
      })[]
    };
    `relationships`?: ({
      `dn`?: string;
      `createdAt`?: string;
      `modifiedAt`?: string;
      `ready`?: boolean;
      `missing`?: (string)[];
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `entryAttributes`?: Record<NullOrStringOrString2>;
      `roleShort`?: string;
      `protocolLabel`?: string;
      `enabled`?: boolean;
      `fedId`?: string;
      `cn`?: string;
      `fedName`?: string;
      `fedRole`?: string;
      `fedProtocol`?: string;
      `fedProvider`?: string;
      `fedPeer`?: string;
      `fedLocalEntityId`?: string;
      `fedEnabled`?: string;
      `fedSsoUrl`?: string;
      `fedTokenUrl`?: string;
      `fedUserinfoUrl`?: string;
      `fedJwksUri`?: string;
      `fedEmailsUrl`?: string;
      `fedJwks`?: string;
      `fedTrustAnchor`?: string;
      `fedSigningCertificate`?: string;
      `fedClientId`?: string;
      `fedClientSecret`?: string;
      `fedResponseMode`?: string;
      `fedTeamId`?: string;
      `fedKeyId`?: string;
      `fedClientSigningKey`?: string;
      `fedTokenAuth`?: string;
      `fedScope`?: string;
      `fedResponseType`?: string;
      `fedIdTokenSignedResponseAlg`?: string;
      `fedUserinfoSignedResponseAlg`?: string;
      `fedRefreshTokens`?: string;
      `fedRefreshEverySeconds`?: string;
      `fedRegister`?: string;
      `fedRegisteredIssuer`?: string;
      `fedRequestObject`?: string;
      `fedRequestObjectSigningAlg`?: string;
      `fedWebFinger`?: string;
      `fedDiscovery`?: string;
      `fedInitiateLogin`?: string;
      `fedBinding`?: string;
      `fedSignRequest`?: string;
      `fedUsernameSource`?: string;
      `fedSubjectClaim`?: string;
      `fedAutocreateUsers`?: string;
      `fedUpdateUserAttributes`?: string;
      `fedProvisionGroups`?: string;
      `fedProvisionCap`?: string;
      `fedProvisionIdleMinutes`?: string;
      `fedSubjectPolicy`?: string;
      `fedSubjectPattern`?: string;
      `fedMayAssertAdministrators`?: string;
      `fedSignalEmailMatch`?: string;
      `fedSignalsEnabled`?: string;
      `fedSignalsIssuer`?: string;
      `fedSignalsDelivery`?: string;
      `fedSignalsTokenUrl`?: string;
      `fedSignalsClientId`?: string;
      `fedSignalsClientSecret`?: string;
      `fedSignalsScope`?: string;
      `fedSignalsBearer`?: string;
      `fedSloUrl`?: string;
      `fedSloBinding`?: string;
      `fedEndSessionUrl`?: string;
      `fedAcceptSignout`?: string;
      `fedRequireSignedLogout`?: string;
      `fedEncryptionKeyType`?: string;
      `fedKeyManagementAlgorithm`?: string;
      `fedContentEncryptionAlgorithm`?: string;
      `fedAllowUnencrypted`?: string;
      `fedAllowUnsolicited`?: string;
      `fedApplication`?: string;
      `fedAuthnMechanism`?: string;
      `fedAuthnRelationship`?: string;
      `fedFirstSeen`?: string;
      `fedLastSeen`?: string;
      `fedAuthentications`?: string;
      `fedUsers`?: string;
      `fedLastUser`?: string;
      `fedLastError`?: string;
      `fedLastErrorAt`?: string;
      `description`?: (string)[];
      `fedAllowedTenants`?: (string)[];
      `fedAuthorizeParams`?: (string)[];
      `fedAttributeMap`?: (string)[];
      `fedSubjectGroup`?: (string)[];
      `fedSubjectDomain`?: (string)[];
      `fedHomeRealmDomain`?: (string)[];
      `fedSignalsEvents`?: (string)[];
      `fedEncryptionKey`?: (string)[];
      `fedRelease`?: (string)[];
      `fedApplicationUse`?: (string)[]
    })[];
    `enabledCount`?: integer;
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: NullableString;
      `noun`?: NullableString
    };
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
    `schema`?: {
      `objectClasses`?: ({
        `name`?: string;
        `what`?: string;
        `where`?: string;
        `standard`?: boolean
      })[];
      `attributes`?: ({
        `name`?: string;
        `what`?: string;
        `kind`?: string;
        `from`?: string;
        `role`?: string;
        `standard`?: boolean;
        `sensitive`?: boolean;
        `secret`?: boolean;
        `identifier`?: boolean;
        `identifierName`?: string;
        `editable`?: BooleanOrString;
        `enum`?: (string)[];
        `families`?: (string)[];
        `familyWhy`?: string;
        `overrides`?: string;
        `strictOverride`?: boolean
      })[]
    };
    `filter`?: {
      `entryq`?: NullableString;
      `agentq`?: NullableString
    };
    `entriesPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: NullableString;
      `noun`?: NullableString
    };
    `agentsPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: NullableString;
      `noun`?: NullableString
    };
    `registrationEntries`?: ({
      `id`?: string;
      `dn`?: string;
      `spiffeId`?: string;
      `parentId`?: string;
      `selectors`?: ({`type`?: string; `value`?: string})[];
      `selectorTexts`?: (string)[];
      `x509SvidTtl`?: numeric;
      `jwtSvidTtl`?: numeric;
      `dnsNames`?: (string)[];
      `federatesWith`?: (string)[];
      `hint`?: string;
      `admin`?: boolean;
      `downstream`?: boolean;
      `storeSvid`?: boolean;
      `expiresAt`?: numeric;
      `expired`?: boolean;
      `revisionNumber`?: numeric;
      `origin`?: string;
      `svidsIssued`?: numeric;
      `lastSvidAt`?: string;
      `createdAt`?: string;
      `modifiedAt`?: string;
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `attributes`?: Record<NullOrStringOrString>
    })[];
    `attestedAgents`?: ({
      `id`?: string;
      `dn`?: string;
      `attestationType`?: string;
      `selectors`?: ({`type`?: string; `value`?: string})[];
      `banned`?: boolean;
      `canReattest`?: boolean;
      `svidHash`?: string;
      `expiresAt`?: numeric;
      `firstSeen`?: string;
      `lastSeen`?: string;
      `attestations`?: numeric;
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `attributes`?: Record<NullOrStringOrString>
    })[];
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
    `schema`?: {
      `objectClasses`?: ({
        `name`?: string;
        `what`?: string;
        `where`?: string;
        `standard`?: boolean
      })[];
      `attributes`?: ({
        `name`?: string;
        `what`?: string;
        `kind`?: string;
        `from`?: string;
        `role`?: string;
        `standard`?: boolean;
        `sensitive`?: boolean;
        `secret`?: boolean;
        `identifier`?: boolean;
        `identifierName`?: string;
        `editable`?: BooleanOrString;
        `enum`?: (string)[];
        `families`?: (string)[];
        `familyWhy`?: string;
        `overrides`?: string;
        `strictOverride`?: boolean
      })[]
    };
    `roles`?: ({
      `name`?: string;
      `dn`?: string;
      `origin`?: NullableString;
      `createdAt`?: NullableString;
      `modifiedAt`?: NullableString;
      `operational`?: (string)[];
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `attributes`?: Record<NullOrStringOrString>
    })[];
    `builtInCatalogue`?: ({`name`?: string; `what`?: string})[];
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: NullableString;
      `noun`?: NullableString
    };
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
    `schema`?: {
      `objectClasses`?: ({
        `name`?: string;
        `what`?: string;
        `where`?: string;
        `standard`?: boolean
      })[];
      `attributes`?: ({
        `name`?: string;
        `what`?: string;
        `kind`?: string;
        `from`?: string;
        `role`?: string;
        `standard`?: boolean;
        `sensitive`?: boolean;
        `secret`?: boolean;
        `identifier`?: boolean;
        `identifierName`?: string;
        `editable`?: BooleanOrString;
        `enum`?: (string)[];
        `families`?: (string)[];
        `familyWhy`?: string;
        `overrides`?: string;
        `strictOverride`?: boolean
      })[]
    };
    `policies`?: ({
      `name`?: string;
      `dn`?: string;
      `origin`?: NullableString;
      `createdAt`?: NullableString;
      `modifiedAt`?: NullableString;
      `operational`?: (string)[];
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `attributes`?: Record<NullOrStringOrString>
    })[];
    `enabledCount`?: integer;
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: NullableString;
      `noun`?: NullableString
    };
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
    `schema`?: {
      `objectClasses`?: ({
        `name`?: string;
        `what`?: string;
        `where`?: string;
        `standard`?: boolean
      })[];
      `attributes`?: ({
        `name`?: string;
        `what`?: string;
        `kind`?: string;
        `from`?: string;
        `role`?: string;
        `standard`?: boolean;
        `sensitive`?: boolean;
        `secret`?: boolean;
        `identifier`?: boolean;
        `identifierName`?: string;
        `editable`?: BooleanOrString;
        `enum`?: (string)[];
        `families`?: (string)[];
        `familyWhy`?: string;
        `overrides`?: string;
        `strictOverride`?: boolean
      })[]
    };
    `peps`?: ({
      `name`?: string;
      `dn`?: string;
      `origin`?: NullableString;
      `createdAt`?: NullableString;
      `modifiedAt`?: NullableString;
      `operational`?: (string)[];
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `attributes`?: Record<NullOrStringOrString>
    })[];
    `enabledCount`?: integer;
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: NullableString;
      `noun`?: NullableString
    };
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
    `persistence`?: {
      `mode`?: string;
      `configuredMode`?: string;
      `enabled`?: boolean;
      `healthy`?: NullableBoolean;
      `dataDir`?: NullableString;
      `database`?: NullableObject79;
      `engine`?: NullableString;
      `writeDelayMs`?: numeric;
      `persistsDirectory`?: boolean;
      `persistsRealms`?: boolean;
      `persistsAppconfig`?: boolean;
      `pending`?: boolean;
      `writes`?: numeric;
      `failures`?: numeric;
      `lastWriteAt`?: NumericOrStringOrNull;
      `lastError`?: NullableString;
      `restoredAt`?: NumericOrStringOrNull;
      `restored`?: {`realms`?: numeric; `entries`?: numeric; `overrides`?: numeric};
      `entriesTracked`?: numeric;
      `realmsTracked`?: numeric;
      `coordinates`?: boolean;
      `minted`?: {
        `persisting`?: boolean;
        `supported`?: boolean;
        `unsupportedReason`?: string;
        `sealed`?: boolean;
        `mode`?: string;
        `setting`?: boolean;
        `retentionMs`?: numeric;
        `stores`?: numeric;
        `shared`?: numeric;
        `handles`?: ({`handle`?: string; `shape`?: string; `scope`?: string})[];
        `pending`?: numeric;
        `writes`?: numeric;
        `failures`?: numeric;
        `rowsWritten`?: numeric;
        `rowsDeleted`?: numeric;
        `lastWriteAt`?: NumericOrStringOrNull;
        `lastError`?: NullableString;
        `restoredAt`?: NumericOrStringOrNull;
        `restored`?: numeric;
        `droppedUnreadable`?: numeric;
        `droppedUnknown`?: numeric;
        `droppedPoison`?: numeric;
        `poisonDrops`?: ({
          `at`?: string;
          `code`?: string;
          `message`?: string;
          `rows`?: numeric;
          `handles`?: (string)[];
          `realms`?: (string)[]
        })[]
      };
      `usedAssertions`?: {
        `store`?: NullableString;
        `kind`?: NullableString;
        `persistent`?: boolean;
        `atomicAcrossProcesses`?: boolean;
        `why`?: NullableString;
        `cap`?: numeric;
        `live`?: NullableNumber;
        `liveIsCurrent`?: boolean
      };
      `replication`?: {
        `coordinating`?: boolean;
        `supported`?: boolean;
        `startedAt`?: NumericOrStringOrNull;
        `appliedSeq`?: numeric;
        `highestSeq`?: numeric;
        `holes`?: numeric;
        `holeRanges`?: numeric;
        `holesAbandoned`?: numeric;
        `pollIntervalMs`?: numeric;
        `pulls`?: numeric;
        `nudges`?: numeric;
        `failures`?: numeric;
        `rowsApplied`?: numeric;
        @js(#{`description`:"A count per name."}) `byKind`?: Record<numeric>;
        `lastPullAt`?: NumericOrStringOrNull;
        `lastError`?: NullableString;
        `otherProcesses`?: numeric;
        `originsDropped`?: numeric;
        `retention`?: {
          `retentionS`?: numeric;
          `readerTtlS`?: numeric;
          `reportedAt`?: NullableString;
          `reportError`?: NullableString;
          `declaredGoneAt`?: NumericOrStringOrNull;
          `fanInGraceS`?: numeric;
          `trimming`?: boolean;
          `lastTrim`?: NullableObject80
        };
        `note`?: string
      };
      `cells`?: NullableObject81;
      `origin`?: NullableObject82;
      `answersAfterCommit`?: boolean;
      `commitBacklog`?: boolean;
      `retryArmed`?: boolean;
      `liveness`?: NullableObject83;
      `eventLoop`?: NullableObject84;
      `note`?: string
    };
    `tls`?: {
      `ldaps`?: boolean;
      `port`?: NullableInteger;
      `url`?: string;
      `listening`?: boolean;
      `error`?: NullableString;
      `startTls`?: boolean;
      `clientCertificateMode`?: string;
      `saslExternal`?: {
        `available`?: boolean;
        `mechanisms`?: (string)[];
        `outsideCertificateAuthorities`?: boolean;
        `rule`?: string
      };
      `clientCertificates`?: string;
      `certificate`?: {
        `subject`?: NullableString;
        `names`?: NullableArray;
        `fingerprint256`?: NullableString;
        `notAfter`?: NullableString;
        `source`?: string
      }
    };
    `autoCreateUsers`?: boolean;
    `autoCreateRule`?: string;
    `authenticationFacts`?: string;
    `enforcedRules`?: (string)[];
    `limits`?: {
      `maxEntries`?: numeric;
      `maxSearchResults`?: numeric;
      `currentEntries`?: numeric;
      `currentEntriesEverywhere`?: numeric
    };
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
    `group`?: {
      `dn`?: string;
      `cn`?: string;
      `rule`?: string;
      `origin`?: string;
      `createdAt`?: NullOrStringOrNumeric;
      `modifiedAt`?: NullOrStringOrNumeric;
      `operational`?: (string)[];
      `memberAttributes`?: (string)[];
      `attributes`?: Record<StringOrString>;
      `members`?: ({
        `value`?: string;
        `attribute`?: string;
        `holds`?: string;
        `dn`?: string;
        `present`?: boolean;
        `kind`?: string;
        `userKey`?: string;
        `cn`?: string;
        `mail`?: string;
        `displayName`?: string
      })[];
      `memberCount`?: numeric;
      `presentCount`?: numeric;
      `danglingCount`?: numeric;
      `claimed`?: ({
        `dn`?: string;
        `kind`?: string;
        `userKey`?: string;
        `cn`?: string;
        `mail`?: string;
        `displayName`?: string;
        `value`?: string;
        `attribute`?: string;
        `holds`?: string;
        `present`?: boolean
      })[];
      `owners`?: ({`dn`?: string; `kind`?: string; `name`?: string; `present`?: boolean})[];
      `maxOwners`?: numeric
    };
    `groups`?: ({
      `dn`?: string;
      `cn`?: string;
      `rule`?: string;
      `description`?: string;
      `objectClass`?: (string)[];
      `origin`?: string;
      `createdAt`?: NullOrStringOrNumeric;
      `modifiedAt`?: NullOrStringOrNumeric;
      `memberCount`?: numeric;
      `presentCount`?: numeric;
      `danglingCount`?: numeric;
      `claimedCount`?: numeric;
      `ownerCount`?: numeric;
      `attributeCount`?: numeric
    })[];
    `groupCount`?: numeric;
    `policyReferences`?: ({
      `attribute`?: string;
      `noun`?: string;
      `choices`?: (string)[];
      `value`?: string
    })[];
    `ownership`?: {
      `kind`?: string;
      `name`?: string;
      `marked`?: boolean;
      `protected`?: boolean;
      `reasons`?: (string)[]
    };
    `membersPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `claimedPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `known`?: Record<boolean>;
    `adminGroups`?: {
      `read`?: NullableString;
      `write`?: NullableString
    }
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
    `coverage`?: {
      `source`?: string;
      `complete`?: boolean;
      `newest`?: NullableNumber;
      `session`?: NullableString;
      `unread`?: boolean;
      `countEstimated`?: boolean
    };
    `matched`?: integer;
    `matchedCredentials`?: integer;
    `shown`?: integer;
    `shownCredentials`?: integer;
    @js(#{`description`:"Credentials held in each family."}) `heldByFamily`?: Record<integer>;
    `filter`?: {
      `family`?: NullableString;
      `kind`?: NullableString;
      `state`?: NullableString;
      `session`?: NullableString
    };
    `families`?: ({
      `family`?: string;
      `label`?: string;
      `kinds`?: (string)[];
      `what`?: string
    })[];
    `revocableKinds`?: (string)[];
    `revokedCount`?: integer;
    `sets`?: (`IssuedSet`)[];
    `issued`?: (`IssuedRecord`)[];
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
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
    }) `settings`?: {
      `page`?: string;
      @js(#{`description`:"In the order `config.js` declares them."}) `groups`?: (WithGroupSettings)[];
      `settingCount`?: integer;
      @js(#{`description`:"How many of them can be changed while the service runs."}) `editableCount`?: integer;
      @js(#{`description`:"The keys on this page with a runtime override in force."}) `overridden`?: (string)[];
      @js(#{`description`:"The operation that writes them."}) `setWith`?: string;
      `context`?: {
        `configFile`?: NullableString;
        `defaultsFile`?: string;
        `persistsAppconfig`?: boolean;
        `persistsRealms`?: boolean;
        `persistenceMode`?: string;
        `inRealm`?: boolean;
        `realmId`?: string
      };
      @js(#{`description`:"A group drawn on another page as well, and those pages."}) `sharedWith`?: Record<({`path`?: string; `label`?: NullableString})[]>
    }
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
    }) `settings`?: {
      `page`?: string;
      @js(#{`description`:"In the order `config.js` declares them."}) `groups`?: (WithGroupSettings)[];
      `settingCount`?: integer;
      @js(#{`description`:"How many of them can be changed while the service runs."}) `editableCount`?: integer;
      @js(#{`description`:"The keys on this page with a runtime override in force."}) `overridden`?: (string)[];
      @js(#{`description`:"The operation that writes them."}) `setWith`?: string;
      `context`?: {
        `configFile`?: NullableString;
        `defaultsFile`?: string;
        `persistsAppconfig`?: boolean;
        `persistsRealms`?: boolean;
        `persistenceMode`?: string;
        `inRealm`?: boolean;
        `realmId`?: string
      };
      @js(#{`description`:"A group drawn on another page as well, and those pages."}) `sharedWith`?: Record<({
        `path`?: string;
        `label`?: NullableString
      })[]>
    };
    @js(#{`description`:"The page's first paragraph, as the console draws it."}) `leadHtml`?: string;
    @js(#{`description`:"The caveats, as the console draws them."}) `alsoHtml`?: (string)[];
    `status`?: WithModeConfiguredModeEnabledEtcOrWithSelfModeWhyEtc
  }

@component model `TokenLifetimes` {
    `lifetimes`?: {
      `accessTokenTtlS`?: numeric;
      `idTokenTtlS`?: numeric;
      `refreshTokenTtlS`?: numeric;
      `clockSkewS`?: numeric
    };
    `settings`?: ({
      `key`?: string;
      `group`?: string;
      `label`?: string;
      `description`?: string;
      `type`?: string;
      `enumValues`?: (string)[];
      `csvValues`?: (string)[];
      `ordered`?: boolean;
      @js(#{`description`:"The sentence beside each of a list's values."}) `csvValueNotes`?: Record<string>;
      `selectAll`?: {
        `onlyWhileOn`?: ({
          `setting`?: string;
          `values`?: (string)[];
          `on`?: boolean;
          `canBeOn`?: boolean
        })[];
        `aloneWhileOn`?: ({
          `setting`?: string;
          `values`?: (string)[];
          `on`?: boolean;
          `canBeOn`?: boolean
        })[]
      };
      `min`?: numeric;
      `max`?: numeric;
      `step`?: numeric;
      `value`?: StringOrNumericOrBooleanEtc2;
      `text`?: string;
      `source`?: string;
      `editable`?: boolean;
      `restartReason`?: string;
      `editRefusal`?: string;
      `env`?: NullableString;
      `legacyEnv`?: NullableString;
      `appconfigPath`?: string;
      `default`?: StringOrNumericOrBooleanEtc2;
      `masked`?: boolean;
      `realmSettable`?: boolean;
      `overridden`?: boolean
    })[];
    `tokens`?: {
      `held`?: integer;
      `forgotten`?: integer;
      `cap`?: numeric;
      `revoked`?: integer;
      `byKind`?: ({
        `kind`?: string;
        `issued`?: integer;
        `valid`?: integer;
        `expired`?: integer;
        `revoked`?: integer;
        `notYetValid`?: integer;
        `noExpiry`?: integer;
        `bound`?: integer
      })[]
    };
    `now`?: numeric;
    `context`?: NullableObject93;
    `overridable`?: ({`setting`?: string; `attribute`?: string})[]
  }

@component model `SamlAssertions` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: StringOrString;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `assertions`?: {
      `saml2LifetimeMin`?: numeric;
      `saml11LifetimeMin`?: numeric;
      `clockSkewS`?: numeric;
      `saml2WindowS`?: numeric;
      `saml11WindowS`?: numeric
    };
    `perApplication`?: ({`setting`?: string; `attribute`?: string; `profile`?: string})[];
    `settings`?: ({
      `key`?: string;
      `group`?: string;
      `label`?: string;
      `description`?: string;
      `type`?: string;
      `enumValues`?: (string)[];
      `csvValues`?: (string)[];
      `ordered`?: boolean;
      @js(#{`description`:"The sentence beside each value."}) `csvValueNotes`?: Record<string>;
      @js(#{`description`:"The rules by kind: onlyWhileOn and aloneWhileOn."}) `selectAll`?: Record<({
        `setting`?: string;
        `values`?: (string)[];
        `on`?: boolean;
        `canBeOn`?: boolean
      })[]>;
      `min`?: numeric;
      `max`?: numeric;
      `step`?: numeric;
      `value`?: BooleanOrNumericOrStringEtc;
      `text`?: NullableString;
      `source`?: string;
      `editable`?: boolean;
      `restartReason`?: string;
      `editRefusal`?: string;
      `env`?: NullableString;
      `legacyEnv`?: NullableString;
      `appconfigPath`?: string;
      `default`?: BooleanOrNumericOrStringEtc;
      `masked`?: boolean;
      `realmSettable`?: boolean;
      `overridden`?: boolean
    })[];
    `assertionsIssued`?: {
      `held`?: numeric;
      `forgotten`?: numeric;
      `cap`?: numeric;
      `byKind`?: ({
        `kind`?: string;
        `issued`?: numeric;
        `valid`?: numeric;
        `expired`?: numeric;
        `noExpiry`?: numeric
      })[]
    };
    `now`?: numeric;
    `context`?: NullableObject94;
    `rows`?: ({
      `key`?: string;
      `unit`?: string;
      `kind`?: NullableString;
      `profile`?: string;
      `field`?: string
    })[];
    @js(#{`description`:"Each setting in seconds, by key."}) `seconds`?: Record<NullableNumber>
  }

@component model `ClaimSets` {
    `reservedJwtClaims`?: (string)[];
    `placeholders`?: (string)[];
    `attributeCatalogue`?: ({
      `ldap`?: string;
      `claim`?: string;
      `label`?: NullableString;
      `schema`?: NullableString;
      @js(#{`description`:"Whether it is ticked, by claim set."}) `sets`?: Record<boolean>;
      `generated`?: boolean;
      `custom`?: boolean;
      `syntax`?: NullableString;
      `pacClaimId`?: string
    })[];
    `precedence`?: string;
    `sets`?: ({
      `id`?: string;
      `label`?: string;
      `claims`?: ({
        `name`?: string;
        `value`?: string;
        `attribute`?: string;
        `multi`?: boolean;
        `type`?: string;
        `nameFormat`?: string;
        `namespace`?: string;
        `claimId`?: string
      })[];
      `attributes`?: (string)[];
      @js(#{
        `x-free-form`:"The claims one person would be issued, keyed and nested by the claim names the catalogue and an administrator chose.",
        `description`:"The claims one person would be issued, keyed and nested by the claim names the catalogue and an administrator chose."
      }) `attributeClaims`?: unknown;
      `attributeReport`?: ({
        `ldap`?: string;
        `claim`?: string;
        @js(#{
          `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
          `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
        }) `value`?: unknown;
        `source`?: string;
        `ldpTerm`?: NullableString;
        `claimId`?: string;
        `values`?: (Shape5)[]
      })[];
      `attributeClaimPreview`?: ({
        `name`?: string;
        `attribute`?: string;
        `carried`?: boolean;
        @js(#{
          `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
          `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
        }) `value`?: unknown
      })[];
      @js(#{`description`:"Partners withholding it, by claim."}) `withheldFrom`?: Record<(string)[]>
    })[];
    `attributeChoices`?: ({`attribute`?: string; `from`?: (string)[]})[];
    `preview`?: {
      `user`?: string;
      @js(#{`description`:"By directory attribute."}) `byLdap`?: Record<{
        `ldap`?: string;
        `claim`?: string;
        @js(#{
          `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
          `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
        }) `value`?: unknown;
        `source`?: string;
        `ldpTerm`?: NullableString;
        `claimId`?: string;
        `values`?: (Shape5)[]
      }>;
      `entryFound`?: boolean
    };
    `groups`?: {
      `enabled`?: boolean;
      `loaded`?: boolean;
      `claim`?: NullableString;
      `valueForm`?: NullableString;
      `memberOfCounts`?: boolean;
      `sets`?: (string)[];
      `problem`?: string;
      `grants`?: string;
      `precedence`?: string;
      `settings`?: (string)[];
      `preview`?: {
        `user`?: string;
        `key`?: NullableString;
        `application`?: string;
        `enabled`?: boolean;
        `loaded`?: boolean;
        `claim`?: NullableString;
        `valueForm`?: NullableString;
        `memberOfCounts`?: boolean;
        `reason`?: string;
        `dn`?: NullableString;
        `entryFound`?: boolean;
        `groups`?: ({
          `cn`?: NullableString;
          `dn`?: string;
          `rule`?: NullableString;
          `via`?: (string)[];
          `viaMemberOf`?: boolean
        })[];
        `values`?: (string)[]
      }
    };
    `withholding`?: ({`id`?: string; `names`?: (string)[]})[]
  }

@component model `KerberosPacClaims` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: StringOrString;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `enabled`?: boolean;
    `setting`?: string;
    `types`?: (string)[];
    `placeholders`?: (string)[];
    `idFormat`?: string;
    `precedence`?: string;
    `sets`?: ({
      `id`?: string;
      `label`?: string;
      `claims`?: ({
        `name`?: string;
        `value`?: string;
        `attribute`?: string;
        `multi`?: boolean;
        `type`?: string;
        `nameFormat`?: string;
        `namespace`?: string;
        `claimId`?: string
      })[];
      `attributes`?: (string)[]
    })[];
    `attributeCatalogue`?: ({
      `ldap`?: string;
      `claim`?: string;
      `label`?: NullableString;
      `schema`?: NullableString;
      @js(#{`description`:"Whether it is ticked, by claim set."}) `sets`?: Record<boolean>;
      `generated`?: boolean;
      `custom`?: boolean;
      `syntax`?: NullableString;
      `pacClaimId`?: string
    })[];
    `attributeChoices`?: ({`attribute`?: string; `from`?: (string)[]})[];
    `preview`?: {
      `user`?: string;
      `entryFound`?: boolean;
      @js(#{`description`:"By directory attribute."}) `byLdap`?: Record<{
        `ldap`?: string;
        `claim`?: string;
        @js(#{
          `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
          `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
        }) `value`?: unknown;
        `source`?: string;
        `ldpTerm`?: NullableString;
        `claimId`?: string;
        `values`?: (Shape5)[]
      }>;
      `claims`?: ({
        `name`?: string;
        `id`?: string;
        `type`?: string;
        `values`?: (Shape5)[];
        `from`?: string;
        `dropped`?: boolean
      })[]
    }
  }

@component model `UserInfoClaimSets` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: StringOrString;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `reservedJwtClaims`?: (string)[];
    `claimsRequest`?: {
      `supported`?: boolean;
      `members`?: (string)[];
      `maxClaims`?: numeric;
      `requestable`?: ({
        `claim`?: string;
        `ldap`?: string;
        `label`?: NullableString;
        `grouped`?: boolean
      })[];
      `fromTheSignIn`?: (string)[];
      `precedence`?: (string)[];
      `notEnforced`?: (string)[];
      `directParameter`?: {
        `note`?: string;
        `spellings`?: (string)[];
        `malformedIsRefused`?: string
      };
      `preview`?: {
        `asked`?: boolean;
        `ok`?: boolean;
        `error`?: string;
        `request`?: string;
        @js(#{
          `x-free-form`:"The claims request as a caller typed it, parsed: OIDC Core 5.5 keys it by the claims they ask for.",
          `description`:"The claims request as a caller typed it, parsed: OIDC Core 5.5 keys it by the claims they ask for."
        }) `parsed`?: unknown;
        `ignoredMembers`?: (string)[];
        `idTokenNames`?: (string)[];
        @js(#{
          `x-free-form`:"The claims one person would be issued for that request, keyed by the names it asked for.",
          `description`:"The claims one person would be issued for that request, keyed by the names it asked for."
        }) `claims`?: unknown;
        `report`?: ({
          `requested`?: string;
          `claim`?: string;
          `ldap`?: string;
          @js(#{
            `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
            `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
          }) `value`?: unknown;
          `source`?: string
        })[];
        `unresolvable`?: (string)[];
        `essentialAndAbsent`?: (string)[];
        `valueMismatches`?: (string)[];
        `entryFound`?: boolean
      }
    };
    `request`?: string;
    `inventedEmail`?: NullableString;
    `placeholders`?: (string)[];
    `attributeCatalogue`?: ({
      `ldap`?: string;
      `claim`?: string;
      `label`?: NullableString;
      `schema`?: NullableString;
      @js(#{`description`:"Whether it is ticked, by claim set."}) `sets`?: Record<boolean>;
      `generated`?: boolean;
      `custom`?: boolean;
      `syntax`?: NullableString;
      `pacClaimId`?: string
    })[];
    `precedence`?: string;
    `sets`?: ({
      `id`?: string;
      `label`?: string;
      `claims`?: ({
        `name`?: string;
        `value`?: string;
        `attribute`?: string;
        `multi`?: boolean;
        `type`?: string;
        `nameFormat`?: string;
        `namespace`?: string;
        `claimId`?: string
      })[];
      `attributes`?: (string)[];
      @js(#{
        `x-free-form`:"The claims one person would be issued, keyed and nested by the claim names the catalogue and an administrator chose.",
        `description`:"The claims one person would be issued, keyed and nested by the claim names the catalogue and an administrator chose."
      }) `attributeClaims`?: unknown;
      `attributeReport`?: ({
        `ldap`?: string;
        `claim`?: string;
        @js(#{
          `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
          `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
        }) `value`?: unknown;
        `source`?: string;
        `ldpTerm`?: NullableString;
        `claimId`?: string;
        `values`?: (Shape5)[]
      })[];
      `attributeClaimPreview`?: ({
        `name`?: string;
        `attribute`?: string;
        `carried`?: boolean;
        @js(#{
          `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
          `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
        }) `value`?: unknown
      })[];
      @js(#{`description`:"Partners withholding it, by claim."}) `withheldFrom`?: Record<(string)[]>
    })[];
    `attributeChoices`?: ({`attribute`?: string; `from`?: (string)[]})[];
    `preview`?: {
      `user`?: string;
      @js(#{`description`:"By directory attribute."}) `byLdap`?: Record<{
        `ldap`?: string;
        `claim`?: string;
        @js(#{
          `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
          `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
        }) `value`?: unknown;
        `source`?: string;
        `ldpTerm`?: NullableString;
        `claimId`?: string;
        `values`?: (Shape5)[]
      }>;
      `entryFound`?: boolean
    };
    `groups`?: {
      `enabled`?: boolean;
      `loaded`?: boolean;
      `claim`?: NullableString;
      `valueForm`?: NullableString;
      `memberOfCounts`?: boolean;
      `sets`?: (string)[];
      `problem`?: string;
      `grants`?: string;
      `precedence`?: string;
      `settings`?: (string)[];
      `preview`?: {
        `user`?: string;
        `key`?: NullableString;
        `application`?: string;
        `enabled`?: boolean;
        `loaded`?: boolean;
        `claim`?: NullableString;
        `valueForm`?: NullableString;
        `memberOfCounts`?: boolean;
        `reason`?: string;
        `dn`?: NullableString;
        `entryFound`?: boolean;
        `groups`?: ({
          `cn`?: NullableString;
          `dn`?: string;
          `rule`?: NullableString;
          `via`?: (string)[];
          `viaMemberOf`?: boolean
        })[];
        `values`?: (string)[]
      }
    };
    `withholding`?: ({`id`?: string; `names`?: (string)[]})[]
  }

@component model `SamlAttributeSets` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: StringOrString;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `defaultSaml11Namespace`?: string;
    `placeholders`?: (string)[];
    `attributeCatalogue`?: ({
      `ldap`?: string;
      `claim`?: string;
      `label`?: NullableString;
      `schema`?: NullableString;
      @js(#{`description`:"Whether it is ticked, by claim set."}) `sets`?: Record<boolean>;
      `generated`?: boolean;
      `custom`?: boolean;
      `syntax`?: NullableString;
      `pacClaimId`?: string
    })[];
    `precedence`?: string;
    `sets`?: ({
      `id`?: string;
      `label`?: string;
      `claims`?: ({
        `name`?: string;
        `value`?: string;
        `attribute`?: string;
        `multi`?: boolean;
        `type`?: string;
        `nameFormat`?: string;
        `namespace`?: string;
        `claimId`?: string
      })[];
      `attributes`?: (string)[];
      @js(#{
        `x-free-form`:"The claims one person would be issued, keyed and nested by the claim names the catalogue and an administrator chose.",
        `description`:"The claims one person would be issued, keyed and nested by the claim names the catalogue and an administrator chose."
      }) `attributeClaims`?: unknown;
      `attributeReport`?: ({
        `ldap`?: string;
        `claim`?: string;
        @js(#{
          `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
          `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
        }) `value`?: unknown;
        `source`?: string;
        `ldpTerm`?: NullableString;
        `claimId`?: string;
        `values`?: (Shape5)[]
      })[];
      `attributeClaimPreview`?: ({
        `name`?: string;
        `attribute`?: string;
        `carried`?: boolean;
        @js(#{
          `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
          `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
        }) `value`?: unknown
      })[];
      @js(#{`description`:"Partners withholding it, by claim."}) `withheldFrom`?: Record<(string)[]>
    })[];
    `attributeChoices`?: ({`attribute`?: string; `from`?: (string)[]})[];
    `preview`?: {
      `user`?: string;
      @js(#{`description`:"By directory attribute."}) `byLdap`?: Record<{
        `ldap`?: string;
        `claim`?: string;
        @js(#{
          `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
          `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
        }) `value`?: unknown;
        `source`?: string;
        `ldpTerm`?: NullableString;
        `claimId`?: string;
        `values`?: (Shape5)[]
      }>;
      `entryFound`?: boolean
    };
    `groups`?: {
      `enabled`?: boolean;
      `loaded`?: boolean;
      `claim`?: NullableString;
      `valueForm`?: NullableString;
      `memberOfCounts`?: boolean;
      `sets`?: (string)[];
      `problem`?: string;
      `grants`?: string;
      `precedence`?: string;
      `settings`?: (string)[];
      `preview`?: {
        `user`?: string;
        `key`?: NullableString;
        `application`?: string;
        `enabled`?: boolean;
        `loaded`?: boolean;
        `claim`?: NullableString;
        `valueForm`?: NullableString;
        `memberOfCounts`?: boolean;
        `reason`?: string;
        `dn`?: NullableString;
        `entryFound`?: boolean;
        `groups`?: ({
          `cn`?: NullableString;
          `dn`?: string;
          `rule`?: NullableString;
          `via`?: (string)[];
          `viaMemberOf`?: boolean
        })[];
        `values`?: (string)[]
      }
    };
    `withholding`?: ({`id`?: string; `names`?: (string)[]})[]
  }

  

@component model `CredentialClaims` {
    `selected`?: (string)[];
    `defaults`?: (string)[];
    `ldpOmitted`?: (string)[];
    `attributes`?: ({
      `ldap`?: string;
      `claim`?: string;
      `label`?: string;
      `schema`?: string;
      `ldpTerm`?: string;
      `selected`?: boolean;
      `example`?: {
        `value`?: StringOrNumericOrBooleanEtc4;
        `source`?: string
      }
    })[];
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: StringOrString;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `preview`?: {
      `user`?: string;
      `claims`?: {
        @js(#{`description`:"The credential subject's claims."}) `claims`?: Record<StringOrNumericOrBooleanEtc4OrListOfRecordStringOrNumericOrBooleanEtc4>;
        `report`?: ({
          `ldap`?: string;
          `claim`?: string;
          `value`?: StringOrNumericOrBooleanEtc4;
          `source`?: string;
          `ldpTerm`?: NullableString
        })[];
        `entryFound`?: boolean
      }
    }
  }

@component model `VerifierRequest` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: StringOrString;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `requested`?: (string)[];
    `defaults`?: (string)[];
    `format`?: string;
    `formats`?: ({
      `id`?: string;
      `label`?: string;
      `identifiedBy`?: string;
      `identifier`?: StringOrString;
      `selectiveDisclosure`?: string;
      `holderBinding`?: string;
      `configurations`?: (string)[];
      `identifierText`?: string;
      `what`?: string
    })[];
    `ldpOmitted`?: (string)[];
    `catalogue`?: ({
      `claim`?: string;
      `label`?: string;
      `nested`?: boolean;
      `attributes`?: ({`ldap`?: string; `schema`?: string})[];
      `ldpTerms`?: (string)[];
      `paths`?: ((string)[])[];
      `requested`?: boolean;
      `issued`?: {`known`?: boolean; `carried`?: (string)[]; `missing`?: (string)[]}
    })[];
    `dcqlQuery`?: {
      `credentials`?: ({
        `id`?: string;
        `format`?: string;
        `meta`?: {
          `vct_values`?: (string)[];
          `doctype_value`?: string;
          `type_values`?: (StringOrString)[]
        };
        `require_cryptographic_holder_binding`?: boolean;
        `claims`?: ({`path`?: (string)[]})[]
      })[];
      `credential_sets`?: ({`options`?: ((string)[])[]; `required`?: boolean})[]
    };
    `extras`?: ({`claim`?: string; `paths`?: ((string)[])[]})[];
    `recentVerifications`?: {
      `verifications`?: ({
        `state`?: string;
        `format`?: string;
        `responseType`?: string;
        `responseMode`?: string;
        `byReference`?: boolean;
        `clientId`?: string;
        `requested`?: (string)[];
        `expiresAt`?: string;
        `received`?: boolean;
        `ok`?: NullableBoolean;
        `decidedAt`?: NullableString;
        `claims`?: (string)[];
        `failedChecks`?: (string)[];
        `error`?: string
      })[];
      `total`?: integer;
      `limit`?: integer
    };
    `startChoices`?: {
      `format`?: (string)[];
      `by`?: (string)[];
      `mode`?: (string)[];
      `response_type`?: (string)[];
      `response_mode`?: (string)[];
      `client_id_prefix`?: (string)[]
    }
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
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: (string)[];
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean;
      `listening`?: boolean
    })[]
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
    `policies`?: ({
      `name`?: string;
      `policyId`?: NullableString;
      `kind`?: string;
      `version`?: string;
      `enabled`?: boolean;
      `isRoot`?: boolean;
      `combiningAlgId`?: string;
      `description`?: string;
      `application`?: NullableString;
      `orphanedAt`?: NullableString;
      `problems`?: (string)[]
    })[];
    `applicationPolicies`?: ({
      `application`?: string;
      `known`?: boolean;
      `enforced`?: boolean;
      `policies`?: ({
        `name`?: string;
        `policyId`?: NullableString;
        `version`?: string;
        `enabled`?: boolean;
        `orphanedAt`?: NullableString;
        `referenced`?: boolean
      })[]
    })[];
    `templates`?: ({
      `id`?: string;
      `label`?: string;
      `blurb`?: string;
      `what`?: string;
      `parameters`?: ({
        `name`?: string;
        `label`?: string;
        `help`?: NullableString;
        `type`?: string;
        `dflt`?: StringOrNumericOrBooleanEtc
      })[]
    })[];
    `serviceOwn`?: ({
      `key`?: string;
      `label`?: string;
      `decides`?: string;
      `asked`?: string;
      `remote`?: boolean;
      `name`?: string;
      `ok`?: boolean;
      `builtIn`?: boolean;
      `why`?: string;
      `setting`?: string;
      `template`?: string;
      `entry`?: boolean;
      `enabled`?: NullableBoolean;
      `effect`?: string;
      `readsRisk`?: boolean
    })[];
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: (string)[];
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean;
      `listening`?: boolean
    })[]
  }

@component model `XacmlEditor` {
    `xacml`?: boolean;
    `message`?: string;
    `policies`?: (string)[];
    `serviceOwn`?: ({
      `key`?: string;
      `label`?: string;
      `decides`?: string;
      `asked`?: string;
      `remote`?: boolean;
      `name`?: string;
      `ok`?: boolean;
      `builtIn`?: boolean;
      `why`?: string;
      `setting`?: string;
      `template`?: string;
      `entry`?: boolean;
      `enabled`?: NullableBoolean;
      `effect`?: string;
      `readsRisk`?: boolean
    })[];
    `policy`?: NullableObject96;
    `problem`?: NullableString;
    `tree`?: ({
      `path`?: string;
      `depth`?: integer;
      `kind`?: string;
      `label`?: string;
      `detail`?: string;
      `options`?: {
        `kind`?: string;
        `removable`?: boolean;
        `additions`?: ({`action`?: string; `label`?: string; `help`?: string})[]
      };
      `edit`?: NullableObject97
    })[];
    `menus`?: NullableObject98;
    `problems`?: (NullableString)[];
    `xpathVersionGaps`?: (NullableString)[];
    `document`?: string;
    `alfa`?: NullableString;
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: (string)[];
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean;
      `listening`?: boolean
    })[]
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
    `enforcement`?: {
      `allowed`?: boolean;
      `bias`?: string;
      `why`?: NullableString
    };
    `enforcements`?: ({
      `allowed`?: boolean;
      `bias`?: string;
      `why`?: NullableString
    })[];
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: (string)[];
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean;
      `listening`?: boolean
    })[]
  }

@component model `GnapServer` {
    `page`?: string;
    `title`?: string;
    `enabled`?: boolean;
    `specifications`?: (string)[];
    `endpoints`?: {
      `grant`?: string;
      `discovery`?: string;
      `rsDiscovery`?: string;
      `continuation`?: string;
      `tokenManagement`?: string;
      `introspection`?: string;
      `resourceRegistration`?: string;
      `userCode`?: string;
      `keys`?: string;
      `zcapController`?: string;
      `accessTokenStatusList`?: string;
      `biscuitRevocations`?: string
    };
    `capabilities`?: {
      `grant_request_endpoint`?: string;
      `interaction_start_modes_supported`?: StringOrStringOrBooleanEtc;
      `interaction_finish_methods_supported`?: StringOrStringOrBooleanEtc;
      `key_proofs_supported`?: StringOrStringOrBooleanEtc;
      `sub_id_formats_supported`?: StringOrStringOrBooleanEtc;
      `assertion_formats_supported`?: StringOrStringOrBooleanEtc;
      `key_rotation_supported`?: StringOrStringOrBooleanEtc;
      `token_formats_supported`?: StringOrStringOrBooleanEtc
    };
    `authorizationServers`?: ({
      `id`?: string;
      `label`?: string;
      `capabilities`?: {
        `grant_request_endpoint`?: string;
        `interaction_start_modes_supported`?: StringOrStringOrBooleanEtc;
        `interaction_finish_methods_supported`?: StringOrStringOrBooleanEtc;
        `key_proofs_supported`?: StringOrStringOrBooleanEtc;
        `sub_id_formats_supported`?: StringOrStringOrBooleanEtc;
        `assertion_formats_supported`?: StringOrStringOrBooleanEtc;
        `key_rotation_supported`?: StringOrStringOrBooleanEtc;
        `token_formats_supported`?: StringOrStringOrBooleanEtc
      }
    })[];
    `authorizationServersPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `tokenFormats`?: (string)[];
    `verificationMaterial`?: {
      `jwt`?: {
        `jwks_uri`?: string;
        `alg`?: string;
        `kid`?: string;
        `typ`?: string;
        `status_list_aggregation_endpoint`?: string
      };
      `biscuit`?: {
        `algorithm`?: string;
        `root_public_key`?: string;
        `revocation_endpoint`?: string;
        `jwk`?: {
          `kty`?: string;
          `use`?: string;
          `alg`?: string;
          `kid`?: string;
          `key_ops`?: (string)[];
          `ext`?: boolean;
          `crv`?: string;
          `x`?: string;
          `y`?: string;
          `n`?: string;
          `e`?: string;
          `pub`?: string;
          `ek`?: string;
          `x5c`?: (string)[];
          `x5t`?: string;
          `x5t#S256`?: string;
          `x5u`?: string
        };
        `root_public_keys`?: (string)[]
      };
      `zcap`?: {`controller`?: string; `cryptosuite`?: string};
      `macaroon`?: {`root_key`?: string};
      `jwt-encrypted`?: {`authorization_server`?: string; `resource_server`?: string}
    };
    `grants`?: {
      `state`?: NullableString;
      `states`?: (string)[];
      `paging`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      };
      `rows`?: ({
        `id`?: string;
        `state`?: string;
        `authorizationServer`?: NullableString;
        `grantEndpoint`?: NullableString;
        `client`?: NullableString;
        `proof`?: NullableString;
        `resourceOwner`?: NullableString;
        `decision`?: NullableString;
        `interaction`?: NullableObject100;
        `tokens`?: integer;
        `derivedFrom`?: NullableString;
        `createdAt`?: NullOrStringOrNumeric;
        `updatedAt`?: NullOrStringOrNumeric;
        `finalization`?: NullableObject101;
        `grantExpiresAt`?: NullOrStringOrNumeric;
        `history`?: ({
          `at`?: NullOrStringOrNumeric;
          `state`?: string;
          `note`?: NullableString
        })[]
      })[]
    };
    `resourceSets`?: {
      `paging`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      };
      `rows`?: ({
        `reference`?: string;
        `resourceServer`?: string;
        `access`?: (Shape6)[];
        `tokenFormats`?: NullableArray;
        `introspectionRequired`?: boolean;
        `createdAt`?: NullOrStringOrNumeric
      })[]
    };
    `actions`?: (string)[];
    `settings`?: NullableObject61
  }

@component model `GnapMonitor` {
    `page`?: string;
    `title`?: string;
    `since`?: NullOrStringOrNumeric;
    `events`?: ({`event`?: string; `counter`?: string; `label`?: string})[];
    `totals`?: Record<numeric>;
    `tokensByFormat`?: Record<numeric>;
    `applications`?: integer;
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    `rows`?: ({
      `identifier`?: string;
      `name`?: NullableString;
      `kinds`?: (string)[];
      `role`?: string;
      `registered`?: boolean;
      `finishUris`?: (string)[];
      `webApplication`?: boolean;
      `grantsHeld`?: {
        `total`?: integer;
        `pending`?: integer;
        `approved`?: integer;
        `finalized`?: integer
      };
      `activeTokens`?: integer;
      `counters`?: Record<NumericOrStringOrNullEtc>;
      `lastAt`?: NullOrStringOrNumeric;
      `lastEvent`?: NullableString
    })[]
  }

@component model `XacmlMonitor` {
    `xacml`?: boolean;
    `message`?: string;
    `policies`?: {
      `total`?: integer;
      `enabled`?: integer;
      `root`?: NullableString
    };
    `peps`?: {`embedded`?: integer; `remote`?: integer; `total`?: integer};
    `decisions`?: {
      `here`?: {
        `decisions`?: integer;
        `allowed`?: integer;
        `refused`?: integer;
        `unenforced`?: integer;
        `undischargeable`?: integer
      };
      `remote`?: {
        `decisions`?: integer;
        `allowed`?: integer;
        `refused`?: integer;
        `unenforced`?: integer;
        `undischargeable`?: integer
      };
      `combined`?: {
        `decisions`?: integer;
        `allowed`?: integer;
        `refused`?: integer;
        `unenforced`?: integer;
        `undischargeable`?: integer
      }
    };
    `since`?: string;
    `enabled`?: boolean;
    `remotePepsEnabled`?: boolean;
    `realm`?: {`id`?: string; `name`?: NullableString};
    `rows`?: ({
      `id`?: string;
      `label`?: string;
      `kind`?: string;
      `where`?: string;
      `module`?: string;
      `guards`?: string;
      `enforces`?: boolean;
      `bias`?: NullableString;
      `dischargesObligations`?: boolean;
      `decisions`?: integer;
      `allowed`?: NullableInteger;
      `refused`?: NullableInteger;
      `permit`?: NullableInteger;
      `deny`?: NullableInteger;
      `notApplicable`?: NullableInteger;
      `indeterminate`?: NullableInteger;
      `other`?: NullableInteger;
      `undischargeable`?: integer;
      `lastAt`?: StringOrNumericOrNull;
      `lastDecision`?: NullableString;
      `lastAllowed`?: NullableBoolean;
      `remote`?: {
        `authenticated`?: boolean;
        `certificateSubject`?: string;
        `current`?: boolean;
        `stale`?: boolean;
        `enabled`?: boolean;
        `registeredAt`?: NullableString;
        `lastSeen`?: NullableString;
        `syncToken`?: string;
        `policyCount`?: NullableInteger;
        `version`?: string;
        `lastNotify`?: string
      }
    })[];
    `remoteRows`?: ({
      `id`?: string;
      `label`?: string;
      `kind`?: string;
      `where`?: string;
      `module`?: string;
      `guards`?: string;
      `enforces`?: boolean;
      `bias`?: NullableString;
      `dischargesObligations`?: boolean;
      `decisions`?: integer;
      `allowed`?: NullableInteger;
      `refused`?: NullableInteger;
      `permit`?: NullableInteger;
      `deny`?: NullableInteger;
      `notApplicable`?: NullableInteger;
      `indeterminate`?: NullableInteger;
      `other`?: NullableInteger;
      `undischargeable`?: integer;
      `lastAt`?: StringOrNumericOrNull;
      `lastDecision`?: NullableString;
      `lastAllowed`?: NullableBoolean;
      `remote`?: {
        `authenticated`?: boolean;
        `certificateSubject`?: string;
        `current`?: boolean;
        `stale`?: boolean;
        `enabled`?: boolean;
        `registeredAt`?: NullableString;
        `lastSeen`?: NullableString;
        `syncToken`?: string;
        `policyCount`?: NullableInteger;
        `version`?: string;
        `lastNotify`?: string
      }
    })[];
    `elsewhere`?: ({
      `id`?: string;
      `name`?: NullableString;
      `count`?: integer
    })[];
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: (string)[];
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean;
      `listening`?: boolean
    })[]
  }

@component model `XacmlPeps` {
    `xacml`?: boolean;
    `message`?: string;
    `enabled`?: boolean;
    `syncToken`?: NullableString;
    `staleAfterS`?: numeric;
    `requiresCertificate`?: boolean;
    `notify`?: {
      `on`?: boolean;
      `allowedHosts`?: (string)[];
      `timeoutMs`?: numeric;
      `transport`?: {
        `allowHttp`?: boolean;
        `skipTlsVerificationSet`?: boolean;
        `skipTlsVerification`?: boolean;
        `caFile`?: string
      }
    };
    `peps`?: ({
      `name`?: string;
      `dn`?: string;
      `identity`?: string;
      `certificateSubject`?: string;
      `thumbprint`?: string;
      `authenticated`?: boolean;
      `notifyUrl`?: string;
      `bias`?: string;
      `resource`?: string;
      `description`?: string;
      `version`?: string;
      `enabled`?: boolean;
      `registeredAt`?: string;
      `lastSeen`?: string;
      `syncToken`?: string;
      `policyCount`?: NullableNumber;
      `decisions`?: NullableNumber;
      `allowed`?: NullableNumber;
      `refused`?: NullableNumber;
      `undischargeable`?: NullableNumber;
      `lastNotify`?: string;
      `current`?: boolean;
      `stale`?: boolean;
      `notifyProblem`?: NullableString;
      `listenerCertificate`?: NullableObject102
    })[];
    `elsewhere`?: ({
      `id`?: string;
      `name`?: NullableString;
      `count`?: integer
    })[];
    `listenerCertificates`?: {
      `useCase`?: string;
      `keyAlgorithms`?: (string)[];
      `defaultKeyAlg`?: string
    };
    `current`?: integer;
    `stale`?: integer;
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: (string)[];
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean;
      `listening`?: boolean
    })[]
  }

@component model `Ssf` {
    `installed`?: boolean;
    `enabled`?: boolean;
    `issuer`?: string;
    `metadataUrl`?: string;
    `metadata`?: {
      `spec_version`?: string;
      `issuer`?: string;
      `jwks_uri`?: string;
      `delivery_methods_supported`?: (string)[];
      `configuration_endpoint`?: string;
      `status_endpoint`?: string;
      `add_subject_endpoint`?: string;
      `remove_subject_endpoint`?: string;
      `verification_endpoint`?: string;
      `default_subjects`?: string;
      `authorization_schemes`?: ({`spec_urn`?: string})[];
      `critical_subject_members`?: (string)[]
    };
    `signingAlgorithm`?: string;
    `delivery`?: ({
      `method`?: string;
      `name`?: string;
      `what`?: string;
      `offered`?: boolean
    })[];
    `push`?: {
      `allowed`?: boolean;
      `transport`?: {
        `allowHttp`?: boolean;
        `skipTlsVerificationSet`?: boolean;
        `skipTlsVerification`?: boolean;
        `caFile`?: string
      };
      `allowedHosts`?: (string)[];
      `retries`?: numeric;
      `maxResponseBytes`?: numeric;
      `note`?: string
    };
    `eventTypes`?: ({
      `uri`?: string;
      `name`?: string;
      `short`?: string;
      `family`?: string;
      `subject`?: BooleanOrStringOrNull;
      `what`?: string;
      `offered`?: boolean;
      `members`?: ({
        `name`?: string;
        `required`?: BooleanOrStringOrNull;
        `what`?: string;
        `type`?: NullableString;
        `values`?: (string)[]
      })[];
      `required`?: (string)[];
      `subjectFormats`?: (string)[];
      `deprecated`?: string
    })[];
    `subjectFormats`?: ({
      `format`?: string;
      `members`?: (string)[];
      `what`?: string;
      `example`?: {
        `format`?: string;
        `uri`?: string;
        `email`?: string;
        `iss`?: string;
        `sub`?: string;
        `id`?: string;
        `phone_number`?: string;
        `url`?: string;
        `jti`?: string;
        `issuer`?: string;
        `assertion_id`?: string;
        `ip-addresses`?: (string)[];
        `identifiers`?: ({`format`?: string; `email`?: string; `phone_number`?: string})[]
      }
    })[];
    `complexSubjectMembers`?: ({`name`?: string; `what`?: string})[];
    `criticalSubjectMembers`?: (string)[];
    `authentication`?: {
      `required`?: boolean;
      `realm`?: string;
      `scopes`?: {
        `read`?: string;
        `write`?: string;
        `readAlso`?: (string)[];
        `writeAlso`?: (string)[];
        `writeIncludesRead`?: boolean
      };
      `refusedPassword`?: string;
      `metadataIsOpen`?: boolean;
      `passwordVerified`?: boolean;
      `schemes`?: ({
        `id`?: string;
        `name`?: string;
        `spec_urn`?: string;
        `what`?: string;
        `offered`?: boolean
      })[];
      `note`?: string
    };
    `streams`?: ({
      `stream_id`?: string;
      `status`?: string;
      `delivery`?: string;
      `events_delivered`?: (string)[];
      `subjects`?: integer;
      `queued`?: integer;
      `counters`?: Record<numeric>;
      `createdAt`?: NullOrStringOrNumeric;
      `lastPushError`?: NullableString
    })[];
    `endpoints`?: ({`method`?: string; `path`?: string; `what`?: string})[];
    `reachableNegatives`?: ({`what`?: string; `answer`?: string})[];
    `doesNotDo`?: (string)[];
    `streamDetail`?: ({
      `stream_id`?: string;
      `iss`?: NullableString;
      `aud`?: NullOrStringOrString;
      `status`?: string;
      `statusReason`?: NullableString;
      `delivery`?: {
        `method`?: string;
        `endpoint_url`?: NullableString
      };
      `events_delivered`?: (string)[];
      `events_requested`?: (string)[];
      `format`?: NullableString;
      `description`?: NullableString;
      `createdAt`?: NullOrStringOrNumeric;
      `updatedAt`?: NullOrStringOrNumeric;
      `createdBy`?: NullableString;
      `internal`?: boolean;
      `counters`?: Record<numeric>;
      `lastPushError`?: NullableString;
      `lastPushAt`?: NullOrStringOrNumeric;
      `subjects`?: ({
        `text`?: string;
        `verified`?: NullableBoolean;
        `addedAt`?: NullOrStringOrNumeric;
        @js(#{
          `x-free-form`:"An RFC 9493 subject identifier, as a stream was given it or a person named it: the format decides the members, an `aliases` nests, and SSF 1.0 section 3.3 lets a receiver add its own.",
          `description`:"An RFC 9493 subject identifier, as a stream was given it or a person named it: the format decides the members, an `aliases` nests, and SSF 1.0 section 3.3 lets a receiver add its own."
        }) `subject`?: unknown
      })[];
      `queue`?: ({
        `jti`?: string;
        `queuedAt`?: NullOrStringOrNumeric;
        `deliveredAt`?: NullOrStringOrNumeric;
        `summary`?: NullableObject103
      })[];
      `dead`?: boolean;
      `deadSince`?: string;
      `deadReason`?: string;
      `failingSince`?: string;
      `nextProbeAt`?: string;
      `deadLetters`?: ({
        `jti`?: string;
        `queuedAt`?: NullOrStringOrNumeric;
        `deadAt`?: NullOrStringOrNumeric;
        `reason`?: NullableString;
        `errorCode`?: NullableString;
        `status`?: NullableInteger;
        `signed`?: boolean;
        `summary`?: NullableObject103
      })[];
      `log`?: ({`at`?: string; `kind`?: string; `text`?: string})[]
    })[];
    `deadLetters`?: {
      `retentionS`?: numeric;
      `maxPerStream`?: numeric;
      `deadStreamTimeoutS`?: numeric;
      `pushes`?: {
        `active`?: integer;
        `waiting`?: integer;
        `concurrency`?: numeric;
        `backlog`?: numeric
      }
    };
    `settings`?: NullableObject61;
    `statuses`?: (string)[];
    `streamTotals`?: {
      `streams`?: integer;
      `enabled`?: integer;
      `delivered`?: numeric;
      `failed`?: numeric;
      `waiting`?: integer;
      `dead`?: integer;
      `deadLetters`?: integer
    };
    `streamFilter`?: NullableString;
    `paging`?: {
      `streams`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      }
    };
    `note`?: string;
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: StringOrString;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean;
      `listening`?: boolean
    })[]
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
    `eventTypes`?: ({
      `uri`?: string;
      `name`?: string;
      `short`?: string;
      `family`?: string;
      `subject`?: BooleanOrStringOrNull;
      `what`?: string;
      `offered`?: boolean;
      `members`?: ({
        `name`?: string;
        `required`?: BooleanOrStringOrNull;
        `what`?: string;
        `type`?: NullableString;
        `values`?: (string)[]
      })[];
      `required`?: (string)[];
      `subjectFormats`?: (string)[];
      `deprecated`?: string
    })[];
    `totals`?: Record<numeric>;
    `sessions`?: ({
      `sessionId`?: string;
      `sub`?: NullableString;
      `username`?: NullableString;
      `iss`?: NullableString;
      `protocol`?: NullableString;
      `establishedAt`?: NullOrStringOrNumeric;
      `updatedAt`?: NullOrStringOrNumeric;
      `state`?: NullableString;
      `acr`?: NullableString;
      `amr`?: (string)[];
      `assurance`?: {`namespace`?: string; `level`?: string; `previousLevel`?: string};
      `compliance`?: NullableString;
      `risk`?: {`level`?: string; `previousLevel`?: string; `reason`?: string};
      @js(#{
        `x-free-form`:"The claims a `token-claims-change` event said changed: whichever a person configured or an emitter named.",
        `description`:"The claims a `token-claims-change` event said changed: whichever a person configured or an emitter named."
      }) `claims`?: unknown;
      `credentials`?: ({
        `at`?: string;
        `credentialType`?: string;
        `changeType`?: string;
        `friendlyName`?: string
      })[];
      `counts`?: Record<numeric>;
      `total`?: integer;
      `events`?: ({
        `jti`?: string;
        `uri`?: string;
        `name`?: string;
        `at`?: string;
        `streamId`?: string;
        `warnings`?: (string)[]
      })[];
      `streams`?: (string)[];
      `notes`?: (string)[];
      `subject`?: string
    })[];
    `tracked`?: integer;
    `cap`?: numeric;
    `issuer`?: string;
    `ssfEnabled`?: boolean;
    `applications`?: ({
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
    })[];
    `streams`?: ({
      `stream_id`?: string;
      `aud`?: NullOrStringOrString;
      `status`?: string;
      `delivery`?: string;
      `subjects`?: integer;
      `takes`?: (string)[]
    })[];
    `catalogue`?: ({
      `uri`?: string;
      `name`?: string;
      `short`?: string;
      `family`?: string;
      `subject`?: BooleanOrStringOrNull;
      `what`?: string;
      `offered`?: boolean;
      `members`?: ({
        `name`?: string;
        `required`?: BooleanOrStringOrNull;
        `what`?: string;
        `type`?: NullableString;
        `values`?: (string)[]
      })[];
      `required`?: (string)[];
      `subjectFormats`?: (string)[];
      `deprecated`?: string
    })[];
    `settings`?: NullableObject61;
    `filter`?: {
      `sessions`?: NullableString;
      `applications`?: NullableString
    };
    `paging`?: {
      `sessions`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      };
      `applications`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      };
      `streams`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      };
      `events`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      }
    };
    `shown`?: {
      `sessions`?: ({
        `sessionId`?: string;
        `sub`?: NullableString;
        `username`?: NullableString;
        `iss`?: NullableString;
        `protocol`?: NullableString;
        `establishedAt`?: NullOrStringOrNumeric;
        `updatedAt`?: NullOrStringOrNumeric;
        `state`?: NullableString;
        `acr`?: NullableString;
        `amr`?: (string)[];
        `assurance`?: {`namespace`?: string; `level`?: string; `previousLevel`?: string};
        `compliance`?: NullableString;
        `risk`?: {`level`?: string; `previousLevel`?: string; `reason`?: string};
        @js(#{
          `x-free-form`:"The claims a `token-claims-change` event said changed: whichever a person configured or an emitter named.",
          `description`:"The claims a `token-claims-change` event said changed: whichever a person configured or an emitter named."
        }) `claims`?: unknown;
        `credentials`?: ({
          `at`?: string;
          `credentialType`?: string;
          `changeType`?: string;
          `friendlyName`?: string
        })[];
        `counts`?: Record<numeric>;
        `total`?: integer;
        `events`?: ({
          `jti`?: string;
          `uri`?: string;
          `name`?: string;
          `at`?: string;
          `streamId`?: string;
          `warnings`?: (string)[]
        })[];
        `streams`?: (string)[];
        `notes`?: (string)[];
        `subject`?: string
      })[];
      `applications`?: ({
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
      })[];
      `streams`?: ({
        `stream_id`?: string;
        `aud`?: NullOrStringOrString;
        `status`?: string;
        `delivery`?: string;
        `subjects`?: integer;
        `takes`?: (string)[]
      })[]
    };
    `matched`?: {`sessions`?: integer; `applications`?: integer; `streams`?: integer};
    `streamCounts`?: {`total`?: integer; `taking`?: integer};
    `id`?: string;
    `session`?: NullableObject104;
    `events`?: ({
      `jti`?: string;
      `uri`?: string;
      `name`?: string;
      `at`?: string;
      `streamId`?: string;
      `warnings`?: (string)[]
    })[]
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
    `eventTypes`?: ({
      `uri`?: string;
      `name`?: string;
      `short`?: string;
      `family`?: string;
      `subject`?: BooleanOrStringOrNull;
      `what`?: string;
      `offered`?: boolean;
      `members`?: ({
        `name`?: string;
        `required`?: BooleanOrStringOrNull;
        `what`?: string;
        `type`?: NullableString;
        `values`?: (string)[]
      })[];
      `required`?: (string)[];
      `subjectFormats`?: (string)[];
      `deprecated`?: string
    })[];
    `optStates`?: (string)[];
    `lifecycleStates`?: (string)[];
    `totals`?: Record<numeric>;
    `accounts`?: ({
      `accountId`?: string;
      `sub`?: NullableString;
      `username`?: NullableString;
      `iss`?: NullableString;
      `dn`?: NullableString;
      `realm`?: NullableString;
      `email`?: NullableString;
      `phone`?: NullableString;
      `formerIdentifiers`?: (string)[];
      `createdAt`?: NullOrStringOrNumeric;
      `updatedAt`?: NullOrStringOrNumeric;
      `lifecycle`?: NullableString;
      `kind`?: string;
      `application`?: string;
      `serviceAccount`?: boolean;
      `optOut`?: NullableString;
      `optOutApplies`?: boolean;
      `credentialStanding`?: NullableString;
      `credentialChangeRequired`?: boolean;
      `recoveryActivated`?: boolean;
      `identifierChanges`?: ({`at`?: string; `from`?: string; `to`?: string})[];
      `credentials`?: ({`at`?: string; `credentialType`?: string; `discoveredAt`?: numeric})[];
      `counts`?: Record<numeric>;
      `total`?: integer;
      `suppressed`?: integer;
      `events`?: ({
        `jti`?: string;
        `uri`?: string;
        `name`?: string;
        `at`?: string;
        `streamId`?: string;
        `warnings`?: (string)[]
      })[];
      `streams`?: (string)[];
      `notes`?: (string)[];
      `subject`?: string
    })[];
    `tracked`?: integer;
    `cap`?: numeric;
    `issuer`?: string;
    `ssfEnabled`?: boolean;
    `applications`?: ({
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
    })[];
    `streams`?: ({
      `stream_id`?: string;
      `aud`?: NullOrStringOrString;
      `status`?: string;
      `delivery`?: string;
      `subjects`?: integer;
      `takes`?: (string)[]
    })[];
    `catalogue`?: ({
      `uri`?: string;
      `name`?: string;
      `short`?: string;
      `family`?: string;
      `subject`?: BooleanOrStringOrNull;
      `what`?: string;
      `offered`?: boolean;
      `members`?: ({
        `name`?: string;
        `required`?: BooleanOrStringOrNull;
        `what`?: string;
        `type`?: NullableString;
        `values`?: (string)[]
      })[];
      `required`?: (string)[];
      `subjectFormats`?: (string)[];
      `deprecated`?: string
    })[];
    `settings`?: NullableObject61;
    `filter`?: {
      `accounts`?: NullableString;
      `applications`?: NullableString
    };
    `paging`?: {
      `accounts`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      };
      `applications`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      };
      `streams`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      };
      `events`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      }
    };
    `shown`?: {
      `accounts`?: ({
        `accountId`?: string;
        `sub`?: NullableString;
        `username`?: NullableString;
        `iss`?: NullableString;
        `dn`?: NullableString;
        `realm`?: NullableString;
        `email`?: NullableString;
        `phone`?: NullableString;
        `formerIdentifiers`?: (string)[];
        `createdAt`?: NullOrStringOrNumeric;
        `updatedAt`?: NullOrStringOrNumeric;
        `lifecycle`?: NullableString;
        `kind`?: string;
        `application`?: string;
        `serviceAccount`?: boolean;
        `optOut`?: NullableString;
        `optOutApplies`?: boolean;
        `credentialStanding`?: NullableString;
        `credentialChangeRequired`?: boolean;
        `recoveryActivated`?: boolean;
        `identifierChanges`?: ({`at`?: string; `from`?: string; `to`?: string})[];
        `credentials`?: ({`at`?: string; `credentialType`?: string; `discoveredAt`?: numeric})[];
        `counts`?: Record<numeric>;
        `total`?: integer;
        `suppressed`?: integer;
        `events`?: ({
          `jti`?: string;
          `uri`?: string;
          `name`?: string;
          `at`?: string;
          `streamId`?: string;
          `warnings`?: (string)[]
        })[];
        `streams`?: (string)[];
        `notes`?: (string)[];
        `subject`?: string
      })[];
      `applications`?: ({
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
      })[];
      `streams`?: ({
        `stream_id`?: string;
        `aud`?: NullOrStringOrString;
        `status`?: string;
        `delivery`?: string;
        `subjects`?: integer;
        `takes`?: (string)[]
      })[]
    };
    `matched`?: {`accounts`?: integer; `applications`?: integer; `streams`?: integer};
    `streamCounts`?: {`total`?: integer; `taking`?: integer};
    `id`?: string;
    `account`?: NullableObject105;
    `events`?: ({
      `jti`?: string;
      `uri`?: string;
      `name`?: string;
      `at`?: string;
      `streamId`?: string;
      `warnings`?: (string)[]
    })[]
  }

@component model `Scim` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: StringOrString;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `installed`?: boolean;
    `enabled`?: boolean;
    `baseUrl`?: NullableString;
    `specifications`?: (string)[];
    `store`?: NullableObject106;
    `identifiers`?: NullableObject107;
    `authentication`?: NullableObject108;
    `endpoints`?: ({`method`?: string; `path`?: string; `what`?: string})[];
    `doesNotDo`?: (string)[];
    `reachableNegatives`?: ({`what`?: string; `answer`?: string})[];
    `mapping`?: {
      `user`?: ({
        `scim`?: string;
        `ldap`?: NullableString;
        `kind`?: NullableString;
        `type`?: NullableString;
        `parent`?: NullableString;
        `extension`?: boolean;
        `readOnly`?: boolean;
        `required`?: boolean;
        `schema`?: string;
        `note`?: string
      })[];
      `group`?: ({
        `scim`?: string;
        `ldap`?: NullableString;
        `kind`?: NullableString;
        `type`?: NullableString;
        `parent`?: NullableString;
        `extension`?: boolean;
        `readOnly`?: boolean;
        `required`?: boolean;
        `schema`?: string;
        `note`?: string
      })[]
    };
    `counters`?: {
      `total`?: numeric;
      `ok`?: numeric;
      `failed`?: numeric;
      `firstAt`?: NumericOrStringOrNull;
      `lastAt`?: NumericOrStringOrNull;
      `operations`?: ({
        `operation`?: string;
        `label`?: string;
        `method`?: string;
        `what`?: string;
        `count`?: numeric
      })[];
      `resourceTypes`?: ({
        `resourceType`?: NullableString;
        `count`?: numeric
      })[];
      @js(#{`description`:"A count per name."}) `byStatus`?: Record<numeric>;
      @js(#{`description`:"A count per name."}) `byScimType`?: Record<numeric>;
      @js(#{`description`:"A count per name."}) `byAuthScheme`?: Record<numeric>
    };
    `settings`?: NullableObject109;
    `scimClients`?: NullableObject110
  }

@component model `Signals` {
    `status`?: NullableObject111;
    `received`?: ({
      `jti`?: string;
      `at`?: NullOrStringOrNumeric;
      `tokenDigest`?: string;
      `surface`?: NullableString;
      `stream`?: NullableString;
      `name`?: string;
      `types`?: (string)[];
      `vocabulary`?: string;
      `issuer`?: string;
      `audience`?: string;
      `audienceOk`?: boolean;
      `subject`?: string;
      @js(#{
        `x-free-form`:"An event's body as this receiver took it in: each event type has its own members, and a refused delivery is held here too.",
        `description`:"An event's body as this receiver took it in: each event type has its own members, and a refused delivery is held here too."
      }) `payload`?: unknown;
      `verified`?: boolean;
      `verificationNote`?: NullableString;
      `reactions`?: ({
        `event`?: string;
        `reaction`?: string;
        `skipped`?: string;
        `observed`?: boolean;
        `ended`?: integer;
        `revoked`?: integer;
        `failed`?: boolean
      })[];
      `contentType`?: NullableString;
      `correctMediaType`?: boolean;
      `problem`?: string
    })[];
    `total`?: integer;
    `filter`?: {`received`?: NullableString};
    `paging`?: {
      `received`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      }
    }
  }

@component model `SsfDeadLetters` {
    `installed`?: boolean;
    `enabled`?: boolean;
    `note`?: string;
    `realm`?: string;
    `generatedAt`?: string;
    `pushDelivery`?: boolean;
    `causes`?: ({
      `id`?: string;
      `label`?: string;
      `code`?: string;
      `what`?: string;
      `count`?: integer
    })[];
    `totals`?: {
      `held`?: integer;
      `streamsHolding`?: integer;
      `signed`?: integer;
      `unsigned`?: integer;
      `deadStreams`?: integer;
      `halfOpenStreams`?: integer;
      `failingStreams`?: integer;
      `pushStreams`?: integer;
      `oldestAt`?: string;
      `newestAt`?: string;
      `oldestAgeS`?: NullableNumber;
      `newestAgeS`?: NullableNumber;
      `deadLetteredEver`?: numeric
    };
    `timeline`?: {
      `bucketS`?: numeric;
      `windowS`?: numeric;
      `from`?: string;
      `to`?: string;
      `buckets`?: ({
        `start`?: string;
        `startMs`?: numeric;
        `total`?: integer;
        `counts`?: Record<numeric>
      })[];
      `peak`?: integer;
      `olderThanWindow`?: integer
    };
    `byCode`?: ({
      `errorCode`?: string;
      `count`?: integer;
      `cause`?: string;
      `summary`?: string
    })[];
    `byStatus`?: ({`status`?: numeric; `count`?: integer})[];
    `byEventType`?: ({`type`?: string; `name`?: string; `count`?: integer})[];
    `streams`?: ({
      `stream_id`?: string;
      `aud`?: NullOrStringOrString;
      `endpoint_url`?: string;
      `status`?: string;
      `state`?: string;
      `held`?: integer;
      `causes`?: Record<numeric>;
      `oldestAt`?: string;
      `newestAt`?: string;
      `deadLetteredEver`?: numeric;
      `deadSince`?: string;
      `failingSince`?: string;
      `nextProbeAt`?: string;
      `deadReason`?: string;
      `lastPushError`?: string;
      `lastPushAt`?: NullOrStringOrNumeric
    })[];
    `letters`?: ({
      `stream_id`?: string;
      `jti`?: string;
      `queuedAt`?: NullOrStringOrNumeric;
      `deadAt`?: NullOrStringOrNumeric;
      `ageS`?: NullableNumber;
      `cause`?: string;
      `reason`?: string;
      `errorCode`?: string;
      `status`?: numeric;
      `signed`?: boolean;
      `streamKnown`?: boolean;
      `event`?: NullableObject112
    })[];
    `settings`?: {
      `retentionS`?: numeric;
      `maxPerStream`?: numeric;
      `deadStreamTimeoutS`?: numeric;
      `sweepS`?: numeric;
      `pushConcurrency`?: numeric;
      `pushBacklog`?: numeric;
      `pushRetries`?: numeric
    };
    `process`?: {
      `pid`?: integer;
      `thread`?: NullOrIntegerOrString;
      `role`?: string;
      `pushes`?: {
        `active`?: integer;
        `waiting`?: integer;
        `concurrency`?: numeric;
        `backlog`?: numeric
      };
      `sweeps`?: ({
        `at`?: string;
        `held`?: integer;
        `letters`?: integer;
        `expired`?: integer;
        `orphaned`?: integer;
        `trimmed`?: integer;
        `deadStreams`?: integer;
        `probes`?: integer
      })[];
      `sinceStart`?: {
        `firstSweepAt`?: string;
        `sweeps`?: numeric;
        `letters`?: numeric;
        `expired`?: numeric;
        `orphaned`?: numeric;
        `trimmed`?: numeric;
        `probes`?: numeric
      }
    };
    `filter`?: {
      `q`?: NullableString;
      `stream`?: NullableString;
      `cause`?: NullableString
    };
    `matched`?: integer;
    `paging`?: {
      `letters`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      };
      `streams`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: string;
        `noun`?: string
      }
    }
  }

@component model `ScimMonitor` {
    `installed`?: boolean;
    `enabled`?: boolean;
    `baseUrl`?: NullableString;
    `schemes`?: ({
      `id`?: string;
      `type`?: string;
      `canonical`?: boolean;
      `name`?: string;
      `enabled`?: boolean;
      `refusedByMode`?: string;
      `setting`?: string;
      `primary`?: boolean;
      `scoped`?: boolean;
      `applicationScoped`?: boolean;
      `recorded`?: boolean;
      `challenged`?: boolean;
      `spec`?: string;
      `specUri`?: string;
      `description`?: string
    })[];
    `authRequired`?: boolean;
    `store`?: NullableObject106;
    `counters`?: {
      `calls`?: numeric;
      `ok`?: numeric;
      `failed`?: numeric;
      `successRate`?: NullableNumber;
      `firstAt`?: NumericOrStringOrNull;
      `lastAt`?: NumericOrStringOrNull;
      `since`?: NumericOrStringOrNull;
      `latency`?: {
        `totalMs`?: numeric;
        `averageMs`?: NullableNumber;
        `maxMs`?: numeric
      };
      `bytesOut`?: numeric;
      `authentication`?: {
        `distinct`?: numeric;
        `applications`?: numeric;
        `identities`?: numeric;
        `anonymous`?: numeric;
        `refused`?: numeric;
        `capped`?: boolean;
        `cap`?: numeric;
        @js(#{`description`:"A count per name."}) `byScheme`?: Record<numeric>
      };
      `operations`?: ({
        `operation`?: string;
        `label`?: string;
        `method`?: string;
        `what`?: string;
        `count`?: numeric;
        `ok`?: numeric;
        `failed`?: numeric;
        `averageMs`?: NullableNumber;
        `maxMs`?: NullableNumber;
        `bytes`?: numeric
      })[];
      `resourceTypes`?: ({
        `resourceType`?: NullableString;
        `count`?: numeric
      })[];
      @js(#{`description`:"A count per name."}) `byStatus`?: Record<numeric>;
      @js(#{`description`:"A count per name."}) `byStatusClass`?: Record<numeric>;
      @js(#{`description`:"A count per name."}) `byScimType`?: Record<numeric>;
      `clients`?: ({
        `principal`?: NullableString;
        `kind`?: NullableString;
        `calls`?: numeric;
        `ok`?: numeric;
        `failed`?: numeric;
        `schemes`?: (string)[];
        `resourceTypes`?: (string)[];
        `firstAt`?: NumericOrStringOrNull;
        `lastAt`?: NumericOrStringOrNull;
        `lastOperation`?: NullableString;
        `lastStatus`?: NumericOrStringOrNull
      })[];
      `recent`?: ({
        `at`?: NumericOrStringOrNull;
        `operation`?: NullableString;
        `resourceType`?: NullableString;
        `status`?: NumericOrStringOrNull;
        `ok`?: boolean;
        `scimType`?: NullableString;
        `scheme`?: NullableString;
        `principal`?: NullableString;
        `ms`?: NullableNumber;
        `bytes`?: NullableNumber;
        `method`?: NullableString;
        `path`?: NullableString
      })[];
      `recentCap`?: numeric;
      `realm`?: {
        `id`?: NullableString;
        `name`?: NullableString
      }
    }
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
    `filter`?: {
      `type`?: NullableString;
      `mode`?: NullableString;
      `outcome`?: NullableString;
      `protocol`?: NullableString;
      `q`?: NullableString
    };
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `types`?: ({
      `type`?: string;
      `protocol`?: string;
      `mode`?: string;
      `label`?: string;
      `spec`?: string;
      `policed`?: boolean;
      `what`?: string
    })[];
    `modes`?: ({`mode`?: string; `label`?: string; `what`?: string})[];
    `outcomes`?: (string)[];
    `roles`?: ({`role`?: string; `label`?: string; `what`?: string})[];
    `acts`?: ({
      `seq`?: numeric;
      `origin`?: string;
      `at`?: NullableNumber;
      `protocol`?: string;
      `type`?: string;
      `typeLabel`?: string;
      `mode`?: string;
      `spec`?: string;
      `policed`?: boolean;
      `outcome`?: string;
      `initial`?: {
        `key`?: string;
        `presented`?: string;
        `application`?: string;
        `what`?: string
      };
      `intermediary`?: {
        `key`?: string;
        `presented`?: string;
        `application`?: string;
        `what`?: string
      };
      `target`?: {
        `key`?: string;
        `presented`?: string;
        `application`?: string;
        `what`?: string
      };
      `authorizedBy`?: string;
      `reason`?: string;
      `consumed`?: ({`kind`?: string; `identifier`?: string; `note`?: string})[];
      `produced`?: ({`kind`?: string; `identifier`?: string; `note`?: string})[];
      `sessionId`?: string;
      `note`?: string;
      `chainKey`?: string
    })[];
    `chains`?: ({
      `chainKey`?: string;
      `protocol`?: string;
      `type`?: string;
      `typeLabel`?: string;
      `mode`?: string;
      `initial`?: {
        `key`?: string;
        `presented`?: string;
        `application`?: string;
        `what`?: string
      };
      `intermediary`?: {
        `key`?: string;
        `presented`?: string;
        `application`?: string;
        `what`?: string
      };
      `target`?: {
        `key`?: string;
        `presented`?: string;
        `application`?: string;
        `what`?: string
      };
      `acts`?: integer;
      `issued`?: integer;
      `refused`?: integer;
      `firstAt`?: NullableNumber;
      `lastAt`?: NullableNumber;
      `authorizedBy`?: string;
      `reason`?: string
    })[];
    `applications`?: ({
      `key`?: string;
      `identifier`?: string;
      `spellings`?: (string)[];
      `roles`?: {`initial`?: numeric; `intermediary`?: numeric; `target`?: numeric};
      `protocols`?: (string)[];
      `acts`?: integer;
      `issued`?: integer;
      `refused`?: integer;
      `credentials`?: integer;
      `firstAt`?: NullableNumber;
      `lastAt`?: NullableNumber;
      `identityKey`?: string;
      `chains`?: integer
    })[];
    `graph`?: {
      `realm`?: {
        `id`?: string;
        `name`?: NullableString;
        `isDefault`?: boolean
      };
      `issuer`?: string;
      `nodes`?: ({
        `id`?: string;
        `kind`?: string;
        `key`?: string;
        `presented`?: string;
        `application`?: string;
        `aliases`?: (string)[];
        `what`?: string;
        `roles`?: {`initial`?: numeric; `intermediary`?: numeric; `target`?: numeric};
        `protocols`?: (string)[];
        `acts`?: integer;
        `issued`?: integer;
        `refused`?: integer;
        `firstAt`?: NullableNumber;
        `lastAt`?: NullableNumber;
        `selfTarget`?: boolean;
        `chiefRole`?: string;
        `realm`?: {
          `id`?: string;
          `name`?: NullableString;
          `isDefault`?: boolean
        };
        `issuer`?: string;
        `credentials`?: integer;
        `flows`?: (string)[];
        `authentications`?: integer;
        `isSubject`?: boolean;
        `isClient`?: boolean;
        `kinds`?: (string)[];
        `grants`?: integer;
        `exposes`?: integer;
        `dangling`?: integer
      })[];
      `edges`?: ({
        `id`?: string;
        `from`?: string;
        `to`?: string;
        `fromRole`?: string;
        `toRole`?: string;
        `relation`?: string;
        `skipped`?: (string)[];
        `chainKey`?: string;
        `protocol`?: NullableString;
        `protocols`?: (string)[];
        `type`?: NullableString;
        `typeLabel`?: NullableString;
        `mode`?: string;
        `spec`?: NullableString;
        `policed`?: boolean;
        `subject`?: NullableString;
        `actor`?: NullableString;
        `acts`?: integer;
        `issued`?: integer;
        `refused`?: integer;
        `credentials`?: integer;
        `firstAt`?: NullableNumber;
        `lastAt`?: NullableNumber;
        `authorizedBy`?: string;
        `reason`?: string;
        `consumed`?: ({
          `kind`?: string;
          `count`?: integer;
          `identifiers`?: (string)[];
          `moreIdentifiers`?: integer;
          `notes`?: (string)[]
        })[];
        `produced`?: ({
          `kind`?: string;
          `count`?: integer;
          `identifiers`?: (string)[];
          `moreIdentifiers`?: integer;
          `notes`?: (string)[]
        })[];
        `consumedFold`?: Record<{
          `kind`?: string;
          `count`?: integer;
          `identifiers`?: (string)[];
          `moreIdentifiers`?: integer;
          `notes`?: (string)[]
        }>;
        `producedFold`?: Record<{
          `kind`?: string;
          `count`?: integer;
          `identifiers`?: (string)[];
          `moreIdentifiers`?: integer;
          `notes`?: (string)[]
        }>;
        `attribute`?: string;
        `mechanism`?: string;
        `setOn`?: string;
        `used`?: boolean;
        `authentications`?: ({
          `protocol`?: string;
          `method`?: string;
          `count`?: integer;
          `at`?: NullableNumber;
          `lastAt`?: NullableNumber
        })[];
        `audience`?: string;
        `audienceRegistered`?: boolean;
        `permissions`?: (string)[];
        `scopes`?: (string)[];
        `permissionId`?: string;
        `permissionName`?: string;
        `baseUri`?: NullableString;
        `description`?: NullableString;
        `asked`?: boolean
      })[];
      `tokens`?: ({
        `seq`?: numeric;
        `at`?: NullableNumber;
        `kind`?: string;
        `identifier`?: string;
        `note`?: string;
        `protocol`?: string;
        `type`?: string;
        `typeLabel`?: string;
        `mode`?: string;
        `chainKey`?: string;
        `subject`?: NullableString;
        `actor`?: NullableString;
        `target`?: NullableString
      })[];
      `tokensLeftOff`?: integer;
      `maxTokenRows`?: integer;
      `acts`?: integer;
      `chains`?: integer;
      `credentials`?: ({
        `at`?: NullableNumber;
        `family`?: string;
        `kind`?: string;
        `identifier`?: string;
        `flow`?: string;
        `flowLabel`?: NullableString;
        `flowProtocol`?: NullableString;
        `flowSpec`?: NullableString;
        `flowOidc`?: NullableString;
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
        `expiresAtMs`?: NullableNumber
      })[];
      `credentialsOnDelegationLines`?: integer;
      `subject`?: string;
      `counts`?: {`nodes`?: integer; `edges`?: integer; `grants`?: integer}
    };
    `policy`?: {
      `pairs`?: ({
        `mechanism`?: string;
        `type`?: string;
        `frontEnd`?: string;
        `target`?: string;
        `realm`?: string;
        `attribute`?: string;
        `setOn`?: string;
        `setOnRole`?: string;
        `requires`?: string;
        `targetKnown`?: boolean;
        `warning`?: string;
        `note`?: string
      })[];
      `accounts`?: ({
        `principal`?: string;
        `realm`?: string;
        `notDelegated`?: boolean;
        `trustedToAuthenticateForDelegation`?: boolean;
        `okAsDelegate`?: boolean;
        `autoCreated`?: boolean;
        `description`?: string;
        `effects`?: (string)[]
      })[]
    };
    `allowed`?: {
      `resources`?: ({
        `identifier`?: string;
        `name`?: string;
        `baseUri`?: NullableString;
        `rawBaseUri`?: string;
        `permissions`?: ({
          `name`?: NullableString;
          `description`?: NullableString;
          `id`?: NullableString;
          `raw`?: NullableString;
          `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
        })[];
        `grantsHeld`?: integer
      })[];
      `permissions`?: ({
        `resource`?: string;
        `resourceName`?: string;
        `baseUri`?: NullableString;
        `name`?: NullableString;
        `description`?: NullableString;
        `id`?: NullableString;
        `raw`?: NullableString;
        `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
      })[];
      `grants`?: ({
        `client`?: string;
        `clientName`?: string;
        `permissionId`?: string;
        `resource`?: string;
        `resourceName`?: string;
        `baseUri`?: NullableString;
        `permissionName`?: NullableString;
        `description`?: NullableString;
        `dangling`?: boolean;
        `asked`?: boolean
      })[];
      `counts`?: {
        `resources`?: integer;
        `permissions`?: integer;
        `unidentified`?: integer;
        `grants`?: integer;
        `dangling`?: integer;
        `unused`?: integer;
        `ungranted`?: integer;
        `clients`?: integer
      };
      `graph`?: {
        `realm`?: {
          `id`?: string;
          `name`?: NullableString;
          `isDefault`?: boolean
        };
        `issuer`?: string;
        `nodes`?: ({
          `id`?: string;
          `kind`?: string;
          `key`?: string;
          `presented`?: string;
          `application`?: string;
          `aliases`?: (string)[];
          `what`?: string;
          `roles`?: {`initial`?: numeric; `intermediary`?: numeric; `target`?: numeric};
          `protocols`?: (string)[];
          `acts`?: integer;
          `issued`?: integer;
          `refused`?: integer;
          `firstAt`?: NullableNumber;
          `lastAt`?: NullableNumber;
          `selfTarget`?: boolean;
          `chiefRole`?: string;
          `realm`?: {
            `id`?: string;
            `name`?: NullableString;
            `isDefault`?: boolean
          };
          `issuer`?: string;
          `credentials`?: integer;
          `flows`?: (string)[];
          `authentications`?: integer;
          `isSubject`?: boolean;
          `isClient`?: boolean;
          `kinds`?: (string)[];
          `grants`?: integer;
          `exposes`?: integer;
          `dangling`?: integer
        })[];
        `edges`?: ({
          `id`?: string;
          `from`?: string;
          `to`?: string;
          `fromRole`?: string;
          `toRole`?: string;
          `relation`?: string;
          `skipped`?: (string)[];
          `chainKey`?: string;
          `protocol`?: NullableString;
          `protocols`?: (string)[];
          `type`?: NullableString;
          `typeLabel`?: NullableString;
          `mode`?: string;
          `spec`?: NullableString;
          `policed`?: boolean;
          `subject`?: NullableString;
          `actor`?: NullableString;
          `acts`?: integer;
          `issued`?: integer;
          `refused`?: integer;
          `credentials`?: integer;
          `firstAt`?: NullableNumber;
          `lastAt`?: NullableNumber;
          `authorizedBy`?: string;
          `reason`?: string;
          `consumed`?: ({
            `kind`?: string;
            `count`?: integer;
            `identifiers`?: (string)[];
            `moreIdentifiers`?: integer;
            `notes`?: (string)[]
          })[];
          `produced`?: ({
            `kind`?: string;
            `count`?: integer;
            `identifiers`?: (string)[];
            `moreIdentifiers`?: integer;
            `notes`?: (string)[]
          })[];
          `consumedFold`?: Record<{
            `kind`?: string;
            `count`?: integer;
            `identifiers`?: (string)[];
            `moreIdentifiers`?: integer;
            `notes`?: (string)[]
          }>;
          `producedFold`?: Record<{
            `kind`?: string;
            `count`?: integer;
            `identifiers`?: (string)[];
            `moreIdentifiers`?: integer;
            `notes`?: (string)[]
          }>;
          `attribute`?: string;
          `mechanism`?: string;
          `setOn`?: string;
          `used`?: boolean;
          `authentications`?: ({
            `protocol`?: string;
            `method`?: string;
            `count`?: integer;
            `at`?: NullableNumber;
            `lastAt`?: NullableNumber
          })[];
          `audience`?: string;
          `audienceRegistered`?: boolean;
          `permissions`?: (string)[];
          `scopes`?: (string)[];
          `permissionId`?: string;
          `permissionName`?: string;
          `baseUri`?: NullableString;
          `description`?: NullableString;
          `asked`?: boolean
        })[];
        `tokens`?: ({
          `seq`?: numeric;
          `at`?: NullableNumber;
          `kind`?: string;
          `identifier`?: string;
          `note`?: string;
          `protocol`?: string;
          `type`?: string;
          `typeLabel`?: string;
          `mode`?: string;
          `chainKey`?: string;
          `subject`?: NullableString;
          `actor`?: NullableString;
          `target`?: NullableString
        })[];
        `tokensLeftOff`?: integer;
        `maxTokenRows`?: integer;
        `acts`?: integer;
        `chains`?: integer;
        `credentials`?: ({
          `at`?: NullableNumber;
          `family`?: string;
          `kind`?: string;
          `identifier`?: string;
          `flow`?: string;
          `flowLabel`?: NullableString;
          `flowProtocol`?: NullableString;
          `flowSpec`?: NullableString;
          `flowOidc`?: NullableString;
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
          `expiresAtMs`?: NullableNumber
        })[];
        `credentialsOnDelegationLines`?: integer;
        `subject`?: string;
        `counts`?: {`nodes`?: integer; `edges`?: integer; `grants`?: integer}
      };
      `filter`?: {
        `permissions`?: NullableString;
        `grants`?: NullableString
      };
      `paging`?: {
        `permissions`?: {
          `page`?: integer;
          `pages`?: integer;
          `perPage`?: integer;
          `firstRow`?: integer;
          `lastRow`?: integer;
          `total`?: integer;
          `param`?: NullableString;
          `noun`?: NullableString
        };
        `grants`?: {
          `page`?: integer;
          `pages`?: integer;
          `perPage`?: integer;
          `firstRow`?: integer;
          `lastRow`?: integer;
          `total`?: integer;
          `param`?: NullableString;
          `noun`?: NullableString
        }
      }
    };
    `delegationPolicy`?: {
      `enforced`?: boolean;
      `attributes`?: Record<string>;
      `protectedGroups`?: (string)[];
      `pairs`?: ({
        `mechanism`?: string;
        `intermediary`?: string;
        `target`?: string;
        `targetApplication`?: NullableString;
        `attribute`?: string;
        `setOn`?: string;
        `setOnRole`?: string;
        `impersonates`?: boolean;
        `subjectGroups`?: (string)[];
        `targetKnown`?: boolean;
        `warning`?: string
      })[];
      `pairsPaging`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: NullableString;
        `noun`?: NullableString
      };
      `intermediaries`?: ({
        `application`?: string;
        `impersonates`?: boolean;
        `semantics`?: (string)[];
        `defaultSemantics`?: string;
        `notDelegated`?: boolean;
        `subjectGroups`?: (string)[]
      })[];
      `intermediariesPaging`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: NullableString;
        `noun`?: NullableString
      };
      `people`?: ({
        `username`?: string;
        `dn`?: string;
        `notDelegated`?: boolean;
        `mayAct`?: string;
        `semantics`?: (string)[];
        `defaultSemantics`?: string
      })[];
      `peoplePaging`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: NullableString;
        `noun`?: NullableString
      }
    };
    `all`?: integer;
    `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: NullableString;
      `noun`?: NullableString
    };
    `delegationPerPage`?: integer;
    `chainPage`?: {
      `shown`?: ({
        `chainKey`?: string;
        `protocol`?: string;
        `type`?: string;
        `typeLabel`?: string;
        `mode`?: string;
        `initial`?: {
          `key`?: string;
          `presented`?: string;
          `application`?: string;
          `what`?: string
        };
        `intermediary`?: {
          `key`?: string;
          `presented`?: string;
          `application`?: string;
          `what`?: string
        };
        `target`?: {
          `key`?: string;
          `presented`?: string;
          `application`?: string;
          `what`?: string
        };
        `acts`?: integer;
        `issued`?: integer;
        `refused`?: integer;
        `firstAt`?: NullableNumber;
        `lastAt`?: NullableNumber;
        `authorizedBy`?: string;
        `reason`?: string
      })[];
      `paging`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: NullableString;
        `noun`?: NullableString
      }
    };
    `pairPage`?: {
      `shown`?: ({
        `mechanism`?: string;
        `type`?: string;
        `frontEnd`?: string;
        `target`?: string;
        `realm`?: string;
        `attribute`?: string;
        `setOn`?: string;
        `setOnRole`?: string;
        `requires`?: string;
        `targetKnown`?: boolean;
        `warning`?: string;
        `note`?: string
      })[];
      `paging`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: NullableString;
        `noun`?: NullableString
      }
    };
    `flagPage`?: {
      `shown`?: ({
        `principal`?: string;
        `realm`?: string;
        `notDelegated`?: boolean;
        `trustedToAuthenticateForDelegation`?: boolean;
        `okAsDelegate`?: boolean;
        `autoCreated`?: boolean;
        `description`?: string;
        `effects`?: (string)[]
      })[];
      `paging`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: NullableString;
        `noun`?: NullableString
      }
    };
    `mechanismPage`?: {
      `shown`?: ({
        `type`?: string;
        `protocol`?: string;
        `mode`?: string;
        `label`?: string;
        `spec`?: string;
        `policed`?: boolean;
        `what`?: string
      })[];
      `paging`?: {
        `page`?: integer;
        `pages`?: integer;
        `perPage`?: integer;
        `firstRow`?: integer;
        `lastRow`?: integer;
        `total`?: integer;
        `param`?: NullableString;
        `noun`?: NullableString
      }
    };
    `applicationChooser`?: {
      `total`?: integer;
      `entries`?: ({
        `key`?: string;
        `names`?: (NullableString)[];
        `label`?: string;
        `detail`?: string;
        `href`?: string
      })[];
      `slice`?: {`matched`?: integer; `from`?: integer};
      `search`?: string;
      `complete`?: boolean
    };
    `userChooser`?: {
      `total`?: integer;
      `entries`?: ({
        `key`?: string;
        `names`?: (NullableString)[];
        `label`?: string;
        `detail`?: string;
        `href`?: string
      })[];
      `slice`?: {`matched`?: integer; `from`?: integer};
      `search`?: string;
      `complete`?: boolean
    };
    `permissionsView`?: {
      `register`?: {
        `resources`?: ({
          `identifier`?: string;
          `name`?: string;
          `baseUri`?: NullableString;
          `rawBaseUri`?: string;
          `permissions`?: ({
            `name`?: NullableString;
            `description`?: NullableString;
            `id`?: NullableString;
            `raw`?: NullableString;
            `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
          })[];
          `grantsHeld`?: integer
        })[];
        `permissions`?: ({
          `resource`?: string;
          `resourceName`?: string;
          `baseUri`?: NullableString;
          `name`?: NullableString;
          `description`?: NullableString;
          `id`?: NullableString;
          `raw`?: NullableString;
          `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
        })[];
        `grants`?: ({
          `client`?: string;
          `clientName`?: string;
          `permissionId`?: string;
          `resource`?: string;
          `resourceName`?: string;
          `baseUri`?: NullableString;
          `permissionName`?: NullableString;
          `description`?: NullableString;
          `dangling`?: boolean;
          `asked`?: boolean
        })[];
        `counts`?: {
          `resources`?: integer;
          `permissions`?: integer;
          `unidentified`?: integer;
          `grants`?: integer;
          `dangling`?: integer;
          `unused`?: integer;
          `ungranted`?: integer;
          `clients`?: integer
        }
      };
      `listState`?: {
        `permWanted`?: string;
        `grantWanted`?: string;
        `permPage`?: {
          `shown`?: ({
            `resource`?: string;
            `resourceName`?: string;
            `baseUri`?: NullableString;
            `name`?: NullableString;
            `description`?: NullableString;
            `id`?: NullableString;
            `raw`?: NullableString;
            `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
          })[];
          `paging`?: {
            `page`?: integer;
            `pages`?: integer;
            `perPage`?: integer;
            `firstRow`?: integer;
            `lastRow`?: integer;
            `total`?: integer;
            `param`?: NullableString;
            `noun`?: NullableString
          }
        };
        `grantPage`?: {
          `shown`?: ({
            `client`?: string;
            `clientName`?: string;
            `permissionId`?: string;
            `resource`?: string;
            `resourceName`?: string;
            `baseUri`?: NullableString;
            `permissionName`?: NullableString;
            `description`?: NullableString;
            `dangling`?: boolean;
            `asked`?: boolean
          })[];
          `paging`?: {
            `page`?: integer;
            `pages`?: integer;
            `perPage`?: integer;
            `firstRow`?: integer;
            `lastRow`?: integer;
            `total`?: integer;
            `param`?: NullableString;
            `noun`?: NullableString
          }
        }
      };
      `allApplications`?: ({`identifier`?: string; `name`?: string})[]
    };
    `exchangePolicyView`?: {
      `register`?: {
        `pairs`?: ({
          `mechanism`?: string;
          `intermediary`?: string;
          `target`?: string;
          `targetApplication`?: NullableString;
          `attribute`?: string;
          `setOn`?: string;
          `setOnRole`?: string;
          `impersonates`?: boolean;
          `subjectGroups`?: (string)[];
          `targetKnown`?: boolean;
          `warning`?: string
        })[];
        `intermediaries`?: ({
          `application`?: string;
          `impersonates`?: boolean;
          `semantics`?: (string)[];
          `defaultSemantics`?: string;
          `notDelegated`?: boolean;
          `subjectGroups`?: (string)[]
        })[];
        `people`?: ({
          `username`?: string;
          `dn`?: string;
          `notDelegated`?: boolean;
          `mayAct`?: string;
          `semantics`?: (string)[];
          `defaultSemantics`?: string
        })[];
        `protectedGroups`?: (string)[];
        `enforced`?: boolean;
        `attributes`?: Record<string>
      };
      `pairs`?: {
        `shown`?: ({
          `mechanism`?: string;
          `intermediary`?: string;
          `target`?: string;
          `targetApplication`?: NullableString;
          `attribute`?: string;
          `setOn`?: string;
          `setOnRole`?: string;
          `impersonates`?: boolean;
          `subjectGroups`?: (string)[];
          `targetKnown`?: boolean;
          `warning`?: string
        })[];
        `paging`?: {
          `page`?: integer;
          `pages`?: integer;
          `perPage`?: integer;
          `firstRow`?: integer;
          `lastRow`?: integer;
          `total`?: integer;
          `param`?: NullableString;
          `noun`?: NullableString
        }
      };
      `intermediaries`?: {
        `shown`?: ({
          `application`?: string;
          `impersonates`?: boolean;
          `semantics`?: (string)[];
          `defaultSemantics`?: string;
          `notDelegated`?: boolean;
          `subjectGroups`?: (string)[]
        })[];
        `paging`?: {
          `page`?: integer;
          `pages`?: integer;
          `perPage`?: integer;
          `firstRow`?: integer;
          `lastRow`?: integer;
          `total`?: integer;
          `param`?: NullableString;
          `noun`?: NullableString
        }
      };
      `people`?: {
        `shown`?: ({
          `username`?: string;
          `dn`?: string;
          `notDelegated`?: boolean;
          `mayAct`?: string;
          `semantics`?: (string)[];
          `defaultSemantics`?: string
        })[];
        `paging`?: {
          `page`?: integer;
          `pages`?: integer;
          `perPage`?: integer;
          `firstRow`?: integer;
          `lastRow`?: integer;
          `total`?: integer;
          `param`?: NullableString;
          `noun`?: NullableString
        }
      }
    };
    `facts`?: {
      `users`?: Record<boolean>;
      `apps`?: Record<{`name`?: string; `dnLabel`?: string}>
    }
  }

@js(#{
    `description`:"One thing that happened, with the facts of it and no credential of any kind. Written out rather than left open because a caller filtering or alerting on this list needs a name for every field.",
    `additionalProperties`:true
  }) @component model `AuditEvent` {
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
    `filter`?: {
      `category`?: NullableString;
      `action`?: NullableString;
      `outcome`?: NullableString;
      `actor`?: NullableString;
      `q`?: NullableString;
      `code`?: NullableString;
      `address`?: NullableString
    };
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `categories`?: ({`category`?: string; `label`?: string; `what`?: string})[];
    `actions`?: ({`action`?: string; `category`?: string; `label`?: string})[];
    `outcomes`?: (string)[];
    `events`?: ({
      `seq`?: numeric;
      `origin`?: NullableString;
      `at`?: numeric;
      `category`?: string;
      `action`?: string;
      `outcome`?: string;
      `errorCode`?: NullableString;
      `actor`?: string;
      `actorForm`?: string;
      `target`?: string;
      `protocol`?: string;
      `channel`?: string;
      `address`?: string;
      `summary`?: string;
      @js(#{
        `x-free-form`:"What this one kind of event recorded about its own act: several hundred call sites each name their members, and values are trimmed by `detailOf()`.",
        `description`:"What this one kind of event recorded about its own act: several hundred call sites each name their members, and values are trimmed by `detailOf()`."
      }) `detail`?: unknown
    })[];
    @js(#{
      `description`:"Which page of how many, and the query parameter that moves it."
    }) `paging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: string;
      `noun`?: string
    };
    @js(#{`description`:"The actors on this page that are people known here."}) `knownActors`?: Record<boolean>;
    `settings`?: NullableObject113;
    `verifiesCredentials`?: boolean;
    `persisted`?: boolean
  }

@js(#{
    `description`:"A refusal or a failure. The sentence is for a person; no error code is ever in it."
  }) @component model `SharedModel1` {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `message`?: string;
    `why`?: string;
    `status`?: integer
  }

@component model `SharedModel8` is ({
    `path`?: string;
    `label`?: string;
    `blurb`?: string;
    `hidden`?: boolean;
    `title`?: string;
    `what`?: string
  })[];
  

@component model `SharedModel7` {
    `path`?: string;
    `label`?: string;
    `blurb`?: string;
    `hidden`?: boolean;
    `title`?: string;
    `what`?: string;
    `items`?: `SharedModel8`
  }

@component model `SharedModel6` is (`SharedModel7`)[];
  

@component model `SharedModel5` {
    `path`?: string;
    `label`?: string;
    `blurb`?: string;
    `hidden`?: boolean;
    `title`?: string;
    `what`?: string;
    `items`?: `SharedModel6`
  }

@component model `SharedModel4` is (`SharedModel5`)[];
  

@component model `SharedModel3` {`title`?: string; `what`?: string; `items`?: `SharedModel4`}

@component model `SharedModel2` is (`SharedModel3`)[];
  

@component model `SharedModel10` {
    `locale`?: string;
    `chain`?: (string)[];
    `catalog`?: string;
    `direction`?: "ltr" | "rtl";
    `matched`?: boolean
  }

  

@component model `SharedModel9` {
    `negotiated`?: `SharedModel10`;
    `offered`?: ({`tag`?: string; `name`?: string})[];
    @js(#{`description`:"Each catalog along the chain, by language tag."}) `catalogs`?: Record<ListOfRecordString>;
    @js(#{`description`:"Each static catalog, by language tag."}) `catalogFiles`?: Record<string>
  }

@component model `SharedModel11` {`ok`: boolean; `errors`?: (string)[]; `locale`?: `SharedModel9`}

@component model `SharedModel13` {
    `shape`?: string;
    `label`?: string;
    `sublabel`?: NullableString;
    `identifier`?: NullableString;
    `title`?: string;
    `href`?: NullableString;
    `dashed`?: boolean
  }

@js(#{`description`:"Each node's look, by node id."}) @component model `SharedModel12` is Record<`SharedModel13`>;
  

@component model `SharedModel15` {
    `id`?: string;
    `kind`?: string;
    `realm`?: {`id`?: string; `name`?: string; `isDefault`?: boolean};
    `issuer`?: string;
    `roles`?: {`initial`?: integer; `intermediary`?: integer; `target`?: integer};
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

@component model `SharedModel14` is (`SharedModel15`)[];
  

@component model `SharedModel19` {
    `kind`?: string;
    `count`?: integer;
    `identifiers`?: (string)[];
    `moreIdentifiers`?: integer;
    `notes`?: (string)[]
  }

@component model `SharedModel18` is (`SharedModel19`)[];
  

@component model `SharedModel20` is Record<`SharedModel19`>;
  

@component model `SharedModel17` {
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
    `consumed`?: `SharedModel18`;
    `produced`?: `SharedModel18`;
    `attribute`?: string;
    `mechanism`?: string;
    `setOn`?: string;
    `used`?: boolean;
    `consumedFold`?: `SharedModel20`;
    `producedFold`?: `SharedModel20`;
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

@component model `SharedModel16` is (`SharedModel17`)[];
  

@component model `SharedModel22` {
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

@component model `SharedModel21` is (`SharedModel22`)[];
  

@component model `SharedModel23` {
    `total`?: integer;
    `entries`?: ({
      `key`?: string;
      `names`?: (string)[];
      `label`?: string;
      `detail`?: string;
      `href`?: string
    })[];
    `slice`?: {`matched`?: integer; `from`?: integer};
    `search`?: "contains" | "exact";
    `complete`?: boolean
  }

@component model `SharedModel24` {
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
  }) @hoisted model SharedModel25_h1349 {}

@component union `SharedModel25` {SharedModel25_h1349}

@component model `SharedModel26` {
    `applications`?: integer;
    `grants`?: integer;
    `lines`?: integer;
    `permissions`?: integer;
    `dangling`?: integer;
    `selfGrants`?: integer;
    `asked`?: integer;
    `unused`?: integer
  }

@component model `SharedModel28` {
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

@component model `SharedModel27` is (`SharedModel28`)[];
  

@component model `SharedModel29` {
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `total`?: integer;
    `param`?: NullableString;
    `noun`?: NullableString
  }

@component model `SharedModel31` {
    `resource`?: string;
    `resourceName`?: string;
    `baseUri`?: string;
    `name`?: string;
    `description`?: string;
    `id`?: NullableString;
    `raw`?: string;
    `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
  }

@component model `SharedModel30` is (`SharedModel31`)[];
  

@component model `SharedModel33` {`key`?: string; `members`?: (string)[]; `counts`?: `SharedModel26`}

@component model `SharedModel32` is (`SharedModel33`)[];
  

@component model `SharedModel36` {
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

@component model `SharedModel35` is (`SharedModel36`)[];
  

@component model `SharedModel34` {
    `realm`?: {`id`?: string; `name`?: string; `isDefault`?: boolean};
    `issuer`?: string;
    `nodes`?: `SharedModel14`;
    `edges`?: `SharedModel16`;
    `tokens`?: `SharedModel21`;
    `tokensLeftOff`?: integer;
    `maxTokenRows`?: integer;
    `acts`?: integer;
    `chains`?: integer;
    `counts`?: {`nodes`?: integer; `edges`?: integer; `grants`?: integer};
    `credentials`?: `SharedModel35`;
    `credentialsOnDelegationLines`?: integer;
    `subject`?: string
  }

@component model `SharedModel41` {
    `name`?: string;
    `description`?: string;
    `id`?: NullableString;
    `raw`?: string;
    `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
  }

@component model `SharedModel40` is (`SharedModel41`)[];
  

@component model `SharedModel39` {
    `identifier`?: string;
    `name`?: string;
    `baseUri`?: string;
    `rawBaseUri`?: string;
    `permissions`?: `SharedModel40`;
    `grantsHeld`?: integer
  }

@component model `SharedModel38` is (`SharedModel39`)[];
  

@component model `SharedModel42` {
    `resources`?: integer;
    `permissions`?: integer;
    `unidentified`?: integer;
    `grants`?: integer;
    `dangling`?: integer;
    `unused`?: integer;
    `ungranted`?: integer;
    `clients`?: integer
  }

@component model `SharedModel37` {
    `resources`?: `SharedModel38`;
    `permissions`?: `SharedModel30`;
    `grants`?: `SharedModel27`;
    `counts`?: `SharedModel42`
  }

@component model `SharedModel45` {
    `key`?: string;
    `members`?: (string)[];
    `grants`?: `SharedModel27`;
    `permissions`?: `SharedModel30`;
    `counts`?: `SharedModel26`
  }

@component model `SharedModel44` is (`SharedModel45`)[];
  

@component model `SharedModel43` {
    `clusters`?: `SharedModel44`;
    @js(#{`description`:"Each application, to its group's key."}) `memberOf`?: Record<string>;
    `counts`?: {
      `clusters`?: integer;
      `applications`?: integer;
      `largest`?: integer;
      `alone`?: integer;
      `joined`?: integer
    }
  }

@component model `SharedModel46` {`shown`?: `SharedModel27`; `paging`?: `SharedModel29`}

@component model `SharedModel47` {`shown`?: `SharedModel30`; `paging`?: `SharedModel29`}

@component model `SharedModel49` {
    `onlyWhileOn`?: ({
      `setting`?: string;
      `values`?: (string)[];
      `on`?: boolean;
      `canBeOn`?: boolean
    })[];
    `aloneWhileOn`?: ({
      `setting`?: string;
      `values`?: (string)[];
      `on`?: boolean;
      `canBeOn`?: boolean
    })[]
  }

@component model `SharedModel48` {
    `key`?: string;
    `group`?: string;
    `label`?: string;
    `description`?: string;
    `type`?: string;
    `enumValues`?: (string)[];
    `csvValues`?: (string)[];
    `ordered`?: boolean;
    @js(#{`description`:"A sentence per value of the row."}) `csvValueNotes`?: Record<string>;
    `selectAll`?: `SharedModel49`;
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

@component model `SharedModel51` {
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
    `initial`?: {
      `key`?: string;
      `presented`?: string;
      `application`?: string;
      `what`?: string
    };
    `intermediary`?: {
      `key`?: string;
      `presented`?: string;
      `application`?: string;
      `what`?: string
    };
    `target`?: {
      `key`?: string;
      `presented`?: string;
      `application`?: string;
      `what`?: string
    };
    `authorizedBy`?: string;
    `reason`?: string;
    `consumed`?: ({`kind`?: string; `identifier`?: string; `note`?: string})[];
    `produced`?: ({`kind`?: string; `identifier`?: string; `note`?: string})[];
    `sessionId`?: string;
    `note`?: string;
    `chainKey`?: string
  }

@component model `SharedModel50` is (`SharedModel51`)[];
  

@component model `SharedModel55` {
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

@component model `SharedModel54` is (`SharedModel55`)[];
  

@component model `SharedModel56` is ({
    `id`?: string;
    `label`?: string;
    `classical`?: boolean;
    `families`?: (string)[];
    `note`?: string
  })[];
  

@component model `SharedModel57` is ({
    `id`?: string;
    `label`?: string;
    `family`?: string;
    `kind`?: string;
    `signs`?: boolean;
    `slow`?: boolean
  })[];
  

@component model `SharedModel58` is ({
    `id`?: string;
    `label`?: string;
    `subject`?: string;
    `keyAlg`?: string;
    `notAfter`?: string;
    `hasAlternativeKey`?: boolean
  })[];
  

@component model `SharedModel60` {
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

@component model `SharedModel59` is (`SharedModel60`)[];
  

@component model `SharedModel53` {
    `fields`?: (string)[];
    `profiles`?: `SharedModel54`;
    `pqModes`?: `SharedModel56`;
    `pqMode`?: string;
    `keyAlgorithms`?: `SharedModel57`;
    `alternativeKeyAlgorithms`?: `SharedModel57`;
    `signatureAlgorithms`?: ({`id`?: string; `label`?: string; `weak`?: boolean; `kind`?: string})[];
    `signerLabel`?: string;
    `keystoreFormats`?: (string)[];
    `keyUsageBits`?: ({`name`?: string; `what`?: string})[];
    `extendedKeyUsages`?: ({`name`?: string; `oid`?: string})[];
    `netscapeTypes`?: ({`name`?: string})[];
    `accessMethods`?: (string)[];
    `dnFields`?: ({`attr`?: string; `field`?: string})[];
    `issuers`?: `SharedModel58`;
    `objects`?: `SharedModel59`;
    `maxObjects`?: integer;
    `slowFamilies`?: (string)[];
    @js(#{`description`:"The certificate form, by field name."}) `draft`?: Record<Shape8>
  }

@component model `SharedModel52` {
    `ok`: boolean;
    `errors`?: (string)[];
    `why`?: string;
    @js(#{`description`:"The certificate form, by field name."}) `draft`?: Record<Shape8>;
    `algorithm`?: string;
    `workbench`?: `SharedModel53`
  }

@component model `SharedModel61` {
    `ok`: boolean;
    `changed`?: boolean;
    `clientSecret`?: string;
    `message`?: string;
    `errors`?: (string)[]
  }

@js(#{
    `x-free-form`:"The inside of an OpenAPI document (its paths and components): a statement about this API in OpenAPI's own vocabulary, whose every model is stated at the operation it describes.",
    `description`:"The inside of an OpenAPI document (its paths and components): a statement about this API in OpenAPI's own vocabulary, whose every model is stated at the operation it describes."
  }) @component model `SharedModel62` {}

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
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
    `realm`?: {`id`?: string; `name`?: string};
    `wsTrustIssuer`?: NullableString;
    `realms`?: get_admin_api_console_r200_application_json_realms_h1386;
    `realmRoot`?: string;
    `portalHref`?: string;
    `sections`?: `SharedModel2`;
    @js(#{`description`:"Every console page's label, by its path."}) `navLabels`?: Record<string>;
    `retiring`?: NullableObject114;
    `runtime`?: {
      `process`?: string;
      `mode`?: string;
      `database`?: string;
      `keyEncryptionKey`?: string;
      `databasePassword`?: string
    };
    `persistence`?: {`enabled`?: boolean; `mode`?: string};
    `version`?: {`version`?: string; `stamped`?: boolean; `buildInfo`?: string};
    `locale`?: `SharedModel9`
  },
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
  `responses/200/content/application~1json/schema`: `SharedModel11`,
  `responses/400/content/application~1json/schema`: `SharedModel11`,
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
    `drawing`?: {
      `width`?: numeric;
      `height`?: numeric;
      `failed`?: NullableString
    };
    `looks`?: `SharedModel12`;
    `label`?: string;
    `svg`?: string;
    `realm`?: {`id`?: string; `name`?: string; `isDefault`?: boolean};
    `issuer`?: string;
    `nodes`?: `SharedModel14`;
    `edges`?: `SharedModel16`;
    `tokens`?: `SharedModel21`;
    `tokensLeftOff`?: integer;
    `maxTokenRows`?: integer;
    `acts`?: integer;
    `chains`?: integer;
    `filter`?: {
      `type`?: NullableString;
      `mode`?: NullableString;
      `outcome`?: NullableString;
      `protocol`?: NullableString;
      `q`?: NullableString
    };
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
    `types`?: ({
      `type`?: string;
      `protocol`?: string;
      `mode`?: string;
      `label`?: string;
      `spec`?: string;
      `policed`?: boolean;
      `what`?: string
    })[];
    `modes`?: ({`mode`?: string; `label`?: string; `what`?: string})[];
    `outcomes`?: (string)[];
    `applicationChooser`?: `SharedModel23`;
    `userChooser`?: `SharedModel23`;
    `mapKey`?: string;
    `directoryLoaded`?: boolean;
    `facts`?: `SharedModel24`
  },
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
    `realm`?: {`id`?: string; `name`?: string; `isDefault`?: boolean};
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
      `brokeredUse`?: `SharedModel25`;
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
      `use`?: `SharedModel25`
    })[];
    `drawing`?: {
      `width`?: numeric;
      `height`?: numeric;
      `failed`?: NullableString
    };
    `label`?: string;
    `svg`?: string;
    `roles`?: ({`role`?: string; `label`?: string; `short`?: string; `what`?: string})[];
    `protocols`?: ({
      `protocol`?: string;
      `label`?: string;
      `family`?: string;
      `what`?: string;
      `needs`?: (string)[];
      `spec`?: string;
      `signalsOnly`?: boolean
    })[];
    `mapKey`?: string
  },
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `key`:#{`type`:"string"},
      `members`:#{`type`:"array",`items`:#{`type`:"string"}},
      `counts`:#{`$ref`:"#/components/schemas/SharedModel26"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_admin_api_console_delegation_cluster_r200_application_json_group_h1397 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `key`:#{`type`:"string"},
      `members`:#{`type`:"array",`items`:#{`type`:"string"}},
      `grants`:#{`$ref`:"#/components/schemas/SharedModel27"},
      `permissions`:#{`$ref`:"#/components/schemas/SharedModel30"},
      `counts`:#{`$ref`:"#/components/schemas/SharedModel26"}
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
    `drawing`?: {
      `width`?: numeric;
      `height`?: numeric;
      `failed`?: NullableString
    };
    `looks`?: `SharedModel12`;
    `label`?: string;
    `svg`?: string;
    `application`?: NullableString;
    `group`?: get_admin_api_console_delegation_cluster_r200_application_json_group_h1397;
    `grants`?: `SharedModel27`;
    `grantsPaging`?: `SharedModel29`;
    `permissions`?: `SharedModel30`;
    `permissionsPaging`?: `SharedModel29`;
    `groups`?: `SharedModel32`;
    `counts`?: {
      `clusters`?: integer;
      `applications`?: integer;
      `largest`?: integer;
      `alone`?: integer;
      `joined`?: integer
    };
    `paging`?: `SharedModel29`;
    `asked`?: string;
    `graph`?: `SharedModel34`;
    `cluster`?: get_admin_api_console_delegation_cluster_r200_application_json_cluster_h1398;
    `register`?: `SharedModel37`;
    `clusters`?: `SharedModel43`;
    `grantPage`?: `SharedModel46`;
    `permissionPage`?: `SharedModel47`;
    `groupPage`?: {`shown`?: `SharedModel44`; `paging`?: `SharedModel29`};
    `facts`?: `SharedModel24`;
    @js(#{`description`:"Each name in the answer the registry holds."}) `apps`?: Record<{`name`?: string; `dnLabel`?: string}>
  },
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
    `drawing`?: {
      `width`?: numeric;
      `height`?: numeric;
      `failed`?: NullableString
    };
    `looks`?: `SharedModel12`;
    `label`?: string;
    `svg`?: string;
    `graph`?: `SharedModel34`;
    `counts`?: `SharedModel42`;
    `grants`?: `SharedModel27`;
    `groups`?: `SharedModel32`;
    `groupCounts`?: {
      `clusters`?: integer;
      `applications`?: integer;
      `largest`?: integer;
      `alone`?: integer;
      `joined`?: integer
    };
    `groupsPaging`?: `SharedModel29`;
    `register`?: `SharedModel37`;
    `clusters`?: `SharedModel43`;
    `shownGroups`?: `SharedModel44`;
    `facts`?: `SharedModel24`;
    @js(#{`description`:"Each name in the answer the registry holds."}) `apps`?: Record<{`name`?: string; `dnLabel`?: string}>
  },
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
            `settings`:#{`type`:"array",`items`:#{`$ref`:"#/components/schemas/SharedModel48"}}
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
      `resources`?: `SharedModel38`;
      `permissions`?: `SharedModel30`;
      `grants`?: `SharedModel27`;
      `counts`?: `SharedModel42`;
      `filter`?: {
        `permissions`?: NullableString;
        `grants`?: NullableString
      };
      `paging`?: {`permissions`?: `SharedModel29`; `grants`?: `SharedModel29`}
    };
    `settings`?: get_admin_api_console_delegation_settings_r200_application_json_settings_h1402;
    `register`?: `SharedModel37`;
    `listState`?: {
      `permWanted`?: string;
      `grantWanted`?: string;
      `permPage`?: `SharedModel47`;
      `grantPage`?: `SharedModel46`
    };
    `allApplications`?: ({`identifier`?: string; `name`?: string})[]
  },
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
    `drawing`?: {
      `width`?: numeric;
      `height`?: numeric;
      `failed`?: NullableString
    };
    `looks`?: `SharedModel12`;
    `label`?: string;
    `svg`?: string;
    `chain`?: get_admin_api_console_delegation_chain_r200_application_json_chain_h1404;
    `chainKey`?: string;
    `found`?: boolean;
    `acts`?: `SharedModel50`;
    `graph`?: `SharedModel34`;
    `held`?: integer;
    `maxRecords`?: integer;
    `mapKey`?: string;
    `facts`?: `SharedModel24`
  },
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
    `persistence`?: {`enabled`?: boolean; `mode`?: string};
    `testDouble`?: boolean;
    `sections`?: `SharedModel2`
  },
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
    `realm`?: {`id`?: string; `name`?: string};
    `kinds`?: ({`kind`?: string; `label`?: string; `what`?: string})[];
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
      `families`?: ({`id`?: string; `label`?: string})[];
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
      `described`?: `SharedModel48`
    })[];
    `fieldGroups`?: ({`id`?: string; `label`?: string; `families`?: (string)[]})[];
    `familyChoices`?: ({
      `id`?: string;
      `label`?: string;
      `families`?: (string)[];
      `kind`?: string;
      `what`?: string
    })[];
    `longTextAttributes`?: (string)[];
    `defaultSecretLifetimeDays`?: numeric;
    `persistence`?: {
      `persistsDirectory`?: boolean;
      `mode`?: NullableString
    };
    `resourceMetadataImport`?: {
      `wellKnown`?: string;
      `acceptsNonconforming`?: boolean;
      `dialsInternalAddresses`?: boolean
    };
    `editable`?: ({
      `name`?: string;
      `mode`?: Shape9;
      `sensitive`?: boolean;
      `families`?: (string)[]
    })[]
  },
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
    `drawing`?: {
      `width`?: numeric;
      `height`?: numeric;
      `failed`?: NullableString
    };
    `looks`?: `SharedModel12`;
    `label`?: string;
    `svg`?: string;
    `user`?: get_admin_api_console_delegation_user_r200_application_json_user_h1415;
    `asked`?: NullableString;
    `key`?: string;
    `credentials`?: `SharedModel35`;
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
    `acts`?: `SharedModel50`;
    `graph`?: `SharedModel34`;
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
      `tokens`?: {
        `issued`?: integer;
        `valid`?: integer;
        `expired`?: integer;
        `revoked`?: integer;
        `other`?: integer
      };
      `artifacts`?: integer;
      `lastAt`?: numeric;
      `delegated`?: boolean;
      `acts`?: integer;
      `issued`?: integer;
      `refused`?: integer;
      `chains`?: integer;
      `roles`?: {`initial`?: integer; `intermediary`?: integer; `target`?: integer}
    })[];
    `usersComplete`?: boolean;
    `chooser`?: `SharedModel23`;
    `mapKey`?: string;
    `facts`?: `SharedModel24`
  },
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
    `drawing`?: {
      `width`?: numeric;
      `height`?: numeric;
      `failed`?: NullableString
    };
    `looks`?: `SharedModel12`;
    `label`?: string;
    `svg`?: string;
    `application`?: get_admin_api_console_delegation_application_r200_application_json_application_h1419;
    `asked`?: NullableString;
    `key`?: string;
    `registered`?: boolean;
    `registeredName`?: string;
    `acts`?: `SharedModel50`;
    `graph`?: `SharedModel34`;
    @js(#{`description`:"The roles played, by the act's `seq`."}) `rolesBySeq`?: Record<(string)[]>;
    `applications`?: ({
      `key`?: string;
      `identifier`?: string;
      `spellings`?: (string)[];
      `roles`?: {`initial`?: integer; `intermediary`?: integer; `target`?: integer};
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
    `roles`?: ({`role`?: string; `label`?: string; `what`?: string})[];
    `chooser`?: `SharedModel23`;
    `mapKey`?: string;
    `facts`?: `SharedModel24`
  },
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
  `responses/200/content/application~1json/schema`: `SharedModel52`,
  `responses/400/content/application~1json/schema`: `SharedModel52`,
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
  `responses/200/content/application~1json/schema`: `SharedModel52`,
  `responses/400/content/application~1json/schema`: `SharedModel52`,
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
  `responses/200/content/application~1json/schema`: `SharedModel52`,
  `responses/400/content/application~1json/schema`: `SharedModel52`,
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
  }) `requestBody/content/application~1json/schema`: {
    @js(#{`description`:"The `id` of a row in `workbench.objects`."}) `objectId`: string
  },
  `responses/200/content/application~1json/schema`: `SharedModel52`,
  `responses/400/content/application~1json/schema`: `SharedModel52`,
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
  `responses/200/content/application~1json/schema`: `SharedModel61`,
  `responses/400/content/application~1json/schema`: `SharedModel61`,
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

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
    `paths`: `SharedModel62`;
    `components`?: `SharedModel62`
  },
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  
}
