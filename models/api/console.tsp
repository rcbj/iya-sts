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

using IyaSts.ApiLib;

@apiDocument(#{
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

@hoisted union IssuedRecord_jti_v4_i_h1 {string, numeric, boolean}

@hoisted union IssuedRecord_jti_h2 {string, numeric, boolean, null, (IssuedRecord_jti_v4_i_h1)[]}

@hoisted union IssuedRecord_sub_v4_i_h3 {string, numeric, boolean}

@hoisted union IssuedRecord_sub_h4 {string, numeric, boolean, null, (IssuedRecord_sub_v4_i_h3)[]}

@hoisted union IssuedRecord_username_v4_i_h5 {string, numeric, boolean}

@hoisted union IssuedRecord_username_h6 {string, numeric, boolean, null, (IssuedRecord_username_v4_i_h5)[]}

@hoisted union IssuedRecord_typ_v4_i_h7 {string, numeric, boolean}

@hoisted union IssuedRecord_typ_h8 {string, numeric, boolean, null, (IssuedRecord_typ_v4_i_h7)[]}

@js(#{`$types`:#["number","null"]}) @hoisted model IssuedRecord_expiresAtMs_h9 {}

@js(#{`$types`:#["number","null"]}) @hoisted model IssuedRecord_revokedAt_h10 {}

@hoisted union IssuedRecord_client_id_v4_i_h11 {string, numeric, boolean}

@hoisted union IssuedRecord_client_id_h12 {string, numeric, boolean, null, (IssuedRecord_client_id_v4_i_h11)[]}

@hoisted union IssuedRecord_scope_v4_i_h13 {string, numeric, boolean}

@hoisted union IssuedRecord_scope_h14 {string, numeric, boolean, null, (IssuedRecord_scope_v4_i_h13)[]}

@hoisted union IssuedRecord_identifier_v4_i_h15 {string, numeric, boolean}

@hoisted union IssuedRecord_identifier_h16 {string, numeric, boolean, null, (IssuedRecord_identifier_v4_i_h15)[]}

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
    `jti`?: IssuedRecord_jti_h2;
    `sub`?: IssuedRecord_sub_h4;
    `username`?: IssuedRecord_username_h6;
    `typ`?: IssuedRecord_typ_h8;
    `issuedAt`?: numeric;
    `expiresAtMs`?: IssuedRecord_expiresAtMs_h9;
    `revocable`?: boolean;
    `revoked`?: boolean;
    `revokedAt`?: IssuedRecord_revokedAt_h10;
    `revokedVia`?: string;
    `sessionId`?: string;
    `setId`?: string;
    `jkt`?: string;
    `grant`?: string;
    `client_id`?: IssuedRecord_client_id_h12;
    `scope`?: IssuedRecord_scope_h14;
    `identifier`?: IssuedRecord_identifier_h16;
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

@js(#{`description`:"One operation."}) @hoisted model ApiIndex_operations_i_h17 {
    `method`?: string;
    `path`?: string;
    `operationId`?: string;
    `summary`?: string;
    @js(#{`description`:"The /admin control this operation is the API form of."}) `mirrors`?: string;
    @js(#{`description`:"Which of the two kinds the operation is (#454)."}) `kind`?: "management" | "console";
    @js(#{
      `description`:"The console pages drawn from this operation's data by one of the console's own operations (#454); present only where there are any."
    }) `drawnOn`?: (string)[]
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
    }) `operations`?: (ApiIndex_operations_i_h17)[]
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

@hoisted union Metrics_claims_i_claims_i_value_v4_i_h18 {string, numeric, boolean}

@hoisted union Metrics_claims_i_claims_i_value_h19 {
    string,
    numeric,
    boolean,
    null,
    (Metrics_claims_i_claims_i_value_v4_i_h18)[]
  }

@js(#{`$types`:#["integer","null"]}) @hoisted model Metrics_calls_rows_i_lastStatus_h20 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model Metrics_signOnSessions_held_h21 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model Metrics_signOnSessions_active_h22 {}

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
        `value`?: Metrics_claims_i_claims_i_value_h19;
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
        `lastStatus`?: Metrics_calls_rows_i_lastStatus_h20;
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
      `held`?: Metrics_signOnSessions_held_h21;
      `active`?: Metrics_signOnSessions_active_h22;
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

@hoisted union KeyList_settings_groups_i_settings_i_value_v4_i_h23 {string, numeric, boolean}

@js(#{
    `description`:"The effective value, coerced to its type: a number for int/port, a boolean for bool, an array of strings for csv."
  }) @hoisted union KeyList_settings_groups_i_settings_i_value_h24 {
    string,
    numeric,
    boolean,
    null,
    (KeyList_settings_groups_i_settings_i_value_v4_i_h23)[]
  }

@hoisted union KeyList_settings_groups_i_settings_i_default_v4_i_h25 {string, numeric, boolean}

@js(#{
    `description`:"The built-in default: the `dflt` column of `config.js`'s table, which `env/defaults.js` is GENERATED from. It is what the value WOULD be with nothing set anywhere."
  }) @hoisted union KeyList_settings_groups_i_settings_i_default_h26 {
    string,
    numeric,
    boolean,
    null,
    (KeyList_settings_groups_i_settings_i_default_v4_i_h25)[]
  }

@js(#{
    `description`:"One setting: what it is, what it is set to, and where that came from."
  }) @hoisted model KeyList_settings_groups_i_settings_i_h27 {
    @js(#{
      `description`:"The dot path, which is BOTH the name every operation here takes and the path in the appconfig file. `oid4vci.batchSize` is `appconfig.oid4vci.batchSize`."
    }) `key`?: string;
    @js(#{
      `description`:"The protocol it belongs to, and the console's section heading."
    }) `group`?: string;
    `label`?: string;
    @js(#{`description`:"What it does and why the default is the default."}) `description`?: string;
    @js(#{
      `description`:"How a value posted for it is coerced and checked: one of `config.js`'s types (string, int, port, bool, csv, enum, color)."
    }) `type`?: string;
    @js(#{`description`:"Present on `enum` settings only."}) `enumValues`?: (string)[];
    @js(#{
      `description`:"Present on a `csv` setting whose entries must each be one of these; absent on an open list."
    }) `csvValues`?: (string)[];
    @js(#{
      `description`:"Present, true, when a sensitive value here was replaced."
    }) `masked`?: boolean;
    @js(#{
      `description`:"Present, true, on a `csv` setting whose order is a preference: the first value is the most preferred."
    }) `ordered`?: boolean;
    @js(#{
      `description`:"Present beside `csvValues` where the setting describes each value: the value mapped to one sentence."
    }) `csvValueNotes`?: Record<string>;
    @js(#{
      `description`:"Present on an `ordered` setting whose select-all is narrowed by other settings. `onlyWhileOn`: the values are selected only while that setting is on. `aloneWhileOn`: while that setting is on, only the values are selected. `canBeOn` is false where this mode never lets that setting be on."
    }) `selectAll`?: {
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
    @js(#{
      `description`:"The lowest value POST /config/set will take, on an int setting that declares one."
    }) `min`?: numeric;
    @js(#{`description`:"The highest value it will take."}) `max`?: numeric;
    @js(#{
      `description`:"The value must be a MULTIPLE of this, counted from `min`. The four token lifetimes use 30."
    }) `step`?: numeric;
    `value`?: KeyList_settings_groups_i_settings_i_value_h24;
    @js(#{
      `description`:"The same value on one line: what the console shows in its input and what the environment variable would carry."
    }) `text`?: string;
    @js(#{
      `description`:"Where the effective value came from, highest first: this trust realm's own value; a runtime override set through this API or the console; the setting's own environment variable; a legacy variable (no row has one since #523); the appconfig file CONFIG_FILE names; `env/defaults.js`, the DEFAULT appconfig file that one is unioned on top of. `default` is reachable only for the DERIVED settings, whose value is a function of a neighbouring setting: for every other setting, no value anywhere stops this service from STARTING."
    }) `source`?: "realm" | "override" | "env" | "env-legacy" | "appconfig" | "defaults" | "default";
    @js(#{
      `description`:"Whether POST /config/set will take it from the realm this answer was read in. False means either the value was consumed at startup or `editRefusal` is set. It is refused rather than accepted, because an accepted change that does nothing reads as having worked."
    }) `editable`?: boolean;
    @js(#{
      `description`:"Why it is not editable, when the value was consumed at startup."
    }) `restartReason`?: string;
    @js(#{
      `description`:"Why this row cannot be edited from the realm the reader is in: `realms.maxCount` while a realm other than the default is ambient. Absent on every row of the default realm's answer."
    }) `editRefusal`?: string;
    @js(#{`description`:"Its environment variable."}) `env`?: string;
    `appconfigPath`?: string;
    `default`?: KeyList_settings_groups_i_settings_i_default_h26;
    @js(#{`description`:"Whether a trust realm may hold its own value for it."}) `realmSettable`?: boolean;
    @js(#{
      `description`:"Whether a runtime override is in force. Equal to `source === \"override\"`, and reported separately so a caller can filter without matching a string."
    }) `overridden`?: boolean
  }

@js(#{`description`:"One group's settings."}) @hoisted model KeyList_settings_groups_i_h28 {
    `group`?: string;
    `settings`?: (KeyList_settings_groups_i_settings_i_h27)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model KeyList_settings_context_configFile_h29 {}

@js(#{`$types`:#["string","null"]}) @hoisted model KeyList_settings_sharedWith_ap_i_label_h30 {}

@js(#{`$types`:#["string","null"]}) @hoisted model KeyList_keys_i_kty_h31 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `subject`:#{`type`:#["string","null"]},
      `issuedBy`:#{`type`:#["string","null"]},
      `notAfter`:#{`type`:#["string","null"]},
      `pinned`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model KeyList_keys_i_certifiedBy_h32 {}

@js(#{`$types`:#["string","null"]}) @hoisted model KeyList_keys_i_fingerprint_h33 {}

@js(#{`$types`:#["string","null"]}) @hoisted model KeyList_keys_i_subject_h34 {}

@js(#{`$types`:#["string","null"]}) @hoisted model KeyList_keys_i_notAfter_h35 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `kind`:#{`type`:"string"},
      `algorithm`:#{`type`:"string"},
      `label`:#{`type`:"string"},
      `family`:#{`type`:"string"},
      `standard`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model KeyList_keys_i_pqc_h36 {}

@js(#{`description`:"One key pair."}) @hoisted model KeyList_keys_i_h37 {
    @js(#{`description`:"What POST /admin-api/keys/export takes as `key`."}) `id`?: string;
    `label`?: string;
    `alg`?: string;
    `kty`?: KeyList_keys_i_kty_h31;
    `crv`?: string;
    `bits`?: numeric;
    @js(#{`description`:"Empty for the TLS key, which has a fingerprint instead."}) `kid`?: string;
    @js(#{`description`:"`realm` or `process`."}) `scope`?: string;
    `realm`?: string;
    @js(#{`description`:"Whether a PKCS#12 is possible."}) `hasCertificate`?: boolean;
    `generated`?: boolean;
    `certifiedBy`?: KeyList_keys_i_certifiedBy_h32;
    @js(#{`description`:"Empty means not exportable."}) `formats`?: (string)[];
    `usedFor`?: (string)[];
    `fingerprint`?: KeyList_keys_i_fingerprint_h33;
    `subject`?: KeyList_keys_i_subject_h34;
    `names`?: (string)[];
    `notAfter`?: KeyList_keys_i_notAfter_h35;
    `pqc`?: KeyList_keys_i_pqc_h36
  }

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `scheduled`:#{`type`:"boolean"},
      `offReason`:#{`type`:"string"},
      `units`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `unit`:#{`type`:"string"},
            `current`:#{`type`:#["string","null"]},
            `next`:#{
              `type`:#["object","null"],
              `additionalProperties`:false,
              `properties`:#{`kid`:#{`type`:"string"},`since`:#{`type`:#["string","null"]}}
            },
            `retired`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `kid`:#{`type`:"string"},
                  `retiredAt`:#{`type`:#["string","null"]},
                  `verifiesUntil`:#{`type`:#["string","null"]}
                }
              }
            },
            `lastRotated`:#{`type`:#["string","null"]},
            `intervalDays`:#{`type`:"number"},
            `graceDays`:#{`type`:"number"},
            `credentialSigner`:#{`type`:"boolean"}
          }
        }
      },
      `refresh`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `lastRotated`:#{`type`:#["string","null"]},
          `retired`:#{`type`:"integer"},
          `graceDays`:#{`type`:"number"}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model KeyList_rotation_h38 {}

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
      @js(#{`description`:"In the order `config.js` declares them."}) `groups`?: (KeyList_settings_groups_i_h28)[];
      `settingCount`?: integer;
      @js(#{`description`:"How many of them can be changed while the service runs."}) `editableCount`?: integer;
      @js(#{`description`:"The keys on this page with a runtime override in force."}) `overridden`?: (string)[];
      @js(#{`description`:"The operation that writes them."}) `setWith`?: string;
      `context`?: {
        `configFile`?: KeyList_settings_context_configFile_h29;
        `defaultsFile`?: string;
        `persistsAppconfig`?: boolean;
        `persistsRealms`?: boolean;
        `persistenceMode`?: string;
        `inRealm`?: boolean;
        `realmId`?: string
      };
      @js(#{`description`:"A group drawn on another page as well, and those pages."}) `sharedWith`?: Record<({`path`?: string; `label`?: KeyList_settings_sharedWith_ap_i_label_h30})[]>
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
    `keys`?: (KeyList_keys_i_h37)[];
    `rotation`?: KeyList_rotation_h38;
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

@js(#{`description`:"One file."}) @hoisted model KeyExport_files_i_h39 {`name`?: string; `mime`?: string; `bytes`?: integer; `base64`?: string}

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
    `files`?: (KeyExport_files_i_h39)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_signing_certificateFingerprint_h40 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_curveKeys_i_kid_h41 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_curveKeys_i_certificateFingerprint_h42 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_postQuantum_keys_i_kid_h43 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_postQuantum_keys_i_certificateFingerprint_h44 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_signerGroups_keys_i_kind_h45 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_signerGroups_keys_i_kid_h46 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_signerGroups_keys_i_pairedSlot_h47 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_signerGroups_keys_i_certificateFingerprint_h48 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_tls_subject_h49 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_tls_fingerprint256_h50 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_tls_certificates_i_algorithm_h51 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_tls_certificates_i_certificateFingerprint_h52 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_tls_notAfter_h53 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_spiffe_trustDomain_h54 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_keys_spiffe_authorityFingerprint_h55 {}

@hoisted union CryptoMetadata_families_i_algorithms_i_values_i_h56 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_signatures_jws_i_family_h57 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_signatures_xml_i_family_h58 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_signatures_xml_i_hash_h59 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_signatures_xml_i_keyKind_h60 {}

@js(#{`$types`:#["boolean","null"]}) @hoisted model CryptoMetadata_signatures_canonicalization_i_exclusive_h61 {}

@js(#{`$types`:#["boolean","null"]}) @hoisted model CryptoMetadata_signatures_canonicalization_i_comments_h62 {}

@js(#{`$types`:#["boolean","null"]}) @hoisted model CryptoMetadata_signatures_canonicalization_i_usedHere_h63 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_encryption_jwe_contentEncryption_i_note_h64 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_postQuantum_algorithms_composite_i_mlDsa_h65 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_postQuantum_algorithms_composite_i_traditional_h66 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_postQuantum_algorithms_composite_i_prehash_h67 {}

@js(#{`$types`:#["string","null"]}) @hoisted model CryptoMetadata_postQuantum_algorithms_composite_i_domainSeparator_h68 {}

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
        `certificateFingerprint`?: CryptoMetadata_keys_signing_certificateFingerprint_h40;
        `what`?: string
      };
      `curveKeys`?: ({
        `alg`?: string;
        `kty`?: string;
        `crv`?: string;
        `kid`?: CryptoMetadata_keys_curveKeys_i_kid_h41;
        `certificateFingerprint`?: CryptoMetadata_keys_curveKeys_i_certificateFingerprint_h42
      })[];
      `postQuantum`?: {
        `algorithms`?: (string)[];
        `generated`?: boolean;
        `keys`?: ({
          `alg`?: string;
          `kty`?: string;
          `kid`?: CryptoMetadata_keys_postQuantum_keys_i_kid_h43;
          `certificateFingerprint`?: CryptoMetadata_keys_postQuantum_keys_i_certificateFingerprint_h44
        })[];
        `what`?: string
      };
      `signerGroups`?: {
        `model`?: string;
        `keys`?: ({
          `group`?: string;
          `slot`?: string;
          `alg`?: string;
          `kind`?: CryptoMetadata_keys_signerGroups_keys_i_kind_h45;
          `kid`?: CryptoMetadata_keys_signerGroups_keys_i_kid_h46;
          `pairedSlot`?: CryptoMetadata_keys_signerGroups_keys_i_pairedSlot_h47;
          `certificateFingerprint`?: CryptoMetadata_keys_signerGroups_keys_i_certificateFingerprint_h48
        })[]
      };
      `bbs`?: {`cryptosuite`?: string; `curve`?: string; `what`?: string};
      `tls`?: {
        `subject`?: CryptoMetadata_keys_tls_subject_h49;
        `names`?: (string)[];
        `fingerprint256`?: CryptoMetadata_keys_tls_fingerprint256_h50;
        `certificates`?: ({
          `algorithm`?: CryptoMetadata_keys_tls_certificates_i_algorithm_h51;
          `certificateFingerprint`?: CryptoMetadata_keys_tls_certificates_i_certificateFingerprint_h52
        })[];
        `notAfter`?: CryptoMetadata_keys_tls_notAfter_h53;
        `perRealm`?: boolean;
        `what`?: string
      };
      `spiffe`?: {
        `enabled`?: boolean;
        `ready`?: boolean;
        `perRealm`?: boolean;
        `trustDomain`?: CryptoMetadata_keys_spiffe_trustDomain_h54;
        `authoritySource`?: string;
        `svidKeyType`?: string;
        `authorityKeyType`?: string;
        `x509KeyType`?: string;
        `jwtKeyType`?: string;
        `x509Authorities`?: integer;
        `authorityFingerprint`?: CryptoMetadata_keys_spiffe_authorityFingerprint_h55;
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
        `values`?: (CryptoMetadata_families_i_algorithms_i_values_i_h56)[];
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
        `family`?: CryptoMetadata_signatures_jws_i_family_h57;
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
        `family`?: CryptoMetadata_signatures_xml_i_family_h58;
        `hash`?: CryptoMetadata_signatures_xml_i_hash_h59;
        `keyKind`?: CryptoMetadata_signatures_xml_i_keyKind_h60;
        `verifiedHere`?: boolean;
        `signsWith`?: boolean
      })[];
      `canonicalization`?: ({
        `uri`?: string;
        `label`?: string;
        `exclusive`?: CryptoMetadata_signatures_canonicalization_i_exclusive_h61;
        `comments`?: CryptoMetadata_signatures_canonicalization_i_comments_h62;
        `usedHere`?: CryptoMetadata_signatures_canonicalization_i_usedHere_h63
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
          `note`?: CryptoMetadata_encryption_jwe_contentEncryption_i_note_h64
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
          `mlDsa`?: CryptoMetadata_postQuantum_algorithms_composite_i_mlDsa_h65;
          `traditional`?: CryptoMetadata_postQuantum_algorithms_composite_i_traditional_h66;
          `prehash`?: CryptoMetadata_postQuantum_algorithms_composite_i_prehash_h67;
          `domainSeparator`?: CryptoMetadata_postQuantum_algorithms_composite_i_domainSeparator_h68
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

@js(#{`$types`:#["string","null"]}) @hoisted model SessionList_filter_q_h69 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SessionList_filter_protocol_h70 {}

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
      `q`?: SessionList_filter_q_h69;
      `protocol`?: SessionList_filter_protocol_h70
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

@hoisted union SessionRow_amr_h71 {string, (string)[]}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `bound`:#{`type`:"boolean"},
      `fact`:#{`type`:"string"},
      `alg`:#{`type`:"string"},
      `boundAt`:#{`type`:"number"},
      `refreshedAt`:#{`type`:"number"},
      `refreshes`:#{`type`:"number"},
      `reasons`:#{`type`:"array",`items`:#{`type`:"string"}}
    },
    `$types`:#["object","null"]
  }) @hoisted model SessionRow_deviceBound_h72 {}

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
    `amr`?: SessionRow_amr_h71;
    `acr`?: string;
    `deviceBound`?: SessionRow_deviceBound_h72;
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

@js(#{`$types`:#["number","null"]}) @hoisted model UserList_directoryPeople_h73 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `people`:#{`type`:"number"},
      `withSecond`:#{`type`:"number"},
      `withTotp`:#{`type`:"number"},
      `withKeys`:#{`type`:"number"},
      `primaryKeys`:#{`type`:"number"},
      `unreadable`:#{`type`:"number"},
      `withPassword`:#{`type`:"number"},
      `passwordOnly`:#{`type`:"number"},
      `noWayIn`:#{`type`:"number"},
      `signedInHere`:#{`type`:#["number","null"]},
      `neverSignedInHere`:#{`type`:#["number","null"]}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserList_directoryCounts_h74 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserList_directoryCountedAt_h75 {}

@js(#{`$types`:#["number","null"]}) @hoisted model UserList_directoryCountsKeptFor_h76 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserList_filter_q_h77 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserList_filter_protocol_h78 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserList_filter_factor_h79 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserList_filter_kind_h80 {}

@js(#{`$types`:#["number","null"]}) @hoisted model UserList_withActiveSession_h81 {}

@hoisted union UserList_users_i_events_i_amr_h82 {string, (string)[]}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `username`:#{`type`:"string"},
      `inDirectory`:#{`type`:"boolean"},
      `known`:#{`type`:"boolean"},
      `password`:#{`type`:"boolean"},
      `primaryKeys`:#{`type`:"number"},
      `mfaKeys`:#{`type`:"number"},
      `totp`:#{`type`:"boolean"},
      `totpUsable`:#{`type`:"boolean"},
      `totpDetail`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `enrolledAt`:#{`type`:"number"},
          `lastUsedAt`:#{`type`:"number"},
          `algorithm`:#{`type`:"string"},
          `digits`:#{`type`:"number"},
          `period`:#{`type`:"number"},
          `sealed`:#{`type`:"boolean"},
          `unusable`:#{`type`:"boolean"},
          `why`:#{`type`:"string"}
        }
      },
      `backupCodes`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `present`:#{`type`:"boolean"},
          `usable`:#{`type`:"boolean"},
          `total`:#{`type`:"number"},
          `remaining`:#{`type`:"number"},
          `used`:#{`type`:"number"},
          `generatedAt`:#{`type`:"number"},
          `lastUsedAt`:#{`type`:"number"},
          `sealed`:#{`type`:"boolean"},
          `hashed`:#{`type`:"boolean"},
          `legacy`:#{`type`:"boolean"},
          `why`:#{`type`:"string"}
        }
      },
      `recoveryAdvised`:#{`type`:"boolean"},
      `mfaRequired`:#{`type`:"boolean"},
      `secondFactor`:#{`type`:#["string","null"]},
      `usable`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserList_users_i_factors_h83 {}

@js(#{`$types`:#["number","null"]}) @hoisted model UserList_users_i_liveSessions_h84 {}

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
    `directoryPeople`?: UserList_directoryPeople_h73;
    `directoryCounts`?: UserList_directoryCounts_h74;
    `directoryCountedAt`?: UserList_directoryCountedAt_h75;
    `directoryCountsKeptFor`?: UserList_directoryCountsKeptFor_h76;
    `registryCap`?: numeric;
    `filter`?: {
      `q`?: UserList_filter_q_h77;
      `protocol`?: UserList_filter_protocol_h78;
      `factor`?: UserList_filter_factor_h79;
      `kind`?: UserList_filter_kind_h80
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
    `withActiveSession`?: UserList_withActiveSession_h81;
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
        `amr`?: UserList_users_i_events_i_amr_h82;
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
      `factors`?: UserList_users_i_factors_h83;
      `inDirectory`?: boolean;
      `serviceAccount`?: boolean;
      `liveSessions`?: UserList_users_i_liveSessions_h84;
      `dn`?: string
    })[]
  }

@hoisted union UserDetail_user_events_i_amr_h85 {string, (string)[]}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `username`:#{`type`:"string"},
      `owners`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `dn`:#{`type`:"string"},
            `kind`:#{`type`:"string"},
            `name`:#{`type`:"string"},
            `present`:#{`type`:"boolean"}
          }
        }
      },
      `ownership`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `kind`:#{`type`:"string"},
          `name`:#{`type`:"string"},
          `marked`:#{`type`:"boolean"},
          `protected`:#{`type`:"boolean"},
          `reasons`:#{`type`:"array",`items`:#{`type`:"string"}}
        }
      },
      `destination`:#{`type`:#["string","null"]},
      `secretName`:#{`type`:#["string","null"]},
      `rotatedAt`:#{`type`:#["string","null"]},
      `previousPasswordUntil`:#{`type`:#["string","null"]},
      `rotation`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `enabled`:#{`type`:"boolean"},
          `rotates`:#{`type`:"boolean"},
          `nextDueAt`:#{`type`:#["string","null"]},
          `failures`:#{`type`:"number"},
          `lastError`:#{`type`:#["string","null"]},
          `lastAttemptAt`:#{`type`:#["string","null"]},
          `alarm`:#{`type`:"boolean"}
        }
      },
      `policy`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `exemptFromSecondFactor`:#{`type`:"boolean"},
          `allowBrowserSignIn`:#{`type`:"boolean"},
          `doors`:#{`type`:"array",`items`:#{`type`:"string"}},
          `requiresOwner`:#{`type`:"boolean"},
          `from`:#{`type`:"string"},
          `name`:#{`type`:#["string","null"]}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_serviceAccount_h86 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `subject`:#{`type`:"string"},
      `level`:#{`type`:"string"},
      `score`:#{`type`:"number"},
      `previousLevel`:#{`type`:"string"},
      `reason`:#{`type`:"string"},
      `lastAssessment`:#{`type`:"string"},
      `crossedAt`:#{`type`:"number"},
      `updatedAt`:#{`type`:"number"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_risk_h87 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `password`:#{`type`:"boolean"},
      `passwordChangeRequired`:#{`type`:"boolean"},
      `passwordResetLink`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{`expires`:#{`type`:"number"},`expired`:#{`type`:"boolean"}}
      },
      `disabled`:#{`type`:"boolean"},
      `mfaRequirement`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `required`:#{`type`:"boolean"},
          `byUser`:#{`type`:"boolean"},
          `byRealm`:#{`type`:"boolean"},
          `byAdministrator`:#{`type`:"boolean"},
          `offered`:#{`type`:"boolean"},
          `exemptServiceAccount`:#{`type`:"boolean"}
        }
      },
      `usable`:#{`type`:"boolean"},
      `activated`:#{`type`:"boolean"},
      `mfaRequired`:#{`type`:"boolean"},
      `secondFactor`:#{`type`:#["string","null"]},
      `totp`:#{`type`:"boolean"},
      `totpUsable`:#{`type`:"boolean"},
      `totpDetail`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `enrolledAt`:#{`type`:"number"},
          `lastUsedAt`:#{`type`:"number"},
          `algorithm`:#{`type`:"string"},
          `digits`:#{`type`:"number"},
          `period`:#{`type`:"number"},
          `sealed`:#{`type`:"boolean"},
          `unusable`:#{`type`:"boolean"},
          `why`:#{`type`:"string"}
        }
      },
      `backupCodes`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `present`:#{`type`:"boolean"},
          `usable`:#{`type`:"boolean"},
          `total`:#{`type`:"number"},
          `remaining`:#{`type`:"number"},
          `used`:#{`type`:"number"},
          `generatedAt`:#{`type`:"number"},
          `lastUsedAt`:#{`type`:"number"},
          `sealed`:#{`type`:"boolean"},
          `hashed`:#{`type`:"boolean"},
          `legacy`:#{`type`:"boolean"},
          `why`:#{`type`:"string"}
        }
      },
      `keys`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `credentialId`:#{`type`:"string"},
            `label`:#{`type`:#["string","null"]},
            `signCount`:#{`type`:"number"},
            `enrolledAt`:#{`type`:"number"},
            `aaguid`:#{`type`:#["string","null"]},
            `algorithm`:#{
              `type`:"object",
              `additionalProperties`:false,
              `properties`:#{
                `name`:#{`type`:"string"},
                `coseAlg`:#{`type`:#["number","null"]},
                `text`:#{`type`:"string"},
                `postQuantum`:#{`type`:"boolean"},
                `insecure`:#{`type`:"boolean"},
                `lane`:#{`type`:"string"}
              }
            },
            `lane`:#{`type`:"string"},
            `attestation`:#{
              `type`:#["object","null"],
              `additionalProperties`:false,
              `properties`:#{
                `policy`:#{`type`:"string"},
                `format`:#{`type`:"string"},
                `type`:#{`type`:"string"},
                `verified`:#{`type`:"boolean"},
                `trusted`:#{`type`:"boolean"},
                `anchor`:#{`type`:"string"},
                `aaguid`:#{`type`:#["string","null"]},
                `model`:#{`type`:"string"},
                `certificationLevel`:#{`type`:"string"},
                `mdsStatus`:#{`type`:"string"},
                `mdsVersion`:#{
                  `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
                },
                `checkedAt`:#{`type`:"number"},
                `algorithms`:#{
                  `type`:#["object","null"],
                  `additionalProperties`:false,
                  `properties`:#{
                    `statement`:#{`type`:"string"},
                    `statementCoseAlg`:#{`type`:#["integer","null"]},
                    `certificates`:#{
                      `type`:"array",
                      `items`:#{
                        `type`:"object",
                        `additionalProperties`:false,
                        `properties`:#{
                          `algorithm`:#{`type`:"string"},
                          `oid`:#{`type`:"string"},
                          `family`:#{`type`:"string"},
                          `postQuantum`:#{`type`:"boolean"},
                          `composite`:#{`type`:"boolean"}
                        }
                      }
                    },
                    `anchor`:#{
                      `type`:#["object","null"],
                      `additionalProperties`:false,
                      `properties`:#{
                        `algorithm`:#{`type`:"string"},
                        `oid`:#{`type`:"string"},
                        `family`:#{`type`:"string"},
                        `postQuantum`:#{`type`:"boolean"},
                        `composite`:#{`type`:"boolean"}
                      }
                    },
                    `postQuantum`:#{`type`:"boolean"},
                    `members`:#{
                      `type`:"array",
                      `items`:#{
                        `type`:"object",
                        `additionalProperties`:false,
                        `properties`:#{
                          `format`:#{`type`:"string"},
                          `statement`:#{`type`:"string"},
                          `statementCoseAlg`:#{`type`:#["integer","null"]},
                          `certificates`:#{
                            `type`:"array",
                            `items`:#{
                              `type`:"object",
                              `additionalProperties`:false,
                              `properties`:#{
                                `algorithm`:#{`type`:"string"},
                                `oid`:#{`type`:"string"},
                                `family`:#{`type`:"string"},
                                `postQuantum`:#{`type`:"boolean"},
                                `composite`:#{`type`:"boolean"}
                              }
                            }
                          },
                          `anchor`:#{
                            `type`:#["object","null"],
                            `additionalProperties`:false,
                            `properties`:#{
                              `algorithm`:#{`type`:"string"},
                              `oid`:#{`type`:"string"},
                              `family`:#{`type`:"string"},
                              `postQuantum`:#{`type`:"boolean"},
                              `composite`:#{`type`:"boolean"}
                            }
                          }
                        }
                      }
                    }
                  }
                },
                `conveyance`:#{`type`:"string"},
                `enterpriseDowngraded`:#{`type`:"boolean"},
                `attestationKeyId`:#{`type`:"string"},
                `deviceSerial`:#{`type`:"string"},
                `deviceSerialSource`:#{`type`:"string"},
                `evidence`:#{
                  `type`:"object",
                  `additionalProperties`:false,
                  `properties`:#{
                    `syntax`:#{`type`:"string"},
                    `version`:#{`type`:"number"},
                    `object`:#{`type`:"string"},
                    `objectDigest`:#{`type`:"string"},
                    `evidenceRecord`:#{`type`:"string"},
                    `timestamps`:#{`type`:"array",`items`:#{`type`:"string"}},
                    `createdAt`:#{
                      `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
                    },
                    `renewedAt`:#{
                      `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
                    },
                    `renewAfter`:#{
                      `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
                    },
                    `hashAlgorithm`:#{`type`:"string"},
                    `tsa`:#{`type`:#["string","null"]}
                  }
                },
                `androidRevocation`:#{
                  `type`:"object",
                  `additionalProperties`:false,
                  `properties`:#{
                    `status`:#{`type`:"string"},
                    `reason`:#{`type`:"string"},
                    `serial`:#{`type`:"string"},
                    `listVersion`:#{`type`:"string"},
                    `checkedAt`:#{
                      `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
                    },
                    `chainSerials`:#{`type`:"array",`items`:#{`type`:"string"}},
                    `why`:#{`type`:"string"}
                  }
                }
              }
            },
            `attestationAlgorithms`:#{
              `type`:"object",
              `additionalProperties`:false,
              `properties`:#{
                `verified`:#{`type`:"boolean"},
                `trusted`:#{`type`:"boolean"},
                `recorded`:#{`type`:"boolean"},
                `statement`:#{`type`:"string"},
                `statements`:#{`type`:"array",`items`:#{`type`:"string"}},
                `certificates`:#{
                  `type`:"array",
                  `items`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `algorithm`:#{`type`:"string"},
                      `family`:#{`type`:"string"},
                      `postQuantum`:#{`type`:"boolean"}
                    }
                  }
                },
                `postQuantum`:#{`type`:"boolean"}
              }
            },
            `name`:#{`type`:"string"},
            `group`:#{`type`:"string"},
            `provider`:#{`type`:#["string","null"]},
            `lastUsedAt`:#{`type`:"number"},
            `backupEligible`:#{`type`:#["boolean","null"]},
            `backupState`:#{`type`:#["boolean","null"]},
            `transports`:#{`type`:"array",`items`:#{`type`:"string"}},
            `discoverable`:#{`type`:#["boolean","null"]},
            `deviceSerial`:#{`type`:#["string","null"]},
            `possiblyReplaced`:#{
              `type`:#["object","null"],
              `additionalProperties`:false,
              `properties`:#{`by`:#{`type`:"string"},`at`:#{`type`:"number"}}
            },
            `withoutUsername`:#{
              `type`:"object",
              `additionalProperties`:false,
              `properties`:#{`ready`:#{`type`:"boolean"},`text`:#{`type`:"string"}}
            },
            `postQuantumRefused`:#{`type`:"string"}
          }
        }
      },
      `primaryKeys`:#{`type`:"number"},
      `mfaKeys`:#{`type`:"number"},
      `appPasswords`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `id`:#{`type`:"string"},
            `name`:#{`type`:"string"},
            `doors`:#{`type`:"array",`items`:#{`type`:"string"}},
            `doorLabels`:#{`type`:"array",`items`:#{`type`:"string"}},
            `createdAt`:#{`type`:"number"},
            `createdBy`:#{`type`:"string"},
            `lastUsedAt`:#{`type`:"number"},
            `lastUsedDoor`:#{`type`:"string"}
          }
        }
      },
      `passwordOnlyDoors`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `secondFactor`:#{`type`:"boolean"},
          `refused`:#{`type`:"array",`items`:#{`type`:"string"}},
          `accepted`:#{`type`:"array",`items`:#{`type`:"string"}},
          `passwordAloneDoors`:#{`type`:"array",`items`:#{`type`:"string"}},
          `sentence`:#{`type`:"string"}
        }
      },
      `policy`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `totpEnabled`:#{`type`:"boolean"},
          `backupCodesEnabled`:#{`type`:"boolean"},
          `backupCodesCount`:#{`type`:"number"},
          `webauthnEnabled`:#{`type`:"boolean"},
          `primaryAllowed`:#{`type`:"boolean"},
          `mfaAllowed`:#{`type`:"boolean"},
          `maxKeysPerPerson`:#{`type`:"number"}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_factors_h88 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `bound`:#{`type`:"boolean"},
      `fact`:#{`type`:"string"},
      `alg`:#{`type`:"string"},
      `boundAt`:#{`type`:"number"},
      `refreshedAt`:#{`type`:"number"},
      `refreshes`:#{`type`:"number"},
      `reasons`:#{`type`:"array",`items`:#{`type`:"string"}}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_sessions_i_deviceBound_h89 {}

@hoisted union UserDetail_sessions_i_tokens_i_client_id_h90 {string, (string)[]}

@hoisted union UserDetail_sessions_i_tokens_i_scope_h91 {string, (string)[]}

@hoisted union UserDetail_tokensOnEndedSessions_i_client_id_h92 {string, (string)[]}

@hoisted union UserDetail_tokensOnEndedSessions_i_scope_h93 {string, (string)[]}

@hoisted union UserDetail_tokensWithNoSession_i_client_id_h94 {string, (string)[]}

@hoisted union UserDetail_tokensWithNoSession_i_scope_h95 {string, (string)[]}

@hoisted union UserDetail_artifacts_i_expiresAt_v1_h96 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_artifacts_i_expiresAt_h97 {null, UserDetail_artifacts_i_expiresAt_v1_h96}

@hoisted union UserDetail_artifacts_i_etype_h98 {string, numeric}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `dn`:#{`type`:"string"},
      `found`:#{`type`:"boolean"},
      `entry`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `dn`:#{`type`:"string"},
          `origin`:#{`type`:"string"},
          `createdAt`:#{
            `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
          },
          `modifiedAt`:#{
            `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
          },
          `operational`:#{`type`:"array",`items`:#{`type`:"string"}},
          `attributes`:#{
            `type`:"object",
            `additionalProperties`:#{
              `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
            }
          },
          `rule`:#{`type`:"string"},
          `members`:#{
            `type`:"array",
            `items`:#{
              `type`:"object",
              `additionalProperties`:false,
              `properties`:#{
                `value`:#{`type`:"string"},
                `attribute`:#{`type`:"string"},
                `holds`:#{`type`:"string"},
                `dn`:#{`type`:"string"},
                `present`:#{`type`:"boolean"},
                `kind`:#{`type`:"string"},
                `userKey`:#{`type`:"string"},
                `cn`:#{`type`:"string"},
                `mail`:#{`type`:"string"},
                `displayName`:#{`type`:"string"}
              }
            }
          }
        }
      },
      `alsoNamed`:#{`type`:"array",`items`:#{`type`:"string"}},
      `baseDn`:#{`type`:"string"},
      `usersDn`:#{`type`:"string"},
      `port`:#{`type`:#["number","null"]},
      `listening`:#{`type`:"boolean"},
      `listenError`:#{`type`:#["string","null"]},
      `ldapsPort`:#{`type`:#["number","null"]},
      `ldapsListening`:#{`type`:"boolean"},
      `autoCreateUsers`:#{`type`:"boolean"},
      `entryCount`:#{`type`:"number"},
      `maxEntries`:#{`type`:"number"},
      `full`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_ldap_h99 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `subject`:#{`type`:"string"},
      `issuer`:#{`type`:"string"},
      `serialHex`:#{`type`:"string"},
      `notBefore`:#{`type`:"string"},
      `notAfter`:#{`type`:"string"},
      `expired`:#{`type`:"boolean"},
      `selfSigned`:#{`type`:"boolean"},
      `keyType`:#{`type`:"string"},
      `thumbprint`:#{`type`:"string"},
      `unreadable`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_credentials_keyPairs_i_keys_i_certificate_h100 {}

@js(#{`$types`:#["boolean","null"]}) @hoisted model UserDetail_kerberos_productKdc_h101 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `kvno`:#{`type`:#["number","null"]},
      `etypes`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{`etype`:#{`type`:"number"},`name`:#{`type`:"string"}}
        }
      },
      `derivedAt`:#{`type`:"string"},
      `derivedOn`:#{`type`:"string"},
      `sealed`:#{`type`:"boolean"},
      `current`:#{`type`:"boolean"},
      `retained`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `kvno`:#{`type`:#["number","null"]},
            `etypes`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{`etype`:#{`type`:"number"},`name`:#{`type`:"string"}}
              }
            },
            `retiredAt`:#{`type`:"string"},
            `expiresAt`:#{`type`:"string"}
          }
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_kerberos_keys_h102 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `dn`:#{`type`:"string"},
      `attributes`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `name`:#{`type`:"string"},
            `label`:#{`type`:"string"},
            `schema`:#{`type`:"string"},
            `note`:#{`type`:"string"},
            `simple`:#{`type`:"boolean"},
            `must`:#{`type`:"boolean"},
            `format`:#{`type`:"string"},
            `custom`:#{`type`:"boolean"},
            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
            `required`:#{`type`:"boolean"},
            `why`:#{`type`:"string"},
            `example`:#{`type`:"string"},
            `editable`:#{`type`:"boolean"},
            `group`:#{`type`:"string"},
            `multi`:#{`type`:"boolean"},
            `choices`:#{`type`:"array",`items`:#{`type`:"string"}}
          }
        }
      },
      `withheld`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `name`:#{`type`:"string"},
            `label`:#{`type`:"string"},
            `kind`:#{`type`:"string"},
            `why`:#{`type`:"string"}
          }
        }
      },
      `mail`:#{`type`:"string"},
      `pseudonyms`:#{`type`:"array",`items`:#{`type`:"string"}},
      `pseudonymPending`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_attributeEditor_h103 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `reason`:#{`type`:"string"},
      `at`:#{`type`:"number"},
      `note`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_gnapGrants_i_finalization_h104 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserDetail_gnapGrants_i_client_h105 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserDetail_gnapGrants_i_clientName_h106 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserDetail_gnapGrants_i_authorizationServer_h107 {}

@js(#{`$types`:#["number","null"]}) @hoisted model UserDetail_gnapGrants_i_createdAt_h108 {}

@js(#{`$types`:#["number","null"]}) @hoisted model UserDetail_gnapGrants_i_updatedAt_h109 {}

@js(#{`$types`:#["number","null"]}) @hoisted model UserDetail_gnapGrants_i_grantExpiresAt_h110 {}

@js(#{`$types`:#["number","null"]}) @hoisted model UserDetail_gnapGrants_i_subjectReleasedAt_h111 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserDetail_gnapGrants_i_derivedFrom_h112 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserDetail_gnapGrants_i_tokens_i_label_h113 {}

@js(#{`$types`:#["number","null"]}) @hoisted model UserDetail_gnapGrants_i_tokens_i_issuedAt_h114 {}

@js(#{`$types`:#["number","null"]}) @hoisted model UserDetail_gnapGrants_i_tokens_i_expiresAt_h115 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserDetail_gnapGrants_i_tokens_i_revokedWhy_h116 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `page`:#{`type`:"integer"},
      `pages`:#{`type`:"integer"},
      `perPage`:#{`type`:"integer"},
      `firstRow`:#{`type`:"integer"},
      `lastRow`:#{`type`:"integer"},
      `total`:#{`type`:"integer"},
      `param`:#{`type`:"string"},
      `noun`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_gnapGrantsPaging_h117 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `multiCell`:#{`type`:"boolean"},
      `cell`:#{`type`:"string"},
      `complete`:#{`type`:"boolean"},
      `note`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_gnapGrantsCells_h118 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `user`:#{`type`:"string"},
      `resources`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `id`:#{`type`:"string"},
            `name`:#{`type`:"string"},
            `type`:#{`type`:"string"},
            `scopes`:#{`type`:"array",`items`:#{`type`:"string"}},
            `resourceServer`:#{`type`:"string"},
            `owner`:#{`type`:"string"},
            `ownerKind`:#{`type`:"string"},
            `createdAt`:#{`type`:"number"}
          }
        }
      },
      `shares`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `id`:#{`type`:"string"},
            `resourceId`:#{`type`:"string"},
            `scopes`:#{`type`:"array",`items`:#{`type`:"string"}},
            `recipient`:#{
              `type`:"object",
              `additionalProperties`:false,
              `properties`:#{
                `kind`:#{`type`:"string"},
                `value`:#{`type`:"string"},
                `label`:#{`type`:"string"}
              }
            },
            `expires`:#{`type`:"string"},
            `acr`:#{`type`:"string"},
            `askMe`:#{`type`:"boolean"}
          }
        }
      },
      `held`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `jti`:#{`type`:"string"},
            `requestingParty`:#{`type`:"string"},
            `client`:#{`type`:"string"},
            `resourceServer`:#{`type`:"string"},
            `permissions`:#{
              `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
            },
            `upgradedFrom`:#{`type`:"string"},
            `createdAt`:#{`type`:"number"},
            `exp`:#{`type`:"number"}
          }
        }
      },
      `pending`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `id`:#{`type`:"string"},
            `state`:#{`type`:"string"},
            `owner`:#{`type`:"string"},
            `ownerKind`:#{`type`:"string"},
            `requester`:#{`type`:"string"},
            `client`:#{`type`:"string"},
            `resourceServer`:#{`type`:"string"},
            `permissions`:#{
              `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
            },
            `createdAt`:#{`type`:"number"},
            `expiresAt`:#{`type`:"number"}
          }
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_uma_h119 {}

@hoisted union UserDetail_page_params_ap_v0_h120 {string, numeric, boolean, null}

@hoisted union UserDetail_page_params_ap_v1_i_h121 {string, numeric, boolean, null}

@hoisted union UserDetail_page_params_ap_h122 {
    UserDetail_page_params_ap_v0_h120,
    (UserDetail_page_params_ap_v1_i_h121)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model UserDetail_page_mfa_mech_keys_i_attachment_h123 {}

@js(#{`$types`:#["boolean","null"]}) @hoisted model UserDetail_page_mfa_mech_keys_i_userVerified_h124 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserDetail_page_mfa_mech_keys_i_aaguid_h125 {}

@js(#{`$types`:#["number","null"]}) @hoisted model UserDetail_page_mfa_mech_keys_i_algorithm_v0_coseAlg_h126 {}

@hoisted union UserDetail_page_mfa_mech_keys_i_algorithm_h127 {
    {
      `name`?: string;
      `coseAlg`?: UserDetail_page_mfa_mech_keys_i_algorithm_v0_coseAlg_h126;
      `text`?: string;
      `postQuantum`?: boolean;
      `insecure`?: boolean;
      `lane`?: string
    },
    null,
    string
  }

@js(#{`$types`:#["number","null"]}) @hoisted model UserDetail_page_mfa_mech_keys_i_coseAlg_h128 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `policy`:#{`type`:"string"},
      `format`:#{`type`:"string"},
      `type`:#{`type`:"string"},
      `verified`:#{`type`:"boolean"},
      `trusted`:#{`type`:"boolean"},
      `anchor`:#{`type`:"string"},
      `aaguid`:#{`type`:#["string","null"]},
      `model`:#{`type`:"string"},
      `certificationLevel`:#{`type`:"string"},
      `mdsStatus`:#{`type`:"string"},
      `mdsVersion`:#{
        `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
      },
      `checkedAt`:#{`type`:"number"},
      `algorithms`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `statement`:#{`type`:"string"},
          `statementCoseAlg`:#{`type`:#["integer","null"]},
          `certificates`:#{
            `type`:"array",
            `items`:#{
              `type`:"object",
              `additionalProperties`:false,
              `properties`:#{
                `algorithm`:#{`type`:"string"},
                `oid`:#{`type`:"string"},
                `family`:#{`type`:"string"},
                `postQuantum`:#{`type`:"boolean"},
                `composite`:#{`type`:"boolean"}
              }
            }
          },
          `anchor`:#{
            `type`:#["object","null"],
            `additionalProperties`:false,
            `properties`:#{
              `algorithm`:#{`type`:"string"},
              `oid`:#{`type`:"string"},
              `family`:#{`type`:"string"},
              `postQuantum`:#{`type`:"boolean"},
              `composite`:#{`type`:"boolean"}
            }
          },
          `postQuantum`:#{`type`:"boolean"},
          `members`:#{
            `type`:"array",
            `items`:#{
              `type`:"object",
              `additionalProperties`:false,
              `properties`:#{
                `format`:#{`type`:"string"},
                `statement`:#{`type`:"string"},
                `statementCoseAlg`:#{`type`:#["integer","null"]},
                `certificates`:#{
                  `type`:"array",
                  `items`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `algorithm`:#{`type`:"string"},
                      `oid`:#{`type`:"string"},
                      `family`:#{`type`:"string"},
                      `postQuantum`:#{`type`:"boolean"},
                      `composite`:#{`type`:"boolean"}
                    }
                  }
                },
                `anchor`:#{
                  `type`:#["object","null"],
                  `additionalProperties`:false,
                  `properties`:#{
                    `algorithm`:#{`type`:"string"},
                    `oid`:#{`type`:"string"},
                    `family`:#{`type`:"string"},
                    `postQuantum`:#{`type`:"boolean"},
                    `composite`:#{`type`:"boolean"}
                  }
                }
              }
            }
          }
        }
      },
      `conveyance`:#{`type`:"string"},
      `enterpriseDowngraded`:#{`type`:"boolean"},
      `attestationKeyId`:#{`type`:"string"},
      `deviceSerial`:#{`type`:"string"},
      `deviceSerialSource`:#{`type`:"string"},
      `evidence`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `syntax`:#{`type`:"string"},
          `version`:#{`type`:"number"},
          `object`:#{`type`:"string"},
          `objectDigest`:#{`type`:"string"},
          `evidenceRecord`:#{`type`:"string"},
          `timestamps`:#{`type`:"array",`items`:#{`type`:"string"}},
          `createdAt`:#{
            `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
          },
          `renewedAt`:#{
            `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
          },
          `renewAfter`:#{
            `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
          },
          `hashAlgorithm`:#{`type`:"string"},
          `tsa`:#{`type`:#["string","null"]}
        }
      },
      `androidRevocation`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `status`:#{`type`:"string"},
          `reason`:#{`type`:"string"},
          `serial`:#{`type`:"string"},
          `listVersion`:#{`type`:"string"},
          `checkedAt`:#{
            `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
          },
          `chainSerials`:#{`type`:"array",`items`:#{`type`:"string"}},
          `why`:#{`type`:"string"}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_page_mfa_mech_keys_i_attestation_h129 {}

@js(#{`$types`:#["boolean","null"]}) @hoisted model UserDetail_page_mfa_mech_keys_i_backupEligible_h130 {}

@js(#{`$types`:#["boolean","null"]}) @hoisted model UserDetail_page_mfa_mech_keys_i_backupState_h131 {}

@js(#{`$types`:#["boolean","null"]}) @hoisted model UserDetail_page_mfa_mech_keys_i_discoverable_h132 {}

@js(#{`$types`:#["number","null"]}) @hoisted model UserDetail_page_mfa_mech_keys_i_minPinLength_h133 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserDetail_page_mfa_mech_keys_i_provider_h134 {}

@js(#{`$types`:#["number","null"]}) @hoisted model UserDetail_page_mfa_mech_keys_i_previousCoseAlg_h135 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `enrolledAt`:#{`type`:"number"},
      `lastUsedAt`:#{`type`:"number"},
      `algorithm`:#{`type`:"string"},
      `digits`:#{`type`:"number"},
      `period`:#{`type`:"number"},
      `sealed`:#{`type`:"boolean"},
      `unusable`:#{`type`:"boolean"},
      `why`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_page_mfa_mech_totpDetail_h136 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `present`:#{`type`:"boolean"},
      `usable`:#{`type`:"boolean"},
      `total`:#{`type`:"number"},
      `remaining`:#{`type`:"number"},
      `used`:#{`type`:"number"},
      `generatedAt`:#{`type`:"number"},
      `lastUsedAt`:#{`type`:"number"},
      `sealed`:#{`type`:"boolean"},
      `hashed`:#{`type`:"boolean"},
      `legacy`:#{`type`:"boolean"},
      `why`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_page_mfa_mech_backupCodes_h137 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserDetail_page_mfa_mech_secondFactor_h138 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{`expires`:#{`type`:"number"},`expired`:#{`type`:"boolean"}},
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_page_mfa_mech_passwordResetLink_h139 {}

@hoisted union UserDetail_page_mfa_webauthn_minPinLength_v1_h140 {boolean, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_webauthn_minPinLength_h141 {null, UserDetail_page_mfa_webauthn_minPinLength_v1_h140}

@hoisted union UserDetail_page_mfa_verifications_verifications_i_recorded_v1_h142 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_verifications_verifications_i_recorded_h143 {
    null,
    UserDetail_page_mfa_verifications_verifications_i_recorded_v1_h142
  }

@hoisted union UserDetail_page_mfa_devices_devices_i_keys_i_added_v1_h144 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_devices_devices_i_keys_i_added_h145 {null, UserDetail_page_mfa_devices_devices_i_keys_i_added_v1_h144}

@hoisted union UserDetail_page_mfa_devices_devices_i_keys_i_attestation_verifiedAt_v1_h146 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_devices_devices_i_keys_i_attestation_verifiedAt_h147 {
    null,
    UserDetail_page_mfa_devices_devices_i_keys_i_attestation_verifiedAt_v1_h146
  }

@hoisted union UserDetail_page_mfa_devices_devices_i_keys_i_attestation_revocation_checkedAt_v1_h148 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_devices_devices_i_keys_i_attestation_revocation_checkedAt_h149 {
    null,
    UserDetail_page_mfa_devices_devices_i_keys_i_attestation_revocation_checkedAt_v1_h148
  }

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `status`:#{`type`:"string"},
      `compliance`:#{`type`:"string"},
      `level`:#{`type`:"string"},
      `previous`:#{`type`:#["string","null"]},
      `at`:#{
        `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
      },
      `source`:#{`type`:"string"},
      `actor`:#{`type`:"string"},
      `reason`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_page_mfa_devices_devices_i_complianceChange_h150 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `status`:#{`type`:"string"},
      `compliance`:#{`type`:"string"},
      `level`:#{`type`:"string"},
      `previous`:#{`type`:#["string","null"]},
      `at`:#{
        `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
      },
      `source`:#{`type`:"string"},
      `actor`:#{`type`:"string"},
      `reason`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_page_mfa_devices_devices_i_statusChange_h151 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `status`:#{`type`:"string"},
      `compliance`:#{`type`:"string"},
      `level`:#{`type`:"string"},
      `previous`:#{`type`:#["string","null"]},
      `at`:#{
        `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
      },
      `source`:#{`type`:"string"},
      `actor`:#{`type`:"string"},
      `reason`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_page_mfa_devices_devices_i_riskChange_h152 {}

@hoisted union UserDetail_page_mfa_devices_devices_i_enrolment_at_v1_h153 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_devices_devices_i_enrolment_at_h154 {null, UserDetail_page_mfa_devices_devices_i_enrolment_at_v1_h153}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `generation`:#{`type`:"number"},
      `issuedAt`:#{`type`:"string"},
      `browser`:#{`type`:"string"},
      `secondFactorAt`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_page_mfa_devices_devices_i_rememberedBrowser_h155 {}

@hoisted union UserDetail_page_mfa_devices_devices_i_lastUsed_v1_h156 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_devices_devices_i_lastUsed_h157 {null, UserDetail_page_mfa_devices_devices_i_lastUsed_v1_h156}

@hoisted union UserDetail_page_mfa_devices_devices_i_created_v1_h158 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_devices_devices_i_created_h159 {null, UserDetail_page_mfa_devices_devices_i_created_v1_h158}

@hoisted union UserDetail_page_mfa_selfIssued_subjects_i_enrolledAt_v1_h160 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_selfIssued_subjects_i_enrolledAt_h161 {null, UserDetail_page_mfa_selfIssued_subjects_i_enrolledAt_v1_h160}

@hoisted union UserDetail_page_mfa_selfIssued_subjects_i_provedAt_v1_h162 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_selfIssued_subjects_i_provedAt_h163 {null, UserDetail_page_mfa_selfIssued_subjects_i_provedAt_v1_h162}

@hoisted union UserDetail_page_mfa_publishedDids_dids_i_createdAt_v1_h164 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_publishedDids_dids_i_createdAt_h165 {null, UserDetail_page_mfa_publishedDids_dids_i_createdAt_v1_h164}

@hoisted union UserDetail_page_mfa_publishedDids_dids_i_deactivated_v1_v2_at_v1_h166 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_publishedDids_dids_i_deactivated_v1_v2_at_h167 {
    null,
    UserDetail_page_mfa_publishedDids_dids_i_deactivated_v1_v2_at_v1_h166
  }

@hoisted union UserDetail_page_mfa_publishedDids_dids_i_deactivated_v1_h168 {
    boolean,
    string,
    {
      `at`?: UserDetail_page_mfa_publishedDids_dids_i_deactivated_v1_v2_at_h167;
      `by`?: string;
      `reason`?: string;
      `via`?: string
    }
  }

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_publishedDids_dids_i_deactivated_h169 {null, UserDetail_page_mfa_publishedDids_dids_i_deactivated_v1_h168}

@hoisted union UserDetail_page_mfa_publishedDids_dids_i_currentVersion_h170 {string, numeric}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `change`:#{`type`:"string"},
      `expiresAt`:#{
        `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_page_mfa_publishedDids_dids_i_pending_h171 {}

@hoisted union UserDetail_page_mfa_publishedDids_dids_i_versions_i_versionId_h172 {string, numeric}

@hoisted union UserDetail_page_mfa_publishedDids_dids_i_versions_i_created_v1_h173 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_publishedDids_dids_i_versions_i_created_h174 {
    null,
    UserDetail_page_mfa_publishedDids_dids_i_versions_i_created_v1_h173
  }

@hoisted union UserDetail_page_mfa_publishedDids_dids_i_versions_i_authorizedBy_i_at_v1_h175 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_publishedDids_dids_i_versions_i_authorizedBy_i_at_h176 {
    null,
    UserDetail_page_mfa_publishedDids_dids_i_versions_i_authorizedBy_i_at_v1_h175
  }

@hoisted union UserDetail_page_mfa_publishedDids_dids_i_versions_i_authorizedBy_i_versionId_h177 {string, numeric}

@hoisted union UserDetail_page_mfa_signing_certificates_i_notBefore_v1_h178 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_signing_certificates_i_notBefore_h179 {null, UserDetail_page_mfa_signing_certificates_i_notBefore_v1_h178}

@hoisted union UserDetail_page_mfa_signing_certificates_i_notAfter_v1_h180 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_signing_certificates_i_notAfter_h181 {null, UserDetail_page_mfa_signing_certificates_i_notAfter_v1_h180}

@js(#{`$types`:#["string","null"]}) @hoisted model UserDetail_page_mfa_signing_certificates_i_reason_h182 {}

@hoisted union UserDetail_page_mfa_signing_certificates_i_revokedAt_v1_h183 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_mfa_signing_certificates_i_revokedAt_h184 {null, UserDetail_page_mfa_signing_certificates_i_revokedAt_v1_h183}

@hoisted union UserDetail_page_delegation_delegate_v1_h185 {
    string,
    {
      `dn`?: string;
      `name`?: string;
      `kind`?: string;
      `present`?: boolean;
      `sub`?: string
    }
  }

@js(#{`$comb`:"oneOf"}) @hoisted union UserDetail_page_delegation_delegate_h186 {null, UserDetail_page_delegation_delegate_v1_h185}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `subject`:#{`type`:"string"},
      `issuer`:#{`type`:"string"},
      `serialHex`:#{`type`:"string"},
      `notBefore`:#{`type`:"string"},
      `notAfter`:#{`type`:"string"},
      `expired`:#{`type`:"boolean"},
      `selfSigned`:#{`type`:"boolean"},
      `keyType`:#{`type`:"string"},
      `thumbprint`:#{`type`:"string"},
      `unreadable`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model UserDetail_page_keyPairs_purposes_i_keys_i_certificate_h187 {}

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
        `amr`?: UserDetail_user_events_i_amr_h85;
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
    `serviceAccount`?: UserDetail_serviceAccount_h86;
    `risk`?: UserDetail_risk_h87;
    `factors`?: UserDetail_factors_h88;
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
      `deviceBound`?: UserDetail_sessions_i_deviceBound_h89;
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
        `client_id`?: UserDetail_sessions_i_tokens_i_client_id_h90;
        `audience`?: string;
        `scope`?: UserDetail_sessions_i_tokens_i_scope_h91;
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
      `client_id`?: UserDetail_tokensOnEndedSessions_i_client_id_h92;
      `audience`?: string;
      `scope`?: UserDetail_tokensOnEndedSessions_i_scope_h93;
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
      `client_id`?: UserDetail_tokensWithNoSession_i_client_id_h94;
      `audience`?: string;
      `scope`?: UserDetail_tokensWithNoSession_i_scope_h95;
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
      `expiresAt`?: UserDetail_artifacts_i_expiresAt_h97;
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
      `etype`?: UserDetail_artifacts_i_etype_h98;
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
    `ldap`?: UserDetail_ldap_h99;
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
          `certificate`?: UserDetail_credentials_keyPairs_i_keys_i_certificate_h100;
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
      `productKdc`?: UserDetail_kerberos_productKdc_h101;
      `personKeys`?: boolean;
      `principal`?: string;
      `nameUsable`?: boolean;
      `person`?: boolean;
      `disabled`?: boolean;
      `keys`?: UserDetail_kerberos_keys_h102
    };
    `attributeEditor`?: UserDetail_attributeEditor_h103;
    `gnapGrants`?: ({
      `id`?: string;
      `state`?: string;
      `finalization`?: UserDetail_gnapGrants_i_finalization_h104;
      `client`?: UserDetail_gnapGrants_i_client_h105;
      `clientName`?: UserDetail_gnapGrants_i_clientName_h106;
      `authorizationServer`?: UserDetail_gnapGrants_i_authorizationServer_h107;
      `createdAt`?: UserDetail_gnapGrants_i_createdAt_h108;
      `updatedAt`?: UserDetail_gnapGrants_i_updatedAt_h109;
      `grantExpiresAt`?: UserDetail_gnapGrants_i_grantExpiresAt_h110;
      `approvedBy`?: string;
      @js(#{
        `x-free-form`:"An RFC 9635 access right as the client asked for it: a reference string or an object in the access type the resource server defines.",
        `description`:"An RFC 9635 access right as the client asked for it: a reference string or an object in the access type the resource server defines."
      }) `rights`?: unknown;
      `rightsAre`?: string;
      `subjectReleasedAt`?: UserDetail_gnapGrants_i_subjectReleasedAt_h111;
      `derivedFrom`?: UserDetail_gnapGrants_i_derivedFrom_h112;
      `tokens`?: ({
        `jti`?: string;
        `label`?: UserDetail_gnapGrants_i_tokens_i_label_h113;
        `format`?: string;
        `issuedAt`?: UserDetail_gnapGrants_i_tokens_i_issuedAt_h114;
        `expiresAt`?: UserDetail_gnapGrants_i_tokens_i_expiresAt_h115;
        `state`?: string;
        `bearer`?: boolean;
        @js(#{
          `x-free-form`:"An RFC 9635 access right as the client asked for it: a reference string or an object in the access type the resource server defines.",
          `description`:"An RFC 9635 access right as the client asked for it: a reference string or an object in the access type the resource server defines."
        }) `access`?: unknown;
        `revokedWhy`?: UserDetail_gnapGrants_i_tokens_i_revokedWhy_h116
      })[];
      `revocable`?: boolean
    })[];
    `gnapGrantsPaging`?: UserDetail_gnapGrantsPaging_h117;
    `gnapGrantsCells`?: UserDetail_gnapGrantsCells_h118;
    `uma`?: UserDetail_uma_h119;
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
      `params`?: Record<UserDetail_page_params_ap_h122>;
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
            `attachment`?: UserDetail_page_mfa_mech_keys_i_attachment_h123;
            `userVerified`?: UserDetail_page_mfa_mech_keys_i_userVerified_h124;
            `aaguid`?: UserDetail_page_mfa_mech_keys_i_aaguid_h125;
            `algorithm`?: UserDetail_page_mfa_mech_keys_i_algorithm_h127;
            `coseAlg`?: UserDetail_page_mfa_mech_keys_i_coseAlg_h128;
            `attestation`?: UserDetail_page_mfa_mech_keys_i_attestation_h129;
            `backupEligible`?: UserDetail_page_mfa_mech_keys_i_backupEligible_h130;
            `backupState`?: UserDetail_page_mfa_mech_keys_i_backupState_h131;
            `transports`?: (string)[];
            `discoverable`?: UserDetail_page_mfa_mech_keys_i_discoverable_h132;
            `minPinLength`?: UserDetail_page_mfa_mech_keys_i_minPinLength_h133;
            `userHandle`?: string;
            `lane`?: string;
            `enrolledBy`?: {`username`?: string; `sub`?: string; `at`?: numeric};
            `provider`?: UserDetail_page_mfa_mech_keys_i_provider_h134;
            `providerSource`?: string;
            `name`?: string;
            `group`?: string;
            `upgradedAt`?: numeric;
            `upgradedTo`?: string;
            `previousAlgorithm`?: string;
            `previousCoseAlg`?: UserDetail_page_mfa_mech_keys_i_previousCoseAlg_h135;
            `previousCredentialId`?: string;
            `upgradeMode`?: string;
            `possiblyReplacedBy`?: string;
            `possiblyReplacedAt`?: numeric;
            `policyRefused`?: Record<{`why`?: string; `at`?: numeric}>;
            `attestationRefused`?: {`why`?: string; `at`?: numeric}
          })[];
          `totp`?: boolean;
          `totpUsable`?: boolean;
          `totpDetail`?: UserDetail_page_mfa_mech_totpDetail_h136;
          `usable`?: boolean;
          `backupCodes`?: UserDetail_page_mfa_mech_backupCodes_h137;
          `mfaRequired`?: boolean;
          `mailFactor`?: {
            `held`?: string;
            `optedIn`?: string;
            `why`?: string;
            `verified`?: boolean
          };
          `secondFactor`?: UserDetail_page_mfa_mech_secondFactor_h138;
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
          `passwordResetLink`?: UserDetail_page_mfa_mech_passwordResetLink_h139;
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
          `minPinLength`?: UserDetail_page_mfa_webauthn_minPinLength_h141;
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
            `recorded`?: UserDetail_page_mfa_verifications_verifications_i_recorded_h143;
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
              `added`?: UserDetail_page_mfa_devices_devices_i_keys_i_added_h145;
              `addedBy`?: string;
              `proof`?: string;
              `attestation`?: {
                `level`?: string;
                `format`?: string;
                `summary`?: string;
                `verifiedAt`?: UserDetail_page_mfa_devices_devices_i_keys_i_attestation_verifiedAt_h147;
                `chainSerials`?: (string)[];
                `revocation`?: {
                  `status`?: string;
                  `reason`?: string;
                  `serial`?: string;
                  `listVersion`?: string;
                  `checkedAt`?: UserDetail_page_mfa_devices_devices_i_keys_i_attestation_revocation_checkedAt_h149;
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
            `complianceChange`?: UserDetail_page_mfa_devices_devices_i_complianceChange_h150;
            `status`?: string;
            `statusChange`?: UserDetail_page_mfa_devices_devices_i_statusChange_h151;
            `riskLevel`?: string;
            `riskChange`?: UserDetail_page_mfa_devices_devices_i_riskChange_h152;
            `platform`?: string;
            `model`?: string;
            `os`?: string;
            `enrolment`?: {
              `method`?: string;
              `at`?: UserDetail_page_mfa_devices_devices_i_enrolment_at_h154;
              `actor`?: string
            };
            `nativeSso`?: boolean;
            `rememberedBrowser`?: UserDetail_page_mfa_devices_devices_i_rememberedBrowser_h155;
            `sessionLive`?: boolean;
            `lastUsed`?: UserDetail_page_mfa_devices_devices_i_lastUsed_h157;
            `created`?: UserDetail_page_mfa_devices_devices_i_created_h159
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
            `enrolledAt`?: UserDetail_page_mfa_selfIssued_subjects_i_enrolledAt_h161;
            `by`?: string;
            `proof`?: string;
            `provedAt`?: UserDetail_page_mfa_selfIssued_subjects_i_provedAt_h163;
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
            `createdAt`?: UserDetail_page_mfa_publishedDids_dids_i_createdAt_h165;
            `by`?: string;
            `state`?: string;
            `deactivated`?: UserDetail_page_mfa_publishedDids_dids_i_deactivated_h169;
            `proof`?: string;
            `preferred`?: boolean;
            `currentVersion`?: UserDetail_page_mfa_publishedDids_dids_i_currentVersion_h170;
            `pending`?: UserDetail_page_mfa_publishedDids_dids_i_pending_h171;
            `versions`?: ({
              `versionId`?: UserDetail_page_mfa_publishedDids_dids_i_versions_i_versionId_h172;
              `created`?: UserDetail_page_mfa_publishedDids_dids_i_versions_i_created_h174;
              `change`?: string;
              `keys`?: ({`id`?: string; `kty`?: string; `crv`?: string; `alg`?: string})[];
              `authorizedBy`?: ({
                `kind`?: string;
                `subject`?: string;
                `actor`?: string;
                `at`?: UserDetail_page_mfa_publishedDids_dids_i_versions_i_authorizedBy_i_at_h176;
                `keyThumbprint`?: string;
                `versionId`?: UserDetail_page_mfa_publishedDids_dids_i_versions_i_authorizedBy_i_versionId_h177;
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
            `notBefore`?: UserDetail_page_mfa_signing_certificates_i_notBefore_h179;
            `notAfter`?: UserDetail_page_mfa_signing_certificates_i_notAfter_h181;
            `thumbprint`?: string;
            `state`?: string;
            `reason`?: UserDetail_page_mfa_signing_certificates_i_reason_h182;
            `revokedAt`?: UserDetail_page_mfa_signing_certificates_i_revokedAt_h184;
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
        `delegate`?: UserDetail_page_delegation_delegate_h186;
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
            `certificate`?: UserDetail_page_keyPairs_purposes_i_keys_i_certificate_h187;
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

@hoisted union Saml2ServiceProviderList_protocolEndpoints_i_methods_h188 {string, (string)[]}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_serviceProviders_i_name_h189 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_serviceProviders_i_slug_h190 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_serviceProviders_i_idpEntityId_h191 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_paging_param_h192 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_paging_noun_h193 {}

@hoisted union Saml2ServiceProviderList_settings_groups_i_settings_i_value_h194 {boolean, numeric, string, (string)[], null}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_settings_groups_i_settings_i_text_h195 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_settings_groups_i_settings_i_env_h196 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_settings_groups_i_settings_i_legacyEnv_h197 {}

@hoisted union Saml2ServiceProviderList_settings_groups_i_settings_i_default_h198 {boolean, numeric, string, (string)[], null}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_settings_context_configFile_h199 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_settings_context_defaultsFile_h200 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_settings_context_realmId_h201 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_mdqRefused_i_firstAt_h202 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_mdqRefused_i_lastAt_h203 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_mdqRefusedPaging_param_h204 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_mdqRefusedPaging_noun_h205 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `ok`:#{`type`:"boolean"},
      `lastAttemptAt`:#{`type`:"string"},
      `lastSuccessAt`:#{`type`:"string"},
      `failingSince`:#{`type`:"string"},
      `failures`:#{`type`:"number"},
      `why`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model Saml2ServiceProviderList_metadata_refresh_h206 {}

@js(#{`$types`:#["boolean","null"]}) @hoisted model Saml2ServiceProviderList_metadata_assertionConsumerServices_i_isDefault_h207 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_slug_h208 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml2ServiceProviderList_idpEntityId_h209 {}

@component model `Saml2ServiceProviderList` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: Saml2ServiceProviderList_protocolEndpoints_i_methods_h188;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `serviceProviders`?: ({
      `name`?: Saml2ServiceProviderList_serviceProviders_i_name_h189;
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
      `slug`?: Saml2ServiceProviderList_serviceProviders_i_slug_h190;
      `idpEntityId`?: Saml2ServiceProviderList_serviceProviders_i_idpEntityId_h191;
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
      `param`?: Saml2ServiceProviderList_paging_param_h192;
      `noun`?: Saml2ServiceProviderList_paging_noun_h193
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
          `value`?: Saml2ServiceProviderList_settings_groups_i_settings_i_value_h194;
          `text`?: Saml2ServiceProviderList_settings_groups_i_settings_i_text_h195;
          `source`?: string;
          `editable`?: boolean;
          `restartReason`?: string;
          `editRefusal`?: string;
          `env`?: Saml2ServiceProviderList_settings_groups_i_settings_i_env_h196;
          `legacyEnv`?: Saml2ServiceProviderList_settings_groups_i_settings_i_legacyEnv_h197;
          `appconfigPath`?: string;
          `default`?: Saml2ServiceProviderList_settings_groups_i_settings_i_default_h198;
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
        `configFile`?: Saml2ServiceProviderList_settings_context_configFile_h199;
        `defaultsFile`?: Saml2ServiceProviderList_settings_context_defaultsFile_h200;
        `persistsAppconfig`?: boolean;
        `persistsRealms`?: boolean;
        `persistenceMode`?: string;
        `inRealm`?: boolean;
        `realmId`?: Saml2ServiceProviderList_settings_context_realmId_h201
      };
      @js(#{`description`:"The other pages, by settings group."}) `sharedWith`?: Record<({`path`?: string; `label`?: string})[]>
    };
    `artifactsAwaitingResolution`?: numeric;
    `requestsHeldForSignIn`?: numeric;
    `mdqRefused`?: ({
      `entityId`?: string;
      `why`?: string;
      `firstAt`?: Saml2ServiceProviderList_mdqRefused_i_firstAt_h202;
      `lastAt`?: Saml2ServiceProviderList_mdqRefused_i_lastAt_h203;
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
      `param`?: Saml2ServiceProviderList_mdqRefusedPaging_param_h204;
      `noun`?: Saml2ServiceProviderList_mdqRefusedPaging_noun_h205
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
      `refresh`?: Saml2ServiceProviderList_metadata_refresh_h206;
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
        `isDefault`?: Saml2ServiceProviderList_metadata_assertionConsumerServices_i_isDefault_h207;
        `binding`?: string;
        `location`?: string
      })[];
      `singleLogoutServices`?: ({`binding`?: string; `location`?: string; `responseLocation`?: string})[];
      `encryptionCertificate`?: boolean
    };
    `identifier`?: string;
    `slug`?: Saml2ServiceProviderList_slug_h208;
    `idpEntityId`?: Saml2ServiceProviderList_idpEntityId_h209;
    `metadataUrl`?: string;
    `ssoUrl`?: string;
    `sloUrl`?: string;
    `arsUrl`?: string
  }

@hoisted union FederationRelationshipList_ready_h210 {integer, boolean}

@js(#{`$types`:#["string","null"]}) @hoisted model FederationRelationshipList_filter_q_h211 {}

@js(#{`$types`:#["string","null"]}) @hoisted model FederationRelationshipList_filter_role_h212 {}

@js(#{`$types`:#["string","null"]}) @hoisted model FederationRelationshipList_filter_category_h213 {}

@js(#{`$types`:#["string","null"]}) @hoisted model FederationRelationshipList_container_h214 {}

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
            `settings`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `key`:#{`type`:"string"},
                  `group`:#{`type`:"string"},
                  `label`:#{`type`:"string"},
                  `description`:#{`type`:"string"},
                  `type`:#{`type`:"string"},
                  `enumValues`:#{
                    `type`:"array",
                    `items`:#{
                      `anyOf`:#[
                        #{`type`:"string"},
                        #{`type`:"number"},
                        #{`type`:"boolean"},
                        #{`type`:"null"}
                      ]
                    }
                  },
                  `csvValues`:#{
                    `type`:"array",
                    `items`:#{
                      `anyOf`:#[
                        #{`type`:"string"},
                        #{`type`:"number"},
                        #{`type`:"boolean"},
                        #{`type`:"null"}
                      ]
                    }
                  },
                  `ordered`:#{`type`:"boolean"},
                  `csvValueNotes`:#{`type`:"object",`additionalProperties`:#{`type`:"string"}},
                  `selectAll`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `onlyWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      },
                      `aloneWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      }
                    }
                  },
                  `min`:#{`type`:"number"},
                  `max`:#{`type`:"number"},
                  `step`:#{`type`:"number"},
                  `value`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `text`:#{`type`:#["string","null"]},
                  `source`:#{`type`:"string"},
                  `editable`:#{`type`:"boolean"},
                  `restartReason`:#{`type`:"string"},
                  `editRefusal`:#{`type`:"string"},
                  `env`:#{
                    `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                  },
                  `legacyEnv`:#{
                    `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                  },
                  `appconfigPath`:#{`type`:"string"},
                  `default`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `masked`:#{`type`:"boolean"},
                  `realmSettable`:#{`type`:"boolean"},
                  `overridden`:#{`type`:"boolean"}
                }
              }
            }
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
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model FederationRelationshipList_settings_h215 {}

@hoisted union FederationRelationshipList_provider_h216 {
    string,
    null,
    {
      `id`?: string;
      `label`?: string;
      `note`?: string;
      `docs`?: string;
      `realmOn`?: boolean
    }
  }

@js(#{`$types`:#["string","null"]}) @hoisted model FederationRelationshipList_endpoints_metadata_h217 {}

@js(#{`$types`:#["string","null"]}) @hoisted model FederationRelationshipList_endpoints_jwks_h218 {}

@js(#{`$types`:#["string","null"]}) @hoisted model FederationRelationshipList_endpoints_initiateLogin_h219 {}

@hoisted union FederationRelationshipList_editable_i_editable_h220 {boolean, string}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `relationship`:#{`type`:"string"},
      `name`:#{`type`:"string"},
      `kind`:#{`type`:"string"},
      `enabled`:#{`type`:"boolean"},
      `signalsEnabled`:#{`type`:"boolean"},
      `receiving`:#{`type`:"boolean"},
      `issuer`:#{`type`:"string"},
      `delivery`:#{`type`:"string"},
      `eventsRequested`:#{`type`:"array",`items`:#{`type`:"string"}},
      `credential`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `method`:#{`type`:"string"},
          `tokenEndpoint`:#{`type`:"string"},
          `clientId`:#{`type`:"string"},
          `scope`:#{`type`:"string"},
          `secretHeld`:#{`type`:"boolean"}
        }
      },
      `ready`:#{`type`:"boolean"},
      `missing`:#{`type`:"array",`items`:#{`type`:"string"}},
      `config`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `issuer`:#{
            `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
            `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
          },
          `jwks_uri`:#{
            `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
            `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
          },
          `configuration_endpoint`:#{
            `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
            `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
          },
          `status_endpoint`:#{
            `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
            `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
          },
          `add_subject_endpoint`:#{
            `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
            `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
          },
          `remove_subject_endpoint`:#{
            `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
            `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
          },
          `verification_endpoint`:#{
            `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
            `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
          },
          `delivery_methods_supported`:#{
            `type`:"array",
            `items`:#{
              `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
              `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
            }
          }
        }
      },
      `discoveryUrl`:#{`type`:"string"},
      `discoveredAt`:#{`type`:"string"},
      `streamId`:#{`type`:"string"},
      `stream`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `stream_id`:#{
            `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
            `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
          },
          `aud`:#{
            `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
            `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
          },
          `events_supported`:#{
            `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
            `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
          },
          `events_requested`:#{
            `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
            `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
          },
          `events_delivered`:#{
            `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
            `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
          },
          `delivery`:#{
            `type`:"object",
            `additionalProperties`:false,
            `properties`:#{
              `method`:#{
                `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
                `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
              },
              `endpoint_url`:#{
                `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.",
                `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure."
              }
            }
          }
        }
      },
      `streamDelivery`:#{`type`:"string"},
      `streamAud`:#{`type`:"array",`items`:#{`type`:"string"}},
      `pollEndpoint`:#{`type`:"string"},
      `pushEndpoint`:#{`type`:"string"},
      `pushEndpointSet`:#{`type`:"boolean"},
      `state`:#{`type`:"string"},
      `streamStatus`:#{`type`:"string"},
      `verifiedAt`:#{`type`:"string"},
      `lastPollAt`:#{`type`:"string"},
      `lastPollResult`:#{`type`:"string"},
      `lastError`:#{`type`:"string"},
      `counts`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `received`:#{`type`:"integer"},
          `verified`:#{`type`:"integer"},
          `refused`:#{`type`:"integer"},
          `acted`:#{`type`:"integer"}
        }
      },
      `blocks`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `relationship`:#{`type`:"string"},
            `username`:#{`type`:"string"},
            `at`:#{`type`:"string"},
            `event`:#{`type`:"string"},
            `jti`:#{`type`:"string"},
            `by`:#{`type`:"string"}
          }
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model FederationRelationshipList_signals_h221 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `application`:#{`type`:"string"},
      `streams`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `streamId`:#{`type`:"string"},
            `delivery`:#{`type`:"string"},
            `status`:#{`type`:"string"},
            `eventsDelivered`:#{`type`:"array",`items`:#{`type`:"string"}},
            `createdBy`:#{`type`:"string"},
            `lastActivityAt`:#{`type`:"string"},
            `dead`:#{`type`:"boolean"},
            `deadLetters`:#{`type`:"integer"}
          }
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model FederationRelationshipList_outboundSignals_h222 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `policy`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `family`:#{`type`:"string"},
          `keyType`:#{`type`:"string"},
          `management`:#{`type`:"string"},
          `content`:#{`type`:"string"}
        }
      },
      `required`:#{`type`:"boolean"},
      `allowUnencrypted`:#{`type`:"boolean"},
      `graceS`:#{`type`:"number"},
      `current`:#{`type`:"string"},
      `certificatePem`:#{`type`:"string"},
      `jwk`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `kty`:#{`type`:"string"},
          `use`:#{`type`:"string"},
          `alg`:#{`type`:"string"},
          `kid`:#{`type`:"string"},
          `key_ops`:#{`type`:"array",`items`:#{`type`:"string"}},
          `ext`:#{`type`:"boolean"},
          `crv`:#{`type`:"string"},
          `x`:#{`type`:"string"},
          `y`:#{`type`:"string"},
          `n`:#{`type`:"string"},
          `e`:#{`type`:"string"},
          `pub`:#{`type`:"string"},
          `ek`:#{`type`:"string"},
          `x5c`:#{`type`:"array",`items`:#{`type`:"string"}},
          `x5t`:#{`type`:"string"},
          `x5t#S256`:#{`type`:"string"},
          `x5u`:#{`type`:"string"}
        }
      },
      `keys`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `kid`:#{`type`:"string"},
            `keyType`:#{`type`:"string"},
            `state`:#{`type`:"string"},
            `notAfter`:#{
              `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
            },
            `createdAt`:#{
              `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
            },
            `retiresAt`:#{
              `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
            },
            `decrypts`:#{`type`:"boolean"},
            `sealed`:#{`type`:"boolean"}
          }
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model FederationRelationshipList_encryption_h223 {}

@hoisted union FederationRelationshipList_setFields_i_editable_h224 {boolean, string}

@hoisted union FederationRelationshipList_multiFields_i_editable_h225 {boolean, string}

@hoisted union FederationRelationshipList_signalSetFields_i_editable_h226 {boolean, string}

@hoisted union FederationRelationshipList_schema_i_editable_h227 {boolean, string}

@hoisted union FederationRelationshipList_protocolEndpoints_i_methods_h228 {string, (string)[]}

@component model `FederationRelationshipList` {
    `relationshipCount`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `ready`?: FederationRelationshipList_ready_h210;
    `filter`?: {
      `q`?: FederationRelationshipList_filter_q_h211;
      `role`?: FederationRelationshipList_filter_role_h212;
      `category`?: FederationRelationshipList_filter_category_h213
    };
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `container`?: FederationRelationshipList_container_h214;
    `max`?: numeric;
    `settings`?: FederationRelationshipList_settings_h215;
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
    `provider`?: FederationRelationshipList_provider_h216;
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
      `metadata`?: FederationRelationshipList_endpoints_metadata_h217;
      `jwks`?: FederationRelationshipList_endpoints_jwks_h218;
      `initiateLogin`?: FederationRelationshipList_endpoints_initiateLogin_h219;
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
      `editable`?: FederationRelationshipList_editable_i_editable_h220
    })[];
    `unmappedAttributes`?: ({`name`?: string; `refused`?: string; `first`?: string; `last`?: string})[];
    `signals`?: FederationRelationshipList_signals_h221;
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
    `outboundSignals`?: FederationRelationshipList_outboundSignals_h222;
    `encryption`?: FederationRelationshipList_encryption_h223;
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
      `editable`?: FederationRelationshipList_setFields_i_editable_h224
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
      `editable`?: FederationRelationshipList_multiFields_i_editable_h225
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
      `editable`?: FederationRelationshipList_signalSetFields_i_editable_h226
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
      `editable`?: FederationRelationshipList_schema_i_editable_h227
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
      `methods`?: FederationRelationshipList_protocolEndpoints_i_methods_h228;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean;
      `listening`?: boolean
    })[]
  }

@hoisted union Saml11RelyingPartyList_protocolEndpoints_i_methods_h229 {string, (string)[]}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml11RelyingPartyList_relyingParties_i_name_h230 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml11RelyingPartyList_relyingParties_i_slug_h231 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml11RelyingPartyList_relyingParties_i_idpProviderId_h232 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml11RelyingPartyList_paging_param_h233 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml11RelyingPartyList_paging_noun_h234 {}

@hoisted union Saml11RelyingPartyList_settings_groups_i_settings_i_value_h235 {boolean, numeric, string, (string)[], null}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml11RelyingPartyList_settings_groups_i_settings_i_text_h236 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml11RelyingPartyList_settings_groups_i_settings_i_env_h237 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml11RelyingPartyList_settings_groups_i_settings_i_legacyEnv_h238 {}

@hoisted union Saml11RelyingPartyList_settings_groups_i_settings_i_default_h239 {boolean, numeric, string, (string)[], null}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml11RelyingPartyList_settings_context_configFile_h240 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml11RelyingPartyList_settings_context_defaultsFile_h241 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml11RelyingPartyList_settings_context_realmId_h242 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml11RelyingPartyList_slug_h243 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Saml11RelyingPartyList_idpProviderId_h244 {}

@component model `Saml11RelyingPartyList` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: Saml11RelyingPartyList_protocolEndpoints_i_methods_h229;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `relyingParties`?: ({
      `name`?: Saml11RelyingPartyList_relyingParties_i_name_h230;
      `authentications`?: numeric;
      `sessions`?: numeric;
      `users`?: numeric;
      `firstSeen`?: string;
      `lastSeen`?: string;
      `assertionConsumerServices`?: (string)[];
      `nameIdFormats`?: (string)[];
      `profiles`?: (string)[];
      `identifier`?: string;
      `slug`?: Saml11RelyingPartyList_relyingParties_i_slug_h231;
      `idpProviderId`?: Saml11RelyingPartyList_relyingParties_i_idpProviderId_h232;
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
      `param`?: Saml11RelyingPartyList_paging_param_h233;
      `noun`?: Saml11RelyingPartyList_paging_noun_h234
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
          `value`?: Saml11RelyingPartyList_settings_groups_i_settings_i_value_h235;
          `text`?: Saml11RelyingPartyList_settings_groups_i_settings_i_text_h236;
          `source`?: string;
          `editable`?: boolean;
          `restartReason`?: string;
          `editRefusal`?: string;
          `env`?: Saml11RelyingPartyList_settings_groups_i_settings_i_env_h237;
          `legacyEnv`?: Saml11RelyingPartyList_settings_groups_i_settings_i_legacyEnv_h238;
          `appconfigPath`?: string;
          `default`?: Saml11RelyingPartyList_settings_groups_i_settings_i_default_h239;
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
        `configFile`?: Saml11RelyingPartyList_settings_context_configFile_h240;
        `defaultsFile`?: Saml11RelyingPartyList_settings_context_defaultsFile_h241;
        `persistsAppconfig`?: boolean;
        `persistsRealms`?: boolean;
        `persistenceMode`?: string;
        `inRealm`?: boolean;
        `realmId`?: Saml11RelyingPartyList_settings_context_realmId_h242
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
    `slug`?: Saml11RelyingPartyList_slug_h243;
    `idpProviderId`?: Saml11RelyingPartyList_idpProviderId_h244;
    `metadataUrl`?: string;
    `ssoUrl`?: string;
    `responderUrl`?: string
  }

@hoisted union SamlIdpInitiatedList_protocolEndpoints_i_methods_h245 {string, (string)[]}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlIdpInitiatedList_idpInitiated_i_endpoint_h246 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlIdpInitiatedList_idpInitiatedPaging_param_h247 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlIdpInitiatedList_idpInitiatedPaging_noun_h248 {}

@component model `SamlIdpInitiatedList` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: SamlIdpInitiatedList_protocolEndpoints_i_methods_h245;
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
      `endpoint`?: SamlIdpInitiatedList_idpInitiated_i_endpoint_h246;
      `missing`?: (string)[]
    })[];
    `idpInitiatedPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: SamlIdpInitiatedList_idpInitiatedPaging_param_h247;
      `noun`?: SamlIdpInitiatedList_idpInitiatedPaging_noun_h248
    };
    `realmSwitches`?: ({
      `protocol`?: string;
      `label`?: string;
      `setting`?: string;
      `attribute`?: string;
      `enabled`?: boolean
    })[]
  }

@js(#{
    `x-free-form`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines.",
    `description`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines."
  }) @hoisted model AuthorizationServerList_authorizationServers_i_overrides_ap_h249 {}

@js(#{
    `x-free-form`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines.",
    `description`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines."
  }) @hoisted model AuthorizationServerList_overrides_ap_h250 {}

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
      @js(#{`description`:"The members this server overrides."}) `overrides`?: Record<AuthorizationServerList_authorizationServers_i_overrides_ap_h249>;
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
    @js(#{`description`:"The members this server overrides."}) `overrides`?: Record<AuthorizationServerList_overrides_ap_h250>;
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

@hoisted union ApplicationList_registered_h251 {boolean, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_filter_q_h252 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_filter_kind_h253 {}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","null"]}) @hoisted model ApplicationList_filter_exclude_h254 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_container_h255 {}

@js(#{`$types`:#["number","null"]}) @hoisted model ApplicationList_max_h256 {}

@hoisted union ApplicationList_kinds_i_h257 {string, {`kind`?: string; `label`?: string; `what`?: string}}

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
            `settings`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `key`:#{`type`:"string"},
                  `group`:#{`type`:"string"},
                  `label`:#{`type`:"string"},
                  `description`:#{`type`:"string"},
                  `type`:#{`type`:"string"},
                  `enumValues`:#{`type`:"array",`items`:#{`type`:"string"}},
                  `csvValues`:#{`type`:"array",`items`:#{`type`:"string"}},
                  `ordered`:#{`type`:"boolean"},
                  `csvValueNotes`:#{
                    `type`:"object",
                    `additionalProperties`:#{`type`:"string"},
                    `description`:"The sentence beside each of a list's values."
                  },
                  `selectAll`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `onlyWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      },
                      `aloneWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      }
                    }
                  },
                  `min`:#{`type`:"number"},
                  `max`:#{`type`:"number"},
                  `step`:#{`type`:"number"},
                  `value`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{`type`:"array",`items`:#{`type`:"string"}}
                    ]
                  },
                  `text`:#{`type`:"string"},
                  `source`:#{`type`:"string"},
                  `editable`:#{`type`:"boolean"},
                  `restartReason`:#{`type`:"string"},
                  `editRefusal`:#{`type`:"string"},
                  `env`:#{`type`:#["string","null"]},
                  `legacyEnv`:#{`type`:#["string","null"]},
                  `appconfigPath`:#{`type`:"string"},
                  `default`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{`type`:"array",`items`:#{`type`:"string"}}
                    ]
                  },
                  `masked`:#{`type`:"boolean"},
                  `realmSettable`:#{`type`:"boolean"},
                  `overridden`:#{`type`:"boolean"}
                }
              }
            }
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
        `description`:"The other pages each settings group is drawn on."
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_settings_h258 {}

@hoisted union ApplicationList_protocols_i_h259 {
    string,
    {
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
    }
  }

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_applications_i_dnLabel_h260 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_applications_i_dn_h261 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_applications_i_name_h262 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_applications_i_description_h263 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_applications_i_origin_h264 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_applications_i_createdAt_h265 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_applications_i_modifiedAt_h266 {}

@hoisted union ApplicationList_applications_i_attributes_ap_v4_i_h267 {string, numeric, boolean}

@hoisted union ApplicationList_applications_i_attributes_ap_h268 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_applications_i_attributes_ap_v4_i_h267)[]
  }

@hoisted union ApplicationList_applications_i_fields_ap_v4_i_h269 {string, numeric, boolean}

@hoisted union ApplicationList_applications_i_fields_ap_h270 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_applications_i_fields_ap_v4_i_h269)[]
  }

@hoisted union ApplicationList_page_v1_config_fields_i_editable_h271 {string, boolean}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","null"]}) @hoisted model ApplicationList_page_v1_config_fields_i_choices_h272 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_config_fields_i_example_h273 {}

@hoisted union ApplicationList_page_v1_config_fields_i_described_value_h274 {string, numeric, boolean, null, (string)[]}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_config_fields_i_described_env_h275 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_config_fields_i_described_legacyEnv_h276 {}

@hoisted union ApplicationList_page_v1_config_fields_i_described_default_h277 {string, numeric, boolean, null, (string)[]}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `signed`:#{`type`:"boolean"},
      `outcome`:#{`type`:"string"},
      `binding`:#{`type`:"string"},
      `signatureMethod`:#{`type`:"string"},
      `weak`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_config_observed_samlLastRequest_h278 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `subject`:#{`type`:"string"},
      `sha256`:#{`type`:"string"},
      `unreadable`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_config_observed_samlObservedSigningCertificate_h279 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_launchUrls_ap_endpoint_h280 {}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","null"]}) @hoisted model ApplicationList_page_v1_accessTypes_i_actions_h281 {}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","null"]}) @hoisted model ApplicationList_page_v1_accessTypes_i_datatypes_h282 {}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","null"]}) @hoisted model ApplicationList_page_v1_accessTypes_i_privileges_h283 {}

@hoisted union ApplicationList_page_v1_accessTypes_i_bearer_v4_i_h284 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_accessTypes_i_bearer_h285 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_accessTypes_i_bearer_v4_i_h284)[]
  }

@js(#{`$types`:#["number","null"]}) @hoisted model ApplicationList_page_v1_accessTypes_i_maxLifetimeS_h286 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `known`:#{`type`:"boolean"},
      `enforced`:#{`type`:"boolean"},
      `reference`:#{`type`:#["string","null"]},
      `policy`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `name`:#{`type`:"string"},
          `policyId`:#{`type`:#["string","null"]},
          `version`:#{`type`:#["string","null"]},
          `enabled`:#{`type`:"boolean"},
          `application`:#{`type`:#["string","null"]},
          `orphanedAt`:#{`type`:#["string","null"]},
          `own`:#{`type`:"boolean"},
          `editor`:#{`type`:"string"}
        }
      },
      `usable`:#{`type`:"boolean"},
      `failure`:#{`type`:"string"},
      `why`:#{`type`:"string"},
      `types`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `type`:#{`type`:"string"},
            `covered`:#{`type`:"boolean"},
            `uncovered`:#{`type`:"array",`items`:#{`type`:"string"}},
            `rows`:#{`type`:"integer"},
            `notForPolicy`:#{`type`:"array",`items`:#{`type`:"string"}}
          }
        }
      },
      `unreadable`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{`stored`:#{`type`:"string"},`problem`:#{`type`:"string"}}
        }
      },
      `template`:#{`type`:"string"},
      `peps`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `group`:#{`type`:"string"},
          `authzenGroup`:#{`type`:"string"},
          `total`:#{`type`:"integer"},
          `truncated`:#{`type`:"boolean"},
          `unlocated`:#{`type`:"integer"},
          `holders`:#{
            `type`:"array",
            `items`:#{
              `type`:"object",
              `additionalProperties`:false,
              `properties`:#{
                `name`:#{`type`:"string"},
                `kind`:#{`type`:"string"},
                `dn`:#{`type`:"string"},
                `member`:#{`type`:"boolean"},
                `scoped`:#{`type`:"boolean"},
                `scope`:#{`type`:"boolean"},
                `why`:#{`type`:"string"}
              }
            }
          }
        }
      },
      `applicationPolicies`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`count`:#{`type`:"integer"},`max`:#{`type`:"number"}}
      },
      `choices`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `categories`:#{`type`:"array",`items`:#{`type`:"string"}},
          `dataTypes`:#{`type`:"array",`items`:#{`type`:"string"}},
          `multiplicities`:#{`type`:"array",`items`:#{`type`:"string"}}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_fga_h287 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissionClaims_permissions_i_description_h288 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissionClaims_permissions_i_id_h289 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_did_did_h290 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_clientSecret_secrets_i_description_h291 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `subject`:#{`type`:"string"},
      `issuer`:#{`type`:"string"},
      `serialHex`:#{`type`:"string"},
      `notBefore`:#{`type`:"string"},
      `notAfter`:#{`type`:"string"},
      `expired`:#{`type`:"boolean"},
      `selfSigned`:#{`type`:"boolean"},
      `keyType`:#{`type`:#["string","null"]},
      `thumbprint`:#{`type`:"string"},
      `unreadable`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_credentials_purposes_i_certificate_h292 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_purposes_i_chain_i_keyType_h293 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `subject`:#{`type`:"string"},
      `issuer`:#{`type`:"string"},
      `serialHex`:#{`type`:"string"},
      `notBefore`:#{`type`:"string"},
      `notAfter`:#{`type`:"string"},
      `expired`:#{`type`:"boolean"},
      `selfSigned`:#{`type`:"boolean"},
      `keyType`:#{`type`:#["string","null"]},
      `thumbprint`:#{`type`:"string"},
      `unreadable`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_credentials_purposes_i_registered_keys_i_certificate_h294 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_purposes_i_registered_certificates_i_keyType_h295 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_mtls_certificates_i_label_h296 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_mtls_certificates_i_subject_h297 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_mtls_certificates_i_keyAlg_h298 {}

@hoisted union ApplicationList_page_v1_credentials_mtls_certificates_i_notBefore_h299 {string, numeric, null}

@hoisted union ApplicationList_page_v1_credentials_mtls_certificates_i_notAfter_h300 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_mtls_certificates_i_thumbprint_h301 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_mtls_certificates_i_reason_h302 {}

@hoisted union ApplicationList_page_v1_credentials_mtls_certificates_i_revokedAt_h303 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_mtls_certificates_i_certificatePem_h304 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_signing_certificates_i_label_h305 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_signing_certificates_i_subject_h306 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_signing_certificates_i_keyAlg_h307 {}

@hoisted union ApplicationList_page_v1_credentials_signing_certificates_i_notBefore_h308 {string, numeric, null}

@hoisted union ApplicationList_page_v1_credentials_signing_certificates_i_notAfter_h309 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_signing_certificates_i_thumbprint_h310 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_signing_certificates_i_reason_h311 {}

@hoisted union ApplicationList_page_v1_credentials_signing_certificates_i_revokedAt_h312 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_signing_certificates_i_certificatePem_h313 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_credentials_stored_dn_h314 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_signals_streams_i_statusReason_h315 {}

@hoisted union ApplicationList_page_v1_signals_streams_i_aud_v4_i_h316 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_signals_streams_i_aud_h317 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_signals_streams_i_aud_v4_i_h316)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_signals_streams_i_delivery_endpoint_url_h318 {}

@hoisted union ApplicationList_page_v1_signals_streams_i_createdAt_h319 {string, numeric}

@hoisted union ApplicationList_page_v1_signals_streams_i_updatedAt_h320 {string, numeric}

@hoisted union ApplicationList_page_v1_signals_streams_i_lastPushAt_h321 {string, numeric}

@hoisted union ApplicationList_page_v1_signals_settings_i_value_h322 {string, numeric, boolean, null, (string)[]}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_signals_json_streams_i_statusReason_h323 {}

@hoisted union ApplicationList_page_v1_signals_json_streams_i_aud_v4_i_h324 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_signals_json_streams_i_aud_h325 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_signals_json_streams_i_aud_v4_i_h324)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_signals_json_streams_i_delivery_endpoint_url_h326 {}

@hoisted union ApplicationList_page_v1_signals_json_streams_i_createdAt_h327 {string, numeric}

@hoisted union ApplicationList_page_v1_signals_json_streams_i_updatedAt_h328 {string, numeric}

@hoisted union ApplicationList_page_v1_signals_json_streams_i_lastPushAt_h329 {string, numeric}

@hoisted union ApplicationList_page_v1_signals_json_settings_i_value_h330 {string, numeric, boolean, null, (string)[]}

@hoisted union ApplicationList_page_v1_softwareStatement_keyProblems_i_v4_i_h331 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_softwareStatement_keyProblems_i_h332 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_softwareStatement_keyProblems_i_v4_i_h331)[]
  }

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `readable`:#{`type`:"boolean"},
      `why`:#{`type`:"string"},
      `verifies`:#{`type`:"boolean"},
      `typed`:#{`type`:"boolean"},
      `issuer`:#{`type`:"string"},
      `issuedAt`:#{`type`:"number"},
      `expiresAt`:#{`type`:"number"},
      `metadata`:#{
        `x-free-form`:"RFC 7591 client metadata fixed by a software statement: any member a publisher chose, including extensions no specification defines.",
        `description`:"RFC 7591 client metadata fixed by a software statement: any member a publisher chose, including extensions no specification defines."
      },
      `thumbprint`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_softwareStatement_issued_h333 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `issuer`:#{`type`:"string"},
      `trusted`:#{`type`:"boolean"},
      `publisher`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_softwareStatement_registeredWith_h334 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `readable`:#{`type`:"boolean"},
      `why`:#{`type`:"string"},
      `verifies`:#{`type`:"boolean"},
      `typed`:#{`type`:"boolean"},
      `issuer`:#{`type`:"string"},
      `issuedAt`:#{`type`:"number"},
      `expiresAt`:#{`type`:"number"},
      `metadata`:#{
        `x-free-form`:"RFC 7591 client metadata fixed by a software statement: any member a publisher chose, including extensions no specification defines.",
        `description`:"RFC 7591 client metadata fixed by a software statement: any member a publisher chose, including extensions no specification defines."
      },
      `thumbprint`:#{`type`:"string"},
      `statement`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_softwareStatement_json_issued_h335 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `issuer`:#{`type`:"string"},
      `trusted`:#{`type`:"boolean"},
      `publisher`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_softwareStatement_json_registeredWith_h336 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_held_i_baseUri_h337 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_held_i_description_h338 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_exposes_i_baseUri_h339 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_exposes_i_description_h340 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_exposes_i_id_h341 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_exposes_i_raw_h342 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_offerable_i_baseUri_h343 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_offerable_i_description_h344 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_offerable_i_id_h345 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_offerable_i_raw_h346 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_heldPage_shown_i_baseUri_h347 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_heldPage_shown_i_description_h348 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_exposedPage_shown_i_baseUri_h349 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_exposedPage_shown_i_description_h350 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_exposedPage_shown_i_id_h351 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_exposedPage_shown_i_raw_h352 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_grantedOutPage_shown_i_baseUri_h353 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_permissions_grantedOutPage_shown_i_description_h354 {}

@hoisted union ApplicationList_page_v1_claims_i_realm_i_value_v4_i_h355 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_claims_i_realm_i_value_h356 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_claims_i_realm_i_value_v4_i_h355)[]
  }

@hoisted union ApplicationList_page_v1_claims_i_own_i_value_v4_i_h357 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_claims_i_own_i_value_h358 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_claims_i_own_i_value_v4_i_h357)[]
  }

@hoisted union ApplicationList_page_v1_claims_i_effective_i_value_v4_i_h359 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_claims_i_effective_i_value_h360 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_claims_i_effective_i_value_v4_i_h359)[]
  }

@hoisted union ApplicationList_page_v1_claimSelections_preview_byLdap_ap_value_v4_i_h361 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_claimSelections_preview_byLdap_ap_value_h362 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_claimSelections_preview_byLdap_ap_value_v4_i_h361)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_claimSelections_preview_byLdap_ap_ldpTerm_h363 {}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","null"]}) @hoisted model ApplicationList_page_v1_claimSelections_sets_i_own_h364 {}

@hoisted union ApplicationList_page_v1_claimSelections_sets_i_claims_ap_v0_v4_i_h365 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_claimSelections_sets_i_claims_ap_v0_h366 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_claimSelections_sets_i_claims_ap_v0_v4_i_h365)[]
  }

@hoisted union ApplicationList_page_v1_claimSelections_sets_i_claims_ap_v1_ap_v4_i_h367 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_claimSelections_sets_i_claims_ap_v1_ap_h368 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_claimSelections_sets_i_claims_ap_v1_ap_v4_i_h367)[]
  }

@js(#{`description`:"A claim's members, as `address` has."}) @hoisted model ApplicationList_page_v1_claimSelections_sets_i_claims_ap_v1_h369 is Record<ApplicationList_page_v1_claimSelections_sets_i_claims_ap_v1_ap_h368>;
  

@hoisted union ApplicationList_page_v1_claimSelections_sets_i_claims_ap_h370 {
    ApplicationList_page_v1_claimSelections_sets_i_claims_ap_v0_h366,
    ApplicationList_page_v1_claimSelections_sets_i_claims_ap_v1_h369
  }

@hoisted union ApplicationList_page_v1_claimSelections_sets_i_report_i_value_v4_i_h371 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_claimSelections_sets_i_report_i_value_h372 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_claimSelections_sets_i_report_i_value_v4_i_h371)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_claimSelections_sets_i_report_i_ldpTerm_h373 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `attribute`:#{`type`:"string"},
      `realm`:#{`type`:"array",`items`:#{`type`:"string"}},
      `own`:#{`type`:#["array","null"],`items`:#{`type`:"string"}},
      `inherited`:#{`type`:"boolean"},
      `effective`:#{`type`:"array",`items`:#{`type`:"string"}},
      `claims`:#{
        `type`:"object",
        `additionalProperties`:#{
          `anyOf`:#[
            #{
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
            #{
              `type`:"object",
              `additionalProperties`:#{
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
              `description`:"A claim's members, as `address` has."
            }
          ]
        },
        `description`:"The claims, by name."
      },
      `report`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `ldap`:#{`type`:"string"},
            `claim`:#{`type`:"string"},
            `value`:#{
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
            `source`:#{`type`:"string"},
            `ldpTerm`:#{`type`:#["string","null"]}
          }
        }
      },
      `ldpOmitted`:#{`type`:"array",`items`:#{`type`:"string"}}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_claimSelections_credential_h374 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_credentials_rules_i_defaultProfile_h375 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `basicAuthentication`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      },
      `certificateAuthentication`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      },
      `serverKeyGeneration`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_enrollment_credentials_est_h376 {}

@hoisted union ApplicationList_page_v1_enrollment_credentials_certificates_i_notBefore_h377 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_credentials_certificates_i_notAfter_h378 {string, numeric}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `kind`:#{`type`:"string"},
      `id`:#{`type`:"string"},
      `admin`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_enrollment_credentials_certificates_i_requestedBy_h379 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_credentials_certificates_i_replaces_h380 {}

@hoisted union ApplicationList_page_v1_enrollment_credentials_certificates_i_attestation_v4_i_h381 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_enrollment_credentials_certificates_i_attestation_h382 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_enrollment_credentials_certificates_i_attestation_v4_i_h381)[]
  }

@hoisted union ApplicationList_page_v1_enrollment_credentials_certificates_i_revoked_at_h383 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_credentials_paged_shown_i_notBefore_h384 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_credentials_paged_shown_i_notAfter_h385 {string, numeric}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `kind`:#{`type`:"string"},
      `id`:#{`type`:"string"},
      `admin`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_enrollment_credentials_paged_shown_i_requestedBy_h386 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_credentials_paged_shown_i_replaces_h387 {}

@hoisted union ApplicationList_page_v1_enrollment_credentials_paged_shown_i_attestation_v4_i_h388 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_enrollment_credentials_paged_shown_i_attestation_h389 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_enrollment_credentials_paged_shown_i_attestation_v4_i_h388)[]
  }

@hoisted union ApplicationList_page_v1_enrollment_credentials_paged_shown_i_revoked_at_h390 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_credentials_eabKeys_i_createdAt_h391 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_credentials_eabKeys_i_expiresAt_h392 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_credentials_eabKeys_i_createdBy_h393 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_credentials_eabKeys_i_boundAccount_h394 {}

@hoisted union ApplicationList_page_v1_enrollment_credentials_eabKeys_i_boundAt_h395 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_credentials_challenges_i_profile_h396 {}

@hoisted union ApplicationList_page_v1_enrollment_credentials_challenges_i_createdAt_h397 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_credentials_challenges_i_expiresAt_h398 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_credentials_challenges_i_createdBy_h399 {}

@hoisted union ApplicationList_page_v1_enrollment_credentials_challenges_i_usedAt_h400 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_credentials_json_rules_i_defaultProfile_h401 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `basicAuthentication`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      },
      `certificateAuthentication`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      },
      `serverKeyGeneration`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_enrollment_credentials_json_est_h402 {}

@hoisted union ApplicationList_page_v1_enrollment_credentials_json_certificates_i_notBefore_h403 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_credentials_json_certificates_i_notAfter_h404 {string, numeric}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `kind`:#{`type`:"string"},
      `id`:#{`type`:"string"},
      `admin`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_enrollment_credentials_json_certificates_i_requestedBy_h405 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_credentials_json_certificates_i_replaces_h406 {}

@hoisted union ApplicationList_page_v1_enrollment_credentials_json_certificates_i_attestation_v4_i_h407 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_enrollment_credentials_json_certificates_i_attestation_h408 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_enrollment_credentials_json_certificates_i_attestation_v4_i_h407)[]
  }

@hoisted union ApplicationList_page_v1_enrollment_credentials_json_certificates_i_revoked_at_h409 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_credentials_json_eabKeys_i_createdAt_h410 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_credentials_json_eabKeys_i_expiresAt_h411 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_credentials_json_eabKeys_i_createdBy_h412 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_credentials_json_eabKeys_i_boundAccount_h413 {}

@hoisted union ApplicationList_page_v1_enrollment_credentials_json_eabKeys_i_boundAt_h414 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_credentials_json_scepChallenges_i_profile_h415 {}

@hoisted union ApplicationList_page_v1_enrollment_credentials_json_scepChallenges_i_createdAt_h416 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_credentials_json_scepChallenges_i_expiresAt_h417 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_credentials_json_scepChallenges_i_createdBy_h418 {}

@hoisted union ApplicationList_page_v1_enrollment_credentials_json_scepChallenges_i_usedAt_h419 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_config_rules_i_defaultProfile_h420 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `basicAuthentication`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      },
      `certificateAuthentication`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      },
      `serverKeyGeneration`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_enrollment_config_est_h421 {}

@hoisted union ApplicationList_page_v1_enrollment_config_certificates_i_notBefore_h422 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_config_certificates_i_notAfter_h423 {string, numeric}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `kind`:#{`type`:"string"},
      `id`:#{`type`:"string"},
      `admin`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_enrollment_config_certificates_i_requestedBy_h424 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_config_certificates_i_replaces_h425 {}

@hoisted union ApplicationList_page_v1_enrollment_config_certificates_i_attestation_v4_i_h426 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_enrollment_config_certificates_i_attestation_h427 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_enrollment_config_certificates_i_attestation_v4_i_h426)[]
  }

@hoisted union ApplicationList_page_v1_enrollment_config_certificates_i_revoked_at_h428 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_config_paged_shown_i_notBefore_h429 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_config_paged_shown_i_notAfter_h430 {string, numeric}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `kind`:#{`type`:"string"},
      `id`:#{`type`:"string"},
      `admin`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_enrollment_config_paged_shown_i_requestedBy_h431 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_config_paged_shown_i_replaces_h432 {}

@hoisted union ApplicationList_page_v1_enrollment_config_paged_shown_i_attestation_v4_i_h433 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_enrollment_config_paged_shown_i_attestation_h434 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_enrollment_config_paged_shown_i_attestation_v4_i_h433)[]
  }

@hoisted union ApplicationList_page_v1_enrollment_config_paged_shown_i_revoked_at_h435 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_config_eabKeys_i_createdAt_h436 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_config_eabKeys_i_expiresAt_h437 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_config_eabKeys_i_createdBy_h438 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_config_eabKeys_i_boundAccount_h439 {}

@hoisted union ApplicationList_page_v1_enrollment_config_eabKeys_i_boundAt_h440 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_config_challenges_i_profile_h441 {}

@hoisted union ApplicationList_page_v1_enrollment_config_challenges_i_createdAt_h442 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_config_challenges_i_expiresAt_h443 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_config_challenges_i_createdBy_h444 {}

@hoisted union ApplicationList_page_v1_enrollment_config_challenges_i_usedAt_h445 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_config_json_rules_i_defaultProfile_h446 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `basicAuthentication`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      },
      `certificateAuthentication`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      },
      `serverKeyGeneration`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_enrollment_config_json_est_h447 {}

@hoisted union ApplicationList_page_v1_enrollment_config_json_certificates_i_notBefore_h448 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_config_json_certificates_i_notAfter_h449 {string, numeric}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `kind`:#{`type`:"string"},
      `id`:#{`type`:"string"},
      `admin`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_enrollment_config_json_certificates_i_requestedBy_h450 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_config_json_certificates_i_replaces_h451 {}

@hoisted union ApplicationList_page_v1_enrollment_config_json_certificates_i_attestation_v4_i_h452 {string, numeric, boolean}

@hoisted union ApplicationList_page_v1_enrollment_config_json_certificates_i_attestation_h453 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_page_v1_enrollment_config_json_certificates_i_attestation_v4_i_h452)[]
  }

@hoisted union ApplicationList_page_v1_enrollment_config_json_certificates_i_revoked_at_h454 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_config_json_eabKeys_i_createdAt_h455 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_config_json_eabKeys_i_expiresAt_h456 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_config_json_eabKeys_i_createdBy_h457 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_config_json_eabKeys_i_boundAccount_h458 {}

@hoisted union ApplicationList_page_v1_enrollment_config_json_eabKeys_i_boundAt_h459 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_config_json_scepChallenges_i_profile_h460 {}

@hoisted union ApplicationList_page_v1_enrollment_config_json_scepChallenges_i_createdAt_h461 {string, numeric}

@hoisted union ApplicationList_page_v1_enrollment_config_json_scepChallenges_i_expiresAt_h462 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_page_v1_enrollment_config_json_scepChallenges_i_createdBy_h463 {}

@hoisted union ApplicationList_page_v1_enrollment_config_json_scepChallenges_i_usedAt_h464 {string, numeric, null}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `realm`:#{`type`:"string"},
      `frontEnds`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `realm`:#{`type`:"string"},
            `via`:#{`type`:"string"},
            `path`:#{`type`:"array",`items`:#{`type`:"string"}},
            `ok`:#{`type`:"boolean"},
            `problems`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `kind`:#{`type`:"string"},
                  `params`:#{
                    `type`:"object",
                    `additionalProperties`:#{`type`:"string"},
                    `description`:"What the sentence names."
                  },
                  `text`:#{`type`:"string"}
                }
              }
            },
            `actor`:#{`type`:"string"}
          }
        }
      },
      `targets`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `realm`:#{`type`:"string"},
            `via`:#{`type`:"string"},
            `path`:#{`type`:"array",`items`:#{`type`:"string"}},
            `ok`:#{`type`:"boolean"},
            `problems`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `kind`:#{`type`:"string"},
                  `params`:#{
                    `type`:"object",
                    `additionalProperties`:#{`type`:"string"},
                    `description`:"What the sentence names."
                  },
                  `text`:#{`type`:"string"}
                }
              }
            },
            `target`:#{`type`:"string"},
            `classicRefused`:#{`type`:"boolean"},
            `classicProblems`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `kind`:#{`type`:"string"},
                  `params`:#{
                    `type`:"object",
                    `additionalProperties`:#{`type`:"string"},
                    `description`:"What the sentence names."
                  },
                  `text`:#{`type`:"string"}
                }
              }
            }
          }
        }
      },
      `selfRealms`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `realm`:#{`type`:"string"},
            `via`:#{`type`:"string"},
            `path`:#{`type`:"array",`items`:#{`type`:"string"}},
            `ok`:#{`type`:"boolean"},
            `problems`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `kind`:#{`type`:"string"},
                  `params`:#{
                    `type`:"object",
                    `additionalProperties`:#{`type`:"string"},
                    `description`:"What the sentence names."
                  },
                  `text`:#{`type`:"string"}
                }
              }
            },
            `accepted`:#{`type`:"boolean"}
          }
        }
      },
      `tgtDelegation`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `unconstrained`:#{`type`:"boolean"},
          `foreignTgtDelegation`:#{`type`:"string"},
          `trusts`:#{
            `type`:"array",
            `items`:#{
              `type`:"object",
              `additionalProperties`:false,
              `properties`:#{
                `partner`:#{`type`:"string"},
                `allowed`:#{`type`:"boolean"},
                `attributes`:#{`type`:"array",`items`:#{`type`:"string"}},
                `delivered`:#{`type`:"boolean"}
              }
            }
          }
        }
      },
      `choices`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `krb5S4uSelfRealm`:#{`type`:"array",`items`:#{`type`:"string"}},
          `krb5ForeignTgtDelegation`:#{`type`:"array",`items`:#{`type`:"string"}}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_page_v1_krb5Across_h465 {}

@hoisted union ApplicationList_page_h466 {
    integer,
    {
      @js(#{`description`:"What each attribute of the entry is."}) `notes`?: Record<{`text`?: string; `sensitive`?: boolean}>;
      `config`?: {
        `fields`?: ({
          `attribute`?: string;
          `type`?: string;
          `long`?: boolean;
          `editable`?: ApplicationList_page_v1_config_fields_i_editable_h271;
          `sensitive`?: boolean;
          `overrides`?: string;
          `choices`?: ApplicationList_page_v1_config_fields_i_choices_h272;
          `example`?: ApplicationList_page_v1_config_fields_i_example_h273;
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
            `value`?: ApplicationList_page_v1_config_fields_i_described_value_h274;
            `text`?: string;
            `source`?: string;
            `editable`?: boolean;
            `restartReason`?: string;
            `editRefusal`?: string;
            `env`?: ApplicationList_page_v1_config_fields_i_described_env_h275;
            `legacyEnv`?: ApplicationList_page_v1_config_fields_i_described_legacyEnv_h276;
            `appconfigPath`?: string;
            `default`?: ApplicationList_page_v1_config_fields_i_described_default_h277;
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
          `samlLastRequest`?: ApplicationList_page_v1_config_observed_samlLastRequest_h278;
          `samlObservedSigningCertificate`?: ApplicationList_page_v1_config_observed_samlObservedSigningCertificate_h279;
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
        `endpoint`?: ApplicationList_page_v1_launchUrls_ap_endpoint_h280
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
        `actions`?: ApplicationList_page_v1_accessTypes_i_actions_h281;
        `datatypes`?: ApplicationList_page_v1_accessTypes_i_datatypes_h282;
        `privileges`?: ApplicationList_page_v1_accessTypes_i_privileges_h283;
        `required`?: (string)[];
        `interaction`?: string;
        `consentActions`?: (string)[];
        `bearer`?: ApplicationList_page_v1_accessTypes_i_bearer_h285;
        `maxLifetimeS`?: ApplicationList_page_v1_accessTypes_i_maxLifetimeS_h286;
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
      `fga`?: ApplicationList_page_v1_fga_h287;
      `permissionClaims`?: {
        `permissions`?: ({
          `name`?: string;
          `description`?: ApplicationList_page_v1_permissionClaims_permissions_i_description_h288;
          `id`?: ApplicationList_page_v1_permissionClaims_permissions_i_id_h289;
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
        `did`?: ApplicationList_page_v1_did_did_h290;
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
            `description`?: ApplicationList_page_v1_credentials_clientSecret_secrets_i_description_h291;
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
          `certificate`?: ApplicationList_page_v1_credentials_purposes_i_certificate_h292;
          `chain`?: ({
            `subject`?: string;
            `issuer`?: string;
            `serialHex`?: string;
            `notBefore`?: string;
            `notAfter`?: string;
            `expired`?: boolean;
            `selfSigned`?: boolean;
            `keyType`?: ApplicationList_page_v1_credentials_purposes_i_chain_i_keyType_h293;
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
              `certificate`?: ApplicationList_page_v1_credentials_purposes_i_registered_keys_i_certificate_h294
            })[];
            `certificates`?: ({
              `subject`?: string;
              `issuer`?: string;
              `serialHex`?: string;
              `notBefore`?: string;
              `notAfter`?: string;
              `expired`?: boolean;
              `selfSigned`?: boolean;
              `keyType`?: ApplicationList_page_v1_credentials_purposes_i_registered_certificates_i_keyType_h295;
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
            `label`?: ApplicationList_page_v1_credentials_mtls_certificates_i_label_h296;
            `subject`?: ApplicationList_page_v1_credentials_mtls_certificates_i_subject_h297;
            `keyAlg`?: ApplicationList_page_v1_credentials_mtls_certificates_i_keyAlg_h298;
            `notBefore`?: ApplicationList_page_v1_credentials_mtls_certificates_i_notBefore_h299;
            `notAfter`?: ApplicationList_page_v1_credentials_mtls_certificates_i_notAfter_h300;
            `thumbprint`?: ApplicationList_page_v1_credentials_mtls_certificates_i_thumbprint_h301;
            `state`?: string;
            `reason`?: ApplicationList_page_v1_credentials_mtls_certificates_i_reason_h302;
            `revokedAt`?: ApplicationList_page_v1_credentials_mtls_certificates_i_revokedAt_h303;
            `certificatePem`?: ApplicationList_page_v1_credentials_mtls_certificates_i_certificatePem_h304
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
            `label`?: ApplicationList_page_v1_credentials_signing_certificates_i_label_h305;
            `subject`?: ApplicationList_page_v1_credentials_signing_certificates_i_subject_h306;
            `keyAlg`?: ApplicationList_page_v1_credentials_signing_certificates_i_keyAlg_h307;
            `notBefore`?: ApplicationList_page_v1_credentials_signing_certificates_i_notBefore_h308;
            `notAfter`?: ApplicationList_page_v1_credentials_signing_certificates_i_notAfter_h309;
            `thumbprint`?: ApplicationList_page_v1_credentials_signing_certificates_i_thumbprint_h310;
            `state`?: string;
            `reason`?: ApplicationList_page_v1_credentials_signing_certificates_i_reason_h311;
            `revokedAt`?: ApplicationList_page_v1_credentials_signing_certificates_i_revokedAt_h312;
            `certificatePem`?: ApplicationList_page_v1_credentials_signing_certificates_i_certificatePem_h313
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
          `dn`?: ApplicationList_page_v1_credentials_stored_dn_h314;
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
          `statusReason`?: ApplicationList_page_v1_signals_streams_i_statusReason_h315;
          `aud`?: ApplicationList_page_v1_signals_streams_i_aud_h317;
          `delivery`?: {
            `method`?: string;
            `endpoint_url`?: ApplicationList_page_v1_signals_streams_i_delivery_endpoint_url_h318
          };
          `events_requested`?: (string)[];
          `events_delivered`?: (string)[];
          `format`?: string;
          `description`?: string;
          `createdBy`?: string;
          `createdAt`?: ApplicationList_page_v1_signals_streams_i_createdAt_h319;
          `updatedAt`?: ApplicationList_page_v1_signals_streams_i_updatedAt_h320;
          `lastPushAt`?: ApplicationList_page_v1_signals_streams_i_lastPushAt_h321;
          `lastPushError`?: string
        })[];
        `settings`?: ({
          `setting`?: string;
          `attribute`?: string;
          `value`?: ApplicationList_page_v1_signals_settings_i_value_h322;
          `source`?: string
        })[];
        `json`?: {
          `installed`?: boolean;
          `streams`?: ({
            `stream_id`?: string;
            `status`?: string;
            `statusReason`?: ApplicationList_page_v1_signals_json_streams_i_statusReason_h323;
            `aud`?: ApplicationList_page_v1_signals_json_streams_i_aud_h325;
            `delivery`?: {
              `method`?: string;
              `endpoint_url`?: ApplicationList_page_v1_signals_json_streams_i_delivery_endpoint_url_h326
            };
            `events_requested`?: (string)[];
            `events_delivered`?: (string)[];
            `format`?: string;
            `description`?: string;
            `createdBy`?: string;
            `createdAt`?: ApplicationList_page_v1_signals_json_streams_i_createdAt_h327;
            `updatedAt`?: ApplicationList_page_v1_signals_json_streams_i_updatedAt_h328;
            `lastPushAt`?: ApplicationList_page_v1_signals_json_streams_i_lastPushAt_h329;
            `lastPushError`?: string
          })[];
          `settings`?: ({
            `setting`?: string;
            `attribute`?: string;
            `value`?: ApplicationList_page_v1_signals_json_settings_i_value_h330;
            `source`?: string
          })[]
        }
      };
      `softwareStatement`?: {
        `issuers`?: (string)[];
        `usableKeys`?: integer;
        `keyProblems`?: (ApplicationList_page_v1_softwareStatement_keyProblems_i_h332)[];
        `issuedToken`?: string;
        `issued`?: ApplicationList_page_v1_softwareStatement_issued_h333;
        `registeredWith`?: ApplicationList_page_v1_softwareStatement_registeredWith_h334;
        `settings`?: {
          `requireTrustedIssuer`?: boolean;
          `opensRegistration`?: boolean;
          `required`?: boolean;
          `lifetimeSeconds`?: numeric
        };
        `json`?: {
          `declaredIssuers`?: (string)[];
          `usableKeys`?: integer;
          `issued`?: ApplicationList_page_v1_softwareStatement_json_issued_h335;
          `registeredWith`?: ApplicationList_page_v1_softwareStatement_json_registeredWith_h336;
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
          `baseUri`?: ApplicationList_page_v1_permissions_held_i_baseUri_h337;
          `permissionName`?: string;
          `description`?: ApplicationList_page_v1_permissions_held_i_description_h338;
          `dangling`?: boolean;
          `asked`?: boolean
        })[];
        `exposes`?: ({
          `resource`?: string;
          `resourceName`?: string;
          `baseUri`?: ApplicationList_page_v1_permissions_exposes_i_baseUri_h339;
          `name`?: string;
          `description`?: ApplicationList_page_v1_permissions_exposes_i_description_h340;
          `id`?: ApplicationList_page_v1_permissions_exposes_i_id_h341;
          `raw`?: ApplicationList_page_v1_permissions_exposes_i_raw_h342;
          `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
        })[];
        `offerable`?: ({
          `resource`?: string;
          `resourceName`?: string;
          `baseUri`?: ApplicationList_page_v1_permissions_offerable_i_baseUri_h343;
          `name`?: string;
          `description`?: ApplicationList_page_v1_permissions_offerable_i_description_h344;
          `id`?: ApplicationList_page_v1_permissions_offerable_i_id_h345;
          `raw`?: ApplicationList_page_v1_permissions_offerable_i_raw_h346;
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
            `baseUri`?: ApplicationList_page_v1_permissions_heldPage_shown_i_baseUri_h347;
            `permissionName`?: string;
            `description`?: ApplicationList_page_v1_permissions_heldPage_shown_i_description_h348;
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
            `baseUri`?: ApplicationList_page_v1_permissions_exposedPage_shown_i_baseUri_h349;
            `name`?: string;
            `description`?: ApplicationList_page_v1_permissions_exposedPage_shown_i_description_h350;
            `id`?: ApplicationList_page_v1_permissions_exposedPage_shown_i_id_h351;
            `raw`?: ApplicationList_page_v1_permissions_exposedPage_shown_i_raw_h352;
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
            `baseUri`?: ApplicationList_page_v1_permissions_grantedOutPage_shown_i_baseUri_h353;
            `permissionName`?: string;
            `description`?: ApplicationList_page_v1_permissions_grantedOutPage_shown_i_description_h354;
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
          `value`?: ApplicationList_page_v1_claims_i_realm_i_value_h356;
          `nameFormat`?: string;
          `namespace`?: string;
          `attribute`?: string;
          `multi`?: boolean;
          `type`?: string
        })[];
        `own`?: ({
          `name`?: string;
          `value`?: ApplicationList_page_v1_claims_i_own_i_value_h358;
          `nameFormat`?: string;
          `namespace`?: string;
          `attribute`?: string;
          `multi`?: boolean;
          `type`?: string
        })[];
        `effective`?: ({
          `name`?: string;
          `value`?: ApplicationList_page_v1_claims_i_effective_i_value_h360;
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
            `value`?: ApplicationList_page_v1_claimSelections_preview_byLdap_ap_value_h362;
            `source`?: string;
            `ldpTerm`?: ApplicationList_page_v1_claimSelections_preview_byLdap_ap_ldpTerm_h363
          }>;
          `entryFound`?: boolean
        };
        `sets`?: ({
          `id`?: string;
          `label`?: string;
          `attribute`?: string;
          `realm`?: (string)[];
          `own`?: ApplicationList_page_v1_claimSelections_sets_i_own_h364;
          `inherited`?: boolean;
          `effective`?: (string)[];
          @js(#{`description`:"The claims, by name."}) `claims`?: Record<ApplicationList_page_v1_claimSelections_sets_i_claims_ap_h370>;
          `report`?: ({
            `ldap`?: string;
            `claim`?: string;
            `value`?: ApplicationList_page_v1_claimSelections_sets_i_report_i_value_h372;
            `source`?: string;
            `ldpTerm`?: ApplicationList_page_v1_claimSelections_sets_i_report_i_ldpTerm_h373
          })[]
        })[];
        `credential`?: ApplicationList_page_v1_claimSelections_credential_h374
      };
      `enrollment`?: {
        `credentials`?: {
          `families`?: (string)[];
          `rules`?: ({
            `family`?: string;
            `label`?: string;
            `allowedProfiles`?: (string)[];
            `allowedProfilesSource`?: string;
            `defaultProfile`?: ApplicationList_page_v1_enrollment_credentials_rules_i_defaultProfile_h375;
            `defaultProfileSource`?: string;
            `certificateLifetimeDays`?: numeric;
            `certificateLifetimeSource`?: string
          })[];
          `cap`?: {`value`?: numeric; `source`?: string};
          `est`?: ApplicationList_page_v1_enrollment_credentials_est_h376;
          `certificates`?: ({
            `serialHex`?: string;
            `family`?: string;
            `profile`?: string;
            `subject`?: string;
            `names`?: (string)[];
            `thumbprint`?: string;
            `keyAlg`?: string;
            `notBefore`?: ApplicationList_page_v1_enrollment_credentials_certificates_i_notBefore_h377;
            `notAfter`?: ApplicationList_page_v1_enrollment_credentials_certificates_i_notAfter_h378;
            `issuedAt`?: string;
            `requestedBy`?: ApplicationList_page_v1_enrollment_credentials_certificates_i_requestedBy_h379;
            `via`?: string;
            `keySource`?: string;
            `replaces`?: ApplicationList_page_v1_enrollment_credentials_certificates_i_replaces_h380;
            `certificatePem`?: string;
            `chainPem`?: (string)[];
            `device`?: string;
            `attestation`?: ApplicationList_page_v1_enrollment_credentials_certificates_i_attestation_h382;
            `revoked`?: {
              `at`?: ApplicationList_page_v1_enrollment_credentials_certificates_i_revoked_at_h383;
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
              `notBefore`?: ApplicationList_page_v1_enrollment_credentials_paged_shown_i_notBefore_h384;
              `notAfter`?: ApplicationList_page_v1_enrollment_credentials_paged_shown_i_notAfter_h385;
              `issuedAt`?: string;
              `requestedBy`?: ApplicationList_page_v1_enrollment_credentials_paged_shown_i_requestedBy_h386;
              `via`?: string;
              `keySource`?: string;
              `replaces`?: ApplicationList_page_v1_enrollment_credentials_paged_shown_i_replaces_h387;
              `certificatePem`?: string;
              `chainPem`?: (string)[];
              `device`?: string;
              `attestation`?: ApplicationList_page_v1_enrollment_credentials_paged_shown_i_attestation_h389;
              `revoked`?: {
                `at`?: ApplicationList_page_v1_enrollment_credentials_paged_shown_i_revoked_at_h390;
                `reason`?: string;
                `by`?: string
              };
              `expired`?: boolean;
              `status`?: string
            })[]
          };
          `eabKeys`?: ({
            `kid`?: string;
            `createdAt`?: ApplicationList_page_v1_enrollment_credentials_eabKeys_i_createdAt_h391;
            `expiresAt`?: ApplicationList_page_v1_enrollment_credentials_eabKeys_i_expiresAt_h392;
            `createdBy`?: ApplicationList_page_v1_enrollment_credentials_eabKeys_i_createdBy_h393;
            `boundAccount`?: ApplicationList_page_v1_enrollment_credentials_eabKeys_i_boundAccount_h394;
            `boundAt`?: ApplicationList_page_v1_enrollment_credentials_eabKeys_i_boundAt_h395;
            `status`?: string
          })[];
          `challenges`?: ({
            `id`?: string;
            `profile`?: ApplicationList_page_v1_enrollment_credentials_challenges_i_profile_h396;
            `createdAt`?: ApplicationList_page_v1_enrollment_credentials_challenges_i_createdAt_h397;
            `expiresAt`?: ApplicationList_page_v1_enrollment_credentials_challenges_i_expiresAt_h398;
            `createdBy`?: ApplicationList_page_v1_enrollment_credentials_challenges_i_createdBy_h399;
            `usedAt`?: ApplicationList_page_v1_enrollment_credentials_challenges_i_usedAt_h400;
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
              `defaultProfile`?: ApplicationList_page_v1_enrollment_credentials_json_rules_i_defaultProfile_h401;
              `defaultProfileSource`?: string;
              `certificateLifetimeDays`?: numeric;
              `certificateLifetimeSource`?: string
            })[];
            `certificateCap`?: {`value`?: numeric; `source`?: string};
            `est`?: ApplicationList_page_v1_enrollment_credentials_json_est_h402;
            `certificates`?: ({
              `serialHex`?: string;
              `family`?: string;
              `profile`?: string;
              `subject`?: string;
              `names`?: (string)[];
              `thumbprint`?: string;
              `keyAlg`?: string;
              `notBefore`?: ApplicationList_page_v1_enrollment_credentials_json_certificates_i_notBefore_h403;
              `notAfter`?: ApplicationList_page_v1_enrollment_credentials_json_certificates_i_notAfter_h404;
              `issuedAt`?: string;
              `requestedBy`?: ApplicationList_page_v1_enrollment_credentials_json_certificates_i_requestedBy_h405;
              `via`?: string;
              `keySource`?: string;
              `replaces`?: ApplicationList_page_v1_enrollment_credentials_json_certificates_i_replaces_h406;
              `certificatePem`?: string;
              `chainPem`?: (string)[];
              `device`?: string;
              `attestation`?: ApplicationList_page_v1_enrollment_credentials_json_certificates_i_attestation_h408;
              `revoked`?: {
                `at`?: ApplicationList_page_v1_enrollment_credentials_json_certificates_i_revoked_at_h409;
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
              `createdAt`?: ApplicationList_page_v1_enrollment_credentials_json_eabKeys_i_createdAt_h410;
              `expiresAt`?: ApplicationList_page_v1_enrollment_credentials_json_eabKeys_i_expiresAt_h411;
              `createdBy`?: ApplicationList_page_v1_enrollment_credentials_json_eabKeys_i_createdBy_h412;
              `boundAccount`?: ApplicationList_page_v1_enrollment_credentials_json_eabKeys_i_boundAccount_h413;
              `boundAt`?: ApplicationList_page_v1_enrollment_credentials_json_eabKeys_i_boundAt_h414;
              `status`?: string
            })[];
            `scepChallenges`?: ({
              `id`?: string;
              `profile`?: ApplicationList_page_v1_enrollment_credentials_json_scepChallenges_i_profile_h415;
              `createdAt`?: ApplicationList_page_v1_enrollment_credentials_json_scepChallenges_i_createdAt_h416;
              `expiresAt`?: ApplicationList_page_v1_enrollment_credentials_json_scepChallenges_i_expiresAt_h417;
              `createdBy`?: ApplicationList_page_v1_enrollment_credentials_json_scepChallenges_i_createdBy_h418;
              `usedAt`?: ApplicationList_page_v1_enrollment_credentials_json_scepChallenges_i_usedAt_h419;
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
            `defaultProfile`?: ApplicationList_page_v1_enrollment_config_rules_i_defaultProfile_h420;
            `defaultProfileSource`?: string;
            `certificateLifetimeDays`?: numeric;
            `certificateLifetimeSource`?: string
          })[];
          `cap`?: {`value`?: numeric; `source`?: string};
          `est`?: ApplicationList_page_v1_enrollment_config_est_h421;
          `certificates`?: ({
            `serialHex`?: string;
            `family`?: string;
            `profile`?: string;
            `subject`?: string;
            `names`?: (string)[];
            `thumbprint`?: string;
            `keyAlg`?: string;
            `notBefore`?: ApplicationList_page_v1_enrollment_config_certificates_i_notBefore_h422;
            `notAfter`?: ApplicationList_page_v1_enrollment_config_certificates_i_notAfter_h423;
            `issuedAt`?: string;
            `requestedBy`?: ApplicationList_page_v1_enrollment_config_certificates_i_requestedBy_h424;
            `via`?: string;
            `keySource`?: string;
            `replaces`?: ApplicationList_page_v1_enrollment_config_certificates_i_replaces_h425;
            `certificatePem`?: string;
            `chainPem`?: (string)[];
            `device`?: string;
            `attestation`?: ApplicationList_page_v1_enrollment_config_certificates_i_attestation_h427;
            `revoked`?: {
              `at`?: ApplicationList_page_v1_enrollment_config_certificates_i_revoked_at_h428;
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
              `notBefore`?: ApplicationList_page_v1_enrollment_config_paged_shown_i_notBefore_h429;
              `notAfter`?: ApplicationList_page_v1_enrollment_config_paged_shown_i_notAfter_h430;
              `issuedAt`?: string;
              `requestedBy`?: ApplicationList_page_v1_enrollment_config_paged_shown_i_requestedBy_h431;
              `via`?: string;
              `keySource`?: string;
              `replaces`?: ApplicationList_page_v1_enrollment_config_paged_shown_i_replaces_h432;
              `certificatePem`?: string;
              `chainPem`?: (string)[];
              `device`?: string;
              `attestation`?: ApplicationList_page_v1_enrollment_config_paged_shown_i_attestation_h434;
              `revoked`?: {
                `at`?: ApplicationList_page_v1_enrollment_config_paged_shown_i_revoked_at_h435;
                `reason`?: string;
                `by`?: string
              };
              `expired`?: boolean;
              `status`?: string
            })[]
          };
          `eabKeys`?: ({
            `kid`?: string;
            `createdAt`?: ApplicationList_page_v1_enrollment_config_eabKeys_i_createdAt_h436;
            `expiresAt`?: ApplicationList_page_v1_enrollment_config_eabKeys_i_expiresAt_h437;
            `createdBy`?: ApplicationList_page_v1_enrollment_config_eabKeys_i_createdBy_h438;
            `boundAccount`?: ApplicationList_page_v1_enrollment_config_eabKeys_i_boundAccount_h439;
            `boundAt`?: ApplicationList_page_v1_enrollment_config_eabKeys_i_boundAt_h440;
            `status`?: string
          })[];
          `challenges`?: ({
            `id`?: string;
            `profile`?: ApplicationList_page_v1_enrollment_config_challenges_i_profile_h441;
            `createdAt`?: ApplicationList_page_v1_enrollment_config_challenges_i_createdAt_h442;
            `expiresAt`?: ApplicationList_page_v1_enrollment_config_challenges_i_expiresAt_h443;
            `createdBy`?: ApplicationList_page_v1_enrollment_config_challenges_i_createdBy_h444;
            `usedAt`?: ApplicationList_page_v1_enrollment_config_challenges_i_usedAt_h445;
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
              `defaultProfile`?: ApplicationList_page_v1_enrollment_config_json_rules_i_defaultProfile_h446;
              `defaultProfileSource`?: string;
              `certificateLifetimeDays`?: numeric;
              `certificateLifetimeSource`?: string
            })[];
            `certificateCap`?: {`value`?: numeric; `source`?: string};
            `est`?: ApplicationList_page_v1_enrollment_config_json_est_h447;
            `certificates`?: ({
              `serialHex`?: string;
              `family`?: string;
              `profile`?: string;
              `subject`?: string;
              `names`?: (string)[];
              `thumbprint`?: string;
              `keyAlg`?: string;
              `notBefore`?: ApplicationList_page_v1_enrollment_config_json_certificates_i_notBefore_h448;
              `notAfter`?: ApplicationList_page_v1_enrollment_config_json_certificates_i_notAfter_h449;
              `issuedAt`?: string;
              `requestedBy`?: ApplicationList_page_v1_enrollment_config_json_certificates_i_requestedBy_h450;
              `via`?: string;
              `keySource`?: string;
              `replaces`?: ApplicationList_page_v1_enrollment_config_json_certificates_i_replaces_h451;
              `certificatePem`?: string;
              `chainPem`?: (string)[];
              `device`?: string;
              `attestation`?: ApplicationList_page_v1_enrollment_config_json_certificates_i_attestation_h453;
              `revoked`?: {
                `at`?: ApplicationList_page_v1_enrollment_config_json_certificates_i_revoked_at_h454;
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
              `createdAt`?: ApplicationList_page_v1_enrollment_config_json_eabKeys_i_createdAt_h455;
              `expiresAt`?: ApplicationList_page_v1_enrollment_config_json_eabKeys_i_expiresAt_h456;
              `createdBy`?: ApplicationList_page_v1_enrollment_config_json_eabKeys_i_createdBy_h457;
              `boundAccount`?: ApplicationList_page_v1_enrollment_config_json_eabKeys_i_boundAccount_h458;
              `boundAt`?: ApplicationList_page_v1_enrollment_config_json_eabKeys_i_boundAt_h459;
              `status`?: string
            })[];
            `scepChallenges`?: ({
              `id`?: string;
              `profile`?: ApplicationList_page_v1_enrollment_config_json_scepChallenges_i_profile_h460;
              `createdAt`?: ApplicationList_page_v1_enrollment_config_json_scepChallenges_i_createdAt_h461;
              `expiresAt`?: ApplicationList_page_v1_enrollment_config_json_scepChallenges_i_expiresAt_h462;
              `createdBy`?: ApplicationList_page_v1_enrollment_config_json_scepChallenges_i_createdBy_h463;
              `usedAt`?: ApplicationList_page_v1_enrollment_config_json_scepChallenges_i_usedAt_h464;
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
      `krb5Across`?: ApplicationList_page_v1_krb5Across_h465
    }
  }

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_dnLabel_h467 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_dn_h468 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_name_h469 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_description_h470 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_origin_h471 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_createdAt_h472 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_modifiedAt_h473 {}

@hoisted union ApplicationList_attributes_ap_v4_i_h474 {string, numeric, boolean}

@hoisted union ApplicationList_attributes_ap_h475 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_attributes_ap_v4_i_h474)[]
  }

@hoisted union ApplicationList_fields_ap_v4_i_h476 {string, numeric, boolean}

@hoisted union ApplicationList_fields_ap_h477 {string, numeric, boolean, null, (ApplicationList_fields_ap_v4_i_h476)[]}

@hoisted union ApplicationList_attributesShown_i_values_i_v4_i_h478 {string, numeric, boolean}

@hoisted union ApplicationList_attributesShown_i_values_i_h479 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_attributesShown_i_values_i_v4_i_h478)[]
  }

@hoisted union ApplicationList_authenticationEvents_i_origin_h480 {string, numeric, null}

@hoisted union ApplicationList_authenticationEvents_i_detail_ap_h481 {string, numeric, boolean}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_clientSecret_secrets_i_description_h482 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `subject`:#{`type`:"string"},
      `issuer`:#{`type`:"string"},
      `serialHex`:#{`type`:"string"},
      `notBefore`:#{`type`:"string"},
      `notAfter`:#{`type`:"string"},
      `expired`:#{`type`:"boolean"},
      `selfSigned`:#{`type`:"boolean"},
      `keyType`:#{`type`:#["string","null"]},
      `thumbprint`:#{`type`:"string"},
      `unreadable`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_credentials_keyPairs_i_certificate_h483 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_keyPairs_i_chain_i_keyType_h484 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `subject`:#{`type`:"string"},
      `issuer`:#{`type`:"string"},
      `serialHex`:#{`type`:"string"},
      `notBefore`:#{`type`:"string"},
      `notAfter`:#{`type`:"string"},
      `expired`:#{`type`:"boolean"},
      `selfSigned`:#{`type`:"boolean"},
      `keyType`:#{`type`:#["string","null"]},
      `thumbprint`:#{`type`:"string"},
      `unreadable`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_credentials_keyPairs_i_registered_keys_i_certificate_h485 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_keyPairs_i_registered_certificates_i_keyType_h486 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_mtls_certificates_i_label_h487 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_mtls_certificates_i_subject_h488 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_mtls_certificates_i_keyAlg_h489 {}

@hoisted union ApplicationList_credentials_mtls_certificates_i_notBefore_h490 {string, numeric, null}

@hoisted union ApplicationList_credentials_mtls_certificates_i_notAfter_h491 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_mtls_certificates_i_thumbprint_h492 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_mtls_certificates_i_reason_h493 {}

@hoisted union ApplicationList_credentials_mtls_certificates_i_revokedAt_h494 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_mtls_certificates_i_certificatePem_h495 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_signing_certificates_i_label_h496 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_signing_certificates_i_subject_h497 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_signing_certificates_i_keyAlg_h498 {}

@hoisted union ApplicationList_credentials_signing_certificates_i_notBefore_h499 {string, numeric, null}

@hoisted union ApplicationList_credentials_signing_certificates_i_notAfter_h500 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_signing_certificates_i_thumbprint_h501 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_signing_certificates_i_reason_h502 {}

@hoisted union ApplicationList_credentials_signing_certificates_i_revokedAt_h503 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_signing_certificates_i_certificatePem_h504 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_credentials_stored_dn_h505 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_sharedSignals_streams_i_statusReason_h506 {}

@hoisted union ApplicationList_sharedSignals_streams_i_aud_v4_i_h507 {string, numeric, boolean}

@hoisted union ApplicationList_sharedSignals_streams_i_aud_h508 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_sharedSignals_streams_i_aud_v4_i_h507)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_sharedSignals_streams_i_delivery_endpoint_url_h509 {}

@hoisted union ApplicationList_sharedSignals_streams_i_createdAt_h510 {string, numeric}

@hoisted union ApplicationList_sharedSignals_streams_i_updatedAt_h511 {string, numeric}

@hoisted union ApplicationList_sharedSignals_streams_i_lastPushAt_h512 {string, numeric}

@hoisted union ApplicationList_sharedSignals_settings_i_value_h513 {string, numeric, boolean, null, (string)[]}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_certificateEnrollment_rules_i_defaultProfile_h514 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `basicAuthentication`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      },
      `certificateAuthentication`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      },
      `serverKeyGeneration`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_certificateEnrollment_est_h515 {}

@hoisted union ApplicationList_certificateEnrollment_certificates_i_notBefore_h516 {string, numeric}

@hoisted union ApplicationList_certificateEnrollment_certificates_i_notAfter_h517 {string, numeric}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `kind`:#{`type`:"string"},
      `id`:#{`type`:"string"},
      `admin`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_certificateEnrollment_certificates_i_requestedBy_h518 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_certificateEnrollment_certificates_i_replaces_h519 {}

@hoisted union ApplicationList_certificateEnrollment_certificates_i_attestation_v4_i_h520 {string, numeric, boolean}

@hoisted union ApplicationList_certificateEnrollment_certificates_i_attestation_h521 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_certificateEnrollment_certificates_i_attestation_v4_i_h520)[]
  }

@hoisted union ApplicationList_certificateEnrollment_certificates_i_revoked_at_h522 {string, numeric}

@hoisted union ApplicationList_certificateEnrollment_eabKeys_i_createdAt_h523 {string, numeric}

@hoisted union ApplicationList_certificateEnrollment_eabKeys_i_expiresAt_h524 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_certificateEnrollment_eabKeys_i_createdBy_h525 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_certificateEnrollment_eabKeys_i_boundAccount_h526 {}

@hoisted union ApplicationList_certificateEnrollment_eabKeys_i_boundAt_h527 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_certificateEnrollment_scepChallenges_i_profile_h528 {}

@hoisted union ApplicationList_certificateEnrollment_scepChallenges_i_createdAt_h529 {string, numeric}

@hoisted union ApplicationList_certificateEnrollment_scepChallenges_i_expiresAt_h530 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_certificateEnrollment_scepChallenges_i_createdBy_h531 {}

@hoisted union ApplicationList_certificateEnrollment_scepChallenges_i_usedAt_h532 {string, numeric, null}

@hoisted union ApplicationList_customClaims_i_realm_i_value_v4_i_h533 {string, numeric, boolean}

@hoisted union ApplicationList_customClaims_i_realm_i_value_h534 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_customClaims_i_realm_i_value_v4_i_h533)[]
  }

@hoisted union ApplicationList_customClaims_i_own_i_value_v4_i_h535 {string, numeric, boolean}

@hoisted union ApplicationList_customClaims_i_own_i_value_h536 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_customClaims_i_own_i_value_v4_i_h535)[]
  }

@hoisted union ApplicationList_customClaims_i_effective_i_value_v4_i_h537 {string, numeric, boolean}

@hoisted union ApplicationList_customClaims_i_effective_i_value_h538 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_customClaims_i_effective_i_value_v4_i_h537)[]
  }

@hoisted union ApplicationList_claimSelections_preview_byLdap_ap_value_v4_i_h539 {string, numeric, boolean}

@hoisted union ApplicationList_claimSelections_preview_byLdap_ap_value_h540 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_claimSelections_preview_byLdap_ap_value_v4_i_h539)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_claimSelections_preview_byLdap_ap_ldpTerm_h541 {}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","null"]}) @hoisted model ApplicationList_claimSelections_sets_i_own_h542 {}

@hoisted union ApplicationList_claimSelections_sets_i_claims_ap_v0_v4_i_h543 {string, numeric, boolean}

@hoisted union ApplicationList_claimSelections_sets_i_claims_ap_v0_h544 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_claimSelections_sets_i_claims_ap_v0_v4_i_h543)[]
  }

@hoisted union ApplicationList_claimSelections_sets_i_claims_ap_v1_ap_v4_i_h545 {string, numeric, boolean}

@hoisted union ApplicationList_claimSelections_sets_i_claims_ap_v1_ap_h546 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_claimSelections_sets_i_claims_ap_v1_ap_v4_i_h545)[]
  }

@js(#{`description`:"A claim's members, as `address` has."}) @hoisted model ApplicationList_claimSelections_sets_i_claims_ap_v1_h547 is Record<ApplicationList_claimSelections_sets_i_claims_ap_v1_ap_h546>;
  

@hoisted union ApplicationList_claimSelections_sets_i_claims_ap_h548 {
    ApplicationList_claimSelections_sets_i_claims_ap_v0_h544,
    ApplicationList_claimSelections_sets_i_claims_ap_v1_h547
  }

@hoisted union ApplicationList_claimSelections_sets_i_report_i_value_v4_i_h549 {string, numeric, boolean}

@hoisted union ApplicationList_claimSelections_sets_i_report_i_value_h550 {
    string,
    numeric,
    boolean,
    null,
    (ApplicationList_claimSelections_sets_i_report_i_value_v4_i_h549)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_claimSelections_sets_i_report_i_ldpTerm_h551 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `attribute`:#{`type`:"string"},
      `realm`:#{`type`:"array",`items`:#{`type`:"string"}},
      `own`:#{`type`:#["array","null"],`items`:#{`type`:"string"}},
      `inherited`:#{`type`:"boolean"},
      `effective`:#{`type`:"array",`items`:#{`type`:"string"}},
      `claims`:#{
        `type`:"object",
        `additionalProperties`:#{
          `anyOf`:#[
            #{
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
            #{
              `type`:"object",
              `additionalProperties`:#{
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
              `description`:"A claim's members, as `address` has."
            }
          ]
        },
        `description`:"The claims, by name."
      },
      `report`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `ldap`:#{`type`:"string"},
            `claim`:#{`type`:"string"},
            `value`:#{
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
            `source`:#{`type`:"string"},
            `ldpTerm`:#{`type`:#["string","null"]}
          }
        }
      },
      `ldpOmitted`:#{`type`:"array",`items`:#{`type`:"string"}}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_claimSelections_credential_h552 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `readable`:#{`type`:"boolean"},
      `why`:#{`type`:"string"},
      `verifies`:#{`type`:"boolean"},
      `typed`:#{`type`:"boolean"},
      `issuer`:#{`type`:"string"},
      `issuedAt`:#{`type`:"number"},
      `expiresAt`:#{`type`:"number"},
      `metadata`:#{
        `x-free-form`:"RFC 7591 client metadata fixed by a software statement: any member a publisher chose, including extensions no specification defines.",
        `description`:"RFC 7591 client metadata fixed by a software statement: any member a publisher chose, including extensions no specification defines."
      },
      `thumbprint`:#{`type`:"string"},
      `statement`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_softwareStatements_issued_h553 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `issuer`:#{`type`:"string"},
      `trusted`:#{`type`:"boolean"},
      `publisher`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ApplicationList_softwareStatements_registeredWith_h554 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_delegatedPermissions_held_i_baseUri_h555 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_delegatedPermissions_held_i_description_h556 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_delegatedPermissions_exposes_i_baseUri_h557 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_delegatedPermissions_exposes_i_description_h558 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_delegatedPermissions_exposes_i_id_h559 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_delegatedPermissions_exposes_i_raw_h560 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_delegatedPermissions_offerable_i_h561 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_delegatedPermissions_grantedOut_i_baseUri_h562 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ApplicationList_delegatedPermissions_grantedOut_i_description_h563 {}

@component model `ApplicationList` {
    `applicationCount`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `registered`?: ApplicationList_registered_h251;
    `filter`?: {
      `q`?: ApplicationList_filter_q_h252;
      `kind`?: ApplicationList_filter_kind_h253;
      `exclude`?: ApplicationList_filter_exclude_h254
    };
    `container`?: ApplicationList_container_h255;
    `max`?: ApplicationList_max_h256;
    `kinds`?: (ApplicationList_kinds_i_h257)[];
    `settings`?: ApplicationList_settings_h258;
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
    `protocols`?: (ApplicationList_protocols_i_h259)[];
    `applications`?: ({
      `identifier`?: string;
      `dnLabel`?: ApplicationList_applications_i_dnLabel_h260;
      `dn`?: ApplicationList_applications_i_dn_h261;
      `name`?: ApplicationList_applications_i_name_h262;
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
      `description`?: ApplicationList_applications_i_description_h263;
      `origin`?: ApplicationList_applications_i_origin_h264;
      `createdAt`?: ApplicationList_applications_i_createdAt_h265;
      `modifiedAt`?: ApplicationList_applications_i_modifiedAt_h266;
      `operational`?: (string)[];
      @js(#{`description`:"By attribute name."}) `attributes`?: Record<ApplicationList_applications_i_attributes_ap_h268>;
      @js(#{`description`:"By attribute name."}) `fields`?: Record<ApplicationList_applications_i_fields_ap_h270>;
      `secretExpiry`?: {`state`?: string; `at`?: string}
    })[];
    `page`?: ApplicationList_page_h466;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `identifier`?: string;
    `dnLabel`?: ApplicationList_dnLabel_h467;
    `dn`?: ApplicationList_dn_h468;
    `name`?: ApplicationList_name_h469;
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
    `description`?: ApplicationList_description_h470;
    `origin`?: ApplicationList_origin_h471;
    `createdAt`?: ApplicationList_createdAt_h472;
    `modifiedAt`?: ApplicationList_modifiedAt_h473;
    `operational`?: (string)[];
    @js(#{`description`:"By attribute name."}) `attributes`?: Record<ApplicationList_attributes_ap_h475>;
    @js(#{`description`:"By attribute name."}) `fields`?: Record<ApplicationList_fields_ap_h477>;
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
      `values`?: (ApplicationList_attributesShown_i_values_i_h479)[];
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
      `origin`?: ApplicationList_authenticationEvents_i_origin_h480;
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
      @js(#{`description`:"What the event recorded."}) `detail`?: Record<ApplicationList_authenticationEvents_i_detail_ap_h481>
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
          `description`?: ApplicationList_credentials_clientSecret_secrets_i_description_h482;
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
        `certificate`?: ApplicationList_credentials_keyPairs_i_certificate_h483;
        `chain`?: ({
          `subject`?: string;
          `issuer`?: string;
          `serialHex`?: string;
          `notBefore`?: string;
          `notAfter`?: string;
          `expired`?: boolean;
          `selfSigned`?: boolean;
          `keyType`?: ApplicationList_credentials_keyPairs_i_chain_i_keyType_h484;
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
            `certificate`?: ApplicationList_credentials_keyPairs_i_registered_keys_i_certificate_h485
          })[];
          `certificates`?: ({
            `subject`?: string;
            `issuer`?: string;
            `serialHex`?: string;
            `notBefore`?: string;
            `notAfter`?: string;
            `expired`?: boolean;
            `selfSigned`?: boolean;
            `keyType`?: ApplicationList_credentials_keyPairs_i_registered_certificates_i_keyType_h486;
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
          `label`?: ApplicationList_credentials_mtls_certificates_i_label_h487;
          `subject`?: ApplicationList_credentials_mtls_certificates_i_subject_h488;
          `keyAlg`?: ApplicationList_credentials_mtls_certificates_i_keyAlg_h489;
          `notBefore`?: ApplicationList_credentials_mtls_certificates_i_notBefore_h490;
          `notAfter`?: ApplicationList_credentials_mtls_certificates_i_notAfter_h491;
          `thumbprint`?: ApplicationList_credentials_mtls_certificates_i_thumbprint_h492;
          `state`?: string;
          `reason`?: ApplicationList_credentials_mtls_certificates_i_reason_h493;
          `revokedAt`?: ApplicationList_credentials_mtls_certificates_i_revokedAt_h494;
          `certificatePem`?: ApplicationList_credentials_mtls_certificates_i_certificatePem_h495
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
          `label`?: ApplicationList_credentials_signing_certificates_i_label_h496;
          `subject`?: ApplicationList_credentials_signing_certificates_i_subject_h497;
          `keyAlg`?: ApplicationList_credentials_signing_certificates_i_keyAlg_h498;
          `notBefore`?: ApplicationList_credentials_signing_certificates_i_notBefore_h499;
          `notAfter`?: ApplicationList_credentials_signing_certificates_i_notAfter_h500;
          `thumbprint`?: ApplicationList_credentials_signing_certificates_i_thumbprint_h501;
          `state`?: string;
          `reason`?: ApplicationList_credentials_signing_certificates_i_reason_h502;
          `revokedAt`?: ApplicationList_credentials_signing_certificates_i_revokedAt_h503;
          `certificatePem`?: ApplicationList_credentials_signing_certificates_i_certificatePem_h504
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
        `dn`?: ApplicationList_credentials_stored_dn_h505;
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
        `statusReason`?: ApplicationList_sharedSignals_streams_i_statusReason_h506;
        `aud`?: ApplicationList_sharedSignals_streams_i_aud_h508;
        `delivery`?: {
          `method`?: string;
          `endpoint_url`?: ApplicationList_sharedSignals_streams_i_delivery_endpoint_url_h509
        };
        `events_requested`?: (string)[];
        `events_delivered`?: (string)[];
        `format`?: string;
        `description`?: string;
        `createdBy`?: string;
        `createdAt`?: ApplicationList_sharedSignals_streams_i_createdAt_h510;
        `updatedAt`?: ApplicationList_sharedSignals_streams_i_updatedAt_h511;
        `lastPushAt`?: ApplicationList_sharedSignals_streams_i_lastPushAt_h512;
        `lastPushError`?: string
      })[];
      `settings`?: ({
        `setting`?: string;
        `attribute`?: string;
        `value`?: ApplicationList_sharedSignals_settings_i_value_h513;
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
        `defaultProfile`?: ApplicationList_certificateEnrollment_rules_i_defaultProfile_h514;
        `defaultProfileSource`?: string;
        `certificateLifetimeDays`?: numeric;
        `certificateLifetimeSource`?: string
      })[];
      `certificateCap`?: {`value`?: numeric; `source`?: string};
      `est`?: ApplicationList_certificateEnrollment_est_h515;
      `certificates`?: ({
        `serialHex`?: string;
        `family`?: string;
        `profile`?: string;
        `subject`?: string;
        `names`?: (string)[];
        `thumbprint`?: string;
        `keyAlg`?: string;
        `notBefore`?: ApplicationList_certificateEnrollment_certificates_i_notBefore_h516;
        `notAfter`?: ApplicationList_certificateEnrollment_certificates_i_notAfter_h517;
        `issuedAt`?: string;
        `requestedBy`?: ApplicationList_certificateEnrollment_certificates_i_requestedBy_h518;
        `via`?: string;
        `keySource`?: string;
        `replaces`?: ApplicationList_certificateEnrollment_certificates_i_replaces_h519;
        `certificatePem`?: string;
        `chainPem`?: (string)[];
        `device`?: string;
        `attestation`?: ApplicationList_certificateEnrollment_certificates_i_attestation_h521;
        `revoked`?: {
          `at`?: ApplicationList_certificateEnrollment_certificates_i_revoked_at_h522;
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
        `createdAt`?: ApplicationList_certificateEnrollment_eabKeys_i_createdAt_h523;
        `expiresAt`?: ApplicationList_certificateEnrollment_eabKeys_i_expiresAt_h524;
        `createdBy`?: ApplicationList_certificateEnrollment_eabKeys_i_createdBy_h525;
        `boundAccount`?: ApplicationList_certificateEnrollment_eabKeys_i_boundAccount_h526;
        `boundAt`?: ApplicationList_certificateEnrollment_eabKeys_i_boundAt_h527;
        `status`?: string
      })[];
      `scepChallenges`?: ({
        `id`?: string;
        `profile`?: ApplicationList_certificateEnrollment_scepChallenges_i_profile_h528;
        `createdAt`?: ApplicationList_certificateEnrollment_scepChallenges_i_createdAt_h529;
        `expiresAt`?: ApplicationList_certificateEnrollment_scepChallenges_i_expiresAt_h530;
        `createdBy`?: ApplicationList_certificateEnrollment_scepChallenges_i_createdBy_h531;
        `usedAt`?: ApplicationList_certificateEnrollment_scepChallenges_i_usedAt_h532;
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
        `value`?: ApplicationList_customClaims_i_realm_i_value_h534;
        `nameFormat`?: string;
        `namespace`?: string;
        `attribute`?: string;
        `multi`?: boolean;
        `type`?: string
      })[];
      `own`?: ({
        `name`?: string;
        `value`?: ApplicationList_customClaims_i_own_i_value_h536;
        `nameFormat`?: string;
        `namespace`?: string;
        `attribute`?: string;
        `multi`?: boolean;
        `type`?: string
      })[];
      `effective`?: ({
        `name`?: string;
        `value`?: ApplicationList_customClaims_i_effective_i_value_h538;
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
          `value`?: ApplicationList_claimSelections_preview_byLdap_ap_value_h540;
          `source`?: string;
          `ldpTerm`?: ApplicationList_claimSelections_preview_byLdap_ap_ldpTerm_h541
        }>;
        `entryFound`?: boolean
      };
      `sets`?: ({
        `id`?: string;
        `label`?: string;
        `attribute`?: string;
        `realm`?: (string)[];
        `own`?: ApplicationList_claimSelections_sets_i_own_h542;
        `inherited`?: boolean;
        `effective`?: (string)[];
        @js(#{`description`:"The claims, by name."}) `claims`?: Record<ApplicationList_claimSelections_sets_i_claims_ap_h548>;
        `report`?: ({
          `ldap`?: string;
          `claim`?: string;
          `value`?: ApplicationList_claimSelections_sets_i_report_i_value_h550;
          `source`?: string;
          `ldpTerm`?: ApplicationList_claimSelections_sets_i_report_i_ldpTerm_h551
        })[]
      })[];
      `credential`?: ApplicationList_claimSelections_credential_h552
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
      `issued`?: ApplicationList_softwareStatements_issued_h553;
      `registeredWith`?: ApplicationList_softwareStatements_registeredWith_h554;
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
        `baseUri`?: ApplicationList_delegatedPermissions_held_i_baseUri_h555;
        `permissionName`?: string;
        `description`?: ApplicationList_delegatedPermissions_held_i_description_h556;
        `dangling`?: boolean;
        `asked`?: boolean
      })[];
      `exposes`?: ({
        `resource`?: string;
        `resourceName`?: string;
        `baseUri`?: ApplicationList_delegatedPermissions_exposes_i_baseUri_h557;
        `name`?: string;
        `description`?: ApplicationList_delegatedPermissions_exposes_i_description_h558;
        `id`?: ApplicationList_delegatedPermissions_exposes_i_id_h559;
        `raw`?: ApplicationList_delegatedPermissions_exposes_i_raw_h560;
        `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
      })[];
      `offerable`?: (ApplicationList_delegatedPermissions_offerable_i_h561)[];
      `grantedOut`?: ({
        `client`?: string;
        `clientName`?: string;
        `permissionId`?: string;
        `resource`?: string;
        `resourceName`?: string;
        `baseUri`?: ApplicationList_delegatedPermissions_grantedOut_i_baseUri_h562;
        `permissionName`?: string;
        `description`?: ApplicationList_delegatedPermissions_grantedOut_i_description_h563;
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

@js(#{`$types`:#["string","null"]}) @hoisted model NewUserForm_container_h564 {}

@js(#{
    `additionalProperties`:#{
      `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
    },
    `$types`:#["object","null"]
  }) @hoisted model NewUserForm_invented_h565 {}

@js(#{
    `description`:"Every attribute a person may be created with, and the four ways they can be given a way in."
  }) @component model `NewUserForm` {
    `directory`?: boolean;
    `container`?: NewUserForm_container_h564;
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
    `invented`?: NewUserForm_invented_h565;
    `inventRefused`?: string
  }

@js(#{`$types`:#["string","null"]}) @hoisted model NewApplicationForm_container_h566 {}

@js(#{`$types`:#["number","null"]}) @hoisted model NewApplicationForm_max_h567 {}

@hoisted union NewApplicationForm_declarations_i_editable_h568 {string, boolean}

@hoisted union NewApplicationForm_fields_i_editable_h569 {string, boolean}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","null"]}) @hoisted model NewApplicationForm_fields_i_choices_h570 {}

@js(#{`$types`:#["string","null"]}) @hoisted model NewApplicationForm_fields_i_example_h571 {}

@hoisted union NewApplicationForm_fields_i_described_value_h572 {string, numeric, boolean, null, (string)[]}

@js(#{`$types`:#["string","null"]}) @hoisted model NewApplicationForm_fields_i_described_env_h573 {}

@js(#{`$types`:#["string","null"]}) @hoisted model NewApplicationForm_fields_i_described_legacyEnv_h574 {}

@hoisted union NewApplicationForm_fields_i_described_default_h575 {string, numeric, boolean, null, (string)[]}

@hoisted union NewApplicationForm_editable_i_mode_h576 {string, boolean}

@component model `NewApplicationForm` {
    `directory`?: boolean;
    `container`?: NewApplicationForm_container_h566;
    `max`?: NewApplicationForm_max_h567;
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
      `editable`?: NewApplicationForm_declarations_i_editable_h568;
      `sensitive`?: boolean;
      `what`?: string;
      `families`?: ({`id`?: string; `label`?: string})[];
      `everyFamily`?: boolean
    })[];
    `fields`?: ({
      `attribute`?: string;
      `type`?: string;
      `long`?: boolean;
      `editable`?: NewApplicationForm_fields_i_editable_h569;
      `sensitive`?: boolean;
      `overrides`?: string;
      `choices`?: NewApplicationForm_fields_i_choices_h570;
      `example`?: NewApplicationForm_fields_i_example_h571;
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
        `value`?: NewApplicationForm_fields_i_described_value_h572;
        `text`?: string;
        `source`?: string;
        `editable`?: boolean;
        `restartReason`?: string;
        `editRefusal`?: string;
        `env`?: NewApplicationForm_fields_i_described_env_h573;
        `legacyEnv`?: NewApplicationForm_fields_i_described_legacyEnv_h574;
        `appconfigPath`?: string;
        `default`?: NewApplicationForm_fields_i_described_default_h575;
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
      `mode`?: NewApplicationForm_editable_i_mode_h576;
      `sensitive`?: boolean;
      `families`?: (string)[]
    })[]
  }

@js(#{`$types`:#["number","null"]}) @hoisted model GroupList_port_h577 {}

@js(#{`$types`:#["string","null"]}) @hoisted model GroupList_listenError_h578 {}

@js(#{`$types`:#["number","null"]}) @hoisted model GroupList_ldapsPort_h579 {}

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
            `settings`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `key`:#{`type`:"string"},
                  `group`:#{`type`:"string"},
                  `label`:#{`type`:"string"},
                  `description`:#{`type`:"string"},
                  `type`:#{`type`:"string"},
                  `enumValues`:#{
                    `type`:"array",
                    `items`:#{
                      `anyOf`:#[
                        #{`type`:"string"},
                        #{`type`:"number"},
                        #{`type`:"boolean"},
                        #{`type`:"null"}
                      ]
                    }
                  },
                  `csvValues`:#{
                    `type`:"array",
                    `items`:#{
                      `anyOf`:#[
                        #{`type`:"string"},
                        #{`type`:"number"},
                        #{`type`:"boolean"},
                        #{`type`:"null"}
                      ]
                    }
                  },
                  `ordered`:#{`type`:"boolean"},
                  `csvValueNotes`:#{`type`:"object",`additionalProperties`:#{`type`:"string"}},
                  `selectAll`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `onlyWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      },
                      `aloneWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      }
                    }
                  },
                  `min`:#{`type`:"number"},
                  `max`:#{`type`:"number"},
                  `step`:#{`type`:"number"},
                  `value`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `text`:#{`type`:#["string","null"]},
                  `source`:#{`type`:"string"},
                  `editable`:#{`type`:"boolean"},
                  `restartReason`:#{`type`:"string"},
                  `editRefusal`:#{`type`:"string"},
                  `env`:#{
                    `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                  },
                  `legacyEnv`:#{
                    `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                  },
                  `appconfigPath`:#{`type`:"string"},
                  `default`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `masked`:#{`type`:"boolean"},
                  `realmSettable`:#{`type`:"boolean"},
                  `overridden`:#{`type`:"boolean"}
                }
              }
            }
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
            `anyOf`:#[
              #{`type`:"string"},
              #{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{`path`:#{`type`:"string"},`label`:#{`type`:"string"}}
              }
            ]
          }
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model GroupList_settings_h580 {}

@js(#{`$types`:#["string","null"]}) @hoisted model GroupList_filter_q_h581 {}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","null"]}) @hoisted model GroupList_filter_exclude_h582 {}

@js(#{`$types`:#["string","null"]}) @hoisted model GroupList_adminGroups_read_h583 {}

@js(#{`$types`:#["string","null"]}) @hoisted model GroupList_adminGroups_write_h584 {}

@hoisted union GroupList_groups_i_createdAt_v1_h585 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union GroupList_groups_i_createdAt_h586 {null, GroupList_groups_i_createdAt_v1_h585}

@hoisted union GroupList_groups_i_modifiedAt_v1_h587 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union GroupList_groups_i_modifiedAt_h588 {null, GroupList_groups_i_modifiedAt_v1_h587}

@js(#{`description`:"Every group the embedded directory holds."}) @component model `GroupList` {
    `baseDn`?: string;
    `usersDn`?: string;
    `groupsDn`?: string;
    `port`?: GroupList_port_h577;
    `listening`?: boolean;
    `listenError`?: GroupList_listenError_h578;
    `ldapsPort`?: GroupList_ldapsPort_h579;
    `ldapsListening`?: boolean;
    `entryCount`?: numeric;
    `groupCount`?: numeric;
    `matched`?: numeric;
    `shown`?: numeric;
    `canWrite`?: boolean;
    `membershipValues`?: numeric;
    `dangling`?: numeric;
    `settings`?: GroupList_settings_h580;
    `filter`?: {
      `q`?: GroupList_filter_q_h581;
      `exclude`?: GroupList_filter_exclude_h582
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
      `read`?: GroupList_adminGroups_read_h583;
      `write`?: GroupList_adminGroups_write_h584
    };
    `groups`?: ({
      `dn`?: string;
      `cn`?: string;
      `rule`?: string;
      `description`?: string;
      `objectClass`?: (string)[];
      `origin`?: string;
      `createdAt`?: GroupList_groups_i_createdAt_h586;
      `modifiedAt`?: GroupList_groups_i_modifiedAt_h588;
      `memberCount`?: numeric;
      `presentCount`?: numeric;
      `danglingCount`?: numeric;
      `claimedCount`?: numeric;
      `ownerCount`?: numeric;
      `attributeCount`?: numeric
    })[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryEntryList_filter_q_h589 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryEntryList_filter_origin_h590 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `complete`:#{`type`:"boolean"},
      `scanned`:#{`type`:"integer"},
      `scanLimit`:#{`type`:"integer"}
    },
    `$types`:#["object","null"]
  }) @hoisted model DirectoryEntryList_search_h591 {}

@hoisted union DirectoryEntryList_entries_i_attributes_ap_v1_h592 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union DirectoryEntryList_entries_i_attributes_ap_h593 {null, DirectoryEntryList_entries_i_attributes_ap_v1_h592}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryEntryList_paging_param_h594 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryEntryList_paging_noun_h595 {}

@component model `DirectoryEntryList` {
    `baseDn`?: string;
    `count`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `filter`?: {
      `q`?: DirectoryEntryList_filter_q_h589;
      `origin`?: DirectoryEntryList_filter_origin_h590
    };
    `origins`?: (string)[];
    @js(#{`description`:"A count per name."}) `originCounts`?: Record<numeric>;
    `order`?: string;
    `search`?: DirectoryEntryList_search_h591;
    `entries`?: ({
      `dn`?: string;
      `origin`?: string;
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `attributes`?: Record<DirectoryEntryList_entries_i_attributes_ap_h593>
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
      `param`?: DirectoryEntryList_paging_param_h594;
      `noun`?: DirectoryEntryList_paging_noun_h595
    };
    `directory`?: boolean;
    `message`?: string
  }

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryApplicationList_filter_q_h596 {}

@hoisted union DirectoryApplicationList_schema_attributes_i_editable_h597 {boolean, string}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryApplicationList_applications_i_dnLabel_h598 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryApplicationList_applications_i_dn_h599 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryApplicationList_applications_i_name_h600 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryApplicationList_applications_i_description_h601 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryApplicationList_applications_i_origin_h602 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryApplicationList_applications_i_createdAt_h603 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryApplicationList_applications_i_modifiedAt_h604 {}

@hoisted union DirectoryApplicationList_applications_i_attributes_ap_v1_h605 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union DirectoryApplicationList_applications_i_attributes_ap_h606 {null, DirectoryApplicationList_applications_i_attributes_ap_v1_h605}

@hoisted union DirectoryApplicationList_applications_i_fields_ap_v1_h607 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union DirectoryApplicationList_applications_i_fields_ap_h608 {null, DirectoryApplicationList_applications_i_fields_ap_v1_h607}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryApplicationList_paging_param_h609 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryApplicationList_paging_noun_h610 {}

@component model `DirectoryApplicationList` {
    `baseDn`?: string;
    `container`?: string;
    `count`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `max`?: integer;
    `filter`?: {`q`?: DirectoryApplicationList_filter_q_h596};
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
        `editable`?: DirectoryApplicationList_schema_attributes_i_editable_h597;
        `enum`?: (string)[];
        `families`?: (string)[];
        `familyWhy`?: string;
        `overrides`?: string;
        `strictOverride`?: boolean
      })[]
    };
    `applications`?: ({
      `identifier`?: string;
      `dnLabel`?: DirectoryApplicationList_applications_i_dnLabel_h598;
      `dn`?: DirectoryApplicationList_applications_i_dn_h599;
      `name`?: DirectoryApplicationList_applications_i_name_h600;
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
      `description`?: DirectoryApplicationList_applications_i_description_h601;
      `origin`?: DirectoryApplicationList_applications_i_origin_h602;
      `createdAt`?: DirectoryApplicationList_applications_i_createdAt_h603;
      `modifiedAt`?: DirectoryApplicationList_applications_i_modifiedAt_h604;
      `operational`?: (string)[];
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `attributes`?: Record<DirectoryApplicationList_applications_i_attributes_ap_h606>;
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `fields`?: Record<DirectoryApplicationList_applications_i_fields_ap_h608>
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
      `param`?: DirectoryApplicationList_paging_param_h609;
      `noun`?: DirectoryApplicationList_paging_noun_h610
    };
    `directory`?: boolean;
    `message`?: string
  }

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryFederationList_filter_q_h611 {}

@hoisted union DirectoryFederationList_schema_attributes_i_editable_h612 {boolean, string}

@hoisted union DirectoryFederationList_relationships_i_entryAttributes_ap_v1_h613 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union DirectoryFederationList_relationships_i_entryAttributes_ap_h614 {
    null,
    DirectoryFederationList_relationships_i_entryAttributes_ap_v1_h613
  }

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryFederationList_paging_param_h615 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryFederationList_paging_noun_h616 {}

@component model `DirectoryFederationList` {
    `baseDn`?: string;
    `container`?: string;
    `count`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `max`?: integer;
    `filter`?: {`q`?: DirectoryFederationList_filter_q_h611};
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
        `editable`?: DirectoryFederationList_schema_attributes_i_editable_h612;
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
      }) `entryAttributes`?: Record<DirectoryFederationList_relationships_i_entryAttributes_ap_h614>;
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
      `param`?: DirectoryFederationList_paging_param_h615;
      `noun`?: DirectoryFederationList_paging_noun_h616
    };
    `directory`?: boolean;
    `message`?: string
  }

@hoisted union DirectorySpiffe_schema_attributes_i_editable_h617 {boolean, string}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectorySpiffe_filter_entryq_h618 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectorySpiffe_filter_agentq_h619 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectorySpiffe_entriesPaging_param_h620 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectorySpiffe_entriesPaging_noun_h621 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectorySpiffe_agentsPaging_param_h622 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectorySpiffe_agentsPaging_noun_h623 {}

@hoisted union DirectorySpiffe_registrationEntries_i_attributes_ap_v1_h624 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union DirectorySpiffe_registrationEntries_i_attributes_ap_h625 {null, DirectorySpiffe_registrationEntries_i_attributes_ap_v1_h624}

@hoisted union DirectorySpiffe_attestedAgents_i_attributes_ap_v1_h626 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union DirectorySpiffe_attestedAgents_i_attributes_ap_h627 {null, DirectorySpiffe_attestedAgents_i_attributes_ap_v1_h626}

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
        `editable`?: DirectorySpiffe_schema_attributes_i_editable_h617;
        `enum`?: (string)[];
        `families`?: (string)[];
        `familyWhy`?: string;
        `overrides`?: string;
        `strictOverride`?: boolean
      })[]
    };
    `filter`?: {
      `entryq`?: DirectorySpiffe_filter_entryq_h618;
      `agentq`?: DirectorySpiffe_filter_agentq_h619
    };
    `entriesPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: DirectorySpiffe_entriesPaging_param_h620;
      `noun`?: DirectorySpiffe_entriesPaging_noun_h621
    };
    `agentsPaging`?: {
      `page`?: integer;
      `pages`?: integer;
      `perPage`?: integer;
      `firstRow`?: integer;
      `lastRow`?: integer;
      `total`?: integer;
      `param`?: DirectorySpiffe_agentsPaging_param_h622;
      `noun`?: DirectorySpiffe_agentsPaging_noun_h623
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
      }) `attributes`?: Record<DirectorySpiffe_registrationEntries_i_attributes_ap_h625>
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
      }) `attributes`?: Record<DirectorySpiffe_attestedAgents_i_attributes_ap_h627>
    })[];
    `directory`?: boolean;
    `message`?: string
  }

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryRoleList_filter_q_h628 {}

@hoisted union DirectoryRoleList_schema_attributes_i_editable_h629 {boolean, string}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryRoleList_roles_i_origin_h630 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryRoleList_roles_i_createdAt_h631 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryRoleList_roles_i_modifiedAt_h632 {}

@hoisted union DirectoryRoleList_roles_i_attributes_ap_v1_h633 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union DirectoryRoleList_roles_i_attributes_ap_h634 {null, DirectoryRoleList_roles_i_attributes_ap_v1_h633}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryRoleList_paging_param_h635 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryRoleList_paging_noun_h636 {}

@component model `DirectoryRoleList` {
    `baseDn`?: string;
    `container`?: string;
    `count`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `max`?: integer;
    `filter`?: {`q`?: DirectoryRoleList_filter_q_h628};
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
        `editable`?: DirectoryRoleList_schema_attributes_i_editable_h629;
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
      `origin`?: DirectoryRoleList_roles_i_origin_h630;
      `createdAt`?: DirectoryRoleList_roles_i_createdAt_h631;
      `modifiedAt`?: DirectoryRoleList_roles_i_modifiedAt_h632;
      `operational`?: (string)[];
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `attributes`?: Record<DirectoryRoleList_roles_i_attributes_ap_h634>
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
      `param`?: DirectoryRoleList_paging_param_h635;
      `noun`?: DirectoryRoleList_paging_noun_h636
    };
    `directory`?: boolean;
    `message`?: string
  }

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryPolicyList_filter_q_h637 {}

@hoisted union DirectoryPolicyList_schema_attributes_i_editable_h638 {boolean, string}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryPolicyList_policies_i_origin_h639 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryPolicyList_policies_i_createdAt_h640 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryPolicyList_policies_i_modifiedAt_h641 {}

@hoisted union DirectoryPolicyList_policies_i_attributes_ap_v1_h642 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union DirectoryPolicyList_policies_i_attributes_ap_h643 {null, DirectoryPolicyList_policies_i_attributes_ap_v1_h642}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryPolicyList_paging_param_h644 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryPolicyList_paging_noun_h645 {}

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
    `filter`?: {`q`?: DirectoryPolicyList_filter_q_h637};
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
        `editable`?: DirectoryPolicyList_schema_attributes_i_editable_h638;
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
      `origin`?: DirectoryPolicyList_policies_i_origin_h639;
      `createdAt`?: DirectoryPolicyList_policies_i_createdAt_h640;
      `modifiedAt`?: DirectoryPolicyList_policies_i_modifiedAt_h641;
      `operational`?: (string)[];
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `attributes`?: Record<DirectoryPolicyList_policies_i_attributes_ap_h643>
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
      `param`?: DirectoryPolicyList_paging_param_h644;
      `noun`?: DirectoryPolicyList_paging_noun_h645
    };
    `directory`?: boolean;
    `message`?: string
  }

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryPepList_filter_q_h646 {}

@hoisted union DirectoryPepList_schema_attributes_i_editable_h647 {boolean, string}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryPepList_peps_i_origin_h648 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryPepList_peps_i_createdAt_h649 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryPepList_peps_i_modifiedAt_h650 {}

@hoisted union DirectoryPepList_peps_i_attributes_ap_v1_h651 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union DirectoryPepList_peps_i_attributes_ap_h652 {null, DirectoryPepList_peps_i_attributes_ap_v1_h651}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryPepList_paging_param_h653 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryPepList_paging_noun_h654 {}

@component model `DirectoryPepList` {
    `baseDn`?: string;
    `container`?: string;
    `count`?: integer;
    `matched`?: integer;
    `shown`?: integer;
    `max`?: integer;
    `filter`?: {`q`?: DirectoryPepList_filter_q_h646};
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
        `editable`?: DirectoryPepList_schema_attributes_i_editable_h647;
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
      `origin`?: DirectoryPepList_peps_i_origin_h648;
      `createdAt`?: DirectoryPepList_peps_i_createdAt_h649;
      `modifiedAt`?: DirectoryPepList_peps_i_modifiedAt_h650;
      `operational`?: (string)[];
      @js(#{
        `description`:"Attribute names, which are data in a schemaless directory, and values."
      }) `attributes`?: Record<DirectoryPepList_peps_i_attributes_ap_h652>
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
      `param`?: DirectoryPepList_paging_param_h653;
      `noun`?: DirectoryPepList_paging_noun_h654
    };
    `directory`?: boolean;
    `message`?: string
  }

@js(#{`$types`:#["integer","null"]}) @hoisted model DirectoryService_port_h655 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_listenError_h656 {}

@js(#{`$types`:#["boolean","null"]}) @hoisted model DirectoryService_persistence_healthy_h657 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_persistence_dataDir_h658 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `host`:#{`type`:#["string","null"]},
      `port`:#{`type`:#["string","null"]},
      `database`:#{`type`:#["string","null"]},
      `user`:#{`type`:#["string","null"]},
      `passwordFrom`:#{`type`:"string"},
      `passwordProvider`:#{`type`:"string"},
      `passwordSecret`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `secret`:#{`type`:"string"},
          `configured`:#{`type`:"boolean"},
          `provider`:#{`type`:"string"},
          `label`:#{`type`:"string"},
          `known`:#{`type`:"boolean"},
          `where`:#{
            `type`:"object",
            `additionalProperties`:false,
            `properties`:#{
              `from`:#{`type`:"string"},
              `shared`:#{`type`:"boolean"},
              `region`:#{`type`:"string"},
              `vault`:#{`type`:"string"},
              `endpoint`:#{`type`:"string"},
              `field`:#{`type`:"string"},
              `wraps`:#{`type`:"string"},
              `authenticates`:#{`type`:"string"}
            }
          },
          `shared`:#{`type`:"boolean"},
          `field`:#{`type`:"string"},
          `providers`:#{
            `type`:"array",
            `items`:#{
              `type`:"object",
              `additionalProperties`:false,
              `properties`:#{`id`:#{`type`:"string"},`label`:#{`type`:"string"}}
            }
          }
        }
      },
      `sslmode`:#{`type`:"string"},
      `encrypted`:#{`type`:"boolean"},
      `verifyCertificate`:#{`type`:"boolean"},
      `caFile`:#{`type`:#["string","null"]},
      `tls`:#{`type`:"string"},
      `note`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model DirectoryService_persistence_database_h659 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_persistence_engine_h660 {}

@hoisted union DirectoryService_persistence_lastWriteAt_h661 {numeric, string, null}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_persistence_lastError_h662 {}

@hoisted union DirectoryService_persistence_restoredAt_h663 {numeric, string, null}

@hoisted union DirectoryService_persistence_minted_lastWriteAt_h664 {numeric, string, null}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_persistence_minted_lastError_h665 {}

@hoisted union DirectoryService_persistence_minted_restoredAt_h666 {numeric, string, null}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_persistence_usedAssertions_store_h667 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_persistence_usedAssertions_kind_h668 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_persistence_usedAssertions_why_h669 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DirectoryService_persistence_usedAssertions_live_h670 {}

@hoisted union DirectoryService_persistence_replication_startedAt_h671 {numeric, string, null}

@hoisted union DirectoryService_persistence_replication_lastPullAt_h672 {numeric, string, null}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_persistence_replication_lastError_h673 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_persistence_replication_retention_reportedAt_h674 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_persistence_replication_retention_reportError_h675 {}

@hoisted union DirectoryService_persistence_replication_retention_declaredGoneAt_h676 {numeric, string, null}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `at`:#{`type`:"string"},
      `error`:#{`type`:#["string","null"]},
      `trimmed`:#{`type`:"number"},
      `bound`:#{`type`:#["number","null"]},
      `readers`:#{`type`:"number"},
      `readersGone`:#{`type`:"number"}
    },
    `$types`:#["object","null"]
  }) @hoisted model DirectoryService_persistence_replication_retention_lastTrim_h677 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `cell`:#{`type`:#["string","null"]},
      `jurisdiction`:#{`type`:#["string","null"]},
      `globalReplication`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `coordinating`:#{`type`:"boolean"},
          `supported`:#{`type`:"boolean"},
          `startedAt`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]},
          `appliedSeq`:#{`type`:"number"},
          `highestSeq`:#{`type`:"number"},
          `holes`:#{`type`:"number"},
          `holeRanges`:#{`type`:"number"},
          `holesAbandoned`:#{`type`:"number"},
          `pollIntervalMs`:#{`type`:"number"},
          `pulls`:#{`type`:"number"},
          `nudges`:#{`type`:"number"},
          `failures`:#{`type`:"number"},
          `rowsApplied`:#{`type`:"number"},
          `byKind`:#{
            `type`:"object",
            `additionalProperties`:#{`type`:"number"},
            `description`:"A count per name."
          },
          `lastPullAt`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]},
          `lastError`:#{`type`:#["string","null"]},
          `otherProcesses`:#{`type`:"number"},
          `originsDropped`:#{`type`:"number"},
          `retention`:#{
            `type`:"object",
            `additionalProperties`:false,
            `properties`:#{
              `retentionS`:#{`type`:"number"},
              `readerTtlS`:#{`type`:"number"},
              `reportedAt`:#{`type`:#["string","null"]},
              `reportError`:#{`type`:#["string","null"]},
              `declaredGoneAt`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]},
              `fanInGraceS`:#{`type`:"number"},
              `trimming`:#{`type`:"boolean"},
              `lastTrim`:#{
                `type`:#["object","null"],
                `additionalProperties`:false,
                `properties`:#{
                  `at`:#{`type`:"string"},
                  `error`:#{`type`:#["string","null"]},
                  `trimmed`:#{`type`:"number"},
                  `bound`:#{`type`:#["number","null"]},
                  `readers`:#{`type`:"number"},
                  `readersGone`:#{`type`:"number"}
                }
              }
            }
          },
          `note`:#{`type`:"string"}
        }
      },
      `routing`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `indexed`:#{`type`:"number"},
          `conflicts`:#{`type`:"number"},
          `lastConflict`:#{`type`:#["string","null"]},
          `projectionWrites`:#{`type`:"number"}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model DirectoryService_persistence_cells_h678 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `origin`:#{`type`:#["string","null"]},
      `adopted`:#{`type`:"boolean"},
      `why`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model DirectoryService_persistence_origin_h679 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `open`:#{`type`:"boolean"},
      `queries`:#{`type`:"number"},
      `connects`:#{`type`:"number"},
      `drops`:#{`type`:"number"},
      `viaPool`:#{`type`:"number"}
    },
    `$types`:#["object","null"]
  }) @hoisted model DirectoryService_persistence_liveness_h680 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `lastReport`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `maxMs`:#{`type`:"number"},
          `p99Ms`:#{`type`:"number"},
          `meanMs`:#{`type`:"number"},
          `at`:#{`type`:"string"}
        }
      },
      `sinceReport`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `maxMs`:#{`type`:"number"},
          `p99Ms`:#{`type`:"number"},
          `meanMs`:#{`type`:"number"},
          `at`:#{`type`:"string"}
        }
      },
      `warnAboveMs`:#{`type`:"number"}
    },
    `$types`:#["object","null"]
  }) @hoisted model DirectoryService_persistence_eventLoop_h681 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model DirectoryService_tls_port_h682 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_tls_error_h683 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_tls_certificate_subject_h684 {}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","null"]}) @hoisted model DirectoryService_tls_certificate_names_h685 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_tls_certificate_fingerprint256_h686 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_tls_certificate_notAfter_h687 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model DirectoryService_ldapPort_h688 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model DirectoryService_ldapsPort_h689 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DirectoryService_certificateProvenance_h690 {}

@component model `DirectoryService` {
    `url`?: string;
    `port`?: DirectoryService_port_h655;
    `listening`?: boolean;
    `listenError`?: DirectoryService_listenError_h656;
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
      `healthy`?: DirectoryService_persistence_healthy_h657;
      `dataDir`?: DirectoryService_persistence_dataDir_h658;
      `database`?: DirectoryService_persistence_database_h659;
      `engine`?: DirectoryService_persistence_engine_h660;
      `writeDelayMs`?: numeric;
      `persistsDirectory`?: boolean;
      `persistsRealms`?: boolean;
      `persistsAppconfig`?: boolean;
      `pending`?: boolean;
      `writes`?: numeric;
      `failures`?: numeric;
      `lastWriteAt`?: DirectoryService_persistence_lastWriteAt_h661;
      `lastError`?: DirectoryService_persistence_lastError_h662;
      `restoredAt`?: DirectoryService_persistence_restoredAt_h663;
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
        `lastWriteAt`?: DirectoryService_persistence_minted_lastWriteAt_h664;
        `lastError`?: DirectoryService_persistence_minted_lastError_h665;
        `restoredAt`?: DirectoryService_persistence_minted_restoredAt_h666;
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
        `store`?: DirectoryService_persistence_usedAssertions_store_h667;
        `kind`?: DirectoryService_persistence_usedAssertions_kind_h668;
        `persistent`?: boolean;
        `atomicAcrossProcesses`?: boolean;
        `why`?: DirectoryService_persistence_usedAssertions_why_h669;
        `cap`?: numeric;
        `live`?: DirectoryService_persistence_usedAssertions_live_h670;
        `liveIsCurrent`?: boolean
      };
      `replication`?: {
        `coordinating`?: boolean;
        `supported`?: boolean;
        `startedAt`?: DirectoryService_persistence_replication_startedAt_h671;
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
        `lastPullAt`?: DirectoryService_persistence_replication_lastPullAt_h672;
        `lastError`?: DirectoryService_persistence_replication_lastError_h673;
        `otherProcesses`?: numeric;
        `originsDropped`?: numeric;
        `retention`?: {
          `retentionS`?: numeric;
          `readerTtlS`?: numeric;
          `reportedAt`?: DirectoryService_persistence_replication_retention_reportedAt_h674;
          `reportError`?: DirectoryService_persistence_replication_retention_reportError_h675;
          `declaredGoneAt`?: DirectoryService_persistence_replication_retention_declaredGoneAt_h676;
          `fanInGraceS`?: numeric;
          `trimming`?: boolean;
          `lastTrim`?: DirectoryService_persistence_replication_retention_lastTrim_h677
        };
        `note`?: string
      };
      `cells`?: DirectoryService_persistence_cells_h678;
      `origin`?: DirectoryService_persistence_origin_h679;
      `answersAfterCommit`?: boolean;
      `commitBacklog`?: boolean;
      `retryArmed`?: boolean;
      `liveness`?: DirectoryService_persistence_liveness_h680;
      `eventLoop`?: DirectoryService_persistence_eventLoop_h681;
      `note`?: string
    };
    `tls`?: {
      `ldaps`?: boolean;
      `port`?: DirectoryService_tls_port_h682;
      `url`?: string;
      `listening`?: boolean;
      `error`?: DirectoryService_tls_error_h683;
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
        `subject`?: DirectoryService_tls_certificate_subject_h684;
        `names`?: DirectoryService_tls_certificate_names_h685;
        `fingerprint256`?: DirectoryService_tls_certificate_fingerprint256_h686;
        `notAfter`?: DirectoryService_tls_certificate_notAfter_h687;
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
    `ldapPort`?: DirectoryService_ldapPort_h688;
    `ldapsPort`?: DirectoryService_ldapsPort_h689;
    `certificateProvenance`?: DirectoryService_certificateProvenance_h690;
    `directory`?: boolean;
    `message`?: string
  }

@js(#{`$types`:#["number","null"]}) @hoisted model GroupDetail_port_h691 {}

@js(#{`$types`:#["string","null"]}) @hoisted model GroupDetail_listenError_h692 {}

@js(#{`$types`:#["number","null"]}) @hoisted model GroupDetail_ldapsPort_h693 {}

@hoisted union GroupDetail_group_createdAt_v1_h694 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union GroupDetail_group_createdAt_h695 {null, GroupDetail_group_createdAt_v1_h694}

@hoisted union GroupDetail_group_modifiedAt_v1_h696 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union GroupDetail_group_modifiedAt_h697 {null, GroupDetail_group_modifiedAt_v1_h696}

@hoisted union GroupDetail_group_attributes_ap_h698 {string, (string)[]}

@hoisted union GroupDetail_groups_i_createdAt_v1_h699 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union GroupDetail_groups_i_createdAt_h700 {null, GroupDetail_groups_i_createdAt_v1_h699}

@hoisted union GroupDetail_groups_i_modifiedAt_v1_h701 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union GroupDetail_groups_i_modifiedAt_h702 {null, GroupDetail_groups_i_modifiedAt_v1_h701}

@js(#{`$types`:#["string","null"]}) @hoisted model GroupDetail_adminGroups_read_h703 {}

@js(#{`$types`:#["string","null"]}) @hoisted model GroupDetail_adminGroups_write_h704 {}

@js(#{
    `description`:"One group, with the same directory facts the list carries around it."
  }) @component model `GroupDetail` {
    `baseDn`?: string;
    `usersDn`?: string;
    `groupsDn`?: string;
    `port`?: GroupDetail_port_h691;
    `listening`?: boolean;
    `listenError`?: GroupDetail_listenError_h692;
    `ldapsPort`?: GroupDetail_ldapsPort_h693;
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
      `createdAt`?: GroupDetail_group_createdAt_h695;
      `modifiedAt`?: GroupDetail_group_modifiedAt_h697;
      `operational`?: (string)[];
      `memberAttributes`?: (string)[];
      `attributes`?: Record<GroupDetail_group_attributes_ap_h698>;
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
      `createdAt`?: GroupDetail_groups_i_createdAt_h700;
      `modifiedAt`?: GroupDetail_groups_i_modifiedAt_h702;
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
      `read`?: GroupDetail_adminGroups_read_h703;
      `write`?: GroupDetail_adminGroups_write_h704
    }
  }

@hoisted union IssuedSet_username_v4_i_h705 {string, numeric, boolean}

@hoisted union IssuedSet_username_h706 {string, numeric, boolean, null, (IssuedSet_username_v4_i_h705)[]}

@hoisted union IssuedSet_sub_v4_i_h707 {string, numeric, boolean}

@hoisted union IssuedSet_sub_h708 {string, numeric, boolean, null, (IssuedSet_sub_v4_i_h707)[]}

@hoisted union IssuedSet_client_id_v4_i_h709 {string, numeric, boolean}

@hoisted union IssuedSet_client_id_h710 {string, numeric, boolean, null, (IssuedSet_client_id_v4_i_h709)[]}

@hoisted union IssuedSet_scope_v4_i_h711 {string, numeric, boolean}

@hoisted union IssuedSet_scope_h712 {string, numeric, boolean, null, (IssuedSet_scope_v4_i_h711)[]}

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
    `username`?: IssuedSet_username_h706;
    `sub`?: IssuedSet_sub_h708;
    `client_id`?: IssuedSet_client_id_h710;
    `audience`?: string;
    `scope`?: IssuedSet_scope_h712;
    `sessionId`?: string;
    `sessionAuthenticated`?: boolean;
    `grant`?: string;
    `revocableCount`?: integer;
    `revokedCount`?: integer;
    `members`?: (`IssuedRecord`)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model IssuedSetDetail_setKey_h713 {}

@js(#{`$comb`:"oneOf"}) @hoisted union IssuedSetDetail_set_h714 {null, `IssuedSet`}

@js(#{`$types`:#["string","null"]}) @hoisted model IssuedSetDetail_why_h715 {}

@component model `IssuedSetDetail` {
    `setKey`?: IssuedSetDetail_setKey_h713;
    `set`?: IssuedSetDetail_set_h714;
    `found`?: boolean;
    `why`?: IssuedSetDetail_why_h715
  }

@js(#{`$types`:#["number","null"]}) @hoisted model IssuedList_coverage_newest_h716 {}

@js(#{`$types`:#["string","null"]}) @hoisted model IssuedList_coverage_session_h717 {}

@js(#{`$types`:#["string","null"]}) @hoisted model IssuedList_filter_family_h718 {}

@js(#{`$types`:#["string","null"]}) @hoisted model IssuedList_filter_kind_h719 {}

@js(#{`$types`:#["string","null"]}) @hoisted model IssuedList_filter_state_h720 {}

@js(#{`$types`:#["string","null"]}) @hoisted model IssuedList_filter_session_h721 {}

@component model `IssuedList` {
    `held`?: integer;
    `heldSets`?: integer;
    `coverage`?: {
      `source`?: string;
      `complete`?: boolean;
      `newest`?: IssuedList_coverage_newest_h716;
      `session`?: IssuedList_coverage_session_h717;
      `unread`?: boolean;
      `countEstimated`?: boolean
    };
    `matched`?: integer;
    `matchedCredentials`?: integer;
    `shown`?: integer;
    `shownCredentials`?: integer;
    @js(#{`description`:"Credentials held in each family."}) `heldByFamily`?: Record<integer>;
    `filter`?: {
      `family`?: IssuedList_filter_family_h718;
      `kind`?: IssuedList_filter_kind_h719;
      `state`?: IssuedList_filter_state_h720;
      `session`?: IssuedList_filter_session_h721
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
    `description`:"The CONFIG_FILE this process was started with, which is the file to edit to make a change survive a restart. Nothing here ever writes to it.",
    `$types`:#["string","null"]
  }) @hoisted model Config_configFile_h722 {}

@hoisted union Config_groups_i_settings_i_value_v4_i_h723 {string, numeric, boolean}

@js(#{
    `description`:"The effective value, coerced to its type: a number for int/port, a boolean for bool, an array of strings for csv."
  }) @hoisted union Config_groups_i_settings_i_value_h724 {
    string,
    numeric,
    boolean,
    null,
    (Config_groups_i_settings_i_value_v4_i_h723)[]
  }

@hoisted union Config_groups_i_settings_i_default_v4_i_h725 {string, numeric, boolean}

@js(#{
    `description`:"The built-in default: the `dflt` column of `config.js`'s table, which `env/defaults.js` is GENERATED from. It is what the value WOULD be with nothing set anywhere."
  }) @hoisted union Config_groups_i_settings_i_default_h726 {
    string,
    numeric,
    boolean,
    null,
    (Config_groups_i_settings_i_default_v4_i_h725)[]
  }

@js(#{
    `description`:"One setting: what it is, what it is set to, and where that came from."
  }) @hoisted model Config_groups_i_settings_i_h727 {
    @js(#{
      `description`:"The dot path, which is BOTH the name every operation here takes and the path in the appconfig file. `oid4vci.batchSize` is `appconfig.oid4vci.batchSize`."
    }) `key`?: string;
    @js(#{
      `description`:"The protocol it belongs to, and the console's section heading."
    }) `group`?: string;
    `label`?: string;
    @js(#{`description`:"What it does and why the default is the default."}) `description`?: string;
    @js(#{
      `description`:"How a value posted for it is coerced and checked: one of `config.js`'s types (string, int, port, bool, csv, enum, color)."
    }) `type`?: string;
    @js(#{`description`:"Present on `enum` settings only."}) `enumValues`?: (string)[];
    @js(#{
      `description`:"Present on a `csv` setting whose entries must each be one of these; absent on an open list."
    }) `csvValues`?: (string)[];
    @js(#{
      `description`:"Present, true, when a sensitive value here was replaced."
    }) `masked`?: boolean;
    @js(#{
      `description`:"Present, true, on a `csv` setting whose order is a preference: the first value is the most preferred."
    }) `ordered`?: boolean;
    @js(#{
      `description`:"Present beside `csvValues` where the setting describes each value: the value mapped to one sentence."
    }) `csvValueNotes`?: Record<string>;
    @js(#{
      `description`:"Present on an `ordered` setting whose select-all is narrowed by other settings. `onlyWhileOn`: the values are selected only while that setting is on. `aloneWhileOn`: while that setting is on, only the values are selected. `canBeOn` is false where this mode never lets that setting be on."
    }) `selectAll`?: {
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
    @js(#{
      `description`:"The lowest value POST /config/set will take, on an int setting that declares one."
    }) `min`?: numeric;
    @js(#{`description`:"The highest value it will take."}) `max`?: numeric;
    @js(#{
      `description`:"The value must be a MULTIPLE of this, counted from `min`. The four token lifetimes use 30."
    }) `step`?: numeric;
    `value`?: Config_groups_i_settings_i_value_h724;
    @js(#{
      `description`:"The same value on one line: what the console shows in its input and what the environment variable would carry."
    }) `text`?: string;
    @js(#{
      `description`:"Where the effective value came from, highest first: this trust realm's own value; a runtime override set through this API or the console; the setting's own environment variable; a legacy variable (no row has one since #523); the appconfig file CONFIG_FILE names; `env/defaults.js`, the DEFAULT appconfig file that one is unioned on top of. `default` is reachable only for the DERIVED settings, whose value is a function of a neighbouring setting: for every other setting, no value anywhere stops this service from STARTING."
    }) `source`?: "realm" | "override" | "env" | "env-legacy" | "appconfig" | "defaults" | "default";
    @js(#{
      `description`:"Whether POST /config/set will take it from the realm this answer was read in. False means either the value was consumed at startup or `editRefusal` is set. It is refused rather than accepted, because an accepted change that does nothing reads as having worked."
    }) `editable`?: boolean;
    @js(#{
      `description`:"Why it is not editable, when the value was consumed at startup."
    }) `restartReason`?: string;
    @js(#{
      `description`:"Why this row cannot be edited from the realm the reader is in: `realms.maxCount` while a realm other than the default is ambient. Absent on every row of the default realm's answer."
    }) `editRefusal`?: string;
    @js(#{`description`:"Its environment variable."}) `env`?: string;
    `appconfigPath`?: string;
    `default`?: Config_groups_i_settings_i_default_h726;
    @js(#{`description`:"Whether a trust realm may hold its own value for it."}) `realmSettable`?: boolean;
    @js(#{
      `description`:"Whether a runtime override is in force. Equal to `source === \"override\"`, and reported separately so a caller can filter without matching a string."
    }) `overridden`?: boolean
  }

@js(#{`description`:"One group's settings."}) @hoisted model Config_groups_i_h728 {`group`?: string; `settings`?: (Config_groups_i_settings_i_h727)[]}

@js(#{`description`:"One group, and the page or pages that draw it."}) @hoisted model Config_homes_i_h729 {
    `group`?: string;
    `pages`?: (string)[];
    @js(#{`description`:"The pages' console labels, in the same order."}) `labels`?: (string)[]
  }

@hoisted union Config_settings_groups_i_settings_i_value_v4_i_h730 {string, numeric, boolean}

@js(#{
    `description`:"The effective value, coerced to its type: a number for int/port, a boolean for bool, an array of strings for csv."
  }) @hoisted union Config_settings_groups_i_settings_i_value_h731 {
    string,
    numeric,
    boolean,
    null,
    (Config_settings_groups_i_settings_i_value_v4_i_h730)[]
  }

@hoisted union Config_settings_groups_i_settings_i_default_v4_i_h732 {string, numeric, boolean}

@js(#{
    `description`:"The built-in default: the `dflt` column of `config.js`'s table, which `env/defaults.js` is GENERATED from. It is what the value WOULD be with nothing set anywhere."
  }) @hoisted union Config_settings_groups_i_settings_i_default_h733 {
    string,
    numeric,
    boolean,
    null,
    (Config_settings_groups_i_settings_i_default_v4_i_h732)[]
  }

@js(#{
    `description`:"One setting: what it is, what it is set to, and where that came from."
  }) @hoisted model Config_settings_groups_i_settings_i_h734 {
    @js(#{
      `description`:"The dot path, which is BOTH the name every operation here takes and the path in the appconfig file. `oid4vci.batchSize` is `appconfig.oid4vci.batchSize`."
    }) `key`?: string;
    @js(#{
      `description`:"The protocol it belongs to, and the console's section heading."
    }) `group`?: string;
    `label`?: string;
    @js(#{`description`:"What it does and why the default is the default."}) `description`?: string;
    @js(#{
      `description`:"How a value posted for it is coerced and checked: one of `config.js`'s types (string, int, port, bool, csv, enum, color)."
    }) `type`?: string;
    @js(#{`description`:"Present on `enum` settings only."}) `enumValues`?: (string)[];
    @js(#{
      `description`:"Present on a `csv` setting whose entries must each be one of these; absent on an open list."
    }) `csvValues`?: (string)[];
    @js(#{
      `description`:"Present, true, when a sensitive value here was replaced."
    }) `masked`?: boolean;
    @js(#{
      `description`:"Present, true, on a `csv` setting whose order is a preference: the first value is the most preferred."
    }) `ordered`?: boolean;
    @js(#{
      `description`:"Present beside `csvValues` where the setting describes each value: the value mapped to one sentence."
    }) `csvValueNotes`?: Record<string>;
    @js(#{
      `description`:"Present on an `ordered` setting whose select-all is narrowed by other settings. `onlyWhileOn`: the values are selected only while that setting is on. `aloneWhileOn`: while that setting is on, only the values are selected. `canBeOn` is false where this mode never lets that setting be on."
    }) `selectAll`?: {
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
    @js(#{
      `description`:"The lowest value POST /config/set will take, on an int setting that declares one."
    }) `min`?: numeric;
    @js(#{`description`:"The highest value it will take."}) `max`?: numeric;
    @js(#{
      `description`:"The value must be a MULTIPLE of this, counted from `min`. The four token lifetimes use 30."
    }) `step`?: numeric;
    `value`?: Config_settings_groups_i_settings_i_value_h731;
    @js(#{
      `description`:"The same value on one line: what the console shows in its input and what the environment variable would carry."
    }) `text`?: string;
    @js(#{
      `description`:"Where the effective value came from, highest first: this trust realm's own value; a runtime override set through this API or the console; the setting's own environment variable; a legacy variable (no row has one since #523); the appconfig file CONFIG_FILE names; `env/defaults.js`, the DEFAULT appconfig file that one is unioned on top of. `default` is reachable only for the DERIVED settings, whose value is a function of a neighbouring setting: for every other setting, no value anywhere stops this service from STARTING."
    }) `source`?: "realm" | "override" | "env" | "env-legacy" | "appconfig" | "defaults" | "default";
    @js(#{
      `description`:"Whether POST /config/set will take it from the realm this answer was read in. False means either the value was consumed at startup or `editRefusal` is set. It is refused rather than accepted, because an accepted change that does nothing reads as having worked."
    }) `editable`?: boolean;
    @js(#{
      `description`:"Why it is not editable, when the value was consumed at startup."
    }) `restartReason`?: string;
    @js(#{
      `description`:"Why this row cannot be edited from the realm the reader is in: `realms.maxCount` while a realm other than the default is ambient. Absent on every row of the default realm's answer."
    }) `editRefusal`?: string;
    @js(#{`description`:"Its environment variable."}) `env`?: string;
    `appconfigPath`?: string;
    `default`?: Config_settings_groups_i_settings_i_default_h733;
    @js(#{`description`:"Whether a trust realm may hold its own value for it."}) `realmSettable`?: boolean;
    @js(#{
      `description`:"Whether a runtime override is in force. Equal to `source === \"override\"`, and reported separately so a caller can filter without matching a string."
    }) `overridden`?: boolean
  }

@js(#{`description`:"One group's settings."}) @hoisted model Config_settings_groups_i_h735 {
    `group`?: string;
    `settings`?: (Config_settings_groups_i_settings_i_h734)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model Config_settings_context_configFile_h736 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Config_settings_sharedWith_ap_i_label_h737 {}

@js(#{
    `description`:"Every setting this service has, grouped by the protocol it belongs to. The same table the /admin/config page renders and the same call it makes, so the console and this API cannot come to describe different sets of settings."
  }) @component model `Config` {
    @js(#{`description`:"The realm this was read in."}) `realm`?: string;
    @js(#{`description`:"The keys that realm holds a value of its own for."}) `realmSettings`?: (string)[];
    `configFile`?: Config_configFile_h722;
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
    }) `groups`?: (Config_groups_i_h728)[];
    @js(#{
      `description`:"WHERE EACH GROUP IS EDITED: every group is drawn on the console page for the protocol it configures, so a caller can send a person to the right page. Every one of those forms posts to the same four actions."
    }) `homes`?: (Config_homes_i_h729)[];
    @js(#{
      `description`:"Empty, and reported rather than left implicit. A sentence here means a setting group exists that no console page draws."
    }) `homeProblems`?: (string)[];
    @js(#{
      `description`:"The settings this page draws, described: the same rows GET /config returns, filtered to the ones this page owns."
    }) `settings`?: {
      `page`?: string;
      @js(#{`description`:"In the order `config.js` declares them."}) `groups`?: (Config_settings_groups_i_h735)[];
      `settingCount`?: integer;
      @js(#{`description`:"How many of them can be changed while the service runs."}) `editableCount`?: integer;
      @js(#{`description`:"The keys on this page with a runtime override in force."}) `overridden`?: (string)[];
      @js(#{`description`:"The operation that writes them."}) `setWith`?: string;
      `context`?: {
        `configFile`?: Config_settings_context_configFile_h736;
        `defaultsFile`?: string;
        `persistsAppconfig`?: boolean;
        `persistsRealms`?: boolean;
        `persistenceMode`?: string;
        `inRealm`?: boolean;
        `realmId`?: string
      };
      @js(#{`description`:"A group drawn on another page as well, and those pages."}) `sharedWith`?: Record<({`path`?: string; `label`?: Config_settings_sharedWith_ap_i_label_h737})[]>
    }
  }

@js(#{`description`:"One link the page offers."}) @hoisted model PageSettings_links_i_h738 {`href`?: string; `what`?: string}

@hoisted union PageSettings_settings_groups_i_settings_i_value_v4_i_h739 {string, numeric, boolean}

@js(#{
    `description`:"The effective value, coerced to its type: a number for int/port, a boolean for bool, an array of strings for csv."
  }) @hoisted union PageSettings_settings_groups_i_settings_i_value_h740 {
    string,
    numeric,
    boolean,
    null,
    (PageSettings_settings_groups_i_settings_i_value_v4_i_h739)[]
  }

@hoisted union PageSettings_settings_groups_i_settings_i_default_v4_i_h741 {string, numeric, boolean}

@js(#{
    `description`:"The built-in default: the `dflt` column of `config.js`'s table, which `env/defaults.js` is GENERATED from. It is what the value WOULD be with nothing set anywhere."
  }) @hoisted union PageSettings_settings_groups_i_settings_i_default_h742 {
    string,
    numeric,
    boolean,
    null,
    (PageSettings_settings_groups_i_settings_i_default_v4_i_h741)[]
  }

@js(#{
    `description`:"One setting: what it is, what it is set to, and where that came from."
  }) @hoisted model PageSettings_settings_groups_i_settings_i_h743 {
    @js(#{
      `description`:"The dot path, which is BOTH the name every operation here takes and the path in the appconfig file. `oid4vci.batchSize` is `appconfig.oid4vci.batchSize`."
    }) `key`?: string;
    @js(#{
      `description`:"The protocol it belongs to, and the console's section heading."
    }) `group`?: string;
    `label`?: string;
    @js(#{`description`:"What it does and why the default is the default."}) `description`?: string;
    @js(#{
      `description`:"How a value posted for it is coerced and checked: one of `config.js`'s types (string, int, port, bool, csv, enum, color)."
    }) `type`?: string;
    @js(#{`description`:"Present on `enum` settings only."}) `enumValues`?: (string)[];
    @js(#{
      `description`:"Present on a `csv` setting whose entries must each be one of these; absent on an open list."
    }) `csvValues`?: (string)[];
    @js(#{
      `description`:"Present, true, when a sensitive value here was replaced."
    }) `masked`?: boolean;
    @js(#{
      `description`:"Present, true, on a `csv` setting whose order is a preference: the first value is the most preferred."
    }) `ordered`?: boolean;
    @js(#{
      `description`:"Present beside `csvValues` where the setting describes each value: the value mapped to one sentence."
    }) `csvValueNotes`?: Record<string>;
    @js(#{
      `description`:"Present on an `ordered` setting whose select-all is narrowed by other settings. `onlyWhileOn`: the values are selected only while that setting is on. `aloneWhileOn`: while that setting is on, only the values are selected. `canBeOn` is false where this mode never lets that setting be on."
    }) `selectAll`?: {
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
    @js(#{
      `description`:"The lowest value POST /config/set will take, on an int setting that declares one."
    }) `min`?: numeric;
    @js(#{`description`:"The highest value it will take."}) `max`?: numeric;
    @js(#{
      `description`:"The value must be a MULTIPLE of this, counted from `min`. The four token lifetimes use 30."
    }) `step`?: numeric;
    `value`?: PageSettings_settings_groups_i_settings_i_value_h740;
    @js(#{
      `description`:"The same value on one line: what the console shows in its input and what the environment variable would carry."
    }) `text`?: string;
    @js(#{
      `description`:"Where the effective value came from, highest first: this trust realm's own value; a runtime override set through this API or the console; the setting's own environment variable; a legacy variable (no row has one since #523); the appconfig file CONFIG_FILE names; `env/defaults.js`, the DEFAULT appconfig file that one is unioned on top of. `default` is reachable only for the DERIVED settings, whose value is a function of a neighbouring setting: for every other setting, no value anywhere stops this service from STARTING."
    }) `source`?: "realm" | "override" | "env" | "env-legacy" | "appconfig" | "defaults" | "default";
    @js(#{
      `description`:"Whether POST /config/set will take it from the realm this answer was read in. False means either the value was consumed at startup or `editRefusal` is set. It is refused rather than accepted, because an accepted change that does nothing reads as having worked."
    }) `editable`?: boolean;
    @js(#{
      `description`:"Why it is not editable, when the value was consumed at startup."
    }) `restartReason`?: string;
    @js(#{
      `description`:"Why this row cannot be edited from the realm the reader is in: `realms.maxCount` while a realm other than the default is ambient. Absent on every row of the default realm's answer."
    }) `editRefusal`?: string;
    @js(#{`description`:"Its environment variable."}) `env`?: string;
    `appconfigPath`?: string;
    `default`?: PageSettings_settings_groups_i_settings_i_default_h742;
    @js(#{`description`:"Whether a trust realm may hold its own value for it."}) `realmSettable`?: boolean;
    @js(#{
      `description`:"Whether a runtime override is in force. Equal to `source === \"override\"`, and reported separately so a caller can filter without matching a string."
    }) `overridden`?: boolean
  }

@js(#{`description`:"One group's settings."}) @hoisted model PageSettings_settings_groups_i_h744 {
    `group`?: string;
    `settings`?: (PageSettings_settings_groups_i_settings_i_h743)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_settings_context_configFile_h745 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_settings_sharedWith_ap_i_label_h746 {}

@js(#{`$types`:#["boolean","null"]}) @hoisted model PageSettings_status_v0_healthy_h747 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v0_dataDir_h748 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `host`:#{`type`:#["string","null"]},
      `port`:#{`type`:#["string","null"]},
      `database`:#{`type`:#["string","null"]},
      `user`:#{`type`:#["string","null"]},
      `passwordFrom`:#{`type`:"string"},
      `passwordProvider`:#{`type`:"string"},
      `passwordSecret`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `secret`:#{`type`:"string"},
          `configured`:#{`type`:"boolean"},
          `provider`:#{`type`:"string"},
          `label`:#{`type`:"string"},
          `known`:#{`type`:"boolean"},
          `where`:#{
            `type`:"object",
            `additionalProperties`:false,
            `properties`:#{
              `from`:#{`type`:"string"},
              `shared`:#{`type`:"boolean"},
              `region`:#{`type`:"string"},
              `vault`:#{`type`:"string"},
              `endpoint`:#{`type`:"string"},
              `field`:#{`type`:"string"},
              `authenticates`:#{`type`:"string"},
              `wraps`:#{`type`:"string"}
            }
          },
          `shared`:#{`type`:"boolean"},
          `field`:#{`type`:"string"},
          `providers`:#{
            `type`:"array",
            `items`:#{
              `type`:"object",
              `additionalProperties`:false,
              `properties`:#{`id`:#{`type`:"string"},`label`:#{`type`:"string"}}
            }
          }
        }
      },
      `sslmode`:#{`type`:"string"},
      `encrypted`:#{`type`:"boolean"},
      `verifyCertificate`:#{`type`:"boolean"},
      `caFile`:#{`type`:#["string","null"]},
      `tls`:#{`type`:"string"},
      `note`:#{`type`:"string"}
    },
    `description`:"Parsed out of the connection string, which is never returned.",
    `$types`:#["object","null"]
  }) @hoisted model PageSettings_status_v0_database_h749 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v0_engine_h750 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v0_lastWriteAt_h751 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v0_lastError_h752 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v0_restoredAt_h753 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v0_minted_lastWriteAt_h754 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v0_minted_restoredAt_h755 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model PageSettings_status_v0_usedAssertions_live_h756 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v0_replication_startedAt_h757 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v0_replication_lastPullAt_h758 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v0_replication_lastError_h759 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v0_replication_retention_reportedAt_h760 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v0_replication_retention_reportError_h761 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v0_replication_retention_declaredGoneAt_h762 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `at`:#{`type`:"string"},
      `error`:#{`type`:#["string","null"]},
      `readersGone`:#{`type`:"integer"},
      `readers`:#{`type`:"integer"},
      `bound`:#{
        `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"}]}]
      },
      `trimmed`:#{`type`:"integer"}
    },
    `$types`:#["object","null"]
  }) @hoisted model PageSettings_status_v0_replication_retention_lastTrim_h763 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `cell`:#{`type`:"string"},
      `jurisdiction`:#{`type`:#["string","null"]},
      `globalReplication`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `coordinating`:#{`type`:"boolean"},
          `supported`:#{`type`:"boolean"},
          `startedAt`:#{`type`:#["string","null"]},
          `appliedSeq`:#{`type`:"number"},
          `highestSeq`:#{`type`:"number"},
          `holes`:#{`type`:"integer"},
          `holeRanges`:#{`type`:"integer"},
          `holesAbandoned`:#{`type`:"integer"},
          `pollIntervalMs`:#{`type`:"number"},
          `pulls`:#{`type`:"integer"},
          `nudges`:#{`type`:"integer"},
          `failures`:#{`type`:"integer"},
          `rowsApplied`:#{`type`:"integer"},
          `byKind`:#{
            `type`:"object",
            `additionalProperties`:#{`type`:"integer"},
            `description`:"Rows applied, per kind of change."
          },
          `lastPullAt`:#{`type`:#["string","null"]},
          `lastError`:#{`type`:#["string","null"]},
          `otherProcesses`:#{`type`:"integer"},
          `originsDropped`:#{`type`:"integer"},
          `retention`:#{
            `type`:"object",
            `additionalProperties`:false,
            `properties`:#{
              `retentionS`:#{`type`:"integer"},
              `readerTtlS`:#{`type`:"integer"},
              `reportedAt`:#{`type`:#["string","null"]},
              `reportError`:#{`type`:#["string","null"]},
              `declaredGoneAt`:#{`type`:#["string","null"]},
              `fanInGraceS`:#{`type`:"integer"},
              `trimming`:#{`type`:"boolean"},
              `lastTrim`:#{
                `type`:#["object","null"],
                `additionalProperties`:false,
                `properties`:#{
                  `at`:#{`type`:"string"},
                  `error`:#{`type`:#["string","null"]},
                  `readersGone`:#{`type`:"integer"},
                  `readers`:#{`type`:"integer"},
                  `bound`:#{
                    `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"}]}]
                  },
                  `trimmed`:#{`type`:"integer"}
                }
              }
            }
          },
          `note`:#{`type`:"string"}
        }
      },
      `routing`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `indexed`:#{`type`:"integer"},
          `conflicts`:#{`type`:"integer"},
          `lastConflict`:#{`type`:#["string","null"]},
          `projectionWrites`:#{`type`:"integer"}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model PageSettings_status_v0_cells_h764 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `origin`:#{`type`:"string"},
      `adopted`:#{`type`:"boolean"},
      `why`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model PageSettings_status_v0_origin_h765 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `open`:#{`type`:"boolean"},
      `queries`:#{`type`:"integer"},
      `connects`:#{`type`:"integer"},
      `drops`:#{`type`:"integer"},
      `viaPool`:#{`type`:"integer"}
    },
    `$types`:#["object","null"]
  }) @hoisted model PageSettings_status_v0_liveness_h766 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `lastReport`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `maxMs`:#{`type`:"number"},
          `p99Ms`:#{`type`:"number"},
          `meanMs`:#{`type`:"number"},
          `at`:#{`type`:"string"}
        }
      },
      `sinceReport`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `maxMs`:#{`type`:"number"},
          `p99Ms`:#{`type`:"number"},
          `meanMs`:#{`type`:"number"},
          `at`:#{`type`:"string"}
        }
      },
      `warnAboveMs`:#{`type`:"number"}
    },
    `$types`:#["object","null"]
  }) @hoisted model PageSettings_status_v0_eventLoop_h767 {}

@js(#{
    `description`:"What the store is actually doing, which is a different fact from what `persistence.*` says it should."
  }) @hoisted model PageSettings_status_v0_h768 {
    `mode`?: string;
    `configuredMode`?: string;
    `enabled`?: boolean;
    `healthy`?: PageSettings_status_v0_healthy_h747;
    `dataDir`?: PageSettings_status_v0_dataDir_h748;
    `database`?: PageSettings_status_v0_database_h749;
    `engine`?: PageSettings_status_v0_engine_h750;
    `writeDelayMs`?: integer;
    `persistsDirectory`?: boolean;
    `persistsRealms`?: boolean;
    `persistsAppconfig`?: boolean;
    `pending`?: boolean;
    `writes`?: integer;
    `failures`?: integer;
    `lastWriteAt`?: PageSettings_status_v0_lastWriteAt_h751;
    `lastError`?: PageSettings_status_v0_lastError_h752;
    `restoredAt`?: PageSettings_status_v0_restoredAt_h753;
    `restored`?: {`realms`?: integer; `entries`?: integer; `overrides`?: integer};
    `entriesTracked`?: integer;
    `realmsTracked`?: integer;
    `coordinates`?: boolean;
    `minted`?: {
      `persisting`?: boolean;
      `supported`?: boolean;
      `unsupportedReason`?: string;
      `sealed`?: boolean;
      `mode`?: string;
      `setting`?: boolean;
      `retentionMs`?: numeric;
      `stores`?: integer;
      `shared`?: integer;
      `handles`?: ({`handle`?: string; `shape`?: string; `scope`?: string})[];
      `pending`?: integer;
      `writes`?: integer;
      `failures`?: integer;
      `rowsWritten`?: integer;
      `rowsDeleted`?: integer;
      `lastWriteAt`?: PageSettings_status_v0_minted_lastWriteAt_h754;
      `lastError`?: string;
      `restoredAt`?: PageSettings_status_v0_minted_restoredAt_h755;
      `restored`?: integer;
      `droppedUnreadable`?: integer;
      `droppedUnknown`?: integer;
      `droppedPoison`?: integer;
      `poisonDrops`?: ({
        `at`?: string;
        `code`?: string;
        `message`?: string;
        `rows`?: integer;
        `handles`?: (string)[];
        `realms`?: (string)[]
      })[]
    };
    `usedAssertions`?: {
      `store`?: string;
      `kind`?: string;
      `persistent`?: boolean;
      `atomicAcrossProcesses`?: boolean;
      `why`?: string;
      `cap`?: numeric;
      `live`?: PageSettings_status_v0_usedAssertions_live_h756;
      `liveIsCurrent`?: boolean
    };
    `replication`?: {
      `coordinating`?: boolean;
      `supported`?: boolean;
      `startedAt`?: PageSettings_status_v0_replication_startedAt_h757;
      `appliedSeq`?: numeric;
      `highestSeq`?: numeric;
      `holes`?: integer;
      `holeRanges`?: integer;
      `holesAbandoned`?: integer;
      `pollIntervalMs`?: numeric;
      `pulls`?: integer;
      `nudges`?: integer;
      `failures`?: integer;
      `rowsApplied`?: integer;
      @js(#{`description`:"Rows applied, per kind of change."}) `byKind`?: Record<integer>;
      `lastPullAt`?: PageSettings_status_v0_replication_lastPullAt_h758;
      `lastError`?: PageSettings_status_v0_replication_lastError_h759;
      `otherProcesses`?: integer;
      `originsDropped`?: integer;
      `retention`?: {
        `retentionS`?: integer;
        `readerTtlS`?: integer;
        `reportedAt`?: PageSettings_status_v0_replication_retention_reportedAt_h760;
        `reportError`?: PageSettings_status_v0_replication_retention_reportError_h761;
        `declaredGoneAt`?: PageSettings_status_v0_replication_retention_declaredGoneAt_h762;
        `fanInGraceS`?: integer;
        `trimming`?: boolean;
        `lastTrim`?: PageSettings_status_v0_replication_retention_lastTrim_h763
      };
      `note`?: string
    };
    `cells`?: PageSettings_status_v0_cells_h764;
    `origin`?: PageSettings_status_v0_origin_h765;
    `answersAfterCommit`?: boolean;
    `commitBacklog`?: boolean;
    `retryArmed`?: boolean;
    `liveness`?: PageSettings_status_v0_liveness_h766;
    `eventLoop`?: PageSettings_status_v0_eventLoop_h767;
    `note`?: string
  }

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v1_self_refused_h769 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v1_self_nodeId_h770 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v1_self_name_h771 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v1_self_role_h772 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v1_self_joinedAt_h773 {}

@js(#{`$types`:#["number","null"]}) @hoisted model PageSettings_status_v1_self_msSinceRenewal_h774 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v1_self_lastHeartbeatError_h775 {}

@hoisted union PageSettings_status_v1_self_leases_i_token_h776 {numeric, string}

@js(#{`$types`:#["number","null"]}) @hoisted model PageSettings_status_v1_snapshotAgeMs_h777 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v1_nodes_i_name_h778 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v1_nodes_i_mode_h779 {}

@js(#{`$types`:#["string","null"]}) @hoisted model PageSettings_status_v1_nodes_i_version_h780 {}

@hoisted union PageSettings_status_v1_nodes_i_info_port_h781 {string, numeric, boolean, null}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `at`:#{`type`:"number"},
      `pid`:#{`type`:"string"},
      `caches`:#{
        `type`:"array",
        `items`:#{
          `type`:"array",
          `items`:#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"},#{`type`:"null"}]}
        },
        `description`:"name, size, largest realm, valid, bound, hits, misses, evictions, refusals."
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model PageSettings_status_v1_nodes_i_info_caches_h782 {}

@js(#{
    `description`:"Whether its settings fingerprint agrees with the node answering; the fingerprint is never returned.",
    `$types`:#["boolean","null"]
  }) @hoisted model PageSettings_status_v1_nodes_i_agrees_h783 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `running`:#{`type`:"array",`items`:#{`type`:"string"}},
      `restarts`:#{
        `type`:"object",
        `additionalProperties`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{`count`:#{`type`:"integer"},`lastEndedAt`:#{`type`:"number"}}
        },
        `description`:"Per running name."
      },
      `leftOrExpired`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `nodeId`:#{`type`:"string"},
            `name`:#{`type`:#["string","null"]},
            `earlierLives`:#{`type`:"integer"}
          }
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model PageSettings_status_v1_members_h784 {}

@js(#{`$types`:#["number","null"]}) @hoisted model PageSettings_status_v1_databaseNow_h785 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `askedAt`:#{`type`:"number"},
      `cells`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `cell`:#{`type`:"string"},
            `jurisdiction`:#{`type`:#["string","null"]},
            `reachable`:#{`type`:"boolean"},
            `answeredMs`:#{`type`:"number"},
            `summary`:#{
              `x-free-form`:"Another cell's own cluster summary, relayed: that cell may run another build, so this one does not narrow it.",
              `description`:"Another cell's own cluster summary, relayed: that cell may run another build, so this one does not narrow it."
            },
            `error`:#{`type`:"string"}
          }
        }
      },
      `error`:#{`type`:#["string","null"]}
    },
    `$types`:#["object","null"]
  }) @hoisted model PageSettings_status_v1_otherCells_h786 {}

@js(#{
    `description`:"Whether a cluster is WORKING, which `cluster.mode` being set does not say."
  }) @hoisted model PageSettings_status_v1_h787 {
    `self`?: {
      `mode`?: string;
      `why`?: string;
      `refused`?: PageSettings_status_v1_self_refused_h769;
      `configured`?: string;
      `nodeId`?: PageSettings_status_v1_self_nodeId_h770;
      `name`?: PageSettings_status_v1_self_name_h771;
      `role`?: PageSettings_status_v1_self_role_h772;
      `joinedAt`?: PageSettings_status_v1_self_joinedAt_h773;
      `heartbeatMs`?: numeric;
      `ttlMs`?: numeric;
      `lastStallMs`?: numeric;
      `msSinceRenewal`?: PageSettings_status_v1_self_msSinceRenewal_h774;
      `heartbeatFailures`?: integer;
      `lastHeartbeatError`?: PageSettings_status_v1_self_lastHeartbeatError_h775;
      `leases`?: ({
        `name`?: string;
        `token`?: PageSettings_status_v1_self_leases_i_token_h776
      })[];
      `fingerprintSet`?: boolean;
      `agreementSettings`?: (string)[];
      `capabilities`?: {
        `rows`?: ({
          `id`?: string;
          `section`?: string;
          `by`?: string;
          `what`?: string;
          `provided`?: boolean;
          `note`?: string;
          `accepted`?: boolean
        })[];
        `missing`?: (string)[];
        `acceptedMissing`?: (string)[];
        `unknownAccepted`?: (string)[];
        `ready`?: boolean
      }
    };
    `snapshotAgeMs`?: PageSettings_status_v1_snapshotAgeMs_h777;
    `nodes`?: ({
      `nodeId`?: string;
      `name`?: PageSettings_status_v1_nodes_i_name_h778;
      `mode`?: PageSettings_status_v1_nodes_i_mode_h779;
      `version`?: PageSettings_status_v1_nodes_i_version_h780;
      `startedAt`?: numeric;
      `heartbeatAt`?: numeric;
      `expiresAt`?: numeric;
      `leftAt`?: numeric;
      @js(#{`description`:"What only that node can say about itself."}) `info`?: {
        `pid`?: integer;
        `host`?: string;
        `port`?: PageSettings_status_v1_nodes_i_info_port_h781;
        `uptimeMs`?: numeric;
        `workers`?: integer;
        `lastStallMs`?: numeric;
        `caches`?: PageSettings_status_v1_nodes_i_info_caches_h782;
        @js(#{`description`:"Base64, the PEM's body."}) `listenerCertificates`?: (string)[]
      };
      `agrees`?: PageSettings_status_v1_nodes_i_agrees_h783
    })[];
    `members`?: PageSettings_status_v1_members_h784;
    `leases`?: ({
      `name`?: string;
      `holder`?: string;
      `token`?: numeric;
      `acquiredAt`?: numeric;
      `expiresAt`?: numeric
    })[];
    `databaseNow`?: PageSettings_status_v1_databaseNow_h785;
    `otherCells`?: PageSettings_status_v1_otherCells_h786;
    @js(#{
      `description`:"Where each shared secret's value came from, never the value."
    }) `secrets`?: {
      `started`?: boolean;
      `secrets`?: ({`name`?: string; `what`?: string; `source`?: string})[]
    };
    `barrier`?: {
      `active`?: boolean;
      `holds`?: boolean;
      `requests`?: integer;
      `caughtUp`?: integer;
      `gaveUp`?: integer;
      `heldForCommit`?: integer;
      `answeredUnheld`?: integer;
      `commitFailures`?: integer;
      `totalWaitMs`?: numeric;
      `totalHoldMs`?: numeric;
      `refusedForCommit`?: integer;
      `heldForBacklog`?: integer;
      `ldapHeldForCommit`?: integer;
      `ldapRefusedForCommit`?: integer;
      `meanWaitMs`?: numeric;
      `meanHoldMs`?: numeric
    }
  }

@hoisted union PageSettings_status_h788 {PageSettings_status_v0_h768, PageSettings_status_v1_h787}

@js(#{
    `description`:"One console page, and the settings it draws: the same described rows GET /config returns, filtered to the ones that page owns."
  }) @component model `PageSettings` {
    @js(#{`description`:"The console path this mirrors."}) `page`?: string;
    `title`?: string;
    @js(#{`description`:"What the page says the family is, as plain text."}) `what`?: string;
    @js(#{
      `description`:"The caveats the page carries, in order. On these pages the caveats are most of the content: what a family does NOT check is the half a client author cannot read off a protocol trace."
    }) `notes`?: (string)[];
    `links`?: (PageSettings_links_i_h738)[];
    @js(#{
      `description`:"The settings this page draws, described: the same rows GET /config returns, filtered to the ones this page owns."
    }) `settings`?: {
      `page`?: string;
      @js(#{`description`:"In the order `config.js` declares them."}) `groups`?: (PageSettings_settings_groups_i_h744)[];
      `settingCount`?: integer;
      @js(#{`description`:"How many of them can be changed while the service runs."}) `editableCount`?: integer;
      @js(#{`description`:"The keys on this page with a runtime override in force."}) `overridden`?: (string)[];
      @js(#{`description`:"The operation that writes them."}) `setWith`?: string;
      `context`?: {
        `configFile`?: PageSettings_settings_context_configFile_h745;
        `defaultsFile`?: string;
        `persistsAppconfig`?: boolean;
        `persistsRealms`?: boolean;
        `persistenceMode`?: string;
        `inRealm`?: boolean;
        `realmId`?: string
      };
      @js(#{`description`:"A group drawn on another page as well, and those pages."}) `sharedWith`?: Record<({
        `path`?: string;
        `label`?: PageSettings_settings_sharedWith_ap_i_label_h746
      })[]>
    };
    @js(#{`description`:"The page's first paragraph, as the console draws it."}) `leadHtml`?: string;
    @js(#{`description`:"The caveats, as the console draws them."}) `alsoHtml`?: (string)[];
    `status`?: PageSettings_status_h788
  }

@hoisted union TokenLifetimes_settings_i_value_h789 {string, numeric, boolean, null, (string)[]}

@js(#{`$types`:#["string","null"]}) @hoisted model TokenLifetimes_settings_i_env_h790 {}

@js(#{`$types`:#["string","null"]}) @hoisted model TokenLifetimes_settings_i_legacyEnv_h791 {}

@hoisted union TokenLifetimes_settings_i_default_h792 {string, numeric, boolean, null, (string)[]}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `configFile`:#{`type`:#["string","null"]},
      `defaultsFile`:#{`type`:#["string","null"]},
      `persistsAppconfig`:#{`type`:"boolean"},
      `persistsRealms`:#{`type`:"boolean"},
      `persistenceMode`:#{`type`:"string"},
      `inRealm`:#{`type`:"boolean"},
      `realmId`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model TokenLifetimes_context_h793 {}

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
      `value`?: TokenLifetimes_settings_i_value_h789;
      `text`?: string;
      `source`?: string;
      `editable`?: boolean;
      `restartReason`?: string;
      `editRefusal`?: string;
      `env`?: TokenLifetimes_settings_i_env_h790;
      `legacyEnv`?: TokenLifetimes_settings_i_legacyEnv_h791;
      `appconfigPath`?: string;
      `default`?: TokenLifetimes_settings_i_default_h792;
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
    `context`?: TokenLifetimes_context_h793;
    `overridable`?: ({`setting`?: string; `attribute`?: string})[]
  }

@hoisted union SamlAssertions_protocolEndpoints_i_methods_h794 {string, (string)[]}

@hoisted union SamlAssertions_settings_i_value_h795 {boolean, numeric, string, (string)[], null}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAssertions_settings_i_text_h796 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAssertions_settings_i_env_h797 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAssertions_settings_i_legacyEnv_h798 {}

@hoisted union SamlAssertions_settings_i_default_h799 {boolean, numeric, string, (string)[], null}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `configFile`:#{`type`:#["string","null"]},
      `defaultsFile`:#{`type`:#["string","null"]},
      `persistsAppconfig`:#{`type`:"boolean"},
      `persistsRealms`:#{`type`:"boolean"},
      `persistenceMode`:#{`type`:"string"},
      `inRealm`:#{`type`:"boolean"},
      `realmId`:#{`type`:#["string","null"]}
    },
    `$types`:#["object","null"]
  }) @hoisted model SamlAssertions_context_h800 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAssertions_rows_i_kind_h801 {}

@js(#{`$types`:#["number","null"]}) @hoisted model SamlAssertions_seconds_ap_h802 {}

@component model `SamlAssertions` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: SamlAssertions_protocolEndpoints_i_methods_h794;
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
      `value`?: SamlAssertions_settings_i_value_h795;
      `text`?: SamlAssertions_settings_i_text_h796;
      `source`?: string;
      `editable`?: boolean;
      `restartReason`?: string;
      `editRefusal`?: string;
      `env`?: SamlAssertions_settings_i_env_h797;
      `legacyEnv`?: SamlAssertions_settings_i_legacyEnv_h798;
      `appconfigPath`?: string;
      `default`?: SamlAssertions_settings_i_default_h799;
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
    `context`?: SamlAssertions_context_h800;
    `rows`?: ({
      `key`?: string;
      `unit`?: string;
      `kind`?: SamlAssertions_rows_i_kind_h801;
      `profile`?: string;
      `field`?: string
    })[];
    @js(#{`description`:"Each setting in seconds, by key."}) `seconds`?: Record<SamlAssertions_seconds_ap_h802>
  }

@js(#{`$types`:#["string","null"]}) @hoisted model ClaimSets_attributeCatalogue_i_label_h803 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ClaimSets_attributeCatalogue_i_schema_h804 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ClaimSets_attributeCatalogue_i_syntax_h805 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ClaimSets_sets_i_attributeReport_i_ldpTerm_h806 {}

@js(#{
    `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
    `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
  }) @hoisted model ClaimSets_sets_i_attributeReport_i_values_i_h807 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ClaimSets_preview_byLdap_ap_ldpTerm_h808 {}

@js(#{
    `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
    `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
  }) @hoisted model ClaimSets_preview_byLdap_ap_values_i_h809 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ClaimSets_groups_claim_h810 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ClaimSets_groups_valueForm_h811 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ClaimSets_groups_preview_key_h812 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ClaimSets_groups_preview_claim_h813 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ClaimSets_groups_preview_valueForm_h814 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ClaimSets_groups_preview_dn_h815 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ClaimSets_groups_preview_groups_i_cn_h816 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ClaimSets_groups_preview_groups_i_rule_h817 {}

@component model `ClaimSets` {
    `reservedJwtClaims`?: (string)[];
    `placeholders`?: (string)[];
    `attributeCatalogue`?: ({
      `ldap`?: string;
      `claim`?: string;
      `label`?: ClaimSets_attributeCatalogue_i_label_h803;
      `schema`?: ClaimSets_attributeCatalogue_i_schema_h804;
      @js(#{`description`:"Whether it is ticked, by claim set."}) `sets`?: Record<boolean>;
      `generated`?: boolean;
      `custom`?: boolean;
      `syntax`?: ClaimSets_attributeCatalogue_i_syntax_h805;
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
        `ldpTerm`?: ClaimSets_sets_i_attributeReport_i_ldpTerm_h806;
        `claimId`?: string;
        `values`?: (ClaimSets_sets_i_attributeReport_i_values_i_h807)[]
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
        `ldpTerm`?: ClaimSets_preview_byLdap_ap_ldpTerm_h808;
        `claimId`?: string;
        `values`?: (ClaimSets_preview_byLdap_ap_values_i_h809)[]
      }>;
      `entryFound`?: boolean
    };
    `groups`?: {
      `enabled`?: boolean;
      `loaded`?: boolean;
      `claim`?: ClaimSets_groups_claim_h810;
      `valueForm`?: ClaimSets_groups_valueForm_h811;
      `memberOfCounts`?: boolean;
      `sets`?: (string)[];
      `problem`?: string;
      `grants`?: string;
      `precedence`?: string;
      `settings`?: (string)[];
      `preview`?: {
        `user`?: string;
        `key`?: ClaimSets_groups_preview_key_h812;
        `application`?: string;
        `enabled`?: boolean;
        `loaded`?: boolean;
        `claim`?: ClaimSets_groups_preview_claim_h813;
        `valueForm`?: ClaimSets_groups_preview_valueForm_h814;
        `memberOfCounts`?: boolean;
        `reason`?: string;
        `dn`?: ClaimSets_groups_preview_dn_h815;
        `entryFound`?: boolean;
        `groups`?: ({
          `cn`?: ClaimSets_groups_preview_groups_i_cn_h816;
          `dn`?: string;
          `rule`?: ClaimSets_groups_preview_groups_i_rule_h817;
          `via`?: (string)[];
          `viaMemberOf`?: boolean
        })[];
        `values`?: (string)[]
      }
    };
    `withholding`?: ({`id`?: string; `names`?: (string)[]})[]
  }

@hoisted union KerberosPacClaims_protocolEndpoints_i_methods_h818 {string, (string)[]}

@js(#{`$types`:#["string","null"]}) @hoisted model KerberosPacClaims_attributeCatalogue_i_label_h819 {}

@js(#{`$types`:#["string","null"]}) @hoisted model KerberosPacClaims_attributeCatalogue_i_schema_h820 {}

@js(#{`$types`:#["string","null"]}) @hoisted model KerberosPacClaims_attributeCatalogue_i_syntax_h821 {}

@js(#{`$types`:#["string","null"]}) @hoisted model KerberosPacClaims_preview_byLdap_ap_ldpTerm_h822 {}

@js(#{
    `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
    `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
  }) @hoisted model KerberosPacClaims_preview_byLdap_ap_values_i_h823 {}

@js(#{
    `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
    `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
  }) @hoisted model KerberosPacClaims_preview_claims_i_values_i_h824 {}

@component model `KerberosPacClaims` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: KerberosPacClaims_protocolEndpoints_i_methods_h818;
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
      `label`?: KerberosPacClaims_attributeCatalogue_i_label_h819;
      `schema`?: KerberosPacClaims_attributeCatalogue_i_schema_h820;
      @js(#{`description`:"Whether it is ticked, by claim set."}) `sets`?: Record<boolean>;
      `generated`?: boolean;
      `custom`?: boolean;
      `syntax`?: KerberosPacClaims_attributeCatalogue_i_syntax_h821;
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
        `ldpTerm`?: KerberosPacClaims_preview_byLdap_ap_ldpTerm_h822;
        `claimId`?: string;
        `values`?: (KerberosPacClaims_preview_byLdap_ap_values_i_h823)[]
      }>;
      `claims`?: ({
        `name`?: string;
        `id`?: string;
        `type`?: string;
        `values`?: (KerberosPacClaims_preview_claims_i_values_i_h824)[];
        `from`?: string;
        `dropped`?: boolean
      })[]
    }
  }

@hoisted union UserInfoClaimSets_protocolEndpoints_i_methods_h825 {string, (string)[]}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_claimsRequest_requestable_i_label_h826 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_inventedEmail_h827 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_attributeCatalogue_i_label_h828 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_attributeCatalogue_i_schema_h829 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_attributeCatalogue_i_syntax_h830 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_sets_i_attributeReport_i_ldpTerm_h831 {}

@js(#{
    `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
    `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
  }) @hoisted model UserInfoClaimSets_sets_i_attributeReport_i_values_i_h832 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_preview_byLdap_ap_ldpTerm_h833 {}

@js(#{
    `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
    `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
  }) @hoisted model UserInfoClaimSets_preview_byLdap_ap_values_i_h834 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_groups_claim_h835 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_groups_valueForm_h836 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_groups_preview_key_h837 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_groups_preview_claim_h838 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_groups_preview_valueForm_h839 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_groups_preview_dn_h840 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_groups_preview_groups_i_cn_h841 {}

@js(#{`$types`:#["string","null"]}) @hoisted model UserInfoClaimSets_groups_preview_groups_i_rule_h842 {}

@component model `UserInfoClaimSets` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: UserInfoClaimSets_protocolEndpoints_i_methods_h825;
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
        `label`?: UserInfoClaimSets_claimsRequest_requestable_i_label_h826;
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
    `inventedEmail`?: UserInfoClaimSets_inventedEmail_h827;
    `placeholders`?: (string)[];
    `attributeCatalogue`?: ({
      `ldap`?: string;
      `claim`?: string;
      `label`?: UserInfoClaimSets_attributeCatalogue_i_label_h828;
      `schema`?: UserInfoClaimSets_attributeCatalogue_i_schema_h829;
      @js(#{`description`:"Whether it is ticked, by claim set."}) `sets`?: Record<boolean>;
      `generated`?: boolean;
      `custom`?: boolean;
      `syntax`?: UserInfoClaimSets_attributeCatalogue_i_syntax_h830;
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
        `ldpTerm`?: UserInfoClaimSets_sets_i_attributeReport_i_ldpTerm_h831;
        `claimId`?: string;
        `values`?: (UserInfoClaimSets_sets_i_attributeReport_i_values_i_h832)[]
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
        `ldpTerm`?: UserInfoClaimSets_preview_byLdap_ap_ldpTerm_h833;
        `claimId`?: string;
        `values`?: (UserInfoClaimSets_preview_byLdap_ap_values_i_h834)[]
      }>;
      `entryFound`?: boolean
    };
    `groups`?: {
      `enabled`?: boolean;
      `loaded`?: boolean;
      `claim`?: UserInfoClaimSets_groups_claim_h835;
      `valueForm`?: UserInfoClaimSets_groups_valueForm_h836;
      `memberOfCounts`?: boolean;
      `sets`?: (string)[];
      `problem`?: string;
      `grants`?: string;
      `precedence`?: string;
      `settings`?: (string)[];
      `preview`?: {
        `user`?: string;
        `key`?: UserInfoClaimSets_groups_preview_key_h837;
        `application`?: string;
        `enabled`?: boolean;
        `loaded`?: boolean;
        `claim`?: UserInfoClaimSets_groups_preview_claim_h838;
        `valueForm`?: UserInfoClaimSets_groups_preview_valueForm_h839;
        `memberOfCounts`?: boolean;
        `reason`?: string;
        `dn`?: UserInfoClaimSets_groups_preview_dn_h840;
        `entryFound`?: boolean;
        `groups`?: ({
          `cn`?: UserInfoClaimSets_groups_preview_groups_i_cn_h841;
          `dn`?: string;
          `rule`?: UserInfoClaimSets_groups_preview_groups_i_rule_h842;
          `via`?: (string)[];
          `viaMemberOf`?: boolean
        })[];
        `values`?: (string)[]
      }
    };
    `withholding`?: ({`id`?: string; `names`?: (string)[]})[]
  }

@hoisted union SamlAttributeSets_protocolEndpoints_i_methods_h843 {string, (string)[]}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAttributeSets_attributeCatalogue_i_label_h844 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAttributeSets_attributeCatalogue_i_schema_h845 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAttributeSets_attributeCatalogue_i_syntax_h846 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAttributeSets_sets_i_attributeReport_i_ldpTerm_h847 {}

@js(#{
    `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
    `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
  }) @hoisted model SamlAttributeSets_sets_i_attributeReport_i_values_i_h848 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAttributeSets_preview_byLdap_ap_ldpTerm_h849 {}

@js(#{
    `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.",
    `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path."
  }) @hoisted model SamlAttributeSets_preview_byLdap_ap_values_i_h850 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAttributeSets_groups_claim_h851 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAttributeSets_groups_valueForm_h852 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAttributeSets_groups_preview_key_h853 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAttributeSets_groups_preview_claim_h854 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAttributeSets_groups_preview_valueForm_h855 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAttributeSets_groups_preview_dn_h856 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAttributeSets_groups_preview_groups_i_cn_h857 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SamlAttributeSets_groups_preview_groups_i_rule_h858 {}

@component model `SamlAttributeSets` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: SamlAttributeSets_protocolEndpoints_i_methods_h843;
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
      `label`?: SamlAttributeSets_attributeCatalogue_i_label_h844;
      `schema`?: SamlAttributeSets_attributeCatalogue_i_schema_h845;
      @js(#{`description`:"Whether it is ticked, by claim set."}) `sets`?: Record<boolean>;
      `generated`?: boolean;
      `custom`?: boolean;
      `syntax`?: SamlAttributeSets_attributeCatalogue_i_syntax_h846;
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
        `ldpTerm`?: SamlAttributeSets_sets_i_attributeReport_i_ldpTerm_h847;
        `claimId`?: string;
        `values`?: (SamlAttributeSets_sets_i_attributeReport_i_values_i_h848)[]
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
        `ldpTerm`?: SamlAttributeSets_preview_byLdap_ap_ldpTerm_h849;
        `claimId`?: string;
        `values`?: (SamlAttributeSets_preview_byLdap_ap_values_i_h850)[]
      }>;
      `entryFound`?: boolean
    };
    `groups`?: {
      `enabled`?: boolean;
      `loaded`?: boolean;
      `claim`?: SamlAttributeSets_groups_claim_h851;
      `valueForm`?: SamlAttributeSets_groups_valueForm_h852;
      `memberOfCounts`?: boolean;
      `sets`?: (string)[];
      `problem`?: string;
      `grants`?: string;
      `precedence`?: string;
      `settings`?: (string)[];
      `preview`?: {
        `user`?: string;
        `key`?: SamlAttributeSets_groups_preview_key_h853;
        `application`?: string;
        `enabled`?: boolean;
        `loaded`?: boolean;
        `claim`?: SamlAttributeSets_groups_preview_claim_h854;
        `valueForm`?: SamlAttributeSets_groups_preview_valueForm_h855;
        `memberOfCounts`?: boolean;
        `reason`?: string;
        `dn`?: SamlAttributeSets_groups_preview_dn_h856;
        `entryFound`?: boolean;
        `groups`?: ({
          `cn`?: SamlAttributeSets_groups_preview_groups_i_cn_h857;
          `dn`?: string;
          `rule`?: SamlAttributeSets_groups_preview_groups_i_rule_h858;
          `via`?: (string)[];
          `viaMemberOf`?: boolean
        })[];
        `values`?: (string)[]
      }
    };
    `withholding`?: ({`id`?: string; `names`?: (string)[]})[]
  }

@hoisted union CredentialClaims_attributes_i_example_value_v4_i_h859 {string, numeric, boolean}

@hoisted union CredentialClaims_attributes_i_example_value_h860 {
    string,
    numeric,
    boolean,
    null,
    (CredentialClaims_attributes_i_example_value_v4_i_h859)[]
  }

@hoisted union CredentialClaims_protocolEndpoints_i_methods_h861 {string, (string)[]}

@hoisted union CredentialClaims_preview_claims_claims_ap_v0_v4_i_h862 {string, numeric, boolean}

@hoisted union CredentialClaims_preview_claims_claims_ap_v0_h863 {
    string,
    numeric,
    boolean,
    null,
    (CredentialClaims_preview_claims_claims_ap_v0_v4_i_h862)[]
  }

@hoisted union CredentialClaims_preview_claims_claims_ap_v1_ap_v4_i_h864 {string, numeric, boolean}

@hoisted union CredentialClaims_preview_claims_claims_ap_v1_ap_h865 {
    string,
    numeric,
    boolean,
    null,
    (CredentialClaims_preview_claims_claims_ap_v1_ap_v4_i_h864)[]
  }

@js(#{`description`:"A claim's members, as `address` has."}) @hoisted model CredentialClaims_preview_claims_claims_ap_v1_h866 is Record<CredentialClaims_preview_claims_claims_ap_v1_ap_h865>;
  

@hoisted union CredentialClaims_preview_claims_claims_ap_h867 {
    CredentialClaims_preview_claims_claims_ap_v0_h863,
    CredentialClaims_preview_claims_claims_ap_v1_h866
  }

@hoisted union CredentialClaims_preview_claims_report_i_value_v4_i_h868 {string, numeric, boolean}

@hoisted union CredentialClaims_preview_claims_report_i_value_h869 {
    string,
    numeric,
    boolean,
    null,
    (CredentialClaims_preview_claims_report_i_value_v4_i_h868)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model CredentialClaims_preview_claims_report_i_ldpTerm_h870 {}

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
        `value`?: CredentialClaims_attributes_i_example_value_h860;
        `source`?: string
      }
    })[];
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: CredentialClaims_protocolEndpoints_i_methods_h861;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `preview`?: {
      `user`?: string;
      `claims`?: {
        @js(#{`description`:"The credential subject's claims."}) `claims`?: Record<CredentialClaims_preview_claims_claims_ap_h867>;
        `report`?: ({
          `ldap`?: string;
          `claim`?: string;
          `value`?: CredentialClaims_preview_claims_report_i_value_h869;
          `source`?: string;
          `ldpTerm`?: CredentialClaims_preview_claims_report_i_ldpTerm_h870
        })[];
        `entryFound`?: boolean
      }
    }
  }

@hoisted union VerifierRequest_protocolEndpoints_i_methods_h871 {string, (string)[]}

@hoisted union VerifierRequest_formats_i_identifier_h872 {string, (string)[]}

@hoisted union VerifierRequest_dcqlQuery_credentials_i_meta_type_values_i_h873 {string, (string)[]}

@js(#{`$types`:#["boolean","null"]}) @hoisted model VerifierRequest_recentVerifications_verifications_i_ok_h874 {}

@js(#{`$types`:#["string","null"]}) @hoisted model VerifierRequest_recentVerifications_verifications_i_decidedAt_h875 {}

@component model `VerifierRequest` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: VerifierRequest_protocolEndpoints_i_methods_h871;
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
      `identifier`?: VerifierRequest_formats_i_identifier_h872;
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
          `type_values`?: (VerifierRequest_dcqlQuery_credentials_i_meta_type_values_i_h873)[]
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
        `ok`?: VerifierRequest_recentVerifications_verifications_i_ok_h874;
        `decidedAt`?: VerifierRequest_recentVerifications_verifications_i_decidedAt_h875;
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

@js(#{`$types`:#["string","null"]}) @hoisted model Xacml_root_h876 {}

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
            `settings`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `key`:#{`type`:"string"},
                  `group`:#{`type`:"string"},
                  `label`:#{`type`:"string"},
                  `description`:#{`type`:"string"},
                  `type`:#{`type`:"string"},
                  `enumValues`:#{`type`:"array",`items`:#{`type`:"string"}},
                  `csvValues`:#{`type`:"array",`items`:#{`type`:"string"}},
                  `ordered`:#{`type`:"boolean"},
                  `csvValueNotes`:#{`type`:"object",`additionalProperties`:#{`type`:"string"}},
                  `selectAll`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `onlyWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      },
                      `aloneWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      }
                    }
                  },
                  `min`:#{`type`:"number"},
                  `max`:#{`type`:"number"},
                  `step`:#{`type`:"number"},
                  `value`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `text`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"}
                    ]
                  },
                  `source`:#{`type`:"string"},
                  `editable`:#{`type`:"boolean"},
                  `restartReason`:#{`type`:#["string","null"]},
                  `editRefusal`:#{`type`:#["string","null"]},
                  `env`:#{
                    `oneOf`:#[
                      #{`type`:"null"},
                      #{
                        `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                      }
                    ]
                  },
                  `legacyEnv`:#{
                    `oneOf`:#[
                      #{`type`:"null"},
                      #{
                        `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                      }
                    ]
                  },
                  `appconfigPath`:#{`type`:"string"},
                  `default`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `masked`:#{`type`:"boolean"},
                  `realmSettable`:#{`type`:"boolean"},
                  `overridden`:#{`type`:"boolean"}
                }
              }
            }
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
            `properties`:#{`path`:#{`type`:"string"},`label`:#{`type`:#["string","null"]}}
          }
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model Xacml_settings_h877 {}

@component model `Xacml` {
    `xacml`?: boolean;
    `message`?: string;
    `enabled`?: boolean;
    `policies`?: integer;
    `enabledPolicies`?: integer;
    `root`?: Xacml_root_h876;
    `pipAvailable`?: boolean;
    `settings`?: Xacml_settings_h877;
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
    `description`:"The entry's flag, or null when there is no entry.",
    `$types`:#["boolean","null"]
  }) @hoisted model XacmlServiceOwnPolicy_enabled_h878 {}

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
    `enabled`?: XacmlServiceOwnPolicy_enabled_h878;
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

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlPolicies_root_h879 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlPolicies_policies_i_policyId_h880 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlPolicies_policies_i_application_h881 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlPolicies_policies_i_orphanedAt_h882 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlPolicies_applicationPolicies_i_policies_i_policyId_h883 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlPolicies_applicationPolicies_i_policies_i_orphanedAt_h884 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlPolicies_templates_i_parameters_i_help_h885 {}

@hoisted union XacmlPolicies_templates_i_parameters_i_dflt_h886 {string, numeric, boolean, null}

@js(#{`$types`:#["boolean","null"]}) @hoisted model XacmlPolicies_serviceOwn_i_enabled_h887 {}

@component model `XacmlPolicies` {
    `xacml`?: boolean;
    `message`?: string;
    `root`?: XacmlPolicies_root_h879;
    `policies`?: ({
      `name`?: string;
      `policyId`?: XacmlPolicies_policies_i_policyId_h880;
      `kind`?: string;
      `version`?: string;
      `enabled`?: boolean;
      `isRoot`?: boolean;
      `combiningAlgId`?: string;
      `description`?: string;
      `application`?: XacmlPolicies_policies_i_application_h881;
      `orphanedAt`?: XacmlPolicies_policies_i_orphanedAt_h882;
      `problems`?: (string)[]
    })[];
    `applicationPolicies`?: ({
      `application`?: string;
      `known`?: boolean;
      `enforced`?: boolean;
      `policies`?: ({
        `name`?: string;
        `policyId`?: XacmlPolicies_applicationPolicies_i_policies_i_policyId_h883;
        `version`?: string;
        `enabled`?: boolean;
        `orphanedAt`?: XacmlPolicies_applicationPolicies_i_policies_i_orphanedAt_h884;
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
        `help`?: XacmlPolicies_templates_i_parameters_i_help_h885;
        `type`?: string;
        `dflt`?: XacmlPolicies_templates_i_parameters_i_dflt_h886
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
      `enabled`?: XacmlPolicies_serviceOwn_i_enabled_h887;
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

@js(#{`$types`:#["boolean","null"]}) @hoisted model XacmlEditor_serviceOwn_i_enabled_h888 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `name`:#{`type`:"string"},
      `enabled`:#{`type`:"boolean"},
      `isRoot`:#{`type`:"boolean"},
      `policyId`:#{`type`:#["string","null"]},
      `kind`:#{`type`:#["string","null"]},
      `version`:#{`type`:#["string","null"]},
      `combiningAlgId`:#{`type`:#["string","null"]},
      `description`:#{`type`:#["string","null"]}
    },
    `$types`:#["object","null"]
  }) @hoisted model XacmlEditor_policy_h889 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlEditor_problem_h890 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `node`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `kind`:#{`type`:"string"},
          `id`:#{`type`:"string"},
          `description`:#{`type`:#["string","null"]},
          `version`:#{`type`:#["string","null"]},
          `combiningAlgId`:#{`type`:"string"},
          `xpathVersion`:#{`type`:#["string","null"]},
          `target`:#{`type`:"null"},
          `condition`:#{`type`:"null"},
          `maxDelegationDepth`:#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"},#{`type`:"null"}]},
          `effect`:#{`type`:"string"},
          `ref`:#{`type`:"string"},
          `matchId`:#{`type`:"string"},
          `value`:#{
            `type`:"object",
            `additionalProperties`:false,
            `properties`:#{
              `kind`:#{`type`:"string"},
              `type`:#{`type`:"string"},
              `lexical`:#{`type`:"string"},
              `namespaces`:#{`type`:"object",`additionalProperties`:#{`type`:#["string","null"]}},
              `xpathCategory`:#{`type`:#["string","null"]},
              `category`:#{`type`:#["string","null"]},
              `attributeId`:#{`type`:"string"},
              `dataType`:#{`type`:"string"},
              `issuer`:#{`type`:#["string","null"]},
              `mustBePresent`:#{`type`:"boolean"},
              `path`:#{`type`:"string"},
              `contextSelectorId`:#{`type`:#["string","null"]},
              `functionId`:#{`type`:"string"},
              `description`:#{`type`:#["string","null"]},
              `variableId`:#{`type`:"string"}
            }
          },
          `reference`:#{
            `type`:"object",
            `additionalProperties`:false,
            `properties`:#{
              `kind`:#{`type`:"string"},
              `type`:#{`type`:"string"},
              `lexical`:#{`type`:"string"},
              `namespaces`:#{`type`:"object",`additionalProperties`:#{`type`:#["string","null"]}},
              `xpathCategory`:#{`type`:#["string","null"]},
              `category`:#{`type`:#["string","null"]},
              `attributeId`:#{`type`:"string"},
              `dataType`:#{`type`:"string"},
              `issuer`:#{`type`:#["string","null"]},
              `mustBePresent`:#{`type`:"boolean"},
              `path`:#{`type`:"string"},
              `contextSelectorId`:#{`type`:#["string","null"]},
              `functionId`:#{`type`:"string"},
              `description`:#{`type`:#["string","null"]},
              `variableId`:#{`type`:"string"}
            }
          },
          `namespaces`:#{`type`:"object",`additionalProperties`:#{`type`:#["string","null"]}},
          `type`:#{`type`:"string"},
          `lexical`:#{`type`:"string"},
          `xpathCategory`:#{`type`:#["string","null"]},
          `category`:#{`type`:#["string","null"]},
          `attributeId`:#{`type`:"string"},
          `dataType`:#{`type`:"string"},
          `issuer`:#{`type`:#["string","null"]},
          `mustBePresent`:#{`type`:"boolean"},
          `path`:#{`type`:"string"},
          `contextSelectorId`:#{`type`:#["string","null"]},
          `functionId`:#{`type`:"string"},
          `variableId`:#{`type`:"string"},
          `on`:#{`type`:"string"},
          `name`:#{`type`:"string"}
        }
      },
      `algorithms`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `uri`:#{`type`:"string"},
            `label`:#{`type`:"string"},
            `what`:#{`type`:"string"}
          }
        }
      },
      `scope`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{`id`:#{`type`:"string"},`detail`:#{`type`:"string"}}
        }
      },
      `valueShortType`:#{`type`:#["string","null"]}
    },
    `$types`:#["object","null"]
  }) @hoisted model XacmlEditor_tree_i_edit_h891 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `types`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{`value`:#{`type`:"string"},`label`:#{`type`:"string"}}
        }
      },
      `categories`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{`value`:#{`type`:"string"},`label`:#{`type`:"string"}}
        }
      },
      `functions`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{`value`:#{`type`:"string"},`label`:#{`type`:"string"}}
        }
      },
      `matchFunctions`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{`value`:#{`type`:"string"},`label`:#{`type`:"string"}}
        }
      },
      `xpathType`:#{`type`:"string"},
      `resourceCategory`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model XacmlEditor_menus_h892 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlEditor_problems_i_h893 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlEditor_xpathVersionGaps_i_h894 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlEditor_alfa_h895 {}

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
      `enabled`?: XacmlEditor_serviceOwn_i_enabled_h888;
      `effect`?: string;
      `readsRisk`?: boolean
    })[];
    `policy`?: XacmlEditor_policy_h889;
    `problem`?: XacmlEditor_problem_h890;
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
      `edit`?: XacmlEditor_tree_i_edit_h891
    })[];
    `menus`?: XacmlEditor_menus_h892;
    `problems`?: (XacmlEditor_problems_i_h893)[];
    `xpathVersionGaps`?: (XacmlEditor_xpathVersionGaps_i_h894)[];
    `document`?: string;
    `alfa`?: XacmlEditor_alfa_h895;
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

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlDecision_resource_h896 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `code`:#{`type`:"string"},
      `message`:#{`type`:#["string","null"]},
      `detail`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `attributeId`:#{`type`:"string"},
          `category`:#{`type`:"string"},
          `dataType`:#{`type`:"string"},
          `problems`:#{`type`:"array",`items`:#{`type`:"string"}},
          `errors`:#{`type`:"array",`items`:#{`type`:"string"}},
          `type`:#{`type`:"string"},
          `lexical`:#{`type`:"string"}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model XacmlDecision_status_h897 {}

@hoisted union XacmlDecision_applicablePolicies_i_h898 {string, {`kind`?: string; `id`?: string; `version`?: string}}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlDecision_enforcement_why_h899 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlDecision_enforcements_i_why_h900 {}

@component model `XacmlDecision` {
    `xacml`?: boolean;
    `message`?: string;
    `asked`?: boolean;
    `subject`?: string;
    `action`?: string;
    `resource`?: XacmlDecision_resource_h896;
    `decision`?: string;
    `status`?: XacmlDecision_status_h897;
    `obligations`?: (string)[];
    `advice`?: (string)[];
    `applicablePolicies`?: (XacmlDecision_applicablePolicies_i_h898)[];
    `enforcement`?: {
      `allowed`?: boolean;
      `bias`?: string;
      `why`?: XacmlDecision_enforcement_why_h899
    };
    `enforcements`?: ({
      `allowed`?: boolean;
      `bias`?: string;
      `why`?: XacmlDecision_enforcements_i_why_h900
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

@hoisted union GnapServer_capabilities_interaction_start_modes_supported_h901 {(string)[], string, boolean, null}

@hoisted union GnapServer_capabilities_interaction_finish_methods_supported_h902 {(string)[], string, boolean, null}

@hoisted union GnapServer_capabilities_key_proofs_supported_h903 {(string)[], string, boolean, null}

@hoisted union GnapServer_capabilities_sub_id_formats_supported_h904 {(string)[], string, boolean, null}

@hoisted union GnapServer_capabilities_assertion_formats_supported_h905 {(string)[], string, boolean, null}

@hoisted union GnapServer_capabilities_key_rotation_supported_h906 {(string)[], string, boolean, null}

@hoisted union GnapServer_capabilities_token_formats_supported_h907 {(string)[], string, boolean, null}

@hoisted union GnapServer_authorizationServers_i_capabilities_interaction_start_modes_supported_h908 {(string)[], string, boolean, null}

@hoisted union GnapServer_authorizationServers_i_capabilities_interaction_finish_methods_supported_h909 {(string)[], string, boolean, null}

@hoisted union GnapServer_authorizationServers_i_capabilities_key_proofs_supported_h910 {(string)[], string, boolean, null}

@hoisted union GnapServer_authorizationServers_i_capabilities_sub_id_formats_supported_h911 {(string)[], string, boolean, null}

@hoisted union GnapServer_authorizationServers_i_capabilities_assertion_formats_supported_h912 {(string)[], string, boolean, null}

@hoisted union GnapServer_authorizationServers_i_capabilities_key_rotation_supported_h913 {(string)[], string, boolean, null}

@hoisted union GnapServer_authorizationServers_i_capabilities_token_formats_supported_h914 {(string)[], string, boolean, null}

@js(#{`$types`:#["string","null"]}) @hoisted model GnapServer_grants_state_h915 {}

@js(#{`$types`:#["string","null"]}) @hoisted model GnapServer_grants_rows_i_authorizationServer_h916 {}

@js(#{`$types`:#["string","null"]}) @hoisted model GnapServer_grants_rows_i_grantEndpoint_h917 {}

@js(#{`$types`:#["string","null"]}) @hoisted model GnapServer_grants_rows_i_client_h918 {}

@js(#{`$types`:#["string","null"]}) @hoisted model GnapServer_grants_rows_i_proof_h919 {}

@js(#{`$types`:#["string","null"]}) @hoisted model GnapServer_grants_rows_i_resourceOwner_h920 {}

@js(#{`$types`:#["string","null"]}) @hoisted model GnapServer_grants_rows_i_decision_h921 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `modes`:#{`type`:"array",`items`:#{`type`:"string"}},
      `finish`:#{`type`:#["string","null"]},
      `started`:#{
        `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
      },
      `expiresAt`:#{
        `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model GnapServer_grants_rows_i_interaction_h922 {}

@js(#{`$types`:#["string","null"]}) @hoisted model GnapServer_grants_rows_i_derivedFrom_h923 {}

@hoisted union GnapServer_grants_rows_i_createdAt_v1_h924 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union GnapServer_grants_rows_i_createdAt_h925 {null, GnapServer_grants_rows_i_createdAt_v1_h924}

@hoisted union GnapServer_grants_rows_i_updatedAt_v1_h926 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union GnapServer_grants_rows_i_updatedAt_h927 {null, GnapServer_grants_rows_i_updatedAt_v1_h926}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `reason`:#{`type`:"string"},
      `at`:#{
        `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
      },
      `note`:#{`type`:#["string","null"]}
    },
    `$types`:#["object","null"]
  }) @hoisted model GnapServer_grants_rows_i_finalization_h928 {}

@hoisted union GnapServer_grants_rows_i_grantExpiresAt_v1_h929 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union GnapServer_grants_rows_i_grantExpiresAt_h930 {null, GnapServer_grants_rows_i_grantExpiresAt_v1_h929}

@hoisted union GnapServer_grants_rows_i_history_i_at_v1_h931 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union GnapServer_grants_rows_i_history_i_at_h932 {null, GnapServer_grants_rows_i_history_i_at_v1_h931}

@js(#{`$types`:#["string","null"]}) @hoisted model GnapServer_grants_rows_i_history_i_note_h933 {}

@js(#{
    `x-free-form`:"An RFC 9635 section 8 access right as a resource server registered it: a string reference, or an object whose members are that API's own.",
    `description`:"An RFC 9635 section 8 access right as a resource server registered it: a string reference, or an object whose members are that API's own."
  }) @hoisted model GnapServer_resourceSets_rows_i_access_i_h934 {}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","null"]}) @hoisted model GnapServer_resourceSets_rows_i_tokenFormats_h935 {}

@hoisted union GnapServer_resourceSets_rows_i_createdAt_v1_h936 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union GnapServer_resourceSets_rows_i_createdAt_h937 {null, GnapServer_resourceSets_rows_i_createdAt_v1_h936}

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
            `settings`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `key`:#{`type`:"string"},
                  `group`:#{`type`:"string"},
                  `label`:#{`type`:"string"},
                  `description`:#{`type`:"string"},
                  `type`:#{`type`:"string"},
                  `enumValues`:#{
                    `type`:"array",
                    `items`:#{
                      `anyOf`:#[
                        #{`type`:"string"},
                        #{`type`:"number"},
                        #{`type`:"boolean"},
                        #{`type`:"null"}
                      ]
                    }
                  },
                  `csvValues`:#{
                    `type`:"array",
                    `items`:#{
                      `anyOf`:#[
                        #{`type`:"string"},
                        #{`type`:"number"},
                        #{`type`:"boolean"},
                        #{`type`:"null"}
                      ]
                    }
                  },
                  `ordered`:#{`type`:"boolean"},
                  `csvValueNotes`:#{`type`:"object",`additionalProperties`:#{`type`:"string"}},
                  `selectAll`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `onlyWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      },
                      `aloneWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      }
                    }
                  },
                  `min`:#{`type`:"number"},
                  `max`:#{`type`:"number"},
                  `step`:#{`type`:"number"},
                  `value`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `text`:#{`type`:#["string","null"]},
                  `source`:#{`type`:"string"},
                  `editable`:#{`type`:"boolean"},
                  `restartReason`:#{`type`:"string"},
                  `editRefusal`:#{`type`:"string"},
                  `env`:#{
                    `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                  },
                  `legacyEnv`:#{
                    `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                  },
                  `appconfigPath`:#{`type`:"string"},
                  `default`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `masked`:#{`type`:"boolean"},
                  `realmSettable`:#{`type`:"boolean"},
                  `overridden`:#{`type`:"boolean"}
                }
              }
            }
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
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model GnapServer_settings_h938 {}

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
      `interaction_start_modes_supported`?: GnapServer_capabilities_interaction_start_modes_supported_h901;
      `interaction_finish_methods_supported`?: GnapServer_capabilities_interaction_finish_methods_supported_h902;
      `key_proofs_supported`?: GnapServer_capabilities_key_proofs_supported_h903;
      `sub_id_formats_supported`?: GnapServer_capabilities_sub_id_formats_supported_h904;
      `assertion_formats_supported`?: GnapServer_capabilities_assertion_formats_supported_h905;
      `key_rotation_supported`?: GnapServer_capabilities_key_rotation_supported_h906;
      `token_formats_supported`?: GnapServer_capabilities_token_formats_supported_h907
    };
    `authorizationServers`?: ({
      `id`?: string;
      `label`?: string;
      `capabilities`?: {
        `grant_request_endpoint`?: string;
        `interaction_start_modes_supported`?: GnapServer_authorizationServers_i_capabilities_interaction_start_modes_supported_h908;
        `interaction_finish_methods_supported`?: GnapServer_authorizationServers_i_capabilities_interaction_finish_methods_supported_h909;
        `key_proofs_supported`?: GnapServer_authorizationServers_i_capabilities_key_proofs_supported_h910;
        `sub_id_formats_supported`?: GnapServer_authorizationServers_i_capabilities_sub_id_formats_supported_h911;
        `assertion_formats_supported`?: GnapServer_authorizationServers_i_capabilities_assertion_formats_supported_h912;
        `key_rotation_supported`?: GnapServer_authorizationServers_i_capabilities_key_rotation_supported_h913;
        `token_formats_supported`?: GnapServer_authorizationServers_i_capabilities_token_formats_supported_h914
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
      `state`?: GnapServer_grants_state_h915;
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
        `authorizationServer`?: GnapServer_grants_rows_i_authorizationServer_h916;
        `grantEndpoint`?: GnapServer_grants_rows_i_grantEndpoint_h917;
        `client`?: GnapServer_grants_rows_i_client_h918;
        `proof`?: GnapServer_grants_rows_i_proof_h919;
        `resourceOwner`?: GnapServer_grants_rows_i_resourceOwner_h920;
        `decision`?: GnapServer_grants_rows_i_decision_h921;
        `interaction`?: GnapServer_grants_rows_i_interaction_h922;
        `tokens`?: integer;
        `derivedFrom`?: GnapServer_grants_rows_i_derivedFrom_h923;
        `createdAt`?: GnapServer_grants_rows_i_createdAt_h925;
        `updatedAt`?: GnapServer_grants_rows_i_updatedAt_h927;
        `finalization`?: GnapServer_grants_rows_i_finalization_h928;
        `grantExpiresAt`?: GnapServer_grants_rows_i_grantExpiresAt_h930;
        `history`?: ({
          `at`?: GnapServer_grants_rows_i_history_i_at_h932;
          `state`?: string;
          `note`?: GnapServer_grants_rows_i_history_i_note_h933
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
        `access`?: (GnapServer_resourceSets_rows_i_access_i_h934)[];
        `tokenFormats`?: GnapServer_resourceSets_rows_i_tokenFormats_h935;
        `introspectionRequired`?: boolean;
        `createdAt`?: GnapServer_resourceSets_rows_i_createdAt_h937
      })[]
    };
    `actions`?: (string)[];
    `settings`?: GnapServer_settings_h938
  }

@hoisted union GnapMonitor_since_v1_h939 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union GnapMonitor_since_h940 {null, GnapMonitor_since_v1_h939}

@js(#{`$types`:#["string","null"]}) @hoisted model GnapMonitor_rows_i_name_h941 {}

@hoisted union GnapMonitor_rows_i_counters_ap_h942 {numeric, string, null, Record<numeric>}

@hoisted union GnapMonitor_rows_i_lastAt_v1_h943 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union GnapMonitor_rows_i_lastAt_h944 {null, GnapMonitor_rows_i_lastAt_v1_h943}

@js(#{`$types`:#["string","null"]}) @hoisted model GnapMonitor_rows_i_lastEvent_h945 {}

@component model `GnapMonitor` {
    `page`?: string;
    `title`?: string;
    `since`?: GnapMonitor_since_h940;
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
      `name`?: GnapMonitor_rows_i_name_h941;
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
      `counters`?: Record<GnapMonitor_rows_i_counters_ap_h942>;
      `lastAt`?: GnapMonitor_rows_i_lastAt_h944;
      `lastEvent`?: GnapMonitor_rows_i_lastEvent_h945
    })[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlMonitor_policies_root_h946 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlMonitor_realm_name_h947 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlMonitor_rows_i_bias_h948 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_rows_i_allowed_h949 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_rows_i_refused_h950 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_rows_i_permit_h951 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_rows_i_deny_h952 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_rows_i_notApplicable_h953 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_rows_i_indeterminate_h954 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_rows_i_other_h955 {}

@hoisted union XacmlMonitor_rows_i_lastAt_h956 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlMonitor_rows_i_lastDecision_h957 {}

@js(#{`$types`:#["boolean","null"]}) @hoisted model XacmlMonitor_rows_i_lastAllowed_h958 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlMonitor_rows_i_remote_registeredAt_h959 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlMonitor_rows_i_remote_lastSeen_h960 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_rows_i_remote_policyCount_h961 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlMonitor_remoteRows_i_bias_h962 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_remoteRows_i_allowed_h963 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_remoteRows_i_refused_h964 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_remoteRows_i_permit_h965 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_remoteRows_i_deny_h966 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_remoteRows_i_notApplicable_h967 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_remoteRows_i_indeterminate_h968 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_remoteRows_i_other_h969 {}

@hoisted union XacmlMonitor_remoteRows_i_lastAt_h970 {string, numeric, null}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlMonitor_remoteRows_i_lastDecision_h971 {}

@js(#{`$types`:#["boolean","null"]}) @hoisted model XacmlMonitor_remoteRows_i_lastAllowed_h972 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlMonitor_remoteRows_i_remote_registeredAt_h973 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlMonitor_remoteRows_i_remote_lastSeen_h974 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model XacmlMonitor_remoteRows_i_remote_policyCount_h975 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlMonitor_elsewhere_i_name_h976 {}

@component model `XacmlMonitor` {
    `xacml`?: boolean;
    `message`?: string;
    `policies`?: {
      `total`?: integer;
      `enabled`?: integer;
      `root`?: XacmlMonitor_policies_root_h946
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
    `realm`?: {`id`?: string; `name`?: XacmlMonitor_realm_name_h947};
    `rows`?: ({
      `id`?: string;
      `label`?: string;
      `kind`?: string;
      `where`?: string;
      `module`?: string;
      `guards`?: string;
      `enforces`?: boolean;
      `bias`?: XacmlMonitor_rows_i_bias_h948;
      `dischargesObligations`?: boolean;
      `decisions`?: integer;
      `allowed`?: XacmlMonitor_rows_i_allowed_h949;
      `refused`?: XacmlMonitor_rows_i_refused_h950;
      `permit`?: XacmlMonitor_rows_i_permit_h951;
      `deny`?: XacmlMonitor_rows_i_deny_h952;
      `notApplicable`?: XacmlMonitor_rows_i_notApplicable_h953;
      `indeterminate`?: XacmlMonitor_rows_i_indeterminate_h954;
      `other`?: XacmlMonitor_rows_i_other_h955;
      `undischargeable`?: integer;
      `lastAt`?: XacmlMonitor_rows_i_lastAt_h956;
      `lastDecision`?: XacmlMonitor_rows_i_lastDecision_h957;
      `lastAllowed`?: XacmlMonitor_rows_i_lastAllowed_h958;
      `remote`?: {
        `authenticated`?: boolean;
        `certificateSubject`?: string;
        `current`?: boolean;
        `stale`?: boolean;
        `enabled`?: boolean;
        `registeredAt`?: XacmlMonitor_rows_i_remote_registeredAt_h959;
        `lastSeen`?: XacmlMonitor_rows_i_remote_lastSeen_h960;
        `syncToken`?: string;
        `policyCount`?: XacmlMonitor_rows_i_remote_policyCount_h961;
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
      `bias`?: XacmlMonitor_remoteRows_i_bias_h962;
      `dischargesObligations`?: boolean;
      `decisions`?: integer;
      `allowed`?: XacmlMonitor_remoteRows_i_allowed_h963;
      `refused`?: XacmlMonitor_remoteRows_i_refused_h964;
      `permit`?: XacmlMonitor_remoteRows_i_permit_h965;
      `deny`?: XacmlMonitor_remoteRows_i_deny_h966;
      `notApplicable`?: XacmlMonitor_remoteRows_i_notApplicable_h967;
      `indeterminate`?: XacmlMonitor_remoteRows_i_indeterminate_h968;
      `other`?: XacmlMonitor_remoteRows_i_other_h969;
      `undischargeable`?: integer;
      `lastAt`?: XacmlMonitor_remoteRows_i_lastAt_h970;
      `lastDecision`?: XacmlMonitor_remoteRows_i_lastDecision_h971;
      `lastAllowed`?: XacmlMonitor_remoteRows_i_lastAllowed_h972;
      `remote`?: {
        `authenticated`?: boolean;
        `certificateSubject`?: string;
        `current`?: boolean;
        `stale`?: boolean;
        `enabled`?: boolean;
        `registeredAt`?: XacmlMonitor_remoteRows_i_remote_registeredAt_h973;
        `lastSeen`?: XacmlMonitor_remoteRows_i_remote_lastSeen_h974;
        `syncToken`?: string;
        `policyCount`?: XacmlMonitor_remoteRows_i_remote_policyCount_h975;
        `version`?: string;
        `lastNotify`?: string
      }
    })[];
    `elsewhere`?: ({
      `id`?: string;
      `name`?: XacmlMonitor_elsewhere_i_name_h976;
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

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlPeps_syncToken_h977 {}

@js(#{`$types`:#["number","null"]}) @hoisted model XacmlPeps_peps_i_policyCount_h978 {}

@js(#{`$types`:#["number","null"]}) @hoisted model XacmlPeps_peps_i_decisions_h979 {}

@js(#{`$types`:#["number","null"]}) @hoisted model XacmlPeps_peps_i_allowed_h980 {}

@js(#{`$types`:#["number","null"]}) @hoisted model XacmlPeps_peps_i_refused_h981 {}

@js(#{`$types`:#["number","null"]}) @hoisted model XacmlPeps_peps_i_undischargeable_h982 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlPeps_peps_i_notifyProblem_h983 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `subject`:#{`type`:"string"},
      `serialHex`:#{`type`:"string"},
      `notBefore`:#{`type`:"string"},
      `notAfter`:#{`type`:"string"},
      `expired`:#{`type`:"boolean"},
      `thumbprint`:#{`type`:"string"},
      `keyAlg`:#{`type`:"string"},
      `signatureAlg`:#{`type`:"string"},
      `dnsNames`:#{`type`:"array",`items`:#{`type`:"string"}},
      `ipAddresses`:#{`type`:"array",`items`:#{`type`:"string"}},
      `issuedAt`:#{`type`:"string"},
      `certificatePem`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model XacmlPeps_peps_i_listenerCertificate_h984 {}

@js(#{`$types`:#["string","null"]}) @hoisted model XacmlPeps_elsewhere_i_name_h985 {}

@component model `XacmlPeps` {
    `xacml`?: boolean;
    `message`?: string;
    `enabled`?: boolean;
    `syncToken`?: XacmlPeps_syncToken_h977;
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
      `policyCount`?: XacmlPeps_peps_i_policyCount_h978;
      `decisions`?: XacmlPeps_peps_i_decisions_h979;
      `allowed`?: XacmlPeps_peps_i_allowed_h980;
      `refused`?: XacmlPeps_peps_i_refused_h981;
      `undischargeable`?: XacmlPeps_peps_i_undischargeable_h982;
      `lastNotify`?: string;
      `current`?: boolean;
      `stale`?: boolean;
      `notifyProblem`?: XacmlPeps_peps_i_notifyProblem_h983;
      `listenerCertificate`?: XacmlPeps_peps_i_listenerCertificate_h984
    })[];
    `elsewhere`?: ({
      `id`?: string;
      `name`?: XacmlPeps_elsewhere_i_name_h985;
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

@hoisted union Ssf_eventTypes_i_subject_h986 {boolean, string, null}

@hoisted union Ssf_eventTypes_i_members_i_required_h987 {boolean, string, null}

@js(#{`$types`:#["string","null"]}) @hoisted model Ssf_eventTypes_i_members_i_type_h988 {}

@hoisted union Ssf_streams_i_createdAt_v1_h989 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Ssf_streams_i_createdAt_h990 {null, Ssf_streams_i_createdAt_v1_h989}

@js(#{`$types`:#["string","null"]}) @hoisted model Ssf_streams_i_lastPushError_h991 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Ssf_streamDetail_i_iss_h992 {}

@hoisted union Ssf_streamDetail_i_aud_v1_h993 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union Ssf_streamDetail_i_aud_h994 {null, Ssf_streamDetail_i_aud_v1_h993}

@js(#{`$types`:#["string","null"]}) @hoisted model Ssf_streamDetail_i_statusReason_h995 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Ssf_streamDetail_i_delivery_endpoint_url_h996 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Ssf_streamDetail_i_format_h997 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Ssf_streamDetail_i_description_h998 {}

@hoisted union Ssf_streamDetail_i_createdAt_v1_h999 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Ssf_streamDetail_i_createdAt_h1000 {null, Ssf_streamDetail_i_createdAt_v1_h999}

@hoisted union Ssf_streamDetail_i_updatedAt_v1_h1001 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Ssf_streamDetail_i_updatedAt_h1002 {null, Ssf_streamDetail_i_updatedAt_v1_h1001}

@js(#{`$types`:#["string","null"]}) @hoisted model Ssf_streamDetail_i_createdBy_h1003 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Ssf_streamDetail_i_lastPushError_h1004 {}

@hoisted union Ssf_streamDetail_i_lastPushAt_v1_h1005 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Ssf_streamDetail_i_lastPushAt_h1006 {null, Ssf_streamDetail_i_lastPushAt_v1_h1005}

@js(#{`$types`:#["boolean","null"]}) @hoisted model Ssf_streamDetail_i_subjects_i_verified_h1007 {}

@hoisted union Ssf_streamDetail_i_subjects_i_addedAt_v1_h1008 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Ssf_streamDetail_i_subjects_i_addedAt_h1009 {null, Ssf_streamDetail_i_subjects_i_addedAt_v1_h1008}

@hoisted union Ssf_streamDetail_i_queue_i_queuedAt_v1_h1010 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Ssf_streamDetail_i_queue_i_queuedAt_h1011 {null, Ssf_streamDetail_i_queue_i_queuedAt_v1_h1010}

@hoisted union Ssf_streamDetail_i_queue_i_deliveredAt_v1_h1012 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Ssf_streamDetail_i_queue_i_deliveredAt_h1013 {null, Ssf_streamDetail_i_queue_i_deliveredAt_v1_h1012}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `jti`:#{`type`:"string"},
      `iat`:#{`type`:"number"},
      `issuer`:#{`type`:"string"},
      `audience`:#{
        `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
      },
      `types`:#{`type`:"array",`items`:#{`type`:"string"}},
      `name`:#{`type`:"string"},
      `subject`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model Ssf_streamDetail_i_queue_i_summary_h1014 {}

@hoisted union Ssf_streamDetail_i_deadLetters_i_queuedAt_v1_h1015 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Ssf_streamDetail_i_deadLetters_i_queuedAt_h1016 {null, Ssf_streamDetail_i_deadLetters_i_queuedAt_v1_h1015}

@hoisted union Ssf_streamDetail_i_deadLetters_i_deadAt_v1_h1017 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Ssf_streamDetail_i_deadLetters_i_deadAt_h1018 {null, Ssf_streamDetail_i_deadLetters_i_deadAt_v1_h1017}

@js(#{`$types`:#["string","null"]}) @hoisted model Ssf_streamDetail_i_deadLetters_i_reason_h1019 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Ssf_streamDetail_i_deadLetters_i_errorCode_h1020 {}

@js(#{`$types`:#["integer","null"]}) @hoisted model Ssf_streamDetail_i_deadLetters_i_status_h1021 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `jti`:#{`type`:"string"},
      `iat`:#{`type`:"number"},
      `issuer`:#{`type`:"string"},
      `audience`:#{
        `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
      },
      `types`:#{`type`:"array",`items`:#{`type`:"string"}},
      `name`:#{`type`:"string"},
      `subject`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model Ssf_streamDetail_i_deadLetters_i_summary_h1022 {}

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
            `settings`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `key`:#{`type`:"string"},
                  `group`:#{`type`:"string"},
                  `label`:#{`type`:"string"},
                  `description`:#{`type`:"string"},
                  `type`:#{`type`:"string"},
                  `enumValues`:#{
                    `type`:"array",
                    `items`:#{
                      `anyOf`:#[
                        #{`type`:"string"},
                        #{`type`:"number"},
                        #{`type`:"boolean"},
                        #{`type`:"null"}
                      ]
                    }
                  },
                  `csvValues`:#{
                    `type`:"array",
                    `items`:#{
                      `anyOf`:#[
                        #{`type`:"string"},
                        #{`type`:"number"},
                        #{`type`:"boolean"},
                        #{`type`:"null"}
                      ]
                    }
                  },
                  `ordered`:#{`type`:"boolean"},
                  `csvValueNotes`:#{`type`:"object",`additionalProperties`:#{`type`:"string"}},
                  `selectAll`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `onlyWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      },
                      `aloneWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      }
                    }
                  },
                  `min`:#{`type`:"number"},
                  `max`:#{`type`:"number"},
                  `step`:#{`type`:"number"},
                  `value`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `text`:#{`type`:#["string","null"]},
                  `source`:#{`type`:"string"},
                  `editable`:#{`type`:"boolean"},
                  `restartReason`:#{`type`:"string"},
                  `editRefusal`:#{`type`:"string"},
                  `env`:#{
                    `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                  },
                  `legacyEnv`:#{
                    `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                  },
                  `appconfigPath`:#{`type`:"string"},
                  `default`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `masked`:#{`type`:"boolean"},
                  `realmSettable`:#{`type`:"boolean"},
                  `overridden`:#{`type`:"boolean"}
                }
              }
            }
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
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model Ssf_settings_h1023 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Ssf_streamFilter_h1024 {}

@hoisted union Ssf_protocolEndpoints_i_methods_h1025 {string, (string)[]}

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
      `subject`?: Ssf_eventTypes_i_subject_h986;
      `what`?: string;
      `offered`?: boolean;
      `members`?: ({
        `name`?: string;
        `required`?: Ssf_eventTypes_i_members_i_required_h987;
        `what`?: string;
        `type`?: Ssf_eventTypes_i_members_i_type_h988;
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
      `createdAt`?: Ssf_streams_i_createdAt_h990;
      `lastPushError`?: Ssf_streams_i_lastPushError_h991
    })[];
    `endpoints`?: ({`method`?: string; `path`?: string; `what`?: string})[];
    `reachableNegatives`?: ({`what`?: string; `answer`?: string})[];
    `doesNotDo`?: (string)[];
    `streamDetail`?: ({
      `stream_id`?: string;
      `iss`?: Ssf_streamDetail_i_iss_h992;
      `aud`?: Ssf_streamDetail_i_aud_h994;
      `status`?: string;
      `statusReason`?: Ssf_streamDetail_i_statusReason_h995;
      `delivery`?: {
        `method`?: string;
        `endpoint_url`?: Ssf_streamDetail_i_delivery_endpoint_url_h996
      };
      `events_delivered`?: (string)[];
      `events_requested`?: (string)[];
      `format`?: Ssf_streamDetail_i_format_h997;
      `description`?: Ssf_streamDetail_i_description_h998;
      `createdAt`?: Ssf_streamDetail_i_createdAt_h1000;
      `updatedAt`?: Ssf_streamDetail_i_updatedAt_h1002;
      `createdBy`?: Ssf_streamDetail_i_createdBy_h1003;
      `internal`?: boolean;
      `counters`?: Record<numeric>;
      `lastPushError`?: Ssf_streamDetail_i_lastPushError_h1004;
      `lastPushAt`?: Ssf_streamDetail_i_lastPushAt_h1006;
      `subjects`?: ({
        `text`?: string;
        `verified`?: Ssf_streamDetail_i_subjects_i_verified_h1007;
        `addedAt`?: Ssf_streamDetail_i_subjects_i_addedAt_h1009;
        @js(#{
          `x-free-form`:"An RFC 9493 subject identifier, as a stream was given it or a person named it: the format decides the members, an `aliases` nests, and SSF 1.0 section 3.3 lets a receiver add its own.",
          `description`:"An RFC 9493 subject identifier, as a stream was given it or a person named it: the format decides the members, an `aliases` nests, and SSF 1.0 section 3.3 lets a receiver add its own."
        }) `subject`?: unknown
      })[];
      `queue`?: ({
        `jti`?: string;
        `queuedAt`?: Ssf_streamDetail_i_queue_i_queuedAt_h1011;
        `deliveredAt`?: Ssf_streamDetail_i_queue_i_deliveredAt_h1013;
        `summary`?: Ssf_streamDetail_i_queue_i_summary_h1014
      })[];
      `dead`?: boolean;
      `deadSince`?: string;
      `deadReason`?: string;
      `failingSince`?: string;
      `nextProbeAt`?: string;
      `deadLetters`?: ({
        `jti`?: string;
        `queuedAt`?: Ssf_streamDetail_i_deadLetters_i_queuedAt_h1016;
        `deadAt`?: Ssf_streamDetail_i_deadLetters_i_deadAt_h1018;
        `reason`?: Ssf_streamDetail_i_deadLetters_i_reason_h1019;
        `errorCode`?: Ssf_streamDetail_i_deadLetters_i_errorCode_h1020;
        `status`?: Ssf_streamDetail_i_deadLetters_i_status_h1021;
        `signed`?: boolean;
        `summary`?: Ssf_streamDetail_i_deadLetters_i_summary_h1022
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
    `settings`?: Ssf_settings_h1023;
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
    `streamFilter`?: Ssf_streamFilter_h1024;
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
      `methods`?: Ssf_protocolEndpoints_i_methods_h1025;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean;
      `listening`?: boolean
    })[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model CaepApplication_name_h1026 {}

@hoisted union CaepApplication_lastPushAt_v1_h1027 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union CaepApplication_lastPushAt_h1028 {null, CaepApplication_lastPushAt_v1_h1027}

@js(#{`$types`:#["string","null"]}) @hoisted model CaepApplication_lastPushError_h1029 {}

@component model `CaepApplication` {
    `identifier`?: string;
    `name`?: CaepApplication_name_h1026;
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
    `lastPushAt`?: CaepApplication_lastPushAt_h1028;
    `lastPushError`?: CaepApplication_lastPushError_h1029
  }

@hoisted union Caep_eventTypes_i_subject_h1030 {boolean, string, null}

@hoisted union Caep_eventTypes_i_members_i_required_h1031 {boolean, string, null}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_eventTypes_i_members_i_type_h1032 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_sessions_i_sub_h1033 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_sessions_i_username_h1034 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_sessions_i_iss_h1035 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_sessions_i_protocol_h1036 {}

@hoisted union Caep_sessions_i_establishedAt_v1_h1037 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Caep_sessions_i_establishedAt_h1038 {null, Caep_sessions_i_establishedAt_v1_h1037}

@hoisted union Caep_sessions_i_updatedAt_v1_h1039 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Caep_sessions_i_updatedAt_h1040 {null, Caep_sessions_i_updatedAt_v1_h1039}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_sessions_i_state_h1041 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_sessions_i_acr_h1042 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_sessions_i_compliance_h1043 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_applications_i_name_h1044 {}

@hoisted union Caep_applications_i_lastPushAt_v1_h1045 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Caep_applications_i_lastPushAt_h1046 {null, Caep_applications_i_lastPushAt_v1_h1045}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_applications_i_lastPushError_h1047 {}

@hoisted union Caep_streams_i_aud_v1_h1048 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union Caep_streams_i_aud_h1049 {null, Caep_streams_i_aud_v1_h1048}

@hoisted union Caep_catalogue_i_subject_h1050 {boolean, string, null}

@hoisted union Caep_catalogue_i_members_i_required_h1051 {boolean, string, null}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_catalogue_i_members_i_type_h1052 {}

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
            `settings`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `key`:#{`type`:"string"},
                  `group`:#{`type`:"string"},
                  `label`:#{`type`:"string"},
                  `description`:#{`type`:"string"},
                  `type`:#{`type`:"string"},
                  `enumValues`:#{
                    `type`:"array",
                    `items`:#{
                      `anyOf`:#[
                        #{`type`:"string"},
                        #{`type`:"number"},
                        #{`type`:"boolean"},
                        #{`type`:"null"}
                      ]
                    }
                  },
                  `csvValues`:#{
                    `type`:"array",
                    `items`:#{
                      `anyOf`:#[
                        #{`type`:"string"},
                        #{`type`:"number"},
                        #{`type`:"boolean"},
                        #{`type`:"null"}
                      ]
                    }
                  },
                  `ordered`:#{`type`:"boolean"},
                  `csvValueNotes`:#{`type`:"object",`additionalProperties`:#{`type`:"string"}},
                  `selectAll`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `onlyWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      },
                      `aloneWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      }
                    }
                  },
                  `min`:#{`type`:"number"},
                  `max`:#{`type`:"number"},
                  `step`:#{`type`:"number"},
                  `value`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `text`:#{`type`:#["string","null"]},
                  `source`:#{`type`:"string"},
                  `editable`:#{`type`:"boolean"},
                  `restartReason`:#{`type`:"string"},
                  `editRefusal`:#{`type`:"string"},
                  `env`:#{
                    `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                  },
                  `legacyEnv`:#{
                    `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                  },
                  `appconfigPath`:#{`type`:"string"},
                  `default`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `masked`:#{`type`:"boolean"},
                  `realmSettable`:#{`type`:"boolean"},
                  `overridden`:#{`type`:"boolean"}
                }
              }
            }
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
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model Caep_settings_h1053 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_filter_sessions_h1054 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_filter_applications_h1055 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_shown_sessions_i_sub_h1056 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_shown_sessions_i_username_h1057 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_shown_sessions_i_iss_h1058 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_shown_sessions_i_protocol_h1059 {}

@hoisted union Caep_shown_sessions_i_establishedAt_v1_h1060 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Caep_shown_sessions_i_establishedAt_h1061 {null, Caep_shown_sessions_i_establishedAt_v1_h1060}

@hoisted union Caep_shown_sessions_i_updatedAt_v1_h1062 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Caep_shown_sessions_i_updatedAt_h1063 {null, Caep_shown_sessions_i_updatedAt_v1_h1062}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_shown_sessions_i_state_h1064 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_shown_sessions_i_acr_h1065 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_shown_sessions_i_compliance_h1066 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_shown_applications_i_name_h1067 {}

@hoisted union Caep_shown_applications_i_lastPushAt_v1_h1068 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Caep_shown_applications_i_lastPushAt_h1069 {null, Caep_shown_applications_i_lastPushAt_v1_h1068}

@js(#{`$types`:#["string","null"]}) @hoisted model Caep_shown_applications_i_lastPushError_h1070 {}

@hoisted union Caep_shown_streams_i_aud_v1_h1071 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union Caep_shown_streams_i_aud_h1072 {null, Caep_shown_streams_i_aud_v1_h1071}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `sessionId`:#{`type`:"string"},
      `sub`:#{`type`:#["string","null"]},
      `username`:#{`type`:#["string","null"]},
      `iss`:#{`type`:#["string","null"]},
      `protocol`:#{`type`:#["string","null"]},
      `establishedAt`:#{
        `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
      },
      `updatedAt`:#{
        `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
      },
      `state`:#{`type`:#["string","null"]},
      `acr`:#{`type`:#["string","null"]},
      `amr`:#{`type`:"array",`items`:#{`type`:"string"}},
      `assurance`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `namespace`:#{`type`:"string"},
          `level`:#{`type`:"string"},
          `previousLevel`:#{`type`:"string"}
        }
      },
      `compliance`:#{`type`:#["string","null"]},
      `risk`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `level`:#{`type`:"string"},
          `previousLevel`:#{`type`:"string"},
          `reason`:#{`type`:"string"}
        }
      },
      `claims`:#{
        `x-free-form`:"The claims a `token-claims-change` event said changed: whichever a person configured or an emitter named.",
        `description`:"The claims a `token-claims-change` event said changed: whichever a person configured or an emitter named."
      },
      `credentials`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `at`:#{`type`:"string"},
            `credentialType`:#{`type`:"string"},
            `changeType`:#{`type`:"string"},
            `friendlyName`:#{`type`:"string"}
          }
        }
      },
      `counts`:#{`type`:"object",`additionalProperties`:#{`type`:"number"}},
      `total`:#{`type`:"integer"},
      `events`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `jti`:#{`type`:"string"},
            `uri`:#{`type`:"string"},
            `name`:#{`type`:"string"},
            `at`:#{`type`:"string"},
            `streamId`:#{`type`:"string"},
            `warnings`:#{`type`:"array",`items`:#{`type`:"string"}}
          }
        }
      },
      `streams`:#{`type`:"array",`items`:#{`type`:"string"}},
      `notes`:#{`type`:"array",`items`:#{`type`:"string"}},
      `subject`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model Caep_session_h1073 {}

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
      `subject`?: Caep_eventTypes_i_subject_h1030;
      `what`?: string;
      `offered`?: boolean;
      `members`?: ({
        `name`?: string;
        `required`?: Caep_eventTypes_i_members_i_required_h1031;
        `what`?: string;
        `type`?: Caep_eventTypes_i_members_i_type_h1032;
        `values`?: (string)[]
      })[];
      `required`?: (string)[];
      `subjectFormats`?: (string)[];
      `deprecated`?: string
    })[];
    `totals`?: Record<numeric>;
    `sessions`?: ({
      `sessionId`?: string;
      `sub`?: Caep_sessions_i_sub_h1033;
      `username`?: Caep_sessions_i_username_h1034;
      `iss`?: Caep_sessions_i_iss_h1035;
      `protocol`?: Caep_sessions_i_protocol_h1036;
      `establishedAt`?: Caep_sessions_i_establishedAt_h1038;
      `updatedAt`?: Caep_sessions_i_updatedAt_h1040;
      `state`?: Caep_sessions_i_state_h1041;
      `acr`?: Caep_sessions_i_acr_h1042;
      `amr`?: (string)[];
      `assurance`?: {`namespace`?: string; `level`?: string; `previousLevel`?: string};
      `compliance`?: Caep_sessions_i_compliance_h1043;
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
      `name`?: Caep_applications_i_name_h1044;
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
      `lastPushAt`?: Caep_applications_i_lastPushAt_h1046;
      `lastPushError`?: Caep_applications_i_lastPushError_h1047
    })[];
    `streams`?: ({
      `stream_id`?: string;
      `aud`?: Caep_streams_i_aud_h1049;
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
      `subject`?: Caep_catalogue_i_subject_h1050;
      `what`?: string;
      `offered`?: boolean;
      `members`?: ({
        `name`?: string;
        `required`?: Caep_catalogue_i_members_i_required_h1051;
        `what`?: string;
        `type`?: Caep_catalogue_i_members_i_type_h1052;
        `values`?: (string)[]
      })[];
      `required`?: (string)[];
      `subjectFormats`?: (string)[];
      `deprecated`?: string
    })[];
    `settings`?: Caep_settings_h1053;
    `filter`?: {
      `sessions`?: Caep_filter_sessions_h1054;
      `applications`?: Caep_filter_applications_h1055
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
        `sub`?: Caep_shown_sessions_i_sub_h1056;
        `username`?: Caep_shown_sessions_i_username_h1057;
        `iss`?: Caep_shown_sessions_i_iss_h1058;
        `protocol`?: Caep_shown_sessions_i_protocol_h1059;
        `establishedAt`?: Caep_shown_sessions_i_establishedAt_h1061;
        `updatedAt`?: Caep_shown_sessions_i_updatedAt_h1063;
        `state`?: Caep_shown_sessions_i_state_h1064;
        `acr`?: Caep_shown_sessions_i_acr_h1065;
        `amr`?: (string)[];
        `assurance`?: {`namespace`?: string; `level`?: string; `previousLevel`?: string};
        `compliance`?: Caep_shown_sessions_i_compliance_h1066;
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
        `name`?: Caep_shown_applications_i_name_h1067;
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
        `lastPushAt`?: Caep_shown_applications_i_lastPushAt_h1069;
        `lastPushError`?: Caep_shown_applications_i_lastPushError_h1070
      })[];
      `streams`?: ({
        `stream_id`?: string;
        `aud`?: Caep_shown_streams_i_aud_h1072;
        `status`?: string;
        `delivery`?: string;
        `subjects`?: integer;
        `takes`?: (string)[]
      })[]
    };
    `matched`?: {`sessions`?: integer; `applications`?: integer; `streams`?: integer};
    `streamCounts`?: {`total`?: integer; `taking`?: integer};
    `id`?: string;
    `session`?: Caep_session_h1073;
    `events`?: ({
      `jti`?: string;
      `uri`?: string;
      `name`?: string;
      `at`?: string;
      `streamId`?: string;
      `warnings`?: (string)[]
    })[]
  }

@hoisted union Risc_eventTypes_i_subject_h1074 {boolean, string, null}

@hoisted union Risc_eventTypes_i_members_i_required_h1075 {boolean, string, null}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_eventTypes_i_members_i_type_h1076 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_accounts_i_sub_h1077 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_accounts_i_username_h1078 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_accounts_i_iss_h1079 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_accounts_i_dn_h1080 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_accounts_i_realm_h1081 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_accounts_i_email_h1082 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_accounts_i_phone_h1083 {}

@hoisted union Risc_accounts_i_createdAt_v1_h1084 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Risc_accounts_i_createdAt_h1085 {null, Risc_accounts_i_createdAt_v1_h1084}

@hoisted union Risc_accounts_i_updatedAt_v1_h1086 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Risc_accounts_i_updatedAt_h1087 {null, Risc_accounts_i_updatedAt_v1_h1086}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_accounts_i_lifecycle_h1088 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_accounts_i_optOut_h1089 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_accounts_i_credentialStanding_h1090 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_applications_i_name_h1091 {}

@hoisted union Risc_applications_i_lastPushAt_v1_h1092 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Risc_applications_i_lastPushAt_h1093 {null, Risc_applications_i_lastPushAt_v1_h1092}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_applications_i_lastPushError_h1094 {}

@hoisted union Risc_streams_i_aud_v1_h1095 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union Risc_streams_i_aud_h1096 {null, Risc_streams_i_aud_v1_h1095}

@hoisted union Risc_catalogue_i_subject_h1097 {boolean, string, null}

@hoisted union Risc_catalogue_i_members_i_required_h1098 {boolean, string, null}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_catalogue_i_members_i_type_h1099 {}

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
            `settings`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `key`:#{`type`:"string"},
                  `group`:#{`type`:"string"},
                  `label`:#{`type`:"string"},
                  `description`:#{`type`:"string"},
                  `type`:#{`type`:"string"},
                  `enumValues`:#{
                    `type`:"array",
                    `items`:#{
                      `anyOf`:#[
                        #{`type`:"string"},
                        #{`type`:"number"},
                        #{`type`:"boolean"},
                        #{`type`:"null"}
                      ]
                    }
                  },
                  `csvValues`:#{
                    `type`:"array",
                    `items`:#{
                      `anyOf`:#[
                        #{`type`:"string"},
                        #{`type`:"number"},
                        #{`type`:"boolean"},
                        #{`type`:"null"}
                      ]
                    }
                  },
                  `ordered`:#{`type`:"boolean"},
                  `csvValueNotes`:#{`type`:"object",`additionalProperties`:#{`type`:"string"}},
                  `selectAll`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `onlyWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      },
                      `aloneWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      }
                    }
                  },
                  `min`:#{`type`:"number"},
                  `max`:#{`type`:"number"},
                  `step`:#{`type`:"number"},
                  `value`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `text`:#{`type`:#["string","null"]},
                  `source`:#{`type`:"string"},
                  `editable`:#{`type`:"boolean"},
                  `restartReason`:#{`type`:"string"},
                  `editRefusal`:#{`type`:"string"},
                  `env`:#{
                    `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                  },
                  `legacyEnv`:#{
                    `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
                  },
                  `appconfigPath`:#{`type`:"string"},
                  `default`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{
                          `anyOf`:#[
                            #{`type`:"string"},
                            #{`type`:"number"},
                            #{`type`:"boolean"},
                            #{`type`:"null"}
                          ]
                        }
                      }
                    ]
                  },
                  `masked`:#{`type`:"boolean"},
                  `realmSettable`:#{`type`:"boolean"},
                  `overridden`:#{`type`:"boolean"}
                }
              }
            }
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
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model Risc_settings_h1100 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_filter_accounts_h1101 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_filter_applications_h1102 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_shown_accounts_i_sub_h1103 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_shown_accounts_i_username_h1104 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_shown_accounts_i_iss_h1105 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_shown_accounts_i_dn_h1106 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_shown_accounts_i_realm_h1107 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_shown_accounts_i_email_h1108 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_shown_accounts_i_phone_h1109 {}

@hoisted union Risc_shown_accounts_i_createdAt_v1_h1110 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Risc_shown_accounts_i_createdAt_h1111 {null, Risc_shown_accounts_i_createdAt_v1_h1110}

@hoisted union Risc_shown_accounts_i_updatedAt_v1_h1112 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Risc_shown_accounts_i_updatedAt_h1113 {null, Risc_shown_accounts_i_updatedAt_v1_h1112}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_shown_accounts_i_lifecycle_h1114 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_shown_accounts_i_optOut_h1115 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_shown_accounts_i_credentialStanding_h1116 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_shown_applications_i_name_h1117 {}

@hoisted union Risc_shown_applications_i_lastPushAt_v1_h1118 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Risc_shown_applications_i_lastPushAt_h1119 {null, Risc_shown_applications_i_lastPushAt_v1_h1118}

@js(#{`$types`:#["string","null"]}) @hoisted model Risc_shown_applications_i_lastPushError_h1120 {}

@hoisted union Risc_shown_streams_i_aud_v1_h1121 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union Risc_shown_streams_i_aud_h1122 {null, Risc_shown_streams_i_aud_v1_h1121}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `accountId`:#{`type`:"string"},
      `sub`:#{`type`:#["string","null"]},
      `username`:#{`type`:#["string","null"]},
      `iss`:#{`type`:#["string","null"]},
      `dn`:#{`type`:#["string","null"]},
      `realm`:#{`type`:#["string","null"]},
      `email`:#{`type`:#["string","null"]},
      `phone`:#{`type`:#["string","null"]},
      `formerIdentifiers`:#{`type`:"array",`items`:#{`type`:"string"}},
      `createdAt`:#{
        `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
      },
      `updatedAt`:#{
        `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
      },
      `lifecycle`:#{`type`:#["string","null"]},
      `kind`:#{`type`:"string"},
      `application`:#{`type`:"string"},
      `serviceAccount`:#{`type`:"boolean"},
      `optOut`:#{`type`:#["string","null"]},
      `optOutApplies`:#{`type`:"boolean"},
      `credentialStanding`:#{`type`:#["string","null"]},
      `credentialChangeRequired`:#{`type`:"boolean"},
      `recoveryActivated`:#{`type`:"boolean"},
      `identifierChanges`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `at`:#{`type`:"string"},
            `from`:#{`type`:"string"},
            `to`:#{`type`:"string"}
          }
        }
      },
      `credentials`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `at`:#{`type`:"string"},
            `credentialType`:#{`type`:"string"},
            `discoveredAt`:#{`type`:"number"}
          }
        }
      },
      `counts`:#{`type`:"object",`additionalProperties`:#{`type`:"number"}},
      `total`:#{`type`:"integer"},
      `suppressed`:#{`type`:"integer"},
      `events`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `jti`:#{`type`:"string"},
            `uri`:#{`type`:"string"},
            `name`:#{`type`:"string"},
            `at`:#{`type`:"string"},
            `streamId`:#{`type`:"string"},
            `warnings`:#{`type`:"array",`items`:#{`type`:"string"}}
          }
        }
      },
      `streams`:#{`type`:"array",`items`:#{`type`:"string"}},
      `notes`:#{`type`:"array",`items`:#{`type`:"string"}},
      `subject`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model Risc_account_h1123 {}

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
      `subject`?: Risc_eventTypes_i_subject_h1074;
      `what`?: string;
      `offered`?: boolean;
      `members`?: ({
        `name`?: string;
        `required`?: Risc_eventTypes_i_members_i_required_h1075;
        `what`?: string;
        `type`?: Risc_eventTypes_i_members_i_type_h1076;
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
      `sub`?: Risc_accounts_i_sub_h1077;
      `username`?: Risc_accounts_i_username_h1078;
      `iss`?: Risc_accounts_i_iss_h1079;
      `dn`?: Risc_accounts_i_dn_h1080;
      `realm`?: Risc_accounts_i_realm_h1081;
      `email`?: Risc_accounts_i_email_h1082;
      `phone`?: Risc_accounts_i_phone_h1083;
      `formerIdentifiers`?: (string)[];
      `createdAt`?: Risc_accounts_i_createdAt_h1085;
      `updatedAt`?: Risc_accounts_i_updatedAt_h1087;
      `lifecycle`?: Risc_accounts_i_lifecycle_h1088;
      `kind`?: string;
      `application`?: string;
      `serviceAccount`?: boolean;
      `optOut`?: Risc_accounts_i_optOut_h1089;
      `optOutApplies`?: boolean;
      `credentialStanding`?: Risc_accounts_i_credentialStanding_h1090;
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
      `name`?: Risc_applications_i_name_h1091;
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
      `lastPushAt`?: Risc_applications_i_lastPushAt_h1093;
      `lastPushError`?: Risc_applications_i_lastPushError_h1094
    })[];
    `streams`?: ({
      `stream_id`?: string;
      `aud`?: Risc_streams_i_aud_h1096;
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
      `subject`?: Risc_catalogue_i_subject_h1097;
      `what`?: string;
      `offered`?: boolean;
      `members`?: ({
        `name`?: string;
        `required`?: Risc_catalogue_i_members_i_required_h1098;
        `what`?: string;
        `type`?: Risc_catalogue_i_members_i_type_h1099;
        `values`?: (string)[]
      })[];
      `required`?: (string)[];
      `subjectFormats`?: (string)[];
      `deprecated`?: string
    })[];
    `settings`?: Risc_settings_h1100;
    `filter`?: {
      `accounts`?: Risc_filter_accounts_h1101;
      `applications`?: Risc_filter_applications_h1102
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
        `sub`?: Risc_shown_accounts_i_sub_h1103;
        `username`?: Risc_shown_accounts_i_username_h1104;
        `iss`?: Risc_shown_accounts_i_iss_h1105;
        `dn`?: Risc_shown_accounts_i_dn_h1106;
        `realm`?: Risc_shown_accounts_i_realm_h1107;
        `email`?: Risc_shown_accounts_i_email_h1108;
        `phone`?: Risc_shown_accounts_i_phone_h1109;
        `formerIdentifiers`?: (string)[];
        `createdAt`?: Risc_shown_accounts_i_createdAt_h1111;
        `updatedAt`?: Risc_shown_accounts_i_updatedAt_h1113;
        `lifecycle`?: Risc_shown_accounts_i_lifecycle_h1114;
        `kind`?: string;
        `application`?: string;
        `serviceAccount`?: boolean;
        `optOut`?: Risc_shown_accounts_i_optOut_h1115;
        `optOutApplies`?: boolean;
        `credentialStanding`?: Risc_shown_accounts_i_credentialStanding_h1116;
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
        `name`?: Risc_shown_applications_i_name_h1117;
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
        `lastPushAt`?: Risc_shown_applications_i_lastPushAt_h1119;
        `lastPushError`?: Risc_shown_applications_i_lastPushError_h1120
      })[];
      `streams`?: ({
        `stream_id`?: string;
        `aud`?: Risc_shown_streams_i_aud_h1122;
        `status`?: string;
        `delivery`?: string;
        `subjects`?: integer;
        `takes`?: (string)[]
      })[]
    };
    `matched`?: {`accounts`?: integer; `applications`?: integer; `streams`?: integer};
    `streamCounts`?: {`total`?: integer; `taking`?: integer};
    `id`?: string;
    `account`?: Risc_account_h1123;
    `events`?: ({
      `jti`?: string;
      `uri`?: string;
      `name`?: string;
      `at`?: string;
      `streamId`?: string;
      `warnings`?: (string)[]
    })[]
  }

@hoisted union Scim_protocolEndpoints_i_methods_h1124 {string, (string)[]}

@js(#{`$types`:#["string","null"]}) @hoisted model Scim_baseUrl_h1125 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `what`:#{`type`:"string"},
      `users`:#{`type`:"string"},
      `groups`:#{`type`:"string"},
      `baseDn`:#{`type`:"string"},
      `userCount`:#{`type`:"number"},
      `groupCount`:#{`type`:"number"},
      `entryCount`:#{`type`:"number"},
      `maxEntries`:#{`type`:"number"}
    },
    `$types`:#["object","null"]
  }) @hoisted model Scim_store_h1126 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `id`:#{`type`:"string"},
      `why`:#{`type`:"string"},
      `example`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model Scim_identifiers_h1127 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `required`:#{`type`:"boolean"},
      `discoveryOpen`:#{`type`:"boolean"},
      `realm`:#{`type`:"string"},
      `scopes`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`read`:#{`type`:"string"},`write`:#{`type`:"string"}}
      },
      `hobaRegistration`:#{`type`:"string"},
      `digestAlgorithms`:#{`type`:"array",`items`:#{`type`:"string"}},
      `schemes`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `id`:#{`type`:"string"},
            `type`:#{`type`:"string"},
            `canonical`:#{`type`:"boolean"},
            `name`:#{`type`:"string"},
            `enabled`:#{`type`:"boolean"},
            `refusedByMode`:#{`type`:"string"},
            `setting`:#{`type`:"string"},
            `primary`:#{`type`:"boolean"},
            `scoped`:#{`type`:"boolean"},
            `applicationScoped`:#{`type`:"boolean"},
            `recorded`:#{`type`:"boolean"},
            `challenged`:#{`type`:"boolean"},
            `spec`:#{`type`:"string"},
            `specUri`:#{`type`:"string"},
            `description`:#{`type`:"string"}
          }
        }
      },
      `policy`:#{`type`:"array",`items`:#{`type`:"string"}}
    },
    `$types`:#["object","null"]
  }) @hoisted model Scim_authentication_h1128 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Scim_mapping_user_i_ldap_h1129 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Scim_mapping_user_i_kind_h1130 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Scim_mapping_user_i_type_h1131 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Scim_mapping_user_i_parent_h1132 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Scim_mapping_group_i_ldap_h1133 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Scim_mapping_group_i_kind_h1134 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Scim_mapping_group_i_type_h1135 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Scim_mapping_group_i_parent_h1136 {}

@hoisted union Scim_counters_firstAt_h1137 {numeric, string, null}

@hoisted union Scim_counters_lastAt_h1138 {numeric, string, null}

@js(#{`$types`:#["string","null"]}) @hoisted model Scim_counters_resourceTypes_i_resourceType_h1139 {}

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
            `settings`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `key`:#{`type`:"string"},
                  `group`:#{`type`:"string"},
                  `label`:#{`type`:"string"},
                  `description`:#{`type`:"string"},
                  `type`:#{`type`:"string"},
                  `enumValues`:#{`type`:"array",`items`:#{`type`:"string"}},
                  `csvValues`:#{`type`:"array",`items`:#{`type`:"string"}},
                  `ordered`:#{`type`:"boolean"},
                  `csvValueNotes`:#{
                    `type`:"object",
                    `additionalProperties`:#{`type`:"string"},
                    `description`:"The sentence beside each value."
                  },
                  `selectAll`:#{
                    `type`:"object",
                    `additionalProperties`:#{
                      `type`:"array",
                      `items`:#{
                        `type`:"object",
                        `additionalProperties`:false,
                        `properties`:#{
                          `setting`:#{`type`:"string"},
                          `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                          `on`:#{`type`:"boolean"},
                          `canBeOn`:#{`type`:"boolean"}
                        }
                      }
                    },
                    `description`:"The rules by kind: onlyWhileOn and aloneWhileOn."
                  },
                  `min`:#{`type`:"number"},
                  `max`:#{`type`:"number"},
                  `step`:#{`type`:"number"},
                  `value`:#{
                    `anyOf`:#[
                      #{`type`:"boolean"},
                      #{`type`:"number"},
                      #{`type`:"string"},
                      #{`type`:"array",`items`:#{`type`:"string"}},
                      #{`type`:"null"}
                    ]
                  },
                  `text`:#{`type`:#["string","null"]},
                  `source`:#{`type`:"string"},
                  `editable`:#{`type`:"boolean"},
                  `restartReason`:#{`type`:"string"},
                  `editRefusal`:#{`type`:"string"},
                  `env`:#{`type`:#["string","null"]},
                  `legacyEnv`:#{`type`:#["string","null"]},
                  `appconfigPath`:#{`type`:"string"},
                  `default`:#{
                    `anyOf`:#[
                      #{`type`:"boolean"},
                      #{`type`:"number"},
                      #{`type`:"string"},
                      #{`type`:"array",`items`:#{`type`:"string"}},
                      #{`type`:"null"}
                    ]
                  },
                  `masked`:#{`type`:"boolean"},
                  `realmSettable`:#{`type`:"boolean"},
                  `overridden`:#{`type`:"boolean"}
                }
              }
            }
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
          `realmId`:#{`type`:#["string","null"]}
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
        `description`:"The other pages, by settings group."
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model Scim_settings_h1140 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `family`:#{`type`:"string"},
      `clients`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `id`:#{`type`:"string"},
            `identifier`:#{`type`:"string"},
            `dn`:#{`type`:"string"},
            `name`:#{`type`:"string"},
            `baseUrl`:#{`type`:"string"},
            `authMethod`:#{`type`:"string"},
            `username`:#{`type`:"string"},
            `tokenEndpoint`:#{`type`:"string"},
            `oauthClientId`:#{`type`:"string"},
            `oauthClientAuth`:#{`type`:"string"},
            `oauthScope`:#{`type`:"string"},
            `oauthResource`:#{`type`:"string"},
            `tlsSource`:#{`type`:"string"},
            `tlsCertificate`:#{`type`:"string"},
            `caCertificates`:#{`type`:"string"},
            `scopeMode`:#{`type`:"string"},
            `scopeFilter`:#{`type`:"string"},
            `groupMode`:#{`type`:"string"},
            `deprovision`:#{`type`:"string"},
            `reconcileMinutes`:#{`type`:"string"},
            `jurisdiction`:#{`type`:"string"},
            `maxRequestsPerSecond`:#{`type`:"string"},
            `scopeGroups`:#{`type`:"array",`items`:#{`type`:"string"}},
            `groups`:#{`type`:"array",`items`:#{`type`:"string"}},
            `cells`:#{`type`:"array",`items`:#{`type`:"string"}},
            `enabled`:#{`type`:"boolean"},
            `passwordSet`:#{`type`:"boolean"},
            `oauthClientSecretSet`:#{`type`:"boolean"},
            `tlsPrivateKeySet`:#{`type`:"boolean"},
            `certificate`:#{
              `type`:#["object","null"],
              `additionalProperties`:false,
              `properties`:#{
                `subject`:#{`type`:"string"},
                `issuer`:#{`type`:"string"},
                `notAfter`:#{`type`:#["string","null"]},
                `serial`:#{`type`:#["string","null"]},
                `error`:#{`type`:"string"}
              }
            },
            `problems`:#{`type`:"array",`items`:#{`type`:"string"}},
            `usable`:#{`type`:"boolean"},
            `counts`:#{
              `type`:"object",
              `additionalProperties`:false,
              `properties`:#{
                `queued`:#{`type`:"number"},
                `retrying`:#{`type`:"number"},
                `dead`:#{`type`:"number"},
                `sent`:#{`type`:"number"}
              }
            },
            `pausedUntil`:#{`type`:"string"},
            `failures`:#{`type`:"number"},
            `lastReconcileAt`:#{`type`:"string"},
            `lastReconcile`:#{
              `type`:#["object","null"],
              `additionalProperties`:false,
              `properties`:#{
                `ok`:#{`type`:"boolean"},
                `users`:#{`type`:"number"},
                `groups`:#{`type`:"number"},
                `deprovisioned`:#{`type`:"number"},
                `why`:#{`type`:"string"},
                `notPushedHere`:#{`type`:"boolean"}
              }
            },
            `byCell`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `cell`:#{`type`:"string"},
                  `here`:#{`type`:"boolean"},
                  `reachable`:#{`type`:"boolean"},
                  `error`:#{`type`:"string"},
                  `withheld`:#{`type`:"string"},
                  `identifier`:#{`type`:"string"},
                  `pushes`:#{`type`:"boolean"},
                  `counts`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `queued`:#{`type`:"number"},
                      `retrying`:#{`type`:"number"},
                      `dead`:#{`type`:"number"},
                      `sent`:#{`type`:"number"}
                    }
                  },
                  `pausedUntil`:#{`type`:"string"},
                  `failures`:#{`type`:"number"},
                  `lastReconcileAt`:#{`type`:"string"},
                  `queued`:#{
                    `type`:"array",
                    `items`:#{
                      `type`:"object",
                      `additionalProperties`:false,
                      `properties`:#{
                        `id`:#{`type`:"string"},
                        `realm`:#{`type`:#["string","null"]},
                        `clientId`:#{`type`:"string"},
                        `uri`:#{`type`:#["string","null"]},
                        `state`:#{`type`:"string"},
                        `generation`:#{`type`:#["number","null"]},
                        `attempts`:#{`type`:#["number","null"]},
                        `inFlight`:#{`type`:"boolean"},
                        `holder`:#{`type`:"string"},
                        `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]},
                        `errorCode`:#{`type`:#["string","null"]},
                        `why`:#{`type`:#["string","null"]},
                        `queuedAt`:#{`type`:"string"},
                        `nextAttemptAt`:#{`type`:"string"},
                        `lastAttemptAt`:#{`type`:"string"},
                        `finishedAt`:#{`type`:"string"},
                        `client`:#{`type`:"string"},
                        `type`:#{`type`:"string"},
                        `uuid`:#{`type`:"string"},
                        `name`:#{`type`:"string"},
                        `pendingChange`:#{`type`:"boolean"}
                      }
                    }
                  },
                  `retrying`:#{
                    `type`:"array",
                    `items`:#{
                      `type`:"object",
                      `additionalProperties`:false,
                      `properties`:#{
                        `id`:#{`type`:"string"},
                        `realm`:#{`type`:#["string","null"]},
                        `clientId`:#{`type`:"string"},
                        `uri`:#{`type`:#["string","null"]},
                        `state`:#{`type`:"string"},
                        `generation`:#{`type`:#["number","null"]},
                        `attempts`:#{`type`:#["number","null"]},
                        `inFlight`:#{`type`:"boolean"},
                        `holder`:#{`type`:"string"},
                        `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]},
                        `errorCode`:#{`type`:#["string","null"]},
                        `why`:#{`type`:#["string","null"]},
                        `queuedAt`:#{`type`:"string"},
                        `nextAttemptAt`:#{`type`:"string"},
                        `lastAttemptAt`:#{`type`:"string"},
                        `finishedAt`:#{`type`:"string"},
                        `client`:#{`type`:"string"},
                        `type`:#{`type`:"string"},
                        `uuid`:#{`type`:"string"},
                        `name`:#{`type`:"string"},
                        `pendingChange`:#{`type`:"boolean"}
                      }
                    }
                  },
                  `dead`:#{
                    `type`:"array",
                    `items`:#{
                      `type`:"object",
                      `additionalProperties`:false,
                      `properties`:#{
                        `id`:#{`type`:"string"},
                        `realm`:#{`type`:#["string","null"]},
                        `clientId`:#{`type`:"string"},
                        `uri`:#{`type`:#["string","null"]},
                        `state`:#{`type`:"string"},
                        `generation`:#{`type`:#["number","null"]},
                        `attempts`:#{`type`:#["number","null"]},
                        `inFlight`:#{`type`:"boolean"},
                        `holder`:#{`type`:"string"},
                        `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]},
                        `errorCode`:#{`type`:#["string","null"]},
                        `why`:#{`type`:#["string","null"]},
                        `queuedAt`:#{`type`:"string"},
                        `nextAttemptAt`:#{`type`:"string"},
                        `lastAttemptAt`:#{`type`:"string"},
                        `finishedAt`:#{`type`:"string"},
                        `client`:#{`type`:"string"},
                        `type`:#{`type`:"string"},
                        `uuid`:#{`type`:"string"},
                        `name`:#{`type`:"string"},
                        `pendingChange`:#{`type`:"boolean"}
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      `choices`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `authMethods`:#{`type`:"array",`items`:#{`type`:"string"}},
          `oauthClientAuth`:#{`type`:"array",`items`:#{`type`:"string"}},
          `tlsSources`:#{`type`:"array",`items`:#{`type`:"string"}},
          `scopeModes`:#{`type`:"array",`items`:#{`type`:"string"}},
          `groupModes`:#{`type`:"array",`items`:#{`type`:"string"}},
          `deprovision`:#{`type`:"array",`items`:#{`type`:"string"}}
        }
      },
      `httpAllowed`:#{`type`:"boolean"},
      `client`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `id`:#{`type`:"string"},
          `identifier`:#{`type`:"string"},
          `dn`:#{`type`:"string"},
          `name`:#{`type`:"string"},
          `baseUrl`:#{`type`:"string"},
          `authMethod`:#{`type`:"string"},
          `username`:#{`type`:"string"},
          `tokenEndpoint`:#{`type`:"string"},
          `oauthClientId`:#{`type`:"string"},
          `oauthClientAuth`:#{`type`:"string"},
          `oauthScope`:#{`type`:"string"},
          `oauthResource`:#{`type`:"string"},
          `tlsSource`:#{`type`:"string"},
          `tlsCertificate`:#{`type`:"string"},
          `caCertificates`:#{`type`:"string"},
          `scopeMode`:#{`type`:"string"},
          `scopeFilter`:#{`type`:"string"},
          `groupMode`:#{`type`:"string"},
          `deprovision`:#{`type`:"string"},
          `reconcileMinutes`:#{`type`:"string"},
          `jurisdiction`:#{`type`:"string"},
          `maxRequestsPerSecond`:#{`type`:"string"},
          `scopeGroups`:#{`type`:"array",`items`:#{`type`:"string"}},
          `groups`:#{`type`:"array",`items`:#{`type`:"string"}},
          `cells`:#{`type`:"array",`items`:#{`type`:"string"}},
          `enabled`:#{`type`:"boolean"},
          `passwordSet`:#{`type`:"boolean"},
          `oauthClientSecretSet`:#{`type`:"boolean"},
          `tlsPrivateKeySet`:#{`type`:"boolean"},
          `certificate`:#{
            `type`:#["object","null"],
            `additionalProperties`:false,
            `properties`:#{
              `subject`:#{`type`:"string"},
              `issuer`:#{`type`:"string"},
              `notAfter`:#{`type`:#["string","null"]},
              `serial`:#{`type`:#["string","null"]},
              `error`:#{`type`:"string"}
            }
          },
          `problems`:#{`type`:"array",`items`:#{`type`:"string"}},
          `usable`:#{`type`:"boolean"},
          `counts`:#{
            `type`:"object",
            `additionalProperties`:false,
            `properties`:#{
              `queued`:#{`type`:"number"},
              `retrying`:#{`type`:"number"},
              `dead`:#{`type`:"number"},
              `sent`:#{`type`:"number"}
            }
          },
          `pausedUntil`:#{`type`:"string"},
          `failures`:#{`type`:"number"},
          `lastReconcileAt`:#{`type`:"string"},
          `lastReconcile`:#{
            `type`:#["object","null"],
            `additionalProperties`:false,
            `properties`:#{
              `ok`:#{`type`:"boolean"},
              `users`:#{`type`:"number"},
              `groups`:#{`type`:"number"},
              `deprovisioned`:#{`type`:"number"},
              `why`:#{`type`:"string"},
              `notPushedHere`:#{`type`:"boolean"}
            }
          },
          `byCell`:#{
            `type`:"array",
            `items`:#{
              `type`:"object",
              `additionalProperties`:false,
              `properties`:#{
                `cell`:#{`type`:"string"},
                `here`:#{`type`:"boolean"},
                `reachable`:#{`type`:"boolean"},
                `error`:#{`type`:"string"},
                `withheld`:#{`type`:"string"},
                `identifier`:#{`type`:"string"},
                `pushes`:#{`type`:"boolean"},
                `counts`:#{
                  `type`:"object",
                  `additionalProperties`:false,
                  `properties`:#{
                    `queued`:#{`type`:"number"},
                    `retrying`:#{`type`:"number"},
                    `dead`:#{`type`:"number"},
                    `sent`:#{`type`:"number"}
                  }
                },
                `pausedUntil`:#{`type`:"string"},
                `failures`:#{`type`:"number"},
                `lastReconcileAt`:#{`type`:"string"},
                `queued`:#{
                  `type`:"array",
                  `items`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `id`:#{`type`:"string"},
                      `realm`:#{`type`:#["string","null"]},
                      `clientId`:#{`type`:"string"},
                      `uri`:#{`type`:#["string","null"]},
                      `state`:#{`type`:"string"},
                      `generation`:#{`type`:#["number","null"]},
                      `attempts`:#{`type`:#["number","null"]},
                      `inFlight`:#{`type`:"boolean"},
                      `holder`:#{`type`:"string"},
                      `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]},
                      `errorCode`:#{`type`:#["string","null"]},
                      `why`:#{`type`:#["string","null"]},
                      `queuedAt`:#{`type`:"string"},
                      `nextAttemptAt`:#{`type`:"string"},
                      `lastAttemptAt`:#{`type`:"string"},
                      `finishedAt`:#{`type`:"string"},
                      `client`:#{`type`:"string"},
                      `type`:#{`type`:"string"},
                      `uuid`:#{`type`:"string"},
                      `name`:#{`type`:"string"},
                      `pendingChange`:#{`type`:"boolean"}
                    }
                  }
                },
                `retrying`:#{
                  `type`:"array",
                  `items`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `id`:#{`type`:"string"},
                      `realm`:#{`type`:#["string","null"]},
                      `clientId`:#{`type`:"string"},
                      `uri`:#{`type`:#["string","null"]},
                      `state`:#{`type`:"string"},
                      `generation`:#{`type`:#["number","null"]},
                      `attempts`:#{`type`:#["number","null"]},
                      `inFlight`:#{`type`:"boolean"},
                      `holder`:#{`type`:"string"},
                      `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]},
                      `errorCode`:#{`type`:#["string","null"]},
                      `why`:#{`type`:#["string","null"]},
                      `queuedAt`:#{`type`:"string"},
                      `nextAttemptAt`:#{`type`:"string"},
                      `lastAttemptAt`:#{`type`:"string"},
                      `finishedAt`:#{`type`:"string"},
                      `client`:#{`type`:"string"},
                      `type`:#{`type`:"string"},
                      `uuid`:#{`type`:"string"},
                      `name`:#{`type`:"string"},
                      `pendingChange`:#{`type`:"boolean"}
                    }
                  }
                },
                `dead`:#{
                  `type`:"array",
                  `items`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `id`:#{`type`:"string"},
                      `realm`:#{`type`:#["string","null"]},
                      `clientId`:#{`type`:"string"},
                      `uri`:#{`type`:#["string","null"]},
                      `state`:#{`type`:"string"},
                      `generation`:#{`type`:#["number","null"]},
                      `attempts`:#{`type`:#["number","null"]},
                      `inFlight`:#{`type`:"boolean"},
                      `holder`:#{`type`:"string"},
                      `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]},
                      `errorCode`:#{`type`:#["string","null"]},
                      `why`:#{`type`:#["string","null"]},
                      `queuedAt`:#{`type`:"string"},
                      `nextAttemptAt`:#{`type`:"string"},
                      `lastAttemptAt`:#{`type`:"string"},
                      `finishedAt`:#{`type`:"string"},
                      `client`:#{`type`:"string"},
                      `type`:#{`type`:"string"},
                      `uuid`:#{`type`:"string"},
                      `name`:#{`type`:"string"},
                      `pendingChange`:#{`type`:"boolean"}
                    }
                  }
                }
              }
            }
          },
          `queues`:#{
            `type`:"object",
            `additionalProperties`:false,
            `properties`:#{
              `queued`:#{
                `type`:"array",
                `items`:#{
                  `type`:"object",
                  `additionalProperties`:false,
                  `properties`:#{
                    `id`:#{`type`:"string"},
                    `realm`:#{`type`:#["string","null"]},
                    `clientId`:#{`type`:"string"},
                    `uri`:#{`type`:#["string","null"]},
                    `state`:#{`type`:"string"},
                    `generation`:#{`type`:#["number","null"]},
                    `attempts`:#{`type`:#["number","null"]},
                    `inFlight`:#{`type`:"boolean"},
                    `holder`:#{`type`:"string"},
                    `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]},
                    `errorCode`:#{`type`:#["string","null"]},
                    `why`:#{`type`:#["string","null"]},
                    `queuedAt`:#{`type`:"string"},
                    `nextAttemptAt`:#{`type`:"string"},
                    `lastAttemptAt`:#{`type`:"string"},
                    `finishedAt`:#{`type`:"string"},
                    `client`:#{`type`:"string"},
                    `type`:#{`type`:"string"},
                    `uuid`:#{`type`:"string"},
                    `name`:#{`type`:"string"},
                    `pendingChange`:#{`type`:"boolean"}
                  }
                }
              },
              `retrying`:#{
                `type`:"array",
                `items`:#{
                  `type`:"object",
                  `additionalProperties`:false,
                  `properties`:#{
                    `id`:#{`type`:"string"},
                    `realm`:#{`type`:#["string","null"]},
                    `clientId`:#{`type`:"string"},
                    `uri`:#{`type`:#["string","null"]},
                    `state`:#{`type`:"string"},
                    `generation`:#{`type`:#["number","null"]},
                    `attempts`:#{`type`:#["number","null"]},
                    `inFlight`:#{`type`:"boolean"},
                    `holder`:#{`type`:"string"},
                    `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]},
                    `errorCode`:#{`type`:#["string","null"]},
                    `why`:#{`type`:#["string","null"]},
                    `queuedAt`:#{`type`:"string"},
                    `nextAttemptAt`:#{`type`:"string"},
                    `lastAttemptAt`:#{`type`:"string"},
                    `finishedAt`:#{`type`:"string"},
                    `client`:#{`type`:"string"},
                    `type`:#{`type`:"string"},
                    `uuid`:#{`type`:"string"},
                    `name`:#{`type`:"string"},
                    `pendingChange`:#{`type`:"boolean"}
                  }
                }
              },
              `dead`:#{
                `type`:"array",
                `items`:#{
                  `type`:"object",
                  `additionalProperties`:false,
                  `properties`:#{
                    `id`:#{`type`:"string"},
                    `realm`:#{`type`:#["string","null"]},
                    `clientId`:#{`type`:"string"},
                    `uri`:#{`type`:#["string","null"]},
                    `state`:#{`type`:"string"},
                    `generation`:#{`type`:#["number","null"]},
                    `attempts`:#{`type`:#["number","null"]},
                    `inFlight`:#{`type`:"boolean"},
                    `holder`:#{`type`:"string"},
                    `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]},
                    `errorCode`:#{`type`:#["string","null"]},
                    `why`:#{`type`:#["string","null"]},
                    `queuedAt`:#{`type`:"string"},
                    `nextAttemptAt`:#{`type`:"string"},
                    `lastAttemptAt`:#{`type`:"string"},
                    `finishedAt`:#{`type`:"string"},
                    `client`:#{`type`:"string"},
                    `type`:#{`type`:"string"},
                    `uuid`:#{`type`:"string"},
                    `name`:#{`type`:"string"},
                    `pendingChange`:#{`type`:"boolean"}
                  }
                }
              },
              `counts`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `queued`:#{`type`:"number"},
                  `retrying`:#{`type`:"number"},
                  `dead`:#{`type`:"number"},
                  `sent`:#{`type`:"number"}
                }
              }
            }
          },
          `linked`:#{`type`:"number"},
          `discovery`:#{
            `type`:#["object","null"],
            `additionalProperties`:false,
            `properties`:#{
              `ok`:#{`type`:"boolean"},
              `patch`:#{`type`:"boolean"},
              `filter`:#{`type`:"boolean"},
              `etag`:#{`type`:"boolean"},
              `endpoints`:#{
                `type`:"object",
                `additionalProperties`:#{`type`:"string"},
                `description`:"The path of each resource type, by its name."
              },
              `why`:#{`type`:"string"},
              `maxResults`:#{`type`:"number"},
              `bulk`:#{`type`:"boolean"},
              `authenticationSchemes`:#{`type`:"array",`items`:#{`type`:"string"}},
              `at`:#{`type`:"string"}
            }
          }
        }
      },
      `missing`:#{`type`:"string"},
      `cellId`:#{`type`:#["string","null"]}
    },
    `$types`:#["object","null"]
  }) @hoisted model Scim_scimClients_h1141 {}

@component model `Scim` {
    `protocolEndpoints`?: ({
      `name`?: string;
      `methods`?: Scim_protocolEndpoints_i_methods_h1124;
      `url`?: string;
      `route`?: string;
      `transport`?: string;
      `registered`?: boolean
    })[];
    `installed`?: boolean;
    `enabled`?: boolean;
    `baseUrl`?: Scim_baseUrl_h1125;
    `specifications`?: (string)[];
    `store`?: Scim_store_h1126;
    `identifiers`?: Scim_identifiers_h1127;
    `authentication`?: Scim_authentication_h1128;
    `endpoints`?: ({`method`?: string; `path`?: string; `what`?: string})[];
    `doesNotDo`?: (string)[];
    `reachableNegatives`?: ({`what`?: string; `answer`?: string})[];
    `mapping`?: {
      `user`?: ({
        `scim`?: string;
        `ldap`?: Scim_mapping_user_i_ldap_h1129;
        `kind`?: Scim_mapping_user_i_kind_h1130;
        `type`?: Scim_mapping_user_i_type_h1131;
        `parent`?: Scim_mapping_user_i_parent_h1132;
        `extension`?: boolean;
        `readOnly`?: boolean;
        `required`?: boolean;
        `schema`?: string;
        `note`?: string
      })[];
      `group`?: ({
        `scim`?: string;
        `ldap`?: Scim_mapping_group_i_ldap_h1133;
        `kind`?: Scim_mapping_group_i_kind_h1134;
        `type`?: Scim_mapping_group_i_type_h1135;
        `parent`?: Scim_mapping_group_i_parent_h1136;
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
      `firstAt`?: Scim_counters_firstAt_h1137;
      `lastAt`?: Scim_counters_lastAt_h1138;
      `operations`?: ({
        `operation`?: string;
        `label`?: string;
        `method`?: string;
        `what`?: string;
        `count`?: numeric
      })[];
      `resourceTypes`?: ({
        `resourceType`?: Scim_counters_resourceTypes_i_resourceType_h1139;
        `count`?: numeric
      })[];
      @js(#{`description`:"A count per name."}) `byStatus`?: Record<numeric>;
      @js(#{`description`:"A count per name."}) `byScimType`?: Record<numeric>;
      @js(#{`description`:"A count per name."}) `byAuthScheme`?: Record<numeric>
    };
    `settings`?: Scim_settings_h1140;
    `scimClients`?: Scim_scimClients_h1141
  }

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `id`:#{`type`:"string"},
      `label`:#{`type`:"string"},
      `audience`:#{`type`:"string"},
      `receivePath`:#{`type`:"string"},
      `inboxPath`:#{`type`:"string"},
      `sees`:#{`type`:"string"},
      `realm`:#{`type`:"string"},
      `enabled`:#{`type`:"boolean"},
      `ssfEnabled`:#{`type`:"boolean"},
      `internalReceivers`:#{`type`:"boolean"},
      `pushDelivery`:#{`type`:"boolean"},
      `caepEnabled`:#{`type`:"boolean"},
      `riscEnabled`:#{`type`:"boolean"},
      `held`:#{`type`:"integer"},
      `max`:#{`type`:"number"},
      `stream`:#{
        `type`:#["object","null"],
        `additionalProperties`:false,
        `properties`:#{
          `stream_id`:#{`type`:"string"},
          `iss`:#{`type`:#["string","null"]},
          `aud`:#{
            `oneOf`:#[
              #{`type`:"null"},
              #{
                `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}]
              }
            ]
          },
          `status`:#{`type`:"string"},
          `statusReason`:#{`type`:#["string","null"]},
          `delivery`:#{`type`:"string"},
          `endpoint_url`:#{`type`:"string"},
          `pollEveryMs`:#{`type`:"number"},
          `delivers`:#{`type`:"integer"},
          `requested`:#{`type`:"integer"},
          `caepDelivered`:#{`type`:"integer"},
          `riscDelivered`:#{`type`:"integer"},
          `queued`:#{`type`:"integer"},
          `counters`:#{`type`:"object",`additionalProperties`:#{`type`:"number"}},
          `lastPushAt`:#{
            `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}]
          },
          `lastPushError`:#{`type`:#["string","null"]}
        }
      },
      `why`:#{`type`:"array",`items`:#{`type`:"string"}}
    },
    `$types`:#["object","null"]
  }) @hoisted model Signals_status_h1142 {}

@hoisted union Signals_received_i_at_v1_h1143 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union Signals_received_i_at_h1144 {null, Signals_received_i_at_v1_h1143}

@js(#{`$types`:#["string","null"]}) @hoisted model Signals_received_i_surface_h1145 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Signals_received_i_stream_h1146 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Signals_received_i_verificationNote_h1147 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Signals_received_i_contentType_h1148 {}

@js(#{`$types`:#["string","null"]}) @hoisted model Signals_filter_received_h1149 {}

@component model `Signals` {
    `status`?: Signals_status_h1142;
    `received`?: ({
      `jti`?: string;
      `at`?: Signals_received_i_at_h1144;
      `tokenDigest`?: string;
      `surface`?: Signals_received_i_surface_h1145;
      `stream`?: Signals_received_i_stream_h1146;
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
      `verificationNote`?: Signals_received_i_verificationNote_h1147;
      `reactions`?: ({
        `event`?: string;
        `reaction`?: string;
        `skipped`?: string;
        `observed`?: boolean;
        `ended`?: integer;
        `revoked`?: integer;
        `failed`?: boolean
      })[];
      `contentType`?: Signals_received_i_contentType_h1148;
      `correctMediaType`?: boolean;
      `problem`?: string
    })[];
    `total`?: integer;
    `filter`?: {`received`?: Signals_filter_received_h1149};
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

@js(#{`$types`:#["number","null"]}) @hoisted model SsfDeadLetters_totals_oldestAgeS_h1150 {}

@js(#{`$types`:#["number","null"]}) @hoisted model SsfDeadLetters_totals_newestAgeS_h1151 {}

@hoisted union SsfDeadLetters_streams_i_aud_v1_h1152 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union SsfDeadLetters_streams_i_aud_h1153 {null, SsfDeadLetters_streams_i_aud_v1_h1152}

@hoisted union SsfDeadLetters_streams_i_lastPushAt_v1_h1154 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union SsfDeadLetters_streams_i_lastPushAt_h1155 {null, SsfDeadLetters_streams_i_lastPushAt_v1_h1154}

@hoisted union SsfDeadLetters_letters_i_queuedAt_v1_h1156 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union SsfDeadLetters_letters_i_queuedAt_h1157 {null, SsfDeadLetters_letters_i_queuedAt_v1_h1156}

@hoisted union SsfDeadLetters_letters_i_deadAt_v1_h1158 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union SsfDeadLetters_letters_i_deadAt_h1159 {null, SsfDeadLetters_letters_i_deadAt_v1_h1158}

@js(#{`$types`:#["number","null"]}) @hoisted model SsfDeadLetters_letters_i_ageS_h1160 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `name`:#{`type`:"string"},
      `types`:#{`type`:"array",`items`:#{`type`:"string"}},
      `subject`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model SsfDeadLetters_letters_i_event_h1161 {}

@hoisted union SsfDeadLetters_process_thread_v1_h1162 {integer, string}

@js(#{`$comb`:"oneOf"}) @hoisted union SsfDeadLetters_process_thread_h1163 {null, SsfDeadLetters_process_thread_v1_h1162}

@js(#{`$types`:#["string","null"]}) @hoisted model SsfDeadLetters_filter_q_h1164 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SsfDeadLetters_filter_stream_h1165 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SsfDeadLetters_filter_cause_h1166 {}

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
      `oldestAgeS`?: SsfDeadLetters_totals_oldestAgeS_h1150;
      `newestAgeS`?: SsfDeadLetters_totals_newestAgeS_h1151;
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
      `aud`?: SsfDeadLetters_streams_i_aud_h1153;
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
      `lastPushAt`?: SsfDeadLetters_streams_i_lastPushAt_h1155
    })[];
    `letters`?: ({
      `stream_id`?: string;
      `jti`?: string;
      `queuedAt`?: SsfDeadLetters_letters_i_queuedAt_h1157;
      `deadAt`?: SsfDeadLetters_letters_i_deadAt_h1159;
      `ageS`?: SsfDeadLetters_letters_i_ageS_h1160;
      `cause`?: string;
      `reason`?: string;
      `errorCode`?: string;
      `status`?: numeric;
      `signed`?: boolean;
      `streamKnown`?: boolean;
      `event`?: SsfDeadLetters_letters_i_event_h1161
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
      `thread`?: SsfDeadLetters_process_thread_h1163;
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
      `q`?: SsfDeadLetters_filter_q_h1164;
      `stream`?: SsfDeadLetters_filter_stream_h1165;
      `cause`?: SsfDeadLetters_filter_cause_h1166
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

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_baseUrl_h1167 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `what`:#{`type`:"string"},
      `users`:#{`type`:"string"},
      `groups`:#{`type`:"string"},
      `baseDn`:#{`type`:"string"},
      `userCount`:#{`type`:"number"},
      `groupCount`:#{`type`:"number"},
      `entryCount`:#{`type`:"number"},
      `maxEntries`:#{`type`:"number"}
    },
    `$types`:#["object","null"]
  }) @hoisted model ScimMonitor_store_h1168 {}

@js(#{`$types`:#["number","null"]}) @hoisted model ScimMonitor_counters_successRate_h1169 {}

@hoisted union ScimMonitor_counters_firstAt_h1170 {numeric, string, null}

@hoisted union ScimMonitor_counters_lastAt_h1171 {numeric, string, null}

@hoisted union ScimMonitor_counters_since_h1172 {numeric, string, null}

@js(#{`$types`:#["number","null"]}) @hoisted model ScimMonitor_counters_latency_averageMs_h1173 {}

@js(#{`$types`:#["number","null"]}) @hoisted model ScimMonitor_counters_operations_i_averageMs_h1174 {}

@js(#{`$types`:#["number","null"]}) @hoisted model ScimMonitor_counters_operations_i_maxMs_h1175 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_counters_resourceTypes_i_resourceType_h1176 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_counters_clients_i_principal_h1177 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_counters_clients_i_kind_h1178 {}

@hoisted union ScimMonitor_counters_clients_i_firstAt_h1179 {numeric, string, null}

@hoisted union ScimMonitor_counters_clients_i_lastAt_h1180 {numeric, string, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_counters_clients_i_lastOperation_h1181 {}

@hoisted union ScimMonitor_counters_clients_i_lastStatus_h1182 {numeric, string, null}

@hoisted union ScimMonitor_counters_recent_i_at_h1183 {numeric, string, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_counters_recent_i_operation_h1184 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_counters_recent_i_resourceType_h1185 {}

@hoisted union ScimMonitor_counters_recent_i_status_h1186 {numeric, string, null}

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_counters_recent_i_scimType_h1187 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_counters_recent_i_scheme_h1188 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_counters_recent_i_principal_h1189 {}

@js(#{`$types`:#["number","null"]}) @hoisted model ScimMonitor_counters_recent_i_ms_h1190 {}

@js(#{`$types`:#["number","null"]}) @hoisted model ScimMonitor_counters_recent_i_bytes_h1191 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_counters_recent_i_method_h1192 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_counters_recent_i_path_h1193 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_counters_realm_id_h1194 {}

@js(#{`$types`:#["string","null"]}) @hoisted model ScimMonitor_counters_realm_name_h1195 {}

@component model `ScimMonitor` {
    `installed`?: boolean;
    `enabled`?: boolean;
    `baseUrl`?: ScimMonitor_baseUrl_h1167;
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
    `store`?: ScimMonitor_store_h1168;
    `counters`?: {
      `calls`?: numeric;
      `ok`?: numeric;
      `failed`?: numeric;
      `successRate`?: ScimMonitor_counters_successRate_h1169;
      `firstAt`?: ScimMonitor_counters_firstAt_h1170;
      `lastAt`?: ScimMonitor_counters_lastAt_h1171;
      `since`?: ScimMonitor_counters_since_h1172;
      `latency`?: {
        `totalMs`?: numeric;
        `averageMs`?: ScimMonitor_counters_latency_averageMs_h1173;
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
        `averageMs`?: ScimMonitor_counters_operations_i_averageMs_h1174;
        `maxMs`?: ScimMonitor_counters_operations_i_maxMs_h1175;
        `bytes`?: numeric
      })[];
      `resourceTypes`?: ({
        `resourceType`?: ScimMonitor_counters_resourceTypes_i_resourceType_h1176;
        `count`?: numeric
      })[];
      @js(#{`description`:"A count per name."}) `byStatus`?: Record<numeric>;
      @js(#{`description`:"A count per name."}) `byStatusClass`?: Record<numeric>;
      @js(#{`description`:"A count per name."}) `byScimType`?: Record<numeric>;
      `clients`?: ({
        `principal`?: ScimMonitor_counters_clients_i_principal_h1177;
        `kind`?: ScimMonitor_counters_clients_i_kind_h1178;
        `calls`?: numeric;
        `ok`?: numeric;
        `failed`?: numeric;
        `schemes`?: (string)[];
        `resourceTypes`?: (string)[];
        `firstAt`?: ScimMonitor_counters_clients_i_firstAt_h1179;
        `lastAt`?: ScimMonitor_counters_clients_i_lastAt_h1180;
        `lastOperation`?: ScimMonitor_counters_clients_i_lastOperation_h1181;
        `lastStatus`?: ScimMonitor_counters_clients_i_lastStatus_h1182
      })[];
      `recent`?: ({
        `at`?: ScimMonitor_counters_recent_i_at_h1183;
        `operation`?: ScimMonitor_counters_recent_i_operation_h1184;
        `resourceType`?: ScimMonitor_counters_recent_i_resourceType_h1185;
        `status`?: ScimMonitor_counters_recent_i_status_h1186;
        `ok`?: boolean;
        `scimType`?: ScimMonitor_counters_recent_i_scimType_h1187;
        `scheme`?: ScimMonitor_counters_recent_i_scheme_h1188;
        `principal`?: ScimMonitor_counters_recent_i_principal_h1189;
        `ms`?: ScimMonitor_counters_recent_i_ms_h1190;
        `bytes`?: ScimMonitor_counters_recent_i_bytes_h1191;
        `method`?: ScimMonitor_counters_recent_i_method_h1192;
        `path`?: ScimMonitor_counters_recent_i_path_h1193
      })[];
      `recentCap`?: numeric;
      `realm`?: {
        `id`?: ScimMonitor_counters_realm_id_h1194;
        `name`?: ScimMonitor_counters_realm_name_h1195
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

@js(#{`description`:"One configured pair.",`additionalProperties`:true}) @hoisted model DelegationPolicy_pairs_i_h1196 {
    `mechanism`?: "classic" | "rbcd";
    @js(#{
      `description`:"The same mechanism id an ACT carries, so the two halves of this resource can be read against each other without a second lookup table."
    }) `type`?: string;
    @js(#{`description`:"Who may act."}) `frontEnd`?: string;
    @js(#{`description`:"What may be reached."}) `target`?: string;
    `realm`?: string;
    @js(#{
      `description`:"`msDS-AllowedToDelegateTo` or `msDS-AllowedToActOnBehalfOfOtherIdentity`."
    }) `attribute`?: string;
    @js(#{
      `description`:"THE ACCOUNT THE PERMISSION LIVES ON, and the field to read first. Classic puts it on the front end, where only a domain admin can set it; resource-based puts it on the back end, where whoever controls that object can set it themselves. That is the entire security story of RBCD."
    }) `setOn`?: string;
    `setOnRole`?: "front end" | "back end";
    @js(#{`description`:"What ELSE the mechanism needs beyond the attribute."}) `requires`?: string;
    @js(#{
      `description`:"Whether this KDC has a principal by that name. A misspelt SPN fails at TGS time with an error about authorization rather than spelling."
    }) `targetKnown`?: boolean;
    @js(#{
      `description`:"Why this pair may still fail although the attribute names it. The expensive one: a front end with no TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION gets a non-forwardable ticket out of S4U2Self, so classic S4U2Proxy then fails complaining about the evidence — two steps from the attribute that caused it."
    }) `warning`?: string;
    `note`?: string
  }

@js(#{`description`:"One account.",`additionalProperties`:true}) @hoisted model DelegationPolicy_accounts_i_h1197 {
    `principal`?: string;
    `realm`?: string;
    `notDelegated`?: boolean;
    `trustedToAuthenticateForDelegation`?: boolean;
    @js(#{
      `description`:"ADVICE TO THE CLIENT and not a control: it tells a client this service may be trusted with forwarded credentials, a client is free to ignore it, and this KDC enforces nothing by it."
    }) `okAsDelegate`?: boolean;
    `autoCreated`?: boolean;
    `description`?: string;
    @js(#{`description`:"What each flag actually does."}) `effects`?: (string)[]
  }

@js(#{
    `description`:"WHO MAY DELEGATE TO WHOM, before anybody has tried. KERBEROS ONLY, and that is not an omission: Kerberos is the only family here that polices delegation at all. WS-Trust puts no authorization on OnBehalfOf or ActAs, and RFC 8693 leaves the policy to the authorization server, which this one does not have.",
    `additionalProperties`:true
  }) @component model `DelegationPolicy` {
    @js(#{
      `description`:"One per (front end, target, mechanism). The two mechanisms are in ONE list because the messages and the KDC options are identical and the whole difference is which of the two accounts carries the permission — which is `setOn`."
    }) `pairs`?: (DelegationPolicy_pairs_i_h1196)[];
    @js(#{
      `description`:"Principals carrying a flag that changes what delegation can do to them or with them. Two of the three STOP delegation rather than permit it, and one is not a control at all. Listed whether or not a pair names them."
    }) `accounts`?: (DelegationPolicy_accounts_i_h1197)[]
  }

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_filter_type_h1198 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_filter_mode_h1199 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_filter_outcome_h1200 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_filter_protocol_h1201 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_filter_q_h1202 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_acts_i_at_h1203 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_chains_i_firstAt_h1204 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_chains_i_lastAt_h1205 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_applications_i_firstAt_h1206 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_applications_i_lastAt_h1207 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_realm_name_h1208 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_graph_nodes_i_firstAt_h1209 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_graph_nodes_i_lastAt_h1210 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_nodes_i_realm_name_h1211 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_edges_i_protocol_h1212 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_edges_i_type_h1213 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_edges_i_typeLabel_h1214 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_edges_i_spec_h1215 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_edges_i_subject_h1216 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_edges_i_actor_h1217 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_graph_edges_i_firstAt_h1218 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_graph_edges_i_lastAt_h1219 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_graph_edges_i_authentications_i_at_h1220 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_graph_edges_i_authentications_i_lastAt_h1221 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_edges_i_baseUri_h1222 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_edges_i_description_h1223 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_graph_tokens_i_at_h1224 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_tokens_i_subject_h1225 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_tokens_i_actor_h1226 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_tokens_i_target_h1227 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_graph_credentials_i_at_h1228 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_credentials_i_flowLabel_h1229 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_credentials_i_flowProtocol_h1230 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_credentials_i_flowSpec_h1231 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_credentials_i_flowOidc_h1232 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_graph_credentials_i_state_h1233 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_graph_credentials_i_expiresAtMs_h1234 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_resources_i_baseUri_h1235 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_resources_i_permissions_i_name_h1236 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_resources_i_permissions_i_description_h1237 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_resources_i_permissions_i_id_h1238 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_resources_i_permissions_i_raw_h1239 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_permissions_i_baseUri_h1240 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_permissions_i_name_h1241 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_permissions_i_description_h1242 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_permissions_i_id_h1243 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_permissions_i_raw_h1244 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_grants_i_baseUri_h1245 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_grants_i_permissionName_h1246 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_grants_i_description_h1247 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_realm_name_h1248 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_allowed_graph_nodes_i_firstAt_h1249 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_allowed_graph_nodes_i_lastAt_h1250 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_nodes_i_realm_name_h1251 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_edges_i_protocol_h1252 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_edges_i_type_h1253 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_edges_i_typeLabel_h1254 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_edges_i_spec_h1255 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_edges_i_subject_h1256 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_edges_i_actor_h1257 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_allowed_graph_edges_i_firstAt_h1258 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_allowed_graph_edges_i_lastAt_h1259 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_allowed_graph_edges_i_authentications_i_at_h1260 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_allowed_graph_edges_i_authentications_i_lastAt_h1261 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_edges_i_baseUri_h1262 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_edges_i_description_h1263 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_allowed_graph_tokens_i_at_h1264 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_tokens_i_subject_h1265 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_tokens_i_actor_h1266 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_tokens_i_target_h1267 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_allowed_graph_credentials_i_at_h1268 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_credentials_i_flowLabel_h1269 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_credentials_i_flowProtocol_h1270 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_credentials_i_flowSpec_h1271 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_credentials_i_flowOidc_h1272 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_graph_credentials_i_state_h1273 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_allowed_graph_credentials_i_expiresAtMs_h1274 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_filter_permissions_h1275 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_filter_grants_h1276 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_paging_permissions_param_h1277 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_paging_permissions_noun_h1278 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_paging_grants_param_h1279 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_allowed_paging_grants_noun_h1280 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_delegationPolicy_pairs_i_targetApplication_h1281 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_delegationPolicy_pairsPaging_param_h1282 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_delegationPolicy_pairsPaging_noun_h1283 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_delegationPolicy_intermediariesPaging_param_h1284 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_delegationPolicy_intermediariesPaging_noun_h1285 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_delegationPolicy_peoplePaging_param_h1286 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_delegationPolicy_peoplePaging_noun_h1287 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_paging_param_h1288 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_paging_noun_h1289 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_chainPage_shown_i_firstAt_h1290 {}

@js(#{`$types`:#["number","null"]}) @hoisted model DelegationList_chainPage_shown_i_lastAt_h1291 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_chainPage_paging_param_h1292 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_chainPage_paging_noun_h1293 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_pairPage_paging_param_h1294 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_pairPage_paging_noun_h1295 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_flagPage_paging_param_h1296 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_flagPage_paging_noun_h1297 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_mechanismPage_paging_param_h1298 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_mechanismPage_paging_noun_h1299 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_applicationChooser_entries_i_names_i_h1300 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_userChooser_entries_i_names_i_h1301 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_register_resources_i_baseUri_h1302 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_register_resources_i_permissions_i_name_h1303 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_register_resources_i_permissions_i_description_h1304 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_register_resources_i_permissions_i_id_h1305 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_register_resources_i_permissions_i_raw_h1306 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_register_permissions_i_baseUri_h1307 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_register_permissions_i_name_h1308 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_register_permissions_i_description_h1309 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_register_permissions_i_id_h1310 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_register_permissions_i_raw_h1311 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_register_grants_i_baseUri_h1312 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_register_grants_i_permissionName_h1313 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_register_grants_i_description_h1314 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_listState_permPage_shown_i_baseUri_h1315 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_listState_permPage_shown_i_name_h1316 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_listState_permPage_shown_i_description_h1317 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_listState_permPage_shown_i_id_h1318 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_listState_permPage_shown_i_raw_h1319 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_listState_permPage_paging_param_h1320 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_listState_permPage_paging_noun_h1321 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_listState_grantPage_shown_i_baseUri_h1322 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_listState_grantPage_shown_i_permissionName_h1323 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_listState_grantPage_shown_i_description_h1324 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_listState_grantPage_paging_param_h1325 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_permissionsView_listState_grantPage_paging_noun_h1326 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_exchangePolicyView_register_pairs_i_targetApplication_h1327 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_exchangePolicyView_pairs_shown_i_targetApplication_h1328 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_exchangePolicyView_pairs_paging_param_h1329 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_exchangePolicyView_pairs_paging_noun_h1330 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_exchangePolicyView_intermediaries_paging_param_h1331 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_exchangePolicyView_intermediaries_paging_noun_h1332 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_exchangePolicyView_people_paging_param_h1333 {}

@js(#{`$types`:#["string","null"]}) @hoisted model DelegationList_exchangePolicyView_people_paging_noun_h1334 {}

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
      `type`?: DelegationList_filter_type_h1198;
      `mode`?: DelegationList_filter_mode_h1199;
      `outcome`?: DelegationList_filter_outcome_h1200;
      `protocol`?: DelegationList_filter_protocol_h1201;
      `q`?: DelegationList_filter_q_h1202
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
      `at`?: DelegationList_acts_i_at_h1203;
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
      `firstAt`?: DelegationList_chains_i_firstAt_h1204;
      `lastAt`?: DelegationList_chains_i_lastAt_h1205;
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
      `firstAt`?: DelegationList_applications_i_firstAt_h1206;
      `lastAt`?: DelegationList_applications_i_lastAt_h1207;
      `identityKey`?: string;
      `chains`?: integer
    })[];
    `graph`?: {
      `realm`?: {
        `id`?: string;
        `name`?: DelegationList_graph_realm_name_h1208;
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
        `firstAt`?: DelegationList_graph_nodes_i_firstAt_h1209;
        `lastAt`?: DelegationList_graph_nodes_i_lastAt_h1210;
        `selfTarget`?: boolean;
        `chiefRole`?: string;
        `realm`?: {
          `id`?: string;
          `name`?: DelegationList_graph_nodes_i_realm_name_h1211;
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
        `protocol`?: DelegationList_graph_edges_i_protocol_h1212;
        `protocols`?: (string)[];
        `type`?: DelegationList_graph_edges_i_type_h1213;
        `typeLabel`?: DelegationList_graph_edges_i_typeLabel_h1214;
        `mode`?: string;
        `spec`?: DelegationList_graph_edges_i_spec_h1215;
        `policed`?: boolean;
        `subject`?: DelegationList_graph_edges_i_subject_h1216;
        `actor`?: DelegationList_graph_edges_i_actor_h1217;
        `acts`?: integer;
        `issued`?: integer;
        `refused`?: integer;
        `credentials`?: integer;
        `firstAt`?: DelegationList_graph_edges_i_firstAt_h1218;
        `lastAt`?: DelegationList_graph_edges_i_lastAt_h1219;
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
          `at`?: DelegationList_graph_edges_i_authentications_i_at_h1220;
          `lastAt`?: DelegationList_graph_edges_i_authentications_i_lastAt_h1221
        })[];
        `audience`?: string;
        `audienceRegistered`?: boolean;
        `permissions`?: (string)[];
        `scopes`?: (string)[];
        `permissionId`?: string;
        `permissionName`?: string;
        `baseUri`?: DelegationList_graph_edges_i_baseUri_h1222;
        `description`?: DelegationList_graph_edges_i_description_h1223;
        `asked`?: boolean
      })[];
      `tokens`?: ({
        `seq`?: numeric;
        `at`?: DelegationList_graph_tokens_i_at_h1224;
        `kind`?: string;
        `identifier`?: string;
        `note`?: string;
        `protocol`?: string;
        `type`?: string;
        `typeLabel`?: string;
        `mode`?: string;
        `chainKey`?: string;
        `subject`?: DelegationList_graph_tokens_i_subject_h1225;
        `actor`?: DelegationList_graph_tokens_i_actor_h1226;
        `target`?: DelegationList_graph_tokens_i_target_h1227
      })[];
      `tokensLeftOff`?: integer;
      `maxTokenRows`?: integer;
      `acts`?: integer;
      `chains`?: integer;
      `credentials`?: ({
        `at`?: DelegationList_graph_credentials_i_at_h1228;
        `family`?: string;
        `kind`?: string;
        `identifier`?: string;
        `flow`?: string;
        `flowLabel`?: DelegationList_graph_credentials_i_flowLabel_h1229;
        `flowProtocol`?: DelegationList_graph_credentials_i_flowProtocol_h1230;
        `flowSpec`?: DelegationList_graph_credentials_i_flowSpec_h1231;
        `flowOidc`?: DelegationList_graph_credentials_i_flowOidc_h1232;
        `flowStated`?: boolean;
        `holder`?: string;
        `audience`?: string;
        `scope`?: string;
        `issuer`?: string;
        `state`?: DelegationList_graph_credentials_i_state_h1233;
        `sessionId`?: string;
        `revocable`?: boolean;
        `revoked`?: boolean;
        `detail`?: string;
        `expiresAtMs`?: DelegationList_graph_credentials_i_expiresAtMs_h1234
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
        `baseUri`?: DelegationList_allowed_resources_i_baseUri_h1235;
        `rawBaseUri`?: string;
        `permissions`?: ({
          `name`?: DelegationList_allowed_resources_i_permissions_i_name_h1236;
          `description`?: DelegationList_allowed_resources_i_permissions_i_description_h1237;
          `id`?: DelegationList_allowed_resources_i_permissions_i_id_h1238;
          `raw`?: DelegationList_allowed_resources_i_permissions_i_raw_h1239;
          `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
        })[];
        `grantsHeld`?: integer
      })[];
      `permissions`?: ({
        `resource`?: string;
        `resourceName`?: string;
        `baseUri`?: DelegationList_allowed_permissions_i_baseUri_h1240;
        `name`?: DelegationList_allowed_permissions_i_name_h1241;
        `description`?: DelegationList_allowed_permissions_i_description_h1242;
        `id`?: DelegationList_allowed_permissions_i_id_h1243;
        `raw`?: DelegationList_allowed_permissions_i_raw_h1244;
        `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
      })[];
      `grants`?: ({
        `client`?: string;
        `clientName`?: string;
        `permissionId`?: string;
        `resource`?: string;
        `resourceName`?: string;
        `baseUri`?: DelegationList_allowed_grants_i_baseUri_h1245;
        `permissionName`?: DelegationList_allowed_grants_i_permissionName_h1246;
        `description`?: DelegationList_allowed_grants_i_description_h1247;
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
          `name`?: DelegationList_allowed_graph_realm_name_h1248;
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
          `firstAt`?: DelegationList_allowed_graph_nodes_i_firstAt_h1249;
          `lastAt`?: DelegationList_allowed_graph_nodes_i_lastAt_h1250;
          `selfTarget`?: boolean;
          `chiefRole`?: string;
          `realm`?: {
            `id`?: string;
            `name`?: DelegationList_allowed_graph_nodes_i_realm_name_h1251;
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
          `protocol`?: DelegationList_allowed_graph_edges_i_protocol_h1252;
          `protocols`?: (string)[];
          `type`?: DelegationList_allowed_graph_edges_i_type_h1253;
          `typeLabel`?: DelegationList_allowed_graph_edges_i_typeLabel_h1254;
          `mode`?: string;
          `spec`?: DelegationList_allowed_graph_edges_i_spec_h1255;
          `policed`?: boolean;
          `subject`?: DelegationList_allowed_graph_edges_i_subject_h1256;
          `actor`?: DelegationList_allowed_graph_edges_i_actor_h1257;
          `acts`?: integer;
          `issued`?: integer;
          `refused`?: integer;
          `credentials`?: integer;
          `firstAt`?: DelegationList_allowed_graph_edges_i_firstAt_h1258;
          `lastAt`?: DelegationList_allowed_graph_edges_i_lastAt_h1259;
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
            `at`?: DelegationList_allowed_graph_edges_i_authentications_i_at_h1260;
            `lastAt`?: DelegationList_allowed_graph_edges_i_authentications_i_lastAt_h1261
          })[];
          `audience`?: string;
          `audienceRegistered`?: boolean;
          `permissions`?: (string)[];
          `scopes`?: (string)[];
          `permissionId`?: string;
          `permissionName`?: string;
          `baseUri`?: DelegationList_allowed_graph_edges_i_baseUri_h1262;
          `description`?: DelegationList_allowed_graph_edges_i_description_h1263;
          `asked`?: boolean
        })[];
        `tokens`?: ({
          `seq`?: numeric;
          `at`?: DelegationList_allowed_graph_tokens_i_at_h1264;
          `kind`?: string;
          `identifier`?: string;
          `note`?: string;
          `protocol`?: string;
          `type`?: string;
          `typeLabel`?: string;
          `mode`?: string;
          `chainKey`?: string;
          `subject`?: DelegationList_allowed_graph_tokens_i_subject_h1265;
          `actor`?: DelegationList_allowed_graph_tokens_i_actor_h1266;
          `target`?: DelegationList_allowed_graph_tokens_i_target_h1267
        })[];
        `tokensLeftOff`?: integer;
        `maxTokenRows`?: integer;
        `acts`?: integer;
        `chains`?: integer;
        `credentials`?: ({
          `at`?: DelegationList_allowed_graph_credentials_i_at_h1268;
          `family`?: string;
          `kind`?: string;
          `identifier`?: string;
          `flow`?: string;
          `flowLabel`?: DelegationList_allowed_graph_credentials_i_flowLabel_h1269;
          `flowProtocol`?: DelegationList_allowed_graph_credentials_i_flowProtocol_h1270;
          `flowSpec`?: DelegationList_allowed_graph_credentials_i_flowSpec_h1271;
          `flowOidc`?: DelegationList_allowed_graph_credentials_i_flowOidc_h1272;
          `flowStated`?: boolean;
          `holder`?: string;
          `audience`?: string;
          `scope`?: string;
          `issuer`?: string;
          `state`?: DelegationList_allowed_graph_credentials_i_state_h1273;
          `sessionId`?: string;
          `revocable`?: boolean;
          `revoked`?: boolean;
          `detail`?: string;
          `expiresAtMs`?: DelegationList_allowed_graph_credentials_i_expiresAtMs_h1274
        })[];
        `credentialsOnDelegationLines`?: integer;
        `subject`?: string;
        `counts`?: {`nodes`?: integer; `edges`?: integer; `grants`?: integer}
      };
      `filter`?: {
        `permissions`?: DelegationList_allowed_filter_permissions_h1275;
        `grants`?: DelegationList_allowed_filter_grants_h1276
      };
      `paging`?: {
        `permissions`?: {
          `page`?: integer;
          `pages`?: integer;
          `perPage`?: integer;
          `firstRow`?: integer;
          `lastRow`?: integer;
          `total`?: integer;
          `param`?: DelegationList_allowed_paging_permissions_param_h1277;
          `noun`?: DelegationList_allowed_paging_permissions_noun_h1278
        };
        `grants`?: {
          `page`?: integer;
          `pages`?: integer;
          `perPage`?: integer;
          `firstRow`?: integer;
          `lastRow`?: integer;
          `total`?: integer;
          `param`?: DelegationList_allowed_paging_grants_param_h1279;
          `noun`?: DelegationList_allowed_paging_grants_noun_h1280
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
        `targetApplication`?: DelegationList_delegationPolicy_pairs_i_targetApplication_h1281;
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
        `param`?: DelegationList_delegationPolicy_pairsPaging_param_h1282;
        `noun`?: DelegationList_delegationPolicy_pairsPaging_noun_h1283
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
        `param`?: DelegationList_delegationPolicy_intermediariesPaging_param_h1284;
        `noun`?: DelegationList_delegationPolicy_intermediariesPaging_noun_h1285
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
        `param`?: DelegationList_delegationPolicy_peoplePaging_param_h1286;
        `noun`?: DelegationList_delegationPolicy_peoplePaging_noun_h1287
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
      `param`?: DelegationList_paging_param_h1288;
      `noun`?: DelegationList_paging_noun_h1289
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
        `firstAt`?: DelegationList_chainPage_shown_i_firstAt_h1290;
        `lastAt`?: DelegationList_chainPage_shown_i_lastAt_h1291;
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
        `param`?: DelegationList_chainPage_paging_param_h1292;
        `noun`?: DelegationList_chainPage_paging_noun_h1293
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
        `param`?: DelegationList_pairPage_paging_param_h1294;
        `noun`?: DelegationList_pairPage_paging_noun_h1295
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
        `param`?: DelegationList_flagPage_paging_param_h1296;
        `noun`?: DelegationList_flagPage_paging_noun_h1297
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
        `param`?: DelegationList_mechanismPage_paging_param_h1298;
        `noun`?: DelegationList_mechanismPage_paging_noun_h1299
      }
    };
    `applicationChooser`?: {
      `total`?: integer;
      `entries`?: ({
        `key`?: string;
        `names`?: (DelegationList_applicationChooser_entries_i_names_i_h1300)[];
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
        `names`?: (DelegationList_userChooser_entries_i_names_i_h1301)[];
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
          `baseUri`?: DelegationList_permissionsView_register_resources_i_baseUri_h1302;
          `rawBaseUri`?: string;
          `permissions`?: ({
            `name`?: DelegationList_permissionsView_register_resources_i_permissions_i_name_h1303;
            `description`?: DelegationList_permissionsView_register_resources_i_permissions_i_description_h1304;
            `id`?: DelegationList_permissionsView_register_resources_i_permissions_i_id_h1305;
            `raw`?: DelegationList_permissionsView_register_resources_i_permissions_i_raw_h1306;
            `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
          })[];
          `grantsHeld`?: integer
        })[];
        `permissions`?: ({
          `resource`?: string;
          `resourceName`?: string;
          `baseUri`?: DelegationList_permissionsView_register_permissions_i_baseUri_h1307;
          `name`?: DelegationList_permissionsView_register_permissions_i_name_h1308;
          `description`?: DelegationList_permissionsView_register_permissions_i_description_h1309;
          `id`?: DelegationList_permissionsView_register_permissions_i_id_h1310;
          `raw`?: DelegationList_permissionsView_register_permissions_i_raw_h1311;
          `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
        })[];
        `grants`?: ({
          `client`?: string;
          `clientName`?: string;
          `permissionId`?: string;
          `resource`?: string;
          `resourceName`?: string;
          `baseUri`?: DelegationList_permissionsView_register_grants_i_baseUri_h1312;
          `permissionName`?: DelegationList_permissionsView_register_grants_i_permissionName_h1313;
          `description`?: DelegationList_permissionsView_register_grants_i_description_h1314;
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
            `baseUri`?: DelegationList_permissionsView_listState_permPage_shown_i_baseUri_h1315;
            `name`?: DelegationList_permissionsView_listState_permPage_shown_i_name_h1316;
            `description`?: DelegationList_permissionsView_listState_permPage_shown_i_description_h1317;
            `id`?: DelegationList_permissionsView_listState_permPage_shown_i_id_h1318;
            `raw`?: DelegationList_permissionsView_listState_permPage_shown_i_raw_h1319;
            `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
          })[];
          `paging`?: {
            `page`?: integer;
            `pages`?: integer;
            `perPage`?: integer;
            `firstRow`?: integer;
            `lastRow`?: integer;
            `total`?: integer;
            `param`?: DelegationList_permissionsView_listState_permPage_paging_param_h1320;
            `noun`?: DelegationList_permissionsView_listState_permPage_paging_noun_h1321
          }
        };
        `grantPage`?: {
          `shown`?: ({
            `client`?: string;
            `clientName`?: string;
            `permissionId`?: string;
            `resource`?: string;
            `resourceName`?: string;
            `baseUri`?: DelegationList_permissionsView_listState_grantPage_shown_i_baseUri_h1322;
            `permissionName`?: DelegationList_permissionsView_listState_grantPage_shown_i_permissionName_h1323;
            `description`?: DelegationList_permissionsView_listState_grantPage_shown_i_description_h1324;
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
            `param`?: DelegationList_permissionsView_listState_grantPage_paging_param_h1325;
            `noun`?: DelegationList_permissionsView_listState_grantPage_paging_noun_h1326
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
          `targetApplication`?: DelegationList_exchangePolicyView_register_pairs_i_targetApplication_h1327;
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
          `targetApplication`?: DelegationList_exchangePolicyView_pairs_shown_i_targetApplication_h1328;
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
          `param`?: DelegationList_exchangePolicyView_pairs_paging_param_h1329;
          `noun`?: DelegationList_exchangePolicyView_pairs_paging_noun_h1330
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
          `param`?: DelegationList_exchangePolicyView_intermediaries_paging_param_h1331;
          `noun`?: DelegationList_exchangePolicyView_intermediaries_paging_noun_h1332
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
          `param`?: DelegationList_exchangePolicyView_people_paging_param_h1333;
          `noun`?: DelegationList_exchangePolicyView_people_paging_noun_h1334
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

@js(#{`$types`:#["string","null"]}) @hoisted model AuditList_filter_category_h1335 {}

@js(#{`$types`:#["string","null"]}) @hoisted model AuditList_filter_action_h1336 {}

@js(#{`$types`:#["string","null"]}) @hoisted model AuditList_filter_outcome_h1337 {}

@js(#{`$types`:#["string","null"]}) @hoisted model AuditList_filter_actor_h1338 {}

@js(#{`$types`:#["string","null"]}) @hoisted model AuditList_filter_q_h1339 {}

@js(#{`$types`:#["string","null"]}) @hoisted model AuditList_filter_code_h1340 {}

@js(#{`$types`:#["string","null"]}) @hoisted model AuditList_filter_address_h1341 {}

@js(#{`$types`:#["string","null"]}) @hoisted model AuditList_events_i_origin_h1342 {}

@js(#{`$types`:#["string","null"]}) @hoisted model AuditList_events_i_errorCode_h1343 {}

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
            `settings`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `key`:#{
                    `type`:"string",
                    `description`:"The dot path, which is BOTH the name every operation here takes and the path in the appconfig file. `oid4vci.batchSize` is `appconfig.oid4vci.batchSize`."
                  },
                  `group`:#{
                    `type`:"string",
                    `description`:"The protocol it belongs to, and the console's section heading."
                  },
                  `label`:#{`type`:"string"},
                  `description`:#{
                    `type`:"string",
                    `description`:"What it does and why the default is the default."
                  },
                  `type`:#{
                    `type`:"string",
                    `description`:"How a value posted for it is coerced and checked: one of `config.js`'s types (string, int, port, bool, csv, enum, color)."
                  },
                  `enumValues`:#{
                    `type`:"array",
                    `items`:#{`type`:"string"},
                    `description`:"Present on `enum` settings only."
                  },
                  `csvValues`:#{
                    `type`:"array",
                    `items`:#{`type`:"string"},
                    `description`:"Present on a `csv` setting whose entries must each be one of these; absent on an open list."
                  },
                  `masked`:#{
                    `type`:"boolean",
                    `description`:"Present, true, when a sensitive value here was replaced."
                  },
                  `ordered`:#{
                    `type`:"boolean",
                    `description`:"Present, true, on a `csv` setting whose order is a preference: the first value is the most preferred."
                  },
                  `csvValueNotes`:#{
                    `type`:"object",
                    `additionalProperties`:#{`type`:"string"},
                    `description`:"Present beside `csvValues` where the setting describes each value: the value mapped to one sentence."
                  },
                  `selectAll`:#{
                    `type`:"object",
                    `additionalProperties`:false,
                    `properties`:#{
                      `onlyWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      },
                      `aloneWhileOn`:#{
                        `type`:"array",
                        `items`:#{
                          `type`:"object",
                          `additionalProperties`:false,
                          `properties`:#{
                            `setting`:#{`type`:"string"},
                            `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                            `on`:#{`type`:"boolean"},
                            `canBeOn`:#{`type`:"boolean"}
                          }
                        }
                      }
                    },
                    `description`:"Present on an `ordered` setting whose select-all is narrowed by other settings. `onlyWhileOn`: the values are selected only while that setting is on. `aloneWhileOn`: while that setting is on, only the values are selected. `canBeOn` is false where this mode never lets that setting be on."
                  },
                  `min`:#{
                    `type`:"number",
                    `description`:"The lowest value POST /config/set will take, on an int setting that declares one."
                  },
                  `max`:#{`type`:"number",`description`:"The highest value it will take."},
                  `step`:#{
                    `type`:"number",
                    `description`:"The value must be a MULTIPLE of this, counted from `min`. The four token lifetimes use 30."
                  },
                  `value`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"},#{`type`:"boolean"}]}
                      }
                    ],
                    `description`:"The effective value, coerced to its type: a number for int/port, a boolean for bool, an array of strings for csv."
                  },
                  `text`:#{
                    `type`:"string",
                    `description`:"The same value on one line: what the console shows in its input and what the environment variable would carry."
                  },
                  `source`:#{
                    `type`:"string",
                    `enum`:#["realm","override","env","env-legacy","appconfig","defaults","default"],
                    `description`:"Where the effective value came from, highest first: this trust realm's own value; a runtime override set through this API or the console; the setting's own environment variable; a legacy variable (no row has one since #523); the appconfig file CONFIG_FILE names; `env/defaults.js`, the DEFAULT appconfig file that one is unioned on top of. `default` is reachable only for the DERIVED settings, whose value is a function of a neighbouring setting: for every other setting, no value anywhere stops this service from STARTING."
                  },
                  `editable`:#{
                    `type`:"boolean",
                    `description`:"Whether POST /config/set will take it from the realm this answer was read in. False means either the value was consumed at startup or `editRefusal` is set. It is refused rather than accepted, because an accepted change that does nothing reads as having worked."
                  },
                  `restartReason`:#{
                    `type`:"string",
                    `description`:"Why it is not editable, when the value was consumed at startup."
                  },
                  `editRefusal`:#{
                    `type`:"string",
                    `description`:"Why this row cannot be edited from the realm the reader is in: `realms.maxCount` while a realm other than the default is ambient. Absent on every row of the default realm's answer."
                  },
                  `env`:#{`type`:"string",`description`:"Its environment variable."},
                  `appconfigPath`:#{`type`:"string"},
                  `default`:#{
                    `anyOf`:#[
                      #{`type`:"string"},
                      #{`type`:"number"},
                      #{`type`:"boolean"},
                      #{`type`:"null"},
                      #{
                        `type`:"array",
                        `items`:#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"},#{`type`:"boolean"}]}
                      }
                    ],
                    `description`:"The built-in default: the `dflt` column of `config.js`'s table, which `env/defaults.js` is GENERATED from. It is what the value WOULD be with nothing set anywhere."
                  },
                  `realmSettable`:#{
                    `type`:"boolean",
                    `description`:"Whether a trust realm may hold its own value for it."
                  },
                  `overridden`:#{
                    `type`:"boolean",
                    `description`:"Whether a runtime override is in force. Equal to `source === \"override\"`, and reported separately so a caller can filter without matching a string."
                  }
                },
                `description`:"One setting: what it is, what it is set to, and where that came from."
              }
            }
          },
          `description`:"One group's settings."
        },
        `description`:"In the order `config.js` declares them."
      },
      `settingCount`:#{`type`:"integer"},
      `editableCount`:#{
        `type`:"integer",
        `description`:"How many of them can be changed while the service runs."
      },
      `overridden`:#{
        `type`:"array",
        `items`:#{`type`:"string"},
        `description`:"The keys on this page with a runtime override in force."
      },
      `setWith`:#{`type`:"string",`description`:"The operation that writes them."},
      `context`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `configFile`:#{`type`:#["string","null"]},
          `defaultsFile`:#{`type`:"string"},
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
            `properties`:#{`path`:#{`type`:"string"},`label`:#{`type`:#["string","null"]}}
          }
        },
        `description`:"A group drawn on another page as well, and those pages."
      }
    },
    `description`:"The settings this page draws, described: the same rows GET /config returns, filtered to the ones this page owns.",
    `$types`:#["object","null"]
  }) @hoisted model AuditList_settings_h1344 {}

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
      `category`?: AuditList_filter_category_h1335;
      `action`?: AuditList_filter_action_h1336;
      `outcome`?: AuditList_filter_outcome_h1337;
      `actor`?: AuditList_filter_actor_h1338;
      `q`?: AuditList_filter_q_h1339;
      `code`?: AuditList_filter_code_h1340;
      `address`?: AuditList_filter_address_h1341
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
      `origin`?: AuditList_events_i_origin_h1342;
      `at`?: numeric;
      `category`?: string;
      `action`?: string;
      `outcome`?: string;
      `errorCode`?: AuditList_events_i_errorCode_h1343;
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
    `settings`?: AuditList_settings_h1344;
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

@js(#{`description`:"A translated message by its key."}) @hoisted model SharedModel9_catalogs_ap_h1345 is Record<string>;
  

@component model `SharedModel9` {
    `negotiated`?: `SharedModel10`;
    `offered`?: ({`tag`?: string; `name`?: string})[];
    @js(#{`description`:"Each catalog along the chain, by language tag."}) `catalogs`?: Record<SharedModel9_catalogs_ap_h1345>;
    @js(#{`description`:"Each static catalog, by language tag."}) `catalogFiles`?: Record<string>
  }

@component model `SharedModel11` {`ok`: boolean; `errors`?: (string)[]; `locale`?: `SharedModel9`}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel13_sublabel_h1346 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel13_identifier_h1347 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel13_href_h1348 {}

@component model `SharedModel13` {
    `shape`?: string;
    `label`?: string;
    `sublabel`?: SharedModel13_sublabel_h1346;
    `identifier`?: SharedModel13_identifier_h1347;
    `title`?: string;
    `href`?: SharedModel13_href_h1348;
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
  

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel29_param_h1350 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel29_noun_h1351 {}

@component model `SharedModel29` {
    `page`?: integer;
    `pages`?: integer;
    `perPage`?: integer;
    `firstRow`?: integer;
    `lastRow`?: integer;
    `total`?: integer;
    `param`?: SharedModel29_param_h1350;
    `noun`?: SharedModel29_noun_h1351
  }

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel31_id_h1352 {}

@component model `SharedModel31` {
    `resource`?: string;
    `resourceName`?: string;
    `baseUri`?: string;
    `name`?: string;
    `description`?: string;
    `id`?: SharedModel31_id_h1352;
    `raw`?: string;
    `grantedTo`?: ({`identifier`?: string; `name`?: string; `asked`?: boolean})[]
  }

@component model `SharedModel30` is (`SharedModel31`)[];
  

@component model `SharedModel33` {`key`?: string; `members`?: (string)[]; `counts`?: `SharedModel26`}

@component model `SharedModel32` is (`SharedModel33`)[];
  

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel36_state_h1353 {}

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
    `state`?: SharedModel36_state_h1353;
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

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel41_id_h1354 {}

@component model `SharedModel41` {
    `name`?: string;
    `description`?: string;
    `id`?: SharedModel41_id_h1354;
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

@js(#{
    `items`:#{`type`:#["string","number","boolean"]},
    `$types`:#["string","number","boolean","array","null"]
  }) @hoisted model SharedModel48_value_h1355 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel48_text_h1356 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel48_restartReason_h1357 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel48_editRefusal_h1358 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel48_env_h1359 {}

@hoisted union SharedModel48_legacyEnv_v1_h1360 {string, (string)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union SharedModel48_legacyEnv_h1361 {null, SharedModel48_legacyEnv_v1_h1360}

@js(#{
    `items`:#{`type`:#["string","number","boolean"]},
    `$types`:#["string","number","boolean","array","null"]
  }) @hoisted model SharedModel48_default_h1362 {}

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
    `value`?: SharedModel48_value_h1355;
    `text`?: SharedModel48_text_h1356;
    `source`?: string;
    `editable`?: boolean;
    `restartReason`?: SharedModel48_restartReason_h1357;
    `editRefusal`?: SharedModel48_editRefusal_h1358;
    `env`?: SharedModel48_env_h1359;
    `legacyEnv`?: SharedModel48_legacyEnv_h1361;
    `appconfigPath`?: string;
    `default`?: SharedModel48_default_h1362;
    `masked`?: boolean;
    `realmSettable`?: boolean;
    `overridden`?: boolean
  }

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel51_origin_h1363 {}

@component model `SharedModel51` {
    `seq`?: numeric;
    `origin`?: SharedModel51_origin_h1363;
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
  

@js(#{`$types`:#["number","null"]}) @hoisted model SharedModel55_pathLen_h1364 {}

@component model `SharedModel55` {
    `id`?: string;
    `label`?: string;
    `ca`?: boolean;
    `selfSigned`?: boolean;
    `years`?: numeric;
    `keyUsage`?: (string)[];
    `extKeyUsage`?: (string)[];
    `pathLen`?: SharedModel55_pathLen_h1364;
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
  

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_profile_h1365 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_profileLabel_h1366 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_issuerSubject_h1367 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_issuerId_h1368 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_serialHex_h1369 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_keyAlgLabel_h1370 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_signatureAlg_h1371 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_signatureAlgLabel_h1372 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_pqMode_h1373 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_altKeyAlg_h1374 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_notBefore_h1375 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_notAfter_h1376 {}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_thumbprint_h1377 {}

@hoisted union SharedModel60_createdAt_v1_h1378 {string, numeric}

@js(#{`$comb`:"oneOf"}) @hoisted union SharedModel60_createdAt_h1379 {null, SharedModel60_createdAt_v1_h1378}

@js(#{`$types`:#["string","null"]}) @hoisted model SharedModel60_certificatePem_h1380 {}

@component model `SharedModel60` {
    `id`?: string;
    `ca`?: boolean;
    `profile`?: SharedModel60_profile_h1365;
    `profileLabel`?: SharedModel60_profileLabel_h1366;
    `subject`?: string;
    `issuerSubject`?: SharedModel60_issuerSubject_h1367;
    `issuerId`?: SharedModel60_issuerId_h1368;
    `selfSigned`?: boolean;
    `serialHex`?: SharedModel60_serialHex_h1369;
    `keyAlg`?: string;
    `keyAlgLabel`?: SharedModel60_keyAlgLabel_h1370;
    `signatureAlg`?: SharedModel60_signatureAlg_h1371;
    `signatureAlgLabel`?: SharedModel60_signatureAlgLabel_h1372;
    `pqMode`?: SharedModel60_pqMode_h1373;
    `altKeyAlg`?: SharedModel60_altKeyAlg_h1374;
    `altSigned`?: boolean;
    `notBefore`?: SharedModel60_notBefore_h1375;
    `notAfter`?: SharedModel60_notAfter_h1376;
    `expired`?: boolean;
    `thumbprint`?: SharedModel60_thumbprint_h1377;
    `createdAt`?: SharedModel60_createdAt_h1379;
    `hasPrivateKey`?: boolean;
    `hasCsr`?: boolean;
    `certificatePem`?: SharedModel60_certificatePem_h1380;
    `csrPem`?: string
  }

@component model `SharedModel59` is (`SharedModel60`)[];
  

@js(#{`$types`:#["string","boolean","number","null"]}) @hoisted model SharedModel53_draft_ap_h1381 {}

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
    @js(#{`description`:"The certificate form, by field name."}) `draft`?: Record<SharedModel53_draft_ap_h1381>
  }

@js(#{`$types`:#["string","boolean","number","null"]}) @hoisted model SharedModel52_draft_ap_h1382 {}

@component model `SharedModel52` {
    `ok`: boolean;
    `errors`?: (string)[];
    `why`?: string;
    @js(#{`description`:"The certificate form, by field name."}) `draft`?: Record<SharedModel52_draft_ap_h1382>;
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

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_api_explorer_r200_application_json_audience_h1383 {}

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
    `audience`?: get_admin_api_console_api_explorer_r200_application_json_audience_h1383;
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

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_r200_application_json_wsTrustIssuer_h1385 {}

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

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `since`:#{`type`:"number"},
      `sinceIso`:#{`type`:"string"},
      `inProgress`:#{`type`:"boolean"},
      `interrupted`:#{`type`:"boolean"},
      `finishesBy`:#{`type`:"number"},
      `refusing`:#{`type`:"string"},
      `why`:#{`type`:"string"},
      `finish`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_admin_api_console_r200_application_json_retiring_h1387 {}

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
    `wsTrustIssuer`?: get_admin_api_console_r200_application_json_wsTrustIssuer_h1385;
    `realms`?: get_admin_api_console_r200_application_json_realms_h1386;
    `realmRoot`?: string;
    `portalHref`?: string;
    `sections`?: `SharedModel2`;
    @js(#{`description`:"Every console page's label, by its path."}) `navLabels`?: Record<string>;
    `retiring`?: get_admin_api_console_r200_application_json_retiring_h1387;
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
  

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_map_r200_application_json_drawing_failed_h1388 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_map_r200_application_json_filter_type_h1389 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_map_r200_application_json_filter_mode_h1390 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_map_r200_application_json_filter_outcome_h1391 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_map_r200_application_json_filter_protocol_h1392 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_map_r200_application_json_filter_q_h1393 {}

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
  `responses/200/content/image~1svg+xml/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `drawing`?: {
      `width`?: numeric;
      `height`?: numeric;
      `failed`?: get_admin_api_console_delegation_map_r200_application_json_drawing_failed_h1388
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
      `type`?: get_admin_api_console_delegation_map_r200_application_json_filter_type_h1389;
      `mode`?: get_admin_api_console_delegation_map_r200_application_json_filter_mode_h1390;
      `outcome`?: get_admin_api_console_delegation_map_r200_application_json_filter_outcome_h1391;
      `protocol`?: get_admin_api_console_delegation_map_r200_application_json_filter_protocol_h1392;
      `q`?: get_admin_api_console_delegation_map_r200_application_json_filter_q_h1393
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
  

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_federation_map_r200_application_json_drawing_failed_h1394 {}

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
      `failed`?: get_admin_api_console_federation_map_r200_application_json_drawing_failed_h1394
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
  

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_cluster_r200_application_json_drawing_failed_h1395 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_cluster_r200_application_json_application_h1396 {}

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
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getDelegationCluster`(`parameters/0/schema`: string,
  `parameters/1/schema`: "json" | "svg",
  @js(#{`minimum`:1}) `parameters/2/schema`: integer,
  @js(#{`minimum`:1,`maximum`:300}) `parameters/3/schema`: integer,
  `responses/200/content/image~1svg+xml/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `drawing`?: {
      `width`?: numeric;
      `height`?: numeric;
      `failed`?: get_admin_api_console_delegation_cluster_r200_application_json_drawing_failed_h1395
    };
    `looks`?: `SharedModel12`;
    `label`?: string;
    `svg`?: string;
    `application`?: get_admin_api_console_delegation_cluster_r200_application_json_application_h1396;
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
  

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_allowed_r200_application_json_drawing_failed_h1399 {}

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
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getDelegationAllowed`(@js(#{`minimum`:1}) `parameters/0/schema`: integer,
  @js(#{`minimum`:1,`maximum`:300}) `parameters/1/schema`: integer,
  `parameters/2/schema`: "json" | "svg",
  `responses/200/content/image~1svg+xml/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `drawing`?: {
      `width`?: numeric;
      `height`?: numeric;
      `failed`?: get_admin_api_console_delegation_allowed_r200_application_json_drawing_failed_h1399
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
  

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_settings_r200_application_json_allowed_filter_permissions_h1400 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_settings_r200_application_json_allowed_filter_grants_h1401 {}

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
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getDelegationSettings`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  @js(#{`minimum`:1}) `parameters/2/schema`: integer,
  @js(#{`minimum`:1,`maximum`:300}) `parameters/3/schema`: integer,
  `responses/200/content/application~1json/schema`: {
    `allowed`?: {
      `resources`?: `SharedModel38`;
      `permissions`?: `SharedModel30`;
      `grants`?: `SharedModel27`;
      `counts`?: `SharedModel42`;
      `filter`?: {
        `permissions`?: get_admin_api_console_delegation_settings_r200_application_json_allowed_filter_permissions_h1400;
        `grants`?: get_admin_api_console_delegation_settings_r200_application_json_allowed_filter_grants_h1401
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
  

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_chain_r200_application_json_drawing_failed_h1403 {}

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
      `failed`?: get_admin_api_console_delegation_chain_r200_application_json_drawing_failed_h1403
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
  

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_dashboard_r200_application_json_issuer_h1405 {}

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
    `issuer`?: get_admin_api_console_dashboard_r200_application_json_issuer_h1405;
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
  

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_applications_new_r200_application_json_container_h1406 {}

@js(#{`$types`:#["number","null"]}) @hoisted model get_admin_api_console_applications_new_r200_application_json_max_h1407 {}

@js(#{`$types`:#["string","boolean","null"]}) @hoisted model get_admin_api_console_applications_new_r200_application_json_declarations_i_editable_h1408 {}

@js(#{`$types`:#["string","boolean","null"]}) @hoisted model get_admin_api_console_applications_new_r200_application_json_fields_i_editable_h1409 {}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","null"]}) @hoisted model get_admin_api_console_applications_new_r200_application_json_fields_i_choices_h1410 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_applications_new_r200_application_json_fields_i_example_h1411 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_applications_new_r200_application_json_persistence_mode_h1412 {}

@js(#{`$types`:#["string","boolean","null"]}) @hoisted model get_admin_api_console_applications_new_r200_application_json_editable_i_mode_h1413 {}

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
    `container`?: get_admin_api_console_applications_new_r200_application_json_container_h1406;
    `max`?: get_admin_api_console_applications_new_r200_application_json_max_h1407;
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
      `editable`?: get_admin_api_console_applications_new_r200_application_json_declarations_i_editable_h1408;
      `sensitive`?: boolean;
      `what`?: string;
      `families`?: ({`id`?: string; `label`?: string})[];
      `everyFamily`?: boolean
    })[];
    `fields`?: ({
      `attribute`?: string;
      `type`?: string;
      `long`?: boolean;
      `editable`?: get_admin_api_console_applications_new_r200_application_json_fields_i_editable_h1409;
      `sensitive`?: boolean;
      `overrides`?: string;
      `choices`?: get_admin_api_console_applications_new_r200_application_json_fields_i_choices_h1410;
      `example`?: get_admin_api_console_applications_new_r200_application_json_fields_i_example_h1411;
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
      `mode`?: get_admin_api_console_applications_new_r200_application_json_persistence_mode_h1412
    };
    `resourceMetadataImport`?: {
      `wellKnown`?: string;
      `acceptsNonconforming`?: boolean;
      `dialsInternalAddresses`?: boolean
    };
    `editable`?: ({
      `name`?: string;
      `mode`?: get_admin_api_console_applications_new_r200_application_json_editable_i_mode_h1413;
      `sensitive`?: boolean;
      `families`?: (string)[]
    })[]
  },
  `responses/default/content/application~1json/schema`: `SharedModel1`): void;
  

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_user_r200_application_json_drawing_failed_h1414 {}

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

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_user_r200_application_json_asked_h1416 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `credentials`:#{`type`:"integer"},
      `acts`:#{`type`:"integer"},
      `chains`:#{`type`:"integer"},
      `authentications`:#{`type`:"integer"},
      `applications`:#{`type`:"integer"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_admin_api_console_delegation_user_r200_application_json_counts_h1417 {}

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
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getConsoleDelegationUser`(`parameters/0/schema`: string,
  `parameters/1/schema`: "json" | "svg",
  `responses/200/content/image~1svg+xml/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `drawing`?: {
      `width`?: numeric;
      `height`?: numeric;
      `failed`?: get_admin_api_console_delegation_user_r200_application_json_drawing_failed_h1414
    };
    `looks`?: `SharedModel12`;
    `label`?: string;
    `svg`?: string;
    `user`?: get_admin_api_console_delegation_user_r200_application_json_user_h1415;
    `asked`?: get_admin_api_console_delegation_user_r200_application_json_asked_h1416;
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
    `counts`?: get_admin_api_console_delegation_user_r200_application_json_counts_h1417;
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
  

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_application_r200_application_json_drawing_failed_h1418 {}

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

@js(#{`$types`:#["string","null"]}) @hoisted model get_admin_api_console_delegation_application_r200_application_json_asked_h1420 {}

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
      }
    ],
    `security`:#[#{`oauth2`:#["admin:console"]},#{`bearerAuth`:#[]}]
  })
op `getConsoleDelegationApplication`(`parameters/0/schema`: string,
  `parameters/1/schema`: "json" | "svg",
  `responses/200/content/image~1svg+xml/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `drawing`?: {
      `width`?: numeric;
      `height`?: numeric;
      `failed`?: get_admin_api_console_delegation_application_r200_application_json_drawing_failed_h1418
    };
    `looks`?: `SharedModel12`;
    `label`?: string;
    `svg`?: string;
    `application`?: get_admin_api_console_delegation_application_r200_application_json_application_h1419;
    `asked`?: get_admin_api_console_delegation_application_r200_application_json_asked_h1420;
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
      `drawnOn`?: (string)[]
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
