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
    #{`name`:"PKI",`description`:""},
    #{`name`:"Delegation",`description`:""},
    #{`name`:"Federation",`description`:""},
    #{`name`:"Applications",`description`:""}
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
              `device:compliance`:"Report device compliance through POST /admin-api/device-compliance, and nothing else — the scope an MDM or posture feed holds (#164). Issued only to a client that declares it.",
              `xacml:pep-audit`:"Push a remote PEP's decision records through POST /admin-api/pep-audit, and nothing else. Issued to the PEP's own RFC 7523 self-assertion through sts-remote-pep, only while its entry is in the remote PEPs' group (REMOTE_PEPS)."
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

@js(#{`description`:"Where each box of the federation picture links, by node id: an application to the applications register, a partner to its first relationship, this service nowhere."}) @component model `FederationBoxLinks` is Record<{@js(#{`description`:"The console page the box links to."}) `href`?: string}>;
  

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
    `consumed`?: `WithOkMessageErrors63`;
    `produced`?: `WithOkMessageErrors63`;
    `attribute`?: string;
    `mechanism`?: string;
    `setOn`?: string;
    `used`?: boolean;
    `consumedFold`?: `WithIdFromTo2`;
    `producedFold`?: `WithIdFromTo2`;
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
  

@component model `WithKeyMembersCounts2` {`key`?: string; `members`?: (string)[]; `counts`?: `WithApplicationsGrantsLines2`}

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
    `counts`?: `WithApplicationsGrantsLines2`
  }

@component model `WithClustersDescriptionMemberOf` is (`WithKeyMembersGrants`)[];
  

@component model `WithClustersDescriptionMemberOf2` {
    `clusters`?: `WithClustersDescriptionMemberOf`;
    @js(#{`description`:"Each application, to its group's key."}) `memberOf`?: Record<string>;
    `counts`?: WithClustersApplicationsLargestEtc5
  }

@component model `WithShownPagingShown` {`shown`?: `WithPagePagesPerPage4`; `paging`?: `WithPagePagesPerPage2`}

@component model `WithShownPagingOnlyWhileOn` {`shown`?: `WithKeyMembersCounts`; `paging`?: `WithPagePagesPerPage2`}

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
    `selectAll`?: `WithOnlyWhileOnAloneWhileOnKey`;
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
  

@component model `WithIdLabelFamily` is ({
    `id`?: string;
    `label`?: string;
    `family`?: string;
    `kind`?: string;
    `signs`?: boolean;
    `slow`?: boolean;
    `tlsUsable`?: boolean
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
    `pqModes`?: `WithIdLabelClassical2`;
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
    `issuers`?: `WithIdLabelSubject`;
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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

@js(#{`description`:"One certificate of the text handed in, as it reads."})
@component model `InspectedCertificate` {
    @js(#{`description`:"The PEM block, as it was found in the text."}) `pem`: string;
    `subject`: string;
    `issuer`: string;
    @js(#{`description`:"The serial number, lower-case hex."}) `serialHex`: string;
    `notBefore`: string;
    `notAfter`: string;
    @js(#{`description`:"Whether basicConstraints says it is a CA."}) `ca`: boolean;
    `selfIssued`: boolean;
    @js(#{`description`:"The SHA-256 of the DER in the colon form `openssl x509 -fingerprint -sha256` prints."}) `fingerprint256`: string;
    @js(#{`description`:"The SHA-256 of the DER, lower-case hex: what `certificate-sha256` binds and `tls.trustedProxyCertificates` pins."}) `sha256`: string;
    @js(#{`description`:"The SHA-256 of its SubjectPublicKeyInfo, lower-case hex: what a certificate sign-in profile's `issuers` names a CA by, and what `spki-sha256` binds. Empty where the key could not be read."}) `spkiSha256`: string;
    @js(#{`description`:"Its subjectKeyIdentifier, lower-case hex, or empty."}) `ski`: string;
    `keyUsage`: (string)[];
    `extendedKeyUsage`: (string)[];
    @js(#{`description`:"Its `urn:uuid:` subjectAltNames: a FIPS 201 card UUID."}) `cardUuids`: (string)[]
  }

@js(#{`description`:"The certificate that issued the first one, or null where none of the others handed in and no client trust anchor verifies its signature."})
@component model `InspectedIssuer` {
    `subject`: string;
    `spkiSha256`: string;
    @js(#{`description`:"`bundle` (handed in) or `truststore` (a client trust anchor)."}) `from`: "bundle" | "truststore"
  }

@component model `InspectedCertificates` {
    `ok`: boolean;
    `errors`?: (string)[];
    `certificates`?: (`InspectedCertificate`)[];
    `issuer`?: `InspectedIssuer` | null;
    @js(#{`description`:"With `bindings: true`, the values of `stsCertificateBinding` the first certificate is found by: `spki-sha256`, and `issuer-serial` and `issuer-ski` where its issuer was found. Empty otherwise."}) `bindings`?: ({
      `method`: "spki-sha256" | "issuer-serial" | "issuer-ski";
      `value`: string
    })[]
  }

@endpoint("/admin-api/console/certificates/inspect",
  "post",
  #{
    `operationId`:"inspectCertificates",
    `summary`:"Read the certificates in a PEM text, for certificate sign-in's editors",
    `description`:"A form helper that writes and keeps nothing (#2080). Answers, for each PEM certificate in `pem`, its subject, issuer, serial, validity, SHA-256 and the SHA-256 of its SubjectPublicKeyInfo — what a certificate sign-in profile's `issuers` (`certSignIn.profiles`) names a CA by — so the console's editors for that setting, `piv.externalIssuers`, `piv.attestationAnchors` and a person's `stsCertificateBinding` show what a certificate is and never compute a digest in the browser. With `bindings: true` it also answers the `stsCertificateBinding` values the FIRST certificate is found by — `spki-sha256`, and `issuer-serial` and `issuer-ski` from its issuer, the first of the other certificates or the client truststore's anchors whose key verifies its signature — in the grammar the directory stores. What the editors lead to is a management operation: `POST /admin-api/config/set` for a setting, `POST /admin-api/users/add-attribute` for a binding.\n\nAt most 262144 characters and 64 certificates; a text with none, or a block that is not a certificate, is refused (400, STS-ADMIN-0953, STS-ADMIN-0954).\n\n**Mirrors** `GET /admin/piv` on the admin console.",
    `tags`:#["PKI"],
    `responses`:#{
      `200`:#{
        `description`:"Each certificate as it reads, the first one's issuer and its binding values.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The text was refused; `errors` says why.",
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
op `inspectCertificates`(@js(#{
    `examples`:#[#{`pem`:"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",`bindings`:true}]
  }) `requestBody/content/application~1json/schema`: {
    @js(#{
      `maxLength`:262144,
      `description`:"One or more PEM certificates; text around them is ignored. The first is the one `bindings` asks about, and the others are the candidates for its issuer."
    }) `pem`: string;
    @js(#{`description`:"Also answer the first certificate's `stsCertificateBinding` values."}) `bindings`?: boolean
  },
  `responses/200/content/application~1json/schema`: `InspectedCertificates`,
  `responses/400/content/application~1json/schema`: `InspectedCertificates`,
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

@endpoint("/admin-api/console/delegation/map",
  "get",
  #{
    `operationId`:"getDelegationMap",
    `summary`:"The delegation picture: the graph, each box, the drawing",
    `description`:"The same acts as `GET /admin-api/delegation`, with the time taken out and the parties shared: a party that is the intermediary of six chains is ONE node with six edges. Drawn from everything that MATCHED the filter, not from one page of it.\n\n`nodes` and `edges` are the graph. `looks` says what each node IS, by node id: its label, its shape, the identifier a protocol would present for it, and the console page it links to — which the directory and the application registry decide. `svg` is the drawing, with its links in it; `drawing` is its size, says so if the layout failed, and says whether this realm verifies what is presented (`verifiesCredentials`). The console lays the picture out in the browser from `nodes`, `edges`, `looks` and `drawing`, with the code that draws `svg` here. `summary` carries the counts by mechanism, kind and outcome that the filter's choices show.\n\nWith `format=svg` the answer is the SVG document alone, with no links in it, as `image/svg+xml`.\n\n**Mirrors** `GET /admin/delegation/map` on the admin console.",
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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

@endpoint("/admin-api/console/federation/map",
  "get",
  #{
    `operationId`:"getFederationMap",
    `summary`:"This realm's federation relationships, drawn",
    `description`:"Every federation relationship of the trust realm, filtered by `role`, `protocol` and text, as a graph — the partners, this service and the applications behind each relationship — with the relationships and their sign-ins, where each box links (`looks`), the drawing (`svg`, with its links) and its size, the filter's vocabulary and the key. The console lays the picture out in the browser from `nodes`, `edges`, `relationships`, `looks` and `drawing.verifiesCredentials`, with the code that draws `svg` here.\n\nWith `format=svg` the answer is the SVG document alone, with no links in it, as `image/svg+xml`.\n\n**Mirrors** `GET /admin/federation/map` on the admin console.",
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
      `relationships`?: (string)[];
      @js(#{`description`:"This service's box: the trust realm's id."}) `realm`?: string;
      @js(#{`description`:"This service's box: the trust realm's name."}) `realmName`?: string;
      @js(#{`description`:"A foreign service provider's box: the application this service knows it as."}) `application`?: string;
      @js(#{`description`:"A partner's box: its own name for itself."}) `peer`?: string
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
    `looks`?: `FederationBoxLinks`;
    `label`?: string;
    `svg`?: string;
    `roles`?: (WithRoleLabelShortEtc4)[];
    `protocols`?: (WithProtocolLabelFamilyEtc7)[];
    `mapKey`?: string
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `key`:#{`type`:"string"},
      `members`:#{`type`:"array",`items`:#{`type`:"string"}},
      `counts`:#{`$ref`:"#/components/schemas/WithApplicationsGrantsLines2"}
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
      `counts`:#{`$ref`:"#/components/schemas/WithApplicationsGrantsLines2"}
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
    `grantsPaging`?: `WithPagePagesPerPage2`;
    `permissions`?: `WithKeyMembersCounts`;
    `permissionsPaging`?: `WithPagePagesPerPage2`;
    `groups`?: `WithAtFamilyKind2`;
    `counts`?: WithClustersApplicationsLargestEtc5;
    `paging`?: `WithPagePagesPerPage2`;
    `asked`?: string;
    `graph`?: `WithRealmIssuerNodes4`;
    `cluster`?: get_admin_api_console_delegation_cluster_r200_application_json_cluster_h1398;
    `register`?: `WithResourcesPermissionsGrants`;
    `clusters`?: `WithClustersDescriptionMemberOf2`;
    `grantPage`?: `WithShownPagingShown`;
    `permissionPage`?: `WithShownPagingOnlyWhileOn`;
    `groupPage`?: {`shown`?: `WithClustersDescriptionMemberOf`; `paging`?: `WithPagePagesPerPage2`};
    `facts`?: `WithDescriptionUsersDescription`;
    @js(#{`description`:"Each name in the answer the registry holds."}) `apps`?: Record<{`name`?: string; `dnLabel`?: string}>
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
    `groupsPaging`?: `WithPagePagesPerPage2`;
    `register`?: `WithResourcesPermissionsGrants`;
    `clusters`?: `WithClustersDescriptionMemberOf2`;
    `shownGroups`?: `WithClustersDescriptionMemberOf`;
    `facts`?: `WithDescriptionUsersDescription`;
    @js(#{`description`:"Each name in the answer the registry holds."}) `apps`?: Record<{`name`?: string; `dnLabel`?: string}>
  },
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
      `paging`?: {`permissions`?: `WithPagePagesPerPage2`; `grants`?: `WithPagePagesPerPage2`}
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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
    `description`:"One chain — (mechanism, initial identity, intermediary, target) — named by its `chain` key, as `GET /admin-api/delegation` lists them in `chains`. The answer is the chain, every act on it (not paged), the graph of those acts and, as for `/delegation/map`, `looks`, the drawing (`svg`, with its links) and its size.\n\n**A KEY NO ACT IS HELD UNDER IS NOT AN ERROR**: the store is capped and drops the oldest, so the answer is `found: false` with `maxRecords`.\n\nWith `format=svg` the answer is the SVG document alone, with no links in it, as `image/svg+xml`.\n\n**Mirrors** `GET /admin/delegation/chain` on the admin console.",
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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
    `createFields`?: (`CreateFormField`)[];
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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  

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
  `responses/default/content/application~1json/schema`: `RefusalFailure`): void;
  
}
