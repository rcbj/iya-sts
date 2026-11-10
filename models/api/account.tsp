// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/api/account.tsp
//
// Written by hand (#1390). THE ACCOUNT API OPENAPI DOCUMENT'S SOURCE:
// `models/tools/generate.mjs` compiles it during the image build, the service
// serves the result and holds every answer to it.
//
// The reasoning below sat beside the code this replaced.
//
//
//
// ---------------------------------------------------------------------------
// WHAT `/account-api` ANSWERS, PER OPERATION AND STATUS (#1353), keyed by
// operationId. `common/response_model_kit.ts` says how a model is written;
// `tests/openapi_response_models.js` fails on an operation with none.
//
// THE ORDER IS `account_api.ts`'s `PROVIDERS`, so that a reader of one provider
// finds its models together, with its own views above them.
//
// **A POST ANSWERS IN `account-api/CLAUDE.md`'s MEMBERS** (*What an answer
// is*): `message`, `view`, `go`, `errors` with `ok: false`, `stepUp`,
// `location`, `files`. `act()` below is that shape, with the view each
// operation draws.
//
// **EVERY REFUSAL THAT CARRIES MORE THAN `{ ok, errors }` IS NAMED, STATUS BY
// STATUS.** `ctx.refuse(res, status, code, errors, extra)` answers
// `{ ok: false, errors, ...extra }`, and a status with no model takes `ERROR`,
// which has no `view`. So an operation whose refusal draws a page lists every
// status that refusal goes out on, and `answers()` keeps a 400 that has no
// extras from inheriting the 200's model (`Kit.applyModels` would otherwise).
// ---------------------------------------------------------------------------
// A number where the source does not promise a whole one: a time read back out
// of a store, a duration out of a setting.
// A value a store hands back as it was written: an ISO instant in one register,
// milliseconds in another. `Date.now()` and `toISOString()` both occur.
// A refusal, from the gate or from a handler.
// ---------------------------------------------------------------------------
// WHAT MORE THAN ONE PROVIDER'S VIEW NAMES.
// ---------------------------------------------------------------------------
// `{ page, pages, per, total }`, this API's own paging; `shared` leaves `per`
// out.
// `AdminViews.pagingJson()`, which GNAP's list shares with the console.
// `i18n.offered()`.
// `Negotiated` in `common/i18n.ts`.
// `AccountApi.localeData()`.
// A link's own page, refused: what `web_portal_runtime.ts` draws in place.
// `AccountApi`'s `getOpenApi`: closed at the top and free below it.
// ---------------------------------------------------------------------------
// `account_api.ts`'s own: the index, the document, who is signed in.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `portal/account_overview.ts`.
// ---------------------------------------------------------------------------
// `inetorgperson.ts`'s `describe()`.
// `account_overview.ts`'s `signalsView()`: a Shared Signals event as it came.
// ---------------------------------------------------------------------------
// `portal/portal_sign_ins.ts`.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `portal/portal_consents.ts`.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `portal/portal_gnap.ts`, over `gnap_console.ts`'s `personGrantsView()`.
// ---------------------------------------------------------------------------
// `GnapGrants.finalize()`'s record, or null while the grant is not final.
// ---------------------------------------------------------------------------
// `portal/portal_mail.ts`.
// ---------------------------------------------------------------------------
// A link checked, or spent.
// ---------------------------------------------------------------------------
// `portal/portal_pseudonyms.ts`.
// ---------------------------------------------------------------------------
// `{ refused }` where the directory could not be asked at all.
// ---------------------------------------------------------------------------
// `portal/portal_owned.ts`.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `portal/portal_shared.ts`, over `uma/uma_owner_policy.ts`.
// ---------------------------------------------------------------------------
// `view()` answers `{ ok: false }` where the owner's document will not parse,
// and a refusal embeds that view whole; its code is a mark (#1355).
// ---------------------------------------------------------------------------
// `portal/account_password.ts`.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `portal/account_keys.ts`.
// ---------------------------------------------------------------------------
// `keyRow()`.
// `credentials.ts`'s `keyUpgradeHistory()`.
// `refused()` is the 400 and the 500; a browser that may retry classically is a
// 400 with no view, which `view` being optional covers.
// ---------------------------------------------------------------------------
// `portal/account_mfa.ts`.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `portal/account_signing_key.ts`.
// ---------------------------------------------------------------------------
// `{ name, mime, base64 }`: a file saved once, never on a URL (`files`).
// A TLS client certificate's (`kind`, `issued`) or a signing key's (the
// rest); `files` on both.
// ---------------------------------------------------------------------------
// `portal/portal_certificates.ts`, over `common/cert_enrollment.ts`.
// ---------------------------------------------------------------------------
// `publicRecord()`.
// The statuses `core.refuse()` writes, each of which `made.status` can carry.
// An ACME key's `hmacKey` or a SCEP `challenge`, shown once.
// ---------------------------------------------------------------------------
// `portal/portal_app_passwords.ts`.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `portal/portal_kerberos.ts`.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `portal/portal_delegate.ts`.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `portal/portal_self_issued.ts`, over `oid4vc/siop.ts` and `person_did.ts`.
// ---------------------------------------------------------------------------
// `person_did.ts`'s `list()`. A version's `authorizedBy` is one of the records
// its writers keep: the wallet's or the current key's proof, or a person's act.
// A DID this realm hosts is deactivated through `didAct()`, whose answer
// carries the page's `view`; any other subject answers the message alone.
// Free-form takes null too, which `Kit.nullable()`'s `oneOf` would refuse
// as matching both of its arms.
// ---------------------------------------------------------------------------
// `portal/portal_wallet.ts`.
// ---------------------------------------------------------------------------
// `vc_offers.ts`'s `buildCredentialOffer()`: OpenID4VCI 1.0 section 4.1.1, with
// the one grant this service puts in it.
// Beside the list after a POST, so the code never reaches a URL.
// ---------------------------------------------------------------------------
// `portal/portal_devices.ts`, over `common/devices.ts`.
// ---------------------------------------------------------------------------
// `attestation_revocation.ts`'s `verdictOf()`, on a downgraded key.
// `DeviceKey` in `common/devices.ts`, one value of `stsDeviceKey`.
// By `kind`: an X.509 certificate's facts, a public JWK, or a passkey's name.
// `Devices.view()`.
// A key proved: 201, which `operation.responses['200']` also has to name or the
// document would keep the builder's bare object there.
// ---------------------------------------------------------------------------
// `portal/portal_ciba.ts`.
// ---------------------------------------------------------------------------
// What a sign-in again asks for. `maxAge` only where a connection wants a
// recent one (`portal_connected_accounts.ts`).
// `?stepup=` and `?gnapstepup=` answer this alone.
// ---------------------------------------------------------------------------
// `portal/portal_access_requests.ts`, over `authzen_access_request.ts`.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `portal/portal_device.ts`.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `portal/portal_claim_sources.ts`.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `portal/portal_connected_accounts.ts`.
// ---------------------------------------------------------------------------
// `{ ok: false, stepUp }` IS A 200 here: the connection is not refused, the
// browser is sent to sign in again and comes back.
// ---------------------------------------------------------------------------
// `portal/account_activation.ts`: nobody is signed in, and the link's step
// decides which of these a view carries (`setupView()`, `keyView()`,
// `refusedView()`, `finish()`, `afterKey()`).
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `portal/account_reset.ts`.
// ---------------------------------------------------------------------------

import "../lib/api_lib.tsp";
import "./common.tsp";

using IyaSts.ApiLib;
using IyaSts.Api.Common;

@apiDocument(#{
  `x-iya-every-operation`:#[#{`name`:"DPoP",`in`:"header",`required`:false,`schema`:#{`type`:"string"},`description`:"RFC 9449: the proof of possession for the DPoP-bound access token, which `Authorization: DPoP <token>` requires."},#{`name`:"X-Requested-With",`in`:"header",`required`:false,`schema`:#{`type`:"string"},`description`:"Added by an Android WebView, naming the application that hosts the page. This API reads nothing in it."}],
  `openapi`:"3.1.0",
  `info`:#{
    `title`:"IYA STS Account API",
    `version`:"0.0.0",
    `description`:"The user portal's API: everything a person can see and do about their own account in this trust realm. The person is ALWAYS the access token's subject — no operation takes a username, an id or a DN naming whose account it is. A token is obtained by the authorization code flow with PKCE (S256) as the public client `sts-user-portal`, with `resource` set to this API, and is DPoP-bound (RFC 9449): send it as `Authorization: DPoP <token>` with a `DPoP` proof carrying `ath`. It stops working when the sign-on session it was issued on ends. The few operations marked `x-access: link` take no token: they spend the single-use secret of an activation or reset link they carry."
  },
  `servers`:#[#{`url`:""}],
  `tags`:#[
    #{`name`:"API"},
    #{`name`:"Overview"},
    #{`name`:"Applications"},
    #{`name`:"Security activity"},
    #{`name`:"Recent sign-ins"},
    #{`name`:"Consents"},
    #{`name`:"GNAP grants"},
    #{`name`:"Email"},
    #{`name`:"Forgotten password"},
    #{`name`:"Sign-in names"},
    #{`name`:"Resources I own"},
    #{`name`:"Sharing"},
    #{`name`:"Password"},
    #{`name`:"Passkeys"},
    #{`name`:"Authenticator app"},
    #{`name`:"Signing keys"},
    #{`name`:"Certificates"},
    #{`name`:"App passwords"},
    #{`name`:"Kerberos"},
    #{`name`:"Who may act for you"},
    #{`name`:"Self-issued IDs"},
    #{`name`:"Wallet"},
    #{`name`:"Devices"},
    #{`name`:"Sign-in requests"},
    #{`name`:"Access requests"},
    #{`name`:"Sign in a device"},
    #{`name`:"Claim sources"},
    #{`name`:"Connected accounts"},
    #{`name`:"Activation"},
    #{`name`:"Password reset link"}
  ],
  `components`:#{
    `securitySchemes`:#{
      `portal`:#{
        `type`:"oauth2",
        `description`:"The authorization code flow with PKCE as a public client; every token DPoP-bound (RFC 9449).",
        `flows`:#{
          `authorizationCode`:#{
            `authorizationUrl`:"/oauth2/authorize",
            `tokenUrl`:"/oauth2/token",
            `scopes`:#{`account:manage`:"Read and manage your own account."}
          }
        }
      }
    }
  },
  `x-iya-doc`:"account"
})
namespace IyaSts.Api.Account {
  

@endpoint("/account-api",
  "get",
  #{
    `operationId`:"getIndex",
    `tags`:#["API"],
    `summary`:"Lists every operation of this API",
    `description`:"Each operation's method, path, access and the portal page or form it is the door of. The portal reads it to know which operation a form goes to.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-access`:"public"
  })
op `getIndex`(`responses/200/content/application~1json/schema`: {
    `api`?: string;
    `document`?: string;
    `operations`?: ({
      `method`?: string;
      `path`?: string;
      `operationId`?: string;
      `tag`?: string;
      `access`?: string;
      `mirrors`?: NullableString;
      `summary`?: string;
      `query`?: (string)[]
    })[]
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/openapi.json",
  "get",
  #{
    `operationId`:"getOpenApi",
    `tags`:#["API"],
    `summary`:"This API's OpenAPI 3.1 document",
    `description`:"Built from the operation table at the moment it is asked, for the realm it is asked in. It carries no secret.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-access`:"public"
  })
op `getOpenApi`(`responses/200/content/application~1json/schema`: {
    `openapi`?: string;
    `info`?: WithTitleVersionDescription;
    `servers`?: ({`url`?: string})[];
    `tags`?: ({`name`?: string})[];
    @js(#{
      `x-free-form`:"The inside of an OpenAPI document (its paths and components): a statement about this API in OpenAPI's own vocabulary, whose every model is stated at the operation it describes.",
      `description`:"The inside of an OpenAPI document (its paths and components): a statement about this API in OpenAPI's own vocabulary, whose every model is stated at the operation it describes."
    }) `paths`?: unknown;
    @js(#{
      `x-free-form`:"The inside of an OpenAPI document (its paths and components): a statement about this API in OpenAPI's own vocabulary, whose every model is stated at the operation it describes.",
      `description`:"The inside of an OpenAPI document (its paths and components): a statement about this API in OpenAPI's own vocabulary, whose every model is stated at the operation it describes."
    }) `components`?: unknown
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

@endpoint("/account-api/me",
  "get",
  #{
    `operationId`:"getMe",
    `tags`:#["API"],
    `summary`:"Who is signed in, and what every page is drawn with",
    `description`:"The person (from the token, never the request), the realm, the language data — the negotiation, the portal's catalogs and the locales offered — and the build. The portal draws its frame from it.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person"
  })
op `getMe`(`responses/200/content/application~1json/schema`: {
    `user`?: {
      `username`?: string;
      `sub`?: string;
      `name`?: string;
      `email`?: string;
      `photo`?: string
    };
    `realm`?: {`id`?: string; `prefix`?: string};
    `client`?: string;
    `expiresAt`?: NullableNumber;
    `mode`?: string;
    `locale`?: WithNegotiatedDescriptionCatalogsEtc4;
    `version`?: WithVersionBuildInfo
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/announcements",
  "get",
  #{
    `operationId`:"getAnnouncements",
    `tags`:#["API"],
    `summary`:"Announcements for everybody signed in to the portal",
    `description`:"What an administrator broadcast to the user portal after `since` — the `now` this operation answered your tab's first ask with — within `ssf.announcementKeepS`, oldest first. With no `since` it answers only `now`, so a tab shows what arrived after it signed in. `everyMs` is how often to ask again.",
    `parameters`:#[
      #{
        `name`:"since",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `example`:"0"
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person"
  })
op `getAnnouncements`(@js(#{`pattern`:"^[0-9]{1,16}$"}) `parameters/0/schema`: string,
  `responses/200/content/application~1json/schema`: WithNowEveryMsAnnouncements,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

@endpoint("/account-api/locale",
  "get",
  #{
    `operationId`:"getLocale",
    `tags`:#["API"],
    `summary`:"The language data a page for nobody is drawn with",
    `description`:"For the pages a person reaches with no sign-in — an activation or reset link, the forgot-password form, an address verification: the negotiation from the browser alone, the portal's catalogs, the offered locales and the build.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-access`:"public"
  })
op `getLocale`(`responses/200/content/application~1json/schema`: {
    `locale`?: WithNegotiatedDescriptionCatalogsEtc4;
    `version`?: WithVersionBuildInfo
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@js(#{
    `additionalProperties`:false,
    `properties`:#{`dn`:#{`type`:"string"}},
    `$types`:#["object","null"]
  }) @hoisted model get_account_api_overview_r200_application_json_entry_h5 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `classes`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `id`:#{`type`:"string"},
            `name`:#{`type`:"string"},
            `rfc`:#{`type`:"string"},
            `oid`:#{`type`:"string"},
            `what`:#{`type`:"string"},
            `rows`:#{
              `type`:"array",
              `items`:#{
                `type`:"object",
                `additionalProperties`:false,
                `properties`:#{
                  `ldap`:#{`type`:"string"},
                  `label`:#{`type`:"string"},
                  `rfc`:#{`type`:"string"},
                  `note`:#{`type`:"string"},
                  `must`:#{`type`:"boolean"},
                  `secret`:#{`type`:"boolean"},
                  `binary`:#{`type`:"boolean"},
                  `present`:#{`type`:"boolean"},
                  `count`:#{`type`:"integer"},
                  `values`:#{`type`:"array",`items`:#{`type`:"string"}},
                  `bytes`:#{`type`:"integer"}
                }
              }
            },
            `held`:#{`type`:"integer"},
            `total`:#{`type`:"integer"}
          }
        }
      },
      `held`:#{`type`:"integer"},
      `total`:#{`type`:"integer"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_account_api_overview_r200_application_json_directory_h7 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `path`:#{`type`:"string"},
      `origin`:#{`type`:"string"},
      `selfService`:#{`type`:"boolean"},
      `limits`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `maxFileBytes`:#{`type`:"number"},
          `maxStoredBytes`:#{`type`:"number"},
          `minPixels`:#{`type`:"number"},
          `maxPixels`:#{`type`:"number"},
          `types`:#{`type`:"array",`items`:#{`type`:"string"}}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_account_api_overview_r200_application_json_photo_h8 {}

@endpoint("/account-api/overview",
  "get",
  #{
    `operationId`:"getOverview",
    `tags`:#["Overview"],
    `summary`:"Who you are, this session, and how you sign in",
    `description`:"Your username, subject and directory entry's DN; when the sign-on session began, how it authenticated (amr, acr) and when it ends; every standard inetOrgPerson attribute your entry holds, from a fixed list (`directory`, null with no directory or no entry — then `session` carries what the sign-in said); a summary of your credentials (`mechanisms`); the language your entry holds with those offered (`language`); and the realm's custom attributes whose definition shows them on the portal, with your values and whether you may change them (`customAttributes`, empty with no entry).\n\nThe door of the portal's `GET /portal`.",
    `parameters`:#[
      #{
        `name`:"done",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `example`:"example"
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal"
  })
op `getOverview`(@js(#{`maxLength`:200}) `parameters/0/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `username`?: string;
    `sub`?: string;
    `entry`?: get_account_api_overview_r200_application_json_entry_h5;
    `session`?: {`email`?: string; `name`?: string};
    `signOn`?: {
      `startedAt`?: numeric;
      `authTime`?: numeric;
      `authentications`?: numeric;
      `amr`?: (string)[];
      `acr`?: string;
      `deviceBound`?: {
        `bound`?: boolean;
        `alg`?: string;
        `fact`?: string;
        `reasons`?: (string)[]
      }
    };
    `sessionEnds`?: numeric;
    `timesSignedIn`?: NullableNumber;
    `directory`?: get_account_api_overview_r200_application_json_directory_h7;
    `mechanisms`?: {
      `password`?: boolean;
      `keys`?: integer;
      `totp`?: boolean;
      `totpUsable`?: boolean;
      `mfaRequired`?: boolean;
      `secondFactor`?: string;
      `backupCodes`?: {
        `present`?: boolean;
        `usable`?: boolean;
        `remaining`?: numeric;
        `total`?: numeric
      }
    };
    `language`?: {`held`?: string; `offered`?: (WithTagName)[]};
    `customAttributes`?: ({
      `name`?: string;
      `label`?: string;
      `description`?: string;
      `syntax`?: string;
      `multi`?: boolean;
      `values`?: (string)[];
      `editable`?: boolean
    })[];
    `photo`?: get_account_api_overview_r200_application_json_photo_h8
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/language",
  "post",
  #{
    `operationId`:"setLanguage",
    `tags`:#["Overview"],
    `summary`:"Sets or removes your preferred language",
    `description`:"Writes `preferredLanguage` on your own entry (RFC 2798), which ranks above the browser for every page this service draws for you, and sets the language cookie; an empty `lang` removes it and follows the browser. A tag no catalog answers is refused.\n\nThe door of the portal's `POST /portal/language`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/language",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`lang`:""}}}}
  })
op `setLanguage`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `description`:"A BCP 47 tag this service has a catalog for, or empty to follow the browser.",
      `maxLength`:64
    }) `lang`?: string
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGo,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/photo",
  "post",
  #{
    `operationId`:"setProfilePhoto",
    `tags`:#["Overview"],
    `summary`:"Sets your profile photo",
    `description`:"Keeps `image`, a base64-encoded JPEG or PNG, as your photo: its metadata is removed, it gets a new random address, and the `picture` claim names that address from now on. The file's bytes decide its type, and the realm's limits are on the Overview's `photo.limits`.\n\nThe door of the portal's `POST /portal/photo`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"Product mode, with no public base URL pinned.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `413`:#{
        `description`:"The file is larger than the realm keeps.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/photo",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`image`:"not-an-image"}}}}
  })
op `setProfilePhoto`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `maxLength`:4194304,
      `description`:"The JPEG or PNG file, base64-encoded."
    }) `image`: string
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGoEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/409/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/413/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/photo/remove",
  "post",
  #{
    `operationId`:"removeProfilePhoto",
    `tags`:#["Overview"],
    `summary`:"Removes your profile photo",
    `description`:"Removes the image and the `picture` claim's address. A copy from a federation partner stays removed: the next sign-in through them does not bring it back.\n\nThe door of the portal's `POST /portal/photo/remove`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/photo/remove"
  })
op `removeProfilePhoto`(`responses/200/content/application~1json/schema`: WithOkMessageGoEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@js(#{`maxItems`:100}) @hoisted model post_account_api_attributes_b_application_json_values_v1_h11 is (StringMax1024)[];
  

@js(#{
    `description`:"Every value the attribute is to hold afterwards; none clears it. A single-valued attribute takes one."
  }) @hoisted union post_account_api_attributes_b_application_json_values_h12 {
    EmptyText,
    post_account_api_attributes_b_application_json_values_v1_h11
  }

@endpoint("/account-api/attributes",
  "post",
  #{
    `operationId`:"setCustomAttribute",
    `tags`:#["Overview"],
    `summary`:"Replaces your own values of one custom attribute",
    `description`:"Writes `values` as every value the realm's custom attribute `attribute` holds on your own entry, checked against its syntax; no values clears it. Only an attribute whose definition shows it on the portal and lets you edit it (`customAttributes[].editable` on the Overview). A value the realm's attribute policy requires may not be emptied in product mode.\n\nThe door of the portal's `POST /portal/attributes`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/attributes",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`attribute`:"no-such-attribute",`values`:#[]}}}}
  })
op `setCustomAttribute`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `maxLength`:64,
      `description`:"The custom attribute's name, one this realm's definition lets you edit on the portal."
    }) `attribute`: string;
    `values`?: post_account_api_attributes_b_application_json_values_h12
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGo,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/applications",
  "get",
  #{
    `operationId`:"getApplications",
    `tags`:#["Applications"],
    `summary`:"The applications you can be signed in to",
    `description`:"Every registered application that is a sign-in destination (OpenID Connect, OAuth 2.0, SAML 2.0, SAML 1.1, WS-Federation) for which the issuance policy, asked as a dry run, permits you at least one family — its home page, the identity-provider-initiated sign-in links it offers (`launches`, each /launch/{app}?protocol=…), the families permitted and withheld. Twenty to a page; the counts of those refused and not evaluated are carried too.\n\nThe door of the portal's `GET /portal/applications`.",
    `parameters`:#[
      #{
        `name`:"done",
        `in`:"query",
        `required`:false,
        `schema`:null
      },
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The page of the list, 1 for the first.",
        `example`:1
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/applications"
  })
op `getApplications`(@js(#{`maxLength`:200}) `parameters/0/schema`: string,
  @js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/1/schema`: unknown,
  `responses/200/content/application~1json/schema`: {
    `rows`?: ({
      `identifier`?: string;
      `name`?: string;
      `homePage`?: NullableString;
      `launchable`?: (string)[];
      `description`?: string;
      `families`?: (string)[];
      `ways`?: (string)[];
      `withheld`?: (string)[];
      `launches`?: ({`protocol`?: string; `label`?: string; `url`?: string})[]
    })[];
    `page`?: integer;
    `pages`?: integer;
    `refused`?: integer;
    `notSignIn`?: integer;
    `scanned`?: integer;
    `total`?: integer;
    `truncated`?: boolean;
    `limit`?: numeric
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `applies`:#{`type`:"boolean"},
      `why`:#{`type`:"string"},
      `state`:#{`type`:"string"},
      `since`:#{`type`:"string"},
      `hours`:#{`type`:"number"},
      `moves`:#{`type`:"array",`items`:#{`type`:"string"}}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_account_api_signals_r200_application_json_participation_h21 {}

@endpoint("/account-api/signals",
  "get",
  #{
    `operationId`:"getSecurityActivity",
    `tags`:#["Security activity"],
    `summary`:"The security events this portal was told about you",
    `description`:"The CAEP and RISC events this portal received as a Shared Signals receiver that are about you (an event it cannot tie to you is left out), twenty to a page, each with whether its signature verified and what this portal did with it; and whether events about your account are shared (RISC section 2.8, `participation`, null while RISC is off).\n\nThe door of the portal's `GET /portal/signals`.",
    `parameters`:#[
      #{
        `name`:"done",
        `in`:"query",
        `required`:false,
        `schema`:null
      },
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The page of the list, 1 for the first.",
        `example`:1
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/signals"
  })
op `getSecurityActivity`(@js(#{`maxLength`:200}) `parameters/0/schema`: string,
  @js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/1/schema`: unknown,
  `responses/200/content/application~1json/schema`: {
    `incomplete`?: boolean;
    `rows`?: ({
      `at`?: Shape;
      `name`?: string;
      `vocabulary`?: string;
      `type`?: string;
      @js(#{
        `x-free-form`:"The event's payload as a transmitter signed it: CAEP and RISC events carry members by event type, and an unknown type is shown as it came.",
        `description`:"The event's payload as a transmitter signed it: CAEP and RISC events carry members by event type, and an unknown type is shown as it came."
      }) `payload`?: unknown;
      `verified`?: boolean;
      `verificationNote`?: string;
      `reactions`?: ({
        `failed`?: boolean;
        `skipped`?: string;
        `observed`?: boolean;
        `ended`?: numeric
      })[]
    })[];
    `page`?: integer;
    `pages`?: integer;
    `participation`?: get_account_api_signals_r200_application_json_participation_h21
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/signals",
  "post",
  #{
    `operationId`:"moveRiscParticipation",
    `tags`:#["Security activity"],
    `summary`:"Stops, cancels stopping, or resumes sharing security events about you",
    `description`:"RISC 1.0 section 2.8's account-holder moves. Opting out takes effect only after risc.optOutDelayHours, and can be cancelled until then.\n\nThe door of the portal's `POST /portal/signals`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"That move is not one your account can make now.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `503`:#{
        `description`:"Shared Signals is off, so nothing was recorded.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/signals",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`move`:"optOutCancelled"}}}}
  })
op `moveRiscParticipation`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `description`:"The move: start opting out, cancel that, or opt back in."
    }) `move`?: "optOutInitiated" | "optOutCancelled" | "optIn"
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGo,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/409/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/503/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/sign-ins",
  "get",
  #{
    `operationId`:"getSignIns",
    `tags`:#["Recent sign-ins"],
    `summary`:"Your assessed sign-ins, with the application of each",
    `description`:"One page (`paging`, moved by `page`, newest first) of the assessments of your sign-ins: when, the city, country and network, the browser and system, the door, the application (the client the sign-in named), the risk level, and your answer if you gave one. `days` is how far back the list looks (`audit.authenticationHistoryDays`, thirty by default, set per realm). `paging.total` counts every sign-in of that window. `thisSession` is the assessment of the session this token was issued on.\n\nThe door of the portal's `GET /portal/sign-ins`.",
    `parameters`:#[
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `rows`, newest first. Clamped to the last.",
        `example`:1
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/sign-ins"
  })
op `getSignIns`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/0/schema`: unknown,
  `responses/200/content/application~1json/schema`: WithDaysThisSessionPagingEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/sign-ins",
  "post",
  #{
    `operationId`:"answerSignIn",
    `tags`:#["Recent sign-ins"],
    `summary`:"Says whether a sign-in was you",
    `description`:"`confirm` is recorded, and lowers your standing only when said from another, low-risk session. `deny` puts your standing at HIGH: everything you hold is ended, this session included, and RISC is told the credential is compromised (`ended: true`).\n\nThe door of the portal's `POST /portal/sign-ins`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/sign-ins",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"deny",`assessment`:"no-such-id"}}}}
  })
op `answerSignIn`(`requestBody/content/application~1json/schema`: {
    @js(#{`description`:"`confirm`: this was me. `deny`: this was not me."}) `action`: "confirm" | "deny";
    @js(#{
      `minLength`:1,
      `maxLength`:200,
      `description`:"The assessment's id, from the list."
    }) `assessment`: string
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `ended`?: boolean;
    `view`?: WithDaysThisSessionPagingEtc4
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/consents",
  "get",
  #{
    `operationId`:"getConsents",
    `tags`:#["Consents"],
    `summary`:"What you have agreed each application may ask for",
    `description`:"One page (`paging`) of `groups`, one per application you have consented to, the newest first: its client_id, its name, and each scope with when you agreed (a GeneralizedTime). `administrative` is every scope an application's global consent answered for you that still stands, which is not yours to withdraw.\n\nThe door of the portal's `GET /portal/consents`.",
    `parameters`:#[
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `example`:1
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/consents"
  })
op `getConsents`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/0/schema`: unknown,
  `responses/200/content/application~1json/schema`: WithPagingGroupsAdministrative,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/consents",
  "post",
  #{
    `operationId`:"withdrawConsent",
    `tags`:#["Consents"],
    `summary`:"Withdraws a consent of yours",
    `description`:"One scope (`action=scope`) or everything an application holds (`action=application`). Every token that application holds for you under it is revoked, and a refresh token granted before is refused even after you agree again. A consent that is not on your own entry is refused.\n\nThe door of the portal's `POST /portal/consents`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/consents",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"scope",`client`:"no-such-id",`scope`:"no-such-id"}}}}
  })
op `withdrawConsent`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `description`:"`scope`: withdraw one scope. `application`: withdraw everything one application holds."
    }) `action`: "scope" | "application";
    @js(#{
      `minLength`:1,
      `maxLength`:512,
      `description`:"The application's client_id."
    }) `client`: string;
    @js(#{`description`:"The scope, for `action=scope`.",`maxLength`:1024}) `scope`?: string;
    `page`?: EmptyTextOrIntegerFrom1To1000003
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGo,
  `responses/400/content/application~1json/schema`: {
    `ok`: boolean;
    `errors`: (string)[];
    `error`?: string;
    `view`?: WithPagingGroupsAdministrative
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/gnap",
  "get",
  #{
    `operationId`:"getGnapGrants",
    `tags`:#["GNAP grants"],
    `summary`:"The GNAP grants you gave",
    `description`:"One page (`paging`) of `rows`: each grant whose resource owner you are — the client, its state or why it ended, its access rights (RFC 9635 objects or references), the tokens issued under it, when it was granted and until when, and whether you may revoke it. The same view an administrator's user page draws. Under cells, `cells` says when another cell may hold more.\n\nThe door of the portal's `GET /portal/gnap`.",
    `parameters`:#[
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `example`:1
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/gnap"
  })
op `getGnapGrants`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/0/schema`: unknown,
  `responses/200/content/application~1json/schema`: WithUserTotalRowsEtc5,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/gnap",
  "post",
  #{
    `operationId`:"revokeGnapGrant",
    `tags`:#["GNAP grants"],
    `summary`:"Revokes a GNAP grant you gave",
    `description`:"The client's own RFC 9635 section 5.4 act, performed for you: every token issued under the grant stops working, the grant is finalized as revoked, and CAEP session-revoked is sent. A grant that is not yours is refused.\n\nThe door of the portal's `POST /portal/gnap`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/gnap",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`grant`:"no-such-id"}}}}
  })
op `revokeGnapGrant`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `minLength`:1,
      `maxLength`:4096,
      `pattern`:"^[A-Za-z0-9_-]+$",
      `description`:"The grant to end, from the list."
    }) `grant`: string;
    `page`?: EmptyTextOrIntegerFrom1To1000003
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGo,
  `responses/400/content/application~1json/schema`: {
    `ok`: boolean;
    `errors`: (string)[];
    `error`?: string;
    `view`?: WithUserTotalRowsEtc5
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/email",
  "get",
  #{
    `operationId`:"getEmail",
    `tags`:#["Email"],
    `summary`:"Your email address, its messages, and what was sent",
    `description`:"`address` and whether it is `verified`, a change waiting for its link (`changing`), whether mail can be sent (`available`), the message `categories` (only `notification` is `optional`; `sent` says whether you are sent it), and one page of the messages `sent` to you, newest first — never their bodies — moved by `sentPage` and described by `sentPaging`.\n\nThe door of the portal's `GET /portal/email`.",
    `parameters`:#[
      #{
        `name`:"sentPage",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `sent`, newest first. Clamped to the last.",
        `example`:1
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/email"
  })
op `getEmail`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/0/schema`: unknown,
  `responses/200/content/application~1json/schema`: {
    `address`?: string;
    `verified`?: boolean;
    `changing`?: string;
    `available`?: boolean;
    `categories`?: (WithIdLabelWhatEtc5)[];
    `sent`?: ({
      `queuedAt`?: Shape;
      `subject`?: NullableString;
      `to`?: NullOrStringOrString;
      `state`?: NullableString
    })[];
    `sentPaging`?: WithPagePagesPerEtc4
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

@js(#{
    `description`:"`verify` sends a link to the address on your entry; `change` sends one to `address`; `preferences` saves `notification`."
  }) @hoisted union post_account_api_email_b_application_json_action_h86 {
    EmptyText,
    "verify" | "preferences" | "change"
  }

  

@js(#{`description`:"`on` to be sent notifications, for `preferences`."}) @hoisted union post_account_api_email_b_application_json_notification_h88 {
    EmptyText,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

@endpoint("/account-api/email",
  "post",
  #{
    `operationId`:"postEmail",
    `tags`:#["Email"],
    `summary`:"Verifies your address, changes it, or saves your choices",
    `description`:"`verify` sends a verification link to your address; `change` sends one to a new address, which takes effect only when that link is used; `preferences` saves whether you are sent notifications. The two that send mail are rate limited. A refusal carries the page's `view`.\n\nThe door of the portal's `POST /portal/email`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts; try again later.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/email",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"change",`address`:"not-an-address"}}}}
  })
op `postEmail`(`requestBody/content/application~1json/schema`: {
    `action`?: post_account_api_email_b_application_json_action_h86;
    @js(#{`description`:"The new address, for `change`.",`maxLength`:254}) `address`?: string;
    `notification`?: post_account_api_email_b_application_json_notification_h88
  },
  `responses/200/content/application~1json/schema`: WithStepUpOkMessageEtc4,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc48,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc48,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/verify-email",
  "get",
  #{
    `operationId`:"getEmailVerification",
    `tags`:#["Email"],
    `summary`:"Checks an address verification link, and spends nothing",
    `description`:"Takes no token: the link's `user` and `token` are the credential. Answers the address the link would verify, or `view.refused`. Opening it spends nothing, so a mail scanner cannot verify an address nobody read. Rate limited.\n\nThe door of the portal's `GET /portal/verify-email`.",
    `parameters`:#[
      #{
        `name`:"user",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The username the link names.",
        `example`:"nobody-example"
      },
      #{
        `name`:"X-Link-Token",
        `in`:"header",
        `required`:false,
        `schema`:null,
        `description`:"The single-use secret the link carried in its fragment."
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts; `view.refused` says so.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-access`:"link",
    `x-mirrors`:"GET /portal/verify-email"
  })
op `getEmailVerification`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`minLength`:1,`maxLength`:256}]}}) `parameters/0/schema`: unknown,
  `parameters/1/schema`: string,
  `responses/200/content/application~1json/schema`: WithAddressUsernameToken,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc5,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc5,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

  

  

@endpoint("/account-api/verify-email",
  "post",
  #{
    `operationId`:"verifyEmail",
    `tags`:#["Email"],
    `summary`:"Verifies the address an address verification link names",
    `description`:"Spends the link. Answers `view.verified`, or `view.refused`. Rate limited.\n\nThe door of the portal's `POST /portal/verify-email`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts; `view.refused` says so.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-access`:"link",
    `x-mirrors`:"POST /portal/verify-email",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`user`:"nobody-example",`token`:"no-such-token"}}}}
  })
op `verifyEmail`(`requestBody/content/application~1json/schema`: WithUserToken,
  `responses/200/content/application~1json/schema`: WithOkMessageGoEtc42,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc5,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc5,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/forgot-password",
  "get",
  #{
    `operationId`:"getForgotPassword",
    `tags`:#["Forgotten password"],
    `summary`:"Whether a forgotten password can be reset here, and how",
    `description`:"`threeFields` when a recovery code is asked for beside the account and its address. 404 where self-service reset is not offered (the setting off, no transport, or development mode).\n\nThe door of the portal's `GET /portal/forgot-password`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `404`:#{
        `description`:"Not offered here; `view.notOffered` says so.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-access`:"public",
    `x-mirrors`:"GET /portal/forgot-password"
  })
op `getForgotPassword`(`responses/200/content/application~1json/schema`: WithThreeFieldsNoteTooManyEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/404/content/application~1json/schema`: WithOkErrorsErrorEtc44,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/forgot-password",
  "post",
  #{
    `operationId`:"requestPasswordReset",
    `tags`:#["Forgotten password"],
    `summary`:"Asks for a password reset link",
    `description`:"Answers ONE SENTENCE whatever happened (`view.note`), before the work is done, so neither its words nor its timing say whether the account exists; the link, if any, is mailed to the address on the account. Rate limited per account and address.\n\nThe door of the portal's `POST /portal/forgot-password`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `404`:#{
        `description`:"Not offered here.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts; `view.tooMany` says so.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-access`:"public",
    `x-mirrors`:"POST /portal/forgot-password",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`account`:"nobody-example"}}}}
  })
op `requestPasswordReset`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `description`:"Your username, or the address on your account.",
      `maxLength`:256
    }) `account`?: string;
    @js(#{
      `description`:"The address on your account, where a recovery code is asked for.",
      `maxLength`:254
    }) `address`?: string;
    @js(#{
      `description`:"One of your recovery codes, where one is asked for.",
      `maxLength`:64
    }) `code`?: string
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `view`?: WithThreeFieldsNoteTooManyEtc4
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/404/content/application~1json/schema`: WithOkErrorsErrorEtc44,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc44,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/pseudonyms",
  "get",
  #{
    `operationId`:"getPseudonyms",
    `tags`:#["Sign-in names"],
    `summary`:"The other names you can sign in with",
    `description`:"`pseudonyms` are live. `pending` is an email that is not a name until its link is opened. `cap` is eight. `available` says whether an email can be mailed a link.\n\nThe door of the portal's `GET /portal/pseudonyms`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `503`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/pseudonyms"
  })
op `getPseudonyms`(`responses/200/content/application~1json/schema`: {
    `pseudonyms`?: (string)[];
    `pending`?: NullableString;
    `cap`?: numeric;
    `available`?: boolean
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/503/content/application~1json/schema`: WithOkErrorsErrorEtc5,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

@js(#{
    `description`:"`add` adds `value`; `remove` drops it; `cancel-pending` drops a name that is waiting for its link."
  }) @hoisted union post_account_api_pseudonyms_b_application_json_action_h110 {
    EmptyText,
    "add" | "remove" | "cancel-pending"
  }

@endpoint("/account-api/pseudonyms",
  "post",
  #{
    `operationId`:"postPseudonyms",
    `tags`:#["Sign-in names"],
    `summary`:"Adds, removes or cancels one sign-in name",
    `description`:"`add` of an email mails a link to `/portal/verify-pseudonym` and is not a name until that link is used, unless the address is already your verified one. Any other name is live at once. `remove` drops a live name. `cancel-pending` drops a name waiting for its link. Adding is rate limited. The link's secret is not in the answer.\n\nThe door of the portal's `POST /portal/pseudonyms`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts; try again later.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `503`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/pseudonyms",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"remove",`value`:"nobody-example"}}}}
  })
op `postPseudonyms`(`requestBody/content/application~1json/schema`: {
    `action`?: post_account_api_pseudonyms_b_application_json_action_h110;
    @js(#{`description`:"The name, for `add` and `remove`.",`maxLength`:254}) `value`?: string
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGo,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc43,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc43,
  `responses/503/content/application~1json/schema`: WithOkErrorsErrorEtc43,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/verify-pseudonym",
  "get",
  #{
    `operationId`:"getPseudonymVerification",
    `tags`:#["Sign-in names"],
    `summary`:"Checks a sign-in-name link, and spends nothing",
    `description`:"Takes no token: the link's `user` and `token` are the credential. Answers the name the link would confirm. Opening it spends nothing. This is not `/portal/verify-email`. Rate limited.\n\nThe door of the portal's `GET /portal/verify-pseudonym`.",
    `parameters`:#[
      #{
        `name`:"user",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The username the link names.",
        `example`:"nobody-example"
      },
      #{
        `name`:"X-Link-Token",
        `in`:"header",
        `required`:false,
        `schema`:null,
        `description`:"The single-use secret the link carried in its fragment."
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts; `view.refused` says so.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `503`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-access`:"link",
    `x-mirrors`:"GET /portal/verify-pseudonym"
  })
op `getPseudonymVerification`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`minLength`:1,`maxLength`:256}]}}) `parameters/0/schema`: unknown,
  `parameters/1/schema`: string,
  `responses/200/content/application~1json/schema`: WithAddressUsernameToken,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc5,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc5,
  `responses/503/content/application~1json/schema`: WithOkErrorsErrorEtc5,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

  

  

@endpoint("/account-api/verify-pseudonym",
  "post",
  #{
    `operationId`:"verifyPseudonym",
    `tags`:#["Sign-in names"],
    `summary`:"Confirms the sign-in name a link names",
    `description`:"Spends the link. Answers `view.verified`, or `view.refused`. Rate limited. Not the recovery-address link.\n\nThe door of the portal's `POST /portal/verify-pseudonym`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts; `view.refused` says so.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `503`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-access`:"link",
    `x-mirrors`:"POST /portal/verify-pseudonym",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`user`:"nobody-example",`token`:"no-such-token"}}}}
  })
op `verifyPseudonym`(`requestBody/content/application~1json/schema`: WithUserToken,
  `responses/200/content/application~1json/schema`: WithOkMessageGoEtc42,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc5,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc5,
  `responses/503/content/application~1json/schema`: WithOkErrorsErrorEtc5,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/owned/roles",
  "get",
  #{
    `operationId`:"getOwnedRoles",
    `tags`:#["Resources I own"],
    `summary`:"What you own: roles",
    `description`:"One page (`paging`, moved by `page`) of the roles whose `owner` values name you or a group you are in (#604), in name order. Each row's `via` says how it is yours: `you` where an owner value is your own entry, and `groups`, the groups of yours it names. Since #607 an owner may administer what they own through /admin-api with owner:read and owner:write.\n\nThe door of the portal's `GET /portal/owned/roles`.",
    `parameters`:#[
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `rows`. Clamped to the last.",
        `example`:1
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/owned/roles"
  })
op `getOwnedRoles`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/0/schema`: unknown,
  `responses/200/content/application~1json/schema`: WithKindPagingRows,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/owned/groups",
  "get",
  #{
    `operationId`:"getOwnedGroups",
    `tags`:#["Resources I own"],
    `summary`:"What you own: groups",
    `description`:"One page (`paging`, moved by `page`) of the groups whose `owner` values name you or a group you are in (#604), in name order. Each row's `via` says how it is yours: `you` where an owner value is your own entry, and `groups`, the groups of yours it names. Since #607 an owner may administer what they own through /admin-api with owner:read and owner:write.\n\nThe door of the portal's `GET /portal/owned/groups`.",
    `parameters`:#[
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `rows`. Clamped to the last.",
        `example`:1
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/owned/groups"
  })
op `getOwnedGroups`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/0/schema`: unknown,
  `responses/200/content/application~1json/schema`: WithKindPagingRows,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/owned/service-accounts",
  "get",
  #{
    `operationId`:"getOwnedServiceAccounts",
    `tags`:#["Resources I own"],
    `summary`:"What you own: service accounts",
    `description`:"One page (`paging`, moved by `page`) of the service accounts whose `stsServiceAccountOwner` values name you or a group you are in (#604), in name order. Each row's `via` says how it is yours: `you` where an owner value is your own entry, and `groups`, the groups of yours it names. Since #607 an owner may administer what they own through /admin-api with owner:read and owner:write.\n\nThe door of the portal's `GET /portal/owned/service-accounts`.",
    `parameters`:#[
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `rows`. Clamped to the last.",
        `example`:1
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/owned/service-accounts"
  })
op `getOwnedServiceAccounts`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/0/schema`: unknown,
  `responses/200/content/application~1json/schema`: WithKindPagingRows,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/owned/applications",
  "get",
  #{
    `operationId`:"getOwnedApplications",
    `tags`:#["Resources I own"],
    `summary`:"What you own: applications",
    `description`:"One page (`paging`, moved by `page`) of the applications whose `appOwner` values name you or a group you are in (#604), in name order. Each row's `via` says how it is yours: `you` where an owner value is your own entry, and `groups`, the groups of yours it names. Since #607 an owner may administer what they own through /admin-api with owner:read and owner:write.\n\nThe door of the portal's `GET /portal/owned/applications`.",
    `parameters`:#[
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `rows`. Clamped to the last.",
        `example`:1
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/owned/applications"
  })
op `getOwnedApplications`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/0/schema`: unknown,
  `responses/200/content/application~1json/schema`: WithKindPagingRows,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/shared",
  "get",
  #{
    `operationId`:"getShared",
    `tags`:#["Sharing"],
    `summary`:"What you share through User-Managed Access",
    `description`:"One page (`paging`) of `resources`: the resources resource servers registered on your behalf, each with its scopes and the `shares` your sharing policy holds for it; the `custom` rules of your policy the share form did not write, with their ALFA; the `pending` requests waiting for your approval; and, where the realm allows it (`alfaEditing`), your whole policy as `alfa`. `enabled` says whether UMA is on.\n\nThe door of the portal's `GET /portal/shared`.",
    `parameters`:#[
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `example`:1
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/shared"
  })
op `getShared`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/0/schema`: unknown,
  `responses/200/content/application~1json/schema`: WithOkEnabledResourcesEtc10,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@js(#{
    `description`:"approve, refuse: the waiting request's id, from the list."
  }) @hoisted union post_account_api_shared_b_application_json_pending_h149 {
    EmptyText,
    StringMin1Max256Matching8fe5b0
  }

  

  

@js(#{`description`:"share: the resource's _id, one of yours."}) @hoisted union post_account_api_shared_b_application_json_resource_h152 {
    EmptyText,
    StringMin1Max256Matching8fe5b0
  }

  

  

  

@hoisted union post_account_api_shared_b_application_json_scope_v1_h156 {
    StringMin1Max256,
    (StringMin1Max256)[]
  }

@js(#{
    `description`:"share: the scopes, each one the resource was registered with."
  }) @hoisted union post_account_api_shared_b_application_json_scope_h157 {
    EmptyText,
    post_account_api_shared_b_application_json_scope_v1_h156
  }

  

@js(#{`description`:"share: who the share is with."}) @hoisted union post_account_api_shared_b_application_json_recipientKind_h159 {
    EmptyText,
    "person" | "group" | "realm" | "claim"
  }

  

  

@js(#{
    `description`:"share: the username, the group's name, or the claim's value."
  }) @hoisted union post_account_api_shared_b_application_json_recipient_h162 {
    EmptyText,
    StringMin1Max256
  }

  

  

@js(#{`description`:"share, recipientKind claim: the claim's name."}) @hoisted union post_account_api_shared_b_application_json_claim_h165 {
    EmptyText,
    StringMin1Max256
  }

  

  

@js(#{`description`:"share: an optional date the share ends."}) @hoisted union post_account_api_shared_b_application_json_expires_h168 {
    EmptyText,
    StringMin1Max256
  }

  

  

@js(#{
    `description`:"share: an optional authentication level the requesting party's session must meet."
  }) @hoisted union post_account_api_shared_b_application_json_acr_h171 {
    EmptyText,
    StringMin1Max256
  }

  

@js(#{`description`:"share: ask the owner each time."}) @hoisted union post_account_api_shared_b_application_json_askMe_h173 {
    EmptyText,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

  

  

@js(#{`description`:"unshare: the share's id, from the list."}) @hoisted union post_account_api_shared_b_application_json_share_h176 {
    EmptyText,
    StringMin1Max256Matching8fe5b0
  }

  

@js(#{`maxLength`:65536}) @hoisted scalar post_account_api_shared_b_application_json_alfa_v1_h178 extends string;
  

@js(#{`description`:"alfa: the whole document, as ALFA."}) @hoisted union post_account_api_shared_b_application_json_alfa_h179 {
    EmptyText,
    post_account_api_shared_b_application_json_alfa_v1_h178
  }

  

  

@endpoint("/account-api/shared",
  "post",
  #{
    `operationId`:"actShared",
    `tags`:#["Sharing"],
    `summary`:"Shares a resource, removes a share, or rewrites your policy",
    `description`:"`action` share writes one rule into your sharing policy: a resource of yours, its scopes, and who — a person, a group, anyone signed in to this realm, or anyone whose claim has a value — with an optional expiry, authentication level and \"ask me each time\". `approve` and `refuse` answer a request waiting for you; an approval adds a share for that person for a day. `unshare` removes one and revokes the requesting party tokens that carried it. `alfa` replaces the whole policy, where the realm allows it, and revokes every token over your resources. A resource or share that is not yours is refused.\n\nThe door of the portal's `POST /portal/shared`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `500`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/shared",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"unshare",`share`:"no-such-id"}}}}
  })
op `actShared`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `description`:"share adds a share; unshare removes one; alfa replaces the whole document, where the realm allows it; approve and refuse answer a request waiting for you."
    }) `action`: "share" | "unshare" | "alfa" | "approve" | "refuse";
    `pending`?: post_account_api_shared_b_application_json_pending_h149;
    `resource`?: post_account_api_shared_b_application_json_resource_h152;
    `scope`?: post_account_api_shared_b_application_json_scope_h157;
    `recipientKind`?: post_account_api_shared_b_application_json_recipientKind_h159;
    `recipient`?: post_account_api_shared_b_application_json_recipient_h162;
    `claim`?: post_account_api_shared_b_application_json_claim_h165;
    `expires`?: post_account_api_shared_b_application_json_expires_h168;
    `acr`?: post_account_api_shared_b_application_json_acr_h171;
    `askMe`?: post_account_api_shared_b_application_json_askMe_h173;
    `share`?: post_account_api_shared_b_application_json_share_h176;
    `alfa`?: post_account_api_shared_b_application_json_alfa_h179;
    `page`?: EmptyTextOrIntegerFrom1To1000003
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `view`?: WithOkEnabledResourcesEtc10
  },
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc416,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc416,
  `responses/500/content/application~1json/schema`: WithOkErrorsErrorEtc416,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/shared-with-me",
  "get",
  #{
    `operationId`:"getSharedWithMe",
    `tags`:#["Sharing"],
    `summary`:"What others share with you",
    `description`:"One page (`paging`) of `rows`: each permission a requesting party token issued to you carries — the resource, its resource server and owner, the scopes, the client that holds the token, and until when.\n\nThe door of the portal's `GET /portal/shared-with-me`.",
    `parameters`:#[
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `example`:1
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/shared-with-me"
  })
op `getSharedWithMe`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/0/schema`: unknown,
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `paging`?: WithPagePagesTotal;
    `rows`?: ({
      `resourceId`?: string;
      `name`?: string;
      `resourceServer`?: string;
      `owner`?: string;
      `scopes`?: (string)[];
      `client`?: string;
      `expiresAt`?: numeric
    })[]
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/password",
  "get",
  #{
    `operationId`:"getPassword",
    `tags`:#["Password"],
    `summary`:"Whether you have a password, and what one must be",
    `description`:"`hasPassword`, and `rules`: the password policy's rules for you (`enforced` false in development mode, where nothing is checked).\n\nThe door of the portal's `GET /portal/password`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/password"
  })
op `getPassword`(`responses/200/content/application~1json/schema`: WithHasPasswordRules,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/password",
  "post",
  #{
    `operationId`:"changePassword",
    `tags`:#["Password"],
    `summary`:"Changes your password",
    `description`:"Re-proves the current password (rate limited, in the budget the Kerberos keytab shares), screens the new one against breached passwords, applies the password policy, and tells your relying parties over CAEP. A refusal carries the page's `view`.\n\nThe door of the portal's `POST /portal/password`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts; try again later.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/password",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`current`:"not-the-password",`next`:"not",`confirm`:"equal"}}}}
  })
op `changePassword`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `description`:"Your current password: a change re-proves it.",
      `maxLength`:1024
    }) `current`?: string;
    @js(#{`description`:"The new password.",`maxLength`:1024}) `next`?: string;
    @js(#{`description`:"The new password again.",`maxLength`:1024}) `confirm`?: string
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGo,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc45,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc45,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/keys",
  "get",
  #{
    `operationId`:"getKeys",
    `tags`:#["Passkeys"],
    `summary`:"Your passkeys, and adding one",
    `description`:"Each passkey you hold (`keys`), grouped `device` or `security-key`, with its name, provider, dates, algorithm, what its attestation proved and whether the realm's passkey policy refuses it at sign-in. `enrol` says whether you may add one and, while a registration is waiting, the ceremony to run (`enrol.pending`) and the lanes a passkey may be created in (`enrol.lanes`, #643). `signals` is the WebAuthn Signal API's data, one entry per lane whose user handle you hold.\n\nThe door of the portal's `GET /portal/keys`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/keys"
  })
op `getKeys`(`responses/200/content/application~1json/schema`: WithPasswordMfaRequiredKeysEtc5,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

@js(#{
    `description`:"`begin` mints a challenge, `finish` answers it, `cancel` drops it."
  }) @hoisted union post_account_api_keys_b_application_json_action_h198 {
    EmptyText,
    "begin" | "finish" | "cancel"
  }

  

@js(#{`description`:"Ignored since #1135: a passkey carries no role."}) @hoisted union post_account_api_keys_b_application_json_role_h200 {
    EmptyText,
    "primary" | "mfa"
  }

  

@js(#{`description`:"`begin`: which call to action was pressed."}) @hoisted union post_account_api_keys_b_application_json_kind_h202 {
    EmptyText,
    "passkey" | "security-key"
  }

  

@js(#{
    `description`:"`begin`: `classical` (the default) or `pqc`, where the realm offers a post-quantum passkey beside a classical one."
  }) @hoisted union post_account_api_keys_b_application_json_lane_h204 {
    EmptyText,
    "classical" | "pqc"
  }

  

@js(#{
    `description`:"`begin`: `classical` retries with the classical algorithms only, where `enrol.pending.fallback.classical` says the realm allows it."
  }) @hoisted union post_account_api_keys_b_application_json_algorithms_h206 {
    EmptyText,
    "classical"
  }

  

  

@js(#{`description`:"`finish`: the pending enrolment the ceremony answers."}) @hoisted union post_account_api_keys_b_application_json_enrolment_id_h209 {
    EmptyText,
    StringMin1Max4096Matchinga5aa8a
  }

@endpoint("/account-api/keys",
  "post",
  #{
    `operationId`:"enrolKey",
    `tags`:#["Passkeys"],
    `summary`:"Begins, finishes or cancels adding a passkey",
    `description`:"`begin` mints a challenge and holds it (the policy and the `lane`, #643, checked at the door; `algorithms: classical`, #944, the classical retry, refused where the realm forbids a classical passkey); `finish` verifies the browser's registration with the sign-in screen's address rules and answers `go` naming the new passkey; `cancel` drops the waiting one. A refusal carries the page's `view`, except a browser error reported with its own `capabilities` property while the classical retry is offered (#961): that enrolment stays and the answer carries no view. `role` is accepted and ignored since #1135: a passkey carries no role, and the realm decides how every key may be used. `enrol.allowed` says whether the realm accepts a new passkey for any use.\n\nThe door of the portal's `POST /portal/keys`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `500`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/keys",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"cancel"}}}}
  })
op `enrolKey`(`requestBody/content/application~1json/schema`: {
    `action`?: post_account_api_keys_b_application_json_action_h198;
    `role`?: post_account_api_keys_b_application_json_role_h200;
    `kind`?: post_account_api_keys_b_application_json_kind_h202;
    `lane`?: post_account_api_keys_b_application_json_lane_h204;
    `algorithms`?: post_account_api_keys_b_application_json_algorithms_h206;
    `enrolment_id`?: post_account_api_keys_b_application_json_enrolment_id_h209;
    @js(#{
      `description`:"`finish`: the browser's ceremony result, as JSON.",
      `maxLength`:65536
    }) `credential`?: string
  },
  `responses/200/content/application~1json/schema`: WithStepUpOkMessageEtc4,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc414,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/500/content/application~1json/schema`: WithOkErrorsErrorEtc414,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/keys/remove",
  "post",
  #{
    `operationId`:"removeKey",
    `tags`:#["Passkeys"],
    `summary`:"Removes one of your passkeys",
    `description`:"Refused where it would leave you no way to sign in. Your relying parties are told over CAEP, and every session the passkey signed in ends (`sessionsEnded` counts them, #722); your other sessions stay.\n\nThe door of the portal's `POST /portal/remove-key`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/remove-key",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`credentialId`:"no-such-id"}}}}
  })
op `removeKey`(`requestBody/content/application~1json/schema`: {
    `credentialId`?: EmptyTextOrStringMin1Max4096Matchinga5aa8a
  },
  `responses/200/content/application~1json/schema`: {`stepUp`?: WithAcrValuesPromptMaxAge; 
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `sessionsEnded`?: integer
  },
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc414,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/keys/rename",
  "post",
  #{
    `operationId`:"renameKey",
    `tags`:#["Passkeys"],
    `summary`:"Renames one of your passkeys",
    `description`:"At most 60 characters, no control characters; an empty name puts the default back.\n\nThe door of the portal's `POST /portal/rename-key`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/rename-key",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`credentialId`:"no-such-id",`label`:"example"}}}}
  })
op `renameKey`(`requestBody/content/application~1json/schema`: {
    `credentialId`?: EmptyTextOrStringMin1Max4096Matchinga5aa8a;
    @js(#{
      `description`:"Its new name; empty puts the default back.",
      `maxLength`:200
    }) `label`?: string
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGo,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc414,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/mfa",
  "get",
  #{
    `operationId`:"getMfa",
    `tags`:#["Authenticator app"],
    `summary`:"Your authenticator app, emailed factor and recovery codes",
    `description`:"`totp`: whether an authenticator app is set up (and its algorithm, digits, period, when set up and last used) and whether one is offered. `setup`: an enrolment in progress — the QR code as a `data:` image, the secret grouped for typing, the issuer and the parameters — derived from the pending secret on every call. `doors`: the password-only doors that refuse your own password. `emailFactor`: the emailed second factor, or null where none is offered. `codes`: your recovery codes' state — never the codes, of which only hashes are stored.\n\nThe door of the portal's `GET /portal/mfa`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/mfa"
  })
op `getMfa`(`responses/200/content/application~1json/schema`: WithUsernameVerifiesCredentialsTotpEtc8,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

@js(#{
    `description`:"The step: `start` an authenticator app, `confirm` it with a code, `remove` it; `generate-codes`, `confirm-codes` or `discard-codes` a set of recovery codes; `email-factor-on` or `email-factor-off`."
  }) @hoisted union post_account_api_mfa_b_application_json_action_h255 {
    EmptyText,
    "start" | "confirm" | "remove" | "generate-codes" | "confirm-codes" | "discard-codes" | "email-factor-on" | "email-factor-off"
  }

  

@js(#{
    `description`:"For `email-factor-on`: a mailed `code` or a sign-in `link`."
  }) @hoisted union post_account_api_mfa_b_application_json_kind_h257 {EmptyText, "code" | "link"}

@endpoint("/account-api/mfa",
  "post",
  #{
    `operationId`:"changeMfa",
    `tags`:#["Authenticator app"],
    `summary`:"Sets up, confirms or removes your second factors",
    `description`:"`start` mints a secret and holds it (ask the view for the QR code); `confirm` checks a code from the app (rate limited) and enrols it; `remove` takes it off, and ends every session its codes signed in (`sessionsEnded`, #722). `generate-codes` answers a set of recovery codes ONCE, in `view.fresh`, and stores nothing; `confirm-codes` stores their hashes; `discard-codes` throws the pending set away. `email-factor-on` (with `kind`) and `email-factor-off` opt in and out of the emailed second factor. A refusal carries the page's `view`.\n\nThe door of the portal's `POST /portal/mfa`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many codes tried; try again later.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/mfa",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"confirm",`code`:"000000"}}}}
  })
op `changeMfa`(`requestBody/content/application~1json/schema`: {
    `action`?: post_account_api_mfa_b_application_json_action_h255;
    `kind`?: post_account_api_mfa_b_application_json_kind_h257;
    @js(#{`description`:"For `confirm`: the code the app shows.",`maxLength`:32}) `code`?: string;
    @js(#{
      `description`:"For `confirm-codes` and `discard-codes`: the pending set's handle, from `generate-codes`'s answer.",
      `maxLength`:128
    }) `handle`?: string
  },
  `responses/200/content/application~1json/schema`: {`stepUp`?: WithAcrValuesPromptMaxAge; 
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `view`?: WithUsernameVerifiesCredentialsTotpEtc8;
    `sessionsEnded`?: integer
  },
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc411,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc411,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/signing-key",
  "get",
  #{
    `operationId`:"getSigningKeys",
    `tags`:#["Signing keys"],
    `summary`:"Your signing key pairs and TLS client certificates",
    `description`:"`profiles`: RFC 7523's JWT and RFC 7522's SAML key pairs — for each, `held.keys` (every key pair you hold, newest first: its `handle` — kid or thumbprint —, label, state, expiry and certificate), the issuers you may assert as, and `atCap` (you hold `maxPerPerson` valid ones, `pki.personSigningKeyMax`). `tls`: your TLS client certificates, where one signs you in, and what the form offers. `offered` (`pki.personSelfService`) and `issuable` (a certificate authority exists) say whether you may generate. No private key is ever in this answer.\n\nThe door of the portal's `GET /portal/signing-key`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/signing-key"
  })
op `getSigningKeys`(`responses/200/content/application~1json/schema`: WithUsernameEntryHoldsAnyEtc11,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

@js(#{
    `description`:"`generate` a signing key pair (for `purpose`) or `revoke` one of yours (by `handle`); `generate-tls-client` or `revoke-tls-client` a TLS client certificate."
  }) @hoisted union post_account_api_signing_key_b_application_json_action_h291 {
    EmptyText,
    "generate" | "revoke" | "generate-tls-client" | "revoke-tls-client"
  }

  

@js(#{`description`:"For `generate-tls-client`: the key algorithm."}) @hoisted union post_account_api_signing_key_b_application_json_key_alg_h293 {
    EmptyText,
    "rsa-2048" | "rsa-3072" | "ec-p256" | "ec-p384"
  }

  

@js(#{`description`:"For `revoke` and `revoke-tls-client`: why."}) @hoisted union post_account_api_signing_key_b_application_json_reason_h295 {
    EmptyText,
    "cessationOfOperation" | "keyCompromise"
  }

  

@js(#{
    `description`:"For `generate` and `revoke`: RFC 7523's `jwt` key pairs (the default) or RFC 7522's `saml` ones."
  }) @hoisted union post_account_api_signing_key_b_application_json_purpose_h297 {
    EmptyText,
    "jwt" | "saml"
  }

@endpoint("/account-api/signing-key",
  "post",
  #{
    `operationId`:"changeSigningKeys",
    `tags`:#["Signing keys"],
    `summary`:"Generates or revokes a signing key or TLS certificate",
    `description`:"`generate` ADDS a key pair for `purpose` from this realm's Issuing CA, named by `label` (refused at the cap); `revoke` revokes one of yours by `handle`, with `reason`: its certificate goes on the CRL and the key stops being accepted. `generate-tls-client` issues a TLS client certificate; `revoke-tls-client` revokes one of yours. Both generations answer the private key (unencrypted PKCS#8 PEM) and the certificate chain ONCE, in `view.fresh.files.key` and `view.fresh.files.chain` (base64). Both generations are refused (403) where self-service is off, and rate limited. A refusal carries the page's `view`.\n\nThe door of the portal's `POST /portal/signing-key`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many generations; try again later.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `500`:#{
        `description`:"Issued and then lost; nothing usable was kept.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/signing-key",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"revoke",`handle`:"no-such-id"}}}}
  })
op `changeSigningKeys`(`requestBody/content/application~1json/schema`: {
    `action`?: post_account_api_signing_key_b_application_json_action_h291;
    @js(#{
      `description`:"For `generate`: what you call the key pair. For `generate-tls-client`: what you call the device.",
      `maxLength`:80
    }) `label`?: string;
    @js(#{
      `description`:"For `revoke`: the key pair's `kid` (RFC 7523) or certificate thumbprint (RFC 7522), one of yours.",
      `maxLength`:128,
      `pattern`:"^[A-Za-z0-9_:-]*$"
    }) `handle`?: string;
    `key_alg`?: post_account_api_signing_key_b_application_json_key_alg_h293;
    @js(#{
      `description`:"For `revoke-tls-client`: the certificate's serial, one of yours.",
      `maxLength`:80,
      `pattern`:"^[0-9A-Fa-f:]*$"
    }) `serial`?: string;
    `reason`?: post_account_api_signing_key_b_application_json_reason_h295;
    `purpose`?: post_account_api_signing_key_b_application_json_purpose_h297
  },
  `responses/200/content/application~1json/schema`: {`stepUp`?: WithAcrValuesPromptMaxAge; 
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `view`?: WithUsernameEntryHoldsAnyEtc11
  },
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc417,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc417,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc417,
  `responses/500/content/application~1json/schema`: WithOkErrorsErrorEtc417,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/certificates",
  "get",
  #{
    `operationId`:"getCertificates",
    `tags`:#["Certificates"],
    `summary`:"Your certificates and the enrollment credentials you hold",
    `description`:"The certificates ACME, EST and SCEP issued for your entry, your ACME account binding keys and SCEP challenge passwords (never their secrets), the EST and SCEP profiles you may ask for, the host names registered on your entry, and the addresses of each family in this realm. A family turned off is null.\n\nThe door of the portal's `GET /portal/certificates`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/certificates"
  })
op `getCertificates`(`responses/200/content/application~1json/schema`: WithNameResolvedReasonsEtc12,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

@js(#{`description`:"What to do."}) @hoisted union post_account_api_certificates_b_application_json_action_h315 {
    EmptyText,
    "create-eab" | "delete-eab" | "create-challenge" | "delete-challenge" | "revoke"
  }

  

@js(#{`description`:"The profile a new SCEP challenge is for."}) @hoisted union post_account_api_certificates_b_application_json_profile_h317 {
    EmptyText,
    "tls-server" | "tls-client" | "tls-server-client" | "digital-signature" | "key-encipherment" | "code-signing" | "email" | "timestamping" | "smartcard-logon" | "device"
  }

  

@js(#{`description`:"The RFC 5280 reason for a revocation."}) @hoisted union post_account_api_certificates_b_application_json_reason_h319 {
    EmptyText,
    "unspecified" | "keyCompromise" | "affiliationChanged" | "superseded" | "cessationOfOperation"
  }

@endpoint("/account-api/certificates",
  "post",
  #{
    `operationId`:"changeCertificates",
    `tags`:#["Certificates"],
    `summary`:"Makes or deletes an enrollment credential, or revokes a certificate",
    `description`:"`create-eab` and `create-challenge` (rate limited) make an ACME account binding key or a SCEP challenge password for your entry; its secret is in the answer's `view.fresh`, ONCE. `delete-eab` and `delete-challenge` remove an unused one of yours; `revoke` revokes a certificate issued for you. Anything that is not yours is answered as not found.\n\nThe door of the portal's `POST /portal/certificates`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `404`:#{
        `description`:"You hold no such credential or certificate.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many made; try again later.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `500`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `503`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/certificates",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"delete-eab",`kid`:"no-such-id"}}}}
  })
op `changeCertificates`(`requestBody/content/application~1json/schema`: {
    `action`?: post_account_api_certificates_b_application_json_action_h315;
    @js(#{
      `description`:"The account binding key to delete.",
      `maxLength`:600,
      `pattern`:"^[A-Za-z0-9_-]*$"
    }) `kid`?: string;
    @js(#{
      `description`:"The challenge password to delete.",
      `maxLength`:600,
      `pattern`:"^[A-Za-z0-9_-]*$"
    }) `id`?: string;
    `profile`?: post_account_api_certificates_b_application_json_profile_h317;
    @js(#{
      `description`:"The serial of the certificate to revoke.",
      `maxLength`:80,
      `pattern`:"^[0-9A-Fa-f:]*$"
    }) `serial`?: string;
    `reason`?: post_account_api_certificates_b_application_json_reason_h319
  },
  `responses/200/content/application~1json/schema`: {`stepUp`?: WithAcrValuesPromptMaxAge; 
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `view`?: WithNameResolvedReasonsEtc12
  },
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc412,
  `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc412,
  `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc412,
  `responses/404/content/application~1json/schema`: WithOkErrorsErrorEtc412,
  `responses/409/content/application~1json/schema`: WithOkErrorsErrorEtc412,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc412,
  `responses/500/content/application~1json/schema`: WithOkErrorsErrorEtc412,
  `responses/503/content/application~1json/schema`: WithOkErrorsErrorEtc412,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/app-passwords",
  "get",
  #{
    `operationId`:"getAppPasswords",
    `tags`:#["App passwords"],
    `summary`:"Your app passwords, and the doors that need one",
    `description`:"Which of the five password-only doors refuse your own password (`doors`), the door table, the app passwords you hold (never their values), and whether making one is on.\n\nThe door of the portal's `GET /portal/app-passwords`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/app-passwords"
  })
op `getAppPasswords`(`responses/200/content/application~1json/schema`: WithUsernameDoorsDoorTableEtc10,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

@js(#{`description`:"`create` makes one; `revoke` ends the one `id` names."}) @hoisted union post_account_api_app_passwords_b_application_json_action_h377 {
    EmptyText,
    "create" | "revoke"
  }

  

@js(#{`description`:"Accept the new password at the ldap door."}) @hoisted union post_account_api_app_passwords_b_application_json_door_ldap_h379 {
    EmptyText,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

  

@js(#{`description`:"Accept the new password at the wstrust door."}) @hoisted union post_account_api_app_passwords_b_application_json_door_wstrust_h381 {
    EmptyText,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

  

@js(#{`description`:"Accept the new password at the scim door."}) @hoisted union post_account_api_app_passwords_b_application_json_door_scim_h383 {
    EmptyText,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

  

@js(#{`description`:"Accept the new password at the ssf door."}) @hoisted union post_account_api_app_passwords_b_application_json_door_ssf_h385 {
    EmptyText,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

  

@js(#{`description`:"Accept the new password at the est door."}) @hoisted union post_account_api_app_passwords_b_application_json_door_est_h387 {
    EmptyText,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

@endpoint("/account-api/app-passwords",
  "post",
  #{
    `operationId`:"changeAppPasswords",
    `tags`:#["App passwords"],
    `summary`:"Makes or revokes one of your app passwords",
    `description`:"`create` (rate limited) makes one for the doors whose `door_<id>` is on; the password is in the answer's `view.fresh`, ONCE. `revoke` ends the one `id` names; an id that is not yours is answered as not found.\n\nThe door of the portal's `POST /portal/app-passwords`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `404`:#{
        `description`:"You hold no app password with that id.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many made; try again later.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/app-passwords",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"revoke",`id`:"NOSUCHID"}}}}
  })
op `changeAppPasswords`(`requestBody/content/application~1json/schema`: {
    `action`?: post_account_api_app_passwords_b_application_json_action_h377;
    @js(#{
      `description`:"What the new password is for, in your words.",
      `maxLength`:200
    }) `name`?: string;
    @js(#{
      `description`:"The id of the app password to revoke.",
      `maxLength`:8,
      `pattern`:"^[A-Za-z2-7]*$"
    }) `id`?: string;
    `door_ldap`?: post_account_api_app_passwords_b_application_json_door_ldap_h379;
    `door_wstrust`?: post_account_api_app_passwords_b_application_json_door_wstrust_h381;
    `door_scim`?: post_account_api_app_passwords_b_application_json_door_scim_h383;
    `door_ssf`?: post_account_api_app_passwords_b_application_json_door_ssf_h385;
    `door_est`?: post_account_api_app_passwords_b_application_json_door_est_h387
  },
  `responses/200/content/application~1json/schema`: {`stepUp`?: WithAcrValuesPromptMaxAge; 
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `view`?: WithUsernameDoorsDoorTableEtc10
  },
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc49,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/404/content/application~1json/schema`: WithOkErrorsErrorEtc49,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc49,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/kerberos",
  "get",
  #{
    `operationId`:"getKerberos",
    `tags`:#["Kerberos"],
    `summary`:"Your Kerberos principal and its keys",
    `description`:"Whether this realm has a KDC and you are a principal in it, the principal, and in product mode the keys' kvno and encryption types; `disabled` for an account no keytab is made for.\n\nThe door of the portal's `GET /portal/kerberos`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/kerberos"
  })
op `getKerberos`(`responses/200/content/application~1json/schema`: WithKdcPersonPrincipalEtc7,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

@js(#{`description`:"`keytab`, the one thing this page does."}) @hoisted union post_account_api_kerberos_b_application_json_action_h399 {EmptyText, "keytab"}

@endpoint("/account-api/kerberos",
  "post",
  #{
    `operationId`:"makeKeytab",
    `tags`:#["Kerberos"],
    `summary`:"Makes you a keytab from your own password",
    `description`:"Re-proves the password (rate limited in the budget the password change shares), derives the keys from it and checks them against the KDC's. The keytab is in the answer's `view.made`, base64, ONCE: nothing can show it again. Nothing about the account changes.\n\nThe door of the portal's `POST /portal/kerberos`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts; try again later.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/kerberos",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"keytab",`current`:"not-the-password"}}}}
  })
op `makeKeytab`(`requestBody/content/application~1json/schema`: {
    `action`?: post_account_api_kerberos_b_application_json_action_h399;
    @js(#{
      `description`:"Your password: the keytab is derived from it, and it re-proves you.",
      `maxLength`:1024
    }) `current`?: string
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `view`?: WithKdcPersonPrincipalEtc7
  },
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc47,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc47,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/delegate",
  "get",
  #{
    `operationId`:"getDelegate",
    `tags`:#["Who may act for you"],
    `summary`:"Who may act for you",
    `description`:"`mayAct`, the DN named in your entry's stsMayAct (every access token about you carries it as RFC 8693 may_act), `delegate.kind` (`person` or `application`, null where the DN names no entry any more), and `notDelegated`, whether your account refuses delegation.\n\nThe door of the portal's `GET /portal/delegate`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/delegate"
  })
op `getDelegate`(`responses/200/content/application~1json/schema`: WithMayActDelegateNotDelegated,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

@js(#{`description`:"`set` names the delegate; `clear` removes it."}) @hoisted union post_account_api_delegate_b_application_json_action_h408 {
    EmptyText,
    "set" | "clear"
  }

@endpoint("/account-api/delegate",
  "post",
  #{
    `operationId`:"setDelegate",
    `tags`:#["Who may act for you"],
    `summary`:"Names, or clears, who may act for you",
    `description`:"Writes stsMayAct on your own entry: a person or an application of this realm, by DN. A token exchange presenting a token about you is then refused for any other actor.\n\nThe door of the portal's `POST /portal/delegate`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/delegate",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"clear"}}}}
  })
op `setDelegate`(`requestBody/content/application~1json/schema`: {
    `action`?: post_account_api_delegate_b_application_json_action_h408;
    @js(#{
      `description`:"The DN of a person or an application in this realm, for `action=set`.",
      `maxLength`:1024
    }) `delegate`?: string
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGo,
  `responses/400/content/application~1json/schema`: {
    `ok`: boolean;
    `errors`: (string)[];
    `error`?: string;
    `view`?: WithMayActDelegateNotDelegated
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/delegate/candidates",
  "get",
  #{
    `operationId`:"findDelegateCandidates",
    `tags`:#["Who may act for you"],
    `summary`:"Finds people you may name, by part of their username",
    `description`:"The people of this realm whose username (`uid`, the RDN value of their entry) contains `q`, at least three characters: native people only — never one a federation partner's or a consumer provider's sign-in created — and never you, a disabled account, a service account, a group or an application. At most ten, each `{ uid, cn, dn }` and nothing else; `more` says more matched, and a narrower `q` finds them. Naming one is POST /account-api/delegate with its `dn`.\n\nThe door of the portal's `GET /portal/delegate/candidates`.",
    `parameters`:#[
      #{
        `name`:"q",
        `in`:"query",
        `required`:true,
        `schema`:null,
        `description`:"Part of a username (`uid`), at least three characters. Matched as a contains against the RDN value of the people in this realm's `ou=users`.",
        `example`:"nob"
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Fewer than three characters (STS-PORTAL-0620).",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many searches in the window (STS-PORTAL-0621, or the rate limiter's own code).",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `503`:#{
        `description`:"The directory could not answer (STS-PORTAL-0622).",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/delegate/candidates"
  })
op `findDelegateCandidates`(@js(#{`maxLength`:256}) `parameters/0/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `query`?: string;
    @js(#{`description`:"At most ten."}) `people`?: ({`uid`?: string; `cn`?: string; `dn`?: string})[];
    `more`?: boolean
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/503/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@hoisted union get_account_api_self_issued_p1_h413 {
    EmptyText,
    "published" | "authorized" | "changed"
  }

  

  

@hoisted union get_account_api_self_issued_p2_h416 {
    EmptyText,
    StringMatchinga3848a
  }

@endpoint("/account-api/self-issued",
  "get",
  #{
    `operationId`:"getSelfIssued",
    `tags`:#["Self-issued IDs"],
    `summary`:"The wallet keys that sign you in with SIOPv2",
    `description`:"`subjects`: each enrolled self-issued subject (a DID or a JWK thumbprint), its label, when and by whom it was enrolled, and how (`proof`: `wallet`, proved by you, or `admin`, by an administrator), whether it is your preferred DID (`preferred`, #693), and where the key came from (`location`: `{ kind, value }` — `web`, the web wallet at that address; `app`, a wallet app, by the name it reported or ''; `dc_api`, your browser, by its origin or ''; `admin`; or null, not recorded), and where its DID document is (`didDocumentUrl`, a did:web's published address, or `didResolved`, a did:jwk or did:key resolved from the identifier at /portal/self-issued/did). `enabled`: whether the self-issued sign-in is on; `turnOn`, where it is off: the setting (`setting`) and environment variable (`env`) that turn it on, whether you may change it (`administrator`: you hold Admin Write in this realm) and, if you may, the console page that does (`page`); null where it is on. `didClaim`: whether the preferred DID may be released as the `did` claim here. A key is enrolled by proving it, at /authn/wallet?siop=1&enrol=1, which comes back with `enrolled=1`; `notice` then says so. Where the directory holds no entry for the person the token names it is refused (STS-PORTAL-0616) rather than answered as an empty list. `published` (#1291): whether this realm publishes a did:web for you (`enabled`), who holds its key (`custody`: `wallet`, `realm` or `download`), how many you may hold (`maxPerPerson`) and hold now (`active`), whether you may publish one more (`canPublish`), and each one you hold (`dids`): its `rid`, `did`, `documentUrl`, `custody`, `state` (`active`, `deactivated`), `proof`, `preferred`, `currentVersion`, any change waiting for its new key (`pending`) and its `versions`, each with its keys and what authorized it. A wallet act that just finished comes back with `did` (`published`, `authorized` or `changed`), and `notice` says so.\n\nThe door of the portal's `GET /portal/self-issued`.",
    `parameters`:#[
      #{
        `name`:"enrolled",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"`1` when the wallet sign-in has just enrolled a subject.",
        `example`:"1"
      },
      #{
        `name`:"did",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"A published DID's wallet act that has just finished (#1291): `published`, `authorized` (the change's first proof; prove the new key next) or `changed`."
      },
      #{
        `name`:"rid",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The published DID that act was about."
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `404`:#{
        `description`:"The directory holds no entry for the token's person (STS-PORTAL-0616).",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/self-issued"
  })
op `getSelfIssued`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`enum`:#["1"]}]}}) `parameters/0/schema`: unknown,
  @js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`enum`:#["published","authorized","changed"]}]}}) `parameters/1/schema`: unknown,
  @js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`pattern`:"^[A-Za-z0-9_-]{22}(?:[A-Za-z0-9_-]{12})?$"}]}}) `parameters/2/schema`: unknown,
  `responses/200/content/application~1json/schema`: WithEnabledTurnOnLoginHintEtc8,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/404/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

@js(#{
    `description`:"`remove` (the default) takes the subject off; `prefer` marks it as your preferred DID (#693), and `unprefer` clears the mark."
  }) @hoisted union post_account_api_self_issued_b_application_json_action_h422 {
    EmptyText,
    "remove" | "prefer" | "unprefer"
  }

@endpoint("/account-api/self-issued",
  "post",
  #{
    `operationId`:"removeSelfIssued",
    `tags`:#["Self-issued IDs"],
    `summary`:"Removes a self-issued subject of yours, or marks one as your preferred DID",
    `description`:"`remove` (the default): the subject no longer signs you in. One that is not enrolled for you is refused. `prefer` (#693): marks one DID you PROVED with your wallet as your preferred one — the one a client you consent to may be told as the `did` claim, where the realm releases it (`oauth2.didClaim`); a subject an administrator added, or a JWK thumbprint, is refused (STS-PORTAL-0615). `unprefer` clears the mark. Removing the preferred subject clears it too.\n\nThe door of the portal's `POST /portal/self-issued`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/self-issued",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"remove",`subject`:"did:jwk:no-such-subject"}}}}
  })
op `removeSelfIssued`(`requestBody/content/application~1json/schema`: {
    `action`?: post_account_api_self_issued_b_application_json_action_h422;
    @js(#{`maxLength`:2048,`description`:"The enrolled subject, from the list."}) `subject`: string
  },
  `responses/200/content/application~1json/schema`: WithStepUpOkMessageEtc5,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc413,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@hoisted union get_account_api_self_issued_did_p0_h433 {
    EmptyText,
    StringMax2048
  }

@endpoint("/account-api/self-issued/did",
  "get",
  #{
    `operationId`:"getSelfIssuedDidDocument",
    `tags`:#["Self-issued IDs"],
    `summary`:"The DID document of one of your enrolled did:jwk or did:key subjects",
    `description`:"`document`: the DID document of `subject`, resolved from the identifier itself — a did:jwk or did:key is its own document, so nothing is published and nothing is fetched. Only a subject enrolled for you: any other is refused (STS-PORTAL-0618), and a did:web (its document is the one published at its address, linked from the list) or a JWK thumbprint (no DID) is refused (STS-PORTAL-0619). With no `subject`, `{ subject: '', document: null }`.\n\nThe door of the portal's `GET /portal/self-issued/did`.",
    `parameters`:#[
      #{
        `name`:"subject",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"One of your enrolled self-issued subjects: a did:jwk or a did:key. Left out, the page says to choose one.",
        `example`:"did:jwk:no-such-subject"
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"A did:web or a JWK thumbprint, whose document is not the identifier (STS-PORTAL-0619).",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `404`:#{
        `description`:"Not one of your enrolled subjects (STS-PORTAL-0618).",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/self-issued/did"
  })
op `getSelfIssuedDidDocument`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`maxLength`:2048}]}}) `parameters/0/schema`: unknown,
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `subject`?: string;
    @js(#{
      `x-free-form`:"A DID document as the DID's method resolved it (W3C DID Core), or null: its verification methods and services are the DID controller's to state.",
      `description`:"A DID document as the DID's method resolved it (W3C DID Core), or null: its verification methods and services are the DID controller's to state."
    }) `document`?: unknown
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/404/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@js(#{
    `description`:"The published DID's random id, from the list; every action but `publish` names one."
  }) @hoisted union post_account_api_self_issued_dids_b_application_json_rid_h436 {
    EmptyText,
    StringMatchinga3848a
  }

@endpoint("/account-api/self-issued/dids",
  "post",
  #{
    `operationId`:"actOnPublishedDid",
    `tags`:#["Self-issued IDs"],
    `summary`:"Publishes a did:web for you, changes its key, or deactivates it",
    `description`:"A did:web this realm publishes for you (#1291), where it does (`did.personPublishing`). `publish`: a new DID whose key this realm generates — kept sealed in `realm` custody, or answered ONCE as `view.fresh.file` (a private JWK) in `download` custody and never kept. In `wallet` custody a DID is published, and its key changed, by proving keys with your wallet at /authn/wallet?siop=1&enrol=1&did_act=…, and this act refuses those (STS-VC-0173). `add-key` and `rotate-key` of a `realm`-custody DID append a version with a newly generated key, beside or instead of the current ones. `deactivate` ends one: its address answers 410 Gone for good, its history stays resolvable, and it no longer signs you in, nor is it preferred or released. Refusals carry the library's code (STS-VC-0167 to STS-VC-0176).\n\nThe door of the portal's `POST /portal/self-issued/dids`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: publishing is off, no pinned base in product mode, the cap, the custody, no such DID, or not stored (STS-VC-0167 to STS-VC-0176).",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/self-issued/dids",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"deactivate",`rid`:"AAAAAAAAAAAAAAAAAAAAAA"}}}}
  })
op `actOnPublishedDid`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `description`:"`publish` a DID whose key this realm generates (`realm` or `download` custody); `add-key` or `rotate-key` of a `realm`-custody DID; `deactivate` one of your DIDs."
    }) `action`: "publish" | "add-key" | "rotate-key" | "deactivate";
    `rid`?: post_account_api_self_issued_dids_b_application_json_rid_h436
  },
  `responses/200/content/application~1json/schema`: WithStepUpOkMessageEtc5,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc413,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/credentials/offerable",
  "get",
  #{
    `operationId`:"getOfferableCredentials",
    `tags`:#["Wallet"],
    `summary`:"The credentials you can put into your own wallet",
    `description`:"`configurations`: each credential configuration this realm's OpenID4VCI issuer offers — its `credential_configuration_id` (`id`), its format, the name its metadata gives it, and whether it names the issuer by DID. `modes`: the two pre-authorized offers, `cross-device` (Appendix H.2) and `deferred` (H.3). `lifetimeSeconds`: how long an offer and its code are honoured (`oid4vci.offerTtlS`). `wallet`: the configured web wallet a link opens, or empty. `batchSize`: how many copies of a credential one issuance gives your wallet, each bound to a different key of the wallet's (`oid4vci.batchSize`, OpenID4VCI 1.0 section 8.2). `issued`: the credentials this realm still records as issued to you, ONE PER ISSUANCE, newest first — each one's `id`, configuration, when it was issued and expires, its `status` (`valid`, `suspended`, `revoked`, `removed` by you, `signed-out` by a global sign-out, `expired`, or `mixed` where its copies differ, with `counts`), whether you can remove it, the last event your wallet reported to the Notification Endpoint (OpenID4VCI 1.0 section 11), and its `copies`: each one's own `id`, `position` of `of`, state, the RFC 7638 thumbprint of the wallet key it is bound to (`keyThumbprint`), the holder's DID where it is DID-bound, and its `statusIndex`. `issued` is one page of issuances (`paging`, moved by `page`, 20 to a page); `paging.total` counts them all. A token whose `sub` and person do not name each other is refused (STS-PORTAL-0617) rather than shown somebody else's history, or nobody's as an empty one.\n\nThe door of the portal's `GET /portal/wallet`.",
    `parameters`:#[
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `issued`, newest first. Clamped to the last.",
        `example`:1
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/wallet"
  })
op `getOfferableCredentials`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/0/schema`: unknown,
  `responses/200/content/application~1json/schema`: WithConfigurationsModesLifetimeSecondsEtc8,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/credentials/offers",
  "post",
  #{
    `operationId`:"createCredentialOffer",
    `tags`:#["Wallet"],
    `summary`:"Makes a Credential Offer for your own wallet",
    `description`:"A pre-authorized Credential Offer (OpenID4VCI section 4.1, Appendix H.2 or H.3) of one configuration, about YOU — the token's person; nobody else can be named. Answered once, in place: `offer.credentialOffer`, the offer by value (`offer.byValue.offerUri`, an `openid-credential-offer://` URI, and `walletUrl`, the configured web wallet's link) and by reference (`offer.byReference`, whose `offerUri` is short enough for a QR code, e.g. `openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fsts.example%2Foid4vci%2Fcredential-offer%2F3q2-7w...`), when the offer and its code stop being honoured (`expiresAt`), and the Transaction Code (`txCode`, e.g. `40317`) the wallet will ask for — shown to you, never carried in the offer. The offer is made on the sign-on session your token was issued on, which is reported over CAEP as session-presented (OpenID4VCI). The same `offer` is in `view`, for the page. `signingAlg`, optional, is the algorithm the credential is signed with — one of the configuration's `signingAlgs` in the GET, the post-quantum ML-DSA, SLH-DSA and composite drafts among them for the JOSE formats; left out, the configured default.\n\nThe door of the portal's `POST /portal/wallet`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The configuration is not one this issuer offers (STS-PORTAL-0589), or its credentials are not signed with the `signingAlg` asked for (STS-PORTAL-0592).",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/wallet",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`configuration`:"no-such-id",`mode`:"cross-device"}}}}
  })
op `createCredentialOffer`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `minLength`:1,
      `maxLength`:2048,
      `description`:"The `credential_configuration_id` to offer, one of `GET /account-api/credentials/offerable`'s."
    }) `configuration`: string;
    @js(#{
      `description`:"`cross-device` (Appendix H.2: issued as soon as the wallet asks) or `deferred` (H.3: the credential endpoint answers a `transaction_id` first)."
    }) `mode`: "cross-device" | "deferred";
    @js(#{
      `description`:"The algorithm the credential is signed with, one of the configuration's `signingAlgs`; left out or empty, the configured `oid4vci.credentialSigningAlgorithm`.",
      `maxLength`:64
    }) `signingAlg`?: string;
    `page`?: EmptyTextOrIntegerFrom1To1000004
  },
  `responses/200/content/application~1json/schema`: {`stepUp`?: {`acrValues`?: string; `prompt`?: string; `maxAge`?: numeric}; 
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `offer`?: WithConfigurationIdSigningAlgModeEtc8;
    `view`?: WithConfigurationsModesLifetimeSecondsEtc8
  },
  `responses/400/content/application~1json/schema`: {
    `ok`: boolean;
    `errors`: (string)[];
    `error`?: string;
    `view`?: WithConfigurationsModesLifetimeSecondsEtc8
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/403/content/application~1json/schema`: {
    `ok`: boolean;
    `errors`: (string)[];
    `error`?: string;
    `view`?: WithConfigurationsModesLifetimeSecondsEtc8
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/credentials/remove",
  "post",
  #{
    `operationId`:"removeIssuedCredential",
    `tags`:#["Wallet"],
    `summary`:"Removes a credential issued to you: every copy, or one",
    `description`:"The credential named by its `id` is revoked. An issuance's `id` (from `issued`) names every copy of it — with batch issuance one issuance gives your wallet several copies, each bound to a different key — and removes each copy still good; a copy's `id` (from that issuance's `copies`) removes that copy alone and leaves the others as they are. Each copy removed has its Token Status List entry set INVALID, which is final and what a verifier reads, is marked revoked in the issued register and no longer signs you in; your relying parties are told once over CAEP (credential-change, revoke). It is NOT deleted from your wallet: neither OpenID4VP nor OpenID4VCI lets an issuer do that, so delete it in the wallet yourself. Only a credential of yours can be named; removing one already removed is answered as done. `scope` says what the id named and `removed` how many copies this act removed; the page's `view` is in the answer.\n\nThe door of the portal's `POST /portal/remove-wallet-credential`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"No credential or issuance of yours has that id (STS-PORTAL-0591).",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/remove-wallet-credential",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`id`:"no-such-id"}}}}
  })
op `removeIssuedCredential`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `minLength`:1,
      `maxLength`:64,
      `description`:"An issuance's `id`, from `issued` in `GET /account-api/credentials/offerable`, which removes every copy of it; or one copy's, from its `copies`, which removes that copy alone."
    }) `id`: string;
    `page`?: EmptyTextOrIntegerFrom1To1000004
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `scope`?: string;
    `removed`?: integer;
    `view`?: WithConfigurationsModesLifetimeSecondsEtc8
  },
  `responses/400/content/application~1json/schema`: {
    `ok`: boolean;
    `errors`: (string)[];
    `error`?: string;
    `view`?: WithConfigurationsModesLifetimeSecondsEtc8
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/devices",
  "get",
  #{
    `operationId`:"getDevices",
    `tags`:#["Devices"],
    `summary`:"Your devices, and how to register one",
    `description`:"Each device you own: its applications, whether its Native SSO secret is live, its keys and their attestation, how it was registered and when it was last used. Then the key-proof step (`proof`: the challenge held, with the `audience` and `proofTyp` a proof names), the passkeys built into a device that can be linked (`link`) or the link ceremony armed (`linking`), and whether this browser may be remembered.\n\nThe door of the portal's `GET /portal/devices`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/devices"
  })
op `getDevices`(`responses/200/content/application~1json/schema`: WithDevicesPlatformsProofEtc8,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

@js(#{`description`:"What to do; `remove` where none is named."}) @hoisted union post_account_api_devices_b_application_json_action_h520 {
    EmptyText,
    "remove" | "challenge" | "prove" | "cancel-proof" | "link-begin" | "link-finish" | "link-cancel" | "remember-browser"
  }

@endpoint("/account-api/devices",
  "post",
  #{
    `operationId`:"actOnDevices",
    `tags`:#["Devices"],
    `summary`:"Registers, links, remembers or removes a device",
    `description`:"`challenge` then `prove` registers a device by a key proof (or an App Attest object); `link-begin` then `link-finish` links a passkey built into it by a fresh assertion; `remember-browser` remembers this browser (a cookie on the answer); `remove` removes a device and its Native SSO secret. A refusal carries the page's `view`.\n\nThe door of the portal's `POST /portal/devices`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/devices",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"remove",`id`:"no-such-id"}}}}
  })
op `actOnDevices`(`requestBody/content/application~1json/schema`: {
    `action`?: post_account_api_devices_b_application_json_action_h520;
    @js(#{`description`:"`remove`: the device.",`maxLength`:64}) `id`?: string;
    @js(#{
      `description`:"`prove`, `link-finish`: the challenge being answered.",
      `maxLength`:128
    }) `challenge`?: string;
    @js(#{
      `description`:"`prove`: the device-key-proof+jwt JWS.",
      `maxLength`:65536
    }) `proof`?: string;
    @js(#{
      `description`:"`prove`: an App Attest key id, beside its object.",
      `maxLength`:128
    }) `app_attest_key_id`?: string;
    @js(#{
      `description`:"`prove`: an App Attest attestation object.",
      `maxLength`:65536
    }) `app_attest_object`?: string;
    @js(#{
      `description`:"`prove`, `link-begin`: an existing device to add the key to; a new device where empty.",
      `maxLength`:64
    }) `device`?: string;
    @js(#{
      `description`:"`link-begin`: the passkey (built into this device) to link.",
      `maxLength`:1400
    }) `credential_id`?: string;
    @js(#{
      `description`:"`link-finish`: the WebAuthn assertion, as JSON.",
      `maxLength`:65536
    }) `credential`?: string;
    @js(#{`description`:"The device's name.",`maxLength`:128}) `label`?: string;
    @js(#{`description`:"`prove`: the key's name.",`maxLength`:128}) `key_label`?: string;
    @js(#{`description`:"The device's platform.",`maxLength`:32}) `platform`?: string;
    @js(#{`description`:"The device's model.",`maxLength`:128}) `model`?: string;
    @js(#{`description`:"The device's operating system.",`maxLength`:128}) `os`?: string
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGo,
  `responses/400/content/application~1json/schema`: {
    `ok`: boolean;
    `errors`: (string)[];
    `error`?: string;
    `view`?: WithDevicesPlatformsProofEtc8
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/devices/challenge",
  "post",
  #{
    `operationId`:"deviceChallenge",
    `tags`:#["Devices"],
    `summary`:"A key-proof challenge, for a device app",
    `description`:"Issues a challenge bound to the sign-on session this token was issued on: `{ ok, challenge, audience, typ, expires_at, proof_endpoint }`. The device signs a JWS of type `typ` over `{ nonce: challenge, aud: audience, iat }` with the key it registers, and posts it to `proof_endpoint`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`purpose`:"key"}}}}
  })
op `deviceChallenge`(`requestBody/content/application~1json/schema`: {
    @js(#{`description`:"What the challenge is for; `key`, the only one."}) `purpose`?: "key"
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `challenge`?: string;
    `audience`?: string;
    `typ`?: string;
    `expires_at`?: Shape;
    `proof_endpoint`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/devices/proof",
  "post",
  #{
    `operationId`:"deviceProof",
    `tags`:#["Devices"],
    `summary`:"A device app's key proof",
    `description`:"Answers a challenge with a key proof or an Apple App Attest object, registering the device (or adding the key to `device_id`). Answers 201 `{ ok, device, key }`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `201`:#{
        `description`:"The device is registered: `{ ok, device, key }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`challenge`:"no-such-id",`proof`:"not-a-proof"}}}}
  })
op `deviceProof`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `minLength`:1,
      `maxLength`:128,
      `description`:"The challenge `devices/challenge` issued."
    }) `challenge`: string;
    @js(#{`description`:"The device-key-proof+jwt JWS.",`maxLength`:65536}) `proof`?: string;
    @js(#{`description`:"Or an Apple App Attest key and object.",`$open`:true}) `app_attest`?: {
      @js(#{`maxLength`:128}) `key_id`: string;
      @js(#{`maxLength`:65536}) `attestation`: string
    };
    @js(#{
      `description`:"An existing device of yours to add the key to.",
      `maxLength`:64
    }) `device_id`?: string;
    @js(#{`maxLength`:128}) `label`?: string;
    @js(#{`maxLength`:128}) `key_label`?: string;
    @js(#{`maxLength`:32}) `platform`?: string;
    @js(#{`maxLength`:128}) `model`?: string;
    @js(#{`maxLength`:128}) `os`?: string
  },
  `responses/200/content/application~1json/schema`: WithOkDeviceKey,
  `responses/201/content/application~1json/schema`: WithOkDeviceKey,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@js(#{
    `items`:#{
      `type`:"object",
      `additionalProperties`:false,
      `properties`:#{`name`:#{`type`:"string"},`value`:#{`type`:"string"}}
    },
    `$types`:#["array","null"]
  }) @hoisted model get_account_api_ciba_r200_application_json_requests_i_requestContext_h530 {}

@endpoint("/account-api/ciba",
  "get",
  #{
    `operationId`:"getSignInRequests",
    `tags`:#["Sign-in requests"],
    `summary`:"The sign-in requests waiting for you, and your user code",
    `description`:"The CIBA requests a client made to sign you in elsewhere (each with its binding message, scopes, requested acr values and expiry), whether you have a CIBA user code, and the GNAP grants waiting for you as their owner — each right with `field` (the checkbox value) and `limitsHtml` (its limit controls). With `stepup` or `gnapstepup` the answer is only `stepUp`: sign in again with `acrValues`, `prompt=login`.\n\nThe door of the portal's `GET /portal/ciba`.",
    `parameters`:#[
      #{
        `name`:"stepup",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"A CIBA request id: answered `stepUp`, the sign-in again its acr values need.",
        `example`:"no-such-id"
      },
      #{
        `name`:"gnapstepup",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"A waiting GNAP request id: answered `stepUp`, the sign-in again its rights need."
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/ciba"
  })
op `getSignInRequests`(@js(#{`maxLength`:256}) `parameters/0/schema`: string,
  @js(#{`maxLength`:256}) `parameters/1/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `enabled`?: boolean;
    `requests`?: ({
      `id`?: string;
      `clientName`?: NullableString;
      `bindingMessage`?: string;
      `requestContext`?: get_account_api_ciba_r200_application_json_requests_i_requestContext_h530;
      `scope`?: NullableString;
      `acrValues`?: (string)[];
      `expiresAt`?: Shape
    })[];
    `hasCode`?: boolean;
    `gnap`?: ({
      `id`?: string;
      `display`?: NullableString;
      `client`?: NullableString;
      `declared`?: boolean;
      `requestedBy`?: string;
      `acr`?: (string)[];
      `subject`?: boolean;
      `expiresAt`?: Shape;
      `rights`?: ({
        `field`?: string;
        `limitsHtml`?: string;
        `reference`?: string;
        `type`?: string;
        `parts`?: string
      })[]
    })[];
    `stepUp`?: WithAcrValuesPromptMaxAge
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@js(#{`description`:"The GNAP rights ticked.",`$comb`:"oneOf"}) @hoisted union post_account_api_ciba_b_application_json_right_h536 {string, (string)[]}

@endpoint("/account-api/ciba",
  "post",
  #{
    `operationId`:"answerSignInRequest",
    `tags`:#["Sign-in requests"],
    `summary`:"Sets your user code, or answers a request",
    `description`:"A JSON body: `action` — `set-code` (with `code`), `clear-code`, `approve` / `deny` (with the CIBA request's `id`), or `gnap-approve` / `gnap-deny` (with the GNAP request's `id`, the ticked `right` values, `subject: \"yes\"`, and any `lim_t<k>r<r>_<member>` limit controls lowered). An approval stronger than the sign-on session proved is refused 403 with `stepUp`.\n\nThe door of the portal's `POST /portal/ciba`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/ciba",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"deny",`id`:"no-such-id"}}}}
  })
op `answerSignInRequest`(@js(#{
    `patternProperties`:#{
      `^lim_t[0-9]+r[0-9]+_[A-Za-z]+$`:#{`description`:"A limit control lowered on one right."}
    },
    `$open`:true
  }) `requestBody/content/application~1json/schema`: {
    `action`: "set-code" | "clear-code" | "approve" | "deny" | "gnap-approve" | "gnap-deny";
    @js(#{`description`:"The request's id."}) `id`?: string;
    @js(#{`description`:"Your user code."}) `code`?: string;
    `right`?: post_account_api_ciba_b_application_json_right_h536;
    @js(#{`description`:"Release your identity (GNAP)."}) `subject`?: "yes"
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGo,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/403/content/application~1json/schema`: {
    `ok`: boolean;
    `errors`: (string)[];
    `error`?: string;
    `stepUp`?: WithAcrValuesPromptMaxAge
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/access-requests",
  "get",
  #{
    `operationId`:"getAccessRequests",
    `tags`:#["Access requests"],
    `summary`:"The AuthZEN access requests waiting for you to decide",
    `description`:"The pending access requests (#1180) whose denying policy named you an approver — its approver role, its approver group, or the application's owners — and that the access-control policy lets you decide: each with who it is about, what it asks to do to what, through which PEP and application, and until when it waits. `enabled` is false where the realm has the profile off.\n\nThe door of the portal's `GET /portal/access-requests`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/access-requests"
  })
op `getAccessRequests`(`responses/200/content/application~1json/schema`: WithEnabledRows,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/access-requests",
  "post",
  #{
    `operationId`:"decideAccessRequest",
    `tags`:#["Access requests"],
    `summary`:"Approves or denies an AuthZEN access request",
    `description`:"Decides one request as you, after the access-control policy (action approve-access-request on resource authzen-access-request) said you may: an approval is handed to the PEP to carry on its next evaluation, which the realm's policy decides afresh; a denial ends the request. Refused for a request you may not decide, your own included where the policy forbids self-approval, and for one no longer pending.\n\nThe door of the portal's `POST /portal/access-requests`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/access-requests",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`request`:"no-such-id",`action`:"deny"}}}}
  })
op `decideAccessRequest`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `minLength`:1,
      `maxLength`:128,
      `pattern`:"^[A-Za-z0-9_-]+$",
      `description`:"The access request, from the list."
    }) `request`: string;
    @js(#{`description`:"approve or deny."}) `action`: "approve" | "deny"
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGo,
  `responses/400/content/application~1json/schema`: {
    `ok`: boolean;
    `errors`: (string)[];
    `error`?: string;
    `view`?: WithEnabledRows
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/device",
  "get",
  #{
    `operationId`:"getDeviceRequest",
    `tags`:#["Sign in a device"],
    `summary`:"The device request a user code brings up",
    `description`:"RFC 8628 section 3.3. With no `user_code`, only whether the flow is on. With one, the waiting request — the client and the scopes — so that you see what you would approve before approving it (section 5.4). Five codes that match nothing lock the sign-on session out for ten minutes (section 5.1).\n\nThe door of the portal's `GET /portal/device`.",
    `parameters`:#[
      #{
        `name`:"user_code",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The code the device shows; brings up its request.",
        `example`:"NOSUCHCODE"
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `404`:#{
        `description`:"No device is waiting with that code.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many codes that matched nothing.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/device"
  })
op `getDeviceRequest`(@js(#{`maxLength`:32}) `parameters/0/schema`: string,
  `responses/200/content/application~1json/schema`: WithEnabledTypedRecord,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/404/content/application~1json/schema`: WithOkErrorsErrorEtc42,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc42,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/device",
  "post",
  #{
    `operationId`:"answerDeviceRequest",
    `tags`:#["Sign in a device"],
    `summary`:"Approves or denies a device sign-in",
    `description`:"An approval issues the device tokens for you, on the sign-on session this token was issued on, which ends them when it ends.\n\nThe door of the portal's `POST /portal/device`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many codes that matched nothing.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/device",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"deny",`user_code`:"NOSUCHCODE"}}}}
  })
op `answerDeviceRequest`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `description`:"`approve` signs you in on the device; `deny` refuses it."
    }) `action`: "approve" | "deny";
    @js(#{
      `minLength`:1,
      `maxLength`:32,
      `description`:"The code the device shows."
    }) `user_code`: string
  },
  `responses/200/content/application~1json/schema`: WithOkMessageGo,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc42,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc42,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/claim-sources",
  "get",
  #{
    `operationId`:"getClaimSources",
    `tags`:#["Claim sources"],
    `summary`:"The Claims Providers you can link, and your links",
    `description`:"`providers`: one page (`paging`, moved by `page`) of the Claims Providers this realm registered — each one's id, name, issuer, the claims it supplies and whether they are aggregated or distributed — with your `link` (when, and whether it has gone `stale`) or null. `linked` counts your links over every page. `done` and `problem`, which the provider's callback sends back, come back as `notice` and `problem`.\n\nThe door of the portal's `GET /portal/claim-sources`.",
    `parameters`:#[
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which page of `providers`. Clamped to the last."
      },
      #{
        `name`:"done",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"What a finished link said, from the callback.",
        `example`:"example"
      },
      #{
        `name`:"problem",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Why a link could not be finished, from the callback."
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/claim-sources"
  })
op `getClaimSources`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"integer",`minimum`:1,`maximum`:100000}]}}) `parameters/0/schema`: unknown,
  @js(#{`maxLength`:200}) `parameters/1/schema`: string,
  @js(#{`maxLength`:400}) `parameters/2/schema`: string,
  `responses/200/content/application~1json/schema`: WithProvidersPagingLinkedEtc5,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/claim-sources",
  "post",
  #{
    `operationId`:"linkClaimSource",
    `tags`:#["Claim sources"],
    `summary`:"Links or unlinks a Claims Provider",
    `description`:"`link` answers `location`, the provider's authorization endpoint (code flow with PKCE): send the browser there. The answer sets the `sts_claim_link` cookie, scoped to /portal/claim-sources/callback, which finishes the link only in the browser holding it, while the sign-on session this token was issued on is live. `unlink` removes the link.\n\nThe door of the portal's `POST /portal/claim-sources`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/claim-sources",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"unlink",`id`:"no-such-id"}}}}
  })
op `linkClaimSource`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `description`:"`link` starts the provider's sign-in; `unlink` removes the link."
    }) `action`: "link" | "unlink";
    @js(#{`maxLength`:64,`description`:"The Claims Provider's id."}) `id`: string
  },
  `responses/200/content/application~1json/schema`: {`ok`?: boolean; `message`?: string; `go`?: string; `location`?: string},
  `responses/400/content/application~1json/schema`: {
    `ok`: boolean;
    `errors`: (string)[];
    `error`?: string;
    `view`?: WithProvidersPagingLinkedEtc5
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/connected-accounts",
  "get",
  #{
    `operationId`:"getConnectedAccounts",
    `tags`:#["Connected accounts"],
    `summary`:"The consumer providers you can connect, and yours",
    `description`:"`providers`: every consumer or social provider this realm offers (#565), each one's relationship id, name and provider, and whether your account is `connected` to it. `done` and `problem`, which a provider's return sends back, come back as `notice` and `problem`.\n\nThe door of the portal's `GET /portal/connected-accounts`.",
    `parameters`:#[
      #{
        `name`:"done",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The provider a finished connect connected, from its return.",
        `example`:"example"
      },
      #{
        `name`:"problem",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Why a connect could not be finished, from its return."
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"GET /portal/connected-accounts"
  })
op `getConnectedAccounts`(@js(#{`maxLength`:200}) `parameters/0/schema`: string,
  @js(#{`maxLength`:400}) `parameters/1/schema`: string,
  `responses/200/content/application~1json/schema`: WithProvidersConnectedNoticeEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

@endpoint("/account-api/connected-accounts",
  "post",
  #{
    `operationId`:"connectAccount",
    `tags`:#["Connected accounts"],
    `summary`:"Connects or disconnects a consumer provider",
    `description`:"`connect` answers `location`, the provider's authorization address: send the browser there. It needs a sign-on session whose risk is LOW or unscored, and an authentication within federation.connectRecentAuthMinutes — otherwise the answer is `stepUp`, a sign-in again. The answer sets the `sts_fed_link` cookie, which finishes the connect only in the browser holding it. `disconnect` removes your connection and ends the sessions it started; it is refused (409) while the connection is your only way to sign in — no password, passkey or other connection.\n\nThe door of the portal's `POST /portal/connected-accounts`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"No access token, or one that does not verify, has expired, was revoked, outlived its sign-on session, or came without its DPoP proof. `WWW-Authenticate` says which.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The token is for another audience or does not carry `account:manage`, or the access policy refused the person.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[#{`portal`:#["account:manage"]}],
    `x-access`:"person",
    `x-mirrors`:"POST /portal/connected-accounts",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"disconnect",`id`:"no-such-id"}}}}
  })
op `connectAccount`(`requestBody/content/application~1json/schema`: {
    @js(#{
      `description`:"`connect` starts the provider's sign-in; `disconnect` removes the connection."
    }) `action`: "connect" | "disconnect";
    @js(#{`maxLength`:64,`description`:"The provider relationship's id."}) `id`: string
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `location`?: string;
    `stepUp`?: WithAcrValuesPromptMaxAge
  },
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc410,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/401/content/application~1json/schema`: WithOkErrorsErrorEtc4,
  `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc410,
  `responses/409/content/application~1json/schema`: WithOkErrorsErrorEtc410,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/activation",
  "get",
  #{
    `operationId`:"getActivation",
    `tags`:#["Activation"],
    `summary`:"Checks an activation link and answers the setup form",
    `description`:"Takes no token: the link's `user` and `token` are the credential. Spends nothing — a link opened by a prefetch or a mail scanner still works. Rate limited. Every failure answers the same sentence. The answer is the first step: the password rules, whether a passkey and an authenticator app are offered, and whether a passkey may be the only way in (`passkeyAlone`, #1135).\n\nThe door of the portal's `GET /portal/activate`.",
    `parameters`:#[
      #{
        `name`:"user",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The username the link names.",
        `example`:"nobody-example"
      },
      #{
        `name`:"X-Link-Token",
        `in`:"header",
        `required`:false,
        `schema`:null,
        `description`:"The single-use secret the link carried in its fragment."
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-access`:"link",
    `x-mirrors`:"GET /portal/activate"
  })
op `getActivation`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`minLength`:1,`maxLength`:256}]}}) `parameters/0/schema`: unknown,
  `parameters/1/schema`: string,
  `responses/200/content/application~1json/schema`: WithStepUserTokenEtc22,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc415,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc415,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

  

  

@js(#{`description`:"The link's single-use token."}) @hoisted union post_account_api_activation_b_application_json_token_h587 {
    EmptyText,
    StringMin1Max4096Matchingfb79a8
  }

  

@js(#{`description`:"`setup`: `1` registers a passkey."}) @hoisted union post_account_api_activation_b_application_json_passkey_h589 {
    EmptyText,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

  

@js(#{
    `description`:"Before #1135: `primary` or `mfa` registers a passkey, `none` does not; `passkey` says the same."
  }) @hoisted union post_account_api_activation_b_application_json_key_role_h591 {
    EmptyText,
    "none" | "primary" | "mfa"
  }

  

@js(#{`description`:"`1`: set up an authenticator app too."}) @hoisted union post_account_api_activation_b_application_json_totp_h593 {
    EmptyText,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

  

@js(#{`description`:"Which step this answers."}) @hoisted union post_account_api_activation_b_application_json_step_h595 {
    EmptyText,
    "setup" | "key" | "totp"
  }

  

@js(#{`description`:"`setup`: where the passkey lives."}) @hoisted union post_account_api_activation_b_application_json_kind_h597 {
    EmptyText,
    "passkey" | "security-key"
  }

  

@js(#{
    `description`:"`setup`: `classical` (the default) or `pqc`, where the realm offers a post-quantum passkey beside a classical one."
  }) @hoisted union post_account_api_activation_b_application_json_lane_h599 {
    EmptyText,
    "classical" | "pqc"
  }

  

  

@js(#{`description`:"`key`: the pending registration."}) @hoisted union post_account_api_activation_b_application_json_enrolment_id_h602 {
    EmptyText,
    StringMin1Max4096Matchinga5aa8a
  }

@endpoint("/account-api/activation",
  "post",
  #{
    `operationId`:"activate",
    `tags`:#["Activation"],
    `summary`:"Answers one step of an activation",
    `description`:"`setup` sets the password and starts a passkey (the `key` view) or an authenticator app (the `totp` view) where they were chosen; `key` answers the passkey's ceremony; `totp` the app's code. The link is checked again, claimed before anything is set, and spent only by the step that finishes, which answers the `ready` view. Nobody is signed in by it. A passkey carries no role (#1135): `passkey` asks for one, and `key_role` is still accepted, `primary` and `mfa` both asking for one.\n\nThe door of the portal's `POST /portal/activate`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-access`:"link",
    `x-mirrors`:"POST /portal/activate",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`user`:"nobody-example",`token`:"no-such-token",`password`:"not",`confirm`:"equal"}}}}
  })
op `activate`(`requestBody/content/application~1json/schema`: {
    `user`?: EmptyTextOrStringMin1Max2562;
    `token`?: post_account_api_activation_b_application_json_token_h587;
    @js(#{`description`:"`setup`: the password to set.",`maxLength`:1024}) `password`?: string;
    @js(#{`description`:"`setup`: the password again.",`maxLength`:1024}) `confirm`?: string;
    `passkey`?: post_account_api_activation_b_application_json_passkey_h589;
    `key_role`?: post_account_api_activation_b_application_json_key_role_h591;
    `totp`?: post_account_api_activation_b_application_json_totp_h593;
    `step`?: post_account_api_activation_b_application_json_step_h595;
    @js(#{
      `description`:"`totp`: the code the authenticator app shows.",
      `maxLength`:32
    }) `code`?: string;
    `kind`?: post_account_api_activation_b_application_json_kind_h597;
    `lane`?: post_account_api_activation_b_application_json_lane_h599;
    `enrolment_id`?: post_account_api_activation_b_application_json_enrolment_id_h602;
    @js(#{
      `description`:"`key`: the browser's ceremony result, as JSON.",
      `maxLength`:65536
    }) `credential`?: string
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `view`?: WithStepUserTokenEtc22
  },
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc415,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc415,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

@endpoint("/account-api/reset-password",
  "get",
  #{
    `operationId`:"getPasswordReset",
    `tags`:#["Password reset link"],
    `summary`:"Checks a password reset link, and spends nothing",
    `description`:"Takes no token: the link's `user` and `token` are the credential. Answers the form's view — the username, the service's address and the password rules — or one sentence for every way a link can fail (`view.refused`), so nobody learns which usernames have a link outstanding. Rate limited.\n\nThe door of the portal's `GET /portal/reset-password`.",
    `parameters`:#[
      #{
        `name`:"user",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The username the link names.",
        `example`:"nobody-example"
      },
      #{
        `name`:"X-Link-Token",
        `in`:"header",
        `required`:false,
        `schema`:null,
        `description`:"The single-use secret the link carried in its fragment."
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts; `view.refused` says so.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-access`:"link",
    `x-mirrors`:"GET /portal/reset-password"
  })
op `getPasswordReset`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`minLength`:1,`maxLength`:256}]}}) `parameters/0/schema`: unknown,
  `parameters/1/schema`: string,
  `responses/200/content/application~1json/schema`: WithUsernameTokenBaseEtc8,
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc46,
  `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc46,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc46,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  

  

  

  

  

@endpoint("/account-api/reset-password",
  "post",
  #{
    `operationId`:"spendPasswordReset",
    `tags`:#["Password reset link"],
    `summary`:"Sets a new password from a reset link, and spends it",
    `description`:"Checks the link again, claims it, screens the password against breached passwords and the password policy, stores it, clears the must-change flag, and spends the link; signs nobody in. CAEP credential-change is sent. A refusal carries the page's `view`; success answers `view.done`.\n\nThe door of the portal's `POST /portal/reset-password`.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"The request did not validate, or was refused: `{ ok: false, errors: [...] }`.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts; `view.refused` says so.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `500`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-access`:"link",
    `x-mirrors`:"POST /portal/reset-password",
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`user`:"nobody-example",`token`:"no-such-token",`password`:"not",`confirm`:"equal"}}}}
  })
op `spendPasswordReset`(`requestBody/content/application~1json/schema`: {
    `user`?: EmptyTextOrStringMin1Max2562;
    `token`?: EmptyTextOrStringMin1Max4096Matchingfb79a8;
    @js(#{`description`:"The new password.",`maxLength`:1024}) `password`?: string;
    @js(#{`description`:"The new password again.",`maxLength`:1024}) `confirm`?: string
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `message`?: string;
    `go`?: string;
    `view`?: WithUsernameTokenBaseEtc8
  },
  `responses/400/content/application~1json/schema`: WithOkErrorsErrorEtc46,
  `responses/403/content/application~1json/schema`: WithOkErrorsErrorEtc46,
  `responses/429/content/application~1json/schema`: WithOkErrorsErrorEtc46,
  `responses/500/content/application~1json/schema`: WithOkErrorsErrorEtc46,
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: WithOkErrorsErrorEtc4): void;
  
}

@hoisted model WithUrnIetfParamsOauthGrantTypePreAuthorizedCodeAuthorizationCode { `urn:ietf:params:oauth:grant-type:pre-authorized_code`?: WithPreAuthorizedCodeTxCode; `authorization_code`?: WithIssuerState }
