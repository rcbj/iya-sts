// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/api/authn.tsp
//
// Written by hand (#1390). THE AUTHENTICATION API OPENAPI DOCUMENT'S SOURCE:
// `models/tools/generate.mjs` compiles it during the image build, the service
// serves the result and holds every answer to it.
//
// The reasoning below sat beside the code this replaced.
//
//
//
// ---------------------------------------------------------------------------
// WHAT `/authn-api` ANSWERS, PER OPERATION AND STATUS (#1353), keyed by
// operationId. `common/response_model_kit.ts` says how a model is written;
// `tests/openapi_response_models.js` fails on an operation with none.
//
// **AN ANSWER THAT DOES NOT FIT IS NOT SENT, AND HERE THAT MEANS SOMEBODY
// CANNOT SIGN IN.** So each model is the UNION of what every branch can send,
// read from the code that builds it, and hardly anything is `required`:
//
//   * a view is `authn/authn.ts`'s (`screenView()`, `selectIdpView()`,
//     `accountsView()`, `passwordChangeView()`, `mfaView()` and what it calls),
//     `authn/email_factor.ts`'s, `oauth-oidc/consent_screen.ts`'s,
//     `logout/logout.ts`'s or `oid4vc/vc_signin.ts`'s;
//   * an act's answer is one of the shapes `authn.ts` lists under *What the
//     sign-in screen's acts answer*, and a refusal of one carries the same
//     members at whichever status it was refused with, so `Models.act()` names
//     one model for every status an act can refuse at. `refuse()` in
//     `authn_api.ts` adds `error` and `error_description` to `ok` and `errors`,
//     and a refusal may come from there as well as from the module that owns
//     the act.
//
// **`Kit.applyModels()` GIVES A STATUS WITH NO MODEL OF ITS OWN THE 200's WHEN
// IT IS 400**, so every operation here names its 400: a view's would otherwise
// be a refusal held to the view's members.
//
// **A GEOFENCE REFUSES IN PLAIN TEXT** (`CellPlacement.servePermitted()`): a
// person homed in another cell who may not be served from here gets a 403 as
// `text/plain` from the first-factor acts, so those declare both media types
// (`Models.withGeofence()`). The validator refuses a media type a status does
// not declare, and this is the one non-JSON answer this API has.
//
// **WHAT IS NOT MODELLED AS A CLOSED OBJECT, AND WHY** — two places, each with
// its reason in `x-free-form`: the inner paths of this API's own OpenAPI
// document, and the `limits` member of an RFC 9396 authorization detail, whose
// members beyond the six `common/access_limits.ts` names are the API's own
// under a schema an operator declared.
//
// No function here is entered and left out loud: each runs only while this
// table is built, once per load, as `common/response_model_kit.ts`'s helpers
// do, and this module has no logger of its own for the same reason.
// ---------------------------------------------------------------------------
// How a model is listed: helpers, on the code style's rule, each run only while
// this table is built (see the header for why none logs).
// SEVERAL DOCUMENTS IN ONE PLACE (a step's page is `mfaView()`'s or the
// emailed factor's, a sign-out's view an inventory, a result or a refusal)
// ARE ONE CLOSED OBJECT HOLDING EVERY ONE'S MEMBERS, not an `anyOf`: what is
// being
// guarded is a member nobody declared, and an `anyOf`'s failure names every
// arm's complaint about every member, where this names the member. An
// enumerated member takes each document's values.
// A view: its answer, and a refusal of the request. `extra` for a view that
// has refusals of its own.
// An act: every status it can refuse at carries the same members as its
// success, because the same functions answer them. 415 and the other binding
// refusals are `refuse()`'s, which that model holds too.
// The acts through `screenAct()` and `certificateSignIn()`, which may meet
// `servePermitted()`: see the header.
// ---------------------------------------------------------------------------
// THE REFUSALS.
// ---------------------------------------------------------------------------
// A refusal, from the gate or from a handler. `next` because several handlers
// answer `{ ok: false, next: 'refused', errors }` at a status no operation
// lists (a 500 from the wallet's door, a 429 at a passkey's options); the two
// `error` members because `oauthError()` and `refuse()` carry them, and the
// session store's 503 (`refuseUnread()`) carries only them.
// `refuse()`'s members and the rest of a plain refusal, for spreading into an
// answer that may also be one.
// ---------------------------------------------------------------------------
// WHAT SEVERAL VIEWS SHARE.
// ---------------------------------------------------------------------------
// `preferredLanguageOf()`: a person's own language, for the browser's chooser.
// `common/applications.js`, `clientDisplayOf()` (#1300): null where the client
// registered no logo, policy or terms.
// The calling protocol's own rows, drawn as they are.
// `partnerLinks()`: one federation partner as a link.
// `accountRows()`: a signed-in account has `signedInAt` and `authTime`, a
// remembered one `signedOutAt`.
// ---------------------------------------------------------------------------
// WEBAUTHN'S OPTIONS (WebAuthn Level 3), as this service's own vocabulary
// carries them: `authn/webauthn_policy.ts` hands the browser's script these
// and the script builds the dictionaries from them, so `algorithms` here is
// `pubKeyCredParams`'s COSE identifiers and `credProps` and `minPinLength` are
// the extensions asked for.
// ---------------------------------------------------------------------------
// `creationOptions()`, and `upgradeCreationOptions()` over it. An algorithm
// name with no COSE identifier would be `undefined` in the list, which JSON
// writes as null, so an item may be null: the page's complaint about that is
// more use to a person than a 500 here.
// `requestOptions()` and `discoverableRequestOptions()`.
// `webauthnFacts()` and `upgradeStepFacts()`: the retry's facts; `upgrade` is
// the second's.
// `facts.ceremony`, the members both a ceremony's own answer and the view it
// was deleted from speak of.
// A reason this step's ceremony cannot run, told before it does.
// `webauthnFacts()` less `ceremony`, which `mfaView()` deletes;
// `upgradeStepFacts()` answers the same members with `postLogin.upgrade` set.
// ---------------------------------------------------------------------------
// THE SIGN-IN SCREEN.
// ---------------------------------------------------------------------------
// `screenView()`.
// `partnersOf()`.
// `kerberosOption()`.
// `walletOption()`.
// ---------------------------------------------------------------------------
// A STEP'S PAGE: `mfaView()`, with the member its page adds, or the emailed
// factor's `view()`, which is a different document in the same place.
// ---------------------------------------------------------------------------
// `stepLinks()`.
// `mfaSetupFacts()`.
// `EmailFactor.view()`: `stepFacts()` where the step is live; `elsewhere`,
// `open` and `end` (its `endView()`) otherwise.
// ---------------------------------------------------------------------------
// THE WALLET'S VIEWS (#574), `oid4vc/vc_signin.ts`: a start, a wait, or a
// refusal of kind `refused` (`refusedView()`).
// ---------------------------------------------------------------------------
// `VcVerifier.dcApiRequestFor()`.
// ---------------------------------------------------------------------------
// THE ANSWERS TO AN ACT.
// ---------------------------------------------------------------------------
// The next step, or its refusal: `authn.ts`'s `screenRefused()` (`location`
// where a step's end refused the session, `passkey` after a refused passkey),
// `stepAnswer()`, `leave()`, `restartFrom()`, `sendHome()` (`home-cell`, whose
// `fields` are a request's own parameters), `stepRefused()`,
// `passwordChangeRefused()`, the emailed factor's `endAnswer()` (`end`) and
// `sendAct()` (`stay`), the account picker's and the consent screen's answers
// are all this.
// `POST /wallet`, the poll and the Digital Credentials API's answer: a wait, a
// refusal with its view (`VcSignin.refuse()`), or what `finish()` ends in,
// which is whatever a sign-in's end is, a next step included.
// A row of a sign-out's result.
// `accountStep()`.
// `subjectRefusal()`: a name that may not be used, and nobody to act on.
// `resultView()`.
// `POST /logout` and `/logout/accounts` (`signOutAct()`,
// `signOutAccountsAct()`): the result, the signed-out document's form, the next
// page, or a refusal.
// ---------------------------------------------------------------------------
// THE SIGN-OUT'S INVENTORY: `Logout.row()`'s members, whichever family's
// `collect()` made it (each passes only those; `secret` is deleted on the way
// out). A LDAP connection's id is a socket's number or its address, and a row
// can come from a store that recorded nothing, hence the handle's two types and
// the times' null: a sign-out page refused over a missing timestamp would be
// the worst page to lose.
// ---------------------------------------------------------------------------
// `inventoryFor()`.
// ---------------------------------------------------------------------------
// THE CONSENT SCREEN: `consentView()`.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE ACTS, BY WHAT THEY ANSWER.
// ---------------------------------------------------------------------------
// `accountsRefused()`, and the 503 of a set that could not be read.
// `refuse()` at the wallet's door, with `answerDcApi()`'s statuses (400 and
// 403) and a claim store's 503 among them.
// The members every view's envelope has beside the view.
// A step's page: `mfaStep()`. A refused emailed-factor page is a whole answer
// with its `end` view and `errors`, and a refused second-factor page
// `refuse()`'s, both at 400.
// `startView()`, `waitView()` and what `admitted()`, `startable()`, `closed()`
// refuse them with.
// `signOutView()`: the inventory, the account step where the browser holds
// several, or `subjectRefusal()`.
// `signOutAccountsView()`, or `accountsOff()`.
// --- the screen -----------------------------------------------------------
// `go` where fewer than two partners are left: the screen, instead.
// `AuthnApi.passkeyOptions()`, and `refuse()` before it.
// --- the forced password change -------------------------------------------
// --- the steps after the screen -------------------------------------------
// `mfaWebauthnOptions()`: `facts.ceremony`, or `stepRefused()`.
// --- the wallet -----------------------------------------------------------
// --- the sign-out ---------------------------------------------------------
// --- several accounts in one browser --------------------------------------
// `browserAccounts()`, with `anotherAccount` where the setting is on.
// --- the consent screen ---------------------------------------------------

import "../lib/api_lib.tsp";

using IyaSts.ApiLib;

@apiDocument(#{
  `x-iya-every-operation`:#[#{`name`:"X-Requested-With",`in`:"header",`required`:false,`description`:"Added by an Android WebView, naming the application that hosts the page. This API reads nothing in it.",`schema`:#{`type`:"string"}}],
  `openapi`:"3.1.0",
  `info`:#{
    `title`:"IYA STS Sign-in API",
    `version`:"0.0.0",
    `description`:"The sign-in screen's API: what the screen offers for a pending sign-in, and the acts it sends. Unauthenticated and keyed by the pending sign-in's id; every act is bound to the browser's session cookie by a CSRF token. Answers name the next step; refusals are English and carry no error code. And the sign-out page's (#577): what a sign-out would end for the person the session names, and the act that ends it."
  },
  `servers`:#[#{`url`:""}],
  `tags`:#[#{`name`:"Sign-in"}],
  `x-iya-doc`:"authn"
})
namespace IyaSts.Api.Authn {
  

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_r200_application_json_operations_i_mirrors_h1 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_r200_application_json_operations_i_action_h2 {}

@endpoint("/authn-api",
  "get",
  #{
    `operationId`:"getIndex",
    `tags`:#["Sign-in"],
    `summary`:"Lists every operation of this API",
    `description`:"Each operation, its method and path, and the sign-in page or control it is the door of.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[]
  })
op `getIndex`(`responses/200/content/application~1json/schema`: {
    `api`?: string;
    `openapi`?: string;
    `operations`?: ({
      `method`?: "GET" | "POST";
      `path`?: string;
      `operationId`?: string;
      `access`?: string;
      `mirrors`?: get_authn_api_r200_application_json_operations_i_mirrors_h1;
      `action`?: get_authn_api_r200_application_json_operations_i_action_h2;
      `summary`?: string
    })[]
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/openapi.json",
  "get",
  #{
    `operationId`:"getOpenApi",
    `tags`:#["Sign-in"],
    `summary`:"This API's OpenAPI document",
    `description`:"Generated from the operation table and its body schemas.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[]
  })
op `getOpenApi`(`responses/200/content/application~1json/schema`: {
    `openapi`?: string;
    `info`?: {`title`?: string; `version`?: string; `description`?: string};
    `servers`?: ({`url`?: string})[];
    `tags`?: ({`name`?: string})[];
    @js(#{
      `x-free-form`:"The operations and components of an OpenAPI document are that specification's vocabulary, not this API's, and this document describes itself with them.",
      `description`:"The operations and components of an OpenAPI document are that specification's vocabulary, not this API's, and this document describes itself with them."
    }) `paths`?: unknown;
    @js(#{
      `x-free-form`:"The operations and components of an OpenAPI document are that specification's vocabulary, not this API's, and this document describes itself with them.",
      `description`:"The operations and components of an OpenAPI document are that specification's vocabulary, not this API's, and this document describes itself with them."
    }) `components`?: unknown
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `name`:#{`type`:"string"},
      `logo`:#{`type`:"string"},
      `logoOrigin`:#{`type`:"string"},
      `policy`:#{`type`:"string"},
      `tos`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_pending__id__r200_application_json_view_clientDisplay_h3 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{`name`:#{`type`:"string"},`mfaNote`:#{`type`:"boolean"}},
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_pending__id__r200_application_json_view_certificate_h4 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{`register`:#{`type`:"string"}},
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_pending__id__r200_application_json_view_postQuantumRequired_h5 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `kind`:#{`type`:"string",`enum`:#["own-one","own-many","any"]},
      `options`:#{
        `type`:"array",
        `items`:#{
          `type`:"object",
          `additionalProperties`:false,
          `properties`:#{
            `id`:#{`type`:"string"},
            `label`:#{`type`:"string"},
            `protocolLabel`:#{`type`:"string"},
            `peer`:#{`type`:"string"},
            `category`:#{`type`:"string"},
            `provider`:#{`type`:"string"},
            `href`:#{`type`:"string"}
          }
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_pending__id__r200_application_json_view_partners_h6 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `state`:#{`type`:"string",`enum`:#["offered","withheld-key","withheld-mfa"]},
      `href`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_pending__id__r200_application_json_view_kerberos_h7 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `state`:#{`type`:"string",`enum`:#["offered","withheld"]},
      `mfaNote`:#{`type`:"boolean"},
      `href`:#{`type`:"string"},
      `siop`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_pending__id__r200_application_json_view_wallet_h8 {}

@endpoint("/authn-api/pending/{id}",
  "get",
  #{
    `operationId`:"getScreen",
    `tags`:#["Sign-in"],
    `summary`:"What the sign-in screen offers for a pending sign-in",
    `description`:"The screen's view, as facts and no words: the authentication policy's mechanisms, the passkey policy's boxes, the demands the calling protocol made, the partners, the Kerberos and wallet doors, what this mode checks, and the protocol's own rows — and `csrf`, the token every act on this sign-in carries.\n\nThe door of the sign-in surface's `GET /authn/login`.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending sign-in's id: a bearer capability, as the `authn` the screen was opened with.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-mirrors`:"GET /authn/login"
  })
op `getScreen`(`parameters/0/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `id`?: string;
      `base`?: string;
      `protocol`?: string;
      `application`?: string;
      `error`?: string;
      `locked`?: string;
      `hint`?: string;
      `screen`?: boolean;
      `password`?: boolean;
      `keys`?: {
        `enabled`?: boolean;
        `mfaAllowed`?: boolean;
        `primaryAllowed`?: boolean
      };
      `demands`?: {
        `mfa`?: boolean;
        `key`?: boolean;
        `passwordless`?: boolean;
        `via`?: string
      };
      `remember`?: boolean;
      `anonymous`?: boolean;
      `passkey`?: boolean;
      `usernameless`?: boolean;
      `email`?: {`code`?: boolean; `link`?: boolean};
      `clientDisplay`?: get_authn_api_pending__id__r200_application_json_view_clientDisplay_h3;
      `reauthentication`?: string;
      `certificate`?: get_authn_api_pending__id__r200_application_json_view_certificate_h4;
      `postQuantumRequired`?: get_authn_api_pending__id__r200_application_json_view_postQuantumRequired_h5;
      `forgot`?: string;
      `partners`?: get_authn_api_pending__id__r200_application_json_view_partners_h6;
      `kerberos`?: get_authn_api_pending__id__r200_application_json_view_kerberos_h7;
      `wallet`?: get_authn_api_pending__id__r200_application_json_view_wallet_h8;
      `verifiesCredentials`?: boolean;
      `fingerprint`?: boolean;
      `details`?: ({`label`?: string; `value`?: string; `note`?: string})[]
    }
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/pending/{id}/partners",
  "get",
  #{
    `operationId`:"getPartners",
    `tags`:#["Sign-in"],
    `summary`:"The federation partners a sign-in may choose between",
    `description`:"Resolved again from the application's entry; with fewer than two left, `go` names the sign-in screen instead.\n\nThe door of the sign-in surface's `GET /authn/select-idp`.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending sign-in's id: a bearer capability, as the `authn` the screen was opened with.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-mirrors`:"GET /authn/select-idp"
  })
op `getPartners`(`parameters/0/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `id`?: string;
      `base`?: string;
      `protocol`?: string;
      `application`?: string;
      `problems`?: (string)[];
      `partners`?: ({
        `id`?: string;
        `label`?: string;
        `protocolLabel`?: string;
        `peer`?: string;
        `category`?: string;
        `provider`?: string;
        `href`?: string
      })[];
      `details`?: ({`label`?: string; `value`?: string; `note`?: string})[]
    };
    `go`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{`const`:""}) @hoisted scalar post_authn_api_pending__id__password_b_application_json_username_v0_h9 extends string;
  

@js(#{`minLength`:1,`maxLength`:256}) @hoisted scalar post_authn_api_pending__id__password_b_application_json_username_v1_h10 extends string;
  

@hoisted union post_authn_api_pending__id__password_b_application_json_username_h11 {
    post_authn_api_pending__id__password_b_application_json_username_v0_h9,
    post_authn_api_pending__id__password_b_application_json_username_v1_h10
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_pending__id__password_b_application_json_use_webauthn_v0_h12 extends string;
  

@hoisted union post_authn_api_pending__id__password_b_application_json_use_webauthn_h13 {
    post_authn_api_pending__id__password_b_application_json_use_webauthn_v0_h12,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_pending__id__password_b_application_json_webauthn_only_v0_h14 extends string;
  

@hoisted union post_authn_api_pending__id__password_b_application_json_webauthn_only_h15 {
    post_authn_api_pending__id__password_b_application_json_webauthn_only_v0_h14,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_pending__id__password_b_application_json_remember_browser_v0_h16 extends string;
  

@hoisted union post_authn_api_pending__id__password_b_application_json_remember_browser_h17 {
    post_authn_api_pending__id__password_b_application_json_remember_browser_v0_h16,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

@endpoint("/authn-api/pending/{id}/password",
  "post",
  #{
    `operationId`:"signInWithPassword",
    `tags`:#["Sign-in"],
    `summary`:"Signs in with a username and password, or a passkey for the named account",
    `description`:"The Sign In button: the password checked (in product mode), rate limited by identity and address, the risk assessed, the issuance policy asked, and the second factor, the set-up step or the forced password change answered as the next step. `webauthn_only` asks for a passkey instead of the password.\n\nThe door of the sign-in surface's `POST /authn/login`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending sign-in's id: a bearer capability, as the `authn` the screen was opened with.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`text/plain`:#{`schema`:null},`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`username`:"nobody-example",`password`:"not-the-password"}}}},
    `x-mirrors`:"POST /authn/login"
  })
op `signInWithPassword`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {
    `username`?: post_authn_api_pending__id__password_b_application_json_username_h11;
    @js(#{`maxLength`:1024}) `password`?: string;
    `use_webauthn`?: post_authn_api_pending__id__password_b_application_json_use_webauthn_h13;
    `webauthn_only`?: post_authn_api_pending__id__password_b_application_json_webauthn_only_h15;
    `remember_browser`?: post_authn_api_pending__id__password_b_application_json_remember_browser_h17;
    @js(#{`maxLength`:64,`pattern`:"^[A-Za-z0-9]*$"}) `device_fp`?: string
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  `responses/403/content/text~1plain/schema`: string,
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/pending/{id}/cancel",
  "post",
  #{
    `operationId`:"cancelSignIn",
    `tags`:#["Sign-in"],
    `summary`:"Declines the sign-in",
    `description`:"Cancel: the calling protocol is told the person declined (`authn_error=access_denied`) at `location`.\n\nThe door of the sign-in surface's `POST /authn/login`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending sign-in's id: a bearer capability, as the `authn` the screen was opened with.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`text/plain`:#{`schema`:null},`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{}}}},
    `x-mirrors`:"POST /authn/login"
  })
op `cancelSignIn`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  `responses/403/content/text~1plain/schema`: string,
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{`const`:""}) @hoisted scalar post_authn_api_pending__id__anonymous_b_application_json_remember_browser_v0_h18 extends string;
  

@hoisted union post_authn_api_pending__id__anonymous_b_application_json_remember_browser_h19 {
    post_authn_api_pending__id__anonymous_b_application_json_remember_browser_v0_h18,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

@endpoint("/authn-api/pending/{id}/anonymous",
  "post",
  #{
    `operationId`:"continueAnonymously",
    `tags`:#["Sign-in"],
    `summary`:"Continues without signing in",
    `description`:"Where `authn.unauthenticatedSessions` is on: a session that records that nobody authenticated.\n\nThe door of the sign-in surface's `POST /authn/login`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending sign-in's id: a bearer capability, as the `authn` the screen was opened with.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`text/plain`:#{`schema`:null},`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`remember_browser`:"0"}}}},
    `x-mirrors`:"POST /authn/login"
  })
op `continueAnonymously`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {
    `remember_browser`?: post_authn_api_pending__id__anonymous_b_application_json_remember_browser_h19;
    @js(#{`maxLength`:64,`pattern`:"^[A-Za-z0-9]*$"}) `device_fp`?: string
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  `responses/403/content/text~1plain/schema`: string,
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{`const`:""}) @hoisted scalar post_authn_api_pending__id__certificate_b_application_json_remember_browser_v0_h20 extends string;
  

@hoisted union post_authn_api_pending__id__certificate_b_application_json_remember_browser_h21 {
    post_authn_api_pending__id__certificate_b_application_json_remember_browser_v0_h20,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

@endpoint("/authn-api/pending/{id}/certificate",
  "post",
  #{
    `operationId`:"continueWithCertificate",
    `tags`:#["Sign-in"],
    `summary`:"Continues as the holder of the connection's TLS client certificate",
    `description`:"Where the view offers `certificate` (#1051): the TLS client certificate this connection presented, its revocation consulted, the identity gate asked for this sign-in's realm, and an application's certificate refused — the checks `GET /tls/sign-in` makes — as a first factor, `amr [\"swk\"]`. The authentication policy, the risk and the issuance policy decide as for any first factor, and a second factor is the next step where one is needed.\n\nThe door of the sign-in surface's `POST /authn/login`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending sign-in's id: a bearer capability, as the `authn` the screen was opened with.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`text/plain`:#{`schema`:null},`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`remember_browser`:"0"}}}},
    `x-mirrors`:"POST /authn/login"
  })
op `continueWithCertificate`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {
    `remember_browser`?: post_authn_api_pending__id__certificate_b_application_json_remember_browser_h21;
    @js(#{`maxLength`:64,`pattern`:"^[A-Za-z0-9]*$"}) `device_fp`?: string
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  `responses/403/content/text~1plain/schema`: string,
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{`const`:""}) @hoisted scalar post_authn_api_pending__id__email_b_application_json_username_v0_h22 extends string;
  

@js(#{`minLength`:1,`maxLength`:256}) @hoisted scalar post_authn_api_pending__id__email_b_application_json_username_v1_h23 extends string;
  

@hoisted union post_authn_api_pending__id__email_b_application_json_username_h24 {
    post_authn_api_pending__id__email_b_application_json_username_v0_h22,
    post_authn_api_pending__id__email_b_application_json_username_v1_h23
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_pending__id__email_b_application_json_remember_browser_v0_h25 extends string;
  

@hoisted union post_authn_api_pending__id__email_b_application_json_remember_browser_h26 {
    post_authn_api_pending__id__email_b_application_json_remember_browser_v0_h25,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

@endpoint("/authn-api/pending/{id}/email",
  "post",
  #{
    `operationId`:"signInByEmail",
    `tags`:#["Sign-in"],
    `summary`:"Mails a sign-in code or link as a first factor",
    `description`:"Where the authentication policy accepts one (#64): the next step is the page that waits for it, the same whether or not the account exists.\n\nThe door of the sign-in surface's `POST /authn/login`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending sign-in's id: a bearer capability, as the `authn` the screen was opened with.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`text/plain`:#{`schema`:null},`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`username`:"nobody-example",`kind`:"code"}}}},
    `x-mirrors`:"POST /authn/login"
  })
op `signInByEmail`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {
    `username`?: post_authn_api_pending__id__email_b_application_json_username_h24;
    `kind`: "code" | "link";
    `remember_browser`?: post_authn_api_pending__id__email_b_application_json_remember_browser_h26;
    @js(#{`maxLength`:64,`pattern`:"^[A-Za-z0-9]*$"}) `device_fp`?: string
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  `responses/403/content/text~1plain/schema`: string,
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/pending/{id}/passkey/options",
  "post",
  #{
    `operationId`:"passkeyOptions",
    `tags`:#["Sign-in"],
    `summary`:"Arms a passkey ceremony with no username",
    `description`:"A single-use challenge on the pending sign-in, the RP ID and the request options, for the button and the username field's autofill (conditional mediation).\n\nThe door of the sign-in surface's `POST /authn/login`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending sign-in's id: a bearer capability, as the `authn` the screen was opened with.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{}}}},
    `x-mirrors`:"POST /authn/login"
  })
op `passkeyOptions`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {},
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "refused";
    `challenge`?: string;
    `rpId`?: string;
    `options`?: {
      `rpId`?: string;
      `userVerification`?: string;
      `timeout`?: numeric;
      `hints`?: (string)[]
    }
  },
  `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "refused";
    `challenge`?: string;
    `rpId`?: string;
    `options`?: {
      `rpId`?: string;
      `userVerification`?: string;
      `timeout`?: numeric;
      `hints`?: (string)[]
    }
  },
  `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "refused";
    `challenge`?: string;
    `rpId`?: string;
    `options`?: {
      `rpId`?: string;
      `userVerification`?: string;
      `timeout`?: numeric;
      `hints`?: (string)[]
    }
  },
  `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "refused";
    `challenge`?: string;
    `rpId`?: string;
    `options`?: {
      `rpId`?: string;
      `userVerification`?: string;
      `timeout`?: numeric;
      `hints`?: (string)[]
    }
  },
  `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "refused";
    `challenge`?: string;
    `rpId`?: string;
    `options`?: {
      `rpId`?: string;
      `userVerification`?: string;
      `timeout`?: numeric;
      `hints`?: (string)[]
    }
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{`const`:""}) @hoisted scalar post_authn_api_pending__id__passkey_b_application_json_remember_browser_v0_h27 extends string;
  

@hoisted union post_authn_api_pending__id__passkey_b_application_json_remember_browser_h28 {
    post_authn_api_pending__id__passkey_b_application_json_remember_browser_v0_h27,
    "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no"
  }

@endpoint("/authn-api/pending/{id}/passkey",
  "post",
  #{
    `operationId`:"signInWithPasskey",
    `tags`:#["Sign-in"],
    `summary`:"Signs in with a passkey and no username",
    `description`:"The ceremony's result, verified with user verification required against the challenge `passkey/options` armed.\n\nThe door of the sign-in surface's `POST /authn/login`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending sign-in's id: a bearer capability, as the `authn` the screen was opened with.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`text/plain`:#{`schema`:null},`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`credential`:"{}"}}}},
    `x-mirrors`:"POST /authn/login"
  })
op `signInWithPasskey`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {
    @js(#{`maxLength`:65536}) `credential`?: string;
    `remember_browser`?: post_authn_api_pending__id__passkey_b_application_json_remember_browser_h28;
    @js(#{`maxLength`:64,`pattern`:"^[A-Za-z0-9]*$"}) `device_fp`?: string
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  `responses/403/content/text~1plain/schema`: string,
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/password-change/{id}",
  "get",
  #{
    `operationId`:"getPasswordChange",
    `tags`:#["Sign-in"],
    `summary`:"The forced password change a sign-in is waiting on",
    `description`:"Whose password, and why it must be changed now where there is a reason to give; `csrf` as for the screen.\n\nThe door of the sign-in surface's `GET /authn/password-change`.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The password change step's id.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-mirrors`:"GET /authn/password-change"
  })
op `getPasswordChange`(`parameters/0/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {`id`?: string; `username`?: string; `notice`?: string}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/password-change/{id}",
  "post",
  #{
    `operationId`:"changePassword",
    `tags`:#["Sign-in"],
    `summary`:"Stores the new password and continues the sign-in",
    `description`:"Held to the password policy; the sign-in then continues exactly as after the password step — second factor included.\n\nThe door of the sign-in surface's `POST /authn/password-change`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The password change step's id.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`new_password`:"not",`confirm_password`:"equal"}}}},
    `x-mirrors`:"POST /authn/password-change"
  })
op `changePassword`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {
    @js(#{`maxLength`:1024}) `new_password`?: string;
    @js(#{`maxLength`:1024}) `confirm_password`?: string
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/password-change/{id}/start-over",
  "post",
  #{
    `operationId`:"startOverFromPasswordChange",
    `tags`:#["Sign-in"],
    `summary`:"Leaves the forced password change and starts the sign-in over",
    `description`:"Changes nothing: the step is ended and the pending sign-in it was minted from is put back under its id, so the request it carries completes after the person signs in again. `next: redirect` to the sign-in screen.\n\nThe door of the sign-in surface's `POST /authn/password-change`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The password change step's id.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{}}}},
    `x-mirrors`:"POST /authn/password-change"
  })
op `startOverFromPasswordChange`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `name`:#{`type`:"string"},
      `logo`:#{`type`:"string"},
      `logoOrigin`:#{`type`:"string"},
      `policy`:#{`type`:"string"},
      `tos`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r200_application_json_view_clientDisplay_h29 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{`id`:#{`type`:"string"},`name`:#{`type`:"string"}},
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r200_application_json_view_webauthn_chosen_h30 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{`why`:#{`type`:"string"}},
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r200_application_json_view_webauthn_postQuantumRefused_h31 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{`why`:#{`type`:"string"}},
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r200_application_json_view_webauthn_hardwareRefused_h32 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{`register`:#{`type`:"string"}},
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r200_application_json_view_webauthn_postQuantumHelp_h33 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `asksPostQuantum`:#{`type`:"boolean"},
      `classical`:#{`type`:"boolean"},
      `retrying`:#{`type`:"boolean"},
      `upgrade`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r200_application_json_view_webauthn_fallback_h34 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `required`:#{`type`:"boolean"},
      `upgrade`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `phase`:#{`type`:"string",`enum`:#["proof","registration"]},
          `name`:#{`type`:"string"},
          `previousAlgorithm`:#{`type`:"string"}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r200_application_json_view_webauthn_postLogin_h35 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `uri`:#{`type`:"string"},
      `secret`:#{`type`:"string"},
      `algorithm`:#{`type`:"string"},
      `digits`:#{`type`:"number"},
      `period`:#{`type`:"number"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r200_application_json_view_setup_totp_h36 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `name`:#{`type`:"string"},
      `logo`:#{`type`:"string"},
      `logoOrigin`:#{`type`:"string"},
      `policy`:#{`type`:"string"},
      `tos`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r400_application_json_view_clientDisplay_h37 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{`id`:#{`type`:"string"},`name`:#{`type`:"string"}},
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r400_application_json_view_webauthn_chosen_h38 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{`why`:#{`type`:"string"}},
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r400_application_json_view_webauthn_postQuantumRefused_h39 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{`why`:#{`type`:"string"}},
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r400_application_json_view_webauthn_hardwareRefused_h40 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{`register`:#{`type`:"string"}},
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r400_application_json_view_webauthn_postQuantumHelp_h41 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `asksPostQuantum`:#{`type`:"boolean"},
      `classical`:#{`type`:"boolean"},
      `retrying`:#{`type`:"boolean"},
      `upgrade`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r400_application_json_view_webauthn_fallback_h42 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `required`:#{`type`:"boolean"},
      `upgrade`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{
          `phase`:#{`type`:"string",`enum`:#["proof","registration"]},
          `name`:#{`type`:"string"},
          `previousAlgorithm`:#{`type`:"string"}
        }
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r400_application_json_view_webauthn_postLogin_h43 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `uri`:#{`type`:"string"},
      `secret`:#{`type`:"string"},
      `algorithm`:#{`type`:"string"},
      `digits`:#{`type`:"number"},
      `period`:#{`type`:"number"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_mfa__id__r400_application_json_view_setup_totp_h44 {}

@endpoint("/authn-api/mfa/{id}",
  "get",
  #{
    `operationId`:"getStep",
    `tags`:#["Sign-in"],
    `summary`:"What a second-factor or emailed-factor step's page shows",
    `description`:"The step's view for the page `page` names (`totp`, `webauthn`, `backup-code`, `password`, `setup`, `email-code`, `email-link`, `email-link-open`, `post-login`; the step's own where left out), as facts and no words: the person, the ways round the factor asked for, the set-up step's choice and its authenticator app's `otpauth:` URI, the passkey ceremony's description, an emailed factor's state — and `csrf`. Refused (400) where the page could never be drawn for the step: an expired step, a code page for somebody with no authenticator app, a passkey page for somebody holding no passkey (any key may answer the step since #1135; the authentication policy decides whether this use is open). `key` names the passkey a person chose where the passkey policy offers them one by one.\n\nThe door of the sign-in surface's `GET /authn/totp, /authn/webauthn, /authn/backup-code, /authn/password-factor, /authn/mfa-setup, /authn/email-code, /authn/email-link, /authn/email-link/open, /authn/post-login`.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"page",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which of the step's pages; the step's own where left out.",
        `example`:"totp"
      },
      #{
        `name`:"key",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"The passkey a person chose, where the passkey policy offers them one by one (#534)."
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-mirrors`:"GET /authn/totp, /authn/webauthn, /authn/backup-code, /authn/password-factor, /authn/mfa-setup, /authn/email-code, /authn/email-link, /authn/email-link/open, /authn/post-login"
  })
op `getStep`(`parameters/0/schema`: string,
  @js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`enum`:#["totp","webauthn","backup-code","password","setup","email-code","email-link","email-link-open","post-login"]}]}}) `parameters/1/schema`: unknown,
  @js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`minLength`:1,`maxLength`:4096,`pattern`:"^[A-Za-z0-9_-]+$"}]}}) `parameters/2/schema`: unknown,
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `page`?: string;
      `id`?: string;
      `username`?: string;
      `passwordless`?: boolean;
      `links`?: {
        `totp`?: boolean;
        `webauthn`?: boolean;
        `wallet`?: boolean;
        `password`?: boolean;
        `email`?: string;
        `backup`?: boolean
      };
      `clientDisplay`?: get_authn_api_mfa__id__r200_application_json_view_clientDisplay_h29;
      `totp`?: {`digits`?: numeric; `period`?: numeric};
      `amr`?: (string)[];
      `backup`?: {
        `factor`?: "passkey" | "code" | "link" | "app";
        `back`?: string;
        `remaining`?: numeric;
        `total`?: numeric;
        `low`?: boolean
      };
      `webauthn`?: {
        `mode`?: "create" | "get";
        `passwordless`?: boolean;
        `choices`?: ({`id`?: string; `name`?: string})[];
        `chosen`?: get_authn_api_mfa__id__r200_application_json_view_webauthn_chosen_h30;
        `problem`?: string;
        `postQuantumRefused`?: get_authn_api_mfa__id__r200_application_json_view_webauthn_postQuantumRefused_h31;
        `hardwareRefused`?: get_authn_api_mfa__id__r200_application_json_view_webauthn_hardwareRefused_h32;
        `postQuantumHelp`?: get_authn_api_mfa__id__r200_application_json_view_webauthn_postQuantumHelp_h33;
        `postQuantumAllowCredentials`?: string;
        `fallback`?: get_authn_api_mfa__id__r200_application_json_view_webauthn_fallback_h34;
        `rpId`?: string;
        `widened`?: boolean;
        `challenge`?: string;
        `attestation`?: string;
        `algorithms`?: (string)[];
        `postLogin`?: get_authn_api_mfa__id__r200_application_json_view_webauthn_postLogin_h35;
        `lanes`?: (string)[];
        `lane`?: string;
        `userVerification`?: string;
        `residentKey`?: string;
        `attachment`?: string
      };
      `setup`?: {
        `state`?: "choose" | "totp";
        `offered`?: {`totp`?: boolean; `webauthn`?: boolean};
        `optional`?: boolean;
        `proved`?: boolean;
        `recovery`?: boolean;
        `totp`?: get_authn_api_mfa__id__r200_application_json_view_setup_totp_h36
      };
      `postLogin`?: {
        `activity`?: string;
        `reason`?: string;
        `required`?: boolean;
        `canSkip`?: boolean;
        `method`?: string;
        `failed`?: string;
        `separate`?: boolean;
        `snoozeDays`?: numeric;
        `deadline`?: string
      };
      `state`?: "ask" | "code" | "wait" | "open" | "elsewhere" | "end";
      `kind`?: "code" | "link";
      `primary`?: boolean;
      `address`?: string;
      `minutes`?: numeric;
      `seconds`?: numeric;
      `notice`?: string;
      `others`?: {
        `totp`?: boolean;
        `webauthn`?: boolean;
        `password`?: boolean;
        `backup`?: boolean
      };
      `title`?: string;
      `sentence`?: string
    };
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `page`?: string;
      `id`?: string;
      `username`?: string;
      `passwordless`?: boolean;
      `links`?: {
        `totp`?: boolean;
        `webauthn`?: boolean;
        `wallet`?: boolean;
        `password`?: boolean;
        `email`?: string;
        `backup`?: boolean
      };
      `clientDisplay`?: get_authn_api_mfa__id__r400_application_json_view_clientDisplay_h37;
      `totp`?: {`digits`?: numeric; `period`?: numeric};
      `amr`?: (string)[];
      `backup`?: {
        `factor`?: "passkey" | "code" | "link" | "app";
        `back`?: string;
        `remaining`?: numeric;
        `total`?: numeric;
        `low`?: boolean
      };
      `webauthn`?: {
        `mode`?: "create" | "get";
        `passwordless`?: boolean;
        `choices`?: ({`id`?: string; `name`?: string})[];
        `chosen`?: get_authn_api_mfa__id__r400_application_json_view_webauthn_chosen_h38;
        `problem`?: string;
        `postQuantumRefused`?: get_authn_api_mfa__id__r400_application_json_view_webauthn_postQuantumRefused_h39;
        `hardwareRefused`?: get_authn_api_mfa__id__r400_application_json_view_webauthn_hardwareRefused_h40;
        `postQuantumHelp`?: get_authn_api_mfa__id__r400_application_json_view_webauthn_postQuantumHelp_h41;
        `postQuantumAllowCredentials`?: string;
        `fallback`?: get_authn_api_mfa__id__r400_application_json_view_webauthn_fallback_h42;
        `rpId`?: string;
        `widened`?: boolean;
        `challenge`?: string;
        `attestation`?: string;
        `algorithms`?: (string)[];
        `postLogin`?: get_authn_api_mfa__id__r400_application_json_view_webauthn_postLogin_h43;
        `lanes`?: (string)[];
        `lane`?: string;
        `userVerification`?: string;
        `residentKey`?: string;
        `attachment`?: string
      };
      `setup`?: {
        `state`?: "choose" | "totp";
        `offered`?: {`totp`?: boolean; `webauthn`?: boolean};
        `optional`?: boolean;
        `proved`?: boolean;
        `recovery`?: boolean;
        `totp`?: get_authn_api_mfa__id__r400_application_json_view_setup_totp_h44
      };
      `postLogin`?: {
        `activity`?: string;
        `reason`?: string;
        `required`?: boolean;
        `canSkip`?: boolean;
        `method`?: string;
        `failed`?: string;
        `separate`?: boolean;
        `snoozeDays`?: numeric;
        `deadline`?: string
      };
      `state`?: "ask" | "code" | "wait" | "open" | "elsewhere" | "end";
      `kind`?: "code" | "link";
      `primary`?: boolean;
      `address`?: string;
      `minutes`?: numeric;
      `seconds`?: numeric;
      `notice`?: string;
      `others`?: {
        `totp`?: boolean;
        `webauthn`?: boolean;
        `password`?: boolean;
        `backup`?: boolean
      };
      `title`?: string;
      `sentence`?: string
    };
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/mfa/{id}/totp",
  "post",
  #{
    `operationId`:"checkCode",
    `tags`:#["Sign-in"],
    `summary`:"Checks a one-time code from an authenticator app",
    `description`:"RFC 6238, checked in every mode and rate limited by identity and address; a refused code keeps the step.\n\nThe door of the sign-in surface's `POST /authn/totp`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`code`:"000000"}}}},
    `x-mirrors`:"POST /authn/totp"
  })
op `checkCode`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {@js(#{`maxLength`:32}) `code`?: string},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/mfa/{id}/backup-code",
  "post",
  #{
    `operationId`:"spendRecoveryCode",
    `tags`:#["Sign-in"],
    `summary`:"Checks and spends a recovery code",
    `description`:"In place of the second factor; a code that cannot be marked spent is refused.\n\nThe door of the sign-in surface's `POST /authn/backup-code`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`code`:"no-such-code"}}}},
    `x-mirrors`:"POST /authn/backup-code"
  })
op `spendRecoveryCode`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {@js(#{`maxLength`:64}) `code`?: string},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/mfa/{id}/password",
  "post",
  #{
    `operationId`:"checkFactorPassword",
    `tags`:#["Sign-in"],
    `summary`:"Checks a password as the second factor after a wallet",
    `description`:"Rate limited on the sign-in bucket.\n\nThe door of the sign-in surface's `POST /authn/password-factor`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`password`:"not-the-password"}}}},
    `x-mirrors`:"POST /authn/password-factor"
  })
op `checkFactorPassword`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {@js(#{`maxLength`:1024}) `password`?: string},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{`const`:""}) @hoisted scalar post_authn_api_mfa__id__webauthn_options_b_application_json_key_v0_h45 extends string;
  

@js(#{`minLength`:1,`maxLength`:4096,`pattern`:"^[A-Za-z0-9_-]+$"}) @hoisted scalar post_authn_api_mfa__id__webauthn_options_b_application_json_key_v1_h46 extends string;
  

@hoisted union post_authn_api_mfa__id__webauthn_options_b_application_json_key_h47 {
    post_authn_api_mfa__id__webauthn_options_b_application_json_key_v0_h45,
    post_authn_api_mfa__id__webauthn_options_b_application_json_key_v1_h46
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_mfa__id__webauthn_options_b_application_json_lane_v0_h48 extends string;
  

@hoisted union post_authn_api_mfa__id__webauthn_options_b_application_json_lane_h49 {
    post_authn_api_mfa__id__webauthn_options_b_application_json_lane_v0_h48,
    "classical" | "pqc"
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_mfa__id__webauthn_options_b_application_json_algorithms_v0_h50 extends string;
  

@hoisted union post_authn_api_mfa__id__webauthn_options_b_application_json_algorithms_h51 {
    post_authn_api_mfa__id__webauthn_options_b_application_json_algorithms_v0_h50,
    "classical"
  }

@js(#{`$types`:#["number","null"]}) @hoisted model post_authn_api_mfa__id__webauthn_options_r200_application_json_options_algorithms_i_h52 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `asksPostQuantum`:#{`type`:"boolean"},
      `classical`:#{`type`:"boolean"},
      `retrying`:#{`type`:"boolean"},
      `upgrade`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model post_authn_api_mfa__id__webauthn_options_r200_application_json_fallback_h53 {}

@js(#{`$types`:#["number","null"]}) @hoisted model post_authn_api_mfa__id__webauthn_options_r400_application_json_options_algorithms_i_h54 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `asksPostQuantum`:#{`type`:"boolean"},
      `classical`:#{`type`:"boolean"},
      `retrying`:#{`type`:"boolean"},
      `upgrade`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model post_authn_api_mfa__id__webauthn_options_r400_application_json_fallback_h55 {}

@js(#{`$types`:#["number","null"]}) @hoisted model post_authn_api_mfa__id__webauthn_options_r403_application_json_options_algorithms_i_h56 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `asksPostQuantum`:#{`type`:"boolean"},
      `classical`:#{`type`:"boolean"},
      `retrying`:#{`type`:"boolean"},
      `upgrade`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model post_authn_api_mfa__id__webauthn_options_r403_application_json_fallback_h57 {}

@js(#{`$types`:#["number","null"]}) @hoisted model post_authn_api_mfa__id__webauthn_options_r415_application_json_options_algorithms_i_h58 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `asksPostQuantum`:#{`type`:"boolean"},
      `classical`:#{`type`:"boolean"},
      `retrying`:#{`type`:"boolean"},
      `upgrade`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model post_authn_api_mfa__id__webauthn_options_r415_application_json_fallback_h59 {}

@js(#{`$types`:#["number","null"]}) @hoisted model post_authn_api_mfa__id__webauthn_options_r429_application_json_options_algorithms_i_h60 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `asksPostQuantum`:#{`type`:"boolean"},
      `classical`:#{`type`:"boolean"},
      `retrying`:#{`type`:"boolean"},
      `upgrade`:#{`type`:"boolean"}
    },
    `$types`:#["object","null"]
  }) @hoisted model post_authn_api_mfa__id__webauthn_options_r429_application_json_fallback_h61 {}

@endpoint("/authn-api/mfa/{id}/webauthn/options",
  "post",
  #{
    `operationId`:"passkeyStepOptions",
    `tags`:#["Sign-in"],
    `summary`:"Arms the passkey step's ceremony",
    `description`:"The step's challenge, the RP ID, the user (its handle and display name), the keys allowed and excluded and the passkey policy's options, for `navigator.credentials.create()` or `.get()` as `mode` says. `lane` (`classical` or `pqc`) chooses the lane a registration is made in where the realm offers both (#643): its handle, its algorithms and its exclude list. `algorithms: classical` (#944) arms a registration with the classical algorithms only, the retry `fallback.classical` says may be offered after an ML-DSA-first registration failed on the device; refused (400) where the realm forbids a classical passkey.\n\nThe door of the sign-in surface's `POST /authn/webauthn`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`lane`:"classical"}}}},
    `x-mirrors`:"POST /authn/webauthn"
  })
op `passkeyStepOptions`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {
    `key`?: post_authn_api_mfa__id__webauthn_options_b_application_json_key_h47;
    `lane`?: post_authn_api_mfa__id__webauthn_options_b_application_json_lane_h49;
    `algorithms`?: post_authn_api_mfa__id__webauthn_options_b_application_json_algorithms_h51
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `mode`?: "create" | "get";
    `challenge`?: string;
    `rpId`?: string;
    `user`?: {`name`?: string; `displayName`?: string; `id`?: string};
    `allow`?: (string)[];
    `exclude`?: (string)[];
    `options`?: {
      `rp`?: {`name`?: string; `id`?: string};
      `algorithms`?: (post_authn_api_mfa__id__webauthn_options_r200_application_json_options_algorithms_i_h52)[];
      `attestation`?: string;
      `timeout`?: numeric;
      `authenticatorSelection`?: {
        `userVerification`?: string;
        `residentKey`?: string;
        `requireResidentKey`?: boolean;
        `authenticatorAttachment`?: string
      };
      `credProps`?: boolean;
      `minPinLength`?: boolean;
      `hints`?: (string)[];
      `rpId`?: string;
      `userVerification`?: string
    };
    `fallback`?: post_authn_api_mfa__id__webauthn_options_r200_application_json_fallback_h53;
    `next`?: "refused"
  },
  `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `mode`?: "create" | "get";
    `challenge`?: string;
    `rpId`?: string;
    `user`?: {`name`?: string; `displayName`?: string; `id`?: string};
    `allow`?: (string)[];
    `exclude`?: (string)[];
    `options`?: {
      `rp`?: {`name`?: string; `id`?: string};
      `algorithms`?: (post_authn_api_mfa__id__webauthn_options_r400_application_json_options_algorithms_i_h54)[];
      `attestation`?: string;
      `timeout`?: numeric;
      `authenticatorSelection`?: {
        `userVerification`?: string;
        `residentKey`?: string;
        `requireResidentKey`?: boolean;
        `authenticatorAttachment`?: string
      };
      `credProps`?: boolean;
      `minPinLength`?: boolean;
      `hints`?: (string)[];
      `rpId`?: string;
      `userVerification`?: string
    };
    `fallback`?: post_authn_api_mfa__id__webauthn_options_r400_application_json_fallback_h55;
    `next`?: "refused"
  },
  `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `mode`?: "create" | "get";
    `challenge`?: string;
    `rpId`?: string;
    `user`?: {`name`?: string; `displayName`?: string; `id`?: string};
    `allow`?: (string)[];
    `exclude`?: (string)[];
    `options`?: {
      `rp`?: {`name`?: string; `id`?: string};
      `algorithms`?: (post_authn_api_mfa__id__webauthn_options_r403_application_json_options_algorithms_i_h56)[];
      `attestation`?: string;
      `timeout`?: numeric;
      `authenticatorSelection`?: {
        `userVerification`?: string;
        `residentKey`?: string;
        `requireResidentKey`?: boolean;
        `authenticatorAttachment`?: string
      };
      `credProps`?: boolean;
      `minPinLength`?: boolean;
      `hints`?: (string)[];
      `rpId`?: string;
      `userVerification`?: string
    };
    `fallback`?: post_authn_api_mfa__id__webauthn_options_r403_application_json_fallback_h57;
    `next`?: "refused"
  },
  `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `mode`?: "create" | "get";
    `challenge`?: string;
    `rpId`?: string;
    `user`?: {`name`?: string; `displayName`?: string; `id`?: string};
    `allow`?: (string)[];
    `exclude`?: (string)[];
    `options`?: {
      `rp`?: {`name`?: string; `id`?: string};
      `algorithms`?: (post_authn_api_mfa__id__webauthn_options_r415_application_json_options_algorithms_i_h58)[];
      `attestation`?: string;
      `timeout`?: numeric;
      `authenticatorSelection`?: {
        `userVerification`?: string;
        `residentKey`?: string;
        `requireResidentKey`?: boolean;
        `authenticatorAttachment`?: string
      };
      `credProps`?: boolean;
      `minPinLength`?: boolean;
      `hints`?: (string)[];
      `rpId`?: string;
      `userVerification`?: string
    };
    `fallback`?: post_authn_api_mfa__id__webauthn_options_r415_application_json_fallback_h59;
    `next`?: "refused"
  },
  `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `mode`?: "create" | "get";
    `challenge`?: string;
    `rpId`?: string;
    `user`?: {`name`?: string; `displayName`?: string; `id`?: string};
    `allow`?: (string)[];
    `exclude`?: (string)[];
    `options`?: {
      `rp`?: {`name`?: string; `id`?: string};
      `algorithms`?: (post_authn_api_mfa__id__webauthn_options_r429_application_json_options_algorithms_i_h60)[];
      `attestation`?: string;
      `timeout`?: numeric;
      `authenticatorSelection`?: {
        `userVerification`?: string;
        `residentKey`?: string;
        `requireResidentKey`?: boolean;
        `authenticatorAttachment`?: string
      };
      `credProps`?: boolean;
      `minPinLength`?: boolean;
      `hints`?: (string)[];
      `rpId`?: string;
      `userVerification`?: string
    };
    `fallback`?: post_authn_api_mfa__id__webauthn_options_r429_application_json_fallback_h61;
    `next`?: "refused"
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/mfa/{id}/webauthn",
  "post",
  #{
    `operationId`:"finishPasskeyStep",
    `tags`:#["Sign-in"],
    `summary`:"Verifies the passkey step's ceremony and finishes the step",
    `description`:"A registration where the step enrols a key, an assertion otherwise — decided by the step, not the body.\n\nThe door of the sign-in surface's `POST /authn/webauthn`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`credential`:"{}"}}}},
    `x-mirrors`:"POST /authn/webauthn"
  })
op `finishPasskeyStep`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {@js(#{`maxLength`:65536}) `credential`?: string},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/mfa/{id}/setup/totp",
  "post",
  #{
    `operationId`:"beginAppEnrolment",
    `tags`:#["Sign-in"],
    `summary`:"Begins enrolling an authenticator app at the set-up step",
    `description`:"The next step is the set-up page again, drawing the secret.\n\nThe door of the sign-in surface's `POST /authn/mfa-setup`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{}}}},
    `x-mirrors`:"POST /authn/mfa-setup"
  })
op `beginAppEnrolment`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/mfa/{id}/setup/confirm",
  "post",
  #{
    `operationId`:"confirmAppEnrolment",
    `tags`:#["Sign-in"],
    `summary`:"Confirms an authenticator app with its first code",
    `description`:"Rate limited; on success a session of two factors.\n\nThe door of the sign-in surface's `POST /authn/mfa-setup`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`code`:"000000"}}}},
    `x-mirrors`:"POST /authn/mfa-setup"
  })
op `confirmAppEnrolment`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {@js(#{`maxLength`:32}) `code`?: string},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/mfa/{id}/setup/webauthn",
  "post",
  #{
    `operationId`:"beginKeyEnrolment",
    `tags`:#["Sign-in"],
    `summary`:"Chooses a passkey at the set-up step",
    `description`:"The next step is the passkey page's registration.\n\nThe door of the sign-in surface's `POST /authn/mfa-setup`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{}}}},
    `x-mirrors`:"POST /authn/mfa-setup"
  })
op `beginKeyEnrolment`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/mfa/{id}/skip",
  "post",
  #{
    `operationId`:"ignoreOffer",
    `tags`:#["Sign-in"],
    `summary`:"Ignores an offered second factor (#246)",
    `description`:"Only where the step was offered rather than required: the sign-in finishes on the password.\n\nThe door of the sign-in surface's `POST /authn/mfa-setup`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{}}}},
    `x-mirrors`:"POST /authn/mfa-setup"
  })
op `ignoreOffer`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/mfa/{id}/post-login/register",
  "post",
  #{
    `operationId`:"registerPostLoginPasskey",
    `tags`:#["Sign-in"],
    `summary`:"Chooses to register the passkey a post-login activity asks for",
    `description`:"The next step is the passkey page's registration, offering ML-DSA only; the key has no role (#1135). Its finish starts the session the sign-in was held for. Where the realm can no longer enrol an ML-DSA passkey the session starts without it (STS-AUTHN-0475).\n\nThe door of the sign-in surface's `POST /authn/post-login`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{}}}},
    `x-mirrors`:"POST /authn/post-login"
  })
op `registerPostLoginPasskey`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/mfa/{id}/post-login/skip",
  "post",
  #{
    `operationId`:"skipPostLoginActivity",
    `tags`:#["Sign-in"],
    `summary`:"Puts a post-login activity off",
    `description`:"For the profile's `snoozeDays`; the held session starts. Refused (400) once the allotted time since the first invitation has passed (STS-AUTHN-0474).\n\nThe door of the sign-in surface's `POST /authn/post-login`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{}}}},
    `x-mirrors`:"POST /authn/post-login"
  })
op `skipPostLoginActivity`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/mfa/{id}/email/send",
  "post",
  #{
    `operationId`:"sendEmailedFactor",
    `tags`:#["Sign-in"],
    `summary`:"Mails a code or a sign-in link for the step (#64)",
    `description`:"To the person's verified address only; a resend replaces the last. `next: stay` with `notice: resent` where it went. A link's binding cookie is set on this answer.\n\nThe door of the sign-in surface's `POST /authn/email-code, /authn/email-link`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`kind`:"code"}}}},
    `x-mirrors`:"POST /authn/email-code, /authn/email-link"
  })
op `sendEmailedFactor`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {`kind`: "code" | "link"},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/mfa/{id}/email/code",
  "post",
  #{
    `operationId`:"checkEmailedCode",
    `tags`:#["Sign-in"],
    `summary`:"Checks an emailed code",
    `description`:"Once for the cluster, a bounded number of wrong codes per step, rate limited as the one-time code is.\n\nThe door of the sign-in surface's `POST /authn/email-code`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`code`:"000000"}}}},
    `x-mirrors`:"POST /authn/email-code"
  })
op `checkEmailedCode`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {@js(#{`maxLength`:32}) `code`?: string},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{`const`:""}) @hoisted scalar post_authn_api_mfa__id__email_link_open_b_application_json_t_v0_h62 extends string;
  

@js(#{`minLength`:1,`maxLength`:4096,`pattern`:"^[A-Za-z0-9_-]+$"}) @hoisted scalar post_authn_api_mfa__id__email_link_open_b_application_json_t_v1_h63 extends string;
  

@hoisted union post_authn_api_mfa__id__email_link_open_b_application_json_t_h64 {
    post_authn_api_mfa__id__email_link_open_b_application_json_t_v0_h62,
    post_authn_api_mfa__id__email_link_open_b_application_json_t_v1_h63
  }

@endpoint("/authn-api/mfa/{id}/email-link/open",
  "post",
  #{
    `operationId`:"spendEmailedLink",
    `tags`:#["Sign-in"],
    `summary`:"Spends a mailed sign-in link: its Continue button",
    `description`:"Only in the browser that asked for the link (the `sts_email_binding` cookie). Opening the link spends nothing.\n\nThe door of the sign-in surface's `POST /authn/email-link/open`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`t`:"noSuchLinkTokenExample"}}}},
    `x-mirrors`:"POST /authn/email-link/open"
  })
op `spendEmailedLink`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {`t`?: post_authn_api_mfa__id__email_link_open_b_application_json_t_h64},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/mfa/{id}/start-over",
  "post",
  #{
    `operationId`:"startOver",
    `tags`:#["Sign-in"],
    `summary`:"Leaves a sign-in step and starts the sign-in over",
    `description`:"Every second-factor, set-up and emailed-factor page's Start over button. The step is ended with whatever it held (an emailed code, a link, an enrolment in progress), no session is started and no factor is counted, and the pending sign-in the step was minted from is put back under its id, so the request it carries completes after the person signs in again. `next: redirect` to the sign-in screen; a step that has already ended is refused (400).\n\nThe door of the sign-in surface's `POST /authn/totp, /authn/webauthn, /authn/backup-code, /authn/password-factor, /authn/mfa-setup, /authn/email-code, /authn/email-link, /authn/email-link/open`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The second-factor or emailed-factor step's id: a bearer capability, as the `mfa` its page was opened with.",
        `schema`:null,
        `example`:"noSuchStepExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{}}}},
    `x-mirrors`:"POST /authn/totp, /authn/webauthn, /authn/backup-code, /authn/password-factor, /authn/mfa-setup, /authn/email-code, /authn/email-link, /authn/email-link/open"
  })
op `startOver`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/wallet",
  "get",
  #{
    `operationId`:"getWalletStart",
    `tags`:#["Sign-in"],
    `summary`:"What a wallet sign-in's start page needs",
    `description`:"Takes the start page's query — `authn` (a pending sign-in) or `mfa` (a second-factor step), `siop=1` for a self-issued ID Token, `enrol=1` to enrol one from a session (with `login_hint` naming which of the browser's accounts, and `did_act` one of a published DID's wallet acts, #1291) — and answers what is being started and `csrf`, after the refusals a start would meet. It creates nothing.\n\nThe door of the sign-in surface's `GET /authn/wallet`.",
    `parameters`:#[
      #{
        `name`:"authn",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"A pending sign-in.",
        `example`:"noSuchSignInExample"
      },
      #{
        `name`:"mfa",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"A second-factor step."
      },
      #{
        `name`:"siop",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"`1` for a self-issued ID Token rather than a presentation."
      },
      #{
        `name`:"enrol",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"`1` to enrol a key from a session rather than to sign in."
      },
      #{
        `name`:"login_hint",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Which of this browser's accounts an enrolment is for."
      },
      #{
        `name`:"did_act",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"A published DID's wallet act, on an enrolment (#1291)."
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `404`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `410`:#{
        `description`:"The answer.",
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
    `security`:#[],
    `x-mirrors`:"GET /authn/wallet"
  })
op `getWalletStart`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`minLength`:1,`maxLength`:4096}]}}) `parameters/0/schema`: unknown,
  @js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`minLength`:1,`maxLength`:4096}]}}) `parameters/1/schema`: unknown,
  @js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`enum`:#["1"]}]}}) `parameters/2/schema`: unknown,
  @js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`enum`:#["1"]}]}}) `parameters/3/schema`: unknown,
  @js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`minLength`:1,`maxLength`:4096}]}}) `parameters/4/schema`: unknown,
  @js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`minLength`:1,`maxLength`:4096}]}}) `parameters/5/schema`: unknown,
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "start" | "refused";
      `kind`?: string;
      `secondFactor`?: boolean;
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "start" | "refused";
      `kind`?: string;
      `secondFactor`?: boolean;
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/401/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "start" | "refused";
      `kind`?: string;
      `secondFactor`?: boolean;
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "start" | "refused";
      `kind`?: string;
      `secondFactor`?: boolean;
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/404/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "start" | "refused";
      `kind`?: string;
      `secondFactor`?: boolean;
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/409/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "start" | "refused";
      `kind`?: string;
      `secondFactor`?: boolean;
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/410/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "start" | "refused";
      `kind`?: string;
      `secondFactor`?: boolean;
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/500/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "start" | "refused";
      `kind`?: string;
      `secondFactor`?: boolean;
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/503/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "start" | "refused";
      `kind`?: string;
      `secondFactor`?: boolean;
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet_b_application_json_authn_v0_h65 extends string;
  

@js(#{`minLength`:1,`maxLength`:4096}) @hoisted scalar post_authn_api_wallet_b_application_json_authn_v1_h66 extends string;
  

@hoisted union post_authn_api_wallet_b_application_json_authn_h67 {
    post_authn_api_wallet_b_application_json_authn_v0_h65,
    post_authn_api_wallet_b_application_json_authn_v1_h66
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet_b_application_json_mfa_v0_h68 extends string;
  

@js(#{`minLength`:1,`maxLength`:4096}) @hoisted scalar post_authn_api_wallet_b_application_json_mfa_v1_h69 extends string;
  

@hoisted union post_authn_api_wallet_b_application_json_mfa_h70 {
    post_authn_api_wallet_b_application_json_mfa_v0_h68,
    post_authn_api_wallet_b_application_json_mfa_v1_h69
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet_b_application_json_enrol_v0_h71 extends string;
  

@hoisted union post_authn_api_wallet_b_application_json_enrol_h72 {post_authn_api_wallet_b_application_json_enrol_v0_h71, "1"}

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet_b_application_json_siop_v0_h73 extends string;
  

@hoisted union post_authn_api_wallet_b_application_json_siop_h74 {post_authn_api_wallet_b_application_json_siop_v0_h73, "1"}

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet_b_application_json_wallet_v0_h75 extends string;
  

@js(#{`minLength`:1,`maxLength`:2048,`format`:"uri"}) @hoisted scalar post_authn_api_wallet_b_application_json_wallet_v1_h76 extends string;
  

@hoisted union post_authn_api_wallet_b_application_json_wallet_h77 {
    post_authn_api_wallet_b_application_json_wallet_v0_h75,
    post_authn_api_wallet_b_application_json_wallet_v1_h76
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet_b_application_json_login_hint_v0_h78 extends string;
  

@js(#{`minLength`:1,`maxLength`:4096}) @hoisted scalar post_authn_api_wallet_b_application_json_login_hint_v1_h79 extends string;
  

@hoisted union post_authn_api_wallet_b_application_json_login_hint_h80 {
    post_authn_api_wallet_b_application_json_login_hint_v0_h78,
    post_authn_api_wallet_b_application_json_login_hint_v1_h79
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet_b_application_json_did_act_v0_h81 extends string;
  

@js(#{`minLength`:1,`maxLength`:4096}) @hoisted scalar post_authn_api_wallet_b_application_json_did_act_v1_h82 extends string;
  

@hoisted union post_authn_api_wallet_b_application_json_did_act_h83 {
    post_authn_api_wallet_b_application_json_did_act_v0_h81,
    post_authn_api_wallet_b_application_json_did_act_v1_h82
  }

@endpoint("/authn-api/wallet",
  "post",
  #{
    `operationId`:"startWalletSignIn",
    `tags`:#["Sign-in"],
    `summary`:"Starts a wallet sign-in",
    `description`:"An OpenID4VP request bound to the pending sign-in (or the step, or the enrolment) and to this browser by the `sts_wallet_binding` cookie this answer sets; `go` names the wait page.\n\nThe door of the sign-in surface's `GET /authn/wallet`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `404`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `410`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts.",
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
    `security`:#[],
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`authn`:"noSuchSignInExample"}}}},
    `x-mirrors`:"GET /authn/wallet"
  })
op `startWalletSignIn`(`parameters/0/schema`: string,
  `requestBody/content/application~1json/schema`: {
    `authn`?: post_authn_api_wallet_b_application_json_authn_h67;
    `mfa`?: post_authn_api_wallet_b_application_json_mfa_h70;
    `enrol`?: post_authn_api_wallet_b_application_json_enrol_h72;
    `siop`?: post_authn_api_wallet_b_application_json_siop_h74;
    `wallet`?: post_authn_api_wallet_b_application_json_wallet_h77;
    `login_hint`?: post_authn_api_wallet_b_application_json_login_hint_h80;
    `did_act`?: post_authn_api_wallet_b_application_json_did_act_h83
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/401/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/404/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/409/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/410/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/500/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/503/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `protocol`:#{`type`:"string"},
      `data`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`request`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_wallet__state__r200_application_json_view_dcRequest_h84 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `protocol`:#{`type`:"string"},
      `data`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`request`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_wallet__state__r400_application_json_view_dcRequest_h85 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `protocol`:#{`type`:"string"},
      `data`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`request`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_wallet__state__r401_application_json_view_dcRequest_h86 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `protocol`:#{`type`:"string"},
      `data`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`request`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_wallet__state__r403_application_json_view_dcRequest_h87 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `protocol`:#{`type`:"string"},
      `data`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`request`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_wallet__state__r404_application_json_view_dcRequest_h88 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `protocol`:#{`type`:"string"},
      `data`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`request`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_wallet__state__r409_application_json_view_dcRequest_h89 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `protocol`:#{`type`:"string"},
      `data`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`request`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_wallet__state__r410_application_json_view_dcRequest_h90 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `protocol`:#{`type`:"string"},
      `data`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`request`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_wallet__state__r500_application_json_view_dcRequest_h91 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `protocol`:#{`type`:"string"},
      `data`:#{
        `type`:"object",
        `additionalProperties`:false,
        `properties`:#{`request`:#{`type`:"string"}}
      }
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_wallet__state__r503_application_json_view_dcRequest_h92 {}

@endpoint("/authn-api/wallet/{state}",
  "get",
  #{
    `operationId`:"getWalletWait",
    `tags`:#["Sign-in"],
    `summary`:"What the wallet sign-in's wait page draws",
    `description`:"For the browser that started the transaction only: the Digital Credentials API request, the same-device link (`sameDevice`: the request under the scheme a wallet app registers for, `oid4vp.walletInvocation`), a configured web wallet's link (`webWallet`, or empty), the QR code's text where `oid4vp.signInCrossDevice` offers it, the seconds left and the poll's interval, and `csrf`.\n\nThe door of the sign-in surface's `GET /authn/wallet/wait`.",
    `parameters`:#[
      #{
        `name`:"state",
        `in`:"path",
        `required`:true,
        `description`:"The wallet sign-in's transaction: a bearer capability, answered to this browser only (its `sts_wallet_binding` cookie).",
        `schema`:null,
        `example`:"noSuchWalletStateExample"
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `404`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `410`:#{
        `description`:"The answer.",
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
    `security`:#[],
    `x-mirrors`:"GET /authn/wallet/wait"
  })
op `getWalletWait`(`parameters/0/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "wait" | "refused";
      `state`?: string;
      `kind`?: string;
      `secondFactor`?: boolean;
      `authn`?: string;
      `mfa`?: string;
      `enrol`?: boolean;
      `dcRequest`?: get_authn_api_wallet__state__r200_application_json_view_dcRequest_h84;
      `sameDevice`?: string;
      `webWallet`?: string;
      `qr`?: string;
      `expiresIn`?: numeric;
      `pollSeconds`?: numeric;
      `protocol`?: string;
      `verifier`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "wait" | "refused";
      `state`?: string;
      `kind`?: string;
      `secondFactor`?: boolean;
      `authn`?: string;
      `mfa`?: string;
      `enrol`?: boolean;
      `dcRequest`?: get_authn_api_wallet__state__r400_application_json_view_dcRequest_h85;
      `sameDevice`?: string;
      `webWallet`?: string;
      `qr`?: string;
      `expiresIn`?: numeric;
      `pollSeconds`?: numeric;
      `protocol`?: string;
      `verifier`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/401/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "wait" | "refused";
      `state`?: string;
      `kind`?: string;
      `secondFactor`?: boolean;
      `authn`?: string;
      `mfa`?: string;
      `enrol`?: boolean;
      `dcRequest`?: get_authn_api_wallet__state__r401_application_json_view_dcRequest_h86;
      `sameDevice`?: string;
      `webWallet`?: string;
      `qr`?: string;
      `expiresIn`?: numeric;
      `pollSeconds`?: numeric;
      `protocol`?: string;
      `verifier`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "wait" | "refused";
      `state`?: string;
      `kind`?: string;
      `secondFactor`?: boolean;
      `authn`?: string;
      `mfa`?: string;
      `enrol`?: boolean;
      `dcRequest`?: get_authn_api_wallet__state__r403_application_json_view_dcRequest_h87;
      `sameDevice`?: string;
      `webWallet`?: string;
      `qr`?: string;
      `expiresIn`?: numeric;
      `pollSeconds`?: numeric;
      `protocol`?: string;
      `verifier`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/404/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "wait" | "refused";
      `state`?: string;
      `kind`?: string;
      `secondFactor`?: boolean;
      `authn`?: string;
      `mfa`?: string;
      `enrol`?: boolean;
      `dcRequest`?: get_authn_api_wallet__state__r404_application_json_view_dcRequest_h88;
      `sameDevice`?: string;
      `webWallet`?: string;
      `qr`?: string;
      `expiresIn`?: numeric;
      `pollSeconds`?: numeric;
      `protocol`?: string;
      `verifier`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/409/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "wait" | "refused";
      `state`?: string;
      `kind`?: string;
      `secondFactor`?: boolean;
      `authn`?: string;
      `mfa`?: string;
      `enrol`?: boolean;
      `dcRequest`?: get_authn_api_wallet__state__r409_application_json_view_dcRequest_h89;
      `sameDevice`?: string;
      `webWallet`?: string;
      `qr`?: string;
      `expiresIn`?: numeric;
      `pollSeconds`?: numeric;
      `protocol`?: string;
      `verifier`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/410/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "wait" | "refused";
      `state`?: string;
      `kind`?: string;
      `secondFactor`?: boolean;
      `authn`?: string;
      `mfa`?: string;
      `enrol`?: boolean;
      `dcRequest`?: get_authn_api_wallet__state__r410_application_json_view_dcRequest_h90;
      `sameDevice`?: string;
      `webWallet`?: string;
      `qr`?: string;
      `expiresIn`?: numeric;
      `pollSeconds`?: numeric;
      `protocol`?: string;
      `verifier`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/500/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "wait" | "refused";
      `state`?: string;
      `kind`?: string;
      `secondFactor`?: boolean;
      `authn`?: string;
      `mfa`?: string;
      `enrol`?: boolean;
      `dcRequest`?: get_authn_api_wallet__state__r500_application_json_view_dcRequest_h91;
      `sameDevice`?: string;
      `webWallet`?: string;
      `qr`?: string;
      `expiresIn`?: numeric;
      `pollSeconds`?: numeric;
      `protocol`?: string;
      `verifier`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/503/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `wallet`?: "wait" | "refused";
      `state`?: string;
      `kind`?: string;
      `secondFactor`?: boolean;
      `authn`?: string;
      `mfa`?: string;
      `enrol`?: boolean;
      `dcRequest`?: get_authn_api_wallet__state__r503_application_json_view_dcRequest_h92;
      `sameDevice`?: string;
      `webWallet`?: string;
      `qr`?: string;
      `expiresIn`?: numeric;
      `pollSeconds`?: numeric;
      `protocol`?: string;
      `verifier`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `reissue`?: string
    };
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet__state__status_b_application_json_authn_v0_h93 extends string;
  

@js(#{`minLength`:1,`maxLength`:4096}) @hoisted scalar post_authn_api_wallet__state__status_b_application_json_authn_v1_h94 extends string;
  

@hoisted union post_authn_api_wallet__state__status_b_application_json_authn_h95 {
    post_authn_api_wallet__state__status_b_application_json_authn_v0_h93,
    post_authn_api_wallet__state__status_b_application_json_authn_v1_h94
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet__state__status_b_application_json_mfa_v0_h96 extends string;
  

@js(#{`minLength`:1,`maxLength`:4096}) @hoisted scalar post_authn_api_wallet__state__status_b_application_json_mfa_v1_h97 extends string;
  

@hoisted union post_authn_api_wallet__state__status_b_application_json_mfa_h98 {
    post_authn_api_wallet__state__status_b_application_json_mfa_v0_h96,
    post_authn_api_wallet__state__status_b_application_json_mfa_v1_h97
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet__state__status_b_application_json_enrol_v0_h99 extends string;
  

@hoisted union post_authn_api_wallet__state__status_b_application_json_enrol_h100 {
    post_authn_api_wallet__state__status_b_application_json_enrol_v0_h99,
    "1"
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet__state__status_b_application_json_response_code_v0_h101 extends string;
  

@js(#{`minLength`:1,`maxLength`:4096}) @hoisted scalar post_authn_api_wallet__state__status_b_application_json_response_code_v1_h102 extends string;
  

@hoisted union post_authn_api_wallet__state__status_b_application_json_response_code_h103 {
    post_authn_api_wallet__state__status_b_application_json_response_code_v0_h101,
    post_authn_api_wallet__state__status_b_application_json_response_code_v1_h102
  }

@endpoint("/authn-api/wallet/{state}/status",
  "post",
  #{
    `operationId`:"walletStatus",
    `tags`:#["Sign-in"],
    `summary`:"Whether the wallet has answered, and the sign-in once it has",
    `description`:"The poll: `wait` until the wallet has answered, then the sign-in finished in this request — once, in the browser that started it, with the right `response_code` where one is carried.\n\nThe door of the sign-in surface's `GET /authn/wallet/wait`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"state",
        `in`:"path",
        `required`:true,
        `description`:"The wallet sign-in's transaction: a bearer capability, answered to this browser only (its `sts_wallet_binding` cookie).",
        `schema`:null,
        `example`:"noSuchWalletStateExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `404`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `410`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts.",
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
    `security`:#[],
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`authn`:"noSuchSignInExample"}}}},
    `x-mirrors`:"GET /authn/wallet/wait"
  })
op `walletStatus`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {
    `authn`?: post_authn_api_wallet__state__status_b_application_json_authn_h95;
    `mfa`?: post_authn_api_wallet__state__status_b_application_json_mfa_h98;
    `enrol`?: post_authn_api_wallet__state__status_b_application_json_enrol_h100;
    `response_code`?: post_authn_api_wallet__state__status_b_application_json_response_code_h103
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/401/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/404/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/409/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/410/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/500/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/503/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet__state__dc_api_b_application_json_authn_v0_h104 extends string;
  

@js(#{`minLength`:1,`maxLength`:4096}) @hoisted scalar post_authn_api_wallet__state__dc_api_b_application_json_authn_v1_h105 extends string;
  

@hoisted union post_authn_api_wallet__state__dc_api_b_application_json_authn_h106 {
    post_authn_api_wallet__state__dc_api_b_application_json_authn_v0_h104,
    post_authn_api_wallet__state__dc_api_b_application_json_authn_v1_h105
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet__state__dc_api_b_application_json_mfa_v0_h107 extends string;
  

@js(#{`minLength`:1,`maxLength`:4096}) @hoisted scalar post_authn_api_wallet__state__dc_api_b_application_json_mfa_v1_h108 extends string;
  

@hoisted union post_authn_api_wallet__state__dc_api_b_application_json_mfa_h109 {
    post_authn_api_wallet__state__dc_api_b_application_json_mfa_v0_h107,
    post_authn_api_wallet__state__dc_api_b_application_json_mfa_v1_h108
  }

@js(#{`const`:""}) @hoisted scalar post_authn_api_wallet__state__dc_api_b_application_json_enrol_v0_h110 extends string;
  

@hoisted union post_authn_api_wallet__state__dc_api_b_application_json_enrol_h111 {
    post_authn_api_wallet__state__dc_api_b_application_json_enrol_v0_h110,
    "1"
  }

@js(#{`maxLength`:1048576}) @hoisted scalar post_authn_api_wallet__state__dc_api_b_application_json_response_v0_h112 extends string;
  

@js(#{`$open`:true}) @hoisted model post_authn_api_wallet__state__dc_api_b_application_json_response_v1_h113 {@js(#{`maxLength`:200}) `protocol`: string; `data`: unknown}

@hoisted union post_authn_api_wallet__state__dc_api_b_application_json_response_h114 {
    post_authn_api_wallet__state__dc_api_b_application_json_response_v0_h112,
    post_authn_api_wallet__state__dc_api_b_application_json_response_v1_h113
  }

@endpoint("/authn-api/wallet/{state}/dc-api",
  "post",
  #{
    `operationId`:"answerWalletDcApi",
    `tags`:#["Sign-in"],
    `summary`:"The Digital Credentials API's answer",
    `description`:"The DigitalCredential `navigator.credentials.get()` answered, from a page on this service's own origin: decrypted where the request asked for `dc_api.jwt`, verified with `origin:<origin>` as the audience, answered once, and the sign-in finished in this request.\n\nThe door of the sign-in surface's `GET /authn/wallet/wait`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"state",
        `in`:"path",
        `required`:true,
        `description`:"The wallet sign-in's transaction: a bearer capability, answered to this browser only (its `sts_wallet_binding` cookie).",
        `schema`:null,
        `example`:"noSuchWalletStateExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `404`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `410`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts.",
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
    `security`:#[],
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`authn`:"noSuchSignInExample",`response`:"{}"}}}},
    `x-mirrors`:"GET /authn/wallet/wait"
  })
op `answerWalletDcApi`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {
    `authn`?: post_authn_api_wallet__state__dc_api_b_application_json_authn_h106;
    `mfa`?: post_authn_api_wallet__state__dc_api_b_application_json_mfa_h109;
    `enrol`?: post_authn_api_wallet__state__dc_api_b_application_json_enrol_h111;
    `response`?: post_authn_api_wallet__state__dc_api_b_application_json_response_h114
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/401/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/404/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/409/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/410/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/500/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  `responses/503/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean};
    `go`?: string;
    `state`?: string;
    `expiresIn`?: numeric;
    `view`?: {
      `wallet`?: "refused";
      `heading`?: string;
      `retry`?: string;
      `checks`?: ({`ok`?: boolean; `name`?: string; `detail`?: string})[];
      `verdict`?: string;
      `back`?: string;
      `backKind`?: "portal" | "screen" | "none";
      `reissue`?: string
    }
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@hoisted union get_authn_api_logout_r200_application_json_view_families_i_rows_i_handle_h115 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r200_application_json_view_families_i_rows_i_label_h116 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r200_application_json_view_families_i_rows_i_detail_h117 {}

@js(#{`$types`:#["number","null"]}) @hoisted model get_authn_api_logout_r200_application_json_view_families_i_rows_i_startedAt_h118 {}

@js(#{`$types`:#["number","null"]}) @hoisted model get_authn_api_logout_r200_application_json_view_families_i_rows_i_expiresAt_h119 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r200_application_json_view_families_i_rows_i_why_h120 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r200_application_json_view_families_i_rows_i_sessionId_h121 {}

@hoisted union get_authn_api_logout_r400_application_json_view_families_i_rows_i_handle_h122 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r400_application_json_view_families_i_rows_i_label_h123 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r400_application_json_view_families_i_rows_i_detail_h124 {}

@js(#{`$types`:#["number","null"]}) @hoisted model get_authn_api_logout_r400_application_json_view_families_i_rows_i_startedAt_h125 {}

@js(#{`$types`:#["number","null"]}) @hoisted model get_authn_api_logout_r400_application_json_view_families_i_rows_i_expiresAt_h126 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r400_application_json_view_families_i_rows_i_why_h127 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r400_application_json_view_families_i_rows_i_sessionId_h128 {}

@hoisted union get_authn_api_logout_r401_application_json_view_families_i_rows_i_handle_h129 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r401_application_json_view_families_i_rows_i_label_h130 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r401_application_json_view_families_i_rows_i_detail_h131 {}

@js(#{`$types`:#["number","null"]}) @hoisted model get_authn_api_logout_r401_application_json_view_families_i_rows_i_startedAt_h132 {}

@js(#{`$types`:#["number","null"]}) @hoisted model get_authn_api_logout_r401_application_json_view_families_i_rows_i_expiresAt_h133 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r401_application_json_view_families_i_rows_i_why_h134 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r401_application_json_view_families_i_rows_i_sessionId_h135 {}

@hoisted union get_authn_api_logout_r403_application_json_view_families_i_rows_i_handle_h136 {string, numeric}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r403_application_json_view_families_i_rows_i_label_h137 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r403_application_json_view_families_i_rows_i_detail_h138 {}

@js(#{`$types`:#["number","null"]}) @hoisted model get_authn_api_logout_r403_application_json_view_families_i_rows_i_startedAt_h139 {}

@js(#{`$types`:#["number","null"]}) @hoisted model get_authn_api_logout_r403_application_json_view_families_i_rows_i_expiresAt_h140 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r403_application_json_view_families_i_rows_i_why_h141 {}

@js(#{`$types`:#["string","null"]}) @hoisted model get_authn_api_logout_r403_application_json_view_families_i_rows_i_sessionId_h142 {}

@endpoint("/authn-api/logout",
  "get",
  #{
    `operationId`:"getSignOut",
    `tags`:#["Sign-in"],
    `summary`:"Everything a sign-out would end",
    `description`:"The sign-out page's view, as facts and no words: every family of live session or credential this service holds for the person the browser's session names — or `username`, where naming somebody is open (a development test control) — each row with whether it can be ended and why not, and `csrf`. Refused (403) for a name that may not be used, and (401) with nobody to act on.\n\nThe door of the sign-in surface's `GET /logout`.",
    `parameters`:#[
      #{
        `name`:"username",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Whom the page is about, where naming somebody is open (development mode and `logout.anyUser`), or the caller's own name; the browser's session otherwise.",
        `example`:"nobody-example"
      },
      #{
        `name`:"account",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"With authn.multipleAccounts on (#561): one of this browser's signed-in accounts, by its key."
      },
      #{
        `name`:"login_hint",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"With authn.multipleAccounts on (#561): the account the sign-out's account step preselects."
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-mirrors`:"GET /logout"
  })
op `getSignOut`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`minLength`:1,`maxLength`:256}]}}) `parameters/0/schema`: unknown,
  @js(#{`minLength`:1,`maxLength`:600}) `parameters/1/schema`: string,
  @js(#{`maxLength`:512}) `parameters/2/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `state`?: "inventory" | "accounts" | "refused" | "nobody";
      `username`?: string;
      `named`?: boolean;
      `naming`?: "open" | "off" | "product";
      `account`?: string;
      `key`?: string;
      `sessions`?: numeric;
      `families`?: ({
        `id`?: string;
        `label`?: string;
        `protocol`?: string;
        `spec`?: string;
        `what`?: string;
        `terminable`?: boolean;
        `rows`?: ({
          `id`?: string;
          `family`?: string;
          `kind`?: string;
          `handle`?: get_authn_api_logout_r200_application_json_view_families_i_rows_i_handle_h115;
          `label`?: get_authn_api_logout_r200_application_json_view_families_i_rows_i_label_h116;
          `detail`?: get_authn_api_logout_r200_application_json_view_families_i_rows_i_detail_h117;
          `startedAt`?: get_authn_api_logout_r200_application_json_view_families_i_rows_i_startedAt_h118;
          `expiresAt`?: get_authn_api_logout_r200_application_json_view_families_i_rows_i_expiresAt_h119;
          `terminable`?: boolean;
          `why`?: get_authn_api_logout_r200_application_json_view_families_i_rows_i_why_h120;
          `sessionId`?: get_authn_api_logout_r200_application_json_view_families_i_rows_i_sessionId_h121
        })[];
        `held`?: numeric;
        `notListed`?: numeric;
        `failure`?: string
      })[];
      `total`?: numeric;
      `listed`?: numeric;
      `notListed`?: numeric;
      `maxRows`?: numeric;
      `at`?: numeric;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `verifiesCredentials`?: boolean
    };
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `state`?: "inventory" | "accounts" | "refused" | "nobody";
      `username`?: string;
      `named`?: boolean;
      `naming`?: "open" | "off" | "product";
      `account`?: string;
      `key`?: string;
      `sessions`?: numeric;
      `families`?: ({
        `id`?: string;
        `label`?: string;
        `protocol`?: string;
        `spec`?: string;
        `what`?: string;
        `terminable`?: boolean;
        `rows`?: ({
          `id`?: string;
          `family`?: string;
          `kind`?: string;
          `handle`?: get_authn_api_logout_r400_application_json_view_families_i_rows_i_handle_h122;
          `label`?: get_authn_api_logout_r400_application_json_view_families_i_rows_i_label_h123;
          `detail`?: get_authn_api_logout_r400_application_json_view_families_i_rows_i_detail_h124;
          `startedAt`?: get_authn_api_logout_r400_application_json_view_families_i_rows_i_startedAt_h125;
          `expiresAt`?: get_authn_api_logout_r400_application_json_view_families_i_rows_i_expiresAt_h126;
          `terminable`?: boolean;
          `why`?: get_authn_api_logout_r400_application_json_view_families_i_rows_i_why_h127;
          `sessionId`?: get_authn_api_logout_r400_application_json_view_families_i_rows_i_sessionId_h128
        })[];
        `held`?: numeric;
        `notListed`?: numeric;
        `failure`?: string
      })[];
      `total`?: numeric;
      `listed`?: numeric;
      `notListed`?: numeric;
      `maxRows`?: numeric;
      `at`?: numeric;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `verifiesCredentials`?: boolean
    };
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/401/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `state`?: "inventory" | "accounts" | "refused" | "nobody";
      `username`?: string;
      `named`?: boolean;
      `naming`?: "open" | "off" | "product";
      `account`?: string;
      `key`?: string;
      `sessions`?: numeric;
      `families`?: ({
        `id`?: string;
        `label`?: string;
        `protocol`?: string;
        `spec`?: string;
        `what`?: string;
        `terminable`?: boolean;
        `rows`?: ({
          `id`?: string;
          `family`?: string;
          `kind`?: string;
          `handle`?: get_authn_api_logout_r401_application_json_view_families_i_rows_i_handle_h129;
          `label`?: get_authn_api_logout_r401_application_json_view_families_i_rows_i_label_h130;
          `detail`?: get_authn_api_logout_r401_application_json_view_families_i_rows_i_detail_h131;
          `startedAt`?: get_authn_api_logout_r401_application_json_view_families_i_rows_i_startedAt_h132;
          `expiresAt`?: get_authn_api_logout_r401_application_json_view_families_i_rows_i_expiresAt_h133;
          `terminable`?: boolean;
          `why`?: get_authn_api_logout_r401_application_json_view_families_i_rows_i_why_h134;
          `sessionId`?: get_authn_api_logout_r401_application_json_view_families_i_rows_i_sessionId_h135
        })[];
        `held`?: numeric;
        `notListed`?: numeric;
        `failure`?: string
      })[];
      `total`?: numeric;
      `listed`?: numeric;
      `notListed`?: numeric;
      `maxRows`?: numeric;
      `at`?: numeric;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `verifiesCredentials`?: boolean
    };
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `state`?: "inventory" | "accounts" | "refused" | "nobody";
      `username`?: string;
      `named`?: boolean;
      `naming`?: "open" | "off" | "product";
      `account`?: string;
      `key`?: string;
      `sessions`?: numeric;
      `families`?: ({
        `id`?: string;
        `label`?: string;
        `protocol`?: string;
        `spec`?: string;
        `what`?: string;
        `terminable`?: boolean;
        `rows`?: ({
          `id`?: string;
          `family`?: string;
          `kind`?: string;
          `handle`?: get_authn_api_logout_r403_application_json_view_families_i_rows_i_handle_h136;
          `label`?: get_authn_api_logout_r403_application_json_view_families_i_rows_i_label_h137;
          `detail`?: get_authn_api_logout_r403_application_json_view_families_i_rows_i_detail_h138;
          `startedAt`?: get_authn_api_logout_r403_application_json_view_families_i_rows_i_startedAt_h139;
          `expiresAt`?: get_authn_api_logout_r403_application_json_view_families_i_rows_i_expiresAt_h140;
          `terminable`?: boolean;
          `why`?: get_authn_api_logout_r403_application_json_view_families_i_rows_i_why_h141;
          `sessionId`?: get_authn_api_logout_r403_application_json_view_families_i_rows_i_sessionId_h142
        })[];
        `held`?: numeric;
        `notListed`?: numeric;
        `failure`?: string
      })[];
      `total`?: numeric;
      `listed`?: numeric;
      `notListed`?: numeric;
      `maxRows`?: numeric;
      `at`?: numeric;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `verifiesCredentials`?: boolean
    };
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{`const`:""}) @hoisted scalar post_authn_api_logout_b_application_json_scope_v0_h143 extends string;
  

@hoisted union post_authn_api_logout_b_application_json_scope_h144 {
    post_authn_api_logout_b_application_json_scope_v0_h143,
    "global" | "selected"
  }

@js(#{`maxLength`:4096}) @hoisted scalar post_authn_api_logout_b_application_json_select_i_h145 extends string;
  

@js(#{`const`:""}) @hoisted scalar post_authn_api_logout_b_application_json_username_v0_h146 extends string;
  

@js(#{`minLength`:1,`maxLength`:256}) @hoisted scalar post_authn_api_logout_b_application_json_username_v1_h147 extends string;
  

@hoisted union post_authn_api_logout_b_application_json_username_h148 {
    post_authn_api_logout_b_application_json_username_v0_h146,
    post_authn_api_logout_b_application_json_username_v1_h147
  }

@endpoint("/authn-api/logout",
  "post",
  #{
    `operationId`:"signOut",
    `tags`:#["Sign-in"],
    `summary`:"Signs out: everything, or what was ticked",
    `description`:"A `scope` of `global`, or no selection, ends everything the person holds; `select` ends those rows only, each looked up again now. The answer is the result, or the signed-out document that carries what the browser must still do.\n\nThe door of the sign-in surface's `POST /logout`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`scope`:"selected",`select`:#["no-such-row"]}}}},
    `x-mirrors`:"POST /logout"
  })
op `signOut`(`parameters/0/schema`: string,
  `requestBody/content/application~1json/schema`: {
    `scope`?: post_authn_api_logout_b_application_json_scope_h144;
    @js(#{`maxItems`:10000}) `select`?: (post_authn_api_logout_b_application_json_select_i_h145)[];
    `username`?: post_authn_api_logout_b_application_json_username_h148;
    @js(#{`minLength`:1,`maxLength`:600}) `account`?: string
  },
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  `responses/401/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  `responses/409/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/logout/accounts",
  "get",
  #{
    `operationId`:"getSignOutAccounts",
    `tags`:#["Sign-in"],
    `summary`:"Which account a sign-out is for",
    `description`:"The sign-out's account step: this browser's signed-in accounts, each by its key, names and whether it is the browser's default — never a sid — the one `login_hint` names, preselected, and `csrf`. 400 where authn.multipleAccounts is off.\n\nThe door of the sign-in surface's `GET /logout/accounts`.",
    `parameters`:#[
      #{
        `name`:"username",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"Whom the page is about, where naming somebody is open (development mode and `logout.anyUser`), or the caller's own name; the browser's session otherwise."
      },
      #{
        `name`:"account",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"With authn.multipleAccounts on (#561): one of this browser's signed-in accounts, by its key."
      },
      #{
        `name`:"login_hint",
        `in`:"query",
        `required`:false,
        `schema`:null,
        `description`:"With authn.multipleAccounts on (#561): the account the sign-out's account step preselects.",
        `example`:"nobody-example"
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-mirrors`:"GET /logout/accounts"
  })
op `getSignOutAccounts`(@js(#{`$raw`:#{`anyOf`:#[#{`type`:"string",`const`:""},#{`type`:"string",`minLength`:1,`maxLength`:256}]}}) `parameters/0/schema`: unknown,
  @js(#{`minLength`:1,`maxLength`:600}) `parameters/1/schema`: string,
  @js(#{`maxLength`:512}) `parameters/2/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `state`?: "accounts";
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    };
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `state`?: "accounts";
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    };
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/logout/accounts",
  "post",
  #{
    `operationId`:"chooseSignOutAccount",
    `tags`:#["Sign-in"],
    `summary`:"Chooses the account to sign out, or every account",
    `description`:"An account's key answers `next: inventory` and the address of that person's sign-out page; `all` signs every account in this browser out — each person's own global sign-out — and answers as `POST /authn-api/logout` does. 409 for an account no longer signed in here.\n\nThe door of the sign-in surface's `POST /logout/accounts`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `401`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`account`:"name:nobody-example"}}}},
    `x-mirrors`:"POST /logout/accounts"
  })
op `chooseSignOutAccount`(`parameters/0/schema`: string,
  `requestBody/content/application~1json/schema`: {@js(#{`minLength`:1,`maxLength`:600}) `account`: string},
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  `responses/401/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  `responses/409/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "signed-out" | "inventory" | "refused";
    `username`?: string;
    `account`?: string;
    `location`?: string;
    `ownSessionEnded`?: boolean;
    `scope`?: "global" | "selected";
    `form`?: {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}};
    `view`?: {
      `state`?: "result" | "refused" | "nobody" | "accounts";
      `scope`?: "global" | "selected";
      `key`?: string;
      `message`?: string;
      `terminated`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `skipped`?: ({`id`?: string; `label`?: string; `message`?: string})[];
      `remaining`?: numeric;
      `verifiesCredentials`?: boolean;
      `accounts`?: ({
        `key`?: string;
        `username`?: string;
        `displayName`?: string;
        `current`?: boolean
      })[];
      `preselected`?: string;
      `naming`?: "open" | "off" | "product"
    }
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/pending/{id}/accounts",
  "get",
  #{
    `operationId`:"getAccountChoice",
    `tags`:#["Sign-in"],
    `summary`:"The accounts a sign-in may continue as",
    `description`:"The account picker's view: this browser's signed-in accounts and the signed-out ones it remembers — each by its key, names, state and times, never a sid — whether Use another account is open, and the protocol's own rows; and `csrf`. 503 with Retry-After where the browser's account set, or a session it lists, could not be read.\n\nThe door of the sign-in surface's `GET /authn/accounts`.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending sign-in's id: a bearer capability, as the `authn` the screen was opened with.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
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
    `x-mirrors`:"GET /authn/accounts"
  })
op `getAccountChoice`(`parameters/0/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `id`?: string;
      `base`?: string;
      `protocol`?: string;
      `application`?: string;
      `reason`?: string;
      `accounts`?: ({
        `key`?: string;
        `sub`?: string;
        `username`?: string;
        `displayName`?: string;
        `state`?: "signed-in" | "signed-out";
        `signedInAt`?: numeric;
        `authTime`?: numeric;
        `signedOutAt`?: numeric;
        `current`?: boolean
      })[];
      `another`?: {`open`?: boolean};
      `max`?: numeric;
      `details`?: ({`label`?: string; `value`?: string; `note`?: string})[]
    }
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/503/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/pending/{id}/accounts/select",
  "post",
  #{
    `operationId`:"selectAccount",
    `tags`:#["Sign-in"],
    `summary`:"Continues as one of this browser's accounts",
    `description`:"The account is checked again: its session must still be live in this browser, and a demand for two factors it does not meet sends the person to sign in again as that account. A signed-out account goes to the sign-in with its name filled in. Every selection rotates the sts_accounts handle. 503 with Retry-After where the browser's accounts could not be read.\n\nThe door of the sign-in surface's `POST /authn/accounts`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending sign-in's id: a bearer capability, as the `authn` the screen was opened with.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`account`:"name:nobody-example"}}}},
    `x-mirrors`:"POST /authn/accounts"
  })
op `selectAccount`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {@js(#{`minLength`:1,`maxLength`:600}) `account`: string},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/409/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/503/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/pending/{id}/accounts/another",
  "post",
  #{
    `operationId`:"useAnotherAccount",
    `tags`:#["Sign-in"],
    `summary`:"Signs in as another account",
    `description`:"The sign-in the picker stood in front of, with nothing filled in; refused while every place the browser has is a signed-in account.\n\nThe door of the sign-in surface's `POST /authn/accounts`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending sign-in's id: a bearer capability, as the `authn` the screen was opened with.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{}}}},
    `x-mirrors`:"POST /authn/accounts"
  })
op `useAnotherAccount`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/409/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/503/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/pending/{id}/accounts/forget",
  "post",
  #{
    `operationId`:"forgetAccount",
    `tags`:#["Sign-in"],
    `summary`:"Forgets a signed-out account",
    `description`:"Only an account that signed out in this browser; a signed-in one is signed out at /logout. No session is touched.\n\nThe door of the sign-in surface's `POST /authn/accounts`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending sign-in's id: a bearer capability, as the `authn` the screen was opened with.",
        `schema`:null,
        `example`:"noSuchSignInExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `409`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `429`:#{
        `description`:"Too many attempts.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`account`:"name:nobody-example"}}}},
    `x-mirrors`:"POST /authn/accounts"
  })
op `forgetAccount`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  `requestBody/content/application~1json/schema`: {@js(#{`minLength`:1,`maxLength`:600}) `account`: string},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/409/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/503/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/accounts",
  "get",
  #{
    `operationId`:"getAccounts",
    `tags`:#["Sign-in"],
    `summary`:"The accounts this browser holds",
    `description`:"Each signed-in and remembered account of the browser's account set — key, subject, names, state, times, and whether it is the browser's default — never a sid or a token; `enabled` false and no accounts where authn.multipleAccounts is off. With it on, `anotherAccount` is where Sign in with another account starts: the user portal, asked to sign in again.",
    `parameters`:#[

    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[]
  })
op `getAccounts`(`responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `enabled`?: boolean;
    `accounts`?: ({
      `key`?: string;
      `sub`?: string;
      `username`?: string;
      `displayName`?: string;
      `state`?: "signed-in" | "signed-out";
      `signedInAt`?: numeric;
      `authTime`?: numeric;
      `signedOutAt`?: numeric;
      `current`?: boolean
    })[];
    `max`?: numeric;
    `anotherAccount`?: string;
    `csrf`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `name`:#{`type`:"string"},
      `logo`:#{`type`:"string"},
      `logoOrigin`:#{`type`:"string"},
      `policy`:#{`type`:"string"},
      `tos`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_consent__id__r200_application_json_view_clientDisplay_h149 {}

@js(#{
    `additionalProperties`:false,
    `properties`:#{
      `description`:#{`type`:"string"},
      `name`:#{`type`:"string"},
      `identifier`:#{`type`:"string"},
      `baseUri`:#{`type`:"string"}
    },
    `$types`:#["object","null"]
  }) @hoisted model get_authn_api_consent__id__r200_application_json_view_scopes_i_permission_h150 {}

@endpoint("/authn-api/consent/{id}",
  "get",
  #{
    `operationId`:"getConsent",
    `tags`:#["Sign-in"],
    `summary`:"What the OAuth consent screen asks",
    `description`:"The consent screen's view, as facts and no words: who is signed in, the application asking (its name and client_id), each scope outstanding and the permission it resolves to, each RFC 9396 authorization detail member by member, the limits a person may lower, what was already agreed, and the request's own parameters — and `csrf`. Refused (400) where nothing is pending under the id, or the browser's session is not the person it was asked of.\n\nThe door of the sign-in surface's `GET /oauth2/consent`.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending consent's id: a bearer capability, as the `consent` the consent screen was opened with, answered only to the browser whose session is the person asked.",
        `schema`:null,
        `example`:"noSuchConsentExample"
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `default`:#{
        `description`:"A refusal or a failure.",
        `content`:#{`application/json`:#{`schema`:null}}
      }
    },
    `security`:#[],
    `x-mirrors`:"GET /oauth2/consent"
  })
op `getConsent`(`parameters/0/schema`: string,
  `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `csrf`?: string;
    `uiLocales`?: string;
    `preferredLanguage`?: {`value`?: string; `populated`?: boolean};
    `view`?: {
      `consent`?: boolean;
      `username`?: string;
      `base`?: string;
      `client`?: {`id`?: string; `name`?: string};
      `clientDisplay`?: get_authn_api_consent__id__r200_application_json_view_clientDisplay_h149;
      `resources`?: (string)[];
      `scopes`?: ({
        `scope`?: string;
        `permission`?: get_authn_api_consent__id__r200_application_json_view_scopes_i_permission_h150;
        `releasesDid`?: boolean
      })[];
      `authorizationDetails`?: ({
        `type`?: string;
        `description`?: string;
        `resource`?: string;
        `audience`?: string;
        `members`?: ({`name`?: string; `value`?: string})[]
      })[];
      `already`?: ({`scope`?: string; `global`?: boolean; `at`?: string})[];
      `limits`?: ({
        `r`?: integer;
        `type`?: string;
        @js(#{
          `x-free-form`:"The limits member of an RFC 9396 authorization detail, as the client sent it: beyond the six members common/access_limits.ts names, every member is the API's own, under a schema an operator declared for its type.",
          `description`:"The limits member of an RFC 9396 authorization detail, as the client sent it: beyond the six members common/access_limits.ts names, every member is the API's own, under a schema an operator declared for its type."
        }) `limits`?: unknown;
        `rows`?: ({`member`?: string; `label`?: string; `value`?: string})[]
      })[];
      `attribute`?: string;
      `protocol`?: string;
      `details`?: ({`label`?: string; `value`?: string; `note`?: string})[]
    }
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  

@endpoint("/authn-api/consent/{id}",
  "post",
  #{
    `operationId`:"answerConsent",
    `tags`:#["Sign-in"],
    `summary`:"Allows or denies what the consent screen asks",
    `description`:"`action: allow` writes one oauthConsent value per scope onto the person's entry and records an RFC 9396 Allow for this one request, with any limit lowered (`lim_t0r<n>_<member>`, as the page draws them; a raised one is refused); `action: deny` records nothing. Either way the pending consent is spent and the answer names the authorization request to go back to.\n\nThe door of the sign-in surface's `POST /oauth2/consent`.\n\nSent with `Content-Type: application/json`, an `Origin` of this service and `X-CSRF-Token` — the `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
    `parameters`:#[
      #{
        `name`:"id",
        `in`:"path",
        `required`:true,
        `description`:"The pending consent's id: a bearer capability, as the `consent` the consent screen was opened with, answered only to the browser whose session is the person asked.",
        `schema`:null,
        `example`:"noSuchConsentExample"
      },
      #{
        `name`:"X-CSRF-Token",
        `in`:"header",
        `required`:false,
        `description`:"The `csrf` the page's view answered, bound to the browser's `sts_session` cookie.",
        `schema`:null
      }
    ],
    `responses`:#{
      `200`:#{
        `description`:"The answer.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `400`:#{
        `description`:"Refused: `{ ok: false, errors }` — the body, the id, or the act itself.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `403`:#{
        `description`:"No Origin of this service, or no CSRF token bound to this browser's session.",
        `content`:#{`application/json`:#{`schema`:null}}
      },
      `415`:#{
        `description`:"Not a JSON body.",
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
    `requestBody`:#{`required`:true,`content`:#{`application/json`:#{`schema`:null,`example`:#{`action`:"deny"}}}},
    `x-mirrors`:"POST /oauth2/consent"
  })
op `answerConsent`(`parameters/0/schema`: string,
  `parameters/1/schema`: string,
  @js(#{`$open`:true}) `requestBody/content/application~1json/schema`: {`action`: "allow" | "deny"},
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/200/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/400/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/403/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/415/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the second-factor step `step`, whose page is `location`. `password-change`: the forced change, at `location`. `home-cell`: send `form` as it is. `stay`: draw the page again. `refused`: `errors` says why, in English; with `location` the sign-in screen says it, and with `end` the page ends."
  }) `responses/429/content/application~1json/schema`: {
    `ok`?: boolean;
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string;
    `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused";
    `location`?: string;
    `step`?: string;
    `id`?: string;
    `form`?: {
      `method`?: "GET" | "POST";
      `action`?: string;
      @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string>
    };
    `notice`?: string;
    `end`?: {`title`?: string};
    `passkey`?: {`unknownCredential`?: string; `autofill`?: boolean}
  },
  @js(#{
    `description`:"A refusal or a failure, in English. No error code is ever in it."
  }) `responses/default/content/application~1json/schema`: {
    `ok`?: boolean;
    `next`?: "refused";
    `errors`?: (string)[];
    `error`?: string;
    `error_description`?: string
  }): void;
  
}
