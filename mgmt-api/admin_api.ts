// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_api.ts
//
// ---------------------------------------------------------------------------
// THE MANAGEMENT API. Everything the /admin console shows and everything it can
// change, at /admin-api, over JSON, with no browser and no HTML anywhere in it.
//
// It exists because the console's controls are forms. A form is the right shape
// for a person and the wrong one for anything else: a caller that wants to
// revoke a token from a script, or read what this issuer is about to mint from
// a CI job, was left either parsing a redirect or knowing which hidden field to
// post. Every page already answered `?format=json` — this is the other half of
// that, and the half the console never had.
//
// ---------------------------------------------------------------------------
// THE ONE RULE THAT MATTERS HERE, and it is a rule about the FUTURE rather than
// about this file: **a control added to /admin gets an operation here in the
// same commit.** Not eventually, and not "when somebody needs it" — an API that
// covers eight of nine controls is worse than one that covers none, because the
// ninth is discovered by a caller who has already written the code that assumes
// it.
//
// Two things make that cheap rather than a matter of discipline:
//
//   * **This module decides nothing.** Every POST here calls the SAME action
//     function the console's form posts to — adminActions.tokenAction,
//     claimsAction,
//     vcAction, vpConfigAction — with `action` taken from the URL instead of
//     from a hidden input, and every GET calls the same JSON view the page's
//     `?format=json` answers. So adding an action to the console's switch is
//     most of adding it here: what is left is one row of the table below.
//   * **The OpenAPI document is built from that table** (admin_api_spec.ts), so
//     an operation cannot exist and be undocumented, and cannot be documented
//     and not exist. What no code can check is the direction that matters — a
//     new console control with no row here — and that is what this
//     repository's own tests/protocol/admin_api.js (a `local: true` job)
//     asserts, by walking the console's own NAV and the action names each of
//     its action handlers accepts.
//
// ---------------------------------------------------------------------------
// **PROTECTED SINCE 2026-09-09, AND THIS HEADER SAID THE OPPOSITE UNTIL THEN.**
// It read "NOT PROTECTED, deliberately", and gave three reasons. Every one of
// them was true and the third is what the change was for: anybody who could
// reach this port could grant themselves both console roles here.
//
// What gates it is an **OAuth 2.0 access token** audienced to this API —
// `admin:read` to read, `admin:write` to change anything — which become the
// built-in ADMIN_READ and ADMIN_WRITE roles, so the requirement is stated in
// the same `access-control` document every other access decision here is. One
// middleware on the base path covers every operation by construction.
//
// **It is a DIFFERENT credential from the console's, not the same gate
// widened**, and that distinction is the whole design: the console takes a
// browser session, this takes a token. `adminApi.authRequired` is the off
// switch and restores the open API exactly — in development mode only since
// #446 (2026-10-05); product ignores it turned off, see `tokenRequired()`.
//
// **THE THREE REASONS IT WAS OPEN ARE KEPT VERBATIM IN `mgmt-api/CLAUDE.md`**
// rather than here, because they are now the argument for that off switch and
// an argument in two places is one that will disagree with itself. Both of the
// things they were defending still hold: a test still drives this API — the
// launchers mint a token before any job runs — and it is still the way back in
// when nobody holds a console role.
//
// The prediction that header made came true to the letter and is worth reading
// as one: it said that if this ever changed it would be a SEPARATE setting with
// a separate argument (`admin.apiAuthRequired` was the name considered) and
// never a quiet extension of `admin.authRequired` to this path. It was —
// `adminApi.authRequired`, in a group of its own. `admin.authRequired` itself
// no longer exists: `global.mode` replaced it on 2026-09-06.
//
// ---------------------------------------------------------------------------
// Route order: this module must come AFTER admin.js, and that is a plain
// dependency rather than a preference — it requires that module for the action
// functions and the JSON views. Nothing here collides with any path, and it
// registers no wildcard, so its position is otherwise free (rule 1). Since
// #50's R1 (2026-09-16) that position is the place of this module's
// `register()` call in `common/protocol_stack.ts` (19), not the place it is
// required; the dependency on `admin.js` being loaded first is still a
// require-order one.
//
// Every action resource takes the action as a PATH PARAMETER — /admin-api/
// tokens/revoke, one express pattern `:action` behind every real URL. That
// keeps the router honest (one row in GET /admin/sts-metadata per resource,
// showing the parameter) while the OpenAPI document lists each URL as the
// separate operation it is, which is what makes the explorer's per-action
// forms possible. An unknown action is not a 404: it reaches the console's own
// handler and comes back as its "Unknown action" refusal, naming the ones that
// exist.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AdminApi` takes the modules it uses through its constructor
// (`AdminApiDeps`). Since R2 the composition root
// (`common/protocol_stack.ts`) builds the instance, and the module's old
// names are FACADES that forward to it, for the JavaScript callers; a process
// without the root builds a default at load. `AdminApi` is exported beside
// them for the root.
//
// **THE ROUTES ARE REGISTERED BY TWO METHODS**, because the old file ran a
// statement between them: `registerGate()` (the access-token middleware on
// the base path), then `compileRequestSchemas()`, then `registerRoutes()`
// (the table's operations). `AdminApi.wire()` calls
// `compileRequestSchemas()` when the instance is installed, and the module
// exports a `registerRoutes(app)` that calls `registerGate()` and then the
// table's `registerRoutes()`; `common/protocol_stack.ts` calls it at 19,
// where requiring this module used to register both (#50, R1), so the route
// order is unchanged. Requiring the module registers nothing. (The schemas
// are therefore recorded BEFORE the gate is registered rather than after it,
// and since #617 each is compiled only when a request first reaches its
// operation; neither reads the other.)
//
// `PROTOCOL_SETTINGS_OPERATIONS` and `ROUTES` are typed `any[]`, as the
// JavaScript's JSDoc typed the second: a union of a few hundred object
// literal types is not a type anybody reads.
//
// **THE TABLES WHOSE ENTRIES CALL THIS MODULE**
// (`PROTOCOL_SETTINGS_OPERATIONS`, `ROUTES`) are built by `build…()` methods.
// Since R2 they are module-level `let`s filled by `AdminApi.wire()`, in the
// order they were declared, when the instance is installed — for a process
// without the root, that is still at load — and `ROUTES` is exported through
// a getter. The startup banner, which counts the instance's operations, is
// logged from `wire()` too, straight after them, as it was.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import ModelTables = require('../common/model_tables');
// Types a row of actions by its own actions' operations (#1579); returns it.
import ApiRows = require('../common/api_rows');
// The error-code registry, a leaf. A refusal here is MARKED on the response for
// the call log and never written into the JSON a caller receives.
import errorCodes = require('../common/error_codes');
import ResponseModelKit = require('../common/response_model_kit');
// THE CONSOLE'S LANGUAGE (#539 phase 5): the catalogs and the negotiation,
// and the hosted surfaces' table for the console's own client id — and the
// prose a view carries, in the caller's language (#543). Libraries.
import i18n = require('../common/i18n');
import serverProse = require('../common/server_prose');
import PageLocale = require('../common/page_locale');
import oidcRp = require('../common/oidc_rp');
import lingeringClose = require('../common/lingering_close');
// A service account's owner bound, which the document states (#600). A
// library: the actions layer loaded it long before this module.
import serviceAccounts = require('../common/service_accounts');
// Who owns what, and what an owner may not touch (#607): a library whose
// reads are lazy, so this require moves no route and closes no cycle.
import ownership = require('../common/ownership');
// Whether a create can race another node's, and the sentence a refused one
// carries (#46 section 3). A LIBRARY that registers nothing.
import createClaims = require('../ldap/directory_create_claims');
import helpers = require('../common/helpers');
const { log, parseBody, baseUrlOf, STS } = helpers;
// BOTH ARE LIBRARIES (rule 3): they register no route, so requiring them here
// cannot move one or join a cycle. `crypto.js` is THE one place this service
// verifies a signature. (`roles.js` turned an access token's scopes into the
// roles the access policy asks for until #303; `role_permissions.ts` answers
// the roles the token's subject holds now — see the gate below.)
import stsCrypto = require('../common/crypto');
// WHICH CLIENTS MAY HOLD `admin:*` (#110) — the gate asks it of every token.
import scopePolicy = require('../common/scope_policy');
// THE ROLES A TOKEN'S SUBJECT HOLDS NOW, LESS THOSE ITS SCOPES DO NOT CARRY
// (#302, #303) — what the gate hands the access-control policy. A library
// (rule 3).
import rolePermissions = require('../common/role_permissions');
// The member types a role may be restricted to (#93), for the enum below.
import roles = require('../common/roles');
// The password policy's FIELD TABLE, which the request schema of
// `save-password-policy` is generated from — for `narrowDoorProperties()`'s
// reason: a hand-written list of what an operation accepts is a second
// definition of the table and goes stale in the document a caller trusts most.
import passwordPolicy = require('../common/password_policy');
// THE KINDS OF POLICY (#64): the policies resource documents two actions per
// kind, and each save's body from that kind's FIELDS.
import policyKinds = require('../admin-core/policy_kinds');
import admin = require('../admin-ui/admin');
// WHAT A REALM ADMINISTRATOR MAY NOT REACH (2026-09-14, #32) — the console's
// table, asked of a realm's own token and a realm's own session here. A
// library with no route.
import adminScope = require('../admin-ui/admin_scope');
import configDump = require('../admin-core/config_dump');
// ---------------------------------------------------------------------------
// THE ACTION LAYER (2026-09-12). Every operation below that CHANGES something
// calls a function here rather than one on the console module.
//
// **THAT IS THE WHOLE OF WHY THIS FILE STILL REQUIRES BOTH.** Rule 7 says a
// console control and an API operation must not be able to disagree, and the
// way that was enforced until today was that this file called the console's
// own functions — which worked, and which made the surface a machine drives
// downstream of the surface a person reads. The DECISIONS moved to
// admin-core/, which neither surface owns; what is still reached for on
// `admin` is what the console genuinely owns — the JSON views it renders
// beside its pages, and `respondToAction()`, which is transport.
// ---------------------------------------------------------------------------
import adminActions = require('../admin-core/admin_actions');
// AND THE READ HALF (2026-09-12). Thirty-eight functions that answer a
// question and build no markup; `admin-core/admin_views.ts` argues the line.
// What is still reached for on `admin` below is the console's own structure
// — which pages exist, where a settings group is edited — and the views that
// draw HTML, whose json half is still computed in the same pass as the page.
import adminViews = require('../admin-core/admin_views');
// THE PKI PAGE'S VIEW AND ITS FOUR ACTIONS. A PLAIN REQUIRE IN THE ORDINARY
// DIRECTION, which is what rule 3e asks for when one is available: that module
// is loaded at 18a — before this file — so this is a cache hit, and it
// registers only `/admin/pki`, which is already in the router by now. Since
// #50's R1 requiring it registers nothing at all — `common/protocol_stack.ts`
// calls its `registerRoutes(app)` at 18a — so this require could not move
// that route wherever it ran. Compare `admin-ui/crypto_metadata.ts`, which is
// at 20a and therefore needed a slot.
import pkiAdmin = require('../admin-ui/pki_admin');
// The key algorithms a TLS listener certificate may be issued with, for the
// `issue-pep-certificate` request schema's enum (2026-09-13) — read from the
// module that refuses the others, so the document cannot offer one it would
// refuse. A LIBRARY (rule 3): a cache hit, and it registers nothing.
import pki = require('../common/pki');
// The certificate catalogue and details model both certificate dialogs read
// (2026-09-13). A LIBRARY in `admin-core/`, required at 19 like the two above.
import certificateViews = require('../admin-core/certificate_views');
// Which endpoints each Protocols page lists (2026-09-13). The console adds
// them in `respond()`; this file adds the same member to the GET that
// `mirrors` that page — see the registration loop and sendJson().
import protocolEndpoints = require('../admin-core/protocol_endpoints');
// 18b, required in the ORDINARY DIRECTION for the same reason as the line
// above: `common/protocol_stack.ts` loads it, and registers
// `/admin/encryption` through its `registerRoutes(app)`, before this file, so
// this is a cache hit and moves no route. (Until #50's R1 it registered that
// route at its own require time, which is why the order mattered; requiring
// it registers nothing now.)
import encryptionAdmin = require('../admin-ui/encryption_admin');
// 18c, same ordinary-direction require and the same reason.
import databaseAdmin = require('../admin-ui/database_admin');
import secretsAdmin = require('../admin-ui/secrets_admin');
// 18g (#74), the same ordinary-direction require and the same reason.
import cachesAdmin = require('../admin-ui/caches_admin');
// THE STATUS LISTS' PAGE (#38's follow-ups), for its two functions (rule 7).
import vcStatusAdmin = require('../admin-ui/vc_status_admin');
// Server configuration → Mode (#181): its one view, rule 7.
import modeAdmin = require('../admin-ui/mode_admin');
import listenersAdmin = require('../admin-ui/listeners_admin');
import workerPoolsAdmin = require('../admin-ui/worker_pools_admin');
// Monitoring → Node Health (#329): its one view, rule 7.
import nodeHealthAdmin = require('../admin-ui/node_health_admin');
// Server configuration → Cells (#98): `cellsView()` and `peopleOf()`.
import cellsAdmin = require('../admin-ui/cells_admin');
// The scheduler's page (#49): its view and its two actions, rule 7.
import schedulerAdmin = require('../admin-ui/scheduler_admin');
// The mail channel's two pages (#63), mirrored below (rule 7).
import mailAdmin = require('../admin-ui/mail_admin');
// The device register's three pages (#164, #218), required in the ordinary
// direction for the reason `mailAdmin` is: built at 18q, before this file.
import devicesAdmin = require('../admin-ui/devices_admin');
// Monitoring → Risk (#62): its view and its four actions, rule 7.
import riskAdmin = require('../admin-ui/risk_admin');
// Monitoring → Geolocation (#255): its one view, rule 7.
import geolocationAdmin = require('../admin-ui/geolocation_admin');
// The embedded protocol debugger's report (2026-09-13). A page module required
// at 18 like the one above, and it reads the listener's status lazily, so this
// require moves no route.
import debuggerAdmin = require('../debugger/debugger_admin');
// The setting table, for the two narrow doors' request schemas: their
// properties are BUILT from the keys those doors refuse against, and the
// TYPE of each comes from the row config.js already holds for it. See
// narrowDoorProperties() below.
import config = require('../common/config');
// The two console roles, for the `enum` on the role parameter and on both
// request bodies. A library that registers nothing, so requiring it here moves
// no route; taking the ids from it rather than writing them twice is what stops
// the OpenAPI document offering a role this service does not have.
import rbac = require('../admin-ui/admin_rbac');
// The claim sets, for the `enum` on every `set` field below and for the two
// lists that decide which of them each action resource carries. Also a library
// that registers nothing — admin.js has required it long before this line — so
// taking the ids from it moves no route and cannot let this document offer a
// set the service does not have.
import stats = require('../common/admin_stats');
// A DISABLED ACCOUNT (2026-09-17): the gate refuses a person's token once
// their account is disabled. A library loaded long before this file.
import accountState = require('../common/account_state');
// The applications registry, for the `enum` of protocol family ids on the
// create body. A library too — it registers nothing and admin.js required it
// long before this line — so this moves no route, and taking the ids from the
// table the create VALIDATES against is what stops this document offering a
// family that call would refuse.
import applications = require('../common/applications');
// WHICH WRITES ARE THE SECURITY ADMINISTRATOR'S (#645): a leaf the gate asks.
import SecurityOperations = require('../common/security_operations');
// RFC 9728, for `load-resource-metadata`: the realm's authorization servers the
// document is compared with are addressed by the request, so this handler
// computes them and hands them to the action. A library that registers nothing.
import resourceMetadata = require('../oauth-oidc/protected_resource_metadata');
import spec = require('./admin_api_spec');
// THE CLOSED SETS (#86). A LEAF (rule 3): the refusal sentence this file's
// enum errors use, the query-parameter check, and the register the console
// gate reads — filled here at wire time from the same table the document is
// built from. `admin-ui/admin.ts` requires it too, in the ordinary direction.
import closedSets = require('../common/closed_sets');
// THE TABLES FOUR MORE CLOSED SETS ARE READ OFF (#86), so the document's
// enum is the list the handler checks against rather than a copy of it. All
// four are libraries that register no route and are already loaded by the
// time this module is (`risk_admin` at 18j, `mail_admin` at 18l, the console
// and `admin-core` at 18), so each require is a cache hit: the risk
// catalogue, the built-in mail messages, the claims an identity-assurance
// verification may cover, and the federation schema's editable fields.
import riskDatasets = require('../risk/risk_datasets');
import mailTemplates = require('../common/mail_templates');
import identityAssurance = require('../common/identity_assurance');
import federation = require('../federation/federation');
// The consumer provider catalogue (#565): the enum of `create`'s `provider`.
import consumerProviders = require('../federation/consumer_providers');
// THE OPENID4VP VERIFIER (#587): `POST /verifications/start` builds its
// request through the Verifier's own `startVerification()`, and the
// document's closed sets are its START_VOCABULARY. A converted route module
// loaded at 11–14, so this is a cache hit that registers nothing (rule 1).
import vcVerifier = require('../oid4vc/vc_verifier');
// THE OPENID4VCI ISSUER (#594): the two reads of what it saw, which were
// non-spec routes of its own until then. Loaded at 11–14 and converted, so
// this is a cache hit that registers nothing (rule 1).
import vcIssuer = require('../oid4vc/vc_issuer');
// And six LEAVES the filters and the PKI and XACML actions are held to (#86):
// the audit vocabulary, the delegation register's types, the used-assertion
// history's formats, the issuance kinds, the ISO 3166 alpha-2 codes and
// XACML's two Effect values. Each requires `helpers` at most and registers
// nothing; `xacml_model` is the XACML family's table and loads here earlier
// than the family does (23c), which moves no route because it has none.
import audit = require('../common/audit');
import delegation = require('../common/delegation');
import usedAssertions = require('../common/used_assertions');
import issuanceGate = require('../common/issuance_gate');
import countryCodes = require('../common/country_codes');
import xacmlModel = require('../xacml/xacml_model');

// ---------------------------------------------------------------------------
// THE DOCUMENT IS THE VALIDATOR (2026-09-06).
//
// Every action in the table below already carries a `requestBody` — a real
// JSON Schema with `properties`, `required` and `additionalProperties: false`
// — and `admin_api_spec.ts` publishes it verbatim in the OpenAPI document.
// **Until now nothing checked a request against it.** The document described
// what to POST and the handlers read whatever arrived, so the two could
// disagree for as long as anybody liked and the only way to find out was to
// read both.
//
// ajv compiles THE SAME OBJECT the document publishes. Not a copy of it, not a
// second description of it in another notation — the identical value, reached
// through the identical table — which is what makes "the document is accurate"
// a property of the code rather than a claim somebody has to re-check. That is
// the same argument `sts_metadata.js` makes about the router and
// `crypto_metadata.js` makes about the algorithm tables, applied to request
// bodies.
//
// **WHY ajv HERE AND zod EVERYWHERE ELSE.** `common/validation.js` is zod
// because a protocol endpoint's rules are written in prose in an RFC and have
// to be expressed somewhere. This surface is the opposite case: the rules are
// ALREADY written down, as JSON Schema, because the document has to publish
// them. A zod schema here would be a second spelling of an existing artefact —
// the "one copy of each fact" rule, broken on purpose, in the one place the
// fact is already machine-readable.
//
// `strict: false` because these are OpenAPI schemas: they carry `examples` and
// `description` members that ajv's strict mode reports as unknown keywords.
// `allErrors` so a caller fixing a body sees everything wrong with it at once
// — the opposite of `common/validation.js`'s first-issue-only rule, and for a
// reason: this is a developer with a document open, not a browser mid-sign-in.
// ---------------------------------------------------------------------------
// `any` for the type checker (#50): CommonJS modules whose declared types are
// ES default exports.
import AjvModule = require('ajv');
import addFormatsModule = require('ajv-formats');
import responseChecks = require('../common/response_models');

const Ajv: any = AjvModule;
const addFormats: any = addFormatsModule;

// `verbose` so an `enum` error carries the value it refused, which the
// refusal sentence names (#86).
const ajv = new Ajv({ strict: false, allErrors: true, coerceTypes: false,
                      verbose: true });
addFormats(ajv);

// THE FIELD GRID'S OWN SHAPE (#446), which the two `update-fields` actions
// read beside a JSON `fields` object (`applicationFieldsFrom()`,
// `fieldsCoveredBy()`): one box per value, `field.<attribute>.<n>`, or one
// `field.<attribute>` holding a value per line, and `present` naming every
// field the form drew so an emptied one is cleared. Declared so the static
// console can send its form as drawn — a member a closed schema does not
// name is one the console would have to leave out, and a box left out is a
// value the reader typed and lost.
const FIELD_GRID_MEMBERS = {
  present: { type: ['string', 'array'], items: { type: 'string' },
             description: 'The fields the console\'s form drew, by ' +
                          'attribute name, space or comma separated or as a ' +
                          'list: each one is cleared when the form carries ' +
                          'no value for it.' }
};
// THE KERBEROS TRUST RECORD'S FIELDS (#430 Phase 4), the request body of
// `add` and `update` on `/admin-api/kerberos/trusts`: what the Trusts tab's
// form posts, under the names `kerberos/krb5_trusts.ts` reads. The lists take
// a JSON array or the form's text (comma- or line-separated); a checkbox
// column named `attribute` arrives as `attributes`, and `attributesShown`
// says the form drew it, so none ticked is an empty list rather than none
// sent. `forestTrustInfo` is the object, or the form's two text areas.
const TRUST_FIELDS = {
    type: 'object',
    properties: {
      partnerRealm: { type: 'string',
                      description: 'The partner Kerberos realm, ' +
                                   'PARTNER.EXAMPLE.' },
      netbiosName: { type: 'string',
                     description: 'Its NetBIOS (flat) name; the realm\'s ' +
                                  'first label by default.' },
      partnerSid: { type: 'string',
                    description: 'Its domain SID, S-1-5-21-a-b-c; a ' +
                                 'trust realm\'s own by default.' },
      type: { type: 'string', enum: ['external', 'trust-realm'],
              description: '`external` — a KDC elsewhere — or ' +
                           '`trust-realm`, another trust realm of this ' +
                           'service.' },
      partnerTrustRealm: { type: 'string',
                           description: 'For `trust-realm`: that trust ' +
                                        'realm\'s id.' },
      direction: { type: 'string',
                   enum: ['bidirectional', 'inbound', 'outbound'],
                   description: 'Which keys the record holds.' },
      keySource: { type: 'string', enum: ['password', 'generate'],
                   description: 'Where a key it does not hold yet comes ' +
                                'from.' },
      password: { type: 'string',
                  description: 'The shared trust password, for ' +
                               '`keySource: "password"`. Never shown back.' },
      attributes: { type: 'array', items: { type: 'string' },
                    description: '[MS-ADTS] 6.1.6.7.9\'s bits by name.' },
      attributesShown: { type: 'string',
                         description: 'Set by the console\'s form: the ' +
                                      'attribute boxes were drawn.' },
      suffixes: { type: ['array', 'string'], items: { type: 'string' },
                  description: 'The DNS suffixes routed to the partner.' },
      enctypes: { type: ['array', 'string'],
                  items: { type: ['integer', 'string'] },
                  description: 'The enctypes its keys are made for, by ' +
                               'number; AES by default.' },
      claimsTransformation: { type: 'string',
                              enum: ['drop-all', 'allow-all'],
                              description: 'What becomes of a claims set ' +
                                           'arriving across it.' },
      forestTrustInfo: { type: ['object', 'string', 'null'],
                         description: 'A cross-forest trust\'s { domains: ' +
                                      '[{ sid, dnsName, netbiosName, ' +
                                      'sidEnabled }], topLevelNames: ' +
                                      '[{ name, enabled }] }.' },
      forestDomains: { type: 'string',
                       description: 'The form\'s text: a domain per line, ' +
                                    '`<sid> <dns name> <netbios name> ' +
                                    '[disabled]`.' },
      forestNames: { type: 'string',
                     description: 'The form\'s text: a top-level name per ' +
                                  'line, `<name> [disabled]`.' },
      enabled: { type: 'boolean',
                 description: 'Whether it is used; true by default.' }
    },
    required: ['partnerRealm'],
    examples: [{ partnerRealm: 'PARTNER.EXAMPLE', direction: 'bidirectional',
                 keySource: 'generate', attributes: ['quarantined'],
                 suffixes: ['partner.example'] }],
    additionalProperties: false
};

// The body of the acts that name a trust and nothing else.
const TRUST_PARTNER_ONLY = {
  type: 'object',
  properties: {
    partnerRealm: { type: 'string',
                    description: 'The partner Kerberos realm.' }
  },
  required: ['partnerRealm'],
  examples: [{ partnerRealm: 'PARTNER.EXAMPLE' }],
  additionalProperties: false
};

const FIELD_GRID_PATTERN = {
  '^field\\.': { type: ['string', 'array'], items: { type: 'string' },
                   description: 'The console form\'s boxes: ' +
                                '`field.<attribute>.<n>` one value each, in ' +
                                'box order, or `field.<attribute>` with a ' +
                                'value per line. Merged over `fields`.' }
};

// ---------------------------------------------------------------------------
// THE COMPONENTS THE DOCUMENT DEFINES, SO A `$ref` INTO THEM RESOLVES.
//
// Three request schemas here refer to a shared definition rather than
// repeating it — `replaceClaims`, `replaceUserInfoClaims` and
// `replaceSamlAttributes` all take a list of `#/components/schemas/ClaimEntry`,
// which is exactly the reuse the components section exists for.
//
// **A JSON POINTER STARTING `#/` IS RESOLVED AGAINST THE ROOT OF THE SCHEMA
// BEING COMPILED**, and a `requestBody` compiled on its own is its own root —
// so the pointer looks for `components` INSIDE the request body and finds
// nothing. The first version of this registered the components as a separate
// schema under `$id: '#'` and it made no difference for exactly that reason.
//
// So each schema is compiled wrapped in a root that carries the components
// beside it. `components` is not a JSON Schema keyword and ajv ignores it under
// `strict: false` — what it is there for is to be POINTED AT. Nothing about the
// published document changes: `admin_api_spec.ts` still emits `requestBody`
// verbatim, and this wrapper exists only for the length of the compile.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// **WHAT IS ENFORCED IS STRUCTURE AND THE CLOSED SETS. `required` IS STRIPPED
// FROM THE COMPILED COPY AND KEPT IN THE DOCUMENT.**
//
// The rule is the one this file rests on: *the validator adds the checks
// nothing else makes, and never duplicates a check the handler already makes
// better.* It was applied on 2026-09-06 and three of the four JSON Schema
// assertions here fell on the ENFORCED side:
//
//   * `additionalProperties: false` — a member the operation does not define.
//     This is the one that catches the silently ignored field, which is the
//     failure a passing test cannot see. It found four in this repository's own
//     suite on the day it was written: `acs` and `binding` on the SAML 2.0
//     resource, `target` on SAML 1.1, and a `name` that should have been
//     `label` on the authorization-server create — every one of them a member
//     the handler never read and the job asserted nothing about.
//   * `type` — a number or an array where a string belongs.
//   * `enum` — a value outside the closed set the document declares (#86,
//     2026-09-26). **It was stripped until then**, on the argument that
//     `applicationsAction()` refuses an unknown kind by naming the kinds and
//     that ajv would replace the sentence with "must be equal to one of the
//     allowed values". Both halves were true and the conclusion was wrong,
//     because the handler that explains itself was the exception: the #86
//     audit found closed-set fields that a handler silently ignored, silently
//     replaced with its default, or STORED. So the enum is enforced here, and
//     the sentence is `common/closed_sets.ts`'s — the field, the value, how
//     many values it accepts and every one — which is as good as the kinds
//     refusal was and is the same words at every door.
//
// NOT ENFORCED, because a handler already answers it and says more:
//
//   * `required` — `logoutAction()` answers a sign-out with no identity with
//     *Name the identity ... in `user`*, and `sts_admin_api_operations.js`
//     asserts that wording SO THAT A CALLER CAN TELL WHICH REFUSAL IT MET.
//
// **An enum is compiled with `""` added to it**, when it does not already
// hold it, and that is not a loophole: an empty string is how a form — and a
// form-encoded body copied from the console, which this API takes — says
// "nothing chosen", and the handlers here treat it as absent. The refusal
// sentence names the declared set, without it. Stripped recursively, because
// these schemas nest — an array's `items` and a `$ref`'d `ClaimEntry` each
// carry their own.
// ---------------------------------------------------------------------------
const NOT_ENFORCED_HERE = ['required'];

// ---------------------------------------------------------------------------
// THE ONE EXCEPTION TO ENFORCING AN ENUM, AND IT IS MARKED WHERE IT APPLIES.
//
// A property carrying `x-refused-by-handler: true` keeps its `enum` in the
// published document and is NOT held to it here, by the console register or
// by the query check (`common/closed_sets.ts` skips it too). It is for a
// handler whose refusal of a value outside the set says something the
// validator cannot: `spiffe/entries/update`'s `field` refuses a field that
// records what HAPPENED differently from one that does not exist, and
// `sts_admin_api_operations.js` asserts the difference, because a caller
// fixing a request has to know which of the two it met. The marker is a
// vendor extension (OpenAPI's `x-`), so the document says out loud which
// sets are the handler's to refuse. A new use needs that argument made for
// it — "the handler refuses it too" is not one; nearly every handler does.
// ---------------------------------------------------------------------------
const REFUSED_BY_HANDLER = 'x-refused-by-handler';

// ---------------------------------------------------------------------------
// A ROW OF THE TABLE IS TYPED BY THE MODEL (#1579). A row naming one
// operationId has its handler typed by that operation in
// `types/api.generated.d.ts` (`IyaApi.AdminOperations`, the Management and
// Admin Console APIs together): the body and query names it may read, and
// what `sendJson()` may answer at a literal 2xx status. A row that serves
// several (`POST …/:action`) is typed by the union of its actions'
// operations. `types/api-handlers.d.ts` argues it.
//
// THE CONSOLE'S TWINS (#454): a management operation whose console twin
// answers the same handler's whole answer, where the management one leaves
// the console's members out (`withConsoleRoutes()`). Declared here, beside
// the row type, because the twin's handler is the management row's: it is
// typed by both operations.
// ---------------------------------------------------------------------------

// What a drawing adds to a delegation answer: the box looks, the SVG,
// its size and label, and the page's chooser, key and facts.
const CONSOLE_DRAWING = ['drawing', 'looks', 'label', 'svg', 'chooser',
                         'mapKey', 'facts'];
const CONSOLE_TWINS = [
  { of: 'getStatus', path: '/console/dashboard',
    operationId: 'getConsoleDashboard',
    members: ['base', 'persistence', 'testDouble', 'sections'],
    drawing: false },
  { of: 'getNewApplicationForm', path: '/console/applications/new',
    operationId: 'getConsoleNewApplicationForm',
    members: ['fieldGroups', 'familyChoices', 'longTextAttributes',
              'persistence', 'resourceMetadataImport'],
    drawing: false },
  { of: 'getDelegationUser', path: '/console/delegation/user',
    operationId: 'getConsoleDelegationUser',
    members: CONSOLE_DRAWING, drawing: true },
  { of: 'getDelegationApplication', path: '/console/delegation/application',
    operationId: 'getConsoleDelegationApplication',
    members: CONSOLE_DRAWING, drawing: true }
] as const;
type AdminOps = IyaApi.AdminOperations;
type ConsoleTwinOf<K> =
  Extract<(typeof CONSOLE_TWINS)[number], { of: K }>['operationId'];
type AdminServed<K extends keyof AdminOps> = AdminOps[K | ConsoleTwinOf<K>];
type AdminOneRow = {
  [K in keyof AdminOps]: {
    operationId: K;
    handler?: (req: IyaApi.RequestTo<AdminServed<K>>,
               res: IyaApi.Answering<AdminServed<K>>, next?: any) => unknown;
    [member: string]: any;
  }
}[keyof AdminOps];
type AdminRow = AdminOneRow | IyaApi.AdminActionRow;

// What `AdminApi` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface AdminApiDeps {
  errorCodes: typeof errorCodes;
  createClaims: typeof createClaims;
  helpers: typeof helpers;
  log: typeof log;
  parseBody: typeof parseBody;
  baseUrlOf: typeof baseUrlOf;
  STS: typeof STS;
  stsCrypto: typeof stsCrypto;
  scopePolicy: typeof scopePolicy;
  rolePermissions: typeof rolePermissions;
  passwordPolicy: typeof passwordPolicy;
  admin: typeof admin;
  adminScope: typeof adminScope;
  adminActions: typeof adminActions;
  adminViews: typeof adminViews;
  pkiAdmin: typeof pkiAdmin;
  pki: typeof pki;
  certificateViews: typeof certificateViews;
  protocolEndpoints: typeof protocolEndpoints;
  encryptionAdmin: typeof encryptionAdmin;
  databaseAdmin: typeof databaseAdmin;
  secretsAdmin: typeof secretsAdmin;
  cachesAdmin: typeof cachesAdmin;
  vcStatusAdmin: typeof vcStatusAdmin;
  debuggerAdmin: typeof debuggerAdmin;
  config: typeof config;
  rbac: typeof rbac;
  stats: typeof stats;
  accountState: typeof accountState;
  applications: typeof applications;
  resourceMetadata: typeof resourceMetadata;
  spec: typeof spec;
  closedSets: typeof closedSets;
  riskDatasets: typeof riskDatasets;
  mailTemplates: typeof mailTemplates;
  identityAssurance: typeof identityAssurance;
  federation: typeof federation;
  audit: typeof audit;
  delegation: typeof delegation;
  usedAssertions: typeof usedAssertions;
  issuanceGate: typeof issuanceGate;
  countryCodes: typeof countryCodes;
  xacmlModel: typeof xacmlModel;
  realms: typeof realms;
  jwtAccessToken: typeof jwtAccessToken;
  mtls: typeof mtls;
  dpop: typeof dpop;
  senderConstraints: typeof senderConstraints;
  accessGate: typeof accessGate;
  mode: typeof mode;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadApiExplorer(): typeof import('../admin-ui/api_explorer');
  loadGnapConsole(): typeof import('../gnap/gnap_console');
  loadAcmeApi(): typeof import('../acme/acme_api');
  loadEstApi(): typeof import('../est/est_api');
  loadScepApi(): typeof import('../scep/scep_api');
  loadOidfedApi(): typeof import('../oidfed/oidfed_api');
  loadOauth2MonitorApi(): typeof import('../oauth-oidc/oauth2_monitor_api');
  loadGrantManagementApi(): typeof import('../oauth-oidc/grant_management_api');
  loadClaimsProvidersApi(): typeof import('../oauth-oidc/claims_providers_api');
  // The attribute source operations (#94).
  loadAttributeSourcesApi():
    typeof import('../attribute-sources/attribute_sources_api');
  // The secret push destinations' operations (#221 P3).
  loadSecretDestinationsApi(): typeof import('./secret_destinations_api');
  // The AuthZEN tab's operations (#563).
  loadAuthzenApi(): typeof import('./authzen_api');
  loadUmaApi(): typeof import('./uma_api');
  // Monitoring → Passkeys' operations (#942).
  loadPasskeyReportApi(): typeof import('./passkey_report_api');
  // Directory → Post-login activities' operations (#1111).
  loadPostLoginActivitiesApi(): typeof import('./post_login_activities_api');
  // Monitoring → Audit export's operations (#641).
  loadAuditExportApi(): typeof import('./audit_export_api');
  // Server configuration → Sign-in appearance's operations (#717).
  loadBrandingApi(): typeof import('./branding_api');
  // The outbound SCIM clients' operations (#552).
  loadScimClientsApi(): typeof import('./scim_clients_api');
  loadProviderCommandsApi(): typeof import('../oauth-oidc/provider_commands_api');
  loadSsfTransmittersApi(): typeof import('../ssf/ssf_transmitters_api');
}

type RouteApp = typeof app;

/**
 * The management API at `/admin-api`: every console control as a JSON
 * operation, over the same action functions and views the console uses, behind
 * an OAuth 2.0 access-token gate.
 */
// The operations that change how somebody signs in (#1538). `disable-mfa`
// and `disable-primary-keys` since #1577: #1558 gave them the four clear
// actions' `evidence`, being the same act on every factor at once, and they
// had been left out of this list, so they were the two that took none of the
// recent sign-in the single-factor removals take.
const REAUTHENTICATED_ACTIONS = ['set-password', 'reset-password',
  'issue-password-reset', 'clear-totp', 'clear-key', 'clear-backup-codes',
  'clear-email-factor', 'disable-mfa', 'disable-primary-keys', 'set-mail',
  'create-app-password', 'revoke-app-password'];

class AdminApi {
  /**
   * Builds the management API over the given dependencies.
   *
   * @param deps - the modules it uses, and loaders for the lazily required ones
   */
  constructor(private readonly deps: AdminApiDeps) {
    deps.log.debug("Entering AdminApi.constructor().");
    deps.log.debug("Leaving AdminApi.constructor().");
  }

  // What the composition root passes, from the real modules, with the lazy
  // requires as loaders.
  /**
   * Returns the dependencies the composition root passes, from the real
   * modules, with the lazy requires as loaders.
   *
   * @returns the dependencies
   */
  static defaultDeps(): AdminApiDeps {
    log.debug("Entering AdminApi.defaultDeps().");
    log.debug("Leaving AdminApi.defaultDeps().");
    return {
      errorCodes: errorCodes,
      createClaims: createClaims,
      helpers: helpers,
      log: log,
      parseBody: parseBody,
      baseUrlOf: baseUrlOf,
      STS: STS,
      stsCrypto: stsCrypto,
      scopePolicy: scopePolicy,
      rolePermissions: rolePermissions,
      passwordPolicy: passwordPolicy,
      admin: admin,
      adminScope: adminScope,
      adminActions: adminActions,
      adminViews: adminViews,
      pkiAdmin: pkiAdmin,
      pki: pki,
      certificateViews: certificateViews,
      protocolEndpoints: protocolEndpoints,
      encryptionAdmin: encryptionAdmin,
      databaseAdmin: databaseAdmin,
      secretsAdmin: secretsAdmin,
      cachesAdmin: cachesAdmin,
      vcStatusAdmin: vcStatusAdmin,
      debuggerAdmin: debuggerAdmin,
      config: config,
      rbac: rbac,
      stats: stats,
      accountState: accountState,
      applications: applications,
      resourceMetadata: resourceMetadata,
      spec: spec,
      closedSets: closedSets,
      riskDatasets: riskDatasets,
      mailTemplates: mailTemplates,
      identityAssurance: identityAssurance,
      federation: federation,
      audit: audit,
      delegation: delegation,
      usedAssertions: usedAssertions,
      issuanceGate: issuanceGate,
      countryCodes: countryCodes,
      xacmlModel: xacmlModel,
      realms: realms,
      jwtAccessToken: jwtAccessToken,
      mtls: mtls,
      dpop: dpop,
      senderConstraints: senderConstraints,
      accessGate: accessGate,
      mode: mode,
      loadApiExplorer: function () {
        return require('../admin-ui/api_explorer');
      },
      loadGnapConsole: function () {
        return require('../gnap/gnap_console');
      },
      loadAcmeApi: function () {
        return require('../acme/acme_api');
      },
      loadEstApi: function () {
        return require('../est/est_api');
      },
      loadScepApi: function () {
        return require('../scep/scep_api');
      },
      // OPENID FEDERATION (#132): the same shape, its view and acts reached
      // lazily inside each handler.
      loadOidfedApi: function () {
        return require('../oidfed/oidfed_api');
      },
      loadOauth2MonitorApi: function () {
        return require('../oauth-oidc/oauth2_monitor_api');
      },
      loadAttributeSourcesApi: function () {
        return require('../attribute-sources/attribute_sources_api');
      },
      loadSecretDestinationsApi: function () {
        return require('./secret_destinations_api');
      },
      loadUmaApi: function () {
        return require('./uma_api');
      },
      loadAuthzenApi: function () {
        return require('./authzen_api');
      },
      loadPasskeyReportApi: function () {
        return require('./passkey_report_api');
      },
      loadPostLoginActivitiesApi: function () {
        return require('./post_login_activities_api');
      },
      loadAuditExportApi: function () {
        return require('./audit_export_api');
      },
      loadBrandingApi: function () {
        return require('./branding_api');
      },
      loadScimClientsApi: function () {
        return require('./scim_clients_api');
      },
      loadClaimsProvidersApi: function () {
        return require('../oauth-oidc/claims_providers_api');
      },
      loadProviderCommandsApi: function () {
        return require('../oauth-oidc/provider_commands_api');
      },
      loadSsfTransmittersApi: function () {
        return require('../ssf/ssf_transmitters_api');
      },
      loadGrantManagementApi: function () {
        return require('../oauth-oidc/grant_management_api');
      }
    };
  }

  // THE LOAD-TIME WORK, run once for the installed instance (#50, R2): the
  // two tables, the request schemas and the startup banner, in the order
  // this module ran them at load.
  /**
   * Runs the load-time work once for the installed instance: builds the two
   * route tables, compiles the request schemas, registers the console's closed
   * sets and logs the startup banner.
   *
   * @param instance - the installed instance
   */
  static wire(instance: AdminApi): void {
    log.debug("Entering AdminApi.wire().");
    PROTOCOL_SETTINGS_OPERATIONS = instance.buildProtocolSettingsOperations();
    ROUTES = spec.named(instance.buildRoutes());
    instance.declareImplicitParameters(ROUTES);
    instance.compileRequestSchemas();
    instance.registerConsoleClosedSets();
    log.info(startupBanner(instance.operationSummaries().length));
    log.debug("Leaving AdminApi.wire().");
  }

  /**
   * Returns a copy of a JSON Schema with what this API does not enforce at the
   * door taken out: `required`, an enum the handler refuses in its own words,
   * and with `""` added to every other enum.
   *
   * @param node - the schema, or any node inside it
   * @returns the copy
   */
  structureOnly(node) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminApi.structureOnly().");
    if (Array.isArray(node)) {
      log.debug("Leaving AdminApi.structureOnly().");
      return node.map(this.structureOnly.bind(this));
    }
    if (!node || typeof node !== 'object') {
      log.debug("Leaving AdminApi.structureOnly().");
      return node;
    }
    const out: any = {};
    Object.keys(node).forEach(function (key) {
      if (NOT_ENFORCED_HERE.indexOf(key) >= 0) {
        return;
      }
      if (key === 'enum' && node[REFUSED_BY_HANDLER] === true) {
        // The handler refuses this one, in words of its own.
        return;
      }
      if (key === 'enum' && Array.isArray(node.enum)) {
        // The empty string is absent (see NOT_ENFORCED_HERE's header).
        out.enum = node.enum.indexOf('') >= 0 ? node.enum.slice()
                                              : node.enum.concat('');
        return;
      }
      out[key] = self.structureOnly(node[key]);
    });
    // #1347 — THE INTEGER BOUNDARY BACKSTOP. Every request integer this API
    // takes is bounded to ±Number.MAX_SAFE_INTEGER unless its own schema names
    // a tighter bound, so a fuzzed or mistaken magnitude (a ttl of 9.22e21,
    // which the Schemathesis gate fed) is refused at the door (400,
    // STS-API-0009) rather than reaching a handler that writes it to a bigint
    // column and poisons a flush. No legitimate admin-api integer approaches
    // that ceiling — the largest is an epoch-millisecond instant, the year
    // 287396 — and a value beyond it has already lost integer precision. It is
    // a BACKSTOP, not the fix: `persistence_minted.js`'s expiryOf()/sortAtFor()
    // cap the one known column and the flush drops any other permanent data
    // error. It is injected into the ajv copy only, not the published document,
    // and `type: ['integer','string']` still admits a numeric STRING (the
    // console form case), which the handler parses — the bound holds the JSON
    // number, which is what a machine client sends.
    const types = Array.isArray(out.type) ? out.type : [out.type];
    if (types.indexOf('integer') >= 0) {
      if (typeof out.maximum !== 'number') {
        out.maximum = Number.MAX_SAFE_INTEGER;
      }
      if (typeof out.minimum !== 'number') {
        out.minimum = -Number.MAX_SAFE_INTEGER;
      }
    }
    log.debug("Leaving AdminApi.structureOnly().");
    return out;
  }

  /**
   * Returns a request schema ready for ajv: `structureOnly()` of it, with the
   * document's named schemas as `components`.
   *
   * **`components` IS PASSED IN, AND EVERY CALLER PASSES THE SAME ONE (#365,
   * 2026-09-30).** It used to be `structureOnly(spec.SCHEMAS)` made here, a
   * fresh deep copy of the whole components table (about 170 KB) for each of
   * the 363 validators — and ajv keeps every root it compiled in its cache
   * for the life of the process, so the copies were never collected: about
   * 60 MB of every process's heap. The copy is made once, with the first
   * validator `validatorFor()` compiles (#617), and each root points at it.
   * ajv reads a schema
   * and never writes to it, so a shared subtree is exactly what the copies
   * were, 363 times fewer; what each validator accepts and refuses, and the
   * words it refuses in, are unchanged.
   *
   * @param schema - an operation's request schema
   * @param components - the one `{ schemas: structureOnly(spec.SCHEMAS) }`
   * @returns the schema to compile
   */
  compilable(schema, components) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.compilable().");
    log.debug("Leaving AdminApi.compilable().");
    return Object.assign({}, this.structureOnly(schema),
                         { components: components });
  }

  /**
   * Returns the key a compiled request validator is held under.
   *
   * @param route - the route pattern or path
   * @param action - the action name, or empty for a plain route
   * @returns the key
   */
  validatorKeyOf(route, action) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.validatorKeyOf().");
    log.debug("Leaving AdminApi.validatorKeyOf().");
    return route + '\u0000' + (action || '');
  }

  // ---------------------------------------------------------------------------
  // THE REQUEST SCHEMAS ARE COMPILED ON FIRST USE (#617, 2026-10-14).
  //
  // Every one of the 363 was compiled by ajv when the instance was wired —
  // in every process, at every start, ~1.2 s of the ~3 s the management
  // API's load cost on 8081 (measured in the tests image: 1144 ms for
  // `compileRequestSchemas()` against 4 ms to build the whole route table),
  // and almost none of them is ever reached by a given process. Now `wire()`
  // only RECORDS each operation's schema under its validator key, and
  // `validatorFor()` compiles one the first time a request reaches it and
  // keeps it. What a validator accepts and refuses, and the words it refuses
  // in, are unchanged; the routes, the gate and the console's closed sets are
  // registered exactly where and when they were (rule 1). The one thing that
  // moves is WHEN a schema this repository wrote that ajv will not compile is
  // reported (STS-API-0010): at its operation's first request rather than at
  // start — so `compileAllRequestSchemas()` compiles the lot on demand, and
  // `tests/admin_api_lazy_validators.js` asks it to and holds that none fails.
  // ---------------------------------------------------------------------------
  /**
   * Records every request schema in the route table under its validator key,
   * to be compiled by `validatorFor()` when first needed.
   *
   * @returns how many schemas were recorded
   */
  compileRequestSchemas() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminApi.compileRequestSchemas().");
    let recorded = 0;
    validators.clear();
    validatorSources.clear();
    sharedComponents = null;
    ROUTES.forEach(function (entry) {
      const route = entry.route || entry.path;
      const rows = entry.actions || [];
      rows.forEach(function (action) {
        if (!action.requestBody) {
          return;
        }
        validatorSources.set(self.validatorKeyOf(route, action.action),
                             { schema: action.requestBody,
                               name: action.operationId });
        recorded = recorded + 1;
      });
      if (entry.requestBody) {
        validatorSources.set(self.validatorKeyOf(route, ''),
                             { schema: entry.requestBody,
                               name: entry.operationId || route });
        recorded = recorded + 1;
      }
    });
    log.debug("Leaving AdminApi.compileRequestSchemas(). " + recorded +
              " schema(s) recorded, none compiled yet.");
    return recorded;
  }

  /**
   * Returns the compiled validator for a validator key, compiling it the
   * first time; null when the operation has no schema or its schema would
   * not compile (logged once under `STS-API-0010`).
   *
   * @param key - the key from `validatorKeyOf()`
   * @returns the validator, or null
   */
  validatorFor(key) {
    const { log, errorCodes, spec } = this.deps;
    log.debug("Entering AdminApi.validatorFor().");
    if (validators.has(key)) {
      log.debug("Leaving AdminApi.validatorFor(). Compiled already.");
      return validators.get(key);
    }
    const source = validatorSources.get(key);
    if (!source) {
      log.debug("Leaving AdminApi.validatorFor(). No schema.");
      return null;
    }
    // ONE copy of the enforced components for every root (#365; see
    // `compilable()`), made with the first validator.
    if (!sharedComponents) {
      sharedComponents = { schemas: this.structureOnly(spec.SCHEMAS) };
    }
    let compiled = null;
    try {
      compiled = ajv.compile(this.compilable(source.schema,
                                             sharedComponents));
    } catch (e) {
      // A schema this repository wrote that ajv will not compile. Logged by
      // operation so it names the row to fix; the operation goes on working
      // unvalidated, because a management API that would not answer is worse
      // than one operation whose body is unchecked. Remembered as null, so it
      // is said once rather than on every request.
      log.error(errorCodes.tag('STS-API-0010') +
                'admin-api: the request schema for ' + source.name +
                ' would not compile and that operation is unvalidated: ' +
                e.message);
    }
    validators.set(key, compiled);
    log.debug("Leaving AdminApi.validatorFor(). " +
              (compiled ? "Compiled." : "Would not compile."));
    return compiled;
  }

  /**
   * Compiles every recorded request schema now, for a test or a caller that
   * wants every one checked at once.
   *
   * @returns `{ built, failed }`, the operations' names that would not
   *   compile in `failed`
   */
  compileAllRequestSchemas() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminApi.compileAllRequestSchemas().");
    let built = 0;
    const failed = [];
    validatorSources.forEach(function (source, key) {
      if (self.validatorFor(key)) {
        built = built + 1;
      } else {
        failed.push(source.name);
      }
    });
    log.debug("Leaving AdminApi.compileAllRequestSchemas(). " + built +
              " built, " + failed.length + " failed.");
    return { built: built, failed: failed };
  }

  /**
   * Says how many request validators this process has compiled so far, and
   * how many schemas are recorded.
   *
   * @returns `{ compiled, recorded }`
   */
  validatorCounts() {
    const { log } = this.deps;
    log.debug("Entering AdminApi.validatorCounts().");
    log.debug("Leaving AdminApi.validatorCounts().");
    return { compiled: validators.size, recorded: validatorSources.size };
  }

  // ---------------------------------------------------------------------------
  // THE CONSOLE'S CLOSED SETS, FROM THIS TABLE (#86).
  //
  // Every operation here names the console control it is the machine's door
  // to — `mirrors: 'POST /admin/users and POST /admin/users/new'` — and a
  // console form posts the SAME `action` the operation is named for (rule 7;
  // `/permissions/define-permission`'s stutter is that rule showing). So the
  // enums an action's request schema declares are registered in
  // `common/closed_sets.ts` under every console page its route mirrors, and
  // the console gate holds a form POST to them. The console has no copy of
  // any set: a value this document adds to an enum is accepted on both doors
  // the moment it is added, and one it removes is refused on both.
  //
  // Only a flat field is held there (a form has nothing nested); what a form
  // spells differently from the API — `leafKeyAlg` for `keyAlg` — is simply
  // not matched, and is the handler's to refuse. Returns how many controls
  // hold at least one field.
  // ---------------------------------------------------------------------------
  /**
   * Registers the enums each action's request schema declares in
   * `common/closed_sets.ts` under every console page its route mirrors, so the
   * console gate holds a form POST to the same sets.
   *
   * @returns how many controls hold at least one closed field
   */
  registerConsoleClosedSets() {
    const { log, spec, closedSets } = this.deps;
    log.debug("Entering AdminApi.registerConsoleClosedSets().");
    let held = 0;
    const pagesOf = function (mirrors) {
      const pages = [];
      const re = /POST (\/admin(?:\/[^\s,]*)?)/g;
      let m;
      while ((m = re.exec(String(mirrors || ''))) !== null) {
        pages.push(m[1]);
      }
      return pages;
    };
    ROUTES.forEach(function (entry) {
      if (entry.method === 'GET') {
        return;
      }
      // An action may name a control of its own (`source.mirrors` in
      // `admin_api_spec.ts`), and wins over its route's, as it does in the
      // document.
      const rows = (entry.actions || []).map(function (a) {
        return { action: a.action || '', body: a.requestBody,
                 pages: pagesOf(a.mirrors || entry.mirrors) };
      });
      if (entry.requestBody && !(entry.actions || []).length) {
        rows.push({ action: '', body: entry.requestBody,
                    pages: pagesOf(entry.mirrors) });
      }
      rows.forEach(function (row) {
        if (!row.body || !row.pages.length) {
          return;
        }
        const fields = closedSets.collect(row.body, spec.SCHEMAS);
        if (!fields.length) {
          return;
        }
        row.pages.forEach(function (page) {
          closedSets.registerConsole(page, row.action, fields);
        });
        held = held + 1;
      });
    });
    log.debug("Leaving AdminApi.registerConsoleClosedSets(). " + held +
              " control(s) hold a closed set.");
    return held;
  }

  // ---------------------------------------------------------------------------
  // A QUERY PARAMETER'S CLOSED SET (#86). The enums an operation's
  // `parameters` declare `in: query` were published and never checked, so a
  // filter spelt wrong answered 200 with every row — the answer to a question
  // nobody asked. Both the route's parameters and its action's are held.
  // ---------------------------------------------------------------------------
  /**
   * Checks the request's query parameters against the enums the operation's
   * route and action declare `in: query`.
   *
   * @param entry - the route table entry
   * @param req - the request
   * @returns `closedSets.checkQuery()`'s result, `{ ok, ... }`
   */
  checkQueryEnums(entry, req) {
    const { log, closedSets } = this.deps;
    log.debug("Entering AdminApi.checkQueryEnums().");
    const parameters = this.parametersOf(entry, req);
    const checked = closedSets.checkQuery(parameters, req.query);
    log.debug("Leaving AdminApi.checkQueryEnums(). " +
              (checked.ok ? "Accepted." : "Refused."));
    return checked;
  }

  /**
   * The parameters a request's operation declares: its route's and, for an
   * action resource, the action's.
   *
   * @param entry - the route table entry
   * @param req - the request
   * @returns the parameters
   */
  parametersOf(entry, req) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.parametersOf().");
    const action = String((req.params && req.params.action) || '');
    const row = (entry.actions || []).filter(function (a) {
      return a.action === action;
    })[0];
    log.debug("Leaving AdminApi.parametersOf().");
    return (entry.parameters || []).concat((row && row.parameters) || []);
  }

  // ---------------------------------------------------------------------------
  // WHAT EVERY OPERATION TAKES WITHOUT SAYING SO (#1476). Declared here, once
  // for the whole table, so that the document and the refusals read the same
  // `parameters`: `DPoP` (RFC 9449), which the console sends on every call,
  // and `cell`, which `common/cell_placement.ts` reads for every path under
  // `/admin-api` before any handler runs (`/admin-api/...?cell=<id>`). The
  // console twins made in `buildRoutes()` have their own row and are covered
  // by the same walk.
  // ---------------------------------------------------------------------------
  /**
   * Adds to every operation the parameters every operation takes.
   *
   * @param routes - the route table
   */
  declareImplicitParameters(routes: any[]): void {
    const { log } = this.deps;
    log.debug("Entering AdminApi.declareImplicitParameters().");
    const implicit = ModelTables.file('openapi.every.json').management;
    routes.forEach(function (entry) {
      const own = entry.parameters || [];
      entry.parameters = own.concat(implicit.filter(function (one) {
        return !own.some(function (p) {
          return p.in === one.in && p.name === one.name;
        });
      }));
    });
    log.debug("Leaving AdminApi.declareImplicitParameters().");
  }

  // ---------------------------------------------------------------------------
  // Turn ajv's errors into the `{ ok: false, errors: [...] }` shape every
  // refusal on this API already uses, so a caller parses one thing.
  //
  // `instancePath` is a JSON Pointer (`/redirect_uris/0`); the leading slash is
  // dropped and the rest is written with dots, because a caller is reading it
  // beside a body they typed rather than resolving a pointer.
  // ---------------------------------------------------------------------------
  /**
   * Turns ajv's errors into the refusal sentences this API answers with, paths
   * written with dots.
   *
   * @param errors - ajv's `errors`
   * @returns one message per error, or one generic message
   */
  errorsFromAjv(errors) {
    const { log, closedSets } = this.deps;
    log.debug("Entering AdminApi.errorsFromAjv().");
    const out = (errors || []).map(function (e) {
      const where = String(e.instancePath || '').replace(/^\//, '')
                                                .replace(/\//g, '.');
      const missing = e.params && e.params.missingProperty;
      const extra = e.params && e.params.additionalProperty;
      if (e.keyword === 'enum' && e.params &&
          Array.isArray(e.params.allowedValues)) {
        // A value outside a closed set (#86), in the words every door uses.
        // The `""` the compile added is not part of the declared set.
        return closedSets.sentence(where || 'the request', e.data,
          e.params.allowedValues.filter(function (v) {
            return v !== '';
          }));
      }
      if (missing) {
        return '"' + missing + '" is required.';
      }
      if (extra) {
        return '"' + extra + '" is not a member of this request. The ' +
               'operation\'s schema in the OpenAPI document lists what is.';
      }
      return (where ? '"' + where + '" ' : 'the request ') + e.message + '.';
    });
    log.debug("Leaving AdminApi.errorsFromAjv(). " + out.length +
              " message(s).");
    return out.length ? out : ['The request body did not match this ' +
                               'operation\'s schema.'];
  }

  // ---------------------------------------------------------------------------
  // The check itself, run before a handler sees the request.
  //
  // **`action` IS REMOVED BEFORE VALIDATING, and that is not a loophole.**
  // Every action resource here is `/<resource>/:action`, so the action is a
  // PATH segment and the schemas describe the body WITHOUT it — they carry
  // `additionalProperties: false`, so leaving it in would refuse every request
  // on this API. A caller that also puts `action` in the body is ignored
  // exactly as it was before: `withAction()` takes the path parameter and
  // overwrites.
  // ---------------------------------------------------------------------------
  /**
   * Validates a request's body against its operation's compiled schema, with
   * `action` removed first because it is a path segment.
   *
   * A handler that owns its body, or an operation with no schema, is accepted.
   *
   * @param req - the request
   * @returns `{ ok: true }`, or `{ ok: false, errors }`
   */
  checkRequestBody(req) {
    const { log, parseBody } = this.deps;
    log.debug("Entering AdminApi.checkRequestBody().");
    const route = req.__adminApiRoute || '';
    const action = String((req.params && req.params.action) || '');
    if (req.__adminApiHandlerOwnsBody) {
      // A NARROW DOOR: the handler validates the WHOLE body and refuses an
      // unknown member by naming the ones it accepts. See `handlerOwnsBody` on
      // the route table.
      log.debug("Leaving AdminApi.checkRequestBody(). The handler owns this " +
                "body.");
      return { ok: true };
    }
    const validate = this.validatorFor(this.validatorKeyOf(route, action)) ||
                     this.validatorFor(this.validatorKeyOf(route, ''));
    if (!validate) {
      // No schema for this operation — a GET, an unknown action the handler is
      // about to refuse by name, or a row that carries none. Not this
      // function's business to invent one.
      log.debug("Leaving AdminApi.checkRequestBody(). No schema for this " +
                "operation.");
      return { ok: true };
    }
    const body = parseBody(req);
    const subject = Object.assign({}, body);
    delete subject.action;
    if (validate(subject)) {
      log.debug("Leaving AdminApi.checkRequestBody(). Accepted.");
      return { ok: true };
    }
    log.debug("Leaving AdminApi.checkRequestBody(). Refused with " +
              (validate.errors || []).length + " error(s).");
    return { ok: false, errors: this.errorsFromAjv(validate.errors) };
  }

  // A WINDOWED CONSOLE PAGE THAT FAILED (#359, and the review of #692): an
  // unreadable store is a 503 the caller may retry — the bridge's timeout
  // (STS-LDAP-0130) or refusal (0131), the request's spent budget (0175),
  // or an asynchronous question the store did not answer (0139, which
  // `ldap_server.js`'s `storeAsked()` marks) — and anything else is the
  // bug it is: a 500 under its own code, or `fallback` when it has none.
  /**
   * Answers a rejected directory page: 503 for an unreadable store, 500
   * otherwise.
   *
   * @param res - the response
   * @param e - the rejection
   * @param what - what could not be drawn, for the log line
   * @param fallback - the code of a failure that carries none
   * @returns true when it was the store (a 503)
   */
  answerDirectoryFailure(res, e, what: string, fallback: string): boolean {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AdminApi.answerDirectoryFailure().");
    const code = errorCodes.codeOf(e);
    const store = code === 'STS-LDAP-0130' || code === 'STS-LDAP-0131' ||
      code === 'STS-LDAP-0139' || code === 'STS-LDAP-0175';
    if (store) {
      log.error(errorCodes.tag(code) + 'admin-api: ' + what + ' could not ' +
                'be read from the store: ' + ((e && e.message) || e));
      res.setHeader('Retry-After', '5');
      // STS-LDAP-0130, STS-LDAP-0131, STS-LDAP-0139, STS-LDAP-0175.
      errorCodes.mark(res, code);
      this.sendJson(res, 503, { error: 'temporarily_unavailable',
        error_description: 'The directory could not be read; try again ' +
          'shortly.' });
      log.debug("Leaving AdminApi.answerDirectoryFailure(). Unavailable.");
      return true;
    }
    log.error(errorCodes.tag(code || fallback) + 'admin-api: ' + what +
              ' could not be drawn: ' + ((e && e.stack) || e));
    // The rejection's own code, or `fallback` (STS-LDAP-0176).
    errorCodes.mark(res, code || fallback);
    this.sendJson(res, 500, { error: 'server_error',
      error_description: require('../common/mode').hidesFailureDetail()
        ? 'The request could not be completed.'
        : String((e && e.message) || e) });
    log.debug("Leaving AdminApi.answerDirectoryFailure(). A failure.");
    return false;
  }

  // Every reply here is JSON, is never cached, and is pretty-printed. The last
  // of those is not decoration: the caller of a mock's admin API is usually a
  // person at a terminal or a test whose failure message is the body, and a 40
  // KB single line is unreadable in both.
  /**
   * Sends a JSON reply, pretty-printed and `Cache-Control: no-store`, adding
   * `protocolEndpoints` to a successful object reply to a GET that mirrors a
   * Protocols page.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param body - the reply
   */
  // What a federation act may say of a relationship (#1354): the record without
  // its credentials and without the entry holding them. A write answered both
  // in clear while the read has always masked them, and a caller's client log
  // is where such an answer ends up. FED_RECORD no longer declares them, so an
  // answer that carried one again would be refused rather than sent.
  federationAnswer(result) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.federationAnswer().");
    if (!result || !result.relationship) {
      log.debug("Leaving AdminApi.federationAnswer(). No record.");
      return result;
    }
    const shown = Object.assign({}, result.relationship);
    delete shown.entry;
    federation.SCHEMA.attributes.forEach(function (field) {
      if (field.sensitive) {
        delete shown[field.name];
      }
    });
    log.debug("Leaving AdminApi.federationAnswer().");
    return Object.assign({}, result, { relationship: shown });
  }

  // TYPED BY THE OPERATION (#1579): through a handler's response (a row's
  // `IyaApi.Answering`), `body` is held to the model's answer at a literal
  // 2xx status. Inside, it is the untyped value it always was.
  sendJson<R, S extends number>(res: R, status: S,
                                answer: IyaApi.AnswerOf<R, S>): void;
  sendJson(res: any, status: number, answer: any): void {
    const { log } = this.deps;
    log.debug("Entering AdminApi.sendJson(). status=" + status);
    let body = answer;
    // A 500 is by definition something nobody planned to say, so product mode
    // says nothing of it to the caller (ASVS 5.0.0 16.5.1). The sites that send
    // one log it.
    if (status === 500 && body && typeof body === 'object' &&
        require('../common/mode').hidesFailureDetail()) {
      const generic = 'The request could not be completed.';
      body = Object.assign({}, body,
        Array.isArray(body.errors) ? { errors: [generic] } : {},
        body.error_description ? { error_description: generic } : {});
    }
    // The realm's endpoints for a Protocols page, when this is the GET that
    // mirrors one: the registration loop computed them onto `res.locals`, and
    // the member is added to a successful object answer the way the console's
    // `respond()` adds it to the page's JSON. Every other answer is untouched.
    const rows = res.locals && res.locals.protocolEndpoints;
    if (rows && status === 200 && body && typeof body === 'object' &&
        !Array.isArray(body)) {
      body = Object.assign({}, body, { protocolEndpoints: rows });
    }
    // WHAT ONLY THE CONSOLE DRAWS, LEFT OUT OF A MANAGEMENT ANSWER (#454):
    // the members the registration loop names for an operation whose
    // console twin answers them (`withConsoleRoutes()`).
    // AN OWNER'S READ (#607): the one object, not the register around it.
    const ownerProjection = res.locals && res.locals.ownerProjection;
    if (typeof ownerProjection === 'function' && status === 200 && body &&
        typeof body === 'object' && !Array.isArray(body)) {
      body = ownerProjection(body);
    }
    const consoleMembers = res.locals && res.locals.consoleMembers;
    if (consoleMembers && status === 200 && body && typeof body === 'object' &&
        !Array.isArray(body)) {
      body = Object.assign({}, body);
      consoleMembers.forEach(function (name) {
        delete body[name];
      });
    }
    // THE PROSE THE SERVER WROTE INTO THE VIEW, IN THE CALLER'S LANGUAGE
    // (#543): only when the request names one in `Accept-Language` — the
    // console sends the locale it negotiated — and never in an OpenAPI
    // document, which stays English (rcbj's answers 1 and 2). A caller that
    // names no language reads exactly what it read before.
    if (status >= 200 && status < 300 && this.translatesAnswer(res.req)) {
      body = serverProse.translateView(body, serverProse.translatorFor(
        res.req.headers['accept-language'],
        (res.locals && res.locals.proseRoute) || ''));
    }
    // ADDED TO, never set: CORS may already have said `Vary: Origin`. A
    // response a test builds by hand has no `vary()`, and needs none.
    if (typeof res.vary === 'function') {
      res.vary('Accept-Language');
    }
    // AN ACT'S ANSWER CARRIES NO ERROR CODE (#1355), though it may hand back a
    // row the page's GET carries one on: only that page draws it.
    body = ResponseModelKit.actAnswer(res, body);
    res.status(status).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving AdminApi.sendJson().");
  }

  /**
   * Says whether an answer's server-written prose is translated (#543):
   * every answer to a request that names a language, except the OpenAPI
   * documents, which are an integrator's reference and stay English.
   *
   * @param req - the request
   * @returns true when the answer is translated
   */
  translatesAnswer(req) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.translatesAnswer().");
    const named = !!(req && req.headers && req.headers['accept-language']);
    const out = named && !/\/openapi\.json$/.test(String(req.path || ''));
    log.debug("Leaving AdminApi.translatesAnswer(). " + out);
    return out;
  }

  // The action a POST names, from the path rather than the body. It is forced
  // over whatever the body carried so that a body copied from the console's
  // form — which does carry `action` — cannot mean something other than the URL
  // it was sent to.
  // ---------------------------------------------------------------------------
  // A CREATE CLAIMS ITS NAME ACROSS NODES FIRST (2026-09-14, #46 section 3),
  // for `POST /admin-api/users/create` and `/admin-api/groups/create` —
  // `ldap/directory_create_claims.ts` argues it. The directory module is looked
  // up in the require CACHE and never required from here: it registers routes,
  // it is below this module in the route order, and a process that never loaded
  // it has no directory to race for (the action refuses on its own).
  // Resolves to `{ ok, settle }` or the refusal; inert where nothing can race.
  // ---------------------------------------------------------------------------
  /**
   * Claims a name across cluster nodes before a create, through the directory
   * module if this process has loaded it.
   *
   * @param what - the name to claim
   * @returns a promise of `{ ok, settle }` or the claim's refusal; an inert
   *   claim when there is no directory in this process
   */
  claimForCreate(what) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.claimForCreate().");
    let directory = null;
    try {
      const cached = require.cache[require.resolve('../ldap/ldap_server')];
      directory = cached && cached.loaded ? cached.exports : null;
    } catch (e) {
      log.debug("Caught in AdminApi.claimForCreate(): " +
                ((e && e.message) || e));
    }
    if (!directory || typeof directory.claimCreate !== 'function') {
      log.debug("Leaving AdminApi.claimForCreate(). No directory in this " +
                "process.");
      return Promise.resolve({ ok: true, settle: function () {} });
    }
    log.debug("Leaving AdminApi.claimForCreate().");
    return directory.claimCreate(what);
  }

  // ---------------------------------------------------------------------------
  // RUN AN ACTION, CLAIMING ITS NAME FIRST WHEN THERE IS ONE TO CLAIM. `what`
  // is null for an action that creates nothing, and then — and wherever a
  // create cannot race (`createClaims.active()` false, which is every
  // single-process service) — `run` is called SYNCHRONOUSLY, exactly as the
  // handler did before. Otherwise the claim is awaited, a refusal answered in
  // this API's shape (409 when another create holds the name, 400 when the
  // name is longer than the coordinator holds, or 503 when the store could
  // not be asked), and `run` handed the claim to settle with the action's
  // outcome.
  // ---------------------------------------------------------------------------
  /**
   * Runs an action, claiming its name first when there is one to claim and a
   * create can race.
   *
   * Without a claim `run` is called synchronously. A refused claim is answered
   * 409 when another create holds the name, 400 when the name is longer than
   * the coordinator holds (#1402), or 503 when the store could not be asked.
   * A throw after the claim settles it as failed and answers 500.
   *
   * @param res - the response
   * @param what - the name to claim, or null
   * @param run - the action, handed the claim to settle
   * @returns what `run` returns, or a promise when a claim was awaited
   */
  runClaimed(res, what, run) {
    const { log, createClaims, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering AdminApi.runClaimed().");
    const idle = { ok: true, settle: function () {} };
    if (!what || !createClaims.active()) {
      log.debug("Leaving AdminApi.runClaimed(). Nothing to claim.");
      return run(idle);
    }
    log.debug("Leaving AdminApi.runClaimed(). Claiming first.");
    return this.claimForCreate(what).then(function (held) {
      if (!held.ok) {
        if (held.reason === 'name') {
          // A name longer than the coordinator holds cannot succeed on a
          // retry, so this is a 400 and carries no Retry-After (#1402).
          errorCodes.mark(res, 'STS-LDAP-0210');
          self.sendJson(res, 400, { ok: false,
            errors: [createClaims.refusalMessage(held)] });
          return;
        }
        errorCodes.mark(res, held.code);
        if (held.reason === 'store') {
          // The create-claims store could not be asked (STS-LDAP-0093, fail
          // closed), which is transient — the coordination store is
          // momentarily unreachable — so the 503 carries Retry-After, as
          // `answerDirectoryFailure()` does. A handled 503 without it reads as
          // an uncaught server error (#1356: groups/create under fuzzing).
          res.setHeader('Retry-After', '5');
        }
        self.sendJson(res, held.reason === 'store' ? 503 : 409,
                      { ok: false,
                        errors: [createClaims.refusalMessage(held)] });
        return;
      }
      try {
        run(held);
      } catch (e) {
        held.settle(false);
        log.error(errorCodes.tag('STS-API-0113') + 'admin-api: a create that ' +
                  'had claimed its name threw: ' + ((e && e.message) || e));
        errorCodes.mark(res, 'STS-API-0113');
        self.sendJson(res, 500, {
          ok: false,
          errors: ['The create failed: ' + ((e && e.message) || e)] });
      }
    });
  }

  // THE BROADCAST PAGE'S VIEW (#1086): what `GET /admin-api/broadcast`
  // answers, and what the POST checks `everyRealm` against.
  /**
   * Builds the broadcast page's view for the caller.
   *
   * @param req - the request, for the caller's gate state
   * @returns the view
   */
  broadcastView(req) {
    const { log, config } = this.deps;
    log.debug("Entering AdminApi.broadcastView().");
    const realmsMod = require('../common/realms');
    const receivers = require('../ssf/ssf_receivers');
    let state = null;
    try {
      state = adminViews.gateStateFor(req);
    } catch (e) {
      log.debug("Caught in AdminApi.broadcastView(): " +
                ((e && e.message) || e));
      // No gate state: treated as a realm administrator, the narrower reach.
      state = null;
    }
    const realm = realmsMod.currentId();
    const serviceAdmin = !!state && state.authority !== 'realm';
    const ssfOn = !!config.value('ssf.enabled');
    const receiversOn = !!receivers.enabled();
    const view = {
      realm: realm,
      surfaces: receivers.SURFACES.map(function (one) {
        return { id: one.id, label: one.label };
      }),
      everyRealm: serviceAdmin && realm === realmsMod.DEFAULT_ID,
      realmCount: realmsMod.count(),
      maxChars: Number(config.value('ssf.announcementMaxChars')),
      pollMs: Number(config.value('ssf.announcementPollMs')),
      keepS: Number(config.value('ssf.announcementKeepS')),
      ready: ssfOn && receiversOn,
      why: !ssfOn ? 'Shared Signals is off (ssf.enabled).'
        : (!receiversOn ? 'This service\'s own receivers are off ' +
                          '(ssf.internalReceivers).' : '')
    };
    log.debug("Leaving AdminApi.broadcastView().");
    return view;
  }

  /**
   * Returns the body with `action` set from the path parameter, over whatever
   * the body carried.
   *
   * @param req - the request
   * @param body - the parsed body
   * @returns the new body
   */
  // A person changing how somebody signs in must have signed in recently
  // (#1538, ASVS 5.0.0 7.5.1). A program has no person to ask. Answered as RFC
  // 9470 says, so a client knows to sign in again; the console does that in its
  // popup and resends.
  reauthenticationOwed(res, action) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.reauthenticationOwed().");
    const caller = res && res.locals && res.locals.apiCaller;
    const limit = Number(require('../common/config')
      .value('account.recentAuthMinutes')) * 60;
    if (!limit || !caller || caller.kind !== 'person' ||
        REAUTHENTICATED_ACTIONS.indexOf(String(action)) < 0) {
      log.debug("Leaving AdminApi.reauthenticationOwed(). Not asked.");
      return false;
    }
    const at = Number(caller.authTime || 0);
    log.debug("Leaving AdminApi.reauthenticationOwed().");
    return !(at > 0 && Date.now() / 1000 - at <= limit);
  }

  refuseStaleSignIn(req, res) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AdminApi.refuseStaleSignIn().");
    const limit = Number(require('../common/config')
      .value('account.recentAuthMinutes')) * 60;
    const scheme = /^dpop /i.test(String(req.headers.authorization || ''))
      ? 'DPoP' : 'Bearer';
    res.set('WWW-Authenticate', scheme +
            ' error="insufficient_user_authentication", max_age=' + limit);
    errorCodes.mark(res, 'STS-API-0145');
    this.sendJson(res, 401, { ok: false,
      error: 'insufficient_user_authentication',
      errors: ['Sign in again to make this change.'] });
    log.debug("Leaving AdminApi.refuseStaleSignIn().");
  }

  withAction(req, body) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.withAction().");
    log.debug("Leaving AdminApi.withAction().");
    return Object.assign({}, body, { action: String(req.params.action || '') });
  }

  // The two spellings of a list, joined. A JSON body carries one `attributes`
  // array; a form body copied from the console carries `attribute` repeated.
  // Both are accepted for the same reason the console accepts both.
  /**
   * Returns a list field in both its spellings joined: a repeated form field
   * and a JSON array.
   *
   * @param req - the request
   * @param body - the parsed body
   * @param one - the singular field name
   * @param many - the plural field name
   * @returns the names
   */
  namesOf(req, body, one, many) {
    const { log, admin } = this.deps;
    log.debug("Entering AdminApi.namesOf(). " + one + "/" + many);
    const names = admin.listField(req, body, one)
                       .concat(admin.listField(req, body, many));
    log.debug("Leaving AdminApi.namesOf(). " + names.length + " name(s).");
    return names;
  }

  // --- the policies resource's actions (#64)
  // --------------------------------------
  //
  // Two per kind in `admin-core/policy_kinds.ts`, the save's body built from
  // the kind's own FIELDS. The prose of the two kinds this service defines is
  // written out; a kind registered later gets the generic sentences, which
  // are true of every kind because every kind implements the same interface.
  /**
   * Returns the policies resource's action rows, two per policy kind in
   * `admin-core/policy_kinds.ts`, their bodies built from each kind's fields.
   *
   * @returns the action rows
   */
  policyKindActions() {
    const { log } = this.deps;
    log.debug("Entering AdminApi.policyKindActions().");
    const PROSE = {
      password: {
        save: 'Writes `cn=<profile>,ou=passwordPolicies` in this realm\'s ' +
              'directory, REPLACING what is there: `default`, or a named ' +
              'policy, created by its first save (#1236). ' +
              '`generatedLength` must be at least `minLength`, and ' +
              '`minSymbols`, `requireUppercase` and `requireDigit` may only ' +
              'be 0 or false (ASVS 5.0.0 6.2.5). An application ' +
              '(`appPasswordPolicy`) and a group (`stsPasswordPolicy`) name ' +
              'a named policy; of those naming one for a person the lowest ' +
              '`precedence` applies (ties by name), else `default`, and a ' +
              'reference to a policy the realm does not hold names ' +
              'nothing, and the rest still rank (STS-AUTHN-0539). A named ' +
              'policy still named is not removed (STS-AUTHN-0540). **A ' +
              'change applies to the NEXT password set in this realm and ' +
              'to nothing already stored**, ' +
              'which is a hash and cannot be re-checked.',
        example: { minLength: 14 }
      },
      authn: {
        save: 'Writes `cn=default,ou=authnPolicies` in this realm\'s ' +
              'directory, REPLACING what is there — in the DEFAULT realm, ' +
              'the profile every realm without its own follows. At least ' +
              'one mechanism must be a first factor, and with ' +
              '`requireSecondFactor: always` at least one a second. ' +
              '**An email mechanism cannot be turned on while this realm ' +
              'cannot send mail** (`STS-AUTHN-0244`), and NIST SP 800-63B-4 ' +
              'section 3.1.3.1 advises against email as an authenticator ' +
              'at all, which is why both are off by default. There is no ' +
              '`never`: a person who holds a second factor is always asked ' +
              'for it.',
        example: { emailCodeTtlS: 240 }
      },
      // #221: the third kind.
      serviceAccount: {
        save: 'Writes `cn=default,ou=serviceAccountPolicies` in this ' +
              'realm\'s directory, REPLACING what is there; a realm with no ' +
              'entry of its own follows the default realm\'s. Every default ' +
              'is the more secure one: no second-factor exemption, no ' +
              'browser sign-in, no rotation, an owner required. Two rules ' +
              'read other registers: `generatedLength` may not be below the ' +
              'password policy\'s `minLength`, and `rotationEnabled` is ' +
              'refused while the realm has no push destination. The seven ' +
              '`allow*` door fields say which password doors a service ' +
              'account may use. **A NAMED profile (#1240)** — `profile` of ' +
              'lower-case letters, digits and hyphens, with `precedence` — ' +
              'is this realm\'s own and governs every service account ' +
              'whose `stsServiceAccountPolicy` names it (set on the ' +
              'person\'s Policies tab or by `POST ' +
              '/admin-api/users/set-attribute`; only a service account may ' +
              'hold it, STS-SVCACCT-0048). A reference the realm does not ' +
              'hold gets `default` and is logged (STS-SVCACCT-0047), and a ' +
              'named profile an account still names is not deleted ' +
              '(STS-SVCACCT-0049).',
        example: { rotationEnabled: false, allowBrowserSignIn: false }
      },
      // #527: the fourth kind.
      passkey: {
        save: 'Writes `cn=default,ou=passkeyPolicies` in this realm\'s ' +
              'directory, REPLACING what is there; a realm with no entry of ' +
              'its own follows the default realm\'s. `allowUsernameless` ' +
              '(on by default) offers a passkey sign-in with no username. ' +
              '`requireUsernameless` (off, #608) makes it the only way in ' +
              'for an application whose named authentication policy ' +
              '(`appAuthnPolicy`) lists `webauthn` alone as its first ' +
              'factor: no username field, and a sign-in naming a person ' +
              'refused; it needs `allowUsernameless`, and the `default` ' +
              'profile never applies it to the admin console, the debugger ' +
              'or the user portal. ' +
              'While it is off, "Use a security key" asks the authenticator ' +
              'for a discoverable credential (`residentKey: required`), as ' +
              '"Create a passkey" always does; while it is on, it asks ' +
              '`securityKeyResidentKey` (`discouraged`, `preferred` or ' +
              '`required`, default `required`). `backupEligibility` ' +
              '(`allow` by default) set to `disallow` refuses a synced ' +
              '(backup-eligible) passkey at registration and at sign-in. ' +
              '`enforcePinLength` (off) asks a key for its minimum PIN ' +
              'length (CTAP 2.1 minPinLength) and holds it to ' +
              '`minPinLength` (4 to 63); `pinLengthOnlyIfSupported` (off) ' +
              'accepts a key that does not report. ' +
              '`enforceAttestationAtSignIn` (off) holds every passkey ' +
              'sign-in to the attestation rules in force. ' +
              '`passkeyHints`, `securityKeyHints` and `signInHints` are ' +
              'the WebAuthn hints each ceremony sends, in order, or `none`. ' +
              '`enterpriseSerialAttribute` (empty) names the attribute of ' +
              'a person\'s entry holding their security-key serials, which ' +
              'a registration\'s trusted enterprise attestation must name. ' +
              '`userDisplayName`, `rpNameExtras` and `credentialLabel` ' +
              'are the names a passkey prompt and a new key show. ' +
              '`aggregateDevices` (on) offers a person\'s passkeys as one ' +
              'sign-in choice; off, one per passkey. ' +
              '`postQuantumRequired` (`off`, #718) set to `sign-in` lets ' +
              'only a post-quantum (ML-DSA) passkey sign a person in, as ' +
              'the first credential or the second factor, and ' +
              '`registration-and-sign-in` refuses a classical one at ' +
              'registration too; refused while the realm offers no ML-DSA ' +
              '(STS-AUTHN-0357). ' +
              '`attestationAlgorithms` (`none`, #941, optional) lists the ' +
              'algorithms a passkey\'s ATTESTATION must be signed with, ' +
              'statement and every certificate leaf to anchor: ' +
              '`post-quantum`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, ' +
              '`slh-dsa`, `composite-ml-dsa`; set, it demands a trusted ' +
              'statement and refuses any other at registration ' +
              '(STS-AUTHN-0411), and at sign-in while ' +
              '`enforceAttestationAtSignIn` is on (STS-AUTHN-0412). ' +
              '`postQuantumAllowCredentials` (`realm`, ' +
              '#946; optional) chooses how the passkey step names the ' +
              'keys while one is required: `narrow` the post-quantum ones ' +
              'only, `list-and-refuse` every one, a classical assertion ' +
              'then refused after the ceremony with a page saying why, ' +
              'and `realm` the realm\'s ' +
              'webauthn.postQuantumAllowCredentials. ' +
              '`registrationAlgorithms` (`realm`, #940; optional) is the ' +
              'ordered list a registration offers this profile\'s people ' +
              'in place of the realm\'s webauthn.algorithms, and ' +
              '`registrationMode` (`realm`, #940; optional) is `pq-only` ' +
              '(ML-DSA only, no classical retry), `pq-first` (ML-DSA, then ' +
              'the classical algorithms, whatever the realm\'s pqcOnly), ' +
              '`classical-only` (no ML-DSA, no post-quantum lane) or ' +
              '`realm` (webauthn.pqcOnly and ' +
              'webauthn.pqcAlongsideClassical); a passkey outside what the ' +
              'profile offers is refused at registration (STS-AUTHN-0432). ' +
              '`clientRules` (empty, #1112; optional) names the clients — ' +
              '`<browser> on <system>`, each a family or `*` with an ' +
              'optional major-version range, `;` between rules — whose ' +
              'registrations offer the list less ML-DSA, where a classical ' +
              'passkey is allowed. ' +
              'Refused: `classical-only` with `postQuantumRequired` not ' +
              '`off` or with `attestationAlgorithms` set (STS-AUTHN-0430), ' +
              'and `pq-only` or `pq-first` where the list offered names no ' +
              'ML-DSA (STS-AUTHN-0431).',
        example: { allowUsernameless: false, requireUsernameless: false,
                   securityKeyResidentKey: 'required',
                   backupEligibility: 'allow',
                   enforcePinLength: false, minPinLength: 4,
                   pinLengthOnlyIfSupported: false,
                   enforceAttestationAtSignIn: false,
                   passkeyHints: 'client-device,hybrid',
                   securityKeyHints: 'security-key', signInHints: 'none',
                   enterpriseSerialAttribute: '',
                   userDisplayName: 'displayName, givenName sn',
                   rpNameExtras: 'none', credentialLabel: '',
                   aggregateDevices: true, postQuantumRequired: 'off',
                   attestationAlgorithms: 'none',
                   postQuantumAllowCredentials: 'realm',
                   registrationAlgorithms: 'realm',
                   registrationMode: 'realm', lanes: 'realm',
                   clientRules: '' }
      },
      // #539: the fifth kind, with named profiles an application or a
      // group names (#1238).
      locale: {
        save: 'Writes `cn=<profile>,ou=localePolicies` in this realm\'s ' +
              'directory, REPLACING what is there; a realm with no ' +
              '`default` of its own follows the default realm\'s, and named ' +
              'profiles are the realm\'s own. `defaultLocale` (`en`) is a ' +
              'BCP 47 language tag: the language a page falls back to, and ' +
              'mail to a person who names none is written in. ' +
              '`populatePreferredLanguage` (on) gives a person created ' +
              'without a `preferredLanguage` that tag. A named profile ' +
              'carries a `precedence` (1 to 1000, 100 when left out) and ' +
              'lists nothing: an application names it in ' +
              '`appLocalePolicy` and a group in `stsLocalePolicy`, and of ' +
              'those naming one for a page the lowest precedence applies, ' +
              'else `default`. A named profile something names is not ' +
              'deleted (STS-I18N-0014).',
        example: { defaultLocale: 'fr-CA', populatePreferredLanguage: true }
      },
      // #396: the sixth kind, with two acts of its own for the realm's
      // custom attributes.
      attributes: {
        save: 'Writes `cn=default,ou=attributePolicies` in this realm\'s ' +
              'directory, REPLACING what is there; a realm with no entry of ' +
              'its own follows the default realm\'s, and the built-in ' +
              'default is `givenName, sn, mail`. `requiredAttributes` is ' +
              'the list (an array, or comma-separated) of attributes every ' +
              'person must hold besides `uid`, `cn` and `sn`, which are ' +
              'always required; a name a person here cannot be given a ' +
              'value for — `userPassword`, a binary attribute, `memberOf`, ' +
              'an `sts` attribute, or a custom attribute this realm does ' +
              'not define — is refused (STS-LDAP-0166). **Enforced in ' +
              'product mode**: a create without one is refused at every ' +
              'door (STS-LDAP-0162), and an edit may not take one away ' +
              '(STS-LDAP-0164). `GET /admin-api/policies?missing=count` ' +
              'counts the people who lack one, where the directory is held ' +
              'in memory.',
        example: { requiredAttributes: ['givenName', 'sn', 'mail'] }
      },
      // #1096: the seventh kind, with named profiles chosen by group.
      postLogin: {
        save: 'Writes `cn=<profile>,ou=postLoginPolicies` in this realm\'s ' +
              'directory, REPLACING what is there; a realm with no ' +
              '`default` of its own follows the default realm\'s, and named ' +
              'profiles are the realm\'s own. **Off by default** ' +
              '(`enabled`). On, a person the profile reaches who is due the ' +
              '`activity` is asked after signing in, before being sent back ' +
              'to the application: `pqc-passkey-migration` asks a person ' +
              'holding a classical passkey and no post-quantum one to ' +
              'register an ML-DSA passkey, and — per `noPasskey` — a ' +
              'person holding none to register one. A passkey has no role ' +
              '(#1135): `noPasskeyRole` is accepted and ignored. Skip puts ' +
              'it off ' +
              '`snoozeDays`; once `graceDays` (0 = never) have passed since ' +
              'the person\'s first invitation Skip is refused ' +
              '(STS-AUTHN-0474) and the sign-in is held until it is done, ' +
              'and a door that cannot ask for it refuses the sign-in ' +
              '(STS-AUTHN-0473). A named profile carries a ' +
              '`precedence` and nothing else: a group names it in ' +
              '`stsPostLoginPolicy` (`POST /admin-api/groups/set-policy`) ' +
              'and an application in `appPostLoginPolicy` ' +
              '(`POST /admin-api/applications/set`). Of the profile the ' +
              'application signed in to names and those the person\'s ' +
              'groups name the lowest `precedence` wins, so a named ' +
              'profile with `enabled` off excludes them; a started ' +
              'activity\'s mail and the progress report know no ' +
              'application and select by the groups alone. A profile ' +
              'something names is not deleted (STS-AUTHN-0543). ' +
              '`method` (#1100) is how a classical passkey is migrated: ' +
              '`upgrade` (proved once, then replaced ' +
              'in place on its authenticator), `alongside` (an ML-DSA ' +
              'passkey beside it) or `automatic` (the lanes decide). ' +
              '`attestation` (#1102): `post-quantum` counts an ML-DSA ' +
              'passkey as migrated only where its recorded attestation is ' +
              'post-quantum too. `noPasskeyFallback` (#1103): `classical` ' +
              'offers a person with no passkey a classical retry where ' +
              'their device cannot make ML-DSA.',
        example: { enabled: true, activity: 'pqc-passkey-migration',
                   snoozeDays: 7, graceDays: 30, noPasskey: 'invite',
                   method: 'automatic',
                   attestation: 'any', noPasskeyFallback: 'none' }
      }
    };
    const cap = function (text) {
      log.debug("Entering cap().");
      log.debug("Leaving cap().");
      return text.charAt(0).toUpperCase() + text.slice(1);
    };
    // A kind's save and reset are named after it, so the checker knows them
    // only as the model's operations of that name (#1579).
    type SaveOrReset =
      Extract<keyof AdminOps, `save${string}Policy` | `reset${string}Policy`>;
    const out: Array<IyaApi.ActionOf<AdminOps>> = [];
    policyKinds.list().forEach(function (kind) {
      const module = kind.module;
      const prose = PROSE[kind.id] || {
        save: 'Writes this kind\'s `cn=default` under `' + kind.container +
              '`, REPLACING what is there.',
        example: {}
      };
      // A KIND WITH NAMED PROFILES (#535, the passkey policy) takes any
      // profile name and the selectors; the others have `default` only.
      const named = Array.isArray(module.SELECTORS);
      const profileSchema = named
        ? { type: 'string', pattern: '^(default|[a-z0-9][a-z0-9-]{0,63})$',
            description: 'Which profile: `default`, or a named profile ' +
                         '(lower-case letters, digits and hyphens), which ' +
                         'is created by its first save.' }
        : { type: 'string', enum: [module.DEFAULT_PROFILE],
            description: 'Which profile. Only `default` exists.' };
      const properties: Record<string, any> = {
        profile: profileSchema,
        description: { type: 'string',
                       description: 'What the profile is for, for the next ' +
                                    'person. Optional.' }
      };
      // Each selector the kind declares, and no other (#1235: a precedence;
      // what a profile covers names it).
      const selects = function (key: string): boolean {
        log.debug("Entering selects().");
        log.debug("Leaving selects().");
        return named && module.SELECTORS.some(function (one: any) {
          return one.key === key;
        });
      };
      if (selects('selectApplications')) {
        properties.selectApplications = {
          oneOf: [{ type: 'array', items: { type: 'string' } },
                  { type: 'string' }],
          description: 'A named profile only: the applications it applies ' +
                       'to (identifier or client_id), a list or comma-' +
                       'separated.' };
      }
      if (selects('selectGroups')) {
        properties.selectGroups = {
          oneOf: [{ type: 'array', items: { type: 'string' } },
                  { type: 'string' }],
          description: 'A named profile only: the groups (cn or DN) whose ' +
                       'members it applies to.' };
      }
      if (selects('precedence')) {
        properties.precedence = {
          oneOf: [{ type: 'integer', minimum: 1, maximum: 1000 },
                  { type: 'string' }],
          description: 'A named profile only: the lowest matching ' +
                       'precedence wins. Default 100.' };
      }
      module.FIELDS.forEach(function (field) {
        properties[field.key] = field.type === 'bool'
          ? { oneOf: [{ type: 'boolean' }, { type: 'string' }],
              description: field.what + ' (`true`/`false`, or `TRUE`/' +
                           '`FALSE` from a form.) Default ' + field.dflt +
                           '.' }
          : field.type === 'enum'
            ? { type: 'string', enum: field.values,
                description: field.what + ' Default `' + field.dflt + '`.' }
          : field.type === 'attributes' || field.type === 'text' ||
            field.type === 'clientRules'
            ? { type: 'string',
                description: field.what + ' Default empty.' }
          : field.type === 'attribute'
            ? { type: 'string',
                description: field.what + ' A directory attribute name, or ' +
                             'empty for none. Default empty.' }
          : field.type === 'locale'
            ? { type: 'string',
                description: field.what + ' Default `' + field.dflt + '`.' }
          : field.type === 'attributeList'
            ? { oneOf: [{ type: 'array', items: { type: 'string' } },
                        { type: 'string' }],
                description: field.what + ' Default `' + field.dflt + '`.' }
          : field.type === 'list'
            ? { type: 'string',
                description: field.what + ' An ordered, comma-separated ' +
                             'list of ' + (field.values || []).join(', ') +
                             ', or `none`. Default `' + field.dflt + '`.' }
            : { oneOf: [{ type: 'integer', minimum: field.min,
                          maximum: field.max },
                        { type: 'string' }],
                description: field.what + ' Between ' + field.min + ' and ' +
                             field.max + '. Default ' + field.dflt + '.' };
      });
      // A RETIRED FIELD STILL ACCEPTED (#1135): the post-login profile's
      // `noPasskeyRole` left `FIELDS` when a passkey lost its role, and a
      // body that still carries it — a caller written before, a vendored
      // test — would otherwise be refused by `additionalProperties: false`.
      // `PostLoginPolicy.validate()` reads `FIELDS` only, so it is ignored.
      if (kind.id === 'postLogin') {
        properties.noPasskeyRole = {
          type: 'string',
          description: 'Ignored since #1135: a passkey has no role, so a ' +
                       'person with none registers a passkey and nothing ' +
                       'else is asked. Accepted so that an older body is ' +
                       'not refused; not stored, not answered.' };
      }
      out.push({
        action: policyKinds.saveAction(kind),
        operationId: ('save' + cap(kind.id) + 'Policy') as SaveOrReset });
      out.push({
        action: policyKinds.resetAction(kind),
        operationId: ('reset' + cap(kind.id) + 'Policy') as SaveOrReset });
      // A KIND'S OWN ACTS (#396), described by the kind itself.
      (kind.extraActions || []).forEach(function (extra) {
        out.push({
          action: extra.action,
          operationId: extra.operationId
        });
      });
    });
    log.debug("Leaving AdminApi.policyKindActions(). " + out.length + ".");
    return out;
  }

  // --- the shared parameter descriptions
  // --------------------------------------
  //
  // Written once because three lists page identically, and because a caller
  // that has learned to walk one of them has learned to walk all three.
  //
  // The two numbers are `admin_views`' — they moved there from the console,
  // which never exported them, so until #70 this read both off `admin` and
  // the document said "maximum: undefined" and "Defaults to undefined".
  /**
   * Returns the `page` and `per` query parameters every paged list takes.
   *
   * @returns the two parameter objects
   */
  pagingParameters() {
    const { log, adminViews } = this.deps;
    log.debug("Entering AdminApi.pagingParameters().");
    log.debug("Leaving AdminApi.pagingParameters().");
    return [
      { name: 'page', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1, examples: [1] },
        description: 'Which page of the match to return. CLAMPED rather than ' +
                     'refused: a page past the end returns the last one, and ' +
                     'the reply says which page it actually is.' },
      { name: 'per', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1,
                  maximum: adminViews.MAX_ROWS, examples: [10] },
        description: 'Rows per page. Defaults to ' +
                     adminViews.DEFAULT_PER_PAGE + ' and is capped at ' +
                     adminViews.MAX_ROWS + '. On a ' +
                     'drill-down it is SHARED by every list in the reply, ' +
                     'which each carry a page number of their own.' }
    ];
  }

  // The page parameters of a DRILL-DOWN, which is a different shape from a list
  // and has to be, because a drill-down answers with several lists at once —
  // five on /users, two on /groups. One `page` would move all of them together,
  // so each gets a parameter named after itself and `per` above stays shared.
  //
  // Every one is clamped the way `page` is, and every one is answered: the
  // reply carries a `<name>Paging` object beside the array, with the same
  // member names the flat lists put at the top level. A caller walks these
  // exactly as it walks /tokens, one list at a time. ONE NAME PER LIST: the
  // parameter is the reply array's own name with `Page` on the end, and the
  // object answering it is that name with `Paging` on the end. A caller that
  // can read the reply can therefore write the request without a table mapping
  // one set of names onto the other.
  /**
   * Returns a drill-down's page parameters: `<name>Page` for each of its lists,
   * answered by `<name>Paging`.
   *
   * @param lists - the lists, each `{ name, description }`
   * @returns one parameter object per list
   */
  detailPagingParameters(lists) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.detailPagingParameters().");
    log.debug("Leaving AdminApi.detailPagingParameters().");
    return lists.map(function (list) {
      return { name: list.name + 'Page', in: 'query', required: false,
               schema: { type: 'integer', minimum: 1, examples: [1] },
               description: 'Which page of `' + list.name + '` to return, ' +
                            'answered by `' + list.name + 'Paging`. ' +
                            list.description };
    });
  }

  /**
   * Returns the action rows of one claim-set family (custom claims, SAML
   * attributes or UserInfo claims), from the family's parameters.
   *
   * @param family - `sets`, `noun`, `carrier`, `example`, `placeholder`
   *   (one that expands in this family), `reserved` and the operationIds
   *   in `ids`
   * @returns the action rows
   */
  claimSetActions<K extends keyof AdminOps>(family: {
    ids: Record<'add' | 'addAttribute' | 'remove' | 'clear' | 'replace' |
                'attributes' | 'all' | 'none', K>;
    [member: string]: any;
  }): Array<IyaApi.ActionOf<AdminOps, K>> {
    const { log } = this.deps;
    log.debug("Entering AdminApi.claimSetActions(). " + family.sets.length +
              " set(s).");
    const noun = family.noun;
    const setField = { type: 'string', enum: family.sets.slice() };
    const rows: Array<IyaApi.ActionOf<AdminOps, K>> = [
      { action: 'add', operationId: family.ids.add },
      { action: 'add-attribute-claim', operationId: family.ids.addAttribute },
      { action: 'remove', operationId: family.ids.remove },
      { action: 'clear', operationId: family.ids.clear },
      { action: 'replace', operationId: family.ids.replace },
      // --- the directory-attribute half of a set ----------------------------
      //
      // Three operations rather than one with a mode, mirroring the console's
      // three buttons, and the reason is in admin.js beside them: an empty
      // `attributes` array would otherwise be ambiguous between "clear it" and
      // "my HTTP client dropped an empty array", which is a real behaviour of
      // real clients and the kind of ambiguity that silently empties a set.
      { action: 'attributes', operationId: family.ids.attributes },
      { action: 'attributes-all', operationId: family.ids.all },
      { action: 'attributes-clear', operationId: family.ids.none }
    ];
    log.debug("Leaving AdminApi.claimSetActions(). " + rows.length +
              " action(s).");
    return rows;
  }

  // ---------------------------------------------------------------------------
  // THE TABLE. Express registration and the OpenAPI document are both built
  // from it, which is what makes them incapable of disagreeing.
  //
  // A row is either a plain operation (`path` + `handler`) or an action
  // resource (`route` with `:action` in it + `handler` + `actions`), where each
  // action is one documented operation at its own concrete URL.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // THE PROTOCOL SETTINGS PAGES, mirrored. Rule 7 wants an operation per
  // console page, and on 2026-08-27 eight pages arrived at once — one per
  // protocol family whose appconfig rows had no page of their own. TOTP,
  // WebAuthn, recovery codes, persistence and the cluster have joined them
  // since, so the table holds thirteen.
  //
  // THERE IS NO POST BESIDE ANY OF THEM, and that is the rule read exactly
  // rather than a gap. Every form on those pages posts `set-many` to
  // /admin/config, which `POST /admin-api/config/set-many` already mirrors, so
  // a POST here would be one more door per page onto one function — the thing
  // this parity exists to prevent. It is the same answer /admin-api/scim and
  // /admin-api/applications/new give, for the same reason.
  //
  // They are BUILT FROM A TABLE for the reason the console's own pages are: the
  // operations differ only in prose, and eight hand-written rows would have
  // been seven copies plus the one somebody edited. The generated OpenAPI
  // document cannot tell the difference — `admin_api_spec.ts` reads this array
  // and nothing else.
  // ---------------------------------------------------------------------------
  /**
   * Returns the read-only GET operations for the protocol pages' settings, one
   * per page, built from a table.
   *
   * @returns the operations
   */
  buildProtocolSettingsOperations(): any[] {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering AdminApi.buildProtocolSettingsOperations().");
    // `as const`, so each row's operationId is the model's (#1579): the
    // handler below is typed by the union of the thirteen.
    const SETTINGS_PAGES = ([
      { path: '/oauth2', console: '/admin/oauth2', tag: 'OAuth 2.0 / OIDC',
        operationId: 'getOauth2Settings' },
      { path: '/oid4vci-settings', console: '/admin/vc',
        settingsPage: '/admin/oid4vci', tag: 'OpenID4VCI',
        operationId: 'getOid4vciSettings' },
      { path: '/oid4vp-settings', console: '/admin/vc',
        settingsPage: '/admin/oid4vp', tag: 'OpenID4VP',
        operationId: 'getOid4vpSettings' },
      // THE TWO SECOND FACTORS (2026-09-10). Rule 7: `/admin/totp` and
      // `/admin/webauthn` arrived on the console and owe an operation in the
      // same change. Both replies carry the page's `status` block — the
      // MECHANISM, read from the module that performs it — beside the settings,
      // which is why they are worth fetching rather than reading `GET /config`.
      { path: '/totp', console: '/admin/totp', tag: 'TOTP MFA',
        operationId: 'getTotpSettings' },
      // THE THIRD MECHANISM (2026-09-10). Rule 7 again: `/admin/backup-codes`
      // arrived on the console and owes an operation in the same change.
      { path: '/backup-codes', console: '/admin/backup-codes',
        tag: 'Recovery codes', operationId: 'getBackupCodesSettings' },
      { path: '/webauthn', console: '/admin/webauthn', tag: 'WebAuthn',
        operationId: 'getWebauthnSettings' },
      { path: '/kerberos', console: '/admin/kerberos', tag: 'Kerberos',
        operationId: 'getKerberosSettings' },
      { path: '/ldap', console: '/admin/ldap', tag: 'LDAP',
        operationId: 'getLdapSettings' },
      // The newest of these, 2026-08-27, and the only one whose reply carries a
      // `status` member: a persistence setting that is SET and a persistence
      // store that is WORKING are two different facts, and the gap between them
      // is the whole failure mode this feature has. See admin.js's
      // persistenceStatusBlock().
      { path: '/persistence', console: '/admin/persistence', tag: 'Persistence',
        operationId: 'getPersistenceSettings' },
      // THE CLUSTER (2026-09-14, #46). Like `/persistence`, a `status` member
      // beside the settings, because `cluster.mode` SET and a cluster WORKING
      // are two facts. See admin.js's clusterStatusBlock().
      { path: '/cluster', console: '/admin/cluster', tag: 'Cluster',
        operationId: 'getClusterSettings' },
      { path: '/wstrust', console: '/admin/wstrust', tag: 'WS-Trust',
        operationId: 'getWsTrustSettings' },
      { path: '/wsfed', console: '/admin/wsfed', tag: 'WS-Federation',
        operationId: 'getWsFedSettings' },
      { path: '/tls', console: '/admin/tls', tag: 'TLS',
        operationId: 'getTlsSettings' }
    ] as const);
    type SettingsId = (typeof SETTINGS_PAGES)[number]['operationId'];
    const PROTOCOL_SETTINGS_OPERATIONS: AdminRow[] = SETTINGS_PAGES.map(
      function (row: {
        path: string;
        console: string;
        tag: string;
        operationId: SettingsId;
        settingsPage?: string;
      }): AdminRow {
      return { method: 'GET', path: BASE + row.path, tag: row.tag,
               operationId: row.operationId,
               mirrors: 'GET ' + row.console,
               handler: function (
                 req: IyaApi.RequestTo<AdminOps[SettingsId]>,
                 res: IyaApi.Answering<AdminOps[SettingsId]>) {
                 log.debug("Entering the management API " + row.console + " " +
                     "endpoint.");
                 // Through the row's `prepare` step, which the Cluster page
                 // has (#361): the same answer the console draws.
                 admin.preparedSettingsJsonFor(
                   row.settingsPage || row.console).then(
                   function (json) {
                     self.sendJson(res, 200, json);
                     log.debug("Leaving the management API " + row.console +
                               " endpoint.");
                   });
               } };
    });
    log.debug("Leaving AdminApi.buildProtocolSettingsOperations().");
    return PROTOCOL_SETTINGS_OPERATIONS;
  }

  // ---------------------------------------------------------------------------
  // THE REQUEST SCHEMA OF A NARROW DOOR, BUILT FROM THE LIST THAT DOOR ACTUALLY
  // REFUSES AGAINST.
  //
  // `/token-lifetimes/set` and `/saml-assertions/set` exist to give a caller
  // one refusal the wide `/config/set-many` cannot: a key outside their own
  // list is refused BY NAME rather than ignored. That makes the list
  // load-bearing in the document — a caller reads it to know what may be sent —
  // and it was written out here BY HAND beside a list held in admin.js. Both
  // had drifted: this document named four token-lifetime settings against six,
  // and THREE assertion settings against sixteen. So it is derived, the way
  // every operation in this file is derived from the table that registers it.
  //
  // The TYPE comes from config.js's own row for the setting, so a boolean does
  // not arrive in the document as an integer.
  /**
   * Returns the request-body properties of a narrow settings door, built from
   * `config.js`'s row for each key (type, label, and enum set).
   *
   * @param keys - the setting keys the door accepts
   * @returns the properties object
   */
  narrowDoorProperties(keys) {
    const { log, config } = this.deps;
    log.debug("Entering AdminApi.narrowDoorProperties(). " + keys.length +
              " key(s).");
    const out = {};
    const byKey = {};
    config.SETTINGS.forEach(function (setting) {
      byKey[setting.key] = setting;
    });
    keys.forEach(function (key) {
      const setting = byKey[key] || {};
      const type = setting.type === 'bool' ? 'boolean'
          : (setting.type === 'int' ? 'integer' : 'string');
      out[key] = { type: type, description: setting.label || '' };
      // An `enum` row's set, published (#86). These doors own their body
      // and `config.js` refuses a value outside it by name; the document
      // says what that set is, and the console register holds the forms
      // that post these keys to it.
      if (setting.type === 'enum' && Array.isArray(setting.enumValues)) {
        out[key].enum = setting.enumValues.slice();
      }
    });
    log.debug("Leaving AdminApi.narrowDoorProperties().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE ATTRIBUTES SCOPED TO A PROTOCOL FAMILY, AS A SENTENCE, GENERATED.
  //
  // One row in `applications.SCHEMA` carries `families` today and the rule it
  // declares is the only refusal in this registry that is about WHICH
  // application rather than about which attribute — so a caller reading this
  // document to learn what it may send has to be told, or it discovers the rule
  // by being refused.
  //
  // GENERATED FROM THE SCHEMA AND NOT TYPED, for the reason the `set` and `add`
  // descriptions above are: a hand-written list of what an operation accepts is
  // a second definition of a table, and it goes wrong silently in exactly the
  // document a caller trusts most. It answers with the empty string when
  // nothing is family-scoped, so removing the last such row removes the
  // paragraph.
  /**
   * Returns the paragraph naming the application attributes scoped to a
   * protocol family, generated from `applications.SCHEMA`.
   *
   * @returns the paragraph, or the empty string when none is family-scoped
   */
  familyScopeNote() {
    const { log, applications } = this.deps;
    log.debug("Entering AdminApi.familyScopeNote().");
    const scoped = applications.SCHEMA.attributes.filter(function (row) {
      return row.editable && row.families && row.families.length;
    });
    if (!scoped.length) {
      log.debug("Leaving AdminApi.familyScopeNote(). Nothing is " +
                "family-scoped.");
      return '';
    }
    const listed = scoped.map(function (row) {
      const labels = row.families.map(function (id) {
        const family = applications.PROTOCOLS.filter(function (one) {
          return one.id === id;
        })[0];
        return family ? family.label : id;
      });
      return '`' + row.name + '` (' + labels.join(', ') + ')';
    }).join(', ');
    log.debug("Leaving AdminApi.familyScopeNote(). " + scoped.length +
              " attribute(s).");
    return '**' + (scoped.length === 1 ? 'One attribute is' : scoped.length +
           ' attributes are') + ' scoped to a PROTOCOL FAMILY and REFUSED on ' +
           'an application declared for none of ' +
           'them: ' + listed + '.** That is ' +
           'unlike every other attribute here, which is inert rather than ' +
           'wrong on an entry that never reaches the protocol it belongs to ' +
           '— these decide what an ENDPOINT does for an identifier, so on an ' +
           'entry no request could ever name they would read as a policy ' +
           'that was in force. Declare the family first (`protocols` on the ' +
           'create, or add to `appAllowedProtocol`). ' +
           'Clearing one is never refused, ' +
           'and `ldapmodify` reaches them like every other attribute.\n\n';
  }

  // ---------------------------------------------------------------------------
  // THE CLOSED SETS THE ROUTE TABLE DECLARES THAT LIVE IN ANOTHER MODULE'S
  // TABLE (#86). Read once per build of the table, from the constant the
  // handler checks against, never retyped: a set retyped here is a second
  // definition, and the #86 audit found three that had gone stale (the
  // application `kind` filter missing three kinds, `revoke-kind` missing
  // `gnap_access_token`, `add-value` missing two multi-valued fields).
  // ---------------------------------------------------------------------------
  /**
   * Returns the closed sets the route table declares that are held in other
   * modules' tables, read from those tables once per build.
   *
   * @returns the sets, keyed by name
   */
  closedLists() {
    const { log, riskDatasets, mailTemplates, identityAssurance, federation,
            applications, stats, audit, delegation, usedAssertions,
            issuanceGate, countryCodes, xacmlModel, pki } = this.deps;
    log.debug("Entering AdminApi.closedLists().");
    const namesOf = function (rows) {
      return rows.map(function (row) {
        return row.name;
      });
    };
    const kinds = [];
    stats.ISSUED_FAMILIES.forEach(function (family) {
      family.kinds.forEach(function (kind) {
        if (kinds.indexOf(kind) < 0) {
          kinds.push(kind);
        }
      });
    });
    const keyAlgs = pki.keyAlgorithms().map(function (one) {
      return one.id;
    });
    const sigAlgs = [];
    keyAlgs.forEach(function (id) {
      pki.signatureAlgorithms(id).forEach(function (one) {
        if (sigAlgs.indexOf(one.id) < 0) {
          sigAlgs.push(one.id);
        }
      });
    });
    const out = {
      // Only a provider this build can import from: an unsupported one's
      // terms cannot be accepted and nothing can be loaded as it.
      riskProviders: Object.keys(riskDatasets.PROVIDERS).filter(function (id) {
        return riskDatasets.PROVIDERS[id].supported !== false;
      }),
      riskDatasets: Object.keys(riskDatasets.CATALOGUE),
      riskFormats: Object.keys(riskDatasets.FORMATS),
      mailTemplates: mailTemplates.BUILT_IN.map(function (one) {
        return one.id;
      }),
      verifiableClaims: identityAssurance.VERIFIABLE_CLAIMS.slice(),
      federationSetFields: namesOf(federation.editableFields('set')),
      federationMultiFields: namesOf(federation.editableFields('multi')),
      applicationKinds: applications.KIND_IDS.slice(),
      tokenFamilies: stats.ISSUED_FAMILIES.map(function (family) {
        return family.family;
      }),
      tokenKinds: kinds,
      revocableKinds: stats.REVOCABLE_KINDS.slice(),
      applicationSetAttributes: namesOf(applications.editableAttributes('set')),
      applicationMultiAttributes:
        namesOf(applications.editableAttributes('multi')),
      // A key the handler will refuse later for having no signature
      // algorithm (an ML-KEM one) is still a key algorithm; that refusal
      // is the handler's, and names why.
      pkiKeyAlgorithms: keyAlgs,
      pkiSignatureAlgorithms: sigAlgs,
      // A CA's alternative (post-quantum) key, #68: `pki.alternativeKeyAlgs()`
      // and `none` for a classical-only authority — alternativeKeyAlgFrom()'s
      // own set.
      pkiAlternativeKeyAlgorithms: pki.alternativeKeyAlgs().concat('none'),
      pkiUseCases: pki.USE_CASE_IDS.slice(),
      pkiImportUseCases: ['root'].concat(pki.USE_CASE_IDS),
      countries: countryCodes.ALPHA2.slice(),
      auditCategories: audit.CATEGORIES.map(function (one) {
        return one.category;
      }),
      auditActions: audit.ACTIONS.map(function (one) {
        return one.action;
      }),
      auditOutcomes: audit.OUTCOMES.slice(),
      usedAssertionFormats: Object.keys(usedAssertions.FORMATS),
      usedAssertionUses: Object.keys(usedAssertions.USES),
      usedAssertionStates: Object.keys(usedAssertions.STATES),
      delegationTypes: delegation.TYPES.map(function (one) {
        return one.type;
      }),
      delegationModes: delegation.MODES.map(function (one) {
        return one.mode;
      }),
      delegationOutcomes: delegation.OUTCOMES.slice(),
      issuanceKinds: issuanceGate.KINDS.slice(),
      xacmlEffects: Object.keys(xacmlModel.EFFECT).map(function (key) {
        return xacmlModel.EFFECT[key];
      }),
      // CAEP 1.0 section 2's `initiating_entity`, the four values it
      // defines. `ssf/ssf_events.js` writes the same four into its event
      // table (not exported); `tests/closed_sets.js` holds the two equal.
      caepInitiatingEntities: ['admin', 'user', 'policy', 'system']
    };
    log.debug("Leaving AdminApi.closedLists().");
    return out;
  }

  /**
   * Builds the route table: every operation of this API, including the rows the
   * family modules declare.
   *
   * @returns the table
   */
  buildRoutes(): any[] {
    const { log, baseUrlOf, config, spec, adminViews, errorCodes,
            encryptionAdmin, databaseAdmin, secretsAdmin, debuggerAdmin,
            cachesAdmin, parseBody, loadApiExplorer, admin, adminActions, rbac, helpers,
            realms, stats, resourceMetadata, applications, loadGnapConsole, pki,
            pkiAdmin, certificateViews, passwordPolicy, loadAcmeApi, loadEstApi,
            loadScepApi, loadOidfedApi, loadOauth2MonitorApi,
            loadGrantManagementApi, loadClaimsProvidersApi,
            loadAttributeSourcesApi, loadSecretDestinationsApi, loadAuthzenApi,
            loadUmaApi,
            loadPasskeyReportApi, loadPostLoginActivitiesApi,
            loadAuditExportApi, loadBrandingApi,
            loadScimClientsApi,
            loadProviderCommandsApi, loadSsfTransmittersApi,
            federation } = this.deps;
    const self = this;
    log.debug("Entering AdminApi.buildRoutes().");
    const closed = this.closedLists();
    // THE DELEGATION FILTER, declared once: the acts (`/delegation`) and
    // the picture of them (`/delegation/map`, #446) take the same five
    // parameters, as the two console pages do.
    // THE DELEGATION PAGES' ONE SHARED QUERY (#1476). Every view of that
    // family is built by `AdminViews` over one query (`delegationPageModel()`
    // and the models that call it), and the console carries a reader's
    // searches, offsets and pages from one view to the next so a drill-down
    // comes back to the page it left. These were read and never declared.
    // `withDelegationQuery()`, below the table, adds them to each row.
    const delegationPageQuery: any[] = ([
      ['permq', 'Part of a permission\'s resource.'],
      ['grantq', 'Part of a grant\'s client or resource.'],
      ['appq', 'The application chooser\'s search.'],
      ['userq', 'The person chooser\'s search.']
    ] as string[][]).map(function (row) {
      return { name: row[0], in: 'query', required: false,
               schema: { type: 'string' } as any, description: row[1] };
    }).concat(([
      ['appfrom', 'Where the application chooser\'s page starts.'],
      ['userfrom', 'Where the person chooser\'s page starts.']
    ] as string[][]).map(function (row) {
      return { name: row[0], in: 'query', required: false,
               schema: { type: 'integer', minimum: 0 } as any,
               description: row[1] };
    })).concat(([
      'chains', 'permissions', 'grants', 'pairs', 'flags', 'mechanisms',
      'policyPairs', 'intermediaries', 'people', 'groups', 'groupGrants',
      'groupPermissions'
    ] as string[]).map(function (name) {
      return { name: name + 'Page', in: 'query', required: false,
               schema: { type: 'integer', minimum: 1 } as any,
               description: 'Which page of `' + name + '` to return, ' +
                            'clamped as `page` is.' };
    }) as any[]);
    const delegationFilter: any[] = [
      { name: 'type', in: 'query', required: false,
        schema: { type: 'string',
                  enum: closed.delegationTypes },
        description: 'One mechanism. The reply\'s `types` member ' +
                     'describes each of them, with the specification it ' +
                     'comes from and whether this service polices it.' },
      { name: 'mode', in: 'query', required: false,
        schema: { type: 'string', enum: closed.delegationModes },
        description: 'The protocol-independent axis: whether what came ' +
                     'out carries the chain. ' +
                     'ANDed with `type`, so a mode ' +
                     'that does not match the mechanism matches nothing.' },
      { name: 'outcome', in: 'query', required: false,
        schema: { type: 'string', enum: closed.delegationOutcomes },
        description: 'Two rather than the audit log\'s three: a ' +
                     'delegation is DECIDED rather than ' +
                     'performed, so there is no third ' +
                     'answer between issuing the credential and refusing ' +
                     'to.' },
      { name: 'protocol', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'The family, spelled as /admin-api/users spells it ' +
                     '— `Kerberos v5`, `WS-Trust`, `OAuth 2.0`. Free ' +
                     'text rather than an enum, for the reason the audit ' +
                     'log\'s `protocol` is.' },
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of ANY party of the chain (normalised ' +
                     'name, presented form or application) or of either ' +
                     'explanation, case-insensitive. One box over six ' +
                     'fields, because the fact a caller has names one of ' +
                     'them and not which column it is in.' }
    ];
    const withDelegationQuery = function (own: any[]): any[] {
      log.debug("Entering withDelegationQuery().");
      const seen: Record<string, boolean> = {};
      const out = own.concat(delegationFilter, self.pagingParameters(),
                             delegationPageQuery).filter(function (one) {
        if (seen[one.name]) {
          return false;
        }
        seen[one.name] = true;
        return true;
      });
      log.debug("Leaving withDelegationQuery().");
      return out;
    };
    const ROUTES: AdminRow[] = [
      { method: 'GET', path: BASE, tag: 'Service',
        operationId: 'getIndex',
        mirrors: 'GET /admin',
        handler: function (req, res) {
          log.debug("Entering the management API index.");
          const base = baseUrlOf(req);
          self.sendJson(res, 200, {
            name: 'IYA STS management API',
            version: VERSION,
            // WHICH BUILD THIS IS, BROKEN OUT (#1298, #1317). `version` is
            // M.N.O.<build>; `build` is the build number on its own (the UTC
            // build instant, or a release build's own) and `release` whether
            // the build was flagged as a release — version.json's own names
            // for both, so a check can compare the two member by member.
            // A test asserting "this stack is running the build it just made"
            // wants the number and the instant on their own, and a report
            // saying which commit an instance is on wants the commit — so each
            // is a field rather than something a client writes a regular
            // expression for. `build` is absent on a stamp a #1298 build
            // wrote, whose version is the bare release.
            //
            // `stamped` is the one that is easy to leave out and worth most:
            // false means this process computed its own record at startup
            // because nothing stamped an artifact, so `builtAt` is the moment
            // it STARTED and comparing it with another instance's says
            // nothing.
            build: APP_VERSION.build || undefined,
            release: APP_VERSION.release === true,
            commit: APP_VERSION.commit || undefined,
            builtAt: APP_VERSION.builtAt,
            stamped: APP_VERSION.stamped === true,
            openapi: base + BASE + '/openapi.json',
            // ------------------------------------------------------------
            // **READ FROM THE SETTING SINCE 2026-09-10; IT WAS THE LITERAL
            // `false`.** This API began requiring an access token on
            // 2026-09-09 and this field went on saying it did not — which a
            // caller could only ever read by presenting the credential the
            // field denied needing. The startup banner had the same bug and
            // was fixed the same day; this one and the OpenAPI document were
            // missed, and `admin_api_spec.ts`'s own header argues why that
            // matters more for the document than for either sentence.
            // ------------------------------------------------------------
            // The value IN FORCE (#446): product ignores `false`.
            protected: self.tokenRequired(),
            // THE EXPLORER IS A CONSOLE PAGE SINCE 2026-09-09 and this field
            // still names it, because a client that read it wants to know
            // where the explorer IS rather than which path space it is in.
            // It moved when this API began requiring a token a browser has
            // no way to carry.
            docs: helpers.rebaseTo(base, 'admin-console') +
                  '/admin/api-explorer',
            console: helpers.rebaseTo(base, 'admin-console') + '/admin',
            operations: self.operationSummaries()
          });
          log.debug("Leaving the management API index.");
        } },

      // THE SERVICE METADATA PAGE (#446): what `/admin/sts-metadata` is
      // drawn from. LAZILY REQUIRED, like the explorer: `sts_metadata.ts` is
      // built last of all because it reads the router, so a require of it
      // here at load would run before the routes it lists exist.
      { method: 'GET', path: BASE + '/sts-metadata', tag: 'Service',
        operationId: 'getStsMetadata',
        mirrors: 'GET /admin/sts-metadata',
        handler: function (req, res) {
          log.debug("Entering the management API metadata endpoint.");
          self.sendJson(res, 200,
                        require('../sts_metadata').pageJson(baseUrlOf(req)));
          log.debug("Leaving the management API metadata endpoint.");
        } },

      { method: 'GET', path: BASE + '/openapi.json', tag: 'Service',
        operationId: 'getOpenApi',
        mirrors: 'GET /admin/sts-metadata',
        handler: function (req, res) {
          log.debug("Entering the OpenAPI document endpoint.");
          // THE MANAGEMENT OPERATIONS ALONE (#454): the console's own are
          // described by `GET /admin-api/console/openapi.json`, so what an
          // integrator reads here is what they can rely on.
          self.sendJson(res, 200,
                        spec.buildSpec(self.routesOfKind('management'),
                                       self.specOptions(req)));
          log.debug("Leaving the OpenAPI document endpoint.");
        } },

      // ---------------------------------------------------------------------
      // THE CRYPTO REPORT. It calls `adminViews.cryptoView()` and computes
      // nothing of its own, which is rule 7 read strictly: the page and this
      // operation must not be able to disagree about what this service's
      // cryptography is, and the way to make that impossible is for there to be
      // one function.
      //
      // It answers 503 rather than 404 when the reporter was never installed —
      // which happens only if `admin-ui/crypto_metadata.ts` was not required —
      // and the two are different facts: a route that exists and cannot answer
      // is a wiring mistake somebody can fix, and a route that does not exist
      // is not. The message names the module rather than saying "unavailable".
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/crypto', tag: 'Service',
        operationId: 'getCryptoMetadata',
        mirrors: 'GET /admin/crypto-metadata',
        handler: function (req, res) {
          log.debug("Entering the management API crypto metadata endpoint.");
          const report = adminViews.cryptoView(req);
          if (!report) {
            errorCodes.mark(res, 'STS-API-0011');
            self.sendJson(res, 503, { ok: false, errors: [
              'The crypto report is not installed in this process. ' +
              'admin-ui/crypto_metadata.ts fills it at its own require time, ' +
              'and server.js requires that module after tls/tls_server. This ' +
              'is a 503 and not a 404 because the route exists — what is ' +
              'missing is the module behind it.'] });
            log.debug("Leaving the management API crypto metadata endpoint. " +
                      "No reporter.");
            return;
          }
          self.sendJson(res, 200, report);
          log.debug("Leaving the management API crypto metadata endpoint.");
        } },

      // ---------------------------------------------------------------------
      // THE ENCRYPTION REPORT. `encryptionAdmin.encryptionView()` and nothing
      // of its own, which is rule 7 read the same strict way the crypto report
      // above it is: the console page and this operation must not be able to
      // report different NUMBERS for the same counters, and one function is the
      // only way to make that impossible.
      //
      // **IT NEEDS NO 503 BRANCH, unlike the operation above it**, and the
      // difference is worth stating rather than looking like an omission: that
      // one reaches its reporter across an inverted hook that a process may not
      // have filled, and this one reaches a module it requires directly. There
      // is no state in which the route exists and the function does not.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/encryption', tag: 'Service',
        operationId: 'getEncryption',
        mirrors: 'GET /admin/encryption',
        // THE DATA ENCRYPTION KEYS (#391 P2) are one paged list of the reply,
        // `dataKeys.keys`, moved by `dataKeysPage` — ids, realms, classes and
        // states, never a key.
        parameters: [
          { name: 'dataKeysPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of `dataKeys.keys` to return, clamped ' +
                         'as every page is; `dataKeys.paging` says which ' +
                         'page it is.' }
        ].concat(this.pagingParameters().filter(function (one) {
          return one.name === 'per';
        })),
        handler: function (req, res) {
          log.debug("Entering the management API encryption report endpoint.");
          self.sendJson(res, 200,
                        encryptionAdmin.encryptionView(req.query || {}));
          log.debug("Leaving the management API encryption report endpoint.");
        } },

      // THE DATA-KEY ACTS (#391 P2, P5): `/admin/encryption/data-keys`'s
      // four forms, through the one function they post to. Each QUEUES a run of
      // `common/data_key_rotation.ts`'s jobs and answers 202.
      ApiRows.actions({ method: 'POST',
        route: BASE + '/encryption/:action', tag: 'Service',
        mirrors: 'POST /admin/encryption/data-keys',
        handler: function (req, res) {
          log.debug("Entering the management API data-key endpoint.");
          const body = self.withAction(req, parseBody(req));
          const result = encryptionAdmin.dataKeysAction(
            req, body, 'the management API at /admin-api/encryption/' +
            body.action);
          if (!result.ok) {
            errorCodes.mark(res, result.errorCode || 'STS-API-0014');
            self.sendJson(res, result.status || 400,
                          { ok: false, errors: result.errors });
            log.debug("Leaving the management API data-key endpoint. " +
                      "Refused.");
            return;
          }
          self.sendJson(res, 202, { ok: true, accepted: true,
            runId: result.runId, message: result.message,
            run: BASE + '/scheduler?run=' + encodeURIComponent(result.runId) });
          log.debug("Leaving the management API data-key endpoint. Queued " +
                    result.runId + ".");
        },
        actions: [
          { action: 'rotate-data-keys', operationId: 'rotateDataKeys' },
          { action: 'reencrypt-data-keys',
            operationId: 'reencryptDataKeys' },
          { action: 'count-data-keys', operationId: 'countDataKeys' },
          { action: 'rotate-kek', operationId: 'rotateKek' }
        ] }),

      // ---------------------------------------------------------------------
      // CELLS (#98). `cellsAdmin.cellsView()` — the function `/admin/cells`
      // draws — and `peopleOf()`, another cell's residents under its release
      // policy. Neither changes anything; the Cells settings are written
      // through `POST /admin-api/config/set`. A call naming `?cell=` on any
      // operation is relayed to that cell whole (common/cell_placement.ts).
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/cells', tag: 'Service',
        operationId: 'getCells',
        mirrors: 'GET /admin/cells',
        // THE PAGE'S DRILL-DOWN TOO (#446): with `people`, the answer also
        // carries that cell's residents as `people` — what
        // `GET /admin-api/cells/people` answers — so the page is drawn from
        // one answer, as the console's own JSON always was.
        parameters: [
          { name: 'people', in: 'query', required: false,
            schema: { type: 'string', examples: ['cell-a'] },
            description: 'A cell whose residents to list, under its release ' +
                         'policy.' },
          { name: 'after', in: 'query', required: false,
            schema: { type: 'string', examples: ['alice'] },
            description: 'With `people`: the last name of the previous ' +
                         'page.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API cells endpoint.");
          cellsAdmin.cellsPageView(req.query).then(function (view) {
            self.sendJson(res, 200, view);
            log.debug("Leaving the management API cells endpoint.");
          }, function (e) {
            log.debug("Caught in the management API cells endpoint: " +
                      ((e && e.message) || e));
            const code = errorCodes.codeOf(e);
            if (code === 'STS-LDAP-0130' || code === 'STS-LDAP-0131' ||
                code === 'STS-LDAP-0139' || code === 'STS-LDAP-0175') {
              log.error(errorCodes.tag(code) +
                        'admin-api: the cells page could not be read from ' +
                        'the store: ' + ((e && e.message) || e));
              res.setHeader('Retry-After', '5');
              // STS-LDAP-0130, STS-LDAP-0131, STS-LDAP-0139, STS-LDAP-0175.
              errorCodes.mark(res, code);
              self.sendJson(res, 503, { error: 'temporarily_unavailable',
                error_description: 'The directory could not be read; try ' +
                  'again shortly.' });
              log.debug("Leaving the management API cells endpoint. " +
                        "Unavailable.");
              return;
            }
            errorCodes.mark(res, 'STS-CELL-0191');
            self.sendJson(res, 500, { error: 'server_error',
                                      error_description: String(
                                        (e && e.message) || e) });
          });
        } },
      { method: 'GET', path: BASE + '/cells/people', tag: 'Service',
        operationId: 'getCellPeople',
        mirrors: 'GET /admin/cells?people=',
        parameters: [
          { name: 'cell', in: 'query', required: true,
            schema: { type: 'string', minLength: 1, maxLength: 16,
                      examples: ['cell-a'] },
            description: 'The other cell\'s id.' },
          { name: 'after', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256, examples: ['alice'] },
            description: 'The last login name of the previous page.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API cell people endpoint.");
          // The cell that relayed this call here, when it did (`?cell=`
          // naming this one, D11): this cell then answers its own residents.
          cellsAdmin.peopleOf(String((req.query && req.query.cell) || ''),
                              String((req.query && req.query.after) || ''),
                              String((req.stsCellRelay &&
                                      req.stsCellRelay.from) || ''))
            .then(function (view) {
              self.sendJson(res, 200, view);
              log.debug("Leaving the management API cell people endpoint.");
            }, function (e) {
              log.debug("Caught in the management API cell people " +
                        "endpoint: " + ((e && e.message) || e));
              const code = errorCodes.codeOf(e);
              if (code === 'STS-LDAP-0130' || code === 'STS-LDAP-0131' ||
                  code === 'STS-LDAP-0139' || code === 'STS-LDAP-0175') {
                log.error(errorCodes.tag(code) +
                          'admin-api: a cell\'s residents could not be ' +
                          'read from the store: ' + ((e && e.message) || e));
                res.setHeader('Retry-After', '5');
                // STS-LDAP-0130, STS-LDAP-0131, STS-LDAP-0139,
                // STS-LDAP-0175.
                errorCodes.mark(res, code);
                self.sendJson(res, 503, { error: 'temporarily_unavailable',
                  error_description: 'The directory could not be read; ' +
                    'try again shortly.' });
                log.debug("Leaving the management API cell people " +
                          "endpoint. Unavailable.");
                return;
              }
              errorCodes.mark(res, 'STS-CELL-0191');
              self.sendJson(res, 500, { error: 'server_error',
                                        error_description: String(
                                          (e && e.message) || e) });
              log.debug("Leaving the management API cell people endpoint.");
            });
        } },

      // AN ACTION RESOURCE RATHER THAN A BARE POST (2026-09-28), for
      // `/keys/:action`'s reason: `sts_admin_api_operations.js` probes every
      // POST resource with an action nobody has heard of and requires a 400
      // naming the ones that exist, and a literal `/cells/rehome` answered
      // Express's 404. One action today.
      ApiRows.actions({ method: 'POST',
        route: BASE + '/cells/:action', tag: 'Service',
        mirrors: 'POST /admin/cells (action=rehome)',
        handler: function (req, res) {
          log.debug("Entering the management API rehome endpoint.");
          const body = self.withAction(req, parseBody(req));
          if (body.action !== 'rehome') {
            // The sentence the suite reads — `/keys/:action`'s shape.
            errorCodes.mark(res, 'STS-API-0014');
            self.sendJson(res, 400, { ok: false, errors: [
              'Unknown action "' + body.action + '". The actions here are: ' +
              'rehome.'] });
            log.debug("Leaving the management API rehome endpoint. " +
                      "Unknown action.");
            return;
          }
          cellsAdmin.rehomeAction(String((body && body.username) || ''),
                                  String((body && body.target) || ''),
                                  'the management API')
            .then(function (result) {
              if (!result.ok) {
                // The refusal's own code, from cell_rehome.ts.
                errorCodes.mark(res, errorCodes.codeOf(result) ||
                                     'STS-CELL-0192');
                self.sendJson(res, 400, result);
                log.debug("Leaving the management API rehome endpoint. " +
                          "Refused.");
                return;
              }
              self.sendJson(res, 200, result);
              log.debug("Leaving the management API rehome endpoint.");
            }, function (e) {
              log.debug("Caught in the management API rehome endpoint: " +
                        ((e && e.message) || e));
              errorCodes.mark(res, 'STS-CELL-0192');
              self.sendJson(res, 500, { ok: false, errors: [String(
                (e && e.message) || e)] });
            });
        },
        actions: [
          { action: 'rehome', operationId: 'rehomePerson' }
        ] }),

      // ---------------------------------------------------------------------
      // BROADCAST AN ANNOUNCEMENT (#1086): Server configuration → Broadcast
      // Announcement, and its rule 7 twin. The view says who may reach what
      // — a realm administrator their realm, a service administrator in the
      // default realm every realm as well — and the action is
      // `ssf.broadcastAnnouncement()`, the one place an announcement is
      // built and sent. Both reach `ssf/` LAZILY, at request time: a require
      // from here when this file loads would load the family out of the
      // require order.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/broadcast', tag: 'Shared Signals',
        operationId: 'getBroadcast',
        mirrors: 'GET /admin/broadcast',
        handler: function (req, res) {
          log.debug("Entering the management API broadcast endpoint.");
          self.sendJson(res, 200, self.broadcastView(req));
          log.debug("Leaving the management API broadcast endpoint.");
        } },

      ApiRows.actions({ method: 'POST', route: BASE + '/broadcast/:action',
        tag: 'Shared Signals',
        mirrors: 'POST /admin/broadcast',
        handler: function (req, res) {
          log.debug("Entering the management API broadcast action.");
          const body = self.withAction(req, parseBody(req));
          const refuse = function (errors) {
            errorCodes.mark(res, 'STS-SSF-0153');
            self.sendJson(res, 400, { ok: false, errors: errors });
          };
          if (String(body.action || '') !== 'send') {
            refuse(['Unknown action "' + String(body.action || '') +
                    '". The one is: send.']);
            log.debug("Leaving the management API broadcast action. " +
                      "Unknown action.");
            return;
          }
          const view = self.broadcastView(req);
          const everyRealm = ['true', 'on', 'yes', '1', 'every']
            .indexOf(String(body.everyRealm || body.scope || '')
              .toLowerCase()) >= 0 || body.everyRealm === true;
          if (everyRealm && !view.everyRealm) {
            refuse(['Only a service administrator in the default realm ' +
                    'may broadcast to every realm; this goes to the "' +
                    view.realm + '" realm only.']);
            log.debug("Leaving the management API broadcast action. Not " +
                      "every realm.");
            return;
          }
          const surfaces = [].concat(body.surfaces == null ? []
                                                           : body.surfaces)
            .reduce(function (all, one) {
              return all.concat(String(one).split(',').map(function (x) {
                return x.trim();
              }));
            }, []);
          let state = null;
          try {
            state = adminViews.gateStateFor(req);
          } catch (e) {
            log.debug("Caught in the management API broadcast action: " +
                      ((e && e.message) || e));
            // No gate state to read: the audit row names the door instead.
            state = null;
          }
          require('../ssf/ssf').broadcastAnnouncement({
            message: body.message, surfaces: surfaces,
            everyRealm: everyRealm,
            by: (state && state.username) ||
                'the management API at /admin-api/broadcast'
          }).then(function (result) {
            if (!result.ok) {
              errorCodes.mark(res, errorCodes.codeOf(result) ||
                                   'STS-SSF-0153');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API broadcast action.");
          });
        },
        actions: [
          { action: 'send', operationId: 'sendBroadcast' }
        ] }),

      // The console's own open tabs ask this every ssf.announcementPollMs.
      { method: 'GET', path: BASE + '/announcements', tag: 'Shared Signals',
        operationId: 'getConsoleAnnouncements',
        mirrors: 'no console page — the announcement banner every console ' +
                 'page draws, fed by POST /admin/broadcast (#1086)',
        parameters: [
          { name: 'since', in: 'query', required: false,
            schema: { type: 'integer', minimum: 0, examples: [0] },
            description: 'The `now` of the first answer, in milliseconds.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API announcements endpoint.");
          self.sendJson(res, 200, require('../ssf/ssf_receivers')
            .announcementsFor('admin-console', Number(req.query.since) || 0));
          log.debug("Leaving the management API announcements endpoint.");
        } },

      // ---------------------------------------------------------------------
      // THE MODE (#181). `modeAdmin.modeView()` — `common/mode.js`'s
      // `report()` for the realm the call is in, the function `/admin/mode`
      // answers — and nothing else. It CHANGES nothing: `global.mode` is set
      // through `POST /admin-api/config/set` like every other setting.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/mode', tag: 'Service',
        operationId: 'getMode',
        mirrors: 'GET /admin/mode',
        handler: function (req, res) {
          log.debug("Entering the management API mode endpoint.");
          self.sendJson(res, 200, modeAdmin.modeView());
          log.debug("Leaving the management API mode endpoint.");
        } },

      // ---------------------------------------------------------------------
      // THE ACCOUNT API'S DOCUMENT (#568). The user portal's API,
      // `/account-api`, publishes its OpenAPI document itself at
      // `/account-api/openapi.json`, to anybody, because it carries no secret;
      // this is the same document for the console's *Account API* page, which
      // draws it from here like every page — the realm's, since the account
      // API is per realm. It describes and calls nothing: every operation of
      // that API acts on the signed-in person's own account.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/account-api', tag: 'Service',
        operationId: 'getAccountApi',
        mirrors: 'GET /admin/account-api',
        handler: function (req, res) {
          log.debug("Entering the management API account API endpoint.");
          // LAZILY, for the explorer's reason: the account API gathers its
          // operations from the portal's page modules when its routes are
          // registered, and this file is loaded later than that anyway.
          const accountApi = require('../account-api/account_api');
          const document = accountApi.document(req);
          let operations = 0;
          Object.keys(document.paths || {}).forEach(function (path) {
            operations += Object.keys(document.paths[path]).length;
          });
          self.sendJson(res, 200, {
            url: helpers.baseUrlOf(req) + '/account-api/openapi.json',
            paths: Object.keys(document.paths || {}).length,
            operations: operations, document: document });
          log.debug("Leaving the management API account API endpoint.");
        } },

      // ---------------------------------------------------------------------
      // THE LISTENERS (#423), AND THE CUSTOM ONES WITH WHICH APPLICATION IS ON
      // WHICH (#472). `listenersAdmin.listenersView()`, the function
      // `/admin/listeners` answers, and its two writes. The built-in
      // listeners' TLS settings are still set through config/set; the custom
      // listeners and the mapping are set here, because the mapping's write
      // is the one that may need `confirm` (rcbj's D6).
      // ---------------------------------------------------------------------
      // MALWARE SCANNING (#1501).
      { method: 'GET', path: BASE + '/malware-scanning', tag: 'Service',
        operationId: 'getMalwareScanning',
        mirrors: 'GET /admin/malware-scanning',
        handler: function (req, res) {
          log.debug("Entering the management API malware scanning endpoint.");
          self.sendJson(res, 200, require('../admin-ui/malware_scan_admin')
            .view());
          log.debug("Leaving the management API malware scanning endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/malware-scanning/:action',
        tag: 'Service', mirrors: 'POST /admin/malware-scanning',
        handler: function (req, res) {
          log.debug("Entering the management API malware scanning action.");
          if (req.params.action !== 'test') {
            errorCodes.mark(res, 'STS-CORE-0170');
            self.sendJson(res, 400, { ok: false, errors: ['Unknown action "' +
              req.params.action + '". The one action is: test.'] });
            log.debug("Leaving the malware scanning action. Unknown.");
            return;
          }
          void require('../admin-ui/malware_scan_admin').test()
            .then(function (result) {
              log.debug("Entering the malware scanning test's answer.");
              if (result.ok) {
                self.sendJson(res, 200, { ok: true, message: 'The service ' +
                  'flagged the EICAR test file, so it is scanning.' });
              } else {
                errorCodes.mark(res, 'STS-CORE-0169');
                self.sendJson(res, 400, { ok: false, errors: [result.why] });
              }
              log.debug("Leaving the malware scanning test's answer.");
            });
          log.debug("Leaving the management API malware scanning action.");
        },
        actions: [{ action: 'test', operationId: 'testMalwareScanning' }] }),

      { method: 'GET', path: BASE + '/listeners', tag: 'Service',
        operationId: 'getListeners',
        mirrors: 'GET /admin/listeners',
        handler: function (req, res) {
          log.debug("Entering the management API listeners endpoint.");
          self.sendJson(res, 200, listenersAdmin.listenersView());
          log.debug("Leaving the management API listeners endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/listeners/:action', tag: 'Service',
        mirrors: 'POST /admin/listeners',
        handler: function (req, res) {
          log.debug("Entering the management API listeners action " +
                    "endpoint.");
          const body = parseBody(req);
          const result = listenersAdmin.listenersAction(req, body);
          if (!result || !result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) ||
                                 'STS-CORE-0154');
          }
          self.sendJson(res, result && result.ok ? 200 : 400, result);
          log.debug("Leaving the management API listeners action " +
                    "endpoint.");
        },
        actions: [
          { action: 'set-listeners', operationId: 'setListeners' },

          { action: 'set-applications', operationId: 'setListenerApplications' }
        ] }),

      // ---------------------------------------------------------------------
      // THE CACHES (#74). `cachesAdmin.cachesView()` and nothing else — the
      // function the page's `?format=json` answers — with the page's own
      // parameters, so the list and one cache's paged entries are one
      // operation, as `/admin/caches` and `/admin/caches?cache=` are one page.
      // ---------------------------------------------------------------------
      // THE STATUS LISTS (#38's follow-ups): `vcStatusAdmin.statusView()`
      // and `statusAction()`, the two functions Monitoring → Verifiable
      // Credentials (`/admin/vc/monitor`) draws — the Credential status tab
      // of `/admin/vc` until #752, which moved the page and not these.
      { method: 'GET', path: BASE + '/vc-status', tag: 'Credential status',
        operationId: 'getCredentialStatus',
        mirrors: 'GET /admin/vc/monitor',
        parameters: [].concat(self.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API credential status " +
                    "endpoint.");
          self.sendJson(res, 200, vcStatusAdmin.statusView(req,
                                                           req.query).json);
          log.debug("Leaving the management API credential status " +
                    "endpoint.");
        } },

      ApiRows.actions({ method: 'POST', route: BASE + '/vc-status/:action',
        tag: 'Credential status',
        mirrors: 'POST /admin/vc/monitor',
        handler: function (req, res) {
          log.debug("Entering the management API credential status action.");
          const result = vcStatusAdmin.statusAction(
            self.withAction(req, parseBody(req)),
            'the management API at /admin-api/vc-status');
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-VC-0082');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API credential status action.");
        },
        // The publish action below carries a body of another shape; each
        // operationId is the model's (#1579).
        actions: (['suspend', 'reinstate', 'revoke'] as const).map(
          function (action): IyaApi.ActionOf<AdminOps,
            'suspendCredential' | 'reinstateCredential' | 'revokeCredential' |
            'publishStatusList'> {
            return {
              action: action,
              operationId: `${action}Credential` as const
            };
          }).concat([{
          // THE STATUS-LIST PUBLISH (#598), moved here from the VC API's
          // test hook `POST /oid4vci/status-lists/bitstring/{purpose}/
          // publish` when the VC API became a product surface: an
          // operator's act, Admin Write, beside the per-credential controls
          // on Monitoring → Verifiable Credentials.
          // `admin-ui/vc_status_admin.ts` argues it.
          action: 'publish',
          operationId: 'publishStatusList'
        }])
      }),

      // ---------------------------------------------------------------------
      // RISK SCORING (#62 P1, 2026-09-22): `riskAdmin.riskView()` and
      // `riskAdmin.riskAction()`, the two functions `/admin/risk` answers.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/risk', tag: 'Risk',
        operationId: 'getRisk',
        mirrors: 'GET /admin/risk',
        parameters: [
          { name: 'address', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'An IPv4 or IPv6 address to look up.' },
          { name: 'authenticator', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'An AAGUID, an AAID (`XXXX#XXXX`) or an ' +
                         'attestation certificate key identifier (40 hex ' +
                         'digits) to look up in the FIDO metadata (#1080).' },
          { name: 'level', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Only the assessments at this level.' },
          { name: 'subject', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Only this person\'s assessments.' }
        ].concat(this.pagingParameters().filter(function (one) {
          return one.name === 'per';
        })).concat(this.detailPagingParameters([
          { name: 'assessments',
            description: 'The sign-ins assessed in the last 7 days, newest ' +
                         'first, ' + adminViews.DEFAULT_PER_PAGE + ' by ' +
                         'default.' },
          { name: 'subjects',
            description: 'The realm\'s people by current standing, highest ' +
                         'score first, twenty-five by default.' },
          { name: 'failures',
            description: 'The refused passwords of the last 7 days, newest ' +
                         'first, fifty by default (#313).' }
        ])),
        handler: function (req, res) {
          log.debug("Entering the management API risk endpoint.");
          const realmOnly = riskAdmin.realmOnly(req);
          riskAdmin.riskView(req.query, realmOnly).then(function (view) {
            self.sendJson(res, 200, view);
            log.debug("Leaving the management API risk endpoint.");
          }).catch(function (e) {
            log.warn(errorCodes.tag('STS-RISK-0011') + 'risk: the view ' +
                     'failed: ' + ((e && e.message) || e));
            errorCodes.mark(res, 'STS-RISK-0011');
            self.sendJson(res, 500, { ok: false,
                                      errors: [String((e && e.message) ||
                                                      e)] });
            log.debug("Leaving the management API risk endpoint. Failed.");
          });
        } },

      // Monitoring → Risk Scoring (#62): `riskAdmin.metricsView()`.
      { method: 'GET', path: BASE + '/risk/metrics', tag: 'Risk',
        operationId: 'getRiskMetrics',
        mirrors: 'GET /admin/risk-scoring',
        parameters: [
          { name: 'window', in: 'query', required: false,
            schema: { type: 'string', enum: ['1h', '24h', '7d', '30d'],
                      examples: ['24h'] },
            description: 'How far back the assessments are counted; 24h ' +
                         'when absent.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API risk metrics endpoint.");
          const realmOnly = riskAdmin.realmOnly(req);
          riskAdmin.metricsView(req.query, realmOnly).then(function (view) {
            self.sendJson(res, 200, view);
            log.debug("Leaving the management API risk metrics endpoint.");
          }).catch(function (e) {
            log.warn(errorCodes.tag('STS-RISK-0025') + 'risk: the metrics ' +
                     'failed: ' + ((e && e.message) || e));
            errorCodes.mark(res, 'STS-RISK-0025');
            self.sendJson(res, 500, { ok: false,
                                      errors: [String((e && e.message) ||
                                                      e)] });
            log.debug("Leaving the management API risk metrics endpoint. " +
                      "Failed.");
          });
        } },

      // Monitoring → Geolocation (#255): `geolocationAdmin.geoView()`, the
      // counts the page draws, suppression applied the same way.
      { method: 'GET', path: BASE + '/geolocation', tag: 'Risk',
        operationId: 'getGeolocation',
        mirrors: 'GET /admin/geolocation',
        parameters: [
          { name: 'window', in: 'query', required: false,
            schema: { type: 'string', enum: ['live', '24h', '7d', '30d'],
                      examples: ['7d'] },
            description: 'Live sessions, or everybody over a span; live ' +
                         'when absent.' },
          { name: 'continent', in: 'query', required: false,
            schema: { type: 'string', enum: ['africa', 'antarctica', 'asia',
                                             'europe', 'north-america',
                                             'oceania', 'south-america'],
                      examples: ['europe'] },
            description: 'One continent\'s countries.' },
          { name: 'country', in: 'query', required: false,
            schema: { type: 'string', pattern: '^[A-Za-z]{2}$',
                      examples: ['FR'] },
            description: 'One country (ISO 3166-1 alpha-2) and its cities.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API geolocation endpoint.");
          geolocationAdmin.geoView(req.query).then(function (view) {
            if (!view.ok) {
              errorCodes.mark(res, 'STS-RISK-0042');
              self.sendJson(res, 400, { ok: false, errors: view.errors });
              log.debug("Leaving the management API geolocation endpoint. " +
                        "Refused.");
              return;
            }
            self.sendJson(res, 200, view);
            log.debug("Leaving the management API geolocation endpoint.");
          }).catch(function (e) {
            log.warn(errorCodes.tag('STS-RISK-0041') + 'geolocation: the ' +
                     'view failed: ' + ((e && e.message) || e));
            errorCodes.mark(res, 'STS-RISK-0041');
            self.sendJson(res, 500, { ok: false,
                                      errors: [String((e && e.message) ||
                                                      e)] });
            log.debug("Leaving the management API geolocation endpoint. " +
                      "Failed.");
          });
        } },

      // THE DATASET UPLOAD (#215): `POST /admin/risk/upload`'s twin (rule 7).
      // The body is the FILE — never parsed: `common/app.js` exempts this
      // path from its body parsers, and `risk/risk_upload.ts` streams it to
      // disk — and the fields are query parameters, which the handler
      // checks by name. ABOVE `/risk/:action`, which would otherwise take
      // `upload` as an action it does not know.
      { method: 'POST', path: BASE + '/risk/upload', tag: 'Risk',
        operationId: 'uploadRiskDataset',
        mirrors: 'POST /admin/risk/upload',
        handlerOwnsBody: true,
        parameters: [
          { name: 'dataset', in: 'query', required: true,
            schema: { type: 'string', enum: closed.riskDatasets,
                      examples: ['iplist.operator-allow'] },
            description: 'The dataset, as GET /admin-api/risk lists them.' },
          { name: 'format', in: 'query', required: true,
            schema: { type: 'string', enum: closed.riskFormats,
                      examples: ['ip-list'] },
            description: 'The format of the file once expanded. Each ' +
                         'dataset takes only some of them, which the ' +
                         'handler refuses by name.' },
          { name: 'realm', in: 'query', required: false,
            schema: { type: 'string', examples: ['no-such-realm'] },
            description: 'The realm, for an operator list only.' },
          { name: 'version', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The version\'s name; its SHA-256 by default.' },
          { name: 'sha256', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The SHA-256 of the file AS SENT (compressed, if ' +
                         'it is), which the provider publishes; a ' +
                         'mismatch refuses the version.' },
          { name: 'publishedAt', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'An ISO 8601 date.' },
          { name: 'provider', in: 'query', required: false,
            schema: { type: 'string', enum: closed.riskProviders } },
          { name: 'licence', in: 'query', required: false,
            schema: { type: 'string' } },
          { name: 'attribution', in: 'query', required: false,
            schema: { type: 'string' } },
          { name: 'activate', in: 'query', required: false,
            schema: { type: 'string', enum: ['true', 'false'] },
            description: '`false` loads without activating.' },
          { name: 'acceptTerms', in: 'query', required: false,
            // `on` is what the console's checkbox sends, and the handler has
            // always read it as `true` (`risk/risk_upload.ts`).
            schema: { type: 'string', enum: ['true', 'false', 'on'] },
            description: 'Accept the provider\'s current terms as part of ' +
                         'this import.' },
          { name: 'overrideSignature', in: 'query', required: false,
            schema: { type: 'string', enum: ['true', 'false', 'on'] },
            description: '`fido.mds3` only: load the BLOB even if its ' +
                         'signature or signing chain does not verify. Its ' +
                         'contents are then UNAUTHENTICATED; the version is ' +
                         'recorded with `verification: overridden` and the ' +
                         'reason, and revocation is not checked. Refused ' +
                         'for any other dataset.' }
        ],
        requestBodyTypes: ['application/octet-stream', 'application/gzip',
                           'application/zip'],
        handler: function (req, res) {
          log.debug("Entering the management API risk upload.");
          riskAdmin.receiveUpload(req, 'the management API at ' +
                                  '/admin-api/risk/upload')
            .then(function (answer) {
              if (answer.close) {
                lingeringClose.arm(req, res);
              }
              if (answer.code) {
                errorCodes.mark(res, answer.code);
              }
              self.sendJson(res, answer.status, answer.body);
              log.debug("Leaving the management API risk upload. " +
                        answer.status);
            }).catch(function (e) {
              log.warn(errorCodes.tag('STS-RISK-0037') + 'risk: an upload ' +
                       'failed: ' + ((e && e.message) || e));
              errorCodes.mark(res, 'STS-RISK-0037');
              lingeringClose.arm(req, res);
              self.sendJson(res, 500, { ok: false,
                                        errors: [String((e && e.message) ||
                                                        e)] });
              log.debug("Leaving the management API risk upload. Threw.");
            });
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/risk/:action', tag: 'Risk',
        mirrors: 'POST /admin/risk',
        handler: function (req, res) {
          log.debug("Entering the management API risk action.");
          riskAdmin.riskAction(self.withAction(req, parseBody(req)),
                               'the management API at /admin-api/risk')
            .then(function (result) {
              if (!result.ok) {
                errorCodes.mark(res, errorCodes.codeOf(result) ||
                                     'STS-RISK-0011');
              }
              self.sendJson(res, result.ok ? 200 : 400, result);
              log.debug("Leaving the management API risk action.");
            }).catch(function (e) {
              log.warn(errorCodes.tag('STS-RISK-0011') + 'risk: an action ' +
                       'failed: ' + ((e && e.message) || e));
              errorCodes.mark(res, 'STS-RISK-0011');
              self.sendJson(res, 500, { ok: false,
                                        errors: [String((e && e.message) ||
                                                        e)] });
              log.debug("Leaving the management API risk action. Threw.");
            });
        },
        actions: [
          { action: 'import', operationId: 'importRiskDataset' },
          { action: 'activate', operationId: 'activateRiskDataset' },
          { action: 'reload', operationId: 'reloadRiskDatasetVersion' },
          { action: 'rollback', operationId: 'rollbackRiskDataset' },
          { action: 'accept-terms', operationId: 'acceptRiskProviderTerms' },
          { action: 'delete', operationId: 'deleteRiskDatasetVersion' }
        ]
      }),

      // ---------------------------------------------------------------------
      // MAIL (#63, 2026-09-22). `mailAdmin.settingsView()` and
      // `outboxView()` — what the two pages' `?format=json` answer — and
      // `settingsAction()` and `outboxAction()`, the functions their forms
      // post to. The paths are the pages' paths, so a realm administrator is
      // confined by the same rule on both surfaces.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/mail', tag: 'Service',
        operationId: 'getMail',
        mirrors: 'GET /admin/mail',
        parameters: [
          { name: 'template', in: 'query', required: false,
            schema: { type: 'string', enum: closed.mailTemplates,
                      examples: ['password-reset'] },
            description: 'A message id, to answer its wording.' },
          { name: 'lang', in: 'query', required: false,
            schema: { type: 'string', examples: ['fr'] },
            description: 'The language of `template`; `en` by default.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API mail endpoint.");
          const json = mailAdmin.settingsView(req, req.query);
          if (req.query && req.query.template && !json.template) {
            errorCodes.mark(res, 'STS-MAIL-0017');
            self.sendJson(res, 404, { ok: false, errors: ['There is no ' +
              'message "' + String(req.query.template) + '".'] });
            log.debug("Leaving the management API mail endpoint. Unknown.");
            return;
          }
          self.sendJson(res, 200, json);
          log.debug("Leaving the management API mail endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/mail/:action', tag: 'Service',
        mirrors: 'POST /admin/mail',
        handler: function (req, res) {
          log.debug("Entering the management API mail action.");
          const result = mailAdmin.settingsAction(
            self.withAction(req, parseBody(req)), '',
            'the management API at /admin-api/mail');
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-MAIL-0025');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API mail action.");
        },
        actions: [
          { action: 'test', operationId: 'sendMailTestMessage' },
          { action: 'verify', operationId: 'sendMailVerificationLink' },
          { action: 'save-template', operationId: 'saveMailTemplate' },
          { action: 'reset-template', operationId: 'resetMailTemplate' }
        ]
      }),

      { method: 'GET', path: BASE + '/mail/outbox', tag: 'Service',
        operationId: 'getMailOutbox',
        mirrors: 'GET /admin/mail/outbox',
        parameters: [
          { name: 'state', in: 'query', required: false,
            schema: { type: 'string', enum: ['pending', 'sent', 'captured',
                                             'dead'] },
            description: 'Only messages in this state (`dead`: the dead ' +
                         'letters).' },
          { name: 'q', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'A person, an address, a message or a code.' },
          { name: 'message', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One message\'s id.' }
        ].concat(self.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API mail outbox endpoint.");
          self.sendJson(res, 200, mailAdmin.outboxView(req, req.query));
          log.debug("Leaving the management API mail outbox endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/mail/outbox/:action', tag: 'Service',
        mirrors: 'POST /admin/mail/outbox',
        handler: function (req, res) {
          log.debug("Entering the management API mail outbox action.");
          const result = mailAdmin.outboxAction(
            self.withAction(req, parseBody(req)), '');
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-MAIL-0025');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API mail outbox action.");
        },
        actions: [
          { action: 'retry', operationId: 'retryMailDeadLetter' }
        ]
      }),

      // ---------------------------------------------------------------------
      // THE DEVICE REGISTER (#164, #218, 2026-09-26). `devicesAdmin`'s
      // `listView()`, `registrationView()` and `monitorView()` — what the
      // three pages' `?format=json` answer — and `action()`, the function
      // the list page's five forms post to. A key is recorded as proven by
      // nobody and self-asserted whichever door it came through; neither
      // surface forwards a proof or an attestation from a body.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/devices', tag: 'Devices',
        operationId: 'getDevices',
        mirrors: 'GET /admin/devices',
        parameters: [
          { name: 'device', in: 'query', required: false,
            schema: { type: 'string' }, description: 'One device\'s id.' },
          { name: 'q', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'A substring of the id, the label, the owner\'s ' +
                         'DN, a key\'s thumbprint or label, the platform, ' +
                         'model or OS.' },
          { name: 'ownerKind', in: 'query', required: false,
            schema: { type: 'string', enum: ['person', 'application'] },
            description: 'Only devices a person, or an application, owns.' },
          { name: 'owner', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Only this owner\'s: a username, an application ' +
                         'identifier (with `ownerKind=application`) or a ' +
                         'DN.' },
          { name: 'application', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Only devices this application used.' },
          { name: 'compliance', in: 'query', required: false,
            schema: { type: 'string',
                      enum: ['compliant', 'not-compliant', 'unknown'] },
            description: 'Only devices in this compliance state.' },
          // THE THREE LEVELS `common/devices.ts` records (#446 found the
          // third missing here, when the console's own filter, which offers
          // all three, began reaching this operation): `bearer` is a
          // remembered browser holding no key of its own.
          { name: 'attestation', in: 'query', required: false,
            schema: { type: 'string',
                      enum: ['attested', 'self-asserted', 'bearer'] },
            description: 'Only attested, self-asserted or bearer devices ' +
                         '(a remembered browser, with no key of its own).' },
          { name: 'keyKind', in: 'query', required: false,
            schema: { type: 'string',
                      enum: ['x509', 'jwk', 'webauthn', 'native-sso'] },
            description: 'Only devices recognised by this kind of key.' },
          { name: 'status', in: 'query', required: false,
            schema: { type: 'string', enum: ['active', 'compromised'] },
            description: 'Only active, or compromised, devices.' }
        ].concat(self.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API devices list endpoint.");
          const json = devicesAdmin.listView(req, req.query);
          if (req.query && req.query.device !== undefined && !json.found) {
            errorCodes.mark(res, 'STS-DEVICE-0007');
          }
          self.sendJson(res, 200, json);
          log.debug("Leaving the management API devices list endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/devices/:action', tag: 'Devices',
        mirrors: 'POST /admin/devices',
        handler: function (req, res) {
          log.debug("Entering the management API devices action.");
          const result = devicesAdmin.action(
            self.withAction(req, parseBody(req)), '',
            'the management API at /admin-api/devices');
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) ||
                                 'STS-DEVICE-0013');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API devices action.");
        },
        actions: [
          { action: 'create', operationId: 'createDevice' },
          { action: 'update', operationId: 'updateDevice' },
          { action: 'remove', operationId: 'removeDevice' },
          { action: 'add-key', operationId: 'addDeviceKey' },
          { action: 'remove-key', operationId: 'removeDeviceKey' },
          { action: 'set-compliance', operationId: 'setDeviceCompliance' },
          { action: 'set-status', operationId: 'setDeviceStatus' }
        ]
      }),

      // ---------------------------------------------------------------------
      // THE MDM / POSTURE FEED (#164 decision 2, phase 3). Not an
      // administrator's operation: its token carries `device:compliance`,
      // a protected scope (#110) issued only to a client that declares it,
      // and the gate takes that scope — and only that — here
      // (`isDeviceComplianceFeed()`), so a feed holds nothing else.
      // ---------------------------------------------------------------------
      { method: 'POST', path: BASE + DEVICE_COMPLIANCE_PATH, tag: 'Devices',
        operationId: 'reportDeviceCompliance',
        mirrors: 'no console form — an MDM feed; an administrator uses the ' +
                 'device page\'s set-compliance',
        parameters: [],
        handler: function (req, res) {
          log.debug("Entering the management API device compliance feed.");
          // The feed's client, which the gate verified and left on the
          // response; '' where the gate is off.
          const result = devicesAdmin.mdmFeed(parseBody(req),
            String(res.locals.apiClientId || ''));
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) ||
                                 'STS-DEVICE-0007');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API device compliance feed.");
        } },

      { method: 'GET', path: BASE + '/devices/monitor', tag: 'Devices',
        operationId: 'getDevicesMonitor',
        mirrors: 'GET /admin/devices/monitor',
        parameters: [
          { name: 'days', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, maximum: 366,
                      examples: [30] },
            description: 'How many days the timeline covers; 30 by ' +
                         'default.' }
        ],
        handler: function (req, res, next) {
          log.debug("Entering the management API devices monitor endpoint.");
          // Asynchronous since #820: the counts are asked of the store and
          // one page of devices is read, never every device.
          devicesAdmin.monitorViewAsync(req, req.query).then(function (view) {
            self.sendJson(res, 200, view);
          }).catch(function (e) {
            log.debug("Caught in the management API devices monitor " +
                      "endpoint: " + ((e && e.message) || e));
            next(e);
          });
          log.debug("Leaving the management API devices monitor endpoint.");
        } },

      // #221: Monitoring → Service accounts, the rotation's state per
      // account. Rule 7.
      { method: 'GET', path: BASE + '/service-accounts', tag: 'Users',
        operationId: 'getServiceAccounts',
        mirrors: 'GET /admin/service-accounts',
        parameters: ([
          { name: 'failing', in: 'query', required: false,
            schema: { type: 'string', enum: ['true'] },
            description: '`true`: only accounts whose last rotation ' +
                         'failed.' },
          { name: 'account', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One service account, by username (#607): the ' +
                         'answer is `{ found, account }` alone — `account` ' +
                         'as a row of `accounts` is, with ' +
                         '`ownerProtected` — and an owner of the account ' +
                         'may ask it with owner:read.' }
        ] as any[]).concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API service accounts " +
                    "endpoint.");
          // ONE ACCOUNT (#607): the read an owner may ask, and the facts the
          // portal's page draws — never the realm's other accounts.
          const one = String((req.query || {}).account || '').trim();
          if (one) {
            const facts = serviceAccounts.of(one);
            self.sendJson(res, 200, { found: !!facts, account: facts });
            log.debug("Leaving the management API service accounts " +
                      "endpoint. One account.");
            return;
          }
          self.sendJson(res, 200,
                        adminViews.serviceAccountsMonitorJson(req.query));
          log.debug("Leaving the management API service accounts " +
                    "endpoint.");
        } },

      { method: 'GET', path: BASE + '/device-registration', tag: 'Devices',
        operationId: 'getDeviceRegistration',
        mirrors: 'GET /admin/device-registration',
        parameters: [],
        handler: async function (req, res) {
          log.debug("Entering the management API device registration " +
                    "endpoint.");
          self.sendJson(res, 200,
                        await devicesAdmin.registrationViewWithStatus(req));
          log.debug("Leaving the management API device registration " +
                    "endpoint.");
        } },

      // ---------------------------------------------------------------------
      // THE SCHEDULER (#49, 2026-09-22). `schedulerAdmin.schedulerView()` —
      // the function the page's `?format=json` answers — and
      // `schedulerAdmin.schedulerAction()`, the function its two forms post
      // to. Nothing here reads the scheduler a second way.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/scheduler', tag: 'Service',
        operationId: 'getScheduler',
        mirrors: 'GET /admin/scheduler',
        parameters: [
          { name: 'jobsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the job register to return, answered ' +
                         'by `jobsPaging`.' },
          { name: 'run', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'A run id, to answer that run.' },
          { name: 'job', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Only the runs of this job.' },
          { name: 'outcome', in: 'query', required: false,
            schema: { type: 'string', enum: ['succeeded', 'failed',
                                             'abandoned', 'running',
                                             'queued'] },
            description: 'Only the runs in this state.' }
        ].concat(self.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API scheduler endpoint.");
          // Awaited, and the handler catches: Express 4 does not look at
          // what a handler returns (the database report's reason).
          schedulerAdmin.schedulerView(req, req.query).then(function (json) {
            self.sendJson(res, 200, json);
            log.debug("Leaving the management API scheduler endpoint.");
          }).catch(function (e) {
            errorCodes.mark(res, 'STS-SCHED-0013');
            self.sendJson(res, 500, { ok: false, errors: [
              'The scheduler report could not be built: ' +
              (e && e.message ? e.message : String(e))] });
            log.debug("Leaving the management API scheduler endpoint. It " +
                      "threw.");
          });
          log.debug("Leaving handler().");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/scheduler/:action', tag: 'Service',
        mirrors: 'POST /admin/scheduler',
        handler: function (req, res) {
          log.debug("Entering the management API scheduler action.");
          const result = schedulerAdmin.schedulerAction(req,
            self.withAction(req, parseBody(req)),
            'the management API at /admin-api/scheduler');
          if (!result.ok) {
            errorCodes.mark(res, result.errorCode || 'STS-ADMIN-0012');
            self.sendJson(res, result.status || 400,
                          { ok: false, errors: result.errors });
            log.debug("Leaving the management API scheduler action. " +
                      "Refused.");
            return;
          }
          self.sendJson(res, 202, result);
          log.debug("Leaving the management API scheduler action.");
        },
        actions: [
          { action: 'run', operationId: 'runSchedulerJob' },
          { action: 'step-down', operationId: 'stepDownScheduler' }
        ]
      }),

      { method: 'GET', path: BASE + '/caches', tag: 'Service',
        operationId: 'getCaches',
        mirrors: 'GET /admin/caches',
        parameters: [
          { name: 'cache', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'A cache `name`, to answer its entries rather ' +
                         'than the list.' }
        ].concat(self.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API caches endpoint.");
          self.sendJson(res, 200, cachesAdmin.cachesView(req.query));
          log.debug("Leaving the management API caches endpoint.");
        } },

      // ---------------------------------------------------------------------
      // THE WORKER POOLS (#327). `workerPoolsAdmin.workerPoolsView()` — the
      // function `/admin/worker-pools?format=json` answers — and nothing
      // else. Pinned to the front process with the page
      // (`request_pool.js`'s NEVER_DISPATCHED), because only it holds the
      // pools.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/worker-pools', tag: 'Service',
        operationId: 'getWorkerPools',
        mirrors: 'GET /admin/worker-pools',
        parameters: [
          { name: 'node', in: 'query', required: false,
            schema: { type: 'string', examples: ['node-a'] },
            description: 'A cluster node\'s NAME (`cluster.nodeName`, ' +
                         'node-a, node-b, …), to answer about that node ' +
                         'alone: its view at the top, `nodes` holding its ' +
                         'one section. An unknown name is 404 with the ' +
                         'names there are (#332).' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API worker pools endpoint.");
          workerPoolsAdmin.workerPoolsView({ node: req.query && req.query.node
            ? String(req.query.node) : '' }).then(function (view) {
            if (view.notFound) {
              errorCodes.mark(res, 'STS-CORE-0126');
              self.sendJson(res, 404, { ok: false, errors: [
                'There is no node named ' + view.notFound + '.'],
                nodes: view.nodeNames });
              return;
            }
            self.sendJson(res, 200, view);
          }).catch(function (e) {
            log.debug("Caught in the management API worker pools " +
                      "endpoint: " + ((e && e.message) || e));
            log.error(errorCodes.tag('STS-WORKER-0044') + 'The worker ' +
                      'pools report could not be built: ' +
                      ((e && e.message) || e));
            errorCodes.mark(res, 'STS-WORKER-0044');
            self.sendJson(res, 500, { ok: false, errors: [
              'The worker pools report could not be built.'] });
          });
          log.debug("Leaving the management API worker pools endpoint.");
        } },

      // ---------------------------------------------------------------------
      // NODE HEALTH (#329). `nodeHealthAdmin.nodeHealthView()` — the
      // function `/admin/node-health?format=json` answers — and nothing
      // else. Pinned to the front process with the page
      // (`request_pool.js`'s NEVER_DISPATCHED), because only it knows every
      // process of the node.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/node-health', tag: 'Service',
        operationId: 'getNodeHealth',
        mirrors: 'GET /admin/node-health',
        parameters: [
          { name: 'node', in: 'query', required: false,
            schema: { type: 'string', examples: ['node-a'] },
            description: 'A cluster node\'s NAME (`cluster.nodeName`, ' +
                         'node-a, node-b, …), to answer about that node ' +
                         'alone: its view at the top, `nodes` holding its ' +
                         'one section. An unknown name is 404 with the ' +
                         'names there are (#332).' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API node health endpoint.");
          nodeHealthAdmin.nodeHealthView({ node: req.query && req.query.node
            ? String(req.query.node) : '' }).then(function (view) {
            if (view.notFound) {
              errorCodes.mark(res, 'STS-CORE-0126');
              self.sendJson(res, 404, { ok: false, errors: [
                'There is no node named ' + view.notFound + '.'],
                nodes: view.nodeNames });
              return;
            }
            self.sendJson(res, 200, view);
          }).catch(function (e) {
            log.debug("Caught in the management API node health " +
                      "endpoint: " + ((e && e.message) || e));
            log.error(errorCodes.tag('STS-CORE-0124') + 'The node health ' +
                      'report could not be built: ' +
                      ((e && e.message) || e));
            errorCodes.mark(res, 'STS-CORE-0124');
            self.sendJson(res, 500, { ok: false, errors: [
              'The node health report could not be built.'] });
          });
          log.debug("Leaving the management API node health endpoint.");
        } },

      // ---------------------------------------------------------------------
      // NODE HEALTH'S ONE CONTROL (#611): a full garbage collection, on
      // demand. `nodeHealthAdmin.collectGarbage()` — the function the page's
      // Collect buttons are sent to — and nothing else. Under
      // `/admin-api/node-health`, so `request_pool.js`'s NEVER_DISPATCHED
      // already pins it to the front process: only that process knows the
      // worker threads and can ask them. A POST, so `admin:write`; a service
      // operation, so a realm's own token is refused it (its `mirrors` is a
      // service page, `admin_scope.ts`).
      // ---------------------------------------------------------------------
      ApiRows.actions({ method: 'POST',
        route: BASE + '/node-health/:action', tag: 'Service',
        mirrors: 'POST /admin/node-health',
        handler: function (req, res) {
          log.debug("Entering the management API node health action.");
          nodeHealthAdmin.collectGarbage(self.withAction(req, parseBody(req)),
                                         self.callerNameOf(res))
            .then(function (result) {
              const out = Object.assign({}, result);
              delete out.status;
              delete out.errorCode;
              if (!result.ok) {
                errorCodes.mark(res, result.errorCode || 'STS-CORE-0160');
                self.sendJson(res, result.status || 400, out);
                log.debug("Leaving the management API node health action. " +
                          "Refused.");
                return;
              }
              self.sendJson(res, 200, out);
              log.debug("Leaving the management API node health action.");
            }).catch(function (e) {
              log.debug("Caught in the management API node health action: " +
                        ((e && e.message) || e));
              log.error(errorCodes.tag('STS-CORE-0158') + 'A garbage ' +
                        'collection could not be run: ' +
                        ((e && e.message) || e));
              errorCodes.mark(res, 'STS-CORE-0158');
              self.sendJson(res, 500, { ok: false, errors: [
                'The garbage collection could not be run.'] });
            });
          log.debug("Leaving handler().");
        },
        actions: [
          { action: 'collect-garbage', operationId: 'collectGarbage' }
        ] }),

      // ---------------------------------------------------------------------
      // THE DATABASE REPORT. `databaseAdmin.databaseView()` and nothing else,
      // which is rule 7 read the strict way: the page and this operation must
      // not be able to report different numbers, and one function is the only
      // way to make that impossible.
      //
      // **IT IS THE ONE OPERATION ON THIS API WHOSE REPLY SHAPE IS DECIDED BY
      // SOMETHING OUTSIDE THIS SERVICE**, and a client has to be told so rather
      // than discovering it: the members under `probes.*.row` and
      // `probes.*.rows` are PostgreSQL's own columns, so they differ between
      // major versions. A client reading a named column should treat its
      // absence as ordinary.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/database', tag: 'Service',
        operationId: 'getDatabase',
        mirrors: 'GET /admin/database',
        handler: function (req, res) {
          log.debug("Entering the management API database report endpoint.");
          // **AWAITED, AND THE HANDLER CATCHES.** Express 4 does not look at
          // what a handler returns, so a rejection here would be an unhandled
          // rejection and a request that never gets an answer — the same trap
          // the token endpoint's wrapper exists for. This is the only operation
          // on this API that talks to a database, so it is the only one that
          // can reject for a reason outside this process.
          databaseAdmin.databaseView().then(function (report) {
            self.sendJson(res, 200, report);
            log.debug("Leaving the management API database report endpoint.");
          }).catch(function (e) {
            errorCodes.mark(res, 'STS-API-0012');
            self.sendJson(res, 500, { ok: false, errors: [
              'The database report could not be built: ' +
              (e && e.message ? e.message : String(e))] });
            log.debug("Leaving the management API database report endpoint. " +
                      "It threw.");
          });
          log.debug("Leaving handler().");
        } },

      // ---------------------------------------------------------------------
      // THE SECRET-STORE REPORT. `secretsAdmin.secretsView()` and nothing else,
      // which is rule 7 read the strict way: the page and this operation must
      // not be able to report a different state of the same store.
      //
      // **NOTHING IN THE REPLY IS A SECRET AND NOTHING IN IT CAME FROM READING
      // ONE.** Every probe behind it is a metadata read — a stat of the key
      // file, a `sys` endpoint, a KV version history, a `DescribeSecret`, a
      // listing of version properties — and `common/secrets.js` deletes a
      // deny-list of member names from whatever a provider hands back before it
      // leaves that module. This operation is `admin:read`, like every other
      // read here, and there is deliberately no write beside it: a rotate would
      // destroy everything sealed under the key.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/secrets', tag: 'Service',
        operationId: 'getSecrets',
        mirrors: 'GET /admin/secrets',
        handler: function (req, res) {
          log.debug("Entering the management API secret store report " +
                    "endpoint.");
          // **AWAITED, AND THE HANDLER CATCHES**, for `getDatabase`'s reason:
          // express 4 does not look at what a handler returns, so a rejection
          // would be an unhandled rejection and a request that never gets an
          // answer. This is the other operation here that talks to something
          // outside this process.
          secretsAdmin.secretsView().then(function (report) {
            self.sendJson(res, 200, report);
            log.debug("Leaving the management API secret store report " +
                      "endpoint.");
          }).catch(function (e) {
            errorCodes.mark(res, 'STS-API-0013');
            self.sendJson(res, 500, { ok: false, errors: [
              'The secret store report could not be built: ' +
              (e && e.message ? e.message : String(e))] });
            log.debug("Leaving the management API secret store report " +
                      "endpoint. It threw.");
          });
          log.debug("Leaving handler().");
        } },

      // ---------------------------------------------------------------------
      // THE EMBEDDED PROTOCOL DEBUGGER (2026-09-13).
      // `debuggerAdmin.debuggerView()` and nothing else — rule 7 — and
      // read-only: the debugger's settings are `config/set` like every other
      // row, and who may USE it is the two console roles, granted at
      // `rbac/grant`. Pinned to the front process, which is the only one
      // holding the listener and the api child.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/debugger', tag: 'Service',
        operationId: 'getDebugger',
        mirrors: 'GET /admin/debugger',
        handler: function (req, res) {
          log.debug("Entering the management API debugger report endpoint.");
          try {
            self.sendJson(res, 200, debuggerAdmin.debuggerView());
          } catch (e) {
            log.debug("Caught in handler(): " + ((e && e.message) || e));
            errorCodes.mark(res, 'STS-DBG-0023');
            self.sendJson(res, 500, { ok: false, errors: [
              'The debugger report could not be built: ' +
              (e && e.message ? e.message : String(e))] });
          }
          log.debug("Leaving the management API debugger report endpoint.");
        } },

      // ---------------------------------------------------------------------
      // THE KEY PAIRS. Two operations, because LISTING what this process holds
      // and HANDING A KEY OVER are different acts and only the second is a
      // write.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/keys', tag: 'Service',
        operationId: 'getKeys',
        mirrors: 'GET /admin/keys',
        handler: function (req, res) {
          log.debug("Entering the management API key list endpoint.");
          const report = adminViews.keysView(req);
          if (!report) {
            errorCodes.mark(res, 'STS-API-0011');
            self.sendJson(res, 503, { ok: false, errors: [
              'The crypto reporter is not installed in this process. ' +
              'admin-ui/crypto_metadata.ts fills it at its own require ' +
              'time.'] });
            log.debug("Leaving the management API key list endpoint. No " +
                      "reporter.");
            return;
          }
          self.sendJson(res, 200, report);
          log.debug("Leaving the management API key list endpoint.");
        } },

      { method: 'GET', path: BASE + '/keys/history/certificate',
        tag: 'Service',
        operationId: 'getKeyHistoryCertificate',
        mirrors: 'GET /admin/keys/history',
        parameters: [
          { name: 'unit', in: 'query', required: true,
            schema: { type: 'string', examples: ['jose:RS256'] },
            description: 'The signing unit, `jose:RS256` and the like.' },
          { name: 'kid', in: 'query', required: true,
            schema: { type: 'string', examples: ['no-such-kid'] },
            description: 'The key\'s identifier.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API key certificate endpoint.");
          const q = req.query || {};
          const pem = adminViews.signingHistoryCertificate(
            String(q.unit || ''), String(q.kid || ''));
          if (!pem) {
            errorCodes.mark(res, 'STS-KEYS-0068');
            self.sendJson(res, 404, { ok: false, errors: [
              'This realm has no certificate recorded for that key.'] });
            log.debug("Leaving the management API key certificate " +
                      "endpoint. None held.");
            return;
          }
          res.status(200)
             .set('Content-Type', 'application/pem-certificate-chain')
             .set('Cache-Control', 'no-store')
             .set('Content-Disposition', 'attachment; filename="' +
                  String(q.kid || 'certificate').replace(/[^A-Za-z0-9._-]/g,
                                                        '_') + '.pem"')
             .send(pem);
          log.debug("Leaving the management API key certificate endpoint.");
        } },

      { method: 'GET', path: BASE + '/keys/history', tag: 'Service',
        operationId: 'getKeyHistory',
        mirrors: 'GET /admin/keys/history',
        parameters: [
          { name: 'unit', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One signing unit (`jose:RS256`, `xml:RS256`, ' +
                         '`jose:ES256:P-256`, `bbs:BBS`, …). Omitted, the ' +
                         'answer is the index of units and their counts.' }
        ].concat(self.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API key history endpoint.");
          const view = adminViews.signingHistoryView(req.query || {});
          if (!view.observed) {
            errorCodes.mark(res, 'STS-API-0011');
            self.sendJson(res, 503, { ok: false, errors: [
              'The signing-key history is not available in this process.'] });
            log.debug("Leaving the management API key history endpoint. " +
                      "No history.");
            return;
          }
          if (view.unit && !view.found) {
            errorCodes.mark(res, 'STS-KEYS-0068');
            self.sendJson(res, 400, { ok: false, errors: [
              'This realm has no record of a signing unit called "' +
              view.unit + '".'], units: view.units.map(function (one) {
                return one.unit;
              }) });
            log.debug("Leaving the management API key history endpoint. " +
                      "Unknown unit.");
            return;
          }
          self.sendJson(res, 200, view);
          log.debug("Leaving the management API key history endpoint. " +
                    view.rows.length + " row(s).");
        } },

      // AN ACTION RESOURCE RATHER THAN A BARE POST, and the suite is why. Every
      // other POST here is `/<resource>/:action`, and
      // `sts_admin_api_operations.js` probes each of them with an action nobody
      // has heard of and requires a 400 naming the ones that exist. A literal
      // `/keys/export` looked like that resource and was not one, so the probe
      // got a 404 — the route pattern simply did not match. One `export` action
      // today; a second (an import, a rotation) goes in the same list.
      ApiRows.actions({ method: 'POST',
        route: BASE + '/keys/:action', tag: 'Service',
        // BOTH console paths (2026-09-22): the rotate and emergency actions
        // (#48) came in through this handler and the declaration still named
        // only the export form, so `/admin/keys`'s two Rotate forms mirrored
        // no operation and `sts_admin_console` reported their POST target as
        // a route that does not exist (rule 7).
        mirrors: 'POST /admin/keys/export and POST /admin/keys/rotate',
        handler: function (req, res) {
          log.debug("Entering the management API key export endpoint.");
          const body = self.withAction(req, parseBody(req));
          // ROTATE AND EMERGENCY (#48): the console's `/admin/keys/rotate`,
          // through the one action it posts to. `crypto_metadata.ts` is
          // required HERE, at the request, because it is 20a in the order and
          // this module is 19.
          if (body.action === 'rotate' || body.action === 'emergency') {
            const result = require('../admin-ui/crypto_metadata')
              .keysAction(req, body, 'the management API at ' +
                          '/admin-api/keys/' + body.action);
            if (!result.ok) {
              errorCodes.mark(res, result.errorCode || 'STS-API-0014');
              self.sendJson(res, result.status || 400,
                            { ok: false, errors: result.errors });
              log.debug("Leaving the management API key endpoint. Refused.");
              return;
            }
            self.sendJson(res, 202, { ok: true, accepted: true,
              runId: result.runId, emergency: result.emergency,
              units: result.units, message: result.message,
              run: BASE + '/scheduler?run=' +
                   encodeURIComponent(result.runId) });
            log.debug("Leaving the management API key endpoint. Queued " +
                      result.runId + ".");
            return;
          }
          if (body.action !== 'export') {
            // THE SENTENCE IS THE SHAPE THE SUITE READS, and that is not a
            // formatting preference: `sts_admin_api_operations.js` matches
            // `Unknown action "x". <phrase>: <list>.` on every action resource,
            // because `admin_api.js` uses the same sentence to check that every
            // console action has an operation here. A handler that stopped
            // writing it would turn that check off with nothing failing.
            errorCodes.mark(res, 'STS-API-0014');
            self.sendJson(res, 400, { ok: false, errors: [
              'Unknown action "' + body.action + '". The actions here are: ' +
              'export, rotate, emergency.'] });
            log.debug("Leaving the management API key export endpoint. " +
                      "Unknown action.");
            return;
          }
          const pending = adminViews.keysExport(String(body.key || ''),
                                           String(body.format || 'pem'),
                                           String(body.password || ''));
          if (!pending) {
            errorCodes.mark(res, 'STS-API-0011');
            self.sendJson(res, 503, { ok: false, errors: [
              'The crypto reporter is not installed in this process.'] });
            log.debug("Leaving the management API key export endpoint. No " +
                      "reporter.");
            return;
          }
          pending.then(function (result) {
            if (!result.ok) {
              errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0015');
              self.sendJson(res, 400, result);
              log.debug("Leaving the management API key export endpoint. " +
                        "Refused.");
              return;
            }
            self.sendJson(res, 200, {
              ok: true,
              status: result.status,
              publicOnly: !!result.publicOnly,
              files: result.files.map(function (file) {
                const data = Buffer.isBuffer(file.data) ? file.data
                  : (typeof file.data === 'string' ?
                     Buffer.from(file.data, 'utf8')
                     : Buffer.from(file.data));
                return { name: file.name, mime: file.mime,
                         bytes: data.length,
                         base64: data.toString('base64') };
              })
            });
            log.debug("Leaving the management API key export endpoint. " +
                      result.files.length + " file(s).");
          }).catch(function (e) {
            errorCodes.mark(res, 'STS-API-0016');
            self.sendJson(res, 400,
                          { ok: false, errors: ['The export failed: ' +
                                                e.message] });
            log.debug("Leaving the management API key export endpoint. Threw.");
          });
          log.debug("Leaving handler().");
        },
        actions: [
          { action: 'export', operationId: 'exportKey' },
          // ROTATE AND EMERGENCY (#48, 2026-09-22): /admin/keys/rotate's two
          // forms. An example is what `sts_admin_api_operations.js` drives,
          // and an emergency signs a realm out, so each example names a unit
          // no realm holds and is the 400 (STS-KEYS-0065, asked before the
          // confirmation) that rotates nothing (#1475). `sts_key_rotation.js`
          // drives both for real, in a realm of its own, and the operations
          // job's NOT_DRIVEN_HERE says so.
          { action: 'rotate', operationId: 'rotateSigningKeys' },
          { action: 'emergency', operationId: 'rotateSigningKeysEmergency' }
        ] }),

      // ---------------------------------------------------------------------
      // THE EXPLORER USED TO BE HERE — `GET /admin-api/docs` and
      // `/admin-api/docs/explorer.js` — AND MOVED TO THE CONSOLE ON 2026-09-09.
      //
      // It is `/admin/api-explorer`, built by `admin-ui/api_explorer.ts` at
      // 19a. The move happened because of the gate at the foot of this file:
      // this API began requiring an OAuth 2.0 access token, and a browser
      // navigating to a URL carries none — so the one page in this service
      // written to be opened in a browser had become the one page a browser
      // could not open. The console linked to it and the link answered 401.
      //
      // **THE OPERATION BELOW IS WHAT RULE 7 ASKS FOR NOW.** A console page
      // gets an operation here that names it, and this is that page's — it
      // reports what the explorer is reading and what the caller's roles would
      // let them do, without repeating the document, which `GET
      // /admin-api/openapi.json` above already is.
      //
      // Two things did NOT move and are worth saying so nobody goes looking:
      // `admin_api_docs.ts` and `admin_api_explorer.js` are still in this
      // directory, because the style, the script and the realm-prefix argument
      // belong to this API's document rather than to the console's shell. The
      // console requires them.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/console/api-explorer', kind: 'console',
        tag: 'Service',
        operationId: 'getApiExplorer',
        mirrors: 'GET /admin/api-explorer',
        handler: function (req, res) {
          log.debug("Entering the API explorer operation.");
          // LAZILY REQUIRED, like the GNAP operations' `gnap_console.js`. That
          // module is loaded at 19a — after this one — because it needs the
          // route table below to build its document; a require at the top of
          // this file would be a cycle, and one in the other direction would
          // move routes. The same arrangement `xacml.js` and `xacml_admin.js`
          // have. (Since #50's R1 a require of it registers nothing —
          // `common/protocol_stack.ts` registers its routes at 19a — so only
          // the cycle is left of that argument, and it is enough.)
          // WHO THE CALLS ARE MADE AS, for the static console's explorer
          // (#446): the token this request carried, its subject and scopes.
          const explorer = loadApiExplorer().explorerJson(req);
          const caller = (res.locals && res.locals.apiCaller) || null;
          if (caller) {
            explorer.who = String(caller.name || '');
            explorer.scope = (caller.scopes || []).join(' ');
          }
          self.sendJson(res, 200, explorer);
          log.debug("Leaving the API explorer operation.");
        } },

      // THE CONSOLE'S FRAME (#446): what the static console draws around
      // every page — the sidebar, the banners, the foot — for this caller.
      { method: 'GET', path: BASE + '/console', kind: 'console',
        tag: 'Service',
        operationId: 'getConsoleShell',
        parameters: [
          { name: 'catalogs', in: 'query', required: false,
            description: 'files: name the static catalog files instead of ' +
                         'carrying the catalogs.',
            schema: { type: 'string', enum: ['files'] } }
        ],
        mirrors: 'GET /admin',
        handler: function (req, res) {
          log.debug("Entering the management API console shell endpoint.");
          // THE GATE IS THE TOKEN'S: the static console has no session of
          // its own, so who is signed in, and what they may see, is what
          // this API decided for the caller (`meJson()`).
          const gate = self.consoleGateOf(self.meJson(req, res));
          // AND THE LANGUAGE IT IS DRAWN IN (#539 phase 5): the negotiation
          // for this administrator and the console's own client, and the
          // console's catalogs along its chain, for the browser's translator.
          self.sendJson(res, 200, Object.assign(
            admin.shellJson(req, gate, gate),
            { locale: self.consoleLocale(req, res,
              req.query && req.query.catalogs === 'files') }));
          log.debug("Leaving the management API console shell endpoint.");
        } },

      // THE CONSOLE'S LANGUAGE CHOOSER (#539 phase 5): the signed-in
      // administrator's own preferredLanguage, written through the person
      // editor as the portal's and the sign-in screen's choosers write it,
      // and the console's catalogs in the new language answered so the page
      // is drawn again without a second request. An empty `lang` removes the
      // preference and follows the browser. It needs the console role
      // alone (the gate's frame list): it changes nothing but the caller's
      // own entry. A refused tag is English, as every refusal is.
      { method: 'POST', path: BASE + '/console/language', kind: 'console',
        tag: 'Service',
        operationId: 'setConsoleLanguage',
        mirrors: 'GET /admin',
        handler: function (req, res) {
          log.debug("Entering the console language endpoint.");
          self.consoleSetLanguage(req, res);
          log.debug("Leaving the console language endpoint.");
        } },

      { method: 'GET', path: BASE + '/status', tag: 'Service',
        operationId: 'getStatus',
        mirrors: 'GET /admin',
        handler: function (req, res) {
          log.debug("Entering the management API status endpoint.");
          // The dashboard's answer since #446: the totals as before, and
          // the visible sections, persistence and the base URL beside them —
          // which since #454 only its console twin,
          // `GET /admin-api/console/dashboard`, answers: this operation names
          // them in `consoleMembers` and `sendJson()` takes them off.
          // Its totals asked asynchronously (2026-10-21): the snapshot's
          // register rows and the directory's tally stood a request worker
          // still for ten seconds on 8081.
          log.debug("Leaving the management API status endpoint. Asking.");
          return admin.dashboardJsonAsync(req).then(function (json) {
            self.sendJson(res, 200, json);
          }, function (e) {
            log.debug("Caught in the management API status endpoint: " +
                      ((e && e.message) || e));
            // 503 for a store it could not read, 500 for anything else
            // (#695: every failure was a "try again shortly").
            self.answerDirectoryFailure(res, e, 'the console\'s totals',
                                        'STS-LDAP-0176');
          });
        } },

      // ---------------------------------------------------------------------
      // WHO AM I, AND WHAT MAY I DO HERE (#446, 2026-10-05).
      //
      // The console is becoming a static application whose only knowledge of
      // its reader is the access token it presents. Everything the
      // server-rendered console learned from `adminViews.gateStateFor(req)` —
      // who is signed in, which authority they are, what they hold, which
      // pages `admin_scope.ts` hides from them, whether the roster is still
      // open — it has to be TOLD, and this is where. It answers what the gate
      // above DECIDED for this request rather than deciding anything: the
      // caller, scopes and roles are the ones the gate left on
      // `res.locals.apiCaller`, so the answer cannot disagree with what the
      // next call will be allowed.
      //
      // It mirrors no console page: it is the console's banner and the
      // filter on its navigation, which every page draws.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/me', tag: 'Service',
        operationId: 'getMe',
        mirrors: 'no console page — what the gate decided for the caller; ' +
                 'the console draws its banner and its navigation from it',
        handler: function (req, res) {
          log.debug("Entering the management API me endpoint.");
          self.sendJson(res, 200, self.meJson(req, res));
          log.debug("Leaving the management API me endpoint.");
        } },

      { method: 'GET', path: BASE + '/metrics', tag: 'Metrics',
        operationId: 'getMetrics',
        mirrors: 'GET /admin/metrics',
        handler: function (req, res, next) {
          log.debug("Entering the management API metrics endpoint.");
          // The sign-on sessions counted by the session index and the newest
          // drawn, while the window is on (#820).
          adminViews.metricsJsonAsync().then(function (json) {
            self.sendJson(res, 200, json);
            log.debug("Leaving the management API metrics endpoint.");
          }).catch(function (e) {
            log.debug("Caught in the management API metrics endpoint: " +
                      ((e && e.message) || e));
            next(e);
          });
        } },

      { method: 'GET', path: BASE + '/users', tag: 'Users',
        operationId: 'getUsers',
        mirrors: 'GET /admin/users',
        parameters: [
          { name: 'user', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One identity, as the list\'s `key` names them. ' +
                         'Returns the drill-down instead of the list.' },
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the identity key, case-insensitive.' },
          { name: 'protocol', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Only identities that authenticated through this ' +
                         'protocol family. The list\'s `protocols` member ' +
                         'says which values there are; it is read off the ' +
                         'data, so a family nobody has used is not offered.' },
          // Read by the handler and published nowhere until #86.
          { name: 'factor', in: 'query', required: false,
            schema: { type: 'string',
                      enum: ['any', 'totp', 'key', 'none', 'unreadable'] },
            description: 'Only people holding a second factor of this ' +
                         'kind, as on GET /admin-api/mfa.' },
          // #221: a service account is a person, tagged `serviceAccount` on
          // its row; this narrows the list to them, or leaves them out.
          { name: 'kind', in: 'query', required: false,
            schema: { type: 'string', enum: ['service', 'person'] },
            description: '`service`: only service accounts (person entries ' +
                         'carrying `stsServiceAccount`); `person`: ' +
                         'everybody else. Each row says which in ' +
                         '`serviceAccount`, and `serviceAccounts` counts ' +
                         'them over the whole list.' },
          { name: 'authenticationsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of `authenticationEvents`, on the ' +
                         '`?user=` reply only. Named rather than the bare ' +
                         '`page` so it does not move the session list. ' +
                         'The member is not `authentications`: that one ' +
                         'is the count.' }
        ].concat(this.pagingParameters()).concat(this.detailPagingParameters([
          { name: 'sessions',
            description: 'Sign-on session blocks, which default to ' +
                         adminViews.DEFAULT_BLOCKS_PER_PAGE + ' rather than ' +
                         adminViews.DEFAULT_PER_PAGE +
                         ' because each one carries a ' +
                         'token list of its own. Only the sessions ON this ' +
                         'page are in the reply.' },
          { name: 'tokensOnEndedSessions',
            description: 'Tokens issued on a session this service no longer ' +
                         'holds.' },
          { name: 'tokensWithNoSession',
            description: 'Tokens issued with no browser session at all: the ' +
                         'grants that never involve one.' },
          { name: 'artifacts',
            description: 'SAML assertions, Kerberos tickets and credentials.' },
          { name: 'federationLinks',
            description: 'The federation partners\' subjects linked to ' +
                         'this person (#109), each `{ link, relationship, ' +
                         'issuer, subject, relationshipExists }`.' },
          { name: 'gnapGrants',
            description: 'The GNAP grants this person is the resource ' +
                         'owner of (#432): each with its state, why it was ' +
                         'finalized (`finalization.reason`: issued, ' +
                         'revoked, rejected, expired), its rights, the ' +
                         'tokens issued under it (label, format, expiry, ' +
                         'state — never a value) and whether it can still ' +
                         'be revoked, which POST ' +
                         '/admin-api/gnap/revoke-grant does with `user`. ' +
                         '`gnapGrantsCells` says what a multi-cell ' +
                         'service\'s list leaves out.' },
          { name: 'uma',
            description: 'This person\'s UMA 2.0 (#1195): `resources` they ' +
                         'own, the `shares` in their document, the ' +
                         'permissions they hold in live RPTs (`held`, ' +
                         'which POST /admin-api/uma/revoke-rpt revokes) and ' +
                         'the requests waiting for them (`pending`). Null ' +
                         'where UMA is not loaded.' }
        ])),
        handler: function (req, res, next) {
          log.debug("Entering the management API users endpoint.");
          // The person's current risk, read first (#62) — the console's
          // route does the same, so the two answers agree.
          // The list's directory names are asked of the store
          // asynchronously (#616: `usersJsonAsync()`), which held a request
          // worker's event loop for seconds at 200,000 people.
          const run = function () {
            log.debug("Entering run().");
            return adminViews.riskFor(req.query).then(function (risk) {
              return adminViews.usersJsonAsync(req, risk);
            }).then(function (json) {
              self.sendJson(res, 200, json);
              log.debug("Leaving run().");
            }, function (e) {
              log.debug("Caught in the management API users endpoint: " +
                        ((e && e.message) || e));
              // The directory read failed after the handler had already
              // started: answer 503 here, and do not rethrow, so a
              // drill-down's fresh() does not also call next().
              // 503 for a store it could not read, 500 for anything else
              // (#695: every failure was a "try again shortly").
              self.answerDirectoryFailure(res, e, 'the users list',
                                          'STS-LDAP-0176');
              log.debug("Leaving run(). The directory could not be read.");
            });
          };
          // The list carries no attempts. The drill-down's do, and they
          // are the audit log: another worker's rows are noted, not held,
          // until fresh() — the wait the audit page already makes (#820).
          const named = req.query && String(req.query.user || '').trim();
          if (!named) {
            log.debug("Leaving the management API users endpoint. " +
                      "The list.");
            return run();
          }
          return audit.fresh().then(run).catch(function (e) {
            log.debug("Caught in the management API users endpoint: " +
                      ((e && e.message) || e));
            log.debug("Leaving the management API users endpoint. " +
                      "fresh().");
            next(e);
          });
        } },

      // RULE 7 FOR /admin/users/new, and it earns its place beyond the parity
      // for the same reason `getNewApplicationForm` does one resource along:
      // what it answers is the CLOSED CATALOGUE `createUser()` validates
      // `attributes` against. A caller that reads this cannot construct a
      // create the service will refuse with "a person here does not have an
      // attribute called ...", and it learns the list from the service rather
      // than from a copy of it in a document.
      //
      // THERE IS NO POST BESIDE IT, which is rule 7 read exactly rather than by
      // shape: that page's controls post `action=create` and `action=fill`, the
      // first is `createUser` below and already exists, and the second creates
      // nothing — it fills a FORM in for a person to edit, and the values it
      // writes are the ones `invent: true` on a create has always written
      // directly. An operation that returned form values to nobody would be an
      // operation with no act behind it.
      // APP PASSWORDS, ONE PERSON'S, PAGED (#101). The list the App passwords
      // block on /admin/users draws, and the one `/portal/app-passwords`
      // draws for the person themselves.
      { method: 'GET', path: BASE + '/users/app-passwords', tag: 'Users',
        operationId: 'getUserAppPasswords',
        mirrors: 'GET /admin/users',
        parameters: [
          { name: 'username', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The older spelling of `user`, read when `user` ' +
                         'is absent.' },
          { name: 'user', in: 'query', required: true,
            schema: { type: 'string' },
            description: 'The person, as /admin-api/users names them.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API app-passwords endpoint.");
          self.sendJson(res, 200, adminViews.appPasswordsJson(req.query));
          log.debug("Leaving the management API app-passwords endpoint.");
        } },

      // STORED CERTIFICATES, ONE PERSON'S (#1061). The list the Stored
      // certificates block on /admin/users draws.
      { method: 'GET', path: BASE + '/users/certificates', tag: 'Users',
        operationId: 'getUserCertificates',
        mirrors: 'GET /admin/users',
        parameters: [
          { name: 'user', in: 'query', required: true,
            schema: { type: 'string', examples: ['alice'] },
            description: 'The person, as /admin-api/users names them.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API certificates endpoint.");
          const answer = adminActions.storedCertificatesOf(
            String((req.query || {}).user || ''));
          if (!answer.ok) {
            errorCodes.mark(res, errorCodes.codeOf(answer) ||
                                 'STS-API-0030');
          }
          self.sendJson(res, answer.ok ? 200 : 400, answer);
          log.debug("Leaving the management API certificates endpoint.");
        } },

      // DEVICES, ONE PERSON'S (#130). The list the Devices block on
      // /admin/users draws.
      { method: 'GET', path: BASE + '/users/devices', tag: 'Users',
        operationId: 'getUserDevices',
        mirrors: 'GET /admin/users',
        parameters: [
          { name: 'username', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The older spelling of `user`, read when `user` ' +
                         'is absent.' },
          { name: 'user', in: 'query', required: true,
            schema: { type: 'string', examples: ['alice'] },
            description: 'The person, as /admin-api/users names them.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API devices endpoint.");
          self.sendJson(res, 200, adminViews.devicesJson(req.query));
          log.debug("Leaving the management API devices endpoint.");
        } },

      // SELF-ISSUED SUBJECTS, ONE PERSON'S (#129). The list the Self-issued
      // IDs block on /admin/users draws.
      { method: 'GET', path: BASE + '/users/self-issued-subjects',
        tag: 'Users', operationId: 'getUserSelfIssuedSubjects',
        mirrors: 'GET /admin/users',
        parameters: [
          { name: 'username', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The older spelling of `user`, read when `user` ' +
                         'is absent.' },
          { name: 'user', in: 'query', required: true,
            schema: { type: 'string', examples: ['alice'] },
            description: 'The person, as /admin-api/users names them.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API self-issued subjects " +
                    "endpoint.");
          self.sendJson(res, 200,
                        adminViews.selfIssuedSubjectsJson(req.query));
          log.debug("Leaving the management API self-issued subjects " +
                    "endpoint.");
        } },

      // PUBLISHED DIDs, ONE PERSON'S (#1291). The list the Published DIDs
      // block on /admin/users draws.
      { method: 'GET', path: BASE + '/users/published-dids',
        tag: 'Users', operationId: 'getUserPublishedDids',
        mirrors: 'GET /admin/users',
        parameters: [
          { name: 'username', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The older spelling of `user`, read when `user` ' +
                         'is absent.' },
          { name: 'user', in: 'query', required: true,
            schema: { type: 'string', examples: ['alice'] },
            description: 'The person, as /admin-api/users names them.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API published DIDs endpoint.");
          self.sendJson(res, 200, adminViews.publishedDidsJson(req.query));
          log.debug("Leaving the management API published DIDs endpoint.");
        } },

      // IDENTITY VERIFICATIONS, ONE PERSON'S, PAGED (#127). The list the
      // Identity verifications block on /admin/users draws.
      { method: 'GET', path: BASE + '/users/verifications', tag: 'Users',
        operationId: 'getUserVerifications',
        mirrors: 'GET /admin/users',
        parameters: [
          { name: 'username', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The older spelling of `user`, read when `user` ' +
                         'is absent.' },
          { name: 'user', in: 'query', required: true,
            schema: { type: 'string' },
            description: 'The person, as /admin-api/users names them.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API verifications endpoint.");
          self.sendJson(res, 200, adminViews.verificationsJson(req.query));
          log.debug("Leaving the management API verifications endpoint.");
        } },

      { method: 'GET', path: BASE + '/users/new', tag: 'Users',
        operationId: 'getNewUserForm',
        mirrors: 'GET /admin/users/new',
        parameters: [
          { name: 'user', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'A username to open the form for, which the form ' +
                         'starts from when the request gives no body.' },
          { name: 'invent', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256, examples: ['alice'] },
            description: 'A username: the answer carries `invented`, the ' +
                         'attribute values this service would invent for ' +
                         'that person, which the console\'s Fill button ' +
                         'puts into every box nobody has typed in. **In ' +
                         'development mode only** — elsewhere `invented` is ' +
                         'null and `inventRefused` says why. It creates ' +
                         'nobody.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API new-user endpoint.");
          // STRAIGHT TO THE LAYER, like the new-application resource beside it.
          const answer: any = adminViews.newUserJson(req);
          // FILL (#446): what the server-rendered form's Fill button
          // answered in its own POST, asked for here because the static
          // console has no other door to it. Refused as well as undrawn in
          // product: a control that is only hidden is not a control that
          // is off.
          if (req.query.invent !== undefined) {
            const name = String(req.query.invent || '').trim();
            if (!answer.offersExampleData) {
              errorCodes.mark(res, 'STS-ADMIN-0016');
              answer.invented = null;
              answer.inventRefused = 'Example data is a development-mode ' +
                'convenience and this service is running as a product ' +
                '(global.mode=product), so nothing was filled in. Type what ' +
                'you know.';
            } else if (!name) {
              errorCodes.mark(res, 'STS-ADMIN-0017');
              answer.invented = null;
              answer.inventRefused = 'Type a username first. The example ' +
                'person is seeded FROM the username, so there is nothing ' +
                'to invent until there is a name to invent it from.';
            } else {
              answer.invented = adminViews.inventedFieldValues(name);
            }
          }
          self.sendJson(res, 200, answer);
          log.debug("Leaving the management API new-user endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/users/:action', tag: 'Users',
        // TWO CONSOLE PATHS, AND BOTH ARE NAMED. One resource legitimately
        // mirrors several controls — /admin-api/xacml/{action} names three —
        // and this action switch is reached from the Users list and from
        // /admin/users/new, which posts to itself rather than to the list so
        // that a generated password and an activation link can be answered in a
        // page body rather than in a 303's query string. Naming only the first
        // would leave the console suite unable to tell that page's Create
        // button from a control that reaches nothing. A THIRD since
        // 2026-10-01: a person's field grid posts to /admin/users/edit, which
        // reaches `update-fields` here. A FOURTH since #600: a person's
        // service account form posts to /admin/users/service-account, whose
        // Save reaches `set-service-account` with the owners table.
        mirrors: 'POST /admin/users, POST /admin/users/new, POST ' +
                 '/admin/users/edit and POST /admin/users/service-account',
        handler: function (req, res) {
          log.debug("Entering the management API users action endpoint.");
          const body = parseBody(req);
          const request = self.withAction(req, body);
          if (self.reauthenticationOwed(res, request.action)) {
            self.refuseStaleSignIn(req, res);
            log.debug("Leaving the management API users action. Sign in again.");
            return undefined;
          }
          // A PASSWORD IN THE REQUEST IS SCREENED AGAINST PWNED PASSWORDS
          // FIRST (#62 P6), for the console route's reason: the action is
          // synchronous and reads the verdict this leaves.
          return require('../common/breached_passwords')
            .screenAll([request.password]).then(function () {
          // A CREATE CLAIMS ITS NAME FIRST — see `claimForCreate()`.
          return self.runClaimed(res, request.action === 'create'
            ? { username: String(request.username || request.user || '') }
            : null, function (held) {
            // `via: 'api'` and the subject of the token the gate verified,
            // for the audit rows this action writes (#446). It was an empty
            // actor while this API authenticated only clients; with no token
            // (development's open API) it still is.
            const answered = adminActions.usersAction(request,
                                             { via: 'api',
                                               actor: self.callerNameOf(res),
                                               // WHO IS ENROLLING A PASSKEY
                                               // FOR SOMEBODY (#945): the
                                               // token's subject, a person,
                                               // or nobody.
                                               admin: self.callerPersonOf(res),
                                               // The address a password reset
                                               // link is built on (2026-09-13).
                                               base: baseUrlOf(req) });
            const send = function (result) {
              log.debug("Entering send().");
              held.settle(!!result.ok);
              // A CREATE'S ACTIVATION LINK, ABSOLUTE as well (#446): it is
              // pasted into a message, and the address it is built on —
              // `global.publicBaseUrl` where one is pinned — is the
              // server's to know, not a browser's.
              if (result.ok &&
                  /^\//.test(String(result.activationUrl || ''))) {
                result.activationLink = baseUrlOf(req) +
                  result.activationUrl;
              }
              if (!result.ok) {
                errorCodes.mark(res, errorCodes.codeOf(result) ||
                                     'STS-API-0030');
              }
              self.sendJson(res, result.ok ? 200 : 400, result);
              log.debug("Leaving send().");
            };
            // AN ACTION THAT ANSWERS LATER (#693): a by-value did:web
            // enrolment fetches the DID document to pin its keys, so
            // `usersAction()` hands back a promise for that one act; every
            // other act still answers at once.
            if (answered && typeof answered.then === 'function') {
              log.debug("Leaving the management API users action " +
                        "endpoint. Answered when the action settles.");
              return answered.then(send, function (e) {
                log.debug("Caught in the management API users action " +
                          "endpoint: " + ((e && e.message) || e));
                held.settle(false);
                log.error(errorCodes.tag('STS-API-0136') + 'admin-api: ' +
                          'the users action ' + request.action + ' failed: ' +
                          ((e && e.message) || e));
                errorCodes.mark(res, 'STS-API-0136');
                self.sendJson(res, 500, { ok: false, errors: [
                  'The action failed: ' + ((e && e.message) || e)] });
              });
            }
            send(answered);
            log.debug("Leaving the management API users action endpoint.");
          });
            });
        },
        actions: [
          { action: 'issue-activation', operationId: 'issueActivationLink' },

          { action: 'create', operationId: 'createUser' },

          // THE OPERATION THAT WAS DOCUMENTED BEFORE IT EXISTED (2026-09-06).
          // `common/credentials.ts` names `POST /admin-api/users/set-password`
          // twice — in the sentence a refused sign-in gets, and in the banner
          // the product-mode bootstrap prints telling an operator to change the
          // generated password — and no such operation had ever been written.
          // Somebody following either instruction got a 404 naming an endpoint
          // this service documents.
          { action: 'set-password', operationId: 'setUserPassword' },

          // -----------------------------------------------------------------
          // THE TWO SECOND-FACTOR REMOVALS (2026-09-10). They are `POST
          // /admin-api/mfa/clear-totp` and `/clear-key` as well — the same two
          // acts through the same switch — and both spellings work because the
          // console control moved and a caller's script did not.
          //
          // **THERE IS NO ENROL BESIDE THEM AND THERE CANNOT BE.** Enrolling an
          // authenticator means being shown a shared secret, and a management
          // API that handed one out would be an administrative door that mints
          // a working second factor for any account — which is not a second
          // factor at all. A WebAuthn ceremony happens in the person's own
          // browser against their own authenticator, which no API can stand in
          // for. Both are `/portal`, or `/portal/activate` with a link that is
          // itself a credential.
          // -----------------------------------------------------------------
          { action: 'clear-totp', operationId: 'clearUserAuthenticatorApp' },

          // -----------------------------------------------------------------
          // THE THIRD REMOVAL (2026-09-10), AND IT IS ALSO THE ONLY ISSUING
          // CONTROL THIS API HAS FOR RECOVERY CODES.
          //
          // There is no `issue-backup-codes` beside it and there will not be,
          // for the reason the two above have no `enrol`: a set is created by
          // the ACT of enrolling a second factor and by nothing else, and a
          // management API that minted one would be an administrative door
          // handing a working second factor to any account. What this operation
          // does is DELETE a set, which re-arms the automatic issue — the next
          // second factor that person enrols creates a new one.
          // -----------------------------------------------------------------
          { action: 'clear-backup-codes', operationId: 'clearUserBackupCodes' },

          // THE EMAILED SECOND FACTOR AND THE ADDRESS (#64).
          { action: 'clear-email-factor', operationId: 'clearUserEmailFactor' },

          { action: 'set-aud-sub', operationId: 'setUserAudSub' },

          { action: 'set-mail', operationId: 'setUserMail' },

          { action: 'set-pseudonyms', operationId: 'setUserPseudonyms' },

          { action: 'set-attribute', operationId: 'setUserAttribute' },

          { action: 'add-attribute', operationId: 'addUserAttributeValue' },

          { action: 'remove-attribute', operationId: 'removeUserAttributeValue' },

          // SEVERAL OF A PERSON'S ATTRIBUTES AT ONCE (2026-10-01): what the
          // Save of a tab of the person's field grid on /admin/users does.
          { action: 'update-fields', operationId: 'updateUserFields' },

          // -----------------------------------------------------------------
          // WHAT AN ADMINISTRATOR DOES TO SOMEBODY'S CREDENTIALS (2026-09-13),
          // mirroring the Password and second-factor controls on a person's
          // /admin/users page. Every one says what it did over Shared Signals —
          // a CAEP credential-change per credential, RISC
          // account-credential-change-required for a reset, RISC
          // recovery-information-changed for cleared recovery codes — to every
          // stream that asked for the type and covers the person.
          // -----------------------------------------------------------------
          { action: 'reset-password', operationId: 'resetUserPassword' },

          { action: 'issue-password-reset',
            operationId: 'issuePasswordResetLink' },

          { action: 'disable-primary-keys', operationId: 'disableUserPasskeys' },

          { action: 'disable-mfa', operationId: 'disableUserSecondFactors' },

          { action: 'require-mfa', operationId: 'requireUserSecondFactor' },

          { action: 'stop-requiring-mfa',
            operationId: 'stopRequiringUserSecondFactor' },

          // A SERVICE ACCOUNT (#221, 2026-10-06), drawn on the person's
          // /admin/users page and the new user screen. Rule 7.
          { action: 'set-service-account',
            operationId: 'setUserServiceAccount' },

          // ONE OWNER, OR THE DESTINATION, AT ONCE (#602): what the person
          // page's Add, Remove and Use save the moment they are pressed.
          { action: 'add-service-account-owner',
            operationId: 'addServiceAccountOwner' },
          { action: 'remove-service-account-owner',
            operationId: 'removeServiceAccountOwner' },
          { action: 'set-service-account-destination',
            operationId: 'setServiceAccountDestination' },

          { action: 'rotate-password',
            operationId: 'rotateServiceAccountPassword' },

          // WHO MAY ACT FOR A PERSON (#108, 2026-09-23) — the person's half
          // of the delegation policy (`common/delegation_policy.ts`), drawn
          // on their /admin/users page. Rule 7.
          { action: 'set-not-delegated', operationId: 'setUserNotDelegated' },

          { action: 'set-may-act', operationId: 'setUserMayAct' },

          { action: 'set-delegation-semantics',
            operationId: 'setUserDelegationSemantics' },

          { action: 'answer-ciba-request',
            operationId: 'answerUserCibaRequest' },

          { action: 'remove-device', operationId: 'removeUserDevice' },

          { action: 'add-certificate', operationId: 'addUserCertificate' },

          { action: 'remove-certificate',
            operationId: 'removeUserCertificate' },

          { action: 'issue-signing-certificate',
            operationId: 'issueUserSigningCertificate' },

          { action: 'revoke-signing-certificate',
            operationId: 'revokeUserSigningCertificate' },

          { action: 'enrol-self-issued-subject',
            operationId: 'enrolUserSelfIssuedSubject' },

          { action: 'remove-self-issued-subject',
            operationId: 'removeUserSelfIssuedSubject' },

          { action: 'set-preferred-self-issued-subject',
            operationId: 'setUserPreferredSelfIssuedSubject' },

          { action: 'deactivate-published-did',
            operationId: 'deactivateUserPublishedDid' },

          { action: 'record-verification',
            operationId: 'recordUserVerification' },

          { action: 'remove-verification',
            operationId: 'removeUserVerification' },

          { action: 'disable', operationId: 'disableUserAccount' },

          { action: 'enable', operationId: 'enableUserAccount' },

          // #109 (2026-09-22): which partners' subjects sign a person in.
          { action: 'federation-link', operationId: 'linkUserFederation' },

          { action: 'federation-unlink', operationId: 'unlinkUserFederation' },

          // -----------------------------------------------------------------
          // APP PASSWORDS (#101, 2026-09-22), mirroring the App passwords
          // block on a person's /admin/users page — which is also where the
          // person's own `/portal/app-passwords` points an administrator.
          // -----------------------------------------------------------------
          { action: 'create-app-password',
            operationId: 'createUserAppPassword' },

          { action: 'revoke-app-password',
            operationId: 'revokeUserAppPassword' },

          // #939: the administrator proves the existing classical passkey
          // in their browser before the API arms ML-DSA registration. These
          // are separate operations because the proof is one-use and the
          // person must approve each ceremony in the authenticator.
          { action: 'begin-passkey-upgrade',
            operationId: 'beginUserPasskeyUpgrade' },
          { action: 'prove-passkey-upgrade',
            operationId: 'proveUserPasskeyUpgrade' },
          { action: 'finish-passkey-upgrade',
            operationId: 'finishUserPasskeyUpgrade' },
          { action: 'cancel-passkey-upgrade',
            operationId: 'cancelUserPasskeyUpgrade' },

          { action: 'clear-key', operationId: 'clearUserSecurityKey' },

          // #470 (rcbj's decision D): the console's Rename on a person's
          // Passkeys table, and the same writer the person's own
          // `/portal/rename-key` calls.
          { action: 'rename-key', operationId: 'renameUserPasskey' },

          // #945: AN ADMINISTRATOR ENROLS A PASSKEY ON A PERSON'S BEHALF,
          // the console's *Enrol a passkey for this person* on their page.
          // Two acts, the person's own enrolment's two steps; the ceremony
          // between them runs in the caller's browser.
          { action: 'begin-passkey-enrolment',
            operationId: 'beginUserPasskeyEnrolment' },

          { action: 'finish-passkey-enrolment',
            operationId: 'finishUserPasskeyEnrolment' }
        ] }),

      // ---------------------------------------------------------------------
      // SESSIONS. The other half of /tokens, and the resource behind
      // /admin/sessions — rule 7, in the same change as the page.
      //
      // It is a SEPARATE resource from /logout rather than a shape of it, and
      // the two questions are why: that one is *what is alice still signed
      // into*, keyed on one identity and reaching eleven families (ten until
      // the wallet sign-in of 2026-09-17, #38); this one is
      // *who is signed in at all*, across everybody, in the three families that
      // have a session. A `user` parameter on the one below could not have
      // answered it, because the answer has no user in it.
      //
      // Both read `logout/logout.ts`, which is the one model of what a live
      // session is — and the POST here is `terminate()` with a selection of
      // one, the SAME function `POST /admin-api/logout/selective` calls. Two
      // operations over one termination, which is the arrangement rule 7 asks
      // for: the console grew a button, so this grew the operation that mirrors
      // it.
      { method: 'GET', path: BASE + '/sessions', tag: 'Sessions',
        operationId: 'getSessions',
        mirrors: 'GET /admin/sessions',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Narrows to rows whose username, subject, handle, ' +
                         'identity key, kind or protocol contains this. One ' +
                         'box over all of them, because a reader arrives ' +
                         'holding exactly one and does not know which.' },
          { name: 'protocol', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Only sessions started through this protocol. The ' +
                         '`protocol` values in the reply are what there is ' +
                         'to ask for; they are read off the live rows rather ' +
                         'than written down, because a federated sign-in ' +
                         'names the relationship it came through.' },
          { name: 'anonymousPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of `unauthenticatedSessions`, the ' +
                         'sessions that authenticated nobody. They are ' +
                         'never filtered, and `unauthenticatedHeld` counts ' +
                         'them all. It shares `per` with the live list.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res, next) {
          log.debug("Entering the management API sessions endpoint.");
          // `.json`, because the view returns the whole MODEL — the rows,
          // the paging and the filters the page needs, with the machine answer
          // inside it. The console used to export a wrapper that unwrapped it
          // here, and repointing this call at the layer without the unwrap
          // answered the model: `/admin-api/sessions` reported 0 sessions for a
          // person holding nine, with nothing erroring.
          //
          // FROM THE SESSION INDEX while the window is on (#820): the whole
          // list held a request worker for two minutes at 470,000 sessions.
          adminViews.sessionsViewAsync(req).then(function (view) {
            self.sendJson(res, 200, view.json);
            log.debug("Leaving the management API sessions endpoint.");
          }).catch(function (e) {
            log.debug("Caught in the management API sessions endpoint: " +
                      ((e && e.message) || e));
            next(e);
          });
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/sessions/:action', tag: 'Sessions',
        mirrors: 'POST /admin/sessions',
        handler: function (req, res) {
          log.debug("Entering the management API sessions action endpoint.");
          const body = parseBody(req);
          // `by` REACHES THE EVENT and not only the audit row: the session
          // family spends it as the `via` it hands `endSessionById()`, which
          // is the sentence in CAEP's `reason_admin`. Who ended it — `admin`
          // here — is stated by `sessionsAction()` itself since #242, rather
          // than read out of these words.
          const result = adminActions.sessionsAction(self.withAction(req, body),
            { by: 'the management API at /admin-api/sessions' });
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0031');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API sessions action endpoint.");
        },
        actions: [
          { action: 'revoke', operationId: 'revokeSession' },
          { action: 'end-all', operationId: 'endAllSessions' }
        ] }),

      { method: 'GET', path: BASE + '/logout', tag: 'Sign-out',
        operationId: 'getLiveSessions',
        mirrors: 'GET /admin/logout',
        parameters: [
          { name: 'user', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The identity to look at, as typed. It is ' +
                         'normalised the way every other door here ' +
                         'normalises one, so `alice`, `alice@REALM` and a ' +
                         '`urn:` subject are one answer.' },
          { name: 'family', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Only rows of this family. The `families` member of ' +
                         'the reply says which values there are; it is read ' +
                         'off the same table the endpoint acts on, so a ' +
                         'family that cannot occur is never offered.' },
          { name: 'deliveryState', in: 'query', required: false,
            schema: { type: 'string', enum: ['pending', 'sent', 'dead'] },
            description: 'Only back-channel Logout Token deliveries in this ' +
                         'state. `dead` is the dead-letter list, whose rows ' +
                         '`POST /admin-api/logout/retry-backchannel` sends ' +
                         'again.' },
          { name: 'deliveryq', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256 },
            description: 'Only deliveries whose client, session, address, ' +
                         'error code or person contains this.' },
          { name: 'backchannelDeliveriesPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the deliveries. Clamped, like every ' +
                         'page parameter here; `per` is shared with the ' +
                         'live rows.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API sign-out endpoint.");
          self.sendJson(res, 200, adminViews.logoutJson(req).json);
          log.debug("Leaving the management API sign-out endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/logout/:action', tag: 'Sign-out',
        mirrors: 'POST /admin/logout',
        handler: function (req, res) {
          log.debug("Entering the management API sign-out action endpoint.");
          const body = parseBody(req);
          const result = adminActions.logoutAction(self.withAction(req, body),
            { via: 'api', actor: self.callerNameOf(res) });
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0032');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API sign-out action endpoint.");
        },
        actions: [
          { action: 'global', operationId: 'globalLogout' },
          { action: 'end', operationId: 'endLiveSessions' },
          { action: 'retry-backchannel',
            operationId: 'retryBackchannelDelivery' },
          { action: 'restore-token', operationId: 'restoreLoggedOutToken' },
          { action: 'restore-kerberos', operationId: 'clearKerberosSignOut' }
        ] }),

      { method: 'GET', path: BASE + '/groups', tag: 'Groups',
        operationId: 'getGroups',
        mirrors: 'GET /admin/groups',
        parameters: [
          { name: 'group', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One group\'s DN. Returns the drill-down.' },
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the DN or the name, case-insensitive.' },
          // #459: the application page's search for
          // `appDelegationSubjectGroup`, which leaves out the groups its
          // list already holds — before the paging, so a page of five is
          // five.
          { name: 'exclude', in: 'query', required: false,
            schema: { type: 'array', items: { type: 'string' } },
            style: 'form', explode: true,
            description: 'A group DN to leave out of the match, compared as ' +
                         'LDAP compares a DN (case and the spaces after a ' +
                         'comma do not matter); repeat it for several. ' +
                         'Applied before the paging, so a page still holds ' +
                         '`per` rows. Ignored when `group` is given.' }
        ].concat(this.pagingParameters()).concat(this.detailPagingParameters([
          { name: 'members',
            description: 'The membership values of the group named by ' +
                         '`group`, resolved. `group.memberCount`, ' +
                         '`presentCount` and `danglingCount` beside them are ' +
                         'counts of the WHOLE list and not of the page — a ' +
                         'group whose seven members resolve to five is the ' +
                         'fact this resource exists to report, and a ' +
                         'per-page count would not be an answer to it.' },
          { name: 'claimed',
            description: 'Entries whose own memberOf names this group while ' +
                         'it does not list them back.' }
        ])),
        handler: function (req, res) {
          log.debug("Entering the management API groups endpoint.");
          self.sendJson(res, 200, adminViews.groupsJson(req));
          log.debug("Leaving the management API groups endpoint.");
        } },

      // -----------------------------------------------------------------------
      // AND THE TWO WRITES (2026-09-06), WHICH CLOSED A HOLE RATHER THAN ADDING
      // A FEATURE.
      //
      // Until today `/admin-api/groups` was a READ and so was `/admin/groups`,
      // and the only two doors onto a group in this directory were an `ldapadd`
      // on the raw socket and `POST /scim/v2/Groups`. So this API could put a
      // PERSON in the directory (`/users/create`) and could not put them in a
      // GROUP, and the console could report a dangling member, a claimed
      // membership and the two groups that decide who may use it without being
      // able to create any of them.
      //
      // **RULE 7 COULD NOT HAVE CAUGHT IT AND THAT IS THE INTERESTING PART.**
      // That rule is a parity check between the console and this API — every
      // control there has an operation here, every operation here names a
      // control there — and it is satisfied exactly when both are missing. It
      // reports drift, not absence. What found this was a load test that had to
      // reach for SCIM to make fifty groups on a service whose own management
      // API creates users five thousand at a time.
      //
      // THE ACTION SWITCH IS IN `adminActions.groupsAction()` and not here,
      // exactly as the users one is: two doors onto one action must not be two
      // readings of what was sent.
      // -----------------------------------------------------------------------
      ApiRows.actions({ method: 'POST',
        route: BASE + '/groups/:action', tag: 'Groups',
        // A SECOND CONSOLE PATH SINCE #603: the group page's Owners tab posts
        // to /admin/groups/owners, so its Find and Add are told apart from the
        // page's other forms; its Add and Remove reach `add-owner` and
        // `remove-owner` here.
        mirrors: 'POST /admin/groups and POST /admin/groups/owners',
        handler: function (req, res) {
          log.debug("Entering the management API groups action endpoint.");
          const body = parseBody(req);
          const request = self.withAction(req, body);
          // A CREATE CLAIMS ITS NAME FIRST — see `claimForCreate()`.
          return self.runClaimed(res, request.action === 'create'
            ? { group: String(request.group || request.displayName || '') }
            : null, function (held) {
            const result = adminActions.groupsAction(request,
              { via: 'api', actor: self.callerNameOf(res) });
            held.settle(!!result.ok);
            if (!result.ok) {
              errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0033');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API groups action endpoint.");
          });
        },
        actions: [
          { action: 'create', operationId: 'createGroup' },

          { action: 'add-member', operationId: 'addGroupMember' },

          // A GROUP'S EMAIL ADDRESS (#989): the group page's Email address
          // form. The directory owns the shape rule and the refusals.
          { action: 'set-mail', operationId: 'setGroupMail' },

          // THE POLICY A GROUP NAMES (#1235, rule 3cx): the group page's
          // picker, one per kind a group selects. The directory owns the
          // check and the refusals.
          { action: 'set-policy', operationId: 'setGroupPolicy' },

          // A GROUP'S OWNERS (#603): what the group page's Owners tab saves
          // the moment Add or Remove is pressed.
          { action: 'add-owner', operationId: 'addGroupOwner' },
          { action: 'remove-owner', operationId: 'removeGroupOwner' }
        ] }),

      // --- The directory itself, entry by entry
      // --------------------------------
      //
      // FIVE OPERATIONS ADDED ON 2026-09-01, ONE PER PAGE, AND THEY EXIST
      // BECAUSE OF RULE 7 RATHER THAN BECAUSE ANYBODY ASKED FOR THEM.
      //
      // `/ldap`, `/ldap/directory`, `/ldap/applications`, `/ldap/federations`
      // and `/ldap/spiffe` were five HTML pages outside the console until that
      // day. They are `/admin/ldap/*` now — console pages, in the console's
      // shell, behind its gate — and the rule this API is written under is that
      // every page of that console has an operation here that mirrors it. So
      // here they are, and the parity check in the suite is what would have
      // noticed if they were not.
      //
      // THE GATE IS THE POINT OF THEM AND NOT AN INCIDENTAL DIFFERENCE. Those
      // pages print `oauthClientSecret` and `fedClientSecret` in the clear,
      // which is why moving them behind the console's gate was the right half
      // of the change; this API takes an access token rather than a browser
      // session, which is what keeps a test able to read the directory without
      // signing a browser in. (It said "deliberately NOT gated" until
      // 2026-09-09, when this API began requiring a token — see the top of this
      // file.)
      //
      // EVERY ONE OF THEM CALLS THE FUNCTION THAT DRAWS THE PAGE, through
      // `adminViews.directoryPageJson()` and the slot `ldap/ldap_server.js`
      // fills — see the block above `setDirectoryPages()` in
      // `admin-ui/admin.ts` for why it cannot be a plain require from here. So
      // a page and its operation cannot come to disagree about what is in the
      // directory: there is one function and it is in the module that owns the
      // store.
      { method: 'GET', path: BASE + '/ldap/directory', tag: 'LDAP',
        operationId: 'getDirectoryEntries',
        mirrors: 'GET /admin/ldap/directory',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the DN, of an attribute name, or of ' +
                         'an attribute value. Case-insensitive.' },
          { name: 'origin', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Only entries that came from here. The values ' +
                         'actually present are in `origins`.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API directory entries endpoint.");
          // A PROMISE IN A WINDOWED PROCESS (#616): the page is asked of the
          // store asynchronously there, so the event loop runs while the
          // database answers. Awaited here and the rejection CAUGHT —
          // Express 4 does not look at what a handler returns — as a 503:
          // the store could not be read, which says nothing about the
          // directory's contents. The rejection's own code where it carries
          // one (the bridge's STS-LDAP-0130/0131), STS-LDAP-0139 otherwise.
          Promise.resolve(adminViews.directoryPageJson('directory', req))
            .then(function (json) {
              self.sendJson(res, 200, json);
              log.debug("Leaving the management API directory entries " +
                        "endpoint.");
            }, function (e) {
              log.debug("Caught in the management API directory entries " +
                        "endpoint: " + ((e && e.message) || e));
              // 503 for a store it could not read, 500 for anything else
              // (#695: every failure was a "try again shortly").
              self.answerDirectoryFailure(res, e, 'the directory page',
                                          'STS-LDAP-0176');
              log.debug("Leaving the management API directory entries " +
                        "endpoint. Unavailable.");
            });
        } },

      { method: 'GET', path: BASE + '/ldap/applications', tag: 'LDAP',
        operationId: 'getDirectoryApplications',
        mirrors: 'GET /admin/ldap/applications',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the identifier, the name, the DN or ' +
                         'any attribute value. Case-insensitive.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API directory applications " +
                    "endpoint.");
          self.sendJson(res, 200,
                        adminViews.directoryPageJson('applications', req));
          log.debug("Leaving the management API directory applications " +
                    "endpoint.");
        } },

      { method: 'GET', path: BASE + '/ldap/federations', tag: 'LDAP',
        operationId: 'getDirectoryFederations',
        mirrors: 'GET /admin/ldap/federations',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the relationship id, the DN, the ' +
                         'protocol or the direction. Case-insensitive.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API directory federations " +
                    "endpoint.");
          self.sendJson(res, 200,
                        adminViews.directoryPageJson('federations', req));
          log.debug("Leaving the management API directory federations " +
                    "endpoint.");
        } },

      { method: 'GET', path: BASE + '/ldap/spiffe', tag: 'LDAP',
        operationId: 'getDirectorySpiffe',
        mirrors: 'GET /admin/ldap/spiffe',
        parameters: [
          { name: 'entryq', in: 'query', required: false,
            schema: { type: 'string' },
            description:
              'Substring of a registration entry\'s SPIFFE ID or DN.' },
          { name: 'agentq', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Substring of an attested agent\'s id or DN.' }
        ].concat(this.pagingParameters()).concat(this.detailPagingParameters([
          { name: 'entries', description: 'The registration entries.' },
          { name: 'agents', description: 'The attested agents.' }
        ])),
        handler: function (req, res) {
          log.debug("Entering the management API directory SPIFFE endpoint.");
          self.sendJson(res, 200, adminViews.directoryPageJson('spiffe', req));
          log.debug("Leaving the management API directory SPIFFE endpoint.");
        } },

      // ---------------------------------------------------------------------
      // THE THREE ADDED ON 2026-09-05, and they are here for rule 7 rather than
      // by analogy: `ou=roles`, `ou=policies` and `ou=peps` each gained a
      // console page that day, and every page of the console has an operation.
      // What made the pages worth writing is that all three modules already
      // PUBLISHED a schema whose comment claimed a page under `/admin/ldap/*`
      // and none of them had one — `common/roles.js` from that afternoon,
      // `xacml/xacml_store.ts` from XACML phase two,
      // `xacml/xacml_pep_registry.ts` from phase five.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/ldap/roles', tag: 'LDAP',
        operationId: 'getDirectoryRoles',
        mirrors: 'GET /admin/ldap/roles',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of a role name, a DN, or any value on ' +
                         'the entry — which includes its members, so this is ' +
                         'how to find the roles one person holds by name.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API directory roles endpoint.");
          self.sendJson(res, 200, adminViews.directoryPageJson('roles', req));
          log.debug("Leaving the management API directory roles endpoint.");
        } },

      { method: 'GET', path: BASE + '/ldap/policies', tag: 'LDAP',
        operationId: 'getDirectoryPolicies',
        mirrors: 'GET /admin/ldap/policies',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of a policy name, a DN, or any value on ' +
                         'the entry — the DOCUMENT included, so this finds ' +
                         'the policy that names a particular resource.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API directory policies endpoint.");
          self.sendJson(res, 200,
                        adminViews.directoryPageJson('policies', req));
          log.debug("Leaving the management API directory policies endpoint.");
        } },

      { method: 'GET', path: BASE + '/ldap/peps', tag: 'LDAP',
        operationId: 'getDirectoryPeps',
        mirrors: 'GET /admin/ldap/peps',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of a PEP name, a DN, or any value on the ' +
                         'entry — a certificate subject or a notify URL ' +
                         'included.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API directory PEPs endpoint.");
          self.sendJson(res, 200, adminViews.directoryPageJson('peps', req));
          log.debug("Leaving the management API directory PEPs endpoint.");
        } },

      // THE DEVICE REGISTER AS THE DIRECTORY HOLDS IT (#164, #218): the
      // ninth, drawn by `ldap/ldap_server.js` like the other eight.
      { method: 'GET', path: BASE + '/ldap/devices', tag: 'LDAP',
        operationId: 'getDirectoryDevices',
        mirrors: 'GET /admin/ldap/devices',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the DN or of any value but the ' +
                         'withheld one.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API directory devices " +
                    "endpoint.");
          Promise.resolve(adminViews.directoryPageJson('devices', req))
            .then(function (json) {
              self.sendJson(res, 200, json);
              log.debug("Leaving the management API directory devices " +
                        "endpoint.");
            }, function (e) {
              log.debug("Caught in the management API directory devices " +
                        "endpoint: " + ((e && e.message) || e));
              self.answerDirectoryFailure(res, e, 'the devices page',
                                          'STS-LDAP-0176');
              log.debug("Leaving the management API directory devices " +
                        "endpoint. Refused.");
            });
        } },

      // LAST OF THE EIGHT, and it is the one that answers about the SOCKETS
      // rather than about what is in the store. It is deliberately not `GET
      // /admin-api/ldap`, which is the SETTINGS: that one says what the ports
      // and the base DN are SET to, and this one says what actually happened
      // when the process tried to bind them. On a host where the system's own
      // slapd already holds 389 those two replies disagree, and the
      // disagreement is the whole value of having both.
      { method: 'GET', path: BASE + '/ldap/service', tag: 'LDAP',
        operationId: 'getDirectoryService',
        mirrors: 'GET /admin/ldap/service',
        parameters: [],
        handler: function (req, res) {
          log.debug("Entering the management API directory service endpoint.");
          self.sendJson(res, 200, adminViews.directoryPageJson('service', req));
          log.debug("Leaving the management API directory service endpoint.");
        } },

      // --- The console's own roles
      // ---------------------------------------------
      //
      // TWO OPERATIONS, AND THIS RESOURCE MATTERS MORE THAN THE OTHERS RATHER
      // THAN LESS. Rule 7 says a console control gets an operation in the same
      // change; here the API half is not merely parity, it is the ONLY door
      // onto the roster that still works when nobody holds a role and
      // `admin.openWhenEmpty` is off — or in product mode, which never opens
      // the console to whoever signs in (#103). The console cannot let you
      // fix that — you
      // cannot reach it — so this can. It reaches it with a DIFFERENT
      // credential: an access token carrying `admin:write`, rather than the
      // console session the roster gates.
      //
      // **THIS COMMENT SAID `/admin-api` WAS UNGATED AND THAT WAS TRUE UNTIL
      // 2026-09-09.** It went on: WITH THE CONSOLE PROTECTED AND THIS API OPEN,
      // ANYBODY WHO CAN REACH THIS PORT CAN GRANT THEMSELVES BOTH ROLES — which
      // is exactly what `adminApi.authRequired` closed. What has NOT changed is
      // that the console's gate exists so a client can be driven through 302 /
      // 401 / 403 and a role model, not to make this service safe to expose: in
      // the default development mode no password is checked anywhere and
      // `/oauth2/token` will mint a token for any username asked of it. Do not
      // put this port on a public address.
      { method: 'GET', path: BASE + '/rbac', tag: 'Admin roles',
        operationId: 'getAdminRoles',
        mirrors: 'GET /admin/rbac',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the person\'s name or of the raw ' +
                         'membership value, case-insensitive.' },
          { name: 'role', in: 'query', required: false,
            schema: { type: 'string', enum: rbac.ROLE_IDS },
            description: 'Only grants of this role.' },
          { name: 'personq', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Narrows `candidates` — the people a role could be ' +
                         'granted to — to usernames containing this, ' +
                         'case-insensitive. Where the directory is held in ' +
                         'memory the list is the directory and who has ' +
                         'signed in; where it is a window (#359) it is the ' +
                         'direct children of ou=users, a page at a time, ' +
                         'and a person who has signed in with no entry is ' +
                         'not listed (a typed name can still be granted). ' +
                         '`candidateSearch` says how many candidates there ' +
                         'are in all and how many matched. A windowed ' +
                         'search\'s count stops at `countCap` (100,000, ' +
                         'the furthest the pager reaches; #1308): where ' +
                         'more match, `matched` is `countCap` and ' +
                         '`countCapped` is true — MORE THAN `matched` ' +
                         'match, and `candidatesPaging` stops there. Held ' +
                         'in memory, the count is exact and `countCapped` ' +
                         'is false. `complete` says ' +
                         'whether this page holds every one it counted: ' +
                         'where it is false, `incomplete` says how many ' +
                         'names a DN cannot hold were left out ' +
                         '(`unusable`), how many counted rows the page ' +
                         'did not reach (`short`, most often two entries ' +
                         'sharing one RDN value), and whether the list ' +
                         'stops at the walk\'s cap (`capped`, `cap`).' },
          { name: 'candidatesPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the matching `candidates`, answered ' +
                         'in `candidatesPaging`. Clamped like `page`. The ' +
                         'page size is `per` when given — shared with ' +
                         '`grants`, as on every reply here carrying two ' +
                         'lists — and otherwise twenty, the size of the ' +
                         'console\'s results pane. `candidates` was the ' +
                         'whole list until 2026-09-13, which on a ' +
                         'directory of thousands was thousands of ' +
                         'rows on every read of the roster.' },
          { name: 'personfrom', in: 'query', required: false,
            schema: { type: 'integer', minimum: 0 },
            description: 'The console results pane\'s OFFSET into the ' +
                         'matching candidates, answered as the page it falls ' +
                         'on. Ignored when `candidatesPage` is given, and ' +
                         'when it is past the end.' },
          { name: 'person', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'A username to look up among ALL the candidates, ' +
                         'not only the page shown. ' +
                         '`picked.candidate` is its row, ' +
                         'or null when nobody by that name could be picked.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API admin roles endpoint.");
          // The layer, not the page: rbacView() built two tables and four forms
          // and this resource used none of them.
          Promise.resolve(adminViews.rbacListJson(req)).then(function (body) {
            self.sendJson(res, 200, body.json);
            log.debug("Leaving the management API admin roles endpoint.");
          }, function (e) {
            log.debug("Caught in the management API admin roles endpoint: " +
                      ((e && e.message) || e));
            self.answerDirectoryFailure(res, e, 'the role roster',
                                        'STS-LDAP-0176');
            log.debug("Leaving the management API admin roles endpoint. " +
                      "Refused.");
          });
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/rbac/:action', tag: 'Admin roles',
        mirrors: 'POST /admin/rbac',
        handler: function (req, res) {
          log.debug("Entering the management API admin roles action endpoint.");
          const body = parseBody(req);
          // `via: 'api'` and an empty actor, for the audit row. The console
          // passes its signed-in user here; this API passes the subject of
          // the token its gate verified (#446), and nobody where no token was
          // required.
          const result = adminActions.rbacAction(self.withAction(req, body),
            { via: 'api', actor: self.callerNameOf(res) });
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0034');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API admin roles action endpoint.");
        },
        actions: [
          { action: 'grant', operationId: 'grantAdminRole' },

          { action: 'revoke', operationId: 'revokeAdminRole' }
        ] }),

      // ---------------------------------------------------------------------
      // MULTI-FACTOR AUTHENTICATION (2026-09-10).
      //
      // **THE CONSOLE PAGE THIS MIRRORED IS GONE AND THIS RESOURCE IS NOT.**
      // `/admin/mfa` lasted hours: it edited the `totp.*` settings AND drew a
      // roster of who held a second factor, and one page could not be filed by
      // both halves. The settings are `/admin/totp` and `/admin/webauthn` under
      // Protocols; the roster is columns on `/admin/users` and the per-person
      // detail is on that person's own row.
      //
      // Rule 7 says a console control owes an operation. It says nothing about
      // an operation whose page moved, and deleting a working one to tidy a
      // table would be a regression dressed as consistency — the same argument
      // `GET /admin-api/users/new` is kept on. So this stays, `mirrors` points
      // at the page that absorbed it, and `adminViews.mfaRosterJson()` answers
      // OUT OF THAT VIEW so there is one tally rather than two scans that agree
      // until they do not.
      //
      // **THE READ IS A REPORT AND THE WRITE IS A RESET**, and there is
      // deliberately no ENROL operation here. Enrolling means being shown a
      // shared secret, and a management API that handed one out would be an
      // administrative door that mints a working second factor for any account
      // — which is not a second factor at all. Enrolment happens where the
      // person is: `/portal/mfa`, or `/portal/activate` with a link that is
      // itself a credential.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/mfa', tag: 'Multi-factor authentication',
        operationId: 'getMultiFactor',
        mirrors: 'GET /admin/users',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the person\'s name, case-insensitive.' },
          { name: 'factor', in: 'query', required: false,
            schema: { type: 'string',
                      enum: ['any', 'totp', 'key', 'none', 'unreadable'] },
            description: '`any` is anybody holding a second factor of either ' +
                         'kind; `none` is the complement of it; ' +
                         '`unreadable` is a factor whose sealed secret this ' +
                         'service can no longer open.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API multi-factor endpoint.");
          // The list's directory names asked asynchronously (#616), as
          // `GET /admin-api/users` asks them.
          adminViews.mfaRosterJsonAsync(req).then(function (json) {
            self.sendJson(res, 200, json);
            log.debug("Leaving the management API multi-factor endpoint.");
          }, function (e) {
            log.debug("Caught in the management API multi-factor " +
                      "endpoint: " + ((e && e.message) || e));
            // 503 for a store it could not read, 500 for anything else
            // (#695: every failure was a "try again shortly").
            self.answerDirectoryFailure(res, e, 'the multi-factor roster',
                                        'STS-LDAP-0176');
          });
        } },

      ApiRows.actions({ method: 'POST', route: BASE + '/mfa/:action',
        tag: 'Multi-factor authentication',
        mirrors: 'POST /admin/users',
        handler: function (req, res) {
          log.debug("Entering the management API multi-factor action " +
                    "endpoint.");
          const body = parseBody(req);
          if (self.reauthenticationOwed(res, req.params.action)) {
            self.refuseStaleSignIn(req, res);
            log.debug("Leaving the management API multi-factor action. Stale.");
            return undefined;
          }
          // `via: 'api'` and whatever actor the caller named, for the audit row
          // — `rbacAction`'s caller's rule: the subject of the token the
          // gate verified (#446), and nobody where no token was required.
          const result = adminActions.mfaAction(self.withAction(req, body),
            { via: 'api', actor: self.callerNameOf(res) });
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0035');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API multi-factor action endpoint.");
        },
        actions: [
          { action: 'clear-totp', operationId: 'clearAuthenticatorApp' },

          { action: 'clear-key', operationId: 'clearSecurityKey' },

          { action: 'clear-email-factor', operationId: 'clearEmailFactor' }
        ] }),

      // ONE CREDENTIAL'S LINEAGE (#446): the console page had no
      // operation, having no form; see
      // `AdminViews.credentialLineageModel()`.
      { method: 'GET', path: BASE + '/tokens/credential', tag: 'Tokens',
        operationId: 'getCredentialLineage',
        mirrors: 'GET /admin/tokens/credential',
        parameters: [
          { name: 'id', in: 'query', required: false,
            schema: { type: 'string', examples: ['no-such-credential'] },
            description: 'The credential\'s identifier, as the tokens ' +
                         'table shows it.' },
          { name: 'format', in: 'query', required: false,
            schema: { type: 'string', enum: ['json', 'svg'],
                      examples: ['json'] },
            description: '`svg` answers the drawing alone, as a document ' +
                         'with no links in it. `json`, the default, ' +
                         'answers everything.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API credential lineage " +
                    "endpoint.");
          if (String((req.query || {}).format || '') === 'svg') {
            const bare = adminViews.credentialLineageModel(req.query,
                                                           { links: false });
            res.status(200).set('Cache-Control', 'no-store')
               .type('image/svg+xml').send(bare.svg);
            log.debug("Leaving the management API credential lineage " +
                      "endpoint. Answered SVG.");
            return;
          }
          self.sendJson(res, 200,
                        adminViews.credentialLineageModel(req.query));
          log.debug("Leaving the management API credential lineage " +
                    "endpoint.");
        } },

      { method: 'GET', path: BASE + '/tokens', tag: 'Tokens',
        operationId: 'getIssued',
        mirrors: 'GET /admin/tokens',
        parameters: [
          { name: 'family', in: 'query', required: false,
            schema: { type: 'string', enum: closed.tokenFamilies },
            description: 'One protocol family. The reply\'s `families` ' +
                         'member lists them with the kinds in each.' },
          { name: 'kind', in: 'query', required: false,
            schema: { type: 'string', enum: closed.tokenKinds },
            description: 'One kind. ANDed with `family`, so a kind from ' +
                         'another family matches nothing — which is what an ' +
                         'empty list then means.\n\n**EVERY FILTER HERE ' +
                         'MATCHES A SET WHEN ANY MEMBER MATCHES.** Asking ' +
                         'for `id_token` answers with the replies that ' +
                         'CONTAIN one — the access token and the refresh ' +
                         'token that came back with it are still in ' +
                         '`members`, because they are part of the same ' +
                         'reply. A caller that wants only the matching ' +
                         'credentials filters `issued` itself; a filter that ' +
                         'hid the neighbours would be the old per-credential ' +
                         'list wearing this one\'s name.' },
          { name: 'state', in: 'query', required: false,
            schema: { type: 'string',
                      enum: ['valid', 'expired', 'revoked', 'not yet valid',
                             'no expiry stated'] },
            description: 'One state, matched against any member — so a set ' +
                         'holding an expired access token and a valid ' +
                         'refresh token is found by both, and its own ' +
                         '`state` reads `mixed` rather than picking one.' },
          { name: 'session', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Only what was issued UNDER one browser sign-on ' +
                         'session, matched exactly on the id — the ' +
                         '`sessionId` every row of GET /admin-api/sessions ' +
                         'carries, and the join between the two ' +
                         'resources.\n\nOnly a credential issued under a ' +
                         'session records one, so an assertion, a Kerberos ' +
                         'ticket, a token from either direct grant and ' +
                         'anything an RFC 8693 exchange produced are absent ' +
                         'by construction rather than ' +
                         'missing. That is a fact about ' +
                         'the credential and not a gap in the recording.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res, next) {
          log.debug("Entering the management API issued-list endpoint.");
          // From the store on demand (2026-10-22, #820): one session's
          // every record, or the newest, and the store's count — never a
          // walk of what this worker happens to hold.
          adminViews.tokensViewAsync(req.query).then(function (view) {
            self.sendJson(res, 200, view.json);
            log.debug("Leaving the management API issued-list endpoint.");
          }).catch(function (e) {
            log.debug("Caught in the management API issued-list endpoint: " +
                      ((e && e.message) || e));
            next(e);
          });
        } },

      { method: 'GET', path: BASE + '/tokens/set', tag: 'Tokens',
        operationId: 'getIssuedSet',
        mirrors: 'GET /admin/tokens/set',
        parameters: [
          { name: 'id', in: 'query', required: true,
            schema: { type: 'string', examples: ['no-such-set'] },
            description: 'The `setKey` off a row of GET /admin-api/tokens.' }
        ],
        handler: function (req, res, next) {
          log.debug("Entering the management API issued-set endpoint.");
          // Found in the store by its key on demand (#820): `set:` through
          // the register's index, `one:` by the record's key.
          adminViews.tokenSetViewAsync(req.query).then(function (view) {
            self.sendJson(res, 200, view.json);
            log.debug("Leaving the management API issued-set endpoint.");
          }).catch(function (e) {
            log.debug("Caught in the management API issued-set endpoint: " +
                      ((e && e.message) || e));
            next(e);
          });
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/tokens/:action', tag: 'Tokens',
        mirrors: 'POST /admin/tokens',
        handler: function (req, res) {
          log.debug("Entering the management API token action endpoint.");
          const body = parseBody(req);
          // A revoke-all, by kind or by user answers with a promise while
          // the register is on demand (#820): a walk of the store that
          // gives the event loop back between its pages.
          return Promise.resolve(adminActions.tokenAction(
            self.withAction(req, body))).then(function (result) {
            if (!result.ok) {
              errorCodes.mark(res, errorCodes.codeOf(result) ||
                                   'STS-API-0036');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API token action endpoint.");
          });
        },
        actions: [
          { action: 'revoke', operationId: 'revokeToken' },

          { action: 'restore', operationId: 'restoreToken' },

          { action: 'revoke-artifact', operationId: 'revokeIssuedArtifact' },

          { action: 'restore-artifact', operationId: 'restoreIssuedArtifact' },

          { action: 'revoke-set', operationId: 'revokeIssuedSet' },

          { action: 'restore-set', operationId: 'restoreIssuedSet' },

          { action: 'revoke-kind', operationId: 'revokeTokensByKind' },

          { action: 'revoke-subject', operationId: 'revokeTokensBySubject' },

          { action: 'revoke-user', operationId: 'revokeTokensByUser' },

          { action: 'revoke-all', operationId: 'revokeAllTokens' }
        ] }),

      // ---------------------------------------------------------------------
      // TRUST REALMS — several logical copies of this service in one process.
      //
      // TWO THINGS ABOUT THESE OPERATIONS ARE UNUSUAL AND BOTH ARE THE POINT.
      //
      // First, THIS WHOLE API IS ITSELF REALM-SCOPED. `/admin-api/config` is
      // the default realm's configuration; `/realm/acme/admin-api/config` is
      // `acme`'s, and a `set` posted there sets it on `acme` alone. That is not
      // a special case anybody wrote here — it falls out of the same
      // path-prefix middleware that makes /oauth2/token realm-scoped, and it
      // means every one of the operations below already works per realm. These
      // five are only the ones that manage the REGISTRY.
      //
      // Second, THE REGISTRY ITSELF IS NOT REALM-SCOPED, and it could not
      // sensibly be: there is one list of realms in this process, so `GET
      // /admin-api/realms` answers the same list whichever prefix it is called
      // under. What differs is `current`, which names the realm the CALL
      // arrived in — and `remove` refuses to remove that one, for the reason
      // the console gives.
      //
      // In development mode a realm's SIGNING KEY is regenerated on every
      // start, so a token minted in a realm today verifies against nothing
      // after a restart; product mode keeps the keys in the persistence store
      // (`common/CLAUDE.md`, `keystore.js`). THE REALM ROW ITSELF is written
      // down since 2026-08-27 when `persistence.realms` has a store under it,
      // along with that realm's own directory; see
      // `GET /admin-api/persistence`. In the default memory mode it is not, and
      // a stack that wants its realms back creates them from these operations —
      // which is why `create` is worth having rather than a config file entry:
      // the thing that starts the stack already speaks this API.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/realms', tag: 'Trust realms',
        operationId: 'getRealms',
        mirrors: 'GET /admin/realms',
        parameters: this.pagingParameters(),
        handler: function (req, res, next) {
          log.debug("Entering the management API trust realms endpoint.");
          // EVERY ROW SHOWS ITS REALM'S `kid`, and reading one MAKES the key
          // set of a realm this node holds none for — twenty realms created on
          // another node were twenty back-to-back generations inside this call,
          // long enough to cost the node its cluster membership (#46). So the
          // sets are made off the event loop first; `prepareKeySets()` never
          // rejects.
          helpers.prepareKeySets(realms.list().map(function (one) {
            return one.id;
          })).then(function () {
            self.sendJson(res, 200, adminViews.realmsJson(req));
            log.debug("Leaving the management API trust realms endpoint.");
          }).catch(function (e) {
            log.debug("Caught in the management API trust realms endpoint: " +
                      ((e && e.message) || e));
            next(e);
          });
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/realms/:action', tag: 'Trust realms',
        mirrors: 'POST /admin/realms',
        handler: function (req, res, next) {
          log.debug("Entering the management API trust realms action " +
                    "endpoint.");
          const body = parseBody(req);
          // A removal answers a promise (#232: it retires the realm first);
          // every other action answers at once. Both are resolved here.
          Promise.resolve(adminActions.realmsAction(self.withAction(req,
                                                                    body)))
            .then(function (result) {
              if (!result.ok) {
                errorCodes.mark(res, errorCodes.codeOf(result) ||
                                     'STS-API-0037');
              }
              self.sendJson(res, result.ok ? 200 : 400, result);
              log.debug("Leaving the management API trust realms action " +
                        "endpoint.");
            }).catch(function (e) {
              log.debug("Caught in the management API trust realms action " +
                        "endpoint: " + ((e && e.message) || e));
              next(e);
            });
        },
        actions: [
          { action: 'create', operationId: 'createRealm' },

          { action: 'update', operationId: 'updateRealm' },

          { action: 'set', operationId: 'setRealmSetting' },

          { action: 'unset', operationId: 'unsetRealmSetting' },

          { action: 'remove', operationId: 'removeRealm' } ] }),

      { method: 'GET', path: BASE + '/config', tag: 'Configuration',
        operationId: 'getConfig',
        mirrors: 'GET /admin/config',
        handler: function (req, res) {
          log.debug("Entering the management API configuration endpoint.");
          self.sendJson(res, 200, admin.configJson());
          log.debug("Leaving the management API configuration endpoint.");
        } },

      { method: 'GET', path: BASE + '/config-dump', tag: 'Configuration',
        operationId: 'getConfigDump',
        mirrors: 'GET /admin/config-dump',
        handler: function (req, res) {
          log.debug("Entering the management API configuration dump.");
          self.sendJson(res, 200, configDump.build(self.callerNameOf(res)));
          log.debug("Leaving the management API configuration dump.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/config/:action', tag: 'Configuration',
        mirrors: 'POST /admin/config, POST ' +
                 '/admin/xacml#xacml-tab-settings and POST ' +
                 '/admin/xacml#xacml-tab-authzen',
        handler: function (req, res) {
          log.debug("Entering the management API configuration action " +
                    "endpoint.");
          const body = parseBody(req);
          const result = adminActions.configAction(self.withAction(req, body));
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0038');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API configuration action " +
                    "endpoint.");
        },
        actions: [
          { action: 'set', operationId: 'setSetting' },

          { action: 'set-many', operationId: 'setSettings' },

          { action: 'reset', operationId: 'resetSetting' },

          { action: 'reset-all', operationId: 'resetAllSettings' } ] }),

      // ---------------------------------------------------------------------
      // The token lifetimes, which are six of the settings above — the three
      // lifetimes, the refresh idle timeout, revoke-on-sign-out and the clock
      // skew — under a name that promises those and nothing else.
      //
      // Rule 7 is satisfied twice over here and it is worth saying which way
      // round. `/admin/token-lifetimes` grew a form, so it gets its operations
      // — that is the rule as written. What it does NOT get is a second store:
      // the handler calls `adminActions.tokenLifetimesAction`, which writes
      // through `config.setOverride()`, which is the same function `POST
      // /config/set` calls against the same override map. So these two
      // operations and the Configuration ones are two doors onto one thing,
      // deliberately, in the way `/admin/rbac` and `ldapmodify` are four doors
      // onto one membership.
      //
      // What the narrow door buys a CALLER, which is why it is not merely a
      // convenience for the page: `POST /config/set-many` takes any key and
      // ignores what it does not know, which is right for a form posting a
      // whole section and wrong for a test that means to set a lifetime — a
      // misspelt key there succeeds and changes nothing. This one refuses
      // anything that is not one of the six, by name.
      ...PROTOCOL_SETTINGS_OPERATIONS,

      { method: 'GET', path: BASE + '/token-lifetimes', tag: 'Token lifetimes',
        operationId: 'getTokenLifetimes',
        mirrors: 'GET /admin/token-lifetimes',
        handler: function (req, res) {
          log.debug("Entering the management API token lifetimes endpoint.");
          self.sendJson(res, 200, adminViews.tokenLifetimesJson());
          log.debug("Leaving the management API token lifetimes endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/token-lifetimes/:action',
        // ---------------------------------------------------------------------
        // A NARROW DOOR: THE HANDLER OWNS THE WHOLE BODY, so the ajv wrapper at
        // the foot of this file stands aside for it.
        //
        // **REFUSING AN UNKNOWN KEY BY NAME IS THE ENTIRE REASON THIS RESOURCE
        // EXISTS BESIDE `/config/set-many`**, which ignores one on purpose — so
        // a narrow door that stopped refusing would be two operations over one
        // function with nothing to tell them apart. The handler's refusal names
        // the key it refused AND lists the ones it sets, and
        // `sts_admin_api_operations.js` asserts both halves.
        //
        // A schema error cannot say either thing: `additionalProperties: false`
        // answers "not a member of this request" and stops. Letting ajv go
        // first would replace a refusal a caller can act on with a worse one
        // and switch off the assertion that guards it, which is the same
        // judgement `structureOnly()` makes about `enum` and `required` one
        // level up.
        // ---------------------------------------------------------------------
        handlerOwnsBody: true,
        tag: 'Token lifetimes',
        mirrors: 'POST /admin/token-lifetimes',
        handler: function (req, res) {
          log.debug("Entering the management API token lifetimes action.");
          const body = parseBody(req);
          const result = adminActions.tokenLifetimesAction(self.withAction(req,
              body));
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0039');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API token lifetimes action.");
        },
        actions: [
          { action: 'set', operationId: 'setTokenLifetimes' },

          { action: 'defaults', operationId: 'resetTokenLifetimes' } ] }),

      // ---------------------------------------------------------------------
      // The SAML assertion settings, which are sixteen of the settings above —
      // the lifetimes, the skew, and the signing, NameID, artifact and SAML 2.0
      // encryption choices (`SAML_ASSERTION_SETTINGS` in admin-core) — under a
      // name that promises those and nothing else.
      //
      // Rule 7 is satisfied the same way /token-lifetimes satisfies it: the
      // Assertions tab on /admin/saml2 uses this resource's operations. It
      // gets no second store either — the handler calls
      // adminActions.samlAssertionsAction, which writes through
      // config.setOverride() against the same override map POST /config/set
      // writes to, and the same map the two identity provider pages' own forms
      // write to. Four doors, one thing.
      //
      // What the narrow door buys a CALLER is what it buys there: POST
      // /config/set-many ignores a key it does not know, which is right for a
      // form posting a whole section and wrong for a test that means to set an
      // assertion lifetime, where a misspelt key succeeds and changes nothing.
      { method: 'GET', path: BASE + '/saml-assertions', tag: 'SAML assertions',
        operationId: 'getSamlAssertions',
        mirrors: 'GET /admin/saml2',
        handler: function (req, res) {
          log.debug("Entering the management API SAML assertions endpoint.");
          self.sendJson(res, 200, adminViews.samlAssertionsJson());
          log.debug("Leaving the management API SAML assertions endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/saml-assertions/:action',
        // ---------------------------------------------------------------------
        // A NARROW DOOR: THE HANDLER OWNS THE WHOLE BODY, so the ajv wrapper at
        // the foot of this file stands aside for it.
        //
        // **REFUSING AN UNKNOWN KEY BY NAME IS THE ENTIRE REASON THIS RESOURCE
        // EXISTS BESIDE `/config/set-many`**, which ignores one on purpose — so
        // a narrow door that stopped refusing would be two operations over one
        // function with nothing to tell them apart. The handler's refusal names
        // the key it refused AND lists the ones it sets, and
        // `sts_admin_api_operations.js` asserts both halves.
        //
        // A schema error cannot say either thing: `additionalProperties: false`
        // answers "not a member of this request" and stops. Letting ajv go
        // first would replace a refusal a caller can act on with a worse one
        // and switch off the assertion that guards it, which is the same
        // judgement `structureOnly()` makes about `enum` and `required` one
        // level up.
        // ---------------------------------------------------------------------
        handlerOwnsBody: true,
        tag: 'SAML assertions',
        mirrors: 'POST /admin/saml2',
        handler: function (req, res) {
          log.debug("Entering the management API SAML assertions action.");
          const body = parseBody(req);
          const result = adminActions.samlAssertionsAction(self.withAction(req,
              body));
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0040');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API SAML assertions action.");
        },
        actions: [
          { action: 'set', operationId: 'setSamlAssertions' },

          { action: 'defaults', operationId: 'resetSamlAssertions' } ] }),

      { method: 'GET', path: BASE + '/claims', tag: 'Custom claims',
        operationId: 'getClaims',
        mirrors: 'GET /admin/claims',
        parameters: [
          { name: 'user', in: 'query', required: false,
            schema: { type: 'string', default: 'alice', examples: ['alice'] },
            description: 'Whose attribute values to preview. Defaults to a ' +
                         'person the directory holds from startup, so the ' +
                         'preview shows real values on a fresh process. ' +
                         'Somebody with no entry gets generated values — the ' +
                         'same invented person every ' +
                         'time, seeded from the name — and ' +
                         '`preview.entryFound` says which of the two ' +
                         'happened.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API claims endpoint.");
          self.sendJson(res, 200,
                        adminViews.claimsJson(
                          adminViews.claimsPreviewUser(req.query)));
          log.debug("Leaving the management API claims endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/claims/:action', tag: 'Custom claims',
        mirrors: 'POST /admin/claims',
        handler: function (req, res) {
          log.debug("Entering the management API claims action endpoint.");
          const body = parseBody(req);
          // The `attributes` action's list, in both spellings, exactly as the
          // credential-claims row below takes it. The other six actions ignore
          // it.
          const names = self.namesOf(req, body, 'attribute', 'attributes');
          // The THIRD argument is the family, and it is what makes this
          // resource the mirror of /admin/claims rather than of the store: a
          // `set` of `saml2` here is refused by name and sent to
          // /admin-api/saml-attributes, exactly as the console's own form post
          // is. The action function, the store and the audit row are the same
          // ones either way.
          const result = adminActions.claimsAction(self.withAction(req, body),
                                                   names,
                                            stats.JWT_CLAIM_SET_IDS);
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0041');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API claims action endpoint.");
        },
        actions: this.claimSetActions(JWT_CLAIM_FAMILY) }),

      // -----------------------------------------------------------------------
      // THE USERINFO HALF OF THE SAME STORE, and the half a client can add to.
      //
      // Its own resource for the reason the SAML one has its own: rule 7 is
      // about the CONTROL, and /admin/userinfo-claims is its own page with its
      // own forms. But it carries something neither of the others does — the
      // OIDC Core section 5.5 vocabulary, in `claimsRequest` — because that is
      // the half of this endpoint's behaviour an administrator does NOT decide,
      // and a caller with no browser has no other way to learn what a claims
      // request may name.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/userinfo-claims', tag: 'UserInfo claims',
        operationId: 'getUserInfoClaims',
        mirrors: 'GET /admin/userinfo-claims',
        parameters: [
          { name: 'user', in: 'query', required: false,
            schema: { type: 'string', default: 'alice', examples: ['alice'] },
            description: 'Whose attribute values to preview. The same ' +
                         'parameter, the same cap and the same default GET ' +
                         '/admin-api/claims takes, deliberately: the three ' +
                         'replies preview one person unless asked otherwise. ' +
                         '`preview.entryFound` says ' +
                         'whether the directory holds ' +
                         'them or the values were invented from the ' +
                         'username.' },
          { name: 'request', in: 'query', required: false,
            schema: { type: 'string',
                      examples: ['{"userinfo":{"birthdate":null}}'] },
            description: 'A section 5.5 claims request, as the JSON a client ' +
                         'would send — for example ' +
                         '`{"userinfo":{"birthdate":null,"address":null}}`. ' +
                         'The ' +
                         'reply\'s `claimsRequest.preview` then says exactly ' +
                         'what that request would return for `user`, ' +
                         'computed by the two functions the UserInfo ' +
                         'endpoint itself calls. A MALFORMED one is reported ' +
                         'in `claimsRequest.preview.error` and does NOT fail ' +
                         'this call: what it shows is the `invalid_request` ' +
                         'a client would be given, which is the thing a ' +
                         'caller is asking about.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API UserInfo claims endpoint.");
          self.sendJson(res, 200,
                        adminViews.userinfoClaimsJson(
                          adminViews.claimsPreviewUser(req.query),
                          adminViews.claimsRequestParameter(req.query)));
          log.debug("Leaving the management API UserInfo claims endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/userinfo-claims/:action',
        tag: 'UserInfo claims',
        mirrors: 'POST /admin/userinfo-claims',
        handler: function (req, res) {
          log.debug("Entering the management API UserInfo claims action " +
                    "endpoint.");
          const body = parseBody(req);
          const names = self.namesOf(req, body, 'attribute', 'attributes');
          const result = adminActions.claimsAction(self.withAction(req, body),
                                                   names,
                                            stats.USERINFO_CLAIM_SET_IDS);
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0042');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API UserInfo claims action " +
                    "endpoint.");
        },
        actions: this.claimSetActions(USERINFO_CLAIM_FAMILY) }),

      // -----------------------------------------------------------------------
      // THE SAML HALF OF THE SAME STORE, mirrored by the Custom SAML
      // attributes tab on /admin/saml2. Two resources rather than one taking
      // four sets, because rule 7 is about the CONTROL: a resource named
      // /saml-attributes is clearer than one promising tokens and leaving a
      // caller to read `getClaims` to find out what an assertion will carry.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/saml-attributes', tag: 'Custom SAML ' +
          'attributes',
        operationId: 'getSamlAttributes',
        mirrors: 'GET /admin/saml2',
        parameters: [
          { name: 'user', in: 'query', required: false,
            schema: { type: 'string', default: 'alice', examples: ['alice'] },
            description: 'Whose attribute values to preview. Defaults to a ' +
                         'person the directory holds from startup, so the ' +
                         'preview shows real values on a fresh process. ' +
                         'Somebody with no entry gets generated values — the ' +
                         'same invented person every time, seeded from the ' +
                         'name — and `preview.entryFound` says which of the ' +
                         'two happened. It is the same parameter, the same ' +
                         'cap and the same default GET ' +
                         '/admin-api/claims takes, deliberately: the ' +
                         'two replies preview one person unless asked ' +
                         'otherwise.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API SAML attributes endpoint.");
          self.sendJson(res, 200,
                        adminViews.samlAttributesJson(
                          adminViews.claimsPreviewUser(req.query)));
          log.debug("Leaving the management API SAML attributes endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/saml-attributes/:action',
        tag: 'Custom SAML attributes',
        mirrors: 'POST /admin/saml2',
        handler: function (req, res) {
          log.debug("Entering the management API SAML attributes action " +
                    "endpoint.");
          const body = parseBody(req);
          const names = self.namesOf(req, body, 'attribute', 'attributes');
          const result = adminActions.claimsAction(self.withAction(req, body),
                                                   names,
                                            stats.SAML_CLAIM_SET_IDS);
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0043');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API SAML attributes action " +
                    "endpoint.");
        },
        actions: this.claimSetActions(SAML_CLAIM_FAMILY) }),

      // -----------------------------------------------------------------------
      // THE KERBEROS PAC HALF OF THE SAME STORE (#493): the sixth set, the
      // claims a ticket's PAC_CLIENT_CLAIMS_INFO carries, on the PAC claims
      // tab under Protocols → Kerberos. Same action function, same audit row,
      // same CAEP announcement, and since #498 the same ticked catalogue.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/kerberos/claims', tag: 'Kerberos',
        operationId: 'getKerberosPacClaims',
        mirrors: 'GET /admin/kerberos',
        parameters: [
          { name: 'user', in: 'query', required: false,
            schema: { type: 'string', default: 'alice', examples: ['alice'] },
            description: 'Whose claims to preview: `preview.claims` is what ' +
                         'their next TGT would carry.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API Kerberos PAC claims " +
                    "endpoint.");
          self.sendJson(res, 200,
                        adminViews.kerberosClaimsJson(
                          adminViews.claimsPreviewUser(req.query)));
          log.debug("Leaving the management API Kerberos PAC claims " +
                    "endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/kerberos/claims/:action',
        tag: 'Kerberos',
        mirrors: 'POST /admin/kerberos#kerberos-tab-claims',
        handler: function (req, res) {
          log.debug("Entering the management API Kerberos PAC claims action " +
                    "endpoint.");
          const body = parseBody(req);
          // The `attributes` action's list (#498), in both spellings, as the
          // other claim-set doors take it.
          const names = self.namesOf(req, body, 'attribute', 'attributes');
          const result = adminActions.claimsAction(self.withAction(req, body),
                                                   names,
                                            stats.KERBEROS_CLAIM_SET_IDS);
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0131');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API Kerberos PAC claims action " +
                    "endpoint.");
        },
        actions: this.claimSetActions(KERBEROS_CLAIM_FAMILY) }),

      { method: 'GET', path: BASE + '/credential-claims',
        tag: 'Credential claims',
        operationId: 'getCredentialClaims',
        mirrors: 'GET /admin/vc',
        parameters: [
          { name: 'user', in: 'query', required: false,
            schema: { type: 'string', default: 'alice', examples: ['alice'] },
            description: 'Whose credential to preview. Defaults to a person ' +
                         'the directory holds from startup, so the preview ' +
                         'shows real values on a fresh process.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API credential-claims endpoint.");
          self.sendJson(res, 200,
                        adminViews.vcJson(adminViews.vcPreviewUser(req.query)));
          log.debug("Leaving the management API credential-claims endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/credential-claims/:action',
        tag: 'Credential claims',
        mirrors: 'POST /admin/vc#vc-tab-claims',
        handler: function (req, res) {
          log.debug("Entering the management API credential-claims action.");
          const body = parseBody(req);
          const names = self.namesOf(req, body, 'attribute', 'attributes');
          const result = adminActions.vcAction(self.withAction(req, body),
                                               names);
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0044');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API credential-claims action.");
        },
        actions: [
          { action: 'select', operationId: 'selectCredentialClaims' },

          { action: 'add', operationId: 'addCredentialClaim' },

          { action: 'remove', operationId: 'removeCredentialClaim' },

          { action: 'defaults', operationId: 'resetCredentialClaims' },

          { action: 'populate', operationId: 'populateDirectory' }
        ] }),

      { method: 'GET', path: BASE + '/verifier-request',
        tag: 'Verifier request',
        operationId: 'getVerifierRequest',
        mirrors: 'GET /admin/vc',
        handler: function (req, res) {
          log.debug("Entering the management API verifier-request endpoint.");
          self.sendJson(res, 200, adminViews.vpConfigJson());
          log.debug("Leaving the management API verifier-request endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/verifier-request/:action',
        tag: 'Verifier request',
        mirrors: 'POST /admin/vc#vc-tab-verifier-request',
        handler: function (req, res) {
          log.debug("Entering the management API verifier-request action.");
          const body = parseBody(req);
          const names = self.namesOf(req, body, 'claim', 'claims');
          const result = adminActions.vpConfigAction(self.withAction(req, body),
                                                     names);
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0045');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API verifier-request action.");
        },
        actions: [
          { action: 'select', operationId: 'selectRequestedClaims' },

          { action: 'add', operationId: 'addRequestedClaim' },

          { action: 'remove', operationId: 'removeRequestedClaim' },

          { action: 'defaults', operationId: 'resetRequestedClaims' },

          { action: 'format', operationId: 'setRequestFormat' }
        ] }),

      // ---------------------------------------------------------------------
      // STARTING A VERIFICATION AND READING ITS OUTCOME (#587, 2026-10-12).
      //
      // Was the administrator's twin of the demonstration Verifier's
      // `/oid4vp/start` and `/oid4vp/result/:state`; since #594 those left
      // for the development companion (`companion/`), which starts its bar
      // door's verifications HERE, as an application holding Admin Write,
      // and names its own completion page (`redirect_uri`). Both call the
      // Verifier's own `startVerification()` and `verificationOutcome()`.
      //
      // THE START CALLS THE VERIFIER RATHER THAN AN `admin-core` ACTION, and
      // that is the one departure from "every operation that changes
      // something calls an action": building a request reads the REQUEST's
      // origin a dozen times below it — the Response URI, the did:web, the
      // OpenID Federation entity identifier, the x509 name — and an action
      // never sees a request (`tests/admin_actions_layer.js`). Nothing is
      // lost: the console's form posts to THIS operation, so there is no
      // second admin door to share it with, and the Verifier is where the
      // page shares it. The require is a cache hit — the Verifier is loaded
      // at 11–14 and registers nothing when required (rule 1).
      // ---------------------------------------------------------------------
      // AN ACTION RESOURCE RATHER THAN A BARE POST, for `/cells/:action`'s
      // reason: `sts_admin_api_operations.js` probes every POST resource
      // with an action nobody has heard of and requires a 400 naming the
      // ones that exist, and a literal `/verifications/start` answered
      // Express's 404. One action today.
      ApiRows.actions({ method: 'POST', route: BASE + '/verifications/:action',
        tag: 'Verifier request',
        mirrors: 'POST /admin/vc#vc-tab-verifier-request',
        handler: async function (req, res) {
          log.debug("Entering the management API verification start.");
          const asked = self.withAction(req, parseBody(req));
          if (asked.action !== 'start') {
            // The sentence the suite reads — `/cells/:action`'s shape.
            errorCodes.mark(res, 'STS-API-0014');
            self.sendJson(res, 400, { ok: false, errors: [
              'Unknown action "' + asked.action + '". The actions here ' +
              'are: start.'] });
            log.debug("Leaving the management API verification start. " +
                      "Unknown action.");
            return;
          }
          const body = Object.assign({}, asked);
          delete body.action;
          // A form-encoded body decodes `dc+sd-jwt`'s `+` to a space;
          // `vpConfigAction()` puts it back for the same reason.
          if (body.format) {
            body.format = String(body.format).replace(/ /g, '+');
          }
          // WHERE THE WALLET IS SENT AFTERWARDS (#594): the caller's own
          // page, held to the calling client's registered redirect URIs
          // wherever only registered addresses are accepted.
          const completion: any = vcVerifier.completionUriFor(
            body.redirect_uri, String(res.locals.apiClientId || ''));
          delete body.redirect_uri;
          if (completion.error) {
            errorCodes.mark(res, 'STS-VC-0123');
            self.sendJson(res, 400, { ok: false,
                                      errors: [completion.error] });
            log.debug("Leaving the management API verification start. " +
                      "An unregistered completion address.");
            return;
          }
          const started: any = await vcVerifier.startVerification(req, body,
            'body', { completionUri: completion.uri });
          if (!started.ok) {
            errorCodes.mark(res, started.code);
            self.sendJson(res, started.status,
                          { ok: false, errors: [started.error] });
            log.debug("Leaving the management API verification start. " +
                      "Refused.");
            return;
          }
          const record = started.record;
          const answer: any = {
            ok: true,
            message: 'Verification ' + record.state + ' started. Send the ' +
                     'wallet to ' + started.walletUrl + ' — or show it ' +
                     started.requestUri + ' — and read the outcome with ' +
                     'GET /admin-api/verifications?state=' +
                     encodeURIComponent(record.state) + '.',
            state: record.state,
            nonce: record.nonce,
            mode: started.mode,
            format: record.format,
            responseType: record.responseType,
            responseMode: record.responseMode,
            byReference: !!record.byReference,
            clientId: record.clientId,
            requested: record.requested || [],
            dcql_query: record.request.dcql_query,
            expiresAt: new Date(record.expires).toISOString(),
            wallet: started.wallet,
            walletUrl: started.walletUrl,
            requestUri: started.requestUri,
            query: started.query,
            redirectUri: completion.uri
          };
          if (record.byReference) {
            answer.request_uri = baseUrlOf(req) + '/oid4vp/request/' +
                                 record.id;
          }
          self.sendJson(res, 200, answer);
          log.debug("Leaving the management API verification start. state=" +
                    record.state);
        },
        actions: [
          { action: 'start', operationId: 'startVerification' }
        ] }),

      { method: 'GET', path: BASE + '/verifications',
        tag: 'Verifier request',
        operationId: 'getVerifications',
        mirrors: 'GET /admin/vc',
        parameters: [
          { name: 'state', in: 'query', required: false,
            schema: { type: 'string', examples: ['no-such-state'] },
            description: 'The `state` `POST /verifications/start` ' +
                         'answered.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API verifications endpoint.");
          const json: any = adminViews.presentationVerificationsJson(req);
          if (json.found === false) {
            errorCodes.mark(res, 'STS-VC-0042');
            self.sendJson(res, 404, { ok: false, found: false,
              state: json.state,
              errors: ['No such presentation: this realm holds no ' +
                       'verification with state "' + json.state + '". ' +
                       'An expired one is removed by the sweep.'] });
            log.debug("Leaving the management API verifications endpoint. " +
                      "Unknown state.");
            return;
          }
          self.sendJson(res, 200, json);
          log.debug("Leaving the management API verifications endpoint.");
        } },

      // ---------------------------------------------------------------------
      // WHAT THE CREDENTIAL ISSUER SAW (#594). The non-spec `GET
      // /oid4vci/last_request` and `GET /oid4vci/notification/:id` answered
      // these to anybody, in a development realm only; they are an
      // administrator's facts, so they are Admin Read reads here, in every
      // mode. `oid4vc/vc_issuer.ts`'s `lastCredentialRequest()` and
      // `notificationRecord()` argue what each says. No console page draws
      // them: a wallet under test, and the job driving it, are who ask.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/oid4vci/last-request',
        tag: 'OpenID4VCI',
        operationId: 'getLastCredentialRequest',
        mirrors: 'no console page — a wallet under test asks it',
        handler: function (req, res) {
          log.debug("Entering the management API last credential request " +
                    "endpoint.");
          self.sendJson(res, 200, vcIssuer.lastCredentialRequest());
          log.debug("Leaving the management API last credential request " +
                    "endpoint.");
        } },

      { method: 'GET', path: BASE + '/oid4vci/notifications',
        tag: 'OpenID4VCI',
        operationId: 'getCredentialNotification',
        mirrors: 'no console page — a wallet under test asks it',
        parameters: [
          { name: 'id', in: 'query', required: true,
            schema: { type: 'string', examples: ['no-such-notification'] },
            description: 'The `notification_id`.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API credential notification " +
                    "endpoint.");
          const record: any = vcIssuer.notificationRecord(
            String(req.query.id || ''));
          if (!record) {
            errorCodes.mark(res, 'STS-VC-0024');
            self.sendJson(res, 404, { ok: false, errors: [
              'No such notification_id: this issuer did not issue it, or ' +
              'it has expired.'] });
            log.debug("Leaving the management API credential notification " +
                      "endpoint. Unknown.");
            return;
          }
          self.sendJson(res, 200, record);
          log.debug("Leaving the management API credential notification " +
                    "endpoint.");
        } },

      // The authorization server profiles — what each discovery document
      // publishes.
      //
      // RFC 9700 section 2.6 asks a server to publish its metadata so that
      // clients stop hard-coding security capabilities. These operations decide
      // what the published document SAYS, per authorization server, which is
      // the other side of that: a client which reads the metadata can be shown
      // reading it, and one which does not can be shown not to.
      //
      // ANY MEMBER IS ACCEPTED, including one this service has never heard of.
      // That is the difference between this and every other resource here — the
      // applications registry REFUSES an attribute outside its schema, because
      // that schema is a published contract about what an entry carries. This
      // has no schema on purpose: publishing something a client did not expect
      // is half the point of a mock.
      // ---------------------------------------------------------------------
      // THE SAML 2.0 IDENTITY PROVIDER.
      //
      // The resource a caller needs before it can drive the Web Browser SSO
      // profile at all, and the reason is the feature itself: the metadata is
      // PER SERVICE PROVIDER, so "the metadata URL" is not a constant a test
      // can hard-code — it is a per-entityID fact this reply carries. A test
      // that guessed the slug rule would be a second implementation of it.
      // ---------------------------------------------------------------------
      // ---------------------------------------------------------------------
      // FEDERATION. Rule 7, and it pays here more than anywhere except /rbac:
      // this API takes a token a test can mint rather than a browser session,
      // so these operations are how a TEST configures a federation partner with
      // no browser and no cookie jar — which is the only way the feature can be
      // exercised automatically at all.
      //
      // The consequence is the same one mgmt-api/CLAUDE.md states for /rbac and
      // it is worth restating here because what is at stake is different:
      // anybody holding an `admin:write` token (or reaching this port with
      // `adminApi.authRequired` off) can configure a federation partner, which
      // means configuring a signing certificate this service will then believe.
      // That is not a new hole — the same caller can already grant themselves
      // both admin roles and mint a token for any username — but it is the
      // sharpest form of it, and the honest sentence is better than the
      // omission.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/federation', tag: 'Federation',
        operationId: 'getFederationRelationships',
        mirrors: 'GET /admin/federation',
        parameters: [
          { name: 'relationship', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One relationship, by its id.' },
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description:
              'Filter the list by id, name, partner or application.' },
          { name: 'role', in: 'query', required: false,
            schema: { type: 'string',
                      enum: ['service-provider', 'identity-provider'] },
            description: 'Only the relationships in which this service takes ' +
                         'that role. `service-provider` is the direction ' +
                         'that CONSUMES somebody else\'s assertions.' },
          { name: 'category', in: 'query', required: false,
            schema: { type: 'string', enum: ['enterprise', 'consumer'] },
            description: 'Only the enterprise partners, or only the ' +
                         'consumer and social providers (#565): a ' +
                         'relationship that names a `provider` is consumer.' }
        ].concat(this.pagingParameters()).concat(this.detailPagingParameters([
          { name: 'links',
            description: 'With `relationship`: the people whose ' +
                         'federationLink is through it (#109), each ' +
                         '`{ username, dn, link, issuer, subject }`.' }
        ])),
        handler: function (req, res) {
          log.debug("Entering the management API federation endpoint.");
          self.sendJson(res, 200, adminViews.federationJson(req));
          log.debug("Leaving the management API federation endpoint.");
        } },

      ApiRows.actions({ method: 'POST', route: BASE + '/federation/:action',
        tag: 'Federation',
        mirrors: 'POST /admin/federation',
        handler: function (req, res) {
          log.debug("Entering the management API federation action endpoint.");
          const body = parseBody(req);
          adminActions.federationAction(self.withAction(req, body),
            { via: 'api', actor: self.callerNameOf(res) || 'admin-api',
              base: baseUrlOf(req) })
            .then(function (result) {
              if (!result.ok) {
                errorCodes.mark(res, errorCodes.codeOf(result) ||
                                     'STS-API-0046');
              }
              self.sendJson(res, result.ok ? 200 : 400,
                            self.federationAnswer(result));
              log.debug("Leaving the management API federation action " +
                        "endpoint.");
            }, function (e) {
              log.error(errorCodes.tag('STS-API-0046') + 'the federation ' +
                        'action threw: ' + ((e && e.stack) || e));
              errorCodes.mark(res, 'STS-API-0046');
              self.sendJson(res, 500, { ok: false,
                errors: ['The federation action failed: ' +
                         ((e && e.message) || e)] });
            });
        },
        actions: [
          { action: 'create', operationId: 'createFederationRelationship' },

          { action: 'set', operationId: 'setFederationField' },

          { action: 'add-value', operationId: 'addFederationValue' },

          { action: 'remove-value', operationId: 'removeFederationValue' },

          { action: 'enable', operationId: 'enableFederationRelationship' },

          { action: 'disable', operationId: 'disableFederationRelationship' },

          { action: 'check-partner', operationId: 'checkFederationPartner' },

          { action: 'register-partner',
            operationId: 'registerAtFederationPartner' },

          { action: 'rotate-key', operationId: 'rotateFederationKey' },

          // A PARTNER'S SHARED SIGNALS (#373, #374): the relationship page's
          // Shared Signals buttons, each handed to ssf/ssf_transmitters.ts.
          ...([
            ['signals-discover', 'discoverFederationSignals',
             'Discover the partner\'s Shared Signals configuration',
             'Fetches `/.well-known/ssf-configuration` under the SSF issuer ' +
             '(`fedSignalsIssuer`, else `fedPeer`; SSF 1.0 section 7), which ' +
             'must name that issuer, a `jwks_uri` and a ' +
             '`configuration_endpoint`, and fetches the keys. Every address ' +
             'dialled afterwards is one that document named. Audited.'],
            ['signals-create-stream', 'createFederationSignalsStream',
             'Create this realm\'s stream at the partner',
             'SSF 1.0 section 8.1.1, discovering first where needed: a poll ' +
             'stream, or — `fedSignalsDelivery` push — a push stream to ' +
             '`/federation/signals/{id}` with an authorization header only ' +
             'this realm and the partner know. Asks for `fedSignalsEvents`. ' +
             'Audited.'],
            ['signals-read-stream', 'readFederationSignalsStream',
             'Read the stream\'s configuration from the partner',
             'Refreshes what is held: audience, events, delivery.'],
            ['signals-update-stream', 'updateFederationSignalsStream',
             'Send fedSignalsEvents to the stream',
             'A PATCH of `events_requested` to the relationship\'s ' +
             '`fedSignalsEvents`. Audited.'],
            ['signals-replace-stream', 'replaceFederationSignalsStream',
             'Replace the stream\'s configuration at the partner',
             'SSF 1.0 section 8.1.1.4: a PUT of the stream_id and every ' +
             'receiver-supplied property — the delivery the stream has, ' +
             '`fedSignalsEvents` as `events_requested`, the description. A ' +
             'push stream is given a new authorization header, held once ' +
             'the partner accepts it. Audited.'],
            ['signals-delete-stream', 'deleteFederationSignalsStream',
             'Delete the stream at the partner', 'Audited.'],
            ['signals-read-status', 'readFederationSignalsStatus',
             'Read the stream\'s status from the partner',
             'SSF 1.0 section 8.1.2.1; the status is held and shown. ' +
             'Audited.'],
            ['signals-verify', 'verifyFederationSignalsStream',
             'Ask the partner for a verification event',
             'SSF 1.0 section 8.1.4.2: its state is checked when the event ' +
             'arrives.'],
            ['signals-poll-now', 'pollFederationSignals',
             'Poll the partner now', 'RFC 8936, as the ssf.foreign-poll job ' +
             'does.']
          ] as const).map(function (one) {
            return { action: one[0], operationId: one[1]
                      };
          }),
          { action: 'signals-set-status',
            operationId: 'setFederationSignalsStatus' },
          ...([['signals-add-subject', 'addFederationSignalsSubject',
               'Add a subject to the stream at the partner',
               'SSF 1.0 section 8.1.3.2. Audited.'],
              ['signals-remove-subject', 'removeFederationSignalsSubject',
               'Remove a subject from the stream at the partner',
               'SSF 1.0 section 8.1.3.3. Audited.']
          ] as const).map(function (one) {
            return { action: one[0], operationId: one[1]
                      };
          }),
          { action: 'signals-unblock', operationId: 'unblockFederationSignals' },

          { action: 'delete', operationId: 'deleteFederationRelationship' }
        ] }),

      { method: 'GET', path: BASE + '/saml2', tag: 'SAML 2.0',
        operationId: 'getSaml2ServiceProviders',
        mirrors: 'GET /admin/saml2',
        parameters: [
          { name: 'q', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Part of a service provider\'s entityID, ' +
                         'case-insensitive, narrowing the list.' },
          { name: 'sp', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One service provider, by its entityID.' }
        ].concat(this.pagingParameters()).concat(this.detailPagingParameters([
          { name: 'mdqRefused',
            description: 'The Metadata Query lookups refused in product ' +
                         'mode (#112), newest first.' }
        ])),
        handler: function (req, res) {
          log.debug("Entering the management API SAML 2.0 endpoint.");
          // The layer decides list-or-detail off `?sp=` exactly as the page
          // does.
          self.sendJson(res, 200, adminViews.saml2Json(req));
          log.debug("Leaving the management API SAML 2.0 endpoint.");
        } },

      ApiRows.actions({ method: 'POST', route: BASE + '/saml2/:action',
        tag: 'SAML 2.0',
        mirrors: 'POST /admin/saml2',
        handler: function (req, res) {
          log.debug("Entering the management API SAML 2.0 action endpoint.");
          const body = parseBody(req);
          // Two actions dial out and answer with a promise (#37 follow-up).
          Promise.resolve(adminActions.saml2Action(self.withAction(req, body),
            { via: 'api', actor: self.callerNameOf(res) }))
            .then(function (result) {
              if (!result.ok) {
                errorCodes.mark(res, errorCodes.codeOf(result) ||
                                     'STS-API-0047');
              }
              self.sendJson(res, result.ok ? 200 : 400, result);
            }, function (e) {
              errorCodes.mark(res, 'STS-API-0047');
              self.sendJson(res, 400, { ok: false, errors: [
                'The action failed: ' + ((e && e.message) || e)] });
            });
          log.debug("Leaving the management API SAML 2.0 action endpoint.");
        },
        actions: [
          { action: 'register', operationId: 'registerSaml2ServiceProvider' },

          { action: 'set-logout-service', operationId: 'addSaml2LogoutService' },

          { action: 'remove-logout-service',
            operationId: 'removeSaml2LogoutService' },

          { action: 'set-signing-certificate',
            operationId: 'setSaml2SigningCertificate' },

          { action: 'remove-signing-certificate',
            operationId: 'removeSaml2SigningCertificate' },

          { action: 'confirm-signing-certificate',
            operationId: 'confirmSaml2SigningCertificate' },

          { action: 'discard-signing-certificate',
            operationId: 'discardSaml2SigningCertificate' },

          { action: 'set-metadata-signing-certificate',
            operationId: 'setSaml2MetadataSigningCertificate' },

          { action: 'refresh-metadata',
            operationId: 'refreshSaml2Metadata' },

          { action: 'mdq-import',
            operationId: 'importSaml2MetadataFromMdq' },

          { action: 'upload-metadata',
            operationId: 'uploadSaml2Metadata' }
        ] }),

      { method: 'GET', path: BASE + '/saml11', tag: 'SAML 1.1',
        operationId: 'getSaml11RelyingParties',
        mirrors: 'GET /admin/saml2',
        parameters: [
          { name: 'q', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Part of a relying party\'s identifier, ' +
                         'case-insensitive, narrowing the list.' },
          { name: 'rp', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One relying party, by its identifier.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API SAML 1.1 endpoint.");
          self.sendJson(res, 200, adminViews.saml11Json(req));
          log.debug("Leaving the management API SAML 1.1 endpoint.");
        } },

      // PROTOCOLS → SAML → IdP-Initiated SSO (#749), rule 7's half of the
      // tab: a read, so `admin:read`, and per realm as every operation here
      // is. The view is `adminViews.samlIdpInitiatedJson()`, which asks the
      // door's own `LaunchLinks.enabled()`.
      { method: 'GET', path: BASE + '/saml-idp-initiated',
        tag: 'SAML 2.0',
        operationId: 'getSamlIdpInitiatedApplications',
        mirrors: 'GET /admin/saml2',
        parameters: this.detailPagingParameters([
          { name: 'idpInitiated',
            description: 'The applications, by identifier.' }
        ]).concat(this.pagingParameters().filter(function (one) {
          return one.name === 'per';
        })),
        handler: function (req, res) {
          log.debug("Entering the management API SAML IdP-initiated " +
                    "endpoint.");
          self.sendJson(res, 200, adminViews.samlIdpInitiatedJson(req));
          log.debug("Leaving the management API SAML IdP-initiated " +
                    "endpoint.");
        } },

      ApiRows.actions({ method: 'POST', route: BASE + '/saml11/:action',
        tag: 'SAML 1.1',
        mirrors: 'POST /admin/saml2#saml-tab-saml11',
        handler: function (req, res) {
          log.debug("Entering the management API SAML 1.1 action endpoint.");
          const body = parseBody(req);
          const result = adminActions.saml11Action(self.withAction(req, body));
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0048');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API SAML 1.1 action endpoint.");
        },
        actions: [
          { action: 'register', operationId: 'registerSaml11RelyingParty' }
        ] }),

      { method: 'GET', path: BASE + '/authorization-servers',
        tag: 'Authorization ' +
          'servers',
        operationId: 'getAuthorizationServers',
        mirrors: 'GET /admin/authorization-servers',
        parameters: [
          { name: 'profile', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One profile, by the path component that selects ' +
                         'it. Answers 200 with `found: false` for one that ' +
                         'is not configured — whose discovery URLs still ' +
                         'answer, with this service\'s own document.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API authorization servers " +
                    "endpoint.");
          self.sendJson(res, 200, adminViews.authorizationServersJson(req));
          log.debug("Leaving the management API authorization servers " +
                    "endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/authorization-servers/:action',
        tag: 'Authorization servers',
        mirrors: 'POST /admin/authorization-servers',
        handler: function (req, res) {
          log.debug("Entering the management API authorization servers " +
                    "action endpoint.");
          const body = parseBody(req);
          const result = adminActions.asAction(self.withAction(req, body));
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0049');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API authorization servers action " +
                    "endpoint.");
        },
        actions: [
          { action: 'create', operationId: 'createAuthorizationServer' },

          { action: 'set', operationId: 'setAuthorizationServerMember' },

          { action: 'remove', operationId: 'removeAuthorizationServerMember' },

          { action: 'reset', operationId: 'resetAuthorizationServerMember' },

          { action: 'delete', operationId: 'deleteAuthorizationServer' }
        ] }),

      // The application registry, read and written.
      //
      // The write half is NOT a third store beside the protocol endpoints and
      // LDAP: every action below calls a function in applications.js which does
      // the same read-modify-write against the same ou=applications entries, so
      // a form post and an ldapmodify are one act arriving by two routes. That
      // is what keeps the one-store rule intact with three ways in.
      //
      // What may be changed is DECLARED and not DERIVED — configuration, which
      // is what RFC 9700 mode reads, but never the counters or the sightings,
      // which are what happened. The line is drawn by each application
      // row's `editable` in the model, so this file offers no opinion about it
      // and the console's selects are built from the same rows these actions
      // validate against.
      { method: 'GET', path: BASE + '/applications', tag: 'Applications',
        operationId: 'getApplications',
        mirrors: 'GET /admin/applications',
        parameters: [
          { name: 'claimsUser', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'On one application, the person the claims preview ' +
                         'is drawn for. Defaults to the signed-in person.' },
          { name: 'application', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One application, by its identifier exactly — the ' +
                         'client_id, wtrealm, AppliesTo, entityID or service ' +
                         'principal name. Answers 200 with `found: false` ' +
                         'for one this service has never accepted, which is ' +
                         'a different fact from one it has refused: an entry ' +
                         'appears when an identifier ' +
                         'is ACCEPTED, so a client ' +
                         'whose every request was turned away has none.' },
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the identifier or the name, ' +
                         'case-insensitive. Ignored when `application` is ' +
                         'given.' },
          { name: 'kind', in: 'query', required: false,
            schema: { type: 'string', enum: closed.applicationKinds },
            description: 'One kind. A record carrying SEVERAL matches on any ' +
                         'of them — an OAuth client that asked for the ' +
                         'openid scope is also a relying party — so these ' +
                         'are not disjoint sets and the counts in the ' +
                         'reply\'s `kinds` member do not sum to the total.' },
          // #459: the application page's search for its two delegation
          // lists, which may not offer the application itself or what the
          // list already holds — left out BEFORE the paging, so a page of
          // five is five, which a filter in the browser could not promise.
          { name: 'exclude', in: 'query', required: false,
            schema: { type: 'array', items: { type: 'string' } },
            style: 'form', explode: true,
            description: 'An identifier to leave out of the match, exactly ' +
                         'as spelled; repeat it for several ' +
                         '(`exclude=a&exclude=b`). Applied before the ' +
                         'paging, so a page still holds `per` rows. The ' +
                         'console\'s application search for ' +
                         '`appAllowedToDelegateTo` and ' +
                         '`appAllowedToActOnBehalfOf` sends the application ' +
                         'itself and the values its list already holds. ' +
                         'Ignored when `application` is given.' },
          { name: 'attributesPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the attribute list, on the ' +
                         '`?application=` reply only. Named rather than the ' +
                         'bare `page` because it moves a list inside the ' +
                         'reply rather than the reply itself.' },
          { name: 'authenticationsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of `authenticationEvents`, on the ' +
                         '`?application=` reply only. Named rather than the ' +
                         'bare `page` so it does not move the attribute ' +
                         'list.' }
        ].concat(this.pagingParameters()).concat(this.detailPagingParameters([
          { name: 'observed',
            description: 'On the `?application=` reply only: the claims ' +
                         'observed on its tokens.' },
          { name: 'held',
            description: 'On the `?application=` reply only: the ' +
                         'delegated permissions it holds.' },
          { name: 'exposed',
            description: 'On the `?application=` reply only: the ' +
                         'permissions it exposes.' },
          { name: 'grantedOut',
            description: 'On the `?application=` reply only: the ' +
                         'permissions it has granted out.' },
          { name: 'enrolled',
            description: 'On the `?application=` reply only: the ' +
                         'certificates on its entry.' },
          { name: 'enrolledConfig',
            description: 'On the `?application=` reply only: those ' +
                         'certificates on its configuration tab.' }
        ])),
        handler: function (req, res, next) {
          log.debug("Entering the management API applications endpoint.");
          const send = function () {
            log.debug("Entering send().");
            self.sendJson(res, 200, adminViews.applicationsJson(req));
            log.debug("Leaving send().");
            log.debug("Leaving the management API applications endpoint.");
          };
          // The list carries no attempts. The drill-down's do, and they
          // are the audit log: another worker's rows are noted, not held,
          // until fresh() — the wait the audit page already makes (#820).
          // Without it the Authentication attempts tab is empty on every
          // application whenever the sign-in was recorded elsewhere.
          const one = req.query && req.query.application;
          if (one === undefined || one === null || String(one) === '') {
            send();
            return;
          }
          audit.fresh().then(send).catch(function (e) {
            log.debug("Caught in the management API applications " +
                      "endpoint: " + ((e && e.message) || e));
            next(e);
          });
        } },

      // WHAT A CREATE MAY SAY, read off the service. Rule 7 asks for an
      // operation per console page and this is /admin/applications/new's — but
      // it earns its place beyond the parity, because what it answers is the
      // two CLOSED VOCABULARIES `create` validates against: the kinds and
      // the fourteen protocol families, each with what it means. A caller that
      // reads this cannot construct a create the service will refuse, which is
      // the property editableAttributes() gives the console's two selects and
      // this gives an API client.
      //
      // THERE IS NO POST BESIDE IT, and that is rule 7 read exactly rather than
      // by shape. The rule is about CONTROLS: that page's one control posts
      // `action=create` to /admin/applications, so the operation mirroring it
      // is `createApplication` below and already exists. A second create here
      // would be two operations over one function, which is the thing the
      // parity rule is trying to prevent rather than an instance of it.
      { method: 'GET', path: BASE + '/applications/new', tag: 'Applications',
        operationId: 'getNewApplicationForm',
        mirrors: 'GET /admin/applications/new',
        handler: function (req, res) {
          log.debug("Entering the management API new-application endpoint.");
          // STRAIGHT TO THE LAYER (2026-09-12). This used to go through the
          // console's newApplicationView(), which built the whole page and
          // threw the markup away — so every call here rendered a form nobody
          // read.
          self.sendJson(res, 200, adminViews.newApplicationJson(req));
          log.debug("Leaving the management API new-application endpoint.");
        } },

      ApiRows.actions({ method: 'POST', route: BASE + '/applications/:action',
        tag: 'Applications',
        // TWO CONSOLE PATHS REACH THIS SWITCH SINCE 2026-09-13: the list page,
        // and /admin/applications/new's RFC 9728 import, whose load and create
        // post to that page so a refusal can redraw it. The console suite reads
        // this field to learn which console paths take a POST.
        // And since #604 the application page's Owners tab, which posts to
        // /admin/applications/owners so its Find is told apart.
        mirrors: 'POST /admin/applications, POST /admin/applications/new, ' +
                 'POST /admin/applications/edit and ' +
                 'POST /admin/applications/owners',
        handler: function (req, res) {
          log.debug("Entering the management API applications action " +
                    "endpoint.");
          const body = parseBody(req);
          // The declared protocol families, in the two spellings the console
          // takes them in — `protocol` repeated, as a checkbox column posts it,
          // and one `protocols` array, as a JSON body carries it. Read through
          // listField() rather than off `body` for the reason namesOf() exists
          // at all: helpers.parseBody() builds a plain object, so a repeated
          // field arrives as whichever value came last and every other one is
          // silently gone. Ignored by every action but `create`, which is where
          // the vocabulary is validated.
          //
          // A COMBINED CHOICE (`vc`) stands for the families it names, which
          // is how the console's checkbox column posts it (#446: the static
          // console sends that form here, where the console's own handler
          // expanded it).
          const protocols = applications.familiesOfChoices(
            self.namesOf(req, body, 'protocol', 'protocols'));
          // AN RFC 9728 DOCUMENT THE CREATE FORM LOADED (#446): the third
          // tab's document, as the reader left it, into the attribute the
          // create writes — what `/admin/applications/new`'s handler did
          // before calling this action.
          if (String(req.params.action || body.action || '') === 'create' &&
              body.metadata) {
            const stored = resourceMetadata.documentFromForm(body);
            if (stored) {
              body['field.oauthResourceMetadata'] = stored;
            }
          }
          const result = adminActions.applicationsAction(self.withAction(req,
              body),
                                                         protocols, {
            authorizationServers: resourceMetadata.authorizationServersOf(req),
            // For `issue-software-statement`: the issuer a statement names is
            // the one published at the address this request arrived on.
            base: baseUrlOf(req),
            // For `add-certificate` and `remove-certificate` (#1227): who
            // the audit row names, as the person's twin names it.
            via: 'api', actor: self.callerNameOf(res)
          });
          // `refresh-metadata` is asynchronous — it dials the service
          // provider's metadata URL — and every other action is not. See that
          // action's comment in admin.js for why one promise is cheaper than
          // forty awaits.
          if (result && typeof result.then === 'function') {
            result.then(function (answer) {
              if (!answer.ok) {
                errorCodes.mark(res,
                                errorCodes.codeOf(answer) || 'STS-API-0050');
              }
              self.sendJson(res, answer.ok ? 200 : 400, answer);
              log.debug("Leaving the management API applications action " +
                        "endpoint. Fetched.");
            });
            log.debug("Leaving handler().");
            return;
          }
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0050');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API applications action endpoint.");
        },
        actions: [
          { action: 'create', operationId: 'createApplication' },

          { action: 'set', operationId: 'setApplicationAttribute' },

          { action: 'add', operationId: 'addApplicationValue' },

          { action: 'remove', operationId: 'removeApplicationValue' },

          // THE FIELD GRID'S SAVE (2026-09-30): the application page's one
          // form, and every attribute it carries at once.
          { action: 'update-fields', operationId: 'updateApplicationFields' },

          // THE PROVENANCE PAIR (2026-09-12). The console's application page
          // draws a Confirm and a Discard button beside every return address a
          // development-mode request put on the entry; rule 7 owes each an
          // operation here, and both call the one action function that page
          // posts to. `applications.returnAddressesOf()` is the rule they
          // change the answer of.
          { action: 'confirm-address',
            operationId: 'confirmApplicationReturnAddress' },

          { action: 'discard-address',
            operationId: 'discardApplicationReturnAddress' },

          // THE CREDENTIALS SECTION'S SECRET CONTROLS (2026-09-13; several
          // secrets since 2026-10-01).
          // AN APPLICATION'S OWNERS (#604): what the application page's
          // Owners tab saves the moment Add or Remove is pressed.
          { action: 'add-owner', operationId: 'addApplicationOwner' },
          { action: 'remove-owner', operationId: 'removeApplicationOwner' },
          { action: 'regenerate-secret',
            operationId: 'regenerateApplicationClientSecret' },

          // ROTATION WITH AN OVERLAP (#49 P5, 2026-09-22; add-and-shorten
          // since 2026-10-01).
          { action: 'rotate-secret',
            operationId: 'rotateApplicationClientSecret' },

          { action: 'add-secret',
            operationId: 'addApplicationClientSecret' },

          { action: 'remove-secret',
            operationId: 'removeApplicationClientSecret' },

          // A credential's value on demand (#446): the application page's
          // folds, which no GET may carry.
          { action: 'reveal-secret',
            operationId: 'revealApplicationSecret' },

          // /admin/applications/new's *Generate Secret* button (2026-09-18).
          { action: 'generate-secret',
            operationId: 'generateClientSecret' },

          // THE DID TAB'S *Generate a key pair* (2026-10-01).
          { action: 'generate-did-key',
            operationId: 'generateApplicationDidKey' },

          // THE DID TAB'S *Download did-configuration.json* (2026-10-01).
          { action: 'sign-domain-linkage',
            operationId: 'signApplicationDomainLinkage' },

          // AN APPLICATION'S OWN CUSTOM CLAIMS AND SAML ATTRIBUTES
          // (2026-10-01): the Custom claims and Custom SAML attributes
          // sections of its configuration tabs.
          { action: 'set-custom-claim',
            operationId: 'setApplicationCustomClaim' },
          { action: 'remove-custom-claim',
            operationId: 'removeApplicationCustomClaim' },

          // AN APPLICATION'S OWN DIRECTORY-ATTRIBUTE SELECTIONS (#495): the
          // catalogue sections of its OAuth / OpenID Connect, SAML and
          // Verifiable Credentials sub-tabs.
          { action: 'set-claim-attributes',
            operationId: 'setApplicationClaimAttributes' },
          // THE OAUTH SUB-TAB'S ONE TABLE (#1144): the three OAuth
          // selections, a column each, under one Save.
          { action: 'set-claim-selections',
            operationId: 'setApplicationClaimSelections' },
          { action: 'inherit-claim-attributes',
            operationId: 'inheritApplicationClaimAttributes' },

          // THE SCOPE CLAIMS TAB (2026-10-09): the claims a resource
          // server's own permissions carry on access tokens addressed to it.
          { action: 'set-permission-claims',
            operationId: 'setApplicationPermissionClaims' },
          { action: 'clear-permission-claims',
            operationId: 'clearApplicationPermissionClaims' },

          // THE ACCESS TYPES TAB (#432 phase 4): one entry of the access-type
          // catalogue RFC 9396 and GNAP share.
          { action: 'set-access-type',
            operationId: 'setApplicationAccessType' },
          { action: 'remove-access-type',
            operationId: 'removeApplicationAccessType' },

          // A TYPE'S MAPPING, ONE ROW AT A TIME (#564, P5): the Access
          // types tab's XACML mapping sub-tabs. AuthZEN's catalogue acts
          // are the model; each rewrites the type's one value through the
          // door `set-access-type` uses.
          { action: 'set-access-type-row',
            operationId: 'setApplicationAccessTypeRow' },
          { action: 'remove-access-type-row',
            operationId: 'removeApplicationAccessTypeRow' },
          { action: 'set-not-for-policy',
            operationId: 'setApplicationAccessTypeNotForPolicy' },

          // THE FINE-GRAINED AUTHORIZATION TAB (#564, P5): the switch, and
          // the policy the application owns.
          { action: 'fga-enable', operationId: 'enableApplicationFga' },
          { action: 'fga-disable', operationId: 'disableApplicationFga' },
          { action: 'fga-create-policy',
            operationId: 'createApplicationFgaPolicy' },
          { action: 'fga-reset-policy',
            operationId: 'resetApplicationFgaPolicy' },

          // THE CREDENTIALS SECTION'S MUTUAL TLS CONTROLS (RFC 8705,
          // 2026-09-13).
          { action: 'issue-tls-client-certificate',
            operationId: 'issueApplicationTlsClientCertificate' },
          { action: 'revoke-tls-client-certificate',
            operationId: 'revokeApplicationTlsClientCertificate' },

          // THE CREDENTIALS SECTION'S MESSAGE-SIGNING CONTROLS (#521).
          { action: 'issue-signing-certificate',
            operationId: 'issueApplicationSigningCertificate' },
          { action: 'revoke-signing-certificate',
            operationId: 'revokeApplicationSigningCertificate' },

          // THE CREDENTIALS SECTION'S STORED CERTIFICATES (#1227): the
          // person's add-certificate and remove-certificate (#1061), on an
          // application's entry.
          { action: 'add-certificate',
            operationId: 'addApplicationCertificate' },
          { action: 'remove-certificate',
            operationId: 'removeApplicationCertificate' },

          // THE SOFTWARE STATEMENTS SECTION'S CONTROL (RFC 7591 section 2.3,
          // 2026-09-13).
          { action: 'issue-software-statement',
            operationId: 'issueApplicationSoftwareStatement' },

          { action: 'revoke-registration',
            operationId: 'revokeApplicationRegistration' },

          { action: 'refresh-metadata',
            operationId: 'refreshApplicationMetadata' },

          { action: 'load-resource-metadata',
            operationId: 'loadProtectedResourceMetadata' },

          // AN APPLICATION AS AN LDIF FILE (#546): the Import / export tab of
          // the application's console page.
          { action: 'export-ldif',
            operationId: 'exportApplicationLdif' },

          { action: 'import-ldif',
            operationId: 'importApplicationLdif' },

          { action: 'forget', operationId: 'deleteApplication' }
        ] }),

      // The audit log. READ ONLY, and that is a decision rather than an
      // operation nobody got round to. Every other resource here has a POST
      // beside it because the console control it mirrors is a form; this one
      // mirrors a page with no form on it, because a clear button on an
      // administrative console would make an audit log unable to answer the one
      // question it exists for. There is nothing to change, so there is nothing
      // to document as changeable. --- Shared Signals
      // -----------------------------------------------------
      //
      // A GET and a POST, and unlike SCIM's the POST is not optional:
      // /admin/ssf has CONTROLS on it — set a status, transmit an event,
      // delete a stream (what has been received went with `POST /ssf/receive`,
      // #593) — and rule 7 is about controls. Every one of them calls the same function the console's form
      // posts to, with `action` taken from the URL instead of from a hidden
      // input.
      //
      // **THERE IS DELIBERATELY NO `create` ACTION**, and that is the rule read
      // exactly rather than a gap. A stream carries a delivery endpoint THIS
      // SERVICE WILL DIAL, and the one place that URL may come from is a
      // receiver that authenticated at `POST /ssf/stream` and asked. A
      // management API that could mint one would be a second door onto the
      // outbound request `ssf/ssf_http.ts` spends its header bounding, and the
      // one with the weaker credential (it read "ungated door" until
      // 2026-09-09) — so the console has no create form either, and the parity
      // holds because there is no control to mirror.
      // ---------------------------------------------------------------------
      // XACML. FIVE READS AND ONE WRITE: four read views are composed into
      // tabs on `/admin/xacml`, and the one action function serves its policy,
      // editor and remote-PEP tabs. The settings tab's forms use the shared
      // configuration action below.
      //
      // RULE 7 IS WHY THIS IS IN THE SAME COMMIT AS THE PAGES. Every control
      // the console grows owes an operation here, and the one that is easiest
      // to forget is not the protocol's own endpoint — it is exactly this.
      { method: 'GET', path: BASE + '/xacml', tag: 'XACML',
        operationId: 'getXacml',
        mirrors: 'GET /admin/xacml',
        handler: function (req, res) {
          log.debug("Entering the management API XACML endpoint.");
          self.sendJson(res, 200, adminViews.xacmlView(req));
          log.debug("Leaving the management API XACML endpoint.");
        } },

      { method: 'GET', path: BASE + '/xacml/policies', tag: 'XACML',
        operationId: 'getXacmlPolicies',
        mirrors: 'GET /admin/xacml',
        handler: function (req, res) {
          log.debug("Entering the management API XACML policies endpoint.");
          self.sendJson(res, 200, adminViews.xacmlPoliciesView(req));
          log.debug("Leaving the management API XACML policies endpoint.");
        } },

      { method: 'GET', path: BASE + '/xacml/editor', tag: 'XACML',
        operationId: 'getXacmlEditor',
        mirrors: 'GET /admin/xacml',
        parameters: [
          { name: 'policy', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The name of one policy. Without it, the root.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API XACML editor endpoint.");
          self.sendJson(res, 200, adminViews.xacmlEditorView(req));
          log.debug("Leaving the management API XACML editor endpoint.");
        } },

      { method: 'GET', path: BASE + '/xacml/decide', tag: 'XACML',
        operationId: 'getXacmlDecision',
        mirrors: 'GET /admin/xacml',
        parameters: [
          { name: 'subject', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Who the decision is asked about.' },
          { name: 'action', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'What they would do.' },
          { name: 'resource', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'What they would do it to.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API XACML decision endpoint.");
          self.sendJson(res, 200, adminViews.xacmlDecideView(req));
          log.debug("Leaving the management API XACML decision endpoint.");
        } },

      // THE ONLY XACML OPERATION ABOUT TRAFFIC. The other six describe the
      // repository — what policies exist, what one says, what the PDP would
      // decide about a subject you name. This one answers what is actually
      // HAPPENING, and it is the operation somebody reaches for when
      // authorization is misbehaving rather than when it is being set up.
      //
      // NO POST BESIDE IT, and that is rule 7 read exactly rather than by
      // shape: the page it mirrors has no control. A reset was refused rather
      // than forgotten — a console that could zero its own monitoring would
      // make every number on it a number somebody might have zeroed, and the
      // audit log, which is the durable record, cannot be reset either.
      // -----------------------------------------------------------------------
      // GNAP (RFC 9635 + RFC 9767), 2026-09-12. Three operations mirroring the
      // two pages `gnap/gnap_admin.ts` draws and the one form on the first of
      // them. Both doors call `gnap/gnap_console.ts`, the view and action layer
      // of this family, so a page and its operation cannot disagree (rule 7).
      // REQUIRED LAZILY: this module is 19 in the require order and GNAP is
      // 23d, and every module that file loads is a library — but a lazy require
      // keeps that true by construction rather than by a reading of today's
      // require graph.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/gnap', tag: 'GNAP',
        operationId: 'getGnap',
        mirrors: 'GET /admin/gnap',
        parameters: [
          { name: 'state', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'A grant state, narrowing the grants; any other ' +
                         'value is no filter at all.' }
        ].concat(this.pagingParameters().filter(function (one) {
          return one.name === 'per';
        })).concat(this.detailPagingParameters([
          { name: 'grants', description: 'The grants, newest first.' },
          { name: 'resources',
            description: 'The registered resource sets.' },
          { name: 'servers',
            description: 'The named authorization servers.' }
        ])),
        handler: function (req, res) {
          log.debug("Entering the management API GNAP endpoint.");
          self.sendJson(res, 200, loadGnapConsole().gnapView(req));
          log.debug("Leaving the management API GNAP endpoint.");
        } },

      { method: 'GET', path: BASE + '/gnap/monitor', tag: 'GNAP',
        operationId: 'getGnapMonitor',
        mirrors: 'GET /admin/gnap/monitor',
        parameters: this.pagingParameters(),
        handler: function (req, res) {
          log.debug("Entering the management API GNAP monitor endpoint.");
          self.sendJson(res, 200, loadGnapConsole().gnapMonitorView(req));
          log.debug("Leaving the management API GNAP monitor endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/gnap/:action', tag: 'GNAP',
        mirrors: 'POST /admin/gnap',
        handler: function (req, res) {
          log.debug("Entering the management API GNAP action endpoint.");
          const result = loadGnapConsole().gnapAction(
              self.withAction(req, parseBody(req)),
                                                       { via: 'api',
                                                         req: req });
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-GNAP-0665');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API GNAP action endpoint.");
        },
        actions: [
          { action: 'revoke-grant', operationId: 'revokeGnapGrant' },
          { action: 'delete-resource-set', operationId: 'deleteGnapResourceSet' }
        ] }),

      { method: 'GET', path: BASE + '/xacml/monitor', tag: 'XACML',
        operationId: 'getXacmlMonitor',
        mirrors: 'GET /admin/xacml/monitor',
        handler: function (req, res) {
          log.debug("Entering the management API XACML monitor endpoint.");
          self.sendJson(res, 200, adminViews.xacmlMonitorView(req));
          log.debug("Leaving the management API XACML monitor endpoint.");
        } },

      { method: 'GET', path: BASE + '/xacml/peps', tag: 'XACML',
        operationId: 'getXacmlPeps',
        mirrors: 'GET /admin/xacml',
        handler: function (req, res) {
          log.debug("Entering the management API XACML remote PEPs endpoint.");
          self.sendJson(res, 200, adminViews.xacmlPepsView(req));
          log.debug("Leaving the management API XACML remote PEPs endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/xacml/:action', tag: 'XACML',
        mirrors: 'POST /admin/xacml#xacml-tab-policies, POST ' +
                 '/admin/xacml#xacml-tab-editor, POST ' +
                 '/admin/xacml#xacml-tab-peps, POST /admin/xacml/policies, ' +
                 'POST /admin/xacml/editor and POST /admin/xacml/peps',
        handler: function (req, res) {
          log.debug("Entering the management API XACML action endpoint.");
          const body = parseBody(req);
          // SETTLED EITHER WAY: `issue-pep-certificate` answers a promise and
          // the other actions answer a result (see `xacmlAction()`), and a
          // rejection is a defect here rather than something a request can
          // cause — so it is a 500 naming the message rather than an unhandled
          // rejection that hangs the request.
          Promise.resolve(adminActions.xacmlAction(self.withAction(req, body)))
            .then(function (result) {
              if (!result.ok) {
                errorCodes.mark(res,
                                errorCodes.codeOf(result) || 'STS-API-0051');
              }
              // THE PRIVATE KEY IN AN ISSUE REPLY IS THE POINT OF THE CALL,
              // handed over once — and `sendJson()` already answers `no-store`,
              // which is what keeps it out of every cache between here and the
              // caller.
              self.sendJson(res, result.ok ? 200 : 400, result);
              log.debug("Leaving the management API XACML action endpoint.");
            }, function (e) {
              log.error(errorCodes.tag('STS-XACML-0072') +
                        'admin_api: an XACML ' +
                        'action threw: ' + ((e && e.stack) || e));
              errorCodes.mark(res, 'STS-XACML-0072');
              self.sendJson(res, 500, { ok: false,
                                        errors: ['That action failed: ' +
                                                 ((e && e.message) || e)] });
              log.debug("Leaving the management API XACML action endpoint. " +
                        "It threw.");
            });
        },
        actions: [
          { action: 'create-from-template', operationId: 'createXacmlPolicy' },
          { action: 'import-alfa', operationId: 'importXacmlAlfa' },
          { action: 'enable', operationId: 'enableXacmlPolicy' },
          { action: 'disable', operationId: 'disableXacmlPolicy' },
          { action: 'set-root', operationId: 'setXacmlRootPolicy' },
          { action: 'delete', operationId: 'deleteXacmlPolicy' },
          { action: 'edit-policy', operationId: 'editXacmlPolicy' },
          { action: 'add-rule', operationId: 'addXacmlRule' },
          { action: 'edit-match', operationId: 'editXacmlMatch' },
          { action: 'remove', operationId: 'removeXacmlNode' },
          // ---------------------------------------------------------------
          // THE REST OF THE EDITOR, AND THE REASON THESE NINETEEN ARRIVED LATE.
          //
          // Phase three documented ten of the twenty-nine actions and shipped.
          // Rule 7 says a control added to the console gets an operation in the
          // same commit, and `tests/protocol/sts_admin_api_operations.js` is
          // the check — it compares the actions this document DECLARES against
          // the ones the handler's refusal sentence NAMES, in both directions,
          // because that sentence is what `tests/protocol/admin_api.js`'s
          // parity check reads to find out what a resource can do. Nineteen
          // actions the sentence named and the document did not meant nineteen
          // console controls that could have lost their operation with nothing
          // failing.
          //
          // It went unnoticed until phase five because that job is this
          // repository's own and had not been run against this branch.
          //
          // EVERY ONE OF THESE TAKES A `path`, which is the address
          // GET /admin-api/xacml/editor gave you, and every one of them is only
          // valid against the document that reply was read from — remove rule 0
          // and every path naming rule 1 now means rule 0. Re-read the tree
          // after each edit rather than reusing paths.
          // ---------------------------------------------------------------
          { action: 'add-target-anyof', operationId: 'addXacmlTargetClause' },
          { action: 'add-allof', operationId: 'addXacmlAlternative' },
          { action: 'add-match', operationId: 'addXacmlMatch' },
          { action: 'edit-rule', operationId: 'editXacmlRule' },
          { action: 'add-condition', operationId: 'addXacmlCondition' },
          { action: 'set-expression-apply', operationId: 'setXacmlApply' },
          { action: 'set-expression-value', operationId: 'setXacmlValue' },
          { action: 'set-expression-designator',
            operationId: 'setXacmlDesignator' },
          { action: 'set-expression-variable', operationId: 'setXacmlVariable' },
          { action: 'add-argument', operationId: 'addXacmlArgument' },
          { action: 'edit-apply', operationId: 'editXacmlApply' },
          { action: 'edit-value', operationId: 'editXacmlValue' },
          { action: 'edit-designator', operationId: 'editXacmlDesignator' },
          { action: 'add-rule-obligation',
            operationId: 'addXacmlRuleObligation' },
          { action: 'add-policy-obligation',
            operationId: 'addXacmlPolicyObligation' },
          { action: 'add-rule-advice', operationId: 'addXacmlRuleAdvice' },
          { action: 'add-policy-advice', operationId: 'addXacmlPolicyAdvice' },
          { action: 'edit-obligation', operationId: 'editXacmlObligation' },
          { action: 'add-assignment', operationId: 'addXacmlAssignment' },
          // ---------------------------------------------------------------
          // THE POLICY SET, THE VARIABLES, THE SELECTORS AND THE FUNCTION
          // REFERENCES.
          //
          // Everything below reaches a part of the XACML syntax the editor
          // could not build before. Four of them are not new controls so much
          // as a repair: `add-policy` exists because a PolicySet used to be
          // offered `add-rule`, which the writer then discarded — an edit
          // accepted, reported as done, and absent from the stored document.
          //
          // EVERY ONE TAKES A `path`, and it is only valid against the document
          // GET /admin-api/xacml/editor returned. Re-read the tree after each
          // edit rather than reusing paths.
          // ---------------------------------------------------------------
          { action: 'add-policy', operationId: 'addXacmlPolicyToSet' },
          { action: 'add-policyset', operationId: 'addXacmlPolicySetToSet' },
          { action: 'add-policy-reference',
            operationId: 'addXacmlPolicyReference' },
          { action: 'add-policyset-reference',
            operationId: 'addXacmlPolicySetReference' },
          { action: 'edit-reference', operationId: 'editXacmlReference' },
          { action: 'add-variable', operationId: 'addXacmlVariable' },
          { action: 'edit-variable', operationId: 'renameXacmlVariable' },
          { action: 'set-expression-selector',
            operationId: 'setXacmlExpressionSelector' },
          { action: 'edit-selector', operationId: 'editXacmlSelector' },
          { action: 'set-expression-function',
            operationId: 'setXacmlExpressionFunction' },
          { action: 'edit-function', operationId: 'editXacmlFunctionReference' },
          { action: 'edit-assignment', operationId: 'editXacmlAssignment' },
          { action: 'disable-pep', operationId: 'disableXacmlPep' },
          { action: 'enable-pep', operationId: 'enableXacmlPep' },
          { action: 'forget-pep', operationId: 'forgetXacmlPep' },
          { action: 'issue-pep-certificate',
            operationId: 'issueXacmlPepCertificate' }
        ] }),

      { method: 'GET', path: BASE + '/ssf', tag: 'Shared Signals',
        operationId: 'getSsf',
        mirrors: 'GET /admin/ssf',
        parameters: [
          { name: 'stream', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256 },
            description: 'Only this stream. An exact stream id; applied ' +
                         'before the streams are paged.' },
          { name: 'streamsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the streams. Clamped, like every ' +
                         'page parameter here.' }
        ].concat(this.pagingParameters().filter(function (one) {
          return one.name === 'per';
        })),
        handler: function (req, res) {
          log.debug("Entering the management API Shared Signals endpoint.");
          self.sendJson(res, 200, adminViews.ssfJson(req));
          log.debug("Leaving the management API Shared Signals endpoint.");
        } },

      // ---------------------------------------------------------------------
      // WHAT COULD NOT BE DELIVERED, COUNTED (2026-09-14) — rule 7's half of
      // Monitoring → Shared Signals → Dead letters. A GET beside the POST
      // `/ssf/:action` below, which it cannot collide with: one method each.
      // No POST of its own, because the page has no control; the two that act
      // on dead letters are that operation's `revive` and `clear-dead-letters`.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/ssf/dead-letters', tag: 'Shared Signals',
        operationId: 'getSsfDeadLetters',
        mirrors: 'GET /admin/ssf/dead-letters',
        parameters: [
          { name: 'dlq', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256 },
            description: 'Narrows the letters to those whose jti, stream, ' +
                         'reason, error code, status, event name, type URI ' +
                         'or subject contains this.' },
          { name: 'dlstream', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256 },
            description: 'Only this stream\'s letters. An exact stream id.' },
          { name: 'dlcause', in: 'query', required: false,
            schema: { type: 'string',
                      enum: ['push-failed', 'backlog-full', 'declared-dead',
                             'dead-stream'] },
            description: 'Only letters of this cause.' },
          { name: 'lettersPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the matched letters. Clamped, like ' +
                         'every page parameter here.' },
          { name: 'streamsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the streams holding a letter or not ' +
                         'delivering, after `dlstream` and `dlcause` have ' +
                         'narrowed them. It shares `per` with the letters.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API dead letters endpoint.");
          self.sendJson(res, 200, adminViews.ssfDeadLettersJson(req));
          log.debug("Leaving the management API dead letters endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/ssf/:action', tag: 'Shared Signals',
        mirrors: 'POST /admin/ssf',
        handler: function (req, res) {
          log.debug("Entering the management API Shared Signals action " +
                    "endpoint.");
          const body = parseBody(req);
          // THE FIRST HANDLER IN THIS FILE THAT AWAITED; PKI, XACML, CAEP, RISC
          // and the database and secret-store reports have since. Transmitting
          // a Security Event Token signs a JWS — which may be ML-DSA or SLH-DSA
          // on the worker pool — and then POSTs it to somebody else's endpoint.
          // Neither can be done synchronously, and answering before either had
          // happened would be this API reporting "sent" about nothing.
          adminActions.ssfAction(self.withAction(req, body))
            .then(function (result) {
            if (!result.ok) {
              errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0052');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API Shared Signals action " +
                      "endpoint.");
          }).catch(function (e) {
            // A rejection here is a bug in ssf/ssf.ts rather than anything a
            // request can cause — its action function resolves a refusal rather
            // than throwing one — so it is reported as a refusal instead of
            // becoming an unhandled rejection that ends the process.
            errorCodes.mark(res, 'STS-API-0018');
            log.error('admin-api: the Shared Signals action threw: ' +
                      e.message);
            self.sendJson(res, 500, { ok: false,
              errors: ['The action failed: ' + e.message] });
            log.debug("Leaving the management API Shared Signals action " +
                      "endpoint. Threw.");
          });
          log.debug("Leaving handler().");
        },
        actions: [
          { action: 'status', operationId: 'setSsfStreamStatus' },

          { action: 'transmit', operationId: 'transmitSsfEvent' },

          { action: 'delete', operationId: 'deleteSsfStream' },

          { action: 'revive', operationId: 'reviveSsfStream' },

          { action: 'verify', operationId: 'verifySsfStream' },

          { action: 'clear-dead-letters', operationId: 'clearSsfDeadLetters' }
        ] }),

      // ---------------------------------------------------------------------
      // CAEP. A GET and a POST, and the POST is not optional: /admin/caep and
      // /admin/caep-sessions carry THREE controls between them — emit an event
      // by hand, reset one session's CAEP state, clear the register — and rule
      // 7 is about controls. All three call the same function the console's
      // forms post to, with `action` taken from the URL instead of from a
      // hidden input.
      //
      // **THERE IS DELIBERATELY NO WAY TO END A SESSION FROM HERE**, and that
      // is the same reading of rule 7 that leaves SSF without a `create`.
      // Emitting a `session-revoked` says a session was revoked; it does not
      // revoke one, and a management API that did both would make "tell the
      // receivers" and "sign this person out" one act — which is exactly the
      // conflation CAEP exists to separate. /logout, /admin/logout and POST
      // /admin-api/logout end sessions, and a sign-out through any of them
      // emits the event on its own.
      { method: 'GET', path: BASE + '/caep', tag: 'CAEP',
        operationId: 'getCaep',
        mirrors: 'GET /admin/caep',
        handler: function (req, res) {
          log.debug("Entering the management API CAEP endpoint.");
          self.sendJson(res, 200, adminViews.caepJson(req));
          log.debug("Leaving the management API CAEP endpoint.");
        } },

      // THE SECOND CAEP READ, AND IT EXISTS BECAUSE OF RULE 7 RATHER THAN
      // BECAUSE THE DOCUMENT IS DIFFERENT. `/admin/caep-sessions` is a page of
      // the console and had no operation naming it — the GET above mirrors
      // `/admin/caep`, and one operation cannot mirror two pages. That gap was
      // invisible until the parity check in tests/protocol/admin_api.js named
      // it.
      //
      // ONE OPERATION ANSWERS BOTH SHAPES, `?session=` deciding which, for the
      // reason /admin-api/permissions/groups gives: the list and the drill-down
      // are the same question at two scales and the console draws them from one
      // register, so two operations would be two places to disagree about what
      // a session's history is.
      { method: 'GET', path: BASE + '/caep/sessions', tag: 'CAEP',
        operationId: 'getCaepSessions',
        mirrors: 'GET /admin/caep-sessions',
        parameters: [
          { name: 'sessq', in: 'query', required: false,
            schema: { type: 'string' },
            description:
              'Narrows the register to rows whose username, `sub`, ' +
                         'session id, SSF subject or protocol contains this.' },
          { name: 'session', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One session id. The reply is then that session and ' +
                         'its events rather than the list.' },
          { name: 'sessionsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the register. Clamped, like every ' +
                         'page parameter here.' },
          { name: 'appq', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Narrows the per-receiver list to rows whose ' +
                         'application name, identifier or stream `aud` ' +
                         'contains this. It deliberately does NOT match ' +
                         'event types: a receiver that takes none of the ' +
                         'eight is exactly the row somebody is looking for ' +
                         'when they ask why nothing arrived.' },
          { name: 'applicationsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the per-receiver list. It shares ' +
                         '`per` with the register above ' +
                         'it, which is the arrangement ' +
                         'every page here that carries two lists has.' },
          { name: 'streamsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the streams a CAEP event could go ' +
                         'to. It shares `per` with the two lists above.' },
          { name: 'eventsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description:
              'Which page of ONE session\'s events, with `session`.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API CAEP sessions endpoint.");
          self.sendJson(res, 200, adminViews.caepSessionsJson(req));
          log.debug("Leaving the management API CAEP sessions endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/caep/:action', tag: 'CAEP',
        mirrors: 'POST /admin/caep',
        handler: function (req, res) {
          log.debug("Entering the management API CAEP action endpoint.");
          const body = parseBody(req);
          // AWAITS, like the Shared Signals handler above and for the same
          // reason: emitting a CAEP event signs a JWS — possibly ML-DSA or
          // SLH-DSA on the worker pool — and then POSTs it to somebody else's
          // endpoint.
          adminActions.caepAction(self.withAction(req, body))
            .then(function (result) {
            if (!result.ok) {
              errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0053');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API CAEP action endpoint.");
          }).catch(function (e) {
            errorCodes.mark(res, 'STS-API-0019');
            log.error('admin-api: the CAEP action threw: ' + e.message);
            self.sendJson(res, 500, { ok: false,
              errors: ['The action failed: ' + e.message] });
            log.debug("Leaving the management API CAEP action endpoint. " +
                      "Threw.");
          });
          log.debug("Leaving handler().");
        },
        actions: [
          { action: 'emit', operationId: 'emitCaepEvent' },

          { action: 'reset-session', operationId: 'resetCaepSession' },

          { action: 'clear', operationId: 'clearCaepSessions' }
        ] }),

      // ---------------------------------------------------------------------
      // RISC. A GET, a second GET and a POST, on exactly the CAEP block's terms
      // and for its reasons: /admin/risc and /admin/risc-accounts carry three
      // controls between them — emit an event by hand, reset one account's RISC
      // state, clear the register — and rule 7 is about controls.
      //
      // **THERE IS DELIBERATELY NO WAY TO DISABLE OR DELETE AN ACCOUNT FROM
      // HERE**, which is the same reading of rule 7 that leaves CAEP without a
      // way to end a session. Emitting an `account-disabled` says an account
      // was disabled; it does not disable one, and a management API that did
      // both would make "tell the receivers" and "deprovision this person" one
      // act — which is exactly the conflation RISC exists to separate. The
      // directory half is POST /admin-api/users and SCIM, and a write through
      // either emits the event on its own when `risc.autoEmit` is on.
      { method: 'GET', path: BASE + '/risc', tag: 'RISC',
        operationId: 'getRisc',
        mirrors: 'GET /admin/risc',
        handler: function (req, res) {
          log.debug("Entering the management API RISC endpoint.");
          self.sendJson(res, 200, adminViews.riscJson(req));
          log.debug("Leaving the management API RISC endpoint.");
        } },

      // THE SECOND RISC READ, for the reason the second CAEP read exists:
      // /admin/risc-accounts is a page of the console and one operation cannot
      // mirror two pages. `?account=` decides the shape, the list or the
      // drill-down, because they are the same question at two scales.
      { method: 'GET', path: BASE + '/risc/accounts', tag: 'RISC',
        operationId: 'getRiscAccounts',
        mirrors: 'GET /admin/risc-accounts',
        parameters: [
          { name: 'acctq', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Narrows the register to rows whose account id, ' +
                         'username, `sub`, email address, telephone number, ' +
                         'SSF subject, directory DN or any FORMER identifier ' +
                         'contains this.' },
          { name: 'account', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One account id. The reply is then that account and ' +
                         'its events rather than the list.' },
          { name: 'accountsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the register. Clamped, like every ' +
                         'page parameter here.' },
          { name: 'rappq', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Narrows the per-receiver list to rows whose ' +
                         'application name, identifier or stream `aud` ' +
                         'contains this. It deliberately does NOT match ' +
                         'event types: a receiver that takes none of the ' +
                         'fourteen is exactly the row somebody is looking ' +
                         'for when they ask why nothing arrived.' },
          { name: 'rapplicationsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the per-receiver list. It shares ' +
                         '`per` with the register above it.' },
          { name: 'streamsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the streams a RISC event could go ' +
                         'to. It shares `per` with the two lists above.' },
          { name: 'eventsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description:
              'Which page of ONE account\'s events, with `account`.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API RISC accounts endpoint.");
          self.sendJson(res, 200, adminViews.riscAccountsJson(req));
          log.debug("Leaving the management API RISC accounts endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/risc/:action', tag: 'RISC',
        mirrors: 'POST /admin/risc',
        handler: function (req, res) {
          log.debug("Entering the management API RISC action endpoint.");
          const body = parseBody(req);
          // AWAITS, like the CAEP handler above and for the same reason.
          adminActions.riscAction(self.withAction(req, body))
            .then(function (result) {
            if (!result.ok) {
              errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0054');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API RISC action endpoint.");
          }).catch(function (e) {
            errorCodes.mark(res, 'STS-API-0020');
            log.error('admin-api: the RISC action threw: ' + e.message);
            self.sendJson(res, 500, { ok: false,
              errors: ['The action failed: ' + e.message] });
            log.debug("Leaving the management API RISC action endpoint. " +
                      "Threw.");
          });
          log.debug("Leaving handler().");
        },
        actions: [
          { action: 'emit', operationId: 'emitRiscEvent' },

          { action: 'reset-account', operationId: 'resetRiscAccount' },

          { action: 'clear', operationId: 'clearRiscAccounts' }
        ] }),

      { method: 'GET', path: BASE + '/scim', tag: 'SCIM',
        operationId: 'getScim',
        mirrors: 'GET /admin/scim',
        parameters: [
          { name: 'client', in: 'query', required: false,
            schema: { type: 'string', maxLength: 512,
                      examples: ['no-such-client'] },
            description: 'One outbound SCIM client\'s identifier (#552): ' +
                         '`scimClients.client` is then that client\'s ' +
                         'page — its queues, dead letters and discovery.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API SCIM endpoint.");
          // Every cell's outbound SCIM clients (#553): asked of the other
          // cells, bounded; never rejects.
          adminViews.scimJsonAcrossCells(req).then(function (json) {
            self.sendJson(res, 200, json);
            log.debug("Leaving the management API SCIM endpoint.");
          }, function (e) {
            log.error(errorCodes.tag('STS-SCIMC-0018') + 'the SCIM view ' +
                      'failed: ' + ((e && e.message) || e));
            errorCodes.mark(res, 'STS-SCIMC-0018');
            self.sendJson(res, 500, { ok: false,
                                      errors: ['The view could not be ' +
                                               'drawn.'] });
            log.debug("Leaving the management API SCIM endpoint. Threw.");
          });
        } },

      // WHAT THAT SURFACE IS ACTUALLY DOING, as opposed to what it is. The
      // operation above mirrors /admin/scim, which is a page about the SURFACE;
      // this one mirrors /admin/scim/monitor, which the console files under
      // MONITORING because where a page goes is decided by the question it
      // answers. Both read one set of counters in common/admin_stats.js through
      // two functions, so there is no second tally for them to disagree over.
      //
      // NO POST BESIDE IT, and that is rule 7 read exactly rather than by
      // shape: the page it mirrors has no control. A reset was refused rather
      // than forgotten — a console that could zero its own monitoring would
      // make every number on it a number somebody might have zeroed, and the
      // audit log, which is the durable record, cannot be reset either.
      // -----------------------------------------------------------------------
      // PKI — the certificate authority this service maintains per trust realm.
      //
      // Rule 7: every control on `/admin/pki` — four when this was written, and
      // the workbench, hierarchy and revocation panes' since — has an action
      // here, through the SAME functions — `pkiAction()` in
      // `admin-ui/pki_admin.ts` — and decides nothing that console does not.
      //
      // **THE MODULE IS REQUIRED IN THE ORDINARY DIRECTION AND NEEDS NO SLOT**,
      // which is the one thing about this resource worth knowing. That module
      // sits at 18a in `common/protocol_stack.ts` — after `admin-ui/admin` and
      // BEFORE this file — so by the time this require runs it is a cache hit
      // and registers nothing. It requires only `admin.js` and `common/pki.js`,
      // and `pki.js` is a LIBRARY (rule 3), so there is no route this could
      // move and no cycle it could close.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/pki', tag: 'PKI',
        operationId: 'getPki',
        mirrors: 'GET /admin/pki',
        // THE TWO KEY-PAIR TABLES ARE PAGED ON THE PAGE (2026-09-13), and the
        // reply says which page each drew without slicing either list:
        // `issued` and `persons` stay WHOLE, because every reader of this
        // resource looks an application up in `issued` by identifier and a
        // reply holding one page would answer "not there" about page two.
        // `admin-ui/pki_admin.ts`'s `keyPairPaging()` argues it.
        // FIVE ROWS A PAGE, AND A CEILING (2026-09-30): `per` here may
        // shorten every list and cannot lengthen one, so its schema says five
        // rather than the console's MAX_ROWS. And each list has a search,
        // applied before it is paged. The `as any` below is a WIDENING, not
        // a library's wrong type: TypeScript takes the array's element type
        // from this first row's integer schema, and the two search rows
        // concatenated after it carry a string one.
        parameters: [
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, maximum: 5 } as any,
            description: 'Rows per page, SHARED by every paged list in the ' +
                         'reply: five by default and at most five.' }
        ].concat(this.detailPagingParameters([
          { name: 'issued',
            description: 'The Applications table on /admin/pki, five rows ' +
                         'a page. `issued` itself is the WHOLE list ' +
                         'whatever page is asked for; `issuedPaging` says ' +
                         'which rows the page drew.' },
          { name: 'persons',
            description: 'The People table on /admin/pki, paged by PERSON — ' +
                         'a person holding both profiles is one member of ' +
                         '`persons` and two rows on the page. `persons` is ' +
                         'the WHOLE list; `personsPaging` says which people ' +
                         'the page drew.' }
        ]), [
          { name: 'issuedq', in: 'query', required: false,
            schema: { type: 'string', maxLength: 200 },
            description: 'Narrows the Applications table before it is ' +
                         'paged: a case-insensitive substring of the ' +
                         'identifier, the profile, the key handle or a ' +
                         'declared issuer. `issuedPaging.total` is then the ' +
                         'count that matched, and `issuedSearch` echoes it.' },
          { name: 'rows', in: 'query', required: false,
            schema: { type: 'string', enum: ['all', 'shown'] },
            description: '`shown` reads each key pair\'s certificate — its ' +
                         '`pqc` member — for the rows of the requested ' +
                         'pages only, which is what the console draws; the ' +
                         'other rows carry no `pqc`. `all`, the default, ' +
                         'reads every row\'s.' },
          { name: 'personsq', in: 'query', required: false,
            schema: { type: 'string', maxLength: 200 },
            description: 'Narrows the People table before it is paged: a ' +
                         'case-insensitive substring of the username, either ' +
                         'key handle or an issuer either profile asserts as. ' +
                         '`personsPaging.total` is then the count that ' +
                         'matched, and `personsSearch` echoes it.' }
        ]),
        handler: function (req, res) {
          log.debug("Entering the management API PKI endpoint.");
          // `rows=shown` IS THE CONSOLE'S OWN CALL (#352, #446): each key
          // pair's certificate is read for the rows the page's two tables
          // draw and no others.
          self.sendJson(res, 200, pkiAdmin.pkiView(req, undefined,
            String(req.query.rows || '') === 'shown'
              ? { shownOnly: true } : undefined));
          log.debug("Leaving the management API PKI endpoint.");
        } },

      // ---------------------------------------------------------------------
      // RULE 7 FOR THE CERTIFICATE DETAILS DIALOG (2026-09-13). `/admin/pki`
      // and `/admin/crypto-metadata` open a certificate's every field and its
      // trust chain over the page; this is the same answer for a machine, from
      // the same view layer — so a certificate cannot be openable on one door
      // and unknown on the other. Without `certificate` it is the LIST a caller
      // finds the fingerprint in.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/certificates', tag: 'PKI',
        operationId: 'getCertificates',
        mirrors: 'GET /admin/pki and GET /admin/crypto-metadata',
        parameters: [
          { name: 'certificate', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'A SHA-256 certificate fingerprint, 64 hexadecimal ' +
                         'digits with or without colons — the `fingerprint` ' +
                         'of a row of the list. Returns that certificate\'s ' +
                         'details instead of the list.' },
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the subject, the issuer or where the ' +
                         'certificate appears, case-insensitive.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API certificates endpoint.");
          if (!String(req.query.certificate || '').trim()) {
            self.sendJson(res, 200, certificateViews.listView(req));
            log.debug("Leaving the management API certificates endpoint. " +
                      "List.");
            return;
          }
          certificateViews.detailsView(req).then(function (view) {
            if (!view.ok) {
              const code = errorCodes.codeOf(view) || 'STS-API-0080';
              errorCodes.mark(res, code);
              self.sendJson(res, code === 'STS-ADMIN-0641' ? 404
                : (code === 'STS-ADMIN-0642' ? 500 : 400), view);
              log.debug("Leaving the management API certificates endpoint. " +
                        "Refused.");
              return;
            }
            self.sendJson(res, 200, view);
            log.debug("Leaving the management API certificates endpoint. One.");
          }).catch(function (e) {
            errorCodes.mark(res, 'STS-ADMIN-0642');
            log.error(errorCodes.tag('STS-ADMIN-0642') + 'admin_api: the ' +
                      'certificate details view failed: ' + e.message);
            self.sendJson(res, 500, { ok: false, errors: [e.message] });
          });
        } },

      // #1360. Paranoid PKI mode, the signer truststore and what is pinned.
      // ABOVE `/pki/:action` only for a reader: one more path segment means the
      // two cannot match the same request.
      { method: 'GET', path: BASE + '/pki/trust', tag: 'PKI',
        operationId: 'getPkiTrust',
        mirrors: 'GET /admin/pki/trust',
        parameters: this.detailPagingParameters([
          { name: 'pins', description: 'The pinned certificates, newest ' +
                                       'first.' }
        ]).concat(this.pagingParameters().filter(function (one) {
          return one.name === 'per';
        })),
        handler: function (req, res) {
          log.debug("Entering the management API PKI trust endpoint.");
          self.sendJson(res, 200, adminViews.pkiTrustJson(req));
          log.debug("Leaving the management API PKI trust endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/pki/trust/:action', tag: 'PKI',
        mirrors: 'POST /admin/pki/trust',
        handler: function (req, res) {
          log.debug("Entering the management API PKI trust action endpoint.");
          const body = parseBody(req);
          // AWAITED, AND THE REJECTION IS TURNED INTO A REFUSAL, `/pki/:action`'s
          // reason: Express 4 does not look at what a handler returns.
          adminActions.pkiTrustAction(self.withAction(req, body),
            { via: 'api', actor: self.callerNameOf(res) })
            .then(function (result) {
              if (!result.ok) {
                errorCodes.mark(res, errorCodes.codeOf(result) ||
                                     'STS-API-0141');
              }
              self.sendJson(res, result.ok ? 200 : 400, result);
              log.debug("Leaving the management API PKI trust action " +
                        "endpoint.");
            }, function (e) {
              log.debug("Caught in the management API PKI trust action " +
                        "endpoint: " + ((e && e.message) || e));
              errorCodes.mark(res, 'STS-API-0141');
              self.sendJson(res, 500, { ok: false, errors: [e.message] });
            });
        },
        actions: [
          { action: 'add', operationId: 'addSignerTrustAnchors' },
          { action: 'remove', operationId: 'removeSignerTrustAnchor' },
          { action: 'recheck', operationId: 'recheckPinnedCertificates' },
          { action: 'set-row', operationId: 'setParanoidPkiRow' }
        ] }),

      ApiRows.actions({ method: 'POST',
        route: BASE + '/pki/:action', tag: 'PKI',
        // TWO CONSOLE PATHS, because the pane answers with a PAGE rather than a
        // redirect and needs a route of its own to do it. This field is how the
        // console suite builds "console paths that take a POST", so a control
        // posting somewhere other than its list page has to be named here or
        // that check quietly stops covering it — which is what /admin/users/new
        // records.
        mirrors: 'POST /admin/pki, POST /admin/pki/certificate and POST ' +
                 '/admin/pki/person',
        handler: function (req, res) {
          log.debug("Entering the management API PKI action endpoint.");
          const body = parseBody(req);
          // **AWAITED, AND THE REJECTION IS TURNED INTO A REFUSAL.** Issuing a
          // certificate is Web Crypto all the way down, so this is the second
          // action handler in this API that resolves rather than returning
          // (`/ssf/:action` is the first, and for a related reason: it signs
          // and then POSTs). Express 4 does not look at what a handler returns,
          // so an unhandled rejection here would be a request that never gets
          // an answer.
          pkiAdmin.pkiAction(self.withAction(req, body))
            .then(function (result) {
            if (!result.ok) {
              errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0055');
            }
            // A PANE ACTION'S NEXT DRAFT, as the workbench draws it (#446):
            // the console draws the pane again from `workbench`, refused or
            // not. `authoring.view()` carries no private key.
            const answered = result && result.draft
              ? Object.assign({}, result,
                              { workbench: pkiAdmin.workbenchOf(result.draft) })
              : result;
            self.sendJson(res, result.ok ? 200 : 400, answered);
            log.debug("Leaving the management API PKI action endpoint.");
          }).catch(function (e) {
            errorCodes.mark(res, 'STS-API-0021');
            log.error('the management API PKI action threw: ' +
                      (e && e.stack ? e.stack : e));
            self.sendJson(res, 500, { ok: false,
                                      errors: ['That action failed: ' +
                                               (e && e.message ? e.message :
                                                e)] });
          });
          log.debug("Leaving handler().");
        },
        actions: [
          { action: 'build', operationId: 'buildPkiChain' },

          { action: 'issue', operationId: 'issuePkiKeyPair' },

          { action: 'revoke', operationId: 'revokePkiKeyPair' },

          // THE OTHER WAY A KEY PAIR IS REPLACED (2026-09-13), drawn beside
          // `issue` on an application's own console page. `common/pki.js`'s
          // `registerCertificate()` decides whether the chain is acceptable.
          { action: 'upload-certificate', operationId: 'uploadPkiCertificate' },

          { action: 'clear', operationId: 'clearPkiChain' },

          // ===================================================================
          // THE CERTIFICATE & KEY CONFIGURATION PANE (2026-09-10).
          //
          // Eight operations, and every one of them takes and returns THE WHOLE
          // FORM. That is not an API shaped by a page: the pane has a hundred
          // and fifteen fields, `apply-profile` rewrites twenty-two of them,
          // and a caller that had to reconstruct the result itself would be a
          // second implementation of what a profile MEANS. So the reply carries
          // `draft` — the form as it should now be — and a caller does
          // `apply-profile`, edits three fields of what came back, and posts it
          // to `issue-certificate`.
          //
          // **THE FIELD NAMES ARE THE DEBUGGER PKI / X.509 PAGE'S, VERBATIM**
          // (`pki_dn_cn`, `pki_ext_bc`, `pki_ku_keyCertSign`). The two are one
          // form over one encoder; `GET /admin-api/pki` publishes the whole
          // list as `workbench.fields`, so a client reads the vocabulary from
          // the service rather than from a copy of it in a document.
          // ===================================================================
          { action: 'apply-profile', operationId: 'applyPkiProfile' },

          { action: 'generate-keys', operationId: 'generatePkiKeyPair' },

          { action: 'generate-alt-keys', operationId: 'generatePkiAltKeyPair' },

          { action: 'issue-certificate', operationId: 'issuePkiCertificate' },

          { action: 'use-key', operationId: 'usePkiStoredKey' },

          { action: 'remove-object', operationId: 'removePkiObject' },

          { action: 'clear-store', operationId: 'clearPkiObjects' },

          { action: 'export', operationId: 'exportPkiKeyPair' },

          // ===================================================================
          // THE HIERARCHY ITSELF (2026-09-11). One Root for the service, an
          // Intermediate per scope, an Issuing CA per use case — and every key
          // pair this service generates as a leaf of it.
          //
          // **`scope` IS A REALM ID, `*service` OR `*process`.** A realm id is
          // `[a-z0-9-]` and must start with a letter or a digit, so the two
          // starred names cannot collide with one. Omitted, it means the realm
          // the request arrived in, which is what every other control here
          // means by saying nothing.
          // ===================================================================
          { action: 'build-root', operationId: 'buildPkiRoot' },

          { action: 'build-scope', operationId: 'buildPkiScope' },

          { action: 'reissue-use-case', operationId: 'reissuePkiUseCase' },

          { action: 'recertify', operationId: 'recertifyPkiUseCase' },

          { action: 'import-ca', operationId: 'importPkiCa' },

          { action: 'pin-key', operationId: 'pinPkiKeyPair' },

          { action: 'unpin-key', operationId: 'unpinPkiKeyPair' },

          // ---------------------------------------------------------------
          // THE REVOCATION PANE'S TWO, SINCE 2026-09-11.
          //
          // They arrived on `/admin/pki` and on `PKI_ACTIONS` and NOT here,
          // which is rule 7 unpaid — and the thing that caught it was not the
          // parity check: `tests/protocol/sts_admin_api_operations.js` compares
          // the refusal SENTENCE this endpoint prints for an unknown action
          // against the actions this document declares, and the sentence is
          // generated from `PKI_ACTIONS`. So the console had two controls whose
          // operations nothing could find, and the API accepted both of them
          // the whole time: the route is `/pki/:action`, so an undeclared
          // action still WORKS — what it does not do is appear in the document,
          // which is the only place a machine driving this API can read the
          // repertoire from.
          // ---------------------------------------------------------------
          { action: 'revoke-certificate', operationId: 'revokePkiCertificate' },

          { action: 'release-hold', operationId: 'releasePkiCertificateHold' }
        ] }),

      { method: 'GET', path: BASE + '/scim/monitor', tag: 'SCIM',
        operationId: 'getScimMonitor',
        mirrors: 'GET /admin/scim/monitor',
        handler: function (req, res) {
          log.debug("Entering the management API SCIM monitor endpoint.");
          self.sendJson(res, 200, adminViews.scimMonitorJson(req));
          log.debug("Leaving the management API SCIM monitor endpoint.");
        } },

      // ---------------------------------------------------------------------
      // WHAT THE CONSOLE WAS TOLD, AND WHY IT IS A RESOURCE OF ITS OWN RATHER
      // THAN A MEMBER OF /admin-api/ssf.
      //
      // That resource is the TRANSMITTER's: the streams, their subjects, their
      // queues and what went out on each. This one is the RECEIVER's, and the
      // whole value of keeping them apart is that this one goes empty when
      // delivery is broken while the other does not — a reply that carried both
      // would answer "what has been said" and "what has been heard" with one
      // document and lose exactly the disagreement worth having.
      // ---------------------------------------------------------------------
      { method: 'GET', path: BASE + '/signals', tag: 'Shared Signals',
        operationId: 'getSignals',
        mirrors: 'GET /admin/signals',
        parameters: [
          { name: 'sigq', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Narrows the list to rows whose event name, type ' +
                         'URI, subject, issuer, audience, `jti` or stream id ' +
                         'contains this. One box over all of them, because a ' +
                         'reader arrives holding one and does not know which ' +
                         'column it is in.' },
          { name: 'receivedPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the delivered events. Clamped, like ' +
                         'every page parameter here.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API signals endpoint.");
          self.sendJson(res, 200, adminViews.signalsJson(req));
          log.debug("Leaving the management API signals endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/signals/:action', tag: 'Shared Signals',
        mirrors: 'POST /admin/signals',
        handler: function (req, res) {
          log.debug("Entering the management API signals action endpoint.");
          const body = parseBody(req);
          const result = adminActions.signalsAction(self.withAction(req, body));
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0056');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API signals action endpoint.");
        },
        actions: [
          { action: 'clear', operationId: 'clearSignalsInbox' }
        ] }),

      // -----------------------------------------------------------------------
      // THE CLIENT-CERTIFICATE TRUSTSTORE (2026-09-12).
      //
      // Rule 7: `/admin/tls/trust` has two controls, so this resource has the
      // same two, through `truststoreAction()` and `truststoreJson()` in
      // `admin-core/`, which reach `tls/tls_server.js` through
      // `admin.setTruststore()`.
      //
      // **BOTH OPERATIONS ARE PINNED TO THE FRONT PROCESS** in
      // `workers.dispatch` mode (`common/request_pool.js`'s
      // `NEVER_DISPATCHED`): the anchors are the configuration of listeners
      // only that process holds, and a worker changing its own copy would
      // change nothing a handshake reads. They are FANNED out nowhere, answered
      // nowhere else, and carry no realm: the array is the process's, so every
      // realm prefix reads and writes the same one.
      //
      // **THIS IS THE RUNTIME DOOR, AND SINCE #597 THE ONLY ONE BESIDE THE
      // CONSOLE'S.** The open `POST /tls/trust` needed no credential, and
      // #597 deleted it; this API's own access token is the credential here,
      // `admin:read` to list and `admin:write` to change — the gate below
      // every operation, by method, so nothing in these two rows re-checks
      // it.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/tls/trust', tag: 'TLS',
        operationId: 'getTruststore',
        mirrors: 'GET /admin/tls/trust',
        parameters: this.pagingParameters(),
        handler: function (req, res) {
          log.debug("Entering the management API truststore endpoint.");
          const json = adminViews.truststoreJson(req);
          if (!json.installed) {
            errorCodes.mark(res, 'STS-API-0017');
          }
          self.sendJson(res, json.installed ? 200 : 503, json);
          log.debug("Leaving the management API truststore endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/tls/trust/:action', tag: 'TLS',
        mirrors: 'POST /admin/tls/trust',
        handler: function (req, res) {
          log.debug("Entering the management API truststore action endpoint.");
          const body = parseBody(req);
          const result = adminActions.truststoreAction(self.withAction(req,
              body),
                                                       { via: 'api' });
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0057');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API truststore action endpoint.");
        },
        actions: [
          { action: 'add', operationId: 'addTrustAnchors' },

          { action: 'remove', operationId: 'removeTrustAnchor' }
        ] }),

      // -----------------------------------------------------------------------
      // MONITORING → TLS CONNECTION (#597, rcbj's decision 3 on #591): what
      // `GET /tls` and `GET /tls/forwarded` showed anybody in development,
      // as a read behind this API's gate, in both modes. The view is
      // `tls/tls_server.js`'s `connectionView()`, reached LAZILY: that module
      // is required at 20, after this one, and requiring it here would
      // register its routes ahead of everything between (rule 1).
      //
      // **PINNED TO THE FRONT PROCESS** with the page
      // (`request_pool.js`'s NEVER_DISPATCHED): the socket a worker sees is
      // the unix socket from its front process, which is not a fact about
      // the caller.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/tls-connection', tag: 'TLS',
        operationId: 'getTlsConnection',
        mirrors: 'GET /admin/tls-connection',
        handler: function (req, res) {
          log.debug("Entering the management API TLS connection endpoint.");
          require('../tls/tls_server').connectionView(req)
            .then(function (view) {
              self.sendJson(res, 200, view);
              log.debug("Leaving the management API TLS connection " +
                        "endpoint.");
            });
        } },

      // -----------------------------------------------------------------------
      // THE STORED KERBEROS KEYS (2026-09-12).
      //
      // Rule 7: `/admin/kerberos/principals` has six controls — the two "Drop
      // previous versions" buttons joined the four on 2026-09-12 — and a
      // person's page under Directory → Users a seventh (#59, "Reset password
      // and download keytab", posted to the same page), and the krbtgt block
      // two more (#169, "Rotate the krbtgt key" and "Rotate and
      // invalidate"), so this resource has the same nine, through
      // `kerberosPrincipalsAction()` and
      // `kerberosPrincipalsJson()` in `admin-core/`, which reach
      // `kerberos/krb5_person_keys.ts` by a plain require.
      //
      // **NO KEY IS IN ANY REPLY BUT THREE**, and those are the whole reason
      // a service principal can be created from a machine: `create-service` and
      // `rotate-service` return the KEYTAB, base64, ONCE — and so does
      // `reset-person-keytab` (#59), derived from the password it sets. Nothing reads a
      // stored key back out afterwards — a lost keytab is replaced by rotating.
      // The GET is built from the public half of each pair of attributes and
      // opens nothing.
      //
      // **A KDC PER TRUST REALM SINCE 2026-09-15**, so a call under a realm
      // prefix reads and writes THAT realm's principals — the people in its
      // directory and the service principals in its registry — and each reply
      // says `trustRealm`. A realm whose `krb5.enabled` is off has no
      // principals and says so. Until that date there was one KDC for the
      // process and every prefix reached the default realm's.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/kerberos/principals', tag: 'Kerberos',
        operationId: 'getKerberosPrincipals',
        mirrors: 'GET /admin/kerberos',
        // `per` and the two lists' own page parameters — NOT
        // pagingParameters(), whose `page` this resource never reads.
        parameters: this.pagingParameters().filter(function (one) {
          return one.name === 'per';
        }).concat(this.detailPagingParameters([
          { name: 'people',
            description: 'Directory people holding keys derived from their ' +
                         'own password.' },
          { name: 'services',
            description: 'Service principals created with a random key.' },
          { name: 'database',
            description: 'Every principal in the KDC\'s database, by its ' +
                         'public fields.' }
        ])),
        handler: function (req, res) {
          log.debug("Entering the management API Kerberos principals " +
                    "endpoint.");
          self.sendJson(res, 200, adminViews.kerberosPrincipalsJson(req));
          log.debug("Leaving the management API Kerberos principals endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/kerberos/principals/:action',
        tag: 'Kerberos',
        mirrors: 'POST /admin/kerberos#kerberos-tab-principals, POST ' +
                 '/admin/kerberos/principals',
        handler: function (req, res) {
          log.debug("Entering the management API Kerberos principals action " +
                    "endpoint.");
          const body = parseBody(req);
          // `reset-person-keytab` (#59) answers a PROMISE — its string-to-key
          // is asynchronous — so every answer is resolved.
          Promise.resolve(adminActions.kerberosPrincipalsAction(
              self.withAction(req, body),
              { via: 'api' }))
            .then(function (result) {
              if (!result.ok) {
                errorCodes.mark(res, errorCodes.codeOf(result) ||
                                     'STS-API-0065');
              }
              if (result.ok && result.keytab) {
                // A key is in the body.
                res.set('Cache-Control', 'no-store');
              }
              self.sendJson(res, result.ok ? 200 : 400, result);
            }, function (e) {
              log.error(errorCodes.tag('STS-API-0065') + 'admin-api: a ' +
                        'Kerberos principals action threw: ' +
                        ((e && e.stack) || e));
              errorCodes.mark(res, 'STS-API-0065');
              self.sendJson(res, 500, { ok: false, errors: ['The action ' +
                'failed inside this service; the log says why.'] });
            });
          log.debug("Leaving the management API Kerberos principals action " +
                    "endpoint. Answering when the action settles.");
        },
        actions: [
          { action: 'create-service',
            operationId: 'createKerberosServicePrincipal' },

          { action: 'rotate-service',
            operationId: 'rotateKerberosServicePrincipal' },

          { action: 'delete-service',
            operationId: 'deleteKerberosServicePrincipal' },

          { action: 'clear-person-keys', operationId: 'clearKerberosPersonKeys' },

          { action: 'drop-previous-service-keys',
            operationId: 'dropKerberosServicePreviousKeys' },

          { action: 'drop-previous-person-keys',
            operationId: 'dropKerberosPersonPreviousKeys' },

          // #59 (2026-09-22): the console's "Reset password and download
          // keytab" on a person's page, rule 7's twin.
          { action: 'reset-person-keytab',
            operationId: 'resetKerberosPersonKeytab' },

          // #169 (2026-09-23): the realm's krbtgt key, rule 7's twins of the
          // two krbtgt controls on /admin/kerberos/principals. Each QUEUES a
          // run of `krb5.krbtgt-rotate-now`; neither returns a key.
          { action: 'rotate-krbtgt',
            operationId: 'rotateKerberosKrbtgt' },

          { action: 'rotate-krbtgt-invalidate',
            operationId: 'rotateKerberosKrbtgtInvalidate' }
        ] }),

      // -----------------------------------------------------------------------
      // THE KERBEROS TRUSTS (#430 Phase 4, 2026-10-20).
      //
      // Rule 7: the Trusts tab of `/admin/kerberos` has seven controls — Add,
      // and per row Edit, Enable or Disable, Rotate key, Remove and Pair —
      // and this resource has the same seven, through
      // `kerberosTrustsAction()` and `kerberosTrustsJson()` in
      // `admin-core/`, which reach `kerberos/krb5_trusts.ts`.
      //
      // **NO KEY AND NO PASSWORD IS IN ANY REPLY**, but one: a key this
      // service GENERATED (`keySource: "generate"`) is in `shown` once, base64
      // per enctype, for the partner's administrator to enter on their side.
      // A trust password is written and never shown back. The audit row of
      // every act names the trust and never a key.
      //
      // **A REALM'S OWN**: a call under a realm prefix reads and writes that
      // realm's records. `pair` — and `rotate-key` with `mirror` — write the
      // matching record on ANOTHER trust realm too, so a realm
      // administrator's token is refused them (`admin-ui/admin_scope.ts`).
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/kerberos/trusts', tag: 'Kerberos',
        operationId: 'getKerberosTrusts',
        mirrors: 'GET /admin/kerberos',
        parameters: this.pagingParameters().filter(function (one) {
          return one.name === 'per';
        }).concat(this.detailPagingParameters([
          { name: 'trusts',
            description: 'The realm\'s trust records.' }
        ])).concat(<any[]>[
          { name: 'trust', in: 'query', required: false,
            description: 'One partner realm, for its record whole.',
            schema: { type: 'string' } }
        ]),
        handler: function (req, res) {
          log.debug("Entering the management API Kerberos trusts endpoint.");
          self.sendJson(res, 200, adminViews.kerberosTrustsJson(req));
          log.debug("Leaving the management API Kerberos trusts endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/kerberos/trusts/:action',
        tag: 'Kerberos',
        mirrors: 'POST /admin/kerberos#kerberos-tab-trusts, POST ' +
                 '/admin/kerberos/trusts',
        handler: function (req, res) {
          log.debug("Entering the management API Kerberos trusts action " +
                    "endpoint.");
          const body = parseBody(req);
          let result;
          try {
            result = adminActions.kerberosTrustsAction(
              self.withAction(req, body), { via: 'api',
                actor: self.callerNameOf(res) || 'admin-api' });
          } catch (e) {
            log.error(errorCodes.tag('STS-API-0135') + 'admin-api: a ' +
                      'Kerberos trusts action threw: ' +
                      ((e && e.stack) || e));
            errorCodes.mark(res, 'STS-API-0135');
            self.sendJson(res, 500, { ok: false, errors: ['The action ' +
              'failed inside this service; the log says why.'] });
            log.debug("Leaving the management API Kerberos trusts action " +
                      "endpoint. Threw.");
            return;
          }
          if (result.ok && result.shown) {
            // A generated key is in the body.
            res.set('Cache-Control', 'no-store');
          }
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) ||
                                 'STS-ADMIN-0859');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API Kerberos trusts action " +
                    "endpoint.");
        },
        actions: [
          { action: 'add', operationId: 'addKerberosTrust' },
          { action: 'update', operationId: 'updateKerberosTrust' },
          { action: 'enable', operationId: 'enableKerberosTrust' },
          { action: 'disable', operationId: 'disableKerberosTrust' },
          { action: 'rotate-key', operationId: 'rotateKerberosTrustKey' },
          { action: 'remove', operationId: 'removeKerberosTrust' },
          { action: 'pair', operationId: 'pairKerberosTrust' }
        ] }),

      { method: 'GET', path: BASE + '/audit/integrity', tag: 'Audit log',
        operationId: 'getAuditIntegrity',
        mirrors: 'GET /admin/audit',
        handler: function (req, res) {
          log.debug("Entering the management API audit integrity endpoint.");
          self.sendJson(res, 200, require('../common/audit').verifyIntegrity());
          log.debug("Leaving the management API audit integrity endpoint.");
        } },

      { method: 'GET', path: BASE + '/audit', tag: 'Audit log',
        operationId: 'getAudit',
        mirrors: 'GET /admin/audit',
        parameters: [
          { name: 'category', in: 'query', required: false,
            schema: { type: 'string',
                      enum: closed.auditCategories },
            description: 'One of the categories. The reply\'s `categories` ' +
                         'member describes each of them.' },
          { name: 'action', in: 'query', required: false,
            schema: { type: 'string', enum: closed.auditActions },
            description: 'One action. ANDed with `category`, so an action ' +
                         'from another category matches nothing — which is ' +
                         'what an empty list then means. ' +
                         'The reply\'s `actions` member ' +
                         'lists every action with the category it belongs ' +
                         'to.' },
          { name: 'outcome', in: 'query', required: false,
            schema: { type: 'string', enum: closed.auditOutcomes },
            description: 'Three rather than two on purpose: a `refused` is ' +
                         'this service working correctly and saying no, an ' +
                         '`error` is this service failing, and collapsing ' +
                         'them would bury the one row worth ' +
                         'paging somebody about under the ' +
                         'fifty that are a client getting its parameters ' +
                         'wrong.' },
          { name: 'actor', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Substring of either spelling of the actor, ' +
                         'case-insensitive — the normalised key (`alice`) or ' +
                         'the form it was presented in (a bind DN, ' +
                         '`alice@REALM`, an X.509 subject). A substring ' +
                         'because the collapse to one key can ' +
                         'only be done where an identity is ' +
                         'normalised, and a directory row\'s actor is a DN.' },
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the summary, the target or the ' +
                         'action, case-insensitive.' },
          { name: 'code', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The FRONT of an error code: a whole code is one ' +
                         'failure condition and `STS-OAUTH` every failure in ' +
                         'that subsystem. docs/error-codes.md lists them. ' +
                         'Every refused or failed request ' +
                         'carries a code; no code is ' +
                         'ever sent to the client that made the request.' },
          { name: 'address', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The FRONT of the client\'s IP address, ' +
                         'case-insensitive: a whole address is one client ' +
                         'and `10.0.` every client in that range. A prefix ' +
                         'rather than a substring, so `10.0.0.1` cannot ' +
                         'match inside `110.0.0.12`.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res, next) {
          log.debug("Entering the management API audit endpoint.");
          // Every other process's events, read now (#820): they are noted,
          // not replicated, until a page asks.
          audit.fresh().then(function () {
            self.sendJson(res, 200, adminViews.auditView(req.query).json);
            log.debug("Leaving the management API audit endpoint.");
          }).catch(function (e) {
            log.debug("Caught in the management API audit endpoint: " +
                      ((e && e.message) || e));
            next(e);
          });
        } },

      // THE ERROR CODES (2026-09-12). A read with no write beside it, which is
      // rule 7 read exactly: the page it mirrors has no control, because the
      // table is source and a code's meaning cannot change at runtime without
      // making every alert rule written against it a statement about something
      // else.
      { method: 'GET', path: BASE + '/error-codes', tag: 'Audit log',
        operationId: 'getErrorCodes',
        mirrors: 'GET /admin/error-codes',
        parameters: [
          { name: 'subsystem', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One subsystem id — `OAUTH`, `LDAP`, `XPEP` — as ' +
                         '`subsystems[].id` lists them. Case-insensitive.' },
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the code, the summary or what the ' +
                         'client sees, case-insensitive — a code pasted out ' +
                         'of a log line, or a protocol error name such as ' +
                         '`invalid_grant`.' },
          { name: 'seen', in: 'query', required: false,
            schema: { type: 'string' },
            description:
              '`1` for only the codes on at least one held audit row.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res, next) {
          log.debug("Entering the management API error codes endpoint.");
          // The codes seen are counted over every process's events (#820).
          audit.fresh().then(function () {
            self.sendJson(res, 200,
                          adminViews.errorCodesView(req.query).json);
            log.debug("Leaving the management API error codes endpoint.");
          }).catch(function (e) {
            log.debug("Caught in the management API error codes endpoint: " +
                      ((e && e.message) || e));
            next(e);
          });
        } },

      // THE USED-ASSERTION HISTORY (2026-09-13). A read with no write beside
      // it, which is rule 7 read exactly: the page it mirrors has no control,
      // because forgetting a row would make a still-valid assertion usable
      // again. A PROMISE, because on a postgres store the history is the
      // database's.
      { method: 'GET', path: BASE + '/used-assertions', tag: 'Tokens',
        operationId: 'getUsedAssertions',
        mirrors: 'GET /admin/used-assertions',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the issuer, the `jti` or `ID`, the ' +
                         'client or the subject, case-insensitive.' },
          { name: 'format', in: 'query', required: false,
            schema: { type: 'string', enum: closed.usedAssertionFormats },
            description: '`jwt` (RFC 7523) or `saml` (RFC 7522).' },
          { name: 'use', in: 'query', required: false,
            schema: { type: 'string',
                      enum: closed.usedAssertionUses },
            description: 'What the assertion was accepted AS — ' +
                         '`request-object` is an RFC 9101 request object ' +
                         'whose `jti` was spent (#35).' },
          { name: 'state', in: 'query', required: false,
            schema: { type: 'string', enum: closed.usedAssertionStates },
            description: '`reserved` (its token request has not finished) or ' +
                         '`spent` (tokens were issued).' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API used assertions endpoint.");
          adminViews.usedAssertionsView(req.query).then(function (view) {
            self.sendJson(res, 200, view.json);
            log.debug("Leaving the management API used assertions endpoint.");
          }).catch(function (e) {
            errorCodes.mark(res, 'STS-API-0081');
            self.sendJson(res, 500, { ok: false, errors: [
              'The used-assertion history could not be read: ' +
              (e && e.message ? e.message : String(e))] });
            log.debug("Leaving the management API used assertions endpoint. " +
                      "It threw.");
          });
          log.debug("Leaving handler().");
        } },

      // Delegation. THE SECOND READ-ONLY RESOURCE HERE, and for a related
      // reason to the audit log's: it mirrors a console page with no form on
      // it. Everything that page shows is an observation — an act happened or
      // it did not, and the policy half is the KERBEROS principal database's
      // configuration, which is not settable from anywhere in this service.
      // There is nothing to change, so there is nothing to document as
      // changeable, and rule 7 is satisfied by this GET alone.
      { method: 'GET', path: BASE + '/delegation', tag: 'Delegation',
        operationId: 'getDelegation',
        mirrors: 'GET /admin/delegation',
        parameters: withDelegationQuery([]),
        handler: function (req, res) {
          log.debug("Entering the management API delegation endpoint.");
          // The page's model since #446: the acts as before, and beside
          // them what /admin/delegation draws (`allowed`,
          // `delegationPolicy`, its other lists and the two choosers).
          self.sendJson(res, 200, adminViews.delegationPageModel(req.query));
          log.debug("Leaving the management API delegation endpoint.");
        } },

      // THE PICTURE OF THOSE ACTS (#446, 2026-10-05). The console page had no
      // operation — it has no form — and a console that is a static client
      // of this API needs what only this process knows about it: what each
      // box IS, where it GOES, and the drawing's markup. See
      // `AdminViews.delegationMapModel()`.
      { method: 'GET', path: BASE + '/console/delegation/map',
        kind: 'console', tag: 'Delegation',
        operationId: 'getDelegationMap',
        mirrors: 'GET /admin/delegation/map',
        parameters: withDelegationQuery(delegationFilter.concat([
          { name: 'format', in: 'query', required: false,
            schema: { type: 'string', enum: ['json', 'svg'] },
            description: '`svg` answers the drawing alone, as a document ' +
                         'with no links in it. `json`, the default, ' +
                         'answers everything.' }
        ])),
        handler: function (req, res) {
          log.debug("Entering the management API delegation map endpoint.");
          if (String((req.query || {}).format || '') === 'svg') {
            const bare = adminViews.delegationMapModel(req.query,
                                                       { links: false });
            res.status(200).set('Cache-Control', 'no-store')
               .type('image/svg+xml').send(bare.svg);
            log.debug("Leaving the management API delegation map endpoint. " +
                      "Answered SVG.");
            return;
          }
          self.sendJson(res, 200, adminViews.delegationMapModel(req.query));
          log.debug("Leaving the management API delegation map endpoint.");
        } },

      // THE FEDERATION PICTURE (#446): the console page had no operation,
      // having no form; see `AdminViews.federationMapModel()`.
      { method: 'GET', path: BASE + '/console/federation/map',
        kind: 'console', tag: 'Federation',
        operationId: 'getFederationMap',
        mirrors: 'GET /admin/federation/map',
        parameters: [
          { name: 'role', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Only relationships in this role.' },
          { name: 'protocol', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Only relationships in this protocol.' },
          { name: 'q', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Text anywhere in a relationship.' },
          { name: 'format', in: 'query', required: false,
            schema: { type: 'string', enum: ['json', 'svg'] },
            description: '`svg` answers the drawing alone, as a document ' +
                         'with no links in it. `json`, the default, ' +
                         'answers everything.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API federation map endpoint.");
          if (String((req.query || {}).format || '') === 'svg') {
            const bare = adminViews.federationMapModel(req.query,
                                                       { links: false });
            res.status(200).set('Cache-Control', 'no-store')
               .type('image/svg+xml').send(bare.svg);
            log.debug("Leaving the management API federation map endpoint. " +
                      "Answered SVG.");
            return;
          }
          self.sendJson(res, 200, adminViews.federationMapModel(req.query));
          log.debug("Leaving the management API federation map endpoint.");
        } },

      // ONE GROUP OF APPLICATIONS, DRAWN (#446): the console page had no
      // operation, having no form; see `AdminViews.delegationClusterModel()`.
      { method: 'GET', path: BASE + '/console/delegation/cluster',
        kind: 'console', tag: 'Delegation',
        operationId: 'getDelegationCluster',
        mirrors: 'GET /admin/delegation/cluster',
        parameters: withDelegationQuery(([] as any[]).concat([
          { name: 'application', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The application\'s identifier, exactly.' },
          { name: 'format', in: 'query', required: false,
            schema: { type: 'string', enum: ['json', 'svg'] },
            description: '`svg` answers the drawing alone, as a document ' +
                         'with no links in it. `json`, the default, ' +
                         'answers everything.' }
        ], self.pagingParameters())),
        handler: function (req, res) {
          log.debug("Entering the management API delegation cluster " +
                    "endpoint.");
          if (String((req.query || {}).format || '') === 'svg') {
            const bare = adminViews.delegationClusterModel(req.query,
                                                           { links: false });
            res.status(200).set('Cache-Control', 'no-store')
               .type('image/svg+xml').send(bare.svg);
            log.debug("Leaving the management API delegation cluster " +
                      "endpoint. Answered SVG.");
            return;
          }
          self.sendJson(res, 200,
                        adminViews.delegationClusterModel(req.query));
          log.debug("Leaving the management API delegation cluster " +
                    "endpoint.");
        } },

      // THE ALLOWED MAPPINGS, DRAWN (#446): the console page had no
      // operation, having no form; see `AdminViews.delegationAllowedModel()`.
      { method: 'GET', path: BASE + '/console/delegation/allowed',
        kind: 'console', tag: 'Delegation',
        operationId: 'getDelegationAllowed',
        mirrors: 'GET /admin/delegation/allowed',
        parameters: withDelegationQuery(([] as any[]).concat(
          self.pagingParameters(), [
          { name: 'format', in: 'query', required: false,
            schema: { type: 'string', enum: ['json', 'svg'] },
            description: '`svg` answers the drawing alone, as a document ' +
                         'with no links in it. `json`, the default, ' +
                         'answers everything.' }
        ])),
        handler: function (req, res) {
          log.debug("Entering the management API allowed delegation " +
                    "endpoint.");
          if (String((req.query || {}).format || '') === 'svg') {
            const bare = adminViews.delegationAllowedModel(req.query,
                                                           { links: false });
            res.status(200).set('Cache-Control', 'no-store')
               .type('image/svg+xml').send(bare.svg);
            log.debug("Leaving the management API allowed delegation " +
                      "endpoint. Answered SVG.");
            return;
          }
          self.sendJson(res, 200,
                        adminViews.delegationAllowedModel(req.query));
          log.debug("Leaving the management API allowed delegation " +
                    "endpoint.");
        } },

      // PROTOCOLS → DELEGATION (#446): what the page draws, as the page
      // answers it; see `AdminViews.delegationSettingsModel()`. The register
      // alone is `GET /admin-api/permissions`.
      { method: 'GET', path: BASE + '/console/delegation-settings',
        kind: 'console', tag: 'Delegation',
        operationId: 'getDelegationSettings',
        mirrors: 'GET /admin/delegation-settings',
        parameters: withDelegationQuery([
          { name: 'permq', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Part of a permission\'s resource.' },
          { name: 'grantq', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Part of a grant\'s client or resource.' }
        ].concat(this.pagingParameters())),
        handler: function (req, res) {
          log.debug("Entering the management API delegation settings " +
                    "endpoint.");
          self.sendJson(res, 200,
                        adminViews.delegationSettingsModel(req.query));
          log.debug("Leaving the management API delegation settings " +
                    "endpoint.");
        } },

      // EVERYTHING DONE IN ONE PERSON'S NAME (#446): the console page had
      // no operation, having no form; see
      // `AdminViews.delegationUserModel()`.
      { method: 'GET', path: BASE + '/delegation/user', tag: 'Delegation',
        operationId: 'getDelegationUser',
        mirrors: 'GET /admin/delegation/user',
        parameters: withDelegationQuery([
          { name: 'user', in: 'query', required: false,
            schema: { type: 'string', examples: ['alice'] },
            description: 'The person, under any spelling this service has ' +
                         'seen them under.' },
          { name: 'format', in: 'query', required: false,
            schema: { type: 'string', enum: ['json', 'svg'],
                      examples: ['json'] },
            description: '`svg` answers the drawing alone, as a document ' +
                         'with no links in it. `json`, the default, ' +
                         'answers everything.' }
        ]),
        handler: function (req, res) {
          log.debug("Entering the management API delegation user endpoint.");
          if (String((req.query || {}).format || '') === 'svg') {
            const bare = adminViews.delegationUserModel(req.query,
                                                        { links: false });
            res.status(200).set('Cache-Control', 'no-store')
               .type('image/svg+xml').send(bare.svg);
            log.debug("Leaving the management API delegation user " +
                      "endpoint. Answered SVG.");
            return;
          }
          self.sendJson(res, 200, adminViews.delegationUserModel(req.query));
          log.debug("Leaving the management API delegation user endpoint.");
        } },

      // ONE APPLICATION'S DELEGATIONS (#446): the console page had no
      // operation, having no form; see
      // `AdminViews.delegationApplicationModel()`.
      { method: 'GET', path: BASE + '/delegation/application',
        tag: 'Delegation',
        operationId: 'getDelegationApplication',
        mirrors: 'GET /admin/delegation/application',
        parameters: withDelegationQuery([
          { name: 'application', in: 'query', required: false,
            schema: { type: 'string', examples: ['no-such-application'] },
            description: 'The application, as a protocol presented it or ' +
                         'normalised.' },
          { name: 'format', in: 'query', required: false,
            schema: { type: 'string', enum: ['json', 'svg'],
                      examples: ['json'] },
            description: '`svg` answers the drawing alone, as a document ' +
                         'with no links in it. `json`, the default, ' +
                         'answers everything.' }
        ]),
        handler: function (req, res) {
          log.debug("Entering the management API delegation application " +
                    "endpoint.");
          if (String((req.query || {}).format || '') === 'svg') {
            const bare = adminViews.delegationApplicationModel(req.query,
              { links: false });
            res.status(200).set('Cache-Control', 'no-store')
               .type('image/svg+xml').send(bare.svg);
            log.debug("Leaving the management API delegation application " +
                      "endpoint. Answered SVG.");
            return;
          }
          self.sendJson(res, 200,
                        adminViews.delegationApplicationModel(req.query));
          log.debug("Leaving the management API delegation application " +
                    "endpoint.");
        } },

      // ONE RELATIONSHIP, DRAWN ALONE (#446): the console page had no
      // operation, having no form; see `AdminViews.delegationChainModel()`.
      { method: 'GET', path: BASE + '/console/delegation/chain',
        kind: 'console', tag: 'Delegation',
        operationId: 'getDelegationChain',
        mirrors: 'GET /admin/delegation/chain',
        parameters: [
          { name: 'chain', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The chain\'s key, `chainKey` on a chain of ' +
                         '`GET /admin-api/delegation`.' },
          { name: 'format', in: 'query', required: false,
            schema: { type: 'string', enum: ['json', 'svg'] },
            description: '`svg` answers the drawing alone, as a document ' +
                         'with no links in it. `json`, the default, ' +
                         'answers everything.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API delegation chain endpoint.");
          if (String((req.query || {}).format || '') === 'svg') {
            const bare = adminViews.delegationChainModel(req.query,
                                                         { links: false });
            res.status(200).set('Cache-Control', 'no-store')
               .type('image/svg+xml').send(bare.svg);
            log.debug("Leaving the management API delegation chain " +
                      "endpoint. Answered SVG.");
            return;
          }
          self.sendJson(res, 200, adminViews.delegationChainModel(req.query));
          log.debug("Leaving the management API delegation chain endpoint.");
        } },

      // THE WS-TRUST AND TOKEN-EXCHANGE DELEGATION POLICY (#108, 2026-09-23)
      // — the configured half of those two families, as the Kerberos one is
      // `policy` on the acts above. READ ONLY here, like the console section
      // it mirrors: the attributes are EDITED through POST
      // /admin-api/applications/set for the single-valued ones
      // (appNotDelegated, appDefaultDelegationSemantics), /add and /remove
      // for the rest, or /update-fields — there is no `applications/update`
      // (#286) — and the two person flags through POST
      // /admin-api/users/set-not-delegated and /set-may-act, which is where
      // every application and person attribute is edited (rule 7 by
      // construction). Paged, three lists on three parameters.
      { method: 'GET', path: BASE + '/delegation/policy', tag: 'Delegation',
        operationId: 'getDelegationPolicy',
        mirrors: 'GET /admin/delegation',
        parameters: [
          { name: 'policyPairsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'The page of `pairs`.' },
          { name: 'intermediariesPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'The page of `intermediaries`.' },
          { name: 'peoplePage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'The page of `people`.' },
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [10] },
            description: 'Rows per page, for all three lists (default ' +
                         '10).' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API delegation policy " +
                    "endpoint.");
          self.sendJson(res, 200,
                        adminViews.delegationPolicyView(req.query).json);
          log.debug("Leaving the management API delegation policy " +
                    "endpoint.");
        } },

      // -----------------------------------------------------------------------
      // DELEGATED PERMISSIONS — the CONFIGURED half of /admin/delegation.
      //
      // A RESOURCE OF ITS OWN RATHER THAN MORE ACTIONS ON `/delegation`, and
      // the reason is the same one the console gives for putting two headings
      // on one page: the acts and the permissions are two registers, and an API
      // that answered both under one path would make a caller tell them apart
      // by the shape of a row.
      //
      // THIS COMMENT SAID `GET /admin-api/delegation` CARRIES THE REGISTER IN
      // AN `allowed` MEMBER, AND IT NEVER HAS (corrected 2026-09-01). Only the
      // CONSOLE route adds that member; this endpoint answers
      // `delegationView(query).json`, which is the ACTS view, the one shared
      // with /admin/delegation/map. The behaviour is right — see that
      // function's header, where folding a second register into it is refused
      // because every caller of the acts view would then pay for a walk of
      // ou=applications it did not ask for — so the sentence went and the code
      // stayed. This resource is where the register is reachable under its own
      // name.
      //
      // THE FIVE ACTION NAMES STUTTER SLIGHTLY UNDER THIS PATH
      // (`/permissions/define-permission`) AND THAT IS DELIBERATE. They are the
      // names in the console's hidden `action` inputs, where the page they sit
      // on is `/admin/delegation` and `define` alone would say nothing about
      // what is being defined — and `remove` and `revoke` are two different
      // things here (one removes a permission somebody exposes, the other takes
      // a grant away from a client). One vocabulary for both doors is worth
      // more than a shorter URL, and rule 7's parity check reads the console's
      // own list.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/permissions', tag: 'Delegation',
        operationId: 'getPermissions',
        mirrors: 'GET /admin/delegation',
        handler: function (req, res) {
          log.debug("Entering the management API permissions endpoint.");
          const view = adminViews.permissionsView();
          self.sendJson(res, 200,
                        Object.assign({}, view.register,
                                      { graph: view.graph }));
          log.debug("Leaving the management API permissions endpoint.");
        } },

      // -----------------------------------------------------------------------
      // THE GROUPINGS, AS A RESOURCE OF ITS OWN (2026-09-02).
      //
      // A MEMBER ON `GET /permissions` WOULD HAVE BEEN THE SHORTER CHANGE AND
      // IT IS THE WRONG ONE, for the reason that reply's own `graph` member is
      // the boundary rather than an example. `graph` is one document about the
      // whole register and its size is the register's; a list of groups that
      // carried its grants would repeat the register once per group, and one
      // that did not would leave a caller no way to ask for a single group's
      // rows at all. It also needs PAGING — the console's own list of groups is
      // paged, and a member of somebody else's reply has nowhere to put a page
      // number.
      //
      // ONE OPERATION ANSWERS BOTH SHAPES, `?application=` deciding which,
      // because they are the same question at two scales and the console draws
      // them with one function: without it, every group with its counts; with
      // it, the ONE group that application is in, with its grants, its
      // permissions and the graph /admin/delegation/cluster draws. Two
      // operations would have been two places to disagree about what a group
      // is.
      //
      // It mirrors `GET /admin/delegation` like the register beside it — the
      // console pages it belongs to are drill-downs of that tab, and rule 7's
      // parity check reads a NAV path.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/permissions/groups', tag: 'Delegation',
        operationId: 'getPermissionGroups',
        mirrors: 'GET /admin/delegation',
        parameters: [
          { name: 'application', in: 'query',
            description: 'One application\'s identifier. Answers the group ' +
                         'it is in, with its rows and its graph, instead of ' +
                         'the list of every group. Matched exactly.',
            schema: { type: 'string' } },
          { name: 'groupsPage', in: 'query',
            description: 'Which page of the group LIST. The same name the ' +
                         'console page uses, because a group list is one of ' +
                         'several lists a delegation page can hold and a ' +
                         'bare `page` would move them together. Not read ' +
                         'when `application` is given.',
            schema: { type: 'integer', minimum: 1, examples: [1] } },
          { name: 'groupGrantsPage', in: 'query',
            description: 'Which page of the GRANTS inside one group. Read ' +
                         'only when `application` is given.',
            schema: { type: 'integer', minimum: 1, examples: [1] } },
          { name: 'groupPermissionsPage', in: 'query',
            description: 'Which page of the PERMISSIONS the applications in ' +
                         'one group expose, granted or not. Read only when ' +
                         '`application` is given.',
            schema: { type: 'integer', minimum: 1, examples: [1] } },
          { name: 'per', in: 'query',
            description: 'Rows per page, shared by both lists above — one ' +
                         '`per` per page is this console\'s rule and this ' +
                         'operation follows it.',
            schema: { type: 'integer', minimum: 1, examples: [10] } }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API permission groups endpoint.");
          self.sendJson(res, 200, adminViews.permissionGroupsView(req.query));
          log.debug("Leaving the management API permission groups endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/permissions/:action', tag: 'Delegation',
        mirrors: 'POST /admin/delegation-settings',
        handler: function (req, res) {
          log.debug("Entering the management API permissions action endpoint.");
          const body = parseBody(req);
          const result = adminActions.permissionsAction(self.withAction(req,
              body), { via: 'api', actor: self.callerNameOf(res) });
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0058');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API permissions action endpoint.");
        },
        actions: [
          { action: 'set-permission-base', operationId: 'setPermissionBase' },

          { action: 'define-permission', operationId: 'definePermission' },

          { action: 'remove-permission', operationId: 'removePermission' },

          { action: 'grant-permission', operationId: 'grantPermission' },

          { action: 'revoke-permission', operationId: 'revokePermission' }
        ] }),

      // -----------------------------------------------------------------------
      // CONSENT — the THIRD register in this family and the first whose rows
      // have a PERSON in them.
      //
      // A resource of its own rather than more actions on `/permissions`, for
      // the reason that one is a resource of its own rather than more actions
      // on `/delegation`: a caller that had to tell an act from an intent from
      // a consent by the shape of a row would be told nothing by any of them.
      // The console draws it on a page of its own for the same reason and rule
      // 7's parity check is what keeps the two in step.
      //
      // THE FOUR ACTION NAMES SAY WHICH HALF THEY TOUCH, and the stutter under
      // this path (`/consent/grant-global-consent`) is deliberate exactly as
      // `/permissions/define-permission`'s is. They are the names in the
      // console's hidden `action` inputs, where the page is `/admin/consent`
      // and `grant` alone would not say whether it meant the override or
      // somebody's answer — and those two are the pair a caller most needs kept
      // apart, because removing the wrong one asks the wrong people again.
      // -----------------------------------------------------------------------
      // -----------------------------------------------------------------------
      // ROLES. Three operations against `adminViews.rolesView()`,
      // `adminViews.rolesPreview()` and `adminActions.rolesAction()` — the same
      // three functions the console calls, so rule 7's parity is a property of
      // the wiring rather than of two lists agreeing.
      //
      // **THE PREVIEW GETS AN OPERATION OF ITS OWN AND NOT A QUERY ON THE
      // FIRST**, and that is the one decision here worth arguing. On the
      // console it IS a query parameter, because a `<form method="get">` is
      // what a page with no script has; over HTTP the two are different
      // questions — one reads a register and the other asks the PDP — and a
      // caller that got a decision by adding two parameters to a listing would
      // have no way to discover it.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/roles', tag: 'Roles',
        operationId: 'getRoles',
        mirrors: 'GET /admin/roles',
        parameters: [
          { name: 'q', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Narrows the configured roles to those whose ' +
                         'name, description or a member contains this.' },
          { name: 'role', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One role\'s name (#604): the answer also carries ' +
                         '`role` — the role in full, its `owners` resolved, ' +
                         '`requiredBy` (the applications whose requirement ' +
                         'names it) and its directory `entry` — or ' +
                         '`role.found: false`.' },
          { name: 'rolesPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the configured roles the search ' +
                         'matched, answered by `paging` and ' +
                         '`shownRoles`; twenty-five by default.' }
        ].concat(this.pagingParameters().filter(function (one) {
          return one.name === 'per';
        })).concat(this.detailPagingParameters([
          { name: 'requiring',
            description: 'The applications that narrowed the roles they ' +
                         'require (#313); `requiringPaging` says where the ' +
                         'page is and `counts.requiring` counts them all.' }
        ])),
        handler: function (req, res) {
          log.debug("Entering the management API roles endpoint.");
          self.sendJson(res, 200, adminViews.rolesView(req.query));
          log.debug("Leaving the management API roles endpoint.");
        } },

      { method: 'GET', path: BASE + '/roles/preview', tag: 'Roles',
        operationId: 'previewRoleIssuance',
        mirrors: 'GET /admin/roles',
        parameters: [
          { name: 'username', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The older spelling of `subject`, read when ' +
                         '`subject` is absent.' },
          { name: 'application', in: 'query',
            schema: { type: 'string', examples: ['no-such-application'] },
            description: 'What something would be issued FOR — a ' +
                         '`client_id`, a wtrealm, a SAML entityID, an SPN. ' +
                         'An application no entry names requires EVERYBODY, ' +
                         'because this service registers one on first sight ' +
                         'and refusing the first request from a new client ' +
                         'is precisely the permissiveness it is for.' },
          { name: 'subject', in: 'query',
            schema: { type: 'string', examples: ['alice'] },
            description: 'Who it would be issued to — a username, or a ' +
                         'client_id where `subjectKind` is `application`.' },
          { name: 'subjectKind', in: 'query',
            schema: { type: 'string', enum: ['user', 'application'],
                      examples: ['user'] },
            description: 'Whether the subject is a person or a client ' +
                         'authenticating as itself. Defaults to `user`.' },
          { name: 'kind', in: 'query',
            schema: { type: 'string', enum: closed.issuanceKinds,
                      examples: ['issue-access-token'] },
            description: 'Which issuance. It becomes the XACML `action-id`, ' +
                         'so a policy may permit an access token and refuse ' +
                         'a refresh token. `GET ' +
                         '/admin-api/roles` lists the nine in ' +
                         '`issuanceKinds`; the default is ' +
                         '`issue-access-token`.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API role preview endpoint.");
          const answer = adminViews.rolesPreview(req.query);
          if (!answer) {
            // NOTHING ASKED IS `answered: false` AND NOT A 400, and that is
            // this operation MIRRORING ITS PAGE rather than being lenient. A
            // GET of /admin/roles with no parameters draws the form and no
            // answer, so this answers the same thing: it is a READ, and a read
            // of this resource with no question in it has nothing to refuse.
            //
            // The hazard the other spelling was guarding against is gone by
            // construction. `issuance_gate.check()` ALLOWS a call that names no
            // application, so an operation that fell through to the gate would
            // hand back a Permit meaning "you did not ask" — which is why there
            // is no `decision` member on this reply at all, and why `answered`
            // is the first thing to read.
            self.sendJson(res, 200, {
              answered: false, available: !!adminViews.rolesView().gated,
              why: '`application` and `subject` are both needed. A decision ' +
                   'needs something being issued FOR and somebody it is ' +
                   'being issued TO, and an issuance named with neither is ' +
                   'allowed by definition rather than by policy — so nothing ' +
                   'was asked and there is no decision here to read.' });
            log.debug("Leaving the management API role preview endpoint. " +
                      "Nothing asked.");
            return;
          }
          self.sendJson(res, 200, Object.assign({ answered: true }, answer));
          log.debug("Leaving the management API role preview endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/roles/:action', tag: 'Roles',
        // A SECOND CONSOLE PATH SINCE #604: the role page's Owners tab posts
        // to /admin/roles/owners, so its Find and Add are told apart from
        // the page's other forms; its Add and Remove reach `add-owner` and
        // `remove-owner` here.
        mirrors: 'POST /admin/roles and POST /admin/roles/owners',
        handler: function (req, res) {
          log.debug("Entering the management API roles action endpoint.");
          const body = parseBody(req);
          const result = adminActions.rolesAction(self.withAction(req, body),
            { via: 'api', actor: self.callerNameOf(res) });
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0059');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API roles action endpoint.");
        },
        actions: [
          { action: 'create-role', operationId: 'createRole' },

          { action: 'delete-role', operationId: 'deleteRole' },

          { action: 'describe-role', operationId: 'describeRole' },

          { action: 'add-member', operationId: 'addRoleMember' },

          { action: 'remove-member', operationId: 'removeRoleMember' },

          { action: 'add-permission', operationId: 'addRolePermission' },

          { action: 'remove-permission', operationId: 'removeRolePermission' },

          { action: 'add-conferring-client',
            operationId: 'addRoleConferringClient' },

          { action: 'remove-conferring-client',
            operationId: 'removeRoleConferringClient' },

          // A ROLE'S OWNERS (#604): what the role page's Owners tab saves the
          // moment Add or Remove is pressed.
          { action: 'add-owner', operationId: 'addRoleOwner' },
          { action: 'remove-owner', operationId: 'removeRoleOwner' }
        ] }),

      // -----------------------------------------------------------------------
      // OWNERSHIP (#607): what an OWNER may administer through this API, and
      // the administrator's mark that closes an object to its owners (rcbj's
      // decision 4). The facts are `common/ownership.ts`'s — the same ones
      // the access-control policy's owner rule reads through the PIP — so
      // this answer and that decision cannot disagree. The mark is an
      // attribute on the object's own entry (`stsOwnerProtected`); its
      // CONSOLE CONTROL is a checkbox on each object's Owners tab (rcbj,
      // 2026-10-13), posting `set-protected` to that tab's route, and an
      // `ldapmodify` by a holder of Admin Write reaches it too.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/ownership', tag: 'Ownership',
        operationId: 'getOwnership',
        mirrors: 'no console form — the owner rule\'s facts; the mark is ' +
                 'stsOwnerProtected on the entry',
        parameters: [
          { name: 'kind', in: 'query', required: true,
            schema: { type: 'string', enum: ownership.KINDS.slice(0),
                      examples: ['application'] },
            description: 'Which kind of object.' },
          { name: 'name', in: 'query', required: true,
            schema: { type: 'string', examples: ['no-such-application'] },
            description: 'A role\'s name, a group\'s cn or DN, a service ' +
                         'account\'s username, an application\'s ' +
                         'identifier.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API ownership endpoint.");
          const query = req.query || {};
          self.sendJson(res, 200, ownership.objectOf(String(query.kind || ''),
                                                     String(query.name || '')));
          log.debug("Leaving the management API ownership endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/ownership/:action', tag: 'Ownership',
        // THE OWNERS TABS' CHECKBOX: each posts `set-protected` to its own
        // tab's route, which is what resolves the form to this operation.
        mirrors: 'POST /admin/roles/owners, POST /admin/groups/owners, ' +
                 'POST /admin/applications/owners, POST ' +
                 '/admin/users/service-account',
        handler: function (req, res) {
          log.debug("Entering the management API ownership action endpoint.");
          const body = parseBody(req);
          const action = String(req.params.action || '');
          if (action !== 'set-protected') {
            errorCodes.mark(res, 'STS-API-0134');
            self.sendJson(res, 400, { ok: false, errors: ['Unknown action "' +
              action.slice(0, 64) + '". The one is: set-protected.'] });
            log.debug("Leaving the management API ownership action " +
                      "endpoint. Unknown action.");
            return;
          }
          const caller = res.locals.apiCaller || {};
          const result = ownership.setProtected(body.kind, body.name,
            body.protected === true || String(body.protected) === 'true',
            { actor: String(caller.name || ''), channel: 'http',
              protocol: 'management API', origin: 'management API' });
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0134');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API ownership action endpoint.");
        },
        actions: [
          { action: 'set-protected', operationId: 'setOwnerProtected' }
        ] }),

      // -----------------------------------------------------------------------
      // POLICIES (2026-09-12; every kind since #64). Two operations over
      // `adminViews.policiesView()` and `adminActions.policiesAction()` — the
      // same two functions /admin/policies calls, so the page and this
      // resource cannot disagree.
      //
      // **THE ACTIONS ARE BUILT FROM `admin-core/policy_kinds.ts`**, two per
      // kind, and **EACH SAVE'S REQUEST SCHEMA FROM ITS KIND'S `FIELDS`**, so
      // a policy registered there is two operations here the same day. Each
      // field takes its JSON type OR a string, because a form-encoded body
      // copied from the console carries `"12"` and `"TRUE"`, and
      // `coerceTypes` is off in this file's ajv for a reason stated beside
      // it; the module parses both spellings and refuses anything else by
      // name.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/policies', tag: 'Policies',
        operationId: 'getPolicies',
        mirrors: 'GET /admin/policies',
        // A CAST: `pagingParameters()`'s inferred element type is its two
        // integer schemas, which this string `enum` is not one of.
        parameters: (this.pagingParameters() as any[]).concat([
          // #396: a walk of the realm's people, so only when asked.
          { name: 'missing', in: 'query', required: false,
            schema: { type: 'string', enum: ['count'] },
            description: '`count` answers `attributes.missing`: how many ' +
                         'people in this realm lack a value of an ' +
                         'attribute the attribute policy requires. A walk ' +
                         'of the realm\'s people, so asked only on request, ' +
                         'and null where the directory is held in the store ' +
                         '(`attributes.missingFilter` is the LDAP filter ' +
                         'that finds them there).' },
          // #1112: the learned passkey clients' own page.
          { name: 'clientsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of `passkey.clients.rows`, the ' +
                         'learned passkey clients. Defaults to 1.' },
          { name: 'clientsPer', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, maximum: 200 },
            description: 'Rows per page of `passkey.clients.rows`. ' +
                         'Defaults to 25.' }
        ]),
        handler: function (req, res) {
          log.debug("Entering the management API policies endpoint.");
          // ASYNCHRONOUS (#1241): the people naming a named profile are a
          // holder question, asked without a synchronous walk.
          adminViews.policiesViewAsync(req.query).then(function (view) {
            log.debug("Entering the policies endpoint's answer.");
            self.sendJson(res, 200, view);
            log.debug("Leaving the policies endpoint's answer.");
          }, function (e) {
            log.debug("Caught in the management API policies endpoint: " +
                      ((e && e.message) || e));
            errorCodes.mark(res, 'STS-API-0060');
            self.sendJson(res, 500, { ok: false, errors: [
              'The policies could not be read.'] });
          });
          log.debug("Leaving the management API policies endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/policies/:action', tag: 'Policies',
        mirrors: 'POST /admin/policies',
        handler: function (req, res) {
          log.debug("Entering the management API policies action endpoint.");
          const body = parseBody(req);
          // THE TOKEN SUBJECT IS THE AUDIT TRAIL (#966), the same subject
          // the users action passes. `callerNameOf` reads the gate's
          // verified subject, and '' stays '' when development's open API
          // has no token.
          // A RESET MAY ANSWER A PROMISE (#1241: who names a named
          // attribute profile is asked asynchronously). The promise is
          // RETURNED: Express does not wait on it, and the `.then` still
          // sends, but an in-process caller reads the answer only once
          // this settles (`tests/admin_api_nominated_actor.js`).
          const answer = function (result) {
            log.debug("Entering the policies action endpoint's answer.");
            if (!result.ok) {
              errorCodes.mark(res, errorCodes.codeOf(result) ||
                                   'STS-API-0060');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the policies action endpoint's answer.");
          };
          const pending = Promise.resolve(
            adminActions.policiesAction(self.withAction(req, body),
                                        { via: 'api',
                                          actor: self.callerNameOf(res) }))
            .then(answer, function (e) {
              log.debug("Caught in the management API policies action " +
                        "endpoint: " + ((e && e.message) || e));
              errorCodes.mark(res, 'STS-API-0060');
              self.sendJson(res, 500, { ok: false, errors: [
                'The policy action failed.'] });
            });
          log.debug("Leaving the management API policies action endpoint.");
          return pending;
        },
        actions: this.policyKindActions() }),

      { method: 'GET', path: BASE + '/consent', tag: 'Delegation',
        operationId: 'getConsent',
        mirrors: 'GET /admin/consent',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the person, the application or the ' +
                         'scope, case-insensitive. Narrows `users` only. ' +
                         'Where the answer is `windowed`, a whole ' +
                         'username, client_id or scope instead.' }
        ].concat(self.detailPagingParameters([
          { name: 'globals',
            description: 'The global overrides, configuration on ' +
                         'application entries.' },
          { name: 'users',
            description: 'The recorded consents, one per (person, ' +
                         'application, scope), after `q`.' }
        ]), self.pagingParameters().filter(function (one) {
          // `per` only: this reply is two lists, so a bare `page` would say
          // nothing about which of them it meant.
          return one.name === 'per';
        })),
        handler: function (req, res, next) {
          log.debug("Entering the management API consent endpoint.");
          // FROM THE STORE while the directory is windowed (#820): the whole
          // register opened every consent holder, one synchronous read each,
          // on the request worker — about 470,000 on 8081.
          adminViews.consentPageViewAsync(req).then(function (view) {
            self.sendJson(res, 200, view.json);
            log.debug("Leaving the management API consent endpoint.");
          }).catch(function (e) {
            log.debug("Caught in the management API consent endpoint: " +
                      ((e && e.message) || e));
            next(e);
          });
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/consent/:action', tag: 'Delegation',
        mirrors: 'POST /admin/consent',
        handler: function (req, res) {
          log.debug("Entering the management API consent action endpoint.");
          const body = parseBody(req);
          const result = adminActions.consentAction(self.withAction(req, body),
            { via: 'api', actor: self.callerNameOf(res) });
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0061');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API consent action endpoint.");
        },
        actions: [
          { action: 'grant-global-consent', operationId: 'grantGlobalConsent' },

          { action: 'revoke-global-consent', operationId: 'revokeGlobalConsent' },

          { action: 'revoke-consent', operationId: 'revokeConsent' },

          { action: 'revoke-application-consent',
            operationId: 'revokeApplicationConsent' },

          { action: 'forget-user-consent', operationId: 'forgetUserConsent' }
        ] }),

      // -----------------------------------------------------------------------
      // SPIFFE. Three resources, mirroring the three console pages one for one,
      // and each POST calls the SAME action function the console's form posts
      // to — with `action` taken from the URL instead of from a hidden input.
      // Rule 7.
      //
      // There is a fourth SPIFFE surface that is deliberately NOT here: the
      // SPIRE Server API itself. It is gRPC, it already does all of this, and
      // wrapping it in JSON would be a second implementation of forty-two
      // methods that could then disagree with the first. What this API covers
      // is the CONSOLE — the trust domain, its authorities, its federated
      // bundles, the registration entries and the agents — which is the parity
      // rule's actual subject.
      // -----------------------------------------------------------------------
      { method: 'GET', path: BASE + '/spiffe', tag: 'SPIFFE',
        operationId: 'getSpiffe',
        mirrors: 'GET /admin/cert-issuance',
        handler: function (req, res) {
          log.debug("Entering the management API SPIFFE endpoint.");
          // NO `.json` HERE, where its two siblings need one: `spiffeJson()`
          // returns the answer itself, and `spiffeEntriesJson()` and
          // `spiffeAgentsJson()` return `{ json, paging }` because their pages
          // need the paging beside it. The console hid that difference behind
          // one export shape; repointing all three the same way sent this
          // resource `undefined`, which reaches a caller as a string.
          self.sendJson(res, 200, adminViews.spiffeJson(req));
          log.debug("Leaving the management API SPIFFE endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/spiffe/:action', tag: 'SPIFFE',
        mirrors: 'POST /admin/spiffe',
        handler: function (req, res) {
          log.debug("Entering the management API SPIFFE action endpoint.");
          const body = parseBody(req);
          // ASYNCHRONOUS, like a handful of other handlers here: rotating an
          // authority generates a key pair, and key generation is async. Most
          // handlers here are synchronous, so the await is local rather than a
          // change to the shape of all of them.
          adminActions.spiffeAction(self.withAction(req, body))
            .then(function (result) {
            if (!result.ok) {
              errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0062');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API SPIFFE action endpoint.");
          }).catch(function (err) {
            errorCodes.mark(res, 'STS-API-0022');
            log.error('The SPIFFE management API action threw: ' + err.message);
            self.sendJson(res, 500, { ok: false, errors: [err.message] });
            log.debug("Leaving the management API SPIFFE action endpoint. It " +
                      "threw.");
          });
          log.debug("Leaving handler().");
        },
        actions: [
          { action: 'rotate', operationId: 'rotateSpiffeAuthority' },

          { action: 'federation-set', operationId: 'setSpiffeFederatedBundle' },

          { action: 'federation-remove',
            operationId: 'removeSpiffeFederatedBundle' }
        ] }),

      { method: 'GET', path: BASE + '/spiffe/entries', tag: 'SPIFFE',
        operationId: 'getSpiffeEntries',
        mirrors: 'GET /admin/cert-issuance',
        parameters: [
          { name: 'entry', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One entry, by its id — the 32 hex characters this ' +
                         'registry minted, which is what the SPIRE Server ' +
                         'API calls `id`. The reply then carries that entry ' +
                         'with every attribute of its directory entry.' },
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the SPIFFE ID, the parent, the entry ' +
                         'id, the hint or any selector, case-insensitive.' },
          { name: 'origin', in: 'query', required: false,
            schema: { type: 'string',
                      // `unstated` is what an entry whose origin was never
                      // recorded carries (`spiffe/spiffe_registry.ts`).
                      enum: ['seed', 'console', 'api', 'grpc', 'auto',
                             'ldap', 'unstated'] },
            description: 'How the entry got here. `auto` is one this service ' +
                         'INVENTED for a workload that matched nothing, ' +
                         'which is the setting `spiffe.autoCreateEntries` — ' +
                         'telling those from entries somebody meant is the ' +
                         'whole reason this field exists.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API SPIFFE entries endpoint.");
          // `entry` names one, as the parameter above has always said.
          const entry = String(req.query.entry || '').trim();
          self.sendJson(res, 200,
                        entry ? adminViews.spiffeEntryJson(entry)
                              : adminViews.spiffeEntriesJson(req).json);
          log.debug("Leaving the management API SPIFFE entries endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/spiffe/entries/:action', tag: 'SPIFFE',
        mirrors: 'POST /admin/spiffe/entries',
        handler: function (req, res) {
          log.debug("Entering the management API SPIFFE entries action " +
                    "endpoint.");
          const body = parseBody(req);
          const result = adminActions.spiffeEntriesAction(self.withAction(req,
              body));
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0063');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API SPIFFE entries action " +
                    "endpoint.");
        },
        actions: [
          { action: 'create', operationId: 'createSpiffeEntry' },

          { action: 'update', operationId: 'updateSpiffeEntry' },

          { action: 'delete', operationId: 'deleteSpiffeEntry' }
        ] }),

      // THE SPIFFE BROKER API'S BROKERS (#170): /admin/spiffe/brokers, rule 7.
      { method: 'GET', path: BASE + '/spiffe/brokers', tag: 'SPIFFE',
        operationId: 'getSpiffeBrokers',
        mirrors: 'GET /admin/cert-issuance',
        parameters: [
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of a broker\'s SPIFFE ID or reference ' +
                         'types, case-insensitive.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API SPIFFE brokers endpoint.");
          self.sendJson(res, 200, adminViews.spiffeBrokersJson(req).json);
          log.debug("Leaving the management API SPIFFE brokers endpoint.");
        } },

      ApiRows.actions({ method: 'POST', route: BASE + '/spiffe/brokers/:action',
        tag: 'SPIFFE', mirrors: 'POST /admin/spiffe/brokers',
        handler: function (req, res) {
          log.debug("Entering the management API SPIFFE brokers action " +
                    "endpoint.");
          const body = parseBody(req);
          const result = adminActions.spiffeBrokersAction(self.withAction(req,
              body));
          if (!result.ok) {
            errorCodes.mark(res,
                            errorCodes.codeOf(result) || 'STS-SPIFFE-0141');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API SPIFFE brokers action " +
                    "endpoint.");
        },
        actions: [
          { action: 'set', operationId: 'setSpiffeBroker' },

          { action: 'remove', operationId: 'removeSpiffeBroker' }
        ] }),

      { method: 'GET', path: BASE + '/spiffe/agents', tag: 'SPIFFE',
        operationId: 'getSpiffeAgents',
        mirrors: 'GET /admin/cert-issuance',
        parameters: [
          { name: 'agent', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'One agent, by its SPIFFE ID — always under ' +
                         '`/spire/agent/`. The reply then carries its ' +
                         'directory entry, where the cn is a DIGEST of the ' +
                         'SPIFFE ID and `spiffeAgentId` is the identity.' },
          { name: 'q', in: 'query', required: false, schema: { type: 'string' },
            description: 'Substring of the agent id, the attestation type or ' +
                         'any selector, case-insensitive.' }
        ].concat(this.pagingParameters()),
        handler: function (req, res) {
          log.debug("Entering the management API SPIFFE agents endpoint.");
          // `agent` names one, as the parameter above has always said.
          const agent = String(req.query.agent || '').trim();
          self.sendJson(res, 200,
                        agent ? adminViews.spiffeAgentJson(agent)
                              : adminViews.spiffeAgentsJson(req).json);
          log.debug("Leaving the management API SPIFFE agents endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/spiffe/agents/:action', tag: 'SPIFFE',
        mirrors: 'POST /admin/spiffe/agents',
        handler: function (req, res) {
          log.debug("Entering the management API SPIFFE agents action " +
                    "endpoint.");
          const body = parseBody(req);
          // The token's subject for the audit row, as rbacAction's caller
          // passes it (#695).
          const result = adminActions.spiffeAgentsAction(self.withAction(req,
              body), { via: 'api', actor: self.callerNameOf(res) });
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0064');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API SPIFFE agents action " +
                    "endpoint.");
        },
        actions: [
          { action: 'ban', operationId: 'banSpiffeAgent' },

          { action: 'unban', operationId: 'unbanSpiffeAgent' },

          { action: 'delete', operationId: 'deleteSpiffeAgent' },

          { action: 'join-token', operationId: 'createSpiffeJoinToken' }
        ] }),
      // CERTIFICATE ENROLLMENT (2026-09-13). Each family's operations are
      // declared beside the family, in a file that registers no route and
      // requires its view model lazily inside each handler — so requiring it
      // here, at 19, moves no route (rule 1), exactly as the GNAP rows above
      // reach `gnap_console.js`.
      ...loadAcmeApi().ROUTES,
      ...loadEstApi().ROUTES,
      ...loadScepApi().ROUTES,
      ...loadOidfedApi().ROUTES,
      // THE OAUTH 2.0 / OIDC MONITORING PAGE (2026-09-13), declared beside its
      // family in the same shape: no route registered there, and its view model
      // required lazily inside each handler.
      ...loadOauth2MonitorApi().ROUTES,
      // GRANT MANAGEMENT (#142): /admin/grants' twin, in the same shape.
      ...loadGrantManagementApi().ROUTES,
      // CLAIMS PROVIDERS (#147): /admin/claim-providers' twin, in the same
      // shape.
      ...loadClaimsProvidersApi().ROUTES,
      // THE ATTRIBUTE SOURCES (#94): the register and its six acts, the
      // console's own (`attribute-sources/attribute_sources_api.ts`).
      ...loadAttributeSourcesApi().ROUTES,
      // THE SECRET PUSH DESTINATIONS (#221 P3): the register and its four
      // acts, the console's own (`mgmt-api/secret_destinations_api.ts`).
      ...loadSecretDestinationsApi().ROUTES,
      // THE AUTHZEN TAB (#563): the API's settings, its attribute catalogue
      // and its callers' scopes, the console's own (`mgmt-api/authzen_api.ts`).
      ...loadAuthzenApi().ROUTES,
      // UMA 2.0 (#1195): Protocols -> UMA's view, counts and nine acts,
      // the console's own (`mgmt-api/uma_api.ts`).
      ...loadUmaApi().ROUTES,
      // MONITORING → PASSKEYS (#942): who holds which passkey algorithm,
      // its export and its Recount now (`mgmt-api/passkey_report_api.ts`).
      ...loadPasskeyReportApi().ROUTES,
      // DIRECTORY → POST-LOGIN ACTIVITIES (#1111): the started activities
      // and their four acts (`mgmt-api/post_login_activities_api.ts`).
      ...loadPostLoginActivitiesApi().ROUTES,
      // MONITORING → AUDIT EXPORT (#641): the destinations and their six
      // acts (`mgmt-api/audit_export_api.ts`).
      ...loadAuditExportApi().ROUTES,
      // SERVER CONFIGURATION → SIGN-IN APPEARANCE (#717): the realm's
      // colours, layout and logo, and their three acts
      // (`mgmt-api/branding_api.ts`).
      ...loadBrandingApi().ROUTES,
      // THE OUTBOUND SCIM CLIENTS (#552): Protocols → SCIM → Clients' twin,
      // the clients and their ten acts (`mgmt-api/scim_clients_api.ts`).
      ...loadScimClientsApi().ROUTES,
      // PROVIDER COMMANDS AND OUTBOUND DELIVERIES (#151): /admin/commands'
      // and /admin/deliveries' twins, in the same shape.
      ...loadProviderCommandsApi().ROUTES,
      // FEDERATION PARTNERS' SHARED SIGNALS (#153, #373): the monitoring
      // page's twin. The acts are federation's (`signals-*` below).
      ...loadSsfTransmittersApi().ROUTES
    ];
    log.debug("Leaving AdminApi.buildRoutes().");
    return this.withConsoleRoutes(ROUTES);
  }

  // ---------------------------------------------------------------------------
  // THE CONSOLE'S OWN OPERATIONS (#454).
  //
  // Since #446 the console is a static application whose one data source is
  // this API, and to draw itself it added operations that exist only for it:
  // its frame, its drawings and its form helpers. They answer in the shape a
  // renderer wants — an SVG laid out on the server, a select's options, the
  // sidebar — and that shape changes whenever a page does, so they are not
  // part of the contract an external client relies on. Every row of the
  // table is therefore one of two KINDS:
  //
  //   * `management`, the default: a realm's resources and the controls on
  //     them, at `/admin-api/...`, described by `/admin-api/openapi.json`,
  //     listed by the index and drawn by the API explorer, and asked for
  //     with ADMIN_READ or ADMIN_WRITE as always;
  //   * `console`: under `/admin-api/console`, described by
  //     `/admin-api/console/openapi.json` alone, and reached with
  //     `admin:console` — the permission of the ADMIN_CONSOLE role the
  //     console's client confers on everybody signing in through it — and,
  //     wherever it shows realm data, ADMIN_READ (or ADMIN_WRITE, for a form
  //     helper) as well.
  //
  // **THIS IS A BOUNDARY FOR CLEANLINESS, NOT FOR SECURITY.** Nothing here
  // shows an administrator anything they could not already reach; what moves
  // is which answers are the API's contract. And rule 7 is untouched: a
  // console CONTROL keeps its management operation, because a console
  // operation is a read or a form helper that writes nothing
  // (`tests/admin_api_kinds.js` holds that).
  //
  // Eight rows are written as console rows where they are declared. The
  // rest is here, because each is DERIVED from a management row: four
  // answers whose console twin is the whole answer and whose management
  // operation leaves the drawing or the form's layout out (`consoleMembers`,
  // which `sendJson()` takes off), the form helpers of two action routes,
  // and the three rows that exist only for the console — its dashboard, the
  // operation list its forms resolve through, and its own document.
  // ---------------------------------------------------------------------------
  /**
   * Adds the console's derived operations to the route table and marks every
   * other row a management operation.
   *
   * @param routes - the table as declared
   * @returns the table with the console's twins, form helpers and own rows
   */
  withConsoleRoutes(routes: any[]): any[] {
    const { log, spec } = this.deps;
    const self = this;
    log.debug("Entering AdminApi.withConsoleRoutes().");
    const byId = function (id) {
      log.debug("Entering byId().");
      log.debug("Leaving byId().");
      return routes.filter(function (entry) {
        return entry.operationId === id;
      })[0];
    };
    const out = routes.slice(0);
    CONSOLE_TWINS.forEach(function (twin) {
      const entry = byId(twin.of);
      // `proseRoute` (#543): the twin answers the management operation's
      // prose, so a prose source names that operation alone.
      const copy = Object.assign({}, entry, {
        kind: 'console', path: BASE + twin.path,
        operationId: twin.operationId,
        proseRoute: entry.route || entry.path });
      // THE MANAGEMENT OPERATION LEAVES THE CONSOLE'S MEMBERS OUT, and a
      // drawing's `format=svg` with them: its parameter is the twin's.
      entry.consoleMembers = twin.members.slice(0);
      entry.consoleTwin = BASE + twin.path;
      if (twin.drawing) {
        entry.parameters = (entry.parameters || []).filter(function (one) {
          return one.name !== 'format';
        });
      }
      out.push(copy);
    });
    // THE FORM HELPERS (#454): a key pair or a profile into the certificate
    // form, a secret into the new application form. Each writes nothing; the
    // act they lead to — `pki/issue-certificate`, `applications/create` —
    // stays a management operation. Same handler, a route of their own.
    const HELPERS = [
      { route: '/pki/:action',
        actions: ['apply-profile', 'generate-keys', 'generate-alt-keys',
                  'use-key'] },
      { route: '/applications/:action', actions: ['generate-secret'] }
    ];
    HELPERS.forEach(function (helper) {
      const entry = routes.filter(function (one) {
        return one.route === BASE + helper.route;
      })[0];
      const moved = entry.actions.filter(function (one) {
        return helper.actions.indexOf(one.action) >= 0;
      }).map(function (one) {
        return Object.assign({}, one, { writesNothing: true });
      });
      entry.actions = entry.actions.filter(function (one) {
        return helper.actions.indexOf(one.action) < 0;
      });
      entry.consoleActions = helper.actions.slice(0);
      out.push(Object.assign({}, entry, {
        kind: 'console', route: BASE + '/console' + helper.route,
        actions: moved, consoleActions: undefined,
        proseRoute: entry.route || entry.path }));
    });
    // Typed by the model like the table's own rows (#1579).
    const consoleOwn: AdminRow[] = [
      { method: 'GET', path: BASE + '/console/operations', kind: 'console',
        tag: 'Service', operationId: 'getConsoleOperations',
        mirrors: 'GET /admin',
        handler: function (req, res) {
          log.debug("Entering the console operations endpoint.");
          self.sendJson(res, 200,
                        { operations: self.operationSummaries('all') });
          log.debug("Leaving the console operations endpoint.");
        } },
      { method: 'GET', path: BASE + '/console/openapi.json', kind: 'console',
        tag: 'Service', operationId: 'getConsoleOpenApi',
        mirrors: 'GET /admin/sts-metadata',
        handler: function (req, res) {
          log.debug("Entering the console OpenAPI document endpoint.");
          self.sendJson(res, 200,
                        spec.buildSpec(self.routesOfKind('console'),
                                       Object.assign(self.specOptions(req),
                                                     { console: true })));
          log.debug("Leaving the console OpenAPI document endpoint.");
        } }];
    out.push(...consoleOwn);
    // RULE 7 FOR A PAGE WHOSE OWN OPERATION MOVED (#454). A page with no
    // form still needs a management GET; for a drawing, that is the
    // operation its data comes from, and the row says so — `drawnOn` is
    // published in the index, where the parity check reads it
    // (`tests/protocol/admin_api.js`), beside `mirrors`.
    const DRAWN_ON = {
      getDelegation: ['/admin/delegation/map', '/admin/delegation/chain'],
      getPermissions: ['/admin/delegation/allowed',
                       '/admin/delegation-settings'],
      getPermissionGroups: ['/admin/delegation/cluster'],
      getFederationRelationships: ['/admin/federation/map'],
      getOpenApi: ['/admin/api-explorer']
    };
    Object.keys(DRAWN_ON).forEach(function (id) {
      byId(id).drawnOn = DRAWN_ON[id].slice(0);
    });
    out.forEach(function (entry) {
      if (!entry.kind) {
        entry.kind = 'management';
      }
    });
    log.debug("Leaving AdminApi.withConsoleRoutes(). " + out.length +
              " row(s).");
    return out;
  }

  /**
   * Returns the route table's rows of one kind.
   *
   * @param kind - `management` or `console`
   * @returns the rows
   */
  routesOfKind(kind: string): any[] {
    const { log } = this.deps;
    log.debug("Entering AdminApi.routesOfKind(). " + kind);
    const rows = (ROUTES || []).filter(function (entry) {
      return (entry.kind || 'management') === kind;
    });
    log.debug("Leaving AdminApi.routesOfKind(). " + rows.length + " row(s).");
    return rows;
  }

  // Whether a request is for one of the console's operations: its path,
  // under the API's base, is `/console` or below it. The prefix IS the kind —
  // `tests/admin_api_kinds.js` holds that no row of one kind sits under the
  // other's — so the gate can ask it of a request it has not routed yet.
  /**
   * Tells whether a request is for one of the console's operations.
   *
   * @param req - the request
   * @returns true under `/admin-api/console`
   */
  isConsoleOperation(req): boolean {
    const { log } = this.deps;
    log.debug("Entering AdminApi.isConsoleOperation().");
    const path = String(req.path || '').replace(/\/+$/, '');
    const answer = path === '/console' || path.indexOf('/console/') === 0;
    log.debug("Leaving AdminApi.isConsoleOperation(). " + answer);
    return answer;
  }

  // Every operation, flattened, for the index. The same walk buildSpec() does,
  // and deliberately not a second list: an index that could disagree with the
  // document would be the first thing to go stale.
  /**
   * Returns every operation flattened, for the index: method, path,
   * operationId, summary and the console control it mirrors.
   *
   * @returns the operations
   */
  operationSummaries(kind?: string) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.operationSummaries(). " +
              (kind || 'management'));
    const out = [];
    // THE MANAGEMENT OPERATIONS unless `all` is asked for (#454): the index
    // and the banner count what an integrator may rely on; the console's
    // form table (`GET /admin-api/console/operations`) wants both kinds.
    const wanted = kind || 'management';
    ROUTES.filter(function (entry) {
      return wanted === 'all' || (entry.kind || 'management') === wanted;
    }).forEach(function (entry) {
      const rowKind = entry.kind || 'management';
      if (!entry.actions) {
        const row: any = { method: entry.method, path: entry.path,
                           operationId: entry.operationId,
                           mirrors: entry.mirrors || '', kind: rowKind };
        // The pages whose console operation draws this one's data (#454).
        if (entry.drawnOn) {
          row.drawnOn = entry.drawnOn.slice(0);
        }
        // WHAT THE CONSOLE MAY FORWARD TO THIS OPERATION (#1476): a page's
        // own query holds names only its address means (`notice`, `view`)
        // and the runtime asks each operation only what it declares.
        if (wanted === 'all' && entry.method === 'GET') {
          row.query = (entry.parameters || []).filter(function (one) {
            return one.in === 'query';
          }).map(function (one) {
            return one.name;
          });
        }
        out.push(row);
        return;
      }
      entry.actions.forEach(function (action) {
        out.push({ method: entry.method,
                   path: entry.route.replace(':action', action.action),
                   operationId: action.operationId, 
                   mirrors: action.mirrors || entry.mirrors || '',
                   kind: rowKind });
      });
    });
    log.debug("Leaving AdminApi.operationSummaries(). " + out.length +
              " operation(s).");
    return out;
  }

  // --- registration
  // -----------------------------------------------------------
  //
  // One express route per row, which for an action resource is one pattern
  // behind every action in it. Registering at require time is what every module
  // here did until #50's R1 (2026-09-16); now `common/protocol_stack.ts` calls
  // the exported `registerRoutes(app)`, which runs the two methods below. See
  // rule 1.
  // ---------------------------------------------------------------------------
  // THE GATE (2026-09-06), AND IT IS THE ONLY THING BETWEEN THIS API AND A
  // TOTAL AUTHENTICATION BYPASS IN PRODUCT MODE.
  //
  // **THIS RESOURCE IS UNGATED IN DEVELOPMENT AND THAT IS DELIBERATE** — it is
  // what the tests drive, and it is the way back in when nobody holds a role,
  // which a service that checks no password needs because there is otherwise no
  // way to bootstrap an administrator. `mgmt-api/CLAUDE.md` has argued that
  // since this API existed, and every word of it is still true of development
  // mode.
  //
  // It cannot survive into a product. Anybody who can reach this port can grant
  // themselves both console roles through `POST /admin-api/rbac/grant`, so an
  // ungated management API is not "a convenience beside a secured console" — it
  // is the console's gate with a documented way around it.
  //
  // **ONE MIDDLEWARE RATHER THAN A CHECK PER HANDLER**, and the reason is this
  // file's shape: there are more than three hundred operations behind about a
  // hundred routes, and a check per handler is one chance per operation to add
  // the next without one. Registered BEFORE the routes below, because express
  // applies middleware only to routes added after it — rule 1's other half.
  //
  // **THE EXPLORER AND ITS DOCUMENT WERE GATED TOO.** They describe every
  // operation this service offers, which is a map of the administrative
  // surface; a product deployment that served that to anybody would be handing
  // out the floor plan. The explorer moved to the console on 2026-09-09 and is
  // behind its session now; the HTML-shaped refusal below is kept for a browser
  // that navigates here anyway.
  // ---------------------------------------------------------------------------
  // AND SINCE 2026-09-09 THE FIRST QUESTION IS AN ACCESS TOKEN, IN EVERY MODE.
  //
  // The paragraphs above are the record of what this surface used to be and are
  // kept because the argument they make is still the argument for the OFF
  // switch: `adminApi.authRequired` restores the open API exactly, and it is
  // the way back in when nobody can mint a token.
  //
  // What changed is the default. `/admin-api` is a MACHINE surface — no
  // browser, no session, no sign-in screen — so it is reached the way a machine
  // reaches a resource server: an OAuth 2.0 access token this service issued,
  // audienced to this API, carrying `admin:read` for a read and `admin:write`
  // for anything that changes state. Three things are checked and each refuses
  // differently, because they are three different mistakes:
  //
  //   * NO TOKEN, or one this service did not sign, or an expired one — 401
  //     with a `WWW-Authenticate` header naming the scopes, which is what an
  //     OAuth client is built to read.
  //   * A TOKEN FOR SOMETHING ELSE — 403. An access token is a bearer
  //     credential, so one minted for another resource server must not be
  //     replayable here; that is the whole purpose of `aud` and it is the check
  //     most often left out.
  //   * A TOKEN WITHOUT THE SCOPE THE OPERATION NEEDS — 403 from the POLICY,
  //     not from this code. ADMIN_READ and ADMIN_WRITE are CONFIGURED roles
  //     since #303, authorizing admin:read and admin:write; the gate hands the
  //     policy the roles the token's subject holds now less those whose
  //     permissions the token does not carry (held ∩ carried,
  //     `common/role_permissions.ts`), and the XACML access-control document
  //     asks for the one the action requires — so what this surface demands
  //     is stated where every other access decision in this service is stated
  //     rather than in an `if` here.
  //
  // THE SCOPE IS NOT THE ROLE, AND SINCE #303 NEITHER IS MADE FROM THE OTHER.
  // A scope is what a client asked for and the authorization server granted;
  // a role is what a subject holds and a policy names. Until #303 the role
  // was READ OFF the scope, which made the scope the authorization — the
  // pattern #88 removes. Keeping them apart is still what lets a deployment
  // write "a read of the management API needs ADMIN_READ" without the
  // document knowing that OAuth exists.
  // ---------------------------------------------------------------------------
  // BOTH SCHEMES SINCE #34 (2026-09-15). It read `Bearer` alone until then, so
  // a DPoP-bound token presented here — with `Authorization: DPoP` — counted as
  // no token at all and got the "this API requires an access token" 401, which
  // is the least useful thing it could say to a client doing the stricter
  // thing. `scheme` is returned with the value because the gate below has to
  // refuse a BOUND token presented as Bearer, and that is a different refusal
  // from a token that does not verify.
  /**
   * Returns the access token the request presents in `Authorization`, and
   * whether as `Bearer` or `DPoP`.
   *
   * @param req - the request
   * @returns `{ token, scheme }`, both empty when none is presented
   */
  presentedTokenOf(req) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.presentedTokenOf().");
    const said = String((req.headers && req.headers.authorization) || '');
    const matched = /^(Bearer|DPoP)\s+(\S+)\s*$/i.exec(said);
    if (!matched) {
      log.debug("Leaving AdminApi.presentedTokenOf(). Nothing presented.");
      return { token: '', scheme: '' };
    }
    log.debug("Leaving AdminApi.presentedTokenOf(). " + matched[1]);
    return { token: matched[2].trim(), scheme: matched[1].toLowerCase() };
  }

  /**
   * Returns the access token the request presents, of either scheme.
   *
   * @param req - the request
   * @returns the token, or the empty string
   */
  bearerOf(req) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.bearerOf().");
    log.debug("Leaving AdminApi.bearerOf().");
    return this.presentedTokenOf(req).token;
  }

  // What `aud` has to name. The CONFIGURED audience first — since 2026-09-13
  // `adminApi.audience` defaults to the base URL of this API
  // (`config.managementApiBaseUrl()`) rather than to the empty string — and,
  // while that row is still at its default or set empty, `/admin-api` under the
  // host the request arrived on as well, which is exactly what a client gets by
  // asking `resource=<base>/admin-api` at the token endpoint. A default cannot
  // see a request, so taking it as the only answer would refuse every token
  // minted under another name for this same process. An operator who sets a
  // value pins that one value, as before.
  /**
   * Returns the audiences a token here may name: the pinned
   * `adminApi.audience`, or, while that is at its default, the configured base
   * and `/admin-api` under the host the request arrived on.
   *
   * @param req - the request
   * @returns the accepted audiences
   */
  wantedAudiences(req) {
    const { log, config, realms, baseUrlOf } = this.deps;
    log.debug("Entering AdminApi.wantedAudiences().");
    const pinned = String(config.value('adminApi.audience') || '').trim();
    const atDefault = config.sourceOf('adminApi.audience') === 'default';
    if (pinned && !atDefault) {
      log.debug("Leaving AdminApi.wantedAudiences().");
      return [pinned];
    }
    // COMPUTED OUTSIDE ANY REALM, for the reason the signing key is taken from
    // the default realm below: THIS credential is service-wide. `baseUrlOf()`
    // glues on `realms.currentPrefix()`, so under `/realm/acme` it would answer
    // `https://host/realm/acme/admin-api` — a different audience per realm.
    // Running in the default realm gives the empty prefix and one audience
    // everywhere. A realm's OWN token (2026-09-14, #32) carries the realm's
    // audience instead and is checked by `realmAudienceAccepted()`, which is
    // the one place a per-realm audience is accepted.
    const fromRequest = realms.run(realms.get(realms.DEFAULT_ID), function () {
      return baseUrlOf(req);
    }) + BASE;
    const wanted = [pinned || config.managementApiBaseUrl()];
    if (wanted.indexOf(fromRequest) < 0) {
      wanted.push(fromRequest);
    }
    log.debug("Leaving AdminApi.wantedAudiences().");
    return wanted;
  }

  // The one audience a refusal or a 401 names: the request-relative one where
  // it is accepted, because that is the `resource` the caller reading the
  // message can actually ask for under the name it used.
  /**
   * Returns the one audience a refusal names: the request-relative one where it
   * is accepted.
   *
   * @param req - the request
   * @returns the audience
   */
  wantedAudience(req) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.wantedAudience().");
    const wanted = this.wantedAudiences(req);
    log.debug("Leaving AdminApi.wantedAudience().");
    return wanted[wanted.length - 1];
  }

  /**
   * Says whether a token's `aud` names one of the accepted audiences.
   *
   * @param claims - the token's claims
   * @param req - the request
   * @returns whether it does
   */
  audienceAccepted(claims, req) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.audienceAccepted().");
    const wanted = this.wantedAudiences(req);
    const held = Array.isArray(claims.aud) ? claims.aud
      : (claims.aud === undefined || claims.aud === null ? [] : [claims.aud]);
    log.debug("Leaving AdminApi.audienceAccepted().");
    return held.map(String).some(function (aud) {
      return wanted.indexOf(aud) >= 0;
    });
  }

  // WHETHER A TARGET NAMES THIS API (#505): the audiences a token here may
  // carry, as `audienceAccepted()` and a realm's own `realmAudienceAccepted()`
  // read them, asked of one string. `common/registered_targets.ts` asks it,
  // so that an RFC 8707 resource naming the management API is one of this
  // service's own resource servers in product — read from the check a token
  // meets here, not from a second copy of it.
  /**
   * Says whether a target (an RFC 8707 resource, a GNAP location) names this
   * API: an audience a token here is accepted with.
   *
   * @param target - the target
   * @param req - the request it arrived on
   * @returns whether it does
   */
  namesThisApi(target, req) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.namesThisApi().");
    const claims = { aud: String(target == null ? '' : target) };
    const named = !!claims.aud && (this.audienceAccepted(claims, req) ||
                                   this.realmAudienceAccepted(claims, req));
    log.debug("Leaving AdminApi.namesThisApi(). " + named);
    return named;
  }

  // ---------------------------------------------------------------------------
  // RFC 9068 SECTION 4 STEP 3 — WHO ISSUED IT (2026-09-13).
  //
  // The addresses this API answers under, as authorization-server bases: every
  // wanted audience that is `<base>/admin-api`, the request's own default-realm
  // base, and the configured base of this API. A token's `iss` must be an
  // issuer one of this service's authorization servers publishes at one of them
  // — the default one, or a named one beneath it — which is
  // `jwt_access_token.js`'s `isHostedIssuer()`, the same reading the other
  // resource servers here make.
  //
  // SEVERAL BASES AND NOT ONE, for `wantedAudiences()`'s reason: this process
  // is reached under more than one name, and the suite mints a token at the
  // address it will call. A token minted under one of them names that one as
  // its issuer and its audience together, so accepting the issuers of exactly
  // the addresses whose audiences are accepted is what keeps the two checks
  // telling the same story. A pinned `adminApi.audience` names no base, which
  // is why the request's own and the configured one are always in the list.
  //
  // ASKED IN THE DEFAULT REALM, because that realm's key verified the token and
  // a pinned `oauth2.issuer` is read per realm.
  // ---------------------------------------------------------------------------
  /**
   * Says whether a token's `iss` is an issuer one of this service's
   * authorization servers publishes at one of the addresses this API answers
   * under (RFC 9068 section 4), asked in the default realm.
   *
   * @param claims - the token's claims
   * @param req - the request
   * @returns whether it is
   */
  issuerAccepted(claims, req) {
    const { log, realms, baseUrlOf, config, jwtAccessToken } = this.deps;
    const self = this;
    log.debug("Entering AdminApi.issuerAccepted().");
    const bases = [];
    const addBase = function (url) {
      const text = String(url || '');
      if (text.length > BASE.length && text.slice(-BASE.length) === BASE) {
        const base = text.slice(0, -BASE.length);
        if (bases.indexOf(base) < 0) {
          bases.push(base);
        }
      }
    };
    const accepted = realms.run(realms.get(realms.DEFAULT_ID), function () {
      self.wantedAudiences(req).forEach(addBase);
      addBase(baseUrlOf(req) + BASE);
      addBase(config.managementApiBaseUrl());
      return bases.some(function (base) {
        return jwtAccessToken.isHostedIssuer(claims.iss, base);
      });
    });
    log.debug("Leaving AdminApi.issuerAccepted(). accepted=" + accepted);
    return accepted;
  }

  // ---------------------------------------------------------------------------
  // A REALM TOKEN'S THREE BOUNDS (2026-09-14, #32). See the gate below.
  // ---------------------------------------------------------------------------

  // Its issuer is THIS realm's: a hosted issuer under the realm's own base.
  /**
   * Says whether a realm token's `iss` is a hosted issuer under the realm's own
   * base.
   *
   * @param claims - the token's claims
   * @param req - the request
   * @returns whether it is
   */
  realmIssuerAccepted(claims, req) {
    const { log, jwtAccessToken, baseUrlOf } = this.deps;
    log.debug("Entering AdminApi.realmIssuerAccepted().");
    const accepted = jwtAccessToken.isHostedIssuer(claims.iss, baseUrlOf(req));
    log.debug("Leaving AdminApi.realmIssuerAccepted(). " + accepted);
    return accepted;
  }

  // Its audience is THIS realm's management API — the request's own base under
  // the realm prefix, which is what `resource=<base>/realm/<id>/admin-api` at
  // that realm's token endpoint gives. `adminApi.audience` pins the SERVICE's
  // audience and is not consulted: it names the unprefixed API.
  /**
   * Says whether a realm token's `aud` names this realm's management API.
   *
   * @param claims - the token's claims
   * @param req - the request
   * @returns whether it does
   */
  realmAudienceAccepted(claims, req) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering AdminApi.realmAudienceAccepted().");
    const wanted = baseUrlOf(req) + BASE;
    const held = Array.isArray(claims.aud) ? claims.aud
      : (claims.aud === undefined || claims.aud === null ? [] : [claims.aud]);
    const accepted = held.map(String).indexOf(wanted) >= 0;
    log.debug("Leaving AdminApi.realmAudienceAccepted(). " + accepted);
    return accepted;
  }

  // Whether this request is the MDM feed (#164 phase 3), `POST
  // /admin-api/device-compliance` — `req.path` is below BASE inside the gate.
  /**
   * Says whether the request is the MDM feed, `POST
   * /admin-api/device-compliance`.
   *
   * @param req - the request
   * @returns whether it is
   */
  isDeviceComplianceFeed(req) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.isDeviceComplianceFeed().");
    const path = String(req.path || '').replace(/\/+$/, '');
    log.debug("Leaving AdminApi.isDeviceComplianceFeed().");
    return req.method === 'POST' && (path === DEVICE_COMPLIANCE_PATH ||
                                     path === BASE + DEVICE_COMPLIANCE_PATH);
  }

  // ---------------------------------------------------------------------------
  // THE OBJECT AN OWNER WOULD ADMINISTER (#607): the row of OWNER_OPERATIONS
  // the request is, the object it names, the action, and — for an
  // application action that writes attributes — every attribute it would
  // write, read the way the handler reads them (`fieldsCoveredBy()`), so the
  // owner rule is asked about each. Null for a request that is not one an
  // owner may ask, or that names no object.
  // ---------------------------------------------------------------------------
  /**
   * Returns the object an owner's request would administer.
   *
   * @param req - the request, inside the gate (`req.path` below BASE)
   * @returns `{ kind, id, action, attributes, project }`, or null
   */
  ownedOperationOf(req) {
    const { log, parseBody, adminActions } = this.deps;
    log.debug("Entering AdminApi.ownedOperationOf().");
    const path = String(req.path || '').replace(/\/+$/, '')
      .replace(new RegExp('^' + BASE + '(?=/)'), '');
    const method = String(req.method || '').toUpperCase();
    let matched: OwnerOperation | null = null;
    let action = '';
    OWNER_OPERATIONS.forEach(function (row) {
      if (matched || row.method !== method) {
        return;
      }
      if (row.path && row.path === path) {
        matched = row;
        action = 'read';
        return;
      }
      const found = row.pattern ? row.pattern.exec(path) : null;
      if (found) {
        matched = row;
        action = found[1];
      }
    });
    if (!matched) {
      log.debug("Leaving AdminApi.ownedOperationOf(). Not an owner's " +
                "operation.");
      return null;
    }
    const row: OwnerOperation = matched;
    const query = req.query || {};
    const body = method === 'GET' ? {} : (parseBody(req) || {});
    const id = row.target(query, body).trim();
    if (!id) {
      log.debug("Leaving AdminApi.ownedOperationOf(). It names no object.");
      return null;
    }
    // THE ATTRIBUTES AN APPLICATION ACT WOULD WRITE: one for the three
    // single-attribute acts, every one an `update-fields` body covers, and
    // the declared families where it carries them.
    let attributes: string[] = [];
    if (row.kind === 'application') {
      if (['set', 'add', 'remove'].indexOf(action) >= 0) {
        attributes = [String(body.attribute || '')].filter(Boolean);
      } else if (action === 'update-fields') {
        attributes = adminActions.fieldsCoveredBy(body).slice(0);
        if ((body.protocolsPresent || body.protocols !== undefined ||
             body.protocol !== undefined) &&
            attributes.indexOf('appAllowedProtocol') < 0) {
          attributes.push('appAllowedProtocol');
        }
      }
    }
    log.debug("Leaving AdminApi.ownedOperationOf(). " + row.kind + " " +
              action + ".");
    return { kind: row.kind, id: id, action: action,
             attributes: attributes, project: row.project || null };
  }

  // ---------------------------------------------------------------------------
  // A WRITE ONLY A SECURITY ADMINISTRATOR MAY MAKE (#645): asked of
  // `common/security_operations.ts` with the console operation this request
  // mirrors and what it reads of the realm the request is about. Null for a
  // read and for every write Admin Write may make.
  // ---------------------------------------------------------------------------
  /**
   * Returns the security change a request is, or null.
   *
   * @param req - the request, inside the gate
   * @returns `{ kind, detail }`, or null
   */
  securityChangeOf(req) {
    const { log, parseBody, rbac, applications, adminActions, config,
            realms } = this.deps;
    log.debug("Entering AdminApi.securityChangeOf().");
    const method = String(req.method || '').toUpperCase();
    if (method === 'GET' || method === 'HEAD') {
      log.debug("Leaving AdminApi.securityChangeOf(). A read.");
      return null;
    }
    const operation = this.consoleOperationOf(req);
    // No body is read for a page no security change is a write of — an
    // upload, the risk datasets, everything but the nine.
    if (SecurityOperations.PATHS.indexOf(
          String(operation.path).replace(/\/+$/, '')) < 0) {
      log.debug("Leaving AdminApi.securityChangeOf(). Not a page one is " +
                "a write of.");
      return null;
    }
    const body = Object.assign({}, parseBody(req) || {});
    const realm = realms.currentId();
    const change = SecurityOperations.classify({
      method: method, path: operation.path, action: operation.action,
      body: body
    }, {
      securityGroup: function () {
        log.debug("Entering securityGroup().");
        log.debug("Leaving securityGroup().");
        return String(config.value(SecurityOperations.SECURITY_GROUP_SETTING) ||
                      '');
      },
      holdsSecurity: function (username) {
        log.debug("Entering holdsSecurity().");
        log.debug("Leaving holdsSecurity().");
        return rbac.holdsSecurity(username, realm);
      },
      applicationValues: function (identifier, attribute) {
        log.debug("Entering applicationValues().");
        const row = applications.get(identifier);
        const fields = (row && row.fields) || {};
        const wanted = String(attribute).toLowerCase();
        const key = Object.keys(fields).filter(function (name) {
          return name.toLowerCase() === wanted;
        })[0];
        log.debug("Leaving applicationValues().");
        return key ? [].concat(fields[key]).map(String) : [];
      },
      personValues: function (username, attribute) {
        log.debug("Entering personValues().");
        log.debug("Leaving personValues().");
        return rbac.personValues(username, attribute, realm);
      },
      groupValues: function (group, attribute) {
        log.debug("Entering groupValues().");
        log.debug("Leaving groupValues().");
        return rbac.groupValues(group, attribute, realm);
      },
      fieldsCoveredBy: function (given) {
        log.debug("Entering fieldsCoveredBy().");
        log.debug("Leaving fieldsCoveredBy().");
        return adminActions.fieldsCoveredBy(given);
      }
    });
    log.debug("Leaving AdminApi.securityChangeOf(). " +
              (change ? change.kind : 'not one'));
    return change;
  }

  // The operation a request is, as the CONSOLE path it mirrors and the action
  // it names: `/admin-api/pki/build-root` is a POST of `build-root` to
  // `/admin/pki`, `/admin-api/config/set-many` one of `set-many` to
  // `/admin/config`. An action route is recognised off ROUTES, so a path
  // segment is only ever an action where this API declares one.
  /**
   * Returns the console operation a request mirrors: the `/admin` path and the
   * action it names.
   *
   * @param req - the request
   * @returns `{ path, action }`
   */
  consoleOperationOf(req) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.consoleOperationOf().");
    // A CONSOLE OPERATION (#454) mirrors the page it draws as its
    // management twin does: `/admin-api/console/delegation/map` is
    // `/admin/delegation/map`, and the frame is `/admin`.
    const path = BASE + String(req.path || '')
      .replace(/^\/console(?=\/|$)/, '');
    let action = '';
    let resource = path;
    ROUTES.forEach(function (entry) {
      const route = String(entry.route || '');
      if (!action && route.slice(-':action'.length) === ':action') {
        const prefix = route.slice(0, -':action'.length);
        const rest = path.slice(prefix.length);
        if (path.indexOf(prefix) === 0 && rest && rest.indexOf('/') < 0) {
          action = rest;
          resource = prefix.replace(/\/$/, '');
        }
      }
    });
    log.debug("Leaving AdminApi.consoleOperationOf(). " + resource + " " +
              action);
    return { path: '/admin' + resource.slice(BASE.length), action: action };
  }

  // ---------------------------------------------------------------------------
  // THE ADMIN SCOPES A TOKEN MAY STILL USE (#110, 2026-09-22): those its
  // client DECLARES, in the realm that issued it. Answers the scope list with
  // every `admin:*` value the client no longer declares taken off, and which
  // were taken.
  //
  // ONE RULE FOR BOTH REALMS. Until #110 the default realm's token was
  // accepted from ANY client carrying `admin:read`/`admin:write` — the token
  // endpoint tied no scope to a client, so any client that could use
  // client_credentials minted Admin Write here, and in development, where a
  // client credential is not verified, that was any client_id — while a
  // realm's token was accepted only from that realm's `sts-management-api`
  // (STS-API-0111). The token endpoint now issues `admin:*` only to a client
  // whose `oauthAllowedScope` lists it, and this asks the same question again
  // on every call, so an allowance removed from a client stops the tokens it
  // already holds. The seeded `sts-api-client` (`sts-management-api` until
  // #1139) and `sts-admin-console`
  // declare both in every realm.
  // ---------------------------------------------------------------------------
  /**
   * Splits a token's scopes into those its client still declares and the
   * `admin:*` and `device:compliance` scopes it no longer does, asked in the
   * realm that issued the token.
   *
   * @param claims - the token's claims
   * @param tokenRealm - the id of the realm that issued the token
   * @param scopes - the token's scopes
   * @returns `{ kept, undeclared }`
   */
  declaredAdminScopes(claims, tokenRealm, scopes) {
    const { log, realms, scopePolicy } = this.deps;
    log.debug("Entering AdminApi.declaredAdminScopes().");
    const clientId = String(claims.client_id || '');
    // The device compliance feed's scope (#164) is held to the same rule,
    // and an owner's two (#607).
    const held = scopePolicy.ADMIN_SCOPES
      .concat([scopePolicy.DEVICE_COMPLIANCE_SCOPE])
      .concat(scopePolicy.OWNER_SCOPES);
    const undeclared = realms.run(realms.get(tokenRealm), function () {
      return scopes.filter(function (one) {
        return held.indexOf(one) >= 0 &&
               !scopePolicy.declares(clientId, one);
      });
    });
    log.debug("Leaving AdminApi.declaredAdminScopes(). " +
              undeclared.length + " undeclared.");
    return { kept: scopes.filter(function (one) {
      return undeclared.indexOf(one) < 0;
    }), undeclared: undeclared };
  }

  // The scope table for a realm's own token. Answers null, or
  // `{ code, detail }`. Which CLIENT it was issued to is
  // declaredAdminScopes()'s question, asked for both realms (#110); this is
  // the realm's confinement.
  /**
   * Returns why a realm's own token may not perform this operation, from the
   * realm administrator's confinement.
   *
   * @param claims - the token's claims
   * @param req - the request
   * @returns null when allowed, or `{ code, detail }`
   */
  realmTokenRefusal(claims, req) {
    const { log, parseBody, adminScope, realms } = this.deps;
    log.debug("Entering AdminApi.realmTokenRefusal().");
    const operation = this.consoleOperationOf(req);
    const body = req.method === 'GET' || req.method === 'HEAD'
      ? null : Object.assign({}, parseBody(req));
    if (body && operation.action) {
      body.action = operation.action;
    }
    const refusal = adminScope.refusalFor(
      { authority: 'realm', identityRealm: realms.currentId() },
      operation.path, body, req.query);
    log.debug("Leaving AdminApi.realmTokenRefusal(). " +
              (refusal ? refusal.reason : 'allowed'));
    return refusal
      ? { code: 'STS-API-0112',
          detail: refusal.detail + ' A realm\'s token reaches that realm\'s ' +
                  'operations only; a service administrator\'s token, from ' +
                  'the default realm, reaches this one.' }
      : null;
  }

  // ---------------------------------------------------------------------------
  // IS AN ACCESS TOKEN REQUIRED ON THIS REQUEST? ONE READING, FOR THE GATE AND
  // FOR EVERYTHING THAT REPORTS IT (#446, 2026-10-05).
  //
  // `adminApi.authRequired` is development-only when it is off: the row
  // carries the `onlyWhile` marker on `mode.opensManagementApi()`, so the
  // value IN FORCE in a product realm is `true` whatever is stored. The gate,
  // the index's `protected`, the OpenAPI document's security section and the
  // startup banner all ask this, because a report reading the stored value
  // would say "open" about an API that is refusing.
  //
  // The mode is the AMBIENT realm's, as everywhere: a product realm of a
  // development process requires the token under its own prefix.
  // ---------------------------------------------------------------------------
  /**
   * Tells whether this API requires an access token here: the value of
   * `adminApi.authRequired` in force, which product mode reads as true.
   *
   * @returns true when a token is required
   */
  tokenRequired(): boolean {
    const { log, mode } = this.deps;
    log.debug("Entering AdminApi.tokenRequired().");
    const required = mode.valueInForce('adminApi.authRequired') === true;
    log.debug("Leaving AdminApi.tokenRequired(). " + required);
    return required;
  }

  // ---------------------------------------------------------------------------
  // A TOKEN DIES WITH THE SIGN-ON SESSION IT WAS ISSUED ON (#446, 2026-10-05).
  //
  // The server-rendered console held a relying-party session that named the
  // sign-on session it came from and ended with it (`common/oidc_rp.ts`), so
  // signing out, or a session running out, closed the console at once. A
  // console that is a client of this API holds a TOKEN instead, and a token
  // is good until it expires unless somebody asks — so this gate asks.
  //
  // No token carries a session identifier (`common/admin_stats.js`,
  // `signJwt()`'s third argument): the token registry was told which session
  // an issuance ran on, and is asked by `jti`. The session is then asked of
  // `authn/`, through `oauth2.sessionIsLive()`, the one answer to "is this
  // session live" a token-bearing door uses. Both in the realm that issued
  // the token, which is where the code flow ran.
  //
  // TWO THINGS IT DELIBERATELY DOES NOT REFUSE. A token issued on NO session
  // — `client_credentials`, and the API explorer's — has nothing to end. And
  // a token the registry no longer holds (it is capped, and drops the oldest)
  // answers no session and is honoured until it expires: refusing what the
  // registry forgot would turn a cache's eviction into a sign-out.
  // ---------------------------------------------------------------------------
  /**
   * Returns the sign-on session a token was issued on when that session has
   * ended.
   *
   * @param claims - the token's verified claims
   * @param tokenRealm - the id of the realm that issued the token
   * @returns the session's id, or '' when the token was issued on no session,
   *   the registry does not hold it, or its session is live
   */
  endedSessionOf(claims, tokenRealm): string {
    const { log, realms, stats } = this.deps;
    log.debug("Entering AdminApi.endedSessionOf().");
    const jti = String((claims && claims.jti) || '');
    if (!jti) {
      log.debug("Leaving AdminApi.endedSessionOf(). No jti.");
      return '';
    }
    const ended = realms.run(realms.get(tokenRealm), function () {
      const sid = String(stats.sessionIdOfJti(jti) || '');
      return sid && !oauth2.sessionIsLive(sid) ? sid : '';
    });
    log.debug("Leaving AdminApi.endedSessionOf(). " +
              (ended ? 'Ended.' : 'Live, or none.'));
    return ended;
  }

  // ---------------------------------------------------------------------------
  // WHO IS CALLING, FOR AN AUDIT ROW (#446, 2026-10-05).
  //
  // The gate leaves the verified token's subject on `res.locals.apiCaller`.
  // With `adminApi.authRequired` off — development only — there is no token
  // and so nobody to name, and this answers ''. It never reads the request:
  // an actor a caller could nominate is not an audit trail.
  // ---------------------------------------------------------------------------
  /**
   * Names the subject of the access token this request was let in on, for an
   * audit row: a person's name, or the client's id.
   *
   * @param res - the response, whose locals the gate wrote
   * @returns the name, or '' where no token was required
   */
  callerNameOf(res): string {
    const { log } = this.deps;
    log.debug("Entering AdminApi.callerNameOf().");
    const caller = res && res.locals && res.locals.apiCaller;
    const name = caller ? String(caller.name || '') : '';
    log.debug("Leaving AdminApi.callerNameOf(). " + (name || '(nobody)'));
    return name;
  }

  // ---------------------------------------------------------------------------
  // WHO IS CALLING, AS A PERSON (#945): an administrator's passkey enrolment
  // records the administrator — the verified token's subject, name and
  // `sub` — and only a PERSON may be that: a client's own token names an
  // application, and development's open API names nobody, so both answer
  // null and the enrolment is refused (STS-AUTHN-0445).
  // ---------------------------------------------------------------------------
  /**
   * Names the person whose access token this request was let in on.
   *
   * @param res - the response, whose locals the gate wrote
   * @returns `{ username, sub }`, or null where the caller is no person
   */
  callerPersonOf(res): { username: string; sub: string } | null {
    const { log } = this.deps;
    log.debug("Entering AdminApi.callerPersonOf().");
    const caller = res && res.locals && res.locals.apiCaller;
    const out = caller && caller.kind === 'person' && caller.name
      ? { username: String(caller.name), sub: String(caller.sub || '') }
      : null;
    log.debug("Leaving AdminApi.callerPersonOf(). " +
              (out ? out.username : '(nobody)'));
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE CONSOLE'S GATE, AS THE TOKEN DECIDED IT (#446).
  //
  // The console's frame says who is signed in and with which roles, and
  // draws the sidebar for that reader (`AdminConsole.shellJson()`). The
  // server-rendered console read it off its own session; the static one has
  // none — the token is the session — so the gate it is drawn from is
  // `meJson()`'s answer in the shape `gateStateFor()` gives: a token is a
  // session, its subject the username, and `ADMIN_READ` / `ADMIN_WRITE` the
  // console's `read` and `write`.
  // ---------------------------------------------------------------------------
  /**
   * Describes the caller as the console's gate does, for the frame.
   *
   * @param me - `meJson()`'s answer
   * @returns the gate state
   */
  consoleGateOf(me) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.consoleGateOf().");
    // SECURITY_ADMIN is the roster's `security` (#645).
    const roles = (me.roles || []).map(function (role) {
      return role === 'ADMIN_READ' ? 'read'
        : (role === 'ADMIN_WRITE' ? 'write'
          : (role === 'SECURITY_ADMIN' ? 'security'
            : String(role).toLowerCase()));
    });
    const held = me.console || {};
    const enforced = !!me.tokenRequired;
    log.debug("Leaving AdminApi.consoleGateOf().");
    return {
      enforced: enforced, available: !!held.available,
      session: !!me.caller,
      username: me.caller ? String(me.caller.name || '') : '',
      authority: me.authority || null, identityRealm: me.realm || null,
      readGroup: me.readGroup, writeGroup: me.writeGroup,
      read: !!me.read, write: !!me.write, security: !!me.security,
      roles: roles,
      open: enforced && !!held.open,
      closed: enforced && !!held.empty && !held.open && !roles.length,
      windowOpens: held.windowOpens !== false, empty: !!held.empty,
      bootstrapPasswordRequired: enforced && !!held.bootstrapPasswordRequired,
      bootstrap: held.bootstrap || null
    };
  }

  // ---------------------------------------------------------------------------
  // `GET /admin-api/me`'S ANSWER (#446, 2026-10-05) — see the operation.
  //
  // THE ROLES ARE THE GATE'S, NOT A SECOND READING. `read` is "the gate would
  // let a GET through" and `write` "anything else": ADMIN_READ and ADMIN_WRITE
  // among the roles the gate handed the access policy, which are held ∩
  // carried (#303). Asking the roster again here could answer differently
  // from the gate that has just let this very request in.
  //
  // The roster IS asked for what only it knows and the gate does not decide
  // on: whether the console is still open to anybody, and the bootstrap
  // administrator's state — what the server-rendered console's banner said
  // from `gateStateFor()`. Asked for a person only, in the token's realm; a
  // roster that cannot be read reports itself unavailable rather than
  // failing the call.
  // ---------------------------------------------------------------------------
  /**
   * Builds `GET /admin-api/me`'s answer from what the gate decided for this
   * request.
   *
   * @param req - the request
   * @param res - the response, whose locals the gate wrote
   * @returns the caller, the authority, the scopes and roles, `read` and
   *   `write`, the roster's state and the console pages the caller may reach
   */
  // THE CONSOLE'S LANGUAGE (#539 phase 5), for the signed-in person and the
  // console's own client id.
  /**
   * Answers the console's `locale` member: the negotiation, the catalogs
   * along its chain and the offered locales.
   *
   * @param req - the request
   * @param res - the response, whose `locals.apiCaller` names the caller
   * @returns the console's language data
   */
  consoleLocale(req, res, asFiles = false) {
    const { log } = this.deps;
    log.debug("Entering AdminApi.consoleLocale().");
    const caller = (res && res.locals && res.locals.apiCaller) || null;
    const page = {
      application: String(oidcRp.SURFACES.admin.clientId),
      username: caller && caller.kind === 'person' ? String(caller.name) : ''
    };
    const out = asFiles ? PageLocale.consoleLanguage(req, page)
      : PageLocale.consoleData(req, page);
    log.debug("Leaving AdminApi.consoleLocale(). " + out.negotiated.locale);
    return out;
  }

  /**
   * Handles `POST /admin-api/console/language`: writes or removes the
   * caller's own preferredLanguage and answers the console's language data.
   *
   * @param req - the request
   * @param res - the response
   * @returns nothing
   */
  consoleSetLanguage(req, res) {
    const { log, parseBody } = this.deps;
    log.debug("Entering AdminApi.consoleSetLanguage().");
    const caller = (res && res.locals && res.locals.apiCaller) || null;
    const asked = String((parseBody(req) || {}).lang || '').trim();
    const tag = asked ? i18n.canonical(asked) : '';
    if (asked && (!tag || !i18n.answers(tag))) {
      errorCodes.mark(res, 'STS-I18N-0008');
      this.sendJson(res, 400, { ok: false, errors: ['"' +
        asked.slice(0, 64) + '" is not a language this service has a ' +
        'catalog for.'] });
      log.debug("Leaving AdminApi.consoleSetLanguage(). Not offered.");
      return;
    }
    if (!caller || caller.kind !== 'person') {
      errorCodes.mark(res, 'STS-I18N-0010');
      this.sendJson(res, 400, { ok: false, errors: ['Only a person signed ' +
        'in to the console has a language of their own to set.'] });
      log.debug("Leaving AdminApi.consoleSetLanguage(). Not a person.");
      return;
    }
    const who = String(caller.name);
    const editor = require('../ldap/person_editor');
    const current = String(require('../common/locale_policy')
      .preferredLanguageOf(who) || '');
    const written = tag
      ? editor.update(who, { attribute: 'preferredLanguage', mode: 'set',
                             value: tag },
                      { actor: who, via: 'the admin console' })
      : (current
        ? editor.update(who, { attribute: 'preferredLanguage',
                               mode: 'remove', value: current },
                        { actor: who, via: 'the admin console' })
        : { ok: true });
    if (!written || !written.ok) {
      errorCodes.mark(res, errorCodes.codeOf(written) || 'STS-I18N-0009');
      this.sendJson(res, 400, { ok: false,
        errors: (written && written.errors) ||
                ['The language could not be written.'] });
      log.debug("Leaving AdminApi.consoleSetLanguage(). Refused.");
      return;
    }
    if (tag) {
      res.append('Set-Cookie', PageLocale.cookieLine(tag));
    }
    this.sendJson(res, 200, { ok: true, locale: this.consoleLocale(req, res) });
    log.debug("Leaving AdminApi.consoleSetLanguage(). " + (tag || 'removed'));
  }

  meJson(req, res) {
    const { log, config, realms, mode, adminScope } = this.deps;
    log.debug("Entering AdminApi.meJson().");
    const caller = (res && res.locals && res.locals.apiCaller) || null;
    const required = this.tokenRequired();
    const realmId = caller ? String(caller.realm) : realms.currentId();
    const authority = !caller ? null
      : (realmId === realms.DEFAULT_ID ? 'service' : 'realm');
    const roles = caller ? (caller.roles || []).slice(0) : [];
    let roster = null;
    if (caller && caller.kind === 'person') {
      try {
        roster = rbac.rolesOf(caller.name, realmId);
      } catch (e) {
        // A roster that cannot be read is reported as unavailable: this is a
        // description of the caller, and the gate has already decided.
        log.debug("Caught in AdminApi.meJson(): " + ((e && e.message) || e));
        roster = null;
      }
    }
    const scopeState = { authority: authority || undefined,
                         identityRealm: realmId };
    const json = {
      tokenRequired: required,
      caller: caller ? { kind: caller.kind, name: caller.name,
                         clientId: caller.clientId } : null,
      realm: realmId,
      readingRealm: realms.currentId(),
      authority: authority,
      scopes: caller ? (caller.scopes || []).slice(0) : [],
      roles: roles,
      read: !required || roles.indexOf('ADMIN_READ') >= 0,
      write: !required || roles.indexOf('ADMIN_WRITE') >= 0,
      // #645: whether a security change would be let through.
      security: !required || roles.indexOf('SECURITY_ADMIN') >= 0,
      expiresAt: caller ? caller.expiresAt : null,
      // The account menu's picture (#719): this realm's copy, a person's only.
      photo: caller && caller.kind === 'person'
        ? require('../common/profile_photo').pathFor(String(caller.name)) : '',
      mode: mode.current(),
      readGroup: config.value('admin.readGroup'),
      writeGroup: config.value('admin.writeGroup'),
      console: {
        available: rbac.available(),
        open: !!(roster && roster.open),
        empty: !!(roster && roster.empty),
        windowOpens: !roster || roster.windowOpens !== false,
        bootstrapPasswordRequired: !!(roster && roster.claimPending),
        bootstrap: (roster && roster.bootstrap) || null
      },
      // The pages alone (2026-10-21): `consoleJson()` built the whole
      // snapshot for them, on every console page.
      pages: admin.consolePages().filter(function (path) {
        return adminScope.pageVisible(scopeState, path);
      })
    };
    log.debug("Leaving AdminApi.meJson(). " +
              (caller ? caller.kind + ' ' + caller.name : 'no caller') +
              ", read=" + json.read + ", write=" + json.write + ".");
    return json;
  }

  // ---------------------------------------------------------------------------
  // WHAT THE OPENAPI DOCUMENT IS BUILT FROM, IN ONE PLACE.
  //
  // `admin_api_spec.ts` is a pure function over the route table and takes every
  // fact about the running service as an option — that is its own rule, and it
  // is what keeps the document from describing one moment. The cost of that
  // rule is that each CALLER has to supply those facts, and there are three:
  // this file's `/admin-api/openapi.json`, and the two in
  // `admin-ui/api_explorer.ts` (the console's copy of the document, and the
  // `?format=json` view that counts its operations).
  //
  // **THREE CALLERS ASSEMBLING THE SAME OPTIONS BY HAND IS THREE ANSWERS
  // WAITING TO DIVERGE**, and one of them already had: the gate's state was not
  // among the options at all, so the document said no credential was needed by
  // an API that requires one. So the options are gathered HERE, beside the
  // table they describe, and a fourth caller gets the same three facts by
  // asking rather than by remembering. `tests/admin_api_document_security.js`
  // asserts that every call site goes through this function.
  // ---------------------------------------------------------------------------
  /**
   * Returns the facts the OpenAPI document is built from: the base URL, the
   * version and whether the gate is on.
   *
   * @param req - the request
   * @returns `{ baseUrl, version, authRequired }`
   */
  specOptions(req) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering AdminApi.specOptions().");
    const options = {
      baseUrl: baseUrlOf(req),
      version: VERSION,
      // The one that was missing. A boolean rather than a truthy test because
      // this becomes a claim in a published document, and the value IN FORCE
      // rather than the stored one (#446): product ignores `false`.
      authRequired: this.tokenRequired()
    };
    log.debug("Leaving AdminApi.specOptions(). authRequired=" +
              options.authRequired);
    return options;
  }

  // THE GATE, registered where it always was: the exported
  // `registerRoutes(app)` calls this first, and `common/protocol_stack.ts`
  // calls that at the point the gate used to be registered, so the route
  // order is unchanged (rule 1; #50, R1).
  /**
   * Registers the access-token gate on the base path, ahead of every operation.
   *
   * With `adminApi.authRequired` in force — always, in product mode — it
   * refuses a missing or unverifiable token with 401 and a token for another
   * audience, issuer or without the needed permission with 403; the permission
   * is decided by the XACML access policy.
   *
   * @param app - the express app
   */
  registerGate(app: RouteApp): void {
    const { log, errorCodes, realms, STS, stsCrypto, jwtAccessToken,
            mtls, dpop, senderConstraints, accessGate,
            rolePermissions } = this.deps;
    const self = this;
    log.debug("Entering AdminApi.registerGate().");
    // EVERY ANSWER IS HELD TO ITS MODEL (#1353), a gate's refusal
    // included, so this comes before the gate. Both documents, because this
    // one prefix serves the management operations and the console's own; asked
    // for the paths alone, so the options a request would supply do not matter.
    responseChecks.install(app as any, BASE, function () {
      return spec.buildSpec(ROUTES, { authRequired: true,
        // reads only the response models: publishes nothing, so no gate state.
      });
    }, spec.refusalSchema());
    app.use(BASE, function (req, res, next) {
      if (self.tokenRequired()) {
        // THE ONE OPERATION THAT IS NOT AN ADMINISTRATOR'S (#164 phase 3):
        // the MDM feed takes `device:compliance` and its role, and nothing
        // else here takes that scope — see DevicesAdmin.mdmFeed().
        const mdmFeed = self.isDeviceComplianceFeed(req);
        // THE CONSOLE'S OWN OPERATIONS (#454) take `admin:console`, the
        // permission of the ADMIN_CONSOLE role the console's client confers
        // on everybody who signs in through it — see withConsoleRoutes().
        const consoleOp = self.isConsoleOperation(req);
        // A WRITE THAT CHANGES SECURITY (#645) takes `admin:security`, the
        // permission of SECURITY_ADMIN, INSTEAD of `admin:write`: a Security
        // Administrator need not hold Admin Write, and Admin Write alone may
        // not make it — see `common/security_operations.ts`.
        const securityChange = mdmFeed || consoleOp ? null
          : self.securityChangeOf(req);
        const scopesWanted = mdmFeed ? 'device:compliance'
          : (consoleOp ? 'admin:console'
            : (securityChange ? 'admin:security'
              : (req.method === 'GET' ? 'admin:read' : 'admin:write')));
        const presentation = self.presentedTokenOf(req);
        const presented = presentation.token;
        if (!presented) {
          // The scope to ask for: the feed's or the console's own (#454)
          // where the operation is one of theirs, both admin scopes
          // otherwise.
          const hint = mdmFeed || consoleOp || securityChange ? scopesWanted
                                            : 'admin:read admin:write';
          res.set('WWW-Authenticate',
                  'Bearer realm="' + BASE + '", scope="' + hint + '"');
          errorCodes.mark(res, 'STS-API-0001');
          return self.sendJson(res, 401, { error: 'unauthorized', errors: [
            'This API requires an OAuth 2.0 access token. Ask ' +
            '/oauth2/token for one with `grant_type=client_credentials`, ' +
            '`scope=' + hint +
            '` and `resource=' +
            self.wantedAudience(req) +
            '`, then send it as `Authorization: Bearer`. ' +
            'adminApi.authRequired turns this off.'] });
        }
        // ---------------------------------------------------------------------
        // VERIFIED AGAINST THE DEFAULT REALM'S KEY, WHEREVER THIS IS REACHED.
        //
        // `STS` is a proxy over the AMBIENT realm's key set, so under
        // `/realm/<id>/admin-api` it is that realm's — and a token minted at
        // the default realm's token endpoint then fails to verify, which is a
        // 401 on a perfectly good credential.
        //
        // Taking the default realm's key is not a workaround for that; it is
        // the SERVICE credential, and the service roster is the default realm's
        // too. A token a realm's key signed would be believed nowhere else if
        // it were believed here, which is why that case is its own block below:
        // since 2026-09-14 (#32) a realm has administrators of its own, their
        // token is tried only under their realm's prefix, and `admin_scope.js`
        // refuses it every service-wide operation. Believing a realm-minted
        // token AS the service credential would be the hole — anybody who could
        // create a realm minting a token for everything — and this key is what
        // keeps it shut.
        //
        // The AUDIENCE needs no such care: `baseUrlOf()` answers scheme and
        // host with no path, so `<base>/admin-api` is the same string in every
        // realm.
        // ---------------------------------------------------------------------
        let claims = null;
        try {
          // Any generation of the DEFAULT realm's key (#42).
          claims = realms.run(realms.get(realms.DEFAULT_ID), function () {
            return helpers.verifyOwnJws(presented);
          });
        } catch (e) {
          log.debug("Caught in a callback in module scope: " +
                    ((e && e.message) || e));
          claims = null;
        }
        // -------------------------------------------------------------------
        // A REALM'S OWN TOKEN (2026-09-14, #32).
        //
        // A trust realm has administrators of its own, and rule 7 owes them the
        // machine door to their realm. A token that does not verify under the
        // default realm's key is tried under the AMBIENT realm's key — and only
        // when the request is under a realm prefix, so a realm's key is never
        // tried at `/admin-api` itself or at another realm's. What such a token
        // may do is then bounded three ways below: its issuer and audience are
        // this realm's, it was issued to this realm's `sts-api-client`
        // client, and `admin-ui/admin_scope.ts` refuses it every service-wide
        // operation.
        //
        // This is the hole the comment above the default-realm key named — a
        // realm-minted credential its API believes — answered rather than
        // reopened: the credential is believed IN THAT REALM ONLY.
        // -------------------------------------------------------------------
        let tokenRealm = realms.DEFAULT_ID;
        if (!claims && realms.currentId() !== realms.DEFAULT_ID) {
          try {
            claims = helpers.verifyOwnJws(presented);
            tokenRealm = realms.currentId();
          } catch (e) {
            log.debug("Caught in a callback in module scope: " +
                      ((e && e.message) || e));
            claims = null;
          }
        }
        // #501: a handle has no '.'. The default realm is tried first, as
        // the JWT is, and the ambient realm only when that missed and the
        // request is under a realm prefix. The first miss is not counted.
        // A revoked row is refused here: the check below is "revoked OR
        // the account is disabled", and a revokedAt-only row would pass it.
        let opaqueAccess = false;
        if (!claims && String(presented).indexOf('.') < 0) {
          let found = realms.run(realms.get(realms.DEFAULT_ID),
            function () {
              return opaqueAccessToken.lookup(presented);
            });
          let heldRealm = realms.DEFAULT_ID;
          if (found.kind === 'unknown' &&
              realms.currentId() !== realms.DEFAULT_ID) {
            found = opaqueAccessToken.lookup(presented);
            heldRealm = realms.currentId();
          }
          if (found.kind === 'active' ||
              (found.kind === 'inactive' && found.why === 'expired')) {
            claims = found.claims;
            opaqueAccess = true;
            tokenRealm = heldRealm;
          } else if (found.kind === 'inactive' &&
                     found.why === 'revoked') {
            errorCodes.mark(res, 'STS-API-0122');
            res.set('WWW-Authenticate',
                    'Bearer error="invalid_token", scope="' +
                    scopesWanted + '"');
            return self.sendJson(res, 401, { error: 'invalid_token',
              errors: [
                'That access token has been revoked, or the account it ' +
                'was issued to is disabled.'] });
          } else if (found.kind === 'unknown') {
            const defIssues = realms.run(realms.get(realms.DEFAULT_ID),
              function () {
                return opaqueAccessToken.issuesOpaque();
              });
            const hereIssues = realms.currentId() === realms.DEFAULT_ID
              ? defIssues : opaqueAccessToken.issuesOpaque();
            if (defIssues || hereIssues) {
              const limited = hereIssues
                ? opaqueAccessToken.noteMiss(req)
                : realms.run(realms.get(realms.DEFAULT_ID), function () {
                    return opaqueAccessToken.noteMiss(req);
                  });
              if (limited) {
                res.set('Retry-After', String(limited.retryAfterS));
                res.set('WWW-Authenticate',
                        'Bearer error="invalid_token", scope="' +
                        scopesWanted + '"');
                errorCodes.mark(res, 'STS-OAUTH-0983');
                return self.sendJson(res, 429, { error: 'invalid_token',
                  errors: [
                    'Too many attempts. Wait ' + limited.retryAfterS +
                    ' seconds and try again.'] });
              }
              errorCodes.mark(res, 'STS-OAUTH-0980');
              res.set('WWW-Authenticate',
                      'Bearer error="invalid_token", scope="' +
                      scopesWanted + '"');
              return self.sendJson(res, 401, { error: 'invalid_token',
                errors: ['That access token is not valid.'] });
            }
          }
        }
        if (!claims) {
          errorCodes.mark(res, 'STS-API-0002');
          res.set('WWW-Authenticate',
                  'Bearer error="invalid_token", scope="' + scopesWanted + '"');
          return self.sendJson(res, 401, { error: 'invalid_token', errors: [
            'That access token was not issued by this service, or its ' +
            'signature does not verify. Tokens are ' +
            'signed with the key at /oauth2/jwks and ' +
            'that key is regenerated on every start in development mode.'] });
        }
        const now = Math.floor(Date.now() / 1000);
        if (claims.exp && Number(claims.exp) <= now) {
          errorCodes.mark(res, 'STS-API-0003');
          res.set('WWW-Authenticate',
                  'Bearer error="invalid_token", scope="' + scopesWanted + '"');
          return self.sendJson(res, 401, { error: 'invalid_token', errors: [
            'That access token expired at ' +
            new Date(Number(claims.exp) * 1000).toISOString() + '.'] });
        }
        // A TOKEN THIS SERVICE HAS SINCE REVOKED OR DISOWNED, AND ONE MADE FOR
        // A PERSON WHOSE ACCOUNT IS DISABLED (2026-09-17, #36 follow-up). This
        // gate checked neither, so an administrator's token went on working
        // until it expired after a global logout — or after their account was
        // disabled, which is the one case the disable exists for.
        // `invalid_token` for both: RFC 6750 section 3.1's "revoked".
        const { accountState } = self.deps;
        const person = String(claims.sub || '');
        if ((claims.jti && self.deps.stats.isRevoked(String(claims.jti))) ||
            (person && person !== String(claims.client_id || '') &&
             accountState.isDisabled(person))) {
          errorCodes.mark(res, 'STS-API-0122');
          res.set('WWW-Authenticate',
                  'Bearer error="invalid_token", scope="' + scopesWanted + '"');
          return self.sendJson(res, 401, { error: 'invalid_token', errors: [
            'That access token has been revoked, or the account it was ' +
            'issued to is disabled.'] });
        }
        // AND A TOKEN WHOSE SIGN-ON SESSION HAS ENDED (#446, 2026-10-05) —
        // see `endedSessionOf()`. `invalid_token`, as for a revoked one: to
        // the caller it is the same fact, a credential that stopped being
        // one, and the code says which.
        const endedSession = self.endedSessionOf(claims, tokenRealm);
        if (endedSession) {
          errorCodes.mark(res, 'STS-API-0126');
          res.set('WWW-Authenticate',
                  'Bearer error="invalid_token", scope="' + scopesWanted + '"');
          return self.sendJson(res, 401, { error: 'invalid_token', errors: [
            'That access token was issued on a sign-on session that has ' +
            'since ended, by a sign-out or by running out. Sign in again ' +
            'to be issued another.'] });
        }
        // RFC 9068 SECTION 4, STEPS 1 AND 3, in its order: the TYPE before the
        // issuer, and both before the audience. Every token this service signs
        // is signed with this key, so without the header an ID Token audienced
        // to a client named `…/admin-api` would be an administrative credential
        // here.
        // An opaque handle has no JOSE header (#501). Issuer and audience
        // below still run.
        if (!opaqueAccess) {
          const typ = jwtAccessToken.typOf(presented);
          if (!jwtAccessToken.isAccessTokenType(typ)) {
            errorCodes.mark(res, 'STS-API-0082');
            res.set('WWW-Authenticate', 'Bearer error="invalid_token", ' +
                    'scope="' + scopesWanted + '"');
            return self.sendJson(res, 401, { error: 'invalid_token',
              errors: [
                'RFC 9068 section 4: a JWT access token\'s typ header ' +
                'must be "at+jwt", and this token\'s is ' +
                (typ ? '"' + typ + '"' : 'absent') +
                '. An ID Token or a refresh token is not an access ' +
                'token, and a token minted before this service issued ' +
                'at+jwt is refused too; ask /oauth2/token for a new one.']
            });
          }
        }
        if (tokenRealm === realms.DEFAULT_ID ? !self.issuerAccepted(claims, req)
                                             : !self.realmIssuerAccepted(claims,
                                                 req)) {
          errorCodes.mark(res, 'STS-API-0083');
          res.set('WWW-Authenticate',
                  'Bearer error="invalid_token", scope="' + scopesWanted + '"');
          return self.sendJson(res, 401, { error: 'invalid_token', errors: [
            'RFC 9068 section 4: the iss claim must exactly match an issuer ' +
            'this service publishes, and this token names ' +
            JSON.stringify(claims.iss || null) +
            '. An issuer is an address, so ' +
            'a token minted under one host name is refused under another; ' +
            'mint it at the address you call this API at, or set ' +
            'global.publicBaseUrl.'] });
        }
        const audienceOk = tokenRealm === realms.DEFAULT_ID
          ? self.audienceAccepted(claims, req) :
            self.realmAudienceAccepted(claims, req);
        if (!audienceOk) {
          errorCodes.mark(res, 'STS-API-0004');
          return self.sendJson(res, 403, { error: 'forbidden', errors: [
            'That access token is for a different audience. It carries ' +
            JSON.stringify(claims.aud || null) + ' and this API answers to ' +
            self.wantedAudiences(req).map(function (aud) {
              return '"' + aud + '"';
            }).join(' or ') + '. A bearer token minted for another resource ' +
            'server must not be replayable here, which is what `aud` is ' +
            'for.'] });
        }
        // RFC 8705 SECTION 3.1 (2026-09-13). This gate verified a token's
        // signature, type, issuer and audience and never looked at
        // `cnf["x5t#S256"]`, so a certificate-bound administrative token was a
        // bearer token here — the one resource server in the service where
        // sender-constraining would matter most. 401 invalid_token, section 3's
        // answer. `true`: the signature was verified above.
        const certificateProblem = mtls.checkBinding(claims, req, true);
        if (certificateProblem) {
          errorCodes.mark(res, 'STS-API-0110');
          res.set('WWW-Authenticate',
                  'Bearer error="invalid_token", scope="' + scopesWanted + '"');
          return self.sendJson(res, 401, {
            error: 'invalid_token',
            errors: [certificateProblem.description] });
        }
        // ---------------------------------------------------------------------
        // AND A CLIENT THAT DECLARED A CERTIFICATE IS HELD TO ONE HERE (#1050,
        // rcbj's decision on #520: "bound tokens only, no bare certificate as
        // a credential"). The check above holds a token that IS bound; this
        // one refuses a token that is NOT, when the client it was issued to
        // declares `tls_client_auth`, `self_signed_tls_client_auth` (among
        // its methods) or `tls_client_certificate_bound_access_tokens` —
        // read NOW, in the realm that issued it, so a declaration added after
        // the token was minted takes it away. The token endpoint no longer
        // issues one (`oauth2.adminApiBindingRefusal()`, STS-OAUTH-0489/0490);
        // this is the other end, for a token issued before that rule, or
        // under a declaration since made, or by a door nobody has found. Its
        // scopes still decide what a bound token may do — this decides only
        // whether it is a credential here at all. In every mode: the client
        // asked for it.
        // ---------------------------------------------------------------------
        if (!mtls.boundThumbprintOf(claims)) {
          const holder = String(claims.client_id || '');
          const declaration = holder
            ? realms.run(realms.get(tokenRealm), function () {
                return mtls.certificateDeclaration(
                  applications.clientConfigOf(holder));
              })
            : '';
          if (declaration) {
            errorCodes.mark(res, 'STS-API-0137');
            res.set('WWW-Authenticate', 'Bearer error="invalid_token", ' +
                    'scope="' + scopesWanted + '"');
            return self.sendJson(res, 401, { error: 'invalid_token', errors: [
              'RFC 8705: client "' + holder + '" declares ' + declaration +
              ', so this API accepts its access tokens only bound to its ' +
              'TLS client certificate (cnf["x5t#S256"]), and this one is ' +
              'not bound. Ask /oauth2/token for a new one over mutual TLS ' +
              'and present it on a connection made with the same ' +
              'certificate.'] });
          }
        }
        // ---------------------------------------------------------------------
        // RFC 9449 SECTION 7, AND THE SAME HOLE ONE CONSTRAINT ALONG (#34,
        // 2026-09-15). The check above was added for RFC 8705 and the DPoP one
        // beside it was never written, so a token carrying `cnf.jkt` — a token
        // whose whole point is that holding it is not enough — was accepted
        // here as a bearer token. Every other resource server in this service
        // refuses that through `dpop.presentedAccessToken()`; this gate
        // verifies its own token and so has to ask for itself.
        //
        // It is NOT the two settings: this runs whatever they say, because it
        // is about honouring a constraint the TOKEN already carries.
        // ---------------------------------------------------------------------
        const boundJkt = dpop.jktOf(claims);
        let proofOk = false;
        if (boundJkt) {
          if (presentation.scheme !== 'dpop') {
            errorCodes.mark(res, 'STS-API-0120');
            res.set('WWW-Authenticate',
                    'DPoP error="invalid_token", scope="' + scopesWanted + '"');
            return self.sendJson(res, 401, { error: 'invalid_token', errors: [
              'That access token is DPoP-bound ' +
              '(it carries cnf.jkt), so it must ' +
              'be sent as "Authorization: DPoP <token>" with a DPoP proof — ' +
              'not ' +
              'as a Bearer token. Presenting it as a bearer token would ' +
              'throw the binding away.'] });
          }
          const checked = dpop.verifyProof(req.headers['dpop'], {
            htm: req.method, htu: dpop.htuOf(req), accessToken: presented,
            expectedJkt: boundJkt, req: req
          });
          if (!checked.ok) {
            errorCodes.mark(res, checked.errorCode || 'STS-API-0121');
            if (checked.needNonce) {
              res.set('DPoP-Nonce', dpop.issueNonce());
              res.set('WWW-Authenticate', 'DPoP error="use_dpop_nonce"');
            } else {
              res.set('WWW-Authenticate', 'DPoP error="invalid_dpop_proof", ' +
                                          'scope="' + scopesWanted + '"');
            }
            // error-code: none — marked above with the proof's own code, or
            // STS-API-0121 where it reported none.
            return self.sendJson(res, 401, { error: 'invalid_dpop_proof',
                                             errors: [checked.description] });
          }
          proofOk = true;
        }
        // #34's two settings, asked of this surface as of every other. The
        // answer is one function, so an operator who turns them on cannot find
        // that one door out of nine kept its own opinion.
        // #446: a token issued to the admin console as a PUBLIC client is
        // honoured only DPoP-bound — `senderConstraints` argues it. The
        // client's entry is read in the realm that issued the token, and
        // only for a client that rule names.
        const issuedTo = String(claims.client_id || '');
        const clientBound =
          senderConstraints.DPOP_BOUND_PUBLIC_CLIENTS.indexOf(issuedTo) >= 0 &&
          realms.run(realms.get(tokenRealm), function () {
            // The registry's client view, whose shape is its own.
            const entry: any = applications.clientConfigOf(issuedTo) || {};
            return senderConstraints.dpopBoundPublicClient(
              issuedTo, entry.token_endpoint_auth_method);
          });
        const required = senderConstraints.accessTokenRefusal({
          where: 'the management API',
          clientBound: clientBound,
          boundJkt: boundJkt,
          proofOk: proofOk,
          boundThumbprint: mtls.boundThumbprintOf(claims),
          certificate: !!mtls.peerCertificate(req),
          certificateMatches: !!mtls.boundThumbprintOf(claims) &&
                              mtls.peerVerified(req) &&
                              mtls.presentedThumbprint(req) ===
                                mtls.boundThumbprintOf(claims),
          mtlsAvailable: mtls.available()
        });
        if (required) {
          errorCodes.mark(res, required.errorCode);
          res.set('WWW-Authenticate',
                  (senderConstraints.accessTokenDpopRequired() ? 'DPoP' :
                   'Bearer') +
                  ' error="' + required.error + '", scope="' + scopesWanted +
                  '"');
          // error-code: none — marked above with the refusal's own code, one of
          // STS-OAUTH-0527 to 0531.
          return self.sendJson(res, 401, { error: required.error,
                                           errors: [required.description] });
        }
        const carried = String(claims.scope || '').split(/\s+/)
          .filter(Boolean);
        const who = String(claims.client_id || claims.sub || '(a client)');
        // THE CLIENT MUST STILL DECLARE WHAT THE TOKEN CARRIES (#110) — see
        // declaredAdminScopes(). 403 when the scope this operation needs is
        // one the client does not declare; an undeclared scope the operation
        // does not need is dropped and the call goes on.
        const declared = self.declaredAdminScopes(claims, tokenRealm, carried);
        // HELD ∩ CARRIED (#302, #303 — rcbj's decision 4 on #303). The roles
        // the token's subject — a person, or a client on client_credentials —
        // holds NOW, in the realm that issued the token, less any role whose
        // permissions the token does not carry. So a role revoked after the
        // token was minted stops working at once rather than when the token
        // expires, and a token carrying only admin:read is not Admin Write
        // because its subject happens to hold that too. The access-control
        // policy is unchanged: it still asks for ADMIN_READ or ADMIN_WRITE,
        // which are configured roles authorizing those scopes now rather
        // than the scopes themselves. See `common/role_permissions.ts`.
        const scopes = declared.kept;
        const effective = rolePermissions.effectiveRoles(claims, scopes,
                                                         tokenRealm);
        // ---------------------------------------------------------------------
        // AN OWNER'S TOKEN (#607). A token carrying `owner:read` or
        // `owner:write` and NOT the admin scope this operation needs is an
        // owner's question: the scope it uses is the owner one, and the
        // policy is asked the owner rule's question — which object, which
        // action, OWNER_READ or OWNER_WRITE — beside the administrator's.
        // Only for an operation an owner may ask (OWNER_OPERATIONS), and only
        // in the realm that issued the token: an owner's identity and the
        // object's owner values are DNs of ONE realm's directory, and the
        // same username in another realm is a different person. Anything
        // else is refused in so many words here (STS-API-0132), because the
        // policy's refusal would only say a role was missing.
        // ---------------------------------------------------------------------
        const ownerScope = req.method === 'GET' ? 'owner:read' : 'owner:write';
        // Never for a security change (#645): naming a policy on an object
        // you own is still naming a policy.
        const ownerPath = !mdmFeed && !consoleOp && !securityChange &&
          carried.indexOf(scopesWanted) < 0 &&
          carried.indexOf(ownerScope) >= 0;
        const owned = ownerPath ? self.ownedOperationOf(req) : null;
        if (ownerPath && (!owned || tokenRealm !== realms.currentId())) {
          errorCodes.mark(res, 'STS-API-0132');
          return self.sendJson(res, 403, { error: 'forbidden', errors: [
            'This access token carries ' + ownerScope + ' and not ' +
            scopesWanted + ', so it is an OWNER\'s token, and an owner\'s ' +
            'token reaches only the operations on one role, group, service ' +
            'account or application it names — GET ' + BASE + '/roles?role=, ' +
            '/groups?group=, /applications?application= or ' +
            '/service-accounts?account=, and POST ' + BASE + '/roles/{action}, ' +
            '/groups/{action}, /applications/{action} or /users/{action} ' +
            'naming the object' + (owned ? ', in the realm that issued the ' +
            'token' : '') + '. A list is not one: what you own is ' +
            '/account-api/owned/{kind}. ' + req.method + ' ' +
            (req.originalUrl || req.url) + ' is ' + (owned
              ? 'in another realm.' : 'not one of these.')] });
        }
        const neededScope = ownerPath ? ownerScope : scopesWanted;
        if (declared.undeclared.indexOf(neededScope) >= 0) {
          errorCodes.mark(res, 'STS-API-0123');
          return self.sendJson(res, 403, { error: 'forbidden', errors: [
            'This access token carries "' + neededScope + '", and the ' +
            'client it was issued to, ' +
            JSON.stringify(claims.client_id || null) + ', does not declare ' +
            'it: a token is honoured here only while its client still ' +
            'holds the scope it uses. ' + (mdmFeed
              ? 'Declare device:compliance on the MDM feed\'s ' +
                'application\'s oauthAllowedScope.'
              : 'An admin or owner scope is held by a delegated permission ' +
                'grant on sts-management-api (#1141): give the client a ' +
                'delegated permission grant of ' +
                'urn:sts:admin-api:' + neededScope + ' (POST ' +
                '/admin-api/permissions/grant-permission), or use ' +
                'sts-api-client, which holds delegated permission grants of ' +
                'admin:read and ' +
                'admin:write.')] });
        }
        if (effective.withdrawn.indexOf(neededScope) >= 0) {
          errorCodes.mark(res, 'STS-API-0125');
          return self.sendJson(res, 403, { error: 'forbidden', errors: [
            'This access token carries "' + neededScope + '", and its ' +
            'subject no longer holds a role authorizing it: ' +
            effective.why + '. A token is honoured here only while its ' +
            'subject\'s roles authorize the scope it uses. ' +
            // THE ROLE THAT AUTHORIZES IT, and where it is granted: a
            // person's console role on the roster, anything else on the
            // role itself (#309: device:compliance is DEVICE_COMPLIANCE's).
            (ownerPath
              ? 'An owner\'s scope is authorized by owning something in ' +
                'the realm that issued the token: be named an owner of a ' +
                'role, group, service account or application there'
              : effective.subject.kind !== 'application' &&
             neededScope !== 'device:compliance'
              ? 'Grant the console role on /admin/rbac (or POST ' +
                '/admin-api/rbac/grant)'
              : 'Add the ' + (effective.subject.kind === 'application'
                  ? 'application' : 'person') + ' to ' +
                (neededScope === 'device:compliance' ? 'DEVICE_COMPLIANCE'
                  : (neededScope === 'admin:read' ? 'ADMIN_READ'
                    : (neededScope === 'admin:security' ? 'SECURITY_ADMIN'
                                                        : 'ADMIN_WRITE'))) +
                ' on /admin/roles (or POST /admin-api/roles/add-member)') +
            ' and ask for a new token.'] });
        }
        // ---------------------------------------------------------------------
        // A SECURITY CHANGE WITHOUT THE SECURITY ADMINISTRATOR (#645), refused
        // HERE and not only by the access-control policy below: with
        // `xacml.enforceAccess` off that policy allows everything, and the
        // separation must not be one setting away from gone. The token must
        // carry `admin:security` and its subject hold SECURITY_ADMIN now
        // (held ∩ carried, above).
        // ---------------------------------------------------------------------
        if (securityChange &&
            (scopes.indexOf('admin:security') < 0 ||
             effective.roles.indexOf('SECURITY_ADMIN') < 0)) {
          log.info('admin-api: refusing ' + req.method + ' ' +
                   (req.originalUrl || req.url) + ' for ' + who + ': ' +
                   securityChange.detail + '.');
          errorCodes.mark(res, 'STS-API-0138');
          return self.sendJson(res, 403, { error: 'forbidden', errors: [
            'Only a Security Administrator may make this change: ' +
            securityChange.detail + '. It needs a token carrying ' +
            'admin:security whose subject holds SECURITY_ADMIN — Admin ' +
            'Write does not reach it. This token carries ' +
            (scopes.length ? scopes.join(', ') : '(no scope)') + '. A ' +
            'Security Administrator grants the role on /admin/rbac (POST ' +
            BASE + '/rbac/grant with role=security).'] });
        }
        if (tokenRealm !== realms.DEFAULT_ID) {
          const realmRefusal = self.realmTokenRefusal(claims, req);
          if (realmRefusal) {
            errorCodes.mark(res, realmRefusal.code);
            // error-code: none — the code is realmRefusal.code, marked above
            return self.sendJson(res, 403, { error: 'forbidden',
                                             errors: [realmRefusal.detail] });
          }
          // SAID ON THE RESPONSE (#49): a realm's own token is that realm's
          // administrator, and a view that shows several realms' rows — the
          // scheduler's — confines itself by this, as it does by a realm
          // administrator's console session.
          res.locals.realmTokenOf = tokenRealm;
        }
        // A CONSOLE OPERATION ASKED WITH A TOKEN THAT IS NOT THE CONSOLE'S
        // (#454): said in so many words, because the policy's refusal would
        // only say a role was missing, and the caller holding Admin Read
        // would not see why that is not enough.
        if (consoleOp && carried.indexOf('admin:console') < 0) {
          errorCodes.mark(res, 'STS-API-0127');
          return self.sendJson(res, 403, { error: 'forbidden', errors: [
            'This is one of the admin console\'s own operations, under ' +
            BASE + '/console: they draw the console and are not part of ' +
            'the management API a client relies on (' + BASE +
            '/openapi.json describes that). They take admin:console, which ' +
            'is issued only to the console\'s client, sts-admin-console, ' +
            'and this token does not carry it. A console client entry ' +
            'seeded before #454 declares no admin:console: add it to the ' +
            'entry\'s oauthAllowedScope and oauthGlobalConsent (POST ' +
            BASE + '/applications/add) and sign in again.'] });
        }
        const held = effective.roles;
        // WHAT THE OPERATION REQUIRES, IN TWO PARTS (#454). `requiredRoles`
        // is any-one-of, as the access-control document has always read it;
        // `requiredAllRoles` is every-one-of, a conjunct beside it, which is
        // what lets one decision mix a role the person holds with one the
        // console's client confers. A console operation needs ADMIN_CONSOLE
        // and — unless it is the frame or the operation list, which show no
        // realm data and are what a person with no console role still needs
        // to be told so — ADMIN_READ for a read or ADMIN_WRITE for a form
        // helper. `/me` is either kind's: who-am-I is the console's first
        // question and an integrator's.
        const path = String(req.path || '').replace(/\/+$/, '');
        // `/console/language` (#539) is the caller's own preferredLanguage,
        // and shows no realm data: the frame's terms.
        const frameOnly = path === '/console' ||
          path === '/console/operations' || path === '/console/language';
        const requiredRoles = mdmFeed ? ['DEVICE_COMPLIANCE']
          : (consoleOp ? ['ADMIN_CONSOLE']
            : (path === '/me' ? ['ADMIN_READ', 'ADMIN_CONSOLE']
              : (securityChange ? ['SECURITY_ADMIN']
                : (req.method === 'GET' ? ['ADMIN_READ'] : ['ADMIN_WRITE']))));
        const requiredAllRoles = consoleOp && !frameOnly
          ? [req.method === 'GET' ? 'ADMIN_READ' : 'ADMIN_WRITE'] : [];
        // THE OWNER RULE'S QUESTION (#607), on an owner's token: the object,
        // the action, the attributes it writes, the person, and the owner
        // role it needs. The administrator's requirement above is still
        // asked, so the first rule decides exactly as before and the second
        // can only add an owner.
        const ownedObject = owned ? {
          kind: owned.kind, id: owned.id, action: owned.action,
          attributes: owned.attributes,
          requiredRole: req.method === 'GET' ? 'OWNER_READ' : 'OWNER_WRITE',
          person: String(effective.subject.name || '')
        } : null;
        const policy = accessGate.check({
          resource: accessGate.RESOURCE.MANAGEMENT_API,
          action: req.method === 'GET' ? accessGate.ACTION.READ
                                       : accessGate.ACTION.WRITE,
          ownedObject: ownedObject,
          // THE REQUIREMENT IS STATED HERE AND ENFORCED THERE. `requiredRoles`
          // travels in the REQUEST — the `access-control` document is written
          // to take it from there, which is what lets one policy decide for
          // every surface — so naming the role per action is the whole of
          // encoding "a read needs ADMIN_READ and a write needs ADMIN_WRITE" in
          // XACML. Nothing in this file decides the outcome; it decides the
          // question.
          requiredRoles: requiredRoles,
          requiredAllRoles: requiredAllRoles,
          subject: { name: who, authenticated: true, roles: held,
                     sessionId: null },
          context: { method: req.method, path: req.originalUrl || req.url }
        });
        if (!policy.allowed && ownedObject) {
          log.info('admin-api: the access policy\'s owner rule refused ' +
                   req.method + ' ' + (req.originalUrl || req.url) + ' for ' +
                   ownedObject.person + '. ' + policy.why);
          errorCodes.mark(res, 'STS-API-0133');
          return self.sendJson(res, 403, { error: 'forbidden', errors: [
            'The access policy\'s owner rule refused this request. An owner ' +
            'may ' + (req.method === 'GET' ? 'read' : 'change') + ' the ' +
            ownedObject.kind + ' "' + ownedObject.id + '" only when it ' +
            'names them, or a group they are in, as an owner; when it is ' +
            'not closed to its owners (a native or protected role, a group ' +
            'or application this service grants through, or one an ' +
            'administrator closed); when "' + ownedObject.action + '" is ' +
            'an action its kind allows an owner' +
            (ownedObject.attributes.length ? ', and every attribute it ' +
              'writes (' + ownedObject.attributes.join(', ') + ') is one an ' +
              'owner may write' : '') +
            '; and never to take its last owner off. ' + policy.why] });
        }
        if (!policy.allowed) {
          log.info('admin-api: the access policy refused ' + req.method + ' ' +
                   (req.originalUrl || req.url) + ' for ' + who + '. ' +
                   policy.why);
          errorCodes.mark(res, 'STS-API-0005');
          return self.sendJson(res, 403, { error: 'forbidden', errors: [
            'The access policy refused this request. ' + policy.why +
            ' This token carries the scope(s) ' +
            (scopes.length ? scopes.join(', ') : '(none)') + ', which is the ' +
            'role(s) ' + (held.length ? held.join(', ') : '(none)') + '. ' +
            (mdmFeed ? 'The device compliance feed needs device:compliance ' +
                       '(DEVICE_COMPLIANCE), and only that'
              : (consoleOp
                ? 'A console operation needs admin:console (ADMIN_CONSOLE)' +
                  (requiredAllRoles.length ? ' and ' +
                    (req.method === 'GET' ? 'admin:read (ADMIN_READ)'
                                          : 'admin:write (ADMIN_WRITE)') : '')
                : (securityChange
                  ? 'This change needs admin:security (SECURITY_ADMIN)'
                  : 'A ' + (req.method === 'GET'
                    ? 'read needs admin:read (ADMIN_READ)'
                    : 'write needs admin:write (ADMIN_WRITE)')))) +
            '. The document is on /admin/xacml and xacml.enforceAccess turns ' +
            'the layer off.'] });
        }
        // WHO CALLED, for an operation that records its caller (#164: the
        // MDM feed's reports name the feed's client).
        res.locals.apiClientId = String(claims.client_id || '');
        // AND THE SUBJECT, WHICH IS THE AUDIT ACTOR (#446, 2026-10-05). Until
        // then every row this API wrote named nobody — "this API
        // authenticates a CLIENT rather than a person" — which was true while
        // the only tokens it saw were `client_credentials` ones. The console
        // is becoming a client of this API that presents the signed-in
        // PERSON's token, so the subject the gate has just verified, and
        // decided the roles of, is who did it: a person's name, or the
        // client's id on `client_credentials`. Read by `callerNameOf()`, by
        // the route wrapper (which hands it to every action as `actor`) and
        // by `common/audit.js`'s HTTP row.
        res.locals.apiCaller = {
          kind: effective.subject.kind === 'application' ? 'application'
                                                         : 'person',
          name: String(effective.subject.name || ''),
          // The token's own subject (#945), which an administrator's
          // passkey enrolment records beside the name.
          sub: String(claims.sub || ''),
          // When this person last authenticated, for `refuseStaleSignIn()`.
          authTime: Number(claims.auth_time) || 0,
          clientId: String(claims.client_id || ''),
          realm: tokenRealm,
          // What the decision above was made on, for `GET /admin-api/me`:
          // the scopes the token carries that its client still declares,
          // the roles its subject holds now that those scopes carry, and
          // when the token stops being accepted.
          scopes: scopes.slice(0),
          roles: held.slice(0),
          expiresAt: claims.exp ? Number(claims.exp) : null
        };
        // ON THE REQUEST TOO (#446): the views a page is drawn from ask
        // `adminViews.gateStateFor(req)` who is looking — a realm
        // administrator's view leaves out what belongs to the service — and
        // that read the console's own session. The static console has none;
        // its token is the session, so the caller this gate verified is
        // who they are asked about.
        req.adminApiCaller = res.locals.apiCaller;
        // WHAT AN OWNER IS ANSWERED (#607): a read whose answer carries more
        // than the one object — the role register around one role — is
        // narrowed to it in `sendJson()`.
        if (owned && owned.project) {
          res.locals.ownerProjection = owned.project;
        }
        res.locals.apiCaller.owner = !!owned;
        return next();
      }
      // ---------------------------------------------------------------------
      // THE SETTING IS OFF, WHICH ONLY DEVELOPMENT MODE CAN BE (#446,
      // 2026-10-05): `tokenRequired()` reads it as the mode lets it be, and
      // product reads `false` as `true`. So this line is the open API of
      // development — what a test drives, and the way back in when nobody
      // can mint a token — and nothing else reaches it.
      //
      // UNTIL #446 PRODUCT FELL BACK, HERE, TO THE CONSOLE'S SESSION AND ITS
      // TWO ROLES (#411; STS-API-0006, 0007 and 0008, all retired). The
      // console is becoming a static application that calls this API with
      // the signed-in person's own token, so there is no console session to
      // fall back to, and a setting that opened this gate would open the
      // console with it. `common/mode.js`'s `opensManagementApi()` argues it.
      // ---------------------------------------------------------------------
      return next();
    });
    log.debug("Leaving AdminApi.registerGate().");
  }

  // THE TABLE'S ROUTES, registered by the exported `registerRoutes(app)`
  // straight after the gate, which `common/protocol_stack.ts` calls at 19
  // (#50, R1). `compileRequestSchemas()` has already run, in `wire()`.
  /**
   * Registers the route table's operations, one express route per row, with the
   * request body and query checks in front of each handler.
   *
   * @param app - the express app
   */
  registerRoutes(app: RouteApp): void {
    const { log, errorCodes, protocolEndpoints, closedSets } = this.deps;
    const self = this;
    log.debug("Entering AdminApi.registerRoutes().");
    // -------------------------------------------------------------------------
    // REGISTRATION IS THE CHOKE POINT, and it has to be: there is no generic
    // dispatcher here. Every handler in the table above reads its own body with
    // `parseBody(req)` and refuses in its own words, so a check written inside
    // them would be one check per operation and the next operation's would be
    // forgotten. Here it is one wrapper, driven by the same table the
    // OpenAPI document is built from, so an operation cannot acquire a schema
    // without acquiring its enforcement.
    //
    // A query string's SHAPE is `common/validation.js`'s guard and the
    // per-page schemas; what goes through here is only its closed sets — a
    // parameter whose declared `enum` does not hold the value (#86).
    // -------------------------------------------------------------------------
    ROUTES.forEach(function (entry) {
      const path = entry.route || entry.path;
      // WHICH OPERATION'S PROSE THE ANSWER CARRIES (#543): the route, or for
      // a console twin the route it mirrors. `sendJson()` hands it to
      // `common/server_prose.ts`, whose sources name the operations their
      // sentences are answered by.
      const proseRoute = entry.proseRoute || path;
      // A query parameter outside its declared set is refused before the
      // handler runs, on a GET and a POST alike (#86).
      // THE REST OF THE QUERY, AND THE HEADERS (#1476): a name the operation
      // does not declare, a value its declared type does not hold, and a
      // custom header nobody defined are each refused, because answering
      // 200 with the question ignored tells the caller it was understood.
      const queryRefused = function (req, res) {
        const asked = self.checkQueryEnums(entry, req);
        if (!asked.ok) {
          log.debug("The management API refused a query parameter against " +
                    (entry.operationId || path) + "'s declared set.");
          errorCodes.mark(res, 'STS-API-0124');
          self.sendJson(res, 400, { ok: false, errors: [asked.sentence] });
          return true;
        }
        const shape = closedSets.checkQueryDeclared(
          self.parametersOf(entry, req), req.query);
        if (!shape.ok) {
          log.debug("The management API refused a query parameter of " +
                    (entry.operationId || path) + ": " + shape.problem + ".");
          if (shape.problem === 'unknown') {
            errorCodes.mark(res, 'STS-API-0142');
          } else {
            errorCodes.mark(res, 'STS-API-0143');
          }
          self.sendJson(res, 400, { ok: false, errors: [shape.sentence] });
          return true;
        }
        const headers = adminApiRequestHeaders.check(
          self.parametersOf(entry, req), req.headers);
        if (!headers.ok) {
          log.debug("The management API refused a request header on " +
                    (entry.operationId || path) + ".");
          errorCodes.mark(res, 'STS-API-0144');
          self.sendJson(res, 400, { ok: false, errors: [headers.sentence] });
          return true;
        }
        return false;
      };
      // A MANAGEMENT ANSWER WITH A CONSOLE TWIN (#454) leaves the console's
      // members out, and refuses the twin's drawing rather than answering
      // it: `format=svg` is the console's.
      const consoleOnly = function (req, res) {
        if (!entry.consoleMembers) {
          return false;
        }
        res.locals.consoleMembers = entry.consoleMembers;
        if (String((req.query || {}).format || '') !== 'svg') {
          return false;
        }
        errorCodes.mark(res, 'STS-API-0129');
        self.sendJson(res, 400, { ok: false, errors: [
          'The drawing is the admin console\'s: ask ' + entry.consoleTwin +
          '?format=svg. This operation answers the data alone.'] });
        return true;
      };
      if (entry.method === 'GET') {
        // A GET that `mirrors` exactly one Protocols page answers that page's
        // endpoints as well, which is rule 7 for the section `respond()` draws
        // there. `mirrors` is the join because it is already the column that
        // says which page an operation is the machine's door to; one naming two
        // pages is not a mirror of either and gets nothing.
        const mirrored = /^GET (\/admin\S*)$/.exec(String(entry.mirrors || ''));
        const page = mirrored &&
                     protocolEndpoints.pages().indexOf(mirrored[1]) >= 0 ?
                     mirrored[1] : null;
        if (!page) {
          app.get(path, function (req, res) {
            res.locals.proseRoute = proseRoute;
            if (consoleOnly(req, res) || queryRefused(req, res)) {
              return undefined;
            }
            return entry.handler(req, res);
          });
          return;
        }
        app.get(path, function (req, res) {
          res.locals.proseRoute = proseRoute;
          if (consoleOnly(req, res) || queryRefused(req, res)) {
            return undefined;
          }
          res.locals.protocolEndpoints = protocolEndpoints.forPage(req, page);
          return entry.handler(req, res);
        });
        return;
      }
      app.post(path, function (req, res) {
        res.locals.proseRoute = proseRoute;
        if (queryRefused(req, res)) {
          return undefined;
        }
        // A FORM HELPER ASKED AT ITS OLD ADDRESS (#454): the action is the
        // console's now, under `/admin-api/console`. Refused rather than
        // answered, or the one handler behind both routes would carry it out
        // and the move would be a second door.
        const asked = String((req.params && req.params.action) || '');
        if ((entry.consoleActions || []).indexOf(asked) >= 0) {
          errorCodes.mark(res, 'STS-API-0128');
          self.sendJson(res, 404, { ok: false, errors: [
            '"' + asked + '" is a form helper of the admin console, at ' +
            path.replace(BASE, BASE + '/console').replace(':action', asked) +
            '. It writes nothing; the act it leads to is an operation ' +
            'here.'] });
          return undefined;
        }
        // AN UNKNOWN ACTION WHERE THE HELPERS LEFT (#454): the handler's
        // refusal names every action it carries out, helpers included, and
        // that sentence is what tests/protocol/admin_api.js reads for the
        // parity — so on the management address it would name four actions
        // the document no longer declares there. The sentence is built here
        // from what this address still declares, in the handler's shape.
        if (entry.consoleActions && asked && !(entry.actions || []).some(
            function (one) {
              return one.action === asked;
            })) {
          const known = entry.actions.map(function (one) {
            return one.action;
          });
          errorCodes.mark(res, 'STS-API-0130');
          self.sendJson(res, 400, { ok: false, errors: [
            'Unknown action "' + asked + '". The ' +
            helpers.numberWord(known.length) + ' are: ' +
            known.join(', ') + '.'] });
          return undefined;
        }
        // The route this request matched, so the wrapper can find its schema
        // without re-deriving the path from what express matched.
        req.__adminApiRoute = path;
        req.__adminApiHandlerOwnsBody = !!entry.handlerOwnsBody;
        const checked = self.checkRequestBody(req);
        if (!checked.ok) {
          log.debug("The management API refused a request body against " +
                    (entry.operationId || path) + "'s schema.");
          errorCodes.mark(res, 'STS-API-0009');
          self.sendJson(res, 400, { ok: false, errors: checked.errors });
          return undefined;
        }
        // WHO IS ACTING is not put into the body: each handler hands its
        // action `callerNameOf(res)` in the action's context (rcbj on #1579,
        // 2026-11-11), and a caller's own `actor` is refused by the closed
        // schema above like any member the model does not declare.
        return entry.handler(req, res);
      });
    });
    log.debug("Leaving AdminApi.registerRoutes().");
  }
}

// Compiled on first use (#617; `validatorFor()`), keyed by the operation the
// request will reach, from the schemas `compileRequestSchemas()` records. A
// schema that will not compile is a MAINTAINER's mistake rather than a
// caller's, so it is logged loudly and that operation is left unvalidated
// rather than refusing every request — the same judgement `ldap_server.js`
// makes about a listener that will not bind.
const validators = new Map();
const validatorSources = new Map();
// The one `{ schemas: structureOnly(spec.SCHEMAS) }` every validator's root
// points at (#365), made with the first validator compiled.
let sharedComponents: any = null;
import docs = require('./admin_api_docs');
// `docs` is required for its place in the require order and nothing of it is
// read here; this reference keeps TypeScript from eliding the require.
void docs;
// The trust realm this call arrived in — for the gate at the foot of this
// file, which verifies a service token under the DEFAULT realm's key and a
// realm's own token under that realm's, and for the realm list's key sets.
// (It was first required for the explorer, which moved to the console on
// 2026-09-09; `docs` above is no longer read in this file.)
import realms = require('../common/realms');
// What request headers this API takes (#1476). A leaf that registers nothing.
import adminApiRequestHeaders = require('../common/request_headers');
// RFC 9068 (2026-09-13): what an access token's type and issuer must be, read
// the way the other resource servers here read them. A library that registers
// no route; `oauth2.js` already required it, so this is a cache hit.
import jwtAccessToken = require('../oauth-oidc/jwt_access_token');
// Opaque access tokens (#501). A library oauth2 already required, so this
// is a cache hit. The gate calls it directly: the token check is not a
// dependency a test's stand-in deps object has to grow.
import opaqueAccessToken = require('../oauth-oidc/opaque_access_token');
// RFC 8705 section 3.1 (2026-09-13): a certificate-bound access token is
// usable only on a connection made with its certificate — the check every
// other resource server here makes through `dpop.presentedAccessToken()`. A
// library that registers nothing; `oauth2.js` already required it.
import mtls = require('../oauth-oidc/mtls');
// RFC 9449 (#34, 2026-09-15): this gate never looked at `cnf.jkt`, so a
// DPoP-bound token was usable here as a plain Bearer token — the hole RFC 8705
// had closed above and this one had not. Both libraries register nothing and
// `oauth2.js` has already required them, so these are cache hits.
import dpop = require('../oauth-oidc/dpop');
import senderConstraints = require('../oauth-oidc/sender_constraints');
// THE VERSION, M.N.O. A LEAF (rule 3): registers nothing and requires nothing
// from this repository, so it cannot move a route or join a cycle.
//
// **IT USED TO BE `require('../package.json').version`**, which was M.N.0 — the
// manifest's placeholder patch while the version carried a build number.
// package.json carries the release, M.N.O, since #1298; the version this
// module answers is that release followed by the build number (#1317), which
// package.json has nowhere to put, so the module stays the one source. See
// common/version.js.
import version = require('../common/version');
const APP_VERSION = version.load();
const VERSION = APP_VERSION.version;

/**
 * The management API's base path.
 */
const BASE = '/admin-api';
// The device compliance feed's path below BASE (#164 phase 3): the one
// operation whose token carries device:compliance rather than an admin scope.
const DEVICE_COMPLIANCE_PATH = '/device-compliance';
// ---------------------------------------------------------------------------
// THE OPERATIONS AN OWNER MAY ASK (#607), below BASE: one object of the four
// kinds a person may own, read or changed. `ownedOperationOf()` reads a
// request against this table; a request it does not find is not an owner's
// question, and a token carrying only the owner scopes is refused there
// (STS-API-0132) rather than asked. WHICH of these an owner may take, on
// which object, is the access-control policy's owner rule — never this
// table, which only names the object the request reaches.
//
//   kind      what the policy's urn:sts:xacml:object-kind says
//   path      the path below BASE, or a pattern whose group is the action
//   target    how the request names the object: a query parameter for a
//             read, a body member for an act
//   project   for a read whose answer carries more than the one object:
//             what of it an owner is answered
//
// A READ needs its target: `GET /roles` with no `role` is the whole register,
// a list, and lists are refused to an owner (rcbj's decision 6) — the portal
// lists through `/account-api/owned/*`.
// ---------------------------------------------------------------------------
interface OwnerOperation {
  method: string;
  kind: string;
  path?: string;
  pattern?: RegExp;
  target: (query: any, body: any) => string;
  project?: (answer: any) => any;
}
// The application attributes an owner's read answers: the access-control
// template's default `ownerApplicationAttributes`, which are what the portal
// draws a form for. A realm whose policy lists fewer refuses the write.
const OWNER_APPLICATION_FIELDS = ['appName', 'appHomePageUrl', 'appCorsOrigin',
  'oauthRedirectUri', 'oauthPostLogoutRedirectUri',
  'oauthFrontchannelLogoutUri', 'oauthBackchannelLogoutUri',
  'samlAssertionConsumerService', 'samlSingleLogoutService',
  // #1296: the token response types the owner may enable.
  'oauthAllowedTokenResponseTypes'];
const OWNER_OPERATIONS: OwnerOperation[] = [
  { method: 'GET', kind: 'role', path: '/roles',
    target: function target(query) {
      log.debug("Entering target().");
      log.debug("Leaving target().");
      return String(query.role || '');
    },
    project: function project(answer) {
      log.debug("Entering project().");
      log.debug("Leaving project().");
      return { role: answer && answer.role };
    } },
  // The group alone: the drill-down's answer also carries every group in
  // the realm (the list the console draws beside it).
  { method: 'GET', kind: 'group', path: '/groups',
    target: function target(query) {
      log.debug("Entering target().");
      log.debug("Leaving target().");
      return String(query.group || '');
    },
    project: function project(answer) {
      log.debug("Entering project().");
      const group = (answer && answer.group) || null;
      log.debug("Leaving project().");
      return { found: !!(answer && answer.found), group: group && {
        dn: group.dn, cn: group.cn, description: group.description,
        members: group.members, memberCount: group.memberCount,
        owners: group.owners, maxOwners: group.maxOwners },
        membersPaging: answer && answer.membersPaging };
    } },
  // The application's own facts and the attributes an owner may write: the
  // drill-down's answer also carries what the console draws its tabs from —
  // other applications' permissions among them.
  { method: 'GET', kind: 'application', path: '/applications',
    target: function target(query) {
      log.debug("Entering target().");
      log.debug("Leaving target().");
      return String(query.application || '');
    },
    project: function project(answer) {
      log.debug("Entering project().");
      const a = answer || {};
      const fields: Record<string, unknown> = {};
      OWNER_APPLICATION_FIELDS.forEach(function (name) {
        if (a.fields && a.fields[name] !== undefined) {
          fields[name] = a.fields[name];
        }
      });
      log.debug("Leaving project().");
      return { found: !!a.found, identifier: a.identifier, name: a.name,
               description: a.description, kinds: a.kinds,
               protocols: a.protocols, fields: fields,
               owners: (a.page && a.page.owners) || [],
               maxOwners: a.page && a.page.maxOwners };
    } },
  { method: 'GET', kind: 'service-account', path: '/service-accounts',
    target: function target(query) {
      log.debug("Entering target().");
      log.debug("Leaving target().");
      return String(query.account || '');
    } },
  { method: 'POST', kind: 'role', pattern: /^\/roles\/([a-z][a-z-]*)$/,
    target: function target(query, body) {
      log.debug("Entering target().");
      log.debug("Leaving target().");
      return String(body.role || '');
    } },
  { method: 'POST', kind: 'group', pattern: /^\/groups\/([a-z][a-z-]*)$/,
    target: function target(query, body) {
      log.debug("Entering target().");
      log.debug("Leaving target().");
      return String(body.group || '');
    } },
  { method: 'POST', kind: 'application',
    pattern: /^\/applications\/([a-z][a-z-]*)$/,
    target: function target(query, body) {
      log.debug("Entering target().");
      log.debug("Leaving target().");
      return String(body.application || '');
    } },
  // AN APPLICATION'S UMA DOCUMENT (#1195): the owner tab of /admin/uma,
  // read with `?owner=` and answered with that tab alone (the page's other
  // lists are every resource server's), and its four owner-* acts. The
  // object is the application, so `ownerApplicationActions` decides them.
  { method: 'GET', kind: 'application', path: '/uma',
    target: function target(query) {
      log.debug("Entering target().");
      log.debug("Leaving target().");
      return String(query.owner || '');
    },
    project: function project(answer) {
      log.debug("Entering project().");
      log.debug("Leaving project().");
      return { owner: (answer && answer.owner) || null };
    } },
  { method: 'POST', kind: 'application',
    pattern: /^\/uma\/(owner-[a-z-]*)$/,
    target: function target(query, body) {
      log.debug("Entering target().");
      log.debug("Leaving target().");
      return String(body.owner || '');
    } },
  { method: 'POST', kind: 'service-account',
    pattern: /^\/users\/([a-z][a-z-]*)$/,
    target: function target(query, body) {
      log.debug("Entering target().");
      log.debug("Leaving target().");
      return String(body.user || body.username || '');
    } }
];
// THE ACCESS GATE, armed by `xacml/xacml_access_pep.ts` at 23c. A LEAF
// (rule 3): with no decider installed `check()` answers "allowed", so a
// process without the XACML family behaves exactly as this file did before.
import accessGate = require('../common/access_gate');
// The mode. A LEAF (rule 3): registers nothing, requires only `config`.
import mode = require('../common/mode');
// THE AUTHORIZATION SERVER, for the one question the gate asks it (#446):
// whether the sign-on session a token was issued on is still live. Built at
// 9 and this module at 19, so this is a cache hit that moves nothing; since
// #50's R1 a require of a converted module registers no route either.
import oauth2 = require('../oauth-oidc/oauth2');
import InstanceSlot = require('../common/instance_slot');

// ---------------------------------------------------------------------------
// THE SEVEN ACTIONS OF A CLAIM SET, FOR WHICHEVER FAMILY OF SETS ASKED.
//
// The console has THREE areas onto one store since 2026-08-26 — /admin/claims
// for the two JWT sets, /admin/userinfo-claims for the UserInfo one and the
// Custom SAML attributes tab on /admin/saml2 — so this API has three action
// resources, and rule 7 means each needs an operation per action. That is
// twenty-one operations describing seven behaviours, and the one thing that
// must not happen is twenty-one DESCRIPTIONS: the copy that is not edited
// beside the others is the one a caller believes, and a document that disagreed
// with itself about whether an empty `attributes` clears a set would be worse
// than one that said nothing.
//
// So the rows are built once, here, and the family is what varies:
//
//   * WHICH SET IDS the `enum` offers — which is the same restriction
//     claimsAction()'s `allowed` argument enforces on the way in, so a caller
//     reading this document cannot construct a call the service will refuse.
//   * THE NOUN. A JWT set carries claims and a SAML set carries attributes,
//     which is what each protocol's own readers call them.
//   * THE RESERVED-NAMES RULE, which is a JWT rule and only a JWT rule:
//     setClaimSet() checks it for `kind === 'jwt'`, because an assertion
//     attribute called `exp` collides with nothing. Documenting it on the SAML
//     operations would tell a caller their call will be refused when it will
//     succeed.
//
// operationIds cannot collide — a generated client would have two methods of
// one name — so each family carries its own, spelled out rather than derived
// from a suffix, because `addClaim` and `addSamlAttribute` are what a caller
// would guess and `addClaim2` is what a suffix would produce.
// ---------------------------------------------------------------------------
const JWT_CLAIM_FAMILY = {
  sets: stats.JWT_CLAIM_SET_IDS,
  noun: 'claim',
  carrier: 'token',
  example: 'id_token',
  placeholder: '${username}',
  reserved: true,
  ids: { add: 'addClaim', addAttribute: 'addAttributeClaim',
         remove: 'removeClaim', clear: 'clearClaims',
         replace: 'replaceClaims', attributes: 'setClaimAttributes',
         all: 'selectAllClaimAttributes',
         none: 'clearClaimAttributes' } as const
};

// The third family, and the one that made the two above it a PATTERN rather
// than a pair. Nothing in claimSetActions() changed to add it — which is the
// test that the parameterisation was real: `sets`, `noun`, `carrier`,
// `example`, `reserved` and the operationIds were the whole of what varied
// between the first two, and they were the whole of what varied for the third.
//
// `reserved: true` is the one row a reader coming from SAML_CLAIM_FAMILY would
// get wrong. The reserved list is not a JWT rule with a JWT exception — it is
// the rule "this artefact has names this service sets itself", and a UserInfo
// response has them: `sub` is required by OIDC Core 5.3.2 and a client MUST
// check it against the ID Token's, and the SIGNED form of the same response is
// a JWT carrying `iss`, `aud` and `exp`. admin_stats.js's reservedNames() is
// where that is decided, once, for every door onto the store.
const USERINFO_CLAIM_FAMILY = {
  sets: stats.USERINFO_CLAIM_SET_IDS,
  noun: 'claim',
  carrier: 'UserInfo response',
  example: 'userinfo',
  placeholder: '${username}',
  reserved: true,
  ids: { add: 'addUserInfoClaim',
         addAttribute: 'addUserInfoAttributeClaim',
         remove: 'removeUserInfoClaim',
         clear: 'clearUserInfoClaims', replace: 'replaceUserInfoClaims',
         attributes: 'setUserInfoClaimAttributes',
         all: 'selectAllUserInfoClaimAttributes',
         none: 'clearUserInfoClaimAttributes' } as const
};

const SAML_CLAIM_FAMILY = {
  sets: stats.SAML_CLAIM_SET_IDS,
  noun: 'attribute',
  carrier: 'assertion',
  example: 'saml11',
  // A SAML attribute's context is `{ subject, audience }` (saml/CLAUDE.md),
  // so `${username}` would reach the assertion as written (#287).
  placeholder: '${subject}',
  reserved: false,
  ids: { add: 'addSamlAttribute',
         addAttribute: 'addSamlDirectoryAttributeClaim',
         remove: 'removeSamlAttribute',
         clear: 'clearSamlAttributes', replace: 'replaceSamlAttributes',
         attributes: 'setSamlDirectoryAttributes',
         all: 'selectAllSamlDirectoryAttributes',
         none: 'clearSamlDirectoryAttributes' } as const
};

// The sixth family (#493): the Kerberos PAC set. `attributeTypes` is the
// four PAC claim types an attribute row may name, and `entryOnly` says a
// ticked attribute is read off the entry alone (#498, which gave the set the
// three `attributes*` operations #493 left out).
const KERBEROS_CLAIM_FAMILY = {
  sets: stats.KERBEROS_CLAIM_SET_IDS,
  noun: 'claim',
  carrier: 'ticket',
  example: 'kerberos-pac',
  placeholder: '${username}',
  reserved: false,
  entryOnly: true,
  attributeTypes: ['string', 'int64', 'uint64', 'boolean'],
  ids: { add: 'addKerberosPacClaim',
         addAttribute: 'addKerberosPacAttributeClaim',
         remove: 'removeKerberosPacClaim',
         clear: 'clearKerberosPacClaims',
         replace: 'replaceKerberosPacClaims',
         attributes: 'setKerberosPacClaimAttributes',
         all: 'selectAllKerberosPacClaimAttributes',
         none: 'clearKerberosPacClaimAttributes' } as const
};

// Filled by `AdminApi.wire()` (#50, R2), in this order, with the request
// schemas compiled straight after.
let PROTOCOL_SETTINGS_OPERATIONS: any[] = null;

let ROUTES: any[] = null;

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.
// Here that is the gate, then every operation, as it was.

// WHAT THIS BANNER SAYS CHANGED ON 2026-09-08 AND THE OLD TEXT IS WORTH
// RECORDING, because it was true for as long as this file existed and is now
// exactly wrong: it read "It is NOT protected", and told a reader that this
// was the surface to reach for when nobody holds a console role. Anybody
// working from a log line from an older build will look for that sentence, so
// the replacement contradicts it in the same place rather than going quiet.
//
// It is computed at startup (when the instance is installed — at require
// time for a process without the root) and says "currently", because
// `adminApi.authRequired` is changeable while running — a banner that stated
// it as a fact would be a line in a log claiming something the operator turned
// off ten minutes later.
//
// Since R2 the banner is logged by `AdminApi.wire()`, which counts the
// installed instance's operations; this function is its text.
function startupBanner(operations: number): string {
  log.debug("Entering startupBanner().");
  const text = 'The management API is at ' + BASE + ': ' +
         operations +
         ' operations over the same functions ' +
         'the /admin console calls. Its OpenAPI document is at ' + BASE +
         '/openapi.json and an explorer that calls it is on the console, ' +
         'at /admin/api-explorer (it was ' + BASE + '/docs until ' +
         '2026-09-09). ' +
         (mode.valueInForce('adminApi.authRequired') === true
           ? 'It REQUIRES an OAuth 2.0 access token (adminApi.authRequired): ' +
             'audience ' +
             (config.sourceOf('adminApi.audience') === 'default'
               ? config.value('adminApi.audience') + ' (or ' + BASE +
                 ' under the host a request arrives on)'
               : (config.value('adminApi.audience') || BASE)) + ', ' +
             'scope admin:read to read and admin:write to write, checked as ' +
             'a XACML access decision against the ADMIN_READ and ADMIN_WRITE ' +
             'roles. Get one from the client_credentials grant as the seeded ' +
             'application sts-api-client, whose secret is ' +
             'adminApi.clientSecret. THAT SETTING IS THE BOOTSTRAP: this ' +
             'surface used to be the way back in when nobody held a console ' +
             'role, and it is only still that if the secret was pinned ' +
             'before the start — a secret minted per start is readable only ' +
             'through the API it unlocks.'
           : 'It is NOT protected (adminApi.authRequired is off, which ' +
             'only development mode honours) — and the console is gated ' +
             'unconditionally, so this is the surface to reach for when ' +
             'nobody holds a console role: POST ' + BASE + '/rbac/grant.');
  log.debug("Leaving startupBanner().");
  return text;
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<AdminApi>(
  'mgmt-api/admin_api',
  () => new AdminApi(AdminApi.defaultDeps()),
  AdminApi.wire,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The management API: every `/admin` console control as a JSON operation at
 * `/admin-api`, gated by an OAuth 2.0 access token.
 *
 * Every POST calls the console's own action function and every GET its JSON
 * view; the OpenAPI document is built from the same route table.
 *
 * @namespace
 */
export = {
  /**
   * Registers the gate and then every operation on the given app; called by
   * `common/protocol_stack.ts`.
   *
   * @param target - the express app
   */
  registerRoutes: (target: any): void => {
    const managementApi = slot.get();
    managementApi.registerGate(target);
    managementApi.registerRoutes(target);
  },
  AdminApi: AdminApi,
  /**
   * Installs the instance the composition root built, which the facades below
   * forward to.
   *
   * @param instance - the instance to install
   */
  installInstance: (instance: AdminApi): void => slot.install(instance),
  /**
   * Says whether the installed instance came from the root or the default.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  BASE: BASE,
  // The three facts the OpenAPI document is built from, gathered in one place
  // so that this file's document and the console explorer's cannot disagree
  // about what this API requires. See specOptions().
  /**
   * Forwards to `AdminApi.specOptions()` on the installed instance.
   */
  specOptions: slot.forward('specOptions'),
  // The table, so that the parent project's tests can assert what this file
  // covers against what the console offers rather than against a list somebody
  // typed into a test.
  /**
   * The route table, built on first use.
   */
  get ROUTES(): any[] {
    slot.get();
    return ROUTES;
  },
  /**
   * Forwards to `AdminApi.operationSummaries()` on the installed instance.
   */
  operationSummaries: slot.forward('operationSummaries'),
  /**
   * Forwards to `AdminApi.namesThisApi()` on the installed instance: whether
   * a target names this API (#505, `common/registered_targets.ts`).
   */
  namesThisApi: slot.forward('namesThisApi'),
  /**
   * Forwards to `AdminApi.checkRequestBody()` on the installed instance: a
   * test asks it what a body sent to an operation would be refused for.
   */
  checkRequestBody: slot.forward('checkRequestBody'),
  /**
   * Forwards to `AdminApi.compileAllRequestSchemas()` on the installed
   * instance: every request schema compiled now (#617), for a test.
   */
  compileAllRequestSchemas: slot.forward('compileAllRequestSchemas'),
  /**
   * Forwards to `AdminApi.validatorCounts()` on the installed instance: how
   * many request validators are compiled and how many recorded (#617).
   */
  validatorCounts: slot.forward('validatorCounts')
};
