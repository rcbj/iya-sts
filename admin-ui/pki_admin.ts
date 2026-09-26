'use strict';
//
// File: pki_admin.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS > PKI: ONE CONSOLE PAGE, `/admin/pki`.
//
// It builds a certificate authority for the realm it is reached in — Root,
// Intermediate, Issuing — and issues signing key pairs from the bottom of it to
// applications, which is what makes RFC 7521 and RFC 7523 usable here without
// an operator moving key material by hand.
//
// **IT MIRRORS THE PARENT PROJECT'S PKI / X.509 WORKFLOW PAGE AND IS NOT A
// COPY OF IT**, and the difference is the whole of why this file looks the way
// it does. That page is `client/public/pki.html` — Web Crypto and pkijs IN THE
// BROWSER, twenty extension cards, a live TLS probe. This console is
// `script-src 'none'` (every page of it but `/admin/api-explorer`), so a page
// of that shape is not available here at any price. What is mirrored is the
// MODEL — the same three CA tiers, the same profiles, the same encoder, from
// `common/vendored/x509.js`, which is that project's own file byte-identical —
// and what is different is that every choice is a form field and every
// computation is on the server.
//
// **THE `script-src` ARGUMENT IS MADE HERE FROM SCRATCH AND IS NOT INHERITED**,
// because `admin-ui/CLAUDE.md`'s rule says the argument has to be made each
// time and that "the page next door does it" is not one. The test is whether
// this page CANNOT work without a script. It plainly can: generating a key pair
// and issuing a certificate are things this process does far better than a
// browser — it holds the CA private keys, and a browser must never — so the
// button is a POST and the result is a re-rendered page. The debugger's page
// needs script because its whole point is that the key never leaves the
// browser; this page's whole point is the opposite.
//
// ---------------------------------------------------------------------------
// IT SHOWS ONE REALM AT A TIME (2026-09-11), WHICH IS THE ONE THING ON THIS
// CONSOLE IT WAS NOT DOING.
//
// The Root, the process branch and THIS realm's Intermediate with its Issuing
// CAs — and no other realm's. Every settings form on this console reads and
// writes the realm it was reached in and the switcher is how you change it;
// this page read the whole process, so an operator in one realm was handed a
// Rebuild button for another realm's authority and a Revoke for a certificate
// issued in it. `realmIdsForTree()` argues the cut, `scopeVisible()` is where
// it is decided, and `SCOPED_ACTIONS` is what stops the write path outliving
// the drawing.
//
// ---------------------------------------------------------------------------
// WHY IT IS AT 18a, ABOVE `mgmt-api/admin_api.ts`, AND NOT A THIRTEENTH SLOT.
//
// Rule 3e's test is whether a require would close a cycle or move a route. A
// require from `admin.js` to this file WOULD close a cycle — this requires that
// one for the shell — so the obvious direction is out. But a require from
// `mgmt-api/admin_api.ts` (19) to this file moves NOTHING: the only route it
// registers is `/admin/pki`, which collides with nothing and is not in any
// other module's path space.
//
// So this is required in `common/protocol_stack.ts` at **18a**, immediately
// after `admin-ui/admin` and BEFORE the management API — which makes the
// management API's own require of it a cache hit that registers nothing. That
// is the same arrangement `admin-ui/crypto_metadata.ts` could NOT have (it sits
// at 20a, after `tls/tls_server` at 20, because it reads that module's
// algorithm table — so it had to have a slot). A slot costs a reader an
// indirection every time, and rule 3e says not to pay for one by analogy.
//
// **SINCE #50's R1 (2026-09-16) REQUIRING THIS FILE REGISTERS NOTHING AT
// ALL**: `common/protocol_stack.ts` calls its `registerRoutes(app)` at 18a,
// so `/admin/pki`'s place in the route order is that call's place, and the
// management API's require of this file could not move a route wherever it
// ran. The argument above is why the file sat where it did while a require
// was a registration, and why the call sits at 18a now; the cycle half of it
// is unchanged.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that has routes (rule 1): `PkiAdmin` takes the
// console shell, `pki`, the pane's model, both registers of key pairs and the
// rest through its constructor, and its `registerRoutes(app)` holds the
// page's five routes in their old order. The table the comments call
// PURPOSE_WRITES is built by the constructor, because its rows read
// `applications` and call a method.
//
// The module exports `registerRoutes(app)`, which `common/protocol_stack.ts`
// calls at 18a, where requiring this module used to register them (#50, R1)
// — requiring the module registers nothing, so `mgmt-api/admin_api.ts`'s
// require of this file is a cache hit that could not move a route anyway. It
// also exports the old names: `pkiView`, `pkiAction`, `pkiActionNames`,
// `paneHtml` and `returnTo`.
//
// R2 (#50): the composition root builds the instance and installs it; this
// module builds none of its own, and its exports are FACADES that forward to
// that instance, for the JavaScript callers. A process without the root
// builds a default instance at load, as loading this module always did.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import admin = require('./admin');
import pki = require('../common/pki');
// The revocation register, the CRLs and the OCSP responders. A LIBRARY
// (rule 3) that registers nothing — the HTTP endpoints are `pki/pki_service.ts`
// at 17b — so requiring it here moves no route and closes no cycle.
import pkiRevocation = require('../common/pki_revocation');
// CAEP credential-change when a revoked certificate was a PERSON's (#145).
// A library over `helpers` and `crypto`; the require moves nothing.
import accountSignals = require('../ssf/account_signals');
import stsCrypto = require('../common/crypto');
// The pane's model: the field table, the six line grammars, the profile
// defaults and what an issue does with all of it. A LIBRARY (rule 3) — it
// registers nothing, so requiring it here moves no route.
import authoring = require('../common/pki_authoring');
import applications = require('../common/applications');
// THE PERSON-ASSERTION REGISTER (2026-09-11). A LIBRARY (rule 3) — it
// registers nothing, holds no store and takes its directory through a slot
// `ldap/ldap_server.js` fills at 21, so requiring it here moves no route. It
// owns what a person's RFC 7523 key pair IS; this file owns the CONTROL that
// creates one, exactly as it owns the application's and `applications.js` owns
// that attribute set.
import personAssertions = require('../common/person_assertions');
import config = require('../common/config');
import realms = require('../common/realms');
import helpers = require('../common/helpers');
// The error-code registry (a leaf). See `refuse()` below for where a code goes.
import errorCodes = require('../common/error_codes');
// A certificate's details, in a dialog over this page (2026-09-13). The
// catalogue and the model are `admin-core/`'s and the dialog is the one
// renderer `/admin/crypto-metadata` draws too — see certificate_dialog.ts.
import certificateViews = require('../admin-core/certificate_views');
import certificateDialog = require('./certificate_dialog');
// Which key pairs use a post-quantum algorithm, and the one icon that says so
// (2026-09-13) — the same pair `/admin/keys` draws with. See pqc_badge.ts.
import pqcSupport = require('../common/pqc_support');
import pqcBadge = require('./pqc_badge');
// The paging arithmetic every console list uses (`pagedRows()`,
// `pagingJson()`). A LIBRARY that registers nothing, and `admin.js` above has
// already loaded it, so this require is a cache hit that moves no route.
import adminViews = require('../admin-core/admin_views');
import InstanceSlot = require('../common/instance_slot');

type Json = any;

// What the page needs from the rest of the service. Named for what is asked
// of each, so a test can supply exactly that and nothing more.
interface PkiAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  stsKeysFor: typeof helpers.stsKeysFor;
  config: typeof config;
  realms: typeof realms;
  pki: typeof pki;
  pkiRevocation: typeof pkiRevocation;
  authoring: typeof authoring;
  applications: typeof applications;
  personAssertions: typeof personAssertions;
  errorCodes: typeof errorCodes;
  certificateViews: typeof certificateViews;
  certificateDialog: typeof certificateDialog;
  pqcSupport: typeof pqcSupport;
  pqcBadge: typeof pqcBadge;
  adminViews: typeof adminViews;
  admin: typeof admin;
  // The console's HTML escaper, `admin.esc`.
  esc: typeof admin.esc;
}

// ---------------------------------------------------------------------------
// THE TWO KEY-PAIR TABLES ARE PAGED (2026-09-13).
//
// *Applications* and *People* drew every row they had, and each grows by one
// row per profile per holder — so a realm that had issued key pairs to a few
// hundred applications put the People table, the revocation pane and the
// certificate pane several thousand pixels below the controls above them.
//
// **TWO LISTS ON ONE PAGE, SO EACH HAS A PAGE PARAMETER OF ITS OWN AND THEY
// SHARE ONE `per`** — `issuedPage` and `personsPage`, which is
// `pagingOf()`'s `options.name` and the arrangement `/admin/consent` and
// `/admin/kerberos/principals` already have. A single `page` would mean
// `next ›` under People silently advancing the Applications table. The names
// are the JSON members' own with `Page` on the end, answered by `issuedPaging`
// and `personsPaging`, which is `/admin-api`'s one-name-per-list rule
// (`detailPagingParameters()` in `mgmt-api/admin_api.ts`): a caller that can
// read the reply can write the request without a table between the two.
//
// **The Applications table pages its ROWS and the People table pages PEOPLE.**
// That is not an inconsistency: `issued` is already one row per application
// per profile, so its rows ARE its units, while `persons` is one member per
// person with the RFC 7522 key pair nested, and the page draws up to two rows
// for each. Paging the drawn rows there would give `personsPaging` numbers
// that index into nothing the JSON holds.
//
// **`?format=json` AND `GET /admin-api/pki` STILL CARRY BOTH LISTS WHOLE**,
// with `issuedPaging` and `personsPaging` beside them saying what the page
// drew — `/admin/delegation`'s rule. The tiles above the tables count the
// whole lists, and every existing reader of `issued` looks an application up
// in it by identifier; a reply that silently held one page would answer
// "not there" about an application on page two.
//
// Twenty-five rows rather than the console's fifty because this page carries
// eight sections, and fifty rows apiece puts the People heading out of reach
// of anything but the scrollbar. `?per=` overrides it for both.
// ---------------------------------------------------------------------------
const KEY_PAIR_PER_PAGE = 25;
const KEY_PAIR_LIST_PARAMS = ['per', 'issuedPage', 'personsPage'];

// The actions this page's form can post. The refusal sentence names every one
// of them and the count comes from this list rather than being written out —
// `ssf/CLAUDE.md` records that a handler phrasing that sentence its own way
// turns two tests off with nothing failing.
// THE FIRST FOUR ARE THE HIERARCHY AND THE APPLICATION LEAF, which is what
// this page was when it was written. The eight after `upload-certificate` are
// the Certificate & Key Configuration pane, which arrived 2026-09-10 — and
// they are on the SAME list because `/admin-api/pki/{action}` mirrors this
// list and rule 7 says every control on this console has an operation. A pane
// action answers with a DRAFT as well as a verdict, which is what the
// console's own POST re-renders and what lets a machine drive the pane
// through the API.
const PKI_ACTIONS = ['build', 'clear', 'issue', 'revoke',
                     // An application's key pair replaced by a certificate
                     // the application brought, since 2026-09-13 — the
                     // other half of `issue`, and drawn beside it on the
                     // application's own page.
                     'upload-certificate',
                     'apply-profile', 'generate-keys', 'generate-alt-keys',
                     'issue-certificate', 'use-key', 'remove-object',
                     'clear-store', 'export',
                     // The hierarchy's own, since 2026-09-11.
                     'build-root', 'build-scope', 'reissue-use-case',
                     'recertify', 'import-ca', 'pin-key',
                     // The revocation pane's, since 2026-09-11. NOT named
                     // `revoke` — that is taken, by the control that takes a
                     // key pair off an application's entry, and the two are
                     // different acts. See the branches in `pkiAction()`.
                     'revoke-certificate', 'release-hold'];

// The actions that carry a `scope`, and therefore the ones a foreign realm
// can be named on. Written out rather than derived: every one of them REPLACES
// or REVOKES something, so a new action joining them silently by pattern is
// exactly the kind of addition this list exists to make deliberate. The
// hierarchy's `build-root` is NOT here — it is the service's own Root, which
// belongs to no realm and rebuilds every branch under it on purpose.
const SCOPED_ACTIONS = ['build-scope', 'reissue-use-case', 'recertify',
                        'import-ca', 'pin-key',
                        'revoke-certificate', 'release-hold'];

// The count in the unknown-action sentence, spelt out. It used to index a
// five-word array, which answered `undefined` the moment this list grew past
// five — and that sentence is matched by
// `tests/vendored/sts_admin_api_operations.js` on every action resource this
// API declares, so it would have turned that check off for this one with
// nothing failing.
const COUNT_WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six',
                     'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve',
                     'thirteen', 'fourteen', 'fifteen'];

class PkiAdmin {
  // The table the comments here call PURPOSE_WRITES — see
  // `purposeWritesTable()`.
  private readonly purposeWrites: Record<string, any>;

  constructor(private readonly deps: PkiAdminDeps) {
    deps.log.debug("Entering PkiAdmin.constructor().");
    this.purposeWrites = this.purposeWritesTable();
    deps.log.debug("Leaving PkiAdmin.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50).
  static defaultDeps(): PkiAdminDeps {
    helpers.log.debug("Entering PkiAdmin.defaultDeps().");
    helpers.log.debug("Leaving PkiAdmin.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      stsKeysFor: helpers.stsKeysFor,
      config: config,
      realms: realms,
      pki: pki,
      pkiRevocation: pkiRevocation,
      authoring: authoring,
      applications: applications,
      personAssertions: personAssertions,
      errorCodes: errorCodes,
      certificateViews: certificateViews,
      certificateDialog: certificateDialog,
      pqcSupport: pqcSupport,
      pqcBadge: pqcBadge,
      adminViews: adminViews,
      admin: admin,
      esc: admin.esc
    };
  }

  // The action names this page's form can post, for the management API.
  pkiActionNames() {
    const { log } = this.deps;
    log.debug("Entering PkiAdmin.pkiActionNames().");
    log.debug("Leaving PkiAdmin.pkiActionNames().");
    return PKI_ACTIONS.slice();
  }

  // RFC 4517 GeneralizedTime, which is how every timestamp in this directory is
  // spelled. Written here rather than imported because `applications.js` keeps
  // its copy private and `helpers.js` has none — three lines, and a fourth
  // spelling of a timestamp on one entry would be worse than a fourth copy of
  // this function.
  private generalizedTime(when: Json) {
    const { log } = this.deps;
    log.debug("Entering PkiAdmin.generalizedTime().");
    const d = when ? new Date(when) : new Date();
    const pad = function (n) {
      log.debug("Entering pad().");
      log.debug("Leaving pad().");
      return String(n).padStart(2, '0');
    };
    log.debug("Leaving PkiAdmin.generalizedTime().");
    return d.getUTCFullYear() + pad(d.getUTCMonth() + 1) + pad(d.getUTCDate()) +
           pad(d.getUTCHours()) + pad(d.getUTCMinutes()) +
           pad(d.getUTCSeconds()) + 'Z';
  }

  // The two tables' paging state out of a query, and ONLY those names: what
  // comes out of here is put into every paging link and every Take-off button's
  // `back`, so the set of names is one this file wrote. A repeated parameter is
  // its first value, and a value that is not a positive integer is dropped
  // rather than carried — `pagingOf()` would clamp it anyway, and a link has no
  // business repeating it.
  private keyPairListView(query: Json) {
    const { log } = this.deps;
    log.debug("Entering PkiAdmin.keyPairListView().");
    const out = {};
    KEY_PAIR_LIST_PARAMS.forEach(function (name) {
      const raw = (query || {})[name];
      const first = Array.isArray(raw) ? raw[0] : raw;
      const value = first == null ? '' : String(first);
      if (/^[1-9][0-9]{0,5}$/.test(value)) {
        out[name] = value;
      }
    });
    log.debug("Leaving PkiAdmin.keyPairListView(). " + Object.keys(out).length +
              " parameter(s).");
    return out;
  }

  // The same thing out of a Take-off button's `back` field, which is a query
  // string a browser sent rather than one this page is looking at. REBUILT and
  // never echoed, for `listViewFromBack()`'s reason in `admin.js`: it ends up
  // in a `Location` header, and the worst a hand-written one can reach is
  // another page of these two tables.
  private keyPairListViewFromBack(raw: Json) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering PkiAdmin.keyPairListViewFromBack().");
    const query = {};
    try {
      new URLSearchParams(String(raw || '').replace(/^\?/, ''))
        .forEach(function (value, key) {
          if (!Object.prototype.hasOwnProperty.call(query, key)) {
            query[key] = value;
          }
        });
    } catch (e) {
      // Unparseable: the first page of each table, which is what a form
      // carrying no `back` at all gets too.
      log.debug("Caught in PkiAdmin.keyPairListViewFromBack(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving PkiAdmin.keyPairListViewFromBack().");
    return self.keyPairListView(query);
  }

  // Both tables' slices and paging, from one query. Called by `pkiJson()` for
  // the two paging members and by `renderPki()` for the rows, over the same two
  // arrays, so the page and `personsPaging` cannot describe different slices.
  private keyPairPaging(query: Json, json: Json) {
    const { log, adminViews } = this.deps;
    log.debug("Entering PkiAdmin.keyPairPaging().");
    const q = query || {};
    const out = {
      applications: adminViews.pagedRows(q, json.issued || [],
        { name: 'issued', noun: 'application rows',
          defaultPer: KEY_PAIR_PER_PAGE }),
      people: adminViews.pagedRows(q, json.persons || [],
        { name: 'persons', noun: 'people', defaultPer: KEY_PAIR_PER_PAGE })
    };
    log.debug("Leaving PkiAdmin.keyPairPaging().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // WHICH ATTRIBUTES AN ISSUE WRITES, PER PROFILE.
  //
  // `common/pki.js` hands a key pair over ONCE and keeps no copy, so this table
  // is the only place the answer exists — and it is a TABLE rather than two
  // branches because the two profiles differ in exactly one interesting way and
  // a branch would hide it: RFC 7523 registers a key as a JWKS (with the chain
  // in `x5c`) and RFC 7522 registers it as a PEM certificate, because SAML has
  // no JWKS. So the JWT set has seven members and the SAML set has six (each
  // counting the provenance attribute since 2026-09-13), and the handle is a
  // `kid` in one and a thumbprint in the other.
  //
  // **THE TWO SETS SHARE NO ATTRIBUTE NAME, WHICH IS THE WHOLE POINT.** An
  // application may hold both key pairs; `oauth-oidc/saml_assertion_grant.js`
  // never reads the JWT set and `oauth-oidc/assertion_grant.js` never reads the
  // SAML one, so neither pair can sign for the other's profile and taking one
  // off leaves the other working. `applications.js`'s SCHEMA argues it at the
  // attributes and that module's header argues it at the verifier.
  // ---------------------------------------------------------------------------
  // (The table the comments here call PURPOSE_WRITES: built by the
  // constructor from this method, because its rows read `applications`
  // and call `generalizedTime()`.)
  private purposeWritesTable(): Record<string, any> {
    const { log, applications } = this.deps;
    const self = this;
    log.debug("Entering PkiAdmin.purposeWritesTable().");
    log.debug("Leaving PkiAdmin.purposeWritesTable().");
    return {
      jwt: {
        // THE NAMES are `applications.KEY_PAIR_ATTRIBUTES`'s, which the schema
        // owns and the application page reads too (2026-09-13); the WRITES
        // below are this table's.
        issuerAttribute: applications.KEY_PAIR_ATTRIBUTES.jwt.issuer,
        handleAttribute: applications.KEY_PAIR_ATTRIBUTES.jwt.handle,
        handleLabel: applications.KEY_PAIR_ATTRIBUTES.jwt.handleLabel,
        privateKeyAttribute: applications.KEY_PAIR_ATTRIBUTES.jwt.privateKey,
        expiresAttribute: applications.KEY_PAIR_ATTRIBUTES.jwt.expires,
        certificateAttribute: applications.KEY_PAIR_ATTRIBUTES.jwt.certificate,
        chainAttribute: applications.KEY_PAIR_ATTRIBUTES.jwt.chain,
        sourceAttribute: applications.KEY_PAIR_ATTRIBUTES.jwt.source,
        registeredAttribute: applications.KEY_PAIR_ATTRIBUTES.jwt.registered,
        attributes: ['oauthAssertionJwks', 'oauthAssertionCertificate',
                     'oauthAssertionCertificateChain',
                     'oauthAssertionPrivateKey',
                     'oauthAssertionKid', 'oauthAssertionExpiresAt',
                     'oauthAssertionKeySource'],
        valuesOf: function (record) {
          log.debug("Entering valuesOf().");
          log.debug("Leaving valuesOf().");
          // ONE LIST, in applications.js (#138), which this service's own
          // surfaces write their private_key_jwt keys through as well.
          return applications.issuedJwtKeyPairValues(record);
        }
      },
      saml: {
        issuerAttribute: applications.KEY_PAIR_ATTRIBUTES.saml.issuer,
        handleAttribute: applications.KEY_PAIR_ATTRIBUTES.saml.handle,
        handleLabel: applications.KEY_PAIR_ATTRIBUTES.saml.handleLabel,
        privateKeyAttribute: applications.KEY_PAIR_ATTRIBUTES.saml.privateKey,
        expiresAttribute: applications.KEY_PAIR_ATTRIBUTES.saml.expires,
        certificateAttribute: applications.KEY_PAIR_ATTRIBUTES.saml.certificate,
        chainAttribute: applications.KEY_PAIR_ATTRIBUTES.saml.chain,
        sourceAttribute: applications.KEY_PAIR_ATTRIBUTES.saml.source,
        registeredAttribute: applications.KEY_PAIR_ATTRIBUTES.saml.registered,
        attributes: ['oauthSamlAssertionCertificate',
                     'oauthSamlAssertionCertificateChain',
                     'oauthSamlAssertionPrivateKey',
                     'oauthSamlAssertionThumbprint',
                     'oauthSamlAssertionExpiresAt',
                     'oauthSamlAssertionKeySource'],
        valuesOf: function (record) {
          log.debug("Entering valuesOf().");
          log.debug("Leaving valuesOf().");
          return [
            ['oauthSamlAssertionCertificate', record.certificatePem],
            ['oauthSamlAssertionCertificateChain', record.chainPem.join('')],
            ['oauthSamlAssertionPrivateKey', record.privateKeyPem],
            ['oauthSamlAssertionThumbprint', record.certificateThumbprint],
            ['oauthSamlAssertionExpiresAt',
             self.generalizedTime(new Date(record.notAfter))],
            ['oauthSamlAssertionKeySource', record.source || 'issued']
          ];
        }
      }
    };
  }

  // ---------------------------------------------------------------------------
  // WHO THE KEY PAIR IS FOR, defaulted and validated in one place (2026-09-11).
  //
  // An empty value means `application`, which is what every caller written
  // before today sends and is why that is the default rather than a required
  // field — the same decision `purposeOf()` below records about `jwt`.
  //
  // **IT IS A FIELD ON THE SAME ACTION RATHER THAN A SECOND ACTION.** Issuing
  // to a person and issuing to an application differ in two things — which
  // subjectAltName the certificate carries and which entry the result is
  // written onto — and everything else about the act is identical: the same
  // Issuing CA, the same profile, the same certificate. A second action would
  // be a second answer to *how does this service issue a signing key pair*, and
  // it is the second one that stops getting the next fix. `common/pki.js`'s
  // SUBJECT_KINDS table makes the same argument one layer down.
  // ---------------------------------------------------------------------------
  private targetOf(body: Json) {
    const { log, pki } = this.deps;
    log.debug("Entering PkiAdmin.targetOf().");
    const asked = String((body && body.target) || '').trim() || 'application';
    log.debug("Leaving PkiAdmin.targetOf().");
    return pki.subjectKindFor(asked) ? asked : '';
  }

  // THE LEAF'S KEY ALGORITHM, UNDER EITHER NAME. The console's issue forms post
  // `leafKeyAlg` (the page carries the hierarchy's `keyAlg` elsewhere); the
  // management API documents `keyAlg` and its schema refuses any other member.
  // Until 2026-09-16 only `leafKeyAlg` was read, so an API caller's `keyAlg`
  // was accepted and silently ignored. Undefined means the Issuing CA's
  // algorithm.
  private leafKeyAlgOf(body: Json) {
    const { log } = this.deps;
    log.debug("Entering PkiAdmin.leafKeyAlgOf().");
    const asked = String(body.leafKeyAlg || body.keyAlg || '').trim();
    log.debug("Leaving PkiAdmin.leafKeyAlgOf(). " + (asked || "The CA's."));
    return asked || undefined;
  }

  // The purpose a request asked for, defaulted and validated in one place. An
  // empty value means `jwt`, which is what every caller written before
  // 2026-09-11 sends and is the reason that is the default rather than a
  // required field.
  private purposeOf(body: Json) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering PkiAdmin.purposeOf().");
    const asked = String((body && body.purpose) || '').trim() || 'jwt';
    log.debug("Leaving PkiAdmin.purposeOf().");
    return self.purposeWrites[asked] ? asked : '';
  }

  private countWord(n: Json) {
    const { log } = this.deps;
    log.debug("Entering PkiAdmin.countWord().");
    log.debug("Leaving PkiAdmin.countWord().");
    return COUNT_WORDS[n] || String(n);
  }

  private realmLabel() {
    const { log, realms } = this.deps;
    log.debug("Entering PkiAdmin.realmLabel().");
    const current = realms.current();
    log.debug("Leaving PkiAdmin.realmLabel().");
    return (current && current.id) ? current.id : 'default';
  }

  // ---------------------------------------------------------------------------
  // A REFUSAL, IN BOTH SHAPES, FROM ONE STRING.
  //
  // This console's action functions answer `{ ok: false, errors: [...] }` and
  // `admin.respondToAction()` renders the array; `/admin-api` sends the whole
  // object back as JSON. **`errors` is the half a TEST reads** —
  // `tests/vendored/sts_admin_api_operations.js` matches the unknown-action
  // sentence out of it on every action resource this API declares, and
  // `tests/vendored/admin_api.js` reads the same sentence to check that every
  // console action has an operation. A handler answering with a `why` alone
  // turns both of those off for its own resource with nothing failing, which is
  // what the first version of this file did and what went red on its first run.
  //
  // `why` is kept beside it because this page's own POST handler prints it and
  // because a caller reading one field should not have to know which. One
  // string, so the two can never disagree.
  //
  // **AND THE CONDITION'S ERROR CODE, WHICH IS ON THE RESULT AND NOT IN IT.**
  // `mark()` puts it under a non-enumerable Symbol, so `JSON.stringify(result)`
  // — which is what `/admin-api` sends — cannot carry it, and the routes below
  // and the management API read it back with `errorCodes.codeOf()` to mark the
  // response they send.
  private refuse(sentence: Json, code: Json) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PkiAdmin.refuse().");
    const refused = { ok: false, errors: [sentence], why: sentence };
    log.debug("Leaving PkiAdmin.refuse().");
    return code ? errorCodes.mark(refused, code) : refused;
  }

  // A module's refusal passed on in this file's shape, keeping the module's own
  // code where it set one and naming the fallback where it did not.
  private refusedBy(result: Json, fallback: Json) {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering PkiAdmin.refusedBy().");
    log.debug("Leaving PkiAdmin.refusedBy().");
    return self.refuse(((result && result.errors) || []).join(' '),
                       errorCodes.codeOf(result) || fallback);
  }

  // Mark the response a PKI route is about to send with the code its result
  // carries. A result that succeeded carries none and marks nothing.
  private markRefusal(res: Json, result: Json, fallback: Json) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PkiAdmin.markRefusal().");
    if (result && result.ok === false) {
      errorCodes.mark(res, errorCodes.codeOf(result) || fallback);
    }
    log.debug("Leaving PkiAdmin.markRefusal().");
  }

  // WHICH SCOPE AN ACTION IS ABOUT. A missing one means the realm the request
  // arrived in, which is what every other control on this console means by
  // saying nothing — the console shows one realm at a time and the switcher is
  // how you change it. `*service` and `*process` are named explicitly because
  // they are not realms at all.
  private scopeFrom(body: Json) {
    const { log, realms, pki } = this.deps;
    log.debug("Entering PkiAdmin.scopeFrom().");
    const asked = String((body && body.scope) || '').trim();
    if (asked === pki.SERVICE_SCOPE || asked === pki.PROCESS_SCOPE) {
      log.debug("Leaving PkiAdmin.scopeFrom().");
      return asked;
    }
    if (asked && asked !== 'default') {
      log.debug("Leaving PkiAdmin.scopeFrom().");
      return asked;
    }
    const current = realms.current();
    log.debug("Leaving PkiAdmin.scopeFrom().");
    return (current && current.id) ? current.id : '';
  }

  // Rebuild every branch under a Root that has just been replaced, and
  // re-certify what hung under each. It is here rather than in `common/pki.js`
  // because the list of realms is the console's question — that module is
  // handed scope ids and has no opinion about which exist.
  private async rebuildEveryScope() {
    const { log, config, pki, errorCodes } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.rebuildEveryScope().');
    // EVERY realm, not the ones this page draws — see `everyRealmId()`.
    const scopes = [pki.PROCESS_SCOPE].concat(self.everyRealmId());
    let done = 0;
    // REPAIRED, NOT BUILT (2026-09-21): a branch another process already
    // rebuilt under this Root is adopted, not built a second time — which
    // left a realm with two Intermediate CAs of one name when another worker
    // repaired it first (`common/pki.js`, `repairBranch()`).
    for (let i = 0; i < scopes.length; i++) {
      const built = await pki.repairBranch(scopes[i],
                                           { organisation: config.value(
                                               'pki.organisation') });
      if (built.ok) {
        done += 1;
        await self.recertifyScope(scopes[i]);
      } else {
        log.error(errorCodes.tag('STS-PKI-0104') + 'pki_admin: the "' +
                  scopes[i] + '" ' +
                  'branch could not be rebuilt under the new Root: ' +
                  (built.errors || []).join(' '));
      }
    }
    log.debug('Leaving PkiAdmin.rebuildEveryScope(). ' + done + ' branch(es).');
    return done;
  }

  // Re-mint everything a scope's Issuing CAs had certified. Called after a
  // branch is rebuilt, because the authorities that signed those certificates
  // no longer exist — leaving them would be the console showing a tree whose
  // leaves chain to nothing.
  private async recertifyScope(scopeId: Json) {
    const { log, stsKeysFor, pki } = this.deps;
    log.debug('Entering PkiAdmin.recertifyScope(). scope=' + scopeId);
    let done = 0;
    const kind = pki.scopeKindOf(scopeId);
    if (kind === 'realm') {
      const keys = stsKeysFor.of ? stsKeysFor.of(scopeId) : null;
      if (keys) {
        const made = await pki.certifyKeySet(scopeId, keys);
        done += made.certified || 0;
      }
    } else {
      done += await pki.certifyRegistered();
    }
    log.debug('Leaving PkiAdmin.recertifyScope(). ' + done +
              ' certificate(s).');
    return done;
  }

  // WHICH STORED OBJECT AN ACTION IS ABOUT. `/admin-api` names it as
  // `objectId`; the console's own buttons carry it as the value of the button
  // that was pressed, which `paneActionFrom()` has already put there — and the
  // store table's radio column (`pki_selected`) is the fallback, which is what
  // makes the Export row work without a button press naming anything.
  private objectIdOf(body: Json) {
    const { log } = this.deps;
    log.debug("Entering PkiAdmin.objectIdOf().");
    log.debug("Leaving PkiAdmin.objectIdOf().");
    return String((body && (body.objectId || body.pki_selected)) || '');
  }

  // ---------------------------------------------------------------------------
  // WHAT THIS PAGE ANSWERS AS JSON, which is also what `GET /admin-api/pki`
  // answers. ONE function, so the page and the management API cannot come to
  // disagree about what this realm's certificate authority is — the same rule
  // every other view in this console follows.
  //
  // **NO PRIVATE KEY IS IN IT**, and that is `common/pki.js`'s doing rather
  // than this file's: `describe()` drops every one of them on the way out, so a
  // caller here could not leak the Root's key by forgetting.
  // ---------------------------------------------------------------------------
  pkiJson(req: Json, draft?: Json) {
    const { log, pki, authoring, applications, personAssertions, pqcSupport,
            adminViews, admin } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.pkiJson().');
    const chain = pki.describe();
    const report = pki.report();
    const json: Json = {
      realm: self.realmLabel(),
      chain: chain,
      // The vocabulary a caller may choose from, published rather than
      // documented: `POST /admin-api/pki/build` learns what it may send from
      // the service instead of from a copy of the list in a document.
      keyAlgorithms: pki.keyAlgorithms(),
      signatureAlgorithms: report.signatureAlgorithms,
      tiers: report.tiers,
      // THE REGISTER, and the SENTENCE, and they are two members rather than
      // one because they answer two questions: `revocation` is what is on the
      // lists right now and `revocationNote` is what this service's revocation
      // MEANS — published and not enforced. A caller that had only the first
      // could read an empty list as "nothing is revoked here" and would be
      // right; a caller that had only the second could not tell whether
      // anything had been.
      revocation: self.revocationModel(),
      revocationNote: report.revocation,
      residency: report.residency,
      encoder: report.encoder,
      actions: PKI_ACTIONS.slice(),
      // Every application this realm has, with whatever the issue control put
      // on its entry. It is READ OFF THE ENTRIES rather than out of a register
      // of this module's own, because there is no such register —
      // `common/pki.js` hands a key pair over once and keeps no copy, so
      // `ou=applications` is the only place the answer exists.
      // **ONE ROW PER APPLICATION AND PER PROFILE, which is two rows for an
      // application holding both key pairs.** A single row with a pair of
      // columns was the first shape of this and it was wrong for a reason worth
      // keeping: every control on it — Take the key pair off, the declared
      // issuer, the expiry — is per profile, so a row that covered both would
      // have had to say which of two things each of its buttons meant.
      issued: pki.PURPOSE_IDS.reduce(function (rows, purpose) {
        const table = self.purposeWrites[purpose];
        return rows.concat(applications.list().map(function (one) {
          const fields = one.fields || {};
          return {
            identifier: one.identifier,
            name: one.name,
            purpose: purpose,
            purposeLabel: pki.purposeFor(purpose).label,
            handleLabel: table.handleLabel,
            handle: fields[table.handleAttribute]
              ? String(fields[table.handleAttribute]) : '',
            expiresAt: fields[table.expiresAttribute]
              ? String(fields[table.expiresAttribute]) : '',
            // A MANAGED KEY PAIR — issued here, or a certificate uploaded in
            // its place (2026-09-13). The second has no private key on the
            // entry, which is why this reads the certificate as well; the
            // private half is `privateKeyHeld`, and `source` says which of the
            // two it was.
            hasKeyPair: !!(fields[table.privateKeyAttribute] ||
                           fields[table.certificateAttribute]),
            privateKeyHeld: !!fields[table.privateKeyAttribute],
            source: fields[table.sourceAttribute]
              ? String(fields[table.sourceAttribute])
              : (fields[table.privateKeyAttribute] ? 'issued' : ''),
            // The declaration, which is the trust decision and is a separate
            // act from being issued a key pair — an application may hold one
            // and declare no issuer, which means it can sign and this service
            // will not accept what it signs as an authorization grant. It is
            // PER PROFILE too: being trusted to assert as a JWT is not being
            // trusted to assert as SAML.
            assertionIssuers: self.valuesOf(fields[table.issuerAttribute]),
            // What the party registered ITSELF, which for RFC 7523 is a JWKS
            // and for RFC 7522 is a certificate — the one place the two
            // profiles' shapes show through this table.
            registeredOwnKeys: purpose === 'saml'
              ? !!fields.oauthSamlAssertionSigningCertificate
              : !!fields.oauthJwks,
            // Whether the key pair on the entry uses a post-quantum algorithm,
            // read off its certificate (2026-09-13): `null` for a classical key
            // or none, otherwise `pqc_support.js`'s kind, label and standard.
            pqc: pqcSupport.of({ certificatePem:
              fields[table.certificateAttribute] })
          };
        }).filter(function (one) {
          return one.hasKeyPair || one.assertionIssuers.length ||
                 one.registeredOwnKeys;
        }));
      }, []),
      // ---------------------------------------------------------------------
      // EVERY PERSON IN THIS REALM WHO HOLDS ONE (2026-09-11), read off their
      // entries for the reason `issued` above is read off applications': this
      // module keeps no register, because `common/pki.js` hands a key pair over
      // once and keeps no copy.
      //
      // **NO PRIVATE KEY IS IN IT.** `person_assertions.holders()` does not
      // return one, and this is a page: a console that drew a person's private
      // key would hand it to everybody who can read the console, on every
      // visit. The issue reply is the one door, and it opens once.
      //
      // ONE ROW PER PERSON, with the RFC 7522 key pair nested as `saml`
      // (2026-09-13). It was one row because a person could hold ONE key pair —
      // RFC 7522's verifier read nothing off a person — and the verifier reads
      // a person's now. The JWT members keep their names so a reader written
      // before that day reads the profile it always did; the page draws a row
      // per profile held, as it does for applications.
      // ---------------------------------------------------------------------
      // Each with `pqc`, read off the person's certificate as `issued` above.
      persons: personAssertions.holders().map(function (one) {
        return Object.assign({}, one, {
          pqc: pqcSupport.of({ certificatePem: one.certificatePem }),
          saml: Object.assign({}, one.saml, {
            pqc: pqcSupport.of({ certificatePem: one.saml.certificatePem }) })
        });
      }),
      personsStorable: personAssertions.storable(),
      personAttributes: personAssertions.ATTRIBUTES.slice(),
      personIssuerAttribute: personAssertions.ISSUER_ATTRIBUTE,
      // WHO A KEY PAIR MAY BE ISSUED TO, published rather than documented — the
      // same rule `purposes` and `keyAlgorithms` follow. The Issue and Take-off
      // controls both take it as `target`.
      subjectKinds: pki.SUBJECT_KINDS.map(function (one) {
        return { id: one.id, label: one.label, what: one.what };
      }),
      // The vocabulary the Issue and Take-off controls take, published rather
      // than documented — the same rule `keyAlgorithms` above follows.
      purposes: pki.PURPOSES.map(function (one) {
        return { id: one.id, label: one.label, what: one.what,
                 attributes: self.purposeWrites[one.id].attributes.slice(),
                 issuerAttribute: self.purposeWrites[one.id].issuerAttribute };
      }),
      // ---------------------------------------------------------------------
      // THE TREE THIS REALM IS UNDER (2026-09-11): the service Root, the
      // process branch, and THIS REALM'S Intermediate with an Issuing CA per
      // use case and what each one has certified beneath it.
      //
      // **IT WAS EVERY REALM'S FOR A DAY**, and `realmIdsForTree()` above
      // argues the narrowing at length. The short of it: the console shows one
      // realm at a time everywhere else, and this page was the one that did
      // not.
      //
      // **`GET /admin-api/pki` NARROWS WITH IT, BECAUSE IT IS THIS FUNCTION.**
      // That is not a side effect to be undone — the API is reached in a realm
      // exactly as the page is (`/realm/acme/admin-api/pki`), so a machine asks
      // the same question the page does and the switcher is the answer for
      // both. A view that answered more than the page drew would be two answers
      // to "what is this realm's certificate authority", which is the rule this
      // whole file is built on.
      //
      // `chain` above is still the THREE-TIER view of the realm this request
      // arrived in — Root, this realm's Intermediate, its application-assertion
      // Issuing CA — because that is what every caller of this resource has
      // always read and what RFC 7523 needs. This is the rest of it, and the
      // two are one store read twice rather than two stores.
      // ---------------------------------------------------------------------
      tree: pki.describeTree(self.realmIdsForTree()),
      // THE PANE, AS DATA. One function for the page and for
      // `GET /admin-api/pki`, which is this console's rule everywhere: the
      // profiles, the five approaches, the algorithm menus as the chosen
      // approach narrows them, the keystore formats, the extension vocabulary,
      // this realm's possible issuers, the object store and the DRAFT the form
      // is to be drawn with. **No private key is in it** — `describeObject()`
      // drops them, and the key material comes out only through the export.
      workbench: authoring.view(undefined, draft),
      settings: admin.configSettingsJson
        ? admin.configSettingsJson('/admin/pki') : null
    };
    // What the two tables on the page drew, beside the whole lists — see
    // `keyPairPaging()` above for why the lists themselves are not sliced.
    const paged = self.keyPairPaging(req && req.query, json);
    json.issuedPaging = adminViews.pagingJson(paged.applications.paging);
    json.personsPaging = adminViews.pagingJson(paged.people.paging);
    log.debug('Leaving PkiAdmin.pkiJson(). ' + json.issued.length +
              ' application(s).');
    return json;
  }

  // ---------------------------------------------------------------------------
  // EVERY REALM THIS SERVICE HAS, as the PKI store spells them — which is
  // `default` for the default realm and NOT the empty string, and that is a
  // correction rather than a restatement (2026-09-11).
  //
  // **`common/pki.js` RESOLVES AN EMPTY SCOPE TO THE AMBIENT REALM**, in
  // `realmIdOf()`, which every read and every write of that store goes through.
  // So `''` does not mean *the default realm* there; it means *whichever realm
  // this request is in*, and the two coincide only in the default realm. This
  // list used to convert `default` to `''`, and while it was also the page's
  // list that was invisible: in the default realm it resolved to the right row,
  // and the tree therefore looked right in the only realm anybody read it in.
  //
  // It is a REBUILD list now, which is where it bites: pressing *Replace the
  // Root* while in `acme` walked `['*process', '', 'acme']`, and the `''` was
  // acme again — so acme's branch was rebuilt twice and THE DEFAULT REALM'S WAS
  // NEVER REBUILT AT ALL, leaving it chained to a Root that no longer exists.
  // `realms.DEFAULT_ID` is the store's own spelling and resolves to the same
  // row from every realm, which is the property this list needs and `''` never
  // had.
  //
  // **THIS IS THE REBUILD'S LIST AND IT IS NOT THE PAGE'S** (2026-09-11). It
  // was both until this date, under a name — `realmIdsForTree()` — that said
  // so, and splitting them is the whole of that change: replacing the Root MUST
  // reach every branch in the process, because a branch left hanging from a
  // Root that no longer exists chains to nothing and every path through it is
  // refused. A page that draws one realm and a rebuild that walks one realm are
  // not the same requirement, and the one name covering both is how a narrowing
  // of the page would have silently narrowed the rebuild.
  // ---------------------------------------------------------------------------
  private everyRealmId() {
    const { log, realms } = this.deps;
    log.debug("Entering PkiAdmin.everyRealmId().");
    log.debug("Leaving PkiAdmin.everyRealmId().");
    return realms.list().map(function (one) { return one.id; });
  }

  // The realm this request arrived in, as the PKI store spells it: `default`
  // for the default realm, for the reason above — and `realms.current().id` is
  // already that spelling, which is why this is a read and not a conversion.
  // One function, because `scopeFrom()`, the tree, the revocation pane and the
  // foreign-scope refusal all have to mean the same realm by it, and four
  // readings of `realms.current()` are four chances not to.
  private currentRealmScope() {
    const { log, realms } = this.deps;
    log.debug("Entering PkiAdmin.currentRealmScope().");
    const current = realms.current();
    log.debug("Leaving PkiAdmin.currentRealmScope().");
    return (current && current.id) ? current.id : '';
  }

  // ===========================================================================
  // WHAT THIS PAGE MAY SHOW, AND WHY IT IS NOT THE WHOLE TREE (2026-09-11).
  //
  // **ONLY THE AUTHORITIES THIS REALM IS UNDER.** The Root, because every realm
  // hangs from it and it is this realm's anchor; the PROCESS branch, because
  // the TLS authority certifies sockets every realm answers on — so it is this
  // realm's front door as much as anybody's (the SPIFFE authority was here too
  // until 2026-09-11, when it moved to a realm's branch) — and this realm's own
  // Intermediate with its Issuing CAs. **Another realm's branch is not drawn.**
  //
  // The console shows ONE REALM AT A TIME and the switcher is how you change
  // it: every settings form on it reads and writes the realm it was reached in,
  // and this page was the one that read the whole process. Drawing every
  // realm's branch made the page grow with the realm count, put a Rebuild
  // button for somebody else's authority on a page that is about yours, and —
  // the part that actually matters — offered a Revoke on a certificate issued
  // in a realm this operator had not switched to.
  //
  // **THE PROCESS BRANCH IS DRAWN IN EVERY REALM AND THAT IS DELIBERATE.** It
  // belongs to no realm, so no realm's page is more its home than another's,
  // and it has no other surface anywhere: hiding it from every realm would
  // leave the TLS authority unreadable and unmanageable from this console.
  //
  // **THE NARROWING IS IN THIS FILE AND NOT IN `common/pki.js`.** That module
  // is handed scope ids and has no opinion about which exist — which is the
  // same reason `rebuildEveryScope()` is here — so the question *which branches
  // does a reader in this realm get* is asked exactly once, where the page is.
  // ===========================================================================
  private realmIdsForTree() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering PkiAdmin.realmIdsForTree().");
    log.debug("Leaving PkiAdmin.realmIdsForTree().");
    return [self.currentRealmScope()];
  }

  // Is this scope one this realm's page draws? The Root and the process branch
  // are, whatever realm you are in; a realm's branch is only its own.
  private scopeVisible(scopeId: Json) {
    const { log, pki } = this.deps;
    const self = this;
    log.debug("Entering PkiAdmin.scopeVisible().");
    const id = String(scopeId);
    log.debug("Leaving PkiAdmin.scopeVisible().");
    return id === pki.SERVICE_SCOPE || id === pki.PROCESS_SCOPE ||
           id === self.currentRealmScope();
  }

  private valuesOf(value: Json) {
    const { log } = this.deps;
    log.debug("Entering PkiAdmin.valuesOf().");
    if (value === undefined || value === null) {
      log.debug("Leaving PkiAdmin.valuesOf().");
      return [];
    }
    log.debug("Leaving PkiAdmin.valuesOf().");
    return (Array.isArray(value) ? value : [value]).map(String).filter(Boolean);
  }

  // ---------------------------------------------------------------------------
  // THE ACTIONS. Asynchronous, because issuing a certificate is Web Crypto all
  // the way down — which is why the two callers `await` this and why it is the
  // second action function in this console that resolves rather than returning
  // (`ssfAction` is the first, for a related reason: it signs and then POSTs).
  // ---------------------------------------------------------------------------
  // ===========================================================================
  // ISSUING TO A PERSON (2026-09-11), and the three ways it differs from
  // issuing to an application. Everything else about the act — the hierarchy,
  // the profile, the certificate, the algorithms — is the same, which is why it
  // is a FIELD on the Issue action and not an action of its own.
  //
  // ~~**ONE: THE PROFILE CAN ONLY BE `jwt`.**~~ **BOTH PROFILES SINCE
  // 2026-09-13.** This read: RFC 7522's verifier reads `oauthSamlAssertion*`
  // off an APPLICATION entry and nothing else, so a SAML key pair on a person's
  // entry would be one nothing reads — a control that appears to work and
  // silently does nothing. That was true, and the refusal (`STS-PKI-0108`,
  // retired) was right while it was; `oauth-oidc/saml_assertion_grant.js` reads
  // a person's `stsSamlAssertion*` now, under the same self-only rule the JWT
  // grant applies.
  //
  // **TWO: IT WRITES `stsAssertion*` OR `stsSamlAssertion*` THROUGH
  // `common/person_assertions.js`** rather than `oauthAssertion*` through
  // `applications.updateApplication()`. The two attribute sets share no name on
  // purpose and no code path crosses them: that is `applications.js`'s rule
  // about its own pair, made a third time for a third kind of holder.
  //
  // **THREE: THE PRIVATE KEY COMES BACK IN THIS REPLY**, which the
  // application's deliberately does not. An application's private key has a
  // credentialed read door already — `applications.view()` opens the seal and
  // `/admin/applications` and `GET /admin-api/applications` draw it — and a
  // person's has none, because nothing in this service prints a person's entry
  // through a module that would open it. The alternatives were a console page
  // that renders somebody's private key on every visit, or a key this service
  // holds that no human can ever obtain. So it is handed over by the act that
  // creates it, once, and the page that carries it says so. **That is also why
  // the console's person form posts to a route of its own**: a 303 with the
  // message on the query string would put a private key in the browser history,
  // the access log and the next request's Referer header.
  // ===========================================================================
  private async issueToPerson(identifier: Json, body: Json) {
    const { log, config, pki, personAssertions } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.issueToPerson(). identifier=' + identifier);
    if (!identifier) {
      log.debug('Leaving PkiAdmin.issueToPerson(). No name.');
      return self.refuse('Name the person the key pair is for.',
                         'STS-PKI-0106');
    }
    if (!personAssertions.storable()) {
      log.debug('Leaving PkiAdmin.issueToPerson(). No directory.');
      return self.refuse('This process has no directory, so there is nowhere ' +
                         'to put a person\'s assertion key pair and nothing ' +
                         'that could read one back. `ldap/ldap_server.js` is ' +
                         'what fills that slot.', 'STS-PKI-0107');
    }
    const purpose = self.purposeOf(body);
    if (!purpose) {
      log.debug("Leaving PkiAdmin.issueToPerson().");
      return self.refuse('"' + body.purpose +
                         '" is not a profile this service issues a signing ' +
                         'key pair for. It issues ' +
                         pki.PURPOSE_IDS.join(' and ') + '.', 'STS-PKI-0011');
    }
    const held = personAssertions.recordFor(identifier);
    if (!held) {
      // Refused rather than creating one, which is the application branch's
      // rule and is stronger here: creating a PERSON in order to give them a
      // credential is exactly what product mode refuses, and a name typed into
      // this box is more likely to be a typo than a decision.
      log.debug('Leaving PkiAdmin.issueToPerson(). Nobody by that name.');
      return self.refuse('There is nobody called "' + identifier +
                         '" in the "' + self.realmLabel() +
                         '" realm. Create them on /admin/users first — ' +
                         'issuing a signing key to somebody who does not ' +
                         'exist would be this page inventing a person in ' +
                         'order to give them a credential, which is the one ' +
                         'thing product mode refuses outright.',
                         'STS-PKI-0109');
    }
    const days = Number(body.days);
    const issued = await pki.issueSigningKeyPair(undefined, {
      identifier: identifier,
      purpose: purpose,
      // WHAT PUTS `urn:sts:person:<name>` IN THE CERTIFICATE, which is what
      // `assertion_grant.js` reads off a presented x5c to hold the person to
      // asserting about themselves. A leaf issued here without it would be
      // indistinguishable from an application's.
      subjectKind: 'person',
      commonName: String(body.commonName || '').trim() || identifier,
      keyAlg: self.leafKeyAlgOf(body),
      days: isFinite(days) && days > 0 ? Math.floor(days)
                                       : config.value('pki.leafLifetimeDays')
    });
    if (!issued.ok) {
      log.debug('Leaving PkiAdmin.issueToPerson(). The issue failed.');
      return self.refusedBy(issued, 'STS-PKI-0105');
    }
    const record = issued.issued;
    const declared = String(body.issuer || '').trim();
    const written = personAssertions.write(identifier, record,
      declared ? { issuer: declared, purpose: purpose } : { purpose: purpose });
    if (!written.ok) {
      log.debug('Leaving PkiAdmin.issueToPerson(). The write failed.');
      return self.refusedBy(written, 'STS-PKI-0110');
    }
    const saml = purpose === 'saml';
    log.debug('Leaving PkiAdmin.issueToPerson(). Issued.');
    return {
      ok: true,
      target: 'person',
      purpose: purpose,
      person: identifier,
      attributes: written.written.slice(),
      kid: record.kid,
      thumbprint: record.certificateThumbprint,
      notAfter: record.notAfter,
      jwsAlg: record.jwsAlg,
      issuer: declared || identifier,
      declared: !!declared,
      certificatePem: record.certificatePem,
      chainPem: record.chainPem.join(''),
      jwks: saml ? null : record.jwks,
      // ONCE. See the header above: this is the only door a person's private
      // key ever comes out of.
      privateKeyPem: record.privateKeyPem,
      why: 'A ' + record.keyAlg + ' signing key pair was issued to "' +
           identifier + '" — a PERSON — for ' + record.purposeLabel + ', ' +
           'signed by this realm\'s Issuing CA, and written onto their ' +
           'directory entry as ' + written.written.join(', ') + '. ' +
           (saml ? 'thumbprint=' + record.certificateThumbprint
                 : 'kid=' + record.kid) +
           ', valid until ' + record.notAfter + '. They can ' +
           (saml ? 'present an RFC 7522 section 2.1 SAML 2.0 assertion with ' +
                   '<Issuer> "' + (declared || identifier) + '" now, and its ' +
                   '<Subject> may name ONLY themselves'
                 : 'present an RFC 7523 section 2.1 assertion as `iss` "' +
                   (declared || identifier) + '" now, and it may name ONLY ' +
                   'themselves as `sub`') +
           ': a person\'s key is their own credential rather than permission ' +
           'to speak for anybody else, and an assertion from them about a ' +
           'third party is refused. **The private key is in this reply and ' +
           'this service will not hand it over again** — it is sealed on the ' +
           'entry and there is no read door for it, which is deliberate: the ' +
           'alternative was a console page that prints somebody\'s private ' +
           'key on every visit.'
    };
  }

  // Take a person's key pair off. It clears the DECLARATION with it, where an
  // application's control leaves `oauthAssertionIssuer` alone — because an
  // application may hold a JWKS it registered itself beside the one this
  // service issued, and a person may not: everything in `stsAssertion*` was put
  // there by the issue, so leaving the declaration would leave somebody
  // declared as an issuer with no key to issue with.
  //
  // ONE PROFILE's key pair, since 2026-09-13 — a person may hold both, and
  // taking one off leaves the other working, which is the application arm's
  // rule.
  private clearPerson(identifier: Json, purpose: Json) {
    const { log, personAssertions } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.clearPerson(). identifier=' + identifier +
              ' purpose=' + purpose);
    if (!identifier) {
      log.debug('Leaving PkiAdmin.clearPerson(). No name.');
      return self.refuse('Name the person to take the key pair off.',
                         'STS-PKI-0106');
    }
    if (!personAssertions.storable()) {
      log.debug('Leaving PkiAdmin.clearPerson(). No directory.');
      return self.refuse('This process has no directory, so nobody holds a ' +
                         'key pair to take off.', 'STS-PKI-0107');
    }
    const done = personAssertions.clear(identifier, purpose);
    if (done.unknown) {
      log.debug('Leaving PkiAdmin.clearPerson(). Nobody by that name.');
      return self.refuse('There is nobody called "' + identifier +
                         '" in the "' +
                         self.realmLabel() + '" realm.', 'STS-PKI-0109');
    }
    if (!done.ok) {
      log.debug('Leaving PkiAdmin.clearPerson(). Nothing to take off.');
      return self.refuse('Nothing was taken off "' + identifier +
                         '" — they hold no ' +
                         (purpose === 'saml' ? 'RFC 7522' : 'RFC 7523') +
                         ' key pair and declare no issuer for it. The other ' +
                         'profile\'s key pair, if they hold one, is ' +
                         'untouched either way.',
                         'STS-PKI-0111');
    }
    log.debug('Leaving PkiAdmin.clearPerson(). Cleared.');
    return { ok: true, target: 'person', person: identifier,
             purpose: purpose,
             removed: done.removed,
             why: 'The ' + (purpose === 'saml' ? 'RFC 7522' : 'RFC 7523') +
                  ' signing key pair was taken off "' + identifier +
                  '", and the issuer declaration with it — ' + done.removed +
                  ' attribute(s). **THIS IS NOT REVOCATION.** The ' +
                  'certificate is still valid, still chains to this realm\'s ' +
                  'Root and is on no list; what changed is that this service ' +
                  'will no longer accept an assertion signed with that key, ' +
                  'because the key is no longer registered against anybody. ' +
                  'A certificate this service issued to a person is still ' +
                  'refused as an authority over anybody else, which it was ' +
                  'before and is a property of the certificate rather than ' +
                  'of the entry.' };
  }

  // ---------------------------------------------------------------------------
  // A CERTIFICATE IN PLACE OF A PERSON'S KEY PAIR (2026-09-13). `pki.js`'s
  // `registerCertificate()` decides the chain exactly as it does for an
  // application — with `subjectKind: 'person'`, so a certificate this realm
  // issued must name THIS person — and `person_assertions.write()` puts the
  // record on the entry through the set the issue writes, with an empty private
  // key that clears the one an earlier issue left. No private key comes back,
  // because none was given: the person holds it.
  // ---------------------------------------------------------------------------
  private async uploadForPerson(identifier: Json, body: Json) {
    const { log, pki, personAssertions } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.uploadForPerson(). identifier=' + identifier);
    if (!identifier) {
      log.debug('Leaving PkiAdmin.uploadForPerson(). No name.');
      return self.refuse('Name the person the certificate is for.',
                         'STS-PKI-0106');
    }
    if (!personAssertions.storable()) {
      log.debug('Leaving PkiAdmin.uploadForPerson(). No directory.');
      return self.refuse('This process has no directory, so there is nowhere ' +
                         'to put a person\'s certificate.', 'STS-PKI-0107');
    }
    const purpose = self.purposeOf(body);
    if (!purpose) {
      log.debug('Leaving PkiAdmin.uploadForPerson(). An unknown profile.');
      return self.refuse('"' + body.purpose +
                         '" is not a profile a person may hold a key pair ' +
                         'for. There are ' +
                         pki.PURPOSE_IDS.join(' and ') + '.', 'STS-PKI-0011');
    }
    if (!personAssertions.recordFor(identifier)) {
      log.debug('Leaving PkiAdmin.uploadForPerson(). Nobody by that name.');
      return self.refuse('There is nobody called "' + identifier +
                         '" in the "' + self.realmLabel() +
                         '" realm. Create them on /admin/users first.',
                         'STS-PKI-0109');
    }
    const registered = await pki.registerCertificate(undefined, {
      identifier: identifier,
      purpose: purpose,
      subjectKind: 'person',
      certificatePem: body.certificate,
      chainPem: body.chain
    });
    if (!registered.ok) {
      log.debug('Leaving PkiAdmin.uploadForPerson(). The upload was refused.');
      return self.refusedBy(registered, 'STS-PKI-0140');
    }
    const record = registered.registered;
    const written = personAssertions.write(identifier, record,
                                           { purpose: purpose });
    if (!written.ok) {
      log.debug('Leaving PkiAdmin.uploadForPerson(). The write failed.');
      return self.refusedBy(written, 'STS-PKI-0110');
    }
    const names = personAssertions.KEY_PAIR_ATTRIBUTES[purpose];
    log.debug('Leaving PkiAdmin.uploadForPerson(). Uploaded.');
    return { ok: true,
             target: 'person',
             person: identifier,
             purpose: purpose,
             source: record.source,
             attributes: written.written.slice(),
             kid: record.kid,
             thumbprint: record.certificateThumbprint,
             subject: record.subject,
             issuer: record.issuer,
             chain: record.chainSubjects.slice(),
             notAfter: record.notAfter,
             revocation: record.revocation,
             why: 'The certificate "' + record.subject + '", issued by "' +
                  record.issuer + '", replaced the ' +
                  pki.purposeFor(purpose).label + ' key pair on "' +
                  identifier + '" — a PERSON — (' +
                  (record.source === 'uploaded-realm-ca'
                    ? 'this realm\'s own certificate authority issued it to ' +
                      'them'
                    : 'an external certificate authority issued it, and its ' +
                      'chain of ' + record.chainSubjects.length +
                      ' certificate(s) up to a self-signed root verified') +
                  '). ' + names.handleLabel + '=' +
                  (purpose === 'saml' ? record.certificateThumbprint
                                      : record.kid) +
                  ', valid until ' + record.notAfter +
                  '. The person holds the private key and this service holds ' +
                  'none; any key pair issued to them here before is gone ' +
                  'from the entry. An assertion signed with it may name ONLY ' +
                  'them.' };
  }

  async pkiAction(body: Json) {
    const { log, config, pki, pkiRevocation, authoring, applications,
            errorCodes } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.pkiAction(). action=' + (body && body.action));
    const action = String((body && body.action) || '');

    // =====================================================================
    // A SCOPED ACTION MAY ONLY NAME A BRANCH THIS REALM CAN SEE (2026-09-11).
    //
    // The seven actions below carry a `scope`, and until this change any of
    // them would act on any realm's branch — which was harmless while the page
    // drew every branch and is not now. **A page that hides a branch and an
    // action that still edits it is the worse of the two halves**: the operator
    // cannot see what they changed, and the realm switcher — which is this
    // console's one answer to "which realm am I acting on" — stops being the
    // answer for this page alone.
    //
    // It is a REFUSAL and not a silent redirection to this realm's own branch:
    // a caller that named `acme` meant `acme`, and quietly rebuilding the
    // default realm's Intermediate instead is the one outcome worse than saying
    // no. The sentence names the switcher, because that is the way to do what
    // was asked.
    //
    // `*service` and `*process` pass — they are not realms, they are drawn in
    // every realm, and `scopeVisible()` is the one place that is decided.
    if (SCOPED_ACTIONS.indexOf(action) >= 0 &&
        !self.scopeVisible(self.scopeFrom(body))) {
      log.debug('Leaving PkiAdmin.pkiAction(). A scope this realm does not ' +
                'draw.');
      return self.refuse('That action names the "' + self.scopeFrom(body) +
                         '" branch, ' +
                         'and this page is the "' + self.realmLabel() +
                         '" realm\'s. A realm\'s certificate authority is ' +
                         'edited in that realm: switch to it with the realm ' +
                         'switcher and try again. The Root and the process ' +
                         'branch are the exception and may be edited from ' +
                         'any realm, because they belong to none.',
                         'STS-PKI-0112');
    }

    if (action === 'build') {
      const years = {};
      pki.TIER_IDS.forEach(function (tier) {
        const asked = Number(body['years_' + tier]);
        if (isFinite(asked) && asked > 0) {
          years[tier] = Math.floor(asked);
        }
      });
      const commonNames = {};
      pki.TIER_IDS.forEach(function (tier) {
        const cn = String(body['cn_' + tier] || '').trim();
        if (cn) {
          commonNames[tier] = cn;
        }
      });
      const built = await pki.buildChain(undefined, {
        // The FORM wins over the setting and the setting is the default, which
        // is the shape every settings-backed control in this console has. An
        // empty `pki.signatureAlgorithm` means "the right one for the key
        // algorithm" — see that row's description for why a fixed value there
        // is wrong for EC. The signature algorithm's default is applied by
        // `pki.js`'s `algorithmsFrom()`, not here (#181): it reads the setting
        // AS IN FORCE, so a SHA-1 value stored in a product realm is the
        // key's own default rather than a refused build, and skips a value
        // the key cannot produce, as every other build does.
        keyAlg: String(body.keyAlg || '').trim() ||
                config.value('pki.keyAlgorithm'),
        signatureAlg: String(body.signatureAlg || '').trim(),
        // Empty is the setting, read by `pki.js`'s algorithmsFrom() (#68).
        altKeyAlg: String(body.altKeyAlg || '').trim() || undefined,
        organisation: String(body.organisation || '').trim() ||
                      config.value('pki.organisation'),
        country: String(body.country || '').trim(),
        commonNames: commonNames,
        years: years
      });
      if (!built.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The build failed.');
        return self.refusedBy(built, 'STS-PKI-0105');
      }
      // -----------------------------------------------------------------------
      // **AND WHAT THE OLD BRANCH HAD CERTIFIED FOR THIS REALM'S OWN KEYS IS
      // RE-MINTED FROM THE NEW ONE (2026-09-15, #46)** — as `build-scope` below
      // and `rebuildEveryScope()` have always done, and as this action, the one
      // `POST /admin-api/pki/build` reaches, never did.
      //
      // A rebuild replaces the Intermediate and every Issuing CA and KEEPS the
      // row's recorded certificates (`buildScopeNow()` carries the row over, so
      // the workbench's objects survive). The realm's JWKS `x5c`, its SAML
      // metadata and every signature header then went on publishing the signing
      // keys' certificates from the SUPERSEDED Issuing CAs, with those CAs and
      // the old Intermediate beside them in the chain — the old Issuing CAs are
      // on the new Intermediate's revocation list, and name the same
      // `intermediate.crl` address as the new ones, so one list was named by
      // certificates of two issuers. `sts_pki_distribution_points` is what saw
      // it.
      //
      // **IT WAS ALWAYS THERE AND WAS HIDDEN BY WHEN A RUNTIME REALM'S KEYS
      // WERE MADE.** Until #46 they were made by the first handler that read
      // them, which for a realm created and then rebuilt at once was AFTER the
      // rebuild, so nothing had been certified from the old branch. `app.js`
      // now makes the request realm's key set before the handler, so the realm
      // watcher's `certifyKeySet()` finds them held and certifies them from the
      // branch the rebuild is about to replace — a whole branch of stale
      // certificates, every time. A certification still IN FLIGHT when the
      // rebuild lands is `certify()`'s to catch, and it does.
      // -----------------------------------------------------------------------
      const remint = await self.recertifyScope(self.scopeFrom({}));
      log.debug('Leaving PkiAdmin.pkiAction(). Built.');
      return { ok: true,
               why: 'A three-tier certificate authority was built for the "' +
                    self.realmLabel() + '" realm, and ' + remint +
                    ' certificate(s) this realm\'s own signing keys publish ' +
                    'were re-minted from it. Anything else issued from a ' +
                    'PREVIOUS hierarchy now chains to nothing — this service ' +
                    'keeps no copy of what it issued, so none of it can be ' +
                    'listed.',
               chain: built.chain };
    }

    if (action === 'clear') {
      const cleared = pki.clearChain();
      if (!cleared.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). Nothing to clear.');
        return self.refusedBy(cleared, 'STS-PKI-0105');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Cleared.');
      return { ok: true,
               why: 'The "' + self.realmLabel() +
                    '" realm\'s certificate authority ' +
                    'was removed. ' + cleared.issuedCount + ' certificate(s) ' +
                    'were issued from it and every one of them now chains to ' +
                    'nothing. The key pairs are still on the application ' +
                    'entries and will still SIGN — what stopped is this ' +
                    'service being able to see that it issued them.' };
    }

    if (action === 'issue') {
      const identifier = String(body.identifier || '').trim();
      const target = self.targetOf(body);
      if (!target) {
        log.debug("Leaving PkiAdmin.pkiAction().");
        return self.refuse('"' + body.target +
                           '" is not a kind of subject this service issues a ' +
                           'signing key pair to. It issues to ' +
                           pki.SUBJECT_KIND_IDS.join(' and ') +
                           ' — an application, which may then assert about ' +
                           'anybody it is trusted to assert about, and a ' +
                           'person, whose key may only assert about ' +
                           'themselves.', 'STS-PKI-0012');
      }
      if (target === 'person') {
        log.debug("Leaving PkiAdmin.pkiAction().");
        return await self.issueToPerson(identifier, body);
      }
      if (!identifier) {
        log.debug("Leaving PkiAdmin.pkiAction().");
        return self.refuse('Name the application the key pair is for.',
                           'STS-PKI-0113');
      }
      const entry = applications.get(identifier);
      if (!entry) {
        log.debug("Leaving PkiAdmin.pkiAction().");
        // Refused rather than creating one, which is the opposite of what
        // `seen()` does and is right here: `seen()` records something that
        // PRESENTED an identifier, and this would be inventing an application
        // in order to give it a credential.
        return self.refuse('There is no application "' + identifier +
                           '" in this realm. Create it on ' +
                           '/admin/applications first — issuing a signing ' +
                           'key to an application nobody has registered ' +
                           'would be this page inventing one in order to ' +
                           'give it a credential.', 'STS-PKI-0114');
      }
      const purpose = self.purposeOf(body);
      if (!purpose) {
        log.debug("Leaving PkiAdmin.pkiAction().");
        return self.refuse('"' + body.purpose +
                           '" is not a profile this service issues a signing ' +
                           'key pair for. It issues ' +
                           pki.PURPOSE_IDS.join(' and ') +
                           ' — RFC 7523\'s JWT assertion and RFC 7522\'s ' +
                           'SAML 2.0 assertion, which are separate key pairs ' +
                           'on purpose.',
                           'STS-PKI-0011');
      }
      const days = Number(body.days);
      const issued = await pki.issueSigningKeyPair(undefined, {
        identifier: identifier,
        purpose: purpose,
        commonName: String(body.commonName || '').trim() || identifier,
        keyAlg: self.leafKeyAlgOf(body),
        days: isFinite(days) && days > 0 ? Math.floor(days)
                                         : config.value('pki.leafLifetimeDays')
      });
      if (!issued.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The issue failed.');
        return self.refusedBy(issued, 'STS-PKI-0105');
      }
      const record = issued.issued;
      // ---------------------------------------------------------------------
      // ONTO THE ENTRY, and this is the only place any of it is written down.
      // `common/pki.js` forgot the private key on the way out of that call, so
      // if any of these writes fails the key pair is GONE — which is why they
      // are done together and why a failure reports which one. WHICH writes is
      // PURPOSE_WRITES's, above: seven for RFC 7523 and six for RFC 7522
      // (both counting the provenance attribute since 2026-09-13), and the
      // difference is that SAML has no JWKS.
      // ---------------------------------------------------------------------
      const writes = self.purposeWrites[purpose].valuesOf(record);
      for (let i = 0; i < writes.length; i++) {
        const done = applications.updateApplication(identifier, {
          attribute: writes[i][0], mode: 'set', value: writes[i][1]
        });
        if (!done || done.ok === false) {
          log.error(errorCodes.tag('STS-PKI-0115') + 'pki_admin: a signing ' +
                                                     'key pair was issued ' +
                                                     'for "' +
                    identifier + '" and ' + writes[i][0] + ' could not be ' +
                    'written: ' + ((done && done.errors) || []).join(' ') +
                    '. The private key is not stored anywhere else and is ' +
                    'now lost; issue again.');
          log.debug("Leaving PkiAdmin.pkiAction().");
          return self.refuse('The key pair was issued and `' + writes[i][0] +
                             '` could not be written to the application ' +
                             'entry: ' +
                             ((done && done.errors) || []).join(' ') +
                             ' This service keeps no second copy of a ' +
                             'private key, so that key pair is gone. Issue ' +
                             'again.',
                             'STS-PKI-0115');
        }
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Issued.');
      const table = self.purposeWrites[purpose];
      log.debug("Leaving PkiAdmin.pkiAction().");
      return { ok: true,
               why: 'A ' + record.keyAlg + ' signing key pair was issued to "' +
                    identifier + '" for ' + record.purposeLabel +
                    ', signed by this realm\'s Issuing CA, and written onto ' +
                    'its entry. ' +
                    table.handleLabel + '=' +
                    (purpose === 'saml' ? record.certificateThumbprint
                                        : record.kid) + ', ' +
                    'valid until ' + record.notAfter +
                    '. It can sign a client assertion now; for it to be ' +
                    'accepted as an AUTHORIZATION grant, declare the issuer ' +
                    'it will use on ' +
                    table.issuerAttribute + '. This is a SEPARATE key pair ' +
                    'from the other profile\'s — an application may hold ' +
                    'both, and neither can sign for the other.',
               purpose: purpose,
               attributes: table.attributes.slice(),
               kid: record.kid,
               thumbprint: record.certificateThumbprint,
               notAfter: record.notAfter,
               jwsAlg: record.jwsAlg };
    }

    // =======================================================================
    // UPLOAD A CERTIFICATE IN PLACE OF THE KEY PAIR (2026-09-13).
    //
    // The other way an application's RFC 7523 or RFC 7522 key pair is replaced,
    // beside `issue`: the application generated its own key pair and brings the
    // certificate. `common/pki.js`'s `registerCertificate()` decides whether
    // the chain is complete and verifies — this realm's own authority may be
    // represented by the leaf alone, anybody else's must arrive with every
    // intermediate and a self-signed root — and hands back a record in the
    // issue's shape with an EMPTY private key, so the writes below are
    // PURPOSE_WRITES's, the same table an issue writes through.
    //
    // **THE EMPTY PRIVATE KEY IS WRITTEN, AND THAT IS WHAT MAKES IT A
    // REPLACEMENT.** Leaving the issued key pair's private half on the entry
    // beside somebody else's certificate would be an entry holding a key for a
    // certificate it does not match — and `/admin/applications` would go on
    // handing it out as though it signed for this application.
    //
    // ~~APPLICATIONS ONLY.~~ **A PERSON TOO, SINCE 2026-09-13**, with
    // `target=person`. This read: *an upload door for somebody else's entry
    // would be an operator registering a key a person never saw.* The concern
    // is the private key, and an upload carries none — the person generated the
    // key pair and holds it, and what an operator registers is the certificate
    // they were issued, by this realm or by an authority the whole chain names.
    // What an upload cannot do for a person is widen them: the grant still
    // holds their key to assertions about themselves, and a certificate this
    // realm issued to somebody ELSE is refused by name (`STS-PKI-0155`).
    // =======================================================================
    if (action === 'upload-certificate') {
      const identifier = String(body.identifier || '').trim();
      const target = self.targetOf(body);
      if (!target) {
        log.debug("Leaving PkiAdmin.pkiAction(). An unknown target.");
        return self.refuse('"' + body.target + '" is not a kind of subject a ' +
                           'certificate is registered for. There are ' +
                           pki.SUBJECT_KIND_IDS.join(' and ') + '.',
                           'STS-PKI-0012');
      }
      if (target === 'person') {
        log.debug("Leaving PkiAdmin.pkiAction().");
        return await self.uploadForPerson(identifier, body);
      }
      if (!identifier) {
        log.debug("Leaving PkiAdmin.pkiAction().");
        return self.refuse('Name the application the certificate is for.',
                           'STS-PKI-0113');
      }
      if (!applications.get(identifier)) {
        log.debug("Leaving PkiAdmin.pkiAction(). No such application.");
        return self.refuse('There is no application "' + identifier +
                           '" in this realm. Create it on ' +
                           '/admin/applications first.',
                           'STS-PKI-0114');
      }
      const purpose = self.purposeOf(body);
      if (!purpose) {
        log.debug("Leaving PkiAdmin.pkiAction().");
        return self.refuse('"' + body.purpose +
                           '" is not a profile this service registers a ' +
                           'signing certificate for. It registers ' +
                           pki.PURPOSE_IDS.join(' and ') + '.', 'STS-PKI-0011');
      }
      const registered = await pki.registerCertificate(undefined, {
        identifier: identifier,
        purpose: purpose,
        certificatePem: body.certificate,
        chainPem: body.chain
      });
      if (!registered.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The upload was refused.');
        return self.refusedBy(registered, 'STS-PKI-0140');
      }
      const record = registered.registered;
      const table = self.purposeWrites[purpose];
      // THE PRIVATE KEY GOES FIRST: a write that failed after it would leave
      // the OLD certificate with no private key on the entry, which refuses
      // rather than signs — where the other order could leave a new certificate
      // beside an old key.
      const writes = table.valuesOf(record).sort(function (a, b) {
        return (a[0] === table.privateKeyAttribute ? -1 : 0) -
               (b[0] === table.privateKeyAttribute ? -1 : 0);
      });
      for (let i = 0; i < writes.length; i++) {
        const done = applications.updateApplication(identifier, {
          attribute: writes[i][0], mode: 'set', value: writes[i][1]
        });
        if (!done || done.ok === false) {
          log.error(errorCodes.tag('STS-PKI-0154') +
                    'pki_admin: a certificate ' +
                    'uploaded for "' + identifier + '" could not be written: ' +
                    writes[i][0] + ': ' +
                    ((done && done.errors) || []).join(' '));
          log.debug("Leaving PkiAdmin.pkiAction(). A write failed.");
          return self.refuse('The certificate verified and `' + writes[i][0] +
                             '` could not be written to the application ' +
                             'entry: ' +
                             ((done && done.errors) || []).join(' ') +
                             ' The entry may hold part of the upload; upload ' +
                             'again.',
                             'STS-PKI-0154');
        }
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Uploaded.');
      return { ok: true,
               purpose: purpose,
               source: record.source,
               attributes: table.attributes.slice(),
               kid: record.kid,
               thumbprint: record.certificateThumbprint,
               subject: record.subject,
               issuer: record.issuer,
               chain: record.chainSubjects.slice(),
               notAfter: record.notAfter,
               revocation: record.revocation,
               why: 'The certificate "' + record.subject + '", issued by "' +
                    record.issuer + '", replaced the ' +
                    pki.purposeFor(purpose).label + ' key pair on "' +
                    identifier + '" (' +
                    (record.source === 'uploaded-realm-ca'
                      ? 'this realm\'s own certificate authority issued it'
                      : 'an external certificate authority issued it, and ' +
                        'its chain of ' + record.chainSubjects.length +
                        ' certificate(s) up to a self-signed root verified') +
                    '). ' + table.handleLabel + '=' +
                    (purpose === 'saml' ? record.certificateThumbprint
                                        : record.kid) +
                    ', valid until ' + record.notAfter + '. The application ' +
                    'holds the private key; this service holds none, and any ' +
                    'key pair issued here before is gone from the entry. For ' +
                    'it to be accepted as an AUTHORIZATION grant the issuer ' +
                    'it will use must be declared on ' + table.issuerAttribute +
                    '.' };
    }

    if (action === 'revoke') {
      const identifier = String(body.identifier || '').trim();
      const target = self.targetOf(body);
      if (!target) {
        log.debug("Leaving PkiAdmin.pkiAction().");
        return self.refuse('"' + body.target +
                           '" is not a kind of subject this service issues a ' +
                           'signing key pair to, so there is none of that ' +
                           'kind to take off. It issues to ' +
                           pki.SUBJECT_KIND_IDS.join(' and ') + '.',
                           'STS-PKI-0012');
      }
      if (target === 'person') {
        if (!self.purposeOf(body)) {
          log.debug("Leaving PkiAdmin.pkiAction(). An unknown profile.");
          return self.refuse('"' + body.purpose +
                             '" is not a profile a person may hold a key ' +
                             'pair for. There are ' +
                             pki.PURPOSE_IDS.join(' and ') + '.',
                             'STS-PKI-0011');
        }
        log.debug("Leaving PkiAdmin.pkiAction().");
        return self.clearPerson(identifier, self.purposeOf(body));
      }
      if (!identifier) {
        log.debug("Leaving PkiAdmin.pkiAction().");
        return self.refuse('Name the application to take the key pair off.',
                           'STS-PKI-0113');
      }
      const purpose = self.purposeOf(body);
      if (!purpose) {
        log.debug("Leaving PkiAdmin.pkiAction().");
        return self.refuse('"' + body.purpose +
                           '" is not a profile this service issues a signing ' +
                           'key pair for. It issues ' +
                           pki.PURPOSE_IDS.join(' and ') + '.', 'STS-PKI-0011');
      }
      // ONE PROFILE'S ATTRIBUTES AND NOT THE OTHER'S. An application commonly
      // holds both key pairs and this control takes ONE off; clearing both
      // would be a button whose label said one thing and did two.
      let removed = 0;
      self.purposeWrites[purpose].attributes.forEach(function (name) {
        const done = applications.updateApplication(identifier, {
          attribute: name, mode: 'set', value: ''
        });
        if (done && done.ok !== false) {
          removed += 1;
        }
      });
      if (!removed) {
        log.debug("Leaving PkiAdmin.pkiAction().");
        return self.refuse('Nothing was taken off "' + identifier +
                           '" — it has no key pair issued for that profile, ' +
                           'or there is no such application. The other ' +
                           'profile\'s key pair, if it holds one, is ' +
                           'untouched either way.',
                           'STS-PKI-0116');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Revoked.');
      return { ok: true,
               purpose: purpose,
               why: 'The ' + pki.purposeFor(purpose).label + ' key pair was ' +
                    'taken off "' + identifier +
                    '". The other profile\'s key pair, if it holds one, is ' +
                    'untouched. ' +
                    // **THIS SENTENCE HAD TO CHANGE ON 2026-09-11 AND THE
                    // DISTINCTION IT DREW DID NOT.** It read *THIS IS NOT
                    // REVOCATION AND THIS SERVICE HAS NO WAY TO REVOKE
                    // ANYTHING: it publishes no CRL and answers no OCSP.* The
                    // second half stopped being true; the first half is more
                    // important now than it was, because there IS a revocation
                    // control on this page and an operator who did this one
                    // could reasonably believe they had used it.
                    '**THIS IS NOT REVOCATION.** The certificate is still ' +
                    'valid, still chains to this realm\'s Root, and is NOT ' +
                    'on any revocation list — what changed is that this ' +
                    'service will no longer accept an assertion signed with ' +
                    'that key, because the key is no longer registered ' +
                    'against this application. To make this service\'s CRL ' +
                    'and OCSP responder say the certificate is revoked as ' +
                    'well, use the Revoke control in the revocation pane, ' +
                    'against the authority that issued it. Somebody dealing ' +
                    'with a compromised key pair wants both.' };
    }

    // =====================================================================
    // THE HIERARCHY'S OWN ACTIONS (2026-09-11): the Root, a scope's branch, one
    // use case's Issuing CA, and the two doors for material an operator
    // supplied.
    // =====================================================================
    if (action === 'build-root') {
      const built = await pki.buildRoot({
        keyAlg: String(body.keyAlg || '').trim() || undefined,
        altKeyAlg: String(body.altKeyAlg || '').trim() || undefined,
        commonName: String(body.commonName || '').trim() || undefined,
        organisation: config.value('pki.organisation'),
        years: Number(body.years) > 0 ? Number(body.years) : undefined
      });
      if (!built.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The Root failed.');
        return self.refusedBy(built, 'STS-PKI-0105');
      }
      // **AND EVERY BRANCH IS REBUILT UNDER IT, IN THE SAME ACT.** A new Root
      // with the old Intermediates still hanging from the old one is a service
      // whose tree does not chain to its own anchor — every path would be
      // refused and the page would show a Root and three branches that look
      // right. Rebuilding them here is what makes "replace the Root" mean what
      // the button says.
      const rebuilt = await self.rebuildEveryScope();
      log.debug('Leaving PkiAdmin.pkiAction(). A new Root.');
      return { ok: true,
               why: 'A new Root CA was built for this service, and ' + rebuilt +
                    ' branch(es) were re-issued under it so the whole tree ' +
                    'chains to it. ANYTHING TRUSTING THE OLD ROOT NO LONGER ' +
                    'TRUSTS THIS SERVICE — the new Root is on this page and ' +
                    'at GET /admin-api/pki. The signing keys themselves are ' +
                    'unchanged, so nothing that verifies against the ' +
                    'published JWKS is affected.',
               root: built.root };
    }

    if (action === 'build-scope') {
      const scope = self.scopeFrom(body);
      const built = await pki.buildScope(scope, {
        keyAlg: String(body.keyAlg || '').trim() || undefined,
        altKeyAlg: String(body.altKeyAlg || '').trim() || undefined,
        organisation: config.value('pki.organisation'),
        replaceImported: !!body.replaceImported
      });
      if (!built.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The branch failed.');
        return self.refusedBy(built, 'STS-PKI-0105');
      }
      const again = await self.recertifyScope(scope);
      log.debug('Leaving PkiAdmin.pkiAction(). A branch was built.');
      return { ok: true,
               why: 'That branch was rebuilt — a new Intermediate CA and a ' +
                    'new Issuing CA for every use case under it — and ' +
                    again + ' certificate(s) were re-minted from the new ' +
                    'authorities. The Root is untouched, because every other ' +
                    'scope hangs from it.' };
    }

    if (action === 'reissue-use-case') {
      const scope = self.scopeFrom(body);
      const useCaseId = String(body.useCase || '').trim();
      const done = await pki.reissueUseCase(scope, useCaseId);
      if (!done.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The reissue failed.');
        return self.refusedBy(done, 'STS-PKI-0105');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Reissued.');
      return { ok: true,
               why: 'The ' + useCaseId +
                    ' Issuing CA was re-issued from this scope\'s ' +
                    'Intermediate with a new key pair, and ' +
                    done.recertified + ' certificate(s) under it were ' +
                    're-minted from it. Every other use case is untouched, ' +
                    'which is the whole reason each has an authority of its ' +
                    'own.' };
    }

    if (action === 'recertify') {
      const scope = self.scopeFrom(body);
      const useCaseId = String(body.useCase || '').trim();
      const done = await pki.recertifyUseCase(scope, useCaseId);
      if (!done.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The renewal failed.');
        return self.refusedBy(done, 'STS-PKI-0105');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Renewed.');
      return { ok: true,
               why: done.recertified +
                    ' certificate(s) were renewed under the same ' + useCaseId +
                    ' Issuing CA, with fresh serials and a fresh validity ' +
                    'window. THE KEYS ARE UNTOUCHED — this is a renewal ' +
                    'rather than a regeneration, so nothing that verifies ' +
                    'against the published keys stops verifying.' };
    }

    if (action === 'import-ca') {
      const scope = self.scopeFrom(body);
      const useCaseId = String(body.useCase || '').trim();
      const done = await pki.importCa(scope, useCaseId, {
        certificatePem: String(body.certificatePem || ''),
        privateKeyPem: String(body.privateKeyPem || '')
      });
      if (!done.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The import was refused.');
        return self.refusedBy(done, 'STS-PKI-0105');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Imported.');
      return { ok: true, why: done.why };
    }

    if (action === 'pin-key') {
      const scope = self.scopeFrom(body);
      const done = await pki.pinKeyPair(scope,
                                        String(body.useCase || '').trim(),
                                        String(body.slot || '').trim(), {
        privateKeyPem: String(body.privateKeyPem || ''),
        certificatePem: String(body.certificatePem || '')
      });
      if (!done.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The pin was refused.');
        return self.refusedBy(done, 'STS-PKI-0105');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Pinned.');
      return { ok: true, why: done.why };
    }


    // =====================================================================
    // THE REVOCATION PANE'S TWO ACTIONS.
    //
    // **`revoke-certificate` IS NOT `revoke`, WHICH IS TWO BRANCHES ABOVE IT.**
    // The older one takes an application's key pair off its directory entry;
    // this one puts a serial on an issuer's certificate revocation list. They
    // share a word and nothing else, and the pane says so where an operator
    // reads it. The names are deliberately not `revoke` and `revoke-key`: this
    // action list is published — `GET /admin-api/pki` carries it and a machine
    // chooses from it — so renaming the existing one to make room would have
    // broken every caller that already had it, to fix a confusion the two
    // descriptions can carry instead.
    //
    // Both are THIN. The refusals, the idempotence, the earlier-entry-wins rule
    // and the `certificateHold`-only release all live in
    // `common/pki_revocation.js`, because they are statements about the
    // register rather than about a console — and a copy of any of them here
    // would be the half that eventually disagreed with the CRL this service
    // actually signs.
    // =====================================================================
    if (action === 'revoke-certificate') {
      // `scopeFrom()` and not `body.scope` raw: it is the one place this file
      // decides what a scope name means, and it already understands `*service`,
      // `*process`, a realm id, and the empty string meaning the realm this
      // request arrived in. A second reading here would be the one that got
      // `default` wrong.
      const scope = self.scopeFrom(body);
      const done = pkiRevocation.revoke(scope, String(body.ca || '').trim(), {
        serialHex: String(body.serialHex || '').trim(),
        reason: String(body.reason || '').trim() || 'superseded',
        subject: String(body.subject || '').trim(),
        note: String(body.note || '').trim()
      });
      if (!done.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The revocation was refused.');
        return self.refusedBy(done, 'STS-PKI-0105');
      }
      // **PUBLISHED TO THE DIRECTORY IMMEDIATELY, AND THE HTTP SIDE NEEDS
      // NOTHING.** A CRL is built and signed on demand at
      // `/pki/crl/{scope}/{ca}`, so the next fetch there already carries this
      // entry; the `ldap://` address in every certificate this
      // authority signed point at a DOCUMENT under `ou=crl`, and a document has
      // to be rewritten or it goes on saying what it said before. That
      // asymmetry is the whole reason this line exists and the reason there is
      // no matching one for HTTP.
      pkiRevocation.publishSoon(scope, String(body.ca || '').trim());
      // A PERSON'S CERTIFICATE REVOKED IS A CREDENTIAL CHANGE (#145). The
      // authority's register says whose it was; the issuer is the authority's
      // own subject, since that is what signed it. An application's, or one
      // this register never recorded, has no person to tell.
      if (!done.already) {
        const caId = String(body.ca || '').trim();
        const serial = pkiRevocation.normalSerial(done.entry.serialHex);
        const held = pki.issuedKeyPairsFor(scope, caId).filter(function (one) {
          return pkiRevocation.normalSerial(one.serialHex) === serial;
        })[0];
        if (held && held.subjectKind === 'person' && held.identifier) {
          let authority = '';
          try {
            const issuer = pki.describeIssuer(scope, caId);
            authority = stsCrypto.certificateIdentifiers(
              issuer && issuer.certificatePem).subject;
          } catch (e) {
            log.debug('Caught in PkiAdmin.pkiAction(): ' +
                      ((e && e.message) || e));
            // No authority to name: the event goes with the serial alone.
          }
          accountSignals.credentialChanged({ username: held.identifier,
            credentialType: 'x509', changeType: 'revoke',
            x509Issuer: authority, x509Serial: serial,
            initiatingEntity: 'admin', via: '/admin/pki',
            reasonAdmin: 'An administrator revoked the certificate ' + serial +
                         ' of ' + held.identifier + ' (' +
                         done.entry.reason + ').',
            reasonUser: 'A certificate of yours was revoked.' });
          // REVOKED FOR `keyCompromise` (#231): the key is known to somebody
          // else, which RISC 1.0 section 2.7 says as `credential-compromise`
          // beside the CAEP revoke above. A CA's own revocation, and what it
          // does to the certificates under it, is #244's.
          if (done.entry.reason === 'keyCompromise') {
            accountSignals.credentialCompromised({
              username: held.identifier, credentialType: 'x509',
              initiatingEntity: 'admin', via: '/admin/pki',
              reasonAdmin: 'An administrator revoked the certificate ' +
                           serial + ' of ' + held.identifier + ' because ' +
                           'its key was compromised.',
              reasonUser: 'A certificate of yours was revoked because its ' +
                          'key may be known to somebody else.' });
          }
        }
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Revoked.');
      return { ok: true, entry: done.entry, already: !!done.already,
               why: done.already
                 ? done.why
                 : 'Certificate ' + done.entry.serialHex + ' is on the "' +
                   String(body.ca || '') +
                   '" authority\'s revocation list as "' + done.entry.reason +
                   '". Its CRL and its OCSP responder say so from now on. ' +
                   'NOTHING ELSE CHANGED: whoever holds that key still holds ' +
                   'it, the certificate still chains, and this service does ' +
                   'not consult its own lists — so what this buys is that a ' +
                   'relying party which DOES check can now find out.' };
    }

    if (action === 'release-hold') {
      // `scopeFrom()` and not `body.scope` raw: it is the one place this file
      // decides what a scope name means, and it already understands `*service`,
      // `*process`, a realm id, and the empty string meaning the realm this
      // request arrived in. A second reading here would be the one that got
      // `default` wrong.
      const scope = self.scopeFrom(body);
      const done = pkiRevocation.release(scope, String(body.ca || '').trim(),
                                         String(body.serialHex || '').trim());
      if (!done.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The release was refused.');
        return self.refusedBy(done, 'STS-PKI-0105');
      }
      pkiRevocation.publishSoon(scope, String(body.ca || '').trim());
      log.debug('Leaving PkiAdmin.pkiAction(). Released.');
      return { ok: true,
               why: 'The hold on ' + String(body.serialHex || '').trim() +
                    ' is lifted and the serial is off that authority\'s ' +
                    'list. A validator that cached the previous CRL will go ' +
                    'on calling it revoked until that copy expires, which is ' +
                    'pki.crlLifetimeMinutes — a hold is the only reason RFC ' +
                    '5280 lets you undo, and even then the undoing is not ' +
                    'instantaneous anywhere but here.' };
    }

    // =====================================================================
    // THE CERTIFICATE & KEY CONFIGURATION PANE.
    //
    // Eight actions, and every one of them answers with a `draft` as well as a
    // verdict — the whole form, as it should be redrawn. That is what the
    // console's own POST renders (it answers a 200 page rather than going
    // through `respondToAction()`, for `/admin/users/new`'s reason: a redirect
    // carries a message on the query string and cannot carry a hundred and
    // fifteen fields), and it is what lets a machine driving `/admin-api` do
    // apply-profile, then issue, without keeping its own copy of the form.
    //
    // The MODEL is `common/pki_authoring.ts`. Nothing about a certificate is
    // decided here — including which values its closed fields take (#86).
    // =====================================================================
    if (['apply-profile', 'generate-keys', 'generate-alt-keys',
         'issue-certificate', 'use-key', 'export'].indexOf(action) >= 0) {
      const closedProblem =
        authoring.closedFieldProblem(authoring.draftFrom(body));
      if (closedProblem) {
        log.debug('Leaving PkiAdmin.pkiAction(). A closed field was ' +
                  'outside its set.');
        return closedProblem;
      }
    }
    if (action === 'apply-profile') {
      const draft = authoring.draftFrom(body);
      const applied = authoring.applyProfile(draft,
                                             String(body.pki_profile || ''));
      log.debug('Leaving PkiAdmin.pkiAction(). The profile was applied.');
      return { ok: true, draft: applied,
               why: 'The extension boxes, the default validity and the ' +
                    'Common Name now say what a ' +
                    ((authoring.profileFor(applied.pki_profile) || {}).label ||
                     applied.pki_profile) + ' carries, and the two algorithm ' +
                    'menus are narrowed to the ' +
                    authoring.pqModeFor(applied.pki_pq_mode).label +
                    ' approach. Nothing has been issued. A Common Name you ' +
                    'typed yourself is never overwritten.' };
    }

    if (action === 'generate-keys' || action === 'generate-alt-keys') {
      const made = await authoring.generateKeys(
        authoring.draftFrom(body),
        action === 'generate-alt-keys' ? 'alt' : 'main');
      if (!made.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The generation failed.');
        return self.refusedBy(made, 'STS-PKI-0105');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). A key pair was generated.');
      return made;
    }

    if (action === 'issue-certificate') {
      const issued = await authoring.issue(undefined,
                                           authoring.draftFrom(body));
      if (!issued.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The issue failed.');
        // THE DRAFT GOES BACK WITH THE REFUSAL, which is the whole reason this
        // page answers with a page: a form of a hundred and fifteen fields
        // redrawn empty because one line of a subjectAltName would not parse is
        // a page somebody would rather not have pressed the button on.
        return errorCodes.mark({ ok: false, errors: issued.errors,
                                 why: issued.errors.join(' '),
                                 draft: authoring.draftFrom(body) },
                               errorCodes.codeOf(issued) || 'STS-PKI-0105');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Issued ' + issued.object.id +
                '.');
      return issued;
    }

    if (action === 'use-key') {
      const loaded = await authoring.useStoredKey(
        undefined, authoring.draftFrom(body), self.objectIdOf(body));
      if (!loaded.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). No such key pair.');
        return self.refusedBy(loaded, 'STS-PKI-0105');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). A stored key pair was loaded.');
      return loaded;
    }

    if (action === 'remove-object') {
      const removed = pki.removeObject(undefined, self.objectIdOf(body));
      if (!removed.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). Nothing was removed.');
        return self.refusedBy(removed, 'STS-PKI-0105');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Removed.');
      return { ok: true, draft: authoring.draftFrom(body),
               why: 'That object and its key pair are gone. Anything it ' +
                    'ISSUED is kept — those certificates are still valid ' +
                    'documents — and will now say that their issuer is ' +
                    'missing.' };
    }

    if (action === 'clear-store') {
      const cleared = pki.clearObjects();
      if (!cleared.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). Nothing to clear.');
        return self.refusedBy(cleared, 'STS-PKI-0105');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). The store was emptied.');
      return { ok: true, draft: authoring.draftFrom(body),
               why: cleared.removed + ' key pair(s) and their certificates ' +
                    'were discarded. The hierarchy above is untouched, and ' +
                    'anything those keys signed is still a valid document ' +
                    'that still chains to whatever signed IT.' };
    }

    if (action === 'export') {
      // **THE CONSOLE DOES NOT COME THROUGH HERE** — `POST /admin/pki/export`
      // calls the model directly, because the answer there is the FILE. This
      // arm is `/admin-api`'s, where a caller wants JSON: the same export, with
      // the bytes base64'd and named. One function underneath either way.
      const written = await authoring.exportKeys(undefined,
                                                 authoring.draftFrom(body),
                                                 self.objectIdOf(body));
      if (!written.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The export was refused.');
        return self.refusedBy(written, 'STS-PKI-0105');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). ' + written.files.length +
                ' file(s).');
      return { ok: true, why: written.status,
               files: written.files.map(function (file) {
                 return { name: file.name, mime: file.mime,
                          base64: Buffer.isBuffer(file.data)
                            ? file.data.toString('base64')
                            : Buffer.from(typeof file.data === 'string'
                                ? file.data : file.data).toString('base64') };
               }) };
    }

    // ---------------------------------------------------------------------
    // **THE REFUSAL NAMES EVERY ACTION AND CARRIES AN `errors` ARRAY, AND BOTH
    // HALVES ARE READ BY A TEST RATHER THAN BEING STYLE.**
    // `tests/vendored/sts_admin_api_operations.js` matches
    // `Unknown action "x". <prose>: a, b, c.` out of `errors` on every action
    // resource this API declares, and `tests/vendored/admin_api.js` reads the
    // same sentence to check that every console action has an operation over
    // there — so a handler that phrased it its own way, or answered with a
    // `why` alone, would turn that parity check off for this resource with
    // nothing failing. The first version of this function did exactly that and
    // went red on its first run, which is what the check is for.
    //
    // The count comes from the list rather than being written out, for the same
    // reason: a fifth action added tomorrow cannot leave the sentence short by
    // one.
    // ---------------------------------------------------------------------
    log.debug('Leaving PkiAdmin.pkiAction(). Unknown action.');
    return self.refuse('Unknown action "' + action + '". The ' +
                       self.countWord(PKI_ACTIONS.length) + ' are: ' +
                       PKI_ACTIONS.join(', ') + '.', 'STS-PKI-0117');
  }

  // ---------------------------------------------------------------------------
  // THE PAGE.
  // ---------------------------------------------------------------------------
  private chainTable(chain: Json) {
    const self = this;
    const { log, certificateDialog, pqcBadge, admin, esc } = this.deps;
    log.debug('Entering PkiAdmin.chainTable().');
    if (!chain) {
      log.debug('Leaving PkiAdmin.chainTable(). No hierarchy.');
      return '';
    }
    const rows = chain.tiers.map(function (tier) {
      return '<tr>' +
        '<td><strong>' + esc(tier.label) + '</strong></td>' +
        '<td><code>' + esc(tier.subject) + '</code></td>' +
        '<td><code>' + esc(tier.serialHex.slice(0, 16)) +
        '&hellip;</code></td>' + '<td>' + esc(tier.notAfter.slice(0, 10)) +
          (tier.expired ? ' <strong>(expired)</strong>' : '') + '</td>' +
        '<td><code>' + esc(tier.keyAlg) + '</code> / <code>' +
          esc(tier.signatureAlg) + '</code>' +
          pqcBadge.badgeFor({ certificatePem: tier.certificatePem,
                              algorithms: [tier.keyAlg] }) +
          self.alternativeNote(tier) + '</td>' +
        '<td><code>' + esc(tier.thumbprint.slice(0, 16)) +
        '&hellip;</code><br>' +
        certificateDialog.link('/admin/pki', tier.thumbprint, 'pki-chain') +
        '</td></tr><tr><td ' +
        'colspan="6">' + admin.tip(tier.what,
          'What the ' + tier.label + ' is for') + '</td></tr>';
    }).join('');
    log.debug('Leaving PkiAdmin.chainTable().');
    return '<table><thead><tr><th>Tier</th><th>Subject</th><th>Serial</th>' +
           '<th>Expires</th><th>Key / signature</th><th>SHA-256</th></tr>' +
           '</thead><tbody>' + rows + '</tbody></table>';
  }

  private pemBlocks(chain: Json) {
    const { log, esc } = this.deps;
    log.debug('Entering PkiAdmin.pemBlocks().');
    if (!chain) {
      log.debug('Leaving PkiAdmin.pemBlocks(). No hierarchy.');
      return '';
    }
    // The certificates, in full, because the ONE thing a relying party has to
    // be given out of band is the Root — and a page that showed a thumbprint
    // and made somebody find the bytes elsewhere would be a page that stops at
    // the interesting part. They are public: a certificate is the half of a key
    // pair that is meant to be handed around.
    log.debug('Leaving PkiAdmin.pemBlocks().');
    return chain.tiers.map(function (tier) {
      return '<details><summary>' + esc(tier.label) +
        ' certificate (PEM)</summary><pre>' + esc(tier.certificatePem) +
        '</pre></details>';
    }).join('');
  }

  private algorithmOptions(json: Json, selected: Json) {
    const { log, esc } = this.deps;
    log.debug("Entering PkiAdmin.algorithmOptions().");
    log.debug("Leaving PkiAdmin.algorithmOptions().");
    return json.keyAlgorithms.map(function (one) {
      return '<option value="' + esc(one.id) + '"' +
        (one.id === selected ? ' selected' : '') + '>' + esc(one.label) +
        '</option>';
    }).join('');
  }

  // The alternative (post-quantum) key a tier holds beside its classical one
  // (#68, ITU-T X.509 clause 9.8). One labelled select, drawn on all three
  // build forms, so the console offers what `altKeyAlg` on the three
  // `/admin-api/pki` actions takes (rule 7).
  private alternativeField(json: Json, selected: Json) {
    const { log, esc, admin } = this.deps;
    log.debug("Entering PkiAdmin.alternativeField().");
    const chosen = String(selected || '') ||
                   String(this.deps.config.value('pki.alternativeKeyAlgorithm'));
    const options = (json.alternativeKeyAlgorithms || []).map(function (id) {
      return '<option value="' + esc(id) + '"' +
        (id === chosen ? ' selected' : '') + '>' +
        esc(id === 'none' ? 'none (classical only)' : id.toUpperCase()) +
        '</option>';
    }).join('');
    log.debug("Leaving PkiAdmin.alternativeField().");
    return '<label' + admin.tip('The post-quantum key each authority holds ' +
      'beside its classical one, in the alternative-key extensions of ' +
      'ITU-T X.509 (2019) clause 9.8. Every certificate the authority ' +
      'issues is then signed twice, and this service refuses one whose ' +
      'second signature is wrong or missing. "none" builds a classical-only ' +
      'authority, which a quantum-capable attacker can forge.') +
      '>Alternative key <select name="altKeyAlg">' + options +
      '</select></label> ';
  }

  // A tier's hybrid half (#68), under its classical algorithms: the key it
  // holds and the algorithm its own alternative signature was made with.
  private alternativeNote(tier: Json) {
    const { log, esc } = this.deps;
    log.debug("Entering PkiAdmin.alternativeNote().");
    if (!tier || !tier.altKeyAlg) {
      log.debug("Leaving PkiAdmin.alternativeNote(). Classical.");
      return '';
    }
    log.debug("Leaving PkiAdmin.alternativeNote().");
    return '<br><small>alt <code>' + esc(tier.altKeyAlg) + '</code>' +
      (tier.altSignatureAlg
        ? ' / signed <code>' + esc(tier.altSignatureAlg) + '</code>'
        : ' / no alternative signature') + '</small>';
  }

  private signatureOptions(json: Json, keyAlg: Json) {
    const { log, esc } = this.deps;
    log.debug('Entering PkiAdmin.signatureOptions(). keyAlg=' + keyAlg);
    // Every algorithm, with the ones this key cannot produce marked rather than
    // hidden — a dropdown that silently drops half its entries when another
    // field changes is a dropdown nobody can reason about with no script to
    // explain it. An impossible pair is refused at the build with the list
    // beside it, which is a sentence rather than a mystery.
    const kind = (json.keyAlgorithms.filter(function (one) {
      return one.id === keyAlg;
    })[0] || {}).kind;
    log.debug('Leaving PkiAdmin.signatureOptions().');
    return '<option value="">(the right one for the key algorithm)</option>' +
      json.signatureAlgorithms.map(function (one) {
        return '<option value="' + esc(one.id) + '">' + esc(one.label) +
          (one.kind !== kind ? ' — needs a ' + esc(one.kind) + ' key' : '') +
          (one.weak ? ' [weak, on purpose — refused in product mode]' : '') +
          '</option>';
      }).join('');
  }

  // ===========================================================================
  // THE CERTIFICATE & KEY CONFIGURATION PANE.
  //
  // The parent project's *PKI / X.509* page has one pane that is the whole act
  // — key pair, certificate fields, subject DN and twenty-two X.509v3
  // extensions, all of them inputs to one button — and this is that pane, drawn
  // by a server for a console with no script on it. `common/pki_authoring.ts`
  // carries the model and the argument for the shape; everything here is
  // markup.
  //
  // **IT IS ONE FORM AND THAT IS LOAD-BEARING.** Every field is re-posted by
  // every button, so *Apply the profile* can rewrite twenty-two extension boxes
  // without a draft being kept anywhere, and *Use this key pair* in the store
  // table below can load a key into the boxes WITHOUT discarding the subject
  // somebody has been typing. A second form around the store would have made
  // that last one impossible.
  //
  // **THE BUTTONS DO NOT SHARE A NAME.** `/admin/users/new` records what
  // happens when two submit buttons are both called `action`: the console suite
  // finds a form by the action it posts, `form.elements.action` becomes a
  // RadioNodeList whose value is empty, and the page's main button reads as a
  // control that reaches nothing. So the Issue button is unnamed behind a
  // hidden `action=issue-certificate`, and every other button has a name of its
  // own that `paneActionFrom()` reads FIRST.
  // ===========================================================================

  // A one-line text box, with the draft's value in it.
  private textField(draft: Json, name: Json, label: Json, title: Json,
                    extra?: Json) {
    const { log, admin, esc } = this.deps;
    log.debug("Entering PkiAdmin.textField().");
    log.debug("Leaving PkiAdmin.textField().");
    return '<label' + admin.tip(title) + '>' + esc(label) +
      ' <input type="text" name="' + esc(name) + '" value="' +
      esc(String(draft[name] === undefined ? '' : draft[name])) + '"' +
      (extra || '') + '></label> ';
  }

  // A textarea. `rows` is small everywhere on this pane on purpose: twenty-two
  // extension cards each with a four-line box is a page nobody can see the foot
  // of, and every one of these grammars is one item per line.
  private areaField(draft: Json, name: Json, label: Json, title: Json,
                    rows: Json, placeholder?: Json) {
    const { log, admin, esc } = this.deps;
    log.debug("Entering PkiAdmin.areaField().");
    log.debug("Leaving PkiAdmin.areaField().");
    return '<div class="pki-field"><label' + admin.tip(title) + '>' +
        esc(label) +
      '<textarea name="' + esc(name) + '" rows="' + (rows || 2) + '"' +
      (placeholder ? ' placeholder="' + esc(placeholder) + '"' : '') + '>' +
      esc(String(draft[name] === undefined ? '' : draft[name])) +
      '</textarea></label></div>';
  }

  // A checkbox. **AN UNTICKED BOX POSTS NOTHING**, which is what `draftFrom()`
  // reads a flag as, so there is deliberately no hidden companion field here: a
  // `<input type="hidden" value="0">` beside each would make every one of these
  // post twice and the last-one-wins parser would decide the answer.
  private checkField(draft: Json, name: Json, label: Json, title: Json) {
    const { log, admin, esc } = this.deps;
    log.debug("Entering PkiAdmin.checkField().");
    log.debug("Leaving PkiAdmin.checkField().");
    return '<label class="pki-flag"' + admin.tip(title) + '><input ' +
      'type="checkbox" name="' + esc(name) + '" value="1"' +
      (draft[name] ? ' checked' : '') + '> ' + esc(label) + '</label> ';
  }

  // A dropdown. `options` is `[{ value, label, group }]`; a group name puts the
  // option in an `<optgroup>`, which is how forty-one key algorithms become a
  // menu with landmarks in it rather than a scroll bar.
  private selectField(draft: Json, name: Json, label: Json, title: Json,
                      options: Json, extra?: Json) {
    const { log, admin, esc } = this.deps;
    log.debug("Entering PkiAdmin.selectField().");
    const current = String(draft[name] === undefined ? '' : draft[name]);
    let html = '';
    let group = null;
    options.forEach(function (one) {
      if (one.group !== group) {
        if (group !== null) {
          html += '</optgroup>';
        }
        group = one.group;
        if (group) {
          html += '<optgroup label="' + esc(group) + '">';
        }
      }
      html += '<option value="' + esc(one.value) + '"' +
        (one.value === current ? ' selected' : '') + '>' + esc(one.label) +
        '</option>';
    });
    if (group) {
      html += '</optgroup>';
    }
    log.debug("Leaving PkiAdmin.selectField().");
    return '<label' + admin.tip(title) + '>' + esc(label) +
      ' <select name="' + esc(name) + '"' + (extra || '') + '>' + html +
      '</select></label> ';
  }

  // One extension card: the head is the extension's own checkbox and its
  // critical flag, the body is whatever that extension carries.
  private extCard(head: Json, body: Json) {
    const { log } = this.deps;
    log.debug("Entering PkiAdmin.extCard().");
    log.debug("Leaving PkiAdmin.extCard().");
    return '<div class="pki-ext"><div class="pki-exthead">' + head + '</div>' +
      (body || '') + '</div>';
  }

  // The twenty-two cards, in RFC 5280's order and then the ones it does not
  // define. Every algorithm list in them is read from the encoder — the nine
  // keyUsage bits, the sixteen extendedKeyUsage purposes, the five Netscape
  // types — so a bit the encoder gains is a checkbox here the day it is added.
  private extensionCards(json: Json, draft: Json) {
    const { log, admin } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.extensionCards().');
    const cards = [];

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_bc', 'basicConstraints',
                      'Whether this certificate may act as a CA, and how ' +
                      'many CAs may follow it. RFC 5280 requires it to be ' +
                      'critical in a CA certificate.') +
      self.checkField(draft, 'pki_bc_critical', 'critical',
                      'RFC 5280: MUST be critical in a CA certificate.'),
      self.checkField(draft, 'pki_bc_ca', 'cA',
                      'This certificate may sign other certificates.') +
      self.textField(draft, 'pki_bc_pathlen', 'pathLenConstraint',
                     'How many further CA certificates may appear below this ' +
                     'one. 0 means it may only sign leaves. Empty means ' +
                     'unlimited.',
                     ' size="6" placeholder="(unlimited)"')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ku', 'keyUsage',
                      'What the certified key may be used for. RFC 5280 says ' +
                      'this SHOULD be critical.') +
      self.checkField(draft, 'pki_ku_critical', 'critical',
                      'RFC 5280: SHOULD be critical.'),
      '<div class="pki-flags">' +
      json.workbench.keyUsageBits.map(function (bit) {
        return self.checkField(draft, 'pki_ku_' + bit.name, bit.name, bit.what);
      }).join('') + '</div>'));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_eku', 'extendedKeyUsage',
                      'The purposes this certificate is for. A TLS client ' +
                      'refuses a server certificate without serverAuth; a ' +
                      'server refuses a client certificate without ' +
                      'clientAuth.') +
      self.checkField(draft, 'pki_eku_critical', 'critical',
                      'Marking this critical means a validator that does not ' +
                      'recognise one of the OIDs must reject the certificate.'),
      '<div class="pki-flags">' +
      json.workbench.extendedKeyUsages.map(function (one) {
        return self.checkField(draft, 'pki_eku_' + one.name, one.name, one.oid);
      }).join('') + '</div>' +
      self.areaField(draft, 'pki_eku_extra', 'Further OIDs (one per line)',
                     'For a purpose that is not one of the ' +
                     json.workbench.extendedKeyUsages.length + ' above.', 1,
                     '1.3.6.1.4.1.99999.1.1')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_skid', 'subjectKeyIdentifier',
                      'The SHA-1 of this certificate’s public key, RFC 5280 ' +
                      'section 4.2.1.2 method (1) — the same value every ' +
                      'other implementation computes, so key identifiers ' +
                      'match across tools.'), ''));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_akid', 'authorityKeyIdentifier',
                      'Identifies the ISSUER’s key, so a validator can find ' +
                      'the right CA certificate when several share a subject.'),
      self.checkField(draft, 'pki_akid_issuer_serial',
                      'also include authorityCertIssuer + serial',
                      'Also name the issuer’s own issuer and serial number. ' +
                      'Rarely needed, occasionally required.')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_san', 'subjectAltName',
                      'The names this certificate is for. For TLS this — not ' +
                      'the Common Name — is what a client checks.') +
      self.checkField(draft, 'pki_san_critical', 'critical',
                      'Should be critical when the subject DN is empty, and ' +
                      'only then.'),
      self.areaField(draft, 'pki_san', 'Names, one per line',
                     'dns:example.com — ip:10.0.0.1 or ip:2001:db8::1 — ' +
                     'email:user@example.com — uri:https://example.com/x — ' +
                     'upn:user@EXAMPLE.COM — krb5:host/x@EXAMPLE.COM — ' +
                     'rid:1.2.3.4 — dirname:CN=alt,O=Example — ' +
                     'othername:<oid>:<base64 DER>.',
                     2, 'dns:localhost\nip:127.0.0.1')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ian', 'issuerAltName',
                      'Alternative names for the issuer. Same syntax as ' +
                      'subjectAltName.') +
      self.checkField(draft, 'pki_ian_critical', 'critical',
                      'Should not normally be critical.'),
      self.areaField(draft, 'pki_ian', 'Names, one per line',
                     'The same syntax as subjectAltName above.', 1,
                     'uri:https://ca.example.com/')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_cdp', 'cRLDistributionPoints',
                      'Where to fetch the CRL that would revoke this ' +
                      'certificate. NOTE that this service publishes none: ' +
                      'the extension is a URL you are asserting, not a ' +
                      'promise this mock keeps.') +
      self.checkField(draft, 'pki_cdp_critical', 'critical',
                      'Rarely critical.'),
      self.areaField(draft, 'pki_cdp', 'URLs, one per line',
                     'Where the CRL that would revoke this certificate is ' +
                     'published.', 1, 'http://crl.example.com/issuing.crl')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_freshest', 'freshestCRL',
                      'Where to fetch the DELTA CRL. The same shape as ' +
                      'cRLDistributionPoints and a different extension.'),
      self.areaField(draft, 'pki_freshest', 'URLs, one per line',
                     'Where the delta CRL is published.', 1,
                     'http://crl.example.com/delta.crl')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_aia', 'authorityInfoAccess',
                      'Where to reach the issuer: its OCSP responder, and a ' +
                      'copy of its own certificate for a client that was ' +
                      'sent an incomplete chain.'),
      self.areaField(draft, 'pki_aia', 'Access descriptions, one per line',
                     'ocsp:<url>, caissuers:<url>, timestamping:<url>, ' +
                     'carepository:<url>, or <oid>:<url> for a method this ' +
                     'page does not name.', 2,
                     'ocsp:http://ocsp.example.com\n' +
                     'caissuers:http://example.com/ca.cer')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_sia', 'subjectInfoAccess',
                      'Services offered by the SUBJECT of this certificate, ' +
                      'rather than by its issuer.'),
      self.areaField(draft, 'pki_sia', 'Access descriptions, one per line',
                     'The same syntax as authorityInfoAccess above.', 1,
                     'carepository:http://example.com/certs/')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_policies', 'certificatePolicies',
                      'The policies this certificate was issued under, with ' +
                      'the two qualifiers RFC 5280 defines.') +
      self.checkField(draft, 'pki_policies_critical', 'critical',
                      'Critical means a validator that cannot process the ' +
                      'policy must reject the certificate.'),
      self.areaField(draft, 'pki_policies', 'Policies, one per line',
                     '<policy oid>, optionally followed by |cps=<uri> and ' +
                     '|notice=<text>. 2.5.29.32.0 is anyPolicy.', 2,
                     '1.3.6.1.4.1.99999.1.1|cps=https://example.com/cps' +
                     '|notice=Test certificates only')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_policy_mappings', 'policyMappings',
                      'Declares that one policy OID in the issuer’s domain ' +
                      'is equivalent to another in the subject’s. RFC 5280 ' +
                      'says this SHOULD be critical, and it is.'),
      self.areaField(draft, 'pki_policy_mappings', 'Mappings, one per line',
                     '<issuer policy oid>=<subject policy oid>.', 1,
                     '1.3.6.1.4.1.99999.1.1=1.3.6.1.4.1.88888.1.1')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_policy_constraints', 'policyConstraints',
                      'Requires an explicit policy, or inhibits policy ' +
                      'mapping, after a number of further certificates. RFC ' +
                      '5280: MUST be critical, and it is.'),
      self.textField(draft, 'pki_require_explicit_policy',
                     'requireExplicitPolicy',
                     'How many further certificates may appear before an ' +
                     'acceptable policy is required. Empty means it is not ' +
                     'set.',
                     ' size="6" placeholder="(not set)"') +
      self.textField(draft, 'pki_inhibit_policy_mapping',
                     'inhibitPolicyMapping',
                     'How many further certificates may still map policies. ' +
                     'Empty means it is not set.',
                     ' size="6" placeholder="(not set)"')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_name_constraints', 'nameConstraints',
                      'Limits the names a CA below this one may certify — ' +
                      'the extension that makes a private CA safe to trust. ' +
                      'RFC 5280: MUST be critical, and only meaningful in a ' +
                      'CA certificate.') +
      self.checkField(draft, 'pki_nc_critical', 'critical',
                      'RFC 5280: MUST be ' +
                                                            'critical.'),
      self.areaField(draft, 'pki_name_constraints', 'Constraints, one per line',
                     '"permit <name>" or "exclude <name>", using the ' +
                     'subjectAltName syntax. An IP constraint takes a PREFIX ' +
                     '(10.0.0.0/8): a name constraint’s iPAddress is the ' +
                     'address followed by its mask, which is the one place a ' +
                     'general name is not simply an address.', 2,
                     'permit dns:example.com\npermit ip:10.0.0.0/8\nexclude ' +
                     'dns:bad.example.com')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_inhibit_any', 'inhibitAnyPolicy',
                      'How many further certificates may still use the ' +
                      'anyPolicy OID. RFC 5280: MUST be critical, and it is.'),
      self.textField(draft, 'pki_inhibit_any_skip', 'skipCerts',
                     '0 means anyPolicy is not accepted below this ' +
                     'certificate at all.', ' size="6" placeholder="0"')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_pkup', 'privateKeyUsagePeriod',
                      'A validity period for the PRIVATE key that is shorter ' +
                      'than the certificate’s — signatures made after it are ' +
                      'not to be trusted, while the certificate goes on ' +
                      'validating them.'),
      self.textField(draft, 'pki_pkup_not_before', 'notBefore',
                     'When the private key may start signing. Encoded as a ' +
                     'GeneralizedTime in UTC. Empty leaves it out.',
                     ' size="18" placeholder="2026-01-01T00:00"') +
      self.textField(draft, 'pki_pkup_not_after', 'notAfter',
                     'When the private key must stop signing — earlier than ' +
                     'the certificate’s own notAfter, which goes on ' +
                     'validating what was signed before it. Empty leaves it ' +
                     'out.',
                     ' size="18" placeholder="2027-01-01T00:00"')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_tls_feature', 'TLS Feature (RFC 7633)',
                      'The TLS extensions a server promises to support. 5 is ' +
                      'status_request — "must-staple"; 17 is ' +
                      'status_request_v2.'),
      self.areaField(draft, 'pki_tls_feature',
                     'Extension numbers, one per line',
                     'One TLS extension number per line.', 1, '5')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ocsp_nocheck', 'id-pkix-ocsp-nocheck',
                      'Tells a validator not to check the revocation status ' +
                      'of this certificate — correct on an OCSP responder’s ' +
                      'own certificate and almost nowhere else.'), ''));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ns_cert_type',
                      'Netscape certificate type',
                      'A pre-RFC 5280 relic that some old appliances still ' +
                      'read. Kept for the same reason SHA-1 is: this is ' +
                      'where you find out.'),
      '<div class="pki-flags">' +
      json.workbench.netscapeTypes.map(function (one) {
        return self.checkField(draft, 'pki_ns_' + one.name, one.name, '');
      }).join('') + '</div>'));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ns_comment', 'Netscape comment',
                      'A free-text comment some tools display when showing ' +
                      'the certificate.'),
      self.textField(draft, 'pki_ns_comment', 'Comment', 'Free text.',
                     ' size="40" placeholder="Issued by the mock STS"')));

    cards.push(self.extCard(
      '<strong' + admin.tip('Any extension at all, by OID and base64 DER — ' +
      'including one this page has never heard of. Without this the ' +
      'extension set would be whatever this page happens to know about, ' +
      'which is not what a debugging tool is for.') +
      '>Any other extension</strong>',
      self.areaField(draft, 'pki_custom_extensions', 'One per line',
                     '<oid>|<critical or ->|<base64 DER of the extension ' +
                     'value>. The value is the DER of the extnValue’s ' +
                     'contents, not the OCTET STRING wrapping it.', 2,
                     '1.3.6.1.4.1.99999.7.7|-|DANDYWJj')));

    log.debug('Leaving PkiAdmin.extensionCards(). ' + cards.length +
              ' card(s).');
    return '<div class="pki-extlist">' + cards.join('') + '</div>';
  }

  // The Issue a Certificate column: what kind of certificate this is, who signs
  // it, how, with what serial and for how long.
  private certificateColumn(json: Json, draft: Json) {
    const { log, admin, esc } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.certificateColumn().');
    const wb = json.workbench;
    const profile = wb.profiles.filter(function (one) {
      return one.id === draft.pki_profile;
    })[0] || {};
    const mode = wb.pqModes.filter(function (one) {
      return one.id === wb.pqMode;
    })[0] || wb.pqModes[0];
    const issuerOptions = [{ value: '', label: wb.issuers.length
      ? '(choose one)' : '(no certificate authority in this realm yet)' }]
      .concat(wb.issuers.map(function (one) {
        return { value: one.id, label: one.label };
      }));
    const html =
      '<div class="pki-col">' +
      '<div class="pki-group">Issue a Certificate</div>' +
      admin.note(
        'The profile sets the extensions below to what that kind of ' +
        'certificate normally carries; every one of them is then editable, ' +
        'which is the point &mdash; issuing the certificate that is wrong in ' +
        'exactly one way is how you find out what refuses it and what does ' +
        'not. <strong>Pressing <em>Apply the profile</em> rewrites the ' +
        'extension boxes</strong>, because on this console the form IS the ' +
        'extension set: a profile that changed what gets issued and not what ' +
        'is shown would be a page that lies about what it is about to do.',
        'What the profile does, and why every field it sets stays editable') +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_profile', 'Profile',
                       'What kind of certificate this is. It sets the ' +
                       'default extensions, the default validity, and ' +
                       'whether it is self-signed.',
                       // **THE LABEL IS THE PROFILE'S OWN AND NOTHING IS
                       // APPENDED TO IT.** `root-ca` is already called "Root CA
                       // (self-signed)" in the encoder's table, so a page
                       // adding its own "(self-signed)" printed it twice —
                       // which is what happens every time a renderer restates a
                       // fact the table it is reading already carries.
                       wb.profiles.map(function (one) {
                         return { value: one.id, label: one.label };
                       })) +
      '<button type="submit" name="defaults" value="1"' +
        admin.tip('Rewrite the extension boxes, the default validity and the ' +
                  'profile\'s Common Name from the profile chosen beside ' +
                  'this button. Nothing is issued and a name you typed is ' +
                  'kept.') +
        '>Apply the profile</button>' +
      '</div>' +
      (profile.selfSigned
        ? admin.note('<strong>' + esc(profile.label) + ' is ' +
          'SELF-SIGNED</strong>, so the key pair below signs its own ' +
          'certificate and <em>Signed by</em> is ignored. A "root" signed by ' +
          'something else is an intermediate.')
        : '') +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_issuer', 'Signed by',
                       'The certificate authority that signs this ' +
                       'certificate. Only authorities whose private key is ' +
                       'still in this service are listed — one whose key was ' +
                       'never kept cannot sign. The three tiers come from ' +
                       'the hierarchy above; anything else is a CA issued ' +
                       'from this pane.', issuerOptions) +
      '</div>' +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_pq_mode', 'Cryptographic Approach',
                       'Which of the three ways this certificate carries ' +
                       'post-quantum cryptography. It filters the Key ' +
                       'Algorithm list beside this column and narrows the ' +
                       'Signature Algorithm below; Hybrid additionally uses ' +
                       'the alternative key pair, which goes into the X.509 ' +
                       '(2019) alternative-signature extensions.',
                       wb.pqModes.map(function (one) {
                         return { value: one.id, label: one.label };
                       })) +
      '<button type="submit" name="defaults" value="1"' +
        admin.tip('Redraw the two algorithm menus for the approach chosen ' +
                  'beside this button. It is the same button as the one ' +
                  'above it: with no script on this console, narrowing a ' +
                  'menu is a round trip.') + '>Apply</button>' +
      '</div>' +
      admin.note(esc(mode.note), mode.label) +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_sig_alg', 'Signature Algorithm',
                       'The algorithm the ISSUER signs with. The list is ' +
                       'what the signing key can actually produce' +
                       (wb.signerLabel ? ' — it is ' + wb.signerLabel + ' — ' :
                        ' ') +
                       'because an RSA key cannot make an ECDSA signature ' +
                       'and offering it produces a Web Crypto error that ' +
                       'names neither.',
                       [{ value: '',
                       label: '(the right one for the signing key)' }]
                    .concat(wb.signatureAlgorithms.map(function (one) {
                      return { value: one.id,
                               label: one.label + (one.weak
                                 ? ' [weak, on purpose]' : '') };
                    }))) +
      '</div>' +
      '<div class="pki-row">' +
      self.textField(draft, 'pki_serial', 'Serial Number (hex)',
                     'Hex, and editable. A random 128-bit positive serial is ' +
                     'filled in for you and a fresh one replaces it after ' +
                     'every issue — that is what the CA/Browser Forum ' +
                     'requires, and what makes a collision on the signed ' +
                     'bytes impractical to arrange. Cleared, one is ' +
                     'generated at issue time anyway.', ' size="36"') +
      self.textField(draft, 'pki_validity_years', 'Validity (years)',
                     'Counted from Not Before, and used only when Not After ' +
                     'below is empty. The profile sets it — 20 for a root, ' +
                     '10 for an intermediate, 5 for an issuing CA, 1 for a ' +
                     'leaf.', ' size="5"') +
      '</div>' +
      '<div class="pki-row">' +
      self.textField(draft, 'pki_not_before', 'Not Before',
                     'Optional — empty means the moment the button is ' +
                     'pressed. Anything Date can read; what is encoded is ' +
                     'the instant, in UTC. A date at or after 2050 is ' +
                     'encoded as a GeneralizedTime, as RFC 5280 requires — a ' +
                     'UTCTime there is read as 1950, i.e. a certificate that ' +
                     'expired seventy years ago.',
                     ' size="20" placeholder="2026-01-01T00:00"') +
      self.textField(draft, 'pki_not_after', 'Not After',
                     'Optional — empty means Not Before plus the validity in ' +
                     'years beside it.',
                     ' size="20" placeholder="(Not Before + validity)"') +
      '</div>' +
      '</div>';
    log.debug('Leaving PkiAdmin.certificateColumn().');
    return html;
  }

  // The Key Pair column: the pair this certificate certifies, the certification
  // request nothing here consumes, the hybrid half, and the export.
  private keyPairColumn(json: Json, draft: Json) {
    const { log, admin, esc } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.keyPairColumn().');
    const wb = json.workbench;
    const algOptions = wb.keyAlgorithms.map(function (one) {
      return { value: one.id, group: one.family,
               label: one.label + (one.slow ? ' — slow to generate' : '') +
                      (one.signs ? '' : ' — subject key only, cannot sign') };
    });
    const slow = wb.keyAlgorithms.filter(function (one) { return one.slow; });
    const html =
      '<div class="pki-col">' +
      '<div class="pki-group">Key Pair</div>' +
      admin.note(
        'The key pair the next certificate certifies &mdash; and, for a ' +
        'self-signed profile, the key that signs it. It is generated ' +
        '<strong>here, in this service</strong>, which is the one place this ' +
        'page differs in kind from the debugger\'s: that page generates in ' +
        'the browser because its whole claim is that the key never leaves ' +
        'it, and this one holds the certificate authority, so the key ' +
        'belongs in the process that signs. It is the same module either way ' +
        '(<code>common/vendored/key_material.js</code>), so the algorithms, ' +
        'the PEM/JWK conversion and the keystore formats are identical ' +
        'rather than similar.',
        'Where this pair comes from') +
      (slow.length
        ? admin.warn(
          '<strong>' + esc(slow.map(function (one) { return one.family; })
            .filter(function (v, i, a) { return a.indexOf(v) === i; })
                               .join(', ')) +
          ' key generation takes SECONDS and it runs on this ' +
          'thread.</strong> This process owns six listener families on one ' +
          'thread, so while a key like that is being made this service ' +
          'answers nobody &mdash; not the next HTTP caller, not the KDC on ' +
          'port 88, not the LDAP socket. It is deliberately not moved to ' +
          '<code>common/worker_pool.js</code>: that pool runs this ' +
          'service\'s own reading of the post-quantum constructions, which ' +
          'is independent of the vendored one on purpose, and crossing the ' +
          'two to save a button a few seconds is exactly the defect that ' +
          'independence exists to expose. In <code>dispatch</code> mode the ' +
          'console holds affinity to a request worker, so the stall is that ' +
          'worker\'s rather than the listener\'s.',
          'One algorithm family is slow, and the cost is real')
        : '') +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_key_alg', 'Key Algorithm',
                       'The algorithm and parameters of the key pair. RSA ' +
                       'sizes are the modulus; the EC entries are the NIST ' +
                       'curves; Ed25519 is the only Edwards curve here. The ' +
                       'list is narrowed by the Cryptographic Approach in ' +
                       'the column beside this one.',
                       algOptions) +
      self.checkField(draft, 'pki_key_jwk', 'show as JWK',
                      'Show the key pair as JWK instead of PEM. The ' +
                      'conversion is key material only — the same key either ' +
                      'way. A POST-QUANTUM pair is shown as PEM whatever ' +
                      'this says, because these two boxes are also the INPUT ' +
                      'for a reuse and a round trip through a representation ' +
                      'this encoder cannot read back would lose the key.') +
      '<button type="submit" name="generate" value="1"' +
        admin.tip('Generate a key pair into the two boxes below WITHOUT ' +
                  'issuing anything, and tick nothing. It exists because ' +
                  'generating a post-quantum pair takes seconds: making one ' +
                  'and then issuing four certificates from it is the ' +
                  'difference between a page somebody can use and one they ' +
                  'cannot.') + '>Generate a key pair</button>' +
      '</div>' +
      '<div class="pki-row">' +
      self.checkField(draft, 'pki_reuse_key', 'reuse the key pair below',
                      'Certify the key pair already in the boxes below ' +
                      'instead of generating a new one — a CA re-issuing its ' +
                      'own certificate, or the pair the store\'s "Use this ' +
                      'key pair" button loaded here. Cleared, every issue ' +
                      'starts from a fresh pair.') +
      self.checkField(draft, 'pki_save_keys',
                      'keep the private key in this service',
                      'THIS IS THE ONE CONTROL ON THIS PANE THAT MEANS ' +
                      'SOMETHING DIFFERENT FROM THE DEBUGGER\'S. There it ' +
                      'decides whether the private key is written to the ' +
                      'browser\'s localStorage; here there is no browser ' +
                      'store, so it decides whether the issued object keeps ' +
                      'its private key in this realm\'s keystore row. ' +
                      'Cleared, the certificate and the public key are ' +
                      'stored and the private half is discarded the moment ' +
                      'the reply is written — so the object can be inspected ' +
                      'and used as a trust anchor, and can never sign again ' +
                      'or be exported.') +
      '</div>' +
      self.areaField(draft, 'pki_private_key', 'Private Key',
                     'PKCS#8 PEM (or JWK). It signs, and for a CA it goes on ' +
                     'signing long after this certificate was issued. There ' +
                     'is no Copy button because this console has no script; ' +
                     'the box selects.', 4) +
      self.areaField(draft, 'pki_public_key', 'Public Key',
                     'SubjectPublicKeyInfo PEM (or JWK). This is what the ' +
                     'certificate certifies.', 3) +
      '<div class="pki-row">' +
      self.checkField(draft, 'pki_gen_csr', 'generate a CSR when the ' +
                                            'certificate is issued',
                      'Also build the PKCS#10 certification request this key ' +
                      'pair and subject would have sent to an external ' +
                      'authority. It is FOR REFERENCE: this page signs the ' +
                      'certificate itself, so nothing here consumes the CSR ' +
                      '— it is what you would paste into a CA that will not ' +
                      'take a certificate you made yourself. The signature ' +
                      'on it is by the private key above, which is the proof ' +
                      'of possession that lets an authority certify a key it ' +
                      'has never seen.') +
      '</div>' +
      self.areaField(draft, 'pki_csr', 'CSR (PKCS#10)',
                     'The certification request for the key pair and subject ' +
                     'above, built from the SAME inputs the certificate was ' +
                     '— a request assembled from a second reading of the ' +
                     'form would differ in ways nobody could see. THREE ' +
                     'EXTENSIONS TRAVEL AND THE REST DO NOT: key usage, ' +
                     'extended key usage, basic constraints and ' +
                     'subjectAltName. subjectKeyIdentifier and ' +
                     'authorityKeyIdentifier are the ISSUER\'s to compute, ' +
                     'and a requester asserting them is asking a CA to ' +
                     'certify its own arithmetic. Empty until the box above ' +
                     'is ticked and something is issued.', 3) +
      // The hybrid half. It is drawn ALWAYS rather than revealed, because
      // revealing it needs a script — and a pane that hid it would leave the
      // alternative key pair unreachable on the one console setting that uses
      // it. The heading says when it applies instead.
      '<div class="pki-group">Alternative (hybrid) Key Pair' +
        (wb.pqMode === 'hybrid' ? '' : ' — not in use') + '</div>' +
      admin.note(
        'ITU-T X.509 (2019) clause 9.8 adds three non-critical extensions ' +
        'that mirror three fields of the certificate: ' +
        '<code>subjectAltPublicKeyInfo</code> (2.5.29.72), ' +
        '<code>altSignatureAlgorithm</code> (2.5.29.73) and ' +
        '<code>altSignatureValue</code> (2.5.29.74). A certificate carrying ' +
        'them is signed twice, with two keys, and a validator that has never ' +
        'heard of the extensions sees an ordinary certificate and accepts it ' +
        '&mdash; which is the entire point. The alternative signature does ' +
        '<strong>not</strong> cover the whole TBSCertificate: it covers the ' +
        '<em>preTBSCertificate</em>, which is the TBSCertificate with the ' +
        '<code>signature</code> field removed and without the ' +
        '<code>altSignatureValue</code> extension. These boxes are used only ' +
        'when the Cryptographic Approach is <em>Hybrid</em>; for a ' +
        'self-signed certificate this pair makes the second signature, and ' +
        'for an issued one the ISSUER\'s alternative key does and this one ' +
        'is only certified.',
        'What the second key is for') +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_alt_key_alg', 'Alternative Algorithm',
                       'Where the post-quantum half of a hybrid certificate ' +
                       'goes, so the list is the post-quantum algorithms ' +
                       'that can sign — a hybrid certificate whose second ' +
                       'key is also RSA is a certificate signed twice by the ' +
                       'same century.',
                       wb.alternativeKeyAlgorithms.map(function (one) {
                         return { value: one.id, group: one.family,
                                  label: one.label +
                                         (one.slow ? ' — slow to generate'
                                                   : '') };
                       })) +
      self.checkField(draft, 'pki_alt_reuse_key', 'reuse the pair below',
                      'Certify the alternative pair already in the boxes ' +
                      'instead of generating a new one.') +
      '<button type="submit" name="generatealt" value="1"' +
        admin.tip('Generate the alternative key pair now. Issuing under the ' +
                  'Hybrid approach generates one anyway if these boxes are ' +
                  'empty.') + '>Generate the alternative pair</button>' +
      '</div>' +
      self.areaField(draft, 'pki_alt_private_key', 'Alternative Private Key',
                     'PKCS#8 PEM. For a self-signed certificate this is what ' +
                     'signs the preTBSCertificate; for an issued one the ' +
                     'issuer\'s own alternative private key is used instead ' +
                     'and this one is only certified.', 3) +
      self.areaField(draft, 'pki_alt_public_key', 'Alternative Public Key',
                     'SubjectPublicKeyInfo PEM. This is what goes into the ' +
                     'subjectAltPublicKeyInfo extension.', 2) +
      '<div class="pki-group">Export</div>' +
      admin.note(
        'Writes out the key pair of the object SELECTED in the store below, ' +
        'or the pair in the boxes above when nothing is selected. It is the ' +
        'same export <code>/admin/keys</code> uses &mdash; ' +
        '<code>common/vendored/key_material.js</code> &mdash; so a ' +
        '<code>.p12</code> from here and one from that page import ' +
        'identically into keytool, OpenSSL, Windows and macOS. <strong>It ' +
        'needs Admin Write</strong>, like every other door here that hands ' +
        'over a private key: reading this console needs Admin Read, and ' +
        'taking a key out of it needs the other role.',
        'What Download writes') +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_ks_format', 'Keystore Format',
                       'PEM: the private key and public key (and the chain, ' +
                       'if an object is selected) in one file. DER: two ' +
                       'binary files, of which the PRIVATE one is sent — ' +
                       'this service will not take a zip dependency to send ' +
                       'two, and the public half comes out of the private ' +
                       'one with one openssl command. JWK: a JWK set. ' +
                       'PKCS#12: a password-protected .p12 holding the key ' +
                       'and its certificate chain.',
                       wb.keystoreFormats.map(function (one) {
                         return { value: one, label: one.toUpperCase() };
                       })) +
      '<label' + admin.tip('Required for PKCS#12. For PEM and DER it ' +
        'encrypts the private key as a PBES2 EncryptedPrivateKeyInfo; for ' +
        'JWK it wraps the set in a PBES2 JWE. Left empty, the private key is ' +
        'written out in the clear.') + '>Password <input type="password" ' +
        'name="pki_ks_password" value="" ' +
        'autocomplete="new-password"></label> ' +
      self.checkField(draft, 'pki_ks_include_chain', 'include the chain',
                      'Put the selected object\'s whole certificate chain in ' +
                      'the file, which is what makes a PKCS#12 importable as ' +
                      'an identity rather than as a bare key.') +
      '<button type="submit" name="export" value="1" ' +
        'formaction="/admin/pki/export"' +
        admin.tip('Download the key pair. This button posts the same form to ' +
                  'a different endpoint, because the answer is a FILE rather ' +
                  'than a page.') + '>Download</button>' +
      '</div>' +
      '</div>';
    log.debug('Leaving PkiAdmin.keyPairColumn().');
    return html;
  }

  // The Subject Distinguished Name column.
  private subjectColumn(json: Json, draft: Json) {
    const { log, admin } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.subjectColumn().');
    const titles = {
      pki_dn_cn: 'commonName (2.5.4.3) — what this certificate is called. ' +
                 'The profile fills it in and replaces its own default when ' +
                 'the profile changes, but never a name you typed. For a TLS ' +
                 'server the name a client actually checks is in ' +
                 'subjectAltName, not here.',
      pki_dn_o: 'organizationName (2.5.4.10) — who the subject belongs to. ' +
                'It is filled from pki.organisation, which is what the ' +
                'hierarchy above carries, because two certificates from one ' +
                'realm reading O=Example and O=sts are two organisations as ' +
                'far as a path validator is concerned.',
      pki_dn_ou: 'organizationalUnitName (2.5.4.11) — the division within ' +
                 'the organization. Repeat it by adding OU=… lines to ' +
                 'Further attributes below; a DN may carry several.',
      pki_dn_l: 'localityName (2.5.4.7) — the city or town.',
      pki_dn_st: 'stateOrProvinceName (2.5.4.8) — spelled out rather than ' +
                 'abbreviated, which is what the CA/Browser Forum asks for.',
      pki_dn_c: 'countryName (2.5.4.6). Two letters, encoded as a ' +
                'PrintableString — a country encoded as UTF8String parses ' +
                'perfectly and is refused by several validators.',
      pki_dn_email: 'emailAddress (1.2.840.113549.1.9.1) — a legacy PKCS#9 ' +
                    'attribute in the DN. S/MIME clients read the rfc822Name ' +
                    'in subjectAltName instead, so an address here alone is ' +
                    'decorative.',
      pki_dn_dc: 'domainComponent (0.9.2342.19200300.100.1.25) — one label ' +
                 'of a DNS name, as Active Directory writes a DN ' +
                 '(DC=example, DC=com). Add further DC=… lines to Further ' +
                 'attributes below, in order.',
      pki_dn_uid: 'userId (0.9.2342.19200300.100.1.1) — the account name, as ' +
                  'a directory holds it.',
      pki_dn_serialnumber: 'The DN attribute called serialNumber (2.5.4.5). ' +
                           'Nothing to do with the certificate\'s serial ' +
                           'number in the first column.'
    };
    const labels = {
      pki_dn_cn: 'CN (Common Name)', pki_dn_o: 'O (Organization)',
      pki_dn_ou: 'OU (Organizational Unit)', pki_dn_l: 'L (Locality)',
      pki_dn_st: 'ST (State / Province)', pki_dn_c: 'C (Country)',
      pki_dn_email: 'emailAddress', pki_dn_dc: 'DC (Domain Component)',
      pki_dn_uid: 'UID', pki_dn_serialnumber: 'serialNumber (DN attribute)'
    };
    const boxes = json.workbench.dnFields.map(function (one) {
      return self.textField(draft, one.field, labels[one.field] || one.attr,
                            titles[one.field] || '',
                            one.field === 'pki_dn_c' ? ' size="4" maxlength="2"'
                                                     : ' size="28"');
    }).join('');
    const html =
      '<div class="pki-col">' +
      '<div class="pki-group">Subject Distinguished Name</div>' +
      admin.note(
        'Written in the order shown &mdash; a Name is an ordered ' +
        'RDNSequence, and a reordered DN is a different name that chains to ' +
        'nothing. For a TLS server, note that the name a client checks is in ' +
        '<code>subjectAltName</code> and not here: every current browser ' +
        'ignores the Common Name entirely.',
        'Why the order matters, and where a TLS name really lives') +
      '<div class="pki-row">' + boxes + '</div>' +
      self.areaField(draft, 'pki_dn_extra',
                     'Further attributes (one NAME=value or OID=value per ' +
                     'line)',
                     'Appended in order. Recognised names include SN, GN, ' +
                     'title, description, businessCategory, postalCode, ' +
                     'STREET, initials, pseudonym, dnQualifier, ' +
                     'generationQualifier and the three EV jurisdiction ' +
                     'attributes; anything else is taken as an OID.', 3,
                     'businessCategory=Private ' +
                     'Organization\n1.3.6.1.4.1.311.60.2.1.3=US') +
      '</div>';
    log.debug('Leaving PkiAdmin.subjectColumn().');
    return html;
  }

  // ---------------------------------------------------------------------------
  // THE STORE, AND WHY IT IS INSIDE THE SAME FORM.
  //
  // *Use this key pair* has to load a key into the boxes above WITHOUT throwing
  // away the subject somebody has been typing, and with no script the only way
  // to keep the rest of the form is to submit it. So these buttons are submit
  // buttons of the one form, each carrying the object's id as its own VALUE —
  // which is also why they have names of their own rather than sharing
  // `action`.
  // ---------------------------------------------------------------------------
  private storeTable(json: Json, draft: Json) {
    const { log, certificateDialog, pqcBadge, admin, esc } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.storeTable().');
    const wb = json.workbench;
    if (!wb.objects.length) {
      log.debug('Leaving PkiAdmin.storeTable(). Empty.');
      // **THE SELECTION IS A FIELD AND IT HAS TO SURVIVE AN EMPTY STORE.** The
      // radio column below carries `pki_selected`, so with no rows there is no
      // control carrying it at all — and a field that is on the form on one
      // render and absent on the next falls back to its default every time the
      // store happens to be empty, which is exactly the kind of control that
      // quietly undoes itself. `tests/pki_authoring.js` compares the drawn
      // fields against the declared ones and caught this.
      return '<input type="hidden" name="pki_selected" value="' +
        esc(String(draft.pki_selected || '')) + '">' +
        admin.note(
        'Nothing has been issued from the pane above in this realm. What is ' +
        'issued here is kept in the <strong>same keystore row as the ' +
        'hierarchy</strong> — sealed under the same key-encryption key, gone ' +
        'with the realm, and in development mode gone with the process, ' +
        'which is the rule the signing key already follows.',
        'The store is empty');
    }
    const rows = wb.objects.slice().reverse().map(function (one) {
      return '<tr>' +
        '<td><label class="pki-flag"><input type="radio" name="pki_selected" ' +
          'value="' + esc(one.id) + '"' +
          (draft.pki_selected === one.id ? ' checked' : '') + '> ' +
          (one.ca ? '<strong>CA</strong>' : 'leaf') + '</label></td>' +
        '<td><code>' + esc(one.subject) + '</code>' +
          (one.selfSigned ? '<br><em>self-signed</em>'
                          : '<br><small>issued by <code>' +
                            esc(one.issuerSubject) + '</code></small>') +
          '</td>' +
        '<td>' + esc(one.profileLabel) + '</td>' +
        '<td><code>' + esc(one.serialHex.slice(0, 16)) +
        '&hellip;</code></td><td>' + esc(String(one.notAfter).slice(0, 10)) +
          (one.expired ? ' <strong>(expired)</strong>' : '') + '</td>' +
        '<td><code>' + esc(one.keyAlg) + '</code> / <code>' +
          esc(one.signatureAlg) + '</code>' +
          pqcBadge.badgeFor({ certificatePem: one.certificatePem,
                              algorithms: [one.keyAlg] }) +
          (one.altKeyAlg
            ? '<br><small>alt <code>' + esc(one.altKeyAlg) + '</code>' +
              (one.altSigned ? ', signed' : ', key only') + '</small>'
            : '') + '</td>' +
        '<td>' + (one.hasPrivateKey ? 'yes'
          : '<em>no — it cannot sign or be exported</em>') + '</td>' +
        '<td>' +
          (one.hasPrivateKey
            ? '<button type="submit" name="use" value="' + esc(one.id) + '"' +
              admin.tip('Load this key pair into the boxes above and tick ' +
                        '"reuse the key pair below", so the next issue ' +
                        'certifies THIS key — a CA renewing its own ' +
                        'certificate. Everything else on the form is kept.') +
              '>Use this key pair</button> '
            : '') +
          '<button type="submit" name="remove" value="' + esc(one.id) + '"' +
          admin.tip('Remove this object. Anything it issued is KEPT — those ' +
                    'certificates are still valid documents — and will say ' +
                    'that their issuer is missing.') + '>Remove</button>' +
        '</td></tr>' +
        '<tr><td colspan="8">' +
          certificateDialog.link('/admin/pki', one.thumbprint, 'workbench') +
          '<details><summary>Certificate (PEM)' +
          (one.hasCsr ? ' and certification request' : '') + '</summary><pre>' +
          esc(one.certificatePem) + (one.csrPem ? '\n' + esc(one.csrPem) : '') +
          '</pre></details></td></tr>';
    }).join('');
    log.debug('Leaving PkiAdmin.storeTable(). ' + wb.objects.length +
              ' row(s).');
    return '<table><thead><tr><th>Select</th><th>Subject</th><th>Profile</th>' +
      '<th>Serial</th><th>Expires</th><th>Key / signature</th>' +
      '<th>Private key</th><th></th></tr></thead><tbody>' + rows + '</tbody>' +
      '</table>' +
      '<div class="pki-row"><button type="submit" name="clearstore" value="1"' +
      admin.tip('Discard every key pair and certificate this pane has issued ' +
                'in this realm. The hierarchy above is NOT touched.') +
      '>Clear the store</button></div>';
  }

  // The whole pane: the three columns, the extensions, the buttons and the
  // store, in one form.
  certificatePane(json: Json, draft: Json) {
    const { log, admin, esc } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.certificatePane().');
    const wb = json.workbench;
    const html =
      '<h3 id="workbench">Certificate &amp; Key Configuration</h3>' +
      admin.note(
        '<strong>This is the parent project&rsquo;s <em>PKI / X.509</em> ' +
        'workflow, on the server.</strong> Build a certificate authority and ' +
        'issue the leaf certificates any of them can sign: TLS server, TLS ' +
        'client for mutual authentication, code signing, S/MIME, OCSP ' +
        'responder, time stamping, smartcard logon and Kerberos PKINIT. ' +
        'Every X.509v3 extension RFC 5280 defines is below, plus the ones in ' +
        'common use that it does not, plus anything at all by OID. The ' +
        'encoder is <code>common/vendored/x509.js</code>, that ' +
        'project&rsquo;s own PKI code byte-identical, so a certificate ' +
        'issued here and one issued there are built by <em>one</em> ' +
        'encoder.<p><strong>What is different is where the computation ' +
        'happens.</strong> That page runs Web Crypto in your browser and ' +
        'filters its menus as you change them; this console is ' +
        '<code>script-src &#39;none&#39;</code>, so every choice is a form ' +
        'field and every computation is here. The two <em>Apply</em> buttons ' +
        'are what that costs: narrowing a menu or rewriting the extension ' +
        'boxes from a profile is a round trip rather than an event ' +
        'handler.</p><p><strong>A <code>cRLDistributionPoints</code> or an ' +
        '<code>authorityInfoAccess</code> you type below is a URL you are ' +
        'ASSERTING, and this pane keeps no promise about it.</strong> That ' +
        'was true of every address on this page until 2026-09-11 and it is ' +
        'still true of every address <em>you type</em> &mdash; what changed ' +
        'is that the certificates this service issues <em>itself</em> now ' +
        'name addresses it really answers: each authority signs a CRL and ' +
        'runs an OCSP responder, and anything issued from one of them can be ' +
        'revoked in the pane below. An object minted here from an authority ' +
        'whose key is in this process is in that register too. One typed at ' +
        'a URL of your own is not, and nothing here will pretend ' +
        'otherwise.</p>',
        'What this pane is, and how it differs from the page it is ' +
        'modelled on') +
      '<form method="post" action="/admin/pki/certificate">' +
      '<input type="hidden" name="action" value="issue-certificate">' +
      '<div class="pki-cols">' +
      self.certificateColumn(json, draft) +
      self.keyPairColumn(json, draft) +
      self.subjectColumn(json, draft) +
      '</div>' +
      '<div class="pki-group">X.509v3 Extensions</div>' +
      admin.note(
        'Every extension RFC 5280 defines, plus the ones in common use that ' +
        'it does not, plus anything at all by OID. <strong>The ' +
        '<em>critical</em> flag is separately settable on each</strong>: a ' +
        'validator must reject a certificate carrying a critical extension ' +
        'it does not understand, so making the wrong one critical is a good ' +
        'way to find out what your stack actually implements. Four of them ' +
        'are fixed critical because RFC 5280 says MUST or SHOULD and a box ' +
        'that could clear it would produce a certificate nothing profiles — ' +
        'policyMappings, policyConstraints and inhibitAnyPolicy.',
        'Which extensions are here, and what the critical flag costs') +
      self.extensionCards(json, draft) +
      '<div class="pki-row">' +
      '<button type="submit"' +
      admin.tip('Generate a key pair unless "reuse the key pair below" is ' +
                'ticked, build the certificate, sign it, and keep both in ' +
                'the store below.') +
      '>Generate key pair &amp; issue certificate</button>' +
      '</div>' +
      '<h3>Keys &amp; Certificates</h3>' +
      admin.note(
        'Everything issued from the pane above, in this realm, newest first. ' +
        'Select a row to export it or to load its key pair back into the ' +
        'form. At most ' + esc(String(wb.maxObjects)) +
        ' are kept: past that the oldest goes and the reply says so, because ' +
        'every one of these is sealed, written to the store and pushed to ' +
        'every request worker when it changes.',
        'What this store is') +
      self.storeTable(json, draft) +
      '</form>';
    log.debug('Leaving PkiAdmin.certificatePane().');
    return html;
  }

  // ---------------------------------------------------------------------------
  // WHICH BUTTON WAS PRESSED. Read FIRST, before `action`, because the Issue
  // button is the unnamed one behind the hidden `action=issue-certificate` and
  // every other button carries a name of its own (see the pane's header for
  // what two buttons sharing `action` cost `/admin/users/new`).
  //
  // `/admin-api` never goes through this: a caller there names the action and
  // the object outright, which is why the action names below are words rather
  // than button labels.
  // ---------------------------------------------------------------------------
  private paneActionFrom(body: Json) {
    const { log } = this.deps;
    log.debug('Entering PkiAdmin.paneActionFrom().');
    const pressed = function (name) {
      log.debug("Entering pressed().");
      log.debug("Leaving pressed().");
      return body[name] !== undefined && body[name] !== '';
    };
    let out: Json = { action: 'issue-certificate' };
    if (pressed('defaults')) {
      out = { action: 'apply-profile' };
    } else if (pressed('generate')) {
      out = { action: 'generate-keys' };
    } else if (pressed('generatealt')) {
      out = { action: 'generate-alt-keys' };
    } else if (pressed('use')) {
      out = { action: 'use-key', objectId: String(body.use) };
    } else if (pressed('remove')) {
      out = { action: 'remove-object', objectId: String(body.remove) };
    } else if (pressed('clearstore')) {
      out = { action: 'clear-store' };
    }
    log.debug('Leaving PkiAdmin.paneActionFrom(). ' + out.action);
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE PAGE, DRAWN WITH A DRAFT.
  //
  // It is a function rather than the body of the GET handler because the pane's
  // POST answers with a PAGE — the form, redrawn, with a hundred and fifteen
  // fields still in it — and a second renderer for that would be a second
  // opinion about what this page looks like.
  //
  // `banner` is the one thing the two callers differ by: the GET has nothing to
  // say and the POST has just done something.
  // ---------------------------------------------------------------------------

  // ===========================================================================
  // THE HIERARCHY AS A TREE (2026-09-11).
  //
  // One Root for the service, an Intermediate per scope, and an Issuing CA per
  // use case under each — with what that authority has actually certified
  // listed beneath it, because a tree of authorities with nothing under them
  // cannot be told from a tree that is wired to nothing.
  //
  // **THE SCOPES IT WALKS ARE THIS REALM'S**, which is `pkiJson()`'s doing and
  // not this function's: it draws whatever `json.tree.scopes` holds, so the
  // question of which branches a reader gets is asked once, above, and this
  // renderer would draw fifty realms just as happily if it were ever handed
  // them.
  //
  // It is drawn as nested lists and not as a diagram. This console has two
  // drawings and both are laid out by `@dagrejs/dagre` on the server; a CA
  // hierarchy is a tree with one root and fixed depth, which indentation says
  // exactly as well and a reader can select text out of.
  // ===========================================================================
  private tierRow(tier: Json, depth: Json, extra?: Json) {
    const self = this;
    const { log, certificateDialog, pqcBadge, esc } = this.deps;
    log.debug("Entering PkiAdmin.tierRow().");
    if (!tier) {
      log.debug("Leaving PkiAdmin.tierRow().");
      return '';
    }
    log.debug("Leaving PkiAdmin.tierRow().");
    return '<tr>' +
      '<td style="padding-left:' + (depth * 1.4) + 'rem">' +
      (depth ? '<span class="pki-branch">&#9492;&#9472;</span> ' : '') +
      '<strong>' + esc(tier.label) + '</strong>' +
      (tier.imported ? ' <em>(imported)</em>' : '') +
      (extra || '') + '</td>' +
      '<td><code>' + esc(tier.subject) + '</code></td>' +
      '<td>' + esc(String(tier.notAfter).slice(0, 10)) +
        (tier.expired ? ' <strong>(expired)</strong>' : '') + '</td>' +
      '<td><code>' + esc(tier.keyAlg) + '</code> / <code>' +
        esc(tier.signatureAlg) + '</code>' +
        pqcBadge.badgeFor({ certificatePem: tier.certificatePem,
                            algorithms: [tier.keyAlg] }) +
        self.alternativeNote(tier) + '</td>' +
      '<td><code>' + esc(String(tier.thumbprint).slice(0, 16)) +
      '&hellip;</code><br>' +
      certificateDialog.link('/admin/pki', tier.thumbprint, 'pki-tree') +
      '</td></tr>';
  }

  private treeSection(json: Json) {
    const { log, certificateDialog, pqcBadge, admin, esc } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.treeSection().');
    const tree = json.tree;
    if (!tree || !tree.rootBuilt) {
      log.debug('Leaving PkiAdmin.treeSection(). No Root.');
      return admin.warn(
        '<strong>This service has no Root CA.</strong> It is built at ' +
        'startup unless <code>pki.autoBuild</code> is off, so seeing this ' +
        'means either that setting is off or the build failed — the startup ' +
        'log says which. Every key this service holds is self-signed until ' +
        'there is one, which is what this service did before 2026-09-11.',
        'No certificate authority');
    }
    let rows = self.tierRow(tree.root, 0);
    tree.scopes.forEach(function (scope) {
      if (!scope.built) {
        rows += '<tr><td style="padding-left:1.4rem">' +
          '<span class="pki-branch">&#9492;&#9472;</span> <em>' +
          esc(scope.label) + ' — not built</em></td>' +
          '<td colspan="4"><em>This scope has no Intermediate CA. Build it ' +
          'below.</em></td></tr>';
        return;
      }
      rows += self.tierRow(scope.intermediate, 1,
                           ' <span class="pki-scope">' +
                           esc(scope.kind === 'process' ? 'process'
                                                        : 'realm ' +
                                                        scope.label) +
                           '</span>');
      scope.issuing.forEach(function (one) {
        if (!one.built) {
          return;
        }
        rows += self.tierRow(one.ca, 2,
                             ' <span class="pki-scope">' + esc(one.id) +
                             '</span>');
        // What it has certified. Indented under its own authority, because the
        // question a reader brings to a tree of CAs is which of them is
        // actually doing anything.
        one.certified.forEach(function (cert) {
          rows += '<tr><td style="padding-left:4.2rem"><span ' +
            'class="pki-branch">&#9492;&#9472;</span> ' + esc(cert.label) +
            (cert.pinned ? ' <em>(your key)</em>' : '') + '</td>' +
            '<td><code>' + esc(cert.subject) + '</code></td>' +
            '<td>' + esc(String(cert.notAfter).slice(0, 10)) +
              (cert.expired ? ' <strong>(expired)</strong>' : '') + '</td>' +
            '<td><code>' + esc(cert.alg || cert.keyAlg || '') + '</code>' +
              pqcBadge.badgeFor({ certificatePem: cert.certificatePem,
                                  algorithms: [cert.keyAlg, cert.alg] }) +
              '</td>' +
            '<td><code>' + esc(String(cert.thumbprint).slice(0, 16)) +
              '&hellip;</code><br>' +
              certificateDialog.link('/admin/pki', cert.thumbprint,
                                     'pki-tree') + '</td></tr>';
        });
        if (!one.certified.length) {
          rows += '<tr><td style="padding-left:4.2rem"><em>nothing certified ' +
            'yet</em></td><td colspan="4"><em>' + esc(one.what) +
            '</em></td></tr>';
        }
      });
    });
    log.debug('Leaving PkiAdmin.treeSection().');
    return '<table><thead><tr><th>Authority</th><th>Subject</th>' +
      '<th>Expires</th><th>Key / signature</th><th>SHA-256</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table>';
  }

  // ---------------------------------------------------------------------------
  // THE CONTROLS, ONE BLOCK PER SCOPE. Rebuild a branch, reissue one use case's
  // Issuing CA, re-certify what hangs under it, import a CA of your own, or pin
  // a key pair of your own for one slot.
  // ---------------------------------------------------------------------------
  private scopeControls(json: Json, scope: Json) {
    const { log, config, admin, esc } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.scopeControls(). scope=' + scope.scope);
    const label = scope.kind === 'process' ? 'the process'
                                           : 'the ' + scope.label + ' realm';
    let html = '<h4>' + esc(scope.kind === 'process' ? 'Process'
                                                    : 'Realm: ' + scope.label) +
      '</h4>';
    html +=
      '<form method="post" action="/admin/pki">' +
      '<input type="hidden" name="action" value="build-scope">' +
      '<input type="hidden" name="scope" value="' + esc(scope.scope) + '">' +
      '<label' + admin.tip('The key algorithm every CA in this branch is ' +
        'generated with. The Root keeps its own — a branch built with a ' +
        'different algorithm from the Root is perfectly legal, and the ' +
        'SIGNATURE on each tier is the one its issuer can produce whatever ' +
        'this says.') + '>Key algorithm <select name="keyAlg">' +
      self.algorithmOptions(json, scope.keyAlg ||
                            config.value('pki.keyAlgorithm')) +
                            '</select></label> ' +
      self.alternativeField(json, scope.altKeyAlg) +
      '<button type="submit"' +
      admin.tip('Replace this branch: a new Intermediate CA and a new ' +
                'Issuing CA for every use case under it. The Root is NOT ' +
                'touched — every other scope hangs from it. Everything this ' +
                'branch had issued chains to nothing the moment this ' +
                'returns, which is why the certificates under it are ' +
                're-minted in the same act.') +
      '>' + (scope.built ? 'Rebuild' : 'Build') + ' this branch</button>' +
      '</form>';
    if (!scope.built) {
      log.debug('Leaving PkiAdmin.scopeControls(). Not built.');
      return html;
    }
    html += '<table><thead><tr><th>Use case</th><th>Issuing ' +
      'CA</th><th>Certified</th><th>Reissue</th><th>Your own ' +
      'CA</th></tr></thead><tbody>';
    scope.issuing.forEach(function (one) {
      html += '<tr>' +
        '<td><strong>' + esc(one.label) + '</strong>' +
          admin.note(esc(one.what)) + '</td>' +
        '<td>' + (one.ca
          ? '<code>' + esc(one.ca.subject) + '</code>' +
            (one.ca.imported ? '<br><em>imported — a CA you supplied</em>' : '')
          : '<em>not built</em>') + '</td>' +
        '<td>' + one.certified.length + '</td>' +
        '<td>' +
          '<form method="post" action="/admin/pki"><input type="hidden" ' +
          'name="action" value="reissue-use-case"><input type="hidden" ' +
          'name="scope" value="' + esc(scope.scope) + '">' +
          '<input type="hidden" name="useCase" value="' + esc(one.id) + '">' +
          '<button type="submit"' +
          admin.tip('Generate a new key pair for this Issuing CA and ' +
                    're-issue it from this scope’s Intermediate, then ' +
                    're-certify everything that hung under it. The other use ' +
                    'cases are untouched, which is the whole reason each has ' +
                    'an authority of its own.') +
          '>Reissue this CA</button></form>' +
          (one.certified.length
            ? '<form method="post" action="/admin/pki">' +
              '<input type="hidden" name="action" value="recertify">' +
              '<input type="hidden" name="scope" value="' + esc(scope.scope) +
              '"><input ' +
              'type="hidden" name="useCase" value="' + esc(one.id) + '">' +
              '<button type="submit"' +
              admin.tip('Re-issue the certificates under this CA from the ' +
                        'same authority, with fresh serials and a fresh ' +
                        'validity window. The KEYS are untouched — this is a ' +
                        'renewal, not a regeneration, so nothing that ' +
                        'verifies against the published keys stops ' +
                        'verifying.') +
              '>Renew certificates</button></form>'
            : '') +
        '</td>' +
        '<td>' +
          (one.certified.length
            ? '<details><summary>Use your own key pair</summary>' +
              admin.note(
                'Replace what this service generated for one SLOT with a key ' +
                'pair of your own. <strong>With no certificate this service ' +
                'issues one</strong> from the authority above, so your key ' +
                'chains to this service&rsquo;s Root exactly as a generated ' +
                'one would; with a certificate, the pair is used as you ' +
                'supplied it and chains wherever that certificate chains.') +
              '<form method="post" action="/admin/pki">' +
              '<input type="hidden" name="action" value="pin-key">' +
              '<input type="hidden" name="scope" value="' + esc(scope.scope) +
              '"><input ' +
              'type="hidden" name="useCase" value="' + esc(one.id) + '">' +
              '<label>Slot <select name="slot">' +
              one.certified.map(function (cert) {
                return '<option value="' + esc(cert.slot) + '">' +
                  esc(cert.slot) + '</option>';
              }).join('') + '</select></label><div ' +
              'class="pki-field"><label>Private key (PEM)<textarea ' +
              'name="privateKeyPem" rows="3"></textarea></label></div><div ' +
              'class="pki-field"><label>Certificate (PEM, optional)<textarea ' +
              'name="certificatePem" ' +
              'rows="2"></textarea></label></div><button type="submit">Use ' +
              'this key pair</button></form></details>'
            : '') +
          '<details><summary>Import a CA</summary><form method="post" ' +
          'action="/admin/pki"><input type="hidden" name="action" ' +
          'value="import-ca"><input type="hidden" name="scope" value="' +
          esc(scope.scope) + '">' +
          '<input type="hidden" name="useCase" value="' + esc(one.id) + '">' +
          '<div class="pki-field"><label>Certificate (PEM)' +
          '<textarea name="certificatePem" rows="3"></textarea></label></div>' +
          '<div class="pki-field"><label>Private key (PEM)' +
          '<textarea name="privateKeyPem" rows="3"></textarea></label></div>' +
          '<button type="submit">Use this as the Issuing CA</button>' +
          '</form></details>' +
        '</td></tr>';
    });
    html += '</tbody></table>';
    log.debug('Leaving PkiAdmin.scopeControls().');
    return html;
  }

  // The Root's own controls. Separate from a scope's because replacing it is a
  // different act with a different consequence: every branch in the process
  // hangs from it.
  private rootControls(json: Json) {
    const { log, config, pki, admin, esc } = this.deps;
    const self = this;
    log.debug("Entering PkiAdmin.rootControls().");
    const tree = json.tree;
    log.debug("Leaving PkiAdmin.rootControls().");
    return '<h4>The Root CA</h4>' +
      admin.warn(
        '<strong>Replacing the Root replaces the trust anchor for the whole ' +
        'service.</strong> Every scope’s Intermediate is signed by it, so ' +
        'rebuilding it here re-signs all of them in the same act — and ' +
        'anything that was trusting the old Root stops trusting this service ' +
        'until it is given the new one. That is the cost of one anchor ' +
        'covering everything, and it is the reason the button says what it ' +
        'does.',
        'This replaces the anchor everything hangs from') +
      '<form method="post" action="/admin/pki">' +
      '<input type="hidden" name="action" value="build-root">' +
      '<label>Key algorithm <select name="keyAlg">' +
      self.algorithmOptions(json, (tree.root && tree.root.keyAlg) ||
                            config.value('pki.keyAlgorithm')) +
                            '</select></label> ' +
      self.alternativeField(json, tree.root &&
                            (tree.root.altKeyAlg ||
                             (tree.rootBuilt ? 'none' : ''))) +
      '<label>Common name <input name="commonName" placeholder="' +
      esc(config.value('pki.organisation')) + ' Root CA"></label> ' +
      '<label>Years <input name="years" size="4" placeholder="20"></label> ' +
      '<button type="submit">' + (tree.rootBuilt ? 'Replace' : 'Build') +
      ' the Root CA</button></form>' +
      '<details><summary>Import a Root of your own</summary>' +
      admin.note(
        'Paste a CA certificate and its private key and this service will ' +
        'hang every Intermediate from it instead of building one &mdash; so ' +
        'the whole tree chains to your own corporate authority and a relying ' +
        'party that already trusts it needs nothing new. <strong>The key is ' +
        'stored exactly as this service stores its own</strong>: in the ' +
        'realm keystore row, sealed under the key-encryption key wherever ' +
        'that key outlives the process, and in the clear in development mode ' +
        'where it does not.') +
      '<form method="post" action="/admin/pki">' +
      '<input type="hidden" name="action" value="import-ca">' +
      '<input type="hidden" name="scope" value="' + esc(pki.SERVICE_SCOPE) +
      '"><input ' +
      'type="hidden" name="useCase" value="root"><div ' +
      'class="pki-field"><label>Certificate (PEM)<textarea ' +
      'name="certificatePem" rows="3"></textarea></label></div><div ' +
      'class="pki-field"><label>Private key (PEM)<textarea ' +
      'name="privateKeyPem" rows="3"></textarea></label></div><button ' +
      'type="submit">Use this as the Root CA</button></form></details>';
  }

  // ---------------------------------------------------------------------------
  // WHAT THIS TREE COVERS, SAID ON THE PAGE RATHER THAN LEFT TO BE DISCOVERED.
  //
  // **THIS WAS A WARNING ABOUT WHAT IT DID NOT COVER UNTIL 2026-09-13**, headed
  // *What one anchor does not cover*, and its first paragraph read: *One
  // family of key material in this service is deliberately NOT a leaf of this
  // tree: the eleven post-quantum signing keys per realm. They are generated by
  // common/pq_jose.js — this service's OWN reading of ML-DSA, SLH-DSA and the
  // composite algorithms, which is deliberately independent of the vendored
  // implementation the certificate encoder uses. Handing a key made by one to
  // the other would be exactly the defect that independence exists to expose,
  // so they carry no certificate at all and are published as bare AKP JWKs.*
  //
  // It was reversed by request, and the independence was kept rather than
  // argued away: only the PUBLIC key crosses, the one byte-layout difference is
  // written out in `common/pki.js`'s `pqSubjectPublicKeyPem()`, and
  // `tests/pq_key_certification.js` holds a `pq_jose.js` signature verifying
  // under the vendored reading against the certificate. `common/pki.js` argues
  // it above `PQ_JOSE_IN_X509`. The ML-DSA listener certificate, which was
  // self-signed beside the certified RSA one, came under the TLS Issuing CA the
  // same day. **It is still a note rather than nothing** because two keys
  // remain outside by their nature, and a reader deciding what to pin needs
  // both named.
  //
  // A page that drew a tree and let a reader conclude "everything is under it"
  // would be the most consequential untruth this console could tell about key
  // material — the whole value of one anchor is knowing exactly what it covers.
  //
  // **THIS NOTE LISTED TWO THINGS UNTIL 2026-09-11 AND NOW LISTS ONE.** The
  // second was the SPIFFE X.509 authority, and the paragraph read: *It is
  // self-signed on purpose: a trust domain whose root was also this
  // service's would conflate two unrelated trust decisions, which is what
  // `spiffe/spiffe_ca.ts` has said since it was written — one process, two
  // PKIs. There is a second, mechanical reason: an Issuing CA here carries
  // `pathLen: 0`, so it may sign leaves and no further authority, and a SPIFFE
  // authority signs SVIDs. The SPIFFE Issuing CA is built and ready above,
  // certifying nothing, so that reversing this is a decision rather than a
  // rebuild.*
  //
  // That last sentence is the one that was acted on. The `pathLen` half was a
  // real obstacle and was fixed rather than argued around — the `spiffe` use
  // case carries `pathLen: 1` and the realm Intermediate above it is widened to
  // match, which is what keeps `NewDownstreamX509CA` working —
  // and the trust-decision half is answered by the SPIFFE authority being a
  // SIBLING of the TLS one rather than the same certificate: narrowing trust to
  // SPIFFE alone is still sayable, by pinning that Issuing CA instead of the
  // Root. `spiffe/spiffe_ca.ts`'s own header carries the argument in full.
  // ---------------------------------------------------------------------------
  private coverageNote(json: Json) {
    const { log, admin } = this.deps;
    log.debug("Entering PkiAdmin.coverageNote().");
    log.debug("Leaving PkiAdmin.coverageNote().");
    return admin.note(
      '<strong>Every signing key pair this service generates is a leaf of ' +
      'this tree, the post-quantum ones included</strong> (2026-09-13). A ' +
      'realm&rsquo;s eleven post-quantum signing keys &mdash; ML-DSA, ' +
      'SLH-DSA and the six composites &mdash; are issued from that ' +
      'realm&rsquo;s own <code>JOSE signing</code> Issuing CA as they are ' +
      'made, and each is refused in any other realm by the Intermediate ' +
      'boundary every leaf here is held to. The keys are still generated and ' +
      'signed with by <code>common/pq_jose.js</code>, this service&rsquo;s ' +
      'own reading of those constructions: only the PUBLIC key reaches the ' +
      'certificate encoder, and a signature from one reading is checked to ' +
      'verify under the other against the certificate. The JWKS is unchanged ' +
      '&mdash; they are still published as AKP JWKs. An ML-DSA listener ' +
      'certificate (<code>tls.certificateAlgorithms</code>) is a leaf of the ' +
      '<code>TLS listeners</code> Issuing CA beside the RSA ' +
      'one.<p><strong>Two keys stay outside, by what they are.</strong> The ' +
      'SPIFFE <em>JWT</em> authority has no certificate to issue &mdash; a ' +
      'JWT-SVID is verified against a bare key in the bundle &mdash; and the ' +
      'OpenID4VCI request-encryption key only DECRYPTS and is trusted ' +
      'because a wallet read it out of the issuer&rsquo;s own ' +
      'metadata.</p><p><strong>The SPIFFE X.509 authority used to be on this ' +
      'list and is under this Root</strong> (2026-09-11) &mdash; it is the ' +
      '<code>SPIFFE authority</code> Issuing CA in each realm\'s branch ' +
      'above, and every X509-SVID this service mints is a leaf of it. It is ' +
      'the one Issuing CA in this hierarchy with <code>pathLen: 1</code> ' +
      'rather than <code>0</code>, because <code>NewDownstreamX509CA</code> ' +
      'on the SPIRE Server API asks it for a CA and not a leaf; the realm ' +
      'Intermediate above it is widened to <code>2</code> to match, and ' +
      '<code>common/pki.js</code> derives the second from the first so the ' +
      'two cannot drift. <a href="/admin/spiffe">The SPIFFE page</a> reports ' +
      'which authority each realm is actually using — a realm with no branch ' +
      'built still falls back to a self-signed one and says so.</p>',
      'What one anchor covers');
  }

  // ===========================================================================
  // THE REVOCATION PANE (2026-09-11), AND THE ONE DISTINCTION IT HAS TO KEEP.
  //
  // **THERE ARE NOW TWO CONTROLS ON THIS PAGE WITH THE WORD *REVOKE* ON THEM
  // AND THEY DO COMPLETELY DIFFERENT THINGS.** That is the thing to get right
  // here, because getting it wrong is not a bug a reader would ever see:
  //
  //   * the `revoke` action in the Applications table — which predates this
  //     pane — TAKES THE KEY PAIR OFF an application's directory entry. It
  //     stops this service ACCEPTING what that key signs, and the certificate
  //     goes on chaining to this realm's Root for anybody who only checks the
  //     chain. It is a change to `ou=applications`.
  //   * `revoke-certificate`, below, puts a SERIAL on an issuer's certificate
  //     revocation list. It changes nothing about who holds what; what it
  //     changes is what this service's CRL and OCSP responder SAY about that
  //     serial from that moment on.
  //
  // Doing one is not doing the other, and an operator taking a compromised key
  // pair off an application almost certainly wants both. The pane says so in as
  // many words rather than quietly doing both from one button: they are
  // different acts with different blast radii — the first is reversible by
  // issuing again, and the second is reversible only for `certificateHold`.
  //
  // ---------------------------------------------------------------------------
  // A REVOCATION IS MADE BY AN ISSUER, WHICH IS WHY THE PANE IS ORGANISED BY
  // AUTHORITY AND NOT BY CERTIFICATE.
  //
  // A serial number is unique only WITHIN one issuer, so *revoke serial 4f2a*
  // is not a question this service can answer — it needs to know which CA is
  // being asked to say it. That is also why there is one CRL and one OCSP
  // responder per authority rather than one per realm: a list per realm would
  // be a document with no valid issuer, and nothing could sign it.
  //
  // So the pane is one section per authority, each carrying what that authority
  // has SIGNED, what it has REVOKED, and the three addresses a client can read
  // its answer from.
  // ===========================================================================

  // The model. Built by `pkiJson()` and rendered by `revocationPane()`, so that
  // `GET /admin-api/pki` carries exactly what the page draws (rule 7).
  private revocationModel() {
    const { log, config, pki, pkiRevocation } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.revocationModel().');
    // THE SAME SCOPES THE TREE DRAWS, AND FOR ITS REASON (2026-09-11): the
    // process branch and this realm's, with `authorities()` putting the Root at
    // the head of the list itself. A Revoke button for an authority in a realm
    // this operator has not switched to is the one leak on this page that is
    // more than untidy — a revocation is permanent, it is made BY AN ISSUER,
    // and the issuer's name on a row is the only thing that says which realm
    // you are about to change.
    //
    // **IT READ `pki.knownScopes()` UNTIL THIS CHANGE**, which is every scope
    // in the keystore. That function had already been got wrong once here — it
    // carries the process branch itself, so concatenating `PROCESS_SCOPE`
    // listed every process authority twice with two sets of Revoke buttons that
    // both worked — and naming the two scopes outright is what stops a third
    // reading of what it happens to filter. An unbuilt scope needs no filtering
    // either: `authorities()` asks `describeScope()` and skips a branch that is
    // not there.
    const scopes = [pki.PROCESS_SCOPE, self.currentRealmScope()]
      .filter(function (id, i, all) { return all.indexOf(id) === i; });
    const authorities = pkiRevocation.authorities(scopes).map(function (one) {
      const points = pkiRevocation.distributionPoints(one.scope, one.ca);
      const revoked = pkiRevocation.listFor(one.scope, one.ca)
        .map(pkiRevocation.describeEntry);
      const revokedBySerial = Object.create(null);
      revoked.forEach(function (entry) {
        revokedBySerial[entry.serialHex] = entry;
      });
      return {
        scope: one.scope,
        scopeSegment: pkiRevocation.scopeSegment(one.scope),
        ca: one.ca,
        label: one.label,
        subject: one.tier.subject,
        notAfter: one.tier.notAfter,
        // WHAT IT SIGNED, each row carrying whether it is already on the list —
        // computed HERE rather than by the renderer, because "is this revoked"
        // is a statement about the register and a page holding a second opinion
        // about it would eventually offer a Revoke button for something already
        // revoked and a Release for something that was never held.
        issued: pkiRevocation.issuedList(one.scope,
                                         one.ca).map(function (cert) {
          const entry = revokedBySerial[cert.serialHex] || null;
          return Object.assign({}, cert, {
            revoked: !!entry,
            revokedAt: entry ? entry.revokedAt : null,
            revokedReason: entry ? entry.reason : null,
            held: !!entry && entry.reason === 'certificateHold'
          });
        }),
        revoked: revoked,
        // A SERIAL ON THE LIST THAT THIS AUTHORITY DID NOT ISSUE IS LEGAL AND
        // IS REPORTED SEPARATELY. RFC 5280 does not require a CA to still hold
        // a record of what it signed in order to revoke it, and this service
        // genuinely reaches that state: a leaf superseded by a rotation is
        // revoked and then REPLACED in the register, so the old serial is on
        // the list with nothing left to point at. Drawing it in the issued
        // table would be inventing a certificate; dropping it would hide most
        // of what the list actually holds.
        revokedNotIssued: revoked.filter(function (entry) {
          return !pkiRevocation.issuedHere(one.scope, one.ca, entry.serialHex);
        }),
        crl: { http: points.http, ldap: points.ldap },
        ocsp: points.ocsp,
        caIssuers: points.caIssuers,
        directoryDn: points.dn
      };
    });
    const out = {
      reasons: pkiRevocation.REASONS.map(function (one) {
        return { id: one.id, code: one.code, what: one.what };
      }),
      authorities: authorities,
      totalRevoked: authorities.reduce(function (n, one) {
        return n + one.revoked.length;
      }, 0),
      crlLifetimeMinutes: Number(config.value('pki.crlLifetimeMinutes')),
      publishedToDirectory: !!config.value('pki.publishCrlToDirectory')
    };
    log.debug('Leaving PkiAdmin.revocationModel(). ' + authorities.length +
              ' authority(ies), ' + out.totalRevoked + ' revoked.');
    return out;
  }

  private reasonSelect(name: Json) {
    const { log, pkiRevocation, esc } = this.deps;
    log.debug("Entering PkiAdmin.reasonSelect().");
    log.debug("Leaving PkiAdmin.reasonSelect().");
    return '<select name="' + esc(name) + '">' +
      pkiRevocation.REASONS.map(function (one) {
        // `superseded` is preselected because it is what a rotation writes and
        // therefore what the overwhelming majority of these entries say. A
        // default of `unspecified` would be the one value RFC 5280 section
        // 5.3.1 says to OMIT the extension for, so the commonest act on this
        // pane would produce the least informative entry available.
        return '<option value="' + esc(one.id) + '"' +
               (one.id === 'superseded' ? ' selected' : '') + '>' +
               esc(one.id) + ' (' + one.code + ')</option>';
      }).join('') + '</select>';
  }

  private issuedRevocationRows(authority: Json) {
    const { log, admin, esc } = this.deps;
    const self = this;
    log.debug("Entering PkiAdmin.issuedRevocationRows().");
    if (!authority.issued.length) {
      log.debug("Leaving PkiAdmin.issuedRevocationRows().");
      return '<tr><td colspan="4"><em>This authority has issued nothing this ' +
             'process can still see.</em></td></tr>';
    }
    log.debug("Leaving PkiAdmin.issuedRevocationRows().");
    return authority.issued.map(function (cert) {
      const state = cert.revoked
        ? '<span class="bad">revoked</span> ' +
          esc(String(cert.revokedReason)) +
          '<br><span class="muted">' + esc(String(cert.revokedAt)) + '</span>'
        : (cert.expired ? '<span class="muted">expired</span>'
                        : '<span class="ok">good</span>');
      const control = cert.revoked
        ? (cert.held
            ? '<form method="post" action="/admin/pki">' +
              '<input type="hidden" name="action" value="release-hold">' +
              '<input type="hidden" name="scope" value="' +
                esc(authority.scope) + '">' +
              '<input type="hidden" name="ca" value="' + esc(authority.ca) +
              '"><input ' +
              'type="hidden" name="serialHex" value="' +
                esc(cert.serialHex) + '">' +
              '<button type="submit"' +
              admin.tip('Take this serial off the list. Only a ' +
                        '`certificateHold` can be released — every other ' +
                        'reason is permanent under RFC 5280, because a ' +
                        'validator is entitled to cache a permanent ' +
                        'revocation for as long as the CRL it read says it ' +
                        'is fresh.') +
              '>Release the hold</button></form>'
            : '<span class="muted">permanent</span>')
        : '<form method="post" action="/admin/pki">' +
          '<input type="hidden" name="action" value="revoke-certificate">' +
          '<input type="hidden" name="scope" value="' + esc(authority.scope) +
          '"><input ' +
          'type="hidden" name="ca" value="' + esc(authority.ca) + '">' +
          '<input type="hidden" name="serialHex" value="' +
            esc(cert.serialHex) + '">' +
          '<input type="hidden" name="subject" value="' + esc(cert.subject) +
          '">' +
          self.reasonSelect('reason') +
          '<input type="text" name="note" placeholder="note (optional)" ' +
            'maxlength="200">' +
          '<button type="submit"' +
          admin.tip('Put this serial on ' + authority.label + '’s revocation ' +
                    'list. It changes nothing about who HOLDS the key — what ' +
                    'it changes is what this service’s CRL and OCSP ' +
                    'responder say about this serial from now on.') +
          '>Revoke</button></form>';
      return '<tr><td><code>' + esc(cert.serialHex) + '</code></td>' +
             '<td>' + esc(cert.subject) +
               (cert.label ? '<br><span class="muted">' + esc(cert.label) +
                             '</span>' : '') +
               '<br><span class="muted">' + esc(cert.kind) + '</span></td>' +
             '<td>' + state + '</td>' +
             '<td>' + control + '</td></tr>';
    }).join('');
  }

  private authorityBlock(authority: Json) {
    const { log, admin, esc } = this.deps;
    const self = this;
    log.debug("Entering PkiAdmin.authorityBlock().");
    const orphans = authority.revokedNotIssued.length
      ? admin.note(
          '<p><strong>' + authority.revokedNotIssued.length + ' serial(s) on ' +
          'this list name a certificate this process no longer holds a ' +
          'record of.</strong> That is the ORDINARY case rather than an ' +
          'error: a certificate superseded by a rotation is revoked and then ' +
          'REPLACED in the register, so the old serial stays on the list ' +
          'with nothing left to point at. RFC 5280 does not ask a CA to ' +
          'still hold what it signed in order to revoke it &mdash; and a ' +
          'validator checking one of these is checking exactly the ' +
          'certificate it was meant to.</p><table ' +
          'class="grid"><thead><tr><th>Serial</th><th>Revoked</th>' +
          '<th>Reason</th><th>Subject ' +
          'as recorded</th></tr></thead><tbody>' +
          authority.revokedNotIssued.map(function (entry) {
            return '<tr><td><code>' + esc(entry.serialHex) + '</code></td>' +
                   '<td>' + esc(String(entry.revokedAt)) + '</td>' +
                   '<td>' + esc(entry.reason) + ' (' + entry.reasonCode + ')' +
                   (entry.note ? '<br><span class="muted">' + esc(entry.note) +
                                 '</span>' : '') + '</td>' +
                   '<td>' + esc(entry.subject || '—') + '</td></tr>';
          }).join('') + '</tbody></table>',
          authority.revokedNotIssued.length + ' revoked serial(s) with no ' +
          'certificate left to show')
      : '';

    log.debug("Leaving PkiAdmin.authorityBlock().");
    return '<h4>' + esc(authority.label) + '</h4>' +
      '<p><code>' + esc(authority.subject) + '</code></p>' +
      '<p class="muted">' + authority.issued.length + ' issued, ' +
      authority.revoked.length + ' revoked. A client reads this ' +
      'authority&rsquo;s answer at ' +
      '<code>' + esc(authority.crl.http) + '</code> (HTTP), ' +
      '<code>' + esc(authority.crl.ldap) + '</code> (LDAP) or ' +
      '<code>' + esc(authority.ocsp) + '</code> (OCSP). ' +
      'Every certificate this authority signs names all three inside ' +
      'itself.</p>' +
      '<table class="grid"><thead><tr><th>Serial</th><th>Subject</th>' +
      '<th>Status</th><th></th></tr></thead><tbody>' +
      self.issuedRevocationRows(authority) +
      '</tbody></table>' + orphans;
  }

  private revocationPane(json: Json) {
    const { log, admin, esc } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.revocationPane().');
    const model = json.revocation;
    if (!model.authorities.length) {
      log.debug('Leaving PkiAdmin.revocationPane(). Nothing built.');
      return '<h3>Revoking a certificate</h3>' +
        admin.note('There is no certificate authority in the ' +
                   esc(self.realmLabel()) +
                   ' realm or on the process branch yet, so there is nothing ' +
                   'here to revoke and no list to publish. Build one above. ' +
                   'Another realm&rsquo;s authorities are not counted ' +
                   '&mdash; they are revoked in that realm.');
    }

    const what = admin.note(
      '<p><strong>A revocation is made BY AN ISSUER</strong>, which is why ' +
      'this pane is organised by authority rather than by certificate: a ' +
      'serial number is unique only within one issuer, so <em>revoke serial ' +
      '4f2a</em> is not a question this service can answer. It is also why ' +
      'there is one CRL and one OCSP responder per authority rather than one ' +
      'per realm &mdash; a list per realm would be a document with no valid ' +
      'issuer, and nothing could sign it.</p><p><strong>This is not the ' +
      '<em>Take the key pair off</em> control in the Applications table, and ' +
      'the difference matters.</strong> That one changes an ' +
      'application&rsquo;s directory entry, so this service stops ACCEPTING ' +
      'what the key signs &mdash; and the certificate goes on chaining to ' +
      'this realm&rsquo;s Root for anybody who only checks the chain. This ' +
      'one changes what the CRL and the OCSP responder SAY, and changes ' +
      'nothing about who holds what. An operator dealing with a compromised ' +
      'key pair almost certainly wants both, and they are two buttons ' +
      'because they are two acts with different blast ' +
      'radii.</p><p><strong>This service PUBLISHES revocation and cannot ' +
      'make anybody consult it.</strong> A certificate revoked here goes on ' +
      'the list and its responder answers <code>revoked</code>; whether that ' +
      'stops anything depends entirely on the relying party. That is true of ' +
      'every certificate authority there has ever been, and it is exactly ' +
      'why a client author would point their stack at this one. <strong>This ' +
      'service does not consult it either</strong> &mdash; a client ' +
      'certificate presented on the main port or on LDAPS 636 is checked ' +
      'against the anchors on <code>/tls/trust</code> and no CRL is fetched ' +
      'for it, so a certificate revoked here still gets in here.</p>',
      'What revoking here does, and the three things it does not do');

    const rotation = admin.note(
      '<p>Most entries on these lists were not put there by hand. ' +
      '<strong>Every rotation revokes what it replaced</strong>, as ' +
      '<code>superseded</code>: reissuing a use case&rsquo;s Issuing CA puts ' +
      'every leaf that CA had signed on its own list and puts the replaced ' +
      'CA on the Intermediate&rsquo;s, and replacing the Root does the same ' +
      'one tier up. That is what makes the lists worth reading &mdash; a ' +
      'service where only hand-revocations appeared would publish an empty ' +
      'CRL for ever while quietly leaving superseded certificates ' +
      'chaining.</p><p>A CRL is <strong>built and signed on demand rather ' +
      'than cached</strong>, so <code>thisUpdate</code> is always now and a ' +
      'revocation is visible to the next fetch. ' +
      '<code>pki.crlLifetimeMinutes</code> is ' +
      esc(String(model.crlLifetimeMinutes)) + ' minute(s), which is what ' +
      '<code>nextUpdate</code> and the HTTP cache header both say. The ' +
      'directory copy under <code>ou=crl</code> is ' +
      (model.publishedToDirectory
        ? 'republished as the list changes'
        : 'OFF (<code>pki.publishCrlToDirectory</code>), so the ' +
          '<code>ldap://</code> address inside ' +
          'these certificates resolve to nothing') + '.</p>',
      'Why these lists are not empty, and how fresh they are');

    const reasons = admin.note(
      '<p>RFC 5280 section 5.3.1 defines eleven values and this service ' +
      'offers nine. <code>7</code> is unused and has never meant anything; ' +
      '<code>removeFromCRL</code> is a delta-CRL verb rather than a reason, ' +
      'and this service publishes no delta CRLs, so offering it would be a ' +
      'control that could never be honoured.</p><ul>' +
      model.reasons.map(function (one) {
        return '<li><code>' + esc(one.id) + '</code> (' + one.code +
               ') &mdash; ' +
               esc(one.what.replace(/\*\*/g, '')) + '</li>';
      }).join('') + '</ul>',
      'The nine reasons, and the two that are deliberately missing');

    log.debug('Leaving PkiAdmin.revocationPane(). ' + model.authorities.length +
              ' authority(ies).');
    return '<h3>Revoking a certificate</h3>' + what + rotation + reasons +
      model.authorities.map(function (authority) {
        return self.authorityBlock(authority);
      }).join('');
  }

  // `extra` is the FIFTH argument and the only caller that passes one is the
  // person form's POST: a private key is handed over once and a banner is not
  // where a PEM block goes. Every other caller passes nothing and the page is
  // what it was.
  //
  // `certificate` is the SIXTH, and it is the details view the GET route
  // resolved for `?certificate=` (2026-09-13): its answer goes on the JSON as
  // `certificateDetails` and its dialog is drawn over the page. Absent, both
  // are absent, and the page is byte for byte what it was.
  private renderPki(req: Json, res: Json, draft: Json, banner: Json,
                    extra?: Json, certificate?: Json) {
    const { log, config, pki, certificateDialog, pqcBadge, adminViews, admin,
            esc } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.renderPki().');
    const json = self.pkiJson(req, draft);
    if (certificate) {
      json.certificateDetails = certificate;
    }
    const chain = json.chain;
    const keyAlg = config.value('pki.keyAlgorithm');
    // The two key-pair tables' pages. Every paging link carries both tables'
    // state, and every Take-off button carries it as `back`, so moving or
    // changing one table leaves the other where the reader left it.
    const paged = self.keyPairPaging(req.query, json);
    const listView = self.keyPairListView(req.query);
    const applicationsNav = admin.pageNavPair('/admin/pki', listView,
                                              paged.applications.paging);
    const peopleNav = admin.pageNavPair('/admin/pki', listView,
                                        paged.people.paging);
    const carryBack = '<input type="hidden" name="back" value="' +
      esc(adminViews.queryWith(listView, {})) + '">';

    const tiles = '<div class="tiles">' +
      admin.tile(chain ? 'yes' : 'no', 'hierarchy built') +
      admin.tile(chain ? String(chain.tiers.length) : '0', 'CA tiers') +
      admin.tile(chain ? String(chain.issuedCount) : '0',
                 'certificates issued') +
      admin.tile(json.issued.filter(function (one) {
        return one.hasKeyPair;
      }).length,
                 'applications holding one') +
      admin.tile(json.persons.filter(function (one) {
        return one.hasKeyPair || one.saml.hasKeyPair;
      }).length,
                 'people holding one') +
      admin.tile(json.realm, 'trust realm') +
      '</div>';

    const what = admin.note(
      '<p>This page builds a <strong>certificate authority for this trust ' +
      'realm</strong> &mdash; a Root CA, an Intermediate CA and an Issuing ' +
      'CA &mdash; and issues signing key pairs from the bottom of it to ' +
      'applications. It exists because of <strong>RFC 7521 and RFC ' +
      '7523</strong>: an application can authenticate to the token endpoint, ' +
      'or present an authorization grant, with a signed assertion instead of ' +
      'a shared secret &mdash; and a signing key nobody vouched for is a key ' +
      'an operator has to move by hand.</p><p><strong>All three tiers are ' +
      'built in one act, or none is.</strong> A trust chain is only worth ' +
      'anything whole: an Issuing CA with no Intermediate above it is a ' +
      'two-tier chain wearing a three-tier name, and a half-built hierarchy ' +
      'is exactly the state in which somebody issues a certificate that ' +
      'verifies here and nowhere else.</p><p><strong>It is per ' +
      'realm.</strong> A trust realm is a logical identity service with its ' +
      'own signing key and its own applications; a CA shared across realms ' +
      'would be one authority vouching for several services, which is the ' +
      'one thing a realm boundary exists to prevent. This page shows the ' +
      '<code>' + esc(json.realm) + '</code> realm.</p><p>The encoder ' +
      'is <code>common/vendored/x509.js</code> &mdash; the parent ' +
      'project&rsquo;s own PKI code, byte-identical, the same one behind its ' +
      '<em>PKI / X.509</em> workflow page. So a certificate issued here and ' +
      'one issued there are built by <em>one</em> encoder, and a difference ' +
      'between them is a difference in the arguments rather than in two ' +
      'implementations that drifted.</p>',
      'What this page is');

    // **THIS BLOCK SAID *Nothing here is revoked, ever* UNTIL 2026-09-11**, and
    // it was true when it was written. What replaced it is narrower rather than
    // absent, because the interesting limit did not go away when the CRLs
    // arrived — it moved. It read *this service publishes revocation and
    // consults none* until 2026-09-12, when presented certificates began to be
    // checked (`common/revocation_status.js`); `json.revocationNote` is
    // `pki.report()`'s sentence and says what is consulted now.
    const limits = admin.warn(
      '<p><strong>Revocation here is PUBLISHED and never ENFORCED.</strong> ' +
      esc(json.revocationNote) + '</p><p>' + esc(json.residency) + '</p>',
      'What this certificate authority does not do');

    const buildForm =
      '<h3>' + (chain ? 'Rebuild' : 'Build') + ' the hierarchy</h3>' +
      (chain ? admin.warn(
        'A hierarchy already exists. Building again ' +
        '<strong>replaces</strong> it, and every certificate issued from the ' +
        'old one chains to nothing the moment it does &mdash; this service ' +
        'keeps no copy of what it issued, so none of them can be listed here.',
        'This replaces what is there') : '') +
      '<form method="post" action="/admin/pki">' +
      '<input type="hidden" name="action" value="build">' +
      '<label>Key algorithm <select name="keyAlg">' +
        self.algorithmOptions(json, keyAlg) + '</select></label> ' +
      '<label>Signature algorithm <select name="signatureAlg">' +
        self.signatureOptions(json, keyAlg) + '</select></label> ' +
      self.alternativeField(json, '') +
      '<label>Organisation (O=) <input name="organisation" value="' +
        esc(config.value('pki.organisation')) + '"></label> <label>Country ' +
      '(C=) <input name="country" size="4" ' +
      'maxlength="2"></label><p>' + pki.TIERS.map(function (tier) {
        return '<label>' + esc(tier.label) + ' CN <input name="cn_' +
          esc(tier.id) + '" placeholder="(named after the ' +
          'organisation)"></label> <label>years <input ' +
          'name="years_' + esc(tier.id) +
          '" size="4" placeholder="' +
          esc(String((json.tiers.filter(function (t) {
            return t.id === tier.id;
          })[0] || {}).years || '')) + '"></label>';
      }).join(' ') + '</p>' +
      '<button type="submit">' + (chain ? 'Rebuild' : 'Build') +
      ' the certificate authority</button>' +
      '</form>' +
      (chain
        ? '<form method="post" action="/admin/pki">' +
          '<input type="hidden" name="action" value="clear">' +
          '<button type="submit">Remove the hierarchy</button></form>'
        : '');

    const purposeOptions = json.purposes.map(function (one) {
      return '<option value="' + esc(one.id) + '">' + esc(one.label) +
             '</option>';
    }).join('');

    const issueForm = chain
      ? '<h3>Issue a signing key pair to an application</h3>' +
        admin.tip(
          'The key pair is generated here, signed by the Issuing CA, and ' +
          'written onto that application’s entry. WHICH attributes depends ' +
          'on the profile: RFC 7523 writes seven &mdash; ' +
          'oauthAssertionPrivateKey, oauthAssertionCertificate, ' +
          'oauthAssertionCertificateChain, oauthAssertionJwks, ' +
          'oauthAssertionKid, oauthAssertionExpiresAt and ' +
          'oauthAssertionKeySource &mdash; and RFC 7522 writes six under ' +
          'oauthSamlAssertion*, with no JWKS among them because SAML has ' +
          'none: what a party registers for that profile is a certificate. ' +
          '<strong>They are separate key pairs and an application may hold ' +
          'both</strong>; neither can sign for the other’s profile, and ' +
          'taking one off leaves the other working. This service keeps NO ' +
          'second copy of the private key — the entry is where it lives, and ' +
          'it is SEALED there: AES-256-GCM under the same key-encryption key ' +
          'as the certificate authority above, wherever that key outlives ' +
          'the process. A directory dump, an ldif file, a database row or a ' +
          'backup holds ciphertext; this console and /admin-api open it for ' +
          'you, because the seal protects the store rather than the page you ' +
          'collect the key from. In development mode it is written in the ' +
          'clear, where the key-encryption key would not survive the restart ' +
          'the entry does. Issuing again replaces what is there.',
          'What issuing writes, and where') +
        '<form method="post" action="/admin/pki">' +
        '<input type="hidden" name="action" value="issue">' +
        '<label>Application <input name="identifier" required></label> ' +
        '<label>Profile <select name="purpose">' + purposeOptions +
          '</select></label> ' +
        '<label>Subject CN <input name="commonName" ' +
          'placeholder="(the application identifier)"></label> ' +
        '<label>Key algorithm <select name="leafKeyAlg">' +
          '<option value="">(the Issuing CA’s: ' + esc(chain.keyAlg) +
          ')</option>' + self.algorithmOptions(json, '') +
          '</select></label> ' +
        '<label>Days <input name="days" size="5" value="' +
          esc(String(config.value('pki.leafLifetimeDays'))) + '"></label> ' +
        '<button type="submit">Generate and issue</button>' +
        '</form>'
      : admin.warn(
        'There is no certificate authority in this realm yet, so there is ' +
        'nothing to issue from. Build one above.',
        'Nothing to issue from');

    // -------------------------------------------------------------------------
    // AND THE SAME CONTROL FOR A PERSON (2026-09-11).
    //
    // It is a form of its own rather than a radio button on the one above, and
    // the reason is the POST target: this one goes to /admin/pki/person, which
    // answers with a PAGE carrying the private key, where every other control
    // on this page 303s with its message on the query string. A private key on
    // a query string is a private key in the browser history, the access log
    // and the next request's Referer header.
    //
    // The ACTION is the same `issue` and the field that tells them apart is
    // `target`, so `/admin-api/pki/issue` drives both — which is rule 7 with no
    // second operation invented for it.
    // -------------------------------------------------------------------------
    const personForm = chain
      ? '<h3>Issue a signing key pair to a person</h3>' +
        admin.tip(
          'RFC 7523 section 2.1 does not say the issuer of an assertion has ' +
          'to be an application. Claim 1 asks only that <code>iss</code> be ' +
          '“a unique identifier for the JWT issuer”, and claim 2 says the ' +
          '<code>sub</code> of an authorization grant “typically identifies ' +
          'an authorized accessor or resource owner”. So a person holding a ' +
          'key of their own, signing <em>this is me, issue a token for ' +
          'me</em>, is the profile read literally — and it is the shape a ' +
          'client author most often wants to exercise: no browser, no ' +
          'password, a signature and an access token. RFC 7522 reads the ' +
          'same way for a SAML <code>&lt;Issuer&gt;</code>. This writes ' +
          '<code>stsAssertion*</code> for the JWT profile or ' +
          '<code>stsSamlAssertion*</code> for the SAML one onto that ' +
          'person’s entry — two sets sharing no name, so neither key pair ' +
          'signs for the other — with the private half sealed exactly as an ' +
          'application’s is. The person’s own page under ' +
          '<code>/admin/users</code> draws both, and replaces either with an ' +
          'uploaded certificate.',
          'What a person’s key pair is for') +
        admin.warn(
          '<p><strong>A person’s assertion may only be about ' +
          'themselves.</strong> The <code>iss</code> and the ' +
          '<code>sub</code> must name the same person, and one naming ' +
          'anybody else is refused — a key issued to one resource owner is ' +
          'that person’s credential rather than permission to speak for the ' +
          'others, and without the rule anybody given a key here could ' +
          'obtain a token as anybody in this realm. <strong>A party that may ' +
          'assert about other people is an APPLICATION</strong> with the ' +
          'issuer declared on it as <code>oauthAssertionIssuer</code> (or ' +
          '<code>oauthSamlAssertionIssuer</code>), which is a decision an ' +
          'operator makes deliberately. That is the whole difference between ' +
          'the two controls.</p><p><strong>The private key is shown ' +
          'once.</strong> It comes back on the page this form posts to and ' +
          'there is no second door to it: it is sealed on the entry and ' +
          'nothing here opens it. An application’s is different because ' +
          '<code>/admin/applications</code> already opens that one, and a ' +
          'console page that printed a <em>person’s</em> private key on ' +
          'every visit would be a worse answer than this.</p>',
          'Two things to know before you press it') +
        '<form method="post" action="/admin/pki/person">' +
        '<input type="hidden" name="action" value="issue">' +
        '<input type="hidden" name="target" value="person">' +
        // BOTH PROFILES SINCE 2026-09-13, which is the select this form did not
        // have: the SAML bearer grant reads a person's RFC 7522 key pair now.
        '<label>Profile <select name="purpose">' +
          json.purposes.map(function (one) {
            return '<option value="' + esc(one.id) + '">' + esc(one.label) +
                   '</option>';
          }).join('') + '</select></label> ' +
        '<label>Person <input name="identifier" required ' +
          'placeholder="a username in ou=users"></label> ' +
        '<label>Declared issuer <input name="issuer" ' +
          'placeholder="(their username)"></label> ' +
        '<label>Subject CN <input name="commonName" ' +
          'placeholder="(their username)"></label> ' +
        '<label>Key algorithm <select name="leafKeyAlg">' +
          '<option value="">(the Issuing CA’s: ' + esc(chain.keyAlg) +
          ')</option>' + self.algorithmOptions(json, '') +
          '</select></label> ' +
        '<label>Days <input name="days" size="5" value="' +
          esc(String(config.value('pki.leafLifetimeDays'))) + '"></label> ' +
        '<button type="submit">Generate and issue</button>' +
        '</form>'
      : '';

    const personRows = !json.personsStorable
      ? admin.warn(
        'This process has no directory, so nobody can hold an assertion key ' +
        'pair and an assertion naming a person as its issuer is refused for ' +
        'want of a registered issuer.', 'No directory')
      : (json.persons.length
        // A ROW PER PROFILE A PERSON HOLDS OR DECLARES (2026-09-13), for the
        // applications table's reason: every fact on the row — the handle, the
        // expiry, the declared issuer and the Take-off button — is per profile.
        ? peopleNav.head +
          '<table><thead><tr><th>Person</th><th>Profile</th>' +
          '<th>Key handle</th><th>Source</th><th>Expires</th>' +
          '<th>Asserts as</th><th></th></tr></thead><tbody>' +
          paged.people.shown.reduce(function (rows, one) {
            [{ id: 'jwt', label: 'RFC 7523 (JWT)', handleLabel: 'kid',
               fact: one, handle: one.kid },
             { id: 'saml', label: 'RFC 7522 (SAML 2.0)',
               handleLabel: 'thumbprint', fact: one.saml,
               handle: one.saml.thumbprint }].forEach(function (p) {
              if (!p.fact.hasKeyPair && !p.fact.declared) {
                return;
              }
              rows.push('<tr>' +
                '<td><a href="/admin/users?user=' +
                  encodeURIComponent(one.username) + '#credentials">' +
                  esc(one.username) + '</a></td>' +
                '<td>' + esc(p.label) + '</td>' +
                '<td><code>' + esc(p.handle || '—') + '</code>' +
                  (p.handle ? ' <small>(' + p.handleLabel + ')</small>' : '') +
                  pqcBadge.badge(p.fact.pqc) + '</td>' +
                '<td>' + esc(p.fact.source || '—') + '</td>' +
                '<td>' + esc(p.fact.expiresAt ? p.fact.expiresAt.slice(0, 8)
                                              : '—') + '</td>' +
                '<td>' + p.fact.issuers.map(function (iss) {
                    return '<code>' + esc(iss) + '</code>';
                  }).join('<br>') +
                  (p.fact.declared ? '' : ' <small>(their own name — nothing ' +
                                          'is declared)</small>') + '</td>' +
                '<td>' + (p.fact.hasKeyPair
                  ? '<form method="post" action="/admin/pki"><input ' +
                    'type="hidden" name="action" value="revoke"><input ' +
                    'type="hidden" name="target" value="person"><input ' +
                    'type="hidden" name="purpose" value="' + p.id + '">' +
                    '<input type="hidden" name="identifier" value="' +
                      esc(one.username) + '">' + carryBack +
                    '<button type="submit">Take this key pair off</button>' +
                    '</form>'
                  : '') + '</td>' +
                '</tr>');
            });
            return rows;
          }, []).join('') + '</tbody></table>' + peopleNav.foot
        : '<p>Nobody in this realm holds an assertion key pair.</p>');

    const issuedRows = json.issued.length
      ? applicationsNav.head +
        '<table><thead><tr><th>Application</th><th>Profile</th>' +
        '<th>Key handle</th><th>Expires</th>' +
        '<th>Declared issuer</th><th>Own keys</th><th></th></tr>' +
        '</thead><tbody>' +
        paged.applications.shown.map(function (one) {
          return '<tr>' +
            '<td><a href="/admin/applications?application=' +
              encodeURIComponent(one.identifier) + '">' +
              esc(one.identifier) + '</a></td>' +
            '<td>' + esc(one.purposeLabel) + '</td>' +
            '<td><code>' + esc(one.handle || '—') + '</code>' +
              (one.handle ? ' <small>(' + esc(one.handleLabel) + ')</small>' :
               '') + pqcBadge.badge(one.pqc) +
              '</td>' +
            '<td>' + esc(one.expiresAt ? one.expiresAt.slice(0, 8) : '—') +
              '</td>' +
            '<td>' + (one.assertionIssuers.length
              ? one.assertionIssuers.map(function (iss) {
                  return '<code>' + esc(iss) + '</code>';
                }).join('<br>')
              : '<em>none — it can authenticate, and cannot present an ' +
                'authorization grant</em>') + '</td>' +
            '<td>' + (one.registeredOwnKeys ? 'yes' : 'no') + '</td>' +
            '<td>' + (one.hasKeyPair
              ? '<form method="post" action="/admin/pki">' +
                '<input type="hidden" name="action" value="revoke">' +
                '<input type="hidden" name="identifier" value="' +
                  esc(one.identifier) + '">' +
                '<input type="hidden" name="purpose" value="' +
                  esc(one.purpose) + '">' + carryBack +
                '<button type="submit">Take this key pair off</button></form>'
              : '') + '</td>' +
            '</tr>';
        }).join('') + '</tbody></table>' + applicationsNav.foot
      : '<p>No application in this realm holds a key pair issued here, and ' +
        'none declares an assertion issuer.</p>';

    const twoActs = admin.note(
      '<p>Holding a key pair and being <em>trusted to assert</em> are two ' +
      'different things, and this table shows both because an application ' +
      'commonly has one and not the other.</p><p><strong>A key pair</strong> ' +
      'lets an application sign. That is all RFC 7523 <em>section 2.2</em> ' +
      'needs &mdash; client authentication, where the assertion says who is ' +
      'calling &mdash; so an application with a key pair and no declared ' +
      'issuer can already authenticate at the token endpoint with ' +
      '<code>private_key_jwt</code>.</p><p><strong>A declared ' +
      '<code>iss</code></strong> (<code>oauthAssertionIssuer</code>, set on ' +
      'the application&rsquo;s own page) is what section <em>2.1</em> needs ' +
      '&mdash; the authorization grant, where the assertion says who the ' +
      'token is <em>for</em>. That grant has no browser, no password and no ' +
      'consent step in it, so the signature is the whole of its security: ' +
      'this service will not accept one from an issuer nobody declared, and ' +
      '<code>oauth2.jwtBearerRequireRegisteredIssuer</code> is on by default ' +
      'for the same reason federation refuses by default.</p><p>An assertion ' +
      'a client issues <em>about itself</em> needs no declaration: its ' +
      '<code>iss</code> is its own <code>client_id</code>, and that lookup ' +
      'already succeeds.</p><p><strong>RFC 7522 is the same two acts over a ' +
      'SAML 2.0 assertion</strong>, with its own key pair and its own ' +
      'declaration (<code>oauthSamlAssertionIssuer</code>). The two profiles ' +
      'are kept apart deliberately: an application trusted to assert as a ' +
      'JWT has not thereby been trusted to assert as SAML, and the key pairs ' +
      'cannot stand in for one another. There is one further difference, and ' +
      'it is the only place this service is <em>stricter</em> for SAML: a ' +
      'JWT assertion may carry its certificate chain in <code>x5c</code> and ' +
      'be accepted because the chain reaches this realm&rsquo;s Root, and a ' +
      'SAML assertion may not. A chain proves the <em>realm</em> issued a ' +
      'key; the URI subjectAltName in the leaf says who to, and the JWT ' +
      'grant reads it for exactly one purpose &mdash; holding a PERSON to ' +
      'asserting about themselves &mdash; rather than binding an ' +
      'application. So a chain still says nothing usable about ' +
      '<em>which</em> application holds a key, and accepting one here would ' +
      'let an application&rsquo;s RFC 7523 leaf sign a SAML assertion, which ' +
      'is exactly the crossing the two key pairs exist to prevent.</p>',
      'A key pair is not a trust decision');

    admin.respond(req, res, json, 'PKI', '/admin/pki',
                  (banner || '') +
                  (extra || '') +
                  tiles + what + limits + pqcBadge.legend() +
                  '<h3 id="pki-tree">The hierarchy</h3>' +
                  admin.note(
                    '<strong>One Root CA for the whole service, an ' +
                    'Intermediate CA per scope, and an Issuing CA for each ' +
                    'use case under it.</strong> Every key pair this service ' +
                    'generates is a leaf of this tree &mdash; the signing ' +
                    'keys of every realm, and the certificate the main port ' +
                    'and LDAPS 636 serve &mdash; so an operator installs ONE ' +
                    'anchor and it covers both of those sockets and every ' +
                    'token this service signs.<p><strong>A realm shares the ' +
                    'Root and has an Intermediate of its own</strong>, and ' +
                    'that is where the realm boundary is: with one Root, ' +
                    '&ldquo;this chains to our Root&rdquo; is true of every ' +
                    'realm&rsquo;s certificates, so a path is checked ' +
                    'against this realm&rsquo;s own Intermediate instead. A ' +
                    'certificate issued in one realm still does not verify ' +
                    'in another.</p><p><strong>What is drawn below is the ' +
                    esc(self.realmLabel()) + ' realm&rsquo;s, and only ' +
                    'that.</strong> The Root, because every realm hangs from ' +
                    'it; the <em>process</em> branch, because the TLS and ' +
                    'SPIFFE authorities certify sockets every realm answers ' +
                    'on; and this realm&rsquo;s own Intermediate with its ' +
                    'Issuing CAs. Another realm&rsquo;s branch is not here ' +
                    'and cannot be edited from here &mdash; <strong>switch ' +
                    'realms to reach it</strong>, which is how every other ' +
                    'setting on this console already works. <code>GET ' +
                    '/admin-api/pki</code> answers exactly this, in ' +
                    'whichever realm it is reached in.</p><p>It is built at ' +
                    'startup (<code>pki.autoBuild</code>). Turning that off ' +
                    'is how this service behaves as it did before ' +
                    '2026-09-11: nothing is built until Build is pressed and ' +
                    'every key carries the self-signed certificate it was ' +
                    'born with.</p>',
                    'What this tree is, and where the realm boundary went') +
                  self.treeSection(json) +
                  self.coverageNote(json) +
                  '<h3>Edit the hierarchy</h3>' +
                  self.rootControls(json) +
                  (json.tree.scopes || []).map(function (scope) {
                    return self.scopeControls(json, scope);
                  }).join('') +
                  (chain ? '<h3 id="pki-chain">This realm&rsquo;s three-tier ' +
                           'view</h3>' +
                           admin.note(
                             'The Root, this realm&rsquo;s Intermediate and ' +
                             'its <em>application assertion</em> Issuing CA ' +
                             '&mdash; which is what <code>GET ' +
                             '/admin-api/pki</code> has always answered and ' +
                             'what RFC 7523 needs. The other Issuing CAs are ' +
                             'in the tree above.') +
                           self.chainTable(chain) +
                           self.pemBlocks(chain) : '') +
                  buildForm + issueForm +
                  '<h3 id="pki-applications">Applications</h3>' + twoActs +
                  (json.issued.length || json.persons.length
                    ? admin.perPageForm('/admin/pki', 'issuedPage', '1',
                        paged.applications.paging.perPage,
                        'That is this table and the People table below it.')
                    : '') +
                  issuedRows +
                  personForm +
                  '<h3 id="pki-people">People</h3>' + personRows +
                  self.revocationPane(json) +
                  self.certificatePane(json, json.workbench.draft) +
                  admin.configFormsFor('/admin/pki') +
                  (certificate
                    ? certificateDialog.dialog('/admin/pki', certificate,
                                               req.query.from)
                    : ''));
    log.debug('Leaving PkiAdmin.renderPki().');
  }

  // ---------------------------------------------------------------------------
  // WHERE A PKI ACTION GOES BACK TO (2026-09-13). The key-pair controls are
  // drawn on an application's own page as well as here — moving a FORM is not
  // moving an ACTION, which is `/admin/delegation`'s arrangement with the grant
  // form — so a form posted from there names `from` and goes back there. `from`
  // is a NAME checked against the one page that sends it, never a URL, and the
  // destination is REBUILT from `identifier` by the console, for
  // `permissionsReturnTo()`'s reason: a redirect target taken out of a request
  // body is an open redirect.
  // ---------------------------------------------------------------------------
  pkiReturnTo(body: Json) {
    const { log, adminViews, admin } = this.deps;
    const self = this;
    log.debug("Entering PkiAdmin.pkiReturnTo().");
    const identifier = String((body && body.identifier) || '').trim();
    if (String((body && body.from) || '') === '/admin/applications' &&
        identifier && typeof admin.applicationReturnTo === 'function') {
      log.debug("Leaving PkiAdmin.pkiReturnTo(). The application page.");
      return admin.applicationReturnTo(body, identifier, '#credentials');
    }
    // AND A PERSON'S OWN PAGE (2026-09-13), whose Credentials section draws the
    // same controls. The same rule: a name, and a destination rebuilt.
    if (String((body && body.from) || '') === '/admin/users' &&
        identifier && typeof admin.userReturnTo === 'function') {
      log.debug("Leaving PkiAdmin.pkiReturnTo(). The person's page.");
      return admin.userReturnTo(body, identifier, '#credentials');
    }
    // A TAKE-OFF BUTTON IN ONE OF THIS PAGE'S TWO PAGED TABLES (2026-09-13),
    // which carries `back` so the reader lands on the page of the table they
    // pressed it in rather than on page 1 of both, several screens above it.
    // Only those buttons carry the field; every other control here posts
    // without it and gets the bare page, as before.
    if (body && Object.prototype.hasOwnProperty.call(body, 'back')) {
      log.debug("Leaving PkiAdmin.pkiReturnTo(). This page, at a key-pair " +
                "table.");
      return '/admin/pki' +
             adminViews.queryWith(self.keyPairListViewFromBack(body.back), {}) +
             (String(body.target || '') === 'person' ? '#pki-people'
                                                     : '#pki-applications');
    }
    log.debug("Leaving PkiAdmin.pkiReturnTo(). This page.");
    return '/admin/pki';
  }

  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, parseBody, authoring, errorCodes, certificateViews,
            certificateDialog, admin, esc } = this.deps;
    const self = this;
    log.debug("Entering PkiAdmin.registerRoutes().");
    app.get('/admin/pki', function (req, res) {
      log.debug('Entering the admin PKI page.');
      if (!certificateDialog.requested(req)) {
        self.renderPki(req, res, null, '');
        log.debug('Leaving the admin PKI page.');
        return;
      }
      // A CERTIFICATE'S DETAILS OVER THE PAGE (2026-09-13). Asynchronous
      // because verifying a chain is Web Crypto; the page is drawn once the
      // answer is in. A refusal still opens the dialog, which says why, and is
      // marked — an open that cannot be answered is a refused lookup, not a
      // page that failed.
      certificateViews.detailsView(req).then(function (view) {
        if (!view.ok) {
          errorCodes.mark(res, errorCodes.codeOf(view) || 'STS-ADMIN-0641');
        }
        self.renderPki(req, res, null, '', '', view);
        log.debug('Leaving the admin PKI page. With a certificate dialog.');
      }).catch(function (e) {
        log.error(errorCodes.tag('STS-ADMIN-0642') + 'pki_admin: the ' +
                  'certificate details view failed: ' + e.message);
        errorCodes.mark(res, 'STS-ADMIN-0642');
        self.renderPki(req, res, null, '', '', { ok: false, errors: [
          'The certificate could not be opened: ' + e.message] });
      });
    });

    // -------------------------------------------------------------------------
    // THE PANE'S POST, WHICH ANSWERS WITH A PAGE AND NOT A REDIRECT.
    //
    // Every other control in this console goes through `respondToAction()`,
    // which 303s back with a message on the query string. This one cannot: what
    // it has to hand back is the FORM — the profile applied, the key pair
    // generated, the refusal with every field still in it — and a query string
    // is not where a hundred and fifteen fields go. `/admin/users/new` made
    // exactly this argument first and for the same reason.
    //
    // **A JSON CALLER STILL GETS JSON**, so `/admin-api`'s behaviour is
    // unchanged and a test may drive either door.
    // -------------------------------------------------------------------------
    app.post('/admin/pki/certificate', function (req, res) {
      log.debug('Entering the admin PKI pane action.');
      const body = parseBody(req);
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-PKI-0101');
        admin.respondToAction(req, res, '/admin/pki',
                              self.refuse('This console session may read but ' +
                                          'not write.', 'STS-PKI-0101'));
        log.debug('Leaving the admin PKI pane action. Read-only.');
        return;
      }
      // WHICH BUTTON, then the action it means. The console never sends an
      // `action` of its own for this form bar the hidden one behind the Issue
      // button, so the pressed button wins.
      const pressed = self.paneActionFrom(body);
      const asked = Object.assign({}, body, { action: pressed.action },
                                  pressed.objectId
                                    ? { objectId: pressed.objectId } : {});
      self.pkiAction(asked).then(function (result) {
        self.markRefusal(res, result, 'STS-PKI-0105');
        if (/json/i.test(String(req.headers['content-type'] || ''))) {
          res.status(result.ok ? 200 : 400).type('application/json')
             .set('Cache-Control', 'no-store')
             .send(JSON.stringify(result, null, 2));
          log.debug('Leaving the admin PKI pane action. Answered JSON.');
          return;
        }
        const message = result.ok ? String(result.why || 'Done.')
          : ((result.errors || []).join(' ') || String(result.why || ''));
        const banner = result.ok ? admin.note(esc(message))
                                 : admin.warn(esc(message), 'That was refused');
        // The draft a refusal carries where it has one, and what was posted
        // where it does not — a refusal that redrew the form empty would be
        // worse than the refusal.
        self.renderPki(req, res, result.draft || authoring.draftFrom(body),
                       banner);
        log.debug('Leaving the admin PKI pane action. ' + pressed.action + '.');
      }).catch(function (e) {
        log.error(errorCodes.tag('STS-PKI-0102') + 'pki_admin: the pane\'s ' +
            pressed.action + ' ' +
            'action threw: ' +
                  (e && e.stack ? e.stack : e));
        errorCodes.mark(res, 'STS-PKI-0102');
        self.renderPki(req, res, authoring.draftFrom(body),
                       admin.warn(esc('That action failed: ' +
                                      (e && e.message ? e.message : e)),
                                  'That was refused'));
        log.debug('Leaving the admin PKI pane action. It threw.');
      });
    });

    // -------------------------------------------------------------------------
    // THE EXPORT, WHICH ANSWERS WITH A FILE.
    //
    // The one form on this page whose answer is not a page. It is the same
    // arrangement `/admin/keys/export` has and for its reasons, including the
    // two that are easy to skip:
    //
    //   * **ADMIN WRITE, asked for explicitly.** Reading this console needs
    //     Admin Read; taking a private key out of it needs the other role. It
    //     is a GET-shaped act done as a POST for exactly that reason.
    //   * **ONE FILE IS THE BODY; SEVERAL ARE A ZIP THIS SERVICE WILL NOT
    //     BUILD.** The DER export is two files (private and public) and the
    //     private one is sent, with the reply saying the public half comes out
    //     of it with one openssl command.
    //
    // A REFUSAL IS A PAGE, so a bad password or an impossible format reads like
    // every other refusal here rather than as a broken download.
    // -------------------------------------------------------------------------
    app.post('/admin/pki/export', function (req, res) {
      log.debug('Entering the admin PKI export.');
      const body = parseBody(req);
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-PKI-0101');
        res.status(403).type('text/plain').set('Cache-Control', 'no-store')
           .send('Exporting a key pair needs the Admin Write role. Reading ' +
                 'this console needs Admin Read; taking a private key out of ' +
                 'it needs the other one.');
        log.debug('Leaving the admin PKI export. Refused: no Admin Write.');
        return;
      }
      const draft = authoring.draftFrom(body);
      authoring.exportKeys(undefined, draft, self.objectIdOf(body))
        .then(function (written) {
          if (!written.ok) {
            self.markRefusal(res, written, 'STS-PKI-0100');
            self.renderPki(req, res, draft,
                           admin.warn(esc(written.errors.join(' ')),
                                      'That export was refused'));
            log.debug('Leaving the admin PKI export. Refused.');
            return;
          }
          const file = written.files[0];
          const data = Buffer.isBuffer(file.data) ? file.data
            : (typeof file.data === 'string' ? Buffer.from(file.data, 'utf8')
               : Buffer.from(file.data));
          res.status(200)
             .set('Content-Type', file.mime || 'application/octet-stream')
             .set('Content-Disposition', 'attachment; filename="' +
                  String(file.name).replace(/[^A-Za-z0-9._-]/g, '_') + '"')
             .set('Cache-Control', 'no-store')
             .send(data);
          log.debug('Leaving the admin PKI export. Sent ' + file.name + ', ' +
                    data.length + ' bytes.');
        }).catch(function (e) {
          log.error(errorCodes.tag('STS-PKI-0103') +
                    'pki_admin: the export threw: ' +
                    (e && e.stack ? e.stack : e));
          errorCodes.mark(res, 'STS-PKI-0103');
          self.renderPki(req, res, draft,
                         admin.warn(esc('That export failed: ' +
                                        (e && e.message ? e.message : e)),
                                    'That export was refused'));
          log.debug('Leaving the admin PKI export. It threw.');
        });
    });

    app.post('/admin/pki', function (req, res) {
      log.debug('Entering the admin PKI action.');
      const body = parseBody(req);
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-PKI-0101');
        admin.respondToAction(req, res, '/admin/pki',
                              self.refuse('This console session may read but ' +
                                          'not write.', 'STS-PKI-0101'));
        log.debug('Leaving the admin PKI action. Read-only.');
        return;
      }
      // **AWAITED, AND THE HANDLER IS WRAPPED.** Express 4 does not look at
      // what a handler returns, so a promise that rejects here would be an
      // unhandled rejection and a request that never gets an answer — the same
      // trap the token endpoint's wrapper exists for, met again by the second
      // asynchronous action function in this console.
      self.pkiAction(body).then(function (result) {
        self.markRefusal(res, result, 'STS-PKI-0105');
        // A SUCCESS HERE SAYS WHAT IT DID IN `why`, and `respondToAction()`
        // puts `message` on the redirect — so every notice from this handler
        // read `undefined`. This page draws no notice and nobody saw it; the
        // application page this handler now also answers to draws one.
        const answered = result && result.ok && result.message === undefined &&
                         result.why
          ? Object.assign({}, result, { message: result.why }) : result;
        admin.respondToAction(req, res, self.pkiReturnTo(body), answered);
        log.debug('Leaving the admin PKI action.');
      }).catch(function (e) {
        log.error(errorCodes.tag('STS-PKI-0102') + 'pki_admin: the ' +
                  String(body && body.action) + ' ' +
                  'action threw: ' + (e && e.stack ? e.stack : e));
        errorCodes.mark(res, 'STS-PKI-0102');
        admin.respondToAction(req, res, '/admin/pki',
                              self.refuse('That action failed: ' +
                                          (e && e.message ? e.message : e),
                                          'STS-PKI-0102'));
        log.debug('Leaving the admin PKI action. It threw.');
      });
    });

    // -------------------------------------------------------------------------
    // THE PERSON FORM'S POST, WHICH ANSWERS WITH A PAGE FOR A DIFFERENT REASON
    // FROM THE PANE'S (2026-09-11).
    //
    // The pane's POST renders a page because what it hands back is a FORM with
    // a hundred and fifteen fields in it. This one renders a page because what
    // it hands back is **a private key**, and `admin.respondToAction()` 303s
    // with its message on the query string — which would put that key in the
    // browser history, in this service's own access log, and in the `Referer`
    // header of the next request the browser makes.
    //
    // It is the SAME `issue` action with `target=person`, so
    // `/admin-api/pki/issue` drives it too and rule 7 is satisfied without a
    // second operation. **A JSON caller still gets JSON**, exactly as the
    // pane's route does.
    // -------------------------------------------------------------------------
    app.post('/admin/pki/person', function (req, res) {
      log.debug('Entering the admin PKI person action.');
      const body = parseBody(req);
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-PKI-0101');
        admin.respondToAction(req, res, '/admin/pki',
                              self.refuse('This console session may read but ' +
                                          'not write.', 'STS-PKI-0101'));
        log.debug('Leaving the admin PKI person action. Read-only.');
        return;
      }
      // The TARGET is forced rather than read. This route exists for one
      // control and a body that arrived here naming `application` would
      // otherwise be answered by the application branch — which writes onto an
      // entry this form never mentioned, and would then render the page with an
      // application's private key on it, which is the one thing the route was
      // written to keep off a query string and is no better on this page.
      const asked = Object.assign({}, body,
                                  { action: 'issue', target: 'person' });
      self.pkiAction(asked).then(function (result) {
        self.markRefusal(res, result, 'STS-PKI-0105');
        if (/json/i.test(String(req.headers['content-type'] || ''))) {
          res.status(result.ok ? 200 : 400).type('application/json')
             .set('Cache-Control', 'no-store')
             .send(JSON.stringify(result, null, 2));
          log.debug('Leaving the admin PKI person action. Answered JSON.');
          return;
        }
        const message = result.ok ? String(result.why || 'Done.')
          : ((result.errors || []).join(' ') || String(result.why || ''));
        const banner = result.ok
          ? admin.note(esc(message).replace(/\*\*(.+?)\*\*/g,
                                            '<strong>$1</strong>'))
          : admin.warn(esc(message), 'That was refused');
        // THE KEY ITSELF, in a block of its own under the banner. It is HERE
        // and nowhere else in this console — see `issueToPerson()`'s header for
        // why there is no read door for it, and `app.js` for why this response,
        // like every document here that publishes a key, is `no-store`.
        const saml = result.ok && result.purpose === 'saml';
        const keyBlock = result.ok
          ? admin.warn(
            '<p>This is the only time this service will show you this key. ' +
            'It is sealed on <code>' + esc(String(result.person)) +
            '</code>’s entry ' + 'as <code>' +
            (saml ? 'stsSamlAssertionPrivateKey' : 'stsAssertionPrivateKey') +
            '</code> and nothing in this console or in ' +
            '<code>/admin-api</code> opens it again. Copy it now; issuing ' +
            'again replaces it.</p>' +
            (saml
              // THE RFC 7522 SHAPE (2026-09-13): what the person signs is an
              // <Assertion>, so the paragraph names its elements rather than a
              // JWT's claims.
              ? '<p>The assertion it signs carries an <code>&lt;Issuer&gt;' +
                '</code> and a <code>&lt;Subject&gt;</code> of <code>' +
                esc(String(result.issuer)) + '</code>, an ' +
                '<code>&lt;AudienceRestriction&gt;</code> naming this ' +
                'service’s token endpoint, a bearer ' +
                '<code>&lt;SubjectConfirmation&gt;</code>, a ' +
                '<code>NotOnOrAfter</code> and an <code>ID</code>, is signed ' +
                'with an XML Signature over the ' +
                '<code>&lt;Assertion&gt;</code>, and is presented as ' +
                '<code>grant_type=urn:ietf:params:oauth:grant-type:' +
                'saml2-bearer</code> with ' +
                '<code>assertion=&lt;base64url&gt;</code>. The ' +
                'certificate’s thumbprint is <code>' +
                esc(String(result.thumbprint)) + '</code>.</p>'
              : '<p>The assertion it signs carries <code>iss</code> and ' +
                '<code>sub</code> of <code>' + esc(String(result.issuer)) +
                '</code>, an <code>aud</code> of this service’s token ' +
                'endpoint or issuer, an <code>exp</code> and a ' +
                '<code>jti</code>, and is presented as ' +
                '<code>grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' +
                '</code> with <code>assertion=&lt;the JWT&gt;</code>. ' +
                '<code>kid</code> is <code>' + esc(String(result.kid)) +
                '</code> and the algorithm is <code>' +
                esc(String(result.jwsAlg)) + '</code>.</p>') +
            '<pre>' + esc(String(result.privateKeyPem)) + '</pre>' +
            '<p>The certificate, which is public and is also on the ' +
            'entry:</p><pre>' + esc(String(result.certificatePem)) + '</pre>',
            'The private key, once')
          : '';
        res.set('Cache-Control', 'no-store');
        // FROM A PERSON'S OWN PAGE (2026-09-13) the answer is drawn in the
        // console shell with a way back to that person, rather than as the PKI
        // page: the reader was looking at one person and the next thing they do
        // is look at them again. `back` is rebuilt by the console from the
        // name, never echoed.
        if (String(body.from || '') === '/admin/users' &&
            typeof admin.userReturnTo === 'function' && body.identifier) {
          const returnTo = admin.userReturnTo(body,
                                              String(body.identifier).trim(),
                                              '#credentials');
          admin.respond(req, res, { ok: !!result.ok }, 'Signing key pair',
                        '/admin/users',
                        banner + keyBlock +
                        '<p><a class="btn" href="' + esc(returnTo) +
                        '">Back to ' +
                        esc(String(body.identifier).trim()) + '</a></p>',
                        admin.upTo ? admin.upTo('/admin/users',
                                                'Signing key pair', {}) : null);
          log.debug('Leaving the admin PKI person action. Drawn for the ' +
                    'person page. ' + (result.ok ? 'Issued.' : 'Refused.'));
          return;
        }
        self.renderPki(req, res, authoring.draftFrom(body), banner, keyBlock);
        log.debug('Leaving the admin PKI person action. ' +
                  (result.ok ? 'Issued.' : 'Refused.'));
      }).catch(function (e) {
        log.error(errorCodes.tag('STS-PKI-0102') + 'pki_admin: the person ' +
                                                   'issue action threw: ' +
                  (e && e.stack ? e.stack : e));
        errorCodes.mark(res, 'STS-PKI-0102');
        self.renderPki(req, res, authoring.draftFrom(body),
                       admin.warn(esc('That action failed: ' +
                                      (e && e.message ? e.message : e)),
                                  'That was refused'));
        log.debug('Leaving the admin PKI person action. It threw.');
      });
    });

    log.debug("Leaving PkiAdmin.registerRoutes().");
  }
}
// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<PkiAdmin>(
  'admin-ui/pki_admin',
  () => new PkiAdmin(PkiAdmin.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  PkiAdmin: PkiAdmin,
  installInstance: (instance: PkiAdmin): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  // For `mgmt-api/admin_api.ts`. Rule 7: every control on this page has an
  // operation, and both go through THESE functions so the API decides nothing
  // the console does not.
  pkiView: slot.forward('pkiJson'),
  pkiAction: slot.forward('pkiAction'),
  pkiActionNames: slot.forward('pkiActionNames'),
  // For `tests/pki_authoring.js` ONLY, and it is worth saying why a renderer
  // is exported at all. The pane's field table is declared in
  // `common/pki_authoring.ts` and DRAWN here, and the two going out of step is
  // the failure this arrangement is most likely to produce: a field parsed and
  // never drawn silently falls to its default on every round trip, and a field
  // drawn and never parsed is a control that does nothing. Neither shows up as
  // an error anywhere. So the test renders the pane and compares the two
  // lists, which it cannot do without this.
  paneHtml: slot.forward('certificatePane'),
  // For `tests/pki_key_pair_paging.js` ONLY. Where a Take-off button in one of
  // the two paged tables sends the browser is a `Location` header built out
  // of a request body, so the test holds the rebuild — the page kept, anything
  // else dropped — rather than trusting that a redirect nobody reads is right.
  returnTo: slot.forward('pkiReturnTo')
};
