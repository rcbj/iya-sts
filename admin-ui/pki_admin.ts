// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// #244, #245: the fan-out a change to the hierarchy owes the people holding
// certificates under it, and the SPIFFE authority notice. A library in
// account_signals's shape (ssf.ts read from the cache); no route, no cycle.
import serviceSignals = require('../ssf/service_signals');
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
// The page's renderer (#446): a `web_` module, loadable in a browser.
import PkiPage = require('./web_pki');

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
// **FIVE ROWS A PAGE, AND NO MORE (rcbj, 2026-09-30)** — it was twenty-five,
// which already undercut the console's fifty because this page carries eight
// sections, and twenty-five rows apiece still put the People heading and the
// revocation pane screens below the controls. Five is a CEILING as well as
// the default (`PKI_MAX_PER_PAGE`, `pagingOf()`'s `maxPer`): `?per=` can
// shorten every list on the page and cannot lengthen one. What replaces
// scrolling a long page is the search box over each list, below.
//
// EVERY PAGED LIST HAS A SEARCH BOX OF ITS OWN (2026-09-30), the console's
// `sectionSearchForm()` — one box per list, under its own heading, on a
// parameter named after the list with `q` on the end (`issuedq`, `personsq`,
// and `ca-…-issuedq` / `ca-…-orphansq` for the authorities below), the
// arrangement `/admin/delegation` has. A search narrows the list BEFORE it is
// paged, so `issuedPaging.total` is the number that matched and the page
// numbers are pages of the matches; the tiles still count the whole lists.
// What each box matches is `searchRows()`'s caller's to say, and every field
// it reads is one the row already carries, so a search costs no certificate
// parse (#352's rule).
// ---------------------------------------------------------------------------
const PKI_MAX_PER_PAGE = 5;
const KEY_PAIR_PER_PAGE = PKI_MAX_PER_PAGE;
const KEY_PAIR_LIST_PARAMS = ['per', 'issuedPage', 'personsPage', 'issuedq',
                              'personsq'];
// The longest search a link carries. A term longer than any field it could
// match is dropped rather than echoed into every link on the page.
const SEARCH_MAX_LENGTH = 200;

// ---------------------------------------------------------------------------
// EACH AUTHORITY'S TWO LISTS IN THE REVOCATION PANE ARE PAGED TOO (#370,
// 2026-09-30).
//
// What an authority SIGNED — each row with a Revoke control — and the serials
// on its list with no certificate left to show grow for ever: every issue
// adds to the first and every rotation to both. Each is a list with a page
// parameter of its own, named from the authority (`listNameOf()`), and they
// share this page's `per` with the key-pair tables. **PAGE BEFORE PER-ROW
// WORK** (#352's rule, learned on Directory → Users): the issued list is
// sorted and sliced first, and only the rows of the page are given their
// revocation state; only the page of orphans is described; and "is this
// serial issued here" is one set per authority, where it was a rebuild of
// the whole issued list per revoked serial. `GET /admin-api/pki` answers the
// same pages, with the paging and the totals beside each list.
//
// A parameter looks like `ca-default-jose-issuedPage`: the scope segment and
// the CA id, restricted to `[a-z0-9_-]`, then the list. `listNameOf()` makes
// the name and `REVOCATION_LIST_PARAM` is what `keyPairListView()` accepts,
// so a link can carry only names this file writes. Each list's search is the
// same name with `q` in place of `Page` (2026-09-30), and five rows a page
// for the key-pair tables' reason.
// ---------------------------------------------------------------------------
const REVOCATION_PER_PAGE = PKI_MAX_PER_PAGE;
const REVOCATION_LIST_PARAM =
  /^ca-[a-z0-9_-]{1,120}-(issued|orphans)(Page|q)$/;

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
                     // Its undoing (#263): a pinned signing key retires and
                     // the generated key signs again.
                     'unpin-key',
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
                        'import-ca', 'pin-key', 'unpin-key',
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

/**
 * Protocols → PKI, `/admin/pki`: the realm's certificate authority (Root,
 * Intermediate, Issuing), the key pairs it issues, the Certificate & Key
 * Configuration pane, revocation and pinned signing keys, every control a form
 * field and every computation on the server.
 */
class PkiAdmin {
  // The table the comments here call PURPOSE_WRITES — see
  // `purposeWritesTable()`.
  private readonly purposeWrites: Record<string, any>;

  /**
   * Builds an instance and its table of what each key-pair purpose writes.
   *
   * @param deps - the certificate authority, the authoring pane, the registers
   * and the console
   */
  constructor(private readonly deps: PkiAdminDeps) {
    deps.log.debug("Entering PkiAdmin.constructor().");
    this.purposeWrites = this.purposeWritesTable();
    deps.log.debug("Leaving PkiAdmin.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50).
  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
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

  // Both tables' slices and paging, from one query. Called by `pkiJson()` for
  // the two paging members and by `renderPki()` for the rows, over the same two
  // arrays, so the page and `personsPaging` cannot describe different slices.
  //
  // EACH TABLE IS SEARCHED BEFORE IT IS PAGED (2026-09-30). The Applications
  // box matches the application's identifier, the profile, the key handle and
  // every declared issuer; the People box the username, both handles and every
  // issuer either profile asserts as — what the table's own columns show, so a
  // match is a row the reader can see the reason for.
  private keyPairPaging(query: Json, json: Json) {
    const { log, adminViews } = this.deps;
    const self = this;
    log.debug("Entering PkiAdmin.keyPairPaging().");
    const q: Json = PkiPage.keyPairListView(query || {});
    const applications = self.searchRows(q.issuedq, json.issued || [],
      function (one: Json) {
        return [one.identifier, one.purposeLabel, one.handle]
          .concat(one.assertionIssuers || []);
      });
    const people = self.searchRows(q.personsq, json.persons || [],
      function (one: Json) {
        const saml = one.saml || {};
        return [one.username, one.kid, saml.thumbprint]
          .concat(one.issuers || [], saml.issuers || []);
      });
    const out = {
      applications: adminViews.pagedRows(q, applications,
        { name: 'issued', noun: 'application rows',
          defaultPer: KEY_PAIR_PER_PAGE, maxPer: PKI_MAX_PER_PAGE }),
      people: adminViews.pagedRows(q, people,
        { name: 'persons', noun: 'people', defaultPer: KEY_PAIR_PER_PAGE,
          maxPer: PKI_MAX_PER_PAGE }),
      search: { issued: q.issuedq || null, persons: q.personsq || null }
    };
    log.debug("Leaving PkiAdmin.keyPairPaging().");
    return out;
  }

  // ONE SEARCH OVER ONE LIST: a case-insensitive substring of any of the
  // strings `textOf(row)` answers. No term is every row, in its order. The
  // matching is deliberately the plainest there is — the same as
  // `/admin/delegation`'s boxes — because a serial pasted out of a log, part
  // of a DN or part of an identifier are all substrings, and a cleverer match
  // would be one the reader has to learn.
  private searchRows(term: Json, rows: Json[],
                     textOf: (row: Json) => Json[]): Json[] {
    const { log } = this.deps;
    log.debug("Entering PkiAdmin.searchRows().");
    const needle = String(term || '').trim().toLowerCase();
    if (!needle) {
      log.debug("Leaving PkiAdmin.searchRows(). No search.");
      return rows;
    }
    const out = rows.filter(function (row) {
      return textOf(row).some(function (text) {
        return text != null &&
          String(text).toLowerCase().indexOf(needle) >= 0;
      });
    });
    log.debug("Leaving PkiAdmin.searchRows(). " + out.length + " of " +
              rows.length + " matched.");
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

  // -------------------------------------------------------------------------
  // WHAT A CHANGE TO THE HIERARCHY OWES THE PEOPLE UNDER IT (#244). Every
  // act that replaces, renews or removes an authority takes a snapshot of
  // the person-held certificates it can reach first, and hands it to
  // `serviceSignals.hierarchyChanged()` once it has succeeded, which decides
  // per certificate whether it was re-minted (`update`) or orphaned
  // (`revoke`) and fans the CAEP credential-change out in batches — and
  // tells a realm whose SPIFFE authority moved (#245). The sentence is for
  // the answer, so an operator reads what their button did to other people.
  // -------------------------------------------------------------------------
  private signalsBefore(scopes: string[], useCaseId?: string): Json {
    const { log } = this.deps;
    log.debug('Entering PkiAdmin.signalsBefore().');
    log.debug('Leaving PkiAdmin.signalsBefore().');
    return serviceSignals.snapshot(scopes, useCaseId || undefined);
  }

  private signalsAfter(before: Json, action: string): string {
    const { log } = this.deps;
    log.debug('Entering PkiAdmin.signalsAfter(). ' + action);
    const told = serviceSignals.hierarchyChanged(before,
      { via: '/admin/pki (' + action + ')' });
    const people = told.updated + told.revoked;
    log.debug('Leaving PkiAdmin.signalsAfter(). ' + people + '.');
    return people ? ' ' + people + ' certificate(s) held by people were ' +
      'affected — ' + told.updated + ' re-issued, ' + told.revoked +
      ' orphaned — and each holder\'s Shared Signals receivers are sent a ' +
      'CAEP credential-change.' : '';
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
  // THE WORKBENCH ALONE, for a draft a pane action answered (#446): the
  // static console draws the pane again from it, where the server-rendered
  // console drew the whole page around `pkiJson(req, draft)`.
  /**
   * The certificate workbench's model for one draft.
   *
   * @param draft - the pane's draft
   * @returns `authoring.view()` of it, which carries no private key
   */
  workbenchOf(draft: Json) {
    const { log, authoring } = this.deps;
    log.debug('Entering PkiAdmin.workbenchOf().');
    log.debug('Leaving PkiAdmin.workbenchOf().');
    return authoring.view(undefined, draft);
  }

  /**
   * Builds the page's model, which `GET /admin-api/pki` also answers: the
   * hierarchy, the issued key pairs, the pane, revocation and pinned signers.
   *
   * No private key is in it; `common/pki.js`'s `describe()` drops every one.
   * @param req - the request, for paging
   * @param draft - the pane's draft to draw, after a pane action
   * @param options - `shownOnly: true` reads each key pair's certificate for
   *   the rows the two tables draw and no others (the page's own call);
   *   absent, every row of both lists carries `pqc`, as the JSON always did
   * @returns the model
   */
  pkiJson(req: Json, draft?: Json, options?: { shownOnly?: boolean }) {
    const { log, pki, authoring, applications, personAssertions,
            certificateViews, adminViews, admin, config,
            pqcSupport } = this.deps;
    const self = this;
    log.debug('Entering PkiAdmin.pkiJson().');
    const chain = pki.describe();
    // ONCE, where it was read once PER PROFILE (#352): the two profiles'
    // rows are two readings of the same entries.
    const everyApplication = applications.list();
    // Each application row's certificate, for `decorate()` below, beside the
    // row rather than on it so that it is in no reply.
    const certificateOf = new WeakMap<object, Json>();
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
      revocation: self.revocationModel(req && req.query),
      revocationNote: report.revocation,
      residency: report.residency,
      encoder: report.encoder,
      // THE PINNED SIGNING KEYS (#263) of this realm: whether it signs with
      // them (`pki.pinnedSigners`), and every one still published — pending,
      // signing, or verifying through its grace — with no private key.
      pinnedSigners: self.pinnedSignersModel(),
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
        return rows.concat(everyApplication.map(function (one) {
          const fields = one.fields || {};
          const row: Json = {
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
            // `pqc` goes LAST, added by `decorate()` below — whether the key
            // pair on the entry uses a post-quantum algorithm, read off its
            // certificate (2026-09-13).
          };
          certificateOf.set(row, fields[table.certificateAttribute]);
          return row;
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
      // Each with `pqc`, read off the person's certificate as `issued` above
      // and added by `decorate()` below. `holders()` reads presence off the
      // entries in one walk and opens no private key (#352).
      persons: personAssertions.holders().map(function (one) {
        return Object.assign({}, one, {
          saml: Object.assign({}, one.saml) });
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
    // The searches the two pages were narrowed by (2026-09-30), null for
    // none: `issuedPaging.total` is the count that MATCHED, and a reader of
    // the reply needs to know that is what it is.
    json.issuedSearch = paged.search.issued;
    json.personsSearch = paged.search.persons;
    // THE ROWS EACH TABLE SHOWS (#446), as indices into the two whole
    // lists: the page draws these and a reader of the reply can find them,
    // where the search and the paging decided them here.
    json.issuedShown = paged.applications.shown.map(function (row: Json) {
      return json.issued.indexOf(row);
    });
    json.personsShown = paged.people.shown.map(function (row: Json) {
      return json.persons.indexOf(row);
    });
    // WHAT THE PAGE'S FORMS ARE FILLED WITH (#446): the defaults it offers
    // and the tiers' names, which it read from the settings and the
    // authority as it drew.
    json.pageDefaults = {
      keyAlgorithm: config.value('pki.keyAlgorithm'),
      organisation: config.value('pki.organisation'),
      leafLifetimeDays: config.value('pki.leafLifetimeDays'),
      alternativeKeyAlgorithm: config.value('pki.alternativeKeyAlgorithm')
    };
    json.tierLabels = pki.TIERS.map(function (tier: Json) {
      return { id: tier.id, label: tier.label };
    });
    json.serviceScope = pki.SERVICE_SCOPE;
    // ---------------------------------------------------------------------
    // PAGE, THEN READ THE CERTIFICATES (#352, 2026-09-29). `pqc` is the one
    // member of a key-pair row that costs a certificate parse, and it was
    // computed for every application and every person before either table
    // was paged. The page draws five of each, so it asks for those
    // (`shownOnly`); the JSON carries both lists whole and so asks for every
    // row, through `certificateViews.pqcOf()`, which parses a certificate
    // once and remembers the answer. Added in place, as the LAST member of
    // each row — where it always was — so the reply is byte for byte what it
    // was, and the rows `keyPairPaging()` slices for the page are these same
    // objects.
    // ---------------------------------------------------------------------
    const decorate = function (row: Json) {
      row.pqc = certificateViews.pqcOf(certificateOf.has(row)
        ? certificateOf.get(row) : row.certificatePem);
      if (row.saml) {
        row.saml.pqc = certificateViews.pqcOf(row.saml.certificatePem);
      }
    };
    const shownOnly = !!(options && options.shownOnly);
    (shownOnly ? paged.applications.shown : json.issued).forEach(decorate);
    (shownOnly ? paged.people.shown : json.persons).forEach(decorate);
    // EVERY CERTIFICATE THE PAGE MARKS (#446): the hierarchy's tiers, the
    // tree's and the object store's, each with the key's post-quantum
    // classification as `pqc`, which the icon is drawn from — a renderer in
    // a browser parses no certificate. A row with no certificate is
    // classified by its algorithm names, as the icon always was.
    const classify = function (node: Json): void {
      if (!node || typeof node !== 'object') {
        return;
      }
      if (Array.isArray(node)) {
        node.forEach(classify);
        return;
      }
      if (Object.prototype.hasOwnProperty.call(node, 'certificatePem') &&
          !Object.prototype.hasOwnProperty.call(node, 'pqc')) {
        node.pqc = pqcSupport.of({
          certificatePem: node.certificatePem,
          algorithms: [node.keyAlg, node.alg].filter(Boolean) });
      }
      Object.keys(node).forEach(function (key: string): void {
        if (key !== 'pqc' && node[key] && typeof node[key] === 'object') {
          classify(node[key]);
        }
      });
    };
    classify([json.chain, json.tree, json.workbench]);
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

  /**
   * Performs one of the page's actions, for the console's POST and
   * `/admin-api/pki/{action}` alike.
   *
   * An action that names a branch this realm does not draw is refused, and an
   * unknown action is refused with the list of known ones; a pane action
   * answers with a `draft` as well as a verdict.
   * @param body - `action` and its fields
   * @returns `ok` with a message (and a draft for a pane action), or a refusal
   * carrying its error code
   */
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
      const signalled = self.signalsBefore([self.scopeFrom({})]);
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
      const toldBuild = self.signalsAfter(signalled, action);
      log.debug('Leaving PkiAdmin.pkiAction(). Built.');
      return { ok: true,
               why: 'A three-tier certificate authority was built for the "' +
                    self.realmLabel() + '" realm, and ' + remint +
                    ' certificate(s) this realm\'s own signing keys publish ' +
                    'were re-minted from it. Anything else issued from a ' +
                    'PREVIOUS hierarchy now chains to nothing — this service ' +
                    'keeps no copy of what it issued, so none of it can be ' +
                    'listed.' + toldBuild,
               chain: built.chain };
    }

    if (action === 'clear') {
      const signalled = self.signalsBefore([self.scopeFrom({})]);
      const cleared = pki.clearChain();
      if (!cleared.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). Nothing to clear.');
        return self.refusedBy(cleared, 'STS-PKI-0105');
      }
      const toldClear = self.signalsAfter(signalled, action);
      log.debug('Leaving PkiAdmin.pkiAction(). Cleared.');
      return { ok: true,
               why: 'The "' + self.realmLabel() +
                    '" realm\'s certificate authority ' +
                    'was removed. ' + cleared.issuedCount + ' certificate(s) ' +
                    'were issued from it and every one of them now chains to ' +
                    'nothing. The key pairs are still on the application ' +
                    'entries and will still SIGN — what stopped is this ' +
                    'service being able to see that it issued them.' +
                    toldClear };
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
      const signalled = self.signalsBefore(self.everyRealmId());
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
      const toldRoot = self.signalsAfter(signalled, action);
      log.debug('Leaving PkiAdmin.pkiAction(). A new Root.');
      return { ok: true,
               why: 'A new Root CA was built for this service, and ' + rebuilt +
                    ' branch(es) were re-issued under it so the whole tree ' +
                    'chains to it. ANYTHING TRUSTING THE OLD ROOT NO LONGER ' +
                    'TRUSTS THIS SERVICE — the new Root is on this page and ' +
                    'at GET /admin-api/pki. The signing keys themselves are ' +
                    'unchanged, so nothing that verifies against the ' +
                    'published JWKS is affected.' + toldRoot,
               root: built.root };
    }

    if (action === 'build-scope') {
      const scope = self.scopeFrom(body);
      const signalled = self.signalsBefore([scope]);
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
      const toldScope = self.signalsAfter(signalled, action);
      log.debug('Leaving PkiAdmin.pkiAction(). A branch was built.');
      return { ok: true,
               why: 'That branch was rebuilt — a new Intermediate CA and a ' +
                    'new Issuing CA for every use case under it — and ' +
                    again + ' certificate(s) were re-minted from the new ' +
                    'authorities. The Root is untouched, because every other ' +
                    'scope hangs from it.' + toldScope };
    }

    if (action === 'reissue-use-case') {
      const scope = self.scopeFrom(body);
      const useCaseId = String(body.useCase || '').trim();
      const signalled = self.signalsBefore([scope], useCaseId);
      const done = await pki.reissueUseCase(scope, useCaseId);
      if (!done.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The reissue failed.');
        return self.refusedBy(done, 'STS-PKI-0105');
      }
      const toldReissue = self.signalsAfter(signalled, action);
      log.debug('Leaving PkiAdmin.pkiAction(). Reissued.');
      return { ok: true,
               why: 'The ' + useCaseId +
                    ' Issuing CA was re-issued from this scope\'s ' +
                    'Intermediate with a new key pair, and ' +
                    done.recertified + ' certificate(s) under it were ' +
                    're-minted from it. Every other use case is untouched, ' +
                    'which is the whole reason each has an authority of its ' +
                    'own.' + toldReissue };
    }

    if (action === 'recertify') {
      const scope = self.scopeFrom(body);
      const useCaseId = String(body.useCase || '').trim();
      const signalled = self.signalsBefore([scope], useCaseId);
      const done = await pki.recertifyUseCase(scope, useCaseId);
      if (!done.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The renewal failed.');
        return self.refusedBy(done, 'STS-PKI-0105');
      }
      const toldRenew = self.signalsAfter(signalled, action);
      log.debug('Leaving PkiAdmin.pkiAction(). Renewed.');
      return { ok: true,
               why: done.recertified +
                    ' certificate(s) were renewed under the same ' + useCaseId +
                    ' Issuing CA, with fresh serials and a fresh validity ' +
                    'window. THE KEYS ARE UNTOUCHED — this is a renewal ' +
                    'rather than a regeneration, so nothing that verifies ' +
                    'against the published keys stops verifying.' +
                    toldRenew };
    }

    if (action === 'import-ca') {
      const scope = self.scopeFrom(body);
      const useCaseId = String(body.useCase || '').trim();
      const signalled = self.signalsBefore([scope], useCaseId);
      const done = await pki.importCa(scope, useCaseId, {
        certificatePem: String(body.certificatePem || ''),
        privateKeyPem: String(body.privateKeyPem || '')
      });
      if (!done.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The import was refused.');
        return self.refusedBy(done, 'STS-PKI-0105');
      }
      const toldImport = self.signalsAfter(signalled, action);
      log.debug('Leaving PkiAdmin.pkiAction(). Imported.');
      return { ok: true, why: done.why + toldImport };
    }

    // PIN AND UNPIN go through `common/signing_rotation.ts` (#263), which
    // hands the key to `pki.pinKeyPair()` and — where the realm signs with
    // pinned keys — computes the grace, writes the audit row and sends
    // `signing-key-rotated`. Required lazily: it is built after this page.
    if (action === 'pin-key') {
      const scope = self.scopeFrom(body);
      const done = await require('../common/signing_rotation').pinSigningKey(
        scope, String(body.useCase || '').trim(),
        String(body.slot || '').trim(), {
          privateKeyPem: String(body.privateKeyPem || ''),
          certificatePem: String(body.certificatePem || ''),
          chainPem: String(body.chainPem || '')
        }, String(body.requestedBy || ''));
      if (!done.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The pin was refused.');
        return self.refusedBy(done, 'STS-PKI-0105');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Pinned.');
      return done.signer
        ? { ok: true, why: done.why, kid: done.signer.kid,
            activatesAt: done.signer.activatesAt }
        : { ok: true, why: done.why };
    }

    if (action === 'unpin-key') {
      const scope = self.scopeFrom(body);
      const done = require('../common/signing_rotation').unpinSigningKey(
        scope, String(body.useCase || '').trim(),
        String(body.slot || '').trim(), String(body.requestedBy || ''));
      if (!done.ok) {
        log.debug('Leaving PkiAdmin.pkiAction(). The unpin was refused.');
        return self.refusedBy(done, 'STS-PKI-0105');
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Unpinned.');
      return { ok: true, why: done.why, unpinned: done.unpinned };
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
      // A PERSON'S CERTIFICATE REVOKED IS A CREDENTIAL CHANGE (#145), and
      // so is an APPLICATION's (#221 P5), told under the application
      // subject. The authority's register says whose it was; the issuer is
      // the authority's own subject, since that is what signed it. One this
      // register never recorded has nobody to tell.
      if (!done.already) {
        const caId = String(body.ca || '').trim();
        const serial = pkiRevocation.normalSerial(done.entry.serialHex);
        const held = pki.issuedKeyPairsFor(scope, caId).filter(function (one) {
          return pkiRevocation.normalSerial(one.serialHex) === serial;
        })[0];
        const kindOfHolder = held ? String(held.subjectKind || '') : '';
        if (held && held.identifier &&
            (kindOfHolder === 'person' || kindOfHolder === 'application')) {
          const whose = kindOfHolder === 'application'
            ? { application: String(held.identifier), username: '' }
            : { username: String(held.identifier) };
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
          accountSignals.credentialChanged({ ...whose,
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
            accountSignals.credentialCompromised({ ...whose,
              credentialType: 'x509',
              initiatingEntity: 'admin', via: '/admin/pki',
              reasonAdmin: 'An administrator revoked the certificate ' +
                           serial + ' of ' + held.identifier + ' because ' +
                           'its key was compromised.',
              reasonUser: 'A certificate of yours was revoked because its ' +
                          'key may be known to somebody else.' });
          }
        }
      }
      // AN AUTHORITY REVOKED IS EVERY LEAF BENEATH IT (#244). On an
      // Intermediate's list the serial may be one of the scope's Issuing CAs;
      // on the Root's, a scope's Intermediate. `caRevoked()` walks down to
      // every person holding a live certificate there and fans the events
      // out in batches — `credential-change` (x509, revoke), and RISC
      // `credential-compromise` too for keyCompromise or cACompromise.
      let tierNote = '';
      const caOfList = String(body.ca || '').trim();
      if (!done.already &&
          (caOfList === 'intermediate' || caOfList === 'root')) {
        const reached = serviceSignals.caRevoked(scope, caOfList,
          done.entry.serialHex, done.entry.reason,
          { via: '/admin/pki (revoke-certificate)' });
        if (reached.tier) {
          tierNote = ' It is ' + (reached.tier === 'issuing-ca'
            ? 'an Issuing CA' : 'an Intermediate CA') + ', so ' +
            reached.people + ' certificate(s) held by people beneath it no ' +
            'longer chain to anything a checking relying party accepts, and ' +
            'each holder\'s Shared Signals receivers are sent a CAEP ' +
            'credential-change' +
            (serviceSignals.COMPROMISE_REASONS.indexOf(done.entry.reason) >= 0
              ? ' and a RISC credential-compromise' : '') + '.';
        }
      }
      log.debug('Leaving PkiAdmin.pkiAction(). Revoked.');
      return { ok: true, entry: done.entry, already: !!done.already,
               why: done.already
                 ? done.why
                 : 'Certificate ' + done.entry.serialHex + ' is on the "' +
                   caOfList +
                   '" authority\'s revocation list as "' + done.entry.reason +
                   '". Its CRL and its OCSP responder say so from now on. ' +
                   'NOTHING ELSE CHANGED: whoever holds that key still holds ' +
                   'it, the certificate still chains, and this service does ' +
                   'not consult its own lists — so what this buys is that a ' +
                   'relying party which DOES check can now find out.' + tierNote };
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
      // The export, as JSON with the bytes base64'd and named. The console's
      // Download button comes through here too since #446, and its runtime
      // saves each named file as the attachment the deleted
      // `POST /admin/pki/export` route sent.
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

  // ---------------------------------------------------------------------------
  // THE CONTROLS, ONE BLOCK PER SCOPE. Rebuild a branch, reissue one use case's
  // Issuing CA, re-certify what hangs under it, import a CA of your own, or pin
  // a key pair of your own for one slot.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // THE PINNED SIGNING KEYS (#263): the model `GET /admin-api/pki` carries and
  // the section this page draws from it. Read in the realm this page is for.
  // ---------------------------------------------------------------------------
  /**
   * Describes the realm's pinned signing keys, each with whether its
   * certificate is expiring soon.
   *
   * @returns whether pinning is on, the pinned keys and their warnings
   */
  pinnedSignersModel() {
    const { log, pki, config, realms } = this.deps;
    log.debug("Entering PkiAdmin.pinnedSignersModel().");
    const realm = String((realms.current() || {}).id || '');
    const days = Number(config.value('pki.pinnedSignerExpiryWarningDays'));
    const keys = pki.pinnedSignersFor(realm).map(function (one: Json) {
      return Object.assign({}, one, {
        expiringSoon: one.role !== 'retired' && one.daysLeft < days
      });
    });
    log.debug("Leaving PkiAdmin.pinnedSignersModel(). " + keys.length + ".");
    return { on: !!config.value('pki.pinnedSigners'),
             leadMinutes: Number(config.value('pki.pinnedSignerLeadMinutes')),
             warningDays: days, keys: keys };
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
  private revocationModel(query?: Json) {
    const { log, config, pki, pkiRevocation, adminViews } = this.deps;
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
    const q = PkiPage.keyPairListView(query || {});
    let totalRevoked = 0;
    const authorities = pkiRevocation.authorities(scopes).map(function (one) {
      const points = pkiRevocation.distributionPoints(one.scope, one.ca);
      const scopeSegment = pkiRevocation.scopeSegment(one.scope);
      const listName = self.listNameOf(scopeSegment, one.ca);
      // THE WHOLE LISTS AS THE REGISTER HOLDS THEM, undecorated: the issued
      // rows are small records already sorted by subject, and the revocation
      // entries are the stored ones. Nothing below is done per row of these
      // but building two sets (#370).
      const issuedAll = pkiRevocation.issuedList(one.scope, one.ca);
      const revokedAll = pkiRevocation.listFor(one.scope, one.ca);
      totalRevoked = totalRevoked + revokedAll.length;
      const revokedBySerial = Object.create(null);
      revokedAll.forEach(function (entry) {
        revokedBySerial[pkiRevocation.normalSerial(entry.serialHex)] = entry;
      });
      const issuedSerials = Object.create(null);
      issuedAll.forEach(function (cert) {
        issuedSerials[cert.serialHex] = true;
      });
      // A SERIAL ON THE LIST THAT THIS AUTHORITY DID NOT ISSUE IS LEGAL AND
      // IS REPORTED SEPARATELY. RFC 5280 does not require a CA to still hold
      // a record of what it signed in order to revoke it, and this service
      // genuinely reaches that state: a leaf superseded by a rotation is
      // revoked and then REPLACED in the register, so the old serial is on
      // the list with nothing left to point at. Drawing it in the issued
      // table would be inventing a certificate; dropping it would hide most
      // of what the list actually holds. One set lookup each (#370), where
      // it was `issuedHere()` — a rebuild of the issued list — per serial.
      const orphansAll = revokedAll.filter(function (entry) {
        return !issuedSerials[pkiRevocation.normalSerial(entry.serialHex)];
      });
      // EACH LIST SEARCHED, THEN PAGED (2026-09-30), over what the stored
      // records already say: the serial, the subject and what the register
      // calls the certificate for the issued list; the serial, the subject as
      // recorded, the reason and the note for the orphans. Nothing here is
      // decorated first, so a search is no dearer than a page.
      const issuedSearch = q[listName + '-issuedq'] || null;
      const orphansSearch = q[listName + '-orphansq'] || null;
      const issuedMatched = self.searchRows(issuedSearch, issuedAll,
        function (cert: Json) {
          return [cert.serialHex, cert.subject, cert.label, cert.kind];
        });
      const orphansMatched = self.searchRows(orphansSearch, orphansAll,
        function (entry: Json) {
          return [entry.serialHex, pkiRevocation.normalSerial(entry.serialHex),
                  entry.subject, entry.reason, entry.note];
        });
      const issuedPage = adminViews.pagedRows(q, issuedMatched,
        { name: listName + '-issued', noun: 'certificates',
          defaultPer: REVOCATION_PER_PAGE, maxPer: PKI_MAX_PER_PAGE });
      const orphansPage = adminViews.pagedRows(q, orphansMatched,
        { name: listName + '-orphans', noun: 'revoked serials',
          defaultPer: REVOCATION_PER_PAGE, maxPer: PKI_MAX_PER_PAGE });
      // WHAT IT SIGNED, THE PAGE OF IT, each row carrying whether it is
      // already on the list — computed HERE rather than by the renderer,
      // because "is this revoked" is a statement about the register and a
      // page holding a second opinion about it would eventually offer a
      // Revoke button for something already revoked and a Release for
      // something that was never held.
      const issued = issuedPage.shown.map(function (cert) {
        const entry = revokedBySerial[cert.serialHex] || null;
        return Object.assign({}, cert, {
          revoked: !!entry,
          revokedAt: entry ? entry.revokedAt : null,
          revokedReason: entry ? entry.reason : null,
          held: !!entry && entry.reason === 'certificateHold'
        });
      });
      const out: Json = {
        scope: one.scope,
        scopeSegment: scopeSegment,
        ca: one.ca,
        label: one.label,
        subject: one.tier.subject,
        notAfter: one.tier.notAfter,
        issued: issued,
        issuedTotal: issuedAll.length,
        issuedPaging: adminViews.pagingJson(issuedPage.paging),
        // What each list was narrowed by, null for nothing; the two pagings'
        // `total` is the count that matched (2026-09-30).
        issuedSearch: issuedSearch,
        orphansSearch: orphansSearch,
        // THE REVOCATIONS THE PAGE'S ROWS CARRY, described — the whole list
        // is `revokedTotal` long and is the CRL's to publish, not this
        // reply's (#370).
        revoked: issued.filter(function (cert) {
          return cert.revoked;
        }).map(function (cert) {
          return pkiRevocation.describeEntry(revokedBySerial[cert.serialHex]);
        }),
        revokedTotal: revokedAll.length,
        revokedNotIssued: orphansPage.shown.map(pkiRevocation.describeEntry),
        revokedNotIssuedTotal: orphansAll.length,
        orphansPaging: adminViews.pagingJson(orphansPage.paging),
        crl: { http: points.http, ldap: points.ldap },
        ocsp: points.ocsp,
        caIssuers: points.caIssuers,
        directoryDn: points.dn
      };
      // The name this authority's two lists' parameters are built on, which
      // the renderer builds its search boxes and the way back from (#446:
      // the page draws from this answer alone, and the pagers from
      // `issuedPaging` and `orphansPaging`).
      out.listName = listName;
      return out;
    });
    const out = {
      reasons: pkiRevocation.REASONS.map(function (one) {
        return { id: one.id, code: one.code, what: one.what };
      }),
      authorities: authorities,
      totalRevoked: totalRevoked,
      crlLifetimeMinutes: Number(config.value('pki.crlLifetimeMinutes')),
      publishedToDirectory: !!config.value('pki.publishCrlToDirectory')
    };
    log.debug('Leaving PkiAdmin.revocationModel(). ' + authorities.length +
              ' authority(ies), ' + out.totalRevoked + ' revoked.');
    return out;
  }

  // The name an authority's two lists page under (#370): its scope segment
  // and CA id, restricted to what `REVOCATION_LIST_PARAM` accepts.
  private listNameOf(scopeSegment: Json, caId: Json) {
    const { log } = this.deps;
    log.debug("Entering PkiAdmin.listNameOf().");
    const clean = function (text: Json) {
      return String(text || 'default').toLowerCase()
        .replace(/[^a-z0-9_-]/g, '_').slice(0, 58);
    };
    log.debug("Leaving PkiAdmin.listNameOf().");
    return 'ca-' + clean(scopeSegment) + '-' + clean(caId);
  }

  /**
   * Registers `/admin/pki`, its actions, the certificate view and export, and a
   * person's key-pair actions.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, parseBody, authoring, errorCodes, certificateViews,
            certificateDialog, admin, esc } = this.deps;
    const self = this;
    log.debug("Entering PkiAdmin.registerRoutes().");





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

/**
 * Protocols → PKI, `/admin/pki`: the realm's certificate authority and the key
 * pairs it issues, and the functions `mgmt-api/admin_api.ts` reaches it through
 * (rule 7).
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  PkiAdmin: PkiAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: PkiAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  // For `mgmt-api/admin_api.ts`. Rule 7: every control on this page has an
  // operation, and both go through THESE functions so the API decides nothing
  // the console does not.
  pkiView: slot.forward('pkiJson'),
  pkiAction: slot.forward('pkiAction'),
  workbenchOf: slot.forward('workbenchOf'),
  // For `tests/pki_authoring.js` ONLY, and it is worth saying why a renderer
  // is exported at all. The pane's field table is declared in
  // `common/pki_authoring.ts` and DRAWN here, and the two going out of step is
  // the failure this arrangement is most likely to produce: a field parsed and
  // never drawn silently falls to its default on every round trip, and a field
  // drawn and never parsed is a control that does nothing. Neither shows up as
  // an error anywhere. So the test renders the pane and compares the two
  // lists, which it cannot do without this.
  // The renderer's since #446 (`web_pki.ts`).
  paneHtml: PkiPage.certificatePane.bind(PkiPage)
};
