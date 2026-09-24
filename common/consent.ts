'use strict';
//
// File: consent.ts
//
// ---------------------------------------------------------------------------
// CONSENT: WHAT A PERSON HAS AGREED THIS APPLICATION MAY ASK FOR ON THEIR
// BEHALF.
//
// The authorization endpoint has always issued whatever was asked for. Since
// 2026-09-01 it asks the person first: the FIRST time a given username signs in
// to a given application for a given scope, `/oauth2/consent` is drawn, and
// nothing is issued until they press a button. The answer is written into the
// embedded directory, on the person's own entry, so the second sign-in is
// silent and an `ldapsearch` can read what somebody agreed to.
//
// ---------------------------------------------------------------------------
// THE UNIT IS (PERSON, APPLICATION, SCOPE) AND IT IS ONE VALUE.
//
// Not (person, application) with a list hanging off it, and not (person,
// application) with a snapshot of the whole scope string. Both of those were
// considered and both answer the wrong question:
//
//   * A SNAPSHOT of the scope string means `openid profile` and `profile
//     openid` are two different consents, and adding one scope to a client's
//     request throws away the agreement to the other four.
//   * A LIST hanging off a pair means one attribute value that grows, which a
//     directory cannot add to or remove from a member of — every change would
//     be a read, a rewrite and a race.
//
// One value per triple makes every operation an `add` or a `remove` of exactly
// the thing being talked about, which is what LDAP is good at, and it makes the
// question the authorization endpoint asks — "which of these five scopes has
// this person not agreed to for this client" — a set difference rather than a
// parse.
//
// ---------------------------------------------------------------------------
// THE VALUE'S SHAPE, AND WHY THE CLIENT_ID IS LAST.
//
//     oauthConsent: 20260901143000Z openid webapp1
//     oauthConsent: 20260901143000Z https://example.com/write webapp1
//
// Three fields separated by a SPACE: when it was agreed, the scope, and the
// application it was agreed for. The order is not cosmetic — it is the only
// order this value can be parsed in without a rule somebody can break:
//
//   * The TIMESTAMP is a GeneralizedTime, which is digits and a `Z`. It cannot
//     contain a space.
//   * The SCOPE cannot contain a space either, and that is guaranteed by
//     CONSTRUCTION rather than by a check: a scope value only ever reaches this
//     module by having been split out of a space-delimited `scope` parameter
//     (RFC 6749 section 3.3), so a value with a space in it is not one scope.
//   * The CLIENT_ID is the one field with no rule at all. `identifierProblem()`
//     in applications.js refuses only a line break, a NUL and 512 characters —
//     a client_id may contain a space, a `|`, a `/`, anything. So it goes LAST
//     and takes the whole remainder of the value.
//
// That is why the delimiter is a space and not this repository's usual `|`: the
// `|` convention (`oauthPermission`'s `name|description`) works because the
// unconstrained field is last there too, and here the unconstrained field
// contains `|` as happily as anything else.
//
// **A PERMISSION IDENTIFIER IS STORED WHOLE.** `https://example.com/write` is
// what the client put in its `scope`, so it is what is recorded and what the
// page shows. Storing the resolved permission NAME (`write`) instead was
// refused for the reason the whole feature exists: two resources may both
// expose `read`, the person agreed to one of them, and a consent recorded as
// `read` would silently cover the other.
//
// ---------------------------------------------------------------------------
// GLOBAL CONSENT: THE SECOND HALF, AND IT IS CONFIGURATION RATHER THAN A
// RECORD.
//
// `oauthGlobalConsent` is an attribute on the CLIENT APPLICATION's entry, one
// value per scope. A scope named there is never asked about: every person who
// signs in to that application skips the prompt for it, and nothing is written
// to anybody's entry. It is how an operator says "this application's use of
// `openid` and `profile` is agreed for everybody here" without visiting a
// person's entry.
//
// **IT IS KEYED ON (APPLICATION, SCOPE) AND NOT ON THE SCOPE ALONE**, and that
// is the decision worth defending. A service-wide list of scopes nobody is ever
// asked about would be shorter to configure and would mean that consenting
// `read` for one application consented it for every application that could
// spell it — including one registered five minutes ago by somebody else. The
// pair is the smallest thing that says what an operator actually means.
//
// **IT IS AN OVERRIDE AND NOT A RECORD, so it writes nothing down about the
// person.** Turning it off leaves no trace behind: the next sign-in is prompted
// again, because nobody ever agreed to anything. That is the opposite of the
// per-user half, which survives the setting being turned off and back on — and
// the difference is exactly the point of having both.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3), IT REGISTERS NO ROUTE, AND IT HOLDS NO STORE.
//
// The store is the DIRECTORY, in both halves: `ou=users` for what a person
// agreed and `ou=applications` for what was configured. A Map here would be a
// second store that looked right on its own and silently disagreed with an
// `ldapsearch` — the same rule `applications.js` and `app_permissions.ts` both
// state about themselves at length.
//
// It requires `helpers.js`, `config.js`, `applications.js`, `error_codes.js`
// and `admin_stats.js` (for `identityKeyOf()`, so that `alice`,
// `urn:uuid:<entryUUID>` and `alice@REALM` are one person here exactly as they
// are one entry in the directory), and NOTHING requires it back — so it closes
// no cycle and moves no route. Since #172 it reaches `oauth-oidc/oauth2_bcp.js`
// LAZILY (`defaultDeps()`'s `grants`), when a withdrawal follows a refresh
// token's grant — see the block above `withdrawnStamp()`, which is also where
// WITHDRAWN MEANS WITHDRAWN is argued.
//
// **THE DIRECTORY ARRIVES THROUGH `setDirectory()`, WHICH `ldap_server.js`
// FILLS AT ITS OWN REQUIRE TIME.** That is the same inversion
// `group_claims.ts`, `applications.js`, `federation.js`, `spiffe_registry.js`,
// `vc_claims.js` and `admin_rbac.js` all use, and for their reason:
// `ldap_server.js` is required at 21 precisely so that its routes are
// registered last, and a require from here would drag every `/ldap` and
// `/admin/ldap` route to the front of the router `/admin/sts-metadata` is built
// by walking (rule 1).
//
// **A SERVICE WHOSE SLOT WAS NEVER FILLED PROMPTS EVERY TIME AND SAYS SO.**
// Not "consents to everything": an unfillable store means an agreement that
// cannot be remembered, and the honest behaviour is to ask again rather than to
// behave as though the answer had been kept. `state().storable` is what the
// console reports it with.
//
// ---------------------------------------------------------------------------
// PER REALM FOR FREE, AND THAT IS NOT AN ACCIDENT.
//
// Both halves live in the directory, the directory is a subtree per realm since
// 2026-08-25, and `applications.js`'s registry is that subtree's
// `ou=applications`. So a consent agreed in `acme` is invisible in the default
// realm without one line in this file mentioning a realm — which is the
// property `common/CLAUDE.md` says to check a new store against, answered by
// having no store.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16).
//
// `Consent` takes the logger, the settings, the application registry, the
// error-code table and the counters through `ConsentDeps`, and holds the
// directory slot as a field. The module still exports every name it did —
// `setDirectory` included, which `ldap/ldap_server.js` fills at its require
// time. Since #50's R2 the composition root builds the instance
// (`Consent.defaultDeps()`) and installs it; the module's old export names are
// FACADES that forward to it, for the JavaScript callers, and a process without
// the root builds a default when this module finishes loading. Its `wire()`
// writes the load line, which reads the instance. `Consent` is exported beside
// them for that root.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import config = require('./config');
import applications = require('./applications');
// The registry of failure codes, a LEAF. A refusal carries its code
// NON-ENUMERABLY on the result (`errorCodes.mark()`), so the JSON a console or
// `/admin-api` caller serialises from it is unchanged.
import errorCodes = require('./error_codes');
// For identityKeyOf() only. A LIBRARY REQUIRING A LIBRARY (rule 3e's test):
// admin_stats.js registers no route and does not require this file, so this
// closes no cycle and moves nothing in the router.
import stats = require('./admin_stats');
import InstanceSlot = require('./instance_slot');
// FAPI 1.0 Part 1 section 5.2.2 item 12 (#138): a leaf requiring helpers and
// config only, with no instance, so requiring it this early builds nothing.
import fapi = require('../oauth-oidc/fapi');

// The attribute a person's agreement is written into, and the one an operator's
// override is written into. Named here rather than spelled at each call site so
// that `ldap_server.js`'s canonical-name table, the console, the management API
// and the two writers below cannot come to disagree about the capitalisation —
// which is a real failure mode in a directory that lower-cases its keys and
// shows them back canonically.
const USER_ATTRIBUTE = 'oauthConsent';
const GLOBAL_ATTRIBUTE = 'oauthGlobalConsent';

// The directory slot: seven functions, validated whole. The last three are
// the WITHDRAWALS (#172), `oauthConsentWithdrawn` on the same entry.
interface ConsentDirectory {
  consentsOf(key: string): { values?: string[] } | null | undefined;
  addConsent(key: string, values: string[]):
    { ok?: boolean; dn?: string; reason?: string } | null | undefined;
  removeConsent(key: string, values: string[]):
    { dn?: string } | null | undefined;
  listConsents():
    Array<{ username: string; dn: string; values?: string[] }> |
    null | undefined;
  withdrawalsOf(key: string): { values?: string[] } | null | undefined;
  addWithdrawal(key: string, values: string[]):
    { ok?: boolean; dn?: string; reason?: string } | null | undefined;
  removeWithdrawal(key: string, values: string[]):
    { dn?: string } | null | undefined;
}

// What revoking a grant's tokens needs from `oauth-oidc/oauth2_bcp.js` — the
// #102 bookkeeping of what one grant issued. Reached LAZILY (see
// `defaultDeps()`), because that module is an OAuth library with stores of
// its own and this one is required long before it.
interface GrantBookkeeping {
  familyOfRefresh(claims: { jti?: string }): string;
  grantMembersOf(familyId: string, alsoJti?: string): string[];
  revokeFamily(familyId: string, clientId: string): Promise<boolean>;
}

// What a consent needs from the rest of the service.
interface ConsentDeps {
  log: typeof helpers.log;
  config: typeof config;
  applications: typeof applications;
  errorCodes: typeof errorCodes;
  stats: typeof stats;
  fapi: typeof fapi;
  grants: () => GrantBookkeeping;
}

// A GeneralizedTime stamp's exact shape — see `parseConsentValue()`.
const CONSENT_STAMP = /^\d{14}Z$/;

// A WITHDRAWAL's stamp (#172): the same GeneralizedTime WITH MILLISECONDS
// (RFC 4517 section 3.3.13 allows the fraction). A consent is compared with
// nothing finer than a second; a withdrawal is compared with the instant a
// grant was made, and two acts in one second must still be told apart.
const WITHDRAWN_STAMP = /^\d{14}\.\d{3}Z$/;

// The attribute a withdrawal is written into, on the person's entry and on
// the application's.
const WITHDRAWN_ATTRIBUTE = 'oauthConsentWithdrawn';
const GLOBAL_WITHDRAWN_ATTRIBUTE = 'oauthGlobalConsentWithdrawn';

// The token kinds a withdrawal revokes: what a grant under consent issued
// and a client can present again. An ID Token is presented to nobody here.
const GRANT_TOKEN_KINDS = ['access_token', 'refresh_token'];

class Consent {
  static readonly USER_ATTRIBUTE = USER_ATTRIBUTE;
  static readonly GLOBAL_ATTRIBUTE = GLOBAL_ATTRIBUTE;

  private directory: ConsentDirectory | null = null;

  constructor(private readonly deps: ConsentDeps) {
    deps.log.debug("Entering Consent.constructor().");
    deps.log.debug("Leaving Consent.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  static defaultDeps(): ConsentDeps {
    log.debug("Entering Consent.defaultDeps().");
    log.debug("Leaving Consent.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      applications: applications,
      errorCodes: errorCodes,
      stats: stats,
      fapi: fapi,
      // LAZILY, and it is the one module here that is: `oauth2_bcp.js` is
      // loaded by the OAuth modules at 9, this one at 8a, and a require at
      // the top of this file would run that module's store declarations
      // before the ones it expects to find — for a function asked only when
      // somebody withdraws a consent.
      grants: function grants(): GrantBookkeeping {
        log.debug("Entering grants().");
        log.debug("Leaving grants().");
        return require('../oauth-oidc/oauth2_bcp');
      }
    };
  }

  // What loading this module did with its instance before R2, run once
  // for whichever instance is installed (#50, R2).
  static wire(instance: Consent): void {
    log.debug("Entering Consent.wire().");
    log.info('The consent register is loaded. The authorization endpoint ' +
             'asks a person before it issues anything for a scope they have ' +
             'not agreed to for that application (oauth2.consentRequired, ' +
             (instance.required() ? 'ON' : 'OFF') + '). Answers are ' +
             'written to ' + USER_ATTRIBUTE + ' on the person\'s own entry; ' +
             GLOBAL_ATTRIBUTE + ' on an application\'s entry consents a ' +
             'scope for everybody without writing anything about anybody.');
    log.debug("Leaving Consent.wire().");
  }

  // ---------------------------------------------------------------------------
  // THE DIRECTORY SLOT.
  //
  // Seven functions, and it is validated WHOLE for `setLogoutReader()`'s
  // reason:
  // a filler that installed the two READS and neither WRITE would leave a
  // service that draws the consent screen, records nothing, and draws it again
  // on the next request — a loop with a button in it, and every part of it
  // working. And one that installed the four consent hooks without the three
  // WITHDRAWAL hooks (#172) could take a consent away without saying when, so
  // a re-consent would revive every refresh token granted before it.
  // ---------------------------------------------------------------------------
  setDirectory(hooks: ConsentDirectory | null | undefined): boolean {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Consent.setDirectory().");
    const needed = ['consentsOf', 'addConsent', 'removeConsent',
                    'listConsents', 'withdrawalsOf', 'addWithdrawal',
                    'removeWithdrawal'];
    const missing = needed.filter(function (name) {
      return !hooks || typeof hooks[name] !== 'function';
    });
    if (missing.length) {
      log.error(errorCodes.tag('STS-REG-0028') +
                'consent: setDirectory() was given something without ' +
                missing.join(', ') + ', so it was refused whole. The ' +
                'consent screen would otherwise draw, record nothing and ' +
                'draw again on the next request.');
      log.debug("Leaving Consent.setDirectory(). Refused.");
      return false;
    }
    this.directory = hooks;
    log.debug("Leaving Consent.setDirectory(). The consent register is " +
              "backed by the directory.");
    return true;
  }

  // WHAT IS IN THE SLOT, so that a test which stubs it can put back WHAT WAS
  // THERE (2026-09-18) — `applications.directoryInstalled()`'s reason, one
  // module along. `tests/run.js` runs every file in one process, and
  // `tests/consent.js` ended by installing a stub whose writes answer
  // `noEntry` and whose reads come back empty: its closing comment said
  // `setDirectory(null)` had removed it, but this function REFUSES anything
  // short of the four hooks and keeps what it had. So every later file that
  // recorded a consent recorded nothing, with no error anywhere —
  // `tests/consent_paging.js` was the first to notice. A test cannot re-run
  // `ldap_server.js`'s fill (a cached module does not re-execute), so the only
  // honest restore is this.
  //
  // Nothing in the SERVICE calls it: the slot is filled once, at the
  // directory's require time, and no code path replaces it.
  directoryInstalled(): ConsentDirectory | null {
    const { log } = this.deps;
    log.debug("Entering Consent.directoryInstalled().");
    log.debug("Leaving Consent.directoryInstalled().");
    return this.directory || null;
  }

  // Is the store reachable at all? Read by the console and by the screen, which
  // both say so rather than letting a person press a button whose effect will
  // not survive the redirect.
  storable() {
    const { log } = this.deps;
    log.debug("Entering Consent.storable().");
    log.debug("Leaving Consent.storable().");
    return !!this.directory;
  }

  // ---------------------------------------------------------------------------
  // THE SETTING.
  //
  // `oauth2.consentRequired` is the one switch, and unlike almost everything
  // else in this service it is ON by default. The argument for that is not the
  // usual one — a mock exists to exercise clients, and the client behaviour
  // being exercised here is the one every real authorization server produces on
  // a first sign-in. A client that has never met a consent screen has never run
  // the code that survives one.
  //
  // OFF means EXACTLY what this service did before this file existed: nothing
  // is asked, nothing is recorded, and `prompt=consent` is honoured no
  // differently from any other prompt value. It is not "consent everything" —
  // no agreement is written down, so turning the setting back on asks again.
  // ---------------------------------------------------------------------------
  //
  // A FAPI PROFILE (#138) REQUIRES IT whatever the setting says: section
  // 5.2.2 item 12, "shall require explicit approval by the user to authorize
  // the requested scope if it has not been previously authorized".
  required() {
    const { log, config, fapi } = this.deps;
    log.debug("Entering Consent.required().");
    log.debug("Leaving Consent.required().");
    // FAPI 1.0 item 12 only; FAPI 2.0 leaves consent to the ordinary rules
    // (rcbj, #140).
    return !!config.value('oauth2.consentRequired') || fapi.requiresConsent();
  }

  // ---------------------------------------------------------------------------
  // THE VALUE GRAMMAR. Two functions, and they are each other's inverse.
  // ---------------------------------------------------------------------------

  // A GeneralizedTime, the same spelling ldap_server.js writes, produced here
  // so that this module does not have to reach into the directory for a clock.
  generalizedTime(when) {
    const { log } = this.deps;
    log.debug("Entering Consent.generalizedTime().");
    const d = when ? new Date(when) : new Date();
    const pad = function (n: number, width?: number): string {
      log.debug("Entering pad().");
      log.debug("Leaving pad().");
      return String(n).padStart(width || 2, '0');
    };
    log.debug("Leaving Consent.generalizedTime().");
    return pad(d.getUTCFullYear(), 4) + pad(d.getUTCMonth() + 1) +
      pad(d.getUTCDate()) + pad(d.getUTCHours()) + pad(d.getUTCMinutes()) +
      pad(d.getUTCSeconds()) + 'Z';
  }

  consentValueOf(scope, clientId, when) {
    const { log } = this.deps;
    log.debug("Entering Consent.consentValueOf().");
    const leaf = String(scope == null ? '' : scope).trim();
    const who = String(clientId == null ? '' : clientId).trim();
    log.debug("Leaving Consent.consentValueOf().");
    return this.generalizedTime(when) + ' ' + leaf + ' ' + who;
  }

  // The inverse. TWO splits and not three: the client_id takes everything after
  // the second space, because it is the one field with no rule about what it
  // may contain.
  //
  // **THE FIRST FIELD IS CHECKED AGAINST THE TIMESTAMP'S SHAPE, and that check
  // is what tells a value this service wrote from a sentence somebody typed.**
  // An `ldapmodify` reaches this attribute like every other, and a grammar that
  // only counted spaces would read `this is not a consent` as a consent to `is`
  // for a client called `not a consent` — a consent to something nobody asked
  // for, invented by a parser out of prose. Fourteen digits and a `Z` is
  // `generalizedTime()`'s output exactly, so anything else comes back with an
  // empty `scope`, which every reader below treats as "not a consent" rather
  // than as a consent to nothing. (`CONSENT_STAMP`, at the top of the file.)
  parseConsentValue(value) {
    const { log } = this.deps;
    log.debug("Entering Consent.parseConsentValue().");
    const text = String(value == null ? '' : value).trim();
    const first = text.indexOf(' ');
    if (first < 0) {
      log.debug("Leaving Consent.parseConsentValue().");
      return { at: '', scope: '', client: '', raw: text };
    }
    const second = text.indexOf(' ', first + 1);
    if (second < 0) {
      log.debug("Leaving Consent.parseConsentValue().");
      return { at: '', scope: '', client: '', raw: text };
    }
    const at = text.slice(0, first);
    if (!CONSENT_STAMP.test(at)) {
      log.debug("Leaving Consent.parseConsentValue().");
      return { at: '', scope: '', client: '', raw: text };
    }
    log.debug("Leaving Consent.parseConsentValue().");
    return {
      at: at,
      scope: text.slice(first + 1, second),
      client: text.slice(second + 1),
      raw: text
    };
  }

  // WHO SOMEBODY IS, in the one spelling this whole feature files answers
  // under.
  //
  // It is `admin_stats.js`'s normalisation and nothing of this module's own —
  // `alice`, `alice@EXAMPLE.COM` and `urn:uuid:<entryUUID>` are one entry in
  // the directory, so they have to be one person here or somebody would be
  // asked again for every spelling of their own name. Exported because
  // `consent_screen.js` has to compare the session against the record it is
  // answering, and a second normalisation over there would be a second opinion
  // about who is at the keyboard.
  identityOf(value) {
    const { log, stats } = this.deps;
    log.debug("Entering Consent.identityOf().");
    log.debug("Leaving Consent.identityOf().");
    return stats.identityKeyOf(value);
  }

  // THE SCOPES IN A `scope` PARAMETER, deduplicated, in the order they were
  // asked for. RFC 6749 section 3.3 makes the value space-delimited and says
  // nothing about order or repetition, so `openid openid profile` is two scopes
  // and the consent screen must not list `openid` twice.
  scopesOf(scope) {
    const { log } = this.deps;
    log.debug("Entering Consent.scopesOf().");
    const seen = [];
    String(scope == null ? '' : scope).split(/\s+/).forEach(function (one) {
      if (one && seen.indexOf(one) < 0) {
        seen.push(one);
      }
    });
    log.debug("Leaving Consent.scopesOf().");
    return seen;
  }

  // ---------------------------------------------------------------------------
  // THE GLOBAL HALF: READ, THEN THE TWO WRITES.
  // ---------------------------------------------------------------------------

  // Every scope this application has been globally consented, in the order the
  // attribute holds them. An application with no entry has none, which is not
  // an error: an identifier this registry has never seen is the ordinary case
  // at this endpoint.
  globalConsentsOf(clientId) {
    const { log, applications } = this.deps;
    log.debug("Entering Consent.globalConsentsOf(). clientId=" +
              (clientId || '(none)'));
    const entry = applications.get(String(clientId || '').trim());
    if (!entry) {
      log.debug("Leaving Consent.globalConsentsOf(). No entry for it.");
      return [];
    }
    const raw = (entry.fields || {})[GLOBAL_ATTRIBUTE];
    const out = [];
    (Array.isArray(raw) ? raw :
     (raw === undefined || raw === null || raw === '' ? [] : [raw]))
      .forEach(function (one) {
        const text = String(one).trim();
        if (text && out.indexOf(text) < 0) {
          out.push(text);
        }
      });
    log.debug("Leaving Consent.globalConsentsOf(). " + out.length +
              " scope(s).");
    return out;
  }

  // GRANT one. It goes through `applications.updateApplication()` rather than
  // writing the attribute here, for the reason app_permissions.ts's five
  // actions do: that function is the ONE door the console form, the management
  // API's generic `update` operation and this action all pass through, so the
  // rules about what may be written live in one place and the
  // `application.update` audit row is written once.
  grantGlobal(clientId, scope, actor?) {
    const { log, applications, errorCodes } = this.deps;
    log.debug("Entering Consent.grantGlobal(). clientId=" + clientId);
    const who = String(clientId == null ? '' : clientId).trim();
    const leaf = String(scope == null ? '' : scope).trim();
    const problem = this.scopeProblem(leaf);
    if (problem) {
      log.debug("Leaving Consent.grantGlobal(). The scope is not usable.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0018');
    }
    const result = applications.updateApplication(who, {
      attribute: GLOBAL_ATTRIBUTE, mode: 'add', value: leaf,
      actor: String(actor || '')
    });
    if (!result.ok) {
      log.debug("Leaving Consent.grantGlobal(). Refused.");
      return result;
    }
    const permission = applications.forPermission(leaf);
    log.info('consent: "' + leaf +
             '" is globally consented for the application "' + who +
             '". Nobody signing in to it will be asked about that scope ' +
             'again, and nothing is written to anybody\'s entry — this is ' +
             'an override rather than a record.');
    log.debug("Leaving Consent.grantGlobal(). ok.");
    return Object.assign({}, result, {
      message: 'Everybody who signs in to "' + who + '" is now treated as ' +
        'having consented to <code>' + leaf + '</code>' +
        (permission ? ', which is the permission "' + permission.name +
          '" exposed by "' + permission.identifier + '"' : '') +
        '. No consent was ' +
        'written onto anybody\'s entry: this is an OVERRIDE, so removing it ' +
        'asks everybody again — including the people who would have said yes.'
    });
  }

  // WITHDRAW ONE. **THE ONE DOOR THAT TAKES `oauthGlobalConsent` OFF AN
  // ENTRY** (#172): `applications.updateApplication()` refuses the generic
  // remove unless it is told this register is the caller
  // (`consentRegister`), because a value taken off there would leave every
  // token issued under it working — the gap this ticket closed.
  //
  // WHAT IT REVOKES: every access and refresh token of this application
  // carrying the scope, for EVERYBODY — except the people who agreed to it
  // themselves, whose tokens were issued under their own consent as much as
  // under the override and still are. The withdrawal instant goes on the
  // APPLICATION's entry (`oauthGlobalConsentWithdrawn`), so re-adding the
  // override covers new grants and revives no old one.
  //
  // **THE HOSTED SURFACES ARE NOT EXEMPT, AND THAT IS DELIBERATE.** The
  // console, the portal and the debugger hold `offline_access` through this
  // override (#118), and their seed says why it is an attribute rather than
  // an exemption: an operator who wants the screen removes the value and gets
  // it. Withdrawing one of them here does what it does to any client: every
  // session of that surface that stood on it cannot renew its tokens and is
  // ended at its next renewal (`oidc_rp.ts`), and the next page runs the code
  // flow — which, the override gone, asks the person. Nobody is locked out.
  // The reply names the surface so an operator is not surprised by it.
  revokeGlobal(clientId, scope, actor?) {
    const { log, applications, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Consent.revokeGlobal(). clientId=" + clientId);
    const who = String(clientId == null ? '' : clientId).trim();
    const leaf = String(scope == null ? '' : scope).trim();
    const result = applications.updateApplication(who, {
      attribute: GLOBAL_ATTRIBUTE, mode: 'remove', value: leaf,
      actor: String(actor || ''), consentRegister: true
    });
    if (!result.ok) {
      log.debug("Leaving Consent.revokeGlobal(). Refused.");
      return result;
    }
    const stamp = self.withdrawnStamp();
    const noted = applications.noteGlobalConsentWithdrawn(who, leaf, stamp);
    if (!noted) {
      log.error(errorCodes.tag('STS-REG-0192') + 'consent: the withdrawal of ' +
                'the global consent to "' + leaf + '" for "' + who + '" ' +
                'could not be written onto its entry. Its tokens are ' +
                'revoked; re-adding the override before they expire would ' +
                'let a refresh token the walk did not reach renew.');
    }
    const revoked = self.revokeIssuedUnder({
      clientId: who, scopes: [leaf],
      spare: function (holder) {
        return self.consentsOf(holder).some(function (one) {
          return one.client === who && one.scope === leaf;
        });
      }
    }, 'the global consent to ' + leaf + ' was withdrawn' +
       (actor ? ' by ' + actor : ''));
    const surface = applications.HOSTED_SURFACE_CLIENT_IDS.indexOf(who) >= 0;
    log.info('consent: "' + who + '" no longer consents "' + leaf + '" for ' +
             'everybody; ' + revoked + ' token(s) issued under it were ' +
             'revoked.' + (surface ? ' It is one of this service\'s own ' +
               'surfaces, whose sessions standing on it end at their next ' +
               'renewal.' : ''));
    log.debug("Leaving Consent.revokeGlobal(). ok.");
    return Object.assign({}, result, {
      revoked: revoked, withdrawnAt: stamp,
      message: '"' + who + '" no longer consents <code>' + leaf +
        '</code> for everybody. The next person to sign in asking for it ' +
        'is PROMPTED — ' +
        'including anybody who was covered by this override, because an ' +
        'override records nothing about the people it covered. Somebody who ' +
        'agreed to it personally, before or after, still has that on their ' +
        'entry and is not asked. ' + self.revokedSentence(revoked) +
        ' Tokens of people who agreed to it themselves were left alone.' +
        (surface ? ' <strong>This is one of this service\'s own ' +
          'surfaces</strong>: every session of it that held this scope ' +
          'through the override is ended at its next token renewal, and the ' +
          'person signs in again and is asked.' : '')
    });
  }

  // RFC 6749 section 3.3's `scope-token`. THE RULE ITSELF IS IN
  // `applications.js`, which owns the schema and therefore owns what a value of
  // `oauthGlobalConsent` may be — see the block above `scopeTokenProblem()`
  // there. This is a one-line delegation rather than a re-export so that the
  // name this module's callers use says what it is about.
  scopeProblem(scope) {
    const { log, applications } = this.deps;
    log.debug("Entering Consent.scopeProblem().");
    log.debug("Leaving Consent.scopeProblem().");
    return applications.scopeTokenProblem(scope);
  }

  // ---------------------------------------------------------------------------
  // THE PER-USER HALF: READ, RECORD, REVOKE, FORGET.
  // ---------------------------------------------------------------------------

  // Everything one person has agreed to, parsed. The identity is normalised
  // through `admin_stats.js` first, so that the key this module looks an entry
  // up by is the key the entry was created under — `alice`, `alice@EXAMPLE.COM`
  // and `urn:uuid:<entryUUID>` are one person to the directory and have to be
  // one person here, or somebody would be asked again for every spelling of
  // their own name.
  consentsOf(username) {
    const { log, stats } = this.deps;
    const self = this;
    log.debug("Entering Consent.consentsOf().");
    if (!this.directory) {
      log.debug("Leaving Consent.consentsOf(). No directory is installed.");
      return [];
    }
    const key = stats.identityKeyOf(username);
    if (!key) {
      log.debug("Leaving Consent.consentsOf(). No identity.");
      return [];
    }
    const found = this.directory.consentsOf(key) || {};
    const rows = (found.values || []).map(function (value) {
      return self.parseConsentValue(value);
    })
                                     .filter(function (one) {
      return !!one.scope;
    });
    log.debug("Leaving Consent.consentsOf(). " + rows.length + " consent(s).");
    return rows;
  }

  // ---------------------------------------------------------------------------
  // THE QUESTION THE AUTHORIZATION ENDPOINT ASKS, AND THE ONE FUNCTION THAT
  // ANSWERS IT.
  //
  // Given a person, a client and the `scope` a request carries, which scopes
  // have not been agreed to? Everything about the decision is here rather than
  // at the endpoint, for the reason `oauth2.js`'s `permissionRefusal()` gives:
  // a rule spread across the caller and the library is a rule that gets decided
  // twice.
  //
  // `all: true` is `prompt=consent` — OIDC Core section 3.1.2.1 says the server
  // SHOULD prompt the person for consent again, so every requested scope
  // becomes outstanding whatever is on the entry. What it does NOT do is delete
  // what was already agreed: re-consenting adds nothing that is not already
  // there, and a person who cancels keeps what they had.
  // ---------------------------------------------------------------------------
  //
  // The answer is typed `any` FOR NOW (#50): `oauth-oidc/oauth2.ts`, not yet
  // converted, reads `names` off a union of this answer and its own fallback
  // literal, which a declared shape would make a type error in that file.
  // Declare the shape when that caller is converted.
  outstanding(request): any {
    const { log, applications } = this.deps;
    const self = this;
    log.debug("Entering Consent.outstanding().");
    const asked = request || {};
    const clientId = String(asked.clientId || '').trim();
    const wanted = self.scopesOf(asked.scope);
    const all = !!asked.all;
    // AN ADMINISTRATOR'S GLOBAL CONSENT IS NOT THE USER'S APPROVAL under a
    // FAPI profile (#138, section 5.2.2 item 12) — this service's own console
    // and portal included, by rcbj's decision: the person approves each
    // client's scope once, and after that it is "previously authorized".
    const global = self.deps.fapi.honoursGlobalConsent()
      ? self.globalConsentsOf(clientId) : [];
    const held = self.consentsOf(asked.username).filter(function (one) {
      return one.client === clientId;
    });
    const rows = wanted.map(function (scope) {
      const mine = held.filter(function (one) {
        return one.scope === scope;
      })[0];
      const globally = global.indexOf(scope) >= 0;
      return {
        scope: scope,
        // WHICH ANSWER COVERS IT, and there are three. The order matters on the
        // page and nowhere else: a scope covered BOTH ways is reported as the
        // person's own, because that is the fact that survives the override
        // being taken away.
        consented: !!mine,
        global: globally,
        at: mine ? mine.at : '',
        // What this scope IS, where this service knows. A delegated permission
        // identifier resolves to the application that exposes it and to the
        // description somebody typed; everything else is just a word, and
        // saying so is better than inventing a sentence about it.
        permission: applications.forPermission(scope) || null
      };
    });
    const out = rows.filter(function (one) {
      return all ? true : (!one.consented && !one.global);
    });
    log.debug("Leaving Consent.outstanding(). " + out.length + " of " +
              rows.length + " scope(s) need an answer.");
    return { clientId: clientId, scopes: rows, outstanding: out,
             names: out.map(function (one) { return one.scope; }) };
  }

  // RECORD an agreement. One value per scope, added in one call so that a
  // person who agreed to five scopes produces one directory write and one audit
  // row rather than five of each.
  //
  // It returns `stored: false` rather than failing when there is no entry to
  // write to — `ldap.autocreateUsers` can be off, and a service that refused to
  // issue because it could not file the paperwork would be a mock that stopped
  // answering. The log says so, and the person is asked again next time, which
  // is the honest consequence.
  record(username, clientId, scopes, actor?) {
    const { log, errorCodes, stats } = this.deps;
    const self = this;
    log.debug("Entering Consent.record().");
    const key = stats.identityKeyOf(username);
    const who = String(clientId || '').trim();
    const list = (Array.isArray(scopes) ? scopes : self.scopesOf(scopes))
      .filter(Boolean);
    if (!this.directory) {
      log.warn(errorCodes.tag('STS-REG-0029') +
               'consent: no directory is installed, so "' + key +
               '" agreeing to ' +
               list.join(', ') + ' for "' + who + '" was not written down. ' +
               'They will be asked again.');
      log.debug("Leaving Consent.record(). No directory.");
      return errorCodes.mark({ ok: true, stored: false, scopes: list },
                             'STS-REG-0029');
    }
    if (!key || !who || !list.length) {
      log.debug("Leaving Consent.record(). Nothing to record.");
      return { ok: true, stored: false, scopes: [] };
    }
    // ONE INSTANT FOR THE WHOLE BATCH, and it is a Date rather than a formatted
    // string: `consentValueOf()` formats, so handing it something already
    // formatted produced `new Date('20260901143000Z')`, which is an Invalid
    // Date — and every value written carried `0NaNNaN…Z` where the timestamp
    // belongs. Five scopes agreed in one press are five values that agree about
    // when.
    const when = new Date();
    const values = list.map(function (scope) {
      return self.consentValueOf(scope, who, when);
    });
    const written = this.directory.addConsent(key, values) || {};
    log.info('consent: "' + key + '" agreed that "' + who + '" may ask for ' +
             list.join(', ') + ' on their behalf. It is on ' +
             (written.dn || 'their entry') + ' as ' + USER_ATTRIBUTE +
             ', so the next sign-in does not ask.');
    log.debug("Leaving Consent.record(). stored=" + !!written.ok);
    const recorded = { ok: true, stored: !!written.ok, dn: written.dn || '',
                       scopes: list,
                       reason: written.reason || '' };
    log.debug("Leaving Consent.record().");
    // NOT WRITTEN DOWN is a failure even though the answer is `ok` — the person
    // is asked again next time, which is the honest consequence and still one
    // an operator wants to count.
    return written.ok ? recorded : errorCodes.mark(recorded, 'STS-REG-0030');
  }

  // REVOKE one triple. The value is REBUILT from the entry rather than taken
  // from the caller, because the timestamp is part of the value and nothing
  // outside this module should have to know that — a form that posted the whole
  // raw value back would break the first time somebody edited the attribute by
  // hand.
  revoke(username, clientId, scope, actor?) {
    const { log, applications, errorCodes, stats } = this.deps;
    const self = this;
    log.debug("Entering Consent.revoke().");
    const key = stats.identityKeyOf(username);
    const who = String(clientId || '').trim();
    const leaf = String(scope || '').trim();
    if (!this.directory) {
      log.debug("Leaving Consent.revoke(). No directory.");
      return errorCodes.mark({ ok: false, errors: ['This service has no ' +
                                   'directory installed, so there is nothing ' +
                                   'to revoke from.'] }, 'STS-REG-0029');
    }
    if (!key || !who || !leaf) {
      log.debug("Leaving Consent.revoke(). Under-specified.");
      return errorCodes.mark({ ok: false, errors: ['A consent is a person, ' +
        'an application and a scope. Send `username`, `client` and `scope` — ' +
        'all three, because one person may consent the same scope to ' +
        'several applications and revoking the wrong one is invisible until ' +
        'somebody is asked again.'] }, 'STS-REG-0031');
    }
    const held = self.consentsOf(key).filter(function (one) {
      return one.client === who && one.scope === leaf;
    });
    if (!held.length) {
      log.debug("Leaving Consent.revoke(). Nothing held.");
      return errorCodes.mark({ ok: false, errors: ['"' + key + '" has not ' +
        'consented "' + leaf + '" for "' + who + '", so there is nothing to ' +
        'take away. A scope covered by GLOBAL consent is not on anybody\'s ' +
        'entry and is removed at /admin/consent instead — that is the ' +
        'difference between an override and a record.'] }, 'STS-REG-0032');
    }
    // WITHDRAWN, NOT ONLY FORGOTTEN (#172): the instant on the entry, then
    // every token issued under it revoked — see the block above
    // `withdrawnStamp()`.
    const outcome = self.withdrawHeld(key, held, actor);
    log.info('consent: "' + key + '" no longer consents "' + leaf + '" for "' +
             who + '". They are asked again the next time that application ' +
             'requests it, and ' + outcome.revoked + ' token(s) issued under ' +
             'it were revoked.');
    log.debug("Leaving Consent.revoke(). ok.");
    return { ok: true, removed: held.length, dn: outcome.dn,
             revoked: outcome.revoked, withdrawnAt: outcome.at,
             message: '"' + key + '" no longer consents <code>' + leaf +
               '</code> for "' + who + '". The next authorization request ' +
               'from that application naming that scope draws the consent ' +
               'screen again. ' + self.revokedSentence(outcome.revoked) };
  }

  // FORGET everything one person agreed to. A separate action rather than a
  // loop over the one above, because the one thing somebody wants after testing
  // a consent screen is to be asked again — and doing that a row at a time on a
  // person with thirty consents is not a control, it is a chore.
  forget(username, actor?) {
    const { log, errorCodes, stats } = this.deps;
    const self = this;
    log.debug("Entering Consent.forget().");
    const key = stats.identityKeyOf(username);
    if (!this.directory) {
      log.debug("Leaving Consent.forget(). No directory.");
      return errorCodes.mark({ ok: false, errors: ['This service has no ' +
                                   'directory installed, so there is nothing ' +
                                   'to forget.'] }, 'STS-REG-0029');
    }
    if (!key) {
      log.debug("Leaving Consent.forget(). No identity.");
      return errorCodes.mark({ ok: false, errors: ['Which person? Send ' +
                                   '`username` exactly as /admin/users names ' +
                                   'them.'] }, 'STS-REG-0031');
    }
    const held = self.consentsOf(key);
    if (!held.length) {
      log.debug("Leaving Consent.forget(). Nothing held.");
      return errorCodes.mark({ ok: false, errors: ['"' + key + '" has ' +
        'consented nothing that is written down. A scope they were never ' +
        'asked about — one under GLOBAL consent — leaves no record, which is ' +
        'what makes this page able to say the difference.'] },
        'STS-REG-0032');
    }
    const outcome = self.withdrawHeld(key, held, actor);
    log.info('consent: every consent "' + key + '" had agreed to (' +
             held.length +
             ') was withdrawn. They are asked again by every application, ' +
             'and ' + outcome.revoked + ' token(s) issued under those ' +
             'consents were revoked.');
    log.debug("Leaving Consent.forget(). " + held.length + " removed.");
    return { ok: true, removed: held.length, dn: outcome.dn,
             revoked: outcome.revoked, withdrawnAt: outcome.at,
             message: held.length + ' consent(s) were removed from "' + key +
               '". ' +
               'Every application that asks them for a scope now draws the ' +
               'consent screen again — except for the scopes under GLOBAL ' +
               'consent, which were never on their entry to begin with. ' +
               self.revokedSentence(outcome.revoked) };
  }

  // ---------------------------------------------------------------------------
  // WITHDRAWN MEANS WITHDRAWN, NOT "ASKED AGAIN NEXT TIME" (#172, 2026-09-23).
  //
  // Until this date a revoke, a forget and a global revoke each edited the
  // record and said, in as many words, that nothing already ISSUED was
  // touched. So a person who withdrew an application's `offline_access`
  // watched it keep refreshing for the refresh token's whole lifetime — and
  // with `offline_access` it did so while they were absent, which is the one
  // thing OpenID Connect Core section 11 says that scope is consented FOR.
  // RFC 6749 section 1.5 makes a refresh token "a string representing the
  // authorization granted to the client by the resource owner"; once the
  // authorization is withdrawn it represents nothing.
  //
  // THREE THINGS, AND EACH ONE CLOSES A GAP THE OTHER TWO LEAVE:
  //
  //   1. **A WITHDRAWAL INSTANT IS RECORDED**, per (person, application,
  //      scope) as `oauthConsentWithdrawn` on the person's entry and per
  //      (application, scope) as `oauthGlobalConsentWithdrawn` on the
  //      application's. The grammar is the consent's own with the instant to
  //      the millisecond (`WITHDRAWN_STAMP`). Without it a RE-CONSENT would
  //      revive every refresh token minted before the withdrawal, because
  //      the record would say "consented" again and nothing would say since
  //      when. One value per pair: a later withdrawal replaces an earlier
  //      one, since only the latest can matter.
  //   2. **EVERY TOKEN ISSUED UNDER THE CONSENT IS REVOKED** at the moment it
  //      is withdrawn (`revokeIssuedUnder()`), through `stats.revoke()` —
  //      the ONE revocation register `/oauth2/revoke`, the console and the
  //      introspection endpoint share, persisted and replicated, so an access
  //      token dies on every node rather than only on the one that took the
  //      click. A refresh token takes its whole grant with it, #102's way
  //      (`grantMembersOf()`, `revokeFamily()`), so the access token minted
  //      beside it goes too even where its own scope was narrowed.
  //   3. **THE REFRESH GRANT RE-CHECKS** (`refreshRefusal()`), against the
  //      directory, in every mode. That is the ENFORCEMENT: it is stateless,
  //      so a refresh token the walk above never saw — minted on another node
  //      in the same instant, forgotten to a cap, issued before a restart —
  //      is refused at its first use. The walk is the prompt clean-up, and
  //      the only thing that reaches an access token before it expires.
  //
  // **WITHDRAWING ONE SCOPE REVOKES THE WHOLE REFRESH TOKEN** (the decision
  // on #172). RFC 6749 section 6 would allow the next refresh to be narrowed
  // to what is left; this service refuses instead, because the refresh
  // token's scope is fixed at the grant and a grant the person has taken part
  // of back is not the grant they gave.
  // ---------------------------------------------------------------------------

  // A withdrawal instant, in `WITHDRAWN_STAMP`'s spelling.
  withdrawnStamp(when?: number | Date): string {
    const { log } = this.deps;
    log.debug("Entering Consent.withdrawnStamp().");
    const d = when === undefined ? new Date() : new Date(when);
    const seconds = this.generalizedTime(d);
    log.debug("Leaving Consent.withdrawnStamp().");
    return seconds.slice(0, 14) + '.' +
      String(d.getUTCMilliseconds()).padStart(3, '0') + 'Z';
  }

  // Either stamp as a millisecond epoch, or NaN for anything else. A
  // consent's stamp has no fraction and reads as the start of its second.
  stampMs(stamp: unknown): number {
    const { log } = this.deps;
    log.debug("Entering Consent.stampMs().");
    const text = String(stamp == null ? '' : stamp);
    if (!CONSENT_STAMP.test(text) && !WITHDRAWN_STAMP.test(text)) {
      log.debug("Leaving Consent.stampMs(). Not a stamp.");
      return NaN;
    }
    const ms = text.length > 15 ? Number(text.slice(15, 18)) : 0;
    log.debug("Leaving Consent.stampMs().");
    return Date.UTC(Number(text.slice(0, 4)), Number(text.slice(4, 6)) - 1,
                    Number(text.slice(6, 8)), Number(text.slice(8, 10)),
                    Number(text.slice(10, 12)), Number(text.slice(12, 14)),
                    ms);
  }

  // A withdrawal value, parsed. The consent grammar, with the withdrawal
  // stamp in front: `<stamp> <scope> <client_id>` on a person's entry and
  // `<stamp> <scope>` on an application's (`global`), the client_id last for
  // `parseConsentValue()`'s reason. Anything else has an empty `scope`.
  parseWithdrawalValue(value: unknown, global?: boolean) {
    const { log } = this.deps;
    log.debug("Entering Consent.parseWithdrawalValue().");
    const text = String(value == null ? '' : value).trim();
    const empty = { at: '', atMs: NaN, scope: '', client: '', raw: text };
    const first = text.indexOf(' ');
    const at = first < 0 ? '' : text.slice(0, first);
    if (!WITHDRAWN_STAMP.test(at)) {
      log.debug("Leaving Consent.parseWithdrawalValue(). Not a withdrawal.");
      return empty;
    }
    const rest = text.slice(first + 1);
    const second = global ? -1 : rest.indexOf(' ');
    if (!global && second < 0) {
      log.debug("Leaving Consent.parseWithdrawalValue(). No client.");
      return empty;
    }
    const scope = global ? rest : rest.slice(0, second);
    if (!scope || /\s/.test(scope)) {
      log.debug("Leaving Consent.parseWithdrawalValue(). No scope.");
      return empty;
    }
    log.debug("Leaving Consent.parseWithdrawalValue().");
    return { at: at, atMs: this.stampMs(at), scope: scope,
             client: global ? '' : rest.slice(second + 1), raw: text };
  }

  // Every withdrawal recorded on one person's entry, parsed.
  withdrawalsOf(username: unknown) {
    const { log, stats } = this.deps;
    const self = this;
    log.debug("Entering Consent.withdrawalsOf().");
    const key = stats.identityKeyOf(username);
    if (!this.directory || !key) {
      log.debug("Leaving Consent.withdrawalsOf(). No directory or no " +
                "identity.");
      return [];
    }
    const found = this.directory.withdrawalsOf(key) || {};
    const rows = (found.values || []).map(function (value) {
      return self.parseWithdrawalValue(value);
    }).filter(function (one) {
      return !!one.scope;
    });
    log.debug("Leaving Consent.withdrawalsOf(). " + rows.length + ".");
    return rows;
  }

  // Every withdrawal of an application's global consent, parsed.
  globalWithdrawalsOf(clientId: unknown) {
    const { log, applications } = this.deps;
    const self = this;
    log.debug("Entering Consent.globalWithdrawalsOf().");
    const entry = applications.get(String(clientId || '').trim());
    const raw = entry ? (entry.fields || {})[GLOBAL_WITHDRAWN_ATTRIBUTE] : [];
    const rows = (Array.isArray(raw) ? raw : (raw ? [raw] : []))
      .map(function (value) {
        return self.parseWithdrawalValue(value, true);
      }).filter(function (one) {
        return !!one.scope;
      });
    log.debug("Leaving Consent.globalWithdrawalsOf(). " + rows.length + ".");
    return rows;
  }

  // RECORD that one person withdrew these (application, scope) pairs, at one
  // instant. A value already there for a pair is REPLACED: only the latest
  // withdrawal can refuse anything, and an attribute that grew by one value
  // per click would be a list nobody could read.
  noteWithdrawn(username: unknown,
                pairs: Array<{ client: string; scope: string }>,
                when?: number) {
    const { log, errorCodes, stats } = this.deps;
    const self = this;
    log.debug("Entering Consent.noteWithdrawn().");
    const key = stats.identityKeyOf(username);
    if (!this.directory || !key || !pairs.length) {
      log.debug("Leaving Consent.noteWithdrawn(). Nothing to write.");
      return { ok: false, stored: false };
    }
    const stamp = self.withdrawnStamp(when);
    const earlier = self.withdrawalsOf(key).filter(function (one) {
      return pairs.some(function (pair) {
        return pair.client === one.client && pair.scope === one.scope;
      });
    }).map(function (one) {
      return one.raw;
    });
    if (earlier.length) {
      this.directory.removeWithdrawal(key, earlier);
    }
    const written = this.directory.addWithdrawal(key, pairs.map(function (p) {
      return stamp + ' ' + p.scope + ' ' + p.client;
    })) || {};
    if (!written.ok) {
      // The record is gone and its tokens are revoked; what is lost is the
      // instant, so a RE-CONSENT could revive a refresh token the walk did
      // not reach. Loud, and coded, because that is a withdrawal half done.
      log.error(errorCodes.tag('STS-REG-0192') + 'consent: the withdrawal ' +
                'of ' + pairs.length + ' consent(s) by "' + key + '" could ' +
                'not be written down (' + (written.reason || 'no entry') +
                '). Their tokens were revoked; a refresh token minted on ' +
                'another node at this instant is refused only while the ' +
                'consent stays withdrawn.');
    }
    log.debug("Leaving Consent.noteWithdrawn(). stored=" + !!written.ok);
    return { ok: !!written.ok, stored: !!written.ok, at: stamp };
  }

  // WHETHER A GRANT STILL STANDS, for the refresh grant. `grantAt` is the
  // instant the grant was made (the refresh token's `grant_at`), `grantType`
  // the grant it came from, and a refusal names its code. Null means go on.
  //
  // For each scope the token carries:
  //
  //   * the PERSON withdrew it for this application at or after the grant —
  //     refused, whatever else holds (`STS-OAUTH-0615`);
  //   * the application's GLOBAL consent to it was withdrawn at or after the
  //     grant, and the person had not agreed to it themselves by the time
  //     of the grant — refused (`STS-OAUTH-0615`). Re-adding the override
  //     does not revive it, and nor does a personal consent given later;
  //   * nothing covers it — no consent of the person's that predates the
  //     grant and no global consent in force — for a grant made at the
  //     AUTHORIZATION ENDPOINT, which is where consent is asked, while
  //     consent is required and `oauth2.refreshRequiresConsent` is on:
  //     refused (`STS-OAUTH-0616`). That is a token minted while
  //     `oauth2.consentRequired` was off, or before the directory could
  //     hold the answer. The other grants never ask anybody, so they are
  //     held to explicit withdrawals only.
  //
  // `at <= grantAt` for a personal consent, because a consent stamp is to the
  // second and was written before the code was minted; a withdrawal in the
  // SAME millisecond as the grant refuses it (`>=`), the safe side of a tie.
  refreshRefusal(asked: { username?: string; clientId?: string;
                          scope?: string; grantAt?: unknown;
                          grantType?: string }) {
    const { log, config, fapi } = this.deps;
    const self = this;
    log.debug("Entering Consent.refreshRefusal().");
    const username = String(asked.username || '');
    const clientId = String(asked.clientId || '').trim();
    if (!username || !clientId) {
      log.debug("Leaving Consent.refreshRefusal(). No person behind it.");
      return null;
    }
    // A token with no grant instant is judged as the oldest grant there
    // could be, which is the safe reading of a token this code did not mint.
    const at = Number(asked.grantAt);
    const grantAt = isFinite(at) && at > 0 ? at : 0;
    const scopes = self.scopesOf(asked.scope);
    const held = self.consentsOf(username).filter(function (one) {
      return one.client === clientId;
    });
    const withdrawn = self.withdrawalsOf(username).filter(function (one) {
      return one.client === clientId;
    });
    const globalWithdrawn = self.globalWithdrawalsOf(clientId);
    const globals = fapi.honoursGlobalConsent()
      ? self.globalConsentsOf(clientId) : [];
    const recordedRequired = asked.grantType === 'authorization_code' &&
      self.required() && !!config.value('oauth2.refreshRequiresConsent');
    for (const scope of scopes) {
      const mine = withdrawn.filter(function (one) {
        return one.scope === scope && one.atMs >= grantAt;
      });
      if (mine.length) {
        log.debug("Leaving Consent.refreshRefusal(). The person withdrew " +
                  scope + ".");
        return { errorCode: 'STS-OAUTH-0615', scope: scope,
                 reason: 'withdrawn',
                 description: 'The person this refresh token was issued ' +
                   'for withdrew their consent to "' + scope + '" for this ' +
                   'client after it was granted, so the grant it represents ' +
                   'no longer exists (RFC 6749 section 1.5). A new ' +
                   'authorization request asks them again.' };
      }
      const personal = held.some(function (one) {
        return one.scope === scope && self.stampMs(one.at) <= grantAt;
      });
      const overrideGone = globalWithdrawn.some(function (one) {
        return one.scope === scope && one.atMs >= grantAt;
      });
      if (overrideGone && !personal) {
        log.debug("Leaving Consent.refreshRefusal(). The global consent to " +
                  scope + " was withdrawn.");
        return { errorCode: 'STS-OAUTH-0615', scope: scope,
                 reason: 'withdrawn',
                 description: 'This client\'s consent to "' + scope + '" ' +
                   'for everybody was withdrawn after this refresh token ' +
                   'was granted, and the person had not agreed to it ' +
                   'themselves, so the grant it represents no longer ' +
                   'exists (RFC 6749 section 1.5).' };
      }
      const global = !overrideGone && globals.indexOf(scope) >= 0;
      if (recordedRequired && !personal && !global) {
        log.debug("Leaving Consent.refreshRefusal(). No recorded consent " +
                  "to " + scope + ".");
        return { errorCode: 'STS-OAUTH-0616', scope: scope,
                 reason: 'unconsented',
                 description: 'Consent is required here and nothing records ' +
                   'the person agreeing to "' + scope + '" for this client ' +
                   'before this refresh token was granted, so it is not ' +
                   'renewed (oauth2.refreshRequiresConsent). A new ' +
                   'authorization request asks them.' };
      }
    }
    log.debug("Leaving Consent.refreshRefusal(). The grant stands.");
    return null;
  }

  // REVOKE WHAT WAS ISSUED UNDER A CONSENT: every access and refresh token of
  // `clientId` whose scope names one of `scopes` — for one person where
  // `username` is given, for everybody otherwise, less the people `spare`
  // answers true for (a global withdrawal spares those who agreed
  // themselves). A refresh token takes its grant with it (#102). Returns the
  // count newly revoked. Synchronous in what it revokes; the family marks,
  // which reach a member minted on another node this instant, are claimed
  // behind it and logged if the claim store cannot be asked.
  revokeIssuedUnder(asked: { username?: string; clientId: string;
                             scopes: string[];
                             spare?: (holder: string) => boolean },
                    via: string): number {
    const { log, stats, errorCodes } = this.deps;
    log.debug("Entering Consent.revokeIssuedUnder(). client=" +
              asked.clientId);
    const clientId = String(asked.clientId || '').trim();
    const wanted = (asked.scopes || []).filter(Boolean);
    const person = asked.username ? stats.identityKeyOf(asked.username) : '';
    if (!clientId || !wanted.length) {
      log.debug("Leaving Consent.revokeIssuedUnder(). Nothing named.");
      return 0;
    }
    const spared: Record<string, boolean> = {};
    const refreshes: string[] = [];
    let count = stats.revokeWhere(function (record) {
      if (GRANT_TOKEN_KINDS.indexOf(record.kind) < 0 ||
          String(record.client_id || '') !== clientId) {
        return false;
      }
      const holder = stats.holderKeyOf(record.username, record.sub);
      if (!holder || (person && holder !== person)) {
        return false;
      }
      const carried = String(record.scope || '').split(/\s+/)
        .concat(record.kind === 'access_token'
          ? String(record.audience || '').split(/\s+/) : []);
      if (!wanted.some(function (one) {
        return carried.indexOf(one) >= 0;
      })) {
        return false;
      }
      if (asked.spare) {
        if (!(holder in spared)) {
          spared[holder] = !!asked.spare(holder);
        }
        if (spared[holder]) {
          return false;
        }
      }
      if (record.kind === 'refresh_token') {
        refreshes.push(String(record.jti));
      }
      return true;
    }, via);
    if (refreshes.length) {
      let grants: GrantBookkeeping | null = null;
      try {
        grants = this.deps.grants();
      } catch (e) {
        // A process without the OAuth modules has no grants to follow; the
        // tokens the walk found are revoked all the same.
        log.debug("Caught in Consent.revokeIssuedUnder(): " +
                  ((e && e.message) || e));
        grants = null;
      }
      refreshes.forEach(function (jti) {
        if (!grants) {
          return;
        }
        const family = grants.familyOfRefresh({ jti: jti });
        grants.grantMembersOf(family, jti).forEach(function (member) {
          if (stats.revoke(member, via + ', with the refresh token of its ' +
                                   'grant')) {
            count += 1;
          }
        });
        if (family) {
          grants.revokeFamily(family, clientId).then(function (ok) {
            if (!ok) {
              log.debug("revokeIssuedUnder(): the family mark for " + family +
                        " was not written; oauth2_bcp.js logged why.");
            }
          }, function (e) {
            log.error(errorCodes.tag('STS-OAUTH-0617') + 'consent: the ' +
                      'refresh family ' + family + ' of a withdrawn ' +
                      'consent could not be revoked by id: ' +
                      ((e && e.message) || e) + '. Its members known here ' +
                      'are revoked, and the refresh grant refuses any ' +
                      'other at its first use.');
          });
        }
      });
    }
    log.info('consent: ' + count + ' token(s) of "' + clientId + '" issued ' +
             'under ' + wanted.join(', ') + (person ? ' for "' + person + '"'
               : '') + ' were revoked (' + via + ').');
    log.debug("Leaving Consent.revokeIssuedUnder(). " + count + ".");
    return count;
  }

  // WITHDRAW EVERY SCOPE ONE PERSON AGREED TO FOR ONE APPLICATION — the
  // portal's "withdraw this application" and the console's and the API's
  // `revoke-application-consent`. `revoke()` per scope would be one
  // withdrawal instant per scope and one walk per scope for what the person
  // did in one press.
  revokeApplication(username: unknown, clientId: unknown, actor?: string) {
    const { log, errorCodes, stats } = this.deps;
    const self = this;
    log.debug("Entering Consent.revokeApplication().");
    const key = stats.identityKeyOf(username);
    const who = String(clientId || '').trim();
    if (!this.directory) {
      log.debug("Leaving Consent.revokeApplication(). No directory.");
      return errorCodes.mark({ ok: false, errors: ['This service has no ' +
        'directory installed, so there is nothing to withdraw.'] },
        'STS-REG-0029');
    }
    if (!key || !who) {
      log.debug("Leaving Consent.revokeApplication(). Under-specified.");
      return errorCodes.mark({ ok: false, errors: ['Send `username` and ' +
        '`client`: the person and the application whose every consent is ' +
        'withdrawn.'] }, 'STS-REG-0031');
    }
    const held = self.consentsOf(key).filter(function (one) {
      return one.client === who;
    });
    if (!held.length) {
      log.debug("Leaving Consent.revokeApplication(). Nothing held.");
      return errorCodes.mark({ ok: false, errors: ['"' + key + '" has ' +
        'consented nothing for "' + who + '" that is written down, so there ' +
        'is nothing to withdraw. A scope under GLOBAL consent is not on ' +
        'anybody\'s entry.'] }, 'STS-REG-0032');
    }
    const outcome = self.withdrawHeld(key, held, actor);
    log.debug("Leaving Consent.revokeApplication(). ok.");
    return Object.assign({ ok: true, removed: held.length, dn: outcome.dn,
                           revoked: outcome.revoked,
                           withdrawnAt: outcome.at },
      { message: '"' + key + '" no longer consents anything for "' + who +
        '" (' + held.length + ' scope(s)). ' + self.revokedSentence(
          outcome.revoked) });
  }

  // THE COMMON TAIL OF revoke(), forget() and revokeApplication(): the
  // records off the entry, the instant on it, and the tokens revoked, per
  // application, in that order — the instant BEFORE the walk, so that a
  // refresh racing the walk on another node is already refused.
  private withdrawHeld(key: string,
                       held: Array<{ client: string; scope: string;
                                     raw: string }>,
                       actor?: string) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Consent.withdrawHeld(). " + held.length + ".");
    if (!this.directory) {
      log.debug("Leaving Consent.withdrawHeld(). No directory.");
      return { dn: '', revoked: 0, at: '' };
    }
    const noted = self.noteWithdrawn(key, held.map(function (one) {
      return { client: one.client, scope: one.scope };
    }));
    const removed = this.directory.removeConsent(key,
      held.map(function (one) {
        return one.raw;
      })) || {};
    const byClient: Record<string, string[]> = {};
    held.forEach(function (one) {
      (byClient[one.client] = byClient[one.client] || []).push(one.scope);
    });
    let revoked = 0;
    Object.keys(byClient).forEach(function (client) {
      revoked += self.revokeIssuedUnder({ username: key, clientId: client,
                                          scopes: byClient[client] },
        'consent withdrawn' + (actor && actor !== key ? ' by ' + actor
                                                       : ' by the person'));
    });
    log.debug("Leaving Consent.withdrawHeld(). " + revoked + " revoked.");
    return { dn: removed.dn || '', revoked: revoked, at: noted.at || '' };
  }

  // What a withdrawal did to what was already issued, in one sentence.
  revokedSentence(count: number): string {
    const { log } = this.deps;
    log.debug("Entering Consent.revokedSentence().");
    log.debug("Leaving Consent.revokedSentence().");
    return (count ? count + ' token(s) issued under it were revoked, '
                  : 'No live token had been issued under it; ') +
      'and every refresh token granted before now is refused at the token ' +
      'endpoint even if consent is given again.';
  }


  // ---------------------------------------------------------------------------
  // THE REGISTER, BOTH HALVES, FROM ONE WALK OF EACH CONTAINER.
  //
  // The same shape `app_permissions.ts`'s `register()` has and for the same
  // reason: the console page, `?format=json` and `GET /admin-api/consent` all
  // read this, so they cannot come to disagree about what is in it.
  // ---------------------------------------------------------------------------
  register() {
    const { log, applications } = this.deps;
    const self = this;
    log.debug("Entering Consent.register().");
    const globals = [];
    applications.list().forEach(function (row) {
      self.globalConsentsOf(row.identifier).forEach(function (scope) {
        const permission = applications.forPermission(scope);
        globals.push({
          client: row.identifier,
          clientName: row.name || row.identifier,
          scope: scope,
          // Whether this scope is a DEFINED delegated permission, and whose. A
          // global consent naming a permission no application defines is not an
          // error — the scope may be one a client simply asks for — so it is
          // reported rather than refused, exactly as a dangling grant is.
          permission: permission ? permission.name : '',
          resource: permission ? permission.identifier : '',
          // Whether the client has also been GRANTED it. The two are
          // independent and the difference is the interesting reading: a
          // consented permission the client does not hold is a person agreeing
          // to something the operator has not allowed, and in product mode —
          // or with `oauth2.delegatedPermissionsEnforced` on — it is refused
          // anyway.
          granted: permission ?
                   applications.holdsPermission(row.identifier, permission.id) :
                   false
        });
      });
    });

    const users = [];
    if (this.directory) {
      (this.directory.listConsents() || []).forEach(function (row) {
        (row.values || []).forEach(function (value) {
          const parsed = self.parseConsentValue(value);
          if (!parsed.scope) {
            // An `ldapmodify` can put anything in this attribute. It is SHOWN
            // rather than dropped, for the reason a dangling grant is shown: a
            // value the page silently ignored would be one somebody had written
            // on purpose and could not find out was being ignored.
            users.push({ username: row.username, dn: row.dn, scope: '',
                         client: '',
                         at: '', raw: value, unreadable: true });
            return;
          }
          users.push({ username: row.username, dn: row.dn, scope: parsed.scope,
                       client: parsed.client, at: parsed.at, raw: parsed.raw,
                       unreadable: false });
        });
      });
    }
    // Newest first, which is what a page about consents somebody just gave has
    // to show — the row you are looking for is the one you just made.
    users.sort(function (a, b) {
      return String(b.at).localeCompare(String(a.at));
    });

    const out = {
      required: self.required(),
      storable: self.storable(),
      attribute: USER_ATTRIBUTE,
      globalAttribute: GLOBAL_ATTRIBUTE,
      globals: globals,
      users: users,
      counts: {
        globals: globals.length,
        consents: users.length,
        people: users.reduce(function (acc, one) {
          return acc.indexOf(one.username) < 0 ?
            acc.concat([one.username]) : acc;
        }, []).length,
        unreadable: users.filter(function (one) {
          return one.unreadable;
        }).length
      }
    };
    log.debug("Leaving Consent.register(). " + out.counts.globals +
              " global, " + out.counts.consents + " recorded.");
    return out;
  }

  // What this feature is doing right now, for the console's own summary and for
  // `/admin-api/consent`. Separate from register() because a caller that wants
  // the state does not want a walk of two containers.
  state() {
    const { log } = this.deps;
    log.debug("Entering Consent.state().");
    const out = {
      required: this.required(),
      storable: this.storable(),
      attribute: USER_ATTRIBUTE,
      globalAttribute: GLOBAL_ATTRIBUTE,
      withdrawnAttribute: WITHDRAWN_ATTRIBUTE,
      globalWithdrawnAttribute: GLOBAL_WITHDRAWN_ATTRIBUTE,
      refreshRequiresConsent:
        !!this.deps.config.value('oauth2.refreshRequiresConsent'),
      settings: ['oauth2.consentRequired', 'oauth2.refreshRequiresConsent']
    };
    log.debug("Leaving Consent.state(). required=" + out.required);
    return out;
  }
}

const log = helpers.log;

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Consent>(
  'common/consent',
  () => new Consent(Consent.defaultDeps()),
  Consent.wire,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  Consent: Consent,
  installInstance: (instance: Consent): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  USER_ATTRIBUTE: USER_ATTRIBUTE,
  GLOBAL_ATTRIBUTE: GLOBAL_ATTRIBUTE,
  WITHDRAWN_ATTRIBUTE: WITHDRAWN_ATTRIBUTE,
  GLOBAL_WITHDRAWN_ATTRIBUTE: GLOBAL_WITHDRAWN_ATTRIBUTE,
  setDirectory: slot.forward('setDirectory'),
  directoryInstalled: slot.forward('directoryInstalled'),
  storable: slot.forward('storable'),
  required: slot.forward('required'),
  consentValueOf: slot.forward('consentValueOf'),
  parseConsentValue: slot.forward('parseConsentValue'),
  scopesOf: slot.forward('scopesOf'),
  identityOf: slot.forward('identityOf'),
  scopeProblem: slot.forward('scopeProblem'),
  globalConsentsOf: slot.forward('globalConsentsOf'),
  grantGlobal: slot.forward('grantGlobal'),
  revokeGlobal: slot.forward('revokeGlobal'),
  consentsOf: slot.forward('consentsOf'),
  outstanding: slot.forward('outstanding'),
  record: slot.forward('record'),
  revoke: slot.forward('revoke'),
  forget: slot.forward('forget'),
  revokeApplication: slot.forward('revokeApplication'),
  withdrawnStamp: slot.forward('withdrawnStamp'),
  stampMs: slot.forward('stampMs'),
  parseWithdrawalValue: slot.forward('parseWithdrawalValue'),
  withdrawalsOf: slot.forward('withdrawalsOf'),
  globalWithdrawalsOf: slot.forward('globalWithdrawalsOf'),
  noteWithdrawn: slot.forward('noteWithdrawn'),
  refreshRefusal: slot.forward('refreshRefusal'),
  revokeIssuedUnder: slot.forward('revokeIssuedUnder'),
  register: slot.forward('register'),
  state: slot.forward('state')
};
