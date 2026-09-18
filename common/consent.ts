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
// no cycle and moves no route.
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

// The attribute a person's agreement is written into, and the one an operator's
// override is written into. Named here rather than spelled at each call site so
// that `ldap_server.js`'s canonical-name table, the console, the management API
// and the two writers below cannot come to disagree about the capitalisation —
// which is a real failure mode in a directory that lower-cases its keys and
// shows them back canonically.
const USER_ATTRIBUTE = 'oauthConsent';
const GLOBAL_ATTRIBUTE = 'oauthGlobalConsent';

// The directory slot: four functions, validated whole.
interface ConsentDirectory {
  consentsOf(key: string): { values?: string[] } | null | undefined;
  addConsent(key: string, values: string[]):
    { ok?: boolean; dn?: string; reason?: string } | null | undefined;
  removeConsent(key: string, values: string[]):
    { dn?: string } | null | undefined;
  listConsents():
    Array<{ username: string; dn: string; values?: string[] }> |
    null | undefined;
}

// What a consent needs from the rest of the service.
interface ConsentDeps {
  log: typeof helpers.log;
  config: typeof config;
  applications: typeof applications;
  errorCodes: typeof errorCodes;
  stats: typeof stats;
}

// A GeneralizedTime stamp's exact shape — see `parseConsentValue()`.
const CONSENT_STAMP = /^\d{14}Z$/;

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
      stats: stats
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
  // Four functions, and it is validated WHOLE for `setLogoutReader()`'s reason:
  // a filler that installed the two READS and neither WRITE would leave a
  // service that draws the consent screen, records nothing, and draws it again
  // on the next request — a loop with a button in it, and every part of it
  // working.
  // ---------------------------------------------------------------------------
  setDirectory(hooks: ConsentDirectory | null | undefined): boolean {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Consent.setDirectory().");
    const needed = ['consentsOf', 'addConsent', 'removeConsent',
                    'listConsents'];
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
  required() {
    const { log, config } = this.deps;
    log.debug("Entering Consent.required().");
    log.debug("Leaving Consent.required().");
    return !!config.value('oauth2.consentRequired');
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

  revokeGlobal(clientId, scope, actor?) {
    const { log, applications } = this.deps;
    log.debug("Entering Consent.revokeGlobal(). clientId=" + clientId);
    const who = String(clientId == null ? '' : clientId).trim();
    const leaf = String(scope == null ? '' : scope).trim();
    const result = applications.updateApplication(who, {
      attribute: GLOBAL_ATTRIBUTE, mode: 'remove', value: leaf,
      actor: String(actor || '')
    });
    if (!result.ok) {
      log.debug("Leaving Consent.revokeGlobal(). Refused.");
      return result;
    }
    log.debug("Leaving Consent.revokeGlobal(). ok.");
    return Object.assign({}, result, {
      message: '"' + who + '" no longer consents <code>' + leaf +
        '</code> for everybody. The next person to sign in asking for it ' +
        'is PROMPTED — ' +
        'including anybody who was covered by this override, because an ' +
        'override records nothing about the people it covered. Somebody who ' +
        'agreed to it personally, before or after, still has that on their ' +
        'entry and is not asked.'
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
    const global = self.globalConsentsOf(clientId);
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
    const removed = this.directory.removeConsent(key,
      held.map(function (one) {
        return one.raw;
      })) || {};
    log.info('consent: "' + key + '" no longer consents "' + leaf + '" for "' +
             who + '". They are asked again the next time that application ' +
             'requests it.');
    log.debug("Leaving Consent.revoke(). ok.");
    return { ok: true, removed: held.length, dn: removed.dn || '',
             message: '"' + key + '" no longer consents <code>' + leaf +
               '</code> for "' + who + '". The next authorization request ' +
               'from that application naming that scope draws the consent ' +
               'screen again. Nothing already ISSUED was touched — an access ' +
               'token minted before this is still valid, exactly as a ' +
               'revoked delegated permission does not re-judge a grant ' +
               'already made.' };
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
    const removed = this.directory.removeConsent(key,
      held.map(function (one) {
        return one.raw;
      })) || {};
    log.info('consent: every consent "' + key + '" had agreed to (' +
             held.length +
             ') was forgotten. They are asked again by every application.');
    log.debug("Leaving Consent.forget(). " + held.length + " removed.");
    return { ok: true, removed: held.length, dn: removed.dn || '',
             message: held.length + ' consent(s) were removed from "' + key +
               '". ' +
               'Every application that asks them for a scope now draws the ' +
               'consent screen again — except for the scopes under GLOBAL ' +
               'consent, which were never on their entry to begin with.' };
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
          // to something the operator has not allowed, and with
          // `oauth2.delegatedPermissionsEnforced` on it is refused anyway.
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
      settings: ['oauth2.consentRequired']
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
  register: slot.forward('register'),
  state: slot.forward('state')
};
