// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_overview.ts
//
// ---------------------------------------------------------------------------
// THE PORTAL'S *YOUR ACCOUNT* PAGES AS `/account-api` OPERATIONS (#568): the
// Overview (`/portal`), the language on the person's own entry, the
// applications they can sign in to (`/portal/applications`) and their
// security activity (`/portal/signals`).
//
// Moved from `portal.ts` when the portal became a static application; the
// pages are drawn in the browser by `web_overview.ts`. Each view carries
// what its page showed and nothing it did not — the reasoning about what
// each page shows is kept below beside the code that builds it.
//
// **THE PERSON IS THE TOKEN'S SUBJECT** (`account-api/account_api.ts`) and no
// operation here takes a name: the entry read is the caller's, the
// applications asked about are the caller's, and the Shared Signals inbox —
// one stream about EVERYBODY in the realm — is narrowed to the caller on the
// way out, failing closed (`portal/CLAUDE.md`).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import credentials = require('../common/credentials');
import inetOrgPerson = require('../common/inetorgperson');
import authn = require('../authn/authn');
import realms = require('../common/realms');
import i18n = require('../common/i18n');
import PageLocale = require('../common/page_locale');
import stats = require('../common/admin_stats');
import applications = require('../common/applications');
import gate = require('../common/issuance_gate');
import signals = require('../ssf/ssf_receivers');
import accountSignals = require('../ssf/account_signals');
import risc = require('../ssf/risc');
import validation = require('../common/validation');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

// THE FIVE FAMILIES THAT ARE A SIGN-IN DESTINATION, each with the issuance
// kind the gate is asked about and what it would issue. A sign-in
// destination is something this identity provider signs a person into in a
// browser, which is the question the Applications page asks. SSF receivers,
// SCIM clients, LDAP binders, SPIFFE workloads, OID4VP verifiers and mutual-
// TLS clients are not sign-in destinations at all. Everything left out is
// counted at the foot of the page rather than dropped silently.
const SIGN_IN_FAMILIES = [
  { protocol: 'oidc', kind: gate.ISSUANCE.ID_TOKEN, how: 'an ID Token' },
  { protocol: 'oauth2', kind: gate.ISSUANCE.ACCESS_TOKEN,
    how: 'an access token' },
  { protocol: 'saml2', kind: gate.ISSUANCE.SAML_ASSERTION,
    how: 'a SAML 2.0 assertion' },
  { protocol: 'saml11', kind: gate.ISSUANCE.SAML_ASSERTION,
    how: 'a SAML 1.1 assertion' },
  { protocol: 'wsfed', kind: gate.ISSUANCE.WSFED_TOKEN,
    how: 'a WS-Federation token' }
];

// How many entries the Applications page will evaluate by default: each
// costs one policy evaluation per distinct issuance kind, on the thread that
// answers every socket. `portal.applicationScanLimit` (2026-09-12), read per
// request, is the setting; the page says when it bites.
const SCAN_LIMIT = 1000;

// Rows per page: a list that draws every row stops working at some size and
// gives no sign of approaching it.
const PER_PAGE = 20;

// `done` is accepted and ignored: an old bookmark carrying one still draws.
const PORTAL_QUERY = vz.object({
  done: vz.string().max(200).optional()
});

// `page` is an INTEGER through `vt.integer()`: a handler never parses a query
// string itself. The bound is generous; the view clamps to the last real
// page, which is what a bookmark to page 40 of a list that shrank should do.
const PAGED_QUERY = vz.object({
  done: vz.string().max(200).optional(),
  page: vt.opt(vt.integer(1, 100000))
    .describe('The page of the list, 1 for the first.')
});

// THE LANGUAGE ON THE PERSON'S OWN ENTRY (#539). One field, the tag — empty
// for "use my browser's language", which removes the attribute.
const LANGUAGE_FORM = vz.object({
  lang: vz.string().max(64).optional()
    .describe('A BCP 47 tag this service has a catalog for, or empty to ' +
              'follow the browser.')
});

// THE ACCOUNT HOLDER'S RISC PARTICIPATION (#146): one of section 2.8's three
// moves a person may make. opt-out-effective is not among them — only the
// scheduler job makes that move, after risc.optOutDelayHours.
const PARTICIPATION_FORM = vz.object({
  move: vz.enum(['optOutInitiated', 'optOutCancelled', 'optIn']).optional()
    .describe('The move: start opting out, cancel that, or opt back in.')
});

interface AccountOverviewDeps {
  log: typeof helpers.log;
  config: typeof config;
  credentials: typeof credentials;
  inetOrgPerson: typeof inetOrgPerson;
  authn: typeof authn;
  realms: typeof realms;
  stats: typeof stats;
  applications: typeof applications;
  gate: typeof gate;
  signals: typeof signals;
  accountSignals: typeof accountSignals;
  risc: typeof risc;
  // The person's own entry, through the portal's directory slot.
  personEntry(username: string): Json;
  // The editor that writes `preferredLanguage`, reached when it is written.
  personEditor(): Json;
  // The realm's OAuth issuer, for OpenID Connect Core section 4's `iss`.
  issuerFor(base: string): string;
}

/**
 * The *Your account* pages' account API operations.
 */
class AccountOverview {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountOverviewDeps) {
    deps.log.debug("Entering AccountOverview.constructor().");
    deps.log.debug("Leaving AccountOverview.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountOverviewDeps {
    helpers.log.debug("Entering AccountOverview.defaultDeps().");
    helpers.log.debug("Leaving AccountOverview.defaultDeps().");
    return {
      log: helpers.log, config: config, credentials: credentials,
      inetOrgPerson: inetOrgPerson, authn: authn, realms: realms,
      stats: stats, applications: applications, gate: gate,
      signals: signals, accountSignals: accountSignals, risc: risc,
      // LAZILY, all three: `portal.ts` is built at 8a beside this module,
      // and the person editor and the issuer's module are the directory's
      // and the authorization server's, built later.
      personEntry: function personEntry(username: string): Json {
        helpers.log.debug("Entering personEntry().");
        helpers.log.debug("Leaving personEntry().");
        return require('./portal').personEntry(username);
      },
      personEditor: function personEditor(): Json {
        helpers.log.debug("Entering personEditor().");
        helpers.log.debug("Leaving personEditor().");
        return require('../ldap/person_editor');
      },
      issuerFor: function issuerFor(base: string): string {
        helpers.log.debug("Entering issuerFor().");
        helpers.log.debug("Leaving issuerFor().");
        return require('../oauth-oidc/jwt_access_token').issuerFor(base);
      }
    };
  }

  // ---------------------------------------------------------------------------
  // THE OVERVIEW: who the person is, this session, a summary of how they
  // sign in, their language, and the wider sign-out. A SUMMARY of the
  // password and the keys with a link to each — "have I got a password, and
  // is a second factor turned on" is the first thing somebody wants from an
  // account page and the last thing they want to hunt for.
  //
  // EVERY STANDARD inetOrgPerson ATTRIBUTE (2026-09-11), DRAWN FROM A FIXED
  // LIST AND NEVER BY ITERATING THE ENTRY: an entry carries whatever anybody
  // put on it, this service's credentials among them. `inetorgperson.ts`'s
  // `describe()` is the list and refuses `userPassword` and the binary
  // attributes itself (`rowFor()`), so this view carries only what that list
  // allows. With no directory, or no entry, the view says which by carrying
  // `directory: null` and the session's own two facts.
  // ---------------------------------------------------------------------------
  /**
   * The Overview's view.
   *
   * @param caller - the signed-in person
   * @returns the view
   */
  overview(caller: AccountCaller): Json {
    const { log, credentials, inetOrgPerson, authn, stats } = this.deps;
    log.debug("Entering AccountOverview.overview().");
    const username = caller.username;
    const mechanisms: Json = credentials.mechanismsFor(username) || {};
    const detail: Json = stats.userDetail ? stats.userDetail(username) : null;
    const entry = this.deps.personEntry(username);
    // THE SIGN-ON SESSION'S account of how this person is signed in: a
    // step-up since the token was issued is on it and nowhere else.
    const signOn: Json = authn.signOnFactsFor(caller.signOn || {});
    const user = caller.session.user || {};
    const backup = mechanisms.backupCodes || {};
    const view: Json = {
      username: username,
      sub: caller.sub,
      entry: entry ? { dn: String(entry.dn || '') } : null,
      // WHAT THE SIGN-IN CARRIED, drawn only where there is no entry: with a
      // directory they are `mail` and `cn` in the attribute table.
      session: { email: String(user.email || ''),
                 name: String(user.name || '') },
      signOn: { startedAt: Number(signOn.startedAt || 0),
                authTime: Number(signOn.authTime || 0),
                authentications: Number(signOn.authentications || 0),
                amr: (signOn.amr || []).slice(0),
                acr: String(signOn.acr || '') },
      sessionEnds: Number(caller.session.expires || 0),
      timesSignedIn: detail ? Number(detail.authentications || 0) : null,
      directory: entry ? inetOrgPerson.describe(entry.attributes) : null,
      mechanisms: {
        password: !!mechanisms.password,
        keys: (mechanisms.keys || []).length,
        totp: !!mechanisms.totp,
        totpUsable: !!mechanisms.totpUsable,
        mfaRequired: !!mechanisms.mfaRequired,
        secondFactor: String(mechanisms.secondFactor || ''),
        backupCodes: { present: !!backup.present, usable: !!backup.usable,
                       remaining: Number(backup.remaining || 0),
                       total: Number(backup.total || 0) }
      },
      language: this.languageOf(entry)
    };
    log.debug("Leaving AccountOverview.overview().");
    return view;
  }

  // THE LANGUAGE ON THE PERSON'S OWN ACCOUNT (#539): `preferredLanguage`
  // (RFC 2798 section 2.7) on their own entry, which ranks above the
  // chooser's cookie and the browser. The card is where a person READS what
  // their account says and can take it off again — "Use my browser's
  // language" removes the attribute, which the chooser cannot do. The
  // locales are `i18n.offered()`, each by its own name.
  /**
   * What the entry's `preferredLanguage` holds, and what may be chosen.
   *
   * @param entry - the person's entry, or null
   * @returns `{ held, offered }`
   */
  languageOf(entry: Json): Json {
    const { log } = this.deps;
    log.debug("Entering AccountOverview.languageOf().");
    const attributes = (entry && entry.attributes) || {};
    const key = Object.keys(attributes).filter(function (one) {
      return one.toLowerCase() === 'preferredlanguage';
    })[0];
    const held = key ? String([].concat(attributes[key])[0] || '') : '';
    log.debug("Leaving AccountOverview.languageOf(). " + (held || 'none'));
    return { held: held, offered: i18n.offered().map(function (one: Json) {
      return { tag: String(one.tag), name: String(one.name) };
    }) };
  }

  // ---------------------------------------------------------------------------
  // POST: THE LANGUAGE (#539). A tag no catalog answers is refused with an
  // English reason (errors stay English, rcbj's decision on #539); the cookie
  // the chooser would have set is set as well, so the page the runtime draws
  // next is in the language just chosen.
  // ---------------------------------------------------------------------------
  /**
   * Writes or removes the caller's own `preferredLanguage`.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  setLanguage(ctx: AccountContext, res: Json, caller: AccountCaller,
              body: Json): unknown {
    const { log } = this.deps;
    log.debug("Entering AccountOverview.setLanguage().");
    const username = caller.username;
    const asked = String(body.lang || '').trim();
    const tag = asked ? i18n.canonical(asked) : '';
    if (asked && (!tag || !i18n.answers(tag))) {
      log.debug("Leaving AccountOverview.setLanguage(). Not offered.");
      return ctx.refuse(res, 400, 'STS-I18N-0008',
        '"' + asked.slice(0, 64) + '" is not a language this service has ' +
        'a catalog for, so your language was not changed.');
    }
    // What the entry holds now: a removal names the value it removes.
    const held = this.languageOf(this.deps.personEntry(username)).held;
    const done = function (): unknown {
      const t = ctx.translatorFor(username);
      return ctx.json(res, 200, { ok: true, go: ctx.PORTAL,
                                  message: t.text('portal.done.language') });
    };
    if (!tag && !held) {
      log.debug("Leaving AccountOverview.setLanguage(). Nothing to remove.");
      return done();
    }
    let written: Json = null;
    try {
      written = this.deps.personEditor().update(username,
        tag ? { attribute: 'preferredLanguage', mode: 'set', value: tag }
            : { attribute: 'preferredLanguage', mode: 'remove', value: held },
        { actor: username, via: 'the user portal' });
    } catch (e) {
      log.debug("Caught in AccountOverview.setLanguage(): " +
                ((e && e.message) || e));
      written = null;
    }
    if (!written || !written.ok) {
      const why = (written && (written.errors || []).join(' ')) ||
        'The directory could not be asked.';
      log.debug("Leaving AccountOverview.setLanguage(). Not written.");
      return ctx.refuse(res, 400, ctx.errorCodes.codeOf(written) ||
                        'STS-I18N-0009',
                        'Your language was not changed: ' + why);
    }
    if (tag) {
      res.append('Set-Cookie', PageLocale.cookieLine(tag));
    }
    log.debug("Leaving AccountOverview.setLanguage(). " + (tag || 'removed'));
    return done();
  }

  // ---------------------------------------------------------------------------
  // APPLICATIONS: WHERE THIS IDENTITY PROVIDER WILL SIGN THE PERSON IN —
  // decided by the SAME `common/issuance_gate.js` call the issuance sites
  // make, as a DRY RUN (`preview: true`), so this page and those endpoints
  // cannot disagree, and a refusal here is not an event.
  //
  // Asked once per application per distinct issuance KIND (SAML 2.0 and 1.1
  // are one kind), because the kind becomes the XACML action-id. An
  // application is listed if ANY of its kinds is permitted, and the row says
  // which were withheld. DECLARED and OBSERVED families both count.
  // ---------------------------------------------------------------------------
  /**
   * The entries the page evaluates at most.
   *
   * @returns the limit
   */
  scanLimit(): number {
    const { log, config } = this.deps;
    log.debug("Entering AccountOverview.scanLimit().");
    const n = Number(config.value('portal.applicationScanLimit'));
    log.debug("Leaving AccountOverview.scanLimit().");
    return isFinite(n) && n > 0 ? Math.floor(n) : SCAN_LIMIT;
  }

  /**
   * Which of the five families an entry is a sign-in destination in.
   *
   * @param row - the application's registry row
   * @returns the families
   */
  signInFamiliesOf(row: Json): Json[] {
    const { log } = this.deps;
    log.debug("Entering AccountOverview.signInFamiliesOf().");
    const declared = row.allowedProtocols || [];
    const recorded = row.recordedProtocols || [];
    log.debug("Leaving AccountOverview.signInFamiliesOf().");
    return SIGN_IN_FAMILIES.filter(function (family) {
      return declared.indexOf(family.protocol) >= 0 ||
             recorded.indexOf(family.protocol) >= 0;
    });
  }

  /**
   * Every application the person may be signed in to, and the counts of
   * those left out.
   *
   * @param username - the signed-in person
   * @returns `{ rows, refused, notSignIn, scanned, total, truncated, limit }`
   */
  applicationsFor(username: string): Json {
    const { log, applications, gate } = this.deps;
    const self = this;
    log.debug("Entering AccountOverview.applicationsFor().");
    const all: Json[] = applications.list();
    const limit = this.scanLimit();
    const scanned = all.slice(0, limit);
    const rows: Json[] = [];
    let refused = 0;
    let notSignIn = 0;
    const labelOf = function (family: Json): string {
      const detail: Json = applications.protocolRow(family.protocol);
      return detail ? detail.label : family.protocol;
    };
    scanned.forEach(function (one: Json) {
      const families = self.signInFamiliesOf(one);
      if (!families.length) {
        notSignIn++;
        return;
      }
      const answers: Json = {};
      families.forEach(function (family) {
        if (Object.prototype.hasOwnProperty.call(answers, family.kind)) {
          return;
        }
        answers[family.kind] = gate.check({
          application: one.identifier, kind: family.kind,
          subject: { kind: 'user', name: username, authenticated: true },
          // THE DRY RUN: nothing is being issued.
          preview: true
        });
      });
      const permitted = families.filter(function (family) {
        return answers[family.kind].allowed;
      });
      if (!permitted.length) {
        refused++;
        return;
      }
      rows.push({
        identifier: one.identifier,
        name: one.name || one.identifier,
        // WHERE TO GO, or '' — `applications.homePageOf()` is the one reader
        // of `appHomePageUrl` and the one place the http/https rule applies.
        homePage: applications.homePageOf(one),
        // OpenID Connect Core section 4's `initiate_login_uri`, or '' (#120).
        initiateLogin: applications.initiateLoginUriOf(one),
        description: one.description || '',
        families: permitted.map(labelOf),
        ways: permitted.map(function (family) {
          return family.how;
        }).filter(function (how, at, list) {
          return list.indexOf(how) === at;
        }),
        // The families the policy did NOT permit, so a row that is half open
        // says so rather than reading as fully open.
        withheld: families.filter(function (family) {
          return !answers[family.kind].allowed;
        }).map(labelOf)
      });
    });
    // ALPHABETICAL, not the registry's last-seen order, which reshuffles
    // between page loads for reasons that have nothing to do with the reader.
    rows.sort(function (a, b) {
      return a.name.toLowerCase().localeCompare(b.name.toLowerCase()) ||
             a.identifier.localeCompare(b.identifier);
    });
    log.debug("Leaving AccountOverview.applicationsFor(). " + rows.length +
              " permitted, " + refused + " refused, " + notSignIn +
              " not sign-in destinations.");
    return { rows: rows, refused: refused, notSignIn: notSignIn,
             scanned: scanned.length, total: all.length,
             truncated: all.length > scanned.length, limit: limit };
  }

  // THE ONE LAUNCH THERE IS: OPENID CONNECT CORE SECTION 4 (#120). A relying
  // party that REGISTERED `initiate_login_uri` asked for a third party to
  // start its sign-in: a GET there with `iss` (this realm's issuer) and
  // `login_hint` (the person, who chose to click), and Enterprise Extensions
  // section 4's `tenant`, `domain_hint` and `target_link_uri` (#148).
  /**
   * The section 4 launch address for a row, or ''.
   *
   * @param row - the row
   * @param issuer - this realm's issuer, or ''
   * @param username - the signed-in person
   * @returns the URL, or ''
   */
  initiateLoginUrl(row: Json, issuer: string, username: string): string {
    const { log, realms } = this.deps;
    log.debug("Entering AccountOverview.initiateLoginUrl().");
    if (!row.initiateLogin || !issuer) {
      log.debug("Leaving AccountOverview.initiateLoginUrl(). None.");
      return '';
    }
    const url = new URL(row.initiateLogin);
    url.searchParams.set('iss', issuer);
    url.searchParams.set('login_hint', username);
    url.searchParams.set('tenant', String(realms.current().id));
    const domain = String(realms.domainOf(realms.current()) || '');
    if (domain) {
      url.searchParams.set('domain_hint', domain);
    }
    if (/^https:\/\//i.test(String(row.homePage || ''))) {
      url.searchParams.set('target_link_uri', String(row.homePage));
    }
    log.debug("Leaving AccountOverview.initiateLoginUrl().");
    return url.toString();
  }

  /**
   * The Applications page's view: one page of the rows, and the counts.
   *
   * @param caller - the signed-in person
   * @param wanted - the page asked for
   * @param base - this realm's base URL
   * @returns the view
   */
  applicationsView(caller: AccountCaller, wanted: number,
                   base: string): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AccountOverview.applicationsView().");
    let issuer = '';
    try {
      issuer = base ? this.deps.issuerFor(base) : '';
    } catch (e) {
      log.debug("Caught in AccountOverview.applicationsView(): " +
                ((e && e.message) || e));
      // No issuer: no section 4 link is drawn.
      issuer = '';
    }
    const found = this.applicationsFor(caller.username);
    const pages = Math.max(1, Math.ceil(found.rows.length / PER_PAGE));
    const at = Math.min(Math.max(1, wanted || 1), pages);
    const shown = found.rows.slice((at - 1) * PER_PAGE, at * PER_PAGE)
      .map(function (row: Json): Json {
        return Object.assign({}, row, {
          launch: self.initiateLoginUrl(row, issuer, caller.username) });
      });
    log.debug("Leaving AccountOverview.applicationsView(). Page " + at +
              ".");
    return { rows: shown, page: at, pages: pages, refused: found.refused,
             notSignIn: found.notSignIn, scanned: found.scanned,
             total: found.total, truncated: found.truncated,
             limit: found.limit };
  }

  // ---------------------------------------------------------------------------
  // YOUR SECURITY ACTIVITY — THIS PORTAL AS A SHARED SIGNALS RECEIVER
  // (2026-09-10). One stream delivers every CAEP and RISC event in the realm
  // to this portal, so the narrowing happens on the way OUT — `view(...,
  // { person })` — and the person is composed from the TOKEN and nothing
  // else. The filter FAILS CLOSED (`isAbout()`): showing one person another
  // person's account lockout is a disclosure. **THERE IS NO CONTROL ON THE
  // LIST**: a person cannot erase the record of what was said about their
  // own account; Clear is the console's.
  // ---------------------------------------------------------------------------
  /**
   * What a person is, for "is this event about me": the username, the
   * subject, and the address the sign-in carried.
   *
   * @param caller - the signed-in person
   * @returns `{ username, sub, mail }`
   */
  personOf(caller: AccountCaller): Json {
    const { log } = this.deps;
    log.debug("Entering AccountOverview.personOf().");
    log.debug("Leaving AccountOverview.personOf().");
    return { username: caller.username, sub: caller.sub,
             mail: String((caller.session.user || {}).email || '') };
  }

  // WHETHER SECURITY EVENTS ABOUT THIS ACCOUNT ARE SHARED (#146, RISC 1.0
  // section 2.8), which the specification makes the account holder's choice.
  // Opting out is not immediate — the delay exists so somebody who has just
  // taken an account over cannot silence the events that would report them —
  // and only the moves the state diagram allows from here are offered. A
  // SERVICE ACCOUNT (#221) has no holder to choose, and `why` says so.
  /**
   * The RISC participation card's state, or null while RISC is off.
   *
   * @param username - the signed-in person
   * @returns `{ applies, why, state, since, hours, moves }`, or null
   */
  participation(username: string): Json {
    const { log, risc, config } = this.deps;
    log.debug("Entering AccountOverview.participation().");
    if (!risc.enabled()) {
      log.debug("Leaving AccountOverview.participation(). RISC is off.");
      return null;
    }
    const now: Json = risc.optOutOf(username);
    log.debug("Leaving AccountOverview.participation(). " + now.state);
    return { applies: now.applies !== false, why: String(now.why || ''),
             state: String(now.state || ''), since: now.since || '',
             hours: Number(config.value('risc.optOutDelayHours')),
             moves: (now.moves || []).slice(0) };
  }

  /**
   * The Security activity page's view.
   *
   * @param caller - the signed-in person
   * @param wanted - the page asked for
   * @returns the view
   */
  signalsView(caller: AccountCaller, wanted: number): Json {
    const { log, signals } = this.deps;
    log.debug("Entering AccountOverview.signalsView().");
    const view: Json = signals.view(signals.PORTAL,
                                    { person: this.personOf(caller) });
    const st: Json = view.status || {};
    const rows: Json[] = view.received || [];
    const pages = Math.max(1, Math.ceil(rows.length / PER_PAGE));
    const at = Math.min(Math.max(1, wanted || 1), pages);
    const shown = rows.slice((at - 1) * PER_PAGE, at * PER_PAGE)
      .map(function (row: Json): Json {
        return { at: row.at, name: row.name, vocabulary: row.vocabulary,
                 type: (row.types || [])[0] || '',
                 payload: row.payload || {}, verified: !!row.verified,
                 verificationNote: row.verificationNote || '',
                 reactions: (row.reactions || []).map(function (r: Json) {
                   return { failed: !!r.failed, skipped: r.skipped || '',
                            observed: !!r.observed,
                            ended: Number(r.ended || 0) };
                 }) };
      });
    log.debug("Leaving AccountOverview.signalsView(). " + shown.length +
              " of " + rows.length + " shown.");
    return { incomplete: !!(st.why && st.why.length), rows: shown,
             page: at, pages: pages,
             participation: this.participation(caller.username) };
  }

  /**
   * Moves the caller's RISC participation (#146).
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  async moveParticipation(ctx: AccountContext, req: Json, res: Json,
                          caller: AccountCaller, body: Json):
      Promise<unknown> {
    const { log, risc, accountSignals } = this.deps;
    log.debug("Entering AccountOverview.moveParticipation().");
    const username = caller.username;
    const move = String(body.move || '');
    if (!risc.enabled() || !risc.optOutMoveAllowed(username, move)) {
      const held: Json = risc.enabled() ? risc.optOutOf(username) : null;
      log.debug("Leaving AccountOverview.moveParticipation(). Not a move " +
                "from here.");
      return ctx.refuse(res, 409, 'STS-PORTAL-0075',
        held && held.applies === false ? String(held.why || '')
          : 'That is not a change your account can make now: it is ' +
            (held ? held.state : 'not taking part') + '.');
    }
    const before = risc.optOutOf(username).state;
    await accountSignals.optOutMoved({ username: username, act: move,
      via: 'portal',
      reasonAdmin: username + ' changed their RISC participation on the ' +
                   'portal.' });
    const after = risc.optOutOf(username).state;
    if (after === before) {
      // Nothing recorded it — Shared Signals is off in this process, so
      // there is no register to move and no receiver to tell.
      log.warn(ctx.errorCodes.tag('STS-PORTAL-0076') + 'portal: ' +
               username + '\'s RISC ' + move + ' was not recorded.');
      log.debug("Leaving AccountOverview.moveParticipation(). Not recorded.");
      return ctx.refuse(res, 503, 'STS-PORTAL-0076',
        'Your choice could not be recorded: this service is not sending ' +
        'security events at the moment.');
    }
    ctx.audit.record({
      category: 'signals', action: 'portal.risc.' + move,
      actor: username, outcome: 'success',
      summary: username + ' moved their RISC participation from ' + before +
               ' to ' + after,
      detail: { address: ctx.websecurity.addressOf(req) }
    });
    const t = ctx.translatorFor(username);
    log.debug("Leaving AccountOverview.moveParticipation(). " + before +
              " -> " + after + ".");
    return ctx.json(res, 200, { ok: true,
      message: after === 'opt-out-initiated'
        ? t.text('portal.done.riscStopping')
        : (after === 'opt-in' ? t.text('portal.done.riscShared')
                              : t.text('portal.done.done')) });
  }

  /**
   * The operations, for `account-api/account_api.ts`.
   *
   * @param ctx - the account API's helpers
   * @returns the operations
   */
  accountOperations(ctx: AccountContext): AccountOperation[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AccountOverview.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/overview',
        operationId: 'getOverview', tag: 'Overview', access: 'person',
        mirrors: 'GET ' + ctx.PORTAL,
        summary: 'Who you are, this session, and how you sign in',
        description: 'Your username, subject and directory entry\'s DN; ' +
          'when the sign-on session began, how it authenticated (amr, acr) ' +
          'and when it ends; every standard inetOrgPerson attribute your ' +
          'entry holds, from a fixed list (`directory`, null with no ' +
          'directory or no entry — then `session` carries what the sign-in ' +
          'said); a summary of your credentials (`mechanisms`); and the ' +
          'language your entry holds with those offered (`language`).',
        query: PORTAL_QUERY,
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          return ctx.json(res, 200, self.overview(caller));
        } },
      { method: 'POST', path: ctx.BASE + '/language',
        operationId: 'setLanguage', tag: 'Overview', access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/language',
        summary: 'Sets or removes your preferred language',
        description: 'Writes `preferredLanguage` on your own entry (RFC ' +
          '2798), which ranks above the browser for every page this ' +
          'service draws for you, and sets the language cookie; an empty ' +
          '`lang` removes it and follows the browser. A tag no catalog ' +
          'answers is refused.',
        body: LANGUAGE_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.setLanguage(ctx, res, caller, input.body);
        } },
      { method: 'GET', path: ctx.BASE + '/applications',
        operationId: 'getApplications', tag: 'Applications',
        access: 'person', mirrors: 'GET ' + ctx.PORTAL + '/applications',
        summary: 'The applications you can be signed in to',
        description: 'Every registered application that is a sign-in ' +
          'destination (OpenID Connect, OAuth 2.0, SAML 2.0, SAML 1.1, ' +
          'WS-Federation) for which the issuance policy, asked as a dry ' +
          'run, permits you at least one family — its home page, its ' +
          'OpenID Connect section 4 launch address (`launch`), the ' +
          'families permitted and withheld. Twenty to a page; the counts ' +
          'of those refused and not evaluated are carried too.',
        query: PAGED_QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return ctx.json(res, 200, self.applicationsView(caller,
            Number(input.query.page || 1), ctx.baseUrlOf(req)));
        } },
      { method: 'GET', path: ctx.BASE + '/signals',
        operationId: 'getSecurityActivity', tag: 'Security activity',
        access: 'person', mirrors: 'GET ' + ctx.PORTAL + '/signals',
        summary: 'The security events this portal was told about you',
        description: 'The CAEP and RISC events this portal received as a ' +
          'Shared Signals receiver that are about you (an event it cannot ' +
          'tie to you is left out), twenty to a page, each with whether ' +
          'its signature verified and what this portal did with it; and ' +
          'whether events about your account are shared (RISC section ' +
          '2.8, `participation`, null while RISC is off).',
        query: PAGED_QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return ctx.json(res, 200, self.signalsView(caller,
            Number(input.query.page || 1)));
        } },
      { method: 'POST', path: ctx.BASE + '/signals',
        operationId: 'moveRiscParticipation', tag: 'Security activity',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/signals',
        summary: 'Stops, cancels stopping, or resumes sharing security ' +
          'events about you',
        description: 'RISC 1.0 section 2.8\'s account-holder moves. ' +
          'Opting out takes effect only after risc.optOutDelayHours, and ' +
          'can be cancelled until then.',
        body: PARTICIPATION_FORM,
        statuses: { 409: 'That move is not one your account can make now.',
                    503: 'Shared Signals is off, so nothing was recorded.' },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.moveParticipation(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving AccountOverview.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<AccountOverview>(
  'portal/account_overview',
  () => new AccountOverview(AccountOverview.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The *Your account* pages' account API operations (#568).
 * @namespace
 */
export = {
  AccountOverview: AccountOverview,
  installInstance: (instance: AccountOverview): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
