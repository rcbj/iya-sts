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
// Since #700 the Overview also carries the realm's custom attributes whose
// definition shows them on the portal, and `POST /account-api/attributes`
// changes the caller's own values of one that definition lets them edit.
//
// **THE PERSON IS THE TOKEN'S SUBJECT** (`account-api/account_api.ts`) and no
// operation here takes a name: the entry read is the caller's, the
// applications asked about are the caller's, and the Shared Signals inbox —
// one stream about EVERYBODY in the realm — is narrowed to the caller on the
// way out, failing closed (`portal/CLAUDE.md`).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import Classes = require('../common/domain_classes');
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
// The one identity-provider-initiated sign-in link per application (#426).
import LaunchLinks = require('../common/launch_links');
import signals = require('../ssf/ssf_receivers');
import accountSignals = require('../ssf/account_signals');
import risc = require('../ssf/risc');
import validation = require('../common/validation');
import ProfilePhoto = require('../common/profile_photo');
import ModelZod = require('../common/model_zod');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountAnswering<K extends keyof IyaApi.Account.Operations> =
  import('../types/account-api').AccountAnswering<K>;
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
const PORTAL_QUERY = ModelZod.query('account', 'getOverview');

// `page` is an INTEGER through `vt.integer()`: a handler never parses a query
// string itself. The bound is generous; the view clamps to the last real
// page, which is what a bookmark to page 40 of a list that shrank should do.
const PAGED_QUERY = ModelZod.query('account', 'getApplications');

// THE LANGUAGE ON THE PERSON'S OWN ENTRY (#539). One field, the tag — empty
// for "use my browser's language", which removes the attribute.
const LANGUAGE_FORM = ModelZod.body('account', 'setLanguage');

// A PERSON'S OWN PROFILE PHOTO (#719): the file, base64-encoded. The browser
// has already cropped and scaled it, and the bytes are judged again here; 3 MiB
// of file is `profilePhoto.maxStoredBytes`' largest value, and four base64
// characters carry three bytes.
const PHOTO_FORM = ModelZod.body('account', 'setProfilePhoto');

// A PERSON'S OWN VALUES OF ONE CUSTOM ATTRIBUTE (#700): the attribute and
// the values it is to hold afterwards — every one, so an empty list (or no
// `values`) clears it. A form's boxes are each a `values`; an empty box is
// no value. At most 100, each the person editor's longest value.
const ATTRIBUTE_FORM = ModelZod.body('account', 'setCustomAttribute');

// THE ACCOUNT HOLDER'S RISC PARTICIPATION (#146): one of section 2.8's three
// moves a person may make. opt-out-effective is not among them — only the
// scheduler job makes that move, after risc.optOutDelayHours.
const PARTICIPATION_FORM = ModelZod.body('account', 'moveRiscParticipation');

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
  // The realm's custom attribute register (#700), reached when asked.
  attributePolicy(): Json;
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
      // LAZILY too (#700): the register is the directory's, and requiring
      // it here would run its load-time declarations at 8a.
      attributePolicy: function attributePolicy(): Json {
        helpers.log.debug("Entering attributePolicy().");
        helpers.log.debug("Leaving attributePolicy().");
        return require('../common/attribute_policy');
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
                acr: String(signOn.acr || ''),
                // Bound to a key this browser holds (#725). `fact` and
                // `reasons` are language-free (#743): skipped names the
                // tokens, and the page translates the sentence.
                deviceBound: {
                  bound: !!(signOn.deviceBound && signOn.deviceBound.bound),
                  alg: String((signOn.deviceBound &&
                               signOn.deviceBound.alg) || ''),
                  fact: String((signOn.deviceBound &&
                                signOn.deviceBound.fact) || 'none'),
                  reasons: Array.isArray(signOn.deviceBound &&
                                         signOn.deviceBound.reasons)
                    ? signOn.deviceBound.reasons.map(String) : [] } },
      sessionEnds: Number(caller.session.expires || 0),
      // HOW MANY TIMES THIS PROCESS HAS SEEN THEM AUTHENTICATE (#672).
      // `userDetail()` answers `{ user, tokens, artifacts }`, and the count
      // is `user.authentications` — the row `/admin/users` draws. From the
      // portal's first day (2026-09-06) until #672 this read
      // `detail.authentications`, a member that shape never had, so the page
      // said 0 for everybody while the console said the true figure; the
      // console's user page reads `detail.user`, which is why it was right.
      // `null` with no row, as before: the page then draws no figure rather
      // than a zero it cannot stand behind.
      timesSignedIn: detail && detail.user
        ? Number(detail.user.authentications || 0) : null,
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
      language: this.languageOf(entry),
      // #700: the realm's custom attributes this person may see, only
      // where they have an entry to hold them.
      customAttributes: entry ? this.customAttributesOf(entry) : [],
      // #719: the photo card, only for a person with an entry to hang it on.
      photo: entry ? ProfilePhoto.viewFor(username) : null
    };
    log.debug("Leaving AccountOverview.overview().");
    return view;
  }

  // ---------------------------------------------------------------------------
  // THE REALM'S CUSTOM ATTRIBUTES ON THE OVERVIEW (#700). Only a definition
  // whose `portalVisible` is TRUE is shown, which is OFF by default: what an
  // administrator defined for the directory is not thereby the person's to
  // read. Like the inetOrgPerson table, drawn from a LIST (the register) and
  // never by iterating the entry. `editable` is the definition's
  // `portalEditable`, which implies visible.
  // ---------------------------------------------------------------------------
  /**
   * The custom attributes the person sees, with their own values.
   *
   * @param entry - the person's entry
   * @returns `[{ name, label, description, syntax, multi, values, editable }]`
   */
  customAttributesOf(entry: Json): Json[] {
    const { log } = this.deps;
    log.debug("Entering AccountOverview.customAttributesOf().");
    let definitions: Json[] = [];
    try {
      definitions = this.deps.attributePolicy().definitions() || [];
    } catch (e) {
      // No register to read shows nothing extra; the page still draws.
      log.debug("Caught in AccountOverview.customAttributesOf(): " +
                ((e && e.message) || e));
      definitions = [];
    }
    const out = definitions.filter(function (one: Json): boolean {
      return !!one.portalVisible;
    }).map((one: Json): Json => {
      return { name: String(one.name), label: String(one.label || one.name),
               description: String(one.description || ''),
               syntax: String(one.syntax || 'string'), multi: !!one.multi,
               values: this.valuesOn(entry, one.name),
               editable: !!one.portalEditable };
    });
    log.debug("Leaving AccountOverview.customAttributesOf(). " + out.length);
    return out;
  }

  // One attribute's values on an entry, whichever case the store keys it by.
  private valuesOn(entry: Json, name: string): string[] {
    const { log } = this.deps;
    log.debug("Entering AccountOverview.valuesOn(). " + name);
    const attributes = (entry && entry.attributes) || {};
    const wanted = String(name || '').toLowerCase();
    const key = Object.keys(attributes).filter(function (one) {
      return one.toLowerCase() === wanted;
    })[0];
    const out = key ? [].concat(attributes[key]).map(String)
      .filter(function (one: string): boolean {
        return one !== '';
      }) : [];
    log.debug("Leaving AccountOverview.valuesOn(). " + out.length);
    return out;
  }

  // ---------------------------------------------------------------------------
  // POST: THE PERSON'S OWN VALUES OF ONE CUSTOM ATTRIBUTE (#700). Refused
  // unless the realm defines it (STS-PORTAL-0626), its definition shows it
  // on the portal (0627) and lets the person edit it (0628). The values are
  // checked against the definition by the person editor, and written through
  // it one edit at a time, as `setLanguage()` writes — so the editor's audit
  // row, its syntax check and the attribute policy's `editRefusal` all hold.
  //
  // **ADDS BEFORE REMOVES**, for a multi-valued attribute: a required value
  // may not be taken away (`editRefusal`), and replacing one value with
  // another by removing first would leave an empty moment the policy
  // refuses. Emptying it outright is asked of the policy BEFORE anything is
  // written, so a refusal changes nothing (STS-LDAP-0164, the editor's own
  // code for that refusal). A single-valued attribute is one `set`.
  // ---------------------------------------------------------------------------
  /**
   * Replaces the caller's own values of one custom attribute.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body: `attribute`, `values`
   * @returns nothing
   */
  setCustomAttribute(ctx: AccountContext,
                     res: AccountAnswering<'setCustomAttribute'>,
                     caller: AccountCaller,
                     body: Json): unknown {
    const { log } = this.deps;
    log.debug("Entering AccountOverview.setCustomAttribute().");
    const username = caller.username;
    const asked = String(body.attribute || '').trim();
    let policy: Json = null;
    let definition: Json = null;
    try {
      policy = this.deps.attributePolicy();
      definition = policy.definition(asked);
    } catch (e) {
      // No register: no custom attribute here, which is the refusal below.
      log.debug("Caught in AccountOverview.setCustomAttribute(): " +
                ((e && e.message) || e));
      definition = null;
    }
    if (!definition) {
      log.debug("Leaving AccountOverview.setCustomAttribute(). Undefined.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0626',
        'This realm has no custom attribute called "' + asked.slice(0, 64) +
        '", so nothing was changed.');
    }
    if (!definition.portalVisible) {
      log.debug("Leaving AccountOverview.setCustomAttribute(). Hidden.");
      return ctx.refuse(res, 403, 'STS-PORTAL-0627',
        definition.name + ' is not shown on this portal, so it is not ' +
        'changed here. Ask an administrator.');
    }
    if (!definition.portalEditable) {
      log.debug("Leaving AccountOverview.setCustomAttribute(). Read-only.");
      return ctx.refuse(res, 403, 'STS-PORTAL-0628',
        definition.name + ' is shown here but is not yours to change. Ask ' +
        'an administrator.');
    }
    const entry = this.deps.personEntry(username);
    if (!entry) {
      log.debug("Leaving AccountOverview.setCustomAttribute(). No entry.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0629',
        'You have no directory entry here to hold ' + definition.name + '.');
    }
    const sent = [].concat(body.values === undefined || body.values === null
      ? [] : body.values).map(function (one: Json): string {
      return String(one).trim();
    }).filter(Boolean);
    const editor = this.deps.personEditor();
    const checked = editor.checkCreateValues(definition.name, sent);
    if (!checked || checked.error) {
      log.debug("Leaving AccountOverview.setCustomAttribute(). Values.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0629',
        'Your ' + definition.label + ' was not changed: ' +
        (checked ? checked.error : definition.name + ' is not an attribute ' +
                   'the directory\'s editor changes.'));
    }
    const wanted: string[] = checked.values;
    const held = this.valuesOn(entry, definition.name);
    // A HOT PATH, run once per value compared: no Entering/Leaving pair,
    // which would drown the log in a line per value.
    const within = function (list: string[], one: string): boolean {
      return list.some(function (other: string): boolean {
        return other.toLowerCase() === one.toLowerCase();
      });
    };
    const adds = wanted.filter(function (one: string): boolean {
      return !within(held, one);
    });
    const removes = held.filter(function (one: string): boolean {
      return !within(wanted, one);
    });
    const t = ctx.translatorFor(username);
    const done = function (): unknown {
      log.debug("Entering done().");
      log.debug("Leaving done().");
      return ctx.json(res, 200, { ok: true, go: ctx.PORTAL,
                                  message: t.text('portal.done.attribute',
                                    { label: definition.label }) });
    };
    if (!adds.length && !removes.length) {
      log.debug("Leaving AccountOverview.setCustomAttribute(). Unchanged.");
      return done();
    }
    // EMPTYING IT IS ASKED FIRST, so a refusal leaves every value in place.
    const lower = definition.name.toLowerCase();
    const leaves = Object.assign({}, entry.attributes || {},
                                 { [lower]: wanted });
    const refusal = wanted.length ? null
      : policy.editRefusal({ [lower]: held }, { [lower]: wanted },
                           { uid: username, attributes: leaves });
    if (refusal) {
      log.debug("Leaving AccountOverview.setCustomAttribute(). Required.");
      return ctx.refuse(res, 400, 'STS-LDAP-0164',
        'Your ' + definition.label + ' was not changed: ' + refusal.message);
    }
    const edits: Json[] = definition.multi
      ? adds.map(function (one: string): Json {
        return { attribute: definition.name, mode: 'add', value: one };
      }).concat(removes.map(function (one: string): Json {
        return { attribute: definition.name, mode: 'remove', value: one };
      }))
      : [{ attribute: definition.name, mode: 'set',
           value: wanted.length ? wanted[0] : '' }];
    for (const edit of edits) {
      let written: Json = null;
      try {
        written = editor.update(username, edit,
                                { actor: username, via: 'the user portal' });
      } catch (e) {
        log.debug("Caught in AccountOverview.setCustomAttribute(): " +
                  ((e && e.message) || e));
        written = null;
      }
      if (!written || !written.ok) {
        const why = (written && (written.errors || []).join(' ')) ||
          'The directory could not be asked.';
        log.debug("Leaving AccountOverview.setCustomAttribute(). Not " +
                  "written.");
        return ctx.refuse(res, 400, ctx.errorCodes.codeOf(written) ||
                          'STS-PORTAL-0629',
                          'Your ' + definition.label + ' was not ' +
                          'changed: ' + why);
      }
    }
    log.debug("Leaving AccountOverview.setCustomAttribute(). " +
              adds.length + " added, " + removes.length + " removed.");
    return done();
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
    const held = Classes.User.fromEntry((entry && entry.attributes) || {})
      .preferredLanguage || '';
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
  async setPhoto(ctx: AccountContext, req: Json,
                 res: AccountAnswering<'setProfilePhoto'>,
                 caller: AccountCaller, body: Json): Promise<unknown> {
    const { log } = this.deps;
    log.debug("Entering AccountOverview.setPhoto().");
    const bytes = Buffer.from(String(body.image || ''), 'base64');
    const refused = await require('../common/malware_scan').refusal(bytes);
    if (refused) {
      log.debug("Leaving AccountOverview.setPhoto(). " + refused.code);
      // error-code: none — the scanner's own, STS-CORE-0168 or STS-CORE-0169
      return ctx.refuse(res, refused.status, refused.code, refused.error);
    }
    const done = ProfilePhoto.setOwn(req, caller.username, bytes);
    if (!done.ok) {
      log.debug("Leaving AccountOverview.setPhoto(). " + done.code);
      return ctx.refuse(res, done.status, done.code || 'STS-PORTAL-0633',
                        done.error);
    }
    const t = ctx.translatorFor(caller.username);
    log.debug("Leaving AccountOverview.setPhoto().");
    return ctx.json(res, 200, { ok: true, go: ctx.PORTAL, photo: done.path,
                                message: t.text('portal.done.photo') });
  }

  /**
   * Handles `POST /account-api/photo/remove`.
   *
   * @param ctx - the API's context
   * @param res - the response
   * @param caller - the token's person
   * @returns what the context's answer returns
   */
  removePhoto(ctx: AccountContext, res: AccountAnswering<'removeProfilePhoto'>,
              caller: AccountCaller): unknown {
    const { log } = this.deps;
    log.debug("Entering AccountOverview.removePhoto().");
    ProfilePhoto.removeOwn(caller.username);
    const t = ctx.translatorFor(caller.username);
    log.debug("Leaving AccountOverview.removePhoto().");
    return ctx.json(res, 200, { ok: true, go: ctx.PORTAL, photo: '',
                                message: t.text('portal.done.photoRemoved') });
  }

  setLanguage(ctx: AccountContext, res: AccountAnswering<'setLanguage'>,
              caller: AccountCaller,
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
        // THE PROTOCOLS A SIGN-IN CAN BE STARTED IN FROM HERE (#426): one the
        // policy permits, with identity-provider-initiated sign-in switched on
        // for this application, and with somewhere registered to send it.
        // Off by default, so most rows have none.
        launchable: self.launchableOf(one, permitted),
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

  // THE LAUNCHES A ROW OFFERS (#426, #713): /launch/{app}?protocol=…, the
  // one link per application the console shows too. OpenID Connect's is
  // Core section 4 (#120), which the portal linked straight to the client
  // until #426; it goes through the door now, which records the launch and
  // obeys the client's switch like the other three.
  /**
   * The protocols a permitted application can be launched in from the portal.
   *
   * @param one - the application's registry row
   * @param permitted - the sign-in families the policy permitted
   * @returns the protocol ids
   */
  launchableOf(one: Json, permitted: Json[]): string[] {
    const { log } = this.deps;
    log.debug("Entering AccountOverview.launchableOf().");
    const allowed = permitted.map(function (family: Json) {
      return family.protocol;
    });
    const out = LaunchLinks.protocolsOf(one).filter(function (row: Json) {
      return row.families.some(function (family: string) {
        return allowed.indexOf(family) >= 0;
      }) && LaunchLinks.enabled(one.identifier, row.id) &&
        !LaunchLinks.missingOf(one, row.id).length;
    }).map(function (row: Json) {
      return row.id;
    });
    log.debug("Leaving AccountOverview.launchableOf(). " + out.length);
    return out;
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
    const found = this.applicationsFor(caller.username);
    const pages = Math.max(1, Math.ceil(found.rows.length / PER_PAGE));
    const at = Math.min(Math.max(1, wanted || 1), pages);
    const shown = found.rows.slice((at - 1) * PER_PAGE, at * PER_PAGE)
      .map(function (row: Json): Json {
        return Object.assign({}, row, {
          launches: (row.launchable || []).map(function (id: string): Json {
            return { protocol: id, label: LaunchLinks.protocol(id).label,
                     url: LaunchLinks.launchUrl(base, row.identifier, id) };
          }) });
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
  async moveParticipation(ctx: AccountContext, req: Json,
                          res: AccountAnswering<'moveRiscParticipation'>,
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
        operationId: 'getOverview', access: 'person',
        query: PORTAL_QUERY,
        handler: function (req, res,
                           caller: AccountCaller): unknown {
          return ctx.json(res, 200, self.overview(caller));
        } },
      { method: 'POST', path: ctx.BASE + '/language',
        operationId: 'setLanguage', access: 'person',
        body: LANGUAGE_FORM,
        handler: function (req, res, caller: AccountCaller,
                           input): unknown {
          return self.setLanguage(ctx, res, caller, input.body);
        } },
      { method: 'POST', path: ctx.BASE + '/photo',
        operationId: 'setProfilePhoto', access: 'person',
        body: PHOTO_FORM,
        handler: function (req, res, caller: AccountCaller,
                           input): unknown {
          return self.setPhoto(ctx, req, res, caller, input.body);
        } },
      { method: 'POST', path: ctx.BASE + '/photo/remove',
        operationId: 'removeProfilePhoto', access: 'person',
        handler: function (req, res,
                           caller: AccountCaller): unknown {
          return self.removePhoto(ctx, res, caller);
        } },
      { method: 'POST', path: ctx.BASE + '/attributes',
        operationId: 'setCustomAttribute', access: 'person', body: ATTRIBUTE_FORM,
        handler: function (req, res, caller: AccountCaller,
                           input): unknown {
          return self.setCustomAttribute(ctx, res, caller, input.body);
        } },
      { method: 'GET', path: ctx.BASE + '/applications',
        operationId: 'getApplications', access: 'person', query: PAGED_QUERY,
        handler: function (req, res, caller: AccountCaller,
                           input): unknown {
          return ctx.json(res, 200, self.applicationsView(caller,
            Number(input.query.page || 1), ctx.baseUrlOf(req)));
        } },
      { method: 'GET', path: ctx.BASE + '/signals',
        operationId: 'getSecurityActivity', access: 'person', query: PAGED_QUERY,
        handler: function (req, res, caller: AccountCaller,
                           input): unknown {
          return ctx.json(res, 200, self.signalsView(caller,
            Number(input.query.page || 1)));
        } },
      { method: 'POST', path: ctx.BASE + '/signals',
        operationId: 'moveRiscParticipation', access: 'person', body: PARTICIPATION_FORM,
        handler: function (req, res, caller: AccountCaller,
                           input): unknown {
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
