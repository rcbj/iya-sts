// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: consumer_providers.ts
//
// ===========================================================================
// CONSUMER AND SOCIAL IDENTITY PROVIDERS AS PROFILES (#565, 2026-10-19).
//
// A consumer provider — Google, Discord, GitHub — is a FEDERATION
// RELATIONSHIP like any other: an `oidc` or `oauth2` relationship on the
// service-provider side, verified, linked, decided by `subjectDecision()`,
// provisioned and signed in through the same funnel. What makes it a
// consumer one is `fedProvider`, which names a PROFILE in this file, and the
// category is DERIVED from it (`categoryOf()`): a relationship with a
// provider is consumer, one without is enterprise. There is no second
// attribute to disagree with the first.
//
// A PROFILE SAYS TWO KINDS OF THING, AND THEY ARE USED AT TWO DIFFERENT
// TIMES (rcbj's decisions on #565):
//
//   * **`defaults`** — the provider's endpoints, issuer, scope and token
//     authentication — are WRITTEN ONTO THE ENTRY when the relationship is
//     created (`apply()`), and are ordinary attributes from then on: visible
//     on the relationship's page, editable, and the only place a dialled URL
//     comes from. So `federation_http.ts`'s argument (*those URLs are
//     supplied by the ADMINISTRATOR*) is untouched: a profile is a form
//     filled in for the administrator, not a source of URLs at sign-in.
//
//   * **The extraction rules** — WHERE the subject, the email, its
//     verification and every profile claim come from — are READ LIVE from
//     the profile at sign-in (`extract()`), never copied onto the entry.
//     Some of these providers depart from OpenID Connect in ways only their
//     own documentation describes (a subject called `id`, an address on a
//     second endpoint, a "verified" flag of their own), and the rule for a
//     provider is a fact about that provider, so it is fixed in ONE place
//     and every relationship of it takes the correction.
//
// A RULE IS `source:path`. The sources are what a sign-in has in hand:
//
//   | source         | what it is                                             |
//   |----------------|--------------------------------------------------------|
//   | `id_token`     | the verified ID Token's payload (OpenID Connect)       |
//   | `access_token` | a verified JWT access token's payload                  |
//   | `token`        | the token endpoint's JSON response itself               |
//   | `userinfo`     | what `fedUserinfoUrl` answered                         |
//   | `emails`       | what `fedEmailsUrl` answered (GitHub's `/user/emails`)  |
//
// and the path is dotted (`data.id`), a number indexes an array, and
// `@primary` selects the first element of an array whose `primary` is true.
//
// WHAT A PROFILE PRODUCES IS A CLAIM BAG, AND NOTHING ELSE. The bag is the
// raw scalar members of the profile's primary source, with the profile's
// NAMED claims written over them in OpenID Connect's vocabulary (`email`,
// `name`, `preferred_username` …). From there the bag goes through
// `federation_map.ts` exactly as an enterprise partner's does — the
// relationship's `fedAttributeMap`, the default table, the reserved-target
// rule (#94) — into the directory entry, and from the entry into whatever
// this service issues. A provider's own member (GitHub's `company`) arrives
// as itself, is listed under *Sent and not written* until somebody maps it,
// and is one form field away from being written. Nothing provider-specific
// reaches an application.
//
// A NAMED CLAIM IS AUTHORITATIVE, EVEN WHEN IT FINDS NOTHING. GitHub's
// `/user` carries an `email` member that is the person's PUBLIC address —
// unverified and chosen for display — while the address that is theirs is
// on `/user/emails`. The profile names `email` from `emails`, so when that
// call fails the raw `email` is REMOVED rather than left behind: a profile
// that says where a claim comes from must not let the same name arrive from
// somewhere it said not to look.
//
// AN EMAIL IS UNVERIFIED UNLESS THE PROFILE SAYS WHERE IT IS VERIFIED
// (decision 8). Each profile names its statement (`email_verified`,
// Discord's `verified`, GitHub's `primary && verified`); a profile with
// none, or a statement that is absent or anything but true, produces
// `email_verified: false`, which `FederationSp.partnerDisownsMail()` already
// honours. The address is still written — it is what the person gave — and
// an unverified one opens no flow that needs a verified address (#64).
//
// THE PROVIDER'S OWN MFA CLAIM SATISFIES NOTHING UNLESS THE PROFILE TRUSTS
// IT (decision 2 of the risk design). `mfa` on a profile is the rule and the
// values it must carry; none of the first three providers asserts one this
// service could rely on, so none has a rule, and the claim is still carried
// on the event behind `federated` by `federatedAmr()`.
//
// THE ADAPTERS ARE A CLOSED SET (rcbj). What a source and a path cannot say
// — a client secret that is a JWT the relying party signs, a form field that
// arrives once, a parameter renamed, an issuer that varies per tenant — is a
// named adapter, implemented where the flow is, and a profile lists the ones
// it needs. `github-verified-email` is the only one the first three need.
//
// WHY NO PROVIDER'S OWN LIBRARY IS USED (rcbj's rule, 2026-10-19: an
// existing TypeScript module first, then JavaScript, the provider's own
// over anybody else's, and our own code only where nothing else serves —
// and beware modules written for an application EMBEDDING the provider,
// which this platform is not). Each candidate for the first three was read
// against what a federation relationship here must keep:
//
//   | Provider | Candidate (publisher)                      | Why it is not used |
//   |----------|--------------------------------------------|--------------------|
//   | Google   | `google-auth-library` (Google, TypeScript) | it dials Google's certificate and token endpoints itself, over its own HTTP stack (gaxios), and verifies ID Tokens with its own crypto — so neither `federation_http.ts`'s outbound policy (the kill switch, https with the CA file, no redirect, the body cap, product's internal-address refusal) nor `common/crypto.js`, the one place this service verifies, would govern a Google sign-in; and it carries `gcp-metadata`, its application-default-credentials probe, into a process that holds no Google credential |
//   | GitHub   | `@octokit/oauth-methods`, `@octokit/request` (GitHub, TypeScript) | built for an app holding its own token: requests go to URLs it composes, through its own fetch, outside the outbound policy; its code exchange (6.0.5's `exchangeWebFlowCode()`) takes no PKCE verifier, which this service always sends |
//   | Discord  | none published by Discord; `discord-oauth2`, `discord.js` (community) | a community wrapper around the same three requests, for a bot or an app storing the person's tokens, which decision 7 refuses |
//
// What each would have contributed is the request shapes, and those are a
// profile's dozen lines. The flow itself — state, PKCE, the code exchange,
// the ID Token checks, revocation of the signer — is already this
// service's, under the invariants every relationship keeps. A provider
// whose protocol needs more than a profile and an adapter can say (a
// client secret that is a JWT, a signed notification) is asked the same
// question again when it is built.
//
// A LEAF: it requires the helpers and nothing of this service's own, so
// `federation.js` (a library the sign-in screen reads) and `federation_sp.ts`
// may both require it.
// ===========================================================================

import helpers = require('../common/helpers');

type Json = any;

/** Where a value is read from at sign-in. */
type Source = 'id_token' | 'access_token' | 'token' | 'userinfo' | 'emails';

/** One extraction rule: a source and a dotted path within it. */
interface Rule {
  source: Source;
  path: string;
}

/** A consumer identity provider's profile. */
interface Profile {
  /** The value of `fedProvider`. */
  id: string;
  /** What to call it on a page and on a sign-in button. */
  label: string;
  /** The relationship's protocol. */
  protocol: 'oidc' | 'oauth2';
  /** A profile for a provider outside the catalogue. */
  generic: boolean;
  /** The provider's developer documentation. */
  docs: string;
  /** Written onto the entry at creation (`apply()`). */
  defaults: Record<string, string>;
  /** Fields the profile needs beyond the protocol's `needs`. */
  needs: string[];
  /** The source whose raw scalar members form the bag. */
  primary: Source;
  /** The subject (`source:path`), or null for the protocol's own rule. */
  subject: string | null;
  /** Claims, in OpenID Connect's vocabulary, each a `source:path`. */
  claims: Record<string, string>;
  /** Where `email_verified` is read, or null: never verified. */
  emailVerified: string | null;
  /** A trusted MFA statement, or null: the provider's satisfies nothing. */
  mfa: { rule: string; values: string[] } | null;
  /** Issuer spellings accepted beside `fedPeer` (Google's bare host). */
  issuerAliases: string[];
  /** The named adapters this profile needs. */
  adapters: string[];
  /** One line for the console: what the provider is, and its catch. */
  note: string;
}

/** The named adapters, a closed set (rcbj, #565). */
const ADAPTERS = ['github-verified-email'];

// ---------------------------------------------------------------------------
// THE CATALOGUE. The first three are rcbj's (Discord among them, 2026-10-19)
// and they are the three shapes every later profile is one of: OpenID
// Connect with nothing unusual (Google), plain OAuth 2.0 with one profile
// endpoint (Discord), and plain OAuth 2.0 with the address on a second one
// (GitHub). The endpoint values are each provider's published ones; the
// feasibility record for every platform the ticket names is
// `docs/federation-consumer-providers.md`.
// ---------------------------------------------------------------------------
const PROFILES: Profile[] = [
  { id: 'google', label: 'Google', protocol: 'oidc', generic: false,
    docs: 'https://developers.google.com/identity/openid-connect/' +
          'openid-connect',
    defaults: {
      fedSsoUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      fedTokenUrl: 'https://oauth2.googleapis.com/token',
      fedJwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
      fedPeer: 'https://accounts.google.com',
      fedScope: 'openid email profile',
      fedTokenAuth: 'client_secret_basic'
    },
    needs: ['fedClientSecret'],
    primary: 'id_token',
    subject: 'id_token:sub',
    claims: {
      email: 'id_token:email',
      name: 'id_token:name',
      given_name: 'id_token:given_name',
      family_name: 'id_token:family_name',
      picture: 'id_token:picture',
      locale: 'id_token:locale'
    },
    emailVerified: 'id_token:email_verified',
    mfa: null,
    // Google's own page: "The value of iss in the ID token is equal to
    // accounts.google.com or https://accounts.google.com."
    issuerAliases: ['accounts.google.com'],
    adapters: [],
    note: 'OpenID Connect. The ID Token names the person; email_verified ' +
          'is Google\'s statement, and hd names a Workspace domain.' },
  { id: 'discord', label: 'Discord', protocol: 'oauth2', generic: false,
    docs: 'https://discord.com/developers/docs/topics/oauth2',
    defaults: {
      fedSsoUrl: 'https://discord.com/oauth2/authorize',
      fedTokenUrl: 'https://discord.com/api/oauth2/token',
      fedUserinfoUrl: 'https://discord.com/api/users/@me',
      fedPeer: 'https://discord.com',
      fedScope: 'identify email',
      fedTokenAuth: 'client_secret_basic'
    },
    needs: ['fedClientSecret', 'fedUserinfoUrl'],
    primary: 'userinfo',
    subject: 'userinfo:id',
    claims: {
      preferred_username: 'userinfo:username',
      name: 'userinfo:global_name',
      email: 'userinfo:email',
      locale: 'userinfo:locale'
    },
    // Discord's user object: "verified — whether the email on this account
    // has been verified". `mfa_enabled` says the ACCOUNT has two factors,
    // not that this sign-in used them, so it is no MFA statement.
    emailVerified: 'userinfo:verified',
    mfa: null,
    issuerAliases: [],
    adapters: [],
    note: 'OAuth 2.0 with no ID Token. The person is /users/@me: the id is ' +
          'the subject, and verified is Discord\'s statement about the ' +
          'address.' },
  { id: 'github', label: 'GitHub', protocol: 'oauth2', generic: false,
    docs: 'https://docs.github.com/en/apps/oauth-apps/building-oauth-apps',
    defaults: {
      fedSsoUrl: 'https://github.com/login/oauth/authorize',
      fedTokenUrl: 'https://github.com/login/oauth/access_token',
      fedUserinfoUrl: 'https://api.github.com/user',
      fedEmailsUrl: 'https://api.github.com/user/emails',
      fedPeer: 'https://github.com',
      fedScope: 'read:user user:email',
      fedTokenAuth: 'client_secret_post'
    },
    needs: ['fedClientSecret', 'fedUserinfoUrl'],
    primary: 'userinfo',
    // The numeric id, never `login`: a login can be renamed and then taken
    // by somebody else, which is OpenID Connect Core section 5.7's warning
    // about preferred_username in another form.
    subject: 'userinfo:id',
    claims: {
      preferred_username: 'userinfo:login',
      name: 'userinfo:name',
      picture: 'userinfo:avatar_url',
      profile: 'userinfo:html_url',
      email: 'emails:@primary.email'
    },
    emailVerified: 'emails:@primary.verified',
    mfa: null,
    issuerAliases: [],
    adapters: ['github-verified-email'],
    note: 'OAuth 2.0 with no ID Token. The person is /user; the address is ' +
          'the primary one on /user/emails, verified only where GitHub says ' +
          'so — /user\'s own email is the public one and is not used.' },
  { id: 'generic-oidc', label: 'Another OpenID Connect provider',
    protocol: 'oidc', generic: true, docs: '',
    defaults: { fedScope: 'openid profile email' },
    needs: [],
    primary: 'id_token',
    subject: null,
    claims: {},
    emailVerified: 'id_token:email_verified',
    mfa: null, issuerAliases: [], adapters: [],
    note: 'A consumer provider outside the catalogue that speaks OpenID ' +
          'Connect. Configured by hand, like an enterprise one.' },
  { id: 'generic-oauth2', label: 'Another OAuth 2.0 provider',
    protocol: 'oauth2', generic: true, docs: '',
    defaults: {},
    needs: ['fedUserinfoUrl'],
    primary: 'userinfo',
    subject: null,
    claims: {},
    emailVerified: 'userinfo:email_verified',
    mfa: null, issuerAliases: [], adapters: [],
    note: 'A consumer provider outside the catalogue with a profile ' +
          'endpoint. fedSubjectClaim names its subject where it is not sub.' }
];

/**
 * The consumer identity provider profiles, and the reading of a sign-in
 * through one. A static utility class over a fixed catalogue.
 */
export = class ConsumerProviders {
  /** The named adapters, a closed set. */
  static readonly ADAPTERS = ADAPTERS;

  /** The provider ids, in catalogue order. */
  static ids(): string[] {
    helpers.log.debug("Entering ConsumerProviders.ids().");
    helpers.log.debug("Leaving ConsumerProviders.ids().");
    return PROFILES.map(function (p) {
      return p.id;
    });
  }

  /**
   * The profile a `fedProvider` value names.
   *
   * @param id - the value
   * @returns the profile, or null for an unknown or empty one
   */
  static profileFor(id: unknown): Profile | null {
    helpers.log.debug("Entering ConsumerProviders.profileFor().");
    const wanted = String(id || '').trim();
    const found = PROFILES.filter(function (p) {
      return p.id === wanted;
    })[0] || null;
    helpers.log.debug("Leaving ConsumerProviders.profileFor().");
    return found;
  }

  /**
   * Whether a relationship is a consumer one: it names a provider.
   *
   * @param record - the relationship
   * @returns consumer or enterprise
   */
  static categoryOf(record: Json): 'consumer' | 'enterprise' {
    helpers.log.debug("Entering ConsumerProviders.categoryOf().");
    helpers.log.debug("Leaving ConsumerProviders.categoryOf().");
    return record && String(record.fedProvider || '').trim()
      ? 'consumer' : 'enterprise';
  }

  /**
   * The catalogue as the console and `/admin-api` describe it: what each
   * provider is, its protocol and the redirect it needs registered. No
   * extraction rule is a secret, so the whole profile is answered.
   *
   * @returns one row per provider
   */
  static catalogue(): Json[] {
    helpers.log.debug("Entering ConsumerProviders.catalogue().");
    const rows = PROFILES.map(function (p) {
      return { id: p.id, label: p.label, protocol: p.protocol,
               generic: p.generic, docs: p.docs, note: p.note,
               defaults: Object.assign({}, p.defaults),
               needs: p.needs.slice(), adapters: p.adapters.slice(),
               subject: p.subject || '',
               emailVerified: p.emailVerified || '',
               claims: Object.keys(p.claims).map(function (name) {
                 return name + '=' + p.claims[name];
               }) };
    });
    helpers.log.debug("Leaving ConsumerProviders.catalogue().");
    return rows;
  }

  /**
   * Writes a profile's defaults onto a relationship being created. A value
   * the caller gave wins, so an administrator can create a Google
   * relationship with a different scope in one act; the protocol is the
   * profile's and is checked by the caller.
   *
   * @param record - the relationship being created (changed in place)
   * @param profile - the profile
   * @param given - what the caller asked for
   */
  static apply(record: Json, profile: Profile, given: Json): void {
    helpers.log.debug("Entering ConsumerProviders.apply(). " + profile.id);
    const asked = given || {};
    record.fedProvider = profile.id;
    Object.keys(profile.defaults).forEach(function (name) {
      const mine = String(asked[name] == null ? '' : asked[name]).trim();
      record[name] = mine || profile.defaults[name];
    });
    helpers.log.debug("Leaving ConsumerProviders.apply().");
  }

  /**
   * The sources a sign-in through this profile has to fetch beyond what
   * the protocol already did: `emails` is the only one, and only where the
   * profile names it.
   *
   * @param profile - the profile, or null
   * @param source - the source asked about
   * @returns whether a rule of the profile reads it
   */
  static reads(profile: Profile | null, source: Source): boolean {
    helpers.log.debug("Entering ConsumerProviders.reads(). " + source);
    if (!profile) {
      helpers.log.debug("Leaving ConsumerProviders.reads(). No profile.");
      return false;
    }
    const rules: string[] = Object.keys(profile.claims).map(function (n) {
      return profile.claims[n];
    });
    if (profile.subject) rules.push(profile.subject);
    if (profile.emailVerified) rules.push(profile.emailVerified);
    if (profile.mfa) rules.push(profile.mfa.rule);
    helpers.log.debug("Leaving ConsumerProviders.reads().");
    return rules.some(function (r) {
      return ConsumerProviders.ruleOf(r).source === source;
    });
  }

  /**
   * The issuers a verified token from this relationship may name: `fedPeer`
   * and the profile's aliases.
   *
   * @param record - the relationship
   * @returns the list, or the one value where there are no aliases
   */
  static issuersFor(record: Json): string | string[] | undefined {
    helpers.log.debug("Entering ConsumerProviders.issuersFor().");
    const peer = String((record && record.fedPeer) || '');
    const profile = ConsumerProviders.profileFor(record && record.fedProvider);
    if (!peer) {
      helpers.log.debug("Leaving ConsumerProviders.issuersFor(). No peer.");
      return undefined;
    }
    // An alias is a spelling of the PROVIDER's own issuer, so it is
    // accepted only while `fedPeer` is still the profile's: a relationship
    // pointed somewhere else has no business accepting Google's bare host.
    if (!profile || !profile.issuerAliases.length ||
        peer !== profile.defaults.fedPeer) {
      helpers.log.debug("Leaving ConsumerProviders.issuersFor().");
      return peer;
    }
    helpers.log.debug("Leaving ConsumerProviders.issuersFor(). Aliases.");
    return [peer].concat(profile.issuerAliases);
  }

  /**
   * Splits a `source:path` rule.
   *
   * @param text - the rule
   * @returns its source and path
   */
  static ruleOf(text: string): Rule {
    helpers.log.debug("Entering ConsumerProviders.ruleOf().");
    const at = String(text).indexOf(':');
    helpers.log.debug("Leaving ConsumerProviders.ruleOf().");
    return { source: String(text).slice(0, at) as Source,
             path: String(text).slice(at + 1) };
  }

  /**
   * Reads one dotted path out of a value. A number indexes an array and
   * `@primary` selects the first element whose `primary` is true.
   *
   * @param value - the value
   * @param path - the path
   * @returns what is there, or undefined
   */
  static readPath(value: unknown, path: string): unknown {
    helpers.log.debug("Entering ConsumerProviders.readPath(). " + path);
    let at: unknown = value;
    const steps = String(path || '').split('.').filter(function (s) {
      return s !== '';
    });
    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      if (at == null || typeof at !== 'object') {
        helpers.log.debug("Leaving ConsumerProviders.readPath(). Absent.");
        return undefined;
      }
      if (step === '@primary') {
        at = Array.isArray(at)
          ? at.filter(function (one) {
            return one && typeof one === 'object' && one.primary === true;
          })[0]
          : undefined;
        continue;
      }
      if (Array.isArray(at)) {
        at = /^\d+$/.test(step) ? at[Number(step)] : undefined;
        continue;
      }
      // An own member only: a path is configuration, and `__proto__` or
      // `constructor` must never walk out of the parsed JSON.
      at = Object.prototype.hasOwnProperty.call(at, step)
        ? (at as Json)[step] : undefined;
    }
    helpers.log.debug("Leaving ConsumerProviders.readPath().");
    return at;
  }

  /**
   * Whether a `source:path` rule is one this module can read, for a value
   * an administrator writes (`fedSubjectClaim`).
   *
   * @param text - the value
   * @returns null, or why not
   */
  static pathProblem(text: unknown): string | null {
    helpers.log.debug("Entering ConsumerProviders.pathProblem().");
    const value = String(text == null ? '' : text).trim();
    if (!/^[A-Za-z0-9_@-]+(\.[A-Za-z0-9_@-]+)*$/.test(value)) {
      helpers.log.debug("Leaving ConsumerProviders.pathProblem(). Shape.");
      return 'a path is member names separated by dots, such as id or ' +
             'data.id';
    }
    if (value.split('.').some(function (s) {
      return s === '__proto__' || s === 'constructor' || s === 'prototype';
    })) {
      helpers.log.debug("Leaving ConsumerProviders.pathProblem(). Proto.");
      return 'a path may not name __proto__, constructor or prototype';
    }
    helpers.log.debug("Leaving ConsumerProviders.pathProblem().");
    return null;
  }

  /**
   * Reads a sign-in through a profile: the subject, the claim bag and the
   * email's verification, from the sources the sign-in has in hand.
   *
   * @param profile - the profile
   * @param sources - `id_token`, `access_token`, `token`, `userinfo` and
   *   `emails`, each the parsed value or undefined
   * @param bag - the bag the protocol branch already built from the
   *   primary source (the ID Token's or the profile endpoint's members,
   *   less the protocol's own); it is the base and is not changed
   * @returns `{ subject, bag, mfa }`, where `subject` is '' when the
   *   profile's rule found nothing and `mfa` is the trusted MFA values or []
   */
  static extract(profile: Profile, sources: Json, bag: Json): Json {
    const { log } = helpers;
    log.debug("Entering ConsumerProviders.extract(). " + profile.id);
    const read = function (text: string): unknown {
      log.debug("Entering read(). " + text);
      const r = ConsumerProviders.ruleOf(text);
      log.debug("Leaving read().");
      return ConsumerProviders.readPath(sources ? sources[r.source] : undefined,
                                        r.path);
    };
    const out: Json = {};
    Object.keys(bag || {}).forEach(function (name) {
      out[name] = bag[name];
    });
    // The named claims, authoritative even where they find nothing: see the
    // header (GitHub's public `email`).
    Object.keys(profile.claims).forEach(function (name) {
      const value = read(profile.claims[name]);
      if (value === undefined || value === null || value === '' ||
          typeof value === 'object') {
        delete out[name];
        return;
      }
      out[name] = typeof value === 'string' ? value : String(value);
    });
    // Unverified unless the profile's statement says true (decision 8).
    const said = profile.emailVerified ? read(profile.emailVerified)
                                       : undefined;
    out.email_verified = said === true || said === 'true';
    let subject = '';
    if (profile.subject) {
      const value = read(profile.subject);
      subject = (typeof value === 'string' || typeof value === 'number')
        ? String(value) : '';
    }
    let mfa: string[] = [];
    if (profile.mfa) {
      const claimed = read(profile.mfa.rule);
      const values = (Array.isArray(claimed) ? claimed : [claimed])
        .map(function (v) {
          return String(v == null ? '' : v);
        });
      const wanted = profile.mfa.values;
      mfa = values.filter(function (v) {
        return wanted.indexOf(v) >= 0;
      });
    }
    log.debug("Leaving ConsumerProviders.extract(). subject " +
              (subject ? 'found' : 'not found') + ', email ' +
              (out.email_verified ? 'verified' : 'unverified') + '.');
    return { subject: subject, bag: out, mfa: mfa };
  }
};
