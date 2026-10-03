// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_ownership.ts
//
// ===========================================================================
// WHO OWNS THE RESOURCE AN ACCESS RIGHT NAMES (#432 phase 5, 2026-10-03).
//
// RFC 9635 section 8's `identifier` names "a specific resource at the RS" —
// one account, one photo album, one mailbox. Until #432 nothing asked whose
// it was: any person signed in at the approval page could approve access to
// any identifier, which made the page a way for one person to hand out
// another's resource. Section 1.4 is plain that the resource owner is the
// one who authorizes access to a resource; a person who does not own it is
// not its resource owner, whatever the client says.
//
// **THE OWNER COMES FROM THE RESOURCE SERVER**, because the resource server
// is the only party that knows, and in one of two ways:
//
//   * ON A REGISTERED RESOURCE SET (RFC 9767 section 3.4). A registration may
//     carry `resource_owners`, an object from an identifier in the set's
//     `access` to the DN of a person or a group in the realm's directory —
//     this service's extension member, refused when it names an identifier
//     the set does not carry or a DN that is not a person or a group here
//     (`gnap_rs.ts`'s `register()`). The newest registration that names an
//     owner for an identifier is the one read.
//   * BY A LOOKUP THE RESOURCE SERVER DECLARES: `gnapOwnerLookupUri` on its
//     application entry, an https URL template holding `{identifier}` once,
//     in its path. The identifier is percent-encoded into that one path
//     segment, the request goes through `federation_http.fetchPublished()`
//     (the outbound policy: https with the certificate verified, internal
//     addresses refused in product mode, no redirect, a timeout, a body
//     cap), and the answer is `{ "owner": "<DN>" }` — or 404 for "nobody
//     owns this", which is an answer and not a failure.
//
// **THE LOOKUP IS A URL A CALLER CAN INFLUENCE, AND ONLY BY THE IDENTIFIER.**
// The root CLAUDE.md's index of dialled URLs is the argument this follows:
// the scheme, host, port and the rest of the path are the ADMINISTRATOR'S,
// written on the resource server's entry and checked when written
// (`applications.js`'s `ownerLookupUriProblem()`); the client chooses only
// the identifier, which can reach no other host and — percent-encoded, `/`
// and `..` included — no other path segment. The answer is read for one
// member and nothing it says is dialled.
//
// **A LOOKUP THAT CANNOT BE ANSWERED IS NOT "NO OWNER".** A resource server
// that declared a lookup said its identifiers have owners; a timeout or a
// 500 is `unresolved`, and the built-in issuance policy refuses the right
// (STS-GNAP-0863) rather than treating the silence as permission.
//
// **CACHED BRIEFLY**, per realm and per (resource server, identifier), for
// `gnap.ownerLookupCacheS` — a grant asks the same question at its request,
// on its approval page and at issue, and a failure is never cached. Ejected
// by the scheduler's `caches.eject-expired` job, bounded at the insert.
//
// **MATCHING.** A person owns what names their own entry, or a group they are
// a member of (directly — the membership the console rosters read). `facts()`
// is what the issue-gnap-right question carries (`ownerKnown`, `owner`,
// `ownerMatches`, `ownerUnresolved`), and the built-in rule refusing a
// mismatch is policy (`xacml_templates.ts`), so a realm can allow a
// delegate or require more. The approval page asks `refusalFor()` before it
// draws, `gnap_interact.ts`.
//
// A LIBRARY (rule 3): no route. The lookups are made ahead of the
// synchronous policy question by `prefetch()`, which every caller of
// `gnap_rights.judge()` awaits first.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import cacheRegistry = require('../common/cache_registry');
import applications = require('../common/applications');
import InstanceSlot = require('../common/instance_slot');
import store = require('./gnap_store');

type Json = any;

// The attribute a resource server declares its lookup in.
const LOOKUP_ATTRIBUTE = 'gnapOwnerLookupUri';
// The most owners a realm's cache holds, and the most bytes an answer may be.
const MAX_CACHED_OWNERS = 1024;
const MAX_ANSWER_BYTES = 16384;
// The most lookups one prefetch makes: a request names a bounded number of
// rights, and this is the bound on what it can make this service dial.
const MAX_LOOKUPS_PER_PREFETCH = 16;

// rs \0 identifier -> { owner, until }
const owners = realms.map();

cacheRegistry.register({
  name: 'gnap.owner-lookups',
  title: 'Resource owners looked up',
  description: 'The owner a resource server\'s gnapOwnerLookupUri named ' +
    'for an identifier, so a grant\'s request, approval page and issue ' +
    'ask the resource server once (#432 phase 5).',
  owner: 'gnap/gnap_ownership.ts',
  scope: 'realm',
  settings: ['gnap.ownerLookupCacheS'],
  maxEntries: function (): number {
    return MAX_CACHED_OWNERS;
  },
  bound: 'Enforced: ' + MAX_CACHED_OWNERS + ' owners per realm, the ' +
    'oldest dropped and looked up again when next needed.',
  lifetime: function (): string {
    return 'gnap.ownerLookupCacheS (' +
      Number(config.value('gnap.ownerLookupCacheS')) + ' s) after the ' +
      'lookup; a failed lookup is never held.';
  },
  eject: cacheRegistry.realmMapEjector(realms, owners,
    function (held: Json): boolean {
      return !(held && Number(held.until) > Date.now());
    }),
  entries: function (): Json[] {
    return cacheRegistry.realmRows(
      realms.list().map(function (r: Json): string {
        return r.id;
      }),
      function (id: string): Json {
        return owners.realmMap(id);
      },
      function (held: Json, key: string): Json {
        return { key: cacheRegistry.clipKey(key), validUntil: held.until };
      });
  }
});
const counter = cacheRegistry.counter('gnap.owner-lookups');

interface GnapOwnershipDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  errorCodes: typeof errorCodes;
  applications: Json;
  store: Json;
  nowMs(): number;
  // The directory's facts about a person or a DN — `credentials.ts`'s
  // `delegationFactsFor()`, required lazily: the credential store is
  // installed long after this module loads.
  directoryFacts(key: string): Json;
  // `federation_http.fetchPublished()`, lazily, for the same reason.
  fetchPublished(url: string, options: Json): Promise<Json>;
}

/**
 * Who owns the resource a GNAP access right's `identifier` names, from a
 * registered resource set or a lookup the resource server declares, and
 * whether a person is that owner (#432 phase 5).
 */
class GnapOwnership {
  /** The application attribute a resource server declares its lookup in. */
  static readonly LOOKUP_ATTRIBUTE = LOOKUP_ATTRIBUTE;

  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the modules it reads
   */
  constructor(private readonly deps: GnapOwnershipDeps) {
    deps.log.debug("Entering GnapOwnership.constructor().");
    deps.log.debug("Leaving GnapOwnership.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): GnapOwnershipDeps {
    helpers.log.debug("Entering GnapOwnership.defaultDeps().");
    helpers.log.debug("Leaving GnapOwnership.defaultDeps().");
    return {
      log: helpers.log, config: config, errorCodes: errorCodes,
      applications: applications, store: store,
      nowMs: function (): number {
        return Date.now();
      },
      directoryFacts: function (key: string): Json {
        helpers.log.debug("Entering directoryFacts().");
        helpers.log.debug("Leaving directoryFacts().");
        return require('../common/credentials').delegationFactsFor(key);
      },
      fetchPublished: function (url: string, options: Json): Promise<Json> {
        helpers.log.debug("Entering fetchPublished().");
        helpers.log.debug("Leaving fetchPublished().");
        return require('../federation/federation_http')
          .fetchPublished(url, options);
      }
    };
  }

  // A DN compared as the directory compares one: each RDN trimmed and
  // lower-cased.
  private static normalizeDn(value: unknown): string {
    helpers.log.debug("Entering GnapOwnership.normalizeDn().");
    helpers.log.debug("Leaving GnapOwnership.normalizeDn().");
    return String(value == null ? '' : value).trim().split(',')
      .map(function (part: string): string {
        return part.trim().toLowerCase();
      }).join(',');
  }

  // The identifier of an object right, or '' for a reference string or a
  // right that names none.
  private identifierOf(right: Json): string {
    const { log } = this.deps;
    log.debug("Entering GnapOwnership.identifierOf().");
    log.debug("Leaving GnapOwnership.identifierOf().");
    return right && typeof right === 'object' &&
      typeof right.identifier === 'string' ? right.identifier : '';
  }

  // The lookup template a resource server's entry declares, or ''.
  private templateOf(rsId: string): string {
    const { log, applications } = this.deps;
    log.debug("Entering GnapOwnership.templateOf(). " + rsId);
    const app = rsId ? applications.get(rsId) : null;
    const raw = app && app.fields ? app.fields[LOOKUP_ATTRIBUTE] : '';
    const value = Array.isArray(raw) ? raw[0] : raw;
    log.debug("Leaving GnapOwnership.templateOf().");
    return value ? String(value) : '';
  }

  // -------------------------------------------------------------------------
  // THE OWNER ON A REGISTERED RESOURCE SET: the newest registration by one of
  // `rsIds` whose access carries an object right of this type and
  // identifier, and whose `resourceOwners` names the identifier.
  // -------------------------------------------------------------------------
  /**
   * Finds the owner a registered resource set declares for a right.
   *
   * @param right - the access right
   * @param rsIds - the resource servers the right is for
   * @returns `{ owner, rs }`, or null
   */
  fromResourceSets(right: Json, rsIds: string[]): Json {
    const { log, store } = this.deps;
    log.debug("Entering GnapOwnership.fromResourceSets().");
    const identifier = this.identifierOf(right);
    let found: Json = null;
    if (identifier) {
      store.listResources().forEach(function (row: Json): void {
        const named = row && row.resourceOwners &&
          typeof row.resourceOwners[identifier] === 'string'
          ? row.resourceOwners[identifier] : '';
        if (!named || (rsIds || []).indexOf(row.rsIdentifier) < 0) {
          return;
        }
        const carries = (row.access || []).some(function (one: Json): boolean {
          return one && typeof one === 'object' && one.type === right.type &&
            one.identifier === identifier;
        });
        if (carries && (!found ||
                        Number(row.createdAt) > Number(found.createdAt))) {
          found = { owner: named, rs: row.rsIdentifier,
                    createdAt: row.createdAt };
        }
      });
    }
    log.debug("Leaving GnapOwnership.fromResourceSets(). " + !!found);
    return found ? { owner: found.owner, rs: found.rs } : null;
  }

  /**
   * Builds the URL a lookup template names for one identifier: the
   * identifier percent-encoded into the one path segment `{identifier}`
   * holds.
   *
   * @param template - the resource server's `gnapOwnerLookupUri`
   * @param identifier - the right's identifier
   * @returns the URL, or '' when the template is not usable
   */
  static lookupUrl(template: string, identifier: string): string {
    helpers.log.debug("Entering GnapOwnership.lookupUrl().");
    const problem = applications.ownerLookupUriProblem(template);
    if (problem || !identifier) {
      helpers.log.debug("Leaving GnapOwnership.lookupUrl(). Unusable.");
      return '';
    }
    // encodeURIComponent leaves . and .. readable as path segments, and a
    // segment of either would climb out of the template's path; they are
    // percent-encoded too.
    const segment = encodeURIComponent(identifier)
      .replace(/\./g, '%2E');
    helpers.log.debug("Leaving GnapOwnership.lookupUrl().");
    return template.replace('{identifier}', segment);
  }

  // One lookup, through the outbound policy. `{ owner }` (owner '' for a 404:
  // nobody owns it) or `{ failed: why }`.
  private async lookup(rsId: string, identifier: string): Promise<Json> {
    const { log, config, errorCodes, nowMs } = this.deps;
    log.debug("Entering GnapOwnership.lookup(). " + rsId);
    const key = rsId + '\u0000' + identifier;
    const held = owners.get(key);
    if (held && Number(held.until) > nowMs()) {
      counter.hit();
      log.debug("Leaving GnapOwnership.lookup(). Cached.");
      return { owner: held.owner };
    }
    counter.miss();
    const url = GnapOwnership.lookupUrl(this.templateOf(rsId), identifier);
    if (!url) {
      log.debug("Leaving GnapOwnership.lookup(). No usable template.");
      return { failed: 'the resource server\'s ' + LOOKUP_ATTRIBUTE +
               ' is not a usable template' };
    }
    let answer: Json;
    try {
      answer = await this.deps.fetchPublished(url, {
        accept: 'application/json', maxBytes: MAX_ANSWER_BYTES });
    } catch (e) {
      log.debug("Caught in GnapOwnership.lookup(): " +
                ((e && e.message) || e));
      answer = { ok: false, status: 0, why: (e && e.message) || String(e) };
    }
    let owner: string | null = null;
    if (answer && answer.status === 404) {
      owner = '';
    } else if (answer && answer.ok && answer.status === 200) {
      try {
        const doc = JSON.parse(Buffer.from(answer.body || '').toString('utf8'));
        if (doc && typeof doc === 'object' && typeof doc.owner === 'string' &&
            doc.owner.length <= 1024) {
          owner = doc.owner;
        }
      } catch (e) {
        log.debug("Caught in GnapOwnership.lookup(): " +
                  ((e && e.message) || e));
        owner = null;
      }
    }
    if (owner === null) {
      const why = answer && answer.why ? String(answer.why)
        : 'the answer was HTTP ' + (answer ? answer.status : 0) +
          ', or not {"owner": "<DN>"}';
      log.warn(errorCodes.tag('STS-GNAP-0869') + 'gnap: the owner lookup ' +
               'of "' + rsId + '" could not be answered: ' + why);
      log.debug("Leaving GnapOwnership.lookup(). Failed.");
      return { failed: why };
    }
    const lifetimeS = Math.max(0, Number(config.value(
      'gnap.ownerLookupCacheS')));
    if (lifetimeS > 0) {
      if (!owners.has(key)) {
        const room = cacheRegistry.makeRoom(owners, MAX_CACHED_OWNERS,
          { name: 'gnap.owner-lookups', counter: counter,
            expired: function (one: Json): boolean {
              return !(one && Number(one.until) > Date.now());
            } });
        counter.evicted(room.evicted);
      }
      owners.set(key, { owner: owner, until: nowMs() + lifetimeS * 1000 });
    }
    log.debug("Leaving GnapOwnership.lookup(). " + (owner ? 'An owner.'
                                                          : 'Nobody.'));
    return { owner: owner };
  }

  // -------------------------------------------------------------------------
  // prefetch(tokens, targetsOf): every lookup the rights of these tokens
  // need, made BEFORE the synchronous policy question. Answers a map the
  // caller hands to `facts()` (through the judge context's `owners`).
  // -------------------------------------------------------------------------
  /**
   * Makes every owner lookup a set of requested tokens needs.
   *
   * @param tokens - `[{ access }]`
   * @param targetsOf - the resource servers a list of rights is for
   * @returns a promise of `{ [rs\0identifier]: { owner } | { failed } }`
   */
  async prefetch(tokens: Json[], targetsOf: (access: Json[]) => string[]):
      Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering GnapOwnership.prefetch().");
    const out: Json = {};
    let made = 0;
    const wanted: Json[] = [];
    (tokens || []).forEach((token: Json): void => {
      (token.access || []).forEach((right: Json): void => {
        const identifier = this.identifierOf(right);
        if (!identifier) {
          return;
        }
        const rsIds = targetsOf([right]) || [];
        if (this.fromResourceSets(right, rsIds)) {
          return;
        }
        rsIds.forEach((rsId: string): void => {
          const key = rsId + '\u0000' + identifier;
          if (this.templateOf(rsId) && out[key] === undefined &&
              wanted.every(function (one: Json): boolean {
                return one.key !== key;
              })) {
            wanted.push({ key: key, rs: rsId, identifier: identifier });
          }
        });
      });
    });
    for (let i = 0; i < wanted.length; i++) {
      if (made >= MAX_LOOKUPS_PER_PREFETCH) {
        out[wanted[i].key] = { failed: 'more than ' +
          MAX_LOOKUPS_PER_PREFETCH + ' owner lookups in one request' };
        continue;
      }
      made++;
      out[wanted[i].key] = await this.lookup(wanted[i].rs,
                                             wanted[i].identifier);
    }
    log.debug("Leaving GnapOwnership.prefetch(). " + made + " lookup(s).");
    return out;
  }

  /**
   * Says whether a person is an owner: the owner DN names their entry, or a
   * group they are a member of.
   *
   * @param ownerDn - the owner, a DN
   * @param username - the person
   * @returns true when they own it
   */
  matches(ownerDn: string, username: string): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapOwnership.matches().");
    if (!ownerDn || !username) {
      log.debug("Leaving GnapOwnership.matches(). Nobody to compare.");
      return false;
    }
    const facts: Json = this.deps.directoryFacts(username) || {};
    if (!facts.found || !facts.person) {
      log.debug("Leaving GnapOwnership.matches(). Not a person here.");
      return false;
    }
    const wanted = GnapOwnership.normalizeDn(ownerDn);
    if (GnapOwnership.normalizeDn(facts.dn) === wanted) {
      log.debug("Leaving GnapOwnership.matches(). Their own entry.");
      return true;
    }
    const member = (facts.groups || []).some(function (g: Json): boolean {
      return GnapOwnership.normalizeDn(g && g.dn) === wanted;
    });
    log.debug("Leaving GnapOwnership.matches(). member=" + member);
    return member;
  }

  /**
   * Says whether a DN is a person or a group in the ambient realm's
   * directory — what a resource set's owner must be.
   *
   * @param dn - the DN
   * @returns 'person', 'group', or '' when it is neither
   */
  ownerKind(dn: string): string {
    const { log } = this.deps;
    log.debug("Entering GnapOwnership.ownerKind().");
    if (!/^[A-Za-z][A-Za-z0-9-]*=/.test(String(dn || ''))) {
      log.debug("Leaving GnapOwnership.ownerKind(). Not a DN.");
      return '';
    }
    const facts: Json = this.deps.directoryFacts(dn) || {};
    if (!facts.found) {
      log.debug("Leaving GnapOwnership.ownerKind(). Nothing there.");
      return '';
    }
    const normalized = GnapOwnership.normalizeDn(facts.dn);
    let kind = '';
    if (facts.person) {
      kind = 'person';
    } else if (/^cn=/.test(normalized) &&
               normalized.indexOf(',ou=applications,') < 0 &&
               !/,ou=(devices|spiffe|policies|claimproviders),/.test(
                 normalized)) {
      kind = 'group';
    }
    log.debug("Leaving GnapOwnership.ownerKind(). " + (kind || 'Neither.'));
    return kind;
  }

  // -------------------------------------------------------------------------
  // THE OWNERSHIP FACTS OF ONE RIGHT, for the issue-gnap-right question:
  //   { known, owner, source, unresolved, matches }
  // `matches` is present only where an approver is known. A right with no
  // identifier, or one nobody declares an owner for, is `{ known: false }`.
  // -------------------------------------------------------------------------
  /**
   * Returns the ownership facts of one right.
   *
   * @param right - the access right
   * @param rsIds - the resource servers the right is for
   * @param approver - the person the grant is for, or ''
   * @param fetched - what `prefetch()` answered
   * @returns `{ known, owner, source, unresolved, matches }`
   */
  facts(right: Json, rsIds: string[], approver: string, fetched: Json): Json {
    const { log } = this.deps;
    log.debug("Entering GnapOwnership.facts().");
    const identifier = this.identifierOf(right);
    if (!identifier) {
      log.debug("Leaving GnapOwnership.facts(). No identifier.");
      return { known: false };
    }
    const fromSet = this.fromResourceSets(right, rsIds);
    let owner = fromSet ? fromSet.owner : '';
    let source = fromSet ? 'resource-set' : '';
    let unresolved = false;
    if (!fromSet) {
      (rsIds || []).forEach((rsId: string): void => {
        if (owner || !this.templateOf(rsId)) {
          return;
        }
        const key = rsId + '\u0000' + identifier;
        const answer = fetched && fetched[key];
        if (!answer || answer.failed !== undefined) {
          // Never fetched (a caller that did not prefetch) is unresolved
          // too: the resource server said its identifiers have owners.
          unresolved = true;
          return;
        }
        if (answer.owner) {
          owner = answer.owner;
          source = 'lookup';
          unresolved = false;
        }
      });
    }
    const out: Json = { known: !!owner, owner: owner, source: source,
                        unresolved: !owner && unresolved };
    if (owner && approver) {
      out.matches = this.matches(owner, approver);
    }
    log.debug("Leaving GnapOwnership.facts(). known=" + out.known);
    return out;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2): see
// `common/instance_slot.ts`. A process that loads this module without the
// root builds the default when it loads.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapOwnership>(
  'gnap/gnap_ownership',
  () => new GnapOwnership(GnapOwnership.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Who owns the resource a GNAP access right names (#432 phase 5). A library
 * that registers no route.
 *
 * @namespace
 */
export = {
  GnapOwnership: GnapOwnership,
  installInstance: (instance: GnapOwnership): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  LOOKUP_ATTRIBUTE: LOOKUP_ATTRIBUTE,
  lookupUrl: GnapOwnership.lookupUrl,
  fromResourceSets: slot.forward('fromResourceSets'),
  prefetch: slot.forward('prefetch'),
  matches: slot.forward('matches'),
  ownerKind: slot.forward('ownerKind'),
  facts: slot.forward('facts'),
  // The cache, for a test that must forget what it held.
  forget: function (): void {
    helpers.log.debug("Entering forget().");
    owners.clear();
    helpers.log.debug("Leaving forget().");
  }
};
