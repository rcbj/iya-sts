'use strict';
//
// File: extended_listing.ts
//
// ===========================================================================
// THE EXTENDED SUBORDINATE LISTING (#135, 2026-09-24): OpenID Federation
// Extended Subordinate Listing 1.0, draft 03 — `federation_extended_list_
// endpoint`, at `/oidfed/extended-list` under the realm's base.
//
// The list endpoint of section 8.2 answers a bare array of identifiers. This
// one answers the same subordinates PAGED, with what a consumer would
// otherwise fetch one statement at a time:
//
//   * **every list parameter** (8.2.1) — `entity_type`, `trust_marked`,
//     `trust_mark_type`, `intermediate` — read as the list endpoint reads
//     them (`oidfed.ts`'s `listing()`), except that `trust_mark_type` may
//     REPEAT here and then matches a subordinate holding ANY of the types
//     (draft 03, table 2). A mark counts when THIS realm issued it and it is
//     still valid, as at the list endpoint;
//   * **`from` and `limit`**: `page_pointer.ts`. The order is the Entity
//     Identifier, and the page is at most `oidfed.listPageMax` long whatever
//     `limit` asks — the draft's "practical upper limit", set so that a page
//     with every claim asked for can still be answered;
//   * **`updated_after` and `updated_before`** against each subordinate's
//     `updated`, and **`audit_timestamps`** to return `registered` and
//     `updated` — both read off the subordinate's history (#137,
//     `oidfed.ts`'s `auditTimesOf()`), so a statement's last change is the
//     last event that changed it;
//   * **`claims`**: `subordinate_statement` (the signed statement, the only
//     one that costs a signature), any top-level claim of that statement
//     (`jwks`, `metadata`, `metadata_policy`, `constraints`, …) read
//     unsigned, and `trust_marks` — the valid marks this realm issued the
//     subordinate, and, for a realm of this service, the marks its own
//     Entity Configuration carries. A claim the subordinate has none of is
//     simply absent ("if available"), and so is a name no statement defines.
//
// **WITH NO `claims`, EACH ENTRY IS ITS `id` ALONE.** The draft leaves the
// default to the responder, and its first figure shows statements returned
// unasked; they are not returned here, because a statement is a SIGNATURE
// and this endpoint is anonymous — a page of fifty would be fifty signatures
// (post-quantum ones, where the realm's key is) for one unauthenticated GET.
// A caller who wants them asks, and pays one page at a time.
//
// **A SUSPENDED SUBORDINATE IS NOT LISTED** (#137): it has no statement.
//
// ERRORS, in 8.9's shape: a pointer this service did not make is 404
// `page_not_found`; a `limit` that is not a positive integer, a time that is
// not a NumericDate and a boolean that is neither is 400 `invalid_request`.
// `unsupported_parameter` is never answered: every parameter the draft
// defines is supported.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import InstanceSlot = require('../common/instance_slot');
import EntityStatement = require('./entity_statement');
import PagePointer = require('./page_pointer');

type Json = any;
type Req = any;

const ENDPOINT = 'extended-list';

interface ExtendedListingDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
}

interface Outcome {
  ok: boolean;
  code?: string;
  why?: string;
  error?: string;
  status?: number;
  body?: Json;
}

class ExtendedListing {
  constructor(private readonly deps: ExtendedListingDeps) {
    deps.log.debug("Entering ExtendedListing.constructor().");
    deps.log.debug("Leaving ExtendedListing.constructor().");
  }

  static defaultDeps(): ExtendedListingDeps {
    helpers.log.debug("Entering ExtendedListing.defaultDeps().");
    helpers.log.debug("Leaving ExtendedListing.defaultDeps().");
    return { log: helpers.log, config: config, realms: realms };
  }

  private refuse(code: string, why: string, error: string,
                 status: number): Outcome {
    this.deps.log.debug("Entering ExtendedListing.refuse(). " + code);
    this.deps.log.debug("Leaving ExtendedListing.refuse().");
    return { ok: false, code: code, why: why, error: error, status: status };
  }

  // Every value of a parameter: repeated, comma- or space-separated.
  static values(v: Json): string[] {
    helpers.log.debug("Entering ExtendedListing.values().");
    const out: string[] = [];
    [].concat(v === undefined || v === null ? [] : v)
      .forEach(function (one: Json): void {
        String(one).split(/[\s,]+/).forEach(function (part: string): void {
          if (part && out.indexOf(part) < 0) {
            out.push(part);
          }
        });
      });
    helpers.log.debug("Leaving ExtendedListing.values(). " + out.length);
    return out;
  }

  // A single-valued parameter as its one value; undefined when absent, and
  // null when it was given twice (which is no one value).
  static single(v: Json): string | null | undefined {
    helpers.log.debug("Entering ExtendedListing.single().");
    if (v === undefined) {
      helpers.log.debug("Leaving ExtendedListing.single(). Absent.");
      return undefined;
    }
    helpers.log.debug("Leaving ExtendedListing.single().");
    return Array.isArray(v) ? null : String(v);
  }

  // The page size: `limit` where it is a positive integer, never more than
  // `oidfed.listPageMax`; null for a `limit` that is not one.
  pageSize(limit: Json): number | null {
    const { log, config } = this.deps;
    log.debug("Entering ExtendedListing.pageSize().");
    const cap = Math.max(1, Number(config.value('oidfed.listPageMax')));
    const one = ExtendedListing.single(limit);
    if (one === undefined) {
      log.debug("Leaving ExtendedListing.pageSize(). The cap.");
      return cap;
    }
    if (one === null || !/^[1-9][0-9]{0,8}$/.test(one)) {
      log.debug("Leaving ExtendedListing.pageSize(). Not a positive integer.");
      return null;
    }
    log.debug("Leaving ExtendedListing.pageSize().");
    return Math.min(cap, Number(one));
  }

  // -------------------------------------------------------------------------
  // THE ANSWER to one request, `{ ok, body }` or a refusal. `entity` is the
  // `Oidfed` instance serving the realm.
  // -------------------------------------------------------------------------
  async answer(entity: Json, req: Req, query: Json): Promise<Outcome> {
    const { log, realms } = this.deps;
    log.debug("Entering ExtendedListing.answer().");
    const q = query || {};
    const limit = this.pageSize(q.limit);
    if (limit === null) {
      log.debug("Leaving ExtendedListing.answer(). A bad limit.");
      return this.refuse('STS-OIDFED-0060', 'limit is a positive integer ' +
                         '(draft 03, table 1).', 'invalid_request', 400);
    }
    const time = function (name: string): number | null | undefined {
      log.debug("Entering time(). " + name);
      const one = ExtendedListing.single(q[name]);
      if (one === undefined) {
        log.debug("Leaving time(). Absent.");
        return undefined;
      }
      log.debug("Leaving time().");
      return one !== null && /^[0-9]{1,12}$/.test(one) ? Number(one) : null;
    };
    const after = time('updated_after');
    const before = time('updated_before');
    if (after === null || before === null) {
      log.debug("Leaving ExtendedListing.answer(). A bad time.");
      return this.refuse('STS-OIDFED-0060', 'updated_after and ' +
                         'updated_before are NumericDates (draft 03, ' +
                         'table 1).', 'invalid_request', 400);
    }
    const bool = function (name: string): boolean | null | undefined {
      log.debug("Entering bool(). " + name);
      const one = ExtendedListing.single(q[name]);
      if (one === undefined) {
        log.debug("Leaving bool(). Absent.");
        return undefined;
      }
      log.debug("Leaving bool().");
      return one === 'true' ? true : one === 'false' ? false : null;
    };
    const audit = bool('audit_timestamps');
    const trustMarked = bool('trust_marked');
    const intermediate = bool('intermediate');
    if (audit === null || trustMarked === null || intermediate === null) {
      log.debug("Leaving ExtendedListing.answer(). A bad boolean.");
      return this.refuse('STS-OIDFED-0060', 'audit_timestamps, ' +
                         'trust_marked and intermediate are true or false.',
                         'invalid_request', 400);
    }
    const types = ExtendedListing.values(q.entity_type);
    const markTypes = ExtendedListing.values(q.trust_mark_type);
    const claims = ExtendedListing.values(q.claims);

    const facts: Json[] = await entity.subordinateFacts(req);
    const rows: Json[] = [];
    for (let i = 0; i < facts.length; i++) {
      const s = facts[i];
      if (types.length && !types.every(function (t: string): boolean {
        return s.heldTypes.indexOf(t) >= 0;
      })) {
        continue;
      }
      if (intermediate !== undefined && s.isIntermediate !== intermediate) {
        continue;
      }
      if (trustMarked === true && !entity.validIssued('', s.entityId).length) {
        continue;
      }
      if (markTypes.length && !markTypes.some(function (t: string) {
        return entity.validIssued(t, s.entityId).length > 0;
      })) {
        continue;
      }
      const times = entity.auditTimesOf(s);
      if (after !== undefined && times.updated < after) {
        continue;
      }
      if (before !== undefined && times.updated > before) {
        continue;
      }
      rows.push({ fact: s, times: times });
    }
    rows.sort(function (a: Json, b: Json): number {
      return a.fact.entityId < b.fact.entityId ? -1
           : a.fact.entityId > b.fact.entityId ? 1 : 0;
    });
    const paged = PagePointer.page(rows, function (r: Json): string {
      return String(r.fact.entityId);
    }, String(realms.current().id), ENDPOINT, q.from, limit);
    if (!paged.ok) {
      log.debug("Leaving ExtendedListing.answer(). Unknown pointer.");
      return this.refuse('STS-OIDFED-0059', 'from is not a pointer this ' +
                         'entity returned as next (draft 03, table 1).',
                         'page_not_found', 404);
    }
    const out: Json[] = [];
    for (let i = 0; i < paged.page.length; i++) {
      const row = paged.page[i];
      const one: Json = { id: row.fact.entityId };
      // updated_after and updated_before RECOMMEND the timestamps, and
      // audit_timestamps=true requires them.
      if (audit === true || after !== undefined || before !== undefined) {
        one.registered = row.times.registered;
        one.updated = row.times.updated;
      }
      await this.addClaims(entity, req, row.fact, claims, one);
      out.push(one);
    }
    const body: Json = { immediate_subordinate_entities: out };
    if (paged.next) {
      body.next = paged.next;
    }
    log.debug("Leaving ExtendedListing.answer(). " + out.length);
    return { ok: true, body: body };
  }

  // The claims asked for, added to one entry.
  private async addClaims(entity: Json, req: Req, fact: Json,
                          claims: string[], one: Json): Promise<void> {
    const { log } = this.deps;
    log.debug("Entering ExtendedListing.addClaims(). " + claims.length);
    if (!claims.length) {
      log.debug("Leaving ExtendedListing.addClaims(). None asked for.");
      return;
    }
    const statement = entity.subordinateStatementClaims(req, fact.entityId);
    for (let i = 0; i < claims.length; i++) {
      const name = claims[i];
      if (name === 'id' || name === 'registered' || name === 'updated') {
        continue;
      }
      if (name === 'subordinate_statement') {
        const signed = await entity.subordinateStatement(req, fact.entityId);
        if (signed.ok) {
          one.subordinate_statement = signed.jwt;
        }
        continue;
      }
      if (name === 'trust_marks') {
        const marks = this.marksOf(entity, fact);
        if (marks.length) {
          one.trust_marks = marks;
        }
        continue;
      }
      if (statement.ok && statement.claims[name] !== undefined &&
          EntityStatement.DEFINED_CLAIMS.indexOf(name) >= 0) {
        one[name] = statement.claims[name];
      }
    }
    log.debug("Leaving ExtendedListing.addClaims().");
  }

  // The Trust Marks of one subordinate: the valid ones this realm issued
  // it, and — for a realm of this service — those its own configuration
  // carries; each once.
  private marksOf(entity: Json, fact: Json): Json[] {
    const { log } = this.deps;
    log.debug("Entering ExtendedListing.marksOf().");
    const out: Json[] = [];
    const seen: Record<string, boolean> = {};
    const add = function (type: string, jwt: string): void {
      log.debug("Entering add().");
      if (jwt && !seen[jwt]) {
        seen[jwt] = true;
        out.push({ trust_mark_type: type, trust_mark: jwt });
      }
      log.debug("Leaving add().");
    };
    entity.validIssued('', fact.entityId).forEach(function (m: Json): void {
      add(String(m.type), String(m.jwt));
    });
    const held = fact.configuration && fact.configuration.trust_marks;
    (Array.isArray(held) ? held : []).forEach(function (m: Json): void {
      add(String(m.trust_mark_type), String(m.trust_mark));
    });
    log.debug("Leaving ExtendedListing.marksOf(). " + out.length);
    return out;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ExtendedListing>(
  'oidfed/extended_listing',
  () => new ExtendedListing(ExtendedListing.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  ExtendedListing: ExtendedListing,
  installInstance: (instance: ExtendedListing): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ENDPOINT: ENDPOINT,
  values: ExtendedListing.values,
  answer: slot.forward('answer')
};
