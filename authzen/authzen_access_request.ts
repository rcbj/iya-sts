// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authzen_access_request.ts
//
// ===========================================================================
// THE AUTHZEN ACCESS REQUEST AND APPROVAL PROFILE (#1180), AND ITS CALLBACK
// COMPANION: THIS SERVICE AS THE PROFILE'S ACCESS REQUEST SERVICE AS WELL AS
// ITS PDP. rcbj's decisions of 2026-10-30 on #1180 are the design:
//
//   1. **THE POLICY MARKS A DENIAL REQUESTABLE**, by the XACML advice
//      `urn:sts:xacml:advice:access-request` on a Deny. Its assignments
//      (`ADVICE_PREFIX` + a name) say who approves — `approver-role`,
//      `approver-group`, `approver-owners` (the resource application's
//      owners, `common/ownership.ts`) — the longest approval
//      (`max-approval-seconds`), whether emergency access is allowed
//      (`emergency`), which context members bind (`context-member`), and
//      the `template` and `reason` the denial carries. No advice, no
//      request: a denial is an ordinary `false`. There is no per-realm or
//      per-application switch beyond `authzen.accessRequests` itself.
//   2. **WHO MAY APPROVE IS ASKED OF THE PDP**: the access-control policy,
//      resource `authzen-access-request`, action `approve-access-request`,
//      with the approver, the requester, the subject and the tuple as
//      facts (`common/access_gate.ts`'s `accessRequestObject`). So
//      self-approval and separation of duties are XACML rules — the
//      built-in document's fourth rule — and never an `if` here. What this
//      file computes is who is ELIGIBLE (the advice's role, group or
//      owners), which is routing — who is mailed, whose portal lists it —
//      and a fact the rule reads.
//   3. **APPROVERS ACT IN THE PORTAL AND THE CONSOLE**: `decide()` is the
//      one door both reach (`portal/portal_access_requests.ts` through
//      `/account-api`, `authzen/authzen_admin.ts` through `/admin-api`), and
//      approvers are mailed through the mail channel. A revocation from
//      either door (#1203) mails the requester the same way, at the address
//      on their own entry and with no link. The portal lists only the live
//      approvals that person gave, and revokes only those: a revocation on
//      the portal's door by anybody but the approval's own approver is
//      refused (`STS-AUTHZEN-0141`). A revocation is asked as its own
//      action, `revoke-access-request`; a repository policy that never
//      names that action is asked `approve-access-request` instead, so a
//      deployment's own policy decides a revocation as it always did.
//   4. **CALLBACK IS IN THE FIRST BUILD**, to a URL registered for the
//      requester (rcbj's decision 4: an application's
//      `appAuthzenCallbackUri`, or a person's or service account's
//      `stsAuthzenCallbackUri`, each written by an administrator) and never
//      one taken from the request alone, under the outbound policy every
//      other delivery takes (`federation_http.deliverJson()`): https
//      verified, no redirect, the internal-address refusal, the kill
//      switch. `federation/CLAUDE.md` carries its row among the URLs this
//      service dials. A failed delivery is retried by this file's own
//      scheduler job, up to a bound snapshotted onto the task, the wait
//      doubling from the backoff up to a day. A finished task is kept past
//      its retention while its delivery is still being tried, never past
//      the bound's last attempt.
//
// ---------------------------------------------------------------------------
// THE INVARIANT THAT GOVERNS EVERYTHING BELOW: AN APPROVAL NEVER TURNS A
// DENIAL INTO A PERMIT BY ITSELF. Approved, a task hands the PEP an
// `approval` to carry on its next evaluation; that evaluation is a NEW
// decision by the realm's root policy, and the approval reaches it only as
// three TRUSTED facts in the environment (`urn:sts:xacml:authzen:
// approval-id`, `:approved-until`, `:approver`) written after `verify()`
// found it — signed by nobody but this realm's store, within its
// `approved_until`, not revoked, presented by the caller it was issued to,
// for the application it was issued for, and the tuple an exact match
// (the profile's structural comparison). A policy that ignores those facts
// denies exactly as it did; a policy that requires them permits only an
// approved tuple. The values a PEP sends in `context.approval` beside the
// id are never believed, except `state` (#1204): a signed approval is
// verified, and a bad signature is not an approval, but the store still
// decides revocation and expiry. A state with no row is not an approval.
//
// THE BINDING. A requestable denial carries a `binding_token`: a JWS this
// realm signs (`oauth2.ts`'s `signPublishedDocument()`, the one signer of a
// published document) over the denied tuple — subject, resource and action
// whole (less `subject.properties.act`, the profile's exclusion), the
// context members the advice named, the caller, the application and the
// advice's approval terms — and `binding_hash`, the base64url SHA-256 of
// the RFC 8785 canonical JSON of `{ subject, resource, action, context }`
// (`stsCrypto.jcsCanonicalJson`). Inline claims stay, which is the form
// the profile recommends; the hash is what a verifier may check instead,
// including a token that carries the hash and omits the inline tuple. The
// token is audienced to this realm's access request endpoint and expires
// with the denial. It is the by-value form an independent service requires
// and a same-service one may still issue.
//
// THE SAME DENIAL IS ALSO A ROW (#1204), keyed by `evaluation_id`, in
// `authzen.accessRequestDenials`. This process is the PDP and the access
// request service together, so a submission may name the denial by
// `evaluation_id` and the echoed `expires_at` and omit the token. When the
// token is present it is authoritative and the id is only checked against
// it. The row outlives the denial by the skew and a day, so an expired
// denial is still told from one this realm never issued. The approval is
// by reference and by value: the task is a store row, looked up by
// `approval.id`, and `approve()` also signs `approval.state`. Revoking one
// is still a write.
//
// THE SUBMISSION SCHEMA (#1204). A requestable denial carries
// `request_schema_url`, the same origin as its `endpoint`
// (`GET /access/v1/access-requests/schema`). The document is JSON
// Schema draft 2020-12 and describes the augmentations
// `requestedAccess()` accepts: `context.business_justification`,
// `requested_access.requested_until` and
// `requested_access.emergency`, and that emergency requires the
// justification. None of them is required on an ordinary submission,
// and the schema is not a second validator. This service hosts no
// form of its own there: see THE HOSTED FORM below for `form_url`.
// `display` (#1204) is a hint for a person, never bound or read back: see
// THE DISPLAY HINTS below.
//
// THE TASK is a row of the per-realm store `authzen.accessRequests`:
// `pending`, then exactly once one of `approved`, `denied`, `expired`,
// `cancelled`, `failed` — every transition one audit row. `failed` (#1202)
// is a workflow step that cannot complete: an approval that could not be
// stored (`STS-AUTHZEN-0142`), or approvers the advice named who resolve,
// certainly, to nobody (`STS-AUTHZEN-0143`, noticed by the job). Expiry is the
// scheduler job `authzen.access-requests` (rcbj's rule on periodic work):
// a pending task past its `expires_at` is moved to `expired` (and its
// callback sent), a finished one is removed a day after it finished, or
// after its approval ran out if that is later, and a callback whose last
// attempt failed in a way that can succeed is sent again. A read checks the
// deadline itself, so an expired task never answers pending whenever the
// job last ran.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50): `AccessRequests` takes what it uses through
// its constructor; the stores are declared at module scope, because a store
// becomes per realm at its declaration (`tests/realm_isolation.js`). A
// LIBRARY: it registers no route — `authzen.ts` carries the four — and its
// job is registered when the composition root installs the instance.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import realms = require('../common/realms');
import stsCrypto = require('../common/crypto');
// The lexical spaces of an advice's values (`termsOf()`). A leaf the
// mapping already loads.
import datatypes = require('../xacml/xacml_datatypes');
import authzenModel = require('./authzen_model');

const { log } = helpers;

type Json = any;
type Req = import('express').Request;
type Res = import('express').Response;

// THE ADVICE that marks a denial requestable, and its assignments' prefix.
const ADVICE_ID = 'urn:sts:xacml:advice:access-request';
const ADVICE_PREFIX = ADVICE_ID + ':';

// The capability the metadata names while this is on.
const CAPABILITY = 'urn:openid:authzen:capability:access-request';

// The request endpoint, under the realm's prefix, and the submission
// schema beside it. The schema path is registered before `/:id`, or
// Express would read "schema" as a task id.
const REQUESTS_PATH = '/access/v1/access-requests';
const SCHEMA_PATH = REQUESTS_PATH + '/schema';
// THE HOSTED FORM AND THE TICKET (#1204): a portal page, so the person
// signs in there and the page is the portal's static surface.
const FORM_PATH = '/portal/access-request';
// The most of a person's own requests the page lists.
const MAX_MINE = 50;
// THE CATALOG COMPANION (#1204): a denial's Catalogs Document, and the one
// catalog under it, the entitlements the policy's advice lists.
const CATALOGS_PATH = REQUESTS_PATH + '/catalogs';
const ENTITLEMENT_POINTER = '/requested_access/entitlement';
// THE BULK COMPANION (#1204): a bundle's id prefix and its index key.
const BUNDLE_PREFIX = 'arb_';
const BUNDLE_KEY = 'bundle:';
// THE ACTOR COMPANION (#1204): the deepest actor chain read, and the
// longest of its identifiers.
const MAX_ACT_DEPTH = 8;
const MAX_URL = 2048;
// A Catalog Endpoint page's default and largest size (the draft's section
// 7: the endpoint MAY clamp `limit`).
const CATALOG_PAGE = 20;
const CATALOG_PAGE_MAX = 50;

// The access-control question (`common/access_gate.ts`).
const GATE_RESOURCE = 'authzen-access-request';
const GATE_ACTION = 'approve-access-request';
// A revocation's own action (#1203). The built-in document permits it
// wherever it permits an approval; a repository policy that never names it
// is asked GATE_ACTION instead, so an existing policy decides a revocation
// as it did before the action existed.
const GATE_REVOKE_ACTION = 'revoke-access-request';

// The lifecycle, the first status the only one that is not terminal, and
// the CALLBACK companion's event names, which are the terminal statuses:
// the model's Task Handle (`models/authzen/authzen_members.tsp`, #1579).
// `partial` is a BULK Task Handle's aggregate only (#1204): no single
// task is ever partial, so it is neither a task's status nor an event.
const STATES = Object.freeze(authzenModel.valuesOf('task-handle', 'status')
  .filter(function (one: string): boolean {
    return one !== 'partial';
  }));
const EVENTS = Object.freeze(STATES.slice(1));

// The context members that are the profile's machinery, never part of the
// authorization-relevant context and never bound.
const MACHINERY = Object.freeze(['access_request', 'evaluation_id',
  'evaluated_at', 'reason', 'approval', 'application',
  'supported_obligations']);

// How long a finished task is kept for the PEP to read it (the profile's
// SHOULD: at least 24 hours after it reached a terminal status).
const RETENTION_S = 86400;

// The clock skew a submission's freshness tolerates (the profile's typical
// 30 seconds).
const SKEW_S = 30;

// The most of anything one row carries, and the most approvers one task
// mails.
const MAX_ID = 128;
const MAX_TEXT = 1024;
const MAX_LIST = 32;
const MAX_MAILED = 50;
const MAX_CALLBACKS = 8;

// The scheduler job.
const JOB = 'authzen.access-requests';
const JOB_EVERY_MS = 60000;

// The longest wait between two callback attempts: the backoff doubles
// from the configured one up to this (#1202).
const BACKOFF_CAP_S = 86400;

// The longest an attempt is held in flight, and the least.
const INFLIGHT_MIN_S = 120;

// The index row of every pending task (`awaiting()`), and the prefix of a
// row per approver (`grantedBy()`): each a list of task ids, so a portal
// page reads its own rows rather than the store.
const PENDING_KEY = 'pending:tasks';
const APPROVER_PREFIX = 'approver:';

// A callback POST that is already running, keyed by realm and task id. A
// Promise cannot be stored on the row. `resetForTests()` clears it.
const flights = new Map<string, Promise<boolean>>();

// The realms whose denial store was last seen full, so the full store is
// logged when it fills and when it has room again, not per denial (#1204).
const denialsFull = new Set<string>();

// ---------------------------------------------------------------------------
// THE STORES, per realm at their declaration and persisted, so a task
// survives a restart in product mode and every request worker reads the
// same one (the minted-row rule of persistence/CLAUDE.md). A row is JSON
// and an in-place edit is re-set (`save()`). No bearer value is a key: the
// index holds an approval id, an idempotency key and a binding token's jti
// as their SHA-256 (`stsCrypto.credentialDigest()`) — and, since 2026-11-16,
// each subject's tasks, under the SHA-256 of the subject id as the PEP sent
// it (*THE SUBJECT INDEX*, below).
// ---------------------------------------------------------------------------
// A hot path (every row a flush writes): no Entering/Leaving pair.
const tasks = realms.map({
  persist: 'authzen.accessRequests',
  expiresAt: function (row: Json): number | null {
    const until = row && typeof row === 'object' ? Number(row.keepUntil) : 0;
    return until > 0 ? (until + 3600) * 1000 : null;
  }
});
const index = realms.map({ persist: 'authzen.accessRequestIndex',
                           expiresAt: realms.expiryField('until', 1000) });
// A requestable denial, keyed by evaluation_id (#1204). It outlives the
// denial (keepUntil is the deadline, the skew and a day) so a submission
// after the window is expired rather than unknown. A hot path of a flush,
// the same as `tasks`: no Entering/Leaving pair.
const denials = realms.map({
  persist: 'authzen.accessRequestDenials',
  expiresAt: function (row: Json): number | null {
    const until = row && typeof row === 'object' ? Number(row.keepUntil) : 0;
    return until > 0 ? until * 1000 : null;
  }
});

// The parts of a `realms.map()` store this module uses.
interface Store {
  readonly size?: number;
  get(key: string): any;
  set(key: string, value: any): unknown;
  delete(key: string): boolean;
  forEach(fn: (value: any, key: string) => void): void;
}

// An access request's approval terms, read off the advice.
interface Terms {
  roles: string[];
  groups: string[];
  owners: boolean;
  maxSeconds: number;
  emergency: boolean;
  contextMembers: string[];
  template: string;
  reason: string;
  // The advice's own display text (#1204), sent verbatim while
  // `authzen.accessRequestDisplay` is on. Present only when the advice
  // gives it, so a binding_token's terms are unchanged otherwise.
  displayTitle?: string;
  displayDescription?: string;
  // The entitlements the advice lists (#1204, the CATALOG companion),
  // `{ value, label }`. Present only when the advice names any, so a
  // binding_token's terms are unchanged otherwise.
  entitlements?: { value: string; label: string }[];
}

// An approver, as the two doors name one.
interface Approver {
  username: string;
  // `portal` or `admin-api`.
  door: string;
  // The roles the door established (the management API's), unioned in by
  // the access PEP.
  roles?: string[];
}

// What `verify()` answers about a presented approval.
interface Verdict {
  ok: boolean;
  reason: string;
  task?: Json;
}

interface AccessRequestDeps {
  log: typeof log;
  config: any;
  audit: any;
  errorCodes: any;
  realms: any;
  helpers: any;
  tasks: Store;
  index: Store;
  denials: Store;
  now: () => number;
  // Loaded when used, never at load: each is far up a chain this library
  // must not load early.
  loadOauth2(): any;
  loadGate(): any;
  loadRoles(): any;
  loadOwnership(): any;
  loadApplications(): any;
  loadAdmin(): any;
  loadMailUses(): any;
  loadFedHttp(): any;
  loadScheduler(): any;
  loadAccessPep(): any;
  loadI18n(): any;
}

/**
 * Formats epoch milliseconds as an RFC 3339 instant, to the second.
 *
 * @param ms - epoch milliseconds
 * @returns the instant, `Z`
 */
function instant(ms: number): string {
  log.debug("Entering instant().");
  log.debug("Leaving instant().");
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Tells whether a value is a JSON object (not an array, not null).
 *
 * @param value - the value
 * @returns true for an object
 */
function isObject(value: unknown): boolean {
  log.debug("Entering isObject().");
  log.debug("Leaving isObject().");
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

/**
 * The profile's access requests: the requestable denial, the submission,
 * the task, the approval, its verification at re-evaluation, the expiry
 * job and the callback.
 */
class AccessRequests {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the logger, settings, audit log, error codes, realms,
   *   helpers, the three stores, a clock, and lazy loaders
   */
  constructor(private readonly deps: AccessRequestDeps) {
    deps.log.debug("Entering AccessRequests.constructor().");
    deps.log.debug("Leaving AccessRequests.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): AccessRequestDeps {
    log.debug("Entering AccessRequests.defaultDeps().");
    const lazy = function (name: string, path: string): () => any {
      log.debug("Entering lazy(). " + name);
      log.debug("Leaving lazy().");
      return function (): any {
        log.debug("Entering " + name + "().");
        log.debug("Leaving " + name + "().");
        return require(path);
      };
    };
    log.debug("Leaving AccessRequests.defaultDeps().");
    return {
      log: log,
      config: require('../common/config'),
      audit: require('../common/audit'),
      errorCodes: require('../common/error_codes'),
      realms: realms,
      helpers: helpers,
      tasks: tasks,
      index: index,
      denials: denials,
      // A hot path (every read of a task asks the clock): no
      // Entering/Leaving pair.
      now: function (): number {
        return Date.now();
      },
      loadOauth2: lazy('loadOauth2', '../oauth-oidc/oauth2'),
      loadGate: lazy('loadGate', '../common/access_gate'),
      loadRoles: lazy('loadRoles', '../common/roles'),
      loadOwnership: lazy('loadOwnership', '../common/ownership'),
      loadApplications: lazy('loadApplications', '../common/applications'),
      loadAdmin: lazy('loadAdmin', './authzen_admin'),
      loadMailUses: lazy('loadMailUses', '../common/mail_uses'),
      loadFedHttp: lazy('loadFedHttp', '../federation/federation_http'),
      loadScheduler: lazy('loadScheduler', '../cluster/scheduler'),
      loadAccessPep: lazy('loadAccessPep', '../xacml/xacml_access_pep'),
      // The catalogs `display` is drawn from (#1204). A leaf.
      loadI18n: lazy('loadI18n', '../common/i18n')
    };
  }

  // -------------------------------------------------------------------------
  // SETTINGS
  // -------------------------------------------------------------------------
  /**
   * Whether the profile answers in this realm (`authzen.accessRequests`).
   *
   * @returns true unless switched off
   */
  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering AccessRequests.enabled().");
    log.debug("Leaving AccessRequests.enabled().");
    return config.value('authzen.accessRequests') !== false;
  }

  // -------------------------------------------------------------------------
  // THE DISPLAY HINTS (#1204; the profile's sections 5.1, 7.1 and 11.11).
  // Hints for a person, never policy (13.4): nothing reads them back, they
  // are not bound and a submission never echoes them. They name no
  // approver, role, group, policy or tuple (19, and 13.3.3).
  // -------------------------------------------------------------------------
  /**
   * Whether the display hints are sent (`authzen.accessRequestDisplay`).
   *
   * @returns true when on
   */
  displays(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering AccessRequests.displays().");
    log.debug("Leaving AccessRequests.displays().");
    return config.value('authzen.accessRequestDisplay') === true;
  }

  /**
   * The languages a request's `Accept-Language` asks for, best first.
   *
   * @param req - the request, or nothing
   * @returns canonical tags
   */
  languagesOf(req: Req | null | undefined): string[] {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.languagesOf().");
    const header = req && req.headers
      ? req.headers['accept-language'] : '';
    if (!header) {
      log.debug("Leaving AccessRequests.languagesOf(). None asked.");
      return [];
    }
    let out: string[] = [];
    try {
      out = this.deps.loadI18n().acceptLanguage(String(header));
    } catch (e) {
      // A header that cannot be read asks for nothing: English.
      log.debug("Caught in AccessRequests.languagesOf(): " +
                ((e && e.message) || e));
      out = [];
    }
    log.debug("Leaving AccessRequests.languagesOf(). " + out.join(' '));
    return out;
  }

  /**
   * A translator for those languages, English when nothing answers.
   *
   * @param languages - canonical tags, best first
   * @returns the translator, or null when none can be built
   */
  private translatorFor(languages: string[]): Json {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.translatorFor().");
    let out: Json = null;
    try {
      out = this.deps.loadI18n().translator(languages || []);
    } catch (e) {
      // No catalog: no display. The hints are optional (5.1, 7.1).
      log.debug("Caught in AccessRequests.translatorFor(): " +
                ((e && e.message) || e));
      out = null;
    }
    log.debug("Leaving AccessRequests.translatorFor(). " + !!out);
    return out;
  }

  /**
   * A requestable denial's `display`: the advice's own text when it gave
   * any, else the service's, in the asked language.
   *
   * @param terms - the advice's terms
   * @param languages - the evaluation request's languages
   * @returns `{ title, description }`, or null when off
   */
  denialDisplay(terms: Terms, languages: string[]): Json | null {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.denialDisplay().");
    if (!self.displays()) {
      log.debug("Leaving AccessRequests.denialDisplay(). Off.");
      return null;
    }
    const t = (terms.displayTitle && terms.displayDescription)
      ? null : self.translatorFor(languages);
    const title = terms.displayTitle ||
      (t ? String(t.text('authzenDisplay.denialTitle')) : '');
    const description = terms.displayDescription ||
      (t ? String(t.text('authzenDisplay.denialDescription')) : '');
    const out: Json = {};
    if (title) {
      out.title = title;
    }
    if (description) {
      out.description = description;
    }
    log.debug("Leaving AccessRequests.denialDisplay().");
    return Object.keys(out).length ? out : null;
  }

  /**
   * A Task Handle's `display`, for its status, in the asked language.
   *
   * @param status - the task's status
   * @param languages - the caller's languages
   * @returns `{ title, description }`, or null when off
   */
  taskDisplay(status: string, languages: string[]): Json | null {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.taskDisplay(). " + status);
    if (!self.displays() || STATES.indexOf(status) < 0) {
      log.debug("Leaving AccessRequests.taskDisplay(). Off.");
      return null;
    }
    const t = self.translatorFor(languages);
    if (!t) {
      log.debug("Leaving AccessRequests.taskDisplay(). No catalog.");
      return null;
    }
    const out = {
      title: String(t.text('authzenDisplay.taskTitle',
                           { status: status })),
      description: String(t.text('authzenDisplay.taskDescription',
                                 { status: status }))
    };
    log.debug("Leaving AccessRequests.taskDisplay().");
    return out;
  }

  // An integer setting, read directly (never `|| n`, the root CLAUDE.md's
  // rule: the row's own min and max bound it).
  private seconds(key: string): number {
    const { log, config } = this.deps;
    log.debug("Entering AccessRequests.seconds(). " + key);
    log.debug("Leaving AccessRequests.seconds().");
    return Number(config.value(key));
  }

  // The current time in epoch seconds. A hot path (every read of a task and
  // of an index row): no Entering/Leaving pair.
  private nowS(): number {
    return Math.floor(this.deps.now() / 1000);
  }

  // -------------------------------------------------------------------------
  // THE PURE HELPERS: the profile's structural comparison, and the JSON a
  // digest is taken over.
  // -------------------------------------------------------------------------
  /**
   * A value as canonical JSON: object members sorted, so two values equal
   * under the profile's structural comparison (same JSON types, strings
   * codepoint for codepoint, arrays in order, the same member names, an
   * absent member distinct from `null`) write the same text.
   *
   * @param value - the value
   * @returns the text
   */
  static canonical(value: unknown): string {
    log.debug("Entering AccessRequests.canonical().");
    // A hot path (every member of every compared object): no
    // Entering/Leaving pair.
    const walk = function (one: any): string {
      if (Array.isArray(one)) {
        return '[' + one.map(walk).join(',') + ']';
      }
      if (one && typeof one === 'object') {
        return '{' + Object.keys(one).filter(function (key: string) {
          return one[key] !== undefined;
        }).sort().map(function (key: string) {
          return JSON.stringify(key) + ':' + walk(one[key]);
        }).join(',') + '}';
      }
      return one === undefined ? 'null' : JSON.stringify(one);
    };
    log.debug("Leaving AccessRequests.canonical().");
    return walk(value);
  }

  /**
   * A subject, resource or action as the binding compares it: the object
   * whole, less `subject.properties.act` (the profile's exclusion, so an
   * actor normalised to `client.actor` compares the same), and less any
   * member the evaluation's model does not name. AuthZEN 1.0 section
   * 10.1.1 has those IGNORED (#936), so one may neither be signed into a
   * denial nor make a submission differ from it.
   *
   * @param name - subject, resource or action
   * @param value - the object
   * @returns a copy
   */
  static bound(name: string, value: unknown): Json {
    log.debug("Entering AccessRequests.bound(). " + name);
    if (!isObject(value)) {
      log.debug("Leaving AccessRequests.bound(). Not an object.");
      return value === undefined ? null : value;
    }
    const out = JSON.parse(JSON.stringify(value));
    const named = authzenModel.fieldOf('evaluation', name).fields
      .map(function (one: Json) {
        return one.name;
      });
    Object.keys(out).forEach(function (key: string) {
      if (named.indexOf(key) < 0) {
        delete out[key];
      }
    });
    if (name === 'subject' && isObject(out.properties)) {
      delete out.properties.act;
      if (!Object.keys(out.properties).length) {
        delete out.properties;
      }
    }
    log.debug("Leaving AccessRequests.bound().");
    return out;
  }

  /**
   * The authorization-relevant context: the members the advice named, as
   * the request carried them (absent ones left absent).
   *
   * @param context - the request's context
   * @param members - the member names
   * @returns the bound members
   */
  static relevant(context: unknown, members: string[]): Json {
    log.debug("Entering AccessRequests.relevant().");
    const given: Json = isObject(context) ? context : {};
    const out: Json = {};
    (members || []).forEach(function (name: string) {
      if (MACHINERY.indexOf(name) < 0 &&
          Object.prototype.hasOwnProperty.call(given, name)) {
        out[name] = given[name];
      }
    });
    log.debug("Leaving AccessRequests.relevant().");
    return out;
  }

  /**
   * The profile's hashed binding: base64url (no padding) SHA-256 of the
   * RFC 8785 canonical JSON of `{ subject, resource, action, context }`.
   * The subject is already bound (`bound()`), and the context is the set
   * `binding_context_members` names, which may be empty.
   *
   * @param subject - the bound subject
   * @param resource - the bound resource
   * @param action - the bound action
   * @param context - the bound context
   * @returns the hash
   */
  static bindingHash(subject: Json, resource: Json, action: Json,
                     context: Json): string {
    log.debug("Entering AccessRequests.bindingHash().");
    const jcs = stsCrypto.jcsCanonicalJson({
      subject: subject === undefined ? null : subject,
      resource: resource === undefined ? null : resource,
      action: action === undefined ? null : action,
      context: isObject(context) ? context : {}
    });
    const out = String(stsCrypto.digest('sha256', jcs, 'base64url'));
    log.debug("Leaving AccessRequests.bindingHash().");
    return out;
  }

  /**
   * Whether a request's tuple is the stored one: subject, resource and
   * action bound the same way, and the named context members.
   *
   * @param stored - the denial or the approval, already bound
   * @param given - the request
   * @param members - the context members that bind
   * @returns true when they match
   */
  private static sameTuple(stored: Json, given: Json,
                           members: string[]): boolean {
    log.debug("Entering AccessRequests.sameTuple().");
    let same = true;
    ['subject', 'resource', 'action'].forEach(function (name: string) {
      if (same && AccessRequests.canonical(AccessRequests.bound(name,
            given[name])) !== AccessRequests.canonical(stored[name])) {
        same = false;
      }
    });
    if (same && AccessRequests.canonical(AccessRequests.relevant(
          given.context, members || [])) !==
        AccessRequests.canonical(stored.context || {})) {
      same = false;
    }
    log.debug("Leaving AccessRequests.sameTuple(). " + same);
    return same;
  }

  /**
   * Reads the access-request advice of a PDP answer into approval terms,
   * or null when the answer carries none.
   *
   * @param advice - the answer's advice, as `xacml_pdp.js` returns it
   * @returns the terms, or null
   */
  static termsOf(advice: Json[]): Terms | null {
    log.debug("Entering AccessRequests.termsOf().");
    const found = (advice || []).filter(function (one: Json) {
      return one && String(one.id) === ADVICE_ID;
    });
    if (!found.length) {
      log.debug("Leaving AccessRequests.termsOf(). No advice.");
      return null;
    }
    const out: Terms = { roles: [], groups: [], owners: false,
                         maxSeconds: 0, emergency: false,
                         contextMembers: [], template: '', reason: '' };
    found.forEach(function (one: Json) {
      (one.assignments || []).forEach(function (a: Json) {
        const id = String(a.attributeId || '');
        if (id.indexOf(ADVICE_PREFIX) !== 0) {
          return;
        }
        let value: unknown = a.value;
        try {
          value = datatypes.writeValue(a.type, a.value);
        } catch (e) {
          // The engine's own value, as it holds it; read as text below.
          log.debug("Caught in AccessRequests.termsOf(): " +
                    ((e && e.message) || e));
        }
        const text = String(value == null ? '' : value).trim();
        const name = id.slice(ADVICE_PREFIX.length);
        // A hot path of one read: no Entering/Leaving pair.
        const add = function (list: string[]): void {
          if (text && list.length < MAX_LIST && list.indexOf(text) < 0) {
            list.push(text.slice(0, 256));
          }
        };
        if (name === 'approver-role') {
          add(out.roles);
        } else if (name === 'approver-group') {
          add(out.groups);
        } else if (name === 'approver-owners') {
          out.owners = out.owners || text === 'true';
        } else if (name === 'max-approval-seconds') {
          const n = Math.floor(Number(text));
          if (n > 0 && (!out.maxSeconds || n < out.maxSeconds)) {
            out.maxSeconds = n;
          }
        } else if (name === 'emergency') {
          out.emergency = out.emergency || text === 'true';
        } else if (name === 'context-member') {
          add(out.contextMembers);
        } else if (name === 'template') {
          out.template = out.template || text.slice(0, 128);
        } else if (name === 'reason') {
          out.reason = out.reason || text.slice(0, 128);
        } else if (name === 'display-title') {
          // The policy author's words (#1204): kept as written, cut,
          // never translated.
          out.displayTitle = out.displayTitle || text.slice(0, 256);
        } else if (name === 'display-description') {
          out.displayDescription = out.displayDescription ||
            text.slice(0, MAX_TEXT);
        } else if (name === 'entitlement') {
          // `value` or `value|label` (#1204): one catalog item.
          const cut = text.indexOf('|');
          const value = (cut < 0 ? text : text.slice(0, cut)).trim()
            .slice(0, MAX_ID);
          const label = (cut < 0 ? '' : text.slice(cut + 1)).trim()
            .slice(0, 256) || value;
          const list = out.entitlements || [];
          if (value && list.length < MAX_LIST &&
              !list.some(function (one) {
                return one.value === value;
              })) {
            list.push({ value: value, label: label });
          }
          out.entitlements = list;
        }
      });
    });
    log.debug("Leaving AccessRequests.termsOf(). " + out.roles.length +
              " role(s), " + out.groups.length + " group(s), owners " +
              out.owners + ".");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE REQUESTABLE DENIAL (the profile's section on it).
  // -------------------------------------------------------------------------
  /**
   * The base URL of this realm's PDP, as the request reached it.
   *
   * @param req - the request
   * @returns the base, the realm's prefix included
   */
  baseOf(req: Req): string {
    const { log, helpers } = this.deps;
    log.debug("Entering AccessRequests.baseOf().");
    log.debug("Leaving AccessRequests.baseOf().");
    return String(helpers.baseUrlOf(req, 'authzen') || '');
  }

  /**
   * The Decision Context members that make a denial requestable:
   * `evaluation_id`, `evaluated_at`, `reason` and `access_request`, with a
   * `binding_token` this realm signed over the denied tuple, a record
   * of that denial keyed by `evaluation_id`, and `request_schema_url`.
   * Null when the profile is off,
   * the answer carries no access-request advice, or the token could not be
   * signed — in each case the denial stays an ordinary `false` (the
   * profile: no `access_request` without verifiable binding material).
   *
   * @param req - the request, for the base
   * @param body - the evaluation request as the caller sent it
   * @param terms - the advice's terms
   * @param caller - the trusted caller's name
   * @param application - the trusted application
   * @returns the context members, or null
   */
  requestableDenial(req: Req, body: Json, terms: Terms | null,
                    caller: string, application: string): Json | null {
    const self = this;
    const { log, errorCodes, helpers } = this.deps;
    log.debug("Entering AccessRequests.requestableDenial().");
    if (!terms || !self.enabled()) {
      log.debug("Leaving AccessRequests.requestableDenial(). Not " +
                "requestable.");
      return null;
    }
    const base = self.baseOf(req);
    const now = self.nowS();
    const lifetime = self.seconds('authzen.accessRequestDenialLifetimeS');
    const expiresAt = instant((now + lifetime) * 1000);
    const evaluationId = 'eval_' + helpers.randomId(18);
    const given: Json = isObject(body) ? body : {};
    const subject = AccessRequests.bound('subject', given.subject);
    const resource = AccessRequests.bound('resource', given.resource);
    const action = AccessRequests.bound('action', given.action);
    const context = AccessRequests.relevant(given.context,
                                             terms.contextMembers);
    let hash = '';
    try {
      hash = AccessRequests.bindingHash(subject, resource, action, context);
    } catch (e) {
      // No verifiable binding without the hash the token claims. The
      // denial stays an ordinary false, the same as a signature that
      // could not be made.
      log.debug("Caught in AccessRequests.requestableDenial(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-AUTHZEN-0087') + 'authzen: a ' +
                'requestable denial\'s binding_hash could not be made, so ' +
                'the denial is answered as an ordinary false: ' +
                ((e && e.message) || e));
      log.debug("Leaving AccessRequests.requestableDenial(). No hash.");
      return null;
    }
    const jti = helpers.randomId(18);
    const claims: Json = {
      aud: base + REQUESTS_PATH,
      sub: String((given.subject || {}).id || ''),
      jti: jti,
      typ: 'authzen-access-request-denial',
      denial_expires_at: expiresAt,
      evaluation_id: evaluationId,
      subject: subject,
      resource: resource,
      action: action,
      context: context,
      binding_context_members: terms.contextMembers.slice(0),
      binding_hash: hash,
      caller: caller,
      application: application,
      terms: terms
    };
    let token = '';
    try {
      token = String(self.deps.loadOauth2().signPublishedDocument(
        claims, base, lifetime, 'oauth-signed-metadata') || '');
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHZEN-0087') + 'authzen: a ' +
                'requestable denial\'s binding_token could not be signed, ' +
                'so the denial is answered as an ordinary false: ' +
                ((e && e.message) || e));
      token = '';
    }
    if (!token) {
      log.debug("Leaving AccessRequests.requestableDenial(). Not signed.");
      return null;
    }
    let exp = now + lifetime;
    try {
      const part = token.split('.')[1] || '';
      const payload = JSON.parse(Buffer.from(part, 'base64url')
        .toString('utf8'));
      if (payload && Number(payload.exp) > 0) {
        exp = Number(payload.exp);
      }
    } catch (e) {
      // The lifetime asked of the signer is the expiry the record keeps.
      log.debug("Caught in AccessRequests.requestableDenial(): " +
                ((e && e.message) || e));
    }
    const deadline = Math.min(exp,
      Math.floor(Date.parse(expiresAt) / 1000) || exp);
    const recorded = self.recordDenial({
      evaluationId: evaluationId,
      jti: jti,
      subject: subject,
      resource: resource,
      action: action,
      context: context,
      bindingContextMembers: terms.contextMembers.slice(0),
      bindingHash: hash,
      caller: caller,
      application: application,
      terms: terms,
      denialExpiresAt: expiresAt,
      exp: exp,
      base: base,
      evaluatedAt: instant(now * 1000),
      reason: terms.reason || 'approval_required',
      template: terms.template || '',
      keepUntil: deadline + SKEW_S + RETENTION_S
    });
    const accessRequest: Json = { expires_at: expiresAt,
                                  endpoint: base + REQUESTS_PATH,
                                  request_schema_url: base + SCHEMA_PATH,
                                  binding_token: token };
    if (terms.template) {
      accessRequest.template = terms.template;
    }
    const display = self.denialDisplay(terms, self.languagesOf(req));
    if (display) {
      accessRequest.display = display;
    }
    // THE HOSTED FORM (#1204) works from the denial's record, so a denial
    // the record could not keep (the 0144 cap) names no form.
    if (recorded && self.formOn()) {
      accessRequest.form_url = self.formUrlOf(base, evaluationId);
    }
    // THE CATALOG COMPANION (#1204, its section 5): only for a recorded
    // denial whose advice lists entitlements; `request_schema_url`, which
    // the draft requires beside it, is always present.
    if (recorded && self.catalogsOn() && (terms.entitlements || []).length) {
      accessRequest.request_catalogs_url = base + CATALOGS_PATH + '/' +
        encodeURIComponent(evaluationId);
    }
    log.debug("Leaving AccessRequests.requestableDenial().");
    return { evaluation_id: evaluationId, evaluated_at: instant(now * 1000),
             reason: terms.reason || 'approval_required',
             access_request: accessRequest };
  }

  // -------------------------------------------------------------------------
  // THE PROBLEM RESPONSES (RFC 9457, the profile's error section).
  // -------------------------------------------------------------------------
  /**
   * Writes an `application/problem+json` answer and marks its code.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param type - the profile's problem type's last segment, or '' for
   *   `about:blank`
   * @param code - the error code, recorded and never sent
   * @param detail - what the caller is told
   */
  // error-code: none — the helper's definition; each caller passes its code.
  problem(res: Res, status: number, type: string, code: string,
          detail: string): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AccessRequests.problem(). " + code);
    errorCodes.mark(res, code);
    // THE TYPE AND ITS TITLE ARE THE MODEL'S (`ProblemTypes`, #1579); a
    // refusal with none is `about:blank`, titled by its status.
    const named = type ? authzenModel.problemType(type) : null;
    // A 415 (#936) is titled for what it is: `about:blank`'s title is the
    // status's phrase (RFC 9457 section 4.2.1), and "Bad request" would
    // tell the caller the body was wrong when it was never read.
    const untitled = status >= 500 ? 'Server error'
      : status === 415 ? 'Unsupported media type'
        : status === 404 ? 'Not found' : 'Bad request';
    const body: Json = {
      type: named ? named.uri : 'about:blank',
      title: named ? named.title : untitled,
      status: status, detail: detail };
    authzenModel.hold('problem', body, 'an access request endpoint');
    res.status(status).type('application/problem+json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving AccessRequests.problem().");
  }

  // -------------------------------------------------------------------------
  // THE TASK
  // -------------------------------------------------------------------------
  // Re-sets a row after an in-place edit: the journal sees `set`, never an
  // edit (gnap_store.ts's rule).
  private save(task: Json): void {
    const { log, tasks } = this.deps;
    log.debug("Entering AccessRequests.save(). " + task.id + " " +
              task.status);
    tasks.set(task.id, task);
    this.noteSubject(task);
    this.notePending(task);
    this.noteApprover(task);
    log.debug("Leaving AccessRequests.save().");
  }

  // -------------------------------------------------------------------------
  // THE PENDING AND APPROVER INDEXES (#1203): what a portal page lists is
  // read through them, so its cost is the person's own rows (an approver's
  // approvals) or the pending tasks (bounded by
  // `authzen.accessRequestMaxPending`), never every task the realm keeps.
  // Each row is a list of task ids in `index`, written by `save()` (one
  // get, and a set only when it changes). Two writers in two processes can
  // lose one another's id; the sweep job walks every task already and puts
  // a missing one back, so a list is at most a minute behind the store.
  // -------------------------------------------------------------------------
  // Adds a task id to an index row, kept until at least `until`.
  private noteUnder(key: string, id: string, until: number): void {
    const { log, index } = this.deps;
    log.debug("Entering AccessRequests.noteUnder().");
    const row = index.get(key);
    const ids: string[] = row && Array.isArray(row.tasks)
      ? row.tasks.slice(0) : [];
    const was = row ? Number(row.until) || 0 : 0;
    const keep = Math.max(was, Number(until) || 0);
    if (row && ids.indexOf(id) >= 0 && was >= keep) {
      log.debug("Leaving AccessRequests.noteUnder(). Already noted.");
      return;
    }
    if (ids.indexOf(id) < 0) {
      ids.push(id);
    }
    index.set(key, { tasks: ids, until: keep });
    log.debug("Leaving AccessRequests.noteUnder().");
  }

  // Takes a task id out of an index row, and the row out when it empties.
  private unnoteUnder(key: string, id: string): void {
    const { log, index } = this.deps;
    log.debug("Entering AccessRequests.unnoteUnder().");
    const row = index.get(key);
    if (!row || !Array.isArray(row.tasks) || row.tasks.indexOf(id) < 0) {
      log.debug("Leaving AccessRequests.unnoteUnder(). Not noted.");
      return;
    }
    const ids = row.tasks.filter(function (one: string) {
      return one !== id;
    });
    if (!ids.length) {
      index.delete(key);
    } else {
      index.set(key, { tasks: ids, until: row.until });
    }
    log.debug("Leaving AccessRequests.unnoteUnder().");
  }

  // The ids an index row lists.
  private idsUnder(key: string): string[] {
    const { log, index } = this.deps;
    log.debug("Entering AccessRequests.idsUnder().");
    const row = index.get(key);
    const out: string[] = row && Array.isArray(row.tasks)
      ? row.tasks.map(String) : [];
    log.debug("Leaving AccessRequests.idsUnder(). " + out.length);
    return out;
  }

  // A pending task is listed; a finished one is taken off.
  private notePending(task: Json): void {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.notePending().");
    if (!task || !task.id) {
      log.debug("Leaving AccessRequests.notePending(). No id.");
      return;
    }
    if (task.status === 'pending') {
      this.noteUnder(PENDING_KEY, String(task.id),
                     Number(task.expiresAt) + RETENTION_S);
    } else {
      this.unnoteUnder(PENDING_KEY, String(task.id));
    }
    log.debug("Leaving AccessRequests.notePending().");
  }

  // The index key of one approver's approvals.
  private static approverKey(username: string): string {
    log.debug("Entering AccessRequests.approverKey().");
    log.debug("Leaving AccessRequests.approverKey().");
    return APPROVER_PREFIX + stsCrypto.credentialDigest(
      String(username == null ? '' : username).trim().toLowerCase());
  }

  // An approval is listed under the person who gave it.
  private noteApprover(task: Json): void {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.noteApprover().");
    const approval = task && task.approval;
    if (!approval || !approval.approver || !task.id) {
      log.debug("Leaving AccessRequests.noteApprover(). No approver.");
      return;
    }
    this.noteUnder(AccessRequests.approverKey(String(approval.approver)),
                   String(task.id), Number(task.keepUntil) || 0);
    log.debug("Leaving AccessRequests.noteApprover().");
  }

  // -------------------------------------------------------------------------
  // THE SUBJECT INDEX (2026-11-16, #1612's rule: a person deleted and made
  // again under the same name inherits nothing).
  //
  // A task names its subject as the PEP sent it — a username, as often as
  // not — and an approval is verified by an exact match of that subject. So
  // a person made again under a deleted person's name was the subject of the
  // deleted person's approvals: a PEP presenting one was answered approved.
  // A person's delete therefore ends their tasks (`forgetSubject()`, from
  // `ldap_server.js`'s `forgetPersonHoldings()`): a pending one is
  // cancelled, an approved one's approval revoked, each with its audit row.
  // To find them without walking the store, each subject's task ids are an
  // index row — `subject:<SHA-256 of the lower-cased id>` in `index`, the
  // module's own per-realm store — written by `save()` (one get, and a set
  // only when the row changes) and kept as long as the latest of its tasks;
  // a task the sweep removes leaves it. A task written before this existed
  // is noted by the sweep job, which walks every task already: the
  // backfill, within a minute of the upgrade, and never on the delete path.
  // -------------------------------------------------------------------------
  private static subjectKey(id: string): string {
    log.debug("Entering AccessRequests.subjectKey().");
    log.debug("Leaving AccessRequests.subjectKey().");
    return 'subject:' + stsCrypto.credentialDigest(
      String(id == null ? '' : id).trim().toLowerCase());
  }

  // A task's subject id, trimmed; '' when it has none.
  private static subjectOf(task: Json): string {
    log.debug("Entering AccessRequests.subjectOf().");
    log.debug("Leaving AccessRequests.subjectOf().");
    return String(((task && task.subject) || {}).id || '').trim();
  }

  // Notes a task under its subject.
  private noteSubject(task: Json): void {
    const { log, index } = this.deps;
    log.debug("Entering AccessRequests.noteSubject().");
    const subject = AccessRequests.subjectOf(task);
    if (!subject || !task.id) {
      log.debug("Leaving AccessRequests.noteSubject(). No subject.");
      return;
    }
    const key = AccessRequests.subjectKey(subject);
    const row = index.get(key);
    const ids: string[] = row && Array.isArray(row.tasks)
      ? row.tasks.slice(0) : [];
    const was = row ? Number(row.until) || 0 : 0;
    const until = Math.max(was, Number(task.keepUntil) || 0);
    if (row && ids.indexOf(task.id) >= 0 && was >= until) {
      log.debug("Leaving AccessRequests.noteSubject(). Already noted.");
      return;
    }
    if (ids.indexOf(task.id) < 0) {
      ids.push(task.id);
    }
    index.set(key, { tasks: ids, until: until });
    log.debug("Leaving AccessRequests.noteSubject().");
  }

  // Takes a removed task out of its subject's row.
  private unnoteSubject(task: Json): void {
    const { log, index } = this.deps;
    log.debug("Entering AccessRequests.unnoteSubject().");
    const subject = AccessRequests.subjectOf(task);
    const key = subject ? AccessRequests.subjectKey(subject) : '';
    const row = key ? index.get(key) : null;
    if (!row || !Array.isArray(row.tasks)) {
      log.debug("Leaving AccessRequests.unnoteSubject(). Not noted.");
      return;
    }
    const ids = row.tasks.filter(function (one: string) {
      return one !== task.id;
    });
    if (!ids.length) {
      index.delete(key);
    } else if (ids.length !== row.tasks.length) {
      index.set(key, { tasks: ids, until: row.until });
    }
    log.debug("Leaving AccessRequests.unnoteSubject().");
  }

  /**
   * Ends every task of the ambient realm whose subject is one of a deleted
   * person's identifiers, found through the subject index: a pending one
   * cancelled, an approved one's approval revoked, each with its audit row.
   * So a person made again under the name is the subject of none of them.
   *
   * @param ids - the deleted person's identifiers (the username, and the
   *   `urn:uuid:` subject and mail addresses a PEP may have sent instead)
   * @returns how many tasks were ended
   */
  forgetSubject(ids: string | string[]): number {
    const self = this;
    const { log, index, audit } = this.deps;
    log.debug("Entering AccessRequests.forgetSubject().");
    const wanted = ([] as string[]).concat(ids || [])
      .map(function (one: string) {
        return String(one == null ? '' : one).trim().toLowerCase();
      }).filter(function (one: string) {
        return !!one;
      });
    let ended = 0;
    wanted.forEach(function (subject: string) {
      const key = AccessRequests.subjectKey(subject);
      const row = index.get(key);
      ((row && row.tasks) || []).forEach(function (id: string) {
        const task = self.task(String(id));
        if (!task ||
            AccessRequests.subjectOf(task).toLowerCase() !== subject) {
          return;
        }
        const why = 'its subject, ' + AccessRequests.subjectOf(task) +
                    ', was deleted from the directory';
        if (task.status === 'pending') {
          if (self.finish(task, 'cancelled',
                          { actor: 'the directory', why: why })) {
            ended += 1;
          }
        } else if (task.status === 'approved' && task.approval &&
                   !task.approval.revokedAt) {
          task.approval.revokedAt = self.nowS();
          self.save(task);
          audit.audit({ action: 'authzen.access-request.revoked',
                        actor: 'the directory', protocol: 'AuthZEN',
                        detail: 'The approval of ' + task.id + ' was ' +
                                'revoked: ' + why + '; a re-evaluation ' +
                                'carrying it is not approved from now on.' });
          ended += 1;
        }
      });
      // AFTER the saves above, which note the subject again.
      if (row) {
        index.delete(key);
      }
    });
    log.debug("Leaving AccessRequests.forgetSubject(). " + ended);
    return ended;
  }

  // One index row, kept until `until` (epoch seconds).
  private remember(kind: string, value: string, taskId: string,
                   extra: Json, until: number): void {
    const { log, index } = this.deps;
    log.debug("Entering AccessRequests.remember(). " + kind);
    index.set(kind + ':' + stsCrypto.credentialDigest(value),
              Object.assign({ task: taskId, until: until }, extra || {}));
    log.debug("Leaving AccessRequests.remember().");
  }

  // The index row for a value, or null.
  private recalled(kind: string, value: string): Json {
    const { log, index } = this.deps;
    log.debug("Entering AccessRequests.recalled(). " + kind);
    const row = value ? index.get(kind + ':' +
                                  stsCrypto.credentialDigest(value)) : null;
    const live = row && Number(row.until) > this.nowS() ? row : null;
    log.debug("Leaving AccessRequests.recalled(). " + !!live);
    return live;
  }

  /**
   * One task by its id, with its deadline applied at the read: a pending
   * task past its `expires_at` reads as expired whenever the job last ran
   * (correctness rather than housekeeping, the root CLAUDE.md's rule).
   *
   * @param id - the task id
   * @returns the row, or null
   */
  task(id: string): Json {
    const self = this;
    const { log, tasks } = this.deps;
    log.debug("Entering AccessRequests.task().");
    const row = id ? tasks.get(String(id)) : null;
    if (!row) {
      log.debug("Leaving AccessRequests.task(). None.");
      return null;
    }
    if (row.status === 'pending' && Number(row.expiresAt) <= self.nowS()) {
      self.finish(row, 'expired', { actor: 'the access request service',
                                    why: 'it reached its expires_at' });
    }
    log.debug("Leaving AccessRequests.task(). " + row.status);
    return row;
  }

  /**
   * The Task Handle a PEP is answered (the profile's task object): never
   * the approver, the policy or the tuple, which a status response must not
   * disclose to a caller not authorized for them.
   *
   * @param task - the row
   * @param languages - the caller's languages, for `display` (#1204);
   *   absent where nobody asked, as on a callback, and then no display
   * @returns the handle
   */
  handleOf(task: Json, languages?: string[]): Json {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.handleOf().");
    const out: Json = {
      id: task.id,
      status: task.status,
      status_endpoint: task.base + REQUESTS_PATH + '/' + task.id,
      expires_at: instant(Number(task.status === 'pending'
        ? task.expiresAt : task.keepUntil) * 1000)
    };
    if (task.status === 'pending') {
      out.links = { cancel: out.status_endpoint + '/cancel' };
      out.progress = { current_step: 1, total_steps: 1,
                       step_name: 'approval' };
    }
    const display = languages ? this.taskDisplay(task.status, languages)
      : null;
    if (display) {
      out.display = display;
    }
    // THE TICKET (sections 7.1 and 11.11, #1204): where the subject sees
    // the request, while the hosted form is on.
    if (this.formOn()) {
      out.links = Object.assign(out.links || {},
                                { ticket: this.ticketUrlOf(task) });
    }
    log.debug("Leaving AccessRequests.handleOf().");
    return out;
  }

  /**
   * The response body for a task: the handle, and the `reevaluate` result
   * once it is approved (the profile: REQUIRED then).
   *
   * @param task - the row
   * @param languages - the caller's languages, for `display`
   * @returns `{ task, result? }`
   */
  bodyOf(task: Json, languages?: string[]): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.bodyOf().");
    const out: Json = { task: self.handleOf(task, languages || []) };
    if (task.status === 'approved' && task.approval) {
      const approval: Json = { id: task.approval.id,
                               approved_at: instant(
                                 task.approval.approvedAt * 1000),
                               approved_until: instant(
                                 task.approval.approvedUntil * 1000) };
      if (task.approval.state) {
        approval.state = task.approval.state;
      }
      out.result = { mode: 'reevaluate', approval: approval };
    }
    // Every answer this body is sent in is held to the model's Task
    // response (#1579): a gap is recorded, the answer is unchanged.
    authzenModel.hold('task-response', out, 'an access request endpoint');
    log.debug("Leaving AccessRequests.bodyOf().");
    return out;
  }

  /**
   * Moves a pending task to a terminal status, exactly once: the audit
   * row, the retention, and the callback. A task already finished is left
   * as it is.
   *
   * @param task - the row, edited in place and re-set
   * @param status - the terminal status
   * @param why - `{ actor, why, code }` for the audit row
   * @returns true when it moved
   */
  finish(task: Json, status: string, why: Json): boolean {
    const self = this;
    const { log, audit } = this.deps;
    log.debug("Entering AccessRequests.finish(). " + task.id + " " + status);
    if (task.status !== 'pending' || STATES.indexOf(status) < 1) {
      log.debug("Leaving AccessRequests.finish(). Already " + task.status +
                ".");
      return false;
    }
    const now = self.nowS();
    task.status = status;
    task.finishedAt = now;
    task.keepUntil = Math.max(now + RETENTION_S,
      task.approval ? Number(task.approval.approvedUntil) : 0);
    if (status === 'failed') {
      // `failed` is the status of a step that could not be written, so a
      // store that will not take this write either still gets the audit
      // row and the callback below: those are the record then.
      try {
        self.save(task);
      } catch (e) {
        log.debug("Caught in AccessRequests.finish(): " +
                  ((e && e.message) || e));
        log.error(self.deps.errorCodes.tag('STS-AUTHZEN-0142') +
                  'authzen: the failed access request ' + task.id +
                  ' could not be stored either: ' + ((e && e.message) || e));
      }
    } else {
      self.save(task);
    }
    // The idempotency key lives as long as the task, the profile's SHOULD.
    if (task.idempotency) {
      self.deps.index.set(task.idempotency.key,
        Object.assign({}, task.idempotency.row,
                      { until: task.keepUntil }));
    }
    audit.audit({
      action: 'authzen.access-request.' + status,
      actor: String((why && why.actor) || ''),
      protocol: 'AuthZEN',
      errorCode: (why && why.code) || undefined,
      detail: 'The access request ' + task.id + ' from ' + task.requester +
        ' (application "' + task.application + '") is ' + status +
        ((why && why.why) ? ': ' + String(why.why) : '') + '.'
    });
    self.notify(task);
    log.debug("Leaving AccessRequests.finish().");
    return true;
  }

  // Writes the denial record. A failure leaves the token issued: the
  // by-value form still verifies, and an evaluation_id of this denial is
  // then unknown (0073).
  //
  // A SIZE CAP, AT THE INSERT (#1204): `authzen.accessRequestMaxDenials`
  // rows per realm. A full store records nothing new, and the denial is
  // still requestable by its binding_token; an evaluation_id-only
  // submission of it is then unknown (0073). The full store is logged when
  // it fills and when it has room again, never once per denial.
  private recordDenial(record: Json): boolean {
    const { log, errorCodes, denials, audit } = this.deps;
    log.debug("Entering AccessRequests.recordDenial().");
    const id = String(record.evaluationId);
    const cap = this.seconds('authzen.accessRequestMaxDenials');
    const realms = this.deps.realms;
    const realm = String((realms && typeof realms.currentId === 'function'
      ? realms.currentId() : '') || '');
    const held = typeof denials.size === 'number' ? denials.size : 0;
    if (cap > 0 && held >= cap && !denials.get(id)) {
      if (!denialsFull.has(realm)) {
        denialsFull.add(realm);
        log.warn(errorCodes.tag('STS-AUTHZEN-0144') + 'authzen: this ' +
                 'realm holds ' + held + ' requestable denials ' +
                 '(authzen.accessRequestMaxDenials), so new ones are not ' +
                 'recorded; each is still requestable by its ' +
                 'binding_token.');
        audit.audit({ action: 'authzen.access-request.denials-full',
                      actor: 'the access request service',
                      protocol: 'AuthZEN', errorCode: 'STS-AUTHZEN-0144',
                      detail: 'The requestable denial store is full (' +
                              held + ' of ' + cap + '). A new denial is ' +
                              'requestable by its binding_token only ' +
                              'until the job removes old ones.' });
      }
      log.debug("Leaving AccessRequests.recordDenial(). Full.");
      return false;
    }
    if (denialsFull.delete(realm)) {
      log.info('authzen: the requestable denial store has room again; ' +
               'denials are recorded by evaluation_id once more.');
    }
    try {
      denials.set(id, record);
    } catch (e) {
      log.debug("Caught in AccessRequests.recordDenial(): " +
                ((e && e.message) || e));
      log.debug("Leaving AccessRequests.recordDenial(). Not written.");
      log.error(errorCodes.tag('STS-AUTHZEN-0139') + 'authzen: the ' +
                'requestable denial ' + record.evaluationId + ' could not ' +
                'be recorded, so an evaluation_id-only submission of it ' +
                'cannot be resolved; the binding_token is still issued: ' +
                ((e && e.message) || e));
      return false;
    }
    log.debug("Leaving AccessRequests.recordDenial().");
    return true;
  }

  // The denial named by an evaluation_id, in the shape `submit()` reads off
  // a binding token, or null when this realm has none for this base that
  // it still keeps.
  private denialByEvaluation(evaluationId: string, base: string): Json | null {
    const { log, denials } = this.deps;
    log.debug("Entering AccessRequests.denialByEvaluation().");
    const id = String(evaluationId || '').slice(0, MAX_ID);
    const row = id ? denials.get(id) : null;
    let bound: Json = null;
    if (row && row.base === base && Number(row.keepUntil) > this.nowS()) {
      bound = {
        jti: row.jti,
        typ: 'authzen-access-request-denial',
        denial_expires_at: row.denialExpiresAt,
        evaluation_id: row.evaluationId,
        subject: row.subject,
        resource: row.resource,
        action: row.action,
        context: row.context || {},
        binding_context_members: row.bindingContextMembers || [],
        binding_hash: row.bindingHash,
        caller: row.caller,
        application: row.application,
        terms: row.terms,
        exp: row.exp
      };
    }
    log.debug("Leaving AccessRequests.denialByEvaluation(). " + !!bound);
    return bound;
  }

  // -------------------------------------------------------------------------
  // THE SUBMISSION (the profile's section on it).
  // -------------------------------------------------------------------------
  /**
   * Verifies one submission's shape, denial binding, freshness, tuple and
   * the caller's scope, without consuming anything (#1204: a bulk
   * submission's every item is checked by this, as a single one is).
   *
   * @param req - the request, for the base
   * @param caller - the admitted caller
   * @param body - the submission, or one bulk item made into one
   * @param scope - `(caller, application)` → the caller's scope check
   * @returns `{ bound, scoped, base }`, or `{ refusal }`
   */
  private verifyOne(req: Req, caller: Json, body: unknown,
                    scope: (caller: Json, application: string) => Json):
    Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.verifyOne().");
    const no = AccessRequests.refusal;
    // THE SHAPE IS THE MODEL'S (#1579): `AccessRequestSubmission` — the
    // members it takes, BULK's refused, the denied tuple's three objects.
    // `denial`, `requested_access` and `callback` are read at their own
    // places below, between the checks that need state.
    const shape = authzenModel.read('access-request', body);
    if (shape) {
      log.debug("Leaving AccessRequests.verifyOne(). " + shape.code);
      return no(400, '', shape.code, shape.message);
    }
    const given: Json = body;
    const denial = given.denial;
    const unbound = authzenModel.field('access-request', 'denial', denial);
    if (unbound) {
      log.debug("Leaving AccessRequests.verifyOne(). No denial.");
      return no(400, 'not_requestable', unbound.code, unbound.message);
    }
    const base = self.baseOf(req);
    // THE TOKEN IS AUTHORITATIVE WHEN IT IS PRESENT. evaluation_id is a
    // binding only with no token, resolved from the denial record. Either
    // way the echo and the freshness below run before anything is consumed.
    let bound: Json = null;
    if (denial.binding_token) {
      bound = self.verifyBinding(String(denial.binding_token), base);
      if (!bound) {
        log.debug("Leaving AccessRequests.verifyOne(). Did not verify.");
        return no(400, 'invalid_denial_binding', 'STS-AUTHZEN-0073',
                  'denial.binding_token is not one this realm issued ' +
                  'for this endpoint.');
      }
      if (denial.evaluation_id !== undefined &&
          String(denial.evaluation_id) !== String(bound.evaluation_id || '')) {
        log.debug("Leaving AccessRequests.verifyOne(). evaluation_id " +
                  "differs.");
        return no(400, 'invalid_denial_binding', 'STS-AUTHZEN-0074',
                  'denial.evaluation_id is not the evaluation the ' +
                  'binding_token names.');
      }
    } else {
      bound = self.denialByEvaluation(String(denial.evaluation_id || ''),
                                      base);
      if (!bound) {
        log.debug("Leaving AccessRequests.verifyOne(). No such denial.");
        return no(400, 'invalid_denial_binding', 'STS-AUTHZEN-0073',
                  'denial.evaluation_id names no requestable denial this ' +
                  'realm issued for this endpoint.');
      }
    }
    const now = self.nowS();
    const echoed = Date.parse(String(denial.expires_at || ''));
    if (String(denial.expires_at || '') !== String(bound.denial_expires_at)) {
      log.debug("Leaving AccessRequests.verifyOne(). expires_at differs.");
      return no(400, 'invalid_denial_binding', 'STS-AUTHZEN-0074',
                'denial.expires_at is not the value the denial carried; ' +
                'echo it unchanged.');
    }
    const deadline = Math.min(Number(bound.exp) || 0,
                              Math.floor(echoed / 1000) || 0);
    if (!(deadline > 0) || now > deadline + SKEW_S) {
      log.debug("Leaving AccessRequests.verifyOne(). Expired.");
      return no(410, 'expired_denial', 'STS-AUTHZEN-0075',
                'The requestable denial expired at ' +
                String(denial.expires_at) + '; evaluate again for a ' +
                'fresh one.');
    }
    const mismatch = self.bindingMismatch(bound, given, caller.name);
    if (mismatch) {
      log.debug("Leaving AccessRequests.verifyOne(). " + mismatch);
      return no(400, 'invalid_denial_binding', 'STS-AUTHZEN-0074',
                'The request does not match the denial it names: ' +
                mismatch + '.');
    }
    // A token that proved the tuple by hash and carried no inline claims:
    // the task's tuple is the submission's, now that the hash matched.
    if (!isObject(bound.subject)) {
      const members = bound.binding_context_members;
      bound.subject = AccessRequests.bound('subject', given.subject);
      bound.resource = AccessRequests.bound('resource', given.resource);
      bound.action = AccessRequests.bound('action', given.action);
      bound.context = Array.isArray(members)
        ? AccessRequests.relevant(given.context, members) : {};
    }
    // THE APPLICATION IS STILL THE CALLER'S: a scope taken away between
    // the denial and the submission ends the request here.
    const scoped = scope(caller, String(bound.application || ''));
    if (!scoped.application) {
      log.debug("Leaving AccessRequests.verifyOne(). Out of scope.");
      return no(403, '', 'STS-AUTHZEN-0077', 'This caller may no longer ' +
                'ask about the application "' +
                String(bound.application).slice(0, 120) + '".');
    }
    log.debug("Leaving AccessRequests.verifyOne().");
    return { bound: bound, scoped: scoped, base: base };
  }

  // A refusal `verifyOne()` hands back, written by its caller.
  private static refusal(status: number, type: string, code: string,
                         detail: string): Json {
    log.debug("Entering AccessRequests.refusal(). " + code);
    log.debug("Leaving AccessRequests.refusal().");
    return { refusal: { status: status, type: type, code: code,
                        detail: detail } };
  }

  /**
   * Answers one submission: the binding verified, the task made (or found
   * again by its Idempotency-Key or its binding token), and the approvers
   * mailed. Writes the response.
   *
   * @param req - the request
   * @param res - the response
   * @param caller - the admitted caller, `{ name, kind, identifier }`
   * @param body - the parsed body, or undefined when it was not JSON
   * @param scope - `(caller, application)` → the caller's scope check
   */
  submit(req: Req, res: Res, caller: Json, body: unknown,
         scope: (caller: Json, application: string) => Json): void {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.submit().");
    // THE BULK COMPANION (#1204): `items`, while it is on, is a bundle of
    // single submissions; off, the single model refuses `items` as before.
    if (isObject(body) && (body as Json).items !== undefined &&
        self.bulkOn()) {
      self.submitBulk(req, res, caller, body as Json, scope);
      log.debug("Leaving AccessRequests.submit(). A bulk submission.");
      return;
    }
    const one = self.verifyOne(req, caller, body, scope);
    if (one.refusal) {
      // error-code: none — verifyOne()'s own code, carried on its refusal.
      self.problem(res, one.refusal.status, one.refusal.type,
                   one.refusal.code, one.refusal.detail);
      log.debug("Leaving AccessRequests.submit(). " + one.refusal.code);
      return;
    }
    const given: Json = body;
    const bound: Json = one.bound;
    const scoped: Json = one.scoped;
    const base: string = one.base;
    // IDEMPOTENCY, scoped to the authenticated caller (the profile's
    // SHOULD), compared over the canonical body.
    const key = String(req.headers['idempotency-key'] || '').slice(0, 256);
    const fingerprint = stsCrypto.digest('sha256',
      AccessRequests.canonical(given), 'base64url');
    const again = (key ? self.recalled('idem', caller.name + '\n' + key)
                       : null) ||
                  self.recalled('jti', String(bound.jti || ''));
    if (again) {
      const earlier = self.task(String(again.task));
      // A TASK THE SUBJECT MADE ON THE HOSTED FORM (#1204) is this denial's
      // one task: its PEP gets it back, unless it asks for something else.
      const formMade = !!earlier && earlier.origin === 'form' &&
        self.sameAugmentations(earlier, given);
      if (earlier && (again.fingerprint === fingerprint || formMade) &&
          earlier.requester === caller.name) {
        res.status(earlier.status === 'pending' ? 202 : 201)
           .type('application/json').set('Cache-Control', 'no-store')
           .set('Location', self.handleOf(earlier).status_endpoint)
           .send(JSON.stringify(self.bodyOf(earlier,
             self.languagesOf(req)), null, 2));
        log.debug("Leaving AccessRequests.submit(). The same request.");
        return;
      }
      self.problem(res, 409, 'duplicate_request', 'STS-AUTHZEN-0076',
                   'This ' + (key ? 'Idempotency-Key' : 'denial') + ' was ' +
                   'already used for a request whose body differs.');
      log.debug("Leaving AccessRequests.submit(). A duplicate.");
      return;
    }
    const asked = self.requestedAccess(given, bound.terms || {});
    if (asked.problem) {
      self.problem(res, 400, '', asked.code, asked.problem);
      log.debug("Leaving AccessRequests.submit(). " + asked.code);
      return;
    }
    const callback = self.callbackOf(given.callback, caller);
    if (callback.problem) {
      self.problem(res, 400, '', callback.code || 'STS-AUTHZEN-0079',
                   callback.problem);
      log.debug("Leaving AccessRequests.submit(). A callback refused.");
      return;
    }
    // THE ACTOR COMPANION (#1204): a claimed chain verified against the
    // caller's own credential, or refused; `client.source` as recorded.
    const acting = self.actorOf(given.client, caller, base);
    if (acting.problem) {
      self.problem(res, 400, '', acting.code, acting.problem);
      log.debug("Leaving AccessRequests.submit(). " + acting.code);
      return;
    }
    if (self.pendingCount() >=
        self.seconds('authzen.accessRequestMaxPending')) {
      self.problem(res, 503, '', 'STS-AUTHZEN-0078', 'This realm holds as ' +
                   'many pending access requests as it may ' +
                   '(authzen.accessRequestMaxPending); try again later.');
      log.debug("Leaving AccessRequests.submit(). Full.");
      return;
    }
    const task = self.openTask({
      base: base, requester: caller.name, requesterKind: caller.kind,
      client: isObject(given.client)
        ? { id: String(given.client.id || '').slice(0, MAX_ID),
            name: String(given.client.name || '').slice(0, MAX_TEXT) }
        : null,
      application: scoped.application, bound: bound, asked: asked,
      callback: callback.value, key: key, fingerprint: fingerprint,
      actor: caller.name, origin: 'pep', formSubmittedBy: '',
      acting: acting.actor, source: acting.source });
    res.status(task.status === 'pending' ? 202 : 201)
       .type('application/json').set('Cache-Control', 'no-store')
       .set('Location', self.handleOf(task).status_endpoint)
       .send(JSON.stringify(self.bodyOf(task, self.languagesOf(req)), null,
                            2));
    log.debug("Leaving AccessRequests.submit(). " + task.id + " " +
              task.status);
  }

  /**
   * Opens a task for a verified denial: the row, its indexes, the audit
   * row, emergency access where it applies, and the approvers' mail. The
   * one place a task is made, for a PEP's submission and the hosted
   * form's (#1204) alike.
   *
   * @param spec - `{ base, requester, requesterKind, client, application,
   *   bound, asked, callback, key, fingerprint, actor, origin,
   *   formSubmittedBy }`
   * @returns the task
   */
  private openTask(spec: Json): Json {
    const self = this;
    const { log, helpers } = this.deps;
    log.debug("Entering AccessRequests.openTask(). " + spec.origin);
    const now = self.nowS();
    const bound = spec.bound;
    const asked = spec.asked;
    const key = String(spec.key || '');
    const task: Json = {
      id: 'arq_' + helpers.randomId(24),
      status: 'pending',
      realm: String(self.deps.realms.currentId() || ''),
      base: spec.base,
      requester: spec.requester,
      requesterKind: spec.requesterKind,
      client: spec.client || null,
      application: spec.application,
      evaluationId: String(bound.evaluation_id || ''),
      subject: bound.subject,
      resource: bound.resource,
      action: bound.action,
      context: bound.context || {},
      contextMembers: bound.binding_context_members || [],
      terms: bound.terms || {},
      requestedUntil: asked.until,
      emergency: asked.emergency,
      justification: asked.justification,
      // The catalog item the request chose (#1204), '' when none.
      entitlement: String(asked.entitlement || ''),
      callback: spec.callback || null,
      createdAt: now,
      expiresAt: now + self.seconds('authzen.accessRequestLifetimeS'),
      keepUntil: now + self.seconds('authzen.accessRequestLifetimeS') +
                 RETENTION_S,
      approval: null,
      decidedBy: '',
      idempotency: null
    };
    // Where the request was made: `pep`, or `form` with the person who
    // submitted it there (#1204), for the audit row and the console.
    if (spec.origin === 'form') {
      task.origin = 'form';
      task.formSubmittedBy = String(spec.formSubmittedBy || '');
    }
    // THE VERIFIED ACTOR CHAIN AND THE SOURCE (#1204, the ACTOR
    // companion), context for the approvers and the audit, never a fact.
    if (spec.acting) {
      task.actor = spec.acting;
    }
    // ONE ITEM OF A BULK REQUEST (#1204): its bundle and its position.
    if (spec.bundle) {
      task.bundle = String(spec.bundle);
      task.position = Number(spec.position) || 0;
    }
    if (spec.source) {
      task.source = spec.source;
    }
    const indexRow: Json = { fingerprint: spec.fingerprint };
    if (key) {
      const indexKey = 'idem:' + stsCrypto.credentialDigest(
        spec.requester + '\n' + key);
      task.idempotency = { key: indexKey, row: Object.assign(
        { task: task.id }, indexRow) };
    }
    self.save(task);
    if (key) {
      self.remember('idem', spec.requester + '\n' + key, task.id, indexRow,
                    task.keepUntil);
    }
    self.remember('jti', String(bound.jti || ''), task.id, indexRow,
                  Number(bound.exp) + SKEW_S);
    self.deps.audit.audit({
      action: 'authzen.access-request.submitted',
      actor: spec.actor,
      protocol: 'AuthZEN',
      detail: 'The access request ' + task.id + ' was submitted for a ' +
        String(task.subject.type || '') + ' to ' +
        String(task.action.name || '') + ' a ' +
        String(task.resource.type || '') + ', application "' +
        task.application + '"' + (task.emergency ? ', as an emergency' : '') +
        (task.entitlement ? ', for the entitlement "' +
          String(task.entitlement).slice(0, 128) + '"' : '') +
        (task.actor ? ', acted for by ' + (task.actor.chain || [])
          .map(function (one: Json) {
            return String(one.id).slice(0, 128);
          }).join(' for ') : '') +
        (key ? ', with an Idempotency-Key' : '') +
        (task.origin === 'form' ? ', by its subject on the hosted form, ' +
          'for the PEP ' + String(task.requester) : '') + '.'
    });
    // EMERGENCY ACCESS (the profile's `requested_access.emergency`, a
    // request signal and never an override): only where the policy's own
    // advice allowed it, with a business justification, for the shortest
    // lifetime, approved at once and every approver told for the review
    // after use the profile asks for.
    if (task.emergency) {
      self.approve(task, { username: '', door: 'emergency' },
                   'emergency access the policy allows, justified: ' +
                   String(task.justification).slice(0, 200));
    }
    self.mailApprovers(task);
    log.debug("Leaving AccessRequests.openTask(). " + task.id);
    return task;
  }

  /**
   * Whether a PEP's submission asks for what the hosted form already asked
   * (#1204): nothing at all, or the same justification, end and emergency.
   *
   * @param task - the form's task
   * @param given - the PEP's submission
   * @returns true when it asks for nothing else
   */
  private sameAugmentations(task: Json, given: Json): boolean {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.sameAugmentations().");
    const context: Json = isObject(given.context) ? given.context : {};
    if (given.requested_access === undefined &&
        context.business_justification === undefined) {
      log.debug("Leaving AccessRequests.sameAugmentations(). Nothing asked.");
      return true;
    }
    const asked = self.requestedAccess(given, task.terms || {});
    const out = !asked.problem &&
      Number(asked.until || 0) === Number(task.requestedUntil || 0) &&
      !!asked.emergency === !!task.emergency &&
      String(asked.justification || '') ===
        String(task.justification || '') &&
      String(asked.entitlement || '') === String(task.entitlement || '');
    log.debug("Leaving AccessRequests.sameAugmentations(). " + out);
    return out;
  }

  // -------------------------------------------------------------------------
  // THE BULK COMPANION (#1204). This service issues no bundle denial — a
  // batch evaluation answers each item with a requestable denial of its own
  // — so every item carries its own `denial` (its section 3.1) and a
  // top-level one is bundle binding material it never issued. Each item is
  // checked exactly as a single submission is (`verifyOne()`, with the
  // top-level subject and context), and becomes an ordinary task: approvers
  // decide it alone, and its approval verifies alone (section 3.6). The
  // bundle is an index row holding the items' ids in order; its Task
  // Handle is built from them whenever it is read (section 3.4). A
  // callback on a bulk submission is refused: the CALLBACK companion's
  // `partial` event is not built.
  // -------------------------------------------------------------------------
  /**
   * Whether `items` is read (`authzen.accessRequestBulk`).
   *
   * @returns true when it and the profile are on
   */
  bulkOn(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering AccessRequests.bulkOn().");
    log.debug("Leaving AccessRequests.bulkOn().");
    return this.enabled() &&
      config.value('authzen.accessRequestBulk') === true;
  }

  /**
   * Answers a bulk submission: every item verified, then every item a
   * task, then the bundle's Task Handle.
   *
   * @param req - the request
   * @param res - the response
   * @param caller - the admitted caller
   * @param given - the submission, with `items`
   * @param scope - `(caller, application)` → the caller's scope check
   */
  private submitBulk(req: Req, res: Res, caller: Json, given: Json,
                     scope: (caller: Json, application: string) => Json):
    void {
    const self = this;
    const { log, helpers, index } = this.deps;
    log.debug("Entering AccessRequests.submitBulk().");
    const most = self.seconds('authzen.accessRequestMaxBulkItems');
    const items: Json[] = Array.isArray(given.items) ? given.items : [];
    if (!Array.isArray(given.items) || !items.length || items.length > most ||
        !items.every(isObject)) {
      self.problem(res, 400, '', 'STS-AUTHZEN-0156', 'items must hold ' +
                   'from 1 to ' + most + ' objects, each with resource, ' +
                   'action and its own denial.');
      log.debug("Leaving AccessRequests.submitBulk(). Bad items.");
      return;
    }
    if (given.resource !== undefined || given.action !== undefined) {
      self.problem(res, 400, '', 'STS-AUTHZEN-0155', 'With items, the ' +
                   'top-level resource and action are omitted (the BULK ' +
                   'companion\'s section 3.1).');
      log.debug("Leaving AccessRequests.submitBulk(). A top-level tuple.");
      return;
    }
    if (given.denial !== undefined ||
        !items.every(function (one: Json): boolean {
          return one.denial !== undefined;
        })) {
      self.problem(res, 400, 'invalid_denial_binding', 'STS-AUTHZEN-0157',
                   'Every item carries its own denial: this service issues ' +
                   'no bundle denial, so a top-level denial binds nothing.');
      log.debug("Leaving AccessRequests.submitBulk(). A bundle denial.");
      return;
    }
    if (given.callback !== undefined) {
      self.problem(res, 400, '', 'STS-AUTHZEN-0159', 'A bulk submission ' +
                   'takes no callback; poll the bundle\'s status endpoint.');
      log.debug("Leaving AccessRequests.submitBulk(). A callback.");
      return;
    }
    // IDEMPOTENCY OVER THE WHOLE BODY (section 3.1), per caller, first: a
    // retry finds its bundle before its items' denials read as used.
    const key = String(req.headers['idempotency-key'] || '').slice(0, 256);
    const fingerprint = stsCrypto.digest('sha256',
      AccessRequests.canonical(given), 'base64url');
    const again = key ? self.recalled('idem', caller.name + '\n' + key)
      : null;
    if (again) {
      const earlier = self.bundleOf(String(again.task));
      if (earlier && again.fingerprint === fingerprint &&
          earlier.row.requester === caller.name) {
        self.sendBundle(res, earlier, self.languagesOf(req));
        log.debug("Leaving AccessRequests.submitBulk(). The same bundle.");
        return;
      }
      self.problem(res, 409, 'duplicate_request', 'STS-AUTHZEN-0076',
                   'This Idempotency-Key was already used for a request ' +
                   'whose body differs.');
      log.debug("Leaving AccessRequests.submitBulk(). A duplicate.");
      return;
    }
    // EACH ITEM, AS A SINGLE SUBMISSION WOULD BE CHECKED, before anything
    // is made.
    const top: Json = isObject(given.requested_access)
      ? given.requested_access : {};
    const checked: Json[] = [];
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const merged: Json = Object.assign({}, top,
        isObject(item.requested_access) ? item.requested_access : {});
      const single: Json = {
        subject: given.subject, resource: item.resource,
        action: item.action, denial: item.denial };
      if (given.context !== undefined) {
        single.context = given.context;
      }
      if (Object.keys(merged).length) {
        single.requested_access = merged;
      }
      const one = self.verifyOne(req, caller, single, scope);
      if (one.refusal) {
        // error-code: none — verifyOne()'s own code, carried on its refusal.
        self.problem(res, one.refusal.status, one.refusal.type,
                     one.refusal.code, 'items[' + i + ']: ' +
                     one.refusal.detail);
        log.debug("Leaving AccessRequests.submitBulk(). Item " + i + ".");
        return;
      }
      if (checked.length &&
          one.scoped.application !== checked[0].scoped.application) {
        self.problem(res, 400, '', 'STS-AUTHZEN-0158', 'items[' + i + ']\'s ' +
                     'denial is about another application: one bulk ' +
                     'request is one application\'s.');
        log.debug("Leaving AccessRequests.submitBulk(). Mixed.");
        return;
      }
      const jti = String(one.bound.jti || '');
      if (self.recalled('jti', jti) ||
          checked.some(function (done: Json): boolean {
            return String(done.bound.jti || '') === jti;
          })) {
        self.problem(res, 409, 'duplicate_request', 'STS-AUTHZEN-0076',
                     'items[' + i + ']\'s denial was already requested.');
        log.debug("Leaving AccessRequests.submitBulk(). Item " + i +
                  " requested.");
        return;
      }
      const asked = self.requestedAccess(single, one.bound.terms || {});
      if (asked.problem) {
        // error-code: none — requestedAccess()'s own code.
        self.problem(res, 400, '', asked.code, 'items[' + i + ']: ' +
                     asked.problem);
        log.debug("Leaving AccessRequests.submitBulk(). " + asked.code);
        return;
      }
      checked.push({ bound: one.bound, scoped: one.scoped, base: one.base,
                     asked: asked });
    }
    const acting = self.actorOf(given.client, caller, checked[0].base);
    if (acting.problem) {
      // error-code: none — actorOf()'s own code.
      self.problem(res, 400, '', acting.code, acting.problem);
      log.debug("Leaving AccessRequests.submitBulk(). " + acting.code);
      return;
    }
    if (self.pendingCount() + checked.length >
        self.seconds('authzen.accessRequestMaxPending')) {
      self.problem(res, 503, '', 'STS-AUTHZEN-0078', 'This realm holds as ' +
                   'many pending access requests as it may ' +
                   '(authzen.accessRequestMaxPending); try again later.');
      log.debug("Leaving AccessRequests.submitBulk(). Full.");
      return;
    }
    const id = BUNDLE_PREFIX + helpers.randomId(24);
    const client = isObject(given.client)
      ? { id: String(given.client.id || '').slice(0, MAX_ID),
          name: String(given.client.name || '').slice(0, MAX_TEXT) }
      : null;
    const ids = checked.map(function (one: Json, i: number): string {
      return String(self.openTask({
        base: one.base, requester: caller.name, requesterKind: caller.kind,
        client: client, application: one.scoped.application,
        bound: one.bound, asked: one.asked, callback: null, key: '',
        fingerprint: fingerprint, actor: caller.name, origin: 'pep',
        formSubmittedBy: '', acting: acting.actor, source: acting.source,
        bundle: id, position: i }).id);
    });
    const now = self.nowS();
    const until = now + self.seconds('authzen.accessRequestLifetimeS') +
      self.seconds('authzen.accessRequestMaxApprovalS') + RETENTION_S;
    index.set(BUNDLE_KEY + stsCrypto.credentialDigest(id),
              { id: id, tasks: ids, requester: caller.name,
                base: checked[0].base, createdAt: now, until: until });
    if (key) {
      self.remember('idem', caller.name + '\n' + key, id,
                    { fingerprint: fingerprint }, until);
    }
    self.deps.audit.audit({
      action: 'authzen.access-request.submitted',
      actor: caller.name,
      protocol: 'AuthZEN',
      detail: 'The bulk access request ' + id + ' was submitted with ' +
        ids.length + ' item(s): ' + ids.join(', ') + '.'
    });
    self.sendBundle(res, self.bundleOf(id), self.languagesOf(req));
    log.debug("Leaving AccessRequests.submitBulk(). " + id);
  }

  /**
   * A bundle and its items, or null when there is none (or it is gone).
   *
   * @param id - the bundle's id
   * @returns `{ row, tasks }`
   */
  bundleOf(id: string): Json {
    const self = this;
    const { log, index } = this.deps;
    log.debug("Entering AccessRequests.bundleOf().");
    if (String(id || '').indexOf(BUNDLE_PREFIX) !== 0) {
      log.debug("Leaving AccessRequests.bundleOf(). Not a bundle.");
      return null;
    }
    const row = index.get(BUNDLE_KEY + stsCrypto.credentialDigest(
      String(id).slice(0, MAX_ID)));
    if (!row || Number(row.until) <= self.nowS()) {
      log.debug("Leaving AccessRequests.bundleOf(). None.");
      return null;
    }
    const tasks = (row.tasks || []).map(function (one: string): Json {
      return self.task(String(one));
    });
    log.debug("Leaving AccessRequests.bundleOf(). " + tasks.length);
    return { row: row, tasks: tasks };
  }

  /**
   * A bundle's Task Handle and body (section 3.4): the aggregate status,
   * and each item's resource, action, status and, once approved, its own
   * result. No top-level result.
   *
   * @param bundle - `bundleOf()`'s answer
   * @param languages - the caller's languages
   * @returns `{ task }`
   */
  bundleBody(bundle: Json, languages: string[]): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.bundleBody().");
    const tasks: Json[] = bundle.tasks;
    const statuses = tasks.map(function (one: Json): string {
      return one ? String(one.status) : 'expired';
    });
    const distinct = statuses.filter(function (one: string, i: number) {
      return statuses.indexOf(one) === i;
    });
    const status = statuses.indexOf('pending') >= 0 ? 'pending'
      : distinct.length === 1 ? distinct[0] : 'partial';
    const items = tasks.map(function (one: Json, i: number): Json {
      if (!one) {
        return { resource: {}, action: {}, status: statuses[i] };
      }
      const item: Json = { resource: one.resource, action: one.action,
                           status: String(one.status) };
      const result = self.bodyOf(one).result;
      if (result) {
        item.result = result;
      }
      return item;
    });
    const ends = tasks.map(function (one: Json): number {
      return one ? Number(one.status === 'pending' ? one.expiresAt
                                                   : one.keepUntil) : 0;
    });
    const endpoint = String(bundle.row.base) + REQUESTS_PATH + '/' +
      String(bundle.row.id);
    const handle: Json = { id: String(bundle.row.id), status: status,
                           status_endpoint: endpoint,
                           expires_at: instant(Math.max.apply(null,
                             ends.concat([0])) * 1000),
                           items: items };
    if (status === 'pending') {
      handle.links = { cancel: endpoint + '/cancel' };
    }
    const display = self.taskDisplay(status, languages || []);
    if (display) {
      handle.display = display;
    }
    const out = { task: handle };
    authzenModel.hold('task-response', out, 'a bulk access request');
    log.debug("Leaving AccessRequests.bundleBody(). " + status);
    return out;
  }

  // Writes a bundle's answer: 202 while any item is pending, 201 once all
  // are finished.
  private sendBundle(res: Res, bundle: Json, languages: string[]): void {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.sendBundle().");
    const body = this.bundleBody(bundle, languages);
    res.status(body.task.status === 'pending' ? 202 : 201)
       .type('application/json').set('Cache-Control', 'no-store')
       .set('Location', body.task.status_endpoint)
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving AccessRequests.sendBundle().");
  }

  // The bundle a caller may read, or null with unknown_task written.
  private callersBundle(res: Res, caller: Json, id: string): Json {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.callersBundle().");
    const bundle = this.bundleOf(id);
    if (!bundle || bundle.row.requester !== caller.name) {
      this.problem(res, 404, 'unknown_task', 'STS-AUTHZEN-0080',
                   'There is no such task for this caller.');
      log.debug("Leaving AccessRequests.callersBundle(). Unknown.");
      return null;
    }
    log.debug("Leaving AccessRequests.callersBundle().");
    return bundle;
  }

  /**
   * A bundle's status endpoint.
   *
   * @param res - the response
   * @param caller - the admitted caller
   * @param id - the bundle's id
   */
  private bundleStatus(res: Res, caller: Json, id: string): void {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.bundleStatus().");
    const bundle = self.callersBundle(res, caller, id);
    if (!bundle) {
      log.debug("Leaving AccessRequests.bundleStatus(). Refused.");
      return;
    }
    const body = self.bundleBody(bundle, self.languagesOf((res as Json).req));
    if (body.task.status === 'pending') {
      res.set('Retry-After',
              String(self.seconds('authzen.accessRequestRetryAfterS')));
    }
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving AccessRequests.bundleStatus(). " + body.task.status);
  }

  /**
   * A bundle's cancellation (section 3.6): every pending item cancelled,
   * the finished ones left; 409 when none was pending.
   *
   * @param res - the response
   * @param caller - the admitted caller
   * @param id - the bundle's id
   * @param body - the optional `{ reason }`
   */
  private bundleCancel(res: Res, caller: Json, id: string,
                       body: unknown): void {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.bundleCancel().");
    const bundle = self.callersBundle(res, caller, id);
    if (!bundle) {
      log.debug("Leaving AccessRequests.bundleCancel(). Refused.");
      return;
    }
    const given: Json = isObject(body) ? body : {};
    let cancelled = 0;
    bundle.tasks.forEach(function (one: Json) {
      if (one && one.status === 'pending' &&
          self.finish(one, 'cancelled', {
            actor: caller.name,
            why: 'with its bulk request ' + id + ', by the requesting PEP' +
              (given.reason ? ' (' + String(given.reason).slice(0, 64) + ')'
                            : '') })) {
        cancelled += 1;
      }
    });
    if (!cancelled) {
      self.problem(res, 409, 'invalid_task_state', 'STS-AUTHZEN-0082',
                   'Every item of this request has already finished.');
      log.debug("Leaving AccessRequests.bundleCancel(). Finished.");
      return;
    }
    const answer = self.bundleBody(self.bundleOf(id),
                                   self.languagesOf((res as Json).req));
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(answer, null, 2));
    log.debug("Leaving AccessRequests.bundleCancel(). " + cancelled);
  }

  // -------------------------------------------------------------------------
  // THE ACTOR COMPANION (#1204). An AuthZEN caller is the PEP itself — a
  // directory entry by its certificate, or a client by its own
  // client_credentials token (`authzen_caller.ts`) — so a credential here
  // can authorize two chains (its section 3.2): one link that is the
  // caller itself, or, link for link, the `act` chain of the caller's own
  // RFC 8693 token. Any other claimed chain is refused (0153): the MUST
  // governs the MAY of the same section, so nothing unverified is kept.
  // `client.source` has no verification in the draft and is audit-only.
  // Neither is ever an XACML fact: the approval question is unchanged.
  // `subject.properties.act` stays out of the binding (`bound()`), the
  // base profile's rule today; openid/authzen#756 would change that.
  // -------------------------------------------------------------------------
  /**
   * Whether `client.actor` and `client.source` are read
   * (`authzen.accessRequestActor`).
   *
   * @returns true when it and the profile are on
   */
  actorOn(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering AccessRequests.actorOn().");
    log.debug("Leaving AccessRequests.actorOn().");
    return this.enabled() &&
      config.value('authzen.accessRequestActor') === true;
  }

  /**
   * The links of an actor chain, immediate actor first: `{ id, issuer,
   * type }` each, from `client.actor`'s `id`/`issuer`/`type` and then the
   * nested `act`'s `sub`/`iss`/`sub_profile`; or a sentence when its shape
   * is wrong.
   *
   * @param actor - `client.actor`
   * @returns `{ links }` or `{ problem }`
   */
  private actorLinks(actor: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.actorLinks().");
    const links: Json[] = [];
    // A hot path of one walk: no Entering/Leaving pair.
    const text = function (value: unknown, most: number): string | null {
      if (value === undefined) {
        return '';
      }
      return typeof value === 'string' && value.length <= most
        ? value : null;
    };
    let at: unknown = actor;
    let depth = 0;
    while (at !== undefined) {
      if (!isObject(at) || depth >= MAX_ACT_DEPTH) {
        log.debug("Leaving AccessRequests.actorLinks(). Not a chain.");
        return { problem: 'client.actor must be an object, its act ' +
                          'nested objects, at most ' + MAX_ACT_DEPTH +
                          ' deep.' };
      }
      const one: Json = at;
      const id = text(depth ? one.sub : one.id, 256);
      const issuer = text(depth ? one.iss : one.issuer, MAX_URL);
      const type = text(depth ? one.sub_profile : one.type, 64);
      if (!id || issuer === null || type === null) {
        log.debug("Leaving AccessRequests.actorLinks(). A bad link.");
        return { problem: 'Every link of client.actor needs a string ' +
                          (depth ? 'sub' : 'id') + ', and its ' +
                          (depth ? 'iss and sub_profile' :
                                   'issuer and type') +
                          ', when present, must be short strings.' };
      }
      const link: Json = { id: id };
      if (issuer) {
        link.issuer = issuer;
      }
      if (type) {
        link.type = type;
      }
      links.push(link);
      at = one.act;
      depth += 1;
    }
    log.debug("Leaving AccessRequests.actorLinks(). " + links.length);
    return { links: links };
  }

  /**
   * Reads and verifies `client.actor`, and reads `client.source` (the
   * ACTOR companion's sections 3.1 and 3.2).
   *
   * @param client - the submission's `client`
   * @param caller - the admitted caller
   * @param base - this realm's base, its issuer for a self link
   * @returns `{ actor, source }` (each null when absent or off), or
   *   `{ problem, code }`
   */
  actorOf(client: unknown, caller: Json, base: string): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.actorOf().");
    if (!self.actorOn() || !isObject(client)) {
      log.debug("Leaving AccessRequests.actorOf(). Not read.");
      return { actor: null, source: null };
    }
    const given: Json = client;
    let source: Json = null;
    if (given.source !== undefined) {
      const s: Json = given.source;
      const fine = isObject(s) &&
        ['session_id', 'integration_id'].every(function (name: string) {
          return s[name] === undefined ||
            (typeof s[name] === 'string' && s[name].length <= 256);
        }) &&
        (s.external_url === undefined ||
         (typeof s.external_url === 'string' &&
          s.external_url.length <= MAX_URL &&
          /^https:\/\/[^\s/?#]+/i.test(s.external_url)));
      if (!fine) {
        log.debug("Leaving AccessRequests.actorOf(). A bad source.");
        return { problem: 'client.source must be an object whose ' +
                          'session_id and integration_id are short ' +
                          'strings and whose external_url is an https ' +
                          'URL.', code: 'STS-AUTHZEN-0154' };
      }
      source = {};
      ['session_id', 'external_url', 'integration_id'].forEach(
        function (name: string) {
          if (s[name]) {
            source[name] = String(s[name]);
          }
        });
      if (!Object.keys(source).length) {
        source = null;
      }
    }
    if (given.actor === undefined) {
      log.debug("Leaving AccessRequests.actorOf(). No actor.");
      return { actor: null, source: source };
    }
    const read = self.actorLinks(given.actor);
    if (read.problem) {
      log.debug("Leaving AccessRequests.actorOf(). A bad chain.");
      return { problem: read.problem, code: 'STS-AUTHZEN-0154' };
    }
    const links: Json[] = read.links;
    const own = [caller.name, caller.clientId, caller.identifier]
      .filter(Boolean).map(String);
    const issuers = [String(base || ''), String(caller.iss || '')]
      .filter(Boolean);
    // 1. ONE LINK THAT IS THE CALLER ITSELF.
    const itself = links.length === 1 &&
      own.indexOf(String(links[0].id)) >= 0 &&
      (!links[0].issuer || issuers.indexOf(String(links[0].issuer)) >= 0);
    // 2. THE CALLER'S OWN TOKEN'S `act` CHAIN, LINK FOR LINK.
    let carried = false;
    if (!itself && isObject(caller.act)) {
      const chain: Json[] = [];
      let at: Json = caller.act;
      while (isObject(at) && chain.length <= MAX_ACT_DEPTH) {
        chain.push(at);
        at = at.act;
      }
      carried = chain.length === links.length &&
        links.every(function (link: Json, i: number) {
          const token = chain[i];
          const iss = String(token.iss || caller.iss || '');
          return String(token.sub || '') === String(link.id) &&
            (!link.issuer || String(link.issuer) === iss);
        });
    }
    if (!itself && !carried) {
      log.debug("Leaving AccessRequests.actorOf(). Not authorized.");
      return { problem: 'The caller\'s credential does not authorize the ' +
                        'actor chain in client.actor.',
               code: 'STS-AUTHZEN-0153' };
    }
    log.debug("Leaving AccessRequests.actorOf(). " + links.length +
              " link(s), " + (itself ? 'the caller itself' : 'its token'));
    return { actor: { chain: links,
                      verifiedBy: itself ? 'caller' : 'token' },
             source: source };
  }

  // -------------------------------------------------------------------------
  // THE CATALOG COMPANION (#1204). A catalog here is the POLICY'S: the
  // entitlements the access-request advice lists for the denied tuple, so
  // it is scoped to the original Subject, Resource and Action by
  // construction (its sections 7 and 11). The Catalogs Document and the
  // Catalog Endpoint answer only the caller the denial was answered to,
  // while it is still scoped to the application; anybody else is told
  // nothing (0149). A query string is never logged (section 13).
  // -------------------------------------------------------------------------
  /**
   * Whether the catalogs answer (`authzen.accessRequestCatalogs`).
   *
   * @returns true when it and the profile are on
   */
  catalogsOn(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering AccessRequests.catalogsOn().");
    log.debug("Leaving AccessRequests.catalogsOn().");
    return this.enabled() &&
      config.value('authzen.accessRequestCatalogs') === true;
  }

  /**
   * The recorded denial a catalog call names, for its own caller, or null
   * with the refusal written.
   *
   * @param res - the response
   * @param caller - the admitted caller
   * @param evaluationId - the denial's id, from the path
   * @param scope - `(caller, application)` → the caller's scope check
   * @returns the record, or null
   */
  private catalogDenial(res: Res, caller: Json, evaluationId: string,
                        scope: (caller: Json, application: string) => Json):
    Json | null {
    const self = this;
    const { log, denials } = this.deps;
    log.debug("Entering AccessRequests.catalogDenial().");
    if (!self.catalogsOn()) {
      self.problem(res, 501, '', 'STS-AUTHZEN-0152', 'The access request ' +
                   'catalogs are turned off in this realm ' +
                   '(authzen.accessRequestCatalogs).');
      log.debug("Leaving AccessRequests.catalogDenial(). Off.");
      return null;
    }
    const id = String(evaluationId || '').slice(0, MAX_ID);
    const row = id ? denials.get(id) : null;
    const ok = !!row && Number(row.keepUntil) > self.nowS() &&
      String(row.caller) === String(caller.name) &&
      ((row.terms || {}).entitlements || []).length > 0 &&
      !!scope(caller, String(row.application || '')).application;
    if (!ok) {
      self.problem(res, 404, '', 'STS-AUTHZEN-0149', 'There is no catalog ' +
                   'for this caller under that denial.');
      log.debug("Leaving AccessRequests.catalogDenial(). Unknown.");
      return null;
    }
    log.debug("Leaving AccessRequests.catalogDenial().");
    return row;
  }

  /**
   * Answers a denial's Catalogs Document (the CATALOG companion's
   * section 6): the one catalog-backed field and its endpoint.
   *
   * @param req - the request, for the base
   * @param res - the response
   * @param caller - the admitted caller
   * @param evaluationId - the denial's id
   * @param scope - the caller's scope check
   */
  catalogsDocument(req: Req, res: Res, caller: Json, evaluationId: string,
                   scope: (caller: Json, application: string) => Json):
    void {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.catalogsDocument().");
    const row = self.catalogDenial(res, caller, evaluationId, scope);
    if (!row) {
      log.debug("Leaving AccessRequests.catalogsDocument(). Refused.");
      return;
    }
    const fields: Json = {};
    fields[ENTITLEMENT_POINTER] = {
      endpoint: self.baseOf(req) + CATALOGS_PATH + '/' +
        encodeURIComponent(String(row.evaluationId)) + '/entitlements',
      search_param: 'q'
    };
    const body = authzenModel.held('catalogs-document', { fields: fields },
                                   'the Catalogs Document');
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving AccessRequests.catalogsDocument().");
  }

  /**
   * Answers the entitlements Catalog Endpoint (the CATALOG companion's
   * sections 7 and 8): the denial's items matching `q`, a page at a time.
   *
   * @param req - the request, for `q`, `cursor` and `limit`
   * @param res - the response
   * @param caller - the admitted caller
   * @param evaluationId - the denial's id
   * @param scope - the caller's scope check
   */
  catalogItems(req: Req, res: Res, caller: Json, evaluationId: string,
               scope: (caller: Json, application: string) => Json): void {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.catalogItems().");
    const row = self.catalogDenial(res, caller, evaluationId, scope);
    if (!row) {
      log.debug("Leaving AccessRequests.catalogItems(). Refused.");
      return;
    }
    // A hot path of one read: no Entering/Leaving pair.
    const first = function (value: unknown): string {
      return String((Array.isArray(value) ? value[0] : value) || '');
    };
    const query: Json = req.query || {};
    const q = first(query.q).trim().toLowerCase().slice(0, 256);
    const asked = Math.floor(Number(first(query.limit)) || 0);
    const limit = asked > 0 ? Math.min(asked, CATALOG_PAGE_MAX)
      : CATALOG_PAGE;
    const tag = stsCrypto.digest('sha256', q, 'base64url').slice(0, 16);
    let offset = 0;
    const cursor = first(query.cursor);
    if (cursor) {
      let read: Json = null;
      try {
        read = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
      } catch (e) {
        log.debug("Caught in AccessRequests.catalogItems(): " +
                  ((e && e.message) || e));
        read = null;
      }
      if (!isObject(read) || read.q !== tag ||
          !Number.isInteger(read.o) || read.o < 0) {
        self.problem(res, 400, '', 'STS-AUTHZEN-0150', 'cursor is not one ' +
                     'this Catalog Endpoint issued for this search.');
        log.debug("Leaving AccessRequests.catalogItems(). A bad cursor.");
        return;
      }
      offset = read.o;
    }
    const matching = ((row.terms || {}).entitlements || []).filter(
      function (one: Json) {
        return !q || String(one.value).toLowerCase().indexOf(q) >= 0 ||
          String(one.label).toLowerCase().indexOf(q) >= 0;
      });
    const page = matching.slice(offset, offset + limit).map(
      function (one: Json) {
        return { value: String(one.value), label: String(one.label) };
      });
    const body: Json = { items: page, total: matching.length };
    if (offset + limit < matching.length) {
      body.next_cursor = Buffer.from(JSON.stringify(
        { o: offset + limit, q: tag }), 'utf8').toString('base64url');
    }
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(authzenModel.held('catalog-response', body,
         'the Catalog Endpoint'), null, 2));
    log.debug("Leaving AccessRequests.catalogItems(). " + page.length);
  }

  // -------------------------------------------------------------------------
  // THE HOSTED FORM AND THE TICKET (#1204; the profile's sections 16, 7.1
  // and 11.11). `form_url` is the portal page `/portal/access-request`
  // with the denial's `evaluation_id`; the subject signs in there and
  // submits the denial's access request themselves. The task is the one a
  // PEP's own submission would make — the recorded tuple, application and
  // terms, `requester` the PEP the denial was answered to — so that PEP
  // reads it, cancels it and re-evaluates with its approval, and gets it
  // back when it submits the same denial (`sameAugmentations()`). The draft
  // does not say how what the person gives reaches the task; making the
  // denial's own submission is this service's answer. `links.ticket` is
  // the same page with the task's id. Nothing on either names an approver
  // (section 19). Only the denial's SUBJECT is answered, the same refusal
  // (0146) whether or not the thing exists.
  // -------------------------------------------------------------------------
  /**
   * Whether the hosted form is on (`authzen.accessRequestForm`).
   *
   * @returns true when it and the profile are on
   */
  formOn(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering AccessRequests.formOn().");
    log.debug("Leaving AccessRequests.formOn().");
    return this.enabled() &&
      config.value('authzen.accessRequestForm') === true;
  }

  /**
   * The portal's base for a base of this realm's PDP: the same origin on a
   * default install, the portal's listener where it has one.
   *
   * @param base - this realm's base, the prefix included
   * @returns the portal's base, the prefix included
   */
  private portalBaseOf(base: string): string {
    const { log, helpers } = this.deps;
    log.debug("Entering AccessRequests.portalBaseOf().");
    let out = String(base || '');
    try {
      out = String(helpers.rebaseTo(out, 'portal') || out);
    } catch (e) {
      // The PDP's own base: the page answers there too.
      log.debug("Caught in AccessRequests.portalBaseOf(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving AccessRequests.portalBaseOf().");
    return out;
  }

  /**
   * A requestable denial's `form_url`.
   *
   * @param base - this realm's base
   * @param evaluationId - the denial's id
   * @returns the URL
   */
  formUrlOf(base: string, evaluationId: string): string {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.formUrlOf().");
    log.debug("Leaving AccessRequests.formUrlOf().");
    return this.portalBaseOf(base) + FORM_PATH + '?evaluation_id=' +
      encodeURIComponent(evaluationId);
  }

  /**
   * A Task Handle's `links.ticket`.
   *
   * @param task - the row
   * @returns the URL
   */
  ticketUrlOf(task: Json): string {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.ticketUrlOf().");
    log.debug("Leaving AccessRequests.ticketUrlOf().");
    return this.portalBaseOf(String(task.base || '')) + FORM_PATH +
      '?request=' + encodeURIComponent(String(task.id));
  }

  /**
   * Whether a person is the subject a denial or a task names: its type one
   * of `authzen.resolveSubjectTypes`, its id one of the person's names.
   *
   * @param username - the signed-in person
   * @param subject - the bound subject
   * @returns true when it is them
   */
  private isSubject(username: string, subject: Json): boolean {
    const { log, config } = this.deps;
    log.debug("Entering AccessRequests.isSubject().");
    const raw = config.value('authzen.resolveSubjectTypes');
    const types = (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one: unknown) {
        return String(one).trim();
      }).filter(Boolean);
    const given: Json = isObject(subject) ? subject : {};
    if (types.indexOf(String(given.type || '')) < 0) {
      log.debug("Leaving AccessRequests.isSubject(). Not a person's type.");
      return false;
    }
    const id = String(given.id == null ? '' : given.id).trim().toLowerCase();
    const out = !!id &&
      this.approverIdentity(username).identity.indexOf(id) >= 0;
    log.debug("Leaving AccessRequests.isSubject(). " + out);
    return out;
  }

  /**
   * What the form shows of a recorded denial: what it asks, and what the
   * person may add. Never who approves.
   *
   * @param row - the denial's record
   * @returns the view's `request`
   */
  private formRequestOf(row: Json): Json {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.formRequestOf().");
    const terms: Json = row.terms || {};
    const until = Math.min(Number(row.exp) || 0,
      Math.floor(Date.parse(String(row.denialExpiresAt || '')) / 1000) || 0);
    const out: Json = {
      evaluationId: String(row.evaluationId),
      subject: row.subject || {},
      action: row.action || {},
      resource: row.resource || {},
      application: String(row.application || ''),
      expiresAt: until,
      emergency: terms.emergency === true,
      entitlements: this.catalogsOn()
        ? (terms.entitlements || []).map(function (one: Json) {
          return { value: String(one.value), label: String(one.label) };
        }) : [],
      maxApprovalS: Number(terms.maxSeconds) > 0
        ? Math.min(Number(terms.maxSeconds),
                   this.seconds('authzen.accessRequestMaxApprovalS'))
        : this.seconds('authzen.accessRequestMaxApprovalS')
    };
    // The advice's own words only: the page is translated in the browser,
    // and the service's sentence is the browser's heading there.
    if (this.displays() && (terms.displayTitle || terms.displayDescription)) {
      out.display = {};
      if (terms.displayTitle) {
        out.display.title = String(terms.displayTitle);
      }
      if (terms.displayDescription) {
        out.display.description = String(terms.displayDescription);
      }
    }
    log.debug("Leaving AccessRequests.formRequestOf().");
    return out;
  }

  /**
   * What the page shows of a task: its status and what it asks.
   *
   * @param task - the row
   * @returns the view's `task`
   */
  private formTaskOf(task: Json): Json {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.formTaskOf().");
    const out: Json = {
      id: String(task.id),
      status: String(task.status),
      origin: task.origin === 'form' ? 'form' : 'pep',
      subject: task.subject || {},
      action: task.action || {},
      resource: task.resource || {},
      application: String(task.application || ''),
      createdAt: Number(task.createdAt) || 0,
      expiresAt: Number(task.expiresAt) || 0
    };
    if (task.status === 'approved' && task.approval &&
        !task.approval.revoked) {
      out.approvedUntil = Number(task.approval.approvedUntil) || 0;
    }
    if (task.entitlement) {
      out.entitlement = String(task.entitlement);
    }
    log.debug("Leaving AccessRequests.formTaskOf().");
    return out;
  }

  /**
   * The requests whose subject is this person, newest first, through the
   * subject index — never a walk of the store.
   *
   * @param username - the signed-in person
   * @returns the rows
   */
  private mineOf(username: string): Json[] {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.mineOf().");
    const seen = new Set<string>();
    const out: Json[] = [];
    self.approverIdentity(username).identity.forEach(function (name: string) {
      self.idsUnder(AccessRequests.subjectKey(name)).forEach(
        function (id: string) {
          if (seen.has(id)) {
            return;
          }
          seen.add(id);
          const task = self.task(id);
          if (task && Number(task.keepUntil) > self.nowS() &&
              self.isSubject(username, task.subject)) {
            out.push(self.formTaskOf(task));
          }
        });
    });
    out.sort(function (a: Json, b: Json) {
      return b.createdAt - a.createdAt;
    });
    log.debug("Leaving AccessRequests.mineOf(). " + out.length);
    return out.slice(0, MAX_MINE);
  }

  /**
   * The page's answer: the form for a denial (`evaluationId`), the ticket
   * for a request (`request`), or the person's own requests (neither).
   *
   * @param username - the signed-in person
   * @param asked - `{ evaluationId, request }`
   * @returns `{ view }`, or `{ refusal: { status, code, message }, view }`
   */
  formView(username: string, asked: Json): Json {
    const self = this;
    const { log, denials } = this.deps;
    log.debug("Entering AccessRequests.formView().");
    const view: Json = { enabled: self.formOn(), mode: 'mine' };
    const refuse = function (status: number, code: string,
                             message: string): Json {
      log.debug("Entering refuse(). " + code);
      log.debug("Leaving refuse().");
      return { refusal: { status: status, code: code, message: message },
               view: { enabled: view.enabled, mode: 'none' } };
    };
    if (!view.enabled) {
      log.debug("Leaving AccessRequests.formView(). Off.");
      return { view: { enabled: false, mode: 'none' } };
    }
    const evaluationId = String((asked || {}).evaluationId || '')
      .slice(0, MAX_ID);
    const requestId = String((asked || {}).request || '').slice(0, MAX_ID);
    if (requestId) {
      const task = self.task(requestId);
      if (!task || Number(task.keepUntil) <= self.nowS() ||
          !self.isSubject(username, task.subject)) {
        log.debug("Leaving AccessRequests.formView(). Not theirs.");
        return refuse(404, 'STS-AUTHZEN-0146', 'There is no access ' +
                      'request about you with that id.');
      }
      view.mode = 'task';
      view.task = self.formTaskOf(task);
      log.debug("Leaving AccessRequests.formView(). The ticket.");
      return { view: view };
    }
    if (!evaluationId) {
      view.mine = self.mineOf(username);
      log.debug("Leaving AccessRequests.formView(). Their requests.");
      return { view: view };
    }
    const row = denials.get(evaluationId);
    if (!row || Number(row.keepUntil) <= self.nowS()) {
      log.debug("Leaving AccessRequests.formView(). No such denial.");
      return refuse(404, 'STS-AUTHZEN-0145', 'This link names no access ' +
                    'request that can be made here. Ask the application ' +
                    'again for a new one.');
    }
    if (!self.isSubject(username, row.subject)) {
      log.debug("Leaving AccessRequests.formView(). Not their denial.");
      return refuse(404, 'STS-AUTHZEN-0146', 'This access request is not ' +
                    'about you, so you cannot make it.');
    }
    const again = self.recalled('jti', String(row.jti || ''));
    const earlier = again ? self.task(String(again.task)) : null;
    if (earlier) {
      view.mode = 'task';
      view.task = self.formTaskOf(earlier);
      log.debug("Leaving AccessRequests.formView(). Already made.");
      return { view: view };
    }
    const request = self.formRequestOf(row);
    if (!(request.expiresAt > 0) ||
        self.nowS() > request.expiresAt + SKEW_S) {
      log.debug("Leaving AccessRequests.formView(). Expired.");
      return refuse(410, 'STS-AUTHZEN-0147', 'This access request can no ' +
                    'longer be made: its link has expired. Ask the ' +
                    'application again for a new one.');
    }
    view.mode = 'denial';
    view.request = request;
    log.debug("Leaving AccessRequests.formView(). The form.");
    return { view: view };
  }

  /**
   * The person submits the access request a recorded denial allows, on
   * the hosted form.
   *
   * @param username - the signed-in person
   * @param given - `{ evaluationId, justification, durationS, emergency }`
   * @returns `{ ok, task }`, or `{ ok: false, status, code, error, view }`
   */
  submitByForm(username: string, given: Json): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.submitByForm().");
    const refuse = function (status: number, code: string, error: string,
                             view: Json): Json {
      log.debug("Entering refuse(). " + code);
      log.debug("Leaving refuse().");
      return { ok: false, status: status, code: code, error: error,
               view: view || { enabled: self.formOn(), mode: 'none' } };
    };
    if (!self.formOn()) {
      log.debug("Leaving AccessRequests.submitByForm(). Off.");
      return refuse(403, 'STS-AUTHZEN-0148', 'Access requests cannot be ' +
                    'made here: the hosted form is turned off.', null);
    }
    const shown = self.formView(username,
      { evaluationId: String((given || {}).evaluationId || '') });
    if (shown.refusal) {
      log.debug("Leaving AccessRequests.submitByForm(). " +
                shown.refusal.code);
      return refuse(shown.refusal.status, shown.refusal.code,
                    shown.refusal.message, shown.view);
    }
    if (shown.view.mode !== 'denial') {
      log.debug("Leaving AccessRequests.submitByForm(). Already made.");
      return refuse(409, 'STS-AUTHZEN-0076', 'This access request was ' +
                    'already made.', shown.view);
    }
    const row = self.deps.denials.get(shown.view.request.evaluationId);
    const bound = self.denialByEvaluation(String(row.evaluationId),
                                          String(row.base || ''));
    if (!bound) {
      log.debug("Leaving AccessRequests.submitByForm(). Gone.");
      return refuse(404, 'STS-AUTHZEN-0145', 'This link names no access ' +
                    'request that can be made here.', null);
    }
    // THE SAME READER AS A PEP'S SUBMISSION: the schema's augmentations,
    // built from the form's fields.
    const durationS = Math.floor(Number((given || {}).durationS) || 0);
    const augmented: Json = { context: {}, requested_access: {} };
    const justification = String((given || {}).justification || '').trim();
    if (justification) {
      augmented.context.business_justification = justification;
    }
    if (durationS > 0) {
      augmented.requested_access.requested_until =
        instant((self.nowS() + durationS) * 1000);
    }
    if ((given || {}).emergency === true) {
      augmented.requested_access.emergency = true;
    }
    if ((given || {}).entitlement) {
      augmented.requested_access.entitlement =
        String((given || {}).entitlement);
    }
    const asked = self.requestedAccess(augmented, bound.terms || {});
    if (asked.problem) {
      log.debug("Leaving AccessRequests.submitByForm(). " + asked.code);
      return refuse(400, asked.code, asked.problem, shown.view);
    }
    if (self.pendingCount() >=
        self.seconds('authzen.accessRequestMaxPending')) {
      log.debug("Leaving AccessRequests.submitByForm(). Full.");
      return refuse(503, 'STS-AUTHZEN-0078', 'This realm holds as many ' +
                    'pending access requests as it may; try again later.',
                    shown.view);
    }
    const task = self.openTask({
      base: String(row.base || ''), requester: String(bound.caller || ''),
      requesterKind: '', client: null,
      application: String(bound.application || ''), bound: bound,
      asked: asked, callback: null, key: '',
      fingerprint: stsCrypto.digest('sha256',
        AccessRequests.canonical({ form: augmented,
                                   evaluation_id: row.evaluationId }),
        'base64url'),
      actor: username, origin: 'form', formSubmittedBy: username });
    log.debug("Leaving AccessRequests.submitByForm(). " + task.id);
    return { ok: true, task: task };
  }

  /**
   * Verifies a binding token: this realm's signature, the typ, the issuer
   * and the audience. Expiry is the caller's, with the skew.
   *
   * @param token - the compact JWS
   * @param base - this realm's base, as the submission reached it
   * @returns the claims, or null
   */
  verifyBinding(token: string, base: string): Json | null {
    const { log, helpers } = this.deps;
    log.debug("Entering AccessRequests.verifyBinding().");
    let claims: Json = null;
    try {
      claims = helpers.verifyOwnJws(token, { ignoreExpiration: true });
    } catch (e) {
      log.debug("Caught in AccessRequests.verifyBinding(): " +
                ((e && e.message) || e));
      claims = null;
    }
    const audiences = claims ? [].concat(claims.aud || []) : [];
    const ok = !!claims &&
      claims.typ === 'authzen-access-request-denial' &&
      claims.iss === base && audiences.indexOf(base + REQUESTS_PATH) >= 0;
    log.debug("Leaving AccessRequests.verifyBinding(). " + ok);
    return ok ? claims : null;
  }

  /**
   * What differs between a submission and the denial it names, or ''.
   *
   * @param bound - the binding token's claims
   * @param given - the submission
   * @param callerName - the caller submitting it
   * @returns a short description, or ''
   */
  bindingMismatch(bound: Json, given: Json, callerName: string): string {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.bindingMismatch().");
    let out = '';
    if (String(bound.caller) !== String(callerName)) {
      out = 'the denial was answered to another caller';
    }
    const hash = typeof bound.binding_hash === 'string'
      ? bound.binding_hash : '';
    if (!out && hash) {
      let computed = '';
      try {
        const members = bound.binding_context_members;
        computed = AccessRequests.bindingHash(
          AccessRequests.bound('subject', given.subject),
          AccessRequests.bound('resource', given.resource),
          AccessRequests.bound('action', given.action),
          Array.isArray(members)
            ? AccessRequests.relevant(given.context, members) : {});
      } catch (e) {
        // A tuple JCS cannot hold is not the denied one.
        log.debug("Caught in AccessRequests.bindingMismatch(): " +
                  ((e && e.message) || e));
        computed = '';
      }
      if (computed !== hash) {
        out = 'binding_hash does not match the denied tuple';
      }
    }
    if (!out && isObject(bound.subject)) {
      ['subject', 'resource', 'action'].forEach(function (name: string) {
        if (!out && AccessRequests.canonical(AccessRequests.bound(name,
              given[name])) !== AccessRequests.canonical(bound[name])) {
          out = name + ' differs from the denied ' + name;
        }
      });
      if (!out && AccessRequests.canonical(AccessRequests.relevant(
            given.context, bound.binding_context_members || [])) !==
          AccessRequests.canonical(bound.context || {})) {
        out = 'an authorization-relevant context member (' +
              (bound.binding_context_members || []).join(', ') +
              ') differs from the denied evaluation\'s';
      }
    } else if (!out && !hash) {
      out = 'the binding token carries no denied tuple';
    }
    log.debug("Leaving AccessRequests.bindingMismatch(). " + (out || 'ok'));
    return out;
  }

  /**
   * The JSON Schema (draft 2020-12) of the augmentations a submission
   * may add (#1204). `$id` is the URL the document is served at.
   * `requestedAccess()` remains the reader: this document is what an
   * autonomous PEP is told to add, and a submission is not checked
   * against it. Other members of a submission, and other members of
   * `context`, stay allowed — the schema does not set
   * `additionalProperties` to false.
   *
   * @param id - the document's own URL
   * @returns the schema
   */
  static submissionSchema(id: string, catalogs?: boolean): Json {
    log.debug("Entering AccessRequests.submissionSchema().");
    const justification: Json = {
      type: 'string',
      minLength: 1,
      maxLength: MAX_TEXT,
      description: 'A business justification. It is trimmed, and at ' +
                   'most ' + MAX_TEXT + ' characters are kept. Required ' +
                   'when requested_access.emergency is true.'
    };
    const out: Json = {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      $id: id,
      title: 'Access request augmentations',
      description: 'What this realm accepts added to an access request ' +
                   'submission. Other members of the submission are the ' +
                   'profile\'s and are not described here. None of these ' +
                   'is required unless requested_access.emergency is true.',
      type: 'object',
      properties: {
        context: {
          type: 'object',
          properties: { business_justification: justification }
        },
        requested_access: {
          type: 'object',
          properties: {
            requested_until: {
              type: 'string',
              format: 'date-time',
              description: 'An RFC 3339 instant in the future. It ' +
                           'shortens the approval. Omitted, the ' +
                           'approval holds for the policy\'s maximum.'
            },
            emergency: {
              type: 'boolean',
              description: 'True asks for emergency access. The ' +
                           'denial\'s policy must allow it, which this ' +
                           'document cannot say. False and omitted are ' +
                           'an ordinary submission.'
            }
          }
        }
      },
      allOf: [{
        if: {
          type: 'object',
          properties: {
            requested_access: {
              type: 'object',
              properties: { emergency: { const: true } },
              required: ['emergency']
            }
          },
          required: ['requested_access']
        },
        then: {
          type: 'object',
          properties: {
            context: {
              type: 'object',
              properties: { business_justification: justification },
              required: ['business_justification']
            }
          },
          required: ['context']
        }
      }]
    };
    // THE CATALOG'S FIELD (#1204), described while the catalogs answer:
    // its values are the Catalog Endpoint's, so the schema says only its
    // shape (the CATALOG companion's section 6: the schema defines the
    // data, the Catalogs Document where it comes from).
    if (catalogs) {
      out.properties.requested_access.properties.entitlement = {
        type: 'string',
        minLength: 1,
        maxLength: MAX_ID,
        description: 'Required when the denial names ' +
                     'request_catalogs_url: one of the values its ' +
                     'Catalog Endpoint lists, exactly as listed.'
      };
    }
    log.debug("Leaving AccessRequests.submissionSchema().");
    return out;
  }

  /**
   * Reads `requested_access` (the two well-known members, the others
   * ignored as the profile's forward compatibility asks) and the
   * emergency path's justification.
   *
   * @param given - the submission
   * @param terms - the advice's terms
   * @returns `{ until, emergency, justification }` or `{ problem, code }`
   */
  requestedAccess(given: Json, terms: Json): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.requestedAccess().");
    const shape = authzenModel.field('access-request', 'requested_access',
                                     given.requested_access);
    if (shape) {
      log.debug("Leaving AccessRequests.requestedAccess(). Not an object.");
      return { problem: shape.message, code: shape.code };
    }
    const asked: Json = given.requested_access === undefined ? {}
      : given.requested_access;
    let until = 0;
    if (asked.requested_until !== undefined) {
      const at = Date.parse(String(asked.requested_until));
      if (typeof asked.requested_until !== 'string' || !(at > 0) ||
          Math.floor(at / 1000) <= self.nowS()) {
        log.debug("Leaving AccessRequests.requestedAccess(). A bad until.");
        return { problem: 'requested_access.requested_until must be an ' +
                          'RFC 3339 instant in the future.',
                 code: 'STS-AUTHZEN-0096' };
      }
      until = Math.floor(at / 1000);
    }
    const emergency = asked.emergency === true;
    const context: Json = isObject(given.context) ? given.context : {};
    const justification = typeof context.business_justification ===
      'string' ? context.business_justification.trim().slice(0, MAX_TEXT)
               : '';
    if (emergency && !terms.emergency) {
      log.debug("Leaving AccessRequests.requestedAccess(). No emergency.");
      return { problem: 'requested_access.emergency was asked for, and the ' +
                        'policy that denied this does not allow emergency ' +
                        'access to it.',
               code: 'STS-AUTHZEN-0083' };
    }
    if (emergency && !justification) {
      log.debug("Leaving AccessRequests.requestedAccess(). Unjustified.");
      return { problem: 'Emergency access needs a business justification, ' +
                        'in context.business_justification.',
               code: 'STS-AUTHZEN-0083' };
    }
    // THE CATALOG'S VALUE, VALIDATED WHEN THE SUBMISSION ARRIVES (the
    // CATALOG companion's section 10.3): one of the denial's own
    // entitlements, required when it lists any. Off, the advice's list is
    // ignored, and so is the member.
    let entitlement = '';
    const listed: Json[] = this.catalogsOn()
      ? (terms.entitlements || []) : [];
    if (listed.length) {
      const chosen = asked.entitlement;
      const known = typeof chosen === 'string' &&
        listed.some(function (one: Json) {
          return one.value === chosen;
        });
      if (!known) {
        log.debug("Leaving AccessRequests.requestedAccess(). No " +
                  "entitlement.");
        return { problem: 'requested_access.entitlement must be one of the ' +
                          'values the denial\'s catalog lists.',
                 code: 'STS-AUTHZEN-0151' };
      }
      entitlement = String(chosen);
    }
    log.debug("Leaving AccessRequests.requestedAccess().");
    return { until: until, emergency: emergency,
             justification: justification, entitlement: entitlement };
  }

  // -------------------------------------------------------------------------
  // THE CALLBACK (the CALLBACK companion), rcbj's decision 4, retried by
  // the access-request job (#1202). A callback is registered only for an
  // application. The task status is never written `failed` because of a
  // delivery: `failed` is itself a callback event, `finish()` moves a task
  // exactly once from `pending`, and the status endpoint is what a PEP
  // enforces from. `callbackDelivery.state` is what becomes `failed`.
  // -------------------------------------------------------------------------
  // An integer setting held to the callback bounds. A value the row already
  // clamped still passes through here when an old task has none.
  private clampAttempts(value: number): number {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.clampAttempts().");
    const n = Math.floor(Number(value));
    let out = 5;
    if (n > 20) {
      out = 20;
    } else if (n >= 1) {
      out = n;
    } else {
      out = 1;
    }
    log.debug("Leaving AccessRequests.clampAttempts().");
    return out;
  }

  private clampBackoff(value: number): number {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.clampBackoff().");
    const n = Math.floor(Number(value));
    let out = 60;
    if (n > 86400) {
      out = 86400;
    } else if (n >= 60) {
      out = n;
    }
    log.debug("Leaving AccessRequests.clampBackoff().");
    return out;
  }

  // The directory entry the caller is, or null when it cannot be read. An
  // mTLS caller is kind `entry` named by DN, including an application; a
  // bearer caller is kind `application` named by its client id.
  private callbackCaller(caller: Json): Json | null {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.callbackCaller().");
    const key = caller && caller.kind === 'application'
      ? String(caller.identifier || caller.clientId || caller.name || '')
      : String((caller && caller.name) || '');
    let looked: Json = null;
    try {
      looked = this.deps.loadAdmin().callerOf(key);
    } catch (e) {
      // A registry that cannot be read registers nothing: the request is
      // then refused a callback, the safe direction.
      log.debug("Caught in AccessRequests.callbackCaller(): " +
                ((e && e.message) || e));
      looked = null;
    }
    log.debug("Leaving AccessRequests.callbackCaller().");
    return looked;
  }

  // The realm settings, overridden by the config line for this exact URL
  // (`endpoint` plus a space). A line that does not parse falls back to
  // the settings: set-callbacks already refused a bad one.
  private policyFor(endpoint: string, configs: string[]): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.policyFor().");
    let attempts = self.clampAttempts(
      self.seconds('authzen.callbackAttempts'));
    let backoffS = self.clampBackoff(
      self.seconds('authzen.callbackBackoffS'));
    const prefix = endpoint + ' ';
    const line = (configs || []).filter(function (one: string) {
      return String(one).indexOf(prefix) === 0;
    })[0];
    if (line) {
      String(line).slice(prefix.length).split(/\s+/).forEach(
        function (token: string) {
          const attemptsMatch = /^attempts=(\d+)$/.exec(token);
          const backoffMatch = /^backoff=(\d+)$/.exec(token);
          if (attemptsMatch) {
            attempts = self.clampAttempts(Number(attemptsMatch[1]));
          }
          if (backoffMatch) {
            backoffS = self.clampBackoff(Number(backoffMatch[1]));
          }
        });
    }
    log.debug("Leaving AccessRequests.policyFor().");
    return { attempts: attempts, backoffS: backoffS };
  }

  // An old task recorded the endpoint and not the bound. The first attempt
  // snapshots the settings then in force, so a later change does not
  // rewrite an in-flight delivery.
  private ensurePolicy(task: Json): void {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.ensurePolicy().");
    const callback = task.callback || {};
    if (!callback.attempts) {
      callback.attempts = self.clampAttempts(
        self.seconds('authzen.callbackAttempts'));
    }
    if (!callback.backoffS) {
      callback.backoffS = self.clampBackoff(
        self.seconds('authzen.callbackBackoffS'));
    }
    task.callback = callback;
    log.debug("Leaving AccessRequests.ensurePolicy().");
  }

  private ensureDelivery(task: Json): Json {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.ensureDelivery().");
    if (!task.callbackDelivery) {
      task.callbackDelivery = {
        state: 'pending',
        attempts: [],
        nextAt: 0,
        inflightUntil: 0,
        bound: task.callback.attempts,
        backoffS: task.callback.backoffS
      };
    }
    log.debug("Leaving AccessRequests.ensureDelivery().");
    return task.callbackDelivery;
  }

  private flightKey(task: Json): string {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.flightKey().");
    log.debug("Leaving AccessRequests.flightKey().");
    return String(task.realm || '') + '\n' + String(task.id || '');
  }

  // A network error, a timeout, an unresolved name or an HTTP 5xx can
  // succeed later. A 4xx, a 3xx and an outbound-policy refusal cannot.
  private deliveryRetryable(status: number, kind: string): boolean {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.deliveryRetryable().");
    let retry = false;
    if (status >= 500) {
      retry = true;
    } else if (status === 0 && (kind === '' || kind === 'network' ||
                                kind === 'timeout' ||
                                kind === 'unresolved')) {
      retry = true;
    }
    log.debug("Leaving AccessRequests.deliveryRetryable(). " + retry);
    return retry;
  }

  /**
   * The callback URLs registered for a caller: an application's
   * `appAuthzenCallbackUri`, or a person's or service account's
   * `stsAuthzenCallbackUri` (rcbj's decision 4 on #1180: a URL registered
   * for the requester; honoured again since the review of #1202, so a
   * 1.1.0 registration keeps working).
   *
   * @param caller - the caller, `{ kind, name, identifier }`
   * @returns the URLs
   */
  registeredCallbacks(caller: Json): string[] {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.registeredCallbacks().");
    const looked = this.callbackCaller(caller);
    const out = looked && Array.isArray(looked.callbacks)
      ? looked.callbacks : [];
    log.debug("Leaving AccessRequests.registeredCallbacks(). " + out.length);
    return out;
  }

  /**
   * Reads a submission's `callback` and holds its endpoint to the caller's
   * registered URLs, exactly.
   *
   * @param given - the submission's `callback`
   * @param caller - the caller
   * @returns `{ value }` (null for none) or `{ problem }`
   */
  callbackOf(given: unknown, caller: Json): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.callbackOf().");
    if (given === undefined) {
      log.debug("Leaving AccessRequests.callbackOf(). None.");
      return { value: null };
    }
    const shape = authzenModel.field('access-request', 'callback', given);
    if (shape) {
      log.debug("Leaving AccessRequests.callbackOf(). Not an object.");
      return { problem: shape.message };
    }
    const looked = self.callbackCaller(caller);
    const asked: Json = given;
    const endpoint = String(asked.endpoint);
    const urls = looked && Array.isArray(looked.callbacks)
      ? looked.callbacks : [];
    if (!/^https:\/\//i.test(endpoint) || urls.indexOf(endpoint) < 0) {
      log.debug("Leaving AccessRequests.callbackOf(). Not registered.");
      return { problem: 'callback.endpoint must be an https URL an ' +
                        'administrator registered for this caller; ' +
                        'this service never dials one taken from a ' +
                        'request alone.' };
    }
    const listed = authzenModel.field('access-request', 'callback.events',
                                      asked.events);
    if (listed) {
      log.debug("Leaving AccessRequests.callbackOf(). Bad events.");
      return { problem: listed.message };
    }
    const events: string[] = asked.events === undefined ? EVENTS.slice(0)
      : asked.events.map(String);
    const state = asked.state === undefined ? undefined
      : String(asked.state).slice(0, MAX_TEXT);
    const policy = self.policyFor(endpoint,
      looked && Array.isArray(looked.callbackConfigs)
        ? looked.callbackConfigs : []);
    log.debug("Leaving AccessRequests.callbackOf().");
    return { value: { endpoint: endpoint, state: state,
                      attempts: policy.attempts, backoffS: policy.backoffS,
                      events: events.filter(function (one: string) {
                        return EVENTS.indexOf(one) >= 0;
                      }) } };
  }

  /**
   * Sends a finished task's callback, where it asked for one and for this
   * event. The first attempt runs from `finish()` and is not awaited. A
   * later attempt is the access-request job. The notification carries no
   * `result`, so a PEP fetches the task before it enforces; it is
   * authenticated by a short JWT this realm signs, audienced to the
   * endpoint, as the Bearer — verifiable with the realm's JWKS.
   *
   * @param task - the finished row
   * @returns a promise of whether it was sent, for a test
   */
  notify(task: Json): Promise<boolean> {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.notify(). " + task.id);
    // THE ROW AS IT IS NOW, never one a caller captured earlier (#1202):
    // the sweep walks rows it read before this, and another process may
    // have written since. Only the delivery record is written here.
    const row = self.currentOf(task) || task;
    const callback = row.callback;
    if (!callback || !Array.isArray(callback.events) ||
        callback.events.indexOf(row.status) < 0) {
      log.debug("Leaving AccessRequests.notify(). Not asked for.");
      return Promise.resolve(false);
    }
    const key = self.flightKey(row);
    const flying = flights.get(key);
    if (flying) {
      log.debug("Leaving AccessRequests.notify(). Already sending.");
      return flying;
    }
    self.ensurePolicy(row);
    const delivery = self.ensureDelivery(row);
    if (delivery.state === 'delivered' || delivery.state === 'failed') {
      log.debug("Leaving AccessRequests.notify(). Already " +
                delivery.state + ".");
      return Promise.resolve(false);
    }
    const now = self.nowS();
    if (Number(delivery.inflightUntil) > now ||
        (delivery.attempts.length > 0 && Number(delivery.nextAt) > now)) {
      log.debug("Leaving AccessRequests.notify(). Not due.");
      return Promise.resolve(false);
    }
    const hold = Math.max(Number(delivery.backoffS) || 60, INFLIGHT_MIN_S);
    delivery.inflightUntil = now + hold;
    delivery.nextAt = now + hold;
    delivery.state = 'pending';
    delivery.bound = row.callback.attempts;
    delivery.backoffS = row.callback.backoffS;
    self.save(row);
    let settle: (value: boolean) => void = function () {
      return undefined;
    };
    const promise = new Promise<boolean>(function (resolve) {
      settle = resolve;
    });
    flights.set(key, promise);
    const clear = function (): void {
      if (flights.get(key) === promise) {
        flights.delete(key);
      }
    };
    self.sendCallback(row).then(function (result: Json) {
      const sent = self.settleDelivery(row, result);
      clear();
      settle(sent);
      return sent;
    }, function (e: Json) {
      // The POST rejected rather than answering. Recorded as a retryable
      // attempt, the same as a network error with no policy kind.
      log.debug("Caught in AccessRequests.notify(): " +
                ((e && e.message) || e));
      const sent = self.settleDelivery(row, {
        ok: false, status: 0, kind: '',
        why: String((e && e.message) || e)
      });
      clear();
      settle(sent);
      return sent;
    });
    log.debug("Leaving AccessRequests.notify(). Sending.");
    return promise;
  }

  // The stored row of a task, re-read by id: what a write after an await
  // must start from (rcbj's rule: no lost revocations). The callback
  // policy the caller holds is kept when the stored row has none yet.
  // Null when the row is gone.
  private currentOf(task: Json): Json | null {
    const { log, tasks } = this.deps;
    log.debug("Entering AccessRequests.currentOf().");
    const row = task && task.id ? tasks.get(String(task.id)) : null;
    if (row && row !== task && !row.callback && task.callback) {
      row.callback = task.callback;
    }
    log.debug("Leaving AccessRequests.currentOf(). " + !!row);
    return row || null;
  }

  // The wait after the nth failed attempt (n from 1): the backoff, doubled
  // for each attempt before it, never over a day (#1202).
  private waitAfter(backoffS: number, n: number): number {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.waitAfter().");
    const base = this.clampBackoff(backoffS);
    let wait = base;
    for (let i = 1; i < n && wait < BACKOFF_CAP_S; i += 1) {
      wait *= 2;
    }
    log.debug("Leaving AccessRequests.waitAfter().");
    return Math.min(wait, BACKOFF_CAP_S);
  }

  // The longest a delivery can still be tried after a task finished: each
  // wait of the bound, each attempt's flight, and a run of the job.
  private horizonS(row: Json): number {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.horizonS().");
    const callback = (row && row.callback) || {};
    const bound = this.clampAttempts(Number(callback.attempts) ||
      this.seconds('authzen.callbackAttempts'));
    const backoff = this.clampBackoff(Number(callback.backoffS) ||
      this.seconds('authzen.callbackBackoffS'));
    let total = JOB_EVERY_MS / 1000;
    for (let n = 1; n <= bound; n += 1) {
      total += Math.max(this.waitAfter(backoff, n), INFLIGHT_MIN_S) +
               JOB_EVERY_MS / 1000;
    }
    log.debug("Leaving AccessRequests.horizonS(). " + total);
    return total;
  }

  // Whether a finished task's callback is still to be delivered: it asked
  // for this event, and its delivery is neither delivered nor failed.
  private deliveryOutstanding(row: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.deliveryOutstanding().");
    const callback = row && row.callback;
    const delivery = row && row.callbackDelivery;
    const out = !!callback && Array.isArray(callback.events) &&
      callback.events.indexOf(row.status) >= 0 &&
      !(delivery && (delivery.state === 'delivered' ||
                     delivery.state === 'failed'));
    log.debug("Leaving AccessRequests.deliveryOutstanding(). " + out);
    return out;
  }

  // Signs the notification and posts it. A signing failure is an attempt
  // with status 0 and no policy kind, so it is retried until the bound is
  // spent: a key can be briefly unreadable.
  private sendCallback(task: Json): Promise<Json> {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.sendCallback().");
    const callback = task.callback;
    const payload: Json = { task: self.handleOf(task) };
    if (callback.state !== undefined) {
      payload.state = callback.state;
    }
    let bearer = '';
    try {
      bearer = String(self.deps.loadOauth2().signPublishedDocument(
        { aud: callback.endpoint, sub: task.requester,
          jti: self.deps.helpers.randomId(18),
          typ: 'authzen-access-request-callback', task_id: task.id,
          status: task.status },
        task.base, 300, 'oauth-signed-metadata') || '');
    } catch (e) {
      log.debug("Caught in AccessRequests.sendCallback(): " +
                ((e && e.message) || e));
      bearer = '';
    }
    if (!bearer) {
      log.debug("Leaving AccessRequests.sendCallback(). Not signed.");
      return Promise.resolve({
        ok: false, status: 0, kind: '',
        why: 'the notification could not be signed'
      });
    }
    authzenModel.hold('callback-notification', payload,
                      'an access request callback');
    let sent: Promise<Json>;
    try {
      sent = self.deps.loadFedHttp().deliverJson(
        { id: task.id, authzenCallbackEndpoint: callback.endpoint },
        'authzenCallbackEndpoint', payload,
        { Authorization: 'Bearer ' + bearer }, {});
    } catch (e) {
      log.debug("Caught in AccessRequests.sendCallback(): " +
                ((e && e.message) || e));
      log.debug("Leaving AccessRequests.sendCallback(). Threw.");
      return Promise.resolve({
        ok: false, status: 0, kind: '',
        why: String((e && e.message) || e)
      });
    }
    log.debug("Leaving AccessRequests.sendCallback(). Sending.");
    return Promise.resolve(sent).then(function (result: Json): Json {
      return result || { ok: false, status: 0, kind: '', why: 'no answer' };
    }, function (e: Json): Json {
      log.debug("Caught in AccessRequests.sendCallback(): " +
                ((e && e.message) || e));
      return { ok: false, status: 0, kind: '',
               why: String((e && e.message) || e) };
    });
  }

  // Records one attempt and either schedules the next, gives up, or marks
  // the delivery delivered. The task status is not written. THE ROW IS
  // RE-READ FIRST (#1202): the POST was awaited, so the task this was
  // handed may be older than the store — a revocation written meanwhile
  // would be lost by saving it whole. Only `callbackDelivery` is written
  // onto the row as it is now, and a row the sweep has removed is not
  // brought back.
  private settleDelivery(task: Json, result: Json): boolean {
    const self = this;
    const { log, audit, errorCodes } = this.deps;
    log.debug("Entering AccessRequests.settleDelivery().");
    const current = self.currentOf(task);
    const row = current || task;
    if (!row.callback) {
      row.callback = task.callback;
    }
    const delivery = self.ensureDelivery(row);
    const store = function (): void {
      log.debug("Entering store().");
      if (current) {
        self.save(current);
      }
      log.debug("Leaving store().");
    };
    const ok = !!(result && result.ok);
    const status = Number(result && result.status) || 0;
    const kind = String((result && result.kind) || '');
    const why = String((result && (result.why || result.status)) ||
                       (ok ? '' : 'no answer')).slice(0, 300);
    const now = self.nowS();
    const attempt: Json = { at: now, status: status, ok: ok, why: why,
                            code: '' };
    delivery.attempts.push(attempt);
    const bound = Number(delivery.bound) || 1;
    if (delivery.attempts.length > bound) {
      delivery.attempts = delivery.attempts.slice(delivery.attempts.length -
                                                   bound);
    }
    if (ok) {
      delivery.state = 'delivered';
      delivery.nextAt = 0;
      delivery.inflightUntil = 0;
      store();
      audit.audit({ action: 'authzen.access-request.callback',
                    actor: 'the access request service', protocol: 'AuthZEN',
                    detail: 'The ' + task.status + ' callback for ' +
                            task.id + ' was delivered (' + status + ').' });
      log.debug("Leaving AccessRequests.settleDelivery(). Delivered.");
      return true;
    }
    const retry = self.deliveryRetryable(status, kind) &&
                  delivery.attempts.length < bound;
    attempt.code = retry ? 'STS-AUTHZEN-0091' : 'STS-AUTHZEN-0135';
    audit.audit({ action: 'authzen.access-request.callback',
                  actor: 'the access request service', protocol: 'AuthZEN',
                  errorCode: 'STS-AUTHZEN-0091',
                  detail: 'The ' + task.status + ' callback for ' + task.id +
                          ' was not delivered: ' + why + '.' });
    log.warn(errorCodes.tag('STS-AUTHZEN-0091') + 'authzen: the callback ' +
             'for the access request ' + task.id + ' was not delivered: ' +
             why);
    if (retry) {
      delivery.state = 'pending';
      delivery.nextAt = now + self.waitAfter(Number(delivery.backoffS),
                                             delivery.attempts.length);
      delivery.inflightUntil = 0;
      store();
      log.debug("Leaving AccessRequests.settleDelivery(). Again at " +
                delivery.nextAt + ".");
      return false;
    }
    self.giveUp(row, task.status, bound, 'will not be tried again');
    store();
    log.debug("Leaving AccessRequests.settleDelivery(). Given up.");
    return false;
  }

  // Marks a delivery failed, with the final STS-AUTHZEN-0135 audit row.
  // The caller stores the row.
  private giveUp(row: Json, event: string, bound: number,
                 why: string): void {
    const { log, audit, errorCodes } = this.deps;
    log.debug("Entering AccessRequests.giveUp().");
    const delivery = this.ensureDelivery(row);
    delivery.state = 'failed';
    delivery.nextAt = 0;
    delivery.inflightUntil = 0;
    audit.audit({ action: 'authzen.access-request.callback',
                  actor: 'the access request service', protocol: 'AuthZEN',
                  errorCode: 'STS-AUTHZEN-0135',
                  detail: 'The ' + event + ' callback for ' + row.id +
                          ' ' + why + ' (' + delivery.attempts.length +
                          ' of ' + bound + '). The task status is ' +
                          'unchanged.' });
    log.warn(errorCodes.tag('STS-AUTHZEN-0135') + 'authzen: the callback ' +
             'for the access request ' + row.id + ' ' + why + '.');
    log.debug("Leaving AccessRequests.giveUp().");
  }

  // -------------------------------------------------------------------------
  // THE STATUS AND THE CANCELLATION
  // -------------------------------------------------------------------------
  /**
   * The task a caller may see, or a problem written: a task that is not the
   * caller's is UNKNOWN to it (a leaked handle is not enough, the
   * profile's task handle leakage rule), and one past its retention is
   * expired.
   *
   * @param res - the response, written on a refusal
   * @param caller - the admitted caller
   * @param id - the task id from the path
   * @returns the row, or null when a problem was written
   */
  callersTask(res: Res, caller: Json, id: string): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.callersTask().");
    const task = self.task(String(id || '').slice(0, MAX_ID));
    if (!task || task.requester !== caller.name) {
      self.problem(res, 404, 'unknown_task', 'STS-AUTHZEN-0080',
                   'There is no such task for this caller.');
      log.debug("Leaving AccessRequests.callersTask(). Unknown.");
      return null;
    }
    if (Number(task.keepUntil) <= self.nowS()) {
      self.problem(res, 410, 'task_expired', 'STS-AUTHZEN-0081',
                   'The task handle has expired.');
      log.debug("Leaving AccessRequests.callersTask(). Expired.");
      return null;
    }
    log.debug("Leaving AccessRequests.callersTask().");
    return task;
  }

  /**
   * Answers the task status endpoint: the task, with `Retry-After` while it
   * is pending.
   *
   * @param res - the response
   * @param caller - the admitted caller
   * @param id - the task id
   */
  status(res: Res, caller: Json, id: string): void {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.status().");
    if (String(id || '').indexOf(BUNDLE_PREFIX) === 0) {
      self.bundleStatus(res, caller, String(id));
      log.debug("Leaving AccessRequests.status(). A bundle.");
      return;
    }
    const task = self.callersTask(res, caller, id);
    if (!task) {
      log.debug("Leaving AccessRequests.status(). Refused.");
      return;
    }
    if (task.status === 'pending') {
      res.set('Retry-After',
              String(self.seconds('authzen.accessRequestRetryAfterS')));
    }
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(self.bodyOf(task,
         self.languagesOf((res as Json).req)), null, 2));
    log.debug("Leaving AccessRequests.status(). " + task.status);
  }

  /**
   * Answers the cancellation endpoint: a pending task of the caller's is
   * cancelled; a finished one is 409.
   *
   * @param res - the response
   * @param caller - the admitted caller
   * @param id - the task id
   * @param body - the optional `{ reason, comment }`
   */
  cancel(res: Res, caller: Json, id: string, body: unknown): void {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.cancel().");
    if (String(id || '').indexOf(BUNDLE_PREFIX) === 0) {
      self.bundleCancel(res, caller, String(id), body);
      log.debug("Leaving AccessRequests.cancel(). A bundle.");
      return;
    }
    const task = self.callersTask(res, caller, id);
    if (!task) {
      log.debug("Leaving AccessRequests.cancel(). Refused.");
      return;
    }
    if (task.status !== 'pending') {
      self.problem(res, 409, 'invalid_task_state', 'STS-AUTHZEN-0082',
                   'The task is already ' + task.status + '.');
      log.debug("Leaving AccessRequests.cancel(). Finished.");
      return;
    }
    const given: Json = isObject(body) ? body : {};
    self.finish(task, 'cancelled', {
      actor: caller.name,
      why: 'by the requesting PEP' + (given.reason
        ? ' (' + String(given.reason).slice(0, 64) + ')' : '') });
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(authzenModel.held('task-response',
         { task: self.handleOf(task, self.languagesOf((res as Json).req)) },
         'the cancellation'), null, 2));
    log.debug("Leaving AccessRequests.cancel().");
  }

  // -------------------------------------------------------------------------
  // THE APPROVERS
  // -------------------------------------------------------------------------
  /**
   * Who a person is as an approver: every name they could be the subject
   * or the requester of a request under, lowercased, for the policy's
   * self-approval comparison.
   *
   * @param username - the person
   * @returns `{ dn, keys, identity }`
   */
  approverIdentity(username: string): Json {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.approverIdentity().");
    const identity: string[] = [];
    // A hot path inside one decision: no Entering/Leaving pair.
    const add = function (value: unknown): void {
      const text = String(value == null ? '' : value).trim().toLowerCase();
      if (text && identity.indexOf(text) < 0) {
        identity.push(text);
      }
    };
    add(username);
    let who: Json = { dn: '', keys: [] };
    try {
      who = this.deps.loadOwnership().identityOf(username) || who;
    } catch (e) {
      log.debug("Caught in AccessRequests.approverIdentity(): " +
                ((e && e.message) || e));
    }
    add(who.dn);
    try {
      const hooks = this.deps.loadAdmin().directoryHooks();
      const entry = hooks ? hooks.locate(username) : null;
      const at = (entry && entry.attributes) || {};
      Object.keys(at).forEach(function (key: string) {
        const lower = key.toLowerCase();
        if (lower === 'mail' || lower === 'uid') {
          [].concat(at[key] || []).forEach(add);
        } else if (lower === 'entryuuid') {
          [].concat(at[key] || []).forEach(function (one: unknown) {
            add('urn:uuid:' + String(one));
          });
        }
      });
    } catch (e) {
      log.debug("Caught in AccessRequests.approverIdentity(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving AccessRequests.approverIdentity(). " +
              identity.length);
    return { dn: String(who.dn || ''), keys: who.keys || [],
             identity: identity };
  }

  /**
   * Whether a person is one of a task's approvers: holding a role the
   * advice named, in a group it named, or an owner of the resource
   * application when it named the owners. Routing and a fact; the policy
   * decides.
   *
   * @param username - the person
   * @param task - the row
   * @returns true when eligible
   */
  eligible(username: string, task: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.eligible().");
    const terms: Json = task.terms || {};
    if (!username) {
      log.debug("Leaving AccessRequests.eligible(). Nobody.");
      return false;
    }
    let out = false;
    try {
      if ((terms.roles || []).length) {
        const roles = this.deps.loadRoles();
        const held = roles.rolesOf({ kind: 'user', name: username,
                                     authenticated: true }) || [];
        out = terms.roles.some(function (one: string) {
          return held.indexOf(one) >= 0;
        });
      }
      if (!out && (terms.groups || []).length) {
        const ownership = this.deps.loadOwnership();
        const who = ownership.identityOf(username) || { groups: [] };
        const names = (who.groups || []).map(function (one: Json) {
          return String(one.cn || '').toLowerCase();
        });
        const keys = (who.groups || []).map(function (one: Json) {
          return ownership.Ownership.dnKey(one.dn);
        });
        out = terms.groups.some(function (one: string) {
          return names.indexOf(String(one).toLowerCase()) >= 0 ||
                 keys.indexOf(ownership.Ownership.dnKey(one)) >= 0;
        });
      }
      if (!out && terms.owners) {
        const ownership = this.deps.loadOwnership();
        const facts = ownership.objectOf('application', task.application);
        const who = ownership.identityOf(username) || { keys: [] };
        out = !!facts && facts.found && (facts.owners || []).some(
          function (dn: string) {
            return (who.keys || []).indexOf(
              ownership.Ownership.dnKey(dn)) >= 0;
          });
      }
    } catch (e) {
      // A register that cannot be read makes nobody an approver: the safe
      // direction, since an approver is somebody something is opened to.
      log.debug("Caught in AccessRequests.eligible(): " +
                ((e && e.message) || e));
      out = false;
    }
    log.debug("Leaving AccessRequests.eligible(). " + out);
    return out;
  }

  /**
   * Asks the access-control policy whether this person may decide this
   * request (rcbj's decision 2).
   *
   * @param task - the row
   * @param approver - who, and through which door
   * @param action - the gate's action: `approve-access-request` (an
   *   approval or a denial, the default) or `revoke-access-request`
   * @returns the gate's answer
   */
  mayDecide(task: Json, approver: Approver, action?: string): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.mayDecide().");
    const gate = self.deps.loadGate();
    const asked = action === GATE_REVOKE_ACTION
      ? (gate.ACTION.REVOKE_ACCESS_REQUEST || GATE_REVOKE_ACTION)
      : (gate.ACTION.APPROVE_ACCESS_REQUEST || GATE_ACTION);
    const identity = self.approverIdentity(approver.username);
    // A hot path inside one decision: no Entering/Leaving pair.
    const lower = function (value: unknown): string {
      return String(value == null ? '' : value).toLowerCase();
    };
    const answer = gate.check({
      resource: gate.RESOURCE.AUTHZEN_ACCESS_REQUEST || GATE_RESOURCE,
      action: asked,
      subject: { name: approver.username, kind: 'user',
                 authenticated: true, roles: approver.roles || [] },
      context: { door: approver.door },
      accessRequestObject: {
        id: task.id,
        requester: lower(task.requester),
        subject: lower((task.subject || {}).id),
        subjectType: String((task.subject || {}).type || ''),
        action: String((task.action || {}).name || ''),
        resource: String((task.resource || {}).id || ''),
        resourceType: String((task.resource || {}).type || ''),
        application: String(task.application || ''),
        eligible: self.eligible(approver.username, task),
        door: approver.door,
        approverIdentity: identity.identity
      }
    });
    // A PERMIT, AND NOTHING LESS. The gate allows everything where no
    // policy decides (`xacml.enforceAccess` off, no decider, a policy that
    // will not load) — the right answer for a console somebody must reach
    // to fix a policy, and the wrong one for an approval, which would then
    // be anybody's, their own request included. So an approval needs a
    // policy that said Permit.
    const decided = !!answer && answer.allowed === true &&
                    answer.decision === 'Permit';
    log.debug("Leaving AccessRequests.mayDecide(). " + decided);
    return decided ? answer
      : { allowed: false, decision: String((answer || {}).decision || ''),
          why: answer && answer.allowed
            ? 'No policy decided this (' + String(answer.why || '') +
              '), and an access request is approved only on a Permit.'
            : String((answer || {}).why || '') };
  }

  /**
   * Signs `approval.state`: a JWS of the approved tuple, the approval id
   * and its window. A failure is logged and the approval still stands by
   * id — a same-service PEP looks the row up, and a state that could not
   * be signed is simply absent.
   *
   * @param task - the row, still pending
   * @param approval - the approval about to be stored
   * @returns the compact JWS, or '' when it could not be signed
   */
  private approvalState(task: Json, approval: Json): string {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering AccessRequests.approvalState(). " + task.id);
    const now = self.nowS();
    const until = Number(approval.approvedUntil);
    const claims: Json = {
      aud: task.base,
      typ: 'authzen-access-request-approval',
      id: approval.id,
      task_id: task.id,
      subject: task.subject,
      resource: task.resource,
      action: task.action,
      context: task.context || {},
      binding_context_members: task.contextMembers || [],
      approved_at: instant(Number(approval.approvedAt) * 1000),
      approved_until: instant(until * 1000),
      approver: approval.approver,
      caller: task.requester,
      application: task.application
    };
    let token = '';
    try {
      token = String(self.deps.loadOauth2().signPublishedDocument(
        claims, task.base, Math.max(1, until - now),
        'oauth-signed-metadata') || '');
    } catch (e) {
      // The approval stands by id. A PEP that cannot be shown a state
      // still resolves the row.
      log.debug("Caught in AccessRequests.approvalState(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-AUTHZEN-0140') + 'authzen: an ' +
                'approval\'s state could not be signed, so the approval ' +
                'stands by id: ' + ((e && e.message) || e));
      token = '';
    }
    log.debug("Leaving AccessRequests.approvalState(). " + !!token);
    return token;
  }

  /**
   * Verifies a presented `approval.state` as this realm's JWS of that typ.
   * Expiry is the store's `approvedUntil`, so the token's `exp` is not a
   * second clock.
   *
   * @param token - the compact JWS
   * @returns the claims, or null
   */
  private verifyApprovalState(token: string): Json | null {
    const { log, helpers } = this.deps;
    log.debug("Entering AccessRequests.verifyApprovalState().");
    let claims: Json = null;
    try {
      claims = helpers.verifyOwnJws(token, { ignoreExpiration: true });
    } catch (e) {
      log.debug("Caught in AccessRequests.verifyApprovalState(): " +
                ((e && e.message) || e));
      claims = null;
    }
    if (!claims || claims.typ !== 'authzen-access-request-approval') {
      log.debug("Leaving AccessRequests.verifyApprovalState(). " +
                "Unverifiable.");
      return null;
    }
    log.debug("Leaving AccessRequests.verifyApprovalState(). Verified.");
    return claims;
  }

  // Marks a task approved: the approval, its lifetime and its index row.
  // False when it could not be stored, and the task is then `failed`.
  private approve(task: Json, approver: Approver, why: string): boolean {
    const self = this;
    const { log, helpers } = this.deps;
    log.debug("Entering AccessRequests.approve(). " + task.id);
    const now = self.nowS();
    const terms: Json = task.terms || {};
    const limits = [now + self.seconds('authzen.accessRequestMaxApprovalS')];
    if (Number(terms.maxSeconds) > 0) {
      limits.push(now + Number(terms.maxSeconds));
    }
    if (Number(task.requestedUntil) > now) {
      limits.push(Number(task.requestedUntil));
    }
    if (approver.door === 'emergency') {
      limits.push(now + self.seconds('authzen.accessRequestEmergencyS'));
    }
    const approval: Json = { id: 'apr_' + helpers.randomId(24),
                             approvedAt: now,
                             approvedUntil: Math.min.apply(null, limits),
                             approver: approver.username || approver.door,
                             door: approver.door, revokedAt: 0 };
    const state = self.approvalState(task, approval);
    if (state) {
      approval.state = state;
    }
    // THE APPROVAL IS STORED BEFORE THE TASK SAYS APPROVED (#1202): its
    // index row first, kept as long as the task will be, then the task. A
    // store that refuses either is a step that cannot complete — the task
    // is `failed`, never an `approved` whose approval no re-evaluation can
    // find.
    const keepUntil = Math.max(now + RETENTION_S,
                               Number(approval.approvedUntil));
    const was = { approval: task.approval, decidedBy: task.decidedBy };
    let stored = false;
    try {
      self.remember('approval', approval.id, task.id, {}, keepUntil);
      task.approval = approval;
      task.decidedBy = approval.approver;
      self.finish(task, 'approved', { actor: approval.approver, why: why });
      stored = true;
    } catch (e) {
      log.debug("Caught in AccessRequests.approve(): " +
                ((e && e.message) || e));
      self.unstore(task, approval, was, String((e && e.message) || e));
    }
    log.debug("Leaving AccessRequests.approve(). " + stored);
    return stored;
  }

  // An approval that could not be stored: the task back to pending as it
  // was, its index row dropped, and the task moved to `failed`.
  private unstore(task: Json, approval: Json, was: Json,
                  why: string): void {
    const self = this;
    const { log, index } = this.deps;
    log.debug("Entering AccessRequests.unstore(). " + task.id);
    try {
      index.delete('approval:' + stsCrypto.credentialDigest(approval.id));
    } catch (e) {
      // The row may never have been written. A stray one names a task
      // that is not approved, so verify() refuses it.
      log.debug("Caught in AccessRequests.unstore(): " +
                ((e && e.message) || e));
    }
    task.status = 'pending';
    delete task.finishedAt;
    task.approval = was.approval;
    task.decidedBy = was.decidedBy;
    self.finish(task, 'failed', {
      actor: 'the access request service', code: 'STS-AUTHZEN-0142',
      why: 'the approval by ' + String(approval.approver) + ' could not be ' +
           'stored (' + why.slice(0, 200) + ')' });
    log.debug("Leaving AccessRequests.unstore().");
  }

  /**
   * Whether this person may revoke this approval. The policy is asked
   * `revoke-access-request` (#1203). A repository policy that never names
   * that action predates it, and is asked `approve-access-request`
   * instead, the question every revocation was until then — so a
   * deployment's own policy decides as it always did.
   *
   * @param task - the row
   * @param approver - who, and through which door
   * @returns the gate's answer
   */
  mayRevoke(task: Json, approver: Approver): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.mayRevoke().");
    const answer = self.mayDecide(task, approver, GATE_REVOKE_ACTION);
    if (answer.allowed || self.policyNamesRevoke()) {
      log.debug("Leaving AccessRequests.mayRevoke(). " + answer.allowed);
      return answer;
    }
    log.debug("Leaving AccessRequests.mayRevoke(). The policy predates " +
              "the action.");
    return self.mayDecide(task, approver, GATE_ACTION);
  }

  // Whether the access-control policy in force names the revoke action:
  // the built-in document does; a repository entry does when its text
  // carries it. One that cannot be read is taken to name it, which asks
  // the revoke question alone — the narrower answer.
  private policyNamesRevoke(): boolean {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.policyNamesRevoke().");
    let names = true;
    try {
      const loaded = this.deps.loadAccessPep().accessPolicy();
      names = !loaded || !loaded.policy || !!loaded.builtIn ||
        JSON.stringify(loaded.policy).indexOf(GATE_REVOKE_ACTION) >= 0;
    } catch (e) {
      log.debug("Caught in AccessRequests.policyNamesRevoke(): " +
                ((e && e.message) || e));
      names = true;
    }
    log.debug("Leaving AccessRequests.policyNamesRevoke(). " + names);
    return names;
  }

  /**
   * One approver's act on one request — approve, deny or revoke — the one
   * door the portal and the console both reach. The policy is asked first.
   *
   * @param id - the task id
   * @param decision - `approve`, `deny` or `revoke`
   * @param approver - who, and through which door
   * @returns `{ ok: true, task }`, or a coded refusal `{ ok: false, errors }`
   */
  decide(id: string, decision: string, approver: Approver): Json {
    const self = this;
    const { log, errorCodes, audit } = this.deps;
    log.debug("Entering AccessRequests.decide(). " + decision);
    const refused = function (code: string, message: string): Json {
      log.debug("Entering refused(). " + code);
      log.debug("Leaving refused().");
      return errorCodes.mark({ ok: false, errors: [message] }, code);
    };
    if (['approve', 'deny', 'revoke'].indexOf(decision) < 0) {
      log.debug("Leaving AccessRequests.decide(). Unknown.");
      return refused('STS-AUTHZEN-0090', 'The decision is approve, deny or ' +
                     'revoke.');
    }
    const task = self.task(String(id || '').slice(0, MAX_ID));
    const wanted = decision === 'revoke' ? 'approved' : 'pending';
    if (!task || task.status !== wanted ||
        (decision === 'revoke' && (!task.approval ||
                                   task.approval.revokedAt))) {
      log.debug("Leaving AccessRequests.decide(). Not " + wanted + ".");
      return refused(decision === 'revoke' ? 'STS-AUTHZEN-0095'
                                           : 'STS-AUTHZEN-0089',
                     'There is no ' + (decision === 'revoke'
                       ? 'live approval' : 'pending access request') +
                     ' with that id in this realm.');
    }
    const answer = decision === 'revoke'
      ? self.mayRevoke(task, approver) : self.mayDecide(task, approver);
    if (!answer.allowed) {
      audit.audit({ action: 'authzen.access-request.approver-refused',
                    actor: approver.username, protocol: 'AuthZEN',
                    errorCode: 'STS-AUTHZEN-0088',
                    detail: 'The access-control policy refused ' +
                            approver.username + ' the ' + decision + ' of ' +
                            task.id + ' (via ' + approver.door + '): ' +
                            String(answer.why || '').slice(0, 300) });
      log.debug("Leaving AccessRequests.decide(). The policy refused.");
      return refused('STS-AUTHZEN-0088', 'The access-control policy does ' +
                     'not let you decide this request (action ' +
                     (decision === 'revoke' ? GATE_REVOKE_ACTION
                                            : GATE_ACTION) +
                     ' on ' + GATE_RESOURCE + '). ' +
                     String(answer.why || ''));
    }
    // ON THE PORTAL'S DOOR A PERSON REVOKES ONLY AN APPROVAL THEY GAVE
    // (#1203), asked after the policy so a refusal it makes is still its
    // own: the page lists only those, and the policy question alone would
    // let any permitted approver revoke another's. The console's door is
    // an administrator's, and keeps the policy's answer.
    if (decision === 'revoke' && approver.door === 'portal' &&
        String(task.approval.approver || '') !== approver.username) {
      audit.audit({ action: 'authzen.access-request.approver-refused',
                    actor: approver.username, protocol: 'AuthZEN',
                    errorCode: 'STS-AUTHZEN-0141',
                    detail: approver.username + ' was refused the ' +
                            'revocation of ' + task.id + ' on the portal: ' +
                            'the approval is not one they gave.' });
      log.debug("Leaving AccessRequests.decide(). Not their approval.");
      return refused('STS-AUTHZEN-0141', 'You can revoke only an approval ' +
                     'you gave.');
    }
    if (decision === 'approve') {
      if (!self.approve(task, approver, 'approved by ' + approver.username +
                        ' via the ' + approver.door)) {
        log.debug("Leaving AccessRequests.decide(). Not stored.");
        return refused('STS-AUTHZEN-0142', 'The approval could not be ' +
                       'stored, so the access request has failed.');
      }
    } else if (decision === 'deny') {
      task.decidedBy = approver.username;
      self.finish(task, 'denied', { actor: approver.username,
                                    why: 'denied by ' + approver.username +
                                         ' via the ' + approver.door });
    } else {
      task.approval.revokedAt = self.nowS();
      self.save(task);
      audit.audit({ action: 'authzen.access-request.revoked',
                    actor: approver.username, protocol: 'AuthZEN',
                    detail: 'The approval of ' + task.id + ' was revoked ' +
                            'by ' + approver.username + ' via the ' +
                            approver.door + '; a re-evaluation carrying it ' +
                            'is not approved from now on.' });
      // The revocation stands even when the requester cannot be mailed.
      self.mailRequester(task, approver);
    }
    log.debug("Leaving AccessRequests.decide(). " + task.status);
    return { ok: true, changed: true, task: self.viewOf(task) };
  }

  /**
   * An administrator's cancellation of a pending request.
   *
   * @param id - the task id
   * @param actor - the administrator
   * @returns `{ ok: true, task }` or a coded refusal
   */
  cancelByAdministrator(id: string, actor: string): Json {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering AccessRequests.cancelByAdministrator().");
    const task = self.task(String(id || '').slice(0, MAX_ID));
    if (!task || task.status !== 'pending') {
      log.debug("Leaving AccessRequests.cancelByAdministrator(). Not " +
                "pending.");
      return errorCodes.mark({ ok: false, errors: ['There is no pending ' +
        'access request with that id in this realm.'] }, 'STS-AUTHZEN-0089');
    }
    self.finish(task, 'cancelled', { actor: actor,
                                     why: 'by an administrator' });
    log.debug("Leaving AccessRequests.cancelByAdministrator().");
    return { ok: true, changed: true, task: self.viewOf(task) };
  }

  /**
   * A task as the console and the portal draw it: what is asked, by whom,
   * for whom, and its state.
   *
   * @param task - the row
   * @returns the view
   */
  viewOf(task: Json): Json {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.viewOf().");
    const approval = task.approval || null;
    log.debug("Leaving AccessRequests.viewOf().");
    // Made on the hosted form (#1204): by whom, for the console.
    const form: Json = task.origin === 'form'
      ? { formSubmittedBy: String(task.formSubmittedBy || '') } : {};
    // The catalog item it chose (#1204), for the approver.
    if (task.entitlement) {
      form.entitlement = String(task.entitlement);
    }
    // Who acted, and where it came from (#1204, the ACTOR companion).
    if (task.actor) {
      form.actor = task.actor;
    }
    if (task.source) {
      form.source = task.source;
    }
    return Object.assign({
      id: task.id, status: task.status, requester: task.requester,
      client: task.client, application: task.application,
      subject: task.subject, action: task.action, resource: task.resource,
      context: task.context, emergency: !!task.emergency,
      justification: task.justification || '',
      createdAt: task.createdAt, expiresAt: task.expiresAt,
      finishedAt: task.finishedAt || 0, decidedBy: task.decidedBy || '',
      approval: approval ? { id: approval.id,
                             approvedAt: approval.approvedAt,
                             approvedUntil: approval.approvedUntil,
                             approver: approval.approver,
                             revoked: !!approval.revokedAt } : null,
      approvers: { roles: (task.terms || {}).roles || [],
                   groups: (task.terms || {}).groups || [],
                   owners: !!(task.terms || {}).owners },
      callbackDelivery: task.callbackDelivery ? {
        state: String(task.callbackDelivery.state || 'pending'),
        bound: Number(task.callbackDelivery.bound) || 0,
        backoffS: Number(task.callbackDelivery.backoffS) || 0,
        nextAt: Number(task.callbackDelivery.nextAt) || 0,
        attempts: (task.callbackDelivery.attempts || []).map(
          function (one: Json) {
            // `code` (#1202): '' for a delivery, the error code otherwise.
            // An attempt recorded before it existed shows the code its
            // outcome had.
            return { at: Number(one.at) || 0, status: Number(one.status) || 0,
                     ok: !!one.ok, why: String(one.why || ''),
                     code: String(one.code || (one.ok ? ''
                                                      : 'STS-AUTHZEN-0091')) };
          })
      } : null
    }, form);
  }

  /**
   * Every task of the ambient realm, newest first, bounded.
   *
   * @param most - how many at most
   * @returns the rows
   */
  list(most: number): Json[] {
    const self = this;
    const { log, tasks } = this.deps;
    log.debug("Entering AccessRequests.list().");
    const out: Json[] = [];
    tasks.forEach(function (row: Json) {
      if (row && row.id) {
        out.push(row);
      }
    });
    out.sort(function (a: Json, b: Json) {
      return Number(b.createdAt) - Number(a.createdAt);
    });
    const shown = out.slice(0, Math.max(0, most)).map(function (row: Json) {
      return self.task(row.id) || row;
    });
    log.debug("Leaving AccessRequests.list(). " + shown.length + " of " +
              out.length);
    return shown;
  }

  /**
   * The pending requests a person may decide: eligible, and the policy
   * letting them — so their own request is not listed where a rule
   * forbids self-approval.
   *
   * @param username - the signed-in person
   * @returns the views
   */
  awaiting(username: string): Json[] {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.awaiting().");
    // THE PENDING INDEX, NOT THE STORE (#1203): the pending tasks only,
    // whose number `authzen.accessRequestMaxPending` bounds, newest first.
    const out = self.rowsOf(self.idsUnder(PENDING_KEY)).filter(
      function (row: Json) {
        return row.status === 'pending' && self.eligible(username, row) &&
          self.mayDecide(row, { username: username,
                                door: 'portal' }).allowed;
      }).slice(0, 100).map(function (row: Json) {
      return self.viewOf(row);
    });
    log.debug("Leaving AccessRequests.awaiting(). " + out.length);
    return out;
  }

  /**
   * The live approvals this person gave and may still revoke (#1203).
   * The approver recorded on the approval, exactly — an emergency
   * approval's approver is the door, so it is not listed here — and the
   * revocation's policy question. One past `approvedUntil` is included:
   * `decide()` still revokes it. Read through the approver's own index
   * row, so the cost is that person's approvals and nobody else's.
   *
   * @param username - the signed-in person
   * @returns the views
   */
  grantedBy(username: string): Json[] {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.grantedBy().");
    const who = String(username || '');
    const ids = who ? self.idsUnder(AccessRequests.approverKey(who)) : [];
    const out = self.rowsOf(ids).filter(function (row: Json) {
      const approval = row.approval;
      return row.status === 'approved' && approval && !approval.revokedAt &&
        approval.approver === who &&
        self.mayRevoke(row, { username: who, door: 'portal' }).allowed;
    }).slice(0, 100).map(function (row: Json) {
      return self.viewOf(row);
    });
    log.debug("Leaving AccessRequests.grantedBy(). " + out.length);
    return out;
  }

  // The tasks an index row lists, newest first, each read with its
  // deadline applied; an id whose task is gone is skipped.
  private rowsOf(ids: string[]): Json[] {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.rowsOf(). " + ids.length);
    const out: Json[] = [];
    ids.forEach(function (id: string) {
      const row = self.task(id);
      if (row && row.id) {
        out.push(row);
      }
    });
    out.sort(function (a: Json, b: Json) {
      return Number(b.createdAt) - Number(a.createdAt);
    });
    log.debug("Leaving AccessRequests.rowsOf(). " + out.length);
    return out;
  }

  // How many tasks of the ambient realm are pending.
  private pendingCount(): number {
    const { log, tasks } = this.deps;
    log.debug("Entering AccessRequests.pendingCount().");
    let n = 0;
    tasks.forEach(function (row: Json) {
      if (row && row.status === 'pending') {
        n += 1;
      }
    });
    log.debug("Leaving AccessRequests.pendingCount(). " + n);
    return n;
  }

  // -------------------------------------------------------------------------
  // THE MAIL (rcbj's decision 3): each approver, at the address on their
  // own entry, through the mail channel — never an address a request names.
  // -------------------------------------------------------------------------
  /**
   * The usernames a task's approvers are, for the mail: the people and the
   * groups' members a configured role names, the named groups' members, and
   * the application's owners (a group owner's members). A computed
   * built-in role has nobody to list and is left out. Bounded.
   *
   * @param task - the row
   * @returns the usernames
   */
  approversOf(task: Json): string[] {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.approversOf().");
    const out = this.approverWalk(task).names;
    log.debug("Leaving AccessRequests.approversOf(). " + out.length);
    return out;
  }

  // The walk `approversOf()` answers, and whether it is CERTAIN (#1202):
  // the directory was readable, nothing threw, and every role the advice
  // named is a configured static role, whose holders are all listed. A
  // computed built-in role, a dynamic selectable role or an unknown one
  // has holders nobody can list, so the walk is not certain then.
  private approverWalk(task: Json): { names: string[]; certain: boolean } {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.approverWalk().");
    const terms: Json = task.terms || {};
    const out: string[] = [];
    let certain = true;
    let hooks: Json = null;
    try {
      hooks = this.deps.loadAdmin().directoryHooks();
    } catch (e) {
      log.debug("Caught in AccessRequests.approverWalk(): " +
                ((e && e.message) || e));
      hooks = null;
    }
    if (!hooks) {
      certain = false;
    }
    // Hot paths of one walk: no Entering/Leaving pair.
    const addName = function (name: unknown): void {
      const text = String(name == null ? '' : name).trim();
      if (text && out.length < MAX_MAILED && out.indexOf(text) < 0) {
        out.push(text);
      }
    };
    const addDn = function (dn: string, depth: number): void {
      const entry = hooks ? hooks.locate(dn) : null;
      if (entry && entry.person) {
        addName(entry.name);
      } else if (hooks && depth < 2) {
        (hooks.members(dn) || []).forEach(function (one: string) {
          addDn(one, depth + 1);
        });
      }
    };
    try {
      const roles = this.deps.loadRoles();
      (terms.roles || []).forEach(function (name: string) {
        const row = roles.read(name);
        if (!row || row.membershipMode === 'dynamic-selectable') {
          certain = false;
        }
        if (row) {
          (row.users || []).forEach(addName);
          (row.groups || []).forEach(function (group: string) {
            addDn(group, 1);
          });
        }
      });
      (terms.groups || []).forEach(function (group: string) {
        addDn(group, 1);
      });
      if (terms.owners) {
        const facts = this.deps.loadOwnership().objectOf('application',
                                                         task.application);
        ((facts && facts.owners) || []).forEach(function (dn: string) {
          addDn(dn, 0);
        });
      }
    } catch (e) {
      log.debug("Caught in AccessRequests.approverWalk(): " +
                ((e && e.message) || e));
      certain = false;
    }
    const subject = String((task.subject || {}).id || '').toLowerCase();
    const names = out.filter(function (one: string) {
      return one.toLowerCase() !== subject;
    });
    // NAMED NOBODY IS NOT NOBODY: advice that named no approver at all is
    // decided by an administrator, so it is never "certainly nobody".
    const named = (terms.roles || []).length + (terms.groups || []).length +
                  (terms.owners ? 1 : 0);
    log.debug("Leaving AccessRequests.approverWalk(). " + names.length);
    return { names: names, certain: certain && named > 0 };
  }

  /**
   * Mails a task's approvers: a pending request waiting for them, or an
   * emergency approval to review after use. Never throws.
   *
   * @param task - the row
   * @returns how many were queued
   */
  mailApprovers(task: Json): number {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering AccessRequests.mailApprovers(). " + task.id);
    let queued = 0;
    try {
      const uses = self.deps.loadMailUses();
      const minutes = Math.max(1, Math.round(
        (Number(task.expiresAt) - self.nowS()) / 60));
      self.approversOf(task).forEach(function (username: string) {
        const sent = uses.authzenAccessRequested(username, {
          requester: task.requester,
          subject: String((task.subject || {}).id || ''),
          action: String((task.action || {}).name || ''),
          resource: String((task.resource || {}).type || '') + ' ' +
                    String((task.resource || {}).id || ''),
          application: task.application,
          emergency: !!task.emergency,
          justification: String(task.justification || ''),
          expiresMinutes: minutes,
          dedupKey: 'authzen-access-request:' + task.id + ':' + username
        });
        if (sent && sent.ok !== false) {
          queued += 1;
        }
      });
    } catch (e) {
      log.warn(errorCodes.tag('STS-AUTHZEN-0093') + 'authzen: the ' +
               'approvers of ' + task.id + ' could not be mailed: ' +
               ((e && e.message) || e));
    }
    log.debug("Leaving AccessRequests.mailApprovers(). " + queued);
    return queued;
  }

  /**
   * The username the mail channel addresses a requester by. The task
   * records the caller's DN, and the channel keys a person by their
   * directory name. An application has no person entry, so it is not
   * mailed.
   *
   * @param task - the row
   * @returns the username, or '' when there is nobody to mail
   */
  private requesterMailName(task: Json): string {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.requesterMailName().");
    const raw = String(task.requester || '').trim();
    if (!raw || task.requesterKind === 'application') {
      log.debug("Leaving AccessRequests.requesterMailName(). Nobody.");
      return '';
    }
    let name = '';
    try {
      const hooks = this.deps.loadAdmin().directoryHooks();
      const entry = hooks && hooks.locate ? hooks.locate(raw) : null;
      if (entry && entry.person && entry.name) {
        name = String(entry.name);
      }
    } catch (e) {
      // A directory that cannot be asked leaves the notice unsent. The
      // revocation already stands.
      log.debug("Caught in AccessRequests.requesterMailName(): " +
                ((e && e.message) || e));
      name = '';
    }
    log.debug("Leaving AccessRequests.requesterMailName(). " +
              (name ? 'A person.' : 'Nobody.'));
    return name;
  }

  /**
   * Mails the requester that an approval of their request was revoked.
   * Never throws: the revocation is already saved. A requester the channel
   * cannot address — an application, a person with no `mail` — is skipped.
   *
   * @param task - the row, already revoked
   * @param approver - who revoked it
   * @returns nothing
   */
  mailRequester(task: Json, approver: Approver): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AccessRequests.mailRequester(). " + task.id);
    try {
      const approval = task.approval || {};
      this.deps.loadMailUses().authzenAccessRevoked(
        this.requesterMailName(task), {
          approver: approver.username || approver.door,
          subject: String((task.subject || {}).id || ''),
          action: String((task.action || {}).name || ''),
          resource: String((task.resource || {}).type || '') + ' ' +
                    String((task.resource || {}).id || ''),
          application: task.application,
          dedupKey: 'authzen-access-revoked:' + task.id + ':' +
                    String(approval.revokedAt || '')
        });
    } catch (e) {
      // The revocation stands. The code is the mail's failure, logged.
      log.debug("Caught in AccessRequests.mailRequester(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-AUTHZEN-0138') + 'authzen: the ' +
               'requester of ' + task.id + ' could not be mailed: ' +
               ((e && e.message) || e));
    }
    log.debug("Leaving AccessRequests.mailRequester().");
  }

  // -------------------------------------------------------------------------
  // RE-EVALUATION (the profile's section on verifying the approval).
  // -------------------------------------------------------------------------
  /**
   * Verifies a presented `context.approval` against the store: the id
   * names an approved task of this realm, presented by the caller it was
   * issued to, for the same application, not revoked, inside its
   * `approved_until`, and the tuple an exact match. A presented `state`
   * is verified first and must name that same approval and tuple; a bad
   * signature is not an approval even when the row would be. The
   * timestamps beside the id are never believed, and a state with no row
   * is not an approval: revocation stays a write.
   *
   * @param approval - `context.approval` as sent
   * @param body - the evaluation request
   * @param callerName - the trusted caller
   * @param application - the trusted application
   * @returns the verdict, with the reason the profile names when it fails
   */
  verify(approval: Json, body: Json, callerName: string,
         application: string): Verdict {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.verify().");
    const id = isObject(approval) && typeof approval.id === 'string'
      ? approval.id.slice(0, MAX_ID) : '';
    const given: Json = isObject(body) ? body : {};
    const stateToken = isObject(approval) && typeof approval.state === 'string'
      ? approval.state : '';
    const stateClaims = stateToken ? self.verifyApprovalState(stateToken)
                                   : null;
    // A STATE THAT VERIFIES BUT NAMES ANOTHER TUPLE IS NOT A FORGERY
    // (#1204): a PEP echoing a real approval for another resource is
    // out_of_scope, next_action request — what it would be answered had it
    // sent the id alone. The tuple is held below, against the row.
    if (stateToken && (!stateClaims ||
                       String(stateClaims.id || '') !== id)) {
      log.debug("Leaving AccessRequests.verify(). The state does not " +
                "verify.");
      return { ok: false, reason: 'approval_unverifiable' };
    }
    const held = self.recalled('approval', id);
    const task = held ? self.task(String(held.task)) : null;
    if (!task || !task.approval || task.approval.id !== id ||
        task.requester !== callerName) {
      log.debug("Leaving AccessRequests.verify(). Unverifiable.");
      return { ok: false, reason: 'approval_unverifiable' };
    }
    if (stateClaims) {
      const audiences = [].concat(stateClaims.aud || []);
      if (stateClaims.iss !== task.base || audiences.indexOf(task.base) < 0) {
        log.debug("Leaving AccessRequests.verify(). The state is not " +
                  "this realm's.");
        return { ok: false, reason: 'approval_unverifiable' };
      }
    }
    if (task.approval.revokedAt ||
        Number(task.approval.approvedUntil) <= self.nowS()) {
      log.debug("Leaving AccessRequests.verify(). Expired or revoked.");
      return { ok: false, reason: 'approval_expired', task: task };
    }
    const same = task.application === application &&
      AccessRequests.sameTuple(task, given, task.contextMembers || []);
    if (!same) {
      log.debug("Leaving AccessRequests.verify(). Out of scope.");
      return { ok: false, reason: 'out_of_scope', task: task };
    }
    log.debug("Leaving AccessRequests.verify(). Verified.");
    return { ok: true, reason: '', task: task };
  }

  /**
   * The trusted facts a verified approval adds to the XACML request.
   *
   * @param verdict - what `verify()` answered
   * @returns `{ approvalId, approvedUntil, approver }`, or null
   */
  static factsOf(verdict: Verdict | null): Json {
    log.debug("Entering AccessRequests.factsOf().");
    if (!verdict || !verdict.ok || !verdict.task) {
      log.debug("Leaving AccessRequests.factsOf(). None.");
      return null;
    }
    const approval = verdict.task.approval;
    log.debug("Leaving AccessRequests.factsOf().");
    // The entitlement the approved request chose (#1204), a fourth
    // trusted fact; '' (and so absent) when it chose none.
    return { approvalId: approval.id,
             approvedUntil: instant(Number(approval.approvedUntil) * 1000),
             approver: String(approval.approver || ''),
             approvedEntitlement: String(verdict.task.entitlement || '') };
  }

  /**
   * The Decision Context members of a re-evaluation that presented an
   * approval (the profile's re-evaluation denials): on a permit, the
   * approval's id and expiry; on a denial, `reason` and `next_action` —
   * `request` only where a fresh requestable denial goes with it.
   *
   * @param verdict - what `verify()` answered
   * @param decision - the decision
   * @param fresh - the fresh requestable denial's members, or null
   * @returns the members
   */
  static reevaluation(verdict: Verdict, decision: boolean,
                      fresh: Json | null): Json {
    log.debug("Entering AccessRequests.reevaluation().");
    if (decision && verdict.ok) {
      log.debug("Leaving AccessRequests.reevaluation(). Permitted.");
      return { approval: { id: verdict.task.approval.id,
                           approved_until: instant(Number(
                             verdict.task.approval.approvedUntil) * 1000) } };
    }
    const reason = verdict.ok ? 'policy_denied' : verdict.reason;
    const again = !!fresh && (reason === 'approval_expired' ||
                              reason === 'out_of_scope');
    log.debug("Leaving AccessRequests.reevaluation(). " + reason);
    return { reason: reason, next_action: again ? 'request' : 'none' };
  }

  // -------------------------------------------------------------------------
  // THE METADATA
  // -------------------------------------------------------------------------
  /**
   * The members the PDP metadata gains while the profile is on: the
   * endpoint, the capability, and `jwks_uri` (the profile: a PDP issuing a
   * signed `binding_token` publishes one).
   *
   * @param req - the request
   * @returns the members, or null while off
   */
  metadata(req: Req): Json | null {
    const self = this;
    const { log, helpers } = this.deps;
    log.debug("Entering AccessRequests.metadata().");
    if (!self.enabled()) {
      log.debug("Leaving AccessRequests.metadata(). Off.");
      return null;
    }
    log.debug("Leaving AccessRequests.metadata().");
    return { access_request_endpoint: self.baseOf(req) + REQUESTS_PATH,
             jwks_uri: String(helpers.baseUrlOf(req) || '') + '/oauth2/jwks',
             capability: CAPABILITY };
  }

  // -------------------------------------------------------------------------
  // THE JOB (rcbj's rule on periodic work): expiry, and the retention.
  // -------------------------------------------------------------------------
  /**
   * One run in the ambient realm: every pending task past its deadline
   * moved to `expired` (its callback sent), every finished one past its
   * retention removed with its index rows, every denial record past its
   * `keepUntil` removed, and every callback delivery that is due sent
   * again.
   *
   * @param ctx - the scheduler's run context
   * @returns `{ summary }`
   */
  sweep(ctx?: Json): Json {
    const self = this;
    const { log, tasks, index, denials, errorCodes } = this.deps;
    log.debug("Entering AccessRequests.sweep().");
    const now = self.nowS();
    let expired = 0;
    let removed = 0;
    let retried = 0;
    let dropped = 0;
    let failed = 0;
    let held = 0;
    const pendingIds: string[] = [];
    try {
      const rows: Json[] = [];
      tasks.forEach(function (row: Json) {
        rows.push(row);
      });
      for (let i = 0; i < rows.length; i += 1) {
        if (ctx && typeof ctx.stillOwner === 'function' && !ctx.stillOwner()) {
          break;
        }
        const row = rows[i];
        if (!row || !row.id) {
          continue;
        }
        // THE SUBJECT INDEX'S BACKFILL (2026-11-16): a task written before
        // it existed is noted here; a noted one costs a get. The approver
        // and pending indexes are repaired the same way (#1203).
        self.noteSubject(row);
        self.noteApprover(row);
        if (row.status === 'pending') {
          pendingIds.push(String(row.id));
        }
        if (row.status === 'pending' && Number(row.expiresAt) <= now) {
          if (self.finish(row, 'expired', {
                actor: 'the access request service',
                why: 'it reached its expires_at' })) {
            expired += 1;
          }
        } else if (row.status === 'pending') {
          // A STEP THAT CANNOT COMPLETE (#1202): the advice named
          // approvers, and they resolve, certainly, to nobody.
          const walk = self.approverWalk(row);
          if (walk.certain && !walk.names.length &&
              self.finish(row, 'failed', {
                actor: 'the access request service',
                code: 'STS-AUTHZEN-0143',
                why: 'the approvers its advice names resolve to nobody ' +
                     'who may decide it' })) {
            failed += 1;
          }
        } else if (Number(row.keepUntil) <= now &&
                   self.deliveryOutstanding(row) &&
                   now < Number(row.keepUntil) + self.horizonS(row)) {
          // KEPT WHILE ITS CALLBACK IS STILL BEING TRIED (#1202), never
          // past the bound's last attempt.
          held += 1;
          if (self.callbackDue(row, now)) {
            self.notify(row);
            retried += 1;
          }
        } else if (Number(row.keepUntil) <= now) {
          if (self.deliveryOutstanding(row)) {
            // The horizon passed with the delivery still open: the final
            // row is written before the task goes.
            const bound = Number((row.callbackDelivery || {}).bound) ||
              Number((row.callback || {}).attempts) || 1;
            self.giveUp(row, String(row.status), bound,
                        'was not delivered before the task was removed');
          }
          tasks.delete(row.id);
          self.unnoteSubject(row);
          self.unnoteUnder(PENDING_KEY, String(row.id));
          if (row.approval) {
            index.delete('approval:' +
                         stsCrypto.credentialDigest(row.approval.id));
            if (row.approval.approver) {
              self.unnoteUnder(AccessRequests.approverKey(
                String(row.approval.approver)), String(row.id));
            }
          }
          if (row.idempotency) {
            index.delete(row.idempotency.key);
          }
          removed += 1;
        } else if (self.callbackDue(row, now)) {
          self.notify(row);
          retried += 1;
        }
      }
      // THE PENDING LIST, repaired: every task still pending, whether this
      // walk found it or a submission since listed it.
      const listed = self.idsUnder(PENDING_KEY).filter(function (id: string) {
        const one = tasks.get(id);
        return !!one && one.status === 'pending';
      });
      const repaired = rows.filter(function (one: Json) {
        return one && one.status === 'pending' &&
               pendingIds.indexOf(String(one.id)) >= 0;
      }).map(function (one: Json) {
        return String(one.id);
      });
      listed.forEach(function (id: string) {
        if (repaired.indexOf(id) < 0) {
          repaired.push(id);
        }
      });
      if (repaired.length) {
        index.set(PENDING_KEY, { tasks: repaired,
                                 until: now + RETENTION_S * 30 });
      } else if (index.get(PENDING_KEY)) {
        index.delete(PENDING_KEY);
      }
      const stale: string[] = [];
      index.forEach(function (row: Json, key: string) {
        if (!row || Number(row.until) <= now) {
          stale.push(key);
        }
      });
      stale.forEach(function (key: string) {
        index.delete(key);
      });
      const gone: string[] = [];
      denials.forEach(function (row: Json, key: string) {
        if (!row || Number(row.keepUntil) <= now) {
          gone.push(key);
        }
      });
      gone.forEach(function (key: string) {
        denials.delete(key);
        dropped += 1;
      });
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHZEN-0092') + 'authzen: the access ' +
                'request sweep failed: ' + ((e && e.message) || e));
      throw e;
    }
    const parts: string[] = [];
    if (expired || removed) {
      parts.push(expired + ' access request(s) expired, ' + removed +
                 ' removed.');
    }
    if (failed) {
      parts.push(failed + ' access request(s) failed.');
    }
    if (retried) {
      parts.push(retried + ' callback(s) retried.');
    }
    if (held) {
      parts.push(held + ' finished access request(s) kept for a callback ' +
                 'still being tried.');
    }
    if (dropped) {
      parts.push(dropped + ' denial record(s) removed.');
    }
    const summary = parts.join(' ');
    log.debug("Leaving AccessRequests.sweep(). " + (summary || 'Nothing.'));
    return { summary: summary };
  }

  /**
   * Registers the job with the scheduler, once per process.
   *
   * @returns true when registered, false when it already was
   */
  registerJobs(): boolean {
    const self = this;
    const { log, config } = this.deps;
    log.debug("Entering AccessRequests.registerJobs().");
    const s = self.deps.loadScheduler();
    if (s.job(JOB)) {
      log.debug("Leaving AccessRequests.registerJobs(). Already there.");
      return false;
    }
    s.register({
      id: JOB,
      title: 'AuthZEN access request expiry',
      describe: 'Moves every pending AuthZEN access request (#1180) past ' +
                'its expires_at to expired — writing its audit row and ' +
                'sending its callback — removes a finished one a day ' +
                'after it finished, or once its approval ran out if that ' +
                'is later, removes a requestable denial a day after its ' +
                'window, and retries a callback delivery that failed ' +
                'with a network error or an HTTP 5xx, up to the attempt ' +
                'bound, each wait twice the last (#1202). A finished one ' +
                'is kept while its callback is still being tried, and a ' +
                'pending one whose approvers resolve to nobody is moved to ' +
                'failed. A read applies the deadline itself, so this is ' +
                'the record and the clean-up, never what decides.',
      owner: 'authzen/authzen_access_request.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return JOB_EVERY_MS;
      },
      off: function (): string {
        return config.value('authzen.accessRequests') === false
          ? 'authzen.accessRequests is off in this realm.' : '';
      },
      manual: true,
      timeoutS: 300,
      run: function (ctx: Json): Promise<Json> {
        return Promise.resolve().then(function () {
          return self.sweep(ctx);
        });
      }
    });
    log.debug("Leaving AccessRequests.registerJobs().");
    return true;
  }

  /**
   * Forgets every task of the ambient realm. For a test.
   */
  resetForTests(): void {
    const { log, tasks, index, denials } = this.deps;
    log.debug("Entering AccessRequests.resetForTests().");
    const keys: string[] = [];
    tasks.forEach(function (value: Json, key: string) {
      keys.push(key);
    });
    keys.forEach(function (key: string) {
      tasks.delete(key);
    });
    const indexKeys: string[] = [];
    index.forEach(function (value: Json, key: string) {
      indexKeys.push(key);
    });
    indexKeys.forEach(function (key: string) {
      index.delete(key);
    });
    const denialKeys: string[] = [];
    denials.forEach(function (value: Json, key: string) {
      denialKeys.push(key);
    });
    denialKeys.forEach(function (key: string) {
      denials.delete(key);
    });
    flights.clear();
    log.debug("Leaving AccessRequests.resetForTests().");
  }

  // A finished task whose callback event includes this status, and whose
  // delivery is not already done, in flight, or waiting for its backoff.
  // A task that finished before the delivery record existed is due too:
  // the process can stop between finish()'s save and notify().
  private callbackDue(row: Json, now: number): boolean {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.callbackDue().");
    const callback = row && row.callback;
    let due = false;
    if (row && row.status !== 'pending' && callback &&
        Array.isArray(callback.events) &&
        callback.events.indexOf(row.status) >= 0) {
      const delivery = row.callbackDelivery;
      const done = delivery && (delivery.state === 'delivered' ||
                                delivery.state === 'failed');
      const inflight = delivery && Number(delivery.inflightUntil) > now;
      const waiting = delivery && delivery.attempts &&
                      delivery.attempts.length > 0 &&
                      Number(delivery.nextAt) > now;
      due = !done && !inflight && !waiting &&
            !flights.has(this.flightKey(row));
    }
    log.debug("Leaving AccessRequests.callbackDue(). " + due);
    return due;
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2); the job is
// registered when it is installed, as `post_login_activities.ts`'s is.
const slot = new InstanceSlot<AccessRequests>(
  'authzen/authzen_access_request',
  () => new AccessRequests(AccessRequests.defaultDeps()),
  function (instance: AccessRequests): void {
    instance.registerJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The AuthZEN Access Request and Approval Profile (#1180).
 * @namespace
 */
export = {
  AccessRequests: AccessRequests,
  installInstance: (instance: AccessRequests): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ADVICE_ID: ADVICE_ID,
  ADVICE_PREFIX: ADVICE_PREFIX,
  CAPABILITY: CAPABILITY,
  REQUESTS_PATH: REQUESTS_PATH,
  SCHEMA_PATH: SCHEMA_PATH,
  submissionSchema: AccessRequests.submissionSchema,
  GATE_RESOURCE: GATE_RESOURCE,
  GATE_ACTION: GATE_ACTION,
  STATES: STATES,
  EVENTS: EVENTS,
  JOB: JOB,
  MAX_CALLBACKS: MAX_CALLBACKS,
  canonical: AccessRequests.canonical,
  bound: AccessRequests.bound,
  relevant: AccessRequests.relevant,
  bindingHash: AccessRequests.bindingHash,
  termsOf: AccessRequests.termsOf,
  factsOf: AccessRequests.factsOf,
  reevaluation: AccessRequests.reevaluation,
  enabled: slot.forward('enabled'),
  baseOf: slot.forward('baseOf'),
  requestableDenial: slot.forward('requestableDenial'),
  submit: slot.forward('submit'),
  status: slot.forward('status'),
  cancel: slot.forward('cancel'),
  problem: slot.forward('problem'),
  task: slot.forward('task'),
  handleOf: slot.forward('handleOf'),
  formOn: slot.forward('formOn'),
  formView: slot.forward('formView'),
  submitByForm: slot.forward('submitByForm'),
  FORM_PATH: FORM_PATH,
  actorOn: slot.forward('actorOn'),
  bulkOn: slot.forward('bulkOn'),
  bundleOf: slot.forward('bundleOf'),
  actorOf: slot.forward('actorOf'),
  CATALOGS_PATH: CATALOGS_PATH,
  catalogsOn: slot.forward('catalogsOn'),
  catalogsDocument: slot.forward('catalogsDocument'),
  catalogItems: slot.forward('catalogItems'),
  verify: slot.forward('verify'),
  decide: slot.forward('decide'),
  cancelByAdministrator: slot.forward('cancelByAdministrator'),
  viewOf: slot.forward('viewOf'),
  list: slot.forward('list'),
  awaiting: slot.forward('awaiting'),
  grantedBy: slot.forward('grantedBy'),
  eligible: slot.forward('eligible'),
  approversOf: slot.forward('approversOf'),
  metadata: slot.forward('metadata'),
  notify: slot.forward('notify'),
  sweep: slot.forward('sweep'),
  forgetSubject: slot.forward('forgetSubject'),
  registerJobs: slot.forward('registerJobs'),
  resetForTests: slot.forward('resetForTests')
};
