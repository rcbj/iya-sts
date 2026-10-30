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
//      approvers are mailed through the mail channel.
//   4. **CALLBACK IS IN THE FIRST BUILD**, to a URL registered for the
//      requester only (`appAuthzenCallbackUri` on an application,
//      `stsAuthzenCallbackUri` on a person's or service account's entry,
//      written by an administrator) and never one taken from the request
//      alone, under the outbound policy every other delivery takes
//      (`federation_http.deliverJson()`): https verified, no redirect, the
//      internal-address refusal, the kill switch. `federation/CLAUDE.md`
//      carries its row among the URLs this service dials.
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
// id are never believed.
//
// THE BINDING. A requestable denial carries a `binding_token`: a JWS this
// realm signs (`oauth2.ts`'s `signPublishedDocument()`, the one signer of a
// published document) over the denied tuple — subject, resource and action
// whole (less `subject.properties.act`, the profile's exclusion), the
// context members the advice named, the caller, the application and the
// advice's approval terms — audienced to this realm's access request
// endpoint and expiring with the denial. So a submission needs no state from
// the denial: it is verified offline, which is the by-value form the profile
// requires of an independent service and allows a same-service one, and
// nothing is written per denial. The approval is the other way round: the
// task is a store row and the PDP looks `approval.id` up in it (the
// profile's by-reference form), so revoking one is a write, not a wait.
//
// THE TASK is a row of the per-realm store `authzen.accessRequests`:
// `pending`, then exactly once one of `approved`, `denied`, `expired`,
// `cancelled`, `failed` — every transition one audit row. Expiry is the
// scheduler job `authzen.access-requests` (rcbj's rule on periodic work):
// a pending task past its `expires_at` is moved to `expired` (and its
// callback sent), and a finished one is removed a day after it finished, or
// after its approval ran out if that is later. A read checks the deadline
// itself, so an expired task never answers pending whenever the job last
// ran.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50): `AccessRequests` takes what it uses through
// its constructor; the stores are declared at module scope, because a store
// becomes per realm at its declaration (`tests/realm_isolation.js`). A
// LIBRARY: it registers no route — `authzen.ts` carries the three — and its
// job is registered when the composition root installs the instance.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import realms = require('../common/realms');
import stsCrypto = require('../common/crypto');
// The lexical spaces of an advice's values (`termsOf()`). A leaf the
// mapping already loads.
import datatypes = require('../xacml/xacml_datatypes');

const { log } = helpers;

type Json = any;
type Req = import('express').Request;
type Res = import('express').Response;

// THE ADVICE that marks a denial requestable, and its assignments' prefix.
const ADVICE_ID = 'urn:sts:xacml:advice:access-request';
const ADVICE_PREFIX = ADVICE_ID + ':';

// The profile's problem types (its section on error responses).
const PROBLEM = 'urn:openid:authzen:access-request:error:';

// The capability the metadata names while this is on.
const CAPABILITY = 'urn:openid:authzen:capability:access-request';

// The request endpoint, under the realm's prefix.
const REQUESTS_PATH = '/access/v1/access-requests';

// The access-control question (`common/access_gate.ts`).
const GATE_RESOURCE = 'authzen-access-request';
const GATE_ACTION = 'approve-access-request';

// The lifecycle.
const STATES = Object.freeze(['pending', 'approved', 'denied', 'expired',
                              'cancelled', 'failed']);

// The CALLBACK companion's event names.
const EVENTS = Object.freeze(['approved', 'denied', 'expired', 'cancelled',
                              'failed']);

// The members a submission may carry at its top level. `items` is BULK's
// and refused; anything else is a mistake rather than an extension point.
const SUBMISSION_MEMBERS = Object.freeze(['subject', 'resource', 'action',
  'context', 'denial', 'requested_access', 'client', 'callback']);

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

// ---------------------------------------------------------------------------
// THE STORES, per realm at their declaration and persisted, so a task
// survives a restart in product mode and every request worker reads the
// same one (the minted-row rule of persistence/CLAUDE.md). A row is JSON
// and an in-place edit is re-set (`save()`). No bearer value is a key: the
// index holds an approval id, an idempotency key and a binding token's jti
// as their SHA-256 (`stsCrypto.credentialDigest()`).
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

// The parts of a `realms.map()` store this module uses.
interface Store {
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
   *   helpers, the two stores, a clock, and lazy loaders
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
      loadScheduler: lazy('loadScheduler', '../cluster/scheduler')
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
   * actor normalised to `client.actor` compares the same).
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
   * `binding_token` this realm signed over the denied tuple. Null when the
   * profile is off, the answer carries no access-request advice, or the
   * token could not be signed — in each case the denial stays an ordinary
   * `false` (the profile: no `access_request` without verifiable binding
   * material).
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
    const claims: Json = {
      aud: base + REQUESTS_PATH,
      sub: String((given.subject || {}).id || ''),
      jti: helpers.randomId(18),
      typ: 'authzen-access-request-denial',
      denial_expires_at: expiresAt,
      evaluation_id: evaluationId,
      subject: AccessRequests.bound('subject', given.subject),
      resource: AccessRequests.bound('resource', given.resource),
      action: AccessRequests.bound('action', given.action),
      context: AccessRequests.relevant(given.context, terms.contextMembers),
      binding_context_members: terms.contextMembers.slice(0),
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
    const accessRequest: Json = { expires_at: expiresAt,
                                  endpoint: base + REQUESTS_PATH,
                                  binding_token: token };
    if (terms.template) {
      accessRequest.template = terms.template;
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
    const titles: Json = {
      not_requestable: 'Access is not requestable',
      expired_denial: 'The requestable denial has expired',
      invalid_denial_binding: 'The request cannot be bound to the denial',
      duplicate_request: 'The Idempotency-Key was used for another request',
      unknown_task: 'There is no such task',
      task_expired: 'The task has expired',
      invalid_task_state: 'The task is not in a state that allows this'
    };
    res.status(status).type('application/problem+json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify({
         type: type ? PROBLEM + type : 'about:blank',
         title: type ? titles[type] : (status >= 500 ? 'Server error'
                                                      : 'Bad request'),
         status: status, detail: detail }, null, 2));
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
    log.debug("Leaving AccessRequests.save().");
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
   * @returns the handle
   */
  handleOf(task: Json): Json {
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
    log.debug("Leaving AccessRequests.handleOf().");
    return out;
  }

  /**
   * The response body for a task: the handle, and the `reevaluate` result
   * once it is approved (the profile: REQUIRED then).
   *
   * @param task - the row
   * @returns `{ task, result? }`
   */
  bodyOf(task: Json): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.bodyOf().");
    const out: Json = { task: self.handleOf(task) };
    if (task.status === 'approved' && task.approval) {
      out.result = { mode: 'reevaluate',
                     approval: { id: task.approval.id,
                                 approved_at: instant(
                                   task.approval.approvedAt * 1000),
                                 approved_until: instant(
                                   task.approval.approvedUntil * 1000) } };
    }
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
    self.save(task);
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

  // -------------------------------------------------------------------------
  // THE SUBMISSION (the profile's section on it).
  // -------------------------------------------------------------------------
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
    const { log, helpers } = this.deps;
    log.debug("Entering AccessRequests.submit().");
    if (!isObject(body)) {
      self.problem(res, 400, '', 'STS-AUTHZEN-0071', 'An access request ' +
                   'is a JSON object with subject, resource, action and ' +
                   'denial.');
      log.debug("Leaving AccessRequests.submit(). Not an object.");
      return;
    }
    const given: Json = body;
    if (given.items !== undefined) {
      self.problem(res, 400, '', 'STS-AUTHZEN-0071', 'This service does ' +
                   'not implement the bulk companion profile; submit one ' +
                   'item at a time.');
      log.debug("Leaving AccessRequests.submit(). Bulk.");
      return;
    }
    const stray = Object.keys(given).filter(function (key: string) {
      return SUBMISSION_MEMBERS.indexOf(key) < 0;
    })[0];
    if (stray) {
      self.problem(res, 400, '', 'STS-AUTHZEN-0071', 'An access request ' +
                   'has no member "' + stray.slice(0, 64) + '"; it takes ' +
                   SUBMISSION_MEMBERS.join(', ') + '.');
      log.debug("Leaving AccessRequests.submit(). An unknown member.");
      return;
    }
    const missing = ['subject', 'resource', 'action'].filter(
      function (key: string) {
        return !isObject(given[key]);
      })[0];
    if (missing) {
      self.problem(res, 400, '', 'STS-AUTHZEN-0071', missing + ' is ' +
                   'required, the AuthZEN ' + missing + ' of the denied ' +
                   'evaluation, as a JSON object.');
      log.debug("Leaving AccessRequests.submit(). No " + missing + ".");
      return;
    }
    const denial = given.denial;
    if (!isObject(denial) || (!denial.binding_token &&
                              !denial.evaluation_id)) {
      self.problem(res, 400, 'not_requestable', 'STS-AUTHZEN-0072',
                   'The request carries no denial with the binding_token ' +
                   'of a requestable denial, so it is not based on one.');
      log.debug("Leaving AccessRequests.submit(). No denial.");
      return;
    }
    if (!denial.binding_token) {
      // THE BY-REFERENCE FORM IS NOT KEPT HERE: this service records
      // nothing per denial (the header), so an evaluation_id alone names
      // nothing it can resolve.
      self.problem(res, 400, 'invalid_denial_binding', 'STS-AUTHZEN-0073',
                   'denial.binding_token is required here: this PDP binds ' +
                   'a denial by value and keeps no record of evaluations ' +
                   'to resolve an evaluation_id against.');
      log.debug("Leaving AccessRequests.submit(). No token.");
      return;
    }
    const base = self.baseOf(req);
    const bound = self.verifyBinding(String(denial.binding_token), base);
    if (!bound) {
      self.problem(res, 400, 'invalid_denial_binding', 'STS-AUTHZEN-0073',
                   'denial.binding_token is not one this realm issued for ' +
                   'this endpoint.');
      log.debug("Leaving AccessRequests.submit(). Did not verify.");
      return;
    }
    const now = self.nowS();
    const echoed = Date.parse(String(denial.expires_at || ''));
    if (String(denial.expires_at || '') !== String(bound.denial_expires_at)) {
      self.problem(res, 400, 'invalid_denial_binding', 'STS-AUTHZEN-0074',
                   'denial.expires_at is not the value the denial carried; ' +
                   'echo it unchanged.');
      log.debug("Leaving AccessRequests.submit(). expires_at differs.");
      return;
    }
    const deadline = Math.min(Number(bound.exp) || 0,
                              Math.floor(echoed / 1000) || 0);
    if (!(deadline > 0) || now > deadline + SKEW_S) {
      self.problem(res, 410, 'expired_denial', 'STS-AUTHZEN-0075',
                   'The requestable denial expired at ' +
                   String(denial.expires_at) + '; evaluate again for a ' +
                   'fresh one.');
      log.debug("Leaving AccessRequests.submit(). Expired.");
      return;
    }
    const mismatch = self.bindingMismatch(bound, given, caller.name);
    if (mismatch) {
      self.problem(res, 400, 'invalid_denial_binding', 'STS-AUTHZEN-0074',
                   'The request does not match the denial it names: ' +
                   mismatch + '.');
      log.debug("Leaving AccessRequests.submit(). " + mismatch);
      return;
    }
    // THE APPLICATION IS STILL THE CALLER'S: a scope taken away between
    // the denial and the submission ends the request here.
    const scoped = scope(caller, String(bound.application || ''));
    if (!scoped.application) {
      self.problem(res, 403, '', 'STS-AUTHZEN-0077', 'This caller may no ' +
                   'longer ask about the application "' +
                   String(bound.application).slice(0, 120) + '".');
      log.debug("Leaving AccessRequests.submit(). Out of scope.");
      return;
    }
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
      if (earlier && again.fingerprint === fingerprint &&
          earlier.requester === caller.name) {
        res.status(earlier.status === 'pending' ? 202 : 201)
           .type('application/json').set('Cache-Control', 'no-store')
           .set('Location', self.handleOf(earlier).status_endpoint)
           .send(JSON.stringify(self.bodyOf(earlier), null, 2));
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
      self.problem(res, 400, '', 'STS-AUTHZEN-0079', callback.problem);
      log.debug("Leaving AccessRequests.submit(). A callback refused.");
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
    const task: Json = {
      id: 'arq_' + helpers.randomId(24),
      status: 'pending',
      realm: String(self.deps.realms.currentId() || ''),
      base: base,
      requester: caller.name,
      requesterKind: caller.kind,
      client: isObject(given.client)
        ? { id: String(given.client.id || '').slice(0, MAX_ID),
            name: String(given.client.name || '').slice(0, MAX_TEXT) }
        : null,
      application: scoped.application,
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
      callback: callback.value,
      createdAt: now,
      expiresAt: now + self.seconds('authzen.accessRequestLifetimeS'),
      keepUntil: now + self.seconds('authzen.accessRequestLifetimeS') +
                 RETENTION_S,
      approval: null,
      decidedBy: '',
      idempotency: null
    };
    const indexRow = { fingerprint: fingerprint };
    if (key) {
      const indexKey = 'idem:' + stsCrypto.credentialDigest(caller.name +
                                                            '\n' + key);
      task.idempotency = { key: indexKey, row: Object.assign(
        { task: task.id }, indexRow) };
    }
    self.save(task);
    if (key) {
      self.remember('idem', caller.name + '\n' + key, task.id, indexRow,
                    task.keepUntil);
    }
    self.remember('jti', String(bound.jti || ''), task.id, indexRow,
                  Number(bound.exp) + SKEW_S);
    self.deps.audit.audit({
      action: 'authzen.access-request.submitted',
      actor: caller.name,
      protocol: 'AuthZEN',
      detail: 'The access request ' + task.id + ' was submitted for a ' +
        String(task.subject.type || '') + ' to ' +
        String(task.action.name || '') + ' a ' +
        String(task.resource.type || '') + ', application "' +
        task.application + '"' + (task.emergency ? ', as an emergency' : '') +
        (key ? ', with an Idempotency-Key' : '') + '.'
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
    res.status(task.status === 'pending' ? 202 : 201)
       .type('application/json').set('Cache-Control', 'no-store')
       .set('Location', self.handleOf(task).status_endpoint)
       .send(JSON.stringify(self.bodyOf(task), null, 2));
    log.debug("Leaving AccessRequests.submit(). " + task.id + " " +
              task.status);
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
    log.debug("Leaving AccessRequests.bindingMismatch(). " + (out || 'ok'));
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
    const asked: Json = given.requested_access === undefined ? {}
      : given.requested_access;
    if (!isObject(asked)) {
      log.debug("Leaving AccessRequests.requestedAccess(). Not an object.");
      return { problem: 'requested_access must be a JSON object.',
               code: 'STS-AUTHZEN-0096' };
    }
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
    log.debug("Leaving AccessRequests.requestedAccess().");
    return { until: until, emergency: emergency,
             justification: justification };
  }

  // -------------------------------------------------------------------------
  // THE CALLBACK (the CALLBACK companion), rcbj's decision 4.
  // -------------------------------------------------------------------------
  /**
   * The callback URLs registered for a caller: `appAuthzenCallbackUri` on
   * an application, `stsAuthzenCallbackUri` on a person's or service
   * account's entry — an administrator's, never the caller's.
   *
   * @param caller - the caller, `{ kind, name, identifier }`
   * @returns the URLs
   */
  registeredCallbacks(caller: Json): string[] {
    const { log } = this.deps;
    log.debug("Entering AccessRequests.registeredCallbacks().");
    let out: string[] = [];
    try {
      const looked = this.deps.loadAdmin().callerOf(
        caller.kind === 'application'
          ? String(caller.identifier || caller.clientId || caller.name)
          : String(caller.name));
      out = looked && Array.isArray(looked.callbacks) ? looked.callbacks
                                                       : [];
    } catch (e) {
      // A registry that cannot be read registers nothing: the request is
      // then refused a callback, the safe direction.
      log.debug("Caught in AccessRequests.registeredCallbacks(): " +
                ((e && e.message) || e));
      out = [];
    }
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
    const asked: Json = given;
    if (!isObject(asked) || typeof asked.endpoint !== 'string') {
      log.debug("Leaving AccessRequests.callbackOf(). Not an object.");
      return { problem: 'callback must be a JSON object with an endpoint.' };
    }
    const endpoint = String(asked.endpoint);
    if (!/^https:\/\//i.test(endpoint) ||
        self.registeredCallbacks(caller).indexOf(endpoint) < 0) {
      log.debug("Leaving AccessRequests.callbackOf(). Not registered.");
      return { problem: 'callback.endpoint must be an https URL an ' +
                        'administrator registered for this caller; this ' +
                        'service never dials one taken from a request ' +
                        'alone.' };
    }
    const events = asked.events === undefined ? EVENTS.slice(0)
      : (Array.isArray(asked.events) ? asked.events.map(String) : null);
    if (!events) {
      log.debug("Leaving AccessRequests.callbackOf(). Bad events.");
      return { problem: 'callback.events must be an array of event names.' };
    }
    const state = asked.state === undefined ? undefined
      : String(asked.state).slice(0, MAX_TEXT);
    log.debug("Leaving AccessRequests.callbackOf().");
    return { value: { endpoint: endpoint, state: state,
                      events: events.filter(function (one: string) {
                        return EVENTS.indexOf(one) >= 0;
                      }) } };
  }

  /**
   * Sends a finished task's callback, where it asked for one and for this
   * event. One attempt, never awaited: a callback is a notification and the
   * task status endpoint stays authoritative (the companion's words), so a
   * failure is recorded and nothing is retried. The notification carries
   * no `result`, so a PEP fetches the task before it enforces; it is
   * authenticated by a short JWT this realm signs, audienced to the
   * endpoint, as the Bearer — verifiable with the realm's JWKS.
   *
   * @param task - the finished row
   * @returns a promise of whether it was sent, for a test
   */
  notify(task: Json): Promise<boolean> {
    const self = this;
    const { log, audit, errorCodes } = this.deps;
    log.debug("Entering AccessRequests.notify(). " + task.id);
    const callback = task.callback;
    if (!callback || callback.events.indexOf(task.status) < 0) {
      log.debug("Leaving AccessRequests.notify(). Not asked for.");
      return Promise.resolve(false);
    }
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
      log.debug("Caught in AccessRequests.notify(): " +
                ((e && e.message) || e));
      bearer = '';
    }
    const failed = function (why: string): boolean {
      log.debug("Entering failed().");
      log.warn(errorCodes.tag('STS-AUTHZEN-0091') + 'authzen: the ' +
               'callback for the access request ' + task.id + ' was not ' +
               'delivered: ' + why);
      audit.audit({ action: 'authzen.access-request.callback',
                    actor: 'the access request service', protocol: 'AuthZEN',
                    errorCode: 'STS-AUTHZEN-0091',
                    detail: 'The ' + task.status + ' callback for ' +
                            task.id + ' was not delivered: ' +
                            String(why).slice(0, 300) + '.' });
      log.debug("Leaving failed().");
      return false;
    };
    if (!bearer) {
      log.debug("Leaving AccessRequests.notify(). Not signed.");
      return Promise.resolve(failed('the notification could not be signed'));
    }
    let sent: Promise<Json>;
    try {
      sent = self.deps.loadFedHttp().deliverJson(
        { id: task.id, authzenCallbackEndpoint: callback.endpoint },
        'authzenCallbackEndpoint', payload,
        { Authorization: 'Bearer ' + bearer }, {});
    } catch (e) {
      log.debug("Caught in AccessRequests.notify(): " +
                ((e && e.message) || e));
      log.debug("Leaving AccessRequests.notify(). Threw.");
      return Promise.resolve(failed(String((e && e.message) || e)));
    }
    log.debug("Leaving AccessRequests.notify(). Sending.");
    return Promise.resolve(sent).then(function (result: Json): boolean {
      if (!result || !result.ok) {
        return failed(String((result && (result.why || result.status)) ||
                             'no answer'));
      }
      audit.audit({ action: 'authzen.access-request.callback',
                    actor: 'the access request service', protocol: 'AuthZEN',
                    detail: 'The ' + task.status + ' callback for ' +
                            task.id + ' was delivered (' + result.status +
                            ').' });
      return true;
    }, function (e: Json): boolean {
      log.debug("Caught in AccessRequests.notify(): " +
                ((e && e.message) || e));
      return failed(String((e && e.message) || e));
    });
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
       .send(JSON.stringify(self.bodyOf(task), null, 2));
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
       .send(JSON.stringify({ task: self.handleOf(task) }, null, 2));
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
   * @returns the gate's answer
   */
  mayDecide(task: Json, approver: Approver): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AccessRequests.mayDecide().");
    const gate = self.deps.loadGate();
    const identity = self.approverIdentity(approver.username);
    // A hot path inside one decision: no Entering/Leaving pair.
    const lower = function (value: unknown): string {
      return String(value == null ? '' : value).toLowerCase();
    };
    const answer = gate.check({
      resource: gate.RESOURCE.AUTHZEN_ACCESS_REQUEST || GATE_RESOURCE,
      action: gate.ACTION.APPROVE_ACCESS_REQUEST || GATE_ACTION,
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

  // Marks a task approved: the approval, its lifetime and its index row.
  private approve(task: Json, approver: Approver, why: string): void {
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
    const approval = { id: 'apr_' + helpers.randomId(24), approvedAt: now,
                       approvedUntil: Math.min.apply(null, limits),
                       approver: approver.username || approver.door,
                       door: approver.door, revokedAt: 0 };
    task.approval = approval;
    task.decidedBy = approval.approver;
    self.finish(task, 'approved', { actor: approval.approver, why: why });
    self.remember('approval', approval.id, task.id, {},
                  Number(task.keepUntil));
    log.debug("Leaving AccessRequests.approve().");
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
    const answer = self.mayDecide(task, approver);
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
                     GATE_ACTION + ' on ' + GATE_RESOURCE + '). ' +
                     String(answer.why || ''));
    }
    if (decision === 'approve') {
      self.approve(task, approver, 'approved by ' + approver.username +
                   ' via the ' + approver.door);
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
    return {
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
                   owners: !!(task.terms || {}).owners }
    };
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
    const out = self.list(Number.MAX_SAFE_INTEGER).filter(function (row) {
      return row.status === 'pending' && self.eligible(username, row) &&
        self.mayDecide(row, { username: username, door: 'portal' }).allowed;
    }).slice(0, 100).map(function (row: Json) {
      return self.viewOf(row);
    });
    log.debug("Leaving AccessRequests.awaiting(). " + out.length);
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
    const terms: Json = task.terms || {};
    const out: string[] = [];
    let hooks: Json = null;
    try {
      hooks = this.deps.loadAdmin().directoryHooks();
    } catch (e) {
      log.debug("Caught in AccessRequests.approversOf(): " +
                ((e && e.message) || e));
      hooks = null;
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
      log.debug("Caught in AccessRequests.approversOf(): " +
                ((e && e.message) || e));
    }
    const subject = String((task.subject || {}).id || '').toLowerCase();
    log.debug("Leaving AccessRequests.approversOf(). " + out.length);
    return out.filter(function (one: string) {
      return one.toLowerCase() !== subject;
    });
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

  // -------------------------------------------------------------------------
  // RE-EVALUATION (the profile's section on verifying the approval).
  // -------------------------------------------------------------------------
  /**
   * Verifies a presented `context.approval` against the store: the id
   * names an approved task of this realm, presented by the caller it was
   * issued to, for the same application, not revoked, inside its
   * `approved_until`, and the tuple an exact match. Only `id` is read off
   * the request; the timestamps beside it are never believed.
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
    const held = self.recalled('approval', id);
    const task = held ? self.task(String(held.task)) : null;
    if (!task || !task.approval || task.approval.id !== id ||
        task.requester !== callerName) {
      log.debug("Leaving AccessRequests.verify(). Unverifiable.");
      return { ok: false, reason: 'approval_unverifiable' };
    }
    if (task.approval.revokedAt ||
        Number(task.approval.approvedUntil) <= self.nowS()) {
      log.debug("Leaving AccessRequests.verify(). Expired or revoked.");
      return { ok: false, reason: 'approval_expired', task: task };
    }
    const given: Json = isObject(body) ? body : {};
    const same = task.application === application &&
      ['subject', 'resource', 'action'].every(function (name: string) {
        return AccessRequests.canonical(AccessRequests.bound(name,
          given[name])) === AccessRequests.canonical(task[name]);
      }) &&
      AccessRequests.canonical(AccessRequests.relevant(given.context,
        task.contextMembers || [])) ===
      AccessRequests.canonical(task.context || {});
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
    return { approvalId: approval.id,
             approvedUntil: instant(Number(approval.approvedUntil) * 1000),
             approver: String(approval.approver || '') };
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
   * retention removed with its index rows.
   *
   * @param ctx - the scheduler's run context
   * @returns `{ summary }`
   */
  sweep(ctx?: Json): Json {
    const self = this;
    const { log, tasks, index, errorCodes } = this.deps;
    log.debug("Entering AccessRequests.sweep().");
    const now = self.nowS();
    let expired = 0;
    let removed = 0;
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
        if (row.status === 'pending' && Number(row.expiresAt) <= now) {
          if (self.finish(row, 'expired', {
                actor: 'the access request service',
                why: 'it reached its expires_at' })) {
            expired += 1;
          }
        } else if (row.status !== 'pending' &&
                   Number(row.keepUntil) <= now) {
          tasks.delete(row.id);
          if (row.approval) {
            index.delete('approval:' +
                         stsCrypto.credentialDigest(row.approval.id));
          }
          if (row.idempotency) {
            index.delete(row.idempotency.key);
          }
          removed += 1;
        }
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
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHZEN-0092') + 'authzen: the access ' +
                'request sweep failed: ' + ((e && e.message) || e));
      throw e;
    }
    const summary = expired || removed
      ? expired + ' access request(s) expired, ' + removed + ' removed.'
      : '';
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
                'sending its callback — and removes a finished one a day ' +
                'after it finished, or once its approval ran out if that ' +
                'is later. A read applies the deadline itself, so this is ' +
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
    const { log, tasks, index } = this.deps;
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
    log.debug("Leaving AccessRequests.resetForTests().");
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
  GATE_RESOURCE: GATE_RESOURCE,
  GATE_ACTION: GATE_ACTION,
  STATES: STATES,
  EVENTS: EVENTS,
  JOB: JOB,
  MAX_CALLBACKS: MAX_CALLBACKS,
  canonical: AccessRequests.canonical,
  bound: AccessRequests.bound,
  relevant: AccessRequests.relevant,
  termsOf: AccessRequests.termsOf,
  factsOf: AccessRequests.factsOf,
  reevaluation: AccessRequests.reevaluation,
  enabled: slot.forward('enabled'),
  requestableDenial: slot.forward('requestableDenial'),
  submit: slot.forward('submit'),
  status: slot.forward('status'),
  cancel: slot.forward('cancel'),
  problem: slot.forward('problem'),
  task: slot.forward('task'),
  verify: slot.forward('verify'),
  decide: slot.forward('decide'),
  cancelByAdministrator: slot.forward('cancelByAdministrator'),
  viewOf: slot.forward('viewOf'),
  list: slot.forward('list'),
  awaiting: slot.forward('awaiting'),
  eligible: slot.forward('eligible'),
  approversOf: slot.forward('approversOf'),
  metadata: slot.forward('metadata'),
  notify: slot.forward('notify'),
  sweep: slot.forward('sweep'),
  registerJobs: slot.forward('registerJobs'),
  resetForTests: slot.forward('resetForTests')
};
