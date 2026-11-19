// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: pep_audit.ts
//
// ---------------------------------------------------------------------------
// A REMOTE PEP'S DECISIONS, RECORDED IN THIS SERVICE'S AUDIT LOG (#1827).
//
// A remote XACML PEP (`xacml-pep/`) decides in its own process against the
// policy it pulled, so until #1827 the only record of what it decided was a
// line on its own standard output: this service learnt the COUNTS from the
// heartbeat and nothing else, and a container that was removed took its
// decisions with it. Now the PEP queues a record per decision it made and
// pushes them, in order and at least once, to `POST /admin-api/pep-audit`,
// and this file turns each into one audit row.
//
// **THE DOOR IS THE MANAGEMENT API, AND THAT IS rcbj's RULE, NOT A
// CONVENIENCE** (2026-11-16): "Every log event pushed to iya-sts must be
// through an authenticated request on the mgmt API. Tie access to the built
// in group of remote PEPs." So the gate there decides who may push, by the
// mechanisms it already has: the token carries `xacml:pep-audit` and nothing
// else on `/admin-api` takes that scope (`admin_api.ts`'s
// `isPepAuditFeed()`, the device-compliance feed's shape); the scope is
// authorized by the built-in role REMOTE_PEPS, which is membership of the
// group `roles.remotePepGroup` names, asked at issuance and on every call;
// and the token is the PEP's own RFC 7523 self-assertion
// (`person_assertions.js`) presented through the seeded public client
// `sts-remote-pep`, bound to the PEP's DPoP key since the PEP's token
// credential (#1827's follow-up; to its certificate before, which phase 4
// retired). Nothing here asks any of
// that again. What this file asks is the one question the gate cannot: is
// the caller a PEP REGISTERED in this realm's `ou=peps`, the register the
// console's PEP list is drawn from — the heartbeat's rule, for its reason.
//
// ---------------------------------------------------------------------------
// WHAT A ROW CARRIES, AND WHAT IT DOES NOT.
//
// The PEP sends what its own log line carries and this service's matching
// row carries (`xacml.decision`, `authzen.decision`): the decision, allowed
// or refused, the subject and resource and action a `/protected` request
// named, the applicable policies, the obligations — for a reverse-proxy
// request (#1760) the route, the method and path, the person its session
// names and the status it answered — and for an AuthZEN
// evaluation the caller, the application, the two types and the action,
// never a property value or an id the caller sent (decision 9 on #563).
// Every value is held to `audit.js`'s own limits there.
//
// **TWO TIMES, KEPT APART.** The row's `at` is when this service RECEIVED
// the record, because the audit chain (ASVS 5.0.0 16.4.2) is the order this
// process wrote rows in; `decidedAt` in the detail is when the PEP decided.
// Rewriting one into the other would put a row in the chain out of order.
//
// **AT LEAST ONCE, AND A REPEAT IS RECOGNISABLE RATHER THAN SUPPRESSED.**
// The PEP removes a record only when it is acknowledged, so an answer lost
// on the way back sends the batch again. Every row names the PEP, the
// process `instance` and the record's `seq`, which together identify one
// decision; a mark suppressing repeats would need a new attribute on the
// `ou=peps` entry (a model, an OID and a catalog in every language) to
// be right across the nodes of a cluster, and was left out on that cost
// (#1827).
//
// **THE ERROR CODE IS THE PEP'S**, carried on the row where it is one the
// table knows (`STS-AUTHZEN-0028` for an evaluation that faulted), so a
// filter by code finds a remote PEP's faults beside this service's own.
// The rows are `summarised`: the PEP logged each one already, and a batch of
// five hundred must not become five hundred lines here.
//
// A static utility class: the handler hands it the parsed body, the caller's
// name and the modules it records through, and it answers what to send.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');

/**
 * The most records one push may carry. The PEP sends 200 by default and at
 * most 500; a larger body is a client this service did not write.
 */
const MAX_EVENTS = 500;

/**
 * The two kinds of record, and the audit action each becomes.
 */
const ACTION_OF_KIND: Record<string, string> = Object.freeze({
  enforcement: 'xacml.remote.enforcement',
  authzen: 'authzen.remote.decision',
  // The reverse proxy's (#1760): a request to a route, decided against the
  // route's own policy.
  proxy: 'xacml.remote.proxy'
});

/**
 * An `instance`: the PEP's process id, hex or a UUID's spelling.
 */
const INSTANCE_PATTERN = /^[A-Za-z0-9-]{1,64}$/;

/**
 * The XACML decisions a record may name.
 */
const DECISIONS = ['Permit', 'Deny', 'NotApplicable', 'Indeterminate'];

type Json = any;

/**
 * What `record()` answers: the status to send and the body.
 */
interface PepAuditAnswer {
  ok: boolean;
  status: number;
  code: string;
  body: Json;
}

/**
 * The modules `record()` writes through, handed in by the handler.
 */
interface PepAuditDeps {
  log: { debug(message: string): void; info(message: string): void;
         warn(message: string): void };
  audit: { audit(event: Json): Json };
  errorCodes: { isKnown(code: string): boolean; tag(code: string): string };
  registry: { read(name: string): Json };
  realmId: string;
}

/**
 * Records the decisions a remote PEP pushed to `POST /admin-api/pep-audit`
 * as audit rows (#1827).
 */
class PepAudit {
  /**
   * The module's `MAX_EVENTS`.
   */
  static readonly MAX_EVENTS = MAX_EVENTS;
  /**
   * The module's `ACTION_OF_KIND`.
   */
  static readonly ACTION_OF_KIND = ACTION_OF_KIND;

  /**
   * A text member of a record, or ''.
   *
   * @param value - anything
   * @returns the text
   */
  static text(value: unknown): string {
    // A small reader the loop below calls for every member of every record;
    // no Entering/Leaving pair, which would be ten lines per record.
    if (value === undefined || value === null) {
      return '';
    }
    return typeof value === 'object' ? '' : String(value);
  }

  /**
   * A list member of a record as text, or [].
   *
   * @param value - anything
   * @returns the strings it held
   */
  static list(value: unknown): string[] {
    // The same hot reader as text(), for lists.
    if (!Array.isArray(value)) {
      return [];
    }
    return value.filter(function (one) {
      return typeof one === 'string' || typeof one === 'number';
    }).map(String);
  }

  /**
   * Why a body is not a push, or '' when it is one.
   *
   * @param body - the parsed request body
   * @returns the sentence, or ''
   */
  static shapeProblem(body: Json): string {
    const log = helpers.log;
    log.debug("Entering PepAudit.shapeProblem().");
    const b = body || {};
    if (typeof b !== 'object' || Array.isArray(b)) {
      log.debug("Leaving PepAudit.shapeProblem(). Not an object.");
      return 'The body is a JSON object, { "instance": "<id>", "events": ' +
             '[ ... ] }.';
    }
    if (typeof b.instance !== 'string' || !INSTANCE_PATTERN.test(b.instance)) {
      log.debug("Leaving PepAudit.shapeProblem(). No instance.");
      return '`instance` names the PEP process the records came from: ' +
             'one to 64 letters, digits or hyphens.';
    }
    if (!Array.isArray(b.events) || !b.events.length) {
      log.debug("Leaving PepAudit.shapeProblem(). No events.");
      return '`events` is a non-empty array of decision records.';
    }
    if (b.events.length > MAX_EVENTS) {
      log.debug("Leaving PepAudit.shapeProblem(). Too many.");
      return 'One push carries at most ' + MAX_EVENTS + ' records, and ' +
             'this one carries ' + b.events.length + '. Send the rest in ' +
             'the next.';
    }
    const notObject = b.events.some(function (one: Json) {
      return !one || typeof one !== 'object' || Array.isArray(one);
    });
    if (notObject) {
      log.debug("Leaving PepAudit.shapeProblem(). A record is no object.");
      return 'Every member of `events` is a decision record, a JSON object.';
    }
    log.debug("Leaving PepAudit.shapeProblem(). A push.");
    return '';
  }

  /**
   * One record as the audit event it becomes, or null when it cannot be one.
   *
   * @param event - the record the PEP sent
   * @param pep - the PEP's registered name
   * @param instance - the PEP process the batch came from
   * @param deps - for the error-code table
   * @returns the audit event, or null
   */
  static auditEventOf(event: Json, pep: string, instance: string,
                      deps: PepAuditDeps): Json {
    // A HOT PATH: called for every record of a push, up to five hundred, so
    // no Entering/Leaving pair, which would drown the log; record() logs the
    // push once with its counts.
    const action = ACTION_OF_KIND[PepAudit.text(event.kind)];
    if (!action || !Number.isSafeInteger(event.seq) || event.seq < 1) {
      return null;
    }
    const kind = PepAudit.text(event.kind);
    const decision = DECISIONS.indexOf(PepAudit.text(event.decision)) >= 0
      ? PepAudit.text(event.decision) : '';
    const fault = event.fault === true;
    const allowed = event.allowed === true && !fault;
    const said = PepAudit.text(event.code);
    const code = said && deps.errorCodes.isKnown(said) ? said : '';
    const policies = PepAudit.list(event.policies);
    const discharged = PepAudit.list(event.discharged);
    const undischargeable = PepAudit.list(event.undischargeable);
    const what = kind === 'proxy'
      ? (PepAudit.text(event.subject) || 'an unauthenticated caller') +
        ' to ' + (PepAudit.text(event.action) || 'request') + ' ' +
        (PepAudit.text(event.resource) || '/') + ' on route "' +
        PepAudit.text(event.route) + '"' +
        (Number.isSafeInteger(event.status) ? ', answered ' + event.status
                                            : '')
      : kind === 'authzen'
      ? 'a ' + (PepAudit.text(event.subjectType) || 'subject') + ' to ' +
        (PepAudit.text(event.action) || 'act on') + ' a ' +
        (PepAudit.text(event.resource) || 'resource') + ', caller "' +
        PepAudit.text(event.caller) + '", application "' +
        PepAudit.text(event.application) + '"'
      : (PepAudit.text(event.subject) || 'an unnamed subject') + ' to ' +
        (PepAudit.text(event.action) || 'act on') + ' ' +
        (PepAudit.text(event.resource) || 'the protected resource');
    const verdict = fault ? 'nothing (a fault)'
      : (allowed ? 'allowed' : 'refused') +
        (decision ? ' (XACML ' + decision + ')' : '');
    return {
      action: action,
      // The person or the AuthZEN caller the decision was about; the PEP
      // itself is in the detail and the summary.
      actor: kind === 'authzen' ? PepAudit.text(event.caller)
                                : PepAudit.text(event.subject),
      target: PepAudit.text(event.resource),
      protocol: kind === 'authzen' ? 'AuthZEN'
        : (kind === 'proxy' ? 'XACML (reverse proxy)' : 'XACML'),
      channel: 'http',
      outcome: fault ? 'error' : (allowed ? 'success' : 'refused'),
      errorCode: code || undefined,
      // The PEP logged it: a batch is not a line per record here.
      summarised: true,
      summary: 'Remote PEP "' + pep + '" ' + verdict + ' ' + what +
               (undischargeable.length ? '; refused for the obligation ' +
                 undischargeable.join(', ') : '') + '.',
      // THE CAP: `audit.js` keeps twelve detail fields and drops empty
      // ones, so they are ordered by what a reader needs most — who and
      // which decision, then what it was about — and the summary already
      // says the decision in a sentence.
      detail: {
        pep: pep,
        instance: instance,
        seq: event.seq,
        decidedAt: PepAudit.text(event.at),
        decision: decision,
        application: PepAudit.text(event.application),
        route: PepAudit.text(event.route),
        status: Number.isSafeInteger(event.status) ? event.status : '',
        policies: policies.join(', '),
        undischargeable: undischargeable.join(', '),
        why: PepAudit.text(event.why),
        requestId: PepAudit.text(event.requestId),
        // Past the cap where everything above is filled; the summary carries
        // the endpoint and the decision already.
        discharged: discharged.join(', '),
        endpoint: PepAudit.text(event.endpoint),
        bias: PepAudit.text(event.bias),
        // A code the table does not know is kept as the PEP said it.
        pepCode: said && !code ? said : ''
      }
    };
  }

  /**
   * Records one push: every record a row, the highest `seq` acknowledged.
   *
   * @param body - the parsed request body
   * @param pep - the caller's name (the token's subject), the PEP's
   *   registered name
   * @param deps - the modules it writes through
   * @returns the status and body to send
   */
  static record(body: Json, pep: string, deps: PepAuditDeps): PepAuditAnswer {
    const { log, audit, errorCodes, registry } = deps;
    log.debug("Entering PepAudit.record(). pep=" + (pep || '(nobody)'));
    const problem = PepAudit.shapeProblem(body);
    if (problem) {
      log.debug("Leaving PepAudit.record(). Malformed.");
      return { ok: false, status: 400, code: 'STS-XACML-0286',
               body: { error: 'invalid_request', errors: [problem] } };
    }
    let row = null;
    try {
      row = pep ? registry.read(pep) : null;
    } catch (e) {
      // A register that cannot be read registers nobody: refused below.
      log.debug("Caught in PepAudit.record(): " + ((e && e.message) || e));
      row = null;
    }
    if (!row) {
      log.debug("Leaving PepAudit.record(). Not registered.");
      return { ok: false, status: 404, code: 'STS-XACML-0287',
               body: { error: 'not_found', errors: [
                 'No Policy Enforcement Point is registered in the realm "' +
                 deps.realmId + '" as "' + (pep || '(nobody)') + '", the ' +
                 'subject of this access token. A PEP registers (POST ' +
                 '/xacml/pep/register) under its certificate\'s common ' +
                 'name, and its decision records are taken only once it ' +
                 'has.'] } };
    }
    const instance = String(body.instance);
    let recorded = 0;
    let ignored = 0;
    let acknowledged = 0;
    body.events.forEach(function (event: Json) {
      if (Number.isSafeInteger(event.seq) && event.seq > acknowledged) {
        acknowledged = event.seq;
      }
      const auditEvent = PepAudit.auditEventOf(event, pep, instance, deps);
      if (!auditEvent) {
        ignored++;
        return;
      }
      audit.audit(auditEvent);
      recorded++;
    });
    if (ignored) {
      // One line a push, not one a record.
      log.info(errorCodes.tag('STS-XACML-0288') + 'pep-audit: ' + ignored +
               ' of ' + body.events.length + ' record(s) from remote PEP "' +
               pep + '" (instance ' + instance + ') had no positive ' +
               'integer seq or an unknown kind, and were not recorded.');
    }
    log.debug("Leaving PepAudit.record(). " + recorded + " recorded, " +
              ignored + " ignored.");
    return { ok: true, status: 200, code: '',
             body: { acknowledged: acknowledged, recorded: recorded,
                     ignored: ignored } };
  }
}

export = PepAudit;
