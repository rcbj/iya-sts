// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authzen_map.ts
//
// ===========================================================================
// AN AUTHZEN ACCESS EVALUATION, AS AN XACML REQUEST, AND ITS DECISION BACK
// (#563, phase 1, #1160). PURE: no I/O, no route, no store.
//
// AuthZEN Authorization API 1.0 (Final, 2026-01-11) section 5 is the request:
// a `subject` (`type`, `id`, `properties`), an `action` (`name`,
// `properties`), a `resource` (`type`, `id`, `properties`) and an optional
// `context`. This file reads one, refuses what it cannot represent, and
// hands `xacml_request.js`'s `authzen()` the facts — so the request is built
// by THE builder (rule 3br), and a policy written against these identifiers
// matches what the remote PEP's Rust builder spells too.
//
//   subject.id      access-subject  urn:oasis:…:subject:subject-id
//   subject.type    access-subject  urn:sts:xacml:authzen:subject-type
//   action.name     action          urn:oasis:…:action:action-id
//   resource.id     resource        urn:oasis:…:resource:resource-id
//   resource.type   resource        urn:sts:xacml:authzen:resource-type
//   *.properties.*  the catalogue's row, and nothing else
//   context.*       the catalogue's row, and nothing else; but
//   context.application  read by the adapter to choose the caller's scope
//
// and, TRUSTED, written from the caller's authentication and never from the
// body: the realm, `protocol = authzen`, the caller, its application, and
// the `supplied` bag of every member the caller sent.
//
// ---------------------------------------------------------------------------
// THE VALUE RULES (decision 6), each a 400 rather than a conversion that
// changes what a policy reads:
//
//   * THE ROW'S DATATYPE WINS. A JSON string is parsed at it by
//     `xacml_datatypes.js`, which owns every lexical space; a JSON boolean
//     reaches only a boolean row, a JSON number only an integer or a double
//     row, and an integer row refuses a fraction. A number is never quietly
//     a string, nor a string a number.
//   * `null` IS REFUSED. It is neither an empty string nor an absent member,
//     and either reading would be a guess.
//   * AN ARRAY ONLY FOR A `bag` ROW, each element a scalar by the same rules.
//     An empty array is an empty bag, and its path is still in `supplied`.
//   * A NESTED OBJECT ONLY THROUGH DECLARED DOTTED ROWS. `address` holding
//     an object reaches a request as `address.country` and `address.city`
//     if each has a row, and is refused otherwise — never flattened into a
//     string nobody can match.
//   * AN UNDECLARED PROPERTY IS REFUSED, in every mode.
//   * ABSENT AND EMPTY STAY DISTINGUISHABLE: `supplied` names every member
//     sent, so `""` sent and nothing sent are two different requests.
//
// **THE RULES ARE `xacml/xacml_attribute_rows.ts`'s SINCE #564** — the walk,
// the conversion and the bounds — because an access type's `xacml` rows
// (fine-grained authorization, `xacml/fga_map.ts`) convert a detail's
// members by them too, and one copy cannot drift from another. What is
// AuthZEN's here is the request's shape, the undeclared-property sentence
// and the codes, which are what they were before the move.
//
// ---------------------------------------------------------------------------
// THE RESULT (decision 8), FAIL-CLOSED. `true` only on a Permit carrying
// nothing this PDP cannot discharge — `xacml.ts`'s `enforce()`, deny-biased,
// which is the same rule the console's what-if and the remote PEP apply:
//
//   Permit                       true
//   Permit + an undischargeable  false — until the Obligations Profile is
//     obligation                 implemented end to end, there is no way to
//                                hand one to the PEP and know it was done
//   Deny, NotApplicable          false
//   Indeterminate, missing       false — an answer about the request
//     attribute
//   Indeterminate, a fault       an ERROR (500, or a batch item's
//     (STS-XACML-0012, 0013)     context.error), never an ordinary denial
//
// `urn:sts:xacml:obligation:log` is the one obligation discharged, as an
// audit row.
// ===========================================================================

import helpers = require('../common/helpers');
import model = require('../xacml/xacml_model');
import datatypes = require('../xacml/xacml_datatypes');
import xacmlRequest = require('../xacml/xacml_request');
import catalogue = require('./authzen_catalogue');
import rowsGrammar = require('../xacml/xacml_attribute_rows');

const { log } = helpers;

// A catalogue row, as `authzen_catalogue.ts` reads one.
interface CatalogueRow {
  object: string;
  property: string;
  attributeId: string;
  category: string;
  dataType: string;
  multiplicity: string;
  description: string;
}

// One XACML attribute the catalogue sends.
interface MappedAttribute {
  category: string;
  attributeId: string;
  dataType: string;
  values: string[];
}

// One evaluation, read and checked.
interface Evaluation {
  subject: { type: string; id: string };
  action: { name: string };
  resource: { type: string; id: string };
  application: string;
  attributes: MappedAttribute[];
  supplied: string[];
}

// A request that cannot be evaluated: the status, the code and what to tell
// the caller.
interface Refusal {
  status: number;
  code: string;
  message: string;
}

// What `read()` answers.
interface ReadResult {
  evaluation?: Evaluation;
  refusal?: Refusal;
}

// What the adapter knows about the caller, and writes as trusted facts.
interface Trusted {
  realm: string;
  caller: string;
  application: string;
}

// What `outcome()` answers.
interface Outcome {
  fault: boolean;
  decision: boolean;
  xacmlDecision: string;
  why: string;
  undischargeable: string[];
  discharged: string[];
  advice: any[];
}

// The members each object may carry, beside `properties`.
const MEMBERS = Object.freeze({
  subject: ['type', 'id', 'properties'],
  action: ['name', 'properties'],
  resource: ['type', 'id', 'properties'],
  top: ['subject', 'action', 'resource', 'context']
});

// The longest a type, an id or a name may be. Generous; a bound because a
// value goes into the request and the audit row.
const MAX_TEXT = 1024;

// The value rules' kinds (`xacml/xacml_attribute_rows.ts`, which owns the
// rules since #564) and the code each has always had here. The bounds —
// MAX_VALUE characters a string, MAX_BAG values a bag — moved with them.
const VALUE_CODES = Object.freeze({
  null: 'STS-AUTHZEN-0005',
  type: 'STS-AUTHZEN-0006',
  array: 'STS-AUTHZEN-0007',
  object: 'STS-AUTHZEN-0008',
  depth: 'STS-AUTHZEN-0008'
});

/**
 * Builds a refusal of an evaluation request.
 *
 * @param code - the error code
 * @param message - what the caller is told
 * @returns the refusal, status 400
 */
function refused(code: string, message: string): ReadResult {
  log.debug("Entering refused(). " + code);
  log.debug("Leaving refused().");
  return { refusal: { status: 400, code: code, message: message } };
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
 * Reads AuthZEN access evaluations against a realm's catalogue, and maps
 * their decisions back. Pure, without I/O.
 */
class AuthzenMap {
  /**
   * Reads one access evaluation request (section 5) against the realm's
   * catalogue rows.
   *
   * @param body - the parsed JSON body
   * @param rows - the realm's catalogue rows
   * @returns `{ evaluation }`, or `{ refusal }` with status 400
   */
  static read(body: unknown, rows: CatalogueRow[]): ReadResult {
    log.debug("Entering AuthzenMap.read().");
    if (!isObject(body)) {
      log.debug("Leaving AuthzenMap.read(). Not an object.");
      return refused('STS-AUTHZEN-0001',
        'An access evaluation request is a JSON object with subject, ' +
        'action, resource and optionally context.');
    }
    const given: any = body;
    const strayTop = AuthzenMap.stray(given, MEMBERS.top);
    if (strayTop) {
      log.debug("Leaving AuthzenMap.read(). An unknown member.");
      return refused('STS-AUTHZEN-0009',
        'An access evaluation request has no member "' + strayTop + '"; it ' +
        'takes subject, action, resource and context.');
    }
    const parts: any = {};
    const shapes = [
      ['subject', ['type', 'id']],
      ['action', ['name']],
      ['resource', ['type', 'id']]
    ];
    for (let i = 0; i < shapes.length; i += 1) {
      const name = String(shapes[i][0]);
      const required = shapes[i][1] as string[];
      const object = given[name];
      if (object === undefined) {
        log.debug("Leaving AuthzenMap.read(). No " + name + ".");
        return refused('STS-AUTHZEN-0002',
          'The request has no ' + name + ', which AuthZEN requires (' +
          name + '.' + required.join(' and ' + name + '.') + ').');
      }
      if (!isObject(object)) {
        log.debug("Leaving AuthzenMap.read(). " + name + " not an object.");
        return refused('STS-AUTHZEN-0003', name + ' must be a JSON object.');
      }
      const stray = AuthzenMap.stray(object, MEMBERS[name]);
      if (stray) {
        log.debug("Leaving AuthzenMap.read(). An unknown member of " + name +
                  ".");
        return refused('STS-AUTHZEN-0009',
          name + ' has no member "' + stray + '"; it takes ' +
          MEMBERS[name].join(', ') + '.');
      }
      parts[name] = {};
      for (let j = 0; j < required.length; j += 1) {
        const member = required[j];
        const value = object[member];
        if (value === undefined || value === null || value === '') {
          log.debug("Leaving AuthzenMap.read(). No " + name + "." + member +
                    ".");
          return refused('STS-AUTHZEN-0002',
            name + '.' + member + ' is required, and a non-empty string.');
        }
        if (typeof value !== 'string' || value.length > MAX_TEXT) {
          log.debug("Leaving AuthzenMap.read(). " + name + "." + member +
                    " not a string.");
          return refused('STS-AUTHZEN-0003',
            name + '.' + member + ' must be a string of at most ' +
            MAX_TEXT + ' characters.');
        }
        parts[name][member] = value;
      }
      if (object.properties !== undefined && !isObject(object.properties)) {
        log.debug("Leaving AuthzenMap.read(). " + name + ".properties not " +
                  "an object.");
        return refused('STS-AUTHZEN-0003',
          name + '.properties must be a JSON object.');
      }
    }
    if (given.context !== undefined && !isObject(given.context)) {
      log.debug("Leaving AuthzenMap.read(). context not an object.");
      return refused('STS-AUTHZEN-0003', 'context must be a JSON object.');
    }
    const context = given.context || {};
    let application = '';
    if (context.application !== undefined) {
      if (typeof context.application !== 'string' || !context.application ||
          context.application.length > MAX_TEXT) {
        log.debug("Leaving AuthzenMap.read(). A bad context.application.");
        return refused('STS-AUTHZEN-0003',
          'context.application must be a non-empty string naming one of ' +
          'the applications this caller is scoped to.');
      }
      application = context.application;
    }
    const supplied = ['subject.type', 'subject.id', 'action.name',
                      'resource.type', 'resource.id'];
    if (application) {
      supplied.push('context.application');
    }
    const attributes: MappedAttribute[] = [];
    const walked = [
      ['subject', given.subject.properties, 'subject.properties.'],
      ['action', given.action.properties, 'action.properties.'],
      ['resource', given.resource.properties, 'resource.properties.'],
      ['context', AuthzenMap.without(context, catalogue.RESERVED_CONTEXT),
       'context.']
    ];
    for (let k = 0; k < walked.length; k += 1) {
      const problem = AuthzenMap.walk(String(walked[k][0]), walked[k][1] || {},
        '', String(walked[k][2]), rows || [], attributes, supplied, 0);
      if (problem) {
        log.debug("Leaving AuthzenMap.read(). " + problem.refusal.code);
        return problem;
      }
    }
    log.debug("Leaving AuthzenMap.read(). " + attributes.length +
              " mapped attribute(s).");
    return { evaluation: { subject: parts.subject, action: parts.action,
                           resource: parts.resource,
                           application: application,
                           attributes: attributes, supplied: supplied } };
  }

  /**
   * The first member of an object that is not in a list, or ''.
   *
   * @param object - the object
   * @param allowed - the members it may carry
   * @returns the member's name, cut short, or ''
   */
  static stray(object: any, allowed: string[]): string {
    log.debug("Entering AuthzenMap.stray().");
    const found = Object.keys(object).filter(function (key: string) {
      return allowed.indexOf(key) < 0;
    })[0];
    log.debug("Leaving AuthzenMap.stray().");
    return found ? found.slice(0, 64) : '';
  }

  /**
   * An object less some members.
   *
   * @param object - the object
   * @param members - the members to leave out
   * @returns a shallow copy without them
   */
  static without(object: any, members: readonly string[]): any {
    log.debug("Entering AuthzenMap.without().");
    const out: any = {};
    Object.keys(object || {}).forEach(function (key: string) {
      if (members.indexOf(key) < 0) {
        out[key] = object[key];
      }
    });
    log.debug("Leaving AuthzenMap.without().");
    return out;
  }

  /**
   * Walks one object's members against the catalogue, mapping each declared
   * one and refusing the rest — through the shared walk
   * (`xacml/xacml_attribute_rows.ts`, #564), with AuthZEN's codes.
   *
   * @param object - subject, action, resource or context
   * @param value - the members at this level
   * @param prefix - the dotted path down to here, '' at the top
   * @param shown - how the caller's path is spelt, up to the properties
   * @param rows - the catalogue
   * @param out - the attributes mapped so far
   * @param supplied - the paths supplied so far
   * @param depth - how deep this level is
   * @returns a refusal, or null
   */
  static walk(object: string, value: any, prefix: string, shown: string,
              rows: CatalogueRow[], out: MappedAttribute[],
              supplied: string[], depth: number): ReadResult | null {
    log.debug("Entering AuthzenMap.walk(). " + object + " " + prefix);
    const own = rows.filter(function (one: CatalogueRow) {
      return one.object === object;
    }).map(function (one: CatalogueRow) {
      return { path: one.property, attributeId: one.attributeId,
               category: one.category, dataType: one.dataType,
               multiplicity: one.multiplicity };
    });
    const problem = rowsGrammar.walk(value, prefix, shown, own, out, supplied,
                                     depth);
    if (!problem) {
      log.debug("Leaving AuthzenMap.walk().");
      return null;
    }
    if (problem.kind === 'undeclared') {
      log.debug("Leaving AuthzenMap.walk(). Undeclared: " + problem.named);
      return refused('STS-AUTHZEN-0004',
        problem.named + ' is not in this realm\'s AuthZEN attribute ' +
        'catalogue, and an undeclared property is refused in every mode. ' +
        'An administrator declares it on the sts-authzen-api ' +
        'application.');
    }
    log.debug("Leaving AuthzenMap.walk(). " + problem.kind);
    return refused(VALUE_CODES[problem.kind] || 'STS-AUTHZEN-0006',
                   problem.message);
  }

  /**
   * Converts one member's JSON value to the lexical values its row sends —
   * the shared value rules, with AuthZEN's codes.
   *
   * @param row - the catalogue row
   * @param member - the JSON value
   * @param named - the member's path, as the caller would read it
   * @returns `{ lexical }`, or `{ refusal }`
   */
  static valuesOf(row: CatalogueRow, member: unknown, named: string):
      { lexical?: string[]; refusal?: Refusal } {
    log.debug("Entering AuthzenMap.valuesOf(). " + named);
    const read = rowsGrammar.valuesOf(row, member, named);
    if (read.problem) {
      log.debug("Leaving AuthzenMap.valuesOf(). " + read.problem.kind);
      return refused(VALUE_CODES[read.problem.kind] || 'STS-AUTHZEN-0006',
                     read.problem.message);
    }
    log.debug("Leaving AuthzenMap.valuesOf().");
    return { lexical: read.lexical };
  }

  /**
   * The lexical form of one JSON scalar at a datatype, or null (the shared
   * rule).
   *
   * @param type - the row's datatype URI
   * @param value - the JSON scalar
   * @returns the lexical form, or null
   */
  static lexicalOf(type: string, value: unknown): string | null {
    log.debug("Entering AuthzenMap.lexicalOf().");
    log.debug("Leaving AuthzenMap.lexicalOf().");
    return rowsGrammar.lexicalOf(type, value);
  }

  /**
   * A datatype's short name, for a message.
   *
   * @param type - the datatype URI
   * @returns its short name
   */
  static typeName(type: string): string {
    log.debug("Entering AuthzenMap.typeName().");
    log.debug("Leaving AuthzenMap.typeName().");
    return rowsGrammar.typeName(type);
  }

  /**
   * What a caller should send for a datatype, for a message.
   *
   * @param type - the datatype URI
   * @returns the advice
   */
  static typeAdvice(type: string): string {
    log.debug("Entering AuthzenMap.typeAdvice().");
    log.debug("Leaving AuthzenMap.typeAdvice().");
    return rowsGrammar.typeAdvice(type);
  }

  /**
   * Builds the XACML request for one evaluation, through the one builder.
   *
   * @param evaluation - the evaluation `read()` answered
   * @param trusted - the realm, the caller and the application, from the
   *   caller's authentication
   * @returns the request, in `xacml_model.js`'s shape
   */
  static request(evaluation: Evaluation, trusted: Trusted): any {
    log.debug("Entering AuthzenMap.request().");
    const built = new xacmlRequest.AuthorizationRequest({})
      .authzen({ subject: evaluation.subject, action: evaluation.action,
                 resource: evaluation.resource, realm: trusted.realm,
                 caller: trusted.caller, application: trusted.application,
                 supplied: evaluation.supplied,
                 attributes: evaluation.attributes })
      .build();
    log.debug("Leaving AuthzenMap.request().");
    return built;
  }

  /**
   * Maps a PDP answer and its enforcement to an AuthZEN decision,
   * fail-closed (the header's table).
   *
   * @param answer - the PDP's answer
   * @param enforcement - `xacml.ts`'s `enforce()` of it, deny-biased
   * @param faultCode - the error code marked on the answer, or ''
   * @returns the outcome
   */
  static outcome(answer: any, enforcement: any, faultCode: string): Outcome {
    log.debug("Entering AuthzenMap.outcome(). " + (answer || {}).decision);
    const decision = String((answer || {}).decision || '');
    const status = ((answer || {}).status || {}).code || '';
    const fault = !!faultCode ||
      (decision === model.DECISION.INDETERMINATE &&
       (status === model.STATUS.PROCESSING_ERROR ||
        status === model.STATUS.SYNTAX_ERROR));
    const out = {
      fault: fault,
      decision: !fault && !!(enforcement && enforcement.allowed),
      xacmlDecision: decision,
      why: fault
        ? 'The PDP could not evaluate the request: ' +
          String(((answer || {}).status || {}).message || status ||
                 'a fault').slice(0, 300)
        : String((enforcement && enforcement.why) || ''),
      undischargeable: (enforcement && enforcement.undischargeable) || [],
      discharged: (enforcement && enforcement.discharged) || [],
      advice: (answer && answer.advice) || []
    };
    log.debug("Leaving AuthzenMap.outcome(). " +
              (out.fault ? 'A fault.' : String(out.decision)));
    return out;
  }

  /**
   * The `context` a decision carries when `authzen.returnReasons` is on:
   * the XACML decision, why, and any advice — explanatory, and kept apart
   * from `decision`, which alone says whether to allow.
   *
   * @param outcome - what `outcome()` answered
   * @returns the context object
   */
  static reasons(outcome: Outcome): any {
    log.debug("Entering AuthzenMap.reasons().");
    const out: any = {
      xacml_decision: outcome.xacmlDecision,
      reason_admin: { en: outcome.why }
    };
    if (outcome.undischargeable.length) {
      out.undischargeable_obligations = outcome.undischargeable.slice(0);
    }
    if (outcome.advice.length) {
      out.advice = outcome.advice.map(function (one: any) {
        return { id: one.id,
                 attributes: (one.assignments || []).map(function (a: any) {
                   let value: unknown = a.value;
                   try {
                     value = datatypes.writeValue(a.type, a.value);
                   } catch (e) {
                     // An advice value that will not write is sent as the
                     // engine holds it; it is explanatory, never decisive.
                     log.debug("Caught in AuthzenMap.reasons(): " +
                               ((e && e.message) || e));
                   }
                   return { id: a.attributeId, value: value };
                 }) };
      });
    }
    log.debug("Leaving AuthzenMap.reasons().");
    return out;
  }
}

/**
 * The AuthZEN to XACML mapping (#563): a request read against the
 * catalogue, the XACML request built, and the decision mapped back.
 * @namespace
 */
export = {
  AuthzenMap: AuthzenMap,
  MAX_TEXT: MAX_TEXT,
  read: AuthzenMap.read,
  request: AuthzenMap.request,
  outcome: AuthzenMap.outcome,
  reasons: AuthzenMap.reasons
};
