// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authzen_exchange.ts
//
// ===========================================================================
// THE AUTHZEN BINDING FOR OAUTH 2.0 TOKEN EXCHANGE, DIRECTION A: THIS
// SERVICE AS THE PDP ANOTHER AUTHORIZATION SERVER ASKS (#1181).
//
// The binding (OpenID AuthZEN WG, `authzen-oauth-token-exchange-1_0`, Draft
// 1) and the Token Issuance Profile it builds on
// (`authzen-oauth-token-issuance-1_0`) have an authorization server that is
// about to perform an RFC 8693 exchange ask a PDP, over
// `/access/v1/evaluations` with `execute_all`, three kinds of tuple:
//
//   THE SUBJECT GATE          subject = the exchange subject,
//                             action  = issue:<token type>:token_exchange,
//                             resource { type: audience, id: the target }
//   THE REQUESTING PARTY GATE the same, subject = the actor_token's party,
//                             else the authenticated client
//   SCOPE TUPLES              subject = the exchange subject (and, for a
//                             Txn-Token, the requesting party too),
//                             action  = one requested scope, verbatim,
//                             resource { type: protected_resource, id }
//
// with advisory `context`: `client_id`, `subject_token_type`,
// `actor_token_type`, selected claims of the subject token, its `act` and
// `may_act`, `cnf`, and the profile's `acr`, `amr`, `auth_time`, `jti`.
//
// **THIS SERVICE ALREADY DECIDES THAT QUESTION FOR ITS OWN EXCHANGES**, so
// the binding is a CONVERSION and nothing else (rcbj on #1181, 2026-10-30,
// decision 1 and its constraint): the tuples become the question
// `common/delegation_policy.ts` already puts to the issuance policy for a
// local RFC 8693 exchange — the same facts, gathered from the same entries,
// asked through the same `issuance_gate.checkExchange()`, decided by the same
// XACML rules (`xacml_templates.ts`'s EXCHANGE_ATTRIBUTE, or the realm's own
// issuance policy). There is NO second register of who may act for whom,
// and what a local RFC 8693, WS-Trust or Kerberos delegation decides does not
// change: the one addition there is an `authzen` member of the question that
// no other door sends, carried to the request so a policy CAN tell the two
// apart (`xacml_request.js`'s `exchange()`). A scope tuple is the per-scope
// questions a local exchange's scopes meet — `exchange` stage of the issuance
// policy (`exchange-widens-scope`, `exchange-permission-not-delegated`), the
// client's declaration (`scope_policy.ts`), and the subject's roles
// (`role_permissions.ts`) — asked without writing a narrowing row, because
// nothing here issues a token.
//
// **THE CONVERSION RULES ARE FIXED** (decision 2), like the five fixed
// AuthZEN members: `FIXED_RULES` below is the whole table, published on
// `docs/authzen.md`, and `authzen_catalogue.ts` refuses a row naming any
// context member they read (BINDING_CONTEXT). A realm's catalogue may ADD
// rows — a `context.tenant` — and their attributes reach the exchange
// question beside the fixed facts.
//
// **ID-JAG AND TXN-TOKEN ARE IN SCOPE** (decision 3): `id_jag` and
// `txn_token` are registered token type short names here like the OAuth
// ones, an ID-JAG's two-level evaluation needs nothing more (its gate tuples
// name the peer authorization server and only its scope tuples name the
// level-2 resources), and a Txn-Token's scope tuples for the requesting
// party are decided as that party's.
//
// **THE RESPONSE MAY ONLY NARROW.** `context.issuance` on the subject gate
// carries `token_lifetime` (the subject token's remaining life and this
// realm's access-token lifetime for the client, the lesser) and, for a
// request naming no scope, `granted_scope` (the subject token's scope,
// narrowed by the same per-scope questions). Never `sub`, `aud`, `act`,
// `may_act` or any claim: the binding reserves them, and a PDP that wrote
// `act` could fabricate a delegation history.
//
// **DEVELOPMENT MODE ANSWERS AS THE LOCAL TOKEN ENDPOINT WOULD ISSUE.** The
// issuance policy computes `enforced` from the mode, and a local exchange it
// refuses unenforced is issued with "would have been refused" on its row; so
// a gate the policy refused unenforced is `true` here, with STS-AUTHZEN-0110
// on the audit row saying what product would have answered. Product refuses.
//
// Direction B — this authorization server consulting an external PDP — is
// not built (decision 1).
// ===========================================================================

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import catalogue = require('./authzen_catalogue');

const { log } = helpers;

type Json = any;

// THE TOKEN TYPE SHORT NAMES (the issuance profile's registry, and the
// binding's additions), each with the RFC 8693 token type URI it names.
const TOKEN_TYPES: Readonly<Record<string, string>> = Object.freeze({
  access_token: 'urn:ietf:params:oauth:token-type:access_token',
  refresh_token: 'urn:ietf:params:oauth:token-type:refresh_token',
  id_token: 'urn:ietf:params:oauth:token-type:id_token',
  jwt: 'urn:ietf:params:oauth:token-type:jwt',
  saml1: 'urn:ietf:params:oauth:token-type:saml1',
  saml2: 'urn:ietf:params:oauth:token-type:saml2',
  id_jag: 'urn:ietf:params:oauth:token-type:id-jag',
  txn_token: 'urn:ietf:params:oauth:token-type:txn_token'
});

// The grant segment this binding applies to, and its grant type.
const GRANT = 'token_exchange';
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';

// A gate action: `issue:<token type>:<grant>`, each a registered short name
// (`[a-z][a-z0-9_]{0,20}`, the profile's portability bound).
const GATE_ACTION = /^issue:([a-z][a-z0-9_]{0,20}):([a-z][a-z0-9_]{0,20})$/;

// The two resource types, and the three subject types, of the registry.
const GATE_RESOURCE = 'audience';
const SCOPE_RESOURCE = 'protected_resource';
const SUBJECT_TYPES = Object.freeze(['user', 'client', 'workload']);

// The capability the metadata advertises while the binding is on.
const CAPABILITY = 'urn:openid:authzen:capability:token-issuance';

// The JSON type of each context member the fixed rules read (the profile's
// single-type rule). `subject_token` is an object of validated claims.
const CONTEXT_TYPES: Readonly<Record<string, string>> = Object.freeze({
  client_id: 'string',
  acr: 'string',
  amr: 'strings',
  auth_time: 'integer',
  cnf: 'object',
  jti: 'string',
  subject_token_type: 'string',
  actor_token_type: 'string',
  subject_token: 'object',
  act: 'object',
  may_act: 'object'
});

// The subject token claims a fixed rule reads, and their types. Any other
// claim is advisory and ignored, as the binding says of an unknown key.
const SUBJECT_TOKEN_CLAIMS: Readonly<Record<string, string>> = Object.freeze({
  iss: 'string',
  aud: 'string-or-strings',
  client_id: 'string',
  azp: 'string',
  scope: 'string',
  exp: 'integer'
});

// The deepest `act` chain read; deeper is refused as malformed.
const MAX_ACT_DEPTH = 32;

// WHICH GATE A REFUSAL IS ABOUT. The policy's refusal kinds
// (`delegation_policy.ts`'s REFUSAL_ATTRIBUTE and sentences): what the
// subject and the target are refuse the SUBJECT gate — whether a token of
// this kind may exist for this subject and target at all — and what the
// requesting party may do refuses ITS gate. `subject` (protected, or outside
// the actor's subject groups) and a realm policy's own `policy` are about
// the pair, and refuse both. The binding has the AS fail on either and tell
// the client neither, so the split is for the operator's audit row.
const SUBJECT_REFUSALS = Object.freeze(['authority', 'unregistered-target',
                                        'no-target', 'targets']);
const PARTY_REFUSALS = Object.freeze(['intermediary', 'semantics', 'target',
                                      'may-act']);

// THE FIXED CONVERSION RULES (decision 2), as published. Each is a rule of
// this file, and `docs/authzen.md`'s table is this one;
// `tests/authzen_token_exchange.js` F holds the two together.
const FIXED_RULES = Object.freeze([
  { member: 'resource.type = audience, action.name = ' +
            'issue:<type>:token_exchange',
    rule: 'a GATE tuple. The first one for a target is the subject gate; ' +
          'one naming another subject for the same target and type is the ' +
          'requesting party gate; a third subject is refused' },
  { member: 'resource.type = audience, action.name = issue:<type>:<grant>',
    rule: 'any other grant, or a token type not registered: decided false ' +
          '(this PDP decides the token-exchange gate only)' },
  { member: 'resource.type = protected_resource',
    rule: 'a SCOPE tuple: action.name is the scope, verbatim; decided only ' +
          'beside a token-exchange gate in the same batch, and only for the ' +
          'exchange subject (or, for txn_token, the requesting party)' },
  { member: '<type> of the gate action',
    rule: 'the token type short name: access_token, refresh_token, ' +
          'id_token, jwt, saml1, saml2, id_jag, txn_token; sent as ' +
          'urn:sts:xacml:authzen:token-type' },
  { member: 'subject (subject gate)',
    rule: 'the exchange subject: the access-subject of the exchange ' +
          'question, a person by name or urn:uuid subject, an application ' +
          'by identifier or client_id (urn:sts:client:<id> is <id>)' },
  { member: 'subject (requesting party gate)',
    rule: 'the actor: the intermediary-subject of the exchange question; ' +
          'with no requesting party gate, the subject itself (the gates ' +
          'coincide)' },
  { member: 'subject.type',
    rule: 'user, client or workload, else 400; sent as ' +
          'urn:sts:xacml:authzen:subject-type on each party' },
  { member: 'resource.id (gate)',
    rule: 'the one target R, resolved as a local exchange\'s audience is' },
  { member: 'context.subject_token.aud, .client_id, .azp',
    rule: 'S, the application the subject token was issued for, in that ' +
          'order, as a local exchange reads its subject_token' },
  { member: 'context.may_act',
    rule: 'may-act-present, and may-act-names-actor compared with the ' +
          'requesting party (sub, and iss where the claim has one); never ' +
          'a permit by itself' },
  { member: 'context.act',
    rule: 'its depth, as urn:sts:xacml:authzen:act-depth' },
  { member: 'context.subject_token_type, context.actor_token_type',
    rule: 'verbatim, as urn:sts:xacml:authzen:subject-token-type and ' +
          '...:actor-token-type' },
  { member: 'context.subject_token.scope',
    rule: 'what a scope tuple may not widen (exchange stage), and the set ' +
          'granted_scope narrows when the request names no scope' },
  { member: 'context.subject_token.exp',
    rule: 'the ceiling on token_lifetime; none left is a false subject gate' },
  { member: 'context.client_id',
    rule: 'the client whose declared scopes a scope tuple is held to, and ' +
          'whose access-token lifetime bounds token_lifetime' },
  { member: 'context.cnf, .acr, .amr, .auth_time, .jti',
    rule: 'read for their type only; no rule decides on them' },
  { member: 'exchange_semantics',
    rule: 'not sent: the policy chooses by its precedence, as for a local ' +
          'exchange that named none' },
  { member: 'urn:sts:xacml:protocol',
    rule: 'OAuth 2.0, the act\'s protocol, so one policy decides both; the ' +
          'trusted urn:sts:xacml:authzen:caller tells this one apart' }
]);

// What `classify()` answers.
interface Kind {
  kind: string;
  tokenType: string;
}

// One gate group: a target and a token type, its two parties, and the
// decision once made.
interface Group {
  key: string;
  audience: string;
  tokenType: string;
  subject: { type: string; id: string };
  party: { type: string; id: string } | null;
  decided: Json | null;
}

// One item's place in the batch.
interface Entry {
  kind: string;
  tokenType: string;
  group: Group | null;
}

// What `plan()` answers.
interface Plan {
  entries: Entry[];
  groups: Group[];
  hasScopes: boolean;
  exchangeSubject: { type: string; id: string } | null;
  txnParties: string[];
  scopeCache: Record<string, Json>;
}

// The fixed context, read.
interface Fixed {
  clientId: string;
  subjectTokenType: string;
  actorTokenType: string;
  subjectToken: Json;
  act: Json;
  actDepth: number;
  mayAct: Json;
  supplied: string[];
}

// What one item is answered.
interface Answer {
  decision: boolean;
  code: string;
  why: string;
  issuance: Json | null;
  semantics: string;
  decidedBy: string;
  xacmlDecision: string;
}

interface ExchangeDeps {
  log: typeof log;
  config: { value(key: string): any };
  mode: { current(): string };
  applications: Json;
  delegation: Json;
  gate: Json;
  scopeVerdicts: Json;
  scopePolicy: Json;
  rolePermissions: Json;
  loadOauth2(): Json;
  nowSec(): number;
}

/**
 * The token-exchange binding: which tuples it reads, the fixed conversion,
 * and each tuple's answer from the questions a local exchange asks.
 */
class AuthzenTokenExchange {
  /**
   * Builds the binding over its dependencies.
   *
   * @param deps - the logger, settings, mode, application registry, the
   *   delegation policy, the issuance gate, the scope verdicts, the scope
   *   policy, the role permissions, the authorization server and the clock
   */
  constructor(private readonly deps: ExchangeDeps) {
    deps.log.debug("Entering AuthzenTokenExchange.constructor().");
    deps.log.debug("Leaving AuthzenTokenExchange.constructor().");
  }

  /**
   * The dependencies built from the real modules. Every one is a library
   * the token endpoint already loaded, so each require is a cache hit.
   *
   * @returns the dependencies
   */
  static defaultDeps(): ExchangeDeps {
    log.debug("Entering AuthzenTokenExchange.defaultDeps().");
    log.debug("Leaving AuthzenTokenExchange.defaultDeps().");
    return {
      log: log,
      config: require('../common/config'),
      mode: require('../common/mode'),
      applications: require('../common/applications'),
      delegation: require('../common/delegation_policy'),
      gate: require('../common/issuance_gate'),
      scopeVerdicts: require('../xacml/xacml_scope_verdicts'),
      scopePolicy: require('../common/scope_policy'),
      rolePermissions: require('../common/role_permissions'),
      loadOauth2: function (): Json {
        log.debug("Entering loadOauth2().");
        log.debug("Leaving loadOauth2().");
        return require('../oauth-oidc/oauth2');
      },
      nowSec: helpers.nowSec
    };
  }

  /**
   * Whether the binding answers in this realm (`authzen.tokenExchange`).
   *
   * @returns true while it is on
   */
  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering AuthzenTokenExchange.enabled().");
    log.debug("Leaving AuthzenTokenExchange.enabled().");
    return config.value('authzen.tokenExchange') === true;
  }

  /**
   * What kind of tuple a request is, by the fixed rules: a token-exchange
   * gate, another gate, a scope tuple, or none of the binding's.
   *
   * @param body - one evaluation request, defaults merged
   * @returns `{ kind, tokenType }`; kind is `gate`, `other-gate`,
   *   `unregistered-gate`, `scope` or ''
   */
  static classify(body: unknown): Kind {
    log.debug("Entering AuthzenTokenExchange.classify().");
    const given: Json = body && typeof body === 'object' ? body : {};
    const resource = given.resource && typeof given.resource === 'object'
      ? given.resource : {};
    const action = given.action && typeof given.action === 'object'
      ? given.action : {};
    const type = typeof resource.type === 'string' ? resource.type : '';
    const out: Kind = { kind: '', tokenType: '' };
    if (type === SCOPE_RESOURCE) {
      out.kind = 'scope';
    } else if (type === GATE_RESOURCE) {
      const parts = GATE_ACTION.exec(typeof action.name === 'string'
        ? action.name : '');
      if (parts) {
        out.tokenType = parts[1];
        out.kind = parts[2] !== GRANT ? 'other-gate'
          : (Object.prototype.hasOwnProperty.call(TOKEN_TYPES, parts[1])
            ? 'gate' : 'unregistered-gate');
      }
    }
    log.debug("Leaving AuthzenTokenExchange.classify(). " +
              (out.kind || 'Not the binding\'s.'));
    return out;
  }

  /**
   * Plans a batch: each item's kind, the gate groups (one per target and
   * token type) with their two parties, and the exchange subject the scope
   * tuples must name. Answers every item `''` while the binding is off.
   *
   * @param bodies - the items, defaults merged; a null is not an object
   * @returns the plan
   */
  plan(bodies: unknown[]): Plan {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AuthzenTokenExchange.plan(). " + bodies.length);
    const out: Plan = { entries: [], groups: [], hasScopes: false,
                        exchangeSubject: null, txnParties: [],
                        scopeCache: {} };
    const on = self.enabled();
    const subjectOf = function (body: Json): { type: string; id: string } {
      log.debug("Entering subjectOf().");
      const s = body && body.subject && typeof body.subject === 'object'
        ? body.subject : {};
      log.debug("Leaving subjectOf().");
      return { type: String(s.type || ''), id: String(s.id || '') };
    };
    bodies.forEach(function (body: Json) {
      const kind = on ? AuthzenTokenExchange.classify(body)
                      : { kind: '', tokenType: '' };
      const entry: Entry = { kind: kind.kind, tokenType: kind.tokenType,
                             group: null };
      if (kind.kind === 'gate') {
        const audience = String(body.resource.id || '');
        const key = audience + '\u0000' + kind.tokenType;
        const subject = subjectOf(body);
        let group = out.groups.filter(function (one: Group) {
          return one.key === key;
        })[0];
        if (!group) {
          group = { key: key, audience: audience, tokenType: kind.tokenType,
                    subject: subject, party: null, decided: null };
          out.groups.push(group);
          if (!out.exchangeSubject) {
            out.exchangeSubject = subject;
          }
          entry.kind = 'subject-gate';
        } else if (subject.id === group.subject.id &&
                   subject.type === group.subject.type) {
          // The same subject gate asked twice is the same question.
          entry.kind = 'subject-gate';
        } else if (!group.party) {
          group.party = subject;
          entry.kind = 'party-gate';
          if (kind.tokenType === 'txn_token') {
            out.txnParties.push(subject.type + '\u0000' + subject.id);
          }
        } else if (subject.id === group.party.id &&
                   subject.type === group.party.type) {
          entry.kind = 'party-gate';
        } else {
          entry.kind = 'extra-gate';
        }
        entry.group = group;
      } else if (kind.kind === 'scope') {
        out.hasScopes = true;
      }
      out.entries.push(entry);
    });
    // THE SCOPE TUPLES, once every gate is known: the exchange subject's,
    // a Txn-Token requesting party's, a stranger's, or one with no gate.
    out.entries.forEach(function (entry: Entry, i: number) {
      if (entry.kind !== 'scope') {
        return;
      }
      const subject = subjectOf(bodies[i]);
      if (!out.exchangeSubject) {
        entry.kind = 'orphan-scope';
      } else if (subject.id === out.exchangeSubject.id &&
                 subject.type === out.exchangeSubject.type) {
        entry.kind = 'subject-scope';
      } else if (out.txnParties.indexOf(subject.type + '\u0000' +
                                        subject.id) >= 0) {
        entry.kind = 'party-scope';
      } else {
        entry.kind = 'stranger-scope';
      }
    });
    log.debug("Leaving AuthzenTokenExchange.plan(). " + out.groups.length +
              " gate group(s).");
    return out;
  }

  /**
   * Says why a request's context names a member the binding reads although
   * the request is not one of the binding's tuples, or the binding is off.
   *
   * @param body - one evaluation request
   * @param on - whether the binding is on
   * @returns the refusal message, or ''
   */
  static strayContext(body: unknown, on: boolean): string {
    log.debug("Entering AuthzenTokenExchange.strayContext().");
    const given: Json = body && typeof body === 'object' ? body : {};
    const context = given.context && typeof given.context === 'object' &&
      !Array.isArray(given.context) ? given.context : {};
    const named = catalogue.BINDING_CONTEXT.filter(function (key: string) {
      return context[key] !== undefined;
    })[0];
    if (!named) {
      log.debug("Leaving AuthzenTokenExchange.strayContext(). None.");
      return '';
    }
    log.debug("Leaving AuthzenTokenExchange.strayContext(). " + named);
    return 'context.' + named + ' is read by the OAuth token-exchange ' +
      'binding\'s fixed rules, and only on its gate and scope tuples (' +
      'resource.type audience or protected_resource)' +
      (on ? '.' : '; the binding is off in this realm ' +
                  '(authzen.tokenExchange).');
  }

  /**
   * Reads the context members the fixed rules read, each by its one JSON
   * type, and answers the request without them for the catalogue's reader.
   *
   * @param body - one evaluation request of the binding's
   * @returns `{ fixed, rest }`, or `{ refusal }` (STS-AUTHZEN-0100)
   */
  static readContext(body: unknown): { fixed?: Fixed; rest?: Json;
                                       refusal?: string } {
    log.debug("Entering AuthzenTokenExchange.readContext().");
    const given: Json = body && typeof body === 'object' ? body : {};
    const context = given.context && typeof given.context === 'object' &&
      !Array.isArray(given.context) ? given.context : null;
    const isObject = function (value: unknown): boolean {
      log.debug("Entering isObject().");
      log.debug("Leaving isObject().");
      return !!value && typeof value === 'object' && !Array.isArray(value);
    };
    const typed = function (type: string, value: unknown): boolean {
      log.debug("Entering typed(). " + type);
      let ok: boolean;
      if (type === 'string') {
        ok = typeof value === 'string' && value.length <= 2048;
      } else if (type === 'strings') {
        ok = Array.isArray(value) && value.length <= 64 &&
          value.every(function (one: unknown) {
            return typeof one === 'string' && one.length <= 256;
          });
      } else if (type === 'string-or-strings') {
        ok = typed('string', value) || typed('strings', value);
      } else if (type === 'integer') {
        ok = typeof value === 'number' && Number.isSafeInteger(value);
      } else {
        ok = isObject(value);
      }
      log.debug("Leaving typed().");
      return ok;
    };
    const fixed: Fixed = { clientId: '', subjectTokenType: '',
                           actorTokenType: '', subjectToken: {}, act: null,
                           actDepth: 0, mayAct: null, supplied: [] };
    const rest: Json = Object.assign({}, given);
    if (!context) {
      log.debug("Leaving AuthzenTokenExchange.readContext(). No context.");
      return { fixed: fixed, rest: rest };
    }
    const keys = Object.keys(CONTEXT_TYPES);
    for (let i = 0; i < keys.length; i += 1) {
      const key = keys[i];
      const value = context[key];
      if (value === undefined) {
        continue;
      }
      if (!typed(CONTEXT_TYPES[key], value)) {
        log.debug("Leaving AuthzenTokenExchange.readContext(). " + key);
        return { refusal: 'context.' + key + ' must be ' +
          ({ string: 'a string', strings: 'an array of strings',
             integer: 'a whole number', object: 'a JSON object' } as Json)[
            CONTEXT_TYPES[key]] + ' (the token-exchange binding gives each ' +
          'of its context keys one JSON type).' };
      }
      fixed.supplied.push('context.' + key);
    }
    const token = context.subject_token || {};
    const claims = Object.keys(SUBJECT_TOKEN_CLAIMS);
    for (let j = 0; j < claims.length; j += 1) {
      const claim = claims[j];
      if (token[claim] !== undefined &&
          !typed(SUBJECT_TOKEN_CLAIMS[claim], token[claim])) {
        log.debug("Leaving AuthzenTokenExchange.readContext(). " +
                  "subject_token." + claim);
        return { refusal: 'context.subject_token.' + claim + ' must be ' +
          (SUBJECT_TOKEN_CLAIMS[claim] === 'integer' ? 'a whole number'
            : (SUBJECT_TOKEN_CLAIMS[claim] === 'string' ? 'a string'
              : 'a string or an array of strings')) + '.' };
      }
    }
    let depth = 0;
    let link = context.act;
    while (isObject(link)) {
      depth += 1;
      if (depth > MAX_ACT_DEPTH) {
        log.debug("Leaving AuthzenTokenExchange.readContext(). Too deep.");
        return { refusal: 'context.act is nested more than ' + MAX_ACT_DEPTH +
                          ' deep.' };
      }
      link = link.act;
    }
    if (context.may_act !== undefined &&
        typeof context.may_act.sub !== 'string') {
      log.debug("Leaving AuthzenTokenExchange.readContext(). may_act.sub.");
      return { refusal: 'context.may_act must carry sub, a string (RFC ' +
                        '8693 section 4.4).' };
    }
    fixed.clientId = String(context.client_id || '');
    fixed.subjectTokenType = String(context.subject_token_type || '');
    fixed.actorTokenType = String(context.actor_token_type || '');
    fixed.subjectToken = token;
    fixed.act = context.act || null;
    fixed.actDepth = depth;
    fixed.mayAct = context.may_act || null;
    const others: Json = {};
    Object.keys(context).forEach(function (key: string) {
      if (catalogue.BINDING_CONTEXT.indexOf(key) < 0) {
        others[key] = context[key];
      }
    });
    if (Object.keys(others).length) {
      rest.context = others;
    } else {
      delete rest.context;
    }
    log.debug("Leaving AuthzenTokenExchange.readContext().");
    return { fixed: fixed, rest: rest };
  }

  /**
   * A party's name as `delegation_policy.ts` is asked about it: a client's
   * subject `urn:sts:client:<id>` is its client_id, as the token endpoint
   * hands it.
   *
   * @param id - the tuple's subject.id
   * @returns the name
   */
  static partyName(id: string): string {
    log.debug("Entering AuthzenTokenExchange.partyName().");
    const given = String(id || '');
    log.debug("Leaving AuthzenTokenExchange.partyName().");
    return /^urn:sts:client:./.test(given)
      ? given.slice('urn:sts:client:'.length) : given;
  }

  /**
   * The question `delegation_policy.decide()` is asked for one gate group,
   * as the token endpoint would ask it for the same exchange
   * (`oauth2.ts`'s token exchange): the protocol, no requested semantics,
   * the actor, the subject, S's candidates, the one target and may_act —
   * and the `authzen` facts no other door sends.
   *
   * @param group - the gate group
   * @param fixed - the fixed context
   * @param evaluation - the subject gate as `authzen_map.ts` read it
   * @param trusted - `{ caller, application }`
   * @returns the question
   */
  questionFor(group: Group, fixed: Fixed, evaluation: Json,
              trusted: Json): Json {
    const { log, delegation } = this.deps;
    log.debug("Entering AuthzenTokenExchange.questionFor().");
    const party = group.party || group.subject;
    const actorName = AuthzenTokenExchange.partyName(party.id);
    const token = fixed.subjectToken || {};
    const audiences = Array.isArray(token.aud) ? token.aud.map(String)
      : (token.aud ? [String(token.aud)] : []);
    // The requesting party in both of a client's spellings, the token
    // endpoint's `actorIdentity` reason: a may_act naming the bare client_id
    // or its subject names the same client.
    const aliases = [actorName, 'urn:sts:client:' + actorName]
      .filter(function (one: string) {
        return one !== party.id;
      });
    const mayActNamesActor = !!fixed.mayAct &&
      delegation.mayActNames(fixed.mayAct, { sub: party.id, iss: '',
                                             aliases: aliases });
    const question = {
      protocol: 'OAuth 2.0',
      requested: '',
      actor: actorName,
      subject: AuthzenTokenExchange.partyName(group.subject.id),
      source: audiences.concat([String(token.client_id || ''),
                                String(token.azp || '')]),
      targets: group.audience ? [group.audience] : [],
      targetKind: 'audience',
      mayActPresent: !!fixed.mayAct,
      mayActNamesActor: mayActNamesActor,
      authzen: {
        caller: String(trusted.caller || ''),
        application: String(trusted.application || ''),
        subjectType: group.subject.type,
        actorType: party.type,
        tokenType: group.tokenType,
        subjectTokenType: fixed.subjectTokenType,
        actorTokenType: fixed.actorTokenType,
        actDepth: fixed.actDepth,
        supplied: (evaluation.supplied || []).concat(fixed.supplied),
        attributes: evaluation.attributes || []
      }
    };
    log.debug("Leaving AuthzenTokenExchange.questionFor().");
    return question;
  }

  /**
   * Decides one gate group once: the delegation question, then what the
   * subject gate may carry in `context.issuance`.
   *
   * @param plan - the batch's plan
   * @param group - the gate group
   * @param fixed - the fixed context
   * @param evaluation - the gate as `authzen_map.ts` read it
   * @param trusted - `{ caller, application }`
   * @returns the group's decision, kept on the group
   */
  decideGroup(plan: Plan, group: Group, fixed: Fixed, evaluation: Json,
              trusted: Json): Json {
    const self = this;
    const { log, delegation } = this.deps;
    log.debug("Entering AuthzenTokenExchange.decideGroup().");
    if (group.decided) {
      log.debug("Leaving AuthzenTokenExchange.decideGroup(). Kept.");
      return group.decided;
    }
    const question = self.questionFor(group, fixed, evaluation, trusted);
    const decision = delegation.decide(question);
    const out: Json = { decision: decision, question: question,
                        expired: false, issuance: null };
    const passes = decision.allowed || !decision.enforced;
    if (passes) {
      const shaped = self.issuance(plan, group, fixed);
      out.expired = shaped.expired;
      out.issuance = shaped.issuance;
    }
    group.decided = out;
    log.debug("Leaving AuthzenTokenExchange.decideGroup(). " +
              (decision.allowed ? 'Allowed.' : 'Refused: ' +
               decision.refusal));
    return out;
  }

  /**
   * What the subject gate's `context.issuance` carries: `token_lifetime`
   * (the lesser of the subject token's remaining life and this realm's
   * access-token lifetime for the client, for an access token) and, for a
   * request naming no scope, `granted_scope` (the subject token's scope,
   * narrowed by the per-scope questions). Each only NARROWS what the AS
   * would otherwise grant; nothing else is ever written.
   *
   * @param plan - the batch's plan
   * @param group - the gate group
   * @param fixed - the fixed context
   * @returns `{ issuance, expired }`; issuance null when there is nothing
   */
  issuance(plan: Plan, group: Group, fixed: Fixed): { issuance: Json;
                                                      expired: boolean } {
    const self = this;
    const { log, applications, config, nowSec } = this.deps;
    log.debug("Entering AuthzenTokenExchange.issuance().");
    const token = fixed.subjectToken || {};
    const ceilings: number[] = [];
    if (typeof token.exp === 'number') {
      const left = token.exp - nowSec();
      if (left <= 0) {
        log.debug("Leaving AuthzenTokenExchange.issuance(). Expired.");
        return { issuance: null, expired: true };
      }
      ceilings.push(left);
    }
    if (group.tokenType === 'access_token') {
      const client = fixed.clientId ||
        (group.party ? AuthzenTokenExchange.partyName(group.party.id) : '');
      let ttl = 0;
      try {
        ttl = Number(applications.settingFor(client, 'oauth2.accessTokenTtlS',
                                             config)) || 0;
      } catch (e) {
        log.debug("Caught in AuthzenTokenExchange.issuance(): " +
                  ((e && e.message) || e));
        ttl = 0;
      }
      if (ttl > 0) {
        ceilings.push(ttl);
      }
    }
    const out: Json = {};
    if (ceilings.length) {
      out.token_lifetime = Math.floor(Math.min.apply(null, ceilings));
    }
    // A REQUEST NAMING NO SCOPE: the profile's "permit, and grant this set",
    // from the set a local exchange would carry forward — the subject
    // token's scope — narrowed by the same questions a scope tuple meets.
    // A subject token with no scope claim leaves it out, and the AS falls
    // back to its own defaults, the profile's safe degradation.
    if (!plan.hasScopes && typeof token.scope === 'string') {
      const asked = token.scope.split(/\s+/).filter(Boolean);
      const verdicts = self.scopeVerdicts(plan, group.subject, fixed, asked,
                                          true);
      out.granted_scope = asked.filter(function (one: string) {
        return verdicts[one] && verdicts[one].keep;
      }).join(' ');
    }
    log.debug("Leaving AuthzenTokenExchange.issuance().");
    return { issuance: Object.keys(out).length ? out : null,
             expired: false };
  }

  /**
   * The per-scope questions a local exchange's scope meets, for one party
   * and a set of scope values: the exchange stage of the issuance policy
   * (not for the inherited set, which is the subject token's own), the
   * client's declaration, and the party's roles. Asked once per party and
   * set, and kept on the plan.
   *
   * @param plan - the batch's plan
   * @param party - the subject the scopes are for
   * @param fixed - the fixed context
   * @param asked - the scope values
   * @param inherited - true for the subject token's own scope
   * @returns scope → `{ keep, code, why }`
   */
  scopeVerdicts(plan: Plan, party: { type: string; id: string },
                fixed: Fixed, asked: string[], inherited: boolean): Json {
    const self = this;
    const { log, delegation, gate, scopeVerdicts, scopePolicy,
            rolePermissions, mode } = this.deps;
    log.debug("Entering AuthzenTokenExchange.scopeVerdicts(). " +
              asked.length);
    const key = party.type + '\u0000' + party.id + '\u0000' +
      (inherited ? 'i' : 'a') + '\u0000' + asked.join(' ');
    if (plan.scopeCache[key]) {
      log.debug("Leaving AuthzenTokenExchange.scopeVerdicts(). Kept.");
      return plan.scopeCache[key];
    }
    const name = AuthzenTokenExchange.partyName(party.id);
    const exchangeSubject = plan.exchangeSubject || party;
    const isSubject = party.id === exchangeSubject.id &&
      party.type === exchangeSubject.type;
    // The client: the authenticated one the context names, else — a
    // Txn-Token party's own scopes, or no client named — the party itself.
    const client = isSubject ? (fixed.clientId || '') : name;
    const facts = delegation.partyFacts(name) || {};
    const subject = { kind: facts.kind === 'application' ? 'application'
                                                         : 'user',
                      name: String(facts.id || name), authenticated: true };
    const out: Json = {};
    asked.forEach(function (one: string) {
      out[one] = { keep: true, code: '', why: '' };
    });
    const drop = function (one: string, code: string, why: string): void {
      log.debug("Entering drop(). " + one);
      if (out[one] && out[one].keep) {
        out[one] = { keep: false, code: code, why: why };
      }
      log.debug("Leaving drop().");
    };
    // 1. THE EXCHANGE STAGE (`exchange-widens-scope`, and a delegated
    //    permission the client does not hold), the token endpoint's own
    //    question with its own facts, for the subject's requested scopes.
    if (isSubject && !inherited && asked.length) {
      const token = fixed.subjectToken || {};
      const hasScope = typeof token.scope === 'string';
      const granted = hasScope ? token.scope.split(/\s+/).filter(Boolean)
                               : [];
      let permissionOf: Json = {};
      try {
        const found = self.deps.loadOauth2().audienceScopes(asked.join(' '),
                                                            client);
        (found.permissions || []).forEach(function (p: Json) {
          permissionOf[p.scope] = p;
        });
      } catch (e) {
        log.debug("Caught in AuthzenTokenExchange.scopeVerdicts(): " +
                  ((e && e.message) || e));
        permissionOf = {};
      }
      const SA = scopeVerdicts.ATTRIBUTE;
      const answer = gate.checkScopes({
        subject: { kind: 'application', name: client, authenticated: true },
        client: client,
        protocol: 'OAuth 2.0',
        mode: mode.current(),
        stage: 'exchange',
        grantType: GRANT_TYPE,
        requested: asked,
        facts: asked.map(function (one: string): Json {
          const permission = permissionOf[one];
          const inSubject = granted.indexOf(one) >= 0 ||
            (!!permission && granted.indexOf(permission.permission) >= 0);
          const attributes = [
            scopeVerdicts.resourceFact(SA.SUBJECT_TOKEN_HAS_SCOPE, hasScope),
            scopeVerdicts.resourceFact(SA.SCOPE_IN_SUBJECT_TOKEN, inSubject)];
          if (permission) {
            attributes.push(
              scopeVerdicts.resourceFact(SA.SCOPE_DELEGATED, true),
              scopeVerdicts.resourceFact(SA.SCOPE_GRANTED,
                                         !!permission.granted));
          }
          return { scope: one, attributes: attributes };
        })
      }) || {};
      (answer.verdicts || []).forEach(function (v: Json) {
        if (v.verdict === 'refuse' || v.verdict === 'drop') {
          drop(String(v.scope), 'STS-AUTHZEN-0111',
               'the issuance policy ' + (v.verdict === 'refuse'
                 ? 'refuses' : 'drops') + ' it at the exchange stage' +
               (v.code ? ' (' + v.code + ')' : ''));
        }
      });
    }
    // 2. THE CLIENT'S DECLARATION (#110), as `tokenSet()`'s backstop asks.
    if (asked.length) {
      const judged = scopePolicy.judge(asked.join(' '), client,
                                       { stage: 'mint' }) || {};
      ([] as string[])
        .concat(judged.protectedRefused || [], judged.undeclaredRefused || [],
                judged.nativeSsoRefused || [])
        .forEach(function (one: string) {
          drop(one, 'STS-AUTHZEN-0112', 'the client "' + client + '" does ' +
               'not declare it (oauthAllowedScope)');
        });
    }
    // 3. THE PARTY'S ROLES (#302), as `tokenSet()` asks, without the
    //    narrowing row: nothing is issued here.
    if (asked.length && rolePermissions.asksFor(asked.join(' '), subject)) {
      const narrowed = rolePermissions.narrowScope(asked.join(' '), subject,
        { clientId: client, grant: GRANT_TYPE, record: false }) || {};
      (narrowed.removed || []).forEach(function (one: string) {
        drop(one, 'STS-AUTHZEN-0113', narrowed.why || 'no role of "' +
             subject.name + '" authorizes it');
      });
    }
    plan.scopeCache[key] = out;
    log.debug("Leaving AuthzenTokenExchange.scopeVerdicts().");
    return out;
  }

  /**
   * Answers one of the binding's tuples.
   *
   * @param plan - the batch's plan
   * @param entry - the item's entry in the plan
   * @param body - the item, defaults merged
   * @param fixed - its fixed context
   * @param evaluation - the item as `authzen_map.ts` read it
   * @param trusted - `{ caller, application }`
   * @returns the answer
   */
  answer(plan: Plan, entry: Entry, body: Json, fixed: Fixed,
         evaluation: Json, trusted: Json): Answer {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AuthzenTokenExchange.answer(). " + entry.kind);
    const out: Answer = { decision: false, code: '', why: '', issuance: null,
                          semantics: '', decidedBy: '', xacmlDecision: '' };
    const fixedFalse = function (code: string, why: string): Answer {
      log.debug("Entering fixedFalse(). " + code);
      log.debug("Leaving fixedFalse().");
      return Object.assign(out, { code: code, why: why,
                                  decidedBy: 'fixed rule' });
    };
    if (entry.kind === 'other-gate') {
      log.debug("Leaving AuthzenTokenExchange.answer(). Another grant.");
      return fixedFalse('STS-AUTHZEN-0103', 'This PDP decides the ' +
        'token-exchange gate only; ' + String(body.action.name) +
        ' names another grant.');
    }
    if (entry.kind === 'unregistered-gate') {
      log.debug("Leaving AuthzenTokenExchange.answer(). Unregistered type.");
      return fixedFalse('STS-AUTHZEN-0104', '"' + entry.tokenType + '" is ' +
        'not a registered token type short name (' +
        Object.keys(TOKEN_TYPES).join(', ') + ').');
    }
    if (entry.kind === 'extra-gate') {
      log.debug("Leaving AuthzenTokenExchange.answer(). A third party.");
      return fixedFalse('STS-AUTHZEN-0107', 'A token exchange has two ' +
        'parties; this gate names a third subject for the same target and ' +
        'token type.');
    }
    if (entry.kind === 'orphan-scope') {
      log.debug("Leaving AuthzenTokenExchange.answer(). No gate.");
      return fixedFalse('STS-AUTHZEN-0105', 'A scope tuple is decided ' +
        'beside its token-exchange gate (issue:<type>:token_exchange on ' +
        'an audience), and this request carries none.');
    }
    if (entry.kind === 'stranger-scope') {
      log.debug("Leaving AuthzenTokenExchange.answer(). Another subject.");
      return fixedFalse('STS-AUTHZEN-0106', 'A scope tuple names the ' +
        'exchange subject (or, for a Txn-Token, the requesting party); ' +
        'this one names somebody else.');
    }
    if (entry.kind === 'subject-scope' || entry.kind === 'party-scope') {
      const scope = String(body.action.name);
      const party = { type: String(body.subject.type),
                      id: String(body.subject.id) };
      const asked = self.scopesOf(plan, party);
      const verdicts = self.scopeVerdicts(plan, party, fixed, asked, false);
      const verdict = verdicts[scope] || { keep: false,
        code: 'STS-AUTHZEN-0111', why: 'not decided' };
      out.decision = !!verdict.keep;
      out.code = verdict.code;
      out.why = verdict.keep ? 'The issuance policy, the client\'s ' +
        'declaration and the roles keep "' + scope + '".'
        : '"' + scope + '" is not granted: ' + verdict.why + '.';
      out.decidedBy = 'issuance policy';
      out.xacmlDecision = verdict.keep ? 'Permit' : 'Deny';
      log.debug("Leaving AuthzenTokenExchange.answer(). A scope.");
      return out;
    }
    const group = entry.group as Group;
    const decided = self.decideGroup(plan, group, fixed, evaluation, trusted);
    const decision = decided.decision;
    out.semantics = String(decision.semantics || '');
    out.decidedBy = String(decision.decidedBy || '');
    const refusal = String(decision.refusal || '');
    const mine = entry.kind === 'party-gate' ? PARTY_REFUSALS
                                             : SUBJECT_REFUSALS;
    const theirs = entry.kind === 'party-gate' ? SUBJECT_REFUSALS
                                               : PARTY_REFUSALS;
    const aboutMe = !decision.allowed && (theirs.indexOf(refusal) < 0 ||
                                          mine.indexOf(refusal) >= 0);
    // A single gate is both gates (they coincide), so every refusal is its.
    const refusesThis = !decision.allowed &&
      (!group.party || aboutMe);
    if (refusesThis && decision.enforced) {
      out.decision = false;
      out.code = entry.kind === 'party-gate' ? 'STS-AUTHZEN-0109'
                                             : 'STS-AUTHZEN-0108';
      out.why = 'The issuance policy refused the exchange (' + refusal +
        '): ' + String(decision.why || '');
      out.xacmlDecision = 'Deny';
    } else if (decided.expired && entry.kind === 'subject-gate') {
      out.decision = false;
      out.code = 'STS-AUTHZEN-0114';
      out.why = 'The subject token has no lifetime left (subject_token.exp), ' +
        'so any token_lifetime would be 0, which the profile reads as a ' +
        'denial.';
      out.xacmlDecision = 'Deny';
    } else {
      out.decision = true;
      out.xacmlDecision = 'Permit';
      if (refusesThis) {
        out.code = 'STS-AUTHZEN-0110';
        out.why = 'Development mode: the local token endpoint would issue ' +
          'this exchange, so this gate answers true; product would refuse ' +
          'it (' + refusal + '): ' + String(decision.why || '');
      } else if (!decision.allowed) {
        out.why = 'The other gate carries the refusal (' + refusal + ').';
      } else {
        out.why = 'The issuance policy allowed ' + out.semantics + ': ' +
          String(decision.authorizedBy || '');
      }
      if (entry.kind === 'subject-gate' && decided.issuance) {
        out.issuance = AuthzenTokenExchange.narrowOnly(decided.issuance,
          fixed);
      }
    }
    log.debug("Leaving AuthzenTokenExchange.answer(). " + out.decision);
    return out;
  }

  /**
   * Every scope a party's scope tuples ask for in this batch, so the
   * per-scope questions are asked once with the whole requested set, as a
   * local exchange asks them.
   *
   * @param plan - the batch's plan
   * @param party - the party
   * @returns the scope values
   */
  scopesOf(plan: Plan, party: { type: string; id: string }): string[] {
    const { log } = this.deps;
    log.debug("Entering AuthzenTokenExchange.scopesOf().");
    const out: string[] = ((plan as Json).scopeNames || {})[
      party.type + '\u0000' + party.id] || [];
    log.debug("Leaving AuthzenTokenExchange.scopesOf(). " + out.length);
    return out.slice(0);
  }

  /**
   * Notes the scope tuples' values on the plan, by party, once the bodies
   * are known.
   *
   * @param plan - the plan
   * @param bodies - the items, defaults merged
   */
  static noteScopes(plan: Plan, bodies: unknown[]): void {
    log.debug("Entering AuthzenTokenExchange.noteScopes().");
    const names: Json = {};
    plan.entries.forEach(function (entry: Entry, i: number) {
      if (entry.kind !== 'subject-scope' && entry.kind !== 'party-scope') {
        return;
      }
      const body: Json = bodies[i];
      const key = String(body.subject.type) + '\u0000' +
        String(body.subject.id);
      const scope = String((body.action || {}).name || '');
      names[key] = names[key] || [];
      if (scope && names[key].indexOf(scope) < 0) {
        names[key].push(scope);
      }
    });
    (plan as Json).scopeNames = names;
    log.debug("Leaving AuthzenTokenExchange.noteScopes().");
  }

  /**
   * THE NO-BROADENING RULE, held at the last moment: only `token_lifetime`
   * (a positive whole number) and `granted_scope` (a subset of the subject
   * token's scope) may leave, whatever built them — never `sub`, `aud`,
   * `act`, `may_act` or a claim.
   *
   * @param issuance - what was built
   * @param fixed - the fixed context
   * @returns the envelope, or null when nothing survives
   */
  static narrowOnly(issuance: Json, fixed: Fixed): Json {
    log.debug("Entering AuthzenTokenExchange.narrowOnly().");
    const out: Json = {};
    if (Number.isSafeInteger(issuance.token_lifetime) &&
        issuance.token_lifetime > 0) {
      out.token_lifetime = issuance.token_lifetime;
    }
    if (typeof issuance.granted_scope === 'string') {
      const held = String((fixed.subjectToken || {}).scope || '')
        .split(/\s+/).filter(Boolean);
      const granted = issuance.granted_scope.split(/\s+/).filter(Boolean);
      if (granted.every(function (one: string) {
        return held.indexOf(one) >= 0;
      })) {
        out.granted_scope = granted.join(' ');
      } else {
        log.error(errorCodes.tag('STS-AUTHZEN-0115') + 'authzen: a ' +
                  'granted_scope wider than the subject token was built, ' +
                  'and is not sent.');
      }
    }
    log.debug("Leaving AuthzenTokenExchange.narrowOnly().");
    return Object.keys(out).length ? out : null;
  }

  /**
   * The one sentence the audit row adds for a binding tuple: its kind, the
   * token type, and what the exchange question answered. Never a claim or
   * a property value.
   *
   * @param entry - the item's entry
   * @param answer - what `answer()` said
   * @returns the sentence
   */
  static describe(entry: Entry, answer: Answer): string {
    log.debug("Entering AuthzenTokenExchange.describe().");
    const out = 'token exchange binding: ' + entry.kind +
      (entry.tokenType ? ' (' + entry.tokenType + ')' : '') +
      (answer.semantics ? ', semantics ' + answer.semantics : '') +
      (answer.decidedBy ? ', decided by ' + answer.decidedBy : '') +
      (answer.code ? ', ' + answer.code : '') +
      (answer.issuance ? ', shaped ' + Object.keys(answer.issuance).join('+')
                       : '');
    log.debug("Leaving AuthzenTokenExchange.describe().");
    return out;
  }
}

/**
 * The AuthZEN binding for OAuth 2.0 Token Exchange, direction A (#1181).
 * @namespace
 */
export = {
  AuthzenTokenExchange: AuthzenTokenExchange,
  TOKEN_TYPES: TOKEN_TYPES,
  GRANT: GRANT,
  GATE_RESOURCE: GATE_RESOURCE,
  SCOPE_RESOURCE: SCOPE_RESOURCE,
  SUBJECT_TYPES: SUBJECT_TYPES,
  CAPABILITY: CAPABILITY,
  CONTEXT_TYPES: CONTEXT_TYPES,
  FIXED_RULES: FIXED_RULES,
  SUBJECT_REFUSALS: SUBJECT_REFUSALS,
  PARTY_REFUSALS: PARTY_REFUSALS,
  classify: AuthzenTokenExchange.classify,
  readContext: AuthzenTokenExchange.readContext,
  strayContext: AuthzenTokenExchange.strayContext,
  narrowOnly: AuthzenTokenExchange.narrowOnly
};
