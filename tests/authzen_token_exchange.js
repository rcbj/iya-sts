// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/authzen_token_exchange.js
//
// ===========================================================================
// THE AUTHZEN BINDING FOR OAUTH 2.0 TOKEN EXCHANGE, DIRECTION A (#1181), IN
// PROCESS.
//
// `authzen/authzen_exchange.ts` converts the binding's tuples into the
// questions a local RFC 8693 exchange asks. This file holds that, against
// real entries in a throwaway realm, by driving `AuthzenSurface`'s item path
// (`planOf()` and `evaluateOne()`, which the routes call) with a caller
// already admitted — the doors are `tests/authzen_evaluation.js`'s:
//
//   F. THE FIXED RULES: which tuples are the binding's, the context members
//      and their one JSON type, the subject types, and every fixed `false`
//      (another grant, an unregistered type, a third party, a scope with no
//      gate or naming somebody else) — and `docs/authzen.md`'s table is
//      `FIXED_RULES`.
//   C. THE CATALOGUE may add a row (`context.tenant`, whose attribute
//      reaches the exchange question) and may not override one: every
//      member the fixed rules read is refused, and so is a path under one.
//   E. THE SAME DECISION AS A LOCAL EXCHANGE, in both modes: the same
//      question to `delegation_policy.decide()` the token endpoint asks, and
//      the two gates together answering what the local token endpoint would
//      issue — allowed, a refusal of the requesting party, of the subject,
//      of an unregistered target, a may_act naming somebody else (enforced
//      in every mode), and a realm's own issuance policy deciding both.
//   L. THE LOCAL REQUEST IS UNCHANGED: an exchange question without the
//      `authzen` member carries no AuthZEN attribute.
//   N. NARROWING ONLY: `context.issuance` carries `token_lifetime` (never
//      over the subject token's remaining life) and, for a scopeless
//      request, `granted_scope` (a subset of the subject token's), and
//      nothing else; a subject token with no life left is a false gate;
//      `narrowOnly()` drops a value that would broaden.
//   S. SCOPE TUPLES: the exchange stage, the client's declaration and the
//      roles, by mode.
//   J. ID-JAG (two levels) AND TXN-TOKEN (the requesting party's own scope
//      tuples).
//   M. THE METADATA advertises the token issuance capability only while
//      the binding is on; OFF, the tuples are the root policy's again.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
const dir = require('../ldap/ldap_server');
const credentials = require('../common/credentials');
const policy = require('../common/delegation_policy');
const store = require('../xacml/xacml_store');
// Arms `issuance_gate.js`'s decider, the PEP the exchange questions go to.
require('../xacml/xacml_role_pep');
const exchange = require('../authzen/authzen_exchange');
const catalogue = require('../authzen/authzen_catalogue');
const verdicts = require('../xacml/xacml_exchange_verdicts');
const xacmlRequest = require('../xacml/xacml_request');

const log = require('bunyan').createLogger({ name: 'authzen_token_exchange',
  level: process.env.LOG_LEVEL || 'info' });

const BACK = 'https://az-back.example';
const PEER = 'https://az-peer.example';
const ACCESS = 'issue:access_token:token_exchange';

// A realm policy refusing every exchange whose actor is `az-front`, with
// the exchange obligation, and saying nothing about anything else
// (`tests/delegation_policy.js` I's policy, for this file's actor).
const REFUSE_FRONT_POLICY =
  '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" ' +
  'PolicyId="az-refuse-front" Version="1.0" RuleCombiningAlgId="' +
  'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">' +
  '<Target/><Rule RuleId="refuse-az-front" Effect="Deny"><Target><AnyOf>' +
  '<AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:' +
  'string-equal"><AttributeValue DataType="http://www.w3.org/2001/' +
  'XMLSchema#string">exchange-token</AttributeValue><AttributeDesignator ' +
  'AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" ' +
  'Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action" ' +
  'DataType="http://www.w3.org/2001/XMLSchema#string" ' +
  'MustBePresent="false"/></Match><Match MatchId="urn:oasis:names:tc:' +
  'xacml:1.0:function:string-equal"><AttributeValue DataType="http://' +
  'www.w3.org/2001/XMLSchema#string">az-front</AttributeValue>' +
  '<AttributeDesignator AttributeId="urn:oasis:names:tc:xacml:1.0:' +
  'subject:subject-id" Category="urn:oasis:names:tc:xacml:1.0:' +
  'subject-category:intermediary-subject" DataType="http://www.w3.org/' +
  '2001/XMLSchema#string" MustBePresent="false"/></Match></AllOf>' +
  '</AnyOf></Target><ObligationExpressions><ObligationExpression ' +
  'ObligationId="urn:sts:xacml:obligation:exchange" FulfillOn="Deny">' +
  '<AttributeAssignmentExpression AttributeId="urn:sts:xacml:exchange-' +
  'verdict"><AttributeValue DataType="http://www.w3.org/2001/' +
  'XMLSchema#string">refuse</AttributeValue>' +
  '</AttributeAssignmentExpression><AttributeAssignmentExpression ' +
  'AttributeId="urn:sts:xacml:exchange-refusal"><AttributeValue ' +
  'DataType="http://www.w3.org/2001/XMLSchema#string">policy' +
  '</AttributeValue></AttributeAssignmentExpression>' +
  '<AttributeAssignmentExpression AttributeId="urn:sts:xacml:exchange-' +
  'enforced"><AttributeValue DataType="http://www.w3.org/2001/' +
  'XMLSchema#boolean">true</AttributeValue>' +
  '</AttributeAssignmentExpression></ObligationExpression>' +
  '</ObligationExpressions></Rule></Policy>';

function inMode(m, fn) {
  log.debug("Entering inMode(). " + m);
  config.setOverride('global.mode', m);
  try {
    log.debug("Leaving inMode().");
    return fn();
  } finally {
    config.clearOverride('global.mode');
  }
}

// The surface, with an admitted caller and a recorded audit: the doors are
// tests/authzen_evaluation.js's, and this file is about the item path.
function surfaceOf(recorded) {
  log.debug("Entering surfaceOf().");
  const az = require('../authzen/authzen');
  const deps = az.AuthzenSurface.defaultDeps();
  deps.caller = {
    applicationOf: function () {
      log.debug("Entering applicationOf().");
      log.debug("Leaving applicationOf().");
      return { application: 'az-app' };
    }
  };
  deps.audit = {
    audit: function (row) {
      log.debug("Entering audit().");
      recorded.push(row);
      log.debug("Leaving audit().");
    }
  };
  deps.loadMonitor = function () {
    log.debug("Entering loadMonitor().");
    log.debug("Leaving loadMonitor().");
    return { record: function () { return null; } };
  };
  log.debug("Leaving surfaceOf().");
  return new az.AuthzenSurface(deps);
}

// One request, answered item by item as POST /access/v1/evaluations does:
// the defaults merged, the whole planned, each evaluated in order.
function ask(surface, defaults, items, rows) {
  log.debug("Entering ask().");
  const az = require('../authzen/authzen');
  const bodies = (items && items.length ? items : [{}]).map(function (one) {
    return az.AuthzenSurface.merged(defaults || {}, one);
  });
  const plan = surface.planOf(bodies);
  const out = bodies.map(function (body, i) {
    return surface.evaluateOne(body, { name: 'az-pep' }, rows || [],
                               'az#' + i, 'test', plan, i);
  });
  log.debug("Leaving ask().");
  return out;
}

// The binding's two gates and its context, for an exchange of `subject`'s
// token by `party` toward `target`.
function gates(subject, party, target, context, tokenType) {
  log.debug("Entering gates().");
  const action = { name: 'issue:' + (tokenType || 'access_token') +
                         ':token_exchange' };
  const out = {
    defaults: { resource: { type: 'audience', id: target },
                context: context },
    items: [{ subject: subject, action: action }]
  };
  if (party) {
    out.items.push({ subject: party, action: action });
  }
  log.debug("Leaving gates().");
  return out;
}

function fixtures(t) {
  log.debug("Entering fixtures().");
  ['az-alice', 'az-bob', 'az-carol'].forEach(function (name) {
    dir.createUser(name, { invent: false });
  });
  const app = function (identifier, fields) {
    log.debug("Entering app().");
    log.debug("Leaving app().");
    return applications.createApplication({ identifier: identifier,
      protocols: ['oauth2'],
      fields: Object.assign({ oauthClientId: identifier }, fields || {}) });
  };
  const made = [
    app('az-back', { oauthAudience: [BACK] }),
    app('az-front', { appAllowedToDelegateTo: ['az-back'],
                      oauthAllowedScope: ['read:docs'] }),
    app('az-mid', {}),
    app('az-peer', { oauthAudience: [PEER] }),
    app('az-idp', { appAllowedToDelegateTo: ['az-peer'],
                    oauthAllowedScope: ['files.read'] }),
    app('az-wl', { appAllowedToDelegateTo: ['az-back'],
                   oauthAllowedScope: ['txn:read', 'read:docs'] })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the applications were created',
          JSON.stringify(made.filter(function (one) { return !one.ok; })));
  const bob = credentials.setNotDelegated('az-bob', true);
  t.check(bob.ok, 'precondition: az-bob carries stsNotDelegated',
          JSON.stringify(bob));
  log.debug("Leaving fixtures().");
}

function theFixedRules(t, surface) {
  log.debug("Entering theFixedRules().");
  t.log.info('=== F. the fixed rules ===');
  const kind = function (type, name) {
    log.debug("Entering kind().");
    log.debug("Leaving kind().");
    return exchange.classify({ resource: { type: type, id: 'x' },
                               action: { name: name } });
  };
  t.check(kind('audience', ACCESS).kind === 'gate' &&
          kind('audience', ACCESS).tokenType === 'access_token' &&
          kind('audience', 'issue:id_jag:token_exchange').kind === 'gate' &&
          kind('audience', 'issue:txn_token:token_exchange').kind ===
            'gate' &&
          kind('audience', 'issue:access_token:authorization_code').kind ===
            'other-gate' &&
          kind('audience', 'issue:widget:token_exchange').kind ===
            'unregistered-gate' &&
          kind('protected_resource', 'read:docs').kind === 'scope' &&
          kind('audience', 'read').kind === '' &&
          kind('document', ACCESS).kind === '',
          'F1. a gate is resource.type audience and issue:<type>:' +
          'token_exchange, a scope tuple resource.type protected_resource, ' +
          'and nothing else is the binding\'s');
  t.check(Object.keys(exchange.TOKEN_TYPES).join() ===
          'access_token,refresh_token,id_token,jwt,saml1,saml2,id_jag,' +
          'txn_token' &&
          exchange.TOKEN_TYPES.id_jag ===
            'urn:ietf:params:oauth:token-type:id-jag' &&
          exchange.TOKEN_TYPES.txn_token ===
            'urn:ietf:params:oauth:token-type:txn_token',
          'F2. the registered token types, ID-JAG and Txn-Token among them');
  const docs = fs.readFileSync(path.join(ROOT, 'docs/authzen.md'), 'utf8');
  const missing = exchange.FIXED_RULES.filter(function (one) {
    return docs.indexOf(one.member) < 0;
  }).map(function (one) { return one.member; });
  t.check(exchange.FIXED_RULES.length >= 15 && !missing.length,
          'F3. docs/authzen.md publishes every fixed rule (' +
          exchange.FIXED_RULES.length + ')', missing.join('; '));
  t.check(catalogue.BINDING_CONTEXT.join() ===
          Object.keys(exchange.CONTEXT_TYPES).join(),
          'F4. the catalogue reserves exactly the context members the ' +
          'fixed rules read');
  config.setOverride('authzen.tokenExchange', true);
  try {
    const codeOf = function (results, i) {
      log.debug("Entering codeOf().");
      log.debug("Leaving codeOf().");
      return results[i || 0].code || '';
    };
    let r = ask(surface, { resource: { type: 'audience', id: BACK },
                           context: { client_id: 7 } },
                [{ subject: { type: 'user', id: 'az-alice' },
                   action: { name: ACCESS } }]);
    t.check(r[0].status === 400 && codeOf(r) === 'STS-AUTHZEN-0100',
            'F5. a fixed context member in the wrong JSON type is 400',
            JSON.stringify(r));
    r = ask(surface, { resource: { type: 'audience', id: BACK },
                       context: { subject_token: { aud: 3 } } },
            [{ subject: { type: 'user', id: 'az-alice' },
               action: { name: ACCESS } }]);
    t.check(codeOf(r) === 'STS-AUTHZEN-0100', 'F6. and so is a subject ' +
            'token claim a rule reads', JSON.stringify(r));
    r = ask(surface, { resource: { type: 'audience', id: BACK } },
            [{ subject: { type: 'person', id: 'az-alice' },
               action: { name: ACCESS } }]);
    t.check(r[0].status === 400 && codeOf(r) === 'STS-AUTHZEN-0102',
            'F7. subject.type is user, client or workload',
            JSON.stringify(r));
    r = ask(surface, { resource: { type: 'document', id: 'd1' },
                       context: { may_act: { sub: 'x' } } },
            [{ subject: { type: 'user', id: 'az-alice' },
               action: { name: 'read' } }]);
    t.check(r[0].status === 400 && codeOf(r) === 'STS-AUTHZEN-0101',
            'F8. a binding context member on a tuple that is not the ' +
            'binding\'s is 400', JSON.stringify(r));
    r = ask(surface, { resource: { type: 'audience', id: BACK } },
            [{ subject: { type: 'user', id: 'az-alice' },
               action: { name: 'issue:access_token:authorization_code' } },
             { subject: { type: 'user', id: 'az-alice' },
               action: { name: 'issue:widget:token_exchange' } }]);
    t.check(r[0].decision === false && codeOf(r, 0) === 'STS-AUTHZEN-0103' &&
            r[1].decision === false && codeOf(r, 1) === 'STS-AUTHZEN-0104' &&
            r[0].status === 200, 'F9. another grant, and an unregistered ' +
            'token type, are each a decision: false', JSON.stringify(r));
    r = ask(surface, {},
            [{ subject: { type: 'user', id: 'az-alice' },
               action: { name: 'read:docs' },
               resource: { type: 'protected_resource', id: BACK } }]);
    t.check(r[0].decision === false && codeOf(r) === 'STS-AUTHZEN-0105',
            'F10. a scope tuple with no gate beside it is false',
            JSON.stringify(r));
    const g = gates({ type: 'user', id: 'az-alice' },
                    { type: 'client', id: 'az-front' }, BACK,
                    { client_id: 'az-front',
                      subject_token: { aud: 'az-front' } });
    g.items.push({ subject: { type: 'client', id: 'az-mid' },
                   action: { name: ACCESS } });
    g.items.push({ subject: { type: 'user', id: 'az-carol' },
                   action: { name: 'read:docs' },
                   resource: { type: 'protected_resource', id: BACK } });
    r = ask(surface, g.defaults, g.items);
    t.check(r[2].decision === false && codeOf(r, 2) === 'STS-AUTHZEN-0107' &&
            r[3].decision === false && codeOf(r, 3) === 'STS-AUTHZEN-0106',
            'F11. a third party for one target is false, and so is a scope ' +
            'tuple naming somebody other than the exchange subject',
            JSON.stringify(r));
  } finally {
    config.clearOverride('authzen.tokenExchange');
  }
  log.debug("Leaving theFixedRules().");
}

function theCatalogue(t) {
  log.debug("Entering theCatalogue().");
  t.log.info('=== C. the catalogue adds and never overrides ===');
  const refused = catalogue.BINDING_CONTEXT.filter(function (member) {
    return catalogue.parse({ object: 'context', property: member,
                             attributeId: 'urn:example:' + member })
      .code !== 'STS-AUTHZEN-0011';
  });
  t.check(!refused.length, 'C1. a row naming any member the fixed rules ' +
          'read is refused (STS-AUTHZEN-0011)', refused.join(', '));
  t.equal(catalogue.parse({ object: 'context',
                            property: 'subject_token.scope',
                            attributeId: 'urn:example:scope' }).code,
          'STS-AUTHZEN-0011', 'C2. and so is a path under one');
  const tenant = catalogue.parse({ object: 'context', property: 'tenant',
                                   attributeId: 'urn:example:tenant' });
  t.check(!!tenant.row, 'C3. a row of the realm\'s own is accepted',
          JSON.stringify(tenant));
  const read = exchange.readContext({ context: { tenant: 'acme',
    client_id: 'az-front' } });
  t.check(read.fixed && read.fixed.clientId === 'az-front' &&
          JSON.stringify(read.rest.context) === '{"tenant":"acme"}',
          'C4. the fixed members are read by their rules and the rest is ' +
          'left for the catalogue', JSON.stringify(read));
  log.debug("Leaving theCatalogue().");
  return tenant.row;
}

// One case of E: the local question and the AuthZEN batch for the same
// exchange, and what each answered.
function bothWays(surface, asked, rows) {
  log.debug("Entering bothWays().");
  const local = policy.decide({
    protocol: 'OAuth 2.0', requested: '', targetKind: 'audience',
    actor: asked.actor, subject: asked.subject,
    source: asked.source, targets: [asked.target],
    mayActPresent: !!asked.mayAct,
    mayActNamesActor: !!asked.mayAct &&
      policy.mayActNames(asked.mayAct, { sub: asked.actor, iss: '',
        aliases: ['urn:sts:client:' + asked.actor] })
  });
  const context = { client_id: asked.actor,
                    subject_token: { aud: asked.source } };
  if (asked.mayAct) {
    context.may_act = asked.mayAct;
  }
  const g = gates({ type: 'user', id: asked.subject },
                  { type: 'client', id: asked.actor }, asked.target,
                  context);
  const answered = ask(surface, g.defaults, g.items, rows);
  log.debug("Leaving bothWays().");
  return { local: local, answered: answered,
           issued: answered[0].decision && answered[1].decision };
}

function theSameDecision(t, surface, tenantRow) {
  log.debug("Entering theSameDecision().");
  config.setOverride('authzen.tokenExchange', true);
  try {
    ['development', 'product'].forEach(function (m) {
      t.log.info('=== E. the same decision as a local exchange, in ' + m +
                 ' ===');
      inMode(m, function () {
        const cases = [
          { what: 'allowed', actor: 'az-front', subject: 'az-alice',
            source: ['az-front'], target: BACK, refusal: '' },
          { what: 'a requesting party with no relationship',
            actor: 'az-mid', subject: 'az-alice', source: ['az-front'],
            target: BACK, refusal: 'target', gate: 1 },
          { what: 'a subject never delegated', actor: 'az-front',
            subject: 'az-bob', source: ['az-front'], target: BACK,
            refusal: 'subject', gate: 'both' },
          { what: 'an unregistered target', actor: 'az-front',
            subject: 'az-alice', source: ['az-front'],
            target: 'https://nowhere.example', gate: 0 },
          { what: 'a may_act naming somebody else', actor: 'az-front',
            subject: 'az-alice', source: ['az-front'], target: BACK,
            mayAct: { sub: 'az-carol' }, refusal: 'may-act', gate: 1 }
        ];
        cases.forEach(function (c, i) {
          const r = bothWays(surface, c);
          const local = r.local;
          const wouldIssue = local.allowed || !local.enforced;
          const sameRefusal = !c.refusal || local.refusal === c.refusal;
          const gateOk = local.allowed ||
            (c.gate === 0 ? !r.answered[0].decision || !local.enforced
              : c.gate === 1 ? !r.answered[1].decision || !local.enforced
                : (!r.answered[0].decision && !r.answered[1].decision) ||
                  !local.enforced);
          t.check(r.issued === wouldIssue && sameRefusal && gateOk,
                  'E' + (i + 1) + '. ' + m + ': ' + c.what + ' — the two ' +
                  'gates answer what the local token endpoint would issue' +
                  (local.allowed ? '' : ' (' + local.refusal +
                   (local.enforced ? ', enforced' : ', not enforced') + ')'),
                  JSON.stringify({ local: local, answered: r.answered }));
        });
        if (m === 'product') {
          const r = bothWays(surface, cases[4]);
          t.check(!r.local.allowed && r.local.enforced &&
                  r.answered[1].decision === false &&
                  r.answered[1].code === 'STS-AUTHZEN-0109',
                  'E6. a may_act mismatch refuses the requesting party ' +
                  'gate (STS-AUTHZEN-0109)', JSON.stringify(r));
        } else {
          const r = bothWays(surface, cases[4]);
          t.check(!r.local.allowed && r.local.enforced &&
                  r.answered[1].decision === false,
                  'E6. a may_act mismatch is enforced in development too, ' +
                  'there as at the token endpoint', JSON.stringify(r));
          const dev = bothWays(surface, cases[1]);
          t.check(dev.answered[1].decision === true &&
                  dev.answered[1].code === 'STS-AUTHZEN-0110',
                  'E7. development answers true where the token endpoint ' +
                  'would issue, and says product would not ' +
                  '(STS-AUTHZEN-0110)', JSON.stringify(dev));
        }
      });
    });
    t.log.info('=== E. one policy decides both ===');
    const written = store.write('az-refuse-front', REFUSE_FRONT_POLICY,
                                { enabled: true });
    t.check(written && written.ok, 'precondition: the policy was written',
            JSON.stringify(written));
    config.setOverride('xacml.issuancePolicy', 'az-refuse-front');
    try {
      inMode('product', function () {
        const r = bothWays(surface, { actor: 'az-front', subject: 'az-alice',
                                      source: ['az-front'], target: BACK });
        t.check(!r.local.allowed && r.local.refusal === 'policy' &&
                r.local.decidedBy === 'policy' &&
                r.answered[0].decision === false &&
                r.answered[1].decision === false,
                'E8. the realm\'s own issuance policy refuses the local ' +
                'exchange and the one asked over AuthZEN alike (policy, ' +
                'both gates)', JSON.stringify(r));
      });
    } finally {
      config.clearOverride('xacml.issuancePolicy');
      store.remove('az-refuse-front');
    }
    // THE QUESTION ITSELF: what the binding asks is the token endpoint's
    // question, and the catalogue's own row rides with it.
    const g = gates({ type: 'user', id: 'az-alice' },
                    { type: 'client', id: 'urn:sts:client:az-front' }, BACK,
                    { subject_token: { aud: ['az-front'], azp: 'az-x' },
                      tenant: 'acme', act: { sub: 'a', act: { sub: 'b' } },
                      subject_token_type:
                        'urn:ietf:params:oauth:token-type:access_token' });
    const az = require('../authzen/authzen');
    const bodies = g.items.map(function (one) {
      return az.AuthzenSurface.merged(g.defaults, one);
    });
    const plan = surface.planOf(bodies);
    const read = exchange.readContext(bodies[0]);
    const evaluation = require('../authzen/authzen_map')
      .read(read.rest, [tenantRow]).evaluation;
    const q = surface.deps.exchange.questionFor(plan.groups[0], read.fixed,
      evaluation, { caller: 'az-pep', application: 'az-app' });
    t.check(q.protocol === 'OAuth 2.0' && q.requested === '' &&
            q.actor === 'az-front' && q.subject === 'az-alice' &&
            JSON.stringify(q.source) === '["az-front","","az-x"]' &&
            JSON.stringify(q.targets) === JSON.stringify([BACK]) &&
            q.targetKind === 'audience' && q.authzen.actDepth === 2 &&
            q.authzen.tokenType === 'access_token' &&
            q.authzen.attributes.some(function (one) {
              return one.attributeId === 'urn:example:tenant' &&
                     one.values[0] === 'acme';
            }), 'E9. the question is the token endpoint\'s — protocol, ' +
            'no semantics asked, the actor by client_id, S from aud then ' +
            'client_id then azp, the one target — with the act depth, the ' +
            'token type and the catalogue\'s row beside it',
            JSON.stringify(q));
  } finally {
    config.clearOverride('authzen.tokenExchange');
  }
  log.debug("Leaving theSameDecision().");
}

function theLocalRequest(t) {
  log.debug("Entering theLocalRequest().");
  t.log.info('=== L. the local request is unchanged ===');
  const facts = { subject: { id: 'alice' }, actor: { id: 'front' },
                  source: { id: 'front' }, target: { id: 'back', count: 1 } };
  const ids = function (request) {
    log.debug("Entering ids().");
    const out = [];
    request.categories.forEach(function (c) {
      c.attributes.forEach(function (a) {
        out.push(a.attributeId);
      });
    });
    log.debug("Leaving ids().");
    return out;
  };
  const local = ids(verdicts.requestFor({ facts: facts, mode: 'product',
                                          protocol: 'OAuth 2.0' }));
  const asked = ids(verdicts.requestFor({ facts: Object.assign({}, facts, {
    authzen: { caller: 'pep', tokenType: 'id_jag' } }), mode: 'product',
    protocol: 'OAuth 2.0' }));
  const V = xacmlRequest.VOCABULARY;
  t.check(!local.some(function (id) {
    return id.indexOf('urn:sts:xacml:authzen:') === 0;
  }) && asked.indexOf(V.AUTHZEN_TOKEN_TYPE) >= 0 &&
          asked.indexOf(V.AUTHZEN_CALLER) >= 0 &&
          JSON.stringify(asked.slice(0, local.length)) ===
            JSON.stringify(local),
          'L1. a local exchange question carries no AuthZEN attribute, ' +
          'and one asked over AuthZEN carries the same ones first and its ' +
          'own after', JSON.stringify({ local: local, asked: asked }));
  log.debug("Leaving theLocalRequest().");
}

function theNarrowing(t, surface) {
  log.debug("Entering theNarrowing().");
  t.log.info('=== N. narrowing only ===');
  config.setOverride('authzen.tokenExchange', true);
  try {
    inMode('product', function () {
      const exp = Math.floor(Date.now() / 1000) + 120;
      const g = gates({ type: 'user', id: 'az-alice' },
                      { type: 'client', id: 'az-front' }, BACK,
                      { client_id: 'az-front',
                        subject_token: { aud: 'az-front', exp: exp,
                                         scope: 'read:docs write:docs' } });
      const r = ask(surface, g.defaults, g.items);
      const issuance = (r[0].context || {}).issuance || {};
      t.check(r[0].decision && r[1].decision &&
              issuance.token_lifetime > 0 && issuance.token_lifetime <= 120 &&
              issuance.granted_scope === 'read:docs' &&
              Object.keys(issuance).every(function (key) {
                return ['token_lifetime', 'granted_scope'].indexOf(key) >= 0;
              }) && !(r[1].context && r[1].context.issuance),
              'N1. the subject gate carries token_lifetime (no more than ' +
              'the subject token has left) and, asking no scope, the ' +
              'subject token\'s scope narrowed to what the client ' +
              'declares — and nothing else, on that gate alone',
              JSON.stringify(r));
      const old = gates({ type: 'user', id: 'az-alice' },
                        { type: 'client', id: 'az-front' }, BACK,
                        { client_id: 'az-front',
                          subject_token: { aud: 'az-front',
                            exp: Math.floor(Date.now() / 1000) - 5 } });
      const expired = ask(surface, old.defaults, old.items);
      t.check(expired[0].decision === false &&
              expired[0].code === 'STS-AUTHZEN-0114',
              'N2. a subject token with no life left is a false subject ' +
              'gate: token_lifetime 0 would be a denial anyway',
              JSON.stringify(expired));
      const shaped = exchange.narrowOnly({ token_lifetime: 30,
        granted_scope: 'read:docs admin', sub: 'mallory', aud: 'x',
        act: { sub: 'y' }, may_act: { sub: 'z' }, claims: { a: 1 } },
        { subjectToken: { scope: 'read:docs' } });
      t.check(JSON.stringify(shaped) === '{"token_lifetime":30}',
              'N3. a granted_scope wider than the subject token is not ' +
              'sent, and sub, aud, act, may_act and claims never are',
              JSON.stringify(shaped));
    });
  } finally {
    config.clearOverride('authzen.tokenExchange');
  }
  log.debug("Leaving theNarrowing().");
}

function theScopes(t, surface) {
  log.debug("Entering theScopes().");
  config.setOverride('authzen.tokenExchange', true);
  try {
    ['development', 'product'].forEach(function (m) {
      t.log.info('=== S. scope tuples, in ' + m + ' ===');
      inMode(m, function () {
        const g = gates({ type: 'user', id: 'az-alice' },
                        { type: 'client', id: 'az-front' }, BACK,
                        { client_id: 'az-front',
                          subject_token: { aud: 'az-front',
                            scope: 'read:docs write:docs' } });
        ['read:docs', 'write:docs', 'admin:all'].forEach(function (scope) {
          g.items.push({ subject: { type: 'user', id: 'az-alice' },
                         action: { name: scope },
                         resource: { type: 'protected_resource',
                                     id: BACK } });
        });
        const r = ask(surface, g.defaults, g.items);
        const product = m === 'product';
        t.check(r[0].decision && r[1].decision && r[2].decision === true &&
                !(r[0].context && r[0].context.issuance &&
                  r[0].context.issuance.granted_scope !== undefined),
                'S1. ' + m + ': a scope the subject token carries and the ' +
                'client declares is true, and with scope tuples there is no ' +
                'granted_scope', JSON.stringify(r));
        t.check(product ? (r[3].decision === false &&
                           r[3].code === 'STS-AUTHZEN-0112')
                        : r[3].decision === true,
                'S2. ' + m + ': a scope the client does not declare is ' +
                (product ? 'false (STS-AUTHZEN-0112)'
                         : 'true, as development issues it'),
                JSON.stringify(r[3]));
        t.check(product ? (r[4].decision === false &&
                           r[4].code === 'STS-AUTHZEN-0111')
                        : true,
                'S3. ' + m + ': a scope wider than the subject token\'s ' +
                (product ? 'is refused at the exchange stage ' +
                           '(STS-AUTHZEN-0111)'
                         : 'is the policy\'s to refuse in product only'),
                JSON.stringify(r[4]));
      });
    });
  } finally {
    config.clearOverride('authzen.tokenExchange');
  }
  log.debug("Leaving theScopes().");
}

function theTokenTypes(t, surface) {
  log.debug("Entering theTokenTypes().");
  t.log.info('=== J. ID-JAG and Txn-Token ===');
  config.setOverride('authzen.tokenExchange', true);
  try {
    inMode('product', function () {
      // ID-JAG: the gates name the resource authorization server (level
      // 1), the scope tuples the resource behind it (level 2).
      const jag = gates({ type: 'user', id: 'az-alice' },
                        { type: 'client', id: 'az-idp' }, PEER,
                        { client_id: 'az-idp',
                          subject_token_type:
                            'urn:ietf:params:oauth:token-type:id_token',
                          subject_token: { aud: 'az-idp',
                                           scope: 'files.read' } },
                        'id_jag');
      jag.items.push({ subject: { type: 'user', id: 'az-alice' },
                       action: { name: 'files.read' },
                       resource: { type: 'protected_resource',
                                   id: 'https://api.app.example' } });
      let r = ask(surface, jag.defaults, jag.items);
      t.check(r[0].decision && r[1].decision && r[2].decision,
              'J1. an ID-JAG: both level-1 gates on the peer authorization ' +
              'server, decided by the delegation the identity provider\'s ' +
              'client holds to it, and a level-2 scope tuple',
              JSON.stringify(r));
      const mid = gates({ type: 'user', id: 'az-alice' },
                        { type: 'client', id: 'az-mid' }, PEER,
                        { client_id: 'az-mid',
                          subject_token: { aud: 'az-mid' } }, 'id_jag');
      r = ask(surface, mid.defaults, mid.items);
      t.check(r[0].decision && r[1].decision === false,
              'J2. an ID-JAG for a client with no delegation into that ' +
              'trust domain refuses its gate', JSON.stringify(r));
      // TXN-TOKEN: the requesting workload's scope tuples are its own.
      const txn = gates({ type: 'user', id: 'az-alice' },
                        { type: 'workload', id: 'az-wl' }, BACK,
                        { subject_token: { aud: 'az-wl',
                                           scope: 'read:docs' },
                          subject_token_type:
                            'urn:ietf:params:oauth:token-type:jwt' },
                        'txn_token');
      txn.items.push({ subject: { type: 'workload', id: 'az-wl' },
                       action: { name: 'txn:read' },
                       resource: { type: 'protected_resource', id: BACK } });
      txn.items.push({ subject: { type: 'workload', id: 'az-wl' },
                       action: { name: 'txn:write' },
                       resource: { type: 'protected_resource', id: BACK } });
      r = ask(surface, txn.defaults, txn.items);
      t.check(r[0].decision && r[1].decision && r[2].decision === true &&
              r[3].decision === false && r[3].code === 'STS-AUTHZEN-0112',
              'J3. a Txn-Token: the workload\'s own scope tuples are decided ' +
              'as the workload\'s — one it declares true, one it does not ' +
              'false', JSON.stringify(r));
      const plain = gates({ type: 'user', id: 'az-alice' },
                          { type: 'client', id: 'az-front' }, BACK,
                          { client_id: 'az-front',
                            subject_token: { aud: 'az-front' } });
      plain.items.push({ subject: { type: 'client', id: 'az-front' },
                         action: { name: 'read:docs' },
                         resource: { type: 'protected_resource',
                                     id: BACK } });
      r = ask(surface, plain.defaults, plain.items);
      t.check(r[2].decision === false && r[2].code === 'STS-AUTHZEN-0106',
              'J4. outside a Txn-Token, a scope tuple for the requesting ' +
              'party is false: scope is the subject\'s authority',
              JSON.stringify(r));
    });
  } finally {
    config.clearOverride('authzen.tokenExchange');
  }
  log.debug("Leaving theTokenTypes().");
}

function theMetadata(t, surface) {
  log.debug("Entering theMetadata().");
  t.log.info('=== M. the metadata, and off ===');
  config.setOverride('authzen.signedMetadata', false);
  try {
    const req = { headers: { host: 'sts.example' }, protocol: 'https',
                  secure: true, originalUrl: '/', url: '/',
                  get: function (name) {
                    log.debug("Entering get().");
                    log.debug("Leaving get().");
                    return name.toLowerCase() === 'host' ? 'sts.example'
                                                         : undefined;
                  } };
    const off = surface.metadata(req);
    config.setOverride('authzen.tokenExchange', true);
    let on;
    try {
      on = surface.metadata(req);
    } finally {
      config.clearOverride('authzen.tokenExchange');
    }
    t.check(off.capabilities === undefined &&
            JSON.stringify(on.capabilities) ===
              '["urn:openid:authzen:capability:token-issuance"]',
            'M1. the token issuance capability is advertised only while ' +
            'the binding answers', JSON.stringify({ off: off, on: on }));
  } finally {
    config.clearOverride('authzen.signedMetadata');
  }
  const plan = surface.planOf([{ subject: { type: 'user', id: 'a' },
                                 action: { name: ACCESS },
                                 resource: { type: 'audience', id: BACK } }]);
  t.check(plan.entries[0].kind === '',
          'M2. off, a gate tuple is the root policy\'s, as before the ' +
          'binding', JSON.stringify(plan.entries));
  log.debug("Leaving theMetadata().");
}

// EVERYTHING IN A THROWAWAY REALM, removed afterwards, as
// tests/delegation_policy.js does and for its reason.
function run(t) {
  log.debug("Entering run().");
  const id = 'aztx-' + process.pid;
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  try {
    realms.run(made.realm, function () {
      fixtures(t);
      const recorded = [];
      const surface = surfaceOf(recorded);
      theFixedRules(t, surface);
      const tenantRow = theCatalogue(t);
      theSameDecision(t, surface, tenantRow);
      theLocalRequest(t);
      theNarrowing(t, surface);
      theScopes(t, surface);
      theTokenTypes(t, surface);
      theMetadata(t, surface);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'authzen_token_exchange',
  describe: 'the AuthZEN OAuth token-exchange binding, direction A (#1181)',
  run: run
};
