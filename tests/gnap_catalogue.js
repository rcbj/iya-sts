// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_catalogue.js
//
// ===========================================================================
// ONE ACCESS-TYPE CATALOGUE FOR RFC 9396 AND GNAP, AND EACH GNAP ACCESS
// RIGHT A POLICY QUESTION (#432 phases 4 and 3).
//
//   A. THE GRAMMAR: every catalogue member a definition may carry, and what
//      `applications.authorizationDetailsTypeOf()` refuses — the limits
//      schema SUBSET, a reserved introspection claim, derivableFrom naming
//      itself, consentActions outside actions, bounds.
//   B. THE CONSOLE'S DOOR (`set-access-type`, `remove-access-type`): declare,
//      replace, refuse (STS-REG-0294), remove, remove what is not there
//      (STS-REG-0295) — the actions `/admin-api/applications/{action}` takes.
//   C. RFC 9396 READS IT: an action outside the type's list (0456), limits on
//      a type with no limits schema (STS-OAUTH-0876) and limits its schema
//      refuses (0877), maxLifetimeFor(), bearerRefusedBy(), and the
//      introspection view filtered per resource server with its claims.
//   D. GNAP READS IT: conformanceRefusal() (0812, 0813, 0814).
//   E. EACH BUILT-IN RULE THROUGH THE POLICY, in both modes: an
//      uncatalogued type (STS-GNAP-0810 in product only, and the mode
//      predicate agreeing), the bearer flag (0111, realm and client), a
//      type refusing bearer (0811), a protected scope (0719),
//      gnapAllowedAccess and an unknown reference (0112), the type's
//      maximum lifetime as a token cap at the issue stage, and a refusal at
//      the issue stage DROPPING the right.
//   F. NARROWING, through a REALM'S OWN POLICY (`xacml.issuancePolicy`):
//      values taken off, an absent dimension narrowed against the
//      catalogue's list, narrowed to nothing (STS-GNAP-0817), and a
//      reference that cannot be narrowed.
//   G. derivableBeyond(): a type declared derivable from a type the
//      original carries, and nothing else.
//   H. GNAP INTROSPECTION'S VIEW: another resource server's rights withheld,
//      this one's claims added.
//
// IN PROCESS, in a throwaway realm, with the issuance PEP armed so a realm
// policy is honoured. The over-HTTP half is `tests/vendored/
// sts_gnap_catalogue.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
const dir = require('../ldap/ldap_server');
const errorCodes = require('../common/error_codes');
const mode = require('../common/mode');
const store = require('../xacml/xacml_store');
// Arms `issuance_gate.js`'s decider: the realm's policy is asked first.
require('../xacml/xacml_role_pep');
const catalogue = require('../oauth-oidc/authorization_details');
const rights = require('../gnap/gnap_rights');
const gnapDelegation = require('../gnap/gnap_delegation');

const log = require('bunyan').createLogger({ name: 'gnap_catalogue',
  level: process.env.LOG_LEVEL || 'info' });

const RS = 'https://pay.gc.test/api';
const OTHER = 'https://other.gc.test/api';

// A realm policy that NARROWS (section F), built from the template so the
// built-in rules are kept beside the two the test puts in front of them:
// gc-pay loses the action `refund`, gc-refund the action `x`.
function narrowingPolicy() {
  log.debug("Entering narrowingPolicy().");
  const templates = require('../xacml/xacml_templates');
  const model = require('../xacml/xacml_model');
  const B = templates.PolicyBuilders;
  const GR = templates.GNAP_RIGHT_ATTRIBUTE;
  const STRING = 'http://www.w3.org/2001/XMLSchema#string';
  const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
  const built = templates.build('role-issuance', {}, { name: 'gc-narrow' });
  const assign = function (id, v) {
    log.debug("Entering assign().");
    log.debug("Leaving assign().");
    return { attributeId: id, category: null, issuer: null,
             expression: B.value(STRING, v) };
  };
  const rule = function (id, type, assignments) {
    log.debug("Entering rule().");
    log.debug("Leaving rule().");
    return { id: 'gc-narrow:rule:' + id, effect: model.EFFECT.PERMIT,
             description: 'a narrowing for the test',
             target: B.targetOf([[
               B.match(F1 + 'string-equal', B.value(STRING, GR.ACTION),
                       B.designator(model.CATEGORY.ACTION,
                                    model.ATTRIBUTE.ACTION_ID, STRING))], [
               B.match(F1 + 'string-equal', B.value(STRING, type),
                       B.designator(model.CATEGORY.RESOURCE,
                                    model.ATTRIBUTE.RESOURCE_ID, STRING))]]),
             condition: null,
             obligations: [{ id: GR.OBLIGATION, on: model.EFFECT.PERMIT,
                             assignments: assignments }],
             advice: [] };
  };
  log.debug("Leaving narrowingPolicy().");
  return { built: built, rule: rule, assign: assign, GR: GR };
}

function run(t) {
  log.debug("Entering run().");
  const id = 'gc-' + process.pid;
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
      inRealm(t);
    });
  } finally {
    config.clearOverride('global.mode');
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

const PAY = {
  type: 'gc-pay', description: 'a payment',
  actions: ['initiate', 'status', 'refund'],
  datatypes: ['card', 'transfer'],
  required: ['actions'],
  bearer: false, maxLifetimeS: 120,
  introspectionClaims: ['email'],
  limits: { type: 'object',
            properties: { amount: { type: 'number', minimum: 0,
                                    maximum: 1000 },
                          currency: { type: 'string', pattern: '^[A-Z]{3}$' } },
            required: ['amount'], additionalProperties: false },
  schema: { type: 'object',
            properties: { creditor: { type: 'string' } } }
};

function inRealm(t) {
  log.debug("Entering inRealm().");
  grammar(t);
  const fx = fixtures(t);
  consoleDoor(t);
  rar(t);
  gnapConformance(t);
  builtInRules(t, fx);
  narrowing(t, fx);
  derivation(t);
  introspection(t);
  log.debug("Leaving inRealm().");
}

// ---------------------------------------------------------------- A
function grammar(t) {
  log.debug("Entering grammar().");
  t.log.info('=== A. the grammar ===');
  const of = applications.authorizationDetailsTypeOf;
  const d = of(JSON.stringify(PAY));
  t.check(!d.problem && d.bearer === false && d.maxLifetimeS === 120 &&
          d.actions.length === 3 && !!d.validateLimits &&
          d.introspectionClaims[0] === 'email',
          'A1. every catalogue member reads', JSON.stringify(d.problem));
  const bad = [
    [{ type: 'x', limits: { $ref: 'https://evil.example/s' } }, /\$ref/,
     'A2. a limits schema may not $ref anything'],
    [{ type: 'x', limits: { anyOf: [{ type: 'string' }] } }, /anyOf/,
     'A3. nor use a combinator'],
    [{ type: 'x', limits: { type: 'object', additionalProperties:
                            { type: 'string' } } },
     /additionalProperties/, 'A4. additionalProperties is true or false'],
    [{ type: 'x', introspectionClaims: ['sub'] }, /already carries/,
     'A5. an introspection claim may not be a reserved member'],
    [{ type: 'x', derivableFrom: ['x'] }, /itself/,
     'A6. derivableFrom may not name the type itself'],
    [{ type: 'x', actions: ['read'], consentActions: ['delete'] },
     /consentActions/, 'A7. consentActions must be among actions'],
    [{ type: 'x', maxLifetimeS: 0 }, /maxLifetimeS/,
     'A8. maxLifetimeS is at least a second'],
    [{ type: 'x', bearer: 'no' }, /bearer/, 'A9. bearer is a boolean'],
    [{ type: 'x', interaction: 'sometimes' }, /interaction/,
     'A10. interaction is always, default or never'],
    [{ type: 'x', actions: ['a', 'a'] }, /twice/,
     'A11. a list names a value once'],
    [{ type: 'x', required: ['type'] }, /required/,
     'A12. required need not name type']
  ];
  bad.forEach(function (one) {
    const r = of(JSON.stringify(one[0]));
    t.check(one[1].test(r.problem), one[2], r.problem);
  });
  log.debug("Leaving grammar().");
}

function fixtures(t) {
  log.debug("Entering fixtures().");
  dir.createUser('gc-alice', { invent: false,
                               attributes: { mail: 'alice@gc.test' } });
  const app = function (identifier, kind, protocols, fields) {
    log.debug("Entering app().");
    log.debug("Leaving app().");
    return applications.createApplication({ identifier: identifier,
      kind: kind, protocols: protocols, fields: fields || {} });
  };
  const made = [
    app('gc-pay-rs', 'gnap-resource-server', ['gnap', 'oauth2'],
        { gnapResourceServerUri: RS, oauthClientId: 'gc-pay-rs',
          oauthAuthorizationDetailsType: [JSON.stringify(PAY),
            JSON.stringify({ type: 'gc-refund',
                             derivableFrom: ['gc-pay'] })] }),
    app('gc-other-rs', 'gnap-resource-server', ['gnap', 'oauth2'],
        { gnapResourceServerUri: OTHER, oauthClientId: 'gc-other-rs',
          oauthAuthorizationDetailsType: [JSON.stringify({
            type: 'gc-other', introspectionClaims: ['email'] })] }),
    app('gc-client', 'gnap-client', ['gnap'], {}),
    app('gc-limited', 'gnap-client', ['gnap'],
        { gnapAllowedAccess: ['gc-pay'] }),
    app('gc-nobearer', 'gnap-client', ['gnap'],
        { gnapBearerTokens: 'FALSE' })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the fixtures were created',
          JSON.stringify(made.filter(function (one) { return !one.ok; })));
  log.debug("Leaving fixtures().");
  return { client: applications.get('gc-client'),
           limited: applications.get('gc-limited'),
           nobearer: applications.get('gc-nobearer') };
}

// ---------------------------------------------------------------- B
function consoleDoor(t) {
  log.debug("Entering consoleDoor().");
  t.log.info('=== B. the console\'s door ===');
  const adminActions = require('../admin-core/admin_actions');
  let r = adminActions.applicationsAction({ action: 'set-access-type',
    application: 'gc-other-rs', type: 'gc-door',
    actions: 'read\nwrite', bearer: 'false', maxLifetimeS: '60',
    introspectionClaims: ['email'],
    limits: '{"type":"object","properties":{"count":{"type":"integer"}}}' });
  let entry = catalogue.typeOf('gc-door');
  t.check(r.ok && entry && entry.identifier === 'gc-other-rs' &&
          entry.actions.join() === 'read,write' && entry.bearer === false &&
          entry.maxLifetimeS === 60 && !!entry.validateLimits,
          'B1. set-access-type declares a type from named fields',
          JSON.stringify(r));
  r = adminActions.applicationsAction({ action: 'set-access-type',
    application: 'gc-other-rs', type: 'gc-door', actions: ['read'] });
  entry = catalogue.typeOf('gc-door');
  t.check(r.ok && entry && entry.actions.join() === 'read' &&
          entry.bearer === null &&
          [].concat(applications.get('gc-other-rs').fields
            .oauthAuthorizationDetailsType).length === 2,
          'B2. a second save REPLACES the definition of that type',
          JSON.stringify(r));
  r = adminActions.applicationsAction({ action: 'set-access-type',
    application: 'gc-other-rs', type: 'gc-door',
    limits: '{"oneOf":[]}' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-REG-0294' &&
          catalogue.typeOf('gc-door').actions.join() === 'read',
          'B3. a definition that does not read is refused (STS-REG-0294) ' +
          'and the one declared stays', JSON.stringify(r));
  r = adminActions.applicationsAction({ action: 'remove-access-type',
    application: 'gc-other-rs', type: 'gc-door' });
  t.check(r.ok && !catalogue.typeOf('gc-door'),
          'B4. remove-access-type takes it off', JSON.stringify(r));
  r = adminActions.applicationsAction({ action: 'remove-access-type',
    application: 'gc-other-rs', type: 'gc-door' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-REG-0295',
          'B5. removing a type it does not declare is STS-REG-0295',
          JSON.stringify(r));
  t.check(adminActions.APPLICATION_ACTIONS.indexOf('set-access-type') >= 0 &&
          adminActions.APPLICATION_ACTIONS.indexOf('remove-access-type') >= 0,
          'B6. both are application actions, the list /admin-api reads');
  log.debug("Leaving consoleDoor().");
}

// ---------------------------------------------------------------- C
function rar(t) {
  log.debug("Entering rar().");
  t.log.info('=== C. RFC 9396 reads the catalogue ===');
  const parse = function (details) {
    log.debug("Entering parse().");
    log.debug("Leaving parse().");
    return catalogue.parse(JSON.stringify(details), { clientId: 'gc-client' });
  };
  let r = parse([{ type: 'gc-pay', actions: ['initiate'] }]);
  t.check(r.ok, 'C1. a detail meeting its type is accepted',
          JSON.stringify(r));
  r = parse([{ type: 'gc-pay', actions: ['delete'] }]);
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-OAUTH-0456',
          'C2. an action the type does not list is 0456', r.error);
  r = parse([{ type: 'gc-pay' }]);
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-OAUTH-0456' &&
          /requires/.test(r.error),
          'C3. a required member missing is 0456', r.error);
  r = parse([{ type: 'gc-other', limits: { amount: 1 } }]);
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-OAUTH-0876',
          'C4. limits on a type with no limits schema is STS-OAUTH-0876',
          r.error);
  r = parse([{ type: 'gc-pay', actions: ['initiate'],
               limits: { amount: 5000 } }]);
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-OAUTH-0877',
          'C5. limits its schema refuses are STS-OAUTH-0877', r.error);
  r = parse([{ type: 'gc-pay', actions: ['initiate'],
               limits: { amount: 50, currency: 'EUR' } }]);
  t.check(r.ok, 'C6. limits its schema accepts', JSON.stringify(r));
  r = parse([{ type: 'gc-nobody' }]);
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-OAUTH-0453',
          'C7. an undeclared type is still refused in development (RFC 9396 ' +
          'section 5)', r.error);
  t.check(catalogue.maxLifetimeFor([{ type: 'gc-pay' }, { type: 'gc-other' }])
          === 120 && catalogue.maxLifetimeFor([{ type: 'gc-other' }]) ===
          null, 'C8. maxLifetimeFor() is the shortest a type declares');
  t.check(catalogue.bearerRefusedBy([{ type: 'gc-other' },
                                     { type: 'gc-pay' }]) === 'gc-pay' &&
          catalogue.bearerRefusedBy([{ type: 'gc-other' }]) === '',
          'C9. bearerRefusedBy() names the type declaring bearer: false');
  const both = [{ type: 'gc-pay', actions: ['initiate'] },
                { type: 'gc-other' }];
  const view = catalogue.introspectionView(both, 'gc-pay-rs', 'gc-alice');
  t.check(view.owned && view.rights.length === 1 &&
          view.rights[0].type === 'gc-pay' &&
          view.claims.email === 'alice@gc.test',
          'C10. the owning resource server sees its own type and the ' +
          'claims it declares', JSON.stringify(view));
  const stranger = catalogue.introspectionView(both, 'gc-client',
                                               'gc-alice');
  t.check(!stranger.owned && Object.keys(stranger.claims).length === 0,
          'C11. a caller owning none of the types is not told the claims',
          JSON.stringify(stranger));
  log.debug("Leaving rar().");
}

// ---------------------------------------------------------------- D
function gnapConformance(t) {
  log.debug("Entering gnapConformance().");
  t.log.info('=== D. GNAP reads the catalogue ===');
  const tok = function (access) {
    log.debug("Entering tok().");
    log.debug("Leaving tok().");
    return [{ label: '', access: access }];
  };
  t.check(rights.conformanceRefusal(tok([{ type: 'gc-pay',
    actions: ['status'], locations: [RS] }])) === null,
          'D1. a right meeting its type passes');
  let r = rights.conformanceRefusal(tok([{ type: 'gc-pay',
    actions: ['status'], locations: [OTHER] }]));
  t.check(r && errorCodes.codeOf(r) === 'STS-GNAP-0812' &&
          r.gnapError === 'invalid_request',
          'D2. a location the owner does not answer to is 0812',
          JSON.stringify(r));
  r = rights.conformanceRefusal(tok([{ type: 'gc-other', limits: {} }]));
  t.check(r && errorCodes.codeOf(r) === 'STS-GNAP-0813',
          'D3. limits on a type with none is 0813', JSON.stringify(r));
  r = rights.conformanceRefusal(tok([{ type: 'gc-pay', actions: ['status'],
                                       limits: { amount: -1 } }]));
  t.check(r && errorCodes.codeOf(r) === 'STS-GNAP-0814',
          'D4. limits the schema refuses are 0814', JSON.stringify(r));
  t.check(rights.conformanceRefusal(tok(['a-reference', { type: 'gc-x' }]))
          === null, 'D5. a reference and an uncatalogued type are not ' +
          'judged by a catalogue entry');
  log.debug("Leaving gnapConformance().");
}

// ---------------------------------------------------------------- E
function builtInRules(t, fx) {
  log.debug("Entering builtInRules().");
  t.log.info('=== E. each built-in rule, through the policy ===');
  const judge = function (app, access, opts) {
    log.debug("Entering judge().");
    const o = opts || {};
    log.debug("Leaving judge().");
    return rights.judge([{ label: 'one', bearer: !!o.bearer,
                           access: access }],
                        { app: app, approval: o.approval || 'pending',
                          approver: o.approver || '' },
                        o.stage || 'request');
  };
  const code = function (r) {
    log.debug("Entering code().");
    log.debug("Leaving code().");
    return r && r.ok === false ? errorCodes.codeOf(r) : 'kept';
  };
  const unknownType = [{ type: 'gc-uncatalogued', actions: ['read'] }];
  ['development', 'product'].forEach(function (m) {
    config.setOverride('global.mode', m);
    const r = judge(fx.client, unknownType);
    const refused = m === 'product';
    t.check(code(r) === (refused ? 'STS-GNAP-0810' : 'kept'),
            'E1. ' + m + ': an uncatalogued type is ' +
            (refused ? 'refused (0810)' : 'granted'), code(r));
    t.check(mode.grantsUncataloguedAccess() === !refused,
            'E2. ' + m + ': mode.grantsUncataloguedAccess() agrees with ' +
            'the policy');
  });
  config.clearOverride('global.mode');
  const pay = [{ type: 'gc-pay', actions: ['status'] }];
  let r = judge(fx.client, pay, { bearer: true });
  t.check(code(r) === 'STS-GNAP-0811',
          'E3. a bearer token for a type declaring bearer: false is 0811',
          code(r));
  config.setOverride('gnap.bearerTokens', false);
  r = judge(fx.client, [{ type: 'gc-other' }], { bearer: true });
  t.check(code(r) === 'STS-GNAP-0111' && r.gnapError === 'invalid_flag',
          'E4. gnap.bearerTokens off: a bearer token is 0111 invalid_flag',
          code(r));
  config.clearOverride('gnap.bearerTokens');
  r = judge(fx.nobearer, [{ type: 'gc-other' }], { bearer: true });
  t.check(code(r) === 'STS-GNAP-0111',
          'E5. gnapBearerTokens FALSE on the client: 0111', code(r));
  r = judge(fx.client, ['ssf:read']);
  t.check(code(r) === 'STS-GNAP-0719' && /protected scope/.test(r.why),
          'E6. a protected scope the client does not declare is 0719',
          code(r));
  r = judge(fx.limited, [{ type: 'gc-other' }]);
  t.check(code(r) === 'STS-GNAP-0112',
          'E7. a right gnapAllowedAccess does not list is 0112', code(r));
  t.check(judge(fx.limited, pay).ok,
          'E8. …and one it lists is kept');
  config.setOverride('gnap.unknownAccessReferences', 'refuse');
  r = judge(fx.client, ['gc-not-registered']);
  t.check(code(r) === 'STS-GNAP-0112' && /names nothing/.test(r.why),
          'E9. an unknown reference where the setting refuses is 0112',
          code(r));
  config.clearOverride('gnap.unknownAccessReferences');
  t.check(judge(fx.client, ['gc-not-registered']).ok,
          'E10. …and accepted where it does not');
  r = judge(fx.client, pay, { stage: 'issue', approval: 'interaction',
                              approver: 'gc-alice' });
  t.check(r.ok && r.tokens[0].maxLifetimeS === 120,
          'E11. at the issue stage the type\'s maxLifetimeS caps the token',
          JSON.stringify(r.tokens));
  config.setOverride('global.mode', 'product');
  r = judge(fx.client, pay.concat(unknownType),
            { stage: 'issue', approval: 'skipped' });
  t.check(r.ok && r.tokens[0].access.length === 1 &&
          r.dropped.length === 1 && r.dropped[0].code === 'STS-GNAP-0810',
          'E12. a refusal at the issue stage DROPS the right from its token',
          JSON.stringify(r));
  config.clearOverride('global.mode');
  log.debug("Leaving builtInRules().");
}

// ---------------------------------------------------------------- F
function narrowing(t, fx) {
  log.debug("Entering narrowing().");
  t.log.info('=== F. a realm\'s own policy narrows ===');
  const p = narrowingPolicy();
  t.check(p.built.ok, 'precondition: the template built',
          JSON.stringify(p.built.why));
  const policy = p.built.policy;
  const extra = [
    p.rule('drop-refund', 'gc-pay',
           [p.assign(p.GR.VERDICT, 'narrow'),
            p.assign(p.GR.DROP_ACTION, 'refund')]),
    p.rule('drop-all', 'gc-refund',
           [p.assign(p.GR.VERDICT, 'narrow'),
            p.assign(p.GR.DROP_ACTION, 'x')])
  ];
  policy.rules = extra.concat(policy.rules);
  const xml = require('../xacml/xacml_xml');
  const written = store.write('gc-narrow', xml.writePolicy(policy),
                              { enabled: true });
  t.check(written && written.ok, 'precondition: the realm policy was ' +
          'written', JSON.stringify(written));
  config.setOverride('xacml.issuancePolicy', 'gc-narrow');
  try {
    const judge = function (access) {
      log.debug("Entering judge().");
      log.debug("Leaving judge().");
      return rights.judge([{ label: 'one', access: access }],
                          { app: fx.client, approval: 'pending' }, 'request');
    };
    let r = judge([{ type: 'gc-pay', actions: ['status', 'refund'] }]);
    t.check(r.ok && r.tokens[0].access[0].actions.join() === 'status' &&
            r.narrowed.length === 1,
            'F1. the realm\'s policy takes refund off a listed dimension',
            JSON.stringify(r));
    r = judge([{ type: 'gc-pay', datatypes: ['card'] }]);
    t.check(r.ok && r.tokens[0].access[0].actions.join() ===
            'initiate,status',
            'F2. an ABSENT dimension is narrowed against the catalogue\'s ' +
            'list, never left unrestricted', JSON.stringify(r));
    r = judge([{ type: 'gc-refund' }]);
    t.check(!r.ok && errorCodes.codeOf(r) === 'STS-GNAP-0817',
            'F3. narrowing an unrestricted dimension the catalogue lists ' +
            'nothing for is a refusal (0817)', JSON.stringify(r));
    r = judge([{ type: 'gc-pay', actions: ['refund'] }]);
    t.check(!r.ok && errorCodes.codeOf(r) === 'STS-GNAP-0817',
            'F4. narrowed to nothing is 0817', JSON.stringify(r));
    r = judge([{ type: 'gc-other' }]);
    t.check(r.ok && !r.narrowed.length,
            'F5. a type the realm\'s rules say nothing of is kept by the ' +
            'built-in rules beside them', JSON.stringify(r));
  } finally {
    config.clearOverride('xacml.issuancePolicy');
    store.remove('gc-narrow');
  }
  log.debug("Leaving narrowing().");
}

// ---------------------------------------------------------------- G
function derivation(t) {
  log.debug("Entering derivation().");
  t.log.info('=== G. derivableBeyond() ===');
  t.check(gnapDelegation.derivableBeyond([{ type: 'gc-pay' }],
                                         { type: 'gc-refund' }, {}) === true,
          'G1. a type declared derivable from one the original carries');
  t.check(gnapDelegation.derivableBeyond([{ type: 'gc-other' }],
                                         { type: 'gc-refund' }, {}) === false,
          'G2. …and not from any other type');
  t.check(gnapDelegation.derivableBeyond([{ type: 'gc-pay' }],
                                         { type: 'gc-other' }, {}) === false,
          'G3. a type declaring nothing is not derivable beyond the subset');
  t.check(gnapDelegation.derivableBeyond([{ type: 'gc-pay' }], 'gc-refund',
                                         {}) === false,
          'G4. a reference string never is');
  log.debug("Leaving derivation().");
}

// ---------------------------------------------------------------- H
function introspection(t) {
  log.debug("Entering introspection().");
  t.log.info('=== H. GNAP introspection, per resource server ===');
  const record = { username: 'gc-alice',
                   access: [{ type: 'gc-pay', actions: ['status'] },
                            { type: 'gc-other' }, 'a-reference',
                            { type: 'gc-uncatalogued' }] };
  const mine = rights.introspection(record,
                                    applications.get('gc-pay-rs'));
  t.check(mine.rights.length === 3 &&
          !mine.rights.some(function (one) {
            return one && one.type === 'gc-other';
          }) && mine.claims.email === 'alice@gc.test',
          'H1. another resource server\'s type is withheld; this one\'s ' +
          'claims are added', JSON.stringify(mine));
  const theirs = rights.introspection(record,
                                      applications.get('gc-other-rs'));
  t.check(theirs.rights.length === 3 &&
          theirs.claims.email === 'alice@gc.test' &&
          !theirs.rights.some(function (one) {
            return one && one.type === 'gc-pay';
          }), 'H2. and the other way round', JSON.stringify(theirs));
  const nobody = rights.introspection({ access: record.access },
                                      applications.get('gc-pay-rs'));
  t.check(Object.keys(nobody.claims).length === 0,
          'H3. a token about nobody releases no claims');
  log.debug("Leaving introspection().");
}

module.exports = {
  name: 'gnap_catalogue',
  describe: 'one access-type catalogue for RFC 9396 and GNAP, and each GNAP ' +
            'access right a question to the issuance policy (#432 phases 3 ' +
            'and 4)',
  run: run
};
