// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/fga_map.js
//
// ---------------------------------------------------------------------------
// FINE-GRAINED AUTHORIZATION'S MAPPING, IN PROCESS (#564, phase P2).
//
// `xacml/fga_map.ts` and `xacml/xacml_attribute_rows.ts` are pure, and the
// definition grammar is `common/applications.js`'s, so the whole contract is
// asserted here without a port:
//
//   G. THE GRAMMAR, at the write door (`STS-REG-0112`): a type's `xacml`
//      rows and their defaults; every refusal of a row onto a RESERVED
//      identifier (`urn:sts:xacml:*`, subject-id and its siblings, the
//      current-time attributes, a bare directory name in a subject
//      category); an unknown category, datatype, multiplicity or member; a
//      row or `notForPolicy` entry on `type` or a common field; two rows
//      for one member, one inside another, or onto one attribute; a member
//      both mapped and not for policy. A definition with neither member
//      reads as before.
//   S. ONE IMPLEMENTATION: AuthZEN's catalogue and FGA refuse by the same
//      function and name categories and datatypes from the same tables.
//   C. THE COMMON DATA FIELDS: each built-in row, applied when present and
//      absent when not, with no declaration.
//   V. THE VALUE RULES and the defensive refusals: the row's datatype wins,
//      null, arrays only for a bag, nested objects only through dotted rows,
//      an undeclared member, a `notForPolicy` member left out entirely, and
//      a definition, detail or trusted fact that is not usable.
//   U. COVERAGE: `uncovered()` for no schema, an open schema, a closed one
//      covered and not, a nested object reached by a row, and the keywords
//      that leave a level open.
//   D. THE DIGEST: stable across member order and spacing, a bare name the
//      same as its object, the parsed definition the same as its value, and
//      changed by an edit.
//   R. THE REQUEST: the issue's `document_access` example through `fga()`,
//      and decided by the real engine against an ALFA policy that reads the
//      built-in and declared attributes.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'fga_map',
  level: process.env.LOG_LEVEL || 'info' });

const applications = require('../common/applications');
const fga = require('../xacml/fga_map');
const rowsGrammar = require('../xacml/xacml_attribute_rows');
const catalogue = require('../authzen/authzen_catalogue');
const model = require('../xacml/xacml_model');
const pdp = require('../xacml/xacml_pdp');
const alfa = require('../xacml/xacml_alfa');
const xacmlRequest = require('../xacml/xacml_request');

const V = xacmlRequest.VOCABULARY;
const S = model.CATEGORY.ACCESS_SUBJECT;
const R = model.CATEGORY.RESOURCE;
const A = model.CATEGORY.ACTION;
const E = model.CATEGORY.ENVIRONMENT;

// The issue's example type, declared with a closed schema, one member
// mapped, one nested member mapped and one deliberately not.
function documentAccess(extra) {
  log.debug("Entering documentAccess().");
  const out = Object.assign({
    type: 'document_access',
    description: 'Access to documents',
    actions: ['read', 'update', 'delete'],
    schema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        type: { const: 'document_access' },
        actions: { type: 'array', items: { type: 'string' } },
        identifier: { type: 'string' },
        locations: { type: 'array', items: { type: 'string' } },
        classification: { type: 'string' },
        owner: {
          type: 'object', additionalProperties: false,
          properties: { department: { type: 'string' },
                        country: { type: 'string' } }
        },
        note: { type: 'string' }
      }
    },
    xacml: [
      { path: 'classification', attributeId: 'urn:example:classification' },
      { path: 'owner.department', attributeId: 'urn:example:department' },
      { path: 'owner.country', attributeId: 'urn:example:country' }
    ],
    notForPolicy: ['note']
  }, extra || {});
  log.debug("Leaving documentAccess().");
  return out;
}

// A definition read through the grammar, as every reader reads one.
function read(definition) {
  log.debug("Entering read().");
  log.debug("Leaving read().");
  return applications.authorizationDetailsTypeOf(JSON.stringify(definition));
}

// The write door's answer for a definition: its code, or ''.
function writeCode(definition) {
  log.debug("Entering writeCode().");
  const problem = applications.authorizationDetailsAttributeProblem(
    'oauthAuthorizationDetailsType', JSON.stringify(definition));
  log.debug("Leaving writeCode().");
  return problem ? problem.code : '';
}

// A definition with one row, for the row refusals.
function withRow(row) {
  log.debug("Entering withRow().");
  log.debug("Leaving withRow().");
  return { type: 'probe', xacml: [row] };
}

// The values one attribute of a built request carries, or null.
function valuesOf(built, category, attributeId) {
  log.debug("Entering valuesOf().");
  let out = null;
  built.categories.forEach(function (one) {
    if (one.category !== category) {
      return;
    }
    one.attributes.forEach(function (attribute) {
      if (attribute.attributeId === attributeId) {
        out = (out || []).concat(attribute.values.map(function (value) {
          return value.lexical;
        }));
      }
    });
  });
  log.debug("Leaving valuesOf().");
  return out;
}

// The trusted facts every request below is built with.
function trusted(extra) {
  log.debug("Entering trusted().");
  log.debug("Leaving trusted().");
  return Object.assign({ realm: 'acme', application: 'document-service',
                         stage: 'token', clientId: 'docs-client',
                         subject: { id: 'alice', kind: 'user' } },
                       extra || {});
}

// The code a request was refused with, or ''.
function requestCode(detail, definition, facts) {
  log.debug("Entering requestCode().");
  const built = fga.request(detail, definition, facts || trusted());
  log.debug("Leaving requestCode().");
  return built.refusal ? built.refusal.code : '';
}

function theGrammar(t) {
  log.debug("Entering theGrammar().");
  t.log.info('=== G. the grammar ===');
  const parsed = read(documentAccess());
  t.check(!parsed.problem && parsed.xacml.length === 3 &&
          parsed.xacml[0].category === R &&
          parsed.xacml[0].dataType === model.TYPE.STRING &&
          parsed.xacml[0].multiplicity === 'single' &&
          parsed.notForPolicy.join() === 'note',
          'G1. a row defaults to resource, string and single; notForPolicy ' +
          'is read', JSON.stringify(parsed.problem || parsed.xacml));
  const plain = applications.authorizationDetailsTypeOf(JSON.stringify({
    type: 'payment_initiation', schema: { type: 'object' } }));
  const bare = applications.authorizationDetailsTypeOf('payment_initiation');
  t.check(!plain.problem && plain.xacml.length === 0 &&
          plain.notForPolicy.length === 0 && !bare.problem &&
          bare.type === 'payment_initiation' && bare.xacml.length === 0,
          'G2. a definition with neither member, or a bare name, reads as ' +
          'before');
  t.equal(writeCode(documentAccess()), '', 'G3. the write door takes it');
  const refusals = [
    ['G4. urn:sts:xacml:role (this service\'s namespace)',
     { path: 'a', attributeId: 'urn:sts:xacml:role' }],
    ['G5. the namespace in any case',
     { path: 'a', attributeId: 'URN:STS:XACML:fga:stage' }],
    ['G6. subject-id', { path: 'a', attributeId: model.ATTRIBUTE.SUBJECT_ID,
                         category: 'access-subject' }],
    ['G7. resource-id', { path: 'a',
                          attributeId: model.ATTRIBUTE.RESOURCE_ID }],
    ['G8. action-id', { path: 'a', attributeId: model.ATTRIBUTE.ACTION_ID,
                        category: 'action' }],
    ['G9. current-time', { path: 'a', category: 'environment',
                           attributeId: model.ATTRIBUTE.CURRENT_TIME }],
    ['G10. a bare directory name in a subject category',
     { path: 'a', attributeId: 'employeeType', category: 'access-subject' }],
    ['G11. an unknown category', { path: 'a', attributeId: 'urn:x:a',
                                   category: 'somewhere' }],
    ['G12. an unknown datatype', { path: 'a', attributeId: 'urn:x:a',
                                   dataType: 'decimal' }],
    ['G13. an unknown multiplicity', { path: 'a', attributeId: 'urn:x:a',
                                       multiplicity: 'many' }],
    ['G14. an unknown member', { path: 'a', attributeId: 'urn:x:a',
                                 property: 'a' }],
    ['G15. a row on type', { path: 'type', attributeId: 'urn:x:a' }],
    ['G16. a row on a common field', { path: 'actions',
                                       attributeId: 'urn:x:a' }],
    ['G17. a path that is not one', { path: 'a..b', attributeId: 'urn:x:a' }]
  ];
  refusals.forEach(function (one) {
    t.equal(writeCode(withRow(one[1])), 'STS-REG-0112', one[0] +
            ' is refused at the write');
  });
  t.equal(writeCode(withRow({ path: 'a', attributeId: 'employeeType' })), '',
          'G18. a bare name OUTSIDE a subject category is an identifier ' +
          'like any other');
  const lists = [
    ['G19. two rows for one member', { type: 'p', xacml: [
      { path: 'a', attributeId: 'urn:x:a' },
      { path: 'a', attributeId: 'urn:x:b' }] }],
    ['G20. a row inside another\'s member', { type: 'p', xacml: [
      { path: 'a', attributeId: 'urn:x:a' },
      { path: 'a.b', attributeId: 'urn:x:b' }] }],
    ['G21. two members onto one attribute', { type: 'p', xacml: [
      { path: 'a', attributeId: 'urn:x:a' },
      { path: 'b', attributeId: 'urn:x:a' }] }],
    ['G22. notForPolicy on a common field', { type: 'p',
                                              notForPolicy: ['locations'] }],
    ['G23. a member both mapped and not for policy', { type: 'p',
      xacml: [{ path: 'a.b', attributeId: 'urn:x:a' }],
      notForPolicy: ['a'] }],
    ['G24. notForPolicy that is not an array', { type: 'p',
                                                 notForPolicy: 'note' }],
    ['G25. xacml that is not an array', { type: 'p', xacml: {} }]
  ];
  lists.forEach(function (one) {
    t.equal(writeCode(one[1]), 'STS-REG-0112', one[0] + ' is refused');
  });
  log.debug("Leaving theGrammar().");
}

function oneImplementation(t) {
  log.debug("Entering oneImplementation().");
  t.log.info('=== S. one implementation ===');
  const cases = [['urn:sts:xacml:role', R], [model.ATTRIBUTE.SUBJECT_ID, S],
                 ['employeeType', S], ['urn:example:ok', S]];
  t.check(cases.every(function (one) {
    return catalogue.reservedProblem(one[0], one[1]) ===
           rowsGrammar.reservedProblem(one[0], one[1]);
  }) && catalogue.TYPE_NAMES === rowsGrammar.TYPE_NAMES &&
       catalogue.CATEGORY_NAMES === rowsGrammar.CATEGORY_NAMES,
          'S1. AuthZEN\'s catalogue refuses by the shared function and names ' +
          'from the shared tables');
  const authzenRow = catalogue.parse({ object: 'resource', property: 'a',
                                       attributeId: 'urn:sts:xacml:role' });
  const fgaRow = fga.FgaMap.parseRow({ path: 'a',
                                       attributeId: 'urn:sts:xacml:role' },
                                     'xacml[0]');
  t.check(authzenRow.code === 'STS-AUTHZEN-0011' && !!fgaRow.problem &&
          fgaRow.problem.indexOf(rowsGrammar.reservedProblem(
            'urn:sts:xacml:role', R)) >= 0,
          'S2. the same row is refused by both, each under its own code',
          JSON.stringify([authzenRow, fgaRow]));
  log.debug("Leaving oneImplementation().");
}

function theCommonFields(t) {
  log.debug("Entering theCommonFields().");
  t.log.info('=== C. the common data fields ===');
  const definition = read({ type: 'bare_access' });
  const built = fga.request({
    type: 'bare_access', actions: ['read', 'list'],
    locations: ['https://documents.example.com'], identifier: 'doc-123',
    datatypes: ['pdf'], privileges: ['owner'] }, definition, trusted());
  const q = built.request;
  t.check(!built.refusal &&
          valuesOf(q, A, V.FGA_DETAIL_ACTION).join() === 'read,list' &&
          valuesOf(q, R, V.FGA_DETAIL_LOCATION).join() ===
            'https://documents.example.com' &&
          valuesOf(q, R, V.FGA_DETAIL_IDENTIFIER).join() === 'doc-123' &&
          valuesOf(q, R, V.FGA_DETAIL_DATATYPE).join() === 'pdf' &&
          valuesOf(q, A, V.FGA_DETAIL_PRIVILEGE).join() === 'owner',
          'C1. each common field reaches its built-in row with no ' +
          'declaration', JSON.stringify(built.refusal || q));
  const sparse = fga.request({ type: 'bare_access', actions: ['read'] },
                             definition, trusted()).request;
  t.check(valuesOf(sparse, R, V.FGA_DETAIL_LOCATION) === null &&
          valuesOf(sparse, R, V.FGA_DETAIL_IDENTIFIER) === null &&
          valuesOf(sparse, A, V.FGA_DETAIL_ACTION).join() === 'read',
          'C2. a field the detail does not carry is no attribute at all');
  t.check(fga.COMMON_ROWS.every(function (one) {
    return one.attributeId.indexOf('urn:sts:xacml:fga:detail:') === 0;
  }), 'C3. every built-in identifier is under urn:sts:xacml:fga:detail:');
  log.debug("Leaving theCommonFields().");
}

function theValueRules(t) {
  log.debug("Entering theValueRules().");
  t.log.info('=== V. the value rules ===');
  const definition = read({ type: 'typed', xacml: [
    { path: 'level', attributeId: 'urn:x:level', dataType: 'integer' },
    { path: 'name', attributeId: 'urn:x:name' },
    { path: 'when', attributeId: 'urn:x:when', dataType: 'dateTime' },
    { path: 'tags', attributeId: 'urn:x:tags', multiplicity: 'bag' },
    { path: 'amount.currency', attributeId: 'urn:x:currency' }
  ], notForPolicy: ['memo'] });
  t.equal(definition.problem, '', 'V0. the typed definition reads');
  const code = function (detail) {
    log.debug("Entering code().");
    log.debug("Leaving code().");
    return requestCode(Object.assign({ type: 'typed' }, detail), definition);
  };
  t.equal(code({ level: 2.5 }), 'STS-FGA-0105',
          'V1. an integer row refuses a fraction');
  t.equal(code({ name: 7 }), 'STS-FGA-0105',
          'V2. a string row refuses a number (never quietly a string)');
  t.equal(code({ when: 'yesterday' }), 'STS-FGA-0105',
          'V3. a string outside the datatype\'s lexical space');
  t.equal(code({ name: null }), 'STS-FGA-0104', 'V4. null is refused');
  t.equal(code({ tags: ['a', null] }), 'STS-FGA-0104',
          'V5. a null in a bag is refused');
  t.equal(code({ name: ['a'] }), 'STS-FGA-0106',
          'V6. an array for a single row is refused');
  t.equal(code({ name: { a: 1 } }), 'STS-FGA-0107',
          'V7. an object for a row is refused');
  t.equal(code({ tags: [{ a: 1 }] }), 'STS-FGA-0107',
          'V8. a bag of objects is refused');
  t.equal(code({ amount: { value: '1' } }), 'STS-FGA-0103',
          'V9. a nested member no row names is refused');
  t.equal(code({ stranger: 'x' }), 'STS-FGA-0103',
          'V10. an undeclared member is refused, never an attribute');
  const ok = fga.request({ type: 'typed', level: 3, name: 'n',
    when: '2026-10-29T10:00:00Z', tags: [], amount: { currency: 'EUR' },
    memo: 'private' }, definition, trusted());
  const q = ok.request;
  t.check(!ok.refusal && valuesOf(q, R, 'urn:x:level').join() === '3' &&
          valuesOf(q, R, 'urn:x:currency').join() === 'EUR' &&
          valuesOf(q, R, 'urn:x:tags').length === 0,
          'V11. whole numbers, dotted rows and an empty bag map',
          JSON.stringify(ok.refusal || ok.attributes));
  const memoSeen = JSON.stringify(q).indexOf('private') >= 0;
  const supplied = valuesOf(q, E, V.FGA_SUPPLIED) || [];
  t.check(!memoSeen && supplied.indexOf('memo') < 0 &&
          supplied.indexOf('tags') >= 0 &&
          supplied.indexOf('amount.currency') >= 0 &&
          supplied.indexOf('type') < 0,
          'V12. a notForPolicy member is neither an attribute nor supplied; ' +
          'an empty bag is still supplied', supplied.join());
  t.equal(requestCode({ type: 'typed' }, { type: 'typed', problem: 'bad' }),
          'STS-FGA-0100', 'V13. an unusable definition is refused');
  t.equal(requestCode({ type: 'other' }, definition), 'STS-FGA-0101',
          'V14. a detail of another type is refused');
  t.equal(requestCode('typed', definition), 'STS-FGA-0101',
          'V15. a detail that is not an object is refused');
  t.equal(requestCode({ type: 'typed' }, definition,
                      trusted({ stage: 'whenever' })), 'STS-FGA-0102',
          'V16. a stage the builder does not know is refused');
  t.equal(requestCode({ type: 'typed' }, definition,
                      trusted({ application: '' })), 'STS-FGA-0102',
          'V17. no owning application is refused');
  log.debug("Leaving theValueRules().");
}

function theCoverage(t) {
  log.debug("Entering theCoverage().");
  t.log.info('=== U. coverage ===');
  t.equal(fga.uncovered(read({ type: 'n' })).join(), '*',
          'U1. no schema: uncoverable');
  t.equal(fga.uncovered(read({ type: 'o', schema: { type: 'object',
    properties: { a: {}, actions: {} } } })).join(), '*,a',
          'U2. an open schema: its named members and *');
  t.equal(fga.uncovered(read(documentAccess())).join(), '',
          'U3. the closed example, every member mapped or not for policy');
  const missing = documentAccess({ notForPolicy: [] });
  t.equal(fga.uncovered(read(missing)).join(), 'note',
          'U4. a permitted member neither mapped nor listed is uncovered');
  const half = documentAccess({ xacml: [
    { path: 'classification', attributeId: 'urn:example:classification' },
    { path: 'owner.department', attributeId: 'urn:example:department' }] });
  t.equal(fga.uncovered(read(half)).join(), 'owner.country',
          'U5. a nested object a row reaches into is walked member by member');
  const openOwner = documentAccess();
  openOwner.schema = JSON.parse(JSON.stringify(openOwner.schema));
  delete openOwner.schema.properties.owner.additionalProperties;
  t.equal(fga.uncovered(read(openOwner)).join(), 'owner.*',
          'U6. ... and is uncoverable when it is open');
  const notOwner = documentAccess({ xacml: [
    { path: 'classification', attributeId: 'urn:example:classification' }],
    notForPolicy: ['note', 'owner'] });
  t.equal(fga.uncovered(read(notOwner)).join(), '',
          'U7. a whole object not for policy covers what is under it');
  const pattern = documentAccess();
  pattern.schema = Object.assign({}, pattern.schema,
                                 { patternProperties: { '^x-': {} } });
  t.equal(fga.uncovered(read(pattern)).join(), '*',
          'U8. patternProperties leaves a level open');
  const unevaluated = { type: 'u', schema: { type: 'object',
    unevaluatedProperties: false, properties: { a: {} } },
    notForPolicy: ['a'] };
  t.equal(fga.uncovered(read(unevaluated)).join(), '',
          'U9. unevaluatedProperties false with no applicator closes it');
  const applied = { type: 'u', schema: { type: 'object',
    unevaluatedProperties: false, properties: { a: {} },
    allOf: [{ properties: { b: {} } }] }, notForPolicy: ['a'] };
  t.equal(fga.uncovered(read(applied)).join(), '*',
          'U10. ... but not beside an applicator that could name more');
  log.debug("Leaving theCoverage().");
}

function theDigest(t) {
  log.debug("Entering theDigest().");
  t.log.info('=== D. the digest ===');
  const one = '{"type":"d","actions":["a","b"],"description":"x"}';
  const two = '{ "description": "x",\n  "actions": ["a", "b"], "type": "d" }';
  const digest = fga.digest(one);
  t.check(/^[0-9a-f]{64}$/.test(digest) && digest === fga.digest(two),
          'D1. a SHA-256 in hex, the same across member order and spacing',
          digest);
  t.equal(fga.digest('bare'), fga.digest('{"type":"bare"}'),
          'D2. a bare name is its object');
  t.equal(fga.digest(applications.authorizationDetailsTypeOf(two)), digest,
          'D3. the parsed definition digests as its value does');
  t.check(fga.digest('{"type":"d","actions":["a"],"description":"x"}') !==
          digest, 'D4. an edit changes it');
  log.debug("Leaving theDigest().");
}

// THE POLICY THE REQUEST BELOW IS DECIDED AGAINST: a reader may be granted
// a detail of an internal document at the token endpoint; anything asking
// to delete is refused.
const POLICY = [
  'namespace fga {',
  '    attribute act { category = actionCat',
  '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id"',
  '        type = string }',
  '    attribute detailAction { category = actionCat',
  '        id = "urn:sts:xacml:fga:detail:action" type = string }',
  '    attribute stage { category = environmentCat',
  '        id = "urn:sts:xacml:fga:stage" type = string }',
  '    attribute classification { category = resourceCat',
  '        id = "urn:example:classification" type = string }',
  '    policy documentService {',
  '        id = "urn:test:fga-probe"',
  '        apply firstApplicable',
  '        target clause act == "grant-authorization-detail"',
  '        rule noDelete {',
  '            deny',
  '            target clause detailAction == "delete"',
  '        }',
  '        rule internalAtToken {',
  '            permit',
  '            target clause stage == "token"',
  '            target clause classification == "internal"',
  '        }',
  '    }',
  '}'
].join('\n');

function theRequest(t) {
  log.debug("Entering theRequest().");
  t.log.info('=== R. the request ===');
  const definition = read(documentAccess());
  const detail = { type: 'document_access', actions: ['read', 'update'],
                   identifier: 'document-123',
                   locations: ['https://documents.example.com'],
                   classification: 'internal',
                   owner: { department: 'legal' }, note: 'do not log' };
  const built = fga.request(detail, definition, trusted());
  const q = built.request;
  t.check(!built.refusal &&
          valuesOf(q, A, model.ATTRIBUTE.ACTION_ID).join() ===
            'grant-authorization-detail' &&
          valuesOf(q, R, model.ATTRIBUTE.RESOURCE_ID).join() ===
            'document_access' &&
          valuesOf(q, R, V.FGA_APPLICATION).join() === 'document-service' &&
          valuesOf(q, R, V.FGA_DETAIL_TYPE).join() === 'document_access' &&
          valuesOf(q, R, V.FGA_DEFINITION_DIGEST).join() ===
            fga.digest(definition) && built.digest === fga.digest(definition),
          'R1. the action, resource-id, application, type and digest',
          JSON.stringify(built.refusal || q));
  t.check(valuesOf(q, S, model.ATTRIBUTE.SUBJECT_ID).join() === 'alice' &&
          valuesOf(q, S, V.SUBJECT_KIND).join() === 'user' &&
          valuesOf(q, S, V.CLIENT_ID).join() === 'docs-client' &&
          valuesOf(q, E, V.REALM).join() === 'acme' &&
          valuesOf(q, E, V.PROTOCOL).join() === 'oauth2' &&
          valuesOf(q, E, V.FGA_STAGE).join() === 'token',
          'R2. the subject, client, realm, protocol and stage are the ' +
          'adapter\'s');
  t.check(valuesOf(q, R, 'urn:example:classification').join() ===
            'internal' &&
          valuesOf(q, R, 'urn:example:department').join() === 'legal' &&
          valuesOf(q, R, 'urn:example:country') === null &&
          JSON.stringify(q).indexOf('do not log') < 0,
          'R3. the declared rows map; an absent member is absent; the ' +
          'member not for policy is nowhere');
  const policy = alfa.parse(POLICY);
  const decide = function (changes, facts) {
    log.debug("Entering decide().");
    const asked = fga.request(Object.assign({}, detail, changes), definition,
                              trusted(facts));
    log.debug("Leaving decide().");
    return pdp.evaluate(policy, asked.request, {}).decision;
  };
  t.equal(decide({}), model.DECISION.PERMIT,
          'R4. the engine permits an internal document at the token stage');
  t.equal(decide({ actions: ['read', 'delete'] }), model.DECISION.DENY,
          'R5. a detail asking to delete is denied');
  t.equal(decide({ classification: 'secret' }),
          model.DECISION.NOT_APPLICABLE,
          'R6. NotApplicable for a secret document');
  t.equal(decide({}, { stage: 'access', action: 'read' }),
          model.DECISION.NOT_APPLICABLE,
          'R7. at access the action is the caller\'s, and this issuance ' +
          'policy does not apply');
  log.debug("Leaving theRequest().");
}

async function run(t) {
  log.debug("Entering run().");
  theGrammar(t);
  oneImplementation(t);
  theCommonFields(t);
  theValueRules(t);
  theCoverage(t);
  theDigest(t);
  theRequest(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'fga_map',
  describe: 'fine-grained authorization: an RFC 9396 detail as an XACML ' +
            'request (#564)',
  run: run
};
