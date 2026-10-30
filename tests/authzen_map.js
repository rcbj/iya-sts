// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/authzen_map.js
//
// ---------------------------------------------------------------------------
// THE AUTHZEN MAPPING CONTRACT, IN PROCESS (#563 phase 1, #1160).
//
// `authzen/authzen_catalogue.ts` and `authzen/authzen_map.ts` are pure, so
// the whole contract is asserted here without a port:
//
//   C. THE CATALOGUE. A row's grammar and its defaults; every refusal of a
//      row that maps onto a RESERVED identifier (this service's own
//      `urn:sts:xacml:` namespace, subject-id and its two siblings,
//      `context.application`, and a bare directory name in a subject
//      category); a second row for one property read once.
//   R. THE REQUEST'S SHAPE. The four AuthZEN objects, their required
//      members, and a member AuthZEN does not define.
//   V. THE VALUE RULES. An undeclared property, null, the row's datatype
//      winning (a fraction for an integer, a number for a string), arrays
//      only for a bag, nested objects only through dotted rows, and absent
//      against empty kept apart by the `supplied` bag.
//   B. THE BUILT REQUEST, through `xacml_request.js`'s `authzen()`: XACML's
//      own three identifiers, the two type identifiers, the trusted facts.
//   P. THE PIP AND AN EMPTY BAG. The ticket asks whether the engine consults
//      the PIP for an attribute present with an EMPTY bag. It does — the
//      resolver is asked whenever a designator found no value, and an empty
//      bag has none — which is why a catalogue row may never map onto a
//      reserved identifier: a VALUE suppresses the PIP, an empty bag does not.
//   D. THE DECISION, fail-closed, through the real engine and `xacml.ts`'s
//      `enforce()`: Permit, Deny, NotApplicable, Indeterminate over a missing
//      attribute (false) and over a fault (an error), and a Permit carrying
//      an obligation this PDP cannot discharge (false).
//   S. THE SHARED TABLE (#1179), `xacml-pep/authzen_cases.json`: the same
//      catalogue values and requests the remote PEP's edge PDP is held to
//      (`cargo test -p xacml-pep`), so the service and the container
//      refuse, supply and map one request one way. The table is the one
//      place a case is added; neither test owns it.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'authzen_map',
  level: process.env.LOG_LEVEL || 'info' });

const catalogue = require('../authzen/authzen_catalogue');
const map = require('../authzen/authzen_map');
const model = require('../xacml/xacml_model');
const pdp = require('../xacml/xacml_pdp');
const alfa = require('../xacml/xacml_alfa');
const xacmlRequest = require('../xacml/xacml_request');

const V = xacmlRequest.VOCABULARY;

const CASES = require('path').join(__dirname, '..', 'xacml-pep',
                                   'authzen_cases.json');

// The rows every value check below reads.
function rows() {
  log.debug("Entering rows().");
  const values = [
    { object: 'subject', property: 'department',
      attributeId: 'urn:example:department' },
    { object: 'subject', property: 'clearance', dataType: 'integer',
      attributeId: 'urn:example:clearance' },
    { object: 'subject', property: 'groups', multiplicity: 'bag',
      attributeId: 'urn:example:groups' },
    { object: 'resource', property: 'classification',
      attributeId: 'urn:example:classification' },
    { object: 'resource', property: 'owner.country',
      attributeId: 'urn:example:owner-country' },
    { object: 'resource', property: 'size', dataType: 'double',
      attributeId: 'urn:example:size' },
    { object: 'action', property: 'urgent', dataType: 'boolean',
      attributeId: 'urn:example:urgent' },
    { object: 'context', property: 'when', dataType: 'dateTime',
      attributeId: 'urn:example:when' },
    { object: 'context', property: 'source_ip',
      attributeId: 'urn:example:source-ip' }
  ];
  const read = catalogue.rowsOf(values.map(function (one) {
    return JSON.stringify(one);
  }));
  log.debug("Leaving rows().");
  return read.rows;
}

// A request with the four required members, and whatever `extra` adds.
function request(extra) {
  log.debug("Entering request().");
  const out = {
    subject: { type: 'user', id: 'alice' },
    action: { name: 'read' },
    resource: { type: 'document', id: 'doc-1' }
  };
  Object.keys(extra || {}).forEach(function (key) {
    if (out[key] && typeof extra[key] === 'object') {
      out[key] = Object.assign({}, out[key], extra[key]);
    } else {
      out[key] = extra[key];
    }
  });
  log.debug("Leaving request().");
  return out;
}

// The code a read refused with, or '' when it was accepted.
function codeOf(body) {
  log.debug("Entering codeOf().");
  const read = map.read(body, rows());
  log.debug("Leaving codeOf().");
  return read.refusal ? read.refusal.code : '';
}

// The values one attribute of a built request carries.
function valuesOf(built, category, attributeId) {
  log.debug("Entering valuesOf().");
  const out = [];
  built.categories.forEach(function (one) {
    if (one.category !== category) {
      return;
    }
    one.attributes.forEach(function (attribute) {
      if (attribute.attributeId === attributeId) {
        attribute.values.forEach(function (value) {
          out.push(value.lexical);
        });
      }
    });
  });
  log.debug("Leaving valuesOf().");
  return out;
}

function theCatalogue(t) {
  log.debug("Entering theCatalogue().");
  t.log.info('=== C. the catalogue ===');
  const plain = catalogue.parse(JSON.stringify({ object: 'resource',
    property: 'classification', attributeId: 'urn:example:c' }));
  t.check(plain.row && plain.row.category === model.CATEGORY.RESOURCE &&
          plain.row.dataType === model.TYPE.STRING &&
          plain.row.multiplicity === 'single',
          'C1. a row takes its object\'s category, string and single by ' +
          'default', JSON.stringify(plain));
  const named = catalogue.parse({ object: 'context', property: 'when',
    attributeId: 'urn:example:when', category: 'environment',
    dataType: 'dateTime', multiplicity: 'bag' });
  t.check(named.row && named.row.dataType === model.TYPE.DATETIME &&
          named.row.category === model.CATEGORY.ENVIRONMENT,
          'C2. short category and datatype names are stored as their URIs',
          JSON.stringify(named));
  t.check(catalogue.valueOf(named.row).indexOf(model.TYPE.DATETIME) > 0,
          'C3. a row is written back with the URIs');
  const refusal = function (value) {
    log.debug("Entering refusal().");
    log.debug("Leaving refusal().");
    return catalogue.parse(value).code || '';
  };
  t.equal(refusal('{not json'), 'STS-AUTHZEN-0010',
          'C4. a value that is not JSON is refused (STS-AUTHZEN-0010)');
  t.equal(refusal({ object: 'resource', property: 'x', attributeId: 'u:x',
                    colour: 'red' }), 'STS-AUTHZEN-0010',
          'C5. an unknown member of a row is refused');
  t.equal(refusal({ object: 'principal', property: 'x', attributeId: 'u:x' }),
          'STS-AUTHZEN-0010', 'C6. an object AuthZEN does not have is refused');
  t.equal(refusal({ object: 'resource', property: 'a..b',
                    attributeId: 'u:x' }), 'STS-AUTHZEN-0010',
          'C7. an empty path segment is refused');
  t.equal(refusal({ object: 'resource', property: 'x', attributeId: 'u:x',
                    dataType: 'xpathExpression' }), 'STS-AUTHZEN-0010',
          'C8. xpathExpression, which JSON cannot carry, is refused');
  t.equal(refusal({ object: 'resource', property: 'x', attributeId: 'u:x',
                    multiplicity: 'many' }), 'STS-AUTHZEN-0010',
          'C9. a multiplicity other than single or bag is refused');
  t.equal(refusal({ object: 'subject', property: 'roles',
                    attributeId: V.ROLE }), 'STS-AUTHZEN-0011',
          'C10. a row onto urn:sts:xacml:role is refused — a request-supplied ' +
          'value would suppress the PIP and forge the subject\'s roles');
  t.equal(refusal({ object: 'context', property: 'p',
                    attributeId: V.AUTHZEN_APPLICATION }), 'STS-AUTHZEN-0011',
          'C11. a row onto a trusted AuthZEN fact is refused');
  t.equal(refusal({ object: 'context', property: 'p',
                    attributeId: 'URN:STS:XACML:setting:x' }),
          'STS-AUTHZEN-0011',
          'C12. the namespace is reserved however it is cased');
  t.equal(refusal({ object: 'subject', property: 'who',
                    attributeId: model.ATTRIBUTE.SUBJECT_ID }),
          'STS-AUTHZEN-0011', 'C13. a row onto subject-id is refused');
  t.equal(refusal({ object: 'resource', property: 'r',
                    attributeId: model.ATTRIBUTE.RESOURCE_ID }),
          'STS-AUTHZEN-0011', 'C14. and onto resource-id');
  t.equal(refusal({ object: 'context', property: 'application',
                    attributeId: 'urn:example:app' }), 'STS-AUTHZEN-0011',
          'C15. context.application is the adapter\'s, not the catalogue\'s');
  t.equal(refusal({ object: 'subject', property: 'type',
                    attributeId: 'employeeType' }), 'STS-AUTHZEN-0012',
          'C16. a bare directory name in a subject category is refused ' +
          '(STS-AUTHZEN-0012): the directory is authoritative there');
  t.equal(refusal({ object: 'context', property: 'who',
                    attributeId: 'employeeType',
                    category: 'access-subject' }), 'STS-AUTHZEN-0012',
          'C17. by the row\'s category, not its object');
  t.check(!catalogue.parse({ object: 'resource', property: 'owner',
                             attributeId: 'owner' }).code,
          'C18. a bare name in the resource category is any other name');
  const twice = catalogue.rowsOf([
    JSON.stringify({ object: 'resource', property: 'x', attributeId: 'u:1' }),
    JSON.stringify({ object: 'resource', property: 'x', attributeId: 'u:2' }),
    'garbage'
  ]);
  t.check(twice.rows.length === 1 && twice.rows[0].attributeId === 'u:1' &&
          twice.problems.length === 2,
          'C19. reading an entry, a second row for one property and a value ' +
          'that is not a row are left out and named',
          JSON.stringify(twice));
  log.debug("Leaving theCatalogue().");
}

function theShape(t) {
  log.debug("Entering theShape().");
  t.log.info('=== R. the request\'s shape ===');
  t.equal(codeOf('a string'), 'STS-AUTHZEN-0001',
          'R1. a body that is not an object is refused (STS-AUTHZEN-0001)');
  t.equal(codeOf({ action: { name: 'r' },
                   resource: { type: 'd', id: '1' } }), 'STS-AUTHZEN-0002',
          'R2. no subject is refused (STS-AUTHZEN-0002)');
  t.equal(codeOf(request({ subject: { type: '' } })), 'STS-AUTHZEN-0002',
          'R3. an empty subject.type is a missing one');
  t.equal(codeOf(request({ action: { name: null } })), 'STS-AUTHZEN-0002',
          'R4. a null action.name is a missing one');
  t.equal(codeOf(request({ resource: { id: 7 } })), 'STS-AUTHZEN-0003',
          'R5. a number for resource.id is the wrong type (STS-AUTHZEN-0003)');
  t.equal(codeOf(request({ subject: { properties: [] } })),
          'STS-AUTHZEN-0003', 'R6. properties that are not an object');
  t.equal(codeOf(request({ context: 'x' })), 'STS-AUTHZEN-0003',
          'R7. a context that is not an object');
  t.equal(codeOf(request({ context: { application: 5 } })),
          'STS-AUTHZEN-0003', 'R8. a context.application that is not a ' +
          'string');
  t.equal(codeOf(request({ evaluations: [] })), 'STS-AUTHZEN-0009',
          'R9. a member a single evaluation does not define is refused ' +
          '(STS-AUTHZEN-0009)');
  t.equal(codeOf(request({ subject: { name: 'x' } })), 'STS-AUTHZEN-0009',
          'R10. and one of subject\'s');
  const read = map.read(request({ context: { application: 'portal' } }),
                        rows());
  t.check(read.evaluation && read.evaluation.application === 'portal' &&
          read.evaluation.attributes.length === 0,
          'R11. context.application is read as the application, and sends ' +
          'no attribute of its own', JSON.stringify(read));
  log.debug("Leaving theShape().");
}

function theValues(t) {
  log.debug("Entering theValues().");
  t.log.info('=== V. the value rules ===');
  t.equal(codeOf(request({ subject: { properties: { title: 'x' } } })),
          'STS-AUTHZEN-0004', 'V1. an undeclared property is refused ' +
          '(STS-AUTHZEN-0004)');
  t.equal(codeOf(request({ context: { other: 'x' } })), 'STS-AUTHZEN-0004',
          'V2. so is an undeclared context member');
  t.equal(codeOf(request({ subject: { properties: { department: null } } })),
          'STS-AUTHZEN-0005', 'V3. null is refused (STS-AUTHZEN-0005)');
  t.equal(codeOf(request({ subject: { properties: { department: 3 } } })),
          'STS-AUTHZEN-0006', 'V4. a number is not quietly a string ' +
          '(STS-AUTHZEN-0006)');
  t.equal(codeOf(request({ subject: { properties: { clearance: 1.5 } } })),
          'STS-AUTHZEN-0006', 'V5. an integer row refuses a fraction');
  t.equal(codeOf(request({ subject: { properties: { clearance: '1.5' } } })),
          'STS-AUTHZEN-0006', 'V6. and a string that is not an integer');
  t.equal(codeOf(request({ subject: { properties: { clearance: 3 } } })), '',
          'V7. a whole number reaches an integer row');
  t.equal(codeOf(request({ subject: { properties: { clearance: '3' } } })), '',
          'V8. so does a string in its lexical form');
  t.equal(codeOf(request({ action: { properties: { urgent: 1 } } })),
          'STS-AUTHZEN-0006', 'V9. a number is not a boolean');
  t.equal(codeOf(request({ action: { properties: { urgent: true } } })), '',
          'V10. true reaches a boolean row');
  t.equal(codeOf(request({ resource: { properties: { size: 2.5 } } })), '',
          'V11. a number reaches a double row');
  t.equal(codeOf(request({ context: { when: 'yesterday' } })),
          'STS-AUTHZEN-0006', 'V12. a string that does not parse at the ' +
          'row\'s datatype is refused');
  t.equal(codeOf(request({ context: { when: '2026-10-29T12:00:00Z' } })), '',
          'V13. and one that does is accepted');
  t.equal(codeOf(request({ subject: { properties: { department: ['a'] } } })),
          'STS-AUTHZEN-0007', 'V14. an array for a single row is refused ' +
          '(STS-AUTHZEN-0007)');
  t.equal(codeOf(request({ subject: { properties: { groups: ['a', null] } } })),
          'STS-AUTHZEN-0005', 'V15. a null inside a bag is refused');
  t.equal(codeOf(request({ subject: { properties: { groups: [['a']] } } })),
          'STS-AUTHZEN-0008', 'V16. a bag is of scalars (STS-AUTHZEN-0008)');
  t.equal(codeOf(request({ resource: {
    properties: { classification: { level: 1 } } } })),
          'STS-AUTHZEN-0008', 'V17. an object for a scalar row is refused, ' +
          'never flattened');
  t.equal(codeOf(request({ resource: {
    properties: { owner: { country: 'SE' } } } })), '',
          'V18. a nested object reaches a request through its dotted row');
  t.equal(codeOf(request({ resource: {
    properties: { owner: { city: 'Lund' } } } })), 'STS-AUTHZEN-0004',
          'V19. and a member of it no row names is undeclared');
  t.equal(codeOf(request({ resource: { properties: { owner: 'SE' } } })),
          'STS-AUTHZEN-0004', 'V20. a branch sent as a scalar is undeclared');
  const empty = map.read(request({ subject: { properties: {
    department: '', groups: [] } } }), rows());
  const absent = map.read(request(), rows());
  const evaluation = empty.evaluation || { supplied: [], attributes: [] };
  t.check(evaluation.supplied.indexOf('subject.properties.department') >= 0 &&
          evaluation.supplied.indexOf('subject.properties.groups') >= 0 &&
          absent.evaluation.supplied
            .indexOf('subject.properties.department') < 0,
          'V21. absent and empty stay distinguishable: supplied names a ' +
          'member sent empty and not one left out',
          JSON.stringify([evaluation.supplied, absent.evaluation.supplied]));
  const groups = evaluation.attributes.filter(function (one) {
    return one.attributeId === 'urn:example:groups';
  })[0];
  const department = evaluation.attributes.filter(function (one) {
    return one.attributeId === 'urn:example:department';
  })[0];
  t.check(groups && groups.values.length === 0 && department &&
          department.values.length === 1 && department.values[0] === '',
          'V22. an empty array is an empty bag, and "" is one empty value',
          JSON.stringify(evaluation.attributes));
  log.debug("Leaving theValues().");
}

function theBuiltRequest(t) {
  log.debug("Entering theBuiltRequest().");
  t.log.info('=== B. the built request ===');
  const read = map.read(request({
    subject: { properties: { department: 'eng', clearance: 4 } },
    resource: { properties: { classification: 'internal' } },
    context: { application: 'portal', source_ip: '192.0.2.25' } }), rows());
  const built = map.request(read.evaluation, { realm: 'acme',
    caller: 'cn=pep-1,ou=users,dc=acme', application: 'portal' });
  const S = model.CATEGORY.ACCESS_SUBJECT;
  const R = model.CATEGORY.RESOURCE;
  const A = model.CATEGORY.ACTION;
  const E = model.CATEGORY.ENVIRONMENT;
  t.check(valuesOf(built, S, model.ATTRIBUTE.SUBJECT_ID).join() === 'alice' &&
          valuesOf(built, A, model.ATTRIBUTE.ACTION_ID).join() === 'read' &&
          valuesOf(built, R, model.ATTRIBUTE.RESOURCE_ID).join() === 'doc-1',
          'B1. subject.id, action.name and resource.id are XACML\'s own ' +
          'subject-id, action-id and resource-id');
  t.check(valuesOf(built, S, V.AUTHZEN_SUBJECT_TYPE).join() === 'user' &&
          valuesOf(built, R, V.AUTHZEN_RESOURCE_TYPE).join() === 'document',
          'B2. the two types are urn:sts:xacml:authzen:subject-type and ' +
          'resource-type');
  t.check(valuesOf(built, E, V.PROTOCOL).join() === 'authzen' &&
          valuesOf(built, E, V.REALM).join() === 'acme' &&
          valuesOf(built, E, V.AUTHZEN_CALLER).join() ===
            'cn=pep-1,ou=users,dc=acme' &&
          valuesOf(built, E, V.AUTHZEN_APPLICATION).join() === 'portal',
          'B3. the trusted facts are written: the protocol, the realm, the ' +
          'caller and its application');
  t.check(valuesOf(built, S, 'urn:example:clearance').join() === '4' &&
          valuesOf(built, E, 'urn:example:source-ip').join() ===
            '192.0.2.25' &&
          valuesOf(built, R, 'urn:example:classification').join() ===
            'internal',
          'B4. each property reaches its row\'s attribute');
  const clearance = built.categories.filter(function (one) {
    return one.category === S;
  })[0].attributes.filter(function (one) {
    return one.attributeId === 'urn:example:clearance';
  })[0];
  t.equal(clearance.values[0].type, model.TYPE.INTEGER,
          'B5. at the row\'s datatype');
  t.check(valuesOf(built, E, V.AUTHZEN_SUPPLIED)
            .indexOf('context.application') >= 0 &&
          valuesOf(built, E, V.AUTHZEN_SUPPLIED)
            .indexOf('subject.properties.department') >= 0,
          'B6. supplied names every member sent',
          valuesOf(built, E, V.AUTHZEN_SUPPLIED).join());
  log.debug("Leaving theBuiltRequest().");
}

// THE POLICY THE DECISIONS BELOW ARE MADE AGAINST: a Permit for a reader of
// an internal document, a Deny for a delete, an obligation this PDP cannot
// discharge on an `export`, and a `clearance` it MUST find on an `audit`.
const POLICY = [
  'namespace authzen {',
  '    attribute act { category = actionCat',
  '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id"',
  '        type = string }',
  '    attribute classification { category = resourceCat',
  '        id = "urn:example:classification" type = string }',
  '    attribute protocol { category = environmentCat',
  '        id = "urn:sts:xacml:protocol" type = string }',
  '    policy authzenProbe {',
  '        id = "urn:test:authzen-probe"',
  '        apply firstApplicable',
  '        target clause protocol == "authzen"',
  '        rule readInternal {',
  '            permit',
  '            target clause act == "read"',
  '            target clause classification == "internal"',
  '        }',
  '        rule noDelete {',
  '            deny',
  '            target clause act == "delete"',
  '        }',
  '    }',
  '}'
].join('\n');

function thePip(t) {
  log.debug("Entering thePip().");
  t.log.info('=== P. the PIP and an empty bag ===');
  const asked = [];
  const resolver = function (designator) {
    log.debug("Entering resolver().");
    asked.push(designator.attributeId);
    log.debug("Leaving resolver().");
    return [];
  };
  const read = map.read(request({ subject: { properties: { groups: [] } } }),
                        rows());
  const built = map.request(read.evaluation, { realm: '', caller: 'x',
                                               application: '' });
  const context = pdp.makeContext(built, { resolver: resolver });
  pdp.resolveDesignator({ category: model.CATEGORY.ACCESS_SUBJECT,
    attributeId: 'urn:example:groups', dataType: model.TYPE.STRING,
    mustBePresent: false, issuer: null }, context);
  t.check(asked.indexOf('urn:example:groups') >= 0,
          'P1. an attribute sent with an EMPTY bag still reaches the PIP — ' +
          'only a value suppresses it, which is the reserved-identifier ' +
          'rule\'s reason', JSON.stringify(asked));
  asked.length = 0;
  const valued = map.request(map.read(request({ subject: { properties: {
    groups: ['staff'] } } }), rows()).evaluation,
    { realm: '', caller: 'x', application: '' });
  pdp.resolveDesignator({ category: model.CATEGORY.ACCESS_SUBJECT,
    attributeId: 'urn:example:groups', dataType: model.TYPE.STRING,
    mustBePresent: false, issuer: null },
    pdp.makeContext(valued, { resolver: resolver }));
  t.check(asked.length === 0,
          'P2. and an attribute sent with a value never does',
          JSON.stringify(asked));
  log.debug("Leaving thePip().");
}

function theDecision(t) {
  log.debug("Entering theDecision().");
  t.log.info('=== D. the decision, fail-closed ===');
  const surface = require('../xacml/xacml');
  const policy = alfa.parse(POLICY);
  const decide = function (body) {
    log.debug("Entering decide().");
    const read = map.read(body, rows());
    const built = map.request(read.evaluation, { realm: '', caller: 'c',
                                                 application: '' });
    const answer = pdp.evaluate(policy, built, {});
    log.debug("Leaving decide().");
    return map.outcome(answer, surface.enforce(answer, 'deny-biased'), '');
  };
  const permit = decide(request({ resource: { properties: {
    classification: 'internal' } } }));
  t.check(!permit.fault && permit.decision === true &&
          permit.xacmlDecision === model.DECISION.PERMIT,
          'D1. Permit is true', JSON.stringify(permit));
  const deny = decide(request({ action: { name: 'delete' } }));
  t.check(!deny.fault && deny.decision === false &&
          deny.xacmlDecision === model.DECISION.DENY, 'D2. Deny is false');
  const none = decide(request({ action: { name: 'list' } }));
  t.check(!none.fault && none.decision === false &&
          none.xacmlDecision === model.DECISION.NOT_APPLICABLE,
          'D3. NotApplicable is false', JSON.stringify(none));
  const missing = map.outcome({ decision: model.DECISION.INDETERMINATE,
    status: { code: model.STATUS.MISSING_ATTRIBUTE } },
    surface.enforce({ decision: model.DECISION.INDETERMINATE }), '');
  t.check(!missing.fault && missing.decision === false,
          'D4. Indeterminate over a missing attribute is an ordinary false');
  const fault = map.outcome({ decision: model.DECISION.INDETERMINATE,
    status: { code: model.STATUS.PROCESSING_ERROR, message: 'boom' } },
    surface.enforce({ decision: model.DECISION.INDETERMINATE }), '');
  t.check(fault.fault && fault.decision === false,
          'D5. Indeterminate over a processing error is a FAULT, not a ' +
          'denial');
  const marked = map.outcome({ decision: model.DECISION.INDETERMINATE,
    status: { code: model.STATUS.OK } },
    surface.enforce({ decision: model.DECISION.INDETERMINATE }),
    'STS-XACML-0012');
  t.check(marked.fault, 'D6. as is an answer marked STS-XACML-0012 (a root ' +
          'policy that will not load)');
  const obligation = { decision: model.DECISION.PERMIT, status: {},
    obligations: [{ id: 'urn:example:obligation:notify', assignments: [] }],
    advice: [] };
  const obliged = map.outcome(obligation,
                              surface.enforce(obligation, 'deny-biased'), '');
  t.check(!obliged.fault && obliged.decision === false &&
          obliged.undischargeable.indexOf('urn:example:obligation:notify') >=
            0,
          'D7. a Permit carrying an obligation this PDP cannot discharge is ' +
          'false', JSON.stringify(obliged));
  const logged = { decision: model.DECISION.PERMIT, status: {},
    obligations: [{ id: 'urn:sts:xacml:obligation:log', assignments: [] }],
    advice: [] };
  t.check(map.outcome(logged, surface.enforce(logged, 'deny-biased'), '')
            .decision === true,
          'D8. and one carrying only the log obligation, which is ' +
          'discharged, is true');
  const reasons = map.reasons(obliged);
  t.check(reasons.xacml_decision === 'Permit' &&
          reasons.undischargeable_obligations.length === 1 &&
          typeof reasons.reason_admin.en === 'string',
          'D9. the reasons a decision may carry name the XACML decision and ' +
          'why', JSON.stringify(reasons));
  log.debug("Leaving theDecision().");
}

// THE PUBLIC PAGE'S WORKED EXAMPLE (#1182) IS HELD TO THE CODE: its ALFA
// policy parses, and the request it shows converts and decides as the page
// says — true for a staff subject, false otherwise.
function thePublishedExample(t) {
  log.debug("Entering thePublishedExample().");
  t.log.info('=== X. docs/authzen.md\'s worked example ===');
  const fs = require('fs');
  const text = fs.readFileSync(require('path').join(__dirname, '..', 'docs',
                                                     'authzen.md'), 'utf8');
  const start = text.indexOf('namespace docs {');
  const block = start >= 0 ? text.slice(start, text.indexOf('```', start))
    : '';
  let policy = null;
  try {
    policy = alfa.parse(block);
  } catch (e) {
    log.debug("Caught in thePublishedExample(): " + ((e && e.message) || e));
    policy = null;
  }
  t.check(!!policy, 'X1. the page\'s ALFA policy parses', block.slice(0, 80));
  if (!policy) {
    log.debug("Leaving thePublishedExample(). No policy.");
    return;
  }
  const rows = catalogue.rowsOf([JSON.stringify({ object: 'resource',
    property: 'classification',
    attributeId: 'urn:example:classification' })]).rows;
  const read = map.read({
    subject: { type: 'user', id: 'alice' },
    action: { name: 'read' },
    resource: { type: 'document', id: 'doc-1',
                properties: { classification: 'internal' } },
    context: { application: 'engineering-portal' } }, rows);
  const built = map.request(read.evaluation, { realm: 'acme',
    caller: 'cn=docs-pep,ou=users,dc=acme,dc=example',
    application: 'engineering-portal' });
  const decideAs = function (role) {
    log.debug("Entering decideAs().");
    const answer = pdp.evaluate(policy, built, { resolver: function (d) {
      return d.attributeId === 'employeeType' ? [role] : [];
    } });
    log.debug("Leaving decideAs().");
    return answer.decision;
  };
  t.check(decideAs('staff') === model.DECISION.PERMIT &&
          decideAs('contractor') !== model.DECISION.PERMIT,
          'X2. the worked example decides as the page says: Permit for a ' +
          'staff subject, not for another',
          decideAs('staff') + ' / ' + decideAs('contractor'));
  log.debug("Leaving thePublishedExample().");
}

// THE OBLIGATIONS PROFILE (#1177): the conversion of an XACML obligation and
// the rule that only a PEP declaring every type is handed any.
function theObligations(t) {
  log.debug("Entering theObligations().");
  t.log.info('=== O. the Obligations Profile ===');
  const surface = require('../xacml/xacml');
  const assignment = function (id, value) {
    log.debug("Entering assignment().");
    log.debug("Leaving assignment().");
    return { attributeId: id, type: model.TYPE.STRING, value: value };
  };
  const stepUp = { id: map.OBLIGATION_PREFIX + 'step-up', assignments: [
    assignment(map.OBLIGATION_PREFIX + 'step-up:acr_value', 'phr'),
    assignment('amr_values', 'hwk')] };
  const other = { id: 'urn:example:obligation:watermark',
                  assignments: [assignment('urn:example:text', 'secret')] };
  const logged = { id: 'urn:sts:xacml:obligation:log', assignments: [] };
  const permit = function (obligations) {
    log.debug("Entering permit().");
    log.debug("Leaving permit().");
    return { decision: model.DECISION.PERMIT, status: {}, advice: [],
             obligations: obligations };
  };
  const converted = map.obligationsOf(permit([stepUp, other, logged]));
  t.check(converted.handed.length === 2 &&
          converted.handed[0].type === 'step-up' &&
          converted.handed[0].properties.acr_value === 'phr' &&
          Array.isArray(converted.handed[0].properties.amr_values) &&
          converted.handed[1].type === 'custom' &&
          converted.handed[1].properties.xacml_obligation ===
            'urn:example:obligation:watermark' &&
          converted.handed[1].properties.text === 'secret' &&
          converted.handed[0].id !== converted.handed[1].id,
          'O1. a prefixed obligation is its registered type, any other is ' +
          'custom, a property is its attribute id\'s last segment, and the ' +
          'log obligation is discharged here and not handed',
          JSON.stringify(converted));
  const decide = function (answer, supported) {
    log.debug("Entering decide().");
    log.debug("Leaving decide().");
    return map.outcome(answer, surface.enforce(answer, 'deny-biased'), '',
                       supported);
  };
  let o = decide(permit([stepUp]), null);
  t.check(o.decision === false && o.obligations.length === 0,
          'O2. a PEP that declared nothing is handed nothing, and the ' +
          'Permit stays false', JSON.stringify(o));
  o = decide(permit([stepUp]), ['notification']);
  t.check(o.decision === false && o.obligations.length === 0,
          'O3. nor is one that declared other types');
  o = decide(permit([stepUp]), ['step-up']);
  t.check(o.decision === true && o.obligations.length === 1 &&
          o.obligations[0].type === 'step-up',
          'O4. one that declared every type is handed them, and the Permit ' +
          'is true', JSON.stringify(o));
  o = decide({ decision: model.DECISION.DENY, status: {}, advice: [],
               obligations: [{ id: map.OBLIGATION_PREFIX + 'notification',
                 assignments: [assignment('to', 'soc@example.com'),
                               assignment('body', 'denied')] }] },
             ['notification']);
  t.check(o.decision === false && o.obligations.length === 1 &&
          Array.isArray(o.obligations[0].properties.to),
          'O5. a Deny\'s obligations are handed beside false',
          JSON.stringify(o));
  o = decide(permit([{ id: map.OBLIGATION_PREFIX + 'step-up',
                       assignments: [] }]), ['step-up']);
  t.check(o.decision === false && o.obligations.length === 0 &&
          o.obligationProblems.length === 1,
          'O6. a registered type without a property it requires hands ' +
          'nothing, and the Permit is false', JSON.stringify(o));
  t.equal(catalogue.parse({ object: 'context',
                            property: 'supported_obligations',
                            attributeId: 'urn:example:x' }).code,
          'STS-AUTHZEN-0011',
          'O7. context.supported_obligations is the adapter\'s, not a ' +
          'catalogue property');
  t.equal(codeOf(request({ context: { supported_obligations: 'step-up' } })),
          'STS-AUTHZEN-0003', 'O8. supported_obligations is an array');
  const declared = map.read(request({ context: {
    supported_obligations: ['step-up'] } }), rows());
  t.check(declared.evaluation &&
          declared.evaluation.supportedObligations.join() === 'step-up' &&
          declared.evaluation.supplied
            .indexOf('context.supported_obligations') >= 0,
          'O9. and is read as the declaration', JSON.stringify(declared));
  log.debug("Leaving theObligations().");
}

function theSharedTable(t) {
  log.debug("Entering theSharedTable().");
  t.log.info('=== S. the table the edge PDP shares (#1179) ===');
  const table = JSON.parse(require('fs').readFileSync(CASES, 'utf8'));
  const shared = table.rows.map(function (value) {
    return catalogue.parse(value).row;
  });
  t.check(shared.every(Boolean) && shared.length === table.rows.length,
          'S1. every row of the shared table is a row here',
          JSON.stringify(shared));
  const wrong = [];
  table.catalogue.forEach(function (one) {
    const code = catalogue.parse(one.value).code || '';
    if (code !== one.code) {
      wrong.push(one.what + ': expected "' + one.code + '", got "' + code +
                 '"');
    }
  });
  t.check(table.catalogue.length >= 15 && !wrong.length,
          'S2. every catalogue case of the shared table (' +
          table.catalogue.length + ') is read here as the edge PDP reads it',
          wrong.join('; '));
  const different = [];
  table.requests.forEach(function (one) {
    const read = map.read(one.body, shared);
    const code = read.refusal ? read.refusal.code : '';
    if (code !== one.code ||
        (read.refusal && read.refusal.status !== 400)) {
      different.push(one.what + ': expected "' + one.code + '", got "' +
                     code + '"');
      return;
    }
    if (read.evaluation && one.supplied &&
        JSON.stringify(read.evaluation.supplied) !==
          JSON.stringify(one.supplied)) {
      different.push(one.what + ': supplied ' +
                     JSON.stringify(read.evaluation.supplied));
    }
    if (read.evaluation && one.attributes) {
      const got = read.evaluation.attributes.map(function (attribute) {
        return { attributeId: attribute.attributeId,
                 values: attribute.values };
      });
      if (JSON.stringify(got) !== JSON.stringify(one.attributes)) {
        different.push(one.what + ': attributes ' + JSON.stringify(got));
      }
    }
  });
  t.check(table.requests.length >= 30 && !different.length,
          'S3. every request case of the shared table (' +
          table.requests.length + ') is refused, supplied and mapped here ' +
          'as the edge PDP does it', different.join('; '));
  log.debug("Leaving theSharedTable().");
}

async function run(t) {
  log.debug("Entering run().");
  theCatalogue(t);
  theShape(t);
  theValues(t);
  theBuiltRequest(t);
  thePip(t);
  theDecision(t);
  thePublishedExample(t);
  theObligations(t);
  theSharedTable(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'authzen_map',
  describe: 'the AuthZEN to XACML mapping contract (#563): the catalogue ' +
            'and its reserved identifiers, the request\'s shape, every ' +
            'value rule, the built request, the PIP and an empty bag, and ' +
            'the fail-closed decision',
  run: run
};
