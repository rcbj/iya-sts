// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/own_members.js
//
// ---------------------------------------------------------------------------
// A NAME A CALLER CHOSE READS AN OWN MEMBER, NEVER AN INHERITED ONE
// (2026-11-12).
//
// #1664 fixed the XACML editor's path WRITING through `__proto__`. The same
// walk READ through it in the rest of `xacml/`, `authzen/` and the RFC 9396
// parser that feeds the FGA gate, wherever a name from a request, a detail,
// a policy document or a stored row was looked up in a plain-object table:
// `constructor`, `toString`, `hasOwnProperty` and `__proto__` answered a
// function or `Object.prototype` instead of "absent". Each section here is
// one such read, asserted to answer what an unknown name answers — and,
// beside it, an OWN member answering exactly what it answered before:
//
//   H. `common/own_members.ts` itself, and the editor's `ownStep()` over it.
//   R. the attribute-row grammar FGA and AuthZEN share: a category or a
//      datatype called `constructor` / `toString`.
//   J. the XACML JSON Profile: `DataType: "constructor"`.
//   E. the engine: a FunctionId, a combining algorithm, a datatype, a
//      VariableId, a VariableReference, a PolicyIdReference; and a variable
//      or a referenced policy really called `__proto__` still resolving.
//   P. the XACML editor's variables: one called `toString` added and
//      renamed to, one called `__proto__` added as a member.
//   S. the policy store's repository: a policy whose PolicyId is
//      `__proto__` is a member of it, in a realm of this file's own.
//   A. ALFA: a category, an undeclared attribute, an algorithm name; and an
//      attribute really called `constructor`.
//   G. GNAP's right verdicts: an interaction word or a drop attribute named
//      after an inherited member.
//   Z. AuthZEN: an obligation property named `constructor` or `__proto__`,
//      and a token-exchange scope called `constructor` (which carried a
//      delegated-permission fact into the issuance policy).
//   O. RFC 9396: a detail of `type: "constructor"` is refused as an unknown
//      type (STS-OAUTH-0453).
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'own_members',
  level: process.env.LOG_LEVEL || 'info' });

const ownMembers = require('../common/own_members');
const errorCodes = require('../common/error_codes');
const rowsGrammar = require('../xacml/xacml_attribute_rows');
const fga = require('../xacml/fga_map');
const catalogue = require('../authzen/authzen_catalogue');
const model = require('../xacml/xacml_model');
const datatypes = require('../xacml/xacml_datatypes');
const functions = require('../xacml/xacml_functions');
const pdp = require('../xacml/xacml_pdp');
const validate = require('../xacml/xacml_validate');
const json = require('../xacml/xacml_json');
const xml = require('../xacml/xacml_xml');
const alfa = require('../xacml/xacml_alfa');
const editor = require('../xacml/xacml_editor');
const gnapVerdicts = require('../xacml/xacml_gnap_right_verdicts');
const templates = require('../xacml/xacml_templates');
const authzenMap = require('../authzen/authzen_map');
const exchange = require('../authzen/authzen_exchange');
const scopeVerdicts = require('../xacml/xacml_scope_verdicts');
const details = require('../oauth-oidc/authorization_details');

// The names an object inherits from Object.prototype that a caller can
// spell, each of which read as present before.
const INHERITED = ['constructor', 'toString', 'hasOwnProperty', 'valueOf',
                   'isPrototypeOf', '__proto__', '__defineGetter__'];

const NS = 'urn:oasis:names:tc:xacml:3.0:core:schema:wd-17';
const DENY_OVERRIDES =
  'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides';
const STRING = 'http://www.w3.org/2001/XMLSchema#string';
const STRING_EQUAL = 'urn:oasis:names:tc:xacml:1.0:function:string-equal';

function attempt(f) {
  log.debug("Entering attempt().");
  try {
    const value = f();
    log.debug("Leaving attempt().");
    return { value: value };
  } catch (e) {
    log.debug("Caught in attempt(): " + ((e && e.message) || e));
    log.debug("Leaving attempt().");
    return { error: String((e && e.message) || e) };
  }
}

function policyXml(alg, variables, condition) {
  log.debug("Entering policyXml().");
  log.debug("Leaving policyXml().");
  return '<Policy xmlns="' + NS + '" PolicyId="p" Version="1.0" ' +
    'RuleCombiningAlgId="' + alg + '"><Target/>' + (variables || '') +
    '<Rule RuleId="r" Effect="Permit">' +
    (condition ? '<Condition>' + condition + '</Condition>' : '') +
    '</Rule></Policy>';
}

function variableXml(id, value) {
  log.debug("Entering variableXml().");
  log.debug("Leaving variableXml().");
  return '<VariableDefinition VariableId="' + id + '"><AttributeValue ' +
    'DataType="' + STRING + '">' + value + '</AttributeValue>' +
    '</VariableDefinition>';
}

function referenceIsX(id) {
  log.debug("Entering referenceIsX().");
  log.debug("Leaving referenceIsX().");
  return '<Apply FunctionId="' + STRING_EQUAL + '"><VariableReference ' +
    'VariableId="' + id + '"/><AttributeValue DataType="' + STRING +
    '">x</AttributeValue></Apply>';
}

function theHelper(t) {
  log.debug("Entering theHelper().");
  t.log.info('=== H. the helper ===');
  const table = { own: 1, zero: 0 };
  t.check(INHERITED.every(function (name) {
    return !ownMembers.has(table, name) &&
           ownMembers.read(table, name) === undefined;
  }), 'H1. no inherited name is a member, and each reads undefined');
  t.check(ownMembers.read(table, 'own') === 1 &&
          ownMembers.read(table, 'zero') === 0 &&
          ownMembers.has(table, 'zero'),
          'H2. an own member reads as it did, a falsy one included');
  const list = ['a', 'b'];
  t.check(ownMembers.has(list, '1') && !ownMembers.has(list, '2') &&
          !ownMembers.has(list, 'length') && !ownMembers.has(list, '-1') &&
          !ownMembers.has(list, '1e0') && ownMembers.read(list, 0) === 'a',
          'H3. an array\'s members are digits below its length');
  t.check(!ownMembers.has(null, 'x') && !ownMembers.has('text', 'length') &&
          ownMembers.read(undefined, 'x') === undefined,
          'H4. a step off something that is not an object is no member');
  const map = {};
  ownMembers.put(map, '__proto__', { kind: 'held' });
  t.check(Object.getPrototypeOf(map) === Object.prototype &&
          Object.keys(map).join() === '__proto__' &&
          ownMembers.read(map, '__proto__').kind === 'held' &&
          map.kind === undefined,
          'H5. put() stores `__proto__` as a member, never as the prototype');
  t.check(editor.XacmlEditor.ownStep({ rules: [] }, 'rules') &&
          !editor.XacmlEditor.ownStep({}, 'constructor') &&
          !editor.XacmlEditor.ownStep([1], '1'),
          'H6. the editor\'s ownStep() is the same rule');
  log.debug("Leaving theHelper().");
}

function theRowGrammar(t) {
  log.debug("Entering theRowGrammar().");
  t.log.info('=== R. the attribute-row grammar ===');
  t.check(INHERITED.every(function (name) {
    return rowsGrammar.categoryOf(name) === '' &&
           rowsGrammar.dataTypeOf(name) === '';
  }), 'R1. an inherited name is neither a category nor a datatype',
          JSON.stringify(INHERITED.map(function (name) {
            return [typeof rowsGrammar.categoryOf(name),
                    typeof rowsGrammar.dataTypeOf(name)];
          })));
  t.check(rowsGrammar.categoryOf('resource') === model.CATEGORY.RESOURCE &&
          rowsGrammar.categoryOf(model.CATEGORY.ACTION) ===
            model.CATEGORY.ACTION &&
          rowsGrammar.dataTypeOf('') === model.TYPE.STRING &&
          rowsGrammar.dataTypeOf('integer') === model.TYPE.INTEGER,
          'R2. a short name or a URI resolves as before');
  const fgaRow = fga.FgaMap.parseRow({ path: 'a', attributeId: 'urn:x:a',
                                       category: 'constructor' }, 'xacml[0]');
  const fgaType = fga.FgaMap.parseRow({ path: 'a', attributeId: 'urn:x:a',
                                        dataType: 'toString' }, 'xacml[0]');
  t.check(!fgaRow.row && /category/.test(fgaRow.problem || '') &&
          !fgaType.row && /dataType/.test(fgaType.problem || ''),
          'R3. an FGA row with category "constructor" or dataType ' +
          '"toString" is refused', JSON.stringify([fgaRow, fgaType]));
  const authzenRow = catalogue.parse({ object: 'resource', property: 'a',
                                       attributeId: 'urn:x:a',
                                       category: 'constructor' });
  t.check(authzenRow.code === 'STS-AUTHZEN-0010',
          'R4. an AuthZEN catalogue row with category "constructor" is ' +
          'refused', JSON.stringify(authzenRow));
  log.debug("Leaving theRowGrammar().");
}

function theJsonProfile(t) {
  log.debug("Entering theJsonProfile().");
  t.log.info('=== J. the JSON Profile ===');
  const request = function (type) {
    log.debug("Entering request().");
    log.debug("Leaving request().");
    return { Request: { AccessSubject: { Attribute: [
      { AttributeId: 'a', Value: 'x', DataType: type }] } } };
  };
  const refused = INHERITED.filter(function (name) {
    const tried = attempt(function () {
      return json.parseRequest(request(name));
    });
    return tried.error && /Unknown DataType/.test(tried.error);
  });
  t.equal(refused.length, INHERITED.length,
          'J1. a DataType named after an inherited member is refused as ' +
          'unknown', refused.join(','));
  const parsed = json.parseRequest(request('integer'));
  t.check(parsed.categories[0].attributes[0].values[0].type ===
            model.TYPE.INTEGER ||
          JSON.stringify(parsed).indexOf(model.TYPE.INTEGER) >= 0,
          'J2. a short datatype name still resolves');
  log.debug("Leaving theJsonProfile().");
}

function theEngine(t) {
  log.debug("Entering theEngine().");
  t.log.info('=== E. the engine ===');
  t.check(INHERITED.every(function (name) {
    return functions.lookup(name) === null &&
           pdp.lookupCombiner(name) === null &&
           datatypes.typeOf(name) === null &&
           model.canonicalType(name) === name;
  }), 'E1. no inherited name is a function, a combiner or a datatype');
  t.check(functions.lookup(STRING_EQUAL) !== null &&
          pdp.lookupCombiner(DENY_OVERRIDES) !== null &&
          datatypes.typeOf(STRING).name === 'string',
          'E2. the real ones resolve as before');

  const twice = attempt(function () {
    return Object.keys(xml.parsePolicy(policyXml(DENY_OVERRIDES,
      variableXml('toString', 'x'))).variables);
  });
  t.check(!twice.error && twice.value.join() === 'toString',
          'E3. a VariableId "toString" is one definition, not "defined ' +
          'twice"', JSON.stringify(twice));

  // The reader validates what it reads, so the refusal arrives there; the
  // validator and the PDP are each asked as well, of a model whose
  // reference is renamed after it was read.
  const read = attempt(function () {
    return xml.parsePolicy(policyXml(DENY_OVERRIDES, '',
                                     referenceIsX('constructor')));
  });
  t.check(/no VariableDefinition/.test(read.error || ''),
          'E4. a VariableReference to "constructor" is refused as undefined ' +
          'by the reader', JSON.stringify(read));
  const renamed = xml.parsePolicy(policyXml(DENY_OVERRIDES,
    variableXml('v', 'x'), referenceIsX('v')));
  const rename = function (node) {
    log.debug("Entering rename().");
    if (node && typeof node === 'object') {
      if (node.kind === 'variableRef') {
        node.variableId = 'constructor';
      }
      Object.keys(node).forEach(function (key) {
        rename(node[key]);
      });
    }
    log.debug("Leaving rename().");
  };
  rename(renamed.rules[0].condition);
  delete renamed.variables.v;
  const problems = validate.problemsIn(renamed);
  const answer = pdp.evaluate(renamed, { categories: [] });
  t.check(problems.some(function (one) {
    return /no VariableDefinition/.test(one);
  }) && answer.decision === model.DECISION.INDETERMINATE &&
          /no VariableDefinition/.test(answer.status.message || ''),
          'E5. and by the validator and the PDP, not as a cycle',
          JSON.stringify([problems, answer.status]));

  const fnXml = policyXml(DENY_OVERRIDES, '', '<Apply FunctionId="toString">' +
    '<AttributeValue DataType="' + STRING + '">x</AttributeValue></Apply>');
  const fn = attempt(function () {
    return validate.problemsIn(xml.parsePolicy(fnXml));
  });
  t.check(/Unknown function "toString"/.test(fn.error ||
                                            JSON.stringify(fn.value)),
          'E6. a FunctionId "toString" is an unknown function',
          JSON.stringify(fn));

  const set = function (ref) {
    log.debug("Entering set().");
    log.debug("Leaving set().");
    return xml.parsePolicy('<PolicySet xmlns="' + NS + '" PolicySetId="s" ' +
      'Version="1.0" PolicyCombiningAlgId="urn:oasis:names:tc:xacml:3.0:' +
      'policy-combining-algorithm:deny-overrides"><Target/>' +
      '<PolicyIdReference>' + ref + '</PolicyIdReference></PolicySet>');
  };
  const unresolved = pdp.evaluate(set('constructor'), { categories: [] },
                                  { repository: {} });
  t.check(/UnresolvedReference/.test(unresolved.status.message || ''),
          'E7. a PolicyIdReference to "constructor" is unresolved',
          JSON.stringify(unresolved.status));

  // A POLICY CALLED `__proto__` RESOLVES AS IT DID: by the accident of
  // becoming the repository's prototype before, and as itself now.
  const repository = {};
  ownMembers.put(repository, '__proto__',
                 xml.parsePolicy(policyXml(DENY_OVERRIDES)));
  t.equal(pdp.evaluate(set('__proto__'), { categories: [] },
                       { repository: repository }).decision,
          model.DECISION.PERMIT,
          'E8. a policy really called "__proto__" is still referenced');
  // A VARIABLE CALLED `__proto__` was refused as "defined twice" (the
  // reader found Object.prototype under the name); it is a variable now.
  const proto = attempt(function () {
    return xml.parsePolicy(policyXml(DENY_OVERRIDES,
      variableXml('__proto__', 'x'), referenceIsX('__proto__')));
  });
  t.check(!proto.error && validate.problemsIn(proto.value).length === 0 &&
          pdp.evaluate(proto.value, { categories: [] }).decision ===
            model.DECISION.PERMIT &&
          Object.keys(proto.value.variables).join() === '__proto__',
          'E9. a variable called "__proto__" is defined and read as an own ' +
          'member', JSON.stringify(proto.error || ''));
  log.debug("Leaving theEngine().");
}

function theEditor(t) {
  log.debug("Entering theEditor().");
  t.log.info('=== P. the editor\'s variables ===');
  const policy = templates.build('rbac', {}, { name: 'own-vars' }).policy;
  const added = editor.applyEdit(policy, '', 'add-variable',
                                 { variableId: 'toString' });
  t.check(added.ok && ownMembers.has(policy.variables, 'toString'),
          'P1. a variable called "toString" is added, not "already defined"',
          added.why || added.what);
  const renamed = editor.applyEdit(policy, 'variables.toString',
                                   'edit-variable',
                                   { variableId: 'constructor' });
  t.check(renamed.ok && ownMembers.has(policy.variables, 'constructor') &&
          !ownMembers.has(policy.variables, 'toString'),
          'P2. and renamed to "constructor"', renamed.why || renamed.what);
  const proto = editor.applyEdit(policy, '', 'add-variable',
                                 { variableId: '__proto__' });
  t.check(proto.ok && Object.getPrototypeOf(policy.variables) ===
            Object.prototype &&
          Object.keys(policy.variables).indexOf('__proto__') >= 0,
          'P3. a variable called "__proto__" is a member of the policy, ' +
          'not the prototype of its variables', proto.why || proto.what);
  const twice = editor.applyEdit(policy, '', 'add-variable',
                                 { variableId: 'constructor' });
  t.check(!twice.ok && /already defines/.test(twice.why || ''),
          'P4. and an own variable is still refused a second time',
          twice.why || twice.what);
  log.debug("Leaving theEditor().");
}

function theRepository(t) {
  log.debug("Entering theRepository().");
  t.log.info('=== S. the repository ===');
  require('../common/app');
  require('../ldap/ldap_server');
  const realms = require('../common/realms');
  const store = require('../xacml/xacml_store');
  const id = 'own-members-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  t.check(made.ok, 'S0. a trust realm of this file\'s own',
          (made.errors || []).join(' '));
  if (!made.ok) {
    log.debug("Leaving theRepository(). No realm.");
    return;
  }
  try {
    realms.run(made.realm, function () {
      log.debug("Entering inRealm().");
      const document = policyXml(DENY_OVERRIDES)
        .replace('PolicyId="p"', 'PolicyId="__proto__"');
      const written = store.write('own-proto', document, { enabled: true });
      const repository = store.repository();
      t.check(written.ok && ownMembers.has(repository, '__proto__') &&
              Object.getPrototypeOf(repository) === Object.prototype &&
              repository.rules === undefined,
              'S1. a policy whose id is "__proto__" is a member of the ' +
              'repository, and lends nothing to the other names',
              JSON.stringify(written));
      log.debug("Leaving inRealm().");
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving theRepository().");
}

function theAlfa(t) {
  log.debug("Entering theAlfa().");
  t.log.info('=== A. ALFA ===');
  const category = attempt(function () {
    return alfa.parse('namespace a {\n attribute r { category = ' +
      'constructor id = "urn:x:r" type = string }\n policy p {\n apply ' +
      'denyOverrides\n rule x { permit condition r == "a" }\n }\n}');
  });
  t.check(/Unknown category "constructor"/.test(category.error || ''),
          'A1. a category called "constructor" is unknown',
          JSON.stringify(category));
  const undeclared = attempt(function () {
    return alfa.parse('namespace a {\n policy p {\n apply denyOverrides\n ' +
      'rule x { permit condition toString == "a" }\n }\n}');
  });
  t.check(/never declared/.test(undeclared.error || ''),
          'A2. an undeclared attribute called "toString" is refused as ' +
          'undeclared', JSON.stringify(undeclared));
  t.check(alfa.algorithmUriOf('constructor') === null &&
          alfa.algorithmUriOf('denyOverrides') === DENY_OVERRIDES,
          'A3. "constructor" names no algorithm; denyOverrides still does');
  const declared = attempt(function () {
    return alfa.parse('namespace a {\n attribute constructor { category = ' +
      'resourceCat id = "urn:x:c" type = string }\n policy p {\n apply ' +
      'denyOverrides\n rule x { permit condition constructor == "a" }\n ' +
      '}\n}');
  });
  t.check(!declared.error &&
          JSON.stringify(declared.value).indexOf('urn:x:c') >= 0,
          'A4. an attribute really declared as "constructor" is read',
          JSON.stringify(declared.error || ''));
  log.debug("Leaving theAlfa().");
}

function theGnapVerdicts(t) {
  log.debug("Entering theGnapVerdicts().");
  t.log.info('=== G. GNAP right verdicts ===');
  const GR = gnapVerdicts.GNAP_RIGHT;
  const answer = function (assignments) {
    log.debug("Entering answer().");
    log.debug("Leaving answer().");
    return { obligations: [{ id: GR.OBLIGATION, assignments: assignments }] };
  };
  const word = gnapVerdicts.verdictOf(answer([
    { attributeId: GR.VERDICT, lexical: 'keep' },
    { attributeId: GR.INTERACTION, lexical: 'constructor' }]));
  t.equal(word && word.interaction, 'always',
          'G1. an interaction word "constructor" is unknown, and asks for ' +
          'the person');
  const drop = attempt(function () {
    return gnapVerdicts.verdictOf(answer([
      { attributeId: GR.VERDICT, lexical: 'keep' },
      { attributeId: 'constructor', lexical: 'x' }]));
  });
  t.check(!drop.error && drop.value.verdict === 'keep',
          'G2. an assignment named "constructor" is no drop list',
          JSON.stringify(drop));
  const real = gnapVerdicts.verdictOf(answer([
    { attributeId: GR.VERDICT, lexical: 'narrow' },
    { attributeId: GR.INTERACTION, lexical: 'none' },
    { attributeId: GR.DROP_ACTION, lexical: 'write' }]));
  t.check(real.interaction === 'none' &&
          real.drop.actions.join() === 'write' && real.verdict === 'narrow',
          'G3. the real words still read');
  log.debug("Leaving theGnapVerdicts().");
}

function theAuthzen(t) {
  log.debug("Entering theAuthzen().");
  t.log.info('=== Z. AuthZEN ===');
  const assign = function (name, value) {
    log.debug("Entering assign().");
    log.debug("Leaving assign().");
    return { attributeId: 'urn:example:' + name, type: model.TYPE.STRING,
             value: value };
  };
  const converted = authzenMap.obligationsOf({
    decision: model.DECISION.PERMIT, status: {}, advice: [],
    obligations: [{ id: 'urn:example:obligation:mark', assignments: [
      assign('constructor', 'a'), assign('__proto__', 'b'),
      assign('text', 'c'), assign('text', 'd')] }] });
  const properties = converted.handed[0] && converted.handed[0].properties;
  t.check(!!properties &&
          ownMembers.read(properties, 'constructor') === 'a' &&
          ownMembers.read(properties, '__proto__') === 'b' &&
          Object.getPrototypeOf(properties) === Object.prototype &&
          JSON.stringify(properties.text) === '["c","d"]' &&
          properties.xacml_obligation === 'urn:example:obligation:mark',
          'Z1. obligation properties named "constructor" and "__proto__" ' +
          'are the values assigned, and a repeat still becomes a list',
          JSON.stringify(properties));

  const facts = {};
  const deps = {
    log: log,
    mode: { current: function () {
      log.debug("Entering current().");
      log.debug("Leaving current().");
      return 'development';
    } },
    delegation: { partyFacts: function () {
      log.debug("Entering partyFacts().");
      log.debug("Leaving partyFacts().");
      return {};
    } },
    gate: { checkScopes: function (question) {
      log.debug("Entering checkScopes().");
      question.facts.forEach(function (one) {
        ownMembers.put(facts, one.scope, one.attributes.length);
      });
      log.debug("Leaving checkScopes().");
      return { verdicts: [] };
    } },
    scopeVerdicts: scopeVerdicts,
    scopePolicy: { judge: function () {
      log.debug("Entering judge().");
      log.debug("Leaving judge().");
      return {};
    } },
    rolePermissions: { asksFor: function () {
      log.debug("Entering asksFor().");
      log.debug("Leaving asksFor().");
      return false;
    } },
    loadOauth2: function () {
      log.debug("Entering loadOauth2().");
      log.debug("Leaving loadOauth2().");
      return { audienceScopes: function () {
        log.debug("Entering audienceScopes().");
        log.debug("Leaving audienceScopes().");
        return { permissions: [{ scope: 'read', permission: 'api.read',
                                 granted: true }] };
      } };
    }
  };
  const binding = new exchange.AuthzenTokenExchange(deps);
  const out = binding.scopeVerdicts({ scopeCache: {} },
    { type: 'user', id: 'alice' },
    { clientId: 'client', subjectToken: { scope: 'read' } },
    ['read', 'constructor', '__proto__'], false);
  t.check(facts.read === 4 && ownMembers.read(facts, 'constructor') === 2 &&
          ownMembers.read(facts, '__proto__') === 2,
          'Z2. a scope called "constructor" carries no delegated-permission ' +
          'fact; "read", which has one, still does', JSON.stringify(facts));
  t.check(Object.getPrototypeOf(out) === Object.prototype &&
          ownMembers.read(out, '__proto__').keep === true &&
          out.write === undefined && out.read.keep === true,
          'Z3. a scope called "__proto__" is a verdict, and no other scope ' +
          'inherits one from it');
  log.debug("Leaving theAuthzen().");
}

function theDetails(t) {
  log.debug("Entering theDetails().");
  t.log.info('=== O. RFC 9396 ===');
  const codes = INHERITED.map(function (name) {
    const r = details.parse(JSON.stringify([{ type: name }]));
    return name + '=' + (r.ok ? 'ok' : errorCodes.codeOf(r));
  });
  t.check(codes.every(function (one) {
    return /=STS-OAUTH-0453$/.test(one);
  }), 'O1. a detail whose type is an inherited name is an unknown type ' +
      '(section 5)', codes.join(' '));
  t.check(details.typeOf('constructor') === null &&
          details.maxLifetimeFor([{ type: 'constructor' }]) === null &&
          details.requiredAcrsOf([{ type: 'toString' }]).length === 0 &&
          details.bearerRefusedBy([{ type: 'valueOf' }]) === '',
          'O2. and no other reader of the catalogue finds one');
  log.debug("Leaving theDetails().");
}

// Each section is run on its own, so a throw in one (what an inherited
// member read as a value tends to do) is a failed check of that section and
// the sections after it still run.
function section(t, name, body) {
  log.debug("Entering section(). " + name);
  const tried = attempt(function () {
    return body(t);
  });
  t.check(!tried.error, name + ' ran to its end', tried.error || '');
  log.debug("Leaving section().");
}

async function run(t) {
  log.debug("Entering run().");
  section(t, 'H', theHelper);
  section(t, 'R', theRowGrammar);
  section(t, 'J', theJsonProfile);
  section(t, 'E', theEngine);
  section(t, 'P', theEditor);
  section(t, 'S', theRepository);
  section(t, 'A', theAlfa);
  section(t, 'G', theGnapVerdicts);
  section(t, 'Z', theAuthzen);
  section(t, 'O', theDetails);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'own_members',
  describe: 'a name a caller chose reads an own member, never an inherited ' +
            'one: XACML, AuthZEN, FGA and RFC 9396 (2026-11-12)',
  run: run
};
