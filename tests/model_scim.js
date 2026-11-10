// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_scim.js
//
// ---------------------------------------------------------------------------
// THE SCIM MODEL, AND WHAT HOLDS IT TO THE DIRECTORY (#1579).
//
// `models/scim/scim.tsp` states SCIM's schemas and the attribute mapping, and
// the build's check (`models/lib/scim_lib.mjs`'s checkScim()) is what stops a
// wrong one. The generated table the image carries is asserted clean against
// the real directory objects, and each refusal is asserted on a copy of it
// with one thing broken. That the generated table answers on the wire exactly
// as the hand-written one did is `tests/scim_model_wire.js`'s.
// ---------------------------------------------------------------------------

const path = require('path');
const url = require('url');

const log = require('bunyan').createLogger({
  name: 'model_scim',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');
const ModelTables = require('../common/model_tables');

// The directory objects a mapping row's attribute is found on, as
// `readDirectory()` hands them to the check.
function objects() {
  log.debug("Entering objects().");
  const out = ['person', 'group', 'operational'].map(function (id) {
    return { id: id, attributes: ModelTables.schema(id).attributes,
             personAttributes: [] };
  });
  log.debug("Leaving objects().");
  return out;
}

// A copy of the generated table, for one thing to be broken in.
function copy() {
  log.debug("Entering copy().");
  log.debug("Leaving copy().");
  return JSON.parse(JSON.stringify(ModelTables.file('scim.json')));
}

// A schema of a copy, by name.
function schema(scim, name) {
  log.debug("Entering schema().");
  log.debug("Leaving schema().");
  return scim.schemas.filter(function (one) {
    return one.name === name;
  })[0];
}

// An attribute of a schema, or a sub-attribute of an attribute, by name.
function attribute(owner, name) {
  log.debug("Entering attribute().");
  log.debug("Leaving attribute().");
  return (owner.attributes || owner.subAttributes).filter(function (one) {
    return one.name === name;
  })[0];
}

async function run(t) {
  log.debug("Entering run().");
  const lib = await import(url.pathToFileURL(path.join(ROOT, 'models', 'lib',
    'scim_lib.mjs')).href);
  const held = objects();
  const refused = function (what, pattern, broken) {
    const said = lib.checkScim(broken, held).join('; ');
    t.check(pattern.test(said), 'refused: ' + what, said || '(nothing)');
  };

  const generated = ModelTables.file('scim.json');
  t.check(lib.checkScim(generated, held).length === 0,
          'the generated SCIM model is clean against the directory objects',
          lib.checkScim(generated, held).join('; '));
  t.check(['User', 'Group', 'EnterpriseUser', 'IyaStsUser',
           'CustomAttributes'].join(',') ===
          generated.schemas.map(function (one) {
            return one.name;
          }).join(','), 'it states the five schemas /Schemas lists, in order');
  t.check(generated.mapping.user.length === 38 &&
          generated.mapping.group.length === 5,
          'it states the User table\'s 38 rows and the Group table\'s 5',
          generated.mapping.user.length + ', ' +
          generated.mapping.group.length);

  let broken = copy();
  broken.mapping.user[0].ldap = 'noSuchAttribute';
  refused('a row kept in an attribute no directory object declares',
          /noSuchAttribute, which no directory object declares/, broken);

  broken = copy();
  broken.mapping.group[0].ldap = 'mail';
  refused('a Group row kept in a person\'s attribute',
          /group row 1 .* is kept in mail/, broken);

  broken = copy();
  attribute(attribute(schema(broken, 'User'), 'emails'), 'type')
    .canonicalValues.push('home');
  refused('a type no row stores', /offers work,home and its rows store work/,
          broken);

  broken = copy();
  schema(broken, 'User').attributes.push({ name: 'nickName', type: 'string',
    multiValued: false, required: false, mutability: 'readWrite',
    direction: 'both' });
  refused('a published attribute the directory has no place for (#206)',
          /User.nickName is published and the directory has no place/,
          broken);

  broken = copy();
  delete attribute(schema(broken, 'User'), 'profileUrl').referenceTypes;
  refused('a reference with no referenceTypes',
          /profileUrl is a reference and names no referenceTypes/, broken);

  broken = copy();
  schema(broken, 'IyaStsUser').shipped = true;
  refused('a shipped schema scimmy has no class for',
          /IyaStsUser is not one/, broken);

  broken = copy();
  broken.mapping.user[3].row = 99;
  refused('a row out of sequence', /out of sequence/, broken);

  broken = copy();
  schema(broken, 'User').extensions.push({
    schema: 'urn:ietf:params:scim:schemas:extension:x:2.0:User',
    required: false });
  refused('an extension the model does not declare',
          /which the model does not declare/, broken);

  broken = copy();
  broken.mapping.user[0].section = undefined;
  refused('a required row with no section to cite',
          /is required and names no section/, broken);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_scim',
  describe: 'the SCIM model, held to the directory (#1579): the generated ' +
            'table is clean, and each of the build\'s refusals bites',
  run: run
};
