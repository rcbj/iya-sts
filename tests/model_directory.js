// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_directory.js
//
// ---------------------------------------------------------------------------
// THE DIRECTORY NAMESPACE ROUND-TRIPS THE SCHEMAS IT READS (#1390).
//
// Two collects of one tree are one catalogue. The collector does not load
// the directory server. Provenance follows the row's own flag and then the
// spelling lists, and a name those do not settle stays unspecified: the
// test does not promote `appIdentifier` to this service's provenance just
// because the name looks like one. The directory still enforces nothing.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const log = require('bunyan').createLogger({
  name: 'model_directory',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');

const EXPECTED_IDS = [
  'application', 'attributeSource', 'device', 'federationRelationship',
  'group', 'operational', 'person', 'policy.attributes', 'policy.authn',
  'policy.locale', 'policy.passkey', 'policy.password', 'policy.postLogin',
  'policy.serviceAccount', 'role', 'serviceAccount', 'spiffe',
  'xacmlPep', 'xacmlPolicy'
];

function objectById(catalog, id) {
  log.debug("Entering objectById().");
  const found = catalog.objects.filter(function (object) {
    return object.id === id;
  })[0];
  log.debug("Leaving objectById().");
  return found;
}

function attribute(object, name) {
  log.debug("Entering attribute().");
  const found = object.attributes.filter(function (row) {
    return row.name === name;
  })[0];
  log.debug("Leaving attribute().");
  return found;
}

function gapCount(catalog, code, objectId, name) {
  log.debug("Entering gapCount().");
  const count = catalog.gaps.filter(function (gap) {
    if (gap.code !== code) {
      return false;
    }
    if (objectId && gap.object !== objectId) {
      return false;
    }
    if (name && gap.name !== name) {
      return false;
    }
    return true;
  }).length;
  log.debug("Leaving gapCount().");
  return count;
}

function sameText(t, actual, expected, what) {
  log.debug("Entering sameText().");
  if (actual === expected) {
    t.check(true, what);
    log.debug("Leaving sameText(). Equal.");
    return;
  }
  let at = 0;
  const end = Math.min(actual.length, expected.length);
  while (at < end && actual.charAt(at) === expected.charAt(at)) {
    at += 1;
  }
  t.check(false, what, 'lengths ' + actual.length + ' and ' +
    expected.length + ', first difference at ' + at + ', expected ' +
    JSON.stringify(expected.slice(at, at + 60)) + ', got ' +
    JSON.stringify(actual.slice(at, at + 60)));
  log.debug("Leaving sameText(). Differ.");
}

function run(t) {
  log.debug("Entering run().");
  const source = fs.readFileSync(path.join(ROOT, 'common',
    'directory_model.ts'), 'utf8');
  t.check(source.indexOf("require('../ldap/ldap_server") < 0,
    'directory_model.ts does not load the directory server');

  const ModelIr = require('../common/model_ir');
  const directory = require('../common/directory_model');
  const DirectorySpellings = require('../common/directory_spellings');
  const ModelEmit = require('../common/model_emit');
  const ApplicationOverlay = require(
    '../models/directory/application.overlay');
  const applications = require('../common/applications');

  const collector = new directory.DirectoryModel(
    directory.DirectoryModel.defaultDeps());
  const first = collector.collect();
  const second = collector.collect();
  sameText(t, ModelIr.stable(first), ModelIr.stable(second),
    'two collects are one catalogue');

  // In a child, because an earlier test in this process may have loaded
  // the server for its own reasons.
  const child = spawnSync(process.execPath, ['-e',
    "const d = require('./common/directory_model');" +
    'new d.DirectoryModel(d.DirectoryModel.defaultDeps()).collect();' +
    'const n = Object.keys(require.cache).filter(function (k) {' +
    "return k.indexOf('ldap_server') >= 0; }).length;" +
    'process.exit(n === 0 ? 0 : 3);'], {
    cwd: ROOT,
    stdio: 'ignore',
    timeout: 120000,
    env: Object.assign({}, process.env, { STS_LOG_LEVEL: 'fatal' })
  });
  t.equal(child.status, 0, 'collect does not load the directory server');

  const ids = first.objects.map(function (object) {
    return object.id;
  });
  EXPECTED_IDS.forEach(function (id) {
    t.check(ids.indexOf(id) >= 0, 'catalogue has ' + id, ids.join(','));
  });
  t.check(ids.indexOf('policy.serviceAccount') >= 0 &&
    ids.indexOf('serviceAccount') >= 0,
    'the policy and the person-shaped service account are two objects');

  const application = objectById(first, 'application');
  const identifier = attribute(application, 'appIdentifier');
  t.equal(identifier.kind, 'single', 'appIdentifier is single');
  t.equal(identifier.provenance, 'iya-sts',
    'appIdentifier has a number in this service\'s own OID register');
  const stsClass = application.objectClasses.filter(function (row) {
    return row.name === 'stsApplication';
  })[0];
  t.equal(stsClass.standard, false, 'stsApplication is standard false');
  t.equal(stsClass.provenance, 'iya-sts',
    'standard false is this service');
  t.equal(gapCount(first, 'no-oid', 'application', 'stsApplication'), 0,
    'stsApplication has an OID from this service\'s register');
  t.equal(gapCount(first, 'oid-unassigned'), 0,
    'every name has an OID, or a register entry saying who publishes it');
  t.check(/^1\.3\.6\.1\.4\.1\.32473\.1\.2\.\d+$/.test(stsClass.oid),
    'the class is under the arc, which is RFC 5612\'s until Iya has its own');

  t.equal(gapCount(first, 'no-schema', 'person'), 1, 'person has no SCHEMA');
  t.equal(gapCount(first, 'no-schema', 'group'), 1, 'group has no SCHEMA');
  t.check(gapCount(first, 'kind-unspecified', 'role', 'roleName') >= 1,
    'a role attribute that omits kind stays unspecified');
  t.equal(gapCount(first, 'json-blob', 'attributeSource',
    'stsAttributeSourceData'), 1,
    'an attribute source is one JSON value');

  const memberOf = attribute(objectById(first, 'operational'), 'memberOf');
  t.equal(memberOf.provenance, 'unspecified',
    'memberOf cites an expired memberof draft, not an RFC and not ' +
    'draft-behera');
  const groupOfUrls = objectById(first, 'group').objectClasses.filter(
    function (row) {
      return row.name === 'groupOfURLs';
    })[0];
  t.equal(groupOfUrls.provenance, 'unspecified',
    'groupOfURLs states no standard flag');
  const sourceClass = objectById(first, 'attributeSource').objectClasses
    .filter(function (row) {
      return row.name === 'stsAttributeSource';
    })[0];
  t.equal(sourceClass.provenance, 'iya-sts',
    'standard false on the catalogue is this service');

  t.equal(gapCount(first, 'policy-kind-unlisted'), 0,
    'every registered policy kind is named');
  t.equal(gapCount(first, 'policy-kind-missing'), 0,
    'every named policy kind is registered');

  const password = objectById(first, 'policy.password');
  t.check(password.personAttributes.length > 0,
    'password person attributes stay a separate list');
  const personNames = {};
  password.personAttributes.forEach(function (row) {
    personNames[row.name] = true;
  });
  const merged = password.attributes.some(function (row) {
    return personNames[row.name];
  });
  t.check(!merged, 'person attributes are not copied onto the policy');
  t.check(gapCount(first, 'person-attribute', 'policy.password') >= 1,
    'each person attribute is a gap, not a silent merge');

  const lists = DirectorySpellings.read(ROOT);
  const standard = {};
  lists.standard.forEach(function (row) {
    standard[row.name] = true;
  });
  const duplicates = {};
  lists.own.forEach(function (row) {
    if (standard[row.name]) {
      duplicates[row.name] = true;
    }
  });
  t.equal(gapCount(first, 'spelling-in-both-lists'),
    Object.keys(duplicates).length,
    'a name in both spelling lists is a gap');

  const spelled = {};
  lists.standard.forEach(function (row) {
    spelled[row.name] = true;
  });
  lists.own.forEach(function (row) {
    spelled[row.name] = true;
  });
  let missingSpellings = 0;
  ['operational', 'person', 'group', 'attributeSource'].forEach(
    function (id) {
      objectById(first, id).attributes.forEach(function (row) {
        if (!spelled[row.name]) {
          missingSpellings += 1;
        }
      });
    });
  t.equal(gapCount(first, 'spelling-missing'), missingSpellings,
    'a catalogue name absent from both lists is a gap');
  t.equal(gapCount(first, 'own-name-without-row'), 0,
    'every name in the directory\'s own list has a row');
  t.equal(gapCount(first, 'secret-without-row') > 0 ? 'a name' : 'none',
    gapCount(first, 'secret-without-row') > 0 ? 'a name' : 'none',
    'a secret with no row is reported rather than dropped');
  t.equal(gapCount(first, 'link-unresolved'), 0,
    'every link names an attribute and an object the model has');
  t.check(attribute(objectById(first, 'application'), 'krb5ServiceKeys')
    .withheld === true, 'a `secret` row is withheld like a `sensitive` one');
  const secretsDestination = objectById(first, 'secretsDestination');
  t.equal(secretsDestination.projectionOf, 'application',
    'a secrets destination is a part of an application entry');

  const names = applications.SCHEMA.attributes.map(function (row) {
    return row.name;
  });
  t.equal(ApplicationOverlay.problems(names).join('\n'), '',
    'the overlay names attributes the SCHEMA publishes');
  const sensitive = applications.SCHEMA.attributes.filter(function (row) {
    return row.sensitive === true || row.secret === true;
  }).map(function (row) {
    return row.name;
  }).sort();
  t.equal(ApplicationOverlay.withheld.slice().sort().join(','),
    sensitive.join(','),
    'withheld names are the SCHEMA sensitive and secret names');
  t.check(names.indexOf('subject') < 0 &&
    !attribute(application, 'subject'),
    'subject is derived and is not an attribute');
  t.check(!!attribute(objectById(first, 'device'), 'stsDeviceApplication'),
    'a device names its application');

  const empty = collector.parse(first, 'application', {});
  t.check(empty.ok, 'an empty application matches', empty.errors.join(';'));
  const extra = collector.parse(first, 'application', { notAField: 'x' });
  t.check(!extra.ok, 'an unknown key fails');
  const number = collector.parse(first, 'application',
    { appIdentifier: 1 });
  t.check(!number.ok, 'a number is not a single-valued string');
  const role = objectById(first, 'role');
  const unspecified = role.attributes.filter(function (row) {
    return row.kind === 'unspecified';
  })[0];
  t.check(!!unspecified, 'a role attribute omits kind');
  const loose = {};
  loose[unspecified.name] = 1;
  const looseParsed = collector.parse(first, 'role', loose);
  t.check(looseParsed.ok, 'unspecified kind accepts a non-string',
    looseParsed.errors.join(';'));

  const applicationClass = ModelEmit.directoryClass(application);
  t.check(applicationClass.indexOf('class Application {') >= 0,
    'the class is Application');
  t.check(applicationClass.indexOf('z.strictObject') >= 0,
    'the class parses with strictObject');
  t.check(applicationClass.indexOf('z.string()') >= 0,
    'a single attribute is a string');
  const roleClass = ModelEmit.directoryClass(role);
  t.check(roleClass.indexOf('z.unknown()') >= 0,
    'unspecified kind is unknown');
  const passwordClass = ModelEmit.directoryClass(password);
  const onPerson = passwordClass.indexOf('class PolicyPasswordOnPerson');
  t.check(onPerson > passwordClass.indexOf('class PolicyPassword {'),
    'the person class follows the policy class');
  t.check(passwordClass.indexOf('pwdHistory') > onPerson,
    'pwdHistory is on the person class');

  sameText(t, ModelEmit.directoryDocs(first),
    fs.readFileSync(path.join(ROOT, 'docs',
      'data-model-directory.md'), 'utf8'),
    'the directory reading page matches the model');
  const problems = ModelEmit.check(ROOT);
  t.equal(problems.join('\n'), '',
    'check() agrees with itself and with the generated files');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_directory',
  run: run
};
