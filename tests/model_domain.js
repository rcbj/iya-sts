// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_domain.js
//
// ---------------------------------------------------------------------------
// THE CANONICAL DOMAIN MODELS, AND WHAT HOLDS THEM TO THE DIRECTORY (#1390).
//
// `models/domain/` says what a concept means and where each field is stored.
// The build's check is what stops a wrong model, so its refusals are asserted
// here on fixtures; the catalogue the image carries is then asserted against
// the real directory objects, and an entry is mapped end to end.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const url = require('url');

const log = require('bunyan').createLogger({
  name: 'model_domain',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');
const DomainMap = require('../common/domain_map');
const ModelTables = require('../common/model_tables');

function field(extra) {
  log.debug("Entering field().");
  log.debug("Leaving field().");
  return Object.assign({ name: 'f', optional: true, type: 'string',
    from: { attr: 'a' } }, extra);
}

function directory(attribute) {
  log.debug("Entering directory().");
  log.debug("Leaving directory().");
  return [{ id: 'o', personAttributes: [],
    attributes: [Object.assign({ name: 'a', kind: 'single' }, attribute)] }];
}

function concept(one) {
  log.debug("Entering concept().");
  log.debug("Leaving concept().");
  return [{ name: 'C', area: 'Area', entry: 'o', fields: [one],
    invariants: [] }];
}

function refusals(t, checkDomains) {
  log.debug("Entering refusals().");
  const one = function (fieldRow, attribute) {
    return checkDomains(concept(fieldRow), directory(attribute)).join(';');
  };
  t.equal(one(field(), {}), '', 'a correct field passes');
  t.check(/does not declare/.test(one(field({ from: { attr: 'z' } }), {})),
    'an attribute the object does not declare is refused');
  t.check(/is not one/.test(one(field({ from: { attr: 'a', on: 'q' } }), {})),
    'a directory object that does not exist is refused');
  t.check(/does not say secret/.test(one(field(), { sensitive: true })),
    'a sensitive attribute read without saying so is refused');
  t.check(/does not say secret/.test(one(field(), { secret: true })),
    'a secret attribute read without saying so is refused');
  t.check(/does not say secret/.test(one(field(), { withheld: true })),
    'a withheld attribute read without saying so is refused');
  t.check(/does not say secret/.test(checkDomains(concept(field()),
    directory({}), ['A']).join(';')),
  'an attribute on the withheld list read without saying so is refused');
  t.check(/not marked sensitive/.test(
    one(field({ from: { attr: 'a', secret: true } }), {})),
  'a secret claimed of an ordinary attribute is refused');
  t.check(/transform/.test(one(field(), { kind: 'multi' })),
    'one value of a multi-valued attribute must say which');
  t.equal(one(field({ from: { attr: 'a', transform: 'first' } }),
    { kind: 'multi' }), '', 'and may, by saying transform: first');
  t.check(/holds one value/.test(one(field({ array: true }), {})),
    'a list over a single-valued attribute is refused');
  t.check(/holds one value/.test(one(field({ array: true }),
    { kind: 'unspecified', storedAs: 'single' })),
  'a stated type says one value where the kind is silent');
  t.check(/transform/.test(one(field(),
    { kind: 'unspecified', storedAs: 'multi' })),
  'and says several');
  t.check(/exactly one/.test(one(field({ derived: 'x' }), {})),
    'a field with two sources is refused');
  t.check(/held on a record/.test(checkDomains([{ name: 'C', area: 'Area',
    record: 'r', fields: [field()], invariants: [] }], directory({})).join(';')),
  'an attribute on a concept held on a record is refused');
  t.check(/entry and record/.test(checkDomains([{ name: 'C', area: 'Area',
    fields: [], invariants: [] }], directory({})).join(';')),
  'a concept held nowhere is refused');
  t.check(/exactly one/.test(one({ name: 'f', type: 'string' }, {})),
    'a field with no source is refused');
  t.check(/may not have/.test(one(field({ type: 'unknown' }), {})),
    'a type a concept may not have is refused');
  log.debug("Leaving refusals().");
}

function declarations(t) {
  log.debug("Entering declarations().");
  const committed = fs.readFileSync(path.join(ROOT, 'types',
    'domain.generated.d.ts'), 'utf8');
  const built = fs.readFileSync(path.join(ROOT, 'models', 'generated',
    'domain.d.ts'), 'utf8');
  t.check(committed === built, 'types/domain.generated.d.ts is what the ' +
    'model generates (tests/tools/regenerate-model-docs.sh)');
  t.check(/interface User \{/.test(built) &&
    !/interface User \{[^}]*password/i.test(built),
  'the User declaration has no password');
  log.debug("Leaving declarations().");
}

function catalogue(t) {
  log.debug("Entering catalogue().");
  const concepts = ModelTables.file('domain.json').concepts;
  const names = concepts.map(function (one) {
    return one.name;
  });
  ['User', 'Credential', 'Group', 'ServiceAccount', 'Device', 'Application',
    'OAuthClient', 'SamlServiceProvider', 'WsFederationRelyingParty', 'Role',
    'XacmlPolicy', 'FederationRelationship', 'TrustAnchor',
    'SignerTrustAnchor', 'Session', 'AuthenticationEvent', 'IssuedToken',
    'AuditEvent'].forEach(function (name) {
    t.check(names.indexOf(name) >= 0, name + ' is in the catalogue');
  });
  concepts.forEach(function (one) {
    t.check(one.what.length > 0 && one.area.length > 0,
      one.name + ' says what it is and where it belongs');
  });
  const user = concepts.filter(function (one) {
    return one.name === 'User';
  })[0];
  t.check(user.fields.every(function (one) {
    return !one.from || !one.from.secret;
  }), 'a User carries no field marked secret');
  t.check(user.invariants.map(function (one) {
    return one.id;
  }).indexOf('user.no-credential') >= 0, 'and says so as an invariant');
  log.debug("Leaving catalogue().");
}

function mapping(t) {
  log.debug("Entering mapping().");
  const entry = { APPIDENTIFIER: 'app-1', appName: ['Widgets'],
    appRegistered: 'TRUE', appFirstSeen: '20261109101112Z',
    appLastSeen: 'not a time',
    oauthClientId: ['c1'], oauthClientSecret: ['sealed'],
    oauthRedirectUri: ['https://a.example/cb', 'https://b.example/cb'] };
  const app = DomainMap.fromEntry('Application', entry,
    { derived: { realm: 'acme' } });
  t.equal(app.identifier, 'app-1', 'an attribute is found in any case');
  t.equal(app.displayName, 'Widgets', 'one value of a list is one value');
  t.equal(app.registered, true, 'TRUE is a boolean');
  t.equal(app.firstSeen, '2026-11-09T10:11:12Z', 'GeneralizedTime is a date');
  t.equal(app.lastSeen, undefined, 'a value that is not a date is left out');
  t.equal(app.realm, 'acme', 'a derived field comes from the caller');
  t.equal(app.oauth.redirectUris.length, 2, 'a list stays a list');
  t.equal(app.oauth.clientSecrets, undefined,
    'a secret is left out by default');
  t.equal(app.saml, undefined, 'a protocol it has nothing of is absent');
  t.equal(JSON.stringify(DomainMap.fromEntry('Application', entry,
    { secrets: ['oauth.clientSecrets'] }).oauth.clientSecrets),
  '["sealed"]', 'a secret is given to the caller who names it');
  t.equal(JSON.stringify(DomainMap.missing('Application', {})),
    '["identifier","realm"]', 'missing() names the required fields');
  const user = DomainMap.fromEntry('User', { uid: ['alice'], cn: ['A'],
    userPassword: 'x' }, { on: { operational: { entryUUID: 'u-1' } },
    derived: { realm: '' } });
  t.equal(JSON.stringify(user),
    '{"entryUuid":"u-1","username":"alice","realm":"","cn":["A"]}',
    'a User is its fields and no password, read across two objects');
  let threw = false;
  try {
    DomainMap.fromEntry('NoSuch', {});
  } catch (e) {
    log.debug("Caught in mapping(): " + ((e && e.message) || e));
    threw = true;
  }
  t.check(threw, 'a concept nobody declared is refused');
  log.debug("Leaving mapping().");
}

// A concept held on a record has no directory object to be checked against
// at build time, so it is held to REAL records here: every field that says
// where it lives must find a value of its type on one.
function heldToReal(t, name, record) {
  log.debug("Entering heldToReal().");
  const value = DomainMap.fromRecord(name, record);
  const fields = DomainMap.catalogue().get(name).fields;
  fields.filter(function (one) {
    return !one.optional;
  }).forEach(function (one) {
    t.check(value[one.name] !== undefined, name + '.' + one.name +
      ' is on a real record', JSON.stringify(Object.keys(record)));
  });
  log.debug("Leaving heldToReal().");
  return value;
}

async function records(t) {
  log.debug("Entering records().");
  const realms = require('../common/realms');
  const audit = require('../common/audit');
  const stats = require('../common/admin_stats');
  const authn = require('../authn/authn');
  const res = { req: null };
  ['set', 'append', 'status', 'type', 'send'].forEach(function (name) {
    res[name] = function () {
      return res;
    };
  });
  await realms.run(realms.DEFAULT_REALM, async function () {
    audit.audit({ category: 'admin', action: 'admin.test', actor: 'a',
      target: 't', summary: 'model_domain' });
    const event = heldToReal(t, 'AuditEvent', audit.list()[0]);
    t.equal(event.action, 'admin.test', 'an audit event maps');
    const now = Math.floor(Date.now() / 1000);
    stats.recordJwt({ iss: 'i', sub: 's', aud: 'a', exp: now + 60, iat: now,
      jti: 'model-domain-jti', typ: 'Bearer', scope: 'x' }, 'h.p.s',
    { kind: 'access_token', client: 'c' });
    const row = stats.tokenList().filter(function (one) {
      return one.jti === 'model-domain-jti';
    })[0];
    const token = heldToReal(t, 'IssuedToken', row);
    t.equal(token.subject, 's', 'an issued token maps');
    const session = await authn.startSession(res, 'domain-probe', ['pwd'],
      'urn:x', 'OAuth 2.0 / OIDC', { credential: { kind: 'password' } });
    const mapped = heldToReal(t, 'Session', session);
    t.equal(mapped.username, 'domain-probe', 'a nested member is reached');
    t.equal(mapped.events.length, 1, 'a list of concepts is mapped');
    t.equal(mapped.events[0].protocol, 'OAuth 2.0 / OIDC',
      'and each one is the concept');
    heldToReal(t, 'AuthenticationEvent', session.events[0]);
    t.check(JSON.stringify(mapped).indexOf(session.handleHash) < 0,
      'the browser handle\'s hash is not part of a Session');
  });
  log.debug("Leaving records().");
}

async function run(t) {
  log.debug("Entering run().");
  const lib = await import(url.pathToFileURL(path.join(ROOT, 'models', 'lib',
    'domain_lib.mjs')).href);
  refusals(t, lib.checkDomains);
  catalogue(t);
  declarations(t);
  mapping(t);
  await records(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_domain',
  describe: 'the canonical domain models, held to the directory (#1390)',
  run: run
};
