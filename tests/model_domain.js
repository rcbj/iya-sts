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
  const classes = fs.readFileSync(path.join(ROOT, 'models', 'generated',
    'domain_classes.txt'), 'utf8');
  t.check(fs.readFileSync(path.join(ROOT, 'common', 'domain_classes.ts'),
    'utf8') === classes, 'common/domain_classes.ts is what the model generates');
  const api = fs.readFileSync(path.join(ROOT, 'models', 'generated', 'api.d.ts'),
    'utf8');
  t.check(fs.readFileSync(path.join(ROOT, 'types', 'api.generated.d.ts'),
    'utf8') === api, 'types/api.generated.d.ts is what the model generates');
  const Classes = require('../common/domain_classes');
  t.equal(Classes.User.fromEntry({ uid: ['a'] }).username, 'a',
    'a generated class makes its concept');
  t.check(/interface User \{/.test(built) &&
    !/interface User \{[^}]*password/i.test(built),
  'the User declaration has no password');
  log.debug("Leaving declarations().");
}

function projectionsAreReal(t) {
  log.debug("Entering projectionsAreReal().");
  const concepts = DomainMap.catalogue();
  const rows = ModelTables.file('api.projections.json');
  t.check(rows.length >= 15, 'published shapes are tied to concepts (' +
    rows.length + ')');
  rows.forEach(function (row) {
    const fields = concepts.get(row.concept).fields.map(function (one) {
      return one.name;
    });
    const shared = row.fields.filter(function (one) {
      return fields.indexOf(one) >= 0;
    });
    t.check(shared.length >= 3, row.name + ' shares fields with ' +
      row.concept, shared.join(','));
  });
  log.debug("Leaving projectionsAreReal().");
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

// THE SERVICE READS THESE RECORDS THROUGH THEIR CONCEPTS (#1579): each
// reader below is asked with `DomainMap.fromRecord()` watched, so a reader
// that goes back to the raw record fails here. The audit export's wire
// format is held byte for byte, because reading through the concept must not
// change what a destination receives.
async function readers(t) {
  log.debug("Entering readers().");
  const realms = require('../common/realms');
  const authn = require('../authn/authn');
  const logout = require('../logout/logout');
  const adminViews = require('../admin-core/admin_views');
  const audit = require('../common/audit');
  const AuditExport = require('../common/audit_export').AuditExport;
  const asked = [];
  const original = DomainMap.fromRecord;
  DomainMap.fromRecord = function (name, record, options, at) {
    asked.push(name);
    return original.call(DomainMap, name, record, options, at);
  };
  const through = function (name, what, fn) {
    asked.length = 0;
    const out = fn();
    t.check(asked.indexOf(name) >= 0, what + ' reads through ' + name,
      JSON.stringify(asked));
    return out;
  };
  const res = { req: null };
  ['set', 'append', 'status', 'type', 'send'].forEach(function (name) {
    res[name] = function () {
      return res;
    };
  });
  try {
    await realms.run(realms.DEFAULT_REALM, async function () {
      const session = await authn.startSession(res, 'domain-reader', ['pwd'],
        'urn:x', 'OAuth 2.0 / OIDC', { credential: { kind: 'password' } });
      const first = session.events[0].at;
      t.equal(through('Session', 'authn.sessionStartedAt()', function () {
        return authn.sessionStartedAt(session);
      }), first * 1000, 'a session began at its first event');
      t.equal(through('Session', 'authn.lastAuthenticatedAt()', function () {
        return authn.lastAuthenticatedAt(session);
      }), first, 'and was last authenticated at its latest');
      t.equal(through('Session', 'authn.signOnFactsFor()', function () {
        return authn.signOnFactsFor(session);
      }).acr, 'urn:x', 'the sign-on facts are the concept\'s');
      const rows = through('Session', 'logout.liveSessions()', function () {
        return logout.liveSessions([session]);
      });
      t.equal(rows.length && rows[0].username, 'domain-reader',
        'the session list draws the concept');
      through('Session', 'the console\'s sign-on session rows', function () {
        return adminViews.signOnSessionRows([session]);
      });
      const stats = require('../common/admin_stats');
      const now = Math.floor(Date.now() / 1000);
      stats.recordJwt({ iss: 'i', sub: 's', aud: 'a', exp: now + 600,
        iat: now, jti: 'model-domain-reader-jti', typ: 'Bearer', scope: 'x',
        username: 'domain-reader', client_id: 'c' }, 'h.p.s',
      { kind: 'access_token', client: 'c' });
      const inventory = through('IssuedToken', 'the sign-out inventory',
        function () {
          return logout.inventoryFor(stats.identityKeyOf('domain-reader'));
        });
      t.check(JSON.stringify(inventory).indexOf('model-domain-reader-jti') >= 0,
        'and lists the token');
      audit.audit({ category: 'admin', action: 'admin.test', actor: 'a',
        target: 'model-domain-reader', summary: 'model_domain' });
      t.check(through('AuditEvent', 'the audit view\'s filter', function () {
        return adminViews.auditView({ q: 'model-domain-reader' });
      }).json.matched >= 1, 'and finds the row');
    });
    const row = { seq: 7, origin: 'proc-1', at: 1700000000000,
      category: 'admin', action: 'admin.test', outcome: 'refused',
      errorCode: 'STS-CORE-0001', actor: 'alice', actorForm: 'alice@R',
      target: 't', protocol: 'SCIM 2.0', channel: 'http',
      address: '10.0.0.1', summary: 'S', prev: '', mac: 'm',
      detail: { client_id: 'c1', note: 'n' } };
    const opts = { origin: '', realm: 'r', source: 'sts', names: new Set() };
    const event = through('AuditEvent', 'the audit export', function () {
      return AuditExport.canonical(row, opts);
    });
    t.equal(JSON.stringify(event), JSON.stringify({
      id: 'proc-1:7', seq: 7, origin: 'proc-1',
      timestamp: '2023-11-14T22:13:20.000Z', at: 1700000000000,
      severity: AuditExport.severityName('refused'), category: 'admin',
      action: 'admin.test', outcome: 'refused', errorCode: 'STS-CORE-0001',
      source: 'sts', realm: 'r', subject: 'alice', subjectForm: 'alice@R',
      client: 'c1', address: '10.0.0.1', target: 't', protocol: 'SCIM 2.0',
      channel: 'http', message: 'S',
      attributes: AuditExport.redact(row.detail, opts.names)
    }), 'the audit export\'s event is what it was before the concept');
  } finally {
    DomainMap.fromRecord = original;
  }
  log.debug("Leaving readers().");
}

async function run(t) {
  log.debug("Entering run().");
  const lib = await import(url.pathToFileURL(path.join(ROOT, 'models', 'lib',
    'domain_lib.mjs')).href);
  refusals(t, lib.checkDomains);
  catalogue(t);
  projectionsAreReal(t);
  declarations(t);
  mapping(t);
  await records(t);
  await readers(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_domain',
  describe: 'the canonical domain models, held to the directory (#1390)',
  run: run
};
