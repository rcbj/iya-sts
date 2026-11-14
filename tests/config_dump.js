// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: config_dump.js
//
// ===========================================================================
// WHAT THE CONFIGURATION DUMP HIDES, AND WHAT IT MUST STILL SHOW.
//
// The masking is admin-core/config_dump.ts's. A secret that survives it leaves
// the service in a file somebody will attach to a ticket; a pointer it hides
// makes the dump useless for the question it exists to answer. Both halves
// are held here, and tests/protocol/sts_config_dump.js holds the running door.
// ===========================================================================

const helpers = require('../common/helpers');
const { ConfigDump, MASK } = require('../admin-core/config_dump');

const log = helpers.log;

function checkNames(t) {
  log.debug("Entering checkNames().");
  ['global.edgeSecret', 'admin.bootstrapPassword', 'keys.kekToken',
    'adminApi.clientSecret', 'krb5.servicePassword', 'krb5.serviceSalt',
    'scim.digestPassword', 'persistence.databasePasswordToken',
    'keys.vaultClientKey', 'future.apiKey', 'future.privateKey',
    'future.clientCredential'].forEach(function (key) {
    t.check(ConfigDump.nameIsSensitive(key), key + ' is masked by name');
  });
  ['mail.smtpPasswordRef', 'persistence.databasePasswordField',
    'persistence.databasePasswordVault', 'tls.keyFile', 'keys.kekFile',
    'spiffe.k8sTokenFile', 'gnap.tokenFormats', 'global.logLevel',
    'authn.passwordAloneDoors', 'auditExport.redactKeys',
    'oauth2.dynamicRegistrationTokenResponseTypes']
    .forEach(function (key) {
      t.check(!ConfigDump.nameIsSensitive(key), key + ' is shown');
    });
  log.debug("Leaving checkNames().");
}

function checkText(t) {
  log.debug("Entering checkText().");
  const canary = 'canary-value-9f31';
  [['postgres://sts:' + canary + '@db:5432/sts', 'a URL\'s password'],
    ['-----BEGIN PRIVATE KEY-----\n' + canary + '\n-----END PRIVATE KEY-----',
      'a PEM private key'],
    ['-----BEGIN EC PRIVATE KEY-----\n' + canary, 'an unterminated PEM key'],
    ['Bearer ' + canary, 'an authorization header'],
    ['Endpoint=sb://x;AccessKey=' + canary, 'a connection string'],
    ['{"kty":"EC","crv":"P-256","d":"' + canary + '"}', 'a JWK']]
    .forEach(function (one) {
      const out = ConfigDump.maskText(one[0]);
      t.check(out.indexOf(canary) < 0, one[1] + ' is masked');
      t.check(out.indexOf(MASK) >= 0, one[1] + ' shows the mask');
    });
  const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlMTIz';
  t.equal(ConfigDump.maskText(jwt), MASK, 'a JWT is masked');
  ['https://sts.example.net:8443/path', 'password,secret,token',
    '/run/secrets/sts-kek', 'postgres://db:5432/sts']
    .forEach(function (plain) {
      t.equal(ConfigDump.maskText(plain), plain, plain + ' is left alone');
    });
  log.debug("Leaving checkText().");
}

function row(key, type, value, dflt) {
  log.debug("Entering row().");
  log.debug("Leaving row().");
  return { key: key, group: 'G', label: 'L', description: 'D', type: type,
           value: value, default: dflt, text: String(value), source: 'env',
           env: 'E', overridden: false, editable: true };
}

function checkRows(t) {
  log.debug("Entering checkRows().");
  const none = new Set();
  const secret = ConfigDump.row(row('a.clientSecret', 'string', 'hunter2',
                                    'dflt-secret'), none);
  t.equal(secret.value, MASK, 'a secret value is masked');
  t.equal(secret.default, MASK, 'a secret default is masked');
  t.equal(secret.masked, true, 'the row says so');
  t.equal(secret.text, undefined, 'the one-line copy is not carried');
  t.equal(secret.description, undefined, 'prose is not carried');
  const marked = ConfigDump.row(row('a.opaque', 'string', 'hunter2', ''),
                                new Set(['a.opaque']));
  t.equal(marked.value, MASK, 'secret: true masks whatever the name');
  const empty = ConfigDump.row(row('a.clientSecret', 'string', '', ''), none);
  t.equal(empty.value, '', 'an unset secret stays visibly unset');
  t.equal(empty.masked, undefined, 'and hid nothing');
  const number = ConfigDump.row(row('a.tokenTtlMs', 'int', 5, 5), none);
  t.equal(number.value, 5, 'a number is shown');
  const list = ConfigDump.row(row('a.urls', 'csv',
    ['ldap://u:hunter2@h', 'ldap://h'], []), none);
  t.check(JSON.stringify(list).indexOf('hunter2') < 0,
          'a list element is read too');
  t.equal(list.value[1], 'ldap://h', 'and the rest of the list stands');
  log.debug("Leaving checkRows().");
}

function checkTable(t) {
  log.debug("Entering checkTable().");
  const none = new Set();
  const secret = ConfigDump.maskDescribed(
    row('a.clientSecret', 'string', 'hunter2', 'dflt'), none);
  t.equal(secret.value, MASK, 'the table masks the value');
  t.equal(secret.text, MASK, 'and the copy a form is drawn from');
  t.equal(secret.default, MASK, 'and the default');
  t.equal(secret.description, 'D', 'and keeps the rest of the row');
  const plain = row('a.plain', 'string', 'shown', 'shown');
  t.equal(ConfigDump.maskDescribed(plain, none).masked, undefined,
          'an ordinary row is not marked');
  const dump = new ConfigDump({
    log: log, config: { secretKeys: function () {
      return [];
    } },
    realms: {}, version: {}, auditLog: {}, now: function () {
      return new Date(0);
    }
  });
  const held = row('a.clientSecret', 'string', 'hunter2', '');
  t.check(dump.isEchoOfMask(held, MASK), 'a posted mask keeps the secret');
  t.check(!dump.isEchoOfMask(held, 'new-password'), 'a new value does not');
  t.check(!dump.isEchoOfMask(row('a.clientSecret', 'string', '', ''), MASK),
          'with no secret held the mask is just text');
  t.check(!dump.isEchoOfMask(row('a.plain', 'string', 'x', ''), MASK),
          'nor on an ordinary parameter');
  const keyed = new ConfigDump({
    log: log, realms: {}, version: {}, auditLog: {},
    now: function () {
      return new Date(0);
    },
    config: { SETTINGS: [{ key: 'a.opaque', type: 'string', secret: true },
                         { key: 'a.clientSecret', type: 'string' },
                         { key: 'a.tokenCount', type: 'int' }] }
  });
  t.equal(keyed.maskKeyed('a.opaque', 'x'), MASK, 'a value by its mark');
  t.equal(keyed.maskKeyed('a.clientSecret', 'x'), MASK, 'a value by its name');
  t.equal(keyed.maskKeyed('a.tokenCount', '5'), '5', 'not a number');
  t.equal(keyed.maskKeyed('gone.clientSecret', 'x'), MASK,
          'and a key the table no longer has errs towards hiding');
  t.equal(keyed.maskKeyed('a.clientSecret', ''), '', 'an unset one stays unset');
  const url = row('a.databaseUrl', 'string', 'postgres://u:pw@h/db', '');
  t.check(dump.isEchoOfMask(url, 'postgres://u:' + MASK + '@h/db'),
          'a partly masked value posted back keeps it too');
  log.debug("Leaving checkTable().");
}

function checkBuild(t) {
  log.debug("Entering checkBuild().");
  const audited = [];
  const realm = { id: 'acme', overrides: { 'a.clientSecret': 'x' } };
  let current = 'default';
  const build = function () {
    return new ConfigDump({
      log: log,
      now: function () {
        return new Date(0);
      },
      version: { load: function () {
        return { version: '1.0.0.0' };
      } },
      auditLog: { record: function (one) {
        audited.push(one);
      } },
      config: {
        secretKeys: function () {
          return [];
        },
        snapshot: function () {
          return { configFile: null, defaultsFile: 'd',
                   groups: [{ group: 'G', settings: [
                     row('a.clientSecret', 'string', 'global-canary', ''),
                     row('a.plain', 'string', 'shown', '')] }] };
        },
        describeKeys: function (keys) {
          return keys.map(function (key) {
            return row(key, 'string', 'realm-canary', '');
          });
        }
      },
      realms: {
        DEFAULT_ID: 'default',
        currentId: function () {
          return current;
        },
        list: function () {
          return [{ id: 'default' }, realm];
        },
        run: function (r, fn) {
          return fn();
        }
      }
    }).build('auditor');
  };
  const service = build();
  const text = JSON.stringify(service);
  t.check(text.indexOf('canary') < 0, 'no secret, global or realm, is in it');
  t.equal(service.scope, 'service', 'the default realm dumps the service');
  t.equal(service.realms.length, 1, 'every other realm');
  t.equal(service.realms[0].id, 'acme', 'named');
  t.equal(service.masking.maskedValues, 2, 'and the masked values counted');
  t.equal(audited[0].action, 'admin.config-dump', 'the read is audited');
  t.equal(audited[0].actor, 'auditor', 'with who asked');
  t.check(JSON.stringify(audited).indexOf('canary') < 0,
          'and the audit row carries no value');
  current = 'acme';
  const confined = build();
  t.equal(confined.scope, 'realm', 'a realm dumps itself');
  t.equal(confined.realms.length, 0, 'and sees no other realm');
  log.debug("Leaving checkBuild().");
}

function run(t) {
  log.debug("Entering run().");
  checkNames(t);
  checkText(t);
  checkRows(t);
  checkTable(t);
  checkBuild(t);
  log.debug("Leaving run().");
}

module.exports = { name: 'config_dump', run: run };
