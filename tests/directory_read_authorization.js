'use strict';
//
// File: directory_read_authorization.js
//
// ---------------------------------------------------------------------------
// WHO MAY READ WHAT OVER THE DIRECTORY'S OWN SOCKET, IN PRODUCT MODE
// (#106, 2026-09-23).
//
// `ldap/directory_read_policy.ts` is the rule table and `ldap/ldap_server.js`
// asks it at three doors — a search's entries, a search's FILTER and a
// compare — and refuses a bind as anything that is not a person.
// `tests/directory_read_security.js` holds the bind, the credentials and the
// unbound read; this holds what a BOUND identity may see:
//
//   1. a person reads their OWN entry whole;
//   2. with `ldap.directoryReadableAttributes` empty (the default) another
//      person is not there — a base search and a compare answer noSuchObject
//      (32) with STS-LDAP-0013, exactly as a DN that does not exist;
//   3. widened, another person shows only the listed attributes, a FILTER
//      cannot see the rest (`(telephoneNumber=*)` matches nobody but the
//      reader), a compare of a listed one answers, and of any other one is
//      50 with STS-LDAP-0099 — whether or not the entry holds it;
//   4. a group is visible to its members only, without its member list unless
//      `ldap.groupMembersReadable`;
//   5. an application is invisible, and its container shows only itself;
//   6. Admin Read reads everything (no credential, still);
//   7. a realm's own administrator reads their realm and is nobody in the
//      default realm;
//   8. only a person binds: an application's DN is 49, STS-LDAP-0100;
//   9. the audit row counts what a search withheld;
//  10. development is unchanged — every one of those reads answers.
//
// **TWO HALVES, AND THEY ARE DIFFERENT CLAIMS.** Sections 1–10 go through
// `performOperation()`, the function a request worker runs a dispatched
// directory operation with — which is the handler the socket runs AND the proof
// that the one thing a worker cannot derive, the bound DN, reaches the check.
// Section 11 starts a CHILD in each mode with the directory's own LDAPS
// listener on 127.0.0.1:0 and drives it with a real ldapjs CLIENT, so the
// answers are what a directory client actually gets on the wire: the result
// codes, the absent attributes, the filter's silence.
//
// In process because `global.mode` is a runtime override here; everything
// written is taken back in a `finally`, because `run.js` runs every file in
// one process — and a role grant left behind would close the console's
// empty-roster door for every later file.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const config = require('../common/config');
const audit = require('../common/audit');
const credentials = require('../common/credentials');
const realms = require('../common/realms');
const ldap = require('../ldap/ldap_server');
const adminRbac = require('../admin-ui/admin_rbac');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({
  name: 'directory_read_authorization',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const STAMP = Date.now().toString(36);
const READER = 'readauth-reader-' + STAMP;
const OTHER = 'readauth-other-' + STAMP;
const ADMIN = 'readauth-admin-' + STAMP;
const REALM_ADMIN = 'readauth-radmin-' + STAMP;
const REALM = 'readauth' + STAMP;
const IN_GROUP = 'readauth-in-' + STAMP;
const OUT_GROUP = 'readauth-out-' + STAMP;
const APP = 'readauth-app-' + STAMP;
// Long and mixed, so a product-mode password policy has nothing to refuse.
const PASSWORD = 'Ra-' + STAMP + '-Correct.Horse.Battery.Staple.42';
const WIDENED = 'objectClass,cn,uid,mail';

function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug("Leaving withSettings().");
    return fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

function product(fn) {
  log.debug("Entering product().");
  log.debug("Leaving product().");
  return withSettings({ 'global.mode': 'product' }, fn);
}

function search(boundDn, base, filter, scope, attributes) {
  log.debug("Entering search().");
  log.debug("Leaving search().");
  return ldap.performOperation('search', {
    dn: base, boundDn: boundDn, channel: 'ldaps',
    scope: scope === undefined ? 2 : scope,
    filter: filter || '(objectclass=*)', attributes: attributes || [],
    sizeLimit: 0
  });
}

function compare(boundDn, dn, attribute, value) {
  log.debug("Entering compare().");
  log.debug("Leaving compare().");
  return ldap.performOperation('compare', {
    dn: dn, boundDn: boundDn, channel: 'ldaps', attribute: attribute,
    value: value
  });
}

function add(boundDn, dn, attributes) {
  log.debug("Entering add().");
  log.debug("Leaving add().");
  return ldap.performOperation('add', {
    dn: dn, boundDn: boundDn, channel: 'ldaps',
    attributes: Object.keys(attributes).map(function (type) {
      return { type: type, values: [].concat(attributes[type]) };
    })
  });
}

function replace(boundDn, dn, type, values) {
  log.debug("Entering replace().");
  log.debug("Leaving replace().");
  return ldap.performOperation('modify', {
    dn: dn, boundDn: boundDn, channel: 'ldaps',
    changes: [{ operation: 'replace',
                modification: { type: type, values: [].concat(values) } }]
  });
}

// The code on the most recent row naming this target. A code never reaches the
// client, so the audit row is the one place it can be read back.
function lastCodeFor(target) {
  log.debug("Entering lastCodeFor().");
  const row = audit.list().filter(function (event) {
    return event.target === target && event.errorCode;
  })[0];
  log.debug("Leaving lastCodeFor().");
  return row ? row.errorCode : '';
}

function refused(t, result, errorName, code, target, what) {
  log.debug("Entering refused().");
  t.check(result.ok === false && result.errorName === errorName,
          what + ' — refused with ' + errorName,
          JSON.stringify({ ok: result.ok, errorName: result.errorName,
                           error: result.error }));
  t.equal(lastCodeFor(target), code, what + ' — recorded as ' + code);
  log.debug("Leaving refused().");
}

// The DNs a search returned, normalised.
function dnsOf(result) {
  log.debug("Entering dnsOf().");
  log.debug("Leaving dnsOf().");
  return (result.entries || []).map(function (entry) {
    return ldap.normalizeDn(entry.objectName || entry.dn || '');
  });
}

// The attribute names one returned entry carries, lower-cased.
function namesOn(result, dn) {
  log.debug("Entering namesOn().");
  const wanted = ldap.normalizeDn(dn);
  const entry = (result.entries || []).filter(function (one) {
    return ldap.normalizeDn(one.objectName || one.dn || '') === wanted;
  })[0];
  log.debug("Leaving namesOn().");
  return entry ? (entry.attributes || []).map(function (attribute) {
    return String(attribute.type).toLowerCase();
  }) : null;
}

// Everything the ten sections need, made in development (where no write is
// authorized) so that product mode below only READS.
function setUp(t, made) {
  log.debug("Entering setUp().");
  [READER, OTHER, ADMIN].forEach(function (name) {
    ldap.createUser(name, { invent: false });
    made.people.push(name);
  });
  const dns = {
    reader: ldap.objectFor(READER).entry.dn,
    other: ldap.objectFor(OTHER).entry.dn,
    admin: ldap.objectFor(ADMIN).entry.dn,
    users: ldap.usersDn(),
    groups: ldap.groupsDn(),
    applications: ldap.applicationsDn()
  };
  dns.inGroup = 'cn=' + IN_GROUP + ',' + dns.groups;
  dns.outGroup = 'cn=' + OUT_GROUP + ',' + dns.groups;
  dns.app = 'cn=' + APP + ',' + dns.applications;
  dns.missing = 'uid=readauth-nobody-' + STAMP + ',' + dns.users;
  [[dns.reader, 'reader'], [dns.other, 'other']].forEach(function (pair) {
    replace('', pair[0], 'telephoneNumber', '+1 555 0100');
    replace('', pair[0], 'mail', pair[1] + '-' + STAMP + '@readauth.test');
  });
  const groupsMade = [
    add('', dns.inGroup, { objectClass: ['top', 'groupOfNames'],
                           cn: IN_GROUP, description: 'the reader is in it',
                           member: [dns.reader, dns.other] }),
    add('', dns.outGroup, { objectClass: ['top', 'groupOfNames'],
                            cn: OUT_GROUP, member: [dns.other] }),
    add('', dns.app, { objectClass: ['top', 'applicationProcess'],
                       cn: APP, description: 'an application entry' })
  ];
  groupsMade.forEach(function (result, index) {
    if (result.ok) {
      made.entries.push([dns.inGroup, dns.outGroup, dns.app][index]);
    }
  });
  t.check(groupsMade.every(function (r) { return r.ok === true; }),
          'precondition: two groups and an application entry were added',
          JSON.stringify(groupsMade));
  const set = credentials.setPassword(READER, PASSWORD);
  t.check(set && set.ok !== false,
          'precondition: the reader has a password', JSON.stringify(set));
  log.debug("Leaving setUp().");
  return dns;
}

function development(t, dns) {
  log.debug("Entering development().");
  t.log.info('=== 10. development is unchanged ===');
  const everyone = search(dns.reader, dns.users);
  t.check(dnsOf(everyone).indexOf(ldap.normalizeDn(dns.other)) !== -1 &&
          (namesOn(everyone, dns.other) || []).indexOf('telephonenumber') !==
            -1,
          'in development a person reads another person whole',
          JSON.stringify(namesOn(everyone, dns.other)));
  t.check(search(dns.reader, dns.app, null, 0).ok === true &&
          search(dns.reader, dns.outGroup, null, 0).ok === true,
          'and an application and a group they are not in');
  const phone = compare(dns.reader, dns.other, 'telephoneNumber',
                        '+1 555 0100');
  t.check(phone.ok === true && phone.endArg === true,
          'and compares another person\'s telephoneNumber',
          JSON.stringify(phone));
  const appBind = ldap.performOperation('bind', {
    dn: dns.app, boundDn: '', channel: 'ldaps', credentials: 'anything',
    remoteAddress: '203.0.113.7' });
  t.check(appBind.ok === true,
          'and an application\'s DN binds, as every DN does there',
          JSON.stringify(appBind));
  log.debug("Leaving development().");
}

function selfAndOthers(t, dns) {
  log.debug("Entering selfAndOthers().");
  t.log.info('=== 1. a person reads their own entry whole ===');
  const own = search(dns.reader, dns.reader, null, 0, ['*', 'memberOf']);
  const ownNames = namesOn(own, dns.reader) || [];
  t.check(own.ok === true && ownNames.indexOf('telephonenumber') !== -1 &&
          ownNames.indexOf('mail') !== -1 &&
          ownNames.indexOf('userpassword') === -1,
          'their own entry, every attribute but a credential',
          JSON.stringify(ownNames));

  t.log.info('=== 2. another person, with the setting empty ===');
  const everyone = search(dns.reader, dns.users);
  t.check(everyone.ok === true &&
          dnsOf(everyone).indexOf(ldap.normalizeDn(dns.other)) === -1 &&
          dnsOf(everyone).indexOf(ldap.normalizeDn(dns.reader)) !== -1,
          'a subtree search of ou=users returns themselves and not the ' +
          'other person', JSON.stringify(dnsOf(everyone)));
  const containerNames = namesOn(everyone, dns.users) || [];
  t.check(containerNames.length > 0 &&
          containerNames.every(function (name) {
            return ['objectclass', 'ou'].indexOf(name) !== -1;
          }),
          'and the container itself, by name only',
          JSON.stringify(namesOn(everyone, dns.users)));
  refused(t, search(dns.reader, dns.other, null, 0), 'NoSuchObjectError',
          'STS-LDAP-0013', dns.other,
          'a base search of another person');
  refused(t, search(dns.reader, dns.missing, null, 0), 'NoSuchObjectError',
          'STS-LDAP-0013', dns.missing,
          'a base search of a DN that does not exist — the same answer');
  refused(t, compare(dns.reader, dns.other, 'mail', 'x'),
          'NoSuchObjectError', 'STS-LDAP-0013', dns.other,
          'a compare on another person');

  t.log.info('=== 3. widened, the listed attributes and nothing else ===');
  withSettings({ 'ldap.directoryReadableAttributes': WIDENED }, function () {
    const listed = search(dns.reader, dns.users);
    const theirs = namesOn(listed, dns.other) || [];
    t.check(theirs.length > 0 && theirs.indexOf('mail') !== -1 &&
            theirs.indexOf('uid') !== -1 &&
            theirs.indexOf('telephonenumber') === -1,
            'another person now shows uid and mail and not telephoneNumber',
            JSON.stringify(theirs));
    const phones = search(dns.reader, dns.users, '(telephoneNumber=*)');
    t.check(phones.ok === true &&
            dnsOf(phones).join('|') === ldap.normalizeDn(dns.reader),
            'THE FILTER: (telephoneNumber=*) matches the reader and nobody ' +
            'else', JSON.stringify(dnsOf(phones)));
    const oracle = search(dns.reader, dns.users,
                          '(&(uid=' + OTHER + ')(telephoneNumber=+1*))');
    t.check(oracle.ok === true && oracle.entries.length === 0,
            'and a substring on it cannot read the other number a digit at ' +
            'a time', JSON.stringify(dnsOf(oracle)));
    const byMail = search(dns.reader, dns.users,
                          '(mail=other-' + STAMP + '@readauth.test)');
    t.check(dnsOf(byMail).join('|') === ldap.normalizeDn(dns.other),
            'while a filter on a listed attribute finds them',
            JSON.stringify(dnsOf(byMail)));
    const mail = compare(dns.reader, dns.other, 'mail',
                         'other-' + STAMP + '@readauth.test');
    t.check(mail.ok === true && mail.endArg === true,
            'a compare of a listed attribute answers', JSON.stringify(mail));
    refused(t, compare(dns.reader, dns.other, 'telephoneNumber', '+1 555 0100'),
            'InsufficientAccessRightsError', 'STS-LDAP-0099', dns.other,
            'a compare of an unlisted attribute the entry holds');
    refused(t, compare(dns.reader, dns.other, 'title', 'x'),
            'InsufficientAccessRightsError', 'STS-LDAP-0099', dns.other,
            'and of one it does not hold — 50 again, not 16, so the ' +
            'refusal does not say which');
  });
  log.debug("Leaving selfAndOthers().");
}

function groupsAndInvisibles(t, dns) {
  log.debug("Entering groupsAndInvisibles().");
  t.log.info('=== 4. a group, to its members only ===');
  const groups = search(dns.reader, dns.groups);
  t.check(dnsOf(groups).indexOf(ldap.normalizeDn(dns.inGroup)) !== -1 &&
          dnsOf(groups).indexOf(ldap.normalizeDn(dns.outGroup)) === -1,
          'the group they are in is listed and the other is not',
          JSON.stringify(dnsOf(groups)));
  const inNames = namesOn(groups, dns.inGroup) || [];
  t.check(inNames.indexOf('cn') !== -1 &&
          inNames.indexOf('description') !== -1 &&
          inNames.indexOf('member') === -1,
          'with cn and description and no member list',
          JSON.stringify(inNames));
  const byMember = search(dns.reader, dns.groups,
                          '(member=' + dns.other + ')');
  t.check(byMember.ok === true && byMember.entries.length === 0,
          'and a filter cannot read the member list either',
          JSON.stringify(dnsOf(byMember)));
  withSettings({ 'ldap.groupMembersReadable': 'true' }, function () {
    const listed = search(dns.reader, dns.inGroup, null, 0);
    t.check((namesOn(listed, dns.inGroup) || []).indexOf('member') !== -1,
            'ldap.groupMembersReadable turns the member list on',
            JSON.stringify(namesOn(listed, dns.inGroup)));
  });
  refused(t, search(dns.reader, dns.outGroup, null, 0), 'NoSuchObjectError',
          'STS-LDAP-0013', dns.outGroup,
          'a base search of a group they are not in');

  t.log.info('=== 5. an application is invisible ===');
  refused(t, search(dns.reader, dns.app, null, 0), 'NoSuchObjectError',
          'STS-LDAP-0013', dns.app, 'a base search of an application');
  refused(t, compare(dns.reader, dns.app, 'cn', APP), 'NoSuchObjectError',
          'STS-LDAP-0013', dns.app, 'a compare on an application');
  const apps = search(dns.reader, dns.applications);
  t.check(apps.ok === true &&
          dnsOf(apps).join('|') === ldap.normalizeDn(dns.applications),
          'a subtree search of ou=applications returns the container alone',
          JSON.stringify(dnsOf(apps)));
  const row = audit.list().filter(function (event) {
    return event.target === dns.applications &&
           event.action === 'directory.search';
  })[0];
  t.check(!!row && row.detail && row.detail.withheldEntries >= 1,
          '9. the search\'s audit row counts what it withheld',
          JSON.stringify(row && row.detail));
  log.debug("Leaving groupsAndInvisibles().");
}

function administrators(t, dns, made) {
  log.debug("Entering administrators().");
  t.log.info('=== 6. Admin Read reads everything ===');
  const grant = adminRbac.grant(ADMIN, 'read', { via: 'test' });
  made.granted = grant && grant.ok !== false;
  t.check(made.granted, 'precondition: the probe administrator holds Admin ' +
          'Read (and not Admin Write)', JSON.stringify(grant));
  const all = search(dns.admin, dns.users, null, 2, ['*', 'userPassword']);
  const theirs = namesOn(all, dns.other) || [];
  t.check(theirs.indexOf('telephonenumber') !== -1 &&
          (namesOn(all, dns.reader) || []).indexOf('userpassword') === -1,
          'every person whole, and still no credential',
          JSON.stringify(theirs));
  t.check(search(dns.admin, dns.app, null, 0).ok === true &&
          search(dns.admin, dns.outGroup, null, 0).ok === true,
          'the application and every group');
  const phone = compare(dns.admin, dns.other, 'telephoneNumber',
                        '+1 555 0100');
  t.check(phone.ok === true && phone.endArg === true,
          'and compares anything but a credential', JSON.stringify(phone));

  t.log.info('=== 7. a realm\'s own administrator, in and out of it ===');
  const created = realms.create({ id: REALM, name: REALM });
  made.realm = created && created.ok !== false;
  t.check(made.realm, 'precondition: a throwaway realm was created',
          JSON.stringify(created));
  const inside = realms.run(realms.get(REALM), function () {
    ldap.createUser(REALM_ADMIN, { invent: false });
    ldap.createUser(OTHER, { invent: false });
    return { admin: ldap.objectFor(REALM_ADMIN).entry.dn,
             other: ldap.objectFor(OTHER).entry.dn,
             users: ldap.usersDn(),
             granted: adminRbac.grant(REALM_ADMIN, 'read',
                                      { via: 'test', realm: REALM }) };
  });
  t.check(inside.granted && inside.granted.ok !== false,
          'precondition: Admin Read on the realm\'s own roster',
          JSON.stringify(inside.granted));
  const theirRealm = search(inside.admin, inside.users);
  t.check(dnsOf(theirRealm).indexOf(ldap.normalizeDn(inside.other)) !== -1,
          'they read a person of their realm', JSON.stringify(
            dnsOf(theirRealm)));
  const defaultRealm = search(inside.admin, dns.users);
  t.check(defaultRealm.ok === true &&
          dnsOf(defaultRealm).join('|') === ldap.normalizeDn(dns.users),
          'and in the default realm they see the container and nobody in it',
          JSON.stringify(dnsOf(defaultRealm)));
  refused(t, search(inside.admin, dns.other, null, 0), 'NoSuchObjectError',
          'STS-LDAP-0013', dns.other,
          'a default-realm person is not there for them');
  log.debug("Leaving administrators().");
}

function binds(t, dns) {
  log.debug("Entering binds().");
  t.log.info('=== 8. only a person binds ===');
  refused(t, ldap.performOperation('bind', {
    dn: dns.app, boundDn: '', channel: 'ldaps', credentials: 'anything',
    remoteAddress: '203.0.113.8' }), 'InvalidCredentialsError',
          'STS-LDAP-0100', dns.app, 'a bind as an application\'s DN');
  const person = ldap.performOperation('bind', {
    dn: dns.reader, boundDn: '', channel: 'ldaps', credentials: PASSWORD,
    remoteAddress: '203.0.113.8' });
  t.check(person.ok === true, 'while the person binds',
          JSON.stringify(person));
  const rootDse = search('', '', '(objectclass=*)', 0);
  t.check(rootDse.ok === true && rootDse.entries.length === 1,
          'and the root DSE still answers an unbound connection');
  log.debug("Leaving binds().");
}

// ---------------------------------------------------------------------------
// 11. OVER THE WIRE: a real ldapjs client against the directory's own LDAPS
// listener, in a child process per mode. The child runs `overTheSocket()`
// below — this same file, required there — and writes its report where
// READAUTH_REPORT says.
// ---------------------------------------------------------------------------
function inAChild(mode) {
  log.debug("Entering inAChild(). " + mode);
  const out = path.join(os.tmpdir(), 'readauth-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath, ['-e',
    'require(' + JSON.stringify(__filename) + ').overTheSocket()'], {
    env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_MODE: mode,
                                STS_HOST: '127.0.0.1', LDAP_PORT: '0',
                                LDAPS_PORT: '0', READAUTH_REPORT: out }),
    encoding: 'utf8', timeout: 120000, cwd: ROOT
  });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // The child exited before writing; the checks show its output instead.
    report = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written; the read above already said so.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  log.debug("Leaving inAChild().");
  return { report: report || {},
           output: String(result.stdout || '') + String(result.stderr || '') };
}

// One ldapjs call, settled either way: `{ code, entries, matched }`. ldapjs
// emits `error` and never `end` for a refused search, so both settle it.
function ask(client, kind, a, b, c) {
  log.debug("Entering ask(). " + kind);
  log.debug("Leaving ask().");
  return new Promise(function (resolve) {
    if (kind === 'bind') {
      client.bind(a, b, function (e) {
        resolve({ code: e ? e.code : 0 });
      });
      return;
    }
    if (kind === 'compare') {
      client.compare(a, b, c, function (e, matched) {
        resolve({ code: e ? e.code : 0, matched: !!matched });
      });
      return;
    }
    const entries = [];
    client.search(a, b, function (e, res) {
      if (e) {
        resolve({ code: e.code, entries: [] });
        return;
      }
      res.on('searchEntry', function (entry) {
        const pojo = entry.pojo || entry;
        entries.push({ dn: String(pojo.objectName).toLowerCase(),
                       names: (pojo.attributes || []).map(function (x) {
                         return String(x.type).toLowerCase();
                       }) });
      });
      res.on('error', function (err) {
        resolve({ code: err.code, entries: entries });
      });
      res.on('end', function (done) {
        resolve({ code: done ? done.status : 0, entries: entries });
      });
    });
  });
}

// What the child does. Everything it makes is written through this module's
// functions (or by an administrator's add), then read back by a client.
async function overTheSocket() {
  log.debug("Entering overTheSocket().");
  const report = {};
  try {
    const ldapjs = require('ldapjs');
    const product = config.value('global.mode') === 'product';
    [READER, OTHER, ADMIN].forEach(function (name) {
      ldap.createUser(name, { invent: false });
      credentials.setPassword(name, PASSWORD);
    });
    const reader = ldap.objectFor(READER).entry.dn;
    const other = ldap.objectFor(OTHER).entry.dn;
    const admin = ldap.objectFor(ADMIN).entry.dn;
    const app = 'cn=' + APP + ',' + ldap.applicationsDn();
    adminRbac.grant(ADMIN, 'write', { via: 'test' });
    report.other = ldap.normalizeDn(other);
    report.setup = [
      replace(admin, other, 'telephoneNumber', '+1 555 0199').ok,
      replace(admin, other, 'mail', 'other@readauth.test').ok,
      add(admin, app, { objectClass: ['top', 'applicationProcess'],
                        cn: APP }).ok ];
    const ready = await ldap.listen().whenReady;
    const url = 'ldaps://127.0.0.1:' + ready.ldapsPort;
    const connect = function () {
      log.debug("Entering connect().");
      const client = ldapjs.createClient({ url: url, reconnect: false,
        tlsOptions: { rejectUnauthorized: false } });
      client.on('error', function (e) {
        // ldapjs emits on the client as well as calling back; the operation
        // in flight reports it.
        log.debug("The LDAP client emitted: " + ((e && e.message) || e));
      });
      log.debug("Leaving connect().");
      return client;
    };
    let client = connect();
    report.readerBind = await ask(client, 'bind', reader, PASSWORD);
    report.own = await ask(client, 'search', reader, { scope: 'base' });
    report.otherBase = await ask(client, 'search', other, { scope: 'base' });
    report.missingBase = await ask(client, 'search',
      'uid=nobody-' + STAMP + ',' + ldap.usersDn(), { scope: 'base' });
    report.everyone = await ask(client, 'search', ldap.usersDn(),
                                { scope: 'sub', filter: '(objectClass=*)' });
    report.appBase = await ask(client, 'search', app, { scope: 'base' });
    config.setOverride('ldap.directoryReadableAttributes', WIDENED);
    report.widened = await ask(client, 'search', ldap.usersDn(),
                               { scope: 'sub', filter: '(objectClass=*)' });
    report.phones = await ask(client, 'search', ldap.usersDn(),
                              { scope: 'sub', filter: '(telephoneNumber=*)' });
    report.compareMail = await ask(client, 'compare', other, 'mail',
                                   'other@readauth.test');
    report.comparePhone = await ask(client, 'compare', other,
                                    'telephoneNumber', '+1 555 0199');
    config.clearOverride('ldap.directoryReadableAttributes');
    client.unbind(function () {});
    client = connect();
    report.adminBind = await ask(client, 'bind', admin, PASSWORD);
    report.adminOther = await ask(client, 'search', other, { scope: 'base' });
    report.adminApp = await ask(client, 'search', app, { scope: 'base' });
    client.unbind(function () {});
    client = connect();
    report.appBind = await ask(client, 'bind', app, PASSWORD);
    client.unbind(function () {});
    report.product = product;
  } catch (e) {
    log.debug("Caught in overTheSocket(): " + ((e && e.message) || e));
    // Reported whole, so the parent's checks say what stopped the child.
    report.threw = String((e && e.stack) || e);
  }
  fs.writeFileSync(process.env.READAUTH_REPORT, JSON.stringify(report));
  log.debug("Leaving overTheSocket().");
  process.exit(0);
}

function namesIn(result, dn) {
  log.debug("Entering namesIn().");
  const hit = ((result && result.entries) || []).filter(function (entry) {
    return ldap.normalizeDn(entry.dn) === ldap.normalizeDn(dn);
  })[0];
  log.debug("Leaving namesIn().");
  return hit ? hit.names : null;
}

function overTheWire(t) {
  log.debug("Entering overTheWire().");
  t.log.info('=== 11. over the wire, a real ldapjs client on LDAPS ===');
  const prod = inAChild('product');
  const p = prod.report;
  const detail = JSON.stringify(p).slice(0, 1500) + prod.output.slice(-600);
  t.check(p.product === true && !p.threw &&
          (p.setup || []).every(Boolean) && p.readerBind.code === 0,
          '11a. PRODUCT: a child directory, its setup, and a person bound ' +
          'over LDAPS', detail);
  if (p.product !== true || p.threw) {
    log.debug("Leaving overTheWire(). The product child did not run.");
    return;
  }
  // The child made its own people, named by ITS stamp, and says who.
  const otherIn = function (report, result) {
    log.debug("Entering otherIn().");
    log.debug("Leaving otherIn().");
    return ((result && result.entries) || []).filter(function (entry) {
      return ldap.normalizeDn(entry.dn) === report.other;
    });
  };
  t.check(p.own.code === 0 && p.own.entries.length === 1 &&
          p.own.entries[0].names.indexOf('uid') !== -1 &&
          p.own.entries[0].names.indexOf('userpassword') === -1,
          '11b. PRODUCT: they read their own entry', JSON.stringify(p.own));
  t.check(p.otherBase.code === 32 && p.missingBase.code === 32,
          '11c. PRODUCT: another person\'s DN and a DN that does not exist ' +
          'both answer 32 on the wire',
          JSON.stringify([p.otherBase, p.missingBase]));
  t.check(p.everyone.code === 0 && otherIn(p, p.everyone).length === 0,
          '11d. PRODUCT: a subtree search does not return the other person',
          JSON.stringify(p.everyone));
  t.check(p.appBase.code === 32,
          '11e. PRODUCT: an application answers 32', JSON.stringify(p.appBase));
  const widened = otherIn(p, p.widened)[0];
  t.check(!!widened && widened.names.indexOf('mail') !== -1 &&
          widened.names.indexOf('telephonenumber') === -1,
          '11f. PRODUCT: widened, the other person shows mail and not ' +
          'telephoneNumber', JSON.stringify(p.widened));
  t.check(p.phones.code === 0 && otherIn(p, p.phones).length === 0,
          '11g. PRODUCT: (telephoneNumber=*) does not match them on the wire',
          JSON.stringify(p.phones));
  // ldapjs's client turns compareTrue (6) into a success whose second
  // argument is true, so a match reads as code 0 and `matched`.
  t.check(p.compareMail.code === 0 && p.compareMail.matched === true &&
          p.comparePhone.code === 50,
          '11h. PRODUCT: a compare of mail answers compareTrue, of ' +
          'telephoneNumber 50',
          JSON.stringify([p.compareMail, p.comparePhone]));
  t.check(p.adminBind.code === 0 && p.adminOther.code === 0 &&
          (namesIn(p.adminOther, p.adminOther.entries.length
            ? p.adminOther.entries[0].dn : '') || [])
            .indexOf('telephonenumber') !== -1 &&
          p.adminApp.code === 0 && p.adminApp.entries.length === 1,
          '11i. PRODUCT: an administrator reads the other person whole and ' +
          'the application', JSON.stringify([p.adminOther, p.adminApp]));
  t.check(p.appBind.code === 49,
          '11j. PRODUCT: a bind as the application\'s DN is 49',
          JSON.stringify(p.appBind));

  const dev = inAChild('development');
  const d = dev.report;
  t.check(d.product === false && !d.threw && d.otherBase.code === 0 &&
          d.appBase.code === 0 && otherIn(d, d.phones).length === 1 &&
          d.comparePhone.code === 0 && d.comparePhone.matched === true &&
          d.appBind.code === 0,
          '11k. DEVELOPMENT: over the same wire every one of those reads ' +
          'answers, and the application\'s DN binds',
          JSON.stringify(d).slice(0, 1500) + dev.output.slice(-600));
  log.debug("Leaving overTheWire().");
}

function run(t) {
  log.debug("Entering run().");
  const made = { people: [], entries: [], granted: false, realm: false };
  try {
    const dns = setUp(t, made);
    development(t, dns);
    product(function () {
      selfAndOthers(t, dns);
      groupsAndInvisibles(t, dns);
      administrators(t, dns, made);
      binds(t, dns);
    });
    overTheWire(t);
  } finally {
    if (made.granted) {
      adminRbac.revoke(ADMIN, 'read', { via: 'test' });
    }
    if (made.realm) {
      realms.remove(REALM);
    }
    made.entries.forEach(function (dn) {
      ldap.performOperation('del', { dn: dn, boundDn: '', channel: 'ldaps' });
    });
    made.people.forEach(function (name) {
      const view = ldap.objectFor(name);
      if (view && view.entry) {
        ldap.performOperation('del', { dn: view.entry.dn, boundDn: '',
                                       channel: 'ldaps' });
      }
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_read_authorization',
  describe: 'product mode: per-identity LDAP read authorization — self, ' +
            'administrators, other people by ' +
            'ldap.directoryReadableAttributes, ' +
            'groups by membership, applications invisible, the filter and ' +
            'compare oracles, only people bind; development unchanged',
  run: run,
  overTheSocket: overTheSocket
};
