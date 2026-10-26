// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: report_query.js
//
// ---------------------------------------------------------------------------
// THE REPORT DOCUMENT, THE THREE FORMATS, AND WHO MAY BE ISSUED A SCOPE
// (#956).
//
// In process, because the decisions are on the document, the scope string,
// the row projections and an in-memory schedule. Nothing here opens a
// listener: the HTTP status of a refusal, the DPoP gate and a scheduled
// run against a directory are not this file. `Limits.fixed` is the caps,
// so the test does not read `report.*` to decide a query. Issuance
// narrowing does read the two admin group names and `report.usersGroup`,
// and puts them back. The schedule uses the in-memory definition store
// and an injected rights checker, and it does not drain the job it queues.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const Catalog = require('../report/catalog');
const Limits = require('../report/limits');
const Query = require('../report/query');
const Formats = require('../report/formats');

const log = require('bunyan').createLogger({ name: 'report_query',
  level: process.env.LOG_LEVEL || 'info' });

const limits = Limits.fixed({
  syncMaxRows: 5,
  asyncMaxRows: 20,
  pdfMaxRows: 4
});

function ask(document, catalog) {
  log.debug("Entering ask().");
  const query = new Query({
    catalog: catalog || new Catalog(),
    limits: limits
  });
  const result = query.validate(document);
  log.debug("Leaving ask().");
  return result;
}

function unbounded() {
  log.debug("Entering unbounded().");
  const catalog = new Catalog([{
    id: 'live',
    bounded: false,
    retention: 'A test source that cannot stop early.',
    fields: [{ id: 'name', type: 'string', filter: true, sort: true,
      group: false }]
  }]);
  log.debug("Leaving unbounded().");
  return catalog;
}

function people(extra) {
  log.debug("Entering people().");
  const document = {
    source: 'users',
    select: ['username']
  };
  const keys = Object.keys(extra || {});
  for (let i = 0; i < keys.length; i++) {
    document[keys[i]] = extra[keys[i]];
  }
  log.debug("Leaving people().");
  return document;
}

function rows(count) {
  log.debug("Entering rows().");
  const out = [];
  for (let i = 0; i < count; i++) {
    out.push({ username: 'u' + i });
  }
  log.debug("Leaving rows().");
  return out;
}

function documents(t) {
  log.debug("Entering documents().");
  const statement = 'SELECT SENTINEL_SQL_MARKER FROM users';
  const asText = ask(statement);
  t.equal(asText.ok, false, 'a statement is refused');
  t.equal(asText.error, 'invalid_query', 'a statement is invalid_query');
  t.equal(asText.code, 'STS-REPORT-0004', 'a statement is 0004');
  t.check(asText.description.indexOf('SENTINEL_SQL_MARKER') < 0,
    'the refusal does not repeat the statement',
    asText.description);

  const second = ask({ sources: ['users'], source: 'users',
    select: ['username'] });
  t.equal(second.error, 'invalid_query', 'a second source key is refused');

  const arraySource = ask({ source: ['users'], select: ['username'] });
  t.equal(arraySource.error, 'invalid_query',
    'an array source is one source too many');
  t.check(arraySource.description.indexOf('one source') >= 0,
    'the refusal says one source', arraySource.description);

  const secret = ask(people({ select: ['userPassword'], limit: 10000000 }));
  t.equal(secret.error, 'unknown_field',
    'a credential id is an unknown field');
  t.equal(secret.code, 'STS-REPORT-0002', 'userPassword is 0002');
  t.check(new Catalog().field('users', 'userPassword') == null,
    'userPassword is not a catalog field');
  t.check(Catalog.credentialIds().indexOf('userPassword') >= 0,
    'userPassword is named only as a credential id');

  const extra = ask(people({ extra: 1 }));
  t.equal(extra.error, 'invalid_query', 'an unknown key is invalid_query');
  t.equal(extra.code, 'STS-REPORT-0004', 'an unknown key is 0004');

  const offset = ask(people({ offset: 1 }));
  t.equal(offset.error, 'invalid_query', 'an offset is an unknown key');
  t.equal(offset.code, 'STS-REPORT-0004', 'an offset is 0004');

  const filipino = ask(people({ locale: 'fil' }));
  t.equal(filipino.ok, true, 'fil is a language tag');
  t.equal(filipino.plan.locale, 'fil', 'the plan keeps the language');

  const like = ask(people({
    where: { op: 'like', field: 'username', value: 'a' }
  }));
  t.equal(like.error, 'unsupported_operation',
    'an operator the type does not list is refused');
  t.equal(like.code, 'STS-REPORT-0003', 'like is 0003');

  const omitted = ask(people({}));
  t.equal(omitted.ok, true, 'an omitted limit is accepted');
  t.equal(omitted.plan.limit, 5, 'the omitted limit is the sync cap');
  t.equal(omitted.plan.execution, 'sync',
    'auto on a bounded source under the cap is sync');
  t.equal(omitted.plan.format, 'json', 'the default format is json');
  t.equal(omitted.plan.mode, 'auto', 'the default mode is auto');

  const overSync = ask(people({ mode: 'sync', limit: 6 }));
  t.equal(overSync.error, 'result_too_large',
    'sync over the cap is result_too_large');
  t.equal(overSync.code, 'STS-REPORT-0005', 'sync over the cap is 0005');

  const live = ask({ source: 'live', select: ['name'], mode: 'sync',
    limit: 1 }, unbounded());
  t.equal(live.error, 'result_too_large',
    'sync on an unbounded source is result_too_large');

  const becomesJob = ask(people({ mode: 'auto', limit: 6 }));
  t.equal(becomesJob.ok, true, 'auto over the sync cap is still a query');
  t.equal(becomesJob.plan.execution, 'async',
    'auto over the sync cap is a job');

  const overAsync = ask(people({ mode: 'auto', limit: 21 }));
  t.equal(overAsync.error, 'result_too_large',
    'auto over the async cap is result_too_large');
  const asyncOver = ask(people({ mode: 'async', limit: 21 }));
  t.equal(asyncOver.error, 'result_too_large',
    'async over the async cap is result_too_large');

  const zero = ask(people({ limit: 0 }));
  t.equal(zero.error, 'invalid_query', 'a limit of 0 is invalid_query');
  t.check(zero.description.indexOf('positive whole number') >= 0,
    'a limit of 0 says why', zero.description);

  const pdfRows = ask(people({ format: 'pdf', mode: 'async', limit: 5 }));
  t.equal(pdfRows.error, 'result_too_large',
    'a PDF over its row cap is result_too_large');
  t.check(pdfRows.description.indexOf('CSV') >= 0,
    'the PDF refusal names CSV', pdfRows.description);

  t.equal(limits.syncMaxRows(), 5, 'Limits.fixed supplies the sync cap');
  t.equal(limits.asyncMaxMs(), 120000,
    'the async time cap keeps its default');
  t.equal(Limits.fixed({}).asyncMaxMs(), 120000,
    'Limits.fixed with no override keeps the async time cap');
  t.equal(limits.usersGroup(), '',
    'a fixed limits object keeps the empty users group');
  log.debug("Leaving documents().");
}

function formats(t) {
  log.debug("Entering formats().");
  const plan = { source: 'users', fields: ['username'], locale: 'en' };
  const one = Formats.pdf(plan, rows(40),
    { realm: 'default', when: '2026-10-25T00:00:00Z' }, 1);
  t.equal(one.ok, true, '40 rows fit on one page');
  t.check(one.ok && one.body.slice(0, 8).toString('utf8') === '%PDF-1.4',
    'the body is a PDF 1.4 file');

  const two = Formats.pdf(plan, rows(41),
    { realm: 'default', when: '2026-10-25T00:00:00Z' }, 1);
  t.equal(two.ok, false, '41 rows need a second page');
  t.equal(two.reason, 'pages', 'the page cap names pages');

  const german = Formats.pdf(
    { source: 'users', fields: ['username'], locale: 'de' },
    rows(1), { realm: 'default', when: 't' }, 1);
  const germanText = german.ok ? german.body.toString('utf8') : '';
  t.check(germanText.indexOf('Bericht') >= 0,
    'German chrome is drawn for de', germanText.slice(0, 80));
  t.check(germanText.indexOf('Requested language') < 0,
    'de is a language the page can draw');

  const japanese = Formats.pdf(
    { source: 'users', fields: ['username'], locale: 'ja' },
    rows(1), { realm: 'default', when: 't' }, 1);
  const japaneseText = japanese.ok ? japanese.body.toString('utf8') : '';
  t.check(japaneseText.indexOf('Requested language: ja') >= 0,
    'another language is named on the page', japaneseText.slice(0, 120));

  const filipino = Formats.pdf(
    { source: 'users', fields: ['username'], locale: 'fil' },
    rows(1), { realm: 'default', when: 't' }, 1);
  const filipinoText = filipino.ok ? filipino.body.toString('utf8') : '';
  t.check(filipinoText.indexOf('Ulat') >= 0,
    'Filipino chrome is drawn for fil', filipinoText.slice(0, 80));
  t.check(filipinoText.indexOf('Requested language') < 0,
    'fil is a language the page can draw');

  const swedish = Formats.pdf(
    { source: 'users', fields: ['username'], locale: 'sv' },
    rows(1), { realm: 'default', when: 't' }, 1);
  const swedishText = swedish.ok ? swedish.body.toString('utf8') : '';
  t.check(swedishText.indexOf('Rapport') >= 0,
    'Swedish chrome is drawn for sv', swedishText.slice(0, 80));

  const chinese = Formats.pdf(
    { source: 'users', fields: ['username'], locale: 'zh-Hans' },
    rows(1), { realm: 'default', when: 't' }, 1);
  const chineseText = chinese.ok ? chinese.body.toString('utf8') : '';
  t.check(chineseText.indexOf('Requested language: zh-Hans') >= 0,
    'Chinese is named and drawn in English', chineseText.slice(0, 160));

  const csv = Formats.csv(
    { source: 'users', fields: ['username', 'mail'], locale: null },
    [{ username: 'a,b', mail: 'say "hi"' }]).toString('utf8');
  t.equal(csv, 'username,mail\r\n"a,b","say ""hi"""\r\n',
    'CSV quotes the way RFC 4180 quotes, with CRLF');

  const json = JSON.parse(Formats.json(
    { source: 'users', fields: ['username'], locale: null },
    [{ username: 'ada' }]).toString('utf8'));
  t.equal(json.truncated, false, 'JSON says the body is whole');
  t.equal(json.source, 'users', 'JSON names the source');
  t.equal(json.rows[0].username, 'ada', 'JSON keeps the row');
  log.debug("Leaving formats().");
}

function rightsOf(t) {
  log.debug("Entering rightsOf().");
  const config = require('../common/config');
  const rights = require('../report/rights');
  let calls = 0;
  try {
    const readSet = config.setOverride('admin.readGroup', 'admin-read');
    const writeSet = config.setOverride('admin.writeGroup', 'admin-write');
    t.equal(readSet.ok, true, 'admin.readGroup accepts the test value');
    t.equal(writeSet.ok, true, 'admin.writeGroup accepts the test value');
    config.clearOverride('report.usersGroup');
    rights.installMemberProbe(function () {
      calls += 1;
      return false;
    });
    const untouched = rights.reportNarrowScope('openid profile',
      { kind: 'user', name: 'ada' });
    t.equal(untouched, 'openid profile',
      'a scope with neither report scope is returned as it was');
    t.equal(calls, 0, 'that return does not ask about membership');

    calls = 0;
    const client = rights.reportNarrowScope(
      'openid report:use report:admin',
      { kind: 'application', name: 'other' });
    t.equal(client, 'openid',
      'an application subject keeps neither report scope');
    t.equal(calls, 0, 'an application subject is not a group member');

    rights.installMemberProbe(function (username, group) {
      calls += 1;
      return username === 'ada' && group === 'admin-read';
    });
    calls = 0;
    const admin = rights.reportNarrowScope(
      'openid report:use report:admin',
      { kind: 'user', name: 'ada' });
    t.equal(admin, 'openid report:use report:admin',
      'an administrator who asked keeps both');

    rights.installMemberProbe(function () {
      return false;
    });
    const outsider = rights.reportNarrowScope(
      'openid report:use report:admin',
      { kind: 'user', name: 'bea' });
    t.equal(outsider, 'openid',
      'with no users group, a non-administrator keeps neither');

    const groupSet = config.setOverride('report.usersGroup', 'reporters');
    t.equal(groupSet.ok, true, 'report.usersGroup accepts the test value');
    rights.installMemberProbe(function (username, group) {
      return username === 'bea' && group === 'reporters';
    });
    const member = rights.reportNarrowScope(
      'openid report:use report:admin',
      { kind: 'user', name: 'bea' });
    t.equal(member, 'openid report:use',
      'a member of the users group keeps report:use only');

    rights.installMemberProbe(function () {
      return false;
    });
    const missed = rights.reportNarrowScope(
      'openid report:use',
      { kind: 'user', name: 'cy' });
    t.equal(missed, 'openid',
      'someone outside the users group loses report:use');
  } finally {
    config.clearOverride('admin.readGroup');
    config.clearOverride('admin.writeGroup');
    config.clearOverride('report.usersGroup');
    rights.installMemberProbe(null);
    log.debug("Leaving rightsOf().");
  }
}

function artifacts(t) {
  log.debug("Entering artifacts().");
  const stores = require('../report/stores');
  stores.resetForTests();
  const bytes = Buffer.from('username\r\nada\r\n', 'utf8');
  const stored = stores.putArtifact('job-1', bytes, 'abc', 'text/csv').
    then(function () {
      return stores.getArtifact('job-1');
    }).then(function (got) {
      t.equal(got.mediaType, 'text/csv', 'the artifact keeps its type');
      t.equal(got.sha256, 'abc', 'the artifact keeps its digest');
      t.check(Buffer.compare(got.bytes, bytes) === 0,
        'the artifact bytes round-trip');
      return stores.deleteArtifact('job-1');
    }).then(function () {
      return stores.getArtifact('job-1');
    }).then(function (gone) {
      t.equal(gone, null, 'a deleted artifact is gone');
      stores.resetForTests();
    }).then(function () {
      log.debug("Leaving artifacts().");
    }, function (e) {
      log.debug("Caught in artifacts(): " + ((e && e.message) || e));
      stores.resetForTests();
      log.debug("Leaving artifacts().");
      throw e;
    });
  return stored;
}

function projections(t) {
  log.debug("Entering projections().");
  const sources = require('../report/sources');
  const OpenApi = require('../report/openapi');
  const catalog = new Catalog();
  const listed = catalog.list();
  t.equal(listed.length, 10, 'the catalog has ten sources');
  const ids = listed.map(function (src) {
    return src.id;
  });
  t.check(ids.indexOf('authActivity') >= 0, 'authActivity is a source');
  t.check(ids.indexOf('attributeSources') >= 0,
    'attributeSources is a source');
  t.check(catalog.field('users', 'userPassword') == null,
    'userPassword is still not a field');
  const status = catalog.field('users', 'status');
  t.check(status && status.meaning.indexOf('pwdAccountLockedTime') >= 0,
    'locked means pwdAccountLockedTime is set',
    status && status.meaning);
  for (let i = 0; i < listed.length; i++) {
    t.equal(listed[i].paging, 'limit',
      listed[i].id + ' pages by limit');
    t.equal(listed[i].relationships.length, 0,
      listed[i].id + ' has no relationships');
    for (let f = 0; f < listed[i].fields.length; f++) {
      t.check(!!listed[i].fields[f].meaning,
        listed[i].id + '.' + listed[i].fields[f].id + ' has a meaning');
    }
  }

  const at = Date.parse('2026-10-25T12:00:00.000Z');
  const attempts = sources.activityRows([{
    action: 'authentication',
    outcome: 'success',
    actor: 'ada',
    protocol: 'oidc',
    at: at,
    detail: {
      method: 'passkey',
      amr: 'pop',
      application: 'portal',
      sessionId: 'secret-session',
      note: 'secret-note'
    }
  }, {
    action: 'authentication.refused',
    outcome: 'refused',
    actor: 'bea',
    at: at,
    detail: { amr: 'pwd' }
  }, {
    action: 'session.reauthenticate',
    at: at,
    detail: { method: 'passkey' }
  }]);
  t.equal(attempts.length, 2, 'a reauthentication is not an attempt');
  t.equal(attempts[0].mechanism, 'passkey',
    'mechanism is detail.method when it is present');
  t.equal(attempts[0].application, 'portal', 'application is copied');
  t.equal(attempts[0].day, '2026-10-25', 'day is the UTC calendar day');
  t.equal(attempts[0].timestamp, '2026-10-25T12:00:00.000Z',
    'the audit time is an ISO string');
  t.equal(Object.prototype.hasOwnProperty.call(attempts[0], 'sessionId'),
    false, 'a session id is not a field');
  t.equal(Object.prototype.hasOwnProperty.call(attempts[0], 'note'),
    false, 'a note is not a field');
  t.equal(attempts[1].mechanism, 'pwd',
    'mechanism falls back to detail.amr');
  t.equal(attempts[1].application, '',
    'a row with neither application nor client id is blank');

  const mechs = sources.mechanismRows({ passwordPrimary: true }, [{
    identifier: 'empty-app',
    fields: {}
  }, {
    identifier: 'portal',
    fields: {
      appAuthnMechanism: ['webauthn'],
      appMfaMechanism: ['totp']
    }
  }]);
  let realm = 0;
  let password = null;
  let primary = null;
  let second = null;
  for (let m = 0; m < mechs.length; m++) {
    const row = mechs[m];
    if (row.application === 'realm') {
      realm += 1;
      if (row.id === 'password') {
        password = row;
      }
    }
    if (row.application === 'portal' && row.type === 'primary') {
      primary = row;
    }
    if (row.application === 'portal' && row.type === 'second') {
      second = row;
    }
  }
  t.equal(realm, 11, 'every realm mechanism is one row');
  t.equal(mechs.length, 13,
    'an empty application list adds nothing, and two listed values do');
  t.equal(password && password.enabled, true,
    'a realm flag that is on is enabled');
  t.equal(primary && primary.id, 'webauthn',
    'a listed primary mechanism is a row');
  t.equal(primary && primary.enabled, true,
    'a listed primary mechanism is enabled');
  t.equal(second && second.id, 'totp',
    'a listed second factor is a row');
  t.equal(second && second.type, 'second',
    'appMfaMechanism is type second');

  const attrs = sources.attributeSourceRows([{
    id: 'hr',
    dialect: 'postgres',
    database: 'people',
    table: 'staff',
    keyAttribute: 'uid',
    refresh: ['sign-in', 'schedule'],
    onFailure: 'keep',
    enabled: true,
    host: 'db.example',
    port: 5432,
    user: 'reader',
    passwordRef: 'secret',
    caCertificates: 'CERT'
  }]);
  t.equal(attrs.length, 1, 'one definition is one row');
  t.equal(attrs[0].id, 'hr', 'the source id is kept');
  t.equal(attrs[0].dialect, 'postgres', 'the dialect is kept');
  t.equal(attrs[0].database, 'people', 'the database name is kept');
  t.equal(attrs[0].table, 'staff', 'the table is kept');
  t.equal(attrs[0].keyAttribute, 'uid', 'the key attribute is kept');
  t.equal(attrs[0].mode, 'sign-in,schedule',
    'refresh modes are joined');
  t.equal(attrs[0].onFailure, 'keep', 'onFailure is kept');
  t.equal(attrs[0].enabled, true, 'enabled stays a boolean');
  const dropped = ['host', 'port', 'user', 'passwordRef', 'caCertificates'];
  for (let d = 0; d < dropped.length; d++) {
    t.equal(Object.prototype.hasOwnProperty.call(attrs[0], dropped[d]),
      false, dropped[d] + ' is not a field');
  }

  const spec = OpenApi.document(catalog);
  t.equal(spec.openapi, '3.0.3', 'the document is OpenAPI 3.0.3');
  const paths = [
    '/report-api',
    '/report-api/openapi.json',
    '/report-api/catalog',
    '/report-api/catalog/{id}',
    '/report-api/queries',
    '/report-api/definitions',
    '/report-api/definitions/{id}',
    '/report-api/definitions/{id}/share',
    '/report-api/definitions/{id}/run',
    '/report-api/jobs',
    '/report-api/jobs/{id}',
    '/report-api/jobs/{id}/cancel',
    '/report-api/jobs/{id}/result'
  ];
  for (let p = 0; p < paths.length; p++) {
    t.check(Object.prototype.hasOwnProperty.call(spec.paths, paths[p]),
      paths[p] + ' is in the document');
  }
  log.debug("Leaving projections().");
}

async function budget(t) {
  log.debug("Entering budget().");
  const sources = require('../report/sources');
  const plan = {
    source: 'users',
    select: ['username'],
    fields: ['username'],
    where: null,
    orderBy: [],
    limit: 1,
    aggregate: null,
    groupBy: []
  };
  sources.installReader(function () {
    return Promise.resolve();
  });
  try {
    const slow = await sources.read(plan, {
      startedMs: 1,
      budgetMs: 5,
      execution: 'async'
    });
    t.equal(slow.ok, false, 'an async read past its budget fails');
    t.equal(slow.code, 'STS-REPORT-0034', 'the async time cap is 0034');
    t.equal(slow.error, 'result_too_large',
      'the public token stays result_too_large');
    const sync = await sources.read(plan, {
      startedMs: 1,
      budgetMs: 5,
      execution: 'sync'
    });
    t.equal(sync.code, 'STS-REPORT-0005',
      'the same clock on a synchronous read is 0005');
  } finally {
    sources.installReader(null);
    log.debug("Leaving budget().");
  }
}

function scheduledDocument() {
  log.debug("Entering scheduledDocument().");
  const document = {
    source: 'users',
    select: ['username'],
    where: { op: 'eq', field: 'username', param: 'who' },
    limit: 1,
    mode: 'async',
    format: 'json'
  };
  log.debug("Leaving scheduledDocument().");
  return document;
}

async function schedules(t) {
  log.debug("Entering schedules().");
  require('../common/config');
  const stores = require('../report/stores');
  const rights = require('../report/rights');
  const jobs = require('../report/jobs');
  const when = Date.parse('2026-10-25T12:00:30Z');
  stores.resetForTests();
  rights.installChecker(function () {
    return { ok: true, username: 'ada' };
  });
  try {
    const saved = jobs.save({
      owner: 'urn:uuid:test',
      name: 'who',
      document: scheduledDocument(),
      schedule: '* * * * *',
      scheduleEnabled: true,
      parameters: { who: 'ada' }
    });
    t.equal(saved.ok, true, saved.ok ?
      'a parameterised definition is stored' :
      'a parameterised definition is stored: ' + saved.description);
    if (saved.ok) {
      const first = await jobs.scheduleNow(when);
      t.equal(first.enqueued, 1, 'a due definition with a value is queued');
      const queued = stores.listJobs();
      t.equal(queued.length, 1, 'one job was queued');
      t.equal(queued[0] && queued[0].parameters &&
        queued[0].parameters.who, 'ada',
        'the queued job carries the stored parameter');
      const held = stores.getDefinition(saved.definition.id);
      t.equal(typeof held.lastSlot, 'number',
        'a successful enqueue consumes the slot');
      const again = await jobs.scheduleNow(when);
      t.equal(again.enqueued, 0, 'the same occurrence is not queued twice');
    }

    stores.resetForTests();
    const missing = jobs.save({
      owner: 'urn:uuid:test',
      name: 'who',
      document: scheduledDocument(),
      schedule: '* * * * *',
      scheduleEnabled: true
    });
    t.equal(missing.ok, true, missing.ok ?
      'a save without values still type-checks' :
      'a save without values still type-checks: ' + missing.description);
    if (missing.ok) {
      t.equal(missing.definition.parameters, null,
        'the type-check dummy is not stored');
      const skipped = await jobs.scheduleNow(when);
      t.equal(skipped.enqueued, 0, 'a missing parameter is not queued');
      const held = stores.getDefinition(missing.definition.id);
      t.equal(held.lastSlot, null,
        'a missing parameter does not consume the slot');
      t.check(held.failures && held.failures.length >= 1,
        'the skip is noted on the definition');
      const note = held.failures[held.failures.length - 1];
      t.equal(note.description, 'A saved parameter was not given.',
        'the note names the missing parameter');
    }

    stores.resetForTests();
    stores.putDefinition({
      id: 'def-bad',
      name: 'bad',
      owner: 'urn:uuid:test',
      document: {
        source: 'users',
        select: ['no-such-field'],
        limit: 1,
        mode: 'async'
      },
      parameters: null,
      schedule: '* * * * *',
      scheduleEnabled: true,
      notify: false,
      groups: [],
      lastSlot: null,
      failures: [],
      createdAt: 1,
      modifiedAt: 1
    });
    const refused = await jobs.scheduleNow(when);
    t.equal(refused.enqueued, 0, 'an invalid query is not queued');
    const bad = stores.getDefinition('def-bad');
    t.equal(typeof bad.lastSlot, 'number',
      'a query that no longer validates consumes the slot');
  } finally {
    rights.installChecker(null);
    stores.resetForTests();
    log.debug("Leaving schedules().");
  }
}

async function run(t) {
  log.debug("Entering run().");
  documents(t);
  formats(t);
  rightsOf(t);
  await artifacts(t);
  projections(t);
  await budget(t);
  await schedules(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'report_query',
  describe: 'report documents, formats, issuance, projections, schedules',
  run: run
};
