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
//
// THE INDEXED LOOKUPS (#985, `narrowing()`) are driven against a directory
// DOUBLE installed through `sources.installDirectory()`, which counts each
// door the reader opens — the name lookup, the UUID lookup, the window's
// `byMail` and `uidContains`, and the page walk — so the file can hold the
// claim the issue is about: a filter the store can answer never pages the
// people, and the rows are the walk's. A real windowed directory needs a
// postgres store, which this file does not open; the double answers what
// `ldap_server.js`'s doors answer, in their shapes.
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
  t.equal(limits.syncMaxMs(), 10000,
    'the sync time cap keeps its default');
  t.equal(Limits.fixed({}).asyncMaxMs(), 120000,
    'Limits.fixed with no override keeps the async time cap');
  t.equal(Limits.fixed({}).syncMaxMs(), 10000,
    'Limits.fixed with no override keeps the sync time cap');
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
    '/report-api/realms',
    '/report-api/groups',
    '/report-api/schedules',
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
      t.equal(queued[0] && queued[0].queuedBecause, 'schedule',
        'a scheduled job says it was scheduled');
      const times = jobs.scheduleTimes(stores.getDefinition(
        saved.definition.id), when);
      t.equal(times.lastSlotAt, '2026-10-25T12:00:00.000Z',
        'the occurrence taken is the minute the schedule fired');
      t.equal(times.nextRunAt, '2026-10-25T12:01:00.000Z',
        'and the next run is the next minute');
      t.equal(jobs.scheduleTimes({ schedule: '* * * * *',
        scheduleEnabled: false, lastSlot: null }, when).nextRunAt, null,
        'a schedule that is off has no next run');

      // The schedules endpoint (#992): mine, the realm, one owner.
      const api = require('../report/report_api');
      stores.putDefinition({
        id: 'def-other', name: 'theirs', owner: 'urn:uuid:other',
        // Off, so the second scheduleNow() below still queues nothing;
        // the list shows a schedule whether or not it is on.
        document: scheduledDocument(), parameters: { who: 'bea' },
        schedule: '0 9 * * 1', scheduleEnabled: false, notify: false,
        groups: [], lastSlot: null, failures: [{ at: when,
          description: 'A saved parameter was not given.' }],
        createdAt: 1, modifiedAt: 1
      });
      stores.putDefinition({
        id: 'def-plain', name: 'no schedule', owner: 'urn:uuid:test',
        document: scheduledDocument(), parameters: { who: 'ada' },
        schedule: '', scheduleEnabled: false, notify: false, groups: [],
        lastSlot: null, failures: [], createdAt: 1, modifiedAt: 1
      });
      const mine = api.schedulesView({ subject: 'urn:uuid:test',
        scope: 'report:use' }, {});
      t.equal(mine.scope, 'mine', 'report:use lists its own');
      t.equal(mine.schedules.map(function (s) {
        return s.definition.id;
      }).join(','), saved.definition.id,
        'only the caller\'s scheduled definition, not the unscheduled one ' +
        'and not another owner\'s');
      t.equal(mine.schedules[0].jobs.length, 1,
        'with its scheduled job');
      t.equal(mine.schedules[0].jobs[0].queuedBecause, 'schedule',
        'which says it was scheduled');
      t.equal(mine.schedules[0].definition.nextRunAt !== null, true,
        'and its next run');
      const realm = api.schedulesView({ subject: 'urn:uuid:admin',
        scope: 'report:use report:admin' }, {});
      t.equal(realm.scope, 'realm', 'report:admin lists the realm');
      t.equal(realm.total, 2, 'both scheduled definitions');
      t.equal(realm.schedules[0].definition.name, 'theirs',
        'in name order');
      t.equal(realm.schedules[0].definition.failures[0].description,
        'A saved parameter was not given.',
        'with the notes a skipped run left');
      const one = api.schedulesView({ subject: 'urn:uuid:admin',
        scope: 'report:admin' }, { owner: 'urn:uuid:other' });
      t.equal(one.total, 1, 'an administrator may ask for one owner');
      t.equal(one.owner, 'urn:uuid:other', 'and the answer names them');
      const refused = api.schedulesView({ subject: 'urn:uuid:test',
        scope: 'report:use' }, { owner: 'urn:uuid:other' });
      t.equal(refused.ok, false, 'report:use may not ask for another owner');
      t.equal(refused.code, 'STS-REPORT-0038', 'and the refusal is 0038');
      const self = api.schedulesView({ subject: 'urn:uuid:test',
        scope: 'report:use' }, { owner: 'urn:uuid:test' });
      t.equal(self.total, 1, 'naming oneself is allowed');
      const paged = api.schedulesView({ subject: 'urn:uuid:admin',
        scope: 'report:admin' }, { per: 1, page: 2 });
      t.equal(paged.pages === 2 && paged.schedules.length === 1 &&
        paged.schedules[0].definition.id === saved.definition.id, true,
        'the list pages');
      t.equal(api.schedulesView({ subject: 'urn:uuid:admin',
        scope: 'report:admin' }, { per: 1000 }).per, 100,
        'per is capped at a hundred');
      t.equal(jobs.jobView(queued[0], false).queuedBecause, 'schedule',
        'and its view carries the reason');
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

const USERS_DN = 'ou=users,dc=example,dc=com';
const GROUPS_DN = 'ou=groups,dc=example,dc=com';

function person(uid, extra) {
  log.debug("Entering person().");
  const attributes = {
    uid: [uid],
    cn: [uid.toUpperCase()],
    mail: [uid + '@example.com'],
    entryUUID: ['00000000-0000-4000-8000-00000000000' + uid.length],
    createTimestamp: ['20261001120000Z']
  };
  Object.keys(extra || {}).forEach(function (key) {
    attributes[key] = extra[key];
  });
  const entry = {
    dn: 'uid=' + uid + ',' + USERS_DN,
    origin: 'test',
    attributes: attributes
  };
  log.debug("Leaving person().");
  return entry;
}

/**
 * A directory double with the doors `report/sources.ts` opens, each
 * counted. `windowed` decides which directory it says it is.
 *
 * @param {boolean} windowed - whether the double is a window onto a store
 * @returns {{ ldap: object, calls: object, people: object[] }}
 */
function directoryDouble(windowed) {
  log.debug("Entering directoryDouble().");
  const ada = person('ada', {
    entryUUID: ['11111111-1111-4111-8111-111111111111'] });
  const bea = person('bea', { pwdAccountLockedTime: ['20261001120000Z'] });
  const cy = person('cy');
  const xbea = person('xbea');
  const people = [ada, bea, cy, xbea];
  const staff = {
    dn: 'cn=staff,' + GROUPS_DN,
    origin: 'test',
    attributes: { cn: ['staff'], objectClass: ['groupOfNames'],
      mail: ['staff@example.com'], member: [ada.dn] }
  };
  // Eight groups for the search's paging (#989): staff with an address,
  // the rest without, so a page of five is five and the second page two.
  const moreGroups = ['auditors', 'board', 'catering', 'dev', 'finance',
    'ops', 'reporters'].map(function (name) {
    return { dn: 'cn=' + name + ',' + GROUPS_DN, origin: 'test',
      attributes: { cn: [name], objectClass: ['groupOfNames'],
        description: ['the ' + name] } };
  });
  const allGroups = [staff].concat(moreGroups);
  const calls = { byName: 0, byUuid: 0, byMail: 0, contains: 0, walk: 0,
    groups: 0, groupPages: 0 };
  const byName = {};
  people.forEach(function (one) {
    byName[one.attributes.uid[0]] = one;
  });
  const entries = new Map();
  people.concat([staff]).forEach(function (one) {
    entries.set(one.dn, one);
  });
  const ldap = {
    entries: entries,
    usersDn: function () {
      return USERS_DN;
    },
    groupsDn: function () {
      return GROUPS_DN;
    },
    directoryIsWindowed: function () {
      return windowed;
    },
    existingUserEntry: function (name) {
      return byName[String(name).toLowerCase()] || null;
    },
    existingUserEntriesAsync: function (names) {
      calls.byName++;
      return Promise.resolve(names.map(function (name) {
        return byName[String(name).toLowerCase()] || null;
      }));
    },
    entriesByUuidsAsync: function (uuids) {
      calls.byUuid++;
      const out = new Map();
      uuids.forEach(function (uuid) {
        const wanted = String(uuid).toLowerCase();
        out.set(wanted, people.filter(function (one) {
          return one.attributes.entryUUID[0] === wanted;
        })[0] || null);
      });
      return Promise.resolve(out);
    },
    allGroupEntries: function () {
      calls.groupList = (calls.groupList || 0) + 1;
      return allGroups.map(function (one) {
        return { dn: one.dn, attributes: one.attributes, members: [] };
      });
    },
    groupsOfUser: function (name) {
      calls.groups++;
      return { groups: name === 'ada' ? [
        { cn: 'staff', via: ['member'], viaMemberOf: false },
        { cn: 'claimed', via: [], viaMemberOf: true }
      ] : [] };
    },
    residentsPageAsync: function () {
      calls.walk++;
      return Promise.resolve({
        people: people.map(function (one) {
          return { name: one.attributes.uid[0] };
        }),
        more: false,
        next: ''
      });
    },
    directoryWindow: {
      findWindowedAsync: function (realmId, name, args, predicate) {
        calls.byMail++;
        const hits = name === 'byMail' ? people.filter(function (one) {
          return predicate(one);
        }) : [];
        return Promise.resolve(hits.map(function (one) {
          return { key: one.dn.toLowerCase(), entry: one };
        }));
      },
      uidContainsAsync: function (realmId, parent, needle, limit) {
        calls.contains++;
        if (needle === 'full') {
          return Promise.resolve({ rows: [], asked: limit });
        }
        const rows = people.filter(function (one) {
          return one.attributes.uid[0].indexOf(needle) >= 0;
        }).map(function (one) {
          return { key: one.dn.toLowerCase(), entry: one };
        });
        return Promise.resolve({ rows: rows, asked: rows.length });
      },
      rdnPageAsync: function () {
        calls.groupPages++;
        return Promise.resolve({
          rows: [{ key: staff.dn.toLowerCase(), entry: staff, rdn: 'staff' }],
          last: 'staff',
          asked: 1
        });
      }
    }
  };
  log.debug("Leaving directoryDouble().");
  return { ldap: ldap, calls: calls, people: people };
}

function names(result) {
  log.debug("Entering names().");
  const out = (result && result.rows || []).map(function (row) {
    return row.username;
  });
  log.debug("Leaving names().");
  return out;
}

async function narrowing(t) {
  log.debug("Entering narrowing().");
  const sources = require('../report/sources');
  const OpenApi = require('../report/openapi');

  // The catalog's marks, and the two documents that carry them.
  const catalog = new Catalog();
  t.equal(catalog.indexedFor('users', 'username').join(','),
    'eq,in,contains,startsWith', 'username is indexed for four operators');
  t.equal(catalog.indexedFor('users', 'mail').join(','), 'eq,in',
    'mail is indexed for equality');
  t.equal(catalog.indexedFor('users', 'entryUuid').join(','), 'eq,in',
    'entryUuid is indexed for equality');
  t.equal(catalog.indexedFor('users', 'displayName').length, 0,
    'a sealed field is indexed for nothing');
  t.equal(catalog.indexedFor('groups', 'name').length, 0,
    'no other source carries a mark');
  t.equal(catalog.indexedFor('users', 'userPassword').length, 0,
    'a credential id is indexed for nothing');
  const spec = OpenApi.document(catalog);
  t.check(spec.components && spec.components.schemas &&
    spec.components.schemas.Field &&
    spec.components.schemas.Field.properties.indexed,
    'the OpenAPI Field schema carries indexed');

  // The planner.
  const indexedOf = function (field) {
    return catalog.indexedFor('users', field);
  };
  const plan = function (where) {
    return sources.indexedLookups(where, indexedOf, 0);
  };
  const eq = plan({ op: 'eq', field: 'username', value: 'ada' });
  t.equal(JSON.stringify(eq),
    JSON.stringify([{ field: 'username', op: 'eq', values: ['ada'] }]),
    'username equals is one exact lookup');
  const list = plan({ op: 'in', field: 'username', value: ['ada', 'bea'] });
  t.equal(list && list[0].values.join(','), 'ada,bea',
    'username in is one exact lookup over the values');
  const contains = plan({ op: 'contains', field: 'username', value: 'RCB' });
  t.equal(JSON.stringify(contains),
    JSON.stringify([{ field: 'username', op: 'contains', values: ['rcb'] }]),
    'username contains is a lower-cased substring lookup');
  t.equal(plan({ op: 'contains', field: 'username', value: 'rc' }), null,
    'a needle under three characters is not indexed');
  const starts = plan({ op: 'startsWith', field: 'username', value: 'bea' });
  t.equal(starts && starts[0].op, 'contains',
    'startsWith is asked as the substring superset');
  t.equal(plan({ op: 'contains', field: 'mail', value: 'example' }), null,
    'mail contains has no index');
  t.equal(plan({ op: 'contains', field: 'displayName', value: 'Ada' }), null,
    'a sealed field has no index');
  t.equal(plan({ op: 'ne', field: 'username', value: 'ada' }), null,
    'ne is not a lookup');
  t.equal(plan({ op: 'isNull', field: 'mail' }), null,
    'isNull is not a lookup');
  t.equal(plan({ op: 'not', arg: { op: 'eq', field: 'username',
    value: 'ada' } }), null, 'not is not a lookup');
  const andOne = plan({ op: 'and', args: [
    { op: 'eq', field: 'status', value: 'locked' },
    { op: 'eq', field: 'username', value: 'ada' }] });
  t.equal(andOne && andOne.length === 1 && andOne[0].field, 'username',
    'an and is the lookups of its indexed arm');
  const andExact = plan({ op: 'and', args: [
    { op: 'contains', field: 'username', value: 'load' },
    { op: 'eq', field: 'mail', value: 'a@b' }] });
  t.equal(andExact && andExact[0].field, 'mail',
    'an and prefers an exact arm to a substring one');
  const orBoth = plan({ op: 'or', args: [
    { op: 'eq', field: 'username', value: 'ada' },
    { op: 'eq', field: 'mail', value: 'bea@example.com' }] });
  t.equal(orBoth && orBoth.length, 2,
    'an or of indexed arms is the union of their lookups');
  t.equal(plan({ op: 'or', args: [
    { op: 'eq', field: 'username', value: 'ada' },
    { op: 'eq', field: 'status', value: 'locked' }] }), null,
    'an or with a sealed arm is not a lookup');
  const many = [];
  for (let i = 0; i < 17; i++) {
    many.push({ op: 'eq', field: 'username', value: 'u' + i });
  }
  t.equal(plan({ op: 'or', args: many }), null,
    'an or of more than sixteen lookups walks');
  t.equal(plan(null), null, 'no filter is no lookup');

  // The reader, against a windowed double.
  const built = directoryDouble(true);
  sources.installDirectory(built.ldap);
  const calls = built.calls;
  const reset = function () {
    Object.keys(calls).forEach(function (key) {
      calls[key] = 0;
    });
  };
  const read = function (extra, execution) {
    const asked = ask(people(extra));
    if (!asked.ok) {
      return Promise.resolve(asked);
    }
    return sources.read(asked.plan, {
      startedMs: Date.now(),
      budgetMs: 5000,
      execution: execution || 'sync'
    });
  };
  const selectAll = ['username', 'status', 'mail', 'memberOf'];
  try {
    reset();
    const one = await read({ select: selectAll,
      where: { op: 'eq', field: 'username', value: 'ada' }, limit: 5 });
    t.equal(one.ok, true, 'username equals is answered');
    t.equal(names(one).join(','), 'ada', 'username equals names the person');
    t.equal(one.rows[0].memberOf, 'staff',
      'the row carries the groups that list the person, from the index');
    t.equal(calls.byName, 1, 'one name lookup');
    t.equal(calls.walk, 0, 'the people were not paged');
    t.equal(calls.groupPages, 0, 'the groups were not paged');

    reset();
    const some = await read({ select: selectAll,
      where: { op: 'in', field: 'username', value: ['bea', 'nobody', 'ada'] },
      limit: 5 });
    t.equal(names(some).join(','), 'bea,ada',
      'username in names the people found, a missing name skipped');
    t.equal(calls.byName + calls.walk, 1, 'one lookup and no walk');

    reset();
    const short = await read({
      where: { op: 'contains', field: 'username', value: 'ad' }, limit: 5 });
    t.equal(short.ok, false, 'a short substring cannot be answered now');
    t.equal(short.code, 'STS-REPORT-0036', 'the unbounded filter is 0036');
    t.equal(short.error, 'result_too_large',
      'the public token is result_too_large');
    t.equal(short.unbounded, true, 'the refusal says it is unbounded');
    t.check(short.description.indexOf('username (eq, in, contains, ' +
      'startsWith)') >= 0 && short.description.indexOf('mail (eq, in)') >= 0 &&
      short.description.indexOf('entryUuid (eq, in)') >= 0,
      'the refusal names the indexed fields', short.description);
    t.equal(calls.walk, 0, 'a refused read paged nobody');

    reset();
    const sub = await read({
      where: { op: 'contains', field: 'username', value: 'bea' }, limit: 5 });
    t.equal(names(sub).join(','), 'bea,xbea',
      'contains is answered from the substring index');
    t.equal(calls.contains, 1, 'one substring lookup');

    reset();
    const prefix = await read({
      where: { op: 'startsWith', field: 'username', value: 'bea' }, limit: 5 });
    t.equal(names(prefix).join(','), 'bea',
      'startsWith narrows the substring superset in process');

    reset();
    const mail = await read({
      where: { op: 'eq', field: 'mail', value: 'ada@example.com' }, limit: 5 });
    t.equal(names(mail).join(','), 'ada', 'mail equals names the person');
    t.equal(calls.byMail, 1, 'one mail lookup');
    // The store's lookup ignores case; the filter does not, as the walk's
    // did not, so the answer is the walk's and not the index's.
    reset();
    const shouted = await read({
      where: { op: 'eq', field: 'mail', value: 'ADA@example.com' }, limit: 5 });
    t.equal(names(shouted).length, 0,
      'a different-case address is looked up and then filtered out');
    t.equal(calls.byMail, 1, 'the lookup was still asked, not a walk');
    t.equal(calls.walk, 0, 'and nobody was paged');

    reset();
    const uuid = await read({
      where: { op: 'eq', field: 'entryUuid',
        value: '11111111-1111-4111-8111-111111111111' }, limit: 5 });
    t.equal(names(uuid).join(','), 'ada', 'entryUuid equals names the person');
    t.equal(calls.byUuid, 1, 'one UUID lookup');

    reset();
    const narrowedOut = await read({ select: selectAll,
      where: { op: 'and', args: [
        { op: 'eq', field: 'username', value: 'ada' },
        { op: 'eq', field: 'status', value: 'locked' }] }, limit: 5 });
    t.equal(names(narrowedOut).length, 0,
      'the other arm still applies to the candidates');
    t.equal(calls.walk, 0, 'an and with an indexed arm paged nobody');

    reset();
    const locked = await read({ select: selectAll,
      where: { op: 'and', args: [
        { op: 'eq', field: 'status', value: 'locked' },
        { op: 'in', field: 'username', value: ['ada', 'bea'] }] }, limit: 5 });
    t.equal(names(locked).join(','), 'bea',
      'the sealed arm keeps the locked candidate');

    reset();
    const either = await read({
      where: { op: 'or', args: [
        { op: 'eq', field: 'username', value: 'ada' },
        { op: 'eq', field: 'mail', value: 'bea@example.com' }] }, limit: 5 });
    t.equal(names(either).join(','), 'ada,bea', 'an or unions the lookups');

    reset();
    const sealed = await read({
      where: { op: 'contains', field: 'displayName', value: 'A' }, limit: 5 });
    t.equal(sealed.code, 'STS-REPORT-0036',
      'a sealed-field filter is refused synchronously on a window');
    const sealedJob = await read({
      where: { op: 'contains', field: 'displayName', value: 'A' }, limit: 5 },
      'async');
    t.equal(sealedJob.ok, true, 'the same filter runs as a job');
    t.check(calls.walk >= 1, 'the job walked the people');
    t.equal(names(sealedJob).join(','), 'ada,bea,xbea',
      'the walk answers the sealed-field filter');

    reset();
    const plain = await read({ limit: 2 });
    t.equal(plain.ok, true, 'no filter, no order and no count still walks');
    t.equal(names(plain).length, 2, 'the walk stops at the limit');

    reset();
    const ordered = await read({ orderBy: [{ field: 'username',
      dir: 'asc' }], limit: 2 });
    t.equal(ordered.code, 'STS-REPORT-0036',
      'an order with no indexed filter must see everybody, so is refused');
    const counted = await read({ aggregate: 'count', groupBy: ['status'],
      select: ['status'], limit: 5 });
    t.equal(counted.code, 'STS-REPORT-0036',
      'a count with no indexed filter is refused');
    t.equal(calls.walk, 0, 'neither refusal paged anybody');

    reset();
    const capped = await read({
      where: { op: 'contains', field: 'username', value: 'full' }, limit: 5 });
    t.equal(capped.code, 'STS-REPORT-0036',
      'a substring the store answers at its cap is not trusted whole');
    t.equal(calls.contains, 1, 'the store was asked once');
  } finally {
    sources.installDirectory(null);
  }

  // The reader, against the memory directory: a name is still a lookup; a
  // substring and an address have no index and walk the in-process Map.
  const memory = directoryDouble(false);
  sources.installDirectory(memory.ldap);
  try {
    const found = await read({ select: selectAll,
      where: { op: 'eq', field: 'username', value: 'cy' }, limit: 5 });
    t.equal(names(found).join(','), 'cy', 'memory: a name is looked up');
    t.equal(memory.calls.byName, 1, 'memory: through the name door');
    const walked = await read({
      where: { op: 'contains', field: 'displayName', value: 'A' }, limit: 5 });
    t.equal(walked.ok, true, 'memory: a sealed filter is answered now');
    t.equal(names(walked).join(','), 'ada,bea,xbea',
      'memory: the walk of the Map answers it');
    const substring = await read({
      where: { op: 'contains', field: 'username', value: 'bea' }, limit: 5 });
    t.equal(names(substring).join(','), 'bea,xbea',
      'memory: a substring walks, and the filter still holds');
    t.equal(memory.calls.contains, 0,
      'memory: the window is never asked');
  } finally {
    sources.installDirectory(null);
  }
  log.debug("Leaving narrowing().");
}

// A form double for `queryDocument()`: `elements` by name, no checked
// field boxes.
function formDouble(values) {
  log.debug("Entering formDouble().");
  const elements = {};
  Object.keys(values).forEach(function (name) {
    elements[name] = { value: values[name] };
  });
  const form = {
    elements: elements,
    querySelectorAll: function () {
      return [];
    }
  };
  log.debug("Leaving formDouble().");
  return form;
}

// A translator over the English report catalog, built as the browser's
// `WebI18n` builds one (`report.key` → message).
function englishTranslator() {
  log.debug("Entering englishTranslator().");
  const fs = require('fs');
  const path = require('path');
  const messages = require('../common/web_messages');
  const own = JSON.parse(fs.readFileSync(path.join(__dirname, '..',
    'common', 'locales', 'report', 'en.json'), 'utf8'));
  const flat = {};
  Object.keys(own).forEach(function (key) {
    flat['report.' + key] = own[key];
  });
  log.debug("Leaving englishTranslator().");
  return messages.WebTranslator.fromData({ catalogs: { en: flat },
    negotiated: { locale: 'en', chain: ['en'], catalog: 'en',
                  direction: 'ltr', matched: true } });
}

function chrome(t) {
  log.debug("Entering chrome().");
  const ReportRuntime = require('../report/web_report_pages');
  const api = require('../report/report_api');
  const OpenApi = require('../report/openapi');
  const tr = englishTranslator();

  // The realms view, in a process with no realm defined.
  const view = api.realmsView();
  t.equal(view.current.id, 'default',
    'the realms view names the default realm');
  t.equal(view.current.prefix, '', 'the default realm has no prefix');
  t.equal(view.realms, null, 'with realms off the list is null');

  // The realm field: one realm is a name; several are a select.
  const alone = ReportRuntime.realmHtml(tr, view, '/report/jobs');
  t.check(alone.indexOf('class="realmname"') >= 0 &&
    alone.indexOf('<select') < 0,
    'one realm is drawn as its name, with no select', alone);
  t.check(alone.indexOf('Trust realm') >= 0, 'the field is labelled');
  const several = ReportRuntime.realmHtml(tr, {
    current: { id: 'acme', name: 'Acme', prefix: '/realm/acme' },
    realms: [
      { id: 'default', name: 'Default', prefix: '' },
      { id: 'acme', name: 'Acme', prefix: '/realm/acme' },
      { id: 'beta', name: 'Be<ta', prefix: '/realm/beta' }]
  }, '/report/jobs');
  t.check(several.indexOf('data-form="realm"') >= 0,
    'several realms are a form the runtime handles');
  t.equal((several.match(/<option /g) || []).length, 3,
    'one option per realm');
  t.check(several.indexOf('value="acme" selected') >= 0,
    'the current realm is selected');
  t.check(several.indexOf('Be&lt;ta') >= 0 && several.indexOf('Be<ta') < 0,
    'a realm name is escaped');
  t.check(several.indexOf('name="to" value="/report/jobs"') >= 0,
    'the page path rides on the form');
  t.check(several.indexOf('>Go<') >= 0, 'the Go button is drawn');
  t.equal(ReportRuntime.realmHtml(tr, null, '/report'), '',
    'no view yet draws nothing');

  // The two bars: the reader's controls above, right-justified; the pages
  // below.
  const bars = ReportRuntime.navHtml(tr, '<i>REALM</i>', '<i>MENU</i>',
    '<i>LANG</i>', '/report/jobs');
  const top = bars.indexOf('<div class="topbar">');
  const main = bars.indexOf('<div class="bar">');
  t.check(top === 0 && main > top, 'the top bar comes before the nav bar');
  const topHtml = bars.slice(top, main);
  t.check(topHtml.indexOf('REALM') >= 0 && topHtml.indexOf('LANG') >= 0 &&
    topHtml.indexOf('MENU') >= 0,
    'the top bar holds the realm field, the language chooser and the menu');
  t.check(topHtml.indexOf('REALM') < topHtml.indexOf('LANG') &&
    topHtml.indexOf('LANG') < topHtml.indexOf('MENU'),
    'in that order');
  t.check(bars.slice(main).indexOf('REALM') < 0 &&
    bars.slice(main).indexOf('data-act="refresh"') >= 0 &&
    bars.slice(main).indexOf('/logout') < 0,
    'the nav bar holds the pages and Refresh, and no Sign out');

  // The buttons: Save first in the document, disabled and hidden until
  // the Save query box is ticked, so Enter runs until then and saves after.
  const actions = ReportRuntime.actionsHtml(tr);
  const saveAt = actions.indexOf('value="save"');
  const runAt = actions.indexOf('value="run"');
  t.check(saveAt >= 0 && runAt > saveAt,
    'the Save button comes before Run in the document');
  const saveTag = actions.slice(actions.lastIndexOf('<button', saveAt),
    saveAt);
  t.check(saveTag.indexOf(' disabled') >= 0 && saveTag.indexOf(' hidden') >= 0,
    'the Save button starts disabled as well as hidden', saveTag);
  t.check(saveTag.indexOf('save-only') >= 0,
    'the Save button is one the Save query box reveals');
  const runTag = actions.slice(actions.lastIndexOf('<button', runAt), runAt);
  t.check(runTag.indexOf('disabled') < 0 && runTag.indexOf('hidden') < 0,
    'the Run button is the default button until then');

  // The footer.
  const foot = ReportRuntime.footerHtml(tr, { version: '0.1.1', stamped: true,
    buildInfo: 'built 2026-10-26' });
  t.check(foot.indexOf('iya-sts version 0.1.1') >= 0,
    'the footer names the version', foot);
  t.check(foot.indexOf('title="built 2026-10-26"') >= 0,
    'the build is the footer\'s title');
  t.equal(ReportRuntime.footerHtml(tr, null), '',
    'no version draws no footer');

  // A filter row, with and without the +.
  const first = ReportRuntime.filterRowHtml(tr, 0, '<option value="a">a' +
    '</option>', true);
  t.check(first.indexOf('name="filterField0"') >= 0 &&
    first.indexOf('name="filterOp0"') >= 0 &&
    first.indexOf('name="filterValue0"') >= 0,
    'the first row\'s controls are numbered 0');
  t.check(first.indexOf('data-act="add-filter"') >= 0,
    'the last row carries the +');
  const third = ReportRuntime.filterRowHtml(tr, 2, '', false);
  t.check(third.indexOf('name="filterField2"') >= 0,
    'a later row is numbered for its place');
  t.check(third.indexOf('data-act="add-filter"') < 0,
    'a row that is not last has no +');

  // The reader takes as many rows as the form holds.
  const one = ReportRuntime.queryDocument(formDouble({
    source: 'users', filterField0: 'username', filterOp0: 'eq',
    filterValue0: 'ada', limit: '10', format: 'json'
  }), 'en');
  t.equal(JSON.stringify(one.where),
    JSON.stringify({ op: 'eq', field: 'username', value: 'ada' }),
    'one row is one leaf');
  const three = ReportRuntime.queryDocument(formDouble({
    source: 'users',
    filterField0: 'username', filterOp0: 'eq', filterValue0: 'ada',
    filterField1: '', filterOp1: '', filterValue1: '',
    filterField2: 'status', filterOp2: 'eq', filterValue2: 'locked',
    saveQuery: 'on', definitionName: 'who',
    limit: '10', format: 'json'
  }), 'en');
  t.equal(three.where && three.where.op, 'and',
    'several rows are an and');
  t.equal(three.where && three.where.args.length, 2,
    'a blank row in the middle is skipped and the rows after it are read');
  t.equal(three.where && three.where.args[1].field, 'status',
    'the third row is read');
  t.equal(Object.prototype.hasOwnProperty.call(three, 'saveQuery'), false,
    'the Save query box is not part of the document');

  // Why a job is a job.
  t.check(ReportRuntime.becauseHtml(tr, 'every-person')
    .indexOf('read every person') >= 0,
    'an every-person job says it has to read every person');
  t.check(ReportRuntime.becauseHtml(tr, 'schedule')
    .indexOf('scheduled run') >= 0, 'a scheduled job says so');
  t.equal(ReportRuntime.becauseHtml(tr, null), '',
    'a job that recorded no reason draws no sentence');
  t.equal(ReportRuntime.becauseHtml(tr, 'other'), '',
    'an unknown reason draws no sentence');

  // The owner's name, in a process with no directory resolver.
  t.equal(api.ownerName('urn:uuid:00000000-0000-4000-8000-000000000000'),
    '', 'a subject nobody can name is shown as it is');

  // The schedule editor: an expression into the controls and back.
  const weekly = ReportRuntime.scheduleFieldsOf('30 9 * * 1,3');
  t.equal(weekly.at.slice(11), '09:30', 'the time is read off the cron');
  t.equal(weekly.days.join(','), '1,3', 'the weekdays are read off the cron');
  const yearly = ReportRuntime.scheduleFieldsOf('0 6 15 2 *');
  t.check(/-02-15T06:00$/.test(yearly.at),
    'a day and month are read off the cron', yearly.at);
  t.equal(yearly.days.length, 0, 'a yearly cron ticks no weekday');
  t.equal(ReportRuntime.scheduleFieldsOf('*/5 * * * *').at, '',
    'an expression the editor cannot draw leaves the controls empty');
  const editor = ReportRuntime.scheduleEditorHtml(tr, '30 9 * * 1,3');
  t.check(editor.indexOf('type="datetime-local"') >= 0 &&
    editor.indexOf('name="scheduleAt"') >= 0,
    'the editor is a date-time control');
  t.equal((editor.match(/name="repeatDay"/g) || []).length, 7,
    'and seven weekday boxes');
  t.check(editor.indexOf('value="1" checked') >= 0 &&
    editor.indexOf('value="3" checked') >= 0 &&
    editor.indexOf('value="2" checked') < 0,
    'the cron\'s weekdays are ticked and the others are not');
  t.check(editor.indexOf('every Mon, Wed') >= 0,
    'the preview names the days in the page\'s language', editor);
  const weeklyForm = {
    elements: { scheduleAt: { value: '2026-11-02T09:30' } },
    querySelectorAll: function () {
      return [{ value: '1' }, { value: '3' }];
    }
  };
  t.equal(ReportRuntime.scheduleCronOf(weeklyForm), '30 9 * * 1,3',
    'weekdays and a time compose a weekly cron');
  const yearlyForm = {
    elements: { scheduleAt: { value: '2026-02-15T06:00' } },
    querySelectorAll: function () {
      return [];
    }
  };
  t.equal(ReportRuntime.scheduleCronOf(yearlyForm), '0 6 15 2 *',
    'no weekday composes a yearly cron on that date');
  t.equal(ReportRuntime.scheduleCronOf({ elements: {},
    querySelectorAll: function () {
      return [];
    } }), '', 'no date is no schedule');
  t.equal(ReportRuntime.schedulePreview(tr, ''), 'No schedule.',
    'the preview of no schedule');
  t.check(ReportRuntime.schedulePreview(tr, '*/5 * * * *')
    .indexOf('*/5 * * * *') >= 0,
    'an expression the editor cannot draw is shown as it is');

  // The OpenAPI document.
  const spec = OpenApi.document(new Catalog());
  t.check(spec.components.schemas.Realms &&
    spec.components.schemas.Index.properties.version,
    'the OpenAPI document carries the realms and the version');
  t.check(spec.components.schemas.Job.properties.queuedBecause &&
    spec.components.schemas.Definition.properties.ownerName,
    'and the job\'s reason and the owner\'s name');
  log.debug("Leaving chrome().");
}

function groups(t) {
  log.debug("Entering groups().");
  const sources = require('../report/sources');
  const ReportRuntime = require('../report/web_report_pages');
  const OpenApi = require('../report/openapi');
  const tr = englishTranslator();
  const built = directoryDouble(true);
  sources.installDirectory(built.ldap);
  try {
    // The search: five a page, name order, case-insensitive, with mail.
    const first = sources.groupSearch('', 1);
    t.equal(first.per, 5, 'a page is five');
    t.equal(first.total, 8, 'every group is counted');
    t.equal(first.pages, 2, 'eight groups are two pages');
    t.equal(first.groups.length, 5, 'the first page holds five');
    t.equal(first.groups[0].name, 'auditors', 'in name order');
    const second = sources.groupSearch('', 2);
    t.equal(second.groups.length, 3, 'the second page holds the rest');
    t.equal(sources.groupSearch('', 9).page, 2,
      'a page past the end is the last page');
    const found = sources.groupSearch('STA', 1);
    t.equal(found.groups.map(function (g) {
      return g.name;
    }).join(','), 'staff', 'the search is a case-insensitive substring');
    t.equal(found.groups[0].mail, 'staff@example.com',
      'a group carries its own address');
    t.equal(found.groups[0].dn, 'cn=staff,' + GROUPS_DN,
      'and its DN');
    t.equal(sources.groupSearch('nobody-here', 1).groups.length, 0,
      'no match is an empty page');

    // Who is emailed: the groups with an address, and the ones without.
    const split = sources.groupRecipients(['cn=staff,' + GROUPS_DN,
      'CN=Dev,' + GROUPS_DN, 'cn=gone,' + GROUPS_DN], built.ldap);
    t.equal(split.addressed.length, 1, 'one shared group has an address');
    t.equal(split.addressed[0].mail, 'staff@example.com',
      'and it is the one sent to');
    t.equal(split.missing.map(function (g) {
      return g.name;
    }).join(','), 'dev,cn=gone,' + GROUPS_DN,
      'a group with no address and a group that is gone are each noted');
    t.equal(split.missing[0].name, 'dev',
      'a known group without an address is named by its cn');
  } finally {
    sources.installDirectory(null);
  }

  // The shared query form, filled from a saved document.
  const catalog = new Catalog();
  const spec = OpenApi.document(catalog);
  const cat = { sources: catalog.list().map(function (src) {
    return { id: src.id, fields: src.fields };
  }) };
  const filled = ReportRuntime.queryFormHtml(tr, cat.sources, {
    source: 'users',
    select: ['username', 'mail'],
    where: { op: 'and', args: [
      { op: 'eq', field: 'username', value: 'ada' },
      { op: 'contains', field: 'mail', value: 'example' }] },
    orderBy: [{ field: 'mail', dir: 'desc' }],
    limit: 25,
    format: 'csv'
  });
  t.check(filled.indexOf('<option value="users" selected>') >= 0,
    'the saved source is selected');
  t.check(filled.indexOf('value="username" checked') >= 0 &&
    filled.indexOf('value="mail" checked') >= 0 &&
    filled.indexOf('value="status" checked') < 0,
    'the saved fields are ticked and the others are not');
  t.check(filled.indexOf('name="filterField1"') >= 0 &&
    filled.indexOf('name="filterField2"') < 0,
    'two filter rows for two leaves');
  t.check(filled.indexOf('name="filterValue0" value="ada"') >= 0 &&
    filled.indexOf('name="filterValue1" value="example"') >= 0,
    'each row carries its leaf\'s value', filled.slice(0, 200));
  t.check(/filterOp1"[^]*?<option value="contains" selected>/.test(filled),
    'the second row\'s operator is selected');
  t.check(filled.indexOf('name="limit" value="25"') >= 0,
    'the saved limit');
  t.check(filled.indexOf('<option value="csv" selected>') >= 0,
    'the saved format');
  t.check(filled.indexOf('<option value="desc" selected>') >= 0,
    'the saved sort direction');
  t.check(filled.indexOf('name="whereJson"') < 0,
    'a filter the rows can draw rides on no JSON');
  const counted = ReportRuntime.queryFormHtml(tr, cat.sources, {
    source: 'users', select: ['status'], aggregate: 'count',
    groupBy: ['status'] });
  t.check(counted.indexOf('name="counted" checked') >= 0,
    'a count document ticks Count');
  t.check(/groupBy"[^]*?<option value="status" selected>/.test(counted),
    'and selects its group field');
  t.check(counted.indexOf('value="username" checked') >= 0,
    'a count document leaves every field ticked, as the form started');
  const complex = ReportRuntime.queryFormHtml(tr, cat.sources, {
    source: 'users',
    where: { op: 'or', args: [
      { op: 'eq', field: 'username', value: 'ada' },
      { op: 'eq', field: 'username', value: 'bea' }] } });
  t.check(complex.indexOf('name="whereJson"') >= 0 &&
    complex.indexOf('name="filterValue0" value=') < 0,
    'a filter the rows cannot draw rides along as JSON, the rows empty');
  const fresh = ReportRuntime.queryFormHtml(tr, cat.sources, null);
  t.check(fresh.indexOf('name="filterField0"') >= 0 &&
    fresh.indexOf('name="limit" value="100"') >= 0,
    'no document is the New Query page\'s empty form');
  t.equal(ReportRuntime.whereLeaves(null).length, 0, 'no filter is no leaf');
  t.equal(ReportRuntime.whereLeaves({ op: 'not', arg: {} }), null,
    'a not cannot be drawn as rows');
  t.equal(ReportRuntime.whereLeaves({ op: 'in', field: 'username',
    value: ['a'] }), null, 'an in cannot be drawn as rows');

  // The JSON ride-back through the reader.
  const carried = ReportRuntime.queryDocument(formDouble({
    source: 'users', limit: '10', format: 'json',
    whereJson: JSON.stringify({ op: 'not',
      arg: { op: 'eq', field: 'status', value: 'locked' } })
  }), 'en');
  t.equal(carried.where && carried.where.op, 'not',
    'with no row filled in, the JSON filter is carried back');
  const overridden = ReportRuntime.queryDocument(formDouble({
    source: 'users', limit: '10', format: 'json',
    filterField0: 'status', filterOp0: 'eq', filterValue0: 'locked',
    whereJson: JSON.stringify({ op: 'not', arg: {} })
  }), 'en');
  t.equal(overridden.where && overridden.where.op, 'eq',
    'a row filled in replaces the JSON filter');

  // The pane: five hits with an Add each, a pager, a chosen row.
  const page = ReportRuntime.groupResultsHtml(tr, {
    page: 2, pages: 3, groups: [
      { dn: 'cn=a,' + GROUPS_DN, name: 'a', mail: 'a@example.com' },
      { dn: 'cn=b,' + GROUPS_DN, name: 'b', mail: '' }]
  }, ['cn=b,' + GROUPS_DN]);
  t.equal((page.match(/data-act="group-add"/g) || []).length, 2,
    'an Add per hit');
  t.check(page.indexOf('a@example.com') >= 0 &&
    page.indexOf('no email address') >= 0,
    'each hit shows its address, or that it has none');
  t.check(/data-dn="cn=b,[^"]*"[^>]*disabled/.test(page),
    'a hit already chosen cannot be added again');
  t.check(page.indexOf('Page 2 of 3') >= 0 &&
    page.indexOf('data-page="1"') >= 0 && page.indexOf('data-page="3"') >= 0,
    'the pager names the page and offers both neighbours');
  t.equal(ReportRuntime.groupResultsHtml(tr, { page: 1, pages: 1,
    groups: [] }, []).indexOf('No group matches.') >= 0, true,
    'no hit says so');
  const chosenRow = ReportRuntime.chosenGroupHtml(tr,
    { dn: 'cn=Staff,' + GROUPS_DN, name: 'Staff', mail: 's@example.com' });
  t.check(chosenRow.indexOf('name="group" value="cn=Staff,') >= 0 &&
    chosenRow.indexOf('data-dn="cn=staff,') >= 0 &&
    chosenRow.indexOf('data-act="group-remove"') >= 0,
    'a chosen group is a hidden input, keyed lower-cased, with a Remove');

  t.check(spec.components.schemas.GroupPage &&
    spec.paths['/report-api/groups'],
    'the OpenAPI document carries the group search');

  // A tooltip on every field, the console's shape: a title on the label.
  const labelled = (fresh.match(/<label[^>]*>/g) || []);
  const untitled = labelled.filter(function (one) {
    return one.indexOf(' title="') < 0 && one.indexOf('name="field"') < 0;
  });
  t.check(labelled.length >= 8, 'the query form labels its fields',
    String(labelled.length));
  t.equal(untitled.filter(function (one) {
    return !/^<label>$/.test(one);
  }).length, 0, 'every labelled control carries a tooltip', untitled.join(' '));
  t.check(fresh.indexOf('title="The catalog source the report reads') >= 0,
    'the tooltip is the catalog\'s sentence');
  const sched = ReportRuntime.scheduleEditorHtml(tr, '');
  t.check(sched.indexOf('<label title="The time of day, in UTC') >= 0 &&
    sched.indexOf('<label title="The weekdays the schedule repeats') >= 0,
    'the schedule editor\'s two labels carry theirs');
  const realmField = ReportRuntime.realmHtml(tr,
    { current: { id: 'default', name: 'Default', prefix: '' }, realms: null },
    '/report');
  t.check(realmField.indexOf(
    'title="The trust realm this page is showing') >= 0,
    'the realm field carries its tooltip');

  // The schedule's status under the editor: next run, last occurrence,
  // how it works, and the notes a skipped run left.
  const status = ReportRuntime.scheduleStatusHtml(tr, {
    nextRunAt: '2026-10-27T09:30:00.000Z',
    lastSlotAt: '2026-10-26T09:30:00.000Z',
    failures: [{ at: Date.parse('2026-10-26T09:30:05Z'),
      description: 'A saved parameter was not given.' }]
  });
  t.check(status.indexOf('Next run: 2026-10-27 09:30 UTC.') >= 0 &&
    status.indexOf('Last occurrence taken: 2026-10-26 09:30 UTC.') >= 0,
    'the status names the next run and the last occurrence', status);
  t.check(status.indexOf('checked about once a minute') >= 0,
    'and says how a schedule runs');
  t.check(status.indexOf('A saved parameter was not given.') >= 0 &&
    status.indexOf('Why a scheduled run did not happen') >= 0,
    'the notes a skipped run left are listed');
  const idle = ReportRuntime.scheduleStatusHtml(tr, { nextRunAt: null,
    lastSlotAt: null, failures: [] });
  t.check(idle.indexOf('No run is due') >= 0 &&
    idle.indexOf('did not happen') < 0,
    'no schedule says so and lists nothing');

  // The status bubble: the console's flash, ok or err, with a dismiss.
  const okBubble = ReportRuntime.flashHtml(tr, 'ok', 'Saved.');
  t.check(okBubble.indexOf('<div class="flash" role="status">') === 0 &&
    okBubble.indexOf('<div class="ok">Saved.') >= 0 &&
    okBubble.indexOf('data-act="dismiss"') >= 0,
    'an ok message is a flash with a dismiss', okBubble);
  const errBubble = ReportRuntime.flashHtml(tr, 'err', 'a <b>');
  t.check(errBubble.indexOf('<div class="err">a &lt;b&gt;') >= 0,
    'an error message is escaped');
  t.check(tr.text('report.downloadFailed', { status: '410' })
    .indexOf('HTTP 410') >= 0, 'a failed download names its status');

  // The parameters: the names a filter holds, and the sentence under Run.
  t.equal(ReportRuntime.paramNames({ op: 'and', args: [
    { op: 'eq', field: 'username', param: 'who' },
    { op: 'or', args: [{ op: 'eq', field: 'status', param: 'state' },
      { op: 'eq', field: 'username', param: 'who' }] },
    { op: 'not', arg: { op: 'eq', field: 'mail', param: 'addr' } }]
  }).join(','), 'who,state,addr', 'every parameter a filter names, once');
  t.equal(ReportRuntime.paramNames({ op: 'eq', field: 'a', value: 'b' })
    .length, 0, 'a value is not a parameter');
  const helpNamed = ReportRuntime.parametersHelpHtml(tr, { where:
    { op: 'eq', field: 'username', param: 'who' } });
  t.check(helpNamed.indexOf('This definition names: who.') >= 0 &&
    helpNamed.indexOf('{&quot;who&quot;: &quot;rcbj&quot;}') >= 0,
    'the sentence names the parameters and shows the example', helpNamed);
  t.check(ReportRuntime.parametersHelpHtml(tr, { where: null })
    .indexOf('names no parameter, so the box is ignored') >= 0,
    'a definition with none says the box is ignored');
  log.debug("Leaving groups().");
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
  await narrowing(t);
  chrome(t);
  groups(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'report_query',
  describe: 'report documents, formats, issuance, projections, schedules, ' +
    'indexed lookups, the page chrome, the groups',
  run: run
};
