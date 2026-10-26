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
      member: [ada.dn] }
  };
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

  // The OpenAPI document.
  const spec = OpenApi.document(new Catalog());
  t.check(spec.components.schemas.Realms &&
    spec.components.schemas.Index.properties.version,
    'the OpenAPI document carries the realms and the version');
  log.debug("Leaving chrome().");
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
  log.debug("Leaving run().");
}

module.exports = {
  name: 'report_query',
  describe: 'report documents, formats, issuance, projections, schedules, ' +
    'indexed lookups, the page chrome',
  run: run
};
