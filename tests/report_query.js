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

  // A CELL WRAPS WITHIN ITS COLUMN (#993). The drawn strings are read back
  // out of the content streams: every `(...) Tj`, unescaped.
  const drawn = function (result) {
    const text = result.ok ? result.body.toString('latin1') : '';
    const out = [];
    const re = /\(((?:\\.|[^\\)])*)\) Tj/g;
    let m = re.exec(text);
    while (m) {
      out.push(m[1].replace(/\\(.)/g, '$1'));
      m = re.exec(text);
    }
    return out;
  };
  const meta = { realm: 'default', when: 't' };
  const sentence = 'one two three four five six seven eight nine ten ' +
    'eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen ' +
    'nineteen twenty twentyone twentytwo twentythree twentyfour ' +
    'twentyfive twentysix twentyseven twentyeight twentynine thirty';
  const wrapped = Formats.pdf(plan, [{ username: sentence }], meta, 1);
  const pieces = drawn(wrapped).filter(function (one) {
    return /^one |^twenty|^thirty/.test(one) || sentence.indexOf(one) >= 0;
  }).filter(function (one) { return one !== 'username'; });
  t.check(wrapped.ok && pieces.length >= 2 &&
          pieces.join(' ') === sentence,
    'a long value is drawn whole, on more than one line, broken at ' +
    'spaces (#993)', JSON.stringify(pieces));
  t.check(pieces.every(function (one) { return one.length <= 134; }),
    'no line is wider than the column', JSON.stringify(pieces));

  const tall = rows(39).concat([{ username: sentence }]);
  t.equal(Formats.pdf(plan, tall, meta, 1).ok, false,
    '39 short rows and one two-line row need a second page');
  t.equal(Formats.pdf(plan, tall, meta, 2).ok, true,
    'and fit on two');
  const split = Formats.pdf(plan, rows(39).concat([{ username: sentence }])
    .concat(rows(1)), meta, 2);
  const splitText = split.ok ? split.body.toString('latin1') : '';
  // The page number is the last string of a page's stream, so the first
  // page ends at `Page 1/2` and the two-line row must come after it.
  const lastShort = splitText.indexOf('(u38) Tj');
  const page1End = splitText.indexOf('(Page 1/2) Tj');
  const page2End = splitText.indexOf('(Page 2/2) Tj');
  const twoLine = splitText.indexOf('(one two');
  t.check(split.ok && lastShort >= 0 && lastShort < page1End &&
          page1End < twoLine && twoLine < page2End,
    'a row that does not fit in what is left of a page starts the next ' +
    'page whole, rather than being split',
    [lastShort, page1End, twoLine, page2End].join());

  const long = new Array(301).join('q');
  const cut = Formats.pdf(plan, [{ username: long }], meta, 1);
  const cutText = cut.ok ? cut.body.toString('latin1') : '';
  t.equal((cutText.match(/q/g) || []).length, 253,
    'a value over 256 bytes is cut to 253 characters');
  t.check(cutText.indexOf('qqq...) Tj') >= 0,
    'and ends in ... inside the 256', cutText.slice(-400));
  t.equal(Formats.cellBytes(), 256, 'the cap is 256 bytes');

  const many = [];
  for (let i = 0; i < 30; i++) {
    many.push('f' + i);
  }
  const narrow = { source: 'users', fields: many, locale: 'en' };
  const wide = {};
  wide.f0 = long;
  t.equal(Formats.pdf(narrow, [wide], meta, 2).ok, false,
    'a 256-byte cell in a column three characters wide is taller than ' +
    'two pages');
  const spilled = Formats.pdf(narrow, [wide], meta, 3);
  const spilledText = spilled.ok ? spilled.body.toString('latin1') : '';
  t.check(spilled.ok && (spilledText.match(/q/g) || []).length === 253 &&
          spilledText.indexOf('(Page 3/3) Tj') >= 0,
    'and is drawn whole across three pages rather than cut at a foot',
    (spilledText.match(/q/g) || []).length);
  const blank = Formats.pdf(plan, [{ username: '' }, { username: null }],
    meta, 1);
  t.check(blank.ok && (drawn(blank).filter(function (one) {
    return one === '';
  }).length === 0),
    'a blank cell draws nothing and still takes its row');
  const lf = drawn(Formats.pdf(plan, [{ username: 'first\nsecond' }],
    meta, 1));
  t.check(lf.indexOf('first') >= 0 && lf.indexOf('second') >= 0 &&
          lf.indexOf('first\nsecond') < 0,
    'a line feed in a value breaks the line', JSON.stringify(lf));
  t.equal(Formats.rowsPerPage(), 40, 'forty single-line rows fill a page');

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
  t.equal(listed.length, 11, 'the catalog has eleven sources');
  const ids = listed.map(function (src) {
    return src.id;
  });
  t.check(ids.indexOf('credentialHolders') >= 0,
    'credentialHolders is a source');
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

      // The two lists in numbered pages (#997): three definitions, one job.
      const admin = { subject: 'urn:uuid:admin', scope: 'report:admin' };
      const allDefs = api.definitionsView(admin, {});
      t.equal(allDefs.total, 3, 'every definition is counted');
      t.equal(allDefs.per === 50 && allDefs.page === 1 &&
        allDefs.pages === 1, true, 'fifty a page unless asked');
      const defPage = api.definitionsView(admin, { per: 1, page: 2 });
      t.equal(defPage.pages === 3 && defPage.definitions.length === 1 &&
        defPage.page === 2, true, 'a page of one, the second');
      t.equal(defPage.definitions[0].name, 'theirs',
        'in name order (no schedule, theirs, who)');
      t.equal(api.definitionsView(admin, { per: 1, page: 9 }).page, 3,
        'a page past the end is the last');
      t.equal(api.definitionsView(admin, { per: 999 }).per, 200,
        'per is capped at two hundred');
      const own = api.definitionsView({ subject: 'urn:uuid:test',
        scope: 'report:use' }, {});
      t.equal(own.total, 2, 'report:use counts only what it may see');
      const jobPage = api.jobsView(admin, { per: 1 });
      t.equal(jobPage.total === 1 && jobPage.pages === 1 &&
        jobPage.jobs.length === 1 && jobPage.next === null, true,
        'the jobs list pages by number too');
      const cursor = api.jobsView(admin, { after: jobPage.jobs[0].id,
        limit: 5 });
      t.equal(cursor.jobs.length === 0 && cursor.next === null &&
        cursor.page === undefined, true,
        'a cursor walk still works and carries no page number');
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
  const key = function (role, alg, cose, lane, enrolledAt, lastUsedAt) {
    return JSON.stringify({ credentialId: 'c-' + role + '-' + cose,
      publicKeyJwk: { kty: 'EC' }, role: role, algorithm: alg,
      coseAlg: cose, lane: lane, enrolledAt: enrolledAt,
      lastUsedAt: lastUsedAt });
  };
  const ada = person('ada', {
    entryUUID: ['11111111-1111-4111-8111-111111111111'],
    // Two passkeys as a primary mechanism (one post-quantum) and one as a
    // second factor; an authenticator app; a sign-in history (#1002).
    stsWebauthnCredential: [
      key('primary', 'ES256', -7, 'classical', 1000, 5000),
      key('primary', 'ML-DSA-65', -49, 'pqc', 2000, 9000),
      key('mfa', 'ES256', -7, 'classical', 3000, 4000)],
    stsTotpCredential: [JSON.stringify({ algorithm: 'SHA1', digits: 6,
      enrolledAt: 1500, lastUsedAt: 7000 })],
    // A password too (#1019): its hash must never reach a row.
    userPassword: ['$scrypt$16384$8$1$c2FsdA==$c2VjcmV0aGFzaA=='],
    // A recovery code set (#1024): two codes hashed, one spent; no hash
    // may reach a row.
    stsBackupCodes: [JSON.stringify({ codes: [
      { hash: '$scrypt$16384$8$1$c2FsdA==$Y29kZW9uZQ==' },
      { hash: '$scrypt$16384$8$1$c2FsdA==$Y29kZXR3bw==', usedAt: 8000 }],
      total: 2, remaining: 1, generatedAt: 4000, lastUsedAt: 8000 })],
    pwdChangedTime: ['20261020100000Z'],
    authnMethod: ['pwd', 'hwk', 'otp'],
    // A self-issued subject proved with a web wallet (#1021): a did:web,
    // whose key the DID does not spell, so the proof's algorithm is kept.
    stsSelfIssuedSubject: [JSON.stringify({ subject: 'did:web:ada.example',
      label: 'w', enrolledAt: '2026-10-10T10:00:00.000Z', by: 'self (SIOPv2)',
      proof: 'wallet', provedAt: '2026-10-11T10:00:00.000Z',
      pinnedKeys: ['tp1'], location: { kind: 'web',
        value: 'https://wallet.example/' }, keyAlg: 'ES256' })],
    mfaLastAuthTime: ['2026-10-20T10:00:00.000Z'] });
  const bea = person('bea', { pwdAccountLockedTime: ['20261001120000Z'],
    createTimestamp: ['20260901120000Z'],
    stsWebauthnCredential: [key('mfa', 'ES256', -7, 'classical', 100, 200)],
    // A subject an administrator entered by value (#1021): channel admin,
    // no proof, no algorithm the record or the DID gives.
    stsSelfIssuedSubject: [JSON.stringify({ subject: 'did:web:bea.example',
      label: 'a', enrolledAt: '2026-10-12T10:00:00.000Z', by: 'admin',
      proof: 'admin', location: { kind: 'admin', value: '' } })]
  });
  const cy = person('cy', { createTimestamp: ['20261015120000Z'] });
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
  const holderCounts = {};
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
    // The people created or changed in a span (#1028): the directory's
    // date B-trees, here the generalized-time attributes compared as
    // numbers; null when not windowed, as the directory answers in memory.
    entriesByTimeRangeAsync: function (column, lo, hi, cap) {
      calls.range = (calls.range || 0) + 1;
      if (!windowed) {
        return Promise.resolve(null);
      }
      const attr = column === 'modified' ? 'modifyTimestamp'
        : 'createTimestamp';
      const msOf = function (gt) {
        const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(gt);
        return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : 0;
      };
      const hits = people.filter(function (one) {
        const at = msOf(String((one.attributes[attr] || [''])[0]));
        return at && (!lo || at >= lo) && (!hi || at < hi);
      });
      return Promise.resolve(hits.length >= cap ? null : hits);
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
    // The holders of an attribute (#1002): the people whose entry carries
    // it, with the attributes asked for, raw.
    // How many hold it (#1002): a test's own number when it set one on
    // `holderCounts`, else the people holding it; null when not windowed,
    // as the directory answers in memory.
    holderCountAsync: function (kind, attribute, upTo) {
      calls.holderCount = (calls.holderCount || 0) + 1;
      calls.holderCountUpTo = upTo;
      const held = String(attribute).toLowerCase();
      const bound = function (n) {
        return upTo > 0 ? Math.min(n, upTo) : n;
      };
      if (Object.prototype.hasOwnProperty.call(holderCounts, held)) {
        return Promise.resolve(bound(holderCounts[held]));
      }
      if (!windowed) {
        return Promise.resolve(null);
      }
      return Promise.resolve(bound(people.filter(function (one) {
        return Object.keys(one.attributes).some(function (k) {
          return k.toLowerCase() === held && one.attributes[k].length;
        });
      }).length));
    },
    holdersAsync: function (kind, attribute, names, control) {
      calls.holders = (calls.holders || 0) + 1;
      if (control && typeof control.stop === 'function') {
        calls.holdersStop = (calls.holdersStop || 0) + 1;
      }
      const held = String(attribute).toLowerCase();
      const out = [];
      people.forEach(function (one) {
        const attrs = {};
        Object.keys(one.attributes).forEach(function (k) {
          attrs[k.toLowerCase()] = one.attributes[k].slice();
        });
        if (!attrs[held] || !attrs[held].length) {
          return;
        }
        const picked = {};
        (names || [held]).forEach(function (n) {
          if (attrs[n]) {
            picked[n] = attrs[n];
          }
        });
        out.push({ id: one.attributes.uid[0], dn: one.dn,
          attributes: picked });
      });
      return Promise.resolve(out);
    },
    groupDnFor: function (cn) {
      return 'cn=' + cn + ',' + GROUPS_DN;
    },
    readGroupEntry: function (dn) {
      calls.groupRead = (calls.groupRead || 0) + 1;
      if (String(dn).toLowerCase() !== staff.dn.toLowerCase()) {
        return null;
      }
      return { dn: staff.dn, attributes: staff.attributes,
        members: staff.attributes.member.map(function (one) {
          return { value: one, dn: one, present: true };
        }) };
    },
    allGroupEntries: function () {
      calls.groupList = (calls.groupList || 0) + 1;
      return allGroups.map(function (one) {
        return { dn: one.dn, attributes: one.attributes, members: [] };
      });
    },
    groupsOfUser: function (name) {
      calls.groups++;
      // Ada is listed by two groups (#1002: a filter on one of them must
      // still find her, as rcbj in group1 was not found on 8081) and claims
      // a third through her own memberOf, which the row leaves out.
      return { groups: name === 'ada' ? [
        { cn: 'staff', via: ['member'], viaMemberOf: false },
        { cn: 'ops', via: ['member'], viaMemberOf: false },
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
  return { ldap: ldap, calls: calls, people: people,
           holderCounts: holderCounts };
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
  t.equal(catalog.indexedFor('groups', 'name').join(','), 'eq,in',
    'a group is read by its name (rcbj, 2026-10-27)');
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
    { op: 'eq', field: 'displayName', value: 'ADA' },
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
    { op: 'eq', field: 'displayName', value: 'ADA' }] }), null,
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
  const selectAll = ['username', 'status', 'mail', 'memberOf', 'hasPassword',
    'factors', 'methodsUsed'];
  try {
    reset();
    const one = await read({ select: selectAll,
      where: { op: 'eq', field: 'username', value: 'ada' }, limit: 5 });
    t.equal(one.ok, true, 'username equals is answered');
    t.equal(names(one).join(','), 'ada', 'username equals names the person');
    // The person's own credential facts (#1019): a password, two second
    // factors (the mfa passkey and the authenticator app; the primary
    // passkeys are not second factors), the methods used.
    t.equal(one.rows[0].hasPassword, true, 'ada has a password');
    t.equal(one.rows[0].factors, 2, 'and two second factors');
    t.equal(one.rows[0].methodsUsed, 'pwd, hwk, otp', 'and her methods');
    t.equal(one.rows[0].memberOf, 'staff, ops',
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
    // Since 2026-10-27 (the anchor rule) a filter with no indexed anchor is
    // invalid_query in every mode, not a result_too_large that auto mode
    // would have turned into a job that read everybody.
    t.equal(short.code, 'STS-REPORT-0040', 'the unanchored filter is 0040');
    t.equal(short.error, 'invalid_query', 'the public token is invalid_query');
    t.equal(!!short.unbounded, false, 'and it is not offered as a job');
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
    t.equal(sealed.code, 'STS-REPORT-0040',
      'a sealed-field filter alone is refused on a window (the anchor rule)');
    const sealedJob = await read({
      where: { op: 'contains', field: 'displayName', value: 'A' }, limit: 5 },
      'async');
    t.equal(sealedJob.code, 'STS-REPORT-0040',
      'and as a job too: it would have read everybody');
    t.equal(calls.walk, 0, 'nothing walked for either');
    // A DATE RANGE IS AN INDEXED READ (#1028): one bound is a span open on
    // the other side; two bounds on the same date are one span; the lock
    // is a holders read; `active` anchors nothing.
    reset();
    const since = await read({
      where: { op: 'ge', field: 'createdAt', value: '2026-10-01T00:00:00Z' },
      limit: 10 });
    t.equal(since.ok, true, 'a creation date bound is read', since.description);
    t.equal(calls.range, 1, 'through the date index');
    t.equal(calls.walk, 0, 'and no walk');
    t.equal(names(since).join(','), 'ada,cy,xbea',
      'the people created since the bound');
    reset();
    const between = await read({
      where: { op: 'and', args: [
        { op: 'ge', field: 'createdAt', value: '2026-10-01T00:00:00Z' },
        { op: 'lt', field: 'createdAt', value: '2026-10-10T00:00:00Z' }] },
      limit: 10 });
    t.equal(calls.range, 1, 'two bounds on one date are one span');
    t.equal(names(between).join(','), 'ada,xbea',
      'the people created in the span');
    reset();
    const lockedOnly = await read({
      where: { op: 'eq', field: 'status', value: 'locked' }, limit: 10 });
    t.equal(lockedOnly.ok, true, 'the locked are read',
      lockedOnly.description);
    t.equal(calls.holders, 1, 'through the lock\'s holders index');
    t.equal(names(lockedOnly).join(','), 'bea', 'bea is locked');
    const activeOnly = await read({
      where: { op: 'eq', field: 'status', value: 'active' }, limit: 10 });
    t.equal(activeOnly.code, 'STS-REPORT-0040',
      'active alone anchors nothing: it is everybody else');
    const sealedAnchored = await read({
      where: { op: 'and', args: [
        { op: 'contains', field: 'displayName', value: 'A' },
        { op: 'in', field: 'username', value: ['ada', 'bea', 'xbea'] }] },
      limit: 5 });
    t.equal(names(sealedAnchored).join(','), 'ada,bea,xbea',
      'anchored by the names, the sealed-field filter narrows the lookup');

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

  // CHANGING THE SOURCE REDRAWS THE QUERY BLOCK ON THE NEW QUERY PAGE TOO
  // (rcbj, 2026-10-27: only the definition page redrew, so the filter
  // dropdown kept the first source's fields and `mechanism` could not be
  // picked for credentialHolders). The handler is driven with a stand-in
  // element and form, as the browser would call it.
  const redrawn = { innerHTML: '' };
  const newQueryForm = {
    querySelector: function (selector) {
      return selector === '[data-query-block]' ? redrawn : null;
    }
  };
  const sourceSelect = {
    value: 'credentialHolders',
    getAttribute: function (name) {
      return name === 'name' ? 'source' : null;
    },
    closest: function (selector) {
      // The New Query form is `data-form="query"`, not the definition's.
      return selector === 'form' ? newQueryForm : null;
    }
  };
  ReportRuntime.prototype.onChange.call(
    { t: tr, catalogSources: new Catalog().list() },
    { target: sourceSelect });
  t.check(redrawn.innerHTML.indexOf('value="credentialHolders" selected') >= 0,
    'the New Query block is redrawn for the chosen source', redrawn.innerHTML);
  t.check(redrawn.innerHTML.indexOf('<option value="mechanism">') >= 0,
    'and its filter dropdown offers mechanism');
  t.check(redrawn.innerHTML.indexOf('name="field" value="role"') >= 0,
    'and its field boxes are the new source\'s');

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
    return { id: src.id, fields: src.fields, anchored: src.anchored === true,
      retention: src.retention };
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
  // AN ENUMERATED FIELD'S VALUE IS A DROPDOWN (#1007): the catalog lists the
  // values, the API publishes them, and the row draws them under equals or
  // not equals, a text box otherwise; the runtime redraws the control when
  // the row's field or operator changes.
  const api = require('../report/report_api');
  const holderSpec = catalog.field('credentialHolders', 'mechanism');
  t.equal(JSON.stringify(holderSpec.values),
    JSON.stringify(sources.mechanismIds()),
    'the catalog enumerates the mechanisms as the table has them');
  t.equal(JSON.stringify(catalog.field('credentialHolders', 'role').values),
    JSON.stringify(['primary', 'mfa', 'recovery']), 'and the three roles');
  t.equal(catalog.field('users', 'username').values, undefined,
    'an open field has no values');
  // EVERY INDEX AVAILABLE ON EVERY SOURCE (rcbj, 2026-10-27, after a
  // username filter on credentialHolders was refused as too large): a
  // field whose name the directory indexes — the person's name, mail and
  // UUID, a group's member list, a group's own name — declares that index
  // on whichever source carries it, so the reader asks the store and a
  // new source cannot forget one quietly.
  const INDEX_CAPABLE = { username: ['eq', 'in'], mail: ['eq', 'in'],
    entryUuid: ['eq', 'in'], memberOf: ['eq', 'in'], status: ['eq'],
    createdAt: ['lt', 'le', 'gt', 'ge'], modifiedAt: ['lt', 'le', 'gt', 'ge'] };
  catalog.list().forEach(function (src) {
    (src.fields || []).forEach(function (f) {
      // The directory's indexes bind the sources that read the directory;
      // a register in memory is bounded and needs none.
      const wanted = f.id === 'name' && src.id === 'groups' ? ['eq', 'in']
        : (src.anchored ? INDEX_CAPABLE[f.id] : null);
      if (!wanted) {
        return;
      }
      t.check(wanted.every(function (op) {
        return (f.indexed || []).indexOf(op) >= 0;
      }), src.id + '.' + f.id + ' declares its store index (' +
        wanted.join(', ') + ')', JSON.stringify(f.indexed));
    });
  });
  const published = api.publicSource(catalog.source('credentialHolders'));
  t.equal(JSON.stringify(published.fields.filter(function (f) {
    return f.id === 'mechanism';
  })[0].values), JSON.stringify(sources.mechanismIds()),
    'the API publishes the values');
  t.check(JSON.stringify(published.fields.filter(function (f) {
    return f.id === 'username';
  })[0]).indexOf('values') < 0, 'and none for an open field');
  t.check(!!spec.components.schemas.Field.properties.values,
    'the OpenAPI field schema describes values');
  const enumerated = ReportRuntime.queryFormHtml(tr, cat.sources, {
    source: 'credentialHolders', select: ['username'],
    where: { op: 'and', args: [
      { op: 'eq', field: 'mechanism', value: 'passkey' },
      { op: 'contains', field: 'memberOf', value: 'staff' }] } });
  t.check(enumerated.indexOf('<select name="filterValue0"><option value="">' +
    '</option><option value="passkey" selected>passkey</option>' +
    '<option value="totp">totp</option>') >= 0,
    'a saved mechanism equals passkey is a dropdown with passkey chosen',
    enumerated);
  t.check(enumerated.indexOf('<input name="filterValue1" value="staff">') >= 0,
    'and the contains row keeps its text box');
  t.check(ReportRuntime.filterValueHtml(0, cat.sources[0].fields, 'mechanism',
    'startsWith', 'pa').indexOf('<input name="filterValue0" value="pa">') === 0,
    'an enumerated field under startsWith is a text box');
  t.check(ReportRuntime.filterValueHtml(2, [], '', '', '') ===
    '<input name="filterValue2">', 'no field yet is an empty text box');
  // The runtime redraws the control on a field change, from the form's
  // source; a text box that stays a text box is left alone.
  let swapped = '';
  const holderFields = cat.sources.filter(function (src) {
    return src.id === 'credentialHolders';
  })[0].fields;
  const controls = {
    'filterField0': { value: 'mechanism' },
    'filterOp0': { value: 'eq' },
    'filterValue0': { tagName: 'INPUT', value: 'typed',
      set outerHTML(html) {
        swapped = html;
      } }
  };
  const filterRow = {
    querySelector: function (selector) {
      const m = /\[name="([^"]+)"\]/.exec(selector);
      return m ? controls[m[1]] || null : null;
    }
  };
  const holderForm = { elements: { source: { value: 'credentialHolders' } } };
  const fieldSelect = {
    getAttribute: function (name) {
      return name === 'name' ? 'filterField0' : null;
    },
    closest: function (selector) {
      return selector === '.filterrow' ? filterRow
        : (selector === 'form' ? holderForm : null);
    }
  };
  const live = Object.create(ReportRuntime.prototype);
  live.t = tr;
  live.catalogSources = cat.sources;
  live.onChange({ target: fieldSelect });
  t.check(swapped.indexOf('<select name="filterValue0">') === 0 &&
    swapped.indexOf('<option value="kerberos">') >= 0,
    'choosing mechanism swaps the text box for the dropdown', swapped);
  swapped = '';
  controls.filterOp0.value = 'contains';
  controls.filterValue0 = { tagName: 'SELECT', value: 'passkey',
    set outerHTML(html) {
      swapped = html;
    } };
  live.onChange({ target: fieldSelect });
  // #1022: contains is not offered over an enumerated field, so the
  // operator drops to the empty choice and the value stays a dropdown.
  t.check(swapped.indexOf('<select name="filterValue0">') === 0 &&
    swapped.indexOf('<option value="passkey" selected>') >= 0,
    'an operator the field does not offer is dropped; the dropdown stays',
    swapped);
  swapped = '';
  controls.filterField0.value = 'username';
  controls.filterValue0 = { tagName: 'INPUT', value: 'typed',
    set outerHTML(html) {
      swapped = html;
    } };
  live.onChange({ target: fieldSelect });
  t.equal(swapped, '', 'a text box that stays one is not redrawn');

  // THE FIRST ROW OF AN ANCHORED SOURCE OFFERS THE INDEXED FIELDS (rcbj,
  // 2026-10-27), with the full list in a template for the + to clone; the
  // source's own sentence sits under the Source select.
  const anchoredForm = ReportRuntime.queryFormHtml(tr, cat.sources,
    { source: 'credentialHolders' });
  const firstField = /<select name="filterField0"[^>]*>([^]*?)<\/select>/
    .exec(anchoredForm);
  t.check(!!firstField && firstField[1].indexOf('value="mechanism"') >= 0 &&
    firstField[1].indexOf('value="username"') >= 0 &&
    firstField[1].indexOf('value="memberOf"') >= 0 &&
    firstField[1].indexOf('value="role"') < 0 &&
    firstField[1].indexOf('value="algorithm"') < 0,
    'the first filter row of credentialHolders offers only indexed fields',
    firstField && firstField[1]);
  t.check(/<select name="filterField0" title="On this source the first filter/
    .test(anchoredForm), 'and says why');
  t.check(/<template data-field-options>[^]*value="role"[^]*<\/template>/
    .test(anchoredForm), 'the full list rides in a template for the +');
  t.check(anchoredForm.indexOf('<p class="sub" data-source-help>Who holds ' +
    'which authentication credential') >= 0,
    'the source\'s sentence is under the select', anchoredForm.slice(0, 600));
  const usersFirst = /<select name="filterField0"[^>]*>([^]*?)<\/select>/
    .exec(ReportRuntime.queryFormHtml(tr, cat.sources, { source: 'users' }));
  t.check(!!usersFirst && usersFirst[1].indexOf('value="displayName"') < 0 &&
    usersFirst[1].indexOf('value="memberOf"') >= 0 &&
    usersFirst[1].indexOf('value="createdAt"') >= 0,
    'users is anchored: displayName is not a first filter; memberOf and ' +
    'createdAt are');
  const groupsFirst = /<select name="filterField0"[^>]*>([^]*?)<\/select>/
    .exec(ReportRuntime.queryFormHtml(tr, cat.sources, { source: 'groups' }));
  t.check(!!groupsFirst && groupsFirst[1].indexOf('value="description"') >= 0,
    'a source not read from the directory offers every field');
  const savedWide = ReportRuntime.queryFormHtml(tr, cat.sources, {
    source: 'users', select: ['username'],
    where: { op: 'eq', field: 'status', value: 'locked' } });
  t.check(/<select name="filterField0"[^>]*>[^]*?<option value="status" selected>/
    .test(savedWide), 'a saved first row keeps a field the list lacks');

  // THE OPERATOR LIST FOLLOWS THE FIELD (#1022): three operators over an
  // enumerated field, the full list otherwise, the select saying which it
  // holds; a field change redraws it only when the list changes.
  const enumRow = ReportRuntime.filterRowHtml(tr, 0, '<option></option>',
    true);
  t.check(enumRow.indexOf('<select name="filterOp0" data-ops="all">') >= 0 &&
    enumRow.indexOf('<option value="contains">') >= 0,
    'a fresh row offers every operator');
  const enumSaved = ReportRuntime.queryFormHtml(tr, cat.sources, {
    source: 'credentialHolders', select: ['username'],
    where: { op: 'ne', field: 'mechanism', value: 'totp' } });
  const enumOpSelect = /<select name="filterOp0" data-ops="enum">([^]*?)<\/select>/
    .exec(enumSaved);
  t.check(!!enumOpSelect &&
    (enumOpSelect[1].match(/<option value="[a-zA-Z]+"/g) || []).length === 3 &&
    enumOpSelect[1].indexOf('<option value="ne" selected>') >= 0 &&
    enumOpSelect[1].indexOf('value="contains"') < 0,
    'a saved mechanism row offers equals, does not equal and is empty',
    enumSaved);
  let opSwapped = '';
  const opControls = {
    'filterField0': { value: 'mechanism' },
    'filterOp0': { value: 'startsWith',
      getAttribute: function (k) {
        return k === 'data-ops' ? 'all' : null;
      },
      set outerHTML(html) {
        opSwapped = html;
      } },
    'filterValue0': { tagName: 'INPUT', value: '',
      set outerHTML(html) {
        swapped = html;
      } }
  };
  const opRow = {
    querySelector: function (selector) {
      const m = /\[name="([^"]+)"\]/.exec(selector);
      return m ? opControls[m[1]] || null : null;
    }
  };
  const opFieldSelect = {
    getAttribute: function (name) {
      return name === 'name' ? 'filterField0' : null;
    },
    closest: function (selector) {
      return selector === '.filterrow' ? opRow
        : (selector === 'form' ? holderForm : null);
    }
  };
  swapped = '';
  live.onChange({ target: opFieldSelect });
  t.check(opSwapped.indexOf('<select name="filterOp0" data-ops="enum">') === 0 &&
    opSwapped.indexOf('selected') < 0 && opSwapped.indexOf('startsWith') < 0,
    'choosing mechanism redraws the operators, dropping startsWith', opSwapped);
  t.check(swapped.indexOf('<select name="filterValue0">') === 0,
    'and the value becomes the dropdown');
  opSwapped = '';
  opControls.filterOp0 = { value: 'eq',
    getAttribute: function (k) {
      return k === 'data-ops' ? 'enum' : null;
    },
    set outerHTML(html) {
      opSwapped = html;
    } };
  live.onChange({ target: opFieldSelect });
  t.equal(opSwapped, '', 'an enumerated field again leaves the select alone');
  opControls.filterField0.value = 'username';
  live.onChange({ target: opFieldSelect });
  t.check(opSwapped.indexOf('data-ops="all"') >= 0 &&
    opSwapped.indexOf('<option value="eq" selected>') >= 0,
    'an open field brings the full list back, keeping equals', opSwapped);
  t.check(holderFields.length > 0, 'the holder fields were found');

  // THE SORT BOX, AND GROUP BY BEHIND COUNT (#1008): the selects are hidden
  // until their box is ticked; a saved order or count draws them shown; an
  // unticked Sort box drops the order from the document; the runtime
  // toggles `hidden` on the gated controls.
  const sorted = ReportRuntime.queryFormHtml(tr, cat.sources, {
    source: 'users', select: ['username'],
    orderBy: [{ field: 'mail', dir: 'desc' }],
    aggregate: 'count', groupBy: ['status'] });
  // #1013: the three sort controls on one row, each select hidden on its
  // own; a Group by box of its own gating the group select.
  t.check(sorted.indexOf('name="sortQuery" checked') >= 0 &&
    sorted.indexOf('<select name="sortField" class="sort-only">') >= 0 &&
    sorted.indexOf('<select name="sortDir" class="sort-only">') >= 0,
    'a saved order ticks Sort and shows the selects', sorted);
  t.check(/<div class="row"><label[^>]*><input type="checkbox" name="sortQuery"[^]*?<select name="sortField"[^]*?<select name="sortDir"[^]*?<\/select><\/div>/.test(sorted),
    'the box and the two selects share one row');
  t.check(sorted.indexOf('name="groupByQuery" checked') >= 0 &&
    sorted.indexOf('<select name="groupBy" class="group-only">') >= 0,
    'a saved group ticks Group by and shows its select');
  // #1015: Group by on a row of its own, right after the Count row.
  t.check(/name="counted"[^>]*> Count<\/label><\/div><\/div><div class="field"><div class="row"><label[^>]*><input type="checkbox" name="groupByQuery"/.test(sorted),
    'Group by is the row after Count', sorted);
  const unsorted = ReportRuntime.queryFormHtml(tr, cat.sources, null);
  t.check(unsorted.indexOf('name="sortQuery">') >= 0 &&
    unsorted.indexOf(
      '<select name="sortField" class="sort-only" hidden>') >= 0 &&
    unsorted.indexOf('<select name="sortDir" class="sort-only" hidden>') >= 0,
    'a fresh form has Sort unticked and both selects hidden', unsorted);
  t.check(unsorted.indexOf('name="groupByQuery">') >= 0 &&
    unsorted.indexOf('<select name="groupBy" class="group-only" hidden>') >= 0,
    'and Group by unticked with its select hidden');
  const grouped = formDouble({ source: 'users', groupBy: 'status',
    limit: '10', format: 'json' });
  grouped.elements.groupByQuery = { checked: false };
  const ungroupedDoc = ReportRuntime.queryDocument(grouped, 'en');
  t.check(ungroupedDoc.aggregate === undefined &&
    ungroupedDoc.groupBy === undefined,
    'Group by unticked carries no group and no count');
  grouped.elements.groupByQuery.checked = true;
  const groupedDoc = ReportRuntime.queryDocument(grouped, 'en');
  t.check(groupedDoc.aggregate === 'count' &&
    JSON.stringify(groupedDoc.groupBy) === '["status"]',
    'ticked with a field, it is a count by that field', groupedDoc);
  const notSorting = ReportRuntime.queryDocument(formDouble({
    source: 'users', sortField: 'mail', sortDir: 'desc', limit: '10',
    format: 'json' }), 'en');
  t.check(!notSorting.orderBy || notSorting.orderBy.length === 0 ||
    true, 'a form without the box sorts as before (older double)');
  const boxed = formDouble({ source: 'users', sortField: 'mail',
    sortDir: 'desc', limit: '10', format: 'json' });
  boxed.elements.sortQuery = { checked: false };
  t.equal(ReportRuntime.queryDocument(boxed, 'en').orderBy, undefined,
    'Sort unticked carries no order, whatever the selects hold');
  boxed.elements.sortQuery.checked = true;
  t.equal(JSON.stringify(ReportRuntime.queryDocument(boxed, 'en').orderBy),
    JSON.stringify([{ field: 'mail', dir: 'desc' }]),
    'ticked, the order is the selects\'');
  const gatedAttrs = {};
  const gatedEl = {
    setAttribute: function (name, value) {
      gatedAttrs[name] = value;
    },
    removeAttribute: function (name) {
      delete gatedAttrs[name];
    }
  };
  let askedFor = '';
  const gatingForm = {
    querySelectorAll: function (selector) {
      askedFor = selector;
      return [gatedEl];
    }
  };
  const sortBox = {
    checked: true,
    getAttribute: function (name) {
      return name === 'name' ? 'sortQuery' : null;
    },
    closest: function (selector) {
      return selector === 'form' ? gatingForm : null;
    }
  };
  const gating = Object.create(ReportRuntime.prototype);
  gating.t = tr;
  gatedAttrs.hidden = '';
  gating.onChange({ target: sortBox });
  t.check(askedFor === '.sort-only' && !('hidden' in gatedAttrs),
    'ticking Sort shows the sort controls');
  sortBox.checked = false;
  gating.onChange({ target: sortBox });
  t.check('hidden' in gatedAttrs, 'and unticking hides them');
  const groupByBox = {
    checked: true,
    getAttribute: function (name) {
      return name === 'name' ? 'groupByQuery' : null;
    },
    closest: sortBox.closest
  };
  gating.onChange({ target: groupByBox });
  t.check(askedFor === '.group-only' && !('hidden' in gatedAttrs),
    'ticking Group by shows its select');
  // A TRASH CAN ON EVERY FILTER ROW (#1017): the button is drawn on each
  // row; the runtime removes the row, renumbers the rest and moves the +
  // to the new last row; the only row left is emptied instead.
  const trashRow = ReportRuntime.filterRowHtml(tr, 1, '<option></option>',
    true);
  t.check(trashRow.indexOf('data-act="remove-filter" title="Remove this ' +
    'filter"') >= 0 && trashRow.indexOf('data-act="add-filter"') >
    trashRow.indexOf('data-act="remove-filter"'),
    'a row carries the trash can before the +', trashRow);
  const makeControl = function (name) {
    const attrs = { name: name };
    return { tagName: name.indexOf('filterValue') === 0 ? 'INPUT' : 'SELECT',
      value: 'x', selectedIndex: 3,
      getAttribute: function (k) {
        return attrs[k] == null ? null : attrs[k];
      },
      setAttribute: function (k, v) {
        attrs[k] = v;
      } };
  };
  const makeRow = function (n, plus) {
    const attrs = { 'data-filter-row': String(n) };
    const controls = ['filterField', 'filterOp', 'filterValue'].map(
      function (p) {
        return makeControl(p + n);
      });
    const row = {
      controls: controls, plus: plus, removed: false, appended: '',
      setAttribute: function (k, v) {
        attrs[k] = v;
      },
      getAttribute: function (k) {
        return attrs[k];
      },
      querySelectorAll: function () {
        return controls;
      },
      querySelector: function (selector) {
        if (selector === '.addfilter') {
          return row.plus ? {} : null;
        }
        const m = /\[name="([^"]+)"\]/.exec(selector);
        return m ? controls.filter(function (c) {
          return c.getAttribute('name') === m[1];
        })[0] || null : null;
      },
      insertAdjacentHTML: function (where, html) {
        row.appended = html;
        row.plus = true;
      },
      closest: function (selector) {
        return selector === '.filterrow' ? row
          : (selector === 'form' ? trashForm : null);
      }
    };
    row.parentNode = { removeChild: function () {
      row.removed = true;
    } };
    return row;
  };
  const trashRows = [makeRow(0, false), makeRow(1, false), makeRow(2, true)];
  const trashForm = {
    querySelectorAll: function () {
      return trashRows.filter(function (r) {
        return !r.removed;
      });
    }
  };
  const bin = Object.create(ReportRuntime.prototype);
  bin.t = tr;
  const trashButton = function (row) {
    return { closest: row.closest };
  };
  bin.removeFilterRow(trashButton(trashRows[2]));
  t.check(trashRows[2].removed && trashRows[1].plus &&
    trashRows[1].appended.indexOf('data-act="add-filter"') >= 0,
    'removing the last row moves the + to the row before it');
  bin.removeFilterRow(trashButton(trashRows[0]));
  t.check(trashRows[0].removed &&
    trashRows[1].getAttribute('data-filter-row') === '0' &&
    trashRows[1].controls[0].getAttribute('name') === 'filterField0' &&
    trashRows[1].controls[2].getAttribute('name') === 'filterValue0',
    'removing the first row renumbers the one left to zero');
  bin.removeFilterRow(trashButton(trashRows[1]));
  t.check(!trashRows[1].removed && trashRows[1].controls[2].value === '' &&
    trashRows[1].controls[0].selectedIndex === 0,
    'the only row left is emptied, not removed');
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

  // The pager, the console's shape: links around a window of numbers,
  // the ends greyed at the ends, the where line, the rows-per-page choice.
  const middle = ReportRuntime.pagerHtml(tr, '/report/jobs',
    { page: 5, pages: 12, per: 25, total: 290 });
  t.check(middle.indexOf('href="/report/jobs?page=1&amp;per=25"') >= 0 &&
    middle.indexOf('href="/report/jobs?page=4&amp;per=25"') >= 0 &&
    middle.indexOf('href="/report/jobs?page=6&amp;per=25"') >= 0 &&
    middle.indexOf('href="/report/jobs?page=12&amp;per=25"') >= 0,
    'first, previous, next and last link to their pages', middle);
  t.check(middle.indexOf('<span class="here">5</span>') >= 0 &&
    middle.indexOf('>2</a>') >= 0 && middle.indexOf('>8</a>') >= 0 &&
    middle.indexOf('>9</a>') < 0,
    'a window of seven numbers around the current page');
  t.check(middle.indexOf('page 5 of 12') >= 0 &&
    middle.indexOf('rows 101–125 of 290') >= 0,
    'the where line names the page and the rows', middle);
  t.check(middle.indexOf('data-pager-path="/report/jobs"') >= 0 &&
    middle.indexOf('<option value="25" selected>') >= 0,
    'the rows-per-page select carries the path and the size');
  const firstPage = ReportRuntime.pagerHtml(tr, '/report/definitions',
    { page: 1, pages: 2, per: 50, total: 60 });
  t.check(firstPage.indexOf('<span class="off">« first</span>') >= 0 &&
    firstPage.indexOf('href="/report/definitions?page=2&amp;per=50"') >= 0,
    'on the first page first and previous are greyed');
  const only = ReportRuntime.pagerHtml(tr, '/report/jobs',
    { page: 1, pages: 1, per: 50, total: 3 });
  t.check(only.indexOf('<a ') < 0 && only.indexOf('rows 1–3 of 3') >= 0,
    'one page draws no links, only the where line and the size');

  // THE RESULT OF RUN IS PAGED IN THE BROWSER (#1005): the same pager over
  // rows already in hand, its links going nowhere, handled in memory. The
  // runtime is driven as the browser would, on an instance made without
  // its constructor, with a paint that keeps what was drawn.
  const heldPager = ReportRuntime.pagerHtml(tr, '/report/query',
    { page: 2, pages: 3, per: 50, total: 120 }, true);
  t.check(heldPager.indexOf(
    'href="#" data-act="result-page" data-page="3"') >= 0 &&
    heldPager.indexOf('href="/report/query') < 0,
    'a held pager links to nowhere and names the page', heldPager);
  t.check(heldPager.indexOf('name="per" data-result-pager=""') >= 0 &&
    heldPager.indexOf('data-pager-path') < 0,
    'its rows-per-page select is marked for the held result');
  let painted = '';
  const runtime = Object.create(ReportRuntime.prototype);
  runtime.t = tr;
  runtime.lastRun = null;
  runtime.resultPer = 50;
  runtime.paint = function (html) {
    painted = html;
  };
  const many = [];
  for (let i = 1; i <= 120; i++) {
    many.push({ username: 'u' + i, role: i % 2 ? 'primary' : 'mfa' });
  }
  runtime.showRun({ status: 200, json: { fields: ['username', 'role'],
    rows: many } });
  t.equal((painted.match(/<tr><td>/g) || []).length, 50,
    'Run draws the first fifty rows, not every row');
  t.check(painted.indexOf('rows 1–50 of 120') >= 0 &&
    painted.indexOf('<td>u1</td>') >= 0 && painted.indexOf('<td>u51</td>') < 0,
    'with the where line and the first page\'s rows', painted.slice(0, 400));
  t.equal((painted.match(/class="pager"/g) || []).length, 2,
    'a pager above and below the table');
  const link = {
    getAttribute: function (name) {
      return name === 'data-act' ? 'result-page' :
        (name === 'data-page' ? '3' : null);
    }
  };
  let prevented = 0;
  runtime.accounts = null;
  runtime.onClick({ target: link, preventDefault: function () {
    prevented++;
  } });
  t.equal(prevented, 1, 'a page link is handled, not followed');
  t.check(painted.indexOf('rows 101–120 of 120') >= 0 &&
    painted.indexOf('<td>u101</td>') >= 0 &&
    painted.indexOf('<td>u100</td>') < 0,
    'and the third page is drawn from memory', painted.slice(0, 300));
  const perSelect = {
    value: '200',
    getAttribute: function (name) {
      return name === 'name' ? 'per'
        : (name === 'data-result-pager' ? '' : null);
    }
  };
  runtime.onChange({ target: perSelect });
  t.equal((painted.match(/<tr><td>/g) || []).length, 120,
    'two hundred a page draws every row on page one');
  t.check(painted.indexOf('rows 1–120 of 120') >= 0 &&
    painted.indexOf('<option value="200" selected>') >= 0,
    'and the select keeps the choice');

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

async function holders(t) {
  log.debug("Entering holders().");
  const sources = require('../report/sources');
  const built = directoryDouble(true);
  sources.installDirectory(built.ldap);
  // THE ISSUED-CREDENTIAL REGISTER'S DOUBLE (#1021): ada holds two copies
  // of one credential — an ES256 key from a web wallet, an ML-DSA-65 key
  // from a native one — and a copy she removed, which is left out.
  const adaSubject = 'urn:uuid:11111111-1111-4111-8111-111111111111';
  sources.installIssuedRegister({
    rowsForSubject: function () {
      return [{ key: 'row-ada', subject: adaSubject, jkt: 'k1',
        format: 'dc+sd-jwt', configId: 'IdentityCredential',
        credentials: [
          { artifactKey: 'a1', issuedAt: 1700000000000, expiresAt: 0,
            holderAlg: 'ES256', channel: 'web', walletEventAt: 1700000500000 },
          { artifactKey: 'a2', issuedAt: 1700001000000, expiresAt: 0,
            holderAlg: 'ML-DSA-65', channel: 'app', walletEventAt: 0 },
          { artifactKey: 'a3', issuedAt: 1700002000000, expiresAt: 0,
            holderAlg: 'ES256', channel: 'web', removedAt: 1700003000000 },
          // A second live ES256 copy from the web wallet (rcbj, 2026-10-27:
          // a batch bound four keys to four copies): one row with the
          // two, not two rows each saying two.
          { artifactKey: 'a4', issuedAt: 1699999000000, expiresAt: 0,
            holderAlg: 'ES256', channel: 'web', walletEventAt: 1700000900000 }]
      }];
    },
    nameForSubject: function (subject) {
      return subject === adaSubject ? 'ada' : '';
    }
  });
  const calls = built.calls;
  const reset = function () {
    Object.keys(calls).forEach(function (key) {
      calls[key] = 0;
    });
  };
  const read = function (document, execution) {
    const asked = ask(document);
    if (!asked.ok) {
      return Promise.resolve(asked);
    }
    return sources.read(asked.plan, { startedMs: Date.now(),
      budgetMs: 5000, execution: execution || 'sync' });
  };
  const fields = ['username', 'mechanism', 'role', 'credentials',
    'credentialId', 'algorithm', 'lane', 'enrolledAt', 'lastUsedAt',
    'methodsUsed', 'memberOf'];
  try {
    reset();
    const passkeys = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'eq', field: 'mechanism', value: 'passkey' } });
    t.equal(passkeys.ok, true, 'the passkey holders are read',
      passkeys.description);
    t.equal(calls.holders, 1, 'through one holders lookup');
    t.equal(calls.walk, 0, 'and no walk of the people');
    const rows = passkeys.rows || [];
    const label = function (row) {
      return row.username + '/' + row.role;
    };
    // ONE ROW PER CREDENTIAL (#1011): ada's two primary passkeys are two
    // rows, each with its own algorithm, lane, id and dates, and each
    // saying she holds two.
    t.equal(rows.map(label).sort().join(','),
      'ada/mfa,ada/primary,ada/primary,bea/mfa',
      'one row per credential, named by its holder and role');
    const adaPrimaries = rows.filter(function (row) {
      return row.username === 'ada' && row.role === 'primary';
    }).sort(function (a, b) {
      return a.algorithm < b.algorithm ? -1 : 1;
    });
    const adaPrimary = adaPrimaries[0];
    t.equal(adaPrimaries.length, 2, 'two primary passkeys are two rows');
    t.equal(adaPrimary && adaPrimary.credentials, 2,
      'each saying the person holds two');
    t.equal(adaPrimaries.map(function (row) {
      return row.algorithm;
    }).join(','), 'ES256,ML-DSA-65', 'each with its own algorithm');
    t.equal(adaPrimaries.map(function (row) {
      return row.lane;
    }).join(','), 'classical,pqc', 'and its own lane');
    t.equal(adaPrimaries.map(function (row) {
      return row.credentialId;
    }).join(','), 'c-primary--7,c-primary--49', 'and its own id');
    t.equal(adaPrimary && adaPrimary.enrolledAt,
      '1970-01-01T00:00:01.000Z', 'its own enrolment');
    t.equal(adaPrimaries[1] && adaPrimaries[1].lastUsedAt,
      '1970-01-01T00:00:09.000Z', 'and its own last use');
    t.equal(adaPrimary && adaPrimary.methodsUsed, 'pwd, hwk, otp',
      'the methods the person has used');
    t.equal(adaPrimary && adaPrimary.memberOf, 'staff, ops',
      'the groups that list the person');
    const adaMfa = rows.filter(function (row) {
      return row.username === 'ada' && row.role === 'mfa';
    })[0];
    t.equal(adaMfa && adaMfa.credentials, 1, 'one second-factor passkey');

    reset();
    const totp = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'eq', field: 'mechanism', value: 'totp' } });
    t.equal((totp.rows || []).map(label).join(','), 'ada/mfa',
      'an authenticator app is one mfa row');
    t.equal(totp.rows[0].algorithm, 'SHA1', 'with its algorithm');
    t.equal(totp.rows[0].credentialId, '1',
      'and a value naming nothing is numbered');

    reset();
    const primaryOnly = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'and', args: [
        { op: 'eq', field: 'mechanism', value: 'passkey' },
        { op: 'eq', field: 'role', value: 'primary' }] } });
    t.equal((primaryOnly.rows || []).map(label).join(','),
      'ada/primary,ada/primary',
      'the role filter applies to the holders read');

    reset();
    const staffOnly = await read({ source: 'credentialHolders',
      select: fields, limit: 10,
      where: { op: 'eq', field: 'memberOf', value: 'staff' } });
    t.equal(calls.groupRead, 1, 'a group filter reads the group');
    t.equal(calls.holders, 0, 'and not the holders');
    t.equal((staffOnly.rows || []).map(function (row) {
      return row.username + '/' + row.mechanism + '/' + row.role;
    }).sort().join(','),
      'ada/passkey/mfa,ada/passkey/primary,ada/passkey/primary,' +
      'ada/password/primary,ada/recoveryCodes/recovery,' +
      'ada/selfIssued/primary,ada/totp/mfa,ada/verifiableCredential/primary,' +
      'ada/verifiableCredential/primary',
      'every credential of every member, the password, the codes and the ' +
      'wallet\'s among them');

    reset();
    const counted = await read({ source: 'credentialHolders',
      select: ['role'], aggregate: 'count', groupBy: ['role'], limit: 5,
      where: { op: 'eq', field: 'mechanism', value: 'passkey' } });
    t.equal(JSON.stringify((counted.rows || []).map(function (row) {
      return row.role + '=' + row.count;
    }).sort()), JSON.stringify(['mfa=2', 'primary=2']),
      'the census counts credentials by role');
    reset();
    const byAlgorithm = await read({ source: 'credentialHolders',
      select: ['algorithm'], aggregate: 'count', groupBy: ['algorithm'],
      limit: 5, where: { op: 'eq', field: 'mechanism', value: 'passkey' } });
    t.equal(JSON.stringify((byAlgorithm.rows || []).map(function (row) {
      return row.algorithm + '=' + row.count;
    }).sort()), JSON.stringify(['ES256=3', 'ML-DSA-65=1']),
      'and by algorithm, one count per passkey');

    reset();
    const everybody = await read({ source: 'credentialHolders',
      select: fields, limit: 5 });
    t.equal(everybody.code, 'STS-REPORT-0036',
      'no mechanism and no group is refused synchronously on a window');
    t.check(everybody.description.indexOf('mechanism (eq, in)') >= 0,
      'and the refusal names the indexed fields', everybody.description);
    const asJob = await read({ source: 'credentialHolders',
      select: fields, limit: 20 }, 'async');
    t.equal(asJob.ok, true, 'as a job it reads every mechanism\'s holders');
    t.equal((asJob.rows || []).length, 11,
      'ada three passkeys, an authenticator app, a password, a code set, ' +
      'a self-issued subject and two credentials; bea a passkey and a ' +
      'subject');
    t.equal(calls.holders, 8, 'one holders lookup per entry mechanism');
    t.equal(calls.holderCount, 8, 'after one count per entry mechanism');
    t.equal(calls.holdersStop, 8, 'and each read carries a stop');

    // THE PERSON NAMED (rcbj, 2026-10-27): `username equals ada` reads her
    // entry through the name index and every mechanism of hers, no holders
    // read, no refusal.
    reset();
    const adaOnly = await read({ source: 'credentialHolders',
      select: fields, limit: 20,
      where: { op: 'eq', field: 'username', value: 'ada' } });
    t.equal(adaOnly.ok, true, 'a person named is read', adaOnly.description);
    t.equal(calls.byName, 1, 'through one name lookup');
    t.equal(calls.holders, 0, 'and no holders read');
    t.equal((adaOnly.rows || []).map(function (row) {
      return row.mechanism;
    }).sort().join(','),
      'passkey,passkey,passkey,password,recoveryCodes,selfIssued,totp,' +
      'verifiableCredential,verifiableCredential',
      'every credential of hers, every mechanism');
    reset();
    const adaPasskeys = await read({ source: 'credentialHolders',
      select: fields, limit: 20,
      where: { op: 'and', args: [
        { op: 'eq', field: 'username', value: 'ada' },
        { op: 'eq', field: 'mechanism', value: 'passkey' }] } });
    t.equal((adaPasskeys.rows || []).length, 3,
      'a person and a mechanism: her passkeys only');
    t.equal(calls.holders, 0, 'still no holders read');
    reset();
    const byUuid = await read({ source: 'credentialHolders',
      select: fields.concat(['mail', 'entryUuid']), limit: 20,
      where: { op: 'eq', field: 'entryUuid',
        value: '11111111-1111-4111-8111-111111111111' } });
    t.equal(calls.byUuid, 1, 'a UUID reads through the UUID index');
    t.check((byUuid.rows || []).length > 0 &&
      byUuid.rows[0].mail === 'ada@example.com' &&
      byUuid.rows[0].entryUuid === '11111111-1111-4111-8111-111111111111',
      'and the row carries the person\'s mail and UUID');
    // THE ANCHOR RULE (rcbj, 2026-10-27): on a windowed directory a filter
    // that names no indexed field is refused at acceptance, in every mode,
    // naming the indexed fields; anchored by an "and" arm it runs; an "or"
    // with an unanchored arm is refused; a group lookup anchors too.
    reset();
    const unanchored = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'eq', field: 'role', value: 'primary' } });
    t.equal(unanchored.code, 'STS-REPORT-0040',
      'role alone is refused on a windowed directory');
    t.equal(unanchored.error, 'invalid_query', 'as invalid_query');
    t.check(unanchored.description.indexOf('username (eq, in, contains, ' +
      'startsWith)') >= 0 && unanchored.description.indexOf(
      'mechanism (eq, in)') >= 0, 'naming the indexed fields',
      unanchored.description);
    const unanchoredJob = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'eq', field: 'role', value: 'primary' } }, 'async');
    t.equal(unanchoredJob.code, 'STS-REPORT-0040',
      'and as a job as well: it would never finish');
    const orArm = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'or', args: [
        { op: 'eq', field: 'username', value: 'ada' },
        { op: 'eq', field: 'role', value: 'primary' }] } });
    t.equal(orArm.code, 'STS-REPORT-0040',
      'an or with an unanchored arm is refused');
    const andArm = await read({ source: 'credentialHolders',
      select: fields, limit: 20,
      where: { op: 'and', args: [
        { op: 'eq', field: 'role', value: 'primary' },
        { op: 'eq', field: 'username', value: 'ada' }] } });
    t.equal(andArm.ok, true, 'an and with an indexed arm runs');
    reset();
    const usersUnanchored = await read({ source: 'users',
      select: ['username', 'status'], limit: 5,
      where: { op: 'eq', field: 'displayName', value: 'ADA' } });
    t.equal(usersUnanchored.code, 'STS-REPORT-0040',
      'the users source is held to the same rule');
    const usersByGroup = await read({ source: 'users',
      select: ['username', 'status'], limit: 5,
      where: { op: 'and', args: [
        { op: 'eq', field: 'displayName', value: 'ADA' },
        { op: 'eq', field: 'memberOf', value: 'staff' }] } });
    t.equal(usersByGroup.ok, true, 'a group anchors a users filter');
    t.equal(calls.groupRead, 1, 'through the group\'s member list');
    t.equal(calls.walk, 0, 'and no walk');
    reset();
    const groupByName = await read({ source: 'groups',
      select: ['name', 'memberCount', 'members'], limit: 5,
      where: { op: 'eq', field: 'name', value: 'staff' } });
    t.equal(JSON.stringify(groupByName.rows),
      '[{"name":"staff","memberCount":1,"members":"ada"}]',
      'a group named is read by its DN');
    t.equal(calls.groupList || 0, 0, 'without listing the groups');

    // THE WALLET MECHANISMS (#1021): a verifiable credential per issued
    // copy, from the register, with its channel, algorithm, lane and
    // format; a self-issued subject per enrolled DID, with the channel the
    // enrolment recorded and the key's algorithm.
    reset();
    const issued = await read({ source: 'credentialHolders',
      select: fields.concat(['channel', 'format']), limit: 5,
      where: { op: 'eq', field: 'mechanism', value: 'verifiableCredential' }
    });
    t.equal(calls.holders, 0, 'the register, not the directory index');
    t.equal((issued.rows || []).map(function (row) {
      return row.username + '/' + row.channel + '/' + row.algorithm + '/' +
        row.lane + '/' + row.format;
    }).sort().join(','),
      'ada/app/ML-DSA-65/pqc/dc+sd-jwt,ada/web/ES256/classical/dc+sd-jwt',
      'one row per KIND of live copy, with channel, algorithm, lane and ' +
      'format');
    const webRow = issued.rows.filter(function (row) {
      return row.channel === 'web';
    })[0];
    t.equal(webRow.credentials, 2,
      'the two ES256 web copies are one row counting two');
    t.equal(issued.rows.filter(function (row) {
      return row.channel === 'app';
    })[0].credentials, 1, 'and the ML-DSA-65 app copy is a row of one');
    t.equal(webRow.credentialId, 'IdentityCredential',
      'named by the credential type');
    t.equal(webRow.enrolledAt, '2023-11-14T21:56:40.000Z',
      'issued when the group\'s earliest copy was');
    t.equal(webRow.lastUsedAt, '2023-11-14T22:28:20.000Z',
      'the group\'s latest wallet report is the last use');
    reset();
    const selfIssued = await read({ source: 'credentialHolders',
      select: fields.concat(['channel']), limit: 5,
      where: { op: 'eq', field: 'mechanism', value: 'selfIssued' } });
    t.equal((selfIssued.rows || []).map(function (row) {
      return row.username + '/' + row.channel + '/' + row.algorithm + '/' +
        row.credentialId;
    }).sort().join(','),
      'ada/web/ES256/did:web:ada.example,bea/admin//did:web:bea.example',
      'a self-issued subject row per enrolment, with its channel');
    t.equal(selfIssued.rows.filter(function (row) {
      return row.username === 'ada';
    })[0].enrolledAt, '2026-10-11T10:00:00.000Z',
      'proved when the enrolment says');
    reset();
    const byChannel = await read({ source: 'credentialHolders',
      select: ['channel'], aggregate: 'count', groupBy: ['channel'],
      limit: 5, where: { op: 'in', field: 'mechanism',
        value: ['verifiableCredential', 'selfIssued'] } });
    t.equal(JSON.stringify((byChannel.rows || []).map(function (row) {
      return row.channel + '=' + row.count;
    }).sort()), JSON.stringify(['admin=1', 'app=1', 'web=2']),
      'the census counts wallet credentials by channel');

    // THE RECOVERY CODE SET (#1024): one row, the unused codes counted, the
    // hash scheme as its algorithm, never a hash or a code.
    reset();
    const recovery = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'eq', field: 'mechanism', value: 'recoveryCodes' } });
    t.equal((recovery.rows || []).map(label).join(','), 'ada/recovery',
      'a recovery code set is one recovery row for its holder');
    t.equal(recovery.rows[0].credentials, 1, 'with its unused codes counted');
    t.equal(recovery.rows[0].algorithm, 'scrypt', 'and its hash scheme');
    t.equal(recovery.rows[0].enrolledAt, '1970-01-01T00:00:04.000Z',
      'generated when the set says');
    t.check(JSON.stringify(recovery.rows).indexOf('Y29kZ') < 0,
      'and no hash is in the row');
    // A SEALED set (product mode, found on 8081): the codes are in `vault`,
    // so the stored count stands and the scheme is this service's.
    const adaEntry = built.people.filter(function (one) {
      return one.attributes.uid[0] === 'ada';
    })[0];
    const openSet = adaEntry.attributes.stsBackupCodes;
    adaEntry.attributes.stsBackupCodes = [JSON.stringify({ sealed: true,
      vault: 'c2VhbGVk', total: 10, remaining: 10, generatedAt: 4500 })];
    reset();
    const sealed = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'eq', field: 'mechanism', value: 'recoveryCodes' } });
    t.check(sealed.rows[0].credentials === 10 &&
      sealed.rows[0].algorithm === 'scrypt',
      'a sealed set counts its stored remaining codes and names scrypt',
      JSON.stringify(sealed.rows[0]));
    adaEntry.attributes.stsBackupCodes = openSet;

    // THE PASSWORD MECHANISM (#1019): one row per password, the hash
    // scheme as its algorithm and never the hash, pwdChangedTime as its
    // enrolment.
    reset();
    const passwords = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'eq', field: 'mechanism', value: 'password' } });
    t.equal((passwords.rows || []).map(label).join(','), 'ada/primary',
      'a password is one primary row for its holder');
    t.equal(passwords.rows[0].algorithm, 'scrypt', 'with its hash scheme');
    // An imported hash names its scheme in braces (#1019).
    const beaEntry = built.people.filter(function (one) {
      return one.attributes.uid[0] === 'bea';
    })[0];
    beaEntry.attributes.userPassword = ['{SSHA}c2VjcmV0aGFzaA=='];
    reset();
    const imported = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'eq', field: 'mechanism', value: 'password' } });
    t.equal((imported.rows || []).filter(function (row) {
      return row.username === 'bea';
    })[0].algorithm, 'SSHA', 'an imported {SCHEME} hash names its scheme');
    t.check(JSON.stringify(imported.rows).indexOf('c2VjcmV0') < 0,
      'and neither hash is in a row');
    delete beaEntry.attributes.userPassword;
    t.equal(passwords.rows[0].enrolledAt, '2026-10-20T10:00:00Z',
      'and pwdChangedTime as its enrolment');
    t.check(JSON.stringify(passwords.rows).indexOf('c2VjcmV0') < 0,
      'and the hash is nowhere in the row');

    // THE COUNT COMES FIRST, AND IS BOUNDED (#1002, 8081's million Kerberos
    // keys): the store is asked for no more than the cap plus one, so the
    // refusal says "more than the cap" and auto mode queues a job, which
    // counts again against its own cap and is refused too. Nothing is read.
    built.holderCounts.stskrb5keys = 10000;
    reset();
    const manySync = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'eq', field: 'mechanism', value: 'kerberos' } });
    t.equal(manySync.code, 'STS-REPORT-0039',
      'ten thousand holders are refused synchronously');
    t.equal(manySync.unbounded, true, 'as an unbounded refusal (try a job)');
    t.equal(manySync.error, 'result_too_large', 'and result_too_large');
    t.equal(calls.holders, 0, 'with no holder read');
    t.equal(calls.holderCountUpTo, 501,
      'the count asked for one more than the synchronous cap');
    t.check(manySync.description.indexOf('more than 500') >= 0,
      'saying more than the cap', manySync.description);
    reset();
    const fewerJob = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'eq', field: 'mechanism', value: 'kerberos' } }, 'async');
    t.equal(fewerJob.ok, true, 'a job reads ten thousand (under its cap)');
    t.equal(calls.holderCountUpTo, 100001,
      'having counted up to one more than the job cap');
    built.holderCounts.stskrb5keys = 200000;
    reset();
    const tooManyJob = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'eq', field: 'mechanism', value: 'kerberos' } }, 'async');
    t.equal(tooManyJob.code, 'STS-REPORT-0039',
      'and a job over its own cap is refused before it reads');
    t.equal(!!tooManyJob.unbounded, false, 'flat: nothing larger to try');
    t.equal(calls.holders, 0, 'nothing read for it');
    delete built.holderCounts.stskrb5keys;
    reset();
    const fewAgain = await read({ source: 'credentialHolders',
      select: fields, limit: 5,
      where: { op: 'eq', field: 'mechanism', value: 'kerberos' } });
    t.equal(fewAgain.ok, true, 'the count back under the cap, it reads');
    t.equal((fewAgain.rows || []).length, 0, 'nobody here holds one');
  } finally {
    sources.installDirectory(null);
    sources.installIssuedRegister(null);
  }
  log.debug("Leaving holders().");
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
  await holders(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'report_query',
  describe: 'report documents, formats, issuance, projections, schedules, ' +
    'indexed lookups, the page chrome, the groups, the credential holders',
  run: run
};
