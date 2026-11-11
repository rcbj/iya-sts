// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/audit_export.js
//
// ---------------------------------------------------------------------------
// AUDIT EXPORT (#641).
//
// The parent must not require common/audit_export. tests/run.js loads every
// test file in one process, and that module builds its instance when it is
// required. A later load of the composition root would then refuse to install
// a second one. Everything that touches the module runs in a child.
//
// What the child holds:
//   S. the canonical event, redaction, the syslog line, the webhook
//      template, acknowledgement URLs, and HTTP classification
//   A. add, update, remove, enable, disable and test, and the codes
//   D. the cursor: prime, a bookmark gap, a sequence hole, skip, one save,
//      stillOwner, hold, recover, give-up, and HTTP 400
//   F. one append, rotation, and a path that climbs
//   Y. one TCP syslog frame
//   H. a webhook that is not followed, and Splunk's one acknowledgement
//   P. private addresses, metadata, and product mode
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_AUDIT_EXPORT_CHILD';
const MARK = 'AUDIT-EXPORT-CHILD ';

const log = require('bunyan').createLogger({ name: 'audit_export',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

function memoryMap() {
  log.debug("Entering memoryMap().");
  const data = new Map();
  const map = {
    get: function (key) {
      log.debug("Entering get().");
      const value = data.has(key) ? data.get(key) : null;
      log.debug("Leaving get().");
      return value;
    },
    set: function (key, value) {
      log.debug("Entering set().");
      data.set(key, value);
      log.debug("Leaving set().");
    },
    delete: function (key) {
      log.debug("Entering delete().");
      data.delete(key);
      log.debug("Leaving delete().");
    },
    forEach: function (fn) {
      log.debug("Entering forEach().");
      data.forEach(fn);
      log.debug("Leaving forEach().");
    }
  };
  log.debug("Leaving memoryMap().");
  return map;
}

function fakeAudit(rows) {
  log.debug("Entering fakeAudit().");
  const recorded = [];
  const book = {
    rows: rows || [],
    recorded: recorded,
    localEvents: function () {
      log.debug("Entering localEvents().");
      log.debug("Leaving localEvents().");
      return book.rows.slice();
    },
    failure: function (errorCode, row) {
      log.debug("Entering failure().");
      recorded.push(Object.assign({ kind: 'failure',
                                    errorCode: errorCode }, row || {}));
      log.debug("Leaving failure().");
    },
    audit: function (row) {
      log.debug("Entering audit().");
      recorded.push(Object.assign({ kind: 'audit' }, row || {}));
      log.debug("Leaving audit().");
    }
  };
  log.debug("Leaving fakeAudit().");
  return book;
}

function scriptedDns(table) {
  log.debug("Entering scriptedDns().");
  function lookup(host) {
    log.debug("Entering lookup().");
    const name = String(host || '').toLowerCase();
    const answer = Object.prototype.hasOwnProperty.call(table, name)
      ? table[name] : [{ address: '8.8.8.8', family: 4 }];
    if (answer === 'fail') {
      log.debug("Leaving lookup(). Failed.");
      return Promise.reject(new Error('lookup failed'));
    }
    log.debug("Leaving lookup().");
    return Promise.resolve(answer);
  }
  log.debug("Leaving scriptedDns().");
  return { lookup: lookup };
}

function fakeTransport(script) {
  log.debug("Entering fakeTransport().");
  const calls = [];
  function request(options, cb) {
    log.debug("Entering request().");
    const chunks = [];
    const req = {
      setTimeout: function () {
        return req;
      },
      on: function () {
        return req;
      },
      write: function (buf) {
        chunks.push(Buffer.from(buf));
        return true;
      },
      end: function () {
        const body = Buffer.concat(chunks).toString('utf8');
        const call = { options: options, body: body,
                       headers: options.headers || {} };
        calls.push(call);
        const answered = script(call);
        const status = answered.status;
        const res = {
          statusCode: status,
          headers: answered.headers || {},
          destroy: function () {},
          on: function (ev, fn) {
            if (ev === 'data' && answered.body != null &&
                !(status >= 300 && status < 400)) {
              const raw = typeof answered.body === 'string'
                ? answered.body : JSON.stringify(answered.body);
              fn(Buffer.from(raw));
            }
            if (ev === 'end') {
              process.nextTick(fn);
            }
            return res;
          }
        };
        cb(res);
      },
      destroy: function () {}
    };
    log.debug("Leaving request().");
    return req;
  }
  log.debug("Leaving fakeTransport().");
  return { request: request, calls: calls };
}

function makeExporter(AuditExport, base, parts) {
  log.debug("Entering makeExporter().");
  const given = parts || {};
  const deps = {
    log: log,
    config: base.config,
    mode: base.mode,
    realms: base.realms,
    audit: given.audit || fakeAudit([]),
    errorCodes: base.errorCodes,
    keystore: base.keystore,
    outbound: base.outbound,
    version: base.version,
    scheduler: function () {
      return given.scheduler || null;
    },
    destinations: given.destinations || memoryMap(),
    cursors: given.cursors || memoryMap(),
    fs: given.fs || base.fs,
    http: given.http || base.http,
    https: given.https || base.https,
    dgram: given.dgram || base.dgram,
    dns: given.dns || base.dns,
    net: given.net || base.net,
    tls: given.tls || base.tls,
    path: base.path,
    os: base.os,
    crypto: base.crypto
  };
  const exporter = new AuditExport(deps);
  log.debug("Leaving makeExporter().");
  return exporter;
}

function auditRow(seq, extra) {
  log.debug("Entering auditRow().");
  const row = {
    seq: seq,
    at: 1700000000000,
    category: 'admin',
    action: 'admin.login',
    outcome: 'success',
    actor: 'urn:uuid:person',
    summary: 'event ' + seq,
    detail: { client_id: 'app', note: 'plain' }
  };
  const over = extra || {};
  Object.keys(over).forEach(function (key) {
    row[key] = over[key];
  });
  log.debug("Leaving auditRow().");
  return row;
}

function expectedId(exporter, seq) {
  log.debug("Entering expectedId().");
  const origin = exporter.originId() || 'local';
  log.debug("Leaving expectedId().");
  return origin + ':' + seq;
}

function failures(book, code) {
  log.debug("Entering failures().");
  const rows = book.recorded.filter(function (row) {
    return row.kind === 'failure' && row.errorCode === code;
  });
  log.debug("Leaving failures().");
  return rows;
}

function applyOverride(cfg, key, value, t, what) {
  log.debug("Entering applyOverride().");
  const result = cfg.setOverride(key, value);
  const ok = !!(result && result.ok);
  if (!ok) {
    const errors = result && result.errors ? result.errors.join('; ') : '';
    t.check(false, what, errors);
  }
  log.debug("Leaving applyOverride(). " + ok);
  return ok;
}

function clearKeys(cfg, keys) {
  log.debug("Entering clearKeys().");
  keys.forEach(function (key) {
    cfg.clearOverride(key);
  });
  log.debug("Leaving clearKeys().");
}

function okSend(disposition) {
  log.debug("Entering okSend().");
  log.debug("Leaving okSend().");
  return {
    ok: true, kind: 'ok', disposition: disposition || 'accepted',
    code: '', why: '', retryAfterMs: 0, ackId: null
  };
}

function badSend(kind, code, why) {
  log.debug("Entering badSend().");
  log.debug("Leaving badSend().");
  return {
    ok: false, kind: kind, disposition: 'failed', code: code,
    why: why || 'down', retryAfterMs: 0, ackId: null
  };
}

function countSets(cursors) {
  log.debug("Entering countSets().");
  const state = { n: 0 };
  const raw = cursors.set;
  cursors.set = function (key, value) {
    log.debug("Entering set().");
    state.n += 1;
    raw.call(cursors, key, value);
    log.debug("Leaving set().");
  };
  log.debug("Leaving countSets().");
  return state;
}

async function staticForms(AuditExport, base, t) {
  log.debug("Entering staticForms().");
  const names = new Set(['password', 'token', 'access_token', 'ssn']);
  const redacted = AuditExport.redact({
    password: 'p',
    nested: {
      Token: 't',
      ok: 'keep',
      items: [{ access_token: 'a', ssn: '9' }]
    }
  }, names);
  t.check(redacted.password === '[redacted]' &&
          redacted.nested.Token === '[redacted]' &&
          redacted.nested.ok === 'keep' &&
          redacted.nested.items[0].access_token === '[redacted]' &&
          redacted.nested.items[0].ssn === '[redacted]',
          'S1. nested attributes on the redaction list are replaced',
          JSON.stringify(redacted));
  const filled = AuditExport.fillTemplate(
    '{message} {event_type} {nope}', {
      message: 'see {event_type}',
      action: 'login'
    });
  t.check(filled === 'see {event_type} login {nope}',
          'S2. a template value is not expanded a second time', filled);
  const event = {
    id: 'a"b\\c]d', at: 1700000000000, outcome: 'success',
    action: 'sign in', message: 'ok', realm: 'default',
    origin: 'node-a', seq: 1, category: 'admin'
  };
  const line = AuditExport.syslogLine(event, {
    facility: 16, appName: 'iya-sts'
  });
  t.check(line.indexOf('<133>1 ') === 0 &&
          line.indexOf('[iyaAudit ') >= 0 &&
          line.indexOf('id="a\\"b\\\\c\\]d"') >= 0 &&
          line.indexOf('sign_in') >= 0 &&
          line.charAt(line.length - 1) !== '\n',
          'S3. a success is facility local0 severity notice, and ' +
          'structured data is escaped', line);
  const warned = AuditExport.syslogLine(
    Object.assign({}, event, { outcome: 'refused', message: 'caf\u00e9' }),
    { facility: 16 });
  t.check(warned.indexOf('<132>1 ') === 0 &&
          warned.indexOf('\uFEFF') >= 0,
          'S4. a refusal is severity 4, and a non-ASCII message ' +
          'carries the BOM', warned.slice(0, 40));
  const erred = AuditExport.syslogLine(
    Object.assign({}, event, { outcome: 'error' }), { facility: 16 });
  t.check(erred.indexOf('<131>1 ') === 0,
          'S5. an error is severity 3', erred.slice(0, 12));
  t.check(AuditExport.transportOf({}) === 'tcp' &&
          AuditExport.transportOf({ transport: 'nope' }) === 'tcp' &&
          AuditExport.transportOf({ transport: 'udp' }) === 'udp' &&
          AuditExport.portOf({}) === 514 &&
          AuditExport.portOf({ transport: 'tls' }) === 6514,
          'S6. syslog defaults to TCP port 514, and TLS to 6514');
  t.check(AuditExport.parseMode(640) === parseInt('640', 8) &&
          AuditExport.parseMode('640') === parseInt('640', 8) &&
          AuditExport.parseMode('') === parseInt('640', 8) &&
          AuditExport.parseMode(0) === parseInt('640', 8) &&
          AuditExport.parseMode(999) === -1,
          'S7. a file mode is three octal digits, and 640 is the default');
  const eventUrl = 'https://hec.example/services/collector/event?token=1';
  t.check(AuditExport.ackUrl(eventUrl) ===
          'https://hec.example/services/collector/ack',
          'S8. an /event collector URL acknowledges at /ack',
          AuditExport.ackUrl(eventUrl));
  const collector = 'https://hec.example/services/collector#frag';
  t.check(AuditExport.ackUrl(collector) ===
          'https://hec.example/services/collector/ack',
          'S9. a /collector URL gains /ack, and the fragment is dropped',
          AuditExport.ackUrl(collector));
  const other = 'https://hec.example/services/x?x=1';
  t.check(AuditExport.ackUrl(other) ===
          'https://hec.example/services/x/ack',
          'S10. any other path gains /ack, and the query is dropped',
          AuditExport.ackUrl(other));
  const rejected = AuditExport.classifyHttp(
    { status: 400, json: null, retryAfterMs: 0 }, false);
  const redirected = AuditExport.classifyHttp(
    { status: 302, code: 'STS-AUDIT-0014', why: 'redirect',
      retryAfterMs: 0, json: null }, false);
  const collectorCode = AuditExport.classifyHttp(
    { status: 200, json: { code: 4, ackId: 9 }, retryAfterMs: 0 }, true);
  const waiting = AuditExport.classifyHttp(
    { status: 200, json: { code: 0, ackId: 9 }, retryAfterMs: 0 }, true);
  const limited = AuditExport.classifyHttp(
    { status: 429, json: null, retryAfterMs: 2000, why: 'slow' }, false);
  t.check(rejected.kind === 'permanent' &&
          rejected.code === 'STS-AUDIT-0015' &&
          redirected.kind === 'pause' &&
          redirected.code === 'STS-AUDIT-0014' &&
          collectorCode.kind === 'pause' &&
          collectorCode.code === 'STS-AUDIT-0007' &&
          waiting.kind === 'ack-wait' && waiting.ackId === 9 &&
          limited.kind === 'transient' && limited.retryAfterMs === 2000,
          'S11. HTTP 400 is permanent, a redirect and a collector ' +
          'code pause, and an ack id waits');
  t.check(AuditExport.isPrivate('100.64.0.1') &&
          AuditExport.isPrivate('100.127.255.1') &&
          !AuditExport.isPrivate('100.63.255.1') &&
          !AuditExport.isPrivate('100.128.0.1') &&
          AuditExport.isPrivate('10.1.2.3') &&
          AuditExport.isPrivate('::1') &&
          !AuditExport.isPrivate('8.8.8.8'),
          'S12. RFC 6598 100.64.0.0/10 is private, and its neighbours ' +
          'are not');
  t.check(AuditExport.isMetadata('169.254.169.254') &&
          AuditExport.isMetadata('::ffff:169.254.169.254') &&
          AuditExport.isMetadata('metadata.google.internal') &&
          AuditExport.isMetadata('x.metadata.google.internal') &&
          AuditExport.isMetadata('instance-data.ec2.internal') &&
          !AuditExport.isMetadata('8.8.8.8'),
          'S13. cloud metadata names and 169.254.169.254 are metadata');
  const cleaned = AuditExport.safeWhy(
    'down https://secret.example/token\nnext');
  t.check(cleaned.indexOf('https://') < 0 &&
          cleaned.indexOf('[url]') >= 0 && cleaned.indexOf('\n') < 0,
          'S14. a stored failure drops the URL', cleaned);
  const jobs = {};
  const scheduler = {
    job: function (id) {
      log.debug("Entering job().");
      log.debug("Leaving job().");
      return jobs[id] || null;
    },
    register: function (job) {
      log.debug("Entering register().");
      jobs[job.id] = job;
      log.debug("Leaving register().");
    }
  };
  const exporter = makeExporter(AuditExport, base, { scheduler: scheduler });
  t.check(exporter.registerJobs() === true &&
          jobs['audit.export'].kind === 'per-process' &&
          jobs['audit.export'].scope === 'realm' &&
          jobs['audit.export'].quiet === true &&
          jobs['audit.export'].everySetting === 'auditExport.intervalS' &&
          exporter.registerJobs() === false,
          'S15. audit.export is one quiet per-process realm job');
  t.check(exporter.offHere() === 'No audit export destination is enabled.',
          'S16. the job is off while no destination is enabled',
          exporter.offHere());
  log.debug("Leaving staticForms().");
}

async function acts(AuditExport, base, codes, t) {
  log.debug("Entering acts().");
  const book = fakeAudit([]);
  const dnsTable = {};
  const exporter = makeExporter(AuditExport, base, {
    audit: book,
    dns: scriptedDns(dnsTable)
  });
  const unknown = await exporter.act({ action: 'nope' });
  t.check(unknown.ok === false &&
          codes.codeOf(unknown) === 'STS-AUDIT-0001',
          'A1. an unknown act is STS-AUDIT-0001', codes.codeOf(unknown));
  const badId = await exporter.act({
    action: 'add', id: 'Bad_Id', type: 'syslog', host: 'siem.example'
  });
  t.check(badId.ok === false && codes.codeOf(badId) === 'STS-AUDIT-0001',
          'A2. an id outside the register shape is STS-AUDIT-0001',
          codes.codeOf(badId));
  const added = await exporter.act({
    action: 'add', id: 'siem', type: 'syslog', name: 'SIEM',
    host: 'siem.example', transport: 'tcp'
  });
  t.check(added.ok === true && added.destination.host === 'siem.example' &&
          added.destination.transport === 'tcp',
          'A3. a syslog destination is stored', JSON.stringify(added));
  const duplicate = await exporter.act({
    action: 'add', id: 'siem', type: 'syslog', host: 'siem.example'
  });
  t.check(duplicate.ok === false &&
          codes.codeOf(duplicate) === 'STS-AUDIT-0001',
          'A4. a duplicate id is STS-AUDIT-0001',
          codes.codeOf(duplicate));
  const missing = await exporter.act({ action: 'update', id: 'missing' });
  t.check(missing.ok === false &&
          codes.codeOf(missing) === 'STS-AUDIT-0002',
          'A5. an unknown id is STS-AUDIT-0002', codes.codeOf(missing));
  const token = 'tok-keep-me';
  const hec = await exporter.act({
    action: 'add', id: 'hec', type: 'splunk', name: 'HEC',
    url: 'https://hec.example/services/collector/event',
    token: token, ack: true
  });
  const view = exporter.view();
  const shown = JSON.stringify(view);
  t.check(hec.ok === true && shown.indexOf(token) < 0 &&
          view.thisProcess === true,
          'A6. a view names this process and does not carry the token',
          shown.slice(0, 400));
  const hecRow = view.destinations.filter(function (row) {
    return row.id === 'hec';
  })[0];
  t.check(hecRow && hecRow.tokenSet === true && hecRow.token === undefined,
          'A7. the page learns that a token is set, not what it is',
          JSON.stringify(hecRow));
  const kept = await exporter.act({
    action: 'update', id: 'hec', token: ''
  });
  const stored = exporter.readDest('hec');
  t.check(kept.ok === true && exporter.openBox(stored.token) === token,
          'A8. an empty token on update keeps the stored one',
          exporter.openBox(stored && stored.token));
  const secret = 'Bearer hidden';
  const hook = await exporter.act({
    action: 'add', id: 'hook', type: 'webhook', name: 'Hook',
    url: 'https://hooks.example/in',
    headers: 'Authorization: ' + secret + '\nX-Trace: yes',
    template: '{message}'
  });
  const hookView = exporter.view();
  const hookRow = hookView.destinations.filter(function (row) {
    return row.id === 'hook';
  })[0];
  const hookText = JSON.stringify(hookView);
  t.check(hook.ok === true && hookText.indexOf(secret) < 0 &&
          hookText.indexOf('hidden') < 0 &&
          hookRow.secretHeaderSet.indexOf('Authorization') >= 0 &&
          hookRow.headerText.indexOf('X-Trace') >= 0 &&
          hookRow.headerText.indexOf('Authorization') < 0,
          'A9. a credential header is sealed and leaves the plain set',
          hookText.slice(0, 500));
  const renamed = await exporter.act({
    action: 'update', id: 'hook', name: 'Hook two'
  });
  const still = exporter.publicDest(exporter.readDest('hook'));
  t.check(renamed.ok === true &&
          still.headerText.indexOf('X-Trace') >= 0,
          'A10. an update that omits headers keeps them', still.headerText);
  const cleared = await exporter.act({
    action: 'update', id: 'hook', headers: ''
  });
  const afterClear = exporter.publicDest(exporter.readDest('hook'));
  t.check(cleared.ok === true && afterClear.headerText === '' &&
          afterClear.secretHeaderSet.indexOf('Authorization') >= 0,
          'A11. empty plain headers replace, and secret headers stay',
          JSON.stringify(afterClear.secretHeaderSet));
  const fsMod = require('fs');
  const os = require('os');
  const dir = fsMod.mkdtempSync(path.join(os.tmpdir(), 'audit-export-'));
  const file = path.join(dir, 'audit.ndjson');
  const created = await exporter.act({
    action: 'add', id: 'files', type: 'file', name: 'File',
    path: file, mode: '640'
  });
  t.check(created.ok === true && created.destination.path === file,
          'A12. an absolute file path is stored', JSON.stringify(created));
  exporter.putCursor('files', Object.assign(AuditExport.emptyCursor(), {
    primed: true, seq: 9, failingSince: 5
  }));
  const tested = await exporter.act({ action: 'test', id: 'files' });
  const cursor = exporter.readCursor('files');
  const testRows = book.recorded.filter(function (row) {
    return row.action === 'admin.audit-export.test';
  });
  const onDisk = fsMod.readFileSync(file, 'utf8');
  let synthetic = {};
  try {
    synthetic = JSON.parse(onDisk.trim());
  } catch (e) {
    // The assertion below reports a body that was not one JSON line.
    log.debug("Caught in acts(): " + ((e && e.message) || e));
    synthetic = { parse: String((e && e.message) || e) };
  }
  t.check(tested.ok === true && tested.diagnostic.test === true &&
          cursor.seq === 9 && cursor.failingSince === 5 &&
          book.rows.length === 0 && testRows.length === 1 &&
          testRows[0].outcome === 'success' &&
          !testRows[0].detail.exportSkip &&
          synthetic.action === 'audit.export.test' &&
          synthetic.attributes && synthetic.attributes.test === true &&
          String(synthetic.id).indexOf('test:files:') === 0,
          'A13. the synthetic test is not an audit row, and the ' +
          'cursor stays', JSON.stringify({
            ok: tested.ok, seq: cursor.seq, audit: testRows.length,
            action: synthetic.action
          }));
  const climb = await exporter.act({
    action: 'add', id: 'climb', type: 'file',
    path: dir + '/../etc/passwd'
  });
  t.check(climb.ok === false && codes.codeOf(climb) === 'STS-AUDIT-0004',
          'A14. a path that climbs is STS-AUDIT-0004',
          codes.codeOf(climb));
  const relative = await exporter.act({
    action: 'add', id: 'rel', type: 'file', path: 'audit.ndjson'
  });
  t.check(relative.ok === false &&
          codes.codeOf(relative) === 'STS-AUDIT-0004',
          'A15. a relative path is STS-AUDIT-0004',
          codes.codeOf(relative));
  const badMode = await exporter.act({
    action: 'add', id: 'mode', type: 'file', path: file, mode: '999'
  });
  t.check(badMode.ok === false &&
          codes.codeOf(badMode) === 'STS-AUDIT-0001',
          'A16. a mode that is not octal is STS-AUDIT-0001',
          codes.codeOf(badMode));
  if (applyOverride(base.config, 'auditExport.fileRoots', dir, t,
                    'A17. file roots can be set')) {
    const outside = await exporter.act({
      action: 'add', id: 'out', type: 'file', path: '/etc/hostname'
    });
    t.check(outside.ok === false &&
            codes.codeOf(outside) === 'STS-AUDIT-0004',
            'A17. a path outside the configured roots is refused',
            codes.codeOf(outside));
  }
  clearKeys(base.config, ['auditExport.fileRoots']);
  const disabled = exporter.setEnabled({ id: 'siem' }, false);
  const enabled = exporter.setEnabled({ id: 'siem' }, true);
  t.check(disabled.ok === true && enabled.ok === true &&
          enabled.destination.enabled === true,
          'A18. disable and enable keep the destination');
  const removed = exporter.removeDest({ id: 'siem' });
  const gone = await exporter.act({ action: 'remove', id: 'siem' });
  t.check(removed.ok === true && gone.ok === false &&
          codes.codeOf(gone) === 'STS-AUDIT-0002',
          'A19. remove drops the destination', codes.codeOf(gone));
  const actions = book.recorded.filter(function (row) {
    return row.kind === 'audit';
  }).map(function (row) {
    return row.action;
  });
  t.check(actions.indexOf('admin.audit-export.add') >= 0 &&
          actions.indexOf('admin.audit-export.test') >= 0 &&
          actions.indexOf('admin.audit-export.remove') >= 0,
          'A20. configuration changes are audited', actions.join(','));
  fsMod.rmSync(dir, { recursive: true, force: true });
  log.debug("Leaving acts().");
}

function installCursor(cursors, id, fields) {
  log.debug("Entering installCursor().");
  const AuditExport = fields.cls;
  const stored = Object.assign(AuditExport.emptyCursor(), fields.cursor);
  cursors.set(id, stored);
  log.debug("Leaving installCursor().");
  return stored;
}

async function delivery(AuditExport, base, t) {
  log.debug("Entering delivery().");
  const book = fakeAudit([]);
  const cursors = memoryMap();
  const sets = countSets(cursors);
  const exporter = makeExporter(AuditExport, base, {
    audit: book, cursors: cursors
  });
  const keys = ['auditExport.batch', 'auditExport.retryInitialMs'];
  const batchOk = applyOverride(base.config, 'auditExport.batch', 3, t,
                                'D0. the batch can be set');
  const retryOk = applyOverride(base.config,
                                'auditExport.retryInitialMs', 60000, t,
                                'D0. the first retry delay can be set');
  if (!batchOk || !retryOk) {
    clearKeys(base.config, keys);
    log.debug("Leaving delivery(). Settings refused.");
    return;
  }
  try {
    await deliverAll(AuditExport, exporter, book, cursors, sets, t);
  } finally {
    clearKeys(base.config, keys);
  }
  log.debug("Leaving delivery().");
}

async function deliverAll(AuditExport, exporter, book, cursors, sets, t) {
  log.debug("Entering deliverAll().");
  book.rows = [auditRow(100), auditRow(101)];
  exporter.putDest({
    id: 'prime', type: 'file', enabled: true, path: '/tmp/prime',
    excludeAttributes: ''
  });
  let primeSends = 0;
  exporter.offerEvent = async function () {
    primeSends += 1;
    return okSend('accepted');
  };
  sets.n = 0;
  await exporter.walkDestination('prime', {});
  const primed = exporter.readCursor('prime');
  t.check(primed.primed === true && primed.seq === 101 &&
          primed.delivered === 2 && primed.droppedGap === 0 &&
          primeSends === 2 && failures(book, 'STS-AUDIT-0009').length === 0 &&
          sets.n === 1,
          'D1. an unprimed cursor backfills the ring, and that is not ' +
          'a gap', JSON.stringify({
            seq: primed.seq, gap: primed.droppedGap, sets: sets.n
          }));
  const built = exporter.buildEvent(auditRow(7, {
    detail: {
      password: 'p',
      nested: { Token: 't', ok: 'keep' },
      ssn: '9'
    }
  }), { excludeAttributes: 'ssn' });
  t.check(built.id === expectedId(exporter, 7) &&
          built.attributes.password === '[redacted]' &&
          built.attributes.nested.Token === '[redacted]' &&
          built.attributes.nested.ok === 'keep' &&
          built.attributes.ssn === '[redacted]' &&
          String(built.source).indexOf('audit-export') >= 0,
          'D2. the event id is origin:seq and nested secrets are removed',
          JSON.stringify(built.attributes));
  book.recorded.length = 0;
  book.rows = [auditRow(1), auditRow(3), auditRow(5)];
  exporter.putDest({
    id: 'hole', type: 'file', enabled: true, path: '/tmp/hole',
    excludeAttributes: ''
  });
  installCursor(cursors, 'hole', {
    cls: AuditExport,
    cursor: { primed: true, seq: 0, nextSeq: 1 }
  });
  let holeSends = 0;
  exporter.offerEvent = async function () {
    holeSends += 1;
    return okSend('accepted');
  };
  await exporter.walkDestination('hole', {});
  const holed = exporter.readCursor('hole');
  t.check(holed.droppedGap === 0 && holed.delivered === 3 &&
          holed.seq === 5 && holeSends === 3 &&
          failures(book, 'STS-AUDIT-0009').length === 0,
          'D3. a missing sequence number is not a gap',
          JSON.stringify({ seq: holed.seq, gap: holed.droppedGap }));
  book.recorded.length = 0;
  book.rows = [auditRow(20), auditRow(21)];
  exporter.putDest({
    id: 'gap', type: 'file', enabled: true, path: '/tmp/gap',
    excludeAttributes: ''
  });
  installCursor(cursors, 'gap', {
    cls: AuditExport,
    cursor: { primed: true, seq: 5, nextSeq: 10 }
  });
  await exporter.walkDestination('gap', {});
  const gapped = exporter.readCursor('gap');
  const gapRows = failures(book, 'STS-AUDIT-0009');
  t.check(gapped.droppedGap === 1 && gapped.seq === 21 &&
          gapRows.length === 1 && gapRows[0].detail.bookmark === 10 &&
          gapRows[0].detail.exportSkip === true,
          'D4. a trimmed bookmark is one episode',
          JSON.stringify(gapRows[0] && gapRows[0].detail));
  book.recorded.length = 0;
  book.rows = [
    auditRow(1, { detail: { exportSkip: true } }),
    auditRow(2),
    auditRow(3, { detail: { exportSkip: true } })
  ];
  exporter.putDest({
    id: 'skip', type: 'file', enabled: true, path: '/tmp/skip',
    excludeAttributes: ''
  });
  installCursor(cursors, 'skip', {
    cls: AuditExport,
    cursor: { primed: true, seq: 0, nextSeq: 1 }
  });
  const skippedIds = [];
  exporter.offerEvent = async function (dest, event) {
    skippedIds.push(event.id);
    return okSend('accepted');
  };
  await exporter.walkDestination('skip', {});
  const skipped = exporter.readCursor('skip');
  t.check(skippedIds.length === 1 &&
          skippedIds[0] === expectedId(exporter, 2) &&
          skipped.seq === 3 && skipped.delivered === 1,
          'D5. exportSkip advances the cursor and is not sent',
          skippedIds.join(','));
  book.rows = [auditRow(1), auditRow(2)];
  exporter.putDest({
    id: 'own', type: 'file', enabled: true, path: '/tmp/own',
    excludeAttributes: ''
  });
  const stored = installCursor(cursors, 'own', {
    cls: AuditExport,
    cursor: { primed: true, seq: 0, nextSeq: 1 }
  });
  let owned = 0;
  exporter.offerEvent = async function () {
    return okSend('transmitted');
  };
  sets.n = 0;
  await exporter.walkDestination('own', {
    stillOwner: function () {
      owned += 1;
      return owned < 2;
    }
  });
  const ownedCursor = cursors.get('own');
  t.check(owned === 2 && ownedCursor.seq === 1 &&
          ownedCursor.delivered === 1 && sets.n === 1 &&
          stored.seq === 0 && ownedCursor !== stored,
          'D6. the cursor is saved once, as a new object, and a lost ' +
          'owner stops the walk', JSON.stringify({
            seq: ownedCursor.seq, sets: sets.n, stored: stored.seq
          }));
  book.recorded.length = 0;
  book.rows = [auditRow(1)];
  exporter.putDest({
    id: 'hold', type: 'webhook', enabled: true,
    url: 'https://hooks.example/in', excludeAttributes: ''
  });
  installCursor(cursors, 'hold', {
    cls: AuditExport,
    cursor: { primed: true, seq: 0, nextSeq: 1 }
  });
  let holdSends = 0;
  let holdFail = true;
  exporter.offerEvent = async function () {
    holdSends += 1;
    if (holdFail) {
      return badSend('transient', 'STS-AUDIT-0007',
                     'down https://secret.example/x');
    }
    return okSend('accepted');
  };
  await exporter.walkDestination('hold', {});
  const held = exporter.readCursor('hold');
  const firstFail = failures(book, 'STS-AUDIT-0007');
  t.check(held.seq === 0 && held.failingSince > 0 && held.retries === 1 &&
          held.pausedUntil > Date.now() && holdSends === 1 &&
          firstFail.length === 1 &&
          held.lastFailure.indexOf('https://') < 0,
          'D7. a transient failure holds the cursor and is audited once',
          held.lastFailure);
  await exporter.walkDestination('hold', {});
  t.check(holdSends === 1 && failures(book, 'STS-AUDIT-0007').length === 1,
          'D8. a paused destination is not failed again on the next run',
          String(holdSends));
  const resumed = exporter.readCursor('hold');
  resumed.pausedUntil = 0;
  exporter.putCursor('hold', resumed);
  holdFail = false;
  await exporter.walkDestination('hold', {});
  const recovered = exporter.readCursor('hold');
  const recovery = book.recorded.filter(function (row) {
    return row.kind === 'audit' && row.action === 'service.failure' &&
      row.outcome === 'success';
  });
  t.check(recovered.seq === 1 && recovered.failingSince === 0 &&
          recovery.length === 1 && recovery[0].detail.exportSkip === true,
          'D9. the first success after a failure is one recovery row',
          JSON.stringify(recovery[0] && recovery[0].detail));
  book.recorded.length = 0;
  book.rows = [auditRow(1), auditRow(2), auditRow(3), auditRow(4)];
  exporter.putDest({
    id: 'drop', type: 'webhook', enabled: true,
    url: 'https://hooks.example/in', excludeAttributes: ''
  });
  installCursor(cursors, 'drop', {
    cls: AuditExport,
    cursor: {
      primed: true, seq: 0, nextSeq: 1,
      failingSince: Date.now() - 90000000
    }
  });
  let dropSends = 0;
  exporter.offerEvent = async function () {
    dropSends += 1;
    return badSend('transient', 'STS-AUDIT-0007', 'still down');
  };
  sets.n = 0;
  await exporter.walkDestination('drop', {});
  const dropped = exporter.readCursor('drop');
  const giveUp = failures(book, 'STS-AUDIT-0011');
  t.check(dropSends === 1 && dropped.failedPermanent === 3 &&
          dropped.seq === 3 && dropped.failingSince > 0 &&
          dropped.pausedUntil > Date.now() && giveUp.length === 1 &&
          giveUp[0].detail.count === 3 &&
          giveUp[0].detail.firstId === expectedId(exporter, 1) &&
          giveUp[0].detail.lastId === expectedId(exporter, 3) &&
          sets.n === 1,
          'D10. an expired probe drops one batch and sends only the probe',
          JSON.stringify({
            sends: dropSends, failed: dropped.failedPermanent,
            count: giveUp[0] && giveUp[0].detail.count
          }));
  book.recorded.length = 0;
  book.rows = [auditRow(1), auditRow(2), auditRow(3)];
  exporter.putDest({
    id: 'perm', type: 'webhook', enabled: true,
    url: 'https://hooks.example/in', excludeAttributes: ''
  });
  installCursor(cursors, 'perm', {
    cls: AuditExport,
    cursor: { primed: true, seq: 0, nextSeq: 1 }
  });
  let permSends = 0;
  exporter.offerEvent = async function () {
    permSends += 1;
    return badSend('permanent', 'STS-AUDIT-0015', 'rejected');
  };
  await exporter.walkDestination('perm', {});
  const permanent = exporter.readCursor('perm');
  t.check(permSends === 3 && permanent.seq === 3 &&
          permanent.failedPermanent === 3 && permanent.pausedUntil === 0 &&
          failures(book, 'STS-AUDIT-0015').length === 3 &&
          failures(book, 'STS-AUDIT-0011').length === 0,
          'D11. HTTP 400 advances each event and does not pause',
          JSON.stringify({
            sends: permSends, paused: permanent.pausedUntil
          }));
  if (!applyOverride(exporter.deps.config, 'auditExport.batch', 4, t,
                     'D12. a larger batch can be set')) {
    log.debug("Leaving deliverAll(). No second batch.");
    return;
  }
  book.recorded.length = 0;
  book.rows = [auditRow(1), auditRow(2), auditRow(3), auditRow(4),
               auditRow(5)];
  exporter.putDest({
    id: 'mix', type: 'webhook', enabled: true,
    url: 'https://hooks.example/in', excludeAttributes: ''
  });
  installCursor(cursors, 'mix', {
    cls: AuditExport,
    cursor: {
      primed: true, seq: 0, nextSeq: 1,
      failingSince: Date.now() - 90000000
    }
  });
  let mixSends = 0;
  exporter.offerEvent = async function () {
    mixSends += 1;
    if (mixSends <= 2) {
      return badSend('permanent', 'STS-AUDIT-0015', 'rejected');
    }
    return badSend('transient', 'STS-AUDIT-0007', 'still down');
  };
  await exporter.walkDestination('mix', {});
  const mixed = exporter.readCursor('mix');
  const mixedGive = failures(book, 'STS-AUDIT-0011');
  t.check(mixSends === 3 && mixed.seq === 4 &&
          mixed.failedPermanent === 4 &&
          failures(book, 'STS-AUDIT-0015').length === 2 &&
          mixedGive.length === 1 && mixedGive[0].detail.count === 2,
          'D12. HTTP 400 does not start the batch drop',
          JSON.stringify({
            sends: mixSends, seq: mixed.seq,
            count: mixedGive[0] && mixedGive[0].detail.count
          }));
  ['prime', 'hole', 'gap', 'skip', 'own', 'hold', 'drop', 'perm',
   'mix'].forEach(function (id) {
    const dest = exporter.readDest(id);
    if (dest) {
      exporter.putDest(Object.assign({}, dest, { enabled: false }));
    }
  });
  const seen = [];
  exporter.walkDestination = async function (id) {
    seen.push(id);
    if (id === 'bad') {
      throw new Error('boom');
    }
  };
  exporter.putDest({
    id: 'bad', type: 'file', enabled: true, path: '/tmp/bad',
    excludeAttributes: ''
  });
  exporter.putDest({
    id: 'good', type: 'file', enabled: true, path: '/tmp/good',
    excludeAttributes: ''
  });
  exporter.putDest({
    id: 'off', type: 'file', enabled: false, path: '/tmp/off',
    excludeAttributes: ''
  });
  let summary = null;
  let threw = false;
  try {
    summary = await exporter.runAsync({});
  } catch (e) {
    // One destination throwing must not fail the tick. The check names it.
    log.debug("Caught in deliverAll(): " + ((e && e.message) || e));
    threw = true;
  }
  t.check(!threw && summary && summary.destinations === 2 &&
          seen.indexOf('bad') >= 0 && seen.indexOf('good') >= 0 &&
          seen.indexOf('off') < 0,
          'D13. one destination throwing leaves the others running',
          JSON.stringify({ threw: threw, seen: seen,
                           n: summary && summary.destinations }));
  log.debug("Leaving deliverAll().");
}

async function filesOnDisk(AuditExport, base, t) {
  log.debug("Entering filesOnDisk().");
  const fsMod = require('fs');
  const os = require('os');
  const dir = fsMod.mkdtempSync(path.join(os.tmpdir(), 'audit-export-w-'));
  const file = path.join(dir, 'audit.ndjson');
  const opened = [];
  const files = Object.assign({}, fsMod.promises, {
    open: async function (target, flag, mode) {
      const rec = { path: target, flag: flag, mode: mode, writes: [] };
      opened.push(rec);
      const fh = await fsMod.promises.open(target, flag, mode);
      return {
        stat: function () {
          return fh.stat();
        },
        close: function () {
          return fh.close();
        },
        write: async function (buf) {
          rec.writes.push(Buffer.from(buf));
          return fh.write(buf);
        }
      };
    }
  });
  const book = fakeAudit([auditRow(1)]);
  const cursorBook = memoryMap();
  const writer = makeExporter(AuditExport, base, {
    audit: book, fs: files, cursors: cursorBook
  });
  writer.putDest({
    id: 'disk', type: 'file', enabled: true, path: file, mode: 640,
    rotateBytes: 0, excludeAttributes: ''
  });
  installCursor(cursorBook, 'disk', {
    cls: AuditExport,
    cursor: { primed: true, seq: 0, nextSeq: 1 }
  });
  await writer.walkDestination('disk', {});
  const first = opened[0];
  const text = first && first.writes[0]
    ? first.writes[0].toString('utf8') : '';
  t.check(opened.length === 1 && first.flag === 'a' &&
          first.mode === parseInt('640', 8) && first.writes.length === 1 &&
          text.charAt(text.length - 1) === '\n' &&
          JSON.parse(text).seq === 1,
          'F1. one event is one append of one JSON line',
          JSON.stringify({
            opens: opened.length,
            writes: first && first.writes.length,
            mode: first && first.mode
          }));
  book.rows.push(auditRow(2));
  writer.putDest(Object.assign({}, writer.readDest('disk'), {
    rotateBytes: 1
  }));
  await writer.walkDestination('disk', {});
  const names = fsMod.readdirSync(dir);
  const baseName = path.basename(file);
  const rotated = names.filter(function (name) {
    return name !== baseName;
  });
  t.check(rotated.length === 1 && opened.length === 2 &&
          opened[1].writes.length === 1,
          'F2. a full file is renamed and the new line is its own write',
          names.join(','));
  const climbed = await writer.sendFile({
    id: 'climb', path: dir + '/../etc/passwd', mode: '640', rotateBytes: 0
  }, { id: 'x' });
  t.check(climbed.ok === false && climbed.kind === 'pause' &&
          climbed.code === 'STS-AUDIT-0004',
          'F3. a send rechecks a path that climbs', climbed.code);
  const full = Object.assign({}, fsMod.promises, {
    open: async function () {
      const err = new Error('no space');
      err.code = 'ENOSPC';
      throw err;
    }
  });
  const fullBook = fakeAudit([auditRow(1)]);
  const fullCursors = memoryMap();
  const fullWriter = makeExporter(AuditExport, base, {
    audit: fullBook, fs: full, cursors: fullCursors
  });
  fullWriter.putDest({
    id: 'full', type: 'file', enabled: true, path: file, mode: '640',
    rotateBytes: 0, excludeAttributes: ''
  });
  installCursor(fullCursors, 'full', {
    cls: AuditExport,
    cursor: { primed: true, seq: 0, nextSeq: 1 }
  });
  await fullWriter.walkDestination('full', {});
  const fullCursor = fullWriter.readCursor('full');
  t.check(fullCursor.seq === 0 && fullCursor.retries === 1 &&
          failures(fullBook, 'STS-AUDIT-0008').length === 1,
          'F4. a full filesystem holds the cursor',
          JSON.stringify({
            seq: fullCursor.seq, code: failures(fullBook, 'STS-AUDIT-0008')
              .map(function (row) { return row.errorCode; })
          }));
  writer.closeFile('disk');
  fsMod.rmSync(dir, { recursive: true, force: true });
  log.debug("Leaving filesOnDisk().");
}

function listenLoopback(net) {
  log.debug("Entering listenLoopback().");
  const pending = new Promise(function (resolve, reject) {
    const server = net.createServer();
    const holder = { frame: null, server: server, port: 0 };
    server.on('connection', function (sock) {
      holder.frame = readFrame(sock);
    });
    server.once('error', function (err) {
      reject(err);
    });
    server.listen(0, '127.0.0.1', function () {
      holder.port = server.address().port;
      resolve(holder);
    });
  });
  log.debug("Leaving listenLoopback().");
  return pending;
}

function readFrame(sock) {
  log.debug("Entering readFrame().");
  const pending = new Promise(function (resolve, reject) {
    const chunks = [];
    const timer = setTimeout(function () {
      reject(new Error('no syslog frame'));
    }, 2000);
    sock.on('data', function (chunk) {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      const space = buf.indexOf(0x20);
      if (space < 1) {
        return;
      }
      const len = Number(buf.slice(0, space).toString('ascii'));
      if (!isFinite(len) || buf.length < space + 1 + len) {
        return;
      }
      clearTimeout(timer);
      resolve(buf.slice(space + 1, space + 1 + len).toString('utf8'));
    });
  });
  log.debug("Leaving readFrame().");
  return pending;
}

async function syslogTcp(AuditExport, base, t) {
  log.debug("Entering syslogTcp().");
  const net = require('net');
  const holder = await listenLoopback(net);
  const exporter = makeExporter(AuditExport, base, {});
  const event = AuditExport.canonical({
    seq: 3, at: 1700000000000, outcome: 'success', action: 'sign in',
    summary: 'signed in', category: 'admin'
  }, {
    origin: 'node-a', realm: 'default', source: 'sts', names: new Set()
  });
  const pipe = { socket: null };
  let result = null;
  try {
    result = await exporter.sendSyslog({
      id: 'sys', type: 'logrhythm', host: '127.0.0.1',
      port: holder.port, transport: 'tcp', facility: 16, appName: 'iya-sts'
    }, event, pipe);
    const text = holder.frame ? await holder.frame : '';
    t.check(result.ok === true && result.disposition === 'transmitted' &&
            text === AuditExport.syslogLine(event, {
              facility: 16, appName: 'iya-sts'
            }),
            'Y1. TCP syslog sends one octet-counted frame and no extra ' +
            'newline', JSON.stringify({
              ok: result.ok, disposition: result.disposition,
              got: text.slice(0, 80)
            }));
  } catch (e) {
    // A missed frame is a failed check. The listener is still closed below.
    log.debug("Caught in syslogTcp(): " + ((e && e.message) || e));
    t.check(false, 'Y1. TCP syslog sends one octet-counted frame',
            (e && e.message) || e);
  } finally {
    exporter.closePipe(pipe);
    holder.server.close();
  }
  log.debug("Leaving syslogTcp().");
}

async function httpDelivery(AuditExport, base, codes, t) {
  log.debug("Entering httpDelivery().");
  const redirect = fakeTransport(function () {
    return {
      status: 302,
      headers: { location: 'https://evil.example/taken' }
    };
  });
  const dnsTable = {};
  const book = fakeAudit([]);
  const exporter = makeExporter(AuditExport, base, {
    audit: book,
    dns: scriptedDns(dnsTable),
    https: redirect
  });
  const redirected = await exporter.sendHttp({
    id: 'hook', type: 'webhook',
    url: 'https://hooks.example/in',
    template: '{message}',
    headers: { 'X-Trace': 'yes' },
    secretHeaders: {
      Authorization: { sealed: false, value: 'Bearer hidden' }
    }
  }, {
    message: 'see {event_type}', action: 'login', at: 1700000000000
  });
  const call = redirect.calls[0] || { headers: {}, body: '', options: {} };
  t.check(redirected.ok === false && redirected.kind === 'pause' &&
          redirected.code === 'STS-AUDIT-0014' &&
          redirect.calls.length === 1 &&
          String(redirected.why).indexOf('evil.example') < 0 &&
          call.body === 'see {event_type}' &&
          call.headers.Authorization === 'Bearer hidden' &&
          call.headers['X-Trace'] === 'yes' &&
          String(call.headers['User-Agent']).indexOf('audit-export') >= 0 &&
          call.options.hostname === 'hooks.example' &&
          typeof call.options.lookup === 'function',
          'H1. a webhook redirect is not followed, and the template ' +
          'is one pass', JSON.stringify({
            code: redirected.code, calls: redirect.calls.length,
            body: call.body
          }));
  const rejected = fakeTransport(function () {
    return { status: 400, body: 'no' };
  });
  const rejector = makeExporter(AuditExport, base, {
    dns: scriptedDns(dnsTable), https: rejected
  });
  const refusal = await rejector.sendHttp({
    id: 'hook', type: 'webhook', url: 'https://hooks.example/in',
    template: '', headers: {}, secretHeaders: {}
  }, { message: 'one', at: 1700000000000, seq: 1 });
  t.check(refusal.kind === 'permanent' &&
          refusal.code === 'STS-AUDIT-0015' && rejected.calls.length === 1,
          'H2. HTTP 400 is that event only', refusal.code);
  let acked = false;
  const hec = fakeTransport(function (one) {
    const target = String(one.options.path || '');
    if (target.indexOf('/ack') >= 0) {
      return { status: 200, body: { acks: { '7': acked } } };
    }
    return { status: 200, body: { code: 0, ackId: 7 } };
  });
  const rows = fakeAudit([auditRow(1), auditRow(2)]);
  const cursors = memoryMap();
  const collector = makeExporter(AuditExport, base, {
    audit: rows, dns: scriptedDns(dnsTable), https: hec, cursors: cursors
  });
  collector.putDest({
    id: 'hec', type: 'splunk', enabled: true, ack: true,
    url: 'https://hec.example/services/collector/event?x=1',
    token: { sealed: false, value: 'tok-keep-me' },
    source: 'iya-sts', sourcetype: 'iya:audit', index: '',
    excludeAttributes: ''
  });
  await collector.walkDestination('hec', {});
  const parked = collector.readCursor('hec');
  const eventCalls = hec.calls.filter(function (one) {
    return String(one.options.path || '').indexOf('/ack') < 0;
  });
  const ackCalls = hec.calls.filter(function (one) {
    return String(one.options.path || '').indexOf('/ack') >= 0;
  });
  t.check(parked.ackId === 7 && parked.seq === 0 &&
          parked.inFlightSeq === 1 &&
          parked.lastDisposition === 'accepted' &&
          eventCalls.length === 1 && ackCalls.length === 0 &&
          eventCalls[0].headers.Authorization === 'Splunk tok-keep-me',
          'H3. an acknowledgement parks one event',
          JSON.stringify({
            ack: parked.ackId, seq: parked.seq, events: eventCalls.length
          }));
  await collector.walkDestination('hec', {});
  const pending = collector.readCursor('hec');
  const ackAfter = hec.calls.filter(function (one) {
    return String(one.options.path || '').indexOf('/ack') >= 0;
  });
  t.check(pending.ackId === 7 && pending.retries === 0 &&
          pending.failingSince === 0 && ackAfter.length === 1 &&
          String(ackAfter[0].options.path).indexOf('x=1') < 0 &&
          ackAfter[0].headers['X-Splunk-Request-Channel'] &&
          hec.calls.filter(function (one) {
            return String(one.options.path || '').indexOf('/ack') < 0;
          }).length === 1,
          'H4. a false acknowledgement waits without a new failure ' +
          'and without another event',
          JSON.stringify({
            retries: pending.retries, acks: ackAfter.length,
            path: ackAfter[0] && ackAfter[0].options.path
          }));
  acked = true;
  await collector.walkDestination('hec', {});
  const done = collector.readCursor('hec');
  const events = hec.calls.filter(function (one) {
    return String(one.options.path || '').indexOf('/ack') < 0;
  });
  t.check(done.seq === 1 && done.delivered === 1 &&
          done.lastDisposition === 'accepted' && done.inFlightSeq === 2 &&
          events.length === 2,
          'H5. a true acknowledgement advances, and the next event ' +
          'is the one in flight', JSON.stringify({
            seq: done.seq, delivered: done.delivered, events: events.length
          }));
  void codes;
  log.debug("Leaving httpDelivery().");
}

async function addresses(AuditExport, base, t) {
  log.debug("Entering addresses().");
  const table = {};
  let looked = false;
  const dns = {
    lookup: function (host) {
      log.debug("Entering lookup().");
      looked = true;
      const name = String(host || '').toLowerCase();
      const answer = Object.prototype.hasOwnProperty.call(table, name)
        ? table[name] : [{ address: '8.8.8.8', family: 4 }];
      if (answer === 'fail') {
        log.debug("Leaving lookup(). Failed.");
        return Promise.reject(new Error('lookup failed'));
      }
      log.debug("Leaving lookup().");
      return Promise.resolve(answer);
    }
  };
  const exporter = makeExporter(AuditExport, base, { dns: dns });
  looked = false;
  const metadata = await exporter.screenHost('169.254.169.254', true);
  t.check(metadata.ok === false && metadata.code === 'STS-AUDIT-0005' &&
          !looked,
          'P1. metadata is refused before DNS', metadata.why);
  looked = false;
  const named = await exporter.screenHost('metadata.google.internal', true);
  t.check(named.ok === false && !looked,
          'P2. a metadata name is refused before DNS', named.why);
  table['public.example'] = [{ address: '127.0.0.1', family: 4 }];
  const rebound = await exporter.screenHost('public.example', true);
  t.check(rebound.ok === false && rebound.code === 'STS-AUDIT-0005',
          'P3. a public name that resolves to loopback is refused',
          rebound.why);
  table['127.0.0.1'] = [{ address: '127.0.0.1', family: 4 }];
  const loop = await exporter.screenHost('127.0.0.1', true);
  t.check(loop.ok === true && loop.addresses[0] === '127.0.0.1',
          'P4. development allows a loopback host whose answers are ' +
          'loopback', JSON.stringify(loop.addresses));
  table['100.64.1.1'] = [{ address: '100.64.1.1', family: 4 }];
  const cgnat = await exporter.screenHost('100.64.1.1', true);
  t.check(cgnat.ok === false && cgnat.code === 'STS-AUDIT-0005',
          'P5. carrier-grade NAT is refused with private addresses',
          cgnat.why);
  table['missing.example'] = 'fail';
  const unsaved = await exporter.screenHost('missing.example', false);
  const unsent = await exporter.screenHost('missing.example', true);
  t.check(unsaved.ok === true && unsent.ok === false &&
          unsent.code === 'STS-AUDIT-0005',
          'P6. a lookup failure at save is kept, and at send it pauses',
          unsent.why);
  const plain = await exporter.screenUrl('http://127.0.0.1/hook', true);
  t.check(plain.ok === false,
          'P7. plain http is refused while allowHttp is off', plain.why);
  const userinfo = await exporter.screenUrl(
    'https://user:secret@hooks.example/in', false);
  t.check(userinfo.ok === false && userinfo.code === 'STS-AUDIT-0005',
          'P8. a URL with userinfo is refused', userinfo.why);
  const keys = ['auditExport.allowHttp', 'global.mode',
                'auditExport.allowPrivateDestinations'];
  try {
    if (!applyOverride(base.config, 'auditExport.allowHttp', true, t,
                       'P9. allowHttp can be set in development')) {
      log.debug("Leaving addresses(). No allowHttp.");
      return;
    }
    const allowed = await exporter.screenUrl('http://127.0.0.1/hook', true);
    t.check(allowed.ok === true,
            'P9. development may dial plain http to loopback', allowed.why);
    if (!applyOverride(base.config, 'global.mode', 'product', t,
                       'P10. product mode can be set')) {
      log.debug("Leaving addresses(). No product mode.");
      return;
    }
    const productHttp = await exporter.screenUrl(
      'http://127.0.0.1/hook', true);
    table['10.1.2.3'] = [{ address: '10.1.2.3', family: 4 }];
    const productPrivate = await exporter.screenHost('10.1.2.3', true);
    t.check(productHttp.ok === false &&
            productHttp.code === 'STS-AUDIT-0005' &&
            productPrivate.ok === false,
            'P10. product mode refuses plain http and private addresses',
            productHttp.why + ' ' + productPrivate.why);
    if (applyOverride(base.config, 'auditExport.allowPrivateDestinations',
                      true, t, 'P11. private destinations can be allowed')) {
      const opened = await exporter.screenHost('10.1.2.3', true);
      const stillMeta = await exporter.screenHost('169.254.169.254', true);
      const wide = await exporter.screenHost('100.64.1.1', true);
      t.check(opened.ok === true && stillMeta.ok === false &&
              wide.ok === true,
              'P11. allowing private addresses still refuses metadata',
              stillMeta.why);
    }
  } finally {
    clearKeys(base.config, keys);
  }
  log.debug("Leaving addresses().");
}

async function childBody() {
  log.debug("Entering childBody().");
  const auditExport = require('../common/audit_export');
  const config = require('../common/config');
  const errorCodes = require('../common/error_codes');
  const mode = require('../common/mode');
  const realms = require('../common/realms');
  const version = require('../common/version');
  const OutboundTls = require('../common/outbound_tls');
  const keystore = require('../common/keystore');
  const fs = require('fs');
  const os = require('os');
  const http = require('http');
  const https = require('https');
  const dgram = require('dgram');
  const dns = require('dns');
  const net = require('net');
  const tls = require('tls');
  const crypto = require('../common/crypto');
  const t = recorder();
  t.check(auditExport.JOB_ID === 'audit.export' &&
          auditExport.instanceOrigin() === 'default',
          'S0. loading the module builds the default instance',
          auditExport.instanceOrigin());
  const base = {
    config: config,
    mode: mode,
    realms: realms,
    errorCodes: errorCodes,
    keystore: keystore,
    outbound: OutboundTls,
    version: version,
    fs: fs.promises,
    http: http,
    https: https,
    dgram: dgram,
    dns: dns.promises,
    net: net,
    tls: tls,
    path: path,
    os: os,
    crypto: crypto
  };
  const AuditExport = auditExport.AuditExport;
  await staticForms(AuditExport, base, t);
  await acts(AuditExport, base, errorCodes, t);
  await delivery(AuditExport, base, t);
  await filesOnDisk(AuditExport, base, t);
  await syslogTcp(AuditExport, base, t);
  await httpDelivery(AuditExport, base, errorCodes, t);
  await addresses(AuditExport, base, t);
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath,
    process.execArgv.concat([__filename]), {
      cwd: ROOT, env: clean, encoding: 'utf8', timeout: 180000,
      maxBuffer: 64 * 1024 * 1024
    });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-2000) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== Audit export (#641) ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'audit_export',
  describe: 'Audit export (#641): destinations, this process\'s cursor ' +
            'over its own audit ring, and delivery to syslog, a file, a ' +
            'webhook and Splunk HEC',
  run: run
};
