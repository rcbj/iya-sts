// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: report_staging.js
//
// ---------------------------------------------------------------------------
// A REPORT IS BUILT ON DISK AND STORED IN PIECES (#1045).
//
// In process, against a temporary `risk.uploadDirectory` and a store double
// that keeps the driver's two piece methods in maps:
//
//   A. Each format's pieces are the bytes its whole form always was: JSON
//      is `JSON.stringify` of the document, and a PDF's cross-reference
//      table points at every object it names.
//   B. `finishToFile()` writes into the staging directory and hashes on the
//      way; the byte cap, a directory with no room and a directory that
//      cannot be written each refuse with their code and leave no file.
//   C. A file is stored as sealed pieces of PIECE_BYTES, none holding the
//      report's text. It reads back a piece at a time. A piece moved to
//      another place, or one that is gone, is refused (STS-REPORT-0051).
//      A row written before #1045 is still read.
//   D. A job runs to completed, and its build file is gone however the job
//      ends: completed, or failed in the store.
//   E. The clean-up job removes this process's unheld files and another
//      process's stale ones, and nothing else.
//   F. The download streams the pieces, and cuts the response rather than
//      completing it when a piece fails or the digest does not match.
//   G. Against a real postgres, only when STS_TEST_POSTGRES_URL names one:
//      the driver's own SQL — the table `open()` makes, the pieces and the
//      marker in one transaction, a piece read by key, and the one-statement
//      delete. The in-process suite has no database and skips it.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');
const config = require('../common/config');
const Limits = require('../report/limits');
const Formats = require('../report/formats');
const executor = require('../report/executor');
const stores = require('../report/stores');
const Staging = require('../report/staging');

const log = require('bunyan').createLogger({ name: 'report_staging',
  level: process.env.LOG_LEVEL || 'info' });

const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'report-staging-'));
const PIECE = Staging.ReportStaging.PIECE_BYTES;

function plan(format, fields) {
  log.debug("Entering plan().");
  log.debug("Leaving plan().");
  return { source: 'users', fields: fields || ['username', 'mail'],
    locale: null, format: format, execution: 'async' };
}

function rows(n, width) {
  log.debug("Entering rows().");
  const out = [];
  const pad = 'x'.repeat(width || 0);
  for (let i = 0; i < n; i++) {
    out.push({ username: 'person' + i + pad, mail: 'p' + i + '@example.com' });
  }
  log.debug("Leaving rows().");
  return out;
}

function sha(bytes) {
  log.debug("Entering sha().");
  log.debug("Leaving sha().");
  return nodeCrypto.createHash('sha256').update(bytes).digest('hex');
}

function buildFiles() {
  log.debug("Entering buildFiles().");
  log.debug("Leaving buildFiles().");
  return fs.readdirSync(DIR).filter(function (name) {
    return Staging.ReportStaging.FILE_NAME.test(name);
  });
}

// The driver's artifact methods over maps, the piece methods included.
function storeDouble() {
  log.debug("Entering storeDouble().");
  const heads = new Map();
  const pieces = new Map();
  const db = {
    heads: heads,
    pieces: pieces,
    failNext: false,
    putReportArtifact: function (row) {
      heads.set(row.realm + '|' + row.jobId, Object.assign({}, row));
      return Promise.resolve();
    },
    putReportArtifactPieces: async function (row, iterable) {
      if (db.failNext) {
        db.failNext = false;
        throw new Error('the database went away');
      }
      let seq = 0;
      for await (const piece of iterable) {
        pieces.set(row.realm + '|' + row.jobId + '|' + seq, piece);
        seq += 1;
      }
      heads.set(row.realm + '|' + row.jobId, { bytes: Buffer.from(
        row.prefix + seq + ':' + row.size), sha256: row.sha256,
        mediaType: row.mediaType, createdAt: row.createdAt });
      return seq;
    },
    getReportArtifactPiece: function (key) {
      return Promise.resolve(pieces.get(key.realm + '|' + key.jobId + '|' +
        key.seq) || null);
    },
    getReportArtifact: function (key) {
      return Promise.resolve(heads.get(key.realm + '|' + key.jobId) || null);
    },
    deleteReportArtifact: function (key) {
      heads.delete(key.realm + '|' + key.jobId);
      Array.from(pieces.keys()).forEach(function (k) {
        if (k.indexOf(key.realm + '|' + key.jobId + '|') === 0) {
          pieces.delete(k);
        }
      });
      return Promise.resolve();
    }
  };
  log.debug("Leaving storeDouble().");
  return db;
}

function partA(t) {
  log.debug("Entering partA().");
  t.log.info('=== A. the pieces are the whole ===');
  const p = plan('json');
  const some = rows(3).concat([{ username: null, mail: 'a"b\n' }]);
  const joined = Array.from(Formats.jsonParts(p, some)).join('');
  t.equal(joined, JSON.stringify({ source: p.source, fields: p.fields,
    rows: some, truncated: false }),
    'A1. JSON in pieces is JSON.stringify of the whole document');
  t.equal(Array.from(Formats.jsonParts(p, [])).join(''),
    JSON.stringify({ source: p.source, fields: p.fields, rows: [],
      truncated: false }), 'A2. and so is an empty one');
  const csv = Array.from(Formats.csvParts(plan('csv'), some)).join('');
  t.equal(csv.split('\r\n').length, 6,
    'A3. CSV in pieces is a header and a line a row, each ending CRLF');
  const pdf = Formats.pdfParts(plan('pdf'), rows(90), { realm: 'r',
    when: 'w' }, 10);
  t.check(pdf.ok, 'A4. a PDF of three pages is laid out');
  const body = Buffer.from(Array.from(pdf.parts).join(''), 'utf8');
  const text = body.toString('latin1');
  const start = Number(/startxref\n(\d+)\n%%EOF\n$/.exec(text)[1]);
  t.equal(text.slice(start, start + 4), 'xref',
    'A5. startxref points at the cross-reference table');
  const offsets = text.slice(start).split('\n').slice(3)
    .filter(function (line) {
      return / 00000 n $/.test(line);
    }).map(function (line) {
      return Number(line.slice(0, 10));
    });
  t.check(offsets.length === 9 && offsets.every(function (off, i) {
    return text.slice(off, off + String(i + 1).length + 6) ===
      (i + 1) + ' 0 obj';
  }), 'A6. and every offset in it is its object\'s', offsets.join(','));
  t.equal(Formats.pdf(plan('pdf'), rows(90), { realm: 'r', when: 'w' }, 10)
    .body.toString('latin1'), text,
    'A7. Formats.pdf() is the pieces put together');
  t.equal(Formats.pdfParts(plan('pdf'), rows(90), { realm: 'r', when: 'w' },
    2).ok, false, 'A8. and past the page cap nothing is laid out');
  log.debug("Leaving partA().");
}

async function partB(t) {
  log.debug("Entering partB().");
  t.log.info('=== B. built in the staging directory ===');
  const capped = Limits.fixed({ asyncMaxBytes: 4 * PIECE });
  const some = rows(40000);
  const done = await executor.finishToFile(plan('csv'), some, capped,
    { realm: 'r', when: 'w' });
  t.check(done.ok, 'B1. a CSV of a few MiB is built', done.description);
  const whole = Formats.csv(plan('csv'), some);
  t.check(done.ok && path.dirname(done.file.path) === DIR &&
    fs.existsSync(done.file.path),
    'B2. in risk.uploadDirectory, the directory risk uploads use',
    done.file && done.file.path);
  t.check(done.ok && done.bytes === whole.length && done.sha256 ===
    sha(whole) && sha(fs.readFileSync(done.file.path)) === sha(whole),
    'B3. its size and digest are the whole report\'s, hashed on the way');
  t.check(Staging.ReportStaging.heldFiles().indexOf(done.file.path) >= 0,
    'B4. and this process holds it');
  await done.file.remove();
  t.check(!fs.existsSync(done.file.path) &&
    Staging.ReportStaging.heldFiles().length === 0,
    'B5. remove() deletes it and lets it go');
  const small = Limits.fixed({ asyncMaxBytes: PIECE });
  const big = await executor.finishToFile(plan('json'), rows(40000), small,
    { realm: 'r', when: 'w' });
  t.check(!big.ok && big.code === 'STS-REPORT-0005' &&
    buildFiles().length === 0,
    'B6. past the byte cap the render stops, is refused, and leaves no file',
    JSON.stringify(big));
  const full = await executor.finishToFile(plan('csv'), rows(3), capped,
    { realm: 'r', when: 'w' }, { freeBytes: function () {
      return Promise.resolve(4 * PIECE);
    } });
  t.check(!full.ok && full.code === 'STS-REPORT-0049' &&
    buildFiles().length === 0,
    'B7. a directory without room for the cap and the reserve refuses ' +
    'before a byte is written', JSON.stringify(full));
  const blocker = path.join(DIR, 'not-a-directory');
  fs.writeFileSync(blocker, 'x');
  config.setOverride('risk.uploadDirectory', path.join(blocker, 'below'));
  let unwritable;
  try {
    unwritable = await executor.finishToFile(plan('csv'), rows(3), capped,
      { realm: 'r', when: 'w' });
  } finally {
    config.setOverride('risk.uploadDirectory', DIR);
    fs.rmSync(blocker, { force: true });
  }
  t.check(!unwritable.ok && unwritable.code === 'STS-REPORT-0050',
    'B8. a directory that cannot be made refuses', JSON.stringify(unwritable));
  log.debug("Leaving partB().");
}

async function partC(t) {
  log.debug("Entering partC().");
  t.log.info('=== C. stored in sealed pieces ===');
  const keystore = require('../common/keystore');
  if (!keystore.sealed()) {
    t.check(keystore.useEphemeralKek(nodeCrypto.randomBytes(32)
      .toString('hex')), 'C0. a key-encryption key is installed');
  }
  const db = storeDouble();
  stores.setDriver(db, 'test');
  try {
    const capped = Limits.fixed({ asyncMaxBytes: 8 * PIECE });
    const some = rows(30000, 40);
    const done = await executor.finishToFile(plan('csv'), some, capped,
      { realm: 'r', when: 'w' });
    const whole = Formats.csv(plan('csv'), some);
    const want = Math.ceil(whole.length / PIECE);
    await stores.putArtifactFile('job-pieces', done.file, done.sha256,
      'text/csv');
    await done.file.remove();
    t.check(want >= 3 && db.pieces.size === want,
      'C1. a ' + whole.length + '-byte report is ' + want + ' pieces',
      String(db.pieces.size));
    const sealed = Array.from(db.pieces.values()).map(function (b) {
      return Buffer.from(b).toString('utf8');
    });
    t.check(sealed.every(function (text) {
      return text.indexOf('$aesgcm$') === 0 &&
        text.indexOf('person1') < 0 && text.indexOf('example.com') < 0;
    }), 'C2. each sealed, none holding the report\'s text');
    const head = Array.from(db.heads.values())[0];
    t.equal(Buffer.from(head.bytes).toString('utf8'), '$pieces$1:' + want +
      ':' + whole.length, 'C3. the row holds the count and the size');
    const opened = await stores.openArtifact('job-pieces');
    const seen = [];
    for await (const piece of opened.pieces()) {
      seen.push(piece.length);
    }
    t.check(seen.length === want && seen.slice(0, -1).every(function (n) {
      return n === PIECE;
    }), 'C4. it reads back a piece at a time', seen.join(','));
    const back = await stores.getArtifact('job-pieces');
    t.check(back && sha(back.bytes) === sha(whole) &&
      back.sha256 === sha(whole), 'C5. and the pieces are the report');
    const keys = Array.from(db.pieces.keys());
    const zero = db.pieces.get(keys[0]);
    db.pieces.set(keys[0], db.pieces.get(keys[1]));
    db.pieces.set(keys[1], zero);
    t.equal(await stores.getArtifact('job-pieces'), null,
      'C6. two pieces swapped are refused, not served out of order');
    db.pieces.delete(keys[1]);
    let thrown = null;
    try {
      for await (const piece of (await stores.openArtifact('job-pieces'))
          .pieces()) {
        void piece;
      }
    } catch (e) {
      thrown = e;
    }
    t.check(thrown && thrown.code === 'STS-REPORT-0051',
      'C7. and a piece that is gone is STS-REPORT-0051');
    await stores.putArtifact('job-old', Buffer.from('a,b\r\n'), 'x',
      'text/csv');
    const old = await stores.getArtifact('job-old');
    t.equal(old && old.bytes.toString('utf8'), 'a,b\r\n',
      'C8. a whole sealed row, as written before #1045, still reads');
    await stores.deleteArtifact('job-pieces');
    t.check(!db.heads.has('default|job-pieces') && Array.from(db.pieces
      .keys()).every(function (k) {
        return k.indexOf('|job-pieces|') < 0;
      }), 'C9. a delete takes the pieces with the row');
  } finally {
    stores.clearDriver();
  }
  log.debug("Leaving partC().");
}

async function partD(t) {
  log.debug("Entering partD().");
  t.log.info('=== D. a job\'s file is gone however it ends ===');
  const sources = require('../report/sources');
  const audit = require('../common/audit');
  const realFresh = audit.fresh;
  const realList = audit.list;
  const realRecord = audit.record;
  const failures = [];
  audit.record = function (info) {
    if (info && info.action === 'report.job.fail') {
      failures.push(info.errorCode);
    }
    return realRecord.apply(audit, arguments);
  };
  audit.fresh = function () {
    return Promise.resolve();
  };
  audit.list = function () {
    return [{ action: 'authentication', outcome: 'success', actor: 'ada',
      category: 'authentication', at: Date.now(), detail: {} }];
  };
  const db = storeDouble();
  stores.resetForTests();
  stores.setDriver(db, 'test');
  const job = function (id) {
    return { id: id, status: 'queued', owner: 'app', ownerKind: 'application',
      ownerRealm: '', submittedAt: Date.now(), parameters: null,
      document: { source: 'auditEvents', select: ['actor', 'outcome'],
        limit: 5, mode: 'async', format: 'csv' } };
  };
  try {
    stores.putJob(job('job-ok'));
    await sources.runOne(stores.getJob('job-ok'), {});
    const ok = stores.getJob('job-ok') || {};
    t.equal(ok.status, 'completed', 'D1. a job completes', ok.error);
    const back = await stores.getArtifact('job-ok');
    t.check(back && sha(back.bytes) === ok.sha256 &&
      back.bytes.length === ok.byteSize,
      'D2. its stored pieces are its digest and its size');
    t.equal(buildFiles().length, 0, 'D3. and its build file is gone');
    db.failNext = true;
    stores.putJob(job('job-fail'));
    await sources.runOne(stores.getJob('job-fail'), {});
    const failed = stores.getJob('job-fail') || {};
    t.equal(failed.status + ' ' + failures.join(','),
      'failed STS-REPORT-0053',
      'D4. a job the store refuses fails, said as the store\'s failure');
    t.equal(buildFiles().length, 0, 'D5. and its build file is gone too');
  } finally {
    audit.fresh = realFresh;
    audit.list = realList;
    audit.record = realRecord;
    stores.clearDriver();
    stores.resetForTests();
  }
  log.debug("Leaving partD().");
}

async function partE(t) {
  log.debug("Entering partE().");
  t.log.info('=== E. the clean-up job ===');
  const RS = Staging.ReportStaging;
  const uuid = function () {
    return nodeCrypto.randomUUID();
  };
  const mine = path.join(DIR, 'report-build-' + RS.PROCESS_TAG + '-' +
    uuid() + '.part');
  const theirsOld = path.join(DIR, 'report-build-1x00000000-' + uuid() +
    '.part');
  const theirsNew = path.join(DIR, 'report-build-2x00000000-' + uuid() +
    '.part');
  const stranger = path.join(DIR, 'somebody-elses.part');
  [mine, theirsOld, theirsNew, stranger].forEach(function (f) {
    fs.writeFileSync(f, 'x');
  });
  const opened = await RS.open(PIECE);
  const now = Date.now();
  const staleMs = new Limits().asyncMaxMs() + RS.STALE_GRACE_MS;
  const old = (now - staleMs - 60000) / 1000;
  fs.utimesSync(theirsOld, old, old);
  fs.utimesSync(stranger, old, old);
  const swept = await RS.sweep(now);
  t.check(!fs.existsSync(mine), 'E1. this process\'s file it no longer ' +
    'holds is removed');
  t.check(!fs.existsSync(theirsOld), 'E2. another process\'s stale file ' +
    'is removed');
  t.check(fs.existsSync(theirsNew), 'E3. another process\'s fresh file ' +
    'is kept');
  t.check(fs.existsSync(stranger), 'E4. a file whose name is not a ' +
    'build\'s is never touched');
  t.check(fs.existsSync(opened.file.path) && swept.held === 1 &&
    swept.removed === 2, 'E5. a held file is kept and touched',
    JSON.stringify(swept));
  await opened.file.remove();
  [theirsNew, stranger].forEach(function (f) {
    fs.rmSync(f, { force: true });
  });
  const scheduler = { jobs: {}, job: function (id) {
    return this.jobs[id];
  }, register: function (spec) {
    this.jobs[spec.id] = spec;
  } };
  t.check(RS.registerJobs(scheduler) && scheduler.jobs[RS.CLEANUP_JOB]
    .kind === 'per-process' && scheduler.jobs[RS.CLEANUP_JOB]
    .everySetting === 'risk.uploadSweepS',
    'E6. it is a per-process scheduler job on risk.uploadSweepS');
  log.debug("Leaving partE().");
}

function fakeResponse(writable) {
  log.debug("Entering fakeResponse().");
  const EventEmitter = require('events');
  const res = new EventEmitter();
  res.chunks = [];
  res.headers = {};
  res.destroyed = false;
  res.ended = false;
  res.set = function (k, v) {
    res.headers[k.toLowerCase()] = v;
  };
  res.type = function (v) {
    res.headers['content-type'] = v;
  };
  res.status = function (s) {
    res.statusCode = s;
  };
  res.write = function (b) {
    res.chunks.push(b);
    if (!writable) {
      setImmediate(function () {
        res.emit('drain');
      });
    }
    return !!writable;
  };
  res.end = function () {
    res.ended = true;
  };
  res.destroy = function () {
    res.destroyed = true;
  };
  log.debug("Leaving fakeResponse().");
  return res;
}

async function partF(t) {
  log.debug("Entering partF().");
  t.log.info('=== F. the download streams ===');
  const api = require('../report/report_api');
  const pieces = [Buffer.from('a'.repeat(10)), Buffer.from('b'.repeat(5))];
  const whole = Buffer.concat(pieces);
  const source = function (list, fail) {
    return (async function* () {
      for (let i = 0; i < list.length; i++) {
        if (fail === i) {
          throw Object.assign(new Error('gone'), { code: 'STS-REPORT-0051' });
        }
        yield list[i];
      }
    })();
  };
  const go = async function (res, list, fail, digest, size) {
    const it = source(list, fail);
    const first = await it.next();
    return api.streamPieces(res, 'text/csv; charset=utf-8',
      'attachment; filename="report.csv"', size, first, it, digest);
  };
  const res = fakeResponse(false);
  const ok = await go(res, pieces, -1, sha(whole), whole.length);
  t.check(ok && res.ended && !res.destroyed && Buffer.concat(res.chunks)
    .equals(whole) && res.headers['content-length'] === '15' &&
    res.headers['cache-control'] === 'no-store',
    'F1. the pieces go out in order, waiting on drain, and the answer ends');
  const cut = fakeResponse(true);
  const broken = await go(cut, pieces, 1, sha(whole), whole.length);
  t.check(!broken && cut.destroyed && !cut.ended,
    'F2. a piece that fails part-way cuts the response');
  const wrong = fakeResponse(true);
  const mismatched = await go(wrong, pieces, -1, sha(Buffer.from('x')),
    whole.length);
  t.check(!mismatched && wrong.destroyed && !wrong.ended,
    'F3. a digest that does not match cuts it rather than ending it');
  log.debug("Leaving partF().");
}

async function partG(t) {
  log.debug("Entering partG().");
  const url = process.env.STS_TEST_POSTGRES_URL || '';
  if (!url) {
    t.log.info('=== G. skipped: STS_TEST_POSTGRES_URL names no database ' +
      '(the in-process suite has none) ===');
    log.debug("Leaving partG(). Skipped.");
    return;
  }
  t.log.info('=== G. against ' + url.replace(/:[^:@/]*@/, ':***@') + ' ===');
  const knexStore = require('../persistence/knex_store');
  const postgres = require('../persistence/persistence_postgres');
  const dbName = 'report_staging_' + process.pid;
  // The driver never dials in the clear (#273), so the database named must
  // speak TLS; its certificate is not verified here (`verifyTls: false`),
  // as a throwaway server's self-signed one could not be.
  const tls = { rejectUnauthorized: false };
  const admin = knexStore.openConnection({ connectionString: url,
    ssl: tls });
  await admin.connect();
  const dbUrl = url.replace(/\/[^/?]*(\?|$)/, '/' + dbName + '$1');
  let driver = null;
  try {
    await admin.query('CREATE DATABASE ' + dbName);
    driver = postgres.create({ url: dbUrl, log: log, verifyTls: false });
    await driver.open();
    stores.setDriver(driver, 'postgres');
    const capped = Limits.fixed({ asyncMaxBytes: 8 * PIECE });
    const some = rows(30000, 40);
    const whole = Formats.csv(plan('csv'), some);
    const done = await executor.finishToFile(plan('csv'), some, capped,
      { realm: 'r', when: 'w' });
    await stores.putArtifactFile('job-pg', done.file, done.sha256,
      'text/csv');
    await done.file.remove();
    const db = knexStore.openConnection({ connectionString: dbUrl,
      ssl: tls });
    await db.connect();
    try {
      const counted = await db.query('SELECT count(*)::int AS n, ' +
        'max(length(bytes))::int AS biggest FROM sts_report_artifact_pieces ' +
        'WHERE job_id = $1', ['job-pg']);
      const want = Math.ceil(whole.length / PIECE);
      t.equal(counted.rows[0].n, want, 'G1. open() made the pieces table ' +
        'and the ' + want + ' pieces are rows of it');
      const head = await db.query('SELECT convert_from(bytes, \'UTF8\') ' +
        'AS b FROM sts_report_artifacts WHERE job_id = $1', ['job-pg']);
      t.equal(head.rows[0] && head.rows[0].b, '$pieces$1:' + want + ':' +
        whole.length, 'G2. the artifact row holds the marker');
      const back = await stores.getArtifact('job-pg');
      t.check(back && sha(back.bytes) === sha(whole),
        'G3. the pieces read back by key are the report');
      await stores.deleteArtifact('job-pg');
      const left = await db.query('SELECT (SELECT count(*) FROM ' +
        'sts_report_artifact_pieces)::int + (SELECT count(*) FROM ' +
        'sts_report_artifacts)::int AS n');
      t.equal(left.rows[0].n, 0, 'G4. one delete takes the pieces and ' +
        'the row');
    } finally {
      await db.end();
    }
  } finally {
    stores.clearDriver();
    if (driver) {
      await driver.close();
    }
    await admin.query('DROP DATABASE IF EXISTS ' + dbName);
    await admin.end();
  }
  log.debug("Leaving partG().");
}

async function run(t) {
  log.debug("Entering run().");
  config.setOverride('risk.uploadDirectory', DIR);
  try {
    partA(t);
    await partB(t);
    await partC(t);
    await partD(t);
    await partE(t);
    await partF(t);
    await partG(t);
  } finally {
    config.clearOverride('risk.uploadDirectory');
    fs.rmSync(DIR, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'report_staging',
  describe: 'report artifacts built in the staging directory, stored in ' +
    'sealed pieces, the build file removed, the clean-up job, the streamed ' +
    'download',
  run: run
};
