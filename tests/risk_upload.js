'use strict';
//
// File: risk_upload.js
//
// ===========================================================================
// A RISK DATASET UPLOADED AS A FILE (#215, 2026-09-24), in process, on the
// memory store.
//
// `risk/risk_upload.ts` streams an upload to `risk.uploadDirectory` and
// `risk/risk_expand.ts` expands it as `importVersion()` reads it. The two
// doors are driven here with synthetic request streams — the API's (the body
// is the file, the fields a query) and the console's (multipart, the fields
// before the file) — and the console's route with a fake app, for its role
// check. `tests/vendored/sts_admin_risk_upload.js` drives both over HTTP
// against a running service, the body-parser exemption and the gate
// included. What this file holds:
//
//   A. gzip, zip and plain, each told apart by content, each loaded to
//      `active` after an answer that came while it was `loading`, and the
//      file deleted afterwards; the SHA-256 is of the file as sent.
//   B. A decompression bomb (gzip, and a zip whose declared size is over the
//      allowance) refused as STS-RISK-0032, and a zip of two data entries as
//      STS-RISK-0033 — while a directory and __MACOSX/ beside one data entry
//      are not counted.
//   C. The size cap: a declared length over it refused before a byte is
//      read, and an undeclared body stopped where it passes it
//      (STS-RISK-0028); no room in the directory (STS-RISK-0029).
//   D. The console's form: a wrong CSRF token, and a file before the token,
//      refused before the file is written; a field after the file, no file,
//      a second file; the route refusing a session without Admin Write.
//   E. The API's: a body type it does not take, an unknown parameter.
//   F. The exemption predicate `common/app.js` and the console gate share:
//      exactly the two paths, as express routes them.
//   G. Crash leftovers: a version left `loading` is refused by
//      `abandonStalled()` (STS-RISK-0035) and an import then stops; the
//      per-process sweep removes another process's stale file and this
//      process's unheld one, and leaves a fresh one and a stranger alone.
//   H. The one expansion path: a .gz and a .zip by PATH (the dataset
//      directory's and the install-time loader's way in) load too.
//
// Every file is built here, in memory or a temporary directory, from
// synthetic lines in the RFC 2544 benchmarking range; none is committed.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const stream = require('stream');
const zlib = require('zlib');
const nodeCrypto = require('crypto');

const config = require('../common/config');
const riskStore = require('../risk/risk_store');
const riskDatasets = require('../risk/risk_datasets');
const riskUpload = require('../risk/risk_upload');
const riskTerms = require('../risk/risk_terms');
const websecurity = require('../common/websecurity');
const zipWriter = require('./vendored/zip_writer');

const log = require('bunyan').createLogger({ name: 'risk_upload',
  level: process.env.LOG_LEVEL || 'info' });

const SESSION = 'risk-upload-session';
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'risk-upload-'));

// N synthetic addresses in 198.18.0.0/15 (RFC 2544), one per line, with a
// stamp in a comment so each list is a new version.
function listOf(n, stamp) {
  log.debug("Entering listOf().");
  const lines = ['# risk_upload ' + stamp];
  for (let i = 0; i < n; i++) {
    lines.push('198.18.' + Math.floor(i / 250) + '.' + (i % 250));
  }
  log.debug("Leaving listOf().");
  return lines.join('\n') + '\n';
}

// A request the API door reads: a stream of `body`, with its headers and
// query. `declared` overrides the Content-Length (null leaves it out).
function apiRequest(body, query, type, declared) {
  log.debug("Entering apiRequest().");
  const req = stream.Readable.from([body]);
  req.headers = { 'content-type': type || 'application/octet-stream' };
  if (declared !== null) {
    req.headers['content-length'] = String(declared === undefined
      ? body.length : declared);
  }
  req.query = query;
  req.method = 'POST';
  req.originalUrl = '/admin-api/risk/upload';
  log.debug("Leaving apiRequest().");
  return req;
}

// A multipart/form-data body: `parts` in order, `{ name, value }` for a
// field and `{ name, filename, data }` for a file.
function multipart(parts) {
  log.debug("Entering multipart().");
  const boundary = '----risk-upload-' + nodeCrypto.randomBytes(8)
    .toString('hex');
  const chunks = [];
  parts.forEach(function (p) {
    chunks.push(Buffer.from('--' + boundary + '\r\n'));
    if (p.filename) {
      chunks.push(Buffer.from('Content-Disposition: form-data; name="' +
        p.name + '"; filename="' + p.filename + '"\r\nContent-Type: ' +
        'application/octet-stream\r\n\r\n'));
      chunks.push(Buffer.isBuffer(p.data) ? p.data : Buffer.from(p.data));
    } else {
      chunks.push(Buffer.from('Content-Disposition: form-data; name="' +
        p.name + '"\r\n\r\n' + p.value));
    }
    chunks.push(Buffer.from('\r\n'));
  });
  chunks.push(Buffer.from('--' + boundary + '--\r\n'));
  const body = Buffer.concat(chunks);
  const req = stream.Readable.from([body]);
  req.headers = { 'content-type': 'multipart/form-data; boundary=' + boundary,
                  'content-length': String(body.length) };
  req.query = {};
  req.method = 'POST';
  req.originalUrl = '/admin/risk/upload';
  log.debug("Leaving multipart().");
  return req;
}

// The console's door, with this test's session.
function formDoor() {
  log.debug("Entering formDoor().");
  log.debug("Leaving formDoor().");
  return {
    via: 'the admin console', source: 'upload', actor: 'a test',
    csrf: function (fields) {
      return websecurity.checkCsrf(SESSION, fields);
    },
    scope: function () {
      return null;
    }
  };
}

function apiDoor() {
  log.debug("Entering apiDoor().");
  log.debug("Leaving apiDoor().");
  return {
    via: 'the management API', source: 'upload', actor: 'a test', csrf: null,
    scope: function () {
      return null;
    }
  };
}

// The fields every form upload of an operator deny list carries, the token
// first, as the console's form sends them.
function denyFields(extra) {
  log.debug("Entering denyFields().");
  log.debug("Leaving denyFields().");
  return [{ name: 'csrf_token', value: websecurity.tokenFor(SESSION) },
          { name: 'dataset', value: 'iplist.operator-deny' },
          { name: 'format', value: 'ip-list' },
          { name: 'realm', value: 'default' }].concat(extra || []);
}

// The version's state once it is no longer loading.
async function settled(realm, dataset, version) {
  log.debug("Entering settled(). " + version);
  for (let i = 0; i < 400; i++) {
    const rows = await riskStore.listVersions(realm, dataset);
    const v = rows.filter(function (r) {
      return r.version === version;
    })[0];
    if (v && v.state !== 'loading') {
      log.debug("Leaving settled(). " + v.state);
      return v;
    }
    await new Promise(function (r) { setTimeout(r, 25); });
  }
  log.debug("Leaving settled(). Still loading.");
  return null;
}

// The upload files in the directory now.
function filesIn() {
  log.debug("Entering filesIn().");
  log.debug("Leaving filesIn().");
  return fs.readdirSync(DIR).filter(function (n) {
    return /^risk-upload-/.test(n);
  });
}

// The files once every import this file started has released its own.
async function drained() {
  log.debug("Entering drained().");
  for (let i = 0; i < 200 && filesIn().length; i++) {
    await new Promise(function (r) { setTimeout(r, 25); });
  }
  log.debug("Leaving drained().");
  return filesIn();
}

async function partA(t) {
  log.debug("Entering partA().");
  const gz = zlib.gzipSync(listOf(1200, 'A1'));
  const a1 = await riskUpload.receiveRaw(apiRequest(gz, {
    dataset: 'iplist.operator-deny', format: 'ip-list', realm: 'default' },
    'application/gzip'), apiDoor());
  const v1 = await settled('default', 'iplist.operator-deny',
                           a1.body.version);
  t.check(a1.status === 202 && a1.body.state === 'loading' &&
          a1.body.kind === 'gzip' &&
          a1.body.sha256 === nodeCrypto.createHash('sha256').update(gz)
            .digest('hex') &&
          v1 && v1.state === 'active' && v1.rowCount === 1200,
          'A1. a gzip body is answered 202 while loading, its SHA-256 is the ' +
          'file as sent, and it becomes active with every row',
          JSON.stringify([a1, v1 && v1.state]));
  const zip = zipWriter.makeZip([
    { name: 'lists/' , data: '' },
    { name: '__MACOSX/lists/._deny.txt', data: 'resource fork' },
    { name: 'lists/deny.txt', data: listOf(900, 'A2') }]);
  const a2 = await riskUpload.receiveForm(multipart(denyFields([
    { name: 'file', filename: 'deny.zip', data: zip }])), formDoor());
  const v2 = await settled('default', 'iplist.operator-deny',
                           a2.body.version);
  t.check(a2.status === 202 && a2.body.kind === 'zip' && v2 &&
          v2.state === 'active' && v2.rowCount === 900,
          'A2. a zip through the console\'s form, its one data entry beside ' +
          'a ' +
          'directory and a __MACOSX/ entry, loads to active',
          JSON.stringify([a2, v2 && v2.state]));
  const a3 = await riskUpload.receiveRaw(apiRequest(Buffer.from(
    listOf(700, 'A3')), { dataset: 'iplist.operator-deny',
                           format: 'ip-list', realm: 'default' }),
    apiDoor());
  const v3 = await settled('default', 'iplist.operator-deny',
                           a3.body.version);
  t.check(a3.status === 202 && a3.body.kind === 'plain' && v3 &&
          v3.state === 'active' && v3.rowCount === 700,
          'A3. plain text loads as it is',
          JSON.stringify([a3, v3 && v3.state]));
  const left = await drained();
  t.check(left.length === 0,
          'A4. every uploaded file is deleted once its import ends',
          left.join(', '));
  log.debug("Leaving partA().");
}

async function partB(t) {
  log.debug("Entering partB().");
  // Twenty megabytes of one letter compress to a few kilobytes: past the
  // 16 MiB floor, and a thousand to one. One long line rather than millions
  // of empty ones, so the reader meets the refusal in a few reads.
  const bomb = zlib.gzipSync(Buffer.alloc(20 * 1024 * 1024, 0x61),
                             { level: 9 });
  const b1 = await riskUpload.receiveRaw(apiRequest(bomb, {
    dataset: 'iplist.operator-deny', format: 'ip-list', realm: 'default',
    version: 'bomb-gz' }), apiDoor());
  const v1 = await settled('default', 'iplist.operator-deny', 'bomb-gz');
  t.check(b1.status === 202 && v1 && v1.state === 'refused' &&
          v1.errorCode === 'STS-RISK-0032' &&
          /decompression bomb/.test(v1.refusal),
          'B1. a gzip decompression bomb is refused while it expands, and ' +
          'the version says why', JSON.stringify(v1));
  const liar = zipWriter.makeZip([{ name: 'deny.txt', data: listOf(5, 'B2'),
                                    declaredSize: 900 * 1024 * 1024 }]);
  await riskUpload.receiveRaw(apiRequest(liar, {
    dataset: 'iplist.operator-deny', format: 'ip-list', realm: 'default',
    version: 'bomb-zip' }), apiDoor());
  const v2 = await settled('default', 'iplist.operator-deny', 'bomb-zip');
  t.check(v2 && v2.state === 'refused' && v2.errorCode === 'STS-RISK-0032',
          'B2. a zip entry declaring more than the allowance is refused ' +
          'before a byte of it is read', JSON.stringify(v2));
  const two = zipWriter.makeZip([{ name: 'a.txt', data: listOf(3, 'B3a') },
                                 { name: 'b.txt', data: listOf(3, 'B3b') }]);
  await riskUpload.receiveRaw(apiRequest(two, {
    dataset: 'iplist.operator-deny', format: 'ip-list', realm: 'default',
    version: 'two-entries' }, 'application/zip'), apiDoor());
  const v3 = await settled('default', 'iplist.operator-deny', 'two-entries');
  t.check(v3 && v3.state === 'refused' && v3.errorCode === 'STS-RISK-0033' &&
          /a\.txt, b\.txt/.test(v3.refusal),
          'B3. a zip of two data entries is refused as ambiguous, naming them',
          JSON.stringify(v3));
  const corrupt = Buffer.concat([zlib.gzipSync(listOf(4000, 'B4'))
    .subarray(0, 2000)]);
  await riskUpload.receiveRaw(apiRequest(corrupt, {
    dataset: 'iplist.operator-deny', format: 'ip-list', realm: 'default',
    version: 'truncated-gz' }), apiDoor());
  const v4 = await settled('default', 'iplist.operator-deny', 'truncated-gz');
  t.check(v4 && v4.state === 'refused' && v4.errorCode === 'STS-RISK-0034' &&
          v4.rowCount === 0,
          'B4. a truncated gzip stream is refused as corrupt, and nothing of ' +
          'it is kept', JSON.stringify(v4));
  const active = (await riskStore.listDatasets()).filter(function (r) {
    return r.dataset === 'iplist.operator-deny' && r.realm === 'default';
  })[0];
  t.check(active && ['bomb-gz', 'bomb-zip', 'two-entries', 'truncated-gz']
            .indexOf(active.activeVersion) < 0,
          'B5. the active version is untouched by every refusal',
          JSON.stringify(active));
  await drained();
  log.debug("Leaving partB().");
}

async function partC(t) {
  log.debug("Entering partC().");
  config.setOverride('risk.uploadMaxBytes', '4096');
  const big = Buffer.from(listOf(2000, 'C1'));
  const declared = apiRequest(big, { dataset: 'iplist.operator-deny',
    format: 'ip-list', realm: 'default' });
  const c1 = await riskUpload.receiveRaw(declared, apiDoor());
  t.check(c1.status === 413 && c1.code === 'STS-RISK-0028' && c1.close &&
          declared.readableFlowing === null && filesIn().length === 0,
          'C1. a declared length over risk.uploadMaxBytes is refused before ' +
          'a byte is read', JSON.stringify([c1, declared.readableFlowing]));
  const c2 = await riskUpload.receiveRaw(apiRequest(big, {
    dataset: 'iplist.operator-deny', format: 'ip-list', realm: 'default' },
    'application/octet-stream', null), apiDoor());
  const c2b = await riskUpload.receiveForm(multipart(denyFields([
    { name: 'file', filename: 'big.txt', data: big }])), formDoor());
  t.check(c2.status === 413 && c2.code === 'STS-RISK-0028' &&
          c2b.status === 413 && c2b.code === 'STS-RISK-0028' &&
          (await drained()).length === 0,
          'C2. an undeclared body, and a form\'s file, are stopped where ' +
          'they ' +
          'pass the cap, and nothing is kept', JSON.stringify([c2, c2b]));
  config.clearOverride('risk.uploadMaxBytes');
  const full = new riskUpload.RiskUpload(Object.assign(
    riskUpload.RiskUpload.defaultDeps(), {
      freeBytes: function () {
        return Promise.resolve(1024);
      } }));
  const c3 = await full.receiveRaw(apiRequest(Buffer.from(listOf(5, 'C3')), {
    dataset: 'iplist.operator-deny', format: 'ip-list', realm: 'default' }),
    apiDoor());
  t.check(c3.status === 507 && c3.code === 'STS-RISK-0029' &&
          filesIn().length === 0,
          'C3. an upload the directory has no room for is refused before a ' +
          'byte is read', JSON.stringify(c3));
  log.debug("Leaving partC().");
}

async function partD(t) {
  log.debug("Entering partD().");
  const file = { name: 'file', filename: 'deny.txt', data: listOf(5, 'D') };
  const wrong = await riskUpload.receiveForm(multipart([
    { name: 'csrf_token', value: 'not-this-sessions' },
    { name: 'dataset', value: 'iplist.operator-deny' },
    { name: 'format', value: 'ip-list' }, file]), formDoor());
  const late = await riskUpload.receiveForm(multipart([
    { name: 'dataset', value: 'iplist.operator-deny' },
    { name: 'format', value: 'ip-list' }, file,
    { name: 'csrf_token', value: websecurity.tokenFor(SESSION) }]),
    formDoor());
  t.check(wrong.status === 403 && wrong.code === 'STS-ADMIN-0005' &&
          late.status === 403 && late.code === 'STS-ADMIN-0005' &&
          (await drained()).length === 0,
          'D1. a wrong CSRF token, and a token that comes after the file, ' +
          'are ' +
          'refused before the file is written', JSON.stringify([wrong, late]));
  const after = await riskUpload.receiveForm(multipart(denyFields([file,
    { name: 'version', value: 'too-late' }])), formDoor());
  const none = await riskUpload.receiveForm(multipart(denyFields()),
                                            formDoor());
  const twice = await riskUpload.receiveForm(multipart(denyFields([file,
    { name: 'file2', filename: 'b.txt', data: listOf(5, 'D2') }])),
    formDoor());
  t.check(after.status === 400 && after.code === 'STS-RISK-0031' &&
          none.status === 400 && /no file/.test(none.body.errors[0]) &&
          twice.status === 400 && twice.code === 'STS-RISK-0031' &&
          (await drained()).length === 0,
          'D2. a field after the file, a form with no file, and a second ' +
          'file are refused, and nothing is kept',
          JSON.stringify([after.body, none.body, twice.body]));
  const noTerms = await riskUpload.receiveForm(multipart([
    { name: 'csrf_token', value: websecurity.tokenFor(SESSION) },
    { name: 'dataset', value: 'iplist.tor-exit' },
    { name: 'format', value: 'ip-list' }, file]), formDoor());
  t.check(noTerms.status === 400 && noTerms.code === 'STS-RISK-0014' &&
          (await drained()).length === 0,
          'D3. a provider whose terms nobody accepted is refused before the ' +
          'file is written', JSON.stringify(noTerms.body));
  // THE ROUTE: a session that may read and not write is refused before the
  // upload reads anything.
  const admin = require('../admin-ui/admin');
  const riskAdmin = require('../admin-ui/risk_admin');
  const routes = {};
  riskAdmin.registerRoutes({
    get: function () {},
    post: function (p, fn) {
      routes[p] = fn;
    }
  });
  const saved = admin.mayWrite;
  admin.mayWrite = function () {
    return false;
  };
  const req = multipart(denyFields([file]));
  const res = { headers: {}, statusCode: 0, location: '', marked: [] };
  const answered = new Promise(function (resolve) {
    res.set = function (k, v) {
      res.headers[k] = v;
      return res;
    };
    res.status = function (n) {
      res.statusCode = n;
      return res;
    };
    res.type = function () {
      return res;
    };
    res.send = function (b) {
      res.body = b;
      resolve();
      return res;
    };
    res.redirect = function (n, where) {
      res.statusCode = n;
      res.location = where;
      resolve();
      return res;
    };
  });
  try {
    routes[riskAdmin.UPLOAD](req, res);
    await answered;
  } finally {
    admin.mayWrite = saved;
  }
  t.check(res.statusCode === 303 && /error=/.test(res.location) &&
          res.headers.Connection === 'close' &&
          req.readableFlowing === null && filesIn().length === 0,
          'D4. the console route refuses a session without Admin Write ' +
          'before the upload reads a byte', JSON.stringify(res));
  log.debug("Leaving partD().");
}

async function partE(t) {
  log.debug("Entering partE().");
  const e1 = await riskUpload.receiveRaw(apiRequest(Buffer.from('x'), {
    dataset: 'iplist.operator-deny', format: 'ip-list' }, 'text/plain'),
    apiDoor());
  const e2 = await riskUpload.receiveRaw(apiRequest(Buffer.from('x'), {
    dataset: 'iplist.operator-deny', format: 'ip-list', colour: 'blue' }),
    apiDoor());
  const e3 = await riskUpload.receiveRaw(apiRequest(Buffer.alloc(0), {
    dataset: 'iplist.operator-deny', format: 'ip-list', realm: 'default' }),
    apiDoor());
  t.check(e1.status === 415 && e1.code === 'STS-RISK-0031' &&
          e2.status === 400 && /colour/.test(e2.body.errors[0]) &&
          e3.status === 400 && /empty/.test(e3.body.errors[0]) &&
          (await drained()).length === 0,
          'E1. the API refuses a body type it does not take, a parameter it ' +
          'does not know, and an empty file',
          JSON.stringify([e1.body, e2.body, e3.body]));
  log.debug("Leaving partE().");
}

async function partF(t) {
  log.debug("Entering partF().");
  const app = require('../common/app');
  const ask = function (method, p, base) {
    return app.isStreamedUpload({ method: method, path: p,
                                  baseUrl: base || '' });
  };
  t.check(ask('POST', '/admin/risk/upload') &&
          ask('POST', '/admin-api/risk/upload') &&
          ask('POST', '/admin/risk/upload/') &&
          ask('POST', '/ADMIN/Risk/Upload') &&
          ask('POST', '/risk/upload', '/admin') &&
          !ask('GET', '/admin/risk/upload') &&
          !ask('POST', '/admin/risk') &&
          !ask('POST', '/admin/risk/uploads') &&
          !ask('POST', '/admin-api/risk/import') &&
          !ask('POST', '/admin/risk/upload/x') &&
          !ask('POST', '/x/admin/risk/upload'),
          'F1. the body parsers and the console gate leave exactly the two ' +
          'upload paths alone, as express routes them');
  log.debug("Leaving partF().");
}

async function partG(t) {
  log.debug("Entering partG().");
  const long = Date.now() - 3600000;
  await riskStore.beginVersion({ realm: 'default',
    dataset: 'iplist.operator-deny', version: 'orphan', format: 'ip-list',
    provider: 'operator', licence: '', source: 'upload', sha256: 'x',
    byteCount: 1, parameters: {}, verification: 'none', publishedAt: long,
    fetchedAt: long });
  const fresh = Date.now();
  await riskStore.beginVersion({ realm: 'default',
    dataset: 'iplist.operator-deny', version: 'alive', format: 'ip-list',
    provider: 'operator', licence: '', source: 'upload', sha256: 'y',
    byteCount: 1, parameters: {}, verification: 'none', publishedAt: fresh,
    fetchedAt: fresh });
  const out = await riskDatasets.abandonStalled();
  const rows = await riskStore.listVersions('default', 'iplist.operator-deny');
  const of = function (v) {
    return rows.filter(function (r) {
      return r.version === v;
    })[0];
  };
  const touched = await riskStore.touchVersion('default',
    'iplist.operator-deny', 'orphan', Date.now(), 5);
  t.check(out.refused === 1 && of('orphan').state === 'refused' &&
          of('orphan').errorCode === 'STS-RISK-0035' &&
          of('alive').state === 'loading' && touched === false,
          'G1. a version left loading past risk.importStallMinutes is ' +
          'refused, a live one is not, and the refused one can no longer be ' +
          'stamped — which is what stops its import',
          JSON.stringify([out, of('orphan'), of('alive').state]));
  await riskStore.finishVersion('default', 'iplist.operator-deny', 'alive', {
    state: 'refused', rowCount: 0, loadedAt: Date.now(), refusal: 'test' });
  const stale = path.join(DIR, 'risk-upload-1xdeadbeef-' +
                          nodeCrypto.randomUUID() + '.part');
  const young = path.join(DIR, 'risk-upload-2xcafecafe-' +
                          nodeCrypto.randomUUID() + '.part');
  const mine = path.join(DIR, 'risk-upload-' + riskUpload.PROCESS_TAG + '-' +
                         nodeCrypto.randomUUID() + '.part');
  const stranger = path.join(DIR, 'operator-notes.txt');
  [stale, young, mine, stranger].forEach(function (f) {
    fs.writeFileSync(f, 'x');
  });
  const hour = (Date.now() - 3600000) / 1000;
  fs.utimesSync(stale, hour, hour);
  fs.utimesSync(stranger, hour, hour);
  const swept = await riskUpload.sweep();
  t.check(swept.removed === 2 && !fs.existsSync(stale) &&
          !fs.existsSync(mine) && fs.existsSync(young) &&
          fs.existsSync(stranger),
          'G2. the per-process sweep removes another process\'s stale upload ' +
          'and this process\'s unheld one, and leaves a fresh upload and a ' +
          'file that is not an upload', JSON.stringify(swept));
  fs.rmSync(young, { force: true });
  fs.rmSync(stranger, { force: true });
  log.debug("Leaving partG().");
}

async function partH(t) {
  log.debug("Entering partH().");
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'risk-expand-'));
  const gz = path.join(work, 'deny.csv');
  fs.writeFileSync(gz, zlib.gzipSync(listOf(300, 'H1')));
  const zip = path.join(work, 'deny.bin');
  fs.writeFileSync(zip, zipWriter.makeZip([{ name: 'x.txt',
                                             data: listOf(200, 'H2') }]));
  // The allow list, which nothing above loaded: the shrink rule has no
  // active version to hold these to.
  const h1 = await riskDatasets.importVersion({
    dataset: 'iplist.operator-allow', format: 'ip-list', realm: 'default',
    path: gz, version: 'by-path-gz', source: 'directory' });
  const h2 = await riskDatasets.importVersion({
    dataset: 'iplist.operator-allow', format: 'ip-list', realm: 'default',
    path: zip, version: 'by-path-zip', source: 'install', activate: false });
  const sha = nodeCrypto.createHash('sha256').update(fs.readFileSync(gz))
    .digest('hex');
  fs.rmSync(work, { recursive: true, force: true });
  t.check(h1.ok && h1.rows === 300 && h1.sha256 === sha &&
          h2.ok && h2.rows === 200,
          'H1. a .gz and a .zip by path — the dataset directory\'s and the ' +
          'loader\'s way in — are expanded by content through the same path, ' +
          'whatever they are called', JSON.stringify([h1, h2]));
  log.debug("Leaving partH().");
}

async function run(t) {
  log.debug("Entering run().");
  config.setOverride('risk.uploadDirectory', DIR);
  riskStore.reset();
  riskDatasets.forget();
  try {
    await partA(t);
    await partB(t);
    await partC(t);
    await partD(t);
    await partE(t);
    await partF(t);
    await partG(t);
    await partH(t);
  } finally {
    config.clearOverride('risk.uploadDirectory');
    config.clearOverride('risk.uploadMaxBytes');
    fs.rmSync(DIR, { recursive: true, force: true });
  }
  // The terms module is loaded for the provider the D3 refusal names.
  log.debug("Leaving run(). " + typeof riskTerms.status);
}

module.exports = {
  name: 'risk_upload',
  describe: 'a risk dataset uploaded as a file (#215): gzip, zip and plain ' +
            'by content, loading then active, the bombs and the ambiguous ' +
            'zip refused, the size cap and a full disk, the console form\'s ' +
            'CSRF and field order, the API\'s body types, the exemption ' +
            'predicate, crash leftovers, and the one expansion path',
  run: run
};
