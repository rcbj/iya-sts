'use strict';
//
// File: risk/risk_upload.ts
//
// ===========================================================================
// A DATASET FILE, UPLOADED (#215, 2026-09-24).
//
// rcbj: "loading a dataset on Monitoring → Risk today means pasting its
// contents into a text box. That works for a Tor list and not for a DB-IP
// city file of several hundred megabytes. Add a file upload." There are two
// doors and this file is what both of them do:
//
//   * **the console**: `POST /admin/risk/upload`, a plain
//     `multipart/form-data` form with a real submit button and no script,
//     carrying the dataset, the format, and optionally the version, the
//     SHA-256 and the provider's terms accepted — the fields BEFORE the
//     file, which is the order a browser sends the form in;
//   * **its rule 7 twin**: `POST /admin-api/risk/upload`, the file as the
//     request body (`application/octet-stream`, `application/gzip` or
//     `application/zip`) and the fields as query parameters.
//
// SIX RULES, in the order a request meets them:
//
//   1. **AUTHENTICATED BEFORE A BYTE IS ACCEPTED.** The console's gate (a
//      session holding Admin Write) and the API's (an access token with
//      `admin:write`) both run on the request's HEADERS, ahead of this file,
//      exactly as for every other write. What a gate cannot see — the
//      console's CSRF token and a realm administrator's reach — is in the
//      FIELDS, so the console form's fields come before its file and this
//      file checks the token (`csrf`) and the realm (`scope`) when the file
//      part begins, before it writes any of it. A declared length over
//      `risk.uploadMaxBytes` is refused before the body is read at all.
//   2. **STREAMED, NEVER BUFFERED.** `common/app.js`'s body parsers drain
//      every body into memory at 5 MB; the two upload paths are their one
//      exception, argued where it is made. The dispatch path already pipes
//      (`request_pool.js`'s `proxy()`), so a request worker receives the
//      bytes as they arrive too. The file goes to `risk.uploadDirectory`,
//      its SHA-256 computed on the way (`crypto.sha256Digester()`), and is
//      refused past `risk.uploadMaxBytes` (STS-RISK-0028) or when the
//      directory's free space (`statfs`) cannot hold it (STS-RISK-0029).
//   3. **EXPANDED BY CONTENT, AS IT IS READ.** Nothing here decompresses:
//      `importVersion()` reads the file through `risk_expand.ts`, the one
//      expansion path the dataset directory and the install-time loader
//      share, which refuses a decompression bomb and an ambiguous zip.
//   4. **ASYNCHRONOUS.** The answer goes as soon as the file is stored and
//      the version is recorded `loading` (`importVersion()`'s `onBegun`);
//      the page and `GET /admin-api/risk` then show it `active` or
//      `refused` with its reason. A refusal found BEFORE the version is
//      recorded — terms not accepted, the version already loaded — is the
//      answer itself.
//   5. **THE FILE GOES WHEN THE IMPORT ENDS, HOWEVER IT ENDS.** And a crash
//      that stopped a process mid-import leaves two things, each with a
//      scheduler job and no timer: its file, which `risk.upload-cleanup`
//      (per process, below) deletes once nobody has touched it for
//      `risk.importStallMinutes`, and its version, which
//      `risk.stalled-imports` (a cluster job in `risk_datasets.ts`) marks
//      refused. A process keeps its own files fresh — every batch touches
//      the file, and every run of the per-process job touches the ones it
//      holds — so only a stopped process's file ever grows old.
//   6. **EVERY REFUSAL HAS A CODE**, and the partial file is deleted with it.
//
// A LIBRARY (rule 3): it registers no route. The console's route is
// `admin-ui/risk_admin.ts`'s and the API's is `mgmt-api/admin_api.ts`'s;
// each builds the DOOR it is (who acts, the CSRF check, the realm check) and
// hands the request here. Its one scheduler job is registered when its
// instance is wired, in every process.
// ===========================================================================

import bunyan = require('bunyan');
import fs = require('fs');
import nodeCrypto = require('crypto');
import path = require('path');
import stream = require('stream');
import config = require('../common/config');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import riskDatasets = require('./risk_datasets');
import RiskExpand = require('./risk_expand');

// busboy (MIT) parses multipart/form-data as a stream. It ships no
// declarations, so it is `any` here.
const busboy: any = require('busboy');

const log = bunyan.createLogger({ name: 'sts-risk-upload' });
config.registerLogger(log);

type Json = any;

// The package root, which a relative `risk.uploadDirectory` is resolved
// against — as `persistence.dataDir` is, for its reason: the working
// directory is whatever the process was started in.
const ROOT = path.join(__dirname, '..');

// Free space the directory must keep beyond the upload itself: a disk left
// with nothing is a disk the next log line cannot be written to.
const RESERVE_BYTES = 16 * 1024 * 1024;

// The fields an upload may carry, whichever door it came through. The
// console's form adds `csrf_token`, which the door checks.
const FIELDS = ['dataset', 'format', 'realm', 'version', 'sha256',
                'publishedAt', 'provider', 'licence', 'attribution',
                'activate', 'acceptTerms'];

// The request bodies the API door takes. None of them decides how the file
// is read — its first bytes do (`risk_expand.ts`) — but a caller naming a
// type says it is sending a file, and anything else is refused rather than
// guessed at.
const API_TYPES = ['application/octet-stream', 'application/gzip',
                   'application/zip'];

// Multipart bounds: one file, a handful of short fields.
const MAX_FIELDS = 32;
const MAX_FIELD_BYTES = 64 * 1024;
const MAX_PARTS = 40;

// This process's own mark on the files it writes, so the clean-up job can
// tell its files from another process's.
const PROCESS_TAG = String(process.pid) + 'x' +
  nodeCrypto.randomBytes(4).toString('hex');
const FILE_NAME = /^risk-upload-([a-z0-9]+)-[0-9a-f-]{36}\.part$/;

const CLEANUP_JOB = 'risk.upload-cleanup';

// Who is uploading, and the checks a gate could not make on headers alone.
interface UploadDoor {
  // The audit channel and the importer's `source` (the console, the API).
  via: string;
  source: string;
  // Who acts, for the terms acceptance an upload may carry and the audit.
  actor: string;
  // The console's CSRF check over the fields, or null for the API (a bearer
  // token is not something a browser attaches on another site's behalf).
  csrf: ((fields: Json) => { ok: boolean; reason?: string;
                             detail?: string }) | null;
  // A realm administrator's reach over the fields: `{ code, why }` when the
  // fields name what is not theirs, null otherwise.
  scope: (fields: Json) => { code: string; why: string } | null;
}

// What the route answers: an HTTP status, the code to mark (on a refusal),
// and the body.
interface UploadAnswer {
  status: number;
  code: string;
  body: Json;
  // Set on a refusal made while the body may still be arriving: the route
  // answers with `Connection: close`, so the client is not left sending
  // hundreds of megabytes into a request that has already been answered.
  close?: boolean;
}

interface RiskUploadDeps {
  log: { debug(m: string): void; info(m: string): void; warn(m: string): void;
         error(m: string): void };
  config: { value(key: string): any };
  datasets: typeof riskDatasets;
  now(): number;
  // The directory's free bytes: `fs.promises.statfs()`'s `bavail * bsize`.
  // A dependency so a test can say the disk is full.
  freeBytes(dir: string): Promise<number>;
  scheduler(): Json;
}

class RiskUpload {
  static readonly FIELDS = FIELDS;
  static readonly API_TYPES = API_TYPES;
  static readonly CLEANUP_JOB = CLEANUP_JOB;
  static readonly PROCESS_TAG = PROCESS_TAG;

  // The files this process is writing or importing now.
  private readonly held = new Set<string>();

  constructor(private readonly deps: RiskUploadDeps) {
    deps.log.debug("Entering RiskUpload.constructor().");
    deps.log.debug("Leaving RiskUpload.constructor().");
  }

  static defaultDeps(): RiskUploadDeps {
    log.debug("Entering RiskUpload.defaultDeps().");
    log.debug("Leaving RiskUpload.defaultDeps().");
    return {
      log: log,
      config: config,
      datasets: riskDatasets,
      now: function (): number {
        return Date.now();
      },
      freeBytes: function (dir: string): Promise<number> {
        log.debug("Entering freeBytes().");
        log.debug("Leaving freeBytes().");
        return fs.promises.statfs(dir).then(function (s: Json): number {
          return Number(s.bavail) * Number(s.bsize);
        });
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      }
    };
  }

  // Where uploads are written, resolved.
  directory(): string {
    const { log, config } = this.deps;
    log.debug("Entering RiskUpload.directory().");
    const dir = String(config.value('risk.uploadDirectory') || '');
    log.debug("Leaving RiskUpload.directory().");
    return path.resolve(ROOT, dir || './data/risk-uploads');
  }

  // A refusal, coded.
  private static refusal(status: number, code: string, why: string,
                         close?: boolean): UploadAnswer {
    log.debug("Entering RiskUpload.refusal(). " + code);
    log.debug("Leaving RiskUpload.refusal().");
    return { status: status, code: code, close: !!close,
             body: errorCodes.mark({ ok: false, errors: [why] }, code) };
  }

  // The declared length, or -1 when the request did not declare one.
  private static declaredLength(req: Json): number {
    log.debug("Entering RiskUpload.declaredLength().");
    const raw = req && req.headers ? req.headers['content-length'] : undefined;
    const n = raw === undefined ? -1 : Number(raw);
    log.debug("Leaving RiskUpload.declaredLength().");
    return isFinite(n) && n >= 0 ? n : -1;
  }

  // -------------------------------------------------------------------------
  // THE CHECKS BEFORE ANY BYTE IS READ: the body is still unread (a body
  // parser that took it would leave this waiting for ever), the declared
  // length is within the cap, the directory exists and has room. Null when
  // the upload may go on; the refusal otherwise.
  // -------------------------------------------------------------------------
  private async before(req: Json): Promise<UploadAnswer | null> {
    const { log, config, freeBytes } = this.deps;
    log.debug("Entering RiskUpload.before().");
    if (req._body || req.body !== undefined || req.readableEnded) {
      // `common/app.js` exempts exactly these paths from its parsers; a body
      // already read means that exemption and the route disagree, and the
      // honest answer is to say so rather than wait for bytes that will
      // never come.
      log.error(errorCodes.tag('STS-RISK-0031') + 'risk: an upload reached ' +
                'its handler with its body already read — common/app.js ' +
                'exempts the upload paths from its body parsers, and this ' +
                'request was not exempted: ' + String(req.originalUrl));
      log.debug("Leaving RiskUpload.before(). Body already read.");
      return RiskUpload.refusal(500, 'STS-RISK-0031', 'This upload\'s body ' +
        'was read before it reached the upload, so there is nothing left ' +
        'to store. The service\'s body-parser exemption does not match ' +
        'this path; this is a defect to report, not a request to retry.');
    }
    const max = Number(config.value('risk.uploadMaxBytes'));
    const declared = RiskUpload.declaredLength(req);
    if (declared > max) {
      log.debug("Leaving RiskUpload.before(). Declared too large.");
      return RiskUpload.refusal(413, 'STS-RISK-0028', 'The upload declares ' +
        declared + ' bytes, and the most an upload may be is ' + max +
        ' (risk.uploadMaxBytes). Nothing was read.', true);
    }
    const dir = this.directory();
    try {
      await fs.promises.mkdir(dir, { recursive: true, mode: 0o700 });
      await fs.promises.access(dir, fs.constants.W_OK);
    } catch (e) {
      log.error(errorCodes.tag('STS-RISK-0030') + 'risk: the upload ' +
                'directory ' + dir + ' cannot be written: ' +
                ((e && e.message) || e));
      log.debug("Leaving RiskUpload.before(). Directory.");
      return RiskUpload.refusal(500, 'STS-RISK-0030', 'The upload ' +
        'directory (risk.uploadDirectory) cannot be written: ' +
        ((e && e.code) || (e && e.message) || e) + '. Nothing was read.',
        true);
    }
    const need = (declared >= 0 ? declared : max) + RESERVE_BYTES;
    let free = -1;
    try {
      free = await freeBytes(dir);
    } catch (e) {
      log.debug("Caught in RiskUpload.before(): " + ((e && e.message) || e));
      // A filesystem that will not say how full it is: the write itself is
      // still bounded by the cap, and a disk that fills is refused below
      // (ENOSPC), so the upload goes on rather than be refused on a guess.
      free = -1;
    }
    if (free >= 0 && free < need) {
      log.warn(errorCodes.tag('STS-RISK-0029') + 'risk: an upload of ' +
               (declared >= 0 ? declared + ' bytes' : 'undeclared length') +
               ' was refused: ' + dir + ' has ' + free + ' bytes free.');
      log.debug("Leaving RiskUpload.before(). No room.");
      return RiskUpload.refusal(507, 'STS-RISK-0029', 'The upload directory ' +
        'has ' + free + ' bytes free and this upload needs ' + need +
        (declared >= 0 ? '' : ' — it declared no length, so the most an ' +
         'upload may be (risk.uploadMaxBytes) is what is kept free for it; ' +
         'send a Content-Length') + '. Nothing was read.', true);
    }
    log.debug("Leaving RiskUpload.before().");
    return null;
  }

  // The fields as the importer takes them: strings, trimmed, the two flags
  // as the console's checkbox (`on`) or the API's `true`.
  private static importFields(fields: Json): Json {
    log.debug("Entering RiskUpload.importFields().");
    const f = fields || {};
    const text = function (name: string): string {
      return String(f[name] === undefined ? '' : f[name]).trim();
    };
    log.debug("Leaving RiskUpload.importFields().");
    return {
      dataset: text('dataset'), format: text('format'), realm: text('realm'),
      version: text('version') || undefined,
      sha256: text('sha256').toLowerCase() || undefined,
      publishedAt: text('publishedAt') ? Date.parse(text('publishedAt')) || 0
                                       : 0,
      provider: text('provider') || undefined,
      licence: text('licence') || undefined,
      attribution: f.attribution === undefined ? undefined
                                               : text('attribution'),
      activate: text('activate') !== 'false',
      acceptTerms: ['true', 'on'].indexOf(text('acceptTerms')) >= 0
    };
  }

  // -------------------------------------------------------------------------
  // THE CHECKS ON THE FIELDS, before the file: named at all, the door's
  // CSRF and realm checks, and whether the import may begin
  // (`risk_datasets.precheck()`: the dataset, format, realm, provider and
  // terms). Null when the file may be written.
  // -------------------------------------------------------------------------
  private async fieldsRefusal(fields: Json, door: UploadDoor,
                              target: string): Promise<UploadAnswer | null> {
    const { log, datasets } = this.deps;
    log.debug("Entering RiskUpload.fieldsRefusal().");
    if (door.csrf) {
      const token = door.csrf(fields);
      if (!token.ok) {
        log.warn('risk: an upload through ' + door.via + ' was refused on ' +
                 'CSRF (' + String(token.reason || '') + '), for ' +
                 door.actor + '.');
        log.debug("Leaving RiskUpload.fieldsRefusal(). CSRF.");
        return RiskUpload.refusal(403, 'STS-ADMIN-0005', 'That form did not ' +
          'come from this console: ' + String(token.detail || token.reason) +
          ' Nothing was stored.', true);
      }
    }
    const f = RiskUpload.importFields(fields);
    if (!f.dataset || !f.format) {
      log.debug("Leaving RiskUpload.fieldsRefusal(). Unnamed.");
      return RiskUpload.refusal(400, 'STS-RISK-0031', 'An upload names its ' +
        'dataset and its format' + (door.csrf ? ', in fields that come ' +
        'before the file' : '') + '. Nothing was stored.', true);
    }
    const scoped = door.scope(Object.assign({ action: 'import' }, f));
    if (scoped) {
      log.debug("Leaving RiskUpload.fieldsRefusal(). Scope.");
      // error-code: none — the code is scoped.code, admin_scope.ts's own
      return RiskUpload.refusal(403, scoped.code, scoped.why +
                                ' Nothing was stored.', true);
    }
    const refused = await datasets.precheck(Object.assign({}, f, {
      path: target, source: door.source, actor: door.actor }));
    if (refused) {
      log.debug("Leaving RiskUpload.fieldsRefusal(). Not admitted.");
      return { status: 400, code: errorCodes.codeOf(refused) || 'STS-RISK-0001',
               body: refused, close: true };
    }
    log.debug("Leaving RiskUpload.fieldsRefusal().");
    return null;
  }

  // -------------------------------------------------------------------------
  // THE FILE ITSELF: `source` written to `target`, hashed and counted on the
  // way, refused past the cap. Resolves `{ ok, bytes, sha256 }` or the
  // refusal; the partial file is deleted with a refusal.
  // -------------------------------------------------------------------------
  private store(source: stream.Readable, target: string,
                truncated: () => boolean): Promise<Json> {
    const { log, config } = this.deps;
    log.debug("Entering RiskUpload.store().");
    const max = Number(config.value('risk.uploadMaxBytes'));
    const digest = stsCrypto.sha256Digester();
    let bytes = 0;
    let over = false;
    const meter = new stream.Transform({
      // One call per chunk of the upload — a hot path, so no
      // Entering/Leaving pair.
      transform: function (chunk: Buffer, encoding: string,
                           done: (e?: Error | null, c?: Buffer) => void) {
        bytes += chunk.length;
        if (bytes > max) {
          over = true;
          done(new Error('over risk.uploadMaxBytes'));
          return;
        }
        digest.update(chunk);
        done(null, chunk);
      }
    });
    const out = fs.createWriteStream(target, { flags: 'wx', mode: 0o600 });
    log.debug("Leaving RiskUpload.store().");
    return new Promise(function (resolve) {
      let settled = false;
      // NOT `stream.pipeline()`: on an error it destroys every stream it
      // was given, and the first of them is the REQUEST — whose socket the
      // refusal still has to be written to. The request is unpiped and left
      // to drain instead, and the route answers `Connection: close`.
      const settle = function (e: Json): void {
        log.debug("Entering settle(). " + ((e && (e.code || e.message)) ||
                                           'finished'));
        if (settled) {
          log.debug("Leaving settle(). Already settled.");
          return;
        }
        settled = true;
        if (!e && truncated()) {
          // busboy stopped the file at its `fileSize` limit: the same cap.
          over = true;
        }
        if (!e && !over) {
          resolve({ ok: true, bytes: bytes, sha256: digest.hex() });
          log.debug("Leaving settle(). Stored.");
          return;
        }
        source.unpipe(meter);
        source.resume();
        out.destroy();
        fs.promises.rm(target, { force: true }).catch(function (x: Json) {
          log.debug("Caught removing a refused upload: " +
                    ((x && x.message) || x));
          // The clean-up job removes what is left; the refusal stands.
        });
        if (over) {
          resolve(RiskUpload.refusal(413, 'STS-RISK-0028', 'The upload is ' +
            'larger than ' + max + ' bytes (risk.uploadMaxBytes); it was ' +
            'stopped there and nothing of it is kept.', true));
        } else if (e && (e.code === 'ENOSPC' || e.code === 'EDQUOT')) {
          log.warn(errorCodes.tag('STS-RISK-0029') + 'risk: the upload ' +
                   'directory filled while an upload was written.');
          resolve(RiskUpload.refusal(507, 'STS-RISK-0029', 'The upload ' +
            'directory filled while the file was written (' + e.code +
            '); nothing of it is kept.', true));
        } else if (e && e.premature) {
          resolve(RiskUpload.refusal(400, 'STS-RISK-0031', 'The upload ' +
            'ended before its body did; nothing of it is kept.', true));
        } else {
          log.error(errorCodes.tag('STS-RISK-0030') + 'risk: an upload ' +
                    'could not be written to ' + target + ': ' +
                    ((e && e.message) || e));
          resolve(RiskUpload.refusal(500, 'STS-RISK-0030', 'The upload ' +
            'could not be written: ' + ((e && e.code) || (e && e.message) ||
            e) + '; nothing of it is kept.', true));
        }
        log.debug("Leaving settle(). Refused.");
      };
      source.on('error', function (e: Json): void {
        settle({ premature: true, message: (e && e.message) || String(e) });
      });
      source.on('close', function (): void {
        if (!source.readableEnded) {
          settle({ premature: true, message: 'closed before its end' });
        }
      });
      meter.on('error', settle);
      out.on('error', settle);
      out.on('finish', function (): void {
        settle(null);
      });
      source.pipe(meter).pipe(out);
    });
  }

  // A new file's path in the directory, this process's mark on it.
  private newTarget(): string {
    const { log } = this.deps;
    log.debug("Entering RiskUpload.newTarget().");
    const name = 'risk-upload-' + PROCESS_TAG + '-' + nodeCrypto.randomUUID() +
                 '.part';
    log.debug("Leaving RiskUpload.newTarget().");
    return path.join(this.directory(), name);
  }

  // -------------------------------------------------------------------------
  // THE STORED FILE, IMPORTED (rule 4): `importVersion()` on its path, with
  // the digest already computed. Resolves when the version is recorded
  // `loading` — the upload's answer — or, if it ends first, with how it
  // ended. The file is deleted when the import ends, however it ends.
  // -------------------------------------------------------------------------
  private importStored(target: string, stored: Json, fields: Json,
                       door: UploadDoor): Promise<UploadAnswer> {
    const { log, datasets } = this.deps;
    const self = this;
    log.debug("Entering RiskUpload.importStored().");
    const f = RiskUpload.importFields(fields);
    let kind = 'plain';
    try {
      kind = RiskExpand.sniff(RiskExpand.headOf(target));
    } catch (e) {
      log.debug("Caught in RiskUpload.importStored(): " +
                ((e && e.message) || e));
      // Only for the answer's `kind`; the importer reads the file itself
      // and refuses what it cannot.
      kind = 'unknown';
    }
    let lastTouch = 0;
    log.debug("Leaving RiskUpload.importStored().");
    return new Promise(function (resolve) {
      let answered = false;
      const answer = function (a: UploadAnswer): void {
        log.debug("Entering answer(). " + a.status);
        if (!answered) {
          answered = true;
          resolve(a);
        }
        log.debug("Leaving answer().");
      };
      datasets.importVersion(Object.assign({}, f, {
        path: target, fileSha256: stored.sha256, source: door.source,
        sourceUri: '', actor: door.actor,
        onBegun: function (what: Json): void {
          log.debug("Entering onBegun(). " + what.version);
          answer({ status: 202, code: '', body: {
            ok: true, state: 'loading', dataset: what.dataset,
            realm: what.realm, version: what.version, sha256: what.sha256,
            bytes: stored.bytes, kind: kind,
            message: 'Stored ' + stored.bytes + ' bytes (' + kind + ') and ' +
                     'began loading ' + what.dataset + ' version ' +
                     what.version + '. It shows as loading until it is ' +
                     'active, or refused with its reason.' } });
          log.debug("Leaving onBegun().");
        },
        onProgress: function (): void {
          log.debug("Entering onProgress().");
          const at = Date.now();
          if (at - lastTouch > 5000) {
            lastTouch = at;
            fs.promises.utimes(target, at / 1000, at / 1000)
              .catch(function (e: Json): void {
                log.debug("Caught touching an upload: " +
                          ((e && e.message) || e));
                // The per-process job touches it as well; one missed
                // touch is not a lost file.
              });
          }
          log.debug("Leaving onProgress().");
        }
      })).then(function (result: Json): void {
        log.debug("Entering the upload's import outcome.");
        if (!result || !result.ok) {
          answer({ status: 400,
                   code: errorCodes.codeOf(result) || 'STS-RISK-0001',
                   body: result || { ok: false, errors: ['refused'] } });
        } else {
          answer({ status: 200, code: '', body: result });
        }
        log.debug("Leaving the upload's import outcome.");
      }, function (e: Json): void {
        log.error(errorCodes.tag('STS-RISK-0037') + 'risk: an uploaded ' +
                  f.dataset + ' failed to import: ' +
                  ((e && e.stack) || e));
        answer(RiskUpload.refusal(500, 'STS-RISK-0037', 'The import failed: ' +
          ((e && e.message) || e) + '.'));
      }).then(function (): Promise<void> {
        return self.release(target);
      });
    });
  }

  // A file this process is done with: forgotten and deleted.
  private release(target: string): Promise<void> {
    const { log } = this.deps;
    const held = this.held;
    log.debug("Entering RiskUpload.release().");
    log.debug("Leaving RiskUpload.release().");
    return fs.promises.rm(target, { force: true }).then(function (): void {
      held.delete(target);
    }, function (e: Json): void {
      log.warn(errorCodes.tag('STS-RISK-0036') + 'risk: an uploaded file ' +
               'could not be deleted after its import (' +
               ((e && e.message) || e) + '); the ' + CLEANUP_JOB + ' job ' +
               'will remove it.');
      held.delete(target);
    });
  }

  // -------------------------------------------------------------------------
  // THE API DOOR: the body is the file, the query the fields.
  // -------------------------------------------------------------------------
  async receiveRaw(req: Json, door: UploadDoor): Promise<UploadAnswer> {
    const { log } = this.deps;
    log.debug("Entering RiskUpload.receiveRaw().");
    const type = String(req.headers['content-type'] || '').split(';')[0]
      .trim().toLowerCase();
    if (API_TYPES.indexOf(type) < 0) {
      log.debug("Leaving RiskUpload.receiveRaw(). Content type.");
      return RiskUpload.refusal(415, 'STS-RISK-0031', 'An upload\'s body is ' +
        'the file, sent as one of ' + API_TYPES.join(', ') + ' — not "' +
        (type || 'nothing') + '". Whether it is gzip, zip or plain text is ' +
        'read from its first bytes. Nothing was stored.', true);
    }
    const q = req.query || {};
    const unknown = Object.keys(q).filter(function (k: string): boolean {
      return FIELDS.indexOf(k) < 0;
    });
    const repeated = Object.keys(q).filter(function (k: string): boolean {
      return typeof q[k] !== 'string';
    });
    if (unknown.length || repeated.length) {
      log.debug("Leaving RiskUpload.receiveRaw(). Parameters.");
      return RiskUpload.refusal(400, 'STS-RISK-0031', (unknown.length
        ? 'Unknown parameter(s): ' + unknown.join(', ') + '.'
        : 'Each parameter is given once: ' + repeated.join(', ') + '.') +
        ' An upload takes ' + FIELDS.join(', ') + '. Nothing was stored.',
        true);
    }
    const early = await this.before(req);
    if (early) {
      log.debug("Leaving RiskUpload.receiveRaw(). Before the body.");
      return early;
    }
    const target = this.newTarget();
    const fieldsWrong = await this.fieldsRefusal(q, door, target);
    if (fieldsWrong) {
      log.debug("Leaving RiskUpload.receiveRaw(). Fields.");
      return fieldsWrong;
    }
    this.held.add(target);
    const stored = await this.store(req, target, function (): boolean {
      return false;
    });
    if (!stored.ok) {
      this.held.delete(target);
      log.debug("Leaving RiskUpload.receiveRaw(). Not stored.");
      return stored;
    }
    if (!stored.bytes) {
      await this.release(target);
      log.debug("Leaving RiskUpload.receiveRaw(). Empty.");
      return RiskUpload.refusal(400, 'STS-RISK-0031', 'The upload is empty. ' +
                                'Nothing was stored.');
    }
    const answer = await this.importStored(target, stored, q, door);
    log.debug("Leaving RiskUpload.receiveRaw(). " + answer.status);
    return answer;
  }

  // -------------------------------------------------------------------------
  // THE CONSOLE DOOR: multipart/form-data, the fields first and then the
  // one file. The CSRF token and every field are read before the file part,
  // and checked when it begins; a field after the file, a second file, or
  // no file at all is refused.
  // -------------------------------------------------------------------------
  async receiveForm(req: Json, door: UploadDoor): Promise<UploadAnswer> {
    const { log, config } = this.deps;
    const self = this;
    log.debug("Entering RiskUpload.receiveForm().");
    if (!/^multipart\/form-data/i.test(String(req.headers['content-type'] ||
                                              ''))) {
      log.debug("Leaving RiskUpload.receiveForm(). Content type.");
      return RiskUpload.refusal(415, 'STS-RISK-0031', 'The upload form is ' +
        'sent as multipart/form-data. Nothing was stored.', true);
    }
    const early = await this.before(req);
    if (early) {
      log.debug("Leaving RiskUpload.receiveForm(). Before the body.");
      return early;
    }
    const max = Number(config.value('risk.uploadMaxBytes'));
    let parser: Json;
    try {
      parser = busboy({ headers: req.headers,
                        limits: { files: 1, fields: MAX_FIELDS,
                                  fieldSize: MAX_FIELD_BYTES,
                                  parts: MAX_PARTS, fileSize: max } });
    } catch (e) {
      log.debug("Caught in RiskUpload.receiveForm(): " +
                ((e && e.message) || e));
      // busboy refuses a content type with no boundary at construction.
      log.debug("Leaving RiskUpload.receiveForm(). Not multipart.");
      return RiskUpload.refusal(400, 'STS-RISK-0031', 'The upload is not ' +
        'a multipart body this service can read: ' + ((e && e.message) || e) +
        '. Nothing was stored.', true);
    }
    const fields: Json = {};
    let target = '';
    let fileSeen = false;
    let stored: Promise<Json> | null = null;
    log.debug("Leaving RiskUpload.receiveForm(). Reading.");
    return new Promise<UploadAnswer>(function (resolve) {
      let done = false;
      const finish = function (a: UploadAnswer): void {
        log.debug("Entering finish(). " + a.status);
        if (!done) {
          done = true;
          if (a.status >= 400) {
            // Left to drain rather than destroyed: the refusal is still to
            // be written to this socket, and the route closes it after.
            req.unpipe(parser);
            req.resume();
            if (target) {
              self.held.delete(target);
              fs.promises.rm(target, { force: true }).catch(function (e: Json) {
                log.debug("Caught removing a refused upload: " +
                          ((e && e.message) || e));
                // The clean-up job removes what is left.
              });
            }
          }
          resolve(a);
        }
        log.debug("Leaving finish().");
      };
      const refuse = function (status: number, code: string,
                               why: string): void {
        log.debug("Entering refuse(). " + code);
        finish(RiskUpload.refusal(status, code, why, true));
        log.debug("Leaving refuse().");
      };
      // THE IMPORT BEGINS WHEN BOTH HAVE HAPPENED: the form is parsed to its
      // end (a field after the file would have been refused by then) and
      // the file is stored. busboy can finish parsing a small form while
      // the file's stream still holds its bytes unread — the fields are
      // still being checked — so either may come second.
      let parsed = false;
      let proceeding = false;
      const proceed = function (): void {
        log.debug("Entering proceed().");
        if (done || proceeding || !parsed || !stored) {
          log.debug("Leaving proceed(). Not yet.");
          return;
        }
        proceeding = true;
        stored.then(function (s: Json): Promise<UploadAnswer> | null {
          if (!s.ok || done) {
            return null;
          }
          if (!s.bytes) {
            return self.release(target).then(function (): UploadAnswer {
              return RiskUpload.refusal(400, 'STS-RISK-0031', 'The file is ' +
                                        'empty. Nothing was stored.');
            });
          }
          return self.importStored(target, s, fields, door);
        }).then(function (a: UploadAnswer | null): void {
          if (a) {
            finish(a);
          }
        });
        log.debug("Leaving proceed().");
      };
      // A FIELD AFTER THE FILE is refused — but only once the fields that
      // came before it have been checked, so a form that fails the CSRF
      // check is refused as that whatever else is wrong with it.
      let lateField = '';
      const refuseLate = function (): void {
        log.debug("Entering refuseLate(). " + lateField);
        refuse(400, 'STS-RISK-0031', 'The field "' + lateField + '" came ' +
               'after the file. Every field of the upload form goes before ' +
               'it — the order the console\'s form sends them in. Nothing ' +
               'was stored.');
        log.debug("Leaving refuseLate().");
      };
      parser.on('field', function (name: string, value: string): void {
        if (fileSeen) {
          lateField = lateField || name;
          if (stored) {
            refuseLate();
          }
          return;
        }
        fields[name] = value;
      });
      parser.on('file', function (name: string, file: stream.Readable): void {
        if (fileSeen || done) {
          file.resume();
          refuse(400, 'STS-RISK-0031', 'An upload carries one file. ' +
                 'Nothing was stored.');
          return;
        }
        fileSeen = true;
        // Not read until the fields have been checked: busboy stops reading
        // the request while this stream is not consumed.
        file.pause();
        target = self.newTarget();
        self.fieldsRefusal(fields, door, target).then(function (wrong: Json) {
          if (wrong) {
            file.resume();
            finish(wrong);
            return;
          }
          if (done) {
            file.resume();
            return;
          }
          if (lateField) {
            file.resume();
            refuseLate();
            return;
          }
          self.held.add(target);
          stored = self.store(file, target, function (): boolean {
            return !!(file as Json).truncated;
          });
          stored.then(function (s: Json): void {
            if (!s.ok) {
              finish(s);
            }
          });
          proceed();
        }, function (e: Json): void {
          log.error(errorCodes.tag('STS-RISK-0037') + 'risk: an upload\'s ' +
                    'fields could not be checked: ' + ((e && e.stack) || e));
          file.resume();
          finish(RiskUpload.refusal(500, 'STS-RISK-0037', 'The upload ' +
            'could not be checked: ' + ((e && e.message) || e) + '.', true));
        });
      });
      parser.on('filesLimit', function (): void {
        refuse(400, 'STS-RISK-0031', 'An upload carries one file. Nothing ' +
               'was stored.');
      });
      parser.on('fieldsLimit', function (): void {
        refuse(400, 'STS-RISK-0031', 'The upload form carries at most ' +
               MAX_FIELDS + ' fields. Nothing was stored.');
      });
      parser.on('partsLimit', function (): void {
        refuse(400, 'STS-RISK-0031', 'The upload form carries at most ' +
               MAX_PARTS + ' parts. Nothing was stored.');
      });
      parser.on('error', function (e: Json): void {
        refuse(400, 'STS-RISK-0031', 'The upload is not a multipart body ' +
               'this service can read: ' + ((e && e.message) || e) +
               '. Nothing was stored.');
      });
      parser.on('close', function (): void {
        log.debug("Entering the upload form's close.");
        parsed = true;
        if (!done && !fileSeen) {
          // No file at all: the fields are still checked, so a forged
          // form is refused as one rather than as an empty upload.
          self.fieldsRefusal(fields, door, 'unwritten').then(
            function (wrong: Json): void {
              finish(wrong || RiskUpload.refusal(400, 'STS-RISK-0031',
                'The upload carried no file. Choose one, then press ' +
                'Upload. Nothing was stored.'));
            }, function (e: Json): void {
              log.debug("Caught checking a form with no file: " +
                        ((e && e.message) || e));
              finish(RiskUpload.refusal(400, 'STS-RISK-0031', 'The ' +
                'upload carried no file. Nothing was stored.'));
            });
          log.debug("Leaving the upload form's close. No file.");
          return;
        }
        proceed();
        log.debug("Leaving the upload form's close.");
      });
      req.on('aborted', function (): void {
        refuse(400, 'STS-RISK-0031', 'The upload ended before its body ' +
               'did. Nothing was stored.');
      });
      req.pipe(parser);
    });
  }

  // -------------------------------------------------------------------------
  // THE PER-PROCESS CLEAN-UP (rule 5): every file this process holds is
  // touched, a file of this process's that it no longer holds is removed
  // (what a refusal's own removal missed), and another process's file
  // nobody has touched for `risk.importStallMinutes` — a process that
  // stopped — is removed. A file whose name is not an upload's is never
  // touched: the directory may be a volume an operator also uses.
  // -------------------------------------------------------------------------
  async sweep(): Promise<Json> {
    const { log, config, now } = this.deps;
    log.debug("Entering RiskUpload.sweep().");
    const dir = this.directory();
    const out = { held: 0, removed: 0 };
    let names: string[] = [];
    try {
      names = await fs.promises.readdir(dir);
    } catch (e) {
      log.debug("Caught in RiskUpload.sweep(): " + ((e && e.message) || e));
      // No directory yet: nothing was ever uploaded here.
      log.debug("Leaving RiskUpload.sweep(). No directory.");
      return out;
    }
    const at = now();
    const stallMs = Number(config.value('risk.importStallMinutes')) * 60000;
    for (const name of names) {
      const m = FILE_NAME.exec(name);
      if (!m) {
        continue;
      }
      const file = path.join(dir, name);
      if (this.held.has(file)) {
        out.held += 1;
        await fs.promises.utimes(file, at / 1000, at / 1000)
          .catch(function (e: Json): void {
            log.debug("Caught touching a held upload: " +
                      ((e && e.message) || e));
            // Touched again at the next run; a file an import is reading
            // is not removed by its own process in any case.
          });
        continue;
      }
      let old = m[1] === PROCESS_TAG;
      if (!old) {
        const st = await fs.promises.stat(file).catch(function (e: Json) {
          log.debug("Caught reading an upload's age: " +
                    ((e && e.message) || e));
          // Gone already — another process's sweep, or its own import.
          return null;
        });
        old = !!st && at - st.mtimeMs > stallMs;
      }
      if (old) {
        const removed = await fs.promises.rm(file, { force: true })
          .then(function (): boolean {
            return true;
          }, function (e: Json): boolean {
            log.warn(errorCodes.tag('STS-RISK-0036') + 'risk: a leftover ' +
                     'upload ' + name + ' could not be removed: ' +
                     ((e && e.message) || e));
            return false;
          });
        if (removed) {
          out.removed += 1;
          log.warn(errorCodes.tag('STS-RISK-0036') + 'risk: removed the ' +
                   'leftover upload ' + name + ', which ' +
                   (m[1] === PROCESS_TAG ? 'this process no longer holds'
                                          : 'no live process has touched ' +
                                            'for risk.importStallMinutes') +
                   '.');
        }
      }
    }
    log.debug("Leaving RiskUpload.sweep(). " + out.removed + " removed.");
    return out;
  }

  // The per-process job, registered in every process when the instance is
  // wired, as the scheduler asks.
  registerJobs(): boolean {
    const { log, scheduler } = this.deps;
    log.debug("Entering RiskUpload.registerJobs().");
    const s = scheduler();
    if (!s || typeof s.register !== 'function' || s.job(CLEANUP_JOB)) {
      log.debug("Leaving RiskUpload.registerJobs(). Nothing to do.");
      return false;
    }
    const self = this;
    s.register({
      id: CLEANUP_JOB,
      title: 'Risk upload clean-up',
      describe: 'In every process: keeps the dataset uploads this process ' +
                'is importing fresh, and deletes from risk.uploadDirectory ' +
                'an upload no live process has touched for ' +
                'risk.importStallMinutes — what a process that stopped ' +
                'mid-import left behind.',
      owner: 'risk/risk_upload.ts',
      kind: 'per-process', quiet: true,
      everySetting: 'risk.uploadSweepS', everySettingUnit: 's',
      manual: true,
      run: function (): Promise<Json> {
        return self.sweep();
      }
    });
    log.debug("Leaving RiskUpload.registerJobs().");
    return true;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) at 18j, after the
// datasets it hands files to. Wiring it registers the clean-up job.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<RiskUpload>(
  'risk/risk_upload',
  () => new RiskUpload(RiskUpload.defaultDeps()),
  function (instance: RiskUpload): void {
    instance.registerJobs();
  },
  log);

slot.buildNowUnlessDeferred();

export = {
  RiskUpload: RiskUpload,
  installInstance: (instance: RiskUpload): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  FIELDS: RiskUpload.FIELDS,
  API_TYPES: RiskUpload.API_TYPES,
  CLEANUP_JOB: RiskUpload.CLEANUP_JOB,
  PROCESS_TAG: RiskUpload.PROCESS_TAG,
  directory: slot.forward('directory'),
  receiveRaw: slot.forward('receiveRaw'),
  receiveForm: slot.forward('receiveForm'),
  sweep: slot.forward('sweep'),
  registerJobs: slot.forward('registerJobs')
};
