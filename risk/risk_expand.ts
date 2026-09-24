'use strict';
//
// File: risk/risk_expand.ts
//
// ===========================================================================
// A DATASET FILE, EXPANDED BY WHAT IT IS AND NOT BY WHAT IT IS CALLED (#215,
// 2026-09-24).
//
// Providers publish their datasets compressed — DB-IP Lite as `.csv.gz`, and
// an operator's own export is as likely to be a `.zip` — and a city file is
// several hundred megabytes expanded. This is the ONE place a dataset file
// is expanded, whichever door it came through: an upload on Monitoring →
// Risk or `POST /admin-api/risk/upload` (`risk_upload.ts`), a file in
// `risk.datasetsDirectory`, and the install-time loader (`risk_install.ts`),
// which used to gunzip a `.gz` address itself on the way to disk. All three
// hand `risk_datasets.ts`'s `importVersion()` a PATH, and its line reader
// asks this file for the bytes.
//
// FOUR RULES, each of which is a refusal somebody would otherwise meet in
// the wrong place:
//
//   1. **BY CONTENT.** gzip by its magic bytes (1f 8b, RFC 1952 section
//      2.3.1), zip by its local-header signature (`PK\x03\x04`, or the
//      end-of-central-directory record of an empty archive), plain text
//      otherwise. A name is what somebody typed; `datasets.csv` that is a
//      gzip stream is expanded, and `list.gz` that is text is read as text.
//   2. **STREAMED, NEVER WRITTEN.** The expansion is a stream handed to the
//      line reader. No expanded copy is written to disk, so the disk an
//      upload needs is the size of the upload.
//   3. **A ZIP HOLDS ONE DATA ENTRY OR IS REFUSED AS AMBIGUOUS**
//      (STS-RISK-0033). Directories are not data, and neither is macOS's
//      `__MACOSX/` resource-fork tree, which Finder's *Compress* adds to
//      every archive it makes — refusing those would refuse most archives an
//      operator on a Mac could make. An encrypted entry, or one compressed
//      with anything but stored or deflate, is refused too: yauzl reads
//      neither, and a refusal that names the reason beats a garbled line.
//   4. **A DECOMPRESSION BOMB IS REFUSED WHILE IT IS STILL SMALL**
//      (STS-RISK-0032). The expanded bytes are counted as they are produced
//      and stop at the ALLOWANCE: `risk.expansionMaxRatio` times the file's
//      size, but never less than RATIO_FLOOR_BYTES (a list of a few hundred
//      bytes compresses far better than any ratio a real dataset shows, and
//      refusing it would be the check being wrong), and never more than
//      `risk.expandedMaxBytes`. A zip entry's declared size is held to the
//      same allowance before a byte of it is read, and yauzl holds the entry
//      to its declared size as it reads.
//
// A corrupt stream — a truncated gzip, a zip whose central directory does
// not parse — is STS-RISK-0034. Every error this raises carries its code
// (`errorCodes.codeOf()`), which `importVersion()` records on the refused
// version.
//
// A UTILITY CLASS OF STATIC METHODS (#50's rule for a small helper): it holds
// no state, needs no instance, and its limits arrive as an argument, so no
// composition-root slot is needed and nothing about the require order
// changes.
// ===========================================================================

import bunyan = require('bunyan');
import fs = require('fs');
import stream = require('stream');
import zlib = require('zlib');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');

// yauzl (MIT) reads a zip's central directory and streams one entry. It
// ships no declarations, so it is `any` here.
const yauzl: any = require('yauzl');

const log = bunyan.createLogger({ name: 'sts-risk-expand' });
config.registerLogger(log);

type Json = any;

// Below this many expanded bytes the ratio is not asked (rule 4).
const RATIO_FLOOR_BYTES = 16 * 1024 * 1024;

// What is expanded, and how much it may become.
interface ExpandLimits {
  // `risk.expandedMaxBytes`: the most any file may expand to.
  maxBytes: number;
  // `risk.expansionMaxRatio`: the most it may expand to per byte stored.
  maxRatio: number;
}

// An opened file: its kind, the bytes to read (expanded where it was
// compressed), and `close()`, which must be called however reading ends.
interface Opened {
  kind: 'gzip' | 'zip' | 'plain';
  entry: string;
  stream: stream.Readable;
  close(): void;
}

class RiskExpand {
  static readonly RATIO_FLOOR_BYTES = RATIO_FLOOR_BYTES;

  // The limits as the settings say now, for the callers that have no
  // reason to choose their own.
  static limits(): ExpandLimits {
    log.debug("Entering RiskExpand.limits().");
    log.debug("Leaving RiskExpand.limits().");
    return {
      maxBytes: Number(config.value('risk.expandedMaxBytes')),
      maxRatio: Number(config.value('risk.expansionMaxRatio'))
    };
  }

  // Rule 1: what the first bytes say the file is.
  static sniff(head: Buffer): 'gzip' | 'zip' | 'plain' {
    log.debug("Entering RiskExpand.sniff().");
    const b = head || Buffer.alloc(0);
    let kind: 'gzip' | 'zip' | 'plain' = 'plain';
    if (b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b) {
      kind = 'gzip';
    } else if (b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b &&
               ((b[2] === 0x03 && b[3] === 0x04) ||
                (b[2] === 0x05 && b[3] === 0x06))) {
      kind = 'zip';
    }
    log.debug("Leaving RiskExpand.sniff(). " + kind);
    return kind;
  }

  // The first bytes of a file, for sniff().
  static headOf(file: string): Buffer {
    log.debug("Entering RiskExpand.headOf().");
    const fd = fs.openSync(file, 'r');
    try {
      const head = Buffer.alloc(4);
      const read = fs.readSync(fd, head, 0, 4, 0);
      log.debug("Leaving RiskExpand.headOf().");
      return head.subarray(0, read);
    } finally {
      fs.closeSync(fd);
    }
  }

  // Rule 4's allowance for a file of `stored` bytes.
  static allowance(stored: number, limits: ExpandLimits): number {
    log.debug("Entering RiskExpand.allowance().");
    const byRatio = Math.max(RATIO_FLOOR_BYTES,
                             Math.max(0, Number(stored) || 0) *
                             Math.max(1, Number(limits.maxRatio) || 1));
    log.debug("Leaving RiskExpand.allowance().");
    return Math.min(Math.max(0, Number(limits.maxBytes) || 0), byRatio);
  }

  // The refusal of a bomb, coded.
  private static bomb(expanded: number, stored: number,
                      limits: ExpandLimits): Error {
    log.debug("Entering RiskExpand.bomb().");
    log.debug("Leaving RiskExpand.bomb().");
    return errorCodes.mark(new Error('the file expands past what it may: ' +
      'more than ' + expanded + ' bytes from ' + stored + ' stored, where ' +
      'the most allowed is ' + RiskExpand.allowance(stored, limits) +
      ' (risk.expandedMaxBytes ' + limits.maxBytes + ', ' +
      'risk.expansionMaxRatio ' + limits.maxRatio + ' to 1). A dataset does ' +
      'not compress like that; a decompression bomb does. Nothing of it ' +
      'is kept.'), 'STS-RISK-0032');
  }

  // A pass-through that counts what the expansion produced and fails the
  // stream at the allowance (rule 4).
  private static counter(stored: number,
                         limits: ExpandLimits): stream.Transform {
    log.debug("Entering RiskExpand.counter().");
    const most = RiskExpand.allowance(stored, limits);
    let seen = 0;
    log.debug("Leaving RiskExpand.counter().");
    return new stream.Transform({
      // One call per chunk of the expansion — a hot path, so no
      // Entering/Leaving pair.
      transform: function (chunk: Buffer, encoding: string,
                           done: (e?: Error | null, c?: Buffer) => void) {
        seen += chunk.length;
        if (seen > most) {
          done(RiskExpand.bomb(seen, stored, limits));
          return;
        }
        done(null, chunk);
      }
    });
  }

  // A corrupt stream, coded (STS-RISK-0034) unless it already carries a
  // code of its own (a bomb, an ambiguous archive).
  private static corrupt(kind: string, e: Json): Error {
    log.debug("Entering RiskExpand.corrupt().");
    if (e && errorCodes.codeOf(e)) {
      log.debug("Leaving RiskExpand.corrupt(). Already coded.");
      return e;
    }
    log.debug("Leaving RiskExpand.corrupt().");
    return errorCodes.mark(new Error('the ' + kind + ' file could not be ' +
      'expanded: ' + ((e && e.message) || e) + '. Nothing of it is kept.'),
      'STS-RISK-0034');
  }

  // -------------------------------------------------------------------------
  // OPEN A FILE FOR READING, expanded if it is compressed. The stream fails
  // with a coded error on a bomb or a corrupt file; `close()` releases the
  // file (and the archive) however reading ended, and is safe to call twice.
  // -------------------------------------------------------------------------
  static async open(file: string, given?: ExpandLimits): Promise<Opened> {
    log.debug("Entering RiskExpand.open().");
    const limits = given || RiskExpand.limits();
    const kind = RiskExpand.sniff(RiskExpand.headOf(file));
    const stored = fs.statSync(file).size;
    if (kind === 'plain') {
      const plain = fs.createReadStream(file);
      log.debug("Leaving RiskExpand.open(). Plain.");
      return { kind: kind, entry: '', stream: plain,
               close: function (): void {
                 log.debug("Entering close(). plain");
                 plain.destroy();
                 log.debug("Leaving close().");
               } };
    }
    if (kind === 'gzip') {
      const raw = fs.createReadStream(file);
      const gunzip = zlib.createGunzip();
      const counted = RiskExpand.counter(stored, limits);
      const coded = new stream.PassThrough();
      // Whichever stage fails, the reader sees one coded refusal on the
      // stream it reads.
      const fail = function (e: Json): void {
        log.debug("Entering fail(). gzip");
        coded.destroy(RiskExpand.corrupt('gzip', e));
        log.debug("Leaving fail().");
      };
      raw.on('error', fail);
      gunzip.on('error', fail);
      counted.on('error', fail);
      raw.pipe(gunzip).pipe(counted).pipe(coded);
      log.debug("Leaving RiskExpand.open(). gzip.");
      return { kind: kind, entry: '', stream: coded,
               close: function (): void {
                 log.debug("Entering close(). gzip");
                 raw.destroy();
                 gunzip.destroy();
                 coded.destroy();
                 log.debug("Leaving close().");
               } };
    }
    const opened = await RiskExpand.openZip(file, stored, limits);
    log.debug("Leaving RiskExpand.open(). zip.");
    return opened;
  }

  // Rule 3: the one data entry of a zip, streamed.
  private static openZip(file: string, stored: number,
                         limits: ExpandLimits): Promise<Opened> {
    log.debug("Entering RiskExpand.openZip().");
    log.debug("Leaving RiskExpand.openZip().");
    return new Promise(function (resolve, reject) {
      yauzl.open(file, { lazyEntries: true, autoClose: false,
                         validateEntrySizes: true },
                 function (e: Json, zip: Json): void {
        if (e || !zip) {
          reject(RiskExpand.corrupt('zip', e || 'no archive'));
          return;
        }
        const data: Json[] = [];
        let skipped = 0;
        zip.on('error', function (err: Json): void {
          zip.close();
          reject(RiskExpand.corrupt('zip', err));
        });
        zip.on('entry', function (entry: Json): void {
          const name = String(entry.fileName || '');
          if (/\/$/.test(name) || /^__MACOSX\//.test(name)) {
            skipped += 1;
          } else {
            data.push(entry);
          }
          zip.readEntry();
        });
        zip.on('end', function (): void {
          const refuse = function (why: string, code: string): void {
            log.debug("Entering refuse(). " + code);
            zip.close();
            reject(errorCodes.mark(new Error(why), code));
            log.debug("Leaving refuse().");
          };
          if (data.length !== 1) {
            refuse('the zip archive holds ' + data.length + ' data ' +
                   'entr' + (data.length === 1 ? 'y' : 'ies') +
                   (data.length ? ' (' + data.slice(0, 5).map(
                     function (one: Json): string {
                       return String(one.fileName);
                     }).join(', ') + (data.length > 5 ? ', …' : '') + ')'
                                : '') +
                   (skipped ? ' beside ' + skipped + ' director' +
                              (skipped === 1 ? 'y' : 'ies') +
                              ' or __MACOSX entr' +
                              (skipped === 1 ? 'y' : 'ies') : '') +
                   ', and a dataset upload must hold exactly one: which ' +
                   'one is meant would be a guess. Zip the one file.',
                   'STS-RISK-0033');
            return;
          }
          const entry = data[0];
          if (entry.isEncrypted && entry.isEncrypted()) {
            refuse('the zip entry ' + entry.fileName + ' is encrypted, ' +
                   'and an encrypted entry cannot be read here.',
                   'STS-RISK-0033');
            return;
          }
          if (entry.compressionMethod !== 0 &&
              entry.compressionMethod !== 8) {
            refuse('the zip entry ' + entry.fileName + ' is compressed ' +
                   'with method ' + entry.compressionMethod + '; only ' +
                   'stored (0) and deflate (8) are read.', 'STS-RISK-0033');
            return;
          }
          if (Number(entry.uncompressedSize) >
              RiskExpand.allowance(stored, limits)) {
            zip.close();
            reject(RiskExpand.bomb(Number(entry.uncompressedSize), stored,
                                   limits));
            return;
          }
          zip.openReadStream(entry, function (err: Json,
                                              raw: stream.Readable): void {
            if (err || !raw) {
              zip.close();
              reject(RiskExpand.corrupt('zip', err || 'no entry stream'));
              return;
            }
            const coded = new stream.PassThrough();
            const counted = RiskExpand.counter(stored, limits);
            const fail = function (x: Json): void {
              log.debug("Entering fail(). zip");
              coded.destroy(RiskExpand.corrupt('zip', x));
              log.debug("Leaving fail().");
            };
            raw.on('error', fail);
            counted.on('error', fail);
            raw.pipe(counted).pipe(coded);
            resolve({ kind: 'zip', entry: String(entry.fileName),
                      stream: coded,
                      close: function (): void {
                        log.debug("Entering close(). zip");
                        raw.destroy();
                        coded.destroy();
                        zip.close();
                        log.debug("Leaving close().");
                      } });
          });
        });
        zip.readEntry();
      });
    });
  }

  // -------------------------------------------------------------------------
  // A WHOLE FILE AS TEXT, expanded — the FIDO MDS3 BLOB, which is one signed
  // document rather than lines. `maxChars` bounds what is held (the BLOB's
  // own cap, `risk.mdsMaxBytes`); past it the read is refused.
  // -------------------------------------------------------------------------
  static async readText(file: string, maxChars: number,
                        given?: ExpandLimits): Promise<string> {
    log.debug("Entering RiskExpand.readText().");
    const opened = await RiskExpand.open(file, given);
    const chunks: Buffer[] = [];
    let size = 0;
    try {
      for await (const chunk of opened.stream) {
        size += chunk.length;
        if (maxChars > 0 && size > maxChars) {
          throw errorCodes.mark(new Error('the file is larger than the ' +
            maxChars + ' bytes a document of this kind may be.'),
            'STS-RISK-0032');
        }
        chunks.push(Buffer.from(chunk));
      }
    } finally {
      opened.close();
    }
    log.debug("Leaving RiskExpand.readText(). " + size + " byte(s).");
    return Buffer.concat(chunks).toString('utf8');
  }
}

export = RiskExpand;
