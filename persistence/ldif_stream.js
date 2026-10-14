// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: persistence/ldif_stream.js
//
// ===========================================================================
// AN LDIF FILE READ ONE RECORD AT A TIME (#629, 2026-10-14).
//
// `persistence_ldif.fromLdif()` is this service's RFC 2849 reader and takes
// a whole document as one string, which is right for a realm's file and
// wrong for the bulk import's: forty million people are about four hundred
// million lines, and a string that long does not exist in V8. So this reads
// the file as a stream of lines, cuts it into RECORDS at the blank lines
// that separate them (RFC 2849 section 2: `1*SEP` between records), and
// hands each record's text to `fromLdif()` — the same unfolding, the same
// `::` base64, the same comments — so there is still one LDIF reader here,
// asked once per record instead of once per file.
//
// A record carries its ORDINAL (1 for the first record with a `dn:`, the
// `version: 1` line and any comment-only block before it are not records)
// and the LINE it starts on, which is what the import reports and what
// `--skip` counts in. A record holding a `:<` URL value is marked: the
// codec drops such a line with one warning, and the import refuses the
// record instead, so a value is never silently missing.
// ===========================================================================

const fs = require('fs');
const readline = require('readline');

const log = require('bunyan').createLogger({
  name: 'sts-ldif-stream',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info' });

// A logger with nothing to say, for `fromLdif()`'s per-record calls: its
// warning about a URL line is the import's refusal here, said once there.
const QUIET = {
  debug: function () {},
  info: function () {},
  warn: function () {},
  error: function () {}
};

// A record's lines become text and are parsed. A HOT PATH — once per record,
// fifty million times in a load — so no Entering/Leaving pair, which would
// drown the log.
function parseRecord(lines) {
  const text = lines.join('\n');
  const entries = require('./persistence_ldif').fromLdif(text, QUIET);
  return entries.length ? entries : [];
}

// Whether a line of a record is a `name:< url` value. A continuation line
// (one leading space) is not, and neither is a comment. A HOT PATH: once per
// line, so no Entering/Leaving pair.
function isUrlLine(line) {
  if (!line || line.charAt(0) === ' ' || line.charAt(0) === '#') {
    return false;
  }
  const colon = line.indexOf(':');
  return colon > 0 && line.charAt(colon + 1) === '<';
}

/**
 * Reads an LDIF file record by record, without holding it.
 *
 * Each record is `{ ordinal, line, entry, url, extra }`: `entry` is
 * `fromLdif()`'s `{ dn, attributes }` (attribute names lower-cased, values
 * arrays of strings), `url` is true where a line was a `:<` URL value, and
 * `extra` is true where the block held more than one `dn:` (a missing blank
 * line), which the import refuses rather than guessing.
 *
 * @param file - the path of the LDIF file
 * @returns an async iterator of records
 */
async function* records(file) {
  log.debug("Entering records(). " + file);
  const input = fs.createReadStream(file, { encoding: 'utf8',
                                            highWaterMark: 1 << 20 });
  const lines = readline.createInterface({ input: input,
                                           crlfDelay: Infinity });
  let block = [];
  let blockLine = 0;
  let lineNo = 0;
  let ordinal = 0;
  let url = false;
  const finish = function () {
    const entries = block.length ? parseRecord(block) : [];
    const out = entries.length
      ? { ordinal: ordinal + 1, line: blockLine, entry: entries[0],
          url: url, extra: entries.length > 1 }
      : null;
    if (out) {
      ordinal += 1;
    }
    block = [];
    url = false;
    return out;
  };
  try {
    for await (const line of lines) {
      lineNo += 1;
      if (line === '' || line === '\r') {
        const done = finish();
        if (done) {
          yield done;
        }
        continue;
      }
      if (!block.length) {
        blockLine = lineNo;
      }
      if (isUrlLine(line)) {
        url = true;
      }
      block.push(line);
    }
    const last = finish();
    if (last) {
      yield last;
    }
  } finally {
    lines.close();
    input.destroy();
  }
  log.debug("Leaving records(). " + ordinal + " record(s).");
}

/**
 * Streaming LDIF records over the service's own RFC 2849 codec (#629).
 * @namespace
 */
module.exports = {
  records: records,
  isUrlLine: isUrlLine
};
