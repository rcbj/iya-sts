// ===========================================================================
// zip_writer.js — A ZIP ARCHIVE, BUILT BY THIS SUITE'S OWN CODE (#215).
//
// For the dataset upload's tests — `tests/risk_upload.js` in process and
// `sts_admin_risk_upload.js` over HTTP — which need a zip of one file, of
// several, with a directory and a `__MACOSX/` entry beside the one that is
// data, and one whose declared size is a lie. The service reads zips with
// yauzl; a test that made its archives with the same library's sibling would
// be the reader agreeing with its own family, so this is written from the
// format (PKWARE APPNOTE 6.3.x, sections 4.3.7, 4.3.12 and 4.3.16) on node's
// zlib: a local header and data per entry, a central directory, and the
// end-of-central-directory record. Stored (0) or deflate (8); no ZIP64, no
// encryption, no data descriptor.
//
// NOTHING IS WRITTEN TO THE REPOSITORY. Every archive is built in memory at
// run time from synthetic lines (`tests/no_third_party_datasets.js` fails on
// a `.zip` in the tree).
// ===========================================================================

'use strict';

const zlib = require('zlib');

const log = require('bunyan').createLogger({ name: 'zip_writer',
  level: process.env.LOG_LEVEL || 'info' });

// One archive from `entries`: `[{ name, data (Buffer or string), method?
// (8 by default, 0 for stored), declaredSize? (to lie about the expanded
// size) }]`. A name ending in `/` is a directory entry.
function makeZip(entries) {
  log.debug("Entering makeZip().");
  const locals = [];
  const centrals = [];
  let offset = 0;
  entries.forEach(function (e) {
    const name = Buffer.from(String(e.name), 'utf8');
    const data = Buffer.isBuffer(e.data) ? e.data
      : Buffer.from(String(e.data || ''), 'utf8');
    const method = e.method === 0 || /\/$/.test(e.name) ? 0 : 8;
    const body = method === 8 ? zlib.deflateRawSync(data) : data;
    const crc = zlib.crc32(data) >>> 0;
    const size = e.declaredSize === undefined ? data.length : e.declaredSize;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0x21, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(size, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, name, body);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0x21, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(size, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(/\/$/.test(e.name) ? 0x10 : 0, 38);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);
    offset += local.length + name.length + body.length;
  });
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  log.debug("Leaving makeZip().");
  return Buffer.concat(locals.concat([directory, end]));
}

module.exports = { makeZip: makeZip };
