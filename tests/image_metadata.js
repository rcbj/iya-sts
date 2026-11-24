// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: image_metadata.js
//
// ===========================================================================
// AN IMAGE THIS SERVICE PUBLISHES, WITHOUT ITS METADATA (#2140, ASVS 5.0.0
// 14.2.8): `common/image_metadata.ts`, and the sign-in logo through it.
//
// The three images below are real files (made with an image library, 24 by
// 16 pixels, a gradient), each carrying what a phone or an editor writes: the
// JPEG an EXIF block with a GPS position and a camera name, the PNG two tEXt
// chunks (an author and a position), the WebP an EXIF and an XMP chunk.
// Asserted here:
//
//   A. THE JPEG loses its EXIF (APP1) and nothing else: the result is the
//      file with that one segment cut out, byte for byte, so the tables, the
//      frame and the scan a decoder reads are the ones it had; its sides are
//      the same.
//   B. THE PNG loses its tEXt chunks, every chunk left has a correct CRC, and
//      its IDAT still inflates to exactly the rows its IHDR describes.
//   C. THE WEBP loses its EXIF and XMP chunks and the extended header's two
//      flags; its image chunk is untouched and the RIFF size is right.
//   D. A JPEG with a second image after its end (a phone's Multi-Picture
//      Format) keeps only the first, and that one's MPF index goes; a file
//      that cannot be walked answers null.
//   E. THE LOGO: `Branding.setLogo()` keeps the cleaned bytes, and the
//      stored sha256, sides and size describe them; the served logo carries
//      no metadata; a PNG that cannot be walked to its IEND is refused with
//      STS-AUTHN-0624.
//
// The decode itself was also checked outside this file when the fixtures
// were made: each cleaned file decodes to the same pixels as the original.
// ===========================================================================

delete process.env.CONFIG_FILE;

const zlib = require('zlib');
const log = require('bunyan').createLogger({ name: 'image_metadata',
  level: process.env.LOG_LEVEL || 'info' });

const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const stsCrypto = require('../common/crypto');
const Branding = require('../common/branding');
const ImageMetadata = require('../common/image_metadata');

const REALM = 'image-metadata-test';

const JPEG = Buffer.from(
  '/9j/4AAQSkZJRgABAQAAAQABAAD/4QCgRXhpZgAATU0AKgAAAAgAAgEPAAIAAAALAAAAJogl' +
  'AAQAAAABAAAAMgAAAABFeGFtcGxlQ2FtAAAABAABAAIAAAACTgAAAAACAAUAAAADAAAAaAAD' +
  'AAIAAAACRQAAAAAEAAUAAAADAAAAgAAAAAAAAAA0AAAAAQAAABYAAAABAAAAAwAAAAEAAAAE' +
  'AAAAAQAAADYAAAABAAAADgAAAAH/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQY' +
  'GBcUFhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYa' +
  'KCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wAAR' +
  'CAAQABgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAA' +
  'AgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkK' +
  'FhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWG' +
  'h4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl' +
  '5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREA' +
  'AgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYk' +
  'NOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOE' +
  'hYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk' +
  '5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDx+x8P9Pk/SugsvD/T5P0rvrHw/wBPk/Su' +
  'gsfD/T5P0r0MTnXmeRkvEO2pwFj4f6fJ+lFev2Ph/p8n6UV4tTOve3P0/B8Q/u1qf//Z',
  'base64');

const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAABgAAAAQCAIAAACDRijCAAAAFnRFWHRBdXRob3IASmFuZSBR' +
  'LiBFeGFtcGxlkcNQgQAAABl0RVh0TG9jYXRpb24ANTIuMzY3Nk4gNC45MDQxRVBXEpwAAAAg' +
  'SURBVHicY2RgaOBiYKAcsTDwM1AFjBo0atCoQSPVIADQoAKFsaxMmwAAAABJRU5ErkJggg==',
  'base64');

const WEBP = Buffer.from(
  'UklGRg4BAABXRUJQVlA4WAoAAAAMAAAAFwAADwAAVlA4TCIAAAAvF8ADALkyRPQ/dhHR/wCR' +
  'tk0d3L/jwcNRGMCYAKoeqP8ERVhJRpgAAABNTQAqAAAACAACAQ8AAgAAAAsAAAAmiCUABAAA' +
  'AAEAAAAyAAAAAEV4YW1wbGVDYW0AAAAEAAEAAgAAAAJOAAAAAAIABQAAAAMAAABoAAMAAgAA' +
  'AAJFAAAAAAQABQAAAAMAAACAAAAAAAAAADQAAAABAAAAFgAAAAEAAAADAAAAAQAAAAQAAAAB' +
  'AAAANgAAAAEAAAAOAAAAAVhNUCAmAAAAPHg6eG1wbWV0YT5KYW5lIFEuIEV4YW1wbGU8L3g6' +
  'eG1wbWV0YT4=',
  'base64');

// What none of the cleaned files may still hold.
const METADATA = /Exif|ExampleCam|Jane|52\.3676|tEXt|XMP |xmpmeta|MPF/;

// The PNG's chunks as [name, data, crcOk].
function pngChunks(b) {
  log.debug("Entering pngChunks().");
  const out = [];
  let i = 8;
  while (i + 12 <= b.length) {
    const length = b.readUInt32BE(i);
    const name = b.toString('latin1', i + 4, i + 8);
    const data = b.slice(i + 8, i + 8 + length);
    const crc = b.readUInt32BE(i + 8 + length);
    out.push([name, data,
              (zlib.crc32(b.slice(i + 4, i + 8 + length)) >>> 0) === crc]);
    i += 12 + length;
  }
  log.debug("Leaving pngChunks().");
  return out;
}

// The JPEG's segments before its scan, as [marker, start, end].
function jpegSegments(b) {
  log.debug("Entering jpegSegments().");
  const out = [];
  let i = 2;
  while (i + 4 <= b.length && b[i] === 0xff && b[i + 1] !== 0xda) {
    const end = i + 2 + b.readUInt16BE(i + 2);
    out.push([b[i + 1], i, end]);
    i = end;
  }
  log.debug("Leaving jpegSegments().");
  return out;
}

function sectionA(t) {
  log.debug("Entering sectionA().");
  t.log.info('=== A. a JPEG with an EXIF GPS block ===');
  t.check(JPEG.indexOf(Buffer.from('Exif')) > 0 &&
          JPEG.indexOf(Buffer.from('ExampleCam')) > 0,
          'A0. the fixture carries an EXIF block with a GPS position');
  const out = ImageMetadata.stripped(JPEG, 'image/jpeg');
  t.check(Buffer.isBuffer(out) && !METADATA.test(out.toString('latin1')),
          'A1. the cleaned JPEG holds no EXIF');
  const app1 = jpegSegments(JPEG).filter(function (s) {
    return s[0] === 0xe1;
  });
  t.equal(app1.length, 1, 'A2. the fixture has one APP1 segment');
  const expected = Buffer.concat([JPEG.slice(0, app1[0][1]),
                                  JPEG.slice(app1[0][2])]);
  t.check(out.equals(expected),
          'A3. the result is the file with that segment cut out, byte for ' +
          'byte: the tables, frame and scan a decoder reads are untouched',
          out.length + ' vs ' + expected.length);
  const before = Branding.sniff(JPEG);
  const after = Branding.sniff(out);
  t.check(after.type === 'image/jpeg' && after.width === 24 &&
          after.height === 16 && after.width === before.width &&
          after.height === before.height,
          'A4. and it is still a 24 by 16 JPEG', JSON.stringify(after));
  log.debug("Leaving sectionA().");
}

function sectionB(t) {
  log.debug("Entering sectionB().");
  t.log.info('=== B. a PNG with tEXt chunks ===');
  t.check(pngChunks(PNG).filter(function (c) {
    return c[0] === 'tEXt';
  }).length === 2, 'B0. the fixture carries two tEXt chunks');
  const out = ImageMetadata.stripped(PNG, 'image/png');
  const chunks = pngChunks(out);
  t.equal(chunks.map(function (c) {
    return c[0];
  }).join(' '), 'IHDR IDAT IEND',
  'B1. only the image\'s chunks are left');
  t.check(!METADATA.test(out.toString('latin1')),
          'B2. and nothing of the text');
  t.check(chunks.every(function (c) {
    return c[2];
  }), 'B3. every chunk left has a correct CRC');
  const ihdr = chunks[0][1];
  const width = ihdr.readUInt32BE(0);
  const height = ihdr.readUInt32BE(4);
  const rows = zlib.inflateSync(chunks[1][1]);
  t.check(width === 24 && height === 16 &&
          rows.length === height * (1 + width * 3),
          'B4. its IDAT inflates to exactly the 16 rows of 24 RGB pixels ' +
          'its IHDR describes', width + 'x' + height + ' ' + rows.length);
  const seen = Branding.sniff(out);
  t.check(seen.width === 24 && seen.height === 16,
          'B5. and its sides read the same', JSON.stringify(seen));
  log.debug("Leaving sectionB().");
}

function sectionC(t) {
  log.debug("Entering sectionC().");
  t.log.info('=== C. a WebP with EXIF and XMP chunks ===');
  const out = ImageMetadata.stripped(WEBP, 'image/webp');
  t.check(Buffer.isBuffer(out) && !METADATA.test(out.toString('latin1')),
          'C1. the cleaned WebP holds neither EXIF nor XMP');
  t.equal(out.readUInt32LE(4), out.length - 8,
          'C2. its RIFF size is the file\'s');
  t.equal(out[20] & 0x0c, 0, 'C3. the extended header\'s EXIF and XMP ' +
          'flags are cleared');
  const image = WEBP.indexOf(Buffer.from('VP8L'));
  const size = WEBP.readUInt32LE(image + 4);
  t.check(out.indexOf(WEBP.slice(image, image + 8 + size)) > 0,
          'C4. the image chunk is untouched');
  const seen = Branding.sniff(out);
  t.check(seen.type === 'image/webp' && seen.width === 24 &&
          seen.height === 16, 'C5. and it is still a 24 by 16 WebP',
          JSON.stringify(seen));
  log.debug("Leaving sectionC().");
}

function sectionD(t) {
  log.debug("Entering sectionD().");
  t.log.info('=== D. a second image after the end, and a broken file ===');
  const mpf = Buffer.from([0xff, 0xe2, 0x00, 0x08, 0x4d, 0x50, 0x46, 0x00,
                           0x00, 0x00]);
  const withMpf = Buffer.concat([JPEG.slice(0, 2), mpf, JPEG.slice(2),
                                 JPEG]);
  const out = ImageMetadata.stripped(withMpf, 'image/jpeg');
  t.check(Buffer.isBuffer(out) &&
          out.equals(ImageMetadata.stripped(JPEG, 'image/jpeg')),
          'D1. the appended image (with its own EXIF) and the MPF index go',
          out ? out.length : 'null');
  t.equal(ImageMetadata.stripped(JPEG.slice(0, 400), 'image/jpeg'), null,
          'D2. a JPEG cut before its end answers null');
  t.equal(ImageMetadata.stripped(PNG.slice(0, 60), 'image/png'), null,
          'D3. a PNG cut before its IEND answers null');
  t.equal(ImageMetadata.stripped(WEBP.slice(0, 40), 'image/webp'), null,
          'D4. a WebP cut short answers null');
  t.equal(ImageMetadata.stripped(Buffer.from('<svg/>'), 'image/svg+xml'),
          null, 'D5. a type with no writer answers null');
  log.debug("Leaving sectionD().");
}

function sectionE(t) {
  log.debug("Entering sectionE().");
  t.log.info('=== E. the sign-in logo ===');
  const cases = [['JPEG', JPEG, 'image/jpeg'], ['PNG', PNG, 'image/png'],
                 ['WebP', WEBP, 'image/webp']];
  cases.forEach(function (c, n) {
    const set = Branding.setLogo(c[1], { alt: 'Acme', actor: 'test' });
    const record = Branding.logoRecord();
    const kept = record ? Buffer.from(String(record.data), 'base64')
      : Buffer.alloc(0);
    t.check(set.ok && record && record.type === c[2] &&
            !METADATA.test(kept.toString('latin1')) &&
            kept.equals(ImageMetadata.stripped(c[1], c[2])),
            'E' + (n * 3 + 1) + '. a ' + c[0] + ' logo is kept without its ' +
            'metadata', JSON.stringify(set));
    t.check(record && record.sha256 ===
              stsCrypto.digest('sha256', kept, 'hex') &&
            record.bytes === kept.length && kept.length < c[1].length &&
            set.logo && set.logo.sha256 === record.sha256,
            'E' + (n * 3 + 2) + '. its sha256 and size describe the cleaned ' +
            'bytes');
    t.check(record && record.width === 24 && record.height === 16,
            'E' + (n * 3 + 3) + '. and its sides are the image\'s');
  });
  const broken = Branding.setLogo(PNG.slice(0, 60),
                                  { alt: 'Acme', actor: 'test' });
  t.check(!broken.ok && broken.status === 400 &&
          errorCodes.codeOf(broken) === 'STS-AUTHN-0624',
          'E10. a PNG that cannot be walked to its IEND is refused',
          JSON.stringify(broken));
  t.check(Branding.removeLogo('test').removed,
          'E11. (the logo is removed)');
  log.debug("Leaving sectionE().");
}

async function run(t) {
  log.debug("Entering run().");
  sectionA(t);
  sectionB(t);
  sectionC(t);
  sectionD(t);
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!t.check(made.ok, 'the test realm is created',
               (made.errors || []).join(' '))) {
    log.debug("Leaving run().");
    return;
  }
  try {
    realms.run(made.realm, function () {
      sectionE(t);
    });
  } finally {
    realms.remove(REALM);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'image_metadata',
  describe: 'a published image without its metadata (#2140): a JPEG\'s ' +
            'EXIF, a PNG\'s text and a WebP\'s EXIF and XMP removed, each ' +
            'still the same image; the sign-in logo kept cleaned',
  run: run
};
