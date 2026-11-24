// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: image_metadata.ts
//
// ===========================================================================
// AN IMAGE THIS SERVICE PUBLISHES, REWRITTEN WITHOUT ITS METADATA (#2140,
// ASVS 5.0.0 14.2.8).
//
// Two images are served to anybody: a person's profile photo (#719,
// `profile_photo.ts`) and a realm's sign-in logo (#717, `branding.ts`). A
// phone's EXIF says where a picture was taken, XMP and a PNG's text chunks
// name who made it, and an image is served to whoever has the address — the
// logo to everybody who opens a sign-in page. So what is kept is REWRITTEN
// first: the chunks or segments a viewer needs to draw the image stay, and
// everything else goes, including anything after the image's end (so a
// file cannot be a picture and something else at once).
//
// The writers were `profile_photo.ts`'s own until #2140 moved them here so
// the logo could use them. Nothing here decodes pixels: there is no image
// library in this service. Each writer walks the container and keeps what
// is listed; a file it cannot walk to its end answers null, and the caller
// refuses it rather than keep it uncleaned.
//
//   * **JPEG**: APP0 (JFIF), an APP2 holding an ICC colour profile and
//     APP14 (Adobe's colour transform, without which some files decode
//     wrongly) stay; every other application segment — APP1's EXIF and XMP
//     among them — and every comment go. The image ends at the FIRST end
//     marker after the scan starts: an end marker cannot occur inside
//     entropy-coded data, so what follows is not this image. Until #2140 it
//     was the LAST, which kept a second image appended after the first (a
//     phone's Multi-Picture Format gain map or depth map), with that
//     image's own EXIF; for the same reason an APP2 that is not a colour
//     profile (MPF's index of those images) now goes.
//   * **PNG**: the chunks in `PNG_KEPT`, nothing after `IEND`. Text
//     (`tEXt`, `zTXt`, `iTXt`), `eXIf`, `tIME`, an animation's frames
//     (`acTL`, `fcTL`, `fdAT`: a viewer then draws the default image) and
//     any chunk nobody registered go.
//   * **WebP** (#2140; the logo accepts it, the photo does not): the RIFF
//     chunks in `WEBP_KEPT`. `EXIF`, `XMP ` and unknown chunks go, the
//     extended header's EXIF and XMP flags are cleared, and the RIFF size
//     is rewritten. An animation's frames ARE the image (an animated WebP has
//     no still default, unlike a PNG), so `ANIM` and `ANMF` stay, each frame
//     keeping only its `ALPH`, `VP8 ` and `VP8L`.
//
// A static utility class (rcbj's rule on #50). A LIBRARY: it registers no
// route and holds no state, and requires only `helpers` for the logger, so
// requiring it from either 6a-brand or 6a-photo moves nothing.
// ===========================================================================

import helpers = require('./helpers');

const log = helpers.log;

type Kept = Buffer | null;

// The chunks of a PNG a viewer needs: its image and how to colour it.
// Everything else — text, EXIF, an animation's frames, a chunk nobody
// registered — goes.
const PNG_KEPT = Object.freeze(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS',
                                'gAMA', 'cHRM', 'sRGB', 'iCCP', 'sBIT',
                                'pHYs']);

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47,
                                   0x0d, 0x0a, 0x1a, 0x0a]);

// The chunks of an extended WebP a viewer needs (RFC 9649 section 2.7).
const WEBP_KEPT = Object.freeze(['VP8X', 'ICCP', 'ANIM', 'ANMF', 'ALPH',
                                 'VP8 ', 'VP8L']);

// What one animation frame (`ANMF`) keeps after its 16-byte header.
const WEBP_FRAME_KEPT = Object.freeze(['ALPH', 'VP8 ', 'VP8L']);

// The extended header's flags for EXIF and XMP (RFC 9649 section 2.7).
const VP8X_EXIF = 0x08;
const VP8X_XMP = 0x04;

// The signature an APP2 segment holding an ICC profile starts with.
const ICC_APP2 = Buffer.from('ICC_PROFILE\0', 'latin1');

/**
 * Rewrites a JPEG, PNG or WebP without its metadata. A static utility
 * class; it holds no state.
 */
class ImageMetadata {
  static readonly PNG_KEPT = PNG_KEPT;
  static readonly WEBP_KEPT = WEBP_KEPT;

  /**
   * A JPEG with its metadata segments and anything after its end removed.
   *
   * APP0 (JFIF), an APP2 ICC profile and APP14 stay; every other
   * application segment and every comment goes. A file that is not walkable
   * to the end of its image answers null.
   *
   * @param b - the file, starting with the SOI marker
   * @returns the rewritten file, or null
   */
  static strippedJpeg(b: Buffer): Kept {
    log.debug("Entering ImageMetadata.strippedJpeg().");
    const pieces: Buffer[] = [b.slice(0, 2)];
    let i = 2;
    while (i + 4 <= b.length) {
      if (b[i] !== 0xff) {
        log.debug("Leaving ImageMetadata.strippedJpeg(). Not a marker.");
        return null;
      }
      const marker = b[i + 1];
      if (marker === 0xff) {
        i += 1;
        continue;
      }
      if (marker === 0xda) {
        // The scan. Everything from here is the image, to the first end
        // marker: 0xFF 0xD9 cannot occur inside entropy-coded data (a data
        // 0xFF is followed by 0x00), so what follows it is another image or
        // a polyglot's other half.
        const end = b.indexOf(Buffer.from([0xff, 0xd9]), i + 2);
        if (end < 0) {
          log.debug("Leaving ImageMetadata.strippedJpeg(). No end.");
          return null;
        }
        pieces.push(b.slice(i, end + 2));
        log.debug("Leaving ImageMetadata.strippedJpeg().");
        return Buffer.concat(pieces);
      }
      const length = b.readUInt16BE(i + 2);
      if (length < 2 || i + 2 + length > b.length) {
        log.debug("Leaving ImageMetadata.strippedJpeg(). A bad length.");
        return null;
      }
      const application = marker >= 0xe0 && marker <= 0xef;
      const colourProfile = marker === 0xe2 &&
        b.slice(i + 4, i + 4 + ICC_APP2.length).equals(ICC_APP2);
      const keptApplication = marker === 0xe0 || colourProfile ||
                              marker === 0xee;
      const dropped = marker === 0xfe || (application && !keptApplication);
      if (!dropped) {
        pieces.push(b.slice(i, i + 2 + length));
      }
      i += 2 + length;
    }
    log.debug("Leaving ImageMetadata.strippedJpeg(). No scan.");
    return null;
  }

  /**
   * A PNG holding only the chunks in `PNG_KEPT`, and nothing after `IEND`.
   *
   * @param b - the file, starting with the PNG signature
   * @returns the rewritten file, or null when it does not walk to `IEND`
   */
  static strippedPng(b: Buffer): Kept {
    log.debug("Entering ImageMetadata.strippedPng().");
    if (!b.slice(0, 8).equals(PNG_SIGNATURE)) {
      log.debug("Leaving ImageMetadata.strippedPng(). No signature.");
      return null;
    }
    const pieces: Buffer[] = [b.slice(0, 8)];
    let i = 8;
    while (i + 12 <= b.length) {
      const length = b.readUInt32BE(i);
      const end = i + 12 + length;
      if (end > b.length) {
        log.debug("Leaving ImageMetadata.strippedPng(). A bad length.");
        return null;
      }
      const name = b.toString('latin1', i + 4, i + 8);
      if (PNG_KEPT.indexOf(name) >= 0) {
        pieces.push(b.slice(i, end));
      }
      if (name === 'IEND') {
        log.debug("Leaving ImageMetadata.strippedPng().");
        return Buffer.concat(pieces);
      }
      i = end;
    }
    log.debug("Leaving ImageMetadata.strippedPng(). No IEND.");
    return null;
  }

  /**
   * The RIFF chunks between two offsets, as `[fourcc, payload]` pairs.
   *
   * @param b - the bytes
   * @param from - the first chunk's offset
   * @param to - where the chunks end
   * @returns the chunks, or null when one runs past `to`
   */
  static riffChunks(b: Buffer, from: number,
                    to: number): Array<[string, Buffer]> | null {
    log.debug("Entering ImageMetadata.riffChunks().");
    const out: Array<[string, Buffer]> = [];
    let i = from;
    while (i + 8 <= to) {
      const name = b.toString('latin1', i, i + 4);
      const size = b.readUInt32LE(i + 4);
      if (i + 8 + size > to) {
        log.debug("Leaving ImageMetadata.riffChunks(). A bad size.");
        return null;
      }
      out.push([name, b.slice(i + 8, i + 8 + size)]);
      // A chunk is padded to an even length.
      i += 8 + size + (size & 1);
    }
    log.debug("Leaving ImageMetadata.riffChunks(). " + out.length);
    return out;
  }

  /**
   * One RIFF chunk written out, padded to an even length.
   *
   * @param name - its four characters
   * @param payload - its data
   * @returns the chunk's bytes
   */
  static riffChunk(name: string, payload: Buffer): Buffer {
    log.debug("Entering ImageMetadata.riffChunk(). " + name);
    const head = Buffer.alloc(8);
    head.write(name, 0, 'latin1');
    head.writeUInt32LE(payload.length, 4);
    const pad = payload.length & 1 ? Buffer.alloc(1) : Buffer.alloc(0);
    log.debug("Leaving ImageMetadata.riffChunk().");
    return Buffer.concat([head, payload, pad]);
  }

  /**
   * A WebP holding only the chunks in `WEBP_KEPT`, its EXIF and XMP flags
   * cleared, and nothing after its RIFF size.
   *
   * @param b - the file, starting with `RIFF....WEBP`
   * @returns the rewritten file, or null when it cannot be walked or holds
   *   no image
   */
  static strippedWebp(b: Buffer): Kept {
    log.debug("Entering ImageMetadata.strippedWebp().");
    if (b.length < 20 || b.toString('latin1', 0, 4) !== 'RIFF' ||
        b.toString('latin1', 8, 12) !== 'WEBP') {
      log.debug("Leaving ImageMetadata.strippedWebp(). No signature.");
      return null;
    }
    const riffEnd = 8 + b.readUInt32LE(4);
    const chunks = riffEnd <= b.length
      ? ImageMetadata.riffChunks(b, 12, riffEnd) : null;
    if (!chunks || !chunks.length) {
      log.debug("Leaving ImageMetadata.strippedWebp(). Not walkable.");
      return null;
    }
    const first = chunks[0][0];
    const kept: Buffer[] = [];
    let images = 0;
    if (first === 'VP8 ' || first === 'VP8L') {
      // The simple format is one chunk; anything after it is not the image.
      kept.push(ImageMetadata.riffChunk(first, chunks[0][1]));
      images = 1;
    } else if (first === 'VP8X') {
      for (let c = 0; c < chunks.length; c++) {
        const name = chunks[c][0];
        let payload = chunks[c][1];
        if (WEBP_KEPT.indexOf(name) < 0) {
          continue;
        }
        if (name === 'VP8X') {
          if (c !== 0 || payload.length < 10) {
            log.debug("Leaving ImageMetadata.strippedWebp(). A bad VP8X.");
            return null;
          }
          payload = Buffer.from(payload);
          payload[0] = payload[0] & ~(VP8X_EXIF | VP8X_XMP);
        } else if (name === 'ANMF') {
          const frame = payload.length >= 16
            ? ImageMetadata.riffChunks(payload, 16, payload.length) : null;
          if (!frame) {
            log.debug("Leaving ImageMetadata.strippedWebp(). A bad frame.");
            return null;
          }
          const parts: Buffer[] = [payload.slice(0, 16)];
          frame.forEach(function (f) {
            if (WEBP_FRAME_KEPT.indexOf(f[0]) >= 0) {
              parts.push(ImageMetadata.riffChunk(f[0], f[1]));
            }
          });
          payload = Buffer.concat(parts);
        }
        if (name === 'VP8 ' || name === 'VP8L' || name === 'ANMF') {
          images += 1;
        }
        kept.push(ImageMetadata.riffChunk(name, payload));
      }
    }
    if (!images) {
      log.debug("Leaving ImageMetadata.strippedWebp(). No image.");
      return null;
    }
    const body = Buffer.concat(kept);
    const head = Buffer.alloc(12);
    head.write('RIFF', 0, 'latin1');
    head.writeUInt32LE(4 + body.length, 4);
    head.write('WEBP', 8, 'latin1');
    log.debug("Leaving ImageMetadata.strippedWebp().");
    return Buffer.concat([head, body]);
  }

  /**
   * The file as it will be kept, or null when it cannot be rewritten.
   *
   * @param bytes - the file
   * @param type - its type, as the bytes decided it (`image/jpeg`,
   *   `image/png` or `image/webp`)
   * @returns the rewritten file, or null for a file that cannot be walked
   *   or a type with no writer
   */
  static stripped(bytes: Buffer, type: string): Kept {
    log.debug("Entering ImageMetadata.stripped(). " + type);
    let out: Kept = null;
    if (type === 'image/png') {
      out = ImageMetadata.strippedPng(bytes);
    } else if (type === 'image/jpeg') {
      out = ImageMetadata.strippedJpeg(bytes);
    } else if (type === 'image/webp') {
      out = ImageMetadata.strippedWebp(bytes);
    }
    log.debug("Leaving ImageMetadata.stripped(). " + (out ? out.length
                                                          : 'refused'));
    return out;
  }
}

export = ImageMetadata;
