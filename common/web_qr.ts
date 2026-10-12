// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_qr.ts
//
// ---------------------------------------------------------------------------
// A QR CODE, DRAWN IN THE BROWSER (#589, 2026-10-12).
//
// `/portal/wallet` shows the Credential Offer it just made as a QR code for
// a wallet on another device to scan (OpenID4VCI Appendix H.2 and H.3). The
// portal is a static application since #568: every page is drawn by its
// renderer from an `/account-api` answer, and the answer is the OFFER — a
// URI — not a picture of it. So the picture is made here, from the URI,
// rather than by the server as an image the answer would have to carry.
//
// AND THE SIGN-IN SURFACE'S SET-UP STEP (#572) draws an authenticator app's
// `otpauth:` URI the same way, which is why this is in `common/` — it was
// `portal/web_qr.ts` until then — and is a module both bundles carry.
//
// **WHY NOT THE `qrcode` PACKAGE THE SERVER USES**: a `web_` module requires
// other `web_` modules only (`portal/CLAUDE.md`), so that the bundle a
// browser loads is this repository's code and nothing it pulled in; and the
// whole of what is needed is ISO/IEC 18004's byte mode at one error
// correction level, which is this file. `tests/portal_wallet.js` holds it to
// the `qrcode` package module for module, for every mask, across the
// versions an offer URI reaches — an encoder that is wrong draws a picture
// that scans as nothing, and nothing else here would notice.
//
// The layout is ISO/IEC 18004:2015's, in the order Project Nayuki's
// reference implementation (MIT) writes it: the function patterns, the
// data and error correction codewords interleaved by block, the zig-zag
// placement, the eight masks scored by the four penalty rules, the format
// and version information.
//
// The answer is an inline SVG: the portal's policy is `img-src 'self'`, and
// markup drawn into the page needs no `data:` image to be allowed.
//
// A `web_` MODULE: it requires other `web_` modules only (here, none) and
// logs nothing.
// ---------------------------------------------------------------------------

// The error correction levels, in the tables' order, with the two bits
// each writes into the format information (ISO/IEC 18004 table 12).
const LEVELS: Record<string, { index: number; bits: number }> = {
  L: { index: 0, bits: 1 },
  M: { index: 1, bits: 0 },
  Q: { index: 2, bits: 3 },
  H: { index: 3, bits: 2 }
};

// Error correction codewords per block, by level and version (table 9).
const ECC_PER_BLOCK: number[][] = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30,
   28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
   30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26,
   26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
   28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28,
   26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
   30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28,
   26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
   30, 30, 30]
];

// Error correction blocks, by level and version (table 9).
const BLOCKS: number[][] = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10,
   12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17,
   17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47,
   49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20,
   23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62,
   65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25,
   25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74,
   77, 81]
];

/**
 * A QR code: `size` modules a side, `modules[y][x]` true where dark.
 */
interface QrMatrix {
  version: number;
  mask: number;
  size: number;
  modules: boolean[][];
}

/**
 * One QR code being built: the grid, which modules are function patterns,
 * and the steps that fill them.
 */
class QrBuilder {
  readonly size: number;
  readonly modules: boolean[][];
  readonly isFunction: boolean[][];

  /**
   * An empty grid for a version.
   *
   * @param version - 1 to 40
   * @param level - the error correction level's table row
   */
  constructor(readonly version: number, readonly level: number) {
    this.size = version * 4 + 17;
    this.modules = [];
    this.isFunction = [];
    for (let y = 0; y < this.size; y++) {
      this.modules.push(new Array(this.size).fill(false));
      this.isFunction.push(new Array(this.size).fill(false));
    }
  }

  /**
   * Sets a function module.
   *
   * @param x - the column
   * @param y - the row
   * @param dark - its colour
   */
  set(x: number, y: number, dark: boolean): void {
    this.modules[y][x] = dark;
    this.isFunction[y][x] = true;
  }

  /**
   * The timing, finder and alignment patterns, and the format and version
   * areas reserved (format drawn with a dummy mask, replaced later).
   */
  drawFunctionPatterns(): void {
    for (let i = 0; i < this.size; i++) {
      this.set(6, i, i % 2 === 0);
      this.set(i, 6, i % 2 === 0);
    }
    this.drawFinder(3, 3);
    this.drawFinder(this.size - 4, 3);
    this.drawFinder(3, this.size - 4);
    const at = QrBuilder.alignmentPositions(this.version);
    const n = at.length;
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        const corner = (i === 0 && j === 0) || (i === 0 && j === n - 1) ||
                       (i === n - 1 && j === 0);
        if (!corner) {
          this.drawAlignment(at[i], at[j]);
        }
      }
    }
    this.drawFormat(0);
    this.drawVersion();
  }

  /**
   * A finder pattern and its separator, centred on a module.
   *
   * @param x - the centre's column
   * @param y - the centre's row
   */
  drawFinder(x: number, y: number): void {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        const xx = x + dx;
        const yy = y + dy;
        if (xx >= 0 && xx < this.size && yy >= 0 && yy < this.size) {
          this.set(xx, yy, dist !== 2 && dist !== 4);
        }
      }
    }
  }

  /**
   * An alignment pattern centred on a module.
   *
   * @param x - the centre's column
   * @param y - the centre's row
   */
  drawAlignment(x: number, y: number): void {
    for (let dy = -2; dy <= 2; dy++) {
      for (let dx = -2; dx <= 2; dx++) {
        this.set(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }

  /**
   * The two copies of the format information, for a mask.
   *
   * @param mask - 0 to 7
   */
  drawFormat(mask: number): void {
    const levelBits = [LEVELS.L.bits, LEVELS.M.bits, LEVELS.Q.bits,
                       LEVELS.H.bits][this.level];
    const data = (levelBits << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) {
      rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    }
    const bits = ((data << 10) | rem) ^ 0x5412;
    const bit = function (i: number): boolean {
      return ((bits >>> i) & 1) !== 0;
    };
    for (let i = 0; i <= 5; i++) {
      this.set(8, i, bit(i));
    }
    this.set(8, 7, bit(6));
    this.set(8, 8, bit(7));
    this.set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) {
      this.set(14 - i, 8, bit(i));
    }
    for (let i = 0; i < 8; i++) {
      this.set(this.size - 1 - i, 8, bit(i));
    }
    for (let i = 8; i < 15; i++) {
      this.set(8, this.size - 15 + i, bit(i));
    }
    // The dark module, always.
    this.set(8, this.size - 8, true);
  }

  /**
   * The two copies of the version information, from version 7.
   */
  drawVersion(): void {
    if (this.version < 7) {
      return;
    }
    let rem = this.version;
    for (let i = 0; i < 12; i++) {
      rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
    }
    const bits = (this.version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) !== 0;
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.set(a, b, dark);
      this.set(b, a, dark);
    }
  }

  /**
   * The codewords, placed in the zig-zag every QR code reads in.
   *
   * @param data - the interleaved codewords
   */
  drawCodewords(data: number[]): void {
    let i = 0;
    for (let right = this.size - 1; right >= 1; right -= 2) {
      if (right === 6) {
        right = 5;
      }
      for (let vert = 0; vert < this.size; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? this.size - 1 - vert : vert;
          if (!this.isFunction[y][x] && i < data.length * 8) {
            this.modules[y][x] = ((data[i >>> 3] >>> (7 - (i & 7))) & 1) !== 0;
            i++;
          }
        }
      }
    }
  }

  /**
   * XORs a mask over every module that is not a function pattern; applied
   * twice it undoes itself.
   *
   * @param mask - 0 to 7
   */
  applyMask(mask: number): void {
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) {
        let invert: boolean;
        switch (mask) {
        case 0:
          invert = (x + y) % 2 === 0;
          break;
        case 1:
          invert = y % 2 === 0;
          break;
        case 2:
          invert = x % 3 === 0;
          break;
        case 3:
          invert = (x + y) % 3 === 0;
          break;
        case 4:
          invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
          break;
        case 5:
          invert = (x * y) % 2 + (x * y) % 3 === 0;
          break;
        case 6:
          invert = ((x * y) % 2 + (x * y) % 3) % 2 === 0;
          break;
        default:
          invert = ((x + y) % 2 + (x * y) % 3) % 2 === 0;
          break;
        }
        if (!this.isFunction[y][x] && invert) {
          this.modules[y][x] = !this.modules[y][x];
        }
      }
    }
  }

  /**
   * The four penalty rules' score for the grid as it stands; the mask with
   * the lowest is the one drawn.
   *
   * @returns the score
   */
  penalty(): number {
    const size = this.size;
    const m = this.modules;
    let result = 0;
    const self = this;
    const line = function (get: (i: number) => boolean): void {
      let runColor = false;
      let run = 0;
      const history = [0, 0, 0, 0, 0, 0, 0];
      for (let i = 0; i < size; i++) {
        if (get(i) === runColor) {
          run++;
          if (run === 5) {
            result += 3;
          } else if (run > 5) {
            result++;
          }
        } else {
          self.addHistory(run, history);
          if (!runColor) {
            result += self.finderLike(history) * 40;
          }
          runColor = get(i);
          run = 1;
        }
      }
      if (runColor) {
        self.addHistory(run, history);
        run = 0;
      }
      run += size;
      self.addHistory(run, history);
      result += self.finderLike(history) * 40;
    };
    for (let y = 0; y < size; y++) {
      line(function (x: number): boolean {
        return m[y][x];
      });
    }
    for (let x = 0; x < size; x++) {
      line(function (y: number): boolean {
        return m[y][x];
      });
    }
    for (let y = 0; y < size - 1; y++) {
      for (let x = 0; x < size - 1; x++) {
        const c = m[y][x];
        if (c === m[y][x + 1] && c === m[y + 1][x] &&
            c === m[y + 1][x + 1]) {
          result += 3;
        }
      }
    }
    let dark = 0;
    m.forEach(function (row: boolean[]): void {
      row.forEach(function (one: boolean): void {
        dark += one ? 1 : 0;
      });
    });
    const total = size * size;
    const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
    result += k * 10;
    return result;
  }

  /**
   * Pushes a run onto the finder-pattern history (rule 3).
   *
   * @param run - the run's length
   * @param history - the last seven runs, newest first
   */
  addHistory(run: number, history: number[]): void {
    let length = run;
    if (history[0] === 0) {
      // The light area beyond the edge counts.
      length += this.size;
    }
    history.pop();
    history.unshift(length);
  }

  /**
   * How many finder-like patterns (1:1:3:1:1 with four light on a side)
   * the history ends in.
   *
   * @param h - the history
   * @returns 0, 1 or 2
   */
  finderLike(h: number[]): number {
    const n = h[1];
    const core = n > 0 && h[2] === n && h[3] === n * 3 && h[4] === n &&
                 h[5] === n;
    return (core && h[0] >= n * 4 && h[6] >= n ? 1 : 0) +
           (core && h[6] >= n * 4 && h[0] >= n ? 1 : 0);
  }

  /**
   * The centres of the alignment patterns, on each axis.
   *
   * @param version - 1 to 40
   * @returns the positions
   */
  static alignmentPositions(version: number): number[] {
    if (version === 1) {
      return [];
    }
    const count = Math.floor(version / 7) + 2;
    const step = version === 32 ? 26
      : Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
    const out = [6];
    for (let pos = version * 4 + 10; out.length < count; pos -= step) {
      out.splice(1, 0, pos);
    }
    return out;
  }
}

/**
 * QR codes for the portal. A static utility class; it holds no state.
 */
class WebQr {
  /**
   * The modules a version holds that are not function patterns.
   *
   * @param version - 1 to 40
   * @returns the count, in bits
   */
  static rawModules(version: number): number {
    let result = (16 * version + 128) * version + 64;
    if (version >= 2) {
      const align = Math.floor(version / 7) + 2;
      result -= (25 * align - 10) * align - 55;
      if (version >= 7) {
        result -= 36;
      }
    }
    return result;
  }

  /**
   * The data codewords a version holds at a level.
   *
   * @param version - 1 to 40
   * @param level - the level's table row
   * @returns the count
   */
  static dataCodewords(version: number, level: number): number {
    return Math.floor(WebQr.rawModules(version) / 8) -
      ECC_PER_BLOCK[level][version] * BLOCKS[level][version];
  }

  /**
   * GF(2^8) multiplication modulo x^8 + x^4 + x^3 + x^2 + 1.
   *
   * @param x - a byte
   * @param y - a byte
   * @returns their product
   */
  static multiply(x: number, y: number): number {
    let z = 0;
    for (let i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11D);
      z ^= ((y >>> i) & 1) * x;
    }
    return z;
  }

  /**
   * The Reed-Solomon generator polynomial of a degree, highest term
   * implied.
   *
   * @param degree - the error correction codewords per block
   * @returns its coefficients
   */
  static divisor(degree: number): number[] {
    const result: number[] = new Array(degree).fill(0);
    result[degree - 1] = 1;
    let root = 1;
    for (let i = 0; i < degree; i++) {
      for (let j = 0; j < result.length; j++) {
        result[j] = WebQr.multiply(result[j], root);
        if (j + 1 < result.length) {
          result[j] ^= result[j + 1];
        }
      }
      root = WebQr.multiply(root, 0x02);
    }
    return result;
  }

  /**
   * A block's error correction codewords.
   *
   * @param data - the block's data codewords
   * @param divisor - the generator
   * @returns the remainder
   */
  static remainder(data: number[], divisor: number[]): number[] {
    const result: number[] = divisor.map(function (): number {
      return 0;
    });
    data.forEach(function (b: number): void {
      const factor = b ^ (result.shift() as number);
      result.push(0);
      divisor.forEach(function (coef: number, i: number): void {
        result[i] ^= WebQr.multiply(coef, factor);
      });
    });
    return result;
  }

  /**
   * Text as UTF-8 bytes, which is what byte mode carries.
   *
   * @param text - the text
   * @returns the bytes
   */
  static utf8(text: string): number[] {
    // By hand rather than with TextEncoder, which the context a test draws
    // the bundle in does not have (`tests/vendored/portal_signin.js`).
    const out: number[] = [];
    for (const ch of String(text)) {
      const c = ch.codePointAt(0) as number;
      if (c < 0x80) {
        out.push(c);
      } else if (c < 0x800) {
        out.push(0xC0 | (c >> 6), 0x80 | (c & 0x3F));
      } else if (c < 0x10000) {
        out.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F),
                 0x80 | (c & 0x3F));
      } else {
        out.push(0xF0 | (c >> 18), 0x80 | ((c >> 12) & 0x3F),
                 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F));
      }
    }
    return out;
  }

  /**
   * Encodes text as a QR code, in byte mode, in the smallest version that
   * holds it at the level.
   *
   * @param text - what the code says
   * @param level - `L`, `M` (the default), `Q` or `H`
   * @param mask - a mask to force (0 to 7), or none to choose by penalty
   * @returns the matrix
   */
  static matrix(text: string, level?: string, mask?: number): QrMatrix {
    const row = (LEVELS[level || 'M'] || LEVELS.M).index;
    const bytes = WebQr.utf8(text);
    let version = 1;
    let capacity = 0;
    let countBits = 8;
    for (; version <= 40; version++) {
      countBits = version <= 9 ? 8 : 16;
      capacity = WebQr.dataCodewords(version, row) * 8;
      if (4 + countBits + bytes.length * 8 <= capacity) {
        break;
      }
    }
    if (version > 40) {
      throw new Error('Too long for a QR code: ' + bytes.length + ' bytes.');
    }
    // The bit stream: mode, count, data, terminator, padding.
    const bits: number[] = [];
    const append = function (value: number, length: number): void {
      for (let i = length - 1; i >= 0; i--) {
        bits.push((value >>> i) & 1);
      }
    };
    append(0x4, 4);
    append(bytes.length, countBits);
    bytes.forEach(function (b: number): void {
      append(b, 8);
    });
    append(0, Math.min(4, capacity - bits.length));
    append(0, (8 - bits.length % 8) % 8);
    for (let pad = 0xEC; bits.length < capacity; pad ^= 0xEC ^ 0x11) {
      append(pad, 8);
    }
    const data: number[] = [];
    for (let i = 0; i < bits.length; i += 8) {
      let b = 0;
      for (let j = 0; j < 8; j++) {
        b = (b << 1) | bits[i + j];
      }
      data.push(b);
    }
    // The blocks, each with its error correction, interleaved.
    const blockCount = BLOCKS[row][version];
    const eccLength = ECC_PER_BLOCK[row][version];
    const rawCodewords = Math.floor(WebQr.rawModules(version) / 8);
    const shortBlocks = blockCount - rawCodewords % blockCount;
    const shortLength = Math.floor(rawCodewords / blockCount);
    const divisor = WebQr.divisor(eccLength);
    const blocks: number[][] = [];
    for (let i = 0, k = 0; i < blockCount; i++) {
      const length = shortLength - eccLength + (i < shortBlocks ? 0 : 1);
      const part = data.slice(k, k + length);
      k += part.length;
      const ecc = WebQr.remainder(part, divisor);
      if (i < shortBlocks) {
        part.push(0);
      }
      blocks.push(part.concat(ecc));
    }
    const codewords: number[] = [];
    for (let i = 0; i < blocks[0].length; i++) {
      blocks.forEach(function (block: number[], j: number): void {
        if (i !== shortLength - eccLength || j >= shortBlocks) {
          codewords.push(block[i]);
        }
      });
    }
    const qr = new QrBuilder(version, row);
    qr.drawFunctionPatterns();
    qr.drawCodewords(codewords);
    let chosen = typeof mask === 'number' && mask >= 0 && mask <= 7
      ? mask : -1;
    if (chosen < 0) {
      let best = Infinity;
      for (let m = 0; m < 8; m++) {
        qr.applyMask(m);
        qr.drawFormat(m);
        const score = qr.penalty();
        if (score < best) {
          best = score;
          chosen = m;
        }
        qr.applyMask(m);
      }
    }
    qr.applyMask(chosen);
    qr.drawFormat(chosen);
    return { version: version, mask: chosen, size: qr.size,
             modules: qr.modules };
  }

  /**
   * A QR code as an inline SVG, with the four-module quiet zone the
   * standard asks for.
   *
   * @param text - what the code says
   * @param options - `pixels` (the drawn width, 240 by default), `id`,
   *   `label` (its accessible name)
   * @returns the SVG markup
   */
  static svg(text: string,
             options?: { pixels?: number; id?: string;
                         label?: string }): string {
    const opts = options || {};
    const qr = WebQr.matrix(text, 'M');
    const side = qr.size + 8;
    const pixels = opts.pixels || 240;
    let path = '';
    for (let y = 0; y < qr.size; y++) {
      for (let x = 0; x < qr.size; x++) {
        if (qr.modules[y][x]) {
          path += 'M' + (x + 4) + ' ' + (y + 4) + 'h1v1h-1z';
        }
      }
    }
    const escape = function (value: string): string {
      return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    };
    return '<svg xmlns="http://www.w3.org/2000/svg" role="img"' +
      (opts.id ? ' id="' + escape(opts.id) + '"' : '') +
      (opts.label ? ' aria-label="' + escape(opts.label) + '"' : '') +
      ' width="' + pixels + '" height="' + pixels + '" viewBox="0 0 ' +
      side + ' ' + side + '" shape-rendering="crispEdges"' +
      ' data-version="' + qr.version + '">' +
      '<rect width="' + side + '" height="' + side + '" fill="#fff"/>' +
      '<path d="' + path + '" fill="#000"/></svg>';
  }
}

export = WebQr;
