// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: yubiotp.ts
//
// ===========================================================================
// YUBICO OTP, VALIDATED HERE (#1955 P5, design S4 and decision D4).
//
// A YubiKey's OTP slot types a modhex string. The last 32 characters are one
// AES-128-ECB block; the prefix is the public identity, usually 12 characters
// (6 bytes). `common/crypto.js` decrypts the block and checks its CRC. This
// module decides what an OTP is, builds the one a test or an enrolment
// confirmation needs, and signs a YK-VAL parameter list. It holds no store:
// a person's credential, the replay counter and the public-identity index
// are `common/credentials.ts` and `common/yubiotp_store.ts`.
//
// **THE SERVER HOLDS THE AES KEY**, so a code that decrypts is not evidence
// the key is inside a token. Verification answers `hardware: false` and the
// session's `amr` is `otp` only — never `hwk`, and never `phr`. A token an
// administrator imported from a CSV is still recorded, so the lost-key act
// can retire it; the record does not change the `amr`.
//
// **THERE IS NO YUBICLOUD.** Nothing here dials api.yubico.com. A deployment
// that wants Yubico's validation protocol speaks it TO this service, at
// `/wsapi/2.0/verify` (`authn/ykval.ts`), and only when `yubiotp.ykval` is on.
//
// **THE TIMESTAMP IS NOT CHECKED.** The block carries one and this service
// has no clock to hold it to: two OTPs with the same use counter and the
// same session counter are the same OTP whatever their timestamp and random
// bytes say, and that is the replay.
//
// A LIBRARY (rule 3): it registers no route. It requires `config`, `crypto`,
// `helpers`, `error_codes`, `mode` and `authn_policy`, none of which
// requires it back.
// ===========================================================================

import helpers = require('./helpers');
// A refusal a person reads, as a catalog sentence (#2006).
import Sentence = require('./sentence');
import config = require('./config');
import crypto = require('./crypto');
import errorCodes = require('./error_codes');
import mode = require('./mode');
import authnPolicy = require('./authn_policy');
import InstanceSlot = require('./instance_slot');

type Json = any;

interface YubiDeps {
  log: {
    debug(message: string): void;
    info(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  };
  config: { value(key: string): any };
  crypto: {
    randomBytes(n: number): Buffer;
    YUBIOTP_MODHEX: string;
    yubiotpModhexDecode(text: unknown): Buffer | null;
    yubiotpModhexEncode(bytes: Buffer): string;
    yubiotpCrc16(bytes: Buffer): number;
    yubiotpDecrypt(key: unknown, ciphertext: unknown): Json;
    yubiotpEncrypt(key: unknown, plain: unknown): Buffer | null;
    yubiotpHmacSha1(secret: unknown, message: unknown): string;
    constantTimeEquals(a: unknown, b: unknown): boolean;
  };
  errorCodes: {
    mark<T>(result: T, code: string): T;
    tag(code: string): string;
  };
  mode: { refusesPlaintextYubiCsv(): boolean };
  authnPolicy: { allows(mechanism: string, role: string): boolean };
}

/** One decrypted OTP block, once its CRC and private identity have matched. */
interface YubiFields {
  publicId: string;
  privateId: string;
  use: number;
  session: number;
  composite: number;
}

type YubiVerdict =
  | { ok: true; fields: YubiFields }
  | { ok: false; reason: string; detail: string | Sentence };

/**
 * Yubico OTP as a second factor: the shape of an OTP, its decryption, a
 * new slot's programming string, and a YK-VAL signature. The counter is
 * spent by the caller.
 */
class YubiOtp {
  /** The shortest OTP this service accepts, ciphertext and no public id. */
  static readonly MIN_OTP = 32;

  /** The longest OTP this service accepts (a 16-character public id). */
  static readonly MAX_OTP = 48;

  /** How many modhex characters of an OTP are the ciphertext. */
  static readonly CIPHER_CHARS = 32;

  /** A public identity's usual length, in bytes. */
  static readonly PUBLIC_BYTES = 6;

  /** A private identity's length, in bytes. */
  static readonly PRIVATE_BYTES = 6;

  /** A YK-VAL nonce is 16 to 40 letters and digits. */
  static readonly NONCE_RE = /^[A-Za-z0-9]{16,40}$/;

  /**
   * Builds the mechanism over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: YubiDeps) {
    deps.log.debug("Entering YubiOtp.constructor().");
    deps.log.debug("Leaving YubiOtp.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): YubiDeps {
    helpers.log.debug("Entering YubiOtp.defaultDeps().");
    helpers.log.debug("Leaving YubiOtp.defaultDeps().");
    return {
      log: helpers.log, config: config, crypto: crypto,
      errorCodes: errorCodes, mode: mode, authnPolicy: authnPolicy
    };
  }

  private refuse(code: string, reason: string,
                 detail: string | Sentence): YubiVerdict {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering YubiOtp.refuse(). " + code);
    log.debug("Leaving YubiOtp.refuse().");
    return codes.mark({ ok: false, reason: reason, detail: detail }, code);
  }

  /**
   * Whether enrolment, assignment and a claim are offered. A credential
   * already held is still verified when this is false. Both
   * `yubiotp.offered` and the authentication policy's `yubico-otp` row
   * have to allow it.
   *
   * @returns true when both allow it
   */
  offered(): boolean {
    const { log, config: cfg } = this.deps;
    log.debug("Entering YubiOtp.offered().");
    const out = cfg.value('yubiotp.offered') === true &&
      this.deps.authnPolicy.allows('yubico-otp', 'second-factor');
    log.debug("Leaving YubiOtp.offered().");
    return out;
  }

  /**
   * Whether `/wsapi/2.0/verify` checks a client. Off, the route answers
   * `OPERATION_NOT_ALLOWED`.
   *
   * @returns true when `yubiotp.ykval` is on
   */
  ykvalEnabled(): boolean {
    const { log, config: cfg } = this.deps;
    log.debug("Entering YubiOtp.ykvalEnabled().");
    log.debug("Leaving YubiOtp.ykvalEnabled().");
    return cfg.value('yubiotp.ykval') === true;
  }

  /**
   * Whether product mode refuses a CSV whose secrets are in the clear.
   *
   * @returns true when the import is refused
   */
  refusesPlaintextCsv(): boolean {
    const { log, mode: m } = this.deps;
    log.debug("Entering YubiOtp.refusesPlaintextCsv().");
    log.debug("Leaving YubiOtp.refusesPlaintextCsv().");
    return m.refusesPlaintextYubiCsv();
  }

  /**
   * Whether a string has the shape of a YubiKey OTP: 32 to 48 characters,
   * even, and every character modhex.
   *
   * @param text - the code a person typed
   * @returns true when it has that shape
   */
  looksLike(text: unknown): boolean {
    const { log, crypto: c } = this.deps;
    log.debug("Entering YubiOtp.looksLike().");
    const s = String(text == null ? '' : text).replace(/\s+/g, '');
    const ok = s.length >= YubiOtp.MIN_OTP && s.length <= YubiOtp.MAX_OTP &&
               (s.length % 2) === 0 && !!c.yubiotpModhexDecode(s);
    log.debug("Leaving YubiOtp.looksLike(). " + ok);
    return ok;
  }

  /**
   * Splits an OTP into its public identity and its ciphertext.
   *
   * @param text - the OTP
   * @returns `{ publicId, cipher }`, or null
   */
  parse(text: unknown): { publicId: string; cipher: string } | null {
    const { log } = this.deps;
    log.debug("Entering YubiOtp.parse().");
    const s = String(text == null ? '' : text)
      .replace(/\s+/g, '').toLowerCase();
    if (!this.looksLike(s)) {
      log.debug("Leaving YubiOtp.parse(). Not an OTP.");
      return null;
    }
    const cipher = s.slice(-YubiOtp.CIPHER_CHARS);
    const publicId = s.slice(0, -YubiOtp.CIPHER_CHARS);
    log.debug("Leaving YubiOtp.parse(). Public id " + publicId.length +
              " character(s).");
    return { publicId: publicId, cipher: cipher };
  }

  /**
   * The moving factor a replay is judged on: use counter times 256, plus
   * the session-use counter. Zero is refused by the caller before it is
   * stored, because a counter advance treats 0-to-0 as nothing to store.
   *
   * @param use - the use counter
   * @param session - the session-use counter
   * @returns the composite
   */
  // THE USE COUNTER IS FIFTEEN BITS (the #1955 review). Its top bit is a
  // flag — Yubico's libyubikey reads the counter as `ctr & 0x7FFF` and the
  // flag as `ctr & 0x8000` (the OTP was triggered with Caps Lock) — so it is
  // masked off before the counter is compared: counted in, one flagged OTP
  // would have been 32768 uses ahead of every later one, and each of those
  // refused as a replay.
  composite(use: number, session: number): number {
    const { log } = this.deps;
    log.debug("Entering YubiOtp.composite().");
    const out = (Math.floor(Number(use)) & 0x7fff) * 256 +
                (Math.floor(Number(session)) & 0xff);
    log.debug("Leaving YubiOtp.composite().");
    return out;
  }

  /**
   * Decrypts an OTP under a known AES key and private identity.
   *
   * @param secret - `{ k, p, publicId }` the AES key and private identity,
   *   hex, and the public identity the OTP must start with
   * @param otp - the OTP
   * @returns the fields, or a refusal
   */
  open(secret: Json, otp: unknown): YubiVerdict {
    const { log, crypto: c } = this.deps;
    log.debug("Entering YubiOtp.open().");
    const parsed = this.parse(otp);
    if (!parsed || !parsed.publicId) {
      log.debug("Leaving YubiOtp.open(). Shape.");
      return this.refuse('STS-YUBIOTP-0001', 'shape',
        Sentence.say('refusals.factor.yubiShape'));
    }
    const wantPublic = String((secret && secret.publicId) || '');
    if (wantPublic && parsed.publicId !== wantPublic) {
      log.debug("Leaving YubiOtp.open(). Another public id.");
      return this.refuse('STS-YUBIOTP-0003', 'mismatch',
        Sentence.say('refusals.factor.yubiOtherKey'));
    }
    const opened = c.yubiotpDecrypt(secret && secret.k, parsed.cipher);
    if (!opened || !opened.ok || !opened.fields) {
      log.debug("Leaving YubiOtp.open(). Will not decrypt.");
      return this.refuse('STS-YUBIOTP-0003', 'mismatch',
        Sentence.say('refusals.factor.yubiNotDecrypted'));
    }
    const fields = opened.fields;
    if (!fields.crcOk) {
      log.debug("Leaving YubiOtp.open(). CRC.");
      return this.refuse('STS-YUBIOTP-0003', 'mismatch',
        Sentence.say('refusals.factor.yubiNotDecrypted'));
    }
    const wantPrivate = String((secret && secret.p) || '').toLowerCase();
    if (!wantPrivate || !c.constantTimeEquals(fields.privateId, wantPrivate)) {
      log.debug("Leaving YubiOtp.open(). Private id.");
      return this.refuse('STS-YUBIOTP-0003', 'mismatch',
        Sentence.say('refusals.factor.yubiNotDecrypted'));
    }
    const composite = this.composite(fields.use, fields.session);
    if (composite === 0) {
      log.debug("Leaving YubiOtp.open(). Composite zero.");
      return this.refuse('STS-YUBIOTP-0025', 'shape',
        Sentence.say('refusals.factor.yubiZeroCounter'));
    }
    log.debug("Leaving YubiOtp.open(). Use " + fields.use + ', session ' +
              fields.session + '.');
    return { ok: true, fields: {
      publicId: parsed.publicId, privateId: fields.privateId,
      use: Math.floor(Number(fields.use)) & 0x7fff, session: fields.session,
      composite: composite } };
  }

  /**
   * Builds a programming string for slot 1 and the secret it programs.
   * The string is shown once and is never logged.
   *
   * @returns `{ k, p, publicId, ykman }`
   */
  generate(): { k: string; p: string; publicId: string; ykman: string } {
    const { log, crypto: c } = this.deps;
    log.debug("Entering YubiOtp.generate().");
    const key = c.randomBytes(16);
    const priv = c.randomBytes(YubiOtp.PRIVATE_BYTES);
    const pub = c.randomBytes(YubiOtp.PUBLIC_BYTES);
    const k = key.toString('hex');
    const p = priv.toString('hex');
    const publicId = c.yubiotpModhexEncode(pub);
    const ykman = 'ykman otp yubiotp 1 --public-id ' + publicId +
      ' --private-id ' + p + ' --key ' + k;
    log.debug("Leaving YubiOtp.generate(). Public id " + publicId.length +
              " character(s).");
    return { k: k, p: p, publicId: publicId, ykman: ykman };
  }

  /**
   * Builds one OTP, for a test and for nothing a person is shown. The CRC
   * is stamped over the first 14 bytes.
   *
   * @param secret - `{ k, p, publicId }`
   * @param use - the use counter
   * @param session - the session-use counter
   * @returns the OTP, or ''
   */
  otpFor(secret: Json, use: number, session: number): string {
    const { log, crypto: c } = this.deps;
    log.debug("Entering YubiOtp.otpFor().");
    const priv = Buffer.from(String((secret && secret.p) || ''), 'hex');
    if (priv.length !== YubiOtp.PRIVATE_BYTES) {
      log.debug("Leaving YubiOtp.otpFor(). No private id.");
      return '';
    }
    const plain = Buffer.alloc(16);
    priv.copy(plain, 0);
    plain.writeUInt16LE(Math.floor(Number(use)) & 0xffff, 6);
    plain[11] = Math.floor(Number(session)) & 0xff;
    const crc = c.yubiotpCrc16(plain.subarray(0, 14));
    plain.writeUInt16LE((~crc) & 0xffff, 14);
    const block = c.yubiotpEncrypt(secret && secret.k, plain);
    if (!block) {
      log.debug("Leaving YubiOtp.otpFor(). Not encrypted.");
      return '';
    }
    const otp = String((secret && secret.publicId) || '') +
                c.yubiotpModhexEncode(block);
    log.debug("Leaving YubiOtp.otpFor().");
    return otp;
  }

  /**
   * The YK-VAL parameter string: keys sorted, `h` and empty values omitted,
   * joined by `&`.
   *
   * @param params - the parameters
   * @returns the string that is signed
   */
  paramString(params: Json): string {
    const { log } = this.deps;
    log.debug("Entering YubiOtp.paramString().");
    const src = params || {};
    const keys = Object.keys(src).filter(function (k) {
      return k !== 'h' && src[k] !== undefined && src[k] !== null &&
             String(src[k]) !== '';
    }).sort();
    const out = keys.map(function (k) {
      return k + '=' + String(src[k]);
    }).join('&');
    log.debug("Leaving YubiOtp.paramString(). " + keys.length + " key(s).");
    return out;
  }

  /**
   * Signs a YK-VAL parameter list.
   *
   * @param secret - the client key, base64
   * @param params - the parameters, without `h`
   * @returns the signature
   */
  sign(secret: string, params: Json): string {
    const { log, crypto: c } = this.deps;
    log.debug("Entering YubiOtp.sign().");
    const out = c.yubiotpHmacSha1(secret, this.paramString(params));
    log.debug("Leaving YubiOtp.sign().");
    return out;
  }

  /**
   * Checks a YK-VAL signature in constant time.
   *
   * @param secret - the client key, base64
   * @param params - the parameters, including `h`
   * @returns true when `h` matches
   */
  signatureOk(secret: string, params: Json): boolean {
    const { log, crypto: c } = this.deps;
    log.debug("Entering YubiOtp.signatureOk().");
    const got = String((params && params.h) || '');
    const want = this.sign(secret, params);
    const ok = !!got && c.constantTimeEquals(got, want);
    log.debug("Leaving YubiOtp.signatureOk(). " + ok);
    return ok;
  }

  /**
   * Reads a CSV of `serial,public id,private id,aes key`. A header row is
   * skipped. The file is plaintext; the caller has already applied the
   * product-mode refusal.
   *
   * @param text - the file
   * @returns `{ rows, errors }`
   */
  parseCsv(text: unknown): { rows: Json[]; errors: string[] } {
    const { log, crypto: c } = this.deps;
    log.debug("Entering YubiOtp.parseCsv().");
    const rows: Json[] = [];
    const errors: string[] = [];
    const lines = String(text == null ? '' : text).split(/\r?\n/);
    lines.forEach((line, index) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.charAt(0) === '#') {
        return;
      }
      const cells = trimmed.split(',').map(function (one) {
        return one.trim();
      });
      if (index === 0 && /serial/i.test(cells[0])) {
        return;
      }
      if (cells.length < 4) {
        errors.push('Line ' + (index + 1) + ' does not have four fields.');
        return;
      }
      const serial = cells[0];
      const publicId = cells[1].toLowerCase();
      const priv = cells[2].toLowerCase();
      const key = cells[3].toLowerCase();
      const pubBytes = c.yubiotpModhexDecode(publicId);
      if (!serial || serial.length > 64 || /[\u0000-\u001f]/.test(serial)) {
        errors.push('Line ' + (index + 1) + ' has no usable serial.');
        return;
      }
      if (!pubBytes || pubBytes.length < 2 || pubBytes.length > 8) {
        errors.push('Line ' + (index + 1) + ' has a public id that is ' +
                    'not modhex.');
        return;
      }
      if (!/^[0-9a-f]{12}$/.test(priv) || !/^[0-9a-f]{32}$/.test(key)) {
        errors.push('Line ' + (index + 1) + ' has a private id or an AES ' +
                    'key that is not hex.');
        return;
      }
      rows.push({ serial: serial, publicId: publicId, p: priv, k: key });
    });
    log.debug("Leaving YubiOtp.parseCsv(). " + rows.length + " row(s), " +
              errors.length + " error(s).");
    return { rows: rows, errors: errors };
  }

  /**
   * Describes the mechanism for `/admin/crypto-metadata`.
   *
   * @returns the report object
   */
  report(): Json {
    const { log } = this.deps;
    log.debug("Entering YubiOtp.report().");
    log.debug("Leaving YubiOtp.report().");
    return {
      offered: this.offered(),
      ykval: this.ykvalEnabled(),
      algorithm: 'AES-128-ECB of one 16-byte block, no padding. There is ' +
                 'no post-quantum parameter.',
      alphabet: 'modhex (cbdefghijklnrtuv)',
      crc: 'CRC-16, polynomial 0x8408, initialised to 0xffff; residual ' +
           '0xf0b8',
      replay: 'The use counter and the session-use counter, as one value, ' +
              'advanced by compare-and-set in the store. The timestamp is ' +
              'not checked.',
      cloud: 'No. A YubiCloud call is not made. /wsapi/2.0/verify answers ' +
             'YK-VAL 2.0 only when yubiotp.ykval is on.'
    };
  }
}

const slot = new InstanceSlot<YubiOtp>(
  'common/yubiotp',
  () => new YubiOtp(YubiOtp.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Yubico OTP as a second factor (#1955 P5).
 * @namespace
 */
export = {
  YubiOtp: YubiOtp,
  installInstance: (instance: YubiOtp): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  offered: slot.forward('offered'),
  ykvalEnabled: slot.forward('ykvalEnabled'),
  refusesPlaintextCsv: slot.forward('refusesPlaintextCsv'),
  looksLike: slot.forward('looksLike'),
  parse: slot.forward('parse'),
  composite: slot.forward('composite'),
  open: slot.forward('open'),
  generate: slot.forward('generate'),
  otpFor: slot.forward('otpFor'),
  paramString: slot.forward('paramString'),
  sign: slot.forward('sign'),
  signatureOk: slot.forward('signatureOk'),
  parseCsv: slot.forward('parseCsv'),
  report: slot.forward('report')
};
