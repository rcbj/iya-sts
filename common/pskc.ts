// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pskc.ts
//
// ===========================================================================
// THE PORTABLE SYMMETRIC KEY CONTAINER, READ (RFC 6030; #1955 P4, design S3).
//
// An enterprise that buys hardware OATH tokens — pre-programmed YubiKeys,
// display tokens — is sent their secrets in a PSKC seed file: one
// `<KeyPackage>` per key, naming the device (`DeviceInfo`: Manufacturer,
// SerialNo, Model) and the key (`Key`, its algorithm URI, its response
// format, its counter or time step, its secret). This module turns that file
// into keys `common/oath_tokens.ts` keeps unassigned by serial. It decides
// nothing about who gets a token.
//
// **WHAT IS READ, AND WHAT IS REFUSED.**
//
//   * The XML is parsed by `common/xml_parser.js`, the service's one parser:
//     it refuses a document type or entity declaration before xmldom sees
//     the text, and xmldom resolves no external entity. That is what makes
//     reading a file an administrator uploaded safe, and it is the same door
//     SAML's messages come through.
//   * The document element must be RFC 6030's `KeyContainer`, version 1.0.
//     Children are matched by local name inside it, because the RFC's own
//     Figure 7 puts `Salt` and `IterationCount` in no namespace.
//   * Keys: HOTP (`urn:ietf:params:xml:ns:keyprov:pskc:hotp`) and TOTP (the
//     same URN with `totp`, and the `#hotp`/`#totp` spellings of the
//     algorithm profiles draft vendors still write). A PIN key (Figure 5),
//     OCRA or anything else is SKIPPED and reported, never imported as a
//     second factor. A response format must be 6 to 8 DECIMAL digits, a TOTP
//     time origin must be 0 (the verifier has no T0), and the counter and
//     time step must be plain values.
//   * Protection, section 6: none (plaintext, refused in product mode unless
//     `pskc.allowPlaintextImport`), a PRE-SHARED KEY (6.1, AES-CBC or AES
//     Key Wrap) or a PASSPHRASE (6.2, PBKDF2). A file encrypted to a
//     CERTIFICATE (6.3) is refused: this service would have to hold the
//     private key a vendor encrypted to, which is a key-management feature of
//     its own and not one an import form can carry.
//   * THE MAC FIRST (section 6.1.1). AES-CBC has no integrity, so each
//     encrypted secret carries a ValueMAC over its ciphertext, under a MAC key
//     that is itself in the file, encrypted under the same key. The MAC is
//     checked BEFORE the value is decrypted, so a wrong key or an altered
//     value is one refusal ("the key or password is wrong, or the file was
//     altered") and there is no padding oracle to protect.
//
// **THE KEY OR PASSWORD IS NEVER KEPT.** It is an argument of `open()` and of
// nothing else: no store, no log line, no audit row. The opened secrets leave
// this module as bytes for `oath_tokens.ts` to seal.
//
// A LIBRARY (rule 3): it registers no route. It requires `helpers`,
// `crypto`, `error_codes`, `mode` and the XML parser.
// ===========================================================================

import helpers = require('./helpers');
import crypto = require('./crypto');
import errorCodes = require('./error_codes');
import mode = require('./mode');
import InstanceSlot = require('./instance_slot');
import xmlParser = require('./xml_parser');

type Json = any;

const PSKC_NS = 'urn:ietf:params:xml:ns:keyprov:pskc';
const PBKDF2_URIS = [
  'http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#pbkdf2',
  'http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5#pbkdf2'
];
const KEY_ALGORITHMS: Record<string, string> = {
  'urn:ietf:params:xml:ns:keyprov:pskc:hotp': 'hotp',
  'urn:ietf:params:xml:ns:keyprov:pskc#hotp': 'hotp',
  'urn:ietf:params:xml:ns:keyprov:pskc:totp': 'totp',
  'urn:ietf:params:xml:ns:keyprov:pskc#totp': 'totp'
};
// An `AlgorithmParameters/Suite` naming the HMAC (the algorithm profiles'
// convention); SHA-1 where none is named, which is RFC 4226's.
const SUITES: Record<string, string> = {
  'HMAC-SHA1': 'SHA1', 'HMAC-SHA-1': 'SHA1', 'SHA1': 'SHA1',
  'HMAC-SHA256': 'SHA256', 'HMAC-SHA-256': 'SHA256', 'SHA256': 'SHA256',
  'HMAC-SHA512': 'SHA512', 'HMAC-SHA-512': 'SHA512', 'SHA512': 'SHA512'
};

/** The largest seed file one import reads, in characters. */
const MAX_TEXT = 4 * 1024 * 1024;
/** The most key packages one import takes. */
const MAX_PACKAGES = 2000;

interface EncryptedValue {
  algorithm: string;
  cipher: Buffer;
  mac: Buffer | null;
}

interface PskcKey {
  index: number;
  vendor: string;
  serial: string;
  model: string;
  issueNo: string;
  keyId: string;
  kind: string;
  issuer: string;
  digits: number;
  algorithm: string;
  counter: number;
  period: number;
  plain: Buffer | null;
  encrypted: EncryptedValue | null;
}

interface PskcDeps {
  log: typeof helpers.log;
  crypto: Json;
  errorCodes: typeof errorCodes;
  mode: { refusesPlaintextSeedFiles(): boolean };
  DOMParser: new (options?: Json) => { parseFromString(s: string,
                                                       t: string): Json };
}

/**
 * Reads RFC 6030 PSKC seed files: `parse()` the XML, then `open()` it with
 * the pre-shared key or password, the MAC checked first.
 */
class Pskc {
  static readonly NAMESPACE = PSKC_NS;
  static readonly MAX_TEXT = MAX_TEXT;
  static readonly MAX_PACKAGES = MAX_PACKAGES;

  /**
   * Builds the reader over its dependencies.
   *
   * @param deps - the logger, crypto, codes, mode and the XML parser
   */
  constructor(private readonly deps: PskcDeps) {
    deps.log.debug("Entering Pskc.constructor().");
    deps.log.debug("Leaving Pskc.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the real modules
   */
  static defaultDeps(): PskcDeps {
    helpers.log.debug("Entering Pskc.defaultDeps().");
    helpers.log.debug("Leaving Pskc.defaultDeps().");
    return { log: helpers.log, crypto: crypto, errorCodes: errorCodes,
             mode: mode as Json, DOMParser: xmlParser.DOMParser as Json };
  }

  private refuse(code: string, why: string, extra?: Json): Json {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering Pskc.refuse(). " + code);
    log.debug("Leaving Pskc.refuse().");
    return codes.mark(Object.assign({ ok: false, error: why, errors: [why] },
                                    extra || {}), code);
  }

  // -------------------------------------------------------------------------
  // THE TREE, BY LOCAL NAME. `kids()` is every element child with that local
  // name, `kid()` the first; `text()` its trimmed text content.
  // -------------------------------------------------------------------------
  // HOT PATH: kids() runs for every element of a file of up to two thousand
  // packages, so no Entering/Leaving pair, which would drown the log.
  private static kids(node: Json, name: string): Json[] {
    const out: Json[] = [];
    const list = node && node.childNodes ? node.childNodes : [];
    for (let i = 0; i < list.length; i++) {
      const c = list[i];
      if (c && c.nodeType === 1 && (c.localName || c.nodeName) === name) {
        out.push(c);
      }
    }
    return out;
  }

  // HOT PATH: kid() runs for every element of a file of up to two thousand
  // packages, so no Entering/Leaving pair, which would drown the log.
  private static kid(node: Json, name: string): Json {
    return Pskc.kids(node, name)[0] || null;
  }

  // HOT PATH: text() runs for every element of a file of up to two thousand
  // packages, so no Entering/Leaving pair, which would drown the log.
  private static text(node: Json): string {
    return node ? String(node.textContent || '').trim() : '';
  }

  // HOT PATH: path() runs for every element of a file of up to two thousand
  // packages, so no Entering/Leaving pair, which would drown the log.
  private static path(node: Json, names: string[]): Json {
    let at = node;
    for (const n of names) {
      at = at ? Pskc.kid(at, n) : null;
    }
    return at;
  }

  // HOT PATH: b64() runs for every element of a file of up to two thousand
  // packages, so no Entering/Leaving pair, which would drown the log.
  private static b64(text: string): Buffer {
    return Buffer.from(String(text || '').replace(/\s+/g, ''), 'base64');
  }

  // HOT PATH: encryptedOf() runs for every value of a file of up to two
  // thousand packages, so no Entering/Leaving pair, which would drown the
  // log.
  // An EncryptedValue or MACKey element: its method's Algorithm and its
  // CipherData/CipherValue, and the ValueMAC beside it when there is one.
  private static encryptedOf(node: Json, macNode: Json): EncryptedValue | null {
    if (!node) {
      return null;
    }
    const method = Pskc.kid(node, 'EncryptionMethod');
    const value = Pskc.path(node, ['CipherData', 'CipherValue']);
    if (!method || !value) {
      return null;
    }
    return { algorithm: String(method.getAttribute('Algorithm') || ''),
             cipher: Pskc.b64(Pskc.text(value)),
             mac: macNode ? Pskc.b64(Pskc.text(macNode)) : null };
  }

  // HOT PATH: plainOf() runs for every element of a file of up to two thousand
  // packages, so no Entering/Leaving pair, which would drown the log.
  // A counter, time or time step: its plain value, `encrypted` for one that
  // is not plain, or null where the element is absent.
  private static plainOf(node: Json): string | null {
    if (!node) {
      return null;
    }
    const v = Pskc.kid(node, 'PlainValue');
    return v ? Pskc.text(v) : 'encrypted';
  }

  // -------------------------------------------------------------------------
  // PARSE: the container's protection and every key package, without
  // opening anything. A whole-file refusal answers `{ ok: false }`; a key
  // that cannot be imported is SKIPPED with its code and the rest go on.
  // -------------------------------------------------------------------------
  /**
   * Parses a PSKC seed file without opening its secrets.
   *
   * @param source - the XML text
   * @returns `{ ok, protection, keyName, pbkdf2, mac, keys, skipped }`, or a
   *   refusal
   */
  parse(source: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering Pskc.parse().");
    const text = String(source == null ? '' : source);
    if (!text.trim() || text.length > MAX_TEXT) {
      log.debug("Leaving Pskc.parse(). Empty or too large.");
      return this.refuse('STS-OATH-0020', 'A PSKC seed file was expected: ' +
        'XML text of at most ' + MAX_TEXT + ' characters.');
    }
    let doc: Json = null;
    const problems: string[] = [];
    try {
      doc = new this.deps.DOMParser({ onError: function (level: string,
                                                         msg: string): void {
        if (level !== 'warning') {
          problems.push(String(msg));
        }
      } }).parseFromString(text, 'text/xml');
    } catch (e) {
      log.debug("Caught in Pskc.parse(): " + ((e && e.message) || e));
      problems.push(String((e && e.message) || e));
    }
    const root = doc && doc.documentElement;
    if (problems.length || !root) {
      log.debug("Leaving Pskc.parse(). Not XML.");
      return this.refuse('STS-OATH-0020', 'The seed file is not XML this ' +
        'service will read (it must be well formed and declare no document ' +
        'type or entity).');
    }
    if ((root.localName || root.nodeName) !== 'KeyContainer' ||
        root.namespaceURI !== PSKC_NS ||
        String(root.getAttribute('Version') || '') !== '1.0') {
      log.debug("Leaving Pskc.parse(). Not a KeyContainer.");
      return this.refuse('STS-OATH-0021', 'The file is not an RFC 6030 ' +
        'KeyContainer of version 1.0 in the ' + PSKC_NS + ' namespace.');
    }
    const protection = this.protectionOf(root);
    if (!protection.ok) {
      log.debug("Leaving Pskc.parse(). Protection refused.");
      return protection;
    }
    const packages = Pskc.kids(root, 'KeyPackage');
    if (!packages.length || packages.length > MAX_PACKAGES) {
      log.debug("Leaving Pskc.parse(). " + packages.length + " packages.");
      return this.refuse('STS-OATH-0029', 'A seed file must hold from 1 to ' +
        MAX_PACKAGES + ' key packages; this one holds ' + packages.length +
        '.');
    }
    const keys: PskcKey[] = [];
    const skipped: Json[] = [];
    packages.forEach((pkg: Json, index: number) => {
      const one = this.packageOf(pkg, index);
      if (one.ok) {
        keys.push(one.key);
      } else {
        skipped.push({ index: index, serial: one.serial || '',
                       keyId: one.keyId || '',
                       errorCode: this.deps.errorCodes.codeOf(one) || '',
                       why: one.error });
      }
    });
    log.debug("Leaving Pskc.parse(). " + keys.length + " key(s), " +
              skipped.length + " skipped.");
    return Object.assign(protection, { keys: keys, skipped: skipped });
  }

  // Section 6: EncryptionKey (a KeyName for a pre-shared key, a DerivedKey
  // for a passphrase, X509Data refused) and the MACMethod beside it.
  private protectionOf(root: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Pskc.protectionOf().");
    const enc = Pskc.kid(root, 'EncryptionKey');
    const macMethod = Pskc.kid(root, 'MACMethod');
    const mac = macMethod ? {
      algorithm: String(macMethod.getAttribute('Algorithm') || ''),
      key: Pskc.encryptedOf(Pskc.kid(macMethod, 'MACKey'), null),
      reference: !!Pskc.kid(macMethod, 'MACKeyReference')
    } : null;
    if (mac && (mac.reference || !mac.key)) {
      log.debug("Leaving Pskc.protectionOf(). A MAC key by reference.");
      return this.refuse('STS-OATH-0023', 'The file\'s MAC key is named by ' +
        'reference (MACKeyReference) rather than carried in it; this ' +
        'service imports only a file that carries its MAC key.');
    }
    if (mac && !this.deps.crypto.pskcAlgorithm(mac.algorithm)) {
      log.debug("Leaving Pskc.protectionOf(). MAC algorithm.");
      return this.refuse('STS-OATH-0023', 'The MAC algorithm ' +
        mac.algorithm + ' is not one this service computes.');
    }
    if (!enc) {
      log.debug("Leaving Pskc.protectionOf(). None.");
      return { ok: true, protection: 'none', keyName: '', pbkdf2: null,
               mac: mac };
    }
    if (Pskc.kid(enc, 'X509Data')) {
      log.debug("Leaving Pskc.protectionOf(). A certificate.");
      return this.refuse('STS-OATH-0023', 'The file is encrypted to a ' +
        'certificate (RFC 6030 section 6.3). Ask the vendor for a file ' +
        'protected by a pre-shared key or a password.');
    }
    const derived = Pskc.kid(enc, 'DerivedKey');
    if (derived) {
      const method = Pskc.kid(derived, 'KeyDerivationMethod');
      const algorithm = method ? String(method.getAttribute('Algorithm') ||
                                        '') : '';
      const params = method ? Pskc.kid(method, 'PBKDF2-params') : null;
      if (PBKDF2_URIS.indexOf(algorithm) < 0 || !params) {
        log.debug("Leaving Pskc.protectionOf(). Not PBKDF2.");
        return this.refuse('STS-OATH-0023', 'The file\'s key derivation ' +
          'is not PBKDF2 (RFC 6030 section 6.2).');
      }
      const prf = Pskc.kid(params, 'PRF');
      const out = {
        ok: true, protection: 'pbe',
        keyName: Pskc.text(Pskc.kid(derived, 'MasterKeyName')),
        pbkdf2: {
          salt: Pskc.b64(Pskc.text(Pskc.path(params, ['Salt',
                                                      'Specified']))),
          iterations: Number(Pskc.text(Pskc.kid(params, 'IterationCount'))),
          keyLength: Number(Pskc.text(Pskc.kid(params, 'KeyLength')) || 16),
          prf: prf ? String(prf.getAttribute('Algorithm') || '') : ''
        },
        mac: mac
      };
      log.debug("Leaving Pskc.protectionOf(). PBE.");
      return out;
    }
    log.debug("Leaving Pskc.protectionOf(). A pre-shared key.");
    return { ok: true, protection: 'pre-shared',
             keyName: Pskc.text(Pskc.kid(enc, 'KeyName')), pbkdf2: null,
             mac: mac };
  }

  // One KeyPackage, read and checked; its secret is left as found.
  private packageOf(pkg: Json, index: number): Json {
    const { log } = this.deps;
    log.debug("Entering Pskc.packageOf(). " + index);
    const device = Pskc.kid(pkg, 'DeviceInfo');
    const key = Pskc.kid(pkg, 'Key');
    const serial = Pskc.text(Pskc.kid(device, 'SerialNo'));
    const keyId = key ? String(key.getAttribute('Id') || '') : '';
    const at = { serial: serial, keyId: keyId };
    if (!key) {
      log.debug("Leaving Pskc.packageOf(). No key.");
      return this.refuse('STS-OATH-0022', 'Key package ' + (index + 1) +
        ' holds no Key.', at);
    }
    const kind = KEY_ALGORITHMS[String(key.getAttribute('Algorithm') || '')];
    if (!kind) {
      log.debug("Leaving Pskc.packageOf(). Not HOTP or TOTP.");
      return this.refuse('STS-OATH-0022', 'Key package ' + (index + 1) +
        ' is a ' + String(key.getAttribute('Algorithm') || 'nameless') +
        ' key, not an HOTP or TOTP token secret; it was skipped.', at);
    }
    if (!serial || !/^[\x21-\x7e]{1,64}$/.test(serial)) {
      log.debug("Leaving Pskc.packageOf(). No serial.");
      return this.refuse('STS-OATH-0028', 'Key package ' + (index + 1) +
        ' names no device serial (DeviceInfo/SerialNo) a token can be kept ' +
        'and claimed by.', at);
    }
    const params = Pskc.kid(key, 'AlgorithmParameters');
    const format = Pskc.kid(params, 'ResponseFormat');
    const digits = format ? Number(format.getAttribute('Length')) : 6;
    const encoding = format ? String(format.getAttribute('Encoding') ||
                                     'DECIMAL') : 'DECIMAL';
    const suiteText = Pskc.text(Pskc.kid(params, 'Suite')).toUpperCase();
    const algorithm = suiteText ? SUITES[suiteText] : 'SHA1';
    if (!(digits >= 6 && digits <= 8) || encoding.toUpperCase() !==
        'DECIMAL' || !algorithm) {
      log.debug("Leaving Pskc.packageOf(). Response format.");
      return this.refuse('STS-OATH-0022', 'Key package ' + (index + 1) +
        ' answers ' + (digits || '?') + ' ' + encoding + ' characters' +
        (suiteText ? ' under ' + suiteText : '') + '; a token here gives 6 ' +
        'to 8 decimal digits over HMAC-SHA-1, -256 or -512.', at);
    }
    const data = Pskc.kid(key, 'Data');
    const secret = Pskc.kid(data, 'Secret');
    const plainNode = Pskc.kid(secret, 'PlainValue');
    const encrypted = Pskc.encryptedOf(Pskc.kid(secret, 'EncryptedValue'),
                                       Pskc.kid(secret, 'ValueMAC'));
    if (!plainNode && !encrypted) {
      log.debug("Leaving Pskc.packageOf(). No secret.");
      return this.refuse('STS-OATH-0022', 'Key package ' + (index + 1) +
        ' carries no secret.', at);
    }
    // The moving factor: a plain value or nothing (an encrypted counter is
    // not read).
    const counterNode = Pskc.kid(data, 'Counter');
    const timeNode = Pskc.kid(data, 'Time');
    const intervalNode = Pskc.kid(data, 'TimeInterval');
    const counterText = Pskc.plainOf(counterNode);
    const timeText = Pskc.plainOf(timeNode);
    const intervalText = Pskc.plainOf(intervalNode);
    if ([counterText, timeText, intervalText].indexOf('encrypted') >= 0 ||
        (counterText !== null && !/^\d{1,15}$/.test(counterText)) ||
        (timeText !== null && timeText !== '0') ||
        (intervalText !== null && !/^\d{1,4}$/.test(intervalText))) {
      log.debug("Leaving Pskc.packageOf(). Moving factor.");
      return this.refuse('STS-OATH-0022', 'Key package ' + (index + 1) +
        ' has a counter, time origin or time step this service cannot ' +
        'use (each must be a plain value; the time origin 0).', at);
    }
    const period = intervalText === null ? 30 : Number(intervalText);
    if (kind === 'totp' && !(period >= 15 && period <= 300)) {
      log.debug("Leaving Pskc.packageOf(). Time step.");
      return this.refuse('STS-OATH-0022', 'Key package ' + (index + 1) +
        ' steps every ' + period + ' seconds; a TOTP token here steps ' +
        'every 15 to 300.', at);
    }
    const out: PskcKey = {
      index: index,
      vendor: Pskc.text(Pskc.kid(device, 'Manufacturer')),
      serial: serial,
      model: Pskc.text(Pskc.kid(device, 'Model')),
      issueNo: Pskc.text(Pskc.kid(device, 'IssueNo')),
      keyId: keyId,
      kind: kind,
      issuer: Pskc.text(Pskc.kid(key, 'Issuer')),
      digits: digits,
      algorithm: algorithm,
      counter: counterText === null ? 0 : Number(counterText),
      period: period,
      plain: plainNode ? Pskc.b64(Pskc.text(plainNode)) : null,
      encrypted: encrypted
    };
    log.debug("Leaving Pskc.packageOf(). " + kind + ".");
    return { ok: true, key: out };
  }

  // -------------------------------------------------------------------------
  // OPEN: the key (a pre-shared key's bytes, or one derived from the
  // password), the MAC key, and every secret — the MAC checked first.
  // -------------------------------------------------------------------------
  /**
   * Opens a parsed seed file: the secrets as bytes. The key or password is
   * used here and kept nowhere.
   *
   * @param parsed - what `parse()` answered
   * @param given - `{ preSharedKey (hex or base64), password }`
   * @returns a promise of `{ ok, keys: [{ …, secret: Buffer }], skipped }`,
   *   or a refusal
   */
  async open(parsed: Json, given?: Json): Promise<Json> {
    const { log, crypto: c, mode: m } = this.deps;
    log.debug("Entering Pskc.open().");
    const g = given || {};
    const keys: PskcKey[] = (parsed && parsed.keys) || [];
    const anyPlain = keys.some(function (k) {
      return !!k.plain;
    });
    if (anyPlain && m.refusesPlaintextSeedFiles()) {
      log.debug("Leaving Pskc.open(). Plaintext refused.");
      return this.refuse('STS-OATH-0024', 'This seed file carries token ' +
        'secrets in plaintext, which product mode refuses unless ' +
        'pskc.allowPlaintextImport is on. Ask the vendor for an encrypted ' +
        'file.');
    }
    const anyEncrypted = keys.some(function (k) {
      return !!k.encrypted;
    });
    let key: Buffer | null = null;
    if (anyEncrypted || (parsed && parsed.mac)) {
      key = await this.keyOf(parsed, g);
      if (!key) {
        log.debug("Leaving Pskc.open(). No key.");
        return this.refuse('STS-OATH-0025', parsed.protection === 'pbe'
          ? 'This seed file is protected by a password; give it with the ' +
            'upload.'
          : 'This seed file is encrypted under a pre-shared key' +
            (parsed.keyName ? ' ("' + String(parsed.keyName).slice(0, 64) +
             '")' : '') + '; give it, in hexadecimal or base64, with the ' +
            'upload.');
      }
    }
    let macKey: Buffer | null = null;
    if (parsed && parsed.mac) {
      try {
        macKey = c.pskcDecrypt(parsed.mac.key.algorithm, key,
                               parsed.mac.key.cipher);
      } catch (e) {
        log.debug("Caught in Pskc.open(): " + ((e && e.message) || e));
        macKey = null;
      }
      if (!macKey) {
        log.debug("Leaving Pskc.open(). The MAC key did not open.");
        return this.refuse('STS-OATH-0026', 'The key or password is wrong, ' +
          'or the file was altered: its MAC key did not decrypt.');
      }
    }
    const opened: Json[] = [];
    for (const k of keys) {
      const one = this.secretOf(k, key, macKey, parsed);
      if (!one.ok) {
        log.debug("Leaving Pskc.open(). A secret refused.");
        return one;
      }
      opened.push(Object.assign({}, k, { secret: one.secret, plain: null,
                                         encrypted: null }));
    }
    log.debug("Leaving Pskc.open(). " + opened.length + " opened.");
    return { ok: true, protection: parsed.protection, keys: opened,
             skipped: (parsed && parsed.skipped) || [] };
  }

  // The decryption key: a pre-shared key's bytes, or PBKDF2 of the password
  // on libuv's pool; null when none of the right kind was given.
  private async keyOf(parsed: Json, given: Json): Promise<Buffer | null> {
    const { log, crypto: c } = this.deps;
    log.debug("Entering Pskc.keyOf().");
    if (parsed.protection === 'pbe') {
      if (!given.password) {
        log.debug("Leaving Pskc.keyOf(). No password.");
        return null;
      }
      try {
        const out = await c.pskcDeriveKeyAsync(String(given.password),
          parsed.pbkdf2.salt, parsed.pbkdf2.iterations,
          parsed.pbkdf2.keyLength, parsed.pbkdf2.prf);
        log.debug("Leaving Pskc.keyOf(). Derived.");
        return out;
      } catch (e) {
        log.debug("Caught in Pskc.keyOf(): " + ((e && e.message) || e));
        log.debug("Leaving Pskc.keyOf(). PBKDF2 refused.");
        return null;
      }
    }
    const text = String(given.preSharedKey || '').replace(/\s+/g, '');
    let out: Buffer | null = null;
    if (/^([0-9a-fA-F]{2})+$/.test(text)) {
      out = Buffer.from(text, 'hex');
    } else if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(text)) {
      out = Buffer.from(text.replace(/-/g, '+').replace(/_/g, '/'),
                        'base64');
    }
    log.debug("Leaving Pskc.keyOf(). " + (out ? out.length : 0) + " octets.");
    return out && [16, 24, 32].indexOf(out.length) >= 0 ? out : null;
  }

  // One key's secret: the plaintext, or the MAC checked and then the value
  // decrypted. CBC without a ValueMAC is refused (section 6.1.1's MUST).
  private secretOf(k: PskcKey, key: Buffer | null, macKey: Buffer | null,
                   parsed: Json): Json {
    const { log, crypto: c } = this.deps;
    log.debug("Entering Pskc.secretOf().");
    if (k.plain) {
      log.debug("Leaving Pskc.secretOf(). Plain.");
      return k.plain.length ? { ok: true, secret: k.plain }
        : this.refuse('STS-OATH-0027', 'Key package ' + (k.index + 1) +
                      ' carries an empty secret.');
    }
    const e = k.encrypted as EncryptedValue;
    const spec = c.pskcAlgorithm(e.algorithm);
    if (!spec || spec.kind !== 'cipher') {
      log.debug("Leaving Pskc.secretOf(). Cipher.");
      return this.refuse('STS-OATH-0023', 'The encryption algorithm ' +
        e.algorithm + ' is not one this service opens.');
    }
    const cbc = /-CBC$/.test(spec.name);
    if (cbc && (!e.mac || !macKey)) {
      log.debug("Leaving Pskc.secretOf(). No MAC.");
      return this.refuse('STS-OATH-0027', 'Key package ' + (k.index + 1) +
        ' is ' + spec.name + '-encrypted with no ValueMAC under a MAC key, ' +
        'and RFC 6030 section 6.1.1 requires one for a cipher with no ' +
        'integrity of its own.');
    }
    if (e.mac && macKey) {
      let verified = false;
      try {
        verified = c.pskcMacVerifies(parsed.mac.algorithm, macKey, e.cipher,
                                     e.mac);
      } catch (err) {
        log.debug("Caught in Pskc.secretOf(): " +
                  ((err && err.message) || err));
        verified = false;
      }
      if (!verified) {
        log.debug("Leaving Pskc.secretOf(). MAC.");
        return this.refuse('STS-OATH-0026', 'The key or password is wrong, ' +
          'or the file was altered: the MAC of key package ' + (k.index + 1) +
          ' did not verify.');
      }
    }
    try {
      const secret = c.pskcDecrypt(e.algorithm, key, e.cipher);
      log.debug("Leaving Pskc.secretOf(). Decrypted.");
      return secret.length ? { ok: true, secret: secret }
        : this.refuse('STS-OATH-0027', 'Key package ' + (k.index + 1) +
                      ' decrypted to an empty secret.');
    } catch (err) {
      log.debug("Caught in Pskc.secretOf(): " +
                ((err && err.message) || err));
      log.debug("Leaving Pskc.secretOf(). Did not decrypt.");
      return this.refuse('STS-OATH-0027', 'Key package ' + (k.index + 1) +
        ' did not decrypt: the key is wrong or the value is not an IV and ' +
        'whole blocks.');
    }
  }
}

const slot = new InstanceSlot<Pskc>(
  'common/pskc',
  () => new Pskc(Pskc.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * RFC 6030 PSKC seed files, read (#1955 P4). A library (rule 3).
 * @namespace
 */
export = {
  Pskc: Pskc,
  NAMESPACE: PSKC_NS,
  installInstance: (instance: Pskc): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  parse: slot.forward('parse'),
  open: slot.forward('open')
};
