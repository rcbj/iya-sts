'use strict';
//
// File: browser_devices.ts
//
// ===========================================================================
// REMEMBERED BROWSERS: A DEVICE KNOWN BY A SIGNED AND ENCRYPTED COOKIE (#265,
// 2026-09-26).
//
// The device register (#164) recognises a device by a key it PROVED: a
// WebAuthn platform credential, a DPoP key, a client certificate, a Native SSO
// secret. A general-purpose browser can prove none of those portably — Linux
// Firefox has no platform authenticator at all — so a person's browsers were
// "unregistered" to risk scoring and could never be linked. rcbj asked for a
// mechanism that works in EVERY browser and is acknowledged to be weaker, and
// decided four things on #265:
//
//   1. an HttpOnly cookie, never localStorage (unreadable by script, sent by
//      the script-free sign-in screen and portal);
//   2. opt-in: "Remember this browser" at sign-in and on /portal/devices;
//   3. a second factor may be skipped on a remembered browser — the
//      authentication policy's `rememberedBrowserSkipsSecondFactor`, off by
//      default, for `rememberedBrowserDays` (30) per realm, never at the admin
//      console or the user portal (below);
//   4. a key pair for this purpose alone, in both signer models: the realm's
//      dedicated browser device keys in `per-algorithm`, the
//      `browser-devices` group's ES256 key in `hybrid-groups`
//      (`helpers.browserDeviceSigner()`).
//
// **WHAT THE COOKIE HOLDS** is a nested JWT: a JWS (ES256, typ
// `browser-device+jwt`) signed by that key, encrypted as a JWE
// (ECDH-ES+A256KW, A256GCM) to the realm's browser device ENCRYPTION key.
// This service is the only party that ever reads it, so the encryption is
// to its own key: it keeps the device id and the owner out of anybody's
// cookie jar, and the signature is what makes the token believed. Claims:
// `iss` and `aud` (`urn:sts:browser-device:<realm>`), `sub` (the device id),
// `owner` (the username at issue), `gen`, `jti`, `iat`, `exp`. Classical and
// small ON PURPOSE: a cookie holds about 4 KB, and an ML-DSA signature alone
// does not fit; a token that would not is refused (STS-DEVICE-0043).
//
// **IT IS A BEARER CREDENTIAL**, and everything below follows from that:
//
//   * The device's attestation is `bearer` — below `self-asserted`. It is
//     never compliant (`devices.setCompliance()` refuses, STS-DEVICE-0039),
//     so it never meets the compliant-device rule or acr and never earns a
//     lowering risk signal. What it DOES do is make the browser the person's
//     own recognised device, which is what stops `new-device` and
//     `unregistered-device` firing on every sign-in from it.
//   * **A COPIED COOKIE IS CAUGHT BY ITS GENERATION.** Every sign-in the
//     browser is recognised at issues the token again with `gen + 1`, and the
//     device keeps the current generation. A token carrying an older one —
//     beyond `devices.browserReissueGraceSeconds`, for two tabs signing in at
//     once — was copied: the device is marked COMPROMISED (which ends every
//     session it holds), the fact says `replayed`, and risk scoring sees
//     `browser-token-replayed`. Refresh-token rotation's argument, for a
//     cookie.
//   * A token naming somebody else's device is `foreign`; one presented by a
//     browser of another family or OS than it was bound to is
//     `contextChanged`. Risk scoring weighs both; neither is refused here.
//
// **THE SECOND-FACTOR SKIP** (`skipsSecondFactor()`) holds only when ALL of:
// the realm's policy turned it on; the browser is recognised, the person's
// own, current (not replayed, not compromised) and in its original browser;
// the second factor was last given ON THIS BROWSER within the policy's days;
// the sign-in is not for the admin console, the user portal or the protocol
// debugger; the person holds no console role; the sign-in's risk is below
// MEDIUM; and nothing demanded a factor (a relying party's acr_values or
// wauth, a security key, a risk step-up) — the caller passes only the
// person's CONFIGURED factor to ask about. The session is then one factor,
// `amr ["pwd"]`, `acr "1"`, exactly as a person with no second factor, so
// a relying party that needs two asks for them and gets them.
//
// A LIBRARY (rule 3), built by the composition root. It registers nothing;
// `authn/authn.ts` and `portal/portal_devices.ts` call it.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import config = require('./config');
import realms = require('./realms');
import stsCrypto = require('./crypto');
import errorCodes = require('./error_codes');
import audit = require('./audit');
import devices = require('./devices');
import authnPolicy = require('./authn_policy');

type Json = any;

const TOKEN_TYPE = 'browser-device+jwt';
const JWE_ALG = 'ECDH-ES+A256KW';
const JWE_ENC = 'A256GCM';
const USE_CASE = 'browser-device-token';
// A cookie's name, value and attributes together may be 4096 bytes in every
// browser (RFC 6265bis section 5.6); the attributes take about 120.
const MAX_TOKEN_BYTES = 3900;
// The clients whose sign-ins are never answered by a remembered browser
// without a second factor (rcbj: "never valid for admin or user portal"),
// and the debugger, which only administrators reach.
const NEVER_SKIP_CLIENTS = ['sts-admin-console', 'sts-user-portal',
                            'sts-debugger-ui'];
const SECOND_FACTOR_AMR = ['otp', 'hwk', 'swk', 'mfa', 'sms', 'face', 'fpt',
                           'iris', 'retina', 'vbm', 'pin', 'sc'];

interface BrowserDevicesDeps {
  log: typeof helpers.log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  devices: typeof devices;
  authnPolicy: typeof authnPolicy;
  keysFor: () => Json;
  signer: () => Json;
  verifiers: () => Map<string, Json>;
  certificateHeaderFor: (useCase: string, alg: string, kid: string) => Json;
  consoleRolesOf: (username: string) => Json;
  realmId: () => string;
  now: () => number;
}

class BrowserDevices {
  static readonly TOKEN_TYPE = TOKEN_TYPE;
  static readonly MAX_TOKEN_BYTES = MAX_TOKEN_BYTES;
  static readonly NEVER_SKIP_CLIENTS = NEVER_SKIP_CLIENTS;

  constructor(private readonly deps: BrowserDevicesDeps) {
    deps.log.debug("Entering BrowserDevices.constructor().");
    deps.log.debug("Leaving BrowserDevices.constructor().");
  }

  static defaultDeps(): BrowserDevicesDeps {
    helpers.log.debug("Entering BrowserDevices.defaultDeps().");
    helpers.log.debug("Leaving BrowserDevices.defaultDeps().");
    return {
      log: helpers.log, config: config, errorCodes: errorCodes, audit: audit,
      devices: devices, authnPolicy: authnPolicy,
      keysFor: function (): Json {
        return helpers.browserDeviceKeysFor();
      },
      signer: function (): Json {
        return helpers.browserDeviceSigner();
      },
      verifiers: function (): Map<string, Json> {
        return helpers.browserDeviceVerifiers();
      },
      certificateHeaderFor: function (useCase: string, alg: string,
                                      kid: string): Json {
        return helpers.certificateHeaderFor(useCase, alg, kid);
      },
      // MEMBERSHIP OF THE CONSOLE ROSTER'S GROUPS — `credentials.ts`'s
      // reading (#246): not `read`/`write`, which are true for everybody
      // while the roster is empty. Found lazily, because
      // `admin-ui/admin_rbac.ts` requires the console and a library here
      // must not; a process with no console has no administrators.
      consoleRolesOf: function (username: string): Json {
        try {
          const rbac = require('../admin-ui/admin_rbac');
          const groups = (rbac.rolesOf(username) || {}).groups;
          const list = Array.isArray(groups) ? groups : [];
          return {
            read: list.some(function (g: Json): boolean {
              return g.role === 'read' || g.role === 'write';
            }),
            write: list.some(function (g: Json): boolean {
              return g.role === 'write';
            })
          };
        } catch (e) {
          helpers.log.debug("Caught in consoleRolesOf(): " +
                            ((e && e.message) || e));
          return { read: false, write: false };
        }
      },
      realmId: function (): string {
        return realms.currentId();
      },
      now: Date.now
    };
  }

  enabled(): boolean {
    this.deps.log.debug("Entering BrowserDevices.enabled().");
    this.deps.log.debug("Leaving BrowserDevices.enabled().");
    return this.deps.config.value('devices.browserDevices') !== false;
  }

  // -------------------------------------------------------------------------
  // THE COOKIE. `__Host-` wherever the main port is TLS — the prefix pins it
  // to this host, Secure and Path=/ — and a name per realm, because realms
  // share a host and a path-scoped cookie would not reach the sign-in screen
  // of the realm it belongs to in every case.
  // -------------------------------------------------------------------------
  private secure(): boolean {
    return !!this.deps.config.value('global.https');
  }

  cookieName(): string {
    const { log } = this.deps;
    log.debug("Entering BrowserDevices.cookieName().");
    const realm = this.deps.realmId();
    const name = (this.secure() ? '__Host-' : '') + 'sts_browser' +
                 (realm && realm !== 'default' ? '_' + realm : '');
    log.debug("Leaving BrowserDevices.cookieName(). " + name);
    return name;
  }

  private lifetimeS(): number {
    return Math.min(400, Math.max(1, Number(this.deps.config.value(
      'devices.browserTokenLifetimeDays')) || 180)) * 86400;
  }

  private setCookie(res: Json, value: string, maxAgeS: number): void {
    const { log } = this.deps;
    log.debug("Entering BrowserDevices.setCookie().");
    const line = this.cookieName() + '=' + value + '; Path=/; HttpOnly; ' +
                 'SameSite=Lax; Max-Age=' + Math.max(0, Math.floor(maxAgeS)) +
                 (this.secure() ? '; Secure' : '');
    // APPENDED, never set: the session cookie is written with `res.set()`,
    // which REPLACES the header, so this goes out after it.
    if (res && typeof res.append === 'function') {
      res.append('Set-Cookie', line);
    } else if (res && typeof res.getHeader === 'function' &&
               typeof res.setHeader === 'function') {
      const held = res.getHeader('Set-Cookie');
      const list = Array.isArray(held) ? held : (held ? [String(held)] : []);
      res.setHeader('Set-Cookie', list.concat([line]));
    }
    log.debug("Leaving BrowserDevices.setCookie().");
  }

  clear(res: Json): void {
    const { log } = this.deps;
    log.debug("Entering BrowserDevices.clear().");
    this.setCookie(res, '', 0);
    log.debug("Leaving BrowserDevices.clear().");
  }

  presented(req: Json): string {
    const { log } = this.deps;
    log.debug("Entering BrowserDevices.presented().");
    const header = String((req && req.headers && req.headers.cookie) || '');
    const name = this.cookieName();
    let found = '';
    header.split(';').forEach(function (part: string): void {
      const at = part.indexOf('=');
      if (at > 0 && part.slice(0, at).trim() === name) {
        found = part.slice(at + 1).trim();
      }
    });
    log.debug("Leaving BrowserDevices.presented(). " +
              (found ? 'Present.' : 'None.'));
    return /^[A-Za-z0-9_.-]{20,4096}$/.test(found) ? found : '';
  }

  // -------------------------------------------------------------------------
  // WHICH BROWSER. A family and an OS read off User-Agent — "Firefox on
  // Linux" — which is what a person recognises on /portal/devices and what a
  // token is bound to. Never more than that: a full User-Agent string changes
  // with every browser update, and a binding that broke monthly would teach
  // everybody to ignore `browser-context-changed`.
  // -------------------------------------------------------------------------
  static browserOf(userAgent: unknown): string {
    helpers.log.debug("Entering BrowserDevices.browserOf().");
    const ua = String(userAgent || '');
    const family = /Edg\//.test(ua) ? 'Edge'
      : (/OPR\//.test(ua) ? 'Opera'
      : (/Firefox\//.test(ua) ? 'Firefox'
      : (/Chrome\//.test(ua) || /CriOS\//.test(ua) ? 'Chrome'
      : (/Safari\//.test(ua) ? 'Safari' : 'a browser'))));
    const os = /iPhone|iPad|iPod/.test(ua) ? 'iOS'
      : (/Android/.test(ua) ? 'Android'
      : (/Windows/.test(ua) ? 'Windows'
      : (/Mac OS X|Macintosh/.test(ua) ? 'macOS'
      : (/CrOS/.test(ua) ? 'ChromeOS'
      : (/Linux/.test(ua) ? 'Linux' : 'another system')))));
    helpers.log.debug("Leaving BrowserDevices.browserOf().");
    return family + ' on ' + os;
  }

  static platformOf(browser: string): string {
    const os = String(browser || '').split(' on ')[1] || '';
    return ({ iOS: 'ios', Android: 'android', Windows: 'windows',
              macOS: 'macos', ChromeOS: 'chromeos', Linux: 'linux' } as Json)[
      os] || 'other';
  }

  private audience(): string {
    return 'urn:sts:browser-device:' + this.deps.realmId();
  }

  // -------------------------------------------------------------------------
  // MINTING: sign with the browser device key, encrypt to the browser device
  // encryption key. Null (and STS-DEVICE-0043 logged) for a token too large
  // for a cookie.
  // -------------------------------------------------------------------------
  mint(deviceId: string, owner: string, gen: number): string | null {
    const { log, errorCodes } = this.deps;
    log.debug("Entering BrowserDevices.mint(). gen=" + gen);
    const now = Math.floor(this.deps.now() / 1000);
    const claims = {
      iss: this.audience(), aud: this.audience(), sub: String(deviceId),
      owner: String(owner), gen: Number(gen),
      jti: nodeCrypto.randomBytes(16).toString('base64url'),
      iat: now, exp: now + this.lifetimeS()
    };
    const signer = this.deps.signer();
    const header = Object.assign({ typ: TOKEN_TYPE },
      this.deps.certificateHeaderFor(USE_CASE, 'ES256', signer.kid));
    const jws = stsCrypto.signJws(claims, signer.key,
      { algorithm: 'ES256', kid: signer.kid, header: header });
    const enc = this.deps.keysFor().enc;
    const jwe = stsCrypto.encryptJweCompact(jws, {
      alg: JWE_ALG, enc: JWE_ENC, jwk: enc.publicJwk, cty: 'JWT',
      typ: 'JWT' });
    if (jwe.length > MAX_TOKEN_BYTES) {
      log.warn(errorCodes.tag('STS-DEVICE-0043') + 'devices: a remembered ' +
               'browser\'s token is ' + jwe.length + ' bytes, more than a ' +
               'cookie holds (devices.browserTokenCertificateHeader?); it ' +
               'was not issued.');
      log.debug("Leaving BrowserDevices.mint(). Too large.");
      return null;
    }
    log.debug("Leaving BrowserDevices.mint(). " + jwe.length + " bytes.");
    return jwe;
  }

  // -------------------------------------------------------------------------
  // READING: decrypt with the encryption key, verify with a key that may have
  // signed it (the dedicated key, or the group's), check the claims. Answers
  // the claims or null with the reason logged (STS-DEVICE-0040).
  // -------------------------------------------------------------------------
  read(value: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering BrowserDevices.read().");
    try {
      const enc = this.deps.keysFor().enc;
      const opened = stsCrypto.decryptJweCompact(value, {
        privateKey: enc.privateKey, allowedAlg: [JWE_ALG],
        allowedEnc: [JWE_ENC], expectedKid: enc.publicJwk.kid });
      const jws = Buffer.isBuffer(opened.plaintext)
        ? opened.plaintext.toString('utf8') : String(opened.plaintext);
      const head = JSON.parse(Buffer.from(jws.split('.')[0], 'base64url')
        .toString('utf8'));
      if (head.typ !== TOKEN_TYPE) {
        throw new Error('the inner token is typ "' + head.typ + '"');
      }
      const key = this.deps.verifiers().get(String(head.kid || ''));
      if (!key) {
        throw new Error('no browser device key of this realm is "' +
                        head.kid + '"');
      }
      const checked = stsCrypto.verifyCompactJws(jws, key,
                                                 { algorithms: ['ES256'] });
      const c = checked.claims || {};
      const now = Math.floor(this.deps.now() / 1000);
      if (c.iss !== this.audience() || c.aud !== this.audience()) {
        throw new Error('the token is for "' + c.aud + '"');
      }
      if (!(Number(c.exp) > now)) {
        throw new Error('the token expired');
      }
      if (!c.sub || !c.owner || !(Number(c.gen) >= 1)) {
        throw new Error('the token names no device, owner or generation');
      }
      log.debug("Leaving BrowserDevices.read(). Device " + c.sub + ".");
      return c;
    } catch (e) {
      log.info(errorCodes.tag('STS-DEVICE-0040') + 'devices: a remembered ' +
               'browser\'s cookie could not be read: ' +
               ((e && e.message) || e));
      log.debug("Leaving BrowserDevices.read(). Unreadable.");
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // RECOGNISING. What `device_recognition.ts` asks for a request that carries
  // the cookie: the device, and what is odd about the token. A REPLAYED
  // generation marks the device compromised HERE, once per request (the
  // caller memoises), because that is the moment the copy is known.
  // -------------------------------------------------------------------------
  recognize(req: Json, subject?: unknown): Json {
    const { log, devices, errorCodes } = this.deps;
    log.debug("Entering BrowserDevices.recognize().");
    if (!this.enabled()) {
      log.debug("Leaving BrowserDevices.recognize(). Off.");
      return null;
    }
    const value = this.presented(req);
    if (!value) {
      log.debug("Leaving BrowserDevices.recognize(). No cookie.");
      return null;
    }
    const claims = this.read(value);
    const device = claims ? devices.byId(claims.sub) : null;
    if (!claims || !device || !device.browser) {
      log.debug("Leaving BrowserDevices.recognize(). Not a browser device.");
      return { device: null, unreadable: true };
    }
    const state = device.browser;
    const gen = Number(claims.gen);
    const held = Number(state.gen) || 0;
    const graceMs = Math.max(0, Number(this.deps.config.value(
      'devices.browserReissueGraceSeconds')) || 0) * 1000;
    const issuedMs = Date.parse(String(state.issuedAt || '')) || 0;
    const flags: Json = { replayed: false, stale: false, foreign: false,
                          contextChanged: false };
    if (gen === held - 1 && this.deps.now() - issuedMs <= graceMs) {
      flags.stale = true;
    } else if (gen !== held) {
      flags.replayed = true;
    }
    if (subject !== undefined && subject !== null && String(subject) &&
        String(claims.owner) !== String(subject)) {
      flags.foreign = true;
    }
    const browser = BrowserDevices.browserOf(req && req.headers &&
                                             req.headers['user-agent']);
    if (state.context && state.context.ua && state.context.ua !== browser) {
      flags.contextChanged = true;
    }
    if (flags.replayed && device.status !== 'compromised') {
      log.warn(errorCodes.tag('STS-DEVICE-0041') + 'devices: remembered ' +
               'browser ' + device.id + ' presented generation ' + gen +
               ' where it holds ' + held + ': the cookie was copied. The ' +
               'device is marked compromised.');
      devices.setStatus(device.id, 'compromised', 'system',
        'A copy of this remembered browser\'s cookie was used (generation ' +
        gen + ' after ' + held + ').', { initiatingEntity: 'system' });
    }
    if (flags.foreign) {
      log.info(errorCodes.tag('STS-DEVICE-0042') + 'devices: remembered ' +
               'browser ' + device.id + ' belongs to ' + claims.owner +
               ', not ' + String(subject) + '.');
    }
    log.debug("Leaving BrowserDevices.recognize(). " + device.id);
    return { device: devices.byId(device.id) || device, claims: claims,
             flags: flags };
  }

  // -------------------------------------------------------------------------
  // AFTER A SESSION STARTS IN A BROWSER (`authn.startSession()`, the one
  // funnel): the token issued again with the next generation for a browser
  // recognised as the person's own, and a new device registered where the
  // person ticked "Remember this browser". `secondFactor` says whether the
  // session's authentication included a second factor, which restarts the
  // policy's skip period for this browser. A cookie that was copied, is not
  // readable or names a compromised device is CLEARED, so the next sign-in is
  // not refused on it again.
  // -------------------------------------------------------------------------
  afterSignIn(req: Json, res: Json, spec: Json): Json {
    const { log, devices, errorCodes, audit } = this.deps;
    log.debug("Entering BrowserDevices.afterSignIn().");
    const s = spec || {};
    const username = String(s.username || '');
    if (!this.enabled() || !res || !username) {
      log.debug("Leaving BrowserDevices.afterSignIn(). Nothing to do.");
      return { ok: true, acted: 'none' };
    }
    const fact = s.recognized || null;
    const nowIso = new Date(this.deps.now()).toISOString();
    if (fact && fact.via === 'browser-cookie' && fact.browserToken) {
      const t = fact.browserToken;
      if (t.replayed || t.foreign || fact.status === 'compromised') {
        this.clear(res);
        log.debug("Leaving BrowserDevices.afterSignIn(). Cleared.");
        return { ok: true, acted: 'cleared' };
      }
      const device = devices.byId(fact.id);
      if (device && device.browser) {
        const state = Object.assign({}, device.browser, {
          gen: (Number(device.browser.gen) || 0) + 1,
          previousIssuedAt: device.browser.issuedAt || '',
          issuedAt: nowIso,
          mfaAt: s.secondFactor ? nowIso : (device.browser.mfaAt || '')
        });
        const token = this.mint(device.id, username, state.gen);
        if (token && devices.setBrowserState(device.id, state)) {
          this.setCookie(res, token, this.lifetimeS());
          log.debug("Leaving BrowserDevices.afterSignIn(). Reissued.");
          return { ok: true, acted: 'reissued', device: device.id };
        }
        if (token) {
          log.warn(errorCodes.tag('STS-DEVICE-0045') + 'devices: remembered ' +
                   'browser ' + device.id + '\'s state could not be ' +
                   'written; its token was not issued again.');
        }
        log.debug("Leaving BrowserDevices.afterSignIn(). Kept.");
        return { ok: false, acted: 'kept' };
      }
    } else if (this.presented(req) && (!fact || fact.unreadable)) {
      this.clear(res);
    }
    if (!s.remember) {
      log.debug("Leaving BrowserDevices.afterSignIn(). Not asked.");
      return { ok: true, acted: 'none' };
    }
    const made = this.remember(req, res, username, !!s.secondFactor);
    log.debug("Leaving BrowserDevices.afterSignIn(). " + made.acted);
    return made;
  }

  // -------------------------------------------------------------------------
  // REGISTERING THIS BROWSER for a signed-in person — the sign-in screen's
  // checkbox (through afterSignIn()) and /portal/devices' button. Refused
  // (STS-DEVICE-0044) when the feature is off; a browser already remembered
  // for this person is simply issued its token again.
  // -------------------------------------------------------------------------
  remember(req: Json, res: Json, username: string,
           secondFactor: boolean): Json {
    const { log, devices, errorCodes, audit } = this.deps;
    log.debug("Entering BrowserDevices.remember().");
    if (!this.enabled()) {
      log.debug("Leaving BrowserDevices.remember(). Off.");
      return errorCodes.mark({ ok: false, acted: 'refused',
        error: 'Remembering browsers is switched off in this realm ' +
               '(devices.browserDevices).' }, 'STS-DEVICE-0044');
    }
    const nowIso = new Date(this.deps.now()).toISOString();
    const browser = BrowserDevices.browserOf(req && req.headers &&
                                             req.headers['user-agent']);
    const state = { gen: 1, issuedAt: nowIso, previousIssuedAt: '',
                    context: { ua: browser },
                    mfaAt: secondFactor ? nowIso : '' };
    const created = devices.create({
      method: 'browser', owner: username, ownerKind: 'person',
      label: browser, platform: BrowserDevices.platformOf(browser),
      browser: state }, username, { initiatingEntity: 'user' });
    if (!created.ok) {
      log.debug("Leaving BrowserDevices.remember(). Not created.");
      return errorCodes.mark({ ok: false, acted: 'refused',
        error: String(created.error || (created.errors || [])[0] ||
                      'The browser could not be registered.') },
        errorCodes.codeOf(created) || 'STS-DEVICE-0044');
    }
    const token = this.mint(created.device.id, username, 1);
    if (!token) {
      devices.remove(created.device.id, username, username,
                     { quiet: true });
      log.debug("Leaving BrowserDevices.remember(). Too large.");
      return errorCodes.mark({ ok: false, acted: 'refused',
        error: 'This browser could not be remembered: its token would not ' +
               'fit in a cookie.' }, 'STS-DEVICE-0043');
    }
    this.setCookie(res, token, this.lifetimeS());
    audit.audit({ action: 'device.browser.remembered', outcome: 'success',
      actor: username, target: username, channel: 'http',
      summary: username + ' asked this service to remember ' + browser +
               ' (device ' + created.device.id + ')',
      detail: { device: created.device.id, browser: browser } });
    log.debug("Leaving BrowserDevices.remember(). " + created.device.id);
    return { ok: true, acted: 'remembered', device: created.device.id };
  }

  // -------------------------------------------------------------------------
  // MAY THIS SIGN-IN SKIP THE SECOND FACTOR? (#265 decision 3.) Every
  // condition in the header; the realm's two policy fields are the only part
  // an administrator can move.
  // -------------------------------------------------------------------------
  skipsSecondFactor(spec: Json): Json {
    const { log, authnPolicy } = this.deps;
    log.debug("Entering BrowserDevices.skipsSecondFactor().");
    const s = spec || {};
    const no = function (why: string): Json {
      log.debug("Leaving BrowserDevices.skipsSecondFactor(). No: " + why);
      return { skip: false, why: why };
    };
    const policy = authnPolicy.rememberedBrowser();
    if (!policy.skipsSecondFactor) {
      return no('the authentication policy does not allow it');
    }
    if (!this.enabled()) {
      return no('devices.browserDevices is off');
    }
    const fact = s.fact || null;
    if (!fact || fact.via !== 'browser-cookie' || !fact.browserToken) {
      return no('no remembered browser');
    }
    const t = fact.browserToken;
    if (t.replayed || t.foreign || t.contextChanged ||
        fact.status === 'compromised' || fact.ownerMatches === false) {
      return no('the remembered browser is not trusted for this');
    }
    if (NEVER_SKIP_CLIENTS.indexOf(String(s.clientId || '')) >= 0) {
      return no('the admin console, user portal and debugger always ask');
    }
    const roles = this.deps.consoleRolesOf(String(s.username || '')) || {};
    if (roles.read || roles.write) {
      return no('an administrator is always asked');
    }
    const level = String(s.riskLevel || '').toUpperCase();
    if (level === 'MEDIUM' || level === 'HIGH') {
      return no('the sign-in\'s risk is ' + level);
    }
    const device = this.deps.devices.byId(fact.id);
    const mfaAt = Date.parse(String((device && device.browser &&
                                     device.browser.mfaAt) || '')) || 0;
    if (!mfaAt ||
        this.deps.now() - mfaAt > policy.days * 86400 * 1000) {
      return no('the second factor was not given on this browser in the ' +
                'last ' + policy.days + ' days');
    }
    log.debug("Leaving BrowserDevices.skipsSecondFactor(). Yes.");
    return { skip: true, why: 'a browser the person chose to remember, ' +
             'where they gave their second factor on ' +
             new Date(mfaAt).toISOString().slice(0, 10) };
  }

  // Did an authentication include a SECOND factor? `mfa` says so outright;
  // otherwise it is two methods of which one is a second-factor method —
  // `["pwd","otp"]` yes, a passwordless `["hwk"]` alone no (one factor).
  static hasSecondFactor(amr: unknown): boolean {
    helpers.log.debug("Entering BrowserDevices.hasSecondFactor().");
    const list = (Array.isArray(amr) ? amr : []).map(String);
    const yes = list.indexOf('mfa') >= 0 ||
      (list.length > 1 && list.some(function (m: string): boolean {
        return SECOND_FACTOR_AMR.indexOf(m) >= 0;
      }));
    helpers.log.debug("Leaving BrowserDevices.hasSecondFactor(). " + yes);
    return yes;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<BrowserDevices>(
  'common/browser_devices',
  () => new BrowserDevices(BrowserDevices.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  BrowserDevices: BrowserDevices,
  installInstance: (instance: BrowserDevices): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  TOKEN_TYPE: TOKEN_TYPE,
  MAX_TOKEN_BYTES: MAX_TOKEN_BYTES,
  NEVER_SKIP_CLIENTS: NEVER_SKIP_CLIENTS,
  browserOf: BrowserDevices.browserOf,
  hasSecondFactor: BrowserDevices.hasSecondFactor,
  enabled: slot.forward('enabled'),
  cookieName: slot.forward('cookieName'),
  presented: slot.forward('presented'),
  clear: slot.forward('clear'),
  mint: slot.forward('mint'),
  read: slot.forward('read'),
  recognize: slot.forward('recognize'),
  afterSignIn: slot.forward('afterSignIn'),
  remember: slot.forward('remember'),
  skipsSecondFactor: slot.forward('skipsSecondFactor')
};
