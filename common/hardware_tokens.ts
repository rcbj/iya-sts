// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: hardware_tokens.ts
//
// ===========================================================================
// THE HARDWARE TOKEN REGISTER (#1955 P1, design X1, X2 and X3).
//
// One physical token — a YubiKey, a smart card — holds several credentials:
// FIDO credentials, PIV certificates, and in later phases a Yubico OTP
// public id, OATH secrets, SSH and OpenPGP keys. This register keeps ONE
// RECORD PER TOKEN in a realm, keyed by (vendor, serial):
//
//   { vendor, serial, model, firmware, formFactor,
//     holder         the entryUUID of the person who holds it,
//     credentials:   [{ kind, ref, holder, family?, addedAt, evidence }],
//     evidence:      [{ source, at, format?, aaguid?, keyId?, detail? }],
//     status:        'active' | 'lost',
//     lost:          { at, by, via, retired: [...] } | null,
//     registeredAt, updatedAt }
//
// **A SERIAL IS RECORDED ONLY FROM ATTESTATION.** The one writer,
// `recordAttested()`, takes an evidence SOURCE from a closed list
// (`EVIDENCE_SOURCES`): today the FIDO enterprise attestation serial (#532,
// `pki.attestationDeviceSerial()`, read by `authn/webauthn_attestation.ts`
// only for an enterprise request), and the PIV attestation and an
// administrator's vendor import that P2 and P4 add. No door takes a serial
// from a request body: a self-declared serial would let anybody claim
// somebody else's key, and every later rule (X3, X4) reads this register as
// evidence.
//
// **WHY A REGISTER OF ITS OWN AND NOT THE DEVICE REGISTER (#164).** The
// design said "extends the device register"; the code says otherwise, and
// the code is right. A device here is the computer or phone a person signs
// in FROM: `device_enrolment.ts` refuses to link a roaming authenticator
// ("it is carried between devices and identifies none of them",
// STS-DEVICE-0022), and everything that reads the device register reads it
// that way — device recognition puts `registeredDevice` on every sign-in
// event whose credential a device holds, the compliant-device acr and the
// `DEVICE.*` XACML attributes are met by a recognised device, risk scoring
// asks `holdsAny()`, `devices.maxPerPerson` evicts a person's least
// recently used device at a Native SSO sign-in, and a compromise ends the
// sessions the device's keys authenticated. A YubiKey filed there would
// make every sign-in with it "from a registered device" and could be
// evicted by a phone's sign-in. So a token is a sibling register, and the
// two meet where they should: the console draws both under Directory, and
// the device page's word for a security key ("security key (Security Key
// NFC by Yubico)", `credentials.keyKind()`) is the model this register
// records.
//
// **WHERE IT IS KEPT.** A per-realm store at its declaration
// (`realms.map()`, `persist: 'hardware_tokens.register'`), cell tier
// (`persistence/tiers.js`: a token is somebody's), sealed in `sts_minted`
// like every other minted row, ON DEMAND (#820) with an index: by holder
// (`h:`), by serial (`s:`) and by credential (`c:<kind>:<ref>`), rewritten
// on every `set()` (the upsert replaces a row's index rows), so a person's
// tokens and a credential's token are one indexed question, never a walk. No
// table is added, so no schema version and no upgrade script. **Like every
// minted store it is not kept across a restart in DEVELOPMENT mode**
// (`persistence/CLAUDE.md`), where the certificate authorities are not
// either; in product mode it is.
//
// **THE BOUND** is the credentials it indexes: a record exists only with a
// credential on it, and a person's FIDO credentials are capped by
// `webauthn.maxKeysPerPerson` at the one writer (`credentials.addKey()`),
// so this register cannot grow faster than the keys it describes. A token
// holds at most MAX_CREDENTIALS credentials and MAX_EVIDENCE evidence rows,
// the oldest dropped at the insert.
//
// **THE LOST-KEY ACT (X2) IS A DISPATCH BY CREDENTIAL KIND.** `markLost()`
// marks the token lost FIRST (so a sign-in racing it already finds the
// token lost — `evidenceFor()` answers nothing for a lost token) and then
// hands each credential to the RETIRER registered for its kind. Two are
// built in, reached lazily so this file closes no cycle:
//
//   * `fido`: the credential is REMOVED from the person's entry
//     (`credentials.removeKey(..., { lost: true })`), a CAEP
//     credential-change `delete` is sent, and the sessions it signed in
//     end. Removed rather than "disabled": no sign-in door reads a disabled
//     mark on a key (`attestationAtSignIn()`, the passkey step, the
//     usernameless ceremony, the device link and step-up all look the key
//     up and use it), so a mark would be a promise kept by some doors;
//     a removed key is refused by every one. A found key is registered
//     again. `{ lost: true }` passes the last-way-in guard: a lost key is
//     not a way in for its holder and is one for whoever found it.
//   * `x509`: the certificate is revoked for keyCompromise through
//     `cert_enrollment.revokeEnrolled()`, the existing path, which updates
//     the CRL and OCSP, stamps the entry's record and sends CAEP's
//     certificate credential-change and RISC's credential-compromise.
//
// **`registerRetirer(kind, retirer)` IS A HOOK, ARGUED UNDER RULE 3e.**
// Later phases' modules (HOTP and PSKC, Yubico OTP, the SSH CA, OpenPGP)
// each RECORD their credentials here, so each requires this file; this file
// requiring them back to retire their credentials would close a cycle every
// time, and the other way round — each phase editing `markLost()` to call
// its module lazily — is a dispatch written as a chain of ifs that a new
// kind can be missing from with nothing failing. The hook is validated
// WHOLE (`retire` a function, `label` a string, a kind from `CREDENTIAL_
// KINDS`), and a credential of a kind with no retirer is NOT silently
// skipped: it is reported as not retired (STS-HWTOKEN-0009) on the answer
// and the audit row, so the page says which credential is still live.
//
// **X3: WHAT A CERTIFICATE SIGN-IN MAY CLAIM.** `evidenceFor('x509', serial)`
// answers whether an active token's attestation evidence covers the key
// (`hardware`) and whether that evidence says the key is on a smart card
// (`smartCard`, which earns RFC 8176 `sc`). PKINIT and the two certificate
// sign-in doors ask it. The old PKINIT inference (smart-card-logon EKU and a
// key this service did not generate) stays as the realm setting
// `hardwareTokens.hardwareClaims`: `inference` (the default, the behaviour
// before #1955, with evidence ADDED) or `evidence` (only recorded evidence
// earns `hwk` and `pkinit-hardware`), which P2 switches PIV to.
//
// A LIBRARY (rule 3): it registers no route. It requires `realms`, `config`,
// `audit`, `error_codes` and `helpers`; `credentials`, `cert_enrollment`,
// `ssf/account_signals` and `logout/logout` are reached at the moment of
// use.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import realms = require('./realms');
import config = require('./config');
import audit = require('./audit');
import errorCodes = require('./error_codes');
import cacheRegistry = require('./cache_registry');

type Json = any;

/**
 * The kinds of credential a token record lists. `fido` and `x509` are
 * recorded since #1955 P1; `hotp` and `totp` since P4 (an OATH token an
 * administrator imported from its vendor's PSKC file, `common/oath_tokens.ts`,
 * which registers both retirers); `yubico-otp` (P5), `ssh` (P3) and
 * `openpgp` (P6) are reserved for the phases that add them, each with its
 * own retirer (`registerRetirer()`).
 */
const CREDENTIAL_KINDS = ['fido', 'x509', 'hotp', 'totp', 'yubico-otp',
                          'ssh', 'openpgp'];

/**
 * Where a serial may come from: the FIDO enterprise attestation (#532), a
 * PIV key attestation (P2), an administrator's vendor import, and since P4
 * `pskc-import`: an OATH token's serial from the DeviceInfo of its vendor's
 * RFC 6030 seed file, recorded when the token is assigned or claimed. A
 * secret enrolled from a QR code names no serial and is never recorded.
 * Nothing else records a serial.
 */
const EVIDENCE_SOURCES = ['fido-enterprise-attestation', 'piv-attestation',
                          'vendor-import', 'pskc-import'];

/** A token's status: `active` or `lost`. */
const STATUSES = ['active', 'lost'];

/** What `hardwareTokens.hardwareClaims` may be. */
const HARDWARE_CLAIMS = ['inference', 'evidence'];

/** How a token is physically made, where its evidence says. */
const FORM_FACTORS = ['', 'usb-a', 'usb-c', 'nfc', 'lightning', 'smart-card',
                      'other'];

const MAX_CREDENTIALS = 64;
const MAX_EVIDENCE = 16;
const MAX_TEXT = 128;
// The most rows one console page asks for; the newest-rows question the
// on-demand store answers is capped at a thousand (`minted.newest`).
const MAX_PAGE = 500;
const NEWEST_CAP = 1000;

// ---------------------------------------------------------------------------
// THE REGISTER, per realm at its declaration. On demand (#820): a process
// holds the tokens it was asked about, and finds a person's or a
// credential's through the index. `indexBy` and `sortBy` run on every row a
// flush writes, so neither has an Entering/Leaving pair (a hot path).
// ---------------------------------------------------------------------------
const register = realms.map({
  persist: 'hardware_tokens.register',
  onDemand: { maxEntries: 5000 },
  indexBy: function (record: Json): string[] {
    const out: string[] = [];
    if (!record) {
      return out;
    }
    if (record.holder) {
      out.push('h:' + String(record.holder));
    }
    if (record.serial) {
      out.push('s:' + String(record.serial));
    }
    (record.credentials || []).forEach(function (c: Json) {
      if (c && c.kind && c.ref) {
        out.push('c:' + String(c.kind) + ':' + String(c.ref));
      }
      if (c && c.holder && c.holder !== record.holder) {
        out.push('h:' + String(c.holder));
      }
    });
    return out;
  },
  sortBy: function (record: Json): number | null {
    const at = record ? Date.parse(String(record.registeredAt || '')) : NaN;
    return at > 0 ? at : null;
  }
});

cacheRegistry.register({
  name: 'hardware_tokens.register',
  title: 'Hardware token register',
  description: 'One row per physical hardware token (a YubiKey, a smart ' +
    'card) in this realm, keyed by vendor and serial: who holds it, its ' +
    'model and the credentials on it. A serial is recorded only from ' +
    'attestation. Never a secret.',
  owner: 'common/hardware_tokens.ts',
  scope: 'realm',
  kind: 'cache',
  persisted: true,
  settings: [],
  maxEntries: function (): number {
    return 5000;
  },
  bound: 'The rows a process holds are a cache of 5,000 per realm; the ' +
    'register itself is bounded by the credentials it lists ' +
    '(webauthn.maxKeysPerPerson for FIDO).',
  lifetime: function (): string {
    return 'Until the token is removed; a lost token is kept, marked lost.';
  },
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, register,
      function (row: Json, key: unknown): object {
        return { key: String(key) + ' (' + String((row && row.status) ||
                      '?') + ')', basis: 'none' };
      });
  }
});

interface TokenCredential {
  kind: string;
  ref: string;
  holder: string;
  family?: string;
  label?: string;
  addedAt: string;
  evidence: { source: string; hardware: boolean; smartCard: boolean;
              // A PIV slot's key's policies, from its attestation (#1955 P2):
              // per credential, since each slot has its own.
              pinPolicy?: string; touchPolicy?: string };
  retired?: { at: string; ok: boolean; code?: string; why?: string };
}

interface Retirer {
  label: string;
  retire: (token: Json, credential: TokenCredential, ctx: Json) =>
    Promise<Json> | Json;
}

interface HardwareTokensDeps {
  log: typeof helpers.log;
  helpers: typeof helpers;
  config: typeof config;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  now: () => number;
  // Reached at the moment of use (header).
  loadCredentials: () => Json;
  loadEnrollment: () => Json;
  loadSignals: () => Json;
  loadLogout: () => Json;
}

/**
 * The hardware token register (#1955 P1): one record per physical token,
 * keyed by vendor and serial, with the credentials on it.
 */
class HardwareTokens {
  static readonly CREDENTIAL_KINDS = CREDENTIAL_KINDS;
  static readonly EVIDENCE_SOURCES = EVIDENCE_SOURCES;
  static readonly STATUSES = STATUSES;
  static readonly HARDWARE_CLAIMS = HARDWARE_CLAIMS;
  static readonly FORM_FACTORS = FORM_FACTORS;
  static readonly MAX_PAGE = MAX_PAGE;

  private readonly retirers: Record<string, Retirer> = {};

  /**
   * Builds the register over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: HardwareTokensDeps) {
    deps.log.debug("Entering HardwareTokens.constructor().");
    this.installBuiltInRetirers();
    deps.log.debug("Leaving HardwareTokens.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): HardwareTokensDeps {
    helpers.log.debug("Entering HardwareTokens.defaultDeps().");
    helpers.log.debug("Leaving HardwareTokens.defaultDeps().");
    return {
      log: helpers.log, helpers: helpers, config: config, audit: audit,
      errorCodes: errorCodes, now: Date.now,
      loadCredentials: function (): Json {
        return require('./credentials');
      },
      loadEnrollment: function (): Json {
        return require('./cert_enrollment');
      },
      loadSignals: function (): Json {
        return require('../ssf/account_signals');
      },
      // `logout/logout` requires the directory, whose JavaScript module
      // registers routes at its require: reached only inside an act, when
      // the stack is long loaded (rule 1).
      loadLogout: function (): Json {
        return require('../logout/logout');
      }
    };
  }

  // -------------------------------------------------------------------------
  // NAMES. A vendor is a lower-case slug; Yubico is `yubico` whichever place
  // named it (the serial extension, an attestation certificate's O=), so a
  // YubiKey's FIDO and PIV evidence meet on one record.
  // -------------------------------------------------------------------------
  /**
   * A vendor's name as the register keys it.
   *
   * @param text - what the evidence named
   * @returns the slug, or '' for nothing usable
   */
  static vendorSlug(text: unknown): string {
    helpers.log.debug("Entering HardwareTokens.vendorSlug().");
    const raw = String(text || '').trim();
    if (/yubico/i.test(raw)) {
      helpers.log.debug("Leaving HardwareTokens.vendorSlug(). Yubico.");
      return 'yubico';
    }
    const slug = raw.toLowerCase().replace(/[^a-z0-9:-]+/g, '-')
      .replace(/^-+|-+$/g, '').slice(0, 64);
    helpers.log.debug("Leaving HardwareTokens.vendorSlug().");
    return slug;
  }

  /**
   * The register's key for a token.
   *
   * @param vendor - the vendor slug
   * @param serial - the serial
   * @returns `<vendor>/<serial>`
   */
  static keyOf(vendor: string, serial: string): string {
    helpers.log.debug("Entering HardwareTokens.keyOf().");
    helpers.log.debug("Leaving HardwareTokens.keyOf().");
    return HardwareTokens.vendorSlug(vendor) + '/' + String(serial || '');
  }

  // The FIDO half of the vendor question: the serial's place names Yubico,
  // else the attestation's model's maker, else the AAGUID — a serial is
  // unique per maker, and an AAGUID names one maker's model.
  /**
   * The vendor a FIDO attestation's serial belongs to.
   *
   * @param attestation - the key's recorded attestation
   * @returns the vendor slug
   */
  static fidoVendor(attestation: Json): string {
    helpers.log.debug("Entering HardwareTokens.fidoVendor().");
    const a = attestation || {};
    let out = '';
    if (a.deviceSerialSource === 'yubico-extension' ||
        /yubico|yubikey/i.test(String(a.model || '')) ||
        /yubico/i.test(String(a.deviceVendor || ''))) {
      out = 'yubico';
    } else if (a.deviceVendor) {
      out = HardwareTokens.vendorSlug(a.deviceVendor);
    }
    if (!out && a.aaguid) {
      out = 'aaguid:' + String(a.aaguid).toLowerCase();
    }
    helpers.log.debug("Leaving HardwareTokens.fidoVendor(). " + out);
    return out;
  }

  // A certificate is referred to by its serial in lower-case hex with no
  // leading zeros and no separators (`pki.certificateSerialHex()`'s form,
  // and what a TLS peer certificate's `serialNumber` becomes), so the
  // writer and every reader agree; any other kind's reference is as given.
  /**
   * A credential reference as the register files it.
   *
   * @param kind - the credential's kind
   * @param ref - its reference
   * @returns the reference, normalised
   */
  static refOf(kind: string, ref: unknown): string {
    helpers.log.debug("Entering HardwareTokens.refOf().");
    const text = HardwareTokens.text(ref);
    const out = kind === 'x509'
      ? text.toLowerCase().replace(/[^0-9a-f]/g, '').replace(/^0+(?=.)/, '')
      : text;
    helpers.log.debug("Leaving HardwareTokens.refOf().");
    return out;
  }

  private holderOf(username: string): string {
    const { log, helpers: h } = this.deps;
    log.debug("Entering HardwareTokens.holderOf().");
    const sub = String(h.subjectForName(username) || '');
    log.debug("Leaving HardwareTokens.holderOf().");
    return sub.indexOf('urn:uuid:') === 0 ? sub.slice(9) : '';
  }

  private nameOfHolder(holder: string): string {
    const { log, helpers: h } = this.deps;
    log.debug("Entering HardwareTokens.nameOfHolder().");
    const name = holder ? String(h.nameForSubject('urn:uuid:' + holder) ||
                                 '') : '';
    log.debug("Leaving HardwareTokens.nameOfHolder().");
    return name;
  }

  private nowIso(): string {
    return new Date(this.deps.now()).toISOString();
  }

  private refuse(code: string, why: string, extra?: Json): Json {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering HardwareTokens.refuse(). " + code);
    const out = Object.assign({ ok: false, error: why, errors: [why] },
                              extra || {});
    log.debug("Leaving HardwareTokens.refuse().");
    return codes.mark(out, code);
  }

  private static text(value: unknown): string {
    return String(value === undefined || value === null ? '' : value)
      .replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, MAX_TEXT);
  }

  // -------------------------------------------------------------------------
  // THE ONE WRITER (header). `spec`:
  //   { username, vendor, serial, model?, firmware?, formFactor?,
  //     credential: { kind, ref, family?, label? },
  //     evidence: { source, format?, aaguid?, keyId?, smartCard?, detail? },
  //     actor?, via? }
  // A lost token registered again starts a new life as active: what the
  // physical key holds now is new credentials, and the old ones were
  // retired when it was reported lost. The lost record is kept on
  // `previousLoss`.
  // -------------------------------------------------------------------------
  /**
   * Records a credential on a token, the serial taken from attestation.
   *
   * @param spec - the person, the token, the credential and the evidence
   * @returns `{ ok, token, created }`, or a refusal
   */
  recordAttested(spec: Json): Json {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.recordAttested().");
    const s = spec || {};
    const ev = s.evidence || {};
    const cred = s.credential || {};
    if (EVIDENCE_SOURCES.indexOf(String(ev.source || '')) < 0) {
      log.debug("Leaving HardwareTokens.recordAttested(). No evidence.");
      return this.refuse('STS-HWTOKEN-0001', 'A token\'s serial is ' +
        'recorded only from attestation (' + EVIDENCE_SOURCES.join(', ') +
        '); "' + HardwareTokens.text(ev.source) + '" is not one.');
    }
    const vendor = HardwareTokens.vendorSlug(s.vendor);
    const serial = HardwareTokens.text(s.serial);
    if (!vendor || !serial || !/^[\x21-\x7e]{1,64}$/.test(serial)) {
      log.debug("Leaving HardwareTokens.recordAttested(). No serial.");
      return this.refuse('STS-HWTOKEN-0002', 'The attestation named no ' +
        'vendor and serial this register can key a token by.');
    }
    const kind = String(cred.kind || '');
    const ref = HardwareTokens.refOf(kind, cred.ref);
    if (CREDENTIAL_KINDS.indexOf(kind) < 0 || !ref) {
      log.debug("Leaving HardwareTokens.recordAttested(). Credential.");
      return this.refuse('STS-HWTOKEN-0003', 'Unknown credential kind "' +
        HardwareTokens.text(kind) + '" or an empty reference. The kinds ' +
        'are ' + CREDENTIAL_KINDS.join(', ') + '.');
    }
    const holder = this.holderOf(String(s.username || ''));
    if (!holder) {
      log.debug("Leaving HardwareTokens.recordAttested(). Nobody.");
      return this.refuse('STS-HWTOKEN-0004', 'The person "' +
        HardwareTokens.text(s.username) + '" has no directory entry to ' +
        'hold a token.');
    }
    const key = HardwareTokens.keyOf(vendor, serial);
    const now = this.nowIso();
    const held: Json = register.get(key) || null;
    const created = !held || held.status === 'lost';
    const formFactor = FORM_FACTORS.indexOf(String(s.formFactor || '')) >= 0
      ? String(s.formFactor || '') : 'other';
    const base: Json = created ? {
      vendor: vendor, serial: serial, holder: holder,
      model: HardwareTokens.text(s.model), firmware:
        HardwareTokens.text(s.firmware), formFactor: formFactor,
      credentials: [], evidence: [], status: 'active', lost: null,
      registeredAt: now, updatedAt: now,
      previousLoss: held && held.status === 'lost' ? held.lost : null
    } : JSON.parse(JSON.stringify(held));
    const previousHolder = created ? '' : String(base.holder || '');
    // The latest attested credential names the holder: whoever registered
    // something on the physical key last has it. A change is audited.
    base.holder = holder;
    if (s.model) {
      base.model = HardwareTokens.text(s.model);
    }
    if (s.firmware) {
      base.firmware = HardwareTokens.text(s.firmware);
    }
    if (s.formFactor && FORM_FACTORS.indexOf(String(s.formFactor)) >= 0) {
      base.formFactor = String(s.formFactor);
    }
    const smartCard = ev.smartCard === true || base.formFactor ===
      'smart-card';
    const entry: TokenCredential = {
      kind: kind, ref: ref, holder: holder, addedAt: now,
      evidence: { source: String(ev.source), hardware: true,
                  smartCard: kind === 'x509' && smartCard }
    };
    // WHAT A PIV ATTESTATION SAID OF THE KEY (#1955 P2, design X4): kept on
    // the credential for the issuance policy's attributes.
    if (ev.pinPolicy) {
      entry.evidence.pinPolicy = HardwareTokens.text(ev.pinPolicy);
    }
    if (ev.touchPolicy) {
      entry.evidence.touchPolicy = HardwareTokens.text(ev.touchPolicy);
    }
    // And of the token: a FIPS-certified key, said by its f9 certificate.
    if (s.fips === true) {
      base.fips = true;
    }
    if (cred.family) {
      entry.family = HardwareTokens.text(cred.family);
    }
    if (cred.label) {
      entry.label = HardwareTokens.text(cred.label);
    }
    base.credentials = (base.credentials || []).filter(function (c: Json) {
      return !(c.kind === kind && c.ref === ref);
    }).concat([entry]).slice(-MAX_CREDENTIALS);
    base.evidence = (base.evidence || []).concat([{
      source: String(ev.source), at: now,
      format: HardwareTokens.text(ev.format),
      aaguid: HardwareTokens.text(ev.aaguid),
      keyId: HardwareTokens.text(ev.keyId),
      detail: HardwareTokens.text(ev.detail)
    }]).slice(-MAX_EVIDENCE);
    base.updatedAt = now;
    register.set(key, base);
    const username = String(s.username || '');
    this.recordAudit(created ? 'hardware-token.create'
                             : 'hardware-token.credential-add',
      s.actor || username, username,
      (created ? 'Hardware token ' : 'A credential was added to hardware ' +
        'token ') + vendor + ' ' + serial + ' (' + kind + ', from ' +
        ev.source + ')',
      { key: key, kind: kind, source: ev.source, via: s.via || '' });
    if (previousHolder && previousHolder !== holder) {
      log.info('hardware_tokens: token ' + key + ' was registered by ' +
               'another person than the one who held it.');
      this.recordAudit('hardware-token.holder-change', s.actor || username,
        username, 'Hardware token ' + key + ' changed hands',
        { key: key, previousHolder: this.nameOfHolder(previousHolder) });
    }
    log.debug("Leaving HardwareTokens.recordAttested(). " +
              (created ? 'Created.' : 'Updated.'));
    return { ok: true, token: this.view(key, base), created: created };
  }

  // -------------------------------------------------------------------------
  // A CREDENTIAL ON A TOKEN THAT IS NOT EVIDENCE (#1955 P2, D7): an escrowed
  // piv-key-management certificate whose key this service generated and the
  // holder loaded onto one of their tokens. It RECORDS NO SERIAL — the token
  // is already in the register, from its own attestation — and its evidence
  // says `hardware: false`, so `evidenceFor()` earns it nothing; it is here
  // only so that the lost-key act retires it with the rest of the card. The
  // token must be active and the holder's.
  // -------------------------------------------------------------------------
  /**
   * Adds a non-evidence credential to an active token its holder names.
   *
   * @param spec - `key`, `username`, `credential: { kind, ref, family?,
   *   label? }`, `actor`
   * @returns `{ ok, token }`, or a refusal
   */
  attachCredential(spec: Json): Json {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.attachCredential().");
    const s = spec || {};
    const key = String(s.key || '');
    const holder = this.holderOf(String(s.username || ''));
    const held: Json = register.get(key) || null;
    if (!held || !holder || held.status !== 'active' ||
        held.holder !== holder) {
      log.debug("Leaving HardwareTokens.attachCredential(). Not theirs.");
      return this.refuse('STS-PIV-0025', 'No active hardware token "' +
        HardwareTokens.text(key) + '" is held by you.');
    }
    const cred = s.credential || {};
    const kind = String(cred.kind || '');
    const ref = HardwareTokens.refOf(kind, cred.ref);
    if (CREDENTIAL_KINDS.indexOf(kind) < 0 || !ref) {
      log.debug("Leaving HardwareTokens.attachCredential(). Credential.");
      return this.refuse('STS-HWTOKEN-0003', 'Unknown credential kind "' +
        HardwareTokens.text(kind) + '" or an empty reference.');
    }
    const next = JSON.parse(JSON.stringify(held));
    const entry: TokenCredential = {
      kind: kind, ref: ref, holder: holder, addedAt: this.nowIso(),
      evidence: { source: 'escrow', hardware: false, smartCard: false }
    };
    if (cred.family) {
      entry.family = HardwareTokens.text(cred.family);
    }
    if (cred.label) {
      entry.label = HardwareTokens.text(cred.label);
    }
    next.credentials = (next.credentials || []).filter(function (c: Json) {
      return !(c.kind === kind && c.ref === ref);
    }).concat([entry]).slice(-MAX_CREDENTIALS);
    next.updatedAt = this.nowIso();
    register.set(key, next);
    this.recordAudit('hardware-token.credential-add',
      String(s.actor || s.username || ''), String(s.username || ''),
      'An escrowed credential was noted on hardware token ' + key + ' (' +
      kind + ', not evidence)', { key: key, kind: kind, source: 'escrow' });
    log.debug("Leaving HardwareTokens.attachCredential(). Attached.");
    return { ok: true, token: this.view(key, next) };
  }

  // -------------------------------------------------------------------------
  // THE FIDO DOOR: a key `credentials.addKey()` has just written. Only a key
  // whose attestation this service verified AND trusts, from an enterprise
  // request, carries a serial (`webauthn_attestation.ts` records it only
  // then), so a key without one is no token and answers null quietly.
  // -------------------------------------------------------------------------
  /**
   * Records a FIDO credential just written, when its attestation named a
   * device serial.
   *
   * @param username - the person
   * @param key - the stored key record
   * @param opts - `actor`, `via`
   * @returns the writer's answer, or null when the key names no serial
   */
  noteFidoKey(username: string, key: Json, opts?: Json): Json {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.noteFidoKey().");
    const att = (key && key.attestation) || {};
    if (!att.deviceSerial || att.verified !== true || att.trusted !== true) {
      log.debug("Leaving HardwareTokens.noteFidoKey(). No attested serial.");
      return null;
    }
    const out = this.recordAttested({
      username: username, vendor: HardwareTokens.fidoVendor(att),
      serial: String(att.deviceSerial), model: String(att.model || ''),
      formFactor: HardwareTokens.formFactorOf(key),
      credential: { kind: 'fido', ref: String(key.credentialId || ''),
                    label: String(key.label || '') },
      evidence: { source: 'fido-enterprise-attestation',
                  format: String(att.format || ''),
                  aaguid: String(att.aaguid || key.aaguid || ''),
                  keyId: String(att.attestationKeyId || ''),
                  detail: String(att.deviceSerialSource || '') },
      actor: (opts && opts.actor) || username,
      via: (opts && opts.via) || 'webauthn'
    });
    log.debug("Leaving HardwareTokens.noteFidoKey().");
    return out;
  }

  // What the transports a FIDO key reported say of how it is made, where
  // they say anything: `nfc` alone is an NFC key, `smart-card` a card.
  /**
   * A FIDO key's form factor, from its transports.
   *
   * @param key - the stored key record
   * @returns one of FORM_FACTORS
   */
  static formFactorOf(key: Json): string {
    helpers.log.debug("Entering HardwareTokens.formFactorOf().");
    const t: string[] = Array.isArray(key && key.transports)
      ? key.transports.map(String) : [];
    const out = t.indexOf('smart-card') >= 0 ? 'smart-card'
      : (t.length === 1 && t[0] === 'nfc' ? 'nfc' : '');
    helpers.log.debug("Leaving HardwareTokens.formFactorOf().");
    return out;
  }

  // A credential that left by another door (a passkey removed on the
  // portal, a certificate revoked by an administrator) is dropped from the
  // record so the page does not list it; the token stays.
  /**
   * Drops a credential from the token that lists it.
   *
   * @param kind - the credential's kind
   * @param ref - its reference
   * @returns true when a record changed
   */
  forgetCredential(kind: string, ref: string): boolean {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.forgetCredential(). " + kind);
    const found = this.byCredential(kind, ref);
    if (!found) {
      log.debug("Leaving HardwareTokens.forgetCredential(). Not listed.");
      return false;
    }
    const next = JSON.parse(JSON.stringify(found.record));
    next.credentials = next.credentials.filter(function (c: Json) {
      return !(c.kind === kind && c.ref === String(ref));
    });
    next.updatedAt = this.nowIso();
    register.set(found.key, next);
    log.debug("Leaving HardwareTokens.forgetCredential(). Dropped.");
    return true;
  }

  // -------------------------------------------------------------------------
  // READS.
  // -------------------------------------------------------------------------
  private byCredential(kind: string, ref: string):
      { key: string; record: Json } | null {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.byCredential().");
    const keys = register.lookup('c:' + kind + ':' + String(ref || ''));
    for (const key of keys) {
      const record = register.get(key);
      // A stale index row answers a record that no longer lists it.
      if (record && (record.credentials || []).some(function (c: Json) {
        return c.kind === kind && c.ref === String(ref);
      })) {
        log.debug("Leaving HardwareTokens.byCredential(). Found.");
        return { key: String(key), record: record };
      }
    }
    log.debug("Leaving HardwareTokens.byCredential(). None.");
    return null;
  }

  /**
   * One token by its key.
   *
   * @param key - `<vendor>/<serial>`
   * @returns its view, or null
   */
  byKey(key: string): Json {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.byKey().");
    const record = register.get(String(key || ''));
    log.debug("Leaving HardwareTokens.byKey().");
    return record ? this.view(String(key), record) : null;
  }

  /**
   * The tokens a person holds, or held, through the holder index.
   *
   * @param username - the person
   * @returns their tokens' views, newest first
   */
  async tokensOf(username: string): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.tokensOf().");
    const holder = this.holderOf(username);
    if (!holder) {
      log.debug("Leaving HardwareTokens.tokensOf(). Nobody.");
      return [];
    }
    let rows: Json[] = [];
    try {
      rows = await register.lookupEntriesAsync('h:' + holder);
    } catch (e) {
      log.debug("Caught in HardwareTokens.tokensOf(): " +
                ((e && e.message) || e));
      // The read pool cannot be asked: what this process holds.
      rows = register.lookup('h:' + holder).map(function (k: Json) {
        return { key: k, value: register.get(k) };
      });
    }
    const seen: Record<string, boolean> = {};
    const out = rows.filter(function (r: Json) {
      const ok = r && r.value && !seen[String(r.key)] &&
        (r.value.holder === holder || (r.value.credentials || [])
          .some(function (c: Json) {
            return c.holder === holder;
          }));
      seen[String(r.key)] = true;
      return ok;
    }).map((r: Json) => {
      return this.view(String(r.key), r.value, holder);
    }).sort(HardwareTokens.newestFirst);
    log.debug("Leaving HardwareTokens.tokensOf(). " + out.length);
    return out;
  }

  private static newestFirst(a: Json, b: Json): number {
    return String(b.registeredAt).localeCompare(String(a.registeredAt));
  }

  // -------------------------------------------------------------------------
  // THE REALM'S LIST, PAGED. Held whole (memory mode, development, an
  // incomplete index) it is the Map, sorted; on demand it is the store's
  // newest rows by `sortBy`, at most a thousand, which the page says. A
  // search by serial or by person is exact and answers any row.
  // -------------------------------------------------------------------------
  /**
   * A page of the realm's tokens.
   *
   * @param opts - `offset`, `limit`, `status`, `q` (a serial, or a
   *   username for that person's tokens)
   * @returns `{ ok, tokens, total, offset, limit, capped }`
   */
  async list(opts?: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.list().");
    const o = opts || {};
    const limit = Math.max(1, Math.min(MAX_PAGE, Number(o.limit) || 25));
    const offset = Math.max(0, Number(o.offset) || 0);
    const status = STATUSES.indexOf(String(o.status || '')) >= 0
      ? String(o.status) : '';
    const q = HardwareTokens.text(o.q);
    let rows: Json[] = [];
    let capped = false;
    let total: number | null = null;
    if (q) {
      const byPerson = await this.tokensOf(q);
      // A serial is one indexed question (`s:`), never a walk.
      let found: Json[] = [];
      try {
        found = await register.lookupEntriesAsync('s:' + q);
      } catch (e) {
        log.debug("Caught in HardwareTokens.list(): " +
                  ((e && e.message) || e));
        // The read pool cannot be asked: what this process holds.
        found = register.lookup('s:' + q).map(function (k: Json) {
          return { key: k, value: register.get(k) };
        });
      }
      const bySerial: Json[] = found.filter(function (r: Json) {
        return r && r.value && String(r.value.serial) === q;
      }).map((r: Json) => {
        return this.view(String(r.key), r.value);
      });
      rows = byPerson.concat(bySerial.filter(function (one) {
        return !byPerson.some(function (p) {
          return p.key === one.key;
        });
      }));
    } else if (register.onDemandLive()) {
      const newest = await register.newestAsync(NEWEST_CAP);
      rows = (newest || []).map((r: Json) => {
        return this.view(String(r.key), r.value);
      });
      total = await register.countAsync();
      capped = total !== null && total > rows.length;
    } else {
      register.forEach((value: Json, key: Json) => {
        rows.push(this.view(String(key), value));
      });
      rows.sort(HardwareTokens.newestFirst);
    }
    if (status) {
      rows = rows.filter(function (r) {
        return r.status === status;
      });
    }
    const out = { ok: true, tokens: rows.slice(offset, offset + limit),
                  total: total !== null && !status && !q ? total
                                                          : rows.length,
                  offset: offset, limit: limit, capped: capped };
    log.debug("Leaving HardwareTokens.list(). " + out.tokens.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // X3: THE EVIDENCE A CREDENTIAL CARRIES. Only an ACTIVE token's: a lost
  // token's credentials prove nothing about where their key is now.
  // -------------------------------------------------------------------------
  /**
   * What recorded attestation evidence says of one credential's key.
   *
   * @param kind - `fido` or `x509` (or a later phase's kind)
   * @param ref - the credential id, or the certificate's serial in hex
   * @returns `{ hardware, smartCard, token, source }`; both false when no
   *   active token lists it
   */
  evidenceFor(kind: string, ref: string): Json {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.evidenceFor(). " + kind);
    const none = { hardware: false, smartCard: false, token: '',
                   source: '', pinPolicy: '', touchPolicy: '', firmware: '',
                   formFactor: '', fips: false };
    const wanted = HardwareTokens.refOf(kind, ref);
    if (!wanted) {
      log.debug("Leaving HardwareTokens.evidenceFor(). No reference.");
      return none;
    }
    let found: Json = null;
    try {
      found = this.byCredential(kind, wanted);
    } catch (e) {
      log.debug("Caught in HardwareTokens.evidenceFor(): " +
                ((e && e.message) || e));
      // A read that failed is no evidence: the claim is not earned.
      found = null;
    }
    if (!found || found.record.status !== 'active') {
      log.debug("Leaving HardwareTokens.evidenceFor(). None.");
      return none;
    }
    const c = (found.record.credentials || []).filter(function (one: Json) {
      return one.kind === kind && String(one.ref) === wanted;
    })[0];
    // The attestation's facts (#1955 P2, X4) beside the evidence: the
    // credential's policies and the token's firmware, form factor and FIPS
    // mark, each '' (false) where the evidence did not say.
    const out = c && c.evidence ? {
      hardware: c.evidence.hardware === true,
      smartCard: c.evidence.smartCard === true,
      token: found.key, source: String(c.evidence.source || ''),
      pinPolicy: String(c.evidence.pinPolicy || ''),
      touchPolicy: String(c.evidence.touchPolicy || ''),
      firmware: String(found.record.firmware || ''),
      formFactor: String(found.record.formFactor || ''),
      fips: found.record.fips === true } : none;
    log.debug("Leaving HardwareTokens.evidenceFor(). " +
              (out.hardware ? 'Hardware.' : 'None.'));
    return out;
  }

  /**
   * Whether the realm still lets the old PKINIT inference earn a hardware
   * claim (`hardwareTokens.hardwareClaims` is `inference`, the default).
   *
   * @returns true when the inference stands
   */
  inferenceAllowed(): boolean {
    const { log, config: cfg } = this.deps;
    log.debug("Entering HardwareTokens.inferenceAllowed().");
    let value = 'inference';
    try {
      value = String(cfg.value('hardwareTokens.hardwareClaims') ||
                     'inference');
    } catch (e) {
      log.debug("Caught in HardwareTokens.inferenceAllowed(): " +
                ((e && e.message) || e));
      // A setting that cannot be read keeps the behaviour before #1955.
      value = 'inference';
    }
    log.debug("Leaving HardwareTokens.inferenceAllowed(). " + value);
    return value !== 'evidence';
  }

  // The certificate sign-in's claim (the two TLS doors): `swk` as before,
  // `hwk` where the evidence says the key is hardware, and `sc` beside it
  // where the evidence says the key is on a smart card. Never inferred: a
  // TLS sign-in had no inference to keep.
  /**
   * The RFC 8176 amr a certificate sign-in earns.
   *
   * @param serialHex - the certificate's serial in hex
   * @returns `['swk']`, `['hwk']` or `['hwk','sc']`
   */
  certificateAmr(serialHex: string): string[] {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.certificateAmr().");
    const ev = this.evidenceFor('x509', String(serialHex || ''));
    const out = ev.hardware ? (ev.smartCard ? ['hwk', 'sc'] : ['hwk'])
                            : ['swk'];
    log.debug("Leaving HardwareTokens.certificateAmr(). " + out.join(','));
    return out;
  }

  // -------------------------------------------------------------------------
  // X2: THE LOST-KEY ACT. `spec`: { key, actor, via, initiatingEntity
  // ('user' | 'admin'), onlyHolder? (a username: the portal, which retires
  // only the caller's own credentials and refuses another's token) }.
  // -------------------------------------------------------------------------
  /**
   * Reports a token lost: marks it, and retires every credential on it
   * through its kind's retirer.
   *
   * @param spec - the token, who acts and through which door
   * @returns `{ ok, token, retired, notRetired }`, or a refusal
   */
  async markLost(spec: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.markLost().");
    const s = spec || {};
    const key = String(s.key || '');
    const record: Json = register.get(key);
    const onlyHolder = s.onlyHolder ? this.holderOf(String(s.onlyHolder))
                                    : '';
    if (!record || (s.onlyHolder && (!onlyHolder ||
                                     record.holder !== onlyHolder))) {
      log.debug("Leaving HardwareTokens.markLost(). Unknown.");
      return this.refuse('STS-HWTOKEN-0005', 'No hardware token "' +
        HardwareTokens.text(key) + '" is ' + (s.onlyHolder
          ? 'held by you.' : 'in this realm\'s register.'));
    }
    if (record.status === 'lost') {
      log.debug("Leaving HardwareTokens.markLost(). Already.");
      return this.refuse('STS-HWTOKEN-0006', 'Hardware token ' + key +
        ' was already reported lost on ' + String((record.lost || {}).at) +
        '.');
    }
    const now = this.nowIso();
    const actor = String(s.actor || '');
    // MARKED FIRST (header): from here no credential on it is evidence.
    const marked = JSON.parse(JSON.stringify(record));
    marked.status = 'lost';
    marked.lost = { at: now, by: actor, via: String(s.via || ''),
                    retired: [] };
    marked.updatedAt = now;
    register.set(key, marked);
    // THE RECOVERY THE LOSS OWES (#724, design X2): a person whose every
    // passkey is on this token is left with nothing as strong, so before
    // the keys go — while `credentials.holdsPasskey()` is still true — a
    // `lost-key` recovery is noted on their entry. The passkey policy's
    // `recoveryAssurance` then holds their next sign-in a passkey did not
    // answer exactly as it holds a reset link's (`not-weaker`: the
    // sign-in screen's set-up step registers a new passkey, and no session
    // until one signs them in); under `any` nothing is written.
    const recoveries = this.noteLossRecoveries(marked, onlyHolder);
    const ctx = { actor: actor, via: String(s.via || ''),
                  initiatingEntity: s.initiatingEntity === 'admin'
                    ? 'admin' : 'user',
                  holderName: this.nameOfHolder(record.holder) };
    const retired: Json[] = [];
    const notRetired: Json[] = [];
    for (const c of (marked.credentials || []) as TokenCredential[]) {
      if (onlyHolder && c.holder && c.holder !== onlyHolder) {
        notRetired.push({ kind: c.kind, ref: c.ref, errorCode:
          'STS-HWTOKEN-0010', why: 'another person registered it' });
        continue;
      }
      const retirer = this.retirers[c.kind];
      if (!retirer) {
        notRetired.push({ kind: c.kind, ref: c.ref,
                          errorCode: 'STS-HWTOKEN-0009',
                          why: 'no retirer is installed for ' + c.kind });
        continue;
      }
      let answer: Json = null;
      try {
        answer = await retirer.retire(marked, c, Object.assign({}, ctx, {
          username: this.nameOfHolder(c.holder || record.holder) }));
      } catch (e) {
        log.debug("Caught in HardwareTokens.markLost(): " +
                  ((e && e.message) || e));
        answer = { ok: false, errorCode: 'STS-HWTOKEN-0007',
                   why: String((e && e.message) || e) };
      }
      const row = { kind: c.kind, ref: c.ref, label: retirer.label,
                    ok: !!(answer && answer.ok),
                    errorCode: answer && !answer.ok
                      ? String(answer.errorCode || 'STS-HWTOKEN-0007') : '',
                    why: answer && !answer.ok ? String(answer.why || '') : '',
                    sessionsEnded: Number((answer && answer.sessionsEnded) ||
                                          0) };
      (row.ok ? retired : notRetired).push(row);
    }
    const done = JSON.parse(JSON.stringify(register.get(key) || marked));
    done.lost = Object.assign({}, done.lost || marked.lost, {
      retired: retired.concat(notRetired).map(function (r) {
        return { kind: r.kind, ref: r.ref, ok: !!r.ok,
                 errorCode: r.errorCode || '' };
      })
    });
    done.credentials = (done.credentials || []).map(function (c: Json) {
      const r = retired.concat(notRetired).filter(function (x) {
        return x.kind === c.kind && x.ref === c.ref;
      })[0];
      return r ? Object.assign({}, c, { retired: { at: now, ok: !!r.ok,
                                                   code: r.errorCode || '' } })
               : c;
    });
    register.set(key, done);
    const target = ctx.holderName;
    this.recordAudit('hardware-token.lost', actor, target,
      'Hardware token ' + key + ' was reported lost: ' + retired.length +
      ' credential(s) retired, ' + notRetired.length + ' not',
      { key: key, via: ctx.via, retired: retired, notRetired: notRetired,
        recoveryNoted: recoveries,
        errorCode: notRetired.length ? notRetired[0].errorCode : undefined });
    if (notRetired.length) {
      // The first row's own code (STS-HWTOKEN-0007, -0009 or -0010, the
      // retirer's), read off the answer; STS-HWTOKEN-0007 when it has none.
      log.error(this.deps.errorCodes.tag(String(notRetired[0].errorCode ||
                                                'STS-HWTOKEN-0007')) +
                'hardware_tokens: token ' + key + ' was reported lost and ' +
                notRetired.length + ' credential(s) on it were not ' +
                'retired.');
    }
    log.debug("Leaving HardwareTokens.markLost(). " + retired.length +
              ' retired, ' + notRetired.length + ' not.');
    return { ok: true, token: this.view(key, done), retired: retired,
             notRetired: notRetired, recoveryNoted: recoveries };
  }

  // The holders a lost token leaves with no other passkey, each noted as a
  // `lost-key` recovery (above). Answers the usernames noted.
  private noteLossRecoveries(token: Json, onlyHolder: string): string[] {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.noteLossRecoveries().");
    const credentials = this.deps.loadCredentials();
    const byHolder: Record<string, string[]> = {};
    (token.credentials || []).forEach(function (c: Json) {
      const who = String(c.holder || token.holder || '');
      if (c.kind === 'fido' && who && (!onlyHolder || who === onlyHolder)) {
        (byHolder[who] = byHolder[who] || []).push(String(c.ref));
      }
    });
    const noted: string[] = [];
    Object.keys(byHolder).forEach((holder) => {
      const name = this.nameOfHolder(holder);
      if (!name) {
        return;
      }
      const lost = byHolder[holder];
      const others = (credentials.keysOf(name) || []).filter(
        function (k: Json) {
          return lost.indexOf(String(k.credentialId)) < 0;
        });
      if (others.length) {
        return;
      }
      try {
        if (credentials.noteRecovery(name, 'lost-key')) {
          noted.push(name);
        }
      } catch (e) {
        log.debug("Caught in HardwareTokens.noteLossRecoveries(): " +
                  ((e && e.message) || e));
        // The removal goes ahead: a key a finder holds is worse than a
        // recovery not held to the policy. The audit row says none was
        // noted.
      }
    });
    log.debug("Leaving HardwareTokens.noteLossRecoveries(). " +
              noted.length);
    return noted;
  }

  // -------------------------------------------------------------------------
  // THE RETIRERS (header, rule 3e).
  // -------------------------------------------------------------------------
  /**
   * Installs the retire action of one credential kind; a later phase's
   * module calls it for the kind it adds.
   *
   * @param kind - one of CREDENTIAL_KINDS
   * @param retirer - `{ label, retire(token, credential, ctx) }`, the
   *   retire answering `{ ok, errorCode?, why?, sessionsEnded? }`
   * @returns true when installed
   */
  registerRetirer(kind: string, retirer: Retirer): boolean {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.registerRetirer(). " + kind);
    if (CREDENTIAL_KINDS.indexOf(String(kind)) < 0 || !retirer ||
        typeof retirer.retire !== 'function' ||
        typeof retirer.label !== 'string' || !retirer.label) {
      log.error(this.deps.errorCodes.tag('STS-HWTOKEN-0008') +
                'hardware_tokens: a retirer for "' + String(kind) +
                '" was refused: it must name a known kind, a label and a ' +
                'retire function.');
      log.debug("Leaving HardwareTokens.registerRetirer(). Refused.");
      return false;
    }
    this.retirers[kind] = retirer;
    log.debug("Leaving HardwareTokens.registerRetirer(). Installed.");
    return true;
  }

  /**
   * The kinds a retirer is installed for.
   *
   * @returns the kinds
   */
  retirerKinds(): string[] {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.retirerKinds().");
    log.debug("Leaving HardwareTokens.retirerKinds().");
    return Object.keys(this.retirers);
  }

  private installBuiltInRetirers(): void {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.installBuiltInRetirers().");
    const self = this;
    this.retirers.fido = {
      label: 'FIDO credential',
      retire: function (token: Json, c: TokenCredential, ctx: Json): Json {
        return self.retireFido(token, c, ctx);
      }
    };
    this.retirers.x509 = {
      label: 'X.509 certificate',
      retire: function (token: Json, c: TokenCredential, ctx: Json):
          Promise<Json> {
        return self.retireCertificate(token, c, ctx);
      }
    };
    log.debug("Leaving HardwareTokens.installBuiltInRetirers().");
  }

  private retireFido(token: Json, c: TokenCredential, ctx: Json): Json {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.retireFido().");
    const credentials = this.deps.loadCredentials();
    const username = String(ctx.username || '');
    const going = (credentials.keysOf(username) || []).filter(
      function (k: Json) {
        return String(k.credentialId) === c.ref;
      })[0] || null;
    if (!going) {
      // Already gone from the entry (removed by another door): nothing is
      // live, which is what retiring was for.
      log.debug("Leaving HardwareTokens.retireFido(). Already removed.");
      return { ok: true, already: true };
    }
    const removed = credentials.removeKey(username, c.ref, { lost: true });
    if (!removed || !removed.ok) {
      log.debug("Leaving HardwareTokens.retireFido(). Refused.");
      return { ok: false, errorCode: this.deps.errorCodes.codeOf(removed) ||
                 'STS-HWTOKEN-0007',
               why: ((removed && removed.errors) || ['not removed'])[0] };
    }
    try {
      const signals = this.deps.loadSignals();
      signals.credentialChanged({ username: username,
        credentialType: signals.keyCredentialType(going),
        fido2Aaguid: String(going.aaguid || ''),
        friendlyName: String(going.label || ''),
        changeType: 'delete', initiatingEntity: ctx.initiatingEntity,
        via: ctx.via,
        reasonAdmin: 'Hardware token ' + token.vendor + ' ' + token.serial +
          ' was reported lost by ' + ctx.actor + '.',
        reasonUser: 'A security key of yours was reported lost, and its ' +
          'passkey was removed.' });
    } catch (e) {
      log.debug("Caught in HardwareTokens.retireFido(): " +
                ((e && e.message) || e));
      // The removal stands; the signal is best effort, as every door's is.
    }
    let ended: Json = null;
    try {
      ended = this.deps.loadLogout().endFactorSessions(username,
        { kind: 'webauthn', credentialId: c.ref },
        { actor: ctx.actor, channel: 'http',
          initiatingEntity: ctx.initiatingEntity,
          by: ctx.actor + ' reporting hardware token ' + token.vendor + ' ' +
              token.serial + ' lost' });
    } catch (e) {
      log.debug("Caught in HardwareTokens.retireFido(): " +
                ((e && e.message) || e));
      // The key is gone, so no new session can start with it; a session
      // it already signed in is ended by the next sign-out or expiry.
      ended = null;
    }
    log.debug("Leaving HardwareTokens.retireFido(). Removed.");
    return { ok: true, sessionsEnded: Number((ended && ended.sessionsEnded) ||
                                             0) };
  }

  private async retireCertificate(token: Json, c: TokenCredential,
                                  ctx: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.retireCertificate().");
    const enrollment = this.deps.loadEnrollment();
    const answer = await enrollment.revokeEnrolled(c.ref, 'keyCompromise',
      ctx.actor, c.family ? { family: c.family } : {});
    if (answer && answer.ok) {
      log.debug("Leaving HardwareTokens.retireCertificate(). Revoked.");
      return { ok: true };
    }
    log.debug("Leaving HardwareTokens.retireCertificate(). Refused.");
    return { ok: false, errorCode: this.deps.errorCodes.codeOf(answer) ||
               'STS-HWTOKEN-0007',
             why: String((answer && (answer.error || (answer.errors || [])[0]))
                         || 'not revoked') };
  }

  // -------------------------------------------------------------------------
  // WHAT A PAGE DRAWS. The holder by name, resolved now (a rename moves
  // nothing here: the record holds the entryUUID). `forHolder` limits the
  // credentials to that person's, for the portal.
  // -------------------------------------------------------------------------
  private view(key: string, record: Json, forHolder?: string): Json {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.view().");
    const r = record || {};
    const self = this;
    const out = {
      key: key, vendor: String(r.vendor || ''),
      serial: String(r.serial || ''), model: String(r.model || ''),
      firmware: String(r.firmware || ''),
      formFactor: String(r.formFactor || ''),
      holder: this.nameOfHolder(String(r.holder || '')),
      attested: (r.evidence || []).length > 0,
      evidenceSources: Array.from(new Set((r.evidence || [])
        .map(function (e: Json) {
          return String(e.source || '');
        }))),
      status: String(r.status || 'active'),
      lostAt: r.lost ? String(r.lost.at || '') : '',
      lostBy: r.lost ? String(r.lost.by || '') : '',
      registeredAt: String(r.registeredAt || ''),
      updatedAt: String(r.updatedAt || ''),
      credentials: (r.credentials || []).filter(function (c: Json) {
        return !forHolder || !c.holder || c.holder === forHolder;
      }).map(function (c: Json) {
        return { kind: String(c.kind), ref: String(c.ref),
                 label: String(c.label || ''),
                 holder: self.nameOfHolder(String(c.holder || '')),
                 addedAt: String(c.addedAt || ''),
                 source: String((c.evidence || {}).source || ''),
                 smartCard: !!(c.evidence && c.evidence.smartCard),
                 retired: c.retired ? !!c.retired.ok : false };
      })
    };
    log.debug("Leaving HardwareTokens.view().");
    return out;
  }

  private recordAudit(action: string, actor: string, target: string,
                      summary: string, detail: Json): void {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.recordAudit(). " + action);
    const d = Object.assign({}, detail || {});
    const code = d.errorCode;
    delete d.errorCode;
    this.deps.audit.audit(Object.assign({
      action: action, actor: String(actor || ''), target: String(target ||
                                                                  ''),
      outcome: 'success', summary: summary, detail: d
    }, code ? { errorCode: code } : {}));
    log.debug("Leaving HardwareTokens.recordAudit().");
  }

  // For the tests: the realm's register cleared.
  /**
   * Clears the ambient realm's register; for tests only.
   */
  forgetForTests(): void {
    const { log } = this.deps;
    log.debug("Entering HardwareTokens.forgetForTests().");
    register.clear();
    log.debug("Leaving HardwareTokens.forgetForTests().");
  }
}

const slot = new InstanceSlot<HardwareTokens>(
  'common/hardware_tokens',
  () => new HardwareTokens(HardwareTokens.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The hardware token register (#1955 P1). A library (rule 3).
 * @namespace
 */
export = {
  HardwareTokens: HardwareTokens,
  CREDENTIAL_KINDS: CREDENTIAL_KINDS,
  EVIDENCE_SOURCES: EVIDENCE_SOURCES,
  HARDWARE_CLAIMS: HARDWARE_CLAIMS,
  installInstance: (instance: HardwareTokens): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  recordAttested: slot.forward('recordAttested'),
  noteFidoKey: slot.forward('noteFidoKey'),
  attachCredential: slot.forward('attachCredential'),
  forgetCredential: slot.forward('forgetCredential'),
  byKey: slot.forward('byKey'),
  tokensOf: slot.forward('tokensOf'),
  list: slot.forward('list'),
  evidenceFor: slot.forward('evidenceFor'),
  inferenceAllowed: slot.forward('inferenceAllowed'),
  certificateAmr: slot.forward('certificateAmr'),
  markLost: slot.forward('markLost'),
  registerRetirer: slot.forward('registerRetirer'),
  retirerKinds: slot.forward('retirerKinds'),
  forgetForTests: slot.forward('forgetForTests')
};
