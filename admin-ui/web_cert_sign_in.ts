// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin-ui/web_cert_sign_in.ts
//
// ---------------------------------------------------------------------------
// CERTIFICATE SIGN-IN'S SETTINGS AS FORM FIELDS (#2080).
//
// rcbj on #2080: "turn the JSON configuration into real form fields", after
// a real PIV sign-in in which the settings were hard to find and harder to
// write. Six settings hold a structure as text, and each gets an editor
// here, drawn in the setting's row in place of its text box:
//
//   certSignIn.profiles        a JSON array of certificate sign-in profiles
//                              (`common/certificate_binding.ts`)
//   listeners.custom,          a JSON array of listener definitions
//   listeners.realm            (`common/listener_map.js`)
//   listeners.applications     a JSON object, application to listeners
//   piv.externalIssuers,       PEM bundles
//   piv.attestationAnchors
//
// **THE VALUE IS STILL THE SETTING'S TEXT, AND THE SAVE IS STILL THE
// SETTING'S.** Each row keeps one control that carries `name="<key>"` — the
// text, in a box under "As JSON" — and the editor's own controls carry no
// `name`, so the form posts exactly the field it always did, through
// `POST /admin-api/config/set-many`, and the write rules (STS-TLS-0065,
// STS-CORE-0153 to 0156) judge it as they judged a typed value. The editor
// writes the box on every change; a value typed into the box is read back
// into the editor. A page drawn and saved without a change posts the text it
// was drawn with, byte for byte.
//
// **A STORED VALUE THE EDITOR READS COMES BACK UNCHANGED.** Each profile,
// listener and mapping keeps the members it was written with, in their
// order, and a member it did not have is written only once it holds
// something (`profileJson()` and its two siblings) — so a profile written by
// hand without `bindings` keeps its default, and one with `"lowAffinity":
// false` keeps saying so. A value the editor cannot read (not JSON, a member
// no editor has) is left to the box, with the reason, rather than shown
// without the part it did not understand.
//
// **WHAT A CERTIFICATE SAYS IS THE SERVER'S TO READ.** The SHA-256 of a
// CA's SubjectPublicKeyInfo that a profile names it by, a certificate's
// fingerprint and a person's binding values are computed by
// `POST /admin-api/console/certificates/inspect` (`common/crypto.js`, the one
// place this service hashes) and by `GET /admin-api/tls/trust`'s
// `spkiSha256`; nothing here computes a digest.
//
// **A PERSON'S BINDINGS** (`personBindings()`), on their Credentials →
// Certificate sign-in sub-tab: their certificate handed in, the three
// high-affinity values derived by the same helper, each added through
// `users/add-attribute` and taken off through `users/remove-attribute` — the
// directory canonicalises and refuses as it does for any other write
// (`ldap/person_editor.ts`).
//
// The lists of names below are `common/certificate_binding.ts`'s, copied
// because a `web_` module requires no server module; `tests/
// cert_sign_in_editor.js` holds them equal.
//
// A `web_` MODULE: it requires `web_` modules only, logs nothing, and is
// bundled for a browser by `build-typescript.sh`. `wire()` is called by
// `ConsoleRuntime.draw()` after every drawing, as the WS-Trust protection
// boxes' is. The console requires script (`../CLAUDE.md`), so no fallback is
// owed for a browser with script blocked; the box is there either way.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import WebSafeDom = require('../common/web_safe_dom');

type Json = any;

const K = 'consoleCertSignIn.';

/** The settings drawn as an editor, by the kind of editor. */
const STRUCTURED: Record<string, string> = {
  'certSignIn.profiles': 'profiles',
  'listeners.custom': 'listeners',
  'listeners.realm': 'listeners',
  'listeners.applications': 'applications',
  'piv.externalIssuers': 'pems',
  'piv.attestationAnchors': 'pems'
};

// `common/certificate_binding.ts`'s lists (header).
const KEY_USAGE_NAMES = ['digitalSignature', 'nonRepudiation',
                         'keyEncipherment', 'dataEncipherment',
                         'keyAgreement', 'keyCertSign', 'cRLSign',
                         'encipherOnly', 'decipherOnly'];
const HIGH_AFFINITY = ['certificate-sha256', 'issuer-serial', 'issuer-ski',
                       'spki-sha256', 'card-uuid'];
const LOW_AFFINITY = ['upn', 'email', 'issuer-subject', 'subject'];
const DEFAULT_BINDINGS = ['certificate-sha256', 'issuer-serial'];

// A profile's members, in the order a new one is written.
const PROFILE_MEMBERS = ['id', 'description', 'issuers', 'keyUsage',
                         'extendedKeyUsage', 'policies', 'bindings',
                         'lowAffinity', 'smartCard'];

// The purposes and policies an administrator setting up a smart card is
// most likely to want, each a box; any other is typed in.
const EKU_PRESETS = [
  { oid: '1.3.6.1.5.5.7.3.2', key: 'ekuClientAuth' },
  { oid: '1.3.6.1.4.1.311.20.2.2', key: 'ekuSmartcardLogon' },
  { oid: '1.3.6.1.5.2.3.4', key: 'ekuPkinitClient' }
];
const POLICY_PRESETS = [
  { oid: '2.16.840.1.101.3.2.1.3.13', key: 'policyPivAuth' }
];

// `common/listener_map.js`'s members of a listener.
const LISTENER_MEMBERS = ['id', 'label', 'port', 'publicBaseUrl',
                          'hostnames', 'certificateFile', 'privateKeyFile',
                          'clientAuth', 'tls'];
const CLIENT_AUTH = ['none', 'optional', 'required'];

const OID = /^[0-2](\.(0|[1-9][0-9]*))+$/;
const PEM_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

const INSPECT = '/admin-api/console/certificates/inspect';
const TRUSTSTORE = '/admin-api/tls/trust?per=300';

/**
 * The editors certificate sign-in's structured settings are drawn with.
 *
 * A static utility class; the state of a page's editors is the page's,
 * held by `wire()`'s closures.
 */
class CertSignInEditors {
  static readonly STRUCTURED = STRUCTURED;
  static readonly KEY_USAGE_NAMES = KEY_USAGE_NAMES;
  static readonly HIGH_AFFINITY = HIGH_AFFINITY;
  static readonly LOW_AFFINITY = LOW_AFFINITY;
  static readonly DEFAULT_BINDINGS = DEFAULT_BINDINGS;
  static readonly EKU_PRESETS = EKU_PRESETS;
  static readonly POLICY_PRESETS = POLICY_PRESETS;

  // =========================================================================
  // THE ROW: an editor's place, and the box that is the value.
  // =========================================================================
  /**
   * The kind of editor a setting is drawn with, or ''.
   *
   * @param key - the setting
   * @returns `profiles`, `listeners`, `applications`, `pems` or ''
   */
  static kindOf(key: string): string {
    return Object.prototype.hasOwnProperty.call(STRUCTURED, key)
      ? STRUCTURED[key] : '';
  }

  /**
   * Draws a structured setting's control: the editor's place, filled by
   * `wire()`, and the box under "As JSON" that carries the value.
   *
   * @param setting - the described setting (`key`, `text`, `description`)
   * @param id - the id the row's label points at, given to the box
   * @param t - the page's translator
   * @returns the control as HTML
   */
  static control(setting: Json, id: string, t?: Json): string {
    t = t || kit.context().t;
    const kind = CertSignInEditors.kindOf(String(setting.key));
    return CertSignInEditors.place(kind, id, t) +
      '<details class="cfg-json"><summary>' + t.html(K + 'asJson') +
      '</summary><textarea name="' + kit.esc(setting.key) + '" id="' +
      kit.esc(id) + '" rows="8" cols="72" spellcheck="false"' +
      kit.tip(setting.description, Infinity) + '>' +
      kit.esc(String(setting.text || '')) + '</textarea></details>';
  }

  /**
   * The place an editor is drawn into, for a box drawn elsewhere.
   *
   * @param kind - the editor's kind
   * @param id - the box's id
   * @param t - the page's translator
   * @param pretty - optional; write the box's JSON indented
   * @returns the place as HTML
   */
  static place(kind: string, id: string, t: Json, pretty?: boolean): string {
    return '<div class="cfg-structured" data-structured="' + kit.esc(kind) +
      '" data-structured-for="' + kit.esc(id) + '"' +
      (pretty ? ' data-structured-pretty="1"' : '') + '><p class="sub">' +
      t.html(K + 'editorLoading') + '</p></div>';
  }

  // =========================================================================
  // THE PROFILES: read, written back, changed.
  // =========================================================================
  /**
   * A value a hash list takes: lower case, no colons or spaces, an optional
   * `sha256:` in front; '' where it is not 64 hexadecimal digits.
   *
   * @param value - as typed
   * @returns the digest, or ''
   */
  static hex64(value: unknown): string {
    const text = String(value == null ? '' : value).trim().toLowerCase()
      .replace(/^sha-?256:/, '').replace(/[:\s]/g, '');
    return /^[0-9a-f]{64}$/.test(text) ? text : '';
  }

  /**
   * Reads `certSignIn.profiles`' text into the editor's profiles.
   *
   * @param text - the setting's text
   * @returns `{ ok, profiles, problem }`; `problem` a catalog key's last
   *   part where the editor cannot read it
   */
  static parseProfiles(text: string): Json {
    const raw = String(text == null ? '' : text).trim();
    if (!raw) {
      return { ok: true, profiles: [], problem: '' };
    }
    let list: Json = null;
    try {
      list = JSON.parse(raw);
    } catch (e) {
      // Not JSON: the box shows it as it is, and the save refuses it.
      return { ok: false, profiles: [], problem: 'notJson' };
    }
    if (!Array.isArray(list)) {
      return { ok: false, profiles: [], problem: 'notArray' };
    }
    const strings = function (v: unknown): boolean {
      return v === undefined || (Array.isArray(v) && v.every(function (x) {
        return typeof x === 'string';
      }));
    };
    const out: Json[] = [];
    for (let i = 0; i < list.length; i++) {
      const one = list[i];
      if (!one || typeof one !== 'object' || Array.isArray(one) ||
          Object.keys(one).some(function (k) {
            return PROFILE_MEMBERS.indexOf(k) < 0;
          }) ||
          (one.id !== undefined && typeof one.id !== 'string') ||
          (one.description !== undefined &&
           typeof one.description !== 'string') ||
          !['issuers', 'keyUsage', 'extendedKeyUsage', 'policies',
            'bindings'].every(function (k) { return strings(one[k]); }) ||
          (one.lowAffinity !== undefined &&
           typeof one.lowAffinity !== 'boolean') ||
          (one.smartCard !== undefined &&
           typeof one.smartCard !== 'boolean')) {
        return { ok: false, profiles: [], problem: 'notProfile' };
      }
      out.push({
        members: Object.keys(one),
        id: String(one.id || ''),
        description: String(one.description || ''),
        issuers: (one.issuers || []).slice(0),
        keyUsage: (one.keyUsage || []).slice(0),
        extendedKeyUsage: (one.extendedKeyUsage || []).slice(0),
        policies: (one.policies || []).slice(0),
        bindings: one.bindings === undefined ? null : one.bindings.slice(0),
        lowAffinity: one.lowAffinity === true,
        smartCard: one.smartCard === true
      });
    }
    return { ok: true, profiles: out, problem: '' };
  }

  /**
   * One profile as the JSON the setting holds: the members it was read
   * with, in their order, then any it has come to hold.
   *
   * @param p - the editor's profile
   * @returns the JSON object
   */
  static profileJson(p: Json): Json {
    const had = p.members || [];
    const order = had.concat(PROFILE_MEMBERS.filter(function (m) {
      return had.indexOf(m) < 0;
    }));
    const out: Json = {};
    order.forEach(function (m: string) {
      const was = had.indexOf(m) >= 0;
      if (m === 'id' || m === 'issuers') {
        out[m] = m === 'id' ? p.id : p.issuers.slice(0);
      } else if (m === 'description') {
        if (was || p.description !== '') {
          out[m] = p.description;
        }
      } else if (m === 'bindings') {
        if (p.bindings !== null) {
          out[m] = p.bindings.slice(0);
        }
      } else if (m === 'lowAffinity' || m === 'smartCard') {
        if (was || p[m] === true) {
          out[m] = p[m] === true;
        }
      } else if (was || p[m].length) {
        out[m] = p[m].slice(0);
      }
    });
    return out;
  }

  /**
   * The setting's text for the editor's profiles: '' for none.
   *
   * @param profiles - the editor's profiles
   * @param pretty - optional; indented
   * @returns the text
   */
  static profilesText(profiles: Json[], pretty?: boolean): string {
    return profiles.length
      ? JSON.stringify(profiles.map(CertSignInEditors.profileJson), null,
                       pretty ? 2 : undefined)
      : '';
  }

  /**
   * A new profile, with an id no other profile has.
   *
   * @param profiles - the profiles it joins
   * @returns the profile
   */
  static newProfile(profiles: Json[]): Json {
    let n = profiles.length + 1;
    const taken = function (id: string): boolean {
      return profiles.some(function (p) { return p.id === id; });
    };
    while (taken('profile-' + n)) {
      n += 1;
    }
    return { members: [], id: 'profile-' + n, description: '', issuers: [],
             keyUsage: [], extendedKeyUsage: [], policies: [],
             bindings: null, lowAffinity: false, smartCard: false };
  }

  /**
   * Applies one change to the profiles, returning new ones.
   *
   * @param profiles - the profiles as they are
   * @param act - `{ op, index, field?, value?, on?, delta? }`: `add`,
   *   `remove`, `move`, `text` (id, description), `toggle` (a value in a
   *   list, `on`), `flag` (lowAffinity, smartCard), `value` (a value typed
   *   or picked for issuers, extendedKeyUsage, policies)
   * @returns `{ profiles, problem }`; `problem` a catalog key's last part
   */
  static applyProfile(profiles: Json[], act: Json): Json {
    const list = profiles.map(function (p) {
      return Object.assign({}, p, {
        members: p.members.slice(0), issuers: p.issuers.slice(0),
        keyUsage: p.keyUsage.slice(0),
        extendedKeyUsage: p.extendedKeyUsage.slice(0),
        policies: p.policies.slice(0),
        bindings: p.bindings === null ? null : p.bindings.slice(0) });
    });
    const i = Number(act.index);
    const p = list[i];
    const done = function (problem?: string): Json {
      return { profiles: list, problem: problem || '' };
    };
    if (act.op === 'add') {
      list.push(CertSignInEditors.newProfile(list));
      return done();
    }
    if (!p) {
      return { profiles: profiles, problem: '' };
    }
    if (act.op === 'remove') {
      list.splice(i, 1);
    } else if (act.op === 'move') {
      const to = i + Number(act.delta);
      if (to >= 0 && to < list.length) {
        list.splice(i, 1);
        list.splice(to, 0, p);
      }
    } else if (act.op === 'text' &&
               (act.field === 'id' || act.field === 'description')) {
      p[act.field] = String(act.value == null ? '' : act.value);
    } else if (act.op === 'flag' &&
               (act.field === 'lowAffinity' || act.field === 'smartCard')) {
      p[act.field] = !!act.on;
      // A NAME METHOD WITHOUT THE OPT-IN IS REFUSED when it is written
      // (rcbj's decision on #2012), so turning the opt-in off takes them
      // out rather than leaving a value the save would refuse.
      if (act.field === 'lowAffinity' && !act.on && p.bindings !== null) {
        p.bindings = p.bindings.filter(function (m: string) {
          return LOW_AFFINITY.indexOf(m) < 0;
        });
      }
    } else if (act.op === 'toggle') {
      const field = String(act.field);
      const value = String(act.value);
      if (field === 'bindings' && p.bindings === null) {
        p.bindings = DEFAULT_BINDINGS.slice(0);
      }
      const held: string[] = p[field];
      if (!Array.isArray(held)) {
        return done();
      }
      if (field === 'bindings' && act.on &&
          LOW_AFFINITY.indexOf(value) >= 0 && !p.lowAffinity) {
        return done('lowNeedsOptIn');
      }
      const at = held.indexOf(value);
      if (act.on && at < 0) {
        held.push(value);
      } else if (!act.on && at >= 0) {
        held.splice(at, 1);
      }
    } else if (act.op === 'value') {
      const field = String(act.field);
      const typed = String(act.value == null ? '' : act.value).trim();
      const value = field === 'issuers' ? CertSignInEditors.hex64(typed)
                                        : typed;
      if (field === 'issuers' && !value) {
        return done('badHash');
      }
      if (field !== 'issuers' && !OID.test(value)) {
        return done('badOid');
      }
      if (!Array.isArray(p[field])) {
        return done();
      }
      if (p[field].indexOf(value) < 0) {
        p[field].push(value);
      }
    }
    return done();
  }

  // =========================================================================
  // THE LISTENERS AND THE MAPPING: read, written back, changed.
  // =========================================================================
  /**
   * Reads a listener definitions' text (`listeners.custom`,
   * `listeners.realm`).
   *
   * @param text - the setting's text
   * @returns `{ ok, listeners, problem }`
   */
  static parseListeners(text: string): Json {
    const raw = String(text == null ? '' : text).trim();
    if (!raw) {
      return { ok: true, listeners: [], problem: '' };
    }
    let list: Json = null;
    try {
      list = JSON.parse(raw);
    } catch (e) {
      // Not JSON: left to the box, which the save refuses (STS-CORE-0153).
      return { ok: false, listeners: [], problem: 'notJson' };
    }
    if (!Array.isArray(list)) {
      return { ok: false, listeners: [], problem: 'notArray' };
    }
    const out: Json[] = [];
    for (let i = 0; i < list.length; i++) {
      const one = list[i];
      if (!one || typeof one !== 'object' || Array.isArray(one) ||
          Object.keys(one).some(function (k) {
            return LISTENER_MEMBERS.indexOf(k) < 0;
          }) ||
          (one.hostnames !== undefined && (!Array.isArray(one.hostnames) ||
            one.hostnames.some(function (h: Json) {
              return typeof h !== 'string';
            }))) ||
          (one.tls !== undefined && (!one.tls ||
            typeof one.tls !== 'object' || Array.isArray(one.tls))) ||
          ['id', 'label', 'publicBaseUrl', 'certificateFile',
           'privateKeyFile', 'clientAuth'].some(function (k) {
            return one[k] !== undefined && typeof one[k] !== 'string';
          }) ||
          (one.port !== undefined && typeof one.port !== 'number' &&
           typeof one.port !== 'string')) {
        return { ok: false, listeners: [], problem: 'notListener' };
      }
      const tls = one.tls || {};
      out.push({
        members: Object.keys(one),
        id: String(one.id || ''), label: String(one.label || ''),
        port: one.port === undefined ? '' : one.port,
        publicBaseUrl: String(one.publicBaseUrl || ''),
        hostnames: (one.hostnames || []).slice(0),
        certificateFile: String(one.certificateFile || ''),
        privateKeyFile: String(one.privateKeyFile || ''),
        clientAuth: String(one.clientAuth || ''),
        tls: Object.keys(tls).map(function (name) {
          return { name: name, value: tls[name] };
        })
      });
    }
    return { ok: true, listeners: out, problem: '' };
  }

  /**
   * One listener as the JSON the setting holds, by `profileJson()`'s rule.
   *
   * @param l - the editor's listener
   * @returns the JSON object
   */
  static listenerJson(l: Json): Json {
    const had = l.members || [];
    const order = had.concat(LISTENER_MEMBERS.filter(function (m) {
      return had.indexOf(m) < 0;
    }));
    const out: Json = {};
    order.forEach(function (m: string) {
      const was = had.indexOf(m) >= 0;
      if (m === 'id' || m === 'port') {
        out[m] = l[m];
      } else if (m === 'hostnames') {
        if (was || l.hostnames.length) {
          out[m] = l.hostnames.slice(0);
        }
      } else if (m === 'tls') {
        if (was || l.tls.length) {
          const block: Json = {};
          l.tls.forEach(function (row: Json) {
            if (String(row.name).trim()) {
              block[String(row.name).trim()] = row.value;
            }
          });
          out[m] = block;
        }
      } else if (was || l[m] !== '') {
        out[m] = l[m];
      }
    });
    return out;
  }

  /**
   * The setting's text for the editor's listeners: '' for none.
   *
   * @param listeners - the editor's listeners
   * @param pretty - optional; indented
   * @returns the text
   */
  static listenersText(listeners: Json[], pretty?: boolean): string {
    return listeners.length
      ? JSON.stringify(listeners.map(CertSignInEditors.listenerJson), null,
                       pretty ? 2 : undefined)
      : '';
  }

  /**
   * A value typed into a `tls` row, as the JSON it is written as: `true`
   * and `false` a boolean, a whole number a number, anything else the text.
   *
   * @param text - as typed
   * @returns the value
   */
  static typedValue(text: string): Json {
    const v = String(text == null ? '' : text).trim();
    if (v === 'true' || v === 'false') {
      return v === 'true';
    }
    return /^-?[0-9]+$/.test(v) ? Number(v) : v;
  }

  /**
   * Applies one change to the listeners, returning new ones.
   *
   * @param listeners - the listeners as they are
   * @param act - `{ op, index, field?, value?, row?, delta? }`: `add`,
   *   `remove`, `move`, `text`, `tls-add`, `tls-remove`, `tls-name`,
   *   `tls-value`
   * @returns the listeners
   */
  static applyListener(listeners: Json[], act: Json): Json[] {
    const list = listeners.map(function (l) {
      return Object.assign({}, l, {
        members: l.members.slice(0), hostnames: l.hostnames.slice(0),
        tls: l.tls.map(function (row: Json) {
          return Object.assign({}, row);
        }) });
    });
    const i = Number(act.index);
    if (act.op === 'add') {
      list.push({ members: [], id: '', label: '', port: '',
                  publicBaseUrl: '', hostnames: [], certificateFile: '',
                  privateKeyFile: '', clientAuth: '', tls: [] });
      return list;
    }
    const l = list[i];
    if (!l) {
      return listeners;
    }
    const row = Number(act.row);
    if (act.op === 'remove') {
      list.splice(i, 1);
    } else if (act.op === 'move') {
      const to = i + Number(act.delta);
      if (to >= 0 && to < list.length) {
        list.splice(i, 1);
        list.splice(to, 0, l);
      }
    } else if (act.op === 'text') {
      const v = String(act.value == null ? '' : act.value);
      if (act.field === 'port') {
        l.port = /^[0-9]+$/.test(v.trim()) ? Number(v.trim()) : v;
      } else if (act.field === 'hostnames') {
        l.hostnames = v.split(',').map(function (h) {
          return h.trim();
        }).filter(Boolean);
      } else if (LISTENER_MEMBERS.indexOf(String(act.field)) >= 0 &&
                 act.field !== 'tls') {
        l[act.field] = v;
      }
    } else if (act.op === 'tls-add') {
      l.tls.push({ name: '', value: '' });
    } else if (act.op === 'tls-remove' && l.tls[row]) {
      l.tls.splice(row, 1);
    } else if (act.op === 'tls-name' && l.tls[row]) {
      l.tls[row].name = String(act.value == null ? '' : act.value);
    } else if (act.op === 'tls-value' && l.tls[row]) {
      l.tls[row].value = CertSignInEditors.typedValue(act.value);
    }
    return list;
  }

  /**
   * Reads `listeners.applications`' text.
   *
   * @param text - the setting's text
   * @returns `{ ok, entries, problem }`, each entry `{ app, listeners,
   *   advertised }` (`advertised` null where it was left out)
   */
  static parseApplications(text: string): Json {
    const raw = String(text == null ? '' : text).trim();
    if (!raw) {
      return { ok: true, entries: [], problem: '' };
    }
    let map: Json = null;
    try {
      map = JSON.parse(raw);
    } catch (e) {
      // Not JSON: left to the box, which the save refuses (STS-CORE-0154).
      return { ok: false, entries: [], problem: 'notJson' };
    }
    if (!map || typeof map !== 'object' || Array.isArray(map)) {
      return { ok: false, entries: [], problem: 'notObject' };
    }
    const out: Json[] = [];
    const apps = Object.keys(map);
    for (let i = 0; i < apps.length; i++) {
      const entry = map[apps[i]];
      if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
          Object.keys(entry).some(function (k) {
            return k !== 'listeners' && k !== 'advertised';
          }) || !Array.isArray(entry.listeners) ||
          entry.listeners.some(function (id: Json) {
            return typeof id !== 'string';
          }) ||
          (entry.advertised !== undefined &&
           typeof entry.advertised !== 'string')) {
        return { ok: false, entries: [], problem: 'notMapping' };
      }
      out.push({ app: apps[i], listeners: entry.listeners.slice(0),
                 advertised: entry.advertised === undefined ? null
                                                            : entry.advertised,
                 members: Object.keys(entry) });
    }
    return { ok: true, entries: out, problem: '' };
  }

  /**
   * The setting's text for the editor's mapping: '' for none.
   *
   * @param entries - the editor's entries
   * @param pretty - optional; indented
   * @returns the text
   */
  static applicationsText(entries: Json[], pretty?: boolean): string {
    if (!entries.length) {
      return '';
    }
    const map: Json = {};
    entries.forEach(function (e: Json) {
      const one: Json = {};
      const had = e.members || ['listeners'];
      const order = had.concat(['listeners', 'advertised'].filter(
        function (m) { return had.indexOf(m) < 0; }));
      order.forEach(function (m: string) {
        if (m === 'listeners') {
          one.listeners = e.listeners.slice(0);
        } else if (e.advertised !== null) {
          one.advertised = e.advertised;
        }
      });
      map[String(e.app)] = one;
    });
    return JSON.stringify(map, null, pretty ? 2 : undefined);
  }

  /**
   * Applies one change to the mapping, returning new entries.
   *
   * @param entries - the entries as they are
   * @param act - `{ op, index, field?, value? }`: `add`, `remove`, `text`
   *   (app, listeners as a comma list, advertised; '' leaves it out)
   * @returns the entries
   */
  static applyApplication(entries: Json[], act: Json): Json[] {
    const list = entries.map(function (e) {
      return Object.assign({}, e, { listeners: e.listeners.slice(0),
                                    members: (e.members || []).slice(0) });
    });
    const i = Number(act.index);
    if (act.op === 'add') {
      list.push({ app: '', listeners: ['main'], advertised: null,
                  members: ['listeners'] });
      return list;
    }
    const e = list[i];
    if (!e) {
      return entries;
    }
    const v = String(act.value == null ? '' : act.value);
    if (act.op === 'remove') {
      list.splice(i, 1);
    } else if (act.op === 'text' && act.field === 'app') {
      e.app = v.trim();
    } else if (act.op === 'text' && act.field === 'listeners') {
      e.listeners = v.split(',').map(function (id) {
        return id.trim();
      }).filter(Boolean);
      if (e.advertised !== null && e.listeners.indexOf(e.advertised) < 0) {
        e.advertised = null;
      }
    } else if (act.op === 'text' && act.field === 'advertised') {
      e.advertised = v === '' ? null : v;
    }
    return list;
  }

  // =========================================================================
  // THE PEM LISTS.
  // =========================================================================
  /**
   * The certificates of a PEM bundle, each block as it was written.
   *
   * @param text - the setting's text
   * @returns `{ ok, blocks, problem }`
   */
  static parsePems(text: string): Json {
    const raw = String(text == null ? '' : text);
    const blocks = raw.match(PEM_BLOCK) || [];
    if (raw.trim() && !blocks.length) {
      return { ok: false, blocks: [], problem: 'notPem' };
    }
    return { ok: true, blocks: blocks.slice(0), problem: '' };
  }

  /**
   * The setting's text for a list of certificates.
   *
   * @param blocks - the PEM blocks
   * @returns the bundle, one block a line apart, or ''
   */
  static pemsText(blocks: string[]): string {
    return blocks.length ? blocks.join('\n') + '\n' : '';
  }

  /**
   * Adds the certificates of a text to a list, each once.
   *
   * @param blocks - the list
   * @param text - the text handed in
   * @returns `{ blocks, added }`
   */
  static addPems(blocks: string[], text: string): Json {
    const out = blocks.slice(0);
    let added = 0;
    (String(text || '').match(PEM_BLOCK) || []).forEach(function (b) {
      const one = b.trim();
      if (out.indexOf(one) < 0) {
        out.push(one);
        added += 1;
      }
    });
    return { blocks: out, added: added };
  }

  // =========================================================================
  // DRAWING.
  // =========================================================================
  /**
   * A list of values, each with a Remove button.
   *
   * @param values - the values
   * @param act - the button's `data-cs-act`
   * @param attrs - the other attributes every button carries
   * @param labelOf - optional; what to show beside a value
   * @param t - the page's translator
   * @returns the list as HTML, or a note that it is empty
   */
  static valueList(values: string[], act: string, attrs: string,
                   labelOf: ((v: string) => string) | null, t: Json): string {
    if (!values.length) {
      return '<p class="sub">' + t.html(K + 'noneYet') + '</p>';
    }
    return '<ul class="cs-values">' + values.map(function (v) {
      const label = labelOf ? labelOf(v) : '';
      return '<li><code>' + kit.esc(v) + '</code>' +
        (label ? ' <span class="sub">' + kit.esc(label) + '</span>' : '') +
        ' <button type="button" class="secondary" data-cs-act="' +
        kit.esc(act) + '" data-cs-value="' + kit.esc(v) + '"' + attrs +
        '>' + t.html(K + 'remove') + '</button></li>';
    }).join('') + '</ul>';
  }

  /**
   * A checkbox, with no `name`: the editor's, never the form's.
   *
   * @param attrs - its data attributes
   * @param on - ticked
   * @param label - its label, as HTML
   * @param disabled - optional
   * @returns the HTML
   */
  static box(attrs: string, on: boolean, label: string,
             disabled?: boolean): string {
    return '<label class="cs-box"><input type="checkbox"' + attrs +
      (on ? ' checked' : '') + (disabled ? ' disabled' : '') + '> ' +
      label + '</label>';
  }

  /**
   * Draws the profiles editor.
   *
   * @param state - `{ profiles, anchors, problem, note }`: `anchors` the
   *   client truststore's `{ subject, spkiSha256, ca }`, or null while it is
   *   read
   * @param t - the page's translator
   * @returns the editor as HTML
   */
  static profilesEditor(state: Json, t: Json): string {
    const anchors: Json[] = state.anchors || [];
    const subjectOf = function (hash: string): string {
      const found = anchors.filter(function (a) {
        return a.spkiSha256 === hash;
      })[0];
      return found ? String(found.subject) : '';
    };
    const cards = state.profiles.map(function (p: Json, i: number) {
      const at = ' data-cs-i="' + i + '"';
      const field = function (name: string, size: number): string {
        const id = CertSignInEditors.idOf(state, 'p' + i + '-' + name);
        return '<label for="' + id + '">' + t.html(K + 'profile.' + name) +
          '</label> <input type="text" id="' + id + '" size="' + size +
          '" data-cs-text="' + name + '"' + at + ' value="' +
          kit.esc(p[name]) + '">';
      };
      const bindings: string[] = p.bindings === null ? DEFAULT_BINDINGS
                                                     : p.bindings;
      const others = function (held: string[], presets: Json[]): string[] {
        return held.filter(function (v) {
          return !presets.some(function (one) { return one.oid === v; });
        });
      };
      const presetBoxes = function (list: string, presets: Json[]): string {
        return presets.map(function (one) {
          return CertSignInEditors.box(' data-cs-toggle="' + list +
            '" data-cs-value="' + kit.esc(one.oid) + '"' + at,
            p[list].indexOf(one.oid) >= 0,
            t.html(K + one.key) + ' <code>' + kit.esc(one.oid) + '</code>');
        }).join(' ');
      };
      const typed = function (list: string, placeholder: string): string {
        return '<input type="text" size="40" data-cs-new="' + list + '"' +
          at + ' placeholder="' + kit.esc(placeholder) + '" aria-label="' +
          kit.esc(placeholder) + '"> <button type="button" ' +
          'data-cs-act="add-value" data-cs-list="' + list + '"' + at + '>' +
          t.html(K + 'add') + '</button>';
      };
      const pick = anchors.length
        ? '<select data-cs-pick="issuers"' + at + ' aria-label="' +
          kit.esc(t.text(K + 'issuers.pick')) + '">' +
          anchors.filter(function (a) { return !!a.spkiSha256; })
            .map(function (a) {
              return '<option value="' + kit.esc(a.spkiSha256) + '">' +
                kit.esc(a.subject + ' — ' + a.spkiSha256.slice(0, 16) +
                        '…') + '</option>';
            }).join('') + '</select> <button type="button" ' +
          'data-cs-act="add-pick"' + at + '>' + t.html(K + 'add') +
          '</button>'
        : '<span class="sub">' + t.html(state.anchors === null
          ? K + 'issuers.reading' : K + 'issuers.noAnchors') + '</span>';
      return '<fieldset class="cs-card"><legend>' +
        t.html(K + 'profile.legend', { n: String(i + 1), id: p.id }) +
        '</legend><div class="formrow">' +
        '<button type="button" class="secondary" data-cs-act="move" ' +
        'data-cs-delta="-1"' + at + (i === 0 ? ' disabled' : '') + '>' +
        t.html(K + 'up') + '</button> <button type="button" ' +
        'class="secondary" data-cs-act="move" data-cs-delta="1"' + at +
        (i === state.profiles.length - 1 ? ' disabled' : '') + '>' +
        t.html(K + 'down') + '</button> <button type="button" ' +
        'class="secondary" data-cs-act="remove"' + at + '>' +
        t.html(K + 'profile.remove') + '</button></div>' +
        '<div class="formrow">' + field('id', 24) + ' ' +
        field('description', 48) + '</div><div class="formrow">' +
        CertSignInEditors.box(' data-cs-flag="smartCard"' + at,
          p.smartCard, t.html(K + 'profile.smartCard')) + '</div>' +
        '<h4>' + t.html(K + 'issuers.heading') + '</h4>' +
        kit.note(t.html(K + 'issuers.note')) +
        CertSignInEditors.valueList(p.issuers, 'remove-value',
          ' data-cs-list="issuers"' + at, subjectOf, t) +
        (p.issuers.length ? '' : kit.warn(t.html(K + 'issuers.needOne'))) +
        '<div class="formrow">' + pick + '</div><div class="formrow">' +
        typed('issuers', t.text(K + 'issuers.hash')) + '</div>' +
        '<div class="formrow"><label for="' +
        CertSignInEditors.idOf(state, 'p' + i + '-pem') + '">' +
        t.html(K + 'issuers.fromCertificate') + '</label><br>' +
        '<textarea id="' + CertSignInEditors.idOf(state, 'p' + i + '-pem') +
        '" rows="3" cols="64" ' +
        'spellcheck="false" data-cs-pem' + at + '></textarea><br>' +
        '<input type="file" accept=".pem,.crt,.cer" data-cs-pem-file' + at +
        ' aria-label="' + kit.esc(t.text(K + 'chooseFile')) + '"> ' +
        '<button type="button" data-cs-act="read-pem"' + at + '>' +
        t.html(K + 'issuers.read') + '</button></div>' +
        '<h4>' + t.html(K + 'keyUsage.heading') + '</h4>' +
        kit.note(t.html(K + 'keyUsage.note')) + '<div class="formrow">' +
        KEY_USAGE_NAMES.map(function (bit) {
          return CertSignInEditors.box(' data-cs-toggle="keyUsage" ' +
            'data-cs-value="' + bit + '"' + at, p.keyUsage.indexOf(bit) >= 0,
            '<code>' + bit + '</code>');
        }).join(' ') + '</div>' +
        '<h4>' + t.html(K + 'eku.heading') + '</h4>' +
        kit.note(t.html(K + 'eku.note')) + '<div class="formrow">' +
        presetBoxes('extendedKeyUsage', EKU_PRESETS) + '</div>' +
        CertSignInEditors.valueList(others(p.extendedKeyUsage, EKU_PRESETS),
          'remove-value', ' data-cs-list="extendedKeyUsage"' + at, null, t) +
        '<div class="formrow">' + typed('extendedKeyUsage',
          t.text(K + 'customOid')) + '</div>' +
        '<h4>' + t.html(K + 'policies.heading') + '</h4>' +
        kit.note(t.html(K + 'policies.note')) + '<div class="formrow">' +
        presetBoxes('policies', POLICY_PRESETS) + '</div>' +
        CertSignInEditors.valueList(others(p.policies, POLICY_PRESETS),
          'remove-value', ' data-cs-list="policies"' + at, null, t) +
        '<div class="formrow">' + typed('policies', t.text(K + 'customOid')) +
        '</div>' +
        '<h4>' + t.html(K + 'bindings.heading') + '</h4>' +
        kit.note(t.html(K + 'bindings.note')) +
        (p.bindings === null
          ? '<p class="sub">' + t.html(K + 'bindings.default') + '</p>' : '') +
        '<p><strong>' + t.html(K + 'bindings.high') + '</strong></p>' +
        '<div class="formrow">' + HIGH_AFFINITY.map(function (m) {
          return CertSignInEditors.box(' data-cs-toggle="bindings" ' +
            'data-cs-value="' + m + '"' + at, bindings.indexOf(m) >= 0,
            '<code>' + m + '</code>');
        }).join(' ') + '</div>' +
        '<p><strong>' + t.html(K + 'bindings.low') + '</strong></p>' +
        '<div class="formrow">' +
        CertSignInEditors.box(' data-cs-flag="lowAffinity"' + at,
          p.lowAffinity, t.html(K + 'bindings.lowAffinity')) + '</div>' +
        kit.warn(t.html(K + 'bindings.lowWarn')) +
        '<div class="formrow">' + LOW_AFFINITY.map(function (m) {
          return CertSignInEditors.box(' data-cs-toggle="bindings" ' +
            'data-cs-value="' + m + '"' + at, bindings.indexOf(m) >= 0,
            '<code>' + m + '</code>', !p.lowAffinity);
        }).join(' ') + '</div></fieldset>';
    }).join('');
    return CertSignInEditors.banner(state, t) +
      kit.note(t.html(K + 'profiles.order')) + cards +
      '<p><button type="button" data-cs-act="add">' +
      t.html(K + 'profiles.add') + '</button></p>';
  }

  /**
   * An id inside one editor, unique on a page that draws two editors of a
   * kind (the Listeners page draws `listeners.custom` twice).
   *
   * @param state - the editor's state (`prefix`, its box's id)
   * @param part - the part's own name
   * @returns the id
   */
  static idOf(state: Json, part: string): string {
    return 'cs-' + String(state.prefix || 'editor') + '-' + part;
  }

  /**
   * The editor's problem and note, above it.
   *
   * @param state - `{ problem, note }`
   * @param t - the page's translator
   * @returns the HTML, or ''
   */
  static banner(state: Json, t: Json): string {
    return (state.problem
      ? '<div class="err">' + t.html(K + 'problem.' + state.problem) +
        (state.detail ? ' ' + kit.esc(state.detail) : '') + '</div>' : '') +
      (state.note ? '<div class="ok">' + kit.esc(state.note) + '</div>' : '');
  }

  /**
   * Draws the listeners editor.
   *
   * @param state - `{ listeners, problem }`
   * @param t - the page's translator
   * @returns the editor as HTML
   */
  static listenersEditor(state: Json, t: Json): string {
    const cards = state.listeners.map(function (l: Json, i: number) {
      const at = ' data-cs-i="' + i + '"';
      const field = function (name: string, size: number,
                              value: string): string {
        const id = CertSignInEditors.idOf(state, 'l' + i + '-' + name);
        return '<label for="' + id + '">' + t.html(K + 'listener.' + name) +
          '</label> <input type="text" id="' + id + '" size="' + size +
          '" data-cs-text="' + name + '"' + at + ' value="' +
          kit.esc(value) + '">';
      };
      const tlsRows = l.tls.map(function (row: Json, r: number) {
        const rat = at + ' data-cs-row="' + r + '"';
        return '<tr><td><input type="text" size="24" data-cs-tls="name"' +
          rat + ' value="' + kit.esc(row.name) + '" aria-label="' +
          kit.esc(t.text(K + 'listener.tlsName')) + '"></td><td>' +
          '<input type="text" size="36" data-cs-tls="value"' + rat +
          ' value="' + kit.esc(Array.isArray(row.value)
            ? row.value.join(',') : String(row.value)) + '" aria-label="' +
          kit.esc(t.text(K + 'listener.tlsValue')) + '"></td><td>' +
          '<button type="button" class="secondary" data-cs-act="tls-remove"' +
          rat + '>' + t.html(K + 'remove') + '</button></td></tr>';
      }).join('');
      return '<fieldset class="cs-card"><legend>' +
        t.html(K + 'listener.legend', { n: String(i + 1), id: l.id }) +
        '</legend><div class="formrow">' +
        '<button type="button" class="secondary" data-cs-act="move" ' +
        'data-cs-delta="-1"' + at + (i === 0 ? ' disabled' : '') + '>' +
        t.html(K + 'up') + '</button> <button type="button" ' +
        'class="secondary" data-cs-act="move" data-cs-delta="1"' + at +
        (i === state.listeners.length - 1 ? ' disabled' : '') + '>' +
        t.html(K + 'down') + '</button> <button type="button" ' +
        'class="secondary" data-cs-act="remove"' + at + '>' +
        t.html(K + 'listener.remove') + '</button></div>' +
        '<div class="formrow">' + field('id', 20, l.id) + ' ' +
        field('label', 32, l.label) + ' ' +
        field('port', 6, String(l.port)) + '</div>' +
        '<div class="formrow">' + field('publicBaseUrl', 48,
          l.publicBaseUrl) + '</div><div class="formrow">' +
        field('hostnames', 48, l.hostnames.join(', ')) + '</div>' +
        '<div class="formrow"><label for="' +
        CertSignInEditors.idOf(state, 'l' + i + '-clientAuth') + '">' +
        t.html(K + 'listener.clientAuth') + '</label> <select id="' +
        CertSignInEditors.idOf(state, 'l' + i + '-clientAuth') +
        '" data-cs-text="clientAuth"' + at + '><option value=""' +
        (l.clientAuth === '' ? ' selected' : '') + '>' +
        t.html(K + 'listener.clientAuthDefault') + '</option>' +
        CLIENT_AUTH.map(function (one) {
          return '<option value="' + one + '"' +
            (l.clientAuth === one ? ' selected' : '') + '>' + one +
            '</option>';
        }).join('') + '</select></div>' +
        kit.note(t.html(K + 'listener.clientAuthNote')) +
        '<div class="formrow">' + field('certificateFile', 40,
          l.certificateFile) + '</div><div class="formrow">' +
        field('privateKeyFile', 40, l.privateKeyFile) + '</div>' +
        kit.note(t.html(K + 'listener.filesNote')) +
        '<h4>' + t.html(K + 'listener.tlsHeading') + '</h4>' +
        kit.note(t.html(K + 'listener.tlsNote')) +
        (tlsRows ? '<table class="grid"><thead><tr><th>' +
          t.html(K + 'listener.tlsName') + '</th><th>' +
          t.html(K + 'listener.tlsValue') + '</th><th></th></tr></thead>' +
          '<tbody>' + tlsRows + '</tbody></table>' : '') +
        '<p><button type="button" class="secondary" data-cs-act="tls-add"' +
        at + '>' + t.html(K + 'listener.tlsAdd') + '</button></p>' +
        '</fieldset>';
    }).join('');
    return CertSignInEditors.banner(state, t) + cards +
      '<p><button type="button" data-cs-act="add">' +
      t.html(K + 'listener.add') + '</button></p>';
  }

  /**
   * Draws the mapping editor.
   *
   * @param state - `{ entries, problem }`
   * @param t - the page's translator
   * @returns the editor as HTML
   */
  static applicationsEditor(state: Json, t: Json): string {
    const rows = state.entries.map(function (e: Json, i: number) {
      const at = ' data-cs-i="' + i + '"';
      return '<tr><td><input type="text" size="18" data-cs-text="app"' + at +
        ' value="' + kit.esc(e.app) + '" aria-label="' +
        kit.esc(t.text(K + 'app.app')) + '"></td><td><input type="text" ' +
        'size="28" data-cs-text="listeners"' + at + ' value="' +
        kit.esc(e.listeners.join(', ')) + '" aria-label="' +
        kit.esc(t.text(K + 'app.listeners')) + '"></td><td><select ' +
        'data-cs-text="advertised"' + at + ' aria-label="' +
        kit.esc(t.text(K + 'app.advertised')) + '"><option value=""' +
        (e.advertised === null ? ' selected' : '') + '>' +
        t.html(K + 'app.first') + '</option>' +
        e.listeners.map(function (id: string) {
          return '<option value="' + kit.esc(id) + '"' +
            (e.advertised === id ? ' selected' : '') + '>' + kit.esc(id) +
            '</option>';
        }).join('') + '</select></td><td><button type="button" ' +
        'class="secondary" data-cs-act="remove"' + at + '>' +
        t.html(K + 'remove') + '</button></td></tr>';
    }).join('');
    return CertSignInEditors.banner(state, t) +
      kit.note(t.html(K + 'app.note')) +
      (rows ? '<table class="grid"><thead><tr><th>' +
        t.html(K + 'app.app') + '</th><th>' + t.html(K + 'app.listeners') +
        '</th><th>' + t.html(K + 'app.advertised') + '</th><th></th></tr>' +
        '</thead><tbody>' + rows + '</tbody></table>'
        : '<p class="sub">' + t.html(K + 'app.none') + '</p>') +
      '<p><button type="button" data-cs-act="add">' +
      t.html(K + 'app.add') + '</button></p>';
  }

  /**
   * Draws a list of certificates.
   *
   * @param state - `{ blocks, facts, problem, note }`: `facts` the
   *   inspection's certificates, by position, or null while they are read
   * @param t - the page's translator
   * @returns the editor as HTML
   */
  static pemsEditor(state: Json, t: Json): string {
    const facts: Json[] = state.facts || [];
    const rows = state.blocks.map(function (b: string, i: number) {
      const f = facts[i] || null;
      return '<tr><td>' + (f ? kit.esc(f.subject) : '<span class="sub">' +
          t.html(state.facts === null ? K + 'pems.reading'
                                      : K + 'pems.unread') + '</span>') +
        '</td><td>' + (f ? '<code>' + kit.esc(f.fingerprint256) + '</code>'
                         : '') + '</td><td>' +
        (f ? kit.esc(String(f.notAfter).slice(0, 10)) : '') + '</td><td>' +
        '<button type="button" class="secondary" data-cs-act="remove" ' +
        'data-cs-i="' + i + '">' + t.html(K + 'remove') + '</button></td>' +
        '</tr>';
    }).join('');
    return CertSignInEditors.banner(state, t) +
      (rows ? '<table class="grid"><thead><tr><th>' +
        t.html(K + 'pems.subject') + '</th><th>' +
        t.html(K + 'pems.fingerprint') + '</th><th>' +
        t.html(K + 'pems.notAfter') + '</th><th></th></tr></thead><tbody>' +
        rows + '</tbody></table>'
        : '<p class="sub">' + t.html(K + 'pems.none') + '</p>') +
      '<div class="formrow"><label>' + t.html(K + 'pems.addLabel') +
      '<br><textarea rows="3" cols="64" spellcheck="false" ' +
      'data-cs-pem></textarea></label><br><input type="file" ' +
      'accept=".pem,.crt,.cer" data-cs-pem-file aria-label="' +
      kit.esc(t.text(K + 'chooseFile')) + '"> <button type="button" ' +
      'data-cs-act="add-pems">' + t.html(K + 'pems.add') + '</button></div>';
  }

  // =========================================================================
  // A PERSON'S BINDINGS (header).
  // =========================================================================
  /**
   * The Certificate sign-in sub-tab of a person's Credentials: the values of
   * `stsCertificateBinding` they hold, each removable, and their
   * certificate handed in to derive the values it is found by.
   *
   * @param t - the page's translator
   * @param user - the person
   * @param values - the values they hold
   * @param write - whether the reader may change them
   * @returns the HTML
   */
  static personBindings(t: Json, user: string, values: string[],
                        write: boolean): string {
    const form = function (action: string, value: string,
                           label: string): string {
      return '<form method="post" action="/admin/users" class="inline">' +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="user" value="' + kit.esc(user) + '">' +
        '<input type="hidden" name="from" value="user">' +
        '<input type="hidden" name="attribute" ' +
        'value="stsCertificateBinding">' +
        '<input type="hidden" name="value" value="' + kit.esc(value) +
        '"><button type="submit" class="secondary">' + label +
        '</button></form>';
    };
    const held = values.length
      ? '<table class="grid"><thead><tr><th>' +
        t.html(K + 'person.thMethod') + '</th><th>' +
        t.html(K + 'person.thValue') + '</th><th></th></tr></thead><tbody>' +
        values.map(function (v) {
          const cut = v.indexOf(':');
          return '<tr><td><code>' + kit.esc(cut > 0 ? v.slice(0, cut) : '') +
            '</code></td><td><code>' + kit.esc(cut > 0 ? v.slice(cut + 1)
                                                       : v) +
            '</code></td><td>' + (write
              ? form('remove-attribute', v, t.html(K + 'remove')) : '') +
            '</td></tr>';
        }).join('') + '</tbody></table>'
      : '<p class="sub">' + t.html(K + 'person.none') + '</p>';
    const derive = write
      ? '<div data-cert-binding="' + kit.esc(user) + '">' +
        '<h3>' + t.html(K + 'person.deriveHeading') + '</h3>' +
        kit.note(t.html(K + 'person.deriveNote')) +
        '<div class="formrow"><label for="cs-person-pem">' +
        t.html(K + 'person.pemLabel') + '</label><br><textarea ' +
        'id="cs-person-pem" rows="5" cols="64" spellcheck="false" ' +
        'data-cb-pem></textarea><br><input type="file" ' +
        'accept=".pem,.crt,.cer" data-cb-pem-file aria-label="' +
        kit.esc(t.text(K + 'chooseFile')) + '"> <button type="button" ' +
        'data-cb-derive>' + t.html(K + 'person.derive') + '</button></div>' +
        '<div data-cb-result></div></div>'
      : kit.note(t.html(K + 'person.needsWrite'));
    return kit.frame('<h2>' + t.html(K + 'person.heading') + '</h2>' +
      kit.note(t.html(K + 'person.lead')) + held) + kit.frame(derive);
  }

  /**
   * The derived values, each with an Add (or a note that it is held).
   *
   * @param t - the page's translator
   * @param user - the person
   * @param answer - the inspection's answer
   * @param held - the values the person holds
   * @param prefix - optional; the console's realm prefix (`/realm/<id>`),
   *   which the Add forms' action carries
   * @returns the HTML
   */
  static derivedBindings(t: Json, user: string, answer: Json,
                         held: string[], prefix?: string): string {
    // A FORM DRAWN AFTER THE PAGE (#2096): `ConsoleRuntime.draw()` puts the
    // realm's prefix on every root-relative action it draws
    // (`WebPage.realmLinks()`), and this table is drawn later, by
    // `wirePerson()`. An action without the prefix is one the console does
    // not claim in a trust realm, so the browser posted it to the DEFAULT
    // realm's /admin/users and nothing was added.
    const action = String(prefix || '') + '/admin/users';
    if (!answer || answer.ok !== true) {
      return '<div class="err">' + kit.esc(((answer && answer.errors) ||
        []).join(' ') || t.text(K + 'problem.inspect')) + '</div>';
    }
    const leaf = (answer.certificates || [])[0] || {};
    const issuer = answer.issuer;
    const rows = (answer.bindings || []).map(function (b: Json) {
      const has = held.indexOf(String(b.value)) >= 0;
      return '<tr><td><code>' + kit.esc(b.method) + '</code></td><td>' +
        '<code>' + kit.esc(b.value) + '</code></td><td>' + (has
          ? '<span class="sub">' + t.html(K + 'person.held') + '</span>'
          : '<form method="post" action="' + kit.esc(action) +
            '" class="inline">' +
            '<input type="hidden" name="action" value="add-attribute">' +
            '<input type="hidden" name="user" value="' + kit.esc(user) +
            '"><input type="hidden" name="from" value="user">' +
            '<input type="hidden" name="attribute" ' +
            'value="stsCertificateBinding"><input type="hidden" ' +
            'name="value" value="' + kit.esc(b.value) + '"><button ' +
            'type="submit">' + t.html(K + 'add') + '</button></form>') +
        '</td></tr>';
    }).join('');
    return '<p>' + t.html(K + 'person.certificate', {
        subject: String(leaf.subject || '') }) + '</p>' +
      (issuer
        ? '<p class="sub">' + t.html(K + 'person.issuerFound', {
            subject: String(issuer.subject), from: String(issuer.from) }) +
          '</p>'
        : kit.warn(t.html(K + 'person.issuerMissing'))) +
      '<table class="grid"><thead><tr><th>' + t.html(K + 'person.thMethod') +
      '</th><th>' + t.html(K + 'person.thValue') + '</th><th></th></tr>' +
      '</thead><tbody>' + rows + '</tbody></table>';
  }

  // =========================================================================
  // THE WIRING (header): called after every drawing.
  // =========================================================================
  /**
   * Wires every structured setting and person binding editor on the page.
   *
   * @param env - the runtime's environment (`document`)
   * @param t - the page's translator
   * @param changed - called when the reader changes a value
   * @param api - `(method, path, body) => Promise<{ status, json }>`, the
   *   runtime's `apiJson()`
   * @param prefix - optional; the console's realm prefix, for a form drawn
   *   after the page (`derivedBindings()`)
   * @returns nothing
   */
  static wire(env: Json, t: Json, changed: () => void,
              api: (method: string, path: string, body?: Json) =>
                Promise<Json>, prefix?: string): void {
    const doc = env && env.document;
    // A stand-in document (a test's) may offer only part of the DOM.
    if (!doc || typeof doc.querySelectorAll !== 'function' ||
        typeof doc.getElementById !== 'function') {
      return;
    }
    const places = doc.querySelectorAll('[data-structured]');
    let anchors: Promise<Json[]> | null = null;
    const readAnchors = function (): Promise<Json[]> {
      if (!anchors) {
        anchors = Promise.resolve(api('GET', TRUSTSTORE))
          .then(function (answer: Json) {
            return answer && answer.status === 200 && answer.json &&
              Array.isArray(answer.json.anchors) ? answer.json.anchors : [];
          }, function () {
            // No truststore to offer: a hash is typed or read from a CA's
            // certificate instead, and the editor says there is none.
            return [];
          });
      }
      return anchors;
    };
    for (let i = 0; i < places.length; i++) {
      CertSignInEditors.wireOne(doc, places[i], t, changed, api, readAnchors);
    }
    const people = doc.querySelectorAll('[data-cert-binding]');
    for (let i = 0; i < people.length; i++) {
      CertSignInEditors.wirePerson(people[i], t, api, prefix);
    }
  }

  /**
   * The text of a chosen file, put in a box.
   *
   * @param input - the file input
   * @param box - the box
   * @returns nothing
   */
  static readFileInto(input: Json, box: Json): void {
    const file = input && input.files && input.files[0];
    if (!file || !box) {
      return;
    }
    Promise.resolve(file.text()).then(function (text: string) {
      box.value = String(text);
      input.value = '';
    }, function (e: Json) {
      // The reason is the browser's; the box says the read failed, in
      // English, as every failure does (#539).
      box.value = 'Could not read ' + String(file.name || '') + ': ' +
        String((e && e.message) || e);
    });
  }

  /**
   * Wires one structured setting's editor to its box.
   *
   * @param doc - the document
   * @param place - the editor's place
   * @param t - the page's translator
   * @param changed - called when the reader changes a value
   * @param api - the runtime's `apiJson()`
   * @param readAnchors - the client truststore, read once per drawing
   * @returns nothing
   */
  static wireOne(doc: Json, place: Json, t: Json, changed: () => void,
                 api: Json, readAnchors: () => Promise<Json[]>): void {
    const kind = String(place.getAttribute('data-structured') || '');
    const box = doc.getElementById(
      String(place.getAttribute('data-structured-for') || ''));
    if (!box || box.disabled) {
      WebSafeDom.render(place, '');
      return;
    }
    const pretty = place.getAttribute('data-structured-pretty') === '1';
    const state: Json = { problem: '', note: '', detail: '',
                          prefix: String(box.id || kind) };
    const read = function (): boolean {
      const text = String(box.value || '');
      const parsed = kind === 'profiles'
        ? CertSignInEditors.parseProfiles(text)
        : kind === 'listeners' ? CertSignInEditors.parseListeners(text)
        : kind === 'applications'
          ? CertSignInEditors.parseApplications(text)
          : CertSignInEditors.parsePems(text);
      if (!parsed.ok) {
        state.unread = parsed.problem;
        return false;
      }
      state.unread = '';
      state.profiles = parsed.profiles;
      state.listeners = parsed.listeners;
      state.entries = parsed.entries;
      if (kind === 'pems') {
        state.blocks = parsed.blocks;
      }
      return true;
    };
    const textOf = function (): string {
      return kind === 'profiles'
        ? CertSignInEditors.profilesText(state.profiles, pretty)
        : kind === 'listeners'
          ? CertSignInEditors.listenersText(state.listeners, pretty)
          : kind === 'applications'
            ? CertSignInEditors.applicationsText(state.entries, pretty)
            : CertSignInEditors.pemsText(state.blocks);
    };
    const draw = function (): void {
      if (state.unread) {
        WebSafeDom.render(place, kit.warn(t.html(K + 'problem.unread') +
          ' ' + t.html(K + 'problem.' + state.unread)));
        const details = box.closest ? box.closest('details') : null;
        if (details) {
          details.open = true;
        }
        return;
      }
      WebSafeDom.render(place, kind === 'profiles'
        ? CertSignInEditors.profilesEditor(state, t)
        : kind === 'listeners' ? CertSignInEditors.listenersEditor(state, t)
        : kind === 'applications'
          ? CertSignInEditors.applicationsEditor(state, t)
          : CertSignInEditors.pemsEditor(state, t));
    };
    const write = function (): void {
      box.value = textOf();
      if (typeof changed === 'function') {
        changed();
      }
    };
    const inspect = function (): void {
      if (kind !== 'pems' || !state.blocks.length) {
        state.facts = [];
        return;
      }
      state.facts = null;
      Promise.resolve(api('POST', INSPECT,
        { pem: state.blocks.join('\n') })).then(function (answer: Json) {
        const ok = answer && answer.json && answer.json.ok === true;
        state.facts = ok ? answer.json.certificates : [];
        if (!ok) {
          state.problem = 'inspect';
          state.detail = ((answer && answer.json && answer.json.errors) ||
                          []).join(' ');
        }
        draw();
      }, function () {
        state.facts = [];
        state.problem = 'inspect';
        draw();
      });
    };
    read();
    if (kind === 'profiles') {
      state.anchors = null;
      readAnchors().then(function (list: Json[]) {
        state.anchors = list;
        draw();
      });
    }
    inspect();
    draw();
    // A VALUE TYPED INTO THE BOX is read back; one the editor cannot read
    // leaves the editor saying so until the box holds one it can.
    box.addEventListener('change', function () {
      read();
      state.problem = '';
      inspect();
      draw();
    });
    const indexOf = function (el: Json): number {
      return Number(el.getAttribute('data-cs-i'));
    };
    const apply = function (act: Json): void {
      state.problem = '';
      state.note = '';
      state.detail = '';
      if (kind === 'profiles') {
        const out = CertSignInEditors.applyProfile(state.profiles, act);
        state.profiles = out.profiles;
        state.problem = out.problem;
      } else if (kind === 'listeners') {
        state.listeners = CertSignInEditors.applyListener(state.listeners,
                                                          act);
      } else if (kind === 'applications') {
        state.entries = CertSignInEditors.applyApplication(state.entries,
                                                           act);
      }
      write();
    };
    // TYPING changes the value and draws nothing, so the field keeps its
    // focus and a button pressed next is still the button it was.
    place.addEventListener('input', function (event: Json) {
      const el = event && event.target;
      if (!el || !el.getAttribute) {
        return;
      }
      const text = el.getAttribute('data-cs-text');
      const tls = el.getAttribute('data-cs-tls');
      if (text) {
        apply({ op: 'text', index: indexOf(el), field: text,
                value: el.value });
      } else if (tls) {
        apply({ op: tls === 'name' ? 'tls-name' : 'tls-value',
                index: indexOf(el), row: el.getAttribute('data-cs-row'),
                value: el.value });
      }
    });
    // ENTER IN A BOX TYPED FOR A LIST ADDS TO THE LIST: the box is inside
    // the settings form, whose Save Enter would otherwise press.
    place.addEventListener('keydown', function (event: Json) {
      const el = event && event.target;
      if (!el || !el.getAttribute || event.key !== 'Enter' ||
          !el.getAttribute('data-cs-new')) {
        return;
      }
      event.preventDefault();
      const scope = el.closest ? (el.closest('.cs-card') || place) : place;
      const button = scope.querySelector('[data-cs-act="add-value"]' +
        '[data-cs-list="' + el.getAttribute('data-cs-new') + '"]');
      if (button) {
        button.click();
      }
    });
    place.addEventListener('change', function (event: Json) {
      const el = event && event.target;
      if (!el || !el.getAttribute) {
        return;
      }
      if (el.hasAttribute && el.hasAttribute('data-cs-pem-file')) {
        const scope = el.closest ? (el.closest('.cs-card') || place) : place;
        CertSignInEditors.readFileInto(el,
          scope.querySelector('[data-cs-pem]'));
        return;
      }
      const toggle = el.getAttribute('data-cs-toggle');
      const flag = el.getAttribute('data-cs-flag');
      if (toggle) {
        apply({ op: 'toggle', index: indexOf(el), field: toggle,
                value: el.getAttribute('data-cs-value'), on: !!el.checked });
        draw();
      } else if (flag) {
        apply({ op: 'flag', index: indexOf(el), field: flag,
                on: !!el.checked });
        draw();
      } else if (el.getAttribute('data-cs-text') === 'listeners' ||
                 el.tagName === 'SELECT') {
        // The advertised listener's choices follow the listeners typed.
        draw();
      }
    });
    place.addEventListener('click', function (event: Json) {
      const el = event && event.target && event.target.closest
        ? event.target.closest('[data-cs-act]') : null;
      if (!el) {
        return;
      }
      const act = String(el.getAttribute('data-cs-act'));
      const index = indexOf(el);
      const scope = el.closest('.cs-card') || place;
      if (act === 'add' || act === 'remove' || act === 'tls-add' ||
          act === 'tls-remove') {
        if (kind === 'pems' && act === 'remove') {
          state.blocks.splice(index, 1);
          if (Array.isArray(state.facts)) {
            state.facts.splice(index, 1);
          }
          write();
        } else {
          apply({ op: act, index: index,
                  row: el.getAttribute('data-cs-row') });
        }
      } else if (act === 'move') {
        apply({ op: 'move', index: index,
                delta: Number(el.getAttribute('data-cs-delta')) });
      } else if (act === 'remove-value') {
        apply({ op: 'toggle', index: index,
                field: el.getAttribute('data-cs-list'),
                value: el.getAttribute('data-cs-value'), on: false });
      } else if (act === 'add-value') {
        const list = String(el.getAttribute('data-cs-list'));
        const input = scope.querySelector('[data-cs-new="' + list + '"]');
        apply({ op: 'value', index: index, field: list,
                value: input ? input.value : '' });
      } else if (act === 'add-pick') {
        const pick = scope.querySelector('[data-cs-pick]');
        apply({ op: 'value', index: index, field: 'issuers',
                value: pick ? pick.value : '' });
      } else if (act === 'read-pem' || act === 'add-pems') {
        const area = scope.querySelector('[data-cs-pem]');
        const text = area ? String(area.value || '') : '';
        if (act === 'add-pems') {
          const out = CertSignInEditors.addPems(state.blocks, text);
          state.problem = out.added ? '' : 'notPem';
          state.blocks = out.blocks;
          if (out.added) {
            write();
            inspect();
          }
          draw();
          return;
        }
        // A CA'S CERTIFICATE, READ BY THE SERVER: its SubjectPublicKeyInfo's
        // SHA-256 is what the profile names it by.
        Promise.resolve(api('POST', INSPECT, { pem: text }))
          .then(function (answer: Json) {
            const json = answer && answer.json;
            if (!json || json.ok !== true) {
              state.problem = 'inspect';
              state.detail = ((json && json.errors) || []).join(' ');
              draw();
              return;
            }
            const certs: Json[] = json.certificates || [];
            const cas = certs.filter(function (c) { return c.ca; });
            (cas.length ? cas : certs).forEach(function (c) {
              apply({ op: 'value', index: index, field: 'issuers',
                      value: c.spkiSha256 });
            });
            state.note = t.text(K + 'issuers.readNote', {
              n: String((cas.length ? cas : certs).length) });
            draw();
          }, function () {
            state.problem = 'inspect';
            draw();
          });
        return;
      } else {
        return;
      }
      draw();
    });
  }

  /**
   * Wires a person's Derive button.
   *
   * @param root - the person's binding editor
   * @param t - the page's translator
   * @param api - the runtime's `apiJson()`
   * @param prefix - optional; the console's realm prefix
   * @returns nothing
   */
  static wirePerson(root: Json, t: Json, api: Json, prefix?: string): void {
    const user = String(root.getAttribute('data-cert-binding') || '');
    const area = root.querySelector('[data-cb-pem]');
    const file = root.querySelector('[data-cb-pem-file]');
    const button = root.querySelector('[data-cb-derive]');
    const result = root.querySelector('[data-cb-result]');
    if (!area || !button || !result) {
      return;
    }
    if (file) {
      file.addEventListener('change', function () {
        CertSignInEditors.readFileInto(file, area);
      });
    }
    // The values the person holds, as the held table drew them.
    const held: string[] = [];
    const page = root.ownerDocument || null;
    const forms = page ? page.querySelectorAll(
      'form input[name="action"][value="remove-attribute"]') : [];
    for (let i = 0; i < forms.length; i++) {
      const value = forms[i].form
        ? forms[i].form.querySelector('input[name="value"]') : null;
      const attribute = forms[i].form
        ? forms[i].form.querySelector('input[name="attribute"]') : null;
      if (value && attribute &&
          attribute.value === 'stsCertificateBinding') {
        held.push(String(value.value));
      }
    }
    button.addEventListener('click', function () {
      Promise.resolve(api('POST', INSPECT,
        { pem: String(area.value || ''), bindings: true }))
        .then(function (answer: Json) {
          WebSafeDom.render(result, CertSignInEditors.derivedBindings(t,
            user, answer && answer.json, held, prefix));
        }, function () {
          WebSafeDom.render(result, CertSignInEditors.derivedBindings(t,
            user, null, held, prefix));
        });
    });
  }
}

export = CertSignInEditors;
