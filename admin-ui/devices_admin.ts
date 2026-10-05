// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: devices_admin.ts
//
// ===========================================================================
// THE DEVICE REGISTER'S THREE CONSOLE PAGES (#164 phase 1 and #218,
// 2026-09-26), and what the management API mirrors of them (rule 7).
//
//   * **/admin/devices** — Directory → Devices. Every device in the realm,
//     paged and filtered by owner kind, compliance, attestation, key kind and
//     a search; `?device=<id>` is one device — its owner, the applications
//     that used it, its keys, attestation, compliance, Native SSO state and
//     last use — with every edit an administrator makes: the label and the
//     descriptive fields, a new owner (a person or an application), a key
//     added or removed, and removal. A form at the foot of the list registers
//     one by hand (decision 6a).
//   * **/admin/device-registration** — Protocols → Device registration. HOW a
//     device arrives and is recognised: each enrolment method and whether it
//     is built yet, the kinds of key, what attestation means here, and the
//     `Devices` settings group (`SETTING_HOMES`).
//   * **/admin/devices/monitor** — Monitoring → Devices. The register counted
//     (owner kind, compliance, attestation, key kind, live against ended
//     Native SSO sign-ins) and its events over time — creations, removals and
//     evictions at a person's bound.
//
// The fourth view #218 names, `/admin/ldap/devices`, is `ldap/ldap_server.js`
// beside the other `/admin/ldap/*` pages, for the reason those are there.
//
// Filed under three sections by the console's filing rule (a page goes where
// the question it answers is asked): *what is in the directory*, *how does a
// device arrive*, and *what happened*. One module, `mail_admin.ts`'s
// arrangement, because the three are views of one register.
//
// **THE CONSOLE AND THE API NEVER FORWARD A PROOF OR AN ATTESTATION.** A key
// added here is recorded with proof `admin` and attestation `self-asserted`:
// an administrator typing a public key proves nothing about who holds the
// private half, and a body claiming `attested` would be the one lie the
// register exists to make impossible. `keySpecOf()` builds the spec from
// three fields and nothing else.
// ===========================================================================

import admin = require('./admin');
import adminViews = require('../admin-core/admin_views');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import devices = require('../common/devices');
// #164 phase 2: the challenge store, the recognition and enrolment
// counters, and the attestation trust anchors this page reports.
import deviceEnrolment = require('../common/device_enrolment');
import deviceRecognition = require('../common/device_recognition');
import pki = require('../common/pki');
import config = require('../common/config');
import mode = require('../common/mode');
import oauth2 = require('../oauth-oidc/oauth2');
// The SPKI thumbprint of a certificate an MDM names a device by (#164).
import stsCrypto = require('../common/crypto');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

/**
 * Directory → Devices: the realm's device list, and one device by `?device=`.
 */
const LIST = '/admin/devices';
/**
 * Protocols → Device registration: how a device arrives and is recognised.
 */
const REGISTRATION = '/admin/device-registration';
/**
 * Monitoring → Devices: the register counted, and its events over time.
 */
const MONITOR = '/admin/devices/monitor';

// The actions the list page takes, for the sentence an unknown one is
// answered with (the parity jobs read the list back out of it).
/**
 * The actions the device list page takes.
 */
const ACTIONS = ['create', 'update', 'remove', 'add-key', 'remove-key',
                 'set-compliance', 'set-status'];

// DEVELOPMENT'S COMPLIANCE TEST CONTROL (#164 decision 9, phase 3): a public
// path, not under /admin, that sets a device's compliance with no credential
// at all — what a client under test drives to see its session and tokens
// react — refused in product by `mode.opensTestControls()`.
/**
 * Development's compliance test control: a public path that sets a device's
 * compliance with no credential, refused in product mode.
 */
const TEST_CONTROL = '/devices/test/compliance';

// The compliance states a DOOR may set. `unknown` is what a device starts
// as; an administrator may put it back (withdrawing a vouch), and a feed or
// the test control reports one of the two CAEP knows.
const FEED_STATES = ['compliant', 'not-compliant'];

// The filters a list takes, each a query parameter of the same name.
const FILTERS = ['q', 'ownerKind', 'owner', 'application', 'compliance',
                 'attestation', 'keyKind', 'status'];

// HOW A DEVICE ARRIVES (#164 decision 6) and whether each door is built. The
// state is a fact about THIS build, not a promise: a door not built yet is
// said to be not built, and the ticket carries when it lands.
const ENROLMENT = [
  { method: 'native-sso', built: true,
    what: 'OpenID Connect Native SSO for Mobile Apps: the first app\'s ' +
          'authorization-code grant with the device_sso scope makes the ' +
          'device and hands it a device_secret, hashed on the entry and ' +
          'good for that sign-on session only.' },
  { method: 'admin', built: true,
    what: 'An administrator, on Directory → Devices or POST ' +
          '/admin-api/devices/create: owned by a person or by an ' +
          'application, with keys typed in by value. A key added this way ' +
          'is recorded as proven by nobody and self-asserted.' },
  { method: 'portal', built: true,
    what: 'The owner on /portal/devices (or its JSON doors, ' +
          'POST /portal/devices/challenge and /portal/devices/proof), ' +
          'proving a key: a device-key-proof+jwt JWS over a challenge ' +
          'bound to their session — with an Android Key Attestation in ' +
          'its x5c, or an Apple App Attest statement instead — or linking ' +
          'a WebAuthn platform credential they enrolled, with a fresh ' +
          'assertion.' },
  { method: 'est', built: true,
    what: 'EST (RFC 7030) simpleenroll at /.well-known/est/device/: a ' +
          'certificate issued to the device entry the request\'s ' +
          'urn:sts:device:<id> names — or to a new one, owned by the ' +
          'requester — with a TPM key attestation ' +
          '(draft-ietf-lamps-csr-attestation, tcg-attest-tpm-certify). ' +
          'The owner for their own device, Admin Write for any.' },
  { method: 'scep', built: true,
    what: 'SCEP (RFC 8894) PKCSReq with a challenge password issued for ' +
          'the device profile — the same, for the devices that speak only ' +
          'it.' }
];

// HOW A DEVICE IS RECOGNISED (#164 decision 1): presenting any key it holds.
const RECOGNITION = [
  { kind: 'x509', built: true,
    what: 'The client certificate on the TLS connection — at a sign-in and ' +
          'at the token endpoint (RFC 8705) — matched by the SHA-256 of its ' +
          'SubjectPublicKeyInfo, so a renewed certificate over the same key ' +
          'is the same device. The handshake proves possession; whether ' +
          'the chain verified is recorded, and a certificate refused on ' +
          'revocation is not recognised.' },
  { kind: 'jwk', built: true,
    what: 'A DPoP proof at the token endpoint, matched by its jkt — the ' +
          'RFC 7638 thumbprint every jwk key carries.' },
  { kind: 'webauthn', built: true,
    what: 'A WebAuthn assertion at a sign-in whose credential is linked to ' +
          'the device.' },
  { kind: 'native-sso', built: true,
    what: 'The Native SSO device_secret, while the sign-on session it was ' +
          'issued for is live.' }
];

interface DevicesAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  adminViews: typeof adminViews;
  errorCodes: typeof errorCodes;
  devices: typeof devices;
  oauth2: typeof oauth2;
  parseBody: typeof helpers.parseBody;
}

/**
 * The device register's three console pages, and the views and actions the
 * management API mirrors of them (rule 7).
 */
class DevicesAdmin {
  /**
   * See the module's `LIST`.
   */
  static readonly LIST = LIST;
  /**
   * See the module's `REGISTRATION`.
   */
  static readonly REGISTRATION = REGISTRATION;
  /**
   * See the module's `MONITOR`.
   */
  static readonly MONITOR = MONITOR;
  /**
   * See the module's `ACTIONS`.
   */
  static readonly ACTIONS = ACTIONS;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the console, the device register and the modules it reads
   */
  constructor(private readonly deps: DevicesAdminDeps) {
    deps.log.debug("Entering DevicesAdmin.constructor().");
    deps.log.debug("Leaving DevicesAdmin.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): DevicesAdminDeps {
    helpers.log.debug("Entering DevicesAdmin.defaultDeps().");
    helpers.log.debug("Leaving DevicesAdmin.defaultDeps().");
    return {
      log: helpers.log,
      admin: admin,
      adminViews: adminViews,
      errorCodes: errorCodes,
      devices: devices,
      oauth2: oauth2,
      parseBody: helpers.parseBody
    };
  }

  // Who is acting: the console session's person, or '' for an API caller.
  /**
   * Answers who is acting: the console session's person, or an empty string for
   * an API caller.
   *
   * @param req - the request
   * @returns the actor's name, or ''
   */
  actorOf(req: Req): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering DevicesAdmin.actorOf().");
    let who = '';
    try {
      const state: Json = adminViews.gateStateFor(req);
      who = String((state && state.username) || '');
    } catch (e) {
      log.debug("Caught in DevicesAdmin.actorOf(): " +
                ((e && e.message) || e));
      who = '';
    }
    log.debug("Leaving DevicesAdmin.actorOf().");
    return who;
  }

  private refuse(code: string, why: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering DevicesAdmin.refuse(). " + code);
    log.debug("Leaving DevicesAdmin.refuse().");
    return errorCodes.mark({ ok: false, errors: [why] }, code);
  }

  // Whether a device's Native SSO secret is bound to a live session of its
  // owner — the question `oauth2.sessionIsLive()` answers, asked with the
  // owner's username so another person's session never counts.
  private liveness(device: Json): (session: string) => boolean {
    const { log, devices, oauth2 } = this.deps;
    log.debug("Entering DevicesAdmin.liveness().");
    const owner = device.ownerKind === 'person'
      ? devices.ownerOf(device.owner) : null;
    log.debug("Leaving DevicesAdmin.liveness().");
    return function (session: string): boolean {
      return !!owner && !!session &&
             oauth2.sessionIsLive(session, owner.name);
    };
  }

  // A device as both surfaces show it: the register's view, with its
  // owner's and applications' names read back out of the directory.
  /**
   * Describes a device as both surfaces show it: the register's view with its
   * owner's and applications' names read back out of the directory.
   *
   * @param device - a device from the register
   * @returns the device's row
   */
  row(device: Json): Json {
    const { log, devices } = this.deps;
    log.debug("Entering DevicesAdmin.row().");
    const out = devices.view(device, this.liveness(device));
    const owner = devices.ownerOf(device.owner);
    out.ownerName = owner ? owner.name : '';
    out.ownerFound = !!owner;
    out.applicationNames = device.applications.map(function (dn: string) {
      const found = devices.ownerOf(dn);
      return found ? found.name : '';
    });
    log.debug("Leaving DevicesAdmin.row().");
    return out;
  }

  private filterOf(query: Json): Json {
    const { log } = this.deps;
    log.debug("Entering DevicesAdmin.filterOf().");
    const out: Json = {};
    const q = query || {};
    FILTERS.forEach(function (name) {
      const value = Array.isArray(q[name]) ? q[name][0] : q[name];
      if (value !== undefined && String(value).trim() !== '') {
        out[name] = String(value).trim();
      }
    });
    log.debug("Leaving DevicesAdmin.filterOf().");
    return out;
  }

  // -------------------------------------------------------------------------
  // /admin/devices — the JSON both surfaces answer. `device=<id>` is one
  // device's drill-down, with `found: false` rather than a 404 for an id the
  // realm does not hold (an answer, not a routing problem).
  // -------------------------------------------------------------------------
  /**
   * Builds `/admin/devices`' view: the realm's devices, filtered and paged, or
   * one device's drill-down when the query names `device`.
   *
   * An id the realm does not hold answers `found: false` rather than a 404.
   * @param req - the request
   * @param query - the query's values
   * @returns the list or the one device
   */
  listView(req: Req, query?: Json): Json {
    const { log, adminViews, devices } = this.deps;
    log.debug("Entering DevicesAdmin.listView().");
    const self = this;
    const q = query || {};
    const vocabulary = {
      ownerKinds: devices.OWNER_KINDS.slice(0),
      keyKinds: devices.KEY_KIND_FILTERS.slice(0),
      compliance: devices.COMPLIANCE_STATES.slice(0),
      attestation: devices.ATTESTATION_LEVELS.slice(0),
      statuses: devices.STATUSES.slice(0),
      platforms: devices.PLATFORMS.slice(0)
    };
    if (q.device !== undefined) {
      const found = devices.byId(String(q.device || ''));
      log.debug("Leaving DevicesAdmin.listView(). One device.");
      return { found: !!found, id: String(q.device || ''),
               device: found ? self.row(found) : null,
               vocabulary: vocabulary };
    }
    const filter = this.filterOf(q);
    const rows = devices.list(filter);
    const paged = adminViews.pagedRows(q, rows, { noun: 'devices' });
    const out: Json = {
      // Counted by the store (#352): no second copy of every device.
      total: devices.count(),
      matched: rows.length,
      filter: filter,
      devices: paged.shown.map(function (d: Json) {
        return self.row(d);
      }),
      page: paged.paging.page, pages: paged.paging.pages,
      perPage: paged.paging.perPage,
      devicesPaging: adminViews.pagingJson(paged.paging),
      vocabulary: vocabulary
    };
    Object.defineProperty(out, 'paging', { value: paged.paging,
                                           enumerable: false });
    log.debug("Leaving DevicesAdmin.listView(). " + rows.length + ".");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE MDM / POSTURE FEED (#164 decision 2, phase 3): `POST
  // /admin-api/device-compliance`, under the protected `device:compliance`
  // scope (the gate in `mgmt-api/admin_api.ts`). The body is one report or
  // `{ reports: [...] }`; each report names its device by `id`, by a key
  // `thumbprint` (with an optional `keyKind`: x509, jwk or webauthn), or by
  // the device's `certificate` (PEM, matched by its SubjectPublicKeyInfo —
  // what an MDM that issued or inventoried the certificate knows), and says
  // `status` (compliant or not-compliant) and, optionally, `reason`. It sets
  // COMPLIANCE ONLY: ownership, keys and status are an administrator's.
  //
  // Every report is answered on its own, in order, and one that names no
  // device or no status is refused without stopping the rest — a posture
  // feed sends a whole fleet and one retired device must not lose the other
  // nine hundred. The change is recorded `source: mdm` with the CLIENT as
  // the actor, so Monitoring → Devices and CAEP's reason say which feed.
  // -------------------------------------------------------------------------
  /**
   * Applies an MDM or posture feed's compliance reports, each on its own and in
   * order: `POST /admin-api/device-compliance`, and the test control.
   *
   * Each report names its device by `id`, a key `thumbprint` or a
   * `certificate`, and sets compliance only. A report that names no device or
   * no status is refused without stopping the rest; a batch outside
   * `devices.complianceFeedMaxReports` is refused whole.
   * @param body - one report, or `{ reports: [...] }`
   * @param clientId - the feed's client, recorded as the actor
   * @param source - `test-control` for the test control; otherwise `mdm`
   * @returns how many were applied and refused, and each report's result
   */
  mdmFeed(body: Json, clientId: string, source?: string): Json {
    const { log } = this.deps;
    log.debug("Entering DevicesAdmin.mdmFeed().");
    const b = body || {};
    const from = source === 'test-control' ? 'test-control' : 'mdm';
    const reports: Json[] = Array.isArray(b.reports) ? b.reports : [b];
    const max = Number(config.value('devices.complianceFeedMaxReports'));
    if (!reports.length || reports.length > max) {
      log.debug("Leaving DevicesAdmin.mdmFeed(). Batch size.");
      return this.refuse('STS-DEVICE-0034', 'A compliance report carries ' +
        'between 1 and ' + max + ' reports ' +
        '(devices.complianceFeedMaxReports); this one carries ' +
        reports.length + '.');
    }
    const results = reports.map((report: Json, index: number): Json => {
      const one = report && typeof report === 'object' ? report : {};
      const device = this.deviceNamedBy(one);
      const status = String(one.status || '').trim();
      if (!device) {
        return errorCodes.mark({ index: index, ok: false, errors: [
          'No device in this realm is named by that ' +
          (one.id ? 'id' : one.thumbprint ? 'thumbprint' : one.certificate
            ? 'certificate' : 'report — give id, thumbprint or ' +
                              'certificate') + '.'] }, 'STS-DEVICE-0007');
      }
      if (FEED_STATES.indexOf(status) < 0) {
        return errorCodes.mark({ index: index, id: device.id, ok: false,
          errors: ['A report\'s status is compliant or not-compliant, not "' +
                   status.slice(0, 32) + '".'] }, 'STS-DEVICE-0011');
      }
      const done = devices.setCompliance(device.id, status, from,
        clientId || from, String(one.reason || '').slice(0, 500) ||
        (from === 'mdm' ? 'Reported by the MDM feed' +
                          (clientId ? ' ' + clientId : '') + '.'
                        : 'Set by the development test control.'));
      return done.ok
        ? { index: index, id: device.id, ok: true, previous: done.previous,
            status: done.status, changed: done.changed,
            signalled: done.signalled }
        : Object.assign({ index: index, id: device.id }, done);
    });
    const applied = results.filter(function (r: Json) {
      return r.ok;
    }).length;
    log.info('devices: ' + from + ' feed' + (clientId ? ' ' + clientId : '') +
             ' reported ' + reports.length + ' device(s); ' + applied +
             ' applied.');
    log.debug("Leaving DevicesAdmin.mdmFeed(). " + applied + " applied.");
    const out: Json = { ok: applied > 0, applied: applied,
                        refused: results.length - applied, results: results,
                        message: applied + ' of ' + results.length +
                                 ' report(s) applied.' };
    if (!applied) {
      out.errors = ['No report was applied: ' + results.map(function (r) {
        return (r.errors || []).join(' ');
      }).join(' | ')];
      errorCodes.mark(out, errorCodes.codeOf(results[0]) ||
                           'STS-DEVICE-0007');
    }
    return out;
  }

  // The device a report names: by `id`, by a key `thumbprint` (optionally
  // `keyKind`), or by its `certificate`'s SubjectPublicKeyInfo. Null for
  // none.
  private deviceNamedBy(report: Json): Json {
    const { log, devices } = this.deps;
    log.debug("Entering DevicesAdmin.deviceNamedBy().");
    let found: Json = null;
    if (report.id) {
      found = devices.byId(String(report.id));
    } else if (report.thumbprint) {
      const kind = String(report.keyKind || '').trim();
      found = devices.byKeyThumbprint(String(report.thumbprint).trim(),
        devices.KEY_KINDS.indexOf(kind) >= 0 ? kind : undefined);
    } else if (report.certificate) {
      try {
        found = devices.byKeyThumbprint(stsCrypto.certificateSpkiThumbprint(
          String(report.certificate).trim()), 'x509');
      } catch (e) {
        log.debug("Caught in DevicesAdmin.deviceNamedBy(): " +
                  ((e && e.message) || e));
        found = null;
      }
    }
    log.debug("Leaving DevicesAdmin.deviceNamedBy(). " + !!found);
    return found;
  }

  // The one key a console form or an API body names: kind, value, label —
  // and NOTHING about proof or attestation (header).
  private keySpecOf(b: Json): Json {
    const { log } = this.deps;
    log.debug("Entering DevicesAdmin.keySpecOf().");
    const kind = String(b.keyKind || b.kind || '').trim();
    const value = b.key !== undefined ? b.key
      : (b.value !== undefined ? b.value
        : (b.certificate !== undefined ? b.certificate
          : (b.jwk !== undefined ? b.jwk : b.credentialId)));
    log.debug("Leaving DevicesAdmin.keySpecOf().");
    return { kind: kind, value: value, label: b.keyLabel !== undefined
      ? b.keyLabel : b.label, proof: 'admin' };
  }

  // -------------------------------------------------------------------------
  // THE LIST PAGE'S ACTIONS: create, update, remove, add-key, remove-key.
  // `actor` is who pressed it (the console's person, or '' for an API
  // token), `via` which surface.
  // -------------------------------------------------------------------------
  /**
   * Takes one of the list page's actions: create, update, remove, add-key or
   * remove-key.
   *
   * @param body - the action and its fields
   * @param actor - who pressed it; '' for an API token
   * @param via - which surface asked
   * @returns `ok` with a message, or a refusal
   */
  action(body: Json, actor: string, via: string): Json {
    const { log, devices } = this.deps;
    log.debug("Entering DevicesAdmin.action().");
    const b = body || {};
    const action = String(b.action || '');
    const who = actor || via;
    if (ACTIONS.indexOf(action) < 0) {
      log.debug("Leaving DevicesAdmin.action(). Unknown.");
      return this.refuse('STS-DEVICE-0013', 'Unknown action "' + action +
        '". The ' + helpers.numberWord(ACTIONS.length) + ' are: ' +
        devices.sentence(ACTIONS) + '.');
    }
    const id = String(b.id || b.device || '').trim();
    if (action !== 'create' && !id) {
      log.debug("Leaving DevicesAdmin.action(). No device.");
      return this.refuse('STS-DEVICE-0007', 'Name the device in `id`.');
    }
    let result: Json;
    if (action === 'create') {
      const keys: Json[] = Array.isArray(b.keys)
        ? b.keys.map((k: Json) => this.keySpecOf(k || {}))
        : (String(b.keyKind || '').trim() && b.key !== undefined &&
           String(b.key).trim() !== '' ? [this.keySpecOf(b)] : []);
      result = devices.create({
        label: b.label, ownerKind: b.ownerKind, owner: b.owner,
        platform: b.platform, model: b.model, os: b.os,
        applications: b.applications, keys: keys, method: 'admin'
      }, who);
    } else if (action === 'update') {
      result = devices.update(id, {
        label: b.label, ownerKind: b.ownerKind, owner: b.owner,
        platform: b.platform, model: b.model, os: b.os,
        applications: b.applications
      }, who);
    } else if (action === 'remove') {
      result = devices.remove(id, undefined, who);
    } else if (action === 'add-key') {
      result = devices.addKey(id, this.keySpecOf(b), who);
    } else if (action === 'remove-key') {
      result = devices.removeKey(id, b.key || b.keyId, who);
    } else if (action === 'set-compliance') {
      // AN ADMINISTRATOR'S VOUCH (#164 phase 3): compliant, not-compliant,
      // or back to unknown. Recorded `source: admin`.
      result = devices.setCompliance(id, String(b.status || b.compliance ||
                                               '').trim(), 'admin', who,
                                     String(b.reason || '').slice(0, 500));
    } else {
      // COMPROMISED, OR RESTORED (#164 phase 4): `devices.setStatus()` does
      // what a compromise causes — its header argues it.
      result = devices.setStatus(id, String(b.status || '').trim(), who,
                                 String(b.reason || '').slice(0, 500),
                                 { initiatingEntity: 'admin' });
    }
    if (!result.ok) {
      log.debug("Leaving DevicesAdmin.action(). Refused.");
      return result;
    }
    log.debug("Leaving DevicesAdmin.action(). " + action);
    const message = result.message ||
      (action === 'set-compliance' ? 'Device ' + id + ' is ' + result.status +
        (result.changed ? ' (was ' + result.previous + ')' : ' (unchanged)') +
        '.'
        : action === 'set-status' ? 'Device ' + id + ' is ' + result.status +
          (result.status === 'compromised' && result.previous !== 'compromised'
            ? ': ' + result.sessionsEnded + ' sign-on session(s) it ' +
              'authenticated were ended, ' + result.certificatesRevoked +
              ' certificate(s) revoked' + (result.secretRevoked
                ? ' and its Native SSO secret revoked' : '')
            : '') + '.' : '');
    return { ok: true, message: message,
             id: result.device ? result.device.id : (result.removed || id),
             device: result.device ? this.row(result.device) : undefined,
             key: result.key ? result.key.id : undefined,
             previous: result.previous, status: result.status,
             sessionsEnded: result.sessionsEnded,
             certificatesRevoked: result.certificatesRevoked };
  }

  // -------------------------------------------------------------------------
  // /admin/device-registration — the JSON both surfaces answer.
  // -------------------------------------------------------------------------
  // The attestation trust anchors, per statement kind: where they come
  // from in this realm and, for the shipped ones, their subjects and pins.
  // Never a certificate's text.
  /**
   * Describes the attestation trust anchors per statement kind: where they come
   * from in this realm and, for the shipped ones, their subjects and pins.
   *
   * @returns the trust anchors; never a certificate's text
   */
  trustAnchors(): Json {
    const { log } = this.deps;
    log.debug("Entering DevicesAdmin.trustAnchors().");
    const shipped = pki.describeDeviceAnchors();
    const row = function (kind: string, setting: string,
                          shippedKind: string): Json {
      log.debug("Entering row(). " + kind);
      const held = pki.deviceAttestationAnchors(shippedKind || kind,
                                                config.value(setting));
      log.debug("Leaving row().");
      return { kind: kind, setting: setting, source: held.source,
               count: held.anchors.length,
               shipped: shippedKind ? shipped[shippedKind] || [] : [] };
    };
    log.debug("Leaving DevicesAdmin.trustAnchors().");
    return [
      row('android-key-attestation', 'devices.androidAttestationTrustAnchors',
          'androidKeyAttestation'),
      row('apple-app-attest', 'devices.appleAppAttestTrustAnchors',
          'appleAppAttest'),
      row('tcg-tpm2-key', 'devices.tpmTrustAnchors', ''),
      { kind: 'webauthn', setting: 'webauthn.attestationTrustAnchors',
        source: 'the FIDO Metadata Service import and the setting, ' +
                'verified at the credential\'s registration (#105)',
        count: null, shipped: [] }
    ];
  }

  /**
   * Builds `/admin/device-registration`'s view: the enrolment methods and
   * whether each is built, the kinds of key, what attestation means here, and
   * the settings.
   *
   * @param req - the request
   * @returns the view
   */
  registrationView(req: Req): Json {
    const { log, admin, devices } = this.deps;
    log.debug("Entering DevicesAdmin.registrationView().");
    log.debug("Leaving DevicesAdmin.registrationView().");
    return {
      enrolment: ENROLMENT.map(function (row) {
        return Object.assign({}, row);
      }),
      recognition: RECOGNITION.map(function (row) {
        return Object.assign({}, row);
      }),
      ownerKinds: devices.OWNER_KINDS.slice(0),
      keyKinds: devices.KEY_KINDS.slice(0),
      keyProofs: devices.KEY_PROOFS.slice(0),
      attestationLevels: devices.ATTESTATION_LEVELS.slice(0),
      attestationFormats: devices.ATTESTATION_FORMATS.slice(0),
      complianceStates: devices.COMPLIANCE_STATES.slice(0),
      complianceSources: devices.COMPLIANCE_SOURCES.slice(0),
      // The four doors that set compliance (#164 phase 3).
      mdmFeed: {
        built: true,
        path: 'POST /admin-api/device-compliance',
        scope: 'device:compliance',
        role: 'DEVICE_COMPLIANCE',
        maxReports: Number(config.value('devices.complianceFeedMaxReports')),
        identifiedBy: ['id', 'thumbprint (with keyKind)', 'certificate'],
        source: 'mdm'
      },
      testControl: {
        path: 'POST ' + TEST_CONTROL,
        open: mode.opensTestControls(),
        predicate: 'opensTestControls',
        source: 'test-control'
      },
      // A federation partner's device-compliance-change, through
      // setCompliance() as the signal-response policy permits (#153, #373,
      // #374 — an MDM being an `ssf` relationship).
      receivedCaep: {
        built: true,
        source: 'caep',
        via: '/admin/federation'
      },
      // What a compliance change, a risk level and a compromise send (#164
      // phase 4): the events and their subject.
      signals: {
        caep: ['device-compliance-change', 'risk-level-change (principal ' +
               'DEVICE)', 'credential-change (x509, fido2-platform, ' +
               'fido2-roaming, ' + devices.DEVICE_KEY_CREDENTIAL_TYPE + ', ' +
               devices.DEVICE_SECRET_CREDENTIAL_TYPE + ')',
               'the device member on session-established, session-presented ' +
               'and session-revoked'],
        risc: ['credential-compromise', 'sessions-revoked'],
        subject: 'complex: device (iss_sub — this realm\'s issuer and the ' +
                 'device id) and user (the owner, where a person)'
      },
      // Where the recognised device is recorded (#164 phase 2).
      recordedAt: {
        signIn: 'the authentication event\'s registeredDevice ' +
                '(authn.registeredDeviceOf(session) reads the latest)',
        tokenEndpoint: 'the issuance request\'s registered_device, ' +
                       'before the issuance gate'
      },
      // WHAT DECIDES ON A DEVICE (#164 phases 5 and 6): risk scoring's
      // signals, the issuance policy's two rules and this realm's switches
      // for them, the acr and the claim. The rules themselves are the
      // issuance policy's (`xacml/xacml_templates.ts`); this says what this
      // realm has switched on.
      decisions: {
        riskSignals: ['compromised-device', 'non-compliant-device',
                      'unregistered-device', 'compliant-attested-device',
                      'compliant-device', 'browser-token-replayed',
                      'browser-token-foreign', 'browser-context-changed'],
        expectRegistered: config.value('devices.expectRegistered') === true,
        refuseCompromised: config.value('devices.refuseCompromised') !==
                           false,
        requireCompliantDevice:
          config.value('devices.requireCompliantDevice') === true,
        compliantDeviceAttested:
          config.value('devices.compliantDeviceAttested') === true,
        policy: 'role-issuance: device-compromised and device-required, ' +
                'reading urn:sts:xacml:device-* and ' +
                'urn:sts:xacml:device-requirement',
        acr: 'urn:sts:acr:compliant-device',
        claim: 'device_id — the register\'s id for a public client, ' +
               'sector-derived for a pairwise one, none for an ephemeral ' +
               'one; in the ID Token, the access token and introspection'
      },
      // Decision 9: whether this realm registers an unattested key.
      unattestedKeys: {
        accepted: mode.acceptsUnattestedDeviceKeys(),
        predicate: 'acceptsUnattestedDeviceKeys',
        adminKeys: 'an administrator\'s by-value key is accepted in both ' +
                   'modes, recorded proof admin and self-asserted'
      },
      trustAnchors: this.trustAnchors(),
      challenges: deviceEnrolment.describeChallenges(),
      settings: admin.configSettingsJson(REGISTRATION)
    };
  }

  // -------------------------------------------------------------------------
  // /admin/devices/monitor — the JSON both surfaces answer. `days` is how
  // many UTC days the timeline covers (30 by default, 366 at most).
  // -------------------------------------------------------------------------
  /**
   * Builds `/admin/devices/monitor`'s view: the register counted and its events
   * over the last `days` UTC days (30 by default, 366 at most).
   *
   * @param req - the request
   * @param query - the query's values
   * @returns the view
   */
  monitorView(req: Req, query?: Json): Json {
    const { log, devices } = this.deps;
    log.debug("Entering DevicesAdmin.monitorView().");
    const self = this;
    const q = query || {};
    const counts = devices.counts(function (d: Json): boolean {
      return self.liveness(d)(d.session);
    });
    log.debug("Leaving DevicesAdmin.monitorView().");
    return { counts: counts, timeline: devices.timeline(Number(q.days) ||
                                                        30),
             // Recognitions, enrolments and attestation outcomes, counted
             // in THIS process (#164 phase 2).
             activity: deviceRecognition.activity(),
             // Where a compliance state can come from, for the page's
             // legend: the register's list, which a page drawn from this
             // answer cannot ask (#446).
             complianceSources: devices.COMPLIANCE_SOURCES.slice(0) };
  }

  // Where a console form goes back to: the device it acted on, or the list
  // once it is gone.
  private backTo(body: Json, result: Json): string {
    const { log } = this.deps;
    log.debug("Entering DevicesAdmin.backTo().");
    const action = String((body && body.action) || '');
    const id = result.ok ? String(result.id || '')
                         : String((body && (body.id || body.device)) || '');
    log.debug("Leaving DevicesAdmin.backTo().");
    return id && !(result.ok && action === 'remove')
      ? LIST + '?device=' + encodeURIComponent(id) : LIST;
  }

  /**
   * Registers the three pages, the list page's actions and the compliance test
   * control.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, admin, errorCodes, parseBody } = this.deps;
    const self = this;
    log.debug("Entering DevicesAdmin.registerRoutes().");
    // THE COMPLIANCE TEST CONTROL (#164 decision 9): development answers
    // anybody, as every test control there does; product refuses it, and
    // the MDM feed under `device:compliance` is the door that remains.
    app.post(TEST_CONTROL, function (req: Req, res: Res): void {
      log.debug('Entering POST ' + TEST_CONTROL + '.');
      res.set('Cache-Control', 'no-store');
      if (!mode.opensTestControls()) {
        log.warn('devices: POST ' + TEST_CONTROL + ' was refused — product ' +
                 'mode does not open test controls.');
        errorCodes.mark(res, 'STS-DEVICE-0035');
        res.status(403).json({ ok: false, errors: [
          'POST ' + TEST_CONTROL + ' is a test control and this realm is ' +
          'in product mode, where test controls are closed. Report ' +
          'compliance through POST /admin-api/device-compliance with an ' +
          'access token carrying device:compliance (its client in the ' +
          'DEVICE_COMPLIANCE role), or set it on the ' +
          'device\'s page under /admin/devices.'] });
        log.debug('Leaving POST ' + TEST_CONTROL + '. Product.');
        return;
      }
      const result = self.mdmFeed(parseBody(req), '', 'test-control');
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-DEVICE-0007');
      }
      res.status(result.ok ? 200 : 400).json(result);
      log.debug('Leaving POST ' + TEST_CONTROL + '.');
    });
    log.debug("Leaving DevicesAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<DevicesAdmin>(
  'admin-ui/devices_admin',
  () => new DevicesAdmin(DevicesAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The device register's three console pages (Directory → Devices, Protocols →
 * Device registration, Monitoring → Devices) and what the management API
 * mirrors of them (rule 7).
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  DevicesAdmin: DevicesAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: DevicesAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  LIST: LIST,
  REGISTRATION: REGISTRATION,
  MONITOR: MONITOR,
  ACTIONS: ACTIONS,
  TEST_CONTROL: TEST_CONTROL,
  // For `mgmt-api/admin_api.ts` (rule 7).
  actorOf: slot.forward('actorOf'),
  listView: slot.forward('listView'),
  action: slot.forward('action'),
  mdmFeed: slot.forward('mdmFeed'),
  registrationView: slot.forward('registrationView'),
  monitorView: slot.forward('monitorView')
};
