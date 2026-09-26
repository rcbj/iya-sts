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

const LIST = '/admin/devices';
const REGISTRATION = '/admin/device-registration';
const MONITOR = '/admin/devices/monitor';

// The actions the list page takes, for the sentence an unknown one is
// answered with (the parity jobs read the list back out of it).
const ACTIONS = ['create', 'update', 'remove', 'add-key', 'remove-key',
                 'set-compliance', 'set-status'];

// DEVELOPMENT'S COMPLIANCE TEST CONTROL (#164 decision 9, phase 3): a public
// path, not under /admin, that sets a device's compliance with no credential
// at all — what a client under test drives to see its session and tokens
// react — refused in product by `mode.opensTestControls()`.
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

class DevicesAdmin {
  static readonly LIST = LIST;
  static readonly REGISTRATION = REGISTRATION;
  static readonly MONITOR = MONITOR;
  static readonly ACTIONS = ACTIONS;

  constructor(private readonly deps: DevicesAdminDeps) {
    deps.log.debug("Entering DevicesAdmin.constructor().");
    deps.log.debug("Leaving DevicesAdmin.constructor().");
  }

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
      total: devices.all().length,
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
      receivedCaep: {
        built: false,
        source: 'caep',
        arrives: 'with #153, the Shared Signals receiver'
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
             activity: deviceRecognition.activity() };
  }

  // -------------------------------------------------------------------------
  // THE HTML
  // -------------------------------------------------------------------------
  private options(list: string[], chosen: string, blank: string): string {
    const { log, admin } = this.deps;
    log.debug("Entering DevicesAdmin.options().");
    log.debug("Leaving DevicesAdmin.options().");
    return (blank !== null ? '<option value="">' + admin.esc(blank) +
            '</option>' : '') + list.map(function (one) {
      return '<option value="' + admin.esc(one) + '"' +
        (one === chosen ? ' selected' : '') + '>' + admin.esc(one) +
        '</option>';
    }).join('');
  }

  private ownerCell(r: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering DevicesAdmin.ownerCell().");
    const esc = admin.esc.bind(admin);
    const link = r.ownerKind === 'application'
      ? '/admin/applications?application=' + encodeURIComponent(r.ownerName)
      : '/admin/users?user=' + encodeURIComponent(r.ownerName);
    log.debug("Leaving DevicesAdmin.ownerCell().");
    return esc(r.ownerKind) + ' ' + (r.ownerFound
      ? '<a href="' + link + '">' + esc(r.ownerName) + '</a>'
      : '<em>not in the directory</em>') + '<br><small><code>' +
      esc(r.owner) + '</code></small>';
  }

  private listHtml(req: Req, json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering DevicesAdmin.listHtml().");
    const self = this;
    const esc = admin.esc.bind(admin);
    const f = json.filter;
    const v = json.vocabulary;
    const filters = '<form method="get" action="' + LIST + '"><div ' +
      'class="formrow"><label for="dev-q">Search</label><input type="text" ' +
      'id="dev-q" name="q" size="24" value="' + esc(f.q || '') +
      '" placeholder="id, label, owner, thumbprint">' +
      '<label for="dev-ok">Owner</label><select id="dev-ok" ' +
      'name="ownerKind">' + this.options(v.ownerKinds, f.ownerKind, 'any') +
      '</select><label for="dev-c">Compliance</label><select id="dev-c" ' +
      'name="compliance">' + this.options(v.compliance, f.compliance, 'any') +
      '</select><label for="dev-a">Attestation</label><select id="dev-a" ' +
      'name="attestation">' + this.options(v.attestation, f.attestation,
                                           'any') +
      '</select><label for="dev-k">Key</label><select id="dev-k" ' +
      'name="keyKind">' + this.options(v.keyKinds, f.keyKind, 'any') +
      '</select><label for="dev-per">Show</label><select id="dev-per" ' +
      'name="per">' + admin.perPageOptions(json.perPage) + '</select>' +
      '<button type="submit">Filter</button>' +
      (Object.keys(f).length ? ' <a href="' + LIST + '">clear</a>' : '') +
      '</div></form>';
    const nav = admin.pageNavPair(LIST, Object.assign({}, f,
      req.query && req.query.per ? { per: String(json.perPage) } : {}),
      json.paging);
    const rows = json.devices.map(function (r: Json): string {
      return '<tr><td><a href="' + LIST + '?device=' +
        encodeURIComponent(r.id) + '">' + esc(r.label) + '</a><br><small>' +
        '<code>' + esc(r.id) + '</code></small></td><td>' +
        self.ownerCell(r) + '</td><td>' + (r.keyKinds.length
          ? esc(r.keyKinds.join(', ')) : '—') + '</td><td>' +
        esc(r.attestation.level) + '</td><td>' + esc(r.compliance) +
        (r.status === 'compromised' ? ' <strong>compromised</strong>' : '') +
        '</td><td>' + (r.nativeSso ? (r.sessionLive ? 'live'
                                                    : 'session ended')
                                   : '—') + '</td><td><small>' +
        esc(r.lastUsed || '—') + '</small></td></tr>';
    }).join('');
    const canWrite = admin.mayWrite(req);
    const create = canWrite ? '<h2>Register a device</h2>' +
      admin.note('Owned by ONE person (a username) or ONE application (its ' +
                 'identifier). A key typed here is public material — a PEM ' +
                 'certificate, a public JWK, or the credential id of a ' +
                 'security key the owner enrolled — and is recorded as ' +
                 'proven by nobody and <strong>self-asserted</strong>. A ' +
                 'person at <code>devices.maxPerPerson</code> is refused ' +
                 'rather than losing a device to make room.') +
      '<form method="post" action="' + LIST + '">' +
      '<input type="hidden" name="action" value="create">' +
      '<div class="formrow"><label for="dev-n-label">Label</label>' +
      '<input type="text" id="dev-n-label" name="label" size="30" ' +
      'maxlength="128"></div>' +
      '<div class="formrow"><label for="dev-n-ok">Owner kind</label>' +
      '<select id="dev-n-ok" name="ownerKind">' +
      this.options(v.ownerKinds, 'person', null) + '</select>' +
      '<label for="dev-n-owner">Owner</label><input type="text" ' +
      'id="dev-n-owner" name="owner" size="24" required></div>' +
      '<div class="formrow"><label for="dev-n-p">Platform</label>' +
      '<select id="dev-n-p" name="platform">' +
      this.options(v.platforms, '', 'unstated') + '</select>' +
      '<label for="dev-n-m">Model</label><input type="text" id="dev-n-m" ' +
      'name="model" size="20" maxlength="128"><label for="dev-n-os">OS' +
      '</label><input type="text" id="dev-n-os" name="os" size="16" ' +
      'maxlength="128"></div>' +
      '<div class="formrow"><label for="dev-n-apps">Applications</label>' +
      '<input type="text" id="dev-n-apps" name="applications" size="40" ' +
      'placeholder="client ids or identifiers, comma separated"></div>' +
      '<div class="formrow"><label for="dev-n-kk">First key</label>' +
      '<select id="dev-n-kk" name="keyKind">' +
      this.options(['x509', 'jwk', 'webauthn'], '', 'none') + '</select>' +
      '<textarea id="dev-n-key" name="key" rows="3" cols="60" ' +
      'placeholder="PEM, JWK JSON or credential id"></textarea></div>' +
      '<div class="formrow"><button type="submit">Register</button></div>' +
      '</form>'
      : admin.note('Registering, editing or removing a device needs ' +
                   '<strong>Admin Write</strong>.');
    log.debug("Leaving DevicesAdmin.listHtml().");
    return '<div class="tiles">' + admin.tile(String(json.total), 'devices') +
      admin.tile(String(json.matched), 'matched') + '</div>' +
      admin.note('Every device this realm knows, each an entry under ' +
                 '<code>ou=devices</code> owned by one person or one ' +
                 'application. <a href="' + MONITOR + '">Monitoring &rarr; ' +
                 'Devices</a> counts them; <a href="/admin/ldap/devices">' +
                 'Device entries</a> is the same register attribute by ' +
                 'attribute; <a href="' + REGISTRATION + '">Device ' +
                 'registration</a> is how one arrives.', 'What this page is') +
      filters + nav.head + '<table class="grid"><thead><tr><th>Device</th>' +
      '<th>Owner</th><th>Keys</th><th>Attestation</th><th>Compliance</th>' +
      '<th>Native SSO</th><th>Last used</th></tr></thead><tbody>' +
      (rows || '<tr><td colspan="7">' + (Object.keys(f).length
        ? 'No device matches. The filter above may be hiding some.'
        : 'None yet.') + '</td></tr>') + '</tbody></table>' + nav.foot +
      create;
  }

  private deviceHtml(req: Req, d: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering DevicesAdmin.deviceHtml().");
    const esc = admin.esc.bind(admin);
    const canWrite = admin.mayWrite(req);
    // A HOT PATH: once per field of every form on the page, so no
    // Entering/Leaving pair — it would drown the log.
    const hidden = function (name: string, value: string): string {
      return '<input type="hidden" name="' + name + '" value="' + esc(value) +
        '">';
    };
    const change = function (c: Json): string {
      log.debug("Entering change().");
      log.debug("Leaving change().");
      return c ? esc(c.status) + ' (was ' + esc(c.previous) + ') at ' +
        esc(c.at) + (c.source ? ' by ' + esc(c.source) : '') +
        (c.actor ? ', ' + esc(c.actor) : '') +
        (c.reason ? ': ' + esc(c.reason) : '') : 'never changed';
    };
    const facts = '<table class="grid"><tbody>' +
      '<tr><th>Id</th><td><code>' + esc(d.id) + '</code><br><small><code>' +
      esc(d.dn) + '</code></small></td></tr>' +
      '<tr><th>Owner</th><td>' + this.ownerCell(d) + '</td></tr>' +
      '<tr><th>Platform, model, OS</th><td>' +
      esc([d.platform, d.model, d.os].filter(Boolean).join(' · ') || '—') +
      '</td></tr>' +
      '<tr><th>Enrolled</th><td>' + esc(d.enrolment.method) +
      (d.enrolment.at ? ' at ' + esc(d.enrolment.at) : '') +
      (d.enrolment.actor ? ' by ' + esc(d.enrolment.actor) : '') +
      '</td></tr>' +
      '<tr><th>Attestation</th><td><strong>' + esc(d.attestation.level) +
      '</strong>' + (d.attestation.level === 'attested'
        ? ' — ' + esc(d.attestation.format) + ': ' +
          esc(d.attestation.summary)
        : ' — no key\'s attestation was verified') + '</td></tr>' +
      '<tr><th>Compliance</th><td><strong>' + esc(d.compliance) +
      '</strong><br><small>' + change(d.complianceChange) +
      '</small></td></tr>' +
      '<tr><th>Status</th><td>' + esc(d.status) + '<br><small>' +
      change(d.statusChange) + '</small></td></tr>' +
      '<tr><th>Risk level</th><td>' + esc(d.riskLevel) + (d.riskChange
        ? '<br><small>' + esc(d.riskChange.level || 'unassessed') +
          ' (was ' + esc(d.riskChange.previous || 'unassessed') + ') at ' +
          esc(d.riskChange.at) + ' by ' + esc(d.riskChange.source) +
          (d.riskChange.reason ? ': ' + esc(d.riskChange.reason) : '') +
          '</small>' : '') + '</td></tr>' +
      '<tr><th>Native SSO</th><td>' + (d.nativeSso ? (d.sessionLive
        ? 'a secret, bound to a <strong>live</strong> sign-on session'
        : 'a secret whose sign-on session has ended') : 'no secret') +
      '</td></tr>' +
      '<tr><th>Last used</th><td>' + esc(d.lastUsed || '—') + '</td></tr>' +
      '</tbody></table>';
    const apps = '<h2>Applications that used it</h2>' +
      (d.applications.length ? '<ul>' + d.applications.map(
        function (dn: string, i: number): string {
          const name = d.applicationNames[i];
          return '<li>' + (name ? '<a href="/admin/applications?' +
            'application=' + encodeURIComponent(name) + '">' + esc(name) +
            '</a> ' : '') + '<small><code>' + esc(dn) + '</code></small></li>';
        }).join('') + '</ul>' : admin.note('None.'));
    const keyRows = d.keys.map(function (k: Json): string {
      return '<tr><td>' + esc(k.label) + '<br><small><code>' + esc(k.id) +
        '</code></small></td><td>' + esc(k.kind) + '</td><td><small><code>' +
        esc(k.thumbprint) + '</code></small></td><td>' + esc(k.proof) +
        '</td><td>' + esc(k.attestation.level) +
        (k.attestation.format !== 'none' ? '<br><small>' +
          esc(k.attestation.format) + '</small>' : '') +
        (k.attestation.summary ? '<br><small>' +
          esc(k.attestation.summary) + '</small>' : '') +
        (k.attestation.verifiedAt ? '<br><small>verified ' +
          esc(k.attestation.verifiedAt) + '</small>' : '') +
        '</td><td><small>' +
        esc(k.added) + (k.addedBy ? ' by ' + esc(k.addedBy) : '') +
        '</small></td><td>' + (canWrite
          ? '<form method="post" action="' + LIST + '" class="inline">' +
            hidden('action', 'remove-key') + hidden('id', d.id) +
            hidden('key', k.id) + '<button type="submit" class="danger">' +
            'Remove</button></form>' : '') + '</td></tr>';
    }).join('');
    const keys = '<h2>Keys</h2>' + admin.note('Each is a way the device is ' +
      'recognised. The thumbprint is SHA-256 over the certificate\'s ' +
      'SubjectPublicKeyInfo, or RFC 7638 over the JWK — which is DPoP\'s ' +
      '<code>jkt</code>.') +
      (keyRows ? '<table class="grid"><thead><tr><th>Key</th><th>Kind</th>' +
        '<th>Thumbprint</th><th>Proof</th><th>Attestation</th><th>Added' +
        '</th><th></th></tr></thead><tbody>' + keyRows + '</tbody></table>'
        : admin.note('None.'));
    const v = { platforms: this.deps.devices.PLATFORMS };
    const compliance = '<h2>Compliance</h2>' + admin.note('An ' +
        'administrator\'s vouch, recorded with source <code>admin</code>. ' +
        'A change a receiver can be told — CAEP knows compliant and ' +
        'not-compliant, and unknown is sent as not-compliant — goes out as ' +
        'CAEP device-compliance-change.') +
      '<form method="post" action="' + LIST + '">' +
      hidden('action', 'set-compliance') + hidden('id', d.id) +
      '<div class="formrow"><label for="dev-c-status">Compliance</label>' +
      '<select id="dev-c-status" name="status">' +
      this.options(this.deps.devices.COMPLIANCE_STATES, d.compliance, null) +
      '</select><label for="dev-c-reason">Reason</label><input type="text" ' +
      'id="dev-c-reason" name="reason" size="40" maxlength="500"></div>' +
      '<div class="formrow"><button type="submit">Set compliance</button>' +
      '</div></form>';
    const status = '<h2>Compromise</h2>' + (d.status === 'compromised'
      ? admin.note('This device is marked <strong>compromised</strong>. ' +
          'Restoring it puts back the risk level the compromise raised; ' +
          'nothing revoked comes back — a certificate is re-issued and a ' +
          'Native SSO secret re-minted at the next sign-in.') +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'set-status') + hidden('id', d.id) +
        hidden('status', 'active') + '<div class="formrow"><label ' +
        'for="dev-s-reason">Reason</label><input type="text" ' +
        'id="dev-s-reason" name="reason" size="40" maxlength="500">' +
        '<button type="submit">Restore to active</button></div></form>'
      : admin.note('Marking it compromised ends every sign-on session one ' +
          'of its keys authenticated, revokes its Native SSO secret and ' +
          'every certificate this service\'s EST or SCEP Issuing CA issued ' +
          'it (keyCompromise), raises its risk level to HIGH, and — for a ' +
          'person\'s device — sends RISC credential-compromise and ' +
          'sessions-revoked. It stays in the register, recognised and ' +
          'saying so.') +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'set-status') + hidden('id', d.id) +
        hidden('status', 'compromised') + '<div class="formrow"><label ' +
        'for="dev-s-reason">Reason</label><input type="text" ' +
        'id="dev-s-reason" name="reason" size="40" maxlength="500">' +
        '<button type="submit" class="danger">Mark compromised</button>' +
        '</div></form>');
    const forms = canWrite
      ? compliance + status +
        '<h2>Add a key</h2>' + admin.note('Public material only; recorded ' +
          'as proven by nobody and self-asserted.') +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'add-key') + hidden('id', d.id) +
        '<div class="formrow"><label for="dev-k-kind">Kind</label>' +
        '<select id="dev-k-kind" name="kind">' +
        this.options(['x509', 'jwk', 'webauthn'], 'jwk', null) +
        '</select><label for="dev-k-label">Label</label><input ' +
        'type="text" id="dev-k-label" name="label" size="24" ' +
        'maxlength="128"></div><div class="formrow"><textarea ' +
        'id="dev-k-value" name="value" rows="4" cols="70" required ' +
        'placeholder="PEM, JWK JSON or credential id"></textarea></div>' +
        '<div class="formrow"><button type="submit">Add the key</button>' +
        '</div></form>' +
        '<h2>Edit</h2>' + admin.note('A new owner takes the device without ' +
          'its Native SSO secret, which was bound to the old owner\'s ' +
          'session; its keys go with it. The applications field replaces ' +
          'the list.') +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'update') + hidden('id', d.id) +
        '<div class="formrow"><label for="dev-e-label">Label</label>' +
        '<input type="text" id="dev-e-label" name="label" size="30" ' +
        'maxlength="128" value="' + esc(d.label) + '"></div>' +
        '<div class="formrow"><label for="dev-e-ok">Owner kind</label>' +
        '<select id="dev-e-ok" name="ownerKind">' +
        this.options(this.deps.devices.OWNER_KINDS, d.ownerKind, null) +
        '</select><label for="dev-e-owner">Owner</label><input type="text" ' +
        'id="dev-e-owner" name="owner" size="24" value="' +
        esc(d.ownerName) + '"></div>' +
        '<div class="formrow"><label for="dev-e-p">Platform</label>' +
        '<select id="dev-e-p" name="platform">' +
        this.options(v.platforms, d.platform, 'unstated') + '</select>' +
        '<label for="dev-e-m">Model</label><input type="text" ' +
        'id="dev-e-m" name="model" size="20" maxlength="128" value="' +
        esc(d.model) + '"><label for="dev-e-os">OS</label><input ' +
        'type="text" id="dev-e-os" name="os" size="16" maxlength="128" ' +
        'value="' + esc(d.os) + '"></div>' +
        '<div class="formrow"><label for="dev-e-apps">Applications</label>' +
        '<input type="text" id="dev-e-apps" name="applications" size="40" ' +
        'value="' + esc(d.applicationNames.filter(Boolean).join(', ')) +
        '"></div><div class="formrow"><button type="submit">Save</button>' +
        '</div></form>' +
        '<h2>Remove</h2>' + admin.note('Removing it revokes the ' +
          'certificates this service issued it (cessationOfOperation, or ' +
          'keyCompromise when it is compromised) and ends the sign-on ' +
          'sessions it authenticated.') +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'remove') + hidden('id', d.id) +
        '<button type="submit" class="danger">Remove this device</button>' +
        '</form>'
      : admin.note('Editing needs <strong>Admin Write</strong>.');
    log.debug("Leaving DevicesAdmin.deviceHtml().");
    return facts + apps + keys + forms;
  }

  private registrationHtml(json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering DevicesAdmin.registrationHtml().");
    const esc = admin.esc.bind(admin);
    const state = function (built: boolean): string {
      log.debug("Entering state().");
      log.debug("Leaving state().");
      return built ? '<span class="state-valid">built</span>'
                   : '<span class="state-none">not built yet</span>';
    };
    log.debug("Leaving DevicesAdmin.registrationHtml().");
    return admin.note('A device is an entry under <code>ou=devices</code>, ' +
        'owned by ONE person or ONE application, holding the keys it is ' +
        'recognised by. <a href="' + LIST + '">Devices</a> is the register; ' +
        'this page is how a device gets into it and how it is known again.',
        'What this page is') +
      '<h2>How a device is registered</h2><table class="grid"><thead><tr>' +
      '<th>Method</th><th>State</th><th>What happens</th></tr></thead>' +
      '<tbody>' + json.enrolment.map(function (r: Json): string {
        return '<tr><td><code>' + esc(r.method) + '</code></td><td>' +
          state(r.built) + '</td><td>' + esc(r.what) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      '<h2>How a device is recognised</h2><table class="grid"><thead><tr>' +
      '<th>Key</th><th>State</th><th>How it is matched</th></tr></thead>' +
      '<tbody>' + json.recognition.map(function (r: Json): string {
        return '<tr><td><code>' + esc(r.kind) + '</code></td><td>' +
          state(r.built) + '</td><td>' + esc(r.what) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      '<h2>Attestation</h2>' +
      admin.note('A device is <strong>attested</strong> when a verifier ' +
        'checked an attestation statement for one of its keys and it ' +
        'chained to a trust anchor below, and <strong>self-asserted' +
        '</strong> otherwise. The formats it records: ' +
        esc(json.attestationFormats.join(', ')) + '. A statement that ' +
        'does not verify is refused in both modes; one that verifies and ' +
        'chains to nothing here is self-asserted. ' +
        (json.unattestedKeys.accepted
          ? 'This realm (development) registers a self-asserted key a ' +
            'device or its owner presents.'
          : 'This realm (product) REFUSES a self-asserted key a device or ' +
            'its owner presents (STS-DEVICE-0024).') + ' ' +
        esc(json.unattestedKeys.adminKeys) + '.') +
      '<table class="grid"><thead><tr><th>Statement</th><th>Anchors</th>' +
      '<th>Setting</th><th>Shipped</th></tr></thead><tbody>' +
      json.trustAnchors.map(function (r: Json): string {
        return '<tr><td><code>' + esc(r.kind) + '</code></td><td>' +
          esc(r.count === null ? r.source : r.count + ' (' + r.source +
                                           ')') +
          '</td><td><code>' + esc(r.setting) + '</code></td><td>' +
          (r.shipped.length ? r.shipped.map(function (a: Json): string {
            return esc(a.subject) + ' — until ' + esc(a.notAfter) +
              '<br><small>SHA-256 <code>' + esc(a.sha256) + '</code>' +
              (a.used ? '' : ' <strong>not used: pin mismatch</strong>') +
              '</small>';
          }).join('<br>') : '—') + '</td></tr>';
      }).join('') + '</tbody></table>' +
      '<h2>Enrolment challenges</h2>' +
      admin.note('The challenges <code>/portal/devices</code> issues are ' +
        'held in <code>' + esc(json.challenges.store) + '</code>, per ' +
        'realm and persisted, one per session and purpose, answered once ' +
        'across the cluster and for ' +
        esc(String(json.challenges.ttlSeconds)) + ' seconds; ' +
        esc(String(json.challenges.live)) + ' are live, of at most ' +
        esc(String(json.challenges.max)) + '.') +
      '<h2>Where a recognised device is recorded</h2>' +
      admin.note('At a sign-in: ' + esc(json.recordedAt.signIn) + '. At ' +
        'the token endpoint: ' + esc(json.recordedAt.tokenEndpoint) + '. ' +
        'A compromised device is still recognised, and says so.') +
      '<h2>Compliance</h2>' +
      admin.note('A device is <code>compliant</code>, ' +
        '<code>not-compliant</code> or <code>unknown</code> (where it ' +
        'starts); every change records its previous value and who set it ' +
        '— ' + esc(json.complianceSources.join(', ')) + '.') +
      '<table class="grid"><thead><tr><th>Door</th><th>State</th>' +
      '<th>How</th></tr></thead><tbody>' +
      '<tr><td>An administrator</td><td>' + state(true) + '</td><td>' +
      'Set compliance on a device\'s page under <a href="' + LIST + '">' +
      'Devices</a>, or <code>POST /admin-api/devices/set-compliance</code> ' +
      '(Admin Write). Source <code>admin</code>.</td></tr>' +
      '<tr><td>An MDM or posture feed</td><td>' + state(true) + '</td><td>' +
      '<code>' + esc(json.mdmFeed.path) + '</code> with an access token ' +
      'carrying <code>' + esc(json.mdmFeed.scope) + '</code> — a PROTECTED ' +
      'scope, issued only to a client that declares it, and the only ' +
      'scope that operation takes: the feed needs no admin scope and gets ' +
      'none. Up to ' + esc(String(json.mdmFeed.maxReports)) + ' reports, ' +
      'each naming its device by ' + esc(json.mdmFeed.identifiedBy.join(', ')) +
      '. Source <code>mdm</code>, the client as actor.</td></tr>' +
      '<tr><td>The test control</td><td>' + (json.testControl.open
        ? '<span class="state-valid">open (development)</span>'
        : '<span class="state-none">refused (product)</span>') +
      '</td><td><code>' + esc(json.testControl.path) + '</code>, no ' +
      'credential, development only (<code>mode.opensTestControls()</code>). ' +
      'Source <code>test-control</code>.</td></tr>' +
      '<tr><td>A received CAEP device-compliance-change</td><td>' +
      state(false) + '</td><td>Arrives with #153, the Shared Signals ' +
      'receiver. Source <code>caep</code>.</td></tr></tbody></table>' +
      '<h2>What goes out over Shared Signals</h2>' +
      admin.note('CAEP: ' + esc(json.signals.caep.join('; ')) + '. RISC, ' +
        'for a person\'s device compromised or removed: ' +
        esc(json.signals.risc.join(' and ')) + '. The subject is ' +
        esc(json.signals.subject) + '. A compliance change goes out only ' +
        'when what a receiver can be told moved: CAEP knows compliant and ' +
        'not-compliant, and unknown is sent as not-compliant.') +
      '<h2>Settings</h2>' + admin.configFormsFor(REGISTRATION);
  }

  private monitorHtml(json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering DevicesAdmin.monitorHtml().");
    const esc = admin.esc.bind(admin);
    const c = json.counts;
    const table = function (title: string, counts: Json): string {
      log.debug("Entering table().");
      log.debug("Leaving table().");
      return '<h2>' + esc(title) + '</h2><table class="grid"><tbody>' +
        Object.keys(counts).map(function (k) {
          return '<tr><th>' + esc(k) + '</th><td>' + esc(String(counts[k])) +
            '</td></tr>';
        }).join('') + '</tbody></table>';
    };
    const t = json.timeline;
    const sources: string[] = this.deps.devices.COMPLIANCE_SOURCES;
    log.debug("Leaving DevicesAdmin.monitorHtml().");
    return '<div class="tiles">' + admin.tile(String(c.total), 'devices') +
      admin.tile(String(c.keys), 'keys') +
      admin.tile(String(c.nativeSso.live), 'live Native SSO') +
      admin.tile(String(t.totals.created), 'registered') +
      admin.tile(String(t.totals.removed), 'removed') +
      admin.tile(String(t.totals.evicted), 'evicted') + '</div>' +
      admin.note('What this realm\'s register holds, counted now, and what ' +
        'happened to it: every registration, removal, and eviction at a ' +
        'person\'s <code>devices.maxPerPerson</code>, kept up to ' +
        '<code>devices.eventsKept</code>, and every compliance change by ' +
        'who made it — admin, mdm, test-control, caep' + (t.since
          ? ' (the oldest is ' +
        'from ' + esc(t.since) + ')' : '') + '. A device removed by an ' +
        '<code>ldapdelete</code> on the socket is not an event here — the ' +
        'register never sees it.', 'What this page is') +
      table('By owner', c.byOwnerKind) +
      table('By compliance', c.byCompliance) +
      table('By risk level', c.byRiskLevel || {}) +
      table('Compliance changes kept, by source', t.totals.compliance || {}) +
      table('By attestation', c.byAttestation) +
      table('By key', c.byKeyKind) +
      table('By enrolment', c.byEnrolment) +
      table('Native SSO', c.nativeSso) +
      table('Keys by attestation format', c.byKeyAttestationFormat || {}) +
      admin.note('Counted in this process since it started (' +
        esc(json.activity.scope) + '): a page served by one node of a ' +
        'cluster shows that node\'s.', 'The counters below') +
      table('Recognitions, by key', json.activity.recognitions) +
      table('Enrolments by a device or its owner, by method',
            json.activity.enrolments) +
      table('Enrolled keys, by attestation', json.activity.attestationLevels) +
      table('Enrolled keys, by attestation format',
            json.activity.attestationFormats) +
      table('Attestations refused', json.activity.attestationRefusals) +
      '<h2>The last ' + esc(String(t.days)) + ' days</h2>' +
      '<table class="grid"><thead><tr><th>Day (UTC)</th><th>Registered' +
      '</th><th>Removed</th><th>Evicted</th>' +
      sources.map(function (src: string): string {
        return '<th>Compliance: ' + esc(src) + '</th>';
      }).join('') + '</tr></thead><tbody>' +
      t.rows.slice(0).reverse().map(function (r: Json): string {
        return '<tr><td>' + esc(r.day) + '</td><td>' + r.created +
          '</td><td>' + r.removed + '</td><td>' + r.evicted + '</td>' +
          sources.map(function (src: string): string {
            return '<td>' + esc(String((r.compliance || {})[src] || 0)) +
              '</td>';
          }).join('') + '</tr>';
      }).join('') + '</tbody></table>';
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

  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, admin, errorCodes, parseBody } = this.deps;
    const self = this;
    log.debug("Entering DevicesAdmin.registerRoutes().");
    app.get(LIST, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + LIST + '.');
      const json = self.listView(req, req.query);
      if (req.query && req.query.device !== undefined) {
        if (!json.found) {
          errorCodes.mark(res, 'STS-DEVICE-0007');
        }
        admin.respond(req, res, json, 'Device ' + (json.device
          ? json.device.label : String(req.query.device)), LIST,
          admin.messagesOf(req) + (json.device
            ? self.deviceHtml(req, json.device)
            : admin.warn('There is no such device in this realm.')),
          admin.upTo(LIST, json.device ? json.device.label : 'Device', {}));
        log.debug('Leaving GET ' + LIST + '. One device.');
        return;
      }
      admin.respond(req, res, json, 'Devices', LIST,
                    admin.messagesOf(req) + self.listHtml(req, json));
      log.debug('Leaving GET ' + LIST + '.');
    });
    app.post(LIST, function (req: Req, res: Res): void {
      log.debug('Entering POST ' + LIST + '.');
      const body = parseBody(req);
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-DEVICE-0014');
        admin.respondToAction(req, res, LIST, { ok: false, errors: [
          'This console session may read but not write.'] });
        log.debug('Leaving POST ' + LIST + '. Read-only.');
        return;
      }
      const result = self.action(body, self.actorOf(req), 'the admin console');
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-DEVICE-0013');
      }
      admin.respondToAction(req, res, self.backTo(body, result), result);
      log.debug('Leaving POST ' + LIST + '.');
    });
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
          'access token carrying device:compliance, or set it on the ' +
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
    app.get(REGISTRATION, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + REGISTRATION + '.');
      const json = self.registrationView(req);
      admin.respond(req, res, json, 'Device registration', REGISTRATION,
                    admin.messagesOf(req) + self.registrationHtml(json));
      log.debug('Leaving GET ' + REGISTRATION + '.');
    });
    app.get(MONITOR, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + MONITOR + '.');
      const json = self.monitorView(req, req.query);
      admin.respond(req, res, json, 'Devices (monitoring)', MONITOR,
                    admin.messagesOf(req) + self.monitorHtml(json));
      log.debug('Leaving GET ' + MONITOR + '.');
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

export = {
  registerRoutes: slot.forward('registerRoutes'),
  DevicesAdmin: DevicesAdmin,
  installInstance: (instance: DevicesAdmin): void => slot.install(instance),
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
