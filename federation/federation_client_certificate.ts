// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: federation_client_certificate.ts
//
// ===========================================================================
// A FAPI 1.0 ADVANCED RELATIONSHIP'S TLS CLIENT CERTIFICATE (#931, rcbj's
// decision of 2026-11-13).
//
// FAPI 1.0 Advanced (Part 2, section 5.2.2, items 5 and 6) has the
// authorization server issue SENDER-CONSTRAINED access tokens, and its
// normative mechanism is mutual TLS (RFC 8705 section 3): the partner binds
// the token to the client certificate the token request was made over
// (`cnf.x5t#S256`) and refuses it at a resource presented over any other.
// Until this file `1-advanced` dialled every partner endpoint with no
// certificate at all, so its tokens were bearer tokens. The root
// `CLAUDE.md`'s row "authenticate to a partner with a client certificate"
// is REVERSED FOR THIS PROFILE ONLY; a plain relationship and the 2.x
// profiles (which bind with DPoP) present nothing, exactly as before.
//
// WHAT IT IS. One certificate per relationship, a leaf of the realm's TLS
// Client Issuing CA with `clientAuth` (`pki.issueFederationClientKeyPair()`),
// held on the relationship as one JSON row (`fedClientCertificate`): the
// certificate and its chain, its `x5t#S256`, its validity, and the private
// key — SEALED under the key-encryption key wherever keys persist and
// refused rather than written in clear there, `federation_encryption.ts`'s
// rule. Its subject is fixed per relationship (`CN=federation <id> client`
// and the realm's O and C), so a partner that registered
// `tls_client_auth_subject_dn` keeps matching across a renewal; a partner
// that pinned the certificate itself must be given the new one, which the
// relationship's page and `GET /admin-api/federation` publish.
//
// WHEN IT IS MADE. When `fedFapi` becomes `1-advanced` (the console's and
// the API's `set`); at the first token request that finds none (so a
// relationship that was `1-advanced` before this file signs in rather than
// failing); and by the scheduler job `federation.client-certificate-renew`,
// which also renews one `federation.clientCertificateRenewDays` before its
// `notAfter`. Nothing here arms a timer (root `CLAUDE.md`, *Anything
// periodic is a scheduler job*).
//
// WHAT IT DOES. `materialFor()` answers the PEMs `federation_http.ts` hands
// node's TLS client as `cert` and `key` — the leaf with its chain, so a
// partner that trusts the service Root can build the path. The token
// request, the refresh and UserInfo present it; the partner decides
// whether it authenticated anything (`fedTokenAuth` tls_client_auth) and
// what it binds. A certificate that cannot be issued or opened refuses the
// sign-in (`STS-FED-0252`) rather than dialling without it: a FAPI 1.0
// Advanced partner would issue an unbound token or refuse, and the first
// would be the silent failure this file exists to close.
//
// All cryptography is `common/crypto.js`'s and `common/pki.js`'s (rule
// 3r); this file seals, parses JSON and decides when. A static utility
// class. It registers nothing but its scheduler job.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import federation = require('./federation');
import stsCrypto = require('../common/crypto');
import keystore = require('../common/keystore');
import errorCodes = require('../common/error_codes');
import scheduler = require('../cluster/scheduler');

type Json = any;

const log = helpers.log;

// What `/admin/encryption` counts the sealed private keys under.
const SEAL_LABEL = 'federation-client-certificate';
// The row's format, so a row written by a later shape is refused by name
// rather than read wrongly.
const ROW_VERSION = 1;
const RENEW_JOB = 'federation.client-certificate-renew';
const DAY_MS = 86400000;
// The issues in flight in this process, by realm and relationship id
// (`issueOnce()`).
// A promise per relationship for as long as one issue takes: bounded by
// the relationships, and empty again when each settles.
const IN_FLIGHT: Map<string, Promise<Json>> = new Map();

/**
 * A FAPI 1.0 Advanced federation relationship's TLS client certificate:
 * issued from the realm's TLS Client Issuing CA, sealed, renewed by a
 * scheduler job, presented to the partner's token and UserInfo endpoints,
 * and published for the partner to register. A static utility class.
 */
class FederationClientCertificate {
  /**
   * The keystore label the sealed private keys are counted under.
   */
  static readonly SEAL_LABEL = SEAL_LABEL;
  /**
   * The id of the scheduler job that issues and renews the certificates.
   */
  static readonly RENEW_JOB = RENEW_JOB;
  /**
   * The row format version; a row of any other is not used.
   */
  static readonly ROW_VERSION = ROW_VERSION;

  /**
   * Whether a relationship presents a client certificate: an OpenID
   * Connect one held to FAPI 1.0 Advanced, and nothing else.
   *
   * @param record - the relationship
   * @returns whether it does
   */
  static needed(record: Json): boolean {
    log.debug("Entering FederationClientCertificate.needed().");
    const out = !!record && record.fedRole === 'service-provider' &&
      record.fedProtocol === 'oidc' &&
      !String(record.fedTrustAnchor || '').trim() &&
      String(record.fedFapi || '').trim() === '1-advanced';
    log.debug("Leaving FederationClientCertificate.needed(). " + out);
    return out;
  }

  /**
   * The relationship's usable row: this format, a certificate, and not
   * past its `notAfter`. Null otherwise.
   *
   * @param record - the relationship
   * @param nowMs - the time to judge against; now by default
   * @returns the row, or null
   */
  static currentOf(record: Json, nowMs?: number): Json {
    log.debug("Entering FederationClientCertificate.currentOf().");
    const row = federation.clientCertificateOf(record);
    const now = Number(nowMs) || Date.now();
    const usable = !!row && Number(row.v) === ROW_VERSION &&
      new Date(String(row.notAfter || '')).getTime() > now;
    log.debug("Leaving FederationClientCertificate.currentOf(). " + usable);
    return usable ? row : null;
  }

  /**
   * Whether a row is due a renewal: none, unusable, or within
   * `federation.clientCertificateRenewDays` of its `notAfter`.
   *
   * @param record - the relationship
   * @param nowMs - the time to judge against; now by default
   * @returns whether it is due
   */
  static due(record: Json, nowMs?: number): boolean {
    log.debug("Entering FederationClientCertificate.due().");
    const now = Number(nowMs) || Date.now();
    const row = FederationClientCertificate.currentOf(record, now);
    const lead = Number(config.value('federation.clientCertificateRenewDays'))
                 * DAY_MS;
    const out = !row ||
      new Date(String(row.notAfter)).getTime() - now <= lead;
    log.debug("Leaving FederationClientCertificate.due(). " + out);
    return out;
  }

  /**
   * Issues a new certificate for a relationship and writes it, sealed.
   * The one it replaces is overwritten: a token already bound to the old
   * certificate stops working at the partner, which is a renewal's ordinary
   * cost and why the job renews well before the end.
   *
   * @param id - the relationship id
   * @param why - the audit sentence
   * @returns a promise of `{ ok, row, message }` or `{ ok: false, errors }`
   *   marked `STS-FED-0252`
   */
  static async issue(id: string, why?: string): Promise<Json> {
    log.debug("Entering FederationClientCertificate.issue(). id=" + id);
    const record = federation.get(id);
    if (!record || !FederationClientCertificate.needed(record)) {
      log.debug("Leaving FederationClientCertificate.issue(). Not needed.");
      return errorCodes.mark({ ok: false, errors: [record
        ? '"' + id + '" is not an OpenID Connect relationship held to ' +
          'fedFapi 1-advanced, the one kind that presents a client ' +
          'certificate.'
        : 'There is no federation relationship called "' + id + '".'] },
                             'STS-FED-0252');
    }
    // Lazily: `pki.js` is a leaf every realm module reaches, and loading
    // it from here at require time would pull it in ahead of the realm
    // watcher for a process that never issues one.
    const pki = require('../common/pki');
    const made = await pki.issueFederationClientKeyPair(undefined,
                                                       { identifier: id });
    if (!made.ok) {
      log.error(errorCodes.tag('STS-FED-0252') + 'federation: no client ' +
                'certificate could be issued for ' + id + ': ' +
                (made.errors || []).join(' '));
      log.debug("Leaving FederationClientCertificate.issue(). Not issued.");
      return errorCodes.mark({ ok: false, errors: ['No client certificate ' +
               'could be issued for "' + id + '": ' +
               (made.errors || []).join(' ')] }, 'STS-FED-0252');
    }
    const issued = made.issued;
    let privateKey = String(issued.privateKeyPem);
    let sealed = false;
    if (keystore.persists()) {
      const closed = keystore.seal(privateKey, SEAL_LABEL);
      if (!closed) {
        log.error(errorCodes.tag('STS-FED-0252') + 'federation: the client ' +
                  'certificate key for ' + id + ' could not be sealed, so it ' +
                  'was not written.');
        log.debug("Leaving FederationClientCertificate.issue(). Not sealed.");
        return errorCodes.mark({ ok: false, errors: ['The client ' +
                 'certificate key for "' + id + '" could not be sealed ' +
                 'under the key-encryption key, and a private key is never ' +
                 'written in clear where keys persist.'] }, 'STS-FED-0252');
      }
      privateKey = closed;
      sealed = true;
    }
    const row: Json = {
      v: ROW_VERSION,
      certificate: stsCrypto.stripPem(issued.certificatePem),
      chain: (issued.chainPem || []).map(stsCrypto.stripPem),
      x5tS256: stsCrypto.certificateThumbprint(issued.certificatePem),
      serialHex: issued.serialHex,
      // RFC 4514's form, leaf first — what RFC 8705 section 2.1.2's
      // tls_client_auth_subject_dn holds and a partner compares against.
      subject: helpers.dnRfc4514(
        stsCrypto.parseCertificate(issued.certificatePem).subject) ||
        String(issued.subject || ''),
      keyAlg: issued.keyAlg,
      notBefore: issued.notBefore,
      notAfter: issued.notAfter,
      createdAt: Date.now(),
      sealed: sealed,
      privateKey: privateKey
    };
    if (!federation.writeClientCertificate(id, row, why ||
                                           'a client certificate was issued')) {
      log.debug("Leaving FederationClientCertificate.issue(). Not written.");
      return errorCodes.mark({ ok: false, errors: ['The directory refused ' +
               'the client certificate for "' + id + '".'] }, 'STS-FED-0252');
    }
    log.info('federation: ' + id + ' has a new TLS client certificate, ' +
             'serial ' + row.serialHex + ', x5t#S256 ' + row.x5tS256 +
             ', until ' + row.notAfter + '.');
    log.debug("Leaving FederationClientCertificate.issue().");
    return { ok: true, row: row,
             message: 'A TLS client certificate, serial ' + row.serialHex +
                      ', valid until ' + row.notAfter + ', is current. Give ' +
                      'the partner the certificate (or its subject DN, for ' +
                      'tls_client_auth) published on the relationship\'s ' +
                      'page.' };
  }

  /**
   * `issue()`, but one at a time per relationship in this process: two
   * sign-ins that both find no certificate share one issue rather than each
   * minting one, the second overwriting the certificate the first one's
   * token was just bound to. (Two PROCESSES can still race; the loser's
   * sign-in is refused at UserInfo by the partner, and the next one works.)
   *
   * @param id - the relationship id
   * @param why - the audit sentence
   * @returns a promise of `issue()`'s answer
   */
  static issueOnce(id: string, why: string): Promise<Json> {
    log.debug("Entering FederationClientCertificate.issueOnce(). id=" + id);
    // Keyed by realm too: a relationship id is unique within one realm.
    const slot = String(realms.currentId() || '') + '\u0000' + id;
    const held = IN_FLIGHT.get(slot);
    if (held) {
      log.debug("Leaving FederationClientCertificate.issueOnce(). Shared.");
      return held;
    }
    const made = FederationClientCertificate.issue(id, why);
    IN_FLIGHT.set(slot, made);
    const forget = function (): void {
      log.debug("Entering forget().");
      IN_FLIGHT.delete(slot);
      log.debug("Leaving forget().");
    };
    made.then(forget, function (e) {
      log.debug("Caught in FederationClientCertificate.issueOnce(): " +
                ((e && e.message) || e));
      forget();
    });
    log.debug("Leaving FederationClientCertificate.issueOnce().");
    return made;
  }

  /**
   * The PEMs node's TLS client presents for a relationship: the leaf with
   * its chain, and the private key, opened. Issues one first where the
   * relationship holds none that is usable (a relationship that became
   * 1-advanced before this existed, or one whose job has not run).
   *
   * @param record - the relationship
   * @returns a promise of `{ ok: true, cert, key, x5tS256 }` or
   *   `{ ok: false, errorCode: 'STS-FED-0252', why }`; never rejects
   */
  static async materialFor(record: Json): Promise<Json> {
    log.debug("Entering FederationClientCertificate.materialFor().");
    // THE STORED RECORD, not the one handed in: a sign-in carries the
    // record it started with (shaped, with discovered endpoints), and a
    // certificate issued by its own token request must be the one its
    // UserInfo request presents — the partner bound the token to it.
    const id = String((record && record.fedId) || '');
    let row = FederationClientCertificate.currentOf(federation.get(id) ||
                                                    record);
    if (!row) {
      let made: Json = null;
      try {
        made = await FederationClientCertificate.issueOnce(id,
          'a client certificate was issued at the first sign-in that ' +
          'needed one');
      } catch (e) {
        log.debug("Caught in FederationClientCertificate.materialFor(): " +
                  ((e && e.message) || e));
        made = { ok: false, errors: [String((e && e.message) || e)] };
      }
      if (!made || !made.ok) {
        log.debug("Leaving FederationClientCertificate.materialFor(). " +
                  "Not issued.");
        return { ok: false, errorCode: 'STS-FED-0252',
                 why: 'the relationship holds no usable TLS client ' +
                      'certificate and none could be issued: ' +
                      ((made && made.errors) || []).join(' ') };
      }
      row = made.row;
    }
    const stored = String(row.privateKey || '');
    const key = row.sealed ? keystore.open(stored, SEAL_LABEL) : stored;
    if (!key) {
      log.warn(errorCodes.tag('STS-FED-0252') + 'federation: ' +
               record.fedId + '\'s client certificate key is sealed under ' +
               'a key-encryption key this process does not hold, so it is ' +
               'not presented and the sign-in is refused.');
      log.debug("Leaving FederationClientCertificate.materialFor(). " +
                "Not opened.");
      return { ok: false, errorCode: 'STS-FED-0252',
               why: 'the client certificate\'s private key will not open' };
    }
    const pem = function (b64: string): string {
      return '-----BEGIN CERTIFICATE-----\n' +
        (String(b64).match(/.{1,64}/g) || []).join('\n') +
        '\n-----END CERTIFICATE-----\n';
    };
    log.debug("Leaving FederationClientCertificate.materialFor().");
    return { ok: true, key: String(key), x5tS256: String(row.x5tS256 || ''),
             cert: [row.certificate].concat(row.chain || []).map(pem)
                     .join('') };
  }

  /**
   * Issues or renews, in the current realm, every certificate a 1-advanced
   * relationship lacks or is due to renew; the scheduler job's body.
   *
   * @param nowMs - the time to judge against; now by default
   * @returns a promise of `{ issued, failed }`
   */
  static async renewDue(nowMs?: number): Promise<Json> {
    log.debug("Entering FederationClientCertificate.renewDue().");
    const now = Number(nowMs) || Date.now();
    let issued = 0;
    let failed = 0;
    const due = federation.inRole('service-provider').filter(function (one) {
      return FederationClientCertificate.needed(one) &&
             FederationClientCertificate.due(one, now);
    });
    for (let i = 0; i < due.length; i++) {
      const held = FederationClientCertificate.currentOf(due[i], now);
      const made = await FederationClientCertificate.issue(due[i].fedId,
        held ? 'the client certificate was renewed before it expires'
             : 'a client certificate was issued by the scheduler');
      if (made.ok) {
        issued += 1;
      } else {
        // Logged under STS-FED-0252 by issue(); the next run tries again.
        failed += 1;
      }
    }
    log.debug("Leaving FederationClientCertificate.renewDue(). " + issued +
              " issued, " + failed + " failed.");
    return { issued: issued, failed: failed };
  }

  /**
   * Registers the renewal scheduler job, once; it runs per realm every hour
   * while `federation.enabled` is on.
   */
  static registerRenewJob(): void {
    log.debug("Entering FederationClientCertificate.registerRenewJob().");
    if (scheduler.job(RENEW_JOB)) {
      log.debug("Leaving FederationClientCertificate.registerRenewJob(). " +
                "Registered.");
      return;
    }
    scheduler.register({
      id: RENEW_JOB,
      title: 'Federation client certificate renewal',
      describe: 'Issues a TLS client certificate to each FAPI 1.0 Advanced ' +
                'federation relationship that holds none, and a new one ' +
                'with the same subject to each whose certificate ends ' +
                'within federation.clientCertificateRenewDays.',
      owner: 'federation/federation_client_certificate.ts',
      scope: 'realm',
      everyMs: function (): number {
        return 3600000;
      },
      off: function (): string {
        return config.value('federation.enabled') ? ''
          : 'federation.enabled is off';
      },
      run: function (ctx: Json): Promise<Json> {
        return FederationClientCertificate.renewDue(ctx.nowMs());
      }
    });
    log.debug("Leaving FederationClientCertificate.registerRenewJob().");
  }

  /**
   * What the relationship page and `GET /admin-api/federation` show of the
   * client certificate: the certificate and its chain as PEM, the subject
   * DN a partner registers as `tls_client_auth_subject_dn`, the
   * `x5t#S256` a bound token carries, the validity and when it renews.
   * Never the private key.
   *
   * @param record - the relationship
   * @returns the view, or null for a relationship that presents none
   */
  static viewOf(record: Json): Json {
    log.debug("Entering FederationClientCertificate.viewOf().");
    if (!FederationClientCertificate.needed(record)) {
      log.debug("Leaving FederationClientCertificate.viewOf(). Not needed.");
      return null;
    }
    const row = federation.clientCertificateOf(record);
    const renewDays = Number(
      config.value('federation.clientCertificateRenewDays'));
    if (!row) {
      log.debug("Leaving FederationClientCertificate.viewOf(). None held.");
      return { held: false, tokenAuth: String(record.fedTokenAuth || ''),
               renewDays: renewDays, certificatePem: '', chainPem: [],
               subject: '', x5tS256: '', serialHex: '', notBefore: '',
               notAfter: '', renewsAt: '', sealed: false };
    }
    const pem = function (b64: string): string {
      return '-----BEGIN CERTIFICATE-----\n' +
        (String(b64).match(/.{1,64}/g) || []).join('\n') +
        '\n-----END CERTIFICATE-----\n';
    };
    const ends = new Date(String(row.notAfter || '')).getTime();
    log.debug("Leaving FederationClientCertificate.viewOf().");
    return {
      held: true,
      tokenAuth: String(record.fedTokenAuth || ''),
      renewDays: renewDays,
      certificatePem: pem(row.certificate),
      chainPem: (row.chain || []).map(pem),
      subject: String(row.subject || ''),
      x5tS256: String(row.x5tS256 || ''),
      serialHex: String(row.serialHex || ''),
      notBefore: String(row.notBefore || ''),
      notAfter: String(row.notAfter || ''),
      renewsAt: isFinite(ends)
        ? new Date(ends - renewDays * DAY_MS).toISOString() : '',
      sealed: !!row.sealed
    };
  }
}

// THE RENEWAL JOB, registered at load like the encryption key's retirement:
// a registration arms no timer — the scheduler's leader runs it.
FederationClientCertificate.registerRenewJob();

export = FederationClientCertificate;
