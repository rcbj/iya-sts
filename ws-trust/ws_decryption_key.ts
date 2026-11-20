// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ws_decryption_key.ts
//
// ===========================================================================
// AN APPLICATION'S OWN WS-TRUST DECRYPTION KEY PAIR (#1668, rcbj's request
// of 2026-11-19).
//
// "Create a configuration field to either upload or generate (from the
// internal CA) a keypair for use with encryption." Until then a WS-Trust
// request could be encrypted only to the realm's XML Encryption
// certificate, which `/saml2/metadata` publishes and no WS-Trust or console
// surface names. Now an application may hold a key pair of its own, on its
// page (Directory → Applications → the application → Credentials) and on
// `/admin-api` (rule 7):
//
//   * ISSUED from the realm's certificate authority by
//     `pki.issueEncryptionKeyPair()` — the `key-encipherment` profile, the
//     leaf a federation relationship's encryption key is (#168): keyUsage
//     keyEncipherment for RSA and keyAgreement for EC, never
//     digitalSignature. Its subject is the realm's standard one, `CN=<the
//     application's identifier>-encrypt`, then the organisation and country
//     every leaf of the realm carries (`pki.organisation`), and its
//     subjectAltName `urn:sts:application:<identifier>`.
//   * UPLOADED as a PEM certificate and its unencrypted PEM private key,
//     checked by `crypto.decryptionKeyPairProblem()`: one certificate, the
//     key its private half, RSA of 2048 bits or more or EC on P-256, P-384
//     or P-521 (what `crypto.decryptElement()` unwraps a content key with),
//     a keyUsage that permits it, a validity that has not ended. Each
//     failure has its code (`STS-ADMIN-0946` to `0949`). PKCS#12 is not
//     taken: the PKI page this is modelled on takes PEM only.
//   * REMOVED, which takes all four attributes off. It is not revocation,
//     as the PKI page's take-off is not: an issued certificate stays valid
//     and is not on a CRL, and a request encrypted to it is refused from
//     then on because nothing here holds its key.
//
// The private key is sealed and WITHHELD by `common/applications.js`
// (`setWstrustDecryptionKey()`, `wstrustDecryptionKeyOf()`): no page, no
// `/admin-api` answer, no directory read and no log line carries it. The
// certificate is public: `state()` gives it to the page and to
// `GET /admin-api/applications?application=`, which is where a client gets
// it, since the realm's WSDL names only the realm's certificate.
//
// `keyFor()` is the other half: the decryption key a requester's
// EncryptedKey names, chosen by `ws_encryption.ts`.
//
// A STATIC UTILITY CLASS (#50), `federation_encryption.ts`'s shape: it
// holds no state, so there is nothing for the composition root to build.
// It requires libraries only and reaches `common/pki.js` LAZILY, at an
// issue, as that file does.
// ===========================================================================

import helpers = require('../common/helpers');
import applications = require('../common/applications');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');

type Json = any;

const log = helpers.log;

// The suffix rcbj named for the common name of an issued certificate.
const CN_SUFFIX = '-encrypt';

// The key type an issue makes when none is asked for.
const DEFAULT_KEY_ALG = 'rsa-3072';

// The NIST names of the curves OpenSSL reports, for the page.
const CURVES = { prime256v1: 'P-256', secp384r1: 'P-384',
                 secp521r1: 'P-521' };

// Which code an upload's problem is refused under.
const UPLOAD_CODES = {
  certificate: 'STS-ADMIN-0946',
  key: 'STS-ADMIN-0946',
  mismatch: 'STS-ADMIN-0947',
  algorithm: 'STS-ADMIN-0948',
  usage: 'STS-ADMIN-0949',
  expired: 'STS-ADMIN-0949'
};

/**
 * An application's own WS-Trust decryption key pair: issued from the realm's
 * CA, uploaded, removed, described, and chosen for a request.
 */
class WsDecryptionKey {
  /**
   * The suffix of an issued certificate's common name.
   */
  static readonly CN_SUFFIX = CN_SUFFIX;
  /**
   * The key type an issue makes by default.
   */
  static readonly DEFAULT_KEY_ALG = DEFAULT_KEY_ALG;

  /**
   * The key types an issue makes: `pki.ENCRYPTION_KEY_ALGS`.
   *
   * @returns the ids
   */
  static keyAlgorithms(): string[] {
    log.debug("Entering WsDecryptionKey.keyAlgorithms().");
    const algs = require('../common/pki').ENCRYPTION_KEY_ALGS.slice();
    log.debug("Leaving WsDecryptionKey.keyAlgorithms().");
    return algs;
  }

  /**
   * The common name an issued certificate carries for an application.
   *
   * @param identifier - the application
   * @returns `<identifier>-encrypt`
   */
  static commonNameFor(identifier: string): string {
    log.debug("Entering WsDecryptionKey.commonNameFor().");
    log.debug("Leaving WsDecryptionKey.commonNameFor().");
    return String(identifier) + CN_SUFFIX;
  }

  /**
   * Describes a certificate for the page and the API: subject, issuer,
   * serial, validity, key type and both thumbprints.
   *
   * @param pem - the certificate
   * @returns the summary, or `{ unreadable }`
   */
  static summary(pem: string): Json {
    log.debug("Entering WsDecryptionKey.summary().");
    try {
      const cert = stsCrypto.parseCertificate(String(pem));
      const notAfter = new Date(cert.validTo);
      const facts = stsCrypto.certificateFacts(cert);
      const out = {
        subject: String(cert.subject || '').split('\n').filter(Boolean)
          .join(', '),
        issuer: String(cert.issuer || '').split('\n').filter(Boolean)
          .join(', '),
        serialHex: String(cert.serialNumber || '').toLowerCase(),
        notBefore: new Date(cert.validFrom).toISOString(),
        notAfter: notAfter.toISOString(),
        expired: notAfter.getTime() < Date.now(),
        selfSigned: cert.subject === cert.issuer,
        keyType: String(cert.publicKey.asymmetricKeyType || ''),
        keyDetail: facts.keyBits ? 'RSA ' + facts.keyBits
          : (facts.curve ? 'EC ' + (CURVES[facts.curve] || facts.curve)
                         : ''),
        keyUsage: facts.keyUsage,
        thumbprint: stsCrypto.digest('sha256', cert.raw, 'base64url'),
        thumbprintSha1: stsCrypto.wssThumbprintSha1(String(pem))
      };
      log.debug("Leaving WsDecryptionKey.summary().");
      return out;
    } catch (e) {
      log.debug("Caught in WsDecryptionKey.summary(): " +
                ((e && e.message) || e));
      // Reported as unreadable rather than dropped, so the page says what
      // the entry holds.
      log.debug("Leaving WsDecryptionKey.summary(). Unreadable.");
      return { unreadable: String((e && e.message) || e) };
    }
  }

  /**
   * What an application's page and `GET /admin-api/applications` say about
   * its decryption key pair: the certificate and its chain, where it came
   * from, whether the private key is held and sealed, and what an issue
   * would make. Never the private key.
   *
   * @param row - the application's view
   * @returns the state
   */
  static state(row: Json): Json {
    log.debug("Entering WsDecryptionKey.state().");
    const names = applications.DECRYPTION_KEY_ATTRIBUTES;
    const fields = (row && row.fields) || {};
    const one = function (name: string): string {
      log.debug("Entering one().");
      const value = fields[name];
      log.debug("Leaving one().");
      return String(Array.isArray(value) ? value[0] || '' : value || '');
    };
    const certificatePem = one(names.certificate);
    const chainPem = one(names.chain);
    const identifier = String((row && row.identifier) || '');
    const pki = require('../common/pki');
    // Asked of the registry: a view withholds the private key, sealed or
    // not, so it cannot say which.
    const facts = applications.wstrustDecryptionKeyFacts(identifier);
    const declared = [].concat((row && row.allowedProtocols) || []);
    const out = {
      held: !!certificatePem,
      wstrustDeclared: declared.indexOf('wstrust') >= 0,
      source: one(names.source),
      certificate: certificatePem
        ? WsDecryptionKey.summary(certificatePem) : null,
      certificatePem: certificatePem,
      chain: (chainPem.match(
        /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ||
        []).map(function (pem) {
          return WsDecryptionKey.summary(pem);
        }),
      privateKeyHeld: facts.privateKeyHeld,
      sealedAtRest: facts.sealed,
      caAvailable: !!pki.hasChain(),
      keyAlgorithms: WsDecryptionKey.keyAlgorithms(),
      defaultKeyAlg: DEFAULT_KEY_ALG,
      commonName: WsDecryptionKey.commonNameFor(identifier),
      attributes: Object.assign({}, names)
    };
    log.debug("Leaving WsDecryptionKey.state(). " + out.held);
    return out;
  }

  /**
   * Issues an application a decryption key pair from the realm's CA and
   * writes it onto its entry, replacing the one it held.
   *
   * @param identifier - the application
   * @param body - `keyAlg` (`rsa-3072` by default, or `ec-p256`), `days`
   * @param ctx - `actor`, `via`
   * @returns a promise of `{ ok: true, message, wstrustDecryption }`, or a
   *   refusal with its code marked
   */
  static async issue(identifier: string, body: Json,
                     ctx: Json): Promise<Json> {
    log.debug("Entering WsDecryptionKey.issue(). " + identifier);
    const asked = body || {};
    const target = applications.get(identifier);
    if (!target) {
      log.debug("Leaving WsDecryptionKey.issue(). No such application.");
      return WsDecryptionKey.noApplication(identifier);
    }
    const pki = require('../common/pki');
    const keyAlg = String(asked.keyAlg || '').trim() || DEFAULT_KEY_ALG;
    const days = Number(asked.days);
    const made = await pki.issueEncryptionKeyPair(undefined, {
      identifier: String(target.identifier),
      encryptionHolder: 'application',
      keyAlg: keyAlg,
      commonName: WsDecryptionKey.commonNameFor(String(target.identifier)),
      days: isFinite(days) && days > 0 ? Math.floor(days) : undefined
    });
    if (!made.ok) {
      log.debug("Leaving WsDecryptionKey.issue(). Not issued.");
      return errorCodes.mark({ ok: false, errors: ['No WS-Trust decryption ' +
        'key pair could be issued to "' + target.identifier + '": ' +
        (made.errors || []).join(' ')] }, 'STS-ADMIN-0945');
    }
    const issued = made.issued;
    const written = applications.setWstrustDecryptionKey(
      String(target.identifier), {
        certificate: String(issued.certificatePem),
        chain: (issued.chainPem || []).join(''),
        privateKey: String(issued.privateKeyPem),
        source: 'issued'
      }, { actor: (ctx && ctx.actor) || '' });
    if (!written.ok) {
      log.error(errorCodes.tag(errorCodes.codeOf(written) || 'STS-REG-0372') +
                'ws-trust: a decryption key pair was issued to "' +
                target.identifier + '" (serial ' + issued.serialHex + ') ' +
                'and could not be written; this service keeps no other ' +
                'copy of its private key.');
      log.debug("Leaving WsDecryptionKey.issue(). Not written.");
      return written;
    }
    WsDecryptionKey.audited('wstrust.decryption-key.issue', target, ctx,
      'A WS-Trust decryption key pair was issued to application "' +
      target.identifier + '" from the realm\'s certificate authority',
      { serialHex: issued.serialHex, keyAlg: issued.keyAlg,
        subject: issued.subject });
    log.info('ws-trust: application ' + target.identifier + ' holds a new ' +
             issued.keyAlg + ' decryption key pair, serial ' +
             issued.serialHex + '.');
    log.debug("Leaving WsDecryptionKey.issue(). Issued.");
    return WsDecryptionKey.answer(String(target.identifier),
      'A ' + issued.keyAlg + ' WS-Trust decryption key pair was issued to "' +
      target.identifier + '" from this realm\'s certificate authority (' +
      issued.subject + ', serial ' + issued.serialHex + ', valid until ' +
      issued.notAfter + '). A request for it is now decrypted with this ' +
      'key and must be encrypted to its certificate; give the requester ' +
      'the certificate.');
  }

  /**
   * Writes an uploaded certificate and private key onto an application, in
   * place of the pair it held, once they are one pair this service can
   * decrypt with.
   *
   * @param identifier - the application
   * @param body - `certificate` and `privateKey`, PEM
   * @param ctx - `actor`, `via`
   * @returns `{ ok: true, message, wstrustDecryption }`, or a refusal with
   *   its code marked
   */
  static upload(identifier: string, body: Json, ctx: Json): Json {
    log.debug("Entering WsDecryptionKey.upload(). " + identifier);
    const asked = body || {};
    const target = applications.get(identifier);
    if (!target) {
      log.debug("Leaving WsDecryptionKey.upload(). No such application.");
      return WsDecryptionKey.noApplication(identifier);
    }
    const checked = stsCrypto.decryptionKeyPairProblem(
      String(asked.certificate || ''), String(asked.privateKey || ''));
    if (!checked.ok) {
      log.debug("Leaving WsDecryptionKey.upload(). " + checked.problem);
      return errorCodes.mark({ ok: false, errors: ['The key pair was not ' +
        'stored: ' + checked.why + '.'] }, UPLOAD_CODES[checked.problem] ||
        'STS-ADMIN-0946');
    }
    // ONE APPLICATION PER CERTIFICATE: the handle a request names would
    // otherwise choose between two entries (`forDecryptionKey()`).
    const elsewhere = stsCrypto.wssCertificateHandles(checked.certificatePem)
      .map(function (handle) {
        return applications.forDecryptionKey(handle);
      }).filter(function (holder) {
        return holder && holder !== String(target.identifier);
      })[0];
    if (elsewhere) {
      log.debug("Leaving WsDecryptionKey.upload(). Held elsewhere.");
      return errorCodes.mark({ ok: false, errors: ['The certificate is ' +
        'already the WS-Trust decryption certificate of "' + elsewhere +
        '"; one certificate decrypts for one application.'] },
        'STS-ADMIN-0950');
    }
    const written = applications.setWstrustDecryptionKey(
      String(target.identifier), {
        certificate: checked.certificatePem,
        chain: '',
        privateKey: String(asked.privateKey),
        source: 'uploaded'
      }, { actor: (ctx && ctx.actor) || '' });
    if (!written.ok) {
      log.debug("Leaving WsDecryptionKey.upload(). Not written.");
      return written;
    }
    const summary = WsDecryptionKey.summary(checked.certificatePem);
    WsDecryptionKey.audited('wstrust.decryption-key.upload', target, ctx,
      'A WS-Trust decryption key pair was uploaded for application "' +
      target.identifier + '"',
      { serialHex: summary.serialHex, keyAlg: checked.keyDetail,
        subject: summary.subject });
    log.debug("Leaving WsDecryptionKey.upload(). Stored.");
    return WsDecryptionKey.answer(String(target.identifier),
      'The ' + checked.keyDetail + ' key pair of "' + summary.subject +
      '" is now the WS-Trust decryption key pair of "' + target.identifier +
      '". A request for it is decrypted with this key and must be ' +
      'encrypted to its certificate.');
  }

  /**
   * Takes an application's decryption key pair off its entry. Not
   * revocation: an issued certificate stays valid; nothing here can open a
   * request encrypted to it any longer.
   *
   * @param identifier - the application
   * @param ctx - `actor`, `via`
   * @returns `{ ok: true, message, wstrustDecryption }`, or a refusal with
   *   its code marked
   */
  static remove(identifier: string, ctx: Json): Json {
    log.debug("Entering WsDecryptionKey.remove(). " + identifier);
    const target = applications.get(identifier);
    if (!target) {
      log.debug("Leaving WsDecryptionKey.remove(). No such application.");
      return WsDecryptionKey.noApplication(identifier);
    }
    if (!applications.wstrustDecryptionKeyFacts(String(target.identifier))
          .held) {
      log.debug("Leaving WsDecryptionKey.remove(). None held.");
      return errorCodes.mark({ ok: false, errors: ['"' + target.identifier +
        '" holds no WS-Trust decryption key pair, so there is nothing to ' +
        'remove.'] }, 'STS-ADMIN-0950');
    }
    const cleared = applications.setWstrustDecryptionKey(
      String(target.identifier), null, { actor: (ctx && ctx.actor) || '' });
    if (!cleared.ok) {
      log.debug("Leaving WsDecryptionKey.remove(). Not cleared.");
      return cleared;
    }
    WsDecryptionKey.audited('wstrust.decryption-key.remove', target, ctx,
      'The WS-Trust decryption key pair of application "' +
      target.identifier + '" was removed', {});
    log.debug("Leaving WsDecryptionKey.remove(). Removed.");
    return WsDecryptionKey.answer(String(target.identifier),
      'The WS-Trust decryption key pair of "' + target.identifier + '" was ' +
      'removed. A request for it is decrypted with the realm\'s key again. ' +
      'This is not revocation: an issued certificate stays valid and is ' +
      'on no revocation list.');
  }

  /**
   * The decryption key a handle names, among the applications' own: the
   * application holding it and its private key, opened for this request.
   *
   * @param handles - `crypto.wssCertificateHandles()`'s forms, as the
   *   EncryptedKey names its recipient
   * @returns `{ owner, privateKey, certificate }`, or null when no
   *   application holds a certificate it names (or its key will not open)
   */
  static keyFor(handles: string[]): Json {
    log.debug("Entering WsDecryptionKey.keyFor().");
    for (let i = 0; i < (handles || []).length; i++) {
      const owner = applications.forDecryptionKey(handles[i]);
      if (!owner) {
        continue;
      }
      const pair = applications.wstrustDecryptionKeyOf(owner);
      if (!pair) {
        log.debug("Leaving WsDecryptionKey.keyFor(). Will not open.");
        return null;
      }
      log.debug("Leaving WsDecryptionKey.keyFor(). " + owner);
      return { owner: owner, privateKey: pair.privateKey,
               certificate: pair.certificate };
    }
    log.debug("Leaving WsDecryptionKey.keyFor(). No application's.");
    return null;
  }

  // The answer every act gives: its sentence and the key pair as it now
  // stands, as the application page and the GET draw it.
  private static answer(identifier: string, message: string): Json {
    log.debug("Entering WsDecryptionKey.answer().");
    const row = applications.get(identifier);
    log.debug("Leaving WsDecryptionKey.answer().");
    return { ok: true, message: message, application: identifier,
             wstrustDecryption: WsDecryptionKey.state(row) };
  }

  private static noApplication(identifier: string): Json {
    log.debug("Entering WsDecryptionKey.noApplication().");
    log.debug("Leaving WsDecryptionKey.noApplication().");
    return errorCodes.mark({ ok: false, errors: ['There is no application ' +
      'called "' + identifier + '" here, and a decryption key pair creates ' +
      'nothing.'] }, 'STS-ADMIN-0950');
  }

  // One audit row per act, naming the application and who acted. Never the
  // private key: the detail is the certificate's serial, type and subject.
  private static audited(action: string, target: Json, ctx: Json,
                         summary: string, detail: Json): void {
    log.debug("Entering WsDecryptionKey.audited(). " + action);
    audit.audit({
      action: action, actor: (ctx && ctx.actor) || '',
      protocol: 'console', channel: 'internal',
      target: String(target.identifier),
      summary: summary,
      detail: Object.assign({ identifier: String(target.identifier),
                              via: (ctx && ctx.via) || 'console' },
                            detail || {})
    });
    log.debug("Leaving WsDecryptionKey.audited().");
  }

}

export = WsDecryptionKey;
