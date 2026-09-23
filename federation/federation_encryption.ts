'use strict';
//
// File: federation_encryption.ts
//
// ===========================================================================
// A PARTNER'S ENCRYPTED ASSERTION OR ID TOKEN, AND THE KEY IT IS ENCRYPTED TO
// (#168, 2026-09-23).
//
// Until this file `/federation/acs/{id}` refused an `<EncryptedAssertion>` as
// "no assertion" (STS-FED-0011), read a JWE ID Token's header as a JWS's and
// failed on the key, and published no key a partner could encrypt to. The
// refusal failed CLOSED, so nothing was accepted that should not have been —
// what it cost was CONFIDENTIALITY: the only way to federate with this
// service was for the partner to turn encryption off, and the person's NameID,
// mail and groups then crossed their browser in clear. Deployment profiles
// (saml2int) expect a service provider to decrypt, and a great many identity
// providers encrypt by default.
//
// So each service-provider-side SAML 2.0, WS-Federation and OpenID Connect
// relationship holds its OWN encryption key pair, and this file owns it:
//
//   * ISSUED under the realm's Intermediate by `common/pki.js`'s
//     `issueEncryptionKeyPair()` — a leaf whose KeyUsage is keyEncipherment
//     (RSA) or keyAgreement (EC) and never digitalSignature — when the
//     relationship is created, and again whenever it is ROTATED from the
//     console or `POST /admin-api/federation/rotate-key` (rule 7). One key per
//     relationship rather than one per realm, so a key that leaks exposes one
//     partner's traffic and a partner that must be cut off can be.
//   * SEALED at rest under the key-encryption key wherever keys persist, as an
//     application's private key is (`keystore.seal()`, label
//     `federation-encryption-key`), and WITHHELD from every LDAP search, page
//     and API reply, which carry the public half.
//   * ROTATED WITH A GRACE PERIOD: the key a rotation replaces keeps
//     decrypting for `federation.encryptionKeyGraceS`, so a partner still
//     holding the old metadata is not refused mid-change. Past it, it decrypts
//     nothing — checked at the READ, so correctness never waits for a timer —
//     and the scheduler job `federation.encryption-key-retire` removes it
//     from the entry (root CLAUDE.md, *Anything periodic is a scheduler job*).
//   * PUBLISHED: `KeyDescriptor use="encryption"` in `/federation/metadata/
//     {id}` for SAML 2.0 and WS-Federation, and `/federation/jwks/{id}` with
//     `use: enc` for OpenID Connect — what the partner registers.
//   * DECRYPTED WITH through `common/crypto.js` only: `decryptElement()` for
//     XML Encryption, `decryptJweCompact()` for JWE (rule 3r). What THIS file
//     adds is the relationship's policy — exactly the algorithms it
//     published, and nothing weaker in any mode.
//
// ---------------------------------------------------------------------------
// ONE CODE FOR EVERY DECRYPTION FAILURE, AND THAT IS THE POINT.
//
// A wrong key, an altered ciphertext, a tag that does not verify, a key that
// will not unwrap: every one is STS-FED-0138, with one sentence on the page.
// A responder that says WHICH step failed is a padding or unwrap oracle to
// whoever can submit ciphertexts (XML Encryption 1.1 section 6.1). The detail
// goes to the log, for the operator. What IS told apart is an algorithm the
// relationship does not accept (STS-FED-0139) — that is read off the document
// in clear, before any key is touched, and says nothing about the key.
//
// ---------------------------------------------------------------------------
// NO POST-QUANTUM KEY ENCAPSULATION, YET.
//
// XML Encryption has no registered ML-KEM method (neither W3C nor OASIS has
// defined one), and JOSE's ML-KEM registration (draft-ietf-jose-pqc-kem) is a
// draft. Confidentiality here is therefore classical against a
// harvest-now-decrypt-later adversary, as `oauth-oidc/id_token_encryption.ts`
// records for the other direction. The KEY TABLE is shaped for the day one is
// registered: every row carries its own `keyType`, so a hybrid
// (X25519MLKEM768-style) key is one more row type beside the classical one,
// and the policy's `keyType` one more value — no table change.
//
// ---------------------------------------------------------------------------
// A STATIC UTILITY CLASS (#50), `federation_links.ts`'s shape: it holds no
// state, so there is nothing for the composition root to build. It requires
// libraries only — the register, the crypto module, the keystore, the mode,
// the error codes, the scheduler — none of which requires it back, and
// reaches `common/pki.js` LAZILY, at the moment a key is issued: that module
// is heavy, and issuing is the one act here that needs it.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import federation = require('./federation');
import stsCrypto = require('../common/crypto');
import keystore = require('../common/keystore');
import errorCodes = require('../common/error_codes');
import scheduler = require('../cluster/scheduler');
import nodeCrypto = require('crypto');

type Json = any;

const log = helpers.log;

// What `/admin/encryption` counts the sealed private keys under.
const SEAL_LABEL = 'federation-encryption-key';
// The key table's row format, so a row written by a later shape is refused by
// name rather than read wrongly.
const ROW_VERSION = 1;
const RETIRE_JOB = 'federation.encryption-key-retire';
const XENC_NS = 'http://www.w3.org/2001/04/xmlenc#';
const XENC11_NS = 'http://www.w3.org/2009/xmlenc11#';
const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';

// What a decryption answers.
interface Decrypted {
  ok: boolean;
  xml?: string;
  plaintext?: string;
  header?: Json;
  kid?: string;
  algorithm?: string;
  code?: string;
  why?: string;
  detail?: string;
}

class FederationEncryption {
  static readonly SEAL_LABEL = SEAL_LABEL;
  static readonly RETIRE_JOB = RETIRE_JOB;
  static readonly ROW_VERSION = ROW_VERSION;

  // -------------------------------------------------------------------------
  // THE ROWS THAT MAY DECRYPT NOW: the current key and a previous one still
  // inside its grace. A previous row past its `retiresAt` is NOT used even if
  // the job has not yet removed it — the expiry is checked at the read.
  // -------------------------------------------------------------------------
  static usableKeys(record: Json, nowMs?: number): Json[] {
    log.debug("Entering FederationEncryption.usableKeys().");
    const now = Number(nowMs) || Date.now();
    const rows = federation.encryptionKeysOf(record).filter(function (row) {
      if (Number(row.v) !== ROW_VERSION) {
        return false;
      }
      if (row.state === 'current') {
        return true;
      }
      return row.state === 'previous' && Number(row.retiresAt) > now;
    });
    // Current first: the partner that has the new metadata is the ordinary
    // case.
    rows.sort(function (a, b) {
      return (a.state === 'current' ? 0 : 1) - (b.state === 'current' ? 0 : 1);
    });
    log.debug("Leaving FederationEncryption.usableKeys(). " + rows.length);
    return rows;
  }

  // The private key of a row, as node's KeyObject, or null when it will not
  // open — a key sealed under a key-encryption key this process no longer
  // holds. Logged, and the row decrypts nothing.
  static privateKeyOf(record: Json, row: Json): nodeCrypto.KeyObject | null {
    log.debug("Entering FederationEncryption.privateKeyOf(). kid=" + row.kid);
    const stored = String(row.privateKey || '');
    const pem = row.sealed ? keystore.open(stored, SEAL_LABEL) : stored;
    if (!pem) {
      log.warn(errorCodes.tag('STS-FED-0137') + 'federation: ' +
               record.fedId + '\'s encryption key ' + row.kid + ' is ' +
               'sealed under a key-encryption key this process does not ' +
               'hold, so it decrypts nothing. Rotate the key.');
      log.debug("Leaving FederationEncryption.privateKeyOf(). Not opened.");
      return null;
    }
    try {
      const key = nodeCrypto.createPrivateKey(pem);
      log.debug("Leaving FederationEncryption.privateKeyOf().");
      return key;
    } catch (e) {
      log.warn(errorCodes.tag('STS-FED-0137') + 'federation: ' +
               record.fedId + '\'s encryption key ' + row.kid + ' does not ' +
               'parse (' + ((e && e.message) || e) + '), so it decrypts ' +
               'nothing. Rotate the key.');
      log.debug("Leaving FederationEncryption.privateKeyOf(). Unreadable.");
      return null;
    }
  }

  // Which key type a management algorithm needs.
  static keyTypeFor(management: string): string {
    log.debug("Entering FederationEncryption.keyTypeFor().");
    log.debug("Leaving FederationEncryption.keyTypeFor().");
    return /^ecdh/i.test(management) ? 'ec-p256' : 'rsa-3072';
  }

  // -------------------------------------------------------------------------
  // XML ENCRYPTION: an EncryptedAssertion, an EncryptedID, an
  // EncryptedAttribute, or the EncryptedData inside a WS-Federation
  // RequestedSecurityToken — `elementXml` is the element serialised whole,
  // namespace declarations included. `{ ok, xml }` is its plaintext.
  // -------------------------------------------------------------------------
  static decryptXml(record: Json, elementXml: string,
                    nowMs?: number): Decrypted {
    log.debug("Entering FederationEncryption.decryptXml(). id=" +
              record.fedId);
    const policy = federation.encryptionPolicyOf(record);
    const keys = FederationEncryption.usableKeys(record, nowMs)
      .filter(function (row) {
        return row.keyType === FederationEncryption.keyTypeFor(
          policy.management);
      });
    if (!keys.length) {
      log.debug("Leaving FederationEncryption.decryptXml(). No key.");
      return { ok: false, code: 'STS-FED-0137',
               why: 'this relationship holds no ' + policy.keyType + ' ' +
                    'encryption key to decrypt with. Rotate its encryption ' +
                    'key, and give the partner the new certificate.' };
    }
    const options = {
      allowedCiphers: [policy.content],
      allowedKeyManagement: [policy.management],
      allowedOaepDigests: ['sha256'],
      logArtifact: helpers.logArtifact
    };
    let last = '';
    for (let i = 0; i < keys.length; i++) {
      const key = FederationEncryption.privateKeyOf(record, keys[i]);
      if (!key) {
        continue;
      }
      const pem = String(key.export({ format: 'pem', type: 'pkcs8' }));
      const out: Json = stsCrypto.decryptElement(elementXml, pem, options);
      if (out.ok) {
        log.debug("Leaving FederationEncryption.decryptXml(). Decrypted " +
                  "with " + keys[i].kid + ".");
        return { ok: true, xml: out.xml, kid: keys[i].kid,
                 algorithm: out.algorithm + ' / ' + out.keyTransport };
      }
      if (out.refused || errorCodes.codeOf(out) === 'STS-KEYS-0070') {
        // READ OFF THE DOCUMENT IN CLEAR, before any key operation: the
        // same answer for every key, so it is answered once.
        log.debug("Leaving FederationEncryption.decryptXml(). A refused " +
                  "algorithm.");
        return { ok: false, code: 'STS-FED-0139',
                 why: 'it is encrypted with an algorithm this relationship ' +
                      'does not accept: ' + out.why + '. It accepts ' +
                      policy.content + ' under ' + policy.management +
                      (policy.management === 'rsa-oaep'
                        ? ' (SHA-256, MGF1-SHA-256)' : '') +
                      ', which is what its metadata publishes.' };
      }
      last = String(out.why || '');
    }
    log.info(errorCodes.tag('STS-FED-0138') + 'federation: ' + record.fedId +
             ': an encrypted element did not decrypt under any of its ' +
             keys.length + ' usable key(s): ' + last);
    log.debug("Leaving FederationEncryption.decryptXml(). Not decrypted.");
    return { ok: false, code: 'STS-FED-0138', detail: last,
             why: FederationEncryption.decryptionFailure() };
  }

  // THE ONE SENTENCE for every decryption failure — see the header.
  static decryptionFailure(): string {
    log.debug("Entering FederationEncryption.decryptionFailure().");
    log.debug("Leaving FederationEncryption.decryptionFailure().");
    return 'what the partner encrypted could not be decrypted with this ' +
           'relationship\'s key. The usual cause is a partner encrypting to ' +
           'a certificate this relationship no longer holds — give it the ' +
           'one published now. Which step failed is in this service\'s log ' +
           'and deliberately not here.';
  }

  // -------------------------------------------------------------------------
  // A JWE — an encrypted ID Token (OpenID Connect Core section 10.2). The
  // plaintext is the NESTED JWS, which the caller verifies exactly as it
  // verifies an unencrypted one: signed, then encrypted, and never encrypted
  // alone.
  // -------------------------------------------------------------------------
  static decryptJwe(record: Json, compact: string, nowMs?: number): Decrypted {
    log.debug("Entering FederationEncryption.decryptJwe(). id=" +
              record.fedId);
    const policy = federation.encryptionPolicyOf(record);
    let header: Json = null;
    try {
      header = JSON.parse(Buffer.from(String(compact).split('.')[0],
                                      'base64url').toString('utf8'));
    } catch (e) {
      log.debug("Caught in FederationEncryption.decryptJwe(): " +
                ((e && e.message) || e));
      header = null;
    }
    if (!header || typeof header !== 'object') {
      log.debug("Leaving FederationEncryption.decryptJwe(). No header.");
      return { ok: false, code: 'STS-FED-0138',
               why: FederationEncryption.decryptionFailure(),
               detail: 'the JWE protected header is not base64url JSON' };
    }
    const alg = String(header.alg || '');
    const enc = String(header.enc || '');
    if (alg !== policy.management || enc !== policy.content) {
      log.debug("Leaving FederationEncryption.decryptJwe(). A refused " +
                "algorithm.");
      return { ok: false, code: 'STS-FED-0139',
               why: 'it is encrypted with alg ' + (alg || '(none)') +
                    ' and enc ' + (enc || '(none)') + ', and this ' +
                    'relationship accepts only alg ' + policy.management +
                    ' with enc ' + policy.content + ' — what its JWKS ' +
                    'and its registration name.' +
                    (federation.REFUSED_ALGORITHMS.indexOf(alg) >= 0 ||
                     federation.REFUSED_ALGORITHMS.indexOf(enc) >= 0
                      ? ' ' + (federation.REFUSED_ALGORITHMS.indexOf(alg) >= 0
                               ? alg : enc) + ' is refused in every mode.'
                      : '') };
    }
    const wanted = FederationEncryption.keyTypeFor(policy.management);
    let keys = FederationEncryption.usableKeys(record, nowMs)
      .filter(function (row) {
        return row.keyType === wanted;
      });
    // THE kid SELECTS, and never establishes (federation/CLAUDE.md, decision
    // 5): a kid naming a key this relationship does not hold, or no longer
    // decrypts with, is "no key" — never a reason to try the others.
    if (header.kid) {
      keys = keys.filter(function (row) {
        return row.kid === header.kid;
      });
    }
    if (!keys.length) {
      log.debug("Leaving FederationEncryption.decryptJwe(). No key.");
      return { ok: false, code: 'STS-FED-0137',
               why: header.kid
                 ? 'it is encrypted to the key "' + header.kid + '", which ' +
                   'this relationship does not hold or no longer decrypts ' +
                   'with. The partner should fetch the JWKS again.'
                 : 'this relationship holds no ' + wanted + ' encryption ' +
                   'key. Rotate its encryption key.' };
    }
    let last = '';
    for (let i = 0; i < keys.length; i++) {
      const key = FederationEncryption.privateKeyOf(record, keys[i]);
      if (!key) {
        continue;
      }
      try {
        const out = stsCrypto.decryptJweCompact(compact, {
          privateKey: key, allowedAlg: [policy.management],
          allowedEnc: [policy.content] });
        log.debug("Leaving FederationEncryption.decryptJwe(). Decrypted " +
                  "with " + keys[i].kid + ".");
        return { ok: true, plaintext: out.plaintext, header: out.header,
                 kid: keys[i].kid, algorithm: alg + ' / ' + enc };
      } catch (e) {
        log.debug("Caught in FederationEncryption.decryptJwe(): " +
                  ((e && e.message) || e));
        last = String((e && e.message) || e);
      }
    }
    log.info(errorCodes.tag('STS-FED-0138') + 'federation: ' + record.fedId +
             ': an encrypted ID Token did not decrypt: ' + last);
    log.debug("Leaving FederationEncryption.decryptJwe(). Not decrypted.");
    return { ok: false, code: 'STS-FED-0138', detail: last,
             why: FederationEncryption.decryptionFailure() };
  }

  // -------------------------------------------------------------------------
  // ISSUE, OR ROTATE: a new key of the relationship's key type becomes
  // `current`; the one it replaces becomes `previous` until
  // `federation.encryptionKeyGraceS` has passed (0 drops it now); an older
  // `previous` is dropped. Resolves `{ ok, kid, message }` or
  // `{ ok: false, errors }` with its code marked.
  // -------------------------------------------------------------------------
  static async rotate(id: string, why?: string): Promise<Json> {
    log.debug("Entering FederationEncryption.rotate(). id=" + id);
    const record = federation.get(id);
    if (!record || !federation.encrypts(record)) {
      log.debug("Leaving FederationEncryption.rotate(). Nothing to rotate.");
      return errorCodes.mark({ ok: false, errors: [record
        ? '"' + id + '" is ' + (record.fedRole !== 'service-provider'
            ? 'an identity-provider-side relationship, which decrypts ' +
              'nothing'
            : 'a ' + record.fedProtocol + ' relationship: SAML 1.1 has no ' +
              'encryption construct and a plain OAuth 2.0 relationship ' +
              'reads no ID Token') + ', so it holds no encryption key.'
        : 'There is no federation relationship called "' + id + '".'] },
                             'STS-FED-0144');
    }
    const policy = federation.encryptionPolicyOf(record);
    // Lazily: see the header.
    const pki = require('../common/pki');
    const spec = { identifier: id, keyAlg: policy.keyType,
                   commonName: 'federation ' + id + ' encryption' };
    let made = await pki.issueEncryptionKeyPair(undefined, spec);
    if (!made.ok && errorCodes.codeOf(made) === 'STS-PKI-0008') {
      // A realm made moments ago whose branch is still being built.
      await pki.ensureScope(realms.currentId());
      made = await pki.issueEncryptionKeyPair(undefined, spec);
    }
    if (!made.ok) {
      log.error(errorCodes.tag('STS-FED-0142') + 'federation: no ' +
                'encryption key could be issued for ' + id + ': ' +
                (made.errors || []).join(' '));
      log.debug("Leaving FederationEncryption.rotate(). Not issued.");
      return errorCodes.mark({ ok: false, errors: ['No encryption key could ' +
               'be issued for "' + id + '": ' +
               (made.errors || []).join(' ')] }, 'STS-FED-0142');
    }
    const issued = made.issued;
    // SEALED WHERE KEYS PERSIST, and refused rather than written in clear
    // where they persist and nothing can seal — `applications.js`'s rule
    // about a private key on an entry.
    let privateKey = String(issued.privateKeyPem);
    let sealed = false;
    if (keystore.persists()) {
      const closed = keystore.seal(privateKey, SEAL_LABEL);
      if (!closed) {
        log.error(errorCodes.tag('STS-FED-0142') + 'federation: the ' +
                  'encryption key for ' + id + ' could not be sealed, so ' +
                  'it was not written.');
        log.debug("Leaving FederationEncryption.rotate(). Not sealed.");
        return errorCodes.mark({ ok: false, errors: ['The encryption key ' +
                 'for "' + id + '" could not be sealed under the ' +
                 'key-encryption key, and a private key is never written ' +
                 'in clear where keys persist.'] }, 'STS-FED-0142');
      }
      privateKey = closed;
      sealed = true;
    }
    const now = Date.now();
    const graceMs = Number(config.value('federation.encryptionKeyGraceS')) *
                    1000;
    const fresh = federation.get(id) || record;
    const rows = federation.encryptionKeysOf(fresh)
      .filter(function (row) {
        return row.state === 'current' && graceMs > 0;
      })
      .map(function (row) {
        return Object.assign({}, row, { state: 'previous',
                                        retiresAt: now + graceMs });
      });
    const jwk = Object.assign({}, issued.publicJwk, { use: 'enc' });
    delete jwk.alg;
    rows.unshift({
      v: ROW_VERSION, kid: issued.kid, keyType: policy.keyType,
      state: 'current', createdAt: now, notAfter: issued.notAfter,
      certificate: stsCrypto.stripPem(issued.certificatePem),
      chain: (issued.chainPem || []).map(stsCrypto.stripPem),
      publicJwk: jwk, sealed: sealed, privateKey: privateKey
    });
    if (!federation.writeEncryptionKeys(id, rows, why ||
                                         'the encryption key was rotated')) {
      log.debug("Leaving FederationEncryption.rotate(). Not written.");
      return errorCodes.mark({ ok: false, errors: ['The directory refused ' +
               'the new encryption key for "' + id + '".'] }, 'STS-FED-0142');
    }
    log.info('federation: ' + id + ' has a new ' + policy.keyType +
             ' encryption key, ' + issued.kid + (rows.length > 1
               ? '; the one it replaces decrypts until ' +
                 new Date(now + graceMs).toISOString() +
                 ' (federation.encryptionKeyGraceS)'
               : '') + '.');
    log.debug("Leaving FederationEncryption.rotate(). " + issued.kid);
    return { ok: true, kid: issued.kid,
             message: 'A new ' + policy.keyType + ' encryption key, ' +
                      issued.kid + ', is current. ' + (rows.length > 1
                        ? 'The one it replaces still decrypts until ' +
                          new Date(now + graceMs).toISOString() + '. '
                        : '') +
                      'Give the partner the certificate or JWKS published ' +
                      'now.' };
  }

  // THE RETIREMENT: every previous row past its `retiresAt`, in this realm,
  // removed. The scheduler job's body; resolves `{ retired }`.
  static retireDue(nowMs?: number): Json {
    log.debug("Entering FederationEncryption.retireDue().");
    const now = Number(nowMs) || Date.now();
    let retired = 0;
    federation.inRole('service-provider').forEach(function (record) {
      const rows = federation.encryptionKeysOf(record);
      const kept = rows.filter(function (row) {
        return row.state !== 'previous' || Number(row.retiresAt) > now;
      });
      if (kept.length === rows.length) {
        return;
      }
      if (federation.writeEncryptionKeys(record.fedId, kept,
            'the encryption key its grace period covered was retired')) {
        retired += rows.length - kept.length;
      } else {
        log.error(errorCodes.tag('STS-FED-0145') + 'federation: the ' +
                  'retired encryption key of ' + record.fedId + ' could ' +
                  'not be removed; it decrypts nothing already, and the ' +
                  'next run tries again.');
      }
    });
    log.debug("Leaving FederationEncryption.retireDue(). " + retired);
    return { retired: retired };
  }

  static registerRetireJob(): void {
    log.debug("Entering FederationEncryption.registerRetireJob().");
    if (scheduler.job(RETIRE_JOB)) {
      log.debug("Leaving FederationEncryption.registerRetireJob(). " +
                "Registered.");
      return;
    }
    scheduler.register({
      id: RETIRE_JOB,
      title: 'Federation encryption key retirement',
      describe: 'Removes from each federation relationship the encryption ' +
                'key a rotation replaced, once ' +
                'federation.encryptionKeyGraceS has passed. The key stopped ' +
                'decrypting at that instant ' +
                'already; this takes it off the entry.',
      owner: 'federation/federation_encryption.ts',
      scope: 'realm',
      everyMs: function (): number {
        return 300000;
      },
      off: function (): string {
        return config.value('federation.enabled') ? ''
          : 'federation.enabled is off';
      },
      run: function (ctx: Json): Json {
        return FederationEncryption.retireDue(ctx.nowMs());
      }
    });
    log.debug("Leaving FederationEncryption.registerRetireJob().");
  }

  // -------------------------------------------------------------------------
  // PUBLICATION.
  // -------------------------------------------------------------------------

  // The current key's public JWK, `use: enc`, with the alg the relationship
  // accepts — what `/federation/jwks/{id}` serves. Null when there is none.
  static publicJwkOf(record: Json): Json {
    log.debug("Entering FederationEncryption.publicJwkOf().");
    const row = federation.currentEncryptionKeyOf(record);
    if (!row || !row.publicJwk) {
      log.debug("Leaving FederationEncryption.publicJwkOf(). None.");
      return null;
    }
    const policy = federation.encryptionPolicyOf(record);
    log.debug("Leaving FederationEncryption.publicJwkOf().");
    return Object.assign({}, row.publicJwk, { kid: row.kid, use: 'enc',
                                              alg: policy.management });
  }

  // `<md:KeyDescriptor use="encryption">` for the current key, with the
  // EncryptionMethods the relationship accepts (saml-metadata-2.0-os section
  // 2.4.1.1), or '' when there is none.
  static keyDescriptorOf(record: Json): string {
    log.debug("Entering FederationEncryption.keyDescriptorOf().");
    const row = federation.currentEncryptionKeyOf(record);
    if (!row) {
      log.debug("Leaving FederationEncryption.keyDescriptorOf(). None.");
      return '';
    }
    const policy = federation.encryptionPolicyOf(record);
    const cipher = stsCrypto.BLOCK_CIPHERS[policy.content];
    const methods = '<md:EncryptionMethod Algorithm="' + cipher.uri + '"/>' +
      (policy.management === 'rsa-oaep'
        ? '<md:EncryptionMethod Algorithm="' + XENC11_NS + 'rsa-oaep">' +
          '<ds:DigestMethod Algorithm="' + XENC_NS + 'sha256"/>' +
          '<xenc11:MGF xmlns:xenc11="' + XENC11_NS + '" Algorithm="' +
          XENC11_NS + 'mgf1sha256"/></md:EncryptionMethod>'
        : '<md:EncryptionMethod Algorithm="' + XENC11_NS + 'ECDH-ES"/>' +
          '<md:EncryptionMethod Algorithm="' + XENC_NS + 'kw-aes256"/>');
    log.debug("Leaving FederationEncryption.keyDescriptorOf().");
    return '<md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="' +
      DS_NS + '"><ds:KeyName>' + helpers.xmlEscape(row.kid) +
      '</ds:KeyName><ds:X509Data><ds:X509Certificate>' + row.certificate +
      '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' + methods +
      '</md:KeyDescriptor>';
  }

  // What the relationship page and `GET /admin-api/federation` show: the
  // policy, the public key table and — for the partner — the certificate as
  // a PEM. Never a private key.
  static viewOf(record: Json): Json {
    log.debug("Entering FederationEncryption.viewOf().");
    if (!federation.encrypts(record)) {
      log.debug("Leaving FederationEncryption.viewOf(). Not applicable.");
      return null;
    }
    const current = federation.currentEncryptionKeyOf(record);
    const now = Date.now();
    log.debug("Leaving FederationEncryption.viewOf().");
    return {
      policy: federation.encryptionPolicyOf(record),
      required: federation.encryptionRequired(record),
      allowUnencrypted: federation.boolOf(record.fedAllowUnencrypted, false),
      graceS: Number(config.value('federation.encryptionKeyGraceS')),
      current: current ? current.kid : '',
      certificatePem: current
        ? '-----BEGIN CERTIFICATE-----\n' +
          (String(current.certificate).match(/.{1,64}/g) || []).join('\n') +
          '\n-----END CERTIFICATE-----\n'
        : '',
      jwk: record.fedProtocol === 'oidc'
        ? FederationEncryption.publicJwkOf(record) : null,
      keys: federation.encryptionKeyView(record).map(function (row) {
        return { kid: row.kid, keyType: row.keyType, state: row.state,
                 notAfter: row.notAfter, createdAt: row.createdAt,
                 retiresAt: row.retiresAt || null,
                 decrypts: row.state === 'current' ||
                           Number(row.retiresAt) > now,
                 sealed: !!row.sealed };
      })
    };
  }
}

// THE RETIREMENT JOB, registered at load like the session sweep in
// `authn/authn.ts`: a registration arms no timer — the scheduler's leader
// runs it.
FederationEncryption.registerRetireJob();

export = FederationEncryption;
