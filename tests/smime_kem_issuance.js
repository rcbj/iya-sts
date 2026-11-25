// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/smime_kem_issuance.js
//
// ---------------------------------------------------------------------------
// AN ML-KEM S/MIME CERTIFICATE THIS REALM ISSUES, ON A PROOF OF POSSESSION
// (#2220; #2009's D4 left it to a later ticket).
//
// A KEM key cannot sign a certification request, so the proof is RFC 9810
// section 5.2.8.3's challenge-response: the service encapsulates to the
// key, the holder decapsulates and sends the secret back. Here the holder
// is node's own ML-KEM (`crypto.decapsulate()`), as `openssl pkeyutl
// -decap` would be.
//
//   A. reading the key: an ML-KEM-768 SubjectPublicKeyInfo is read, an RSA
//      key and text that is no key are refused (STS-OPENPGP-0035);
//   B. the challenge: a ciphertext of ML-KEM-768's length, shown in the
//      portal's view, the secret's digest only kept;
//   C. a wrong secret is refused (STS-OPENPGP-0038) and SPENDS the
//      challenge (a second answer is STS-OPENPGP-0037);
//   D. the right secret: an ML-KEM certificate from the realm's EST Issuing
//      CA, naming the entry's address, emailProtection, keyEncipherment
//      ONLY (RFC 9935), and now the person's S/MIME certificate — one mail
//      can be encrypted to, post-quantum;
//   E. the portal's act answers it once in `view.smimeKemIssued`.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const asn1js = require('asn1js');
const pki = require('../common/pki');
const realms = require('../common/realms');
const ldap = require('../ldap/ldap_server');
const stsCrypto = require('../common/crypto');
const keys = require('../common/openpgp_keys');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({ name: 'smime_kem_issuance',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = Date.now().toString(36);
const KEMMY = 'kem-kemmy-' + RUN;
const MAIL = KEMMY + '@kem-' + RUN + '.example.org';
const CTX = { actor: KEMMY, via: 'test' };

function code(answer) {
  log.debug("Entering code().");
  log.debug("Leaving code().");
  return errorCodes.codeOf(answer) || '';
}

// The secret node's ML-KEM decapsulates from a challenge, as hex: what
// `openssl pkeyutl -decap … | xxd -p` prints.
function decapsulated(pair, challenge) {
  log.debug("Entering decapsulated().");
  const secret = nodeCrypto.decapsulate(pair.privateKey,
    Buffer.from(challenge.cipherText, 'base64'));
  log.debug("Leaving decapsulated().");
  return Buffer.from(secret).toString('hex');
}

// The keyUsage bits of a certificate, by name, read off its DER.
function keyUsageOf(pem) {
  log.debug("Entering keyUsageOf().");
  const der = new nodeCrypto.X509Certificate(pem).raw;
  const pkijs = require('pkijs');
  const cert = pkijs.Certificate.fromBER(der);
  const ext = (cert.extensions || []).filter(function (one) {
    return one.extnID === '2.5.29.15';
  })[0];
  if (!ext) {
    log.debug("Leaving keyUsageOf(). None.");
    return [];
  }
  const bits = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView).result;
  const view = new Uint8Array(bits.valueBlock.valueHexView);
  const names = ['digitalSignature', 'nonRepudiation', 'keyEncipherment',
                 'dataEncipherment', 'keyAgreement', 'keyCertSign',
                 'cRLSign', 'encipherOnly'];
  const out = names.filter(function (name, i) {
    return view.length > 0 && (view[0] & (0x80 >> i)) !== 0;
  });
  log.debug("Leaving keyUsageOf().");
  return out;
}

function checkKeyReading(t, publicPem) {
  log.debug("Entering checkKeyReading().");
  const read = stsCrypto.smimeKemPublicKeyOf(publicPem);
  t.check(read.ok && read.name === 'ML-KEM-768' && read.raw.length === 1184,
          'A1. an ML-KEM-768 public key is read (RFC 9935)',
          JSON.stringify({ ok: read.ok, name: read.name }));
  const rsa = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    .publicKey.export({ type: 'spki', format: 'pem' });
  t.equal(stsCrypto.smimeKemPublicKeyOf(rsa).ok, false,
          'A2. an RSA key is not an ML-KEM key');
  const none = keys.issueSmimeKemChallenge(KEMMY, 'not a key', CTX);
  t.equal(code(none), 'STS-OPENPGP-0035',
          'A3. text that is no public key is refused, STS-OPENPGP-0035');
  const rsaAsked = keys.issueSmimeKemChallenge(KEMMY, rsa, CTX);
  t.equal(code(rsaAsked), 'STS-OPENPGP-0035',
          'A4. an RSA key is refused for an ML-KEM certificate');
  log.debug("Leaving checkKeyReading().");
}

async function checkWrongSecret(t, publicPem) {
  log.debug("Entering checkWrongSecret().");
  const asked = keys.issueSmimeKemChallenge(KEMMY, publicPem, CTX);
  t.check(asked.ok && Buffer.from(asked.challenge.cipherText, 'base64')
    .length === 1088, 'B1. the challenge is an ML-KEM-768 ciphertext ' +
    '(1088 octets)', JSON.stringify(asked.errors || ''));
  const shown = keys.smimeKemChallengeOf(KEMMY);
  t.check(shown && shown.cipherText === asked.challenge.cipherText &&
          shown.algorithm === 'ML-KEM-768',
          'B2. the portal\'s view shows the outstanding challenge');
  t.check(shown && shown.secretDigest === undefined && !shown.spkiPem,
          'B3. and nothing of the secret');
  const wrong = await keys.issueSmimeKemCertificate(KEMMY,
    nodeCrypto.randomBytes(32).toString('hex'), CTX);
  t.equal(code(wrong), 'STS-OPENPGP-0038',
          'C1. a secret that is not the encapsulated one is refused');
  const again = await keys.issueSmimeKemCertificate(KEMMY,
    nodeCrypto.randomBytes(32).toString('hex'), CTX);
  t.equal(code(again), 'STS-OPENPGP-0037',
          'C2. the wrong answer spent the challenge: there is none left');
  t.equal(keys.smimeKemChallengeOf(KEMMY), null,
          'C3. the view shows no challenge once it is spent');
  log.debug("Leaving checkWrongSecret().");
}

async function checkIssued(t, pair, publicPem) {
  log.debug("Entering checkIssued().");
  const asked = keys.issueSmimeKemChallenge(KEMMY, publicPem, CTX);
  const secret = decapsulated(pair, asked.challenge);
  const issued = await keys.issueSmimeKemCertificate(KEMMY, secret, CTX);
  t.check(issued.ok === true,
          'D1. the decapsulated secret issues the certificate',
          JSON.stringify(issued.errors || ''));
  if (!issued.ok) {
    log.debug("Leaving checkIssued(). Not issued.");
    return;
  }
  const cert = new nodeCrypto.X509Certificate(issued.certificate);
  t.check(String(cert.publicKey.asymmetricKeyType) === 'ml-kem-768',
          'D2. it certifies the ML-KEM-768 key that was sent',
          String(cert.publicKey.asymmetricKeyType));
  t.check(cert.publicKey.export({ type: 'spki', format: 'pem' }) ===
          publicPem, 'D3. the very key, byte for byte');
  t.check(String(cert.subjectAltName || '').indexOf('email:' + MAIL) >= 0,
          'D4. it names the entry\'s address as its rfc822Name',
          String(cert.subjectAltName));
  t.check((cert.keyUsage || []).indexOf('1.3.6.1.5.5.7.3.4') >= 0,
          'D5. its extended key usage is emailProtection');
  t.equal(JSON.stringify(keyUsageOf(issued.certificate)),
          JSON.stringify(['keyEncipherment']),
          'D6. keyEncipherment is its only key usage (RFC 9935 section 5)');
  t.check(issued.chain.length >= 3 &&
          new nodeCrypto.X509Certificate(issued.chain[1]).subject
            .indexOf('EST Issuing CA') >= 0,
          'D7. it was issued by the realm\'s EST Issuing CA, chain attached',
          issued.chain.length + ' ' + (issued.chain[1] ? new nodeCrypto
            .X509Certificate(issued.chain[1]).subject : ''));
  const view = keys.view(KEMMY);
  t.check(view.ok && view.mailEncryption.smimeUsable === true &&
          view.mailEncryption.smimeCertificate &&
          view.mailEncryption.smimeCertificate.serial === issued.serial,
          'D8. it is now the person\'s S/MIME certificate, usable for mail',
          JSON.stringify(view.mailEncryption || {}));
  const chosen = stsCrypto.smimeRecipientCertificate(
    [issued.certificate], new Date());
  t.check(chosen.ok && chosen.postQuantum === true,
          'D9. mail is encrypted to it post-quantum (a KEMRecipientInfo)');
  log.debug("Leaving checkIssued().");
}

async function checkPortalAct(t, pair, publicPem) {
  log.debug("Entering checkPortalAct().");
  const account = require('../portal/account_openpgp');
  const self = new account.AccountOpenPgp(
    account.AccountOpenPgp.defaultDeps());
  const answers = [];
  const ctx = {
    errorCodes: errorCodes,
    translatorFor: function () {
      return { text: function (key) {
        return key;
      } };
    },
    json: function (res, status, body) {
      answers.push({ status: status, body: body });
      return body;
    },
    refuse: function (res, status, c, errors) {
      answers.push({ status: status, code: c, errors: errors });
      return null;
    }
  };
  const caller = { username: KEMMY };
  await self.act(ctx, {}, {}, caller, { action: 'smime-kem-challenge',
                                         publicKey: publicPem });
  const first = answers.pop() || {};
  const challenge = first.body && first.body.view &&
    first.body.view.smimeKemChallenge;
  t.check(first.status === 200 && !!challenge,
          'E1. the portal\'s act answers the challenge in its view',
          JSON.stringify(first.errors || first.status));
  if (!challenge) {
    log.debug("Leaving checkPortalAct(). No challenge.");
    return;
  }
  await self.act(ctx, {}, {}, caller, { action: 'smime-kem-issue',
    secret: Buffer.from(decapsulated(pair, challenge), 'hex')
      .toString('base64') });
  const second = answers.pop() || {};
  const issued = second.body && second.body.view &&
    second.body.view.smimeKemIssued;
  t.check(second.status === 200 && issued &&
          /BEGIN CERTIFICATE/.test(issued.certificate) &&
          issued.algorithm === 'ML-KEM-768',
          'E2. a base64 secret issues it, answered once in ' +
          'view.smimeKemIssued', JSON.stringify(second.errors || ''));
  t.equal(self.view(caller).smimeKemIssued, undefined,
          'E3. the page read afterwards does not carry it again');
  log.debug("Leaving checkPortalAct().");
}

async function run(t) {
  log.debug("Entering run().");
  if (!stsCrypto.smimeKemAvailable()) {
    t.check(true, '(ML-KEM cannot be encapsulated on this runtime; ' +
            'STS-OPENPGP-0036 is what a request gets)');
    log.debug("Leaving run(). No ML-KEM here.");
    return;
  }
  if (!pki.hasRoot()) {
    await pki.start({});
  }
  await pki.ensureScope(realms.currentId());
  ldap.createUser(KEMMY, { invent: false, attributes: { mail: MAIL } });
  const pair = nodeCrypto.generateKeyPairSync('ml-kem-768');
  const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  try {
    checkKeyReading(t, publicPem);
    await checkWrongSecret(t, publicPem);
    await checkIssued(t, pair, publicPem);
    await checkPortalAct(t, pair, publicPem);
  } finally {
    keys.forgetForTests();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'smime_kem_issuance',
  describe: '#2220: an ML-KEM S/MIME certificate issued on an RFC 9810 ' +
            'challenge-response proof of possession',
  run: run
};
