// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: kerberos_pkinit.js
//
// ===========================================================================
// PKINIT ON THE KDC (#179, 2026-10-05): A CERTIFICATE AS THE KERBEROS
// PRE-AUTHENTICATION, AND AN ANONYMOUS TICKET AS FAST ARMOR.
//
// What it holds, section by section:
//
//   1. RFC 8636 section 8's KDF vectors through the codec's OtherInfo and
//      `common/crypto.js` section 16 — EXTERNAL answers, so a mistake made
//      the same way on both ends of an exchange is still caught;
//   2. the codec: PA-PK-AS-REP's dhInfo [0] EXPLICIT, as RFC 4556's module
//      says and MIT's client reads, and the AuthPack's round trip;
//   3. `spnego_authn.ts` turning `pkinit` into `swk` and `pkinit-hardware`
//      (with hw-authent) into `hwk` — never `pwd`, and `acr "1"`;
//   4. real AS-REQs through `handleMessage()` with a client written here: a
//      smart-card logon certificate enrolled on a person's entry over EST, a
//      freshness token, ECDH, RFC 8636's KDF — the reply's signature, the KDC
//      certificate's EKU and id-pkinit-san, the reply key, the indicators,
//      hw-authent and AD-INITIAL-VERIFIED-CAS in the TGT — and the refusals:
//      no freshness token, another person's certificate, a replayed
//      AuthPack, group-2-sized MODP, no KDF, a revoked certificate, RSA key
//      transport;
//   5. anonymous PKINIT: the unsigned AuthPack, the anonymous TGT, the KDC's
//      contribution to its session key (PA-PKINIT-KX), and the TGS refusing
//      to sell anything for it;
//   6. in a PRODUCT-MODE CHILD: a person who must hold a second factor is
//      refused on the password alone and admitted by certificate, and a
//      person with no Kerberos keys at all is admitted by certificate and
//      told to sign in once when they bring a password.
//
// WHY IN PROCESS (tests/CLAUDE.md's first question): the vectors need chosen
// inputs, and what the KDC wrote INTO a TGT is sealed under the krbtgt key,
// which only the inside holds. The protocol half — MIT's `kinit -X` and
// `kinit -n` over TCP 88 — is `tests/vendored/sts_kerberos_pkinit.js`.
// Every key pair here is generated at run time; none is in the repository.
// ===========================================================================

const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'kerberos_pkinit',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');

// The KRB5PrincipalName of RFC 8636 section 8's vectors, and the vectors.
const VECTOR_AS_REQ = Buffer.from('aaaaaaaaaaaaaaaaaaaa', 'hex');
const VECTOR_PK_AS_REP = Buffer.from('bbbbbbbbbbbbbbbbbb', 'hex');
const VECTORS = [
  { kdf: '1.3.6.1.5.2.3.6.1', etype: 18,
    key: 'e6ab38c9413e035bb079201ed0b6b73d8d49a814a737c04ee6649614206f73ad' },
  { kdf: '1.3.6.1.5.2.3.6.2', etype: 18,
    key: '77ef4e48c420ae3fec75109d7981697eed5d295c90c62564f7bfd101fa9bc1d5' }
];

// ---------------------------------------------------------------------------
// 1. THE KDF, AGAINST RFC 8636 SECTION 8.
// ---------------------------------------------------------------------------
function kdfMatchesTheVectors(t) {
  log.debug("Entering kdfMatchesTheVectors().");
  t.log.info('=== 1. RFC 8636 section 8: the KDF vectors ===');
  const cryptoLib = require('../common/crypto');
  const codec = require('../kerberos/krb5_pkinit_codec');
  // The vectors' names are strings MIT's parser reads, so both are
  // NT-PRINCIPAL (1) — the one reading that reproduces them.
  const client = codec.encKrb5PrincipalName('SU.SE',
                                            { type: 1, name: ['lha'] });
  const server = codec.encKrb5PrincipalName('SU.SE',
    { type: 1, name: ['krbtgt', 'SU.SE'] });
  VECTORS.forEach(function (v) {
    const otherInfo = codec.encOtherInfo({ kdf: v.kdf, client: client,
      server: server, etype: v.etype, asReq: VECTOR_AS_REQ,
      pkAsRep: VECTOR_PK_AS_REP });
    const key = cryptoLib.pkinitKdf(v.kdf, Buffer.alloc(256), otherInfo,
                                    v.etype);
    t.equal(Buffer.from(key.key).toString('hex'), v.key,
            'RFC 8636 section 8: ' + v.kdf + ', enctype ' + v.etype);
  });
  const legacy = cryptoLib.pkinitOctetString2Key(18, Buffer.alloc(256, 1));
  const expected = Buffer.concat([
    nodeCrypto.createHash('sha1').update(Buffer.from([0]))
      .update(Buffer.alloc(256, 1)).digest(),
    nodeCrypto.createHash('sha1').update(Buffer.from([1]))
      .update(Buffer.alloc(256, 1)).digest()]).subarray(0, 32);
  t.equal(Buffer.from(legacy.key).toString('hex'), expected.toString('hex'),
          'RFC 4556 section 3.2.3.1: octetstring2key is SHA-1 of a counter ' +
          'octet and the secret, truncated');
  log.debug("Leaving kdfMatchesTheVectors().");
}

// ---------------------------------------------------------------------------
// 2. THE CODEC.
// ---------------------------------------------------------------------------
function theCodec(t) {
  log.debug("Entering theCodec().");
  t.log.info('=== 2. the PKINIT codec ===');
  const codec = require('../kerberos/krb5_pkinit_codec');
  const rep = Buffer.from(codec.encPaPkAsRep({
    dhSignedData: Buffer.from('0102', 'hex'), kdf: '1.3.6.1.5.2.3.6.2' }));
  t.equal(rep.subarray(0, 6).toString('hex'), 'a0' +
          rep[1].toString(16).padStart(2, '0') + '30' +
          rep[3].toString(16).padStart(2, '0') + '8002',
          'PA-PK-AS-REP: dhInfo [0] EXPLICIT round DHRepInfo\'s SEQUENCE, ' +
          'then dhSignedData [0] IMPLICIT OCTET STRING — what MIT reads');
  const back = codec.readPaPkAsRep(new Uint8Array(rep));
  t.equal(back.kdf, '1.3.6.1.5.2.3.6.2', 'the KDF reads back');
  const pack = codec.readAuthPack(codec.encAuthPack({
    cusec: 5, ctime: new Date('2026-10-05T00:00:00Z'), nonce: -12345,
    paChecksum: Buffer.alloc(20, 7), freshnessToken: Buffer.from('tok'),
    supportedKdfs: ['1.3.6.1.5.2.3.6.2', '1.3.6.1.5.2.3.6.3'] }));
  t.check(pack.nonce === -12345 && pack.cusec === 5 &&
          Buffer.from(pack.freshnessToken).toString() === 'tok' &&
          pack.supportedKdfs.join(',') ===
            '1.3.6.1.5.2.3.6.2,1.3.6.1.5.2.3.6.3',
          'an AuthPack round-trips, a negative (signed 32-bit) nonce as MIT ' +
          'sends one included', JSON.stringify(pack));
  log.debug("Leaving theCodec().");
}

// ---------------------------------------------------------------------------
// 3. SPNEGO'S READING OF THE INDICATORS.
// ---------------------------------------------------------------------------
function spnegoReadsPkinit(t) {
  log.debug("Entering spnegoReadsPkinit().");
  t.log.info('=== 3. what a PKINIT ticket claims at /authn/spnego ===');
  const spnego = require('../kerberos/spnego_authn');
  const factorsFor = spnego.factorsFor;
  const soft = factorsFor(['initial', 'pre-authent'], ['pkinit']);
  t.check(soft.amr.join(',') === 'swk' && soft.acr === '1',
          'pkinit: amr ["swk"], acr "1" — no password was proven',
          JSON.stringify(soft));
  const hard = factorsFor(['initial', 'pre-authent', 'hw-authent'],
                          ['pkinit', 'pkinit-hardware']);
  t.check(hard.amr.join(',') === 'hwk' && hard.acr === '1',
          'pkinit-hardware with hw-authent: amr ["hwk"], acr "1"',
          JSON.stringify(hard));
  const foreign = factorsFor(['pre-authent'], ['pkinit'], false);
  t.check(foreign.amr.join(',') === 'pwd',
          'a foreign realm\'s indicator counts for nothing',
          JSON.stringify(foreign));
  log.debug("Leaving spnegoReadsPkinit().");
}

// ---------------------------------------------------------------------------
// 4 and 5. AS-REQs THROUGH THE KDC, WITH A CLIENT WRITTEN HERE.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE CLIENT, written here: an EST enrolment for a person, and an AS-REQ with
// PA-PK-AS-REQ (or, with `o.password`, PA-ENC-TIMESTAMP) whose reply it
// opens itself — the Diffie-Hellman, RFC 8636's KDF, the enc-part — and
// whose TGT it opens with the krbtgt key to read what the KDC wrote in it.
// One copy, for the development run here and the product child below.
// ---------------------------------------------------------------------------
function makeClient() {
  log.debug("Entering makeClient().");
  const pki = require('../common/pki');
  const realms = require('../common/realms');
  const cryptoLib = require('../common/crypto');
  const keyMaterial = require('../common/vendored/key_material');
  const ldap = require('../ldap/ldap_server');
  const core = require('../common/cert_enrollment');
  require('../kerberos/krb5_person_keys');
  const principals = require('../kerberos/krb5_principals.js');
  const kdc = require('../kerberos/krb5_kdc.js');
  const msgs = require('../kerberos/krb5_messages.js');
  const kcrypto = require('../kerberos/krb5_crypto.js');
  const asn1 = require('../kerberos/krb5_asn1.js');
  const codec = require('../kerberos/krb5_pkinit_codec');
  const REALM = principals.REALM;
  const enrol = async function (who) {
    log.debug("Entering enrol().");
    const pair = await keyMaterial.generateKeyPair('ec-p256');
    const issued = await core.issue({
      family: 'est', profile: 'smartcard-logon',
      principal: { kind: 'person', id: who, admin: false, hasEntry: true,
                   via: 'test' },
      target: { kind: 'person', id: who }, publicKeyPem: pair.publicPem,
      requested: {}, via: 'test'
    });
    log.debug("Leaving enrol().");
    return { ok: !!issued.ok, why: JSON.stringify(issued.errors || ''),
             pair: pair, record: issued.record };
  };
  const derOf = function (pem) {
    log.debug("Entering derOf().");
    log.debug("Leaving derOf().");
    return Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
                                  .replace(/\s+/g, ''), 'base64');
  };

  // THE CLIENT. `o` chooses what it sends.
  const asReq = async function (who, cert, o) {
    log.debug("Entering asReq().");
    const opts = o || {};
    const anonymous = !!opts.anonymous;
    const body = {
      kdcOptions: anonymous ? [msgs.KDC_OPTION.REQUEST_ANONYMOUS] : [],
      cname: anonymous ? { type: 11, name: ['WELLKNOWN', 'ANONYMOUS'] }
                       : { type: 1, name: [who] },
      realm: REALM, sname: { type: 2, name: ['krbtgt', REALM] },
      till: new Date(Date.now() + 3600000),
      nonce: 4242 + nodeCrypto.randomInt(1000), etypes: [18, 17] };
    const raw = msgs.encKdcReqBody(body);
    const padata = [];
    let ecdh = null;
    let passwordKey = null;
    if (opts.password) {
      passwordKey = await kcrypto.etypeById(18).stringToKey(opts.password,
        Buffer.from(REALM + who, 'utf8'), null);
      const now = new Date();
      padata.push({ type: msgs.PA_TYPE.ENC_TIMESTAMP,
        value: msgs.encEncryptedData({ etype: 18,
          cipher: await kcrypto.etypeById(18).encrypt(passwordKey,
            kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP,
            msgs.encPaEncTsEnc(now, now.getMilliseconds() * 1000)) }) });
    } else if (!opts.bare) {
      const curve = opts.dh === 'modp2' ? null : 'prime256v1';
      let spki;
      if (curve) {
        ecdh = nodeCrypto.generateKeyPairSync('ec', { namedCurve: curve });
        spki = ecdh.publicKey.export({ type: 'spki', format: 'der' });
      } else {
        // A 1024-bit MODP group (Oakley group 2's size): refused.
        const dh = nodeCrypto.getDiffieHellman('modp2');
        dh.generateKeys();
        const intDer = function (b) {
          const v = (b[0] & 0x80) ? Buffer.concat([Buffer.from([0]), b]) : b;
          return asn1.tlv(0x02, new Uint8Array(v));
        };
        spki = Buffer.from(asn1.encSequence([
          asn1.encSequence([codec.encOid('1.2.840.10046.2.1'),
                            asn1.encSequence([intDer(dh.getPrime()),
                                              intDer(dh.getGenerator()),
                                              intDer(Buffer.from([1]))])]),
          codec.encBitString(intDer(dh.getPublicKey()))]));
      }
      const now = new Date();
      const pack = codec.encAuthPack({
        cusec: (now.getMilliseconds() * 1000) % 1000000, ctime: now,
        nonce: 123456789,
        paChecksum: nodeCrypto.createHash('sha1').update(raw).digest(),
        freshnessToken: opts.token || null,
        clientPublicValue: opts.noDh ? null : new Uint8Array(spki),
        supportedKdfs: opts.noKdf ? null : ['1.3.6.1.5.2.3.6.2']
      });
      const signed = cryptoLib.pkinitSignedData(anonymous
        ? { contentType: cryptoLib.PKINIT_OID.authData, content: pack }
        : { contentType: cryptoLib.PKINIT_OID.authData, content: pack,
            signerCertDer: derOf(cert.record.certificatePem),
            chainDers: [], privateKey: cert.pair.privatePem });
      padata.push({ type: codec.PA.PK_AS_REQ,
                    value: codec.encPaPkAsReq({ signedAuthPack: signed }) });
    }
    padata.push({ type: codec.PA.AS_FRESHNESS, value: new Uint8Array(0) });
    const bytes = opts.resend || msgs.encKdcReq({
      msgType: msgs.MSG_TYPE.AS_REQ, padata: padata, reqBody: { raw: raw } });
    if (opts.keep) {
      opts.keep.bytes = bytes;
    }
    const reply = await kdc.handleMessage(bytes);
    if (msgs.identify(reply).applicationNumber ===
        msgs.APPLICATION.KRB_ERROR) {
      const e = msgs.readKrbError(reply);
      const token = (e.eDataPaData || []).filter(function (p) {
        return p.type === codec.PA.AS_FRESHNESS;
      })[0];
      log.debug("Leaving asReq(). KRB-ERROR " + e.errorCode);
      return { ok: false, code: e.errorCode, eText: e.eText,
               offered: (e.eDataPaData || []).map(function (p) {
                 return p.type;
               }),
               token: token ? token.value : null };
    }
    const rep = msgs.readKdcRep(reply);
    if (passwordKey) {
      const plain = msgs.readEncKdcRepPart(await kcrypto.etypeById(18)
        .decrypt(passwordKey, kcrypto.KEY_USAGE.AS_REP_ENCPART,
                 rep.encPart.cipher));
      log.debug("Leaving asReq(). AS-REP to a password.");
      return { ok: true, rep: rep, enc: plain,
               flags: msgs.ticketFlagNames(plain.flags), indicators: [] };
    }
    const pkRep = (rep.padata || []).filter(function (p) {
      return p.type === codec.PA.PK_AS_REP;
    })[0];
    const kx = (rep.padata || []).filter(function (p) {
      return p.type === codec.PA.PKINIT_KX;
    })[0];
    const dh = codec.readPaPkAsRep(pkRep.value);
    const signedReply = cryptoLib.pkinitReadSignedData(dh.dhSignedData);
    const kdcCert = signedReply.certificates[0];
    const verified = cryptoLib.pkinitVerifySignedData(signedReply, kdcCert);
    const keyInfo = codec.readKdcDhKeyInfo(new Uint8Array(
      signedReply.eContent));
    const kdcPub = nodeCrypto.createPublicKey({ key: {
      kty: 'EC', crv: 'P-256',
      x: Buffer.from(keyInfo.subjectPublicKey.subarray(1, 33))
        .toString('base64url'),
      y: Buffer.from(keyInfo.subjectPublicKey.subarray(33, 65))
        .toString('base64url') }, format: 'jwk' });
    const z = nodeCrypto.diffieHellman({ privateKey: ecdh.privateKey,
                                        publicKey: kdcPub });
    const replyKey = cryptoLib.pkinitKdf(dh.kdf, z, codec.encOtherInfo({
      kdf: dh.kdf,
      client: codec.encKrb5PrincipalName(anonymous ? 'WELLKNOWN:ANONYMOUS'
                                                   : REALM, body.cname),
      server: codec.encKrb5PrincipalName(REALM, body.sname), etype: 18,
      asReq: bytes, pkAsRep: pkRep.value }), 18);
    let enc = null;
    try {
      enc = msgs.readEncKdcRepPart(await kcrypto.etypeById(18).decrypt(
        replyKey.key, kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));
    } catch (e) {
      log.debug("Caught in asReq(): " + ((e && e.message) || e));
      enc = null;
    }
    // What the KDC wrote INTO the TGT, opened with the krbtgt key.
    const krbtgt = principals.find(['krbtgt', REALM], REALM);
    const tgtKey = await principals.longTermKey(krbtgt,
                                                rep.ticket.encPart.etype);
    const part = msgs.readEncTicketPart(await kcrypto.etypeById(
      rep.ticket.encPart.etype).decrypt(tgtKey,
        kcrypto.KEY_USAGE.KDC_REP_TICKET, rep.ticket.encPart.cipher));
    const carried = await principals.preauthProvider().ticketIndicators(
      part.authorizationData || [],
      { etype: rep.ticket.encPart.etype, key: tgtKey });
    const verifiedCas = (part.authorizationData || []).some(function (ad) {
      if (ad.type !== 1) {
        return false;
      }
      return msgs.readAuthorizationData(asn1.readTlv(ad.data, 0))
        .some(function (one) { return one.type === 9; });
    });
    let kxOk = null;
    if (kx && enc) {
      const contribution = msgs.readEncryptionKey(asn1.readTlv(
        await kcrypto.etypeById(replyKey.etype).decrypt(replyKey.key, 44,
          msgs.readEncryptedData(asn1.readTlv(kx.value, 0)).cipher), 0));
      const combined = cryptoLib.krbFxCf2(contribution, replyKey, 'PKINIT',
                                          'KEYEXCHANGE');
      kxOk = Buffer.from(combined.key).equals(Buffer.from(enc.key.key));
    }
    log.debug("Leaving asReq(). AS-REP.");
    return { ok: !!enc, rep: rep, enc: enc, signatureOk: verified.ok,
             kdcCert: kdcCert, nonceOk: keyInfo.nonce === 123456789,
             flags: enc ? msgs.ticketFlagNames(enc.flags) : [],
             indicators: carried.indicators, verifiedCas: verifiedCas,
             kxOk: kxOk, crealm: rep.crealm, sessionKey: enc && enc.key };
  };

  log.debug("Leaving makeClient().");
  return { pki: pki, realms: realms, ldap: ldap, core: core,
           principals: principals, kdc: kdc, msgs: msgs, kcrypto: kcrypto,
           asn1: asn1, codec: codec, enrol: enrol, asReq: asReq,
           REALM: REALM };
}

async function throughTheKdc(t) {
  log.debug("Entering throughTheKdc().");
  const c = makeClient();
  const { pki, realms, ldap, core, principals, kdc, msgs, kcrypto, asn1,
          codec, enrol, asReq } = c;
  if (!pki.hasRoot()) {
    await pki.start({});
  }
  await pki.ensureScope(realms.currentId());
  t.check(!!principals.pkinitProvider(), 'the key source carries the PKINIT ' +
          'provider');
  if (!principals.pkinitProvider()) {
    log.debug("Leaving throughTheKdc(). No provider.");
    return;
  }
  const REALM = principals.REALM;
  const ALICE = 'pkalice' + RUN;
  const BOB = 'pkbob' + RUN;
  [ALICE, BOB].forEach(function (who) {
    ldap.createUser(who, { invent: false, attributes: {
      mail: who + '@example.com' } });
  });
  const alice = await enrol(ALICE);
  t.check(alice.ok, 'a smart-card logon certificate is enrolled for ' +
          ALICE + ' over EST', alice.why);
  if (!alice.ok) {
    log.debug("Leaving throughTheKdc(). No certificate.");
    return;
  }
  t.log.info('=== 4. PKINIT through the KDC ===');
  const first = await asReq(ALICE, alice, { bare: true });
  t.check(!first.ok && first.code === 25 &&
          first.offered.indexOf(codec.PA.PK_AS_REQ) !== -1 &&
          first.offered.indexOf(codec.PA.PKINIT_KX) !== -1 && !!first.token,
          'KDC_ERR_PREAUTH_REQUIRED offers PA-PK-AS-REQ, PA-PKINIT-KX and a ' +
          'freshness token', JSON.stringify(first));
  const noToken = await asReq(ALICE, alice, {});
  t.check(!noToken.ok && noToken.code === 24 && !!noToken.token,
          'without the freshness token: KDC_ERR_PREAUTH_FAILED, with a ' +
          'fresh token in the METHOD-DATA (RFC 8070 section 2.4)',
          JSON.stringify(noToken));
  const keep = {};
  const good = await asReq(ALICE, alice, { token: first.token, keep: keep });
  t.check(good.ok, 'a smart-card logon certificate on the entry gets a TGT',
          JSON.stringify(good.code || good.eText || ''));
  if (good.ok) {
    t.check(good.signatureOk && good.nonceOk, 'the KDCDHKeyInfo is signed ' +
            'with the KDC\'s certificate and echoes the nonce');
    const facts = pki.pkinitCertificateFacts(good.kdcCert);
    const san = codec.readKrb5PrincipalName(new Uint8Array(
      facts.pkinitSans[0] || []));
    t.check(facts.ekus.indexOf('1.3.6.1.5.2.3.5') !== -1 &&
            san.name.name.join('/') === 'krbtgt/' + REALM &&
            san.realm === REALM,
            'the KDC certificate carries id-pkinit-KPKdc and an ' +
            'id-pkinit-san of krbtgt/' + REALM, JSON.stringify(facts.ekus));
    t.check(good.indicators.indexOf('pkinit') !== -1 &&
            good.indicators.indexOf('pkinit-hardware') !== -1 &&
            good.flags.indexOf('hw-authent') !== -1,
            'a smart-card logon certificate over a client key: indicators ' +
            'pkinit and pkinit-hardware, and hw-authent',
            JSON.stringify([good.indicators, good.flags]));
    t.check(good.verifiedCas, 'the TGT carries AD-INITIAL-VERIFIED-CAS');
    t.check(good.kxOk === null, 'a named client gets no PA-PKINIT-KX');
    t.check(new Date(good.enc.endtime).getTime() <=
            new Date(alice.record.notAfter).getTime(),
            'the ticket ends no later than the certificate');
  }
  const replay = await asReq(ALICE, alice, { resend: keep.bytes });
  t.check(!replay.ok && replay.code === 34, 'the same signed AuthPack again ' +
          'is KRB_AP_ERR_REPEAT', JSON.stringify(replay));
  const asBob = await asReq(BOB, alice, { token: first.token });
  t.check(!asBob.ok && asBob.code === 75, ALICE + '\'s certificate for ' +
          BOB + ' is KDC_ERR_CLIENT_NAME_MISMATCH', JSON.stringify(asBob));
  const weak = await asReq(ALICE, alice, { token: first.token,
                                           dh: 'modp2' });
  t.check(!weak.ok && weak.code === 65, 'a 1024-bit MODP group is ' +
          'KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED', JSON.stringify(weak));
  const noKdf = await asReq(ALICE, alice, { token: first.token,
                                            noKdf: true });
  t.check(!noKdf.ok && noKdf.code === 100, 'no RFC 8636 KDF, with ' +
          'krb5.pkinitLegacyKdf off, is KDC_ERR_NO_ACCEPTABLE_KDF',
          JSON.stringify(noKdf));
  const noDh = await asReq(ALICE, alice, { token: first.token, noDh: true });
  t.check(!noDh.ok && noDh.code === 81, 'no clientPublicValue (RSA key ' +
          'transport) is KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED',
          JSON.stringify(noDh));
  const revoked = await core.revokeEnrolled(alice.record.serialHex,
                                            'keyCompromise', 'test');
  t.check(revoked && revoked.ok !== false, 'the certificate is revoked');
  const afterRevoke = await asReq(ALICE, alice, { token: first.token });
  t.check(!afterRevoke.ok && afterRevoke.code === 72, 'a revoked ' +
          'certificate is KDC_ERR_REVOKED_CERTIFICATE',
          JSON.stringify(afterRevoke));

  t.log.info('=== 5. anonymous PKINIT, as FAST armor ===');
  const anon = await asReq(null, null, { anonymous: true,
                                         token: first.token });
  t.check(anon.ok && anon.crealm === 'WELLKNOWN:ANONYMOUS' &&
          anon.flags.indexOf('anonymous') !== -1,
          'anonymous PKINIT issues a TGT in WELLKNOWN:ANONYMOUS with the ' +
          'anonymous flag', JSON.stringify(anon.code || anon.flags || ''));
  if (anon.ok) {
    t.check(anon.kxOk === true, 'its session key is KRB-FX-CF2 of the ' +
            'PA-PKINIT-KX contribution and the reply key (RFC 8062 ' +
            'section 7)');
    t.check(!anon.indicators.length && !anon.verifiedCas,
            'it carries no indicator and no AD-INITIAL-VERIFIED-CAS');
    // A TGS-REQ with it: refused, it only armors.
    const session = anon.sessionKey;
    const sbody = { kdcOptions: [], realm: REALM,
                    sname: { type: 2, name: ['krbtgt', REALM] },
                    till: new Date(Date.now() + 3600000), nonce: 99,
                    etypes: [18] };
    const sraw = msgs.encKdcReqBody(sbody);
    const profile = kcrypto.etypeById(session.etype);
    const auth = msgs.encAuthenticator({ crealm: anon.crealm,
      cname: anon.rep.cname, cusec: 1, ctime: new Date(),
      cksum: { type: profile.checksumType,
               checksum: await profile.checksum(session.key,
                 kcrypto.KEY_USAGE.TGS_REQ_AUTH_CKSUM, sraw) } });
    const apReq = msgs.encApReq({ apOptions: [], ticket: anon.rep.ticket,
      authenticator: { etype: session.etype,
        cipher: await profile.encrypt(session.key,
          kcrypto.KEY_USAGE.TGS_REQ_AUTH, auth) } });
    const tgsBytes = msgs.encKdcReq({ msgType: msgs.MSG_TYPE.TGS_REQ,
      padata: [{ type: msgs.PA_TYPE.TGS_REQ, value: apReq }],
      reqBody: { raw: sraw } });
    const tgsReply = msgs.readKrbError(await kdc.handleMessage(tgsBytes));
    t.check(tgsReply.errorCode === 12, 'a TGS-REQ presenting the anonymous ' +
            'TGT is KDC_ERR_POLICY: it is FAST armor and buys nothing',
            JSON.stringify(tgsReply.eText));
  }
  log.debug("Leaving throughTheKdc().");
}

// ---------------------------------------------------------------------------
// 6. PRODUCT MODE, IN A CHILD PROCESS — where PKINIT is for. A person who must
// hold a second factor is refused a ticket on the password alone (#173) and
// gets one with a certificate; a person with NO Kerberos keys (never signed
// in with a password) gets one with a certificate, and with a password is
// told to sign in once, as before. The child requires this file and calls
// the function below: the product KDC's principal database is built at require
// time in the mode the process starts in, as `kerberos_fast_otp.js` explains.
// ---------------------------------------------------------------------------
async function productScenario() {
  log.debug("Entering productScenario().");
  const out = {};
  const keystore = require('../common/keystore');
  keystore.reset();
  keystore.setStore({
    loadKeys: function () { return Promise.resolve([]); },
    saveKeys: function () { return Promise.resolve(); },
    deleteKeys: function () { return Promise.resolve(); }
  });
  await keystore.start();
  const c = makeClient();
  if (!c.pki.hasRoot()) {
    await c.pki.start({});
  }
  await c.pki.ensureScope(c.realms.currentId());
  const credentials = require('../common/credentials');
  const personKeys = require('../kerberos/krb5_person_keys');
  out.product = require('../common/mode').isProduct();
  const P = 'pkmfa' + RUN;
  const K = 'pknokeys' + RUN;
  const PW = 'Correct-Horse-Battery-9!';
  [P, K].forEach(function (who) {
    c.ldap.createUser(who, { invent: false, attributes: {
      mail: who + '@example.com' } });
  });
  credentials.setPassword(P, PW);
  out.required = credentials.setMfaRequired(P, true).ok;
  await personKeys.idle();
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return { ok: r.ok, code: r.code, eText: r.eText,
             indicators: r.indicators, flags: r.flags };
  };
  const certP = await c.enrol(P);
  const certK = await c.enrol(K);
  out.enrolled = certP.ok && certK.ok;
  const first = await c.asReq(P, certP, { bare: true });
  out.passwordAlone = brief(await c.asReq(P, null, { password: PW }));
  out.pkinitMfa = brief(await c.asReq(P, certP, { token: first.token }));
  out.pkinitKeyless = brief(await c.asReq(K, certK, { token: first.token }));
  out.passwordKeyless = brief(await c.asReq(K, null,
                                            { password: 'Any-Password-1!' }));
  log.debug("Leaving productScenario().");
  return out;
}

function inAProductChild(t) {
  log.debug("Entering inAProductChild().");
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const childProcess = require('child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krb5-pkinit-'));
  // A key-encryption key made HERE, at run time, and removed with the
  // directory — no key material lives in the repository.
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  const outFile = path.join(dir, 'report.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const script = 'delete process.env.CONFIG_FILE;' +
    'require(' + JSON.stringify(__filename) + ').productScenario()' +
    '.then(function (r) { require("fs").writeFileSync(process.env.KP_OUT, ' +
    'JSON.stringify(r)); process.exit(0); }).catch(function (e) { ' +
    'require("fs").writeFileSync(process.env.KP_OUT, JSON.stringify({ ' +
    'crashed: e.stack || e.message })); process.exit(0); });';
  const run = childProcess.spawnSync(process.execPath, ['-e', script], {
    env: Object.assign(clean, {
      LOG_LEVEL: 'fatal', KP_OUT: outFile, STS_MODE: 'product',
      KRB5_KRBTGT_PASSWORD: 'pkinit-' +
                            nodeCrypto.randomBytes(12).toString('hex'),
      STS_KEYS_SOURCE: 'persisted', STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: kekFile
    }),
    encoding: 'utf8', timeout: 240000
  });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAProductChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. The check below says so.
    report = null;
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    // Best effort: a temporary directory left behind is litter.
    log.debug("Caught in inAProductChild(): " + ((e && e.message) || e));
  }
  t.check(report !== null && !report.crashed, 'the product-mode child ran to ' +
          'the end', 'exit ' + run.status + ' ' + (report && report.crashed) +
          ' ' + String(run.stderr || '').slice(0, 800));
  log.debug("Leaving inAProductChild().");
  return report && !report.crashed ? report : null;
}

function inProduct(t) {
  log.debug("Entering inProduct().");
  t.log.info('=== 6. product mode: a second factor, and no keys at all ===');
  const r = inAProductChild(t);
  if (!r) {
    log.debug("Leaving inProduct(). No report.");
    return;
  }
  t.check(r.product && r.required && r.enrolled, 'the child is in product ' +
          'mode, the person must hold a second factor, both certificates are ' +
          'enrolled', JSON.stringify(r));
  t.check(!r.passwordAlone.ok && r.passwordAlone.code === 12,
          'the password alone, for a person who must hold a second factor, ' +
          'is KDC_ERR_POLICY (#173)', JSON.stringify(r.passwordAlone));
  t.check(r.pkinitMfa.ok &&
          (r.pkinitMfa.indicators || []).indexOf('pkinit') !== -1,
          'the same person with a certificate gets a TGT carrying pkinit — ' +
          'what #179 is for', JSON.stringify(r.pkinitMfa));
  t.check(r.pkinitKeyless.ok, 'a person with NO Kerberos keys gets a TGT ' +
          'with a certificate', JSON.stringify(r.pkinitKeyless));
  t.check(!r.passwordKeyless.ok && r.passwordKeyless.code === 6 &&
          /no Kerberos keys yet/.test(String(r.passwordKeyless.eText)),
          'and a password from them is still refused with the sentence that ' +
          'says to sign in once (STS-KRB-0104), as before PKINIT',
          JSON.stringify(r.passwordKeyless));
  log.debug("Leaving inProduct().");
}

module.exports = {
  productScenario: productScenario,
  name: 'kerberos_pkinit',
  describe: 'PKINIT (RFC 4556, 8070, 8636, 5349): a certificate as the ' +
            'Kerberos pre-authentication, and anonymous PKINIT (RFC 8062) ' +
            'as FAST armor (#179)',
  run: async function (t) {
    log.debug("Entering run().");
    kdfMatchesTheVectors(t);
    theCodec(t);
    spnegoReadsPkinit(t);
    await throughTheKdc(t);
    inProduct(t);
    log.debug("Leaving run().");
  }
};
