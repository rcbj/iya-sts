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
//   2. the codec: PA-PK-AS-REP's [0] written IMPLICIT, as MIT and Windows
//      read it, and the AuthPack's round trip;
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
//      to sell anything for it.
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
  t.equal(rep.subarray(0, 4).toString('hex'), 'a0' +
          rep[1].toString(16).padStart(2, '0') + '8002',
          'PA-PK-AS-REP: dhInfo [0] IMPLICIT, then dhSignedData [0] ' +
          'IMPLICIT OCTET STRING');
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
async function throughTheKdc(t) {
  log.debug("Entering throughTheKdc().");
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
  const alice = await enrol(ALICE);
  t.check(alice.ok, 'a smart-card logon certificate is enrolled for ' +
          ALICE + ' over EST', alice.why);
  if (!alice.ok) {
    log.debug("Leaving throughTheKdc(). No certificate.");
    return;
  }
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
      nonce: 4242 + Math.floor(Math.random() * 1000), etypes: [18, 17] };
    const raw = msgs.encKdcReqBody(body);
    const padata = [];
    let ecdh = null;
    if (!opts.bare) {
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
      kdf: dh.kdf, client: codec.encKrb5PrincipalName(REALM, body.cname),
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

module.exports = {
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
    log.debug("Leaving run().");
  }
};
