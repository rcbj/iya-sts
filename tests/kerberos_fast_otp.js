'use strict';
//
// File: kerberos_fast_otp.js
//
// ===========================================================================
// A PASSWORD ALONE IS NOT A KERBEROS TICKET FOR A TWO-FACTOR ACCOUNT, AND
// FAST WITH OTP PRE-AUTHENTICATION IS HOW ONE IS HAD (#173, 2026-09-22).
//
// What it holds, section by section:
//
//   1. the primitives FAST is built on, against EXTERNAL answers: RFC 3961's
//      n-fold vectors, MIT's `t_prf.c` pseudo-random vectors for the four AES
//      enctypes, and MIT's `t_cf2.expected` for KRB-FX-CF2 over all five —
//      `common/crypto.js` section 9;
//   2. the new wire format (`kerberos/krb5_fast_codec.ts`) against DER
//      written out by hand, and its round trips;
//   3. `spnego_authn.ts` counting the RFC 8129 indicator `otp` as a second
//      factor — and not from a foreign realm's ticket;
//   4. in a PRODUCT-MODE CHILD, real AS-REQs through `handleMessage()`:
//      the refusal DECISION for a person with an authenticator app, one
//      required to have a second factor on their entry, everybody under the
//      realm's authentication policy, and nobody — and that the refusal comes
//      only after the password verified; FAST armor from a host's TGT, the
//      encrypted challenge, the OTP exchange with the password as the PIN,
//      the step the sign-in screen spent refused at the KDC (one once-only
//      counter), a replayed code, the refusals the armor itself can draw, and
//      the `otp` indicator in the TGT, carried by the TGS into a service
//      ticket and read back by the acceptor.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, which is the question tests/CLAUDE.md asks first: the
// vectors need chosen keys; the codec's DER is asserted byte by byte; the
// product-mode KDC's principal database is built at require time in the mode
// the process starts in, so it is a CHILD with `STS_MODE=product`, as in
// `kerberos_person_keys.js`; and what the TGS copies into a service ticket is
// sealed under a key only the inside can hold. The protocol half, over TCP 88
// against a running service, is `tests/vendored/sts_kerberos_fast_otp.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'kerberos_fast_otp',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// 1. THE PRIMITIVES, AGAINST EXTERNAL VECTORS.
// ---------------------------------------------------------------------------
async function primitivesMatchPublishedVectors(t) {
  log.debug("Entering primitivesMatchPublishedVectors().");
  t.log.info('=== 1. n-fold, the Kerberos PRF and KRB-FX-CF2 against ' +
             'published vectors ===');
  const cryptoLib = require('../common/crypto');
  const kcrypto = require('../kerberos/krb5_crypto.js');
  const prim = require('../kerberos/krb5_primitives.js');
  const hex = function (b) {
    log.debug("Entering hex().");
    log.debug("Leaving hex().");
    return Buffer.from(b).toString('hex');
  };
  // RFC 3961 section A.1.
  [['012345', 8, 'be072631276b1955'],
   ['password', 7, '78a07b6caf85fa'],
   ['Rough Consensus, and Running Code', 8, 'bb6ed30870b7f0e0'],
   ['password', 21, '59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e'],
   ['kerberos', 16, '6b65726265726f737b9b5b2b93132b93']]
    .forEach(function (v) {
      t.equal(hex(cryptoLib.krb5Nfold(Buffer.from(v[0]), v[1])), v[2],
              'RFC 3961 A.1: ' + (v[1] * 8) + '-fold("' + v[0] + '")');
    });
  // MIT krb5 1.19 src/lib/crypto/crypto_tests/t_prf.c.
  const prf = [
    [17, 'ae272e7cdec86ac5138cdb196d8e297d', '0161',
     '77b39a37a868920f2a51f9dd150c5717'],
    [17, '67ab1cfef35e4c27ffdeac60385a3e9c', '0162',
     'e06c0dd31ff02091994f2ef5178bfe3d'],
    [18, 'c01f157211f7b77eaaf457c3e156690127ee127d810ba6392e97baa243eb0616',
     '0161', 'b2628c788e2e9c4a9bb4644678c29f2f'],
    [18, '9d520d2d980aa7cb6b693682b62da258b333867951642ce647ae62b1e5e0b5e9',
     '0262', '0d674dd0f9a6806525a4d92e828bd15a'],
    [19, '3705d96080c17728a0e800eab6e0d23c', hex('test'),
     '9d188616f63852fe86915bb840b4a886ff3e6bb0f819b49b893393d393854295'],
    [20, '6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52',
     hex('test'),
     '9801f69a368c2bf675e59521e177d9a07f67efe1cfde8d3c8d6f6a0256e3b17d' +
     'b3c1b62ad1b8553360d17367eb1514d2']
  ];
  prf.forEach(function (v) {
    t.equal(hex(cryptoLib.krb5Prf(v[0], Buffer.from(v[1], 'hex'),
                                  Buffer.from(v[2], 'hex'))), v[3],
            'MIT t_prf: pseudo-random for enctype ' + v[0] + ' over ' + v[2]);
  });
  // MIT krb5 1.19 t_cf2.in / t_cf2.expected: key1 = string-to-key("key1",
  // salt "key1"), key2 likewise, peppers "a" and "b".
  const cf2 = { 17: '97df97e4b798b29eb31ed7280287a92a',
    18: '4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b',
    23: '24d7f6b6bae4e5c00d2082c5ebab3672',
    19: 'edd02a39d2dbde31611c16e610be062c',
    20: '67f6ea530aea85a37dcbb23349ea52dcc61ca8493ff557252327fd8304341584' };
  for (const etype of [17, 18, 23, 19, 20]) {
    const profile = kcrypto.etypeById(etype);
    const k1 = await profile.stringToKey('key1', prim.utf8('key1'), null);
    const k2 = await profile.stringToKey('key2', prim.utf8('key2'), null);
    const out = cryptoLib.krbFxCf2({ etype: etype, key: k1 },
                                   { etype: etype, key: k2 }, 'a', 'b');
    t.check(hex(out.key) === cf2[etype] && out.etype === etype,
            'MIT t_cf2: KRB-FX-CF2 for enctype ' + etype + ', with the ' +
            'first key\'s enctype', hex(out.key));
  }
  let threw = false;
  try {
    cryptoLib.krb5Prf(16, Buffer.alloc(24), Buffer.from('x'));
  } catch (e) {
    log.debug("Caught in primitivesMatchPublishedVectors(): " +
              ((e && e.message) || e));
    threw = true;
  }
  t.check(threw, 'an enctype with no PRF here (des3) is refused by name, ' +
                 'not guessed at');
  log.debug("Leaving primitivesMatchPublishedVectors().");
}

// ---------------------------------------------------------------------------
// 2. THE WIRE FORMAT.
// ---------------------------------------------------------------------------
function theCodecIsTheSpecifications(t) {
  log.debug("Entering theCodecIsTheSpecifications().");
  t.log.info('=== 2. the FAST, OTP and CAMMAC codec ===');
  const codec = require('../kerberos/krb5_fast_codec');
  const hex = function (b) {
    log.debug("Entering hex().");
    log.debug("Leaving hex().");
    return Buffer.from(b).toString('hex');
  };
  // AD-AUTHENTICATION-INDICATOR ::= SEQUENCE OF UTF8String — "otp" by hand.
  t.equal(hex(codec.encIndicators(['otp'])), '30050c036f7470',
          'RFC 8129: ["otp"] is SEQUENCE { UTF8String "otp" }');
  t.equal(JSON.stringify(codec.readIndicators(Buffer.from(
    '300a0c036f74700c03707764', 'hex'))), '["otp","pwd"]',
          'and a hand-written two-element indicator decodes');
  // PA-OTP-ENC-REQUEST ::= SEQUENCE { nonce [0] OCTET STRING } — and RFC
  // 6560's module is IMPLICIT TAGS, so [0] REPLACES the OCTET STRING tag:
  // 80, not a0 04. MIT's kinit refused the explicit form ("ASN.1 structure
  // is missing a required field"), which is why this is asserted byte by
  // byte.
  t.equal(hex(codec.encOtpEncRequest(Buffer.from('0102', 'hex'))),
          '300480020102', 'RFC 6560: PA-OTP-ENC-REQUEST by hand, IMPLICIT ' +
          '[0]');
  t.check(hex(codec.readOtpEncData(Buffer.from('300480020102', 'hex'))
    .nonce) === '0102', 'the encData reader takes a nonce for a nonce');
  const ts = codec.readOtpEncData(Buffer.from(
    '3013a011180f32303236303932323030303030305a', 'hex'));
  t.check(ts.timestamp instanceof Date &&
          ts.timestamp.toISOString() === '2026-09-22T00:00:00.000Z',
          'and a timestamp for a PA-ENC-TS-ENC (two-pass mode)',
          JSON.stringify(ts));
  // The OTP challenge: flags collect-pin (3) and separate-pin-required (6)
  // are the bits 0x12 in the first octet, under an IMPLICIT [0] — `80 05`,
  // the BIT STRING's own content with its tag replaced.
  const chl = codec.encOtpChallenge({
    nonce: Buffer.from('aa', 'hex'), service: 'EXAMPLE.COM',
    tokenInfo: [{ flags: [codec.OTP_FLAG.COLLECT_PIN,
                          codec.OTP_FLAG.SEPARATE_PIN_REQUIRED],
                  format: codec.OTP_FORMAT.DECIMAL }] });
  t.check(hex(chl).indexOf('300a' + '80050012000000' + '8401' + '00') !==
          -1,
          'the token info is SEQUENCE { [0] IMPLICIT OTPFlags with ' +
          'collect-pin and separate-pin-required as bits 3 and 6, [4] ' +
          'IMPLICIT decimal }', hex(chl));
  t.check(hex(chl).indexOf('8001aa') === 4 &&
          hex(chl).indexOf('810b4558414d504c452e434f4d') !== -1,
          'and the challenge\'s nonce and service are IMPLICIT [0] OCTET ' +
          'STRING and [1] UTF8String', hex(chl));
  const back = codec.readOtpChallenge(chl);
  t.check(hex(back.nonce) === 'aa' && back.service === 'EXAMPLE.COM' &&
          back.tokenInfo.length === 1 &&
          JSON.stringify(back.tokenInfo[0].flags) === '[3,6]' &&
          back.tokenInfo[0].format === 0,
          'PA-OTP-CHALLENGE round-trips', JSON.stringify(back));
  const req = codec.encOtpRequest({ flags: [], encData: { etype: 18,
    cipher: Buffer.from('0011', 'hex') }, value: '123456', pin: 'pässword' });
  const reqBack = codec.readOtpRequest(req);
  t.check(reqBack.value === '123456' && reqBack.pin === 'pässword' &&
          reqBack.encData.etype === 18 && !reqBack.hashing,
          'PA-OTP-REQUEST round-trips, the PIN as UTF-8',
          JSON.stringify(reqBack));
  // MIT's client zero-fills its request, so it sends `iterationCount [4] 0`
  // beside a plain otp-value: that is not a hashed OTP; a count above zero
  // is.
  const mitShaped = function (count) {
    log.debug("Entering mitShaped().");
    const encData = codec.implicit(2, require('../kerberos/krb5_messages.js')
      .encEncryptedData({ etype: 18, cipher: Buffer.from('00', 'hex') }));
    log.debug("Leaving mitShaped().");
    return codec.implicitSequence([
      codec.implicit(0, require('../kerberos/krb5_asn1.js').encFlags([])),
      encData, Buffer.from('8401' + count, 'hex'),
      codec.iOctets(5, Buffer.from('123456'))]);
  };
  t.check(!codec.readOtpRequest(mitShaped('00')).hashing &&
          codec.readOtpRequest(mitShaped('05')).hashing,
          'iterationCount 0 (what MIT\'s kinit sends) is not a hashed OTP; ' +
          'iterationCount 5 is');
  // PA-FX-FAST-REQUEST and REPLY are CHOICEs whose one alternative is [0].
  const fastReq = codec.encFastRequest({
    armor: { type: 1, value: Buffer.from('6e00', 'hex') },
    reqChecksum: { type: 16, checksum: Buffer.from('01', 'hex') },
    encFastReq: { etype: 18, cipher: Buffer.from('02', 'hex') } });
  t.equal(fastReq[0], 0xa0, 'PA-FX-FAST-REQUEST is armored-data [0]');
  const fastBack = codec.readFastRequest(fastReq);
  t.check(fastBack.armor.type === 1 && fastBack.reqChecksum.type === 16 &&
          fastBack.encFastReq.etype === 18,
          'KrbFastArmoredReq round-trips', JSON.stringify(fastBack));
  let refused = false;
  try {
    codec.readFastRequest(Buffer.from('a1023000', 'hex'));
  } catch (e) {
    log.debug("Caught in theCodecIsTheSpecifications(): " +
              ((e && e.message) || e));
    refused = true;
  }
  t.check(refused, 'a PA-FX-FAST-REQUEST that is not [0] does not decode');
  const response = codec.encFastResponse({
    padata: [{ type: 137, value: Buffer.from('7e00', 'hex') }],
    strengthenKey: { etype: 18, key: Buffer.alloc(32, 7) },
    nonce: 12345 });
  const respBack = codec.readFastResponse(response);
  t.check(respBack.nonce === 12345 && respBack.padata[0].type === 137 &&
          respBack.strengthenKey.etype === 18 && respBack.finished === null,
          'KrbFastResponse round-trips', JSON.stringify(respBack));
  const msgs = require('../kerberos/krb5_messages.js');
  const elements = msgs.encAuthorizationData([{ type: 97,
    data: codec.encIndicators(['otp']) }]);
  const cammac = codec.readCammac(codec.encCammac({
    elementsBytes: elements,
    svcVerifier: { enctype: 18, mac: { type: 16,
                                       checksum: Buffer.alloc(12, 1) } } }));
  t.check(cammac.svcVerifier && cammac.svcVerifier.enctype === 18 &&
          cammac.kdcVerifier === null && cammac.elements[0].type === 97 &&
          hex(cammac.elementsBytes) === hex(elements),
          'AD-CAMMAC round-trips its verifiers', JSON.stringify(cammac));
  log.debug("Leaving theCodecIsTheSpecifications().");
}

// ---------------------------------------------------------------------------
// 3. THE SPNEGO SIGN-IN COUNTS THE INDICATOR.
// ---------------------------------------------------------------------------
function spnegoCountsTheOtpIndicator(t) {
  log.debug("Entering spnegoCountsTheOtpIndicator().");
  t.log.info('=== 3. a ticket carrying "otp" is two factors at ' +
             '/authn/spnego ===');
  const door = require('../kerberos/spnego_authn');
  const two = door.factorsFor(['pre-authent', 'initial'], ['otp'], true);
  t.check(two.amr.join(',') === 'pwd,otp' && two.acr === 'mfa',
          'pre-authent and the RFC 8129 indicator otp: amr ["pwd","otp"], ' +
          'acr "mfa" — what the sign-in screen claims after /authn/totp',
          JSON.stringify(two));
  const one = door.factorsFor(['pre-authent'], [], true);
  t.check(one.amr.join(',') === 'pwd' && one.acr === '1',
          'no indicator: one factor, as before', JSON.stringify(one));
  const foreign = door.factorsFor(['pre-authent'], ['otp'], false);
  t.check(foreign.amr.join(',') === 'pwd' && foreign.acr === '1',
          'an indicator from ANOTHER realm\'s ticket counts for nothing ' +
          '(RFC 8129 section 5)', JSON.stringify(foreign));
  const unknown = door.factorsFor(['pre-authent'], ['hardened'], true);
  t.check(unknown.acr === '1', 'an indicator this service does not know is ' +
                               'not a second factor');
  const mode = require('../common/mode');
  t.check(mode.issuesTicketsOnPasswordAlone() === true,
          'development mode issues tickets on a password alone ' +
          '(mode.issuesTicketsOnPasswordAlone)');
  log.debug("Leaving spnegoCountsTheOtpIndicator().");
}

// ---------------------------------------------------------------------------
// 4. PRODUCT MODE, IN A CHILD PROCESS. Serialised with toString() and run with
// `node -e`: every require by the absolute root the parent hands it, and one
// JSON document back.
// ---------------------------------------------------------------------------
/* eslint-disable no-undef */
async function productChild() {
  const R = process.env.KF_ROOT;
  const out = { steps: {} };
  const keystore = require(R + '/common/keystore');
  keystore.reset();
  keystore.setStore({
    loadKeys: function () { return Promise.resolve([]); },
    saveKeys: function () { return Promise.resolve(); },
    deleteKeys: function () { return Promise.resolve(); }
  });
  await keystore.start();
  const nodeCrypto = require('crypto');
  const config = require(R + '/common/config');
  const mode = require(R + '/common/mode');
  const principals = require(R + '/kerberos/krb5_principals.js');
  const kdc = require(R + '/kerberos/krb5_kdc.js');
  const service = require(R + '/kerberos/krb5_service.js');
  const msgs = require(R + '/kerberos/krb5_messages.js');
  const kcrypto = require(R + '/kerberos/krb5_crypto.js');
  const prim = require(R + '/kerberos/krb5_primitives.js');
  const asn1 = require(R + '/kerberos/krb5_asn1.js');
  const gss = require(R + '/kerberos/krb5_gss.js');
  const directory = require(R + '/ldap/ldap_server');
  const credentials = require(R + '/common/credentials');
  // #64: the realm-wide requirement is the authentication policy's.
  const authnPolicy = require(R + '/common/authn_policy');
  const personKeys = require(R + '/kerberos/krb5_person_keys');
  const cryptoLib = require(R + '/common/crypto');
  const codec = require(R + '/kerberos/krb5_fast_codec');
  const REALM = principals.REALM;
  const DOMAIN = REALM.toLowerCase();
  out.product = mode.isProduct();
  out.passwordAloneIssues = mode.issuesTicketsOnPasswordAlone();
  out.provider = !!principals.preauthProvider();

  // --- the RFC 6238 arithmetic, written here and not taken from the service
  const base32 = function (text) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    String(text).replace(/[\s=]/g, '').toUpperCase().split('')
      .forEach(function (c) {
        bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
      });
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return Buffer.from(bytes);
  };
  const codeAt = function (enrolment, atMs) {
    const counter = Math.floor(atMs / 1000 / enrolment.period);
    const msg = Buffer.alloc(8);
    msg.writeBigUInt64BE(BigInt(counter), 0);
    const alg = String(enrolment.algorithm || 'SHA1').toLowerCase()
      .replace('-', '');
    const mac = nodeCrypto.createHmac(alg, base32(enrolment.secret))
      .update(msg).digest();
    const off = mac[mac.length - 1] & 0x0f;
    const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) |
                (mac[off + 2] << 8) | mac[off + 3];
    return String(bin % Math.pow(10, enrolment.digits))
      .padStart(enrolment.digits, '0');
  };

  // --- an ordinary AS-REQ with PA-ENC-TIMESTAMP ---
  async function asReq(name, password, opts) {
    const o = opts || {};
    const etype = 18;
    const profile = kcrypto.etypeById(etype);
    const key = o.key || await profile.stringToKey(password,
      prim.utf8(REALM + (Array.isArray(name) ? name.join('') : name)), null);
    const padata = [];
    if (!o.bare) {
      const now = new Date();
      padata.push({ type: msgs.PA_TYPE.ENC_TIMESTAMP,
        value: msgs.encEncryptedData({ etype: etype,
          cipher: await profile.encrypt(key,
            kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP,
            msgs.encPaEncTsEnc(now, now.getMilliseconds() * 1000)) }) });
    }
    const target = o.sname || ['krbtgt', REALM];
    const bytes = msgs.encKdcReq({
      msgType: msgs.MSG_TYPE.AS_REQ, padata: padata,
      reqBody: { kdcOptions: [],
                 cname: { type: Array.isArray(name) ? 3 : 1,
                          name: Array.isArray(name) ? name : [name] },
                 realm: REALM,
                 sname: { type: target[0] === 'krbtgt' ? 2 : 3,
                          name: target },
                 till: new Date(Date.now() + 3600000), nonce: 777,
                 etypes: [etype] } });
    const reply = await kdc.handleMessage(bytes);
    if (msgs.identify(reply).applicationNumber ===
        msgs.APPLICATION.KRB_ERROR) {
      const e = msgs.readKrbError(reply);
      return { ok: false, code: e.errorCode, eText: e.eText,
               offered: (e.eDataPaData || []).map(function (p) {
                 return p.type;
               }) };
    }
    const rep = msgs.readKdcRep(reply);
    const enc = msgs.readEncKdcRepPart(await profile.decrypt(key,
      kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));
    return { ok: true, rep: rep, enc: enc,
             flags: msgs.ticketFlagNames(enc.flags) };
  }

  // --- a FAST-armored AS-REQ. `build(armorKey)` answers the inner padata. ---
  let armorTgt = null;
  let armorCusec = 1000;
  async function fastReq(name, build, opts) {
    const o = opts || {};
    armorCusec += 1;
    const tgtKey = armorTgt.enc.key;
    const subkey = { etype: 18, key: kcrypto.randomBytes(32) };
    const armorKey = o.resend ? o.resendArmorKey : cryptoLib.krbFxCf2(subkey,
      { etype: tgtKey.etype, key: tgtKey.key }, 'subkeyarmor', 'ticketarmor');
    const armorProfile = kcrypto.etypeById(armorKey.etype);
    const auth = msgs.encAuthenticator({ crealm: REALM,
      cname: armorTgt.rep.cname, cusec: armorCusec, ctime: new Date(),
      subkey: o.noSubkey ? null : subkey });
    const apReq = msgs.encApReq({ apOptions: [], ticket: armorTgt.rep.ticket,
      authenticator: { etype: tgtKey.etype,
        cipher: await kcrypto.etypeById(tgtKey.etype).encrypt(tgtKey.key,
          kcrypto.KEY_USAGE.AP_REQ_AUTH, auth) } });
    const nonce = o.resend ? o.resendNonce : 900000 + armorCusec;
    const body = { kdcOptions: [], cname: { type: 1, name: [name] },
                   realm: REALM, sname: { type: 2, name: ['krbtgt', REALM] },
                   till: new Date(Date.now() + 3600000), nonce: nonce,
                   etypes: [18] };
    const raw = msgs.encKdcReqBody(body);
    const inner = await build(armorKey);
    const fastBytes = codec.encFastReq({ fastOptions: o.fastOptions || [],
                                         padata: inner,
                                         reqBody: { raw: raw } });
    const cksum = await armorProfile.checksum(armorKey.key,
      codec.KEY_USAGE.FAST_REQ_CHKSUM,
      o.otherBody ? msgs.encKdcReqBody(Object.assign({}, body,
                                                     { nonce: 1 })) : raw);
    const pa = codec.encFastRequest({
      armor: { type: 1, value: apReq },
      reqChecksum: { type: armorProfile.checksumType, checksum: cksum },
      encFastReq: { etype: armorKey.etype,
                    cipher: await armorProfile.encrypt(armorKey.key,
                      codec.KEY_USAGE.FAST_ENC, fastBytes) } });
    const bytes = o.resend || msgs.encKdcReq({ msgType: msgs.MSG_TYPE.AS_REQ,
      padata: [{ type: codec.PA.FX_FAST, value: pa }],
      reqBody: { raw: raw } });
    if (o.keep) {
      // The whole request, kept to be sent again byte for byte — a replay.
      o.keep.bytes = bytes;
      o.keep.armorKey = armorKey;
      o.keep.nonce = nonce;
    }
    const reply = await kdc.handleMessage(bytes);
    const openResponse = async function (padata) {
      const fx = (padata || []).filter(function (p) {
        return p.type === codec.PA.FX_FAST;
      })[0];
      if (!fx) {
        return null;
      }
      const sealed = codec.readFastReply(fx.value);
      return codec.readFastResponse(await armorProfile.decrypt(armorKey.key,
        codec.KEY_USAGE.FAST_REP, sealed.cipher));
    };
    if (msgs.identify(reply).applicationNumber ===
        msgs.APPLICATION.KRB_ERROR) {
      const outer = msgs.readKrbError(reply);
      const response = await openResponse(outer.eDataPaData);
      if (!response) {
        return { ok: false, armored: false, code: outer.errorCode,
                 eText: outer.eText };
      }
      const fxError = response.padata.filter(function (p) {
        return p.type === codec.PA.FX_ERROR;
      })[0];
      const e = msgs.readKrbError(fxError.value);
      return { ok: false, armored: true, outerCode: outer.errorCode,
               outerCname: outer.cname ? outer.cname.name.join('/') : null,
               outerCrealm: outer.crealm || null,
               innerCname: e.cname ? e.cname.name.join('/') : null,
               code: e.errorCode, eText: e.eText, nonceOk: response.nonce ===
                                                           nonce,
               innerEData: !!e.eData,
               padata: response.padata, armorKey: armorKey };
    }
    const rep = msgs.readKdcRep(reply);
    const response = await openResponse(rep.padata);
    const finishedOk = !!(response && response.finished &&
      await armorProfile.verifyChecksum(armorKey.key,
        codec.KEY_USAGE.FAST_FINISHED, msgs.encTicket(rep.ticket),
        response.finished.ticketChecksum.checksum));
    const base = o.replyKey ? await o.replyKey(armorKey) : armorKey;
    const replyKey = response && response.strengthenKey
      ? cryptoLib.krbFxCf2(response.strengthenKey, base, 'strengthenkey',
                           'replykey')
      : base;
    let enc = null;
    try {
      enc = msgs.readEncKdcRepPart(await kcrypto.etypeById(replyKey.etype)
        .decrypt(replyKey.key, kcrypto.KEY_USAGE.AS_REP_ENCPART,
                 rep.encPart.cipher));
    } catch (e) {
      return { ok: false, code: -1, eText: 'the AS-REP did not open under ' +
                                           'the strengthened reply key: ' +
                                           e.message };
    }
    return { ok: true, rep: rep, enc: enc, finishedOk: finishedOk,
             nonceOk: response.nonce === nonce && enc.nonce === nonce,
             strengthened: !!response.strengthenKey,
             flags: msgs.ticketFlagNames(enc.flags),
             padata: response.padata, armorKey: armorKey };
  }

  const ltkOf = async function (name, password) {
    return { etype: 18, key: await kcrypto.etypeById(18).stringToKey(
      password, prim.utf8(REALM + name), null) };
  };
  const encChallenge = function (name, password) {
    return async function (armorKey) {
      const ltk = await ltkOf(name, password);
      const challengeKey = cryptoLib.krbFxCf2(armorKey, ltk,
        'clientchallengearmor', 'challengelongterm');
      const now = new Date();
      const cipher = await kcrypto.etypeById(challengeKey.etype).encrypt(
        challengeKey.key, codec.KEY_USAGE.ENC_CHALLENGE_CLIENT,
        msgs.encPaEncTsEnc(now, now.getMilliseconds() * 1000));
      return [{ type: codec.PA.ENCRYPTED_CHALLENGE,
                value: msgs.encEncryptedData({ etype: challengeKey.etype,
                                               cipher: cipher }) }];
    };
  };
  const otpRequest = function (challenge, cookie, pin, code) {
    return async function (armorKey) {
      const encData = { etype: armorKey.etype,
        cipher: await kcrypto.etypeById(armorKey.etype).encrypt(armorKey.key,
          codec.KEY_USAGE.OTP_REQUEST, codec.encOtpEncRequest(challenge.nonce))
      };
      return [cookie, { type: codec.PA.OTP_REQUEST,
        value: codec.encOtpRequest({ flags: [], encData: encData,
                                     value: code,
                                     pin: pin === null ? null : pin }) }];
    };
  };

  // --- the people ---
  const PW = 'Correct-Horse-Battery-9!';
  ['kfotp', 'kfreq', 'kfrealm', 'kfnone'].forEach(function (who) {
    directory.createUser(who, { invent: false });
    credentials.setPassword(who, PW);
  });
  await personKeys.idle();
  const began = credentials.beginTotpEnrolment('kfotp', {});
  out.steps.began = began.ok;
  const confirmAt = Date.now();
  const confirmCode = codeAt(began, confirmAt);
  out.steps.confirmed = credentials.confirmTotpEnrolment('kfotp',
                                                         confirmCode).ok;
  out.steps.required = credentials.setMfaRequired('kfreq', true).ok;
  out.demand = {
    otp: personKeys.personSecondFactor('kfotp'),
    req: personKeys.personSecondFactor('kfreq'),
    none: personKeys.personSecondFactor('kfnone')
  };

  // --- 4a. the refusal decision, over PA-ENC-TIMESTAMP ---
  const brief = function (r) {
    return { ok: r.ok, code: r.code, eText: r.eText, flags: r.flags,
             offered: r.offered, armored: r.armored, outerCode: r.outerCode,
             outerCname: r.outerCname, outerCrealm: r.outerCrealm,
             innerCname: r.innerCname };
  };
  out.bareOtp = brief(await asReq('kfotp', PW, { bare: true }));
  out.pwOtp = brief(await asReq('kfotp', PW));
  out.wrongOtp = brief(await asReq('kfotp', PW + '-wrong'));
  out.pwReq = brief(await asReq('kfreq', PW));
  out.wrongReq = brief(await asReq('kfreq', PW + '-wrong'));
  out.pwNone = brief(await asReq('kfnone', PW));
  out.policySaved = authnPolicy.save('default', Object.assign({},
    authnPolicy.DEFAULTS, { requireSecondFactor: 'always' })).ok;
  out.demand.realm = personKeys.personSecondFactor('kfrealm');
  out.pwRealm = brief(await asReq('kfrealm', PW));
  authnPolicy.reset('default');
  out.pwRealmAfter = brief(await asReq('kfrealm', PW));

  // --- 4b. the host's TGT, the armor ---
  const host = ['host', 'ws1.' + DOMAIN];
  const created = personKeys.createServicePrincipal(host.join('/'),
                                                    { actor: 'test' });
  out.hostCreated = created.ok;
  const hostPrincipal = principals.find(host, REALM);
  const hostKey = await principals.longTermKey(hostPrincipal, 18);
  armorTgt = await asReq(host, null, { key: hostKey });
  out.armorTgt = brief(armorTgt);

  // --- 4c. FAST: the method list, the password alone, the armor's refusals
  const first = await fastReq('kfotp', async function () {
    return [];
  });
  const offered = (first.padata || []).map(function (p) {
    return p.type;
  });
  out.fastFirst = { ok: first.ok, armored: first.armored, code: first.code,
                    outerCode: first.outerCode, offered: offered,
                    nonceOk: first.nonceOk, innerEData: first.innerEData };
  const challengePa = (first.padata || []).filter(function (p) {
    return p.type === codec.PA.OTP_CHALLENGE;
  })[0];
  const cookie = (first.padata || []).filter(function (p) {
    return p.type === codec.PA.FX_COOKIE;
  })[0];
  const challenge = challengePa ? codec.readOtpChallenge(challengePa.value)
                                : null;
  out.challenge = challenge ? {
    nonceBytes: challenge.nonce.length, service: challenge.service,
    flags: challenge.tokenInfo[0].flags } : null;
  out.fastPw = brief(await fastReq('kfotp', encChallenge('kfotp', PW),
                                   { replyKey: async function () {
                                     return ltkOf('kfotp', PW);
                                   } }));
  out.fastWrongPw = brief(await fastReq('kfotp',
                                        encChallenge('kfotp', PW + 'x')));
  out.fastHidden = brief(await fastReq('kfnone', async function () {
    return [];
  }, { fastOptions: [1] }));
  out.fastCritical = brief(await fastReq('kfnone', async function () {
    return [];
  }, { fastOptions: [5] }));
  out.fastBadChecksum = brief(await fastReq('kfnone', async function () {
    return [];
  }, { otherBody: true }));
  out.fastNoSubkey = brief(await fastReq('kfnone', async function () {
    return [];
  }, { noSubkey: true }));
  // The encrypted challenge for a person who owes nothing: a TGT, the KDC's
  // own PA-ENCRYPTED-CHALLENGE inside the armor, and the same ciphertext a
  // second time refused.
  const same = {};
  const noneTgt = await fastReq('kfnone', encChallenge('kfnone', PW),
    { keep: same, replyKey: async function () {
      return ltkOf('kfnone', PW);
    } });
  out.fastNone = { ok: noneTgt.ok, code: noneTgt.code, eText: noneTgt.eText,
                   finishedOk: noneTgt.finishedOk, nonceOk: noneTgt.nonceOk,
                   strengthened: noneTgt.strengthened, flags: noneTgt.flags,
                   kdcChallenge: (noneTgt.padata || []).some(function (p) {
                     return p.type === codec.PA.ENCRYPTED_CHALLENGE;
                   }) };

  // --- 4d. OTP: the step the portal spent, a wrong PIN, no PIN, the right
  // one, and the same code again ---
  const nextCode = codeAt(began, confirmAt + began.period * 1000);
  out.otpSpentAtEnrolment = brief(await fastReq('kfotp',
    otpRequest(challenge, cookie, PW, confirmCode)));
  out.otpWrongPin = brief(await fastReq('kfotp',
    otpRequest(challenge, cookie, 'Not-The-Password-1!', nextCode)));
  out.otpNoPin = brief(await fastReq('kfotp',
    otpRequest(challenge, cookie, null, nextCode)));
  out.otpBadNonce = brief(await fastReq('kfotp',
    otpRequest({ nonce: Buffer.alloc(36, 9) }, cookie, PW, nextCode)));
  const good = await fastReq('kfotp', otpRequest(challenge, cookie, PW,
                                                 nextCode));
  out.otpGood = { ok: good.ok, code: good.code, eText: good.eText,
                  finishedOk: good.finishedOk, nonceOk: good.nonceOk,
                  strengthened: good.strengthened, flags: good.flags };
  out.otpReplay = brief(await fastReq('kfotp',
    otpRequest(challenge, cookie, PW, nextCode)));
  // THE SAME REQUEST, BYTE FOR BYTE: the armor opens (its Authenticator is
  // not what is checked for replay), and the encrypted challenge inside it is
  // the ciphertext the KDC has already spent.
  out.sameEc = brief(await fastReq('kfnone', async function () {
    return [];
  }, { resend: same.bytes, resendArmorKey: same.armorKey,
       resendNonce: same.nonce }));

  // --- 4e. the indicator: in a service ticket bought with the OTP TGT, read
  // with the service's own key, and by the acceptor ---
  async function tgsReq(tgt, clientName, sname) {
    const sessionKey = tgt.enc.key;
    const profile = kcrypto.etypeById(sessionKey.etype);
    const reqBody = { kdcOptions: [], realm: REALM,
                      sname: { type: 3, name: sname },
                      till: new Date(Date.now() + 3600000),
                      nonce: 4242, etypes: [18] };
    const raw = msgs.encKdcReqBody(reqBody);
    const cksum = await profile.checksum(sessionKey.key,
      kcrypto.KEY_USAGE.TGS_REQ_AUTH_CKSUM, raw);
    const auth = msgs.encAuthenticator({ crealm: REALM,
      cname: { type: 1, name: [clientName] },
      cksum: { type: profile.checksumType, checksum: cksum },
      cusec: armorCusec++, ctime: new Date() });
    const apReq = msgs.encApReq({ apOptions: [], ticket: tgt.rep.ticket,
      authenticator: { etype: sessionKey.etype,
        cipher: await profile.encrypt(sessionKey.key,
          kcrypto.KEY_USAGE.TGS_REQ_AUTH, auth) } });
    const bytes = msgs.encKdcReq({ msgType: msgs.MSG_TYPE.TGS_REQ,
      padata: [{ type: msgs.PA_TYPE.TGS_REQ, value: apReq }],
      reqBody: Object.assign({ raw: raw }, reqBody) });
    const reply = await kdc.handleMessage(bytes);
    if (msgs.identify(reply).applicationNumber ===
        msgs.APPLICATION.KRB_ERROR) {
      const e = msgs.readKrbError(reply);
      return { ok: false, code: e.errorCode, eText: e.eText };
    }
    const rep = msgs.readKdcRep(reply);
    const enc = msgs.readEncKdcRepPart(await profile.decrypt(sessionKey.key,
      kcrypto.KEY_USAGE.TGS_REP_ENCPART_SESSKEY, rep.encPart.cipher));
    return { ok: true, rep: rep, enc: enc };
  }
  // What a service ticket's authorization data holds, opened with the key
  // the service holds — the test reads the CAMMAC itself, with the codec,
  // and checks the svc-verifier with the vendored checksum.
  async function indicatorsIn(ticket, key) {
    const part = msgs.readEncTicketPart(await kcrypto.etypeById(
      ticket.encPart.etype).decrypt(key, kcrypto.KEY_USAGE.KDC_REP_TICKET,
                                    ticket.encPart.cipher));
    const found = [];
    let verified = null;
    (part.authorizationData || []).forEach(function (entry) {
      if (entry.type !== 1) {
        return;
      }
      msgs.readAuthorizationData(asn1.readTlv(entry.data, 0))
        .forEach(function (inner) {
          if (inner.type !== 96) {
            return;
          }
          const c = codec.readCammac(inner.data);
          c.elements.forEach(function (el) {
            if (el.type === 97) {
              codec.readIndicators(el.data).forEach(function (s) {
                found.push(s);
              });
            }
          });
          verified = c;
        });
    });
    let svcOk = null;
    if (verified) {
      svcOk = await kcrypto.etypeById(ticket.encPart.etype).verifyChecksum(
        key, 64, verified.elementsBytes, verified.svcVerifier.mac.checksum);
    }
    return { indicators: found, svcOk: svcOk,
             hasKdcVerifier: !!(verified && verified.kdcVerifier) };
  }
  if (good.ok) {
    const svc = await tgsReq(good, 'kfotp', host);
    out.svcFromOtp = svc.ok
      ? await indicatorsIn(svc.rep.ticket, hostKey)
      : { error: svc.code + ' ' + svc.eText };
    // THE ACCEPTOR: the service's own SPN given a stored key, a ticket for
    // it, and `acceptRaw()`'s result.
    const spn = String(config.value('krb5.servicePrincipal'));
    const acceptorCreated = personKeys.createServicePrincipal(spn,
                                                              { actor: 't' });
    out.acceptorCreated = acceptorCreated.ok;
    const forAcceptor = await tgsReq(good, 'kfotp', spn.split('/'));
    if (forAcceptor.ok) {
      const key = forAcceptor.enc.key;
      const auth = msgs.encAuthenticator({ crealm: REALM,
        cname: { type: 1, name: ['kfotp'] }, cusec: 77777,
        ctime: new Date() });
      const apReq = msgs.encApReq({ apOptions: [],
        ticket: forAcceptor.rep.ticket,
        authenticator: { etype: key.etype,
          cipher: await kcrypto.etypeById(key.etype).encrypt(key.key,
            kcrypto.KEY_USAGE.AP_REQ_AUTH, auth) } });
      const accepted = await service.acceptRaw(
        gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, apReq),
        { record: false });
      out.accepted = { ok: accepted.ok, indicators: accepted.authIndicators,
                       failed: (accepted.checks || []).filter(function (c) {
                         return !c.ok;
                       }) };
    } else {
      out.accepted = { error: forAcceptor.code + ' ' + forAcceptor.eText };
    }
  }
  if (noneTgt.ok) {
    const svc = await tgsReq(noneTgt, 'kfnone', host);
    out.svcFromNone = svc.ok
      ? await indicatorsIn(svc.rep.ticket, hostKey)
      : { error: svc.code + ' ' + svc.eText };
  }
  out.policy = personKeys.preauthPolicy();
  return out;
}
/* eslint-enable no-undef */

function inAProductChild(t) {
  log.debug("Entering inAProductChild().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krb5-fast-otp-'));
  const kekFile = path.join(dir, 'kek');
  // A key-encryption key made HERE, at run time, and removed with the
  // directory — no key material lives in the repository.
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
    '(' + productChild.toString() + ')().then(function (r) ' +
    '{require("fs").writeFileSync(process.env.KF_OUT, JSON.stringify(r)); ' +
    'process.exit(0); }).catch(function (e) { ' +
    'require("fs").writeFileSync(process.env.KF_OUT, JSON.stringify({ ' +
    'crashed: e.stack || e.message })); process.exit(0); });';
  const run = childProcess.spawnSync(process.execPath, ['-e', script], {
    env: Object.assign(clean, {
      LOG_LEVEL: 'fatal', KF_ROOT: ROOT, KF_OUT: outFile,
      STS_MODE: 'product',
      KRB5_KRBTGT_PASSWORD: 'fast-otp-' +
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
    // Best effort: a temporary directory left behind is litter, not a failure.
    log.debug("Caught in inAProductChild(): " + ((e && e.message) || e));
  }
  t.check(report !== null && !report.crashed, 'the product-mode child ran to ' +
                                              'the end',
          'exit ' + run.status + ' ' + (report && report.crashed) + ' ' +
          String(run.stderr || '').slice(0, 800));
  log.debug("Leaving inAProductChild().");
  return report;
}

function theRefusalDecision(t, r) {
  log.debug("Entering theRefusalDecision().");
  t.log.info('=== 4a. product: who gets a ticket on a password alone ===');
  t.check(r.product === true && r.passwordAloneIssues === false &&
          r.provider === true,
          'a product KDC, mode.issuesTicketsOnPasswordAlone() false, and the ' +
          'FAST provider installed through the key source',
          JSON.stringify({ product: r.product,
                           issues: r.passwordAloneIssues,
                           provider: r.provider }));
  t.check(r.steps.began && r.steps.confirmed && r.steps.required,
          'kfotp enrolled an authenticator; kfreq is required to have a ' +
          'second factor', JSON.stringify(r.steps));
  t.check(r.demand.otp.needed && r.demand.otp.totp && r.demand.otp.holds &&
          r.demand.req.needed && r.demand.req.byUser && !r.demand.req.holds &&
          r.demand.realm.needed && !r.demand.realm.byUser &&
          !r.demand.none.needed,
          'THE DECISION: enrolled, required by the account, required by the ' +
          'realm — needed; nobody else', JSON.stringify(r.demand));
  t.check(!r.bareOtp.ok && r.bareOtp.code === 25 &&
          r.bareOtp.offered.indexOf(2) !== -1 &&
          r.bareOtp.offered.indexOf(136) !== -1,
          'the bare AS-REQ is PREAUTH_REQUIRED offering PA-ENC-TIMESTAMP AND ' +
          'PA-FX-FAST (the advertisement MIT kinit -T upgrades on)',
          JSON.stringify(r.bareOtp));
  t.check(!r.pwOtp.ok && r.pwOtp.code === 12 &&
          /password alone is not enough/.test(r.pwOtp.eText) &&
          /kinit -T/.test(r.pwOtp.eText),
          'ENROLLED: the right password alone is KDC_ERR_POLICY, naming FAST ' +
          'and OTP', JSON.stringify(r.pwOtp));
  t.check(!r.wrongOtp.ok && r.wrongOtp.code === 24,
          'and a WRONG password is still KDC_ERR_PREAUTH_FAILED — the ' +
          'refusal comes only after the password verified',
          JSON.stringify(r.wrongOtp));
  t.check(!r.pwReq.ok && r.pwReq.code === 12 &&
          /required of this account/.test(r.pwReq.eText) &&
          !r.wrongReq.ok && r.wrongReq.code === 24,
          'REQUIRED BY THE ACCOUNT: KDC_ERR_POLICY for the right password, ' +
          'PREAUTH_FAILED for a wrong one',
          JSON.stringify([r.pwReq, r.wrongReq]));
  t.check(!r.pwRealm.ok && r.pwRealm.code === 12 &&
          /this realm requires/.test(r.pwRealm.eText) && r.pwRealmAfter.ok,
          'REQUIRED BY THE REALM (the authentication policy): ' +
          'KDC_ERR_POLICY, and a ' +
          'ticket once the requirement is cleared',
          JSON.stringify([r.pwRealm, r.pwRealmAfter]));
  t.check(r.pwNone.ok && r.pwNone.flags.indexOf('pre-authent') !== -1,
          'NOBODY OWES ANYTHING: a person with no second factor gets a TGT ' +
          'on the password, as before', JSON.stringify(r.pwNone));
  log.debug("Leaving theRefusalDecision().");
}

function fastArmor(t, r) {
  log.debug("Entering fastArmor().");
  t.log.info('=== 4b/4c. FAST armor and the encrypted challenge ===');
  t.check(r.hostCreated && r.armorTgt.ok,
          'a host principal with a random key gets a TGT with it — the ' +
          'armor ticket (RFC 6113 section 5.4.1.1)',
          JSON.stringify(r.armorTgt));
  const f = r.fastFirst;
  t.check(!f.ok && f.armored && f.code === 25 && f.outerCode === 25 &&
          f.nonceOk && !f.innerEData,
          'an armored bare AS-REQ is PREAUTH_REQUIRED INSIDE the armor: ' +
          'PA-FX-ERROR with no e-data, bound to the request\'s nonce',
          JSON.stringify(f));
  const methods = f.offered.filter(function (type) {
    return type !== 137;
  });
  t.check(f.offered[0] === 137 && methods[0] === 141 &&
          methods.indexOf(138) === 1 &&
          methods.indexOf(133) !== -1 && f.offered.indexOf(19) !== -1 &&
          f.offered.indexOf(2) === -1,
          'the FAST method list: PA-OTP-CHALLENGE FIRST, then ' +
          'PA-ENCRYPTED-CHALLENGE, a PA-FX-COOKIE and ETYPE-INFO2 — and no ' +
          'PA-ENC-TIMESTAMP (PA-FX-ERROR first, carrying the error)',
          JSON.stringify(f.offered));
  t.check(r.challenge && r.challenge.nonceBytes >= 36 &&
          JSON.stringify(r.challenge.flags) === '[3,6]',
          'the challenge\'s nonce has a random part at least as long as the ' +
          'armor key, and asks for the PIN separately (collect-pin, ' +
          'separate-pin-required)', JSON.stringify(r.challenge));
  t.check(!r.fastPw.ok && r.fastPw.armored && r.fastPw.code === 12,
          'the PASSWORD ALONE INSIDE FAST (encrypted challenge) is ' +
          'KDC_ERR_POLICY too, armored', JSON.stringify(r.fastPw));
  t.check(!r.fastWrongPw.ok && r.fastWrongPw.code === 24,
          'and a wrong one PREAUTH_FAILED', JSON.stringify(r.fastWrongPw));
  t.check(r.fastNone.ok && r.fastNone.finishedOk && r.fastNone.nonceOk &&
          r.fastNone.strengthened && r.fastNone.kdcChallenge &&
          r.fastNone.flags.indexOf('pre-authent') !== -1,
          'a person with no second factor gets a TGT through FAST: the ' +
          'KrbFastFinished checksum verifies over the ticket, the reply key ' +
          'is strengthened, and the KDC answers with its own ' +
          'PA-ENCRYPTED-CHALLENGE', JSON.stringify(r.fastNone));
  t.check(!r.sameEc.ok && r.sameEc.code === 34,
          'the SAME encrypted-challenge ciphertext again is ' +
          'KRB_AP_ERR_REPEAT ' +
          '(RFC 6113 section 5.4.6)', JSON.stringify(r.sameEc));
  // hide-client-names is IMPLEMENTED since #205 (Heimdal sets it on every
  // TGS-REQ): the outer error names the anonymous principal, the inner one
  // the client. A critical option this KDC lacks is still refused.
  t.check(!r.fastHidden.ok && r.fastHidden.armored &&
          r.fastHidden.code === 25 &&
          r.fastHidden.outerCname === 'WELLKNOWN/ANONYMOUS' &&
          r.fastHidden.outerCrealm === 'WELLKNOWN:ANONYMOUS' &&
          r.fastHidden.innerCname === 'kfnone',
          'hide-client-names (bit 1) is honoured: the outer KRB-ERROR names ' +
          'the anonymous principal and the armored one the client',
          JSON.stringify(r.fastHidden));
  t.check(!r.fastCritical.ok && r.fastCritical.code === 93,
          'a critical FAST option this KDC does not implement (bit 5) is ' +
          'KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS',
          JSON.stringify(r.fastCritical));
  t.check(!r.fastBadChecksum.ok && r.fastBadChecksum.code === 41 &&
          !r.fastBadChecksum.armored,
          'a req-checksum over a different body is KRB_AP_ERR_MODIFIED',
          JSON.stringify(r.fastBadChecksum));
  t.check(!r.fastNoSubkey.ok && r.fastNoSubkey.code === 24,
          'armor without a subkey is PREAUTH_FAILED',
          JSON.stringify(r.fastNoSubkey));
  log.debug("Leaving fastArmor().");
}

function otpPreauthentication(t, r) {
  log.debug("Entering otpPreauthentication().");
  t.log.info('=== 4d. OTP pre-authentication inside FAST ===');
  t.check(!r.otpSpentAtEnrolment.ok && r.otpSpentAtEnrolment.code === 24 &&
          /already been used/.test(r.otpSpentAtEnrolment.eText),
          'THE CODE THAT CONFIRMED THE ENROLMENT IS REFUSED AT THE KDC — ' +
          'one once-only step for the sign-in screen and Kerberos',
          JSON.stringify(r.otpSpentAtEnrolment));
  t.check(!r.otpWrongPin.ok && r.otpWrongPin.code === 24,
          'a wrong password as the PIN is PREAUTH_FAILED',
          JSON.stringify(r.otpWrongPin));
  t.check(!r.otpNoPin.ok && r.otpNoPin.code === 97,
          'no PIN is KDC_ERR_PIN_REQUIRED', JSON.stringify(r.otpNoPin));
  t.check(!r.otpBadNonce.ok && r.otpBadNonce.code === 24,
          'a nonce the KDC did not issue is PREAUTH_FAILED',
          JSON.stringify(r.otpBadNonce));
  t.check(r.otpGood.ok && r.otpGood.finishedOk && r.otpGood.nonceOk &&
          r.otpGood.strengthened &&
          r.otpGood.flags.indexOf('pre-authent') !== -1,
          'PASSWORD AND CODE: a TGT, the reply under the STRENGTHENED armor ' +
          'key (RFC 6560 section 3.6), the wrong-PIN attempt before it ' +
          'having ' +
          'spent no step', JSON.stringify(r.otpGood));
  t.check(!r.otpReplay.ok && r.otpReplay.code === 24,
          'the same code a second time is refused',
          JSON.stringify(r.otpReplay));
  log.debug("Leaving otpPreauthentication().");
}

function theIndicator(t, r) {
  log.debug("Entering theIndicator().");
  t.log.info('=== 4e. the RFC 8129 indicator ===');
  t.check(r.svcFromOtp && JSON.stringify(r.svcFromOtp.indicators) ===
          '["otp"]' && r.svcFromOtp.svcOk === true &&
          r.svcFromOtp.hasKdcVerifier,
          'a service ticket bought with the OTP TGT carries "otp" in an ' +
          'AD-CAMMAC whose svc-verifier checks under the SERVICE\'s key, ' +
          'with ' +
          'a kdc-verifier beside it', JSON.stringify(r.svcFromOtp));
  t.check(r.svcFromNone && r.svcFromNone.indicators.length === 0,
          'one bought with a password-only TGT carries none',
          JSON.stringify(r.svcFromNone));
  t.check(r.acceptorCreated && r.accepted && r.accepted.ok &&
          JSON.stringify(r.accepted.indicators) === '["otp"]',
          'THE ACCEPTOR reads "otp" off the ticket it accepted, for ' +
          '/authn/spnego', JSON.stringify(r.accepted));
  t.check(r.policy && r.policy.passwordAloneForSecondFactorAccounts ===
          'refused' && r.policy.otpIndicator === 'otp',
          'the policy the console and /admin-api report says so',
          JSON.stringify(r.policy));
  log.debug("Leaving theIndicator().");
}

module.exports = {
  name: 'kerberos_fast_otp',
  describe: 'a password alone is no Kerberos ticket for a two-factor account ' +
            'in product mode, and RFC 6113 FAST with RFC 6560 OTP ' +
            'pre-authentication is (#173)',
  run: async function (t) {
    log.debug("Entering run().");
    await primitivesMatchPublishedVectors(t);
    theCodecIsTheSpecifications(t);
    spnegoCountsTheOtpIndicator(t);
    const report = inAProductChild(t);
    if (!report || report.crashed) {
      log.debug("Leaving run().");
      return;
    }
    theRefusalDecision(t, report);
    fastArmor(t, report);
    otpPreauthentication(t, report);
    theIndicator(t, report);
    log.debug("Leaving run().");
  }
};
