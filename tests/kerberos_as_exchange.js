// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: kerberos_as_exchange.js
// ===========================================================================
// THE AS EXCHANGE AS A CLIENT MEETS IT, AND THE KDC'S VOCABULARY OF REFUSAL
// (from the parent project, 2026-10-22; added here 2026-11-14).
//
// This was the parent project's `tests/krb5_as_exchange.js`, which loaded
// `krb5_kdc.js` in ITS process through a COPY closure of this tree and drove
// it through the debugger's api relay. It moved here with the other three
// in-process Kerberos jobs; what it asserted that nothing in this repository
// already did is below, driven through `kdc.handleMessage()` — the door both
// sockets and `/KdcProxy` reach — with the service's own codec
// (`kerberos/krb5_*.js`), in development mode, where the behaviour accounts
// (`noreauth`, `locked`, `expired`, `aesonly`, `rc4only`, `host/ws01`) exist:
//
//   A. THE TWO-MESSAGE DANCE: a bare AS-REQ is KDC_ERR_PREAUTH_REQUIRED whose
//      ETYPE-INFO2 carries AD's user salt, s2kparams as `krb5.s2kparams`
//      says, rc4-hmac with no salt; the pre-authenticated one is a TGT whose
//      nonce comes back unchanged, flagged initial, pre-authent, forwardable
//      and renewable with a renew-till past its endtime — and whose session
//      key is the SAME BYTES in the ticket (opened with the krbtgt key) and
//      in the client's enc-part.
//   B. ONE MESSAGE: `noreauth` gets a TGT straight away, initial and NOT
//      pre-authent.
//   C. A COMPUTER ACCOUNT's salt is host-shaped (`REALMhostws01.domain`),
//      and the key derived from it authenticates.
//   D. THE CLIENT'S ETYPE ORDER chooses the reply key and the session key
//      (aes256, aes128, rc4-hmac or an RFC 8009 enctype first).
//   E. THE REFUSALS, each with its number, the e-text that says why, and
//      the KDC's own clock (stime): an unknown principal, an unknown
//      service, the wrong realm, a locked account, an expired password, no
//      common enctype both ways round (naming what the principal DOES
//      support), a wrong password (re-sending ETYPE-INFO2 with the right
//      salt), the right password under the wrong salt, a timestamp twenty
//      minutes old (quoting the difference), an AP-REP sent to a KDC,
//      bytes that are not Kerberos, text that wears the AP-REQ tag by
//      accident, a TGS-REQ whose PA-TGS-REQ is unreadable and one with none.
//   F. TCP AND UDP ON ONE PORT, and the same answer over both.
//
// Already held elsewhere and NOT repeated here: ETYPE-INFO2 in the request's
// order and PA-ETYPE-INFO / PA-PW-SALT only beside no newer enctype, and the
// TGT under the krbtgt's strongest key (`kerberos_samba_findings.js`); a
// wrong password, an unknown principal and the wrong realm over the network
// (`protocol/sts_kerberos_spnego.js`).
//
// IN PROCESS because the TGT has to be opened with the krbtgt key, which only
// the inside holds, and because the behaviour accounts are development
// fixtures a deployed service in product mode does not have.
// ===========================================================================

delete process.env.CONFIG_FILE;

const dgram = require('dgram');
const net = require('net');
const config = require('../common/config');
require('../common/app');
const principals = require('../kerberos/krb5_principals.js');
const kdc = require('../kerberos/krb5_kdc.js');
const prim = require('../kerberos/krb5_primitives.js');
const asn1 = require('../kerberos/krb5_asn1.js');
const msgs = require('../kerberos/krb5_messages.js');
const kcrypto = require('../kerberos/krb5_crypto.js');

const log = require('bunyan').createLogger({ name: 'kerberos_as_exchange',
  level: process.env.LOG_LEVEL || 'info' });

const REALM = principals.REALM;
const DOMAIN = REALM.toLowerCase();
// Ordinary behaviour, so a generated name: the KDC creates it on first sight
// with pre-authentication required, the enctypes it serves, AD's user salt
// and the shared development password.
const CLIENT = 'kerberos-as-' + Date.now().toString(36);
const CLIENT_SALT = REALM + CLIENT;

let nonceCounter = 0x11110000;

// One AS-REQ. `fields` overrides any part of the body.
function asReq(fields) {
  log.debug("Entering asReq().");
  const f = fields || {};
  nonceCounter += 1;
  log.debug("Leaving asReq().");
  return msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: f.padata || [],
    reqBody: {
      kdcOptions: f.kdcOptions || [msgs.KDC_OPTION.FORWARDABLE,
                                   msgs.KDC_OPTION.RENEWABLE],
      cname: f.cname || { type: msgs.NAME_TYPE.PRINCIPAL, name: [CLIENT] },
      realm: f.realm || REALM,
      sname: f.sname || { type: msgs.NAME_TYPE.SRV_INST,
                          name: ['krbtgt', REALM] },
      till: f.till || new Date(Date.now() + 10 * 3600 * 1000),
      rtime: new Date(Date.now() + 24 * 3600 * 1000),
      nonce: f.nonce === undefined ? nonceCounter : f.nonce,
      etypes: f.etypes || [18, 17, 23]
    }
  });
}

// Through the KDC's one door, decoded.
async function exchange(bytes) {
  log.debug("Entering exchange().");
  const reply = await kdc.handleMessage(Buffer.from(bytes));
  log.debug("Leaving exchange().");
  return msgs.readKdcResponse(reply);
}

// The ETYPE-INFO2 entries of a KRB-ERROR, or [].
function info2Of(error) {
  log.debug("Entering info2Of().");
  const pa = ((error && error.eDataPaData) || []).filter(function (one) {
    return one.type === msgs.PA_TYPE.ETYPE_INFO2;
  })[0];
  log.debug("Leaving info2Of().");
  return pa ? msgs.readEtypeInfo2(pa.value) : [];
}

// The client's half of pre-authentication: the key from the password and the
// salt the KDC named, and a timestamp under key usage 1.
async function encTimestamp(password, info, at) {
  log.debug("Entering encTimestamp().");
  const profile = kcrypto.etypeById(info.etype);
  const key = await profile.stringToKey(password, prim.utf8(info.salt || ''),
                                        info.s2kparams || null);
  const stamp = msgs.encPaEncTsEnc(at || new Date(), 0);
  const padata = {
    type: msgs.PA_TYPE.ENC_TIMESTAMP,
    value: msgs.encEncryptedData({
      etype: info.etype,
      cipher: await profile.encrypt(key,
        kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP, stamp)
    })
  };
  log.debug("Leaving encTimestamp().");
  return { padata: padata, key: key, profile: profile };
}

// The krbtgt's long-term key for an enctype, from the inside.
async function krbtgtKey(etype) {
  log.debug("Entering krbtgtKey().");
  const krbtgt = principals.find(['krbtgt', REALM], REALM);
  const key = await principals.longTermKey(krbtgt, etype);
  log.debug("Leaving krbtgtKey().");
  return key;
}

// A. -------------------------------------------------------------------------
async function danceSection(t, password) {
  log.debug("Entering danceSection().");
  t.log.info('=== A. the two-message dance ===');
  const first = await exchange(asReq());
  if (!t.check(first.kind === 'KRB-ERROR' && first.error.errorCode === 25 &&
               !!first.error.eDataPaData,
               'A1. a bare AS-REQ is KDC_ERR_PREAUTH_REQUIRED with PA-DATA ' +
               'in its e-data', first.kind + ' ' +
               (first.error && first.error.errorCode))) {
    log.debug("Leaving danceSection(). No PREAUTH_REQUIRED.");
    return null;
  }
  const entries = info2Of(first.error);
  const aes256 = entries.filter(function (e) {
    return e.etype === 18;
  })[0];
  t.check(!!aes256 && aes256.salt === CLIENT_SALT,
          'A2. ETYPE-INFO2 offers aes256 with Active Directory\'s user salt, ' +
          'realm + sAMAccountName and no separator',
          JSON.stringify(aes256));
  if (!aes256) {
    log.debug("Leaving danceSection(). No aes256.");
    return null;
  }
  const sends = String(config.value('krb5.s2kparams') || 'omit') === 'send';
  const s2k = aes256.s2kparams ? prim.toBytes(aes256.s2kparams) : null;
  t.check(sends ? (!!s2k && s2k.length === 4 &&
                   ((s2k[0] << 24) | (s2k[1] << 16) | (s2k[2] << 8) |
                    s2k[3]) === 4096)
                : aes256.s2kparams === null,
          'A3. s2kparams as krb5.s2kparams says (' + (sends ? 'send' : 'omit') +
          '): omitted, as Active Directory does, or RFC 3962\'s 4096 ' +
          'iterations', JSON.stringify(aes256.s2kparams));
  const rc4 = entries.filter(function (e) {
    return e.etype === 23;
  })[0];
  t.check(!!rc4 && rc4.salt === null,
          'A4. rc4-hmac\'s entry carries NO salt — its string-to-key has none',
          JSON.stringify(rc4));

  const pre = await encTimestamp(password, aes256);
  const second = await exchange(asReq({ padata: [pre.padata],
                                        nonce: 0xcafe1234 }));
  if (!t.check(second.kind === 'AS-REP',
               'A5. with the right pre-authentication the KDC issues a TGT',
               second.kind + ' ' + (second.error ? second.error.eText : ''))) {
    log.debug("Leaving danceSection(). No TGT.");
    return null;
  }
  const rep = second.rep;
  t.check(rep.crealm === REALM && rep.cname.name.join('/') === CLIENT &&
          rep.ticket.encPart.etype === 18,
          'A6. the reply names the client and its realm, and the ticket is ' +
          'sealed with aes256', JSON.stringify([rep.crealm, rep.cname.name,
                                                rep.ticket.encPart.etype]));
  const part = msgs.readEncKdcRepPart(await pre.profile.decrypt(pre.key,
    kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));
  t.equal(part.nonce, 0xcafe1234,
          'A7. THE NONCE COMES BACK UNCHANGED — a client\'s only defence ' +
          'against a replayed reply');
  t.check(part.srealm === REALM &&
          part.sname.name.join('/') === 'krbtgt/' + REALM &&
          part.endtime > part.authtime && part.key.etype === 18,
          'A8. the enc-part names krbtgt/' + REALM + ', a positive lifetime ' +
          'and an aes256 session key',
          JSON.stringify([part.srealm, part.sname.name, part.key.etype]));
  const flags = msgs.ticketFlagNames(part.flags);
  t.check(['initial', 'pre-authent', 'forwardable', 'renewable']
    .every(function (one) {
      return flags.indexOf(one) >= 0;
    }) && !!part.renewTill && part.renewTill > part.endtime,
          'A9. flagged initial, pre-authent, forwardable and renewable, with ' +
          'a renew-till beyond its endtime', flags.join(','));

  // The ticket's own copy of the session key, opened with the krbtgt key.
  // Their equality IS the mechanism, and neither end can check it alone.
  const ticketPart = msgs.readEncTicketPart(await kcrypto.etypeById(18)
    .decrypt(await krbtgtKey(18), kcrypto.KEY_USAGE.KDC_REP_TICKET,
             rep.ticket.encPart.cipher));
  t.check(prim.toHex(ticketPart.key.key) === prim.toHex(part.key.key) &&
          ticketPart.cname.name.join('/') === CLIENT &&
          ticketPart.crealm === REALM &&
          ticketPart.endtime.getTime() === part.endtime.getTime(),
          'A10. the session key in the TICKET and in the client\'s enc-part ' +
          'are the same bytes, and both copies agree on the client and the ' +
          'endtime', JSON.stringify([ticketPart.cname.name,
                                     ticketPart.endtime, part.endtime]));
  log.debug("Leaving danceSection().");
  return aes256;
}

// B. -------------------------------------------------------------------------
async function noPreauthSection(t, password) {
  log.debug("Entering noPreauthSection().");
  t.log.info('=== B. an account that does not require pre-authentication ===');
  const reply = await exchange(asReq({
    cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: ['noreauth'] },
    nonce: 0x5150 }));
  if (!t.check(reply.kind === 'AS-REP',
               'B1. noreauth is answered with a TGT in ONE message',
               reply.kind)) {
    log.debug("Leaving noPreauthSection(). No ticket.");
    return;
  }
  const profile = kcrypto.etypeById(reply.rep.encPart.etype);
  const key = await profile.stringToKey(password,
    prim.utf8(REALM + 'noreauth'), null);
  const part = msgs.readEncKdcRepPart(await profile.decrypt(key,
    kcrypto.KEY_USAGE.AS_REP_ENCPART, reply.rep.encPart.cipher));
  const flags = msgs.ticketFlagNames(part.flags);
  t.check(part.nonce === 0x5150 && flags.indexOf('initial') >= 0 &&
          flags.indexOf('pre-authent') < 0,
          'B2. its nonce comes back, and the ticket is initial but NOT ' +
          'pre-authent — no pre-authentication happened, and a service may ' +
          'insist on that flag', flags.join(','));
  log.debug("Leaving noPreauthSection().");
}

// C. -------------------------------------------------------------------------
async function computerSection(t) {
  log.debug("Entering computerSection().");
  t.log.info('=== C. a computer account\'s salt ===');
  const cname = { type: msgs.NAME_TYPE.SRV_HST,
                  name: ['host', 'ws01.' + DOMAIN] };
  const first = await exchange(asReq({ cname: cname }));
  const info = info2Of(first.error).filter(function (e) {
    return e.etype === 18;
  })[0];
  t.check(!!info && info.salt === REALM + 'hostws01.' + DOMAIN,
          'C1. a computer account\'s salt is host-shaped — realm + "host" + ' +
          'short name + DNS domain — not the principal name',
          JSON.stringify(info));
  if (!info) {
    log.debug("Leaving computerSection(). No ETYPE-INFO2.");
    return;
  }
  const pre = await encTimestamp('machine-account-password', info);
  const second = await exchange(asReq({ cname: cname,
                                        padata: [pre.padata] }));
  t.check(second.kind === 'AS-REP',
          'C2. and the key derived from it authenticates',
          second.kind + ' ' + (second.error ? second.error.eText : ''));
  log.debug("Leaving computerSection().");
}

// D. -------------------------------------------------------------------------
async function etypeOrderSection(t, password) {
  log.debug("Entering etypeOrderSection().");
  t.log.info('=== D. the client\'s enctype order ===');
  const cases = [[[18, 17, 23], 18], [[17, 18, 23], 17], [[23, 18], 23],
                 [[19, 20, 18], 19]];
  for (const [offered, expected] of cases) {
    const first = await exchange(asReq({ etypes: offered }));
    const chosen = info2Of(first.error).filter(function (e) {
      return e.etype === expected;
    })[0];
    if (!t.check(!!chosen, 'D. ' + JSON.stringify(offered) + ': the KDC ' +
                 'advertises ' + kcrypto.etypeName(expected),
                 JSON.stringify(info2Of(first.error)))) {
      continue;
    }
    const pre = await encTimestamp(password, chosen);
    const done = await exchange(asReq({ etypes: offered,
                                        padata: [pre.padata] }));
    if (!t.check(done.kind === 'AS-REP', 'D. ' + JSON.stringify(offered) +
                 ': a ticket', done.kind)) {
      continue;
    }
    const part = msgs.readEncKdcRepPart(await pre.profile.decrypt(pre.key,
      kcrypto.KEY_USAGE.AS_REP_ENCPART, done.rep.encPart.cipher));
    t.check(done.rep.encPart.etype === expected &&
            part.key.etype === expected,
            'D. ' + JSON.stringify(offered) + ': the reply and the session ' +
            'key are ' + kcrypto.etypeName(expected) + ', the first the ' +
            'client offered', JSON.stringify([done.rep.encPart.etype,
                                              part.key.etype]));
  }
  log.debug("Leaving etypeOrderSection().");
}

// E. -------------------------------------------------------------------------
// Asserts a refusal: its number, its e-text, and stime (how a client measures
// skew). Answers the error, or null. The malformed PA-TGS-REQ asks only that
// the refusal NAME the part it could not read: its number moved from 25 to
// KRB_ERR_GENERIC here, and the parent's job never pinned one.
async function refused(t, label, request, code, text) {
  log.debug("Entering refused(). " + label);
  const reply = await exchange(request);
  const e = reply.error || {};
  // `code` null: any refusal, so long as it says why.
  const ok = t.check(reply.kind === 'KRB-ERROR' &&
                     (code === null || e.errorCode === code) &&
                     (!text || text.test(e.eText || '')) &&
                     e.stime instanceof Date && !isNaN(e.stime.getTime()),
                     'E. ' + label + ': ' + (code === null ? 'a KRB-ERROR'
                       : msgs.describeError(code).name + ' (' + code + ')') +
                     (text ? ' saying ' + text : '') + ', with stime',
                     reply.kind + ' ' + e.errorCode + ' ' +
                     JSON.stringify(e.eText));
  log.debug("Leaving refused().");
  return ok ? e : null;
}

async function refusalsSection(t, password, aes256) {
  log.debug("Entering refusalsSection().");
  t.log.info('=== E. the KDC refuses in its own vocabulary ===');
  // A name `krb5.unknownUsers` keeps unknown: development invents any other.
  const unknown = principals.reservedUnknown()[0];
  await refused(t, 'an unknown principal (' + unknown + ')', asReq({
    cname: { type: 1, name: [unknown] } }), 6, /no such principal|unknown/);
  await refused(t, 'an unknown service', asReq({
    sname: { type: 2, name: ['krbtgt', 'OTHER.REALM'] } }), 7,
                /no such service/);
  await refused(t, 'the wrong realm', asReq({
    realm: 'OTHER.REALM',
    sname: { type: 2, name: ['krbtgt', 'OTHER.REALM'] } }), 68,
                new RegExp('serves ' +
                           REALM.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  await refused(t, 'a locked account', asReq({
    cname: { type: 1, name: ['locked'] } }), 18, /disabled or locked/);
  await refused(t, 'an expired password', asReq({
    cname: { type: 1, name: ['expired'] } }), 23, /expired/);
  const noSupp = await refused(t, 'an rc4-only client against an AES-only ' +
                               'account', asReq({
    cname: { type: 1, name: ['aesonly'] }, etypes: [23] }), 14,
                               /no common encryption type/);
  t.check(!!noSupp && /aes256|aes128/.test(noSupp.eText || ''),
          'E. and the refusal says what the principal DOES support',
          JSON.stringify(noSupp && noSupp.eText));
  await refused(t, 'an AES-only client against an rc4-only account', asReq({
    cname: { type: 1, name: ['rc4only'] }, etypes: [18, 17] }), 14,
                /no common encryption type/);

  const wrong = await encTimestamp('not the password', aes256);
  const failed = await refused(t, 'a wrong password', asReq({
    padata: [wrong.padata] }), 24, /PREAUTH_FAILED/);
  const resent = failed ? info2Of(failed).filter(function (e) {
    return e.etype === 18;
  })[0] : null;
  t.check(!!resent && resent.salt === CLIENT_SALT,
          'E. PREAUTH_FAILED re-sends ETYPE-INFO2 with the right salt — the ' +
          'client may have used the wrong salt rather than the wrong password',
          JSON.stringify(resent));
  const wrongSalt = await encTimestamp(password,
    { etype: 18, salt: CLIENT_SALT.toUpperCase(),
      s2kparams: aes256.s2kparams });
  await refused(t, 'the right password under the wrong salt', asReq({
    padata: [wrongSalt.padata] }), 24, /PREAUTH_FAILED/);
  const stale = await encTimestamp(password, aes256,
    new Date(Date.now() - 20 * 60 * 1000));
  const skewed = await refused(t, 'a timestamp twenty minutes old', asReq({
    padata: [stale.padata] }), 37, /clock skew/);
  t.check(!!skewed && /\d+ seconds/.test(skewed.eText || ''),
          'E. and the skew refusal quotes the measured difference',
          JSON.stringify(skewed && skewed.eText));

  // Messages that are not a request a KDC answers still get an ANSWER: a
  // client waiting for a reply that never comes learns nothing.
  const apRep = msgs.encApRep({ encPart: { etype: 18,
    cipher: kcrypto.randomBytes(32) } });
  await refused(t, 'an AP-REP sent to a KDC', apRep, 40, null);
  await refused(t, 'bytes that are not Kerberos (a bare SEQUENCE)',
                new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x05]), 60,
                /could not decode/);
  // 'n' is 0x6e, the [APPLICATION 14] tag: text can wear the AP-REQ tag.
  await refused(t, 'text beginning 0x6e, read as an AP-REQ',
                prim.utf8('not kerberos'), 40, null);
  const tgsBody = { kdcOptions: [], realm: REALM,
                    sname: { type: 3, name: ['HTTP', 'web.' + DOMAIN] },
                    till: new Date(Date.now() + 3600000), nonce: 7,
                    etypes: [18] };
  await refused(t, 'a TGS-REQ whose PA-TGS-REQ is unreadable',
                msgs.encKdcReq({ msgType: msgs.MSG_TYPE.TGS_REQ,
                  padata: [{ type: msgs.PA_TYPE.TGS_REQ,
                             value: prim.fromHex('00') }],
                  reqBody: tgsBody }), null, /PA-TGS-REQ/);
  await refused(t, 'a TGS-REQ carrying no TGT at all',
                msgs.encKdcReq({ msgType: msgs.MSG_TYPE.TGS_REQ,
                  reqBody: Object.assign({}, tgsBody, { nonce: 8 }) }), 25,
                /must carry the TGT/);
  log.debug("Leaving refusalsSection().");
}

// F. -------------------------------------------------------------------------
// One framed exchange over TCP.
function overTcp(port, bytes) {
  log.debug("Entering overTcp().");
  log.debug("Leaving overTcp().");
  return new Promise(function (resolve, reject) {
    const socket = net.connect(port, '127.0.0.1');
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(function () {
      socket.destroy();
      reject(new Error('no TCP reply in 10s'));
    }, 10000);
    socket.on('connect', function () {
      const head = Buffer.alloc(4);
      head.writeUInt32BE(bytes.length, 0);
      socket.write(Buffer.concat([head, Buffer.from(bytes)]));
    });
    socket.on('data', function (chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32BE(0)) {
        clearTimeout(timer);
        socket.destroy();
        resolve(buffer.subarray(4, 4 + buffer.readUInt32BE(0)));
      }
    });
    socket.on('error', function (e) {
      clearTimeout(timer);
      reject(e);
    });
  });
}

// One datagram over UDP, unframed (RFC 4120 section 7.2.1).
function overUdp(port, bytes) {
  log.debug("Entering overUdp().");
  log.debug("Leaving overUdp().");
  return new Promise(function (resolve, reject) {
    const socket = dgram.createSocket('udp4');
    const timer = setTimeout(function () {
      socket.close();
      reject(new Error('no UDP reply in 10s'));
    }, 10000);
    socket.on('message', function (message) {
      clearTimeout(timer);
      socket.close();
      resolve(message);
    });
    socket.send(Buffer.from(bytes), port, '127.0.0.1');
  });
}

async function transportsSection(t) {
  log.debug("Entering transportsSection().");
  t.log.info('=== F. TCP and UDP on one port ===');
  const listeners = kdc.listen(0);
  try {
    await listeners.whenReady;
    t.check(listeners.tcp.address().port === listeners.port &&
            listeners.udp.address().port === listeners.port,
            'F1. TCP and UDP listen on ONE port number — a client failing ' +
            'over from UDP retries at the same place',
            JSON.stringify([listeners.port, listeners.tcp.address().port,
                            listeners.udp.address().port]));
    const tcp = msgs.readKdcResponse(await overTcp(listeners.port, asReq()));
    const udp = msgs.readKdcResponse(await overUdp(listeners.port, asReq()));
    t.check(tcp.kind === 'KRB-ERROR' && tcp.error.errorCode === 25 &&
            udp.kind === 'KRB-ERROR' && udp.error.errorCode === 25,
            'F2. a bare AS-REQ over UDP gets the answer it gets over TCP: ' +
            'KDC_ERR_PREAUTH_REQUIRED', JSON.stringify([
              tcp.kind, tcp.error && tcp.error.errorCode,
              udp.kind, udp.error && udp.error.errorCode]));
  } catch (e) {
    log.debug("Caught in transportsSection(): " + ((e && e.message) || e));
    t.bad('F. the KDC\'s own listeners answered', String(e && e.message));
  } finally {
    try {
      listeners.tcp.close();
    } catch (e) {
      // Never bound, or already closed; nothing else holds it.
      log.debug("Caught in transportsSection(): " + ((e && e.message) || e));
    }
    try {
      if (listeners.udp) {
        listeners.udp.close();
      }
    } catch (e) {
      // As above, for the datagram socket.
      log.debug("Caught in transportsSection(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving transportsSection().");
}

async function run(t) {
  log.debug("Entering run().");
  const password = String(config.value('krb5.userPassword'));
  const aes256 = await danceSection(t, password);
  await noPreauthSection(t, password);
  await computerSection(t);
  await etypeOrderSection(t, password);
  if (aes256) {
    await refusalsSection(t, password, aes256);
  }
  await transportsSection(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kerberos_as_exchange',
  describe: 'the AS exchange as a client meets it — salts, s2kparams, the ' +
            'nonce, flags, the session key in both copies, one-message ' +
            'accounts, the client\'s enctype order — and every refusal in ' +
            'the KDC\'s own words, over TCP and UDP (moved from the parent)',
  run: run
};
