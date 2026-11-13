// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: kerberos_renew_till.js
//
// ===========================================================================
// A REQUESTED RENEW-TILL IS HONOURED (#897).
//
// The KDC used to set renew-till to krb5.renewLifetimeSeconds whenever the
// client asked for a renewable ticket, and a service ticket copied its
// ticket-granting ticket's renew-till. An AS-REQ with a one-hour till and a
// three-hour rtime was given a seven-day renew-till. RFC 4120 section 3.1.3
// takes the earliest of the requested rtime and the realm maximum, and a
// service ticket also cannot pass the ticket-granting ticket's renew-till.
//
// The choices that match MIT krb5, and the one that does not, are argued in
// kerberos/CLAUDE.md. This file drives them through kdc.handleMessage():
//
//   * AS, RENEWABLE, rtime of three hours and till of one: endtime is the
//     hour, renew-till is the three hours, in the reply and in the ticket.
//   * AS, rtime past seven days: renew-till is the realm maximum.
//   * AS, RENEWABLE and no rtime: the realm maximum, as before.
//   * AS, rtime before endtime: the flag stays set (MIT). RENEWABLE-OK does
//     not, when the shortened renew-till would not pass endtime.
//   * TGS, a shorter rtime: min(rtime, the TGT's renew-till). An empty
//     option list still inherits RENEWABLE, and a present rtime is still
//     read. A non-renewable TGT cannot buy a renewable service ticket.
//   * RENEW copies renew-till and ignores a longer rtime on the request.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, which is the question tests/CLAUDE.md asks first.
//
// The assertions are about two instants on one ticket, a few seconds apart
// from the request that named them. Over a socket those are a race against
// a network and a container clock; here the file holds the Date it sent.
// The wire half is an interop client (kinit -r), which this process does
// not run. The same codec builds the requests, and the KDC did not.
//
// The probe principal is removed on the way out.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const principals = require('../kerberos/krb5_principals.js');
const kdc = require('../kerberos/krb5_kdc.js');
const msgs = require('../kerberos/krb5_messages.js');
const kcrypto = require('../kerberos/krb5_crypto.js');
const prim = require('../kerberos/krb5_primitives.js');

const log = require('bunyan').createLogger({ name: 'kerberos_renew_till',
  level: process.env.LOG_LEVEL || 'info' });

const ETYPE = 18;
const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;
// KerberosTime is whole seconds, and the KDC's own now() is a call later
// than the stamp this file takes. A requested instant only loses the
// fraction. A cap taken from the KDC's clock may be a couple of seconds off.
const SECOND = 1000;
const CLOCK = 5000;

let nonce = 9000;
let cachedKey = null;

function nextNonce() {
  log.debug("Entering nextNonce().");
  nonce += 1;
  log.debug("Leaving nextNonce().");
  return nonce;
}

function tgtName() {
  log.debug("Entering tgtName().");
  log.debug("Leaving tgtName().");
  return { type: 2, name: ['krbtgt', principals.REALM] };
}

function serviceName() {
  log.debug("Entering serviceName().");
  const parts = String(config.value('krb5.servicePrincipal')).split('/');
  log.debug("Leaving serviceName().");
  return { type: 3, name: parts };
}

function isRenewable(part) {
  log.debug("Entering isRenewable().");
  const flags = (part && part.flags) || [];
  log.debug("Leaving isRenewable().");
  return flags.indexOf(msgs.TICKET_FLAG.RENEWABLE) !== -1;
}

function detail(result) {
  log.debug("Entering detail().");
  const text = result && result.ok ? 'issued'
    : ((result && (result.eText || result.code)) || result);
  log.debug("Leaving detail().");
  return String(text);
}

function within(t, actual, expected, slack, label) {
  log.debug("Entering within().");
  const got = actual instanceof Date ? actual.getTime() : NaN;
  const want = expected instanceof Date ? expected.getTime() : expected;
  const delta = got - want;
  log.debug("Leaving within().");
  t.check(Number.isFinite(delta) && Math.abs(delta) <= slack, label,
          'delta ' + delta + ' ms');
}

function store() {
  log.debug("Entering store().");
  log.debug("Leaving store().");
  return realms.handleFor('krb5.principals');
}

async function clientKey(name) {
  log.debug("Entering clientKey().");
  if (!cachedKey) {
    const profile = kcrypto.etypeById(ETYPE);
    cachedKey = {
      profile: profile,
      key: await profile.stringToKey(
        String(config.value('krb5.userPassword')),
        prim.utf8(principals.REALM + name), null)
    };
  }
  log.debug("Leaving clientKey().");
  return cachedKey;
}

async function asReq(name, spec) {
  log.debug("Entering asReq().");
  const client = await clientKey(name);
  const now = new Date();
  const stamp = msgs.encPaEncTsEnc(now, now.getMilliseconds() * 1000);
  const pa = await client.profile.encrypt(client.key,
    kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP, stamp);
  const reqBody = {
    kdcOptions: spec.kdcOptions || [],
    cname: { type: 1, name: [name] },
    realm: principals.REALM,
    sname: tgtName(),
    till: spec.till,
    nonce: nextNonce(),
    etypes: [ETYPE]
  };
  if (spec.rtime) {
    reqBody.rtime = spec.rtime;
  }
  const bytes = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: [{ type: msgs.PA_TYPE.ENC_TIMESTAMP,
               value: msgs.encEncryptedData(
                 { etype: ETYPE, cipher: pa }) }],
    reqBody: reqBody
  });
  const sentAt = Date.now();
  const reply = await kdc.handleMessage(bytes);
  const id = msgs.identify(reply);
  if (id.applicationNumber === msgs.APPLICATION.KRB_ERROR) {
    const error = msgs.readKrbError(reply);
    log.debug("Leaving asReq().");
    return { ok: false, code: error.errorCode, eText: error.eText,
             sentAt: sentAt };
  }
  const rep = msgs.readKdcRep(reply);
  let enc = null;
  try {
    enc = msgs.readEncKdcRepPart(await client.profile.decrypt(client.key,
      kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));
  } catch (e) {
    log.debug("Caught in asReq(): " + ((e && e.message) || e));
    log.debug("Leaving asReq().");
    return { ok: false, code: -1, eText: 'AS-REP did not decrypt: ' +
                                         e.message, sentAt: sentAt };
  }
  log.debug("Leaving asReq().");
  return { ok: true, rep: rep, enc: enc, sentAt: sentAt };
}

async function tgsReq(earlier, spec) {
  log.debug("Entering tgsReq().");
  const sessionKey = earlier.enc.key;
  const profile = kcrypto.etypeById(sessionKey.etype);
  const reqBody = {
    kdcOptions: spec.kdcOptions || [],
    realm: principals.REALM,
    sname: spec.sname,
    till: spec.till,
    nonce: nextNonce(),
    etypes: [ETYPE]
  };
  if (spec.rtime) {
    reqBody.rtime = spec.rtime;
  }
  const raw = msgs.encKdcReqBody(reqBody);
  const cksum = await profile.checksum(sessionKey.key,
    kcrypto.KEY_USAGE.TGS_REQ_AUTH_CKSUM, raw);
  const auth = msgs.encAuthenticator({
    crealm: principals.REALM,
    cname: { type: 1, name: [spec.client] },
    cksum: { type: profile.checksumType, checksum: cksum },
    cusec: 1000, ctime: new Date()
  });
  const apReq = msgs.encApReq({
    apOptions: [], ticket: earlier.rep.ticket,
    authenticator: { etype: sessionKey.etype,
      cipher: await profile.encrypt(sessionKey.key,
        kcrypto.KEY_USAGE.TGS_REQ_AUTH, auth) }
  });
  const bytes = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.TGS_REQ,
    padata: [{ type: msgs.PA_TYPE.TGS_REQ, value: apReq }],
    reqBody: Object.assign({ raw: raw }, reqBody)
  });
  const sentAt = Date.now();
  const reply = await kdc.handleMessage(bytes);
  if (msgs.identify(reply).applicationNumber === msgs.APPLICATION.KRB_ERROR) {
    const error = msgs.readKrbError(reply);
    log.debug("Leaving tgsReq().");
    return { ok: false, code: error.errorCode, eText: error.eText,
             sentAt: sentAt };
  }
  const rep = msgs.readKdcRep(reply);
  let enc = null;
  try {
    enc = msgs.readEncKdcRepPart(await profile.decrypt(sessionKey.key,
      kcrypto.KEY_USAGE.TGS_REP_ENCPART_SESSKEY, rep.encPart.cipher));
  } catch (e) {
    log.debug("Caught in tgsReq(): " + ((e && e.message) || e));
    log.debug("Leaving tgsReq().");
    return { ok: false, code: -1, eText: 'TGS-REP did not decrypt: ' +
                                         e.message, sentAt: sentAt };
  }
  log.debug("Leaving tgsReq().");
  return { ok: true, rep: rep, enc: enc, sentAt: sentAt };
}

async function ticketPartOf(rep, name) {
  log.debug("Entering ticketPartOf().");
  const etype = rep.ticket.encPart.etype;
  const profile = kcrypto.etypeById(etype);
  const key = await principals.longTermKey(principals.find(name), etype);
  const part = msgs.readEncTicketPart(await profile.decrypt(key,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, rep.ticket.encPart.cipher));
  log.debug("Leaving ticketPartOf().");
  return part;
}

async function withOverrides(pairs, fn) {
  log.debug("Entering withOverrides().");
  pairs.forEach(function (pair) {
    config.setOverride(pair[0], pair[1]);
  });
  try {
    const value = await fn();
    log.debug("Leaving withOverrides().");
    return value;
  } catch (e) {
    log.debug("Caught in withOverrides(): " + ((e && e.message) || e));
    log.debug("Leaving withOverrides().");
    throw e;
  } finally {
    pairs.forEach(function (pair) {
      config.clearOverride(pair[0]);
    });
  }
}

module.exports = {
  name: 'kerberos_renew_till',
  describe: 'a requested Kerberos rtime caps renew-till, in the AS and ' +
            'the TGS exchange, and a renewal does not move it (#897)',
  run: async function (t) {
    log.debug("Entering run().");
    const name = 'renewtill' + process.pid;
    const renewable = [msgs.KDC_OPTION.RENEWABLE];
    const renewableOk = [msgs.KDC_OPTION.RENEWABLE_OK];
    const realmMax = Number(config.value('krb5.renewLifetimeSeconds'));
    const ticketMax = Number(config.value('krb5.ticketLifetimeSeconds'));
    t.equal(realmMax, 604800, 'the realm renewable maximum is seven days');
    t.equal(ticketMax, 36000, 'the ticket maximum is ten hours');
    try {
      t.log.info('=== AS: a short rtime, the maximum, and no rtime ===');
      const shortRtime = new Date(Date.now() + 3 * HOUR);
      const shortTill = new Date(Date.now() + HOUR);
      const short = await asReq(name, {
        kdcOptions: renewable, till: shortTill, rtime: shortRtime
      });
      t.check(short.ok, 'AS with a three-hour rtime issued', detail(short));
      if (short.ok) {
        t.check(isRenewable(short.enc),
                'RENEWABLE with an rtime sets the flag');
        within(t, short.enc.endtime, shortTill, SECOND,
               'endtime is the one hour asked for, not the rtime');
        within(t, short.enc.renewTill, shortRtime, SECOND,
               'renew-till is the three hours asked for, not seven days');
        t.check(short.enc.renewTill.getTime() - short.sentAt < 4 * HOUR,
                'and that renew-till is not the seven-day maximum');
        const inside = await ticketPartOf(short.rep,
                                           ['krbtgt', principals.REALM]);
        t.equal(inside.renewTill.getTime(), short.enc.renewTill.getTime(),
                'the ticket carries the same renew-till as the reply');
        t.check(isRenewable(inside), 'and the ticket itself is renewable');
      }

      const longRtime = new Date(Date.now() + 30 * DAY);
      const capped = await asReq(name, {
        kdcOptions: renewable,
        till: new Date(Date.now() + HOUR),
        rtime: longRtime
      });
      t.check(capped.ok, 'AS with a 30-day rtime issued', detail(capped));
      if (capped.ok) {
        within(t, capped.enc.renewTill, capped.sentAt + realmMax * 1000,
               CLOCK, 'an rtime past the realm maximum is cut to it');
        t.check(longRtime.getTime() - capped.enc.renewTill.getTime() >
                20 * DAY,
                'the 30-day request was not issued as 30 days');
      }

      const omitted = await asReq(name, {
        kdcOptions: renewable, till: new Date(Date.now() + HOUR)
      });
      t.check(omitted.ok, 'AS with RENEWABLE and no rtime issued',
              detail(omitted));
      if (omitted.ok) {
        within(t, omitted.enc.renewTill, omitted.sentAt + realmMax * 1000,
               CLOCK,
               'no rtime still means the realm maximum');
        t.check(isRenewable(omitted.enc), 'and the flag is set');
      }

      t.log.info('=== AS: rtime before endtime keeps the flag; ' +
                 'RENEWABLE-OK does not always ===');
      const earlyRtime = new Date(Date.now() + 30 * 60 * 1000);
      const earlyTill = new Date(Date.now() + HOUR);
      const early = await asReq(name, {
        kdcOptions: renewable, till: earlyTill, rtime: earlyRtime
      });
      t.check(early.ok, 'AS with an rtime before endtime issued',
              detail(early));
      if (early.ok) {
        t.check(isRenewable(early.enc),
                'an explicit RENEWABLE keeps the flag when rtime does ' +
                'not pass endtime, as MIT krb5 does');
        within(t, early.enc.renewTill, earlyRtime, SECOND,
               'renew-till is that earlier rtime');
        within(t, early.enc.endtime, earlyTill, SECOND,
               'endtime is still the till, later than renew-till');
      }

      const okLongTill = new Date(Date.now() + 20 * HOUR);
      const okLong = await asReq(name, {
        kdcOptions: renewableOk, till: okLongTill
      });
      t.check(okLong.ok, 'AS with RENEWABLE-OK past the ticket maximum ' +
                         'issued', detail(okLong));
      if (okLong.ok) {
        t.check(isRenewable(okLong.enc),
                'RENEWABLE-OK sets the flag when till was shortened');
        within(t, okLong.enc.endtime, okLong.sentAt + ticketMax * 1000,
               CLOCK, 'endtime is the ten-hour ticket maximum');
        within(t, okLong.enc.renewTill, okLongTill, SECOND,
               'renew-till is the requested endtime, still under seven days');
      }

      const okShort = await asReq(name, {
        kdcOptions: renewableOk, till: new Date(Date.now() + HOUR)
      });
      t.check(okShort.ok, 'AS with RENEWABLE-OK inside the ticket maximum ' +
                          'issued', detail(okShort));
      if (okShort.ok) {
        t.check(!isRenewable(okShort.enc) && okShort.enc.renewTill === null,
                'RENEWABLE-OK that does not shorten till grants nothing');
      }

      const plain = await asReq(name, {
        kdcOptions: [], till: new Date(Date.now() + HOUR)
      });
      t.check(plain.ok, 'AS with no renewable option issued', detail(plain));
      if (plain.ok) {
        t.check(!isRenewable(plain.enc) && plain.enc.renewTill === null,
                'no RENEWABLE and no RENEWABLE-OK means no renew-till');
      }

      await withOverrides([
        ['krb5.ticketLifetimeSeconds', 3600],
        ['krb5.renewLifetimeSeconds', 1800]
      ], async function () {
        const dropped = await asReq(name, {
          kdcOptions: renewableOk,
          till: new Date(Date.now() + 10 * HOUR)
        });
        t.check(dropped.ok, 'RENEWABLE-OK under a 30-minute renewable ' +
                            'maximum issued', detail(dropped));
        if (dropped.ok) {
          t.check(!isRenewable(dropped.enc) &&
                  dropped.enc.renewTill === null,
                  'RENEWABLE-OK drops the flag when the capped renew-till ' +
                  'does not pass endtime');
          within(t, dropped.enc.endtime, dropped.sentAt + 3600 * 1000,
                 CLOCK, 'that ticket still has the one-hour endtime');
        }
        const keptRtime = new Date(Date.now() + 30 * 60 * 1000);
        const kept = await asReq(name, {
          kdcOptions: renewable,
          till: new Date(Date.now() + 2 * HOUR),
          rtime: keptRtime
        });
        t.check(kept.ok, 'explicit RENEWABLE under the same maximum issued',
                detail(kept));
        if (kept.ok) {
          t.check(isRenewable(kept.enc),
                  'the same rtime with RENEWABLE still sets the flag');
          within(t, kept.enc.renewTill, keptRtime, SECOND,
                 'renew-till is the 30 minutes');
        }
      });

      t.log.info('=== TGS: rtime, the TGT cap, inheritance ===');
      if (short.ok) {
        const asked = new Date(Date.now() + 2 * HOUR);
        const service = await tgsReq(short, {
          client: name, sname: serviceName(),
          kdcOptions: renewable,
          till: new Date(Date.now() + HOUR),
          rtime: asked
        });
        t.check(service.ok, 'TGS with a two-hour rtime issued',
                detail(service));
        if (service.ok) {
          t.check(isRenewable(service.enc),
                  'a renewable TGT and RENEWABLE yield a renewable ' +
                  'service ticket');
          within(t, service.enc.renewTill, asked, SECOND,
                 'its renew-till is the two hours, under the TGT\'s three');
          const opened = await ticketPartOf(service.rep, serviceName().name);
          t.equal(opened.renewTill.getTime(),
                  service.enc.renewTill.getTime(),
                  'the service ticket carries the same renew-till');
        }
        const pastTgt = new Date(Date.now() + 5 * HOUR);
        const bounded = await tgsReq(short, {
          client: name, sname: serviceName(),
          kdcOptions: renewable,
          till: new Date(Date.now() + HOUR),
          rtime: pastTgt
        });
        t.check(bounded.ok, 'TGS with an rtime past the TGT issued',
                detail(bounded));
        if (bounded.ok) {
          t.equal(bounded.enc.renewTill.getTime(),
                  short.enc.renewTill.getTime(),
                  'a service ticket\'s renew-till cannot pass its TGT\'s');
        }
      }

      if (omitted.ok) {
        const inherited = await tgsReq(omitted, {
          client: name, sname: serviceName(),
          kdcOptions: [],
          till: new Date(Date.now() + HOUR)
        });
        t.check(inherited.ok, 'TGS with an empty option list issued',
                detail(inherited));
        if (inherited.ok) {
          t.check(isRenewable(inherited.enc),
                  'a service ticket inherits RENEWABLE when the TGS-REQ ' +
                  'does not repeat it');
          t.equal(inherited.enc.renewTill.getTime(),
                  omitted.enc.renewTill.getTime(),
                  'and, with no rtime, keeps the TGT\'s renew-till');
        }
        const inheritedRtime = new Date(Date.now() + 3 * HOUR);
        const inheritedShort = await tgsReq(omitted, {
          client: name, sname: serviceName(),
          kdcOptions: [],
          till: new Date(Date.now() + HOUR),
          rtime: inheritedRtime
        });
        t.check(inheritedShort.ok,
                'TGS inheriting the flag and sending an rtime issued',
                detail(inheritedShort));
        if (inheritedShort.ok) {
          within(t, inheritedShort.enc.renewTill, inheritedRtime, SECOND,
                 'that rtime is honoured without repeating RENEWABLE');
        }
      }

      if (plain.ok) {
        const refused = await tgsReq(plain, {
          client: name, sname: serviceName(),
          kdcOptions: renewable,
          till: new Date(Date.now() + HOUR),
          rtime: new Date(Date.now() + 3 * HOUR)
        });
        t.check(refused.ok, 'TGS from a non-renewable TGT still issues',
                detail(refused));
        if (refused.ok) {
          t.check(!isRenewable(refused.enc) &&
                  refused.enc.renewTill === null,
                  'asking RENEWABLE cannot add it when the TGT has none');
        }
        const okFromPlain = await tgsReq(plain, {
          client: name, sname: serviceName(),
          kdcOptions: renewableOk,
          till: new Date(Date.now() + 30 * DAY)
        });
        t.check(okFromPlain.ok, 'TGS RENEWABLE-OK from that TGT issues',
                detail(okFromPlain));
        if (okFromPlain.ok) {
          t.check(!isRenewable(okFromPlain.enc) &&
                  okFromPlain.enc.renewTill === null,
                  'RENEWABLE-OK cannot add it either');
        }
      }

      t.log.info('=== RENEW does not move renew-till ===');
      if (short.ok) {
        const renewed = await tgsReq(short, {
          client: name, sname: tgtName(),
          kdcOptions: [msgs.KDC_OPTION.RENEW, msgs.KDC_OPTION.RENEWABLE],
          till: new Date(Date.now() + 10 * HOUR),
          rtime: new Date(Date.now() + 30 * DAY)
        });
        t.check(renewed.ok, 'renewing the three-hour TGT issued',
                detail(renewed));
        if (renewed.ok) {
          t.equal(renewed.enc.renewTill.getTime(),
                  short.enc.renewTill.getTime(),
                  'a longer rtime on the renewal does not move renew-till');
          t.equal(renewed.enc.endtime.getTime(),
                  short.enc.renewTill.getTime(),
                  'the new endtime stops at that same renew-till');
          t.check(isRenewable(renewed.enc), 'the renewed ticket stays ' +
                                            'renewable');
        }
      }
      if (short.ok) {
        const service = await tgsReq(short, {
          client: name, sname: serviceName(),
          kdcOptions: [],
          till: new Date(Date.now() + HOUR),
          rtime: new Date(Date.now() + 3 * HOUR)
        });
        t.check(service.ok, 'a service ticket to renew issued',
                detail(service));
        if (service.ok) {
          const again = await tgsReq(service, {
            client: name, sname: serviceName(),
            kdcOptions: [msgs.KDC_OPTION.RENEW],
            till: new Date(Date.now() + 10 * HOUR),
            rtime: new Date(Date.now() + HOUR)
          });
          t.check(again.ok, 'renewing the service ticket issued',
                  detail(again));
          if (again.ok) {
            t.equal(again.enc.renewTill.getTime(),
                    service.enc.renewTill.getTime(),
                    'a shorter rtime on the renewal does not move ' +
                    'renew-till either');
          }
        }
      }
    } finally {
      store().remove('', name + '@' + principals.REALM);
    }
    log.debug("Leaving run().");
  }
};
