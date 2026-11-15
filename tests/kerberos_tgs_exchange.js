// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: kerberos_tgs_exchange.js
// ===========================================================================
// THE TGS EXCHANGE, THE PAC THE KDC MINTS, AND WHAT A TGS-REQ MAY NOT DO
// (from the parent project, 2026-10-22; added here 2026-11-14).
//
// This is the KDC half of the parent project's `tests/krb5_tgs_ap.js`, which
// loaded `krb5_kdc.js` in ITS process through a COPY closure of this tree.
// The acceptor half is `kerberos_acceptor.js`; the delegation half was
// already `kerberos_delegation.js`, so only the three S4U refusals that file
// did not have are here. Driven through `kdc.handleMessage()` with the local
// client `tests/protocol/krb5_wire.js` (and two hand-built requests it does
// not make), in development mode:
//
//   A. A SERVICE TICKET: a new session key, not initial, pre-authent
//      inherited, no longer-lived than the TGT; the reply under a subkey
//      opens at key usage 9.
//   B. THE PAC, VERIFIED THE WAY A SERVICE AND A KDC WOULD: one PAC, inside
//      AD-IF-RELEVANT; alice's name, SID, Domain Admins and the asserted-
//      identity SID; the TGT's two signatures under the krbtgt key and no
//      ticket or extended KDC signature; the service ticket's four, its
//      server signature under the SERVICE's key and NOT the krbtgt's;
//      PAC_CLIENT_INFO tied to the initial authtime. `noreauth`'s PAC says
//      DONT_REQUIRE_PREAUTH.
//   C. PA-PAC-REQUEST's three states: FALSE gives a TGT and a service ticket
//      with no PAC; absent gives one marked PAC_WAS_GIVEN_IMPLICITLY; TRUE
//      one marked PAC_WAS_REQUESTED.
//   D. THE DEVELOPMENT PARTNER REALM: a request for a service in it is a
//      REFERRAL sealed with the trust key (not the krbtgt key), transiting
//      nothing; followed, a ticket the partner's service opens whose PAC is
//      RE-SIGNED under the partner's keys; a realm with no trust is
//      KDC_ERR_S_PRINCIPAL_UNKNOWN. PARTNER.COM's own client carol gets a
//      PAC in HER domain, signed by that realm's own krbtgt key.
//   E. RENEWAL keeps authtime and renew-till, in the reply and the ticket,
//      and stops AT renew-till; refused for another service, for a ticket
//      that was not renewable, and for one whose renew-till has passed.
//   F. A FORWARDED TGT is another TGT, flagged forwarded, and buys a ticket
//      to anything as its owner; a forwardable TGT of a NOT_DELEGATED
//      account that predates the flag is still refused.
//   G. THE REFUSALS: an unregistered SPN (naming the cause and what would
//      have been registered), the SPNs a client derives from this
//      service's own hosts registered on first sight, and a request body
//      swapped after its checksum was made; and S4U2Self with a forged
//      PA-FOR-USER, S4U2Self to another service, and S4U2Proxy with
//      evidence addressed to somebody else.
//
// Already held elsewhere and NOT repeated: S4U2Self/S4U2Proxy (classic and
// resource-based), protocol transition and the protected user
// (`kerberos_delegation.js`); trust-realm referrals and `transited`
// (`kerberos_trusts.js`); the PAC's client claims (`pac_claims.js`); a
// service ticket presented as a TGT (`kerberos_samba_findings.js`).
//
// IN PROCESS because every ticket here is opened, and two are forged, with
// long-term keys only the inside holds.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
require('../common/app');
require('../ldap/ldap_server');
const principals = require('../kerberos/krb5_principals.js');
const kdc = require('../kerberos/krb5_kdc.js');
const prim = require('../kerberos/krb5_primitives.js');
const kcrypto = require('../kerberos/krb5_crypto.js');
const kpac = require('../kerberos/krb5_pac.js');
const wire = require('./protocol/krb5_wire.js');

const log = require('bunyan').createLogger({ name: 'kerberos_tgs_exchange',
  level: process.env.LOG_LEVEL || 'info' });

const msgs = wire.msgs;
const REALM = principals.REALM;
const DOMAIN = REALM.toLowerCase();
const PARTNER = principals.DEV_PARTNER_REALM;
const SERVICE = ['HTTP', 'web.' + DOMAIN];
const T = {
  label: 'in-process',
  send: function (bytes) {
    log.debug("Entering send().");
    log.debug("Leaving send().");
    return kdc.handleMessage(bytes);
  }
};

function spn(name) {
  log.debug("Entering spn().");
  log.debug("Leaving spn().");
  return { type: msgs.NAME_TYPE.SRV_HST, name: name };
}

function nameOf(text) {
  log.debug("Entering nameOf().");
  log.debug("Leaving nameOf().");
  return text.indexOf('/') >= 0
    ? { type: msgs.NAME_TYPE.SRV_INST, name: text.split('/') }
    : { type: msgs.NAME_TYPE.PRINCIPAL, name: [text] };
}

// A TGT, hand-built because krb5_wire.js's AS exchange sends no padata but
// the timestamp and fixes the options and the lifetimes. `opts`: `realm`,
// `padata` (beside the timestamp), `kdcOptions`, `tillMs`, `rtimeMs`.
async function tgtFor(name, password, opts) {
  log.debug("Entering tgtFor(). " + name);
  const o = opts || {};
  const realm = o.realm || REALM;
  const body = function (nonce) {
    log.debug("Entering body().");
    log.debug("Leaving body().");
    return {
      kdcOptions: o.kdcOptions || [msgs.KDC_OPTION.FORWARDABLE,
                                   msgs.KDC_OPTION.RENEWABLE],
      cname: nameOf(name), realm: realm,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ['krbtgt', realm] },
      till: new Date(Date.now() + (o.tillMs || 10 * 3600 * 1000)),
      rtime: new Date(Date.now() + (o.rtimeMs || 24 * 3600 * 1000)),
      nonce: nonce, etypes: [18, 17]
    };
  };
  const first = msgs.readKdcResponse(await T.send(msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ, padata: [], reqBody: body(1) })));
  const pa = ((first.error && first.error.eDataPaData) || [])
    .filter(function (one) {
      return one.type === msgs.PA_TYPE.ETYPE_INFO2;
    })[0];
  if (!pa) {
    log.debug("Leaving tgtFor(). No ETYPE-INFO2.");
    return null;
  }
  const info = msgs.readEtypeInfo2(pa.value).filter(function (e) {
    return e.etype === 18;
  })[0];
  const profile = kcrypto.etypeById(18);
  const key = await profile.stringToKey(password, prim.utf8(info.salt),
                                        info.s2kparams || null);
  const nonce = 0x2000 + Math.floor(Math.random() * 0x7fff0000);
  const reply = msgs.readKdcResponse(await T.send(msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: [{ type: msgs.PA_TYPE.ENC_TIMESTAMP,
               value: msgs.encEncryptedData({ etype: 18,
                 cipher: await profile.encrypt(key,
                   kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP,
                   msgs.encPaEncTsEnc(new Date(), 0)) }) }]
      .concat(o.padata || []),
    reqBody: body(nonce) })));
  if (reply.kind !== 'AS-REP') {
    log.debug("Leaving tgtFor(). Refused.");
    return null;
  }
  const part = msgs.readEncKdcRepPart(await profile.decrypt(key,
    kcrypto.KEY_USAGE.AS_REP_ENCPART, reply.rep.encPart.cipher));
  log.debug("Leaving tgtFor().");
  return { ticket: reply.rep.ticket, sessionKey: part.key.key,
           etype: part.key.etype, client: reply.rep.cname,
           realm: reply.rep.crealm, authtime: part.authtime,
           endtime: part.endtime, renewTill: part.renewTill,
           flagNames: msgs.ticketFlagNames(part.flags) };
}

// A principal's long-term key, from the inside.
async function keyOf(name, realm, etype) {
  log.debug("Entering keyOf(). " + name.join('/'));
  const principal = principals.find(name, realm);
  const key = principal ? await principals.longTermKey(principal, etype)
                        : null;
  log.debug("Leaving keyOf().");
  return key;
}

// A ticket's enc-part, opened with `key`; null when it does not open.
async function openTicket(ticket, key) {
  log.debug("Entering openTicket().");
  try {
    const part = msgs.readEncTicketPart(await kcrypto
      .etypeById(ticket.encPart.etype)
      .decrypt(key, kcrypto.KEY_USAGE.KDC_REP_TICKET, ticket.encPart.cipher));
    log.debug("Leaving openTicket().");
    return part;
  } catch (e) {
    log.debug("Caught in openTicket(): " + ((e && e.message) || e));
    log.debug("Leaving openTicket(). Does not open.");
    return null;
  }
}

// The one PAC in an opened ticket: { found, pac, path }.
function pacOf(part) {
  log.debug("Entering pacOf().");
  const found = kpac.findPacs((part && part.authorizationData) || []);
  log.debug("Leaving pacOf().");
  return { count: found.length, path: found.length ? found[0].path : null,
           pac: found.length ? kpac.parsePac(found[0].bytes) : null };
}

// The EncTicketPart a ticket signature covers: this PAC's ad-data replaced by
// one zero byte ([MS-PAC] 2.8.3).
function ticketSigned(part) {
  log.debug("Entering ticketSigned().");
  log.debug("Leaving ticketSigned().");
  return msgs.encEncTicketPart(Object.assign({}, part, {
    authorizationData: kpac.wrapPacAsAuthorizationData(new Uint8Array([0]))
  }));
}

function signaturesOk(sigs) {
  log.debug("Entering signaturesOk().");
  log.debug("Leaving signaturesOk().");
  return sigs.length > 0 && sigs.every(function (s) {
    return s.verified === true;
  });
}

function refusedSaying(r, code, text) {
  log.debug("Entering refusedSaying().");
  log.debug("Leaving refusedSaying().");
  return !!r && !r.ok && r.error && r.error.code === code &&
         (!text || text.test(r.error.eText || ''));
}

// A. -------------------------------------------------------------------------
async function serviceTicketSection(t, tgt) {
  log.debug("Entering serviceTicketSection().");
  t.log.info('=== A. a service ticket ===');
  const r = await wire.tgsExchange(T, tgt, spn(SERVICE), REALM);
  if (!t.check(r.ok && r.nonceEchoed, 'A1. the TGS exchange issues a ' +
               'ticket for ' + SERVICE.join('/'), String(r.error))) {
    log.debug("Leaving serviceTicketSection(). No ticket.");
    return null;
  }
  t.check(prim.toHex(r.sessionKey) !== prim.toHex(tgt.sessionKey) &&
          r.sessionKey.length === 32,
          'A2. it carries a NEW aes256 session key, not the TGT\'s');
  t.check(r.flagNames.indexOf('initial') < 0 &&
          r.flagNames.indexOf('pre-authent') >= 0,
          'A3. NOT initial — only the AS exchange issues one — and ' +
          'pre-authent inherited from the TGT', r.flagNames.join(','));
  t.check(r.endtime <= tgt.endtime,
          'A4. a service ticket does not outlive the TGT that bought it',
          r.endtime.toISOString() + ' vs ' + tgt.endtime.toISOString());
  const sub = await wire.tgsExchange(T, tgt, spn(SERVICE), REALM,
                                     { subkeyEtype: 18 })
    .catch(function (e) {
      // The client opens the reply under the subkey; a reply sealed under
      // anything else throws there, and that IS the failure being asked about.
      log.debug("Caught in serviceTicketSection(): " +
                ((e && e.message) || e));
      return { ok: false, error: 'did not open under the subkey: ' +
                                 e.message };
    });
  t.check(sub.ok, 'A5. with a subkey in the Authenticator the reply opens ' +
          'under it, at key usage 9', String(sub.error));
  log.debug("Leaving serviceTicketSection().");
  return r;
}

// B. -------------------------------------------------------------------------
async function pacSection(t, tgt, serviceTicket, password) {
  log.debug("Entering pacSection().");
  t.log.info('=== B. the PAC, verified ===');
  const etype = tgt.ticket.encPart.etype;
  const krbtgt = { etype: etype,
                   key: await keyOf(['krbtgt', REALM], REALM, etype) };
  const inTgt = pacOf(await openTicket(tgt.ticket, krbtgt.key));
  t.check(inTgt.count === 1 && inTgt.path === 'AD-IF-RELEVANT → AD-WIN2K-PAC' &&
          inTgt.pac.problems.length === 0,
          'B1. the TGT carries ONE well-formed PAC, inside AD-IF-RELEVANT',
          JSON.stringify([inTgt.count, inTgt.path,
                          inTgt.pac && inTgt.pac.problems]));
  if (!inTgt.pac) {
    log.debug("Leaving pacSection(). No PAC.");
    return;
  }
  const info = kpac.bufferOfType(inTgt.pac, kpac.TYPE.LOGON_INFO).parsed;
  const sid = principals.domainSidFor(REALM);
  t.check(info.effectiveName === 'alice' && info.userSid === sid + '-1104' &&
          info.groups.some(function (g) {
            return g.relativeId === 512;
          }) && info.extraSids.some(function (e) {
            return e.text === 'S-1-18-1';
          }) && info.notes.length === 0,
          'B2. alice\'s logon info: her name, her SID (RID 1104), Domain ' +
          'Admins (512), the asserted-identity SID a password logon gets, ' +
          'and no consistency notes', JSON.stringify([info.effectiveName,
            info.userSid, info.extraSids.map(function (e) {
              return e.text;
            }), info.notes]));
  t.check(kpac.countOfType(inTgt.pac, kpac.TYPE.TICKET_CHECKSUM) === 0 &&
          kpac.countOfType(inTgt.pac, kpac.TYPE.EXTENDED_KDC_CHECKSUM) === 0,
          'B3. a TGT is encrypted to krbtgt, so it carries NO ticket ' +
          'signature and no extended KDC signature ([MS-PAC] 2.8.2, 2.8.3)');
  const tgtSigs = await kpac.verifySignatures(inTgt.pac,
    { serverKey: krbtgt, kdcKey: krbtgt });
  t.check(tgtSigs.length === 2 && signaturesOk(tgtSigs),
          'B4. its two signatures verify with the krbtgt key',
          JSON.stringify(tgtSigs));

  const svcEtype = serviceTicket.ticket.encPart.etype;
  const service = { etype: svcEtype,
                    key: await keyOf(SERVICE, REALM, svcEtype) };
  const svcPart = await openTicket(serviceTicket.ticket, service.key);
  const inSvc = pacOf(svcPart);
  if (!t.check(inSvc.count === 1 && inSvc.pac.problems.length === 0,
               'B5. the service ticket carries one well-formed PAC',
               JSON.stringify(inSvc.pac && inSvc.pac.problems))) {
    log.debug("Leaving pacSection(). No service PAC.");
    return;
  }
  t.check(kpac.countOfType(inSvc.pac, kpac.TYPE.TICKET_CHECKSUM) === 1 &&
          kpac.countOfType(inSvc.pac, kpac.TYPE.EXTENDED_KDC_CHECKSUM) === 1,
          'B6. a service ticket carries the ticket signature and the ' +
          'extended KDC signature');
  const svcKrbtgt = { etype: svcEtype,
                      key: await keyOf(['krbtgt', REALM], REALM, svcEtype) };
  const svcSigs = await kpac.verifySignatures(inSvc.pac, {
    serverKey: service, kdcKey: svcKrbtgt, ticketBytes: ticketSigned(svcPart)
  });
  t.check(svcSigs.length === 4 && signaturesOk(svcSigs),
          'B7. all four verify — the server signature with the SERVICE\'s ' +
          'key, the rest with krbtgt', JSON.stringify(svcSigs));
  const wrongWay = await kpac.verifySignatures(inSvc.pac,
    { serverKey: svcKrbtgt, kdcKey: svcKrbtgt });
  const server = wrongWay.filter(function (s) {
    return s.type === kpac.TYPE.SERVER_CHECKSUM;
  })[0];
  t.check(!!server && server.verified === false,
          'B8. and the krbtgt key does NOT verify a service ticket\'s server ' +
          'signature — the discrimination a TGT cannot make',
          JSON.stringify(server));
  const clientInfo = kpac.bufferOfType(inSvc.pac,
                                       kpac.TYPE.CLIENT_INFO).parsed;
  t.check(clientInfo.name === 'alice' &&
          clientInfo.clientId.date.getTime() ===
            Math.floor(svcPart.authtime.getTime() / 1000) * 1000,
          'B9. PAC_CLIENT_INFO names alice at the INITIAL authentication ' +
          'time, the ticket\'s authtime', clientInfo.clientId.text + ' vs ' +
          svcPart.authtime.toISOString());

  // noreauth: answered in one message, and the PAC carries the reason.
  const bare = msgs.readKdcResponse(await T.send(msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    reqBody: { kdcOptions: [msgs.KDC_OPTION.FORWARDABLE],
               cname: nameOf('noreauth'), realm: REALM,
               sname: { type: msgs.NAME_TYPE.SRV_INST,
                        name: ['krbtgt', REALM] },
               till: new Date(Date.now() + 3600000), nonce: 0x5151,
               etypes: [18] } })));
  const nPart = bare.kind === 'AS-REP'
    ? await openTicket(bare.rep.ticket, krbtgt.key) : null;
  const nPac = pacOf(nPart);
  const nInfo = nPac.pac
    ? kpac.bufferOfType(nPac.pac, kpac.TYPE.LOGON_INFO).parsed : null;
  t.check(!!nInfo &&
          nInfo.userAccountControlNames.indexOf('DONT_REQUIRE_PREAUTH') >= 0 &&
          msgs.ticketFlagNames(nPart.flags).indexOf('pre-authent') < 0,
          'B10. noreauth\'s PAC carries DONT_REQUIRE_PREAUTH, the reason its ' +
          'exchange was one message, and its ticket is not pre-authent',
          JSON.stringify(nInfo && nInfo.userAccountControlNames));
  log.debug("Leaving pacSection().");
}

// C. -------------------------------------------------------------------------
async function pacRequestSection(t, password) {
  log.debug("Entering pacRequestSection().");
  t.log.info('=== C. PA-PAC-REQUEST\'s three states ===');
  const request = function (include) {
    log.debug("Entering request().");
    log.debug("Leaving request().");
    return [{ type: msgs.PA_TYPE.PAC_REQUEST,
              value: msgs.encPaPacRequest(include) }];
  };
  const declined = await tgtFor('alice', password,
                                { padata: request(false) });
  const implicit = await tgtFor('alice', password);
  const asked = await tgtFor('alice', password, { padata: request(true) });
  if (!t.check(!!declined && !!implicit && !!asked,
               'precondition: three TGTs for alice')) {
    log.debug("Leaving pacRequestSection(). No TGTs.");
    return;
  }
  const etype = declined.ticket.encPart.etype;
  const krbtgt = await keyOf(['krbtgt', REALM], REALM, etype);
  t.equal(pacOf(await openTicket(declined.ticket, krbtgt)).count, 0,
          'C1. include-pac=FALSE: a TGT with NO PAC');
  const svc = await wire.tgsExchange(T, declined, spn(SERVICE), REALM);
  const svcPart = svc.ok ? await openTicket(svc.ticket,
    await keyOf(SERVICE, REALM, svc.ticket.encPart.etype)) : null;
  t.check(svc.ok && pacOf(svcPart).count === 0,
          'C2. and the service ticket bought with it has none either — the ' +
          'KDC carries the TGT\'s authorization data forward rather than ' +
          'looking the account up again', String(svc.error));
  const attrs = async function (tgt) {
    log.debug("Entering attrs().");
    const pac = pacOf(await openTicket(tgt.ticket, krbtgt)).pac;
    const buffer = pac ? kpac.bufferOfType(pac, kpac.TYPE.ATTRIBUTES_INFO)
                       : null;
    log.debug("Leaving attrs().");
    return buffer && buffer.parsed ? buffer.parsed.flagNames : null;
  };
  t.equal(JSON.stringify(await attrs(implicit)),
          JSON.stringify(['PAC_WAS_GIVEN_IMPLICITLY']),
          'C3. no PA-PAC-REQUEST: a PAC, marked PAC_WAS_GIVEN_IMPLICITLY');
  t.equal(JSON.stringify(await attrs(asked)),
          JSON.stringify(['PAC_WAS_REQUESTED']),
          'C4. include-pac=TRUE: marked PAC_WAS_REQUESTED, which is what ' +
          'shows the padata was read at all');
  log.debug("Leaving pacRequestSection().");
}

// D. -------------------------------------------------------------------------
async function partnerSection(t, tgt, password) {
  log.debug("Entering partnerSection().");
  t.log.info('=== D. the development partner realm ' + PARTNER + ' ===');
  const target = ['HTTP', 'app.' + PARTNER.toLowerCase()];
  const referred = await wire.tgsExchange(T, tgt, spn(target), REALM);
  if (!t.check(referred.ok &&
               referred.sname.name.join('/') === 'krbtgt/' + PARTNER,
               'D1. asking for ' + target.join('/') + ' is not an error but ' +
               'a REFERRAL: a ticket for krbtgt/' + PARTNER,
               referred.ok ? referred.sname.name.join('/')
                           : String(referred.error))) {
    log.debug("Leaving partnerSection(). No referral.");
    return;
  }
  t.check(referred.flagNames.indexOf('initial') < 0,
          'D2. a referral ticket is not initial', referred.flagNames.join(','));
  const etype = referred.ticket.encPart.etype;
  const trustKey = await keyOf(['krbtgt', PARTNER], REALM, etype);
  const localKrbtgt = await keyOf(['krbtgt', REALM], REALM, etype);
  const refPart = await openTicket(referred.ticket, trustKey);
  t.check(!!refPart && !(await openTicket(referred.ticket, localKrbtgt)),
          'D3. sealed with the TRUST key, which this realm\'s own krbtgt key ' +
          'does not open — a real referral, not a renamed local ticket');
  t.check(!!refPart && refPart.crealm === REALM &&
          (!refPart.transited || refPart.transited.contents.length === 0),
          'D4. the client\'s realm travels unchanged and a direct trust ' +
          'transits nothing (RFC 4120 3.3.3.2)',
          JSON.stringify(refPart && refPart.transited));

  const followed = await wire.tgsExchange(T, referred, spn(target), PARTNER);
  if (!t.check(followed.ok && followed.srealm === PARTNER &&
               followed.sname.name.join('/') === target.join('/') &&
               followed.client.name.join('/') === 'alice',
               'D5. followed, ' + PARTNER + ' issues the service ticket, ' +
               'still for alice', String(followed.error))) {
    log.debug("Leaving partnerSection(). Not followed.");
    return;
  }
  const sEtype = followed.ticket.encPart.etype;
  const partnerService = { etype: sEtype,
                           key: await keyOf(target, PARTNER, sEtype) };
  const partnerKrbtgt = { etype: sEtype,
    key: await keyOf(['krbtgt', PARTNER], PARTNER, sEtype) };
  const sPart = await openTicket(followed.ticket, partnerService.key);
  const crossed = pacOf(sPart);
  const cInfo = crossed.pac
    ? kpac.bufferOfType(crossed.pac, kpac.TYPE.LOGON_INFO).parsed : null;
  t.check(crossed.count === 1 && crossed.pac.problems.length === 0 &&
          !!cInfo && cInfo.userSid === principals.domainSidFor(REALM) +
            '-1104' && cInfo.groups.some(function (g) {
            return g.relativeId === 512;
          }),
          'D6. the partner\'s service opens it, and the PAC still describes ' +
          'alice in HER domain, groups and all',
          JSON.stringify(cInfo && cInfo.userSid));
  const resigned = crossed.pac ? await kpac.verifySignatures(crossed.pac, {
    serverKey: partnerService, kdcKey: partnerKrbtgt,
    ticketBytes: ticketSigned(sPart) }) : [];
  t.check(signaturesOk(resigned),
          'D7. and verifies under ' + PARTNER + '\'s OWN keys: it was ' +
          'RE-SIGNED', JSON.stringify(resigned));
  const stale = crossed.pac ? await kpac.verifySignatures(crossed.pac, {
    serverKey: { etype: sEtype, key: trustKey },
    kdcKey: { etype: sEtype, key: localKrbtgt } }) : [];
  t.check(stale.filter(function (s) {
    return s.type === kpac.TYPE.SERVER_CHECKSUM;
  }).every(function (s) {
    return s.verified === false;
  }) && stale.length > 0,
          'D8. and NOT under the issuing realm\'s keys — the signatures were ' +
          'recomputed, not passed through');
  const nowhere = await wire.tgsExchange(T, tgt,
    spn(['HTTP', 'app.elsewhere.invalid']), REALM);
  t.check(refusedSaying(nowhere, 7),
          'D9. a realm there is NO trust with is KDC_ERR_S_PRINCIPAL_UNKNOWN ' +
          '— otherwise everything is referred and D1 proves nothing',
          String(nowhere.error));

  const carol = await tgtFor('carol', password, { realm: PARTNER });
  const own = carol ? await wire.tgsExchange(T, carol, spn(target), PARTNER)
                    : null;
  if (!t.check(!!own && own.ok && own.sname.name[0] === 'HTTP',
               'D10. ' + PARTNER + ' serves its own client carol without a ' +
               'referral', own ? String(own.error) : 'no TGT for carol')) {
    log.debug("Leaving partnerSection(). carol.");
    return;
  }
  const oEtype = own.ticket.encPart.etype;
  const oPart = await openTicket(own.ticket,
                                 await keyOf(target, PARTNER, oEtype));
  const oPac = pacOf(oPart);
  const oInfo = oPac.pac
    ? kpac.bufferOfType(oPac.pac, kpac.TYPE.LOGON_INFO).parsed : null;
  t.check(!!oInfo && oInfo.effectiveName === 'carol' &&
          oInfo.logonDomainId.text === principals.DEV_PARTNER_DOMAIN_SID &&
          oInfo.userSid === principals.DEV_PARTNER_DOMAIN_SID + '-2104' &&
          oInfo.logonDomainName === 'PARTNER',
          'D11. carol\'s PAC is in ' + PARTNER + '\'s domain: its SID, her ' +
          'RID 2104, NetBIOS name PARTNER', JSON.stringify(oInfo && [
            oInfo.logonDomainId.text, oInfo.userSid,
            oInfo.logonDomainName]));
  const oSigs = oPac.pac ? await kpac.verifySignatures(oPac.pac, {
    serverKey: { etype: oEtype, key: await keyOf(target, PARTNER, oEtype) },
    kdcKey: { etype: oEtype,
              key: await keyOf(['krbtgt', PARTNER], PARTNER, oEtype) },
    ticketBytes: ticketSigned(oPart) }) : [];
  t.check(signaturesOk(oSigs),
          'D12. signed with ' + PARTNER + '\'s own krbtgt key, not the trust ' +
          'key of the same name', JSON.stringify(oSigs));
  log.debug("Leaving partnerSection().");
}

// A TGT forged with the krbtgt key — a ticket this KDC would have issued at
// some other time, which no client can ask it for now.
async function forgedTgt(user, flags, times) {
  log.debug("Entering forgedTgt(). " + user);
  const profile = kcrypto.etypeById(18);
  const session = kcrypto.randomBytes(profile.keyBytes);
  const cname = { type: msgs.NAME_TYPE.PRINCIPAL, name: [user] };
  const cipher = await profile.encrypt(
    await keyOf(['krbtgt', REALM], REALM, 18),
    kcrypto.KEY_USAGE.KDC_REP_TICKET, msgs.encEncTicketPart(Object.assign({
      flags: flags, key: { etype: 18, key: session }, crealm: REALM,
      cname: cname }, times)));
  log.debug("Leaving forgedTgt().");
  return { ticket: { realm: REALM,
                     sname: { type: msgs.NAME_TYPE.SRV_INST,
                              name: ['krbtgt', REALM] },
                     encPart: { etype: 18, kvno: principals.find(
                       ['krbtgt', REALM], REALM).kvno, cipher: cipher } },
           sessionKey: session, etype: 18, client: cname, realm: REALM };
}

// E. -------------------------------------------------------------------------
async function renewalSection(t, password) {
  log.debug("Entering renewalSection().");
  t.log.info('=== E. renewal ===');
  const krbtgtName = { type: msgs.NAME_TYPE.SRV_INST,
                       name: ['krbtgt', REALM] };
  const tgt = await tgtFor('alice', password,
                           { tillMs: 3600000, rtimeMs: 3 * 3600000 });
  if (!t.check(!!tgt && !!tgt.renewTill && tgt.renewTill > tgt.endtime,
               'precondition: a renewable TGT whose renew-till is past its ' +
               'endtime')) {
    log.debug("Leaving renewalSection(). No TGT.");
    return;
  }
  await new Promise(function (resolve) {
    setTimeout(resolve, 1100);
  });
  // krb5_wire asks for a till eight hours out — past renew-till.
  const renewed = await wire.tgsExchange(T, tgt, krbtgtName, REALM,
                                         { renew: true });
  if (!t.check(renewed.ok, 'E1. the TGT is renewed', String(renewed.error))) {
    log.debug("Leaving renewalSection(). Not renewed.");
    return;
  }
  t.check(renewed.authtime.getTime() === tgt.authtime.getTime() &&
          renewed.endtime > tgt.endtime &&
          renewed.endtime <= tgt.renewTill &&
          renewed.renewTill.getTime() === tgt.renewTill.getTime() &&
          renewed.flagNames.indexOf('initial') < 0,
          'E2. a renewal keeps authtime, extends the ticket no further than ' +
          'renew-till, which itself does not move; and is not initial',
          JSON.stringify([renewed.authtime, tgt.authtime, renewed.endtime,
                          tgt.renewTill, renewed.renewTill]));
  const inside = await openTicket(renewed.ticket,
    await keyOf(['krbtgt', REALM], REALM, renewed.ticket.encPart.etype));
  t.check(!!inside && inside.renewTill.getTime() === tgt.renewTill.getTime() &&
          inside.authtime.getTime() === tgt.authtime.getTime() &&
          inside.endtime.getTime() === renewed.endtime.getTime(),
          'E3. and so does the ticket\'s own copy, which is the one a ' +
          'service reads');
  // STOPPING AT renew-till needs a renew-till nearer than the till asked
  // for, and this KDC sets renew-till by its own renewable lifetime
  // whatever `rtime` said — so the TGT is one it would have issued two hours
  // before that limit, forged with the krbtgt key.
  const near = new Date(Math.floor((Date.now() + 2 * 3600000) / 1000) * 1000);
  const nearTgt = await forgedTgt('alice', [msgs.TICKET_FLAG.RENEWABLE,
                                            msgs.TICKET_FLAG.FORWARDABLE], {
    authtime: new Date(Math.floor((Date.now() - 600000) / 1000) * 1000),
    starttime: new Date(Date.now() - 600000),
    endtime: new Date(Date.now() + 600000),
    renewTill: near });
  const capped = await wire.tgsExchange(T, nearTgt, krbtgtName, REALM,
                                        { renew: true });
  t.check(capped.ok && capped.endtime.getTime() === near.getTime() &&
          capped.renewTill.getTime() === near.getTime(),
          'E3b. asked for eight hours with renew-till two hours out, the ' +
          'renewal stops exactly AT renew-till — uncapped, a renewable ' +
          'ticket never expires', capped.ok
            ? JSON.stringify([capped.endtime, near]) : String(capped.error));
  const elsewhere = await wire.tgsExchange(T, tgt, spn(SERVICE), REALM,
                                           { renew: true });
  t.check(refusedSaying(elsewhere, elsewhere.error && elsewhere.error.code,
                        /SAME service/),
          'E4. RENEW naming another service is refused — it would turn a TGT ' +
          'into a service ticket keeping the TGT\'s life',
          String(elsewhere.error));
  const bob = await tgtFor('bob', password,
                           { kdcOptions: [msgs.KDC_OPTION.FORWARDABLE] });
  const notRenewable = bob && !bob.renewTill
    ? await wire.tgsExchange(T, bob, krbtgtName, REALM, { renew: true })
    : null;
  t.check(!!notRenewable && !notRenewable.ok &&
          /cannot be added afterwards/.test(notRenewable.error.eText),
          'E5. a ticket obtained without RENEWABLE cannot be renewed, and ' +
          'the refusal says renewability is asked for at the start',
          notRenewable ? String(notRenewable.error) : 'bob\'s TGT: ' +
            JSON.stringify(bob && bob.renewTill));
  const stale = await forgedTgt('alice', [msgs.TICKET_FLAG.RENEWABLE,
                                          msgs.TICKET_FLAG.FORWARDABLE], {
    authtime: new Date(Date.now() - 7200000),
    starttime: new Date(Date.now() - 7200000),
    endtime: new Date(Date.now() + 3600000),
    renewTill: new Date(Date.now() - 3600000) });
  const past = await wire.tgsExchange(T, stale, krbtgtName, REALM,
                                      { renew: true });
  t.check(!past.ok && /renew-till passed/.test(past.error.eText),
          'E6. a ticket whose renew-till has passed is refused, naming ' +
          'renew-till rather than its (future) endtime', String(past.error));
  log.debug("Leaving renewalSection().");
}

// F. -------------------------------------------------------------------------
async function forwardedSection(t, tgt) {
  log.debug("Entering forwardedSection().");
  t.log.info('=== F. a forwarded TGT ===');
  const krbtgtName = { type: msgs.NAME_TYPE.SRV_INST,
                       name: ['krbtgt', REALM] };
  const forwarded = await wire.tgsExchange(T, tgt, krbtgtName, REALM,
    { kdcOptions: [msgs.KDC_OPTION.FORWARDED] });
  t.check(forwarded.ok &&
          forwarded.sname.name.join('/') === 'krbtgt/' + REALM &&
          forwarded.flagNames.indexOf('forwarded') >= 0 &&
          forwarded.flagNames.indexOf('forwardable') >= 0,
          'F1. a forwarded TGT is another TICKET-GRANTING ticket, flagged ' +
          'forwarded and still forwardable',
          forwarded.ok ? forwarded.flagNames.join(',')
                       : String(forwarded.error));
  if (forwarded.ok) {
    const anywhere = await wire.tgsExchange(T, forwarded, spn(SERVICE),
                                            REALM);
    t.check(anywhere.ok && anywhere.client.name.join('/') === 'alice',
            'F2. and whoever holds it gets a ticket to anything as alice — ' +
            'unconstrained delegation', String(anywhere.error));
  }
  const old = await forgedTgt('sensitive', [msgs.TICKET_FLAG.FORWARDABLE,
                                            msgs.TICKET_FLAG.INITIAL], {
    authtime: new Date(Date.now() - 60000),
    endtime: new Date(Date.now() + 3600000) });
  const refused = await wire.tgsExchange(T, old, krbtgtName, REALM,
    { kdcOptions: [msgs.KDC_OPTION.FORWARDED] });
  // The ACCOUNT check rather than the forwardable one ("needs a FORWARDABLE
  // ticket to forward"), which this forged ticket would pass.
  t.check(!refused.ok &&
          /is protected from delegation/.test(refused.error.eText) &&
          !/needs a FORWARDABLE/.test(refused.error.eText),
          'F3. a FORWARDABLE TGT of a NOT_DELEGATED account, from before ' +
          'the flag, is still refused — by the ACCOUNT check',
          String(refused.error));
  log.debug("Leaving forwardedSection().");
}

// A TGS-REQ whose body is swapped after the Authenticator's checksum was made
// over the honest one — the assembly krb5_wire.js does right on purpose.
async function swappedBody(tgt) {
  log.debug("Entering swappedBody().");
  const profile = kcrypto.etypeById(tgt.etype);
  const honest = msgs.encKdcReqBody({ kdcOptions: [], realm: REALM,
    sname: spn(SERVICE), till: new Date(Date.now() + 3600000), nonce: 77,
    etypes: [18] });
  const swapped = msgs.encKdcReqBody({ kdcOptions: [], realm: REALM,
    sname: spn(['host', 'ws01.' + DOMAIN]),
    till: new Date(Date.now() + 3600000), nonce: 77, etypes: [18] });
  const now = new Date(Math.floor(Date.now() / 1000) * 1000);
  const authenticator = msgs.encAuthenticator({
    crealm: tgt.realm, cname: tgt.client,
    cksum: { type: profile.checksumType,
             checksum: await profile.checksum(tgt.sessionKey,
               kcrypto.KEY_USAGE.TGS_REQ_AUTH_CKSUM, honest) },
    cusec: 1, ctime: now });
  const apReq = msgs.encApReq({ apOptions: [], ticket: tgt.ticket,
    authenticator: { etype: tgt.etype, cipher: await profile.encrypt(
      tgt.sessionKey, kcrypto.KEY_USAGE.TGS_REQ_AUTH, authenticator) } });
  log.debug("Leaving swappedBody().");
  return msgs.encKdcReq({ msgType: msgs.MSG_TYPE.TGS_REQ,
    padata: [{ type: msgs.PA_TYPE.TGS_REQ, value: apReq }],
    reqBody: { raw: swapped } });
}

// G. -------------------------------------------------------------------------
async function refusalsSection(t, tgt, serviceTicket) {
  log.debug("Entering refusalsSection().");
  t.log.info('=== G. what a TGS-REQ may not do ===');
  const unknown = await wire.tgsExchange(T, tgt,
    spn(['HTTP', 'nosuchhost.elsewhere.invalid']), REALM);
  t.check(refusedSaying(unknown, 7, /no such service/) &&
          /SPN/.test(unknown.error.eText) &&
          /registers a service on first sight/.test(unknown.error.eText),
          'G1. an unregistered SPN is KDC_ERR_S_PRINCIPAL_UNKNOWN naming the ' +
          'Active Directory cause and what this KDC would have registered',
          String(unknown.error));
  for (const host of ['localhost', 'sts', '127.0.0.1', 'anything.' + DOMAIN]) {
    const r = await wire.tgsExchange(T, tgt, spn(['HTTP', host]), REALM);
    t.check(r.ok && r.sname.name.join('/') === 'HTTP/' + host,
            'G2. HTTP/' + host + ', an SPN a client derives for a host this ' +
            'service answers on, is registered on first sight and issued',
            String(r.error));
  }
  const swapped = msgs.readKdcResponse(await T.send(await swappedBody(tgt)));
  t.check(swapped.kind === 'KRB-ERROR' && swapped.error.errorCode === 50 &&
          /checksum does not match/.test(swapped.error.eText || '') &&
          /key usage 6/.test(swapped.error.eText || ''),
          'G3. a body swapped after signing is KRB_AP_ERR_INAPP_CKSUM, ' +
          'naming the checksum and key usage 6',
          JSON.stringify(swapped.error && [swapped.error.errorCode,
                                           swapped.error.eText]));

  const front = ['HTTP', 'frontend.' + DOMAIN];
  const frontTgt = await tgtFor(front.join('/'), 'frontend-service-password');
  if (!t.check(!!frontTgt, 'precondition: a TGT for ' + front.join('/'))) {
    log.debug("Leaving refusalsSection(). No front-end TGT.");
    return;
  }
  const forged = await wire.tgsExchange(T, frontTgt, frontTgt.client, REALM, {
    padata: async function () {
      const pa = await wire.paForUser(frontTgt, 'alice', REALM);
      const value = Uint8Array.from(pa.value);
      value[value.length - 1] ^= 0xff;
      return [{ type: pa.type, value: value }];
    }
  });
  t.check(!forged.ok && /checksum does not verify/.test(forged.error.eText),
          'G4. S4U2Self with a PA-FOR-USER whose checksum does not verify is ' +
          'refused, saying so', String(forged.error));
  const toAnother = await wire.tgsExchange(T, frontTgt,
    spn(['HTTP', 'backend.' + DOMAIN]), REALM, {
      padata: async function () {
        return [await wire.paForUser(frontTgt, 'alice', REALM)];
      }
    });
  t.check(!toAnother.ok && /ticket to YOURSELF/.test(toAnother.error.eText),
          'G5. S4U2Self naming ANOTHER service is refused — PA-FOR-USER ' +
          'alone would otherwise buy a ticket to anything as anybody',
          String(toAnother.error));
  const borrowed = await wire.tgsExchange(T, frontTgt,
    spn(['HTTP', 'backend.' + DOMAIN]), REALM, {
      kdcOptions: [msgs.KDC_OPTION.CNAME_IN_ADDL_TKT],
      additionalTickets: [serviceTicket.ticket]
    });
  t.check(!borrowed.ok && /addressed to itself/.test(borrowed.error.eText),
          'G6. S4U2Proxy with evidence addressed to ANOTHER service is ' +
          'refused — or every service ticket anyone holds would be a ' +
          'delegation credential', String(borrowed.error));
  log.debug("Leaving refusalsSection().");
}

async function run(t) {
  log.debug("Entering run().");
  const password = String(config.value('krb5.userPassword'));
  const tgt = await tgtFor('alice', password);
  if (!t.check(!!tgt, 'precondition: a TGT for alice')) {
    log.debug("Leaving run(). No TGT.");
    return;
  }
  const serviceTicket = await serviceTicketSection(t, tgt);
  if (serviceTicket) {
    await pacSection(t, tgt, serviceTicket, password);
  }
  await pacRequestSection(t, password);
  await partnerSection(t, tgt, password);
  await renewalSection(t, password);
  await forwardedSection(t, tgt);
  if (serviceTicket) {
    await refusalsSection(t, tgt, serviceTicket);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kerberos_tgs_exchange',
  describe: 'the TGS exchange — a service ticket, the PAC verified under the ' +
            'right keys, PA-PAC-REQUEST, the partner realm\'s referral and ' +
            're-signing, renewal, a forwarded TGT — and what a TGS-REQ may ' +
            'not do (moved from the parent)',
  run: run
};
