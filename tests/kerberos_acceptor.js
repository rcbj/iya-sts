// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: kerberos_acceptor.js
// ===========================================================================
// THE KERBEROS ACCEPTOR AND THE SPNEGO NEGOTIATION AROUND IT, OUTCOME BY
// OUTCOME (from the parent project, 2026-10-22; added here 2026-11-14).
//
// Two parent jobs drove these through doors #595 removed: the AP half of
// `tests/krb5_tgs_ap.js` presented tickets to `krb5_service.js`'s TCP socket,
// and `tests/krb5_spnego_http.js` to `/spnego/protected`. Both moved here,
// and drive what stayed — `krb5_service.accept()` and
// `spnego_exchange.negotiate()`, the functions `/authn/spnego` calls — with
// tickets from `kdc.handleMessage()` and the local client
// `tests/protocol/krb5_wire.js`, in development mode:
//
//   A. THE ACCEPTOR'S REFUSALS, each a KRB-ERROR naming its cause: a bare
//      AP-REQ with no GSS wrapper; a genuine ticket for ANOTHER service; a
//      key version the service does not hold ("the keytab is out of
//      date"); an Authenticator twenty minutes old, quoting the tolerance;
//      an Authenticator whose checksum is not 0x8003. And the SPNs a client
//      derives from this service's own hosts (HTTP/localhost, HTTP/sts,
//      HTTP/127.0.0.1), accepted.
//   B. THE NEGOTIATION'S OUTCOMES: Microsoft's mis-typed Kerberos OID
//      accepted and ECHOED; a bare Kerberos token accepted and said to be
//      one; the acceptor's own mechListMIC, verifying under its subkey;
//      request-mic completing in a second round trip without supportedMech;
//      mutual authentication withheld (no AP-REP); no mechanism in common,
//      both ways round (reject, no supportedMech); a pessimistic NegTokenInit
//      (accept-incomplete, naming the mechanism); a MIC over the
//      `[0]`-tagged list, a tampered MIC and an edited mechanism list
//      (reject); a continuation with no negotiation (reject).
//
// Already held elsewhere and NOT repeated: the 401 challenge, the
// accept-completed token with its AP-REP echo, a replay (34), a TGT at the
// acceptor (35), a corrupted Authenticator and the HTTP layer's refusals
// (`protocol/sts_kerberos_spnego.js`); continuations matched by cookie and by
// MIC (`cluster_limits_challenges_retention.js` D); what a sign-in claims
// (`spnego_identity.js`).
//
// IN PROCESS because the negotiation's knobs (`supported`, `wantMic`,
// `mutualOff`) are the library's and no HTTP door passes them since #595,
// and because a stale key version and a non-0x8003 checksum have to be
// built with keys only the inside holds.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
require('../common/app');
const principals = require('../kerberos/krb5_principals.js');
const kdc = require('../kerberos/krb5_kdc.js');
const krb5Service = require('../kerberos/krb5_service.js');
const exchange = require('../kerberos/spnego_exchange.js');
const prim = require('../kerberos/krb5_primitives.js');
const asn1 = require('../kerberos/krb5_asn1.js');
const kcrypto = require('../kerberos/krb5_crypto.js');
const gss = require('../kerberos/krb5_gss.js');
const wire = require('./protocol/krb5_wire.js');

const log = require('bunyan').createLogger({ name: 'kerberos_acceptor',
  level: process.env.LOG_LEVEL || 'info' });

const msgs = wire.msgs;
const spnego = wire.spnego;
const REALM = principals.REALM;
const DOMAIN = REALM.toLowerCase();
const DOOR = '/authn/spnego';
const NTLM = '1.3.6.1.4.1.311.2.2.10';
const WINDOWS = [spnego.KRB5_MECH_OID, spnego.MS_KRB5_MECH_OID, NTLM];
const CLIENT = 'kerberos-acceptor-' + Date.now().toString(36);
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

// A service ticket for `name` (default: the acceptor's own SPN).
async function ticketFor(tgt, name) {
  log.debug("Entering ticketFor().");
  const r = await wire.tgsExchange(T, tgt,
    spn(name || krb5Service.SERVICE_PRINCIPAL), REALM);
  log.debug("Leaving ticketFor().");
  return r.ok ? r : null;
}

// What the acceptor refused with: { ok, code, eText }.
async function presented(tokenBytes) {
  log.debug("Entering presented().");
  const result = await krb5Service.accept(Buffer.from(tokenBytes),
                                          { record: false });
  if (result.ok) {
    log.debug("Leaving presented(). Accepted.");
    return { ok: true, result: result };
  }
  const error = result.reply ? msgs.readKrbError(result.reply) : null;
  log.debug("Leaving presented(). Refused.");
  return { ok: false, code: error ? error.errorCode : null,
           eText: error ? error.eText || '' : '', result: result };
}

function refusal(r, code, text) {
  log.debug("Entering refusal().");
  log.debug("Leaving refusal().");
  return !r.ok && r.code === code && (!text || text.test(r.eText));
}

// A. -------------------------------------------------------------------------
async function acceptorSection(t, tgt, ticket) {
  log.debug("Entering acceptorSection().");
  t.log.info('=== A. the acceptor, ticket by ticket ===');
  const good = await wire.apRequest(ticket);
  const accepted = await presented(good.token);
  t.check(accepted.ok, 'A0. precondition: a fresh AP-REQ for ' +
          krb5Service.SERVICE_PRINCIPAL.join('/') + ' is accepted',
          accepted.code + ' ' + accepted.eText);

  const bare = await presented((await wire.apRequest(ticket)).apReq);
  t.check(refusal(bare, 60, /InitialContextToken|0x60|wrap/i),
          'A1. a bare AP-REQ (0x6e) with no GSS InitialContextToken around ' +
          'it is KRB_ERR_GENERIC naming the missing wrapper',
          bare.code + ' ' + bare.eText);

  const other = await ticketFor(tgt, ['host', 'ws01.' + DOMAIN]);
  const wrongService = other
    ? await presented((await wire.apRequest(other)).token) : null;
  t.check(!!wrongService &&
          refusal(wrongService, 35, /this ticket is for host\/ws01/),
          'A2. a genuine ticket for ANOTHER service is KRB_AP_ERR_NOT_US, ' +
          'naming whom it is for', wrongService &&
            wrongService.code + ' ' + wrongService.eText);

  // The ticket re-addressed to a key version the service never had.
  const stale = gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ,
    msgs.encApReq({
      apOptions: [msgs.AP_OPTION.MUTUAL_REQUIRED],
      ticket: { realm: REALM, sname: spn(krb5Service.SERVICE_PRINCIPAL),
                encPart: { etype: ticket.ticket.encPart.etype, kvno: 99,
                           cipher: ticket.ticket.encPart.cipher } },
      authenticator: { etype: ticket.etype,
                       cipher: kcrypto.randomBytes(64) } }));
  const kvno = await presented(stale);
  t.check(refusal(kvno, 44, /key version/) &&
          /keytab is out of date/.test(kvno.eText),
          'A3. a key version the service does not hold is ' +
          'KRB_AP_ERR_BADKEYVER, spelling out that the keytab is out of date',
          kvno.code + ' ' + kvno.eText);

  const old = await presented((await wire.apRequest(ticket,
    { ctimeOffsetMs: -20 * 60 * 1000 })).token);
  t.check(refusal(old, 37, /\d+ seconds/) && /tolerance/.test(old.eText),
          'A4. an Authenticator twenty minutes old is KRB_AP_ERR_SKEW, ' +
          'quoting the difference and the tolerance', old.code + ' ' +
            old.eText);

  const profile = kcrypto.etypeById(ticket.etype);
  const notGss = msgs.encAuthenticator({
    crealm: ticket.realm, cname: ticket.client,
    cksum: { type: profile.checksumType,
             checksum: await profile.checksum(ticket.sessionKey,
               kcrypto.KEY_USAGE.AP_REQ_AUTH_CKSUM, prim.utf8('not 0x8003')) },
    cusec: 1, ctime: new Date(Math.floor(Date.now() / 1000) * 1000),
    seqNumber: 7 });
  const checksum = await presented(gss.encodeInitialContextToken(
    gss.TOK_ID.AP_REQ, msgs.encApReq({
      apOptions: [msgs.AP_OPTION.MUTUAL_REQUIRED], ticket: ticket.ticket,
      authenticator: { etype: ticket.etype, cipher: await profile.encrypt(
        ticket.sessionKey, kcrypto.KEY_USAGE.AP_REQ_AUTH, notGss) } })));
  t.check(refusal(checksum, 50, /32771|0x8003/),
          'A5. an Authenticator whose checksum is not 0x8003 is ' +
          'KRB_AP_ERR_INAPP_CKSUM, naming the type a GSS caller must send',
          checksum.code + ' ' + checksum.eText);

  for (const host of ['localhost', 'sts', '127.0.0.1']) {
    const derived = await ticketFor(tgt, ['HTTP', host]);
    const r = derived
      ? await presented((await wire.apRequest(derived)).token) : null;
    t.check(!!r && r.ok,
            'A6. a ticket for HTTP/' + host + ' — the SPN a client derives ' +
            'reaching this service at ' + host + ' — is accepted',
            r ? r.code + ' ' + r.eText : 'no ticket for HTTP/' + host);
  }
  log.debug("Leaving acceptorSection().");
}

// B. -------------------------------------------------------------------------
// A request as negotiate() reads one.
function request(tokenBytes) {
  log.debug("Entering request().");
  const headers = tokenBytes
    ? { authorization: 'Negotiate ' +
        Buffer.from(tokenBytes).toString('base64') } : {};
  log.debug("Leaving request().");
  return { headers: headers, ip: '127.0.0.1',
           connection: { remoteAddress: '127.0.0.1' },
           get: function (name) {
             return headers[String(name).toLowerCase()];
           } };
}

// negotiate() with `opts`, and its token read back.
async function negotiated(tokenBytes, opts) {
  log.debug("Entering negotiated().");
  const verdict = await exchange.negotiate(request(tokenBytes),
    Object.assign({ door: DOOR, record: false }, opts || {}));
  const match = /^Negotiate\s+(\S+)/.exec(verdict.wwwAuthenticate || '');
  const token = match ? spnego.decodeNegotiationToken(
    new Uint8Array(Buffer.from(match[1], 'base64'))) : null;
  log.debug("Leaving negotiated(). " + verdict.code);
  return { verdict: verdict, token: token,
           header: verdict.wwwAuthenticate };
}

// A NegTokenInit around a fresh AP-REQ. `mic`: 'list', 'tagged', 'tampered',
// or an array of mechanisms the MIC covers instead of the ones sent.
async function initFor(ticket, mechs, mic) {
  log.debug("Entering initFor().");
  const built = await wire.apRequest(ticket);
  let mechListMic = null;
  if (mic) {
    const covered = Array.isArray(mic) ? mic : mechs;
    const der = spnego.mechTypeListDer(covered);
    mechListMic = await spnego.computeMechListMic({
      key: built.subkey.key, etype: built.subkey.etype, role: 'initiator',
      mechListDer: mic === 'tagged' ? asn1.encContext(0, der) : der,
      sequenceNumber: 0 });
    if (mic === 'tampered') {
      mechListMic = prim.toBytes(mechListMic).slice();
      mechListMic[mechListMic.length - 1] ^= 0x01;
    }
  }
  const init = spnego.encodeNegTokenInit({ mechTypes: mechs,
                                           mechToken: built.token,
                                           mechListMic: mechListMic });
  log.debug("Leaving initFor().");
  return { token: init.token, mechListDer: init.mechListDer, built: built };
}

function rejected(n, code) {
  log.debug("Entering rejected().");
  log.debug("Leaving rejected().");
  return !n.verdict.ok && n.verdict.code === code && !!n.token &&
         n.token.negState === spnego.NEG_STATE.REJECT;
}

async function negotiationSection(t, ticket) {
  log.debug("Entering negotiationSection().");
  t.log.info('=== B. the negotiation, outcome by outcome ===');
  const NS = spnego.NEG_STATE;

  const ms = await negotiated((await initFor(ticket,
    [spnego.MS_KRB5_MECH_OID, NTLM])).token);
  t.check(ms.verdict.ok && ms.token.supportedMech === spnego.MS_KRB5_MECH_OID,
          'B1. Microsoft\'s mis-typed Kerberos OID (1.2.840.48018.1.2.2), ' +
          'which every Windows client offers, is accepted and ECHOED in the ' +
          'spelling the client used', ms.verdict.code + ' ' +
            (ms.token && ms.token.supportedMech));

  const raw = await negotiated((await wire.apRequest(ticket)).token);
  t.check(raw.verdict.ok && raw.verdict.rawKerberos === true,
          'B2. a bare RFC 4121 token with no SPNEGO around it is accepted, ' +
          'and the verdict says it was not a negotiation — none of ' +
          'SPNEGO\'s downgrade protection applied', raw.verdict.code);

  const withMic = await initFor(ticket, WINDOWS, 'list');
  const micd = await negotiated(withMic.token);
  const echoed = micd.verdict.ok ? await wire.readNegotiate(micd.header,
    ticket, withMic.built) : null;
  const acceptorMic = micd.token && micd.token.mechListMic &&
                      echoed && echoed.apRep && echoed.apRep.acceptorSubkey
    ? await spnego.verifyMechListMic({
      key: echoed.apRep.acceptorSubkey.key,
      etype: echoed.apRep.acceptorSubkey.etype,
      mic: micd.token.mechListMic, mechListDer: withMic.mechListDer })
    : null;
  t.check(micd.verdict.ok && micd.verdict.micVerified === true &&
          !!acceptorMic && acceptorMic.ok &&
          acceptorMic.senderRole === 'acceptor',
          'B3. the client\'s mechListMIC verifies, and the acceptor returns ' +
          'its OWN over the same list, keyed with its subkey, in the ' +
          'acceptor\'s role', JSON.stringify([micd.verdict.code,
            acceptorMic && acceptorMic.senderRole]));

  const pending = await initFor(ticket, WINDOWS);
  const first = await negotiated(pending.token, { wantMic: true });
  t.check(first.verdict.code === 'request-mic' &&
          first.verdict.status === 401 && first.token &&
          first.token.negState === NS.REQUEST_MIC,
          'B4. an acceptor that wants the MIC answers request-mic (3) with ' +
          '401, not 200', first.verdict.code);
  const mic = await spnego.computeMechListMic({
    key: pending.built.subkey.key, etype: pending.built.subkey.etype,
    role: 'initiator', mechListDer: pending.mechListDer,
    sequenceNumber: 0 });
  const second = await negotiated(spnego.encodeNegTokenResp(
    { mechListMic: mic }), { wantMic: true });
  t.check(second.verdict.ok && second.token &&
          second.token.negState === NS.ACCEPT_COMPLETED &&
          second.token.supportedMech === null,
          'B5. the continuation carrying the MIC completes it, WITHOUT ' +
          'supportedMech — legal only in the first reply',
          second.verdict.code + ' ' + (second.token &&
            second.token.supportedMech));

  const quiet = await negotiated((await initFor(ticket, WINDOWS)).token,
                                 { mutualOff: true });
  t.check(quiet.verdict.ok && quiet.token &&
          quiet.token.negState === NS.ACCEPT_COMPLETED &&
          quiet.token.responseToken === null && quiet.verdict.mutual === false,
          'B6. with mutual authentication withheld the context completes ' +
          'with NO AP-REP: nothing proved who answered', quiet.verdict.code);

  const ntlmOnly = await negotiated((await initFor(ticket,
    [NTLM, '1.3.6.1.4.1.311.2.2.30'])).token);
  t.check(rejected(ntlmOnly, 'no-common-mechanism') &&
          ntlmOnly.token.supportedMech === null,
          'B7. a client offering nothing this acceptor performs is ' +
          'rejected, naming no mechanism', ntlmOnly.verdict.code);
  const none = await negotiated((await initFor(ticket, WINDOWS)).token,
                                { supported: [] });
  t.check(rejected(none, 'no-common-mechanism'),
          'B8. and an acceptor supporting nothing rejects a perfectly good ' +
          'ticket', none.verdict.code);

  const pessimistic = await negotiated(spnego.encodeNegTokenInit(
    { mechTypes: WINDOWS }).token);
  t.check(pessimistic.verdict.code === 'no-mech-token' && pessimistic.token &&
          pessimistic.token.negState === NS.ACCEPT_INCOMPLETE &&
          pessimistic.token.supportedMech === spnego.KRB5_MECH_OID,
          'B9. a NegTokenInit with no mechToken is accept-incomplete (1), ' +
          'not reject, and names the mechanism to build a token for',
          pessimistic.verdict.code);

  const tagged = await negotiated((await initFor(ticket, WINDOWS,
    'tagged')).token);
  t.check(rejected(tagged, 'bad-mech-list-mic'),
          'B10. a mechListMIC over [0] MechTypeList rather than the ' +
          'MechTypeList is rejected — the ticket is fine, the list is not ' +
          'protected', tagged.verdict.code);
  const tampered = await negotiated((await initFor(ticket, WINDOWS,
    'tampered')).token);
  t.check(rejected(tampered, 'bad-mech-list-mic'),
          'B11. a mechListMIC with one bit flipped is rejected',
          tampered.verdict.code);
  const edited = await negotiated((await initFor(ticket,
    [spnego.KRB5_MECH_OID], WINDOWS)).token);
  t.check(rejected(edited, 'bad-mech-list-mic'),
          'B12. a mechanism list edited after the MIC was made over it is ' +
          'caught by the MIC', edited.verdict.code);

  const nowhere = await negotiated(spnego.encodeNegTokenResp(
    { mechListMic: new Uint8Array(16) }));
  t.check(!nowhere.verdict.ok && nowhere.token &&
          nowhere.token.negState === NS.REJECT,
          'B13. a bare NegTokenResp with no negotiation in progress is ' +
          'rejected', nowhere.verdict.code);
  log.debug("Leaving negotiationSection().");
}

async function run(t) {
  log.debug("Entering run().");
  const got = await wire.asExchange(T, REALM, CLIENT,
    { password: String(config.value('krb5.userPassword')) });
  const tgt = got.tgt;
  const ticket = tgt ? await ticketFor(tgt) : null;
  if (!t.check(!!ticket, 'precondition: a ticket for the acceptor\'s SPN ' +
               krb5Service.SERVICE_PRINCIPAL.join('/'),
               JSON.stringify(got.second || got.first))) {
    log.debug("Leaving run(). No ticket.");
    return;
  }
  await acceptorSection(t, tgt, ticket);
  await negotiationSection(t, ticket);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kerberos_acceptor',
  describe: 'krb5_service.accept()\'s refusals and the derived SPNs, and ' +
            'every outcome of spnego_exchange.negotiate() no HTTP door can ' +
            'reach since #595 (moved from the parent)',
  run: run
};
