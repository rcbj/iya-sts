'use strict';
//
// File: krb5_fast.ts
//
// ===========================================================================
// RFC 6113 FAST, RFC 6560 OTP PRE-AUTHENTICATION AND RFC 8129 AUTHENTICATION
// INDICATORS, FOR THE AS EXCHANGE (#173, 2026-09-22).
//
// **WHY THIS EXISTS.** In product a person's Kerberos keys are derived from
// their directory password (`krb5_person_keys.ts`), and until this file an
// AS-REQ pre-authenticated with that password alone got a ticket-granting
// ticket — through SPNEGO, a session in every browser protocol — for a person
// the sign-in screen would have asked for a TOTP code or a security key. It
// was #101's hole at a sixth door. Unlike the other five, this door CAN ask
// for more, because Kerberos standardised it: FAST armors the AS exchange in a
// tunnel keyed by a ticket the client HOST already holds, and OTP
// pre-authentication carries a one-time code inside it. So the refusal of a
// password alone (`krb5_kdc.js`, `mode.issuesTicketsOnPasswordAlone()`) comes
// with a way in, and this file is that way in.
//
// ---------------------------------------------------------------------------
// WHAT IS IMPLEMENTED, BY SECTION.
//
//   * RFC 6113 section 5.4.1.1 — the ONE armor type, FX_FAST_ARMOR_AP_REQUEST:
//     an AP-REQ carrying a TGT for this realm's own TGS and a subkey. The armor
//     key is KRB-FX-CF2(subkey, ticket session key, "subkeyarmor",
//     "ticketarmor") — `common/crypto.js`, section 9. The TGT is the one the
//     client HOST got with its own keytab (a service principal created at
//     /admin/kerberos/principals), which is what makes the armor authenticate
//     the KDC to the client. Anonymous PKINIT (section 5.4.1.1's second and
//     third ways) is not implemented, and neither is PKINIT at all (#179).
//   * Section 5.4.2 — the request: the armored KrbFastReq's req-body and padata
//     REPLACE the outer ones, the req-checksum binds the two, and a critical
//     FAST option this KDC does not implement (hide-client-names is the one
//     defined) is KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS.
//   * Sections 5.4.3 and 5.4.4 — the reply: every padata inside the encrypted
//     KrbFastResponse, a KrbFastFinished over the ticket, the reply key ALWAYS
//     strengthened, and every error after the armor opened carried as
//     PA-FX-ERROR inside it. A PA-FX-COOKIE rides in every
//     KDC_ERR_PREAUTH_REQUIRED (section 5.2's MUST).
//   * Section 5.4.6 — the encrypted challenge, the password factor inside
//     FAST, with its KDC half and its replay check (a claim on the ciphertext,
//     `cluster/cluster_claims.js`).
//   * RFC 6560 — OTP pre-authentication, four-pass (the nonce from the
//     PA-OTP-CHALLENGE, bound by the cookie) and two-pass (a PA-ENC-TS-ENC).
//     THE ONE TOKEN IT OFFERS IS THE PERSON'S AUTHENTICATOR APP, and the code
//     is verified by `common/credentials.ts`'s `verifyTotpAsync()` — the SAME
//     verifier and the SAME once-only step counter the sign-in screen's
//     `/authn/totp` spends, so one code cannot be used at both doors.
//   * RFC 8129 over RFC 7751 — a ticket issued that way carries the
//     authentication indicator `otp` in an AD-CAMMAC inside AD-IF-RELEVANT,
//     with a kdc-verifier and a svc-verifier; the TGS copies it into the
//     service tickets a TGT buys, and the acceptor reads it for
//     `kerberos/spnego_authn.ts`.
//
// ---------------------------------------------------------------------------
// PASSWORD AND CODE, IN ONE EXCHANGE — AND WHY THAT SHAPE.
//
// RFC 6560 section 3.3 lets a KDC ask for a PIN beside the OTP: the token
// information says "collect-pin" and "separate-pin-required", and the client
// sends the PIN in `otp-pin`. Here the PIN IS THE PERSON'S PASSWORD, checked
// by deriving the Kerberos key from it (RFC 3961 string-to-key with the
// principal's own salt) and comparing it with the key the KDC holds — so a
// #101 APP PASSWORD, which never derives a Kerberos key, is refused like any
// other wrong password. That makes one OTP exchange an authentication with
// BOTH factors, which is what RFC 6113 section 5.3's authentication sets would
// otherwise have expressed: MIT's `kinit` implements the PIN and not the sets,
// so the PIN is the form a real client can use.
//
// The OTP value travels in `otp-value` rather than as key material
// ("must-encrypt-nonce" unset), which RFC 6560 section 3.2 allows only where
// the armor already authenticates the KDC. A host-key TGT armor does, and it is
// the only armor accepted here. The reply key is then the armor key
// (section 3.6), strengthened.
//
// **THE ORDER OF THE CHECKS IS THE PRIVACY OF THE PASSWORD.** The nonce, then
// the PIN, then the code: a wrong password is KDC_ERR_PREAUTH_FAILED before
// any code is looked at, so an OTP request never spends a step for somebody
// who does not know the password.
//
// ---------------------------------------------------------------------------
// WHERE IT SITS. A LIBRARY (rule 3): it registers nothing. It is built by
// `krb5_person_keys.ts`, which hands it to `krb5_principals.js` as part of the
// KEY SOURCE — the slot `krb5_kdc.js` already reads — so the KDC reaches it
// through `principals.preauthProvider()` and gains no require. That is the
// parent project's constraint (kerberos/CLAUDE.md): `krb5_kdc.js`,
// `krb5_service.js` and `spnego.js` are its files, and nothing here, nor
// `common/credentials.ts`, joins the COPY set their require closure is. A
// process without the key source (the parent's in-process jobs) has no FAST
// and behaves exactly as before.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import config = require('../common/config');
import cryptoLib = require('../common/crypto');
import mode = require('../common/mode');
import errorCodes = require('../common/error_codes');
import credentials = require('../common/credentials');
import claims = require('../cluster/cluster_claims');
import kcrypto = require('./krb5_crypto');
import prim = require('./krb5_primitives');
import asn1 = require('./krb5_asn1');
import msgs = require('./krb5_messages');
import principals = require('./krb5_principals');
import codec = require('./krb5_fast_codec');

type Json = any;

// A Kerberos key as the codec carries one. `kvno` is the krbtgt's key
// version where the key is one (#169), so a cookie says which it was sealed
// under.
interface Key {
  etype: number;
  key: Uint8Array;
  kvno?: number | null;
}

// One AS exchange's FAST state, from openAsRequest() to the reply.
interface FastState {
  armorKey: Key;
  nonce: number;
  realm: string;
  fastOptions: number[];
  cookie: Json;
  armorClient: string;
}

// A refusal, in the shape `krb5_kdc.js` hands to errorReply().
interface Refusal {
  ok: false;
  code: number;
  errorCode: string;
  eText: string;
}

interface Krb5FastDeps {
  log: typeof helpers.log;
  config: typeof config;
  cryptoLib: Json;
  mode: typeof mode;
  errorCodes: typeof errorCodes;
  credentials: Json;
  claims: Json;
  kcrypto: Json;
  prim: Json;
  asn1: Json;
  msgs: Json;
  principals: Json;
  codec: typeof codec;
}

// The magic in front of a cookie this KDC sealed, so that somebody else's —
// an empty "MIT" cookie, another KDC's — is recognised as not ours rather
// than failing to decrypt.
const COOKIE_MAGIC = 'STS1';

// How long a cookie, and so a PA-OTP-CHALLENGE's nonce, may be answered.
// MIT's KDC allows ten minutes; so does this one.
const COOKIE_LIFETIME_MS = 10 * 60 * 1000;

// The indicator an OTP pre-authentication puts in a ticket. RFC 8129 section
// 3 allows a site-defined string without a colon; `otp` is what MIT's KDC
// uses for the same thing.
const OTP_INDICATOR = 'otp';

// RFC 6113 section 5.4.2's one defined critical FAST option, and the name it
// puts in its place: RFC 6112's anonymous principal.
const HIDE_CLIENT_NAMES = 1;
const ANONYMOUS_REALM = 'WELLKNOWN:ANONYMOUS';
const ANONYMOUS_NAME = { type: 11, name: ['WELLKNOWN', 'ANONYMOUS'] };

// The claim scope an encrypted challenge is spent under (RFC 6113 section
// 5.4.6's replay check: the same CIPHERTEXT twice).
const CHALLENGE_SCOPE = 'krb5.encrypted-challenge';

class Krb5Fast {
  static readonly OTP_INDICATOR = OTP_INDICATOR;
  static readonly COOKIE_LIFETIME_MS = COOKIE_LIFETIME_MS;
  static readonly CHALLENGE_SCOPE = CHALLENGE_SCOPE;

  constructor(private readonly deps: Krb5FastDeps) {
    deps.log.debug('Entering Krb5Fast.constructor().');
    deps.log.debug('Leaving Krb5Fast.constructor().');
  }

  static defaultDeps(): Krb5FastDeps {
    helpers.log.debug('Entering Krb5Fast.defaultDeps().');
    helpers.log.debug('Leaving Krb5Fast.defaultDeps().');
    return {
      log: helpers.log,
      config: config,
      cryptoLib: cryptoLib,
      mode: mode,
      errorCodes: errorCodes,
      credentials: credentials,
      claims: claims,
      kcrypto: kcrypto,
      prim: prim,
      asn1: asn1,
      msgs: msgs,
      principals: principals,
      codec: codec
    };
  }

  // -------------------------------------------------------------------------
  // SMALL THINGS.
  // -------------------------------------------------------------------------
  private refuse(code: number, errorCode: string, eText: string): Refusal {
    const { log } = this.deps;
    log.debug('Entering Krb5Fast.refuse(). ' + errorCode);
    log.info('krb5-fast: refusing with ' + code + ' (' + errorCode + '): ' +
             eText);
    log.debug('Leaving Krb5Fast.refuse().');
    return { ok: false, code: code, errorCode: errorCode, eText: eText };
  }

  // The KDC's own idea of now, which `krb5.clockOffset` moves on purpose
  // (krb5_kdc.js's kdcTime()) — in development only (#181), so it is read as
  // in force, the way that function reads it.
  private now(): Date {
    const { log, mode } = this.deps;
    log.debug('Entering Krb5Fast.now().');
    log.debug('Leaving Krb5Fast.now().');
    return new Date(Date.now() +
                    (Number(mode.valueInForce('krb5.clockOffset')) || 0) *
                    1000);
  }

  private skewMs(): number {
    const { log, config } = this.deps;
    log.debug('Entering Krb5Fast.skewMs().');
    log.debug('Leaving Krb5Fast.skewMs().');
    return Number(config.value('krb5.clockSkew') || 300) * 1000;
  }

  private cf2(k1: Key, k2: Key, pepper1: string, pepper2: string): Key {
    const { log, cryptoLib } = this.deps;
    log.debug('Entering Krb5Fast.cf2(). ' + pepper1 + '/' + pepper2);
    log.debug('Leaving Krb5Fast.cf2().');
    return cryptoLib.krbFxCf2(k1, k2, pepper1, pepper2);
  }

  // The krbtgt key of a realm this KDC serves, at its first enctype — what a
  // cookie is sealed under. Null when there is no ticket-granting service.
  //
  // **A ROTATION (#169) MOVES IT**, so the key carries its kvno and a cookie
  // names it. `kvno` asks for a PREVIOUS version still kept — a cookie sealed
  // an instant before a rotation, answered an instant after — and a version
  // neither current nor kept is null: the cookie then opens to nothing and
  // the request is refused as answering no challenge this KDC issued, which
  // is the clean refusal (MIT's client starts the exchange again).
  private async tgsKey(realm: string, kvno?: number | null):
      Promise<Key | null> {
    const { log, principals } = this.deps;
    log.debug('Entering Krb5Fast.tgsKey(). ' + realm);
    const krbtgt = principals.find(['krbtgt', realm], realm);
    const etypes = krbtgt ? principals.supportedEtypes(krbtgt) : [];
    if (!krbtgt || !etypes.length) {
      log.debug('Leaving Krb5Fast.tgsKey(). None.');
      return null;
    }
    if (kvno !== undefined && kvno !== null && krbtgt.directoryKeys &&
        Number(kvno) !== Number(krbtgt.kvno)) {
      const kept = principals.retainedKeyFor(krbtgt, etypes[0], Number(kvno));
      log.debug('Leaving Krb5Fast.tgsKey(). ' + (kept ? 'A kept version.'
                                                      : 'Not held.'));
      return kept ? { etype: etypes[0], key: kept.key, kvno: kept.kvno }
                  : null;
    }
    const key = await principals.longTermKey(krbtgt, etypes[0]);
    log.debug('Leaving Krb5Fast.tgsKey().');
    return { etype: etypes[0], key: key,
             kvno: krbtgt.directoryKeys ? Number(krbtgt.kvno) : null };
  }

  // What the KDC advertises OUTSIDE FAST, in every KDC_ERR_PREAUTH_REQUIRED:
  // PA-FX-FAST with an empty value (RFC 6113 section 5.4.2's MUST). It is
  // what makes MIT's `kinit -T` upgrade an ordinary exchange to an armored
  // one.
  outerAdvertisement(): Json {
    const { log, codec } = this.deps;
    log.debug('Entering Krb5Fast.outerAdvertisement().');
    log.debug('Leaving Krb5Fast.outerAdvertisement().');
    return { type: codec.PA.FX_FAST, value: new Uint8Array(0) };
  }

  // -------------------------------------------------------------------------
  // HIDE-CLIENT-NAMES (RFC 6113 section 5.4.2): when the armored request set
  // it, "the KDC implementing PA-FX-FAST MUST identify the client as the
  // anonymous principal [RFC6112] in the KDC reply and the error response" —
  // the OUTER crealm and cname, which travel in the clear. The real ones stay
  // where only the client reads them: the KrbFastFinished (finishAsReply()),
  // the ticket's own encrypted part, and the inner KRB-ERROR (wrapError()).
  // `outerClient()` answers `{ crealm, cname }` for the outer message.
  // -------------------------------------------------------------------------
  hidesClientNames(fast: FastState | null): boolean {
    const { log } = this.deps;
    log.debug('Entering Krb5Fast.hidesClientNames().');
    const hides = !!fast &&
      (fast.fastOptions || []).indexOf(HIDE_CLIENT_NAMES) !== -1;
    log.debug('Leaving Krb5Fast.hidesClientNames(). ' + hides);
    return hides;
  }

  outerClient(fast: FastState | null, crealm: string, cname: Json): Json {
    const { log } = this.deps;
    log.debug('Entering Krb5Fast.outerClient().');
    const hide = this.hidesClientNames(fast);
    log.debug('Leaving Krb5Fast.outerClient().');
    return hide ? { crealm: ANONYMOUS_REALM, cname: ANONYMOUS_NAME }
                : { crealm: crealm, cname: cname };
  }

  // -------------------------------------------------------------------------
  // THE ARMOR AND THE REQUEST (RFC 6113 sections 5.4.1.1 and 5.4.2).
  //
  // Answers `{ ok: true, fast, padata, reqBody }` — the INNER request, which
  // the KDC answers instead of the outer one — or a refusal. A refusal here is
  // sent unarmored, because until the enc-fast-req opens there is no nonce to
  // bind a KrbFastResponse to; RFC 6113 section 5.4.4 lets a client read it as
  // the KDC being unable to accept the armor.
  // -------------------------------------------------------------------------
  async openAsRequest(request: Json, pa: Json): Promise<Json> {
    const { log, codec, msgs, kcrypto, principals } = this.deps;
    log.debug('Entering Krb5Fast.openAsRequest().');
    let armored;
    try {
      armored = codec.readFastRequest(pa.value);
    } catch (e) {
      log.debug('Caught in Krb5Fast.openAsRequest(): ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Fast.openAsRequest(). Not a PA-FX-FAST-REQUEST.');
      return this.refuse(24, 'STS-KRB-0136', 'PA-FX-FAST does not decode ' +
                         'as a PA-FX-FAST-REQUEST');
    }
    if (!armored.armor ||
        armored.armor.type !== codec.ARMOR_AP_REQUEST) {
      log.debug('Leaving Krb5Fast.openAsRequest(). No usable armor.');
      // RFC 6113 section 5.4.1: an unknown armor type is PREAUTH_FAILED, and
      // section 5.4.2 makes the armor mandatory in an AS-REQ.
      return this.refuse(24, 'STS-KRB-0136', armored.armor
        ? 'armor type ' + armored.armor.type + ' is not implemented here; ' +
          'the one armor type is FX_FAST_ARMOR_AP_REQUEST (1)'
        : 'an AS-REQ armored with FAST must carry its armor');
    }
    const armor = await this.armorFromApReq(armored.armor.value);
    if (!armor.ok) {
      log.debug('Leaving Krb5Fast.openAsRequest(). The armor was refused.');
      return armor;
    }
    const opened = await this.openFastReq(armored, armor.armorKey,
                                          request.reqBody.raw, armor.realm,
                                          armor.client, 'an AS-REQ');
    log.debug('Leaving Krb5Fast.openAsRequest().');
    return opened;
  }

  // -------------------------------------------------------------------------
  // FX_FAST_ARMOR_AP_REQUEST (RFC 6113 section 5.4.1.1): the armor AP-REQ's
  // TGT for a realm this KDC serves, its Authenticator at key usage 11 with a
  // subkey, and the armor key KRB-FX-CF2(subkey, ticket session key,
  // "subkeyarmor", "ticketarmor"). Answers `{ ok: true, armorKey, realm,
  // client }` or a refusal. Split out of openAsRequest() when the TGS exchange
  // gained FAST (#204), where a client MAY send the same explicit armor.
  // -------------------------------------------------------------------------
  private async armorFromApReq(armorValue: Uint8Array): Promise<Json> {
    const { log, msgs, kcrypto, principals } = this.deps;
    log.debug('Entering Krb5Fast.armorFromApReq().');
    let apReq;
    try {
      apReq = msgs.readApReq(armorValue);
    } catch (e) {
      log.debug('Caught in Krb5Fast.armorFromApReq(): ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Fast.armorFromApReq(). Armor is not an AP-REQ.');
      return this.refuse(24, 'STS-KRB-0136', 'the FX_FAST_ARMOR_AP_REQUEST ' +
                         'armor is not an AP-REQ');
    }
    // THE ARMOR TICKET MUST BE A TGT FOR A REALM THIS KDC SERVES — "the
    // server name field of the armor ticket MUST identify the TGS of the
    // target realm". The target realm is checked against the INNER request
    // once it is open.
    const sname = apReq.ticket.sname.name || [];
    const armorRealm = apReq.ticket.realm;
    if (sname.length !== 2 || sname[0] !== 'krbtgt' ||
        sname[1] !== armorRealm ||
        principals.realmsServed().indexOf(armorRealm) === -1) {
      log.debug('Leaving Krb5Fast.armorFromApReq(). Not our TGS.');
      return this.refuse(24, 'STS-KRB-0137', 'the armor ticket is for ' +
                         sname.join('/') + '@' + armorRealm + ', not for ' +
                         'the ticket-granting service of a realm this KDC ' +
                         'serves');
    }
    const krbtgt = principals.find(['krbtgt', armorRealm], armorRealm);
    if (!krbtgt) {
      log.debug('Leaving Krb5Fast.armorFromApReq(). No krbtgt key.');
      return this.refuse(31, 'STS-KRB-0137', 'this KDC holds no krbtgt key ' +
                         'for ' + armorRealm + ' to open the armor ticket ' +
                         'with: ' + (principals.krbtgtUnavailableReason() ||
                                     'none is configured'));
    }
    // THE ARMOR TGT MAY BE SEALED UNDER A PREVIOUS krbtgt VERSION (#169): a
    // host that got its armor ticket an instant before a rotation still
    // armors with it, as `ticketKeyFor()` lets a TGS-REQ present it. A kvno
    // neither current nor kept is KRB_AP_ERR_BADKEYVER, not a decrypt
    // failure: the ticket is intact and names a key this KDC gave up.
    const armorKvno = apReq.ticket.encPart.kvno;
    let keptKey: Uint8Array | null = null;
    if (krbtgt.directoryKeys && armorKvno !== null &&
        armorKvno !== undefined && Number(armorKvno) !== Number(krbtgt.kvno)) {
      const kept = principals.retainedKeyFor(krbtgt,
                                             apReq.ticket.encPart.etype,
                                             Number(armorKvno));
      if (!kept) {
        log.debug('Leaving Krb5Fast.armorFromApReq(). Armor under a dropped ' +
                  'krbtgt version.');
        return this.refuse(44, 'STS-KRB-0164', 'the armor ticket was sealed ' +
                           'under key version ' + armorKvno + ' of krbtgt/' +
                           armorRealm + ', which holds version ' +
                           krbtgt.kvno + ' and no longer keeps that one');
      }
      keptKey = kept.key;
    }
    let ticketPart;
    try {
      const key = keptKey || await principals.longTermKey(krbtgt,
                                               apReq.ticket.encPart.etype);
      ticketPart = msgs.readEncTicketPart(
        await kcrypto.etypeById(apReq.ticket.encPart.etype).decrypt(
          key, kcrypto.KEY_USAGE.KDC_REP_TICKET, apReq.ticket.encPart.cipher));
    } catch (e) {
      log.debug('Caught in Krb5Fast.armorFromApReq(): ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Fast.armorFromApReq(). Armor ticket sealed.');
      return this.refuse(31, 'STS-KRB-0137', 'the armor ticket does not ' +
                         'decrypt with this KDC\'s key for krbtgt/' +
                         armorRealm);
    }
    const at = this.now();
    if (ticketPart.endtime.getTime() + this.skewMs() <= at.getTime()) {
      log.debug('Leaving Krb5Fast.armorFromApReq(). Armor ticket expired.');
      return this.refuse(32, 'STS-KRB-0137', 'the armor ticket expired at ' +
                         ticketPart.endtime.toISOString());
    }
    if (ticketPart.starttime &&
        ticketPart.starttime.getTime() > at.getTime() + this.skewMs()) {
      log.debug('Leaving Krb5Fast.armorFromApReq(). Armor not yet valid.');
      return this.refuse(33, 'STS-KRB-0137', 'the armor ticket is not yet ' +
                         'valid');
    }
    let authenticator;
    try {
      authenticator = msgs.readAuthenticator(
        await kcrypto.etypeById(apReq.authenticator.etype).decrypt(
          ticketPart.key.key, kcrypto.KEY_USAGE.AP_REQ_AUTH,
          apReq.authenticator.cipher));
    } catch (e) {
      log.debug('Caught in Krb5Fast.armorFromApReq(): ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Fast.armorFromApReq(). Authenticator sealed.');
      return this.refuse(31, 'STS-KRB-0138', 'the armor AP-REQ\'s ' +
                         'Authenticator does not decrypt with the armor ' +
                         'ticket\'s session key at key usage 11');
    }
    if (authenticator.cname.name.join('/') !==
          ticketPart.cname.name.join('/') ||
        authenticator.crealm !== ticketPart.crealm) {
      log.debug('Leaving Krb5Fast.armorFromApReq(). Names disagree.');
      return this.refuse(36, 'STS-KRB-0138', 'the armor Authenticator and ' +
                         'the armor ticket name different clients');
    }
    if (Math.abs(at.getTime() - authenticator.ctime.getTime()) >
        this.skewMs()) {
      log.debug('Leaving Krb5Fast.armorFromApReq(). Authenticator skew.');
      return this.refuse(37, 'STS-KRB-0138', 'the armor Authenticator\'s ' +
                         'clock is outside the tolerance');
    }
    if (!authenticator.subkey) {
      log.debug('Leaving Krb5Fast.armorFromApReq(). No subkey.');
      // RFC 6113 section 5.4.1.1: "The subkey field in the AP-REQ MUST be
      // present." Without it there is no client contribution to the armor.
      return this.refuse(24, 'STS-KRB-0138', 'the armor AP-REQ\'s ' +
                         'Authenticator carries no subkey, which ' +
                         'FX_FAST_ARMOR_AP_REQUEST requires');
    }
    // NO ARMOR OF AN ENCTYPE THE MODE WITHHOLDS (#182, 2026-09-23). The
    // armor key is KRB-FX-CF2 of the subkey and the ticket's session key and
    // takes the SUBKEY's enctype (RFC 6113 section 5.1), so a client that
    // chose an rc4-hmac subkey would have the whole FAST exchange — the
    // encrypted challenge, the OTP request, the strengthened reply key —
    // keyed with RC4. `common/crypto.js`'s PRF covers enctype 23 because
    // development exercises it; product refuses it here, before any key is
    // made, and a session key of that type with it.
    const withheldArmor = !principals.etypePermitted(
      authenticator.subkey.etype) ? authenticator.subkey.etype :
      (!principals.etypePermitted(ticketPart.key.etype) ?
        ticketPart.key.etype : null);
    if (withheldArmor !== null) {
      log.debug('Leaving Krb5Fast.armorFromApReq(). Withheld enctype.');
      return this.refuse(14, 'STS-KRB-0159', 'the FAST armor ' +
                         (withheldArmor === authenticator.subkey.etype ?
                           'subkey' : 'ticket\'s session key') + ' is ' +
                         kcrypto.etypeName(withheldArmor) + ', which this ' +
                         'KDC does not use in product mode (RFC 8429 ' +
                         'deprecates it)');
    }
    let armorKey: Key;
    try {
      armorKey = this.cf2({ etype: authenticator.subkey.etype,
                            key: authenticator.subkey.key },
                          { etype: ticketPart.key.etype,
                            key: ticketPart.key.key },
                          'subkeyarmor', 'ticketarmor');
    } catch (e) {
      log.debug('Caught in Krb5Fast.armorFromApReq(): ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Fast.armorFromApReq(). No armor key.');
      return this.refuse(24, 'STS-KRB-0138', 'no armor key can be made from ' +
                         'a ' + kcrypto.etypeName(authenticator.subkey.etype) +
                         ' subkey');
    }
    log.debug('Leaving Krb5Fast.armorFromApReq().');
    return { ok: true, armorKey: armorKey, realm: armorRealm,
             client: ticketPart.cname.name.join('/') + '@' +
                     ticketPart.crealm };
  }

  // -------------------------------------------------------------------------
  // THE KrbFastReq (RFC 6113 section 5.4.2), under an armor key however it was
  // made: the req-checksum over `checksumBytes` — the outer KDC-REQ-BODY in an
  // AS-REQ, the PA-TGS-REQ's AP-REQ in a TGS-REQ — then the enc-fast-req, the
  // critical options, and the inner request's realm against the armor's.
  // Answers `{ ok: true, fast, padata, reqBody }` or a refusal.
  // -------------------------------------------------------------------------
  private async openFastReq(armored: Json, armorKey: Key,
                            checksumBytes: Uint8Array, armorRealm: string,
                            armorClient: string, what: string):
      Promise<Json> {
    const { log, codec, kcrypto } = this.deps;
    log.debug('Entering Krb5Fast.openFastReq(). ' + what);
    const armorProfile = kcrypto.etypeById(armorKey.etype);
    // THE req-checksum BINDS THE ARMOR TO THE OUTER REQUEST: over the outer
    // KDC-REQ-BODY's own bytes, under the armor key, at key usage 50, and of
    // the checksum type the armor key's enctype requires.
    let bound = false;
    try {
      bound = armored.reqChecksum.type === armorProfile.checksumType &&
              await armorProfile.verifyChecksum(armorKey.key,
                codec.KEY_USAGE.FAST_REQ_CHKSUM, checksumBytes,
                armored.reqChecksum.checksum);
    } catch (e) {
      log.debug('Caught in Krb5Fast.openFastReq(): ' +
                ((e && e.message) || e));
      bound = false;
    }
    if (!bound) {
      log.debug('Leaving Krb5Fast.openFastReq(). Checksum.');
      return this.refuse(41, 'STS-KRB-0139', 'the FAST req-checksum does ' +
                         'not cover this request\'s body under the armor key ' +
                         '(key usage 50, checksum type ' +
                         armorProfile.checksumType + ')');
    }
    let inner;
    try {
      if (armored.encFastReq.etype !== armorKey.etype) {
        // error-code: none — caught below and refused under STS-KRB-0140
        throw new Error('the enc-fast-req is ' +
                        kcrypto.etypeName(armored.encFastReq.etype) +
                        ' and the armor key ' +
                        kcrypto.etypeName(armorKey.etype));
      }
      inner = codec.readFastReq(await armorProfile.decrypt(armorKey.key,
        codec.KEY_USAGE.FAST_ENC, armored.encFastReq.cipher));
    } catch (e) {
      log.debug('Caught in Krb5Fast.openFastReq(): ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Fast.openFastReq(). Inner request.');
      return this.refuse(31, 'STS-KRB-0140', 'the armored KrbFastReq does ' +
                         'not open under the armor key: ' +
                         ((e && e.message) || e));
    }
    // HIDE-CLIENT-NAMES (bit 1) IS IMPLEMENTED SINCE #205 (2026-09-26):
    // Heimdal's client sets it on every FAST TGS-REQ, so refusing it — as
    // section 5.4.2 lets a KDC do with a critical option it lacks — left a
    // Heimdal client unable to get a service ticket from this KDC at all the
    // moment the TGS exchange gained FAST. See hidesClientNames().
    const critical = (inner.fastOptions || []).filter(function (bit) {
      return bit >= 0 && bit <= 15 && bit !== HIDE_CLIENT_NAMES;
    });
    if (critical.length) {
      log.debug('Leaving Krb5Fast.openFastReq(). Critical options.');
      // Section 5.4.2: "If the KDC does not support a critical option, it
      // MUST fail the request" — and no e-data is defined for the error.
      return this.refuse(93, 'STS-KRB-0141', 'FAST option bit(s) ' +
                         critical.join(', ') + ' are critical and not ' +
                         'implemented here (only hide-client-names, bit 1, ' +
                         'is)');
    }
    if (inner.reqBody.realm !== armorRealm) {
      log.debug('Leaving Krb5Fast.openFastReq(). Another realm.');
      return this.refuse(24, 'STS-KRB-0137', 'the armor ticket is for ' +
                         'krbtgt/' + armorRealm + ' and the request is for ' +
                         inner.reqBody.realm + '; the armor must identify ' +
                         'the ticket-granting service of the realm asked');
    }
    const fast: FastState = {
      armorKey: armorKey,
      nonce: inner.reqBody.nonce,
      realm: armorRealm,
      fastOptions: inner.fastOptions || [],
      cookie: codec.find(inner.padata, codec.PA.FX_COOKIE),
      armorClient: armorClient
    };
    log.info('krb5-fast: ' + what + ' armored by a TGT for ' +
             fast.armorClient +
             ' (' + kcrypto.etypeName(armorKey.etype) + ' armor key)');
    log.debug('Leaving Krb5Fast.openFastReq(). Opened.');
    return { ok: true, fast: fast, padata: inner.padata,
             reqBody: inner.reqBody };
  }

  // -------------------------------------------------------------------------
  // FAST IN THE TGS EXCHANGE (RFC 6113 sections 5.4.1.1 and 5.4.2, #204,
  // 2026-09-26). Called by krb5_kdc.js once the PA-TGS-REQ has verified —
  // its ticket, its Authenticator and the body checksum — with
  // `{ apReqBytes, ticketKey, subkey, realm, client }`: the PA-TGS-REQ's
  // AP-REQ as sent, the ticket's session key, the Authenticator's subkey, the
  // realm of the TGS answering and the ticket's client.
  //
  // THE ARMOR IS IMPLICIT: "the armor key is the same armor key that would be
  // computed if the TGS-REQ authenticator was used in an
  // FX_FAST_ARMOR_AP_REQUEST armor", which needs the subkey the section makes
  // a MUST. An EXPLICIT armor field is opened as in an AS-REQ instead —
  // section 5.4.2 has a client SHOULD NOT send one, and Active Directory and
  // Heimdal both accept it, so refusing it would be stricter than every KDC
  // a client is written against. The req-checksum is over the PA-TGS-REQ's
  // AP-REQ, and the KrbFastReq's req-body and padata replace the outer ones.
  //
  // Until this, the KDC answered a FAST TGS-REQ UNARMORED, as though FAST
  // were not there (kerberos/CLAUDE.md's NOT BUILT): MIT's client, which
  // armors every TGS-REQ implicitly, accepted that, and a client holding
  // section 5.4.3's MUST — reject a TGS reply without PA-FX-FAST — could not
  // use this KDC at all. Samba's fast_tests found it.
  // -------------------------------------------------------------------------
  async openTgsRequest(pa: Json, ctx: Json): Promise<Json> {
    const { log, codec, kcrypto, principals } = this.deps;
    log.debug('Entering Krb5Fast.openTgsRequest().');
    let armored;
    try {
      armored = codec.readFastRequest(pa.value);
    } catch (e) {
      log.debug('Caught in Krb5Fast.openTgsRequest(): ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Fast.openTgsRequest(). Not a request.');
      return this.refuse(24, 'STS-KRB-0165', 'PA-FX-FAST does not decode ' +
                         'as a PA-FX-FAST-REQUEST');
    }
    let armorKey: Key;
    let client = String(ctx.client || '');
    if (armored.armor) {
      if (armored.armor.type !== codec.ARMOR_AP_REQUEST) {
        log.debug('Leaving Krb5Fast.openTgsRequest(). Armor type.');
        return this.refuse(24, 'STS-KRB-0165', 'armor type ' +
                           armored.armor.type + ' is not implemented here; ' +
                           'a TGS-REQ is armored implicitly, or with ' +
                           'FX_FAST_ARMOR_AP_REQUEST (1)');
      }
      const armor = await this.armorFromApReq(armored.armor.value);
      if (!armor.ok) {
        log.debug('Leaving Krb5Fast.openTgsRequest(). Explicit armor.');
        return armor;
      }
      armorKey = armor.armorKey;
      client = armor.client;
    } else {
      if (!ctx.subkey) {
        log.debug('Leaving Krb5Fast.openTgsRequest(). No subkey.');
        return this.refuse(24, 'STS-KRB-0165', 'a TGS-REQ armored ' +
                           'implicitly must carry a subkey in its ' +
                           'PA-TGS-REQ Authenticator (RFC 6113 section ' +
                           '5.4.2)');
      }
      // #182's rule, as for explicit armor: no armor key of an enctype the
      // mode withholds.
      const withheld = !principals.etypePermitted(ctx.subkey.etype)
        ? ctx.subkey.etype
        : (!principals.etypePermitted(ctx.ticketKey.etype)
          ? ctx.ticketKey.etype : null);
      if (withheld !== null) {
        log.debug('Leaving Krb5Fast.openTgsRequest(). Withheld enctype.');
        return this.refuse(14, 'STS-KRB-0159', 'the implicit FAST armor ' +
                           'would be ' + kcrypto.etypeName(withheld) +
                           ', which this KDC does not use in product mode ' +
                           '(RFC 8429 deprecates it)');
      }
      try {
        armorKey = this.cf2({ etype: ctx.subkey.etype, key: ctx.subkey.key },
                            { etype: ctx.ticketKey.etype,
                              key: ctx.ticketKey.key },
                            'subkeyarmor', 'ticketarmor');
      } catch (e) {
        log.debug('Caught in Krb5Fast.openTgsRequest(): ' +
                  ((e && e.message) || e));
        log.debug('Leaving Krb5Fast.openTgsRequest(). No armor key.');
        return this.refuse(24, 'STS-KRB-0165', 'no armor key can be made ' +
                           'from a ' + kcrypto.etypeName(ctx.subkey.etype) +
                           ' subkey');
      }
    }
    const opened = await this.openFastReq(armored, armorKey, ctx.apReqBytes,
                                          ctx.realm, client, 'a TGS-REQ');
    log.debug('Leaving Krb5Fast.openTgsRequest().');
    return opened;
  }

  // -------------------------------------------------------------------------
  // AN ERROR, ARMORED (RFC 6113 section 5.4.4): the KRB-ERROR the KDC built
  // goes inside a KrbFastResponse as PA-FX-ERROR with no e-data, its e-data's
  // padata beside it, and the outer KRB-ERROR's e-data is a METHOD-DATA
  // holding only PA-FX-FAST.
  // -------------------------------------------------------------------------
  async wrapError(errorBytes: Uint8Array, fast: FastState):
      Promise<Uint8Array> {
    const { log, msgs, asn1, codec, kcrypto } = this.deps;
    log.debug('Entering Krb5Fast.wrapError().');
    const e = msgs.readKrbError(errorBytes);
    const fields = {
      ctime: e.ctime, cusec: e.ctime ? e.cusec : null, stime: e.stime,
      susec: e.susec, errorCode: e.errorCode, crealm: e.crealm,
      cname: e.cname, realm: e.realm, sname: e.sname, eText: e.eText
    };
    const inner = msgs.encKrbError(Object.assign({}, fields, { eData: null }));
    const response = codec.encFastResponse({
      padata: [{ type: codec.PA.FX_ERROR, value: inner }]
        .concat(e.eDataPaData || []),
      nonce: fast.nonce
    });
    const cipher = await kcrypto.etypeById(fast.armorKey.etype).encrypt(
      fast.armorKey.key, codec.KEY_USAGE.FAST_REP, response);
    // The outer error names the anonymous principal under hide-client-names
    // (hidesClientNames()); a KRB-ERROR's cname and crealm are OPTIONAL, so
    // one that carried none stays without.
    const hidden = this.hidesClientNames(fast) && (e.cname || e.crealm)
      ? this.outerClient(fast, e.crealm, e.cname) : {};
    const outer = msgs.encKrbError(Object.assign({}, fields, hidden, {
      eData: asn1.encSequenceOf([msgs.encPaData({
        type: codec.PA.FX_FAST,
        value: codec.encFastReply({ etype: fast.armorKey.etype,
                                    cipher: cipher })
      })])
    }));
    log.debug('Leaving Krb5Fast.wrapError(). KRB-ERROR ' + e.errorCode +
              ' armored.');
    return outer;
  }

  // -------------------------------------------------------------------------
  // WHAT A KDC_ERR_PREAUTH_REQUIRED OFFERS INSIDE FAST: the OTP challenge when
  // the person has an authenticator app, the encrypted challenge, and — always
  // — a cookie. The KDC adds ETYPE-INFO2 and PA-PW-SALT itself.
  //
  // `opts.otp` is the KDC's decision; the order is the preference a client
  // reads (MIT's `kinit` tries the first mechanism it can run), so an
  // authenticator holder is offered the OTP first. The encrypted challenge is
  // offered EVEN to a person a password alone will not do for, as
  // PA-ENC-TIMESTAMP is outside FAST: it is how somebody with no
  // authenticator app learns, after proving their password and only then,
  // what the refusal is about.
  // -------------------------------------------------------------------------
  async offers(client: Json, fast: FastState, opts: Json):
      Promise<Json[]> {
    const { log, codec } = this.deps;
    log.debug('Entering Krb5Fast.offers().');
    const options = opts || {};
    const out = [];
    let nonce: Uint8Array | null = null;
    if (options.otp) {
      // RFC 6560 section 3.2: a random component at least as long as the
      // armor key. Four bytes of the time in front, as MIT's KDC does, so a
      // nonce says when it was minted to anybody reading a trace.
      const stamp = Buffer.alloc(4);
      stamp.writeUInt32BE(Math.floor(Date.now() / 1000) >>> 0, 0);
      nonce = new Uint8Array(Buffer.concat([
        stamp, nodeCrypto.randomBytes(Math.max(32,
                                               fast.armorKey.key.length))]));
      out.push({ type: codec.PA.OTP_CHALLENGE, value: codec.encOtpChallenge({
        nonce: nonce,
        service: fast.realm,
        tokenInfo: [{
          // collect-pin and separate-pin-required: the client asks for the
          // PIN — the password — and sends it apart from the code.
          flags: [codec.OTP_FLAG.COLLECT_PIN,
                  codec.OTP_FLAG.SEPARATE_PIN_REQUIRED],
          format: codec.OTP_FORMAT.DECIMAL
        }]
      }) });
    }
    out.push({ type: codec.PA.ENCRYPTED_CHALLENGE,
               value: new Uint8Array(0) });
    const cookie = await this.sealCookie(client, fast, nonce);
    if (cookie) {
      out.push({ type: codec.PA.FX_COOKIE, value: cookie });
    }
    log.debug('Leaving Krb5Fast.offers(). ' + out.length + ' entr' +
              (out.length === 1 ? 'y' : 'ies') + '.');
    return out;
  }

  // THE COOKIE (RFC 6113 section 5.2): opaque to the client, sealed under the
  // realm's krbtgt key so a client cannot alter it, and carrying who it was
  // issued for, when, and the OTP nonce if one was issued. It is what binds a
  // PA-OTP-REQUEST's nonce to a challenge THIS KDC made, on any node that
  // holds the krbtgt key.
  private async sealCookie(client: Json, fast: FastState,
                           nonce: Uint8Array | null): Promise<Uint8Array |
                                                              null> {
    const { log, kcrypto, msgs, codec } = this.deps;
    log.debug('Entering Krb5Fast.sealCookie().');
    const key = await this.tgsKey(fast.realm);
    if (!key) {
      log.debug('Leaving Krb5Fast.sealCookie(). No krbtgt key.');
      return null;
    }
    const body = Buffer.from(JSON.stringify({
      v: 1,
      c: client.name.join('/') + '@' + fast.realm,
      t: Date.now(),
      n: nonce ? Buffer.from(nonce).toString('hex') : ''
    }), 'utf8');
    const cipher = await kcrypto.etypeById(key.etype).encrypt(
      key.key, codec.KEY_USAGE.FX_COOKIE, body);
    log.debug('Leaving Krb5Fast.sealCookie().');
    // The krbtgt kvno rides in the EncryptedData (#169), so the cookie can
    // be opened after a rotation under the version it was sealed with.
    return new Uint8Array(Buffer.concat([
      Buffer.from(COOKIE_MAGIC, 'latin1'),
      Buffer.from(msgs.encEncryptedData({ etype: key.etype,
                                          kvno: key.kvno === undefined
                                            ? null : key.kvno,
                                          cipher: cipher }))]));
  }

  // The cookie a request echoed, opened and checked, or null: not ours, not
  // intact, expired, or for somebody else.
  private async openCookie(client: Json, fast: FastState): Promise<Json> {
    const { log, kcrypto, msgs, asn1, codec } = this.deps;
    log.debug('Entering Krb5Fast.openCookie().');
    const pa = fast.cookie;
    const bytes = pa ? Buffer.from(pa.value) : Buffer.alloc(0);
    if (bytes.length < 5 ||
        bytes.subarray(0, 4).toString('latin1') !== COOKIE_MAGIC) {
      log.debug('Leaving Krb5Fast.openCookie(). Not ours.');
      return null;
    }
    let body;
    try {
      const sealed = msgs.readEncryptedData(asn1.readTlv(
        new Uint8Array(bytes.subarray(4)), 0));
      const key = await this.tgsKey(fast.realm, sealed.kvno);
      if (!key) {
        log.debug('Leaving Krb5Fast.openCookie(). No krbtgt key for it.');
        return null;
      }
      body = JSON.parse(Buffer.from(await kcrypto.etypeById(sealed.etype)
        .decrypt(key.key, codec.KEY_USAGE.FX_COOKIE, sealed.cipher))
        .toString('utf8'));
    } catch (e) {
      log.debug('Caught in Krb5Fast.openCookie(): ' + ((e && e.message) || e));
      log.debug('Leaving Krb5Fast.openCookie(). It does not open.');
      return null;
    }
    const who = client.name.join('/') + '@' + fast.realm;
    if (!body || body.v !== 1 || body.c !== who ||
        !(Date.now() - Number(body.t) < COOKIE_LIFETIME_MS)) {
      log.debug('Leaving Krb5Fast.openCookie(). Expired or another\'s.');
      return null;
    }
    log.debug('Leaving Krb5Fast.openCookie(). Ours.');
    return body;
  }

  // -------------------------------------------------------------------------
  // THE ENCRYPTED CHALLENGE (RFC 6113 section 5.4.6): the password factor
  // inside FAST. Answers `{ ok: true, kdcPadata, etype }` — `etype` is the
  // long-term key's the client used, which the KDC replies under — or a
  // refusal.
  // -------------------------------------------------------------------------
  async checkEncryptedChallenge(client: Json, etype: number, pa: Json,
                                fast: FastState): Promise<Json> {
    const { log, msgs, asn1, kcrypto, principals, codec, claims } = this.deps;
    log.debug('Entering Krb5Fast.checkEncryptedChallenge().');
    let encrypted;
    try {
      encrypted = msgs.readEncryptedData(asn1.readTlv(pa.value, 0));
    } catch (e) {
      log.debug('Caught in Krb5Fast.checkEncryptedChallenge(): ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Fast.checkEncryptedChallenge(). Malformed.');
      return this.refuse(24, 'STS-KRB-0142', 'PA-ENCRYPTED-CHALLENGE is not ' +
                         'an EncryptedData');
    }
    // The challenge key has the ARMOR key's enctype (K1 of KRB-FX-CF2); the
    // long-term key's enctype is the client's choice from ETYPE-INFO2, so the
    // negotiated one is tried first and then every other this principal has.
    const tried = [etype].concat(principals.supportedEtypes(client)
      .filter(function (one) {
        return one !== etype;
      }));
    let opened = null;
    let longTerm: Key | null = null;
    for (const one of tried) {
      try {
        const key = { etype: one,
                      key: await principals.longTermKey(client, one) };
        const challengeKey = this.cf2(fast.armorKey, key,
                                      'clientchallengearmor',
                                      'challengelongterm');
        if (encrypted.etype !== challengeKey.etype) {
          continue;
        }
        opened = msgs.readPaEncTsEnc(
          await kcrypto.etypeById(challengeKey.etype).decrypt(
            challengeKey.key, codec.KEY_USAGE.ENC_CHALLENGE_CLIENT,
            encrypted.cipher));
        longTerm = key;
        break;
      } catch (e) {
        log.debug('Caught in Krb5Fast.checkEncryptedChallenge(): ' +
                  ((e && e.message) || e));
      }
    }
    if (!opened || !longTerm) {
      log.debug('Leaving Krb5Fast.checkEncryptedChallenge(). Wrong key.');
      // What a wrong password looks like here — the same answer
      // PA-ENC-TIMESTAMP gets.
      return this.refuse(24, 'STS-KRB-0142', 'PREAUTH_FAILED');
    }
    const at = this.now();
    if (Math.abs(at.getTime() - opened.patimestamp.getTime()) >
        this.skewMs()) {
      log.debug('Leaving Krb5Fast.checkEncryptedChallenge(). Skew.');
      return this.refuse(37, 'STS-KRB-0143', 'the encrypted challenge\'s ' +
                         'timestamp is outside the clock tolerance');
    }
    // SECTION 5.4.6's REPLAY CHECK: the same CIPHERTEXT, never the same time.
    // Spent across the cluster, for as long as the timestamp could still be
    // inside the tolerance.
    const spent = await claims.claim({
      scope: CHALLENGE_SCOPE,
      value: Buffer.from(encrypted.cipher).toString('hex'),
      ttlMs: 2 * this.skewMs() + 60000
    });
    if (!spent.ok && spent.reason === 'used') {
      log.debug('Leaving Krb5Fast.checkEncryptedChallenge(). Replayed.');
      return this.refuse(34, 'STS-KRB-0144', 'this encrypted challenge has ' +
                         'been presented before');
    }
    if (!spent.ok) {
      log.debug('Leaving Krb5Fast.checkEncryptedChallenge(). No store.');
      return this.refuse(60, 'STS-KRB-0145', 'the encrypted challenge could ' +
                         'not be proved unused just now; try again');
    }
    // The KDC's half: its own time under the KDC challenge key. "If the KDC
    // accepts the encrypted challenge, it MUST include a padata element of
    // type PA-ENCRYPTED-CHALLENGE."
    const kdcKey = this.cf2(fast.armorKey, longTerm, 'kdcchallengearmor',
                            'challengelongterm');
    const stime = this.now();
    const answer = msgs.encEncryptedData({
      etype: kdcKey.etype,
      cipher: await kcrypto.etypeById(kdcKey.etype).encrypt(kdcKey.key,
        codec.KEY_USAGE.ENC_CHALLENGE_KDC,
        msgs.encPaEncTsEnc(stime, (stime.getMilliseconds() * 1000) %
                                  1000000))
    });
    log.info('krb5-fast: the encrypted challenge verified for ' +
             client.name.join('/') + ' (' + kcrypto.etypeName(longTerm.etype) +
             ' long-term key)');
    log.debug('Leaving Krb5Fast.checkEncryptedChallenge(). Verified.');
    return { ok: true, etype: longTerm.etype,
             kdcPadata: [{ type: codec.PA.ENCRYPTED_CHALLENGE,
                           value: answer }] };
  }

  // -------------------------------------------------------------------------
  // THE OTP REQUEST (RFC 6560 sections 3.4 and 3.6). Answers
  // `{ ok: true, replyKey, indicators }` — the armor key, and `otp` — or a
  // refusal. The order is the one the header argues: the nonce, the PIN (the
  // password), then the code.
  // -------------------------------------------------------------------------
  async checkOtpRequest(client: Json, etype: number, pa: Json,
                        fast: FastState): Promise<Json> {
    const { log, codec, kcrypto, prim, principals, credentials } = this.deps;
    log.debug('Entering Krb5Fast.checkOtpRequest().');
    let req;
    try {
      req = codec.readOtpRequest(pa.value);
    } catch (e) {
      log.debug('Caught in Krb5Fast.checkOtpRequest(): ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Fast.checkOtpRequest(). Malformed.');
      return this.refuse(24, 'STS-KRB-0146', 'PA-OTP-REQUEST does not ' +
                         'decode');
    }
    if (req.encData.etype !== fast.armorKey.etype) {
      log.debug('Leaving Krb5Fast.checkOtpRequest(). Etype.');
      // Section 3.4: an encData enctype against KDC policy is
      // KDC_ERR_ETYPE_NOSUPP. The Client Key IS the armor key here.
      return this.refuse(14, 'STS-KRB-0146', 'the PA-OTP-REQUEST encData ' +
                         'must be under the armor key (' +
                         kcrypto.etypeName(fast.armorKey.etype) + ')');
    }
    let encData;
    try {
      encData = codec.readOtpEncData(
        await kcrypto.etypeById(fast.armorKey.etype).decrypt(
          fast.armorKey.key, codec.KEY_USAGE.OTP_REQUEST,
          req.encData.cipher));
    } catch (e) {
      log.debug('Caught in Krb5Fast.checkOtpRequest(): ' +
                ((e && e.message) || e));
      log.debug('Leaving Krb5Fast.checkOtpRequest(). encData sealed.');
      return this.refuse(24, 'STS-KRB-0146', 'the PA-OTP-REQUEST encData ' +
                         'does not open under the armor key at key usage 45');
    }
    if (encData.nonce) {
      // FOUR-PASS: the nonce must be the one the challenge carried, and the
      // cookie is where this KDC wrote it down.
      const cookie = await this.openCookie(client, fast);
      if (!cookie || !cookie.n ||
          cookie.n !== Buffer.from(encData.nonce).toString('hex')) {
        log.debug('Leaving Krb5Fast.checkOtpRequest(). Not our nonce.');
        return this.refuse(24, 'STS-KRB-0146', 'the PA-OTP-REQUEST answers ' +
                           'no PA-OTP-CHALLENGE this KDC issued for this ' +
                           'principal in the last ' +
                           (COOKIE_LIFETIME_MS / 60000) + ' minutes');
      }
    } else {
      // TWO-PASS: a PA-ENC-TS-ENC, checked as an encrypted timestamp is.
      const skew = Math.abs(this.now().getTime() -
                            encData.timestamp.getTime());
      if (skew > this.skewMs()) {
        log.debug('Leaving Krb5Fast.checkOtpRequest(). Skew.');
        return this.refuse(37, 'STS-KRB-0146', 'the PA-OTP-REQUEST ' +
                           'timestamp is outside the clock tolerance');
      }
    }
    if (req.hashing || req.value === null) {
      log.debug('Leaving Krb5Fast.checkOtpRequest(). No otp-value.');
      return this.refuse(24, 'STS-KRB-0152', 'the PA-OTP-REQUEST carries no ' +
                         'otp-value: this KDC did not set must-encrypt-nonce ' +
                         'and does not take a hashed OTP');
    }
    if (req.pin === null || req.pin === '') {
      log.debug('Leaving Krb5Fast.checkOtpRequest(). No PIN.');
      return this.refuse(97, 'STS-KRB-0147', 'this KDC requires the ' +
                         'password as the otp-pin (separate-pin-required)');
    }
    // THE PIN IS THE PASSWORD, checked as the KEY it derives: string-to-key
    // with this principal's own salt, against the key the KDC holds. An app
    // password derives no Kerberos key, so it fails here like any other.
    let pinOk = false;
    try {
      const held = await principals.longTermKey(client, etype);
      const derived = await kcrypto.etypeById(etype).stringToKey(
        req.pin, prim.utf8(client.salt || ''), null);
      pinOk = held.length === derived.length &&
              nodeCrypto.timingSafeEqual(Buffer.from(held),
                                         Buffer.from(derived));
    } catch (e) {
      log.debug('Caught in Krb5Fast.checkOtpRequest(): ' +
                ((e && e.message) || e));
      pinOk = false;
    }
    if (!pinOk) {
      log.debug('Leaving Krb5Fast.checkOtpRequest(). Wrong PIN.');
      return this.refuse(24, 'STS-KRB-0148', 'PREAUTH_FAILED');
    }
    // THE CODE, through the sign-in screen's own verifier and its once-only
    // step (`verifyTotpAsync()`, the cluster counter `authn.totp-step`).
    const name = client.name.length === 1 ? String(client.name[0]) : '';
    let verdict: Json;
    try {
      verdict = name ? await credentials.verifyTotpAsync(name, req.value)
                     : { ok: false, reason: 'none' };
    } catch (e) {
      log.debug('Caught in Krb5Fast.checkOtpRequest(): ' +
                ((e && e.message) || e));
      verdict = { ok: false, reason: 'store' };
    }
    if (!verdict || !verdict.ok) {
      const reason = (verdict && verdict.reason) || 'refused';
      log.debug('Leaving Krb5Fast.checkOtpRequest(). Code refused: ' +
                reason);
      if (reason === 'replay') {
        return this.refuse(24, 'STS-KRB-0150', 'PREAUTH_FAILED: that code ' +
                           'has already been used; wait for the next one');
      }
      if (reason === 'store') {
        return this.refuse(24, 'STS-KRB-0151', 'PREAUTH_FAILED: the code ' +
                           'could not be proved unspent just now');
      }
      return this.refuse(24, 'STS-KRB-0149', 'PREAUTH_FAILED');
    }
    log.info('krb5-fast: OTP pre-authentication verified the password and ' +
             'an authenticator code for ' + client.name.join('/') +
             ' (step ' + verdict.counter + ')');
    log.debug('Leaving Krb5Fast.checkOtpRequest(). Verified.');
    return { ok: true, replyKey: fast.armorKey,
             indicators: [OTP_INDICATOR] };
  }

  // -------------------------------------------------------------------------
  // THE REPLY (RFC 6113 section 5.4.3): the padata inside an encrypted
  // KrbFastResponse, a KrbFastFinished whose checksum covers the ticket, and a
  // STRENGTHENED reply key — always, which section 5.4.6 requires after an
  // encrypted challenge and which costs nothing otherwise. Answers
  // `{ padata, replyKey }`: the outer AS-REP's padata (PA-FX-FAST alone) and
  // the key its enc-part is sealed under.
  // -------------------------------------------------------------------------
  async finishAsReply(opts: Json): Promise<Json> {
    const { log, msgs, kcrypto, codec } = this.deps;
    log.debug('Entering Krb5Fast.finishAsReply().');
    const fast: FastState = opts.fast;
    const replyKey: Key = opts.replyKey;
    const strengthen: Key = {
      etype: replyKey.etype,
      key: kcrypto.randomBytes(kcrypto.etypeById(replyKey.etype).keyBytes)
    };
    const finalKey = this.cf2(strengthen, replyKey, 'strengthenkey',
                              'replykey');
    const armorProfile = kcrypto.etypeById(fast.armorKey.etype);
    const at = this.now();
    const finished = {
      timestamp: at,
      usec: (at.getMilliseconds() * 1000) % 1000000,
      crealm: opts.crealm,
      cname: opts.cname,
      ticketChecksum: {
        type: armorProfile.checksumType,
        checksum: await armorProfile.checksum(fast.armorKey.key,
          codec.KEY_USAGE.FAST_FINISHED, msgs.encTicket(opts.ticket))
      }
    };
    const response = codec.encFastResponse({
      padata: opts.padata || [],
      strengthenKey: strengthen,
      finished: finished,
      nonce: fast.nonce
    });
    const cipher = await armorProfile.encrypt(fast.armorKey.key,
      codec.KEY_USAGE.FAST_REP, response);
    log.debug('Leaving Krb5Fast.finishAsReply().');
    return {
      padata: [{ type: codec.PA.FX_FAST,
                 value: codec.encFastReply({ etype: fast.armorKey.etype,
                                             cipher: cipher }) }],
      replyKey: finalKey
    };
  }

  // -------------------------------------------------------------------------
  // AN AUTHENTICATION INDICATOR IN A TICKET (RFC 8129 over RFC 7751): the
  // AD-AUTHENTICATION-INDICATOR inside an AD-CAMMAC inside AD-IF-RELEVANT
  // (RFC 7751 section 5's SHOULD, for services that know neither). Two
  // verifiers, at key usage 64:
  //
  //   * the svc-verifier, under the key the TICKET is sealed with — what the
  //     acceptor checks, and for a TGT that key is krbtgt's, which is what the
  //     TGS checks before it copies the indicator on;
  //   * the kdc-verifier, under the krbtgt key, over the EncTicketPart with
  //     its authorization data replaced by the CAMMAC's elements — the binding
  //     to the rest of the ticket, for an S4U2Proxy evidence ticket.
  //
  // `encodeTicketPart(ad)` must encode the ticket's EncTicketPart with `ad`
  // as its authorization data and nothing else. Answers the AD entries to put
  // in the ticket, or [] for no indicators.
  // -------------------------------------------------------------------------
  async indicatorAuthData(opts: Json): Promise<Json[]> {
    const { log, msgs, kcrypto, codec } = this.deps;
    log.debug('Entering Krb5Fast.indicatorAuthData().');
    const indicators: string[] = (opts.indicators || []).filter(Boolean);
    if (!indicators.length) {
      log.debug('Leaving Krb5Fast.indicatorAuthData(). None.');
      return [];
    }
    const elements = [{ type: codec.AD.AUTHENTICATION_INDICATOR,
                        data: codec.encIndicators(indicators) }];
    const elementsBytes = msgs.encAuthorizationData(elements);
    const kdcProfile = kcrypto.etypeById(opts.kdcKey.etype);
    const svcProfile = kcrypto.etypeById(opts.serviceKey.etype);
    const cammac = codec.encCammac({
      elementsBytes: elementsBytes,
      kdcVerifier: {
        enctype: opts.kdcKey.etype,
        mac: { type: kdcProfile.checksumType,
               checksum: await kdcProfile.checksum(opts.kdcKey.key,
                 codec.KEY_USAGE.CAMMAC, opts.encodeTicketPart(elements)) }
      },
      svcVerifier: {
        enctype: opts.serviceKey.etype,
        mac: { type: svcProfile.checksumType,
               checksum: await svcProfile.checksum(opts.serviceKey.key,
                 codec.KEY_USAGE.CAMMAC, elementsBytes) }
      }
    });
    log.debug('Leaving Krb5Fast.indicatorAuthData(). ' +
              indicators.join(','));
    return [{ type: codec.AD.IF_RELEVANT,
              data: msgs.encAuthorizationData([{ type: codec.AD.CAMMAC,
                                                 data: cammac }]) }];
  }

  // THE INDICATORS A TICKET CARRIES, read by whoever holds the key it is
  // sealed with (`ticketKey`): the TGS for a TGT, the acceptor for a service
  // ticket. Only a CAMMAC whose svc-verifier verifies under that key counts
  // (RFC 8129 section 5: an application server MUST validate the container,
  // and MUST NOT use an indicator outside one). Answers `{ indicators,
  // problem }`; `problem` names a CAMMAC that did not verify, whose
  // indicators were dropped.
  async ticketIndicators(authorizationData: Json[], ticketKey: Key):
      Promise<Json> {
    const { log, msgs, asn1, kcrypto, codec } = this.deps;
    log.debug('Entering Krb5Fast.ticketIndicators().');
    const found: string[] = [];
    let problem: string | null = null;
    const cammacs: Uint8Array[] = [];
    (authorizationData || []).forEach(function (entry) {
      if (entry.type === codec.AD.CAMMAC) {
        cammacs.push(entry.data);
      } else if (entry.type === codec.AD.IF_RELEVANT) {
        try {
          msgs.readAuthorizationData(asn1.readTlv(entry.data, 0))
            .forEach(function (inner) {
              if (inner.type === codec.AD.CAMMAC) {
                cammacs.push(inner.data);
              }
            });
        } catch (e) {
          log.debug('Caught in Krb5Fast.ticketIndicators(): ' +
                    ((e && e.message) || e));
        }
      }
    });
    for (const bytes of cammacs) {
      let parsed;
      let verified = false;
      try {
        parsed = codec.readCammac(bytes);
        const profile = kcrypto.etypeById(ticketKey.etype);
        verified = !!parsed.svcVerifier &&
          parsed.svcVerifier.mac.type === profile.checksumType &&
          await profile.verifyChecksum(ticketKey.key, codec.KEY_USAGE.CAMMAC,
                                       parsed.elementsBytes,
                                       parsed.svcVerifier.mac.checksum);
      } catch (e) {
        log.debug('Caught in Krb5Fast.ticketIndicators(): ' +
                  ((e && e.message) || e));
        verified = false;
      }
      if (!verified) {
        problem = 'an AD-CAMMAC whose svc-verifier does not verify under ' +
                  'the key the ticket is sealed with';
        continue;
      }
      parsed.elements.forEach(function (element) {
        if (element.type !== codec.AD.AUTHENTICATION_INDICATOR) {
          return;
        }
        try {
          codec.readIndicators(element.data).forEach(function (one) {
            if (found.indexOf(one) === -1) {
              found.push(one);
            }
          });
        } catch (e) {
          log.debug('Caught in Krb5Fast.ticketIndicators(): ' +
                    ((e && e.message) || e));
          problem = 'an AD-AUTHENTICATION-INDICATOR that does not decode';
        }
      });
    }
    log.debug('Leaving Krb5Fast.ticketIndicators(). [' + found.join(',') +
              ']' + (problem ? ' ' + problem : ''));
    return { indicators: found, problem: problem };
  }

  // -------------------------------------------------------------------------
  // WHAT THE KDC DOES, for `/admin/kerberos` and `GET /admin-api/kerberos`
  // (rule 7) — per the AMBIENT realm, because the mode is a realm's.
  // -------------------------------------------------------------------------
  policy(): Json {
    const { log, mode, codec } = this.deps;
    log.debug('Entering Krb5Fast.policy().');
    const refuses = !mode.issuesTicketsOnPasswordAlone();
    log.debug('Leaving Krb5Fast.policy().');
    return {
      fast: true,
      armorTypes: ['FX_FAST_ARMOR_AP_REQUEST (1): a TGT for this realm\'s ' +
                   'ticket-granting service with a subkey (RFC 6113 section ' +
                   '5.4.1.1)'],
      fastFactors: ['PA-ENCRYPTED-CHALLENGE (' +
                    codec.PA.ENCRYPTED_CHALLENGE + ')',
                    'PA-OTP-REQUEST (' + codec.PA.OTP_REQUEST + '), the ' +
                    'password as otp-pin and an authenticator app code'],
      passwordAloneForSecondFactorAccounts: refuses ? 'refused' : 'accepted',
      refusal: refuses
        ? 'KDC_ERR_POLICY (12), after the password verified'
        : null,
      otpIndicator: OTP_INDICATOR,
      notImplemented: ['anonymous PKINIT armor', 'PKINIT (#179)',
                       'FAST in the TGS exchange', 'hide-client-names',
                       'hashed OTP values (must-encrypt-nonce)']
    };
  }
}

export = Krb5Fast;
