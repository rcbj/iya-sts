// ===========================================================================
// tests/vendored/krb5_wire.js — A KERBEROS CLIENT OVER THE NETWORK, FOR A JOB
// THAT HAS TO TALK TO THE KDC THE WAY A REAL CLIENT DOES.
//
// **THIS IS NOT A TEST.** It is the client half `sts_kerberos_spnego.js`
// drives: the AS exchange, the TGS exchange and an AP-REQ wrapped for SPNEGO,
// over EITHER of the two transports a client can reach this KDC by from
// outside — raw TCP (RFC 4120 section 7.2.2) and MS-KKDCP (`POST /KdcProxy`).
// A LOCAL HELPER (tests/vendored/MANIFEST.js's LOCAL_HELPERS), owned here.
//
// ---------------------------------------------------------------------------
// WHY NOT `krb5_drive.js`, WHICH ALREADY DOES AN AS EXCHANGE.
//
// Three reasons, and the first decides it. That file answers "did the KDC
// issue a TGT" and throws the reply away; everything a TGS-REQ and an AP-REQ
// need — the session key inside the enc-part, the ticket itself, the kvno the
// key was derived at — is inside what it discards. It speaks only MS-KKDCP.
// And it throws on a KRB-ERROR, where half of what the job asserts IS a
// KRB-ERROR: a refusal read as an exception cannot be asserted on by code.
// It is not edited here (the owner's rule for this job), so this file is
// the second client rather than a change to the first.
//
// ---------------------------------------------------------------------------
// WHY THE SERVICE'S OWN CODEC, AND WHAT THAT DOES NOT PROVE.
//
// The ASN.1 and RFC 3961 code is the service's vendored codec, loaded from
// the tree the job runs in (`../../kerberos/`, which is `/usr/src/sts/kerberos`
// in the tests image) — `tests/CLAUDE.md` records the same decision for every
// in-process Kerberos job: hand-rolling a second DER encoder to test the first
// would be testing the copy. What that shares is the WIRE FORMAT. What it does
// not share is the ASSEMBLY — which key usage, which key, which bytes the
// checksum covers, what the 0x8003 checksum holds — and that is written out
// here, from RFC 4120 and RFC 4121, not borrowed from the service's KDC or
// acceptor. A mistake the KDC makes in assembly therefore cannot make this
// client agree with it. (The interoperability case that shared-codec clients
// cannot cover — a client that never met this KDC — is the parent project's
// `tests/krb5_mit_client.js`, with real MIT Kerberos.)
// ===========================================================================

"use strict";

const net = require("net");
const path = require("path");

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require("bunyan").createLogger({ name: "krb5_wire",
  level: process.env.LOG_LEVEL || "info" });

// THE SERVICE'S VENDORED CODEC, from the tree this file sits in. A path
// rather than `module_paths.mockStsModule()`, because that function's search
// order is the PARENT project's (a submodule named `sts/`, then a sibling
// checkout), and here the codec is two directories up in every place this job
// runs: a checkout of this repository and the tests image alike.
function codec(name) {
  log.debug("Entering codec(). " + name);
  log.debug("Leaving codec().");
  return require(path.join(__dirname, "..", "..", "kerberos", name));
}

const prim = codec("krb5_primitives.js");
const asn1 = codec("krb5_asn1.js");
const msgs = codec("krb5_messages.js");
const kcrypto = codec("krb5_crypto.js");
const gss = codec("krb5_gss.js");
const spnego = codec("krb5_spnego.js");

// The encryption types asked for, in order. aes256 first because it is the
// KDC's own default and every account here has a key for it; aes128 second so
// a deployment that trimmed `krb5.enctypes` still has something in common.
// Not negotiated beyond that, for krb5_drive.js's reason: a driver that took
// whatever it was offered would hide a KDC offering the wrong thing.
const ETYPES = [18, 17];

// How long one exchange may take. A KDC behind a load balancer answers in
// milliseconds; ten seconds is a hung socket, not a slow one.
const TIMEOUT_MS = 10000;

// A nonce is the client's own, echoed in the enc-part; RFC 4120 wants it
// unpredictable and it is a UInt32 on the wire. The top bit is left clear
// because some decoders read the field as signed.
function randomNonce() {
  log.debug("Entering randomNonce().");
  const b = kcrypto.randomBytes(4);
  log.debug("Leaving randomNonce().");
  return (((b[0] & 0x7f) << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
}

// ---------------------------------------------------------------------------
// THE TWO TRANSPORTS. Each takes the bare Kerberos message and answers the
// bare reply, so every exchange below is written once and run over both.
// ---------------------------------------------------------------------------

// RFC 4120 section 7.2.2: a four-byte big-endian length, then the message,
// in each direction. The reply is read until the length it declares has
// arrived — a reply can span several TCP segments, and a reader that took the
// first `data` event would decode half a ticket.
//
// NOTHING HERE WRITES A PROXY PROTOCOL HEADER, and that is the point on a
// deployment that uses one: the load balancer adds it on the way in, and the
// KDC reads the client's address out of it. A client that sent one itself
// would be forging the address the KDC logs.
function sendTcp(host, port, bytes) {
  log.debug("Entering sendTcp(). " + host + ":" + port);
  log.debug("Leaving sendTcp().");
  return new Promise(function (resolve, reject) {
    const socket = new net.Socket();
    let buffer = Buffer.alloc(0);
    let settled = false;
    const finish = function (err, value) {
      log.debug("Entering finish().");
      if (settled) {
        log.debug("Leaving finish(). Already settled.");
        return;
      }
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (err) {
        reject(err);
        log.debug("Leaving finish(). Refused.");
        return;
      }
      resolve(value);
      log.debug("Leaving finish().");
    };
    const timer = setTimeout(function () {
      finish(new Error("the KDC at " + host + ":" + port + " did not answer " +
                       "within " + TIMEOUT_MS + "ms"));
    }, TIMEOUT_MS);
    socket.on("connect", function () {
      const framed = Buffer.alloc(4 + bytes.length);
      framed.writeUInt32BE(bytes.length, 0);
      Buffer.from(bytes).copy(framed, 4);
      socket.write(framed);
    });
    socket.on("data", function (chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 4) {
        return;
      }
      const declared = buffer.readUInt32BE(0);
      if (buffer.length < 4 + declared) {
        return;
      }
      finish(null, Buffer.from(buffer.subarray(4, 4 + declared)));
    });
    socket.on("end", function () {
      finish(new Error("the KDC at " + host + ":" + port + " closed the " +
                       "connection after " + buffer.length + " byte(s) " +
                       "without a whole reply"));
    });
    socket.on("error", function (e) {
      finish(new Error("could not talk to the KDC at " + host + ":" + port +
                       ": " + e.message));
    });
    socket.connect(Number(port), host);
  });
}

// MS-KKDCP: the same length-framed message inside a KDC-PROXY-MESSAGE
// (SEQUENCE { kerb-message [0] OCTET STRING, target-domain [1] OPTIONAL, … }).
// `target-domain` is left out on purpose: the KDC routes by the realm NAME in
// the request (kerberos/CLAUDE.md), and a job that also named it here could
// not tell which of the two did the routing.
async function sendProxy(baseUrl, bytes) {
  log.debug("Entering sendProxy(). " + baseUrl);
  const framed = Buffer.alloc(4 + bytes.length);
  framed.writeUInt32BE(bytes.length, 0);
  Buffer.from(bytes).copy(framed, 4);
  const body = Buffer.from(
    asn1.encSequence([asn1.encContext(0, asn1.encOctetString(framed))]));
  const r = await fetch(baseUrl + "/KdcProxy", {
    method: "POST",
    headers: { "Content-Type": "application/kerberos" },
    body: body
  });
  const raw = Buffer.from(await r.arrayBuffer());
  if (r.status !== 200) {
    log.debug("Leaving sendProxy(). HTTP " + r.status);
    throw new Error("POST " + baseUrl + "/KdcProxy answered " + r.status +
                    ": " + raw.toString("utf8").slice(0, 300));
  }
  const outer = asn1.readTlv(prim.toBytes(raw), 0);
  const fields = asn1.readTaggedSequence(outer.value);
  const unwrapped = asn1.decOctetString(fields[0]);
  log.debug("Leaving sendProxy().");
  // The same four-byte length, on the way back.
  return Buffer.from(unwrapped.subarray(4));
}

// A transport as a function of the message, so an exchange never knows which
// one it is on. `label` goes into every assertion message.
function tcpTransport(host, port) {
  log.debug("Entering tcpTransport().");
  log.debug("Leaving tcpTransport().");
  return {
    label: "TCP " + host + ":" + port,
    send: function (bytes) {
      log.debug("Entering send().");
      log.debug("Leaving send().");
      return sendTcp(host, port, bytes);
    }
  };
}

function proxyTransport(baseUrl) {
  log.debug("Entering proxyTransport().");
  log.debug("Leaving proxyTransport().");
  return {
    label: "MS-KKDCP " + baseUrl + "/KdcProxy",
    send: function (bytes) {
      log.debug("Entering send().");
      log.debug("Leaving send().");
      return sendProxy(baseUrl, bytes);
    }
  };
}

// ---------------------------------------------------------------------------
// A KRB-ERROR, flattened to what an assertion wants to say about it.
// ---------------------------------------------------------------------------
function errorSummary(error) {
  log.debug("Entering errorSummary().");
  const e = error || {};
  const code = e.errorCode !== undefined ? e.errorCode
                                         : ((e.error || {}).code);
  log.debug("Leaving errorSummary(). " + code);
  return {
    code: code,
    name: (e.error || {}).name || "",
    eText: e.eText || "",
    realm: e.realm || "",
    raw: e,
    toString: function () {
      log.debug("Entering toString().");
      log.debug("Leaving toString().");
      return code + " " + ((e.error || {}).name || "") +
             (e.eText ? " (\"" + e.eText + "\")" : "");
    }
  };
}

// The one AS-REQ shape every call below sends. `padata` is the only thing
// that changes between the two round trips of an exchange.
function asRequest(realm, username, padata, nonce) {
  log.debug("Entering asRequest().");
  const now = Date.now();
  log.debug("Leaving asRequest().");
  return msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: padata || [],
    reqBody: {
      // A LIST OF BIT NUMBERS (krb5_drive.js says why that matters).
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.RENEWABLE],
      cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [username] },
      realm: realm,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", realm] },
      till: new Date(now + 8 * 3600 * 1000),
      rtime: new Date(now + 24 * 3600 * 1000),
      nonce: nonce,
      etypes: ETYPES
    }
  });
}

// ---------------------------------------------------------------------------
// THE AS EXCHANGE, AS TWO ROUND TRIPS WHOSE FIRST IS MEANT TO FAIL.
//
// Answers a record of BOTH, rather than a TGT or a throw, because the job
// asserts on each: what the first refusal offered (the method list and the
// salt), and whether the second was a TGT or a refusal and which.
//
//   { first:   { kind, error? },            the bare AS-REQ's answer
//     offered: [padata types in the method-data],
//     info:    the ETYPE-INFO2 entry used (etype, salt, s2kparams),
//     second:  { kind, error? } | null,     the pre-authenticated answer
//     tgt:     { ticket, sessionKey, etype, client, realm, flags, flagNames,
//                sname, srealm, nonceEchoed, kvno, endtime } | null }
//
// `opts.password` is what the client key is derived from; a WRONG one is how
// the job produces KDC_ERR_PREAUTH_FAILED. `opts.stampOffsetMs` moves the
// PA-ENC-TIMESTAMP, for a skew negative. `opts.keys` — `{ <etype>: bytes }`,
// read out of a KEYTAB (#59, `sts_kerberos_keytab.js`) — is used IN PLACE OF a
// password: the etype chosen is the first one the KDC offered that a key is
// given for, and no string-to-key runs at all, which is what `kinit -k` does.
// ---------------------------------------------------------------------------
async function asExchange(transport, realm, username, opts) {
  log.debug("Entering asExchange(). " + username + "@" + realm + " over " +
            transport.label);
  const options = opts || {};
  const out = { first: null, offered: [], info: null, second: null,
                tgt: null };

  const bare = msgs.readKdcResponse(
    await transport.send(asRequest(realm, username, [], randomNonce())));
  out.first = bare.kind === "KRB-ERROR"
    ? { kind: bare.kind, error: errorSummary(bare.error) }
    : { kind: bare.kind };
  if (bare.kind !== "KRB-ERROR") {
    // A KDC that issued a TGT with no pre-authentication. The job asserts
    // this never happens; it is reported rather than thrown so it can.
    log.debug("Leaving asExchange(). No pre-authentication was asked for.");
    return out;
  }
  const err = bare.error || {};
  out.offered = (err.eDataPaData || []).map(function (pa) {
    return pa.type;
  });
  if (out.first.error.code !== 25) {
    log.debug("Leaving asExchange(). Refused before pre-authentication: " +
              out.first.error.toString());
    return out;
  }
  const entry = (err.eDataPaData || []).filter(function (pa) {
    return pa.type === msgs.PA_TYPE.ETYPE_INFO2;
  })[0];
  if (!entry) {
    log.debug("Leaving asExchange(). No ETYPE-INFO2.");
    return out;
  }
  const infos = msgs.readEtypeInfo2(entry.value) || [];
  const given = options.keys || null;
  const chosen = ETYPES.map(function (id) {
    return infos.filter(function (one) {
      return one.etype === id && (!given || !!given[id]);
    })[0];
  }).filter(Boolean)[0];
  if (!chosen) {
    log.debug("Leaving asExchange(). No etype in common.");
    return out;
  }
  out.info = { etype: chosen.etype, salt: chosen.salt,
               s2kparams: chosen.s2kparams };

  // RFC 3961 string-to-key over the password and the salt the KDC named.
  // ASYNCHRONOUS, like every call on a profile (krb5_drive.js says why that
  // bites).
  const profile = kcrypto.etypeById(chosen.etype);
  const key = given
    ? Uint8Array.from(given[chosen.etype])
    : await profile.stringToKey(
      String(options.password), prim.utf8(chosen.salt || (realm + username)),
      chosen.s2kparams);
  const stamp = msgs.encPaEncTsEnc(
    new Date(Date.now() + Number(options.stampOffsetMs || 0)), 0);
  const padata = [{
    type: msgs.PA_TYPE.ENC_TIMESTAMP,
    value: msgs.encEncryptedData({
      etype: chosen.etype,
      cipher: await profile.encrypt(key,
        kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP, stamp)
    })
  }];
  const nonce = randomNonce();
  const reply = msgs.readKdcResponse(
    await transport.send(asRequest(realm, username, padata, nonce)));
  if (reply.kind === "KRB-ERROR") {
    out.second = { kind: reply.kind, error: errorSummary(reply.error) };
    log.debug("Leaving asExchange(). Refused: " + out.second.error.toString());
    return out;
  }
  out.second = { kind: reply.kind };
  const rep = reply.rep;
  // Key usage 3, under the CLIENT's long-term key: opening this is the
  // client's proof that the KDC holds the same key, i.e. that the password
  // the person typed is the one the KDC derived from.
  const part = msgs.readEncKdcRepPart(
    await kcrypto.etypeById(rep.encPart.etype).decrypt(
      key, kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));
  out.tgt = {
    ticket: rep.ticket,
    sessionKey: part.key.key,
    etype: part.key.etype,
    client: rep.cname,
    realm: rep.crealm,
    flags: part.flags,
    flagNames: msgs.ticketFlagNames(part.flags),
    sname: part.sname,
    srealm: part.srealm,
    nonceEchoed: part.nonce === nonce,
    kvno: rep.encPart.kvno,
    replyEtype: rep.encPart.etype,
    endtime: part.endtime
  };
  log.debug("Leaving asExchange(). A TGT, flags " +
            out.tgt.flagNames.join(","));
  return out;
}

// ---------------------------------------------------------------------------
// THE TGS EXCHANGE.
//
// The three things that go wrong in a TGS-REQ (RFC 4120 sections 5.4.1 and
// 7.5.1), written out because they are the assembly this client must get
// right on its own: the body is encoded ONCE and those exact
// bytes are both checksummed and sent; the checksum is key usage 6 and the
// Authenticator key usage 7, both under the TGT's SESSION key; and the reply's
// enc-part is key usage 8 (no subkey is sent here, so never 9).
//
// Answers { ok: true, ticket, sessionKey, etype, client, realm, sname, srealm,
// flagNames, nonceEchoed } or { ok: false, error }.
// ---------------------------------------------------------------------------
async function tgsExchange(transport, tgt, sname, realm) {
  log.debug("Entering tgsExchange(). " + (sname.name || []).join("/") +
            " over " + transport.label);
  const profile = kcrypto.etypeById(tgt.etype);
  const nonce = randomNonce();
  const body = msgs.encKdcReqBody({
    kdcOptions: [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.RENEWABLE],
    realm: realm || tgt.realm,
    sname: sname,
    till: new Date(Date.now() + 8 * 3600 * 1000),
    nonce: nonce,
    etypes: ETYPES
  });
  const checksum = await profile.checksum(tgt.sessionKey,
    kcrypto.KEY_USAGE.TGS_REQ_AUTH_CKSUM, body);
  const now = new Date();
  const authenticator = msgs.encAuthenticator({
    crealm: tgt.realm,
    cname: tgt.client,
    cksum: { type: profile.checksumType, checksum: checksum },
    cusec: (now.getMilliseconds() * 1000) % 1000000,
    ctime: new Date(Math.floor(now.getTime() / 1000) * 1000),
    subkey: null,
    seqNumber: randomNonce()
  });
  const apReq = msgs.encApReq({
    apOptions: [],
    ticket: tgt.ticket,
    authenticator: {
      etype: tgt.etype,
      cipher: await profile.encrypt(tgt.sessionKey,
        kcrypto.KEY_USAGE.TGS_REQ_AUTH, authenticator)
    }
  });
  const request = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.TGS_REQ,
    padata: [{ type: msgs.PA_TYPE.TGS_REQ, value: apReq }],
    // The SAME bytes the checksum covered; `raw` is used verbatim.
    reqBody: { raw: body }
  });
  const reply = msgs.readKdcResponse(await transport.send(request));
  if (reply.kind === "KRB-ERROR") {
    const error = errorSummary(reply.error);
    log.debug("Leaving tgsExchange(). Refused: " + error.toString());
    return { ok: false, error: error };
  }
  const rep = reply.rep;
  const part = msgs.readEncKdcRepPart(
    await kcrypto.etypeById(rep.encPart.etype).decrypt(tgt.sessionKey,
      kcrypto.KEY_USAGE.TGS_REP_ENCPART_SESSKEY, rep.encPart.cipher));
  log.debug("Leaving tgsExchange(). A ticket for " +
            msgs.principalToString(part.sname, part.srealm));
  return {
    ok: true,
    kind: reply.kind,
    ticket: rep.ticket,
    sessionKey: part.key.key,
    etype: part.key.etype,
    client: rep.cname,
    realm: rep.crealm,
    sname: part.sname,
    srealm: part.srealm,
    flagNames: msgs.ticketFlagNames(part.flags),
    nonceEchoed: part.nonce === nonce,
    endtime: part.endtime
  };
}

// ---------------------------------------------------------------------------
// AN AP-REQ, WRAPPED FOR GSS-API (RFC 4121 section 4.1), FOR A SERVICE TICKET.
//
// The Authenticator's checksum is RFC 4121's 0x8003 structure — channel
// bindings and context flags, NOT a checksum over anything — and the
// Authenticator is key usage 11 under the TICKET's session key. A subkey is
// offered, as every real initiator does; it keys the mechListMIC.
//
// `opts.ctimeOffsetMs` moves the Authenticator's time, for the skew negative;
// `opts.corrupt` flips a byte of the sealed Authenticator, for the integrity
// negative. Answers { token, apReq, subkey, ctime, cusec }.
// ---------------------------------------------------------------------------
async function apRequest(ticket, opts) {
  log.debug("Entering apRequest().");
  const options = opts || {};
  const profile = kcrypto.etypeById(ticket.etype);
  const flags = [gss.GSS_FLAG.MUTUAL, gss.GSS_FLAG.INTEG, gss.GSS_FLAG.CONF];
  const gssChecksum = gss.buildGssChecksum({ flags: flags,
                                             channelBindings: null,
                                             delegation: null });
  // KerberosTime has no fractional seconds, so ctime goes out truncated and
  // the sub-second part travels in cusec — and the AP-REP echoes both.
  const at = new Date(Date.now() + Number(options.ctimeOffsetMs || 0));
  const ctime = new Date(Math.floor(at.getTime() / 1000) * 1000);
  const cusec = (at.getMilliseconds() * 1000 +
                 Math.floor(Math.random() * 1000)) % 1000000;
  const subkey = { etype: ticket.etype,
                   key: kcrypto.randomBytes(profile.keyBytes) };
  const authenticator = msgs.encAuthenticator({
    crealm: ticket.realm,
    cname: ticket.client,
    cksum: { type: gss.CHECKSUM_TYPE_GSS, checksum: gssChecksum },
    cusec: cusec,
    ctime: ctime,
    subkey: subkey,
    seqNumber: randomNonce()
  });
  const sealed = Buffer.from(await profile.encrypt(ticket.sessionKey,
    kcrypto.KEY_USAGE.AP_REQ_AUTH, authenticator));
  if (options.corrupt) {
    // One byte in the middle of the ciphertext: well-formed DER around it,
    // so the only thing that can notice is the integrity check.
    sealed[Math.floor(sealed.length / 2)] ^= 0x01;
  }
  const apReq = msgs.encApReq({
    apOptions: [msgs.AP_OPTION.MUTUAL_REQUIRED],
    ticket: ticket.ticket,
    authenticator: { etype: ticket.etype, cipher: new Uint8Array(sealed) }
  });
  log.debug("Leaving apRequest().");
  return {
    apReq: apReq,
    token: gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, apReq),
    subkey: subkey,
    ctime: ctime,
    cusec: cusec
  };
}

// ---------------------------------------------------------------------------
// A SPNEGO NegTokenInit (RFC 4178) around that AP-REQ — what a browser sends
// after `WWW-Authenticate: Negotiate`. `mechTypes` defaults to what Windows
// offers, Kerberos first; `mic: true` adds the initiator's mechListMIC keyed
// with the Authenticator's subkey (key usage 25), over the MechTypeList's own
// DER — not the `[0]`-tagged form, the commonest mistake in this protocol.
// ---------------------------------------------------------------------------
const WINDOWS_MECHS = [spnego.KRB5_MECH_OID, spnego.MS_KRB5_MECH_OID,
                       "1.3.6.1.4.1.311.2.2.10"];

async function negTokenInit(built, opts) {
  log.debug("Entering negTokenInit().");
  const options = opts || {};
  const mechs = options.mechTypes || WINDOWS_MECHS;
  let mic = null;
  if (options.mic) {
    mic = await spnego.computeMechListMic({
      key: built.subkey.key,
      etype: built.subkey.etype,
      role: "initiator",
      mechListDer: spnego.mechTypeListDer(mechs),
      sequenceNumber: 0
    });
  }
  const init = spnego.encodeNegTokenInit({
    mechTypes: mechs,
    mechToken: built.token,
    mechListMic: mic
  });
  log.debug("Leaving negTokenInit().");
  return Buffer.from(init.token);
}

// ---------------------------------------------------------------------------
// WHAT THE ACCEPTOR ANSWERED, from the `WWW-Authenticate: Negotiate <token>`
// on a reply. Answers null when there is no token, else
// { negState, negStateName, supportedMech, first, apRep?, error? } — `apRep`
// when the responseToken is an AP-REP (opened under the ticket's session key,
// key usage 12, and its ctime/cusec echo compared), `error` when it is a
// KRB-ERROR. RFC 4178's negState has no reason field, so the KRB-ERROR is the
// whole of a rejection's diagnosis.
// ---------------------------------------------------------------------------
async function readNegotiate(header, ticket, built) {
  log.debug("Entering readNegotiate().");
  const match = /^Negotiate\s+(\S+)/i.exec(String(header || ""));
  if (!match) {
    log.debug("Leaving readNegotiate(). No token.");
    return null;
  }
  const bytes = new Uint8Array(Buffer.from(match[1], "base64"));
  const parsed = spnego.decodeNegotiationToken(bytes);
  const out = { kind: parsed.kind, first: bytes[0],
                negState: parsed.negState, negStateName: parsed.negStateName,
                supportedMech: parsed.supportedMech, apRep: null,
                error: null };
  if (!parsed.responseToken) {
    log.debug("Leaving readNegotiate(). No responseToken.");
    return out;
  }
  let inner = parsed.responseToken;
  if (inner.length && inner[0] === 0x60) {
    inner = gss.decodeInitialContextToken(inner).inner;
  }
  const identified = msgs.identify(inner);
  if (identified &&
      identified.applicationNumber === msgs.APPLICATION.KRB_ERROR) {
    out.error = errorSummary(msgs.readKrbError(inner));
    log.debug("Leaving readNegotiate(). " + out.error.toString());
    return out;
  }
  const apRep = msgs.readApRep(inner);
  const part = msgs.readEncApRepPart(
    await kcrypto.etypeById(apRep.encPart.etype).decrypt(ticket.sessionKey,
      kcrypto.KEY_USAGE.AP_REP_ENCPART, apRep.encPart.cipher));
  out.apRep = {
    ctimeEchoed: !!(built && part.ctime &&
                    part.ctime.getTime() === built.ctime.getTime()),
    cusecEchoed: !!(built && part.cusec === built.cusec),
    acceptorSubkey: part.subkey || null
  };
  log.debug("Leaving readNegotiate(). An AP-REP.");
  return out;
}

module.exports = {
  msgs: msgs,
  spnego: spnego,
  ETYPES: ETYPES,
  WINDOWS_MECHS: WINDOWS_MECHS,
  tcpTransport: tcpTransport,
  proxyTransport: proxyTransport,
  asExchange: asExchange,
  tgsExchange: tgsExchange,
  apRequest: apRequest,
  negTokenInit: negTokenInit,
  readNegotiate: readNegotiate,
  errorSummary: errorSummary
};
