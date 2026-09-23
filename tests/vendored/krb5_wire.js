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
// that changes between the two round trips of an exchange. `etypes` replaces
// ETYPES for a job that offers something else — only rc4-hmac, for #182's
// product refusal.
function asRequest(realm, username, padata, nonce, etypes) {
  log.debug("Entering asRequest().");
  const now = Date.now();
  log.debug("Leaving asRequest().");
  return msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: padata || [],
    reqBody: {
      // A LIST OF BIT NUMBERS (krb5_drive.js says why that matters).
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.RENEWABLE],
      // A service-shaped name (`host/ws1.example.com`) is several
      // components — the armor TGT for FAST is a HOST's (#173).
      cname: String(username).indexOf("/") !== -1
        ? { type: 3, name: String(username).split("/") }
        : { type: msgs.NAME_TYPE.PRINCIPAL, name: [username] },
      realm: realm,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", realm] },
      till: new Date(now + 8 * 3600 * 1000),
      rtime: new Date(now + 24 * 3600 * 1000),
      nonce: nonce,
      etypes: etypes || ETYPES
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
// `opts.etypes` is the list OFFERED, in place of ETYPES (#182).
// ---------------------------------------------------------------------------
async function asExchange(transport, realm, username, opts) {
  log.debug("Entering asExchange(). " + username + "@" + realm + " over " +
            transport.label);
  const options = opts || {};
  const out = { first: null, offered: [], info: null, second: null,
                tgt: null };

  const offered = options.etypes || ETYPES;
  const bare = msgs.readKdcResponse(
    await transport.send(asRequest(realm, username, [], randomNonce(),
                                   offered)));
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
  const chosen = offered.map(function (id) {
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
  // bites). `opts.key` is a key from a KEYTAB instead — a host's (#173).
  const profile = kcrypto.etypeById(chosen.etype);
  // A key from a keytab instead of a password: `opts.key`, one key for the
  // enctype the KDC chose (a host's, #173), or `opts.keys`, a keytab's keys
  // by enctype (a person's, #59).
  const key = options.key ? options.key
    : given ? Uint8Array.from(given[chosen.etype])
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
    await transport.send(asRequest(realm, username, padata, nonce, offered)));
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
    endtime: part.endtime,
    // The two times a sign-out job asserts on (#111): `authtime` is what the
    // KDC compares with the sign-out instant, and `renewTill` bounds a
    // renewal.
    authtime: part.authtime,
    renewTill: part.renewTill
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
// flagNames, nonceEchoed, endtime, authtime, renewTill } or
// { ok: false, error }.
//
// `opts.renew` sets the RENEW option (RFC 4120 section 3.3.3.1): "the same
// ticket again, later", for the ticket being presented — so `sname` must be
// that ticket's own service, and the answer keeps its authtime (#111's
// renewal case).
//
// `opts.etypes` is the list offered, in place of ETYPES, and `opts.subkeyEtype`
// puts a fresh random subkey of that enctype in the Authenticator — the reply
// is then sealed under it at key usage 9 (#182: an rc4-hmac subkey, refused
// in product).
// ---------------------------------------------------------------------------
async function tgsExchange(transport, tgt, sname, realm, opts) {
  log.debug("Entering tgsExchange(). " + (sname.name || []).join("/") +
            " over " + transport.label);
  const options = opts || {};
  const profile = kcrypto.etypeById(tgt.etype);
  const nonce = randomNonce();
  const kdcOptions = [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.RENEWABLE];
  if (options.renew) {
    kdcOptions.push(msgs.KDC_OPTION.RENEW);
  }
  const body = msgs.encKdcReqBody({
    kdcOptions: kdcOptions,
    realm: realm || tgt.realm,
    sname: sname,
    till: new Date(Date.now() + 8 * 3600 * 1000),
    nonce: nonce,
    etypes: options.etypes || ETYPES
  });
  const subkey = options.subkeyEtype ? {
    etype: options.subkeyEtype,
    key: kcrypto.randomBytes(kcrypto.etypeById(options.subkeyEtype).keyBytes)
  } : null;
  const checksum = await profile.checksum(tgt.sessionKey,
    kcrypto.KEY_USAGE.TGS_REQ_AUTH_CKSUM, body);
  const now = new Date();
  const authenticator = msgs.encAuthenticator({
    crealm: tgt.realm,
    cname: tgt.client,
    cksum: { type: profile.checksumType, checksum: checksum },
    cusec: (now.getMilliseconds() * 1000) % 1000000,
    ctime: new Date(Math.floor(now.getTime() / 1000) * 1000),
    subkey: subkey,
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
    await kcrypto.etypeById(rep.encPart.etype).decrypt(
      subkey ? subkey.key : tgt.sessionKey,
      subkey ? kcrypto.KEY_USAGE.TGS_REP_ENCPART_SUBKEY
             : kcrypto.KEY_USAGE.TGS_REP_ENCPART_SESSKEY,
      rep.encPart.cipher));
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
    endtime: part.endtime,
    authtime: part.authtime,
    renewTill: part.renewTill
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
// negative; `opts.subkeyEtype` makes the subkey of that enctype. Answers
// { token, apReq, subkey, ctime, cusec }.
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
  // `opts.subkeyEtype`: an initiator subkey of another enctype than the
  // ticket's session key — rc4-hmac, which product refuses (#182).
  const subkeyEtype = options.subkeyEtype || ticket.etype;
  const subkey = { etype: subkeyEtype,
                   key: kcrypto.randomBytes(
                     kcrypto.etypeById(subkeyEtype).keyBytes) };
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

// ===========================================================================
// FAST, OTP PRE-AUTHENTICATION AND AUTHENTICATION INDICATORS — THE CLIENT
// HALF (#173, 2026-09-22), for `sts_kerberos_fast_otp.js`.
//
// **WRITTEN APART FROM THE SERVICE, ON PURPOSE.** The KDC's FAST is
// `kerberos/krb5_fast.ts` and `krb5_fast_codec.ts` with the PRF in
// `common/crypto.js`; none of those is used here. The DER below is written
// out from RFC 6113 section 5.4, RFC 6560 section 4 and RFC 7751/8129 on the
// vendored codec's tag-length-value primitives, and the pseudo-random
// function and KRB-FX-CF2 from RFC 3961 section 5.1, RFC 3962 section 4, RFC
// 8009 section 5 and RFC 6113 section 5.1 — n-fold as the RFC describes it
// (rotate thirteen bits per copy, add with end-around carry) over BigInt,
// rather than MIT's byte loop the service uses. So an assembly mistake the
// KDC makes cannot make this client agree with it. What IS shared is the
// vendored codec's encodings of the RFC 4120 structures, as for the rest of
// this file.
// ===========================================================================
const nodeCrypto = require("crypto");

const FAST = {
  PA_FX_COOKIE: 133, PA_FX_FAST: 136, PA_FX_ERROR: 137,
  PA_ENCRYPTED_CHALLENGE: 138, PA_OTP_CHALLENGE: 141, PA_OTP_REQUEST: 142,
  KU_OTP_REQUEST: 45, KU_FAST_REQ_CHKSUM: 50, KU_FAST_ENC: 51,
  KU_FAST_REP: 52, KU_FAST_FINISHED: 53, KU_ENC_CHALLENGE_CLIENT: 54,
  KU_ENC_CHALLENGE_KDC: 55, KU_CAMMAC: 64,
  AD_IF_RELEVANT: 1, AD_CAMMAC: 96, AD_AUTHENTICATION_INDICATOR: 97
};

// RFC 3961 section 5.1 n-fold, literally: the input replicated, each copy
// rotated 13 bits right, to lcm(in, out) bits, then summed in out-bit chunks
// with ones'-complement (end-around carry) addition.
function nfold(input, outBytes) {
  log.debug("Entering nfold().");
  const inBits = input.length * 8;
  const outBits = outBytes * 8;
  let a = inBits;
  let b = outBits;
  while (b !== 0) {
    const t = b;
    b = a % b;
    a = t;
  }
  const lcm = inBits / a * outBits;
  const inValue = BigInt("0x" + Buffer.from(input).toString("hex"));
  const inMask = (1n << BigInt(inBits)) - 1n;
  const rotr = function (v, n) {
    log.debug("Entering rotr().");
    const k = BigInt(n % inBits);
    log.debug("Leaving rotr().");
    return ((v >> k) | (v << (BigInt(inBits) - k))) & inMask;
  };
  let whole = 0n;
  for (let copy = 0; copy * inBits < lcm; copy++) {
    whole = (whole << BigInt(inBits)) | rotr(inValue, 13 * copy);
  }
  const outMask = (1n << BigInt(outBits)) - 1n;
  let sum = 0n;
  for (let at = 0; at < lcm; at += outBits) {
    sum += (whole >> BigInt(lcm - at - outBits)) & outMask;
    while (sum > outMask) {
      sum = (sum & outMask) + (sum >> BigInt(outBits));
    }
  }
  log.debug("Leaving nfold().");
  return Buffer.from(sum.toString(16).padStart(outBytes * 2, "0"), "hex");
}

// The pseudo-random function of the four AES enctypes (RFC 3962 section 4,
// RFC 8009 section 5), and of rc4-hmac — HMAC-SHA1 over the octets under the
// key, MIT's and `common/crypto.js`'s — so a job can build FAST armor with an
// RC4 subkey and watch product refuse it (#182).
function prf(etype, key, octets) {
  log.debug("Entering prf(). " + etype);
  const k = Buffer.from(key);
  if (etype === 17 || etype === 18) {
    const cipher = etype === 17 ? "aes-128-ecb" : "aes-256-ecb";
    const enc = function (keyBytes, block) {
      log.debug("Entering enc().");
      const c = nodeCrypto.createCipheriv(cipher, keyBytes, null);
      c.setAutoPadding(false);
      log.debug("Leaving enc().");
      return Buffer.concat([c.update(block), c.final()]);
    };
    // DK(key, "prf") = DR truncated: the n-folded constant encrypted and fed
    // back until there are key-length bytes.
    let block = nfold(Buffer.from("prf"), 16);
    let dk = Buffer.alloc(0);
    while (dk.length < k.length) {
      block = enc(k, block);
      dk = Buffer.concat([dk, block]);
    }
    const tmp = nodeCrypto.createHash("sha1").update(Buffer.from(octets))
      .digest().subarray(0, 16);
    log.debug("Leaving prf().");
    return enc(dk.subarray(0, k.length), tmp);
  }
  if (etype === 19 || etype === 20) {
    const bits = etype === 19 ? 256 : 384;
    const len = Buffer.alloc(4);
    len.writeUInt32BE(bits);
    log.debug("Leaving prf().");
    return nodeCrypto.createHmac(etype === 19 ? "sha256" : "sha384", k)
      .update(Buffer.concat([Buffer.from([0, 0, 0, 1]), Buffer.from("prf"),
                             Buffer.from([0]), Buffer.from(octets), len]))
      .digest().subarray(0, bits / 8);
  }
  if (etype === 23) {
    log.debug("Leaving prf().");
    return nodeCrypto.createHmac("sha1", k).update(Buffer.from(octets))
      .digest();
  }
  log.debug("Leaving prf(). Unsupported.");
  // error-code: none — a test client's own refusal, not a service failure
  throw new Error("krb5_wire: no PRF here for enctype " + etype);
}

// RFC 6113 section 5.1: KRB-FX-CF2, with K1's enctype and size.
function cf2(k1, k2, pepper1, pepper2) {
  log.debug("Entering cf2().");
  const size = kcrypto.etypeById(k1.etype).keyBytes;
  const prfPlus = function (key, pepper) {
    log.debug("Entering prfPlus().");
    let out = Buffer.alloc(0);
    for (let i = 1; out.length < size; i++) {
      out = Buffer.concat([out, prf(key.etype, key.key,
        Buffer.concat([Buffer.from([i]), Buffer.from(pepper)]))]);
    }
    log.debug("Leaving prfPlus().");
    return out.subarray(0, size);
  };
  const a = prfPlus(k1, pepper1);
  const b = prfPlus(k2, pepper2);
  const key = Buffer.alloc(size);
  for (let i = 0; i < size; i++) {
    key[i] = a[i] ^ b[i];
  }
  log.debug("Leaving cf2().");
  return { etype: k1.etype, key: new Uint8Array(key) };
}

// DER of the few RFC 6113 and 6560 structures this client sends and reads.
function tagged(fields) {
  log.debug("Entering tagged().");
  log.debug("Leaving tagged().");
  return asn1.encTaggedSequence(fields);
}

function utf8String(text) {
  log.debug("Entering utf8String().");
  log.debug("Leaving utf8String().");
  return asn1.tlv(0x0c, new Uint8Array(Buffer.from(String(text), "utf8")));
}

function fieldsOf(bytes) {
  log.debug("Entering fieldsOf().");
  const t = asn1.readTlv(bytes, 0);
  log.debug("Leaving fieldsOf().");
  return asn1.readTaggedSequence(t.value);
}

function padataList(t) {
  log.debug("Entering padataList().");
  log.debug("Leaving padataList().");
  return asn1.decSequenceOf(t).map(msgs.readPaData);
}

// A keytab (MIT 0x502), read here for the host key the armor TGT needs: the
// SPN's entries, `{ etype, kvno, key }`.
function readKeytab(buf) {
  log.debug("Entering readKeytab().");
  const b = Buffer.from(buf);
  if (b[0] !== 5 || b[1] !== 2) {
    log.debug("Leaving readKeytab(). Not a keytab.");
    throw new Error("krb5_wire: not an MIT 0x502 keytab");
  }
  const out = [];
  let i = 2;
  while (i + 4 <= b.length) {
    let size = b.readInt32BE(i);
    i += 4;
    if (size < 0) {
      i += -size;
      continue;
    }
    const end = i + size;
    const count = b.readUInt16BE(i);
    i += 2;
    const str = function () {
      log.debug("Entering str().");
      const n = b.readUInt16BE(i);
      const v = b.subarray(i + 2, i + 2 + n).toString("latin1");
      i += 2 + n;
      log.debug("Leaving str().");
      return v;
    };
    const realm = str();
    const name = [];
    for (let k = 0; k < count; k++) {
      name.push(str());
    }
    i += 4 + 4;                      // name type, timestamp
    let kvno = b[i];
    i += 1;
    const etype = b.readUInt16BE(i);
    i += 2;
    const keyLen = b.readUInt16BE(i);
    const key = new Uint8Array(b.subarray(i + 2, i + 2 + keyLen));
    i += 2 + keyLen;
    if (end - i >= 4) {
      kvno = b.readUInt32BE(i);
    }
    i = end;
    out.push({ realm: realm, name: name, etype: etype, kvno: kvno, key: key });
  }
  log.debug("Leaving readKeytab(). " + out.length + " entries.");
  return out;
}

// ---------------------------------------------------------------------------
// ONE FAST-ARMORED AS EXCHANGE (RFC 6113 section 5.4).
//
// `armor` is a TGT from asExchange() — a host's, for krbtgt/REALM. A fresh
// subkey per request, the armor key KRB-FX-CF2(subkey, ticket session key,
// "subkeyarmor", "ticketarmor"), the inner request body under the armor key,
// and a req-checksum over the outer body. `inner(armorKey)` answers the inner
// padata. `opts.replyKey(armorKey)` is the reply key before the KDC's
// strengthen-key (the long-term key for an encrypted challenge; the armor key
// for OTP).
//
// Answers { ok: false, armored, code, eText, padata } for an error — the
// PA-FX-ERROR's, read inside the armor — or { ok: true, tgt, finishedOk,
// nonceOk, strengthened, padata } for an AS-REP. `opts.subkeyEtype` makes the
// armor subkey (and so the armor key) of another enctype than aes256 (#182).
// ---------------------------------------------------------------------------
async function fastAsExchange(transport, realm, username, armor, inner,
                              opts) {
  log.debug("Entering fastAsExchange(). " + username + "@" + realm);
  const options = opts || {};
  const subkeyEtype = options.subkeyEtype || 18;
  const subkey = { etype: subkeyEtype,
                   key: kcrypto.randomBytes(
                     kcrypto.etypeById(subkeyEtype).keyBytes) };
  const armorKey = cf2(subkey, { etype: armor.etype, key: armor.sessionKey },
                       "subkeyarmor", "ticketarmor");
  const armorProfile = kcrypto.etypeById(armorKey.etype);
  const now = new Date();
  const authenticator = msgs.encAuthenticator({
    crealm: armor.realm, cname: armor.client,
    cusec: (now.getMilliseconds() * 1000 + Math.floor(Math.random() * 1000)) %
           1000000,
    ctime: new Date(Math.floor(now.getTime() / 1000) * 1000),
    subkey: subkey });
  const apReq = msgs.encApReq({ apOptions: [], ticket: armor.ticket,
    authenticator: { etype: armor.etype,
      cipher: await kcrypto.etypeById(armor.etype).encrypt(armor.sessionKey,
        kcrypto.KEY_USAGE.AP_REQ_AUTH, authenticator) } });
  const nonce = randomNonce();
  const at = Date.now();
  const body = msgs.encKdcReqBody({
    kdcOptions: [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.RENEWABLE],
    cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [username] },
    realm: realm,
    sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", realm] },
    till: new Date(at + 8 * 3600 * 1000),
    rtime: new Date(at + 24 * 3600 * 1000),
    nonce: nonce, etypes: ETYPES });
  const innerPadata = await inner(armorKey);
  // KrbFastReq ::= SEQUENCE { fast-options [0], padata [1], req-body [2] }
  const fastReq = tagged([
    { tag: 0, value: asn1.encFlags([]) },
    { tag: 1, value: asn1.encSequenceOf(innerPadata.map(msgs.encPaData)) },
    { tag: 2, value: body }
  ]);
  const checksum = await armorProfile.checksum(armorKey.key,
    FAST.KU_FAST_REQ_CHKSUM, body);
  // PA-FX-FAST-REQUEST ::= [0] KrbFastArmoredReq { armor [0] KrbFastArmor
  // { armor-type [0], armor-value [1] }, req-checksum [1], enc-fast-req [2] }
  const armored = asn1.encContext(0, tagged([
    { tag: 0, value: tagged([{ tag: 0, value: asn1.encInteger(1) },
                             { tag: 1, value: asn1.encOctetString(apReq) }]) },
    { tag: 1, value: msgs.encChecksum({ type: armorProfile.checksumType,
                                        checksum: checksum }) },
    { tag: 2, value: msgs.encEncryptedData({ etype: armorKey.etype,
        cipher: await armorProfile.encrypt(armorKey.key, FAST.KU_FAST_ENC,
                                           fastReq) }) }
  ]));
  const request = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: [{ type: FAST.PA_FX_FAST, value: armored }],
    reqBody: { raw: body } });
  const reply = msgs.readKdcResponse(await transport.send(request));
  // The KrbFastResponse inside a PA-FX-FAST-REPLY, if there is one.
  const openFast = async function (padata) {
    log.debug("Entering openFast().");
    const fx = (padata || []).filter(function (pa) {
      return pa.type === FAST.PA_FX_FAST;
    })[0];
    if (!fx) {
      log.debug("Leaving openFast(). None.");
      return null;
    }
    const choice = asn1.readTlv(fx.value, 0);
    const armoredRep = asn1.readChildren(choice.value)[0];
    const encRep = msgs.readEncryptedData(
      asn1.readTaggedSequence(armoredRep.value)[0]);
    const plain = await armorProfile.decrypt(armorKey.key, FAST.KU_FAST_REP,
                                             encRep.cipher);
    const f = fieldsOf(plain);
    log.debug("Leaving openFast().");
    return {
      padata: padataList(f[0]),
      strengthenKey: f[1] ? msgs.readEncryptionKey(f[1]) : null,
      finished: f[2] ? asn1.readTaggedSequence(f[2].value) : null,
      nonce: asn1.decInteger(f[3])
    };
  };
  if (reply.kind === "KRB-ERROR") {
    const outer = reply.error;
    const response = await openFast(outer.eDataPaData || []);
    if (!response) {
      log.debug("Leaving fastAsExchange(). An unarmored error.");
      return { ok: false, armored: false, code: outer.errorCode,
               eText: outer.eText || "", padata: [] };
    }
    const fxError = response.padata.filter(function (pa) {
      return pa.type === FAST.PA_FX_ERROR;
    })[0];
    const inside = fxError ? msgs.readKrbError(fxError.value) : outer;
    log.debug("Leaving fastAsExchange(). An armored error " +
              inside.errorCode);
    return { ok: false, armored: true, code: inside.errorCode,
             outerCode: outer.errorCode, eText: inside.eText || "",
             nonceOk: response.nonce === nonce,
             padata: response.padata };
  }
  const rep = reply.rep;
  const response = await openFast(rep.padata);
  let finishedOk = false;
  if (response && response.finished) {
    const ck = msgs.readChecksum(response.finished[4]);
    finishedOk = await armorProfile.verifyChecksum(armorKey.key,
      FAST.KU_FAST_FINISHED, msgs.encTicket(rep.ticket), ck.checksum);
  }
  const base = options.replyKey ? await options.replyKey(armorKey)
                                : armorKey;
  const replyKey = response && response.strengthenKey
    ? cf2({ etype: response.strengthenKey.etype,
            key: response.strengthenKey.key }, base, "strengthenkey",
          "replykey")
    : base;
  const part = msgs.readEncKdcRepPart(
    await kcrypto.etypeById(replyKey.etype).decrypt(replyKey.key,
      kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));
  log.debug("Leaving fastAsExchange(). A TGT.");
  return {
    ok: true, finishedOk: finishedOk,
    nonceOk: !!response && response.nonce === nonce && part.nonce === nonce,
    strengthened: !!(response && response.strengthenKey),
    padata: response ? response.padata : [],
    tgt: { ticket: rep.ticket, sessionKey: part.key.key,
           etype: part.key.etype, client: rep.cname, realm: rep.crealm,
           flagNames: msgs.ticketFlagNames(part.flags) }
  };
}

// RFC 3961 string-to-key for a password and a salt the caller names, for the
// long-term key a FAST factor combines with the armor key.
async function stringToKey(password, salt, etype) {
  log.debug("Entering stringToKey().");
  const key = await kcrypto.etypeById(etype || 18).stringToKey(
    String(password), prim.utf8(String(salt)), null);
  log.debug("Leaving stringToKey().");
  return key;
}

// The inner padata of an ENCRYPTED CHALLENGE (RFC 6113 section 5.4.6) for a
// long-term key.
function encryptedChallenge(longTermKey) {
  log.debug("Entering encryptedChallenge().");
  log.debug("Leaving encryptedChallenge().");
  return async function (armorKey) {
    const key = cf2(armorKey, longTermKey, "clientchallengearmor",
                    "challengelongterm");
    const now = new Date();
    return [{ type: FAST.PA_ENCRYPTED_CHALLENGE,
              value: msgs.encEncryptedData({ etype: key.etype,
                cipher: await kcrypto.etypeById(key.etype).encrypt(key.key,
                  FAST.KU_ENC_CHALLENGE_CLIENT,
                  msgs.encPaEncTsEnc(now, now.getMilliseconds() * 1000)) })
    }];
  };
}

// RFC 6560's ASN.1 module is IMPLICIT TAGS (its Appendix A): a field's
// context tag REPLACES the universal tag rather than wrapping it — `[0] OCTET
// STRING` is `80 len bytes`, `[2] EncryptedData` is `a2` round
// EncryptedData's own fields. (This client and the KDC were both first
// written explicit, agreed with each other, and MIT's kinit refused the
// challenge: "ASN.1 structure is missing a required field".)
function implicitTag(n, encoded) {
  log.debug("Entering implicitTag().");
  const out = Buffer.from(encoded);
  out[0] = (out[0] & 0x20) ? (0xa0 | n) : (0x80 | n);
  log.debug("Leaving implicitTag().");
  return new Uint8Array(out);
}

function implicitChildren(tlv) {
  log.debug("Entering implicitChildren().");
  const map = {};
  asn1.readChildren(tlv.value).forEach(function (child) {
    map[child.tag & 0x1f] = child;
  });
  log.debug("Leaving implicitChildren().");
  return map;
}

// PA-OTP-CHALLENGE ::= SEQUENCE { nonce [0], otp-service [1],
// otp-tokenInfo [2] SEQUENCE OF OTP-TOKENINFO { flags [0], ... format [4]
// } }, implicit.
function readOtpChallenge(bytes) {
  log.debug("Entering readOtpChallenge().");
  const f = implicitChildren(asn1.readTlv(bytes, 0));
  const tokens = asn1.readChildren(f[2].value).map(function (t) {
    const tf = implicitChildren(t);
    // A BIT STRING's content: one octet of unused bits, then the flags.
    return { flags: asn1.bitsFromFlags(tf[0].value.subarray(1)),
             format: tf[4] ? tf[4].value[0] : null };
  });
  log.debug("Leaving readOtpChallenge().");
  return { nonce: f[0].value,
           service: f[1] ? Buffer.from(f[1].value).toString("utf8") : null,
           tokenInfo: tokens };
}

// The inner padata of an OTP REQUEST (RFC 6560 section 4.2) answering
// `challenge`, with the cookie echoed (RFC 6113 section 5.2's MUST).
function otpRequest(challenge, cookie, pin, value) {
  log.debug("Entering otpRequest().");
  log.debug("Leaving otpRequest().");
  return async function (armorKey) {
    // PA-OTP-ENC-REQUEST ::= SEQUENCE { nonce [0] IMPLICIT OCTET STRING }
    const encRequest = asn1.encSequence([
      implicitTag(0, asn1.encOctetString(challenge.nonce))]);
    const parts = [
      implicitTag(0, asn1.encFlags([])),
      implicitTag(2, msgs.encEncryptedData({ etype: armorKey.etype,
        cipher: await kcrypto.etypeById(armorKey.etype).encrypt(
          armorKey.key, FAST.KU_OTP_REQUEST, encRequest) })),
      implicitTag(5, asn1.encOctetString(Buffer.from(String(value))))
    ];
    if (pin !== null) {
      parts.push(implicitTag(6, utf8String(pin)));
    }
    return (cookie ? [cookie] : []).concat([{ type: FAST.PA_OTP_REQUEST,
      value: asn1.encSequence(parts) }]);
  };
}

// The RFC 8129 indicators in a ticket, opened with the key the SERVICE holds:
// from every AD-CAMMAC (inside AD-IF-RELEVANT) whose svc-verifier verifies
// under that key, at key usage 64 over the elements' own DER.
async function ticketIndicators(ticket, serviceKey) {
  log.debug("Entering ticketIndicators().");
  const profile = kcrypto.etypeById(ticket.encPart.etype);
  const part = msgs.readEncTicketPart(await profile.decrypt(serviceKey,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, ticket.encPart.cipher));
  const found = [];
  let cammacs = 0;
  let verified = 0;
  for (const entry of part.authorizationData || []) {
    if (entry.type !== FAST.AD_IF_RELEVANT) {
      continue;
    }
    for (const inner of msgs.readAuthorizationData(
        asn1.readTlv(entry.data, 0))) {
      if (inner.type !== FAST.AD_CAMMAC) {
        continue;
      }
      cammacs += 1;
      const f = fieldsOf(inner.data);
      const elementsTlv = f[0];
      const svc = f[2] ? asn1.readTaggedSequence(f[2].value) : null;
      const mac = svc ? msgs.readChecksum(svc[3]) : null;
      if (mac && await profile.verifyChecksum(serviceKey, FAST.KU_CAMMAC,
                                              elementsTlv.raw,
                                              mac.checksum)) {
        verified += 1;
        msgs.readAuthorizationData(elementsTlv).forEach(function (el) {
          if (el.type === FAST.AD_AUTHENTICATION_INDICATOR) {
            asn1.decSequenceOf(asn1.readTlv(el.data, 0)).forEach(
              function (s) {
                found.push(Buffer.from(s.value).toString("utf8"));
              });
          }
        });
      }
    }
  }
  log.debug("Leaving ticketIndicators(). " + found.join(","));
  return { indicators: found, cammacs: cammacs, verified: verified,
           flagNames: msgs.ticketFlagNames(part.flags) };
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
  errorSummary: errorSummary,
  // #173: FAST, OTP pre-authentication and authentication indicators.
  FAST: FAST,
  nfold: nfold,
  prf: prf,
  cf2: cf2,
  readKeytab: readKeytab,
  fastAsExchange: fastAsExchange,
  stringToKey: stringToKey,
  encryptedChallenge: encryptedChallenge,
  readOtpChallenge: readOtpChallenge,
  otpRequest: otpRequest,
  ticketIndicators: ticketIndicators
};
