// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: kerberos_chain_kit.js
//
// ---------------------------------------------------------------------------
// WHAT THE TWO KERBEROS CHAIN JOBS SHARE (#486): the four tiers of the
// token-exchange chain jobs (#467) and the WS-Trust ones (#473) — a web
// application, an API gateway, an enterprise service bus and a service
// provider — carried by Kerberos service tickets and [MS-SFU]'s two
// extensions instead of access tokens or assertions. rcbj: "I also want to
// implement the logical equivalent of these two tests with Kerberos."
//
// WHAT IS REUSED, AND WHY ONLY THAT. `token_exchange_chain_kit.js` holds
// the parts that do not depend on the protocol, and they are taken from it
// rather than copied: where the service is, which mode it is in, the
// register's baseline read by TIME rather than by `seq`, and the picture's
// one-box rule (#468). `krb5_wire.js` is the Kerberos client — the AS and
// TGS exchanges, PA-FOR-USER, an AP-REQ — and is used as it is. Everything
// else here is Kerberos's own.
//
// ---------------------------------------------------------------------------
// THE MAPPING, AND WHY.
//
// **IMPERSONATION IS PROTOCOL TRANSITION** ([MS-SFU] section 1.3.1). In the
// OAuth job bob signs in to webapp1 by a means that is not a token exchange
// and apigw1 makes the first impersonating exchange; nothing in the token
// apigw1 is handed names it. Kerberos's version of "a service is told who
// the user is and holds nothing of theirs" is exactly S4U2Self: bob signed
// in to webapp1 some other way (a form, a federation — rcbj: no SPNEGO, and
// no Kerberos ticket of bob's anywhere), webapp1 hands his NAME to apigw1,
// and apigw1 asks the KDC for a ticket for bob to itself. That ticket is
// FORWARDABLE only because apigw1's entry allows impersonation (Active
// Directory's TRUSTED_TO_AUTH_FOR_DELEGATION, here `appDelegationSemantics`
// holding `impersonation`; `common/CLAUDE.md` 3az), and classic S4U2Proxy
// needs forwardable evidence. Then apigw1 S4U2Proxy to esb1, and esb1
// S4U2Proxy to sp1, each presenting the ticket it was handed. So webapp1
// sits where it sits in the OAuth job: the place bob signed in, which makes
// no Kerberos request at all — apigw1, not webapp1, does the S4U2Self,
// because in the OAuth impersonation job apigw1 is the first tier to ACT,
// and webapp1's own token is not a credential the next tier presents.
//
// **DELEGATION IS CONSTRAINED DELEGATION WITH REAL EVIDENCE** ([MS-SFU]
// section 1.3.2). bob authenticates to the KDC himself — an AS exchange with
// his password (the development KDC's key for him in development —
// `personKeys()`), then a TGS exchange for a forwardable ticket to webapp1's
// SPN, handed to webapp1 in an AP-REQ (RFC 4120 section 3.2; no HTTP and no
// SPNEGO framing, rcbj's decision). webapp1 presents that ticket as the
// evidence in S4U2Proxy to apigw1, apigw1 the one it receives to esb1, and
// esb1 to sp1. Three hops where the OAuth jobs have two, as in the WS-Trust
// jobs and for their reason: the ticket bob holds is webapp1's, so webapp1
// is the first tier to act on it.
//
// **WHERE THE CHAIN IS RECORDED: THE PAC's S4U_DELEGATION_INFO** ([MS-PAC]
// section 2.9). A delegated ticket names bob and nobody else — the service
// that asked is nowhere in its cname — and the PAC buffer is the analogue of
// `act`: S4U2proxyTarget, the service the ticket is for, and
// S4UTransitedServices, "all services that have been delegated through by
// this client and subsequent services", which a KDC appends to on each
// S4U2Proxy hop. So:
//
//   delegation, at sp1:     transited [webapp1, apigw1, esb1] — webapp1
//                           FIRST, because the evidence of the first hop
//                           was bob's own ticket to it. This is the Kerberos
//                           spelling of #443's "original client": the party
//                           the user authenticated to is on the record.
//   impersonation, at sp1:  transited [apigw1, esb1] — an S4U2Self ticket
//                           has no delegation information of its own
//                           (nothing was delegated THROUGH anybody yet), so
//                           the list starts with the first S4U2Proxy
//                           requester. webapp1 is not on it and should not
//                           be: it held no Kerberos credential of bob's.
//
// Each intermediate ticket is held to the prefix of that list, and its
// S4U2proxyTarget to the tier it was issued for. The list's element FORM is
// not fixed by [MS-PAC] (`RPC_UNICODE_STRING`, no syntax); this KDC writes
// each requester's bare SPN, and the job accepts the SPN with or without
// `@REALM` and logs which it saw.
//
// **CLASSIC, NOT RESOURCE-BASED.** Each tier's own entry names the next
// tier on `appAllowedToDelegateTo` (msDS-AllowedToDelegateTo) — the
// direction the OAuth and WS-Trust jobs configure, "S delegates to R" on S
// — rather than each target accepting its caller on
// `appAllowedToActOnBehalfOf`. Classic is also the form that needs every
// piece of evidence FORWARDABLE, so the chain proves the flag survives each
// hop, where RBCD would not need it (`sts_kerberos_delegation.js` covers
// RBCD on its own).
//
// **EVERY HOP NAMES ITS TARGET BY THE TARGET'S REGISTERED SPN** (rcbj's
// rule for the other pairs). Each tier is a service principal made with
// `create-service`, which stores its keys on the application entry
// `HTTP/<tier>-<tag>.example.com@<REALM>` and registers the SPN on its
// `krb5ServicePrincipalName`; every TGS-REQ's sname is read off that
// attribute, and the register files every act against that application.
//
// **EACH TIER HOLDS ITS OWN KEY**, from the keytab `create-service` (or, on
// a rerun, `rotate-service`) answers once. With it the job is each tier: it
// gets the tier's TGT (an AS exchange with the key, as `kinit -k` does),
// makes the tier's request, and as the next tier OPENS what it was handed —
// the AP-REQ's ticket with its own long-term key, the Authenticator with the
// ticket's session key, and the PAC's server signature with its own key.
// The KDC and ticket signatures are the krbtgt key's and no service can
// check them; the KDC's own check of them on each piece of evidence (#186)
// is what a later hop's success shows.
//
// Each job passes a TAG (`krbimp`, `krbdel`) and gets entries of its own,
// and a person of its own (`bob_end_user-<tag>`, as #482 does for the
// other chain jobs), so the two never race on one password. The entries are
// LEFT BEHIND, for the picture, and a rerun reconciles them.
//
// OWNED HERE (a LOCAL helper, tests/vendored/MANIFEST.js).
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const path = require("path");
const registry = require("./sts_applications.js");
const facts = require("./service_facts.js");
const chain = require("./token_exchange_chain_kit.js");
const wire = require("./krb5_wire.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "kerberos_chain_kit",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // A hand run without CONFIG_FILE still loads; the level falls back.
      return "info";
    }
  })()
});

// The service's own PAC codec, from the tree this file sits in — the reason
// `krb5_wire.js` gives for loading the codec that way.
const kpac = require(path.join(__dirname, "..", "..", "kerberos",
                               "krb5_pac.js"));
const msgs = wire.msgs;
const kcrypto = wire.kcrypto;

// How long product mode may take to start honouring a write — a stored key
// or an edited entry reaching the process that answers the KDC request.
const SETTLE_MS = 20000;

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// A password the realm's policy accepts, generated per process and never
// derivable: the entry outlives the run on a kept deployment.
function freshPassword() {
  log.debug("Entering freshPassword().");
  log.debug("Leaving freshPassword().");
  return "Krb-" + crypto.randomBytes(15).toString("base64url") + "-7b!";
}

// ---------------------------------------------------------------------------
// WHERE AND WHAT THE KDC IS. The realm is the KDC's own (`krb5.realm`, or
// KRB5_REALM). It is reached over MS-KKDCP (`POST /KdcProxy`) on the
// service's own HTTPS origin by default, because that is the one address
// every place this suite runs can reach — the 8081 stack publishes nothing
// else, and an AWS target only its HTTPS port. STS_KDC_HOST (and
// STS_KDC_PORT) selects raw TCP instead, the other jobs' convention.
// ---------------------------------------------------------------------------
async function kdcContext() {
  log.debug("Entering kdcContext().");
  const base = chain.serviceBase();
  const api = base + "/admin-api";
  const product = await chain.isProduct(base);
  const realm = String(process.env.KRB5_REALM ||
                       await facts.setting(api, "krb5.realm") || "");
  assert.ok(realm, "the service names no Kerberos realm (krb5.realm)");
  let transport;
  if (process.env.STS_KDC_HOST) {
    transport = wire.tcpTransport(process.env.STS_KDC_HOST,
      Number(process.env.STS_KDC_PORT ||
             await facts.setting(api, "krb5.kdcPort") || 88));
  } else {
    transport = wire.proxyTransport(base);
  }
  log.info("[kdc] " + (product ? "product" : "development") + " mode, " +
           "realm " + realm + ", over " + transport.label);
  log.debug("Leaving kdcContext().");
  return { base: base, api: api, product: product, realm: realm,
           transport: transport };
}

// ---------------------------------------------------------------------------
// THE CAST, for one job's tag. `next` is the tier each one forwards to, and
// the one table the entries' `appAllowedToDelegateTo` and the hops are both
// read from, so the two cannot describe different chains.
// ---------------------------------------------------------------------------
function castFor(K, tag) {
  log.debug("Entering castFor(). tag=" + tag);
  const named = function (stem, what) {
    log.debug("Entering named(). " + stem);
    const host = stem + "-" + tag + ".example.com";
    const spn = "HTTP/" + host;
    log.debug("Leaving named().");
    return { stem: stem, what: what, spn: spn,
             identifier: spn + "@" + K.realm,
             // Filled in when provisioned: the keys, the TGT, the SPN as
             // the registry holds it.
             keys: null, tgt: null, registeredSpn: "" };
  };
  const webapp = named("webapp1", "web application");
  const gateway = named("apigw1", "API gateway");
  const esb = named("esb1", "enterprise service bus");
  const provider = named("sp1", "service provider");
  webapp.next = gateway;
  gateway.next = esb;
  esb.next = provider;
  provider.next = null;
  const cast = {
    tag: tag,
    user: "bob_end_user-" + tag,
    password: freshPassword(),
    webapp: webapp, gateway: gateway, esb: esb, provider: provider,
    tiers: [webapp, gateway, esb, provider]
  };
  cast.principal = cast.user + "@" + K.realm;
  log.debug("Leaving castFor().");
  return cast;
}

// ---------------------------------------------------------------------------
// /admin-api.
// ---------------------------------------------------------------------------
async function adminCall(K, method, where, body) {
  log.debug("Entering adminCall(). " + method + " " + where);
  const r = await fetch(K.api + where, { method: method,
    headers: { "Content-Type": "application/json",
               Accept: "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in adminCall(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into whatever message names it.
    json = null;
  }
  log.debug("Leaving adminCall(). " + r.status);
  return { status: r.status, json: json, text: text };
}

async function adminOk(K, where, body, what) {
  log.debug("Entering adminOk(). " + where);
  const r = await adminCall(K, "POST", where, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving adminOk().");
  return r.json;
}

// A keytab's keys by enctype, the NEWEST version of each: a rotated
// principal's keytab carries the versions it replaced as well, as MIT's
// `ktadd` leaves one, and the KDC issues under the newest.
function keysOf(keytabB64) {
  log.debug("Entering keysOf().");
  const keys = {};
  const kvnos = {};
  wire.readKeytab(Buffer.from(String(keytabB64), "base64"))
    .forEach(function (one) {
      if (kvnos[one.etype] === undefined || one.kvno > kvnos[one.etype]) {
        kvnos[one.etype] = one.kvno;
        keys[one.etype] = one.key;
      }
    });
  log.debug("Leaving keysOf(). " + Object.keys(keys).join(","));
  return keys;
}

// A tier's principal and its keys: created, or — on a rerun, when the SPN
// already holds a stored key and `create-service` refuses — rotated, which
// answers a keytab with the new key in it. Either way the job holds the key
// the KDC will issue under from now on.
async function servicePrincipal(K, tier) {
  log.debug("Entering servicePrincipal(). " + tier.spn);
  let r = await adminCall(K, "POST", "/kerberos/principals/create-service",
                          { spn: tier.spn });
  let how = "created";
  if (!(r.status === 200 && r.json && r.json.keytab)) {
    log.info("[registry] " + tier.spn + " was not created (" + r.status +
             ": " + r.text.slice(0, 160) + "); rotating its key instead.");
    r = await adminCall(K, "POST", "/kerberos/principals/rotate-service",
                        { spn: tier.spn });
    how = "rotated";
  }
  assert.ok(r.status === 200 && r.json && r.json.keytab, "neither " +
            "create-service nor rotate-service answered a keytab for " +
            tier.spn + ": " + r.status + " " + r.text.slice(0, 300));
  tier.keys = keysOf(r.json.keytab);
  log.info("[registry] " + tier.spn + " " + how + "; the job holds its " +
           "key(s) for enctype(s) " + Object.keys(tier.keys).join(", ") +
           " at kvno " + r.json.kvno + ".");
  log.debug("Leaving servicePrincipal().");
}

// One multi-valued attribute brought to exactly `wanted`: what the entry
// holds and this job does not want comes off, what is missing goes on.
async function settleList(K, identifier, attribute, wanted) {
  log.debug("Entering settleList(). " + identifier + " " + attribute);
  const entry = await registry.entryOf(K.base, identifier);
  const held = registry.valuesOf(entry && entry.fields &&
                                 entry.fields[attribute]);
  for (const value of held) {
    if (wanted.indexOf(value) < 0) {
      await adminOk(K, "/applications/remove", { application: identifier,
                    attribute: attribute, value: value },
                    "removing " + value + " from " + identifier + "'s " +
                    attribute);
    }
  }
  for (const value of wanted) {
    if (held.indexOf(value) < 0) {
      await adminOk(K, "/applications/add", { application: identifier,
                    attribute: attribute, value: value },
                    "adding " + value + " to " + identifier + "'s " +
                    attribute);
    }
  }
  log.debug("Leaving settleList().");
}

async function settleOne(K, identifier, attribute, value) {
  log.debug("Entering settleOne(). " + identifier + " " + attribute);
  const entry = await registry.entryOf(K.base, identifier);
  const held = registry.valuesOf(entry && entry.fields &&
                                 entry.fields[attribute]);
  if (!value) {
    if (held.length) {
      await settleList(K, identifier, attribute, []);
    }
  } else if (held.length !== 1 || held[0] !== value) {
    await adminOk(K, "/applications/set", { application: identifier,
                  attribute: attribute, value: value },
                  "setting " + identifier + "'s " + attribute);
  }
  log.debug("Leaving settleOne().");
}

// ---------------------------------------------------------------------------
// WHAT EACH ENTRY HOLDS. `plan[stem]` is `{ semantics: [...], default,
// delegates: true|false }` for a tier that acts; a tier absent from the plan
// acts for nobody, and its delegation attributes are cleared.
//
//   appAllowedToDelegateTo       the next tier's application, on every tier
//                                that delegates (classic constrained
//                                delegation; the policy's "S must delegate
//                                to R" with S the requester);
//   appDelegationSemantics       `impersonation` where the tier makes an
//                                S4U2Self whose ticket must be forwardable,
//                                and `delegation` where it makes S4U2Proxy
//                                — an entry that names its semantics allows
//                                only those;
//   appDefaultDelegationSemantics  what the tier uses when a request names
//                                none — a Kerberos request always names its
//                                own, so it is set for the entry's reader.
// ---------------------------------------------------------------------------
async function provisionCast(K, cast, plan) {
  log.debug("Entering provisionCast(). " + cast.tag);
  log.info("=== Provisioning " + cast.user + " and the four service " +
           "principals ===");
  await registry.ensurePerson(K.base, cast.user, cast.password);
  for (const tier of cast.tiers) {
    await servicePrincipal(K, tier);
    const wants = plan[tier.stem] || null;
    await settleList(K, tier.identifier, "appAllowedToDelegateTo",
      wants && wants.delegates ? [tier.next.identifier] : []);
    await settleList(K, tier.identifier, "appDelegationSemantics",
                     wants ? wants.semantics : []);
    await settleOne(K, tier.identifier, "appDefaultDelegationSemantics",
                    wants ? wants.default : "");
    // Unconstrained delegation would put ok-as-delegate on every ticket for
    // the tier, a different mechanism from the one this chain is about.
    await settleOne(K, tier.identifier, "krb5TrustedForDelegation", "");
  }
  // Read back: the reply to a write is the service describing what it wrote,
  // and the question is what the registry holds.
  for (const tier of cast.tiers) {
    const entry = await registry.entryOf(K.base, tier.identifier);
    assert.ok(entry, "the registry has no " + tier.identifier);
    const field = function (name) {
      log.debug("Entering field(). " + name);
      log.debug("Leaving field().");
      return registry.valuesOf(entry.fields && entry.fields[name]);
    };
    const spns = field("krb5ServicePrincipalName");
    assert.ok(spns.length >= 1, tier.identifier + " registers no SPN on " +
              "krb5ServicePrincipalName: " + JSON.stringify(entry.fields));
    tier.registeredSpn = spns.filter(function (one) {
      return one.split("@")[0] === tier.spn;
    })[0] || "";
    assert.ok(tier.registeredSpn, tier.identifier + " should register " +
              tier.spn + " on krb5ServicePrincipalName and registers " +
              JSON.stringify(spns));
    const wants = plan[tier.stem] || null;
    assert.deepStrictEqual(field("appAllowedToDelegateTo"),
      wants && wants.delegates ? [tier.next.identifier] : [],
      tier.identifier + "'s appAllowedToDelegateTo");
    assert.deepStrictEqual(field("appDelegationSemantics").slice().sort(),
      (wants ? wants.semantics : []).slice().sort(),
      tier.identifier + "'s appDelegationSemantics");
    log.info("[registry] " + tier.identifier + ": SPN " +
             tier.registeredSpn + "; delegates to " +
             (field("appAllowedToDelegateTo").join(", ") || "nobody") +
             "; semantics " +
             (field("appDelegationSemantics").join(", ") || "none") + ".");
  }
  log.debug("Leaving provisionCast().");
}

// The PERSON's Kerberos key, derived from a password the reset sets — the
// delegation job's bob authenticates to the KDC himself. A SECOND password,
// because the realm's policy refuses one the account has just had.
//
// WHAT BOB PROVES DIFFERS BY MODE, and only in where the key comes from. A
// product KDC keys a person from their own password, so bob's AS exchange
// derives the key from the password he typed. A development KDC keys EVERY
// person from `krb5.userPassword` and checks no person's own password
// (`kerberos/krb5_person_keys.ts`, *DEVELOPMENT MODE*), so the keytab the
// reset answers — derived from the password THAT KDC uses — is the key he
// proves there. Either way the AS exchange is PA-ENC-TIMESTAMP under the
// key the KDC holds for him, which is the thing the step is about.
async function personKeys(K, cast) {
  log.debug("Entering personKeys(). " + cast.user);
  cast.password = freshPassword();
  const r = await adminCall(K, "POST",
    "/kerberos/principals/reset-person-keytab",
    { username: cast.user, password: cast.password });
  assert.ok(r.status === 200 && r.json && r.json.keytab, "a Kerberos key " +
            "for " + cast.user + ": " + r.status + " " + r.text.slice(0, 300));
  cast.userKeys = K.product ? null : keysOf(r.json.keytab);
  log.info("[registry] " + cast.user + "'s password reset; bob proves " +
           (K.product ? "the key derived from it"
                      : "the development KDC's key for him (the keytab)") +
           " at the AS exchange.");
  log.debug("Leaving personKeys().");
}

// ---------------------------------------------------------------------------
// TICKETS.
// ---------------------------------------------------------------------------
// The sname a request names a tier by: its REGISTERED SPN, read off the
// entry, without the realm (the request's own realm field carries that).
function snameOf(tier) {
  log.debug("Entering snameOf(). " + tier.registeredSpn);
  const name = tier.registeredSpn.split("@")[0].split("/");
  log.debug("Leaving snameOf().");
  return { type: msgs.NAME_TYPE.SRV_HST, name: name };
}

// A TGT, retried through product mode's window: the KDC reads a stored key
// once the change has reached the process that answers.
async function tgtWith(K, name, opts) {
  log.debug("Entering tgtWith(). " + name);
  const started = Date.now();
  let got = await wire.asExchange(K.transport, K.realm, name, opts);
  while (!got.tgt && Date.now() - started < SETTLE_MS) {
    await pause(500);
    got = await wire.asExchange(K.transport, K.realm, name, opts);
  }
  assert.ok(got.tgt, "a TGT for " + name + " over " + K.transport.label +
            ": " + String((got.second || got.first || {}).error || ""));
  log.debug("Leaving tgtWith().");
  return got.tgt;
}

async function tierTgt(K, tier) {
  log.debug("Entering tierTgt(). " + tier.spn);
  if (!tier.tgt) {
    tier.tgt = await tgtWith(K, tier.spn, { keys: tier.keys });
    log.info("[wire] " + tier.spn + " holds a TGT (its own key, as " +
             "`kinit -k`); flags " + tier.tgt.flagNames.join(","));
  }
  log.debug("Leaving tierTgt().");
  return tier.tgt;
}

// A TGS exchange retried through product mode's window: an entry edited a
// moment ago may not have reached the process answering yet, and the KDC
// then refuses (12, 13) or — for S4U2Self — issues without `forwardable`.
// The answer after the window is the one asserted on.
async function settled(what, exchange, good) {
  log.debug("Entering settled(). " + what);
  const started = Date.now();
  let r = await exchange();
  while (!good(r) && Date.now() - started < SETTLE_MS &&
         (r.ok || r.error.code === 12 || r.error.code === 13)) {
    log.info("[wire] " + what + " answered " + (r.ok ? "a ticket flagged " +
             r.flagNames.join(",") : String(r.error)) + "; asking again " +
             "while the entries settle.");
    await pause(1000);
    r = await exchange();
  }
  log.debug("Leaving settled().");
  return r;
}

function forwardable(r) {
  log.debug("Entering forwardable().");
  log.debug("Leaving forwardable().");
  return !!r.ok && r.flagNames.indexOf("forwardable") >= 0;
}

// S4U2SELF: `tier` asks for a ticket for the user TO ITSELF, naming the user
// in PA-FOR-USER — no credential of the user's is involved.
async function s4u2self(K, cast, tier) {
  log.debug("Entering s4u2self(). " + tier.spn);
  const tgt = await tierTgt(K, tier);
  const r = await settled(tier.stem + "'s S4U2Self", function () {
    return wire.tgsExchange(K.transport, tgt, snameOf(tier), K.realm, {
      padata: async function () {
        return [await wire.paForUser(tgt, cast.user, K.realm)];
      }
    });
  }, forwardable);
  assert.ok(r.ok, tier.spn + "'s S4U2Self for " + cast.user + " was " +
            "refused: " + String(r.error));
  log.debug("Leaving s4u2self().");
  return r;
}

// S4U2PROXY: `tier` presents `evidence` — a ticket for the user TO ITSELF —
// with cname-in-addl-tkt, asking for a ticket for the same user to the next
// tier, named by that tier's registered SPN.
async function s4u2proxy(K, cast, tier, evidence) {
  log.debug("Entering s4u2proxy(). " + tier.spn + " -> " + tier.next.spn);
  const tgt = await tierTgt(K, tier);
  const r = await settled(tier.stem + "'s S4U2Proxy to " + tier.next.stem,
    function () {
      return wire.tgsExchange(K.transport, tgt, snameOf(tier.next), K.realm,
        { kdcOptions: [msgs.KDC_OPTION.CNAME_IN_ADDL_TKT],
          additionalTickets: [evidence] });
    }, function (one) {
      return one.ok;
    });
  assert.ok(r.ok, tier.spn + "'s S4U2Proxy to " + tier.next.registeredSpn +
            " for " + cast.user + " was refused: " + String(r.error));
  log.debug("Leaving s4u2proxy().");
  return r;
}

// BOB'S OWN TICKET TO webapp1: his TGT from his own key (an AS exchange
// with PA-ENC-TIMESTAMP — personKeys() says which key that is by mode),
// then a TGS exchange for webapp1's registered SPN. Both forwardable.
async function userTicketTo(K, cast, tier) {
  log.debug("Entering userTicketTo(). " + tier.spn);
  const tgt = await tgtWith(K, cast.user, cast.userKeys
    ? { keys: cast.userKeys } : { password: cast.password });
  assert.strictEqual(tgt.client.name.join("/"), cast.user,
                     "bob's TGT names " + tgt.client.name.join("/"));
  assert.ok(tgt.flagNames.indexOf("forwardable") >= 0, "bob's TGT is not " +
            "forwardable: " + tgt.flagNames.join(","));
  log.info("[wire] " + cast.principal + " authenticated to the KDC (" +
           (cast.userKeys ? "the development key" : "his password") +
           "); TGT flags " + tgt.flagNames.join(","));
  const r = await wire.tgsExchange(K.transport, tgt, snameOf(tier), K.realm);
  assert.ok(r.ok, "bob's ticket to " + tier.registeredSpn + ": " +
            String(r.error));
  log.debug("Leaving userTicketTo().");
  return r;
}

// ---------------------------------------------------------------------------
// THE TARGET'S OWN VALIDATION. `holder` hands `ticket` (a TGS-REP answer) to
// `tier` the Kerberos way, in an AP-REQ (RFC 4120 section 3.2); `tier`
// opens it with what only it holds — its long-term key — then the
// Authenticator with the ticket's session key, then the PAC. Answers what
// the tier learned, the ticket included, which it may present as evidence.
// ---------------------------------------------------------------------------
async function accept(K, cast, tier, ticket) {
  log.debug("Entering accept(). " + tier.spn);
  const built = await wire.apRequest(ticket);
  const apReq = msgs.readApReq(built.apReq);
  const encPart = apReq.ticket.encPart;
  const key = tier.keys[encPart.etype];
  assert.ok(key, tier.spn + " holds no key of the ticket's enctype " +
            encPart.etype);
  const profile = kcrypto.etypeById(encPart.etype);
  const part = msgs.readEncTicketPart(await profile.decrypt(key,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, encPart.cipher));
  const auth = apReq.authenticator;
  const authenticator = msgs.readAuthenticator(await kcrypto.etypeById(
    auth.etype).decrypt(part.key.key, kcrypto.KEY_USAGE.AP_REQ_AUTH,
                        auth.cipher));
  const who = part.cname.name.join("/");
  assert.strictEqual(who, cast.user, tier.spn + " opened a ticket for " +
    who + "@" + part.crealm + " rather than " + cast.principal + ". A " +
    "delegated ticket names the USER; the service that asked is nowhere " +
    "in it.");
  assert.strictEqual(part.crealm, K.realm, "the ticket's crealm");
  assert.strictEqual(authenticator.cname.name.join("/"), who,
                     "the Authenticator names somebody else");
  assert.deepStrictEqual(apReq.ticket.sname.name, snameOf(tier).name,
    "the ticket is for " + apReq.ticket.sname.name.join("/") + " rather " +
    "than " + tier.registeredSpn);
  const flagNames = msgs.ticketFlagNames(part.flags);
  // The PAC: present, the server signature verified with this tier's key,
  // and the user it describes.
  const pacs = kpac.findPacs(part.authorizationData || []);
  assert.strictEqual(pacs.length, 1, tier.spn + "'s ticket should carry " +
                     "one PAC and carries " + pacs.length);
  const pac = kpac.parsePac(pacs[0].bytes);
  const signatures = await kpac.verifySignatures(pac,
    { serverKey: { etype: encPart.etype, key: key } });
  const server = signatures.filter(function (one) {
    return one.type === kpac.TYPE.SERVER_CHECKSUM;
  })[0];
  assert.ok(server && server.verified === true, tier.spn + " cannot " +
            "verify the PAC's server signature with its own key: " +
            JSON.stringify(signatures));
  const logon = kpac.bufferOfType(pac, kpac.TYPE.LOGON_INFO);
  assert.ok(logon && logon.parsed &&
            logon.parsed.effectiveName === cast.user, "the PAC's logon " +
            "information names " + JSON.stringify(logon && logon.parsed &&
                                                  logon.parsed.effectiveName) +
            " rather than " + cast.user);
  const info = kpac.bufferOfType(pac, kpac.TYPE.DELEGATION_INFO);
  const delegation = info ? info.parsed : null;
  log.info("[accepted] " + tier.spn + " opened the AP-REQ: ticket for " +
           who + "@" + part.crealm + ", flags " + flagNames.join(",") +
           ", PAC server signature verified, S4U_DELEGATION_INFO " +
           (delegation ? JSON.stringify({
             target: delegation.s4u2proxyTarget,
             transited: delegation.transitedServices }) : "absent"));
  log.debug("Leaving accept().");
  return { ticket: apReq.ticket, flagNames: flagNames, part: part,
           delegation: delegation };
}

// [MS-PAC] 2.9's two fields, held to what this hop should have written.
// `transited` is the list of tiers delegated through, oldest first; `null`
// means the ticket should carry no S4U_DELEGATION_INFO at all (one no
// S4U2Proxy made).
function sameService(written, tier) {
  log.debug("Entering sameService().");
  const bare = String(written || "");
  log.debug("Leaving sameService().");
  return bare === tier.spn || bare === tier.spn + "@" + tierRealm(tier);
}

function tierRealm(tier) {
  log.debug("Entering tierRealm().");
  log.debug("Leaving tierRealm().");
  return tier.identifier.slice(tier.identifier.indexOf("@") + 1);
}

function assertDelegationInfo(accepted, tier, transited) {
  log.debug("Entering assertDelegationInfo(). " + tier.spn);
  const info = accepted.delegation;
  if (transited === null) {
    assert.strictEqual(info, null, tier.spn + "'s ticket came from no " +
      "S4U2Proxy and carries S4U_DELEGATION_INFO " + JSON.stringify(info));
    log.debug("Leaving assertDelegationInfo(). None, correctly.");
    return;
  }
  assert.ok(info, tier.spn + "'s ticket came out of S4U2Proxy and its PAC " +
            "carries no S4U_DELEGATION_INFO ([MS-PAC] section 2.9)");
  assert.ok(sameService(info.s4u2proxyTarget, tier), "S4U2proxyTarget is " +
            JSON.stringify(info.s4u2proxyTarget) + " and should name " +
            tier.spn + ", the service the ticket was issued for");
  const written = info.transitedServices || [];
  assert.ok(written.length === transited.length &&
            transited.every(function (one, i) {
              return sameService(written[i], one);
            }),
    "S4UTransitedServices should be " + JSON.stringify(transited.map(
      function (one) {
        return one.spn;
      })) + " — every service delegated through, oldest first — and is " +
    JSON.stringify(written));
  log.info("[pac] " + tier.stem + "'s ticket: S4U2proxyTarget " +
           info.s4u2proxyTarget + ", S4UTransitedServices " +
           JSON.stringify(written) + ".");
  log.debug("Leaving assertDelegationInfo().");
}

// What the KDC's reply said about a ticket, before anybody opens it.
function assertReply(K, cast, r, tier, wantForwardable, what) {
  log.debug("Entering assertReply(). " + what);
  assert.strictEqual(r.client.name.join("/"), cast.user, what + " names " +
                     r.client.name.join("/") + " rather than " + cast.user);
  assert.strictEqual(r.realm, K.realm, what + "'s crealm");
  assert.deepStrictEqual(r.sname.name, snameOf(tier).name, what + " is for " +
    r.sname.name.join("/") + " rather than " + tier.registeredSpn);
  assert.ok(r.nonceEchoed, what + ": the reply does not echo the nonce");
  if (wantForwardable) {
    assert.ok(r.flagNames.indexOf("forwardable") >= 0, what + " is not " +
      "FORWARDABLE (" + r.flagNames.join(",") + "), and classic " +
      "constrained delegation needs forwardable evidence for the next hop");
  }
  log.info("[wire] " + what + ": for " + r.client.name.join("/") + "@" +
           r.realm + " to " + r.sname.name.join("/") + ", flags " +
           r.flagNames.join(","));
  log.debug("Leaving assertReply().");
}

// ---------------------------------------------------------------------------
// THE REGISTER. A Kerberos ticket has no identifier to quote — no jti, no
// AssertionID — so the act a hop produced is found by what its `produced`
// note says the ticket was FOR ("for <user>@<REALM> to <SPN>"), which names
// this job's own person and this job's own tier, among the acts after the
// run's baseline TIME (never `seq`). Exactly one must match.
// ---------------------------------------------------------------------------
async function registerSince(K, cast, baselineAt) {
  log.debug("Entering registerSince().");
  const after = await adminCall(K, "GET", "/delegation?q=" +
                                encodeURIComponent(cast.user) + "&per=200");
  assert.strictEqual(after.status, 200, "GET /admin-api/delegation: " +
                     after.text.slice(0, 300));
  const mine = (after.json.acts || []).filter(function (row) {
    return Number(row.at || 0) > baselineAt;
  });
  log.debug("Leaving registerSince(). " + mine.length + " act(s).");
  return { acts: mine, graph: after.json.graph || {} };
}

function actFor(cast, acts, type, target) {
  log.debug("Entering actFor(). " + type + " " + target.spn);
  const note = "for " + cast.principal + " to " + target.spn + ",";
  const found = acts.filter(function (row) {
    return row.type === type && row.outcome === "issued" &&
      (row.produced || []).some(function (one) {
        return String(one.note || "").indexOf(note) === 0;
      });
  });
  assert.strictEqual(found.length, 1, "the delegation register should " +
    "hold exactly ONE issued " + type + " act that produced a ticket " +
    note.replace(/,$/, "") + ", and holds " + found.length + ". What it " +
    "holds since this run started: " + JSON.stringify(acts.map(
      function (row) {
        return row.type + " " + row.outcome + " " + row.initial.presented +
          " -> " + row.intermediary.application + " -> " +
          row.target.application;
      })));
  log.debug("Leaving actFor().");
  return found[0];
}

// One act. `expect`: { type, mode, requester, target, semantics, classic }.
function assertAct(K, cast, act, expect) {
  log.debug("Entering assertAct(). " + expect.type);
  assert.strictEqual(act.protocol, "Kerberos v5", "protocol " + act.protocol);
  assert.strictEqual(act.mode, expect.mode, "the " + expect.type + " act's " +
                     "mode is \"" + act.mode + "\" and should be \"" +
                     expect.mode + "\"");
  assert.strictEqual(act.initial.presented, cast.principal, "the act is " +
    "for \"" + act.initial.presented + "\" rather than " + cast.principal);
  assert.strictEqual(act.intermediary.application,
                     expect.requester.identifier, "the act's middle is \"" +
                     act.intermediary.application + "\" rather than " +
                     expect.requester.identifier);
  assert.strictEqual(act.target.application, expect.target.identifier,
    "the act reached \"" + act.target.application + "\" rather than " +
    expect.target.identifier + ", whose registered SPN the request named");
  assert.strictEqual(act.policed, true, "the KDC decides every S4U request " +
                     "by the issuance policy, and this act is not policed");
  // WHAT ALLOWED IT, by name: the semantics, the requester, the person (by
  // username — the policy names a person of its own realm so) and the
  // application reached. Every part of it is provisioned, so the policy
  // ALLOWS it in both modes, and Kerberos enforces in both.
  const allowed = "the issuance policy allowed " + expect.semantics +
      " by \"" + expect.requester.identifier + "\" for \"" + cast.user +
      "\" to \"" + expect.target.identifier + "\"";
  const said = String(act.authorizedBy || "");
  assert.ok(said.indexOf(allowed) >= 0, "the act should say \"" + allowed +
            " …\" and says \"" + said + "\"");
  if (expect.classic) {
    assert.ok(said.indexOf("appAllowedToDelegateTo on " +
                           expect.requester.identifier) === 0,
      "the act should be attributed to classic constrained delegation — " +
      "appAllowedToDelegateTo on " + expect.requester.identifier +
      " — and says \"" + said + "\"");
  }
  if (expect.type === "krb5-s4u2self") {
    assert.ok(/The ticket is FORWARDABLE\./.test(said), "the S4U2Self act " +
              "should say its ticket is forwardable: \"" + said + "\"");
  }
  log.info("[register] " + act.type + " (" + act.mode + "): " +
           act.initial.presented + " -> " + act.intermediary.application +
           " -> " + act.target.application + "; " + said);
  log.debug("Leaving assertAct().");
}

// THE PICTURE: the one-box rule, as `token_exchange_chain_kit.js` holds it
// (#468), asked of two consecutive S4U2Proxy hops — the tier the first
// reaches and the tier that makes the second are ONE box. The graph keys a
// Kerberos party by its principal's NAME (`HTTP/esb1-….example.com`, the
// realm off, as it keys the person by username), and carries the
// application entry beside it, so each tier's box is found by its
// APPLICATION and handed to the shared check by its key.
function boxOf(graph, tier) {
  log.debug("Entering boxOf(). " + tier.identifier);
  const boxes = (graph.nodes || []).filter(function (n) {
    return n.application === tier.identifier;
  });
  assert.strictEqual(boxes.length, 1, "the picture should hold exactly one " +
    "box standing for the application " + tier.identifier + ", and holds " +
    JSON.stringify(boxes.map(function (n) {
      return n.id;
    })) + " (#468)");
  log.debug("Leaving boxOf(). " + boxes[0].id);
  return boxes[0].id;
}

function assertGraphIsAChain(cast, graph, first, second) {
  log.debug("Entering assertGraphIsAChain(). " + second.stem);
  chain.assertGraphIsAChain({ user: cast.user }, graph,
    [{ clientId: boxOf(graph, first) }, { clientId: boxOf(graph, second) }],
    "delegation");
  log.debug("Leaving assertGraphIsAChain().");
}

module.exports = {
  kdcContext: kdcContext,
  castFor: castFor,
  provisionCast: provisionCast,
  personKeys: personKeys,
  userTicketTo: userTicketTo,
  s4u2self: s4u2self,
  s4u2proxy: s4u2proxy,
  accept: accept,
  assertReply: assertReply,
  assertDelegationInfo: assertDelegationInfo,
  registerBaseline: chain.registerBaseline,
  registerSince: registerSince,
  actFor: actFor,
  assertAct: assertAct,
  assertGraphIsAChain: assertGraphIsAChain
};
