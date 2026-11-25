// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: passkey_wire_kit.js
//
// ===========================================================================
// THE PASSKEY JOBS' COMMON PARTS, OVER THE WIRE (#444, D12 phase 5).
//
// **THIS IS A HELPER AND NOT A JOB** (`MANIFEST.js`'s LOCAL_HELPERS). The
// passkey files that held their claims in process (`tests/passkey_*.js`)
// are carried by `sts_passkey_signin_rules.js`, `sts_passkey_policy_rules.js`,
// `sts_passkey_attestation_rules.js` and an extended
// `sts_passkey_dual_lane.js`, and each needs the same five things: a
// throwaway realm of its own, a software authenticator, the ways a passkey
// is registered (the sign-in screen's first use in development, the
// portal's `/account-api/keys`), the ways it signs somebody in (the typed
// passkey step, the usernameless door) and the audit log's codes. They are
// written once here, so a rule a ceremony must keep is kept in one place.
//
// `kit(name, options)` answers a context for one job:
//
//   ctx.realm(prefix, mode)     a realm of the run's STAMP, created through
//                               the root API, `global.mode` set to `mode`
//                               (`development` or `product`) — its
//                               `{ id, base, api }`
//   ctx.call(realm, method, path, body)   the realm's `/admin-api`
//   ctx.setting(realm, key, value) / ctx.reset(realm, key)
//   ctx.savePolicy(realm, fields, profile)  the passkey policy, every row
//                               at its default and `fields` over them
//   ctx.codeCount(realm, code), ctx.newCodes(realm, code, before)
//   ctx.person(realm, name, password)     `/admin-api/users/create`
//   ctx.authenticator(o)        ES256 or ML-DSA-65 (`alg` -7 / -49), BE and
//                               BS (`synced`), an AAGUID, and an attestation
//                               (`attest(ceremony)` answering `{ fmt,
//                               attStmt }`; `none` where left out)
//   ctx.client(realm)           the realm's public OAuth client
//   ctx.screen(realm, headers)  the sign-in screen of an authorization
//                               request: `{ opened, view, cookie }`
//   ctx.usernameless(realm, make)   the usernameless door: armed, `make(c)`
//                               answers the credential, sent
//   ctx.typed(realm, name, o)   a typed sign-in, `{ password }` or
//                               passwordless, to its passkey step:
//                               `{ answer, step }`
//   ctx.ceremony(step, make, key)   that step's ceremony
//   ctx.enrol(client, auth, o)  `/account-api/keys`: begin, the armed
//                               ceremony read back, finish
//   ctx.removeRealms()          only where STS_TEST_REMOVE_REALMS=1
//
// THE AUTHENTICATOR keeps the user handle it was created under and hands
// it back on every assertion, as a discoverable credential does, and signs
// the bytes WebAuthn Level 3 sections 6.1 and 7.2 name. Nothing in it is
// trusted: every key is made when the job runs, and no key material is in
// this repository.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const authnSignin = require("./authn_signin");
const ownPassword = require("./own_password");
const fixtures = require("./oauth_fixtures.js");
const pqc = require("./pqc.js");

const log = require("bunyan").createLogger({ name: "passkey_wire_kit",
  level: process.env.LOG_LEVEL || "info" });

const REDIRECT = "http://localhost:9999/cb";
// A BROWSER'S User-Agent on every sign-in request: a product realm scores
// the risk of a sign-in, and an agent no browser sends is refused
// (STS-RISK-0016) before the rule a section asks about is reached.
const BROWSER = { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) " +
  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" };
const CLIENT = "pk-wire-probe";

function cborHead(major, n) {
  log.debug("Entering cborHead().");
  let out;
  if (n < 24) {
    out = Buffer.from([(major << 5) | n]);
  } else if (n < 256) {
    out = Buffer.from([(major << 5) | 24, n]);
  } else if (n < 65536) {
    out = Buffer.alloc(3);
    out[0] = (major << 5) | 25;
    out.writeUInt16BE(n, 1);
  } else {
    out = Buffer.alloc(5);
    out[0] = (major << 5) | 26;
    out.writeUInt32BE(n, 1);
  }
  log.debug("Leaving cborHead().");
  return out;
}

function cbor(value) {
  log.debug("Entering cbor().");
  let out;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const b = Buffer.from(value);
    out = Buffer.concat([cborHead(2, b.length), b]);
  } else if (typeof value === "string") {
    const b = Buffer.from(value, "utf8");
    out = Buffer.concat([cborHead(3, b.length), b]);
  } else if (typeof value === "number") {
    out = value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  } else if (Array.isArray(value)) {
    out = Buffer.concat([cborHead(4, value.length)].concat(value.map(cbor)));
  } else {
    const entries = value instanceof Map ? Array.from(value.entries())
      : Object.keys(value).map(function (k) {
        return [k, value[k]];
      });
    out = Buffer.concat([cborHead(5, entries.length)].concat(
      entries.map(function (kv) {
        return Buffer.concat([cbor(kv[0]), cbor(kv[1])]);
      })));
  }
  log.debug("Leaving cbor().");
  return out;
}

function sha256(buf) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return nodeCrypto.createHash("sha256").update(buf).digest();
}

function parse(raw) {
  log.debug("Entering parse().");
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in parse(): " + ((e && e.message) || e));
    // Not JSON — a page or an empty answer; the caller quotes `raw`.
    body = null;
  }
  log.debug("Leaving parse().");
  return body;
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function kit(jobName, options) {
  log.debug("Entering kit(). " + jobName);
  const opts = options || {};
  const jobLog = opts.log || log;
  const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
  const root = String(process.env.OID4VCI_ISSUER_URL ||
                      stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
  const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
    .slice(-10);
  const ORIGIN = new URL(root).origin;
  const RP_ID = new URL(root).hostname;
  let checks = 0;

  async function send(method, url, body, headers) {
    log.debug("Entering send(). " + method + " " + url);
    const init = { method: method, redirect: "manual",
                   headers: Object.assign({}, headers || {}) };
    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const r = await fetch(url, init);
    const raw = await r.text();
    log.debug("Leaving send(). " + r.status);
    return { status: r.status, body: parse(raw), raw: raw,
             headers: r.headers };
  }

  const ctx = {
    STAMP: STAMP, root: root, ORIGIN: ORIGIN, RP_ID: RP_ID,
    REDIRECT: REDIRECT, CLIENT: CLIENT, BROWSER: BROWSER, cbor: cbor,
    sha256: sha256,
    send: send, sleep: sleep,

    check: function (what, fn) {
      log.debug("Entering check().");
      fn();
      checks += 1;
      jobLog.info("  [ok] " + what);
      log.debug("Leaving check().");
    },

    checks: function () {
      log.debug("Entering checks().");
      log.debug("Leaving checks().");
      return checks;
    },

    realm: async function (prefix, mode) {
      log.debug("Entering realm(). " + prefix);
      const id = (prefix + "-" + STAMP).slice(0, 40);
      const name = jobName + " " + prefix + " " + STAMP;
      const made = await send("POST", root + "/admin-api/realms/create",
        { id: id, domain: id + ".example.net", name: name });
      assert.ok(made.status === 200 && made.body && made.body.ok !== false,
        "creating the realm " + id + " answered " + made.status + " " +
        made.raw.slice(0, 300));
      const realm = { id: id, name: name, base: root + "/realm/" + id,
                      api: root + "/realm/" + id + "/admin-api" };
      if (mode) {
        const set = await send("POST", root + "/admin-api/realms/set",
          { id: id, key: "global.mode", value: mode });
        assert.ok(set.status === 200 && set.body && set.body.ok !== false,
          "setting " + id + "'s mode to " + mode + " answered " +
          set.status + " " + set.raw.slice(0, 300));
      }
      log.debug("Leaving realm().");
      return realm;
    },

    call: function (realm, method, path, body) {
      log.debug("Entering call(). " + method + " " + path);
      log.debug("Leaving call().");
      return send(method, realm.api + path,
                  method === "GET" ? undefined : (body || {}));
    },

    setting: async function (realm, key, value) {
      log.debug("Entering setting(). " + key + "=" + value);
      const r = await ctx.call(realm, "POST", "/config/set",
                               { key: key, value: String(value) });
      log.debug("Leaving setting(). " + r.status);
      return r;
    },

    mustSet: async function (realm, key, value) {
      log.debug("Entering mustSet(). " + key);
      const r = await ctx.setting(realm, key, value);
      assert.ok(r.status === 200 && r.body && r.body.ok !== false,
        "setting " + key + "=" + value + " in " + realm.id + " answered " +
        r.status + " " + r.raw.slice(0, 300));
      log.debug("Leaving mustSet().");
      return r;
    },

    reset: function (realm, key) {
      log.debug("Entering reset(). " + key);
      log.debug("Leaving reset().");
      return ctx.call(realm, "POST", "/config/reset", { key: key });
    },

    policyDefaults: async function (realm) {
      log.debug("Entering policyDefaults().");
      const page = await ctx.call(realm, "GET", "/policies");
      const defaults = {};
      const fields = (page.body && page.body.passkey &&
                      page.body.passkey.fields) || [];
      fields.forEach(function (field) {
        defaults[field.key] = field.default;
      });
      assert.ok(fields.length > 0, "GET /admin-api/policies answered no " +
        "passkey fields: " + page.status + " " + page.raw.slice(0, 300));
      log.debug("Leaving policyDefaults().");
      return defaults;
    },

    // The passkey policy saved whole — every row at its default, `fields`
    // over them — so a field left out reads as the default, never as what
    // an earlier save left.
    savePolicy: async function (realm, fields, profile, extra) {
      log.debug("Entering savePolicy().");
      const defaults = await ctx.policyDefaults(realm);
      const r = await ctx.call(realm, "POST", "/policies/save-passkey-policy",
        Object.assign({ profile: profile || "default" }, defaults,
                      fields || {}, extra || {}));
      log.debug("Leaving savePolicy(). " + r.status);
      return r;
    },

    mustSavePolicy: async function (realm, fields, profile, extra) {
      log.debug("Entering mustSavePolicy().");
      const r = await ctx.savePolicy(realm, fields, profile, extra);
      assert.ok(r.status === 200 && r.body && r.body.ok !== false,
        "saving the passkey policy " + JSON.stringify(fields) + " in " +
        realm.id + " answered " + r.status + " " + r.raw.slice(0, 400));
      log.debug("Leaving mustSavePolicy().");
      return r;
    },

    codeCount: async function (realm, code) {
      log.debug("Entering codeCount(). " + code);
      const r = await ctx.call(realm, "GET", "/audit?per=500&code=" +
                               encodeURIComponent(code));
      const body = r.body || {};
      log.debug("Leaving codeCount().");
      return Number(body.matched || (body.rows || body.events || []).length ||
                    0);
    },

    // The code's count once it has passed `before` (the audit ring is
    // written as the answer leaves), or what it is after three seconds.
    newCodes: async function (realm, code, before) {
      log.debug("Entering newCodes(). " + code);
      let n = await ctx.codeCount(realm, code);
      for (let i = 0; i < 20 && n <= before; i += 1) {
        await sleep(150);
        n = await ctx.codeCount(realm, code);
      }
      log.debug("Leaving newCodes(). " + n);
      return n - before;
    },

    person: async function (realm, name, password, attributes) {
      log.debug("Entering person(). " + name);
      const body = { username: name, invent: false,
        credential: password ? "password" : "none",
        attributes: Object.assign({ cn: "Passkey " + name,
          givenName: "Passkey", sn: name,
          mail: name + "@passkey-wire.test" }, attributes || {}) };
      // Temporary, then the person's own (#2160, `own_password.js`).
      if (password) {
        body.password = ownPassword.temporaryFor(password);
      }
      const r = await ctx.call(realm, "POST", "/users/create", body);
      assert.ok(r.status === 200 && r.body && r.body.ok !== false,
        "creating " + name + " in " + realm.id + " answered " + r.status +
        " " + r.raw.slice(0, 300));
      if (password) {
        await ownPassword.ownPassword(realm.base, name, password,
          function (who, value) {
            return ctx.call(realm, "POST", "/users/set-password",
                            { user: who, password: value });
          });
      }
      log.debug("Leaving person().");
      return r.body;
    },

    keysOf: async function (realm, name) {
      log.debug("Entering keysOf(). " + name);
      const r = await ctx.call(realm, "GET", "/users?user=" +
                               encodeURIComponent(name));
      log.debug("Leaving keysOf().");
      return (r.body && r.body.factors && r.body.factors.keys) || [];
    },

    client: async function (realm, id) {
      log.debug("Entering client().");
      await fixtures.publicClient(realm.api, id || CLIENT, [REDIRECT]);
      log.debug("Leaving client().");
      return id || CLIENT;
    },

    // ONE SOFTWARE AUTHENTICATOR. `o.alg` -7 (ES256, the default) or -49
    // (ML-DSA-65); `o.synced` sets BE and BS (0x18) on every ceremony,
    // `o.eligible` BE alone; `o.aaguid` (16 bytes) goes in the attested
    // data; `o.attest(c)` answers the attestation `{ fmt, attStmt }` over
    // `c.authData` and `c.clientDataHash`.
    authenticator: function (o) {
      log.debug("Entering authenticator().");
      const a = o || {};
      const alg = a.alg || -7;
      const credentialId = nodeCrypto.randomBytes(32);
      const id = credentialId.toString("base64url");
      const backup = a.synced ? 0x18 : (a.eligible ? 0x08 : 0);
      let cose;
      let sign;
      if (alg === -49) {
        const pair = pqc.generateAkpKeyPair("ML-DSA-65");
        cose = new Map([[1, 7], [3, -49], [-1, Buffer.from(pair.pub)]]);
        sign = function (data) {
          log.debug("Entering sign() (ML-DSA-65).");
          log.debug("Leaving sign() (ML-DSA-65).");
          return Buffer.from(pqc.signWithPriv("ML-DSA-65",
            new Uint8Array(data), pair.priv));
        };
      } else {
        const pair = nodeCrypto.generateKeyPairSync("ec",
          { namedCurve: "prime256v1" });
        const jwk = pair.publicKey.export({ format: "jwk" });
        cose = new Map([[1, 2], [3, -7], [-1, 1],
                        [-2, Buffer.from(jwk.x, "base64url")],
                        [-3, Buffer.from(jwk.y, "base64url")]]);
        sign = function (data) {
          log.debug("Entering sign() (ES256).");
          log.debug("Leaving sign() (ES256).");
          return nodeCrypto.sign("sha256", data, pair.privateKey);
        };
      }
      const aaguid = a.aaguid || Buffer.alloc(16);
      let signCount = 0;
      let userHandle = "";
      const clientData = function (type, challenge) {
        log.debug("Entering clientData().");
        log.debug("Leaving clientData().");
        return Buffer.from(JSON.stringify({ type: type,
          challenge: challenge, origin: a.origin || ORIGIN,
          crossOrigin: false }), "utf8");
      };
      log.debug("Leaving authenticator().");
      return {
        credentialId: id, aaguid: aaguid,
        handle: function () {
          log.debug("Entering handle().");
          log.debug("Leaving handle().");
          return userHandle;
        },
        register: function (challenge, handle, rpId) {
          log.debug("Entering register().");
          userHandle = handle || "";
          const idLen = Buffer.alloc(2);
          idLen.writeUInt16BE(credentialId.length, 0);
          // UP | UV | AT, and BE/BS where the key is synced.
          const authData = Buffer.concat([
            sha256(Buffer.from(rpId || RP_ID, "utf8")),
            Buffer.from([0x45 | backup]), Buffer.alloc(4), aaguid, idLen,
            credentialId, cbor(cose)]);
          const cdj = clientData("webauthn.create", challenge);
          const made = a.attest
            ? a.attest({ authData: authData, clientDataHash: sha256(cdj),
                         sign: sign })
            : { fmt: "none", attStmt: new Map() };
          log.debug("Leaving register().");
          return {
            id: id, rawId: id, type: "public-key",
            authenticatorAttachment: a.attachment || "platform",
            clientExtensionResults: { credProps: { rk: true } },
            response: {
              attestationObject: cbor(new Map([["fmt", made.fmt],
                ["attStmt", made.attStmt], ["authData", authData]]))
                .toString("base64url"),
              clientDataJSON: cdj.toString("base64url"),
              transports: a.transports || ["internal", "hybrid"] } };
        },
        // `uv` false: user presence alone (0x01). `handle` overrides the
        // user handle handed back.
        assert: function (challenge, ao) {
          log.debug("Entering assert().");
          const x = ao || {};
          signCount += 1;
          const count = Buffer.alloc(4);
          count.writeUInt32BE(signCount, 0);
          const authData = Buffer.concat([
            sha256(Buffer.from(x.rpId || RP_ID, "utf8")),
            Buffer.from([(x.uv === false ? 0x01 : 0x05) | backup]), count]);
          const cdj = clientData("webauthn.get", challenge);
          const signature = sign(Buffer.concat([authData, sha256(cdj)]));
          const h = x.handle === undefined ? userHandle : x.handle;
          log.debug("Leaving assert().");
          return {
            id: id, rawId: id, type: "public-key",
            authenticatorAttachment: a.attachment || "platform",
            response: {
              authenticatorData: authData.toString("base64url"),
              clientDataJSON: cdj.toString("base64url"),
              signature: Buffer.from(signature).toString("base64url"),
              userHandle: h || null } };
        }
      };
    },

    // The sign-in screen of an authorization request (a pending record
    // exists only there), with the cookie the authorization endpoint set.
    screen: async function (realm, given, clientId) {
      log.debug("Entering screen().");
      const headers = given || BROWSER;
      const challenge = fixtures.pkce();
      const started = await fetch(realm.base + "/oauth2/authorize?" +
        new URLSearchParams({ client_id: clientId || CLIENT,
          redirect_uri: REDIRECT,
          response_type: "code", scope: "openid",
          code_challenge: challenge.challenge,
          code_challenge_method: challenge.method }).toString(),
        { redirect: "manual", headers: headers });
      const location = started.headers.get("location") || "";
      assert.ok(/\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(location),
        "the authorization endpoint did not send us to the sign-in " +
        "screen: " + started.status + " " + location);
      const set = started.headers.getSetCookie
        ? started.headers.getSetCookie() : [];
      const opened = await authnSignin.screen(realm.base, location, {
        cookie: set.map(function (one) {
          return String(one).split(";")[0];
        }).join("; "), headers: headers });
      log.debug("Leaving screen().");
      return { opened: opened, view: opened.view || {},
               cookie: opened.cookie, location: location };
    },

    // The usernameless door: armed as the page arms it, then `make(armed)`
    // (the armed answer: `challenge`, `rpId`, `options`) answers the
    // credential, or null for none.
    usernameless: async function (realm, make, s) {
      log.debug("Entering usernameless().");
      const screen = s || await ctx.screen(realm);
      const armed = await authnSignin.passkeyOptions(realm.base,
                                                     screen.opened);
      const credential = make ? make((armed.json || {}).challenge || "x",
                                     armed.json || {}) : null;
      const answer = await authnSignin.act(realm.base, "/authn-api/pending/" +
        encodeURIComponent(screen.opened.id) + "/passkey",
        { credential: credential ? JSON.stringify(credential) : "" },
        { cookie: armed.cookie || screen.opened.cookie,
          csrf: screen.opened.csrf, headers: BROWSER });
      answer.armed = armed;
      answer.screen = screen;
      log.debug("Leaving usernameless(). " + answer.next);
      return answer;
    },

    // A typed sign-in to its passkey step: `o.password` signs in with it
    // (the passkey the second step), otherwise passwordless
    // (`webauthn_only`). `{ answer, step }` — the step a `step()` answer,
    // null where the screen did not move to one.
    typed: async function (realm, name, o) {
      log.debug("Entering typed(). " + name);
      const t = Object.assign({ headers: BROWSER }, o || {});
      const s = await ctx.screen(realm, t.headers);
      const fields = t.password
        ? { action: "login", username: name, password: t.password,
            use_webauthn: "1" }
        : { action: "login", username: name, password: "",
            webauthn_only: "1" };
      const answer = await authnSignin.submit(realm.base, s.opened.id,
        fields, { screen: s.opened, cookie: s.opened.cookie,
                  headers: t.headers });
      let step = null;
      if (answer.next === "mfa" && answer.location) {
        step = await authnSignin.step(answer.location,
          { cookie: answer.cookie, headers: t.headers });
      }
      log.debug("Leaving typed(). " + answer.next);
      return { answer: answer, step: step, screen: s };
    },

    // The passkey step's ceremony: armed (for `key`, a chosen passkey),
    // made by `make(armed)`, sent. The answer, `armed` beside it.
    ceremony: function (step, make, key) {
      log.debug("Entering ceremony().");
      log.debug("Leaving ceremony().");
      return authnSignin.passkeyStep(step, make, key
        ? { key: key, headers: BROWSER } : { headers: BROWSER });
    },

    // An enrolment at `/account-api/keys`, as the portal's page makes one:
    // begun (`o.lane`, `o.kind`), the armed ceremony read back off the
    // page, answered by `auth`. `{ begun, pending, done }`.
    enrol: async function (client, auth, o) {
      log.debug("Entering enrol().");
      const e = o || {};
      const begin = { action: "begin", kind: e.kind || "passkey" };
      if (e.lane) {
        begin.lane = e.lane;
      }
      const begun = await client.api("POST", "/account-api/keys", begin);
      if (!(begun.status === 200 && begun.json && begun.json.ok !== false)) {
        log.debug("Leaving enrol(). Not begun: " + begun.status);
        return { begun: begun, pending: null, done: null };
      }
      const page = await client.api("GET", "/account-api/keys");
      const pending = (page.json && page.json.enrol &&
                       page.json.enrol.pending) || {};
      if (!auth) {
        log.debug("Leaving enrol(). Begun only.");
        return { begun: begun, pending: pending, done: null, page: page };
      }
      const done = await client.api("POST", "/account-api/keys",
        { action: "finish", enrolment_id: pending.id,
          credential: JSON.stringify(auth.register(pending.challenge,
            pending.userHandle, pending.rpId)) });
      log.debug("Leaving enrol(). " + done.status);
      return { begun: begun, pending: pending, done: done, page: page };
    },

    redirected: function (answer) {
      log.debug("Entering redirected().");
      log.debug("Leaving redirected().");
      return !!answer && answer.next === "redirect";
    },

    said: function (answer) {
      log.debug("Entering said().");
      log.debug("Leaving said().");
      return ((answer && answer.errors) || []).join(" ") + " " +
             JSON.stringify((answer && answer.json) || {});
    },

    // REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe
    // that would otherwise fill its directory) every realm this run made —
    // each id carries the run's STAMP — is removed, pass or fail. A suite
    // run leaves them standing (tests/CLAUDE.md, *No job removes a realm*).
    removeRealms: async function () {
      log.debug("Entering removeRealms().");
      if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
        log.debug("Leaving removeRealms(). Not asked to.");
        return;
      }
      const listed = await send("GET", root + "/admin-api/realms?per=500");
      const mine = ((listed.body && listed.body.realms) || []).filter(
        function (one) {
          return one.id !== "default" && one.id.indexOf(STAMP) >= 0;
        });
      for (const one of mine) {
        const r = await send("POST", root + "/admin-api/realms/remove",
                             { id: one.id });
        jobLog.info("removed the realm " + one.id + " (" + r.status + ")");
      }
      log.debug("Leaving removeRealms().");
    },

    // The job's main: `test()`, then the realms removed where asked, then
    // the exit status — a failure reported after the removal.
    main: async function (test) {
      log.debug("Entering main().");
      let failure = null;
      try {
        await test();
      } catch (e) {
        log.debug("Caught in main(): " + ((e && e.message) || e));
        // Reported below, after the realms are removed.
        failure = e;
      }
      try {
        await ctx.removeRealms();
      } catch (e) {
        log.debug("Caught in main(): " + ((e && e.message) || e));
        // A realm left behind is not a failed assertion.
        jobLog.warn("removing this run's realms failed: " + e.message);
      }
      if (failure) {
        jobLog.error(failure.stack || failure.message);
        log.debug("Leaving main(). Failed.");
        process.exit(1);
      }
      jobLog.info(checks + " check(s) passed.");
      jobLog.info("Test completed successfully.");
      log.debug("Leaving main().");
    }
  };
  log.debug("Leaving kit().");
  return ctx;
}

module.exports = { kit: kit, cbor: cbor, sha256: sha256 };
