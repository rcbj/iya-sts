// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_model_wire.js
//
// ===========================================================================
// WHAT THE GNAP ENDPOINTS ANSWER, HELD TO THE RECORDED WIRE, OVER THE WIRE
// (#1579 item 6; #444 D12, phase 8).
//
// `tests/gnap_model_wire.js` holds every answer of a scripted conversation
// with every GNAP endpoint — discovery, the grant endpoint's refusals and
// its pending and issued answers, continuation, modification and
// revocation, the start modes and `/gnap-api`, token management,
// introspection and resource registration — to
// `tests/gnap_model_wire.snapshot.json`, from a child process in the
// default realm, development and then product mode. This job has the same
// conversation, step for step and in the same order, with a RUNNING
// service, in a development and a product realm of this run's own, and
// holds every answer to the snapshot after putting back what only the
// place of the conversation changes:
//
//   * the realm: this run's `/realm/<id>` prefix, in every path and URL;
//   * the origin: `https://localhost:<port>` is the recorded
//     `http://127.0.0.1:<port>`, in every spelling; HSTS and a cookie's
//     `Secure`, which only a TLS listener sends;
//   * the error code the in-process file read off the response object is
//     read off `/admin-api/audit` — the newest `protocol.call` row the step
//     added, or none;
//   * the model's gaps (`gnap_model.gaps()` in process) are the codes a gap
//     records, STS-GNAP-0910 and 0911, which must not rise in either realm.
//
// The in-process file's placeholders (`VOLATILE_MEMBERS`, `RANDOM_MEMBERS`,
// `scrub()`, `normalise()`) are its own, copied unchanged.
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const K = require("./oauth_wire_kit.js").kit("sts_gnap_model_wire");
const G = require("./gnap_wire_kit.js").gnapKit(K);

const log = K.log;
const gnap = G.gnap;
const SNAPSHOT = process.env.GNAP_WIRE_SNAPSHOT ||
  path.join(__dirname, "..", "gnap_model_wire.snapshot.json");
const SKIPPED_HEADERS = ["date", "connection", "keep-alive",
                         "content-length", "etag", "transfer-encoding",
                         "strict-transport-security"];

function kept(headers) {
  log.debug("Entering kept().");
  const out = {};
  Object.keys(headers || {}).sort().forEach(function (name) {
    if (SKIPPED_HEADERS.indexOf(name) < 0) {
      out[name] = headers[name];
    }
  });
  log.debug("Leaving kept().");
  return out;
}

function parsed(type, text) {
  log.debug("Entering parsed().");
  if (/json/.test(String(type || "")) && text) {
    try {
      log.debug("Leaving parsed().");
      return JSON.parse(text);
    } catch (e) {
      log.debug("Caught in parsed(): " + ((e && e.message) || e));
      // Not JSON after all: recorded as the in-process file records it.
      log.debug("Leaving parsed().");
      return { unparsed: text };
    }
  }
  log.debug("Leaving parsed().");
  return text;
}

async function newestSeq(realm) {
  log.debug("Entering newestSeq().");
  const r = await K.send(K.rb(realm) + "/admin-api/audit?per=1&action=" +
                         "protocol.call");
  log.debug("Leaving newestSeq().");
  return Number((r.json || {}).newestSeq || 0);
}

// The error code of the newest protocol.call row past `before` for
// `target`, or "".
async function codeSince(realm, before, target) {
  log.debug("Entering codeSince().");
  const pathOnly = String(target).split("?")[0];
  let code = "";
  for (let i = 0; i < 6; i += 1) {
    const r = await K.send(K.rb(realm) + "/admin-api/audit?per=5&action=" +
                           "protocol.call");
    const rows = ((r.json || {}).events || []).filter(function (one) {
      return Number(one.seq || 0) > before &&
             String(one.target || one.summary || "").indexOf(pathOnly) >= 0;
    });
    if (rows.length) {
      code = String(rows[0].errorCode || "");
      break;
    }
    await K.sleep(80);
  }
  log.debug("Leaving codeSince(). " + code);
  return code;
}

// The fixtures of one mode, written through /admin-api: what the
// in-process file made with `applications.createApplication()`.
async function fixtures(mode, h) {
  log.debug("Entering fixtures(). " + mode.name);
  const tag = mode.name.slice(0, 3);
  const RS_URI = "https://rs-" + tag + ".gw.test/api";
  const FINISH = "https://client-" + tag + ".gw.test/finish";
  const TYPE = "gw-" + tag + "-read";
  const keys = {};
  const make = async function (id, kind, fields) {
    keys[id] = new gnap.Client({ key: gnap.newKey("ES256", "kid-" + id) });
    await G.entry(h, id, kind, keys[id], fields);
  };
  const who = "gw-" + tag + "-user";
  await K.ok(h.realmApi + "/users/create", { username: who, invent: false,
    attributes: { cn: who, sn: who, givenName: who,
                  mail: who + "@gw.test" } }, "created the person");
  await make("gw-" + tag + "-rs", "gnap-resource-server", {
    gnapResourceServerUri: RS_URI,
    oauthAuthorizationDetailsType: [JSON.stringify({ type: TYPE,
      actions: ["read", "write"] })] });
  await make("gw-" + tag + "-web", "gnap-client", { gnapFinishUri: [FINISH] });
  await make("gw-" + tag + "-trusted", "gnap-client",
             { gnapSkipInteraction: "TRUE" });
  log.debug("Leaving fixtures().");
  return { tag: tag, RS_URI: RS_URI, FINISH: FINISH, TYPE: TYPE,
           keys: keys };
}

// One mode's conversation, as the in-process file has it.
async function conversation(mode, realm) {
  log.debug("Entering conversation(). " + mode.name);
  const h = realm.h;
  const prefix = "/realm/" + realm.id;
  const base = K.base + prefix;
  const wire = [];
  const f = await fixtures(mode, h);
  const RS_URI = f.RS_URI;
  const FINISH = f.FINISH;
  const TYPE = f.TYPE;
  const web = f.keys["gw-" + f.tag + "-web"];
  const trusted = f.keys["gw-" + f.tag + "-trusted"];
  const rs = f.keys["gw-" + f.tag + "-rs"];
  const right = function (extra) {
    return Object.assign({ type: TYPE, actions: ["read"],
                           locations: [RS_URI] }, extra || {});
  };
  const remember = async function (name, method, p, r, before) {
    const code = await codeSince(realm.id, before, prefix + p);
    wire.push({ mode: mode.name, step: name, method: method, path: p,
                status: r.status, headers: kept(r.headers),
                body: r.json !== null && r.json !== undefined
                  ? r.json : r.text,
                code: code });
    return r;
  };
  const answered = function (r) {
    r.json = parsed(r.headers["content-type"], r.text);
    return r;
  };
  const plain = async function (name, method, p, opts) {
    const o = opts || {};
    const before = await newestSeq(realm.id);
    const headers = Object.assign({}, o.headers || {});
    let body = Buffer.alloc(0);
    if (o.json !== undefined) {
      body = Buffer.from(typeof o.json === "string" ? o.json
                                                    : JSON.stringify(o.json));
      headers["content-type"] = headers["content-type"] ||
        "application/json";
      headers["content-length"] = String(body.length);
    }
    let r;
    try {
      r = answered(await gnap.rawRequest(method, base + p, headers, body,
                                         null));
    } catch (e) {
      log.debug("Caught in plain(): " + ((e && e.message) || e));
      // Recorded as the in-process file records a failed request.
      r = { status: 0, headers: {}, text: String(e && e.message),
            json: null };
    }
    return remember(name, method, p, r, before);
  };
  const signed = async function (name, who, method, p, opts) {
    const before = await newestSeq(realm.id);
    let r;
    try {
      r = answered(await who.send(method, base + p, opts || {}));
    } catch (e) {
      log.debug("Caught in signed(): " + ((e && e.message) || e));
      // Recorded as the in-process file records a failed request.
      r = { status: 0, headers: {}, text: String(e && e.message),
            json: null };
    }
    return remember(name, method, p, r, before);
  };
  // A URL the service answered, as a path under this realm.
  const pathOf = function (uri) {
    if (!uri) {
      return "/nowhere";
    }
    const p = new URL(uri).pathname;
    return p.indexOf(prefix + "/") === 0 ? p.slice(prefix.length) : p;
  };

  // DISCOVERY.
  await plain('discovery', 'OPTIONS', '/gnap');
  await plain('rs discovery', 'GET', '/.well-known/gnap-as-rs');
  await plain('keys', 'GET', '/gnap/keys');
  await plain('zcap controller', 'GET', '/gnap/zcap/controller');
  await plain('biscuit revocations', 'GET', '/gnap/biscuit/revocations');
  await plain('discovery, a named server', 'OPTIONS', '/gw-as/gnap');
  await plain('rs discovery, a named server', 'GET',
              '/.well-known/gnap-as-rs/gw-as');
  await plain('discovery, a bad server name', 'OPTIONS',
              '/' + encodeURIComponent('a b') + '/gnap');

  // THE GRANT ENDPOINT: REFUSALS.
  const webKey = { key: web.keyObject() };
  await plain('grant, not JSON', 'POST', '/gnap',
              { json: 'not json',
                headers: { 'content-type': 'text/plain' } });
  await plain('grant, unsigned', 'POST', '/gnap',
              { json: { client: webKey,
                        access_token: { access: [right()] } } });
  await signed('grant, an array', web, 'POST', '/gnap', { json: [1] });
  await signed('grant, a control character', web, 'POST', '/gnap',
               { json: { client: { key: web.keyObject(),
                                   display: { name: 'a\u0001b' } },
                         access_token: { access: [right()] },
                         interact: { start: ['redirect'] } } });
  await signed('grant, a wrong type', web, 'POST', '/gnap',
               { json: { client: webKey, access_token: { access: 'x' },
                         interact: { start: ['redirect'] } } });
  await signed('grant, an overlong label', web, 'POST', '/gnap',
               { json: { client: webKey,
                         access_token: { access: [right()],
                                         label: 'x'.repeat(300) },
                         interact: { start: ['redirect'] } } });
  await signed('grant, a finish member nobody defines', web, 'POST',
               '/gnap',
               { json: { client: webKey,
                         access_token: { access: [right()] },
                         interact: { start: ['redirect'],
                                     finish: { method: 'redirect',
                                               uri: FINISH,
                                               nonce: 'n-1',
                                               extra: 1 } } } });
  await signed('grant, a finish uri that is not a URI', web, 'POST',
               '/gnap',
               { json: { client: webKey,
                         access_token: { access: [right()] },
                         interact: { start: ['redirect'],
                                     finish: { method: 'redirect',
                                               uri: 'not a uri',
                                               nonce: 'n-1' } } } });
  await signed('grant, no client', web, 'POST', '/gnap',
               { json: { access_token: { access: [right()] } } });
  await signed('grant, the durable flag', web, 'POST', '/gnap',
               { json: { client: webKey,
                         access_token: { access: [right()],
                                         flags: ['durable'] },
                         interact: { start: ['redirect'] } } });
  await signed('grant, an unknown start mode', web, 'POST', '/gnap',
               { json: { client: webKey,
                         access_token: { access: [right()] },
                         interact: { start: ['telepathy'] } } });
  await signed('grant, an unknown finish method', web, 'POST', '/gnap',
               { json: { client: webKey,
                         access_token: { access: [right()] },
                         interact: { start: ['redirect'],
                                     finish: { method: 'carrier-pigeon',
                                               uri: FINISH,
                                               nonce: 'n-1' } } } });
  await signed('grant, an interaction reference', web, 'POST', '/gnap',
               { json: { client: webKey, interact_ref: 'abc',
                         access_token: { access: [right()] } } });
  await signed('grant, two tokens without labels', web, 'POST', '/gnap',
               { json: { client: webKey,
                         access_token: [{ access: [right()] },
                                        { access: [right()] }],
                         interact: { start: ['redirect'] } } });
  await signed('grant, a location nobody registered', web, 'POST',
               '/gnap',
               { json: { client: webKey,
                         access_token: { access: [right({
                           locations: ['https://nobody.gw.test/'] })] },
                         interact: { start: ['redirect'] } } });
  await signed('grant, no resource server at all', web, 'POST', '/gnap',
               { json: { client: webKey,
                         access_token: { access: ['gw-just-a-string'] },
                         interact: { start: ['redirect'] } } });
  await signed('grant, an unknown sub_id format', web, 'POST', '/gnap',
               { json: { client: webKey,
                         subject: { sub_id_formats: ['telepathy'] },
                         interact: { start: ['redirect'] } } });
  await signed('grant, an unknown key', new gnap.Client({
    key: gnap.newKey('ES256', 'kid-gw-stranger') }), 'POST', '/gnap',
               { json: { client: { key: { proof: 'httpsig',
                                          jwk: gnap.newKey('ES256',
                                            'kid-gw-other').publicJwk } },
                         access_token: { access: [right()] },
                         interact: { start: ['redirect'] } } });
  const stranger = new gnap.Client({ key: gnap.newKey('ES256',
                                                      'kid-gw-new') });
  await signed('grant, a key nobody registered', stranger, 'POST',
               '/gnap',
               { json: { client: { key: stranger.keyObject() },
                         access_token: { access: [right()] },
                         interact: { start: ['redirect'] } } });
  await signed('grant, nothing to interact with', web, 'POST', '/gnap',
               { json: { client: webKey,
                         access_token: { access: [right()] } } });

  // THE GRANT ENDPOINT: PENDING AND ISSUED.
  let r = await signed('grant, pending with redirect and finish', web,
                       'POST', '/gnap',
                       { json: { client: webKey,
                                 access_token: { access: [right()] },
                                 subject: { sub_id_formats: ['opaque'] },
                                 interact: { start: ['redirect'],
                                             finish: {
                                               method: 'redirect',
                                               uri: FINISH,
                                               nonce: 'gw-nonce-1' } } } });
  const pending = (r.json && r.json.continue) ? r.json : null;
  r = await signed('grant, pending with a user code', web, 'POST',
                   '/gnap',
                   { json: { client: webKey,
                             access_token: { access: [right()],
                                             label: 'one' },
                             interact: { start: ['user_code',
                                                 'user_code_uri',
                                                 'app'] } } });
  const coded = (r.json && r.json.continue) ? r.json : null;
  r = await signed('grant, issued to a trusted client', trusted, 'POST',
                   '/gnap',
                   { json: { client: { key: trusted.keyObject() },
                             access_token: { access: [right()] } } });
  const issued = (r.json && r.json.access_token) ? r.json : null;
  await signed('grant, two labelled tokens', trusted, 'POST', '/gnap',
               { json: { client: { key: trusted.keyObject() },
                         access_token: [{ access: [right()],
                                          label: 'a' },
                                        { access: [right({
                                          actions: ['write'] })],
                                          label: 'b' }] } });
  await signed('grant, the bearer flag', trusted, 'POST', '/gnap',
               { json: { client: { key: trusted.keyObject() },
                         access_token: { access: [right()],
                                         flags: ['bearer'] } } });

  // CONTINUATION.
  const cont = pending && pending.continue;
  const contPath = cont ? pathOf(cont.uri) : '/gnap/continue/none';
  const contToken = cont && cont.access_token
    ? cont.access_token.value : 'none';
  await signed('continue, no token', web, 'POST', contPath, {});
  await signed('continue, a bad grant path', web, 'POST',
               '/gnap/continue/' + encodeURIComponent('a b'),
               { token: contToken });
  await signed('continue, an unknown token', web, 'POST', contPath,
               { token: 'gw-unknown-token' });
  await signed('continue, a body member nobody defines', web, 'POST',
               contPath, { token: contToken, json: { unexpected: 1 } });
  r = await signed('continue, an interaction reference out of turn',
                   web, 'POST', contPath,
                   { token: contToken,
                     json: { interact_ref: 'gw-ref' } });
  const turned = r.json && r.json.continue && r.json.continue.access_token
    ? r.json.continue.access_token.value : contToken;
  r = await signed('continue, a poll', web, 'POST', contPath,
                   { token: turned });
  let next = r.json && r.json.continue && r.json.continue.access_token
    ? r.json.continue.access_token.value : turned;
  r = await signed('continue, a modification', web, 'PATCH', contPath,
                   { token: next,
                     json: { access_token: { access: [right({
                       actions: ['read', 'write'] })] },
                             interact: { start: ['redirect'] } } });
  next = r.json && r.json.continue && r.json.continue.access_token
    ? r.json.continue.access_token.value : next;
  await signed('continue, a modification with a wrong type', web,
               'PATCH', contPath,
               { token: next, json: { access_token: 5 } });
  await signed('continue, revoked', web, 'DELETE', contPath,
               { token: next });
  await signed('continue, after the revocation', web, 'POST', contPath,
               { token: next });

  // THE START MODES AND /gnap-api.
  const start = coded && coded.interact;
  await plain('start, the app link', 'GET',
              start && start.app ? pathOf(start.app) : '/gnap/app/x');
  await plain('start, an unknown link', 'GET', '/gnap/interact/gw-none');
  await plain('start, the user code page', 'GET', '/gnap/code');
  await plain('gnap-api, the index', 'GET', '/gnap-api');
  await plain('gnap-api, the code view', 'GET', '/gnap-api/code');
  await plain('gnap-api, a code act unbound', 'POST', '/gnap-api/code',
              { json: { code: 'nothing' } });
  await plain('gnap-api, an approval view of nothing', 'GET',
              '/gnap-api/approve/gw-none');
  await plain('gnap-api, an approval act unbound', 'POST',
              '/gnap-api/approve/gw-none', { json: { decision: 'deny' } });

  // TOKEN MANAGEMENT.
  const tokenObject = issued && issued.access_token;
  const tokenValue = tokenObject ? tokenObject.value : 'gw-no-token';
  const manage = tokenObject && tokenObject.manage;
  const managePath = manage ? pathOf(manage.uri) : '/gnap/token/none';
  const manageToken = manage && manage.access_token
    ? manage.access_token.value : 'none';
  await signed('manage, a bad handle', trusted, 'POST',
               '/gnap/token/' + encodeURIComponent('a b'),
               { token: manageToken });
  await signed('manage, an unknown token', trusted, 'POST', managePath,
               { token: 'gw-unknown' });

  // INTROSPECTION AND REGISTRATION (RFC 9767).
  const rsKey = { key: rs.keyObject() };
  await plain('introspect, unsigned', 'POST', '/gnap/introspect',
              { json: { access_token: tokenValue,
                        resource_server: rsKey } });
  await signed('introspect, a live token', rs, 'POST',
               '/gnap/introspect',
               { json: { access_token: tokenValue,
                         resource_server: rsKey } });
  await signed('introspect, an unknown token', rs, 'POST',
               '/gnap/introspect',
               { json: { access_token: 'gw-not-a-token',
                         resource_server: rsKey } });
  await signed('introspect, a malformed token', rs, 'POST',
               '/gnap/introspect',
               { json: { access_token: 'not a token',
                         resource_server: rsKey } });
  await signed('introspect, no resource server', rs, 'POST',
               '/gnap/introspect',
               { json: { access_token: tokenValue } });
  await signed('register, a resource set', rs, 'POST', '/gnap/resource',
               { json: { access: [right()], resource_server: rsKey,
                         token_formats_supported: ['jwt-signed'],
                         token_introspection_required: true } });
  await signed('register, owners of no identifier', rs, 'POST',
               '/gnap/resource',
               { json: { access: [right({ identifier: 'gw-thing' })],
                         resource_server: rsKey,
                         resource_owners: { 'gw-other': 'cn=x' } } });
  await signed('register, a wrong type', rs, 'POST', '/gnap/resource',
               { json: { access: [right()], resource_server: rsKey,
                         token_introspection_required: 'yes' } });

  // ROTATION AND REVOCATION OF THE ISSUED TOKEN, last: the token is
  // gone after them.
  const fresh = new gnap.Client({ key: gnap.newKey('ES256',
                                                   'kid-gw-fresh') });
  r = await signed('manage, a rotation', trusted, 'POST', managePath,
                   { token: manageToken });
  const rotated = r.json && r.json.access_token
    ? r.json.access_token : null;
  const rotatedPath = rotated && rotated.manage
    ? pathOf(rotated.manage.uri) : managePath;
  const rotatedToken = rotated && rotated.manage &&
    rotated.manage.access_token ? rotated.manage.access_token.value
    : manageToken;
  await signed('manage, a key rotation body nobody defines', trusted,
               'POST', rotatedPath,
               { token: rotatedToken, json: { key: fresh.keyObject(),
                                              extra: 1, more: 2,
                                              again: 3, last: 4 } });
  await signed('manage, revoked', trusted, 'DELETE', rotatedPath,
               { token: rotatedToken });
  await signed('manage, after the revocation', trusted, 'POST',
               rotatedPath, { token: rotatedToken });
  log.debug("Leaving conversation(). " + wire.length);
  return wire;
}

// WHAT ONLY THE PLACE CHANGES, put back before the placeholders.
function placed(one, id) {
  log.debug("Entering placed().");
  let text = JSON.stringify(one);
  const origin = new URL(K.base);
  const swaps = [[K.base + "/realm/" + id, "http://127.0.0.1:1"],
    [encodeURIComponent(K.base + "/realm/" + id),
     encodeURIComponent("http://127.0.0.1:1")],
    [K.base, "http://127.0.0.1:1"],
    [encodeURIComponent(K.base), encodeURIComponent("http://127.0.0.1:1")],
    ["/realm/" + id, ""],
    [origin.host, "127.0.0.1:1"]];
  swaps.forEach(function (pair) {
    text = text.split(JSON.stringify(pair[0]).slice(1, -1))
      .join(JSON.stringify(pair[1]).slice(1, -1));
  });
  text = text.replace(/; Secure(?=;|")/g, "").replace(/__Host-sts_/g, "sts_")
    // A page shell names the realm's prefix for its runtime; the default
    // realm's names none, and so writes no attribute.
    .replace(/ data-sts-prefix=\\"\\"/g, "");
  log.debug("Leaving placed().");
  return JSON.parse(text);
}

// The first place two values differ, as a dotted path, or null.
function firstDifference(a, b, where) {
  log.debug("Entering firstDifference().");
  if (JSON.stringify(a) === JSON.stringify(b)) {
    log.debug("Leaving firstDifference(). Equal.");
    return null;
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    const keys = Array.from(new Set(Object.keys(a).concat(Object.keys(b))));
    for (let i = 0; i < keys.length; i++) {
      const inner = firstDifference(a[keys[i]], b[keys[i]],
                                    where + "." + keys[i]);
      if (inner) {
        log.debug("Leaving firstDifference().");
        return inner;
      }
    }
  }
  log.debug("Leaving firstDifference().");
  return where + ": " + String(JSON.stringify(b)).slice(0, 300) +
    " where " + String(JSON.stringify(a)).slice(0, 300) + " was recorded";
}

async function test() {
  log.debug("Entering test().");
  const recorded = JSON.parse(fs.readFileSync(SNAPSHOT, "utf8"));
  const MODES = [{ name: "development", product: false },
                 { name: "product", product: true }];
  let wire = [];
  const gaps = [];
  for (const mode of MODES) {
    const realm = await G.gnapRealm("gw" + mode.name.slice(0, 3),
                                    mode.name);
    const before0910 = await K.codeCount(realm.id, "STS-GNAP-0910");
    const before0911 = await K.codeCount(realm.id, "STS-GNAP-0911");
    const steps = await conversation(mode, realm);
    wire = wire.concat(steps.map(function (one) {
      return placed(one, realm.id);
    }));
    const rose = (await K.codeCount(realm.id, "STS-GNAP-0910")) -
      before0910 + (await K.codeCount(realm.id, "STS-GNAP-0911")) -
      before0911;
    if (rose) {
      gaps.push(mode.name + ": " + rose);
    }
  }
  K.check("every answer of the conversation is its model's (none recorded " +
          "under STS-GNAP-0910/0911)", function () {
    assert.deepStrictEqual(gaps, []);
  });
  const now = normalise({ wire: wire, problems: [] }).wire;
  K.check("the conversation has as many steps as recorded (" +
          recorded.wire.length + ")", function () {
    assert.strictEqual(now.length, recorded.wire.length);
  });
  const differing = [];
  recorded.wire.forEach(function (one, i) {
    const why = firstDifference(one, now[i], "wire");
    if (why) {
      differing.push(one.mode + ", " + one.step + ": " + why);
    } else {
      K.check(one.mode + ", " + one.step + ": " + one.method +
              " answers as recorded (" + one.status + ")", function () {
        assert.ok(true);
      });
    }
  });
  differing.forEach(function (one) {
    log.error("DIFFERS: " + one.slice(0, 1500));
  });
  K.check("every step answers as recorded", function () {
    assert.strictEqual(differing.length, 0, differing.length +
                       " step(s) differ; the first: " +
                       String(differing[0]).slice(0, 600));
  });
  log.debug("Leaving test().");
}



// Member names whose value differs from run to run.
const VOLATILE_MEMBERS = ['value', 'nonce', 'jti', 'instance_id', 'x', 'y',
  'n', 'e', 'kid', 'x5c', 'publicKeyMultibase', 'publicKeyJwk', 'id', 'iat',
  'exp', 'nbf', 'created', 'user_code', 'code', 'interact_ref', 'csrf',
  'root_public_key', 'root_public_keys', 'revocation_ids', 'hash',
  'controller', 'verificationMethod', 'capabilityDelegation',
  'capabilityInvocation', 'assertionMethod', 'authentication', 'sub',
  'cnf', 'jkt', 'expires_in', 'wait', 'status_list', 'resource_reference'];

// Members whose string value is a random token the record keeps as
// `<random>` (#1579). The text pattern below found them only while the
// value happened to hold a capital and a digit, and a grant_id or a finish
// nonce that drew neither failed the record under load; by name, it cannot.
const RANDOM_MEMBERS = ['grant_id', 'finish'];

// Walks a value: a volatile member's value is replaced by its name, and a
// URL's handle segment by a placeholder.
function scrub(value, name) {
  log.debug("Entering scrub().");
  if (name && VOLATILE_MEMBERS.indexOf(name) >= 0 && value !== undefined &&
      value !== null && value !== '' && name !== 'code') {
    log.debug("Leaving scrub(). A volatile member.");
    return '<' + name + '>';
  }
  if (name && RANDOM_MEMBERS.indexOf(name) >= 0 &&
      typeof value === 'string' && value !== '') {
    log.debug("Leaving scrub(). A random member.");
    return '<random>';
  }
  if (Array.isArray(value)) {
    const list = value.map(function (one) {
      return scrub(one, name);
    });
    log.debug("Leaving scrub().");
    return list;
  }
  if (value && typeof value === 'object') {
    const out = {};
    Object.keys(value).forEach(function (key) {
      out[key] = scrub(value[key], key);
    });
    log.debug("Leaving scrub().");
    return out;
  }
  if (name === 'set-cookie' && typeof value === 'string') {
    log.debug("Leaving scrub(). A cookie.");
    return value.replace(/=[^;]*/, '=<cookie>');
  }
  if (typeof value === 'number' && value >= 1.7e9 && value < 2.2e9) {
    log.debug("Leaving scrub(). An instant.");
    return '<epoch>';
  }
  log.debug("Leaving scrub().");
  return value;
}

// The run-to-run values left in text, each replaced by a placeholder.
function normalise(record) {
  log.debug("Entering normalise().");
  // An error code's own member is held: the scrub above spares `code`
  // only where it names a GNAP error (a short word); a user code is
  // replaced below by its shape.
  const PATTERNS = [
    // THE PAGE FOOTER (2026-11-14), on every shell and error page: its
    // version and build line differ per build, and what it holds is
    // `tests/page_footer.js`'s to check, so here it is one placeholder.
    ['footer', /<footer class=\\"sts-footer\\".*?<\/footer>/g],
    ['footercss', /body:has\(>\.sts-footer\).*?\.sts-footer-social\{gap:18px\}\}/g],
    ['uuid', /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi],
    ['time', /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g],
    ['httpdate', /[A-Z][a-z]{2}, \d\d [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d GMT/g],
    ['port', /127\.0\.0\.1(:|%3A)\d+/g],
    ['epoch', /\b1[789]\d{8}\b/g],
    ['uptime', /up \d+ second\(s\)/g],
    // The build's version, whose fourth part is the build instant.
    ['version', /\b\d+\.\d+\.\d+\.\d{14}\b/g],
    ['build', /\b20\d{12}\b/g],
    // A handle in a GNAP path: the grant's, the token's, a start link's.
    ['handle', /(\/gnap\/(?:continue|token|interact|app|approve)\/)[A-Za-z0-9_.~-]+/g],
    ['usercode', /"code": "[A-Z0-9]{4}-?[A-Z0-9]{4}"/g],
    ['thumbprint', /urn:ietf:params:oauth:jwk-thumbprint:sha-256:[A-Za-z0-9_-]+/g],
    ['random', /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{20,}/g],
    // A long random value that happened to draw no digit, or no capital
    // (#1579: an interact `finish` nonce escaped the rule above once). At
    // 32 characters and over, only a random value holds a capital or a
    // digit; the snake_case member names that long hold neither.
    ['random', /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[A-Z0-9])[A-Za-z0-9_-]{32,}/g]
  ];
  const text = JSON.stringify(scrub(record), null, 1);
  let out = text;
  PATTERNS.forEach(function (pair) {
    out = out.replace(pair[1], function (value, prefix) {
      if (pair[0] === 'handle') {
        return prefix + '<handle>';
      }
      if (pair[0] === 'usercode') {
        return '"code": "<usercode>"';
      }
      return '<' + pair[0] + '>';
    });
  });
  log.debug("Leaving normalise().");
  return JSON.parse(out);
}

K.main(test, 133);
