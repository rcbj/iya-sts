// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: tests/peer/peer_commands.js
//
// ===========================================================================
// AN OPENID PROVIDER COMMANDS 1.0 RELYING PARTY'S COMMAND ENDPOINT (#596),
// in place of the service's own `/oauth2/commands/mock-rp`, which #596
// deleted (#591 P5: the runtime ships no demonstration code).
//
// `POST /t/{tenant}/commands`, reached over the peer's TLS listener: a
// `command_endpoint` is https (the provider refuses http at registration),
// so a job names the peer's CA in the realm's `federation.outboundCaFile`.
// A client registered with this address as its `command_endpoint` is a
// relying party that answers every command the way sections 3 to 7 say one
// does.
//
// **WHAT IT CHECKS, as a relying party must (section 9)** — and, unlike the
// mock it replaces, which shared a process and a key store with the
// provider, from the OUTSIDE: the Command Token's signature against a key at
// the `jwks_uri` the realm's OpenID configuration names (fetched over TLS
// the peer verifies), the header `typ: command+jwt`, `iss` equal to that
// configuration's `issuer` (`unrecognized_provider`, 401, otherwise), `exp`,
// `jti` once, no `nonce`, `aud` equal to `client_id`, `tenant` present,
// `sub` only in an account command, `metadata` only in `metadata`,
// `authentication_provider` only in `migrate`.
//
// **WHAT IT KEEPS**: an account state per (client, sub) on the tenant, moved
// by section 6's table — `incompatible_state` (409) where the table says so
// — and an `aud_sub` it invents for each account and returns, so the
// provider learns one.
//
// **ASYNC AND STREAMS**: an `_async` command is answered 202 and its result
// POSTed to the provider's `callback_endpoint` with the token's own
// `callback_token` as Bearer — the endpoint the provider named in its
// `metadata` command, else the issuer's `/oauth2/commands/callback`. The
// mock handed the result over in process; this is the HTTP request a real
// relying party makes, so the callback route is now exercised end to end. A
// streaming tenant command answers `text/event-stream`: an `account-state`
// event per account, then `command-complete`, event ids `1`, `2`, … and
// `Last-Event-ID` honoured.
//
// **TEST KNOBS ON THE REGISTERED URL'S QUERY**, as the mock had them:
// `?fail=N` answers 503 to the first N requests (a retry test), `?drop=K`
// closes a stream after K events once (a resumption test), `?audsub=1`
// says `aud_sub_required` in the metadata answer.
//
// THE READBACK: every command is recorded under the role `commands` — the
// command, the verdict, the status, and the callback's answer for an
// `_async` one — and `GET /t/{tenant}/commands?client_id=…` answers the
// accounts this relying party holds for a client, as the mock's GET did.
// ===========================================================================

const nodeCrypto = require("crypto");
const util = require("./peer_util.js");
const jwt = require("./peer_jwt.js");

const log = util.logger("peer_commands");

const ROLE = "commands";
const CALLBACK_PATH = "/oauth2/commands/callback";
const MAX_JTIS = 5000;

// Section 6's table: the states each command may start from, and where it
// leaves the account ('' — unchanged).
const TABLE = {
  activate: { from: ["unknown"], to: "active" },
  maintain: { from: ["active"], to: "active" },
  suspend: { from: ["active"], to: "suspended" },
  reactivate: { from: ["suspended"], to: "active" },
  archive: { from: ["active", "suspended"], to: "archived" },
  restore: { from: ["archived"], to: "active" },
  delete: { from: ["active", "suspended", "archived"], to: "unknown" },
  audit: { from: null, to: "" },
  invalidate: { from: ["active"], to: "active" },
  migrate: { from: null, to: "" }
};

// What a streaming tenant command does to every account.
const TENANT_MOVES = {
  audit_tenant: null,
  suspend_tenant: { from: ["active"], to: "suspended" },
  archive_tenant: { from: ["active", "suspended"], to: "archived" },
  delete_tenant: { from: ["active", "suspended", "archived"],
                   to: "unknown" },
  invalidate_tenant: null
};

const ACCOUNT_CLAIMS = ["email", "name", "given_name", "family_name",
                        "preferred_username"];

function configure(tenant) {
  log.debug("Entering configure().");
  // Kept across a reconfiguration, as a tenant's keys are: a job that
  // reconfigures mid-run still reads the accounts it made.
  tenant.commands = tenant.commands || {
    accounts: new Map(),
    jtis: new Map(),
    knobs: new Map(),
    callbackEndpoint: "",
    configuration: null,
    jwks: {}
  };
  // The realm may have moved: its discovery is read again.
  tenant.commands.configuration = null;
  tenant.commands.jwks = {};
  log.debug("Leaving configure().");
}

function isAccountCommand(cmd) {
  log.debug("Entering isAccountCommand().");
  log.debug("Leaving isAccountCommand().");
  return Object.prototype.hasOwnProperty.call(TABLE,
    String(cmd).replace(/_async$/, ""));
}

// The aud_sub this relying party gives an account: stable, and not the sub.
function audSubOf(clientId, sub) {
  log.debug("Entering audSubOf().");
  log.debug("Leaving audSubOf().");
  return "rp-" + nodeCrypto.createHash("sha256")
    .update(String(clientId) + "\n" + String(sub)).digest("hex").slice(0, 16);
}

function stateOf(tenant, clientId, sub) {
  log.debug("Entering stateOf().");
  const held = tenant.commands.accounts.get(String(clientId) + " " +
                                            String(sub));
  log.debug("Leaving stateOf().");
  return held ? String(held.state) : "unknown";
}

function setState(tenant, clientId, sub, state, claims) {
  log.debug("Entering setState(). " + state);
  const key = String(clientId) + " " + String(sub);
  if (state === "unknown") {
    tenant.commands.accounts.delete(key);
  } else {
    const held = tenant.commands.accounts.get(key) || {};
    tenant.commands.accounts.set(key, Object.assign({}, held, {
      clientId: String(clientId), sub: String(sub), state: state,
      claims: claims || held.claims || {}, lastAccess: Date.now() }));
  }
  log.debug("Leaving setState().");
}

// One of the query's knobs, while it has uses left for this exact URL.
function knob(tenant, request, name) {
  log.debug("Entering knob(). " + name);
  const asked = Number(request.query.get(name)) || 0;
  if (!asked) {
    log.debug("Leaving knob(). Not asked.");
    return 0;
  }
  const used = Number(tenant.commands.knobs.get(name + " " +
                                                request.targetUri) || 0);
  log.debug("Leaving knob().");
  return used < asked ? asked : 0;
}

function spendKnob(tenant, request, name) {
  log.debug("Entering spendKnob(). " + name);
  const key = name + " " + request.targetUri;
  tenant.commands.knobs.set(key,
                            Number(tenant.commands.knobs.get(key) || 0) + 1);
  log.debug("Leaving spendKnob().");
}

function refusal(tenant, status, error, description, seen, extra) {
  log.debug("Entering refusal(). " + error);
  tenant.record(ROLE, Object.assign({ ok: false, status: status,
                                      error: error,
                                      description: description }, seen));
  log.debug("Leaving refusal().");
  return { status: status, body: Object.assign({ error: error,
    error_description: description }, extra || {}) };
}

// The realm's OpenID configuration: its issuer and jwks_uri. Cached.
async function configurationOf(tenant) {
  log.debug("Entering configurationOf().");
  if (tenant.commands.configuration) {
    log.debug("Leaving configurationOf(). Cached.");
    return tenant.commands.configuration;
  }
  const url = tenant.realmBase + "/.well-known/openid-configuration";
  const r = await util.outbound("GET", url, { ca: tenant.serviceCaPem });
  if (r.status !== 200 || !r.json || !r.json.issuer || !r.json.jwks_uri) {
    log.debug("Leaving configurationOf(). " + r.status);
    throw new Error("the OpenID configuration at " + url + " answered " +
                    r.status);
  }
  tenant.commands.configuration = { issuer: r.json.issuer,
                                    jwksUri: r.json.jwks_uri };
  log.debug("Leaving configurationOf().");
  return tenant.commands.configuration;
}

// The command_token, from a form body (what the provider sends) or JSON.
function tokenOf(request) {
  log.debug("Entering tokenOf().");
  const type = String(request.headers["content-type"] || "");
  let token = "";
  if (/json/i.test(type)) {
    try {
      token = String((JSON.parse(request.body.toString("utf8") || "{}") ||
                      {}).command_token || "");
    } catch (e) {
      log.debug("Caught in tokenOf(): " + ((e && e.message) || e));
      // Refused by the caller as a missing token.
      token = "";
    }
  } else {
    token = String(util.formOf(request.body).command_token || "");
  }
  log.debug("Leaving tokenOf(). " + (token ? "Present." : "Absent."));
  return token;
}

// Section 6.2: the result of an `_async` command, POSTed to the provider's
// callback with the token's callback_token. A 401 is tried again a few
// times: the provider wrote the callback token in whichever of its
// processes delivered the command, and the one this request reaches may
// learn of it a moment later through its change log — which is what the
// mock's in-process `syncNow()` retry was for.
async function callBack(tenant, issuer, callbackToken, answer, command) {
  log.debug("Entering callBack(). " + command);
  const endpoint = tenant.commands.callbackEndpoint ||
                   String(issuer).replace(/\/+$/, "") + CALLBACK_PATH;
  let last = null;
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      last = await util.outbound("POST", endpoint, {
        ca: tenant.serviceCaPem,
        headers: { "Content-Type": "application/json",
                   "Authorization": "Bearer " + callbackToken },
        body: JSON.stringify(answer) });
    } catch (e) {
      log.debug("Caught in callBack(): " + ((e && e.message) || e));
      // Recorded below with the reason, after the last attempt.
      last = { status: 0, text: e.message };
    }
    if (last.status !== 401 && last.status !== 0) {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 300 * attempt);
    });
  }
  tenant.record(ROLE, { ok: last.status === 204, kind: "callback",
                        command: command, endpoint: endpoint,
                        status: last.status,
                        answer: answer,
                        why: last.status === 204 ? ""
                          : String(last.text || "").slice(0, 300) });
  log.debug("Leaving callBack(). " + last.status);
}

// A streaming tenant command (section 7.2), resumable by Last-Event-ID.
function stream(tenant, request, clientId, cmd, seen) {
  log.debug("Entering stream(). " + cmd);
  const move = TENANT_MOVES[cmd];
  const rows = [];
  tenant.commands.accounts.forEach(function (row) {
    if (row && row.clientId === clientId) {
      rows.push(row);
    }
  });
  rows.sort(function (a, b) {
    return String(a.sub).localeCompare(String(b.sub));
  });
  const after = Number(request.headers["last-event-id"] || 0) || 0;
  const drop = knob(tenant, request, "drop");
  if (drop) {
    spendKnob(tenant, request, "drop");
  }
  let text = "";
  let sent = 0;
  let n = 0;
  let dropped = false;
  for (const row of rows) {
    n++;
    if (n <= after) {
      continue;
    }
    if (move && move.from.indexOf(String(row.state)) >= 0) {
      setState(tenant, clientId, row.sub, move.to);
    }
    text += "id: " + n + "\nevent: account-state\ndata: " +
            JSON.stringify({ sub: row.sub,
                             account_state: stateOf(tenant, clientId,
                                                    row.sub) }) + "\n\n";
    sent++;
    if (drop && sent >= drop) {
      dropped = true;
      break;
    }
  }
  if (!dropped) {
    text += "id: " + (n + 1) + "\nevent: command-complete\ndata: " +
            JSON.stringify({ total_accounts: rows.length }) + "\n\n";
  }
  tenant.record(ROLE, Object.assign({ ok: true, status: 200,
                                      events: sent, dropped: dropped,
                                      lastEventId: after || null }, seen));
  log.debug("Leaving stream(). " + sent + " event(s)" +
            (dropped ? ", dropped as asked." : "."));
  return { status: 200, body: text,
           headers: { "Content-Type": "text/event-stream",
                      "Cache-Control": "no-cache" } };
}

// POST /t/{tenant}/commands — THE COMMAND ENDPOINT.
async function command(tenant, request) {
  log.debug("Entering command().");
  if (knob(tenant, request, "fail")) {
    spendKnob(tenant, request, "fail");
    tenant.record(ROLE, { ok: false, status: 503,
                          error: "temporarily_unavailable",
                          why: "a 503, as ?fail asked" });
    log.debug("Leaving command(). A 503, as asked.");
    return { status: 503, body: { error: "temporarily_unavailable" } };
  }
  const token = tokenOf(request);
  if (!token) {
    log.debug("Leaving command(). No command_token.");
    return refusal(tenant, 400, "invalid_request", "command_token is " +
                   "required (section 3).", {});
  }
  let decoded;
  try {
    decoded = jwt.decode(token);
  } catch (e) {
    log.debug("Caught in command(): " + ((e && e.message) || e));
    // Not a JWS: refused as malformed, with what was wrong.
    log.debug("Leaving command(). Not a JWS.");
    return refusal(tenant, 400, "invalid_request", "The Command Token is " +
                   "not a compact JWS: " + e.message, {});
  }
  const header = decoded.header || {};
  const c = decoded.claims || {};
  const cmd = String(c.command || "");
  const seen = { command: cmd, clientId: c.client_id || null,
                 sub: c.sub === undefined ? null : c.sub,
                 header: header, claims: c };
  // The algorithms named, never taken from the token (RFC 8725 section
  // 3.1): a relying party verifies an asymmetric signature with the
  // provider's published keys, and "none" or an HMAC is refused before any
  // key is looked at.
  if (!/^(RS|PS|ES)(256|384|512)$|^ES256K$|^EdDSA$|^Ed25519$/.test(
    String(header.alg || ""))) {
    log.debug("Leaving command(). Algorithm.");
    return refusal(tenant, 400, "invalid_request", "The Command Token's " +
                   "alg " + header.alg + " is not an asymmetric algorithm " +
                   "this relying party verifies.", seen);
  }
  const conf = await configurationOf(tenant);
  const verdict = await jwt.verify(tenant.commands.jwks, conf.jwksUri,
                                   tenant.serviceCaPem, decoded);
  seen.signatureValid = verdict.ok;
  if (!verdict.ok) {
    log.debug("Leaving command(). Signature.");
    return refusal(tenant, 400, "invalid_request", "The Command Token " +
                   "does not verify: " + verdict.why, seen);
  }
  if (c.iss !== conf.issuer) {
    log.debug("Leaving command(). An unknown issuer.");
    return refusal(tenant, 401, "unrecognized_provider", "This relying " +
                   "party does not know the issuer \"" + String(c.iss) +
                   "\" (it expected " + conf.issuer + ").", seen);
  }
  const isAccount = isAccountCommand(cmd);
  const problem =
    header.typ !== "command+jwt" ? "typ is not command+jwt" :
    !(Number(c.exp) > Math.floor(Date.now() / 1000)) ? "the token expired" :
    c.nonce !== undefined ? "a Command Token carries no nonce" :
    !c.jti ? "no jti" :
    c.aud !== c.client_id ? "aud is not client_id" :
    !c.tenant ? "no tenant" :
    isAccount && !c.sub ? "an account command names a sub" :
    !isAccount && (c.sub !== undefined || c.aud_sub !== undefined)
      ? "a tenant command names no sub or aud_sub" :
    (cmd === "metadata") !== (c.metadata !== undefined)
      ? "metadata is in the metadata command and nowhere else" :
    (cmd.replace(/_async$/, "") === "migrate") !==
      (c.authentication_provider !== undefined)
      ? "authentication_provider is in migrate and nowhere else" : null;
  if (problem) {
    log.debug("Leaving command(). " + problem);
    return refusal(tenant, 400, "invalid_request", problem + ".", seen);
  }
  // A resumed stream presents its token again, with Last-Event-ID.
  if (tenant.commands.jtis.has(String(c.jti)) &&
      !request.headers["last-event-id"]) {
    log.debug("Leaving command(). A replay.");
    return refusal(tenant, 400, "invalid_request", "jti " + c.jti +
                   " was already used.", seen);
  }
  tenant.commands.jtis.set(String(c.jti), Date.now());
  if (tenant.commands.jtis.size > MAX_JTIS) {
    tenant.commands.jtis.delete(tenant.commands.jtis.keys().next().value);
  }
  const clientId = String(c.client_id);
  const endpoint = request.targetUri.replace(/\?.*$/, "");
  if (cmd === "metadata") {
    // The provider's own metadata (section 7.1) names its callback.
    if (c.metadata && c.metadata.callback_endpoint) {
      tenant.commands.callbackEndpoint =
        String(c.metadata.callback_endpoint);
    }
    tenant.record(ROLE, Object.assign({ ok: true, status: 200 }, seen));
    log.debug("Leaving command(). Metadata.");
    return { status: 200, body: {
      context: { iss: c.iss, tenant: c.tenant },
      commands_supported: Object.keys(TABLE)
        .concat(Object.keys(TABLE).map(function (k) {
          return k + "_async";
        })).concat(["metadata"]).concat(Object.keys(TENANT_MOVES)),
      command_endpoint: endpoint,
      client_id: clientId,
      aud_sub_required: String(request.query.get("audsub") || "") === "1",
      roles: [{ id: "reader", display: "Reader" },
              { id: "editor", display: "Editor",
                description: "May change things" }]
    } };
  }
  if (Object.prototype.hasOwnProperty.call(TENANT_MOVES, cmd)) {
    log.debug("Leaving command(). A stream.");
    return stream(tenant, request, clientId, cmd, seen);
  }
  const base = cmd.replace(/_async$/, "");
  const rule = TABLE[base];
  if (!rule) {
    log.debug("Leaving command(). Unsupported.");
    return refusal(tenant, 400, "unsupported_command", "\"" + cmd +
                   "\" is not a command this relying party supports.", seen);
  }
  const sub = String(c.sub);
  const before = stateOf(tenant, clientId, sub);
  if (rule.from && rule.from.indexOf(before) < 0) {
    log.debug("Leaving command(). Incompatible.");
    return refusal(tenant, 409, "incompatible_state", "The account is " +
                   before + "; " + base + " needs " +
                   rule.from.join(" or ") + ".", seen,
                   { sub: sub, account_state: before });
  }
  if (rule.to) {
    const claims = {};
    ACCOUNT_CLAIMS.forEach(function (k) {
      if (c[k] !== undefined) {
        claims[k] = c[k];
      }
    });
    setState(tenant, clientId, sub, rule.to, claims);
  }
  const after = stateOf(tenant, clientId, sub);
  const answer = { sub: sub, account_state: after };
  if (after !== "unknown") {
    answer.aud_sub = audSubOf(clientId, sub);
  }
  if (/_async$/.test(cmd)) {
    // Section 6.2: 202 now, the result through the callback after — once
    // this answer is on its way, as a relying party doing the work later
    // would.
    const callbackToken = String(c.callback_token || "");
    tenant.record(ROLE, Object.assign({ ok: true, status: 202,
                                        accountState: after }, seen));
    setTimeout(function () {
      callBack(tenant, c.iss, callbackToken, answer, cmd)
        .catch(function (e) {
          log.debug("Caught in command(): " + ((e && e.message) || e));
          tenant.record(ROLE, { ok: false, kind: "callback", command: cmd,
                                error: e.message });
        });
    }, 50);
    log.debug("Leaving command(). 202.");
    return { status: 202, body: null };
  }
  tenant.record(ROLE, Object.assign({ ok: true, status: 200,
                                      accountState: after }, seen));
  log.debug("Leaving command(). " + after);
  return { status: 200, body: answer };
}

// GET /t/{tenant}/commands?client_id=… — the accounts held for a client.
function accounts(tenant, query) {
  log.debug("Entering accounts().");
  const clientId = String(query.get("client_id") || "");
  const out = [];
  tenant.commands.accounts.forEach(function (row) {
    if (row && row.clientId === clientId) {
      out.push({ sub: row.sub, state: row.state, claims: row.claims });
    }
  });
  log.debug("Leaving accounts(). " + out.length);
  return { status: 200, body: { accounts: out } };
}

module.exports = { configure: configure, command: command,
                   accounts: accounts, audSubOf: audSubOf,
                   TABLE: TABLE, TENANT_MOVES: TENANT_MOVES };
