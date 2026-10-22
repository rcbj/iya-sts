// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// setup.js — prepare 8081 for the one-million-session test. Run it once; it
// is safe to run again (it changes only what is not yet as it wants).
//
// It records every setting it changes in setup.state.json, the FIRST time,
// so teardown.js can put each back exactly: a setting that was an override is
// set back to that value, one that was not is reset (an override left at the
// default value still reads "source: override").
//
// What it changes, and why (README.md has the arithmetic):
//   authn.maxSessions          1,100,000   1M sessions, plus room for the rest
//   authn.sessionLifetimeS     2,592,000   30 days, the maximum
//   risk.listsMatchSpecialPurpose  false   the bridge address is RFC 1918
//   risk.rescoreEveryS            86400    the rescore walks every session
//   risk.networkFailureThreshold 1,000,000 (the maximum) every caller is the
//                                          docker gateway, one network; 20
//                                          refused passwords blocked every
//                                          sign-in after a restart (10-21)
//   oauth2.maxRefreshTokenFamilies 1,000,000  (the maximum) one per person
//   oauth2.maxRevokedJtis      10,000,000   rotation revokes one per refresh
//
// And it creates the application sessions-1m-rp: OIDC, authorization code
// with PKCE and refresh, client_secret_basic, offline_access consented
// globally, tokens that live 12 h (access, ID) and 2 days (refresh; each
// refresh issues a new one, so 2 days is plenty and keeps the revocations
// rotation leaves behind under the 10M cap — README.md).
"use strict";

const fs = require("fs");
const path = require("path");
const c = require("./common");

const STATE = path.join(c.HERE, "setup.state.json");
const MAX_SESSIONS = Number(process.env.MAX_SESSIONS || 1100000);
const ACCESS_TTL = Number(process.env.ACCESS_TTL_S || 43200);
const REFRESH_TTL = Number(process.env.REFRESH_TTL_S || 172800);

const SETTINGS = {
  "authn.maxSessions": String(MAX_SESSIONS),
  "authn.sessionLifetimeS": "2592000",
  "risk.listsMatchSpecialPurpose": "false",
  "risk.rescoreEveryS": "86400",
  "risk.networkFailureThreshold": "1000000",
  "oauth2.maxRefreshTokenFamilies": "1000000",
  "oauth2.maxRevokedJtis": "10000000"
};

async function settle() {
  const state = c.readJson(STATE, { prior: {}, app: null });
  const rows = await c.readSettings();
  for (const [key, want] of Object.entries(SETTINGS)) {
    const row = rows[key];
    if (!row) throw new Error("the service has no setting " + key);
    if (!(key in state.prior)) {
      state.prior[key] = { value: row.value, source: row.source };
      c.writeJson(STATE, state);
    }
    if (String(row.value) === want) {
      c.log("  " + key + " is already " + want);
      continue;
    }
    await c.setSetting(key, want);
    c.log("  " + key + ": " + row.value + " -> " + want);
  }
  return state;
}

// A client secret as the service mints one: 48 random bytes, base64url
// (oauth2.registeredSecretBytes). Made here because /admin-api's
// generate-secret is the console's door and is not on this image.
function newSecret() {
  return require("crypto").randomBytes(48).toString("base64url");
}

async function application(state) {
  const got = await c.api("GET", "/applications?application=" +
                          encodeURIComponent(c.cfg.APP_ID));
  const exists = got.status === 200 && got.json &&
    (got.json.found === true || got.json.application ||
     (got.json.fields && Object.keys(got.json.fields).length));
  if (exists && fs.existsSync(c.cfg.CLIENT_SECRET_FILE)) {
    c.log("  application " + c.cfg.APP_ID + " exists; keeping it");
    return;
  }
  if (exists) {
    // There without its secret here: issue a new one and keep it.
    const secret = newSecret();
    const set = await c.api("POST", "/applications/set", {
      identifier: c.cfg.APP_ID, attribute: "oauthClientSecret",
      value: secret });
    if (set.status !== 200) {
      throw new Error("setting the secret answered " + set.status + " " +
                      set.text.slice(0, 300));
    }
    c.writeSecret(c.cfg.CLIENT_SECRET_FILE, secret);
    c.log("  application " + c.cfg.APP_ID + " existed; gave it a new secret");
    return;
  }
  const secret = newSecret();
  const body = {
    identifier: c.cfg.APP_ID,
    name: "One million sessions (load test)",
    protocols: ["oauth2", "oidc"],
    lifetimeDays: 0,
    fields: {
      oauthClientId: [c.cfg.APP_ID],
      oauthClientSecret: secret,
      oauthRedirectUri: [c.cfg.REDIRECT_URI],
      oauthGrantType: ["authorization_code", "refresh_token"],
      oauthResponseType: ["code"],
      oauthTokenEndpointAuthMethod: ["client_secret_basic"],
      oauthAllowedScope: ["openid", "profile", "offline_access"],
      oauthGlobalConsent: ["openid", "profile", "offline_access"],
      oauthAccessTokenTtlS: String(ACCESS_TTL),
      oauthIdTokenTtlS: String(ACCESS_TTL),
      oauthRefreshTokenTtlS: String(REFRESH_TTL),
      oauthRefreshIdleSeconds: String(REFRESH_TTL)
    }
  };
  const r = await c.api("POST", "/applications/create", body);
  if (r.status !== 200) {
    throw new Error("creating " + c.cfg.APP_ID + " answered " + r.status +
                    " " + r.text.slice(0, 500));
  }
  c.writeSecret(c.cfg.CLIENT_SECRET_FILE, secret);
  state.app = { identifier: c.cfg.APP_ID, createdAt: new Date().toISOString() };
  c.writeJson(STATE, state);
  c.log("  created application " + c.cfg.APP_ID + " (secret in " +
        path.basename(c.cfg.CLIENT_SECRET_FILE) + ")");
}

async function main() {
  c.log("setup against " + c.cfg.STS_URL);
  const state = await settle();
  await application(state);
  c.peoplePassword();   // made once, kept in people.secret
  c.log("setup done");
}

main().catch((e) => {
  c.log("setup FAILED: " + (e && e.stack || e));
  process.exit(1);
});
