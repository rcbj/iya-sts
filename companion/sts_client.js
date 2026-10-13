// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: companion/sts_client.js
//
// ===========================================================================
// THE COMPANION'S ONE DOOR INTO THE SERVICE (#594): what it asks iya-sts,
// and as whom.
//
// **AS AN OUTSIDE PARTY, AND NOTHING ELSE.** The companion requires no
// module of the service. It reads what any party may read — the Credential
// Issuer's metadata — and does everything else through `/admin-api`, as an
// application holding an access token like any other client of that API:
// `client_credentials` at `/oauth2/token`, `admin:read admin:write`, the
// API's base as the RFC 8707 `resource`, the client authenticated with its
// own secret (`client_secret_basic`). What it calls:
//
//   GET  /.well-known/openid-credential-issuer   what the issuer offers
//   GET  /admin-api/verifier-request              what the Verifier asks for
//   POST /admin-api/verifications/start           a presentation request,
//                                                 naming the companion's
//                                                 completion page (#594)
//   GET  /admin-api/verifications?state=          what the Verifier decided
//
// **ITS OWN CLIENT.** `COMPANION_CLIENT_ID` and `COMPANION_CLIENT_SECRET`
// name an application an operator registered: it declares the two scopes,
// is a member of ADMIN_READ and ADMIN_WRITE (`mgmt-api/CLAUDE.md`: an
// application holds them by being a member), and lists the companion's
// completion page as a redirect URI, which is what lets a product realm
// accept it as the address a wallet is sent to. **Or the companion registers
// itself**: given the seeded `sts-management-api` client's secret
// (`COMPANION_BOOTSTRAP_SECRET`, the `adminApi.clientSecret` a stack pins),
// it creates that application once — or, after a restart, mints itself a
// new secret on it — and from then on uses only its own. The bootstrap
// secret is used for those three calls and for nothing else.
//
// **WHERE IT DIALS AND WHAT IT CALLS ITSELF.** `COMPANION_STS_URL` is where
// the service is reached from the companion (`https://sts:8081` on the
// compose network); `COMPANION_STS_PUBLIC_URL` is where a person's browser
// and wallet reach it (`https://localhost:8081`), a realm's prefix included.
// Every request is dialled at the first and carries the second's host as
// its `Host`, so the addresses the service builds from the request — the
// Response URI, the request URI, the API's audience — are the ones a wallet
// can reach. The two are the same where nothing translates between them.
//
// **TLS.** Verified against `COMPANION_STS_CA_FILE` when it is set. A
// development stack makes its service Root when it starts, so there is no
// anchor an image could hold: `COMPANION_STS_TLS_INSECURE=true` turns the
// check off, as `PEP_TLS_INSECURE` does for the remote PEP, and the start
// says so in the log.
// ===========================================================================

const fs = require("fs");
const http = require("http");
const https = require("https");
const nodeCrypto = require("crypto");
const util = require("./companion_util.js");

const log = util.logger("sts_client");

const CLIENT_ID_DEFAULT = "iya-sts-companion";
const SCOPE = "admin:read admin:write";

/**
 * A client of one realm of the service.
 */
class StsClient {
  /**
   * @param {object} opts - `stsUrl`, `stsPublicUrl`, `caFile`, `insecure`,
   *   `clientId`, `clientSecret`, `bootstrapSecret`, `redirectUris`
   */
  constructor(opts) {
    log.debug("Entering StsClient.constructor().");
    const o = opts || {};
    this.publicBase = String(o.stsPublicUrl || o.stsUrl || "")
      .replace(/\/+$/, "");
    const dial = new URL(String(o.stsUrl || this.publicBase));
    const shown = new URL(this.publicBase);
    this.dial = { protocol: dial.protocol, hostname: dial.hostname,
                  port: dial.port ||
                        (dial.protocol === "https:" ? "443" : "80") };
    this.hostHeader = shown.host;
    this.prefix = shown.pathname.replace(/\/+$/, "");
    this.ca = o.caFile ? fs.readFileSync(String(o.caFile), "utf8") : null;
    this.insecure = !this.ca && !!o.insecure;
    this.clientId = String(o.clientId || CLIENT_ID_DEFAULT);
    this.clientSecret = String(o.clientSecret || "");
    this.bootstrapSecret = String(o.bootstrapSecret || "");
    this.redirectUris = (o.redirectUris || []).map(String);
    this.cached = null;
    this.registering = null;
    if (this.insecure) {
      log.warn("companion: the service's TLS certificate is NOT verified " +
               "(COMPANION_STS_TLS_INSECURE). Development only: set " +
               "COMPANION_STS_CA_FILE to the service Root to verify it.");
    }
    log.debug("Leaving StsClient.constructor().");
  }

  /**
   * The service's API base as a person and a wallet reach it.
   *
   * @returns {string} the base, the realm's prefix included
   */
  apiBase() {
    log.debug("Entering StsClient.apiBase().");
    log.debug("Leaving StsClient.apiBase().");
    return this.publicBase + "/admin-api";
  }

  /**
   * One request to the service.
   *
   * @param {string} method - the method
   * @param {string} path - under the realm, starting with /
   * @param {object} [opts] - `form` (object), `json`, `token`, `basic`
   *   (`[id, secret]`)
   * @returns {Promise<object>} `{ status, json, text }`
   */
  request(method, path, opts) {
    log.debug("Entering StsClient.request(). " + method + " " +
              String(path).replace(/\?.*$/, ""));
    const self = this;
    const o = opts || {};
    const headers = { Host: this.hostHeader, Accept: "application/json" };
    let body = null;
    if (o.form) {
      body = new URLSearchParams(o.form).toString();
      headers["Content-Type"] = "application/x-www-form-urlencoded";
    } else if (o.json !== undefined) {
      body = JSON.stringify(o.json);
      headers["Content-Type"] = "application/json";
    }
    if (body !== null) {
      headers["Content-Length"] = Buffer.byteLength(body);
    }
    if (o.token) {
      headers.Authorization = "Bearer " + o.token;
    } else if (o.basic) {
      headers.Authorization = "Basic " + Buffer.from(
        encodeURIComponent(o.basic[0]) + ":" +
        encodeURIComponent(o.basic[1])).toString("base64");
    }
    const tls = this.dial.protocol === "https:";
    const options = {
      method: method, hostname: this.dial.hostname, port: this.dial.port,
      path: this.prefix + path, headers: headers, timeout: 15000
    };
    if (tls) {
      options.servername = this.dial.hostname;
      if (this.ca) {
        options.ca = this.ca;
      }
      options.rejectUnauthorized = !self.insecure;
    }
    log.debug("Leaving StsClient.request().");
    return new Promise(function (resolve, reject) {
      const req = (tls ? https : http).request(options, function (res) {
        const chunks = [];
        res.on("data", function (c) {
          chunks.push(c);
        });
        res.on("end", function () {
          const text = Buffer.concat(chunks).toString("utf8");
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            log.debug("Caught in StsClient.request(): " +
                      ((e && e.message) || e));
            // Not JSON: the text is what the caller reads.
            json = null;
          }
          resolve({ status: res.statusCode, json: json, text: text });
        });
      });
      req.on("timeout", function () {
        req.destroy(new Error("the service did not answer in 15 s"));
      });
      req.on("error", reject);
      if (body !== null) {
        req.write(body);
      }
      req.end();
    });
  }

  /**
   * A token for `/admin-api` for a client.
   *
   * @param {string} id - the client's id
   * @param {string} secret - its secret
   * @returns {Promise<object>} the token response
   */
  async mint(id, secret) {
    log.debug("Entering StsClient.mint(). " + id);
    const r = await this.request("POST", "/oauth2/token", {
      basic: [id, secret],
      form: { grant_type: "client_credentials", scope: SCOPE,
              resource: this.apiBase() } });
    if (r.status !== 200 || !r.json || !r.json.access_token) {
      log.debug("Leaving StsClient.mint(). Refused.");
      throw new Error("the token endpoint refused " + id + ": HTTP " +
                      r.status + " " + r.text.slice(0, 300));
    }
    log.debug("Leaving StsClient.mint().");
    return r.json;
  }

  /**
   * Registers the companion as an application of the realm, once, through
   * the seeded management client — or does nothing when the companion was
   * given credentials of its own.
   *
   * @returns {Promise<void>}
   */
  async ensureRegistered() {
    log.debug("Entering StsClient.ensureRegistered().");
    if (this.clientSecret) {
      log.debug("Leaving StsClient.ensureRegistered(). Configured.");
      return;
    }
    if (!this.bootstrapSecret) {
      log.debug("Leaving StsClient.ensureRegistered(). No way in.");
      throw new Error("the companion has no client of its own: set " +
                      "COMPANION_CLIENT_ID and COMPANION_CLIENT_SECRET, or " +
                      "COMPANION_BOOTSTRAP_SECRET (the sts-management-api " +
                      "client's secret) for it to register itself.");
    }
    const admin = (await this.mint("sts-management-api",
                                   this.bootstrapSecret)).access_token;
    const api = async (path, body) => {
      log.debug("Entering api(). " + path);
      const r = await this.request("POST", "/admin-api" + path,
                                   { token: admin, json: body });
      log.debug("Leaving api(). " + r.status);
      return r;
    };
    const secret = nodeCrypto.randomBytes(24).toString("base64url");
    const made = await api("/applications/create", {
      identifier: this.clientId, kind: "oauth2-client",
      name: "iya-sts development companion", protocols: ["oauth2"],
      fields: { oauthClientId: [this.clientId],
                oauthAllowedScope: SCOPE.split(" "),
                oauthClientSecret: secret,
                oauthTokenEndpointAuthMethod: "client_secret_basic",
                oauthRedirectUri: this.redirectUris } });
    let held = secret;
    if (made.status !== 200) {
      // Registered before (a restart): a new secret on the entry, which is
      // the one thing the companion did not keep.
      log.info("companion: " + this.clientId + " is registered already " +
               "(" + made.status + "); minting it a new secret.");
      const fresh = await api("/applications/regenerate-secret",
                              { application: this.clientId });
      if (fresh.status !== 200 || !fresh.json || !fresh.json.clientSecret) {
        log.debug("Leaving StsClient.ensureRegistered(). Refused.");
        throw new Error("could not register the companion: create answered " +
                        made.status + " " + made.text.slice(0, 200) +
                        " and regenerate-secret " + fresh.status + " " +
                        fresh.text.slice(0, 200));
      }
      held = String(fresh.json.clientSecret);
      for (const uri of this.redirectUris) {
        // Already listed is refused or a no-op; either is the state wanted.
        await api("/applications/add", { application: this.clientId,
                                         attribute: "oauthRedirectUri",
                                         value: uri });
      }
    }
    for (const role of ["ADMIN_READ", "ADMIN_WRITE"]) {
      // Already a member is the state wanted, whatever is answered.
      await api("/roles/add-member", { role: role, kind: "application",
                                       member: this.clientId });
    }
    this.clientSecret = held;
    log.info("companion: registered as " + this.clientId + " in " +
             this.publicBase);
    log.debug("Leaving StsClient.ensureRegistered().");
  }

  /**
   * The companion's own token, minted when the last is near its end.
   *
   * @returns {Promise<string>} the access token
   */
  async token() {
    log.debug("Entering StsClient.token().");
    if (this.cached && this.cached.until > Date.now()) {
      log.debug("Leaving StsClient.token(). Cached.");
      return this.cached.token;
    }
    if (!this.registering) {
      this.registering = this.ensureRegistered().catch((e) => {
        log.debug("Caught in StsClient.token(): " + ((e && e.message) || e));
        // Asked again on the next request, rather than failed for good.
        this.registering = null;
        throw e;
      });
    }
    await this.registering;
    const minted = await this.mint(this.clientId, this.clientSecret);
    const life = Math.max(30, Number(minted.expires_in) || 300);
    this.cached = { token: minted.access_token,
                    until: Date.now() + (life - 20) * 1000 };
    log.debug("Leaving StsClient.token().");
    return this.cached.token;
  }

  /**
   * One `/admin-api` call as the companion, once more with a new token if
   * the first was refused as no longer valid.
   *
   * @param {string} method - the method
   * @param {string} path - under /admin-api
   * @param {*} [json] - the body
   * @returns {Promise<object>} `{ status, json, text }`
   */
  async adminApi(method, path, json) {
    log.debug("Entering StsClient.adminApi(). " + method + " " +
              String(path).replace(/\?.*$/, ""));
    let r = await this.request(method, "/admin-api" + path,
                               { token: await this.token(), json: json });
    if (r.status === 401) {
      this.cached = null;
      r = await this.request(method, "/admin-api" + path,
                             { token: await this.token(), json: json });
    }
    log.debug("Leaving StsClient.adminApi(). " + r.status);
    return r;
  }

  /**
   * The Credential Issuer's metadata (OpenID4VCI section 12.2), which
   * anybody may read.
   *
   * @returns {Promise<object>} the metadata
   */
  async issuerMetadata() {
    log.debug("Entering StsClient.issuerMetadata().");
    const r = await this.request("GET",
                                 "/.well-known/openid-credential-issuer");
    if (r.status !== 200 || !r.json) {
      log.debug("Leaving StsClient.issuerMetadata(). " + r.status);
      throw new Error("the issuer's metadata answered HTTP " + r.status);
    }
    log.debug("Leaving StsClient.issuerMetadata().");
    return r.json;
  }
}

module.exports = { StsClient: StsClient, CLIENT_ID_DEFAULT: CLIENT_ID_DEFAULT,
                   SCOPE: SCOPE };
