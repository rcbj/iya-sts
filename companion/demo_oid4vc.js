// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: companion/demo_oid4vc.js
//
// ===========================================================================
// THE OPENID4VC DEMONSTRATION: AN ISSUER'S PAGE AND A VERIFIER'S BAR DOOR,
// IN FRONT OF THE SERVICE (#594, moved out of the service from `oid4vc/`).
//
// Until #594 these were the service's own `/issuer`, `/issuer/offer`,
// `/oid4vp/verifier`, `/oid4vp/start` and `/oid4vp/done`, with
// `/vc-demo-api` behind them. They are pages of the companion now, and they
// reach the service the way a real issuer's web site and a real verifier's
// web site would:
//
//   GET  /issuer           what the issuer offers, read from its metadata;
//                          two ways to put it in a wallet
//   GET  /issuer/offer     a Credential Offer for THIS device: the
//                          authorization_code grant and no issuer_state
//                          (OpenID4VCI 1.0 section 4.1.1 makes it optional),
//                          so the wallet takes the person through the
//                          service's /oauth2/authorize — and a QR code of
//                          the same offer for a wallet on another device
//   GET  /verifier         the bar door: what it asks for, in which format
//   POST /verifier/start   POST /admin-api/verifications/start, then the
//                          wallet (this device) or the QR page (another)
//   GET  /verifier/wait    the QR page, refreshed until the wallet answers
//   GET  /verifier/done    where the wallet sends the browser afterwards
//                          (the `redirect_uri` the Response Endpoint
//                          answers, which the start named), and the verdict
//
// **WHY THE PRE-AUTHORIZED OFFER IS A LINK TO THE PORTAL.** A pre-authorized
// code IS the authorization for a credential about the person it names, so
// only somebody who knows who that person is may make one. rcbj's decision
// on #587 is that this is the person's own self-service: `/portal/wallet`
// (#589) makes it, over `/account-api`, for whoever signed in. The companion
// is not that person and holds no token of theirs, so it sends them there.
// What it can make on its own is the offer that authorizes nothing — the
// same-device one, which only says "this issuer, this credential" and
// leaves the authorization to the service's authorization endpoint.
//
// **WHY THE COMPLETION PAGE IS THE COMPANION'S.** OpenID4VP 1.0 section 8.2
// lets the Response Endpoint answer a `redirect_uri` the wallet then sends
// the browser to. The service used to name its own `/oid4vp/done`, a demo
// page a product realm did not serve. Since #594 the STARTER names it: the
// verification start takes `redirect_uri`, which a realm that accepts only
// registered addresses holds to the calling client's registered redirect
// URIs, and a verification started without one is answered with no
// `redirect_uri` at all. The companion names `/verifier/done` for a
// same-device start and nothing for another device, where no browser is
// waiting for the wallet to come back.
//
// **THE VERIFICATION IS BOUND TO THE BROWSER THAT STARTED IT.** The verdict
// is read through `/admin-api` by `state`, which the browser never sees: the
// companion keeps it in the browser's session, so a link to the completion
// page opened elsewhere shows nothing (the session fixation OpenID4VP
// section 13.3 warns of).
// ===========================================================================

const QRCode = require("qrcode");
const util = require("./companion_util.js");

const log = util.logger("demo_oid4vc");
const esc = util.esc;

// The verifications a session keeps, newest last.
const KEPT = 5;

/**
 * An SVG QR code of a URI, drawn here.
 *
 * @param {string} text - what it encodes
 * @returns {Promise<string>} the SVG markup
 */
async function qrSvg(text) {
  log.debug("Entering qrSvg().");
  const svg = await QRCode.toString(String(text), { type: "svg", margin: 2,
                                                    errorCorrectionLevel: "M" });
  log.debug("Leaving qrSvg().");
  return svg;
}

/**
 * The display name of a credential configuration, from its metadata.
 *
 * @param {string} id - the configuration's id
 * @param {object} entry - its entry in credential_configurations_supported
 * @returns {string} the name
 */
function displayName(id, entry) {
  log.debug("Entering displayName(). " + id);
  const meta = (entry && entry.credential_metadata) || entry || {};
  const shown = Array.isArray(meta.display) && meta.display.length
    ? meta.display[0].name : "";
  log.debug("Leaving displayName().");
  return String(shown || id);
}

/**
 * The OpenID4VC demonstration, mounted on the companion.
 */
class Oid4vcDemo {
  /**
   * @param {object} deps - `sts` (an StsClient), `sessions`, `publicUrl`
   *   (the companion's own base), `walletUrl` (the wallet's address, or '')
   */
  constructor(deps) {
    log.debug("Entering Oid4vcDemo.constructor().");
    this.sts = deps.sts;
    this.sessions = deps.sessions;
    this.publicUrl = String(deps.publicUrl || "").replace(/\/+$/, "");
    this.walletUrl = String(deps.walletUrl || "").replace(/\/+$/, "");
    log.debug("Leaving Oid4vcDemo.constructor().");
  }

  /**
   * The demonstration's entry on the start page.
   *
   * @returns {object} `{ id, title, links }`
   */
  describe() {
    log.debug("Entering Oid4vcDemo.describe().");
    log.debug("Leaving Oid4vcDemo.describe().");
    return { id: "oid4vc", title: "OpenID for Verifiable Credentials",
             links: [{ href: "/issuer", text: "Mock University — get a " +
                       "digital diploma (OpenID4VCI)" },
                     { href: "/verifier", text: "The Bar Door — present a " +
                       "credential (OpenID4VP)" }] };
  }

  /**
   * The completion page a same-device verification names.
   *
   * @returns {string} its absolute URL
   */
  completionUrl() {
    log.debug("Entering Oid4vcDemo.completionUrl().");
    log.debug("Leaving Oid4vcDemo.completionUrl().");
    return this.publicUrl + "/verifier/done";
  }

  /**
   * Adds the demonstration's routes.
   *
   * @param {object} router - `get(path, handler)`, `post(path, handler)`
   */
  mount(router) {
    log.debug("Entering Oid4vcDemo.mount().");
    router.get("/issuer", (req, res, ctx) => this.issuerPage(res, ctx));
    router.get("/issuer/offer", (req, res, ctx) => this.offerPage(res, ctx));
    router.get("/verifier", (req, res, ctx) => this.verifierPage(res, ctx));
    router.post("/verifier/start", (req, res, ctx) => this.start(res, ctx));
    router.get("/verifier/wait", (req, res, ctx) => this.outcome(res, ctx,
                                                                 true));
    router.get("/verifier/done", (req, res, ctx) => this.outcome(res, ctx,
                                                                 false));
    log.debug("Leaving Oid4vcDemo.mount().");
  }

  /**
   * `GET /issuer`.
   *
   * @param {object} res - the response
   * @param {object} ctx - the request's context
   */
  async issuerPage(res, ctx) {
    log.debug("Entering Oid4vcDemo.issuerPage().");
    const meta = await this.sts.issuerMetadata();
    const supported = meta.credential_configurations_supported || {};
    const rows = Object.keys(supported).map((id) => {
      log.debug("Entering issuerPage row. " + id);
      log.debug("Leaving issuerPage row.");
      return "<tr><td>" + esc(displayName(id, supported[id])) +
        "<br><code>" + esc(id) + "</code> · " +
        esc(supported[id].format || "") + "</td><td><a class=\"button\" " +
        "href=\"/issuer/offer?configuration=" + encodeURIComponent(id) +
        "\">Offer it</a></td></tr>";
    }).join("");
    const portal = this.sts.publicBase + "/portal/wallet";
    util.sendHtml(res, 200, util.page("Mock University — digital diploma",
      "<div class=\"card\"><h1>Mock University</h1><p class=\"sub\">Your " +
      "diploma, as a verifiable credential, from <code>" +
      esc(meta.credential_issuer || this.sts.publicBase) + "</code>.</p>" +
      "<h2>Into a wallet, through the sign-in</h2><p>An offer that " +
      "authorizes nothing: your wallet takes you through the issuer's " +
      "sign-in, and the credential is about whoever signs in.</p>" +
      "<table>" + rows + "</table>" +
      "<h2>Already signed in? Pre-authorized, or deferred</h2><p>A " +
      "pre-authorized offer is a credential about you that needs no further " +
      "sign-in, so only you can ask for one: <a href=\"" + esc(portal) +
      "\">your account's wallet page</a> makes it, with its transaction " +
      "code, for another device or for later.</p>" +
      "<p><a href=\"/\">Back to the start</a></p></div>"));
    log.debug("Leaving Oid4vcDemo.issuerPage(). " +
              Object.keys(supported).length + " configuration(s).");
  }

  /**
   * `GET /issuer/offer?configuration=`.
   *
   * @param {object} res - the response
   * @param {object} ctx - the request's context
   */
  async offerPage(res, ctx) {
    log.debug("Entering Oid4vcDemo.offerPage().");
    const meta = await this.sts.issuerMetadata();
    const supported = meta.credential_configurations_supported || {};
    const id = String(ctx.query.get("configuration") || "");
    if (!Object.prototype.hasOwnProperty.call(supported, id)) {
      util.sendError(res, 400, "No such credential",
                     "The issuer offers no credential configuration \"" + id +
                     "\". Choose one on the issuer's page.");
      log.debug("Leaving Oid4vcDemo.offerPage(). Unknown configuration.");
      return;
    }
    const offer = { credential_issuer: meta.credential_issuer,
                    credential_configuration_ids: [id],
                    grants: { authorization_code: {} } };
    const query = "credential_offer=" +
                  encodeURIComponent(JSON.stringify(offer));
    const offerUri = "openid-credential-offer://?" + query;
    const walletLink = this.walletUrl ? this.walletUrl + "?" + query : "";
    util.sendHtml(res, 200, util.page("Mock University — your diploma",
      "<div class=\"card\"><h1>" + esc(displayName(id, supported[id])) +
      "</h1><p class=\"sub\">A Credential Offer (OpenID4VCI section 4.1) " +
      "with the authorization code grant: your wallet signs you in at the " +
      "issuer before the credential is issued.</p>" +
      (walletLink ? "<p><a class=\"button\" id=\"wallet-link\" href=\"" +
                    esc(walletLink) + "\">Open in your wallet</a></p>" : "") +
      "<p><a class=\"button\" id=\"offer-link\" href=\"" + esc(offerUri) +
      "\">Open with a wallet app on this device</a></p>" +
      "<h2>Or scan it with a wallet on another device</h2><div class=\"qr\"" +
      " id=\"offer-qr\">" + await qrSvg(offerUri) + "</div>" +
      "<p class=\"mono\" id=\"offer-uri\">" + esc(offerUri) + "</p>" +
      "<p><a href=\"/issuer\">Back to the issuer</a></p></div>"));
    log.debug("Leaving Oid4vcDemo.offerPage().");
  }

  /**
   * `GET /verifier`: what the Verifier asks for, and the start form.
   *
   * @param {object} res - the response
   * @param {object} ctx - the request's context
   */
  async verifierPage(res, ctx) {
    log.debug("Entering Oid4vcDemo.verifierPage().");
    const r = await this.sts.adminApi("GET", "/verifier-request");
    if (r.status !== 200 || !r.json) {
      util.sendError(res, 502, "The Verifier is not answering",
                     "GET /admin-api/verifier-request answered HTTP " +
                     r.status + ".");
      log.debug("Leaving Oid4vcDemo.verifierPage(). " + r.status);
      return;
    }
    const view = r.json;
    const formats = (view.formats || []).map(function (one) {
      log.debug("Entering verifierPage format. " + one.id);
      log.debug("Leaving verifierPage format.");
      return "<option value=\"" + esc(one.id) + "\"" +
        (one.id === view.format ? " selected" : "") + ">" +
        esc(one.label || one.id) + "</option>";
    }).join("");
    const claims = (view.requested || []).map(function (one) {
      log.debug("Entering verifierPage claim.");
      log.debug("Leaving verifierPage claim.");
      return "<li><code>" + esc(one) + "</code></li>";
    }).join("");
    util.sendHtml(res, 200, util.page("The Bar Door — are you over 21?",
      "<div class=\"card\"><h1>The Bar Door</h1><p class=\"sub\">Show a " +
      "credential to come in. This door asks the service's OpenID4VP " +
      "Verifier for:</p><ul>" + (claims || "<li>the whole credential</li>") +
      "</ul><form method=\"post\" action=\"/verifier/start\">" +
      "<input type=\"hidden\" name=\"csrf\" value=\"" + esc(ctx.session.csrf) +
      "\"><label for=\"format\">The credential's format</label>" +
      "<select id=\"format\" name=\"format\">" + formats + "</select>" +
      "<label for=\"by\">The request</label><select id=\"by\" name=\"by\">" +
      "<option value=\"value\">by value</option><option value=\"reference\"" +
      ">by reference, signed</option></select>" +
      "<label for=\"mode\">Your wallet is</label><select id=\"mode\" " +
      "name=\"mode\"><option value=\"same-device\">on this device</option>" +
      "<option value=\"cross-device\">on another device</option></select>" +
      "<p><button type=\"submit\" id=\"start\">Present a credential" +
      "</button></p></form><p><a href=\"/\">Back to the start</a></p></div>"));
    log.debug("Leaving Oid4vcDemo.verifierPage().");
  }

  /**
   * `POST /verifier/start`.
   *
   * @param {object} res - the response
   * @param {object} ctx - the request's context, its form read
   */
  async start(res, ctx) {
    log.debug("Entering Oid4vcDemo.start().");
    const form = ctx.form || {};
    const mode = form.mode === "cross-device" ? "cross-device"
                                              : "same-device";
    const asked = { mode: mode,
                    by: form.by === "reference" ? "reference" : "value" };
    if (form.format) {
      asked.format = String(form.format);
    }
    // Same device: the wallet comes back to this browser, here. Another
    // device: nobody waits there, so no address is named and the Response
    // Endpoint answers none.
    if (mode === "same-device") {
      asked.redirect_uri = this.completionUrl();
    }
    const r = await this.sts.adminApi("POST", "/verifications/start", asked);
    if (r.status !== 200 || !r.json || !r.json.ok) {
      util.sendError(res, r.status >= 400 && r.status < 500 ? 400 : 502,
                     "The verification did not start",
                     ((r.json && r.json.errors) || [r.text.slice(0, 300)])
                       .join(" "));
      log.debug("Leaving Oid4vcDemo.start(). " + r.status);
      return;
    }
    const started = { state: String(r.json.state), mode: mode,
                      requestUri: String(r.json.requestUri || ""),
                      walletUrl: String(r.json.walletUrl || ""),
                      wallet: String(r.json.wallet || ""),
                      at: Date.now() };
    const kept = ctx.session.verifications;
    kept.push(started);
    while (kept.length > KEPT) {
      kept.shift();
    }
    if (mode === "same-device" && started.wallet) {
      log.debug("Leaving Oid4vcDemo.start(). To the wallet.");
      util.redirect(res, started.walletUrl);
      return;
    }
    log.debug("Leaving Oid4vcDemo.start(). The QR page.");
    util.redirect(res, "/verifier/wait");
  }

  /**
   * `GET /verifier/wait` and `GET /verifier/done`: what was decided for
   * this browser's latest verification, or — while the wallet has not
   * answered — the request to scan, refreshed.
   *
   * @param {object} res - the response
   * @param {object} ctx - the request's context
   * @param {boolean} waiting - the QR page, rather than the completion page
   */
  async outcome(res, ctx, waiting) {
    log.debug("Entering Oid4vcDemo.outcome(). waiting=" + waiting);
    const kept = ctx.session.verifications;
    const latest = kept.length ? kept[kept.length - 1] : null;
    if (!latest) {
      util.sendHtml(res, 200, util.page("The Bar Door",
        "<div class=\"card\"><h1>The Bar Door</h1><p class=\"sub\" " +
        "id=\"nothing\">This browser has not started a presentation here, " +
        "so there is nothing to show. A presentation started in another " +
        "browser is shown only there.</p><p><a href=\"/verifier\">Present " +
        "a credential</a></p></div>"));
      log.debug("Leaving Oid4vcDemo.outcome(). Nothing started.");
      return;
    }
    const r = await this.sts.adminApi("GET", "/verifications?state=" +
                                      encodeURIComponent(latest.state));
    const found = r.status === 200 && r.json ? r.json : null;
    if (!found) {
      util.sendError(res, r.status === 404 ? 404 : 502, "The Bar Door",
                     r.status === 404
                       ? "The Verifier no longer holds this presentation: " +
                         "it expired. Start another."
                       : "GET /admin-api/verifications answered HTTP " +
                         r.status + ".");
      log.debug("Leaving Oid4vcDemo.outcome(). " + r.status);
      return;
    }
    if (!found.received) {
      const qr = latest.mode === "cross-device" || !latest.wallet
        ? "<div class=\"qr\" id=\"request-qr\">" +
          await qrSvg(latest.requestUri) + "</div><p class=\"mono\" " +
          "id=\"request-uri\">" + esc(latest.requestUri) + "</p>" +
          "<p><a class=\"button\" href=\"" + esc(latest.requestUri) +
          "\">Open with a wallet app on this device</a></p>"
        : "";
      util.sendHtml(res, 200, util.page("The Bar Door — present your " +
        "credential", "<div class=\"card\"><h1>Present your credential" +
        "</h1><p class=\"sub\" id=\"waiting\">Scan this with your wallet. " +
        "This page looks again every few seconds.</p>" + qr + "</div>",
        { refresh: 3 }));
      log.debug("Leaving Oid4vcDemo.outcome(). Not yet.");
      return;
    }
    const verdict = found.verdict || {};
    const claims = verdict.claims || {};
    const rows = Object.keys(claims).map(function (name) {
      log.debug("Entering outcome claim row.");
      const value = claims[name];
      log.debug("Leaving outcome claim row.");
      return "<tr><th>" + esc(name) + "</th><td>" +
        esc(typeof value === "object" ? JSON.stringify(value) : value) +
        "</td></tr>";
    }).join("");
    const failed = (verdict.checks || []).filter(function (one) {
      return one && one.ok === false;
    }).map(function (one) {
      return "<li>" + esc(one.name) + (one.detail ? ": " + esc(one.detail)
                                                  : "") + "</li>";
    }).join("");
    const body = verdict.ok
      ? "<p class=\"ok\" id=\"accepted\">Welcome in. The presentation " +
        "verified.</p><table>" + rows + "</table>"
      : "<p class=\"err\" id=\"refused\">Not today. " +
        esc(verdict.error ? "The wallet answered " + verdict.error +
            (verdict.errorDescription ? " (" + verdict.errorDescription +
             ")" : "") + "." : "The presentation did not verify.") +
        "</p>" + (failed ? "<ul>" + failed + "</ul>" : "");
    util.sendHtml(res, 200, util.page("The Bar Door",
      "<div class=\"card\"><h1>The Bar Door</h1>" + body +
      "<p><a href=\"/verifier\">Present another</a></p></div>"));
    log.debug("Leaving Oid4vcDemo.outcome(). ok=" + !!verdict.ok);
  }
}

module.exports = { Oid4vcDemo: Oid4vcDemo };
