// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: companion/demo_kerberos.js
//
// ===========================================================================
// THE KERBEROS AND SPNEGO DEMONSTRATION: A KERBEROS-PROTECTED WEB PAGE AND A
// KERBEROS-PROTECTED TCP SERVICE, IN FRONT OF THE SERVICE'S KDC (#595, phase
// 4 of #591, moved out of the service from `kerberos/`).
//
// Until #595 these were the service's own `/spnego`, `/spnego/protected`,
// `/krb5/service` and the TCP socket on `krb5.servicePort`, answered by the
// service's own acceptor with a key the service held for itself. They are
// the companion's now, and the companion is a Kerberos service the way any
// customer's web application or daemon is:
//
//   GET /spnego             what is protected, behind which service
//                           principal, in which realm (`?format=json`)
//   GET /spnego/protected   RFC 4559: 401 `WWW-Authenticate: Negotiate`
//                           without a ticket; with one, 200 and the
//                           acceptor's mutual-authentication token
//   GET /krb5/service       the TCP service, as JSON: its principal, its
//                           port, and the last exchange
//   TCP COMPANION_KRB5_SERVICE_PORT (8888)
//                           a length-prefixed GSS InitialContextToken
//                           carrying an AP-REQ, answered with the GSS
//                           AP-REP (mutual authentication), a KRB-ERROR
//                           (refused), or a clean close (accepted, no
//                           mutual authentication asked)
//
// **ITS OWN PRINCIPAL, ITS OWN KEYTAB.** `COMPANION_KRB5_SPN` — by default
// `HTTP/<the host of COMPANION_PUBLIC_URL>`, the name a browser and curl
// derive from the URL — is created in the service's KDC through
// `POST /admin-api/kerberos/principals/create-service` (Admin Write, which
// the companion holds), which makes a random key and hands over its keytab
// once; after a restart the companion, which keeps nothing, rotates the key
// instead and is handed a new keytab. The keytab is written to a file only
// this process can read and named to MIT Kerberos as `KRB5_KTNAME`. It is
// asked for at the first request that needs it, not at start, for the
// registration's reason (`sts_client.js`): a companion that came up before
// the service does not fail.
//
// **THE ACCEPTOR IS MIT KERBEROS'S GSS-API, THROUGH THE `kerberos` PACKAGE.**
// Decided for #595 against porting an acceptor: the point of moving the
// demonstration out is that the service's KDC is then exercised by a
// Kerberos service it did not write, as a customer's Apache
// (`mod_auth_gssapi`) or a Java or .NET service exercises it — and an
// acceptor ported from the service's own `krb5_service.js`, or the parent
// project's codec copied in, would be the service agreeing with itself,
// which is exactly how this KDC once shipped without advertising
// PA-ENC-TIMESTAMP (`kerberos/CLAUDE.md`). MIT checks what an acceptor
// checks: the ticket under the keytab's key and kvno, the Authenticator,
// the clock, the replay cache, the GSS checksum, and it answers SPNEGO
// (RFC 4178) and the bare Kerberos mechanism (RFC 4121) both. `kerberos`
// (Apache-2.0, MongoDB's) is a thin N-API binding over
// `gss_accept_sec_context()`, built from source in the image against
// Debian's MIT libraries. It is required LAZILY, so the companion's pages
// and `tests/companion.js` load without it, and a stand-in (`deps.gss`)
// replaces it in that test.
//
// **WHAT IS NOT HERE ANY MORE, AND WHY.** The service's pages drew its own
// acceptor's per-check table, and `/spnego/protected` took three knobs
// (`?mic=require`, `?mech=none`, `?mutual=off`) that made its negotiation
// fail in one chosen way. Both were properties of an acceptor the service
// wrote; MIT's tells a caller whether the context was established and, if
// not, why in one sentence — what a real service's operator sees — and it
// takes no knobs. The negotiation's own diagnostics stay in the service, at
// the sign-in door `/authn/spnego`, whose acceptor is still the service's.
// Each request is a context of its own: a ticket's exchange completes in
// one round trip, and nothing is kept between requests.
// ===========================================================================

const fs = require("fs");
const os = require("os");
const net = require("net");
const path = require("path");
const util = require("./companion_util.js");
const krb5Error = require("./krb5_error.js");

const log = util.logger("demo_kerberos");
const esc = util.esc;

// The largest message the TCP socket reads: an AP-REQ with a PAC is a few
// kilobytes, and a client that sends more is not sending one.
const MAX_TOKEN_BYTES = 64 * 1024;

// The two mechanism OIDs a Negotiate token is told apart by, as DER.
const SPNEGO_OID = Buffer.from("06062b0601050502", "hex");
const KRB5_OID = Buffer.from("06092a864886f712010202", "hex");

/**
 * What kind of token a client sent, read off its first bytes, for the page.
 *
 * @param {Buffer} bytes - the token
 * @returns {string} `SPNEGO`, `Kerberos`, `NTLM` or `unknown`
 */
function tokenKind(bytes) {
  log.debug("Entering tokenKind().");
  let kind = "unknown";
  if (bytes.length > 4 && bytes.subarray(0, 7).toString("latin1") ===
      "NTLMSSP") {
    kind = "NTLM";
  } else if (bytes.length > 12 && bytes[0] === 0x60) {
    const lengthBytes = bytes[1] & 0x80 ? 1 + (bytes[1] & 0x7f) : 1;
    const oid = bytes.subarray(1 + lengthBytes);
    if (oid.subarray(0, SPNEGO_OID.length).equals(SPNEGO_OID)) {
      kind = "SPNEGO";
    } else if (oid.subarray(0, KRB5_OID.length).equals(KRB5_OID)) {
      kind = "Kerberos";
    }
  } else if (bytes.length && (bytes[0] === 0xa1)) {
    kind = "SPNEGO";
  }
  log.debug("Leaving tokenKind(). " + kind);
  return kind;
}

/**
 * MIT Kerberos's GSS-API acceptor, through the `kerberos` package.
 */
class MitAcceptor {
  constructor() {
    log.debug("Entering MitAcceptor.constructor().");
    this.lib = null;
    log.debug("Leaving MitAcceptor.constructor().");
  }

  /**
   * Accepts one token as a fresh context.
   *
   * @param {Buffer} token - the initiator's token
   * @returns {Promise<object>} `{ ok, client, response (Buffer|null),
   *   error }`
   */
  async accept(token) {
    log.debug("Entering MitAcceptor.accept(). " + token.length + " bytes");
    if (!this.lib) {
      // LAZILY: a native module the companion's pages, and the in-process
      // test, do without.
      this.lib = require("kerberos");
    }
    // An empty service name is GSS_C_NO_CREDENTIAL: any principal the
    // keytab holds a key for — which is the companion's one principal.
    const server = await this.lib.initializeServer("");
    try {
      await server.step(token.toString("base64"));
    } catch (e) {
      log.debug("Caught in MitAcceptor.accept(): " + ((e && e.message) ||
                                                       e));
      log.debug("Leaving MitAcceptor.accept(). Refused.");
      return { ok: false, client: "", response: null,
               error: String((e && e.message) || e) };
    }
    log.debug("Leaving MitAcceptor.accept(). " + server.username);
    return { ok: true, client: String(server.username || ""),
             response: server.response
               ? Buffer.from(server.response, "base64") : null,
             error: "" };
  }
}

/**
 * The Kerberos and SPNEGO demonstration, mounted on the companion.
 */
class KerberosDemo {
  /**
   * @param {object} deps - `sts` (an StsClient), `publicUrl`, `spn` (or ''
   *   for the URL's host), `servicePort` (the TCP socket's, 0 for any, null
   *   for none), `keytabDir`, `gss` (a stand-in for the acceptor)
   */
  constructor(deps) {
    log.debug("Entering KerberosDemo.constructor().");
    this.sts = deps.sts;
    this.publicUrl = String(deps.publicUrl || "").replace(/\/+$/, "");
    this.spn = String(deps.spn || "") ||
      "HTTP/" + new URL(this.publicUrl || "http://localhost").hostname;
    this.servicePort = deps.servicePort === undefined ? 8888
      : deps.servicePort;
    this.keytabDir = String(deps.keytabDir || "");
    this.gss = deps.gss || new MitAcceptor();
    this.keytab = null;
    this.provisioning = null;
    this.lastExchange = { spnego: null, tcp: null };
    this.socket = { listening: false, port: null, error: "" };
    log.debug("Leaving KerberosDemo.constructor().");
  }

  /**
   * The demonstration's entry on the start page.
   *
   * @returns {object} `{ id, title, links }`
   */
  describe() {
    log.debug("Entering KerberosDemo.describe().");
    log.debug("Leaving KerberosDemo.describe().");
    return { id: "kerberos", title: "Kerberos and SPNEGO",
             links: [{ href: "/spnego", text: "A Kerberos-protected page " +
                       "(SPNEGO, RFC 4559) — " + this.spn },
                     { href: "/krb5/service", text: "A Kerberos-protected " +
                       "TCP service (an AP-REQ on port " +
                       (this.socket.port || this.servicePort) + ")" }] };
  }

  /**
   * Adds the demonstration's routes.
   *
   * @param {object} router - `get(path, handler)`, `post(path, handler)`
   */
  mount(router) {
    log.debug("Entering KerberosDemo.mount().");
    router.get("/spnego", (req, res, ctx) => this.advertPage(res, ctx));
    router.get("/spnego/protected", (req, res) => this.protectedPage(req,
                                                                     res));
    router.get("/krb5/service", (req, res) => this.serviceJson(res));
    log.debug("Leaving KerberosDemo.mount().");
  }

  /**
   * The keytab, asked of the service's KDC once — again after a failure —
   * and named to MIT Kerberos.
   *
   * @returns {Promise<object>} `{ principal, kvno, etypes, file }`
   */
  ensureKeytab() {
    log.debug("Entering KerberosDemo.ensureKeytab().");
    if (this.keytab) {
      log.debug("Leaving KerberosDemo.ensureKeytab(). Held.");
      return Promise.resolve(this.keytab);
    }
    if (!this.provisioning) {
      this.provisioning = this.provision().catch((e) => {
        log.debug("Caught in KerberosDemo.ensureKeytab(): " +
                  ((e && e.message) || e));
        // Asked again on the next request, rather than failed for good.
        this.provisioning = null;
        throw e;
      });
    }
    log.debug("Leaving KerberosDemo.ensureKeytab(). Asking.");
    return this.provisioning;
  }

  /**
   * Creates (or rotates) the principal and writes its keytab.
   *
   * @returns {Promise<object>} the keytab's description
   */
  async provision() {
    log.debug("Entering KerberosDemo.provision(). " + this.spn);
    const reply = await this.sts.serviceKeytab(this.spn);
    const dir = this.keytabDir ||
      fs.mkdtempSync(path.join(os.tmpdir(), "companion-krb5-"));
    const file = path.join(dir, "companion.keytab");
    fs.writeFileSync(file, Buffer.from(String(reply.keytab), "base64"),
                     { mode: 0o600 });
    // MIT reads the default keytab's name from the environment at each new
    // context, so setting it here reaches every accept that follows.
    process.env.KRB5_KTNAME = "FILE:" + file;
    this.keytab = {
      principal: String(reply.principal || this.spn),
      kvno: reply.kvno,
      etypes: reply.etypes || [],
      keytabKvnos: reply.keytabKvnos || [reply.kvno],
      rotated: !!reply.rotated,
      file: file
    };
    log.info("companion: " + this.keytab.principal + " keyed at kvno " +
             this.keytab.kvno + (reply.rotated ? " (rotated)" : "") +
             "; keytab " + file);
    log.debug("Leaving KerberosDemo.provision().");
    return this.keytab;
  }

  /**
   * The realm the principal is in, once it is known.
   *
   * @returns {string} the realm, or ''
   */
  realm() {
    log.debug("Entering KerberosDemo.realm().");
    const at = this.keytab ? this.keytab.principal.lastIndexOf("@") : -1;
    log.debug("Leaving KerberosDemo.realm().");
    return at >= 0 ? this.keytab.principal.slice(at + 1) : "";
  }

  /**
   * The advertisement, as `GET /spnego?format=json` answers it.
   *
   * @returns {object} the advertisement
   */
  advertisement() {
    log.debug("Entering KerberosDemo.advertisement().");
    const held = this.keytab;
    log.debug("Leaving KerberosDemo.advertisement().");
    return {
      protectedResource: "/spnego/protected",
      servicePrincipalName: held ? held.principal : this.spn,
      realm: this.realm(),
      kvno: held ? held.kvno : null,
      scheme: "Negotiate",
      mechanisms: [{ oid: "1.3.6.1.5.5.2", name: "SPNEGO" },
                   { oid: "1.2.840.113554.1.2.2", name: "Kerberos 5" }],
      acceptor: "MIT Kerberos GSS-API (gss_accept_sec_context)",
      kdc: this.sts.publicBase,
      signInResource: this.sts.publicBase + "/authn/spnego",
      specifications: ["RFC 4178 (SPNEGO)", "RFC 4559 (Negotiate over " +
                       "HTTP)", "RFC 4121 (the Kerberos v5 GSS-API " +
                       "mechanism)"],
      lastExchange: this.lastExchange.spnego
    };
  }

  /**
   * `GET /spnego`: what is protected, and what a client needs to get in.
   *
   * @param {object} res - the response
   * @param {object} ctx - the request's context
   */
  async advertPage(res, ctx) {
    log.debug("Entering KerberosDemo.advertPage().");
    let problem = "";
    try {
      await this.ensureKeytab();
    } catch (e) {
      log.debug("Caught in KerberosDemo.advertPage(): " +
                ((e && e.message) || e));
      // The page still says what would be protected, and why it is not yet.
      problem = String((e && e.message) || e);
    }
    const advert = this.advertisement();
    if (String(ctx.query.get("format") || "").toLowerCase() === "json") {
      util.sendJson(res, problem ? 503 : 200,
                    Object.assign({ problem: problem || null }, advert));
      log.debug("Leaving KerberosDemo.advertPage(). JSON.");
      return;
    }
    util.sendHtml(res, problem ? 503 : 200, util.page("A Kerberos-protected " +
      "page", "<div class=\"card\"><h1>A Kerberos-protected page</h1><p " +
      "class=\"sub\">Kerberos over HTTP: RFC 4559 carries RFC 4178, which " +
      "carries RFC 4121, which carries the AP-REQ.</p>" +
      (problem ? "<p class=\"err\" id=\"keytab-problem\">This service has " +
                 "no key yet: " + esc(problem) + "</p>" : "") +
      "<p><a class=\"button\" href=\"/spnego/protected\">Open the protected " +
      "page</a></p><p>It answers <code>401</code> with <code>" +
      "WWW-Authenticate: Negotiate</code> to anybody without a ticket. A " +
      "browser answers that only for a host on its allow-list (Chrome's " +
      "<code>--auth-server-allowlist</code>, Firefox's <code>network." +
      "negotiate-auth.trusted-uris</code>) and with a ticket cache in the " +
      "realm; <code>kinit</code> then <code>curl --negotiate -u : " +
      esc(this.publicUrl) + "/spnego/protected</code> is the shortest way " +
      "in.</p><h2>What a client needs</h2><table>" +
      "<tr><td>Service principal</td><td><code id=\"spn\">" +
      esc(advert.servicePrincipalName) + "</code></td></tr>" +
      "<tr><td>Realm</td><td><code>" + esc(advert.realm || "(not yet " +
                                           "known)") + "</code></td></tr>" +
      "<tr><td>Key version</td><td><code>" + esc(advert.kvno === null
        ? "(none yet)" : advert.kvno) + "</code></td></tr>" +
      "<tr><td>The KDC</td><td>iya-sts at <code>" + esc(advert.kdc) +
      "</code> (port 88, or MS-KKDCP at <code>/KdcProxy</code>)</td></tr>" +
      "<tr><td>Acceptor</td><td>" + esc(advert.acceptor) + "</td></tr>" +
      "</table><p>The client derives the service principal from the URL's " +
      "host name and finds the KDC from its own configuration, so neither " +
      "is in the exchange — which is why a SPNEGO failure is so often a " +
      "DNS or principal-name problem with no evidence on the wire.</p>" +
      "<h2>The same handshake as a sign-in</h2><p>The service's own <a " +
      "href=\"" + esc(advert.signInResource) + "\"><code>/authn/spnego" +
      "</code></a> performs this negotiation and then starts a session in " +
      "the service, which every protocol it speaks then reads.</p>" +
      "<p><a href=\"/spnego?format=json\">This page as JSON</a> · <a " +
      "href=\"/krb5/service\">the TCP service</a> · <a href=\"/\">Back to " +
      "the start</a></p></div>"));
    log.debug("Leaving KerberosDemo.advertPage().");
  }

  /**
   * Accepts one token and records the exchange.
   *
   * @param {Buffer} token - the initiator's token
   * @param {string} via - `spnego` or `tcp`
   * @returns {Promise<object>} the acceptor's answer, with `kind`
   */
  async acceptToken(token, via) {
    log.debug("Entering KerberosDemo.acceptToken(). " + via);
    const kind = tokenKind(token);
    let out;
    try {
      await this.ensureKeytab();
      out = await this.gss.accept(token);
    } catch (e) {
      log.debug("Caught in KerberosDemo.acceptToken(): " +
                ((e && e.message) || e));
      // No keytab, or no acceptor: a refusal the client is told of.
      out = { ok: false, client: "", response: null,
              error: String((e && e.message) || e) };
    }
    out.kind = kind;
    this.lastExchange[via] = { at: new Date().toISOString(), ok: out.ok,
                               client: out.client || null, token: kind,
                               mutual: !!out.response,
                               error: out.error || null };
    log.info("companion: kerberos " + via + " " + (out.ok
      ? "ACCEPTED " + out.client : "refused: " + out.error));
    log.debug("Leaving KerberosDemo.acceptToken(). " + out.ok);
    return out;
  }

  /**
   * `GET /spnego/protected`: the RFC 4559 exchange.
   *
   * @param {object} req - the request
   * @param {object} res - the response
   */
  async protectedPage(req, res) {
    log.debug("Entering KerberosDemo.protectedPage().");
    const header = String(req.headers.authorization || "");
    const m = /^Negotiate\s+(\S+)\s*$/i.exec(header);
    if (!m) {
      // RFC 4559 section 4: the challenge carries no token; the client
      // knows the rest already, or does not get in.
      res.setHeader("WWW-Authenticate", "Negotiate");
      util.sendHtml(res, 401, util.page("Authentication required",
        "<div class=\"card\"><h1>401 — authentication required</h1>" +
        (header ? "<p class=\"err\">This page speaks <code>Negotiate" +
                  "</code>; the request offered <code>" +
                  esc(header.split(/\s+/)[0]) + "</code>.</p>" : "") +
        "<p>This page is protected with <code>Negotiate</code>. The " +
        "challenge carries no token: the client is expected to get a " +
        "ticket for <code>" + esc(this.spn) + "</code> from its KDC by " +
        "itself.</p><p><a href=\"/spnego\">What a client needs</a></p>" +
        "</div>"));
      log.debug("Leaving KerberosDemo.protectedPage(). Challenge.");
      return;
    }
    const token = Buffer.from(m[1], "base64");
    const out = await this.acceptToken(token, "spnego");
    if (out.response) {
      res.setHeader("WWW-Authenticate", "Negotiate " +
                    out.response.toString("base64"));
    } else if (!out.ok) {
      res.setHeader("WWW-Authenticate", "Negotiate");
    }
    if (!out.ok) {
      util.sendHtml(res, 401, util.page("Ticket refused",
        "<div class=\"card\"><h1>401 — the ticket was refused</h1>" +
        "<p class=\"err\" id=\"refusal\">" + esc(out.error) + "</p>" +
        "<table><tr><td>Token</td><td>" + esc(out.kind) + "</td></tr>" +
        "<tr><td>Service principal</td><td><code>" + esc(this.spn) +
        "</code></td></tr></table><p>The reason above is the acceptor's — " +
        "MIT Kerberos's — and is all a real service's operator would see." +
        "</p><p><a href=\"/spnego\">What a client needs</a></p></div>"));
      log.debug("Leaving KerberosDemo.protectedPage(). Refused.");
      return;
    }
    util.sendHtml(res, 200, util.page("Authenticated",
      "<div class=\"card\"><h1>200 — you are in</h1><p class=\"ok\">" +
      "Authenticated as <strong id=\"client\">" + esc(out.client) +
      "</strong> to <code>" + esc(this.spn) + "</code>.</p><p>This is the " +
      "protected content. Getting here took a Kerberos AP-REQ inside an " +
      "RFC 4121 GSS token" + (out.kind === "SPNEGO" ? " inside an RFC 4178 " +
      "negotiation" : "") + " inside an RFC 4559 HTTP header.</p><table>" +
      "<tr><td>Client</td><td><code>" + esc(out.client) + "</code></td></tr>" +
      "<tr><td>Token</td><td>" + esc(out.kind) + "</td></tr>" +
      "<tr><td>Mutual authentication</td><td>" + (out.response
        ? "the acceptor's token is in the <code>WWW-Authenticate</code> " +
          "header"
        : "none asked for") + "</td></tr>" +
      "<tr><td>Acceptor</td><td>MIT Kerberos GSS-API, with this " +
      "companion's own keytab</td></tr></table>" +
      "<p><a href=\"/spnego\">Back</a></p></div>"));
    log.debug("Leaving KerberosDemo.protectedPage(). Accepted.");
  }

  /**
   * `GET /krb5/service`: the TCP service, as JSON.
   *
   * @param {object} res - the response
   */
  serviceJson(res) {
    log.debug("Entering KerberosDemo.serviceJson().");
    util.sendJson(res, 200, {
      principal: this.keytab ? this.keytab.principal : this.spn,
      kvno: this.keytab ? this.keytab.kvno : null,
      port: this.socket.port,
      listening: this.socket.listening,
      listenError: this.socket.error || null,
      framing: "a 4-byte big-endian length, then a GSS InitialContextToken " +
               "carrying an AP-REQ (RFC 4121 section 4.1)",
      replies: "the GSS-wrapped AP-REP when mutual authentication was asked " +
               "for; a KRB-ERROR when the AP-REQ was refused; nothing (the " +
               "connection is closed) when it was accepted without",
      acceptor: "MIT Kerberos GSS-API (gss_accept_sec_context)",
      maxTokenBytes: MAX_TOKEN_BYTES,
      lastExchange: this.lastExchange.tcp
    });
    log.debug("Leaving KerberosDemo.serviceJson().");
  }

  /**
   * Answers one message on the TCP socket.
   *
   * @param {Buffer} message - the token, unframed
   * @returns {Promise<Buffer|null>} the reply, unframed, or null to close
   */
  async answerTcp(message) {
    log.debug("Entering KerberosDemo.answerTcp().");
    const out = await this.acceptToken(message, "tcp");
    if (out.ok) {
      log.debug("Leaving KerberosDemo.answerTcp(). Accepted.");
      return out.response || null;
    }
    const named = krb5Error.codeFor(out.error);
    const at = this.spn.indexOf("@");
    log.debug("Leaving KerberosDemo.answerTcp(). " + named.name);
    return krb5Error.krbError({
      code: named.code, realm: this.realm(),
      sname: (at >= 0 ? this.spn.slice(0, at) : this.spn).split("/"),
      eText: out.error
    });
  }

  /**
   * Starts the TCP socket. A bind that fails is recorded and shown on
   * `/krb5/service`, never thrown: the pages go on without it.
   *
   * @returns {Promise<object|null>} the server, or null
   */
  listen() {
    log.debug("Entering KerberosDemo.listen().");
    if (this.servicePort === null) {
      log.debug("Leaving KerberosDemo.listen(). Off.");
      return Promise.resolve(null);
    }
    const server = net.createServer((socket) => {
      this.serveConnection(socket);
    });
    log.debug("Leaving KerberosDemo.listen().");
    return new Promise((resolve) => {
      server.on("error", (e) => {
        log.error("companion: the Kerberos TCP service could not listen " +
                  "on " + this.servicePort + ": " + ((e && e.message) || e));
        this.socket = { listening: false, port: null,
                        error: String((e && e.message) || e) };
        resolve(null);
      });
      server.listen(this.servicePort, () => {
        this.socket = { listening: true, port: server.address().port,
                        error: "" };
        log.info("companion: the Kerberos TCP service listens on " +
                 this.socket.port + " as " + this.spn);
        resolve(server);
      });
    });
  }

  /**
   * One connection: length-prefixed messages, each answered in turn.
   *
   * @param {object} socket - the connection
   */
  serveConnection(socket) {
    log.debug("Entering KerberosDemo.serveConnection().");
    let buffer = Buffer.alloc(0);
    socket.on("error", function (e) {
      log.debug("companion: a Kerberos TCP connection failed: " +
                ((e && e.message) || e));
    });
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > 4 + MAX_TOKEN_BYTES ||
          (buffer.length >= 4 && (buffer.readUInt32BE(0) & 0x80000000))) {
        log.warn("companion: a Kerberos TCP client sent more than " +
                 MAX_TOKEN_BYTES + " bytes, or a reserved length; closing");
        socket.destroy();
        return;
      }
      if (buffer.length < 4 || buffer.length < 4 + buffer.readUInt32BE(0)) {
        return;
      }
      const message = buffer.subarray(4, 4 + buffer.readUInt32BE(0));
      buffer = buffer.subarray(4 + message.length);
      this.answerTcp(message).then(function (reply) {
        if (!reply) {
          // Accepted, and no mutual authentication was asked for: nothing
          // to send, so the connection is closed cleanly.
          socket.end();
          return;
        }
        const framed = Buffer.alloc(4 + reply.length);
        framed.writeUInt32BE(reply.length, 0);
        reply.copy(framed, 4);
        socket.write(framed);
      }, function (e) {
        log.error("companion: the Kerberos TCP service failed to answer: " +
                  ((e && e.stack) || e));
        socket.destroy();
      });
    });
    log.debug("Leaving KerberosDemo.serveConnection().");
  }
}

module.exports = { KerberosDemo: KerberosDemo, MitAcceptor: MitAcceptor,
                   tokenKind: tokenKind, MAX_TOKEN_BYTES: MAX_TOKEN_BYTES };
