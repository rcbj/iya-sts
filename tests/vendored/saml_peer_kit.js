// ===========================================================================
// WHAT THE FOUR SAML INTEROPERABILITY JOBS SHARE (#189–#192).
//
// Each job drives one independent SAML implementation — Shibboleth SP 3,
// pysaml2, SimpleSAMLphp and Keycloak's SAML broker — running as a second
// container on the suite's bridge (tests/saml-peers/, the `saml-peers`
// compose profile), against a throwaway realm of this service. What is the
// same for all four lives here:
//
//   * THE CHECK LEDGER — `check()`, `must()`, a floor on the count, the exit.
//   * THE MANAGEMENT API — realms, people, applications, settings, and
//     consuming a peer's SP metadata (#37) exactly as an operator would.
//   * A BROWSER — cookies per host, redirects, forms, the sign-in and consent
//     screens of this service, every SAML message a hop carries captured —
//     that walks BOTH origins: the peer's and the service's. It is plain
//     HTTP, like every SAML job here; no browser fleet (tests/CLAUDE.md).
//   * THE PEER'S OWN LOG, the harness's error-and-warning source: each peer
//     writes it to a directory of the volume the suite shares with its runner
//     (SAML_PEERS_LOG_DIR), and `logWatch()` hands a scenario the lines that
//     arrived while it ran.
//   * THE SERVICE'S TLS ANCHOR, handed to a peer for its back channel
//     (artifact resolution, the attribute query, back-channel logout): the
//     file this job was told to trust (NODE_EXTRA_CA_CERTS), or the service's
//     own `/tls/server-certificate` for a run without one.
//
// OWNED HERE (a LOCAL helper, tests/vendored/MANIFEST.js).
// ===========================================================================

"use strict";

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

const bunyan = require("bunyan");

const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 sts_saml_interop/1.0";

// ---------------------------------------------------------------------------
// ONE KIT PER JOB: the ledger and the logger are the job's own.
// ---------------------------------------------------------------------------
function create(name) {
  const log = bunyan.createLogger({ name: name,
                                    level: appconfig.LOG_LEVEL ||
                                           process.env.LOG_LEVEL || "info" });
  log.debug("Entering create(). " + name);
  if (appconfigProblem) {
    log.debug("CONFIG_FILE could not be read, so the configuration is " +
              "empty: " + appconfigProblem.message);
  }
  let base = process.env.OID4VCI_ISSUER_URL ||
             String(process.env.WSTRUST_STS_URL ||
                    "https://localhost:8081/sts").replace(/\/sts\/?$/, "");
  base = String(base).replace(/\/+$/, "");
  const kit = { log: log, checks: 0, failures: [], findings: [] };

  kit.setBase = function (url) {
    log.debug("Entering setBase(). " + url);
    base = String(url || base).replace(/\/+$/, "");
    log.debug("Leaving setBase().");
  };
  kit.base = function () {
    log.debug("Entering base().");
    log.debug("Leaving base().");
    return base;
  };
  kit.realmBase = function (realm) {
    log.debug("Entering realmBase().");
    log.debug("Leaving realmBase().");
    return base + "/realm/" + realm;
  };

  // ---- the ledger ---------------------------------------------------------
  kit.check = async function (what, fn) {
    log.debug("Entering check(). " + what);
    try {
      await fn();
      kit.checks += 1;
      log.info("  ✓ " + what);
    } catch (e) {
      log.debug("Caught in check(): " + ((e && e.message) || e));
      kit.failures.push(what + " — " + ((e && e.message) || e));
      log.error("  ✗ " + what + "  — " + ((e && e.message) || e));
    }
    log.debug("Leaving check().");
  };
  kit.must = function (condition, message) {
    log.debug("Entering must().");
    if (!condition) {
      log.debug("Leaving must(). Refused.");
      throw new Error("SETUP: " + message);
    }
    log.debug("Leaving must().");
  };
  kit.assert = function (condition, message) {
    log.debug("Entering assert().");
    if (!condition) {
      log.debug("Leaving assert(). Failed.");
      throw new Error(message);
    }
    log.debug("Leaving assert().");
  };
  kit.finish = function (floor) {
    log.debug("Entering finish().");
    if (kit.failures.length) {
      log.error(kit.checks + " check(s) passed, " + kit.failures.length +
                " FAILED:");
      kit.failures.forEach(function (f) {
        log.error("  ✗ " + f);
      });
      log.debug("Leaving finish(). Failed.");
      return 1;
    }
    // A FLOOR ON THE COUNT: a scenario that stops being called takes its
    // assertions with it, and the run would still say "passed".
    if (kit.checks < floor) {
      log.error("only " + kit.checks + " checks ran, fewer than " + floor +
                "; a scenario stopped being called");
      log.debug("Leaving finish(). Under the floor.");
      return 1;
    }
    log.info(kit.checks + " checks passed.");
    log.info("Test completed successfully.");
    log.debug("Leaving finish().");
    return 0;
  };

  // ---- the management API -------------------------------------------------
  kit.api = async function (realm, method, p, payload) {
    log.debug("Entering api(). " + method + " " + p);
    const options = { method: method, redirect: "manual", headers: {} };
    if (payload !== undefined) {
      options.headers["content-type"] = "application/json";
      options.body = JSON.stringify(payload);
    }
    const prefix = realm ? kit.realmBase(realm) : base;
    const r = await fetch(prefix + "/admin-api" + p, options);
    const text = await r.text();
    let body = null;
    try {
      body = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in api(): " + ((e && e.message) || e));
      // Not JSON; `text` carries the answer into every message quoting it.
      body = null;
    }
    log.debug("Leaving api(). status=" + r.status);
    return { status: r.status, body: body, text: text };
  };
  kit.ensureRealm = async function (id, realmMode, overrides) {
    log.debug("Entering ensureRealm(). " + id + " " + realmMode);
    const made = await kit.api(null, "POST", "/realms/create", {
      id: id, domain: id + ".example.net", name: name + " " + realmMode,
      overrides: Object.assign({ "global.mode": realmMode },
                               overrides || {}) });
    kit.must(made.status === 200 ||
             /already/i.test(JSON.stringify(made.body || made.text)),
             "creating the realm " + id + " answered " + made.status + " " +
             made.text.slice(0, 300));
    log.debug("Leaving ensureRealm().");
  };
  kit.setting = async function (realm, key, value) {
    log.debug("Entering setting(). " + key);
    const r = await kit.api(realm, "POST", "/config/set",
                            { key: key, value: value });
    kit.must(r.status === 200, "setting " + key + " in " + realm +
             " answered " + r.status + " " + r.text.slice(0, 300));
    log.debug("Leaving setting().");
  };
  kit.createPerson = async function (realm, username, password, attrs) {
    log.debug("Entering createPerson(). " + realm + " " + username);
    const r = await kit.api(realm, "POST", "/users/create", {
      username: username, invent: false,
      attributes: Object.assign({
        cn: "Peer " + username, givenName: "Peer", sn: username,
        displayName: "Peer " + username,
        mail: username + "@" + realm + ".example.net" }, attrs || {}),
      credential: "password", password: password });
    kit.must(r.status === 200 && r.body && r.body.ok,
             "creating " + username + " in " + realm + " answered " +
             r.status + " " + r.text.slice(0, 300));
    log.debug("Leaving createPerson().");
  };
  kit.createApplication = async function (realm, identifier, protocols,
                                          fields) {
    log.debug("Entering createApplication(). " + identifier);
    const r = await kit.api(realm, "POST", "/applications/create",
      { identifier: identifier, name: name + " " + identifier,
        protocols: protocols, fields: fields || {} });
    kit.must(r.status === 200 && r.body && r.body.ok,
             "creating the application " + identifier + " in " + realm +
             " answered " + r.status + " " + r.text.slice(0, 300));
    log.debug("Leaving createApplication().");
  };
  // CONSUMING A PEER'S METADATA (#37): the operator's upload, which registers
  // its endpoints, keys, NameID formats and flags.
  kit.consumeMetadata = async function (realm, entityId, documentXml) {
    log.debug("Entering consumeMetadata(). " + entityId);
    const r = await kit.api(realm, "POST", "/saml2/upload-metadata",
                            { sp: entityId, document: documentXml });
    kit.must(r.status === 200 && r.body && r.body.ok,
             "consuming the metadata of " + entityId + " in " + realm +
             " answered " + r.status + " " + r.text.slice(0, 600));
    log.debug("Leaving consumeMetadata().");
    return r.body;
  };

  // ---- the service's TLS anchor -------------------------------------------
  kit.stsAnchor = async function () {
    log.debug("Entering stsAnchor().");
    const file = process.env.NODE_EXTRA_CA_CERTS;
    if (file) {
      try {
        const pem = fs.readFileSync(file, "utf8");
        if (/BEGIN CERTIFICATE/.test(pem)) {
          log.debug("Leaving stsAnchor(). From " + file + ".");
          return pem;
        }
      } catch (e) {
        log.debug("Caught in stsAnchor(): " + ((e && e.message) || e));
        // Unreadable: ask the service instead, below.
      }
    }
    const r = await fetch(base + "/tls/server-certificate");
    const pem = await r.text();
    kit.must(r.status === 200 && /BEGIN CERTIFICATE/.test(pem),
             "the service's TLS certificate could not be read (" + r.status +
             ")");
    log.debug("Leaving stsAnchor(). From the service.");
    return pem;
  };

  // ---- the peer's own log ---------------------------------------------------
  //
  // `logWatch(peer, files, isProblem)` remembers where each file ends now;
  // `.since()` answers every line added to any of them since, and
  // `.problems()` those `isProblem` calls a warning or an error. A file that
  // does not exist yet is read from its start when it appears.
  kit.logDir = function (peer) {
    log.debug("Entering logDir(). " + peer);
    const root = process.env.SAML_PEERS_LOG_DIR ||
                 "/run/sts-test/saml-peers";
    log.debug("Leaving logDir().");
    return path.join(root, peer);
  };
  kit.logWatch = function (peer, files, isProblem) {
    log.debug("Entering logWatch(). " + peer);
    const dir = kit.logDir(peer);
    const sizeOf = function (f) {
      log.debug("Entering sizeOf(). " + f);
      try {
        log.debug("Leaving sizeOf().");
        return fs.statSync(path.join(dir, f)).size;
      } catch (e) {
        log.debug("Caught in sizeOf(): " + ((e && e.message) || e));
        // Not written yet: everything it will hold is new.
        log.debug("Leaving sizeOf(). Absent.");
        return 0;
      }
    };
    const marks = {};
    files.forEach(function (f) {
      marks[f] = sizeOf(f);
    });
    const watch = {
      since: function () {
        log.debug("Entering since().");
        const lines = [];
        files.forEach(function (f) {
          let text = "";
          try {
            const buf = fs.readFileSync(path.join(dir, f));
            // A file that shrank was rotated or recreated: read it whole.
            text = buf.slice(buf.length >= marks[f] ? marks[f] : 0)
              .toString("utf8");
          } catch (e) {
            log.debug("Caught in since(): " + ((e && e.message) || e));
            // Still absent: nothing arrived in it.
            text = "";
          }
          text.split(/\r?\n/).filter(Boolean).forEach(function (line) {
            lines.push(f + ": " + line);
          });
        });
        log.debug("Leaving since(). " + lines.length);
        return lines;
      },
      problems: function (allowed) {
        log.debug("Entering problems().");
        const out = watch.since().filter(function (line) {
          return isProblem(line) && !(allowed || []).some(function (re) {
            return re.test(line);
          });
        });
        log.debug("Leaving problems(). " + out.length);
        return out;
      }
    };
    log.debug("Leaving logWatch().");
    return watch;
  };
  // Waits for a line matching `re` to arrive in a watch, up to `ms`.
  kit.waitForLine = async function (watch, re, ms) {
    log.debug("Entering waitForLine(). " + re);
    const deadline = Date.now() + (ms || 5000);
    while (Date.now() < deadline) {
      const hit = watch.since().find(function (l) {
        return re.test(l);
      });
      if (hit) {
        log.debug("Leaving waitForLine(). Found.");
        return hit;
      }
      await kit.sleep(200);
    }
    log.debug("Leaving waitForLine(). Not found.");
    return "";
  };
  kit.logDirReadable = function (peer) {
    log.debug("Entering logDirReadable(). " + peer);
    let ok = false;
    try {
      ok = fs.statSync(kit.logDir(peer)).isDirectory();
    } catch (e) {
      log.debug("Caught in logDirReadable(): " + ((e && e.message) || e));
      ok = false;
    }
    log.debug("Leaving logDirReadable(). " + ok);
    return ok;
  };

  kit.sleep = function (ms) {
    log.debug("Entering sleep().");
    log.debug("Leaving sleep().");
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  };

  // ---- the browser ----------------------------------------------------------
  kit.browser = function () {
    log.debug("Entering browser().");
    const jars = {};
    const b = {
      jarFor: function (url) {
        log.debug("Entering jarFor().");
        const host = new URL(url).host;
        jars[host] = jars[host] || {};
        log.debug("Leaving jarFor().");
        return jars[host];
      },
      cookies: function (url) {
        log.debug("Entering cookies().");
        const jar = b.jarFor(url);
        log.debug("Leaving cookies().");
        return Object.keys(jar).map(function (k) {
          return k + "=" + jar[k];
        }).join("; ");
      },
      take: function (url, res) {
        log.debug("Entering take().");
        const jar = b.jarFor(url);
        (res.headers.getSetCookie ? res.headers.getSetCookie() : [])
          .forEach(function (line) {
            const pair = line.split(";")[0];
            const i = pair.indexOf("=");
            const k = pair.slice(0, i).trim();
            const v = pair.slice(i + 1).trim();
            // An expired or emptied cookie is a deletion.
            if (!v || /expires=Thu, 01[- ]Jan[- ]1970/i.test(line) ||
                /max-age=0\b/i.test(line)) {
              delete jar[k];
            } else {
              jar[k] = v;
            }
          });
        log.debug("Leaving take().");
      },
      forget: function (url) {
        log.debug("Entering forget().");
        jars[new URL(url).host] = {};
        log.debug("Leaving forget().");
      }
    };
    // One request, redirects NOT followed.
    b.hop = async function (url, options) {
      log.debug("Entering hop(). " + ((options && options.method) || "GET") +
                " " + url);
      const o = Object.assign({ redirect: "manual", headers: {} },
                              options || {});
      // A BROWSER'S User-Agent: this walk stands in for a person at a
      // browser, and the risk evaluator scores node's own as an automated
      // client, which a product realm's issuance policy refuses (#62).
      o.headers = Object.assign({ "User-Agent": AGENT }, o.headers);
      const c = b.cookies(url);
      if (c) {
        o.headers.cookie = c;
      }
      const r = await fetch(url, o);
      b.take(url, r);
      const body = r.status >= 300 && r.status < 400 ? "" : await r.text();
      log.debug("Leaving hop(). " + r.status);
      return { status: r.status, headers: r.headers, body: body, url: url,
               location: r.headers.get("location") || "" };
    };
    b.postForm = function (url, fields) {
      log.debug("Entering postForm(). " + url);
      log.debug("Leaving postForm().");
      return b.hop(url, {
        method: "POST", body: new URLSearchParams(fields).toString(),
        headers: { "content-type": "application/x-www-form-urlencoded" } });
    };
    log.debug("Leaving browser().");
    return b;
  };

  // Every form on a page, with its action, method and every named input.
  kit.formsIn = function (html) {
    log.debug("Entering formsIn().");
    const out = [];
    const re = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
    let m = re.exec(String(html || ""));
    while (m) {
      const action = kit.htmlDecode(
        (/action\s*=\s*["']([^"']*)["']/i.exec(m[1]) || [])[1] || "");
      const method = ((/method\s*=\s*["']([^"']*)["']/i.exec(m[1]) ||
                       [])[1] || "get").toLowerCase();
      const fields = {};
      const id = (/id\s*=\s*["']([^"']*)["']/i.exec(m[1]) || [])[1] || "";
      [...m[2].matchAll(/<input\b[^>]*>/gi)].forEach(function (one) {
        const n = /name\s*=\s*["']([^"']+)["']/i.exec(one[0]);
        const v = /value\s*=\s*["']([^"']*)["']/i.exec(one[0]);
        const t = (/type\s*=\s*["']([^"']+)["']/i.exec(one[0]) || [])[1] ||
                  "text";
        // An unticked box posts nothing, as in a browser.
        const unticked = /^(checkbox|radio)$/i.test(t) &&
                         !/\bchecked\b/i.test(one[0]);
        if (n && !unticked && !/^(submit|button|image|reset)$/i.test(t)) {
          fields[kit.htmlDecode(n[1])] = v ? kit.htmlDecode(v[1]) : "";
        }
      });
      out.push({ action: action, method: method, fields: fields, id: id });
      m = re.exec(String(html || ""));
    }
    log.debug("Leaving formsIn(). " + out.length);
    return out;
  };
  kit.htmlDecode = function (text) {
    log.debug("Entering htmlDecode().");
    log.debug("Leaving htmlDecode().");
    return String(text || "").replace(/&#x([0-9a-f]+);/gi, function (_, h) {
      return String.fromCharCode(parseInt(h, 16));
    }).replace(/&#(\d+);/g, function (_, d) {
      return String.fromCharCode(Number(d));
    }).replace(/&quot;/g, "\"").replace(/&apos;/g, "'").replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">").replace(/&amp;/g, "&");
  };
  kit.squash = function (text) {
    log.debug("Entering squash().");
    log.debug("Leaving squash().");
    return String(text || "").replace(/<style[\s\S]*?<\/style>/g, " ")
      .replace(/<script[\s\S]*?<\/script>/g, " ")
      .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 400);
  };
  kit.decodeRedirect = function (value) {
    log.debug("Entering decodeRedirect().");
    log.debug("Leaving decodeRedirect().");
    return zlib.inflateRawSync(Buffer.from(String(value), "base64"))
      .toString("utf8");
  };
  kit.decodePost = function (value) {
    log.debug("Entering decodePost().");
    log.debug("Leaving decodePost().");
    return Buffer.from(String(value), "base64").toString("utf8");
  };

  // Every SAML message a hop carries: a Location's query, or a page's forms.
  kit.messagesIn = function (r) {
    log.debug("Entering messagesIn().");
    const out = [];
    const from = r.url;
    if (r.location) {
      const u = new URL(r.location, r.url);
      for (const field of ["SAMLRequest", "SAMLResponse"]) {
        const v = u.searchParams.get(field);
        if (v) {
          let xml = "";
          try {
            xml = kit.decodeRedirect(v);
          } catch (e) {
            log.debug("Caught in messagesIn(): " + ((e && e.message) || e));
            xml = "(not DEFLATE: " + String(v).slice(0, 60) + ")";
          }
          out.push({ field: field, binding: "redirect", xml: xml,
                     from: from, to: u.origin + u.pathname,
                     signed: !!u.searchParams.get("Signature") });
        }
      }
      for (const field of ["SAMLart", "TARGET"]) {
        if (u.searchParams.get(field) && field === "SAMLart") {
          out.push({ field: "SAMLart", binding: "artifact",
                     artifact: u.searchParams.get("SAMLart"), from: from,
                     to: u.origin + u.pathname });
        }
      }
    }
    if (r.body) {
      kit.formsIn(r.body).forEach(function (f) {
        for (const field of ["SAMLRequest", "SAMLResponse"]) {
          if (f.fields[field]) {
            out.push({ field: field,
                       binding: f.fields.SigAlg ? "simplesign" : "post",
                       xml: kit.decodePost(f.fields[field]), from: from,
                       to: f.action, fields: f.fields });
          }
        }
        if (f.fields.SAMLart) {
          out.push({ field: "SAMLart", binding: "artifact-post",
                     artifact: f.fields.SAMLart, from: from, to: f.action });
        }
      });
    }
    log.debug("Leaving messagesIn(). " + out.length);
    return out;
  };

  // ---------------------------------------------------------------------------
  // A WALK ACROSS BOTH ORIGINS. Follows redirects, answers this service's
  // sign-in and consent screens, submits every auto-posting SAML form (the
  // service's, and each peer's own binding templates), and stops at a page
  // that asks nothing more of it — or where `opts.stopAt(url, r)` says. What
  // every hop carried is captured, in order, with the trail of URLs.
  //
  // `opts.username` / `opts.password` answer the sign-in screen;
  // `opts.onPage(r, forms)` may return { url, fields } (a POST) or
  // { url } (a GET) for a page only the job knows how to answer — a peer's
  // own sign-in, a consent of Keycloak's — or null.
  // ---------------------------------------------------------------------------
  kit.walk = async function (b, startUrl, opts) {
    log.debug("Entering walk(). " + startUrl);
    const o = opts || {};
    const captured = [];
    const trail = [];
    let r = o.first ? await o.first() : await b.hop(startUrl);
    for (let step = 0; step < 40; step += 1) {
      trail.push(r.status + " " + r.url);
      kit.messagesIn(r).forEach(function (m) {
        captured.push(m);
      });
      if (o.stopAt && o.stopAt(r.url, r)) {
        break;
      }
      if (r.status >= 300 && r.status < 400 && r.location) {
        const next = new URL(r.location, r.url).toString();
        if (o.stopBefore && o.stopBefore(next)) {
          trail.push("(stopped before) " + next);
          log.debug("Leaving walk(). Stopped before a redirect.");
          return { captured: captured, last: r, trail: trail, next: next };
        }
        r = await b.hop(next);
        continue;
      }
      if (r.status !== 200) {
        break;
      }
      const forms = kit.formsIn(r.body);
      const custom = o.onPage ? await o.onPage(r, forms) : null;
      if (custom) {
        const to = new URL(custom.url, r.url).toString();
        r = custom.fields ? await b.postForm(to, custom.fields)
                          : await b.hop(to);
        continue;
      }
      const signIn = forms.find(function (f) {
        return "authn_id" in f.fields;
      });
      const consent = forms.find(function (f) {
        return /consent/.test(f.action) || "consent_id" in f.fields;
      });
      const onward = forms.find(function (f) {
        return f.method === "post" &&
               ("SAMLResponse" in f.fields || "SAMLRequest" in f.fields ||
                "SAMLart" in f.fields);
      });
      if (signIn && o.username) {
        const to = new URL(signIn.action || r.url, r.url).toString();
        r = await b.postForm(to, Object.assign({}, signIn.fields, {
          username: o.username, password: o.password, action: "login" }));
        continue;
      }
      if (consent) {
        const to = new URL(consent.action || r.url, r.url).toString();
        r = await b.postForm(to, Object.assign({}, consent.fields, {
          action: "allow", decision: "allow" }));
        continue;
      }
      if (onward) {
        const to = new URL(onward.action || r.url, r.url).toString();
        if (o.stopBefore && o.stopBefore(to)) {
          trail.push("(stopped before) POST " + to);
          log.debug("Leaving walk(). Stopped before a form.");
          return { captured: captured, last: r, trail: trail, next: to,
                   form: onward };
        }
        r = await b.postForm(to, onward.fields);
        continue;
      }
      break;
    }
    log.debug("Leaving walk(). " + trail.length + " hop(s).");
    return { captured: captured, last: r, trail: trail };
  };
  kit.describeWalk = function (w) {
    log.debug("Entering describeWalk().");
    log.debug("Leaving describeWalk().");
    return w.trail.join(" → ") + " — " +
           kit.squash(w.last && w.last.body);
  };
  kit.jsonOf = function (text) {
    log.debug("Entering jsonOf().");
    try {
      log.debug("Leaving jsonOf().");
      return JSON.parse(text);
    } catch (e) {
      log.debug("Caught in jsonOf(): " + ((e && e.message) || e));
      log.debug("Leaving jsonOf(). Not JSON.");
      return null;
    }
  };
  // A finding the job records beside its checks: a behaviour of the peer or
  // the service worth a line in the report, which is not a failure.
  kit.note = function (text) {
    log.debug("Entering note().");
    kit.findings.push(text);
    log.info("  note: " + text);
    log.debug("Leaving note().");
  };

  log.debug("Leaving create().");
  return kit;
}

module.exports = { create: create };
