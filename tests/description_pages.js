// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/description_pages.js
// ===========================================================================
// THE SIX PROTOCOL FAMILIES' DESCRIPTION PAGES ARE A STATIC SURFACE'S SHELL;
// THE PROTOCOL ENDPOINTS BENEATH THEM ARE UNCHANGED (#584).
//
// The whole stack in a child process, over HTTP on 127.0.0.1:
//
//   1. `GET /xacml` and `GET /xacml/description.js` are refused to a caller
//      presenting no certificate while `xacml.enforceAccess` is on — the
//      page's gate holds for its script — and both answer once it is off.
//   2. Each of `/saml2`, `/saml11`, `/xacml`, `/ssf`, `/scim`, `/spiffe`:
//      200, no-store, text/html, no Location; the shell — its family's
//      script on its own path, the card, the `<noscript>`, no server-drawn
//      table — under a policy that runs the script and keeps
//      `frame-ancestors`, carrying a view of the family's kind.
//   3. The JSON form: `?format=json` answers the family's description
//      document (the view's `document` for the four that had one, the view
//      itself for the two SAML pages, which had none); an `Accept` that
//      prefers JSON answers the same; `*/*` and `?format=html` with an
//      `Accept` of JSON answer the shell.
//   4. Each family's `description.js` is served as a script.
//   5. The SAML views name no mock service provider or relying party in
//      either mode (they were deleted, #592), and in product (#585) the
//      XACML document names no embedded PEP; in development it does.
//   6. The protocol endpoints beneath are not converted: the bare
//      `/saml2/ars` and `/saml11/responder` GETs are still drawn by the
//      server under `script-src 'none'`, and the metadata, SCIM discovery
//      and SSF configuration answer what they did, with no shell.
//   7. The renderers draw each family's real view, escaped, in French; no
//      catalog message carries `rich()`'s slot characters.
//   8. The runtime draws `/ssf` from the shell it came in, in the browser's
//      language, loading the `describeSsf` catalogs and nothing else.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'description_pages',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.DP_ROOT;
  const OUT = process.env.DP_OUT;
  const http = require('http');
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function unescape(raw) {
    return raw.replace(/&quot;/g, '"').replace(/&#39;/g, "'")
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  }

  function stateOf(text) {
    const m = /<html[^>]* data-sts-state="([^"]*)"/.exec(String(text || ''));
    return m ? JSON.parse(unescape(m[1])) : null;
  }

  function isShell(r, base) {
    return r.text.indexOf('<script src="' + base + '/description.js" ' +
                          'defer></script>') > 0 &&
      r.text.indexOf('<link rel="stylesheet" href="/web/card.css">') > 0 &&
      r.text.indexOf('<noscript>') > 0 && !/<table/.test(r.text);
  }

  function policyOk(r) {
    const csp = String(r.headers['content-security-policy'] || '');
    return /frame-ancestors 'none'/.test(csp) &&
      /script-src 'self'(;|$)/.test(csp) && !/unsafe-inline/.test(csp);
  }

  function headersOk(r) {
    return r.status === 200 &&
      /no-store/.test(String(r.headers['cache-control'])) &&
      /^text\/html/.test(String(r.headers['content-type'])) &&
      r.headers.location === undefined;
  }

  function translator(namespaces, chain) {
    const messages = require(ROOT_DIR + '/common/web_messages');
    const catalogs = {};
    chain.forEach(function (tag) {
      const flat = {};
      namespaces.forEach(function (ns) {
        const own = JSON.parse(fs.readFileSync(ROOT_DIR + '/common/locales/' +
          ns + '/' + tag + '.json', 'utf8'));
        Object.keys(own).forEach(function (key) {
          flat[ns + '.' + key] = own[key];
        });
      });
      catalogs[tag] = flat;
    });
    return messages.WebTranslator.fromData({ catalogs: catalogs,
      negotiated: { locale: chain[0], chain: chain, catalog: chain[0],
                    direction: 'ltr', matched: true } });
  }

  const FAMILIES = [
    { base: '/saml2', kind: 'saml2', ns: 'describeSaml2', hadJson: false },
    { base: '/saml11', kind: 'saml11', ns: 'describeSaml11', hadJson: false },
    { base: '/xacml', kind: 'xacml', ns: 'describeXacml', hadJson: true },
    { base: '/ssf', kind: 'ssf', ns: 'describeSsf', hadJson: true },
    { base: '/scim', kind: 'scim', ns: 'describeScim', hadJson: true },
    { base: '/spiffe', kind: 'spiffe', ns: 'describeSpiffe', hadJson: true }
  ];

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const get = function (p, headers) {
      return screen.call({ port: port, jar: {}, method: 'GET', path: p,
                           headers: headers || {} });
    };
    const json = function (r) {
      try {
        return JSON.parse(r.text);
      } catch (e) {
        return null;
      }
    };

    // --- 1. the XACML gate holds for the page and its script ---------------
    config.setOverride('xacml.enforceAccess', 'true');
    let page = await get('/xacml');
    let script = await get('/xacml/description.js');
    note(page.status === 403 && script.status === 403 &&
         stateOf(page.text) === null &&
         !/javascript/.test(String(script.headers['content-type'])),
         '1a. with xacml.enforceAccess on, GET /xacml and its script are ' +
         'both refused to a caller presenting no certificate',
         page.status + ' ' + script.status + ' ' +
         script.text.slice(0, 200));
    page = await get('/xacml?format=json');
    note(page.status === 403, '1b. and so is the JSON form', page.status);
    config.setOverride('xacml.enforceAccess', 'false');
    script = await get('/xacml/description.js');
    note(script.status === 200 &&
         /javascript/.test(String(script.headers['content-type'])),
         '1c. with it off the script answers, as the page does',
         script.status);

    // --- 2-4. each family's shell, JSON form and script --------------------
    const views = {};
    for (const f of FAMILIES) {
      const r = await get(f.base, { accept: 'text/html,*/*;q=0.8' });
      const state = stateOf(r.text);
      views[f.kind] = state && state.view;
      note(headersOk(r) && isShell(r, f.base) && policyOk(r) && state &&
           state.view && state.view.kind === f.kind,
           '2. GET ' + f.base + ': 200, no-store, the shell loading ' +
           f.base + '/description.js, under a policy that runs it and ' +
           'keeps frame-ancestors, carrying a ' + f.kind + ' view',
           r.status + ' ' + String(r.headers['content-security-policy']) +
           ' ' + r.text.slice(0, 300));
      const byQuery = await get(f.base + '?format=json');
      const doc = json(byQuery);
      const expected = f.hadJson ? state && state.view.document
                                 : state && state.view;
      note(byQuery.status === 200 && doc &&
           /no-store/.test(String(byQuery.headers['cache-control'])) &&
           /json/.test(String(byQuery.headers['content-type'])) &&
           JSON.stringify(Object.keys(doc).sort()) ===
             JSON.stringify(Object.keys(expected || {}).sort()),
           '3a. ' + f.base + '?format=json answers ' +
           (f.hadJson ? 'the description document the shell carries'
                      : 'the view the shell carries'),
           byQuery.status + ' ' + byQuery.text.slice(0, 200));
      const byAccept = await get(f.base, { accept: 'application/json' });
      note(byAccept.status === 200 && json(byAccept) &&
           JSON.stringify(Object.keys(json(byAccept)).sort()) ===
             JSON.stringify(Object.keys(doc || {}).sort()) &&
           stateOf(byAccept.text) === null,
           '3b. ' + f.base + ' with Accept: application/json answers the ' +
           'same JSON', byAccept.status + ' ' + byAccept.text.slice(0, 200));
      const star = await get(f.base, { accept: '*/*' });
      const asked = await get(f.base + '?format=html',
                              { accept: 'application/json' });
      note(isShell(star, f.base) && isShell(asked, f.base),
           '3c. ' + f.base + ' with Accept */*, and with ?format=html over ' +
           'an Accept of JSON, answers the shell', star.status + ' ' +
           asked.status);
      const js = await get(f.base + '/description.js');
      note(js.status === 200 &&
           /javascript/.test(String(js.headers['content-type'])) &&
           js.text.length > 0,
           '4. ' + f.base + '/description.js is served as a script',
           js.status + ' ' + String(js.headers['content-type']));
    }
    if (views.ssf && views.scim && views.spiffe && views.xacml) {
      note(typeof views.scim.verifiesCredentials === 'boolean' &&
           views.scim.base === '/scim/v2' &&
           typeof views.spiffe.authority.ready === 'boolean' &&
           typeof views.spiffe.https === 'boolean' &&
           typeof views.xacml.trustAnchorDoor === 'string' &&
           views.xacml.trustAnchorDoor.length > 0 &&
           views.ssf.deliveryNames && typeof views.ssf.deliveryNames ===
             'object',
           '2b. each view carries the facts its page drew beside the ' +
           'document', JSON.stringify({ scim: views.scim.base,
             spiffe: views.spiffe.authority,
             xacml: views.xacml.trustAnchorDoor }));
    }

    // --- 5. the demonstrations, by mode (#585) -----------------------------
    const devSaml2 = json(await get('/saml2?format=json'));
    const devSaml11 = json(await get('/saml11?format=json'));
    const devXacml = json(await get('/xacml?format=json'));
    note(devSaml2 && !('sp' in devSaml2.paths) && devSaml11 &&
         !('rp' in devSaml11.paths) && devXacml && devXacml.pep,
         '5a. development: the embedded PEP is listed, and no mock SP or ' +
         'RP (#592)', JSON.stringify([devSaml2 && devSaml2.paths,
                                      devSaml11 && devSaml11.paths]));
    config.setOverride('global.mode', 'product');
    const prodSaml2 = json(await get('/saml2?format=json'));
    const prodSaml11 = json(await get('/saml11?format=json'));
    const prodXacml = json(await get('/xacml?format=json'));
    const prodShell = stateOf((await get('/saml2')).text);
    config.clearOverride('global.mode');
    note(prodSaml2 && !('sp' in prodSaml2.paths) && prodSaml11 &&
         !('rp' in prodSaml11.paths) && prodXacml &&
         prodXacml.pep === null &&
         !(prodXacml.endpoints || []).some(function (row) {
           return row.path === '/xacml/protected';
         }) && prodShell && !('sp' in prodShell.view.paths),
         '5b. product: none of them is listed, in the JSON or the shell',
         JSON.stringify([prodSaml2 && prodSaml2.paths,
                         prodSaml11 && prodSaml11.paths,
                         prodXacml && prodXacml.pep]));

    // --- 6. the protocol endpoints beneath are unchanged ---------------------
    for (const p of ['/saml2/ars', '/saml11/responder']) {
      const r = await get(p);
      note(r.status === 200 && stateOf(r.text) === null &&
           /<table|<h1>/.test(r.text) &&
           /script-src 'none'/.test(String(
             r.headers['content-security-policy'])),
           '6a. GET ' + p + ' is a specification\'s endpoint and is still ' +
           'drawn by the server under script-src \'none\'',
           r.status + ' ' + String(r.headers['content-security-policy']));
    }
    const metadata = await get('/saml2/metadata');
    const ssfConfig = await get('/.well-known/ssf-configuration');
    const spc = await get('/scim/v2/ServiceProviderConfig');
    note(metadata.status === 200 &&
         /xml/.test(String(metadata.headers['content-type'])) &&
         /EntityDescriptor/.test(metadata.text) &&
         json(ssfConfig) && json(ssfConfig).issuer &&
         stateOf(spc.text) === null && !/description\.js/.test(spc.text),
         '6b. the SAML metadata, the SSF configuration and SCIM discovery ' +
         'answer as they did, with no shell',
         metadata.status + ' ' + ssfConfig.status + ' ' + spc.status);

    // --- 7. the renderers ---------------------------------------------------
    const pages = require(ROOT_DIR + '/common/web_description_pages');
    for (const f of FAMILIES) {
      if (!views[f.kind]) {
        continue;
      }
      const fr = translator([f.ns], ['fr', 'en']);
      const drawn = pages.render(f.base, views[f.kind], { t: fr });
      note(drawn.length > 500 && /<h1>/.test(drawn) &&
           drawn.indexOf('<script') < 0 &&
           !/[]/.test(drawn) &&
           !new RegExp(f.ns + '\\.').test(drawn),
           '7a. the ' + f.kind + ' renderer draws the real view in French, ' +
           'every key found', drawn.slice(0, 300));
    }
    const hostile = pages.render('/saml2', Object.assign({}, views.saml2, {
      idpEntityId: '<script>alert(1)</script>' }),
    { t: translator(['describeSaml2'], ['en']) });
    note(hostile.indexOf('<script>') < 0 &&
         hostile.indexOf('&lt;script&gt;alert(1)&lt;/script&gt;') > 0,
         '7b. a value from the view is escaped', hostile.slice(0, 300));
    let slotted = [];
    fs.readdirSync(ROOT_DIR + '/common/locales').filter(function (ns) {
      return /^describe/.test(ns);
    }).forEach(function (ns) {
      fs.readdirSync(ROOT_DIR + '/common/locales/' + ns)
        .forEach(function (file) {
          const text = fs.readFileSync(ROOT_DIR + '/common/locales/' + ns +
                                       '/' + file, 'utf8');
          if (/[]/.test(text)) {
            slotted.push(ns + '/' + file);
          }
        });
    });
    note(slotted.length === 0, '7c. no catalog message carries the ' +
         'slot characters rich() replaces', slotted.join(', '));

    // --- 8. the runtime -----------------------------------------------------
    const r = await get('/ssf');
    const attrs = {};
    const tag = /<html([^>]*)>/.exec(r.text)[1];
    tag.replace(/ ([a-z-]+)="([^"]*)"/g, function (all, n, v) {
      attrs[n] = unescape(v);
      return all;
    });
    const asked = [];
    const env = {
      location: { pathname: '/ssf', search: '', hash: '',
                  href: 'https://sts.example/ssf',
                  origin: 'https://sts.example',
                  assign: function () {
                    return undefined;
                  } },
      history: { pushState: function () {
        return undefined;
      }, replaceState: function () {
        return undefined;
      } },
      document: {
        title: '', body: { innerHTML: '' },
        documentElement: {
          getAttribute: function (n) {
            return n in attrs ? attrs[n] : null;
          },
          setAttribute: function (n, v) {
            attrs[n] = v;
          }
        },
        addEventListener: function () {
          return undefined;
        }
      },
      navigator: { languages: ['fr', 'en'] },
      fetch: function (url, init) {
        const u = new URL(url);
        asked.push(u.pathname);
        return fetch('http://127.0.0.1:' + port + u.pathname + u.search,
                     init);
      }
    };
    const Surface = require(ROOT_DIR + '/common/web_description_surface');
    const surface = new Surface(env);
    await surface.route();
    const drawn = env.document.body.innerHTML;
    const frTitle = JSON.parse(fs.readFileSync(ROOT_DIR +
      '/common/locales/describeSsf/fr.json', 'utf8')).title;
    note(/^<div class="card wide describe">/.test(drawn) &&
         drawn.indexOf('<h1>') > 0 &&
         env.document.title.indexOf(frTitle) === 0 &&
         asked.every(function (p) {
           return /^\/web\/locales\//.test(p) &&
             !/\/(describeScim|describeSaml2|describeSpiffe)\//.test(p);
         }) && asked.some(function (p) {
           return /^\/web\/locales\/describeSsf\//.test(p);
         }),
         '8. the runtime draws /ssf from the shell\'s state, in the ' +
         'browser\'s language, loading its own catalogs and nothing else',
         JSON.stringify(asked) + ' ' + env.document.title + ' ' +
         drawn.slice(0, 300));

    config.clearOverride('xacml.enforceAccess');
    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

/**
 * Runs the child and reports its findings.
 *
 * @param {object} t - the runner's assertion helper
 * @returns {Promise<void>} when done
 */
async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'dp-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  DP_ROOT: ROOT, DP_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'description_pages',
  describe: 'the six protocol families\' description pages are the ' +
            'description surface\'s shell, with their JSON form by query or ' +
            'Accept, /xacml\'s gate over its script, no demonstration in ' +
            'product, and the protocol endpoints beneath unchanged (#584)',
  run: run
};
