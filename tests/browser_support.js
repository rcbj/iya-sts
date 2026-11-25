// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: browser_support.js
//
// ===========================================================================
// EVERY PAGE SAYS WHAT THIS BROWSER LACKS, IN THE READER'S LANGUAGE (#2220,
// ASVS 5.0.0 3.1.1).
//
// `docs/v1.2.0/browser-requirements.md` listed nine gaps; each is closed and
// each is held here, in process with stand-ins for a browser, and over HTTP
// in a child with the whole stack:
//
//   A. THE BROWSER CHECK (`common/web_browser_check.ts`): `missing()` names
//      fetch, Promise, TextEncoder, TextDecoder, URL, URLSearchParams,
//      history.pushState and ECMAScript 2022 (Object.hasOwn,
//      Array.prototype.at) and nothing for a whole browser; `run()` shows
//      the notice, names what is missing, marks `<html>`; a SyntaxError
//      before the document loaded shows it too, and one after does not.
//   B. ITS BUNDLE IS ECMASCRIPT 5: the built `common/browser-check.js` (or,
//      in a tree never built, the same esbuild run `build-typescript.sh`
//      makes) parses with acorn at `ecmaVersion: 5`, carries the SPDX
//      lines, and run in a sandbox with no `fetch` shows the notice itself.
//   C. THE SHELL (`common/shell_document.ts`): the check script before the
//      surface's, both `defer`, the notice hidden after the opening markup,
//      the link to what this service needs from a browser in the notice and
//      in the `<noscript>`; none of it with `browserCheck: false` or a
//      refusal; the policy still `script-src 'self'`. Every entry starts
//      its runtime only where `WebPage.browserFellShort()` is false.
//   D. SESSION STORAGE: `sessionStorageMissing()` for none, a refusing
//      `setItem`, and a working one; `storageOf()` for a window whose
//      property throws; `noStorageWords()` in German; each of the three
//      runtimes asks it in `start()` beside `webCryptoMissing()`.
//   E. WEBAUTHN: `WebWebAuthn.missing()`; the portal's ceremony without
//      `PublicKeyCredential` says so in German beside it, hides its button
//      and sends nothing; the console's passkey upgrade without WebAuthn
//      reports it and calls no API.
//   F. THE SIGN-IN WINDOW BLOCKED: the console's bar says
//      `consoleRuntime.reauth.popupBlocked`, in every base catalog.
//   G. THE PAGE'S CHOICES: `WebPageState.save()` and `take()` round trip
//      a checkbox and a select, keep nothing typed, refuse another person;
//      the portal's and the reports application's `leaveForStepUp()` save
//      before they leave.
//   H. COPY: without `navigator.clipboard` `execCommand('copy')` is used;
//      where that fails too, the portal's button says so in German.
//   I. THE WORDS: the `browser` namespace in every base catalog, loaded by
//      every `WebI18n` and given with every application's catalogData();
//      the link's anchor is a heading of the browser requirements page.
//   J. OVER HTTP, `Accept-Language: de`: /admin, /portal, /report, / and
//      /authn/login answer a shell whose `<noscript>` and hidden notice are
//      German and marked `lang="de"`, and English with no `lang` for none;
//      `/web/browser-check.js` is served as a script.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const childProcess = require('child_process');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'browser_support',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const LOCALES = path.join(ROOT, 'common', 'locales');

// The base catalogs: every catalog that is not a regional overlay.
function baseTags() {
  log.debug("Entering baseTags().");
  const index = JSON.parse(fs.readFileSync(path.join(LOCALES,
    'catalogs.json'), 'utf8'));
  const out = index.catalogs.filter(function (one) {
    return !one.base;
  }).map(function (one) {
    return one.tag;
  });
  log.debug("Leaving baseTags(). " + out.length);
  return out;
}

// One namespace's messages in one catalog.
function catalog(ns, tag) {
  log.debug("Entering catalog(). " + ns + '/' + tag);
  const file = path.join(LOCALES, ns, tag + '.json');
  const out = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8'))
                                  : {};
  log.debug("Leaving catalog().");
  return out;
}

// A translator over the `browser` and `consoleRuntime` catalogs in `tag`,
// falling back to English, as a runtime holds one.
function translatorFor(tag) {
  log.debug("Entering translatorFor(). " + tag);
  const messages = require('../common/web_messages');
  const catalogs = {};
  [tag, 'en'].forEach(function (one) {
    const flat = {};
    ['browser', 'consoleRuntime', 'portal'].forEach(function (ns) {
      const own = catalog(ns, one);
      Object.keys(own).forEach(function (key) {
        flat[ns + '.' + key] = own[key];
      });
    });
    catalogs[one] = flat;
  });
  const out = messages.WebTranslator.fromData({ catalogs: catalogs,
    negotiated: { locale: tag, chain: tag === 'en' ? ['en'] : [tag, 'en'],
                  catalog: tag, direction: 'ltr', matched: true } });
  log.debug("Leaving translatorFor().");
  return out;
}

// A whole browser's globals, as the check reads them.
function wholeWindow() {
  log.debug("Entering wholeWindow().");
  const out = {
    fetch: function () {
      return null;
    },
    Promise: Promise, TextEncoder: TextEncoder, TextDecoder: TextDecoder,
    URL: URL, URLSearchParams: URLSearchParams, Object: Object,
    Array: Array,
    history: { pushState: function () {
      return undefined;
    } }
  };
  log.debug("Leaving wholeWindow().");
  return out;
}

// A document holding the shell's notice, as the check finds it.
function noticeDocument() {
  log.debug("Entering noticeDocument().");
  const attrs = {};
  const notice = { hidden: true, removeAttribute: function (name) {
    if (name === 'hidden') {
      notice.hidden = false;
    }
  } };
  const named = { textContent: '' };
  const listeners = {};
  const doc = {
    attrs: attrs, notice: notice, named: named, listeners: listeners,
    documentElement: {
      setAttribute: function (k, v) {
        attrs[k] = v;
      },
      getAttribute: function (k) {
        return k in attrs ? attrs[k] : null;
      }
    },
    getElementById: function (id) {
      return id === 'sts-browser-check' ? notice
        : (id === 'sts-browser-missing' ? named : null);
    },
    addEventListener: function (type, fn) {
      listeners[type] = fn;
    }
  };
  log.debug("Leaving noticeDocument().");
  return doc;
}

// A window that records its `error` listener.
function listeningWindow(base) {
  log.debug("Entering listeningWindow().");
  const w = Object.assign(base, { handlers: {} });
  w.addEventListener = function (type, fn) {
    w.handlers[type] = fn;
  };
  w.removeEventListener = function (type, fn) {
    if (w.handlers[type] === fn) {
      delete w.handlers[type];
    }
  };
  log.debug("Leaving listeningWindow().");
  return w;
}

// --- A. the browser check --------------------------------------------------
function checkDetection(t) {
  log.debug("Entering checkDetection().");
  const BrowserCheck = require('../common/web_browser_check');
  t.equal(JSON.stringify(BrowserCheck.missing(wholeWindow())), '[]',
          'A1. a whole browser lacks nothing');
  const cases = [['fetch', 'fetch'], ['Promise', 'Promise'],
                 ['TextEncoder', 'TextEncoder'],
                 ['TextDecoder', 'TextDecoder'], ['URL', 'URL'],
                 ['URLSearchParams', 'URLSearchParams']];
  const wrong = [];
  cases.forEach(function (one) {
    const w = wholeWindow();
    delete w[one[0]];
    const said = BrowserCheck.missing(w);
    if (JSON.stringify(said) !== JSON.stringify([one[1]])) {
      wrong.push(one[0] + ' -> ' + JSON.stringify(said));
    }
  });
  const noHistory = wholeWindow();
  noHistory.history = {};
  if (BrowserCheck.missing(noHistory).join() !== 'history.pushState') {
    wrong.push('history');
  }
  const es2021 = wholeWindow();
  es2021.Object = { };
  if (BrowserCheck.missing(es2021).join() !== 'ECMAScript 2022') {
    wrong.push('Object.hasOwn');
  }
  const noAt = wholeWindow();
  noAt.Array = { prototype: {} };
  if (BrowserCheck.missing(noAt).join() !== 'ECMAScript 2022') {
    wrong.push('Array.prototype.at');
  }
  t.check(wrong.length === 0, 'A2. each of fetch, Promise, TextEncoder, ' +
          'TextDecoder, URL, URLSearchParams, history.pushState and ' +
          'ECMAScript 2022 (Object.hasOwn, Array.prototype.at) is named ' +
          'alone when it alone is missing', wrong.join('; '));

  const old = wholeWindow();
  delete old.fetch;
  delete old.URL;
  const doc = noticeDocument();
  const said = BrowserCheck.run(listeningWindow(old), doc);
  t.check(said.join() === 'fetch,URL' && doc.notice.hidden === false &&
          doc.named.textContent === ' (fetch, URL)' &&
          doc.attrs['data-sts-unsupported'] === '1',
          'A3. run() shows the notice, names what is missing in it and ' +
          'marks <html>', JSON.stringify({ said: said, doc: doc.attrs,
                                           named: doc.named.textContent }));

  const w = listeningWindow(wholeWindow());
  const fine = noticeDocument();
  BrowserCheck.run(w, fine);
  t.check(fine.notice.hidden === true && typeof w.handlers.error ===
          'function' && !fine.attrs['data-sts-unsupported'],
          'A4. a whole browser sees no notice, and the check listens for ' +
          'a script that does not parse');
  w.handlers.error({ message: 'Uncaught SyntaxError: Unexpected token' });
  t.check(fine.notice.hidden === false &&
          fine.attrs['data-sts-unsupported'] === '1',
          'A5. a SyntaxError before the document loaded shows the notice');
  const w2 = listeningWindow(wholeWindow());
  const later = noticeDocument();
  BrowserCheck.run(w2, later);
  later.listeners.DOMContentLoaded();
  t.check(!w2.handlers.error && later.notice.hidden === true,
          'A6. once the document has loaded the check stops listening: a ' +
          'later SyntaxError is the page\'s own');
  log.debug("Leaving checkDetection().");
}

// --- B. the bundle is ECMAScript 5 -----------------------------------------
function checkBundle(t) {
  log.debug("Entering checkBundle().");
  let file = path.join(ROOT, 'common', 'browser-check.js');
  let source = 'built';
  if (!fs.existsSync(file)) {
    // A tree never built (a checkout): the same esbuild run the image
    // build makes, into a scratch file.
    source = 'esbuild here';
    file = path.join(os.tmpdir(), 'browser-check-' + process.pid + '.js');
    childProcess.execFileSync(path.join(ROOT, 'tests', 'node_modules',
      '.bin', 'esbuild'), [path.join(ROOT, 'common', 'web_browser_check.ts'),
      '--bundle', '--platform=browser', '--format=iife', '--target=es5',
      '--charset=ascii', '--legal-comments=none', '--minify',
      '--log-level=warning',
      '--banner:js=// SPDX-FileCopyrightText: 2026 Iya CyberSecurity ' +
      'Solutions, LLC\n// SPDX-License-Identifier: BUSL-1.1',
      '--outfile=' + file], { cwd: ROOT });
  }
  const text = fs.readFileSync(file, 'utf8');
  let parsed = '';
  try {
    require(path.join(ROOT, 'tests', 'node_modules', 'acorn'))
      .parse(text, { ecmaVersion: 5 });
    parsed = 'ok';
  } catch (e) {
    log.debug("Caught in checkBundle(): " + ((e && e.message) || e));
    parsed = String((e && e.message) || e);
  }
  t.check(parsed === 'ok', 'B1. the browser check (' + source + ') parses ' +
          'as ECMAScript 5', parsed);
  t.check(/^\/\/ SPDX-FileCopyrightText: /.test(text) &&
          /SPDX-License-Identifier: BUSL-1\.1/.test(text),
          'B2. it opens with the two SPDX lines');
  const old = wholeWindow();
  delete old.fetch;
  const doc = noticeDocument();
  const sandbox = listeningWindow(old);
  vm.runInNewContext(text, { window: sandbox, document: doc });
  t.check(doc.notice.hidden === false &&
          doc.named.textContent.indexOf('fetch') >= 0,
          'B3. run in a browser with no fetch, the bundle shows the notice ' +
          'by itself', doc.named.textContent);
  const builder = fs.readFileSync(path.join(ROOT, 'build-typescript.sh'),
                                  'utf8');
  t.check(/common\/web_browser_check\.ts --bundle[\s\S]{0,120}--target=es5/
            .test(builder) &&
          builder.indexOf('--outfile=common/browser-check.js') > 0,
          'B4. build-typescript.sh bundles it for ECMAScript 5');
  if (source !== 'built') {
    fs.unlinkSync(file);
  }
  log.debug("Leaving checkBundle().");
}

// --- C. the shell --------------------------------------------------------
function checkShell(t) {
  log.debug("Entering checkShell().");
  const ShellDocument = require('../common/shell_document');
  const i18n = require('../common/i18n');
  const spec = function (extra) {
    return Object.assign({ title: 'T', stylesheets: ['/x.css'],
      script: '/x.js', open: '<div class="card">', close: '</div>',
      noscript: '<p>N</p>', loading: '<p>L</p>', footer: false }, extra || {});
  };
  const de = i18n.translator(['de'], 'en');
  const html = ShellDocument.document(spec({ translator: de }));
  const check = html.indexOf('<script src="/web/browser-check.js" defer>');
  const own = html.indexOf('<script src="/x.js" defer>');
  t.check(check > 0 && own > check,
          'C1. the shell runs /web/browser-check.js, deferred, before its ' +
          'own script');
  const notice = /<div class="card"><div id="sts-browser-check" role="alert" hidden lang="de"><div class="err"><p><strong>([^<]+)<\/strong>/
    .exec(html);
  const words = catalog('browser', 'de');
  t.check(!!notice && notice[1] === words['unsupported.title'] &&
          html.indexOf('<span id="sts-browser-missing"></span>') > 0,
          'C2. the notice is drawn hidden after the opening markup, in the ' +
          'translator\'s language and marked lang="de"', notice && notice[1]);
  const link = 'href="https://rcbj.github.io/iya-sts/v1.2.0/' +
    'browser-requirements.html#for-people-using-this-service" ' +
    'rel="noopener noreferrer">' + words.requirements + '</a>';
  t.check(/<noscript lang="de"><p>N<\/p><p class="sts-browser-support">/
            .test(html) && html.split(link).length === 3,
          'C3. the <noscript> is marked lang="de" and both it and the ' +
          'notice link what this service needs from a browser');
  const en = ShellDocument.document(spec({ translator: i18n.translator(['en'],
                                                                       'en') }));
  t.check(en.indexOf('<noscript><p>N</p>') > 0 &&
          en.indexOf('lang="de"') < 0 &&
          en.indexOf('This browser cannot open this page') > 0,
          'C4. in English nothing is marked, and the words are English');
  const off = ShellDocument.document(spec({ browserCheck: false }));
  t.check(off.indexOf('browser-check') < 0 &&
          off.indexOf('sts-browser-support') < 0 &&
          off.indexOf('<noscript><p>N</p></noscript>') > 0,
          'C5. browserCheck: false draws neither the check, the notice nor ' +
          'the link (a specification\'s response)');
  const refused = ShellDocument.document(spec({ refusal: '<p>R</p>' }));
  t.check(refused.indexOf('<script') < 0 &&
          refused.indexOf('sts-browser-check') < 0,
          'C6. a refusal draws no script at all, the check included');
  const policy = ShellDocument.policy({ contentSecurityPolicy: function (d) {
    return d['script-src'];
  } });
  t.equal(policy, "'self'", 'C7. the shell\'s script-src is still \'self\'');
  const spnego = fs.readFileSync(path.join(ROOT, 'kerberos',
                                           'spnego_authn.ts'), 'utf8');
  t.check(/browserCheck: false/.test(spnego),
          'C8. the RFC 4559 exchange\'s shell turns the check off');
  const entries = ['admin-ui/web_console.ts', 'portal/web_portal.ts',
    'report/web_report.ts', 'home/web_home.ts', 'authn/web_authn.ts',
    'gnap/web_gnap_interact.ts', 'logout/web_signout.ts',
    'federation/web_federation_surface.ts',
    'common/web_description_surface.ts'];
  const unguarded = entries.filter(function (rel) {
    const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    return !/typeof document !== 'undefined' &&\s*!\w+\.browserFellShort\(document\)\) \{/
      .test(text);
  });
  t.check(unguarded.length === 0, 'C9. every surface\'s entry starts its ' +
          'runtime only where the check did not mark the document',
          unguarded.join(', '));
  const WebPage = require('../common/web_page');
  const marked = noticeDocument();
  const before = WebPage.browserFellShort(marked);
  marked.documentElement.setAttribute('data-sts-unsupported', '1');
  t.check(!before && WebPage.browserFellShort(marked) &&
          !WebPage.browserFellShort(null),
          'C10. WebPage.browserFellShort() reads the mark');
  log.debug("Leaving checkShell().");
}

// A browser's objects, enough for `WebI18n` over the catalogs on disk.
function i18nEnv(languages) {
  log.debug("Entering i18nEnv().");
  const env = {
    location: { origin: 'https://browser.test', pathname: '/portal',
                search: '', hash: '' },
    navigator: { languages: languages, language: languages[0] },
    document: { documentElement: {
      getAttribute: function () {
        return '';
      },
      setAttribute: function () {
        return undefined;
      } } },
    fetch: function (url) {
      const m = /\/web\/locales\/(.+?)(\?.*)?$/.exec(String(url));
      const file = m ? path.join(LOCALES, decodeURIComponent(m[1])) : '';
      if (!file || !fs.existsSync(file)) {
        return Promise.resolve({ status: 404, json: function () {
          return Promise.resolve(null);
        } });
      }
      const body = JSON.parse(fs.readFileSync(file, 'utf8'));
      return Promise.resolve({ status: 200, json: function () {
        return Promise.resolve(body);
      } });
    }
  };
  log.debug("Leaving i18nEnv().");
  return env;
}

// --- D. session storage ----------------------------------------------------
async function checkStorage(t) {
  log.debug("Entering checkStorage().");
  const SpaClient = require('../common/web_spa_client');
  const held = {};
  const working = {
    setItem: function (k, v) {
      held[k] = String(v);
    },
    getItem: function (k) {
      return k in held ? held[k] : null;
    },
    removeItem: function (k) {
      delete held[k];
    }
  };
  const refusing = Object.assign({}, working, { setItem: function () {
    throw new Error('SecurityError');
  } });
  t.check(SpaClient.sessionStorageMissing({}) &&
          SpaClient.sessionStorageMissing({ sessionStorage: null }) &&
          SpaClient.sessionStorageMissing({ sessionStorage: refusing }) &&
          !SpaClient.sessionStorageMissing({ sessionStorage: working }) &&
          Object.keys(held).length === 0,
          'D1. no storage and a refusing setItem are missing; a working one ' +
          'is not, and the probe is removed');
  const blocked = {};
  Object.defineProperty(blocked, 'sessionStorage', { get: function () {
    throw new Error('SecurityError: blocked');
  } });
  t.check(SpaClient.storageOf(blocked) === null &&
          SpaClient.storageOf({ sessionStorage: working }) === working,
          'D2. storageOf() answers null for a window whose property throws');
  const client = new SpaClient(i18nEnv(['de']), '', {
    clientId: 'browser-test', scope: 'openid', elsewhere: {} });
  const words = await client.noStorageWords('portal');
  const de = catalog('browser', 'de');
  t.check(words.title === de['noStorage.title'] &&
          words.text === de['noStorage.text'],
          'D3. a German browser is told in German', words.title);
  const link = SpaClient.browserSupportHtml(words.t);
  t.check(link.indexOf('#for-people-using-this-service') > 0 &&
          link.indexOf(de.requirements) > 0,
          'D4. the problem carries the link, in German');
  const starts = [['admin-ui/web_runtime.ts', 'consoleRuntime'],
                  ['portal/web_portal_runtime.ts', 'portal'],
                  ['report/web_report_pages.ts', '']];
  const wrong = starts.filter(function (one) {
    const text = fs.readFileSync(path.join(ROOT, one[0]), 'utf8');
    const start = text.indexOf('async start(): Promise<void> {');
    const body = text.slice(start, start + 1600);
    const crypto = body.indexOf('webCryptoMissing(this.env)');
    const storage = body.indexOf('sessionStorageMissing(this.env)');
    const wired = body.indexOf('addEventListener(');
    return start < 0 || crypto < 0 || storage < crypto || wired < storage;
  }).map(function (one) {
    return one[0];
  });
  t.check(wrong.length === 0, 'D5. the console, the portal and the reports ' +
          'application ask for session storage at start, after WebCrypto ' +
          'and before anything is wired', wrong.join(', '));
  const entries = ['admin-ui/web_console.ts', 'portal/web_portal.ts',
                   'report/web_report.ts'].filter(function (rel) {
    return !/sessionStorage: \w+\.storageOf\(window\)/.test(
      fs.readFileSync(path.join(ROOT, rel), 'utf8'));
  });
  t.check(entries.length === 0, 'D6. each entry reads the storage through ' +
          'storageOf(), so a refused property cannot throw first',
          entries.join(', '));
  log.debug("Leaving checkStorage().");
}

// --- E. WebAuthn ----------------------------------------------------------
async function checkWebAuthn(t) {
  log.debug("Entering checkWebAuthn().");
  const WebWebAuthn = require('../common/web_webauthn');
  const creds = { create: function () {
    return null;
  }, get: function () {
    return null;
  } };
  const PKC = function () {
    return undefined;
  };
  t.check(WebWebAuthn.missing({}, { PublicKeyCredential: PKC }) &&
          WebWebAuthn.missing({ credentials: creds }, {}) &&
          WebWebAuthn.missing({ credentials: { create: creds.create } },
                              { PublicKeyCredential: PKC }, 'get') &&
          !WebWebAuthn.missing({ credentials: { create: creds.create } },
                               { PublicKeyCredential: PKC }, 'create') &&
          !WebWebAuthn.missing({ credentials: creds },
                               { PublicKeyCredential: PKC }),
          'E1. WebWebAuthn.missing() asks for PublicKeyCredential and the ' +
          'call the ceremony makes');

  const PortalWebAuthn = require('../portal/web_portal_webauthn');
  const inserted = [];
  const listeners = {};
  const go = { hidden: false, addEventListener: function (type, fn) {
    listeners[type] = fn;
  } };
  const data = {
    getAttribute: function (name) {
      return name === 'data-mode' ? 'create' : '';
    },
    insertAdjacentHTML: function (where, html) {
      inserted.push(where + ' ' + html);
    }
  };
  const els = { 'wa-data': data, 'wa-go': go };
  const doc = { getElementById: function (id) {
    return els[id] || null;
  } };
  const submitted = [];
  PortalWebAuthn.wire(doc, { navigator: {} }, function (form) {
    submitted.push(form);
  }, null, translatorFor('de'));
  listeners.click({ preventDefault: function () {
    return undefined;
  } });
  const de = catalog('browser', 'de');
  t.check(inserted.length === 1 &&
          inserted[0].indexOf('beforeend <div class="err" id="wa-unable" ' +
                              'role="alert">') === 0 &&
          inserted[0].indexOf(de.noPasskeys.split(':')[0]) > 0 &&
          go.hidden === true && submitted.length === 0,
          'E2. the portal\'s ceremony without WebAuthn says so in German ' +
          'beside it, hides its button, and sends nothing',
          inserted.join(' | '));

  const ConsoleRuntime = require('../admin-ui/web_runtime');
  const went = [];
  let called = 0;
  const fake = {
    env: { navigator: {}, window: {} },
    t: translatorFor('de'),
    here: function () {
      return '/admin/users/view?user=ann';
    },
    go: function (to) {
      went.push(to);
      return Promise.resolve();
    },
    apiJson: function () {
      called++;
      return Promise.resolve(null);
    }
  };
  await ConsoleRuntime.prototype.adminPasskeyUpgrade.call(fake,
    { user: 'ann', credentialId: 'x' });
  t.check(called === 0 && went.length === 1 &&
          decodeURIComponent(went[0]).indexOf('error=' + de.noPasskeys) > 0,
          'E3. the console\'s passkey upgrade without WebAuthn reports it ' +
          'in the reader\'s language and begins nothing', went.join(' '));
  log.debug("Leaving checkWebAuthn().");
}

// --- F. the sign-in window blocked -----------------------------------------
function checkPopup(t) {
  log.debug("Entering checkPopup().");
  const absent = baseTags().filter(function (tag) {
    return !catalog('consoleRuntime', tag)['reauth.popupBlocked'];
  });
  t.check(absent.length === 0, 'F1. consoleRuntime.reauth.popupBlocked is ' +
          'in every base catalog', absent.join(', '));
  const ConsoleRuntime = require('../admin-ui/web_runtime');
  const drawn = [];
  const fake = {
    reauth: { url: 'https://x.test/oauth2/authorize' },
    env: { window: { open: function () {
      return null;
    } } },
    t: translatorFor('de'),
    drawReauthBar: function (message) {
      drawn.push(message);
    }
  };
  ConsoleRuntime.prototype.openReauthPopup.call(fake);
  t.equal(drawn[0], catalog('consoleRuntime', 'de')['reauth.popupBlocked'],
          'F2. a blocked sign-in window is said in German');
  log.debug("Leaving checkPopup().");
}

// A form of a checkbox, a select and a text field.
function formOf(action) {
  log.debug("Entering formOf().");
  const box = { name: 'notify', type: 'checkbox', value: 'yes',
                checked: true };
  const select = { name: 'kind', type: 'select-one', value: 'b' };
  const text = { name: 'mail', type: 'text', value: 'ann@example.test' };
  const out = { box: box, select: select, text: text, elements: [box, select,
    text], getAttribute: function (name) {
    return name === 'action' ? action : null;
  } };
  log.debug("Leaving formOf().");
  return out;
}

// --- G. the page's choices -------------------------------------------------
async function checkPageState(t) {
  log.debug("Entering checkPageState().");
  const WebPageState = require('../common/web_page_state');
  const held = {};
  const storage = {
    setItem: function (k, v) {
      held[k] = String(v);
    },
    getItem: function (k) {
      return k in held ? held[k] : null;
    },
    removeItem: function (k) {
      delete held[k];
    }
  };
  const before = formOf('/portal/x');
  const envOf = function (form) {
    return { sessionStorage: storage, now: function () {
      return 1000;
    }, document: { querySelectorAll: function () {
      return [form];
    } } };
  };
  const facts = { prefix: '', path: '/portal/x', subject: 'sub-ann' };
  WebPageState.save(envOf(before), 'k', facts);
  t.check(held.k && held.k.indexOf('ann@example.test') < 0,
          'G1. the choices are kept, and nothing typed', held.k);
  const after = formOf('/portal/x');
  after.box.checked = false;
  after.select.value = 'a';
  after.text.value = '';
  const done = WebPageState.take(envOf(after), 'k', facts);
  t.check(done.state === 'restored' && after.box.checked === true &&
          after.select.value === 'b' && after.text.value === '' &&
          !('k' in held),
          'G2. taken once, the same page and person get the choices back',
          JSON.stringify(done));
  WebPageState.save(envOf(before), 'k', facts);
  const other = WebPageState.take(envOf(formOf('/portal/x')), 'k',
    Object.assign({}, facts, { subject: 'sub-ben' }));
  t.equal(other.state, 'other', 'G3. another person gets nothing back');

  const PortalRuntime = require('../portal/web_portal_runtime');
  const ReportRuntime = require('../report/web_report_pages');
  const order = [];
  const fake = {
    env: { location: { hash: '' } }, prefix: '', subject: 's',
    here: function () {
      return '/portal/x';
    },
    savePageState: function () {
      order.push('save');
    },
    beginSignIn: function () {
      order.push('leave');
      return Promise.resolve();
    }
  };
  await PortalRuntime.prototype.leaveForStepUp.call(fake, 'account:manage',
                                                    '');
  const reportText = fs.readFileSync(path.join(ROOT, 'report',
    'web_report_pages.ts'), 'utf8');
  const at = reportText.indexOf('async leaveForStepUp(');
  const body = reportText.slice(at, at + 600);
  t.check(order.join() === 'save,leave' &&
          body.indexOf('WebPageState.save(') > 0 &&
          body.indexOf('WebPageState.save(') <
            body.indexOf('this.beginSignIn(') &&
          typeof ReportRuntime.prototype.restorePageState === 'function',
          'G4. the portal and the reports application keep the page\'s ' +
          'choices before they leave for permission', order.join());
  log.debug("Leaving checkPageState().");
}

// --- H. copy ---------------------------------------------------------------
async function checkCopy(t) {
  log.debug("Entering checkCopy().");
  const WebClipboard = require('../common/web_clipboard');
  const docWith = function (answer) {
    const appended = [];
    return { appended: appended, body: {
      appendChild: function (el) {
        appended.push(el);
      },
      removeChild: function () {
        return undefined;
      }
    }, createElement: function () {
      return { style: {}, setAttribute: function () {
        return undefined;
      }, focus: function () {
        return undefined;
      }, select: function () {
        return undefined;
      } };
    }, execCommand: function (name) {
      return name === 'copy' && answer;
    } };
  };
  const yes = docWith(true);
  const copied = await WebClipboard.copy(yes, {}, 'abc');
  t.check(copied === true && yes.appended.length === 1 &&
          yes.appended[0].value === 'abc',
          'H1. without navigator.clipboard the text is copied through a ' +
          'selected text area and execCommand');
  const no = docWith(false);
  const button = { textContent: 'Copy', attrs: {},
    getAttribute: function (n) {
      return n in button.attrs ? button.attrs[n] : null;
    },
    setAttribute: function (n, v) {
      button.attrs[n] = v;
    },
    removeAttribute: function (n) {
      delete button.attrs[n];
    } };
  let reset = null;
  const ok = await WebClipboard.copyFrom(no, {}, translatorFor('de'), button,
    'abc', function (fn) {
      reset = fn;
    });
  const de = catalog('browser', 'de');
  t.check(ok === false && button.textContent === de.copyFailed &&
          button.attrs.title === de['copyFailed.hint'],
          'H2. where that fails too, the button says so in German, and its ' +
          'title what to do instead', button.textContent);
  reset();
  t.check(button.textContent === 'Copy' && !('title' in button.attrs),
          'H3. and then says what it said before');
  const runtime = fs.readFileSync(path.join(ROOT, 'portal',
    'web_portal_runtime.ts'), 'utf8');
  t.check(/WebClipboard\.copyFrom\(doc, nav, self\.t, button, text\)/
    .test(runtime), 'H4. the portal\'s Copy goes through it');
  log.debug("Leaving checkCopy().");
}

// --- I. the words ----------------------------------------------------------
function checkWords(t) {
  log.debug("Entering checkWords().");
  const english = catalog('browser', 'en');
  const keys = Object.keys(english);
  const absent = [];
  baseTags().forEach(function (tag) {
    const held = catalog('browser', tag);
    keys.forEach(function (key) {
      if (!held[key]) {
        absent.push(tag + ' ' + key);
      }
    });
  });
  t.check(keys.length >= 25 && absent.length === 0,
          'I1. the ' + keys.length + ' browser keys are in every base ' +
          'catalog', absent.slice(0, 10).join('; '));
  const WebI18n = require('../common/web_i18n');
  const loaded = new WebI18n({}, { url: String }, ['report']);
  const i18n = require('../common/i18n');
  const data = i18n.catalogData(i18n.translator(['fr'], 'en').negotiated,
                                'console');
  t.check(loaded.namespaces.indexOf('browser') >= 0 &&
          data.catalogs.fr['browser.noPasskeys'] ===
            catalog('browser', 'fr').noPasskeys,
          'I2. every WebI18n loads them, and catalogData() gives them with ' +
          'the console\'s');
  const WebDocLinks = require('../common/web_doc_links');
  const doc = fs.readFileSync(path.join(ROOT, 'docs', 'v1.2.0',
    'browser-requirements.md'), 'utf8');
  t.check(/\/browser-requirements\.html#for-people-using-this-service$/
            .test(WebDocLinks.browserSupport()) &&
          /^## For people using this service$/m.test(doc) &&
          !/^\| A blocked or missing/m.test(doc),
          'I3. the link names a heading the browser requirements page has, ' +
          'and the closed gaps are gone from it');
  log.debug("Leaving checkWords().");
}

/**
 * J: the shells over HTTP, in a child with the whole stack.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.BS_ROOT;
  const OUT = process.env.BS_OUT;
  const http = require('http');
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');
    const authn = require(ROOT_DIR + '/authn/authn');
    // A sign-in waiting, as an application's request leaves one: the
    // screen's shell is drawn only for that.
    const signIn = authn.beginAuthentication({ returnTo: '/bs/after',
      protocol: 'bs-probe', application: '' });
    const de = JSON.parse(fs.readFileSync(ROOT_DIR +
      '/common/locales/browser/de.json', 'utf8'));
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const get = function (p, headers) {
      return screen.call({ port: port, jar: {}, method: 'GET', path: p,
                           headers: headers || {} });
    };
    const SHELLS = [['/admin', de['noscript.console']],
                    ['/portal', de['noscript.portal']],
                    ['/report', de['noscript.report']],
                    ['/', null],
                    [signIn, de['noscript.signin']]];
    for (const one of SHELLS) {
      const r = await get(one[0], { accept: 'text/html',
                                    'accept-language': 'de' });
      const text = String(r.text || '');
      const ns = /<noscript([^>]*)>([\s\S]*?)<\/noscript>/.exec(text);
      const words = one[1] === null ? de['noscript.home'].split('<code>')[0]
                                    : one[1].split('<code>')[0];
      note(r.status === 200 && ns && / lang="de"/.test(ns[1]) &&
           ns[2].indexOf(words) >= 0 &&
           ns[2].indexOf('#for-people-using-this-service') > 0,
           'J1. ' + one[0] + ' for Accept-Language: de answers its ' +
           '<noscript> in German, marked lang="de", with the link',
           r.status + ' ' + (ns ? ns[0].slice(0, 300) : text.slice(0, 300)));
      note(text.indexOf('<div id="sts-browser-check" role="alert" hidden ' +
                        'lang="de"><div class="err"><p><strong>' +
                        de['unsupported.title']) > 0 &&
           text.indexOf('<script src="/web/browser-check.js" defer>') > 0,
           'J2. ' + one[0] + '\'s shell runs the check and holds its ' +
           'notice hidden, in German');
      const csp = String(r.headers['content-security-policy'] || '');
      note(/script-src 'self'/.test(csp) && !/unsafe-inline/.test(
        /script-src[^;]*/.exec(csp)[0]),
           'J3. ' + one[0] + '\'s policy is still script-src \'self\'', csp);
    }
    const en = await get('/portal', { accept: 'text/html' });
    note(/<noscript><div class="err">This portal is a script/.test(en.text),
         'J4. with no Accept-Language the portal\'s notice is the English ' +
         'it always was, with no lang', String(en.text).slice(0, 200));
    const script = await get('/web/browser-check.js');
    note(script.status === 200 &&
         /javascript/.test(String(script.headers['content-type'])) &&
         /no-cache/.test(String(script.headers['cache-control'])),
         'J5. /web/browser-check.js is served as a script, no-cache',
         script.status + ' ' + script.headers['content-type']);
    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: String((e && e.stack) || e) });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

// Runs the child and reports its findings.
function checkOverHttp(t) {
  log.debug("Entering checkOverHttp().");
  const out = path.join(os.tmpdir(), 'bs-' + process.pid + '-' +
                        nodeCrypto.randomBytes(4).toString('hex') + '.json');
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
                                  BS_ROOT: ROOT, BS_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in checkOverHttp(): " + ((e && e.message) || e));
    findings = null;
  }
  if (!findings) {
    t.check(false, 'J. the child reported its findings',
            String(result.stderr || '').slice(-2000));
    log.debug("Leaving checkOverHttp(). No findings.");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving checkOverHttp().");
}

async function run(t) {
  log.debug("Entering run().");
  checkDetection(t);
  checkBundle(t);
  checkShell(t);
  await checkStorage(t);
  await checkWebAuthn(t);
  checkPopup(t);
  await checkPageState(t);
  await checkCopy(t);
  checkWords(t);
  checkOverHttp(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'browser_support',
  describe: 'what a browser lacks is said in the reader\'s language: the ' +
            'ES5 browser check, session storage, WebAuthn, the blocked ' +
            'sign-in window, the translated <noscript>, the page state ' +
            'kept, the Copy fallback and the statement for people (#2220)',
  run: run
};
