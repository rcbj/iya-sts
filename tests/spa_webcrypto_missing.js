// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: spa_webcrypto_missing.js
//
// ===========================================================================
// A BROWSER WITHOUT WEBCRYPTO IS TOLD SO, IN ITS LANGUAGE (#2143, ASVS 5.0.0
// 3.7.5).
//
// The console, the portal and the reports application sign in with PKCE and
// DPoP, all of it WebCrypto, which a browser holds only in a secure context.
// On plain HTTP (or in a browser too old to have it) the first
// `crypto.subtle.generateKey()` threw and the page stayed blank. Each
// runtime now asks `SpaClient.webCryptoMissing()` before anything and draws
// one sentence from `noWebCryptoWords()`. In process, with no browser:
//
//   A. THE DETECTION: no `crypto`, a `crypto` without `subtle` (what an
//      insecure origin has), without `getRandomValues`, and a `subtle`
//      missing one call a sign-in makes are all MISSING; node's own
//      `webcrypto` is not.
//   B. THE WORDS: `noWebCrypto.title` and `noWebCrypto.text` exist in
//      `consoleRuntime`, `portal` and `report`, in every base catalog, and
//      every translation names WebCrypto and HTTPS.
//   C. THE PAGE'S LANGUAGE: `noWebCryptoWords()` over a stub `fetch` serving
//      `common/locales/` answers a German browser in German, and with no
//      catalog to be had answers in English rather than drawing a key.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const SpaClient = require('../common/web_spa_client');

const log = require('bunyan').createLogger({ name: 'spa_webcrypto_missing',
  level: process.env.LOG_LEVEL || 'info' });

const LOCALES = path.join(__dirname, '..', 'common', 'locales');
const NAMESPACES = ['consoleRuntime', 'portal', 'report'];

// A browser's objects, enough for `WebI18n`; `serve` false answers nothing.
function envFor(languages, serve) {
  log.debug("Entering envFor().");
  const env = {
    crypto: { getRandomValues: function (a) {
      return a;
    } },
    location: { origin: 'https://webcrypto.test', pathname: '/portal',
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
      if (!serve || !file || !fs.existsSync(file)) {
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
  log.debug("Leaving envFor().");
  return env;
}

async function run(t) {
  log.debug("Entering run().");

  // --- A. the detection ----------------------------------------------------
  const missing = SpaClient.webCryptoMissing;
  t.check(missing(undefined) && missing({}) &&
          missing({ crypto: undefined }),
          'A1. no crypto at all is missing');
  t.check(missing({ crypto: { getRandomValues: function () {
    return null;
  } } }), 'A2. a crypto without subtle (an insecure origin) is missing');
  t.check(missing({ crypto: { subtle: nodeCrypto.webcrypto.subtle } }),
          'A3. a crypto without getRandomValues is missing');
  const partial = {};
  SpaClient.WEBCRYPTO_CALLS.forEach(function (name) {
    partial[name] = function () {
      return null;
    };
  });
  delete partial.sign;
  t.check(missing({ crypto: { getRandomValues: function () {
    return null;
  }, subtle: partial } }),
          'A4. a subtle missing one call a sign-in makes (sign) is missing');
  t.check(!missing({ crypto: nodeCrypto.webcrypto }),
          'A5. a whole WebCrypto (node\'s own) is not missing');

  // --- B. the words, in every base catalog -----------------------------------
  const index = JSON.parse(fs.readFileSync(path.join(LOCALES,
    'catalogs.json'), 'utf8'));
  const bases = index.catalogs.filter(function (one) {
    return !one.base;
  }).map(function (one) {
    return one.tag;
  });
  const absent = [];
  NAMESPACES.forEach(function (ns) {
    bases.forEach(function (tag) {
      const file = path.join(LOCALES, ns, tag + '.json');
      const held = fs.existsSync(file)
        ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
      ['noWebCrypto.title', 'noWebCrypto.text'].forEach(function (key) {
        const said = String(held[key] || '');
        if (!said || (key === 'noWebCrypto.text' &&
            !(said.indexOf('WebCrypto') >= 0 &&
              said.indexOf('HTTPS') >= 0))) {
          absent.push(ns + '/' + tag + ' ' + key);
        }
      });
    });
  });
  t.check(bases.length >= 10 && absent.length === 0,
          'B1. both keys in consoleRuntime, portal and report, in every ' +
          'base catalog (' + bases.join(', ') + '), naming WebCrypto and ' +
          'HTTPS', absent.join('; '));

  // --- C. the page's language ------------------------------------------------
  const options = { clientId: 'webcrypto-test', scope: 'openid',
                    elsewhere: {} };
  const german = new SpaClient(envFor(['de'], true), '', options);
  const de = JSON.parse(fs.readFileSync(path.join(LOCALES, 'portal',
    'de.json'), 'utf8'));
  const words = await german.noWebCryptoWords('portal');
  t.check(words.title === de['noWebCrypto.title'] &&
          words.text === de['noWebCrypto.text'],
          'C1. a German browser is told in German', words.title);
  const offline = new SpaClient(envFor(['de'], false), '', options);
  const english = await offline.noWebCryptoWords('consoleRuntime');
  t.check(/WebCrypto/.test(english.text) && /HTTPS/.test(english.text) &&
          english.title.indexOf('noWebCrypto') < 0,
          'C2. with no catalog to be had, the English is drawn, not a key',
          english.title + ' / ' + english.text);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spa_webcrypto_missing',
  describe: 'the console, portal and reports applications detect a browser ' +
            'without WebCrypto before signing in and draw one translated ' +
            'sentence (#2143)',
  run: run
};
