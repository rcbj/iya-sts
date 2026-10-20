// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// tests/authn_way_out.js — A SIGN-IN PAGE WITH NOWHERE TO GO.
//
// A refusal that drew no view — a pending id this service no longer has,
// a shell with no state, an act that answered no JSON — is the problem
// page: the language chooser and an English sentence, and nothing else.
// The same is true of any screen whose body draws neither a link nor a
// button. The chooser redraws this same page, so it is not a way off.
// That page tells the person to close the browser tab or window and start
// over, and links the realm's root page. A screen that already has a link
// or a button — Sign in, Start over, Allow — is left as it is.
// ===========================================================================
'use strict';
const fs = require('fs');
const path = require('path');
const AuthnSurface = require('../authn/web_authn');
const AuthnPages = require('../authn/web_authn_pages');
const WebTranslator = require('../common/web_messages').WebTranslator;
const log = require('bunyan').createLogger({ name: 'authn_way_out',
  level: process.env.LOG_LEVEL || 'info' });

// One catalog of the authn namespace, as the file holds it. The English
// sentences in `wayOut()` are this file's, and a translation is this
// file's too.
function authnCatalog(tag) {
  log.debug("Entering authnCatalog().");
  const file = path.join(__dirname, '..', 'common', 'locales', 'authn',
                         tag + '.json');
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  log.debug("Leaving authnCatalog().");
  return parsed;
}

// A translator over the authn catalogs named, best first, the way the
// browser's is built: each key prefixed with the namespace.
function translatorOf(tags) {
  log.debug("Entering translatorOf().");
  const catalogs = {};
  tags.forEach(function (tag) {
    const flat = authnCatalog(tag);
    const prefixed = {};
    Object.keys(flat).forEach(function (name) {
      prefixed['authn.' + name] = flat[name];
    });
    catalogs[tag] = prefixed;
  });
  const primary = tags[0];
  const t = WebTranslator.fromData({
    negotiated: { locale: primary, chain: tags.slice(), catalog: primary,
                  direction: 'ltr', matched: true },
    catalogs: catalogs });
  log.debug("Leaving translatorOf().");
  return t;
}

// A browser standing in for one realm. `prefix` is the shell's
// `data-sts-prefix` (`/realm/acme`); absent, the default realm.
function envFor(prefix, pathname) {
  log.debug("Entering envFor().");
  const attrs = {};
  if (prefix) {
    attrs['data-sts-prefix'] = prefix;
  }
  const where = (prefix || '') + (pathname || '/authn/login');
  const env = {
    location: { pathname: where, search: '', hash: '',
                href: 'https://sts.example' + where,
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
      title: '',
      body: { innerHTML: '' },
      documentElement: {
        getAttribute: function (name) {
          if (Object.prototype.hasOwnProperty.call(attrs, name)) {
            return attrs[name];
          }
          return null;
        },
        setAttribute: function () {
          return undefined;
        }
      },
      addEventListener: function () {
        return undefined;
      }
    },
    navigator: { languages: ['en'] },
    window: { setTimeout: setTimeout, clearTimeout: clearTimeout }
  };
  log.debug("Leaving envFor().");
  return env;
}

// The runtime, with a wallet page's start and poll left unarmed: this
// file draws the page, and does not dial the API a wallet page would.
function fresh(prefix, pathname) {
  log.debug("Entering fresh().");
  const env = envFor(prefix, pathname);
  const surface = new AuthnSurface(env);
  surface.walletFlow.onPut = function () {
    return undefined;
  };
  log.debug("Leaving fresh().");
  return { env: env, surface: surface };
}

// Whether the drawn page carries the way off, once, to `href`.
function offersWay(html, href) {
  log.debug("Entering offersWay().");
  const link = '<a id="authn-home" href="' + href + '">';
  const out = html.indexOf('id="authn-way-out"') >= 0 &&
    html.indexOf(link) >= 0 &&
    html.split('id="authn-way-out"').length === 2;
  log.debug("Leaving offersWay().");
  return out;
}

// Whether the drawn page was left without the way off.
function keepsOwn(html) {
  log.debug("Entering keepsOwn().");
  const out = html.indexOf('id="authn-way-out"') < 0 &&
    html.indexOf('id="authn-home"') < 0;
  log.debug("Leaving keepsOwn().");
  return out;
}

// One page of the surface, drawn through `put()` as the runtime draws it.
function page(at, view, prefix) {
  log.debug("Entering page().");
  const box = fresh(prefix);
  const ctx = box.surface.context({});
  ctx.view = view;
  const body = AuthnPages.render(at, view, ctx);
  box.surface.put('page', body, ctx);
  log.debug("Leaving page().");
  return box.env.document.body.innerHTML;
}

function run(t) {
  log.debug("Entering run().");
  const en = authnCatalog('en');
  const frCat = authnCatalog('fr');
  const close = en['stuck.close'];
  const home = en['stuck.home'];
  const way = '<p class="meta" id="authn-way-out">' + close + '</p>' +
    '<p><a id="authn-home" href="/">' + home + '</a></p>';

  t.log.info('=== the two sentences, and what already has a way on ===');
  t.equal(AuthnSurface.wayOut(null), way,
          '1. with no catalog the way off is the English of authn/en.json');
  t.equal(AuthnSurface.wayOut({}), way,
          '1b. a translator with no has() is the same English');
  const fr = translatorOf(['fr', 'en']);
  t.equal(fr.html('authn.stuck.close'), frCat['stuck.close'],
          '2. the French catalog holds stuck.close');
  t.equal(fr.html('authn.stuck.home'), frCat['stuck.home'],
          '2b. the French catalog holds stuck.home');
  t.check(AuthnSurface.hasWayOn('<a href="/x">') &&
          AuthnSurface.hasWayOn('<a class="fedbtn" href="/x">') &&
          AuthnSurface.hasWayOn('<button type="submit">Sign in</button>') &&
          AuthnSurface.hasWayOn('<input type="submit" value="Go">') &&
          AuthnSurface.hasWayOn('<input type=\'submit\'>') &&
          !AuthnSurface.hasWayOn('<a name="top">') &&
          !AuthnSurface.hasWayOn('<input type="text">') &&
          !AuthnSurface.hasWayOn('<form action="/authn/language">') &&
          !AuthnSurface.hasWayOn(''),
          '3. a link or a button is a way on; a form action is not');

  t.log.info('=== the problem page ===');
  const title = 'This page could not be drawn';
  const detail = 'There is no sign-in waiting under that id, or it has ' +
    'expired. Start the request again from the application that sent ' +
    'you here.';
  const stuck = fresh();
  stuck.surface.drawProblem(title, detail);
  const problem = stuck.env.document.body.innerHTML;
  t.equal(problem,
          '<div class="card"><h1>' + title + '</h1><div class="err">' +
          detail + '</div>' + way + '</div>',
          '4. the problem page keeps the English error and puts the way ' +
          'off inside its card');
  t.equal(stuck.env.document.title, title,
          '4b. the document\'s title is the English problem title');

  const chooser = fresh();
  chooser.surface.i18n.chooser = function () {
    return '<form class="language-chooser" method="post" ' +
      'action="/authn/language"><button type="submit">Language' +
      '</button></form>';
  };
  chooser.surface.drawProblem(title, 'The service answered 500.');
  const withChooser = chooser.env.document.body.innerHTML;
  const wayAt = withChooser.indexOf('id="authn-way-out"');
  t.check(withChooser.indexOf('<button type="submit">Language</button>') ===
          withChooser.indexOf('<button') &&
          offersWay(withChooser, '/') &&
          wayAt > withChooser.indexOf('<div class="err">') &&
          withChooser.lastIndexOf('</div>') > wayAt,
          '5. the language chooser\'s button is not a way off',
          withChooser.slice(0, 400));

  const realm = fresh('/realm/acme');
  realm.surface.drawProblem(title, detail);
  const inRealm = realm.env.document.body.innerHTML;
  t.check(offersWay(inRealm, '/realm/acme/') &&
          inRealm.indexOf(detail) >= 0 &&
          inRealm.indexOf('<a id="authn-home" href="/">') < 0,
          '6. in a realm the link is that realm\'s root page',
          inRealm.slice(0, 500));

  const french = fresh();
  french.surface.t = fr;
  french.surface.drawProblem(title, detail);
  const inFrench = french.env.document.body.innerHTML;
  t.check(inFrench.indexOf(detail) >= 0 &&
          inFrench.indexOf(frCat['stuck.close']) >= 0 &&
          inFrench.indexOf(frCat['stuck.home']) >= 0 &&
          inFrench.indexOf(close) < 0,
          '7. the way off is in the page\'s language; the error stays ' +
          'English', inFrench.slice(0, 500));

  // The consent screen loads none of the authn catalog. A refusal there
  // still has to be able to leave, in English.
  const consentT = WebTranslator.fromData({
    negotiated: { locale: 'fr', chain: ['fr'], catalog: 'fr',
                  direction: 'ltr', matched: true },
    catalogs: { fr: { 'consent.heading': 'Autorisation' } } });
  const consent = fresh('', '/oauth2/consent');
  consent.surface.t = consentT;
  consent.surface.drawProblem(title, detail);
  const consentProblem = consent.env.document.body.innerHTML;
  t.check(!consentT.has('authn.stuck.close') &&
          offersWay(consentProblem, '/') &&
          consentProblem.indexOf(close) >= 0 &&
          consentProblem.indexOf(home) >= 0,
          '8. a translator without the authn catalog draws the English ' +
          'way off', consentProblem.slice(0, 400));

  t.log.info('=== screens that draw neither a link nor a button ===');
  const dead = [
    ['/authn/select-idp', { partners: [], base: 'https://sts.example',
                            protocol: 'oidc' }, 'authn.selectIdp.heading'],
    ['/authn/email-code', { state: 'end', title: 'This sign-in has ended',
      sentence: 'The link is no longer valid.' }, 'id="email-error"'],
    ['/authn/email-link', { state: 'elsewhere' }, 'id="email-done"'],
    ['/authn/wallet', { wallet: 'start', kind: 'wallet' },
     'id="wallet-starting"'],
    ['/authn/wallet/wait', { wallet: 'refused',
                             heading: 'Nobody was signed in' },
     'Nobody was signed in'],
    ['/authn/spnego', { kind: 'challenge' }, 'id="spnego-facts"']
  ];
  dead.forEach(function (row) {
    const html = page(row[0], row[1]);
    t.check(offersWay(html, '/') && html.indexOf(row[2]) >= 0 &&
            html.indexOf(row[2]) < html.indexOf('id="authn-way-out"'),
            '9. ' + row[0] + ' gains the way off',
            html.slice(0, 300));
  });
  const emailEnd = page('/authn/email-code',
    { state: 'end', title: 'Ended', sentence: 'Gone.' });
  t.check(emailEnd.indexOf(
            'Start again from the application that sent you here.') >= 0 &&
          emailEnd.indexOf('id="email-error"') <
            emailEnd.indexOf('id="authn-way-out"'),
          '9b. the emailed factor\'s end page keeps its own sentence');
  const realmSelect = page('/authn/select-idp',
    { partners: [], base: 'https://sts.example', protocol: 'oidc' },
    '/realm/acme');
  t.check(offersWay(realmSelect, '/realm/acme/'),
          '9c. an empty partner list in a realm links that realm\'s root');

  t.log.info('=== screens that already have a way on ===');
  const kept = [
    ['/authn/login', {}, 'kc-cancel'],
    ['/authn/password-change', {}, 'password-change-submit'],
    ['/authn/totp', {}, 'totp-submit'],
    ['/authn/email-code', { kind: 'code' }, 'email-send'],
    ['/oauth2/consent', {}, 'consent-allow'],
    ['/authn/select-idp', { partners: [{ label: 'Acme',
      protocolLabel: 'SAML', href: '/federation/go' }],
      base: 'https://sts.example', protocol: 'saml' }, 'fedbtn'],
    ['/authn/wallet/wait', { wallet: 'wait', authn: 'a', state: 'tx',
                             sameDevice: 'openid4vp://x' }, 'wallet-open'],
    ['/authn/wallet/wait', { wallet: 'refused',
                             retry: '/authn/wallet?authn=a' },
     'wallet-retry'],
    ['/authn/wallet/wait', { wallet: 'refused', back: '/authn/login?authn=a',
                             backKind: 'screen' }, 'wallet-fallback'],
    ['/authn/spnego', { kind: 'challenge', pending: { id: 'p1',
      protocol: 'oidc' } }, 'spnego-password'],
    ['/authn/spnego', { kind: 'off', setting: 'kerberos.spnego' },
     'spnego-off'],
    ['/authn/spnego', { kind: 'signed-in', username: 'ada' },
     'spnego-signed-in']
  ];
  kept.forEach(function (row) {
    const html = page(row[0], row[1]);
    t.check(keepsOwn(html) && html.indexOf(row[2]) >= 0,
            '10. ' + row[0] + ' (' + row[2] + ') keeps its own way on',
            html.slice(0, 240));
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'authn_way_out',
  describe: 'A sign-in page with no link and no button tells the person ' +
            'to close the tab and links the realm root; a page that ' +
            'already has either is left as it is',
  run: run
};
