// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: branding.js
//
// ===========================================================================
// A REALM'S SIGN-IN APPEARANCE (#717): `common/branding.ts` and what the
// shell and the card do with it. In process; every write is in a realm this
// file creates and removes, so the default realm is only read.
//
//   A. THE DEFAULT IS THE OLD LOOK. A realm that set nothing is not
//      customised: no stylesheet, no attribute — its shell is byte for byte
//      the shell with branding turned off — and the card's every colour is
//      a custom property whose fallback is the literal it replaced.
//   B. THE COLOUR TYPE: `#rgb` read as `#rrggbb`, anything else refused.
//   C. CONTRAST BELOW WCAG 2.2 AA IS REFUSED (STS-AUTHN-0544), and a pair
//      legal only together is judged together.
//   D. A REALM'S THEME: its `theme.css` carries its colours and the tones
//      derived from them, its shell links it after the card and carries the
//      layout and brand facts, and the default realm is untouched.
//   E. THE LOGO: the bytes decide the type (STS-AUTHN-0545), the size cap
//      (0546), the sides (0547), the alternative text required and kept
//      (0548), the link https only (0551), removal.
//   F. THE ROUTES: theme.css cached for good only under its digest, the
//      logo nosniff and sandboxed with an ETag and a 304, a realm with none
//      404 (0549), a preview refused on a bad colour (0550) and drawn
//      otherwise.
//   G. THE RUNTIME'S HEADER escapes what it draws and drops a link that is
//      not https.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'branding',
  level: process.env.LOG_LEVEL || 'info' });

const realms = require('../common/realms');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const Branding = require('../common/branding');
const ShellDocument = require('../common/shell_document');
const WebCardCss = require('../common/web_card_css');
const WebSurface = require('../common/web_surface');

const REALM = 'brand-test';

// A PNG's first 24 bytes — the signature and the IHDR's sides — are all the
// check reads; the rest of a real image is not needed to judge one.
function png(width, height) {
  log.debug("Entering png().");
  const b = Buffer.alloc(64);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(b, 0);
  b.writeUInt32BE(13, 8);
  b.write('IHDR', 12, 'latin1');
  b.writeUInt32BE(width, 16);
  b.writeUInt32BE(height, 20);
  log.debug("Leaving png().");
  return b;
}

// A JPEG with an APP0 segment and a baseline start of frame.
function jpeg(width, height) {
  log.debug("Entering jpeg().");
  const app0 = Buffer.from([0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46,
                            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
                            0x00, 0x00]);
  const sof = Buffer.alloc(19);
  sof[0] = 0xff;
  sof[1] = 0xc0;
  sof.writeUInt16BE(17, 2);
  sof[4] = 8;
  sof.writeUInt16BE(height, 5);
  sof.writeUInt16BE(width, 7);
  log.debug("Leaving jpeg().");
  return Buffer.concat([Buffer.from([0xff, 0xd8]), app0, sof,
                        Buffer.from([0xff, 0xd9])]);
}

// A WebP of the extended kind, whose sides are 24-bit, less one.
function webp(width, height) {
  log.debug("Entering webp().");
  const b = Buffer.alloc(40);
  b.write('RIFF', 0, 'latin1');
  b.writeUInt32LE(32, 4);
  b.write('WEBP', 8, 'latin1');
  b.write('VP8X', 12, 'latin1');
  b.writeUIntLE(width - 1, 24, 3);
  b.writeUIntLE(height - 1, 27, 3);
  log.debug("Leaving webp().");
  return b;
}

// A response that records what a route did to it.
function response() {
  log.debug("Entering response().");
  const res = { statusCode: 200, headers: {}, body: null, ended: false };
  res.status = function (code) {
    res.statusCode = code;
    return res;
  };
  res.type = function (t) {
    res.headers['content-type'] = t;
    return res;
  };
  res.set = function (name, value) {
    res.headers[String(name).toLowerCase()] = value;
    return res;
  };
  res.vary = function () {
    return res;
  };
  res.send = function (body) {
    res.body = body;
    res.ended = true;
    return res;
  };
  res.end = function () {
    res.ended = true;
    return res;
  };
  log.debug("Leaving response().");
  return res;
}

// The three routes, captured from a stand-in app.
function routes() {
  log.debug("Entering routes().");
  const got = {};
  Branding.registerRoutes({
    get: function (path, handler) {
      got[path] = handler;
    },
    contentSecurityPolicy: function (directives) {
      return Object.keys(directives).map(function (k) {
        return k + ' ' + directives[k];
      }).join('; ');
    }
  });
  log.debug("Leaving routes().");
  return got;
}

function call(handler, query, headers) {
  log.debug("Entering call().");
  const res = response();
  handler({ query: query || {}, headers: headers || {} }, res);
  log.debug("Leaving call().");
  return res;
}

function shellOf(branded) {
  log.debug("Entering shellOf().");
  const spec = { title: 'Sign in', stylesheets: ['/web/card.css?v=1'],
                 script: '/authn/signin.js', open: '', close: '',
                 noscript: 'Needs its script.', loading: '' };
  if (branded === false) {
    spec.branded = false;
  }
  log.debug("Leaving shellOf().");
  return ShellDocument.document(spec);
}

function sectionA(t) {
  log.debug("Entering sectionA().");
  t.log.info('=== A. the default is the old look ===');
  realms.run(realms.get(realms.DEFAULT_ID), function () {
    const theme = Branding.theme();
    t.check(!theme.active && theme.layout === 'centered' && !theme.logo,
            'A1. the default realm, having set nothing, is not customised');
    t.equal(shellOf(), shellOf(false),
            'A2. so its shell is byte for byte the unbranded one: no theme ' +
            'stylesheet and no attribute');
    t.equal(theme.colours.muted, '#666666',
            'A3. and its derived tones are the old literals');
  });
  const css = WebCardCss.CARD_CSS;
  const bare = css.replace(/var\(--sts-[a-z-]+,#[0-9a-f]+\)/g, '');
  t.check(!/#12107c/.test(bare) && !/background:#f4f4f7/.test(bare),
          'A4. the card names the accent and the page only through custom ' +
          'properties, each falling back to its old literal');
  t.check(/var\(--sts-accent,#12107c\)/.test(css) &&
          /color:var\(--sts-on-accent,#fff\)/.test(css) &&
          /\.card\{background:var\(--sts-card,#fff\)/.test(css) &&
          /html\[data-sts-layout=split\]/.test(css),
          'A5. the button, the card and the layouts\' rules are there');
  log.debug("Leaving sectionA().");
}

function sectionB(t) {
  log.debug("Entering sectionB().");
  t.log.info('=== B. the colour type ===');
  const short = config.parseAs('branding.accentColor', '#ABC');
  t.check(short.ok && short.value === '#aabbcc',
          'B1. #rgb is read as lower-case #rrggbb', JSON.stringify(short));
  const word = config.parseAs('branding.accentColor', 'red');
  t.check(!word.ok && errorCodes.codeOf(word) === 'STS-CORE-0006',
          'B2. a colour that is not one is refused by name',
          JSON.stringify(word));
  log.debug("Leaving sectionB().");
}

function sectionC(t) {
  log.debug("Entering sectionC().");
  t.log.info('=== C. contrast below AA is refused ===');
  const pale = Branding.saveSettings({ 'branding.textColor': '#cccccc' });
  t.check(!pale.ok && errorCodes.codeOf(pale) === 'STS-AUTHN-0544',
          'C1. pale text on the white card is refused, STS-AUTHN-0544',
          JSON.stringify(pale));
  t.equal(config.value('branding.textColor'), '#222222',
          'C2. and nothing was written');
  const dark = Branding.saveSettings({ 'branding.cardColor': '#111111',
                                       'branding.textColor': '#eeeeee',
                                       'branding.accentColor': '#8ab4f8' });
  t.check(dark.ok, 'C3. a dark card with light text and a light accent, ' +
          'legal only together, is judged together and saved',
          JSON.stringify(dark));
  const linkLost = Branding.saveSettings({ 'branding.accentColor': '#222222' });
  t.check(!linkLost.ok && errorCodes.codeOf(linkLost) === 'STS-AUTHN-0544',
          'C4. an accent the links would vanish in on that card is refused');
  const notMine = Branding.saveSettings({ 'authn.multipleAccounts': 'false' });
  t.check(!notMine.ok, 'C5. only appearance settings are taken here');
  log.debug("Leaving sectionC().");
}

function sectionD(t) {
  log.debug("Entering sectionD().");
  t.log.info('=== D. a realm\'s theme ===');
  const saved = Branding.saveSettings({ 'branding.layout': 'split',
                                        'branding.displayName': 'Acme <Corp>' });
  t.check(saved.ok, 'D1. a layout and a name are saved', JSON.stringify(saved));
  const theme = Branding.theme();
  t.check(theme.active && theme.layout === 'split' &&
          /--sts-card:#111111/.test(theme.css) &&
          /--sts-text:#eeeeee/.test(theme.css) &&
          /--sts-on-accent:#000000/.test(theme.css),
          'D2. the realm\'s theme carries its colours, and black text on its ' +
          'light accent', theme.css);
  t.check(Branding.contrast(theme.colours.muted, theme.colours.card) >= 4.5 &&
          Branding.contrast(theme.colours.faint, theme.colours.card) >= 4.5,
          'D3. the quieter tones it derives keep AA against the card',
          JSON.stringify(theme.colours));
  const html = shellOf();
  const cardAt = html.indexOf('/web/card.css');
  const themeAt = html.indexOf('/web/theme.css?v=' + theme.digest);
  t.check(cardAt > 0 && themeAt > cardAt,
          'D4. the shell links the realm\'s theme after the card, under its ' +
          'digest');
  t.check(/data-sts-layout="split"/.test(html) &&
          /data-sts-brand-name="Acme &lt;Corp&gt;"/.test(html),
          'D5. and carries the layout and the name, escaped');
  realms.run(realms.get(realms.DEFAULT_ID), function () {
    t.check(!Branding.theme().active && shellOf() === shellOf(false),
            'D6. the default realm is untouched by another realm\'s theme');
  });
  log.debug("Leaving sectionD().");
}

function sectionE(t) {
  log.debug("Entering sectionE().");
  t.log.info('=== E. the logo ===');
  const noAlt = Branding.setLogo(png(64, 32), { actor: 'test' });
  t.check(!noAlt.ok && errorCodes.codeOf(noAlt) === 'STS-AUTHN-0548',
          'E1. a logo without alternative text is refused');
  const html = Branding.setLogo(Buffer.from('<html><script>x</script></html>',
                                            'utf8'),
                                { alt: 'Acme', actor: 'test' });
  t.check(!html.ok && html.status === 415 &&
          errorCodes.codeOf(html) === 'STS-AUTHN-0545',
          'E2. bytes that are not PNG, JPEG or WebP are refused, whatever ' +
          'was declared');
  const tiny = Branding.setLogo(png(8, 8), { alt: 'Acme', actor: 'test' });
  t.check(!tiny.ok && errorCodes.codeOf(tiny) === 'STS-AUTHN-0547',
          'E3. sides under 16 pixels are refused');
  const huge = Branding.setLogo(Buffer.concat([png(64, 32),
                                               Buffer.alloc(300000)]),
                                { alt: 'Acme', actor: 'test' });
  t.check(!huge.ok && huge.status === 413 &&
          errorCodes.codeOf(huge) === 'STS-AUTHN-0546',
          'E4. a logo over branding.logoMaxBytes is refused');
  t.check(Branding.sniff(jpeg(300, 120)).type === 'image/jpeg' &&
          Branding.sniff(jpeg(300, 120)).width === 300 &&
          Branding.sniff(jpeg(300, 120)).height === 120 &&
          Branding.sniff(webp(200, 50)).width === 200 &&
          Branding.sniff(webp(200, 50)).height === 50,
          'E5. a JPEG\'s and a WebP\'s sides are read from their frames');
  const kept = Branding.setLogo(png(64, 32), { alt: 'Acme', actor: 'test' });
  t.check(kept.ok && kept.logo && kept.logo.type === 'image/png' &&
          kept.logo.width === 64 && !('data' in kept.logo),
          'E6. a PNG with its text is kept, and the answer carries no bytes',
          JSON.stringify(kept.logo));
  t.equal(config.value('branding.logoAlt'), 'Acme',
          'E7. the text sent with it is the realm\'s logoAlt');
  const emptied = Branding.saveSettings({ 'branding.logoAlt': '' });
  t.check(!emptied.ok && errorCodes.codeOf(emptied) === 'STS-AUTHN-0548',
          'E8. the text cannot be emptied while the logo is held');
  const http = Branding.saveSettings({ 'branding.logoLinkUrl':
                                         'http://acme.example' });
  t.check(!http.ok && errorCodes.codeOf(http) === 'STS-AUTHN-0551',
          'E9. a link that is not https is refused');
  t.check(Branding.saveSettings({ 'branding.logoLinkUrl':
                                    'https://acme.example/' }).ok,
          'E10. an https one is kept');
  const facts = Branding.shellParts().attributes.reduce(function (o, a) {
    o[a[0]] = a[1];
    return o;
  }, {});
  t.check(/^\/web\/branding\/logo\?v=[0-9a-f]{16}$/.test(
    facts['data-sts-brand-logo']) && facts['data-sts-brand-alt'] === 'Acme' &&
          facts['data-sts-brand-link'] === 'https://acme.example/',
          'E11. the shell carries the logo\'s address, text and link',
          JSON.stringify(facts));
  log.debug("Leaving sectionE().");
}

function sectionF(t) {
  log.debug("Entering sectionF().");
  t.log.info('=== F. the routes ===');
  const r = routes();
  const theme = Branding.theme();
  const pinned = call(r['/web/theme.css'], { v: theme.digest });
  const loose = call(r['/web/theme.css'], {});
  t.check(/immutable/.test(pinned.headers['cache-control']) &&
          loose.headers['cache-control'] === 'no-cache' &&
          String(pinned.body) === theme.css,
          'F1. theme.css is cached for good only under its own digest');
  const logo = call(r['/web/branding/logo'], {});
  t.check(logo.statusCode === 200 &&
          logo.headers['content-type'] === 'image/png' &&
          logo.headers['x-content-type-options'] === 'nosniff' &&
          /sandbox/.test(logo.headers['content-security-policy']) &&
          Buffer.isBuffer(logo.body) && logo.body.length === 64,
          'F2. the logo is served as the type its bytes are, nosniff and ' +
          'sandboxed');
  const again = call(r['/web/branding/logo'], {},
                     { 'if-none-match': logo.headers.etag });
  t.equal(again.statusCode, 304, 'F3. and answers 304 to its own ETag');
  const bad = call(r['/web/branding/preview'], { accent: 'url(x)' });
  t.check(bad.statusCode === 400 &&
          errorCodes.codeOf(bad) === 'STS-AUTHN-0550',
          'F4. a preview of a colour that is not one is refused');
  const preview = call(r['/web/branding/preview'],
                       { layout: 'banner', accent: '#8ab4f8' });
  t.check(preview.statusCode === 200 &&
          /data-sts-layout="banner"/.test(String(preview.body)) &&
          /theme\.css\?preview=1&amp;accent=%238ab4f8&amp;layout=banner/
            .test(String(preview.body)) &&
          !/<script/.test(String(preview.body)),
          'F5. a preview draws the pending layout and colours, with no ' +
          'script');
  t.check(Branding.removeLogo('test').removed && !Branding.logoRecord(),
          'F6. the logo is removed');
  const gone = call(r['/web/branding/logo'], {});
  t.check(gone.statusCode === 404 &&
          errorCodes.codeOf(gone) === 'STS-AUTHN-0549',
          'F7. and a realm with none answers 404');
  t.check(Branding.saveSettings({ 'branding.logoAlt': '' }).ok,
          'F8. with no logo, its text may be emptied');
  log.debug("Leaving sectionF().");
}

function sectionG(t) {
  log.debug("Entering sectionG().");
  t.log.info('=== G. the runtime\'s header ===');
  const drawn = WebSurface.brandHeader({ name: '<b>Acme</b>',
    logo: '/web/branding/logo?v=1', alt: '"quoted"',
    link: 'javascript:alert(1)' });
  t.check(/&lt;b&gt;Acme&lt;\/b&gt;/.test(drawn) &&
          /alt="&quot;quoted&quot;"/.test(drawn) && !/<a /.test(drawn),
          'G1. the name and text are escaped, and a link that is not https ' +
          'is not drawn', drawn);
  t.equal(WebSurface.brandHeader({ name: '', logo: '' }), '',
          'G2. nothing is drawn for a realm with neither');
  t.equal(WebSurface.brandHeader(WebSurface.brandOf(null)), '',
          'G3. nor where the document has no brand facts');
  log.debug("Leaving sectionG().");
}

async function run(t) {
  log.debug("Entering run().");
  sectionA(t);
  sectionB(t);
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!t.check(made.ok, 'the test realm is created',
               (made.errors || []).join(' '))) {
    log.debug("Leaving run().");
    return;
  }
  try {
    realms.run(made.realm, function () {
      sectionC(t);
      sectionD(t);
      sectionE(t);
      sectionF(t);
    });
  } finally {
    realms.remove(REALM);
  }
  sectionG(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'branding',
  describe: 'a realm\'s sign-in appearance (#717): the old look by default, ' +
            'colours held to AA, the theme stylesheet and the shell\'s brand ' +
            'facts, the logo judged by its bytes, and the routes',
  run: run
};
