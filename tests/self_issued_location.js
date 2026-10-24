// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/self_issued_location.js
//
// ===========================================================================
// WHERE AN ENROLLED SELF-ISSUED KEY CAME FROM, AND EACH ROW ON ONE LINE
// (2026-10-20, rcbj on /portal/self-issued: "the subject values ... a single
// line", "a tooltip ... that displays the complete value", "a column called
// Location", and then "don't create huge multi-line values in the Location
// column").
//
//   1. THE NAME A WALLET REPORTS: `siop.reportedName()` keeps a
//      User-Agent's product tokens only — printable ASCII, no comments, no
//      markup, at most 80 characters, '' where nothing usable came.
//   2. THE REQUEST OBJECT ENDPOINT, in a child on `tests/wallet_kit.js`'s
//      in-process server: the web wallet's link carries `?via=web` on its
//      request_uri and the scheme link none; the endpoint answers the same
//      bytes, status and headers with and without it; the FIRST fetch is
//      recorded (`web` with the configured walletUrl, `app` with the
//      reported name, `app` with none) and a re-fetch changes nothing;
//      `VcSignin.locationOf()` turns each into a location, and the Digital
//      Credentials API's answer into `dc_api`.
//   3. THE STORED SHAPE: `siop.enrol()` keeps a checked `location` on a
//      proof, `admin` on an administrator's value, nothing for a kind it
//      does not know, and proving a subject again rewrites it.
//   4. THE PORTAL PAGE: the subject on one line with its whole value in
//      `title`; a Location column whose visible text is short for every
//      kind (and "not recorded" for an old row), the full story in its
//      `title`, everything escaped, and no multi-line cell; the view carries
//      `location` through.
//   5. THE CONSOLE'S BLOCK on /admin/users draws the same column.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'self_issued_location',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// 2. THE CHILD: the whole stack, the Request Object endpoint over HTTP.
// ---------------------------------------------------------------------------
function childMain() {
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const walletKit = require(ROOT + '/tests/wallet_kit');

  walletKit.boot().then(async function (w) {
    const note = w.note;
    try {
      await sections(w, note, w.m);
    } catch (e) {
      note(false, 'the child ran to the end', e && (e.stack || e.message));
    }
    await w.finish(OUT);
    process.exit(0);
  });

  async function sections(w, note, m) {
    const VcSignin = require(ROOT + '/oid4vc/vc_signin').VcSignin;
    const WALLET = 'http://wallet.test:8085';
    await w.inRealm(function () {
      m.config.setOverride('oid4vp.signIn', true);
      m.config.setOverride('oid4vp.signInSelfIssued', true);
      m.config.setOverride('oid4vp.walletUrl', WALLET);
    });
    const requestUriOf = function (link) {
      return new URL(link).searchParams.get('request_uri');
    };
    const txOf = function (state) {
      return w.inRealm(function () {
        return m.verifier.transactionFor(state);
      });
    };

    // 2a. THE LINKS. `start()` fetches the same-device link's request_uri
    // as a wallet app would, with no User-Agent.
    const id = await w.pendingSignIn();
    const s = await w.start(w.browser(), id, { query: { siop: '1' } });
    const view = s.view || {};
    const webUri = view.webWallet ? requestUriOf(view.webWallet) : '';
    const appUri = view.sameDevice ? requestUriOf(view.sameDevice) : '';
    note(/\/oid4vp\/request\/[^?]+\?via=web$/.test(webUri) &&
         view.webWallet.indexOf(WALLET) === 0 &&
         /\/oid4vp\/request\/[^?]+$/.test(appUri) &&
         /^siopv2:\/\//.test(view.sameDevice) &&
         webUri.replace(/\?via=web$/, '') === appUri,
         '2a. the web wallet\'s link carries ?via=web on its request_uri; ' +
         'the scheme link carries none, and both name one request',
         webUri + ' | ' + appUri);
    const first = txOf(s.state).signIn.fetchedBy || {};
    note(first.via === 'link' && first.agent === '',
         '2b. the first fetch, by the scheme link with no User-Agent, is ' +
         'recorded as a link with no name', JSON.stringify(first));

    // 2c. THE ENDPOINT ANSWERS THE SAME WITH AND WITHOUT THE MARKER.
    const plain = await w.request('GET', w.pathOf(appUri));
    const marked = await w.request('GET', w.pathOf(webUri),
      { headers: { 'user-agent': 'Other-Wallet/2' } });
    const headersOf = function (r) {
      const out = Object.assign({}, r.headers || {});
      delete out.date;
      return JSON.stringify(Object.keys(out).sort().map(function (k) {
        return [k, out[k]];
      }));
    };
    note(plain.status === 200 && marked.status === plain.status &&
         plain.text.length > 100 && marked.buffer.equals(plain.buffer) &&
         headersOf(marked) === headersOf(plain),
         '2c. the Request Object endpoint answers byte-identically, the ' +
         'same status and headers, with and without ?via=web',
         plain.status + ' ' + marked.status + ' ' + headersOf(plain) +
         ' | ' + headersOf(marked));
    const after = txOf(s.state).signIn.fetchedBy || {};
    note(after.via === 'link' && after.agent === '' && after.at === first.at,
         '2d. a re-fetch, by another link and another party, overwrites ' +
         'nothing: the first fetch wins', JSON.stringify(after));

    // 2e. EACH KIND, from a fresh transaction's first fetch.
    const fresh = function () {
      return w.inRealm(function () {
        const tx = m.verifier.buildVpRequest(w.fakeReq(''), {
          responseType: 'id_token',
          signIn: { authnId: 'sil-' +
                    require('crypto').randomUUID(), ttlMs: 60000 } });
        tx.signIn.walletUrl = WALLET + '/authorize';
        m.verifier.saveTransaction(tx);
        return { tx: tx,
                 web: m.verifier.vpRequestQuery(w.fakeReq(''), tx, 'web'),
                 app: m.verifier.vpRequestQuery(w.fakeReq(''), tx) };
      });
    };
    const fetchAs = async function (one, which, agent) {
      const uri = new URLSearchParams(one[which]).get('request_uri');
      const headers = agent === undefined ? {} : { 'user-agent': agent };
      await w.request('GET', w.pathOf(uri), { headers: headers });
      return VcSignin.locationOf(txOf(one.tx.state));
    };
    const web = fresh();
    const webAt = await fetchAs(web, 'web', 'Go-http-client/1.1');
    note(webAt.kind === 'web' && webAt.value === WALLET + '/authorize',
         '2e. fetched by the web link (whatever its User-Agent says): web, ' +
         'named by the CONFIGURED walletUrl', JSON.stringify(webAt));
    const app = fresh();
    const appAt = await fetchAs(app, 'app', 'oid4vc-wallet');
    const appAgain = await fetchAs(app, 'web', 'Impostor/9');
    note(appAt.kind === 'app' && appAt.value === 'oid4vc-wallet' &&
         appAgain.kind === 'app' && appAgain.value === 'oid4vc-wallet',
         '2f. fetched by the scheme link as `oid4vc-wallet`: an app of that ' +
         'name, and a later web-link fetch by another party changes nothing',
         JSON.stringify(appAt) + ' ' + JSON.stringify(appAgain));
    const none = fresh();
    const noneAt = await fetchAs(none, 'app');
    note(noneAt.kind === 'app' && noneAt.value === '',
         '2g. fetched with no User-Agent: an app that did not name itself',
         JSON.stringify(noneAt));
    const junk = fresh();
    const junkAt = await fetchAs(junk, 'app',
      '<script>alert(1)</script> "quoted" (comment only)');
    note(junkAt.kind === 'app' && junkAt.value === '',
         '2h. a User-Agent of markup, quotes and a comment names nothing',
         JSON.stringify(junkAt));
    const mixed = fresh();
    const mixedAt = await fetchAs(mixed, 'app',
      'Mozilla/5.0 (X11; Linux x86_64) <b>x</b> Wallet/1.2');
    note(mixedAt.kind === 'app' && mixedAt.value === 'Mozilla/5.0 Wallet/1.2',
         '2i. a browser-shaped User-Agent keeps its product tokens only',
         JSON.stringify(mixedAt));
    const dc = VcSignin.locationOf({ signIn: { via: 'dc_api',
      dcApi: { origin: 'https://sts.test' },
      fetchedBy: { via: 'web', agent: 'x' }, walletUrl: WALLET } });
    const dcBare = VcSignin.locationOf({ signIn: { via: 'dc_api' } });
    note(dc.kind === 'dc_api' && dc.value === 'https://sts.test' &&
         dcBare.kind === 'dc_api' && dcBare.value === '',
         '2j. an answer through the Digital Credentials API is dc_api, with ' +
         'the origin it was asked for, whatever fetched what',
         JSON.stringify(dc) + ' ' + JSON.stringify(dcBare));
    await w.inRealm(function () {
      m.config.clearOverride('oid4vp.walletUrl');
      m.config.clearOverride('oid4vp.signInSelfIssued');
      m.config.clearOverride('oid4vp.signIn');
    });
  }
}

// ---------------------------------------------------------------------------
// 1. THE NAME A WALLET REPORTS.
// ---------------------------------------------------------------------------
function nameSections(t, siop) {
  log.debug("Entering nameSections().");
  t.check(siop.reportedName('oid4vc-wallet') === 'oid4vc-wallet' &&
          siop.reportedName('Go-http-client/1.1') === 'Go-http-client/1.1',
          '1a. a plain product token, and one with a version, are kept');
  // A NUL and a CR LF become spaces, so nothing is joined that was apart,
  // and what they split is no longer a token (`/1`, `X-Evil:`).
  const split = siop.reportedName('Wallet\u0000/1\r\nX-Evil: 1');
  t.check(split === 'Wallet 1',
          '1b. control characters are no part of a name, and join nothing',
          JSON.stringify(split));
  const ctl = siop.reportedName('Good/1\u0007\u001bBadé/2');
  t.check(!/[^\x20-\x7e]/.test(ctl) && ctl.indexOf('Good/1') === 0,
          '1c. only printable ASCII survives', JSON.stringify(ctl));
  const long = siop.reportedName(('Abcdefghij/1 ').repeat(20));
  t.check(long.length <= 80 && long.length > 60 &&
          /^(Abcdefghij\/1 ?)+$/.test(long) && !/ $/.test(long),
          '1d. a long User-Agent is cut at 80 characters, between whole ' +
          'tokens', JSON.stringify(long));
  t.check(siop.reportedName('x'.repeat(200)) === '',
          '1e. one token longer than the cap names nothing');
  t.check(siop.reportedName('<img src=x onerror=alert(1)>') === '' &&
          siop.reportedName('App (nested (comment) here) Real/3') ===
            'App Real/3' &&
          siop.reportedName(undefined) === '' &&
          siop.reportedName(null) === '',
          '1f. markup names nothing, nested comments go, and nothing is ' +
          'nothing');
  log.debug("Leaving nameSections().");
}

// ---------------------------------------------------------------------------
// 3. THE STORED SHAPE, against the real directory in this process.
// ---------------------------------------------------------------------------
function storeSections(t, siop) {
  log.debug("Entering storeSections().");
  const ldap = require('../ldap/ldap_server');
  ldap.createUser('sil-alice', { invent: false,
    attributes: { givenName: 'Alice', sn: 'Located' } });
  const subject = 'did:jwk:' + Buffer.from(JSON.stringify(
    { kty: 'OKP', crv: 'Ed25519', x: 'sil-' + Date.now() }))
    .toString('base64url');
  const proved = siop.enrol('sil-alice', subject, 'phone', 'self (SIOPv2)',
    { proof: siop.PROOF_WALLET,
      location: { kind: 'app', value: 'oid4vc-wallet (Android 14)' } });
  const rowOf = function () {
    return (siop.list('sil-alice') || []).filter(function (one) {
      return one.subject === subject;
    })[0] || {};
  };
  t.check(proved.ok && JSON.stringify(rowOf().location) ===
            JSON.stringify({ kind: 'app', value: 'oid4vc-wallet' }),
          '3a. a proof stores `location: { kind, value }`, the name checked ' +
          'again as it is stored', JSON.stringify(rowOf()));
  const again = siop.enrol('sil-alice', subject, '', 'self (SIOPv2)',
    { proof: siop.PROOF_WALLET,
      location: { kind: 'web', value: 'http://wallet.test:8085/authorize' } });
  t.check(again.ok && again.again && rowOf().location.kind === 'web' &&
          rowOf().location.value === 'http://wallet.test:8085/authorize',
          '3b. proving it again from a web wallet rewrites the location',
          JSON.stringify(rowOf()));
  const odd = siop.enrol('sil-alice', subject, '', 'self (SIOPv2)',
    { proof: siop.PROOF_WALLET, location: { kind: 'carrier-pigeon',
                                            value: 'x' } });
  t.check(odd.ok && rowOf().location === undefined,
          '3c. a kind this service does not know is not stored',
          JSON.stringify(rowOf()));
  const badWeb = siop.locationOf({ kind: 'web', value: 'javascript:alert(1)' });
  const badDc = siop.locationOf({ kind: 'dc_api',
                                  value: 'https://x.test/<script>' });
  t.check(badWeb.kind === 'web' && badWeb.value === '' &&
          badDc.kind === 'dc_api' && badDc.value === '' &&
          siop.locationOf(null) === null &&
          siop.locationOf('web') === null,
          '3d. a web value must be an http(s) address and a browser\'s an ' +
          'origin; anything else keeps the kind and drops the value');
  const thumb = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:' +
    require('crypto').createHash('sha256').update('sil-' + Date.now())
      .digest('base64url');
  const byAdmin = siop.enrol('sil-alice', thumb, 'desk', 'an-admin',
    { location: { kind: 'web', value: 'http://forged.test' } });
  const adminRow = (siop.list('sil-alice') || []).filter(function (one) {
    return one.subject === thumb;
  })[0] || {};
  t.check(byAdmin.ok && JSON.stringify(adminRow.location) ===
            JSON.stringify({ kind: 'admin', value: '' }),
          '3e. an administrator\'s value is `admin`, whatever location the ' +
          'caller passed', JSON.stringify(adminRow));
  log.debug("Leaving storeSections().");
}

// A translator that shows which key it drew and every parameter, as a page
// would: `html()` escapes the parameters, `text()` does not.
function translator() {
  log.debug("Entering translator().");
  const fill = function (key, params, escape) {
    const p = params || {};
    return '[' + key + Object.keys(p).map(function (k) {
      const v = String(p[k]);
      return ' ' + k + '=' + (escape ? v.replace(/&/g, '&amp;')
        .replace(/</g, '&lt;') : v);
    }).join('') + ']';
  };
  log.debug("Leaving translator().");
  return { html: function (key, params) {
    return fill(key, params, true);
  }, text: function (key, params) {
    return fill(key, params, false);
  }, date: function (x) {
    return String(x);
  } };
}

// The `title` and the visible text of the first `.oneline` element of a
// kind in `html` after `from`.
function oneline(html, cls, from) {
  const at = html.indexOf('class="oneline ' + cls + '"', from || 0);
  const m = /^class="[^"]*" title="([^"]*)">([^<]*)</.exec(html.slice(at));
  return at < 0 || !m ? null : { title: m[1], shown: m[2], at: at };
}

// ---------------------------------------------------------------------------
// 4. THE PORTAL PAGE, and its view.
// ---------------------------------------------------------------------------
function pageSections(t, siop) {
  log.debug("Entering pageSections().");
  const SelfIssuedPages = require('../portal/web_self_issued');
  const PortalSelfIssued =
    require('../portal/portal_self_issued').PortalSelfIssued;
  const style = require('../portal/web_portal_kit').STYLE;
  const tr = translator();
  const longDid = 'did:jwk:' + 'eyJ'.repeat(70);
  const rows = [
    { subject: longDid, proof: 'wallet',
      location: { kind: 'web', value: 'http://localhost:8085/authorize' } },
    { subject: 'did:jwk:app', proof: 'wallet',
      location: { kind: 'app', value: 'A&B/1 Wallet\'s/2' } },
    { subject: 'did:jwk:anon', proof: 'wallet',
      location: { kind: 'app', value: '' } },
    { subject: 'did:jwk:dc', proof: 'wallet',
      location: { kind: 'dc_api', value: 'https://sts.test' } },
    { subject: 'did:jwk:dc2', proof: 'wallet',
      location: { kind: 'dc_api', value: '' } },
    { subject: 'did:jwk:<b>admin</b>', proof: 'admin',
      location: { kind: 'admin', value: '' } },
    { subject: 'did:jwk:old', proof: 'wallet', location: null }
  ];
  const html = SelfIssuedPages.render({ enabled: true, subjects: rows },
                                      { t: tr, query: {} });
  const subject = oneline(html, 'subject');
  t.check(!!subject && subject.title === longDid &&
          subject.shown === longDid.slice(0, 13) + '\u2026' +
            longDid.slice(-7) &&
          /<table class="grid">/.test(html) &&
          /<div class="scrollx"><table/.test(html) &&
          style.indexOf('td .oneline{display:inline-block;max-width:13em;' +
                        'overflow:hidden;text-overflow:ellipsis;' +
                        'white-space:nowrap;') >= 0 &&
          style.indexOf('.scrollx{overflow-x:auto') >= 0,
          '4a. the subject is ONE line, its start and its end, and its whole ' +
          'value is its title; the table cannot run past its card',
          subject && subject.title.slice(0, 40));
  t.check(html.indexOf('did:jwk:&lt;b&gt;admin&lt;/b&gt;') >= 0 &&
          html.indexOf('<b>admin</b>') < 0,
          '4b. the subject is escaped in its title and its text');
  t.check(html.indexOf('<th>[portalSelfIssued.location]</th>') >
            html.indexOf('<th>[portalSelfIssued.how]</th>') &&
          (html.match(/<th>/g) || []).length === 7,
          '4c. a Location column, after How: seven columns');
  const cells = [];
  let from = 0;
  for (let i = 0; i < rows.length; i += 1) {
    const one = oneline(html, 'location', from);
    cells.push(one);
    from = one ? one.at + 1 : html.length;
  }
  const want = [
    ['localhost:8085',
     '[portalSelfIssued.locationWebTip url=http://localhost:8085/authorize]'],
    ['A&amp;B/1 Wallet&#39;s/2',
     '[portalSelfIssued.locationAppTip name=A&amp;B/1 Wallet&#39;s/2]'],
    ['[portalSelfIssued.locationAppUnnamed]',
     '[portalSelfIssued.locationAppUnnamedTip]'],
    ['[portalSelfIssued.locationDcApi]',
     '[portalSelfIssued.locationDcApiOriginTip origin=https://sts.test]'],
    ['[portalSelfIssued.locationDcApi]', '[portalSelfIssued.locationDcApiTip]'],
    ['[portalSelfIssued.locationAdmin]', '[portalSelfIssued.locationAdminTip]'],
    ['[portalSelfIssued.locationNone]', '[portalSelfIssued.locationNoneTip]']
  ];
  const kinds = ['web', 'app', 'app unnamed', 'dc_api with an origin',
                 'dc_api', 'admin', 'an old row (not recorded)'];
  want.forEach(function (w, i) {
    const c = cells[i];
    t.check(!!c && c.shown === w[0] && c.title === w[1],
            '4d. Location, ' + kinds[i] + ': the short line shows ' +
            JSON.stringify(w[0]) + ' and the title has the rest',
            JSON.stringify(c));
  });
  t.check(cells.every(function (c) {
    return c && c.shown.length <= 40 && !/<br|\n/.test(c.shown);
  }) && !/<td>[^<]*<br/.test(html) &&
          style.indexOf('td .oneline.location{max-width:10em}') >= 0,
          '4e. no Location value is a multi-line cell: each is one short ' +
          'nowrap line of its own width');
  // A NAME WITH MARKUP never reaches the page as markup, should a stored
  // value somehow hold one: the cell escapes it.
  const hostile = SelfIssuedPages.locationCell(
    { kind: 'app', value: '"><script>x</script>' }, tr);
  t.check(hostile.indexOf('<script>') < 0 &&
          hostile.indexOf('&quot;&gt;&lt;script&gt;') >= 0,
          '4f. the reported name is escaped in its title and its text',
          hostile);
  // THE VIEW CARRIES `location`, checked again, and null for an old row.
  const page = new PortalSelfIssued({
    log: { debug: function () {} },
    config: { value: function () {
      return false;
    } },
    siop: { PROOF_ADMIN: 'admin', locationOf: siop.locationOf,
            list: function () {
              return [
                { subject: 'did:jwk:a', proof: 'wallet',
                  location: { kind: 'app', value: 'oid4vc-wallet (x)' } },
                { subject: 'did:jwk:b', proof: 'wallet' }];
            } }
  });
  const view = page.view('someone');
  t.check(JSON.stringify(view.subjects[0].location) ===
            JSON.stringify({ kind: 'app', value: 'oid4vc-wallet' }) &&
          view.subjects[1].location === null,
          '4g. the account API\'s view carries `location`, and null for an ' +
          'enrolment from before it', JSON.stringify(view.subjects));
  log.debug("Leaving pageSections().");
}

// ---------------------------------------------------------------------------
// 5. THE CONSOLE'S BLOCK.
// ---------------------------------------------------------------------------
function consoleSections(t) {
  log.debug("Entering consoleSections().");
  const UsersPage = require('../admin-ui/web_users');
  const tr = translator();
  const web = UsersPage.siopLocationCell(
    { kind: 'web', value: 'http://localhost:8085/authorize' }, tr);
  const app = UsersPage.siopLocationCell(
    { kind: 'app', value: '<i>x</i>' }, tr);
  const old = UsersPage.siopLocationCell(undefined, tr);
  t.check(web === '<span class="oneline" title="[consoleUsers.mfaSection.' +
            'siopLocationWebTip url=http://localhost:8085/authorize]">' +
            'localhost:8085</span>' &&
          app.indexOf('<i>') < 0 && app.indexOf('&lt;i&gt;') >= 0 &&
          old.indexOf('siopLocationNone]') >= 0 &&
          old.indexOf('siopLocationNoneTip]') >= 0,
          '5a. /admin/users\' self-issued block draws the same Location: ' +
          'one short line, the rest in an escaped title, "not recorded" ' +
          'for an old row', web + ' | ' + app + ' | ' + old);
  const src = require('fs').readFileSync(require('path').join(__dirname,
    '..', 'admin-ui', 'web_users.ts'), 'utf8');
  t.check(src.indexOf("t.html('consoleUsers.mfaSection.siopThLocation')") >=
            0 && src.indexOf('UsersPage.siopLocationCell(one.location, t)') >=
            0,
          '5b. the block\'s table has the Location heading and cell');
  log.debug("Leaving consoleSections().");
}

// ---------------------------------------------------------------------------
// 6. ROWS TOLD APART, AND THE LINK TO A DID'S DOCUMENT.
// ---------------------------------------------------------------------------
function linkSections(t, siop) {
  log.debug("Entering linkSections().");
  const SelfIssuedPages = require('../portal/web_self_issued');
  const PortalSelfIssued =
    require('../portal/portal_self_issued').PortalSelfIssued;
  const tr = translator();
  const PREFIX = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:';
  const one = PREFIX + 'AAAAbbbbCCCCddddEEEEffffGGGGhhhhIIII-KbfXQ-A';
  const two = PREFIX + 'AAAAbbbbCCCCddddEEEEffffGGGGhhhhIIII-ZzZz<9>';
  const html = SelfIssuedPages.render({ enabled: true, subjects: [
    { subject: one, proof: 'wallet' }, { subject: two, proof: 'wallet' }] },
    { t: tr, query: {} });
  const first = oneline(html, 'subject');
  const second = oneline(html, 'subject', first ? first.at + 1 : 0);
  t.check(!!first && !!second && first.shown !== second.shown &&
          first.shown === 'urn:ietf:para…KbfXQ-A' &&
          second.shown === 'urn:ietf:para…ZzZz&lt;9&gt;' &&
          first.title === one &&
          second.title === two.replace('<', '&lt;').replace('>', '&gt;') &&
          SelfIssuedPages.middle('did:jwk:short') === 'did:jwk:short',
          '6a. two subjects sharing a prefix show their start AND their ' +
          'end, so they differ; the title is the whole value, escaped; a ' +
          'short one is shown whole',
          JSON.stringify([first, second]));
  // THE VIEW says where each document is: a did:web's published address,
  // computed by the server; a did:jwk or did:key resolved here; a
  // thumbprint neither.
  const page = new PortalSelfIssued({
    log: { debug: function () {} },
    config: { value: function () {
      return false;
    } },
    siop: { PROOF_ADMIN: 'admin', locationOf: siop.locationOf,
            didWebUrl: siop.didWebUrl,
            list: function () {
              return [{ subject: 'did:web:wallet.example:people:alice' },
                      { subject: 'did:web:wallet.example' },
                      { subject: 'did:jwk:eyJhIjoxfQ' },
                      { subject: 'did:key:z6MkTest' },
                      { subject: one }];
            } }
  });
  const rows = page.view('someone').subjects;
  t.check(rows[0].didDocumentUrl ===
            'https://wallet.example/people/alice/did.json' &&
          rows[1].didDocumentUrl ===
            'https://wallet.example/.well-known/did.json' &&
          !rows[0].didResolved && rows[2].didResolved === true &&
          rows[2].didDocumentUrl === '' && rows[3].didResolved === true &&
          rows[4].didDocumentUrl === '' && rows[4].didResolved === false,
          '6b. the view names a did:web\'s published document, marks a ' +
          'did:jwk and a did:key as resolved here, and a thumbprint as ' +
          'neither', JSON.stringify(rows));
  const drawn = SelfIssuedPages.render({ enabled: true, subjects: rows },
    { t: tr, query: {}, origin: 'https://sts.test', prefix: '/realm/acme' });
  const links = drawn.match(/<div class="didlink"><a [^>]*>/g) || [];
  const attr = function (tag, name) {
    const m = new RegExp(' ' + name + '="([^"]*)"').exec(tag || '');
    return m ? m[1] : null;
  };
  const resolvedHref = '/portal/self-issued/did?subject=' +
    encodeURIComponent('did:jwk:eyJhIjoxfQ');
  t.check(links.length === 4 &&
          attr(links[0], 'href') ===
            'https://wallet.example/people/alice/did.json' &&
          attr(links[0], 'title') ===
            'https://wallet.example/people/alice/did.json' &&
          attr(links[2], 'href') === resolvedHref &&
          attr(links[2], 'title') ===
            'https://sts.test/realm/acme' + resolvedHref &&
          attr(links[3], 'href') === '/portal/self-issued/did?subject=' +
            encodeURIComponent('did:key:z6MkTest') &&
          links.every(function (tag) {
            return attr(tag, 'target') === '_blank' &&
              attr(tag, 'rel') === 'noopener noreferrer';
          }) &&
          (drawn.match(/\[portalSelfIssued\.didLink\]<\/a>/g) || [])
            .length === 4,
          '6c. a link on the did:web rows (the published document, title ' +
          'the same URL), on the did:jwk and did:key rows (the resolved ' +
          'page, title absolute and in the realm), none on the thumbprint; ' +
          'each opens a new tab with noopener noreferrer',
          JSON.stringify(links));
  const shell = require('../portal/web_portal_shell');
  const T = { text: function (k) {
    return k;
  }, html: function (k) {
    return k;
  } };
  t.check(shell.navPathFor('/portal/self-issued/did') ===
            '/portal/self-issued' &&
          shell.navPathFor('/portal/self-issued') === '/portal/self-issued' &&
          shell.navPathFor('/portal/nowhere/x') === '/portal/nowhere/x' &&
          shell.headingFor('/portal/self-issued/did', T) ===
            shell.headingFor('/portal/self-issued', T) &&
          shell.keptParams({ subject: 'did:jwk:x', user: 'bob' })
            .join('|') === 'subject,did:jwk:x',
          '6d. the sub-page is headed and placed in the column as ' +
          'Self-issued IDs, and Refresh keeps its subject (and nothing ' +
          'else)');
  const nav = shell.navBar('/portal/self-issued/did', T);
  t.check(/<a href="\/portal\/self-issued">/.test(nav) &&
          !/aria-current/.test(nav),
          '6e. its column links back to the list', nav.slice(0, 120));
  log.debug("Leaving linkSections().");
}

// ---------------------------------------------------------------------------
// 7. THE OPERATION, in a child: the whole stack, a real portal sign-in.
// ---------------------------------------------------------------------------
function didChildMain() {
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const fs = require('fs');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  (async function () {
    try {
      require(ROOT + '/common/protocol_stack');
      const http = require('http');
      const nodeCrypto = require('crypto');
      const app = require(ROOT + '/common/app');
      const ldap = require(ROOT + '/ldap/ldap_server');
      const credentials = require(ROOT + '/common/credentials');
      const errorCodes = require(ROOT + '/common/error_codes');
      const siop = require(ROOT + '/oid4vc/siop');
      const di = require(ROOT + '/oid4vc/vc_data_integrity');
      const stsCrypto = require(ROOT + '/common/crypto');
      const signin = require(ROOT + '/tests/protocol/portal_signin');
      const stamp = String(process.pid);
      const ALICE = 'sid-alice-' + stamp;
      const BOB = 'sid-bob-' + stamp;
      const PASSWORD = 'Did-Doc-' + stamp + '-Passw0rd!';
      [ALICE, BOB].forEach(function (name) {
        ldap.createUser(name, { invent: false });
        credentials.setPassword(name, PASSWORD);
      });
      const jwkOf = function () {
        const pair = nodeCrypto.generateKeyPairSync('ec',
          { namedCurve: 'P-256' });
        const j = pair.publicKey.export({ format: 'jwk' });
        return { kty: j.kty, crv: j.crv, x: j.x, y: j.y };
      };
      const aliceJwk = di.didJwkOf(jwkOf());
      const aliceKey = di.didKeyOf(jwkOf());
      const aliceWeb = 'did:web:wallet.example:' + stamp;
      const aliceThumb = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:' +
        stsCrypto.jwkThumbprint(jwkOf());
      const bobJwk = di.didJwkOf(jwkOf());
      const strangerJwk = di.didJwkOf(jwkOf());
      const proved = { proof: siop.PROOF_WALLET };
      const enrolled = [
        siop.enrol(ALICE, aliceJwk, 'a', 'self (SIOPv2)', proved),
        siop.enrol(ALICE, aliceKey, 'b', 'self (SIOPv2)', proved),
        siop.enrol(ALICE, aliceWeb, 'c', 'self (SIOPv2)',
                   { proof: siop.PROOF_WALLET,
                     pinnedKeys: ['A'.repeat(43)] }),
        siop.enrol(ALICE, aliceThumb, 'd', 'self (SIOPv2)', proved),
        siop.enrol(BOB, bobJwk, 'e', 'self (SIOPv2)', proved)];
      note(enrolled.every(function (r) {
        return r.ok;
      }), 'precondition: alice holds a did:jwk, a did:key, a did:web and ' +
          'a thumbprint, bob a did:jwk', JSON.stringify(enrolled.map(
            function (r) {
              return r.error || 'ok';
            })));
      const marks = [];
      const server = http.createServer(function (req, res) {
        res.on('finish', function () {
          marks.push(errorCodes.codeOf(res));
        });
        app(req, res);
      });
      await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
      const base = 'http://127.0.0.1:' + server.address().port;
      const alice = await signin.signInToThePortal(base, ALICE, null,
                                                   { password: PASSWORD });
      note(!!alice.token, 'alice signs in as the static portal does');
      const ask = async function (subject) {
        const r = await alice.api('GET', '/account-api/self-issued/did' +
          (subject === null ? '' : '?subject=' +
                                   encodeURIComponent(subject)));
        return { status: r.status, json: r.json || {},
                 code: marks[marks.length - 1] || '', text: r.text };
      };
      const jwkDoc = await ask(aliceJwk);
      note(jwkDoc.status === 200 && jwkDoc.json.subject === aliceJwk &&
           jwkDoc.json.document && jwkDoc.json.document.id === aliceJwk &&
           jwkDoc.json.document.verificationMethod[0].publicKeyJwk &&
           !jwkDoc.code,
           '7a. her own did:jwk: its document, resolved from the identifier',
           jwkDoc.status + ' ' + jwkDoc.text.slice(0, 200));
      const keyDoc = await ask(aliceKey);
      note(keyDoc.status === 200 && keyDoc.json.document &&
           keyDoc.json.document.id === aliceKey &&
           keyDoc.json.document.verificationMethod[0].type === 'Multikey',
           '7b. her own did:key: its document', keyDoc.status + ' ' +
           keyDoc.text.slice(0, 200));
      const bobs = await ask(bobJwk);
      const nobodys = await ask(strangerJwk);
      const junk = await ask('not a subject');
      note(bobs.status === 404 && bobs.code === 'STS-PORTAL-0618' &&
           !bobs.json.document && nobodys.status === 404 &&
           nobodys.code === 'STS-PORTAL-0618' &&
           junk.status === 404 && junk.code === 'STS-PORTAL-0618' &&
           bobs.text.indexOf(BOB) < 0 &&
           JSON.stringify(bobs.json.errors) ===
             JSON.stringify(nobodys.json.errors),
           '7c. another person\'s subject, an unenrolled one and a non-' +
           'subject are refused alike, STS-PORTAL-0618, saying nothing ' +
           'about whose it is', [bobs.status, bobs.code, nobodys.status,
             nobodys.code, junk.code, bobs.text].join(' '));
      const web = await ask(aliceWeb);
      const thumb = await ask(aliceThumb);
      note(web.status === 400 && web.code === 'STS-PORTAL-0619' &&
           thumb.status === 400 && thumb.code === 'STS-PORTAL-0619' &&
           !web.json.document && !thumb.json.document,
           '7d. her own did:web and her own thumbprint are refused, ' +
           'STS-PORTAL-0619: nothing is fetched, and a thumbprint is no DID',
           [web.status, web.code, thumb.status, thumb.code].join(' '));
      const none = await ask(null);
      note(none.status === 200 && none.json.subject === '' &&
           none.json.document === null,
           '7e. naming no subject answers no document, for the page\'s ' +
           'pointer back', none.status + ' ' + none.text.slice(0, 120));
      const list = await alice.api('GET', '/account-api/self-issued');
      const byId = {};
      ((list.json && list.json.subjects) || []).forEach(function (row) {
        byId[row.subject] = row;
      });
      note(byId[aliceWeb] && byId[aliceWeb].didDocumentUrl ===
             'https://wallet.example/' + stamp + '/did.json' &&
           byId[aliceJwk] && byId[aliceJwk].didResolved === true &&
           byId[aliceKey] && byId[aliceKey].didResolved === true &&
           byId[aliceThumb] && byId[aliceThumb].didDocumentUrl === '' &&
           byId[aliceThumb].didResolved === false,
           '7f. GET /account-api/self-issued names each row\'s document',
           JSON.stringify(byId).slice(0, 400));
      const index = await signin.nobody(base, 'GET', '/account-api');
      const op = ((index.json && index.json.operations) || [])
        .filter(function (one) {
          return one.path === '/account-api/self-issued/did';
        })[0];
      const doc = await signin.nobody(base, 'GET',
                                      '/account-api/openapi.json');
      note(op && op.mirrors === 'GET /portal/self-issued/did' &&
           doc.json && doc.json.paths &&
           doc.json.paths['/account-api/self-issued/did'] &&
           doc.json.paths['/account-api/self-issued/did'].get,
           '7g. the index lists the operation as the sub-page\'s, and the ' +
           'OpenAPI document documents it', JSON.stringify(op));
      server.close();
    } catch (e) {
      note(false, 'the child ran to the end', e && (e.stack || e.message));
    }
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })();
}

// ---------------------------------------------------------------------------
// 8. THE PAGE, AND A FRESH TAB OPENED ON IT.
// ---------------------------------------------------------------------------
async function didPageSections(t) {
  log.debug("Entering didPageSections().");
  const SelfIssuedPages = require('../portal/web_self_issued');
  const tr = translator();
  const view = { ok: true, subject: 'did:jwk:x<y>',
                 document: { id: 'did:jwk:x<y>',
                             note: '</pre><script>alert(1)</script>' } };
  const html = SelfIssuedPages.renderDid(view, { t: tr, query: {} });
  const pre = (/<pre class="diddoc" id="siop-did-document">([\s\S]*?)<\/pre>/
    .exec(html) || [])[1] || '';
  t.check(pre.indexOf('&lt;/pre&gt;&lt;script&gt;') >= 0 &&
          html.indexOf('<script>') < 0 &&
          pre.indexOf('\n  &quot;id&quot;: &quot;did:jwk:x&lt;y&gt;&quot;') >=
            0 &&
          /<code id="siop-did">did:jwk:x&lt;y&gt;<\/code>/.test(html) &&
          html.indexOf('[portalSelfIssued.didResolvedNote]') >= 0 &&
          html.indexOf('href="/portal/self-issued"') >= 0,
          '8a. the page shows the DID, the line saying it is resolved from ' +
          'the identifier, and the document as indented JSON, escaped',
          pre.slice(0, 160));
  const none = SelfIssuedPages.renderDid({ ok: true, subject: '',
                                           document: null }, { t: tr });
  const refused = SelfIssuedPages.renderDid({ ok: false, errors: ['x'] },
                                            { t: tr });
  t.check(/id="siop-did-none"/.test(none) && !/<pre/.test(none) &&
          /id="siop-did-none"/.test(refused) && !/<pre/.test(refused),
          '8b. with no subject, or refused, it points back and draws no ' +
          'document');
  const style = require('../portal/web_portal_kit').STYLE;
  t.check(style.indexOf('pre.diddoc{white-space:pre-wrap;' +
                        'overflow-wrap:anywhere;overflow-x:auto;' +
                        'max-width:100%;') >= 0,
          '8c. the JSON wraps inside its card');
  const pages = require('../portal/web_portal_pages');
  const row = pages.find('/portal/self-issued/did');
  t.check(!!row && row.operation === '/account-api/self-issued/did' &&
          (row.access || 'person') === 'person',
          '8d. the sub-page is a signed-in page drawn from its operation');

  // A FRESH TAB, as `target="_blank" rel="noopener"` opens it: nothing in
  // its sessionStorage, so the runtime signs in, and the callback lands it
  // back on the sub-page with its query, drawn from its operation.
  const PortalRuntime = require('../portal/web_portal_runtime');
  const nodeCrypto = require('crypto');
  const ORIGIN = 'https://sts.example.com';
  const DID = 'did:jwk:eyJmcmVzaCI6InRhYiJ9';
  const store = {};
  const calls = [];
  const location = { pathname: '/portal/self-issued/did',
                     search: '?subject=' + encodeURIComponent(DID), hash: '',
                     href: ORIGIN + '/portal/self-issued/did', origin: ORIGIN,
                     assigned: [],
                     assign: function (u) {
                       location.assigned.push(String(u));
                     } };
  const body = { innerHTML: '' };
  const b64u = function (o) {
    return Buffer.from(JSON.stringify(o)).toString('base64url');
  };
  const env = {
    location: location,
    history: { replaceState: function (s0, t0, u) {
                 const at = new URL(String(u), ORIGIN);
                 location.pathname = at.pathname;
                 location.search = at.search;
               },
               pushState: function () {} },
    crypto: globalThis.crypto,
    sessionStorage: { getItem: function (k) {
                        return k in store ? store[k] : null;
                      },
                      setItem: function (k, v) {
                        store[k] = String(v);
                      },
                      removeItem: function (k) {
                        delete store[k];
                      } },
    navigator: { languages: ['en'] },
    document: { title: '', body: body,
                documentElement: { getAttribute: function () {
                                     return null;
                                   },
                                   setAttribute: function () {} },
                createElement: function () {
                  return { setAttribute: function () {}, innerHTML: '' };
                },
                getElementById: function () {
                  return null;
                },
                querySelectorAll: function () {
                  return [];
                },
                querySelector: function () {
                  return null;
                },
                addEventListener: function () {} },
    window: { BroadcastChannel: function () {
                this.postMessage = function () {};
                this.close = function () {};
              },
              AbortController: AbortController,
              confirm: function () {
                return true;
              },
              open: function () {
                return {};
              },
              addEventListener: function () {} },
    fetch: async function (url, init) {
      const u = String(url);
      calls.push(u);
      const empty = { get: function () {
        return '';
      } };
      const answer = function (status, json) {
        return { status: status, headers: empty,
                 json: async function () {
                   return json;
                 } };
      };
      if (/\/oauth2\/token$/.test(u)) {
        const sent = new URLSearchParams(String((init && init.body) || ''));
        const nonce = nodeCrypto.createHash('sha256')
          .update('nonce:' + (sent.get('code_verifier') || ''))
          .digest('base64url');
        return answer(200, { access_token: 'at', expires_in: 300,
          refresh_token: 'rt',
          id_token: b64u({ alg: 'ES256' }) + '.' +
            b64u({ sub: 'urn:uuid:alice', nonce: nonce }) + '.sig' });
      }
      if (/\/account-api\/me$/.test(u)) {
        return answer(200, { user: { username: 'alice' },
                             locale: { offered: [] }, version: {} });
      }
      if (u.indexOf('/account-api/self-issued/did?subject=' +
                    encodeURIComponent(DID)) >= 0) {
        return answer(200, { ok: true, subject: DID,
                             document: { id: DID, fresh: 'tab' } });
      }
      return answer(404, {});
    }
  };
  const rt = new PortalRuntime(env);
  await rt.route();
  const saved = JSON.parse(store['sts-portal-signin'] || '{}');
  const authorize = location.assigned.filter(function (u) {
    return /\/oauth2\/authorize\?/.test(u);
  })[0];
  t.check(!!authorize && saved.returnTo === '/portal/self-issued/did' +
            '?subject=' + encodeURIComponent(DID),
          '8e. a fresh tab on the sub-page signs in, to come back to it ' +
          'with its subject', JSON.stringify(saved));
  location.pathname = '/portal/callback';
  location.search = '?code=c&state=' +
    encodeURIComponent(new URL(authorize).searchParams.get('state'));
  await rt.route();
  t.check(location.pathname === '/portal/self-issued/did' &&
          body.innerHTML.indexOf('id="siop-did-document"') >= 0 &&
          body.innerHTML.indexOf('&quot;fresh&quot;: &quot;tab&quot;') >= 0 &&
          calls.some(function (u) {
            return u.indexOf('/account-api/self-issued/did?subject=') >= 0;
          }),
          '8f. and once signed in, the tab draws the DID page directly from ' +
          'its operation', location.pathname + ' ' +
          body.innerHTML.slice(0, 200) + ' ' + calls.join(' '));
  log.debug("Leaving didPageSections().");
}

async function run(t) {
  log.debug("Entering run().");
  const siop = require('../oid4vc/siop');
  t.log.info('=== 1. the name a wallet reports ===');
  nameSections(t, siop);
  t.log.info('=== 2. the Request Object endpoint, in a child ===');
  kit.inAChild(t, childMain, 'self-issued-location');
  t.log.info('=== 3. the stored shape ===');
  storeSections(t, siop);
  t.log.info('=== 4. the portal page ===');
  pageSections(t, siop);
  t.log.info('=== 5. the console ===');
  consoleSections(t);
  t.log.info('=== 6. rows told apart, and the DID document link ===');
  linkSections(t, siop);
  t.log.info('=== 7. GET /account-api/self-issued/did, in a child ===');
  kit.inAChild(t, didChildMain, 'self-issued-did');
  t.log.info('=== 8. the DID page, and a fresh tab ===');
  await didPageSections(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'self_issued_location',
  describe: '/portal/self-issued draws each subject on one line with its ' +
            'whole value on hover, and where each key came from: the web ' +
            'wallet (told apart by a marker on its request_uri that changes ' +
            'nothing the endpoint answers), the wallet app\'s reported ' +
            'name, the browser, or an administrator',
  run: run
};
