// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: portal_tokens_and_keys.js
//
// ===========================================================================
// THE PORTAL'S TOKENS AND KEYS PAGE (#2053).
//
// One page, a tab per kind a person registers, in the console's order
// (#2052), each tab the existing portal card rather than a copy, and an SSH
// tab over `/account-api/ssh/*`. In process, against the renderers and the
// runtime's two pure parts:
//
//   1. the page is in the bundle and the column, drawn from its own GET, and
//      composes the MFA, OpenPGP and SSH operations;
//   2. the six tabs are drawn in order, the first shown while none is named;
//   3. each tab is the existing card: its forms post where the card's own
//      page posts, and the runtime's `members` maps each back to its tab;
//   4. the SSH tab lists, revokes and issues, and shows an issued
//      certificate once;
//   5. a list and a number in a form reach the API typed (`typedFields`).
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'portal_tokens_and_keys',
  level: process.env.LOG_LEVEL || 'info' });

const T = {
  html: function (key) {
    return key;
  },
  text: function (key) {
    return key;
  },
  has: function () {
    return true;
  },
  date: String,
  locale: 'en', lang: 'en', dir: 'ltr'
};

module.exports = {
  name: 'portal tokens and keys',
  describe: 'the portal\'s Tokens and keys page (#2053): a tab per kind, ' +
            'each the existing card, and SSH user certificates',
  run: async function (t) {
    log.debug('Entering run().');
    const Page = require('../portal/web_tokens_and_keys');
    const PortalPages = require('../portal/web_portal_pages');
    const PortalRuntime = require('../portal/web_portal_runtime');
    const TokensPages = require('../portal/web_tokens');
    const MfaPages = require('../portal/web_mfa');

    t.log.info('=== 1. the page ===');
    const row = PortalPages.find('/portal/tokens-and-keys');
    t.check(!!row && row.operation === '/account-api/tokens-and-keys' &&
            row.compose.mfa === '/account-api/mfa' &&
            row.compose.openpgp === '/account-api/openpgp' &&
            row.compose.ssh === '/account-api/ssh/certificates',
            '1. /portal/tokens-and-keys is drawn from its own GET and ' +
            'composes the three others', JSON.stringify(row || null));

    t.log.info('=== 2. six tabs ===');
    const view = {
      tokens: [], piv: { profiles: ['piv-auth'] }, escrowed: [],
      mfa: { hotp: {}, yubiotp: {} },
      openpgp: { key: null },
      ssh: { certificates: [{ serialHex: '0a', keyType: 'ssh-ed25519',
        keyFingerprint: 'SHA256:x', principals: ['erin'],
        issuedAt: '2026-11-23T00:00:00Z', notAfter: '2026-11-23T00:05:00Z',
        hardwareBound: false, authority: 'classical', revoked: false,
        revokedAt: '' }],
             lifetimes: { softwareSeconds: 300, hardwareSeconds: 3600 } }
    };
    const ctx = { t: T, query: {}, me: { user: { username: 'erin' } } };
    const html = Page.render(view, ctx);
    const ids = ['tk-hardware-tokens', 'tk-oath-tokens', 'tk-yubiotp',
                 'tk-piv', 'tk-ssh', 'tk-openpgp'];
    const links = ids.map(function (id) {
      return html.indexOf('href="#' + id + '"');
    });
    t.check(links.every(function (n, i) {
      return n >= 0 && (i === 0 || n > links[i - 1]);
    }) && html.indexOf('<section class="ptabpanel first" id="' + ids[0] +
                       '">') >= 0,
            '2. the six tabs in the console\'s order, the first shown by ' +
            'default', JSON.stringify(links));

    t.log.info('=== 3. the existing cards ===');
    t.check(html.indexOf(TokensPages.heldCard(view, T)) >= 0 &&
            html.indexOf(TokensPages.claimCard(T)) >= 0 &&
            html.indexOf(TokensPages.enrolCard(view, T)) >= 0 &&
            html.indexOf(MfaPages.hotpCard(view.mfa, T)) >= 0 &&
            html.indexOf(MfaPages.yubiCard(view.mfa, T)) >= 0,
            '3. each tab is the card its page used to draw');
    const actions = (html.match(/<form[^>]*action="([^"]+)"/g) || [])
      .map(function (f) { return /action="([^"]+)"/.exec(f)[1]; });
    const members = row.members || {};
    t.check(actions.length > 0 && actions.every(function (a) {
      return Object.prototype.hasOwnProperty.call(members, a);
    }) && members['/portal/tokens'] === '' &&
            members['/portal/mfa'] === 'mfa' &&
            members['/portal/openpgp'] === 'openpgp',
            '3. every form posts where its card always did, and each post ' +
            'path has the tab its answer goes back to',
            JSON.stringify({ actions: actions, members: members }));

    t.log.info('=== 4. SSH ===');
    t.check(html.indexOf('action="/portal/ssh/revoke"') >= 0 &&
            html.indexOf('name="serialHex" value="0a"') >= 0 &&
            html.indexOf('action="/portal/ssh" data-array="principals" ' +
                         'data-integer="lifetimeS"') >= 0 &&
            html.indexOf('name="principals" required maxlength="1024" ' +
                         'value="erin"') >= 0,
            '4. the SSH tab lists with Revoke and issues, the person\'s uid ' +
            'the default principal');
    const issued = Page.render(Object.assign({}, view, { sshAnswer: {
      ok: true, certificate: 'ssh-ed25519-cert-v01@openssh.com AAAA',
      serialHex: '0b' } }), ctx);
    t.check(issued.indexOf('id="ssh-issued"') >= 0 &&
            issued.indexOf('ssh-ed25519-cert-v01@openssh.com AAAA') >= 0 &&
            html.indexOf('id="ssh-issued"') < 0,
            '4. an issued certificate is shown once, from the answer');
    const refused = Page.render(Object.assign({}, view, {
      ssh: { ok: false, refused: true } }), ctx);
    t.check(refused.indexOf('portalTokens.tk.unavailable') >= 0,
            '4. a member that refused is a note on its tab');

    t.log.info('=== 5. typed fields ===');
    const form = { getAttribute: function (name) {
      return { 'data-array': 'principals',
               'data-integer': 'lifetimeS' }[name] || null;
    } };
    const fields = { principals: 'erin, admins', lifetimeS: '600',
                     publicKey: 'ssh-ed25519 AAAA' };
    PortalRuntime.typedFields(form, fields);
    const empty = { principals: 'erin', lifetimeS: '' };
    PortalRuntime.typedFields(form, empty);
    t.check(JSON.stringify(fields.principals) === '["erin","admins"]' &&
            fields.lifetimeS === 600 &&
            fields.publicKey === 'ssh-ed25519 AAAA' &&
            JSON.stringify(empty) === '{"principals":["erin"]}',
            '5. a list and a number reach the operation typed, an empty ' +
            'number left out', JSON.stringify([fields, empty]));

    t.log.info('=== 6. the two pages the column no longer lists ===');
    const nav = PortalPages.kit.navPages().map(function (item) {
      return item.path;
    });
    t.check(PortalPages.find('/portal/tokens') === null &&
            PortalPages.find('/portal/openpgp') === null &&
            nav.indexOf('/portal/tokens') < 0 &&
            nav.indexOf('/portal/openpgp') < 0 &&
            nav.indexOf('/portal/mfa') >= 0 &&
            PortalRuntime.MOVED['/portal/tokens'] ===
              '/portal/tokens-and-keys#tk-hardware-tokens' &&
            PortalRuntime.MOVED['/portal/openpgp'] ===
              '/portal/tokens-and-keys#tk-openpgp',
            '6. Security keys and OpenPGP are not pages; a bookmark of ' +
            'either opens its tab, and Authenticator app stays',
            JSON.stringify({ nav: nav, moved: PortalRuntime.MOVED }));
    log.debug('Leaving run().');
  }
};
