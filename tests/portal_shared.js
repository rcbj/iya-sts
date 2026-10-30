// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/portal_shared.js
//
// ---------------------------------------------------------------------------
// THE PORTAL'S SHARING SECTION (#1168 phase 3, #1192), in process, in a
// throwaway realm:
//
//   A. the column: one Sharing section, two pages; four operations, each
//      mirroring its page, for the person alone
//   B. /portal/shared's view: the person's resources with their shares,
//      paged; nobody else's
//   C. the form's acts through the operation: share, unshare, and the
//      refusals under their codes and statuses; each act audited without a
//      claim value
//   D. A01 — THE IDENTITY IS THE TOKEN'S: another person's resource cannot
//      be shared, another person's share cannot be removed, and the other
//      person's document is unchanged
//   E. /portal/shared-with-me lists the live RPT permissions the person
//      holds, not an expired one
//   F. the pages draw: a card per resource, the share form posting only
//      fields its operation takes, a Remove per share, the pager
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'portal_shared',
  level: process.env.LOG_LEVEL || 'info' });

async function run(t) {
  log.debug("Entering run().");
  require('../common/i18n');
  require('../common/app');
  const realms = require('../common/realms');
  const ldap = require('../ldap/ldap_server');
  const helpers = require('../common/helpers');
  const store = require('../uma/uma_store');
  const shared = require('../portal/portal_shared');
  const SharedPages = require('../portal/web_shared');
  const PortalKit = require('../portal/web_portal_kit');
  const kit = require('../admin-ui/web_kit');

  const audited = [];
  const ctx = {
    BASE: '/account-api', PORTAL: '/portal',
    translatorFor: function () {
      return { text: function (key, params) {
        return key + (params ? JSON.stringify(params) : '');
      } };
    },
    json: function (res, status, body) {
      return { status: status, body: body };
    },
    refuse: function (res, status, code, errors, extra) {
      return { status: status, code: code,
               body: Object.assign({ ok: false, errors: [].concat(errors) },
                                   extra || {}) };
    },
    audit: { audit: function (row) {
      audited.push(row);
    } }
  };

  // --- A. the column and the operations ----------------------------------
  const section = PortalKit.NAV.filter(function (one) {
    return one.key === 'sharing';
  })[0];
  t.check(section && section.items.map(function (one) {
    return one.path;
  }).join() === '/portal/shared,/portal/shared-with-me' &&
    SharedPages.PAGES.length === 2,
  'A1. Sharing is one section of the column, two pages under it');
  const module = new shared.PortalShared(shared.PortalShared.defaultDeps());
  const ops = module.accountOperations(ctx);
  t.check(ops.length === 3 && ops.every(function (op) {
    return op.access === 'person' &&
      op.mirrors === op.method + ' ' + op.path.replace('/account-api',
                                                       '/portal');
  }), 'A2. three operations, each mirroring its page, for the person ' +
      'alone', JSON.stringify(ops.map(function (op) {
        return op.method + ' ' + op.path;
      })));
  const post = ops.filter(function (op) {
    return op.method === 'POST';
  })[0];
  const call = function (who, body) {
    const parsed = post.body.safeParse(body);
    if (!parsed.success) {
      return { status: 400, schema: parsed.error.message };
    }
    return post.handler({}, {}, { username: who }, { body: parsed.data });
  };

  const id = 'portalsh-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  t.check(made.ok, 'a trust realm to work in', (made.errors || []).join(' '));
  if (!made.ok) {
    log.debug("Leaving run(). No realm.");
    return;
  }
  try {
    await realms.run(made.realm, async function () {
      ['ps-ann', 'ps-bob'].forEach(function (name) {
        ldap.createUser(name, { invent: false });
      });
      const ann = helpers.subjectForName('ps-ann');
      const bob = helpers.subjectForName('ps-bob');
      const photo = store.saveResource({ owner: ann, ownerKind: 'user',
        resourceServer: 'photos', resource_scopes: ['view', 'edit'],
        name: 'Holiday', type: 'https://example.com/photo' });
      const bobs = store.saveResource({ owner: bob, ownerKind: 'user',
        resourceServer: 'photos', resource_scopes: ['view'] });
      for (let i = 0; i < 21; i += 1) {
        store.saveResource({ owner: ann, ownerKind: 'user',
          resourceServer: 'bulk', resource_scopes: ['read'],
          name: 'Item ' + i });
      }

      // --- B ----------------------------------------------------------
      const first = module.view('ps-ann', 1);
      const second = module.view('ps-ann', 2);
      t.check(first.ok && first.resources.length === 20 &&
              first.paging.pages === 2 && first.paging.total === 22 &&
              second.resources.length === 2 &&
              first.resources[0].id === photo._id &&
              !first.resources.concat(second.resources).some(function (r) {
                return r.id === bobs._id;
              }) && first.enabled === false,
              'B1. the view pages the person\'s own resources, twenty a ' +
              'page, nobody else\'s, and says UMA is off',
              JSON.stringify(first.paging));

      // --- C ----------------------------------------------------------
      let r = call('ps-ann', { action: 'share', resource: photo._id,
        scope: ['view', 'edit'], recipientKind: 'person',
        recipient: 'ps-bob', expires: '', acr: '', askMe: 'on' });
      const card = r.body && r.body.view && r.body.view.resources[0] &&
        r.body.view.resources[0].shares[0];
      t.check(r.status === 200 && r.body.ok && card &&
              card.recipient.label === 'ps-bob' && card.askMe === true &&
              /doneShared/.test(r.body.message),
              'C1. a share through the operation answers the page\'s view ' +
              'with the new card', JSON.stringify(r));
      const claimShare = call('ps-ann', { action: 'share',
        resource: photo._id, scope: 'view', recipientKind: 'claim',
        claim: 'email', recipient: 'secret@example.com' });
      const row = audited[audited.length - 1] || {};
      t.check(claimShare.status === 200 && row.action === 'uma.share.add' &&
              JSON.stringify(row).indexOf('secret@example.com') < 0,
              'C2. each act is audited, never with a claim value',
              JSON.stringify(row));
      r = call('ps-ann', { action: 'share', resource: photo._id,
                           scope: 'delete', recipientKind: 'realm' });
      t.check(r.status === 400 && r.code === 'STS-UMA-0301' &&
              r.body.view && r.body.view.ok,
              'C3. a refusal answers 400 under its code, with the view',
              JSON.stringify(r).slice(0, 300));
      r = call('ps-ann', { action: 'alfa', alfa: 'namespace x {}' });
      t.check(r.status === 403 && r.code === 'STS-UMA-0306',
              'C4. ALFA while the realm does not allow it is 403');
      r = call('ps-ann', { action: 'share', resource: photo._id,
                           scope: 'view', recipientKind: 'nobody' });
      t.check(r.status === 400 && !!r.schema,
              'C5. a recipient kind the form does not offer fails the ' +
              'operation\'s schema');
      r = call('ps-ann', { action: 'unshare', share: card.id });
      t.check(r.status === 200 && r.body.ok &&
              r.body.view.resources[0].shares.length === 1 &&
              audited[audited.length - 1].action === 'uma.share.remove',
              'C6. unshare removes that share and no other',
              JSON.stringify(r).slice(0, 300));

      // --- D. A01 ------------------------------------------------------
      const bobShare = call('ps-bob', { action: 'share', resource: bobs._id,
        scope: 'view', recipientKind: 'realm' });
      const bobShareId = bobShare.body.view.resources[0].shares[0].id;
      const bobBefore = store.ownerPolicy(bob).document;
      r = call('ps-ann', { action: 'share', resource: bobs._id,
                           scope: 'view', recipientKind: 'realm' });
      const r2 = call('ps-ann', { action: 'unshare', share: bobShareId });
      t.check(r.status === 400 && r.code === 'STS-UMA-0300' &&
              r2.status === 400 && r2.code === 'STS-UMA-0308' &&
              store.ownerPolicy(bob).document === bobBefore,
              'D1. A01: another person\'s resource cannot be shared, nor ' +
              'their share removed, and their document is unchanged',
              JSON.stringify([r.code, r2.code]));

      // --- E ----------------------------------------------------------
      const now = Math.floor(Date.now() / 1000);
      store.saveRpt({ jti: 'ps-live-' + now, owners: [ann],
        requestingParty: bob, resourceServer: 'photos', client: 'viewer',
        exp: now + 600, permissions: [{ resource_id: photo._id,
                                        resource_scopes: ['view'] }] });
      store.saveRpt({ jti: 'ps-old-' + now, owners: [ann],
        requestingParty: bob, resourceServer: 'photos', client: 'viewer',
        exp: now - 5, permissions: [{ resource_id: photo._id,
                                      resource_scopes: ['edit'] }] });
      const withMe = module.withMe('ps-bob', 1);
      t.check(withMe.ok && withMe.rows.length === 1 &&
              withMe.rows[0].owner === 'ps-ann' &&
              withMe.rows[0].name === 'Holiday' &&
              withMe.rows[0].scopes.join() === 'view' &&
              module.withMe('ps-ann', 1).rows.length === 0,
              'E1. shared-with-me lists the live permissions the person ' +
              'holds, not an expired one, and nobody else\'s',
              JSON.stringify(withMe));

      // --- F ----------------------------------------------------------
      const page = SharedPages.render(module.view('ps-ann', 1),
                                      { t: kit.context().t, query: {} });
      const names = [];
      const re = /name="([^"]+)"/g;
      let m = re.exec(page);
      while (m) {
        if (names.indexOf(m[1]) < 0) {
          names.push(m[1]);
        }
        m = re.exec(page);
      }
      const taken = Object.keys(post.body.shape);
      const stray = names.filter(function (n) {
        return taken.indexOf(n) < 0;
      });
      t.check(page.indexOf('Holiday') >= 0 &&
              page.indexOf('action="/portal/shared"') >= 0 &&
              page.indexOf('value="unshare"') >= 0 &&
              page.indexOf('class="pagenav"') >= 0 && !stray.length,
              'F1. the page draws a card per resource, the share form and ' +
              'a Remove, the pager, and every field it posts is one its ' +
              'operation takes', stray.join(', ') || page.slice(0, 300));
      const mine = SharedPages.withMe(withMe, { t: kit.context().t,
                                                query: {} });
      t.check(mine.indexOf('Holiday') >= 0 && mine.indexOf('ps-ann') >= 0,
              'F2. shared-with-me draws the resource and its owner');
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'portal_shared',
  describe: 'the portal\'s Sharing section (#1168 phase 3): the column, the ' +
            'views, the acts and their refusals, A01, shared-with-me, and ' +
            'the pages',
  run: run
};
