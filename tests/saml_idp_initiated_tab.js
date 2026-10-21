// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: saml_idp_initiated_tab.js
//
// ===========================================================================
// PROTOCOLS → SAML → IdP-Initiated SSO, AND THE OPERATION IT IS DRAWN FROM
// (#749).
//
// `GET /admin-api/saml-idp-initiated` lists the realm's SAML 2.0 and SAML
// 1.1 applications for which an identity-provider-initiated sign-in would be
// ALLOWED — asked through `LaunchLinks.enabled()`, the function the
// `/launch/{app}` door asks — one row per application and family, with the
// `/launch` link, the protocol's own endpoint and what the link lacks; the
// tab draws it. Held here, in a child process, calling the operation's
// handler directly (the gate is `tests/vendored/admin_api.js`'s to hold):
//
//   a. with both realm settings off (the default), only an entry whose own
//      override is TRUE is listed, in its family alone; a WS-Federation
//      entry with its switch on is not a SAML row; an entry with no
//      assertion consumer service is listed with what it is missing; and
//      every row the operation lists is one the door's own predicate says
//      is on, and every row it leaves out is one it says is off;
//   b. with the realm's `saml2.idpInitiatedSso` on, an entry with nothing on
//      it joins, an entry whose override is FALSE stays out, and SAML 1.1 is
//      still governed by its own setting;
//   c. the rows' link is `LaunchLinks.launchUrl()`'s, `/launch/{app}?
//      protocol=…`, and the endpoint `/saml2/unsolicited/…` or
//      `/saml11/sso/…`;
//   d. paging: `per` and `idpInitiatedPage` page the list by identifier, a
//      page past the end is the last page, and the paging names
//      `idpInitiatedPage`, not the SAML 2.0 tab's `page`;
//   e. realm isolation: a realm sees only its own applications, its own
//      switches, and links under its own prefix;
//   f. the tab: with nothing on, it says so and how to turn it on rather
//      than drawing an empty table; with rows, the identifier links to the
//      application's page, the link opens in a new tab with the console's
//      copy button, and the pager carries `idpInitiatedPage`; and the SAML
//      page composes the operation and draws the tab between the SAML 1.1
//      IdP and Assertions tabs.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'saml_idp_initiated_tab',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Run in a child process as a string (`node -e`), so it carries no
// Entering/Leaving pairs: the code style exempts a `node -e` child.
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SIT_ROOT;
  const OUT = process.env.SIT_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const helpers = require(ROOT + '/common/helpers');
    const applications = require(ROOT + '/common/applications');
    const LaunchLinks = require(ROOT + '/common/launch_links');
    const adminApi = require(ROOT + '/mgmt-api/admin_api');
    const WebKit = require(ROOT + '/admin-ui/web_kit');
    const WebPages = require(ROOT + '/admin-ui/web_pages');
    const SamlPage = require(ROOT + '/saml/web_saml');

    const OPERATION = '/admin-api/saml-idp-initiated';
    const entry = adminApi.ROUTES.filter(function (one) {
      return one.method === 'GET' && one.path === OPERATION &&
             typeof one.handler === 'function';
    })[0];
    note(!!entry && entry.operationId === 'getSamlIdpInitiatedApplications' &&
         entry.mirrors === 'GET /admin/saml2',
         '0. the operation is in the management API\'s route table, ' +
         'mirroring the SAML page',
         entry ? entry.operationId + ' ' + entry.mirrors : 'missing');
    if (!entry) {
      fs.writeFileSync(OUT, JSON.stringify(findings));
      process.exit(0);
    }
    const headers = { host: 'sts.example', accept: 'application/json' };
    const requestOf = function (query) {
      return {
        method: 'GET', query: query || {}, headers: headers, body: {},
        protocol: 'https', secure: true, hostname: 'sts.example',
        path: OPERATION, url: OPERATION, originalUrl: OPERATION,
        socket: { encrypted: true }, connection: {},
        get: function (name) {
          return headers[String(name).toLowerCase()];
        }
      };
    };
    // The handler, called with a request carrying only a query.
    const ask = function (query) {
      return new Promise(function (resolve, reject) {
        const req = requestOf(query);
        const res = {
          locals: {}, statusCode: 200,
          status: function (code) {
            this.statusCode = code;
            return this;
          },
          type: function () {
            return this;
          },
          set: function () {
            return this;
          },
          setHeader: function () {
            return this;
          },
          json: function (body) {
            resolve({ status: this.statusCode, body: body,
                      base: helpers.baseUrlOf(req) });
            return this;
          },
          send: function (body) {
            resolve({ status: this.statusCode,
                      body: typeof body === 'string' ? JSON.parse(body)
                                                     : body,
                      base: helpers.baseUrlOf(req) });
            return this;
          },
          end: function () {
            resolve({ status: this.statusCode, body: null });
            return this;
          }
        };
        Promise.resolve().then(function () {
          return entry.handler(req, res);
        }).catch(reject);
      });
    };
    const keysOf = function (answer) {
      return ((answer.body && answer.body.idpInitiated) || [])
        .map(function (row) {
          return row.identifier + '|' + row.protocol;
        });
    };

    // INVENTED FIXTURES: the identifiers and addresses below name nothing
    // outside this test.
    const ACS = 'https://sp.idpinit-tab.example/acs';
    const ON2 = 'urn:idpinit-tab:a-saml2-on';
    const PLAIN2 = 'urn:idpinit-tab:b-saml2-plain';
    const ON11 = 'urn:idpinit-tab:c-saml11-on';
    const BOTH = 'urn:idpinit-tab:d-both-saml2-on';
    const NOACS = 'urn:idpinit-tab:e-saml2-no-acs';
    const WSFED = 'urn:idpinit-tab:f-wsfed-on';
    const OFF2 = 'urn:idpinit-tab:g-saml2-off';
    const made = [
      applications.createApplication({ identifier: ON2, name: 'A on',
        protocols: ['saml2'],
        fields: { samlEntityId: ON2, samlAssertionConsumerService: [ACS],
                  saml2IdpInitiatedSso: 'TRUE' } }),
      applications.createApplication({ identifier: PLAIN2,
        protocols: ['saml2'],
        fields: { samlEntityId: PLAIN2,
                  samlAssertionConsumerService: [ACS] } }),
      applications.createApplication({ identifier: ON11,
        protocols: ['saml11'],
        fields: { samlEntityId: ON11, samlAssertionConsumerService: [ACS],
                  saml11IdpInitiatedSso: 'TRUE' } }),
      applications.createApplication({ identifier: BOTH,
        protocols: ['saml2', 'saml11'],
        fields: { samlEntityId: BOTH, samlAssertionConsumerService: [ACS],
                  saml2IdpInitiatedSso: 'TRUE' } }),
      applications.createApplication({ identifier: NOACS,
        protocols: ['saml2'],
        fields: { samlEntityId: NOACS, saml2IdpInitiatedSso: 'TRUE' } }),
      applications.createApplication({ identifier: WSFED,
        protocols: ['wsfed'],
        fields: { wsfedRealm: [WSFED],
                  wsfedReplyUrl: ['https://rp.idpinit-tab.example/ws'],
                  wsfedIdpInitiatedSso: 'TRUE' } }),
      applications.createApplication({ identifier: OFF2,
        protocols: ['saml2'],
        fields: { samlEntityId: OFF2, samlAssertionConsumerService: [ACS],
                  saml2IdpInitiatedSso: 'FALSE' } })
    ];
    note(made.every(function (one) { return one && one.ok !== false; }),
         '0b. (the seven applications are registered)',
         JSON.stringify(made).slice(0, 600));
    const ours = function (keys) {
      return keys.filter(function (key) {
        return key.indexOf('urn:idpinit-tab:') === 0;
      });
    };

    // --- a. both realm settings off (the default) ----------------------------
    let r = await ask({});
    const offKeys = ours(keysOf(r));
    note(r.status === 200 &&
         offKeys.join() === [ON2 + '|saml2', ON11 + '|saml11',
                             BOTH + '|saml2', NOACS + '|saml2'].join(),
         'a1. with the realm settings off, only entries whose own override ' +
         'is TRUE are listed, each in its own family, by identifier',
         r.status + ' ' + JSON.stringify(offKeys));
    note(r.body.realmSwitches.length === 2 &&
         r.body.realmSwitches.every(function (one) {
           return one.enabled === false;
         }) && r.body.realmSwitches[0].setting === 'saml2.idpInitiatedSso' &&
         r.body.realmSwitches[1].setting === 'saml11.idpInitiatedSso',
         'a2. the answer says both realm switches are off',
         JSON.stringify(r.body.realmSwitches));
    const rowOf = function (answer, id, protocol) {
      return (answer.body.idpInitiated || []).filter(function (row) {
        return row.identifier === id && row.protocol === protocol;
      })[0] || null;
    };
    const noAcs = rowOf(r, NOACS, 'saml2');
    note(noAcs && noAcs.missing.join() === 'samlAssertionConsumerService' &&
         rowOf(r, ON2, 'saml2').missing.length === 0,
         'a3. a row with nowhere to send the sign-in says what it lacks',
         JSON.stringify(noAcs));
    // The door's own predicate, over every SAML entry made here: listed
    // exactly where it says on.
    const expected = [];
    [ON2, PLAIN2, ON11, BOTH, NOACS, WSFED, OFF2].forEach(function (id) {
      LaunchLinks.protocolsOf(applications.get(id)).forEach(function (row) {
        if ((row.id === 'saml2' || row.id === 'saml11') &&
            LaunchLinks.enabled(id, row.id)) {
          expected.push(id + '|' + row.id);
        }
      });
    });
    note(expected.sort().join() === offKeys.slice().sort().join(),
         'a4. the list is exactly what LaunchLinks.enabled() says is on',
         JSON.stringify({ expected: expected, listed: offKeys }));

    // --- c. the link ---------------------------------------------------------
    const on2 = rowOf(r, ON2, 'saml2');
    const on11 = rowOf(r, ON11, 'saml11');
    note(on2 && on2.launchUrl === LaunchLinks.launchUrl(r.base, ON2, 'saml2') &&
         on2.launchUrl.indexOf('/launch/' + encodeURIComponent(ON2) +
                               '?protocol=saml2') > 0 &&
         on2.endpoint.indexOf('/saml2/unsolicited/') > 0 &&
         on2.label === 'SAML 2.0' && on2.name === 'A on' &&
         on2.attribute === 'saml2IdpInitiatedSso' &&
         on11 && on11.launchUrl.indexOf('?protocol=saml11') > 0 &&
         on11.endpoint.indexOf('/saml11/sso/') > 0,
         'c1. each row carries the /launch link and the protocol\'s own ' +
         'endpoint', JSON.stringify([on2, on11]));

    // --- b. the realm's SAML 2.0 setting on ----------------------------------
    config.setOverride('saml2.idpInitiatedSso', true);
    r = await ask({});
    const onKeys = ours(keysOf(r));
    note(onKeys.indexOf(PLAIN2 + '|saml2') >= 0 &&
         onKeys.indexOf(OFF2 + '|saml2') < 0 &&
         onKeys.indexOf(BOTH + '|saml11') < 0 &&
         onKeys.indexOf(ON11 + '|saml11') >= 0 &&
         onKeys.indexOf(WSFED + '|wsfed') < 0 &&
         r.body.realmSwitches[0].enabled === true &&
         r.body.realmSwitches[1].enabled === false,
         'b1. with saml2.idpInitiatedSso on, an entry with nothing on it ' +
         'joins, a FALSE override stays out, and SAML 1.1 keeps its own ' +
         'setting', JSON.stringify(onKeys));

    // --- d. paging -----------------------------------------------------------
    const all = keysOf(r);
    const page2 = await ask({ per: '2', idpInitiatedPage: '2' });
    const past = await ask({ per: '2', idpInitiatedPage: '999' });
    const pg = page2.body.idpInitiatedPaging;
    note(pg.param === 'idpInitiatedPage' && pg.perPage === 2 &&
         pg.page === 2 && pg.total === all.length &&
         pg.pages === Math.ceil(all.length / 2) &&
         keysOf(page2).join() === all.slice(2, 4).join(),
         'd1. per and idpInitiatedPage page the list, by identifier',
         JSON.stringify({ paging: pg, rows: keysOf(page2) }));
    note(past.body.idpInitiatedPaging.page === pg.pages &&
         keysOf(past).join() === all.slice((pg.pages - 1) * 2).join(),
         'd2. a page past the end is the last page',
         JSON.stringify(past.body.idpInitiatedPaging));
    const plainPage = await ask({ per: '2', page: '2' });
    note(plainPage.body.idpInitiatedPaging.page === 1,
         'd3. the SAML 2.0 tab\'s `page` does not move this list',
         JSON.stringify(plainPage.body.idpInitiatedPaging));
    config.setOverride('saml2.idpInitiatedSso', false);

    // --- e. realm isolation --------------------------------------------------
    const REALM = 'idpinittab';
    const created = realms.create({ id: REALM, name: REALM });
    note(created && created.ok, '0c. (the realm is created)',
         JSON.stringify(created && created.errors));
    const realm = realms.get(REALM);
    const IN_REALM = 'urn:idpinit-tab:realm-on';
    const inRealm = await realms.run(realm, async function () {
      const empty = await ask({});
      applications.createApplication({ identifier: IN_REALM,
        protocols: ['saml2'],
        fields: { samlEntityId: IN_REALM,
                  samlAssertionConsumerService: [ACS],
                  saml2IdpInitiatedSso: 'TRUE' } });
      config.setOverride('saml11.idpInitiatedSso', true);
      const one = await ask({});
      return { empty: empty, one: one };
    });
    note(ours(keysOf(inRealm.empty)).length === 0 &&
         inRealm.empty.body.realmSwitches.every(function (one) {
           return one.enabled === false;
         }),
         'e1. a realm lists none of the default realm\'s applications',
         JSON.stringify(keysOf(inRealm.empty)));
    const realmRow = rowOf(inRealm.one, IN_REALM, 'saml2');
    note(ours(keysOf(inRealm.one)).join() === IN_REALM + '|saml2' &&
         realmRow.launchUrl.indexOf('/realm/' + REALM + '/launch/') > 0 &&
         inRealm.one.body.realmSwitches[1].enabled === true,
         'e2. a realm lists its own, with links under its own prefix and ' +
         'its own switches', JSON.stringify(inRealm.one.body));
    r = await ask({});
    note(ours(keysOf(r)).indexOf(IN_REALM + '|saml2') < 0 &&
         r.body.realmSwitches[1].enabled === false,
         'e3. and the default realm sees neither the realm\'s application ' +
         'nor its setting', JSON.stringify(ours(keysOf(r))));

    // --- f. the tab ----------------------------------------------------------
    const ctx = WebKit.context({}, true);
    const t = ctx.t;
    const nothing = SamlPage.idpInitiatedBody(ctx, {
      idpInitiated: [], realmSwitches: inRealm.empty.body.realmSwitches,
      idpInitiatedPaging: inRealm.empty.body.idpInitiatedPaging });
    note(nothing.indexOf(t.html('consoleSaml.idpInitiated.offEverywhere')) >=
           0 &&
         nothing.indexOf('href="/admin/saml2#saml-tab-global-settings"') >=
           0 &&
         nothing.indexOf('<table') < 0,
         'f1. with nothing on, the tab says so and how to turn it on, and ' +
         'draws no table', nothing.slice(0, 1500));
    const drawn = SamlPage.idpInitiatedBody(WebKit.context(
      { per: '2', idpInitiatedPage: '2' }, true), page2.body);
    const first = page2.body.idpInitiated[0];
    note(drawn.indexOf('href="' + WebKit.esc('/admin/applications?' +
           'application=' + encodeURIComponent(first.identifier)) + '"') >=
           0 &&
         drawn.indexOf('href="' + WebKit.esc(first.launchUrl) +
                       '" target="_blank" rel="noopener noreferrer"') >= 0 &&
         drawn.indexOf('class="copybtn"') >= 0 &&
         drawn.indexOf('idpInitiatedPage=1') >= 0 &&
         drawn.indexOf('id="list-idpInitiatedPage"') >= 0,
         'f2. a row links its identifier to the application, opens its ' +
         'link in a new tab with a copy button, and the pager moves ' +
         'idpInitiatedPage', drawn.slice(0, 2500));
    const page = WebPages.pageFor('/admin/saml2');
    const asked = WebPages.composeRequests(page, { idpInitiatedPage: '3',
                                                   page: '2', per: '25' });
    const composed = asked.filter(function (one) {
      return one.member === 'idpInitiated';
    })[0];
    note(composed && composed.operation === OPERATION &&
         composed.params.idpInitiatedPage === '3' &&
         composed.params.per === '25' && !('page' in composed.params) &&
         WebPages.composeRequests(page, {}).some(function (one) {
           return one.member === 'idpInitiated';
         }),
         'f3. the SAML page always composes the operation, with its own ' +
         'page and the shared per', JSON.stringify(asked));

    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'saml-idp-initiated-tab-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SIT_ROOT: ROOT,
                           SIT_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'saml_idp_initiated_tab',
  describe: 'Protocols → SAML → IdP-Initiated SSO (#749): GET ' +
            '/admin-api/saml-idp-initiated lists the SAML 2.0 and SAML 1.1 ' +
            'applications the /launch door would answer, by its own ' +
            'predicate, paged and per realm, and the tab draws it',
  run: run
};
