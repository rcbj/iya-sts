// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: picture_svg.js
//
// ===========================================================================
// THE SVG AN ANSWER CARRIES, AFTER TRANSLATION (#1768).
//
// The console lays a picture out from the translated graph. The `svg`
// member used to be the English drawing of the same answer. `picture_svg.ts`
// redraws it, and only when the picture's inputs changed.
//
//   A. The federation map in French says "Ce service", matches the
//      browser's layout, and leaves the English bytes alone. `format=svg`
//      is that document with no links.
//   B. Every other delegation picture, the credential lineage included,
//      still draws, in English and after a French translation, and matches
//      the browser's layout.
//   C. Geolocation's `picture.svg` is the map the browser draws over the
//      outlines, and a French answer stays a map.
//   D. The PEP picture, which has no server SVG, still draws.
//
// In a child process, because it loads the whole protocol stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'picture_svg',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.PS_ROOT;
  const OUT = process.env.PS_OUT;
  const fs = require('fs');
  const path = require('path');
  const findings = [];
  const t = {
    check: function (ok, what, detail) {
      findings.push({ ok: !!ok, what: what,
                      detail: detail === undefined ? '' : String(detail) });
    }
  };
  const finish = function (err) {
    if (err) {
      findings.push({ ok: false, what: 'the child ran to the end',
                      detail: err && err.stack });
    }
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  };
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const adminViews = require(ROOT + '/admin-core/admin_views');
    const serverProse = require(ROOT + '/common/server_prose');
    const pictureSvg = require(ROOT + '/admin-ui/picture_svg');
    const DelegationPage = require(ROOT + '/admin-ui/web_delegation');
    const FederationPage = require(ROOT + '/federation/web_federation');
    const GeolocationPage = require(ROOT + '/admin-ui/web_geolocation');
    const geolocation = require(ROOT + '/admin-ui/geolocation_admin');
    const PepPicture = require(ROOT + '/xacml/web_pep_picture');
    const kit = require(ROOT + '/admin-ui/web_kit');

    const FED = '/admin-api/console/federation/map';
    const french = serverProse.translatorFor('fr', FED);
    t.check(!!french, 'A0. French negotiates for the federation map');

    // --- A. the federation map ----------------------------------------------
    const model = adminViews.federationMapModel({});
    const english = model.svg;
    const englishKey = model.mapKey;
    t.check(typeof english === 'string' && english.indexOf('<svg') === 0 &&
            english.indexOf('This service') >= 0 &&
            english === FederationPage.laidOut(model, true).svg,
            'A1. the English federation map is the browser\'s picture',
            english && english.length);
    const translated = serverProse.translateView(model, french);
    pictureSvg.align(model, translated, true);
    t.check(model.svg === english && model.mapKey === englishKey,
            'A2. aligning the translation leaves the English answer');
    t.check(translated.svg.indexOf('Ce service') >= 0 &&
            translated.svg !== english &&
            translated.svg === FederationPage.laidOut(translated, true).svg,
            'A3. the French svg is the browser\'s picture and says ' +
            'Ce service',
            translated.svg.indexOf('Ce service'));
    t.check(typeof translated.mapKey === 'string' &&
            translated.mapKey.length > 20,
            'A4. the key is still the server\'s markup',
            translated.mapKey && translated.mapKey.length);

    const bare = adminViews.federationMapModel({}, { links: false });
    const bareSvg = bare.svg;
    t.check(bareSvg.indexOf('<a') < 0 && bareSvg.indexOf('href=') < 0,
            'A5. format=svg in English has no links');
    pictureSvg.align(bare, bare, false);
    t.check(bare.svg === bareSvg,
            'A6. aligning an unchanged document keeps its bytes');
    const bareSrc = adminViews.federationMapModel({}, { links: false });
    const bareOut = serverProse.translateView(bareSrc, french);
    pictureSvg.align(bareSrc, bareOut, false);
    const bareLinks = bareOut.svg.indexOf('<a') < 0 &&
                      bareOut.svg.indexOf('href=') < 0;
    t.check(bareOut.svg.indexOf('Ce service') >= 0 && bareLinks &&
            bareOut.svg === FederationPage.laidOut(bareOut, false).svg &&
            bareSrc.svg.indexOf('href=') < 0,
            'A7. French format=svg matches the browser and has no links');

    // --- B. the other pictures ----------------------------------------------
    const pictures = [
      ['delegation map', adminViews.delegationMapModel({}),
       '/admin-api/console/delegation/map'],
      ['delegation user', adminViews.delegationUserModel({}),
       '/admin-api/delegation/user'],
      ['delegation application', adminViews.delegationApplicationModel({}),
       '/admin-api/delegation/application'],
      ['delegation chain', adminViews.delegationChainModel({}),
       '/admin-api/console/delegation/chain'],
      ['delegation cluster', adminViews.delegationClusterModel({}),
       '/admin-api/console/delegation/cluster'],
      ['delegation allowed', adminViews.delegationAllowedModel({}),
       '/admin-api/console/delegation/allowed'],
      ['credential lineage', adminViews.credentialLineageModel({}),
       '/admin-api/tokens/credential']
    ];
    pictures.forEach(function (row) {
      const name = row[0];
      const one = row[1];
      const route = row[2];
      const svg = one.svg;
      const browser = DelegationPage.laidOut(one, true).svg;
      t.check(typeof svg === 'string' && svg.indexOf('<svg') === 0 &&
              svg === browser,
              'B. ' + name + ' matches the browser',
              svg && svg.length);
      const tr = serverProse.translatorFor('fr', route);
      const fr = serverProse.translateView(one, tr);
      pictureSvg.align(one, fr, true);
      t.check(one.svg === svg &&
              fr.svg.indexOf('<svg') === 0 &&
              fr.svg === DelegationPage.laidOut(fr, true).svg,
              'B. ' + name + ' still matches after French',
              fr.svg && fr.svg.length);
    });

    // --- C. the geolocation map ---------------------------------------------
    const geoView = await geolocation.geoView({});
    const picture = geoView.drawing && geoView.drawing.picture;
    const outlines = JSON.parse(fs.readFileSync(path.join(ROOT,
      'admin-ui', 'natural_earth', 'countries.json'), 'utf8'));
    const mapSvg = GeolocationPage.mapSvg(Object.assign({}, geoView,
      { countryOutlines: outlines }));
    t.check(!!(picture && typeof picture.svg === 'string' &&
               picture.svg.indexOf('<svg') === 0 &&
               picture.svg.indexOf('id="geo-map"') >= 0 &&
               mapSvg.indexOf(picture.svg) >= 0),
            'C1. the geolocation picture is the browser\'s map',
            picture && picture.svg && picture.svg.length);
    const geoTr = serverProse.translatorFor('fr', '/admin-api/geolocation');
    const geoFr = serverProse.translateView(geoView, geoTr);
    const geoBefore = picture.svg;
    pictureSvg.align(geoView, geoFr, true);
    const geoMap = GeolocationPage.mapSvg(Object.assign({}, geoFr,
      { countryOutlines: outlines }));
    t.check(geoView.drawing.picture.svg === geoBefore &&
            geoFr.drawing.picture.svg.indexOf('<svg') === 0 &&
            geoFr.drawing.picture.svg.indexOf('id="geo-map"') >= 0 &&
            geoMap.indexOf(geoFr.drawing.picture.svg) >= 0,
            'C2. a French geolocation answer is still that map',
            geoFr.drawing.picture.svg.length);

    // --- D. the PEP picture, browser only -----------------------------------
    const pep = PepPicture.draw(kit.context({}, true).t, {
      name: 'demo-pep',
      listenerRows: [],
      proxy: { enabled: true, upstream: 'http://app:8080', routes: [] }
    }, null);
    t.check(typeof pep.svg === 'string' && pep.svg.indexOf('<svg') === 0 &&
            pep.svg.indexOf('class="pep-picture"') >= 0 &&
            pep.svg.indexOf('demo-pep') >= 0,
            'D. the PEP picture still draws', pep.svg && pep.svg.length);

    finish(null);
  })().catch(finish);
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'picture-svg-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', PS_ROOT: ROOT, PS_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1500))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'picture_svg',
  describe: 'An answer\'s svg is the console\'s picture in the caller\'s ' +
            'language (#1768), and the other console maps still draw',
  run: run
};
