'use strict';
//
// File: geolocation_map.js
//
// ===========================================================================
// MONITORING → GEOLOCATION (#255): the map, the count and the page.
//
//   A. THE OUTLINES AND THE GEOMETRY (`admin-ui/geo_map.ts`): the vendored
//      Natural Earth table has a row per code and seven continents; Equal
//      Earth is centred and symmetric; a country's view is its main
//      territory (France without Réunion, the United States with Alaska);
//      the scale's five steps cover every count up to the largest once.
//   B. THE COUNT (`risk/risk_store.ts`'s `geography()`, the memory half):
//      people are DISTINCT at every level — one person in two cities is one
//      person in their country — and live sessions count each session at
//      its latest assessment only.
//   C. THE VIEW (`admin-ui/geolocation_admin.ts`): rcbj's decision 4 — a
//      place under `risk.geoMinimumCount` has no number, and such a city is
//      left out and counted in `hidden`; the four refusals
//      (STS-RISK-0042); the live window reads `authn.sessionsForRisk()`.
//   D. THE PICTURE: no script; the world links each country to its
//      continent, a continent each country to its own view; a country draws
//      its numbered cities and not a suppressed one; the world's markup is
//      bounded.
//
// Every address is a documentation one and every place is invented data on
// a real map: no provider's data is in this file (`no_third_party_datasets`).
// In a child process, because it loads the whole protocol stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'geolocation_map',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.GM_ROOT;
  const OUT = process.env.GM_OUT;
  const fs = require('fs');
  const findings = [];
  const t = {
    check: function (ok, what, detail) {
      findings.push({ ok: !!ok, what: what,
                      detail: detail === undefined ? '' : String(detail) });
    }
  };
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const geo = require(ROOT + '/admin-ui/geo_map');
    const page = require(ROOT + '/admin-ui/geolocation_admin');
    const store = require(ROOT + '/risk/risk_store');
    const authn = require(ROOT + '/authn/authn');

    // --- A. the outlines and the geometry -----------------------------------
    const table = geo.countries();
    const continents = new Set(table.list.map(function (c) {
      return c.continent;
    }));
    t.check(table.list.length > 230 && continents.size === 7 &&
            table.byIso.get('FR').continent === 'Europe' &&
            table.byIso.get('SG').continent === 'Asia' &&
            table.byIso.get('AU').continent === 'Oceania' &&
            !table.byIso.has('-99') &&
            /public domain/i.test(table.source.license),
            'A1. a row per code, seven continents, the small states present, ' +
            'and the licence recorded', table.list.length + ' ' +
            Array.from(continents).join(','));
    const origin = geo.project(0, 0);
    const east = geo.project(180, 0);
    const west = geo.project(-180, 0);
    const north = geo.project(0, 90);
    t.check(origin[0] === 0 && origin[1] === 0 &&
            Math.abs(east[0] + west[0]) < 1e-12 && east[0] > 2.6 &&
            north[1] > 1.3,
            'A2. Equal Earth is centred and symmetric',
            JSON.stringify([east, north]));
    const france = geo.countryView(table.byIso.get('FR'), []);
    const us = geo.countryView(table.byIso.get('US'), []);
    t.check(france.east - france.west < 30 && france.south > 35 &&
            us.west + us.lon0 < -150 && us.north > 65,
            'A3. France\'s view is metropolitan France; the United States\' ' +
            'takes in Alaska', JSON.stringify([france, us]));
    const legend = geo.legendOf(250);
    const covered = legend.every(function (s, i) {
      return i === 0 ? s.from === 1 : s.from === legend[i - 1].to + 1;
    }) && legend[legend.length - 1].to === 250;
    t.check(covered && legend.length === 5 && geo.bucketOf(0, 250) === 0 &&
            geo.bucketOf(1, 250) === 1 && geo.bucketOf(250, 250) === 5,
            'A4. the five steps cover 1 to the largest once each',
            JSON.stringify(legend));

    // --- B. the count -------------------------------------------------------
    const REALM = 'geo-map-test';
    realms.create({ id: REALM, name: 'Geolocation map' });
    const now = Date.now();
    let n = 0;
    const seed = function (subject, session, country, city, lat, lon, ago) {
      n++;
      return store.recordAssessment({
        realm: REALM, id: 'a' + n, at: now - ago, phase: 'user',
        door: 'test', subject: subject, sessionId: session,
        addressPrefix: '192.0.2.0/24', country: country,
        subdivision: '', city: city, latitude: lat, longitude: lon,
        level: 'LOW', score: 0.1, signals: [] }, false);
    };
    // France: five people in Paris, one of whom was also in Lyon; one person
    // in Lille (under the minimum). Kenya: two people (under it). One person
    // no dataset placed.
    for (let i = 1; i <= 5; i++) {
      await seed('urn:uuid:p' + i, 's' + i, 'FR', 'Paris', 48.86, 2.35,
                 3600000);
    }
    await seed('urn:uuid:p1', 's1', 'FR', 'Lyon', 45.76, 4.84, 60000);
    await seed('urn:uuid:p6', 's6', 'FR', 'Lille', 50.63, 3.06, 60000);
    await seed('urn:uuid:p7', 's7', 'KE', 'Nairobi', -1.29, 36.82, 60000);
    await seed('urn:uuid:p8', 's8', 'KE', 'Nairobi', -1.29, 36.82, 60000);
    await seed('urn:uuid:p9', 's9', '', '', null, null, 60000);
    // Outside every window but the longest.
    await seed('urn:uuid:p10', 's10', 'JP', 'Tokyo', 35.68, 139.69,
               10 * 86400000);
    const all = await store.geography(REALM, {
      since: now - 86400000, continents: geo.continentTable() }, false);
    const row = function (rows, level, key, value) {
      return rows.filter(function (r) {
        return r.level === level && r[key] === value;
      })[0];
    };
    const fr = row(all.rows, 'country', 'country', 'FR');
    const paris = row(all.rows, 'city', 'city', 'Paris');
    const europe = row(all.rows, 'continent', 'continent', 'Europe');
    const world = row(all.rows, 'world', 'level', 'world');
    t.check(fr.people === 6 && fr.signIns === 7 && paris.people === 5 &&
            europe.people === 6 && world.people === 9 &&
            !row(all.rows, 'country', 'country', 'JP'),
            'B1. people are distinct at every level, and the window ends ' +
            'where it says', JSON.stringify([fr, paris, europe, world]));
    const live = await store.geography(REALM, {
      since: 0, sessionIds: ['s1', 's7'],
      continents: geo.continentTable() }, false);
    t.check(row(live.rows, 'world', 'level', 'world').people === 2 &&
            !row(live.rows, 'city', 'city', 'Paris') &&
            row(live.rows, 'city', 'city', 'Lyon').people === 1,
            'B2. a live session counts once, where its latest assessment ' +
            'placed it', JSON.stringify(live.rows));

    // --- C. the view --------------------------------------------------------
    config.setOverride('risk.geoMinimumCount', 3);
    const inRealm = function (fn) {
      return realms.run(realms.get(REALM), fn);
    };
    const worldView = await inRealm(function () {
      return page.geoView({ window: '24h' });
    });
    const ke = worldView.countries.filter(function (c) {
      return c.iso === 'KE';
    })[0];
    t.check(worldView.ok && worldView.total.people === 9 &&
            worldView.countries[0].iso === 'FR' &&
            worldView.countries[0].people === 6 &&
            ke.people === null && ke.signIns === null && ke.suppressed &&
            worldView.unknown.suppressed && worldView.unknown.people === null,
            'C1. a country under the minimum has no number and is marked ' +
            'suppressed; so is the unknown line', JSON.stringify(worldView)
              .slice(0, 600));
    const frView = await inRealm(function () {
      return page.geoView({ window: '24h', country: 'fr' });
    });
    t.check(frView.level === 'country' && frView.continent.continent ===
            'europe' && frView.cities.length === 1 &&
            frView.cities[0].city === 'Paris' &&
            frView.hidden.cities === 2 && frView.hidden.signIns === 2 &&
            JSON.stringify(frView).indexOf('Lille') < 0,
            'C2. a city under the minimum is left out, even by name, and ' +
            'counted in hidden', JSON.stringify(frView.cities) + ' ' +
            JSON.stringify(frView.hidden));
    const refusals = await inRealm(function () {
      return Promise.all([
        page.geoView({ window: '1y' }),
        page.geoView({ continent: 'atlantis' }),
        page.geoView({ country: 'ZZ' }),
        page.geoView({ country: 'FR', continent: 'asia' })]);
    });
    t.check(refusals.every(function (r) {
      return r.ok === false && r.errorCode === 'STS-RISK-0042';
    }), 'C3. an unknown window, continent or country, and a country with ' +
        'the wrong continent, are refused (STS-RISK-0042)',
            JSON.stringify(refusals));
    const saved = authn.sessionsForRisk;
    let liveView = null;
    try {
      authn.sessionsForRisk = function () {
        return ['s2', 's3', 's4', 'sX'].map(function (id) {
          return { realm: realms.get(REALM), id: id,
                   session: { id: id } };
        }).concat([{ realm: realms.get('default'), id: 's5',
                     session: { id: 's5' } }]);
      };
      liveView = await inRealm(function () {
        return page.geoView({});
      });
    } finally {
      authn.sessionsForRisk = saved;
    }
    t.check(liveView.window === 'live' && liveView.liveSessions === 4 &&
            liveView.total.people === 3 &&
            liveView.countries[0].people === 3,
            'C4. live sessions by default: this realm\'s, each once',
            JSON.stringify(liveView).slice(0, 400));

    // --- D. the picture -----------------------------------------------------
    const worldSvg = page.drawing(worldView).picture.svg;
    t.check(worldSvg.indexOf('<script') < 0 &&
            worldSvg.indexOf('href="/admin/geolocation?window=24h&amp;' +
                             'continent=europe"') >= 0 &&
            worldSvg.indexOf('Europe · 6') >= 0 &&
            worldSvg.length < 700000,
            'D1. the world has no script, links a country to its continent, ' +
            'numbers the continents, and is bounded', worldSvg.length);
    const euView = await inRealm(function () {
      return page.geoView({ window: '24h', continent: 'europe' });
    });
    const euSvg = page.drawing(euView).picture.svg;
    t.check(euSvg.indexOf('href="/admin/geolocation?window=24h&amp;' +
                          'country=FR"') >= 0 &&
            euSvg.indexOf('France · 6') >= 0,
            'D2. a continent links each country to its own view');
    const frSvg = page.drawing(frView).picture.svg;
    const html = page.html(frView);
    t.check(frSvg.indexOf('Paris · 5') >= 0 && frSvg.indexOf('Lille') < 0 &&
            (frSvg.match(/<circle /g) || []).length === 1 &&
            html.indexOf('id="geo-hidden"') >= 0 &&
            html.indexOf('Made with Natural Earth') >= 0 &&
            html.indexOf('id="geo-zoom-continent"') >= 0,
            'D3. a country draws its numbered cities only, and the page ' +
            'says what it held back and credits the outlines',
            frSvg.length);

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'geolocation-map-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', GM_ROOT: ROOT, GM_OUT: out }),
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
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'geolocation_map',
  describe: 'Monitoring → Geolocation (#255): the vendored outlines and the ' +
            'projection, people counted distinct at every level, live ' +
            'sessions at their latest assessment, small counts suppressed ' +
            'and small cities held back, the refusals, and a map with no ' +
            'script whose countries zoom by link',
  run: run
};
