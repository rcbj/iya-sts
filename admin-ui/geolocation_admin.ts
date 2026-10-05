// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin-ui/geolocation_admin.ts
//
// ===========================================================================
// MONITORING → GEOLOCATION (#255, 2026-09-26): where the realm's people
// signed in from, as a map — the world, then a continent, then a country and
// its cities — with the same numbers in tables under it.
//
// WHAT IS COUNTED is what risk scoring already recorded: every assessment
// (`risk/risk_engine.ts`) carries the country, subdivision, city and
// coordinates the active geolocation dataset gave its address, and the store
// counts them (`risk_store.ts`'s `geography()`). Nothing here looks an
// address up, and no address reaches this file — the store keeps it sealed
// and never answers it. rcbj's four decisions, on the ticket:
//
//   1. **BOTH MEANINGS OF "SIGNED IN"**, by the window selector: LIVE
//      SESSIONS (the default) — the realm's live sessions, each at its
//      latest assessment, which is where the person is now — or the distinct
//      people over the last 24 hours, 7 days or 30 days, wherever they were.
//   2. **NATURAL EARTH, VENDORED** for the outlines (`geo_map.ts`).
//   3. **WORLD → CONTINENT → COUNTRY → CITIES.** Each level is a link on
//      the map and in the tables; the page draws one level at a time.
//   4. **SMALL COUNTS ARE SUPPRESSED** (`risk.geoMinimumCount`, 3): a city
//      with fewer people is not drawn or listed — it is counted in its
//      country's "other" line — and a country, continent or total with
//      fewer is shaded and carries no number. The management API applies
//      the same rule; it is the same function. This is personal data, and a
//      city with one person in it names that person to anyone who knows where
//      they live.
//
// PEOPLE ARE COUNTED AT EVERY LEVEL, NEVER SUMMED: a person seen in Lyon and
// Paris is one person in France, so a country's number is not its cities'
// total and the page never says it is.
//
// A REALM ADMINISTRATOR SEES IT for their realm, as they see Monitoring →
// Risk: the page is the realm it is drawn in (`/realm/<id>/admin/geolocation`)
// and nothing in the request names another. Rule 7: `GET
// /admin-api/geolocation` answers `geoView()`, the function the page draws.
// ===========================================================================

import admin = require('./admin');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import config = require('../common/config');
import InstanceSlot = require('../common/instance_slot');
import riskDatasets = require('../risk/risk_datasets');
import riskEngine = require('../risk/risk_engine');
import geoMap = require('./geo_map');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import GeolocationPage = require('./web_geolocation');

type Req = any;
type Res = any;
type Json = any;

/**
 * The console path of Monitoring → Geolocation.
 */
const PAGE = '/admin/geolocation';

// The windows, by the name the query carries; `live` is not a span.
/**
 * The windows by the name the query carries, each with its span in
 * milliseconds; `live` (the realm's live sessions) is not a span.
 */
const WINDOWS: Record<string, number> = {
  'live': 0, '24h': 86400000, '7d': 7 * 86400000, '30d': 30 * 86400000 };
// The renderer's (#446), read back: the page names them and this
// module answers queries in them.
const WINDOW_LABELS = GeolocationPage.WINDOW_LABELS;
// The renderer's (#446), read back: the page names them and this
// module answers queries in them.
const DEFAULT_WINDOW = GeolocationPage.DEFAULT_WINDOW;

// Where each continent's total is written on the world map: inside it, on
// land, and clear of the others. Antarctica is below the world view's edge
// and is labelled only on its own.
const CONTINENT_LABELS: Record<string, number[]> = {
  'africa': [18, 8], 'antarctica': [0, -72], 'asia': [88, 46],
  'europe': [22, 55], 'north-america': [-102, 44],
  'oceania': [134, -25], 'south-america': [-60, -14] };

interface GeolocationAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  errorCodes: typeof errorCodes;
  realms: typeof realms;
  config: typeof config;
  datasets: typeof riskDatasets;
  engine: typeof riskEngine;
  geo: typeof geoMap;
}

/**
 * Monitoring → Geolocation: where the realm's people signed in from, as a map
 * of the world, a continent or a country and its cities, with the same numbers
 * in tables under it.
 */
class GeolocationAdmin {
  /**
   * See the module's `PAGE`.
   */
  static readonly PAGE = PAGE;
  /**
   * See the module's `WINDOWS`.
   */
  static readonly WINDOWS = WINDOWS;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the console, settings, the risk datasets and engine, and the
   * map
   */
  constructor(private readonly deps: GeolocationAdminDeps) {
    deps.log.debug("Entering GeolocationAdmin.constructor().");
    deps.log.debug("Leaving GeolocationAdmin.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): GeolocationAdminDeps {
    helpers.log.debug("Entering GeolocationAdmin.defaultDeps().");
    helpers.log.debug("Leaving GeolocationAdmin.defaultDeps().");
    return {
      log: helpers.log,
      admin: admin,
      errorCodes: errorCodes,
      realms: realms,
      config: config,
      datasets: riskDatasets,
      engine: riskEngine,
      geo: geoMap
    };
  }

  // One query parameter as a string: the console tolerates a repeated one
  // (`admin.ts`'s CONSOLE_QUERY), and the first is the one meant.
  /**
   * Reads one query parameter as a string; of a repeated one, the first.
   *
   * @param query - the query's values
   * @param name - the parameter's name
   * @returns the value, or ''
   */
  static param(query: Json, name: string): string {
    helpers.log.debug("Entering GeolocationAdmin.param().");
    const raw = query ? query[name] : undefined;
    helpers.log.debug("Leaving GeolocationAdmin.param().");
    return String((Array.isArray(raw) ? raw[0] : raw) || '').trim();
  }

  // What the query asks for, or why it cannot be answered. A country names
  // its continent; naming a different one as well is refused rather than
  // one of the two silently winning.
  private scopeOf(query: Json): Json {
    const { log, geo } = this.deps;
    log.debug("Entering GeolocationAdmin.scopeOf().");
    const window = GeolocationAdmin.param(query, 'window') || DEFAULT_WINDOW;
    const continent = GeolocationAdmin.param(query, 'continent')
      .toLowerCase();
    const country = GeolocationAdmin.param(query, 'country').toUpperCase();
    const refuse = function (why: string): Json {
      log.debug("Leaving GeolocationAdmin.scopeOf(). Refused.");
      return { ok: false, errorCode: 'STS-RISK-0042', errors: [why] };
    };
    if (!Object.prototype.hasOwnProperty.call(WINDOWS, window)) {
      return refuse('window must be one of ' +
                    Object.keys(WINDOWS).join(', ') + '.');
    }
    if (continent && !geo.CONTINENTS[continent]) {
      return refuse('continent must be one of ' +
                    Object.keys(geo.CONTINENTS).join(', ') + '.');
    }
    let found: Json = null;
    if (country) {
      found = geo.countries().byIso.get(country) || null;
      if (!found) {
        return refuse('country "' + country + '" is not an ISO 3166-1 ' +
                      'alpha-2 code on the map.');
      }
      if (continent && geo.slugOf(found.continent) !== continent) {
        return refuse(found.name + ' is in ' + found.continent + ', not ' +
                      geo.CONTINENTS[continent].name + '.');
      }
    }
    log.debug("Leaving GeolocationAdmin.scopeOf().");
    return { ok: true, window: window,
             level: found ? 'country' : (continent ? 'continent' : 'world'),
             continent: found ? geo.slugOf(found.continent) : continent,
             country: found };
  }

  // -------------------------------------------------------------------------
  // THE VIEW: what `GET /admin/geolocation?format=json` and `GET
  // /admin-api/geolocation` both answer, suppression applied. A refusal is
  // `{ ok: false, errorCode, errors }`.
  // -------------------------------------------------------------------------
  /**
   * Builds the view `GET /admin/geolocation?format=json` and `GET
   * /admin-api/geolocation` both answer, with counts below
   * `risk.geoMinimumCount` suppressed.
   *
   * @param query - `window`, `continent` and `country`
   * @returns the level drawn, its total and every place counted, or `{ ok:
   * false, errorCode, errors }`
   */
  async geoView(query: Json): Promise<Json> {
    const { log, realms, config, datasets, engine, geo } = this.deps;
    log.debug("Entering GeolocationAdmin.geoView().");
    const scope = this.scopeOf(query);
    if (!scope.ok) {
      log.debug("Leaving GeolocationAdmin.geoView(). Refused.");
      return scope;
    }
    const realm = realms.currentId() || 'default';
    const k = Math.max(1, Number(config.value('risk.geoMinimumCount')) || 1);
    const counted = await engine.geography(realm, {
      live: scope.window === 'live', windowMs: WINDOWS[scope.window],
      continents: geo.continentTable() });
    const byIso = geo.countries().byIso;
    const shown = function (row: Json): Json {
      const suppressed = !row || row.people < k;
      return { people: suppressed ? null : row.people,
               signIns: suppressed ? null : row.signIns,
               suppressed: suppressed && !!row && row.people > 0,
               lastAt: row ? row.lastAt : 0 };
    };
    const rows: Json[] = counted.rows;
    const at = function (level: string): Json[] {
      return rows.filter(function (r: Json): boolean {
        return r.level === level;
      });
    };
    const world = at('world')[0] || { people: 0, signIns: 0, lastAt: 0 };
    // THE TOTAL OF THE PLACE DRAWN: the world, the continent or the country.
    const scoped = scope.level === 'world' ? world
      : (at(scope.level).filter(function (r: Json): boolean {
        return scope.level === 'country'
          ? r.country === scope.country.iso
          : geo.slugOf(r.continent) === scope.continent;
      })[0] || null);
    const continents = Object.keys(geo.CONTINENTS).map(function (s: string) {
      const name = geo.CONTINENTS[s].name;
      const row = at('continent').filter(function (r: Json): boolean {
        return r.continent === name;
      })[0];
      return Object.assign({ continent: s, name: name }, shown(row));
    });
    const countries = at('country').filter(function (r: Json): boolean {
      return !!r.country && (scope.level === 'world' ||
        (scope.level === 'continent'
          ? geo.slugOf(r.continent) === scope.continent
          : r.country === scope.country.iso));
    }).map(function (r: Json): Json {
      const c = byIso.get(r.country);
      // A CODE THE MAP DOES NOT HAVE (#311): DB-IP answers `ZZ` for an
      // address it cannot place, and a row for it linked to
      // ?country=ZZ, which scopeOf() refuses (400). It is kept — those
      // sign-ins happened — but named as what it is, and not linked.
      return Object.assign({ iso: r.country, onMap: !!c,
                             name: c ? c.name
                                     : r.country + ' (not on the map)',
                             continent: geo.slugOf(r.continent) }, shown(r));
    }).sort(function (a: Json, b: Json): number {
      return (b.people || 0) - (a.people || 0) || (a.name < b.name ? -1 : 1);
    });
    // Where nothing said where: an address no active dataset placed.
    const unknown = shown(at('country').filter(function (r: Json): boolean {
      return !r.country;
    })[0]);
    // THE CITIES of the country asked about, the small ones held back.
    const cities: Json[] = [];
    const hidden = { cities: 0, signIns: 0 };
    let countryOnly: Json = null;
    if (scope.level === 'country') {
      at('city').filter(function (r: Json): boolean {
        return r.country === scope.country.iso;
      }).forEach(function (r: Json): void {
        if (!r.city) {
          // The country dataset answered, or the city dataset had no city.
          countryOnly = shown(r);
          return;
        }
        if (r.people < k) {
          hidden.cities++;
          hidden.signIns += r.signIns;
          return;
        }
        cities.push({ city: r.city, subdivision: r.subdivision,
                      latitude: r.latitude, longitude: r.longitude,
                      people: r.people, signIns: r.signIns,
                      lastAt: r.lastAt });
      });
      cities.sort(function (a: Json, b: Json): number {
        return b.people - a.people || (a.city < b.city ? -1 : 1);
      });
    }
    const registry = await datasets.registry(realm);
    const geoSets = registry.datasets.filter(function (d: Json): boolean {
      return d.kind === 'geo';
    });
    const providers = geoSets.filter(function (d: Json): boolean {
      return d.state !== 'empty';
    }).map(function (d: Json): string {
      return d.provider;
    });
    log.debug("Leaving GeolocationAdmin.geoView().");
    const view: Json = {
      ok: true,
      realm: realm,
      window: scope.window,
      windows: Object.keys(WINDOWS),
      level: scope.level,
      continent: scope.continent ? { continent: scope.continent,
        name: geo.CONTINENTS[scope.continent].name } : null,
      country: scope.country ? { iso: scope.country.iso,
                                 name: scope.country.name } : null,
      minimumCount: k,
      database: counted.database,
      since: counted.since,
      liveSessions: counted.liveSessions,
      total: shown(scoped),
      world: shown(world),
      continents: continents,
      countries: countries,
      unknown: unknown,
      cities: cities,
      countryOnly: countryOnly,
      hidden: hidden,
      datasets: geoSets.map(function (d: Json): Json {
        return { dataset: d.dataset, title: d.title, state: d.state,
                 version: d.activeVersion };
      }),
      attributions: (registry.attributions || []).filter(function (a: Json) {
        return providers.indexOf(a.provider) >= 0;
      }),
      outlines: geo.countries().source
    };
    // THE MAP, LAID OUT HERE (#446): the outlines, the projection and the
    // labels' places are this process's, and a page drawn from this answer
    // has none of them. So the picture is part of the answer — markup and
    // its legend, as `/admin-api/delegation/map` answers its drawing — with
    // the colour a place with no data is painted.
    view.drawing = this.drawing(view);
    view.noDataColour = geo.NO_DATA;
    return view;
  }

  // The picture, from the view: which countries are filled how dark, what
  // each links to, the labels and the cities.
  /**
   * Builds the picture from the view: which countries are filled how dark, what
   * each links to, the labels and the cities.
   *
   * @param v - `geoView()`'s answer
   * @returns the picture (`geo_map.ts`'s drawing) and its legend
   */
  drawing(v: Json): Json {
    const { log, geo } = this.deps;
    const self = this;
    log.debug("Entering GeolocationAdmin.drawing().");
    const byIso = geo.countries().byIso;
    const max = Math.max(0, ...v.countries.map(function (c: Json): number {
      return c.people || 0;
    }));
    const areas: Json = {};
    v.countries.forEach(function (c: Json): void {
      const bucket = c.people !== null ? geo.bucketOf(c.people, max)
        : (c.suppressed ? 1 : 0);
      if (!bucket) {
        return;
      }
      areas[c.iso] = {
        bucket: bucket,
        title: c.name + ': ' +
          GeolocationPage.countText(c.people, c.suppressed, v.minimumCount) +
          ' ' + (c.people === 1 ? 'person' : 'people') +
          (c.signIns !== null ? ', ' + c.signIns + ' sign-in(s)' : '') };
    });
    const linkFor = function (iso: string): string {
      const c = byIso.get(iso);
      if (!c) {
        return '';
      }
      return v.level === 'world'
        ? GeolocationPage.hrefOf(v.window, geo.slugOf(c.continent))
        : GeolocationPage.hrefOf(v.window, '', iso);
    };
    let labels: Json[] = [];
    if (v.level === 'world') {
      labels = v.continents.filter(function (c: Json): boolean {
        return c.people !== null || c.suppressed;
      }).map(function (c: Json): Json {
        const p = CONTINENT_LABELS[c.continent];
        return { lon: p[0], lat: p[1],
                 text: c.name + (c.people !== null ? ' · ' + c.people : ''),
                 href: GeolocationPage.hrefOf(v.window, c.continent) };
      });
    } else if (v.level === 'continent') {
      labels = v.countries.filter(function (c: Json): boolean {
        return c.people !== null && byIso.has(c.iso);
      }).map(function (c: Json): Json {
        const p = byIso.get(c.iso).label;
        return { lon: p[0], lat: p[1], text: c.name + ' · ' + c.people,
                 href: GeolocationPage.hrefOf(v.window, '', c.iso) };
      });
    }
    const cities = v.cities.filter(function (c: Json): boolean {
      return typeof c.latitude === 'number' &&
        typeof c.longitude === 'number';
    }).map(function (c: Json): Json {
      return { lon: c.longitude, lat: c.latitude, name: c.city,
               people: c.people,
               title: c.city + (c.subdivision ? ', ' + c.subdivision : '') +
                 ': ' + c.people + ' ' +
                 (c.people === 1 ? 'person' : 'people') + ', ' + c.signIns +
                 ' sign-in(s)' };
    });
    log.debug("Leaving GeolocationAdmin.drawing().");
    return {
      picture: geo.render({
        level: v.level, continent: v.continent && v.continent.continent,
        iso: v.country && v.country.iso, areas: areas, linkFor: linkFor,
        labels: labels, cities: cities,
        title: 'Where people signed in from: ' + (v.country
          ? v.country.name : (v.continent ? v.continent.name : 'the world')) +
          ', ' + WINDOW_LABELS[v.window].toLowerCase() }),
      legend: geo.legendOf(max)
    };
  }

  // DRAWN BY `web_geolocation.ts` (#446): this page is converted for the
  // static console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  html(v: Json): string {
    const { log } = this.deps;
    log.debug("Entering GeolocationAdmin.html().");
    const drawn = GeolocationPage.render(JSON.parse(JSON.stringify(v)));
    log.debug("Leaving GeolocationAdmin.html().");
    return drawn;
  }

  /**
   * Registers `GET /admin/geolocation`.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function }): void {
    const { log, admin, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering GeolocationAdmin.registerRoutes().");
    app.get(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + PAGE + '.');
      self.geoView(req.query).then(function (view: Json): void {
        if (!view.ok) {
          errorCodes.mark(res, 'STS-RISK-0042');
          res.status(400).type('text/html').set('Cache-Control', 'no-store')
             .send(admin.page('Bad request', PAGE, '<div class="card">' +
               '<h2>Bad request</h2><p>' + admin.esc(view.errors.join(' ')) +
               '</p><p><a href="' + PAGE + '">The world map</a></p></div>',
               null, null, req));
          log.debug('Leaving GET ' + PAGE + '. Refused.');
          return;
        }
        const up = view.level === 'world' ? undefined
          : admin.upTo(PAGE, view.country ? view.country.name
                                          : view.continent.name,
                       view.window === DEFAULT_WINDOW ? {}
                         : { window: view.window });
        admin.respond(req, res, view, 'Geolocation', PAGE,
                      admin.messagesOf(req) + self.html(view), up);
        log.debug('Leaving GET ' + PAGE + '.');
      }).catch(function (e: Json): void {
        log.warn(errorCodes.tag('STS-RISK-0041') + 'geolocation: the page ' +
                 'could not be drawn: ' + ((e && e.stack) || e));
        errorCodes.mark(res, 'STS-RISK-0041');
        res.status(500).type('text/plain')
           .send('The geolocation page could not be drawn: ' +
                 ((e && e.message) || e));
        log.debug('Leaving GET ' + PAGE + '. Failed.');
      });
    });
    log.debug("Leaving GeolocationAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<GeolocationAdmin>(
  'admin-ui/geolocation_admin',
  () => new GeolocationAdmin(GeolocationAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Monitoring → Geolocation, `/admin/geolocation`: where the realm's people
 * signed in from, counted from what risk scoring recorded, drawn as a map and
 * tabled under it.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  GeolocationAdmin: GeolocationAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: GeolocationAdmin): void =>
    slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  WINDOWS: WINDOWS,
  hrefOf: GeolocationPage.hrefOf,
  geoView: slot.forward('geoView'),
  drawing: slot.forward('drawing'),
  html: slot.forward('html')
};
