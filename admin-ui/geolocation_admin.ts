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

type Req = any;
type Res = any;
type Json = any;

const PAGE = '/admin/geolocation';

// The windows, by the name the query carries; `live` is not a span.
const WINDOWS: Record<string, number> = {
  'live': 0, '24h': 86400000, '7d': 7 * 86400000, '30d': 30 * 86400000 };
const WINDOW_LABELS: Record<string, string> = {
  'live': 'Live sessions', '24h': 'Last 24 hours', '7d': 'Last 7 days',
  '30d': 'Last 30 days' };
const DEFAULT_WINDOW = 'live';

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

class GeolocationAdmin {
  static readonly PAGE = PAGE;
  static readonly WINDOWS = WINDOWS;

  constructor(private readonly deps: GeolocationAdminDeps) {
    deps.log.debug("Entering GeolocationAdmin.constructor().");
    deps.log.debug("Leaving GeolocationAdmin.constructor().");
  }

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
  static param(query: Json, name: string): string {
    helpers.log.debug("Entering GeolocationAdmin.param().");
    const raw = query ? query[name] : undefined;
    helpers.log.debug("Leaving GeolocationAdmin.param().");
    return String((Array.isArray(raw) ? raw[0] : raw) || '').trim();
  }

  // The page's own address for a window and a place, the default window
  // left out. Root-relative: `app.js` puts it in the realm.
  static hrefOf(window: string, continent?: string, country?: string): string {
    helpers.log.debug("Entering GeolocationAdmin.hrefOf().");
    const parts: string[] = [];
    if (window && window !== DEFAULT_WINDOW) {
      parts.push('window=' + encodeURIComponent(window));
    }
    if (country) {
      parts.push('country=' + encodeURIComponent(country));
    } else if (continent) {
      parts.push('continent=' + encodeURIComponent(continent));
    }
    helpers.log.debug("Leaving GeolocationAdmin.hrefOf().");
    return PAGE + (parts.length ? '?' + parts.join('&') : '');
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
      return Object.assign({ iso: r.country, name: c ? c.name : r.country,
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
    return {
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
  }

  // "12", or "fewer than 3" for a suppressed count, or "—" for none.
  private countText(n: number | null, suppressed: boolean): string {
    const { log, config } = this.deps;
    log.debug("Entering GeolocationAdmin.countText().");
    log.debug("Leaving GeolocationAdmin.countText().");
    if (n !== null) {
      return String(n);
    }
    return suppressed ? 'fewer than ' +
      Math.max(1, Number(config.value('risk.geoMinimumCount')) || 1) : '—';
  }

  // A time in UTC to the minute, or '' for none.
  static stamp(ms: number): string {
    helpers.log.debug("Entering GeolocationAdmin.stamp().");
    helpers.log.debug("Leaving GeolocationAdmin.stamp().");
    return ms ? new Date(ms).toISOString().slice(0, 16).replace('T', ' ') +
      ' UTC' : '';
  }

  // The picture, from the view: which countries are filled how dark, what
  // each links to, the labels and the cities.
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
        title: c.name + ': ' + self.countText(c.people, c.suppressed) +
          ' ' + (c.people === 1 ? 'person' : 'people') +
          (c.signIns !== null ? ', ' + c.signIns + ' sign-in(s)' : '') };
    });
    const linkFor = function (iso: string): string {
      const c = byIso.get(iso);
      if (!c) {
        return '';
      }
      return v.level === 'world'
        ? GeolocationAdmin.hrefOf(v.window, geo.slugOf(c.continent))
        : GeolocationAdmin.hrefOf(v.window, '', iso);
    };
    let labels: Json[] = [];
    if (v.level === 'world') {
      labels = v.continents.filter(function (c: Json): boolean {
        return c.people !== null || c.suppressed;
      }).map(function (c: Json): Json {
        const p = CONTINENT_LABELS[c.continent];
        return { lon: p[0], lat: p[1],
                 text: c.name + (c.people !== null ? ' · ' + c.people : ''),
                 href: GeolocationAdmin.hrefOf(v.window, c.continent) };
      });
    } else if (v.level === 'continent') {
      labels = v.countries.filter(function (c: Json): boolean {
        return c.people !== null && byIso.has(c.iso);
      }).map(function (c: Json): Json {
        const p = byIso.get(c.iso).label;
        return { lon: p[0], lat: p[1], text: c.name + ' · ' + c.people,
                 href: GeolocationAdmin.hrefOf(v.window, '', c.iso) };
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

  // One table: a place per row, linked to its own view when it has one.
  private table(id: string, head: string, rows: Json[],
                hrefOf: (row: Json) => string, extra?: string): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering GeolocationAdmin.table(). " + id);
    const esc = admin.esc.bind(admin);
    const body = rows.map(function (r: Json): string {
      const href = hrefOf(r);
      const name = esc(r.label);
      return '<tr><td>' + (href ? '<a href="' + esc(href) + '">' + name +
                           '</a>' : name) + '</td><td class="num">' +
        esc(self.countText(r.people, r.suppressed)) + '</td><td class="num">' +
        esc(r.signIns === null ? '' : String(r.signIns)) + '</td><td>' +
        esc(r.people === null ? '' : GeolocationAdmin.stamp(r.lastAt)) +
        '</td></tr>';
    }).join('');
    log.debug("Leaving GeolocationAdmin.table().");
    return '<table class="grid" id="' + id + '"><thead><tr><th>' + esc(head) +
      '</th><th>People</th><th>Sign-ins</th><th>Last seen</th></tr></thead>' +
      '<tbody>' + (body || '<tr><td colspan="4">Nobody here in this ' +
                   'window.</td></tr>') + (extra || '') + '</tbody></table>';
  }

  // The page's HTML.
  html(v: Json): string {
    const { log, admin, geo } = this.deps;
    const self = this;
    log.debug("Entering GeolocationAdmin.html(). level=" + v.level);
    const esc = admin.esc.bind(admin);
    const place = function (continent?: string, country?: string): string {
      return GeolocationAdmin.hrefOf(v.window, continent, country);
    };
    const windows = v.windows.map(function (w: string): string {
      const label = esc(WINDOW_LABELS[w]);
      return w === v.window ? '<strong>' + label + '</strong>'
        : '<a id="geo-window-' + w + '" href="' +
          esc(GeolocationAdmin.hrefOf(w, v.continent && v.continent.continent,
                                      v.country && v.country.iso)) + '">' +
          label + '</a>';
    }).join(' &middot; ');
    // The zoom trail: World › continent › country, every level above this
    // one a link. The console's own trail above the heading has one level
    // below the page, so the continent step is here.
    const crumbs: string[] = [v.level === 'world' ? '<strong>World</strong>'
      : '<a id="geo-zoom-world" href="' + esc(place()) + '">World</a>'];
    if (v.continent) {
      crumbs.push(v.level === 'continent'
        ? '<strong>' + esc(v.continent.name) + '</strong>'
        : '<a id="geo-zoom-continent" href="' +
          esc(place(v.continent.continent)) + '">' + esc(v.continent.name) +
          '</a>');
    }
    if (v.country) {
      crumbs.push('<strong>' + esc(v.country.name) + '</strong>');
    }
    const who = v.window === 'live'
      ? 'people signed in now, in ' + v.liveSessions + ' live session(s) ' +
        'with a risk assessment, each where its latest assessment placed it'
      : 'people who signed in over the ' +
        esc(WINDOW_LABELS[v.window].toLowerCase()) + ', wherever they were';
    const drawn = this.drawing(v);
    const legend = drawn.legend.map(function (s: Json): string {
      return '<span class="geo-swatch" style="display:inline-block;' +
        'width:14px;height:14px;border-radius:3px;vertical-align:middle;' +
        'margin:0 4px 0 12px;background:' + s.colour + '"></span>' +
        (s.from === s.to ? s.from : s.from + '–' + s.to);
    }).join('') + '<span style="display:inline-block;width:14px;height:14px;' +
      'border-radius:3px;vertical-align:middle;margin:0 4px 0 12px;' +
      'background:' + geo.NO_DATA + '"></span>none';
    const where = v.country ? ' in ' + esc(v.country.name)
      : (v.continent ? ' in ' + esc(v.continent.name) : '');
    const total = v.total.people !== null
      ? '<strong id="geo-total">' + v.total.people + '</strong> ' +
        (v.total.people === 1 ? 'person' : 'people')
      : '<strong id="geo-total">' + esc(this.countText(null,
                                                      v.total.suppressed)) +
        '</strong> people';
    const noPlace = v.datasets.every(function (d: Json): boolean {
      return d.state === 'empty';
    });
    let tables = '';
    if (v.level === 'world') {
      tables += '<h3>By continent</h3>' + this.table('geo-continents',
        'Continent', v.continents.map(function (c: Json): Json {
          return Object.assign({ label: c.name }, c);
        }), function (r: Json): string {
          return place(r.continent);
        });
    }
    if (v.level !== 'country') {
      const unknown = v.unknown.people !== null || v.unknown.suppressed
        ? '<tr><td><em>Location unknown</em></td><td class="num">' +
          esc(this.countText(v.unknown.people, v.unknown.suppressed)) +
          '</td><td class="num">' + esc(v.unknown.signIns === null ? ''
            : String(v.unknown.signIns)) + '</td><td></td></tr>' : '';
      tables += '<h3>By country</h3>' + this.table('geo-countries',
        'Country', v.countries.map(function (c: Json): Json {
          return Object.assign({ label: c.name }, c);
        }), function (r: Json): string {
          return place('', r.iso);
        }, v.level === 'world' ? unknown : '');
    } else {
      const other = v.hidden.cities
        ? '<tr id="geo-hidden"><td><em>' + v.hidden.cities +
          ' other cit' + (v.hidden.cities === 1 ? 'y' : 'ies') + ', each ' +
          'with fewer than ' + v.minimumCount + ' people</em></td>' +
          '<td></td><td class="num">' + v.hidden.signIns + '</td><td></td>' +
          '</tr>' : '';
      const only = v.countryOnly && (v.countryOnly.people !== null ||
                                     v.countryOnly.suppressed)
        ? '<tr><td><em>City unknown</em></td><td class="num">' +
          esc(this.countText(v.countryOnly.people,
                             v.countryOnly.suppressed)) + '</td>' +
          '<td class="num">' + esc(v.countryOnly.signIns === null ? ''
            : String(v.countryOnly.signIns)) + '</td><td></td></tr>' : '';
      tables += '<h3>By city</h3>' + this.table('geo-cities', 'City',
        v.cities.map(function (c: Json): Json {
          return Object.assign({ label: c.city + (c.subdivision
            ? ', ' + c.subdivision : '') }, c);
        }), function (): string {
          return '';
        }, other + only);
    }
    const states = v.datasets.map(function (d: Json): string {
      return esc(d.title) + ': ' + esc(d.state) +
        (d.version ? ' (' + esc(d.version) + ')' : '');
    }).join('; ');
    const credits = v.attributions.map(function (a: Json): string {
      return '<p class="attribution"><small>' + (a.url
        ? '<a href="' + esc(a.url) + '" rel="noopener">' + esc(a.text) +
          '</a>' : esc(a.text)) + (a.licence ? ', licensed under ' +
        (a.licenceUrl ? '<a href="' + esc(a.licenceUrl) + '" ' +
         'rel="noopener">' + esc(a.licence) + '</a>' : esc(a.licence)) : '') +
        '.</small></p>';
    }).join('');
    log.debug("Leaving GeolocationAdmin.html().");
    return '<div class="card"><h2>Where people signed in from</h2>' +
      '<p>' + windows + '</p>' +
      '<p class="geo-zoom">' + crumbs.join(' &rsaquo; ') + '</p>' +
      (noPlace ? '<p class="warn" id="geo-no-dataset">No geolocation ' +
        'dataset is active, so a sign-in assessed now has no place and is ' +
        'counted under <em>Location unknown</em>. Load one on ' +
        '<a href="/admin/risk">Monitoring → Risk</a>.</p>' : '') +
      '<p>' + total + where + ' &mdash; ' + who + '. Select a ' +
      (v.level === 'world' ? 'country or continent to see its continent'
        : (v.level === 'continent' ? 'country to see its cities'
          : 'neighbouring country to move to it')) + '.</p>' +
      drawn.picture.svg +
      (v.level === 'country'
        ? '<p><small>A circle\'s area is proportional to the people counted ' +
          'in its city.</small></p>'
        : '<p><small>People' + legend + '</small></p>') +
      '<p><small>People are counted once at each level, so a country\'s ' +
      'number is not its cities\' total. A place with fewer than ' +
      v.minimumCount + ' people (<code>risk.geoMinimumCount</code>, on ' +
      '<a href="/admin/risk">Monitoring → Risk</a>) is shaded but not ' +
      'numbered, and such a city is not drawn. A city and its coordinates ' +
      'are often tens of kilometres from where the person is: they are the ' +
      'dataset\'s answer for the address.</small></p>' + tables +
      '<p><small>Counted ' + (v.database ? 'in the database, across every ' +
        'node' : 'in this process\'s memory: the risk history is kept in ' +
        'the database only where the key-encryption key can seal it') +
      '. Datasets: ' + states + '.</small></p>' + credits +
      '<p class="attribution"><small>Country outlines: <a href="' +
      esc(v.outlines.url) + '" rel="noopener">Made with Natural Earth</a> ' +
      '(public domain).</small></p></div>';
  }

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

export = {
  registerRoutes: slot.forward('registerRoutes'),
  GeolocationAdmin: GeolocationAdmin,
  installInstance: (instance: GeolocationAdmin): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  WINDOWS: WINDOWS,
  hrefOf: GeolocationAdmin.hrefOf,
  geoView: slot.forward('geoView'),
  drawing: slot.forward('drawing'),
  html: slot.forward('html')
};
