// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_geolocation.ts
//
// ---------------------------------------------------------------------------
// MONITORING → GEOLOCATION, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Geolocation from the answer of `GET /admin-api/geolocation`: where
// people signed in from, as a map laid out by the server and tables by
// continent, country and city.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `GeolocationAdmin`'s in `admin-ui/geolocation_admin.ts`,
// moved with their comments; that module still draws the page until the
// console's cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * The console path of Monitoring → Geolocation.
 */
const PAGE = '/admin/geolocation';

const WINDOW_LABELS: Record<string, string> = {
  'live': 'Live sessions', '24h': 'Last 24 hours', '7d': 'Last 7 days',
  '30d': 'Last 30 days' };

const DEFAULT_WINDOW = 'live';

/**
 * Draws Geolocation from the answer of `GET /admin-api/geolocation`: where
 * people signed in from, as a map laid out by the server and tables by
 * continent, country and city.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class GeolocationPage {
  /**
   * The windows' labels, by the name the query carries.
   */
  static readonly WINDOW_LABELS = WINDOW_LABELS;

  /**
   * The window a page with none named shows.
   */
  static readonly DEFAULT_WINDOW = DEFAULT_WINDOW;

  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static render(view: Json): string {
    return GeolocationPage.html(view);
  }

  // The page's own address for a window and a place, the default window
  // left out. Root-relative: `app.js` puts it in the realm.
  /**
   * Answers the page's own root-relative address for a window and a place, the
   * default window left out.
   *
   * @param window - the window's name
   * @param continent - a continent's slug
   * @param country - a country's ISO code
   * @returns the address
   */
  static hrefOf(window: string, continent?: string, country?: string): string {
    const parts: string[] = [];
    if (window && window !== DEFAULT_WINDOW) {
      parts.push('window=' + encodeURIComponent(window));
    }
    if (country) {
      parts.push('country=' + encodeURIComponent(country));
    } else if (continent) {
      parts.push('continent=' + encodeURIComponent(continent));
    }
    return PAGE + (parts.length ? '?' + parts.join('&') : '');
  }

  // "12", or "fewer than 3" for a suppressed count, or "—" for none.
  static countText(n: number | null, suppressed: boolean,
                    minimum: number): string {
    if (n !== null) {
      return String(n);
    }
    return suppressed ? 'fewer than ' + minimum : '—';
  }

  // A time in UTC to the minute, or '' for none.
  /**
   * Says a time in UTC to the minute.
   *
   * @param ms - the time in milliseconds
   * @returns the time as text, or '' for none
   */
  static stamp(ms: number): string {
    return ms ? new Date(ms).toISOString().slice(0, 16).replace('T', ' ') +
      ' UTC' : '';
  }

  // One table: a place per row, linked to its own view when it has one.
  static table(id: string, head: string, rows: Json[],
                hrefOf: (row: Json) => string, minimum: number,
                extra?: string): string {
    const self = this;
    const esc = kit.esc.bind(kit);
    const body = rows.map(function (r: Json): string {
      const href = hrefOf(r);
      const name = esc(r.label);
      return '<tr><td>' + (href ? '<a href="' + esc(href) + '">' + name +
                           '</a>' : name) + '</td><td class="num">' +
        esc(self.countText(r.people, r.suppressed, minimum)) +
        '</td><td class="num">' +
        esc(r.signIns === null ? '' : String(r.signIns)) + '</td><td>' +
        esc(r.people === null ? '' : self.stamp(r.lastAt)) +
        '</td></tr>';
    }).join('');
    return '<table class="grid" id="' + id + '"><thead><tr><th>' + esc(head) +
      '</th><th>People</th><th>Sign-ins</th><th>Last seen</th></tr></thead>' +
      '<tbody>' + (body || '<tr><td colspan="4">Nobody here in this ' +
                   'window.</td></tr>') + (extra || '') + '</tbody></table>';
  }

  // The page's HTML.
  /**
   * Draws the page's HTML from the view.
   *
   * @param v - `geoView()`'s answer
   * @returns the page body
   */
  static html(v: Json): string {
    const self = this;
    const esc = kit.esc.bind(kit);
    const place = function (continent?: string, country?: string): string {
      return self.hrefOf(v.window, continent, country);
    };
    const windows = v.windows.map(function (w: string): string {
      const label = esc(WINDOW_LABELS[w]);
      return w === v.window ? '<strong>' + label + '</strong>'
        : '<a id="geo-window-' + w + '" href="' +
          esc(self.hrefOf(w, v.continent && v.continent.continent,
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
    // The map is laid out where the geography is (#446): it arrives in
    // the view as `drawing`.
    const drawn = v.drawing;
    const legend = drawn.legend.map(function (s: Json): string {
      return '<span class="geo-swatch" style="display:inline-block;' +
        'width:14px;height:14px;border-radius:3px;vertical-align:middle;' +
        'margin:0 4px 0 12px;background:' + s.colour + '"></span>' +
        (s.from === s.to ? s.from : s.from + '–' + s.to);
    }).join('') + '<span style="display:inline-block;width:14px;height:14px;' +
      'border-radius:3px;vertical-align:middle;margin:0 4px 0 12px;' +
      'background:' + v.noDataColour + '"></span>none';
    const where = v.country ? ' in ' + esc(v.country.name)
      : (v.continent ? ' in ' + esc(v.continent.name) : '');
    const total = v.total.people !== null
      ? '<strong id="geo-total">' + v.total.people + '</strong> ' +
        (v.total.people === 1 ? 'person' : 'people')
      : '<strong id="geo-total">' + esc(this.countText(null,
                                                      v.total.suppressed,
                                                      v.minimumCount)) +
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
        }, v.minimumCount);
    }
    if (v.level !== 'country') {
      const unknown = v.unknown.people !== null || v.unknown.suppressed
        ? '<tr><td><em>Location unknown</em></td><td class="num">' +
          esc(this.countText(v.unknown.people, v.unknown.suppressed,
                             v.minimumCount)) +
          '</td><td class="num">' + esc(v.unknown.signIns === null ? ''
            : String(v.unknown.signIns)) + '</td><td></td></tr>' : '';
      tables += '<h3>By country</h3>' + this.table('geo-countries',
        'Country', v.countries.map(function (c: Json): Json {
          return Object.assign({ label: c.name }, c);
        }), function (r: Json): string {
          return r.onMap ? place('', r.iso) : '';
        }, v.minimumCount, v.level === 'world' ? unknown : '');
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
                             v.countryOnly.suppressed, v.minimumCount)) +
          '</td>' +
          '<td class="num">' + esc(v.countryOnly.signIns === null ? ''
            : String(v.countryOnly.signIns)) + '</td><td></td></tr>' : '';
      tables += '<h3>By city</h3>' + this.table('geo-cities', 'City',
        v.cities.map(function (c: Json): Json {
          return Object.assign({ label: c.city + (c.subdivision
            ? ', ' + c.subdivision : '') }, c);
        }), function (): string {
          return '';
        }, v.minimumCount, other + only);
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
}

export = GeolocationPage;
