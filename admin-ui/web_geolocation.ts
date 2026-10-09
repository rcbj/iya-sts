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
   * @param ctx - optional; the render context, whose `t` is the page's
   *   translator (#539). `geolocation_admin.ts` passes none and gets the
   *   default, English in node.
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return GeolocationPage.html(view, (ctx || kit.context()).t);
  }

  // A WINDOW'S LABEL, IN THE READER'S LANGUAGE (#539). `WINDOW_LABELS`
  // stays English and exported as it was, for `geolocation_admin.ts`; the
  // page draws these, one literal key each so the catalog test finds them.
  /**
   * Says a window's label, or the same in lower case for a sentence.
   *
   * @param w - the window's name
   * @param t - the page's translator
   * @param lower - true for the form used inside a sentence
   * @returns the label as text
   */
  static windowLabel(w: string, t: Json, lower: boolean): string {
    switch (w) {
      case 'live':
        return lower ? t.text('consoleGeolocation.windowLower.live')
          : t.text('consoleGeolocation.window.live');
      case '24h':
        return lower ? t.text('consoleGeolocation.windowLower.24h')
          : t.text('consoleGeolocation.window.24h');
      case '7d':
        return lower ? t.text('consoleGeolocation.windowLower.7d')
          : t.text('consoleGeolocation.window.7d');
      case '30d':
        return lower ? t.text('consoleGeolocation.windowLower.30d')
          : t.text('consoleGeolocation.window.30d');
      default:
        return lower ? String(WINDOW_LABELS[w]).toLowerCase()
          : WINDOW_LABELS[w];
    }
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

  // "12", or "fewer than 3" for a suppressed count, or "—" for none. `t` is
  // optional: `geolocation_admin.ts` calls this without one and gets the
  // default translator, English in node (#539).
  static countText(n: number | null, suppressed: boolean,
                    minimum: number, t?: Json): string {
    if (n !== null) {
      return String(n);
    }
    const tr = t || kit.context().t;
    return suppressed ? tr.text('consoleGeolocation.fewerThan',
                                { min: minimum }) : '—';
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
                extra: string, t: Json): string {
    const self = this;
    const esc = kit.esc.bind(kit);
    const body = rows.map(function (r: Json): string {
      const href = hrefOf(r);
      const name = esc(r.label);
      return '<tr><td>' + (href ? '<a href="' + esc(href) + '">' + name +
                           '</a>' : name) + '</td><td class="num">' +
        esc(self.countText(r.people, r.suppressed, minimum, t)) +
        '</td><td class="num">' +
        esc(r.signIns === null ? '' : String(r.signIns)) + '</td><td>' +
        esc(r.people === null ? '' : self.stamp(r.lastAt)) +
        '</td></tr>';
    }).join('');
    return '<table class="grid" id="' + id + '"><thead><tr><th>' + esc(head) +
      '</th><th>' + t.html('consoleGeolocation.th.people') + '</th><th>' +
      t.html('consoleGeolocation.th.signIns') + '</th><th>' +
      t.html('consoleGeolocation.th.lastSeen') + '</th></tr></thead>' +
      '<tbody>' + (body || '<tr><td colspan="4">' +
                   t.html('consoleGeolocation.nobody') + '</td></tr>') +
      (extra || '') + '</tbody></table>';
  }

  // The page's HTML.
  /**
   * Draws the page's HTML from the view.
   *
   * @param v - `geoView()`'s answer
   * @param t - optional; the page's translator (#539)
   * @returns the page body
   */
  static html(v: Json, t?: Json): string {
    t = t || kit.context().t;
    const self = this;
    const esc = kit.esc.bind(kit);
    const place = function (continent?: string, country?: string): string {
      return self.hrefOf(v.window, continent, country);
    };
    const windows = v.windows.map(function (w: string): string {
      const label = esc(self.windowLabel(w, t, false));
      return w === v.window ? '<strong>' + label + '</strong>'
        : '<a id="geo-window-' + w + '" href="' +
          esc(self.hrefOf(w, v.continent && v.continent.continent,
                                      v.country && v.country.iso)) + '">' +
          label + '</a>';
    }).join(' &middot; ');
    // The zoom trail: World › continent › country, every level above this
    // one a link. The console's own trail above the heading has one level
    // below the page, so the continent step is here.
    const crumbs: string[] = [v.level === 'world'
      ? '<strong>' + t.html('consoleGeolocation.world') + '</strong>'
      : '<a id="geo-zoom-world" href="' + esc(place()) + '">' +
        t.html('consoleGeolocation.world') + '</a>'];
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
      ? t.html('consoleGeolocation.who.live', { n: v.liveSessions })
      : t.html('consoleGeolocation.who.window',
               { window: self.windowLabel(v.window, t, true) });
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
      'background:' + v.noDataColour + '"></span>' +
      t.html('consoleGeolocation.legend.none');
    const where = v.country
      ? t.html('consoleGeolocation.where', { place: v.country.name })
      : (v.continent
        ? t.html('consoleGeolocation.where', { place: v.continent.name })
        : '');
    const total = v.total.people !== null
      ? '<strong id="geo-total">' + v.total.people + '</strong> ' +
        t.html('consoleGeolocation.total.people', { n: v.total.people })
      : '<strong id="geo-total">' + esc(this.countText(null,
                                                      v.total.suppressed,
                                                      v.minimumCount, t)) +
        '</strong> ' + t.html('consoleGeolocation.total.peopleWord');
    const noPlace = v.datasets.every(function (d: Json): boolean {
      return d.state === 'empty';
    });
    let tables = '';
    if (v.level === 'world') {
      tables += '<h3>' + t.html('consoleGeolocation.byContinent') + '</h3>' +
        this.table('geo-continents',
        t.text('consoleGeolocation.th.continent'),
        v.continents.map(function (c: Json): Json {
          return Object.assign({ label: c.name }, c);
        }), function (r: Json): string {
          return place(r.continent);
        }, v.minimumCount, '', t);
    }
    if (v.level !== 'country') {
      const unknown = v.unknown.people !== null || v.unknown.suppressed
        ? '<tr><td><em>' + t.html('consoleGeolocation.locationUnknown') +
          '</em></td><td class="num">' +
          esc(this.countText(v.unknown.people, v.unknown.suppressed,
                             v.minimumCount, t)) +
          '</td><td class="num">' + esc(v.unknown.signIns === null ? ''
            : String(v.unknown.signIns)) + '</td><td></td></tr>' : '';
      tables += '<h3>' + t.html('consoleGeolocation.byCountry') + '</h3>' +
        this.table('geo-countries',
        t.text('consoleGeolocation.th.country'),
        v.countries.map(function (c: Json): Json {
          return Object.assign({ label: c.name }, c);
        }), function (r: Json): string {
          return r.onMap ? place('', r.iso) : '';
        }, v.minimumCount, v.level === 'world' ? unknown : '', t);
    } else {
      const other = v.hidden.cities
        ? '<tr id="geo-hidden"><td><em>' +
          t.html('consoleGeolocation.hiddenCities',
                 { n: v.hidden.cities, min: v.minimumCount }) + '</em></td>' +
          '<td></td><td class="num">' + v.hidden.signIns + '</td><td></td>' +
          '</tr>' : '';
      const only = v.countryOnly && (v.countryOnly.people !== null ||
                                     v.countryOnly.suppressed)
        ? '<tr><td><em>' + t.html('consoleGeolocation.cityUnknown') +
          '</em></td><td class="num">' +
          esc(this.countText(v.countryOnly.people,
                             v.countryOnly.suppressed, v.minimumCount, t)) +
          '</td>' +
          '<td class="num">' + esc(v.countryOnly.signIns === null ? ''
            : String(v.countryOnly.signIns)) + '</td><td></td></tr>' : '';
      tables += '<h3>' + t.html('consoleGeolocation.byCity') + '</h3>' +
        this.table('geo-cities', t.text('consoleGeolocation.th.city'),
        v.cities.map(function (c: Json): Json {
          return Object.assign({ label: c.city + (c.subdivision
            ? ', ' + c.subdivision : '') }, c);
        }), function (): string {
          return '';
        }, v.minimumCount, other + only, t);
    }
    const states = v.datasets.map(function (d: Json): string {
      return esc(d.title) + ': ' + esc(d.state) +
        (d.version ? ' (' + esc(d.version) + ')' : '');
    }).join('; ');
    const credits = v.attributions.map(function (a: Json): string {
      return '<p class="attribution"><small>' + (a.url
        ? '<a href="' + esc(a.url) + '" rel="noopener">' + esc(a.text) +
          '</a>' : esc(a.text)) + (a.licence
          ? t.html('consoleGeolocation.licensedUnder') +
        (a.licenceUrl ? '<a href="' + esc(a.licenceUrl) + '" ' +
         'rel="noopener">' + esc(a.licence) + '</a>' : esc(a.licence)) : '') +
        '.</small></p>';
    }).join('');
    // Links are markup a message cannot carry, so each sentence holding one
    // is drawn around it (#539).
    return '<div class="card"><h2>' + t.html('consoleGeolocation.heading') +
      '</h2>' +
      '<p>' + windows + '</p>' +
      '<p class="geo-zoom">' + crumbs.join(' &rsaquo; ') + '</p>' +
      (noPlace ? '<p class="warn" id="geo-no-dataset">' +
        t.html('consoleGeolocation.noDataset') +
        '<a href="/admin/risk">' + t.html('consoleGeolocation.link.risk') +
        '</a>.</p>' : '') +
      '<p>' + total + where + ' &mdash; ' + who + '. ' +
      (v.level === 'world' ? t.html('consoleGeolocation.select.world')
        : (v.level === 'continent'
          ? t.html('consoleGeolocation.select.continent')
          : t.html('consoleGeolocation.select.country'))) + '</p>' +
      drawn.picture.svg +
      (v.level === 'country'
        ? '<p><small>' + t.html('consoleGeolocation.circle') +
          '</small></p>'
        : '<p><small>' + t.html('consoleGeolocation.legend.people') +
          legend + '</small></p>') +
      '<p><small>' +
      t.html('consoleGeolocation.counting.before', { min: v.minimumCount }) +
      '<a href="/admin/risk">' + t.html('consoleGeolocation.link.risk') +
      '</a>' + t.html('consoleGeolocation.counting.after') +
      '</small></p>' + tables +
      '<p><small>' + (v.database
        ? t.html('consoleGeolocation.counted.database')
        : t.html('consoleGeolocation.counted.memory')) +
      t.html('consoleGeolocation.datasets') + states + '.</small></p>' +
      credits +
      '<p class="attribution"><small>' +
      t.html('consoleGeolocation.outlines') + '<a href="' +
      esc(v.outlines.url) + '" rel="noopener">Made with Natural Earth</a> ' +
      t.html('consoleGeolocation.publicDomain') + '</small></p></div>';
  }
}

export = GeolocationPage;
