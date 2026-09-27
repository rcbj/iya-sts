'use strict';
//
// File: admin-ui/geo_map.ts
//
// ===========================================================================
// THE GEOLOCATION PICTURE (#255): where a realm's people signed in from,
// drawn as a map — the world, a continent or a country, with every country
// filled by how many people it counts and, on a country, its cities as
// circles. `admin-ui/geolocation_admin.ts` counts; this file draws.
//
// It is a LIBRARY on `delegation_map.ts`'s and `federation_diagram.ts`'s
// terms (rule 3): it registers no route, so its place in the require order
// does not matter, and everything it draws arrives as an argument — which
// countries are filled and how dark, what each links to, which cities —
// so how the console decides what a number IS cannot reach the code that
// decides where it GOES. What it takes from this service is `helpers.js`
// (the logger and the XML escaper) and `delegation_map.ts`'s palette and
// text metric, the latter for `federation_diagram.ts`'s reason: two pictures
// in one console should measure a label and colour a line the same way.
//
// ---------------------------------------------------------------------------
// WHAT IT DOES NOT TAKE FROM THOSE TWO IS DAGRE, and that is not a choice.
// dagre lays out a GRAPH — ranks, orders, coordinates for boxes nobody has
// placed. A map's boxes are placed already, by the earth; what a map needs
// instead is a PROJECTION and OUTLINES:
//
//   * THE PROJECTION is Equal Earth (Šavrič, Patterson and Jenny, 2018): an
//     equal-area pseudocylindrical projection, so a country's filled area is
//     proportional to its real one — which matters on a choropleth, where a
//     reader's eye weighs a colour by how much of it there is. Mercator would
//     make Greenland outweigh Africa. It is six lines (`project()`), and no
//     dependency is worth six lines.
//   * THE OUTLINES are Natural Earth's 1:50m Admin 0 countries, PUBLIC
//     DOMAIN, reduced by `tests/tools/natural-earth.js` to
//     `natural_earth/countries.json` (one row per ISO 3166-1 code, the
//     continent, a label point, the rings rounded to 0.01°). The one
//     third-party dataset this repository ships, and why that is allowed
//     when `risk/CLAUDE.md` says none is shipped, is in `admin-ui/CLAUDE.md`
//     (*`/admin/geolocation` is the third drawing*). It is read when the
//     first map is drawn and held for the life of the process: 1.3 MB, the
//     same for every realm.
//
// AND IT KEEPS THE CSP RULE INTACT, for the delegation picture's reason: the
// SVG is made here and arrives inline as markup, so the console's
// `script-src 'none'` is untouched. ZOOM IS A LINK: every country is an
// `<a>`, and following it draws the next level on the server. A pan-and-zoom
// map in the browser would be the console's second scripted page, to show a
// picture that does not need to move.
//
// ---------------------------------------------------------------------------
// THREE THINGS THAT WENT INTO THE GEOMETRY, each because the obvious version
// draws something wrong:
//
//   * A VIEW HAS A CENTRAL MERIDIAN. Natural Earth cuts every ring at ±180°,
//     which is right for a world centred on Greenwich and wrong for Oceania,
//     Russia or Fiji, whose country view would otherwise span the whole
//     globe. Each view projects longitudes relative to its own centre, and a
//     ring that crosses the view's far side (the new ±180°) is broken into
//     separate strokes there rather than drawn as a line across the map.
//   * A COUNTRY'S VIEW IS ITS MAIN TERRITORY. France's outline carries French
//     Guiana and Réunion; a box around all of it is mostly ocean with France
//     a dot at the top. The view is the largest polygon's box, joined by the
//     polygons whose centres lie within that polygon's own size of it — so
//     Corsica, Alaska and Svalbard are in their countries' views and Réunion
//     is not — and then widened to take in every CITY the page was given, so
//     a person counted is never off the edge.
//   * POINTS ARE THINNED FOR THE SCALE, not for the file. The file keeps
//     0.01° (a kilometre); the world at 960 pixels is 40 km a pixel. A point
//     within `THIN_PX` of the last one kept is dropped as the path is
//     written, and a ring smaller than a pixel is not written at all, so the
//     world is a few hundred kilobytes of markup and a country keeps its
//     coastline.
// ===========================================================================

import fs = require('fs');
import path = require('path');
import helpers = require('../common/helpers');
import delegationMap = require('./delegation_map');
import InstanceSlot = require('../common/instance_slot');

type Json = any;

interface GeoMapDeps {
  log: typeof helpers.log;
  xmlEscape: typeof helpers.xmlEscape;
  textWidth: typeof delegationMap.textWidth;
  readOutlines(): Json;
}

// One country as the file holds it, and as `countries()` answers it.
interface Country {
  iso: string;
  name: string;
  continent: string;
  label: number[];
  polygons: number[][][];
}

// A view: the central meridian and the box, in degrees (longitudes relative
// to `lon0`).
interface View {
  lon0: number;
  west: number;
  east: number;
  south: number;
  north: number;
}

// ---------------------------------------------------------------------------
// THE PALETTE, `delegation_map.ts`'s — and the one thing that is new.
//
// THE FILL SCALE is five steps of the console's indigo, light to dark, and it
// was run through the dataviz palette validator before it was written here
// (`--ordinal`, light surface): one hue, lightness monotone, a visible gap
// between every pair of steps, and the lightest still clearing 2:1 against
// the paper — so a country with one person is never mistaken for a country
// with none, which is `NO_DATA`, a neutral grey with no hue at all. A
// country below `risk.geoMinimumCount` is filled with the lightest step and
// carries no number: shaded, as rcbj decided, and saying no more than "a
// few".
// ---------------------------------------------------------------------------
const PALETTE = delegationMap.COLOURS;
const INK = PALETTE.ink;
const INDIGO = PALETTE.indigo;
const QUIET = PALETTE.quiet;
const PAPER = PALETTE.paper;
const WASH = PALETTE.wash;
const RAMP = ['#a7a2dc', '#857fcb', '#6159b6', '#3b3598', '#12107c'];
const NO_DATA = '#e4e4ea';
// Land outside the country a country view is about: there to say where it
// is, and quieter than anything that counts.
const CONTEXT = '#efeff3';
const OCEAN = '#f7f8fb';
const GRATICULE = '#e3e6ee';
const BORDER = '#ffffff';

// The picture's width; the height follows the view's shape between the two
// bounds, and a view too tall for them is narrowed and centred instead.
const WIDTH = 960;
const MIN_HEIGHT = 260;
const MAX_HEIGHT = 620;
const MARGIN = 12;
// A point closer than this to the last one kept is not written.
const THIN_PX = 0.7;
// A counted country smaller than this on screen also gets a dot at its
// label point, or Singapore would be counted and invisible.
const DOT_BELOW_PX = 7;
const LABEL_SIZE = 12;
const CITY_LABEL_SIZE = 11;

// THE CONTINENTS, by the slug a URL carries: the name Natural Earth files
// each country under, and the view each is drawn in. The boxes are chosen,
// not computed — Russia is filed under Europe and a box around Europe's
// countries would reach the Bering Strait — and a country view is always
// computed, so nothing is cut off where it matters.
const CONTINENTS: Record<string, Json> = {
  'africa': { name: 'Africa',
    view: { lon0: 17, west: -38, east: 38, south: -36, north: 38 } },
  'antarctica': { name: 'Antarctica',
    view: { lon0: 0, west: -180, east: 180, south: -90, north: -55 } },
  'asia': { name: 'Asia',
    view: { lon0: 95, west: -70, east: 55, south: -12, north: 56 } },
  'europe': { name: 'Europe',
    view: { lon0: 12, west: -37, east: 33, south: 34, north: 72 } },
  'north-america': { name: 'North America',
    view: { lon0: -100, west: -70, east: 52, south: 6, north: 78 } },
  'oceania': { name: 'Oceania',
    view: { lon0: 160, west: -50, east: 32, south: -48, north: 22 } },
  'south-america': { name: 'South America',
    view: { lon0: -60, west: -26, east: 28, south: -56, north: 14 } }
};
const WORLD: View = { lon0: 0, west: -180, east: 180, south: -58, north: 84 };

// Equal Earth's coefficients (Šavrič, Patterson and Jenny, 2018).
const A1 = 1.340264;
const A2 = -0.081106;
const A3 = 0.000893;
const A4 = 0.003796;
const M = Math.sqrt(3) / 2;
const RAD = Math.PI / 180;

class GeoMap {
  static readonly RAMP = RAMP;
  static readonly NO_DATA = NO_DATA;
  static readonly CONTINENTS = CONTINENTS;

  private held: { list: Country[]; byIso: Map<string, Country>;
                  source: Json } | null = null;

  constructor(private readonly deps: GeoMapDeps) {
    deps.log.debug("Entering GeoMap.constructor().");
    deps.log.debug("Leaving GeoMap.constructor().");
  }

  static defaultDeps(): GeoMapDeps {
    helpers.log.debug("Entering GeoMap.defaultDeps().");
    helpers.log.debug("Leaving GeoMap.defaultDeps().");
    return {
      log: helpers.log,
      xmlEscape: helpers.xmlEscape,
      textWidth: delegationMap.textWidth,
      readOutlines: function (): Json {
        return JSON.parse(fs.readFileSync(
          path.join(__dirname, 'natural_earth', 'countries.json'), 'utf8'));
      }
    };
  }

  // Every country, read once. `source` is the file's provenance, which the
  // page credits.
  countries(): { list: Country[]; byIso: Map<string, Country>;
                 source: Json } {
    const { log, readOutlines } = this.deps;
    log.debug("Entering GeoMap.countries().");
    if (!this.held) {
      const file = readOutlines();
      const list: Country[] = file.countries || [];
      const byIso = new Map<string, Country>();
      list.forEach(function (c: Country): void {
        byIso.set(c.iso, c);
      });
      const source = Object.assign({}, file);
      delete source.countries;
      this.held = { list: list, byIso: byIso, source: source };
    }
    log.debug("Leaving GeoMap.countries().");
    return this.held;
  }

  // The continent slug a continent name is filed under ('' for none).
  static slugOf(continent: string): string {
    helpers.log.debug("Entering GeoMap.slugOf().");
    const found = Object.keys(CONTINENTS).filter(function (s: string): boolean {
      return CONTINENTS[s].name === continent;
    })[0];
    helpers.log.debug("Leaving GeoMap.slugOf().");
    return found || '';
  }

  // ISO code -> continent name, for the store's count (`risk_store.ts`'s
  // `geography()`, which holds a country and no continent).
  continentTable(): Record<string, string> {
    const { log } = this.deps;
    log.debug("Entering GeoMap.continentTable().");
    const out: Record<string, string> = {};
    this.countries().list.forEach(function (c: Country): void {
      out[c.iso] = c.continent;
    });
    log.debug("Leaving GeoMap.continentTable().");
    return out;
  }

  // A count's step on the scale, 1 to 5, against the largest count drawn;
  // 0 for none. Logarithmic, because sign-ins are: one capital city with a
  // thousand people and forty countries with three would otherwise be one
  // dark country and forty that look empty.
  static bucketOf(n: number, max: number): number {
    helpers.log.debug("Entering GeoMap.bucketOf().");
    helpers.log.debug("Leaving GeoMap.bucketOf().");
    if (!(n > 0)) {
      return 0;
    }
    if (max <= 1) {
      return RAMP.length;
    }
    return Math.max(1, Math.min(RAMP.length,
      Math.ceil(RAMP.length * Math.log(1 + n) / Math.log(1 + max))));
  }

  // The range of counts each step stands for, for the legend: step i holds
  // the n with bucketOf(n, max) === i + 1.
  static legendOf(max: number): Json[] {
    helpers.log.debug("Entering GeoMap.legendOf().");
    const out: Json[] = [];
    let low = 1;
    for (let step = 1; step <= RAMP.length && low <= Math.max(1, max);
         step++) {
      let high = low;
      while (high + 1 <= max && GeoMap.bucketOf(high + 1, max) === step) {
        high++;
      }
      if (GeoMap.bucketOf(low, max) === step) {
        out.push({ colour: RAMP[step - 1], from: low, to: high });
        low = high + 1;
      }
    }
    helpers.log.debug("Leaving GeoMap.legendOf().");
    return out;
  }

  // Equal Earth, of a longitude already relative to the view's meridian.
  // A hot path — every point of every ring drawn — so no Entering or
  // Leaving pair, which would be two log lines per coordinate.
  static project(lon: number, lat: number): number[] {
    const lambda = lon * RAD;
    const theta = Math.asin(M * Math.sin(lat * RAD));
    const t2 = theta * theta;
    const t6 = t2 * t2 * t2;
    return [lambda * Math.cos(theta) /
              (M * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2))),
            theta * (A1 + A2 * t2 + t6 * (A3 + A4 * t2))];
  }

  // A longitude relative to `lon0`, in [-180, 180] — the far side kept on
  // the side it came from, because Natural Earth cuts its rings AT ±180 and
  // a point on the cut folded to the other edge would break every ring that
  // touches it. A hot path, as above.
  static relative(lon: number, lon0: number): number {
    const r = ((lon - lon0 + 540) % 360) - 180;
    return r === -180 && lon > lon0 ? 180 : r;
  }

  // THE VIEW OF ONE COUNTRY: see the header. `cities` widen it.
  countryView(country: Country, cities: Json[]): View {
    const { log } = this.deps;
    log.debug("Entering GeoMap.countryView(). " + country.iso);
    const lon0 = country.label[0];
    const boxOf = function (polygon: number[][]): number[] {
      const ring = polygon[0];
      const box = [Infinity, -Infinity, Infinity, -Infinity];
      for (let i = 0; i < ring.length; i += 2) {
        const x = GeoMap.relative(ring[i], lon0);
        box[0] = Math.min(box[0], x);
        box[1] = Math.max(box[1], x);
        box[2] = Math.min(box[2], ring[i + 1]);
        box[3] = Math.max(box[3], ring[i + 1]);
      }
      return box;
    };
    const boxes = country.polygons.map(boxOf);
    const area = function (b: number[]): number {
      return (b[1] - b[0]) * (b[3] - b[2]);
    };
    const main = boxes.slice().sort(function (a: number[],
                                              b: number[]): number {
      return area(b) - area(a);
    })[0] || [-5, 5, -5, 5];
    const reach = Math.max(15, main[1] - main[0], main[3] - main[2]);
    const box = main.slice();
    boxes.forEach(function (b: number[]): void {
      const cx = (b[0] + b[1]) / 2;
      const cy = (b[2] + b[3]) / 2;
      const dx = Math.max(0, main[0] - cx, cx - main[1]);
      const dy = Math.max(0, main[2] - cy, cy - main[3]);
      if (dx <= reach && dy <= reach) {
        box[0] = Math.min(box[0], b[0]);
        box[1] = Math.max(box[1], b[1]);
        box[2] = Math.min(box[2], b[2]);
        box[3] = Math.max(box[3], b[3]);
      }
    });
    (cities || []).forEach(function (c: Json): void {
      if (typeof c.lon === 'number' && typeof c.lat === 'number') {
        const x = GeoMap.relative(c.lon, lon0);
        box[0] = Math.min(box[0], x);
        box[1] = Math.max(box[1], x);
        box[2] = Math.min(box[2], c.lat);
        box[3] = Math.max(box[3], c.lat);
      }
    });
    // A margin of a tenth, and never less than three degrees across, so a
    // city-state is drawn with something around it.
    const padX = Math.max(1.5, (box[1] - box[0]) * 0.1);
    const padY = Math.max(1.5, (box[3] - box[2]) * 0.1);
    log.debug("Leaving GeoMap.countryView().");
    return { lon0: lon0,
             west: Math.max(-180, box[0] - padX),
             east: Math.min(180, box[1] + padX),
             south: Math.max(-89, box[2] - padY),
             north: Math.min(89, box[3] + padY) };
  }

  // The view's box on the screen: the projected bounds (sampled on a grid,
  // because a meridian is a curve here), the scale and the offsets.
  private frameOf(view: View): Json {
    const { log } = this.deps;
    log.debug("Entering GeoMap.frameOf().");
    let x0 = Infinity;
    let x1 = -Infinity;
    let y0 = Infinity;
    let y1 = -Infinity;
    for (let i = 0; i <= 12; i++) {
      for (let j = 0; j <= 12; j++) {
        const p = GeoMap.project(view.west + (view.east - view.west) * i / 12,
                                 view.south + (view.north - view.south) *
                                   j / 12);
        x0 = Math.min(x0, p[0]);
        x1 = Math.max(x1, p[0]);
        y0 = Math.min(y0, p[1]);
        y1 = Math.max(y1, p[1]);
      }
    }
    const inner = WIDTH - 2 * MARGIN;
    let scale = inner / Math.max(1e-9, x1 - x0);
    let height = (y1 - y0) * scale + 2 * MARGIN;
    if (height > MAX_HEIGHT) {
      scale = (MAX_HEIGHT - 2 * MARGIN) / Math.max(1e-9, y1 - y0);
      height = MAX_HEIGHT;
    }
    height = Math.max(MIN_HEIGHT, height);
    const offsetX = (WIDTH - (x1 - x0) * scale) / 2 - x0 * scale;
    const offsetY = (height - (y1 - y0) * scale) / 2 + y1 * scale;
    log.debug("Leaving GeoMap.frameOf().");
    return { scale: scale, offsetX: offsetX, offsetY: offsetY,
             height: Math.round(height), lon0: view.lon0 };
  }

  // A longitude and latitude on the screen. A hot path, as `project()`.
  static toScreen(frame: Json, lon: number, lat: number): number[] {
    const p = GeoMap.project(GeoMap.relative(lon, frame.lon0), lat);
    return [frame.offsetX + p[0] * frame.scale,
            frame.offsetY - p[1] * frame.scale];
  }

  // One polygon as path data, thinned, with its screen box. A ring whose
  // longitude jumps by more than half the globe between two points crossed
  // the view's far side: the stroke is broken there. A hot path — once per
  // polygon of every country drawn — so no Entering or Leaving pair.
  static polygonPath(frame: Json, polygon: number[][]): Json {
    let d = '';
    const box = [Infinity, -Infinity, Infinity, -Infinity];
    polygon.forEach(function (ring: number[]): void {
      let part = '';
      let lastX = NaN;
      let lastY = NaN;
      let lastLon = NaN;
      let points = 0;
      const rbox = [Infinity, -Infinity, Infinity, -Infinity];
      for (let i = 0; i < ring.length; i += 2) {
        const rel = GeoMap.relative(ring[i], frame.lon0);
        const p = GeoMap.toScreen(frame, ring[i], ring[i + 1]);
        const jump = !isNaN(lastLon) && Math.abs(rel - lastLon) > 180;
        lastLon = rel;
        const last = i + 2 >= ring.length;
        if (!jump && !isNaN(lastX) && !last &&
            Math.abs(p[0] - lastX) < THIN_PX &&
            Math.abs(p[1] - lastY) < THIN_PX) {
          continue;
        }
        part += (isNaN(lastX) || jump ? 'M' : 'L') + p[0].toFixed(1) + ' ' +
          p[1].toFixed(1);
        lastX = p[0];
        lastY = p[1];
        points++;
        rbox[0] = Math.min(rbox[0], p[0]);
        rbox[1] = Math.max(rbox[1], p[0]);
        rbox[2] = Math.min(rbox[2], p[1]);
        rbox[3] = Math.max(rbox[3], p[1]);
      }
      if (points < 3 || (rbox[1] - rbox[0] < 0.5 && rbox[3] - rbox[2] < 0.5)) {
        return;
      }
      d += part + 'Z';
      box[0] = Math.min(box[0], rbox[0]);
      box[1] = Math.max(box[1], rbox[1]);
      box[2] = Math.min(box[2], rbox[2]);
      box[3] = Math.max(box[3], rbox[3]);
    });
    return { d: d, box: box };
  }

  // The lines of longitude and latitude, every `step` degrees, inside the
  // view.
  private graticule(frame: Json, view: View): string {
    const { log } = this.deps;
    log.debug("Entering GeoMap.graticule().");
    const span = Math.max(view.east - view.west, view.north - view.south);
    const step = span > 150 ? 30 : (span > 40 ? 10 : (span > 12 ? 5 : 2));
    let d = '';
    const line = function (points: number[][]): void {
      d += points.map(function (p: number[], i: number): string {
        return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1);
      }).join('');
    };
    for (let lon = Math.ceil((view.west + view.lon0) / step) * step;
         lon <= view.east + view.lon0; lon += step) {
      const points: number[][] = [];
      for (let lat = view.south; lat <= view.north; lat += 1) {
        points.push(GeoMap.toScreen(frame, lon, lat));
      }
      line(points);
    }
    for (let lat = Math.ceil(view.south / step) * step; lat <= view.north;
         lat += step) {
      const points: number[][] = [];
      for (let rel = view.west; rel <= view.east; rel += 1) {
        points.push(GeoMap.toScreen(frame, rel + view.lon0, lat));
      }
      line(points);
    }
    log.debug("Leaving GeoMap.graticule().");
    return '<path d="' + d + '" fill="none" stroke="' + GRATICULE +
      '" stroke-width="0.6"/>';
  }

  // A label with a white halo, so it reads over any fill.
  private label(x: number, y: number, text: string, size: number,
                weight: string, anchor: string): string {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering GeoMap.label().");
    log.debug("Leaving GeoMap.label().");
    return '<text x="' + x.toFixed(1) + '" y="' + y.toFixed(1) +
      '" font-size="' + size + '" font-weight="' + weight +
      '" text-anchor="' + anchor + '" fill="' + INK + '" stroke="' + PAPER +
      '" stroke-width="3" stroke-linejoin="round" paint-order="stroke">' +
      xmlEscape(text) + '</text>';
  }

  // -------------------------------------------------------------------------
  // THE PICTURE. `spec`:
  //
  //   level      'world' | 'continent' | 'country'
  //   continent  the continent's slug (continent level)
  //   iso        the country's code (country level)
  //   areas      iso -> { bucket (0-5), title, href? } — every country the
  //              caller counted; a country not here is NO_DATA, and still
  //              links to `linkFor(iso)` when that answers one
  //   linkFor    iso -> href or '' (the next level down, for any country)
  //   labels     [{ lon, lat, text, href? }] — a continent's or a country's
  //              count, placed by the caller
  //   cities     [{ lon, lat, name, people, title }] (country level)
  //
  // Answers `{ svg, width, height }`. Links are root-relative: `app.js`
  // rewrites them into the realm on the way out of a text/html response,
  // which is the only way this picture is served.
  // -------------------------------------------------------------------------
  render(spec: Json): Json {
    const { log, xmlEscape, textWidth } = this.deps;
    const self = this;
    log.debug("Entering GeoMap.render(). level=" + spec.level);
    const { list, byIso } = this.countries();
    const areas = spec.areas || {};
    const focus: Country | undefined = spec.level === 'country'
      ? byIso.get(String(spec.iso)) : undefined;
    const view: View = spec.level === 'continent' &&
      CONTINENTS[spec.continent] ? CONTINENTS[spec.continent].view
      : (focus ? this.countryView(focus, spec.cities) : WORLD);
    const frame = this.frameOf(view);
    const height = frame.height;
    const onScreen = function (box: number[]): boolean {
      return box[1] >= 0 && box[0] <= WIDTH && box[3] >= 0 &&
        box[2] <= height;
    };
    const shapes: string[] = [];
    const dots: string[] = [];
    list.forEach(function (c: Country): void {
      let d = '';
      const box = [Infinity, -Infinity, Infinity, -Infinity];
      c.polygons.forEach(function (polygon: number[][]): void {
        const drawn = GeoMap.polygonPath(frame, polygon);
        if (drawn.d && onScreen(drawn.box)) {
          d += drawn.d;
          box[0] = Math.min(box[0], drawn.box[0]);
          box[1] = Math.max(box[1], drawn.box[1]);
          box[2] = Math.min(box[2], drawn.box[2]);
          box[3] = Math.max(box[3], drawn.box[3]);
        }
      });
      const area = areas[c.iso];
      const bucket = area ? Number(area.bucket) || 0 : 0;
      // A COUNTRY VIEW IS ABOUT ITS CITIES, so the country itself is pale
      // whatever it counts: its fill on the world's scale would be the
      // darkest step, and the circles are drawn in that same indigo.
      const fill = focus && focus.iso === c.iso ? WASH
        : (bucket ? RAMP[bucket - 1] : (focus ? CONTEXT : NO_DATA));
      const href = (area && area.href) ||
        (spec.linkFor ? spec.linkFor(c.iso) : '');
      const title = (area && area.title) || c.name;
      const wrap = function (inner: string): string {
        return href ? '<a href="' + xmlEscape(href) + '">' + inner + '</a>'
          : '<g>' + inner + '</g>';
      };
      if (d) {
        shapes.push(wrap('<title>' + xmlEscape(title) + '</title>' +
          '<path d="' + d + '" fill="' + fill + '" stroke="' +
          (focus && focus.iso === c.iso ? INK : BORDER) + '" stroke-width="' +
          (focus && focus.iso === c.iso ? '1' : '0.6') +
          '" stroke-linejoin="round" fill-rule="evenodd"/>'));
      }
      // A counted country too small to see: a dot at its label point.
      const small = !d || (box[1] - box[0] < DOT_BELOW_PX &&
                           box[3] - box[2] < DOT_BELOW_PX);
      if (bucket && small && spec.level !== 'country') {
        const p = GeoMap.toScreen(frame, c.label[0], c.label[1]);
        if (p[0] >= 0 && p[0] <= WIDTH && p[1] >= 0 && p[1] <= height) {
          dots.push(wrap('<title>' + xmlEscape(title) + '</title>' +
            '<circle cx="' + p[0].toFixed(1) + '" cy="' + p[1].toFixed(1) +
            '" r="4" fill="' + RAMP[bucket - 1] + '" stroke="' + INK +
            '" stroke-width="0.8"/>'));
        }
      }
    });

    // THE LABELS, largest first and never on top of one another: a label
    // that would overlap one already placed is left to its tooltip.
    const placed: number[][] = [];
    const fits = function (x0: number, y0: number, x1: number,
                           y1: number): boolean {
      if (x0 < 0 || x1 > WIDTH || y0 < 0 || y1 > height) {
        return false;
      }
      return !placed.some(function (b: number[]): boolean {
        return x0 < b[2] && x1 > b[0] && y0 < b[3] && y1 > b[1];
      });
    };
    const texts: string[] = [];
    (spec.labels || []).forEach(function (l: Json): void {
      const p = GeoMap.toScreen(frame, l.lon, l.lat);
      const w = textWidth(l.text, LABEL_SIZE) + 6;
      const box = [p[0] - w / 2, p[1] - LABEL_SIZE, p[0] + w / 2, p[1] + 4];
      if (!fits(box[0], box[1], box[2], box[3])) {
        return;
      }
      placed.push(box);
      const text = self.label(p[0], p[1], l.text, LABEL_SIZE, '600',
                              'middle');
      texts.push(l.href ? '<a href="' + xmlEscape(l.href) + '">' + text +
                          '</a>' : text);
    });

    // THE CITIES, biggest drawn first so a small one on top stays visible;
    // area proportional to people, so the eye compares them fairly.
    const cities = (spec.cities || []).filter(function (c: Json): boolean {
      return typeof c.lon === 'number' && typeof c.lat === 'number';
    }).sort(function (a: Json, b: Json): number {
      return b.people - a.people;
    });
    const most = Math.max(1, ...cities.map(function (c: Json): number {
      return c.people;
    }));
    const circles: string[] = [];
    cities.forEach(function (c: Json): void {
      const p = GeoMap.toScreen(frame, c.lon, c.lat);
      const r = 4 + 14 * Math.sqrt(c.people / most);
      circles.push('<g><title>' + xmlEscape(c.title) + '</title>' +
        '<circle cx="' + p[0].toFixed(1) + '" cy="' + p[1].toFixed(1) +
        '" r="' + r.toFixed(1) + '" fill="' + INDIGO +
        '" fill-opacity="0.72" stroke="' + PAPER + '" stroke-width="2"/>' +
        '</g>');
      const text = c.name + ' · ' + c.people;
      const w = textWidth(text, CITY_LABEL_SIZE) + 4;
      const x = p[0] + r + 3;
      if (fits(x, p[1] - CITY_LABEL_SIZE + 2, x + w, p[1] + 5)) {
        placed.push([x, p[1] - CITY_LABEL_SIZE + 2, x + w, p[1] + 5]);
        texts.push(self.label(x, p[1] + 4, text, CITY_LABEL_SIZE, '400',
                              'start'));
      }
    });

    const svg = '<svg xmlns="http://www.w3.org/2000/svg" id="geo-map" ' +
      'viewBox="0 0 ' + WIDTH + ' ' + height + '" width="100%" ' +
      'style="max-width:' + WIDTH + 'px" role="img" aria-labelledby=' +
      '"geo-map-title" font-family="system-ui, sans-serif">' +
      '<title id="geo-map-title">' + xmlEscape(spec.title || 'Sign-ins') +
      '</title><rect x="0" y="0" width="' + WIDTH + '" height="' + height +
      '" fill="' + OCEAN + '"/>' + this.graticule(frame, view) +
      shapes.join('') + dots.join('') + circles.join('') + texts.join('') +
      '<rect x="0.5" y="0.5" width="' + (WIDTH - 1) + '" height="' +
      (height - 1) + '" fill="none" stroke="' + QUIET +
      '" stroke-opacity="0.35"/></svg>';
    log.debug("Leaving GeoMap.render(). " + svg.length + " byte(s).");
    return { svg: svg, width: WIDTH, height: height };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), with facades, as
// `federation_diagram.ts` has them.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GeoMap>(
  'admin-ui/geo_map',
  () => new GeoMap(GeoMap.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  GeoMap: GeoMap,
  installInstance: (instance: GeoMap): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  render: slot.forward('render'),
  countries: slot.forward('countries'),
  continentTable: slot.forward('continentTable'),
  countryView: slot.forward('countryView'),
  slugOf: GeoMap.slugOf,
  bucketOf: GeoMap.bucketOf,
  legendOf: GeoMap.legendOf,
  project: GeoMap.project,
  RAMP: GeoMap.RAMP,
  NO_DATA: GeoMap.NO_DATA,
  CONTINENTS: GeoMap.CONTINENTS
};
