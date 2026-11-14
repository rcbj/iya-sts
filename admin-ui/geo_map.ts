// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin-ui/geo_map.ts
//
// ===========================================================================
// THE GEOLOCATION PICTURE (#255), AS THIS PROCESS DRAWS IT: where a realm's
// people signed in from, drawn as a map — the world, a continent or a
// country. `admin-ui/geolocation_admin.ts` counts; this file draws the
// `picture.svg` its answer carries.
//
// **THE GEOMETRY IS NOT HERE ANY MORE (#444 phase 2b, 2026-11-14).** It moved,
// verbatim, to `web_geo_map.ts` — the projection, the views, the thinning,
// the labels — which the console's script bundles, so the console draws the
// map in the browser from the answer's `drawing.map` and the outlines it
// fetches from `/admin/geo-outlines.json`, and the Rust runtime ports a
// projection's arithmetic rather than a drawing. That file carries the
// reasoning. What is left here is what only this process has: the logger,
// and the outlines read from disk, once — `natural_earth/countries.json`,
// Natural Earth's public-domain 1:50m countries, reduced by
// `tests/tools/natural-earth.js` (`admin-ui/CLAUDE.md`, *`/admin/geolocation`
// is the third drawing*, says why this one dataset ships).
//
// It is a LIBRARY (rule 3): it registers no route, so its place in the
// require order does not matter, and everything it draws arrives as an
// argument.
// ===========================================================================

import fs = require('fs');
import path = require('path');
import helpers = require('../common/helpers');
import drawingModule = require('./web_geo_map');
import InstanceSlot = require('../common/instance_slot');

type Json = any;

interface GeoMapDeps {
  log: typeof helpers.log;
  drawing: typeof drawingModule;
  readOutlines(): Json;
}

/**
 * The geolocation picture as this process draws it: `web_geo_map.ts`'s
 * geometry over the outlines read from disk. A library that registers no
 * route.
 */
class GeoMap {
  /**
   * The fill scale, `web_geo_map.ts`'s.
   */
  static readonly RAMP = drawingModule.RAMP;
  /**
   * The colour of a country with no data, `web_geo_map.ts`'s.
   */
  static readonly NO_DATA = drawingModule.NO_DATA;
  /**
   * The continents by slug, `web_geo_map.ts`'s.
   */
  static readonly CONTINENTS = drawingModule.CONTINENTS;

  private file: Json = null;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the logger, the drawing and the reader of the country
   * outlines
   */
  constructor(private readonly deps: GeoMapDeps) {
    deps.log.debug("Entering GeoMap.constructor().");
    deps.log.debug("Leaving GeoMap.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): GeoMapDeps {
    helpers.log.debug("Entering GeoMap.defaultDeps().");
    helpers.log.debug("Leaving GeoMap.defaultDeps().");
    return {
      log: helpers.log,
      drawing: drawingModule,
      readOutlines: function (): Json {
        return JSON.parse(fs.readFileSync(GeoMap.outlinesPath(), 'utf8'));
      }
    };
  }

  // Where the outlines are, for the reader above and for the console's
  // `/admin/geo-outlines.json`, which serves the same file's bytes.
  /**
   * Answers the path of `natural_earth/countries.json`.
   *
   * @returns the absolute path
   */
  static outlinesPath(): string {
    helpers.log.debug("Entering GeoMap.outlinesPath().");
    helpers.log.debug("Leaving GeoMap.outlinesPath().");
    return path.join(__dirname, 'natural_earth', 'countries.json');
  }

  // Every country, read once. `source` is the file's provenance, which the
  // page credits.
  /**
   * Reads every country's outline once and holds it.
   *
   * @returns the countries, the same indexed by ISO code, and the file's
   * provenance, which the page credits
   */
  countries(): Json {
    const { log, readOutlines, drawing } = this.deps;
    log.debug("Entering GeoMap.countries().");
    if (!this.file) {
      this.file = readOutlines();
    }
    log.debug("Leaving GeoMap.countries().");
    return drawing.countries(this.file);
  }

  // The continent slug a continent name is filed under ('' for none).
  /**
   * Answers the slug a continent name is filed under.
   *
   * @param continent - the continent's name
   * @returns its slug, or '' for none
   */
  static slugOf(continent: string): string {
    helpers.log.debug("Entering GeoMap.slugOf().");
    helpers.log.debug("Leaving GeoMap.slugOf().");
    return drawingModule.slugOf(continent);
  }

  // ISO code -> continent name, for the store's count (`risk_store.ts`'s
  // `geography()`, which holds a country and no continent).
  /**
   * Maps each country's ISO code to its continent's name.
   *
   * @returns ISO code to continent name
   */
  continentTable(): Record<string, string> {
    const { log } = this.deps;
    log.debug("Entering GeoMap.continentTable().");
    const out: Record<string, string> = {};
    this.countries().list.forEach(function (c: Json): void {
      out[c.iso] = c.continent;
    });
    log.debug("Leaving GeoMap.continentTable().");
    return out;
  }

  /**
   * A count's step on the scale, 1 to 5, against the largest count drawn;
   * 0 for none (`web_geo_map.ts`).
   *
   * @param n - the count
   * @param max - the largest count drawn
   * @returns the step
   */
  static bucketOf(n: number, max: number): number {
    helpers.log.debug("Entering GeoMap.bucketOf().");
    helpers.log.debug("Leaving GeoMap.bucketOf().");
    return drawingModule.bucketOf(n, max);
  }

  /**
   * The legend: each step's colour and the counts it covers.
   *
   * @param max - the largest count drawn
   * @returns one row per step
   */
  static legendOf(max: number): Json[] {
    helpers.log.debug("Entering GeoMap.legendOf().");
    helpers.log.debug("Leaving GeoMap.legendOf().");
    return drawingModule.legendOf(max);
  }

  // A hot path: called for every point of every ring. No Entering/Leaving
  // pair, which would drown the log.
  /**
   * Projects a longitude and latitude with Equal Earth.
   *
   * @param lon - degrees east
   * @param lat - degrees north
   * @returns the projected point
   */
  static project(lon: number, lat: number): number[] {
    return drawingModule.project(lon, lat);
  }

  /**
   * Computes the view one country is drawn in, widened by its cities.
   *
   * @param country - the country's outline
   * @param cities - the cities drawn on it
   * @returns the view: its meridian and its west, east, south and north bounds
   */
  countryView(country: Json, cities: Json[]): Json {
    const { log, drawing } = this.deps;
    log.debug("Entering GeoMap.countryView(). " + (country && country.iso));
    log.debug("Leaving GeoMap.countryView().");
    return drawing.countryView(country, cities);
  }

  /**
   * Draws the map at the world, continent or country level.
   *
   * @param spec - `level`, `continent`, `iso`, `areas` (ISO code to bucket,
   * title and link), `linkFor`, `labels`, `cities` and `title`
   * @returns the SVG, its width and height
   */
  render(spec: Json): Json {
    const { log, drawing } = this.deps;
    log.debug("Entering GeoMap.render(). level=" + spec.level);
    if (!this.file) {
      this.countries();
    }
    const drawn = drawing.render(spec, this.file);
    log.debug("Leaving GeoMap.render(). " + drawn.svg.length + " byte(s).");
    return drawn;
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

/**
 * The geolocation picture: where a realm's people signed in from, drawn as a
 * map of the world, a continent or a country, for
 * `admin-ui/geolocation_admin.ts`, which counts.
 * @namespace
 */
export = {
  GeoMap: GeoMap,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: GeoMap): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  render: slot.forward('render'),
  countries: slot.forward('countries'),
  continentTable: slot.forward('continentTable'),
  countryView: slot.forward('countryView'),
  outlinesPath: GeoMap.outlinesPath,
  slugOf: GeoMap.slugOf,
  bucketOf: GeoMap.bucketOf,
  legendOf: GeoMap.legendOf,
  project: GeoMap.project,
  RAMP: GeoMap.RAMP,
  NO_DATA: GeoMap.NO_DATA,
  CONTINENTS: GeoMap.CONTINENTS
};
