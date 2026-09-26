// ===========================================================================
// tests/tools/natural-earth.js — REGENERATE THE COUNTRY OUTLINES (#255).
//
// Monitoring → Geolocation (`admin-ui/geolocation_admin.ts`) draws a world,
// a continent and a country, and what it draws them WITH is
// `admin-ui/natural_earth/countries.json`: every country's two-letter code,
// name, continent, label point and outline. That file is DERIVED from Natural
// Earth's 1:50m Admin 0 – Countries, which is PUBLIC DOMAIN — the one
// third-party dataset this repository ships, and the exception is argued in
// `admin-ui/CLAUDE.md` (*`/admin/geolocation` is the third drawing*) and
// `risk/CLAUDE.md`. This file is how it was made, so it can be made again
// rather than trusted.
//
//   curl -sSfLo ne50.geojson https://raw.githubusercontent.com/nvkelso/\
//   natural-earth-vector/9380cca83db5f9aef52d5e762765100745f84b27/geojson/\
//   ne_50m_admin_0_countries.geojson
//   node tests/tools/natural-earth.js ne50.geojson
//
// **THE INPUT IS PINNED BY ITS DIGEST**: a different file is refused unless
// `--any` is given, and then the digest written into the output says which
// file it was. The commit above is the last to touch that path upstream.
//
// WHAT IS KEPT, AND WHY IT IS NOT THE FILE AS PUBLISHED:
//
//   * ONE ROW PER ISO 3166-1 CODE, because that is what an assessment holds
//     (`country`, from the city or country dataset). Natural Earth draws
//     some codes as several features — Australia, its Indian Ocean
//     Territories and Ashmore and Cartier all carry `AU` — and they become one
//     row, named and placed by the feature whose own `ISO_A2` is the code.
//     `ISO_A2_EH` is read rather than `ISO_A2`, which is `-99` for France and
//     Norway. Somaliland and Northern Cyprus carry no code; their outlines go
//     to `SO` and `CY`, which is where an address there is geolocated. The
//     Siachen Glacier carries none and is where no address is: it is left out.
//   * SEVEN CONTINENTS. Natural Earth files eight overseas features under
//     "Seven seas (open ocean)"; each goes to its UN region instead, and South
//     Georgia (UN: the Americas) to South America.
//   * COORDINATES ROUNDED TO TWO DECIMALS (about a kilometre), a ring as a
//     flat [lon, lat, lon, lat, …] list, and a point equal to the one before
//     it after rounding dropped. The renderer thins further for the scale it
//     draws at (`GeoMap.ringPath()`), so the world is not drawn at the
//     precision a country needs.
// ===========================================================================

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// This file's own logger, for the Entering/Leaving lines the code style asks
// for.
const log = require('bunyan').createLogger({ name: 'natural-earth',
  level: process.env.LOG_LEVEL || 'info' });

// The input this repository's file was made from.
const PINNED_SHA256 =
  '3e458fc036ad0a66411f2c1e6cac49c5d7bfb81cb1123bc513b22511a2b7fdeb';
const UPSTREAM_COMMIT = '9380cca83db5f9aef52d5e762765100745f84b27';
const OUTPUT = path.join(__dirname, '..', '..', 'admin-ui', 'natural_earth',
                         'countries.json');

// The outlines with no code of their own, and the code an address there is
// geolocated to.
const MERGED = { 'Somaliland': 'SO', 'N. Cyprus': 'CY' };

// Natural Earth's "Seven seas (open ocean)" features, by their UN region.
const SEVEN_SEAS = { Africa: 'Africa', Asia: 'Asia', Europe: 'Europe',
                     Oceania: 'Oceania', Antarctica: 'Antarctica' };

function round(n) {
  log.debug("Entering round().");
  log.debug("Leaving round().");
  return Math.round(Number(n) * 100) / 100;
}

// One GeoJSON ring as a flat list, rounded, repeats dropped.
function ringOf(ring) {
  log.debug("Entering ringOf().");
  const out = [];
  ring.forEach(function (point) {
    const x = round(point[0]);
    const y = round(point[1]);
    const n = out.length;
    if (n && out[n - 2] === x && out[n - 1] === y) {
      return;
    }
    out.push(x, y);
  });
  log.debug("Leaving ringOf().");
  return out;
}

// A feature's polygons, each a list of rings (the first the outside).
function polygonsOf(geometry) {
  log.debug("Entering polygonsOf().");
  const polygons = geometry.type === 'Polygon' ? [geometry.coordinates]
    : geometry.coordinates;
  log.debug("Leaving polygonsOf().");
  return polygons.map(function (polygon) {
    return polygon.map(ringOf).filter(function (ring) {
      return ring.length >= 6;
    });
  }).filter(function (polygon) {
    return polygon.length > 0;
  });
}

function continentOf(p) {
  log.debug("Entering continentOf().");
  if (!/^Seven seas/.test(p.CONTINENT)) {
    log.debug("Leaving continentOf().");
    return p.CONTINENT;
  }
  log.debug("Leaving continentOf(). Seven seas.");
  return SEVEN_SEAS[p.REGION_UN] || 'South America';
}

function main(argv) {
  log.debug("Entering main().");
  const any = argv.indexOf('--any') >= 0;
  const input = argv.filter(function (a) {
    return a !== '--any';
  })[0];
  if (!input) {
    log.debug("Leaving main(). No input.");
    throw new Error('usage: node tests/tools/natural-earth.js ' +
                    '<ne_50m_admin_0_countries.geojson> [--any]');
  }
  const bytes = fs.readFileSync(input);
  const digest = crypto.createHash('sha256').update(bytes).digest('hex');
  if (digest !== PINNED_SHA256 && !any) {
    log.debug("Leaving main(). Not the pinned file.");
    throw new Error('the input\'s SHA-256 is ' + digest + ', not the pinned ' +
                    PINNED_SHA256 + '; pass --any to use it anyway');
  }
  const features = JSON.parse(bytes.toString('utf8')).features;
  const rows = new Map();
  features.forEach(function (f) {
    const p = f.properties;
    const iso = p.ISO_A2_EH !== '-99' ? p.ISO_A2_EH : MERGED[p.NAME];
    if (!iso) {
      return;
    }
    const row = rows.get(iso) || { iso: iso, name: '', continent: '',
                                   label: null, polygons: [] };
    // The feature whose own code this is names and places the row.
    if (!row.name || p.ISO_A2 === iso) {
      row.name = p.NAME;
      row.continent = continentOf(p);
      row.label = [round(p.LABEL_X), round(p.LABEL_Y)];
    }
    row.polygons = row.polygons.concat(polygonsOf(f.geometry));
    rows.set(iso, row);
  });
  const countries = Array.from(rows.values()).sort(function (a, b) {
    return a.iso < b.iso ? -1 : (a.iso > b.iso ? 1 : 0);
  });
  const out = {
    source: 'Natural Earth 1:50m Cultural Vectors, Admin 0 - Countries',
    url: 'https://www.naturalearthdata.com/downloads/50m-cultural-vectors/',
    upstream: 'https://github.com/nvkelso/natural-earth-vector/blob/' +
              UPSTREAM_COMMIT + '/geojson/ne_50m_admin_0_countries.geojson',
    inputSha256: digest,
    license: 'Public domain. "All versions of Natural Earth raster + vector ' +
             'map data found on this website are in the public domain." ' +
             'Made with Natural Earth.',
    generatedBy: 'tests/tools/natural-earth.js',
    countries: countries
  };
  fs.writeFileSync(OUTPUT, JSON.stringify(out) + '\n');
  log.info('wrote ' + countries.length + ' countries to ' + OUTPUT);
  log.debug("Leaving main().");
}

try {
  main(process.argv.slice(2));
} catch (e) {
  log.debug("Caught in natural-earth.js: " + ((e && e.message) || e));
  // A tool run from a shell: the reason is the whole of what it says.
  process.stderr.write(String((e && e.message) || e) + '\n');
  process.exitCode = 1;
}
