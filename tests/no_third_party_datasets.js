'use strict';
//
// File: no_third_party_datasets.js
//
// ===========================================================================
// iya-sts DISTRIBUTES NO THIRD-PARTY DATASET (#62, 2026-09-22).
//
// The independent licence review on #62 drew the line this file holds: the
// geolocation, ASN, Tor, FireHOL, FIDO metadata, Pwned Passwords and GeoLite2
// data risk scoring reads are ADMINISTRATOR-SUPPLIED inputs, pulled into the
// deployment's own database at install time (`risk/risk_install.ts`) and
// never shipped. Several of those terms bind whoever redistributes — IPinfo's
// ShareAlike, FireHOL's constituent lists, FIDO's metadata terms, GeoLite2's
// EULA — so a copy committed "because it was convenient for a test" would put
// the whole project under them.
//
// So the tree is walked, as the image holds it, and a file is refused when it
// is shaped like a provider's distribution:
//
//   * a database format nothing here reads from a repository — `.mmdb`,
//     `.netset`, `.ipset`;
//   * a data file (`.csv`, `.tsv`, `.txt`, `.gz`, `.zip`, `.json`, `.jwt`,
//     `.bin`, `.filter`) whose NAME names a provider — DB-IP, IPinfo,
//     GeoLite/GeoIP, FireHOL or a blocklist, the Tor exit list, the FIDO MDS
//     BLOB, Pwned Passwords.
//
// Code and documentation that NAME a provider (this file, `risk/*.ts`, the
// CLAUDE.md files) are not data files and are not refused; synthetic
// fixtures live inside the test files, in each provider's format and with
// none of its data.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'no_third_party_datasets', level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Directories that are not this repository's to ship: dependencies, and
// build output that is regenerated.
const SKIP = new RegExp('(^|/)(node_modules|\\.git|coverage|' +
                        'debugger/embedded|node-ldapjs)(/|$)');

const DATABASE_EXTENSIONS = /\.(mmdb|netset|ipset)$/i;
const DATA_EXTENSIONS = /\.(csv|tsv|txt|gz|zip|json|jwt|bin|filter)$/i;
const PROVIDER_NAMES = new RegExp('(db-?ip|ipinfo|geolite|geoip|maxmind|' +
                                  'firehol|blocklist|torbulkexit|tor-exit|' +
                                  'exit-?nodes|mds3?-?blob|fido-?mds|' +
                                  'pwned|hibp)', 'i');

function walk(dir, out) {
  log.debug("Entering walk().");
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(ROOT, full).split(path.sep).join('/');
    if (SKIP.test(rel)) {
      return;
    }
    if (entry.isDirectory()) {
      walk(full, out);
    } else if (entry.isFile()) {
      out.push(rel);
    }
  });
  log.debug("Leaving walk().");
  return out;
}

function offending(rel) {
  log.debug("Entering offending().");
  const name = path.basename(rel);
  log.debug("Leaving offending().");
  return DATABASE_EXTENSIONS.test(name) ||
    (DATA_EXTENSIONS.test(name) && PROVIDER_NAMES.test(name));
}

async function run(t) {
  log.debug("Entering run().");
  const files = walk(ROOT, []);
  const found = files.filter(offending);
  t.check(files.length > 100, 'the tree was walked', files.length +
          ' file(s)');
  t.check(found.length === 0,
          'no file in the tree is a third-party dataset — every dataset is ' +
          'supplied by a deployment\'s administrator, never shipped',
          found.join(', '));
  // The rule catches what it says it does: a DB-IP CSV and a GeoLite2
  // database by name, and neither this file nor the importer's source.
  t.check(offending('fixtures/dbip-city-lite-2026-09.csv') &&
          offending('data/GeoLite2-City.mmdb') &&
          offending('x/firehol_level1.netset') &&
          !offending('tests/no_third_party_datasets.js') &&
          !offending('risk/risk_datasets.ts'),
          'and the rule refuses a provider\'s file by its name and format, ' +
          'not the code that reads one');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'no_third_party_datasets',
  describe: 'no third-party dataset (DB-IP, IPinfo, GeoLite2, FireHOL, the ' +
            'Tor exit list, FIDO MDS, Pwned Passwords) is in the tree: they ' +
            'are administrator-supplied at install time (#62)',
  run: run
};
