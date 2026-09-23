'use strict';
//
// File: risk_datasets.js
//
// ===========================================================================
// THE RISK DATASETS AND THE FAILURE HISTORY (#62 P1, 2026-09-22), in
// process, on the memory store.
//
// `risk/risk_store.ts` answers the same methods from maps when there is no
// database, and those are the ones driven here; the postgres driver's SQL is
// driven by `tests/vendored/sts_admin_risk.js` against a real database in the
// single-node and cluster modes. What this file holds:
//
//   A. The address arithmetic every lookup rests on — a range from a single
//      address, a CIDR block or a dashed range, IPv4 and IPv6; the /24 and
//      /48 an address is kept as.
//   B. Import, in every format: DB-IP city (with a quoted city holding a
//      comma), DB-IP ASN, IPinfo Lite with its header, an IP list with
//      comments — and the lookups that read them, hits and misses, IPv4 and
//      IPv6.
//   C. The rules a version meets before it is active: a named SHA-256 that
//      does not match, a file with no row, a version that shrank past the
//      limit — each REFUSED and KEPT, with the active version untouched — and
//      a second import of the same version loading nothing.
//   D. Activation, rollback, deletion and retention.
//   E. Staleness: a dataset past its limit says nothing and is named.
//   F. A per-realm operator list answers in its realm only, and a
//      service-wide dataset cannot be given a realm.
//   G. The dataset directory: a manifest and its file, imported once.
//   H. The failure history: a refused password is recorded with the network
//      and a digest of a name that matched nobody — never the name, never the
//      address.
//   I. Monitoring → Risk's actions refuse an unknown action in rule 7's
//      sentence, and an import through them loads a version.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');

const config = require('../common/config');
const realms = require('../common/realms');
const audit = require('../common/audit');
const stsCrypto = require('../common/crypto');
const riskStore = require('../risk/risk_store');
const riskDatasets = require('../risk/risk_datasets');
const riskFailures = require('../risk/risk_failures');
const riskAdmin = require('../admin-ui/risk_admin');
const riskInstall = require('../risk/risk_install');
const riskTerms = require('../risk/risk_terms');

const log = require('bunyan').createLogger({ name: 'risk_datasets',
  level: process.env.LOG_LEVEL || 'info' });

// EVERY FIXTURE HERE IS SYNTHETIC (the licence review on #62): the addresses
// are the documentation ranges (RFC 5737, RFC 3849) and the benchmarking one
// (RFC 2544), the ASNs are the documentation ones (RFC 5398), and the names
// are made up. They are in each provider's FORMAT and carry none of any
// provider's DATA — `tests/no_third_party_datasets.js` holds the repository
// to that.
const DBIP_CITY = [
  '192.0.2.0,192.0.2.255,OC,AU,Queensland,"Example City, Queensland",' +
    '-27.4748,153.017',
  '198.51.100.0,198.51.100.255,AS,CN,Fujian,Exampleton,26.0614,119.306',
  '2001:db8::,2001:db8:0:ffff:ffff:ffff:ffff:ffff,EU,DE,Berlin,Berlin,' +
    '52.52,13.405',
  'this line is not a row',
  ''
].join('\n');

const DBIP_ASN = [
  '192.0.2.0,192.0.2.255,64496,Example Networks, Ltd.',
  '198.18.8.0,198.18.8.255,64497,Documentation Carrier'
].join('\n');

const IPINFO = [
  'network,country,country_code,continent,continent_code,asn,as_name,' +
    'as_domain',
  '198.18.9.0/24,Switzerland,CH,Europe,EU,AS64498,Example Resolver,' +
    'resolver.example',
  '2001:db8:fe::/48,Switzerland,CH,Europe,EU,AS64498,Example Resolver,' +
    'resolver.example'
].join('\n');

const TOR = [
  '# a synthetic exit list',
  '203.0.113.10',
  '198.18.100.0/24   ; a whole network',
  '203.0.113.50 - 203.0.113.59'
].join('\n');

async function partA(t) {
  log.debug("Entering partA().");
  t.equal(JSON.stringify(riskStore.rangeOf('192.0.2.10')),
          JSON.stringify({ start: '192.0.2.10', end: '192.0.2.10' }),
          'A1. one address is a range of one');
  t.equal(JSON.stringify(riskStore.rangeOf('198.51.100.77/24')),
          JSON.stringify({ start: '198.51.100.0', end: '198.51.100.255' }),
          'A2. a CIDR block is the block it names, host bits or not');
  t.equal(JSON.stringify(riskStore.rangeOf('2001:db8::/32')),
          JSON.stringify({ start: '2001:db8::',
                           end: '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff' }),
          'A3. an IPv6 block, written as inet writes it');
  t.check(riskStore.rangeOf('10.0.0.9 - 10.0.0.1') === null &&
          riskStore.rangeOf('10.0.0.1 - ::1') === null &&
          riskStore.rangeOf('not an address') === null &&
          riskStore.rangeOf('10.0.0.0/33') === null,
          'A4. a backwards range, a range across families, a word and a ' +
          'prefix too long are none');
  t.check(riskStore.prefixOf('203.0.113.77') === '203.0.113.0/24' &&
          riskStore.prefixOf('::ffff:203.0.113.77') === '203.0.113.0/24' &&
          riskStore.prefixOf('2001:db8:1234:5678::1') === '2001:db8:1234::/48' &&
          riskStore.prefixOf('nonsense') === '',
          'A5. an address is kept as its /24 or /48, a mapped IPv4 as IPv4');
  log.debug("Leaving partA().");
}

async function partB(t) {
  log.debug("Entering partB().");
  const city = await riskDatasets.importVersion({
    dataset: 'geo.city', format: 'dbip-city-csv', content: DBIP_CITY,
    version: 'city-1', source: 'upload' });
  t.check(city.ok && city.rows === 3 && city.skipped === 1 &&
          city.activated === true,
          'B1. a DB-IP city file loads its three rows, skips the line that ' +
          'is not one, and is activated', JSON.stringify(city));
  const asn = await riskDatasets.importVersion({
    dataset: 'asn', format: 'dbip-asn-csv', content: DBIP_ASN,
    version: 'asn-1', source: 'upload' });
  t.check(asn.ok && asn.rows === 2, 'B2. a DB-IP ASN file loads',
          JSON.stringify(asn));
  const tor = await riskDatasets.importVersion({
    dataset: 'iplist.tor-exit', format: 'ip-list', content: TOR,
    version: 'tor-1', source: 'upload' });
  t.check(tor.ok && tor.rows === 3 && tor.skipped === 0,
          'B3. an IP list reads an address, a block and a range, and its ' +
          'comments are not rows', JSON.stringify(tor));
  const one = await riskDatasets.lookup('192.0.2.77', 'default');
  t.check(one.geo && one.geo.city === 'Example City, Queensland' &&
          one.geo.country === 'AU' && one.geo.latitude === -27.4748 &&
          one.asn && one.asn.asn === 64496 &&
          one.asn.asOrg === 'Example Networks, Ltd.' &&
          one.datasets['geo.city'] === 'city-1' &&
          one.datasets.asn === 'asn-1',
          'B4. an IPv4 address finds its city (a quoted name with a comma), ' +
          'its ASN, and the versions that answered', JSON.stringify(one));
  const six = await riskDatasets.lookup('2001:db8::1', 'default');
  t.check(six.geo && six.geo.country === 'DE' && !six.asn,
          'B5. an IPv6 address finds its IPv6 range', JSON.stringify(six));
  const miss = await riskDatasets.lookup('198.18.200.1', 'default');
  t.check(!miss.geo && !miss.asn && miss.lists.length === 0,
          'B6. an address in no range finds nothing', JSON.stringify(miss));
  const listed = await riskDatasets.lookup('203.0.113.55', 'default');
  t.check(listed.lists.length === 1 &&
          listed.lists[0].category === 'tor-exit',
          'B7. an address inside a listed range is on the list',
          JSON.stringify(listed.lists));
  const info = await riskDatasets.importVersion({
    dataset: 'geo.country', format: 'ipinfo-lite-csv', content: IPINFO,
    version: 'country-1', source: 'upload' });
  t.check(info.ok && info.rows === 2 && info.skipped === 0,
          'B8. an IPinfo Lite file loads by its header, which is not a row',
          JSON.stringify(info));
  const resolver = await riskDatasets.lookup('198.18.9.9', 'default');
  t.check(resolver.geo && resolver.geo.dataset === 'geo.country' &&
          resolver.geo.country === 'CH',
          'B9. where the city dataset has no range, the country dataset ' +
          'answers', JSON.stringify(resolver.geo));
  t.check(one.attributions.some(function (a) {
    return a.provider === 'dbip-lite' && a.url === 'https://db-ip.com' &&
      /DB-IP/.test(a.text) && a.licence === 'CC BY 4.0' &&
      a.licenceUrl === 'https://creativecommons.org/licenses/by/4.0/' &&
      /reformatted/.test(a.modified);
  }) && resolver.attributions.some(function (a) {
    return a.provider === 'ipinfo-lite';
  }),
          'B10. every lookup carries the credit CC BY 4.0 asks of each ' +
          'provider whose data answered: the attribution linked, the licence ' +
          'named and linked, and that it was modified here',
          JSON.stringify(one.attributions));
  log.debug("Leaving partB().");
}

async function partC(t) {
  log.debug("Entering partC().");
  const wrong = await riskDatasets.importVersion({
    dataset: 'iplist.reputation', format: 'ip-list', content: '192.0.2.1',
    version: 'rep-bad', sha256: 'a'.repeat(64), source: 'upload' });
  const versions = await riskStore.listVersions('', 'iplist.reputation');
  t.check(!wrong.ok && wrong.errors[0].indexOf('SHA-256') >= 0 &&
          versions[0].state === 'refused' &&
          versions[0].errorCode === 'STS-RISK-0002',
          'C1. a file whose SHA-256 is not the one named is refused, and ' +
          'the refused version is KEPT with its reason',
          JSON.stringify(versions[0]));
  const right = await riskDatasets.importVersion({
    dataset: 'iplist.reputation', format: 'ip-list', content: '192.0.2.1',
    version: 'rep-good',
    sha256: stsCrypto.truncatedSha256Hex('192.0.2.1', 64),
    source: 'upload' });
  t.check(right.ok, 'C2. and one whose SHA-256 matches loads',
          JSON.stringify(right));
  const empty = await riskDatasets.importVersion({
    dataset: 'iplist.reputation', format: 'ip-list',
    content: '# nothing\nnot-an-address\n', version: 'rep-empty',
    source: 'upload' });
  t.check(!empty.ok && /No line/.test(empty.errors[0]),
          'C3. a file with no row is refused', JSON.stringify(empty));
  const big = Array.from({ length: 10 }, function (x, i) {
    return '10.10.' + i + '.0/24';
  }).join('\n');
  await riskDatasets.importVersion({ dataset: 'iplist.reputation',
    format: 'ip-list', content: big, version: 'rep-10', source: 'upload' });
  const small = await riskDatasets.importVersion({
    dataset: 'iplist.reputation', format: 'ip-list',
    content: '10.10.0.0/24\n10.10.1.0/24', version: 'rep-2',
    source: 'upload' });
  const still = await riskDatasets.lookup('10.10.9.1', 'default');
  t.check(!small.ok && /fewer is refused/.test(small.errors[0]) &&
          still.datasets['iplist.reputation'] === 'rep-10',
          'C4. a version with more than risk.datasetShrinkLimitPercent ' +
          'fewer rows is refused and the active version stays',
          JSON.stringify(small) + ' ' + JSON.stringify(still.datasets));
  const again = await riskDatasets.importVersion({ dataset: 'iplist.reputation',
    format: 'ip-list', content: big, version: 'rep-10', source: 'upload' });
  t.check(again.ok && again.duplicate === true,
          'C5. the same version again is recorded already, and nothing is ' +
          'loaded twice', JSON.stringify(again));
  log.debug("Leaving partC().");
}

async function partD(t) {
  log.debug("Entering partD().");
  const v2 = await riskDatasets.importVersion({ dataset: 'asn',
    format: 'dbip-asn-csv', version: 'asn-2', source: 'upload',
    content: DBIP_ASN + '\n198.18.9.0,198.18.9.255,64498,Example Resolver' });
  const now = await riskDatasets.lookup('198.18.9.9', 'default');
  t.check(v2.ok && now.asn && now.asn.asn === 64498,
          'D1. a new version replaces the active one', JSON.stringify(now.asn));
  const back = await riskDatasets.rollback('', 'asn', 'a test');
  const after = await riskDatasets.lookup('198.18.9.9', 'default');
  t.check(back.ok && back.version === 'asn-1' && !after.asn,
          'D2. rollback makes the previous version active again, and ' +
          'lookups follow at once', JSON.stringify(back));
  const refusedDelete = await riskDatasets.deleteVersion('', 'asn', 'asn-1',
                                                         'a test');
  t.check(!refusedDelete.ok, 'D3. the active version cannot be deleted');
  const deleted = await riskDatasets.deleteVersion('', 'asn', 'asn-2',
                                                   'a test');
  const versions = await riskStore.listVersions('', 'asn');
  t.check(deleted.ok && deleted.rows === 3 &&
          versions.filter(function (v) {
            return v.version === 'asn-2';
          })[0].state === 'deleted',
          'D4. a superseded version\'s rows can be deleted, and its record ' +
          'stays', JSON.stringify(deleted));
  const cannot = await riskDatasets.activateVersion('', 'asn', 'asn-2',
                                                    'a test');
  t.check(!cannot.ok, 'D5. a deleted version cannot be made active');
  config.setOverride('risk.supersededRetentionDays', 0);
  await riskDatasets.importVersion({ dataset: 'geo.city',
    format: 'dbip-city-csv', content: DBIP_CITY + '\n5.5.5.0,5.5.5.255,EU,' +
      'FR,Paris,Paris,48.85,2.35', version: 'city-2', source: 'upload' });
  const retained = await riskDatasets.retainVersions();
  const cityVersions = await riskStore.listVersions('', 'geo.city');
  config.setOverride('risk.supersededRetentionDays', 30);
  t.check(retained.versions >= 1 && cityVersions.filter(function (v) {
    return v.version === 'city-1';
  })[0].state === 'deleted',
          'D6. retention deletes the rows of a version superseded past ' +
          'risk.supersededRetentionDays', JSON.stringify(retained));
  log.debug("Leaving partD().");
}

async function partE(t) {
  log.debug("Entering partE().");
  // One row against the active version's three would be refused as a
  // shrink (C4); that rule is not what this part is about.
  config.setOverride('risk.datasetShrinkLimitPercent', 100);
  await riskDatasets.importVersion({ dataset: 'iplist.tor-exit',
    format: 'ip-list', content: '192.0.2.200', version: 'tor-old',
    publishedAt: Date.now() - 3 * 86400000, source: 'upload' });
  config.setOverride('risk.datasetShrinkLimitPercent', 50);
  const found = await riskDatasets.lookup('192.0.2.200', 'default');
  t.check(found.lists.length === 0 &&
          found.stale.indexOf('iplist.tor-exit') >= 0 &&
          !found.datasets['iplist.tor-exit'],
          'E1. a list published longer ago than its staleness limit says ' +
          'nothing about an address it lists, and is named as stale',
          JSON.stringify(found));
  const registry = await riskDatasets.registry('default');
  const tor = registry.datasets.filter(function (d) {
    return d.dataset === 'iplist.tor-exit';
  })[0];
  t.equal(tor.state, 'stale', 'E2. and the registry says so');
  log.debug("Leaving partE().");
}

async function partF(t) {
  log.debug("Entering partF().");
  const deny = await riskDatasets.importVersion({
    dataset: 'iplist.operator-deny', realm: 'acme', format: 'ip-list',
    content: '192.0.2.99', version: 'deny-1', source: 'upload' });
  const inAcme = await riskDatasets.lookup('192.0.2.99', 'acme');
  const elsewhere = await riskDatasets.lookup('192.0.2.99', 'default');
  t.check(deny.ok && inAcme.lists.some(function (l) {
    return l.category === 'operator-deny';
  }) && !elsewhere.lists.some(function (l) {
    return l.category === 'operator-deny';
  }), 'F1. an operator list answers in its own realm and no other',
          JSON.stringify(inAcme.lists) + ' ' +
          JSON.stringify(elsewhere.lists));
  const wrongRealm = await riskDatasets.importVersion({
    dataset: 'asn', realm: 'acme', format: 'dbip-asn-csv', content: DBIP_ASN,
    source: 'upload' });
  const noRealm = await riskDatasets.importVersion({
    dataset: 'iplist.operator-allow', format: 'ip-list', content: '10.0.0.1',
    source: 'upload' });
  const badFormat = await riskDatasets.importVersion({
    dataset: 'asn', format: 'ip-list', content: '10.0.0.1',
    source: 'upload' });
  const noSuchRealm = await riskDatasets.importVersion({
    dataset: 'iplist.operator-deny', realm: 'no-such-realm',
    format: 'ip-list', content: '10.0.0.1', source: 'upload' });
  t.check(!wrongRealm.ok && !noRealm.ok && !badFormat.ok &&
          !noSuchRealm.ok,
          'F2. a service dataset with a realm, an operator list without ' +
          'one or for a realm that does not exist, and a format the dataset ' +
          'does not take are refused',
          JSON.stringify([wrongRealm.errors, noRealm.errors,
                          badFormat.errors, noSuchRealm.errors]));
  log.debug("Leaving partF().");
}

async function partG(t) {
  log.debug("Entering partG().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'risk-datasets-'));
  fs.writeFileSync(path.join(dir, 'reputation.txt'), '172.16.5.0/24\n');
  fs.writeFileSync(path.join(dir, 'reputation.json'), JSON.stringify({
    dataset: 'iplist.reputation', format: 'ip-list', file: 'reputation.txt',
    version: 'from-directory', publishedAt: new Date().toISOString() }));
  fs.writeFileSync(path.join(dir, 'broken.json'), '{ not json');
  config.setOverride('risk.datasetsDirectory', dir);
  config.setOverride('risk.datasetShrinkLimitPercent', 100);
  const first = await riskDatasets.importDirectory();
  const second = await riskDatasets.importDirectory();
  const hit = await riskDatasets.lookup('172.16.5.9', 'default');
  config.setOverride('risk.datasetShrinkLimitPercent', 50);
  config.setOverride('risk.datasetsDirectory', '');
  fs.rmSync(dir, { recursive: true, force: true });
  t.check(first.imported === 1 && first.skipped === 1 &&
          second.imported === 0 && second.duplicates === 1 &&
          hit.lists.some(function (l) {
            return l.dataset === 'iplist.reputation';
          }),
          'G1. the directory imports a manifest\'s file once, skips a ' +
          'manifest that is not JSON, and finds it already recorded the ' +
          'second time', JSON.stringify([first, second]));
  log.debug("Leaving partG().");
}

async function partH(t) {
  log.debug("Entering partH().");
  const TYPED = 'correct horse battery staple';
  await audit.withSource({ address: '203.0.113.77' }, function () {
    return riskFailures.recordFailure(TYPED, 'the sign-in screen',
                                      'STS-AUTHN-0054');
  });
  const page = await riskFailures.list('default', { since: 0 });
  const row = page.rows[0] || {};
  t.check(page.total >= 1 && row.prefix === '203.0.113.0/24' &&
          row.door === 'the sign-in screen' &&
          row.errorCode === 'STS-AUTHN-0054' && !row.subject &&
          /^digest /.test(row.name),
          'H1. a refused password is recorded with its network, door and ' +
          'code, and a name that matched nobody as a digest',
          JSON.stringify(row));
  t.check(JSON.stringify(page).indexOf(TYPED) < 0 &&
          JSON.stringify(page).indexOf('203.0.113.77') < 0,
          'H2. and neither the typed name nor the address is anywhere in it');
  t.check(riskFailures.describe().database === false,
          'H3. with no key-encryption key it is held in this process, and ' +
          'says so', JSON.stringify(riskFailures.describe()));
  log.debug("Leaving partH().");
}

async function partI(t) {
  log.debug("Entering partI().");
  const unknown = await riskAdmin.riskAction({ action: 'explode',
                                               dataset: 'asn' }, 'a test');
  t.equal(unknown.errors && unknown.errors[0],
          'Unknown action "explode". The 5 are: import, activate, rollback, ' +
          'delete, accept-terms.',
          'I1. an unknown action is refused in rule 7\'s sentence');
  const imported = await riskAdmin.riskAction({
    action: 'import', dataset: 'iplist.operator-allow', realm: 'acme',
    format: 'ip-list', content: '192.0.2.123\n' }, 'a test');
  const view = await riskAdmin.riskView({ realm: 'acme',
                                          address: '192.0.2.123' });
  t.check(imported.ok && view.lookup.lists.some(function (l) {
    return l.category === 'operator-allow';
  }) && view.datasets.length === Object.keys(riskDatasets.CATALOGUE).length,
          'I2. an import through the page\'s action loads, and the view ' +
          'draws every dataset and the lookup', JSON.stringify(imported));
  log.debug("Leaving partI().");
}

// ---------------------------------------------------------------------------
// J. The licence boundary (the independent review on #62): a provider this
// service does not support is refused, a provider's attribution cannot be
// replaced, and the install-time loader pulls nothing from a provider whose
// terms the operator has not accepted by name — nor over anything but HTTPS.
// ---------------------------------------------------------------------------
async function partJ(t) {
  log.debug("Entering partJ().");
  const geolite = await riskDatasets.importVersion({
    dataset: 'geo.country', format: 'dbip-country-csv',
    provider: 'maxmind-geolite2', content: '192.0.2.0,192.0.2.255,AU',
    source: 'upload' });
  const nobody = await riskDatasets.importVersion({
    dataset: 'geo.country', format: 'dbip-country-csv', provider: 'nobody',
    content: '192.0.2.0,192.0.2.255,AU', source: 'upload' });
  t.check(!geolite.ok && /not supported yet/.test(geolite.errors[0]) &&
          !nobody.ok && /no provider/.test(nobody.errors[0]),
          'J1. a provider not supported yet (GeoLite2), or not known at all, ' +
          'is refused', JSON.stringify([geolite.errors, nobody.errors]));
  const claimed = await riskDatasets.importVersion({
    dataset: 'asn', format: 'dbip-asn-csv', version: 'asn-claimed',
    content: DBIP_ASN + '\n198.18.30.0,198.18.30.255,64499,Other',
    attribution: 'somebody else', source: 'upload', activate: false });
  const versions = await riskStore.listVersions('', 'asn');
  const row = versions.filter(function (v) {
    return v.version === 'asn-claimed';
  })[0] || {};
  t.check(claimed.ok && row.attribution === 'IP Geolocation by DB-IP' &&
          row.parameters.attributionUrl === 'https://db-ip.com',
          'J2. a provider\'s attribution and link are its own, whatever the ' +
          'importer said', JSON.stringify(row));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'risk-install-'));
  const manifest = path.join(dir, 'datasets.json');
  fs.writeFileSync(manifest, JSON.stringify({ datasets: [
    { dataset: 'asn', format: 'dbip-asn-csv',
      url: 'https://download.example/asn.csv.gz' },
    { dataset: 'iplist.reputation', format: 'ip-list',
      url: 'https://lists.example/level1.netset' }] }));
  const before = process.env.STS_DATABASE_URL;
  process.env.STS_DATABASE_URL = 'postgres://nobody@127.0.0.1:1/none';
  const onlyDbip = await riskInstall.RiskInstall.run({ manifest: manifest,
    accepted: ['dbip-lite'], dryRun: true });
  const both = await riskInstall.RiskInstall.run({ manifest: manifest,
    accepted: ['dbip-lite', 'firehol'], dryRun: true });
  if (before === undefined) {
    delete process.env.STS_DATABASE_URL;
  } else {
    process.env.STS_DATABASE_URL = before;
  }
  t.check(onlyDbip === 1 && both === 0,
          'J3. the install-time loader refuses a dataset whose provider\'s ' +
          'terms were not accepted by name, and takes one whose were',
          onlyDbip + ' then ' + both);
  let refused = '';
  await riskInstall.RiskInstall.download('http://download.example/a.csv',
                                         path.join(dir, 'a'))
    .catch(function (e) {
      refused = e.message;
    });
  fs.rmSync(dir, { recursive: true, force: true });
  t.check(/only https/.test(refused),
          'J4. and it fetches over HTTPS only', refused);
  t.check(riskInstall.RiskInstall.optionsOf(['--manifest', 'm.json',
                                              '--accept-terms',
                                              'dbip-lite, tor-project'])
            .accepted.join(',') === 'dbip-lite,tor-project' &&
          riskInstall.RiskInstall.optionsOf([]) === null,
          'J5. its command line names the manifest and the accepted terms');
  log.debug("Leaving partJ().");
}

// ---------------------------------------------------------------------------
// K. THE TERMS (the second licence review on #62): no provider's data is
// imported until somebody has accepted its CURRENT terms, the acceptance is
// recorded with who, how and the terms text, an import may carry its own
// acceptance, terms that changed must be accepted again, and the
// install-time loader writes its acceptances to the store and a log file.
// Run first, before anything has been accepted.
// ---------------------------------------------------------------------------
async function partK(t) {
  log.debug("Entering partK().");
  const refused = await riskDatasets.importVersion({ dataset: 'asn',
    format: 'dbip-asn-csv', content: DBIP_ASN, source: 'upload' });
  t.check(!refused.ok && /have not been accepted/.test(refused.errors[0]),
          'K1. a DB-IP import with nobody having accepted DB-IP\'s terms is ' +
          'refused, and says how to accept them', JSON.stringify(refused));
  const own = await riskDatasets.importVersion({
    dataset: 'iplist.operator-deny', realm: 'acme', format: 'ip-list',
    content: '192.0.2.250\n', version: 'own-1', source: 'upload' });
  t.check(own.ok, 'K2. the operator\'s own list needs no acceptance',
          JSON.stringify(own));
  const carried = await riskDatasets.importVersion({ dataset: 'asn',
    format: 'dbip-asn-csv', content: DBIP_ASN, version: 'asn-0',
    source: 'upload', acceptTerms: true, actor: 'an-administrator' });
  const status = await riskTerms.status();
  const dbip = status.providers.filter(function (p) {
    return p.provider === 'dbip-lite';
  })[0];
  t.check(carried.ok && dbip.accepted &&
          dbip.accepted.acceptedBy === 'an-administrator' &&
          dbip.accepted.acceptedVia === 'upload' &&
          dbip.accepted.termsDigest === riskTerms.termsOf('dbip-lite').digest &&
          /CC BY 4\.0/.test(dbip.accepted.termsText),
          'K3. an import may carry its own acceptance, which is recorded ' +
          'with who, through which door, the terms text and its digest',
          JSON.stringify(dbip.accepted));
  // TERMS THAT CHANGED: an acceptance of an older text covers nothing.
  await riskStore.recordAcceptance({ provider: 'firehol',
    termsDigest: 'an-older-statement', termsText: 'older terms',
    acceptedBy: 'someone', acceptedVia: 'upload', deployment: 'x',
    pageDigest: '', acceptedAt: Date.now() - 1000 });
  const changed = await riskDatasets.importVersion({
    dataset: 'iplist.reputation', format: 'ip-list', content: '192.0.2.9\n',
    source: 'upload' });
  t.check(!changed.ok && /since they changed/.test(changed.errors[0]),
          'K4. terms accepted before they changed must be accepted again',
          JSON.stringify(changed.errors));
  const none = await riskTerms.accept({ provider: 'operator',
                                        acceptedBy: 'x', via: 'y' });
  const geolite = await riskTerms.accept({ provider: 'maxmind-geolite2',
                                           acceptedBy: 'x', via: 'y' });
  t.check(!none.ok && !geolite.ok,
          'K5. there is nothing to accept for the operator\'s own list, and ' +
          'GeoLite2 cannot be accepted: it is not supported',
          JSON.stringify([none.errors, geolite.errors]));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'risk-terms-'));
  const logFile = path.join(dir, 'acceptances.log');
  const failed = await riskInstall.RiskInstall.acceptNamed({
    manifest: '', accepted: ['tor-project', 'firehol', 'operator'],
    dryRun: false, operator: 'Jo Operator', termsLog: logFile });
  const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n')
    .map(function (l) {
      return JSON.parse(l);
    });
  fs.rmSync(dir, { recursive: true, force: true });
  const after = await riskTerms.status();
  t.check(failed === 0 && lines.length === 2 &&
          lines.every(function (l) {
            return l.acceptedBy === 'Jo Operator' && l.termsDigest &&
              l.terms && l.deployment;
          }) && after.providers.filter(function (p) {
            return p.provider === 'firehol';
          })[0].accepted.acceptedVia === 'the install-time loader',
          'K6. the install-time loader records each named provider\'s ' +
          'acceptance in the operator\'s name, in the store and as a line ' +
          'of its terms log with the terms text — and the operator\'s own ' +
          'list, having no terms, is not one of them', JSON.stringify(lines));
  // What every later part imports.
  await riskTerms.accept({ provider: 'ipinfo-lite', acceptedBy: 'a test',
                           via: 'upload' });
  log.debug("Leaving partK().");
}

async function run(t) {
  log.debug("Entering run().");
  // A realm of its own, for the per-realm lists (F, I): an operator list for
  // a realm that does not exist is refused.
  if (!realms.get('acme')) {
    realms.create({ id: 'acme', name: 'risk datasets test' });
  }
  riskStore.reset();
  riskDatasets.forget();
  await partK(t);
  riskDatasets.forget();
  await partA(t);
  await partB(t);
  await partC(t);
  await partD(t);
  await partE(t);
  await partF(t);
  await partG(t);
  await partH(t);
  await partI(t);
  await partJ(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'risk_datasets',
  describe: 'risk datasets on the memory store (#62 P1): the address ' +
            'arithmetic, import in every format with its lookups, the ' +
            'refusals a version meets, activation, rollback, deletion, ' +
            'retention, staleness, per-realm lists, the dataset directory, ' +
            'the failure history, and the page\'s actions',
  run: run
};
