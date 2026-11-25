// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sdk_lockfile.js
//
// ===========================================================================
// THE IMAGE'S OPTIONAL SDKs COME FROM A LOCKFILE (#2141, ASVS 5.0.0 15.2.4).
//
// The Dockerfile installed node-vault and whatever `STS_CLOUD_SDKS` named
// with a bare `npm install <name>` into /opt/sts-sdk: no version, no
// lockfile, install scripts on — while docs/v1.2.0/product-security.md said
// the images install exactly what the lockfiles name. They are now `sdk/`,
// one pinned workspace per SDK and one lockfile, installed with `npm ci
// --omit=dev --ignore-scripts --workspace=…` (the Dockerfile argues it).
//
// In process, because every claim is about FILES — the Dockerfile, sdk/ and
// package.json — and the one script, `sdk/select.js`, the build runs:
//
//   1. no RUN line of the Dockerfile runs `npm install`, and the SDK prefix
//      is installed with `npm ci --omit=dev --ignore-scripts`;
//   2. every optional peer of package.json (what `STS_CLOUD_SDKS` has always
//      named) has a workspace, every workspace pins one package to an exact
//      version, and the lockfile holds that version at the TOP of the tree,
//      where `NODE_PATH=/opt/sts-sdk/node_modules` finds it;
//   3. node-vault, which every image installs, is pinned and has no install
//      script;
//   4. `select.js` maps names (scoped too) to workspaces, always adds
//      node-vault, and refuses an unknown name or a version the lockfile does
//      not hold;
//   5. .dockerignore lets sdk/ into the build context;
//   6. (#2159) tests/tools/dependency-windows.js audits sdk/package-lock.json
//      as well as the root's and names the lockfile on every finding; (#2219)
//      its 90-day update review reads the root lockfile only, never the 27
//      workspaces' pins, and the daily workflow runs the advisory windows
//      alone, the update review only when a dispatch asks; and every
//      `overrides` entry
//      of sdk/package.json is the version the lockfile holds (npm's
//      `--package-lock-only` leaves an existing entry as it was, so an
//      override added without `npm update <name>` would not take).
//   7. (#2220) every `npm ci` in the Dockerfile passes `--ignore-scripts`,
//      the service's own included, and the only packages of the root
//      lockfile with an install script are the ones the Dockerfile names
//      as building nothing the service loads — so a new one cannot arrive
//      unbuilt without failing here.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sdk_lockfile',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SDK = path.join(ROOT, 'sdk');

function readJson(rel) {
  log.debug("Entering readJson().");
  const parsed = JSON.parse(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
  log.debug("Leaving readJson().");
  return parsed;
}

// The Dockerfile's instructions with their continuation lines joined and
// every comment line dropped, so a RUN is read as one statement.
function instructions() {
  log.debug("Entering instructions().");
  const lines = fs.readFileSync(path.join(ROOT, 'Dockerfile'), 'utf8')
    .split('\n')
    .filter(function (line) {
      return !/^\s*#/.test(line);
    });
  const out = [];
  let current = '';
  lines.forEach(function (line) {
    if (/\\\s*$/.test(line)) {
      current += line.replace(/\\\s*$/, ' ');
    } else {
      out.push(current + line);
      current = '';
    }
  });
  log.debug("Leaving instructions().");
  return out;
}

function run(t) {
  log.debug("Entering run().");
  const select = require(path.join(SDK, 'select.js'));

  t.log.info('=== 1. the Dockerfile installs from lockfiles ===');
  const runs = instructions().filter(function (one) {
    return /^RUN\s/.test(one);
  });
  const floating = runs.filter(function (one) {
    return /\bnpm (install|i|add)\b/.test(one);
  });
  t.equal(floating.length, 0,
          'no RUN of the Dockerfile runs `npm install` (' + runs.length +
          ' RUN instructions)');
  const sdkInstall = runs.filter(function (one) {
    return one.indexOf('cd /opt/sts-sdk') >= 0 &&
      one.indexOf('npm ci') >= 0;
  });
  t.equal(sdkInstall.length, 1, 'one RUN installs the SDK prefix with npm ci');
  t.check(sdkInstall.length === 1 &&
          /npm ci --omit=dev --ignore-scripts \$\{workspaces\}/
            .test(sdkInstall[0]) &&
          sdkInstall[0].indexOf('node select.js ${STS_CLOUD_SDKS}') >= 0,
          'with --omit=dev --ignore-scripts and the workspaces select.js ' +
          'chose from STS_CLOUD_SDKS', sdkInstall.join(' / '));
  t.check(instructions().some(function (one) {
    return /^COPY sdk\/ \/opt\/sts-sdk\/\s*$/.test(one);
  }), 'sdk/ is what becomes /opt/sts-sdk');

  t.log.info('=== 2. every optional SDK is a pinned workspace ===');
  const manifest = readJson('package.json');
  const root = readJson('sdk/package.json');
  const lock = readJson('sdk/package-lock.json');
  t.check(JSON.stringify(root.workspaces) === '["packages/*"]' &&
          !root.dependencies && !root.optionalDependencies,
          'sdk/package.json declares its workspaces and no dependency of its ' +
          'own', JSON.stringify(root));
  t.equal(lock.lockfileVersion, 3, 'the lockfile is version 3');
  const peers = Object.keys(manifest.peerDependencies || {}).sort();
  const missing = peers.filter(function (name) {
    return !fs.existsSync(path.join(SDK, 'packages',
                                    select.workspaceOf(name),
                                    'package.json'));
  });
  t.equal(missing.join(', '), '',
          'each of package.json\'s ' + peers.length + ' optional peers has ' +
          'a workspace');
  const workspaces = fs.readdirSync(path.join(SDK, 'packages')).sort();
  const wrong = [];
  workspaces.forEach(function (dir) {
    const pkg = readJson('sdk/packages/' + dir + '/package.json');
    const deps = Object.keys(pkg.dependencies || {});
    const name = deps[0];
    const pinned = name ? pkg.dependencies[name] : '';
    const top = (lock.packages || {})['node_modules/' + name] || {};
    const declared = (lock.packages || {})['packages/' + dir] || {};
    if (deps.length !== 1 || pkg.name !== dir ||
        select.workspaceOf(name) !== dir) {
      wrong.push(dir + ': not one package under its own name');
    } else if (!/^\d+\.\d+\.\d+$/.test(pinned)) {
      wrong.push(dir + ': ' + name + ' is not an exact version (' +
                 pinned + ')');
    } else if (top.version !== pinned) {
      wrong.push(dir + ': the lockfile has ' + name + '@' + top.version +
                 ' at the top of the tree, not ' + pinned);
    } else if (!top.integrity || !top.resolved) {
      wrong.push(dir + ': ' + name + ' has no integrity in the lockfile');
    } else if (!declared.dependencies ||
               declared.dependencies[name] !== pinned) {
      wrong.push(dir + ': the lockfile is older than the manifest');
    }
  });
  t.equal(wrong.join('; '), '',
          'each of the ' + workspaces.length + ' workspaces pins one package ' +
          'exactly, and the lockfile holds it at the top of the tree');

  t.log.info('=== 3. node-vault ===');
  const vault = (lock.packages || {})['node_modules/node-vault'] || {};
  t.check(!!vault.version && !vault.hasInstallScript,
          'node-vault ' + vault.version + ' is pinned and has no install ' +
          'script', JSON.stringify(vault));

  t.log.info('=== 4. select.js ===');
  const exact = function (version, range) {
    return version === range;
  };
  const none = select.select([''], SDK, exact);
  t.equal(JSON.stringify(none),
          JSON.stringify({ workspaces: ['sts-sdk-node-vault'], errors: [] }),
          'an empty STS_CLOUD_SDKS installs node-vault alone');
  const kmsVersion = lock.packages['node_modules/@aws-sdk/client-kms'].version;
  const some = select.select(['mysql2', '@aws-sdk/client-kms@' + kmsVersion,
                              'node-vault'], SDK, exact);
  t.equal(JSON.stringify(some.workspaces),
          JSON.stringify(['sts-sdk-node-vault', 'sts-sdk-mysql2',
                          'sts-sdk-aws-sdk-client-kms']),
          'names, scoped names and a matching version select their ' +
          'workspaces, node-vault once');
  t.equal(some.errors.length, 0, 'and nothing is refused');
  const refused = select.select(['no-such-sdk', 'mysql2@0.0.1'], SDK, exact);
  t.check(refused.errors.length === 2 &&
          /no-such-sdk is not one of the pinned SDKs/
            .test(refused.errors[0]) &&
          /mysql2@0\.0\.1 asks for a version the lockfile does not hold/
            .test(refused.errors[1]),
          'an unknown name and a version the lockfile does not hold are ' +
          'refused', JSON.stringify(refused.errors));
  t.equal(JSON.stringify(select.parseSpec('@aws-sdk/client-kms@^3')),
          JSON.stringify({ name: '@aws-sdk/client-kms', range: '^3' }),
          'a scoped spec splits at its second @');

  t.log.info('=== 5. .dockerignore ===');
  // The tests image is built from the same context as the service image and
  // .dockerignore leaves itself out, so in that image sdk/ being HERE is the
  // proof; on a checkout the file is read as well.
  t.check(fs.existsSync(path.join(SDK, 'package-lock.json')),
          'sdk/ is in the build context (this image is built from it)');
  const ignoreFile = path.join(ROOT, '.dockerignore');
  if (fs.existsSync(ignoreFile)) {
    const ignored = fs.readFileSync(ignoreFile, 'utf8')
      .split('\n')
      .map(function (line) {
        return line.trim();
      })
      .filter(function (line) {
        return /^\/?sdk(\/|$)/.test(line) || line === '*';
      });
    t.equal(ignored.join(', '), '',
            'and .dockerignore names no rule that would leave it out');
  }

  t.log.info('=== 6. the advisory windows cover sdk/ (#2159), the update ' +
             'review does not (#2219) ===');
  const windows = require(path.join(ROOT, 'tests', 'tools',
                                    'dependency-windows.js'));
  t.equal(JSON.stringify(windows.LOCKFILES.map(function (one) {
    return one.name;
  })), JSON.stringify(['package-lock.json', 'sdk/package-lock.json']),
  'dependency-windows audits the root lockfile and sdk/\'s');
  const findings = windows.auditFindings({ vulnerabilities: { tar: { via: [
    { name: 'tar', severity: 'high',
      url: 'https://github.com/advisories/GHSA-34x7-hfp2-rc4v' }, 'node-gyp'
  ] } } }, 'sdk/package-lock.json');
  t.equal(JSON.stringify(findings),
          JSON.stringify([{ id: 'GHSA-34x7-hfp2-rc4v', severity: 'high',
                            package: 'tar',
                            lockfile: 'sdk/package-lock.json' }]),
          'a finding names the lockfile it came from');
  t.equal(JSON.stringify(windows.UPDATE_REVIEW_LOCKFILES.map(function (one) {
    return one.name;
  })), JSON.stringify(['package-lock.json']),
  'the 90-day update review reads the root lockfile only, not the ' +
  workspaces.length + ' sdk/ workspace pins (#2219)');
  const daily = fs.readFileSync(path.join(ROOT, '.github', 'workflows',
                                          'dependency-windows.yml'), 'utf8');
  const dailyRuns = daily.split('\n').filter(function (line) {
    return /node tests\/tools\/dependency-windows\.js/.test(line);
  });
  t.check(dailyRuns.length === 1 && !/--updates/.test(dailyRuns[0]) &&
          /--image-report=/.test(dailyRuns[0]),
          'the daily workflow runs the advisory windows and the image scan, ' +
          'without --updates', dailyRuns.join(' | '));
  t.check(/^\s+if \[ "\$\{UPDATE_REVIEW\}" = true \]; then args\+=\(--updates\); fi$/m
            .test(daily) &&
          /UPDATE_REVIEW: \$\{\{ inputs\.updates && 'true' \|\| 'false' \}\}/
            .test(daily),
          'and adds the update review only when a dispatch asks for it');
  const overrides = root.overrides || {};
  const unheld = Object.keys(overrides).filter(function (name) {
    const held = (lock.packages || {})['node_modules/' + name] || {};
    return held.version !== overrides[name];
  });
  t.equal(unheld.join(', '), '',
          'each of sdk/package.json\'s ' + Object.keys(overrides).length +
          ' overrides is the version the lockfile holds');
  t.check(!(lock.packages || {})['node_modules/request'],
          'and the lockfile holds no `request` (node-gyp 7\'s, #2159)');

  t.log.info('=== 7. no install script runs in the image build (#2220) ===');
  const installs = runs.filter(function (one) {
    return /\bnpm ci\b/.test(one);
  });
  const scripted = installs.filter(function (one) {
    return !/\bnpm ci\b[^&;]*--ignore-scripts/.test(one) &&
      one.indexOf('--prefix ./tests') < 0;
  });
  t.check(installs.length >= 3 && scripted.length === 0,
          'every `npm ci` of the service and the SDKs passes ' +
          '--ignore-scripts (' + installs.length + ' installs)',
          scripted.join(' / '));
  t.check(installs.some(function (one) {
    return /npm ci --omit=dev --ignore-scripts && npm cache clean --force/
      .test(one) && one.indexOf('npm sbom') >= 0;
  }), 'the dependencies stage installs the service\'s tree with ' +
      '--ignore-scripts before writing its SBOM');
  // What the Dockerfile's dependencies-stage comment argues needs no
  // rebuild. A name added here owes that comment a line saying why.
  const NEEDS_NO_BUILD = ['dtrace-provider', 'protobufjs'];
  const rootLock = readJson('package-lock.json');
  const withScripts = Object.keys(rootLock.packages || {})
    .filter(function (key) {
      const one = rootLock.packages[key];
      return key && one.hasInstallScript && !one.dev;
    })
    .map(function (key) {
      return key.replace(/^.*node_modules\//, '');
    })
    .sort();
  t.equal(withScripts.join(', '), NEEDS_NO_BUILD.join(', '),
          'the root lockfile\'s only shipped packages with an install ' +
          'script are the ones whose script builds nothing the service ' +
          'loads');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'sdk_lockfile',
  describe: 'the image installs its optional SDKs from sdk/package-lock.json',
  run: run
};
