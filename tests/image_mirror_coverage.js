// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: image_mirror_coverage.js
//
// ===========================================================================
// EVERY IMAGE THE TEST STACK PULLS, AND EVERY BASE IMAGE IT BUILDS FROM,
// COMES FROM THE PRIVATE MIRROR ON ghcr.io (2026-09-27).
//
// The parent project's b71e078 arrangement, and its test of the same name is
// the original. docker-compose-run-tests.yml takes every third-party image
// from ghcr.io/rcbj/iya-sts/mirror (.github/image-mirror.txt, copied by
// .github/workflows/mirror-images.yml) in two ways:
//
//  * a service that is only run names the mirror in its `image:`;
//  * a FROM is redirected by a named build context — `x-mirror-contexts` in
//    the compose file, tests/tools/mirror-contexts.sh for a `docker build`
//    outside it, and `build-contexts` in build-container.yml — which BuildKit
//    consults before any registry.
//
// BOTH FAIL OPEN. A FROM with no matching named context is not an error: it
// is pulled from Docker Hub exactly as before, and the run is green until the
// day Docker Hub is not there. So this reads the list, the two compose files,
// every Dockerfile the stack builds and the two workflows, and asserts:
//
//  1. every `image:` is the mirror (with a path the list has) or one of this
//     repository's own images under IMAGE_REGISTRY;
//  2. every named context in x-mirror-contexts points at a listed path;
//  3. every `build:` in the compose file carries those contexts;
//  4. every external FROM (and COPY --from) in a Dockerfile compose builds has
//     one — a reference already on ghcr.io/rcbj/ (the corpora) excepted;
//  5. the corpora Dockerfile's FROMs are in the list (its build uses
//     mirror-contexts.sh, which prints the whole list);
//  6. build-container.yml names a context for every FROM of the root
//     Dockerfile, each pointing at a listed path;
//  7. what push-stack-images.sh pushes is what run-tests.sh names.
//
// WHY IN PROCESS, which tests/CLAUDE.md asks first: every claim is a
// comparison between FILES in this repository — readme_ports.js's shape. A
// missing file FAILS rather than skips, because a check that compares nothing
// is the shape of bug it is here to catch.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'image_mirror_coverage',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const MIRROR = 'ghcr.io/rcbj/iya-sts/mirror/';
const MIRROR_PREFIX = '${IMAGE_MIRROR:-ghcr.io/rcbj/iya-sts/mirror}/';
const REGISTRY = '${IMAGE_REGISTRY:-ghcr.io/rcbj/iya-sts}/';
// Dockerfiles docker-compose-run-tests.yml builds.
const COMPOSE_DOCKERFILES = ['Dockerfile', 'tests/Dockerfile',
  'xacml-pep/Dockerfile', 'tests/saml-peers/shibboleth/Dockerfile',
  'tests/saml-peers/simplesamlphp/Dockerfile',
  'tests/saml-peers/pysaml2/Dockerfile', 'tests/saml-peers/keycloak/Dockerfile'];

function read(rel) {
  log.debug("Entering read(). " + rel);
  const file = path.join(ROOT, rel);
  if (!fs.existsSync(file)) {
    log.debug("Leaving read(). Missing.");
    throw new Error(rel + ' is not here. This check must fail rather than ' +
                    'pass vacuously; if the file moved, move it here too ' +
                    '(and in .dockerignore, for the tests image).');
  }
  log.debug("Leaving read().");
  return fs.readFileSync(file, 'utf8');
}

// `upstream  mirror-path` rows of .github/image-mirror.txt.
function mirrorRows(source) {
  log.debug("Entering mirrorRows().");
  const rows = [];
  source.split('\n').forEach(function (line) {
    const text = line.trim();
    if (!text || text.charAt(0) === '#') {
      return;
    }
    const cols = text.split(/\s+/);
    rows.push({ upstream: cols[0], path: cols[1], cols: cols.length });
  });
  log.debug("Leaving mirrorRows(). " + rows.length);
  return rows;
}

// A `${VAR:-default}` resolved to its default, as compose would with the
// variable unset.
function defaults(text) {
  log.debug("Entering defaults().");
  let out = String(text);
  let before = null;
  while (before !== out) {
    before = out;
    out = out.replace(/\$\{[A-Za-z_][A-Za-z0-9_]*:-([^${}]*)\}/g, '$1');
  }
  log.debug("Leaving defaults().");
  return out;
}

function codeLines(source) {
  log.debug("Entering codeLines().");
  log.debug("Leaving codeLines().");
  return source.split('\n').filter(function (line) {
    return !/^\s*#/.test(line);
  });
}

// BuildKit looks a FROM up by its familiar name with `:latest` dropped.
function contextKey(ref) {
  log.debug("Entering contextKey().");
  log.debug("Leaving contextKey().");
  return ref.replace(/^docker\.io\/(library\/)?/, '').replace(/:latest$/, '');
}

// Every external image a Dockerfile names in a FROM or a COPY --from.
function externalRefs(source) {
  log.debug("Entering externalRefs().");
  const stages = new Set();
  const args = {};
  const refs = [];
  codeLines(source).forEach(function (line) {
    let m = /^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S*)/.exec(line);
    if (m) {
      args[m[1]] = m[2];
      return;
    }
    m = /^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
    if (m) {
      const ref = m[1].replace(/^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/,
        function (all, name) {
          return name in args ? args[name] : all;
        });
      if (ref !== 'scratch' && !stages.has(ref) && ref.indexOf('$') < 0) {
        refs.push(ref);
      }
      if (m[2]) {
        stages.add(m[2]);
      }
      return;
    }
    m = /--from=(\S+)/.exec(line);
    if (m && /[:/]/.test(m[1]) && !stages.has(m[1])) {
      refs.push(m[1]);
    }
  });
  log.debug("Leaving externalRefs(). " + refs.length);
  return refs;
}

// The `x-mirror-contexts:` block: name -> target.
function composeContexts(lines) {
  log.debug("Entering composeContexts().");
  const start = lines.findIndex(function (line) {
    return /^x-mirror-contexts:/.test(line);
  });
  const out = {};
  if (start < 0) {
    log.debug("Leaving composeContexts(). None.");
    return out;
  }
  for (let i = start + 1; i < lines.length; i++) {
    if (/^\S/.test(lines[i])) {
      break;
    }
    const m = /^\s+"?([^"]+?)"?:\s*docker-image:\/\/(\S+)\s*$/.exec(lines[i]);
    if (m) {
      out[m[1]] = m[2];
    }
  }
  log.debug("Leaving composeContexts(). " + Object.keys(out).length);
  return out;
}

function run(t) {
  log.debug("Entering run().");
  const rows = mirrorRows(read('.github/image-mirror.txt'));
  const paths = new Set(rows.map(function (r) {
    return r.path;
  }));
  const listKeys = new Set(rows.map(function (r) {
    return contextKey(r.upstream);
  }));
  t.check(rows.length > 0 && rows.every(function (r) {
    return r.cols === 2;
  }), 'image-mirror.txt lists images, two columns each', String(rows.length));

  // 1. every image: in both compose files.
  const compose = read('docker-compose-run-tests.yml');
  const cluster = read('tests/docker-compose-run-tests-cluster.yml');
  const bad = [];
  let images = 0;
  codeLines(compose).concat(codeLines(cluster)).forEach(function (line) {
    const m = /^\s+image:\s*(\S+)\s*$/.exec(line);
    if (!m) {
      return;
    }
    images++;
    const ref = m[1];
    if (ref.indexOf(MIRROR_PREFIX) === 0) {
      const p = defaults(ref.slice(MIRROR_PREFIX.length));
      if (!paths.has(p)) {
        bad.push(ref + ' (mirror path ' + p + ' is not in the list)');
      }
      return;
    }
    const built = /^\$\{[A-Z0-9_]+_IMAGE:-\$\{IMAGE_REGISTRY:-ghcr\.io\/rcbj\/iya-sts\}\//
      .test(ref);
    if (!built) {
      bad.push(ref + ' (neither the mirror nor IMAGE_REGISTRY)');
    }
  });
  t.check(images > 10 && bad.length === 0,
          'every image: in the test stack is the mirror or built here',
          images + ' image(s); ' + bad.join(', '));

  // 2. the contexts point at listed paths.
  const contexts = composeContexts(compose.split('\n'));
  const names = Object.keys(contexts);
  const wrong = names.filter(function (name) {
    const target = defaults(contexts[name]);
    return target.indexOf(MIRROR) !== 0 ||
           !paths.has(target.slice(MIRROR.length));
  });
  t.check(names.length > 0 && wrong.length === 0,
          'every named context in x-mirror-contexts points at a listed path',
          names.length + ' context(s); wrong: ' + wrong.join(', '));

  // 3. every build carries them.
  const code = codeLines(compose).join('\n');
  const builds = (code.match(/^\s+build:\s*$/gm) || []).length;
  const uses = (code.match(/additional_contexts:\s*\*mirror-contexts\b/g) ||
                []).length;
  t.check(builds > 0 && uses === builds,
          'every build: in the compose file carries the mirror contexts',
          builds + ' build(s), ' + uses + ' with the contexts');

  // 4. every FROM compose builds has a context.
  const missing = [];
  let froms = 0;
  COMPOSE_DOCKERFILES.forEach(function (rel) {
    externalRefs(read(rel)).forEach(function (ref) {
      froms++;
      if (ref.indexOf('ghcr.io/rcbj/') === 0) {
        return;
      }
      if (names.indexOf(contextKey(ref)) < 0) {
        missing.push(rel + ': ' + ref);
      }
    });
  });
  t.check(froms > COMPOSE_DOCKERFILES.length && missing.length === 0,
          'every external FROM in a Dockerfile compose builds is redirected ' +
          'to the mirror', froms + ' FROM(s); missing: ' + missing.join(', '));

  // 5. the corpora Dockerfile's FROMs are in the list.
  const corpora = externalRefs(read('tests/corpora/Dockerfile'))
    .filter(function (ref) {
      return !listKeys.has(contextKey(ref));
    });
  t.check(corpora.length === 0,
          'the corpora image\'s FROMs are in the list (its build uses ' +
          'mirror-contexts.sh)', corpora.join(', '));

  // 6. build-container.yml covers the root Dockerfile, and since 2026-10-02
  // the XACML PEP's too: it builds and publishes both, each step with a
  // build-contexts block of its own, so every block is read.
  const workflow = read('.github/workflows/build-container.yml');
  const wf = {};
  const blocks = /build-contexts:\s*\|\n((?:\s+\S.*\n)+)/g;
  let block;
  while ((block = blocks.exec(workflow)) !== null) {
    block[1].split('\n').forEach(function (line) {
      const m = /^\s*([^=\s]+)=docker-image:\/\/(\S+)\s*$/.exec(line);
      if (m) {
        wf[m[1]] = m[2];
      }
    });
  }
  const rootFroms = externalRefs(read('Dockerfile'))
    .concat(externalRefs(read('xacml-pep/Dockerfile')));
  const uncovered = rootFroms.filter(function (ref) {
    const target = wf[contextKey(ref)];
    return !target || target.indexOf(MIRROR) !== 0 ||
           !paths.has(target.slice(MIRROR.length));
  });
  t.check(rootFroms.length > 0 && uncovered.length === 0,
          'build-container.yml redirects every FROM of the service and ' +
          'XACML PEP Dockerfiles to a listed mirror path',
          JSON.stringify(wf) + ' uncovered: ' + uncovered.join(', '));

  // 7. what is pushed is what run-tests.sh names.
  const launcher = read('run-tests.sh');
  const named = [];
  const re = /\$\{IMAGE_REGISTRY\}\/([a-z0-9-]+):\$\{imageTag\}/g;
  let m;
  while ((m = re.exec(launcher)) !== null) {
    named.push(m[1]);
  }
  const push = read('.github/scripts/push-stack-images.sh');
  const listed = ((/^NAMES="([^"]*)"/m.exec(push) || ['', ''])[1])
    .split(/\s+/).filter(Boolean);
  t.check(named.length > 0 &&
          named.slice().sort().join(',') === listed.slice().sort().join(','),
          'push-stack-images.sh pushes exactly the images run-tests.sh names',
          'named ' + named.join(',') + ' / pushed ' + listed.join(','));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'image_mirror_coverage',
  describe: 'every image the test stack pulls or builds FROM comes from the ' +
            'private ghcr.io mirror, and the mirror lists it',
  run: run
};
