// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: client_lab_isolation.js
//
// ===========================================================================
// NOTHING OF THE CLIENT LAB IS IN THE PRODUCT IMAGE (#2056, umbrella #2055 —
// rcbj, 2026-11-23: "Be very careful not to add any of that stuff to the
// product image").
//
// The client lab (`tests/client-lab/`) is a test image of real client
// software and virtual smart cards. It lives under `tests/`, which the
// product Dockerfile's `typescript` stage deletes from the tree before the
// final stage copies that tree. This file is the GUARD that keeps it so, by
// reading the product Dockerfile — a comparison between files, so in
// process (tests/CLAUDE.md asks that first):
//
//   A. The lab is where the rule needs it: `tests/client-lab/` with its own
//      Dockerfile, under the `tests/` the product build deletes.
//   B. The product Dockerfile's FINAL stage copies nothing from the build
//      context that could be the lab (no `COPY .`, no `tests` source), and
//      every stage it copies FROM that took the context (`COPY .` or a
//      `tests` path) removes `./tests` after the last such copy.
//   C. No stage of the product Dockerfile installs, fetches or names a lab
//      package or component (comments aside): jcardsim, SmartPGP,
//      PivApplet, vsmartcard/vpcd, pcscd, OpenSC, yubico-piv-tool, gnupg,
//      scdaemon, postfix, sendmail, openssh-server, oathtool, pam_yubico,
//      pamtester, krb5-user — nor `client-lab`.
//   D. The root package.json's dependencies name none of them, and neither
//      the user's compose files nor the product image's CI build names the
//      lab.
//   E. THE CHECKS CAN FAIL: each of B, C and D is run against a copy of
//      the product Dockerfile changed in exactly the way it guards against,
//      and must report it. A guard that compares nothing passes forever.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'client_lab_isolation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const LAB = 'tests/client-lab';

// The lab's packages and components, as a word in a Dockerfile instruction.
const LAB_WORDS = ['jcardsim', 'smartpgp', 'pivapplet', 'vsmartcard', 'vpcd',
                   'pcscd', 'opensc', 'yubico-piv-tool', 'gnupg', 'gnupg2',
                   'scdaemon', 'postfix', 'sendmail', 'openssh-server',
                   'oathtool', 'pam_yubico', 'libpam-yubico', 'pamtester',
                   'krb5-user', 'client-lab'];

function read(rel) {
  log.debug("Entering read(). " + rel);
  const file = path.join(ROOT, rel);
  if (!fs.existsSync(file)) {
    log.debug("Leaving read(). Missing.");
    throw new Error(rel + ' is not here. This check must fail rather than ' +
                    'pass vacuously; if the file moved, move it here too.');
  }
  log.debug("Leaving read().");
  return fs.readFileSync(file, 'utf8');
}

// A Dockerfile's instructions: comment lines dropped (Docker drops them
// inside a continued instruction too), continuations joined, each
// `{ op, args, line }`, grouped by stage `{ from, name, steps }`.
function stages(text) {
  log.debug("Entering stages().");
  const out = [];
  let current = null;
  let pending = '';
  let startLine = 0;
  const lines = String(text).split('\n');
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (/^\s*#/.test(raw)) {
      continue;
    }
    if (!pending) {
      startLine = i + 1;
    }
    const continued = /\\\s*$/.test(raw);
    pending += (pending ? ' ' : '') + raw.replace(/\\\s*$/, '').trim();
    if (continued) {
      continue;
    }
    const step = pending.trim();
    pending = '';
    if (!step) {
      continue;
    }
    const m = /^(\S+)\s*(.*)$/.exec(step);
    const op = m[1].toUpperCase();
    const args = m[2];
    if (op === 'FROM') {
      const named = /\bAS\s+(\S+)\s*$/i.exec(args);
      current = { from: args.split(/\s+/)[0],
                  name: named ? named[1] : String(out.length), steps: [] };
      out.push(current);
      continue;
    }
    if (current) {
      current.steps.push({ op: op, args: args, line: startLine });
    }
  }
  log.debug("Leaving stages(). " + out.length);
  return out;
}

// A COPY's options and sources (its last word is the destination).
function copyOf(args) {
  log.debug("Entering copyOf().");
  const words = String(args).split(/\s+/).filter(Boolean);
  const opts = {};
  const rest = [];
  for (const w of words) {
    const m = /^--([a-z-]+)(?:=(.*))?$/.exec(w);
    if (m) {
      opts[m[1]] = m[2] === undefined ? true : m[2];
    } else {
      rest.push(w);
    }
  }
  log.debug("Leaving copyOf().");
  return { from: opts.from || null, sources: rest.slice(0, -1) };
}

// Whether a context source could carry the lab.
function carriesLab(source) {
  log.debug("Entering carriesLab(). " + source);
  const s = String(source).replace(/^\.\//, '').replace(/\/+$/, '');
  const yes = s === '.' || s === '' || s === '*' || s === 'tests' ||
    s.indexOf('tests/') === 0 || s.indexOf('client-lab') >= 0;
  log.debug("Leaving carriesLab(). " + yes);
  return yes;
}

// Whether a RUN removes the tree's ./tests.
function removesTests(args) {
  log.debug("Entering removesTests().");
  const yes = /\brm\s+-[a-z]*r[a-z]*f?[a-z]*\b[^;&|]*(\s|^)(\.\/)?tests(\/)?(\s|$)/
    .test(String(args));
  log.debug("Leaving removesTests(). " + yes);
  return yes;
}

/**
 * Every way a product Dockerfile could carry the lab.
 *
 * @param text - the Dockerfile
 * @returns a list of findings, each a sentence; [] for none
 */
function dockerfileFindings(text) {
  log.debug("Entering dockerfileFindings().");
  const all = stages(text);
  const found = [];
  if (!all.length) {
    log.debug("Leaving dockerfileFindings(). No stage.");
    return ['the Dockerfile has no FROM'];
  }
  const byName = {};
  for (const st of all) {
    byName[st.name] = st;
  }
  const final = all[all.length - 1];
  // B: the final stage, and each stage it copies from.
  const copiedFrom = {};
  for (const step of final.steps) {
    if (step.op !== 'COPY' && step.op !== 'ADD') {
      continue;
    }
    const c = copyOf(step.args);
    if (c.from) {
      copiedFrom[c.from] = true;
      continue;
    }
    for (const src of c.sources) {
      if (carriesLab(src)) {
        found.push('line ' + step.line + ': the final stage copies "' + src +
                   '" from the build context, which can carry ' + LAB);
      }
    }
  }
  for (const name of Object.keys(copiedFrom)) {
    const st = byName[name];
    if (!st) {
      // An image, not a stage of this file (the debugger's): it is not
      // built from this context.
      continue;
    }
    let lastCarry = -1;
    let lastRemove = -1;
    st.steps.forEach(function (step, i) {
      if (step.op === 'COPY' || step.op === 'ADD') {
        const c = copyOf(step.args);
        if (!c.from && c.sources.some(carriesLab)) {
          lastCarry = i;
        }
      }
      if (step.op === 'RUN' && removesTests(step.args)) {
        lastRemove = i;
      }
    });
    if (lastCarry >= 0 && lastRemove < lastCarry) {
      found.push('stage "' + name + '", which the final stage copies from, ' +
                 'takes the build context (line ' +
                 st.steps[lastCarry].line + ') and does not remove ./tests ' +
                 'after it');
    }
  }
  // C: any stage, any instruction.
  for (const st of all) {
    const steps = [{ op: 'FROM', args: st.from, line: 0 }].concat(st.steps);
    for (const step of steps) {
      for (const word of LAB_WORDS) {
        const re = new RegExp('(^|[^A-Za-z0-9_.-])' +
          word.replace(/[-.]/g, '\\$&') + '($|[^A-Za-z0-9_-])', 'i');
        if (re.test(step.args)) {
          found.push((step.line ? 'line ' + step.line : 'stage "' + st.name +
                      '"') + ': ' + step.op + ' names "' + word +
                     '", a client lab package or component');
        }
      }
    }
  }
  log.debug("Leaving dockerfileFindings(). " + found.length);
  return found;
}

/**
 * Lab names among a package.json's dependencies.
 *
 * @param text - the package.json
 * @returns the findings
 */
function packageFindings(text) {
  log.debug("Entering packageFindings().");
  const pkg = JSON.parse(text);
  const found = [];
  for (const kind of ['dependencies', 'optionalDependencies',
                      'peerDependencies', 'bundleDependencies',
                      'bundledDependencies']) {
    const deps = pkg[kind] || {};
    const names = Array.isArray(deps) ? deps : Object.keys(deps);
    for (const name of names) {
      const lower = name.toLowerCase();
      if (LAB_WORDS.some(function (w) {
        return lower.indexOf(w) >= 0;
      })) {
        found.push(kind + ' names "' + name + '"');
      }
    }
  }
  log.debug("Leaving packageFindings(). " + found.length);
  return found;
}

// A Dockerfile changed by putting `line` in the final stage, at its end.
function withFinalLine(text, line) {
  log.debug("Entering withFinalLine().");
  log.debug("Leaving withFinalLine().");
  return String(text).replace(/\s*$/, '\n' + line + '\n');
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== A. where the lab is ===');
  t.check(fs.existsSync(path.join(ROOT, LAB, 'Dockerfile')),
          'A1. the lab has its own Dockerfile under ' + LAB);
  t.check(/^tests\//.test(LAB), 'A2. the lab directory is under tests/');
  const product = read('Dockerfile');
  const all = stages(product);
  t.check(all.some(function (st) {
    return st.steps.some(function (s) {
      return s.op === 'RUN' && removesTests(s.args);
    });
  }), 'A3. the product Dockerfile removes ./tests from its tree');

  t.log.info('=== B, C. the product Dockerfile ===');
  const found = dockerfileFindings(product);
  t.check(found.length === 0, 'B/C. the product Dockerfile\'s final stage ' +
          'can carry nothing of the lab, and no stage names a lab package',
          found.join('; '));

  t.log.info('=== D. package.json, the compose files, the product CI ===');
  const deps = packageFindings(read('package.json'));
  t.check(deps.length === 0, 'D1. package.json\'s dependencies name no lab ' +
          'package', deps.join('; '));
  for (const rel of ['docker-compose.yml', 'docker-compose-quick.yml',
                     '.github/workflows/build-container.yml']) {
    t.check(!/client-lab|sts-client-lab/.test(read(rel)),
            'D2. ' + rel + ' does not name the client lab');
  }

  t.log.info('=== E. the checks can fail ===');
  const finalName = all[all.length - 1].name;
  t.check(dockerfileFindings(withFinalLine(product,
            'COPY tests/client-lab /opt/client-lab')).length > 0,
          'E1. a final-stage COPY of tests/client-lab is reported');
  t.check(dockerfileFindings(withFinalLine(product, 'COPY . ./')).length > 0,
          'E2. a final-stage COPY of the whole context is reported');
  t.check(dockerfileFindings(withFinalLine(product,
            'RUN apt-get install -y --no-install-recommends pcscd opensc'))
            .length > 0,
          'E3. a lab package installed in the final stage (' + finalName +
          ') is reported');
  const kept = product.replace(/rm -rf \.\/tests /, 'rm -rf ');
  t.check(kept !== product && dockerfileFindings(kept).some(function (f) {
    return /does not remove \.\/tests/.test(f);
  }), 'E4. a stage that keeps ./tests is reported');
  t.check(packageFindings(JSON.stringify({ dependencies:
            { 'node-jcardsim': '1.0.0' } })).length === 1,
          'E5. a lab name among the dependencies is reported');
  t.check(!removesTests('rm -rf ./node_modules ./tests/node_modules') &&
          removesTests('rm -rf ./tests ./xacml-pep'),
          'E6. removing tests/node_modules is not removing ./tests');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'client_lab_isolation',
  describe: 'nothing of the client lab reaches the product image: the lab ' +
            'is under the tests/ the product build deletes, the final stage ' +
            'copies nothing that could carry it, no stage names a lab ' +
            'package, and package.json names none (#2056)',
  run: run,
  dockerfileFindings: dockerfileFindings
};
