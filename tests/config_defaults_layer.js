// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: config_defaults_layer.js
//
// ===========================================================================
// env/defaults.js, THE TABLE BENEATH IT, AND AN env/ OLDER THAN THE IMAGE.
//
// The port-8081 deployment mounts a directory over the image's
// /usr/src/sts/env. That directory came from an older checkout, so its
// defaults.js hid the image's own; the image added a setting, the setting had
// no value anywhere, and the service crash-looped on STS-CORE-0002 until the
// mount was moved. Since 2026-11-16 the table's own `dflt` is the floor
// beneath the defaults file (common/config.js's header, common/CLAUDE.md,
// *The image's floor*), and this file holds both halves of that:
//
//   A. THE SHIPPED FILE AND THE TABLE AGREE, in both directions — every
//      non-derived row has its `dflt` in env/defaults.js, no derived row is
//      there, and the file carries no key the table does not know. This is
//      the maintainer's mistake requireComplete() used to catch at a start (a
//      row added, the file not regenerated); it is caught here now, before an
//      image is built. `floorVerdict()` is asserted for its three answers,
//      the `refuse` one being what keeps a setting with no default — a
//      required secret — stopping the start.
//   B. A DEFAULTS FILE LACKING A SETTING starts, the setting takes the
//      table's default with source `default`, and a WARNING with STS-CORE-0177
//      names the setting and the file.
//   C. NO DEFAULTS FILE AT ALL starts the same way, and says so.
//   D. A DEFAULTS FILE HOLDING A VALUE THAT IS NOT THE IMAGE'S DEFAULT is used
//      as written, and a WARNING with STS-CORE-0178 names the setting.
//   E. A VALUE THE OPERATOR DID SET, AND SET WRONG, STILL REFUSES
//      (STS-CORE-0108) — over the same stale defaults file, so the floor is
//      shown not to swallow it.
//   F. A DEFAULTS FILE THAT IS THERE AND WILL NOT LOAD STILL REFUSES
//      (STS-CORE-0179).
//
// EVERY CASE RUNS IN A CHILD PROCESS, because config.js decides all of this
// once, at its require, and exits on a refusal. The child replaces the
// defaults file by hooking node's module loader for that one path — the tree
// is never written to, so a run cannot leave a stale file behind.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'config_defaults_layer',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const DEFAULTS_FILE = path.join(ROOT, 'env', 'defaults.js');

// A dot path into an appconfig object, undefined at any missing hop.
function dig(root, dotted) {
  log.debug("Entering dig().");
  let node = root;
  const parts = String(dotted).split('.');
  for (let i = 0; i < parts.length; i++) {
    if (node === null || typeof node !== 'object') {
      log.debug("Leaving dig().");
      return undefined;
    }
    node = node[parts[i]];
  }
  log.debug("Leaving dig().");
  return node;
}

// Every leaf path an appconfig object carries, two levels deep as the table
// uses them.
function leafPaths(root) {
  log.debug("Entering leafPaths().");
  const out = [];
  Object.keys(root).forEach(function (top) {
    const node = root[top];
    if (node && typeof node === 'object' && !Array.isArray(node)) {
      Object.keys(node).forEach(function (leaf) {
        out.push(top + '.' + leaf);
      });
      return;
    }
    out.push(top);
  });
  log.debug("Leaving leafPaths().");
  return out;
}

// The setting the stale cases remove or change: the LAST boolean in the
// shipped file, which is the shape of the incident (the newest setting of the
// last section) and a type whose wrong value is easy to write.
function chosenPath(shipped) {
  log.debug("Entering chosenPath().");
  const bools = leafPaths(shipped).filter(function (p) {
    return p.indexOf('.') > 0 && typeof dig(shipped, p) === 'boolean';
  });
  log.debug("Leaving chosenPath().");
  return bools[bools.length - 1];
}

// ---------------------------------------------------------------------------
// THE CHILD. SCENARIO picks what env/defaults.js looks like to config.js.
// ---------------------------------------------------------------------------
function childMain() {
  log.debug("Entering childMain().");
  const Module = require('module');
  const scenario = process.env.CDL_SCENARIO;
  const shipped = require(DEFAULTS_FILE);
  const target = chosenPath(shipped);
  const stale = JSON.parse(JSON.stringify(shipped));
  const top = target.split('.')[0];
  const leaf = target.split('.')[1];
  if (scenario === 'differing') {
    stale[top][leaf] = !shipped[top][leaf];
  } else {
    delete stale[top][leaf];
  }
  delete require.cache[DEFAULTS_FILE];
  const realLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    const resolved = path.isAbsolute(request) ? request : null;
    if (resolved !== DEFAULTS_FILE || scenario === 'shipped') {
      return realLoad.apply(this, arguments);
    }
    if (scenario === 'missing') {
      const err = new Error('Cannot find module \'' + DEFAULTS_FILE + '\'');
      Object.assign(err, { code: 'MODULE_NOT_FOUND' });
      throw err;
    }
    if (scenario === 'broken') {
      throw new SyntaxError('Unexpected token \'}\'');
    }
    return stale;
  };
  const config = require(path.join(ROOT, 'common', 'config.js'));
  Module._load = realLoad;
  const setting = config.SETTINGS.filter(function (s) {
    return (s.path || s.key) === target;
  })[0];
  const out = { target: target, key: setting && setting.key };
  if (setting) {
    out.value = config.value(setting.key);
    out.dflt = setting.dflt;
    out.source = config.sourceOf(setting.key);
  }
  if (scenario === 'shipped') {
    out.mismatched = [];
    const paths = {};
    config.SETTINGS.forEach(function (s) {
      const p = s.path || s.key;
      paths[p] = s;
      const inFile = dig(shipped, p);
      if (s.derived) {
        if (inFile !== undefined) {
          out.mismatched.push(p + ' is derived and is in the file');
        }
        return;
      }
      if (JSON.stringify(inFile) !== JSON.stringify(s.dflt)) {
        out.mismatched.push(p + ': file ' + JSON.stringify(inFile) +
                            ', table ' + JSON.stringify(s.dflt));
      }
    });
    leafPaths(shipped).forEach(function (p) {
      if (!paths[p]) {
        out.mismatched.push(p + ' is in the file and not in the table');
      }
    });
    out.verdicts = [
      config.floorVerdict({ key: 'x.required', dflt: undefined }),
      config.floorVerdict({ key: 'x.derived', derived: true,
                            dflt: function () { return 1; } }),
      config.floorVerdict({ key: 'x.plain', dflt: false })
    ];
    out.audit = config.auditDefaultsFile();
  }
  process.stdout.write('\nCDL-RESULT ' + JSON.stringify(out) + '\n');
  log.debug("Leaving childMain().");
}

// Runs one scenario and returns its exit status, its stderr, its
// config-logger lines and its result.
function runChild(scenario, configFile) {
  log.debug("Entering runChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$|KRB5_)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  if (configFile) {
    clean.CONFIG_FILE = configFile;
  }
  const result = require('child_process').spawnSync(process.execPath,
    ['-e', 'require(' + JSON.stringify(__filename) + ').childMain()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal',
                                  CDL_SCENARIO: scenario }),
      encoding: 'utf8', timeout: 120000, cwd: ROOT,
      maxBuffer: 64 * 1024 * 1024
    });
  const lines = [];
  let found = null;
  String(result.stdout || '').split('\n').forEach(function (line) {
    if (line.indexOf('CDL-RESULT ') === 0) {
      found = JSON.parse(line.slice('CDL-RESULT '.length));
      return;
    }
    if (line.charAt(0) !== '{') {
      return;
    }
    try {
      lines.push(JSON.parse(line));
    } catch (e) {
      log.debug("Caught in runChild(): " + ((e && e.message) || e));
    }
  });
  log.debug("Leaving runChild().");
  return { status: result.status, stderr: String(result.stderr || ''),
           lines: lines, result: found };
}

// The WARN-level config lines carrying a code.
function warnings(child, code) {
  log.debug("Entering warnings().");
  const hits = child.lines.filter(function (l) {
    return l.name === 'sts-config' && l.level === 40 &&
           String(l.msg).indexOf('[' + code + ']') >= 0;
  });
  log.debug("Leaving warnings().");
  return hits;
}

function tail(child) {
  log.debug("Entering tail().");
  log.debug("Leaving tail().");
  return 'exit ' + child.status + ' ' + child.stderr.slice(-800);
}

function run(t) {
  log.debug("Entering run().");

  // A. The shipped file and the table agree.
  const shipped = runChild('shipped');
  if (t.check(shipped.status === 0 && shipped.result,
              'A: the shipped env/defaults.js starts', tail(shipped))) {
    t.check(shipped.result.mismatched.length === 0,
            'A: env/defaults.js and the table agree in both directions ' +
            '(run node env/generate_defaults.js)',
            shipped.result.mismatched.slice(0, 12).join('; '));
    t.equal(JSON.stringify(shipped.result.verdicts),
            JSON.stringify(['refuse', 'derived', 'floor']),
            'A: a row with no default refuses, a derived one is derived, ' +
            'one with a default takes the floor');
    t.check(shipped.result.audit.floor.length === 0 &&
            shipped.result.audit.differing.length === 0,
            'A: the shipped file leaves nothing to the floor and differs ' +
            'from nothing', JSON.stringify(shipped.result.audit));
    t.check(!warnings(shipped, 'STS-CORE-0177').length &&
            !warnings(shipped, 'STS-CORE-0178').length,
            'A: the shipped file draws no stale-file warning');
  }

  // B. A stale file lacking a setting.
  const lacking = runChild('lacking');
  if (t.check(lacking.status === 0 && lacking.result,
              'B: a defaults file lacking a setting still starts',
              tail(lacking))) {
    const r = lacking.result;
    t.equal(r.value, r.dflt, 'B: ' + r.key + ' takes the table\'s default');
    t.equal(r.source, 'default', 'B: and reports its source as "default"');
    const w = warnings(lacking, 'STS-CORE-0177');
    t.check(w.length === 1 && w[0].msg.indexOf(r.key) >= 0 &&
            w[0].msg.indexOf(DEFAULTS_FILE) >= 0,
            'B: one WARN with STS-CORE-0177 names the setting and the file',
            JSON.stringify(w.map(function (l) { return l.msg; })));
  }

  // C. No defaults file at all.
  const missing = runChild('missing');
  if (t.check(missing.status === 0 && missing.result,
              'C: no defaults file at all still starts', tail(missing))) {
    t.equal(missing.result.value, missing.result.dflt,
            'C: every setting takes the table\'s default');
    const w = warnings(missing, 'STS-CORE-0177');
    t.check(w.length === 1 && w[0].msg.indexOf('it is not there') >= 0,
            'C: the WARN says the file is not there',
            JSON.stringify(w.map(function (l) { return l.msg; })));
  }

  // D. A stale file holding a value that is not the image's default.
  const differing = runChild('differing');
  if (t.check(differing.status === 0 && differing.result,
              'D: a defaults file with a differing value starts',
              tail(differing))) {
    const r = differing.result;
    t.equal(r.value, !r.dflt, 'D: ' + r.key + ' takes the FILE\'s value');
    t.equal(r.source, 'defaults', 'D: and reports its source as "defaults"');
    const w = warnings(differing, 'STS-CORE-0178');
    t.check(w.length === 1 && w[0].msg.indexOf(r.key) >= 0 &&
            w[0].msg.indexOf(DEFAULTS_FILE) >= 0,
            'D: one WARN with STS-CORE-0178 names the setting and the file',
            JSON.stringify(w.map(function (l) { return l.msg; })));
  }

  // E. The operator set the same setting, to something invalid.
  if (lacking.result) {
    const target = lacking.result.target;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cdl-'));
    const file = path.join(dir, 'operator.js');
    const parts = target.split('.');
    fs.writeFileSync(file, 'module.exports = { logLevel: "info", ' +
                     JSON.stringify(parts[0]) + ': { ' +
                     JSON.stringify(parts[1]) + ': "maybe" } };\n');
    const invalid = runChild('lacking', file);
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
    t.check(invalid.status === 1 && !invalid.result &&
            invalid.stderr.indexOf('STS-CORE-0108') >= 0 &&
            invalid.stderr.indexOf(target) >= 0,
            'E: an invalid value the operator set still refuses the start ' +
            '(STS-CORE-0108), over a stale defaults file', tail(invalid));
  }

  // F. A defaults file that is there and will not load.
  const broken = runChild('broken');
  t.check(broken.status === 1 && !broken.result &&
          broken.stderr.indexOf('STS-CORE-0179') >= 0 &&
          broken.stderr.indexOf(DEFAULTS_FILE) >= 0,
          'F: a defaults file that will not load refuses the start ' +
          '(STS-CORE-0179)', tail(broken));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'config_defaults_layer',
  describe: 'env/defaults.js agrees with the table, and an older one ' +
            'costs a warning rather than the start',
  run: run,
  childMain: childMain
};
