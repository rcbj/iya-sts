// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: named_file_descriptor.js
//
// ===========================================================================
// A FILE AN ADMINISTRATOR NAMES IS CHECKED AND READ THROUGH ONE DESCRIPTOR
// (#2247, ASVS 5.0.0 15.4.2).
//
// `security.fileRoots` (#1481) confines, in product, every file a setting or
// an administrator names. Until #2247 it was check-then-use: the PATH was
// resolved and checked, and the caller then opened the path again, so a
// symbolic link swapped in between was followed out of the directories.
// `OutboundTls.readNamedFile()` opens the file once, checks the descriptor
// (a regular file, its real path as the kernel holds it inside a root), and
// reads through it. This file holds it to that:
//
//   A. product: a file inside the roots reads; a link inside them to a file
//      inside them still reads (what /etc/ssl/certs and a secret volume are);
//   B. a link out of the roots, a path that climbs out, a relative path, a
//      directory and a missing file are refused with the one sentence, which
//      names the setting and not the path;
//   C. THE RACE: the path check passes and the path is then swapped for a
//      link out of the roots before the open (the helper's `beforeOpen`
//      seam, not real timing) — refused; and the same where there is no
//      /proc view of the descriptor (the `descriptorLink` seam throws), by
//      the device and inode comparison;
//   D. no refusal leaves a descriptor open;
//   E. development reads as before, unconfined;
//   F. `caFilePems()` keeps its two sentences, and the readers of named files
//      (the truststores' setting files, the mail transports' DKIM key, the
//      revocation CA files and the rest) go through the helper.
//
// In process: `common/outbound_tls` is a library. `global.mode` is a process
// override cleared in the `finally`; `security.fileRoots` is not a runtime
// setting, so it is answered by wrapping `config.value` for the run.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'named_file_descriptor',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The open descriptors of this process, where there is a /proc to count.
function openCount() {
  log.debug("Entering openCount().");
  try {
    const n = fs.readdirSync('/proc/self/fd').length;
    log.debug("Leaving openCount().");
    return n;
  } catch (e) {
    log.debug("Caught in openCount(): " + ((e && e.message) || e));
    log.debug("Leaving openCount(). No /proc.");
    return -1;
  }
}

// What a read answers: { text } or { refused, message, code }.
function attempt(outbound, file, seams) {
  log.debug("Entering attempt().");
  try {
    const text = outbound.readNamedFile(file, seams);
    log.debug("Leaving attempt(). Read.");
    return { text: text };
  } catch (e) {
    log.debug("Caught in attempt(): " + ((e && e.message) || e));
    log.debug("Leaving attempt(). Thrown.");
    return { refused: !!(e && e.namedFileRefused),
             message: String(e && e.message), code: e && e.code };
  }
}

async function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const outbound = require('../common/outbound_tls');

  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'named-file-'));
  const roots = path.join(scratch, 'roots');
  fs.mkdirSync(roots);
  fs.mkdirSync(path.join(roots, 'sub'));
  const good = path.join(roots, 'good.pem');
  const outside = path.join(scratch, 'outside.pem');
  fs.writeFileSync(good, 'inside');
  fs.writeFileSync(outside, 'SECRET-OUTSIDE');
  fs.writeFileSync(path.join(roots, 'sub', 'real.pem'), 'inside-too');
  fs.symlinkSync(outside, path.join(roots, 'link-out.pem'));
  fs.symlinkSync(path.join(roots, 'sub', 'real.pem'),
                 path.join(roots, 'link-in.pem'));

  const realValue = config.value;
  config.value = function (key) {
    return key === 'security.fileRoots' ? roots : realValue.apply(this,
                                                                  arguments);
  };
  const refusedWell = function (r) {
    return !!r.refused && /security\.fileRoots/.test(r.message) &&
      r.message.indexOf(scratch) < 0;
  };
  try {
    const set = config.setOverride('global.mode', 'product');
    t.check(set.ok, 'global.mode=product is accepted', JSON.stringify(set));

    // A. INSIDE.
    let r = attempt(outbound, good);
    t.check(r.text === 'inside', 'product: a file inside the roots reads',
            JSON.stringify(r));
    r = attempt(outbound, path.join(roots, 'link-in.pem'));
    t.check(r.text === 'inside-too', 'and a link inside the roots to a file ' +
            'inside them still reads, as it always did', JSON.stringify(r));

    // B. THE REFUSALS.
    [['a link out of the roots', path.join(roots, 'link-out.pem')],
      ['a path that climbs out', path.join(roots, '..', 'outside.pem')],
      ['a relative path', 'roots/good.pem'],
      ['a directory', path.join(roots, 'sub')],
      ['a file that does not exist', path.join(roots, 'none.pem')]
    ].forEach(function (pair) {
      const answer = attempt(outbound, pair[1]);
      t.check(refusedWell(answer) && answer.text === undefined,
              pair[0] + ' is refused with the one sentence, naming the ' +
              'setting and not the path', JSON.stringify(answer));
    });

    // C. THE RACE, through the helper's seams.
    const before = openCount();
    let checked = false;
    const swap = function (file) {
      checked = true;
      fs.unlinkSync(file);
      fs.symlinkSync(outside, file);
    };
    const raced = path.join(roots, 'raced.pem');
    fs.writeFileSync(raced, 'inside');
    t.check(outbound.namedFileAllowed(raced),
            'the raced path passes the path check before the swap');
    r = attempt(outbound, raced, { beforeOpen: swap });
    t.check(checked, 'the swap ran after the path check and before the open');
    t.check(refusedWell(r) && String(r.text) !== 'SECRET-OUTSIDE',
            'a path swapped for a link out of the roots after the check is ' +
            'refused at the descriptor, and nothing outside is read',
            JSON.stringify(r));

    const noProc = { descriptorLink: function () {
      throw new Error('no /proc here');
    } };
    r = attempt(outbound, good, noProc);
    t.check(r.text === 'inside', 'without a /proc view a file inside the ' +
            'roots still reads (device and inode compared)',
            JSON.stringify(r));
    const raced2 = path.join(roots, 'raced2.pem');
    fs.writeFileSync(raced2, 'inside');
    r = attempt(outbound, raced2, { beforeOpen: swap,
      descriptorLink: noProc.descriptorLink });
    t.check(refusedWell(r), 'and the swap is refused there too',
            JSON.stringify(r));
    // A swap AFTER the open: the descriptor is the inside file, the path is
    // now a link out. The /proc view reads the inside file (it is what was
    // opened); without it the path no longer names the opened file, so it
    // is refused rather than guessed.
    const raced3 = path.join(roots, 'raced3.pem');
    fs.writeFileSync(raced3, 'inside');
    r = attempt(outbound, raced3, { descriptorLink: function () {
      fs.unlinkSync(raced3);
      fs.symlinkSync(outside, raced3);
      throw new Error('no /proc here');
    } });
    t.check(refusedWell(r), 'a path swapped after the open, with no /proc ' +
            'view, is refused: the path no longer names the opened file',
            JSON.stringify(r));

    // D. NOTHING LEFT OPEN.
    const after = openCount();
    t.check(before < 0 || after === before,
            'no read or refusal leaves a descriptor open (' + before + ' -> ' +
            after + ')');

    // F. caFilePems() and the readers.
    t.check(String(outbound.caFilePems(path.join(roots, 'link-out.pem'))) ===
            'it is not a file in a directory security.fileRoots lists',
            'caFilePems() keeps its refusal sentence');
    t.check(String(outbound.caFilePems(good)) === 'it holds no PEM certificate',
            'and reads a permitted file through the helper');
    let thrown = '';
    try {
      outbound.assertNamedFile(outside);
    } catch (e) {
      thrown = String(e && e.message);
    }
    t.check(thrown === 'that is not a file in a directory security.fileRoots ' +
            'lists', 'assertNamedFile() keeps its sentence', thrown);
    const truststores = require('../common/truststores');
    const deps = truststores.Truststores.defaultDeps();
    r = { refused: false };
    try {
      deps.readNamedFile(path.join(roots, 'link-out.pem'));
    } catch (e) {
      r = { refused: !!(e && e.namedFileRefused) };
    }
    t.check(r.refused, 'the truststores\' setting files go through it');
    t.check(deps.readNamedFile(good) === 'inside',
            'and read a permitted file');
    [['common/truststores.ts', 1], ['common/mail_transports.ts', 1],
      ['common/revocation_status.js', 1], ['scim/scim_client.ts', 1],
      ['attribute-sources/attribute_source_drivers.ts', 1],
      ['authzen/authzen_external_pdp.ts', 1],
      ['spiffe/spiffe_sigstore.ts', 1],
      ['spiffe/spiffe_attestor_k8s_psat.ts', 1],
      ['spiffe/spiffe_workload_attestor_k8s.ts', 1],
      ['spiffe/spiffe_attestor_azure_imds.ts', 1],
      ['spiffe/spiffe_attestor_gcp_iit.ts', 1]].forEach(function (pair) {
      const text = fs.readFileSync(path.join(ROOT, pair[0]), 'utf8');
      t.check(text.split('readNamedFile').length - 1 >= pair[1],
              pair[0] + ' reads its named file through readNamedFile()');
    });

    // E. DEVELOPMENT.
    config.setOverride('global.mode', 'development');
    r = attempt(outbound, outside);
    t.check(r.text === 'SECRET-OUTSIDE',
            'development: nothing is confined, and the file reads as before',
            JSON.stringify(r));
    r = attempt(outbound, path.join(roots, 'none.pem'));
    t.check(!r.refused && r.code === 'ENOENT',
            'and a missing file is the fs error, as before', JSON.stringify(r));
  } finally {
    config.value = realValue;
    try {
      config.clearOverride('global.mode');
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      // Never set; nothing to clear.
    }
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'named_file_descriptor',
  describe: '#2247: a file an administrator names is opened once and its ' +
            'descriptor checked against security.fileRoots before it is ' +
            'read, so a link swapped in after the path check is refused',
  run: run
};
