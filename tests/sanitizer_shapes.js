// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/sanitizer_shapes.js
//
// ---------------------------------------------------------------------------
// TWO SHAPES CODEQL FOUND WANTING (2026-10-30), held to what they now claim.
//
// The tag stripper the static surfaces share (`WebMessages.stripTags()`,
// behind `WebKit.plainTextOf()` and `WebPages.textOf()`) used to be one pass
// of `/<[^>]*>/g`, which turns `<scr<b>ipt>` into `<script>`: removing the
// inner tag joins the halves of an outer one. It now repeats until nothing
// is removed, so no `<…>` survives it, whatever the interleaving.
//
// The person editor's DN shape could be made to backtrack exponentially: its
// whitespace was claimable by two parts at once. The shape is now written so
// that no two parts can claim one character, and a string built to defeat
// the old one is refused in constant time.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const WebMessages = require('../common/web_messages').WebMessages;
const WebKit = require('../admin-ui/web_kit');
const WebPages = require('../admin-ui/web_pages');
const DN_SHAPE = require('../ldap/person_editor').DN_SHAPE;

const log = require('bunyan').createLogger({ name: 'sanitizer_shapes',
  level: process.env.LOG_LEVEL || 'info' });

// Fragments built so that one pass of the stripper leaves a tag behind.
const INTERLEAVED = [
  '<scr<b>ipt>alert(1)</scr<b>ipt>',
  '<<i></i>script>',
  '<img src=x one<em>rror=alert(1)>',
  '<<<b></b></b>script>',
  'a <b>bold</b> c <',
  '<a href="x"><b>linked</b></a>'
];

async function run(t) {
  log.debug("Entering run().");

  // --- the stripper, directly -------------------------------------------
  INTERLEAVED.forEach(function (fragment) {
    const out = WebMessages.stripTags(fragment);
    t.check(!/<[^>]*>/.test(out),
            'stripTags() leaves no tag in ' + JSON.stringify(fragment),
            JSON.stringify(out));
  });
  t.check(WebMessages.stripTags('a <b>bold</b> c &lt;x&gt;') ===
            'a bold c &lt;x&gt;',
          'stripTags() keeps the text and the entities',
          JSON.stringify(WebMessages.stripTags('a <b>bold</b> c &lt;x&gt;')));
  t.check(WebMessages.stripTags(null) === '' &&
          WebMessages.stripTags(undefined) === '',
          'stripTags() of nothing is the empty string');

  // --- the two callers --------------------------------------------------
  const plain = WebKit.plainTextOf('<p>Some  <scr<b>ipt>text</p>  here');
  t.check(plain.indexOf('<') < 0 && /^Some\s.*text here$/.test(plain),
          'plainTextOf() strips every tag and collapses the whitespace',
          JSON.stringify(plain));
  const label = WebPages.textOf('<h2>Keys &amp; <scr<i>ipt>certs</h2>');
  t.check(label === 'Keys & certs',
          'textOf() strips every tag and puts the entities back',
          JSON.stringify(label));

  // --- the DN shape -----------------------------------------------------
  ['cn=Jane Doe,ou=People,dc=example,dc=com',
   ' uid=jane , ou=people ,dc=x',
   'cn=a b , ou=c d',
   'cn=x'].forEach(function (dn) {
    t.check(DN_SHAPE.test(dn), 'the DN shape accepts ' + JSON.stringify(dn));
  });
  ['', 'x', 'cn=', 'cn=,ou=x', 'cn=a=b', 'cn=a,,ou=b', 'cn=   ', '=x',
   '1cn=x'].forEach(function (dn) {
    t.check(!DN_SHAPE.test(dn), 'the DN shape refuses ' + JSON.stringify(dn));
  });
  // The string CodeQL named: `A=+,A=` and then many `+ ,A=`, ending in a
  // character no value may hold, so the whole cannot match and the engine
  // has to give up. The old shape took 200 ms at twenty-two repetitions and
  // doubled with each one more; the new one is flat at two hundred, and a
  // bound is asserted rather than a feeling.
  const evil = 'A=+,A=' + '+ ,A='.repeat(200) + '=';
  const started = Date.now();
  const matched = DN_SHAPE.test(evil);
  const took = Date.now() - started;
  t.check(!matched && took < 500,
          'the adversarial DN is refused without backtracking',
          'matched=' + matched + ' ms=' + took);

  log.debug("Leaving run().");
}

module.exports = {
  name: 'sanitizer_shapes',
  describe: 'the shared tag stripper cannot be re-assembled, and the DN ' +
            'shape does not backtrack',
  run: run
};
