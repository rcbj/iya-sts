// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: env/generate_defaults.js
//
// ---------------------------------------------------------------------------
// Writes env/defaults.js from common/config.js's SETTINGS table.
//
//     node env/generate_defaults.js
//
// Run it after adding, removing or re-defaulting a row in that table — and
// tests/config_defaults_layer.js will tell you when you have forgotten, because
// it fails while this file and the table disagree in either direction. (Until
// 2026-11-16 the SERVICE told you, by refusing to start over a row with no
// entry here; it now takes the row's own default and warns, STS-CORE-0177,
// because an operator's older copy of this file met the same refusal on an
// upgrade — common/CLAUDE.md, *The image's floor*.)
//
// WHY GENERATE IT RATHER THAN KEEP IT BY HAND. env/defaults.js is the base
// appconfig layer: it has to carry the `dflt` of every non-derived setting, and
// the same value is already written down in the table, next to the paragraph
// explaining why it is the default. Two copies of a default is one copy that
// will be wrong — and wrong in the quietest possible way, since the service
// would then RUN on one value while /admin/config, the OpenAPI document's
// `default` property and docs/configuration.md's table all reported the
// other.
//
// THE process.exit STUB. Requiring config.js runs requireComplete(), which
// exits when a setting has no value anywhere. Since 2026-11-16 that is only a
// row with no `dflt` at all, which this file could not write a value for
// either, but a row being added may be half-written when this runs, and the
// regeneration is the one moment that is EXPECTED. So the exit is neutralised
// for the length of that require and put straight back. It is done here, in a
// build tool, rather than as a flag in config.js on purpose: a bypass in the
// service is a bypass somebody can leave on in production, and then the rule
// the service is meant to enforce is one environment variable away from not
// existing.
//
// FOUR SETTINGS ARE SKIPPED — the `derived` ones. See env/defaults.js's own
// header, and common/config.js's.
// ---------------------------------------------------------------------------
'use strict';

const path = require('path');
const fs = require('fs');

// This script's own logger. Its level is LOG_LEVEL, and info without one.
const log = require('bunyan').createLogger({ name: 'generate-defaults',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'env', 'defaults.js');

// The table has to be read through the module that owns it, and reading it
// costs a startup check this file is allowed to fail. See the header.
process.env.CONFIG_FILE = process.env.CONFIG_FILE ||
                          path.join(ROOT, 'env', 'defaults.js');
const realExit = process.exit;
process.exit = function () {
  log.debug("Entering exit().");
  log.debug("Leaving exit().");
  return undefined;
};
const c = require(path.join(ROOT, 'common', 'config.js'));
process.exit = realExit;

const header = `// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: env/defaults.js
//
// ---------------------------------------------------------------------------
// THE DEFAULT APPCONFIG FILE. It is not selected with CONFIG_FILE and is not
// meant to be edited to configure a deployment — it is the BASE LAYER that the
// file CONFIG_FILE names is unioned on top of.
//
// Why it exists. Every value the shipped image runs on is written in a file
// an operator can read: common/config.js reads THIS file first and the
// operator's file over it, key by key, and the operator's value wins wherever
// the two overlap. So an operator's file may carry as few or as many keys as
// it likes, and a file which is not this service's at all — the parent
// project's in-process Kerberos jobs point CONFIG_FILE at the TEST suite's
// own config — still loads every module.
//
// IT IS NOT THE LAST WORD, SINCE 2026-11-16. Beneath it is the table's own
// default, in the image, so a copy of this file from an earlier release —
// an env/ directory mounted over the image's, say — cannot stop a newer image
// over a setting it does not carry. The start says so instead (STS-CORE-0177
// for a setting this file lacks, STS-CORE-0178 for one whose value here is
// not the image's default), and docs/configuration.md says what to do.
//
// THE VALUES HERE ARE THE \`dflt\` COLUMN OF config.js's TABLE, and this file is
// GENERATED from it — do not hand-edit a value. Changing a default means
// changing the table, which is the one place that also carries the reasoning
// for what the default is; a value edited only here would disagree with what
// /admin/config reports as the default, with the OpenAPI document's \`default\`
// property, and with docs/configuration.md's table, all three of which read
// the table.
//
// FOUR SETTINGS ARE DELIBERATELY ABSENT: global.https, oid4vp.walletUrl,
// krb5.serviceDomains and adminApi.audience are DERIVED from a neighbour (from
// oauth2.rfc9700 and oauth2.oauth21, from oid4vci.walletUrl, from krb5.realm,
// and from the public base URL or the listener's scheme, host and port). A
// literal here would freeze the derivation at whatever it evaluated to the day
// this file was written, so they resolve through their neighbour instead and
// are exempt from the startup refusal for that reason.
//
// See common/CLAUDE.md, and docs/configuration.md's *Every setting*, which
// lists every setting, its environment variable and its default in one table.
// ---------------------------------------------------------------------------
var config = {
`;

const GROUP_COMMENT = {};
const lines = [];
let lastGroup = null;

// Order: the table's own order, which is the order /admin/config renders and
// the order docs/configuration.md's table is generated in.
const rows = c.SETTINGS.filter(function (s) { return !s.derived; });

// Group by the appconfig path's first segment, since that is what the file's
// nesting has to be. The table's `group` is the human label and is used for the
// section comment.
const sections = [];
const byTop = {};
rows.forEach(function (s) {
  const path = s.path || s.key;
  const top = path.indexOf('.') >= 0 ? path.split('.')[0] : null;
  const bucket = top === null ? '(top level)' : top;
  if (!byTop[bucket]) {
    byTop[bucket] = { top: top, label: s.group, rows: [] };
    sections.push(bucket);
  }
  byTop[bucket].rows.push(s);
});

function literal(setting) {
  log.debug("Entering literal().");
  const v = typeof setting.dflt === 'function' ? setting.dflt() : setting.dflt;
  log.debug("Leaving literal().");
  return JSON.stringify(v);
}

// Width for the trailing label comment, per section, so the comments line up.
// The top-level bucket (there is exactly one key in it, `logLevel`) is emitted
// first, where every appconfig file in this directory already carries it.
sections.sort(function (a, b) {
  return (byTop[a].top === null ? 0 : 1) - (byTop[b].top === null ? 0 : 1);
});

let out = header;
sections.forEach(function (name, i) {
  const section = byTop[name];
  const label = section.top === null ? 'The log level' : section.label;
  const rule = '  // --- ' + label + ' ';
  out += (i ? '\n' : '') + rule + '-'.repeat(Math.max(3,
                                                      74 - rule.length)) + '\n';
  const entries = section.rows.map(function (s) {
    const path = s.path || s.key;
    const leaf = section.top === null ? path :
                 path.slice(section.top.length + 1);
    return { leaf: leaf, lit: literal(s), s: s };
  });
  const width = entries.reduce(function (w, e) {
    return Math.max(w, (e.leaf + ': ' + e.lit).length);
  }, 0);
  const body = entries.map(function (e, j) {
    const last = j === entries.length - 1;
    const pair = e.leaf + ': ' + e.lit +
                 ((last && section.top !== null) ? '' : ',');
    const pad = ' '.repeat(Math.max(1, width + 2 - pair.length));
    const note = e.s.label + (e.s.runtime ? '' : '; restart to apply');
    return (section.top === null ? '  ' : '    ') + pair + pad + '// ' + note;
  }).join('\n');
  if (section.top === null) {
    out += body + '\n';
  } else {
    out += '  ' + section.top + ': {\n' + body + '\n  },\n';
  }
});

out += `};

module.exports = config;
`;
fs.writeFileSync(OUT, out);
process.stderr.write('Wrote ' + OUT + ' — ' + rows.length + ' settings.\n');
