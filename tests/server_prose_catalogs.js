// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: server_prose_catalogs.js
//
// ===========================================================================
// THE PROSE CATALOGS FOLLOW THE SOURCE, AND A VIEW IS TRANSLATED ONLY WHERE
// IT CARRIES THE SOURCE'S OWN ENGLISH (#543, 2026-10-12).
//
// `common/server_prose.ts` translates the sentences the server writes into
// a console view. Its English stays in the source and its translations each
// record the hash of the English they were made from (rcbj's answer 3), so:
//
//   A. Every namespace's `en.json` is exactly what the source says now.
//      Stale, it fails, with the command that rewrites it.
//   B. Every translation file is a catalog `common/locales/catalogs.json`
//      lists, every entry carries a sixteen-digit hash and a text, and a
//      CURRENT translation keeps its English's MARKS verbatim: every `code
//      span` (a setting key, a path or a value translated names something
//      that does not exist), every `{{placeholder}}` of a template (#543
//      phase 2; a dropped one loses a value, an invented one draws braces),
//      every HTML tag and entity (some prose is drawn as markup), and every
//      `**` (a renderer strips them in pairs) — and a coverage note's
//      leading `full`, `partial` or `minimal`, which a consumer parses.
//   C. Every catalog is CURRENT (rcbj, 2026-10-12): a base catalog holds a
//      translation of every English message, made from the English the
//      source says NOW; an overlay holds only current translations; and no
//      catalog holds a key the English no longer has. A new setting, or a
//      changed sentence, fails here until it is translated — in the suite and
//      in the coverage run, which runs this file too. The reader would get
//      the English meanwhile (D), but rcbj asked for the pages in these
//      languages, not partly in them. `node tests/tools/prose-catalogs.js
//      --untranslated=<ns> --tag=<tag>` lists what is owed, and `--merge`
//      takes it back.
//   D. Behaviour: no `Accept-Language`, or one only English answers, means
//      no translation; a described setting is translated member by member;
//      a member that is not the row's English (a stored value) is left; a
//      stale entry serves the new English; a regional overlay wins over its
//      base; the view given is not modified.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const prose = require('../common/server_prose');
const i18n = require('../common/i18n');

const log = require('bunyan').createLogger({ name: 'server_prose_catalogs',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const DIRECTORY = path.join(ROOT, 'common', 'prose_locales');

// The MARKS of a text a translation must keep — its `code spans`, its
// {{placeholders}}, its HTML tags and entities, and its ** — sorted, as one
// string.
// A COVERAGE NOTE's first word — `full`, `partial` or `minimal` — which
// `tests/protocol/sts_metadata.js` reads from the answer and a consumer may
// parse: a translation keeps it verbatim, first (phase 3).
function coverageOf(text) {
  log.debug("Entering coverageOf().");
  const m = /^(full|partial|minimal)\b/.exec(String(text));
  log.debug("Leaving coverageOf().");
  return m ? m[1] : '';
}

// The HTML elements prose may carry, drawn as markup by a raw renderer.
const TAGS = 'a|b|br|code|em|i|kbd|li|ol|p|pre|small|span|strong|sub|sup|' +
             'ul';

function spansOf(text) {
  log.debug("Entering spansOf().");
  const t = String(text);
  const out = [].concat(t.match(/`[^`]+`/g) || [],
                        t.match(/\{\{[A-Za-z0-9]+\}\}/g) || [],
                        // HTML elements by name; `<this value>` is prose.
                        t.match(new RegExp('</?(' + TAGS + ')(\\s[^<>]*)?/?>',
                                           'g')) || [],
                        t.match(/&[A-Za-z]+;|&#[0-9]+;/g) || [],
                        t.match(/\*\*/g) || []).sort().join('\n');
  log.debug("Leaving spansOf().");
  return out;
}

async function run(t) {
  log.debug("Entering run().");
  const catalogs = i18n.catalogs();
  const tags = catalogs.map(function (c) {
    return c.tag;
  });

  // A. The source's English comes from the TOOL, run as a child: it loads
  // the whole protocol stack (a namespace's English may be in a registry
  // its modules fill as they load), which this runner must not.
  const run = childProcess.spawnSync(process.execPath,
    [path.join(ROOT, 'tests', 'tools', 'prose-catalogs.js'), '--print-all'],
    { cwd: ROOT, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024,
      timeout: 300000 });
  let extracted = {};
  try {
    extracted = JSON.parse(run.stdout);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    extracted = {};
  }
  t.check(run.status === 0 && Object.keys(extracted).length > 0,
          'A. the tool extracts every namespace from the loaded service',
          'exit ' + run.status + ' ' + String(run.stderr || '').slice(-600));
  prose.namespaces().forEach(function (ns) {
    const file = path.join(DIRECTORY, ns, 'en.json');
    const want = JSON.stringify(extracted[ns] || {}, null, 2) + '\n';
    const have = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    let first = '';
    if (want !== have) {
      const a = want.split('\n');
      const b = have.split('\n');
      for (let i = 0; i < Math.max(a.length, b.length); i++) {
        if (a[i] !== b[i]) {
          first = 'line ' + (i + 1) + ': source says ' +
                  JSON.stringify(a[i]) + ', file says ' +
                  JSON.stringify(b[i]);
          break;
        }
      }
    }
    t.check(want === have, 'A. ' + ns + '/en.json is what the source says',
            want === have ? '' : first + '. Rewrite it with `node ' +
            'tests/tools/prose-catalogs.js --print=' + ns + '` in the tests ' +
            'image (its header shows how)');
  });

  // B and C, against en.json — which A has just held to the source.
  prose.namespaces().forEach(function (ns) {
    const enFile = path.join(DIRECTORY, ns, 'en.json');
    const english = fs.existsSync(enFile)
      ? JSON.parse(fs.readFileSync(enFile, 'utf8')) : {};
    fs.readdirSync(path.join(DIRECTORY, ns)).forEach(function (name) {
      const tag = name.replace(/\.json$/, '');
      t.check(tags.indexOf(tag) >= 0, 'B. ' + ns + '/' + name +
              ' is a catalog catalogs.json lists', tags.join(' '));
    });
    tags.filter(function (tag) {
      return tag !== prose.SOURCE;
    }).forEach(function (tag) {
      const entries = prose.entriesOf(ns, tag);
      const malformed = [];
      const altered = [];
      Object.keys(entries).forEach(function (key) {
        const one = entries[key];
        if (!/^[0-9a-f]{16}$/.test(one.en) || !one.text.trim()) {
          malformed.push(key);
        } else if (key in english &&
                   one.en === prose.hashOf(english[key]) &&
                   (spansOf(one.text) !== spansOf(english[key]) ||
                    coverageOf(one.text) !== coverageOf(english[key]))) {
          altered.push(key);
        }
      });
      t.check(malformed.length === 0, 'B. every ' + ns + '/' + tag +
              ' entry has a hash and a text', malformed.slice(0, 5)
              .join(', '));
      t.check(altered.length === 0, 'B. every current ' + ns + '/' + tag +
              ' translation keeps its English marks verbatim',
              altered.slice(0, 5).map(function (key) {
                return key + ': ' + spansOf(entries[key].text)
                  .replace(/\n/g, ' ') + ' against ' +
                  spansOf(english[key]).replace(/\n/g, ' ');
              }).join('; '));
      const c = { total: 0, current: 0, stale: [], missing: [], orphans: [] };
      Object.keys(english).forEach(function (key) {
        c.total++;
        if (!entries[key]) {
          c.missing.push(key);
        } else if (entries[key].en === prose.hashOf(english[key])) {
          c.current++;
        } else {
          c.stale.push(key);
        }
      });
      Object.keys(entries).forEach(function (key) {
        if (!(key in english)) {
          c.orphans.push(key);
        }
      });
      const info = catalogs.filter(function (x) {
        return x.tag === tag;
      })[0];
      const owed = (info.base ? [] : c.missing).concat(c.stale);
      t.check(owed.length === 0 && c.orphans.length === 0,
              'C. ' + ns + '/' + tag + (info.base ? ' (an overlay on ' +
              info.base + ')' : '') + ' is current: ' + c.current + ' of ' +
              c.total + ' translated from the English the source says now',
              (info.base ? '' : c.missing.length + ' missing (' +
                c.missing.slice(0, 3).join(', ') + '), ') +
              c.stale.length + ' stale (' + c.stale.slice(0, 3).join(', ') +
              '), ' + c.orphans.length + ' orphaned (' +
              c.orphans.slice(0, 3).join(', ') + '). List what is owed with ' +
              '`node tests/tools/prose-catalogs.js --untranslated=' + ns +
              ' --tag=' + tag + '` and merge it back with `--merge`');
    });
  });

  // D.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'server-prose-'));
  try {
    const english = prose.extract('settings');
    const key = 'global.port';
    const label = english[key + '|label'];
    const description = english[key + '|description'];
    fs.mkdirSync(path.join(tmp, 'settings'));
    fs.writeFileSync(path.join(tmp, 'settings', 'fr.json'), JSON.stringify({
      'global.port|label': { en: prose.hashOf(label), text: 'FR label' },
      // Made from an older English: never served.
      'global.port|description': { en: prose.hashOf('older'),
                                   text: 'FR stale' }
    }));
    fs.writeFileSync(path.join(tmp, 'settings', 'fr-CA.json'),
                     JSON.stringify({
                       'global.port|label': { en: prose.hashOf(label),
                                              text: 'CA label' }
                     }));
    const one = new prose.ServerProse(Object.assign(
      prose.ServerProse.defaultDeps(), { directory: tmp }));
    t.check(one.translatorFor(undefined) === null &&
            one.translatorFor('') === null &&
            one.translatorFor('en-GB') === null &&
            one.translatorFor('de') === null,
            'D. no language named, or only English answering, translates ' +
            'nothing');
    const fr = one.translatorFor('fr-FR, en;q=0.5');
    t.check(!!fr && fr.chain.join(' ') === 'fr', 'D. fr-FR reads fr',
            fr && fr.chain.join(' '));
    const view = { groups: [{ group: 'x', settings: [
      { key: key, label: label, description: description, value: 8081 },
      { key: key, label: 'something an operator wrote' },
      { key: 'no.such.setting', label: label }
    ] }], when: new Date(0) };
    const before = JSON.stringify(view);
    const out = one.translateView(view, fr);
    const rows = out.groups[0].settings;
    t.equal(rows[0].label, 'FR label',
            'D. a described setting\'s label is translated');
    t.equal(rows[0].description, description,
            'D. a translation of an older English serves the new English');
    t.equal(rows[0].value, 8081, 'D. the value is left as it was');
    t.equal(rows[1].label, 'something an operator wrote',
            'D. a member that is not the row\'s English is left');
    t.equal(rows[2].label, label, 'D. an object no setting owns is left');
    t.check(out.when instanceof Date, 'D. a Date is left for JSON');
    t.equal(JSON.stringify(view), before, 'D. the view given is unchanged');
    const ca = one.translatorFor('fr-CA');
    t.equal(one.translateView(view, ca).groups[0].settings[0].label,
            'CA label', 'D. the fr-CA overlay wins over fr');
    t.equal(one.translateView(view, null), view,
            'D. no translator answers the view itself');
    const c = one.coverage('settings', 'fr');
    t.check(c.current === 1 && c.stale.length === 1 &&
            c.stale[0] === 'global.port|description' &&
            c.missing.length === c.total - 2,
            'D. coverage counts current, stale and missing',
            JSON.stringify({ current: c.current, stale: c.stale.length,
                             missing: c.missing.length, total: c.total }));

    // D, a PHRASE source (#543 phase 2): exact, templated, a list inside a
    // template, a parameter-only phrase, and nothing off its routes.
    fs.mkdirSync(path.join(tmp, 'demo'));
    const demoEnglish = {
      'a.label': 'Minimum length',
      'a.mechanism.totp': 'Authenticator app (TOTP)',
      'a.mechanism.mail': 'An emailed code, and a link',
      'a.sentences.factors': 'first factors: {{list}}',
      'a.sentences.length': 'at least {{n}} characters',
      'a.sentences.param.none': 'none'
    };
    const demoFr = {
      'a.label': 'Longueur minimale',
      'a.mechanism.totp': 'Application d\'authentification (TOTP)',
      'a.mechanism.mail': 'Un code envoyé, et un lien',
      'a.sentences.factors': 'premiers facteurs : {{list}}',
      'a.sentences.length': 'au moins {{n}} caractères',
      'a.sentences.param.none': 'aucun'
    };
    const demoFile = {};
    Object.keys(demoFr).forEach(function (k) {
      demoFile[k] = { en: prose.hashOf(demoEnglish[k]), text: demoFr[k] };
    });
    fs.writeFileSync(path.join(tmp, 'demo', 'fr.json'),
                     JSON.stringify(demoFile));
    const demo = new prose.ServerProse(Object.assign(
      prose.ServerProse.defaultDeps(), { directory: tmp, sources: {
        demo: prose.phraseSource({ routes: ['/admin-api/demo'],
                                   extract: function () {
                                     return demoEnglish;
                                   } }) } }));
    const on = demo.translatorFor('fr', '/admin-api/demo');
    const answer = { title: 'Minimum length', none: 'none',
                     rules: ['at least 12 characters',
                             'first factors: Authenticator app (TOTP), ' +
                             'An emailed code, and a link',
                             'first factors: none',
                             'first factors: Authenticator app (TOTP), ' +
                             'cn=someone'],
                     data: 'cn=Minimum length' };
    const fr2 = demo.translateView(answer, on);
    t.equal(fr2.title, 'Longueur minimale', 'D. a phrase is translated');
    t.equal(fr2.rules[0], 'au moins 12 caractères',
            'D. a template is refilled, its number carried over');
    t.equal(fr2.rules[1], 'premiers facteurs : Application ' +
            'd\'authentification (TOTP), Un code envoyé, et un lien',
            'D. a list inside a template is translated item by item, a ' +
            'phrase holding a comma kept whole');
    t.equal(fr2.rules[2], 'premiers facteurs : aucun',
            'D. a parameter-only phrase is translated inside a template');
    t.equal(fr2.none, 'none',
            'D. a parameter-only phrase is never translated on its own');
    t.equal(fr2.rules[3], 'premiers facteurs : Authenticator app (TOTP), ' +
            'cn=someone', 'D. a list with an item that is data is carried ' +
            'over whole');
    t.equal(fr2.data, 'cn=Minimum length', 'D. data is left as it is');
    const off = demo.translateView(answer,
                                   demo.translatorFor('fr', '/admin-api/x'));
    t.equal(off.title, 'Minimum length',
            'D. a phrase source translates nothing off its routes');
    t.equal(prose.fill('at least {{n}} characters, {{m}}', { n: 3 }),
            'at least 3 characters, {{m}}',
            'D. fill() leaves a placeholder with no parameter as written');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'server_prose_catalogs',
  describe: 'the prose catalogs follow the source, every base catalog ' +
            'translates all of it from the current English, every ' +
            'translation keeps its code spans, and a view is translated ' +
            'only where it carries the source\'s own English (#543)',
  run: run
};
