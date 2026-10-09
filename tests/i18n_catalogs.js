// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: i18n_catalogs.js
//
// ===========================================================================
// THE CATALOGS ARE WHOLE AND EVERY TRANSLATION SAYS WHAT ITS ENGLISH SAYS
// (#539, 2026-10-09).
//
// `common/locales/` is data that every user-facing page is drawn from, and a
// mistake in it is not a crash: a missing key draws its own name, and a
// translation that drops `{name}` or a `<code>` silently says less. So:
//
//   A. `catalogs.json`: every catalog tag is canonical, an overlay's base
//      exists, the status is one of three, and every OFFERED locale is
//      answered by a catalog.
//   B. Every namespace has an English file, and every key of every other
//      catalog exists in it — a key only a translation has is a typo.
//   C. Every message parses, and carries EXACTLY its English message's
//      parameters and inline elements, and no element but the four allowed.
//   D. Every BASE catalog (not a regional overlay) holds every English key:
//      rcbj asked for the pages in these languages, not partly in them.
//   E. Every key the source names in `t.html('ns.key'` or `t.text('ns.key'`
//      exists in English, so a renamed key cannot ship drawing its name. (A
//      page's translator is called `t`, by convention, so a scan finds it.)
//   F. Negotiation: `zh-HK` reads the Hong Kong overlay over Traditional and
//      never Simplified; `tl` is Filipino; `fr-CA` overlays `fr`; a language
//      with no catalog falls through to the next preference.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const i18n = require('../common/i18n');

const log = require('bunyan').createLogger({ name: 'i18n_catalogs',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const LOCALES = path.join(ROOT, 'common', 'locales');

// The source files a key may be named in: every .ts and .js this repository
// owns, outside the dependencies, the tests and the vendored copies.
function sourceFiles() {
  log.debug("Entering sourceFiles().");
  const out = [];
  const skip = ['node_modules', 'tests', 'node-ldapjs', '.git', 'docs',
                'vendored', 'embedded', 'rust', 'deploy', '.claude'];
  const walk = function (dir) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      if (skip.indexOf(entry.name) >= 0) {
        return;
      }
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (/\.(ts|js)$/.test(entry.name) &&
                 !/\.d\.ts$/.test(entry.name)) {
        out.push(full);
      }
    });
  };
  walk(ROOT);
  log.debug("Leaving sourceFiles(). " + out.length);
  return out;
}

async function run(t) {
  log.debug("Entering run().");
  const index = JSON.parse(fs.readFileSync(path.join(LOCALES,
                                                     'catalogs.json'),
                                           'utf8'));
  const tags = index.catalogs.map(function (c) {
    return c.tag;
  });

  // A.
  index.catalogs.forEach(function (c) {
    t.check(i18n.canonical(c.tag) === c.tag, 'A. catalog ' + c.tag +
            ' is canonical', i18n.canonical(c.tag));
    t.check(['source', 'machine-unreviewed', 'reviewed']
              .indexOf(c.status) >= 0, 'A. catalog ' + c.tag + ' has a ' +
            'status', c.status);
    if (c.base) {
      t.check(tags.indexOf(c.base) >= 0, 'A. overlay ' + c.tag +
              '\'s base ' + c.base + ' exists');
    }
  });
  t.check(index.source === 'en' && tags.indexOf('en') >= 0,
          'A. English is the source catalog');
  index.offered.forEach(function (o) {
    t.check(i18n.answers(o.tag), 'A. offered ' + o.tag + ' is answered by a ' +
            'catalog');
  });

  // B, C and D.
  const namespaces = i18n.namespaces();
  t.check(namespaces.length > 0, 'B. there are namespaces',
          namespaces.join(' '));
  const english = {};
  namespaces.forEach(function (ns) {
    english[ns] = i18n.messagesOf(ns, 'en');
    t.check(Object.keys(english[ns]).length > 0, 'B. namespace ' + ns +
            ' has an English file');
  });
  let problems = [];
  namespaces.forEach(function (ns) {
    const en = english[ns];
    Object.keys(en).forEach(function (key) {
      try {
        i18n.shapeOf(en[key]);
      } catch (e) {
        problems.push('en ' + ns + '.' + key + ': ' + e.message);
      }
    });
    index.catalogs.forEach(function (c) {
      if (c.tag === 'en') {
        return;
      }
      const msgs = i18n.messagesOf(ns, c.tag);
      Object.keys(msgs).forEach(function (key) {
        if (!(key in en)) {
          problems.push(c.tag + ' ' + ns + '.' + key + ' has no English key');
          return;
        }
        let mine;
        let theirs;
        try {
          mine = i18n.shapeOf(msgs[key]);
          theirs = i18n.shapeOf(en[key]);
        } catch (e) {
          problems.push(c.tag + ' ' + ns + '.' + key + ': ' + e.message);
          return;
        }
        if (mine.params.join(',') !== theirs.params.join(',')) {
          problems.push(c.tag + ' ' + ns + '.' + key + ' has parameters [' +
                        mine.params + '], English [' + theirs.params + ']');
        }
        if (mine.elements.join(',') !== theirs.elements.join(',')) {
          problems.push(c.tag + ' ' + ns + '.' + key + ' has elements [' +
                        mine.elements + '], English [' + theirs.elements +
                        ']');
        }
      });
      if (!c.base) {
        const missing = Object.keys(en).filter(function (key) {
          return !(key in msgs);
        });
        if (missing.length) {
          problems.push(c.tag + ' ' + ns + ' lacks ' + missing.length +
                        ' key(s): ' + missing.slice(0, 8).join(', '));
        }
      }
    });
  });
  // Every element in every message is one of the four allowed.
  namespaces.forEach(function (ns) {
    tags.forEach(function (tag) {
      const msgs = i18n.messagesOf(ns, tag);
      Object.keys(msgs).forEach(function (key) {
        const re = /<\/?([A-Za-z][A-Za-z0-9]*)\b[^>]*>/g;
        let m;
        while ((m = re.exec(msgs[key])) !== null) {
          if (i18n.INLINE_ELEMENTS.indexOf(m[1].toLowerCase()) < 0 ||
              /<[a-z]+\s/i.test(m[0])) {
            problems.push(tag + ' ' + ns + '.' + key + ' carries ' + m[0]);
          }
        }
      });
    });
  });
  t.check(problems.length === 0, 'B-D. every catalog is whole and every ' +
          'translation carries its English message\'s parameters and ' +
          'elements', problems.slice(0, 40).join('\n'));

  // E.
  problems = [];
  // A page's translator is called `t`, always — the convention that makes
  // this scan possible without parsing the program.
  const named =
    /\bt\.(?:html|text)\(\s*'([a-z][a-zA-Z0-9]*)\.([a-zA-Z0-9_.-]+)'/g;
  sourceFiles().forEach(function (file) {
    const body = fs.readFileSync(file, 'utf8');
    let m;
    while ((m = named.exec(body)) !== null) {
      const en = english[m[1]];
      if (!en || !(m[2] in en)) {
        problems.push(path.relative(ROOT, file) + ' names ' + m[1] + '.' +
                      m[2] + ', which English does not have');
      }
    }
  });
  t.check(problems.length === 0, 'E. every key the source names exists in ' +
          'English', problems.slice(0, 40).join('\n'));

  // F.
  t.check(i18n.chainFor('zh-HK').chain.join('>') === 'zh-Hant-HK>zh-Hant>en',
          'F. zh-HK reads the Hong Kong overlay, then Traditional, never ' +
          'Simplified', i18n.chainFor('zh-HK').chain.join('>'));
  t.check(i18n.chainFor('zh-TW').chain.join('>') === 'zh-Hant>en',
          'F. zh-TW reads Traditional', i18n.chainFor('zh-TW').chain.join('>'));
  t.check(i18n.chainFor('zh-CN').chain.join('>') === 'zh-Hans>en',
          'F. zh-CN reads Simplified', i18n.chainFor('zh-CN').chain.join('>'));
  t.check(i18n.negotiate(['tl']).catalog === 'fil', 'F. tl is Filipino');
  t.check(i18n.chainFor('fr-CA').chain.join('>') === 'fr-CA>fr>en',
          'F. fr-CA overlays fr', i18n.chainFor('fr-CA').chain.join('>'));
  t.check(i18n.chainFor('fr').chain.join('>') === 'fr>en',
          'F. fr (France) does not read the Canadian overlay',
          i18n.chainFor('fr').chain.join('>'));
  t.check(i18n.chainFor('es-PA').chain.join('>') === 'es>en' &&
          i18n.chainFor('es-ES').chain.join('>') === 'es-ES>es>en',
          'F. es-PA reads Spanish, es-ES the Spain overlay');
  const passedOver = i18n.negotiate(['de-CH', 'sv'], 'fr');
  t.check(passedOver.locale === 'sv', 'F. a language with no catalog is ' +
          'passed over for the next preference', passedOver.locale);
  t.check(i18n.negotiate(['de'], 'fr-CA').locale === 'fr-CA',
          'F. and the last resort answers when no preference does');
  t.check(i18n.negotiate(['de']).locale === 'en', 'F. and English when ' +
          'nothing does');
  t.check(i18n.canonical('not a tag!') === '' &&
          i18n.canonical('*') === '', 'F. a malformed tag and the wildcard ' +
          'are not tags');
  t.check(i18n.acceptLanguage('de-CH, fr;q=0.9, sv;q=0, *;q=0.1')
            .join(' ') === 'de-CH fr',
          'F. Accept-Language is read by q, q=0 and the wildcard left out');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'i18n_catalogs',
  describe: 'the language catalogs are whole, every translation carries its ' +
            'English message\'s parameters and markup, every key the source ' +
            'names exists, and negotiation follows BCP 47 lookup (#539)',
  run: run
};
