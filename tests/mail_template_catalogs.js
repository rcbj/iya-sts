// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: mail_template_catalogs.js
//
// ===========================================================================
// THE BUILT-IN MAIL TEMPLATES IN EVERY CATALOG LANGUAGE ARE WHOLE, AND EACH
// KEEPS THE RULES ITS ENGLISH KEEPS (#539, 2026-10-09).
//
// `common/mail_locales/<tag>.json` is data a person's reset link, sign-in
// code and security notices are sent in, and a mistake in it is not a crash:
// a translation that drops `{{link}}` sends a reset with nothing to click,
// one that writes an address of its own sends a link somewhere else. So:
//
//   A. Every file is named for a catalog of `common/locales/catalogs.json`
//      (English is `BUILT_IN`, not a file), and every BASE catalog has a file
//      holding every message, the layout and every category's reason.
//   B. Every template in every file passes `MailTemplates.problem()` — the
//      rules a realm's own wording is held to when it is saved — names only
//      known messages, and carries in EACH PART exactly the placeholders its
//      English part does, every link as `href="{{x}}"` exactly as the
//      English writes it, and no element the English does not use.
//   C. An overlay holds only what differs from its base.
//   D. The language walk `templateFor()` makes, asked through
//      `languageOrder()` and `builtInFor()` without the mail store: `fr-CA`
//      reads its overlay over French, `zh-TW` reads Traditional, `zh-HK`
//      never Simplified, `de` falls through to English, and the layout's
//      reason follows the same chain.
//   E. A VALUE FOLLOWS THE RECIPIENT'S LANGUAGE: every `mailValues.<key>` a
//      caller of the channel names exists in the English catalog (the
//      namespace's other rules are `tests/i18n_catalogs.js`'s), and
//      `Mail.resolveValues()` puts a `{ i18n }` message and a `{ date }`
//      instant into words in the language given — the overlay's where it
//      has one — while a plain string, a key outside `mailValues` and an
//      object of any other shape are left as data or rendered empty.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const i18n = require('../common/i18n');
const MailTemplates = require('../common/mail_templates');

const log = require('bunyan').createLogger({ name: 'mail_template_catalogs',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const DIR = path.join(ROOT, 'common', 'mail_locales');
const PARTS = ['subject', 'text', 'html'];

// The element names a piece of HTML uses, once each, sorted.
function elementsOf(html) {
  log.debug("Entering elementsOf().");
  const out = [];
  String(html || '').replace(/<\s*\/?\s*([A-Za-z][A-Za-z0-9]*)/g,
    function (whole, name) {
      const lower = name.toLowerCase();
      if (out.indexOf(lower) < 0) {
        out.push(lower);
      }
      return whole;
    });
  log.debug("Leaving elementsOf().");
  return out.sort();
}

// Every href value in a piece of HTML, in order, as written.
function hrefsOf(html) {
  log.debug("Entering hrefsOf().");
  const out = (String(html || '').match(/\shref\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi) ||
               []).map(function (one) {
    return one.trim();
  });
  log.debug("Leaving hrefsOf().");
  return out;
}

// The language `templateFor()` would send a message in, for a realm with no
// wording of its own: the first language of the order with a built-in
// translation, or English.
function walk(id, preferred, fallback) {
  log.debug("Entering walk().");
  const order = MailTemplates.languageOrder(preferred, fallback);
  for (let i = 0; i < order.length; i++) {
    const found = MailTemplates.builtInFor(id, order[i]);
    if (found) {
      log.debug("Leaving walk(). " + found.lang);
      return found.lang;
    }
    if (order[i] === 'en') {
      break;
    }
  }
  log.debug("Leaving walk(). en");
  return 'en';
}

async function run(t) {
  log.debug("Entering run().");
  const index = JSON.parse(fs.readFileSync(path.join(ROOT, 'common',
                                                     'locales',
                                                     'catalogs.json'),
                                           'utf8'));
  const catalogs = {};
  index.catalogs.forEach(function (c) {
    catalogs[c.tag] = c;
  });
  const files = {};
  fs.readdirSync(DIR).forEach(function (name) {
    t.check(/\.json$/.test(name), 'A. only .json files in ' +
            'common/mail_locales', name);
    const tag = name.replace(/\.json$/, '');
    let body = null;
    try {
      body = JSON.parse(fs.readFileSync(path.join(DIR, name), 'utf8'));
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      t.check(false, 'A. ' + name + ' parses', (e && e.message) || e);
    }
    if (body) {
      files[tag] = body;
    }
  });
  t.check(Object.keys(MailTemplates.localeFiles()).sort().join(',') ===
            Object.keys(files).sort().join(','),
          'A. the loader reads every file the directory holds');

  // A.
  Object.keys(files).forEach(function (tag) {
    t.check(!!catalogs[tag] && tag !== index.source, 'A. ' + tag +
            '.json is named for a catalog other than English');
  });
  const ids = MailTemplates.BUILT_IN.map(function (spec) {
    return spec.id;
  });
  index.catalogs.filter(function (c) {
    return c.tag !== index.source && !c.base;
  }).forEach(function (c) {
    const file = files[c.tag];
    t.check(!!file, 'A. base catalog ' + c.tag + ' has a mail file');
    if (!file) {
      return;
    }
    ids.forEach(function (id) {
      const has = id === MailTemplates.LAYOUT_ID ? file.layout
        : file.templates && file.templates[id];
      t.check(!!has, 'A. ' + c.tag + ' has the ' + id + ' message');
    });
    MailTemplates.CATEGORIES.forEach(function (cat) {
      t.check(!!(file.categories && file.categories[cat.id] &&
                 file.categories[cat.id].reason),
              'A. ' + c.tag + ' has the ' + cat.id + ' reason');
    });
  });

  // B.
  Object.keys(files).forEach(function (tag) {
    const file = files[tag];
    const entries = Object.keys(file.templates || {}).map(function (id) {
      return [id, file.templates[id]];
    });
    if (file.layout) {
      entries.push([MailTemplates.LAYOUT_ID, file.layout]);
    }
    Object.keys(file).forEach(function (key) {
      t.check(['templates', 'layout', 'categories'].indexOf(key) >= 0,
              'B. ' + tag + ' has only templates, layout and categories',
              key);
    });
    Object.keys(file.categories || {}).forEach(function (id) {
      t.check(!!MailTemplates.category(id), 'B. ' + tag + ' names a known ' +
              'category', id);
    });
    entries.forEach(function (entry) {
      const id = entry[0];
      const parts = entry[1];
      const spec = MailTemplates.builtIn(id);
      const where = tag + ' ' + id;
      t.check(!!spec && (id !== MailTemplates.LAYOUT_ID ||
                         (file.templates || {})[id] === undefined),
              'B. ' + where + ' is a known message, in its place');
      if (!spec) {
        return;
      }
      const problem = MailTemplates.problem(spec, parts);
      t.check(problem === '', 'B. ' + where + ' keeps the rules', problem);
      PARTS.forEach(function (part) {
        const want = MailTemplates.placeholders(spec[part]).sort().join(',');
        const got = MailTemplates.placeholders(parts[part]).sort().join(',');
        t.check(want === got, 'B. ' + where + ' ' + part + ' carries ' +
                'exactly the English placeholders', got + ' vs ' + want);
      });
      t.check(hrefsOf(parts.html).join(' ') === hrefsOf(spec.html).join(' '),
              'B. ' + where + ' writes every link as the English does',
              hrefsOf(parts.html).join(' '));
      const allowed = elementsOf(spec.html);
      const extra = elementsOf(parts.html).filter(function (name) {
        return allowed.indexOf(name) < 0;
      });
      t.check(extra.length === 0, 'B. ' + where + ' uses no element the ' +
              'English does not', extra.join(','));
    });
  });

  // C.
  Object.keys(files).forEach(function (tag) {
    const base = catalogs[tag] && catalogs[tag].base;
    if (!base || !files[base]) {
      return;
    }
    Object.keys(files[tag].templates || {}).forEach(function (id) {
      t.check(JSON.stringify(files[tag].templates[id]) !==
                JSON.stringify((files[base].templates || {})[id]),
              'C. overlay ' + tag + ' ' + id + ' differs from ' + base);
    });
  });

  // D.
  t.check(walk('address-verification', 'fr-CA', 'en') === 'fr-CA',
          'D. fr-CA reads its overlay where it has the message');
  t.check(walk('password-reset', 'fr-CA', 'en') === 'fr',
          'D. and French where the overlay does not');
  t.check(walk('password-reset', 'fr', 'en') === 'fr',
          'D. fr reads French, not Canadian');
  t.check(walk('address-verification', 'fr', 'en') === 'fr',
          'D. and not the Canadian overlay');
  t.check(walk('password-reset', 'zh-TW', 'en') === 'zh-Hant',
          'D. zh-TW reads Traditional Chinese');
  ['password-reset', 'address-changed', 'sign-in-code'].forEach(
    function (id) {
      const got = walk(id, 'zh-HK', 'en');
      t.check(got === 'zh-Hant-HK' || got === 'zh-Hant',
              'D. zh-HK reads Traditional for ' + id + ', never Simplified',
              got);
    });
  t.check(walk('address-changed', 'zh-hk', 'en') === 'zh-Hant-HK',
          'D. zh-hk, lower case, reads the Hong Kong overlay');
  t.check(walk('password-reset', 'zh-CN', 'en') === 'zh-Hans',
          'D. zh-CN reads Simplified Chinese');
  t.check(walk('password-reset', 'de', 'en') === 'en',
          'D. de, with no catalog, falls through to English');
  t.check(walk('password-reset', 'de, sv;q=0.5', 'en') === 'sv',
          'D. and a later preference a catalog answers is read');
  t.check(walk('password-reset', 'de', 'es') === 'es',
          'D. the realm\'s default language before English');
  t.check(walk('password-reset', 'tl', 'en') === 'fil',
          'D. tl is Filipino');
  t.check(MailTemplates.builtInFor('password-reset', 'en') === null,
          'D. English is BUILT_IN, never a file');
  t.check(MailTemplates.builtInFor('no-such-message', 'fr') === null,
          'D. an unknown message has no translation');
  t.check(walk(MailTemplates.LAYOUT_ID, 'sv-SE', 'en') === 'sv',
          'D. the layout is translated too');
  t.check(MailTemplates.reasonFor('account', 'es-ES') ===
            files['es-ES'].categories.account.reason,
          'D. the reason reads the overlay');
  t.check(MailTemplates.reasonFor('security', 'es-ES') ===
            files.es.categories.security.reason,
          'D. and its base where the overlay has none');
  t.check(MailTemplates.reasonFor('security', 'de') ===
            MailTemplates.category('security').reason,
          'D. and English for a language no catalog answers');
  const listed = MailTemplates.builtInLanguages('address-changed');
  t.check(listed.indexOf('fr-CA') >= 0 && listed.indexOf('zh-Hans') >= 0 &&
          listed.indexOf('en') < 0,
          'D. builtInLanguages lists every catalog with a translation',
          listed.join(','));
  valuesFollowTheLanguage(t);
  log.debug("Leaving run().");
}

// The source files that hand the channel a `mailValues` message.
const VALUE_CALLERS = ['common/mail_uses.ts', 'admin-core/admin_actions.ts'];

function valuesFollowTheLanguage(t) {
  log.debug("Entering valuesFollowTheLanguage().");
  const english = i18n.messagesOf('mailValues', 'en');
  t.check(Object.keys(english).length > 0,
          'E. the mailValues namespace has an English catalog');
  const named = [];
  VALUE_CALLERS.forEach(function (file) {
    // The compiled `.js` where the `.ts` was stripped from the image; the
    // literals are the same in both.
    const ts = path.join(ROOT, file);
    const text = fs.readFileSync(fs.existsSync(ts) ? ts
      : ts.replace(/\.ts$/, '.js'), 'utf8');
    // `MailUses.said('key'` in mail_uses.ts; the full `'mailValues.key'`
    // literal anywhere else.
    (text.match(/said\('([A-Za-z0-9_.-]+)'/g) || [])
      .forEach(function (one) {
        named.push(one.replace(/^said\('|'$/g, ''));
      });
    (text.match(/'mailValues\.([A-Za-z0-9_.-]+)'/g) || [])
      .forEach(function (one) {
        named.push(one.replace(/^'mailValues\.|'$/g, ''));
      });
  });
  t.check(named.length >= 10, 'E. the callers name mailValues messages',
          named.join(' '));
  const missing = named.filter(function (key) {
    return !Object.prototype.hasOwnProperty.call(english, key);
  });
  t.check(missing.length === 0, 'E. every mailValues key a caller names ' +
          'exists in English', missing.join(' '));

  const mailModule = require('../common/mail');
  const m = new mailModule.Mail(mailModule.Mail.defaultDeps());
  const at = Date.UTC(2026, 9, 9, 12, 34, 0);
  const given = {
    username: 'zoé',
    by: { i18n: 'mailValues.by.administrator' },
    requestedBy: { i18n: 'mailValues.requestedBy.administratorNamed',
                   params: { actor: '<b>boss</b>' } },
    how: { i18n: 'mailValues.how.by', params: { entity: 'admin' } },
    what: { i18n: 'mailValues.credential.type',
            params: { type: 'urn:example:other' } },
    when: { date: at },
    page: { i18n: 'authn.title' },
    odd: { something: 'else' }
  };
  const en = m.resolveValues(given, 'en');
  t.check(en.username === 'zoé' && en.by === 'an administrator' &&
          en.requestedBy === 'an administrator (<b>boss</b>)' &&
          en.how === 'by admin' && en.what === 'urn:example:other',
          'E. in English a message reads as the caller used to write it, ' +
          'a param raw (the renderer escapes it) and an unlisted select ' +
          'value as itself', JSON.stringify(en));
  t.check(en.when === i18n.translator(['en']).date(at) &&
          /UTC/.test(en.when) && /2026/.test(en.when),
          'E. an instant is a date and time in UTC, the zone named', en.when);
  t.check(en.page === '' && en.odd === '',
          'E. a key outside mailValues, and an object of no known shape, ' +
          'render empty rather than as a page\'s words or [object Object]',
          JSON.stringify([en.page, en.odd]));
  const fr = m.resolveValues(given, 'fr');
  t.check(fr.by === 'un administrateur' && fr.how === 'par un administrateur' &&
          fr.username === 'zoé' &&
          fr.when === i18n.translator(['fr']).date(at) && fr.when !== en.when,
          'E. in French the message and the date are French',
          JSON.stringify(fr));
  const sv = m.resolveValues({ what: { i18n: 'mailValues.credential.type',
                                       params: { type: 'password' } } }, 'sv');
  t.check(sv.what === 'Lösenordet', 'E. a select picks the translated branch',
          sv.what);
  const hk = m.resolveValues({ r: { i18n:
    'mailValues.requestedBy.recoveryCode' } }, 'zh-hant-hk');
  const tw = m.resolveValues({ r: { i18n:
    'mailValues.requestedBy.recoveryCode' } }, 'zh-Hant');
  t.check(/電郵/.test(hk.r) && !/電郵/.test(tw.r),
          'E. a regional overlay is read (and a realm\'s lowercased tag ' +
          'reaches it)', JSON.stringify([hk.r, tw.r]));
  log.debug("Leaving valuesFollowTheLanguage().");
}

module.exports = {
  name: 'mail_template_catalogs',
  describe: 'the built-in mail templates in every catalog language are ' +
            'whole, keep the rules and the English placeholders, and are ' +
            'chosen along the BCP 47 chain (#539)',
  run: run
};
