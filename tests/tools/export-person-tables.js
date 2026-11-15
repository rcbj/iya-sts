#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: export-person-tables.js
//
// ---------------------------------------------------------------------------
// WHAT `users/create` READS ABOUT A PERSON, FOR `sts-registers` (#444,
// phase 5, the `apis5` slice).
//
// Two things a create does in Node that the Rust port reads as tables:
//
//   * THE INVENTED PERSON (`oid4vc/vc_claims.ts`'s `personaFor()` and
//     `generatedFor()`): the name tables a mulberry32 stream seeded by the
//     username draws from, in the order it draws, and the credential
//     catalogue's rows with the persona member each fills (`from`) and
//     whether the realm's selection holds it by default. In development a
//     create without `invent: false` writes that person onto the entry
//     (`namePlan()`, `applyVcAttributes()`).
//   * THE TYPED-ATTRIBUTE CHECK (`personAttributesFrom()`, STS-LDAP-0047 and
//     STS-LDAP-0106): the catalogue a create's attribute names are held to
//     (`vcClaims.personField()`), the person editor's editable rows with the
//     format each value is held to (`personEditor.checkCreateValues()`), the
//     format hints and shapes, and the two-letter country codes
//     `common/country_codes.js` knows.
//
// It loads the whole stack, so it runs where TypeScript is compiled: the
// tests image.
//
//   node tests/tools/export-person-tables.js           write the file
//   node tests/tools/export-person-tables.js --check   exit 1 when stale
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'export-person-tables',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..', '..');
const FILE = path.join(ROOT, 'rust', 'crates', 'sts-registers', 'tables',
                       'people.json');

/**
 * The tables, as the Rust crate reads them.
 *
 * @returns {any} the export
 */
function tables() {
  log.debug("Entering tables().");
  require(path.join(ROOT, 'common', 'protocol_stack'));
  const vcClaims = require(path.join(ROOT, 'oid4vc', 'vc_claims'));
  const personEditor = require(path.join(ROOT, 'ldap', 'person_editor'));
  const countryCodes = require(path.join(ROOT, 'common', 'country_codes'));
  const source = fs.readFileSync(path.join(ROOT, 'ldap',
                                           'person_editor.js'), 'utf8');
  // The editor's shapes and hints are module constants it does not export;
  // they are read off the compiled module's text, each by its name, so a
  // change to one is a change here.
  const constant = function (name) {
    log.debug("Entering constant(). " + name);
    const m = new RegExp('^const ' + name + ' = (\\/.*\\/[a-z]*);$', 'm')
      .exec(source);
    if (!m) {
      throw new Error('person_editor.js has no regex ' + name);
    }
    log.debug("Leaving constant().");
    // eslint-disable-next-line no-eval
    return (0, eval)(m[1]).source;
  };
  const hints = (function () {
    log.debug("Entering hints().");
    const m = /^const FORMAT_HINTS = (\{[\s\S]*?\n\});$/m.exec(source);
    if (!m) {
      throw new Error('person_editor.js has no FORMAT_HINTS');
    }
    log.debug("Leaving hints().");
    // eslint-disable-next-line no-eval
    return (0, eval)('(' + m[1] + ')');
  }());
  const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const countries = [];
  for (const a of letters) {
    for (const b of letters) {
      if (countryCodes.alpha3(a + b) !== a + b) {
        countries.push(a + b);
      }
    }
  }
  const out = {
    persona: vcClaims.PERSONA_TABLES,
    // The catalogue (`VC_ATTRIBUTES`), in its order: the attribute, the
    // persona member that fills it, and whether the realm's selection
    // holds it until an administrator changes it.
    catalogue: vcClaims.VC_ATTRIBUTES.map(function (row) {
      return { ldap: row.ldap, from: row.from || '',
               byDefault: !!row.byDefault };
    }),
    defaultSelection: vcClaims.DEFAULT_SELECTION.slice(0),
    // `personField(name)`: every catalogue row but `uid`.
    personFields: vcClaims.PERSON_FIELDS.map(function (row) {
      return row.ldap;
    }),
    // The editor's rows a create holds a value to, in a realm with no
    // custom attribute and no policy kind that names a person.
    editable: personEditor.editableAttributes().map(function (row) {
      return { name: row.name, multi: !!row.multi, format: row.format || '',
               choices: row.choices || null };
    }),
    formatHints: hints,
    maxValueLength: personEditor.MAX_VALUE_LENGTH,
    shapes: {
      email: constant('EMAIL_SHAPE'),
      control: constant('CONTROL'),
      language: constant('LANGUAGE_RANGE'),
      dn: constant('DN_SHAPE')
    },
    countries: countries
  };
  log.debug("Leaving tables().");
  return out;
}

/**
 * The text the file should hold.
 *
 * @returns {string} the text
 */
function rendered() {
  log.debug("Entering rendered().");
  const text = JSON.stringify(tables(), null, 1) + '\n';
  log.debug("Leaving rendered().");
  return text;
}

if (require.main === module) {
  const text = rendered();
  if (process.argv.indexOf('--check') >= 0) {
    let current = null;
    try {
      current = fs.readFileSync(FILE, 'utf8');
    } catch (e) {
      log.debug("Caught in export-person-tables.js: " +
                ((e && e.message) || e));
      current = null;
    }
    if (current !== text) {
      console.error('stale: ' + path.relative(ROOT, FILE) +
                    ' — run node tests/tools/export-person-tables.js');
      process.exit(1);
    }
    console.log('the person tables are current');
    process.exit(0);
  }
  const out = process.argv[2] || FILE;
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, text);
  console.log('wrote ' + out);
  process.exit(0);
}

module.exports = { tables: tables, rendered: rendered };
