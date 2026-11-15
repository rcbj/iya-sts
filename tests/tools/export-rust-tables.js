#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: export-rust-tables.js
//
// ---------------------------------------------------------------------------
// THE RUST RUNTIME'S COPY OF THIS SERVICE'S TABLES (#444, rust/DESIGN.md
// section 4.4), WRITTEN FROM THE ONE TABLE AND NEVER BY HAND.
//
// Until the cutover the Node service runs, so its tables stay the ones that
// are edited — `common/error_codes.js` above all. The Rust crates read a JSON
// export of each, which `sts-core`'s `build.rs` turns into code (a constant
// per error code, so a code missing from the table does not compile). Two
// copies are a chance to drift, so `tests/rust_tables.js` regenerates the
// export in memory and fails when the committed file differs: edit the table,
// run this, commit both.
//
//   node tests/tools/export-rust-tables.js           write the files
//   node tests/tools/export-rust-tables.js --check   exit 1 when stale
//
// At the cutover the direction reverses: the JSON becomes the table and the
// JavaScript is deleted.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const DATA = path.join(ROOT, 'rust', 'crates', 'sts-core', 'tables');
const CRYPTO_DATA = path.join(ROOT, 'rust', 'crates', 'sts-crypto', 'tables');

// Each export: the file it writes and the document it holds. Key order is
// the table's, so a diff of the export reads like a diff of the table.
function errorCodes() {
  const table = require(path.join(ROOT, 'common', 'error_codes.js'));
  return {
    subsystems: table.SUBSYSTEMS.map(function (one) {
      return { id: one.id, label: one.label, where: one.where || '',
               what: one.what || '' };
    }),
    codes: table.CODES.map(function (one) {
      const row = { code: one.code, summary: one.summary,
                    spec: one.spec || '' };
      if (one.retired) {
        row.retired = true;
      }
      return row;
    })
  };
}

// The settings table (`common/config.js`'s SETTINGS) and the keys it
// refuses by name because they were replaced (REPLACED_SETTINGS). A row is
// data except where its default is a FUNCTION: those export `dflt: null`
// and `derivedDefault: true`, and `sts-core::settings` computes them in Rust
// (a function cannot be data). Loading config.js needs its npm dependencies,
// so this export runs where they are installed — the tests image, or a
// checkout after `npm install`.
//
// TWO KINDS OF FUNCTION (#1491). Four are expressions of other settings,
// ported by hand (DERIVED_BY_HAND). Every other one is config.js's
// `strongerInProduct(product, development)` — a closure over two values,
// one per mode — and those two values ARE data: the export reads them by
// calling the default once in each mode and carries them as `byMode`. A
// function that is neither is refused here, so a new kind of derived
// default stops the export rather than reaching Rust as a null.
const DERIVED_BY_HAND = ['global.https', 'adminApi.audience',
                         'oid4vp.walletUrl', 'krb5.serviceDomains'];
const STRONGER_IN_PRODUCT =
  /^function \(\) \{\s*return value\('global\.mode'\) === 'product' \? product : development;\s*\}$/;

// The two values of a `strongerInProduct()` default, read with `global.mode`
// pinned in the environment layer (which `resolve()` reads live). Run where
// nothing above that layer holds the mode: an override or a realm would win.
function byMode(config, row) {
  const saved = process.env.STS_MODE;
  const out = {};
  try {
    ['product', 'development'].forEach(function (mode) {
      process.env.STS_MODE = mode;
      if (config.value('global.mode') !== mode) {
        throw new Error('export-rust-tables: global.mode is not ' + mode +
                        ' with STS_MODE set; run with no override of it');
      }
      out[mode] = row.dflt();
    });
  } finally {
    if (saved === undefined) {
      delete process.env.STS_MODE;
    } else {
      process.env.STS_MODE = saved;
    }
  }
  return out;
}

function settings() {
  const config = require(path.join(ROOT, 'common', 'config.js'));
  return {
    settings: config.SETTINGS.map(function (row) {
      const out = {};
      Object.keys(row).forEach(function (key) {
        if (typeof row[key] === 'function') {
          out[key] = null;
          if (key === 'dflt') {
            out.derivedDefault = true;
            if (DERIVED_BY_HAND.indexOf(row.key) < 0) {
              const source = row.dflt.toString().split('\n').filter(
                function (line) {
                  return !/log\.debug/.test(line);
                }).join('\n');
              if (!STRONGER_IN_PRODUCT.test(source)) {
                throw new Error('export-rust-tables: ' + row.key + '\'s ' +
                  'default is a function of a kind sts-core does not ' +
                  'compute; port it to sts-core::settings and name it in ' +
                  'DERIVED_BY_HAND');
              }
              out.byMode = byMode(config, row);
            }
          }
          return;
        }
        out[key] = row[key];
      });
      return out;
    }),
    replaced: config.REPLACED_SETTINGS
  };
}

// The mode (`common/mode.js`): the names of its predicates — each is a
// method of `sts-core::mode::Mode`, and a Rust test fails on a name it does
// not answer — the sentence each one's write refusal ends with, and the two
// tables `/admin/mode` draws, REQUIREMENTS and NOT_YET.
// `prose` is the #543 harvest of the module's sentences, not a predicate.
const MODE_HELPERS = ['current', 'isProduct', 'isDevelopment', 'allowsValue',
                      'valueInForce', 'inForce', 'writeRefusalReason',
                      'report', 'prose'];

function modeTable() {
  const mode = require(path.join(ROOT, 'common', 'mode.js'));
  const predicates = Object.keys(mode).filter(function (name) {
    return typeof mode[name] === 'function' &&
      MODE_HELPERS.indexOf(name) < 0;
  });
  const fallback = mode.writeRefusalReason('');
  const writeRefusals = {};
  predicates.forEach(function (name) {
    const reason = mode.writeRefusalReason(name);
    if (reason !== fallback) {
      writeRefusals[name] = reason;
    }
  });
  return {
    predicates: predicates,
    writeRefusalFallback: fallback,
    writeRefusals: writeRefusals,
    requirements: mode.REQUIREMENTS,
    notYet: mode.NOT_YET
  };
}

// THE SIGNATURE ALGORITHM REGISTRY (#1368, #1374): every signature algorithm
// this service knows, once, with its spelling on each surface — what
// `sts-crypto::algorithms` reads. The rows as the registry indexes them
// (`pki` renamed `x509`, every surface present, the httpsig JWS aliases of
// RFC 9421 section 3.3.7), each surface's and consumer's recorded order, and
// the tables kept beside the rows. RECORDED is not exported by the module, so
// its consumers are named here; `recorded()` answers [] for any other.
const RECORDED_NAMES = ['jose', 'cose', 'cose.status', 'cose.mdoc', 'xml',
                        'x509', 'httpsig', 'cms', 'dkim', 'tls', 'di'];

function algorithmRegistry() {
  const registry = require(path.join(ROOT, 'common', 'crypto_impl',
                                     'algorithm_registry.js'));
  const recorded = {};
  RECORDED_NAMES.forEach(function (name) {
    recorded[name] = registry.recorded(name);
  });
  return {
    surfaces: registry.SURFACES,
    rawSignatureFamilies: registry.RAW_SIGNATURE_FAMILIES,
    rows: JSON.parse(JSON.stringify(registry.ROWS)),
    recorded: recorded,
    xmlRefused: registry.xmlSignaturesRefused(),
    xmlDigests: registry.xmlDigestMethods(),
    xmlDigestsRefused: registry.xmlDigestsRefused(),
    pkiKeyAlgorithms: registry.pkiKeyAlgorithms()
  };
}

// THE AUDIT LOG'S VOCABULARY (#444, phase 4): `common/audit.js`'s
// CATEGORIES, ACTIONS and OUTCOMES, which `sts-audit::vocabulary` reads —
// the console's filters, the API's `categories` and `actions`, and the
// category an action is filed under all come from them.
const AUDIT_DATA = path.join(ROOT, 'rust', 'crates', 'sts-audit', 'tables');

function auditVocabulary() {
  const audit = require(path.join(ROOT, 'common', 'audit.js'));
  return JSON.parse(JSON.stringify({
    categories: audit.CATEGORIES,
    actions: audit.ACTIONS,
    outcomes: audit.OUTCOMES
  }));
}

// THE MAIL CHANNEL'S MESSAGES (#444, phase 4): `common/mail_templates.ts`'s
// built-in English templates and categories, every translation file under
// `common/mail_locales/` as the module reads it, and the catalog tags the
// language chain is worked out against (`common/locales/catalogs.json`) —
// what `sts-mail::templates` renders from.
const MAIL_DATA = path.join(ROOT, 'rust', 'crates', 'sts-mail', 'tables');

function mailTemplates() {
  const templates = require(path.join(ROOT, 'common', 'mail_templates'));
  const catalogs = require(path.join(ROOT, 'common', 'locales',
                                     'catalogs.json'));
  return JSON.parse(JSON.stringify({
    layoutId: templates.LAYOUT_ID,
    common: templates.COMMON,
    categories: templates.CATEGORIES,
    builtIn: templates.BUILT_IN,
    locales: templates.localeFiles(),
    source: catalogs.source,
    catalogs: catalogs.catalogs
  }));
}

// THE AUTHORIZATION SERVER'S TWO MODE REPORTS (#444, phase 5, the `oauth5`
// slice): `GET /oauth2/rfc9700` (`oauth2_bcp.js`'s `REQUIREMENTS` and the
// constant sentences of `state()`) and `GET /oauth2/oauth21` (`oauth21.js`'s
// `REQUIREMENTS` and `state()`'s), which `sts-oauth::reports` serves. A row
// whose `enforced` or `note` is a FUNCTION depends on the settings, and is
// exported EVALUATED, once for each combination of the four settings those
// functions read — `global.https`, `oauth2.allowImplicitTokenResponses` and
// the two access-token requirements — keyed `https|implicit|dpop|mtls` with
// each a 0 or a 1. `config.value()` answers those four from the combination
// while the export runs, and the settings as they are otherwise: OAuth 2.1
// and FAPI off, so the implicit waiver is the setting alone.
const OAUTH_DATA = path.join(ROOT, 'rust', 'crates', 'sts-oauth', 'tables');
const REPORT_INPUTS = ['global.https', 'oauth2.allowImplicitTokenResponses',
                       'oauth2.accessTokenRequireDpop',
                       'oauth2.accessTokenRequireMtls'];

function oauthReports() {
  const config = require(path.join(ROOT, 'common', 'config.js'));
  const bcp = require(path.join(ROOT, 'oauth-oidc', 'oauth2_bcp.js'));
  const oauth21 = require(path.join(ROOT, 'oauth-oidc', 'oauth21.js'));
  const real = config.value;
  const forced = {};
  config.value = function (key) {
    if (Object.prototype.hasOwnProperty.call(forced, key)) {
      return forced[key];
    }
    if (key === 'oauth2.oauth21' || key === 'oauth2.fapi') {
      return key === 'oauth2.fapi' ? '' : false;
    }
    return real.apply(this, arguments);
  };
  const keys = [];
  for (let i = 0; i < 16; i++) {
    keys.push([8, 4, 2, 1].map(function (bit) {
      return (i & bit) ? '1' : '0';
    }).join('|'));
  }
  const evaluated = function (field) {
    if (typeof field !== 'function') {
      return field === undefined ? null : field;
    }
    const out = {};
    keys.forEach(function (key) {
      key.split('|').forEach(function (bit, n) {
        forced[REPORT_INPUTS[n]] = bit === '1';
      });
      out[key] = field();
    });
    return { computed: out };
  };
  // `what_it_means`, which says whether the mode is on and, for RFC 9700,
  // which scheme the port answers on.
  const meaning = function (stateOf, flag, withTls) {
    const out = {};
    [true, false].forEach(function (on) {
      (withTls && on ? [true, false] : [true]).forEach(function (tls) {
        forced[flag] = on;
        forced['global.https'] = tls;
        out[on ? (withTls ? 'on|' + (tls ? '1' : '0') : 'on') : 'off'] =
          stateOf().what_it_means;
      });
    });
    delete forced[flag];
    delete forced['global.https'];
    return out;
  };
  try {
    const rfc9700 = bcp.state();
    const draft = oauth21.state();
    const bcpMeaning = meaning(bcp.state, 'oauth2.rfc9700', true);
    const draftMeaning = meaning(oauth21.state, 'oauth2.oauth21', false);
    return JSON.parse(JSON.stringify({
      inputs: REPORT_INPUTS,
      rfc9700: {
        rfc: rfc9700.rfc, url: rfc9700.url, scope: rfc9700.scope,
        what_it_means: bcpMeaning,
        requirements: bcp.REQUIREMENTS.map(function (row) {
          return { id: row.id, section: 'RFC 9700 ' + row.section,
                   level: row.level, applies_to: row.appliesTo,
                   title: row.title, enforced: evaluated(row.enforced),
                   note: evaluated(row.note) };
        })
      },
      oauth21: {
        specification: draft.specification, draft: draft.draft,
        url: draft.url, status: draft.status, implies: draft.implies,
        what_it_means: draftMeaning,
        exemptions: draft.exemptions,
        requirements: draft.requirements
      },
      sender_constraints_note: rfc9700.sender_constraints.note
    }));
  } finally {
    config.value = real;
  }
}

const EXPORTS = [
  { file: 'oauth_reports.json', dir: OAUTH_DATA, build: oauthReports },
  { file: 'mail_templates.json', dir: MAIL_DATA, build: mailTemplates },
  { file: 'audit_vocabulary.json', dir: AUDIT_DATA, build: auditVocabulary },
  { file: 'error_codes.json', build: errorCodes },
  { file: 'settings.json', build: settings },
  { file: 'mode.json', build: modeTable },
  { file: 'algorithm_registry.json', dir: CRYPTO_DATA,
    build: algorithmRegistry }
];

// THE APPCONFIG LAYERS (#444, rust/DESIGN.md section 8): `env/*.js` are data,
// and the Rust runtime reads them as `env/*.json`, which are exported here
// beside the tables and checked the same way. `defaults.js` is not among
// them: it is the settings table's `dflt` column, which the runtime compiles
// in from settings.json.
const APPCONFIG = ['local', 'test', 'docker-tests'];

function appconfig(name) {
  return function () {
    const file = path.join(ROOT, 'env', name + '.js');
    delete require.cache[require.resolve(file)];
    return require(file);
  };
}

// The text each export should hold.
function rendered() {
  return EXPORTS.map(function (one) {
    return { file: path.join(one.dir || DATA, one.file),
             text: JSON.stringify(one.build(), null, 1) + '\n' };
  }).concat(APPCONFIG.map(function (name) {
    return { file: path.join(ROOT, 'env', name + '.json'),
             text: JSON.stringify(appconfig(name)(), null, 2) + '\n' };
  }));
}

// The exports whose committed file differs from what the table says.
function stale() {
  return rendered().filter(function (one) {
    let current = null;
    try {
      current = fs.readFileSync(one.file, 'utf8');
    } catch (error) {
      // A missing export is a stale one; the caller names the file.
      current = null;
    }
    return current !== one.text;
  }).map(function (one) {
    return path.relative(ROOT, one.file);
  });
}

if (require.main === module) {
  if (process.argv.indexOf('--check') >= 0) {
    const out = stale();
    if (out.length) {
      console.error('stale: ' + out.join(', ') +
                    ' — run node tests/tools/export-rust-tables.js');
      process.exit(1);
    }
    console.log('the Rust tables are current');
  } else {
    fs.mkdirSync(DATA, { recursive: true });
    fs.mkdirSync(CRYPTO_DATA, { recursive: true });
    fs.mkdirSync(OAUTH_DATA, { recursive: true });
    // A file under env/ is written only where its directory exists.
    rendered().forEach(function (one) {
      fs.writeFileSync(one.file, one.text);
      console.log('wrote ' + path.relative(ROOT, one.file));
    });
  }
}

module.exports = { stale: stale, rendered: rendered };
