// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/lib/pep_lib.mjs
//
// ---------------------------------------------------------------------------
// THE REMOTE PEP'S MODEL WRITTEN OUT (#1830): ITS OPENAPI DOCUMENTS AND ITS
// RUST DATA TYPES.
//
// `models/pep/` is the source of every HTTP surface the remote PEP
// (`rust/bins/xacml-pep`) serves or calls, each an `@apiDocument` written
// with the API namespace's decorators (`api_lib.tsp`), so `documents()` turns
// it back into OpenAPI exactly as it does the five published APIs. The
// reverse proxy's configured routes are not in it: configuration decides
// them, and only the paths the proxy owns whatever it is configured with are.
//
// THE RUST IS `rust_lib.mjs`'s, READ AGAIN FOR ONE CRATE. That renderer (the
// Rust conversion's, #444 D15) writes a crate per document and a shared
// `sts-model-base` for the unions and `double_option`. The PEP is a container
// of its own, built from `rust/` with `-p xacml-pep`, and must not depend on
// the runtime's model crates, so `renderPepRust()` folds what it writes into
// ONE crate, `sts-model-pep`: a module per document, and the unions and
// `double_option` at the crate root. The types themselves are the
// renderer's, unchanged — the same rules for optional, nullable, closed and
// open objects, enums and unions — so a PEP type and a runtime type read a
// member the same way.
//
// `rust_lib.mjs` is a byte-for-byte copy of feature/444's (c89dc552c), so the
// branch that lands second takes either side of an add/add with no change.
// ---------------------------------------------------------------------------

import bunyan from 'bunyan';
import { renderRustApi } from './rust_lib.mjs';

const log = bunyan.createLogger({
  name: 'sts-pep-lib',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

// What `rust_lib.mjs` puts at the top of every file it writes — its notice
// and its comments, every line before the first item — which a folded module
// does not repeat: the module has a notice of its own.
const STRIPPED = /^(\/\/.*)?$/;

const HEADER = ['// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, ' +
  'LLC', '// SPDX-License-Identifier: BUSL-1.1', '//',
'// GENERATED from models/pep/ (#1830) by models/lib/pep_lib.mjs, through',
'// models/lib/rust_lib.mjs (#444, D15). Do not edit: change the model and',
'// run tests/tools/regenerate-pep-model.sh. tests/model_pep.js fails when',
'// this differs.', ''];

/**
 * A document's name as a Rust module, as `rust_lib.mjs` names its crate
 * (`sts-model-<kebab>`) and its `sts-model` alias (`<snake>`).
 *
 * @param name - the document's `x-iya-doc`
 * @returns `{ crate, module }`
 */
function namesOf(name) {
  log.debug("Entering namesOf().");
  const words = name.replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/).filter(Boolean).map(function (word) {
      return word.toLowerCase();
    });
  log.debug("Leaving namesOf().");
  return { crate: 'sts-model-' + words.join('-'), module: words.join('_') };
}

/**
 * The lines of one generated crate's api.rs, as a module of the one crate.
 *
 * @param text - the api.rs `rust_lib.mjs` wrote
 * @param module - the module it becomes
 * @returns the text of `src/generated/<module>.rs`
 */
function folded(text, module) {
  log.debug("Entering folded(). " + module);
  const lines = text.split('\n');
  while (lines.length > 0 && STRIPPED.test(lines[0])) {
    lines.shift();
  }
  const body = lines.join('\n')
    .split('crate::components::').join('crate::' + module + '::components::')
    .split('sts_model_base::').join('crate::');
  log.debug("Leaving folded().");
  return HEADER.join('\n') + '\n' + body.replace(/\n*$/, '\n');
}

/**
 * Every PEP document's types, folded into `sts-model-pep`.
 *
 * @param served - the documents, by `x-iya-doc`
 * @returns `{ files, modules }`: each file's text by its path under the
 *   crate's `src/generated/`, and each document's module with its title
 */
export function renderPepRust(served) {
  log.debug("Entering renderPepRust().");
  const rendered = renderRustApi(served);
  const files = {};
  const modules = [];
  Object.keys(served).sort().forEach(function (name) {
    const names = namesOf(name);
    const text = rendered.files[names.crate + '/src/generated/api.rs'];
    if (text === undefined) {
      log.debug("Leaving renderPepRust(). No crate for " + name + ".");
      throw new Error('rust_lib.mjs wrote no crate for the ' + name +
        ' document; a PEP document must not be one it splits.');
    }
    files[names.module + '.rs'] = folded(text, names.module);
    modules.push({ module: names.module,
      title: (served[name].info && served[name].info.title) || name });
  });
  const unions = rendered.files['sts-model-base/src/generated/unions.rs'] ||
    '';
  files['unions.rs'] = folded(unions, 'unions');
  log.debug("Leaving renderPepRust(). " + modules.length + " module(s).");
  return { files: files, modules: modules };
}

/**
 * An OpenAPI document as the committed file holds it: two-space JSON and a
 * final newline, so a change to the model is a readable diff.
 *
 * @param document - the document
 * @returns the text
 */
export function documentText(document) {
  log.debug("Entering documentText().");
  log.debug("Leaving documentText().");
  return JSON.stringify(document, null, 2) + '\n';
}

/**
 * The committed file name of a document: its `x-iya-doc` in kebab case.
 *
 * @param name - the document's `x-iya-doc`
 * @returns e.g. `pep-service.json`
 */
export function documentFile(name) {
  log.debug("Entering documentFile().");
  log.debug("Leaving documentFile().");
  return namesOf(name).module.split('_').join('-') + '.json';
}

/**
 * A Rust string literal of plain ASCII text, as the obligation rules are.
 *
 * @param text - the text
 * @returns the literal
 */
function rustString(text) {
  log.debug("Entering rustString().");
  if (!/^[\x20-\x7e]*$/.test(text) || /["\\]/.test(text)) {
    log.debug("Leaving rustString(). Not plain.");
    throw new Error('An obligation rule name is not plain ASCII: ' +
      JSON.stringify(text));
  }
  log.debug("Leaving rustString().");
  return '"' + text + '"';
}

/**
 * THE OBLIGATIONS PROFILE'S REGISTERED TYPES AS THE EDGE PDP READS THEM
 * (#1205, #1390): `authzen_obligations.rs`, from the member sets of
 * `models/authzen/authzen_members.tsp` marked `obligation: true` — the same
 * sets `authzen/authzen_model.ts`'s `obligationTypes()` reads for the
 * service — so the two cannot be copies that drift. A required member is
 * what a registered obligation may not be handed without; an array member
 * collects every assignment of its name.
 *
 * @param authzen - what `readAuthzen()` read from the AuthZEN model
 * @returns the file's text
 */
export function renderObligationRules(authzen) {
  log.debug("Entering renderObligationRules().");
  const sets = (authzen.members || []).filter(function (set) {
    return set.obligation === true;
  });
  if (!sets.length) {
    log.debug("Leaving renderObligationRules(). None.");
    throw new Error('The AuthZEN model marks no member set obligation: ' +
      'true.');
  }
  const list = function (names) {
    log.debug("Entering list().");
    log.debug("Leaving list().");
    return '&[' + names.map(rustString).join(', ') + ']';
  };
  const lines = HEADER.slice(0, 3).concat([
    '// GENERATED from models/authzen/authzen_members.tsp (#1205) by',
    '// models/lib/pep_lib.mjs: the Obligations Profile\'s registered types,',
    '// the member sets marked `obligation: true`, in the model\'s order. Do',
    '// not edit: change the model and run tests/tools/regenerate-pep-model.sh.',
    '// tests/model_pep.js fails when this differs.', '',
    '/// One registered type: the properties it may not be handed without,',
    '/// and those that collect every assignment of their name.',
    '#[derive(Debug, Clone, Copy, PartialEq, Eq)]',
    'pub struct ObligationRule {',
    '    pub name: &\'static str,',
    '    pub required: &\'static [&\'static str],',
    '    pub arrays: &\'static [&\'static str],',
    '}', '',
    '/// Every registered type, in the model\'s order.',
    'pub const OBLIGATION_RULES: &[ObligationRule] = &['
  ]);
  sets.forEach(function (set) {
    const required = set.list.filter(function (one) {
      return one.required;
    }).map(function (one) {
      return one.name;
    });
    const arrays = set.list.filter(function (one) {
      return one.types.indexOf('array') >= 0;
    }).map(function (one) {
      return one.name;
    });
    lines.push('    ObligationRule {');
    lines.push('        name: ' + rustString(set.id) + ',');
    lines.push('        required: ' + list(required) + ',');
    lines.push('        arrays: ' + list(arrays) + ',');
    lines.push('    },');
  });
  lines.push('];', '');
  lines.push('/// What the metadata advertises while the profile is on: every ' +
             'registered');
  lines.push('/// type, then `custom`, which is every other obligation.');
  lines.push('pub const SUPPORTED_OBLIGATION_TYPES: &[&str] = ' +
             list(sets.map(function (set) {
               return set.id;
             }).concat(['custom'])) + ';');
  lines.push('');
  log.debug("Leaving renderObligationRules(). " + sets.length + " type(s).");
  return lines.join('\n');
}
