// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/tools/generate_pep.mjs
//
// ---------------------------------------------------------------------------
// WRITES, OR CHECKS, WHAT THE REMOTE PEP'S MODEL GENERATES (#1830).
//
//   node models/tools/generate_pep.mjs           write the files
//   node models/tools/generate_pep.mjs --check   say which differ; exit 1
//
// It compiles `models/pep/main.tsp` — a separate entry point from
// `models/main.tsp`, because the PEP is a container of its own and none of
// its documents is served, validated or typed by the Node service — and
// writes, under the repository root:
//
//   xacml-pep/openapi/<document>.json       one OpenAPI 3.1 document per
//                                           surface, two-space JSON
//   rust/crates/sts-model-pep/src/generated/<document>.rs, unions.rs
//                                           the data types (`pep_lib.mjs`)
//
// UNLIKE `generate.mjs` THESE FILES ARE COMMITTED: the Rust crate is built
// by `cargo` from a checkout and by the PEP's image from `rust/`, neither of
// which runs the TypeSpec compiler, and the documents are what a PEP's
// operator and a client's author read. `tests/model_pep.js` runs `--check`
// in the tests image and fails when a committed file is not what the model
// makes; `tests/tools/regenerate-pep-model.sh` writes them from there.
//
// The compiler is a dependency of `tests/` only (`models/CLAUDE.md`), so it
// is looked for under `tests/node_modules` first and the root's second.
// ---------------------------------------------------------------------------

import fs from 'fs';
import path from 'path';
import url from 'url';
import bunyan from 'bunyan';
import { documents } from '../lib/api_lib.mjs';
import { documentFile, documentText, renderPepRust }
  from '../lib/pep_lib.mjs';

const log = bunyan.createLogger({
  name: 'sts-generate-pep',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const ROOT = path.join(path.dirname(url.fileURLToPath(import.meta.url)),
  '..', '..');

const OPENAPI_DIR = path.join(ROOT, 'xacml-pep', 'openapi');

const RUST_DIR = path.join(ROOT, 'rust', 'crates', 'sts-model-pep', 'src',
  'generated');

/**
 * The TypeSpec compiler's entry module.
 *
 * @returns its file URL
 */
function compilerUrl() {
  log.debug("Entering compilerUrl().");
  const tail = path.join('node_modules', '@typespec', 'compiler', 'dist',
    'src', 'index.js');
  const found = [path.join(ROOT, 'tests', tail), path.join(ROOT, tail)]
    .find(function (one) {
      return fs.existsSync(one);
    });
  if (!found) {
    log.debug("Leaving compilerUrl(). Not installed.");
    throw new Error('The TypeSpec compiler is not installed under tests/ ' +
      'or the root; run this in the tests image ' +
      '(tests/tools/regenerate-pep-model.sh).');
  }
  log.debug("Leaving compilerUrl().");
  return url.pathToFileURL(found).href;
}

/**
 * Compiles the PEP's model and renders every file it generates.
 *
 * @returns every file's text, by its absolute path
 */
export async function render() {
  log.debug("Entering render().");
  const compiler = await import(compilerUrl());
  const program = await compiler.compile(compiler.NodeHost,
    path.join(ROOT, 'models', 'pep', 'main.tsp'), { noEmit: true });
  const errors = program.diagnostics.filter(function (one) {
    return one.severity === 'error';
  });
  if (errors.length > 0) {
    log.debug("Leaving render(). The model did not compile.");
    throw new Error('The PEP model does not compile: ' +
      errors.map(function (one) {
        return one.code + ': ' + one.message;
      }).join('; '));
  }
  const served = documents(program);
  if (Object.keys(served).length === 0) {
    log.debug("Leaving render(). No document.");
    throw new Error('The PEP model declares no @apiDocument.');
  }
  const out = {};
  Object.keys(served).sort().forEach(function (name) {
    out[path.join(OPENAPI_DIR, documentFile(name))] =
      documentText(served[name]);
  });
  const rust = renderPepRust(served);
  Object.keys(rust.files).forEach(function (file) {
    out[path.join(RUST_DIR, file)] = rust.files[file];
  });
  log.debug("Leaving render(). " + Object.keys(out).length + " file(s).");
  return out;
}

/**
 * The generated files that are not what the model makes, and the stale ones
 * in the two directories that it no longer makes.
 *
 * @param rendered - from `render()`
 * @returns paths relative to the root
 */
export function differences(rendered) {
  log.debug("Entering differences().");
  const wrong = [];
  Object.keys(rendered).forEach(function (file) {
    const committed = fs.existsSync(file) ?
      fs.readFileSync(file, 'utf8') : null;
    if (committed !== rendered[file]) {
      wrong.push(path.relative(ROOT, file));
    }
  });
  // THE CRATE'S ROOT IS WRITTEN BY HAND (its `double_option`, its notes) and
  // includes each module by name, so a document the model adds is a line
  // there too, or its file would be written and never compiled.
  const root = path.join(RUST_DIR, '..', 'lib.rs');
  const text = fs.existsSync(root) ? fs.readFileSync(root, 'utf8') : '';
  Object.keys(rendered).filter(function (file) {
    return path.dirname(file) === RUST_DIR;
  }).forEach(function (file) {
    const line = 'include!("generated/' + path.basename(file) + '");';
    if (text.indexOf(line) < 0) {
      wrong.push(path.relative(ROOT, root) + ' (no ' + line + ')');
    }
  });
  [OPENAPI_DIR, RUST_DIR].forEach(function (dir) {
    if (!fs.existsSync(dir)) {
      return;
    }
    fs.readdirSync(dir).forEach(function (one) {
      const file = path.join(dir, one);
      if (rendered[file] === undefined) {
        wrong.push(path.relative(ROOT, file) + ' (no longer generated)');
      }
    });
  });
  log.debug("Leaving differences(). " + wrong.length);
  return wrong;
}

/**
 * Writes every generated file, and removes the ones no longer generated.
 *
 * @param rendered - from `render()`
 * @returns how many were written
 */
function write(rendered) {
  log.debug("Entering write().");
  [OPENAPI_DIR, RUST_DIR].forEach(function (dir) {
    fs.mkdirSync(dir, { recursive: true });
    fs.readdirSync(dir).forEach(function (one) {
      const file = path.join(dir, one);
      if (rendered[file] === undefined) {
        fs.unlinkSync(file);
      }
    });
  });
  Object.keys(rendered).forEach(function (file) {
    fs.writeFileSync(file, rendered[file]);
  });
  log.debug("Leaving write().");
  return Object.keys(rendered).length;
}

const invoked = process.argv[1] &&
  path.resolve(process.argv[1]) === url.fileURLToPath(import.meta.url);

if (invoked) {
  try {
    const rendered = await render();
    if (process.argv.indexOf('--check') >= 0) {
      const wrong = differences(rendered);
      if (wrong.length > 0) {
        console.error('Not what models/pep/ makes; run ' +
          'tests/tools/regenerate-pep-model.sh:\n  ' + wrong.join('\n  '));
        process.exit(1);
      }
      log.info('Every file the PEP model generates is current.');
    } else {
      log.info('Wrote ' + write(rendered) + ' file(s) from models/pep/.');
    }
  } catch (e) {
    log.debug("Caught in generate_pep.mjs: " + ((e && e.message) || e));
    console.error((e && e.message) || e);
    process.exit(1);
  }
}
