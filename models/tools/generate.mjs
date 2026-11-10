#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/tools/generate.mjs
//
// ---------------------------------------------------------------------------
// WRITES WHAT THE SERVICE READS FROM THE MODEL (#1390).
//
// Compiles `models/main.tsp` and writes `models/generated/<id>.schema.json`
// for each directory object written by hand (`authored`). Run by
// `build-typescript.sh` inside an image build only, for the reason that
// script gives: nothing generated is written to the host. A model that does
// not compile fails the build.
// ---------------------------------------------------------------------------

import fs from 'fs';
import path from 'path';
import url from 'url';
import bunyan from 'bunyan';
import { documents, everyOperation, projections, renderApiTypes }
  from '../lib/api_lib.mjs';
import { checkDomains, readDomains, renderClasses, renderTypes }
  from '../lib/domain_lib.mjs';
import { checkScim, readScim } from '../lib/scim_lib.mjs';
import { checkOAuth, readOAuth } from '../lib/oauth_lib.mjs';
import { checkGnap, readGnap } from '../lib/gnap_lib.mjs';
import { checkAuthzen, readAuthzen } from '../lib/authzen_lib.mjs';
import { checkSsf, readSsf } from '../lib/ssf_lib.mjs';
import { checkFacts, factsOf, fieldsOf, linksIn, readDirectory, readPersistence,
  readSpellings, renderScript, schemaOf } from '../lib/model_lib.mjs';

const log = bunyan.createLogger({
  name: 'sts-model-generate',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const ROOT = path.join(path.dirname(url.fileURLToPath(import.meta.url)),
  '..', '..');

/**
 * Compiles the model and writes each authored object's table.
 *
 * @returns how many files were written
 */
async function generate() {
  log.debug("Entering generate().");
  const compiler = await import(url.pathToFileURL(path.join(ROOT, 'tests',
    'node_modules', '@typespec', 'compiler', 'dist', 'src', 'index.js')).href);
  const program = await compiler.compile(compiler.NodeHost,
    path.join(ROOT, 'models', 'main.tsp'), { noEmit: true });
  const errors = program.diagnostics.filter(function (one) {
    return one.severity === 'error';
  });
  if (errors.length > 0) {
    log.debug("Leaving generate(). The model did not compile.");
    throw new Error('The model does not compile: ' +
      errors.map(function (one) {
        return one.code + ': ' + one.message;
      }).join('; '));
  }
  const out = path.join(ROOT, 'models', 'generated');
  fs.mkdirSync(out, { recursive: true });
  const objects = readDirectory(program);
  const authored = objects.filter(function (object) {
    return object.authored === true;
  });
  const wrong = checkFacts(objects);
  if (wrong.length > 0) {
    log.debug("Leaving generate(). An entry's facts are wrong.");
    throw new Error('The directory model is wrong: ' + wrong.join('; '));
  }
  const names = readSpellings(program);
  if (!names) {
    log.debug("Leaving generate(). No name lists.");
    throw new Error('The model does not declare the directory\'s name lists.');
  }
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'directory.names.json'),
    JSON.stringify(names));
  fs.writeFileSync(path.join(out, 'directory.facts.json'),
    JSON.stringify(factsOf(objects)));
  fs.writeFileSync(path.join(out, 'directory.links.json'),
    JSON.stringify(linksIn(objects)));
  const concepts = readDomains(program);
  const problems = checkDomains(concepts, objects, names.secret);
  if (problems.length > 0) {
    log.debug("Leaving generate(). A domain model is wrong.");
    throw new Error('The domain models are wrong: ' + problems.join('; '));
  }
  fs.writeFileSync(path.join(out, 'domain.json'),
    JSON.stringify({ concepts: concepts }));
  fs.writeFileSync(path.join(out, 'domain.d.ts'), renderTypes(concepts));
  fs.writeFileSync(path.join(out, 'domain_classes.txt'),
    renderClasses(concepts));
  const scim = readScim(program);
  const scimProblems = checkScim(scim, objects);
  if (scimProblems.length > 0) {
    log.debug("Leaving generate(). The SCIM model is wrong.");
    throw new Error('The SCIM model is wrong: ' + scimProblems.join('; '));
  }
  fs.writeFileSync(path.join(out, 'scim.json'), JSON.stringify(scim));
  const oauth = readOAuth(program);
  const oauthProblems = checkOAuth(oauth);
  if (oauthProblems.length > 0) {
    log.debug("Leaving generate(). The OAuth model is wrong.");
    throw new Error('The OAuth model is wrong: ' + oauthProblems.join('; '));
  }
  fs.writeFileSync(path.join(out, 'oauth.json'), JSON.stringify(oauth));
  const gnap = readGnap(program);
  const gnapProblems = checkGnap(gnap);
  if (gnapProblems.length > 0) {
    log.debug("Leaving generate(). The GNAP model is wrong.");
    throw new Error('The GNAP model is wrong: ' + gnapProblems.join('; '));
  }
  delete gnap.problems;
  fs.writeFileSync(path.join(out, 'gnap.json'), JSON.stringify(gnap));
  const authzen = readAuthzen(program);
  const authzenProblems = checkAuthzen(authzen);
  if (authzenProblems.length > 0) {
    log.debug("Leaving generate(). The AuthZEN model is wrong.");
    throw new Error('The AuthZEN model is wrong: ' +
                    authzenProblems.join('; '));
  }
  fs.writeFileSync(path.join(out, 'authzen.json'), JSON.stringify(authzen));
  const ssf = readSsf(program);
  const ssfProblems = checkSsf(ssf);
  if (ssfProblems.length > 0) {
    log.debug("Leaving generate(). The Shared Signals model is wrong.");
    throw new Error('The Shared Signals model is wrong: ' +
                    ssfProblems.join('; '));
  }
  fs.writeFileSync(path.join(out, 'ssf.json'), JSON.stringify(ssf));
  const persistence = readPersistence(program);
  fs.writeFileSync(path.join(out, 'persistence.postgres.json'),
    JSON.stringify({ objects: persistence.objects,
      added: persistence.added }));
  fs.writeFileSync(path.join(out, 'schema.sql'), renderScript(
    fs.readFileSync(path.join(ROOT, 'models', 'persistence',
      'schema.template.sql'), 'utf8'), persistence));
  const served = documents(program);
  Object.keys(served).forEach(function (name) {
    fs.writeFileSync(path.join(out, 'openapi.' + name + '.json'),
      JSON.stringify(served[name]));
  });
  fs.writeFileSync(path.join(out, 'api.d.ts'), renderApiTypes(served));
  const projected = projections(program);
  const conceptNames = new Set(concepts.map(function (one) {
    return one.name;
  }));
  const strays = projected.filter(function (one) {
    return !conceptNames.has(one.concept);
  });
  if (strays.length > 0) {
    log.debug("Leaving generate(). A projection names no concept.");
    throw new Error('No such concept: ' + strays.map(function (one) {
      return one.name + ' projects ' + one.concept;
    }).join('; '));
  }
  // What a shape holds is read from its published schema: a shape written as
  // raw JSON Schema has no TypeSpec properties to count.
  projected.forEach(function (one) {
    Object.keys(served).forEach(function (name) {
      const schemas = (served[name].components || {}).schemas || {};
      if (schemas[one.name] && schemas[one.name].properties) {
        one.fields = Object.keys(schemas[one.name].properties);
      }
    });
  });
  fs.writeFileSync(path.join(out, 'api.projections.json'),
    JSON.stringify(projected));
  fs.writeFileSync(path.join(out, 'openapi.every.json'),
    JSON.stringify(everyOperation(program)));
  const mariadb = readPersistence(program, 'mariadb');
  fs.writeFileSync(path.join(out, 'persistence.mariadb.json'),
    JSON.stringify({ objects: mariadb.objects }));
  fs.writeFileSync(path.join(out, 'mariadb.schema.sql'), renderScript(
    fs.readFileSync(path.join(ROOT, 'models', 'persistence',
      'mariadb.template.sql'), 'utf8'), mariadb));
  if (authored.length === 0) {
    log.debug("Leaving generate(). Nothing to write.");
    throw new Error('The model has no object written by hand, so the ' +
      'service would have no table to read.');
  }
  authored.forEach(function (object) {
    fs.writeFileSync(path.join(out, object.id + '.schema.json'),
      JSON.stringify(schemaOf(object)));
    const declared = fieldsOf(object);
    if (declared.fields.length > 0 || declared.selectors.length > 0) {
      fs.writeFileSync(path.join(out, object.id + '.fields.json'),
        JSON.stringify(declared));
    }
  });
  log.debug("Leaving generate().");
  return authored.length;
}

try {
  const written = await generate();
  log.info('Wrote ' + written + ' table(s) from the model.');
} catch (e) {
  log.debug("Caught in generate.mjs: " + ((e && e.message) || e));
  console.error((e && e.message) || e);
  process.exit(1);
}
