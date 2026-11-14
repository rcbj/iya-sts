// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_schemas.ts
//
// ---------------------------------------------------------------------------
// THE JSON SCHEMAS OF EVERY DOCUMENT A GNAP CLIENT OR RESOURCE SERVER SENDS,
// COMPILED WITH AJV AND ENFORCED BEFORE A HANDLER READS A MEMBER.
//
// The user asked (2026-09-12) that the GNAP endpoints do input sanitisation and
// JSON Schema validation. Each document now passes through THREE layers, and
// each layer adds checks the others do not make — the rule the 2026-09-06
// input-validation sweep settled on ("the validator adds the checks nothing
// else makes; it never duplicates a check the handler already makes better"):
//
//   1. `validation.checkDocument()` — the service-wide SANITISATION of any JSON
//      body: bounded depth, bounded key count, and no prototype-polluting
//      member names (`__proto__`, `constructor`, `prototype`) at any depth.
//   2. **these schemas** — the SHAPE, which since #1579 is the MODEL's
//      (`models/gnap/gnap.tsp`, rendered by `models/lib/gnap_lib.mjs`): every
//      known member's JSON type, a length cap on every string, an item cap on
//      every array and a member cap on every object, URI formats where RFC
//      9635 says "absolute URI", and NO control characters in any string.
//      That last one is sanitisation too: a label, a class_id or a display
//      name is echoed onto the approval page, the audit log and the console,
//      and a C0 control character in it is never meaningful.
//   3. `gnap_request.ts`'s walk — the SEMANTICS, refused with the GNAP error
//      code the specification names: a flag twice is `invalid_flag`, a missing
//      label in a multi-token request is `invalid_request`, a key in two
//      formats is `invalid_client`.
//
// Why `required` and enumerations are not in the schemas, and which objects
// are open, is argued in the model's header, beside the declarations it is
// about. This module compiles what the model rendered and names the most
// useful error.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapSchemas` takes the logger and the schemas compiled at load
// through its constructor. The tables are read from the model and compiled
// at require time, for the reason given above `COMPILED`. The module still
// exports `SCHEMAS` and `validate` as FACADES forwarding to the instance the
// composition root builds (#50, R2), for `gnap_request.ts`. A process that loads this module without
// the root builds a default instance when the module loads.
// ---------------------------------------------------------------------------

// `any` for the type checker (#50): CommonJS modules whose declared types are
// ES default exports.
import Ajv2020Module = require('ajv/dist/2020');
import addFormatsModule = require('ajv-formats');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import GnapModel = require('./gnap_model');

const Ajv2020: any = Ajv2020Module;
const addFormats: any = addFormatsModule;

// THE SCHEMAS ARE THE MODEL'S (#1579): `models/gnap/gnap.tsp` renders each
// document, its shared types as `$defs`, and `gnap_model.ts` puts
// `common/validation.js`'s caps in. Until #1579 they were written here by
// hand, and the rendered ones are byte for byte what was written.
const SCHEMAS: Record<string, any> = GnapModel.schemas();

// A string with no C0 control character and no DEL: the model's pattern for
// every string that states none.
const SAFE = GnapModel.SAFE;

// Compiled ONCE, at require time, so a schema that does not compile fails the
// service loudly at start rather than the first request that needs it.
const ajv = new Ajv2020({ strict: true, allErrors: false, coerceTypes: false,
                          allowUnionTypes: true });
addFormats(ajv);
const COMPILED: Record<string, any> = {};
Object.keys(SCHEMAS).forEach(function (name) {
  COMPILED[name] = ajv.compile(SCHEMAS[name]);
});

// What `validate()` answers.
interface Verdict {
  ok: boolean;
  path?: string;
  detail?: string;
}

interface GnapSchemasDeps {
  log: { debug(message: string): void };
  // name -> an ajv validate function, compiled at load.
  compiled: Record<string, any>;
  schemas: Record<string, any>;
}

/**
 * The JSON Schemas of every document a GNAP client or resource server sends,
 * compiled with ajv and enforced before a handler reads a member.
 *
 * The shape layer, between the service-wide sanitisation and the handler's own
 * checks.
 */
class GnapSchemas {
  /**
   * The schema table, by document name (`grantRequest` and the rest).
   */
  static readonly SCHEMAS = SCHEMAS;
  /**
   * The pattern every string must match: no C0 control character and no DEL.
   */
  static readonly SAFE = SAFE;

  /**
   * Builds the validator from the compiled tables and the modules it reads.
   *
   * @param deps - the modules and compiled schemas the composition root passes
   */
  constructor(private readonly deps: GnapSchemasDeps) {
    deps.log.debug("Entering GnapSchemas.constructor().");
    deps.log.debug("Leaving GnapSchemas.constructor().");
  }

  // `{ ok: true }` or `{ ok: false, path, detail }`. The detail names the
  // member by its JSON Pointer, because the client developer's first question
  // is which one.
  /**
   * Validates a document against a named schema.
   *
   * @param name - the schema's name in `SCHEMAS`
   * @param document - the parsed JSON document
   * @returns `{ ok: true }`, or `{ ok: false, path, detail }` with the member
   *   named by its JSON Pointer
   */
  validate(name: string, document: unknown): Verdict {
    const { log, compiled, schemas } = this.deps;
    log.debug("Entering GnapSchemas.validate(). schema=" + name);
    const check = compiled[name];
    if (!check) {
      log.debug("Leaving GnapSchemas.validate(). No such schema.");
      return { ok: false, path: '',
               detail: 'there is no schema called ' + name };
    }
    if (check(document)) {
      log.debug("Leaving GnapSchemas.validate(). Valid.");
      return { ok: true };
    }
    // THE MOST USEFUL ERROR, NOT THE FIRST. ajv reports every branch of an
    // `anyOf` it tried, so a control character inside an object member
    // arrives behind "must be string" from the string branch of the same
    // union — true and useless. A control character is named whenever one
    // was found, and otherwise the error at the deepest path is the one
    // nearest the mistake.
    const errors: any[] = check.errors || [];
    const control = errors.filter(function (one) {
      return one.keyword === 'pattern' && one.params &&
             one.params.pattern === SAFE;
    })[0];
    const first = control || errors.slice().sort(function (a, b) {
      return String(b.instancePath || '').length -
             String(a.instancePath || '').length;
    })[0] || {};
    const path = first.instancePath || '(the document)';
    let detail: string;
    if (first.keyword === 'pattern' &&
        String(first.schemaPath || '').indexOf('pattern') >= 0 &&
        first.params && first.params.pattern === SAFE) {
      detail = path + ' contains a control character, which no member of ' +
                      'a GNAP document may carry';
    } else {
      detail = path + ' ' + (first.message || 'is not valid');
    }
    log.debug("Leaving GnapSchemas.validate(). " + detail);
    return { ok: false, path: path,
             detail: detail + ' (JSON Schema ' + schemas[name].$id + ')' };
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before. The tables are the ones
  // compiled at load.
  /**
   * Returns the real modules and the tables compiled at load, as the instance
   * was built from before the composition root (#50, R2).
   *
   * @returns the default dependencies
   */
  static defaultDeps(): GnapSchemasDeps {
    helpers.log.debug("Entering GnapSchemas.defaultDeps().");
    helpers.log.debug("Leaving GnapSchemas.defaultDeps().");
    return {
      log: helpers.log,
      compiled: COMPILED,
      schemas: SCHEMAS
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapSchemas>(
  'gnap/gnap_schemas',
  () => new GnapSchemas(GnapSchemas.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The JSON Schemas of every document a GNAP client or resource server sends,
 * compiled with ajv.
 *
 * @namespace
 */
export = {
  GnapSchemas: GnapSchemas,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: GnapSchemas): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  SCHEMAS: GnapSchemas.SCHEMAS,
  validate: slot.forward('validate')
};
