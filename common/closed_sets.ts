'use strict';
//
// File: closed_sets.ts
//
// ---------------------------------------------------------------------------
// THE CLOSED SETS AN ADMINISTRATOR'S INPUT IS HELD TO (#86, 2026-09-26).
//
// Numerous fields on the console and on `/admin-api` accept only a fixed set
// of strings — a key algorithm, a delivery method, a role, a target kind —
// and until #86 nothing refused any other value. The management API's
// validator compiled the OpenAPI request schemas with `enum` STRIPPED
// (`AdminApi.structureOnly()`), its query parameters were never checked
// against the enums they declare, and the console's forms never reached that
// validator at all. A value outside the set was then, depending on the
// handler, refused in its own words, silently ignored, silently replaced by
// a default, or stored.
//
// **THE SET IS DECLARED ONCE, AS AN `enum` IN THE OPENAPI DOCUMENT**, which
// is where `mgmt-api/admin_api.ts` already wrote most of them and where a
// caller reads them. This file does not hold a second copy. It holds what
// three doors need to enforce that one declaration:
//
//   * `collect(schema, components)` — every enum a request schema declares,
//     as a path of property names (`*` for an array's items) and its values,
//     following `$ref` into the document's components. `/admin-api` compiles
//     the enums into ajv directly; this is for the two doors ajv does not
//     guard.
//   * THE CONSOLE'S REGISTER. Each `/admin-api` operation names the console
//     control it is the machine's door to (`mirrors: 'POST /admin/users'`),
//     and a console form posts the same `action` the operation is named for.
//     So `admin_api.ts` registers, at wire time, the top-level enums of each
//     action under every console page its route mirrors, and the console
//     gate (`admin-ui/admin.ts`) checks a form POST against them. **A
//     REGISTER IN A LEAF, NOT A SLOT** (rule 3e): both modules require this
//     file in the ordinary direction, as they do `common/cache_registry.js`;
//     neither calls the other.
//   * `checkQuery(parameters, query)` — the enums an operation's `parameters`
//     declare `in: query`, against the query string of a request.
//
// And `sentence()`, the ONE refusal all three doors give, so a caller meets
// the same words wherever they typed the value: the field, the value, how
// many values it accepts and every one of them. It names the set rather than
// saying "must be equal to one of the allowed values", which is ajv's
// sentence and useless to somebody without the document open.
//
// Three rules, each the lesson of an earlier sweep (`common/validation.js`):
//
//   * **AN EMPTY STRING IS ABSENT** at the two form-shaped doors (the console
//     and a query string). An untouched `<select>` whose first option is
//     "(any)" submits `name=`, and refusing it would refuse the page's own
//     default. A JSON body is different — `""` there is a value somebody
//     typed — and ajv refuses it there when the set does not hold it.
//   * **CASE IS EXACT.** The enum is what the handler compares, and every
//     handler this covers compares with `===` or `indexOf()`. Where a handler
//     lower-cases first, the fix is to declare the values it accepts, not to
//     make the check forgiving: a validator that accepts what the handler
//     then refuses is two answers to one question.
//   * **ONLY WHAT IS NOT INSIDE `anyOf`/`oneOf` IS COLLECTED.** An enum in
//     one branch of an alternative is not a rule about the field — the other
//     branch may accept anything — so the console and query doors leave it
//     to the handler, and ajv, which understands alternatives, enforces it
//     on the API.
//
// A LEAF (rule 3): it requires nothing of this service but `bunyan`, so
// either door can require it without moving a route or closing a cycle.
// ---------------------------------------------------------------------------
import bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-closed-sets' });

// One declared enum: where it is in a body, and what it accepts.
interface ClosedField {
  path: string[];
  values: unknown[];
}

// A check's answer: `ok`, or which field, what it held, the set it is held
// to and the sentence to refuse it with. One shape with optional members
// rather than a union, because this tree is checked without strict null
// checks and a union on `ok` does not narrow there.
interface ClosedCheck {
  ok: boolean;
  field?: string;
  value?: unknown;
  values?: unknown[];
  sentence?: string;
}

// A query parameter as an OpenAPI operation declares it.
interface QueryParameter {
  name?: string;
  in?: string;
  schema?: any;
}

// How deep `collect()` follows a schema. The request schemas here nest two or
// three levels; the bound is for a `$ref` cycle, which a components section
// can hold legally and which would otherwise recurse for ever.
const MAX_DEPTH = 12;

class ClosedSets {
  // console page ('/admin/users') + '\u0000' + action → the enums its form
  // is held to. Process-wide, like the cache register: it describes the code,
  // not a realm.
  private static consoleFields: Map<string, ClosedField[]> = new Map();

  // The refusal sentence, shared by the three doors.
  static sentence(field: string, value: unknown, values: unknown[]): string {
    log.debug("Entering ClosedSets.sentence(). field=" + field);
    const shown = values.map(function (v) {
      return JSON.stringify(v);
    });
    log.debug("Leaving ClosedSets.sentence().");
    return '"' + field + '" is ' + JSON.stringify(value) + ', which is not ' +
           'one of the ' + values.length + ' value' +
           (values.length === 1 ? '' : 's') + ' it accepts: ' +
           shown.join(', ') + '.';
  }

  // Every enum a schema declares outside an alternative, with its path.
  static collect(schema: any, components?: any): ClosedField[] {
    log.debug("Entering ClosedSets.collect().");
    const out: ClosedField[] = [];
    ClosedSets.walk(schema, components || {}, [], out, 0);
    log.debug("Leaving ClosedSets.collect(). " + out.length + " enum(s).");
    return out;
  }

  // The recursion `collect()` runs. `anyOf`, `oneOf` and `not` are not
  // descended into, for the reason the header gives.
  private static walk(node: any, components: any, path: string[],
                      out: ClosedField[], depth: number): void {
    log.debug("Entering ClosedSets.walk(). path=" + path.join('.'));
    if (!node || typeof node !== 'object' || depth > MAX_DEPTH) {
      log.debug("Leaving ClosedSets.walk(). Nothing here.");
      return;
    }
    if (typeof node.$ref === 'string') {
      const match = /^#\/components\/schemas\/(.+)$/.exec(node.$ref);
      const target = match && components[match[1]];
      ClosedSets.walk(target, components, path, out, depth + 1);
      log.debug("Leaving ClosedSets.walk(). Followed " + node.$ref + ".");
      return;
    }
    // `x-refused-by-handler` keeps an enum in the document and out of every
    // door's check: `mgmt-api/admin_api.ts`'s REFUSED_BY_HANDLER argues it.
    if (Array.isArray(node.enum) && path.length &&
        node['x-refused-by-handler'] !== true) {
      out.push({ path: path.slice(), values: node.enum.slice() });
    }
    if (Array.isArray(node.allOf)) {
      node.allOf.forEach(function (part) {
        ClosedSets.walk(part, components, path, out, depth + 1);
      });
    }
    if (node.items && typeof node.items === 'object') {
      ClosedSets.walk(node.items, components, path.concat('*'), out,
                      depth + 1);
    }
    const props = node.properties;
    if (props && typeof props === 'object') {
      Object.keys(props).forEach(function (name) {
        ClosedSets.walk(props[name], components, path.concat(name), out,
                        depth + 1);
      });
    }
    log.debug("Leaving ClosedSets.walk().");
  }

  // Held to a set: present, not empty, and not in it. An array (a repeated
  // form field, a repeated query parameter) is each of its members.
  private static firstOutside(value: unknown,
                              values: unknown[]): { found: boolean;
                                                    value?: unknown } {
    log.debug("Entering ClosedSets.firstOutside().");
    const each = Array.isArray(value) ? value : [value];
    for (let i = 0; i < each.length; i++) {
      const one = each[i];
      if (one === undefined || one === null || one === '') {
        continue;
      }
      // A form and a query string carry strings; a declared set of numbers
      // or booleans is compared by its text there.
      const hit = values.some(function (v) {
        return v === one || String(v) === String(one);
      });
      if (!hit) {
        log.debug("Leaving ClosedSets.firstOutside(). Outside the set.");
        return { found: true, value: one };
      }
    }
    log.debug("Leaving ClosedSets.firstOutside(). Inside the set.");
    return { found: false };
  }

  // THE CONSOLE'S REGISTER. `page` is the console path a form posts to
  // ('/admin/users'); `action` the hidden `action` value it posts. Only a
  // TOP-LEVEL enum — a flat form field, or a flat field repeated — is kept,
  // because a form has no nested members to hold to anything deeper.
  static registerConsole(page: string, action: string,
                         fields: ClosedField[]): void {
    log.debug("Entering ClosedSets.registerConsole(). " + page + " " +
              action);
    const flat = fields.filter(function (f) {
      return f.path.length === 1 ||
             (f.path.length === 2 && f.path[1] === '*');
    });
    if (!flat.length) {
      log.debug("Leaving ClosedSets.registerConsole(). No flat enum.");
      return;
    }
    const key = page + '\u0000' + (action || '');
    const held = ClosedSets.consoleFields.get(key) || [];
    flat.forEach(function (f) {
      const already = held.some(function (h) {
        return h.path[0] === f.path[0];
      });
      if (!already) {
        held.push({ path: [f.path[0]], values: f.values.slice() });
      }
    });
    ClosedSets.consoleFields.set(key, held);
    log.debug("Leaving ClosedSets.registerConsole(). " + held.length +
              " field(s) held.");
  }

  // Whether any control on `page` is registered under an action of its own.
  static hasActions(page: string): boolean {
    log.debug("Entering ClosedSets.hasActions(). " + page);
    let found = false;
    ClosedSets.consoleFields.forEach(function (fields, key) {
      const cut = key.indexOf('\u0000');
      if (key.slice(0, cut) === page && key.slice(cut + 1) !== '') {
        found = true;
      }
    });
    log.debug("Leaving ClosedSets.hasActions(). " + found);
    return found;
  }

  // What a console POST to `page` with `action` is held to (for the tests and
  // the gate).
  static forConsole(page: string, action: string): ClosedField[] {
    log.debug("Entering ClosedSets.forConsole(). " + page + " " + action);
    const held = ClosedSets.consoleFields.get(page + '\u0000' +
                                              (action || '')) || [];
    log.debug("Leaving ClosedSets.forConsole(). " + held.length +
              " field(s).");
    return held.slice();
  }

  // Every registered console control, for the tests: [{ page, action,
  // fields }].
  static consoleRegister(): Array<{ page: string; action: string;
                                    fields: ClosedField[] }> {
    log.debug("Entering ClosedSets.consoleRegister().");
    const rows = [];
    ClosedSets.consoleFields.forEach(function (fields, key) {
      const cut = key.indexOf('\u0000');
      rows.push({ page: key.slice(0, cut), action: key.slice(cut + 1),
                  fields: fields.slice() });
    });
    log.debug("Leaving ClosedSets.consoleRegister(). " + rows.length +
              " control(s).");
    return rows;
  }

  // A form body with EVERY value of a repeated field, which
  // `helpers.parseBody()` cannot give (it keeps the last): a checkbox column
  // ticked three times is three values, and each is held to the set. A body
  // that is not form-encoded is the parsed one the caller passes.
  static formValues(req: any, parsed: any): any {
    log.debug("Entering ClosedSets.formValues().");
    const type = String((req && req.headers &&
                         req.headers['content-type']) || '');
    if (typeof req.body !== 'string' ||
        !/^application\/x-www-form-urlencoded/i.test(type)) {
      log.debug("Leaving ClosedSets.formValues(). Not form-encoded.");
      return parsed || {};
    }
    const out = {};
    new URLSearchParams(req.body).forEach(function (v, k) {
      out[k] = Object.prototype.hasOwnProperty.call(out, k)
        ? [].concat(out[k], v) : v;
    });
    log.debug("Leaving ClosedSets.formValues(). " + Object.keys(out).length +
              " field(s).");
    return out;
  }

  // A console form body against what its control is held to. A control with
  // no `action` of its own (a route the API spells without one) is held by
  // the page's `''` row.
  static checkForm(page: string, action: string, body: any): ClosedCheck {
    log.debug("Entering ClosedSets.checkForm(). " + page + " " + action);
    let fields = ClosedSets.forConsole(page, action);
    if (!fields.length && action && !ClosedSets.hasActions(page)) {
      // Only a page whose one operation takes no action falls back to its
      // `''` row: on a page with actions of its own, one action's fields are
      // never applied to another's.
      fields = ClosedSets.forConsole(page, '');
    }
    for (let i = 0; i < fields.length; i++) {
      const name = fields[i].path[0];
      const outside = ClosedSets.firstOutside(body ? body[name] : undefined,
                                              fields[i].values);
      if (outside.found) {
        log.debug("Leaving ClosedSets.checkForm(). Refused on " + name + ".");
        return { ok: false, field: name, value: outside.value,
                 values: fields[i].values,
                 sentence: ClosedSets.sentence(name, outside.value,
                                               fields[i].values) };
      }
    }
    log.debug("Leaving ClosedSets.checkForm(). Accepted.");
    return { ok: true };
  }

  // An operation's query string against the enums its parameters declare.
  static checkQuery(parameters: QueryParameter[] | undefined,
                    query: any): ClosedCheck {
    log.debug("Entering ClosedSets.checkQuery().");
    const declared = (parameters || []).filter(function (p) {
      return p && p.in === 'query' && p.name && p.schema;
    });
    for (let i = 0; i < declared.length; i++) {
      const p = declared[i];
      if (p.schema['x-refused-by-handler'] === true) {
        continue;
      }
      const values = Array.isArray(p.schema.enum) ? p.schema.enum :
                     (p.schema.items && Array.isArray(p.schema.items.enum)
                       ? p.schema.items.enum : null);
      if (!values) {
        continue;
      }
      // A comma-separated list is how an `array` parameter is spelt in a
      // query string (OpenAPI's default `form` style, `explode: false`).
      let raw = query ? query[p.name] : undefined;
      if (p.schema.type === 'array' && typeof raw === 'string') {
        raw = raw.split(',').map(function (s) {
          return s.trim();
        });
      }
      const outside = ClosedSets.firstOutside(raw, values);
      if (outside.found) {
        log.debug("Leaving ClosedSets.checkQuery(). Refused on " + p.name +
                  ".");
        return { ok: false, field: p.name, value: outside.value,
                 values: values,
                 sentence: ClosedSets.sentence(p.name, outside.value,
                                               values) };
      }
    }
    log.debug("Leaving ClosedSets.checkQuery(). Accepted.");
    return { ok: true };
  }
}

export = ClosedSets;
