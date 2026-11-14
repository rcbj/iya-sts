// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_emit.ts
//
// ---------------------------------------------------------------------------
// EMITTERS FOR THE COMMON MODEL (#1390).
//
// TypeSpec is the language. This file writes TypeSpec text from the
// directory catalogue and from the PostgreSQL model, and
// `tests/model_typespec.js` compiles that text with the TypeSpec compiler
// and holds what comes back to the sources. The same write rewrites
// the reading pages under docs/: data-model-directory.md and
// data-model-persistence.md. Those pages are what a reader sees. The
// class text is for a reader and for the tests. It is not written into
// the tree here, because a `.ts` file in the tree is compiled into the
// image and these classes are not what the service runs.
//
// The direction is still source to model for everything but what a test
// proves: nothing in the running service reads these files. OpenAPI bytes
// are captured only when the caller passes documents (`captureDocuments`).
// `check()` does not load the protocol stack and does not build a
// document.
//
// API classes are not generated in v1. Parsing a captured schema is
// Ajv's job (`openapi_import.ts`). Directory and table classes describe
// a Zod `strictObject`, which is what `DirectoryModel.parse` and
// `PostgresImport.parseRow` use. The two are not the same choice, and
// the file says so rather than pretending one library covers both.
//
// A LIBRARY. No route.
// ---------------------------------------------------------------------------

import fs = require('fs');
import path = require('path');
import bunyan = require('bunyan');
import ModelIr = require('./model_ir');
import directory = require('./directory_model');
import PostgresImport = require('./postgres_import');
import MariaDbImport = require('./mariadb_import');
import OpenApiImport = require('./openapi_import');
import ModelTables = require('./model_tables');

const log = bunyan.createLogger({
  name: 'sts-model-emit',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

/**
 * Turns a collected catalogue into TypeSpec and class text.
 */
class ModelEmit {
  /**
   * A TypeScript name. `application` stays `Application`. A dotted id
   * such as `policy.password` becomes `PolicyPassword`, because the
   * dot is not part of a class name.
   *
   * @param id - an object id or a table name
   * @returns the class name
   */
  static className(id: string): string {
    log.debug("Entering ModelEmit.className().");
    const parts = String(id).split(/[^A-Za-z0-9]+/).filter(
      function (part) {
        return part.length > 0;
      });
    const name = parts.map(function (part) {
      return part.charAt(0).toUpperCase() + part.slice(1);
    }).join('');
    log.debug("Leaving ModelEmit.className().");
    return name;
  }

  /**
   * A doc comment, wrapped to 80 columns. An empty text writes nothing.
   * A single token longer than the width is kept whole.
   *
   * @param lines - the file being built
   * @param text - the sentence
   * @param indent - the indent of the comment
   */
  static docComment(lines: string[], text: string, indent: string): void {
    log.debug("Entering ModelEmit.docComment().");
    const clean = ModelEmit.escapeDoc(text);
    if (!clean) {
      log.debug("Leaving ModelEmit.docComment(). Empty.");
      return;
    }
    const width = 80 - (indent.length + 3);
    const wrapped = ModelEmit.wrapWords(clean, width);
    lines.push(indent + '/**');
    wrapped.forEach(function (line) {
      lines.push(indent + ' * ' + line);
    });
    lines.push(indent + ' */');
    log.debug("Leaving ModelEmit.docComment().");
  }

  /**
   * Escapes the end of a block comment.
   *
   * @param text - the sentence
   * @returns the text safe to put in a block comment
   */
  static escapeDoc(text: string): string {
    log.debug("Entering ModelEmit.escapeDoc().");
    const clean = String(text || '').replace(/\*\//g, '* /').trim();
    log.debug("Leaving ModelEmit.escapeDoc().");
    return clean;
  }

  /**
   * Wraps on spaces. A token longer than `width` stays on its own line.
   *
   * @param text - one paragraph
   * @param width - the maximum line length
   * @returns the lines
   */
  static wrapWords(text: string, width: number): string[] {
    log.debug("Entering ModelEmit.wrapWords().");
    const words = text.replace(/\s+/g, ' ').split(' ');
    const lines: string[] = [];
    let current = '';
    words.forEach(function (word) {
      if (!word) {
        return;
      }
      const next = current ? current + ' ' + word : word;
      if (current && next.length > width) {
        lines.push(current);
        current = word;
        return;
      }
      current = next;
    });
    if (current) {
      lines.push(current);
    }
    log.debug("Leaving ModelEmit.wrapWords().");
    return lines;
  }

  /**
   * Class text for one directory object, and a second class when the
   * object lists person attributes. The text is not compiled here.
   *
   * @param object - a catalogue object
   * @returns the class text
   */
  static directoryClass(object: any): string {
    log.debug("Entering ModelEmit.directoryClass().");
    const parts = [ModelEmit.oneClass(ModelEmit.className(object.id),
      object.attributes, true)];
    if (object.personAttributes && object.personAttributes.length > 0) {
      parts.push(ModelEmit.oneClass(
        ModelEmit.className(object.id) + 'OnPerson',
        object.personAttributes, true));
    }
    log.debug("Leaving ModelEmit.directoryClass().");
    return parts.join('\n\n');
  }

  /**
   * Class text for one table. One property per column. `jsonb` and any
   * type this mapping does not name are `unknown`. The same tokens as
   * `PostgresImport.zodOf`.
   *
   * @param table - a table from the PostgreSQL model
   * @returns the class text
   */
  static tableClass(table: any): string {
    log.debug("Entering ModelEmit.tableClass().");
    const fields = (table.columns || []).map(function (column: any) {
      return {
        name: column.name,
        optional: !column.required,
        ts: ModelEmit.columnTs(column.sqlType),
        zod: ModelEmit.columnZod(column.sqlType)
      };
    });
    const text = ModelEmit.fieldsClass(ModelEmit.className(table.name),
      fields);
    log.debug("Leaving ModelEmit.tableClass().");
    return text;
  }

  /**
   * One directory class.
   *
   * @param name - the class name
   * @param attributes - the attributes
   * @param directoryOptional - directory attributes are always optional
   * @returns the class text
   */
  static oneClass(name: string, attributes: any[],
      directoryOptional: boolean): string {
    log.debug("Entering ModelEmit.oneClass().");
    const fields = (attributes || []).map(function (attribute: any) {
      return {
        name: attribute.name,
        optional: directoryOptional,
        ts: ModelEmit.attributeTs(attribute.kind),
        zod: ModelEmit.attributeZod(attribute.kind)
      };
    });
    const text = ModelEmit.fieldsClass(name, fields);
    log.debug("Leaving ModelEmit.oneClass().");
    return text;
  }

  /**
   * The class text. `schema()` is a `z.strictObject`, so an unknown key
   * fails. The tests read this text. They do not compile it.
   *
   * @param name - the class name
   * @param fields - name, optional, TypeScript type, Zod expression
   * @returns the class text
   */
  static fieldsClass(name: string, fields: { name: string;
      optional: boolean; ts: string; zod: string }[]): string {
    log.debug("Entering ModelEmit.fieldsClass().");
    const lines = [
      '// Generated (#1390). Not consulted by the running service.',
      '// Every directory property is optional. Unknown keys fail.',
      'class ' + name + ' {'
    ];
    fields.forEach(function (field) {
      const mark = field.optional ? '?' : '!';
      lines.push('  ' + field.name + mark + ': ' + field.ts + ';');
    });
    lines.push('');
    lines.push('  static schema(): unknown {');
    lines.push('    return z.strictObject({');
    fields.forEach(function (field) {
      const expr = field.optional ? field.zod + '.optional()' : field.zod;
      lines.push('      ' + field.name + ':');
      lines.push('        ' + expr + ',');
    });
    lines.push('    });');
    lines.push('  }');
    lines.push('}');
    log.debug("Leaving ModelEmit.fieldsClass().");
    return lines.join('\n');
  }

  /**
   * The TypeScript type of a directory kind.
   *
   * @param kind - `single`, `multi` or `unspecified`
   * @returns the type
   */
  static attributeTs(kind: string): string {
    log.debug("Entering ModelEmit.attributeTs().");
    if (kind === 'single') {
      log.debug("Leaving ModelEmit.attributeTs(). string.");
      return 'string';
    }
    if (kind === 'multi') {
      log.debug("Leaving ModelEmit.attributeTs(). string[].");
      return 'string[]';
    }
    log.debug("Leaving ModelEmit.attributeTs(). unknown.");
    return 'unknown';
  }

  /**
   * The Zod expression of a directory kind, before `.optional()`.
   *
   * @param kind - `single`, `multi` or `unspecified`
   * @returns the expression
   */
  static attributeZod(kind: string): string {
    log.debug("Entering ModelEmit.attributeZod().");
    if (kind === 'single') {
      log.debug("Leaving ModelEmit.attributeZod(). string.");
      return 'z.string()';
    }
    if (kind === 'multi') {
      log.debug("Leaving ModelEmit.attributeZod(). string array.");
      return 'z.array(z.string())';
    }
    log.debug("Leaving ModelEmit.attributeZod(). unknown.");
    return 'z.unknown()';
  }

  /**
   * The TypeScript type of a SQL type token.
   *
   * @param sqlType - the type from the column
   * @returns the type
   */
  static columnTs(sqlType: string): string {
    log.debug("Entering ModelEmit.columnTs().");
    const token = String(sqlType || '').toLowerCase();
    let type = 'unknown';
    if (token === 'text' || token.indexOf('char') === 0 ||
        token === 'inet' || token === 'cidr' || token === 'xid8') {
      type = 'string';
    } else if (token === 'boolean') {
      type = 'boolean';
    } else if (token === 'smallint' || token === 'integer' ||
        token === 'int' || token === 'real' ||
        token === 'double precision') {
      type = 'number';
    } else if (token === 'bigint' || token === 'bigserial') {
      type = 'number | string';
    } else if (token === 'text[]') {
      type = 'string[]';
    }
    log.debug("Leaving ModelEmit.columnTs().");
    return type;
  }

  /**
   * The Zod expression of a SQL type token, before `.optional()`. The
   * same mapping as `PostgresImport.zodOf`.
   *
   * @param sqlType - the type from the column
   * @returns the expression
   */
  static columnZod(sqlType: string): string {
    log.debug("Entering ModelEmit.columnZod().");
    const token = String(sqlType || '').toLowerCase();
    let expression = 'z.unknown()';
    if (token === 'text' || token.indexOf('char') === 0 ||
        token === 'inet' || token === 'cidr' || token === 'xid8') {
      expression = 'z.string()';
    } else if (token === 'boolean') {
      expression = 'z.boolean()';
    } else if (token === 'smallint' || token === 'integer' ||
        token === 'int' || token === 'real' ||
        token === 'double precision') {
      expression = 'z.number()';
    } else if (token === 'bigint' || token === 'bigserial') {
      expression = 'z.union([z.number(), z.string().regex(/^-?[0-9]+$/)])';
    } else if (token === 'text[]') {
      expression = 'z.array(z.string())';
    }
    log.debug("Leaving ModelEmit.columnZod().");
    return expression;
  }

  /**
   * RFC 4512 definitions of everything in the model that has an OID. A
   * name with no OID cannot be written as a definition, so it is listed
   * instead.
   *
   * @param objects - objects from a compiled model
   * @returns the definitions and the names that have no OID
   */
  static ldapSchema(objects: any[]): { attributeTypes: string[];
      objectClasses: string[]; withoutOid: string[] } {
    log.debug("Entering ModelEmit.ldapSchema().");
    const types = new Map<string, string>();
    const classes = new Map<string, string>();
    const without = new Set<string>();
    objects.forEach(function (object: any) {
      object.objectClasses.forEach(function (item: any) {
        if (!item.oid) {
          without.add(item.name);
          return;
        }
        classes.set(item.name, ModelEmit.classDefinition(item));
      });
      object.attributes.concat(object.personAttributes).forEach(
        function (attribute: any) {
          if (!attribute.oid) {
            without.add(attribute.name);
            return;
          }
          types.set(attribute.name, ModelEmit.typeDefinition(attribute));
        });
    });
    const inOrder = function (table: Map<string, string>) {
      return Array.from(table.keys()).sort().map(function (key) {
        return table.get(key) as string;
      });
    };
    const schema = {
      attributeTypes: inOrder(types),
      objectClasses: inOrder(classes),
      withoutOid: Array.from(without).sort()
    };
    log.debug("Leaving ModelEmit.ldapSchema().");
    return schema;
  }

  /**
   * One attribute type, in RFC 4512's form.
   *
   * @param attribute - an attribute with an OID
   * @returns the definition
   */
  static typeDefinition(attribute: any): string {
    log.debug("Entering ModelEmit.typeDefinition().");
    const parts = ['(', attribute.oid, "NAME '" + attribute.name + "'"];
    if (attribute.sup) {
      parts.push('SUP', attribute.sup);
    }
    [['EQUALITY', attribute.equality], ['ORDERING', attribute.ordering],
      ['SUBSTR', attribute.substr], ['SYNTAX', attribute.syntax]].forEach(
      function (pair) {
        if (pair[1]) {
          parts.push(pair[0], pair[1]);
        }
      });
    if (attribute.ldapSingleValue) {
      parts.push('SINGLE-VALUE');
    }
    if (attribute.noUserModification) {
      parts.push('NO-USER-MODIFICATION');
    }
    if (attribute.usage) {
      parts.push('USAGE', attribute.usage);
    }
    parts.push(')');
    log.debug("Leaving ModelEmit.typeDefinition().");
    return parts.join(' ');
  }

  /**
   * One object class, in RFC 4512's form.
   *
   * @param item - a class with an OID
   * @returns the definition
   */
  static classDefinition(item: any): string {
    log.debug("Entering ModelEmit.classDefinition().");
    const list = function (names: string[]) {
      return names.length === 1 ? names[0] :
        '( ' + names.join(' $ ') + ' )';
    };
    const parts = ['(', item.oid, "NAME '" + item.name + "'"];
    if (item.sup && item.sup.length > 0) {
      parts.push('SUP', list(item.sup));
    }
    parts.push(String(item.classType).toUpperCase());
    if (item.must && item.must.length > 0) {
      parts.push('MUST', list(item.must));
    }
    if (item.may && item.may.length > 0) {
      parts.push('MAY', list(item.may));
    }
    parts.push(')');
    log.debug("Leaving ModelEmit.classDefinition().");
    return parts.join(' ');
  }

  /**
   * Captures documents the caller already built. This does not build
   * them, and `check()` does not call it.
   *
   * @param named - document name and the builder's object
   * @returns one captured model per document
   */
  static captureDocuments(named: { name: string; document: unknown }[]):
      any[] {
    log.debug("Entering ModelEmit.captureDocuments().");
    const captured = named.map(function (one) {
      return OpenApiImport.capture(one.name, one.document);
    });
    log.debug("Leaving ModelEmit.captureDocuments().");
    return captured;
  }

  /**
   * A heading's kramdown id: lower case, spaces as hyphens, and no
   * other punctuation. The same rule as `tests/doc_links.js`.
   *
   * @param title - the heading text
   * @returns the id
   */
  static headingId(title: string): string {
    log.debug("Entering ModelEmit.headingId().");
    const id = String(title).toLowerCase().replace(/[^a-z0-9 -]/g, '').
      replace(/ /g, '-');
    log.debug("Leaving ModelEmit.headingId().");
    return id;
  }

  /**
   * A Markdown table cell. A pipe or a newline would split the row.
   *
   * @param text - the cell
   * @returns the escaped cell
   */
  static tableCell(text: string): string {
    log.debug("Entering ModelEmit.tableCell().");
    const cell = String(text || '').replace(/\\/g, '\\\\').
      replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
    log.debug("Leaving ModelEmit.tableCell().");
    return cell;
  }

  /**
   * How many values an attribute holds, in words.
   *
   * @param kind - `single`, `multi`, or anything else
   * @returns the word
   */
  static valueLabel(kind: string): string {
    log.debug("Entering ModelEmit.valueLabel().");
    if (kind === 'single') {
      log.debug("Leaving ModelEmit.valueLabel(). one.");
      return 'one';
    }
    if (kind === 'multi') {
      log.debug("Leaving ModelEmit.valueLabel(). several.");
      return 'several';
    }
    log.debug("Leaving ModelEmit.valueLabel(). not stated.");
    return 'not stated';
  }

  /**
   * Where a name comes from, in words.
   *
   * @param provenance - the catalogue provenance
   * @returns the word
   */
  static originLabel(provenance: string): string {
    log.debug("Entering ModelEmit.originLabel().");
    if (provenance === 'rfc') {
      log.debug("Leaving ModelEmit.originLabel(). RFC.");
      return 'RFC';
    }
    if (provenance === 'oasis-or-other') {
      log.debug("Leaving ModelEmit.originLabel(). other.");
      return 'other standard';
    }
    if (provenance === 'iya-sts') {
      log.debug("Leaving ModelEmit.originLabel(). service.");
      return 'this service';
    }
    if (provenance === 'derived') {
      log.debug("Leaving ModelEmit.originLabel(). derived.");
      return 'derived';
    }
    log.debug("Leaving ModelEmit.originLabel(). not stated.");
    return 'not stated';
  }

  /**
   * The heading a reader sees for one directory object.
   *
   * @param id - the object id
   * @returns the heading
   */
  static directoryTitle(id: string): string {
    log.debug("Entering ModelEmit.directoryTitle().");
    const titles: { [key: string]: string } = {
      application: 'Application',
      attributeSource: 'Attribute source',
      claimProvider: 'Claims provider',
      kerberosTrust: 'Kerberos trust',
      oidfed: 'OpenID Federation entry',
      secretsDestination: 'Secrets destination',
      signerTrustAnchor: 'Signer trust anchor',
      trustAnchor: 'Trust anchor',
      device: 'Device',
      federationRelationship: 'Federation relationship',
      group: 'Group',
      operational: 'Operational attributes',
      person: 'Person',
      'policy.attributes': 'Attribute policy',
      'policy.authn': 'Authentication policy',
      'policy.locale': 'Locale policy',
      'policy.passkey': 'Passkey policy',
      'policy.password': 'Password policy',
      'policy.postLogin': 'Post-login policy',
      'policy.serviceAccount': 'Service-account policy',
      role: 'Role',
      serviceAccount: 'Service account',
      spiffe: 'SPIFFE',
      xacmlPep: 'XACML policy enforcement point',
      xacmlPolicy: 'XACML policy'
    };
    const title = titles[id] || ModelEmit.className(id);
    log.debug("Leaving ModelEmit.directoryTitle().");
    return title;
  }

  /**
   * The sentence under a model that says where it was recorded.
   *
   * @param object - a catalogue object
   * @returns the sentence
   */
  static sourceSentence(object: any): string {
    log.debug("Entering ModelEmit.sourceSentence().");
    const source = String(object.source || '');
    if (source === 'catalogue') {
      log.debug("Leaving ModelEmit.sourceSentence(). Catalogue.");
      return 'Held in the catalogue. No SCHEMA module.';
    }
    if (source.indexOf('policy_kinds:') === 0) {
      const kind = source.slice('policy_kinds:'.length);
      log.debug("Leaving ModelEmit.sourceSentence(). Policy.");
      return 'A policy profile, kind `' + kind + '`.';
    }
    log.debug("Leaving ModelEmit.sourceSentence(). Module.");
    return 'Recorded in `' + source + '`.';
  }

  /**
   * One attribute's description: secret, families, the model's own
   * sentence, and a citation when the row has one.
   *
   * @param attribute - a catalogue attribute
   * @returns the cell text
   */
  static attributeDescription(attribute: any): string {
    log.debug("Entering ModelEmit.attributeDescription().");
    const parts: string[] = [];
    if (attribute.withheld === true) {
      parts.push('Secret.');
    }
    if (attribute.families && attribute.families.length > 0) {
      parts.push('Families: ' + attribute.families.join(', ') + '.');
    }
    if (attribute.what) {
      parts.push(String(attribute.what));
    }
    if (attribute.from) {
      parts.push('From ' + attribute.from + '.');
    }
    log.debug("Leaving ModelEmit.attributeDescription().");
    return parts.join(' ');
  }

  /**
   * Appends an attribute table.
   *
   * @param lines - the page being built
   * @param attributes - the attributes
   */
  static attributeTable(lines: string[], attributes: any[]): void {
    log.debug("Entering ModelEmit.attributeTable().");
    lines.push('| Attribute | Values | Origin | OID | Description |');
    lines.push('|---|---|---|---|---|');
    (attributes || []).forEach(function (attribute: any) {
      lines.push('| `' + ModelEmit.tableCell(attribute.name) + '` | ' +
        ModelEmit.valueLabel(attribute.kind) + ' | ' +
        ModelEmit.originLabel(attribute.provenance) + ' | ' +
        (attribute.oid ? '`' + attribute.oid + '`' : '') + ' | ' +
        ModelEmit.tableCell(ModelEmit.attributeDescription(attribute)) +
        ' |');
    });
    lines.push('');
    log.debug("Leaving ModelEmit.attributeTable().");
  }

  /**
   * The application's key, subject, and relationships. They are part
   * of the model and are not attributes the TypeSpec property list
   * can show on their own.
   *
   * @param lines - the page being built
   */
  static applicationReading(lines: string[]): void {
    log.debug("Entering ModelEmit.applicationReading().");
    const facts = ModelTables.facts('application');
    lines.push('### Names and the subject');
    lines.push('');
    lines.push('| | |');
    lines.push('|---|---|');
    lines.push('| Key | `' + facts.key + '` |');
    lines.push('| Filing name | `' +
      facts.naming.attribute + '`. ' +
      ModelEmit.tableCell(facts.naming.what) + ' |');
    facts.derived.forEach(function (field: any) {
      lines.push('| Derived | `' + field.name + '`. ' +
        ModelEmit.tableCell(field.what) + ' |');
    });
    lines.push('| Registration | ' +
      facts.registration.map(function (name: string) {
        return '`' + name + '`';
      }).join(', ') + ' |');
    lines.push('| Declared families | `' +
      facts.declaration + '` |');
    lines.push('| Seen families | `' +
      facts.observation + '` |');
    lines.push('');
    lines.push('### Relationships');
    lines.push('');
    lines.push('| Link | Values | Owns the target | Held by | What it is |');
    lines.push('|---|---|---|---|---|');
    ModelTables.links().filter(function (link: any) {
      return link.from === 'application' || link.to === 'application';
    }).forEach(function (link: any) {
      const held = link.from === 'application' ? 'this application' :
        String(link.from);
      lines.push('| `' + link.name + '` | ' +
        ModelEmit.valueLabel(link.cardinality) + ' | ' +
        (link.owns ? 'yes' : 'no') + ' | ' + held + ' | ' +
        ModelEmit.tableCell(link.what) + ' |');
    });
    lines.push('');
    log.debug("Leaving ModelEmit.applicationReading().");
  }

  /**
   * The body of one directory model, under a heading the caller writes.
   *
   * @param lines - the page being built
   * @param object - the catalogue object
   * @param onPerson - the person-side attributes of a policy
   */
  static directoryBody(lines: string[], object: any,
      onPerson: boolean): void {
    log.debug("Entering ModelEmit.directoryBody().");
    const tsp = ModelEmit.className(object.id) +
      (onPerson ? 'OnPerson' : '');
    const attributes = onPerson ? object.personAttributes :
      object.attributes;
    lines.push('TypeSpec model `' + tsp + '`.');
    if (onPerson) {
      lines.push('These attributes live on the person, not on this ' +
        'entry.');
    } else {
      if (object.container) {
        lines.push('Container `' + object.container + '`.');
      }
      lines.push(ModelEmit.sourceSentence(object));
      if (object.note) {
        lines.push(String(object.note));
      }
    }
    lines.push('');
    if (!onPerson && object.objectClasses &&
        object.objectClasses.length > 0) {
      lines.push('| Class | Origin | OID | Kind | Superior | Description |');
      lines.push('|---|---|---|---|---|---|');
      object.objectClasses.forEach(function (item: any) {
        lines.push('| `' + ModelEmit.tableCell(item.name) + '` | ' +
          ModelEmit.originLabel(item.provenance) + ' | ' +
          (item.oid ? '`' + item.oid + '`' : '') + ' | ' +
          (item.classType || '') + ' | ' +
          (item.sup || []).join(', ') + ' | ' +
          ModelEmit.tableCell(item.what || '') + ' |');
      });
      lines.push('');
    }
    if (!attributes || attributes.length === 0) {
      lines.push('This model lists no attributes.');
      lines.push('');
    } else {
      ModelEmit.attributeTable(lines, attributes);
    }
    if (!onPerson && object.id === 'application') {
      ModelEmit.applicationReading(lines);
    }
    log.debug("Leaving ModelEmit.directoryBody().");
  }

  /**
   * The directory models, as a page a person can read.
   *
   * @param catalog - a catalogue from `DirectoryModel.collect()`
   * @returns the Markdown page, including its front matter
   */
  static directoryDocs(catalog: any): string {
    log.debug("Entering ModelEmit.directoryDocs().");
    const entries: { title: string; object: any; onPerson: boolean }[] =
      [];
    (catalog.objects || []).forEach(function (object: any) {
      entries.push({ title: ModelEmit.directoryTitle(object.id),
        object: object, onPerson: false });
      if (object.personAttributes &&
          object.personAttributes.length > 0) {
        entries.push({
          title: ModelEmit.directoryTitle(object.id) + ' on a person',
          object: object,
          onPerson: true
        });
      }
    });
    const lines = [
      '---',
      'title: Directory models',
      'nav_order: 13',
      '---',
      '',
      '<!-- GENERATED by `node common/model_emit.js --docs` from the',
      '     directory model. Do not edit this file by hand.',
      '     tests/model_directory.js fails when it differs. -->',
      '',
      '# Directory models',
      '',
      'These are the directory models, in reading form. Each heading is',
      'one TypeSpec model. [Abstract data model](data-model.md) is the',
      'picture. [LDAP schema](ldap-schema.md) explains the names. The',
      'directory still enforces nothing.',
      '',
      'A value is **one**, **several**, or **not stated** when the model',
      'does not say. A name\'s origin is **RFC**, **other standard**,',
      '**this service**, **derived**, or **not stated**. **Secret** marks',
      'a value the model withholds.',
      ''
    ];
    // The register says whether its root is still a placeholder (#1573).
    // While it is, the page says so; once the Private Enterprise Number is
    // in place the sentence would be false, so it is not written.
    const oidRoot = catalog.oidRoot || { root: '', placeholder: false };
    if (oidRoot.placeholder) {
      lines.push(
        'An OID that begins `' + oidRoot.root + '` is a placeholder. That ' +
          'is the',
        'number RFC 5612 reserves for documentation, and this service\'s own',
        'names use it until its Private Enterprise Number is assigned.',
        '');
    }
    lines.push(
      'This page is rewritten whenever that TypeSpec model is written.',
      'Do not edit it by hand.',
      '',
      '## Models',
      '',
      '| Model | TypeSpec | Container | Attributes |',
      '|---|---|---|---|');
    entries.forEach(function (entry) {
      const tsp = ModelEmit.className(entry.object.id) +
        (entry.onPerson ? 'OnPerson' : '');
      const attributes = entry.onPerson ?
        entry.object.personAttributes : entry.object.attributes;
      const container = entry.onPerson ? 'on the person' :
        (entry.object.container || '');
      lines.push('| [' + entry.title + '](#' +
        ModelEmit.headingId(entry.title) + ') | `' + tsp + '` | ' +
        ModelEmit.tableCell(container) + ' | ' +
        String((attributes || []).length) + ' |');
    });
    lines.push('');
    entries.forEach(function (entry) {
      lines.push('## ' + entry.title);
      lines.push('');
      ModelEmit.directoryBody(lines, entry.object, entry.onPerson);
    });
    log.debug("Leaving ModelEmit.directoryDocs().");
    return lines.join('\n');
  }

  /**
   * Notes for one column of the reading page.
   *
   * @param column - a column
   * @returns the notes cell
   */
  static columnNotes(column: any): string {
    log.debug("Entering ModelEmit.columnNotes().");
    const parts: string[] = [];
    if (column.generated) {
      parts.push('Generated.');
    }
    if (column.attributes && column.attributes.length > 0) {
      parts.push('Directory names: ' + column.attributes.map(
        function (name: string) {
          return '`' + name + '`';
        }).join(', ') + '.');
    }
    log.debug("Leaving ModelEmit.columnNotes().");
    return parts.join(' ');
  }

  /**
   * The persistence models, as a page a person can read.
   *
   * @param model - a model from `PostgresImport.read()`
   * @returns the Markdown page, including its front matter
   */
  static persistenceDocs(model: any): string {
    log.debug("Entering ModelEmit.persistenceDocs().");
    const tables = model.tables || [];
    const lines = [
      '---',
      'title: Persistence models',
      'nav_order: 14',
      '---',
      '',
      '<!-- GENERATED by `node common/model_emit.js --docs` from the',
      '     persistence model. Do not edit this file by hand.',
      '     tests/model_postgres.js fails when it differs. -->',
      '',
      '# Persistence models',
      '',
      'These are the tables in the persistence model, in reading form.',
      'Each heading is one table. [Abstract data model](data-model.md)',
      'is the picture. [PostgreSQL schema](postgres-schema.md) explains',
      'why the tables are shaped this way. This page does not replace',
      'that explanation.',
      '',
      'The MariaDB script is the same schema version. The model emits',
      'it as `mariadb/schema.sql`, that file\'s own bytes. This page',
      'lists the PostgreSQL tables.',
      '',
      'Schema version **' + String(model.version) + '**.',
      '',
      'A required column must be present. **Generated** is a column the',
      'database fills. A directory name on a column is one the schema',
      'already states. A directory attribute does not otherwise become',
      'a column. Indexes, grants, and routines stay in the SQL file.',
      '',
      'This page is rewritten whenever that TypeSpec model is written.',
      'Do not edit it by hand.',
      ''
    ];
    if (model.extensions && model.extensions.length > 0) {
      lines.push('Extensions: ' + model.extensions.map(
        function (name: string) {
          return '`' + name + '`';
        }).join(', ') + '.');
      lines.push('');
    }
    lines.push('## Tables');
    lines.push('');
    lines.push('| Table | TypeSpec | Columns |');
    lines.push('|---|---|---|');
    tables.forEach(function (table: any) {
      lines.push('| [' + table.name + '](#' +
        ModelEmit.headingId(table.name) + ') | `' +
        ModelEmit.className(table.name) + '` | ' +
        String((table.columns || []).length) + ' |');
    });
    lines.push('');
    tables.forEach(function (table: any) {
      lines.push('## ' + table.name);
      lines.push('');
      lines.push('TypeSpec model `' + ModelEmit.className(table.name) +
        '`.');
      lines.push('');
      lines.push('| Column | SQL type | Required | Notes |');
      lines.push('|---|---|---|---|');
      (table.columns || []).forEach(function (column: any) {
        lines.push('| `' + ModelEmit.tableCell(column.name) + '` | `' +
          ModelEmit.tableCell(column.sqlType) + '` | ' +
          (column.required ? 'yes' : 'no') + ' | ' +
          ModelEmit.tableCell(ModelEmit.columnNotes(column)) + ' |');
      });
      lines.push('');
    });
    log.debug("Leaving ModelEmit.persistenceDocs().");
    return lines.join('\n');
  }

  /**
   * Writes the TypeSpec and the two reading pages. `model.json` is not
   * written here.
   *
   * @param root - the package root
   * @param catalog - the directory catalogue
   * @param pg - the persistence model
   */
  static writeReadingFiles(root: string, catalog: any, pg: any): void {
    log.debug("Entering ModelEmit.writeReadingFiles().");
    const dir = path.join(root, 'models', 'directory');
    const persistence = path.join(root, 'models', 'persistence');
    fs.mkdirSync(dir, { recursive: true });
    fs.mkdirSync(persistence, { recursive: true });
    fs.writeFileSync(path.join(root, 'docs', 'data-model-directory.md'),
      ModelEmit.directoryDocs(catalog));
    fs.writeFileSync(
      path.join(root, 'docs', 'data-model-persistence.md'),
      ModelEmit.persistenceDocs(pg));
    log.debug("Leaving ModelEmit.writeReadingFiles().");
  }

  /**
   * Collects both namespaces and writes the TypeSpec and the reading
   * pages.
   *
   * @param root - the package root
   */
  static writeReading(root: string): void {
    log.debug("Entering ModelEmit.writeReading().");
    const deps = directory.DirectoryModel.defaultDeps();
    deps.root = root;
    const collector = new directory.DirectoryModel(deps);
    const catalog = collector.collect();
    const pg = PostgresImport.read(root);
    ModelEmit.writeReadingFiles(root, catalog, pg);
    log.debug("Leaving ModelEmit.writeReading().");
  }

  /**
   * One generated file, compared to a fresh render. A missing file is
   * stale.
   *
   * @param root - the package root
   * @param relative - the path under the package root
   * @param fresh - what the file should contain
   * @param problems - the list being built
   */
  static expectText(root: string, relative: string, fresh: string,
      problems: string[]): void {
    log.debug("Entering ModelEmit.expectText().");
    const full = path.join(root, relative);
    let current = '';
    if (fs.existsSync(full)) {
      current = fs.readFileSync(full, 'utf8');
    }
    if (current !== fresh) {
      problems.push(relative + ' is stale. Run: node common/model_emit.js ' +
        '--docs');
    }
    log.debug("Leaving ModelEmit.expectText().");
  }

  /**
   * Two directory collects agree, and the reading pages and the TypeSpec
   * match the model. OpenAPI is not built here.
   *
   * @param root - the package root
   * @returns problems, empty when the check passes
   */
  static check(root: string): string[] {
    log.debug("Entering ModelEmit.check().");
    const problems: string[] = [];
    const deps = directory.DirectoryModel.defaultDeps();
    deps.root = root;
    const collector = new directory.DirectoryModel(deps);
    const first = collector.collect();
    const second = collector.collect();
    if (ModelIr.stable(first) !== ModelIr.stable(second)) {
      problems.push('directory collect is not stable');
    }
    const pg = PostgresImport.read(root);
    ModelEmit.expectText(root, 'docs/data-model-directory.md',
      ModelEmit.directoryDocs(first), problems);
    ModelEmit.expectText(root, 'docs/data-model-persistence.md',
      ModelEmit.persistenceDocs(pg), problems);
    log.debug("Leaving ModelEmit.check().");
    return problems;
  }

  /**
   * Writes the TypeSpec, the reading pages, a structural `model.json`
   * and `gaps.json`. Class text and OpenAPI documents are not written:
   * a class file would be compiled into the image, and an OpenAPI file
   * rebuilt from pieces would not be the served document.
   *
   * @param root - the package root
   */
  static write(root: string): void {
    log.debug("Entering ModelEmit.write().");
    const deps = directory.DirectoryModel.defaultDeps();
    deps.root = root;
    const collector = new directory.DirectoryModel(deps);
    const catalog = collector.collect();
    const pg = PostgresImport.read(root);
    const maria = MariaDbImport.read(root);
    ModelEmit.writeReadingFiles(root, catalog, pg);
    const tables = pg.tables.map(function (table: any) {
      return {
        name: table.name,
        columns: table.columns.map(function (column: any) {
          return {
            name: column.name,
            sqlType: column.sqlType,
            required: column.required,
            generated: column.generated,
            attributes: column.attributes
          };
        })
      };
    });
    const mariaTables = maria.tables.map(function (table: any) {
      return {
        name: table.name,
        columns: table.columns.map(function (column: any) {
          return {
            name: column.name,
            sqlType: column.sqlType,
            required: column.required,
            generated: column.generated
          };
        })
      };
    });
    fs.writeFileSync(path.join(root, 'models', 'model.json'),
      ModelIr.stable({ directory: catalog, postgres: {
        version: pg.version, tables: tables }, mariadb: {
        version: maria.version, tables: mariaTables } }));
    fs.writeFileSync(path.join(root, 'models', 'gaps.json'),
      ModelIr.stable({ directory: catalog.gaps, postgres: pg.gaps,
        mariadb: maria.gaps }));
    log.debug("Leaving ModelEmit.write().");
  }

  /**
   * `node common/model_emit.js --check`, `--docs`, or `--write`.
   * `--docs` rewrites the TypeSpec and the reading pages.
   *
   * @param argv - arguments after the program name
   */
  static main(argv: string[]): void {
    log.debug("Entering ModelEmit.main().");
    const root = path.join(__dirname, '..');
    if (argv.indexOf('--docs') >= 0) {
      ModelEmit.writeReading(root);
      log.debug("Leaving ModelEmit.main(). Docs.");
      process.exit(0);
    }
    if (argv.indexOf('--check') >= 0) {
      const problems = ModelEmit.check(root);
      if (problems.length > 0) {
        process.stderr.write(problems.join('\n') + '\n');
        log.debug("Leaving ModelEmit.main(). Check failed.");
        process.exit(1);
      }
      log.debug("Leaving ModelEmit.main(). Check passed.");
      process.exit(0);
    }
    if (argv.indexOf('--write') >= 0) {
      ModelEmit.write(root);
      log.debug("Leaving ModelEmit.main(). Wrote.");
      process.exit(0);
    }
    process.stderr.write(
      'Usage: node common/model_emit.js --check|--docs|--write\n');
    log.debug("Leaving ModelEmit.main(). Usage.");
    process.exit(2);
  }
}

export = ModelEmit;

if (require.main === module) {
  ModelEmit.main(process.argv.slice(2));
}
