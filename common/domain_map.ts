// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: domain_map.ts
//
// ---------------------------------------------------------------------------
// A DIRECTORY ENTRY AS THE DOMAIN MODEL SAYS IT MEANS (#1390).
//
// `models/domain/` states what a concept is and where each field is stored;
// the image build writes that to `models/generated/domain.json`. This turns
// an entry's attributes into the concept, by that table and nothing else.
//
// A FIELD MARKED SECRET IS LEFT OUT UNLESS THE CALLER ASKS FOR IT BY NAME.
// A concept is passed around, and the one thing it must not carry by
// accident is a credential.
//
// A VALUE THAT CANNOT BE WHAT THE FIELD SAYS IS LEFT OUT, not guessed at: a
// timestamp that does not parse is an absent timestamp. `missing()` says
// which required fields that left empty.
//
// A LEAF: it requires only `model_tables`.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import ModelTables = require('./model_tables');

const log = bunyan.createLogger({
  name: 'sts-domain-map',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const GENERALIZED_TIME =
  /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?(?:\.\d+)?Z$/;

// Read once: a concept is made per entry, and a report walks every entry.
let concepts: Map<string, any> | null = null;
// Each record concept's fields, worked out once (`recordPlan()`).
const plans = new Map<string, any[]>();

interface FromOptions {
  // Asked for by name: `{ secrets: ['oauth.clientSecrets'] }`.
  secrets?: string[];
  // A derived field's value, by the field's name.
  derived?: Record<string, unknown>;
  // Attributes of another directory object, by that object's id.
  on?: Record<string, Record<string, unknown>>;
}

/**
 * Turns directory entries into domain concepts.
 */
class DomainMap {
  /**
   * The catalogue the image build wrote.
   *
   * @returns the concepts, by name
   */
  static catalogue(): Map<string, any> {
    log.debug("Entering DomainMap.catalogue().");
    if (concepts === null) {
      concepts = new Map<string, any>(ModelTables.file('domain.json').concepts
        .map(function (one: any) {
          return [one.name, one] as [string, any];
        }));
    }
    log.debug("Leaving DomainMap.catalogue().");
    return concepts;
  }

  /**
   * An attribute's values, whatever case the directory answered in.
   *
   * @param attributes - the entry's attributes
   * @param name - the attribute
   * @returns its values, empty when there are none
   */
  static valuesOf(attributes: Record<string, unknown>,
      name: string): string[] {
    log.debug("Entering DomainMap.valuesOf().");
    const wanted = name.toLowerCase();
    const key = Object.keys(attributes || {}).find(function (one) {
      return one.toLowerCase() === wanted;
    });
    const held = key === undefined ? [] : attributes[key];
    const values = (Array.isArray(held) ? held : [held])
      .filter(function (one) {
        return one !== undefined && one !== null;
      }).map(String);
    log.debug("Leaving DomainMap.valuesOf().");
    return values;
  }

  /**
   * One stored value as the field's type.
   *
   * @param type - the field's type
   * @param value - as stored
   * @returns the value, or undefined when it cannot be one
   */
  static typed(type: string, value: string): unknown {
    log.debug("Entering DomainMap.typed().");
    let out: unknown = value;
    if (type === 'boolean') {
      const lower = value.toLowerCase();
      out = lower === 'true' ? true : (lower === 'false' ? false : undefined);
    } else if (type === 'integer') {
      out = /^-?\d+$/.test(value) ? Number(value) : undefined;
    } else if (type === 'dateTime') {
      const parts = GENERALIZED_TIME.exec(value);
      out = parts ? parts[1] + '-' + parts[2] + '-' + parts[3] + 'T' +
        parts[4] + ':' + parts[5] + ':' + (parts[6] || '00') + 'Z' : undefined;
    }
    log.debug("Leaving DomainMap.typed().");
    return out;
  }

  /**
   * A concept from an entry.
   *
   * @param name - the concept
   * @param attributes - the entry's attributes
   * @param options - what the entry alone cannot say
   * @param path - the field path so far, for a nested concept
   * @returns the concept
   */
  static fromEntry<K extends keyof IyaDomain.Concepts>(name: K,
      attributes: Record<string, unknown>, options?: FromOptions,
      path?: string): IyaDomain.Concepts[K] {
    log.debug("Entering DomainMap.fromEntry().");
    const concept = DomainMap.catalogue().get(name);
    if (!concept) {
      log.debug("Leaving DomainMap.fromEntry(). No such concept.");
      throw new TypeError('No domain model is named ' + name);
    }
    const asked = (options && options.secrets) || [];
    const out: any = {};
    concept.fields.forEach(function (field: any) {
      const here = (path ? path + '.' : '') + field.name;
      if (field.embedded) {
        const nested = DomainMap.fromEntry(field.concept, attributes, options,
          here);
        if (Object.keys(nested).length > 0) {
          out[field.name] = nested;
        }
        return;
      }
      if (field.derived) {
        const given = options && options.derived &&
          options.derived[field.name];
        if (given !== undefined) {
          out[field.name] = given;
        }
        return;
      }
      if (field.from.secret && asked.indexOf(here) < 0) {
        return;
      }
      const source = field.from.on ?
        (options && options.on && options.on[field.from.on]) || {} : attributes;
      const values = DomainMap.valuesOf(source, field.from.attr)
        .map(function (one) {
          return DomainMap.typed(field.type, one);
        }).filter(function (one) {
          return one !== undefined;
        });
      if (field.array) {
        if (values.length > 0) {
          out[field.name] = values;
        }
      } else if (values.length > 0) {
        out[field.name] = values[0];
      }
    });
    log.debug("Leaving DomainMap.fromEntry().");
    return out;
  }

  /**
   * A record concept's fields, worked out once: the key split into its path
   * and the JavaScript type a value must have. `fromRecord()` is asked for
   * every session a page draws and every audit row a filter reads, so it
   * does not split a key or look a type up per call.
   *
   * @param name - the concept
   * @returns the plan, or undefined for no such concept
   */
  static recordPlan(name: string): any[] | undefined {
    log.debug("Entering DomainMap.recordPlan().");
    let plan = plans.get(name);
    if (plan === undefined) {
      const concept = DomainMap.catalogue().get(name);
      if (!concept) {
        log.debug("Leaving DomainMap.recordPlan(). No such concept.");
        return undefined;
      }
      plan = concept.fields.map(function (field: any) {
        return {
          name: field.name,
          derived: !!field.derived,
          secret: !!(field.held && field.held.secret),
          path: field.held ? String(field.held.key).split('.') : [],
          type: field.type,
          wanted: field.type === 'integer' ? 'number' : field.type,
          array: !!field.array,
          concept: field.concept
        };
      });
      plans.set(name, plan);
    }
    log.debug("Leaving DomainMap.recordPlan().");
    return plan;
  }

  // A HOT PATH: asked once per field of every record read through a concept,
  // so no Entering/Leaving pair, which would drown the log.
  /**
   * Whether a held value is what a record field says it is.
   *
   * @param step - the field's plan
   * @param value - the value
   * @returns true when it fits
   */
  static fitsRecord(step: any, value: unknown): boolean {
    if (step.type === 'map') {
      return !!value && typeof value === 'object' && !Array.isArray(value);
    }
    if (step.type === 'concept') {
      return !!value && typeof value === 'object';
    }
    return typeof value === step.wanted;
  }

  /**
   * ONE FIELD of a concept from an entry (#1579), for a reader that needs a
   * single fact: a filter over every entry of a walk, or one setting of an
   * application. It reads that field's attribute exactly as `fromEntry()`
   * would, without making the rest of the concept, so a walk costs what it
   * cost when it read the attribute by name. Naming the field is asking for
   * it: a secret field is answered here because the caller named it.
   *
   * @param name - the concept
   * @param field - the field, by its name in the concept
   * @param attributes - the entry's attributes
   * @param options - what the entry alone cannot say
   * @returns the field's value, or undefined when the entry holds none
   */
  static fieldOf<K extends keyof IyaDomain.Concepts,
      F extends keyof IyaDomain.Concepts[K] & string>(name: K, field: F,
      attributes: Record<string, unknown>,
      options?: FromOptions): IyaDomain.Concepts[K][F] {
    log.debug("Entering DomainMap.fieldOf().");
    const concept = DomainMap.catalogue().get(name);
    const found = concept && concept.fields.find(function (one: any) {
      return one.name === field;
    });
    if (!found || !found.from) {
      log.debug("Leaving DomainMap.fieldOf(). No such stored field.");
      throw new TypeError('No stored field ' + field + ' in ' + name);
    }
    const source = found.from.on ?
      (options && options.on && options.on[found.from.on]) || {} : attributes;
    const values = DomainMap.valuesOf(source, found.from.attr)
      .map(function (one) {
        return DomainMap.typed(found.type, one);
      }).filter(function (one) {
        return one !== undefined;
      });
    let out: any;
    if (values.length > 0) {
      out = found.array ? values : values[0];
    }
    log.debug("Leaving DomainMap.fieldOf().");
    return out;
  }

  /**
   * A concept from a record this service's own code keeps. Unlike an entry a
   * record already holds typed values, so a value of another type is left out
   * and nothing is converted.
   *
   * @param name - the concept
   * @param record - the record
   * @param options - what the record alone cannot say
   * @param path - the field path so far, for a nested concept
   * @returns the concept
   */
  static fromRecord<K extends keyof IyaDomain.Concepts>(name: K, record: any,
      options?: FromOptions, path?: string): IyaDomain.Concepts[K] {
    log.debug("Entering DomainMap.fromRecord().");
    const plan = DomainMap.recordPlan(name);
    if (!plan) {
      log.debug("Leaving DomainMap.fromRecord(). No such concept.");
      throw new TypeError('No domain model is named ' + name);
    }
    const asked = (options && options.secrets) || [];
    const out: any = {};
    for (let i = 0; i < plan.length; i++) {
      const step = plan[i];
      if (step.derived) {
        const given = options && options.derived &&
          options.derived[step.name];
        if (given !== undefined) {
          out[step.name] = given;
        }
        continue;
      }
      // The field's path, for a secret asked by name and a nested concept.
      const here = step.secret || step.type === 'concept'
        ? (path ? path + '.' : '') + step.name : '';
      if (step.secret && asked.indexOf(here) < 0) {
        continue;
      }
      let value = record;
      for (let k = 0; k < step.path.length; k++) {
        if (value === undefined || value === null) {
          value = undefined;
          break;
        }
        value = value[step.path[k]];
      }
      if (step.array) {
        if (Array.isArray(value)) {
          const list = [];
          for (let k = 0; k < value.length; k++) {
            if (DomainMap.fitsRecord(step, value[k])) {
              list.push(step.type === 'concept' ? DomainMap.fromRecord(
                step.concept, value[k], options, here) : value[k]);
            }
          }
          out[step.name] = list;
        }
      } else if (DomainMap.fitsRecord(step, value)) {
        out[step.name] = step.type === 'concept' ? DomainMap.fromRecord(
          step.concept, value, options, here) : value;
      }
    }
    log.debug("Leaving DomainMap.fromRecord().");
    return out;
  }

  /**
   * The required fields a concept came out without.
   *
   * @param name - the concept
   * @param value - what `fromEntry()` answered
   * @returns the field names
   */
  static missing(name: keyof IyaDomain.Concepts,
      value: Record<string, unknown>): string[] {
    log.debug("Entering DomainMap.missing().");
    const absent = DomainMap.catalogue().get(name).fields
      .filter(function (field: any) {
        return !field.optional && value[field.name] === undefined;
      }).map(function (field: any) {
        return field.name;
      });
    log.debug("Leaving DomainMap.missing().");
    return absent;
  }
}

export = DomainMap;
