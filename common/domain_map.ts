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
    const concepts = ModelTables.file('domain.json').concepts;
    const byName = new Map<string, any>(concepts.map(function (one: any) {
      return [one.name, one] as [string, any];
    }));
    log.debug("Leaving DomainMap.catalogue().");
    return byName;
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
  static fromEntry(name: string, attributes: Record<string, unknown>,
      options?: FromOptions, path?: string): any {
    log.debug("Entering DomainMap.fromEntry().");
    const concept = DomainMap.catalogue().get(name);
    if (!concept) {
      log.debug("Leaving DomainMap.fromEntry(). No such concept.");
      throw new TypeError('No domain model is named ' + name);
    }
    const asked = (options && options.secrets) || [];
    const out: Record<string, unknown> = {};
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
  static fromRecord(name: string, record: any, options?: FromOptions,
      path?: string): any {
    log.debug("Entering DomainMap.fromRecord().");
    const concept = DomainMap.catalogue().get(name);
    if (!concept) {
      log.debug("Leaving DomainMap.fromRecord(). No such concept.");
      throw new TypeError('No domain model is named ' + name);
    }
    const asked = (options && options.secrets) || [];
    const out: Record<string, unknown> = {};
    const fits = function (field: any, value: unknown): boolean {
      const wanted = field.type === 'integer' ? 'number' : field.type;
      return field.type === 'concept' ?
        !!value && typeof value === 'object' : typeof value === wanted;
    };
    concept.fields.forEach(function (field: any) {
      const here = (path ? path + '.' : '') + field.name;
      if (field.derived) {
        const given = options && options.derived &&
          options.derived[field.name];
        if (given !== undefined) {
          out[field.name] = given;
        }
        return;
      }
      if (field.held.secret && asked.indexOf(here) < 0) {
        return;
      }
      const value = String(field.held.key).split('.')
        .reduce(function (holder: any, key: string) {
          return holder === undefined || holder === null ?
            undefined : holder[key];
        }, record);
      const convert = function (one: unknown): unknown {
        return field.type === 'concept' ?
          DomainMap.fromRecord(field.concept, one, options, here) : one;
      };
      if (field.array) {
        if (Array.isArray(value)) {
          out[field.name] = value.filter(function (one) {
            return fits(field, one);
          }).map(convert);
        }
      } else if (fits(field, value)) {
        out[field.name] = convert(value);
      }
    });
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
  static missing(name: string, value: Record<string, unknown>): string[] {
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
