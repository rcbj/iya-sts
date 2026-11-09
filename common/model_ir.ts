// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_ir.ts
//
// ---------------------------------------------------------------------------
// THE JSON INTERMEDIATE REPRESENTATION FOR THE COMMON MODEL (#1390).
//
// TypeSpec is the language the models are written in, and
// `tests/model_typespec.js` compiles them. The importers build this JSON
// form, and the emitters write from it. A directory model, an API model and a table stay
// different values: nothing here guesses that one is a projection of
// another.
//
// `stable()` is for the directory and persistence catalogues, whose key
// order is the emitter's choice. It is the wrong tool for an OpenAPI
// document: that document's bytes are the builder's, and sorting its keys
// would make a different file.
//
// A LIBRARY. No route, and not registered from `protocol_stack.ts`.
// Failures here are test failures. They are not `STS-*` codes: nothing
// in this module serves a request or writes the audit log.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');

const log = bunyan.createLogger({
  name: 'sts-model-ir',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

/**
 * One gap the importers record instead of inventing a fact.
 */
interface ModelGap {
  code: string;
  object: string;
  name: string;
  detail: string;
}

/**
 * Orders plain objects by key and drops `undefined`, leaving arrays in
 * the order the importer produced.
 */
class ModelIr {
  /**
   * Builds one gap row. Empty object and name sort before named ones.
   *
   * @param code - the gap kind
   * @param detail - what is missing, with no invented replacement
   * @param objectName - the model the gap belongs to
   * @param name - the attribute, operation or column
   * @returns the row
   */
  static gap(code: string, detail: string, objectName?: string,
      name?: string): ModelGap {
    log.debug("Entering ModelIr.gap().");
    const row = {
      code: code,
      object: objectName || '',
      name: name || '',
      detail: detail
    };
    log.debug("Leaving ModelIr.gap().");
    return row;
  }

  /**
   * Sorts gap rows so two collects of the same tree write one text.
   *
   * @param gaps - the rows, unsorted
   * @returns a new array
   */
  static sortGaps(gaps: ModelGap[]): ModelGap[] {
    log.debug("Entering ModelIr.sortGaps().");
    const sorted = gaps.slice().sort(function (a, b) {
      return ModelIr.gapKey(a).localeCompare(ModelIr.gapKey(b));
    });
    log.debug("Leaving ModelIr.sortGaps().");
    return sorted;
  }

  /**
   * The sort key of one gap.
   *
   * @param gap - the row
   * @returns code, object, name and detail joined
   */
  static gapKey(gap: ModelGap): string {
    log.debug("Entering ModelIr.gapKey().");
    const key = [gap.code, gap.object, gap.name, gap.detail].join('\0');
    log.debug("Leaving ModelIr.gapKey().");
    return key;
  }

  /**
   * A JSON rendering whose object keys are sorted. Arrays keep their
   * order, because the order of attributes and of DDL statements is part
   * of the model.
   *
   * @param value - any JSON value
   * @returns the text
   */
  static stable(value: unknown): string {
    log.debug("Entering ModelIr.stable().");
    const text = JSON.stringify(ModelIr.order(value));
    log.debug("Leaving ModelIr.stable().");
    return text;
  }

  /**
   * The value `stable()` stringifies.
   *
   * @param value - any JSON value
   * @returns the ordered copy
   */
  static order(value: unknown): unknown {
    log.debug("Entering ModelIr.order().");
    if (Array.isArray(value)) {
      const items = value.map(function (item) {
        return ModelIr.order(item);
      });
      log.debug("Leaving ModelIr.order(). An array.");
      return items;
    }
    if (!value || typeof value !== 'object') {
      log.debug("Leaving ModelIr.order(). A scalar.");
      return value;
    }
    const source = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    Object.keys(source).sort().forEach(function (key) {
      if (source[key] !== undefined) {
        out[key] = ModelIr.order(source[key]);
      }
    });
    log.debug("Leaving ModelIr.order().");
    return out;
  }
}

export = ModelIr;
