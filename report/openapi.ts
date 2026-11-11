// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openapi.ts
//
// ---------------------------------------------------------------------------
// THE REPORTS API OPENAPI DOCUMENT (#956, #1390).
//
// GET /report-api/openapi.json is this document, and every answer of the
// Reports API is held to it (#1353, `common/response_models.ts`). It is written
// in `models/api/report.tsp`, with the reasoning, and the image build generates
// the file read here. Two things depend on the catalog that is loaded, so they
// are bound here: the enumeration of source ids, and the sentence that lists
// them.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import ModelTables = require('../common/model_tables');

const log = bunyan.createLogger({ name: 'sts-report-openapi' });

/**
 * The Reports API OpenAPI document for the catalog that is loaded now.
 */
class OpenApi {
  /**
   * @param catalog - the catalog, so the description names its sources
   * @returns an OpenAPI 3.0.3 document
   */
  static document(catalog: any): any {
    log.debug("Entering OpenApi.document().");
    const document = OpenApi.bind(
      ModelTables.file('openapi.report.json'), catalog);
    log.debug("Leaving OpenApi.document().");
    return document;
  }

  /**
   * Binds a generated document to a catalog.
   *
   * @param generated - the document as the model states it
   * @param catalog - the catalog
   * @returns the document, with the catalog's source ids in place
   */
  static bind(generated: any, catalog: any): any {
    log.debug("Entering OpenApi.bind().");
    const sources = catalog && typeof catalog.list === 'function' ?
      catalog.list() : [];
    const names = sources.map(function (src: any): string {
      return src.id;
    });
    const document = JSON.parse(JSON.stringify(generated)
      .split('{{sources}}').join(names.join(', ')));
    const id = document.components.schemas.Source.properties.id;
    delete id['x-iya-catalog-sources'];
    id.enum = names;
    log.debug("Leaving OpenApi.bind().");
    return document;
  }
}

export = OpenApi;
