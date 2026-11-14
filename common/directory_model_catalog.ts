// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_model_catalog.ts
//
// ---------------------------------------------------------------------------
// THE DIRECTORY OBJECTS WITH NO MODULE OF THEIR OWN (#1390).
//
// People, groups, attribute sources, the operational attributes and the
// registers that keep their record as one JSON value are written in TypeSpec
// under `models/directory/`. No code owns a table for them. This reads what
// the build generated, in the shape the collector takes.
//
// A LIBRARY. No route.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import ModelTables = require('./model_tables');

const log = bunyan.createLogger({
  name: 'sts-directory-catalog',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const IDS = ['operational', 'person', 'group', 'attributeSource', 'oidfed',
  'claimProvider', 'kerberosTrust', 'trustAnchor', 'signerTrustAnchor'];

/**
 * One catalogued object.
 */
interface CatalogObject {
  id: string;
  container: string;
  section: string;
  objectClasses: any[];
  attributes: any[];
  note: string;
}

/**
 * The objects no module owns.
 */
class DirectoryModelCatalog {
  /**
   * Every catalogued object, from the generated tables.
   *
   * @returns the objects, in a fixed order
   */
  static objects(): CatalogObject[] {
    log.debug("Entering DirectoryModelCatalog.objects().");
    const objects = IDS.map(function (id) {
      const table = ModelTables.schema(id);
      return {
        id: id,
        container: table.container,
        section: table.section,
        note: table.note,
        objectClasses: table.objectClasses,
        attributes: table.attributes
      };
    });
    log.debug("Leaving DirectoryModelCatalog.objects().");
    return objects;
  }
}

export = DirectoryModelCatalog;
