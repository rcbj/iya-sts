// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: report_examples.ts
//
// ---------------------------------------------------------------------------
// AN EXAMPLE ON EVERY `/report-api` OPERATION THAT CAN CARRY ONE (#1483, on
// #1475's rules). What replays them is Schemathesis's Examples phase, with
// the fuzz person's real token, so each is valid against its schema and
// HARMLESS IF EXECUTED: a read of one row, or an act on a definition or job
// nothing holds. A definition's example names a source that does not exist,
// so nothing is stored and no schedule is ever made. `POST /definitions` and
// `POST /jobs` are therefore refused whole, and a query names a source and
// asks for one row at most. `tests/api_request_names.js` holds every operation
// to having one that fits its schema. An operation with no parameter and no
// body is not listed.
// ---------------------------------------------------------------------------

type Json = any;

const NO_DEFINITION = 'noSuchDefinition';
const NO_JOB = 'noSuchJob';
const A_PAGE = { page: 1, per: 20 };
const A_READ = { source: 'users', select: ['username'], limit: 1,
                 mode: 'sync', format: 'json' };
const REFUSED_DOCUMENT = { source: 'no-such-source', limit: 1 };

const EXAMPLES: Record<string, Json> = {
  'GET /report-api/groups': { query: { q: 'no-such-group', page: 1 } },
  'GET /report-api/signals': { query: A_PAGE },
  'GET /report-api/announcements': { query: { since: 0 } },
  'GET /report-api/schedules': { query: A_PAGE },
  'GET /report-api/catalog/{id}': { path: { id: 'users' } },
  'POST /report-api/queries': { body: A_READ },
  'GET /report-api/definitions': { query: A_PAGE },
  'POST /report-api/definitions':
    { body: { name: 'example', document: REFUSED_DOCUMENT } },
  'GET /report-api/definitions/{id}': { path: { id: NO_DEFINITION } },
  'POST /report-api/definitions/{id}': { path: { id: NO_DEFINITION },
    body: { name: 'example', document: REFUSED_DOCUMENT } },
  'DELETE /report-api/definitions/{id}': { path: { id: NO_DEFINITION } },
  'POST /report-api/definitions/{id}/share':
    { path: { id: NO_DEFINITION }, body: { groups: [] } },
  'POST /report-api/definitions/{id}/run':
    { path: { id: NO_DEFINITION }, body: {} },
  'GET /report-api/jobs': { query: A_PAGE },
  'POST /report-api/jobs': { body: REFUSED_DOCUMENT },
  'GET /report-api/jobs/{id}': { path: { id: NO_JOB } },
  'POST /report-api/jobs/{id}/cancel': { path: { id: NO_JOB } },
  'GET /report-api/jobs/{id}/result': { path: { id: NO_JOB } }
};

export = EXAMPLES;
