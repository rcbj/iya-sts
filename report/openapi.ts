// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openapi.ts
//
// ---------------------------------------------------------------------------
// THE REPORT API'S OWN DESCRIPTION (#956).
//
// GET /report-api/openapi.json is this document. It names every released
// route, the query document, the parameter bag, the definition, the job
// and the error body. Field meanings, operators, retention, the limit-only
// page and the empty relationship list are the catalog, which this
// document points at rather than copying, so a new field does not have to
// be written twice. It does not describe an offset or a second source:
// both are refused.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-report-openapi' });

const ERROR = { $ref: '#/components/schemas/Error' };

function jsonBody(schema: any): any {
  log.debug("Entering jsonBody().");
  const body = {
    content: {
      'application/json': { schema: schema }
    }
  };
  log.debug("Leaving jsonBody().");
  return body;
}

function answered(description: string, schema: any): any {
  log.debug("Entering answered().");
  const response = {
    description: description,
    content: jsonBody(schema).content
  };
  log.debug("Leaving answered().");
  return response;
}

function refused(description: string): any {
  log.debug("Entering refused().");
  const response = answered(description, ERROR);
  log.debug("Leaving refused().");
  return response;
}

function operation(summary: string, description: string,
                   extras: any): any {
  log.debug("Entering operation().");
  const op = {
    summary: summary,
    description: description,
    security: [{ dpop: ['report:use', 'report:admin'] }],
    responses: {
      '401': refused('invalid_token or invalid_dpop_proof. The code is ' +
        'recorded and is not in the body.'),
      '403': refused('forbidden or insufficient_scope.')
    }
  };
  const keys = Object.keys(extras || {});
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (key === 'responses') {
      const more = extras.responses;
      const codes = Object.keys(more);
      for (let c = 0; c < codes.length; c++) {
        op.responses[codes[c]] = more[codes[c]];
      }
    } else {
      op[key] = extras[key];
    }
  }
  log.debug("Leaving operation().");
  return op;
}

function idParameter(name: string, description: string): any {
  log.debug("Entering idParameter().");
  const parameter = {
    name: name,
    in: 'path',
    required: true,
    description: description,
    schema: { type: 'string', maxLength: 64 }
  };
  log.debug("Leaving idParameter().");
  return parameter;
}

/**
 * The OpenAPI document for the catalog that is loaded now.
 */
class OpenApi {
  /**
   * @param catalog - the catalog, so the description names its sources
   * @returns an OpenAPI 3.0.3 document
   */
  static document(catalog: any): any {
    log.debug("Entering OpenApi.document().");
    const sources = catalog && typeof catalog.list === 'function' ?
      catalog.list() : [];
    const names = sources.map(function (src: any): string {
      return src.id;
    });
    const document = {
      openapi: '3.0.3',
      info: {
        title: 'IYA STS reports',
        version: '1',
        description: 'The reports API. Every operation takes an access ' +
          'token for this realm\'s /report-api carrying report:use or ' +
          'report:admin — the public client sts-report\'s, DPoP-bound and ' +
          'sent as Authorization: DPoP, or an application\'s own ' +
          '(client_credentials) where the application is a member of ' +
          'REPORT_USE or REPORT_ADMIN and declares the scope. The scopes ' +
          'are the permissions of those two roles; the access-control ' +
          'policy decides every definition and job: an owner their own, a ' +
          'report administrator every one, a shared group\'s member reading ' +
          'and running one shared with them, an application only what it ' +
          'defined. A job id is not an authorization: ' +
          'retrieving a result takes the same token. Paths are after the ' +
          'realm prefix; the default realm has none. The catalog is the ' +
          'field reference. A query names one source. An offset, a second ' +
          'source and a SQL statement are invalid_query. Errors are ' +
          'English. The body never carries an STS-REPORT code.'
      },
      paths: {
        '/report-api': {
          get: operation('The report API index',
            'Names the catalog and realms addresses, and carries the ' +
            'service version the application draws in its footer.', {
              responses: {
                '200': answered('The index.',
                  { $ref: '#/components/schemas/Index' })
              }
            })
        },
        '/report-api/openapi.json': {
          get: operation('This document',
            'The description of the released routes.', {
              responses: {
                '200': answered('This OpenAPI document.',
                  { type: 'object' })
              }
            })
        },
        '/report-api/realms': {
          get: operation('The trust realms',
            'The realm this request is in, and every realm with its id, ' +
            'name and path prefix where realms are active (null where ' +
            'they are not). The application draws its realm field and ' +
            'switch from it.', {
              responses: {
                '200': answered('The realms.',
                  { $ref: '#/components/schemas/Realms' })
              }
            })
        },
        '/report-api/groups': {
          get: operation('Search the realm\'s groups',
            'The groups of this realm whose name or DN contains `q` ' +
            '(case-insensitive; empty matches every group), five a page ' +
            'in name order, each with its own `mail` attribute or an ' +
            'empty string. The definition page builds its share list from ' +
            'it; a definition\'s groups are who is emailed its result, at ' +
            'that address (#989).', {
              parameters: [
                { name: 'q', in: 'query', required: false,
                  schema: { type: 'string' } },
                { name: 'page', in: 'query', required: false,
                  schema: { type: 'integer', minimum: 1 } }
              ],
              responses: {
                '200': answered('One page of groups.',
                  { $ref: '#/components/schemas/GroupPage' })
              }
            })
        },
        '/report-api/signals': {
          get: operation('This application\'s Shared Signals inbox',
            'The CAEP and RISC events this application\'s own stream ' +
            'delivered in this realm, newest first, twenty a page by default (#1042). ' +
            'report:admin sees every one (`scope` realm); anybody else ' +
            'sees only the events about themselves (`scope` own), and an ' +
            'application sees none. Each row says what this application ' +
            'did with it: the sessions it ended and the tokens of its own ' +
            'client it revoked for the person named, or why it did ' +
            'nothing. `receiving` is false, with `why`, when nothing can ' +
            'arrive. `per` is at most 100.', {
              parameters: [
                { name: 'page', in: 'query', required: false,
                  schema: { type: 'integer', minimum: 1 } },
                { name: 'per', in: 'query', required: false,
                  schema: { type: 'integer', minimum: 1, maximum: 100 } }
              ],
              responses: {
                '200': answered('One page of the inbox.',
                  { type: 'object' })
              }
            })
        },
        '/report-api/announcements': {
          get: operation('Announcements for everybody signed in',
            'What an administrator broadcast to this application (#1086) ' +
            'after `since` — the `now` this operation answered the tab\'s ' +
            'first ask with — within ssf.announcementKeepS, oldest first. ' +
            'With no `since` it answers only `now`. `everyMs` is how often ' +
            'an open tab asks again.', {
              parameters: [
                { name: 'since', in: 'query', required: false,
                  schema: { type: 'integer', minimum: 0 } }
              ],
              responses: {
                '200': answered('`now`, `everyMs` and `announcements`.',
                  { type: 'object' })
              }
            })
        },
        '/report-api/schedules': {
          get: operation('The scheduled definitions and their runs',
            'Every definition that carries a schedule, with when it next ' +
            'runs, the occurrence it last took, the notes a skipped run ' +
            'left, and its most recent scheduled jobs. A report:use token ' +
            'sees the definitions it owns or is shared; report:admin sees ' +
            'every one in the realm and may name one owner with `owner` ' +
            '(a urn:uuid subject or a username). A report:use token that ' +
            'names another owner is refused with forbidden (403). Paged; ' +
            '`per` is at most 100.', {
              parameters: [
                { name: 'owner', in: 'query', required: false,
                  schema: { type: 'string' } },
                { name: 'page', in: 'query', required: false,
                  schema: { type: 'integer', minimum: 1 } },
                { name: 'per', in: 'query', required: false,
                  schema: { type: 'integer', minimum: 1, maximum: 100 } }
              ],
              responses: {
                '200': answered('The schedules.',
                  { $ref: '#/components/schemas/SchedulePage' }),
                '403': answered('Another owner was named without ' +
                  'report:admin.', { $ref: '#/components/schemas/Error' })
              }
            })
        },
        '/report-api/catalog': {
          get: operation('The report catalog',
            'Every source. Each field has an id, a meaning, a type, ' +
            'whether it can be filtered, sorted or grouped, and its ' +
            'operators. paging is limit. relationships is empty. ' +
            'retention is the English sentence for how long the rows last.',
            {
              responses: {
                '200': answered('The sources.',
                  { $ref: '#/components/schemas/Catalog' })
              }
            })
        },
        '/report-api/catalog/{id}': {
          get: operation('One report source',
            'The same object the catalog lists for one id.', {
              parameters: [idParameter('id', 'The source id.')],
              responses: {
                '200': answered('The source.',
                  { $ref: '#/components/schemas/SourceEnvelope' }),
                '404': refused('unknown_source.')
              }
            })
        },
        '/report-api/queries': {
          post: operation('Run a query',
            'Synchronous when the source is bounded and the limit fits ' +
            'the sync caps. Otherwise 202 and a job. mode sync over the ' +
            'cap is result_too_large. A body over the byte cap or a sync ' +
            'call over the time cap is refused whole.', {
              requestBody: jsonBody(
                { $ref: '#/components/schemas/QueryDocument' }),
              responses: {
                '200': answered('The JSON, CSV or PDF body. JSON is an ' +
                  'object with rows and truncated false. CSV is RFC 4180. ' +
                  'PDF is PDF 1.4.', { type: 'string' }),
                '202': answered('A job was queued.',
                  { $ref: '#/components/schemas/JobEnvelope' }),
                '400': refused('invalid_query, unknown_source is 404, ' +
                  'unknown_field, unsupported_operation, ' +
                  'unsupported_format or result_too_large.'),
                '429': refused('too_many_jobs.')
              }
            })
        },
        '/report-api/definitions': {
          get: operation('List definitions',
            'The caller\'s own definitions, those shared with a group ' +
            'the caller belongs to, and every definition when the token ' +
            'has report:admin. In name order, numbered pages: `page` and ' +
            '`per` (50 unless given, at most 200); the answer carries ' +
            'page, pages, per and total beside the rows.', {
              parameters: [
                { name: 'page', in: 'query', required: false,
                  schema: { type: 'integer', minimum: 1 } },
                { name: 'per', in: 'query', required: false,
                  schema: { type: 'integer', minimum: 1, maximum: 200 } }
              ],
              responses: {
                '200': answered('The definitions.',
                  { $ref: '#/components/schemas/DefinitionList' })
              }
            }),
          post: operation('Create a definition',
            'Stores the document. parameters is the bag a schedule runs ' +
            'with. A missing value can still be type-checked; it is not ' +
            'stored as a dummy, and the schedule will not run until the ' +
            'value is saved.', {
              requestBody: jsonBody(
                { $ref: '#/components/schemas/DefinitionWrite' }),
              responses: {
                '200': answered('The stored definition.',
                  { $ref: '#/components/schemas/DefinitionEnvelope' }),
                '400': refused('invalid_query.')
              }
            })
        },
        '/report-api/definitions/{id}': {
          get: operation('Read a definition',
            'An id the caller may not see is not_found, the same answer ' +
            'as an id that does not exist.', {
              parameters: [idParameter('id', 'The definition id.')],
              responses: {
                '200': answered('The definition.',
                  { $ref: '#/components/schemas/DefinitionEnvelope' }),
                '404': refused('not_found.')
              }
            }),
          post: operation('Replace a definition',
            'The owner, or report:admin. parameters omitted keeps the ' +
            'stored bag. parameters null clears it.', {
              parameters: [idParameter('id', 'The definition id.')],
              requestBody: jsonBody(
                { $ref: '#/components/schemas/DefinitionWrite' }),
              responses: {
                '200': answered('The stored definition.',
                  { $ref: '#/components/schemas/DefinitionEnvelope' }),
                '400': refused('invalid_query.'),
                '404': refused('not_found.')
              }
            }),
          delete: operation('Delete a definition',
            'The owner, or report:admin. A share cannot delete.', {
              parameters: [idParameter('id', 'The definition id.')],
              responses: {
                '200': answered('Deleted.',
                  { type: 'object' }),
                '404': refused('not_found.')
              }
            })
        },
        '/report-api/definitions/{id}/share': {
          post: operation('Share a definition',
            'Replaces the group list. A share can run and retrieve. It ' +
            'cannot edit or delete. Each value is a group DN in this realm.',
            {
              parameters: [idParameter('id', 'The definition id.')],
              requestBody: jsonBody(
                { $ref: '#/components/schemas/ShareWrite' }),
              responses: {
                '200': answered('The definition.',
                  { $ref: '#/components/schemas/DefinitionEnvelope' }),
                '400': refused('invalid_query.'),
                '404': refused('not_found.')
              }
            })
        },
        '/report-api/definitions/{id}/run': {
          post: operation('Run a saved definition',
            'Always a job. The body is a parameter object, not a query ' +
            'document. A key in the body overrides the stored default. ' +
            'An empty body uses the stored defaults. The stored document ' +
            'already carries locale.', {
              parameters: [idParameter('id', 'The definition id.')],
              requestBody: jsonBody(
                { $ref: '#/components/schemas/ParameterBag' }),
              responses: {
                '202': answered('The job.',
                  { $ref: '#/components/schemas/JobEnvelope' }),
                '400': refused('invalid_query or result_too_large.'),
                '404': refused('not_found.'),
                '429': refused('too_many_jobs.')
              }
            })
        },
        '/report-api/jobs': {
          get: operation('List jobs',
            'Newest first, in numbered pages: `page` and `per` (50 unless ' +
            'given, at most 200), with page, pages, per and total beside ' +
            'the rows. A caller may page by cursor instead: `after` is the ' +
            'previous page\'s next id and `limit` its size. A job id in ' +
            'the list is not permission to read a job the token cannot ' +
            'see.', {
              parameters: [{
                name: 'page', in: 'query', required: false,
                schema: { type: 'integer', minimum: 1 }
              }, {
                name: 'per', in: 'query', required: false,
                schema: { type: 'integer', minimum: 1, maximum: 200 }
              }, {
                name: 'after',
                in: 'query',
                required: false,
                description: 'The last id of the previous page, for a ' +
                  'cursor walk; page and per are then ignored.',
                schema: { type: 'string' }
              }, {
                name: 'limit',
                in: 'query',
                required: false,
                description: 'How many jobs a cursor page returns.',
                schema: { type: 'integer' }
              }],
              responses: {
                '200': answered('The page. next is null on the last page.',
                  { $ref: '#/components/schemas/JobList' })
              }
            }),
          post: operation('Queue a job',
            'The same document as a query, forced to a job even when it ' +
            'would have fit in one synchronous call.', {
              requestBody: jsonBody(
                { $ref: '#/components/schemas/QueryDocument' }),
              responses: {
                '202': answered('The job.',
                  { $ref: '#/components/schemas/JobEnvelope' }),
                '400': refused('invalid_query, unknown_field, ' +
                  'unsupported_operation or result_too_large.'),
                '429': refused('too_many_jobs.')
              }
            })
        },
        '/report-api/jobs/{id}': {
          get: operation('Read a job',
            'The owner and report:admin also receive the query document. ' +
            'A hidden id is job_not_found.', {
              parameters: [idParameter('id', 'The job id.')],
              responses: {
                '200': answered('The job.',
                  { $ref: '#/components/schemas/JobEnvelope' }),
                '404': refused('job_not_found.')
              }
            })
        },
        '/report-api/jobs/{id}/cancel': {
          post: operation('Cancel a job',
            'A queued job becomes cancelled. A running job is asked to ' +
            'stop and is not returned in part.', {
              parameters: [idParameter('id', 'The job id.')],
              responses: {
                '200': answered('The job.',
                  { $ref: '#/components/schemas/JobEnvelope' }),
                '404': refused('job_not_found.')
              }
            })
        },
        '/report-api/jobs/{id}/result': {
          get: operation('Download a result',
            'The artifact bytes. The media type is the format. A job id ' +
            'is not enough: the token must be allowed to see the job. ' +
            'Past artifact retention the result is gone.', {
              parameters: [idParameter('id', 'The job id.')],
              responses: {
                '200': answered('The artifact. JSON, CSV or PDF.',
                  { type: 'string', format: 'binary' }),
                '404': refused('job_not_found.'),
                '409': refused('job_not_ready.'),
                '410': refused('result_expired.')
              }
            })
        }
      },
      components: {
        securitySchemes: {
          dpop: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
            description: 'Send the access token as Authorization: DPoP, ' +
              'with a DPoP proof. Bearer is refused for this token.'
          }
        },
        schemas: {
          Error: {
            type: 'object',
            properties: {
              error: { type: 'string' },
              error_description: { type: 'string' }
            }
          },
          Index: {
            type: 'object',
            properties: {
              service: { type: 'string', example: 'report' },
              catalog: { type: 'string' },
              realms: { type: 'string' },
              version: {
                type: 'object',
                properties: {
                  version: { type: 'string' },
                  stamped: { type: 'boolean' },
                  buildInfo: { type: 'string' }
                }
              }
            }
          },
          Realm: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              name: { type: 'string' },
              prefix: { type: 'string',
                description: 'The realm\'s path prefix; empty for the ' +
                  'default realm.' }
            }
          },
          Realms: {
            type: 'object',
            properties: {
              current: { $ref: '#/components/schemas/Realm' },
              realms: { type: 'array', nullable: true,
                items: { $ref: '#/components/schemas/Realm' } }
            }
          },
          Schedule: {
            type: 'object',
            properties: {
              definition: {
                type: 'object',
                properties: {
                  id: { type: 'string' },
                  name: { type: 'string' },
                  owner: { type: 'string' },
                  ownerName: { type: 'string' },
                  schedule: { type: 'string' },
                  scheduleEnabled: { type: 'boolean' },
                  notify: { type: 'boolean' },
                  nextRunAt: { type: 'string', nullable: true },
                  lastSlotAt: { type: 'string', nullable: true },
                  failures: { type: 'array', items: { type: 'object',
                    properties: { at: { type: 'string', nullable: true },
                      description: { type: 'string' } } } }
                }
              },
              jobs: { type: 'array',
                description: 'The most recent scheduled jobs, newest first, ' +
                  'at most five.',
                items: { $ref: '#/components/schemas/Job' } },
              jobCount: { type: 'integer',
                description: 'How many scheduled jobs the definition has ' +
                  'in all.' }
            }
          },
          SchedulePage: {
            type: 'object',
            properties: {
              scope: { type: 'string', enum: ['mine', 'realm'] },
              owner: { type: 'string', nullable: true },
              page: { type: 'integer' },
              pages: { type: 'integer' },
              per: { type: 'integer' },
              total: { type: 'integer' },
              schedules: { type: 'array',
                items: { $ref: '#/components/schemas/Schedule' } }
            }
          },
          Group: {
            type: 'object',
            properties: {
              dn: { type: 'string' },
              name: { type: 'string', description: 'The cn.' },
              mail: { type: 'string',
                description: 'The group\'s own address, or empty.' }
            }
          },
          GroupPage: {
            type: 'object',
            properties: {
              q: { type: 'string' },
              page: { type: 'integer' },
              pages: { type: 'integer' },
              per: { type: 'integer', example: 5 },
              total: { type: 'integer' },
              groups: { type: 'array',
                items: { $ref: '#/components/schemas/Group' } }
            }
          },
          Field: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              type: { type: 'string',
                enum: ['string', 'number', 'boolean', 'timestamp'] },
              meaning: { type: 'string' },
              filter: { type: 'boolean' },
              sort: { type: 'boolean' },
              group: { type: 'boolean' },
              operators: { type: 'array', items: { type: 'string' } },
              indexed: { type: 'array', items: { type: 'string' },
                description: 'The operators the directory answers with ' +
                  'an index, so a filter using one of them reads only the ' +
                  'rows it names. A users query whose filter uses none, ' +
                  'with an order or a count, or on a sealed field, reads ' +
                  'every person: refused in sync mode (result_too_large), ' +
                  'a job in auto mode.' },
              indexedValues: { type: 'array', items: { type: 'string' },
                description: 'The values whose equality the index ' +
                  'answers, when it answers only some: users status is ' +
                  'indexed for locked, and active is everybody else. ' +
                  'Absent when every value is answered.' },
              values: { type: 'array', items: { type: 'string' },
                description: 'Every value the field can hold, when it is ' +
                  'an enumeration; the page draws a dropdown of them for ' +
                  'equals and not equals. Absent for an open field.' }
            }
          },
          Source: {
            type: 'object',
            properties: {
              id: { type: 'string', enum: names },
              anchored: { type: 'boolean',
                description: 'True for a source read from the directory ' +
                  '(users, credentialHolders): a filter on it has to name ' +
                  'a field whose `indexed` list holds the operator — a ' +
                  'leaf of an and, or every arm of an or — or it is ' +
                  'refused as invalid_query; the other fields narrow an ' +
                  'indexed read.' },
              bounded: { type: 'boolean' },
              retention: { type: 'string' },
              paging: { type: 'string', enum: ['limit'] },
              relationships: { type: 'array', maxItems: 0,
                items: { type: 'string' } },
              fields: { type: 'array',
                items: { $ref: '#/components/schemas/Field' } },
              presets: { type: 'array',
                description: 'Predefined queries (#1110): a name and a ' +
                  'whole query document the page offers as a starting ' +
                  'point. Data, not a stored definition: nobody owns one ' +
                  'and nothing runs it until somebody does.',
                items: { type: 'object',
                  properties: {
                    id: { type: 'string' },
                    name: { type: 'string' },
                    document: { type: 'object',
                                additionalProperties: true }
                  } } }
            }
          },
          Catalog: {
            type: 'object',
            properties: {
              sources: { type: 'array',
                items: { $ref: '#/components/schemas/Source' } }
            }
          },
          SourceEnvelope: {
            type: 'object',
            properties: {
              source: { $ref: '#/components/schemas/Source' }
            }
          },
          Filter: {
            type: 'object',
            description: 'A comparison, or and, or, or not. A comparison ' +
              'names field and either value or param, not both. in takes ' +
              'an array. isNull names only the field. The form offers ' +
              'three comparisons and does not offer in; the API does.',
            properties: {
              op: { type: 'string' },
              field: { type: 'string' },
              value: {},
              param: { type: 'string' },
              args: { type: 'array' },
              arg: { type: 'object' }
            }
          },
          QueryDocument: {
            type: 'object',
            required: ['source', 'select'],
            properties: {
              source: { type: 'string', enum: names,
                description: 'One source. An array is invalid_query.' },
              select: { type: 'array', items: { type: 'string' } },
              where: { $ref: '#/components/schemas/Filter' },
              orderBy: { type: 'array', items: { type: 'object',
                properties: {
                  field: { type: 'string' },
                  dir: { type: 'string', enum: ['asc', 'desc'] }
                } } },
              limit: { type: 'integer', minimum: 1 },
              format: { type: 'string', enum: ['json', 'csv', 'pdf'] },
              mode: { type: 'string', enum: ['auto', 'sync', 'async'] },
              locale: { type: 'string', maxLength: 35,
                description: 'A language tag. Omitted means the PDF ' +
                  'chrome is English. The page sends the signed-in user\'s ' +
                  'language. Filipino and Swedish are drawn. Chinese is ' +
                  'named on an English page because the PDF font is WinAnsi.'
              },
              aggregate: { type: 'string', enum: ['count'] },
              groupBy: { type: 'array', items: { type: 'string' } }
            }
          },
          ParameterBag: {
            type: 'object',
            additionalProperties: true,
            description: 'Parameter name to the value the filter uses. ' +
              'A string, a number, a boolean, null, or a short array of ' +
              'those. Not a nested object.'
          },
          DefinitionWrite: {
            type: 'object',
            required: ['name', 'document'],
            properties: {
              name: { type: 'string', maxLength: 120 },
              document: { $ref: '#/components/schemas/QueryDocument' },
              parameters: { $ref: '#/components/schemas/ParameterBag' },
              schedule: { type: 'string',
                description: 'A UTC cron expression, or empty.' },
              scheduleEnabled: { type: 'boolean' },
              notify: { type: 'boolean',
                description: 'Mail the owner when a scheduled run finishes. ' +
                  'The message links to the job. It does not contain rows.' }
            }
          },
          Definition: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              name: { type: 'string' },
              owner: { type: 'string',
                description: 'The owner\'s subject (urn:uuid:…).' },
              ownerName: { type: 'string',
                description: 'The owner\'s display name, or username; ' +
                  'empty for a subject this realm cannot name.' },
              schedule: { type: 'string',
                description: 'A five-field cron expression in UTC, or ' +
                  'empty. The application composes it from a date-time ' +
                  'and weekday boxes.' },
              scheduleEnabled: { type: 'boolean' },
              nextRunAt: { type: 'string', nullable: true,
                description: 'When the enabled schedule next occurs, ' +
                  'ISO-8601 UTC; null when it is off or has no occurrence.' },
              lastSlotAt: { type: 'string', nullable: true,
                description: 'The most recent occurrence the schedule has ' +
                  'taken (queued, or skipped with a note), or null.' },
              notify: { type: 'boolean' },
              editable: { type: 'boolean' },
              createdAt: { type: 'string', format: 'date-time' },
              modifiedAt: { type: 'string', format: 'date-time' },
              document: { $ref: '#/components/schemas/QueryDocument' },
              parameters: { $ref: '#/components/schemas/ParameterBag' },
              groups: { type: 'array', items: { type: 'string' } },
              failures: { type: 'array', items: { type: 'object' } }
            }
          },
          DefinitionEnvelope: {
            type: 'object',
            properties: {
              definition: { $ref: '#/components/schemas/Definition' }
            }
          },
          DefinitionList: {
            type: 'object',
            properties: {
              definitions: { type: 'array',
                items: { $ref: '#/components/schemas/Definition' } },
              page: { type: 'integer' },
              pages: { type: 'integer' },
              per: { type: 'integer' },
              total: { type: 'integer' }
            }
          },
          ShareWrite: {
            type: 'object',
            required: ['groups'],
            properties: {
              groups: { type: 'array', items: { type: 'string' } }
            }
          },
          Job: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              status: { type: 'string', enum: ['queued', 'running',
                'completed', 'failed', 'cancelled', 'expired'] },
              format: { type: 'string' },
              submittedAt: { type: 'string' },
              completedAt: { type: 'string', nullable: true },
              byteSize: { type: 'integer', nullable: true },
              error: { type: 'string', nullable: true,
                description: 'The public error token. A job that exceeded ' +
                  'report.asyncMaxMs carries result_too_large. The body ' +
                  'of a failed job is not partial.' },
              definitionId: { type: 'string', nullable: true },
              definitionName: { type: 'string', nullable: true },
              source: { type: 'string' },
              fields: { type: 'array', items: { type: 'string' } },
              queuedBecause: { type: 'string', nullable: true,
                enum: ['every-person', 'asked', 'limit', 'source', 'run',
                  'schedule'],
                description: 'Why this query is a job: every-person (an ' +
                  'auto-mode query whose filter the directory cannot ' +
                  'answer from an index, so it has to read every person), ' +
                  'asked (mode async, or POST /jobs), limit (auto over ' +
                  'report.syncMaxRows), source (a source that cannot be ' +
                  'read synchronously), run (a saved definition run by ' +
                  'hand) or schedule.' },
              query: { $ref: '#/components/schemas/QueryDocument' }
            }
          },
          JobEnvelope: {
            type: 'object',
            properties: {
              job: { $ref: '#/components/schemas/Job' }
            }
          },
          JobList: {
            type: 'object',
            properties: {
              jobs: { type: 'array',
                items: { $ref: '#/components/schemas/Job' } },
              next: { type: 'string', nullable: true },
              page: { type: 'integer',
                description: 'Absent on a cursor page.' },
              pages: { type: 'integer' },
              per: { type: 'integer' },
              total: { type: 'integer' }
            }
          }
        }
      }
    };
    log.debug("Leaving OpenApi.document().");
    return document;
  }
}

export = OpenApi;
