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
        description: 'The reports API. Every operation takes a DPoP-bound ' +
          'access token for the public client sts-report, resource this ' +
          'realm\'s /report-api, scope report:use or report:admin, sent ' +
          'as Authorization: DPoP. A job id is not an authorization: ' +
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
            'has report:admin.', {
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
            'Newest first. after is the previous page\'s next id. A job ' +
            'id in the list is not permission to read a job the token ' +
            'cannot see.', {
              parameters: [{
                name: 'after',
                in: 'query',
                required: false,
                description: 'The last id of the previous page.',
                schema: { type: 'string' }
              }, {
                name: 'limit',
                in: 'query',
                required: false,
                description: 'How many jobs to return.',
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
                  'a job in auto mode.' }
            }
          },
          Source: {
            type: 'object',
            properties: {
              id: { type: 'string', enum: names },
              bounded: { type: 'boolean' },
              retention: { type: 'string' },
              paging: { type: 'string', enum: ['limit'] },
              relationships: { type: 'array', maxItems: 0,
                items: { type: 'string' } },
              fields: { type: 'array',
                items: { $ref: '#/components/schemas/Field' } }
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
              owner: { type: 'string' },
              schedule: { type: 'string' },
              scheduleEnabled: { type: 'boolean' },
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
                items: { $ref: '#/components/schemas/Definition' } }
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
              next: { type: 'string', nullable: true }
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
