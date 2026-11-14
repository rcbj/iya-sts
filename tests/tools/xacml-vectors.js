// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: xacml-vectors.js
//
// ---------------------------------------------------------------------------
// THE XACML ENGINE'S VECTORS (#444, the `sts-xacml` crate): what Node's
// engine answers today, for the crate to answer identically. Written by
// `tests/tools/crypto-vectors.js` as `xacml-node.json`
// (`STS_ONLY=xacml`); read by `rust/crates/sts-xacml/tests/node_vectors.rs`
// and `conformance.rs`, the first of which writes `xacml-rust.json` back
// under `STS_WRITE_VECTORS=1`, and `tests/rust_crypto_vectors.js` holds
// THAT to Node through `checkRust()` below.
//
//   suite        every policy document of the OASIS suite, read by
//                `xacml_xml.js` and written back by `writePolicy()` — or the
//                refusal, status and message, of one that does not read
//   conformance  every mandatory case's verdict, as
//                `tests/xacml_conformance.js` reaches it
//   service      every policy this service builds: each template of
//                `xacml_templates.ts` under its defaults and under each
//                parameter changed (the access-control document, the
//                issuance policy with its delegation rules, the FGA and UMA
//                defaults among them), and a UMA owner's share rules
//                (`uma_owner_policy.ts`'s `ruleFor()`), each written, and
//                written again after a read (the writer's fixed point)
//   requests     facts handed to `xacml_request.js`'s builder methods, and
//                the request each one builds
//   access       questions put to `xacml_access_pep.ts`'s decide() over the
//                built-in document, with its request, decision and sentence;
//                what the PIP would read out of the directory is given with
//                each question
//
// Nothing here is secret, but it is generated, so it lives with the rest of
// the vectors and is never committed. It needs the compiled tree: run it in
// the tests image.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const STRING = 'http://www.w3.org/2001/XMLSchema#string';

/**
 * A refusal as the vectors carry it: the XACML status, where the error has
 * one, and the message.
 *
 * @param {any} e - what was thrown
 * @returns {{status: string|null, message: string}} the refusal
 */
function refusal(e) {
  return { status: (e && e.status && e.status.code) || null,
           message: String((e && e.message) || e) };
}

/**
 * Every policy document of the suite, relative to its root, sorted: the
 * `.xml` files that are not a case's Request or Response.
 *
 * @param {string} suiteRoot - `xacml/conformance`
 * @returns {string[]} the relative paths
 */
function suiteDocuments(suiteRoot) {
  const documents = [];
  const walk = function (directory) {
    fs.readdirSync(directory).forEach(function (entry) {
      const full = path.join(directory, entry);
      if (fs.statSync(full).isDirectory()) {
        walk(full);
      } else if (/\.xml$/.test(entry) && !/^(Request|Response)/.test(entry)) {
        documents.push(path.relative(suiteRoot, full));
      }
    });
  };
  walk(suiteRoot);
  return documents.sort();
}

/**
 * Each template under its defaults, then each parameter changed alone — a
 * yes/no flipped, a list cut to its first item and replaced by one it never
 * holds, a free-text parameter given other values — and a UMA owner's
 * document with every kind of share in it.
 *
 * @param {string} ROOT - the repository
 * @param {any} xml - `xacml_xml.js`
 * @param {any} templates - `xacml_templates`
 * @returns {object[]} one row per document
 */
function servicePolicies(ROOT, xml, templates) {
  const service = [];
  const writeBoth = function (row, policy) {
    try {
      row.written = xml.writePolicy(policy);
      row.rewritten = xml.writePolicy(xml.parsePolicy(row.written));
    } catch (e) {
      row.refused = refusal(e);
    }
    service.push(row);
  };
  const alternates = {
    application: ['docs', 'https://rs.example/api?v=1#x', 'a.b (c)*'],
    owner: ['urn:uuid:11111111-2222-4333-8444-555555555555', 'svc/app@X'],
    kind: ['policyset'],
    resource: ['https://api.example/orders'],
    roleAttribute: ['urn:example:role']
  };
  templates.TEMPLATES.forEach(function (template) {
    const variants = [{}];
    template.parameters.forEach(function (parameter) {
      const one = {};
      if (/^(yes|no)$/.test(parameter.dflt)) {
        one[parameter.name] = parameter.dflt === 'yes' ? 'no' : 'yes';
        variants.push(one);
      } else if (parameter.type === 'list') {
        const items = templates.listOf(parameter.dflt);
        one[parameter.name] = items.length ? items[0] : 'x';
        variants.push(one);
        const other = {};
        other[parameter.name] = 'not-a-default, another\nthird';
        variants.push(other);
      } else if (alternates[parameter.name]) {
        alternates[parameter.name].forEach(function (value) {
          const it = {};
          it[parameter.name] = value;
          variants.push(it);
        });
      }
    });
    variants.forEach(function (answers) {
      const built = templates.build(template.id, answers,
                                    { name: template.id });
      if (!built.ok) {
        service.push({ template: template.id, answers: answers,
                       refused: { status: null, message: built.why } });
        return;
      }
      writeBoth({ template: template.id, answers: answers }, built.policy);
    });
  });
  const Owner = require(path.join(ROOT, 'uma', 'uma_owner_policy.js'))
    .UmaOwnerPolicy;
  const shares = [
    { id: 's1', resourceId: 'photo-1', scopes: ['view'], expires: '',
      acr: '', askMe: false,
      recipient: { kind: 'person', value: 'urn:uuid:aaaa' } },
    { id: 's2', resourceId: 'album & co', scopes: ['view', 'edit', 'share'],
      expires: '2027-01-01T00:00:00Z', acr: 'urn:example:acr:mfa',
      askMe: true, recipient: { kind: 'group', value: 'cn=family' } },
    { id: 's3', resourceId: 'doc', scopes: ['read'], expires: '', acr: '',
      askMe: false, recipient: { kind: 'claim', value: 'a@b.example',
                                 claim: 'email' } },
    { id: 's4', resourceId: 'doc', scopes: ['read'], expires: '', acr: '',
      askMe: false, recipient: { kind: 'anyone', value: '' } }
  ];
  const ownerDefault = templates.build('uma-owner-default', {}, {}).policy;
  writeBoth({ template: 'uma-owner-shares', answers: {} },
            Object.assign({}, ownerDefault, {
              rules: ownerDefault.rules.concat(shares.map(function (spec) {
                return Owner.ruleFor(spec);
              }))
            }));
  return service;
}

/**
 * The builder's facts, in the shapes `xacml_request.js` takes them, and what
 * each builds. A row of method `ops` drives the base methods one call at a
 * time; `fgaAccess` is chained after `authzen()`, as the service chains it.
 *
 * @param {any} xacmlRequest - `xacml_request.js`
 * @returns {object} the vocabulary, the closed lists and the rows
 */
function requestVectors(xacmlRequest) {
  const V = xacmlRequest.VOCABULARY;
  const ENV = 'urn:oasis:names:tc:xacml:3.0:attribute-category:environment';
  const ACT = 'urn:oasis:names:tc:xacml:3.0:attribute-category:action';
  const RES = 'urn:oasis:names:tc:xacml:3.0:attribute-category:resource';
  const SUB = 'urn:oasis:names:tc:xacml:1.0:subject-category:access-subject';
  const authzenFacts = {
    subject: { type: 'user', id: 'alice' }, action: { name: 'read' },
    resource: { type: 'document', id: 'doc-1' }, realm: 'acme',
    caller: 'pep-1', application: 'docs', supplied: ['subject.type'],
    attributes: [{ category: RES, attributeId: 'urn:example:owner',
                   dataType: STRING, values: ['alice', 'bob'] }] };
  const rows = [
    { method: 'ops', options: {}, ops: [
      ['principal', 'alice'], ['principal', 'svc', 'application'],
      ['principal', 'bob', 'robot'], ['principal', null],
      ['roles', ['A', 'B']],
      ['target', 'urn:x', 'http://www.w3.org/2001/XMLSchema#anyURI'],
      ['requestedAction', 'GET'], ['requestedScopes', ['openid', 'email']],
      ['client', null], ['client', 'c1'], ['audience', ['https://a', '']],
      ['protocol', 'oauth2'], ['protocol', ''], ['grantType', 'refresh_token'],
      ['mode', 'product'], ['setting', 'oauth2.consentRequired', true],
      ['setting', 'x.y', 'text'], ['setting', 'x.z', null],
      ['stage', 'mint'], ['intermediary', 'actor-1'], ['category', ENV]] },
    { method: 'ops', options: { includeInResult: false, dropEmpty: true,
                                returnPolicyIdList: false }, ops: [
      ['category', SUB], ['principal', ''], ['roles', ['', 'R']],
      ['target', ''], ['setting', 'b', false], ['client', '']] },
    { method: 'authzen', facts: authzenFacts },
    { method: 'authzen', facts: {
      subject: { id: 'bob' }, action: { name: 'write' },
      resource: { id: 'r' }, supplied: [],
      approval: { approvalId: 'ap-1', approvedUntil: '2027-01-01T00:00:00Z',
                  approver: 'carol' } } },
    { method: 'authzen', facts: { approval: { approvedUntil: 'x' } } },
    { method: 'authzen', facts: {} },
    { method: 'fga', facts: {
      realm: 'acme', subject: { id: 'alice', kind: 'user' },
      clientId: 'docs-client', application: 'document-service',
      detailType: 'document_access', definitionDigest: 'abc',
      stage: 'token', action: 'read', grantType: 'authorization_code',
      supplied: ['actions', 'identifier'],
      attributes: [{ category: ACT, attributeId: V.FGA_DETAIL_ACTION,
                     dataType: STRING, values: ['read'] }] } },
    { method: 'fga', facts: { stage: 'par', clientId: 'c',
                              detailType: 't', subject: { id: '' } } },
    { method: 'fga', facts: { stage: 'access', action: 'delete',
                              resourceId: 'doc-9', protocol: 'authzen',
                              subject: { id: 'svc', kind: 'application' } } },
    { method: 'fga', facts: {} },
    { method: 'fgaAccess', facts: { application: 'docs', stage: 'token' },
      authzen: authzenFacts },
    { method: 'fgaAccess', facts: {}, authzen: {} },
    { method: 'uma', facts: {
      realm: 'acme', layer: 'owner', stage: 'upgrade', scope: 'view',
      resource: { id: 'photo-1', type: 'photo', resourceServer: 'rs-1',
                  resourceServerDeclared: true, owner: 'urn:uuid:o',
                  ownerKind: 'user' },
      requestingParty: { id: 'bob', kind: 'user', known: true,
                         isOwner: false, claimSource: 'claim_token',
                         claimIssuer: 'https://idp.example',
                         claimIssuerDeclared: false, acr: 'mfa',
                         groups: ['cn=family', '', 'cn=friends'] },
      clientId: 'client-1', clientGrantDeclared: true,
      claims: { email: ['b@x.example'], age: ['42'], zeta: ['z', 'y'] },
      ticketAgeS: 12.7, rptPresented: true, mode: 'product',
      settings: { 'uma.b': false, 'uma.a': 'text' } } },
    { method: 'uma', facts: { layer: 'fga', scope: 'edit',
                              requestingParty: { id: '' },
                              resource: { ownerKind: 'robot' },
                              ticketAgeS: -1 } },
    { method: 'uma', facts: { layer: 'nope', stage: 'nope',
                              requestingParty: { claimSource: 'other' } } },
    { method: 'uma', facts: { layer: 'owner', ticketAgeS: 0 } }
  ];
  rows.forEach(function (row) {
    const builder = new xacmlRequest.AuthorizationRequest(row.options);
    if (row.method === 'ops') {
      row.ops.forEach(function (op) {
        builder[op[0]].apply(builder, op.slice(1));
      });
    } else if (row.method === 'fgaAccess') {
      builder.authzen(row.authzen).fgaAccess(row.facts);
    } else {
      builder[row.method](row.facts);
    }
    row.built = builder.build();
  });
  return { vocabulary: V, subjectKinds: xacmlRequest.SUBJECT_KINDS,
           fgaStages: xacmlRequest.FGA_STAGES,
           fgaIssuanceStages: xacmlRequest.FGA_ISSUANCE_STAGES,
           umaLayers: xacmlRequest.UMA_LAYERS,
           umaStages: xacmlRequest.UMA_STAGES,
           umaClaimSources: xacmlRequest.UMA_CLAIM_SOURCES,
           constants: { FGA_GRANT_ACTION: xacmlRequest.FGA_GRANT_ACTION,
                        UMA_PERMISSION_ACTION:
                          xacmlRequest.UMA_PERMISSION_ACTION,
                        UMA_FGA_ACTION: xacmlRequest.UMA_FGA_ACTION,
                        UMA_GRANT_TYPE: xacmlRequest.UMA_GRANT_TYPE },
           rows: rows };
}

/**
 * The questions for the access PEP: the portal, the console, the management
 * API's console operations, the owner rule, the report rule and the access
 * request rule, each in its permitted and refused shapes.
 *
 * @param {any} A - `ISSUANCE_ATTRIBUTE`
 * @param {any} model - `xacml_model.js`
 * @returns {object[]} the questions, each with its PIP rows
 */
function accessQuestions(A, model) {
  const S = model.CATEGORY.ACCESS_SUBJECT;
  const R = model.CATEGORY.RESOURCE;
  const BOOL = model.TYPE.BOOLEAN;
  const pip = function (category, attributeId, dataType, values) {
    return { category: category, attributeId: attributeId,
             dataType: dataType, values: values };
  };
  const owned = function (kind, action, attributes) {
    return { kind: kind, id: 'obj-1', action: action,
             requiredRole: action === 'read' ? 'OWNER_READ' : 'OWNER_WRITE',
             attributes: attributes || [], person: 'alice' };
  };
  const ownerPip = function (owners, closed) {
    return [pip(R, A.OBJECT_OWNER, STRING, owners),
            pip(R, A.OBJECT_PROTECTED, BOOL, [closed]),
            pip(S, A.OWNER_IDENTITY, STRING,
                ['uid=alice,ou=people', 'cn=team,ou=groups'])];
  };
  const who = function (name, roles, extra) {
    return Object.assign({ name: name, authenticated: true, roles: roles },
                         extra || {});
  };
  const ownerAsk = function (kind, action, attributes, owners, closed, role) {
    return { resource: 'admin-api', action: action === 'read' ? 'read'
                                                             : 'write',
             subject: who('cli', [role || 'OWNER_WRITE']),
             requiredRoles: [action === 'read' ? 'ADMIN_READ'
                                               : 'ADMIN_WRITE'],
             ownedObject: owned(kind, action, attributes),
             pip: ownerPip(owners, closed) };
  };
  const accessRequest = function (subject, eligible, door, identity) {
    return { id: 'ar-1', requester: 'pep-1', subject: subject,
             subjectType: 'user', action: 'read', resource: 'doc',
             resourceType: 'document', application: 'docs',
             eligible: eligible, door: door, approverIdentity: identity };
  };
  const reportRow = { kind: 'definition', owner: 'urn:uuid:o',
                      groups: ['cn=team,ou=groups'], person: 'alice' };
  const reportRoles = ['REPORT_USE', 'REPORT_ADMIN'];
  return [
    { resource: 'portal', action: 'manage-own', owner: 'alice',
      subject: who('alice', []) },
    { resource: 'portal', action: 'read', owner: 'alice',
      subject: who('bob', ['ADMIN_WRITE']) },
    { resource: 'portal', action: 'read', owner: 'alice',
      subject: who('alice', [], { authenticated: false }) },
    { resource: 'admin-console', action: 'read',
      subject: who('alice', ['ADMIN_READ']),
      requiredRoles: ['ADMIN_READ', 'ADMIN_WRITE'] },
    { resource: 'admin-console', action: 'read',
      subject: who('', []), requiredRoles: ['ADMIN_READ'] },
    { resource: 'scim', action: 'write', subject: who('svc', []) },
    { resource: 'admin-api', action: 'console',
      subject: who('alice', ['ADMIN_CONSOLE'], { label: 'Alice A.' }),
      requiredRoles: ['ADMIN_CONSOLE'], requiredAllRoles: ['ADMIN_READ'] },
    { resource: 'admin-api', action: 'console',
      subject: who('alice', ['ADMIN_CONSOLE', 'ADMIN_READ']),
      requiredRoles: ['ADMIN_CONSOLE'], requiredAllRoles: ['ADMIN_READ'] },
    ownerAsk('group', 'add-member', [], ['cn=team,ou=groups'], 'false'),
    ownerAsk('group', 'add-member', [], ['cn=team,ou=groups'], 'true'),
    ownerAsk('group', 'create', [], ['cn=team,ou=groups'], 'false'),
    ownerAsk('role', 'remove-owner', [], ['uid=alice,ou=people'], 'false'),
    ownerAsk('role', 'remove-owner', [],
             ['uid=alice,ou=people', 'uid=bob,ou=people'], 'false'),
    ownerAsk('application', 'set', ['appName', 'oauthScope'],
             ['uid=alice,ou=people'], 'false'),
    ownerAsk('application', 'set', ['appName', 'description'],
             ['uid=alice,ou=people'], 'false'),
    ownerAsk('service-account', 'read', [], ['cn=team,ou=groups'], 'false',
             'OWNER_READ'),
    ownerAsk('service-account', 'rotate-password', [], ['cn=other'],
             'false'),
    { resource: 'report-api', action: 'run', owner: 'urn:uuid:o',
      subject: who('urn:uuid:u', ['REPORT_USE'], { kind: 'user' }),
      requiredRoles: reportRoles, reportObject: reportRow,
      pip: [pip(S, A.OWNER_IDENTITY, STRING, ['cn=team,ou=groups'])] },
    { resource: 'report-api', action: 'write', owner: 'urn:uuid:o',
      subject: who('urn:uuid:u', ['REPORT_USE'], { kind: 'user' }),
      requiredRoles: reportRoles, reportObject: reportRow,
      pip: [pip(S, A.OWNER_IDENTITY, STRING, ['cn=team,ou=groups'])] },
    { resource: 'report-api', action: 'write', owner: 'urn:uuid:o',
      subject: who('app-1', ['REPORT_ADMIN'], { kind: 'application' }),
      requiredRoles: reportRoles,
      reportObject: { kind: 'job', owner: 'urn:uuid:o', person: '' } },
    { resource: 'report-api', action: 'write', owner: 'urn:uuid:o',
      subject: who('urn:uuid:a', ['REPORT_ADMIN'], { kind: 'user' }),
      requiredRoles: reportRoles,
      reportObject: { kind: 'job', owner: 'urn:uuid:o', person: 'adm' } },
    { resource: 'report-api', action: 'read', owner: 'urn:uuid:o',
      subject: who('urn:uuid:o', ['REPORT_USE'], { kind: 'robot' }),
      requiredRoles: reportRoles, reportObject: reportRow },
    { resource: 'authzen-access-request', action: 'approve-access-request',
      subject: who('carol', [], { label: 'Carol' }),
      requiredRoles: ['APPROVER'],
      accessRequestObject: accessRequest('bob', true, 'portal',
                                         ['carol', 'uid=carol,ou=people']) },
    { resource: 'authzen-access-request', action: 'approve-access-request',
      subject: who('bob', ['APPROVER']), requiredRoles: ['APPROVER'],
      accessRequestObject: accessRequest('bob', true, 'portal', ['bob']) },
    { resource: 'authzen-access-request', action: 'approve-access-request',
      subject: who('root', ['ADMIN_WRITE']),
      accessRequestObject: accessRequest('bob', false, 'admin-api',
                                         ['root']) },
    { resource: 'authzen-access-request', action: 'approve-access-request',
      subject: who('root', ['ADMIN_WRITE']),
      accessRequestObject: accessRequest('bob', false, 'portal', ['root']) },
    { resource: 'authzen-access-request', action: 'approve-access-request',
      subject: who('pep-1', [], { label: 'The PEP' }),
      accessRequestObject: accessRequest('bob', true, 'portal',
                                         ['pep-1']) }
  ];
}

/**
 * The access PEP's decide(), over the built-in document and stand-in
 * registers: the roles held are exactly the subject's `roles`, the resource
 * requires exactly `requiredRoles`, and the PIP answers what the question's
 * `pip` rows say (the owner, protection and identity facts the real PIP
 * reads out of the directory).
 *
 * @param {string} ROOT - the repository
 * @param {any} templates - `xacml_templates`
 * @param {any} model - `xacml_model.js`
 * @param {any} datatypes - `xacml_datatypes.js`
 * @param {any} pdp - `xacml_pdp.js`
 * @returns {object} the rows
 */
function accessVectors(ROOT, templates, model, datatypes, pdp) {
  const accessPep = require(path.join(ROOT, 'xacml', 'xacml_access_pep.js'));
  let pipRows = [];
  const quiet = { debug: function () {}, error: function () {},
                  info: function () {} };
  const pep = new accessPep.XacmlAccessPep({
    log: quiet,
    config: { value: function () { return undefined; } },
    audit: { audit: function () {} },
    errorCodes: { tag: function (code) { return code + ' '; } },
    roles: { rolesOf: function () { return []; } },
    applications: { requiredRolesOf: function () { return []; } },
    templates: templates,
    model: model,
    pdp: pdp,
    pip: { resolverFor: function () {
      return function (designator) {
        const out = [];
        pipRows.forEach(function (row) {
          if (row.category === designator.category &&
              row.attributeId === designator.attributeId &&
              row.dataType === designator.dataType) {
            row.values.forEach(function (v) {
              out.push(datatypes.parseValue(row.dataType, v));
            });
          }
        });
        return out;
      };
    } },
    store: { read: function () { return null; },
             parseDocument: function () { throw new Error('unused'); },
             repository: function () { return {}; } },
    monitor: { record: function () {} }
  });
  const rows = accessQuestions(templates.ISSUANCE_ATTRIBUTE, model)
    .map(function (asked) {
      pipRows = asked.pip || [];
      const held = (asked.subject.roles || []).slice(0);
      const required = (asked.requiredRoles || []).map(String);
      const request = pep.buildRequest(asked, held, required);
      const answer = pep.decide(asked);
      return { asked: asked, held: held, required: required,
               request: request, allowed: answer.allowed,
               decision: answer.decision, why: answer.why };
    });
  return { name: pep.accessPolicyName(), rows: rows };
}

/**
 * Builds `xacml-node.json`.
 *
 * @param {string} ROOT - the repository
 * @returns {object} the vectors
 */
function build(ROOT) {
  const xml = require(path.join(ROOT, 'xacml', 'xacml_xml.js'));
  const model = require(path.join(ROOT, 'xacml', 'xacml_model.js'));
  const datatypes = require(path.join(ROOT, 'xacml', 'xacml_datatypes.js'));
  const pdp = require(path.join(ROOT, 'xacml', 'xacml_pdp.js'));
  const templates = require(path.join(ROOT, 'xacml', 'xacml_templates.js'));
  const xacmlRequest = require(path.join(ROOT, 'xacml', 'xacml_request.js'));
  const conformance = require(path.join(ROOT, 'tests',
                                        'xacml_conformance.js'));
  const suiteRoot = path.join(ROOT, 'xacml', 'conformance');
  const suite = suiteDocuments(suiteRoot).map(function (relative) {
    const text = fs.readFileSync(path.join(suiteRoot, relative), 'utf8');
    try {
      return { path: relative,
               written: xml.writePolicy(xml.parsePolicy(text)) };
    } catch (e) {
      return { path: relative, refused: refusal(e) };
    }
  });
  const mandatory = path.join(suiteRoot, 'mandatory');
  const cases = fs.readdirSync(mandatory).filter(function (entry) {
    return fs.statSync(path.join(mandatory, entry)).isDirectory();
  }).sort().map(function (name) {
    let verdict;
    try {
      verdict = conformance.runCase(
        conformance.readCase(path.join(mandatory, name)));
    } catch (e) {
      verdict = { ok: false, why: 'the runner threw: ' + e.message };
    }
    return { name: name, ok: verdict.ok, why: verdict.why };
  });
  // A document carrying a declaration, which the one XML parser refuses
  // before it reads anything (ASVS 5.0.0 1.5.2, `common/xml_parser.js`).
  const declared = ['<!DOCTYPE Policy><Policy/>',
                    '<Policy><!-- <!ENTITY x "y"> --></Policy>',
                    '<?xml version="1.0"?>\n<! doctype x>'].map(
    function (text) {
      try {
        xml.parsePolicy(text);
        return { text: text, refused: null };
      } catch (e) {
        return { text: text, refused: refusal(e) };
      }
    });
  return { suite: suite, declared: declared, conformance: cases,
           service: servicePolicies(ROOT, xml, templates),
           requests: requestVectors(xacmlRequest),
           access: accessVectors(ROOT, templates, model, datatypes, pdp) };
}

/**
 * Re-runs one `requests` row through Node's builder.
 *
 * @param {any} xacmlRequest - `xacml_request.js`
 * @param {any} row - the row, as `requestVectors()` wrote it
 * @returns {any} the request Node builds for it now
 */
function rebuild(xacmlRequest, row) {
  const builder = new xacmlRequest.AuthorizationRequest(row.options);
  if (row.method === 'ops') {
    row.ops.forEach(function (op) {
      builder[op[0]].apply(builder, op.slice(1));
    });
  } else if (row.method === 'fgaAccess') {
    builder.authzen(row.authzen).fgaAccess(row.facts);
  } else {
    builder[row.method](row.facts);
  }
  return builder.build();
}

/**
 * THE OTHER DIRECTION: what the Rust crate produced (`xacml-rust.json`),
 * held to Node's engine now. Each document Rust wrote reads in Node and
 * Node writes it back to the same bytes, which are the bytes Node writes
 * from the source; each access-control document Rust BUILT reads in Node
 * and is written as Node's template writes it; each request Rust built is
 * the request Node's builder builds from the same facts (bar the one pinned
 * difference, `"undefined"`); and each access request Rust built, evaluated
 * by Node's PDP over Node's built-in document with the same PIP answers,
 * gets the decision Rust reached.
 *
 * @param {string} ROOT - the repository
 * @param {any} rust - `xacml-rust.json`
 * @param {any} node - `xacml-node.json`
 * @param {(ok: boolean, what: string, detail?: string) => void} check -
 *   the runner's assertion
 */
function checkRust(ROOT, rust, node, check) {
  const xml = require(path.join(ROOT, 'xacml', 'xacml_xml.js'));
  const datatypes = require(path.join(ROOT, 'xacml', 'xacml_datatypes.js'));
  const pdp = require(path.join(ROOT, 'xacml', 'xacml_pdp.js'));
  const templates = require(path.join(ROOT, 'xacml', 'xacml_templates.js'));
  const xacmlRequest = require(path.join(ROOT, 'xacml', 'xacml_request.js'));
  const suiteRoot = path.join(ROOT, 'xacml', 'conformance');
  const wrong = [];
  let read = 0;
  rust.suite.forEach(function (row) {
    const source = fs.readFileSync(path.join(suiteRoot, row.path), 'utf8');
    let mine = null;
    try {
      mine = xml.writePolicy(xml.parsePolicy(source));
    } catch (e) {
      mine = null;
      if (row.written !== undefined ||
          row.refused.message !== String((e && e.message) || e)) {
        wrong.push(row.path + ': Rust ' + JSON.stringify(row.refused ||
                   'read it') + ', Node refused: ' + e.message);
      }
      return;
    }
    if (row.written === undefined) {
      wrong.push(row.path + ': Rust refused what Node reads');
      return;
    }
    let again = null;
    try {
      again = xml.writePolicy(xml.parsePolicy(row.written));
    } catch (e) {
      wrong.push(row.path + ': what Rust wrote does not read: ' + e.message);
      return;
    }
    if (row.written !== mine || again !== mine) {
      wrong.push(row.path + ': written differently');
    }
    read += 1;
  });
  check(wrong.length === 0 && rust.suite.length === node.suite.length,
        'xacml: every suite document Rust wrote (' + read + ' of ' +
        rust.suite.length + ', the rest refused alike) reads in Node and is ' +
        'what Node writes', wrong.slice(0, 5).join('; '));

  const documents = [];
  rust.service.forEach(function (row) {
    const built = templates.build(row.template, row.answers,
                                  { name: row.template });
    let mine = '';
    try {
      mine = xml.writePolicy(xml.parsePolicy(row.document));
    } catch (e) {
      documents.push(JSON.stringify(row.answers) + ': does not read: ' +
                     e.message);
      return;
    }
    const want = xml.writePolicy(built.policy);
    if (mine !== want || row.written !== want) {
      documents.push(JSON.stringify(row.answers));
    }
  });
  check(documents.length === 0 && rust.service.length >= 20,
        'xacml: every access-control document Rust built (' +
        rust.service.length + ') is, read and written by Node, the ' +
        'document Node\'s template builds', documents.join('; '));

  const requests = [];
  let pinned = 0;
  rust.requests.forEach(function (row) {
    const facts = node.requests.rows[row.row];
    const want = JSON.stringify(rebuild(xacmlRequest, facts));
    const got = JSON.stringify(row.built);
    if (got === want) {
      return;
    }
    if (facts.method !== 'ops' &&
        want.replace(/"lexical":"undefined"/g, '"lexical":""') === got) {
      pinned += 1;
      return;
    }
    requests.push(row.row + ' (' + facts.method + ')');
  });
  check(requests.length === 0 &&
        rust.requests.length === node.requests.rows.length,
        'xacml: every request the Rust builder built (' +
        rust.requests.length + ') is the one Node\'s builds from the same ' +
        'facts, ' + pinned + ' pinned (Node spells a missing AuthZEN ' +
        'action or resource "undefined")', requests.join(', '));

  const policy = templates.build('access-control', {},
                                 { name: node.access.name }).policy;
  const decisions = [];
  rust.access.forEach(function (row) {
    const asked = node.access.rows[row.row];
    const pip = asked.asked.pip || [];
    const answer = pdp.evaluate(policy, row.request, {
      repository: {},
      resolver: function (designator) {
        const out = [];
        pip.forEach(function (one) {
          if (one.category === designator.category &&
              one.attributeId === designator.attributeId &&
              one.dataType === designator.dataType) {
            one.values.forEach(function (v) {
              out.push(datatypes.parseValue(one.dataType, v));
            });
          }
        });
        return out;
      }
    });
    if (answer.decision !== row.decision || row.why !== asked.why ||
        JSON.stringify(row.request) !== JSON.stringify(asked.request)) {
      decisions.push(row.row + ': Node ' + answer.decision + ', Rust ' +
                     row.decision);
    }
  });
  check(decisions.length === 0 &&
        rust.access.length === node.access.rows.length,
        'xacml: every access request Rust built (' + rust.access.length +
        ') gets, from Node\'s PDP over Node\'s built-in document, the ' +
        'decision Rust reached, with Node\'s sentence',
        decisions.join('; '));
}

module.exports = { build: build, checkRust: checkRust };
