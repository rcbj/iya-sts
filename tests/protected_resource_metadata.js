'use strict';
//
// File: protected_resource_metadata.js
//
// ===========================================================================
// RFC 9728 AS AN IMPORT: WHAT A DOCUMENT IS READ AS, AND WHAT IS REFUSED
// (2026-09-13).
//
// `/admin/applications/new` can create an application from a protected
// resource's metadata document, and `oauth-oidc/protected_resource_metadata.js`
// is the reading. What is asserted here is what no request can choose or no
// reply can show:
//
//   A. the section 2 members — every refusal of a malformed document, by code,
//      an extension member KEPT rather than dropped, and signed_metadata decoded
//      and not applied;
//   B. section 3.1's well-known URL both ways, and section 3.3's verdict;
//   C. which addresses are internal — including both spellings of an
//      IPv4-mapped IPv6 address, which is the classic way round a check;
//   D. the authorization-server comparison, and the realm's list built from a
//      request;
//   E. the plan: a scope under the resource losing its prefix, a scope that is
//      not keeping it, a scope that cannot be a permission left out;
//   F. the two mode-gated MUSTs, warned in development and refused in product;
//   G. the FETCH, against a server in this process: exclusivity of the three
//      sources, a redirect not followed, a status refused, the size cap, the
//      kill switch — and in product mode a loopback URL refused WITHOUT A
//      REQUEST REACHING THE SERVER, which is the assertion the pinning is for;
//   H. the document the third tab leaves;
//   I. multipart/form-data, which the console's CSRF check reads an upload's
//      token out of;
//   J. the create-time checks the permission attributes did not have, and the
//      two new attributes, against a stub directory.
//
// The over-HTTP half — the page's two round trips and the operation — is driven
// by `tests/vendored/sts_admin_api_operations.js`'s example replay and
// `sts_admin_console.js`'s form walk.
// ===========================================================================

delete process.env.CONFIG_FILE;

const http = require('http');

const log = require('bunyan').createLogger({
  name: 'protected_resource_metadata', level: process.env.LOG_LEVEL || 'info' });

// A setting changed for the length of one call and put back with clear, never
// with a second set — tests/CLAUDE.md's rule about `source: override`.
async function withSetting(config, key, value, fn) {
  log.debug("Entering withSetting(). key=" + key);
  const set = config.setOverride(key, value);
  if (set && set.ok === false) {
    throw new Error('could not set ' + key + ': ' +
                    JSON.stringify(set.errors || set));
  }
  try {
    log.debug("Leaving withSetting().");
    return await fn();
  } finally {
    config.clearOverride(key);
  }
}

function codeOf(errorCodes, result) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return errorCodes.codeOf(result) || '(no code)';
}

// A server that answers whatever the current test asks of it, and counts.
function startServer() {
  log.debug("Entering startServer().");
  const state = { hits: 0, handler: null };
  const server = http.createServer(function (req, res) {
    state.hits += 1;
    state.handler(req, res);
  });
  log.debug("Leaving startServer().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      state.port = server.address().port;
      state.server = server;
      resolve(state);
    });
  });
}

const GOOD = {
  resource: 'https://api.example.com',
  authorization_servers: ['https://sts.example.com/',
                          'https://other.example.org'],
  scopes_supported: ['https://api.example.com/read', 'write', 'bad scope',
                     'write'],
  bearer_methods_supported: ['header', 'carrier-pigeon'],
  resource_name: 'Widgets',
  'resource_name#fr': 'Gadgets',
  dpop_bound_access_tokens_required: true,
  x_vendor_extension: { anything: [1, 2] },
  signed_metadata: Buffer.from('{"alg":"RS256"}').toString('base64url') + '.' +
                   Buffer.from('{"resource":"https://evil.example"}')
                         .toString('base64url') + '.c2ln'
};

module.exports = {
  name: 'protected_resource_metadata',
  describe: 'RFC 9728 imports: the members, section 3.3, internal addresses, ' +
            'the plan, the fetch policy and the create-time checks',
  run: async function (t) {
    log.debug("Entering run().");
    const config = require('../common/config');
    const errorCodes = require('../common/error_codes');
    const helpers = require('../common/helpers');
    const applications = require('../common/applications');
    const prm = require('../oauth-oidc/protected_resource_metadata');

    // -----------------------------------------------------------------------
    t.log.info('=== A. the section 2 members ===');
    // -----------------------------------------------------------------------
    const parsed = prm.parseDocument(JSON.stringify(GOOD));
    t.check(parsed.ok, 'a document with every kind of member parses',
            JSON.stringify(parsed.errors || ''));
    t.check(parsed.extensions.indexOf('x_vendor_extension') >= 0,
            'a member RFC 9728 does not define is listed as an extension');
    // Listed is not kept: a reading that listed the member and dropped it
    // passed the line above, and the document the entry stores would then be
    // a different one from the document that was loaded.
    const analysedGood = prm.analyse(JSON.stringify(GOOD), { source: 'pasted' },
                                     { authorizationServers: [] });
    t.check(JSON.stringify(parsed.document.x_vendor_extension) ===
            JSON.stringify(GOOD.x_vendor_extension) &&
            JSON.parse(analysedGood.compact).x_vendor_extension !== undefined,
            'AND IT IS KEPT, in the document and in what the entry would ' +
            'store');
    t.equal(parsed.members.filter(function (m) {
      return m.member === 'resource_name#fr';
    })[0].type, 'string', 'a language-tagged member (section 2.1) is read as ' +
            'the member it tags');
    t.check(parsed.signedMetadata && parsed.signedMetadata.verified === false &&
            parsed.signedMetadata.applied === false &&
            parsed.signedMetadata.claims.resource === 'https://evil.example',
            'signed_metadata is DECODED and neither verified nor applied');
    t.equal(parsed.document.resource, 'https://api.example.com',
            'and its claims did not replace the document\'s own resource');
    t.check(parsed.warnings.some(function (w) {
      return /carrier-pigeon/.test(w);
    }), 'a bearer method RFC 6750 does not define is warned about');

    const refusals = [
      ['', 'STS-REG-0076', 'an empty document'],
      ['not json', 'STS-REG-0076', 'a document that is not JSON'],
      ['[1,2]', 'STS-REG-0076', 'a JSON array'],
      ['{"__proto__":{"x":1},"resource":"https://a.example"}', 'STS-REG-0076',
       'a polluting key'],
      ['{"scopes_supported":["read"]}', 'STS-REG-0077', 'no resource'],
      ['{"resource":"api.example.com"}', 'STS-REG-0077',
       'a resource that is not a URL'],
      ['{"resource":"https://a.example#frag"}', 'STS-REG-0077',
       'a resource with a fragment'],
      ['{"resource":"https://a.example","scopes_supported":"read"}',
       'STS-REG-0077', 'a list member given as a string'],
      ['{"resource":"https://a.example","authorization_servers":["x"]}',
       'STS-REG-0077', 'an authorization server that is not a URL'],
      ['{"resource":"https://a.example",' +
       '"dpop_bound_access_tokens_required":"true"}', 'STS-REG-0077',
       'a boolean given as a string'],
      ['{"resource":"https://a.example","signed_metadata":"abc"}',
       'STS-REG-0077', 'signed_metadata that is not a JWT']
    ];
    refusals.forEach(function (row) {
      const result = prm.parseDocument(row[0]);
      t.check(!result.ok && codeOf(errorCodes, result) === row[1],
              'REFUSED: ' + row[2] + ' (' + row[1] + ')',
              codeOf(errorCodes, result) + ' ' +
              JSON.stringify(result.errors || ''));
    });
    await withSetting(config, 'federation.maxResponseBytes', 1024,
                      async function () {
      const big = prm.parseDocument(JSON.stringify({
        resource: 'https://a.example', resource_name: 'x'.repeat(2000) }));
      t.check(!big.ok && codeOf(errorCodes, big) === 'STS-REG-0076',
              'a document over federation.maxResponseBytes is refused');
    });

    // -----------------------------------------------------------------------
    t.log.info('=== B. section 3.1 and section 3.3 ===');
    // -----------------------------------------------------------------------
    t.equal(prm.wellKnownUrlFor('https://api.example.com'),
            'https://api.example.com/.well-known/oauth-protected-resource',
            'a resource with no path');
    t.equal(prm.wellKnownUrlFor('https://api.example.com/'),
            'https://api.example.com/.well-known/oauth-protected-resource',
            'and the terminating slash after the host is removed first');
    t.equal(prm.wellKnownUrlFor('https://api.example.com/v1/x?q=1'),
            'https://api.example.com/.well-known/oauth-protected-resource' +
            '/v1/x?q=1', 'a path and a query go after the suffix');
    t.equal(JSON.stringify(prm.resourcesForWellKnownUrl(
      'https://api.example.com/.well-known/oauth-protected-resource')),
            JSON.stringify(['https://api.example.com',
                            'https://api.example.com/']),
            'an empty path is either spelling of the resource');
    t.equal(prm.resourcesForWellKnownUrl('https://api.example.com/meta.json'),
            null, 'a URL that is not well-known yields no resource');
    t.check(prm.resourceCheckFor(GOOD, '').checked === false,
            'a pasted document is NOT checked, and says why');
    const matched = prm.resourceCheckFor(GOOD,
      'https://api.example.com/.well-known/oauth-protected-resource');
    t.check(matched.checked && matched.matches, 'a matching fetch matches');
    const mismatched = prm.resourceCheckFor(GOOD,
      'https://api.example.com/.well-known/oauth-protected-resource/other');
    t.check(mismatched.checked && !mismatched.matches,
            'a document describing another resource on the same host does ' +
            'not — the attack section 3.3 exists for');

    // -----------------------------------------------------------------------
    t.log.info('=== C. internal addresses ===');
    // -----------------------------------------------------------------------
    // One mutant is recorded rather than counted: removing the module's own
    // decoding of `::ffff:7f00:1` changes nothing, because node's BlockList
    // already matches an IPv4-mapped IPv6 address against the IPv4 rules. The
    // two mapped spellings are asserted anyway, since that is the property.
    [['127.0.0.1', true], ['10.1.2.3', true], ['172.31.255.255', true],
     ['172.32.0.1', false], ['192.168.0.1', true], ['169.254.169.254', true],
     ['100.64.0.1', true], ['0.0.0.0', true], ['224.0.0.1', true],
     ['::1', true], ['fe80::1', true], ['fd12:3456::1', true],
     ['::ffff:127.0.0.1', true], ['::ffff:7f00:1', true],
     ['::ffff:a00:1', true], ['64:ff9b::a00:1', true],
     ['8.8.8.8', false], ['2606:4700:4700::1111', false],
     ['93.184.216.34', false]].forEach(function (row) {
      const problem = prm.internalAddressProblem(row[0]);
      t.equal(!!problem, row[1], row[0] + (row[1] ? ' is internal'
                                                   : ' is not internal'));
    });

    // -----------------------------------------------------------------------
    t.log.info('=== D. the authorization servers ===');
    // -----------------------------------------------------------------------
    const realmServers = [{ id: 'default', issuer: 'https://sts.example.com' },
                          { id: 'tenant1',
                            issuer: 'https://sts.example.com/tenant1' }];
    const compared = prm.compareAuthorizationServers(GOOD, realmServers);
    t.equal(compared.listed, 2, 'both listed issuers are compared');
    t.check(compared.rows[0].matched &&
            compared.rows[0].authorizationServer === 'default',
            'an issuer differing only by a trailing slash is this realm\'s');
    t.check(!compared.rows[1].matched && compared.anyUnmatched &&
            !compared.allMatched, 'a foreign issuer is not, and the whole ' +
            'comparison says so');
    t.check(prm.compareAuthorizationServers({ resource: 'https://a.example' },
            realmServers).listed === 0, 'a document naming none compares ' +
            'nothing rather than matching nothing');
    const fakeReq = { protocol: 'https', secure: true,
                      headers: { host: 'sts.example.com' },
                      get: function (name) {
                        return this.headers[String(name).toLowerCase()];
                      } };
    const built = prm.authorizationServersOf(fakeReq);
    t.check(built.length >= 1 && built[0].id === 'default' &&
            /sts\.example\.com/.test(built[0].issuer),
            'the realm\'s list is built from the address a request arrived ' +
            'on', JSON.stringify(built));

    // -----------------------------------------------------------------------
    t.log.info('=== E. the plan ===');
    // -----------------------------------------------------------------------
    const plan = prm.planFor(GOOD);
    t.equal(plan.name, GOOD.resource, 'the resource is the default name');
    t.equal(plan.baseUri, GOOD.resource, 'and the permission base URI');
    t.equal(plan.audience, GOOD.resource, 'and the audience');
    t.equal(plan.identifier, plan.clientId,
            'the identifier defaults to the client_id');
    t.check(/^[A-Za-z0-9_-]{6,}/.test(plan.clientId.replace(/^.*?-?client-/,
                                                              '')),
            'the client_id is random base64url', plan.clientId);
    t.check(prm.planFor(GOOD).clientId !== plan.clientId,
            'and a second plan gets a different one');
    const read = plan.permissions[0];
    t.check(read.name === 'read' && read.stripped && read.sameAsAdvertised,
            'a scope under the resource loses the prefix, and its identifier ' +
            'is the scope as advertised');
    const write = plan.permissions[1];
    t.check(write.name === 'write' && !write.stripped &&
            !write.sameAsAdvertised &&
            write.id === 'https://api.example.com/write',
            'a scope not under it is kept, and the plan says what a client ' +
            'has to ask for');
    t.check(!!plan.permissions[2].problem, 'a scope with a space cannot be ' +
            'a permission');
    t.check(plan.permissions[3].duplicate, 'a repeated scope is a duplicate');
    t.equal(plan.permissionLines.join(','), 'read,write',
            'the lines the form is filled with leave out both');
    t.check(plan.warnings.some(function (w) { return /trailing `\/`/.test(w); }),
            'the base-with-a-slash against the audience-without-one is warned');
    t.equal(plan.protocols.join(','), 'oauth2', 'OAuth 2.0 is ticked');

    // -----------------------------------------------------------------------
    t.log.info('=== F. the two mode-gated MUSTs ===');
    // -----------------------------------------------------------------------
    const httpDoc = JSON.stringify({ resource: 'http://api.example.com' });
    const ctx = { authorizationServers: realmServers };
    const devHttp = prm.analyse(httpDoc, { source: 'pasted' }, ctx);
    t.check(devHttp.ok && devHttp.warnings.some(function (w) {
      return /https scheme/.test(w);
    }), 'development: a non-https resource is imported with a warning');
    const wrongUrl = 'https://api.example.com/.well-known/' +
                     'oauth-protected-resource/elsewhere';
    const devMismatch = prm.analyse(JSON.stringify(GOOD),
                                    { source: 'url', url: wrongUrl }, ctx);
    t.check(devMismatch.ok && devMismatch.warnings.some(function (w) {
      return /section 3\.3/.test(w);
    }), 'development: a section 3.3 mismatch is imported with a warning');
    await withSetting(config, 'global.mode', 'product', async function () {
      const prodHttp = prm.analyse(httpDoc, { source: 'pasted' }, ctx);
      t.check(!prodHttp.ok && codeOf(errorCodes, prodHttp) === 'STS-REG-0088',
              'product: a non-https resource is REFUSED');
      const prodMismatch = prm.analyse(JSON.stringify(GOOD),
                                       { source: 'url', url: wrongUrl }, ctx);
      t.check(!prodMismatch.ok &&
              codeOf(errorCodes, prodMismatch) === 'STS-REG-0087',
              'product: a section 3.3 mismatch is REFUSED');
      const prodGood = prm.analyse(JSON.stringify(GOOD), { source: 'pasted' },
                                   ctx);
      t.check(prodGood.ok, 'product: a pasted conforming document is fine');
    });

    // -----------------------------------------------------------------------
    t.log.info('=== G. the fetch ===');
    // -----------------------------------------------------------------------
    const none = await prm.load({}, ctx);
    t.equal(codeOf(errorCodes, none), 'STS-REG-0074',
            'no source is refused');
    const two = await prm.load({ document: '{}', url: 'https://x.example' },
                               ctx);
    t.equal(codeOf(errorCodes, two), 'STS-REG-0075',
            'two sources are refused rather than one being chosen');
    const uploaded = await prm.load({ file: { name: 'prm.json',
                                              text: JSON.stringify(GOOD) } },
                                    ctx);
    t.check(uploaded.ok && uploaded.source === 'upload' &&
            uploaded.filename === 'prm.json', 'an upload loads and is named');
    const asObject = await prm.load({ document: GOOD }, ctx);
    t.check(asObject.ok && asObject.source === 'pasted',
            'a JSON caller may send the document as an object');

    const server = await startServer();
    const origin = 'http://127.0.0.1:' + server.port;
    const local = JSON.stringify({ resource: origin + '/api',
                                   scopes_supported: ['read'] });
    try {
      await withSetting(config, 'federation.outboundAllowInsecure', true,
                        async function () {
        server.handler = function (req, res) {
          if (req.url === '/.well-known/oauth-protected-resource/api') {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(local);
          } else if (req.url === '/moved') {
            res.writeHead(302, { location: '/.well-known/' +
                                           'oauth-protected-resource/api' });
            res.end();
          } else if (req.url === '/big') {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ resource: origin + '/api',
                                     resource_name: 'x'.repeat(5000) }));
          } else {
            res.writeHead(404);
            res.end();
          }
        };
        const fetched = await prm.load({ url: origin + '/.well-known/' +
                                              'oauth-protected-resource/api' },
                                       ctx);
        t.check(fetched.ok && fetched.source === 'url' &&
                fetched.resourceCheck.checked &&
                fetched.resourceCheck.matches,
                'development: a document on loopback is fetched and matches ' +
                'its well-known URL', JSON.stringify(fetched.errors || ''));
        const moved = await prm.load({ url: origin + '/moved' }, ctx);
        t.equal(codeOf(errorCodes, moved), 'STS-REG-0082',
                'a redirect is not followed');
        const missing = await prm.load({ url: origin + '/nothing' }, ctx);
        t.equal(codeOf(errorCodes, missing), 'STS-REG-0083',
                'a 404 is refused');
        await withSetting(config, 'federation.maxResponseBytes', 1024,
                          async function () {
          const big = await prm.load({ url: origin + '/big' }, ctx);
          t.equal(codeOf(errorCodes, big), 'STS-REG-0084',
                  'a body over the cap is refused while it is read');
        });
        await withSetting(config, 'federation.outbound', false,
                          async function () {
          const before = server.hits;
          const off = await prm.load({ url: origin + '/.well-known/' +
                                            'oauth-protected-resource/api' },
                                     ctx);
          t.check(codeOf(errorCodes, off) === 'STS-REG-0078' &&
                  server.hits === before,
                  'federation.outbound off: refused, and nothing was dialled');
        });
        await withSetting(config, 'global.mode', 'product', async function () {
          const before = server.hits;
          const blocked = await prm.load({ url: origin + '/.well-known/' +
                                                'oauth-protected-resource/' +
                                                'api' }, ctx);
          t.check(codeOf(errorCodes, blocked) === 'STS-REG-0080' &&
                  server.hits === before,
                  'PRODUCT: a URL on loopback is refused and NO REQUEST ' +
                  'REACHED THE SERVER', codeOf(errorCodes, blocked) + ' hits ' +
                  (server.hits - before));
          const byName = await prm.load({ url: 'http://localhost:' +
                                               server.port + '/x' }, ctx);
          t.check(codeOf(errorCodes, byName) === 'STS-REG-0080' &&
                  server.hits === before,
                  'PRODUCT: and a NAME resolving to loopback is refused the ' +
                  'same way');
        });
      });
      const insecureOff = await prm.load({ url: origin + '/x' }, ctx);
      t.equal(codeOf(errorCodes, insecureOff), 'STS-REG-0079',
              'plain http with federation.outboundAllowInsecure off is ' +
              'refused before anything is dialled');
    } finally {
      server.server.close();
    }

    // -----------------------------------------------------------------------
    t.log.info('=== H. the document the third tab leaves ===');
    // -----------------------------------------------------------------------
    const edited = JSON.parse(prm.documentFromForm({
      metadata: JSON.stringify(GOOD),
      'metadata.resource_name': '  Renamed  ',
      'metadata.scopes_supported': 'read\n\n  write \n',
      'metadata.bearer_methods_supported': '',
      'metadata.dpop_bound_access_tokens_required': 'false',
      'metadata.signed_metadata': 'x.y.z',
      'metadata.x_vendor_extension': 'overwritten?'
    }));
    t.equal(edited.resource_name, 'Renamed', 'a string member is edited');
    t.equal(JSON.stringify(edited.scopes_supported), '["read","write"]',
            'a list member is one per line, blank lines dropped');
    t.check(!('bearer_methods_supported' in edited),
            'an emptied box removes the member');
    t.equal(edited.dpop_bound_access_tokens_required, false,
            'a boolean is a JSON boolean');
    t.equal(edited.signed_metadata, GOOD.signed_metadata,
            'signed_metadata is never edited');
    t.equal(JSON.stringify(edited.x_vendor_extension),
            JSON.stringify(GOOD.x_vendor_extension),
            'an extension member is kept as it was');
    t.equal(edited.resource, GOOD.resource,
            'a member with no box posted is left alone');
    t.equal(prm.documentFromForm({}), '', 'no document, no value');

    // -----------------------------------------------------------------------
    t.log.info('=== I. multipart/form-data ===');
    // -----------------------------------------------------------------------
    const boundary = '----sts-test-boundary';
    const fileBytes = Buffer.from('{"resource":"https://a.example"}\r\n' +
                                  '--' + boundary + 'not-a-delimiter\r\n',
                                  'utf8');
    const raw = Buffer.concat([
      Buffer.from('--' + boundary + '\r\nContent-Disposition: form-data; ' +
                  'name="action"\r\n\r\nload-resource-metadata\r\n' +
                  '--' + boundary + '\r\nContent-Disposition: form-data; ' +
                  'name="csrf_token"\r\n\r\ntoken-value\r\n' +
                  '--' + boundary + '\r\nContent-Disposition: form-data; ' +
                  'name="file"; filename="doc.json"\r\nContent-Type: ' +
                  'application/json\r\n\r\n', 'utf8'),
      fileBytes,
      Buffer.from('\r\n--' + boundary + '--\r\n', 'utf8')
    ]);
    const req = { headers: { 'content-type': 'multipart/form-data; ' +
                                             'boundary=' + boundary },
                  rawBody: raw, body: raw.toString('utf8') };
    const parts = helpers.multipartParts(req);
    t.equal(parts.length, 3, 'three parts');
    t.equal(parts[2].filename, 'doc.json', 'the file part keeps its name');
    t.check(parts[2].data.equals(fileBytes),
            'the file bytes survive exactly, a boundary-like line inside ' +
            'them included');
    const fields = helpers.parseBody(req);
    t.equal(fields.csrf_token, 'token-value',
            'parseBody() answers an upload\'s fields, which is where the ' +
            'console\'s CSRF check finds the token');
    t.equal(fields.action, 'load-resource-metadata',
            'and its action');
    t.equal(helpers.multipartParts({ headers: { 'content-type':
                                                'multipart/form-data' },
                                     rawBody: raw }).length, 0,
            'no boundary, no parts');

    // -----------------------------------------------------------------------
    t.log.info('=== J. the create-time checks ===');
    // -----------------------------------------------------------------------
    const beforeDirectory = applications.directoryInstalled();
    const entries = {};
    applications.setDirectory({
      allApplications: function () {
        log.debug("Entering allApplications().");
        log.debug("Leaving allApplications().");
        return Object.keys(entries).map(function (id) { return entries[id]; });
      },
      readApplication: function (identifier) {
        log.debug("Entering readApplication().");
        log.debug("Leaving readApplication().");
        return entries[identifier] || null;
      },
      countApplications: function () {
        log.debug("Entering countApplications().");
        log.debug("Leaving countApplications().");
        return Object.keys(entries).length;
      },
      writeApplication: function (identifier, attributes) {
        log.debug("Entering writeApplication().");
        entries[identifier] = { dn: 'cn=' + identifier, origin: 'test',
                                createdAt: '', modifiedAt: '', operational: [],
                                attributes: attributes };
        log.debug("Leaving writeApplication().");
        return true;
      }
    });
    try {
      const create = function (identifier, fields) {
        log.debug("Entering create().");
        log.debug("Leaving create().");
        return applications.createApplication({ identifier: identifier,
                                                protocols: ['oauth2'],
                                                fields: fields });
      };
      const cases = [
        [{ oauthPermissionBaseUri: 'https://a.example',
           oauthPermission: ['bad scope'] }, 'STS-REG-0013',
         'a permission name that is not a scope token'],
        [{ oauthPermissionBaseUri: 'https://a.example',
           oauthPermission: ['read', 'read|again'] }, 'STS-REG-0014',
         'the same permission twice'],
        [{ oauthPermission: ['read'] }, 'STS-REG-0015',
         'permissions with no base URI'],
        [{ oauthPermissionBaseUri: 'not a uri' }, 'STS-REG-0012',
         'a base URI that is not absolute'],
        [{ oauthResourceMetadata: '[1]' }, 'STS-REG-0089',
         'a stored document that is not an object with a resource'],
        [{ oauthResourceMetadataUrl: 'ftp://a.example/x' }, 'STS-REG-0089',
         'a stored URL that is not http or https']
      ];
      cases.forEach(function (row, index) {
        const result = create('prm-refused-' + index, row[0]);
        t.check(!result.ok && codeOf(errorCodes, result) === row[1] &&
                !entries['prm-refused-' + index],
                'a CREATE refuses ' + row[2] + ' (' + row[1] + ') and writes ' +
                'nothing', codeOf(errorCodes, result) + ' ' +
                JSON.stringify(result.errors || ''));
      });
      const good = create('prm-created', {
        oauthClientId: ['prm-created'],
        oauthPermissionBaseUri: 'https://api.example.com',
        oauthAudience: ['https://api.example.com'],
        oauthPermission: ['read', 'write|Change widgets'],
        oauthResourceMetadata: JSON.stringify(GOOD),
        oauthResourceMetadataUrl: 'https://api.example.com/.well-known/' +
                                  'oauth-protected-resource'
      });
      t.check(good.ok, 'a create carrying everything an import proposes is ' +
              'accepted', JSON.stringify(good.errors || ''));
      const stored = (entries['prm-created'] || {}).attributes || {};
      const lower = {};
      Object.keys(stored).forEach(function (k) {
        lower[k.toLowerCase()] = stored[k];
      });
      t.check(JSON.stringify(lower.oauthresourcemetadata || '')
                  .indexOf('api.example.com') >= 0 &&
              JSON.stringify(lower.oauthpermission || '').indexOf('write') >= 0,
              'the document and the permissions are on the entry',
              JSON.stringify(Object.keys(stored)));
      const badUpdate = applications.updateApplication('prm-created', {
        attribute: 'oauthResourceMetadata', mode: 'set', value: '{"a":1}' });
      t.equal(codeOf(errorCodes, badUpdate), 'STS-REG-0089',
              'an UPDATE refuses a document with no resource too');
    } finally {
      applications.setDirectory(beforeDirectory);
    }
    log.debug("Leaving run().");
  }
};
