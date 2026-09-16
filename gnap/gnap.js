// @ts-check
'use strict';
//
// File: gnap.js
//
// ---------------------------------------------------------------------------
// GNAP: THE GRANT NEGOTIATION AND AUTHORIZATION PROTOCOL (RFC 9635) AND ITS
// RESOURCE SERVER CONNECTIONS (RFC 9767), AS ROUTES.
//
// Requiring this module registers every GNAP endpoint (rule 1) — and requires
// `gnap_interact.js`, which registers the pages a resource owner sees, so this
// family has ONE line in the require order the way XACML's does. Every decision
// is `gnap_grants.js`'s and `gnap_rs.js`'s; what is here is transport: which
// path, which method, which JSON and which HTTP status.
//
// ---------------------------------------------------------------------------
// THE ENDPOINTS, AND WHERE THE AUTHORIZATION SERVER CONCEPT COMES IN.
//
//   POST    /gnap, /:as/gnap          the grant endpoint (section 2)
//   OPTIONS /gnap, /:as/gnap          discovery (section 9)
//   POST|PATCH|DELETE /gnap/continue/:grant   continuation (section 5)
//   POST|DELETE /gnap/token/:handle   token management (section 6)
//   GET     /.well-known/gnap-as-rs[/:as]     RS-facing discovery (RFC 9767 3.1)
//   POST    /gnap/introspect          introspection (RFC 9767 3.3)
//   POST    /gnap/resource            resource set registration (RFC 9767 3.4)
//   GET     /gnap/keys                token-format verification material
//   GET     /gnap/zcap/controller     the ZCAP-LD controller document
//   GET|POST /gnap/rs/resource        the demonstration resource server
//
// **A NAMED AUTHORIZATION SERVER IS THE OAUTH SUBSYSTEM'S, NOT A SECOND ONE.**
// `/:as/gnap` selects the same profile `/:as/oauth2/*` does
// (`oauth-oidc/authorization_servers.js`), created on first sight exactly as
// that module's `ensure()` does for OAuth, and that profile's GNAP members
// (section 9's discovery fields) are what the grant endpoint enforces. A grant
// made at one authorization server records it, its tokens' `iss` is that
// server's grant endpoint (RFC 9767 section 3.3: "Grant endpoint URL of the AS
// that issued this token"), and the interaction hash (section 4.2.3) is
// computed over THAT URI — so a client that talks to two named servers gets two
// distinguishable authorization servers, which is section 11.12's defence
// against mix-up attacks.
//
// **THE ONE PATH THAT NEEDED A GUARD IS `/:as/gnap`.** It is two segments where
// OAuth's prefixed routes are three, so it would match `POST /admin/gnap` and
// create an authorization server named "admin" on sight. A reserved first
// segment falls through (`next()`) to whatever else would have answered — in
// the worst case express's own 404, which `tests/vendored/sts_metadata.js`
// reads as unrouted, which it is.
//
// ---------------------------------------------------------------------------
// ERROR RESPONSES (section 3.6, RFC 9767 section 3.5).
//
// `{ "error": { "code", "description" } }`, with `continue` beside it where the
// grant can still be continued (section 3.6 allows it and section 5.1's example
// shows it for `user_denied`). The HTTP status is not specified by either RFC;
// this service uses 401 where the caller failed to authenticate (a key proof, a
// continuation or management token), 403 where an authenticated request was
// refused by the resource owner or policy, 404 where a feature is switched
// off, and 400 for the rest — and RFC 9767 section 3.5 says 400 for every
// RS-facing error, which is what those routes send. The STS error code is on
// the response object (errorCodes.mark) and NEVER in the body.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const config = require('../common/config');
const { log } = require('../common/helpers');
const errorCodes = require('../common/error_codes');
const validation = require('../common/validation');
const authorizationServers = require('../oauth-oidc/authorization_servers');
const grants = require('./gnap_grants');
const rs = require('./gnap_rs');
const tokens = require('./gnap_tokens');
const zcap = require('./token_zcap');
const signals = require('./gnap_signals');

const vz = validation.z;
const vt = validation.types;

const AS_PARAMS = vz.object({ as: vt.opt(vt.identifier) });
const GRANT_PARAMS = vz.object({ grant: vt.base64url });
const HANDLE_PARAMS = vz.object({ handle: vt.base64url });

const STATUS_FOR = {
  invalid_client: 401,
  invalid_resource_server: 400,
  user_denied: 403,
  request_denied: 403,
  unknown_user: 403
};

function gnapError(res, status, code, description, extra) {
  // error-code: none — the helper's trace line, not a call to it.
  log.debug("Entering gnapError(). status=" + status + ", error=" + code);
  const body = Object.assign({ error: { code: code,
                                        description: description } },
                             extra || {});
  res.status(status).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(body));
  // error-code: none — the helper's trace line, not a call to it.
  log.debug("Leaving gnapError().");
}

function sendResult(res, result) {
  log.debug("Entering sendResult().");
  if (result.status === 204) {
    res.status(204).set('Cache-Control', 'no-store').end();
    log.debug("Leaving sendResult().");
    return;
  }
  res.status(result.status || 200)
     .type('application/json')
     .set('Cache-Control', 'no-store')
     .send(JSON.stringify(result.body));
  log.debug("Leaving sendResult().");
}

// A refusal from the engine, in GNAP's shape. The engine has already marked the
// result with its code; the response object is marked from it.
function refuse(res, result, fallbackCode, rsFacing) {
  log.debug("Entering refuse().");
  errorCodes.mark(res,
                  errorCodes.codeOf(result) || result.errorCode ||
                  fallbackCode);
  const status = rsFacing ? (result.status === 404 ? 404 : 400)
    : (result.status || STATUS_FOR[result.gnapError] || 400);
  log.debug("Leaving refuse().");
  // error-code: none — the response was marked on the first line of refuse() with the result's own code or the caller's fallback.
  return gnapError(res, status, result.gnapError || 'invalid_request',
                   result.why, result.extra);
}

// Every async handler goes through here, so a thrown defect is a coded 500 and
// never an unhandled rejection (which ends the process under some node flags).
function guarded(name, handler) {
  log.debug("Entering guarded().");
  log.debug("Leaving guarded().");
  return function (req, res, next) {
    Promise.resolve().then(function () {
      return handler(req, res, next);
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-GNAP-0160') + 'gnap: ' + name +
                ' failed: ' + (e && e.stack || e));
      if (!res.headersSent) {
        errorCodes.mark(res, 'STS-GNAP-0160');
        gnapError(res, 500, 'request_denied', 'The authorization server ' +
                  'could not process this request.');
      }
    });
  };
}

function offCheck(res) {
  log.debug("Entering offCheck().");
  if (config.value('gnap.enabled') === false) {
    errorCodes.mark(res, 'STS-GNAP-0161');
    gnapError(res, 404, 'request_denied', 'GNAP is turned off in this trust ' +
                                          'realm (gnap.enabled).');
    log.debug("Leaving offCheck().");
    return true;
  }
  log.debug("Leaving offCheck().");
  return false;
}

// The authorization server a `/:as` path names, or `null` to fall through.
function asFrom(req, res) {
  log.debug("Entering asFrom().");
  const named = validation.checkParsed({ as: req.params.as }, 'params',
                                       AS_PARAMS);
  if (!named.ok) {
    errorCodes.mark(res, 'STS-GNAP-0162');
    gnapError(res, 400, 'invalid_request', named.detail);
    log.debug("Leaving asFrom().");
    return { answered: true };
  }
  const id = String(named.value.as || '');
  if (grants.RESERVED_AS_NAMES.indexOf(id) >= 0) {
    log.debug("Leaving asFrom().");
    return { fallThrough: true };
  }
  authorizationServers.ensure(id, { autoCreated: true, seen: true });
  log.debug("Leaving asFrom().");
  return { id: id };
}

// ---------------------------------------------------------------------------
// SECTION 2: THE GRANT ENDPOINT.
// ---------------------------------------------------------------------------
function grantEndpoint(named) {
  log.debug("Entering grantEndpoint().");
  log.debug("Leaving grantEndpoint().");
  return guarded('the grant endpoint', async function (req, res, next) {
    log.debug("Entering the grant endpoint.");
    let asId = null;
    if (named) {
      const selected = asFrom(req, res);
      if (selected.answered) {
        log.debug("Leaving the grant endpoint. Bad authorization server name.");
        return undefined;
      }
      if (selected.fallThrough) {
        log.debug("Leaving the grant endpoint. Reserved segment; falling " +
                  "through.");
        return next();
      }
      asId = selected.id;
    }
    if (offCheck(res)) {
      log.debug("Leaving the grant endpoint. Off.");
      return undefined;
    }
    const result = await grants.createGrant(req, asId);
    if (!result.ok) {
      log.debug("Leaving the grant endpoint. Refused: " + result.why);
      return refuse(res, result, 'STS-GNAP-0163');
    }
    sendResult(res, result);
    log.debug("Leaving the grant endpoint.");
    return undefined;
  });
}

// SECTION 9: DISCOVERY, by OPTIONS to the grant endpoint.
function discovery(named) {
  log.debug("Entering discovery().");
  log.debug("Leaving discovery().");
  return function (req, res, next) {
    log.debug("Entering GNAP discovery.");
    let asId = null;
    if (named) {
      const selected = asFrom(req, res);
      if (selected.answered) {
        log.debug("Leaving GNAP discovery. Bad name.");
        return undefined;
      }
      if (selected.fallThrough) {
        log.debug("Leaving GNAP discovery. Reserved segment.");
        return next();
      }
      asId = selected.id;
    }
    if (offCheck(res)) {
      log.debug("Leaving GNAP discovery. Off.");
      return undefined;
    }
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(grants.capabilities(req, asId), null, 2));
    log.debug("Leaving GNAP discovery.");
    return undefined;
  };
}

app.post('/gnap', grantEndpoint(false));
app.options('/gnap', discovery(false));
app.post('/:as/gnap', grantEndpoint(true));
app.options('/:as/gnap', discovery(true));

// ---------------------------------------------------------------------------
// SECTION 5: CONTINUATION.
// ---------------------------------------------------------------------------
const continuation = guarded('the continuation endpoint',
                             async function (req, res) {
  log.debug("Entering the continuation endpoint. method=" + req.method);
  if (offCheck(res)) {
    log.debug("Leaving the continuation endpoint. Off.");
    return;
  }
  const params = validation.checkParsed({ grant: req.params.grant }, 'params',
                                        GRANT_PARAMS);
  if (!params.ok) {
    log.debug("Leaving the continuation endpoint. Bad URI.");
    errorCodes.mark(res, 'STS-GNAP-0164');
    gnapError(res, 401, 'invalid_continuation', 'The continuation URI does ' +
              'not identify a grant request.');
    return;
  }
  const result = await grants.continueGrant(req, params.value.grant);
  if (!result.ok) {
    log.debug("Leaving the continuation endpoint. Refused: " + result.why);
    refuse(res, result, 'STS-GNAP-0165');
    return;
  }
  sendResult(res, result);
  log.debug("Leaving the continuation endpoint.");
});

app.post('/gnap/continue/:grant', continuation);
app.patch('/gnap/continue/:grant', continuation);
app.delete('/gnap/continue/:grant', continuation);

// ---------------------------------------------------------------------------
// SECTION 6: TOKEN MANAGEMENT.
// ---------------------------------------------------------------------------
const management = guarded('the token management endpoint',
                           async function (req, res) {
  log.debug("Entering the token management endpoint. method=" + req.method);
  if (offCheck(res)) {
    log.debug("Leaving the token management endpoint. Off.");
    return;
  }
  const params = validation.checkParsed({ handle: req.params.handle }, 'params',
                                        HANDLE_PARAMS);
  if (!params.ok) {
    log.debug("Leaving the token management endpoint. Bad URI.");
    errorCodes.mark(res, 'STS-GNAP-0166');
    gnapError(res, 401,
              req.method === 'DELETE' ? 'invalid_request' : 'invalid_rotation',
              'The token management URI does not identify a token.');
    return;
  }
  const result = await grants.manageToken(req, params.value.handle);
  if (!result.ok) {
    log.debug("Leaving the token management endpoint. Refused: " + result.why);
    refuse(res, result, 'STS-GNAP-0167');
    return;
  }
  sendResult(res, result);
  log.debug("Leaving the token management endpoint.");
});

app.post('/gnap/token/:handle', management);
app.delete('/gnap/token/:handle', management);

// ---------------------------------------------------------------------------
// RFC 9767: THE RESOURCE-SERVER-FACING API.
// ---------------------------------------------------------------------------
function rsDiscovery(named) {
  log.debug("Entering rsDiscovery().");
  log.debug("Leaving rsDiscovery().");
  return function (req, res, next) {
    log.debug("Entering RS-facing discovery.");
    let asId = null;
    if (named) {
      const selected = asFrom(req, res);
      if (selected.answered) {
        log.debug("Leaving RS-facing discovery. Bad name.");
        return undefined;
      }
      if (selected.fallThrough) {
        log.debug("Leaving RS-facing discovery. Reserved segment.");
        return next();
      }
      asId = selected.id;
    }
    if (offCheck(res)) {
      log.debug("Leaving RS-facing discovery. Off.");
      return undefined;
    }
    const caps = grants.capabilities(req, asId);
    const base = grants.realmBase(req);
    const document = { grant_request_endpoint: caps.grant_request_endpoint };
    if (config.value('gnap.introspection') !== false) {
      document.introspection_endpoint = base + '/gnap/introspect';
    }
    if (caps.token_formats_supported) {
      document.token_formats_supported = caps.token_formats_supported;
    }
    if (config.value('gnap.resourceRegistration') !== false) {
      document.resource_registration_endpoint = base + '/gnap/resource';
    }
    if (caps.key_proofs_supported) {
      document.key_proofs_supported = caps.key_proofs_supported;
    }
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(document, null, 2));
    log.debug("Leaving RS-facing discovery.");
    return undefined;
  };
}

app.get('/.well-known/gnap-as-rs', rsDiscovery(false));
app.get('/.well-known/gnap-as-rs/:as', rsDiscovery(true));

app.post('/gnap/introspect',
         guarded('the introspection endpoint', async function (req, res) {
  log.debug("Entering the introspection endpoint.");
  if (offCheck(res)) {
    log.debug("Leaving the introspection endpoint. Off.");
    return;
  }
  const result = await rs.introspect(req);
  if (!result.ok) {
    log.debug("Leaving the introspection endpoint. Refused: " + result.why);
    refuse(res, result, 'STS-GNAP-0168', true);
    return;
  }
  sendResult(res, result);
  log.debug("Leaving the introspection endpoint.");
}));

app.post('/gnap/resource',
         guarded('the resource registration endpoint',
                 async function (req, res) {
  log.debug("Entering the resource registration endpoint.");
  if (offCheck(res)) {
    log.debug("Leaving the resource registration endpoint. Off.");
    return;
  }
  const result = await rs.register(req);
  if (!result.ok) {
    log.debug("Leaving the resource registration endpoint. Refused: " +
              result.why);
    refuse(res, result, 'STS-GNAP-0169', true);
    return;
  }
  sendResult(res, result);
  log.debug("Leaving the resource registration endpoint.");
}));

// ---------------------------------------------------------------------------
// VERIFICATION MATERIAL for the self-contained formats. Public keys only; a
// document that publishes a key is served `no-store` (root CLAUDE.md,
// *Signing keys, and any document that publishes one*) — both of these do.
// ---------------------------------------------------------------------------
app.get('/gnap/keys', function (req, res) {
  log.debug("Entering GET /gnap/keys.");
  if (offCheck(res)) {
    log.debug("Leaving GET /gnap/keys. Off.");
    return;
  }
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(tokens.publicMaterial(grants.realmBase(req)), null,
                          2));
  log.debug("Leaving GET /gnap/keys.");
});

app.get('/gnap/zcap/controller',
        guarded('the ZCAP controller document', async function (req, res) {
  log.debug("Entering GET /gnap/zcap/controller.");
  if (offCheck(res)) {
    log.debug("Leaving GET /gnap/zcap/controller. Off.");
    return;
  }
  const document = await zcap.controllerDocument(
      tokens.zcapKeys(grants.realmBase(req)));
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(document, null, 2));
  log.debug("Leaving GET /gnap/zcap/controller.");
}));

// ---------------------------------------------------------------------------
// THE DEMONSTRATION RESOURCE SERVER (RFC 9635 sections 7.2 and 9.1).
//
// A GET needs `read` and a POST needs `write` on the type
// `urn:mock-sts:gnap:demo` — or the registered reference its RS-first challenge
// hands out. With no token it answers 401 with the RS-FIRST challenge of
// section 9.1: `WWW-Authenticate: GNAP as_uri=…;access=…;referrer=…`, which is
// how a client that knows only a resource URL discovers where to ask.
// ---------------------------------------------------------------------------
const DEMO_TYPE = 'urn:mock-sts:gnap:demo';
const DEMO_REFERENCE = 'mock-sts-gnap-demo';

function demoResource(req, res) {
  log.debug("Entering demoResource().");
  log.debug("Leaving demoResource().");
  return guarded('the demonstration resource server', async function () {
    log.debug("Entering the demonstration RS. method=" + req.method);
    if (offCheck(res)) {
      log.debug("Leaving the demonstration RS. Off.");
      return;
    }
    if (config.value('gnap.demoResourceServer') === false) {
      errorCodes.mark(res, 'STS-GNAP-0550');
      gnapError(res, 404, 'invalid_request', 'The demonstration resource ' +
                'server is turned off (gnap.demoResourceServer).');
      log.debug("Leaving the demonstration RS. Turned off.");
      return;
    }
    const base = grants.realmBase(req);
    const self = base + '/gnap/rs/resource';
    const action = req.method === 'GET' ? 'read' : 'write';
    const challenge = 'GNAP as_uri="' + grants.grantEndpointOf(req, null) +
        '", ' +
        'access="' +
      DEMO_REFERENCE + '", referrer="' + self + '"';
    if (!req.headers.authorization) {
      errorCodes.mark(res, 'STS-GNAP-0551');
      res.status(401)
         .set('WWW-Authenticate', challenge)
         .set('Cache-Control', 'no-store')
         .type('application/json').send(JSON.stringify({ error: 'invalid_token',
           error_description: 'This resource needs a GNAP access token; ask ' +
           'the authorization server named in WWW-Authenticate.' }));
      log.debug("Leaving the demonstration RS. RS-first challenge.");
      return;
    }
    const required = [{ type: DEMO_TYPE, actions: [action] }];
    const judged = await rs.authenticate(req, { audience: self, base: base });
    if (!judged.ok) {
      errorCodes.mark(res, errorCodes.codeOf(judged) || 'STS-GNAP-0552');
      res.status(judged.status || 401)
         .set('WWW-Authenticate', challenge + ', ' +
          'error="' +
        judged.gnapError + '"').set('Cache-Control', 'no-store').type(
            'application/json')
         .send(JSON.stringify({ error: judged.gnapError,
                                error_description: judged.why }));
      log.debug("Leaving the demonstration RS. Refused: " + judged.why);
      return;
    }
    const covers = require('./gnap_access').accessCovers(judged.model.access,
                                                         required) ||
      (judged.model.access || []).indexOf(DEMO_REFERENCE) >= 0;
    if (!covers) {
      errorCodes.mark(res, 'STS-GNAP-0553');
      res.status(403).set('WWW-Authenticate', challenge + ', ' +
          'error="insufficient_scope"')
         .set('Cache-Control', 'no-store').type('application/json')
         .send(JSON.stringify({ error: 'insufficient_scope',
                                error_description: 'The ' +
           'token does not grant ' + action + ' on ' + DEMO_TYPE + '.' }));
      log.debug("Leaving the demonstration RS. Access not covered.");
      return;
    }
    require('./gnap_monitor').record(judged.record.instanceId, 'rs.presented',
                                     {});
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify({ ok: true, action: action, format: judged.format,
                              method: judged.method,
                              token: judged.model }, null, 2));
    log.debug("Leaving the demonstration RS. Allowed.");
  })(req, res);
}

app.get('/gnap/rs/resource', demoResource);
app.post('/gnap/rs/resource', demoResource);

// The pages a resource owner sees, the two console pages, and the scope hook on
// the SSF streams.
require('./gnap_interact');
require('./gnap_admin');
signals.install();

module.exports = {
  DEMO_TYPE: DEMO_TYPE,
  DEMO_REFERENCE: DEMO_REFERENCE,
  gnapError: gnapError
};
