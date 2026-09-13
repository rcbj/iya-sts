'use strict';
//
// File: gnap_grants.js
//
// ---------------------------------------------------------------------------
// THE GRANT ENGINE: EVERY DECISION A GNAP AUTHORIZATION SERVER MAKES, IN ONE
// ROUTE-FREE LIBRARY.
//
// Two route modules call it — `gnap.js` (the grant endpoint, continuation,
// token management, the RS-facing API) and `gnap_interact.js` (the pages a
// resource owner sees) — and a grant crosses between them twice: created at the
// grant endpoint, decided on a page, released at the continuation URI. So the
// state machine of RFC 9635 section 1.5 lives HERE, where both halves reach it,
// and neither route module holds a rule the other could contradict.
//
// ---------------------------------------------------------------------------
// THE LIFE OF A GRANT, AS THIS SERVICE RUNS IT.
//
//   processing  the request is read, the client and its key identified and
//               PROVED, the user member resolved, the policy asked.
//   pending     interaction is needed. The response carries the start modes
//               and a continuation token. When the RO decides, the grant stays
//               PENDING with a DECISION recorded on it — approved or denied —
//               until the client continues: section 5.1 says an interaction
//               reference presented when the request is "not in the pending
//               state" is `too_many_attempts`, so the grant cannot leave pending
//               before the client has presented it.
//   approved    the client continued; tokens and subject information are
//               released. The grant stays approved (and continuable, section
//               5.3) until it is revoked or its tokens are gone.
//   finalized   revoked by the client (section 5.4), exhausted (too many polls,
//               an interaction reference replayed), or expired. Never leaves.
//
// ---------------------------------------------------------------------------
// WHAT IS MODE-GATED, AND WHAT IS NOT.
//
// The refusals that are the specification's own — an unproved key, a malformed
// request, a flag twice, a continuation token for a different grant — are
// refused in both modes (see gnap_proof.js's header). What changes with
// `global.mode` is what this service decides about things the specification
// leaves to the AS, through the existing predicates rather than a GNAP one
// (root CLAUDE.md, Code style):
//
//   * **an unknown client key** — `mode.autoCreates()`: development makes an
//     application entry for it on sight (the user's decision, 2026-09-12);
//     product refuses `invalid_client` unless it is registered.
//   * **an unregistered finish URI** — `mode.acceptsUnregisteredAddresses()`,
//     through `applications.returnAddressesOf()`: development records it as
//     observed; product refuses `invalid_interaction`.
//
// ---------------------------------------------------------------------------
// APPROVALS ARE REMEMBERED IN THE CONSENT REGISTER, AS DIGEST TOKENS.
//
// `common/consent.js` is where this service writes down what a person agreed an
// application may have, on the person's own directory entry — durable in every
// store mode and shown on every consent surface. Its values are RFC 6749 scope
// tokens and a GNAP right is not one (a reference string may carry spaces; an
// object is JSON), so each approved right is stored as `gnap:` + a truncated
// SHA-256 of its CANONICAL JSON (keys and string arrays sorted), approved by the
// user on 2026-09-12. What that costs is said where it is paid: the register
// shows an opaque value, and the readable right is on the grant record.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const config = require('../common/config');
const helpers = require('../common/helpers');
const { log, nowSec, baseUrlOf } = helpers;
const errorCodes = require('../common/error_codes');
const mode = require('../common/mode');
const audit = require('../common/audit');
const applications = require('../common/applications');
const keystore = require('../common/keystore');
const gate = require('../common/issuance_gate');
const consent = require('../common/consent');
const stats = require('../common/admin_stats');
const authorizationServers = require('../oauth-oidc/authorization_servers');
const store = require('./gnap_store');
const keys = require('./gnap_keys');
const proof = require('./gnap_proof');
const request = require('./gnap_request');
const tokens = require('./gnap_tokens');
const subject = require('./gnap_subject');
const transport = require('./gnap_http');
const monitor = require('./gnap_monitor');
const signals = require('./gnap_signals');
const accessRights = require('./gnap_access');

const PROTOCOL = 'GNAP';
const STATE = store.STATE;

// Application kinds this family records (common/applications.js KINDS).
const KIND_CLIENT = 'gnap-client';
const KIND_RS = 'gnap-resource-server';

// An unambiguous alphabet for user codes (section 4.1.2: "choose from character
// values that are easily copied and typed without ambiguity") — no 0/O, 1/I/L.
const USER_CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

// Reserved first path segments a named authorization server may not take: a
// `/:as/gnap` route would otherwise capture `POST /admin/gnap` and CREATE an
// authorization server called "admin" on sight (authorization_servers.js
// ensure()).
const RESERVED_AS_NAMES = ['admin', 'admin-api', 'realm', 'realms', 'portal', 'authn', 'oauth2',
  'gnap', 'ssf', 'scim', 'xacml', 'saml2', 'saml11', 'wsfed', 'wstrust', 'tls', 'pki',
  'federation', 'spiffe', 'logout', 'ldap', 'krb5', 'sts', '.well-known', 'vci', 'vp',
  'did', 'dpop', 'home', 'KdcProxy'];

function refusal(code, why, gnapError, status) {
  const out = { ok: false, errorCode: code, why: why, gnapError: gnapError || 'invalid_request',
                status: status || null };
  return errorCodes.mark(out, code);
}

function bool(value) {
  return value === true || /^(true|1|yes)$/i.test(String(value == null ? '' : value));
}

function csv(key) {
  const raw = config.value(key);
  const list = Array.isArray(raw) ? raw : String(raw || '').split(',');
  return list.map(function (one) {
    return String(one).trim();
  }).filter(Boolean);
}

function fieldValues(app, name) {
  if (!app || !app.fields) {
    return [];
  }
  const value = app.fields[name];
  if (value === undefined || value === null || value === '') {
    return [];
  }
  return (Array.isArray(value) ? value : [value]).map(String);
}

function field(app, name) {
  return fieldValues(app, name)[0] || null;
}

// ---------------------------------------------------------------------------
// URIS. Every URI a response carries is ABSOLUTE (sections 3.1, 3.2.1, 3.3),
// built from the realm base the request arrived on. The GRANT ENDPOINT carries
// the authorization server's path; the rest do not need to, because every one
// of them identifies a grant or a token that already records its AS.
// ---------------------------------------------------------------------------
function asPath(asId) {
  return asId && asId !== authorizationServers.DEFAULT_ID ? '/' + asId : '';
}

function grantEndpointOf(req, asId) {
  return baseUrlOf(req) + asPath(asId) + '/gnap';
}

function realmBase(req) {
  return baseUrlOf(req);
}

// ---------------------------------------------------------------------------
// THE AUTHORIZATION SERVER'S GNAP CAPABILITIES.
//
// "GNAP incorporates the existing authorization server concept": a named
// authorization server (`/:as/...`) is one profile with one set of capabilities,
// and since 2026-09-12 that profile carries GNAP's section 9 discovery members
// beside its RFC 8414 ones. The defaults come from the `gnap.*` settings; the
// profile's overrides and removals apply on top; and the RESULT is both what
// OPTIONS publishes and what the grant endpoint enforces — the rule
// `authorization_servers.js` states for OAuth, for the same reason: there is no
// second table of what this server does that could disagree with what it says.
// ---------------------------------------------------------------------------
const GNAP_MEMBERS = ['interaction_start_modes_supported', 'interaction_finish_methods_supported',
  'key_proofs_supported', 'sub_id_formats_supported', 'assertion_formats_supported',
  'key_rotation_supported', 'token_formats_supported'];

function defaultCapabilities(req, asId) {
  const startModes = csv('gnap.interactionStartModes').filter(function (m) {
    return request.START_MODES.indexOf(m) >= 0;
  });
  const finish = csv('gnap.finishMethods').filter(function (m) {
    return request.FINISH_METHODS.indexOf(m) >= 0 && (m !== 'push' || config.value('gnap.pushFinish'));
  });
  return {
    grant_request_endpoint: grantEndpointOf(req, asId),
    interaction_start_modes_supported: startModes,
    interaction_finish_methods_supported: finish,
    key_proofs_supported: csv('gnap.keyProofs').filter(function (m) {
      return keys.PROOF_METHODS.indexOf(m) >= 0;
    }),
    sub_id_formats_supported: csv('gnap.subIdFormats').filter(function (f) {
      return subject.SUB_ID_FORMATS_SUPPORTED.indexOf(f) >= 0;
    }),
    assertion_formats_supported: csv('gnap.assertionFormats').filter(function (f) {
      return subject.ASSERTION_FORMATS_SUPPORTED.indexOf(f) >= 0;
    }),
    key_rotation_supported: !!config.value('gnap.keyRotation'),
    token_formats_supported: csv('gnap.tokenFormats').filter(function (f) {
      return tokens.FORMATS.indexOf(f) >= 0;
    })
  };
}

function capabilities(req, asId) {
  const defaults = defaultCapabilities(req, asId);
  const merged = authorizationServers.capabilitiesOf(asId || authorizationServers.DEFAULT_ID,
                                                     defaults, 'gnap');
  const out = { grant_request_endpoint: defaults.grant_request_endpoint };
  GNAP_MEMBERS.forEach(function (member) {
    if (merged[member] !== undefined) {
      out[member] = merged[member];
    }
  });
  return out;
}

// A list capability, or null when the profile REMOVED the member — which the
// OAuth side reads as "enforce nothing" (authorization_servers.js), and so does
// this one.
function capabilityList(req, asId, member) {
  const value = capabilities(req, asId)[member];
  if (value === undefined) {
    return null;
  }
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

function allows(list, value) {
  return list === null || list.indexOf(value) >= 0;
}

// ---------------------------------------------------------------------------
// APPLICATION ENTRIES. Every GNAP client instance and resource server is one
// (the user's requirement), found by the identity of its key, by its static
// instance identifier, or by a dynamic one this AS issued.
// ---------------------------------------------------------------------------
function gnapApplications() {
  return applications.list().filter(function (app) {
    return (app.kinds || []).some(function (kind) {
      return kind === KIND_CLIENT || kind === KIND_RS;
    }) || (app.allowedProtocols || []).indexOf('gnap') >= 0 ||
      !!field(app, 'gnapKey') || !!field(app, 'gnapInstanceId');
  });
}

function registeredKeyIdentity(app) {
  const raw = field(app, 'gnapKey');
  if (!raw) {
    return null;
  }
  try {
    const described = keys.describe(JSON.parse(raw), {});
    return described.ok ? described.identity : null;
  } catch (e) {
    // A registered key that is not JSON. The console refuses to write one; an
    // LDAP modify can. It identifies nobody, and the log says which entry.
    log.warn(errorCodes.tag('STS-GNAP-0652') + 'gnap: the application "' + app.identifier +
             '" carries a gnapKey that is not a JSON key object: ' + e.message);
    return null;
  }
}

function appByKeyIdentity(identity) {
  return gnapApplications().filter(function (app) {
    return registeredKeyIdentity(app) === identity || field(app, 'gnapKeyIdentity') === identity;
  })[0] || null;
}

function appByInstanceId(instanceId) {
  const dynamic = store.instanceById(instanceId);
  if (dynamic) {
    const app = applications.get(dynamic.identifier);
    return app ? { app: app, key: dynamic.key, dynamic: true } : null;
  }
  const app = gnapApplications().filter(function (one) {
    return field(one, 'gnapInstanceId') === instanceId;
  })[0];
  return app ? { app: app, key: field(app, 'gnapKey') ? JSON.parse(field(app, 'gnapKey')) : null,
                 dynamic: false } : null;
}

// Resolve a key REFERENCE (section 7.1.1) against application entries: a
// registered `gnapKeyReference` naming either the entry's public key or its
// shared secret. The secret is SEALED at rest when keys persist
// (common/keystore.js) and arrives opened through applications.get().
function resolveKeyReference(reference) {
  log.debug("Entering resolveKeyReference().");
  const app = gnapApplications().filter(function (one) {
    return field(one, 'gnapKeyReference') === reference;
  })[0];
  if (!app) {
    log.debug("Leaving resolveKeyReference(). Unknown.");
    return null;
  }
  const secret = field(app, 'gnapSymmetricKey');
  if (secret) {
    let bytes = Buffer.from(secret, 'base64url');
    if (keystore.persists() && /^\$aesgcm\$/.test(secret)) {
      // Still ciphertext: the opened view could not open it. Refused rather
      // than used — a MAC keyed with ciphertext would verify nothing any client
      // could produce, and the log names the entry.
      log.warn(errorCodes.tag('STS-GNAP-0653') + 'gnap: the shared key on "' + app.identifier +
               '" could not be opened with this process\'s key-encryption key.');
      log.debug("Leaving resolveKeyReference(). Sealed and unopenable.");
      return null;
    }
    if (bytes.length < 32) {
      // Section 7.1.2: a symmetric key "MUST NOT be a human-memorable password".
      // Thirty-two bytes is HS256's own key length.
      bytes = null;
    }
    log.debug("Leaving resolveKeyReference(). Shared secret.");
    return bytes ? { secret: bytes, proof: field(app, 'gnapKeyProof') || 'httpsig',
                     alg: field(app, 'gnapSymmetricAlg') || 'HS256', app: app } : null;
  }
  const raw = field(app, 'gnapKey');
  log.debug("Leaving resolveKeyReference(). Registered public key.");
  return raw ? { key: JSON.parse(raw), app: app } : null;
}

// ---------------------------------------------------------------------------
// WHO IS CALLING: the client (or RS) member, its key, the entry, and the proof.
//
// `member` is `{ reference, key, classId, display }` (gnap_request.js).
// `kind` is KIND_CLIENT or KIND_RS.
// ---------------------------------------------------------------------------
function identifyCaller(req, body, member, kind, options) {
  log.debug("Entering identifyCaller(). kind=" + kind);
  const opts = options || {};
  let descriptor;
  let app = null;
  let instanceId = null;
  if (member.reference) {
    const found = appByInstanceId(member.reference);
    if (!found) {
      log.debug("Leaving identifyCaller(). Unknown instance identifier.");
      return refusal('STS-GNAP-0080', 'the instance identifier is not one this authorization ' +
                     'server knows (RFC 9635 section 2.3.1).',
                     kind === KIND_RS ? 'invalid_resource_server' : 'invalid_client', 401);
    }
    app = found.app;
    instanceId = member.reference;
    if (found.key) {
      descriptor = keys.describe(found.key, { resolveReference: resolveKeyReference });
    } else if (field(app, 'gnapKeyReference')) {
      descriptor = keys.describe(field(app, 'gnapKeyReference'), { resolveReference: resolveKeyReference });
    } else {
      descriptor = refusal('STS-GNAP-0081', 'the application "' + app.identifier + '" has no key ' +
                           'registered to verify its requests with.', 'invalid_client', 401);
    }
  } else {
    descriptor = keys.describe(member.key, { resolveReference: resolveKeyReference });
  }
  if (!descriptor.ok) {
    log.debug("Leaving identifyCaller(). The key is refused: " + descriptor.why);
    descriptor.status = 401;
    if (kind === KIND_RS && descriptor.gnapError === 'invalid_client') {
      descriptor.gnapError = 'invalid_resource_server';
    }
    return descriptor;
  }
  const verified = proof.verifyRequest(req, body, descriptor, { accessToken: opts.accessToken || null });
  if (!verified.ok) {
    log.debug("Leaving identifyCaller(). Proof refused: " + verified.why);
    monitor.record(app ? app.identifier : '(unidentified)', 'proof.failed',
                   { gnapError: kind === KIND_RS ? 'invalid_resource_server' : 'invalid_client' });
    return Object.assign(verified, { gnapError: kind === KIND_RS ? 'invalid_resource_server'
                                                                  : 'invalid_client', status: 401 });
  }
  if (!app && descriptor.reference) {
    const resolved = resolveKeyReference(descriptor.reference);
    app = resolved ? resolved.app : null;
  }
  if (!app) {
    app = appByKeyIdentity(descriptor.identity);
  }
  let created = false;
  if (!app) {
    // AN UNKNOWN BUT PROVED KEY. Section 2.3.3 lets the AS allow it; the
    // user's decision is that development does, as an application entry, and
    // product does not (the header).
    if (!mode.autoCreates()) {
      log.debug("Leaving identifyCaller(). Unregistered key in product mode.");
      return refusal('STS-GNAP-0082', 'this key is not registered with this authorization ' +
                     'server, and in product mode an application must be provisioned before it ' +
                     'can make requests (RFC 9635 section 2.3.3).',
                     kind === KIND_RS ? 'invalid_resource_server' : 'invalid_client', 401);
    }
    const identifier = 'gnap-' + descriptor.identity.replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 48);
    const fields = { gnapKey: JSON.stringify(descriptor.value), gnapKeyIdentity: descriptor.identity };
    if (member.classId) {
      fields.gnapClassId = member.classId;
    }
    if (member.display && member.display.uri) {
      fields.gnapDisplayUri = member.display.uri;
    }
    if (member.display && member.display.logoUri && member.display.logoUri.length < 2048) {
      fields.gnapLogoUri = member.display.logoUri;
    }
    applications.seen({ identifier: identifier, kind: kind, protocol: PROTOCOL,
                        name: (member.display && member.display.name) || undefined,
                        counts: false, fields: fields,
                        note: 'Created on first sight of a proved GNAP key (development mode).' });
    app = applications.get(identifier);
    created = true;
    if (!app) {
      log.debug("Leaving identifyCaller(). The entry could not be created.");
      return refusal('STS-GNAP-0083', 'the application entry for this key could not be created.',
                     'invalid_client', 401);
    }
  } else {
    applications.seen({ identifier: app.identifier, kind: kind, protocol: PROTOCOL, counts: false });
  }
  log.debug("Leaving identifyCaller(). app=" + app.identifier + ", created=" + created);
  return { ok: true, app: app, descriptor: descriptor, proof: verified, instanceId: instanceId,
           created: created,
          // Section 2.3: "the pre-registered values MUST take precedence".
           display: {
             name: app.name || (member.display && member.display.name) || app.identifier,
             uri: field(app, 'gnapDisplayUri') || (member.display && member.display.uri) || null,
             logoUri: field(app, 'gnapLogoUri') || (member.display && member.display.logoUri) || null
           },
           classId: field(app, 'gnapClassId') || member.classId || null };
}

// ---------------------------------------------------------------------------
// ACCESS POLICY for one requested token.
// ---------------------------------------------------------------------------
function canonicalJson(value) {
  if (Array.isArray(value)) {
    const items = value.map(canonicalJson);
    return '[' + (value.every(function (one) { return typeof one === 'string'; })
      ? items.slice().sort() : items).join(',') + ']';
  }
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(function (name) {
      return JSON.stringify(name) + ':' + canonicalJson(value[name]);
    }).join(',') + '}';
  }
  return JSON.stringify(value);
}

function digestTokenOf(right) {
  return 'gnap:' + nodeCrypto.createHash('sha256').update(canonicalJson(right), 'utf8')
    .digest('base64url').slice(0, 22);
}

// What a client may ask for (`gnapAllowedAccess`: types and reference strings;
// empty means anything) and what an unknown reference string does.
function accessProblem(app, access) {
  log.debug("Entering accessProblem().");
  const allowed = fieldValues(app, 'gnapAllowedAccess');
  for (let i = 0; i < access.length; i++) {
    const right = access[i];
    const name = typeof right === 'string' ? right : right.type;
    if (allowed.length && allowed.indexOf(name) < 0) {
      log.debug("Leaving accessProblem(). Not allowed for this client.");
      return 'the right "' + name + '" is not one this client instance may request';
    }
    if (typeof right === 'string' && !store.resourceByReference(right) &&
        String(config.value('gnap.unknownAccessReferences') || 'accept') === 'refuse' &&
        allowed.indexOf(right) < 0) {
      log.debug("Leaving accessProblem(). Unknown reference refused.");
      return 'the access reference "' + right + '" names nothing registered with this ' +
             'authorization server';
    }
  }
  log.debug("Leaving accessProblem().");
  return '';
}

// ---------------------------------------------------------------------------
// RESOURCE SERVERS AND TOKEN FORMAT for a set of rights.
// ---------------------------------------------------------------------------
function resourceServersFor(access) {
  const found = {};
  (access || []).forEach(function (right) {
    if (typeof right === 'string') {
      const row = store.resourceByReference(right);
      if (row && row.rsIdentifier) {
        found[row.rsIdentifier] = true;
      }
      return;
    }
    (right.locations || []).forEach(function (location) {
      gnapApplications().forEach(function (app) {
        if (fieldValues(app, 'gnapResourceServerUri').some(function (uri) {
          return location === uri || location.indexOf(uri) === 0;
        })) {
          found[app.identifier] = true;
        }
      });
    });
  });
  return Object.keys(found);
}

function chooseFormat(req, grant, access, rsIds) {
  log.debug("Entering chooseFormat().");
  const enabled = capabilityList(req, grant.as, 'token_formats_supported') || tokens.FORMATS;
  let candidates = enabled.slice();
  (access || []).forEach(function (right) {
    if (typeof right === 'string') {
      const row = store.resourceByReference(right);
      if (row && row.tokenFormats && row.tokenFormats.length) {
        candidates = candidates.filter(function (format) {
          return row.tokenFormats.indexOf(format) >= 0;
        });
      }
    }
  });
  if (!candidates.length) {
    log.debug("Leaving chooseFormat(). No format satisfies every resource set.");
    return null;
  }
  const preferences = [];
  if (rsIds.length === 1) {
    const rs = applications.get(rsIds[0]);
    if (field(rs, 'gnapAccessTokenFormat')) {
      preferences.push(field(rs, 'gnapAccessTokenFormat'));
    }
  }
  const client = applications.get(grant.client.identifier);
  if (field(client, 'gnapAccessTokenFormat')) {
    preferences.push(field(client, 'gnapAccessTokenFormat'));
  }
  preferences.push(String(config.value('gnap.accessTokenFormat') || 'jwt-signed'));
  const chosen = preferences.filter(function (format) {
    return candidates.indexOf(format) >= 0;
  })[0] || candidates[0];
  log.debug("Leaving chooseFormat(). " + chosen);
  return chosen;
}

// ---------------------------------------------------------------------------
// TOKEN ISSUANCE for an approved grant (section 3.2).
//
// `requests` is `[{ label, access, bearer }]` of APPROVED rights. Returns the
// response member: an object for a single-token request and an array for a
// multiple-token one (section 3.2.2: the AS MUST NOT switch shapes), omitting a
// token the AS refused (section 3.2.2 allows that).
// ---------------------------------------------------------------------------
async function issueTokens(req, grant, requests, multiple) {
  log.debug("Entering issueTokens(). grant=" + grant.id + ", " + requests.length + " token(s)");
  const out = [];
  const base = realmBase(req);
  const client = applications.get(grant.client.identifier);
  for (let i = 0; i < requests.length; i++) {
    const asked = requests[i];
    if (!asked.access.length) {
      continue;
    }
    const username = grant.ro ? grant.ro.username : null;
    const allowed = gate.check({
      application: grant.client.identifier,
      kind: gate.ISSUANCE.ACCESS_TOKEN,
      subject: username ? { kind: 'user', name: username, authenticated: true }
                        : { kind: 'application', name: grant.client.identifier, authenticated: true },
      claims: null
    });
    if (!allowed.allowed) {
      log.info('gnap: the issuance policy refused a token for grant ' + grant.id + ': ' + allowed.why);
      audit.failure('STS-GNAP-0090', { protocol: PROTOCOL, channel: 'http',
        target: grant.client.identifier, summary: 'The issuance policy refused a GNAP access token',
        detail: { grant: grant.id, why: String(allowed.why || '') } });
      continue;
    }
    const rsIds = resourceServersFor(asked.access);
    const format = chooseFormat(req, grant, asked.access, rsIds);
    if (!format) {
      audit.failure('STS-GNAP-0091', { protocol: PROTOCOL, channel: 'http',
        target: grant.client.identifier, summary: 'No token format satisfies every requested resource set',
        detail: { grant: grant.id } });
      continue;
    }
    const iat = nowSec();
    const lifetime = Number(applications.settingFor(grant.client.identifier,
                                                    'gnap.accessTokenLifetimeS', config)) || 3600;
    const durable = !!config.value('gnap.durableTokens');
    const flags = [];
    if (asked.bearer) {
      flags.push('bearer');
    }
    if (durable) {
      flags.push('durable');
    }
    const keyDescriptor = keys.describe(grant.client.key, { resolveReference: resolveKeyReference });
    const audience = rsIds.slice();
    if (!audience.length && (config.value('gnap.demoResourceServer') !== false)) {
      // A token for nobody in particular is valid at the demonstration RS,
      // which is how a client can present one somewhere at all.
      audience.push(base + '/gnap/rs/resource');
    }
    const model = {
      jti: store.mint(16),
      iss: grant.grantEndpoint,
      sub: username ? helpers.userFor(username).sub : null,
      aud: audience,
      instanceId: grant.client.identifier,
      access: asked.access,
      flags: flags,
      cnf: asked.bearer ? null : keys.confirmationOf(keyDescriptor),
      iat: iat,
      nbf: iat,
      exp: iat + lifetime,
      label: asked.label || null
    };
    const rs = rsIds.length === 1 ? applications.get(rsIds[0]) : null;
    let jweKey = null;
    if (rs && field(rs, 'gnapJweKey')) {
      try {
        jweKey = JSON.parse(field(rs, 'gnapJweKey'));
      } catch (e) {
        // Not a JWK: encrypted to this AS instead, and said so.
        log.warn(errorCodes.tag('STS-GNAP-0654') + 'gnap: "' + rs.identifier + '" carries a ' +
                 'gnapJweKey that is not JSON; jwt-encrypted tokens for it are encrypted to this ' +
                 'authorization server instead: ' + e.message);
      }
    }
    let minted;
    try {
      minted = await tokens.mint(format, model, { base: base,
        rs: rs ? { identity: rs.identifier, jweKey: jweKey } : null,
        sessionId: grant.ro ? grant.ro.sessionId : null, setId: grant.id });
    } catch (e) {
      log.error(errorCodes.tag('STS-GNAP-0092') + 'gnap: a ' + format + ' access token could not ' +
                'be minted for grant ' + grant.id + ': ' + e.message);
      continue;
    }
    const record = store.putToken(Object.assign({}, model, {
      format: format, grantId: grant.id, as: grant.as, key: asked.bearer ? null : grant.client.key,
      proof: asked.bearer ? null : keyDescriptor.proof, revoked: false, createdAt: iat,
      rsIdentifiers: rsIds, username: username
    }), minted.value);
    const response = { value: minted.value, access: asked.access, expires_in: lifetime };
    if (asked.label) {
      response.label = asked.label;
    }
    if (flags.length) {
      response.flags = flags;
    }
    if (config.value('gnap.tokenManagement') !== false) {
      const manageValue = store.issueManagement(record);
      store.saveToken(record);
      response.manage = { uri: base + '/gnap/token/' + record.manageHandle,
                          access_token: { value: manageValue } };
    }
    grant.tokens = (grant.tokens || []).concat([record.jti]);
    monitor.record(grant.client.identifier, 'token.issued', { format: format });
    if (rsIds.length === 1) {
      monitor.record(rsIds[0], 'rs.presented', {});
    }
    audit.audit({ action: 'gnap.token.issue', category: 'protocol', protocol: PROTOCOL,
      channel: 'http', outcome: 'success', actor: username || grant.client.identifier,
      target: grant.client.identifier,
      summary: 'A GNAP ' + format + ' access token was issued',
      detail: { grant: grant.id, jti: record.jti, format: format, bearer: !!asked.bearer,
                label: asked.label || '' } });
    out.push(response);
  }
  if (client) {
    applications.seen({ identifier: client.identifier, kind: KIND_CLIENT, protocol: PROTOCOL,
                        counts: true, user: grant.ro ? grant.ro.username : undefined,
                        sessionId: grant.ro ? grant.ro.sessionId : undefined });
  }
  log.debug("Leaving issueTokens(). " + out.length + " issued.");
  if (!out.length) {
    return null;
  }
  return multiple ? out : out[0];
}

// Subject information for an approved grant with a known RO (section 3.4).
async function releaseSubject(req, grant) {
  log.debug("Entering releaseSubject().");
  if (!grant.request.subject || !grant.ro) {
    log.debug("Leaving releaseSubject(). Nothing requested or no RO.");
    return null;
  }
  const oauth2 = require('../oauth-oidc/oauth2');
  const issuer = oauth2.issuerOf(realmBase(req));
  const formats = grant.request.subject.subIdFormats.filter(function (format) {
    return allows(capabilityList(req, grant.as, 'sub_id_formats_supported'), format);
  });
  const assertionFormats = grant.request.subject.assertionFormats.filter(function (format) {
    return allows(capabilityList(req, grant.as, 'assertion_formats_supported'), format);
  });
  const out = {};
  const ids = subject.subIdsFor(grant.ro.username, formats, { issuer: issuer });
  if (ids.length) {
    out.sub_ids = ids;
  }
  const wanted = assertionFormats.filter(function (format) {
    const kind = format === 'id_token' ? gate.ISSUANCE.ID_TOKEN : gate.ISSUANCE.SAML_ASSERTION;
    return gate.check({ application: grant.client.identifier, kind: kind,
                        subject: { kind: 'user', name: grant.ro.username, authenticated: true },
                        claims: null }).allowed;
  });
  if (wanted.length) {
    out.assertions = await subject.assertionsFor(grant.ro.username, wanted, {
      oauthBase: realmBase(req), instanceId: grant.client.identifier, issuer: issuer,
      authTime: grant.ro.authTime, amr: grant.ro.amr, acr: grant.ro.acr,
      sessionId: grant.ro.sessionId, setId: grant.id });
  }
  out.updated_at = new Date((grant.ro.authTime || nowSec()) * 1000).toISOString();
  monitor.record(grant.client.identifier, 'subject.released', {});
  log.debug("Leaving releaseSubject().");
  return out;
}

// ---------------------------------------------------------------------------
// THE CONTINUATION MEMBER (section 3.1). A new token every time (section 5:
// SHOULD invalidate the previous one), and `wait` always stated, because its
// omission MUST be read as five seconds and a client should not have to know
// that.
// ---------------------------------------------------------------------------
function continueMember(req, grant) {
  const value = store.issueContinuation(grant);
  const wait = Math.max(0, Number(config.value('gnap.continueWaitS')));
  grant.continueNotBefore = nowSec() + (Number.isFinite(wait) ? wait : 5);
  return { access_token: { value: value }, uri: realmBase(req) + '/gnap/continue/' + grant.id,
           wait: Number.isFinite(wait) ? wait : 5 };
}

function newUserCode() {
  const length = Math.min(8, Math.max(6, Number(config.value('gnap.userCodeLength')) || 8));
  for (let attempt = 0; attempt < 20; attempt++) {
    let code = '';
    const bytes = nodeCrypto.randomBytes(length);
    for (let i = 0; i < length; i++) {
      code += USER_CODE_ALPHABET[bytes[i] % USER_CODE_ALPHABET.length];
    }
    if (!store.userCodeTaken(code)) {
      return code;
    }
  }
  return null;
}

// Section 4.1.2: strip what is not in the alphabet, compare case-insensitively.
function normaliseUserCode(input) {
  return String(input || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

// ---------------------------------------------------------------------------
// START INTERACTION (section 3.3). Answers the `interact` response member, or a
// refusal when no mode the client offered can be used and the AS cannot reach
// the RO any other way (section 2.5: invalid_interaction).
// ---------------------------------------------------------------------------
function startInteraction(req, grant, app, interact) {
  log.debug("Entering startInteraction(). grant=" + grant.id);
  const supportedStarts = capabilityList(req, grant.as, 'interaction_start_modes_supported');
  const appModes = fieldValues(app, 'gnapInteractionStartModes');
  const usable = interact.start.filter(function (mode) {
    return request.START_MODES.indexOf(mode) >= 0 && allows(supportedStarts, mode) &&
      (!appModes.length || appModes.indexOf(mode) >= 0);
  });
  const finishMethods = capabilityList(req, grant.as, 'interaction_finish_methods_supported');
  let finish = null;
  if (interact.finish && request.FINISH_METHODS.indexOf(interact.finish.method) >= 0 &&
      allows(finishMethods, interact.finish.method)) {
    finish = interact.finish;
  }
  if (!usable.length && !(finish && finish.method === 'push')) {
    log.debug("Leaving startInteraction(). No usable start mode.");
    return refusal('STS-GNAP-0100', 'none of the interaction start modes offered (' +
                   (interact.start.join(', ') || 'none') + ') is supported for this client, and ' +
                   'this authorization server cannot reach the resource owner another way ' +
                   '(RFC 9635 section 2.5).', 'invalid_interaction');
  }
  if (finish) {
    const addresses = applications.returnAddressesOf(app, 'gnapFinishUri');
    const registered = (addresses.registered || []).indexOf(finish.uri) >= 0;
    if (!mode.acceptsUnregisteredAddresses() && !registered) {
      log.debug("Leaving startInteraction(). Finish URI not registered (product).");
      return refusal('STS-GNAP-0101', 'the interaction finish URI is not registered for this ' +
                     'client instance, and in product mode only a registered one is used ' +
                     '(RFC 9635 sections 2.5.2 and 11.18).', 'invalid_interaction');
    }
    if (mode.acceptsUnregisteredAddresses() && !registered) {
      applications.seen({ identifier: app.identifier, kind: KIND_CLIENT, protocol: PROTOCOL,
                          counts: false, fields: { gnapFinishUri: finish.uri } });
    }
    if (finish.method === 'push') {
      const problem = transport.urlProblem(finish.uri);
      if (problem) {
        log.debug("Leaving startInteraction(). Push URI cannot be dialled.");
        return refusal('STS-GNAP-0102', problem + ' (RFC 9635 section 11.34).',
                       'invalid_interaction');
      }
    }
    if (!/^https:/i.test(finish.uri) && !mode.acceptsUnregisteredAddresses() &&
        !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/)/i.test(finish.uri) &&
        /^http:/i.test(finish.uri)) {
      log.debug("Leaving startInteraction(). Plain http finish URI in product.");
      return refusal('STS-GNAP-0103', 'the finish URI must be https, localhost, or an ' +
                     'application scheme (RFC 9635 section 2.5.2.1).', 'invalid_interaction');
    }
  }
  const base = realmBase(req);
  const lifetime = Number(config.value('gnap.interactionLifetimeS')) || 600;
  const out = {};
  const interaction = { modes: {}, finish: finish, serverNonce: null, expiresAt: nowSec() + lifetime,
                        started: null, decided: false, decision: null, interactRef: null,
                        approvalId: store.mint(18), hints: interact.hints };
  store.putInteraction('approve:' + interaction.approvalId, grant.id);
  usable.forEach(function (mode) {
    if (mode === 'redirect' || mode === 'app') {
      const id = store.mint(18);
      interaction.modes[mode] = { id: id, used: false };
      store.putInteraction(mode + ':' + id, grant.id);
      out[mode] = base + '/gnap/' + (mode === 'redirect' ? 'interact' : 'app') + '/' + id;
    } else if (mode === 'user_code' || mode === 'user_code_uri') {
      const code = interaction.modes.user_code ? interaction.modes.user_code.code
        : (interaction.modes.user_code_uri ? interaction.modes.user_code_uri.code : newUserCode());
      interaction.modes[mode] = { code: code, used: false };
      store.putUserCode(code, grant.id);
      out[mode] = mode === 'user_code' ? code : { code: code, uri: base + '/gnap/code' };
    }
  });
  if (finish) {
    interaction.serverNonce = store.mint(15);
    out.finish = interaction.serverNonce;
  }
  out.expires_in = lifetime;
  grant.interaction = interaction;
  grant.state = STATE.PENDING;
  grant.expiresAt = interaction.expiresAt;
  usable.forEach(function (mode) {
    monitor.record(app.identifier, 'interaction.' + mode, {});
  });
  log.debug("Leaving startInteraction(). modes=" + usable.join(',') + ", finish=" +
            (finish ? finish.method : 'none'));
  return { ok: true, interact: out };
}

// Section 4.2.3.
function interactionHash(clientNonce, serverNonce, interactRef, grantEndpoint, hashMethod) {
  const spec = request.HASH_METHODS[hashMethod || 'sha-256'];
  const digest = nodeCrypto.createHash(spec.node)
    .update([clientNonce, serverNonce, interactRef, grantEndpoint].join('\n'), 'ascii').digest();
  return digest.subarray(0, spec.bits / 8).toString('base64url');
}

// ---------------------------------------------------------------------------
// A NEW GRANT REQUEST (section 2). Answers `{ status, body }` or a refusal.
// ---------------------------------------------------------------------------
async function createGrant(req, asId) {
  log.debug("Entering createGrant(). as=" + (asId || 'default'));
  const body = proof.readBody(req);
  if (!body.ok) {
    log.debug("Leaving createGrant(). Body refused.");
    return body;
  }
  const parsed = request.parseGrantRequest(body.json);
  if (!parsed.ok) {
    log.debug("Leaving createGrant(). Request refused: " + parsed.why);
    return parsed;
  }
  const asked = parsed.request;
  const proofList = capabilityList(req, asId, 'key_proofs_supported');
  const caller = identifyCaller(req, body, asked.client, asked.existingAccessToken ? KIND_RS : KIND_CLIENT);
  if (!caller.ok) {
    log.debug("Leaving createGrant(). Caller refused.");
    return caller;
  }
  if (!allows(proofList, caller.descriptor.proof.method)) {
    log.debug("Leaving createGrant(). Proof method not supported by this AS.");
    return refusal('STS-GNAP-0110', 'this authorization server does not accept the "' +
                   caller.descriptor.proof.method + '" proofing method (see key_proofs_supported).',
                   'invalid_client', 401);
  }
  const app = caller.app;
  const identifier = app.identifier;
  monitor.record(identifier, 'grant.requested', {});
  for (let i = 0; i < asked.tokens.length; i++) {
    if (asked.tokens[i].bearer && (config.value('gnap.bearerTokens') === false ||
        field(app, 'gnapBearerTokens') === 'FALSE')) {
      log.debug("Leaving createGrant(). Bearer not allowed.");
      return refusal('STS-GNAP-0111', 'this client instance may not be issued bearer tokens ' +
                     '(RFC 9635 section 2.1.1).', 'invalid_flag');
    }
    const problem = accessProblem(app, asked.tokens[i].access);
    if (problem) {
      log.debug("Leaving createGrant(). Access refused.");
      return refusal('STS-GNAP-0112', problem + '.', 'request_denied', 403);
    }
  }
  const oauth2 = require('../oauth-oidc/oauth2');
  const resolved = subject.resolveUser(asked.user, { issuer: oauth2.issuerOf(realmBase(req)),
                                                     oauthIssuer: oauth2.issuerOf(realmBase(req)) });
  if (!resolved.ok) {
    log.debug("Leaving createGrant(). User refused.");
    return resolved;
  }
  const grant = store.newGrant({
    as: asId || authorizationServers.DEFAULT_ID,
    grantEndpoint: grantEndpointOf(req, asId),
    referer: String(req.headers.referer || '').slice(0, 512) || null,
    client: { identifier: identifier, instanceId: caller.instanceId, key: caller.descriptor.value,
              keyIdentity: caller.descriptor.identity, proof: caller.descriptor.proof.method,
              display: caller.display, classId: caller.classId },
    request: { tokens: asked.tokens, multiple: asked.multiple, subject: asked.subject,
               interact: asked.interact },
    userHint: resolved.username,
    userVerified: resolved.verified,
    ro: null,
    decision: null,
    delivered: false,
    polls: 0
  });
  store.saveGrant(grant, 'requested by ' + identifier + ' (' + caller.descriptor.proof.method + ')');
  audit.audit({ action: 'gnap.grant.request', category: 'protocol', protocol: PROTOCOL,
    channel: 'http', outcome: 'success', actor: identifier, target: identifier,
    summary: 'A GNAP grant was requested', detail: { grant: grant.id, as: grant.as,
      tokens: asked.tokens.length, subject: !!asked.subject, created: caller.created } });

  // RFC 9767 section 4: a resource server deriving a downstream token.
  if (asked.existingAccessToken) {
    const derived = await deriveToken(req, grant, app, asked);
    log.debug("Leaving createGrant(). Derivation.");
    return derived;
  }

  const response = {};
  if (config.value('gnap.instanceIds') !== false && !caller.instanceId && caller.descriptor.format !== 'reference') {
    const instanceId = store.mint(18);
    store.putInstance(instanceId, { identifier: identifier, key: caller.descriptor.value });
    response.instance_id = instanceId;
  }
  // WITHOUT INTERACTION. A registered client marked `gnapSkipInteraction`
  // (section 2.3.3's "only specific client instances with certain known keys
  // might be trusted with access tokens without the AS interacting directly
  // with the RO") gets tokens with no RO, when it asks for no subject
  // information; with a VERIFIED user assertion it gets them for that person
  // (section 2.4).
  const trusted = field(app, 'gnapSkipInteraction') === 'TRUE' && !caller.created;
  if (trusted && (!asked.subject || resolved.verified)) {
    grant.ro = resolved.verified ? { username: resolved.username, sessionId: null, authTime: nowSec(),
                                     amr: ['assertion'], acr: null } : null;
    grant.decision = { approved: true, tokens: asked.tokens, subject: !!asked.subject };
    const released = await release(req, grant);
    Object.assign(response, released);
    monitor.record(identifier, 'grant.immediate', {});
    log.debug("Leaving createGrant(). Approved without interaction.");
    return { ok: true, status: 200, body: response, grant: grant };
  }
  if (!asked.interact) {
    grant.state = STATE.FINALIZED;
    store.saveGrant(grant, 'refused: interaction required and the client offers none');
    monitor.record(identifier, 'grant.refused', { gnapError: 'invalid_interaction' });
    log.debug("Leaving createGrant(). Interaction needed, none offered.");
    return refusal('STS-GNAP-0113', 'this request needs the resource owner\'s approval and the ' +
                   'client offered no way to interact (RFC 9635 section 2.5).', 'invalid_interaction');
  }
  const started = startInteraction(req, grant, app, asked.interact);
  if (!started.ok) {
    grant.state = STATE.FINALIZED;
    store.saveGrant(grant, 'refused: ' + started.why);
    monitor.record(identifier, 'grant.refused', { gnapError: started.gnapError });
    log.debug("Leaving createGrant(). Interaction refused.");
    return started;
  }
  response.interact = started.interact;
  response.continue = continueMember(req, grant);
  store.saveGrant(grant, 'pending interaction');
  log.debug("Leaving createGrant(). Pending.");
  return { ok: true, status: 200, body: response, grant: grant };
}

// Tokens and subject information for a grant whose decision is approved.
async function release(req, grant) {
  log.debug("Entering release(). grant=" + grant.id);
  const out = {};
  const requests = grant.decision.tokens || [];
  if (requests.length) {
    const issued = await issueTokens(req, grant, requests, grant.request.multiple);
    if (issued) {
      out.access_token = issued;
    }
  }
  if (grant.decision.subject) {
    const released = await releaseSubject(req, grant);
    if (released && (released.sub_ids || released.assertions)) {
      out.subject = released;
    }
  }
  grant.state = STATE.APPROVED;
  grant.delivered = true;
  grant.approvedAccess = accessRights.union ? accessRights.union((grant.approvedAccess || []),
    requests.reduce(function (all, one) { return all.concat(one.access); }, []))
    : requests.reduce(function (all, one) { return all.concat(one.access); }, grant.approvedAccess || []);
  if (config.value('gnap.continueAfterApproval') !== false) {
    out.continue = continueMember(req, grant);
  } else {
    store.dropContinuation(grant);
  }
  store.saveGrant(grant, 'approved and released');
  monitor.record(grant.client.identifier, 'grant.approved', {});
  audit.audit({ action: 'gnap.grant.approve', category: 'protocol', protocol: PROTOCOL,
    channel: 'http', outcome: 'success', actor: grant.ro ? grant.ro.username : grant.client.identifier,
    target: grant.client.identifier, summary: 'A GNAP grant was approved and released',
    detail: { grant: grant.id, tokens: out.access_token ? (Array.isArray(out.access_token)
      ? out.access_token.length : 1) : 0, subject: !!out.subject } });
  log.debug("Leaving release().");
  return out;
}

// ---------------------------------------------------------------------------
// RFC 9767 SECTION 4: TOKEN DERIVATION.
// ---------------------------------------------------------------------------
async function deriveToken(req, grant, app, asked) {
  log.debug("Entering deriveToken().");
  if (config.value('gnap.tokenDerivation') === false) {
    log.debug("Leaving deriveToken(). Off.");
    return refusal('STS-GNAP-0510', 'token derivation is not offered by this authorization server ' +
                   '(RFC 9767 section 4).', 'request_denied', 403);
  }
  const existing = store.tokenByValue(asked.existingAccessToken);
  if (!existing || existing.revoked || (existing.exp && existing.exp < nowSec()) ||
      tokens.isRevokedJti(existing.jti)) {
    log.debug("Leaving deriveToken(). Existing token not active.");
    return refusal('STS-GNAP-0511', 'the existing access token is not active at this authorization ' +
                   'server (RFC 9767 section 4).', 'invalid_request');
  }
  const rsNames = [app.identifier].concat(fieldValues(app, 'gnapResourceServerUri'));
  const forThisRs = !existing.aud.length || existing.aud.some(function (aud) {
    return rsNames.indexOf(aud) >= 0;
  });
  if (!forThisRs) {
    log.debug("Leaving deriveToken(). Existing token not for this RS.");
    return refusal('STS-GNAP-0512', 'the existing access token was not issued for use at this ' +
                   'resource server, so it cannot derive a token (RFC 9767 section 4).',
                   'request_denied', 403);
  }
  const requested = asked.tokens.length ? asked.tokens : [];
  for (let i = 0; i < requested.length; i++) {
    const covered = requested[i].access.every(function (right) {
      return accessRights.accessCovers(existing.access, [right]) || typeof right === 'string' &&
        !!store.resourceByReference(right) && resourceServersFor([right]).length;
    });
    if (!covered) {
      log.debug("Leaving deriveToken(). Asks for more than the existing token.");
      return refusal('STS-GNAP-0513', 'a derived token must not carry more access than the token ' +
                     'it is derived from, except rights registered for a downstream resource ' +
                     'server.', 'request_denied', 403);
    }
  }
  grant.ro = existing.username ? { username: existing.username, sessionId: null,
                                   authTime: existing.iat, amr: ['derived'], acr: null } : null;
  grant.derivedFrom = existing.jti;
  grant.decision = { approved: true, tokens: requested, subject: false };
  const body = await release(req, grant);
  monitor.record(app.identifier, 'rs.derivation', {});
  log.debug("Leaving deriveToken().");
  return { ok: true, status: 200, body: body, grant: grant };
}

// ---------------------------------------------------------------------------
// THE RESOURCE OWNER'S DECISION, from `gnap_interact.js`.
//
// `selection` is `{ approve: bool, tokens: [{label, access}], subject: bool }`
// with the rights the RO LEFT TICKED — section 4 lets the RO "modify the client
// instance's requested access, including limiting ... that access". Answers
// what the page does next: the finish method's redirect URI, or a sentence.
// ---------------------------------------------------------------------------
async function decide(req, grant, session, selection) {
  log.debug("Entering decide(). grant=" + grant.id + ", approve=" + selection.approve);
  const interaction = grant.interaction;
  interaction.decided = true;
  const username = subject.normaliseName(session.user.username);
  if (selection.approve && grant.userHint && grant.userHint !== username &&
      config.value('gnap.allowCrossUser') !== true) {
    // Section 2.4: "If the identified end user does not match the RO present
    // at the AS ... the AS SHOULD reject the request with an unknown_user
    // error." Recorded as the decision, so the continuation says it.
    grant.decision = { approved: false, error: 'unknown_user' };
  } else if (selection.approve) {
    grant.decision = { approved: true, tokens: selection.tokens, subject: !!selection.subject };
    grant.ro = { username: username, sessionId: session.id, authTime: session.authTime,
                 amr: session.amr, acr: session.acr };
    if (config.value('gnap.rememberApprovals') !== false) {
      const digests = [];
      selection.tokens.forEach(function (one) {
        one.access.forEach(function (right) {
          digests.push(digestTokenOf(right));
        });
      });
      if (digests.length) {
        consent.record(username, grant.client.identifier, digests, username);
      }
    }
    signals.noteApprover(grant.client.identifier, username);
  } else {
    grant.decision = { approved: false, error: 'user_denied' };
    grant.ro = { username: username, sessionId: session.id, authTime: session.authTime,
                 amr: session.amr, acr: session.acr };
  }
  monitor.record(grant.client.identifier, grant.decision.approved ? 'grant.approved' : 'grant.denied',
                 { gnapError: grant.decision.error });
  audit.audit({ action: grant.decision.approved ? 'gnap.grant.consent' : 'gnap.grant.deny',
    category: 'protocol', protocol: PROTOCOL, channel: 'http',
    outcome: grant.decision.approved ? 'success' : 'refused',
    errorCode: grant.decision.approved ? undefined : 'STS-GNAP-0120',
    actor: username, target: grant.client.identifier,
    summary: grant.decision.approved ? 'A resource owner approved a GNAP grant'
                                     : 'A resource owner did not approve a GNAP grant',
    detail: { grant: grant.id, why: grant.decision.error || '' } });
  const finished = await finishInteraction(req, grant);
  store.saveGrant(grant, 'resource owner ' + (grant.decision.approved ? 'approved' : 'did not approve') +
                  (grant.decision.error ? ' (' + grant.decision.error + ')' : ''));
  log.debug("Leaving decide().");
  return finished;
}

// A decision already remembered for every requested right — the approval page
// is skipped, the way the OAuth consent screen is.
function rememberedFor(grant, username) {
  if (config.value('gnap.consentRequired') === false) {
    return true;
  }
  if (config.value('gnap.rememberApprovals') === false) {
    return false;
  }
  const held = consent.consentsOf(username).filter(function (row) {
    return row.client === grant.client.identifier;
  }).map(function (row) {
    return row.scope;
  });
  const all = [];
  grant.request.tokens.forEach(function (one) {
    one.access.forEach(function (right) {
      all.push(digestTokenOf(right));
    });
  });
  return all.length > 0 && !grant.request.subject && all.every(function (digest) {
    return held.indexOf(digest) >= 0;
  });
}

// Section 4.2: create the interaction reference, compute the hash, and follow
// the finish method. Answers `{ redirect }`, `{ pushed }` or `{ none }`.
async function finishInteraction(req, grant) {
  log.debug("Entering finishInteraction(). grant=" + grant.id);
  const interaction = grant.interaction;
  interaction.interactRef = store.mint(15);
  const finish = interaction.finish;
  if (!finish) {
    log.debug("Leaving finishInteraction(). No finish method; the client polls.");
    return { none: true };
  }
  const hash = interactionHash(finish.nonce, interaction.serverNonce, interaction.interactRef,
                               grant.grantEndpoint, finish.hashMethod);
  if (finish.method === 'redirect') {
    const target = finish.uri + (finish.uri.indexOf('?') >= 0 ? '&' : '?') +
      'hash=' + encodeURIComponent(hash) + '&interact_ref=' + encodeURIComponent(interaction.interactRef);
    monitor.record(grant.client.identifier, 'finish.redirect', {});
    log.debug("Leaving finishInteraction(). Redirect.");
    return { redirect: target };
  }
  const pushed = await transport.pushFinish(finish.uri, { hash: hash,
                                                          interact_ref: interaction.interactRef });
  if (pushed.ok) {
    monitor.record(grant.client.identifier, 'finish.push', {});
  } else {
    monitor.record(grant.client.identifier, 'finish.push_failed', {});
    audit.failure(pushed.errorCode || 'STS-GNAP-0604', { protocol: PROTOCOL, channel: 'http',
      outcome: 'error', target: grant.client.identifier,
      summary: 'A GNAP push interaction finish was not delivered',
      detail: { grant: grant.id, why: pushed.why, status: pushed.status } });
  }
  interaction.pushed = pushed.ok;
  log.debug("Leaving finishInteraction(). Push ok=" + pushed.ok);
  return { pushed: pushed.ok, why: pushed.why };
}

// ---------------------------------------------------------------------------
// CONTINUATION (section 5). `method` is POST, PATCH or DELETE.
// ---------------------------------------------------------------------------
function continuationCaller(req, grantId) {
  log.debug("Entering continuationCaller().");
  const token = proof.presentedToken(req);
  const grant = store.getGrant(grantId);
  const byToken = token ? store.grantByContinuation(token) : null;
  // Section 5: the URI AND the token together identify ONE grant. A live
  // continuation token for a different grant is refused exactly like an
  // unknown one — it must not even reveal that the URI names a grant.
  if (!grant || !byToken || byToken.id !== grant.id) {
    log.debug("Leaving continuationCaller(). No grant for that URI and token.");
    return refusal('STS-GNAP-0130', 'the continuation URI and access token do not identify an ' +
                   'active grant request (RFC 9635 section 5).', 'invalid_continuation', 401);
  }
  if (grant.state === STATE.FINALIZED) {
    log.debug("Leaving continuationCaller(). Finalized.");
    return refusal('STS-GNAP-0131', 'this grant request is finalized and cannot be continued.',
                   'invalid_continuation', 400);
  }
  const body = proof.readBody(req);
  if (!body.ok) {
    log.debug("Leaving continuationCaller(). Body refused.");
    return body;
  }
  const descriptor = keys.describe(grant.client.key, { resolveReference: resolveKeyReference });
  if (!descriptor.ok) {
    log.debug("Leaving continuationCaller(). The grant's key no longer describes.");
    return Object.assign(descriptor, { status: 401, gnapError: 'invalid_client' });
  }
  const verified = proof.verifyRequest(req, body, descriptor, { accessToken: token });
  if (!verified.ok) {
    monitor.record(grant.client.identifier, 'proof.failed', { gnapError: 'invalid_client' });
    log.debug("Leaving continuationCaller(). Proof refused.");
    return Object.assign(verified, { status: 401, gnapError: 'invalid_client' });
  }
  log.debug("Leaving continuationCaller().");
  return { ok: true, grant: grant, body: body, token: token };
}

function expired(grant) {
  return grant.state === STATE.PENDING && grant.expiresAt && grant.expiresAt < nowSec();
}

function finalize(grant, note) {
  grant.state = STATE.FINALIZED;
  store.dropContinuation(grant);
  store.saveGrant(grant, note);
}

async function continueGrant(req, grantId) {
  log.debug("Entering continueGrant(). method=" + req.method);
  const caller = continuationCaller(req, grantId);
  if (!caller.ok) {
    log.debug("Leaving continueGrant(). Caller refused.");
    return caller;
  }
  const grant = caller.grant;
  const identifier = grant.client.identifier;
  if (expired(grant)) {
    finalize(grant, 'expired');
    log.debug("Leaving continueGrant(). Expired.");
    return refusal('STS-GNAP-0132', 'this grant request expired before it was approved.',
                   'invalid_continuation');
  }
  if (req.method === 'DELETE') {
    return revokeGrant(req, grant);
  }
  if (grant.continueNotBefore && nowSec() < grant.continueNotBefore) {
    monitor.record(identifier, 'continue.too_fast', { gnapError: 'too_fast' });
    const keepGoing = { continue: continueMember(req, grant) };
    store.saveGrant(grant, 'continued too fast');
    log.debug("Leaving continueGrant(). Too fast.");
    return Object.assign(refusal('STS-GNAP-0133', 'the client continued before the wait period ' +
                         'ended (RFC 9635 section 5).', 'too_fast'), { extra: keepGoing });
  }
  if (req.method === 'PATCH') {
    return modifyGrant(req, grant, caller.body);
  }
  const parsed = request.parseContinuation(caller.body.json, caller.body.hadContent);
  if (!parsed.ok) {
    log.debug("Leaving continueGrant(). Continuation body refused.");
    return parsed;
  }
  if (parsed.interactRef) {
    const interaction = grant.interaction;
    if (grant.state !== STATE.PENDING || !interaction) {
      // Section 5.1: MUST return too_many_attempts, SHOULD finalize.
      finalize(grant, 'interaction reference presented outside the pending state');
      monitor.record(identifier, 'grant.refused', { gnapError: 'too_many_attempts' });
      log.debug("Leaving continueGrant(). interact_ref when not pending.");
      return refusal('STS-GNAP-0134', 'an interaction reference was presented for a grant request ' +
                     'that is not pending (RFC 9635 section 5.1).', 'too_many_attempts');
    }
    if (!interaction.interactRef || interaction.interactRef !== parsed.interactRef) {
      const keepGoing = { continue: continueMember(req, grant) };
      store.saveGrant(grant, 'wrong interaction reference presented');
      log.debug("Leaving continueGrant(). Wrong interact_ref.");
      return Object.assign(refusal('STS-GNAP-0135', 'the interaction reference is not the one ' +
                           'issued for this grant request.', 'invalid_interaction'),
                           { extra: keepGoing });
    }
    interaction.interactRef = null;
    interaction.refUsed = true;
    monitor.record(identifier, 'continue.interact_ref', {});
    return settle(req, grant);
  }
  // A POLL (section 5.2).
  monitor.record(identifier, 'continue.poll', {});
  grant.polls = (grant.polls || 0) + 1;
  const maxPolls = Number(config.value('gnap.maxPolls')) || 60;
  if (grant.state === STATE.PENDING && grant.polls > maxPolls) {
    finalize(grant, 'too many polls');
    log.debug("Leaving continueGrant(). Too many polls.");
    return refusal('STS-GNAP-0136', 'the client polled more than ' + maxPolls + ' times before ' +
                   'the resource owner decided (RFC 9635 section 5.2).', 'too_many_attempts');
  }
  if (grant.state === STATE.PENDING && grant.interaction && grant.interaction.finish &&
      !grant.interaction.refUsed) {
    // Section 3.3.5: a client given a finish nonce "MUST NOT continue a grant
    // request before it receives the associated interaction reference".
    const keepGoing = { continue: continueMember(req, grant) };
    store.saveGrant(grant, 'polled before presenting the interaction reference');
    log.debug("Leaving continueGrant(). Poll before the interaction reference.");
    return Object.assign(refusal('STS-GNAP-0137', 'this grant request finishes with a ' +
                         grant.interaction.finish.method + ' carrying an interaction reference; ' +
                         'the client must present it rather than poll (RFC 9635 section 3.3.5).',
                         'invalid_continuation'), { extra: keepGoing });
  }
  return settle(req, grant);
}

// Where a pending grant goes when the client comes back.
async function settle(req, grant) {
  log.debug("Entering settle(). state=" + grant.state);
  if (grant.state === STATE.APPROVED) {
    const body = { continue: continueMember(req, grant) };
    store.saveGrant(grant, 'continued after approval');
    log.debug("Leaving settle(). Already approved; nothing new.");
    return { ok: true, status: 200, body: body };
  }
  if (!grant.decision) {
    const body = { continue: continueMember(req, grant) };
    store.saveGrant(grant, 'polled while pending');
    log.debug("Leaving settle(). Still pending.");
    return { ok: true, status: 200, body: body };
  }
  if (!grant.decision.approved) {
    const code = grant.decision.error || 'user_denied';
    grant.decision = null;
    grant.interaction = null;
    const keepGoing = { continue: continueMember(req, grant) };
    store.saveGrant(grant, 'told the client: ' + code);
    log.debug("Leaving settle(). " + code);
    return Object.assign(refusal(code === 'unknown_user' ? 'STS-GNAP-0121' : 'STS-GNAP-0120',
      code === 'unknown_user' ? 'the person who signed in is not the user the request named ' +
      '(RFC 9635 section 2.4).' : 'the resource owner did not approve the request.', code, 403),
      { extra: keepGoing });
  }
  const body = await release(req, grant);
  log.debug("Leaving settle(). Released.");
  return { ok: true, status: 200, body: body };
}

// Section 5.3.
async function modifyGrant(req, grant, bodyRead) {
  log.debug("Entering modifyGrant().");
  if (grant.state !== STATE.APPROVED && grant.state !== STATE.PENDING) {
    log.debug("Leaving modifyGrant(). Wrong state.");
    return refusal('STS-GNAP-0140', 'only a pending or approved grant request can be modified ' +
                   '(RFC 9635 section 5.3).', 'invalid_continuation');
  }
  const parsed = request.parseModification(bodyRead.json || {});
  if (!parsed.ok) {
    log.debug("Leaving modifyGrant(). Refused.");
    return parsed;
  }
  const asked = parsed.request;
  const app = applications.get(grant.client.identifier);
  if (asked.tokens) {
    for (let i = 0; i < asked.tokens.length; i++) {
      const problem = accessProblem(app, asked.tokens[i].access);
      if (problem) {
        log.debug("Leaving modifyGrant(). Access refused.");
        return refusal('STS-GNAP-0112', problem + '.', 'request_denied', 403);
      }
    }
    grant.request.tokens = asked.tokens;
    grant.request.multiple = asked.multiple;
  }
  if (asked.subject) {
    grant.request.subject = asked.subject;
  }
  monitor.record(grant.client.identifier, 'grant.modified', {});
  const previouslyApproved = grant.approvedAccess || [];
  const requested = grant.request.tokens.reduce(function (all, one) {
    return all.concat(one.access);
  }, []);
  const withinApproval = grant.state === STATE.APPROVED && grant.ro !== undefined &&
    accessRights.accessCovers(previouslyApproved, requested) && !asked.subject;
  grant.state = STATE.PROCESSING;
  if (withinApproval) {
    // Section 5.3's worked example: narrower access, no new consent.
    if (config.value('gnap.revokeOnModify') !== false && config.value('gnap.durableTokens') !== true) {
      revokeTokens(grant, 'grant modified');
    }
    grant.decision = { approved: true, tokens: grant.request.tokens, subject: false };
    const body = await release(req, grant);
    signals.grantModified(req, grant, requested);
    log.debug("Leaving modifyGrant(). Within the earlier approval.");
    return { ok: true, status: 200, body: body };
  }
  if (!asked.interact) {
    grant.state = previouslyApproved.length ? STATE.APPROVED : STATE.PENDING;
    const keepGoing = { continue: continueMember(req, grant) };
    store.saveGrant(grant, 'modification needs approval and no interaction was offered');
    log.debug("Leaving modifyGrant(). Needs interaction, none offered.");
    return Object.assign(refusal('STS-GNAP-0141', 'the modified request asks for more than was ' +
      'approved and offers no way to interact with the resource owner (RFC 9635 section 5.3).',
      'request_denied', 403), { extra: keepGoing });
  }
  grant.decision = null;
  grant.request.interact = asked.interact;
  const started = startInteraction(req, grant, app, asked.interact);
  if (!started.ok) {
    grant.state = previouslyApproved.length ? STATE.APPROVED : STATE.PENDING;
    store.saveGrant(grant, 'modification interaction refused');
    log.debug("Leaving modifyGrant(). Interaction refused.");
    return started;
  }
  const body = { interact: started.interact, continue: continueMember(req, grant) };
  store.saveGrant(grant, 'modified; pending interaction');
  log.debug("Leaving modifyGrant(). Pending interaction.");
  return { ok: true, status: 200, body: body };
}

function revokeTokens(grant, why) {
  (grant.tokens || []).forEach(function (jti) {
    const record = store.tokenByJti(jti);
    if (record && !record.revoked) {
      record.revoked = true;
      record.revokedAt = nowSec();
      record.revokedWhy = why;
      store.dropManagement(record);
      store.saveToken(record);
      if (/^jwt/.test(record.format)) {
        stats.revoke(record.jti, 'GNAP: ' + why);
      }
    }
  });
}

// Section 5.4.
function revokeGrant(req, grant) {
  log.debug("Entering revokeGrant().");
  revokeTokens(grant, 'grant revoked by the client instance');
  finalize(grant, 'revoked by the client instance');
  monitor.record(grant.client.identifier, 'grant.revoked', {});
  audit.audit({ action: 'gnap.grant.revoke', category: 'protocol', protocol: PROTOCOL,
    channel: 'http', outcome: 'success', actor: grant.client.identifier,
    target: grant.client.identifier, summary: 'A GNAP grant was revoked by its client instance',
    detail: { grant: grant.id, tokens: (grant.tokens || []).length } });
  signals.grantRevoked(req, grant, 'The client instance revoked the grant.');
  log.debug("Leaving revokeGrant().");
  return { ok: true, status: 204, body: null };
}

// ---------------------------------------------------------------------------
// TOKEN MANAGEMENT (section 6).
// ---------------------------------------------------------------------------
async function manageToken(req, handle) {
  log.debug("Entering manageToken(). method=" + req.method);
  const presented = proof.presentedToken(req);
  const record = presented ? store.tokenByManagement(handle, presented) : null;
  if (!record) {
    log.debug("Leaving manageToken(). Unknown management URI or token.");
    return refusal('STS-GNAP-0150', 'the token management URI and access token do not identify a ' +
                   'token (RFC 9635 section 6).', req.method === 'DELETE' ? 'invalid_request'
                                                                          : 'invalid_rotation', 401);
  }
  const grant = store.getGrant(record.grantId);
  const body = proof.readBody(req);
  if (!body.ok) {
    log.debug("Leaving manageToken(). Body refused.");
    return body;
  }
  // Section 7.3: bound to the token's own key or, for a bearer token, the
  // client instance's.
  const keyJson = record.key || (grant ? grant.client.key : null);
  const descriptor = keys.describe(keyJson, { resolveReference: resolveKeyReference });
  if (!descriptor.ok) {
    log.debug("Leaving manageToken(). No key to verify with.");
    return Object.assign(descriptor, { status: 401, gnapError: 'invalid_client' });
  }
  if (req.method === 'DELETE') {
    const verified = proof.verifyRequest(req, body, descriptor, { accessToken: presented });
    if (!verified.ok) {
      monitor.record(record.instanceId, 'proof.failed', { gnapError: 'invalid_client' });
      log.debug("Leaving manageToken(). DELETE proof refused.");
      return Object.assign(verified, { status: 401, gnapError: 'invalid_client' });
    }
    record.revoked = true;
    record.revokedAt = nowSec();
    record.revokedWhy = 'revoked by the client instance';
    store.dropManagement(record);
    store.saveToken(record);
    if (/^jwt/.test(record.format)) {
      stats.revoke(record.jti, 'GNAP token management');
    }
    monitor.record(record.instanceId, 'token.revoked', {});
    audit.audit({ action: 'gnap.token.revoke', category: 'protocol', protocol: PROTOCOL,
      channel: 'http', outcome: 'success', actor: record.instanceId, target: record.instanceId,
      summary: 'A GNAP access token was revoked by its client instance',
      detail: { jti: record.jti, format: record.format } });
    signals.tokenRevoked(req, record, grant);
    log.debug("Leaving manageToken(). Revoked.");
    return { ok: true, status: 204, body: null };
  }
  // POST: rotation, optionally with a new key.
  const parsed = request.parseRotation(body.json, body.hadContent);
  if (!parsed.ok) {
    log.debug("Leaving manageToken(). Rotation body refused.");
    return parsed;
  }
  let newDescriptor = null;
  if (parsed.key) {
    if (!config.value('gnap.keyRotation') ||
        capabilities(req, record.as).key_rotation_supported === false) {
      log.debug("Leaving manageToken(). Key rotation off.");
      return refusal('STS-GNAP-0151', 'this authorization server does not allow rotating an access ' +
                     'token\'s key (RFC 9635 section 6.1.1).', 'key_rotation_not_supported');
    }
    if (!record.key) {
      log.debug("Leaving manageToken(). Bearer token has no key to rotate.");
      return refusal('STS-GNAP-0152', 'a bearer token has no key to rotate (RFC 9635 section 6.1.1).',
                     'invalid_rotation');
    }
    newDescriptor = keys.describe(parsed.key, { resolveReference: resolveKeyReference });
    if (!newDescriptor.ok) {
      log.debug("Leaving manageToken(). New key refused.");
      return Object.assign(newDescriptor, { gnapError: 'invalid_rotation' });
    }
  }
  const verified = proof.verifyRequest(req, body, descriptor,
                                       { accessToken: presented, rotation: newDescriptor });
  if (!verified.ok) {
    monitor.record(record.instanceId, 'proof.failed', { gnapError: verified.gnapError });
    log.debug("Leaving manageToken(). Rotation proof refused.");
    return Object.assign(verified, { status: verified.gnapError === 'key_rotation_not_supported' ? 400 : 401,
                                     gnapError: newDescriptor ? verified.gnapError : 'invalid_client' });
  }
  if (record.revoked || tokens.isRevokedJti(record.jti)) {
    log.debug("Leaving manageToken(). Revoked tokens do not rotate.");
    return refusal('STS-GNAP-0153', 'a revoked access token cannot be rotated.', 'invalid_rotation');
  }
  if (grant && grant.state === STATE.FINALIZED) {
    log.debug("Leaving manageToken(). The grant is finalized.");
    return refusal('STS-GNAP-0154', 'the grant this token belongs to is finalized.', 'invalid_rotation');
  }
  const iat = nowSec();
  const lifetime = Math.max(1, (record.exp || iat) - (record.iat || iat)) ||
    (Number(config.value('gnap.accessTokenLifetimeS')) || 3600);
  const cnf = newDescriptor ? keys.confirmationOf(newDescriptor) : record.cnf;
  const model = { jti: store.mint(16), iss: record.iss, sub: record.sub, aud: record.aud,
                  instanceId: record.instanceId, access: record.access, flags: record.flags,
                  cnf: cnf, iat: iat, nbf: iat, exp: iat + lifetime, label: record.label };
  let minted;
  try {
    const rs = record.rsIdentifiers && record.rsIdentifiers.length === 1
      ? applications.get(record.rsIdentifiers[0]) : null;
    minted = await tokens.mint(record.format, model, { base: realmBase(req),
      rs: rs ? { identity: rs.identifier, jweKey: field(rs, 'gnapJweKey') ? JSON.parse(field(rs, 'gnapJweKey')) : null } : null,
      setId: record.grantId });
  } catch (e) {
    log.error(errorCodes.tag('STS-GNAP-0155') + 'gnap: a rotated ' + record.format + ' token could ' +
              'not be minted: ' + e.message);
    return refusal('STS-GNAP-0155', 'the token could not be rotated.', 'invalid_rotation');
  }
  const next = store.putToken(Object.assign({}, record, model, {
    key: newDescriptor ? newDescriptor.value : record.key,
    proof: newDescriptor ? newDescriptor.proof : record.proof,
    rotatedFrom: record.jti, revoked: false, createdAt: iat, manageHandle: null, manageHash: null
  }), minted.value);
  // Section 6.1: "the AS MUST invalidate the current access token value".
  record.revoked = true;
  record.revokedAt = iat;
  record.revokedWhy = 'rotated';
  record.rotatedTo = next.jti;
  store.moveManagement(record, next);
  store.saveToken(record);
  if (/^jwt/.test(record.format)) {
    stats.revoke(record.jti, 'GNAP rotation');
  }
  const manageValue = store.issueManagement(next);
  store.saveToken(next);
  if (grant) {
    grant.tokens = (grant.tokens || []).concat([next.jti]);
    if (newDescriptor) {
      // Section 6.1.1: the grant's key follows the token's most recent rotation.
      grant.client.key = newDescriptor.value;
      grant.client.keyIdentity = newDescriptor.identity;
    }
    store.saveGrant(grant, newDescriptor ? 'token key rotated' : 'token rotated');
  }
  monitor.record(record.instanceId, newDescriptor ? 'token.key_rotated' : 'token.rotated',
                 { format: record.format });
  audit.audit({ action: 'gnap.token.rotate', category: 'protocol', protocol: PROTOCOL,
    channel: 'http', outcome: 'success', actor: record.instanceId, target: record.instanceId,
    summary: 'A GNAP access token was rotated' + (newDescriptor ? ' onto a new key' : ''),
    detail: { from: record.jti, to: next.jti, format: record.format } });
  const response = { value: minted.value, access: next.access, expires_in: lifetime,
                     manage: { uri: realmBase(req) + '/gnap/token/' + next.manageHandle,
                               access_token: { value: manageValue } } };
  if (next.label) {
    response.label = next.label;
  }
  if (next.flags && next.flags.length) {
    response.flags = next.flags;
  }
  log.debug("Leaving manageToken(). Rotated.");
  return { ok: true, status: 200, body: { access_token: response } };
}

module.exports = {
  PROTOCOL: PROTOCOL,
  KIND_CLIENT: KIND_CLIENT,
  KIND_RS: KIND_RS,
  GNAP_MEMBERS: GNAP_MEMBERS,
  RESERVED_AS_NAMES: RESERVED_AS_NAMES,
  capabilities: capabilities,
  capabilityList: capabilityList,
  defaultCapabilities: defaultCapabilities,
  grantEndpointOf: grantEndpointOf,
  realmBase: realmBase,
  gnapApplications: gnapApplications,
  field: field,
  fieldValues: fieldValues,
  resolveKeyReference: resolveKeyReference,
  identifyCaller: identifyCaller,
  createGrant: createGrant,
  continueGrant: continueGrant,
  manageToken: manageToken,
  decide: decide,
  rememberedFor: rememberedFor,
  finishInteraction: finishInteraction,
  interactionHash: interactionHash,
  normaliseUserCode: normaliseUserCode,
  digestTokenOf: digestTokenOf,
  canonicalJson: canonicalJson,
  resourceServersFor: resourceServersFor,
  revokeTokens: revokeTokens
};
