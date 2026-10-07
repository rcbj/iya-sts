// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: listener_map.js
//
// ===========================================================================
// CUSTOM LISTENERS, AND WHICH HOSTED APPLICATION IS ON WHICH (#472,
// 2026-10-07).
//
// rcbj: "I want to be able to define custom listeners and map the hosted
// applications to specific listeners ... Common use cases include putting the
// authentication service on a custom listener that requires MASSL. Or, moving
// the admin console and mgmt API off of the main listener." And: "I want to
// be able to advertise services on multiple listeners potentially. it's up to
// the administrator and their use case."
//
// THREE THINGS ARE DECIDED HERE, AND ONLY HERE:
//
//   1. WHAT THE LISTENERS ARE. The main port is the built-in listener `main`.
//      Beside it an administrator defines HTTPS listeners, each a JSON object
//      — `id`, `port`, `publicBaseUrl`, `hostnames`, `certificateFile` and
//      `privateKeyFile`, `clientAuth` (`none`, `optional` or `required`) and
//      a `tls` block of the per-listener TLS settings (#429's names, with
//      #429's inherit values) — in one of two settings:
//        * `listeners.custom`, the SERVICE's listeners: they answer every
//          realm, under its prefix, as the main port does;
//        * `listeners.realm`, a REALM's own (rcbj's D1: #99's realm listener
//          folded in): `realmOnly`, set on that realm, answering that realm's
//          paths alone (`common/app.js`, STS-TLS-0041).
//      Every node binds every listener (`tls/listeners.js`), because no node
//      is ever exposed on an address of its own.
//
//   2. WHICH APPLICATION IS ON WHICH LISTENER. `listeners.applications`
//      maps an application id (`common/hosted_applications.js`), or `*` for
//      every application not named, to `{ listeners: [...], advertised }`:
//      the listeners that ANSWER it, and the one whose base its URLs are
//      built on. An application the mapping does not mention is on `main`
//      alone, so a service with no mapping is the service it always was.
//      PER REALM, INHERITING (rcbj's D2): a realm's own value is read entry
//      by entry first — its `app`, then its `*` — and the process's after,
//      so a realm says only what differs.
//
//   3. WHERE AN APPLICATION'S URLS ARE BUILT. One canonical base per
//      application per realm (rcbj's D4): the advertised listener's
//      `publicBaseUrl`, or, for `main`, `global.publicBaseUrl` or the
//      request's own address as before. `common/helpers.js`'s
//      `pinnedBaseUrl(app)`, `baseUrlOf(req, app)` and `urlOf(req, path)`
//      ask `advertisedBase()`. The other listeners an application is on are
//      advertised only where a specification has a place for an alternative
//      — RFC 8705's `mtls_endpoint_aliases` (`alternativeBases()`).
//
// AND FOUR RULES ARE HELD AT EVERY WRITE (`config.addWriteRule()` for the
// process's settings, `realms.js`'s `listenerOverrideProblem()` for a
// realm's), over the WHOLE state the write would leave, so no order of writes
// can arrive somewhere a single write could not:
//
//   * every listener is well formed, its id and port its own (no other
//     listener's, none of the process's fixed sockets'), and none exists
//     while this service runs as several cells (#99's rule, kept);
//   * every mapping names applications and listeners that exist in its
//     scope — the process's names `main` and the service's listeners, a
//     realm's those and its own — and a listener a mapping names cannot be
//     removed;
//   * THE SIGN-ON SESSION'S COOKIE MUST REACH EVERY APPLICATION THAT READS IT
//     (rcbj's D3). The cookie is host-only unless `authn.cookieDomain` is
//     set; so the listeners the session-reading applications are on must
//     share one host name, or every one of their host names must be under
//     `authn.cookieDomain`;
//   * A WRITE MAY NOT TAKE `/admin-api` OFF THE LISTENER IT ARRIVED ON
//     unless it says it means to (rcbj's D6): the management API's
//     `PUT /admin-api/listeners/applications` with `confirm: true`. The
//     other half of D6 is `listeners.adminOnMain`, an environment or
//     appconfig setting no write can reach, which puts the console and the
//     API back on `main` whatever the mapping says.
//
// A LEAF IN JAVASCRIPT, for `hosted_applications.js`'s reason: helpers.js
// requires it at load. It requires the settings, the realms, the error codes
// and the catalogue; `common/cells.js` and the ambient request
// (`jose_certificate_header.js`) only lazily, when a write is judged.
// ===========================================================================

const bunyan = require('bunyan');
const config = require('./config');
const realms = require('./realms');
const errorCodes = require('./error_codes');
const applications = require('./hosted_applications');

const log = bunyan.createLogger({ name: 'sts-listener-map' });
config.registerLogger(log);

/**
 * The built-in listener: the main port.
 */
const MAIN = 'main';

const SERVICE_SETTING = 'listeners.custom';
const REALM_SETTING = 'listeners.realm';
const MAP_SETTING = 'listeners.applications';
const RESCUE_SETTING = 'listeners.adminOnMain';
const COOKIE_SETTING = 'authn.cookieDomain';

// Ids a listener may not take: the built-in one, the fixed sockets' names on
// Server configuration -> Listeners, and the mapping's wildcard.
const RESERVED_IDS = ['main', 'ldap', 'ldaps', 'debugger', 'kdc',
                      'krb5-service', 'revocation', 'spiffe-workload',
                      'spiffe-server', 'spiffe-broker', 'cell', 'default'];

// The process's own sockets, by the setting that names each port: a custom
// listener may be on none of them (#99's list, moved here from realms.js).
const PROCESS_PORT_SETTINGS = [
  'global.port', 'pki.httpPort', 'debugger.port', 'krb5.kdcPort',
  'krb5.servicePort', 'ldap.port', 'ldap.tlsPort', 'spiffe.workloadPort',
  'spiffe.serverPort', 'spiffe.brokerPort', 'cells.port'
];

// THE TLS BLOCK: every per-listener setting the main port has (#429), by its
// short name, with the service-wide row it overrides. Read once from
// config.js's own table, so a setting added there for the main port is one a
// custom listener can carry too.
const TLS_FIELDS = {};
config.PER_LISTENER_SETTINGS.forEach(function (spec) {
  if (spec.listeners.indexOf('main') >= 0) {
    TLS_FIELDS[spec.name] = spec.base;
  }
});

const ID_PATTERN = /^[a-z][a-z0-9-]{0,31}$/;
// A DNS name of two labels or more, no leading dot: `authn.cookieDomain`.
const DOMAIN_PATTERN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;
const CLIENT_AUTH = ['none', 'optional', 'required'];

function problem(code, message) {
  log.debug("Entering problem(). " + code);
  log.debug("Leaving problem().");
  return { code: code, message: message };
}

// An https origin with no path, query, fragment or user — the shape every
// listener's public base takes (#99's rule).
function originProblem(where, base) {
  log.debug("Entering originProblem().");
  let parsed = null;
  try {
    parsed = new URL(String(base || ''));
  } catch (e) {
    log.debug("Caught in originProblem(): " + ((e && e.message) || e));
  }
  if (!parsed || parsed.protocol !== 'https:' || parsed.username ||
      parsed.password || (parsed.pathname && parsed.pathname !== '/') ||
      parsed.search || parsed.hash) {
    log.debug("Leaving originProblem(). Not an origin.");
    return problem('STS-CORE-0146', where + '\'s publicBaseUrl must be an ' +
      'https origin with no path, query or user — https://idp.example.com ' +
      'or https://idp.example.com:8443 — and "' + String(base || '') +
      '" is not. A realm\'s /realm/<id> prefix is added after it.');
  }
  log.debug("Leaving originProblem().");
  return null;
}

// One value of a listener's `tls` block, held to the service-wide row it
// overrides: an inherit value (absent, `inherit`, '' or -1, #429's), or a
// value that row would take.
function tlsValueProblem(where, name, value) {
  log.debug("Entering tlsValueProblem(). " + name);
  if (value === undefined || value === null || value === 'inherit' ||
      value === '' || value === -1) {
    log.debug("Leaving tlsValueProblem(). Inherits.");
    return null;
  }
  const base = TLS_FIELDS[name];
  let raw = value;
  if (Array.isArray(value)) {
    raw = value.join(',');
  } else if (value === 'on' || value === 'off') {
    raw = value === 'on' ? 'true' : 'false';
  }
  const parsed = config.parseAs(base, String(raw));
  if (!parsed.ok) {
    log.debug("Leaving tlsValueProblem(). Refused.");
    return problem('STS-CORE-0153', where + '\'s tls.' + name + ' is not a ' +
      'value ' + base + ' takes: ' + parsed.problem + '.');
  }
  log.debug("Leaving tlsValueProblem().");
  return null;
}

/**
 * Parses one setting's list of listener definitions.
 *
 * @param raw - the setting's text: '' or a JSON array
 * @param owner - the realm that owns them; the default realm for the
 *   service's
 * @returns `{ listeners, problem }`: the normalised definitions, and the
 *   first `{ code, message }` found in them or null
 */
function parseListeners(raw, owner) {
  log.debug("Entering parseListeners(). " + owner);
  const text = String(raw === undefined || raw === null ? '' : raw).trim();
  const out = { listeners: [], problem: null };
  if (!text) {
    log.debug("Leaving parseListeners(). None.");
    return out;
  }
  const setting = owner === realms.DEFAULT_ID ? SERVICE_SETTING
                                              : REALM_SETTING;
  let list;
  try {
    list = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in parseListeners(): " + ((e && e.message) || e));
    out.problem = problem('STS-CORE-0153', setting + ' is not JSON: ' +
                          ((e && e.message) || e));
    log.debug("Leaving parseListeners(). Not JSON.");
    return out;
  }
  if (!Array.isArray(list)) {
    out.problem = problem('STS-CORE-0153', setting + ' must be a JSON ' +
                          'array of listener definitions.');
    log.debug("Leaving parseListeners(). Not an array.");
    return out;
  }
  const seen = {};
  for (let i = 0; i < list.length; i += 1) {
    const one = list[i];
    const where = 'listener ' + (one && one.id ? '"' + one.id + '"'
                                               : '#' + (i + 1)) +
                  ' in ' + setting;
    if (!one || typeof one !== 'object' || Array.isArray(one)) {
      out.problem = problem('STS-CORE-0153', where + ' is not an object.');
      break;
    }
    const known = ['id', 'port', 'publicBaseUrl', 'hostnames',
                   'certificateFile', 'privateKeyFile', 'clientAuth', 'tls',
                   'label'];
    const unknown = Object.keys(one).filter(function (k) {
      return known.indexOf(k) < 0;
    });
    if (unknown.length) {
      out.problem = problem('STS-CORE-0153', where + ' has a member this ' +
        'service does not know: ' + unknown.join(', ') + '. A listener ' +
        'takes ' + known.join(', ') + '.');
      break;
    }
    const id = String(one.id || '');
    if (!ID_PATTERN.test(id) || RESERVED_IDS.indexOf(id) >= 0) {
      out.problem = problem('STS-CORE-0153', where + ' needs an id of ' +
        'lower-case letters, digits and hyphens, starting with a letter, ' +
        'at most 32 long, and none of ' + RESERVED_IDS.join(', ') + '.');
      break;
    }
    if (seen[id]) {
      out.problem = problem('STS-CORE-0153', setting + ' defines the ' +
                            'listener "' + id + '" twice.');
      break;
    }
    seen[id] = true;
    const port = Number(one.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      out.problem = problem('STS-CORE-0153', where + ' needs a port from ' +
                            '1 to 65535.');
      break;
    }
    const bad = originProblem(where, one.publicBaseUrl);
    if (bad) {
      out.problem = bad;
      break;
    }
    if (one.hostnames !== undefined && (!Array.isArray(one.hostnames) ||
        one.hostnames.some(function (h) {
          return typeof h !== 'string' || !h.trim();
        }))) {
      out.problem = problem('STS-CORE-0153', where + '\'s hostnames must ' +
                            'be an array of DNS names.');
      break;
    }
    const certificateFile = String(one.certificateFile || '').trim();
    const privateKeyFile = String(one.privateKeyFile || '').trim();
    if (!!certificateFile !== !!privateKeyFile) {
      out.problem = problem('STS-CORE-0153', where + ' names a ' +
        (certificateFile ? 'certificateFile and no privateKeyFile'
                         : 'privateKeyFile and no certificateFile') +
        ': both or neither.');
      break;
    }
    const clientAuth = String(one.clientAuth || 'optional');
    if (CLIENT_AUTH.indexOf(clientAuth) < 0) {
      out.problem = problem('STS-CORE-0153', where + '\'s clientAuth is ' +
                            'one of ' + CLIENT_AUTH.join(', ') + '.');
      break;
    }
    const tls = one.tls === undefined ? {} : one.tls;
    if (!tls || typeof tls !== 'object' || Array.isArray(tls)) {
      out.problem = problem('STS-CORE-0153', where + '\'s tls must be an ' +
                            'object.');
      break;
    }
    const strange = Object.keys(tls).filter(function (k) {
      return !Object.prototype.hasOwnProperty.call(TLS_FIELDS, k);
    });
    if (strange.length) {
      out.problem = problem('STS-CORE-0153', where + '\'s tls has a ' +
        'setting no listener carries: ' + strange.join(', ') + '. It ' +
        'takes ' + Object.keys(TLS_FIELDS).join(', ') + '.');
      break;
    }
    let tlsBad = null;
    Object.keys(tls).some(function (name) {
      tlsBad = tlsValueProblem(where, name, tls[name]);
      return !!tlsBad;
    });
    if (tlsBad) {
      out.problem = tlsBad;
      break;
    }
    // ITS OWN POST-QUANTUM ONLY (#423) needs a 256-bit TLS 1.3 suite in the
    // list it will use — its own, or the service's it inherits — or the
    // listener would refuse every client. tls/tls_server.js holds the same
    // rule for the service's settings.
    if (tls.pqcOnly === true || tls.pqcOnly === 'on') {
      const own = tls.tls13CipherSuites;
      const suites = (Array.isArray(own) ? own : String(own || '')
        .split(',')).map(function (one) {
        return String(one).trim();
      }).filter(Boolean);
      const used = suites.length ? suites : String(config.processValue(
        'tls.tls13CipherSuites') || '').split(',').map(function (one) {
        return one.trim();
      });
      if (used.indexOf('TLS_AES_256_GCM_SHA384') < 0 &&
          used.indexOf('TLS_CHACHA20_POLY1305_SHA256') < 0) {
        out.problem = problem('STS-TLS-0043', where + '\'s tls.pqcOnly ' +
          'needs a 256-bit TLS 1.3 suite (TLS_AES_256_GCM_SHA384 or ' +
          'TLS_CHACHA20_POLY1305_SHA256) in ' + (suites.length
            ? 'its tls.tls13CipherSuites'
            : 'tls.tls13CipherSuites, which it inherits') +
          ', and there is none.');
        break;
      }
    }
    let host = '';
    try {
      host = new URL(String(one.publicBaseUrl)).hostname;
    } catch (e) {
      log.debug("Caught in parseListeners(): " + ((e && e.message) || e));
    }
    const hostnames = (one.hostnames || []).map(function (h) {
      return String(h).trim();
    });
    out.listeners.push({
      id: id, owner: owner, builtin: false, port: port,
      label: String(one.label || id),
      publicBaseUrl: String(one.publicBaseUrl).replace(/\/+$/, ''),
      host: host.toLowerCase(),
      hostnames: hostnames.length ? hostnames : (host ? [host] : []),
      certificateFile: certificateFile, privateKeyFile: privateKeyFile,
      clientAuth: clientAuth, tls: Object.assign({}, tls)
    });
  }
  log.debug("Leaving parseListeners(). " + out.listeners.length);
  return out;
}

/**
 * Parses one mapping of applications to listeners.
 *
 * @param raw - the setting's text: '' or a JSON object
 * @param where - what the mapping is, for a message
 * @returns `{ map, problem }`: the mapping, each entry `{ listeners,
 *   advertised }`, and the first `{ code, message }` found or null
 */
function parseMapping(raw, where) {
  log.debug("Entering parseMapping().");
  const text = String(raw === undefined || raw === null ? '' : raw).trim();
  const out = { map: {}, problem: null };
  if (!text) {
    log.debug("Leaving parseMapping(). None.");
    return out;
  }
  let map;
  try {
    map = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in parseMapping(): " + ((e && e.message) || e));
    out.problem = problem('STS-CORE-0154', where + ' is not JSON: ' +
                          ((e && e.message) || e));
    log.debug("Leaving parseMapping(). Not JSON.");
    return out;
  }
  if (!map || typeof map !== 'object' || Array.isArray(map)) {
    out.problem = problem('STS-CORE-0154', where + ' must be a JSON object ' +
      'from an application id (or *) to { "listeners": [...], ' +
      '"advertised": "..." }.');
    log.debug("Leaving parseMapping(). Not an object.");
    return out;
  }
  const keys = Object.keys(map);
  for (let i = 0; i < keys.length; i += 1) {
    const app = keys[i];
    const entry = map[app];
    if (app !== '*' && !applications.isApplication(app)) {
      out.problem = problem('STS-CORE-0154', where + ' names "' + app +
        '", which is no application. The applications are ' +
        applications.list().map(function (one) {
          return one.id;
        }).join(', ') + ', and * for every one not named.');
      break;
    }
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
        !Array.isArray(entry.listeners) || !entry.listeners.length ||
        entry.listeners.some(function (id) {
          return typeof id !== 'string' || !id;
        })) {
      out.problem = problem('STS-CORE-0154', where + '\'s "' + app + '" ' +
        'needs a non-empty "listeners" array of listener ids.');
      break;
    }
    const strange = Object.keys(entry).filter(function (k) {
      return k !== 'listeners' && k !== 'advertised';
    });
    if (strange.length) {
      out.problem = problem('STS-CORE-0154', where + '\'s "' + app + '" ' +
        'has a member this service does not know: ' + strange.join(', ') +
        '. An entry takes listeners and advertised.');
      break;
    }
    const listed = entry.listeners.filter(function (id, at) {
      return entry.listeners.indexOf(id) === at;
    });
    const advertised = entry.advertised === undefined ? listed[0]
                                                      : entry.advertised;
    if (listed.indexOf(advertised) < 0) {
      out.problem = problem('STS-CORE-0154', where + '\'s "' + app + '" ' +
        'advertises "' + String(advertised) + '", which is not one of its ' +
        'listeners (' + listed.join(', ') + ').');
      break;
    }
    out.map[app] = { listeners: listed, advertised: advertised };
  }
  log.debug("Leaving parseMapping().");
  return out;
}

// The built-in listener, as a definition the rest can read.
function mainListener(publicBaseUrl) {
  log.debug("Entering mainListener().");
  const base = String(publicBaseUrl || '').trim().replace(/\/+$/, '');
  let host = '';
  try {
    host = base ? new URL(base).hostname : '';
  } catch (e) {
    log.debug("Caught in mainListener(): " + ((e && e.message) || e));
  }
  log.debug("Leaving mainListener().");
  return { id: MAIN, owner: realms.DEFAULT_ID, builtin: true, port: 0,
           label: 'Main port', publicBaseUrl: base, host: host.toLowerCase(),
           hostnames: [], certificateFile: '', privateKeyFile: '',
           clientAuth: null, tls: {} };
}

// One realm's own raw value of a realm-layer setting — its override alone,
// never the process's.
function realmOwn(realm, key) {
  log.debug("Entering realmOwn(). " + key);
  const o = realm && realm.overrides;
  log.debug("Leaving realmOwn().");
  return o && Object.prototype.hasOwnProperty.call(o, key) ? o[key] : '';
}

// ---------------------------------------------------------------------------
// THE STATE: everything the four rules and every reader need, read once.
// A write is judged by building the state as it is, patching in the value
// being written, and asking `stateProblem()` of the result.
// ---------------------------------------------------------------------------
function currentState() {
  log.debug("Entering currentState().");
  const state = {
    publicBaseUrl: String(config.processValue('global.publicBaseUrl') || ''),
    service: String(config.processValue(SERVICE_SETTING) || ''),
    map: String(config.processValue(MAP_SETTING) || ''),
    cookieDomain: String(config.processValue(COOKIE_SETTING) || ''),
    realms: {}
  };
  realms.list().forEach(function (realm) {
    if (realm.id === realms.DEFAULT_ID || Number(realm.retiringSince) > 0) {
      return;
    }
    state.realms[realm.id] = {
      own: String(realmOwn(realm, REALM_SETTING) || ''),
      map: String(realmOwn(realm, MAP_SETTING) || ''),
      cookieDomain: realmOwn(realm, COOKIE_SETTING)
    };
  });
  log.debug("Leaving currentState().");
  return state;
}

// The parsed state: every listener by id, and each scope's mapping.
function resolveState(state) {
  log.debug("Entering resolveState().");
  const out = { byId: {}, all: [], problem: null, processMap: {},
                realmMaps: {}, state: state };
  // Inline, once per listener of one read: no Entering/Leaving pair, which
  // would drown `resolveState()`'s own around a push.
  const add = function (one) {
    if (out.byId[one.id] && !out.problem) {
      out.problem = problem('STS-CORE-0153', 'The listener id "' + one.id +
        '" is defined twice (' + out.byId[one.id].owner + ' and ' +
        one.owner + '): an id names one listener in the whole service.');
    }
    out.byId[one.id] = one;
    out.all.push(one);
  };
  add(mainListener(state.publicBaseUrl));
  const service = parseListeners(state.service, realms.DEFAULT_ID);
  out.problem = out.problem || service.problem;
  service.listeners.forEach(add);
  Object.keys(state.realms).forEach(function (id) {
    const own = parseListeners(state.realms[id].own, id);
    out.problem = out.problem || own.problem;
    own.listeners.forEach(add);
  });
  const proc = parseMapping(state.map, MAP_SETTING);
  out.problem = out.problem || proc.problem;
  out.processMap = proc.map;
  Object.keys(state.realms).forEach(function (id) {
    const own = parseMapping(state.realms[id].map, MAP_SETTING +
                             ' on realm "' + id + '"');
    out.problem = out.problem || own.problem;
    out.realmMaps[id] = own.map;
  });
  log.debug("Leaving resolveState(). " + out.all.length);
  return out;
}

// One application's mapping in one realm, from a resolved state: the realm's
// own entry, its `*`, the process's entry, the process's `*`, else `main`.
function effectiveIn(resolved, realmId, app) {
  log.debug("Entering effectiveIn(). " + realmId + " " + app);
  const own = realmId && realmId !== realms.DEFAULT_ID
    ? resolved.realmMaps[realmId] || {} : {};
  const proc = resolved.processMap || {};
  const entry = own[app] || own['*'] || proc[app] || proc['*'] ||
                { listeners: [MAIN], advertised: MAIN };
  // A listener that does not exist, or is another realm's, is not one the
  // application is on; the write rules refuse both, so this is a store
  // edited by hand.
  const usable = entry.listeners.filter(function (id) {
    const one = resolved.byId[id];
    return !!one && (one.owner === realms.DEFAULT_ID ||
                     one.owner === realmId);
  });
  const listeners = usable.length ? usable : [MAIN];
  const advertised = listeners.indexOf(entry.advertised) >= 0
    ? entry.advertised : listeners[0];
  log.debug("Leaving effectiveIn().");
  return { listeners: listeners, advertised: advertised };
}

// THE FOUR RULES (see the header) over a whole state. The first problem, or
// null.
function stateProblem(state, options) {
  log.debug("Entering stateProblem().");
  const resolved = resolveState(state);
  if (resolved.problem) {
    log.debug("Leaving stateProblem(). Malformed.");
    return resolved.problem;
  }
  const custom = resolved.all.filter(function (one) {
    return !one.builtin;
  });
  // THE PORTS: each its own, and none of the process's fixed sockets'.
  const ports = {};
  PROCESS_PORT_SETTINGS.forEach(function (key) {
    let v = 0;
    try {
      v = Number(config.processValue(key));
    } catch (e) {
      log.debug("Caught in stateProblem(): " + ((e && e.message) || e));
    }
    if (v > 0) {
      ports[v] = key;
    }
  });
  for (const one of custom) {
    if (ports[one.port]) {
      log.debug("Leaving stateProblem(). A port taken.");
      return problem('STS-CORE-0147', 'Listener "' + one.id + '" is on ' +
        'port ' + one.port + ', which is already ' + ports[one.port] +
        '. Every node binds every listener, so each port must be its own.');
    }
    ports[one.port] = 'listener "' + one.id + '"';
  }
  if (custom.length) {
    let multiCell = false;
    try {
      multiCell = !!require('./cells').isMulti();
    } catch (e) {
      log.debug("Caught in stateProblem(): " + ((e && e.message) || e));
    }
    if (multiCell) {
      log.debug("Leaving stateProblem(). Several cells.");
      return problem('STS-CORE-0148', 'Custom listeners are not supported ' +
        'while this service runs as several cells: a cell\'s public name ' +
        'and a listener\'s would both claim the browser. It is a follow-up ' +
        'of #99 and #472.');
    }
  }
  // THE MAPPINGS NAME LISTENERS OF THEIR OWN SCOPE.
  const scopeProblem = function (map, realmId, where) {
    log.debug("Entering scopeProblem(). " + where);
    const apps = Object.keys(map);
    for (const app of apps) {
      for (const id of map[app].listeners) {
        const one = resolved.byId[id];
        if (!one) {
          log.debug("Leaving scopeProblem(). Not defined.");
          return problem('STS-CORE-0154', where + ' puts "' + app + '" on ' +
            'the listener "' + id + '", which is not defined. The ' +
            'listeners are ' + resolved.all.map(function (l) {
              return l.id;
            }).join(', ') + '.');
        }
        if (one.owner !== realms.DEFAULT_ID && one.owner !== realmId) {
          log.debug("Leaving scopeProblem(). Another realm's.");
          return problem('STS-CORE-0154', where + ' puts "' + app + '" on ' +
            'the listener "' + id + '", which belongs to realm "' +
            one.owner + '" and answers that realm alone.');
        }
      }
    }
    log.debug("Leaving scopeProblem().");
    return null;
  };
  const procBad = scopeProblem(resolved.processMap, realms.DEFAULT_ID,
                               MAP_SETTING);
  if (procBad) {
    log.debug("Leaving stateProblem(). The process's mapping.");
    return procBad;
  }
  for (const id of Object.keys(resolved.realmMaps)) {
    const bad = scopeProblem(resolved.realmMaps[id], id, MAP_SETTING +
                             ' on realm "' + id + '"');
    if (bad) {
      log.debug("Leaving stateProblem(). A realm's mapping.");
      return bad;
    }
  }
  // THE SIGN-ON SESSION'S COOKIE (rcbj's D3), in every realm — and, first,
  // THE ENTITY CONFIGURATION WHERE THE ISSUER IS: a realm's OpenID
  // Federation Entity Identifier is its OpenID Provider's issuer (#132), and
  // a resolver fetches `<issuer>/.well-known/openid-federation`, so oidfed
  // must be answered on the listener oauth-oidc is advertised on.
  const scopes = [realms.DEFAULT_ID].concat(Object.keys(state.realms));
  for (const realmId of scopes) {
    const issuerAt = effectiveIn(resolved, realmId, 'oauth-oidc').advertised;
    if (effectiveIn(resolved, realmId, 'oidfed').listeners
          .indexOf(issuerAt) < 0) {
      log.debug("Leaving stateProblem(). The Entity Configuration.");
      return problem('STS-CORE-0154', 'In ' + (realmId === realms.DEFAULT_ID
        ? 'the default realm' : 'realm "' + realmId + '"') + ', oauth-oidc ' +
        'is advertised on "' + issuerAt + '", and oidfed is not on it: the ' +
        'Entity Identifier is the issuer, and the Entity Configuration is ' +
        'fetched at <issuer>/.well-known/openid-federation. Put oidfed on "' +
        issuerAt + '" too.');
    }
  }
  for (const realmId of scopes) {
    const cookie = cookieDomainIn(state, realmId);
    if (cookie && !DOMAIN_PATTERN.test(cookie)) {
      log.debug("Leaving stateProblem(). A bad cookie domain.");
      return problem('STS-CORE-0155', COOKIE_SETTING + ' "' + cookie +
        '" is not a DNS name of two labels or more with no leading dot ' +
        '— example.com, idp.example.com.');
    }
    const hosts = {};
    applications.sessionApplications().forEach(function (app) {
      effectiveIn(resolved, realmId, app).listeners.forEach(function (id) {
        const host = resolved.byId[id].host;
        if (host) {
          hosts[host] = hosts[host] || [];
          hosts[host].push(app + ' on ' + id);
        }
      });
    });
    const names = Object.keys(hosts);
    const outside = names.filter(function (host) {
      return cookie && host !== cookie.toLowerCase() &&
        host.slice(-(cookie.length + 1)) !== '.' + cookie.toLowerCase();
    });
    if ((names.length > 1 && !cookie) || outside.length) {
      log.debug("Leaving stateProblem(). The cookie cannot reach.");
      return problem('STS-CORE-0155', 'In ' + (realmId === realms.DEFAULT_ID
        ? 'the default realm' : 'realm "' + realmId + '"') + ', the ' +
        'applications that read the sign-on session (' +
        applications.sessionApplications().join(', ') + ') would be on ' +
        'listeners with host names ' + names.join(', ') + ', and the ' +
        'session cookie ' + (cookie
          ? 'is scoped to ' + cookie + ', which ' + outside.join(', ') +
            ' is not under'
          : 'is host-only (' + COOKIE_SETTING + ' is empty), so a sign-in ' +
            'on one would be unknown to the others') + '. Put them on ' +
        'listeners that share a host name, or set ' + COOKIE_SETTING +
        ' to a domain every one of them is under.');
    }
  }
  // NO WRITE TAKES /admin-api OFF THE LISTENER IT ARRIVED ON UNASKED (D6).
  if (options && options.request && !options.confirmed) {
    const req = options.request;
    const at = listenerOf(req);
    const realmId = (req.realm && req.realm.id) || realms.DEFAULT_ID;
    const before = effectiveIn(resolveState(currentState()), realmId,
                               'management-api');
    const after = effectiveIn(resolved, realmId, 'management-api');
    if (before.listeners.indexOf(at) >= 0 &&
        after.listeners.indexOf(at) < 0 && !rescued()) {
      log.debug("Leaving stateProblem(). It would cut the caller off.");
      return problem('STS-CORE-0156', 'This change takes the management ' +
        'API off the listener "' + at + '" this request arrived on, and ' +
        'nothing on it would answer the next one. Send it to PUT ' +
        '/admin-api/listeners/applications with "confirm": true if that is ' +
        'meant. ' + RESCUE_SETTING + ' (STS_LISTENERS_ADMIN_ON_MAIN) puts ' +
        'the console and the API back on the main port at the next start.');
    }
  }
  log.debug("Leaving stateProblem().");
  return null;
}

// The cookie domain a realm's sign-on session is written with.
function cookieDomainIn(state, realmId) {
  log.debug("Entering cookieDomainIn(). " + realmId);
  const own = realmId !== realms.DEFAULT_ID && state.realms[realmId]
    ? state.realms[realmId].cookieDomain : undefined;
  const raw = own !== undefined && own !== null && own !== ''
    ? own : state.cookieDomain;
  log.debug("Leaving cookieDomainIn().");
  return String(raw || '').trim().replace(/^\./, '');
}

function rescued() {
  log.debug("Entering rescued().");
  let on = false;
  try {
    on = config.processValue(RESCUE_SETTING) === true;
  } catch (e) {
    log.debug("Caught in rescued(): " + ((e && e.message) || e));
  }
  log.debug("Leaving rescued(). " + on);
  return on;
}

// The request a write is being made in, where there is one: the console's
// and the API's doors run inside one, a restore at start does not.
function ambientRequest() {
  log.debug("Entering ambientRequest().");
  let req = null;
  try {
    req = require('./jose_certificate_header').currentRequest() || null;
  } catch (e) {
    log.debug("Caught in ambientRequest(): " + ((e && e.message) || e));
  }
  log.debug("Leaving ambientRequest().");
  return req;
}

// ---------------------------------------------------------------------------
// THE WRITE RULES.
// ---------------------------------------------------------------------------
const PROCESS_KEYS = {};
PROCESS_KEYS[SERVICE_SETTING] = 'service';
PROCESS_KEYS[MAP_SETTING] = 'map';
PROCESS_KEYS[COOKIE_SETTING] = 'cookieDomain';
PROCESS_KEYS['global.publicBaseUrl'] = 'publicBaseUrl';

/**
 * The rule `config.addWriteRule()` is given: a process-wide write of one of
 * the settings these rules read, judged with the whole state it would leave.
 *
 * @param key - the setting being written
 * @param parsed - its parsed value
 * @param inRealm - true for a write landing in a realm's overrides, which
 *   `realms.js` judges whole (`realmOverridesProblem()`)
 * @returns `{ problem, code }`, or null to allow it
 */
function processWriteRule(key, parsed, inRealm) {
  log.debug("Entering processWriteRule(). " + key);
  if (!Object.prototype.hasOwnProperty.call(PROCESS_KEYS, key)) {
    log.debug("Leaving processWriteRule(). Not ours.");
    return null;
  }
  // A WRITE LANDING IN THE AMBIENT REALM — `config.setOverride()` puts a
  // write made inside a realm into that realm's overrides, past realms.js's
  // own doors — is judged as that realm's whole set would be. One made
  // through realms.js for a named realm is judged there again, with the
  // realm it names.
  if (inRealm) {
    const realm = realms.current();
    if (!realm || realm.id === realms.DEFAULT_ID ||
        [REALM_SETTING, MAP_SETTING, COOKIE_SETTING].indexOf(key) < 0) {
      log.debug("Leaving processWriteRule(). A realm's write, not ours.");
      return null;
    }
    const after = Object.assign({}, realm.overrides || {});
    after[key] = parsed;
    const judged = realmOverridesProblem(realm.id, after);
    log.debug("Leaving processWriteRule(). A realm's write.");
    return judged ? { problem: judged.message, code: judged.code } : null;
  }
  const state = currentState();
  state[PROCESS_KEYS[key]] = String(parsed === undefined || parsed === null
                                    ? '' : parsed);
  const req = ambientRequest();
  const found = stateProblem(state, {
    request: key === MAP_SETTING ? req : null,
    confirmed: !!(req && req.stsListenerChangeConfirmed)
  });
  log.debug("Leaving processWriteRule(). " + (found ? found.code : 'ok'));
  return found ? { problem: found.message, code: found.code } : null;
}

/**
 * A realm's overrides as they would be, judged whole: the realm's own
 * listeners, its mapping and its cookie domain, with every other realm's and
 * the process's as they are.
 *
 * @param id - the realm id
 * @param after - the realm's overrides as they would be
 * @returns `{ code, message }`, or null when they are acceptable
 */
function realmOverridesProblem(id, after) {
  log.debug("Entering realmOverridesProblem(). " + id);
  const o = after || {};
  const touched = [REALM_SETTING, MAP_SETTING, COOKIE_SETTING].filter(
    function (k) {
      return Object.prototype.hasOwnProperty.call(o, k);
    });
  if (id === realms.DEFAULT_ID) {
    if (String(o[REALM_SETTING] || '').trim()) {
      log.debug("Leaving realmOverridesProblem(). The default realm.");
      return problem('STS-CORE-0145', 'The default realm\'s listeners are ' +
        'the service\'s: ' + SERVICE_SETTING + '. ' + REALM_SETTING +
        ' can only be set on another realm.');
    }
    log.debug("Leaving realmOverridesProblem(). Default.");
    return null;
  }
  const state = currentState();
  const had = state.realms[id] || { own: '', map: '', cookieDomain: '' };
  state.realms[id] = {
    own: String(o[REALM_SETTING] || ''),
    map: String(o[MAP_SETTING] || ''),
    cookieDomain: o[COOKIE_SETTING]
  };
  if (!touched.length && !had.own && !had.map) {
    log.debug("Leaving realmOverridesProblem(). Nothing of ours.");
    return null;
  }
  const req = ambientRequest();
  const found = stateProblem(state, {
    request: had.map !== state.realms[id].map ? req : null,
    confirmed: !!(req && req.stsListenerChangeConfirmed)
  });
  log.debug("Leaving realmOverridesProblem().");
  return found;
}

/**
 * The state this process starts with, judged as a write would be: an
 * environment or appconfig value no write was asked about.
 *
 * @returns `{ code, message }`, or null
 */
function startupProblem() {
  log.debug("Entering startupProblem().");
  const found = stateProblem(currentState(), null);
  log.debug("Leaving startupProblem().");
  return found;
}

// ---------------------------------------------------------------------------
// THE READERS.
// ---------------------------------------------------------------------------

/**
 * Every listener: `main`, the service's and every realm's own.
 *
 * @returns the definitions, each `{ id, owner, builtin, port, label,
 *   publicBaseUrl, host, hostnames, certificateFile, privateKeyFile,
 *   clientAuth, tls }`
 */
function allListeners() {
  log.debug("Entering allListeners().");
  const out = resolveState(currentState()).all;
  log.debug("Leaving allListeners(). " + out.length);
  return out;
}

/**
 * One listener's definition.
 *
 * @param id - the listener id
 * @returns the definition, or null
 */
function listenerById(id) {
  log.debug("Entering listenerById(). " + id);
  const found = resolveState(currentState()).byId[String(id)] || null;
  log.debug("Leaving listenerById().");
  return found;
}

// Whether anything here can differ from the service before #472: no listener
// beyond the main port, so every application is on it. Read on every request
// by the gate, so it answers from the raw settings without parsing them.
// A hot path: no Entering/Leaving pair.
function isTrivial() {
  if (String(config.processValue(SERVICE_SETTING) || '').trim()) {
    return false;
  }
  const realm = realms.current();
  return !(realm && realm.id !== realms.DEFAULT_ID &&
           String(realmOwn(realm, REALM_SETTING) || '').trim());
}

/**
 * Where one application is, in the ambient realm: the listeners that answer
 * it and the one its URLs are built on. `listeners.adminOnMain` puts the
 * console and the API on `main` and advertises them there.
 *
 * @param app - the application's id, or null for `*`
 * @returns `{ listeners, advertised }`
 */
function effective(app) {
  log.debug("Entering effective(). " + app);
  const realm = realms.current();
  const realmId = realm ? realm.id : realms.DEFAULT_ID;
  if (isTrivial() && !String(config.processValue(MAP_SETTING) || '').trim()) {
    log.debug("Leaving effective(). Trivial.");
    return { listeners: [MAIN], advertised: MAIN };
  }
  const found = effectiveIn(resolveState(currentState()), realmId,
                            app || '*');
  if (app && applications.rescuedApplications().indexOf(app) >= 0 &&
      rescued()) {
    log.debug("Leaving effective(). Rescued.");
    return { listeners: found.listeners.indexOf(MAIN) >= 0
               ? found.listeners : [MAIN].concat(found.listeners),
             advertised: MAIN };
  }
  log.debug("Leaving effective().");
  return found;
}

/**
 * The listener a request arrived on: marked on the socket by the front
 * process, and carried to a request worker on the request.
 *
 * A hot path: no Entering/Leaving pair.
 *
 * @param req - the request
 * @returns the listener id; `main` for an unmarked socket
 */
function listenerOf(req) {
  if (req && req.stsListener) {
    return String(req.stsListener);
  }
  const socket = req && req.socket;
  return socket && socket.stsListener ? String(socket.stsListener) : MAIN;
}

/**
 * Whether a listener answers a path's application, in the ambient realm.
 *
 * @param listenerId - the listener
 * @param app - the application, `EVERYWHERE` or null
 * @returns true when it does
 */
function admits(listenerId, app) {
  log.debug("Entering admits(). " + listenerId + " " + app);
  if (!app || app === applications.EVERYWHERE) {
    log.debug("Leaving admits(). Everywhere.");
    return true;
  }
  const ok = effective(app).listeners.indexOf(String(listenerId)) >= 0;
  log.debug("Leaving admits(). " + ok);
  return ok;
}

/**
 * The base an application's URLs are built on in the ambient realm, without
 * the realm prefix: its advertised listener's `publicBaseUrl`, or '' where
 * that is `main` — whose base is `global.publicBaseUrl` or the request's.
 *
 * @param app - the application's id, or null for `*`
 * @returns the base, or ''
 */
function advertisedBase(app) {
  log.debug("Entering advertisedBase(). " + app);
  const where = effective(app).advertised;
  if (where === MAIN) {
    log.debug("Leaving advertisedBase(). Main.");
    return '';
  }
  const one = listenerById(where);
  log.debug("Leaving advertisedBase().");
  return one ? one.publicBaseUrl : '';
}

/**
 * The advertised listener of an application in the ambient realm.
 *
 * @param app - the application's id, or null for `*`
 * @returns the listener id
 */
function advertisedListener(app) {
  log.debug("Entering advertisedListener(). " + app);
  log.debug("Leaving advertisedListener().");
  return effective(app).advertised;
}

/**
 * The OTHER listeners an application is on, for a document that has a place
 * for an alternative address (RFC 8705 `mtls_endpoint_aliases`): each with
 * its base and client authentication. `main`'s base is '' as above.
 *
 * @param app - the application's id
 * @returns `[{ id, base, clientAuth }]`, the advertised listener left out
 */
function alternatives(app) {
  log.debug("Entering alternatives(). " + app);
  const found = effective(app);
  const resolved = resolveState(currentState());
  const out = found.listeners.filter(function (id) {
    return id !== found.advertised;
  }).map(function (id) {
    const one = resolved.byId[id];
    return { id: id, base: one && !one.builtin ? one.publicBaseUrl : '',
             clientAuth: one ? one.clientAuth : null };
  });
  log.debug("Leaving alternatives(). " + out.length);
  return out;
}

/**
 * Where this process dials ITSELF for one application (#472): the main port
 * when the application is on it — what every back channel here did before
 * custom listeners — and otherwise a listener of its that asks no client
 * certificate it cannot present, the advertised one where every one does.
 *
 * @param app - the application's id
 * @returns `{ id, main, port, publicCa }`: `port` 0 for the main port, and
 *   `publicCa` true where the listener presents an operator's certificate,
 *   which chains to a public CA rather than this service's Root
 */
function dialTarget(app) {
  log.debug("Entering dialTarget(). " + app);
  const found = effective(app);
  if (found.listeners.indexOf(MAIN) >= 0) {
    log.debug("Leaving dialTarget(). The main port.");
    return { id: MAIN, main: true, port: 0, publicCa: false };
  }
  const resolved = resolveState(currentState());
  const open = found.listeners.filter(function (id) {
    const one = resolved.byId[id];
    return !!one && one.clientAuth !== 'required';
  });
  const id = open.length ? open[0] : found.advertised;
  const one = resolved.byId[id];
  log.debug("Leaving dialTarget(). " + id);
  return { id: id, main: false, port: one ? one.port : 0,
           publicCa: !!(one && one.certificateFile) };
}

/**
 * The origins of every listener with a public base: this service's own, for
 * CORS and for the console's `connect-src`.
 *
 * @returns the origins
 */
function ownOrigins() {
  log.debug("Entering ownOrigins().");
  const out = [];
  allListeners().forEach(function (one) {
    if (!one.publicBaseUrl) {
      return;
    }
    try {
      const origin = new URL(one.publicBaseUrl).origin;
      if (out.indexOf(origin) < 0) {
        out.push(origin);
      }
    } catch (e) {
      log.debug("Caught in ownOrigins(): " + ((e && e.message) || e));
    }
  });
  log.debug("Leaving ownOrigins(). " + out.length);
  return out;
}

/**
 * The cookie domain the ambient realm's sign-on session is written with, as
 * a `Set-Cookie` attribute.
 *
 * @returns `; Domain=<domain>`, or '' for a host-only cookie
 */
function cookieDomainAttribute() {
  log.debug("Entering cookieDomainAttribute().");
  const raw = String(config.value(COOKIE_SETTING) || '').trim()
    .replace(/^\./, '');
  log.debug("Leaving cookieDomainAttribute().");
  return raw ? '; Domain=' + raw : '';
}

/**
 * The mapping as the Listeners page and the management API show it, for the
 * ambient realm: every application with the listeners it is on, the
 * advertised one, and whether the realm or the process decided.
 *
 * @returns the rows
 */
function mappingView() {
  log.debug("Entering mappingView().");
  const realm = realms.current();
  const realmId = realm ? realm.id : realms.DEFAULT_ID;
  const resolved = resolveState(currentState());
  const own = realmId !== realms.DEFAULT_ID
    ? resolved.realmMaps[realmId] || {} : {};
  const proc = resolved.processMap || {};
  const rows = applications.list().map(function (one) {
    const found = effective(one.id);
    const from = own[one.id] ? 'realm' : own['*'] ? 'realm *'
      : proc[one.id] ? 'service' : proc['*'] ? 'service *' : 'default';
    return { application: one.id, label: one.label, what: one.what,
             session: one.session, listeners: found.listeners,
             advertised: found.advertised, decidedBy: from };
  });
  log.debug("Leaving mappingView(). " + rows.length);
  return rows;
}

/**
 * What is wrong with the state as it stands, and what deserves a warning,
 * for the Listeners page: the first refusal a write would meet (a value from
 * the environment or a store edited by hand), and the WebAuthn note — the
 * session applications on several host names with no `webauthn.rpId` they
 * are all under, so a passkey registered on one is not usable on another.
 *
 * @returns `{ problem, warnings }`
 */
function health() {
  log.debug("Entering health().");
  const found = stateProblem(currentState(), null);
  const warnings = [];
  const resolved = resolveState(currentState());
  const hosts = {};
  applications.sessionApplications().forEach(function (app) {
    effective(app).listeners.forEach(function (id) {
      const one = resolved.byId[id];
      if (one && one.host) {
        hosts[one.host] = true;
      }
    });
  });
  const names = Object.keys(hosts);
  let rpId = '';
  try {
    rpId = String(config.value('webauthn.rpId') || '').trim().toLowerCase();
  } catch (e) {
    log.debug("Caught in health(): " + ((e && e.message) || e));
  }
  if (names.length > 1 && (!rpId || names.some(function (h) {
    return h !== rpId && h.slice(-(rpId.length + 1)) !== '.' + rpId;
  }))) {
    warnings.push('The applications that read the sign-on session are on ' +
      'host names ' + names.join(', ') + ', and webauthn.rpId ' +
      (rpId ? '(' + rpId + ') is not a domain all of them are under'
            : 'is empty, so each is its own relying party') + ': a ' +
      'passkey registered on one is not usable on another. Set ' +
      'webauthn.rpId to the domain authn.cookieDomain names.');
  }
  log.debug("Leaving health().");
  return { problem: found, warnings: warnings };
}

config.addWriteRule(processWriteRule);

module.exports = {
  MAIN: MAIN,
  SERVICE_SETTING: SERVICE_SETTING,
  REALM_SETTING: REALM_SETTING,
  MAP_SETTING: MAP_SETTING,
  RESCUE_SETTING: RESCUE_SETTING,
  COOKIE_SETTING: COOKIE_SETTING,
  TLS_FIELDS: TLS_FIELDS,
  parseListeners: parseListeners,
  parseMapping: parseMapping,
  allListeners: allListeners,
  listenerById: listenerById,
  isTrivial: isTrivial,
  effective: effective,
  listenerOf: listenerOf,
  admits: admits,
  advertisedBase: advertisedBase,
  advertisedListener: advertisedListener,
  alternatives: alternatives,
  dialTarget: dialTarget,
  ownOrigins: ownOrigins,
  cookieDomainAttribute: cookieDomainAttribute,
  mappingView: mappingView,
  health: health,
  processWriteRule: processWriteRule,
  realmOverridesProblem: realmOverridesProblem,
  startupProblem: startupProblem
};
