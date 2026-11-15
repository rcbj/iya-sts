// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: logout-vectors.js
//
// ---------------------------------------------------------------------------
// THE PROTOCOL-INDEPENDENT SIGN-OUT (#444, phase 5, the `logout` slice):
// what `logout/logout.ts` does — the inventory, the termination in ending
// order, the batch forms, the narrower doors, who a request is about, the
// act, the account step, the page's two operations and the fan-out — for
// the Rust crate `sts-logout` to reproduce. Called by
// `tests/tools/crypto-vectors.js`'s `logout-node.json` row, in a process
// of its own.
//
// THE METHOD IS `session-vectors.js`'s: A RECORDING OF EVERY PORT. Each
// step drives the REAL `Logout` class, an instance built here, whose every
// dependency the Rust crate takes as a port is a FAKE over one small world
// — two people, dora and emil; dora signed in twice, to OpenID Connect,
// WS-Federation and SAML relying parties and through a federation partner,
// holding tokens, a code, a pre-authorized code, wallet rows, a GNAP grant,
// an OAuth grant, a PCT, a directory connection and a Kerberos principal —
// wrapped in a recorder. The Rust test replays each recorded answer to its
// own `Logout` and checks that it made the same calls, with the same
// arguments, in the same order, and gave the same answer.
//
// The world is rebuilt for every case, so each case starts from a known
// state; the steps of a case run one after another on it, so "sign out of
// one, then of everything" sees what the first left.
//
// WHAT THE SESSION'S END ITSELF DOES — the RFC 9700 refresh revocation, the
// access tokens in product (#1449), the Logout Tokens, CAEP — is
// `authn.dropSession()`'s and is held by the session slice's vectors; here
// `endSessionById()` is a port whose call (the session, the `via`, the
// initiating entity) is what is compared. `sts-logout`'s
// `tests/real_sessions.rs` holds the two together over a real store.
// ---------------------------------------------------------------------------

const path = require('path');

/**
 * A JSON copy of what crossed a port: functions and `undefined` dropped
 * from objects, `undefined` as null in arrays, a Map as an object, a Date
 * as its ISO text, an opaque object by its name.
 *
 * @param {any} value - anything
 * @param {any[]} opaque - objects recorded by a name rather than copied
 * @returns {any} its JSON image
 */
function clone(value, opaque) {
  const copy = function (v) {
    if (v === undefined || typeof v === 'function' || typeof v === 'symbol') {
      return undefined;
    }
    if (v === null || typeof v !== 'object') {
      return typeof v === 'number' && !isFinite(v) ? null : v;
    }
    for (let i = 0; i < opaque.length; i++) {
      if (opaque[i].value === v) {
        return opaque[i].name;
      }
    }
    if (v instanceof Map) {
      const o = {};
      v.forEach(function (one, k) {
        const c = copy(one);
        if (c !== undefined) {
          o[String(k)] = c;
        }
      });
      return o;
    }
    if (typeof v.toJSON === 'function') {
      return copy(v.toJSON());
    }
    if (Array.isArray(v)) {
      return v.map(function (one) {
        const c = copy(one);
        return c === undefined ? null : c;
      });
    }
    const out = {};
    Object.keys(v).forEach(function (k) {
      const c = copy(v[k]);
      if (c !== undefined) {
        out[k] = c;
      }
    });
    return out;
  };
  const out = copy(value);
  return out === undefined ? null : out;
}

/**
 * The recorder every fake port writes to.
 *
 * @returns {any} the recorder
 */
function recorder() {
  const rec = { calls: null, depth: 0, opaque: [] };
  rec.copy = function (v) {
    return clone(v, rec.opaque);
  };
  rec.fn = function (port, method, f) {
    return function () {
      const args = Array.prototype.slice.call(arguments);
      if (!rec.calls || rec.depth > 0) {
        return f.apply(this, args);
      }
      // The arguments as they were PASSED: a fake may change what it was
      // handed (an ended grant), and the call is what the port was asked.
      const asked = rec.copy(args);
      rec.depth += 1;
      let answer;
      try {
        answer = f.apply(this, args);
      } finally {
        rec.depth -= 1;
      }
      rec.calls.push({ port: port, method: method, args: asked,
                       answer: rec.copy(answer) });
      return answer;
    };
  };
  return rec;
}

const NOW = Date.UTC(2026, 10, 14, 12, 0, 0);
const DORA = 'urn:uuid:0b6f6c1e-8c55-4b8a-9b2e-3d1f0d5c2a11';
const EMIL = 'urn:uuid:7d0f2a44-1b9c-4f3e-8a6d-5c2b1e9f4d22';
const SECRET = 'logout-vectors-result-secret';

/**
 * One world: everything a person may hold, in every family.
 *
 * @returns {any} the world
 */
function world() {
  const s = function (id, user, sub, authTime, more) {
    return Object.assign({ id: id, user: { username: user, sub: sub },
      authTime: authTime, startedAt: authTime * 1000, amr: ['pwd'],
      acr: '1', expires: NOW + 3600 * 1000, events: [] }, more || {});
  };
  return {
    window: false,
    sessions: {
      s1: s('s1', 'dora', DORA, NOW / 1000 - 600, {
        oidcClients: { appA: { at: 1 }, appB: { at: 2 } },
        wsfedRealms: { 'urn:rp:one': { wreply: 'https://rp1.example/' } },
        saml2ServiceProviders: { 'https://sp.example': { at: 3 } },
        fedPartnerSession: { relationship: 'partner1', protocol: 'saml2' },
        events: [{ at: NOW / 1000 - 600, amr: ['pwd', 'otp'],
                   context: { credential: { kind: 'totp' } } }] }),
      s2: s('s2', 'dora', DORA, NOW / 1000 - 60, {
        oidcClients: { appC: { at: 4 } },
        events: [{ at: NOW / 1000 - 60, amr: ['hwk'],
                   context: { credential: { kind: 'webauthn',
                     fingerprint: 'fp-key-1' } } }] }),
      e1: s('e1', 'emil', EMIL, NOW / 1000 - 30)
    },
    tokens: [
      { jti: 'at-1', kind: 'access_token', typ: 'Bearer', sub: DORA,
        username: 'dora', client_id: 'appA', scope: 'openid', exp: NOW /
        1000 + 600, sessionId: 's1', issuedAt: NOW - 1000, revocable: true,
        jkt: 'thumb', state: 'valid' },
      { jti: 'rt-1', kind: 'refresh_token', typ: 'Refresh', sub: DORA,
        username: 'dora', client_id: 'appA', scope: 'openid', exp: NOW /
        1000 + 6000, sessionId: 's1', issuedAt: NOW - 1000, revocable: true,
        state: 'valid' },
      { jti: 'at-2', kind: 'access_token', typ: 'Bearer', sub: DORA,
        username: 'dora', client_id: 'appC', scope: '', exp: NOW / 1000 +
        600, sessionId: 's2', issuedAt: NOW - 500, revocable: true,
        state: 'valid' },
      { jti: 'at-old', kind: 'access_token', sub: DORA, username: 'dora',
        client_id: 'appA', exp: NOW / 1000 - 600, sessionId: 's1',
        issuedAt: NOW - 9000, revocable: true, state: 'expired' },
      { jti: 'at-e', kind: 'access_token', sub: EMIL, username: 'emil',
        client_id: 'appA', exp: NOW / 1000 + 600, sessionId: 'e1',
        issuedAt: NOW - 100, revocable: true, state: 'valid' }
    ],
    artifacts: [
      { key: 'art-1', kind: 'SAML 2.0 assertion', id: '_a1', sub: DORA,
        username: 'dora', audience: 'https://sp.example', issuedAt: NOW -
        800, expiresAt: NOW + 600, state: 'valid' },
      { key: 'art-2', kind: 'Credential (jwt_vc_json)', id: 'vc-1', sub: DORA,
        username: 'dora', audience: '', issuedAt: NOW - 700, expiresAt: NOW +
        6000, state: 'valid' }
    ],
    codes: [
      { code: 'code-secret-1', key: 'dora', clientId: 'appA',
        redirectUri: 'https://appA.example/cb', scope: 'openid',
        issuedAt: NOW - 10, expiresAt: NOW + 290, sessionId: 's1' }
    ],
    vci: [['digest-1', { user: { username: 'dora', sub: DORA },
                         configurationIds: ['UniversityDegree'],
                         expires: NOW + 600, txCodeDigest: 'x' }]],
    walletSignins: [{ state: 'wallet-state-1', username: 'dora',
                      subject: DORA, decidedAt: '2026-11-14T11:59:00.000Z',
                      expires: NOW + 60 }],
    walletRows: [{ key: 'wallet-row-1', subject: DORA, format: 'jwt_vc_json',
                   credentials: ['c1', 'c2'], jkt: 'abcdefghijklmnopqrstuvwxyz',
                   issuedAt: NOW - 3600 * 1000, expiresAt: NOW + 3600 * 1000 }],
    gnap: [{ id: 'gnap-1', key: 'dora', state: 'approved', live: true,
             client: { identifier: 'gnap-client' }, ro: { sessionId: 's1' },
             tokens: ['t1', 't2'], createdAt: NOW / 1000 - 300 },
           { id: 'gnap-2', key: 'dora', state: 'approved', live: true,
             client: { identifier: 'gnap-other' }, ro: {},
             tokens: ['t3'], createdAt: NOW / 1000 - 200 }],
    grants: [{ grantId: 'grant-abcdef123', subject: DORA, clientId: 'appA',
               scopes: [{ scope: 'openid' }, { scope: 'email' }], tokens: 2,
               created_at: NOW / 1000 - 400, expires_at: NOW / 1000 + 4000 }],
    pcts: [{ key: 'pct-1', subject: DORA, client: 'uma-client',
             issuedAt: NOW / 1000 - 100, expiresAt: NOW / 1000 + 100 }],
    ldap: [{ id: 'c-7', key: 'dora', dn: 'uid=dora,ou=people,dc=sts,dc=mock',
             secure: true, port: 636 }],
    principals: { dora: { name: ['dora'], realm: 'STS.MOCK',
                          signedOutAt: null } },
    deliveries: [],
    revoked: {},
    marked: {}
  };
}

/**
 * The fakes over one world, each method recorded.
 *
 * @param {any} rec - the recorder
 * @param {any} w - the world
 * @param {any} on - the switches of the case (mode, settings, accounts)
 * @returns {any} the dependencies' fakes
 */
function fakes(rec, w, on) {
  const nameOf = function (sub) {
    return sub === DORA ? 'dora' : (sub === EMIL ? 'emil' : '');
  };
  const subOf = function (name) {
    return name === 'dora' ? DORA : (name === 'emil' ? EMIL : '');
  };
  const keyOf = function (value) {
    let text = String(value == null ? '' : value).trim();
    if (/^urn:uuid:/i.test(text)) {
      return nameOf(text) || text;
    }
    const at = text.lastIndexOf('@');
    if (at > 0) {
      text = text.slice(0, at);
    }
    return text;
  };
  const holderKeyOf = function (username, sub) {
    const subject = String(sub || '');
    if (/^urn:uuid:/i.test(subject) && nameOf(subject)) {
      return nameOf(subject);
    }
    return keyOf(username || subject);
  };
  const live = function () {
    return Object.keys(w.sessions).map(function (k) {
      return w.sessions[k];
    });
  };
  const f = rec.fn;
  const notes = function (session, issuer) {
    return Object.keys(session.oidcClients || {}).map(function (client) {
      return client === 'appB'
        ? { clientId: client, url: '', why: 'appB registered no ' +
            'frontchannel_logout_uri' }
        : { clientId: client, url: 'https://' + client + '.example/fc?iss=' +
            encodeURIComponent(issuer) + '&sid=' + session.id,
          uri: 'https://' + client + '.example/fc', sessionRequired:
            client === 'appA' };
    });
  };
  const authn = {
    sessionWindowOn: f('authn', 'sessionWindowOn', function () {
      return w.window;
    }),
    sessionsHeldUnder: f('authn', 'sessionsHeldUnder', function (u, sub) {
      return live().filter(function (one) {
        return one.user.username === u || (sub && one.user.sub === sub);
      });
    }),
    sessionsMatching: f('authn', 'sessionsMatching', function () {
      return live();
    }),
    sessionById: f('authn', 'sessionById', function (id) {
      return w.sessions[id] || null;
    }),
    sessionView: f('authn', 'sessionView', function (one) {
      return { id: one.id, username: one.user.username, methods: one.amr,
               assuranceLevel: one.acr, expires: one.expires };
    }),
    sessionStartedAt: f('authn', 'sessionStartedAt', function (one) {
      return one.startedAt;
    }),
    endSessionById: f('authn', 'endSessionById', function (id) {
      const one = w.sessions[id];
      if (!one) {
        return null;
      }
      // The session's end tells the relying parties still on it (3aq):
      // the deliveries the act then lists.
      Object.keys(one.oidcClients || {}).forEach(function (client) {
        if (client === 'appA') {
          w.deliveries.push({ sessionId: id, client: client,
            uri: 'https://appA.example/bc', state: 'pending' });
        }
      });
      delete w.sessions[id];
      return one;
    }),
    noteSessionChanged: f('authn', 'noteSessionChanged', function () {
      return undefined;
    }),
    multipleAccounts: f('authn', 'multipleAccounts', function () {
      return !!on.accounts;
    }),
    hintAccountKey: f('authn', 'hintAccountKey', function () {
      return undefined;
    }),
    hintAccount: f('authn', 'hintAccount', function () {
      return undefined;
    }),
    sessionOf: f('authn', 'sessionOf', function (req) {
      return (req.sid && w.sessions[req.sid]) || null;
    }),
    signedInAccounts: f('authn', 'signedInAccounts', function (req) {
      return (req.accounts || []).filter(function (one) {
        return !!w.sessions[one.sid];
      });
    }),
    afterAccountSignOut: f('authn', 'afterAccountSignOut', function () {
      return { defaultEnded: true, defaultNow: '' };
    }),
    clearSessionCookie: f('authn', 'clearSessionCookie', function (res) {
      res.cleared = true;
      return undefined;
    }),
    clearSiteDataAfterSignOut: f('authn', 'clearSiteDataAfterSignOut',
      function () {
        return undefined;
      }),
    beginAuthentication: f('authn', 'beginAuthentication', function (opts) {
      return '/authn/login?authn=pending-' + String(opts.returnTo).length;
    }),
    lastAuthenticatedAt: f('authn', 'lastAuthenticatedAt', function (one) {
      return one ? (on.lastAuth !== undefined ? on.lastAuth : one.authTime)
        : 0;
    }),
    sessionNamesFactor: f('authn', 'sessionNamesFactor', function (one,
                                                                   factor) {
      return (one.events || []).some(function (event) {
        const given = (event.context && event.context.credential) || {};
        return given.kind === factor.kind && (factor.kind !== 'webauthn' ||
          given.fingerprint === 'fp-' + factor.credentialId);
      });
    })
  };
  const stats = {
    holderKeyOf: f('stats', 'holderKeyOf', holderKeyOf),
    identityKeyOf: f('stats', 'identityKeyOf', keyOf),
    holdingsOf: f('stats', 'holdingsOf', function (keys) {
      const out = new Map();
      (keys || []).forEach(function (key) {
        out.set(String(key || ''), { tokens: [], artifacts: [] });
      });
      w.tokens.forEach(function (one) {
        const held = out.get(holderKeyOf(one.username, one.sub));
        if (held) {
          held.tokens.push(Object.assign({}, one, w.revoked[one.jti]
            ? { state: 'revoked' } : {}));
        }
      });
      w.artifacts.forEach(function (one) {
        const held = out.get(holderKeyOf(one.username, one.sub));
        if (held) {
          held.artifacts.push(Object.assign({}, one, w.marked[one.key]
            ? { state: 'revoked' } : {}));
        }
      });
      return out;
    }),
    revoke: f('stats', 'revoke', function (jti) {
      const first = !w.revoked[jti];
      w.revoked[jti] = true;
      return first;
    }),
    artifactByKey: f('stats', 'artifactByKey', function (key) {
      return w.artifacts.filter(function (one) {
        return one.key === key;
      })[0] || null;
    }),
    revokeArtifact: f('stats', 'revokeArtifact', function (record) {
      const first = !w.marked[record.key];
      w.marked[record.key] = true;
      return first;
    })
  };
  const frontchannel = {
    clientsOf: f('frontchannel', 'clientsOf', function (one) {
      return Object.keys(one.oidcClients || {});
    }),
    notificationsFor: f('frontchannel', 'notificationsFor', notes),
    render: f('frontchannel', 'render', function (list) {
      return '<h2>Front-channel</h2>' + list.map(function (one) {
        return one.url ? '<iframe src="' + one.url + '"></iframe>' : '';
      }).join('');
    }),
    frameOriginsOf: f('frontchannel', 'frameOriginsOf', function (list) {
      return list.filter(function (one) {
        return !!one.url;
      }).map(function (one) {
        return new URL(one.url).origin;
      });
    })
  };
  let marks = 0;
  const backchannel = {
    mark: f('backchannel', 'mark', function () {
      marks += 1;
      return { at: w.deliveries.length, n: marks };
    }),
    plan: f('backchannel', 'plan', function (one, opts) {
      return (opts.clients || []).filter(function (client) {
        return client === 'appA';
      }).map(function (client) {
        return { sessionId: one.id, client: client,
                 uri: 'https://appA.example/bc' };
      });
    }),
    dispatch: f('backchannel', 'dispatch', function (planned) {
      planned.forEach(function (one) {
        w.deliveries.push(Object.assign({ state: 'pending' }, one));
      });
      return undefined;
    }),
    deliveriesFor: f('backchannel', 'deliveriesFor', function (ids, mark) {
      return w.deliveries.slice(mark.at).filter(function (one) {
        return ids.indexOf(one.sessionId) >= 0;
      });
    }),
    summarize: f('backchannel', 'summarize', function (rows) {
      return rows.length ? rows.length + ' back-channel Logout Token(s) ' +
        'queued.' : '';
    }),
    render: f('backchannel', 'render', function (rows) {
      return rows.length ? '<h2>Back-channel</h2><p>' + rows.length +
        '</p>' : '';
    })
  };
  const wsfed = {
    cleanupTargetsFor: f('wsfed', 'cleanupTargetsFor', function (one) {
      return Object.keys(one.wsfedRealms || {}).map(function (realm) {
        return { realm: realm, url: one.wsfedRealms[realm].wreply +
          '?wa=wsignoutcleanup1.0' };
      });
    })
  };
  const saml2Sso = {
    logoutTargetsFor: f('saml2Sso', 'logoutTargetsFor', function (one) {
      return Object.keys(one.saml2ServiceProviders || {}).map(function (e) {
        return { entityId: e, url: e + '/slo?SAMLRequest=x',
                 from: 'https://sts.example/saml2/slo' };
      });
    })
  };
  const federationSlo = {
    canTellPartner: f('federationSlo', 'canTellPartner', function () {
      return { ok: true };
    }),
    partnerLogoutFor: f('federationSlo', 'partnerLogoutFor',
      function (one, base) {
        return { ok: true, target: { label: one.fedPartnerSession.relationship,
          what: 'a signed LogoutRequest', url: base + '/federation/slo' } };
      }),
    renderPartnerLogouts: f('federationSlo', 'renderPartnerLogouts',
      function (list) {
        return list.length ? '<div class="partners">' + list.length +
          '</div>' : '';
      })
  };
  const oauth2 = {
    outstandingCodesFor: f('oauth2', 'outstandingCodesFor', function (key) {
      return w.codes.filter(function (one) {
        return one.key === key;
      });
    }),
    dropCode: f('oauth2', 'dropCode', function (code) {
      w.codes = w.codes.filter(function (one) {
        return one.code !== code;
      });
      return undefined;
    }),
    issuerOf: f('oauth2', 'issuerOf', function (base) {
      return base;
    })
  };
  const listed = f('vcOffers', 'preAuthorizedCodes', function () {
    return w.vci;
  });
  const vcOffers = { preAuthorizedCodes: {
    forEachDigest: function (cb) {
      listed().forEach(function (pair) {
        cb(pair[1], pair[0]);
      });
    },
    deleteDigest: f('vcOffers', 'deleteDigest', function (digest) {
      w.vci = w.vci.filter(function (pair) {
        return pair[0] !== digest;
      });
      return true;
    })
  } };
  const vcVerifier = {
    signInsAwaitingCollection: f('vcVerifier', 'signInsAwaitingCollection',
      function () {
        return w.walletSignins;
      }),
    withdrawSignIn: f('vcVerifier', 'withdrawSignIn', function (state) {
      const before = w.walletSignins.length;
      w.walletSignins = w.walletSignins.filter(function (one) {
        return one.state !== state;
      });
      return w.walletSignins.length < before;
    })
  };
  const vcIssued = {
    rowsForSubject: f('vcIssued', 'rowsForSubject', function (subject) {
      return w.walletRows.filter(function (one) {
        return one.subject === subject;
      });
    }),
    disown: f('vcIssued', 'disown', function (key) {
      const before = w.walletRows.length;
      w.walletRows = w.walletRows.filter(function (one) {
        return one.key !== key;
      });
      return w.walletRows.length < before;
    })
  };
  const krb5 = {
    kerberosRealmOf: f('krb5Principals', 'kerberosRealmOf', function () {
      return { enabled: on.krb5 !== false };
    }),
    signedOutAt: f('krb5Principals', 'signedOutAt', function (names) {
      const one = w.principals[names[0]];
      return one && one.signedOutAt ? new Date(one.signedOutAt) : null;
    }),
    find: f('krb5Principals', 'find', function (names) {
      return w.principals[names[0]] || null;
    }),
    signOut: f('krb5Principals', 'signOut', function (names) {
      const one = w.principals[names[0]];
      if (!one) {
        return null;
      }
      one.signedOutAt = NOW;
      return { name: one.name, realm: one.realm, signedOutAt: new Date(NOW) };
    })
  };
  Object.defineProperty(krb5, 'REALM', { enumerable: false,
    get: f('krb5Principals', 'REALM', function () {
      return 'STS.MOCK';
    }) });
  const ldapServer = {
    boundConnections: f('ldapServer', 'boundConnections', function () {
      return w.ldap;
    }),
    dropConnectionsFor: f('ldapServer', 'dropConnectionsFor', function (key) {
      const out = w.ldap.filter(function (one) {
        return one.key === key;
      });
      w.ldap = w.ldap.filter(function (one) {
        return one.key !== key;
      });
      return out;
    }),
    signOutAcrossCluster: f('ldapServer', 'signOutAcrossCluster',
      function () {
        return null;
      })
  };
  const gnapRevocation = {
    grantsByKey: f('gnapRevocation', 'grantsByKey', function (keys) {
      const out = new Map();
      keys.forEach(function (key) {
        out.set(key, w.gnap.filter(function (one) {
          return one.key === key;
        }));
      });
      return out;
    }),
    isLive: f('gnapRevocation', 'isLive', function (grant) {
      return !!grant.live;
    }),
    grantsHeldBy: f('gnapRevocation', 'grantsHeldBy', function (key) {
      return w.gnap.filter(function (one) {
        return one.key === key && one.live;
      });
    }),
    liveTokensOf: f('gnapRevocation', 'liveTokensOf', function (grant) {
      return grant.tokens || [];
    }),
    endGrant: f('gnapRevocation', 'endGrant', function (grant) {
      const found = w.gnap.filter(function (one) {
        return one.id === grant.id && one.live;
      })[0];
      if (!found) {
        return false;
      }
      found.live = false;
      return true;
    })
  };
  const grantManagement = {
    list: f('grantManagement', 'list', function () {
      return w.grants;
    }),
    revoke: f('grantManagement', 'revoke', function (id) {
      const found = w.grants.filter(function (one) {
        return one.grantId === id;
      })[0];
      w.grants = w.grants.filter(function (one) {
        return one.grantId !== id;
      });
      return found ? { ok: true, clientId: found.clientId,
                       revoked: found.tokens } : { ok: false };
    })
  };
  const uma = {
    pctsOf: f('uma', 'pctsOf', function (subject) {
      return w.pcts.filter(function (one) {
        return one.subject === subject;
      });
    }),
    deletePct: f('uma', 'deletePct', function (key) {
      const before = w.pcts.length;
      w.pcts = w.pcts.filter(function (one) {
        return one.key !== key;
      });
      return w.pcts.length < before;
    })
  };
  const people = {
    subjectForName: f('people', 'subjectForName', subOf),
    nameForSubject: f('people', 'nameForSubject', nameOf)
  };
  const audit = {
    audit: f('audit', 'audit', function () {
      return undefined;
    }),
    failure: f('audit', 'failure', function () {
      return undefined;
    })
  };
  const host = {
    subjectTerminated: f('cells', 'subjectTerminated', function () {
      return undefined;
    }),
    personSignedOut: f('providerCommands', 'personSignedOut', function () {
      return undefined;
    })
  };
  return { authn: authn, stats: stats, frontchannel: frontchannel,
    backchannel: backchannel, wsfed: wsfed, saml2Sso: saml2Sso,
    federationSlo: federationSlo, oauth2: oauth2, vcOffers: vcOffers,
    vcVerifier: vcVerifier, vcIssued: vcIssued, krb5: krb5,
    ldapServer: ldapServer, gnapRevocation: gnapRevocation,
    grantManagement: grantManagement, uma: uma, people: people,
    audit: audit, host: host };
}

/**
 * Builds the vector set.
 *
 * @param {string} ROOT - the repository root
 * @returns {any} the set
 */
function build(ROOT) {
  const req = function (rel) {
    return require(path.join(ROOT, rel));
  };
  const realNow = Date.now;
  Date.now = function () {
    return NOW;
  };
  const config = req('common/config');
  const realValue = config.value.bind(config);
  const settings = { 'logout.maxRows': 200, 'logout.anyUser': true,
    'logout.ldapDisconnect': true, 'logout.kerberosSignOut': true,
    'account.recentAuthMinutes': 15, 'authn.cookieDomain': '' };
  const helpers = req('common/helpers');
  const logoutModule = req('logout/logout');
  const clusterSecrets = req('cluster/cluster_secrets');
  const cellSessions = req('common/cell_sessions');
  const vcIssued = req('oid4vc/vc_issued');
  const grantManagement = req('oauth-oidc/grant_management');
  const umaStore = req('uma/uma_store');
  const realms = req('common/realms');
  const saved = { get: clusterSecrets.get, subjectTerminated:
    cellSessions.subjectTerminated, rowsForSubject: vcIssued.rowsForSubject,
    disown: vcIssued.disown, list: grantManagement.list,
    revoke: grantManagement.revoke, pctsOf: umaStore.pctsOf,
    deletePct: umaStore.deletePct, subjectForName: helpers.subjectForName,
    nameForSubject: helpers.nameForSubject };
  const commands = require.cache[require.resolve(path.join(ROOT,
    'oauth-oidc', 'provider_commands'))];
  const savedCommand = commands ? commands.exports.personSignedOut : null;
  const out = { now: NOW, secret: SECRET, realm: String(realms.currentId() ||
    ''), prefix: String(realms.currentPrefix() || ''), settings: settings,
    cases: [], sealed: null };
  const caseOf = function (name, on, steps) {
    const rec = recorder();
    const w = world();
    const fk = fakes(rec, w, on);
    const table = Object.assign({}, settings, on.settings || {});
    config.value = function (key) {
      if (Object.prototype.hasOwnProperty.call(table, key)) {
        return table[key];
      }
      return realValue.apply(null, arguments);
    };
    clusterSecrets.get = function (n) {
      return n === 'logout-result' ? Buffer.from(SECRET, 'utf8')
        : saved.get.call(clusterSecrets, n);
    };
    cellSessions.subjectTerminated = fk.host.subjectTerminated;
    vcIssued.rowsForSubject = fk.vcIssued.rowsForSubject;
    vcIssued.disown = fk.vcIssued.disown;
    grantManagement.list = fk.grantManagement.list;
    grantManagement.revoke = fk.grantManagement.revoke;
    umaStore.pctsOf = fk.uma.pctsOf;
    umaStore.deletePct = fk.uma.deletePct;
    helpers.subjectForName = fk.people.subjectForName;
    helpers.nameForSubject = fk.people.nameForSubject;
    if (commands) {
      commands.exports.personSignedOut = fk.host.personSignedOut;
    }
    const deps = Object.assign(logoutModule.Logout.defaultDeps(), {
      config: config,
      mode: { opensTestControls: function () {
        return !on.product;
      }, verifiesCredentials: function () {
        return !!on.product;
      } },
      stats: fk.stats, audit: fk.audit, authn: fk.authn,
      oauth2: fk.oauth2, frontchannel: fk.frontchannel,
      backchannel: fk.backchannel, wsfed: fk.wsfed, saml2Sso: fk.saml2Sso,
      federationSlo: fk.federationSlo, vcOffers: fk.vcOffers,
      vcVerifier: fk.vcVerifier, krb5Principals: fk.krb5,
      ldapServer: fk.ldapServer, gnapRevocation: fk.gnapRevocation,
      grantManagement: grantManagement,
      baseUrlOf: function (r) {
        return r.base;
      }
    });
    const logout = new logoutModule.Logout(deps);
    w.window = !!on.window;
    const done = [];
    steps.forEach(function (step) {
      const request = { query: step.query || {}, headers: step.headers || {},
        base: 'https://sts.example', sid: step.sid || '',
        accounts: (step.accounts || []).map(function (a) {
          return Object.assign({}, a);
        }) };
      const response = { locals: {} };
      rec.opaque = [{ value: request, name: '[request]' },
                    { value: response, name: '[response]' }];
      rec.calls = [];
      let answer = null;
      let threw = null;
      try {
        answer = step.run(logout, request, response);
      } catch (e) {
        threw = String((e && e.message) || e);
      }
      const calls = rec.calls;
      rec.calls = null;
      done.push({ name: step.name, op: step.op, args: step.args || {},
        query: step.query || {}, sid: step.sid || '',
        accounts: step.accounts || [],
        answer: rec.copy(answer), threw: threw, calls: calls });
    });
    out.cases.push({ name: name, product: !!on.product,
      accounts: !!on.accounts, window: !!on.window,
      settings: table, steps: done });
  };
  const opts = function (o) {
    return o;
  };
  const step = function (name, op, args, run, more) {
    return Object.assign({ name: name, op: op, args: args, run: run },
                         more || {});
  };
  const inventory = step('inventory', 'inventoryFor',
    { key: 'dora', issuer: 'https://sts.example' }, function (l) {
      return l.inventoryFor('dora', 'https://sts.example');
    });
  try {
    ['development', 'product'].forEach(function (m) {
      const product = m === 'product';
      // ONE ROW, THEN THE DEFAULT, THEN EVERYTHING.
      caseOf(m + ': one relying party, then the default, then all',
        { product: product }, [
          inventory,
          step('forget appA on s2-less s1', 'terminate',
            { key: 'dora', selection: ['oidc-rp:s1|appA'],
              opts: { issuer: 'https://sts.example', by: 'a test',
                      initiatingEntity: 'user', base: 'https://sts.example',
                      browser: true } }, function (l) {
              return l.terminate('dora', ['oidc-rp:s1|appA'], opts({
                issuer: 'https://sts.example', by: 'a test',
                initiatingEntity: 'user', base: 'https://sts.example',
                browser: true }));
            }),
          step('the page: the default, a global sign-out', 'signOutAct',
            { body: {} }, function (l, r, s) {
              return l.signOutAct(r, s, {});
            }, { sid: 's2' }),
          inventory,
          step('everything, as an administrator', 'terminate',
            { key: 'dora', selection: [], opts: { by: 'the console',
              initiatingEntity: 'admin', channel: 'admin' } }, function (l) {
              return l.terminate('dora', [], { by: 'the console',
                initiatingEntity: 'admin', channel: 'admin' });
            })
        ]);
      caseOf(m + ': a selection ticked across families', { product: product },
        [
          step('held ids', 'heldIds', { key: 'dora' }, function (l) {
            return l.heldIds('dora');
          }),
          step('ticked', 'terminate', { key: 'dora', selection: [
            'session:s1', 'wsfed-rp:s2|nothing', 'token:at-2',
            'issued:art-2', 'krb5:dora@STS.MOCK', 'ldap:c-7',
            'no-such:row'], opts: { by: 'the person', initiatingEntity:
            'user' } }, function (l) {
            return l.terminate('dora', ['session:s1', 'wsfed-rp:s2|nothing',
              'token:at-2', 'issued:art-2', 'krb5:dora@STS.MOCK', 'ldap:c-7',
              'no-such:row'], { by: 'the person', initiatingEntity: 'user' });
          }),
          inventory
        ]);
      caseOf(m + ': the page and its view', { product: product }, [
        step('view, by the cookie', 'signOutView', {}, function (l, r) {
          return l.signOutView(r);
        }, { sid: 's1' }),
        step('view, naming somebody else', 'signOutView', {},
          function (l, r) {
            return l.signOutView(r);
          }, { sid: 's1', query: { username: 'emil' } }),
        step('view, nobody', 'signOutView', {}, function (l, r) {
          return l.signOutView(r);
        }),
        step('act, nobody', 'signOutAct', { body: {} }, function (l, r, s) {
          return l.signOutAct(r, s, {});
        }),
        step('act, another session needs a recent sign-in', 'signOutAct',
          { body: { scope: 'selected', select: ['session:s2'] } },
          function (l, r, s) {
            return l.signOutAct(r, s, { scope: 'selected',
                                        select: ['session:s2'] });
          }, { sid: 's1' }),
        step('act, my own session, ticked', 'signOutAct',
          { body: { scope: 'selected', select: 'session:s1' } },
          function (l, r, s) {
            return l.signOutAct(r, s, { scope: 'selected',
                                        select: 'session:s1' });
          }, { sid: 's1' }),
        step('subject, naming myself', 'subjectOf',
          { body: { username: 'dora@STS.MOCK' } }, function (l, r) {
            const got = l.subjectOf(r, { username: 'dora@STS.MOCK' });
            return got;
          }, { sid: 's2' })
      ]);
    });
    caseOf('product: a recent sign-in ends another session',
      { product: true, lastAuth: NOW / 1000 - 60 }, [
        step('act', 'signOutAct',
          { body: { scope: 'selected', select: ['session:s2', 'token:at-1'] } },
          function (l, r, s) {
            return l.signOutAct(r, s, { scope: 'selected',
              select: ['session:s2', 'token:at-1'] });
          }, { sid: 's1' })
      ]);
    caseOf('development: the session window, a set of people',
      { window: true }, [
        step('held ids for two', 'heldIdsFor', { keys: ['dora', 'emil'] },
          function (l) {
            return l.heldIdsFor(['dora', 'emil']);
          }),
        step('each, globally', 'terminateEach', { list: [
          { key: 'emil', selection: [] }, { key: 'dora',
            selection: ['session:s2'] }], opts: { quiet: true } },
        function (l) {
          return l.terminateEach([{ key: 'emil', selection: [] },
            { key: 'dora', selection: ['session:s2'] }], { quiet: true });
        })
      ]);
    caseOf('development: the narrower doors', {}, [
      step('grants of the session s1', 'revokeGrantsOf',
        { key: 'dora', sessionIds: ['s1'], opts: { by: 'a signal',
          initiatingEntity: 'policy' } }, function (l) {
          return l.revokeGrantsOf('dora', { sessionIds: ['s1'],
            by: 'a signal', initiatingEntity: 'policy' });
        }),
      step('a removed key', 'endFactorSessions',
        { username: 'dora', factor: { kind: 'webauthn',
          credentialId: 'key-1' }, opts: { by: 'the portal',
          initiatingEntity: 'user', channel: 'http' } }, function (l) {
          return l.endFactorSessions('dora', { kind: 'webauthn',
            credentialId: 'key-1' }, { by: 'the portal',
            initiatingEntity: 'user', channel: 'http' });
        }),
      step('a partner ended s1', 'endPartnerSession',
        { session: world().sessions.s1, opts: { issuer: 'https://sts.example',
          by: 'partner1' } }, function (l) {
          return l.endPartnerSession(world().sessions.s1, {
            issuer: 'https://sts.example', by: 'partner1' });
        }),
      step('everything left, with credentials spared', 'terminate',
        { key: 'dora', selection: [], opts: { spareCredentials: true,
          by: 'the person', initiatingEntity: 'user', browser: true,
          base: 'https://sts.example' } }, function (l) {
          return l.terminate('dora', [], { spareCredentials: true,
            by: 'the person', initiatingEntity: 'user', browser: true,
            base: 'https://sts.example' });
        })
    ]);
    caseOf('development: several accounts in one browser',
      { accounts: true }, [
        step('the step', 'signOutView', {}, function (l, r) {
          return l.signOutView(r);
        }, { accounts: [
          { key: DORA, sub: DORA, username: 'dora', displayName: 'Dora',
            current: true, sid: 's2' },
          { key: EMIL, sub: EMIL, username: 'emil', displayName: 'Emil',
            current: false, sid: 'e1' }],
           query: { login_hint: 'emil' } }),
        step('one account', 'signOutAccountsAct', { body: { account: EMIL } },
          function (l, r, s) {
            return l.signOutAccountsAct(r, s, { account: EMIL });
          }, { accounts: [
            { key: DORA, sub: DORA, username: 'dora', displayName: 'Dora',
              current: true, sid: 's2' },
            { key: EMIL, sub: EMIL, username: 'emil', displayName: 'Emil',
              current: false, sid: 'e1' }] }),
        step('every account', 'signOutAccountsAct', { body: { account:
          'all' } }, function (l, r, s) {
          return l.signOutAccountsAct(r, s, { account: 'all' });
        }, { accounts: [
          { key: DORA, sub: DORA, username: 'dora', displayName: 'Dora',
            current: true, sid: 's2' },
          { key: EMIL, sub: EMIL, username: 'emil', displayName: 'Emil',
            current: false, sid: 'e1' }] })
      ]);
    caseOf('development: Kerberos off, nothing ldap', { krb5: false,
      settings: { 'logout.ldapDisconnect': false,
                  'logout.kerberosSignOut': false } }, [inventory]);
    // A SEALED RESULT, for the Rust crate to open, and the fan-out of
    // one, which the signed-out document draws.
    const rec = recorder();
    const fk = fakes(rec, world(), {});
    const sealer = new logoutModule.Logout(Object.assign(
      logoutModule.Logout.defaultDeps(), { frontchannel: fk.frontchannel,
        backchannel: fk.backchannel }));
    const result = { key: 'dora', scope: 'global', message: 'Global logout.',
      terminated: [{ id: 'session:s1', family: 'session', kind: 'x',
                     label: 's1', message: 'ended' }],
      skipped: [], unknown: [], notifications: [{ clientId: 'appA',
        url: 'https://appA.example/fc', uri: 'https://appA.example/fc' }],
      cleanups: [{ realm: 'urn:rp:one', url: 'https://rp1.example/?wa=x' },
                 { realm: 'urn:rp:two' }],
      logoutRequests: [{ entityId: 'https://sp.example',
        url: 'https://sp.example/slo?a=1&b=2', from: 'https://sts/slo' }],
      partnerLogouts: [], backchannel: [] };
    out.sealed = { result: result, sealed: sealer.sealResult(result),
      fanOut: sealer.fanOutOf([result]) };
  } finally {
    Date.now = realNow;
    config.value = realValue;
    clusterSecrets.get = saved.get;
    cellSessions.subjectTerminated = saved.subjectTerminated;
    vcIssued.rowsForSubject = saved.rowsForSubject;
    vcIssued.disown = saved.disown;
    grantManagement.list = saved.list;
    grantManagement.revoke = saved.revoke;
    umaStore.pctsOf = saved.pctsOf;
    umaStore.deletePct = saved.deletePct;
    helpers.subjectForName = saved.subjectForName;
    helpers.nameForSubject = saved.nameForSubject;
    if (commands) {
      commands.exports.personSignedOut = savedCommand;
    }
  }
  return out;
}

/**
 * Checks what the Rust crate sealed opens in Node.
 *
 * @param {string} ROOT - the repository root
 * @param {any} v - `logout-rust.json`
 * @param {Function} check - `(ok, what, detail)`
 * @returns {void}
 */
function checkRust(ROOT, v, check) {
  const logoutModule = require(path.join(ROOT, 'logout', 'logout'));
  const clusterSecrets = require(path.join(ROOT, 'cluster', 'cluster_secrets'));
  const realNow = Date.now;
  const savedGet = clusterSecrets.get;
  try {
    Date.now = function () {
      return Number(v.now);
    };
    clusterSecrets.get = function (n) {
      return n === 'logout-result' ? Buffer.from(String(v.secret), 'utf8')
        : savedGet.call(clusterSecrets, n);
    };
    const logout = new logoutModule.Logout(logoutModule.Logout.defaultDeps());
    const opened = logout.openResult(v.sealed);
    check(!!opened.result &&
          JSON.stringify(opened.result) === JSON.stringify(v.result),
          'logout-rust: Node opens the result sts-logout sealed',
          JSON.stringify(opened).slice(0, 300));
    const tampered = logout.openResult(v.sealed.slice(0, -2) + 'AA');
    check(!tampered.result, 'logout-rust: Node refuses it tampered');
  } finally {
    Date.now = realNow;
    clusterSecrets.get = savedGet;
  }
}

module.exports = { build: build, checkRust: checkRust };

if (require.main === module) {
  const built = build(path.join(__dirname, '..', '..'));
  process.stdout.write(JSON.stringify(built, null, 1) + '\n');
}
