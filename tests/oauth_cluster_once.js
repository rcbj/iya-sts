'use strict';
//
// File: oauth_cluster_once.js
//
// ===========================================================================
// THE OAUTH SINGLE-USE VALUES, ONCE ACROSS SEVERAL NODES (2026-09-14, #46).
//
// Issue #46 section 2's OAuth items: an authorization code, a PAR request_uri,
// a rotated refresh token, a DPoP proof's jti, and the hosted surfaces' own
// token renewal — each was a read, then a write, on a store that reaches the
// other nodes a moment later, and inside that moment two nodes both accepted.
// Each is now spent through `cluster/cluster_claims.js`. What is held here:
//
//   1. THE REFRESH FAMILY (`oauth2_bcp.js`), in process: a second concurrent
//      redemption through a store two "processes" share is a replay that
//      revokes the family; membership survives two children added at once; a
//      child whose parent this node never saw joins the parent's family (the
//      family travels in the token); a family revoked BY ID refuses a member
//      the revoking node never listed.
//   2. THE RENEWAL (`oidc_rp.js`), in process: a renewal already claimed
//      elsewhere is not redeemed again — this node waits and goes on with the
//      winner's tokens, and the session survives.
//   3. THE ENDPOINTS, in a child process on an ephemeral loopback port, against
//      a claim store that yields a macrotask per claim (so two requests really
//      do both reach it) and a CONTROL store that answers every claim "yes":
//        a. two identical Token Requests for one code at once — under the
//           control both are ISSUED (two different token sets), under the
//           claim one is issued and the other answered with that same set;
//        b. the same in RFC 9700 mode — one 200 and one invalid_grant, and the
//           refresh token the winner got is revoked;
//        c. two refreshes of one refresh token at once in RFC 9700 mode — one
//           200 and one invalid_grant, and the winner's new refresh token is
//           refused afterwards because its family was revoked;
//        d. a PAR request_uri whose claim another node holds is refused at the
//           authorization endpoint;
//        e. a DPoP proof whose jti another node holds is refused, a fresh one
//           is accepted, and a proof refused for something else leaves its jti
//           unclaimed.
//
// **THE CHILD** is `tests/par.js`'s reason: loading the protocol stack builds a
// certificate authority and registers every route on the shared app. The
// signer for the DPoP proof is written here, for `sts_dpop.js`'s reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'oauth_cluster_once',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const HOUR = 60 * 60 * 1000;

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// ---------------------------------------------------------------------------
// ONE CLAIM STORE, TWO "PROCESSES". The driver shape `cluster_claims.js` asks
// of `persistence.clusterStore()`, with one macrotask of delay per answer so a
// concurrent caller really does arrive before the first one is answered.
// ---------------------------------------------------------------------------
function sharedClaimStore() {
  log.debug("Entering sharedClaimStore().");
  const rows = new Map();
  const asked = [];
  const key = function (scope, realmId, digest) {
    log.debug("Entering key().");
    log.debug("Leaving key().");
    return scope + ' ' + realmId + ' ' + digest;
  };
  log.debug("Leaving sharedClaimStore().");
  return {
    rows: rows,
    asked: asked,
    claimOnce: function (scope, realmId, digest, opts) {
      log.debug("Entering claimOnce().");
      log.debug("Leaving claimOnce().");
      return sleep(5).then(function () {
        const k = key(scope, realmId, digest);
        const held = rows.get(k);
        const claimed = !held || held.expiresAt <= Date.now();
        if (claimed) {
          rows.set(k, { reservation: opts.reservation,
                        expiresAt: Date.now() + opts.ttlMs });
        }
        asked.push({ scope: scope, digest: digest, claimed: claimed });
        return { claimed: claimed, existing: claimed ? null :
                 { origin: 'the other process' } };
      });
    },
    releaseClaim: function (scope, realmId, digest, reservation) {
      log.debug("Entering releaseClaim().");
      const k = key(scope, realmId, digest);
      const held = rows.get(k);
      if (held && held.reservation === reservation) {
        rows.delete(k);
      }
      log.debug("Leaving releaseClaim().");
      return Promise.resolve(true);
    },
    claimHeld: function (scope, realmId, digest) {
      log.debug("Entering claimHeld().");
      const held = rows.get(key(scope, realmId, digest));
      log.debug("Leaving claimHeld().");
      return Promise.resolve(!!held && held.expiresAt > Date.now());
    },
    purgeClaims: function () {
      log.debug("Entering purgeClaims().");
      log.debug("Leaving purgeClaims().");
      return Promise.resolve(0);
    }
  };
}

// ---------------------------------------------------------------------------
// 1. THE REFRESH FAMILY.
// ---------------------------------------------------------------------------
async function refreshFamily(t) {
  log.debug("Entering refreshFamily().");
  t.log.info('=== 1. the refresh family, once across two processes ===');
  const realms = require('../common/realms');
  const persistence = require('../persistence/persistence');
  const claims = require('../cluster/cluster_claims');
  const bcp = require('../oauth-oidc/oauth2_bcp');
  const store = sharedClaimStore();
  const realStore = persistence.clusterStore;
  persistence.clusterStore = function () {
    log.debug("Entering clusterStore().");
    log.debug("Leaving clusterStore().");
    return store;
  };
  claims.reset();
  try {
    await realms.run(realms.DEFAULT_REALM, async function () {
      // RESTART-ONLY in the default realm, so through the environment, which
      // `config.js` reads per call (tests/oauth21_mode.js does the same).
      const savedMode = process.env.STS_OAUTH2_RFC9700;
      process.env.STS_OAUTH2_RFC9700 = 'true';
      try {
        const exp = Math.floor(Date.now() / 1000) + 3600;
        bcp.noteRefreshIssued('fam-root', '', 'fam-client');
        // Two children of one parent, as two nodes would add them: with the
        // members kept as an array on the family row, the second whole-row
        // write would have lost the first.
        bcp.noteRefreshIssued('fam-child-a', 'fam-root', 'fam-client');
        bcp.noteRefreshIssued('fam-child-b', 'fam-root', 'fam-client');
        t.equal(bcp.familyForIssuance('fam-orphan', 'a-parent-nobody-saw',
                                      'fam-root'), 'fam-root',
                'A CHILD WHOSE PARENT THIS NODE NEVER SAW JOINS THE FAMILY ' +
                'ITS PARENT\'S TOKEN NAMES, rather than starting a new one ' +
                'and splitting the chain');
        t.equal(bcp.familyForIssuance('fam-legacy', 'a-parent-nobody-saw', ''),
                'fam-legacy',
                'and a token from before the family was carried still roots ' +
                'its own, as it did');

        const presented = { jti: 'fam-child-a', client_id: 'fam-client',
                            exp: exp, refresh_family: 'fam-root' };
        const both = await Promise.all([
          bcp.spendRefreshToken({ claims: presented }),
          bcp.spendRefreshToken({ claims: presented })
        ]);
        const won = both.filter(function (one) { return one.ok; });
        const lost = both.filter(function (one) { return !one.ok; })[0];
        t.check(won.length === 1 && lost &&
                lost.errorCode === 'STS-OAUTH-0516' &&
                lost.error === 'invalid_grant',
                'TWO REDEMPTIONS OF ONE REFRESH TOKEN AT ONCE: EXACTLY ONE ' +
                'IS SPENT, and the other is a replay (STS-OAUTH-0516)',
                JSON.stringify(both.map(function (one) {
                  return one.ok || one.errorCode;
                })));
        t.check(store.asked.filter(function (one) {
          return one.scope === 'oauth.refresh';
        }).length === 2,
                'and both reached the shared store — the race happened and ' +
                'the store decided it');
        const revoke = (lost && lost.revoke) || [];
        t.check(['fam-root', 'fam-child-a', 'fam-child-b'].every(
                  function (jti) { return revoke.indexOf(jti) >= 0; }),
                'THE REPLAY REVOKES EVERY MEMBER, including both children ' +
                'added one after the other — membership is derived from each ' +
                'token\'s own record, so neither was lost',
                JSON.stringify(revoke));
        t.equal(lost && lost.family, 'fam-root',
                'and names the family, so the grant can revoke it by id');

        await bcp.revokeFamily('fam-root', 'fam-client');
        const late = await bcp.spendRefreshToken({ claims: {
          jti: 'fam-minted-elsewhere', client_id: 'fam-client', exp: exp,
          refresh_family: 'fam-root' } });
        t.check(!late.ok && late.errorCode === 'STS-OAUTH-0517' &&
                late.revoke.indexOf('fam-minted-elsewhere') >= 0,
                'A FAMILY REVOKED BY ID REFUSES A MEMBER THE REVOKING NODE ' +
                'NEVER LISTED — one minted on another node in the same ' +
                'instant — and revokes it (STS-OAUTH-0517)',
                JSON.stringify(late));

        const failing = {
          claimOnce: function () {
            return Promise.reject(new Error('the database is down'));
          },
          claimHeld: function () {
            return Promise.reject(new Error('the database is down'));
          },
          purgeClaims: function () {
            return Promise.resolve(0);
          }
        };
        persistence.clusterStore = function () {
          log.debug("Entering clusterStore().");
          log.debug("Leaving clusterStore().");
          return failing;
        };
        const down = await bcp.spendRefreshToken({ claims: {
          jti: 'fam-other', client_id: 'fam-client', exp: exp } });
        t.check(!down.ok && down.errorCode === 'STS-OAUTH-0518' &&
                down.status === 500,
                'A STORE THAT CANNOT BE ASKED REFUSES (fail closed, ' +
                'STS-OAUTH-0518) rather than redeem a token it cannot prove ' +
                'unspent', JSON.stringify(down));

        delete process.env.STS_OAUTH2_RFC9700;
        persistence.clusterStore = function () {
          log.debug("Entering clusterStore().");
          log.debug("Leaving clusterStore().");
          return store;
        };
        const off = await Promise.all([
          bcp.spendRefreshToken({ claims: presented }),
          bcp.spendRefreshToken({ claims: presented })
        ]);
        t.check(off[0].ok && off[1].ok,
                'with RFC 9700 mode off nothing is claimed — a refresh token ' +
                'is reusable by design there');
      } finally {
        if (savedMode === undefined) {
          delete process.env.STS_OAUTH2_RFC9700;
        } else {
          process.env.STS_OAUTH2_RFC9700 = savedMode;
        }
      }
    });
  } finally {
    persistence.clusterStore = realStore;
    claims.reset();
  }
  log.debug("Leaving refreshFamily().");
}

// ---------------------------------------------------------------------------
// 2. THE RENEWAL.
// ---------------------------------------------------------------------------
function fakeRes() {
  log.debug("Entering fakeRes().");
  const headers = [];
  log.debug("Leaving fakeRes().");
  return {
    headers: headers,
    headersSent: false,
    getHeader: function () {
      log.debug("Entering getHeader().");
      log.debug("Leaving getHeader().");
      return headers.slice();
    },
    setHeader: function (name, value) {
      log.debug("Entering setHeader().");
      headers.length = 0;
      [].concat(value).forEach(function (v) { headers.push(v); });
      log.debug("Leaving setHeader().");
    },
    req: null
  };
}

function cookieFrom(res, name) {
  log.debug("Entering cookieFrom().");
  let found = '';
  res.headers.forEach(function (line) {
    const pair = String(line).split(';')[0];
    const i = pair.indexOf('=');
    if (i > 0 && pair.slice(0, i).trim() === name) {
      found = pair.slice(i + 1).trim();
    }
  });
  log.debug("Leaving cookieFrom().");
  return found;
}

async function renewalSingleFlight(t) {
  log.debug("Entering renewalSingleFlight().");
  t.log.info('=== 2. a renewal claimed elsewhere is not redeemed again ===');
  const realms = require('../common/realms');
  const authn = require('../authn/authn');
  const oidcRp = require('../common/oidc_rp');
  const claims = require('../cluster/cluster_claims');
  claims.reset();
  const now = Date.now();
  const tokens = {
    accessToken: 'access-cluster-' + now, tokenType: 'Bearer',
    scope: 'openid', accessExpiresAt: now - 1000,
    refreshToken: 'refresh-cluster-' + now, idToken: 'id-' + now,
    idTokenExpiresAt: now - 1000, issuer: 'https://sts.test',
    sub: 'urn:sts:user:cluster-renew', authTime: Math.floor(now / 1000) - 60,
    flowRealm: 'default', host: 'sts.test'
  };
  const made = realms.run(realms.DEFAULT_REALM, function () {
    const parent = authn.startSession(fakeRes(), 'cluster-renew', [], '1',
                                      'Test', {});
    const res = fakeRes();
    const session = authn.startRelyingPartySession({
      res: res, username: 'cluster-renew', claims: {}, via: 'User portal',
      parent: parent.id, parentRealm: realms.DEFAULT_ID,
      surface: 'portal', label: 'User portal', clientId: 'sts-user-portal',
      cookie: 'sts_portal', tokens: tokens,
      renewableUntil: now + 24 * HOUR
    });
    return { parent: parent, session: session,
             cookie: cookieFrom(res, 'sts_portal') };
  });
  const req = { headers: { cookie: 'sts_portal=' + made.cookie } };
  try {
    // Another node won the race: its claim is in the store.
    const elsewhere = await realms.run(realms.DEFAULT_REALM, function () {
      return claims.claim({ scope: 'oidc_rp.renewal', realm: realms.DEFAULT_ID,
                            value: made.session.id + '\n' + tokens.accessToken,
                            ttlMs: 60000 });
    });
    t.check(elsewhere.ok, 'the other node holds the renewal');
    // ... and lands its renewed tokens a moment later.
    setTimeout(function () {
      realms.run(realms.DEFAULT_REALM, function () {
        authn.renewRelyingPartySession({
          realmId: realms.DEFAULT_ID, id: made.session.id,
          tokens: Object.assign({}, tokens, {
            accessToken: 'access-renewed-elsewhere',
            accessExpiresAt: Date.now() + HOUR,
            idTokenExpiresAt: Date.now() + HOUR })
        });
      });
    }, 150);
    const answer = await realms.run(realms.DEFAULT_REALM, function () {
      return oidcRp.renewIfDue(req, fakeRes(), 'portal');
    });
    t.check(answer && answer.renewed === true && answer.elsewhere === true,
            'A RENEWAL ANOTHER NODE HOLDS IS NOT REDEEMED AGAIN: this node ' +
            'waited for that renewal and went on with its tokens',
            JSON.stringify(answer && { renewed: answer.renewed,
                                       elsewhere: answer.elsewhere,
                                       ended: answer.ended,
                                       why: answer.why }));
    const read = realms.run(realms.DEFAULT_REALM, function () {
      return authn.relyingPartySessionOf(req, 'sts_portal',
                                         realms.DEFAULT_ID);
    });
    t.check(!!read && read.rpTokens.accessToken === 'access-renewed-elsewhere',
            'and the session is alive, carrying the winner\'s tokens — a ' +
            'second redemption here would have been an RFC 9700 replay that ' +
            'ended it');
  } finally {
    realms.run(realms.DEFAULT_REALM, function () {
      [made.parent.id, made.session.id].forEach(function (id) {
        if (authn.sessions.get(id)) {
          authn.sessions.delete(id);
        }
      });
    });
    claims.reset();
  }
  log.debug("Leaving renewalSingleFlight().");
}

// ---------------------------------------------------------------------------
// 3. THE ENDPOINTS, IN A CHILD.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.ONCE_ROOT;
  const OUT = process.env.ONCE_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };
  const b64 = function (value) {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
  };

  let jar = {};
  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.form ? new URLSearchParams(o.form).toString() : '';
      const headers = Object.assign({}, o.headers || {});
      if (o.cookies && Object.keys(jar).length) {
        headers.cookie = Object.keys(jar).map(function (k) {
          return k + '=' + jar[k];
        }).join('; ');
      }
      if (method !== 'GET') {
        headers['content-type'] = 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        (res.headers['set-cookie'] || []).forEach(function (line) {
          const pair = line.split(';')[0];
          const eq = pair.indexOf('=');
          jar[pair.slice(0, eq)] = pair.slice(eq + 1);
        });
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            parsed = { parseError: e.message };
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed });
        });
      });
      req.end(body);
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const persistence = require(ROOT + '/persistence/persistence');
    const claims = require(ROOT + '/cluster/cluster_claims');

    // The shared store, yielding per claim; `control` answers every claim
    // "yes", which is what a node without the claim did.
    let control = false;
    const rows = new Map();
    const asked = [];
    const store = {
      claimOnce: function (scope, realmId, digest, opts) {
        return sleep(10).then(function () {
          const k = scope + ' ' + realmId + ' ' + digest;
          const held = rows.get(k);
          const claimed = control || !held || held.expiresAt <= Date.now();
          if (claimed) {
            rows.set(k, { reservation: opts.reservation,
                          expiresAt: Date.now() + opts.ttlMs });
          }
          asked.push({ scope: scope, digest: digest, claimed: claimed });
          return { claimed: claimed, existing: claimed ? null :
                   { origin: 'the other node' } };
        });
      },
      releaseClaim: function (scope, realmId, digest, reservation) {
        const k = scope + ' ' + realmId + ' ' + digest;
        const held = rows.get(k);
        if (held && held.reservation === reservation) {
          rows.delete(k);
        }
        return Promise.resolve(true);
      },
      claimHeld: function (scope, realmId, digest) {
        const held = rows.get(scope + ' ' + realmId + ' ' + digest);
        return Promise.resolve(!!held && held.expiresAt > Date.now());
      },
      purgeClaims: function () {
        return Promise.resolve(0);
      }
    };
    persistence.clusterStore = function () {
      return store;
    };
    const heldBy = function (scope, value) {
      const digest = claims.digestOf(scope, value);
      return asked.filter(function (one) {
        return one.scope === scope && one.digest === digest;
      });
    };

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;

    config.setOverride('oauth2.consentRequired', false);

    const SECRET = 'once-client-secret-0123456789abcdef0123456789';
    const REDIRECT = 'https://rp.once.example/cb';
    const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    applications.createApplication({ identifier: 'once-a',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'once-a', oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    const basic = 'Basic ' + Buffer.from('once-a:' + SECRET).toString('base64');

    const signIn = async function (first) {
      if (!(first.status === 302 &&
            /\/authn\/login/.test(String(first.headers.location || '')))) {
        return first;
      }
      const page = await request(port, 'GET', first.headers.location,
                                 { cookies: true });
      const form = {};
      (page.text.match(/<input type="hidden"[^>]*>/g) || []).forEach(
        function (tag) {
          const name = /name="([^"]+)"/.exec(tag);
          const value = /value="([^"]*)"/.exec(tag);
          if (name) {
            form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
          }
        });
      form.username = 'once-alice';
      form.password = 'anything';
      form.action = 'login';
      const screen = String(first.headers.location).split('?')[0]
        .replace(/^https?:\/\/[^/]+/, '');
      const posted = await request(port, 'POST', screen,
                                   { form: form, cookies: true });
      const back = String(posted.headers.location || '')
        .replace(/^https?:\/\/[^/]+/, '');
      return back ? request(port, 'GET', back, { cookies: true }) : posted;
    };
    const codeFrom = function (r) {
      const loc = String((r && r.headers && r.headers.location) || '');
      if (!r || r.status !== 302 || loc.indexOf(REDIRECT) !== 0) {
        return '';
      }
      return new URL(loc).searchParams.get('code') || '';
    };
    // RFC 9700 mode refuses a code_challenge or a nonce seen before (section
    // 2.1.1), so every authorization request gets a verifier of its own.
    const verifiers = {};
    const newCode = async function () {
      jar = {};
      const verifier = crypto.randomBytes(32).toString('base64url');
      const challenge = crypto.createHash('sha256').update(verifier)
        .digest('base64url');
      const first = await request(port, 'GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: 'once-a', response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid offline_access',
          state: 's-' + crypto.randomBytes(6).toString('hex'),
          nonce: 'n-' + crypto.randomBytes(6).toString('hex'),
          code_challenge: challenge, code_challenge_method: 'S256' })
          .toString());
      const final = await signIn(first);
      const code = codeFrom(final);
      verifiers[code] = verifier;
      return { code: code, final: final };
    };
    const redeem = function (code) {
      return request(port, 'POST', '/oauth2/token', {
        headers: { authorization: basic },
        form: { grant_type: 'authorization_code', code: code,
                redirect_uri: REDIRECT,
                code_verifier: verifiers[code] || VERIFIER } });
    };
    const refresh = function (token) {
      return request(port, 'POST', '/oauth2/token', {
        headers: { authorization: basic },
        form: { grant_type: 'refresh_token', refresh_token: token,
                client_id: 'once-a' } });
    };

    // --- a. the control, then the claim, in development mode -----------------
    control = true;
    let got = await newCode();
    note(!!got.code, '3a0. a code is issued',
         got.final.status + ' ' + got.final.headers.location);
    let pair = await Promise.all([redeem(got.code), redeem(got.code)]);
    note(pair[0].status === 200 && pair[1].status === 200 &&
         pair[0].json.access_token !== pair[1].json.access_token,
         '3a1. CONTROL — with a claim that always says yes, two Token ' +
         'Requests for one code at once are BOTH ISSUED, two different token ' +
         'sets: the double issuance #46 describes, reproduced',
         pair.map(function (r) { return r.status; }).join(','));
    control = false;
    got = await newCode();
    pair = await Promise.all([redeem(got.code), redeem(got.code)]);
    // Since #187 a code used twice is refused in every mode (RFC 6749
    // section 4.1.2), so the loser of the race is a refused replay rather
    // than the old development courtesy's copy of the winner's tokens.
    const statuses = pair.map(function (r) {
      return r.status;
    }).sort();
    note(statuses[0] === 200 && statuses[1] === 400 &&
         (pair[0].status === 400 ? pair[0] : pair[1]).json.error ===
           'invalid_grant',
         '3a2. WITH THE CLAIM, ONE REDEMPTION IS ISSUED and the concurrent ' +
         'identical one is refused as the replay it is (RFC 6749 section ' +
         '4.1.2, in every mode since #187), across the race',
         pair.map(function (r) { return r.status + ' ' +
           String(r.json.access_token || r.text).slice(-12); }).join(' | '));
    const codeAsks = heldBy('oauth.code', got.code);
    note(codeAsks.length === 2 && codeAsks.filter(function (one) {
      return one.claimed;
    }).length === 1,
         '3a3. and both requests reached the store, which spent the code once',
         JSON.stringify(codeAsks));

    // --- d. PAR, before RFC 9700 mode is on ---------------------------------
    jar = {};
    let pushed = await request(port, 'POST', '/oauth2/par', {
      headers: { authorization: basic },
      form: { response_type: 'code', redirect_uri: REDIRECT, scope: 'openid',
              state: 'st-par', nonce: 'n-par', code_challenge: CHALLENGE,
              code_challenge_method: 'S256' } });
    const uri = pushed.json && pushed.json.request_uri;
    note(pushed.status === 201 && !!uri, '3d0. a push is accepted',
         pushed.status + ' ' + pushed.text.slice(0, 160));
    await claims.claim({ scope: 'oauth.par', value: uri, ttlMs: 60000,
                         realm: 'default' });
    let first = await request(port, 'GET', '/oauth2/authorize?' +
      new URLSearchParams({ client_id: 'once-a', request_uri: uri })
        .toString());
    let final = await signIn(first);
    note(final.status === 400 && final.json &&
         final.json.error === 'invalid_request_uri' &&
         /another request at the same moment/.test(
           final.json.error_description || ''),
         '3d1. A REQUEST_URI ANOTHER NODE IS ISSUING ON IS REFUSED here, and ' +
         'no code is issued on it twice',
         final.status + ' ' + final.text.slice(0, 200));

    // --- e. DPoP -------------------------------------------------------------
    const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = ec.publicKey.export({ format: 'jwk' });
    const proof = function (jti, htu) {
      const input = b64({ typ: 'dpop+jwt', alg: 'ES256', jwk: jwk }) + '.' +
        b64({ jti: jti, htm: 'POST', htu: htu || BASE + '/oauth2/token',
              iat: Math.floor(Date.now() / 1000) });
      return input + '.' + crypto.sign('sha256', Buffer.from(input),
        { key: ec.privateKey, dsaEncoding: 'ieee-p1363' })
        .toString('base64url');
    };
    const withProof = function (dpopHeader) {
      return request(port, 'POST', '/oauth2/token', {
        headers: { authorization: basic, dpop: dpopHeader },
        form: { grant_type: 'client_credentials' } });
    };
    const takenJti = 'jti-' + crypto.randomBytes(8).toString('hex');
    await claims.claim({ scope: 'oauth.dpop-jti', value: takenJti,
                         ttlMs: 60000, realm: 'default' });
    let r = await withProof(proof(takenJti));
    note(r.status === 400 && r.json.error === 'invalid_dpop_proof' &&
         /already been used/.test(r.json.error_description || ''),
         '3e1. A DPoP PROOF WHOSE JTI ANOTHER NODE HOLDS IS REFUSED',
         r.status + ' ' + r.text.slice(0, 200));
    const freshJti = 'jti-' + crypto.randomBytes(8).toString('hex');
    r = await withProof(proof(freshJti));
    note(r.status === 200 && r.json.token_type === 'DPoP',
         '3e2. a fresh proof is accepted', r.status + ' ' + r.text.slice(0,
                                                                         200));
    await sleep(30);
    note(await claims.isClaimed({ scope: 'oauth.dpop-jti', value: freshJti,
                                  realm: 'default' }),
         '3e3. and its jti stays claimed for every node');
    const wrongJti = 'jti-' + crypto.randomBytes(8).toString('hex');
    r = await withProof(proof(wrongJti, BASE + '/somewhere-else'));
    await sleep(30);
    note(r.status === 400 && !(await claims.isClaimed({
      scope: 'oauth.dpop-jti', value: wrongJti, realm: 'default' })),
         '3e4. a proof refused for another reason (its htu) leaves its jti ' +
         'unclaimed — only an accepted proof is remembered, as before',
         r.status + ' ' + r.text.slice(0, 160));
    const racingJti = 'jti-' + crypto.randomBytes(8).toString('hex');
    const racing = proof(racingJti);
    pair = await Promise.all([withProof(racing), withProof(racing)]);
    note(pair.filter(function (one) { return one.status === 200; })
           .length === 1,
         '3e5. one proof on two requests at once: exactly one accepted',
         pair.map(function (one) { return one.status; }).join(','));

    // --- b. RFC 9700 mode: a concurrent code replay revokes ------------------
    process.env.STS_OAUTH2_RFC9700 = 'true';
    got = await newCode();
    note(!!got.code, '3b0. a code is issued in RFC 9700 mode',
         got.final.status + ' ' + String(got.final.headers.location ||
                                         got.final.text).slice(0, 200));
    pair = await Promise.all([redeem(got.code), redeem(got.code)]);
    let ok = pair.filter(function (one) { return one.status === 200; });
    let bad = pair.filter(function (one) { return one.status !== 200; });
    note(ok.length === 1 && bad.length === 1 &&
         bad[0].json.error === 'invalid_grant',
         '3b1. RFC 9700 MODE: TWO REDEMPTIONS OF ONE CODE AT ONCE — ONE ' +
         'ISSUED, ONE REFUSED as a replay',
         pair.map(function (one) { return one.status + ' ' +
           one.text.slice(0, 120); }).join(' | '));
    if (ok.length === 1) {
      r = await refresh(ok[0].json.refresh_token);
      note(r.status === 400 && r.json.error === 'invalid_grant',
           '3b2. and what the winner bought is revoked (section 4.5): its ' +
           'refresh token is refused', r.status + ' ' + r.text.slice(0, 160));
    }

    // --- c. RFC 9700 mode: a concurrent refresh revokes the family -----------
    got = await newCode();
    r = await redeem(got.code);
    note(r.status === 200 && !!r.json.refresh_token,
         '3c0. a token set with a refresh token', r.status);
    pair = await Promise.all([refresh(r.json.refresh_token),
                              refresh(r.json.refresh_token)]);
    ok = pair.filter(function (one) { return one.status === 200; });
    bad = pair.filter(function (one) { return one.status !== 200; });
    note(ok.length === 1 && bad.length === 1 &&
         bad[0].json.error === 'invalid_grant',
         '3c1. TWO REFRESHES OF ONE ROTATED TOKEN AT ONCE — ONE ISSUED, ONE ' +
         'REFUSED as a replay',
         pair.map(function (one) { return one.status + ' ' +
           one.text.slice(0, 120); }).join(' | '));
    if (ok.length === 1) {
      r = await refresh(ok[0].json.refresh_token);
      note(r.status === 400 && r.json.error === 'invalid_grant',
           '3c2. and the chain is revoked: the refresh token the winner was ' +
           'issued is refused afterwards', r.status + ' ' +
           r.text.slice(0, 160));
    }
    delete process.env.STS_OAUTH2_RFC9700;

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  t.log.info('=== 3. the endpoints, in a child process ===');
  const out = path.join(os.tmpdir(), 'oauth-once-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', ONCE_ROOT: ROOT,
                                  ONCE_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  await refreshFamily(t);
  await renewalSingleFlight(t);
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oauth_cluster_once',
  describe: '#46 section 2, OAuth: codes, PAR request_uris, rotated refresh ' +
            'tokens, DPoP jtis and the hosted surfaces\' renewal, each spent ' +
            'once across nodes through a cluster claim',
  run: run
};
