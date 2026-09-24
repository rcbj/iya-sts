'use strict';
//
// File: claims_aggregation.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT CLAIMS AGGREGATION (#147), IN PROCESS: what
// `tests/vendored/sts_claims_aggregation.js` cannot reach over HTTP — the
// CONSUMING side (`resolve()`, which a federation sign-in calls), a source
// from a provider this realm never registered, a JWT about somebody else, a
// refresh, sealing, and a setup flow started by another person — against a
// directory kept in memory and a Claims Provider scripted here with a key of
// its own.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const crypto = require('crypto');
const realms = require('../common/realms');
const cp = require('../oauth-oidc/claims_providers');

const log = require('bunyan').createLogger({ name: 'claims_aggregation',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = Date.now().toString(36);
const ISSUER = 'https://cp-' + RUN + '.example';
const STRANGER = 'https://stranger-' + RUN + '.example';

// A JWT signed ES256 with `key`, as a Claims Provider's signed UserInfo.
function sign(key, kid, claims) {
  log.debug("Entering sign().");
  const b64 = function (v) {
    return Buffer.from(JSON.stringify(v)).toString('base64url');
  };
  const input = b64({ alg: 'ES256', kid: kid, typ: 'JWT' }) + '.' +
                b64(claims);
  const sig = crypto.sign('sha256', Buffer.from(input),
                          { key: key, dsaEncoding: 'ieee-p1363' });
  log.debug("Leaving sign().");
  return input + '.' + sig.toString('base64url');
}

// The directory, as `credentials.claimsAggregationStore()` answers it.
function memoryStore() {
  log.debug("Entering memoryStore().");
  const entries = {};
  const tokens = {};
  log.debug("Leaving memoryStore().");
  return {
    tokens: tokens,
    call: function (operation, args) {
      if (operation === 'listClaimProviderEntries') {
        return Object.keys(entries).map(function (cn) {
          return { dn: 'cn=' + cn, attributes: entries[cn] };
        });
      }
      if (operation === 'writeClaimProviderEntry') {
        const attributes = {};
        Object.keys(args[1]).forEach(function (k) {
          const v = args[1][k];
          attributes[k.toLowerCase()] = Array.isArray(v) ? v : [String(v)];
        });
        entries[args[0]] = attributes;
        return true;
      }
      if (operation === 'deleteClaimProviderEntry') {
        const had = !!entries[args[0]];
        delete entries[args[0]];
        return had;
      }
      if (operation === 'readClaimSourceTokens') {
        return tokens[args[0]] || '';
      }
      if (operation === 'writeClaimSourceTokens') {
        if (args[1]) {
          tokens[args[0]] = args[1];
        } else {
          delete tokens[args[0]];
        }
        return true;
      }
      if (operation === 'claimSourceTokenHolders') {
        return Object.keys(tokens).map(function (u) {
          return { username: u, value: tokens[u] };
        });
      }
      return false;
    }
  };
}

async function run(t) {
  log.debug("Entering run().");
  const id = 'ca-' + RUN;
  realms.create({ id: id, name: 'Claims aggregation test' });
  try {
    await realms.run(realms.get(id), function () {
      return body(t);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

async function body(t) {
  log.debug("Entering body().");
  let clock = Date.now();
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = Object.assign(pair.publicKey.export({ format: 'jwk' }),
                            { kid: 'cp-1', use: 'sig', alg: 'ES256' });
  const calls = [];
  // What the scripted provider answers, by URL.
  let aboutWhom = 'their-sub-7';
  let signer = pair.privateKey;
  const provider = function (url, opts) {
    calls.push({ url: url, opts: opts || {} });
    const reply = function (status, body) {
      return Promise.resolve({ ok: status < 300, status: status,
        body: Buffer.from(typeof body === 'string' ? body :
                          JSON.stringify(body)), headers: {}, kind: '',
        why: status < 300 ? '' : 'HTTP ' + status, url: url });
    };
    if (url === ISSUER + '/jwks') {
      return reply(200, { keys: [jwk] });
    }
    if (url === ISSUER + '/token') {
      return reply(200, { access_token: 'at-' + calls.length,
                          refresh_token: 'rt-1', expires_in: 3600,
                          token_type: 'Bearer' });
    }
    if (url === ISSUER + '/userinfo') {
      return reply(200, sign(signer, 'cp-1', { iss: ISSUER, sub: aboutWhom,
        credit_score: 742, iat: Math.floor(clock / 1000) }));
    }
    return reply(404, { error: 'not_found' });
  };
  const store = memoryStore();
  const sealed = [];
  const lib = new cp.ClaimsProviders(Object.assign(
    cp.ClaimsProviders.defaultDeps(), {
      http: function () {
        return { requestConfigured: provider, urlProblem: function (u) {
          return /^https:\/\//.test(String(u)) ? '' : 'must be https';
        } };
      },
      keystore: function () {
        return {
          persists: function () { return true; },
          seal: function (plain, label) {
            sealed.push(label);
            return '$aesgcm$' + Buffer.from(plain).toString('base64');
          },
          open: function (s) {
            return Buffer.from(String(s).slice(8), 'base64').toString();
          }
        };
      },
      scheduler: function () {
        return { job: function () { return true; } };
      },
      audit: function () {
        return { record: function () {} };
      },
      now: function () { return clock; },
      store: store.call
    }));

  // --- 1. the register ----------------------------------------------------
  const good = { id: 'cp', issuer: ISSUER,
    authorizationEndpoint: ISSUER + '/authorize',
    tokenEndpoint: ISSUER + '/token', claimsEndpoint: ISSUER + '/userinfo',
    jwksUri: ISSUER + '/jwks', clientId: 'op-at-cp',
    authMethod: 'client_secret_basic', scope: 'openid',
    claims: ['credit_score'], delivery: 'aggregated' };
  t.check(/lower-case/.test(lib.save(Object.assign({}, good, { id: 'Bad!' }))) &&
          /https/.test(lib.save(Object.assign({}, good,
            { tokenEndpoint: 'http://x/token' }))) &&
          /at least one claim/.test(lib.save(Object.assign({}, good,
            { claims: [] }))),
          '1a. an invalid id, a URL the outbound policy refuses and no claims ' +
          'are refused');
  t.equal(lib.save(good, 's3cret'), '', '1b. a valid provider is written');
  const held = store.call('listClaimProviderEntries', [])[0].attributes;
  t.check(/^\$aesgcm\$/.test(held.stsclaimprovidersecret[0]) &&
          lib.view().providers[0].hasSecret === true &&
          JSON.stringify(lib.view()).indexOf('s3cret') < 0,
          '1c. the secret is sealed, and the view says one is held without ' +
          'showing it');

  // --- 2. the setup phase -------------------------------------------------
  const begun = lib.beginLink('alice', 'cp', 'https://op.example/realm/x');
  const state = new URL(begun.location).searchParams.get('state');
  const stolen = await lib.finishLink('mallory', { state: state,
                                                    code: 'c1' });
  const begun2 = lib.beginLink('alice', 'cp', 'https://op.example/realm/x');
  const state2 = new URL(begun2.location).searchParams.get('state');
  const linked = await lib.finishLink('alice', { state: state2, code: 'c2' });
  const replay = await lib.finishLink('alice', { state: state2, code: 'c2' });
  t.check(!stolen.ok && stolen.code === 'STS-OAUTH-0679' && linked.ok &&
          !replay.ok,
          '2a. a flow finished by another person is refused, and a state is ' +
          'spent once', JSON.stringify({ stolen: stolen, replay: replay }));
  t.check(/^\$aesgcm\$/.test(store.tokens.alice) &&
          lib.linksOf('alice')[0].sub === 'their-sub-7' &&
          JSON.stringify(lib.linksOf('alice')).indexOf('at-') < 0,
          '2b. the tokens are sealed on the entry; the link names the ' +
          'subject there and no token', JSON.stringify(lib.linksOf('alice')));
  const tokenCall = calls.filter(function (c) {
    return c.url === ISSUER + '/token';
  })[0];
  t.check(/^Basic /.test(tokenCall.opts.headers.Authorization) &&
          /code_verifier=/.test(tokenCall.opts.body),
          '2c. the code is redeemed with the client\'s secret and PKCE');

  // --- 3. delivery --------------------------------------------------------
  const refs = await lib.sourcesFor('alice', ['credit_score', 'email']);
  t.check(refs && refs._claim_names.credit_score === 'cp' &&
          !refs._claim_names.email && typeof refs._claim_sources.cp.JWT ===
          'string',
          '3a. a claim the provider supplies is referenced to it; one it ' +
          'does not is left alone', JSON.stringify(refs));
  aboutWhom = 'somebody-else';
  const wrongSub = await lib.sourcesFor('alice', ['credit_score']);
  aboutWhom = 'their-sub-7';
  signer = other.privateKey;
  const forged = await lib.sourcesFor('alice', ['credit_score']);
  signer = pair.privateKey;
  t.check(wrongSub === null && forged === null,
          '3b. a JWT about another subject, or signed by another key, sends ' +
          'nothing');
  t.equal(await lib.sourcesFor('bob', ['credit_score']), null,
          '3c. a person with no link gets no source');

  // --- 4. the consuming side ----------------------------------------------
  const theirJwt = sign(pair.privateKey, 'cp-1', { iss: ISSUER,
    sub: 'x', credit_score: 700 });
  const resolved = await lib.resolve({ _claim_names: { credit_score: 'a' },
                                       _claim_sources: { a: { JWT:
                                                         theirJwt } } });
  const unknownIssuer = await lib.resolve({
    _claim_names: { credit_score: 'a' },
    _claim_sources: { a: { JWT: sign(pair.privateKey, 'cp-1',
      { iss: STRANGER, credit_score: 1 }) } } });
  const badKey = await lib.resolve({ _claim_names: { credit_score: 'a' },
    _claim_sources: { a: { JWT: sign(other.privateKey, 'cp-1',
      { iss: ISSUER, credit_score: 1 }) } } });
  const strangeEndpoint = await lib.resolve({
    _claim_names: { credit_score: 'a' },
    _claim_sources: { a: { endpoint: STRANGER + '/userinfo',
                           access_token: 't' } } });
  const distributed = await lib.resolve({
    _claim_names: { credit_score: 'a' },
    _claim_sources: { a: { endpoint: ISSUER + '/userinfo',
                           access_token: 't' } } });
  t.check(resolved.claims.credit_score === 700 &&
          !unknownIssuer.claims.credit_score &&
          /not registered/.test(unknownIssuer.notes[0]) &&
          !badKey.claims.credit_score &&
          !strangeEndpoint.claims.credit_score &&
          distributed.claims.credit_score === 742,
          '4a. an upstream source is honoured only from a registered ' +
          'provider whose keys verify it, aggregated or distributed',
          JSON.stringify({ u: unknownIssuer.notes, b: badKey.notes,
                           s: strangeEndpoint.notes }));
  const dialled = calls.filter(function (c) {
    return c.url.indexOf(STRANGER) === 0;
  }).length;
  t.equal(dialled, 0, '4b. nothing a foreign token names is dialled');

  // --- 5. refresh ---------------------------------------------------------
  clock += 3600 * 1000 - 60 * 1000;
  const before = calls.length;
  const refreshed = await lib.refreshDue();
  const refreshCall = calls.slice(before).filter(function (c) {
    return /grant_type=refresh_token/.test(String(c.opts.body || ''));
  });
  t.check(/1 Claims Provider token/.test(refreshed.summary) &&
          refreshCall.length === 1,
          '5a. a token a minute from expiring is refreshed by the job',
          refreshed.summary);
  lib.beginLink('carol', 'cp', 'https://op.example/realm/x');
  clock += 20 * 60 * 1000;
  const swept = await lib.refreshDue();
  t.check(/1 abandoned link request/.test(swept.summary),
          '5b. and a setup flow nobody finished is dropped after ten ' +
          'minutes', swept.summary);

  // --- 6. the acts --------------------------------------------------------
  const revoked = await lib.act({ action: 'revoke-link', username: 'alice',
                                  provider: 'cp' }, { via: 'api' });
  const twice = await lib.act({ action: 'revoke-link', username: 'alice',
                                provider: 'cp' }, { via: 'api' });
  const dup = await lib.act(Object.assign({ action: 'add-provider' }, good),
                            { via: 'api' });
  t.check(revoked.ok && !twice.ok && !dup.ok && lib.linksOf('alice')
    .length === 0,
          '6a. revoking a link removes it; revoking again and a duplicate ' +
          'provider are refused');
  t.check(sealed.indexOf('claims-provider-secret') >= 0 &&
          sealed.indexOf('claim-source-tokens') >= 0,
          '6b. both the secret and the tokens went through the keystore',
          JSON.stringify(sealed));
  log.debug("Leaving body().");
}

module.exports = {
  name: 'claims_aggregation',
  describe: 'OpenID Connect Claims Aggregation (#147): the register, the ' +
            'setup flow, delivery, the consuming side, refresh and the acts, ' +
            'in process against a scripted Claims Provider',
  run: run
};
