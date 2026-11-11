// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_oauth.js
//
// ---------------------------------------------------------------------------
// THE OAUTH 2.0 AND OPENID CONNECT MODEL, AND WHAT HOLDS THE SERVICE TO IT
// (#1579).
//
// `models/oauth/oauth.tsp` states every endpoint's request parameters and
// `oauth_members.tsp` the members of every answer, the claim sets and the
// error codes. This holds four things:
//
//   A. the build's check (`models/lib/oauth_lib.mjs`'s checkOAuth()) passes
//      the generated table and refuses each kind of wrong model, asserted on
//      a copy with one thing broken;
//   B. every request validator is the model's: `oauth2.ts` and
//      `consent_screen.ts` declare no zod schema of their own, and each
//      endpoint's validator refuses and accepts what its parameters say;
//   C. what the issuers produced — every answer, decoded JWT and error code
//      `tests/oauth_model_wire.snapshot.json` recorded, in four modes — is
//      the model's, and every error code a funnel in `oauth-oidc/` sends is
//      declared;
//   D. both discovery documents, built with every `oauth2.*` switch on in
//      each FAPI profile, carry no member the model does not name (a child
//      process, so the protocol stack loads fresh).
//
// That the generated validators answer on the wire exactly as the
// hand-written ones did is `tests/oauth_model_wire.js`'s.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const url = require('url');

const log = require('bunyan').createLogger({
  name: 'model_oauth',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');
const ModelTables = require('../common/model_tables');

// A copy of the generated table, for one thing to be broken in.
function copy() {
  log.debug("Entering copy().");
  log.debug("Leaving copy().");
  return JSON.parse(JSON.stringify(ModelTables.file('oauth.json')));
}

// One parameter of an endpoint of a copy, by name.
function param(oauth, id, name) {
  log.debug("Entering param().");
  const endpoint = oauth.endpoints.filter(function (one) {
    return one.id === id;
  })[0];
  log.debug("Leaving param().");
  return endpoint.params.filter(function (one) {
    return one.name === name;
  })[0];
}

// A. The build's refusals.
async function buildCheck(t) {
  log.debug("Entering buildCheck().");
  const lib = await import(url.pathToFileURL(path.join(ROOT, 'models', 'lib',
    'oauth_lib.mjs')).href);
  const generated = ModelTables.file('oauth.json');
  t.check(lib.checkOAuth(generated).length === 0,
          'A. the generated OAuth model is clean',
          lib.checkOAuth(generated).join('; '));
  const refused = function (what, pattern, change) {
    const broken = copy();
    change(broken);
    const said = lib.checkOAuth(broken).join('; ');
    t.check(pattern.test(said), 'A. refused: ' + what, said || '(nothing)');
  };
  refused('a string with no bound', /token\.grant_type is a string with no bound/,
    function (o) {
      delete param(o, 'token', 'grant_type').maxLength;
    });
  refused('a bound stated twice', /states its bound twice/, function (o) {
    param(o, 'token', 'grant_type').cap = 'TEXT';
  });
  refused('a bound on a type that carries its own',
    /checked as scope, which carries its own bound/, function (o) {
      param(o, 'token', 'scope').maxLength = 10;
    });
  refused('an integer without both bounds', /no minimum and maximum/,
    function (o) {
      delete param(o, 'authorize', 'max_age').maximum;
    });
  refused('a pattern that does not compile', /pattern does not compile/,
    function (o) {
      param(o, 'authorize', 'domain_hint').pattern = '([';
    });
  refused('a parameter citing nothing', /logout\.state cites nothing/,
    function (o) {
      param(o, 'logout', 'state').cite = '';
    });
  refused('a required parameter that may be empty',
    /is required and may be empty/, function (o) {
      param(o, 'registered-client', 'client_id').empty = true;
    });
  refused('an endpoint declared twice', /endpoint token is declared twice/,
    function (o) {
      o.endpoints.push(JSON.parse(JSON.stringify(o.endpoints.filter(
        function (one) {
          return one.id === 'token';
        })[0])));
    });
  refused('a member set declared twice', /token-response is declared twice/,
    function (o) {
      o.members.push(JSON.parse(JSON.stringify(o.members.filter(
        function (one) {
          return one.id === 'token-response';
        })[0])));
    });
  refused('an error code declared twice', /invalid_grant is declared twice/,
    function (o) {
      o.errors.push({ code: 'invalid_grant', cite: 'x' });
    });
  refused('an error code outside RFC 6749\'s set', /character set/,
    function (o) {
      o.errors.push({ code: 'bad"code', cite: 'x' });
    });
  log.debug("Leaving buildCheck().");
}

// B. The validators are the model's, and say what it says.
function validators(t) {
  log.debug("Entering validators().");
  ['oauth-oidc/oauth2.ts', 'oauth-oidc/consent_screen.ts']
    .forEach(function (file) {
      // The comments name the shared types the reasoning is about; the
      // code may not use them.
      const text = fs.readFileSync(path.join(ROOT, file), 'utf8')
        .replace(/^\s*\/\/.*$/gm, '');
      t.check(!/\bv[zt]\.|validation\.(z|types)\b/.test(text),
              'B. ' + file + ' writes no request schema of its own');
    });
  const validation = require('../common/validation');
  const OAuthModel = require('../oauth-oidc/oauth_model');
  const accepts = function (id, input, where) {
    return validation.checkParsed(input, where || 'body',
                                  OAuthModel.request(id));
  };
  const generated = ModelTables.file('oauth.json');
  generated.endpoints.forEach(function (endpoint) {
    t.check(!!OAuthModel.request(endpoint.id),
            'B. a validator is generated for ' + endpoint.id);
  });
  // The registration refusals that test a member's JSON type ask the
  // model for it, by a name the model's RegistrationRequest holds.
  const applicationsSource = fs.readFileSync(path.join(ROOT, 'common',
    'applications.js'), 'utf8').replace(/\s+/g, ' ');
  const asked = new Set();
  const pattern = /registration(?:Type|Item)Fits\('([a-z_]+)'/g;
  let found = pattern.exec(applicationsSource);
  while (found) {
    asked.add(found[1]);
    found = pattern.exec(applicationsSource);
  }
  const requestMembers = OAuthModel.members('registration-request').list
    .map(function (one) {
      return one.name;
    });
  const strays = Array.from(asked).filter(function (name) {
    return requestMembers.indexOf(name) < 0;
  });
  t.check(asked.size >= 8 && strays.length === 0,
          'B. every registration refusal testing a member\'s type reads it ' +
          'from the model (' + asked.size + ' named)', strays.join(', '));
  t.check(OAuthModel.memberFits('registration-request', 'default_max_age',
                                300) &&
          !OAuthModel.memberFits('registration-request', 'default_max_age',
                                 1.5) &&
          OAuthModel.itemFits('registration-request', 'request_uris', 'x') &&
          !OAuthModel.itemFits('registration-request', 'request_uris', 5),
          'B. the model types a member and an array\'s values');
  const r1 = accepts('authorize', { max_age: '30', scope: 'openid' },
                     'query');
  t.check(r1.ok && r1.value.max_age === 30,
          'B. authorize: max_age is an integer from 0 to 315360000');
  t.check(!accepts('authorize', { max_age: '-1' }, 'query').ok,
          'B. authorize: max_age below its minimum is refused');
  const r2 = accepts('authorize', { resource: 'https://a.example/' },
                     'query');
  t.check(r2.ok && Array.isArray(r2.value.resource),
          'B. authorize: resource repeats, so one is a list of one');
  t.check(accepts('authorize', { vendor_x: 'kept' }, 'query').value
            .vendor_x === 'kept',
          'B. authorize: an undeclared parameter passes through');
  t.check(accepts('authorize', { code_challenge: '' }, 'query').ok,
          'B. authorize: an empty code_challenge is no value');
  const short = accepts('token', { code_verifier: 'short' });
  t.check(!short.ok && short.field === 'code_verifier',
          'B. token: a code_verifier shorter than 43 is refused');
  t.check(!accepts('token', { grant_type: 'x'.repeat(129) }).ok,
          'B. token: grant_type is bounded at 128');
  const strip = accepts('registered-client', { client_id: 'c', other: 'x' },
                        'params');
  t.check(strip.ok && strip.value.other === undefined,
          'B. registered-client: an undeclared parameter is dropped');
  t.check(!accepts('registered-client', {}, 'params').ok,
          'B. registered-client: client_id is required');
  log.debug("Leaving validators().");
}

// Every decoded JWT in a recorded value, with the member that held it.
function jwtsIn(value, name, out) {
  log.debug("Entering jwtsIn().");
  if (Array.isArray(value)) {
    value.forEach(function (one) {
      jwtsIn(one, name, out);
    });
  } else if (value && typeof value === 'object') {
    if (value.jwt && value.jwt.claims && value.jwt.header) {
      out.push({ name: name, header: value.jwt.header,
                 claims: value.jwt.claims });
    }
    Object.keys(value).forEach(function (key) {
      jwtsIn(value[key], key, out);
    });
  }
  log.debug("Leaving jwtsIn().");
}

// The members a placeholder may stand in for that are numbers.
const NUMERIC = ['iat', 'exp', 'nbf', 'auth_time', 'client_id_issued_at',
  'client_secret_expires_at'];

// A recorded value with each run-to-run placeholder put back as a value of
// the type it replaced, so a type check reads it as the issuer wrote it.
function restored(claims) {
  log.debug("Entering restored().");
  const out = {};
  Object.keys(claims).forEach(function (key) {
    const value = claims[key];
    if (value === '<epoch>' ||
        (NUMERIC.indexOf(key) >= 0 && typeof value === 'string')) {
      out[key] = 1800000000;
    } else {
      out[key] = value;
    }
  });
  log.debug("Leaving restored().");
  return out;
}

// C. What the issuers produced is the model's.
function issued(t) {
  log.debug("Entering issued().");
  const OAuthModel = require('../oauth-oidc/oauth_model');
  const wire = JSON.parse(fs.readFileSync(path.join(__dirname,
    'oauth_model_wire.snapshot.json'), 'utf8')).wire;
  const SETS = {
    'openid-configuration': 'openid-provider-metadata',
    'oauth-authorization-server': 'authorization-server-metadata'
  };
  const problems = [];
  // A registration that sent one member as a wrong JSON type and was
  // accepted would echo it. Since rcbj's decision on #1579 (2026-11-11)
  // every such registration is refused with invalid_client_metadata
  // (STS-OAUTH-1007), so the wire record holds none: one found here is a
  // member the refusal missed, and it is counted rather than hidden.
  const accepted = [];
  const hold = function (where, id, value, sentWrong) {
    OAuthModel.undeclared(id, restored(value)).forEach(function (one) {
      if (sentWrong && one.indexOf(sentWrong + ' is not ') === 0) {
        accepted.push(sentWrong);
        return;
      }
      problems.push(where + ': ' + one);
    });
  };
  const counted = {};
  wire.forEach(function (one) {
    const where = one.mode + ', ' + one.step;
    const body = one.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return;
    }
    let id = SETS[one.step];
    if (!id && one.status >= 400 && body.error) {
      id = 'error-response';
      if (OAuthModel.unknownError(body.error)) {
        problems.push(where + ': the error ' + body.error +
                      ' is not declared');
      }
    } else if (!id && one.path === '/oauth2/token' && one.status === 200) {
      id = 'token-response';
    } else if (!id && one.path === '/oauth2/introspect' &&
               one.status === 200 && body.active !== undefined) {
      id = 'introspection-response';
    } else if (!id && /^\/oauth2\/register/.test(one.path) &&
               one.status < 300) {
      id = 'registration-response';
    } else if (!id && one.path === '/oauth2/device_authorization' &&
               one.status === 200) {
      id = 'device-authorization-response';
    } else if (!id && one.path === '/oauth2/bc-authorize' &&
               one.status === 200) {
      id = 'backchannel-authentication-response';
    } else if (!id && one.path === '/oauth2/par' && one.status === 201) {
      id = 'pushed-authorization-response';
    }
    if (id) {
      // A JWT member was recorded decoded; the answer carried a string.
      const flat = {};
      Object.keys(body).forEach(function (key) {
        flat[key] = body[key] && body[key].jwt ? 'a.b.c' : body[key];
      });
      const probe = /^register, ([a-z_]+) /.exec(one.step);
      hold(where, id, flat, probe && id === 'registration-response'
        ? probe[1] : null);
      counted[id] = (counted[id] || 0) + 1;
    }
    const tokens = [];
    jwtsIn(body, '', tokens);
    tokens.forEach(function (token) {
      const kind = token.header.typ === 'at+jwt' ? 'access-token'
        : token.header.typ === 'token-introspection+jwt'
          ? 'introspection-jwt'
          : token.header.typ === 'logout+jwt' ? 'logout-token'
            : token.name === 'id_token' ? 'id-token' : null;
      if (kind) {
        hold(where + ' (' + kind + ')', kind, token.claims);
        counted[kind] = (counted[kind] || 0) + 1;
      }
    });
  });
  t.check(problems.length === 0,
          'C. every recorded answer, claim set and error code is the ' +
          'model\'s (' + JSON.stringify(counted) + ')',
          problems.slice(0, 20).join('\n'));
  t.check(accepted.length === 0,
          'C. no registration sending a member of a wrong type is accepted ' +
          '(rcbj on #1579)', accepted.join(', '));
  ['openid-provider-metadata', 'token-response', 'error-response',
   'access-token', 'id-token', 'introspection-response',
   'registration-response', 'logout-token',
   'backchannel-authentication-response'].forEach(function (id) {
    t.check((counted[id] || 0) > 0, 'C. the record holds a ' + id);
  });
  // Every error code a funnel of this family sends is declared.
  const sent = new Set();
  fs.readdirSync(path.join(ROOT, 'oauth-oidc')).filter(function (name) {
    return /\.(ts|js)$/.test(name);
  }).forEach(function (name) {
    const text = fs.readFileSync(path.join(ROOT, 'oauth-oidc', name), 'utf8')
      .replace(/\s+/g, ' ');
    const pattern = new RegExp("(oauthError\\(\\s*res,\\s*[^,]{1,40},\\s*|" +
      "refuse\\('STS-[A-Z]+-[0-9]+',\\s*|" +
      "apiError\\(res,\\s*scheme,\\s*[0-9]+,\\s*)'([a-z_]+)'", 'g');
    let found = pattern.exec(text);
    while (found) {
      sent.add(found[2]);
      found = pattern.exec(text);
    }
  });
  const undeclared = Array.from(sent).filter(function (code) {
    return OAuthModel.unknownError(code);
  });
  t.check(sent.size > 10 && undeclared.length === 0,
          'C. every error code oauth-oidc/ sends through a funnel is ' +
          'declared (' + sent.size + ')', undeclared.join(', '));
  log.debug("Leaving issued().");
}

// The child's whole program for D, serialised with toString() and run by
// `node -e` — exempt from the Entering/Leaving rule (root CLAUDE.md, Code
// style), and it carries its errors on the result it writes.
function childMain() {
  const ROOT = process.env.MO_ROOT;
  const OUT = process.env.MO_OUT;
  const http = require('http');
  const result = { documents: 0, problems: [], errors: [] };
  function get(port, p) {
    return new Promise(function (resolve) {
      http.get({ host: '127.0.0.1', port: port, path: p }, function (res) {
        let text = '';
        res.on('data', function (c) {
          text += c;
        });
        res.on('end', function () {
          try {
            resolve(JSON.parse(text));
          } catch (e) {
            resolve(null);
          }
        });
      });
    });
  }
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const OAuthModel = require(ROOT + '/oauth-oidc/oauth_model');
    config.setOverride('realms.maxCount', 100);
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const source = require('fs').readFileSync(ROOT + '/common/config.js',
                                              'utf8');
    const switches = [];
    const pattern = /key: '(oauth2\.[A-Za-z0-9]+)'[^}]*?type: 'bool'/g;
    let found = pattern.exec(source);
    while (found) {
      switches.push(found[1]);
      found = pattern.exec(source);
    }
    // The switches a realm may carry, each tried alone.
    const realmSwitches = switches.filter(function (key, i) {
      const overrides = {};
      overrides[key] = true;
      const made = realms.create({ id: 'mo-try-' + i, name: 'mo-try-' + i,
                                   overrides: overrides });
      if (made.ok) {
        realms.remove('mo-try-' + i);
      }
      return made.ok;
    });
    const profiles = ['off', '1-baseline', '1-advanced', '2-security',
                      '2-message-signing'];
    const prefixes = [''];
    profiles.forEach(function (profile, i) {
      const overrides = { 'oauth2.fapi': profile };
      realmSwitches.forEach(function (key) {
        overrides[key] = true;
      });
      const made = realms.create({ id: 'mo-' + i, name: 'mo-' + i,
                                   overrides: overrides });
      if (made.ok) {
        prefixes.push('/realm/mo-' + i);
      } else {
        result.errors.push(profile + ': ' + JSON.stringify(made.errors));
      }
    });
    switches.forEach(function (key) {
      try {
        config.setOverride(key, 'true');
      } catch (e) {
        result.errors.push(key + ': ' + e.message);
      }
    });
    const SETS = [['/.well-known/oauth-authorization-server',
                   'authorization-server-metadata'],
                  ['/.well-known/openid-configuration',
                   'openid-provider-metadata']];
    for (let i = 0; i < prefixes.length; i++) {
      for (let j = 0; j < SETS.length; j++) {
        const doc = await get(port, prefixes[i] + SETS[j][0]);
        if (!doc) {
          result.errors.push('no document at ' + prefixes[i] + SETS[j][0]);
          continue;
        }
        result.documents += 1;
        OAuthModel.undeclared(SETS[j][1], doc).forEach(function (one) {
          result.problems.push((prefixes[i] || '(default)') + ' ' +
                               SETS[j][0] + ': ' + one);
        });
      }
    }
    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(result));
    process.exit(0);
  })().catch(function (e) {
    result.errors.push(String(e && e.stack));
    require('fs').writeFileSync(OUT, JSON.stringify(result));
    process.exit(0);
  });
}

// D. Both discovery documents with every switch on.
function everySwitch(t) {
  log.debug("Entering everySwitch().");
  const out = path.join(os.tmpdir(), 'model-oauth-' + process.pid + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OAUTH2_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const run = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', MO_ROOT: ROOT, MO_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let result = null;
  try {
    result = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in everySwitch(): " + ((e && e.message) || e));
    result = null;
  }
  if (!t.check(!!result, 'D. the child process reported',
               'exit ' + run.status + ' ' +
               String(run.stderr || '').slice(-600))) {
    log.debug("Leaving everySwitch().");
    return;
  }
  t.check(result.errors.length === 0, 'D. every realm and switch was set',
          result.errors.join('\n'));
  t.check(result.documents >= 12 && result.problems.length === 0,
          'D. both discovery documents, every switch on in each FAPI ' +
          'profile, carry only the model\'s members (' + result.documents +
          ' documents)', result.problems.slice(0, 20).join('\n'));
  log.debug("Leaving everySwitch().");
}

async function run(t) {
  log.debug("Entering run().");
  await buildCheck(t);
  validators(t);
  issued(t);
  everySwitch(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_oauth',
  describe: 'the OAuth 2.0 and OpenID Connect model (#1579): the build\'s ' +
            'refusals, every request validator generated from it, every ' +
            'recorded answer, claim set and error code held to it, and ' +
            'both discovery documents with every switch on',
  run: run
};
