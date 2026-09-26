'use strict';
//
// File: closed_setting_values.js
//
// ===========================================================================
// THE SETTINGS WHOSE VALUES COME FROM A CLOSED SET (#86, 2026-09-26).
//
// Every write of a setting — /admin/config, POST /admin-api/config/set, a
// realm override — runs `TYPES[type].check()` in `common/config.js`. An
// `enum` row was always held to its `enumValues`; a `string` row and a `csv`
// row were held to nothing, so twenty-seven settings whose reader FILTERS by
// a constant of its own module saved any typo, and the reader then dropped
// it, fell back past it or failed on it at its next use. #86 made six of
// those rows `enum` and gave the other twenty-one `csvValues`.
//
// config.js is a leaf and requires nothing from the repository, so each set
// is WRITTEN OUT there, beside a comment naming the constant it mirrors. A
// copy drifts, and the drift is silent in the worst direction: a value the
// module gained is refused on Save with nobody knowing why. So this file
// holds, for every one of those rows:
//
//   A. the list in config.js EQUALS the module's own set — read from the
//      module, never written out a second time here;
//   B. the row's default passes its own check, and so does every value of
//      the set (an enum's one by one, a list's all together);
//   C. a value outside the set is refused — for a list, one bad entry among
//      good ones, and the refusal names that entry;
//   D. `describe()` carries `csvValues`, which is what the management API's
//      Setting schema documents and a client draws choices from; and a `csv`
//      row with no `csvValues` is still an open list.
//
// Two of the readers keep their set INSIDE A FUNCTION rather than in a
// constant — `federation_sp.ts`'s familyAlgorithms() and `oidfed.ts`'s
// registrationTypes() — so for those A asks the function: with the declared
// list in force, it must hand every entry back. That catches a declared
// value the reader would drop; a value the reader gained and the list did
// not is caught by nothing short of reading the source, which the service
// image does not carry.
//
// WHY THE MODULES ARE READ IN A CHILD: most of them are route modules and
// their libraries, and a stack loaded into the runner is shared with every
// file after this one — `realm_support.js`'s arrangement. config.js itself
// is a leaf and is read here directly; nothing below writes to it.
// ===========================================================================

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');
const log = require('bunyan').createLogger({ name: 'closed_setting_values',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
// CONFIG_FILE is DELETED before config.js is required, as every in-process
// file that reads settings does (`account_disable.js`, `config_realm_layer.js`):
// the runner's image names env/local.js, and a module cached with that layer
// would be handed to every later file — `config_realm_layer.js` asserts the
// shipped defaults and fails on it. The CHILDREN below build their own
// environment and set CONFIG_FILE where a case needs one.
delete process.env.CONFIG_FILE;
const config = require(path.join(ROOT, 'common', 'config'));

// The six rows #86 turned from `string` into `enum`.
const ENUM_ROWS = ['oauth2.eddsaCurve', 'pki.keyAlgorithm',
                   'pki.signatureAlgorithm', 'ssf.signingAlgorithm',
                   'caep.defaultRiskLevel', 'risc.subjectFormat'];

// The twenty-one `csv` rows it gave `csvValues`.
const CSV_ROWS = ['gnap.tokenFormats', 'gnap.interactionStartModes',
                  'gnap.finishMethods', 'gnap.keyProofs',
                  'gnap.subIdFormats', 'gnap.assertionFormats',
                  'authn.passwordAloneDoors', 'webauthn.algorithms',
                  'acme.allowedProfiles', 'est.allowedProfiles',
                  'scep.allowedProfiles', 'federation.jwtAlgorithms',
                  'tls.certificateAlgorithms',
                  'oid4vci.requestEncryptionEncValues',
                  'oid4vci.responseEncryptionEncValues',
                  'oidfed.clientRegistrationTypes', 'oid4vp.signInFormats',
                  'krb5.enctypes', 'ssf.deliveryMethods',
                  'caep.autoEmitTypes', 'risc.autoEmitTypes'];

// A value no set here holds. Upper and lower case and a digit, so that no
// case-folding reader could mistake it for one of its own.
const OUTSIDER = 'No-Such-Value-86';

// ---------------------------------------------------------------------------
// The child. Everything it needs is required inside, so the function can be
// shipped as source with `node -e`. It reports each module's set under the
// setting's key, or the error reading it raised; every judgement is made in
// the parent, where it is reported.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const fs = require('fs');
  const ROOT_DIR = process.env.CSV_ROOT;
  const OUT = process.env.CSV_OUT;
  const DECLARED = JSON.parse(process.env.CSV_DECLARED || '{}');
  const report = { error: null, sets: {} };
  function rq(rel) {
    return require(ROOT_DIR + '/' + rel);
  }
  function probe(key, fn) {
    try {
      report.sets[key] = { ok: true, value: fn() };
    } catch (e) {
      // Carried on the report: the parent names the row it broke.
      report.sets[key] = { ok: false,
                           error: String((e && e.stack) || e).slice(0, 600) };
    }
  }
  function values(obj) {
    return Object.keys(obj).map(function (k) {
      return obj[k];
    });
  }
  // A reader that keeps its set in a function: put the declared list in
  // force, ask, and put it back.
  function withDeclared(config, key, fn) {
    const set = config.setOverride(key, DECLARED[key].join(','));
    if (set && set.ok === false) {
      throw new Error('the declared list was refused: ' +
                      JSON.stringify(set.errors));
    }
    try {
      return fn();
    } finally {
      config.clearOverride(key);
    }
  }
  try {
    const config = rq('common/config');
    const stsCrypto = rq('common/crypto');
    probe('oauth2.eddsaCurve', function () {
      const keys = rq('common/helpers').stsKeysFor();
      return (keys.extraKeys || []).filter(function (k) {
        return k.alg === 'EdDSA';
      }).map(function (k) {
        return k.publicJwk.crv;
      });
    });
    probe('pki.keyAlgorithm', function () {
      return rq('common/vendored/key_material').keyAlgIds();
    });
    probe('pki.signatureAlgorithm', function () {
      const x509 = rq('common/vendored/x509');
      return [''].concat(Object.keys(x509.SIG_ALGS).filter(function (id) {
        return !!x509.sigAlg(id);
      }));
    });
    probe('ssf.signingAlgorithm', function () {
      return stsCrypto.JWS_ASYMMETRIC_ALGS.slice();
    });
    probe('caep.defaultRiskLevel', function () {
      const events = rq('ssf/ssf_events');
      const event = events.CAEP_EVENTS.filter(function (e) {
        return e.uri === events.CAEP_PREFIX + 'risk-level-change';
      })[0];
      return event.members.filter(function (m) {
        return m.name === 'current_level';
      })[0].values;
    });
    probe('risc.subjectFormat', function () {
      return rq('ssf/ssf_subjects').PERSON_FORMATS.slice();
    });
    probe('gnap.tokenFormats', function () {
      return rq('gnap/gnap_tokens').FORMATS.slice();
    });
    probe('gnap.interactionStartModes', function () {
      return rq('gnap/gnap_request').START_MODES.slice();
    });
    probe('gnap.finishMethods', function () {
      return rq('gnap/gnap_request').FINISH_METHODS.slice();
    });
    probe('gnap.keyProofs', function () {
      return rq('gnap/gnap_keys').PROOF_METHODS.slice();
    });
    probe('gnap.subIdFormats', function () {
      return rq('gnap/gnap_subject').SUB_ID_FORMATS_SUPPORTED.slice();
    });
    probe('gnap.assertionFormats', function () {
      return rq('gnap/gnap_subject').ASSERTION_FORMATS_SUPPORTED.slice();
    });
    probe('authn.passwordAloneDoors', function () {
      return rq('common/app_passwords').DOOR_IDS.slice();
    });
    probe('webauthn.algorithms', function () {
      return Object.keys(rq('authn/webauthn_policy').ALG_IDS);
    });
    ['acme', 'est', 'scep'].forEach(function (family) {
      probe(family + '.allowedProfiles', function () {
        return rq('common/cert_enrollment').PROFILE_IDS.slice();
      });
    });
    probe('federation.jwtAlgorithms', function () {
      const fedSp = rq('federation/federation_sp');
      return withDeclared(config, 'federation.jwtAlgorithms', function () {
        return fedSp.familyAlgorithms('RSA')
          .concat(fedSp.familyAlgorithms('EC'));
      });
    });
    probe('tls.certificateAlgorithms', function () {
      // tls_server.js builds `rsa` itself and every ML_DSA_OIDS key through
      // makeMlDsaServerCertificate(); anything else it warns about and skips.
      // Read from crypto.js rather than by requiring tls_server.js, which is
      // a JavaScript route module that issues certificates at load.
      return ['rsa'].concat(Object.keys(stsCrypto.ML_DSA_OIDS));
    });
    ['oid4vci.requestEncryptionEncValues',
     'oid4vci.responseEncryptionEncValues'].forEach(function (key) {
      probe(key, function () {
        return rq('oid4vc/vc_issuer').VcIssuer.IMPLEMENTED_ENC_VALUES.slice();
      });
    });
    probe('oidfed.clientRegistrationTypes', function () {
      const oidfed = rq('oidfed/oidfed');
      return withDeclared(config, 'oidfed.clientRegistrationTypes',
        function () {
          return oidfed.registrationTypes();
        });
    });
    probe('oid4vp.signInFormats', function () {
      const verifier = rq('oid4vc/vc_verifier');
      // Asked for nothing it knows, it answers its whole SIGN_IN_FORMATS.
      const all = verifier.signInFormats(['no-such-format-86']);
      // And the reader's second spelling: a `+` a form decoded to a space.
      const spaced = all.filter(function (f) {
        return f.indexOf('+') >= 0;
      }).map(function (f) {
        return f.replace(/\+/g, ' ');
      });
      const back = verifier.signInFormats(spaced);
      if (spaced.length && back.join(',') !== spaced.map(function (f) {
        return f.replace(/ /g, '+');
      }).join(',')) {
        throw new Error('signInFormats() no longer reads "' +
                        spaced.join(', ') + '" as its + spelling');
      }
      return all.concat(spaced);
    });
    probe('krb5.enctypes', function () {
      return Object.keys(rq('kerberos/krb5_crypto').ETYPES);
    });
    probe('ssf.deliveryMethods', function () {
      const streams = rq('ssf/ssf_streams');
      return streams.DELIVERY_METHODS.map(function (row) {
        return row.method;
      }).concat(['push', 'poll']);
    });
    probe('caep.autoEmitTypes', function () {
      const events = rq('ssf/ssf_events');
      const short = values(rq('ssf/caep').AUTO_ACTS);
      return short.concat(short.map(function (name) {
        return events.CAEP_PREFIX + name;
      }));
    });
    probe('risc.autoEmitTypes', function () {
      const events = rq('ssf/ssf_events');
      const short = values(rq('ssf/risc').AUTO_ACTS);
      return short.concat(short.map(function (name) {
        return events.RISC_PREFIX + name;
      }));
    });
  } catch (e) {
    // Carried on the report: the parent says what went wrong.
    report.error = String((e && e.stack) || e);
  }
  fs.writeFileSync(OUT, JSON.stringify(report));
  process.exit(0);
}

// The set a row declares, whichever kind of row it is.
function declaredOf(row) {
  log.debug("Entering declaredOf().");
  log.debug("Leaving declaredOf().");
  return (row && (row.type === 'enum' ? row.enumValues : row.csvValues)) ||
         null;
}

function rowOf(key) {
  log.debug("Entering rowOf(). key=" + key);
  log.debug("Leaving rowOf().");
  return config.SETTINGS.filter(function (row) {
    return row.key === key;
  })[0] || null;
}

// Two lists as one comparable string. ORDER IS NOT COMPARED: several readers
// build their set from an object's keys, and the declared list is written in
// the order a person reads best. A duplicate is kept, so a list naming one
// value twice does not equal one naming it once.
function asSet(list) {
  log.debug("Entering asSet().");
  log.debug("Leaving asSet().");
  return (list || []).map(String).sort().join(' | ');
}

function loadSets() {
  log.debug("Entering loadSets().");
  const out = path.join(os.tmpdir(), 'csv-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const declared = {};
  CSV_ROWS.forEach(function (key) {
    declared[key] = declaredOf(rowOf(key)) || [];
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  CSV_ROOT: ROOT, CSV_OUT: out,
                                  CSV_DECLARED: JSON.stringify(declared) }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in loadSets(): " + ((e && e.message) || e));
    // No report: the child died before writing one; the caller says so.
    report = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in loadSets(): " + ((e && e.message) || e));
  }
  log.debug("Leaving loadSets().");
  return { report: report, result: result };
}

// B, C and D for one row: config.js alone, no module needed.
function checkRow(t, key) {
  log.debug("Entering checkRow(). key=" + key);
  const row = rowOf(key);
  const isEnum = ENUM_ROWS.indexOf(key) >= 0;
  if (!t.check(!!row && row.type === (isEnum ? 'enum' : 'csv') &&
               Array.isArray(declaredOf(row)) &&
               declaredOf(row).length > 0,
               key + ' is ' + (isEnum ? 'an enum' : 'a csv row with ' +
                               'csvValues'),
               row ? 'type ' + row.type : 'no such row')) {
    log.debug("Leaving checkRow(). No set to check.");
    return;
  }
  const set = declaredOf(row);

  // B. The default, and every value of the set. parseAs() runs the same
  // TYPES check every write does, and answers "no value" for an empty one,
  // which for pki.signatureAlgorithm's '' is asked of the set directly.
  const dflt = typeof row.dflt === 'function' ? row.dflt() : row.dflt;
  const dfltText = Array.isArray(dflt) ? dflt.join(',') : String(dflt);
  if (dfltText.trim() === '') {
    t.check(!isEnum || set.indexOf('') >= 0,
            key + '\'s empty default is a member of its set',
            'an enum row whose default it refuses could not be reset');
  } else {
    const parsed = config.parseAs(key, dfltText);
    t.check(parsed.ok === true, key + '\'s default passes its own check',
            parsed.problem || dfltText);
  }
  const good = isEnum ? set.filter(function (v) {
    return v !== '';
  }) : [set.join(',')];
  const refusedGood = good.filter(function (v) {
    return config.parseAs(key, v).ok !== true;
  });
  t.equal(refusedGood.join(', '), '',
          key + ' accepts every value of its set');

  // C. One value outside: alone for an enum, among good ones for a list,
  // and the refusal names it.
  const bad = isEnum ? OUTSIDER : set[0] + ',' + OUTSIDER + ',' +
                                  set[set.length - 1];
  const refused = config.parseAs(key, bad);
  t.check(refused.ok === false &&
          String(refused.problem).indexOf('"' + OUTSIDER + '"') >= 0 &&
          String(refused.problem).indexOf('must be one of') >= 0,
          key + ' refuses a value outside its set, naming it',
          refused.problem || 'accepted: ' + bad);
  if (!isEnum) {
    // As an ARRAY too — the appconfig file's shape, which check() is handed
    // unsplit.
    const arr = config.parseAs(key, [set[0], ' ' + OUTSIDER + ' ']);
    t.check(arr.ok === false, key + ' refuses the same entry in an array',
            arr.problem || 'accepted');
    // D. describe() says which entries it takes.
    t.equal(asSet(config.describe(row).csvValues), asSet(set),
            key + '\'s csvValues are on describe()');
  }
  log.debug("Leaving checkRow().");
}

// ---------------------------------------------------------------------------
// E. THE APPCONFIG FILE AND THE ENVIRONMENT FOLLOW THE SAME RULES (#86).
//
// `config.js`'s `refuseMalformedSettings()` runs when the module loads, so
// each case is a CHILD that loads it: with a value in the environment, in the
// appconfig file, or in both with the bad one SHADOWED by a good one above
// it. The environment is the child's own; this process's is never changed.
// A good file and an empty environment must start, or every refusal below
// would be the same failure for a different reason.
// ---------------------------------------------------------------------------
function startWith(env, fileBody) {
  log.debug("Entering startWith().");
  let file = null;
  if (fileBody !== null) {
    file = path.join(os.tmpdir(), 'csv86-' + process.pid + '-' +
                     require('crypto').randomBytes(6).toString('hex') + '.js');
    fs.writeFileSync(file, 'module.exports = ' + JSON.stringify(fileBody) +
                           ';\n');
  }
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const childEnv = Object.assign(clean, { LOG_LEVEL: 'fatal',
                                          STS_LOG_LEVEL: 'fatal' }, env);
  if (file) {
    childEnv.CONFIG_FILE = file;
  }
  const result = childProcess.spawnSync(process.execPath,
    ['-e', 'require(' + JSON.stringify(path.join(ROOT, 'common', 'config')) +
           ')'], { env: childEnv, encoding: 'utf8', timeout: 60000,
                   cwd: ROOT });
  if (file) {
    try {
      fs.unlinkSync(file);
    } catch (e) {
      // Already gone; nothing else wrote it.
      log.debug("Caught in startWith(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving startWith(). exit " + result.status);
  return { status: result.status, stderr: String(result.stderr || '') };
}

function appconfigRules(t) {
  log.debug("Entering appconfigRules().");
  t.log.info('=== E. the appconfig file and the environment are held to ' +
             'the same rules ===');
  const good = startWith({}, null);
  t.check(good.status === 0, 'a start with nothing set passes the check',
          good.stderr.slice(-600));
  const envBad = startWith({ STS_PKI_KEY_ALGORITHM: 'RSA-2048' }, null);
  t.check(envBad.status === 1 && /STS-CORE-0108/.test(envBad.stderr) &&
          /STS_PKI_KEY_ALGORITHM \(in the environment\)/.test(envBad.stderr) &&
          /pki\.keyAlgorithm/.test(envBad.stderr),
          'an enum value outside its set in the ENVIRONMENT stops the start, ' +
          'by name', envBad.stderr.slice(-600));
  const fileBad = startWith({}, { webauthn: { algorithms: 'ES256,NOSUCHALG' } });
  t.check(fileBad.status === 1 && /STS-CORE-0108/.test(fileBad.stderr) &&
          /webauthn\.algorithms \(in /.test(fileBad.stderr) &&
          /NOSUCHALG/.test(fileBad.stderr),
          'a list entry outside csvValues in the APPCONFIG FILE stops the ' +
          'start, by name', fileBad.stderr.slice(-600));
  const bounds = startWith({}, { totp: { window: -5 } });
  t.check(bounds.status === 1 && /totp\.window/.test(bounds.stderr),
          'and so does a number outside its bounds — the write\'s whole ' +
          'check, not only the closed sets', bounds.stderr.slice(-600));
  const shadowed = startWith({ STS_OAUTH2_EDDSA_CURVE: 'Ed25519' },
                             { oauth2: { eddsaCurve: 'Ed999' } });
  t.check(shadowed.status === 1 && /Ed999/.test(shadowed.stderr) &&
          !/STS_OAUTH2_EDDSA_CURVE \(in the environment\)/
            .test(shadowed.stderr),
          'a bad value SHADOWED by a good environment variable still stops ' +
          'the start, and the good one is not named',
          shadowed.stderr.slice(-600));
  const fine = startWith({ STS_OAUTH2_EDDSA_CURVE: 'Ed448' },
                         { webauthn: { algorithms: 'ES256,EdDSA' } });
  t.check(fine.status === 0, 'values inside their sets, in both layers, ' +
          'start', fine.stderr.slice(-600));
  log.debug("Leaving appconfigRules().");
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== B-D. each row is checked against its own set ===');
  ENUM_ROWS.concat(CSV_ROWS).forEach(function (key) {
    checkRow(t, key);
  });

  t.log.info('=== D. a csv row with no csvValues is still an open list ===');
  const open = config.SETTINGS.filter(function (row) {
    return row.type === 'csv' && !row.csvValues;
  })[0];
  if (t.check(!!open, 'there is an open csv row to ask', 'none left')) {
    t.check(config.parseAs(open.key, OUTSIDER + ',x').ok === true,
            open.key + ' (no csvValues) takes any entry, as before');
    t.check(config.describe(open).csvValues === undefined,
            'and describe() carries no csvValues for it');
  }

  t.log.info('=== A. every declared set equals the module it mirrors ===');
  const loaded = loadSets();
  const report = loaded.report;
  if (!t.check(!!report && !report.error && !!report.sets,
               'the child read the modules\' sets',
               report && report.error ? report.error.slice(0, 800) :
               'exit ' + loaded.result.status + ' ' +
               String(loaded.result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    // Every assertion below compares against the child's report.
    return;
  }
  ENUM_ROWS.concat(CSV_ROWS).forEach(function (key) {
    const got = report.sets[key];
    if (!t.check(!!got && got.ok === true, 'the child read ' + key + '\'s ' +
                 'module set', got ? got.error : 'not reported')) {
      return;
    }
    t.equal(asSet(declaredOf(rowOf(key))), asSet(got.value),
            key + ': the list written out in config.js is the module\'s ' +
            'own set');
  });
  appconfigRules(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'closed_setting_values',
  describe: 'the settings whose reader filters by a closed set are held to ' +
            'that set on every write, config.js\'s copy of each set equals ' +
            'the module constant it mirrors, and a value in the appconfig ' +
            'file or the environment is held to the same check at start',
  run: run
};
