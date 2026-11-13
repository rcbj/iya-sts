// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_saml.js
//
// ---------------------------------------------------------------------------
// THE SAML MODEL, AND WHAT HOLDS BOTH IDENTITY PROVIDERS TO IT (#1579).
//
// `models/saml/saml2.tsp` and `saml11.tsp` state SAML 2.0's and SAML 1.1's
// vocabularies, what this service reads off a request, and the attributes
// and children of every element it writes in the schema's order. This
// holds three things:
//
//   A. the build's check (`models/lib/saml_lib.mjs`'s checkSaml()) passes
//      the generated table and refuses each kind of wrong model, asserted on
//      a copy with one thing broken;
//   B. the vocabularies and orders are the model's: `saml/` writes no SAML
//      URI, QName status code or advertised list of its own, the lists the
//      code branches on are the model's terms, the readers read what the
//      model says, and the writers join their parts in the model's order and
//      refuse a part the model does not name;
//   C. every message and metadata document
//      `tests/saml_model_wire.snapshot.json` recorded is held to its model
//      with nothing to say, and a document out of order is not.
//
// That the builders and readers answer on the wire exactly as the
// hand-written ones did is `tests/saml_model_wire.js`'s.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const url = require('url');

const log = require('bunyan').createLogger({
  name: 'model_saml',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');
const ModelTables = require('../common/model_tables');

// A copy of the generated table, for one thing to be broken in.
function copy() {
  log.debug("Entering copy().");
  log.debug("Leaving copy().");
  return JSON.parse(JSON.stringify(ModelTables.file('saml.json')));
}

// A term of a copy's vocabulary.
function termOf(saml, id, name) {
  log.debug("Entering termOf().");
  log.debug("Leaving termOf().");
  return saml.vocabularies[id].terms.filter(function (one) {
    return one.name === name;
  })[0];
}

// A. The build's refusals.
async function buildCheck(t) {
  log.debug("Entering buildCheck().");
  const lib = await import(url.pathToFileURL(path.join(ROOT, 'models', 'lib',
    'saml_lib.mjs')).href);
  const generated = ModelTables.file('saml.json');
  t.check(lib.checkSaml(generated).length === 0,
          'A. the generated SAML model is clean',
          lib.checkSaml(generated).join('; '));
  const refused = function (what, pattern, change) {
    const broken = copy();
    change(broken);
    const said = lib.checkSaml(broken).join('; ');
    t.check(pattern.test(said), 'A. refused: ' + what, said || '(nothing)');
  };
  refused('a value declared twice in a vocabulary',
    /saml2\.status\.Requester repeats the value/, function (s) {
      termOf(s, 'saml2.status', 'Requester').value =
        termOf(s, 'saml2.status', 'Success').value;
    });
  refused('a term citing nothing', /saml2\.binding\.post cites nothing/,
    function (s) {
      termOf(s, 'saml2.binding', 'post').cite = '';
    });
  refused('a flag on a vocabulary it does not apply to',
    /saml2\.status\.Success carries mfaDemand/, function (s) {
      termOf(s, 'saml2.status', 'Success').mfaDemand = true;
    });
  refused('a term outside its vocabulary\'s prefix',
    /saml2\.binding\.post does not begin with/, function (s) {
      termOf(s, 'saml2.binding', 'post').value = 'urn:example:post';
    });
  refused('an equivalent naming no term of the other vocabulary',
    /password's equivalent nobody is no term/, function (s) {
      termOf(s, 'saml2.authnContext', 'password').equivalent = 'nobody';
    });
  refused('a fixed value the attribute does not accept',
    /saml2\.Assertion@Version is fixed at 2\.0, which it does not accept/,
    function (s) {
      s.messages['saml2.Assertion'].attributes.filter(function (one) {
        return one.xml === 'Version';
      })[0].accepts = ['1.1'];
    });
  refused('an attribute declared twice',
    /saml2\.Response@ID is declared twice/, function (s) {
      const list = s.messages['saml2.Response'].attributes;
      list.push(JSON.parse(JSON.stringify(list[0])));
    });
  refused('a signer\'s element the builder says it writes',
    /saml2\.Response\/Signature is inserted by the signer/, function (s) {
      delete s.messages['saml2.Response'].elements.filter(function (one) {
        return one.xml === 'Signature';
      })[0].written;
    });
  refused('a read on a message nobody reads',
    /saml2\.Response@ID says how it is read/, function (s) {
      s.messages['saml2.Response'].attributes[0].read = true;
    });
  refused('a message citing nothing', /the message saml2\.Status cites/,
    function (s) {
      s.messages['saml2.Status'].cite = '';
    });
  refused('a parameter repeating a wire name',
    /saml11\.browser\.shire has no wire name or repeats one/, function (s) {
      s.params['saml11.browser'].params.filter(function (one) {
        return one.name === 'shire';
      })[0].wire = 'TARGET';
    });
  log.debug("Leaving buildCheck().");
}

// B. The vocabularies, readers and writers are the model's.
function readers(t) {
  log.debug("Entering readers().");
  const SamlModel = require('../saml/saml_model');
  // What the hand-written modules held, which may no longer be written in
  // `saml/`: a SAML URI, a SAML 1.1 QName status code, a Shibboleth
  // protocol or profile URI, and the lists built of them. The browser
  // bundles (`web_*.ts`) are exempt: they require no server module, so the
  // model's reader cannot reach them (saml/CLAUDE.md).
  const HAND = [
    [/'urn:oasis:names:tc:SAML:[0-9.]+:/, 'a SAML URI'],
    [/'samlp:(Success|Requester|Responder|VersionMismatch)'/,
     'a SAML 1.1 status QName'],
    [/'urn:mace:shibboleth:1\.0(:profiles:[A-Za-z]+)?'/,
     'a Shibboleth protocol or profile URI'],
    [/'http:\/\/schemas\.microsoft\.com\/claims\/multipleauthn'/,
     'the multiple-authentication class'],
    [/'urn:ietf:rfc:(1510|2246)'/, 'a SAML 1.1 authentication method'],
    [/asked === 'post' \|\| asked === 'artifact'/,
     'the profile parameter\'s values']
  ];
  fs.readdirSync(path.join(ROOT, 'saml')).filter(function (name) {
    return /\.ts$/.test(name) && name !== 'saml_model.ts' &&
      !/^web_/.test(name);
  }).forEach(function (name) {
    const text = fs.readFileSync(path.join(ROOT, 'saml', name), 'utf8')
      .replace(/^\s*\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
    HAND.forEach(function (pair) {
      t.check(!pair[0].test(text), 'B. saml/' + name + ' writes no ' +
              pair[1] + ' of its own');
    });
  });

  const saml2Sso = require('../saml/saml2_sso');
  const saml11 = require('../saml/saml11');
  const authnContext = require('../saml/authn_context');
  t.check(saml2Sso.NAMEID_FORMATS.join() ===
          SamlModel.terms('saml2.nameIdFormat', 'advertised').join(),
          'B. the SAML 2.0 NameID formats advertised are the model\'s',
          saml2Sso.NAMEID_FORMATS.join());
  t.check(SamlModel.terms('saml2.binding', 'response').join() === [
    SamlModel.term('saml2.binding', 'redirect'),
    SamlModel.term('saml2.binding', 'post'),
    SamlModel.term('saml2.binding', 'simpleSign'),
    SamlModel.term('saml2.binding', 'artifact')].join(),
  'B. a Response is delivered on the four bindings the model marks');
  t.check(SamlModel.terms('saml2.binding', 'request')
    .indexOf(SamlModel.term('saml2.binding', 'artifact')) < 0,
  'B. no AuthnRequest arrives on HTTP-Artifact (#191)');
  t.check(SamlModel.accepts('saml2.AuthnRequest', 'version').join() === '2.0',
          'B. an AuthnRequest is held to Version 2.0');
  t.check(saml11.CONFIRMATION_ARTIFACT ===
          SamlModel.term('saml11.confirmation', 'artifact') &&
          saml11.NAMEID_FORMAT_UNSPECIFIED ===
          SamlModel.term('saml11.nameIdFormat', 'unspecified'),
          'B. SAML 1.1\'s confirmation methods and format are the model\'s');
  t.check(authnContext.AM_KERBEROS === 'urn:ietf:rfc:1510' &&
          authnContext.AC_MULTIFACTOR ===
          SamlModel.term('saml2.authnContext', 'multipleAuthn'),
          'B. the authentication contexts are the model\'s terms');

  const xmldom = require('../common/xml_parser');
  const parse = function (xml) {
    return new xmldom.DOMParser().parseFromString(xml, 'text/xml')
      .documentElement;
  };
  const read = SamlModel.read('saml2.AuthnRequest', parse(
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
    ' ID="_a" Version="2.0" IssueInstant="x" ForceAuthn="true"' +
    ' IsPassive="false" ProviderName="p" AssertionConsumerServiceIndex="3"/>'
  ));
  t.check(read.id === '_a' && read.version === '2.0' &&
          read.forceAuthn === true && read.isPassive === false &&
          read.acsIndex === '3' && read.acsUrl === '' &&
          read.destination === '' && !('providerName' in read),
          'B. an AuthnRequest\'s attributes are read as the model says, ' +
          'and only those it marks read', JSON.stringify(read));
  // XML Schema Part 2 section 3.2.2 (rcbj on #1579): `1` is true and `0`
  // false, after the whitespace is collapsed. Until 2026-11-11 `1` was false.
  const ones = SamlModel.read('saml2.AuthnRequest', parse(
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
    ' ID="_b" Version="2.0" IssueInstant="x" ForceAuthn="1"' +
    ' IsPassive=" 1 "/>'));
  const zeros = SamlModel.read('saml2.AuthnRequest', parse(
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
    ' ID="_c" Version="2.0" IssueInstant="x" ForceAuthn="0"' +
    ' IsPassive="yes"/>'));
  t.check(ones.forceAuthn === true && ones.isPassive === true &&
          zeros.forceAuthn === false && zeros.isPassive === false,
          'B. an xs:boolean is true for "1" as for "true", and false for ' +
          '"0" and for text outside its lexical space',
          JSON.stringify([ones, zeros]));
  t.check(SamlModel.children('saml2.Assertion', {
    attributeStatement: 'C', subject: 'B', issuer: 'A' }) === 'ABC',
  'B. a builder\'s parts are joined in the model\'s order');
  t.check(SamlModel.attributes('saml2.Response', {
    inResponseTo: '_r', id: '_i', issueInstant: 't', destination: '' }) ===
    ' ID="_i" Version="2.0" IssueInstant="t" InResponseTo="_r"',
  'B. a start tag\'s attributes in the model\'s order, the fixed Version ' +
  'always, an empty one omitted');
  let threw = '';
  try {
    SamlModel.children('saml2.Response', { signature: '<x/>' });
  } catch (e) {
    threw = String(e && e.message);
  }
  t.check(/no child signature its builder writes/.test(threw),
          'B. a builder writing what the model says the signer inserts is ' +
          'refused', threw);
  threw = '';
  try {
    SamlModel.attributes('saml2.Response', { colour: 'red' });
  } catch (e) {
    threw = String(e && e.message);
  }
  t.check(/no attribute colour/.test(threw),
          'B. an attribute the model does not declare is refused', threw);
  // SAML 1.1's request is Shibboleth's: the shire's registered binding picks
  // the profile and the relying party's setting the format, so the non-spec
  // `profile` and `format` parameters that once chose them are not declared.
  ['profile', 'format'].forEach(function (name) {
    threw = '';
    try {
      SamlModel.param('saml11.browser', name);
    } catch (e) {
      threw = String(e && e.message);
    }
    t.check(/has no /.test(threw),
            'B. saml11.browser declares no ' + name + ' parameter', threw);
  });
  log.debug("Leaving readers().");
}

// A recorded document with its placeholders made into well-formed text.
function restored(xml) {
  log.debug("Entering restored().");
  log.debug("Leaving restored().");
  return String(xml).replace(/<(id\d+|time|opaque|chain|port|nameid|value|hex|random|uuid|epoch|cookie|handle|incident|digest)>/g,
                             'PH');
}

// C. Every recorded document is the model's.
function answered(t) {
  log.debug("Entering answered().");
  const SamlModel = require('../saml/saml_model');
  const xmldom = require('../common/xml_parser');
  const wire = require('./saml_model_wire');
  const recorded = JSON.parse(fs.readFileSync(wire.SNAPSHOT, 'utf8'));
  const written = {};
  ['saml2.Response', 'saml2.ArtifactResponse', 'saml2.LogoutRequest',
   'saml2.LogoutResponse', 'md.EntityDescriptor', 'saml11.Response']
    .forEach(function (id) {
      const message = SamlModel.message(id);
      written[message.xmlns + ' ' + message.element] = id;
    });
  const counted = {};
  const problems = [];
  wire.messages(recorded).forEach(function (one) {
    let root = null;
    try {
      root = new xmldom.DOMParser().parseFromString(restored(one.xml),
                                                    'text/xml')
        .documentElement;
    } catch (e) {
      // Not a document (a page's text that looked like markup): not one of
      // the messages this holds.
      log.debug("Caught in answered(): " + ((e && e.message) || e));
      root = null;
    }
    // A SOAP answer: the message is the Body's child.
    if (root && root.localName === 'Envelope') {
      const body = root.getElementsByTagNameNS('*', 'Body')[0];
      root = null;
      for (let c = body ? body.firstChild : null; c; c = c.nextSibling) {
        if (c.nodeType === 1) {
          root = c;
          break;
        }
      }
    }
    const id = root ? written[root.namespaceURI + ' ' + root.localName] : '';
    if (!id) {
      return;
    }
    counted[id] = (counted[id] || 0) + 1;
    SamlModel.problemsOf(id, root, root.localName).forEach(function (p) {
      problems.push(one.step + ': ' + p);
    });
  });
  Object.keys(written).forEach(function (key) {
    const id = written[key];
    t.check(counted[id] > 0, 'C. the record holds ' + id + ' documents (' +
            (counted[id] || 0) + ')');
  });
  t.check(problems.length === 0,
          'C. every recorded message and metadata document is the model\'s',
          problems.slice(0, 10).join('\n'));
  // And a document out of the model's order is not.
  const reordered =
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_x" ' +
    'Version="2.0" IssueInstant="t"><samlp:Status><samlp:StatusCode ' +
    'Value="v"/></samlp:Status><saml:Issuer>i</saml:Issuer>' +
    '</samlp:Response>';
  t.check(SamlModel.problems('saml2.Response', reordered).join(' ')
    .indexOf('out of the schema\'s order') >= 0,
  'C. a Response with its Issuer after its Status is held as out of order',
  SamlModel.problems('saml2.Response', reordered).join('; '));
  t.check(SamlModel.problems('saml2.Response',
    reordered.replace('Version="2.0"', 'Version="1.0"')).join(' ')
    .indexOf('not its fixed') >= 0,
  'C. a Response of another Version is held as not its fixed value');
  log.debug("Leaving answered().");
}

async function run(t) {
  log.debug("Entering run().");
  await buildCheck(t);
  readers(t);
  answered(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_saml',
  describe: 'the SAML model (#1579): the build\'s refusals, every SAML URI ' +
            'and list in saml/ the model\'s, the AuthnRequest read and every ' +
            'message written in its order, and every recorded message and ' +
            'metadata document held to it',
  run: run
};
