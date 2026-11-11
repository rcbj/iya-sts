// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_ws.js
//
// ---------------------------------------------------------------------------
// THE SOAP, WS-TRUST AND WS-FEDERATION MODEL, AND WHAT HOLDS `/sts` AND
// `/wsfed` TO IT (#1579).
//
// `models/ws/soap.tsp`, `wstrust.tsp` and `wsfed.tsp` state both SOAP
// versions' envelopes and faults, WS-Trust's namespaces, request types,
// actions, key types, token types and section 11 fault codes, the RST as it
// is read and every RSTR part in the order it is written, and
// WS-Federation's parameters, actions, `wauth` values, claim types, sign-in
// response and metadata role. This holds three things:
//
//   A. the build's check (`models/lib/saml_lib.mjs`'s checkSaml(), the one
//      SAML's model passes) passes the generated `ws.json` and refuses each
//      kind of wrong model the WS families added — a message with no
//      namespace or two, a `namespaces` naming no vocabulary, an `aliasOf`
//      naming no term, a relative term not beginning with '/', a property
//      reference to no vocabulary, two children of one local name in one
//      namespace — and no XML id is outside a family;
//   B. the vocabularies and lists are the model's: `ws-trust/` and
//      `ws-federation/` write no namespace, token type, key type or wauth URI
//      of their own, the SAML terms WS-Federation names are SAML's own
//      (written once, as properties), the RST's credential-free and
//      signed-Body lists are the model's, and the writers join their parts
//      in the model's order;
//   C. every envelope, sign-in response and metadata role
//      `tests/ws_model_wire.snapshot.json` recorded is held to its model with
//      nothing to say — the SAML assertions inside held to SAML's — and a
//      document out of order is not.
//
// That the builders answer on the wire exactly as the hand-written ones did
// is `tests/ws_model_wire.js`'s.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const url = require('url');

const log = require('bunyan').createLogger({
  name: 'model_ws',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');
const ModelTables = require('../common/model_tables');

// A copy of the generated table, for one thing to be broken in.
function copy() {
  log.debug("Entering copy().");
  log.debug("Leaving copy().");
  return JSON.parse(JSON.stringify(ModelTables.file('ws.json')));
}

// A term of a copy's vocabulary.
function termOf(ws, id, name) {
  log.debug("Entering termOf().");
  log.debug("Leaving termOf().");
  return ws.vocabularies[id].terms.filter(function (one) {
    return one.name === name;
  })[0];
}

// A. The build's refusals.
async function buildCheck(t) {
  log.debug("Entering buildCheck().");
  const lib = await import(url.pathToFileURL(path.join(ROOT, 'models', 'lib',
    'saml_lib.mjs')).href);
  const generated = ModelTables.file('ws.json');
  t.check(lib.checkSaml(generated).length === 0,
          'A. the generated WS-Trust and WS-Federation model is clean',
          lib.checkSaml(generated).join('; '));
  t.check(Object.keys(generated.messages).every(function (id) {
    return lib.FAMILIES.ws.some(function (prefix) {
      return id.indexOf(prefix) === 0;
    });
  }) && !Object.keys(ModelTables.file('saml.json').messages)
    .some(function (id) {
      return id in generated.messages;
    }),
  'A. ws.json holds the WS families\' ids and none of SAML\'s');
  const refused = function (what, pattern, change) {
    const broken = copy();
    change(broken);
    const said = lib.checkSaml(broken).join('; ');
    t.check(pattern.test(said), 'A. refused: ' + what, said || '(nothing)');
  };
  refused('a message with both xmlns and namespaces',
    /wst\.Status names its namespace by xmlns or by namespaces/,
    function (w) {
      w.messages['wst.Status'].xmlns = 'urn:x';
    });
  refused('a message with neither',
    /soap12\.Fault names its namespace by xmlns or by namespaces/,
    function (w) {
      delete w.messages['soap12.Fault'].xmlns;
    });
  refused('namespaces naming no vocabulary',
    /wst\.Status's namespaces wst\.nowhere is no vocabulary/, function (w) {
      w.messages['wst.Status'].namespaces = 'wst.nowhere';
    });
  refused('an aliasOf naming no term',
    /saml11Namespace's aliasOf saml3 is no other term/, function (w) {
      termOf(w, 'wst.tokenType', 'saml11Namespace').aliasOf = 'saml3';
    });
  refused('a relative term not beginning with /',
    /wst\.keyType\.bearer is appended to a namespace and does not begin/,
    function (w) {
      termOf(w, 'wst.keyType', 'bearer').value = 'Bearer';
    });
  refused('a property reference to no vocabulary',
    /wsfed\.wauth\.saml11Password is another property, of no vocabulary/,
    function (w) {
      termOf(w, 'wsfed.wauth', 'saml11Password').same = '?.password';
    });
  refused('two children of one local name in one namespace',
    /wst\.RequestedSecurityToken\/Assertion is declared twice/,
    function (w) {
      w.messages['wst.RequestedSecurityToken'].elements[1].xmlns =
        w.messages['wst.RequestedSecurityToken'].elements[0].xmlns;
    });
  refused('a flag on a vocabulary it does not apply to',
    /wst\.fault\.InvalidRequest carries wauth/, function (w) {
      termOf(w, 'wst.fault', 'InvalidRequest').wauth = 'password';
    });
  refused('a parameter repeating a wire name',
    /wsfed\.passive\.wreply has no wire name or repeats one/, function (w) {
      w.params['wsfed.passive'].params.filter(function (one) {
        return one.name === 'wreply';
      })[0].wire = 'wtrealm';
    });
  log.debug("Leaving buildCheck().");
}

// B. The vocabularies, readers and writers are the model's.
function readers(t) {
  log.debug("Entering readers().");
  const WsModel = require('../ws-trust/ws_model');
  const SamlModel = require('../saml/saml_model');
  // What the hand-written modules held, which may no longer be written in
  // either directory outside the model's reader: a URI in quotes, a token
  // type, a key type, and the lists built of them.
  const HAND = [
    [/'https?:\/\//, 'http(s) URI'],
    [/'urn:(oasis|ietf|iya)/, 'urn: URI'],
    [/'\/(Bearer|Issue|RSTRC?\/|status\/)/,
     'trust-namespace-relative value'],
    [/'soap:(Client|Server|Sender|Receiver)'/, 'SOAP fault code'],
    [/\['OnBehalfOf', 'ActAs'/, 'list of another party\'s elements'],
    [/asked === 'saml11' \|\|/, 'list of the token types\' short forms']
  ];
  [['ws-trust', 'wstrust.ts'], ['ws-federation', 'wsfed.ts']]
    .forEach(function (pair) {
      const text = fs.readFileSync(path.join(ROOT, pair[0], pair[1]), 'utf8')
        .replace(/^\s*\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
      HAND.forEach(function (one) {
        t.check(!one[0].test(text), 'B. ' + pair[0] + '/' + pair[1] +
                ' writes no ' + one[1] + ' of its own',
                (text.match(one[0]) || [''])[0]);
      });
    });

  t.check(WsModel.terms('wsfed.wauth', 'wauth', 'password').join() === [
    SamlModel.term('saml11.authnMethod', 'password'),
    SamlModel.term('saml11.authnMethod', 'unspecified'),
    SamlModel.term('saml2.authnContext', 'passwordProtectedTransport'),
    SamlModel.term('saml2.authnContext', 'password'),
    WsModel.term('wsfed.wauth', 'identityPassword'),
    WsModel.term('wsfed.wauth', 'microsoftPassword')].join() &&
    WsModel.termOf('wsfed.wauth', 'saml11Password').same ===
      'saml11.authnMethod.password',
  'B. wauth\'s password demands are SAML\'s own terms and two more, in ' +
  'the order the refusal lists them');
  t.check(WsModel.terms('wsfed.tokenType', 'offered').join() === [
    SamlModel.term('saml11.namespace', 'assertion'),
    SamlModel.term('saml2.namespace', 'assertion')].join(),
  'B. the token types offered are SAML\'s assertion namespaces');
  t.check(WsModel.termOf('wst.tokenType', 'saml11Namespace').aliasOf ===
          'saml11', 'B. the SAML 1.1 namespace asks for the SAML 1.1 token');
  t.check(WsModel.childNames('wst.RequestSecurityToken', 'anotherPartys')
    .join() === 'OnBehalfOf,ActAs,RenewTarget,ValidateTarget,CancelTarget',
  'B. the elements holding another party\'s token are the model\'s');
  t.check(WsModel.childNames('wst.RequestSecurityToken', 'inSignedBody')
    .join() === 'RequestType,KeyType,TokenType,AppliesTo,Lifetime,' +
    'OnBehalfOf,ActAs,RenewTarget,ValidateTarget,CancelTarget,' +
    'Forwardable,Delegatable',
  'B. the elements a signed request carries in its Body are the model\'s, ' +
  'in the order #521\'s refusal names them');
  t.check(WsModel.relative('wst.action', 'issueFinal', 'urn:t') ===
          'urn:t/RSTRC/IssueFinal' &&
          WsModel.relative('wst.keyType', 'bearer', 'urn:t') === 'urn:t/Bearer',
  'B. an action and a key type are appended to the request\'s namespace');
  let threw = '';
  try {
    WsModel.relative('wst.tokenType', 'jwt', 'urn:t');
  } catch (e) {
    threw = String(e && e.message);
  }
  t.check(/not appended to a namespace/.test(threw),
          'B. a vocabulary that is not relative is not appended', threw);
  t.check(WsModel.children('wst.RequestSecurityTokenResponse', {
    keyType: 'C', tokenType: 'A', lifetime: 'B' }) === 'ABC',
  'B. an RSTR\'s parts are joined in the order /sts writes them');
  t.check(WsModel.children('wsfed.RequestSecurityTokenResponse', {
    keyType: 'C', tokenType: 'B', lifetime: 'A' }) === 'ABC',
  'B. a sign-in response\'s parts in AD FS\'s order, a different one');
  threw = '';
  try {
    WsModel.children('soap11.Fault', { detail: '<detail/>' });
  } catch (e) {
    threw = String(e && e.message);
  }
  t.check(/no child detail its builder writes/.test(threw),
          'B. a part the model says is never written is refused', threw);
  t.check(WsModel.terms('wsfed.request', 'answered').join() ===
          'wsignin1.0,wsignout1.0,wsignoutcleanup1.0' &&
          WsModel.param('wsfed.passive', 'wreqptr').refusedAs ===
          'STS-WSFED-0001',
  'B. the wa actions answered and wreqptr\'s refusal are the model\'s');
  // Every section 11 code /sts names is a term of the model's: soapFault()
  // asks the model for it, and a code it does not hold would throw.
  const text = fs.readFileSync(path.join(ROOT, 'ws-trust', 'wstrust.ts'),
                               'utf8');
  const named = new Set();
  const re = /trustFault: '([A-Z][A-Za-z]+)'/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    named.add(m[1]);
  }
  const faults = WsModel.terms('wst.fault');
  const strays = Array.from(named).filter(function (code) {
    return faults.indexOf(code) < 0;
  });
  t.check(named.size > 0 && strays.length === 0,
          'B. every section 11 code /sts names is a term of the model\'s (' +
          Array.from(named).join(', ') + ')', strays.join(', '));
  log.debug("Leaving readers().");
}

// A recorded document with its placeholders made into well-formed text.
function restored(xml) {
  log.debug("Entering restored().");
  log.debug("Leaving restored().");
  return String(xml).replace(/<(id\d+|time|opaque|chain|port|value|hex|random|uuid|epoch|cookie|handle|incident|pem|jwt)>/g,
                             'PH');
}

// C. Every recorded document is the model's.
function answered(t) {
  log.debug("Entering answered().");
  const WsModel = require('../ws-trust/ws_model');
  const xmldom = require('../common/xml_parser');
  const wire = require('./ws_model_wire');
  const recorded = JSON.parse(fs.readFileSync(wire.SNAPSHOT, 'utf8'));
  const counted = {};
  const problems = [];
  const idOf = function (root) {
    log.debug("Entering idOf().");
    const ns = root.namespaceURI;
    const name = root.localName;
    let out = '';
    if (name === 'Envelope') {
      out = ns === WsModel.term('soap.namespace', 'soap11')
        ? 'soap11.Envelope' : 'soap12.Envelope';
    } else if (name === 'RequestSecurityTokenResponseCollection') {
      out = 'wsfed.RequestSecurityTokenResponseCollection';
    } else if (name === 'RequestSecurityTokenResponse') {
      out = 'wsfed.RequestSecurityTokenResponse';
    } else if (name === 'EntityDescriptor') {
      const roles = root.getElementsByTagNameNS(
        WsModel.message('wsfed.RoleDescriptor').xmlns, 'RoleDescriptor');
      out = roles.length ? 'wsfed.RoleDescriptor' : '';
    }
    log.debug("Leaving idOf().");
    return out;
  };
  wire.messages(recorded).forEach(function (one) {
    let root = null;
    try {
      root = new xmldom.DOMParser({ onError: function () {
        // Not a document: not one of the messages this holds.
      } }).parseFromString(restored(one.xml), 'text/xml').documentElement;
    } catch (e) {
      log.debug("Caught in answered(): " + ((e && e.message) || e));
      root = null;
    }
    const id = root ? idOf(root) : '';
    if (!id) {
      return;
    }
    const element = id === 'wsfed.RoleDescriptor'
      ? root.getElementsByTagNameNS(WsModel.message(id).xmlns,
                                    'RoleDescriptor')[0]
      : root;
    counted[id] = (counted[id] || 0) + 1;
    WsModel.problemsOf(id, element, element.localName)
      .forEach(function (p) {
        problems.push(one.step + ': ' + p);
      });
  });
  ['soap11.Envelope', 'soap12.Envelope',
   'wsfed.RequestSecurityTokenResponseCollection',
   'wsfed.RequestSecurityTokenResponse', 'wsfed.RoleDescriptor']
    .forEach(function (id) {
      t.check(counted[id] > 0, 'C. the record holds ' + id + ' documents (' +
              (counted[id] || 0) + ')');
    });
  t.check(problems.length === 0,
          'C. every recorded envelope, sign-in response and metadata role is ' +
          'the model\'s', problems.slice(0, 10).join('\n'));
  // And a document out of the model's order is not, nor one in a namespace
  // the model does not name.
  const rstr = function (ns, inner) {
    log.debug("Entering rstr().");
    log.debug("Leaving rstr().");
    return '<wst:RequestSecurityTokenResponse xmlns:wst="' + ns + '">' +
      inner + '</wst:RequestSecurityTokenResponse>';
  };
  const ns = WsModel.term('wst.namespace', 'trust13');
  const reordered = rstr(ns, '<wst:KeyType>k</wst:KeyType>' +
                         '<wst:TokenType>t</wst:TokenType>');
  t.check(WsModel.problems('wst.RequestSecurityTokenResponse', reordered)
    .join(' ').indexOf('out of the schema\'s order') >= 0,
  'C. an RSTR with its KeyType before its TokenType is held as out of ' +
  'order', WsModel.problems('wst.RequestSecurityTokenResponse', reordered)
    .join('; '));
  t.check(WsModel.problems('wst.RequestSecurityTokenResponse',
    rstr('urn:not-a-trust-namespace', '<wst:TokenType>t</wst:TokenType>'))
    .join(' ').indexOf('not {') >= 0,
  'C. an RSTR in a namespace no trust version has is held as another ' +
  'element');
  t.check(WsModel.problems('wst.RequestSecurityTokenResponse',
    rstr(WsModel.term('wst.namespace', 'trust2004'),
         '<wst:RequestedTokenReference/>')).length === 0,
  'C. 2004/04\'s RequestedTokenReference stands in the attached ' +
  'reference\'s place');
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
  name: 'model_ws',
  describe: 'the SOAP, WS-Trust and WS-Federation model (#1579): the ' +
            'build\'s refusals, every namespace, type and list in ws-trust/ ' +
            'and ws-federation/ the model\'s and SAML\'s terms SAML\'s, ' +
            'every part written in its order, and every recorded envelope, ' +
            'sign-in response and metadata role held to it',
  run: run
};
