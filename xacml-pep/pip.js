// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: xacml-pep/pip.js
//
// ===========================================================================
// THE PIP THIS CONTAINER DOES NOT HAVE, FETCHED FROM THE ONE THAT DOES.
//
// `pep.js` used to say, at length and correctly, that there is no Policy
// Information Point out here: this process holds the ENGINE and the POLICY and
// has no directory, so a designator the request did not carry resolved to an
// empty bag. The consequence was the thing `sts_xacml_remote_pep.js` asserts in
// both directions — the PDP permits somebody this PEP refuses, and this PEP
// permits somebody the PDP refuses — and it is a genuine property of a
// deployment, not a defect.
//
// **IT IS ALSO A PROBLEM, AND THIS FILE IS THE OTHER HALF OF THE ANSWER.** One
// policy deciding two ways in two enforcement points is exactly the drift a
// shared repository exists to prevent, reappearing one layer down. The PDP now
// publishes its PIP at `POST /xacml/pip`, so a designator can be resolved
// against the same directory the embedded PDP reads — and the two agree again.
//
// **THE OLD BEHAVIOUR IS STILL REACHABLE AND IS STILL THE DEFAULT SHAPE OF THE
// ARGUMENT.** `PEP_PIP=false` turns this off, and a PEP with no credential
// cannot use it at all: the endpoint requires a verified client certificate
// whose subject holds `REMOTE_PEPS`. So the no-PIP deployment is a
// configuration rather than a limitation, which is what lets one container
// demonstrate both.
//
// ---------------------------------------------------------------------------
// THE HARD PART IS THAT THE ENGINE'S RESOLVER IS SYNCHRONOUS.
//
// `xacml_pdp.js` calls `resolve(designator)` and expects an array back. An
// HTTP request is not that, and making the engine asynchronous would be a
// change to the evaluator that every conformance case runs through — for the
// benefit of one deployment shape. Refused.
//
// So the fetch happens BEFORE evaluation: this file walks the policy for the
// designators it could ask about, fetches them all in ONE request, and hands
// `pep.js` a synchronous resolver backed by what came back. **That is why the
// PDP's endpoint takes a LIST of designators rather than one** — the batch is
// not an optimisation, it is what makes a synchronous engine able to use a
// remote PIP at all.
//
// ---------------------------------------------------------------------------
// THE WALK IS STATIC, AND IT DELIBERATELY OVER-FETCHES.
//
// It collects every access-subject designator reachable in the policy —
// targets, conditions, variable definitions, obligation and advice
// assignments, and the children of a policy set — without regard to whether
// evaluation would reach it. A branch never taken costs one entry in a batch
// that was going to be sent anyway.
//
// **THE ALTERNATIVE WAS TO EVALUATE TWICE**, once with a recording resolver
// that returns empty bags and then again with the answers. It is exact rather
// than over-approximate, and it was refused: the first pass decides on
// deliberately wrong information, and any obligation or side effect the engine
// grew later would be performed on that wrong pass. A static walk cannot
// decide anything.
//
// **WHAT THE WALK CAN MISS IS A REFERENCE IT CANNOT FOLLOW**, and that is
// handled rather than ignored: `PolicyIdReference` is resolved through the
// repository this PEP holds, exactly as the evaluator resolves it, and a
// reference to something absent is skipped — the evaluator will report it as
// Indeterminate itself, which is a better error than anything this file could
// invent.
//
// ---------------------------------------------------------------------------
// A MISSED DESIGNATOR IS AN EMPTY BAG AND NEVER AN ERROR.
//
// If the fetch fails, if the PDP refuses, if the walk missed something — the
// resolver answers an empty bag, which is EXACTLY what this container did
// before this file existed. So the failure mode of a remote PIP is the
// no-PIP behaviour, degraded and reported, rather than a PEP that stops
// deciding. That is the same rule `sync.js` follows about a failed pull: this
// component enforces with what it has.
//
// It is reported on `GET /` so that "the PIP is not answering" is something an
// operator reads rather than infers from decisions that changed.
// ===========================================================================

const https = require('https');
const http = require('http');
const { URL } = require('url');
const engine = require('./engine.js');
const { log } = require('./common/helpers.js');

const model = engine.model;
const xml = engine.xml;

// The namespace of the two elements XACML does not define. It is a literal
// here rather than imported, for the reason `pep.js` gives about the attribute
// prefix: the module that owns it is not in `engine.js`'s copy list, and
// pulling the mock's HTTP surface into a process that has no directory to
// serve would be a much bigger thing than one string.
const PIP_NS = 'urn:sts:xacml:pip:1.0';

// How many designators one request may carry. The PDP refuses more than fifty,
// so this file refuses to send more than fifty rather than being refused —
// a policy that designates more than that is doing something no real one does,
// and being told so here names the policy rather than the request.
const MAX_DESIGNATORS = 50;

// THE ERROR-CODE TAG, handed in on `options` by `pep.js` — `sync.js` carries
// the same four lines and argues them.
function tag(options, code) {
  log.debug("Entering tag().");
  if (options && typeof options.tag === 'function') {
    log.debug("Leaving tag().");
    return options.tag(code);
  }
  log.debug("Leaving tag().");
  return '[' + code + '] ';
}

// ---------------------------------------------------------------------------
// THE WALK. Every access-subject designator reachable in a policy.
//
// Keyed on the three things that make a designator DIFFERENT to the PIP —
// category, AttributeId and DataType — because the resolver answers at the
// designator's declared type, so `employeeType` as a string and the same
// attribute as an integer are two different questions with two different
// answers.
// ---------------------------------------------------------------------------
function keyOf(designator) {
  log.debug("Entering keyOf().");
  log.debug("Leaving keyOf().");
  return designator.category + '\u0000' + designator.attributeId + '\u0000' +
         designator.dataType;
}

function collectFromExpression(expression, into) {
  log.debug("Entering collectFromExpression().");
  if (!expression || typeof expression !== 'object') {
    log.debug("Leaving collectFromExpression().");
    return;
  }
  if (expression.kind === 'designator') {
    // ONLY THE ACCESS-SUBJECT CATEGORY, because that is the only one the PDP's
    // PIP resolves — asking about a resource designator would spend a slot in
    // the batch on an answer that is always empty, and would make the
    // `<Unresolved>` list on every reply look like a fault.
    if (expression.category === model.CATEGORY.ACCESS_SUBJECT) {
      into[keyOf(expression)] = expression;
    }
    log.debug("Leaving collectFromExpression().");
    return;
  }
  if (expression.kind === 'apply') {
    (expression.args || []).forEach(function (one) {
      collectFromExpression(one, into);
    });
  }
  log.debug("Leaving collectFromExpression().");
  // `value`, `function`, `variableRef` and `selector` carry no designator of
  // their own. A variableRef's DEFINITION is walked where the definitions are,
  // which reaches it once rather than once per reference.
}

function collectFromTarget(target, into) {
  log.debug("Entering collectFromTarget().");
  if (!target) {
    log.debug("Leaving collectFromTarget().");
    return;
  }
  (target.anyOf || []).forEach(function (anyOf) {
    (anyOf.allOf || []).forEach(function (allOf) {
      (allOf.matches || []).forEach(function (match) {
        // The MATCH's reference is the designator; its value is a literal.
        // Both are walked, because a future <Match> shape that put an Apply on
        // either side would otherwise be missed silently.
        collectFromExpression(match.reference, into);
        collectFromExpression(match.value, into);
      });
    });
  });
  log.debug("Leaving collectFromTarget().");
}

function collectFromHolders(holders, into) {
  log.debug("Entering collectFromHolders().");
  (holders || []).forEach(function (holder) {
    (holder.assignments || []).forEach(function (assignment) {
      collectFromExpression(assignment.expression, into);
    });
  });
  log.debug("Leaving collectFromHolders().");
}

function collectFromPolicy(policy, repository, into, seen) {
  log.debug("Entering collectFromPolicy().");
  if (!policy || typeof policy !== 'object') {
    log.debug("Leaving collectFromPolicy().");
    return;
  }
  // A CYCLE IS POSSIBLE THROUGH PolicyIdReference and would be an infinite
  // walk. The evaluator has its own depth guard; this one keeps a visited set,
  // because over-fetching the same policy twice is harmless and looping is not.
  const id = policy.id || '';
  if (id) {
    if (seen[id]) {
      log.debug("Leaving collectFromPolicy().");
      return;
    }
    seen[id] = true;
  }
  if (policy.kind === 'PolicyIdReference' ||
      policy.kind === 'PolicySetIdReference') {
    const referenced = repository && repository[policy.ref];
    if (!referenced) {
      // SKIPPED RATHER THAN REPORTED. The evaluator meets the same missing
      // reference and answers Indeterminate with a message naming it, which is
      // a better error than anything this file could invent — and one this
      // file must not pre-empt, because a reference that is missing HERE may
      // be present by the time evaluation reaches it.
      log.debug('pip: the policy reference "' + policy.ref + '" is not in ' +
                'the repository this PEP holds, so no designator of its is ' +
                'fetched. The evaluator reports it.');
      log.debug("Leaving collectFromPolicy().");
      return;
    }
    collectFromPolicy(referenced, repository, into, seen);
    log.debug("Leaving collectFromPolicy().");
    return;
  }
  collectFromTarget(policy.target, into);
  collectFromHolders(policy.obligations, into);
  collectFromHolders(policy.advice, into);
  Object.keys(policy.variables || {}).forEach(function (name) {
    collectFromExpression(policy.variables[name], into);
  });
  (policy.rules || []).forEach(function (rule) {
    collectFromTarget(rule.target, into);
    collectFromExpression(rule.condition, into);
    collectFromHolders(rule.obligations, into);
    collectFromHolders(rule.advice, into);
  });
  (policy.children || []).forEach(function (child) {
    collectFromPolicy(child, repository, into, seen);
  });
  log.debug("Leaving collectFromPolicy().");
}

function designatorsIn(root, repository) {
  log.debug('Entering designatorsIn().');
  const into = {};
  collectFromPolicy(root, repository || {}, into, {});
  const list = Object.keys(into).map(function (key) {
    return into[key];
  });
  log.debug('Leaving designatorsIn(). ' + list.length + ' designator(s).');
  return list;
}

// ---------------------------------------------------------------------------
// THE QUERY DOCUMENT.
//
// The `<Request>` is the one being decided, written back out — the PDP reads
// the subject out of it exactly as its own PDP does, which is what makes the
// answer the answer the embedded PIP would have given. Only the ACCESS-SUBJECT
// category is sent: the rest of the request says nothing to a PIP that reads a
// person's entry, and sending a whole request would put this PEP's resource
// and action into somebody else's audit log for no purpose.
// ---------------------------------------------------------------------------
function subjectIdOf(request) {
  log.debug("Entering subjectIdOf().");
  let found = '';
  (request.categories || []).forEach(function (category) {
    if (found || category.category !== model.CATEGORY.ACCESS_SUBJECT) {
      return;
    }
    (category.attributes || []).forEach(function (attribute) {
      if (found || attribute.attributeId !== model.ATTRIBUTE.SUBJECT_ID) {
        return;
      }
      if ((attribute.values || []).length) {
        found = attribute.values[0].lexical;
      }
    });
  });
  log.debug("Leaving subjectIdOf().");
  return found;
}

function escape(text) {
  log.debug("Entering escape().");
  log.debug("Leaving escape().");
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// WHETHER THE REQUEST IS ABOUT AN APPLICATION (#303): the issuance
// vocabulary's subject-kind attribute, which `pep.js` asserts from
// `subjectKind`. Forwarded so the PDP resolves the ROLE designator for the
// right kind of subject; absent, the subject is a person, as it always was.
const SUBJECT_KIND = 'urn:sts:xacml:subject-kind';

function subjectKindOf(request) {
  log.debug("Entering subjectKindOf().");
  let kind = 'user';
  (request.categories || []).forEach(function (category) {
    if (category.category !== model.CATEGORY.ACCESS_SUBJECT) {
      return;
    }
    (category.attributes || []).forEach(function (attribute) {
      if (attribute.attributeId === SUBJECT_KIND &&
          (attribute.values || []).length &&
          String(attribute.values[0].lexical) === 'application') {
        kind = 'application';
      }
    });
  });
  log.debug("Leaving subjectKindOf(). " + kind);
  return kind;
}

function queryDocument(subject, designators, kind) {
  log.debug("Entering queryDocument().");
  const parts = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<PIPRequest xmlns="' + PIP_NS + '">',
                 '  <Request xmlns="' + model.NS_XACML + '" ' +
                 'CombinedDecision="false" ReturnPolicyIdList="false">',
                 '    <Attributes Category="' + model.CATEGORY.ACCESS_SUBJECT +
                 '">',
                 '      <Attribute AttributeId="' + model.ATTRIBUTE.SUBJECT_ID +
                 '" IncludeInResult="true">',
                 '        <AttributeValue DataType="' + model.TYPE.STRING +
                 '">' + escape(subject) + '</AttributeValue>',
                 '      </Attribute>']
    .concat(kind === 'application'
      ? ['      <Attribute AttributeId="' + SUBJECT_KIND +
         '" IncludeInResult="false">',
         '        <AttributeValue DataType="' + model.TYPE.STRING +
         '">application</AttributeValue>',
         '      </Attribute>']
      : [])
    .concat(['    </Attributes>', '  </Request>']);
  designators.forEach(function (one) {
    parts.push('  <AttributeDesignator xmlns="' + model.NS_XACML +
               '" Category="' + escape(one.category) + '" AttributeId="' +
               escape(one.attributeId) + '" DataType="' +
               escape(one.dataType) + '" MustBePresent="false"/>');
  });
  parts.push('</PIPRequest>');
  log.debug("Leaving queryDocument().");
  return parts.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// THE REQUEST. Node's own http/https, for `sync.js`'s reason: this container
// takes no dependency to make four kinds of request.
// ---------------------------------------------------------------------------
function post(url, body, options) {
  log.debug('Entering post(). url=' + url);
  log.debug("Leaving post().");
  return new Promise(function (resolve) {
    let target;
    try {
      target = new URL(url);
    } catch (error) {
      resolve({ ok: false, why: 'the PDP URL "' + url + '" will not parse: ' +
                                error.message });
      return;
    }
    const secure = target.protocol === 'https:';
    const lib = secure ? https : http;
    const request = lib.request({
      host: target.hostname,
      port: target.port || (secure ? 443 : 80),
      path: target.pathname + target.search,
      method: 'POST',
      // THE SAME TLS POSTURE THE PULL USES, taken from the same options rather
      // than decided here: a PEP that verified the PDP for one request and not
      // for another would be a security claim that depended on which endpoint
      // it happened to be calling.
      rejectUnauthorized: options.insecure ? false : true,
      // `pdpCa`, the name `pep.js` stores PEP_TLS_CA under and `sync.js`
      // reads. This read `options.ca`, which nothing sets, so until
      // 2026-09-16 the PIP query verified the PDP against the system roots
      // alone while the pull beside it used the configured anchor.
      ca: options.pdpCa || undefined,
      cert: options.clientCertificate || undefined,
      key: options.clientKey || undefined,
      headers: { 'Content-Type': 'application/xml',
                 'Content-Length': Buffer.byteLength(body) },
      timeout: options.timeoutMs
    }, function (response) {
      let text = '';
      response.on('data', function (chunk) { text += chunk; });
      response.on('end', function () {
        log.debug('Leaving post(). status=' + response.statusCode);
        resolve({ ok: response.statusCode === 200,
                  status: response.statusCode, text: text });
      });
    });
    request.on('timeout', function () {
      request.destroy(new Error('timed out after ' + options.timeoutMs + 'ms'));
    });
    request.on('error', function (error) {
      resolve({ ok: false, why: error.message });
    });
    request.write(body);
    request.end();
  });
}

// ---------------------------------------------------------------------------
// READING THE ANSWER — WITH THE ENGINE'S OWN REQUEST READER.
//
// The `<Attributes>` come back in the XACML core namespace, in the shape a
// `<Request>` carries them, which is the whole design of that endpoint: they
// are a REQUEST FRAGMENT. So this wraps them in a `<Request>` element and
// hands the result to `xacml_xml.js`'s `readRequest()` — **the same reader
// the PDP's `POST /xacml/pip` read this PEP's query with**. Nothing here
// parses an attribute value by hand, so there is no second reading of a
// datatype to disagree with the first.
// ---------------------------------------------------------------------------
function readAnswer(text) {
  log.debug('Entering readAnswer().');
  const root = xml.parseDocument(text).documentElement;
  if (xml.localName(root) !== 'PIPResponse') {
    throw new Error('the PDP answered <' + xml.localName(root) +
                    '> where a <PIPResponse> was expected');
  }
  // A synthetic <Request> around the fragment. `readRequest()` takes the NODE,
  // so the wrapper is built in the DOM rather than by re-serializing — which
  // is where namespace declarations inherited from an ancestor go missing.
  const wrapper = root.ownerDocument.createElementNS(model.NS_XACML, 'Request');
  xml.childrenNamed(root, 'Attributes').forEach(function (node) {
    wrapper.appendChild(node.cloneNode(true));
  });
  const parsed = xml.readRequest(wrapper);
  const answers = {};
  (parsed.categories || []).forEach(function (category) {
    (category.attributes || []).forEach(function (attribute) {
      (attribute.values || []).forEach(function (value) {
        const key = category.category + '\u0000' + attribute.attributeId +
                    '\u0000' + value.type;
        if (!answers[key]) {
          answers[key] = [];
        }
        answers[key].push(value.lexical);
      });
    });
  });
  // The diagnostics, for the report. They are in this service's own namespace
  // and a PEP is under no obligation to read them — which is the point of
  // where they are — but an operator looking at `GET /` wants to know that the
  // PIP answered and said the entry does not hold the attribute, rather than
  // that nothing came back at all.
  const unresolved = [];
  const container = xml.firstNamed(root, 'Unresolved');
  if (container) {
    xml.childrenNamed(container, 'Designator').forEach(function (node) {
      const reason = xml.firstNamed(node, 'Reason');
      unresolved.push({
        attributeId: node.getAttribute('AttributeId') || '',
        why: reason ? xml.textOf(reason) : ''
      });
    });
  }
  log.debug('Leaving readAnswer(). ' + Object.keys(answers).length +
            ' resolved, ' + unresolved.length + ' not.');
  return { answers: answers, unresolved: unresolved };
}

// ---------------------------------------------------------------------------
// WHAT `pep.js` CALLS. One function, awaited before evaluation, answering a
// SYNCHRONOUS resolver and a report.
//
// **IT NEVER REJECTS.** Every failure comes back as a resolver that answers
// empty bags and a `why` saying what went wrong, because the degraded state of
// this feature is the state this container was in before it existed. A PEP
// that stopped deciding because a PIP was unreachable would be a worse
// component than one with no PIP at all.
// ---------------------------------------------------------------------------
async function resolverFor(request, holding, options) {
  log.debug('Entering resolverFor().');
  const empty = function () {
    log.debug("Entering empty().");
    log.debug("Leaving empty().");
    return [];
  };

  if (!options.pipEnabled) {
    log.debug('Leaving resolverFor(). Turned off.');
    return { resolve: empty, report: { used: false,
      why: 'PEP_PIP is off, so this PEP decides on what the request asserts ' +
           'and nothing else — which is what a remote PEP with no Policy ' +
           'Information Point does.' } };
  }
  const subject = subjectIdOf(request);
  if (!subject) {
    // NOT AN ERROR. A request naming no subject is perfectly ordinary and
    // there is no entry to read; the PDP's own PIP answers the same way.
    log.debug('Leaving resolverFor(). No subject.');
    return { resolve: empty, report: { used: false,
      why: 'the request names no subject-id, so there is no directory entry ' +
           'to resolve anything against.' } };
  }
  const designators = designatorsIn(holding.root, holding.repository);
  if (!designators.length) {
    log.debug('Leaving resolverFor(). Nothing to ask about.');
    return { resolve: empty, report: { used: false, subject: subject,
      why: 'the policy this PEP holds designates no access-subject ' +
           'attribute, so there is nothing to ask the PIP for.' } };
  }
  if (designators.length > MAX_DESIGNATORS) {
    log.warn(tag(options, 'STS-XPEP-0024') +
             'pip: the policy designates ' + designators.length +
             ' access-subject attributes and the PDP accepts at most ' +
             MAX_DESIGNATORS + ' per query, so NONE was fetched and every ' +
             'designator will resolve to an empty bag. Split the policy, or ' +
             'turn PEP_PIP off and assert the attributes in the request.');
    log.debug("Leaving resolverFor().");
    return { resolve: empty, report: { used: false, subject: subject,
      designators: designators.length,
      why: 'the policy designates ' + designators.length + ' access-subject ' +
           'attributes, which is more than the PDP will answer in one query ' +
           '(' + MAX_DESIGNATORS + ').' } };
  }

  const answered = await post(options.pdpUrl + '/xacml/pip',
                              queryDocument(subject, designators,
                                            subjectKindOf(request)), options);
  if (!answered.ok) {
    // REPORTED AND DEGRADED, NEVER THROWN. See the header.
    const why = answered.why
      ? 'the PIP query could not be made: ' + answered.why
      : 'the PDP answered ' + answered.status + ' to the PIP query' +
        (answered.status === 403
          ? ' — POST /xacml/pip requires a client certificate this service ' +
            'VERIFIES whose subject holds the built-in REMOTE_PEPS role, so ' +
            'check PEP_TLS_CERT and the group roles.remotePepGroup names'
          : '') + '.';
    log.warn((answered.why ? tag(options, 'STS-XPEP-0025')
                           : tag(options, 'STS-XPEP-0026')) +
             'pip: ' + why + ' Every designator will resolve to an empty ' +
             'bag, which is what this PEP did before it had a PIP at all — ' +
             'so it goes on deciding, on less information, and says so.');
    log.debug("Leaving resolverFor().");
    return { resolve: empty, report: { used: false, subject: subject,
      designators: designators.length, failed: true, why: why } };
  }

  let read;
  try {
    read = readAnswer(answered.text);
  } catch (error) {
    log.warn(tag(options, 'STS-XPEP-0027') +
             'pip: the PDP\'s answer would not parse (' + error.message +
             '), so every designator resolves to an empty bag.');
    log.debug("Leaving resolverFor().");
    return { resolve: empty, report: { used: false, subject: subject,
      designators: designators.length, failed: true,
      why: 'the PDP\'s answer would not parse: ' + error.message } };
  }

  // THE RESOLVER. It answers PARSED values at the designator's declared type,
  // which is the contract `xacml_pdp.js` states: never null, never a bag,
  // because the PDP owns the bag's type and a resolver that built one could
  // disagree with the designator about what it just returned.
  function resolve(designator) {
    log.debug('Entering resolve(). id=' + designator.attributeId);
    const lexicals = read.answers[keyOf(designator)];
    if (!lexicals || !lexicals.length) {
      log.debug('Leaving resolve(). Not answered.');
      return [];
    }
    const values = [];
    lexicals.forEach(function (lexical) {
      try {
        values.push(engine.datatypes.parseValue(designator.dataType, lexical));
      } catch (error) {
        // The same rule the PDP's own PIP follows: a value that will not parse
        // at the type the POLICY asked for is DROPPED with a warning rather
        // than making the decision Indeterminate. Reaching this here would
        // mean the PDP wrote a lexical form its own parser will not read back,
        // which is a defect over there rather than a data problem — so it is
        // logged at warn rather than debug.
        log.warn(tag(options, 'STS-XPEP-0028') +
                 'pip: the PDP answered "' + lexical + '" for ' +
                 designator.attributeId + ', which is not a valid ' +
                 designator.dataType + ': ' + error.message);
      }
    });
    log.debug('Leaving resolve(). ' + values.length + ' value(s).');
    return values;
  }

  const resolved = Object.keys(read.answers).length;
  log.info('pip: resolved ' + resolved + ' of ' + designators.length +
           ' designator(s) about "' + subject + '" against the PDP\'s ' +
           'embedded directory.');
  log.debug('Leaving resolverFor(). Answered.');
  return { resolve: resolve, report: { used: true, subject: subject,
    designators: designators.length, resolved: resolved,
    unresolved: read.unresolved } };
}

module.exports = {
  resolverFor: resolverFor,
  // Exported for `tests/xacml_pep.js`, which holds the SHAPE of this container
  // without making a request: the walk is the half of this file that can be
  // asserted in process, and it is the half most likely to miss something when
  // the policy model grows an element.
  designatorsIn: designatorsIn,
  queryDocument: queryDocument,
  subjectKindOf: subjectKindOf,
  readAnswer: readAnswer,
  MAX_DESIGNATORS: MAX_DESIGNATORS
};
