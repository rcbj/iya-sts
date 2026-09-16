// @ts-check
'use strict';
//
// File: return_address.js
//
// ===========================================================================
// WHERE A SIGNED ASSERTION IS DELIVERED, AND WHO GETS TO SAY (2026-09-12).
//
// Three browser profiles deliver a signed assertion to an address the REQUEST
// names: a SAML 2.0 AssertionConsumerServiceURL, a SAML 1.1 `shire`, and a
// WS-Federation `wreply`. Each also had a FALLBACK for a request that named
// none — the registered value if the entry had one, and otherwise this
// service's own mock service provider or relying party (`/saml2/sp`,
// `/saml11/rp`, `/wsfed/rp`).
//
// **IN DEVELOPMENT ALL OF THAT IS UNCHANGED, and it is on purpose.** It is how
// a client under test is pointed at this service without registering first,
// and the mock SP and RP are how a response can be verified with nothing else
// running. Every one of the three files said so beside the line.
//
// **IN PRODUCT (`mode.acceptsUnregisteredAddresses()` false) IT IS AN IDENTITY
// PROVIDER'S RULE INSTEAD**: a response goes only to an address on the
// application's own entry — `samlAssertionConsumerService` for both SAML
// profiles, `wsfedReplyUrl` for WS-Federation — a request naming any other is
// REFUSED, and there is NO fallback to a built-in mock. Without that rule this
// service is a signed-assertion forwarding service: anybody who can put a link
// in front of a signed-in person receives an assertion about them, at an
// address they chose, audienced to an application that never asked.
//
// The comparison is EXACT, which is what RFC 9700 section 4.1.3 asks of a
// redirect URI and is the only rule that does not become a prefix-matching
// hole: a registered `https://sp.example.com/acs` does not admit
// `https://sp.example.com/acs/../evil` or `https://sp.example.com.evil/acs`.
//
// ONE FUNCTION FOR THE THREE, because three copies of "is this address
// registered" are three places for one of them to compare case-insensitively.
//
// A LIBRARY (rule 3): it registers no route and requires only `helpers`,
// `mode` and `error_codes`, all leaves.
//
// ---------------------------------------------------------------------------
// **WHAT COUNTS AS REGISTERED IS NOT DECIDED HERE (2026-09-12).** A caller
// hands this function `registered` and `unconfirmed`, and both come from
// `applications.returnAddressesOf()` — the one place a development-mode
// sighting's OBSERVED mark is read. An address that is on the entry and still
// marked is not in `registered` in product mode; it is in `unconfirmed`, and
// this function refuses it exactly as it refuses an address that is not on the
// entry at all, with the one difference that the sentence says how to confirm
// it and the refusal carries STS-REG-0049 for the caller to mark. A caller that
// passes no `unconfirmed` gets the behaviour this file always had.
// ===========================================================================

const { log } = require('../common/helpers');
const mode = require('../common/mode');
const errorCodes = require('../common/error_codes');

// The sentence that tells an operator how to believe an observed address,
// written once for the two refusals that can meet one.
function confirmHow(spec) {
  log.debug("Entering confirmHow().");
  log.debug("Leaving confirmHow().");
  return 'Confirm it on the application\'s page under /admin/applications, ' +
         'or with POST /admin-api/applications/confirm-address (application "' +
         (spec.application || '(unnamed)') + '", attribute ' + spec.attribute +
         '), if it genuinely is that application\'s — or discard it.';
}

// Every value of a multi-valued attribute, as trimmed non-empty strings.
function valuesOf(value) {
  log.debug("Entering valuesOf().");
  const list = Array.isArray(value) ? value :
               (value === undefined || value === null ? [] : [value]);
  log.debug("Leaving valuesOf().");
  return list.map(function (one) { return String(one).trim(); })
             .filter(function (one) { return one !== ''; });
}

// ---------------------------------------------------------------------------
// `spec`:
//   requested    what the request named ('' for nothing)
//   registered   the addresses `applications.returnAddressesOf()` says the
//                check may believe
//   unconfirmed  the addresses it withheld because they are still marked as
//                observed — always empty in development
//   fallback     the built-in mock's address, used in development only
//   attribute    the attribute's NAME, for the sentence a refusal carries
//   parameter    the request parameter's name, likewise
//   application  the identifier the entry is filed under
//
// Answers `{ ok, url, from }` or `{ ok: false, why }`. In development it is
// exactly the old precedence — the request, then the LAST registered value
// (which is what both SAML modules always took), then the fallback.
// ---------------------------------------------------------------------------
function resolve(spec) {
  log.debug("Entering resolve(). application=" +
            (spec.application || '(none)'));
  const requested = String(spec.requested || '').trim();
  const registered = valuesOf(spec.registered);
  if (mode.acceptsUnregisteredAddresses()) {
    if (requested) {
      log.debug("Leaving resolve(). Development: the request named it.");
      return { ok: true, url: requested, from: 'the request' };
    }
    if (registered.length) {
      log.debug("Leaving resolve(). Development: the registered value.");
      return { ok: true, url: registered[registered.length - 1],
               from: 'the ' + spec.attribute + ' on the application entry' };
    }
    log.debug("Leaving resolve(). Development: the built-in mock.");
    return { ok: true, url: String(spec.fallback || ''),
             from:
               'this service\'s own mock, because nothing named an address' };
  }
  const unconfirmed = valuesOf(spec.unconfirmed);
  // AN OBSERVED ADDRESS IS REFUSED FIRST WHEN IT IS THE ONE ASKED FOR, before
  // either of the refusals below could describe it as absent — it is on the
  // entry, and a sentence saying "not registered anywhere" about an address
  // the operator can see on the page is a sentence that sends them looking for
  // a typo.
  if (requested && unconfirmed.indexOf(requested) >= 0) {
    log.debug("Leaving resolve(). Product: the address named is still marked " +
              "observed.");
    return errorCodes.mark({ ok: false,
             why: 'This realm is in PRODUCT mode, and the ' + spec.parameter +
                 ' ' +
                 '"' +
                  requested + '" is on the ' + spec.attribute + ' of "' +
                  (spec.application || '(unnamed)') + '" but was put there ' +
                  'by a request while the realm was in DEVELOPMENT mode, and ' +
                  'nobody has confirmed it. An address a request taught this ' +
                  'service is not a registered one, so it is refused as ' +
                  'though it were not on the ' +
                  'entry. ' + confirmHow(spec) }, 'STS-REG-0049');
  }
  if (!registered.length && !requested && unconfirmed.length) {
    log.debug("Leaving resolve(). Product: only observed addresses are on " +
              "the entry.");
    return errorCodes.mark({ ok: false,
             why: 'This realm is in PRODUCT mode, so a response is delivered ' +
                  'only to a registered address, and ' +
                  'every ' + spec.attribute + ' on "' +
                  (spec.application || '(unnamed)') + '" (' +
                  unconfirmed.join(', ') +
                  ') was put there by a request in DEVELOPMENT mode and is ' +
                  'still unconfirmed. The request named ' +
                  'no ' + spec.parameter + '. ' +
                  confirmHow(spec) }, 'STS-REG-0049');
  }
  if (!registered.length) {
    log.debug("Leaving resolve(). Product: nothing is registered.");
    return { ok: false,
             why: 'This realm is in PRODUCT mode, so a response is delivered ' +
                  'only to an address registered on the application\'s own ' +
                  'entry, and "' +
                  (spec.application || '(unnamed)') + '" has no ' +
                  spec.attribute + '. ' +
                  (requested
                    ? 'The request named ' + requested + ', which is not ' +
                        'registered anywhere. '
                    : 'The request named no ' + spec.parameter + ' either. ') +
                  'Register the address on the application (the console\'s ' +
                  'application page, POST /admin-api/applications/add with ' +
                  'attribute ' + spec.attribute +
                  ', or an ldapmodify) and send the request again.' };
  }
  if (!requested) {
    log.debug("Leaving resolve(). Product: the request named none; the " +
              "registered one.");
    return { ok: true, url: registered[registered.length - 1],
             from: 'the ' + spec.attribute + ' on the application entry' };
  }
  if (registered.indexOf(requested) < 0) {
    log.debug("Leaving resolve(). Product: an unregistered address was named.");
    return { ok: false,
             why: 'This realm is in PRODUCT mode, and the ' + spec.parameter +
                 ' ' +
                 '"' + requested +
                  '" is not one of the ' + registered.length + ' address(es) ' +
                      'registered as ' +
                  spec.attribute + ' on "' + (spec.application ||
                                              '(unnamed)') + '". ' +
                  'The comparison is exact. Register it on the application ' +
                  'entry if it is genuinely that application\'s, or send the ' +
                  'request with a registered one.' };
  }
  log.debug("Leaving resolve(). Product: a registered address.");
  return { ok: true, url: requested,
           from: 'the request, and it is registered' };
}

module.exports = {
  resolve: resolve
};
