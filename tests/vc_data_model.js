'use strict';
// ===========================================================================
// tests/vc_data_model.js — THE VC DATA MODEL'S MUSTs (#194, 2026-09-26).
//
// oid4vc/vc_data_model.ts is what the VC-API adapter refuses a credential or
// a presentation for. One row per rule it enforces, each a negative the W3C
// VC Data Model 2.0 test suite also sends, and the positives beside them:
// a conforming credential, a 1.1 one, an enveloped one, a presentation.
// ===========================================================================

const log = require('bunyan').createLogger({ name: 'vc_data_model_test',
  level: process.env.LOG_LEVEL || 'info' });

const V2 = 'https://www.w3.org/ns/credentials/v2';

function good() {
  log.debug("Entering good().");
  log.debug("Leaving good().");
  return { '@context': [V2], type: ['VerifiableCredential'],
           issuer: 'did:example:issuer',
           credentialSubject: { id: 'did:example:subject' } };
}

function withChange(fn) {
  log.debug("Entering withChange().");
  const vc = good();
  fn(vc);
  log.debug("Leaving withChange().");
  return vc;
}

async function run(t) {
  log.debug("Entering run().");
  const model = require('../oid4vc/vc_data_model');

  t.log.info('=== A. what conforms ===');
  t.check(model.checkCredential(good()).ok, 'A1. a minimal 2.0 credential');
  t.check(model.checkCredential({
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'], issuer: { id: 'https://issuer.example' },
    issuanceDate: '2024-01-01T00:00:00Z',
    credentialSubject: { name: 'x' } }).ok, 'A2. a 1.1 credential');
  t.check(model.checkCredential(withChange(function (vc) {
    vc.validFrom = '2023-02-25T19:10:39-06:00';
    vc.validUntil = '2033-02-25T19:10:39Z';
    vc.name = [{ '@value': 'Name', '@language': 'en', '@direction': 'ltr' },
               'Plain'];
  }), { atTime: Date.now() }).ok, 'A3. a validity window and language ' +
          'values');
  t.check(model.checkCredential({ '@context': V2,
    type: 'EnvelopedVerifiableCredential', id: 'data:application/vc+jwt,x' },
    { enveloped: true }).ok, 'A4. an enveloped credential');
  t.check(model.checkPresentation({ '@context': [V2],
    type: ['VerifiablePresentation'], holder: { id: 'did:example:holder' },
    verifiableCredential: [good()] }).ok, 'A5. a presentation');

  t.log.info('=== B. what does not ===');
  const refusals = [
    ['no @context', function (vc) { delete vc['@context']; }],
    ['a first context other than the base', function (vc) {
      vc['@context'] = ['https://www.w3.org/ns/credentials/examples/v2']; }],
    ['a context that is a number', function (vc) {
      vc['@context'].push(123192875); }],
    ['a context that is not a URL', function (vc) {
      vc['@context'].push('https ://not-a-url/contexts/example/v1'); }],
    ['two ids', function (vc) { vc.id = ['https://a.example/1',
                                         'https://b.example/1']; }],
    ['an id that is not a URL', function (vc) {
      vc.id = 'https ://not-a-url/vcs/1'; }],
    ['no type', function (vc) { delete vc.type; }],
    ['no VerifiableCredential type', function (vc) {
      vc.type = ['RelationshipCredential']; }],
    ['no issuer', function (vc) { delete vc.issuer; }],
    ['an issuer that is not a URL', function (vc) { vc.issuer = 'fake'; }],
    ['a null issuer', function (vc) { vc.issuer = null; }],
    ['an issuer object whose id is null', function (vc) {
      vc.issuer = { id: null }; }],
    ['no credentialSubject', function (vc) { delete vc.credentialSubject; }],
    ['an empty credentialSubject', function (vc) {
      vc.credentialSubject = {}; }],
    ['one of two subjects empty', function (vc) {
      vc.credentialSubject = [{ id: 'did:example:a' }, {}]; }],
    ['a subject with two ids', function (vc) {
      vc.credentialSubject.id = ['did:example:a', 'did:example:b']; }],
    ['a validFrom that is not a dateTimeStamp', function (vc) {
      vc.validFrom = 'Sat 25 Feb 2023 07:16:31 PM CST'; }],
    ['validFrom after validUntil', function (vc) {
      vc.validFrom = '2030-01-01T00:00:00Z';
      vc.validUntil = '2020-01-01T00:00:00Z'; }],
    ['a credentialStatus with no type', function (vc) {
      vc.credentialStatus = { id: 'did:example:status' }; }],
    ['a credentialStatus with two ids', function (vc) {
      vc.credentialStatus = { type: 'X', id: ['did:example:1',
                                              'did:example:2'] }; }],
    ['a credentialSchema with no id', function (vc) {
      vc.credentialSchema = { type: 'JsonSchema' }; }],
    ['a refreshService with no type', function (vc) {
      vc.refreshService = { id: 'did:example:refresh' }; }],
    ['termsOfUse with no type', function (vc) { vc.termsOfUse = {}; }],
    ['evidence with no type', function (vc) { vc.evidence = {}; }],
    ['a proof with no type', function (vc) {
      vc.proof = { proofPurpose: 'assertionMethod' }; }],
    ['a relatedResource without a digest', function (vc) {
      vc.relatedResource = [{ id: V2 }]; }],
    ['a relatedResource whose digest does not match', function (vc) {
      vc.relatedResource = [{ id: V2, digestMultibase:
        'uM4RgWQc3RUDtjJCSgTJtTfvpZ7SPEg_LNO0ESlovQC0' }]; }],
    ['relatedResource ids repeated', function (vc) {
      vc.relatedResource = [
        { id: V2, digestMultibase:
            'uWZVc7WaX1h4D8rJVb-vlMIqxaEKEb1tYbX8fet7JJzQ' },
        { id: V2, digestMultibase:
            'uWZVc7WaX1h4D8rJVb-vlMIqxaEKEb1tYbX8fet7JJzQ' }]; }]
  ];
  refusals.forEach(function (row) {
    const checked = model.checkCredential(withChange(row[1]));
    t.check(!checked.ok && checked.problems.length > 0,
            'B. refused: ' + row[0],
            JSON.stringify(checked.problems).slice(0, 300));
  });
  t.check(!model.checkCredential(withChange(function (vc) {
    vc.validUntil = '2020-01-01T00:00:00Z';
  }), { atTime: Date.now() }).ok, 'B. refused when verifying: expired');
  t.check(model.checkCredential(withChange(function (vc) {
    vc.relatedResource = { id: V2, digestSRI: 'sha384-l/HrjlBCNWyAX91hr6LFV' +
      '2Y3heB5Tcr6IeE4/Tje8YyzYBM8IhqjHWiWpr8+ZbYU' };
  })).ok, 'B. a matching digestSRI is accepted');
  t.check(!model.checkPresentation({ '@context': [V2],
    type: ['VerifiablePresentation'],
    verifiableCredential: ['eyJhbGciOi...'] }).ok,
          'B. a presentation carrying a credential as a string is refused');
  t.check(!model.checkPresentation({ '@context': [V2],
    type: ['VerifiablePresentation'], holder: 'z6MkpJySvETLnxhQG' }).ok,
          'B. a holder that is not a URL is refused');
  t.check(!model.checkCredential({ '@context': V2,
    type: 'EnvelopedVerifiableCredential', id: 'eyJ...' },
    { enveloped: true }).ok,
          'B. an envelope whose id is not a data: URL is refused');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_data_model',
  describe: 'the VC Data Model 2.0 and 1.1 MUSTs the VC-API adapter ' +
            'refuses a credential or presentation for, one rule per row',
  run: run
};
