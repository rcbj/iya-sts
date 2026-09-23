'use strict';
//
// File: oidfed_metadata_policy.js
//
// ===========================================================================
// OPENID FEDERATION 1.1 SECTION 6 (#132, #133, 2026-09-23), in process,
// against the specification's own examples wherever it gives one:
//
//   1. section 6.1.5's worked example — a Trust Anchor's policy, an
//      Intermediate's policy and metadata, a leaf's metadata — merged and
//      applied to exactly Figure 10's policy and Figure 12's metadata;
//   2. table 1 of 6.1.3.1.8, `essential` against `subset_of`, row by row;
//   3. every operator's merge rule, and the merges that are policy errors;
//   4. the combinations 6.1.3.1 refuses, alone and after a merge;
//   5. critical operators (6.1.3.2): an unknown one ignored, a critical
//      unknown one refusing the chain;
//   6. `scope` read as its values (6.1.3.1.8);
//   7. the three constraints of 6.2 on a four-statement chain, including
//      6.2.1's own examples.
// ===========================================================================

const MetadataPolicy = require('../oidfed/metadata_policy');

const log = require('bunyan').createLogger({ name: 'oidfed_metadata_policy',
  level: process.env.LOG_LEVEL || 'info' });

function same(a, b) {
  log.debug("Entering same().");
  log.debug("Leaving same().");
  return MetadataPolicy.stable(a) === MetadataPolicy.stable(b);
}

// A set comparison for arrays whose order 6.1.3 leaves undefined.
function sameSet(a, b) {
  log.debug("Entering sameSet().");
  log.debug("Leaving sameSet().");
  return Array.isArray(a) && Array.isArray(b) && a.length === b.length &&
         MetadataPolicy.subsetOf(a, b);
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== 1. section 6.1.5 ===');
  const taPolicy = { openid_relying_party: {
    grant_types: { default: ['authorization_code'],
                   subset_of: ['authorization_code', 'refresh_token'],
                   superset_of: ['authorization_code'] },
    token_endpoint_auth_method: { one_of: ['private_key_jwt',
                                           'self_signed_tls_client_auth'],
                                  essential: true },
    token_endpoint_auth_signing_alg: { one_of: ['PS256', 'ES256'] },
    subject_type: { value: 'pairwise' },
    contacts: { add: ['helpdesk@federation.example.org'] } } };
  const intermediate = {
    metadata_policy: { openid_relying_party: {
      grant_types: { subset_of: ['authorization_code'] },
      token_endpoint_auth_method: { one_of: ['self_signed_tls_client_auth'] },
      contacts: { add: ['helpdesk@org.example.org'] } } },
    metadata: { openid_relying_party: {
      sector_identifier_uri: 'https://org.example.org/sector-ids.json',
      policy_uri: 'https://org.example.org/policy.html' } } };
  const resolved = MetadataPolicy.resolve([
    { iss: 'https://ta.example', sub: 'https://org.example',
      metadata_policy: taPolicy },
    { iss: 'https://org.example', sub: 'https://rp.example',
      metadata_policy: intermediate.metadata_policy }]);
  const figure10 = {
    grant_types: { default: ['authorization_code'],
                   superset_of: ['authorization_code'],
                   subset_of: ['authorization_code'] },
    token_endpoint_auth_method: { one_of: ['self_signed_tls_client_auth'],
                                  essential: true },
    token_endpoint_auth_signing_alg: { one_of: ['PS256', 'ES256'] },
    subject_type: { value: 'pairwise' },
    contacts: { add: ['helpdesk@federation.example.org',
                      'helpdesk@org.example.org'] } };
  t.check(resolved.ok && same(resolved.policy.openid_relying_party, figure10),
          '1a. the merged policy is Figure 10',
          JSON.stringify(resolved));
  const chain = [
    { iss: 'https://rp.example', sub: 'https://rp.example',
      metadata: { openid_relying_party: {
        redirect_uris: ['https://rp.example.org/callback'],
        response_types: ['code'],
        token_endpoint_auth_method: 'self_signed_tls_client_auth',
        contacts: ['rp_admins@rp.example.org'] } } },
    { iss: 'https://org.example', sub: 'https://rp.example',
      metadata_policy: intermediate.metadata_policy,
      metadata: intermediate.metadata },
    { iss: 'https://ta.example', sub: 'https://org.example',
      metadata_policy: taPolicy },
    { iss: 'https://ta.example', sub: 'https://ta.example' }];
  const applied = MetadataPolicy.resolvedMetadata(chain);
  const figure12 = {
    redirect_uris: ['https://rp.example.org/callback'],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'self_signed_tls_client_auth',
    subject_type: 'pairwise',
    sector_identifier_uri: 'https://org.example.org/sector-ids.json',
    policy_uri: 'https://org.example.org/policy.html',
    contacts: ['rp_admins@rp.example.org', 'helpdesk@federation.example.org',
               'helpdesk@org.example.org'] };
  const rp = applied.ok ? applied.metadata.openid_relying_party : {};
  t.check(applied.ok && same(Object.assign({}, rp, { contacts: null }),
                             Object.assign({}, figure12, { contacts: null })) &&
          sameSet(rp.contacts, figure12.contacts),
          '1b. the resolved metadata is Figure 12', JSON.stringify(applied));

  t.log.info('=== 2. table 1 of 6.1.3.1.8 ===');
  const rows = [
    [true, ['a', 'e'], ['a']], [false, ['a', 'e'], ['a']],
    [true, ['d', 'e'], []], [false, ['d', 'e'], []],
    [true, undefined, 'error'], [false, undefined, undefined]];
  const outcomes = rows.map(function (row) {
    const md = row[1] === undefined ? {} : { p: row[1] };
    const out = MetadataPolicy.applyToType('t', md,
      { p: { essential: row[0], subset_of: ['a', 'b', 'c'] } });
    if (!out.ok) {
      return 'error';
    }
    return out.metadata.p;
  });
  t.check(rows.every(function (row, i) {
    return same(outcomes[i], row[2]);
  }), '2a. essential with subset_of gives table 1\'s six outputs',
  JSON.stringify(outcomes));

  t.log.info('=== 3. merges ===');
  const merge = function (op, a, b) {
    log.debug("Entering merge().");
    log.debug("Leaving merge().");
    return MetadataPolicy.mergeOperator(op, a, b);
  };
  t.check(merge('value', 'x', 'x').ok && !merge('value', 'x', 'y').ok &&
          merge('default', 1, 1).ok && !merge('default', 1, 2).ok,
          '3a. value and default merge only when equal');
  t.check(sameSet(merge('add', ['a'], ['b', 'a']).value, ['a', 'b']) &&
          sameSet(merge('superset_of', ['a'], ['b']).value, ['a', 'b']),
          '3b. add and superset_of merge to the union');
  t.check(sameSet(merge('subset_of', ['a', 'b'], ['b', 'c']).value, ['b']) &&
          same(merge('subset_of', ['a'], ['c']).value, []) &&
          sameSet(merge('one_of', ['a', 'b'], ['b']).value, ['b']) &&
          !merge('one_of', ['a'], ['c']).ok,
          '3c. subset_of and one_of to the intersection; an empty one_of ' +
          'is an error, an empty subset_of is not');
  t.check(merge('essential', false, true).value === true &&
          merge('essential', false, false).value === false,
          '3d. essential merges by OR');
  t.check(MetadataPolicy.same({ a: 1, b: [1, { c: 2, d: 3 }] },
                              { b: [1, { d: 3, c: 2 }], a: 1 }),
          '3e. object values compare regardless of member order');

  t.log.info('=== 4. combinations ===');
  const refused = function (ops) {
    log.debug("Entering refused().");
    log.debug("Leaving refused().");
    return !MetadataPolicy.validate({ t: { p: ops } }, []).ok;
  };
  t.check(refused({ one_of: ['a'], add: ['a'] }) &&
          refused({ one_of: ['a'], subset_of: ['a'] }) &&
          refused({ one_of: ['a'], superset_of: ['a'] }) &&
          refused({ value: ['a'], add: ['b'] }) &&
          refused({ value: 'a', one_of: ['b'] }) &&
          refused({ value: ['a', 'x'], subset_of: ['a'] }) &&
          refused({ value: ['a'], superset_of: ['a', 'b'] }) &&
          refused({ value: null, essential: true }) &&
          refused({ value: null, default: 'a' }) &&
          refused({ add: ['x'], subset_of: ['a'] }) &&
          refused({ subset_of: ['a'], superset_of: ['a', 'b'] }) &&
          refused({ essential: 'yes' }) && refused({ add: 'a' }),
          '4a. each combination 6.1.3.1 disallows is a policy error');
  t.check(!refused({ value: ['a'], add: ['a'], subset_of: ['a', 'b'],
                     superset_of: ['a'], essential: true }) &&
          !refused({ value: null, subset_of: ['a'] }) &&
          !refused({ one_of: ['a'], default: 'a', essential: true }),
          '4b. and the allowed ones pass');
  const conflict = MetadataPolicy.resolve([
    { metadata_policy: { t: { p: { value: ['a'] } } } },
    { metadata_policy: { t: { p: { subset_of: ['b'] } } } }]);
  t.check(!conflict.ok && conflict.code === 'STS-OIDFED-0002',
          '4c. two valid policies that merge into a forbidden combination ' +
          'refuse the chain (6.1.4.1)', JSON.stringify(conflict));

  t.log.info('=== 5. critical operators ===');
  const ignored = MetadataPolicy.resolve([
    { metadata_policy: { t: { p: { regexp: '^a', default: 'a' } } } }]);
  const critical = MetadataPolicy.resolve([
    { metadata_policy_crit: ['regexp'] },
    { metadata_policy: { t: { p: { regexp: '^a' } } } }]);
  t.check(ignored.ok && same(ignored.policy, { t: { p: { default: 'a' } } }) &&
          !critical.ok && critical.code === 'STS-OIDFED-0004',
          '5a. an unknown operator is ignored, and refused once any ' +
          'statement in the chain makes it critical');

  t.log.info('=== 6. scope ===');
  const scoped = MetadataPolicy.applyToType('oauth_client',
    { scope: 'openid email admin' },
    { scope: { subset_of: ['openid', 'email', 'profile'],
               superset_of: ['openid'] } });
  t.check(scoped.ok && scoped.metadata.scope === 'openid email',
          '6a. scope is narrowed as its values and joined again',
          JSON.stringify(scoped));
  t.check(!MetadataPolicy.applyToType('t', { p: 'a b' },
            { p: { subset_of: ['a'] } }).ok,
          '6b. any other string meeting an array operator is a type error');

  t.log.info('=== 7. constraints ===');
  const fourChain = function (constraints) {
    log.debug("Entering fourChain().");
    log.debug("Leaving fourChain().");
    return [
      { iss: 'https://le.example.com', sub: 'https://le.example.com' },
      { iss: 'https://i1.example.com', sub: 'https://le.example.com',
        constraints: constraints.i1 },
      { iss: 'https://i2.example.com', sub: 'https://i1.example.com',
        constraints: constraints.i2 },
      { iss: 'https://ta.example.com', sub: 'https://i2.example.com',
        constraints: constraints.ta }];
  };
  const ok = function (c) {
    log.debug("Entering ok().");
    log.debug("Leaving ok().");
    return MetadataPolicy.checkConstraints(fourChain(c)).ok;
  };
  t.check(ok({ ta: { max_path_length: 2 } }) &&
          ok({ ta: { max_path_length: 2 }, i2: { max_path_length: 1 } }) &&
          ok({ i1: { max_path_length: 0 } }) &&
          !ok({ ta: { max_path_length: 1 } }),
          '7a. max_path_length: 6.2.1\'s three passing examples and its ' +
          'failing one');
  const naming = function (who, rule, names) {
    log.debug("Entering naming().");
    const c = {};
    c[who] = { naming_constraints: {} };
    c[who].naming_constraints[rule] = names;
    log.debug("Leaving naming().");
    return ok(c);
  };
  t.check(naming('ta', 'permitted', ['.example.com']) &&
          !naming('ta', 'permitted', ['.example.org']) &&
          !naming('i2', 'excluded', ['le.example.com']) &&
          !naming('ta', 'permitted', ['example.com']),
          '7b. naming constraints: ".example.com" admits hosts below it, a ' +
          'bare name only itself, and exclusion wins');
  const stripped = MetadataPolicy.stripEntityTypes(
    { federation_entity: {}, openid_provider: {}, openid_relying_party: {} },
    [{}, { iss: 'a', sub: 'b',
           constraints: { allowed_entity_types: ['openid_provider'] } }]);
  t.check(same(Object.keys(stripped).sort(),
               ['federation_entity', 'openid_provider']) &&
          MetadataPolicy.constraintsProblem(
            { allowed_entity_types: ['federation_entity'] }) !== '',
          '7c. allowed_entity_types strips the rest and never ' +
          'federation_entity, which it may not name');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oidfed_metadata_policy',
  describe: 'OpenID Federation metadata policy and constraints (#132): the ' +
            'spec\'s 6.1.5 example, table 1, merges, combinations, critical ' +
            'operators, scope, and 6.2',
  run: run
};
