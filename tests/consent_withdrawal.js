'use strict';
//
// File: consent_withdrawal.js
//
// ===========================================================================
// WITHDRAWN MEANS WITHDRAWN (#172): THE DECISION THE REFRESH GRANT ASKS, AND
// THE REVOCATION A WITHDRAWAL MAKES, IN PROCESS.
//
// `tests/vendored/sts_consent_withdrawal.js` drives the whole thing over HTTP
// in both modes: a withdrawal through each door, the refresh refused, the
// access token inactive at introspection, a re-consent reviving nothing, the
// portal's form. What is HERE is what cannot be reached that way:
//
//   * **THE CLOCK.** `refreshRefusal()` compares a withdrawal instant with the
//     instant a grant was made, to the millisecond, and a tie REFUSES. Over
//     HTTP the two instants are whatever the clock made them; here they are
//     chosen, so the tie, the millisecond either side and a consent stamped
//     in the same second as the grant are each one assertion.
//   * **SEVERAL SCOPES AND SEVERAL ANSWERS.** Which of the person's own
//     consent, the global override, a personal withdrawal and a global one
//     decides each scope, and that ONE withdrawn scope refuses the whole
//     token — a pure function of four attribute sets.
//   * **THE REVOCATION WALK'S PREDICATE**: which token records a withdrawal
//     revokes (this client, this person, this scope — or the audience, for an
//     access token), who a global withdrawal spares, and that a refresh token
//     takes its grant with it through the #102 bookkeeping.
//   * **THE GENERIC DOOR IS SHUT**: `applications.updateApplication()`
//     refuses to remove an `oauthGlobalConsent` value unless the consent
//     register is the caller, and the withdrawal instant is written onto the
//     application's entry, replacing an earlier one for the same scope.
//
// Everything runs on a PRIVATE `Consent` instance built with stub
// dependencies, so the process-wide slots are touched only by the last
// section, which puts back what it found.
// ===========================================================================

delete process.env.CONFIG_FILE;

const consentModule = require('../common/consent');
const applications = require('../common/applications');

const log = require('bunyan').createLogger({ name: 'consent_withdrawal',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// THE STUBS.
// ---------------------------------------------------------------------------

// One person's two attributes, as the directory would hold them.
function directoryStub(seed) {
  log.debug("Entering directoryStub().");
  const consents = {};
  const withdrawals = {};
  Object.keys(seed || {}).forEach(function (key) {
    consents[key] = (seed[key].consents || []).slice(0);
    withdrawals[key] = (seed[key].withdrawals || []).slice(0);
  });
  function remover(store) {
    log.debug("Entering remover().");
    log.debug("Leaving remover().");
    return function (key, values) {
      log.debug("Entering remove().");
      store[key] = (store[key] || []).filter(function (one) {
        return values.indexOf(one) < 0;
      });
      log.debug("Leaving remove().");
      return { ok: true, dn: 'uid=' + key };
    };
  }
  function adder(store) {
    log.debug("Entering adder().");
    log.debug("Leaving adder().");
    return function (key, values) {
      log.debug("Entering add().");
      store[key] = (store[key] || []).concat(values);
      log.debug("Leaving add().");
      return { ok: true, dn: 'uid=' + key };
    };
  }
  log.debug("Leaving directoryStub().");
  return {
    consents: consents,
    withdrawals: withdrawals,
    hooks: {
      consentsOf: function (key) {
        log.debug("Entering consentsOf().");
        log.debug("Leaving consentsOf().");
        return { values: (consents[key] || []).slice(0) };
      },
      addConsent: adder(consents),
      removeConsent: remover(consents),
      listConsents: function () {
        log.debug("Entering listConsents().");
        log.debug("Leaving listConsents().");
        return [];
      },
      withdrawalsOf: function (key) {
        log.debug("Entering withdrawalsOf().");
        log.debug("Leaving withdrawalsOf().");
        return { values: (withdrawals[key] || []).slice(0) };
      },
      addWithdrawal: adder(withdrawals),
      removeWithdrawal: remover(withdrawals)
    }
  };
}

// Token records, admin_stats.js's shape, and the four functions of it the
// walk calls.
function statsStub(records) {
  log.debug("Entering statsStub().");
  const revoked = [];
  const self = {
    revoked: revoked,
    identityKeyOf: function (value) {
      log.debug("Entering identityKeyOf().");
      log.debug("Leaving identityKeyOf().");
      return String(value || '').toLowerCase();
    },
    holderKeyOf: function (username) {
      log.debug("Entering holderKeyOf().");
      log.debug("Leaving holderKeyOf().");
      return String(username || '').toLowerCase();
    },
    revoke: function (jti) {
      log.debug("Entering revoke().");
      if (revoked.indexOf(jti) >= 0) {
        log.debug("Leaving revoke(). Already.");
        return false;
      }
      revoked.push(jti);
      log.debug("Leaving revoke().");
      return true;
    },
    revokeWhere: function (predicate) {
      log.debug("Entering revokeWhere().");
      let count = 0;
      records.forEach(function (record) {
        if (revoked.indexOf(record.jti) >= 0) {
          return;
        }
        if (predicate(record) && self.revoke(record.jti)) {
          count += 1;
        }
      });
      log.debug("Leaving revokeWhere().");
      return count;
    }
  };
  log.debug("Leaving statsStub().");
  return self;
}

// A private instance: the real module's defaults, with the named deps
// replaced.
function instance(over) {
  log.debug("Entering instance().");
  const deps = Object.assign(consentModule.Consent.defaultDeps(), over);
  log.debug("Leaving instance().");
  return new consentModule.Consent(deps);
}

function fixedConfig(values) {
  log.debug("Entering fixedConfig().");
  log.debug("Leaving fixedConfig().");
  return { value: function (key) {
    log.debug("Entering value().");
    log.debug("Leaving value().");
    return values[key];
  } };
}

const FAPI_OFF = {
  honoursGlobalConsent: function () {
    log.debug("Entering honoursGlobalConsent().");
    log.debug("Leaving honoursGlobalConsent().");
    return true;
  },
  requiresConsent: function () {
    log.debug("Entering requiresConsent().");
    log.debug("Leaving requiresConsent().");
    return false;
  }
};

// An application registry of one entry per client, fields as given.
function registryStub(entries) {
  log.debug("Entering registryStub().");
  log.debug("Leaving registryStub().");
  return Object.assign({}, applications, {
    get: function (identifier) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return entries[identifier] ? { identifier: identifier,
                                     fields: entries[identifier] } : null;
    },
    forPermission: function () {
      log.debug("Entering forPermission().");
      log.debug("Leaving forPermission().");
      return null;
    }
  });
}

function run(t) {
  log.debug("Entering run().");
  const probe = instance({});
  const G = Date.UTC(2026, 8, 23, 12, 0, 0, 500);   // the grant, .500

  // -------------------------------------------------------------------------
  t.log.info('the withdrawal stamp: a GeneralizedTime to the millisecond');
  // -------------------------------------------------------------------------
  t.equal(probe.withdrawnStamp(G), '20260923120000.500Z',
          'the consent grammar\'s stamp with RFC 4517\'s fraction, because a ' +
          'withdrawal is compared with a grant instant and two acts in one ' +
          'second must still be told apart');
  t.equal(probe.stampMs('20260923120000.500Z'), G,
          'and it reads back to the same instant');
  t.equal(probe.stampMs('20260923120000Z'), G - 500,
          'a CONSENT\'s stamp reads as the start of its second');
  t.check(isNaN(probe.stampMs('yesterday')), 'anything else is not a time');
  const parsed = probe.parseWithdrawalValue(
    '20260923120000.500Z openid a client with spaces');
  t.equal(parsed.client, 'a client with spaces',
          'the client_id is LAST and takes the remainder, the consent ' +
          'grammar\'s rule');
  t.equal(probe.parseWithdrawalValue('20260923120000Z openid c').scope, '',
          'A CONSENT VALUE IS NOT A WITHDRAWAL: the stamp without its ' +
          'fraction is refused, so the two attributes cannot be confused');
  t.equal(probe.parseWithdrawalValue('20260923120000.500Z read', true).scope,
          'read', 'the global form is `<stamp> <scope>`');

  // -------------------------------------------------------------------------
  t.log.info('refreshRefusal(): the clock, and a tie refuses');
  // -------------------------------------------------------------------------
  function judge(seed, entries, settings, asked) {
    log.debug("Entering judge().");
    const d = directoryStub(seed);
    const c = instance({
      config: fixedConfig(Object.assign({
        'oauth2.consentRequired': true,
        'oauth2.refreshRequiresConsent': true }, settings || {})),
      fapi: FAPI_OFF,
      applications: registryStub(entries || {}),
      stats: statsStub([])
    });
    c.setDirectory(d.hooks);
    log.debug("Leaving judge().");
    return c.refreshRefusal(Object.assign({ username: 'alice',
      clientId: 'webapp', scope: 'openid profile', grantAt: G,
      grantType: 'authorization_code' }, asked || {}));
  }
  const agreed = ['20260923115900Z openid webapp',
                  '20260923115900Z profile webapp'];
  t.equal(judge({ alice: { consents: agreed } }), null,
          'a grant both of whose scopes the person agreed to before it stands');
  t.equal(judge({ alice: { consents: agreed,
    withdrawals: ['20260923120000.499Z profile webapp'] } }), null,
          'a withdrawal ONE MILLISECOND BEFORE the grant refuses nothing: ' +
          'the grant was made after it, under a consent given again');
  const tie = judge({ alice: { consents: agreed,
    withdrawals: ['20260923120000.500Z profile webapp'] } });
  t.equal(tie && tie.errorCode, 'STS-OAUTH-0615',
          'A WITHDRAWAL IN THE SAME MILLISECOND AS THE GRANT REFUSES IT — ' +
          'the safe side of a tie');
  const after = judge({ alice: { consents: agreed,
    withdrawals: ['20260923120000.501Z profile webapp'] } });
  t.equal(after && after.scope, 'profile',
          'one after it refuses, and names the scope');
  t.equal(judge({ alice: { consents: agreed,
    withdrawals: ['20260923130000.000Z profile otherapp'] } }), null,
          'a withdrawal for ANOTHER application refuses nothing here');
  t.equal(judge({ alice: { consents: agreed,
    withdrawals: ['20260923130000.000Z email webapp'] } }), null,
          'nor one of a scope this token does not carry');

  // -------------------------------------------------------------------------
  t.log.info('refreshRefusal(): several scopes, one withdrawn, whole token');
  // -------------------------------------------------------------------------
  const several = judge({ alice: { consents: agreed.concat([
    '20260923115900Z email webapp']),
    withdrawals: ['20260923130000.000Z email webapp'] } },
    null, null, { scope: 'openid profile email' });
  t.equal(several && several.errorCode, 'STS-OAUTH-0615',
          'ONE WITHDRAWN SCOPE REFUSES THE WHOLE REFRESH TOKEN — the grant ' +
          'is not narrowed to the two still agreed (the decision on #172)');
  const reconsented = judge({ alice: {
    consents: ['20260923115900Z openid webapp',
               '20260923140000Z profile webapp'],
    withdrawals: ['20260923130000.000Z profile webapp'] } });
  t.equal(reconsented && reconsented.errorCode, 'STS-OAUTH-0615',
          'A RE-CONSENT REVIVES NOTHING: the person agreed to `profile` ' +
          'again after withdrawing it, and the token granted before the ' +
          'withdrawal is still refused');

  // -------------------------------------------------------------------------
  t.log.info('refreshRefusal(): the global override, withdrawn and not');
  // -------------------------------------------------------------------------
  const globalOnly = { webapp: { oauthGlobalConsent: ['openid', 'profile'] } };
  t.equal(judge({}, globalOnly), null,
          'a grant the override covered stands, with nothing on the entry');
  const gone = judge({}, { webapp: {
    oauthGlobalConsent: ['openid', 'profile'],
    oauthGlobalConsentWithdrawn: ['20260923130000.000Z profile'] } });
  t.equal(gone && gone.errorCode, 'STS-OAUTH-0615',
          'AN OVERRIDE WITHDRAWN AFTER THE GRANT REFUSES IT EVEN THOUGH IT ' +
          'WAS ADDED BACK — re-adding covers new grants, not old ones');
  t.equal(judge({ alice: { consents: ['20260923115900Z profile webapp'] } },
    { webapp: { oauthGlobalConsent: ['openid'],
                oauthGlobalConsentWithdrawn: ['20260923130000.000Z ' +
                                              'profile'] } }), null,
          'but a person who agreed to it THEMSELVES before the grant is not ' +
          'refused: their grant stood on their own consent as well');
  const lateOwn = judge({ alice: { consents: [
    '20260923140000Z profile webapp'] } }, { webapp: {
    oauthGlobalConsent: ['openid'],
    oauthGlobalConsentWithdrawn: ['20260923130000.000Z profile'] } });
  t.equal(lateOwn && lateOwn.errorCode, 'STS-OAUTH-0615',
          'and one who agreed only AFTER the override was withdrawn is: a ' +
          'consent given later is not the one the grant was made under');

  // -------------------------------------------------------------------------
  t.log.info('refreshRefusal(): nothing recorded, and the setting');
  // -------------------------------------------------------------------------
  const none = judge({});
  t.equal(none && none.errorCode, 'STS-OAUTH-0616',
          'A GRANT FROM THE AUTHORIZATION ENDPOINT THAT NO RECORDED CONSENT ' +
          'COVERED is refused while consent is required — a token minted ' +
          'while consent was off');
  t.equal(judge({}, null, { 'oauth2.refreshRequiresConsent': false }), null,
          'oauth2.refreshRequiresConsent off renews it (the warned-about ' +
          'weaker option)');
  t.equal(judge({}, null, { 'oauth2.consentRequired': false }), null,
          'and consent not required renews it: nobody is asked, so nothing ' +
          'is missing');
  t.equal(judge({}, null, null, { grantType: 'password' }), null,
          'A GRANT THAT NEVER ASKS ANYBODY — the password grant — is held to ' +
          'withdrawals only');
  const pwWithdrawn = judge({ alice: { withdrawals: [
    '20260923130000.000Z profile webapp'] } }, null, null,
    { grantType: 'password' });
  t.equal(pwWithdrawn && pwWithdrawn.errorCode, 'STS-OAUTH-0615',
          'and to those it IS held: a person who withdrew a scope from this ' +
          'client withdrew it from every grant of it');
  const lateConsent = judge({ alice: { consents: [
    '20260923115900Z openid webapp', '20260923140000Z profile webapp'] } });
  t.equal(lateConsent && lateConsent.errorCode, 'STS-OAUTH-0616',
          'a consent recorded only AFTER the grant does not cover it');
  t.equal(judge({ alice: { consents: ['20260923120000Z openid webapp',
                                      '20260923120000Z profile webapp'] } }),
          null,
          'A CONSENT STAMPED IN THE SAME SECOND AS THE GRANT covers it: the ' +
          'screen is answered before the code is minted, and a consent is ' +
          'stamped to the second');
  t.equal(judge({}, null, null, { username: '' }), null,
          'a token with no person behind it is not judged');
  const noInstant = judge({ alice: { consents: agreed, withdrawals: [
    '20200101000000.000Z openid webapp'] } }, null, null,
    { grantAt: undefined });
  t.equal(noInstant && noInstant.errorCode, 'STS-OAUTH-0615',
          'a token with no grant instant is judged the oldest grant there ' +
          'could be, so any withdrawal refuses it');

  // -------------------------------------------------------------------------
  t.log.info('revokeIssuedUnder(): which tokens a withdrawal revokes');
  // -------------------------------------------------------------------------
  const records = [
    { jti: 'at-1', kind: 'access_token', client_id: 'webapp',
      username: 'alice', scope: 'openid profile' },
    { jti: 'rt-1', kind: 'refresh_token', client_id: 'webapp',
      username: 'alice', scope: 'openid profile offline_access' },
    { jti: 'at-narrow', kind: 'access_token', client_id: 'webapp',
      username: 'alice', scope: 'openid' },
    { jti: 'at-api', kind: 'access_token', client_id: 'webapp',
      username: 'alice', scope: '', audience: 'profile' },
    { jti: 'at-other-client', kind: 'access_token', client_id: 'otherapp',
      username: 'alice', scope: 'profile' },
    { jti: 'at-bob', kind: 'access_token', client_id: 'webapp',
      username: 'bob', scope: 'profile' },
    { jti: 'id-1', kind: 'id_token', client_id: 'webapp',
      username: 'alice', scope: 'profile' }
  ];
  const stats = statsStub(records);
  const families = [];
  const grants = {
    familyOfRefresh: function (claims) {
      log.debug("Entering familyOfRefresh().");
      log.debug("Leaving familyOfRefresh().");
      return 'fam-' + claims.jti;
    },
    grantMembersOf: function (family, jti) {
      log.debug("Entering grantMembersOf().");
      log.debug("Leaving grantMembersOf().");
      return family === 'fam-rt-1' ? [jti, 'at-narrow'] : [jti];
    },
    revokeFamily: function (family) {
      log.debug("Entering revokeFamily().");
      families.push(family);
      log.debug("Leaving revokeFamily().");
      return Promise.resolve(true);
    }
  };
  const walker = instance({ stats: stats, grants: function () {
    log.debug("Entering grants().");
    log.debug("Leaving grants().");
    return grants;
  } });
  const count = walker.revokeIssuedUnder({ username: 'alice',
    clientId: 'webapp', scopes: ['profile'] }, 'a test withdrawal');
  t.equal(stats.revoked.slice(0).sort().join(' '),
          'at-1 at-api at-narrow rt-1',
          'THIS CLIENT, THIS PERSON, THIS SCOPE: the access token and the ' +
          'refresh token carrying `profile`, the access token addressed to ' +
          'it as an audience, and — through the refresh token\'s grant — the ' +
          'access token minted beside it whose own scope was narrowed. Not ' +
          'another client\'s, not Bob\'s, and never an ID Token');
  t.equal(count, 4, 'and the count says so');
  t.equal(families.join(' '), 'fam-rt-1',
          'the refresh token\'s family is revoked BY ID as well, for a ' +
          'member minted on another node at this instant');

  const spareStats = statsStub(records);
  const spareWalker = instance({ stats: spareStats, grants: function () {
    log.debug("Entering grants().");
    log.debug("Leaving grants().");
    return grants;
  } });
  spareWalker.revokeIssuedUnder({ clientId: 'webapp', scopes: ['profile'],
    spare: function (holder) {
      log.debug("Entering spare().");
      log.debug("Leaving spare().");
      return holder === 'alice';
    } }, 'a test global withdrawal');
  t.equal(spareStats.revoked.join(' '), 'at-bob',
          'A GLOBAL WITHDRAWAL reaches everybody but the people it spares — ' +
          'those who agreed to the scope themselves');

  // -------------------------------------------------------------------------
  t.log.info('withdrawing: the record goes, the instant is written, the ' +
             'tokens are revoked, and a later withdrawal replaces the earlier');
  // -------------------------------------------------------------------------
  const d = directoryStub({ alice: { consents: agreed, withdrawals: [
    '20200101000000.000Z profile webapp'] } });
  const actStats = statsStub(records);
  const actor = instance({ stats: actStats, grants: function () {
    log.debug("Entering grants().");
    log.debug("Leaving grants().");
    return grants;
  } });
  t.check(actor.setDirectory(d.hooks), 'the seven-hook directory is taken');
  const result = actor.revoke('alice', 'webapp', 'profile', 'admin');
  t.check(result.ok, 'the revoke succeeds');
  t.equal(d.consents.alice.join(' '), '20260923115900Z openid webapp',
          'the consent to profile is off the entry, openid is not');
  t.equal(d.withdrawals.alice.length, 1,
          'ONE withdrawal value for the pair: the earlier one was replaced');
  t.check(/^\d{14}\.\d{3}Z profile webapp$/.test(d.withdrawals.alice[0]),
          'and it is the new instant, to the millisecond: ' +
          d.withdrawals.alice[0]);
  t.equal(result.revoked, 4, 'the reply counts the tokens revoked');
  t.check(/revoked/.test(result.message) &&
          !/Nothing already ISSUED/.test(result.message),
          'and says so, where it used to say nothing issued was touched');
  const refused = actor.setDirectory({ consentsOf: d.hooks.consentsOf,
    addConsent: d.hooks.addConsent, removeConsent: d.hooks.removeConsent,
    listConsents: d.hooks.listConsents });
  t.equal(refused, false,
          'A FOUR-HOOK DIRECTORY IS REFUSED WHOLE: a store that could record ' +
          'a consent and not its withdrawal would let a re-consent revive ' +
          'every token granted before it');

  const app = actor.revokeApplication('alice', 'webapp', 'alice');
  t.check(app.ok && app.removed === 1,
          'revokeApplication() withdraws what is left for the application');
  t.equal((d.consents.alice || []).length, 0, 'and the entry holds nothing');
  t.equal(actor.revokeApplication('alice', 'webapp', 'alice').ok, false,
          'and withdrawing it again is refused: nothing is held');

  // -------------------------------------------------------------------------
  t.log.info('the generic door refuses to remove a global consent, and the ' +
             'withdrawal instant goes onto the application');
  // -------------------------------------------------------------------------
  const before = applications.directoryInstalled();
  const written = {};
  const entryAttrs = { appIdentifier: ['webapp'], cn: ['webapp'],
                       oauthClientId: ['webapp'],
                       oauthGlobalConsent: ['openid', 'profile'],
                       oauthGlobalConsentWithdrawn: [
                         '20200101000000.000Z profile',
                         '20200101000000.000Z email'] };
  applications.setDirectory({
    allApplications: function () {
      log.debug("Entering allApplications().");
      log.debug("Leaving allApplications().");
      return [];
    },
    readApplication: function (identifier) {
      log.debug("Entering readApplication().");
      log.debug("Leaving readApplication().");
      return identifier === 'webapp'
        ? { dn: 'cn=webapp', origin: 'test', createdAt: '', modifiedAt: '',
            operational: [], attributes: written.webapp || entryAttrs }
        : null;
    },
    writeApplication: function (identifier, attributes) {
      log.debug("Entering writeApplication().");
      written[identifier] = attributes;
      log.debug("Leaving writeApplication().");
      return true;
    }
  });
  try {
    const generic = applications.updateApplication('webapp', {
      attribute: 'oauthGlobalConsent', mode: 'remove', value: 'profile' });
    t.equal(generic.ok, false,
            'A GENERIC REMOVE OF A GLOBAL CONSENT IS REFUSED: it would take ' +
            'the value off and leave every token issued under it working');
    t.check(/revoke-global-consent/.test((generic.errors || []).join(' ')),
            'and the refusal names the door that does the whole withdrawal');
    t.check(!written.webapp, 'and nothing was written');
    const direct = applications.updateApplication('webapp', {
      attribute: 'oauthGlobalConsentWithdrawn', mode: 'remove',
      value: '20200101000000.000Z profile' });
    t.equal(direct.ok, false,
            'the withdrawal attribute itself is not editable at all: a form ' +
            'that removed it would bring a withdrawn grant back');
    t.check(applications.noteGlobalConsentWithdrawn('webapp', 'profile',
                                                    '20260923130000.000Z'),
            'the register writes the instant onto the application');
    const values = (written.webapp || {}).oauthGlobalConsentWithdrawn ||
                   (written.webapp || {}).oauthglobalconsentwithdrawn || [];
    t.equal(values.slice(0).sort().join(' | '),
            '20200101000000.000Z email | 20260923130000.000Z profile',
            'REPLACING the earlier value for that scope and leaving the ' +
            'other scope\'s alone');
  } finally {
    applications.setDirectory(before);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'consent_withdrawal',
  describe: 'a withdrawn consent refuses the refresh grant and revokes what ' +
            'was issued under it (#172)',
  run: run
};
