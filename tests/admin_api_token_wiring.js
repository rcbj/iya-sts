'use strict';
//
// File: admin_api_token_wiring.js
//
// ===========================================================================
// EVERY PATH THAT RUNS A JOB ARRANGES AN /admin-api ACCESS TOKEN.
//
// `/admin-api` began requiring an OAuth 2.0 access token on 2026-09-09, and
// twenty-three jobs drive that API. A run that reaches them without a token
// does not fail usefully: it fails NINETEEN times, in nineteen different
// vocabularies, and two of those nineteen do not mention the API at all —
// `sts_saml_encryption` reported that this identity provider would not encrypt
// an assertion, because the service provider certificate it writes through
// `/admin-api` was refused and it does not assert that write.
//
// That is exactly what happened. The change that gated the API taught the two
// DOCKER launchers to mint a token and missed the third path, where the
// service is a throwaway `run-report.js` starts itself — `./run-coverage.sh`,
// `./local-run-tests.sh --no-docker`, and a bare `node run-report.js`. CI's
// coverage job ran the whole protocol half against a gated API with no
// credential.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Every claim here is a comparison between FILES in this repository — the two
// launchers and `tests/tools/run-report.js` — which no running service could
// be asked. It is `readme_ports.js`'s shape (a README against config.js) and
// `xacml_pep.js`'s (a Dockerfile against a module list). Nothing here binds a
// port, starts a service or mints anything.
//
// ---------------------------------------------------------------------------
// WHAT IT DOES *NOT* TRY TO BE.
//
// It is not a test that a token WORKS — `tests/vendored/sts_admin_api_auth.js`
// drives the real gate and its refusals, and it already fails loudly on an
// empty `STS_ADMIN_API_TOKEN`. That job named this bug precisely on the run
// that found it. What no job could see is the launcher that never gave it one,
// because a launcher is not something a job can look at.
//
// **THE ORDERING IS THE PART WORTH PINNING AND IT IS NOT OBVIOUS.**
// `applications.js` seeds `sts-management-api` with a secret minted at every
// start, readable only THROUGH the API it unlocks. So a secret chosen after
// the child is up is a secret nobody can present, and the mint that follows it
// fails with a message about a client secret rather than about ordering. Both
// halves are asserted, and so is the direction between them.
// ===========================================================================

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

// The two docker launchers, which mint a token themselves because the service
// is a CONTAINER they brought up — this runner cannot pin a secret into
// something that was already started, which is the same argument run-report.js
// makes about `--service-url`.
const MINTING_LAUNCHERS = ['local-run-tests.sh', 'docker-run-tests.sh'];

function run(t) {
  t.log.info('=== the two docker launchers mint one themselves ===');
  MINTING_LAUNCHERS.forEach(function (name) {
    const text = read(name);
    t.check(text.indexOf('tests/tools/admin-api-token.js') !== -1,
            name + ' calls tests/tools/admin-api-token.js',
            'that file is the ONE place a run obtains a token; a launcher ' +
            'that asked the token endpoint itself would restate the client ' +
            'id, the grant and the form, and go on passing against a ' +
            'service that had changed any of them');
    t.check(/export\s+STS_ADMIN_API_TOKEN/.test(text),
            name + ' exports STS_ADMIN_API_TOKEN',
            'run-report.js reads it from the environment and hands it to ' +
            'every job together with the attach-admin-token.js preload; a ' +
            'token minted and not exported reaches no job at all');
  });

  // -----------------------------------------------------------------------
  // AND THE THIRD PATH, WHICH IS THE ONE THAT WAS MISSING.
  //
  // `./run-coverage.sh` is deliberately NOT on the list above and must not
  // join it: it never passes --service-url, because V8 collects coverage from
  // inside the process it measures and only a service this runner started can
  // be measured. So the service is a throwaway, and the credential for it can
  // only be arranged by the thing that starts it.
  // -----------------------------------------------------------------------
  t.log.info('=== run-report.js arranges one for a service it starts ===');
  const runner = read('tests/tools/run-report.js');
  const pin = runner.indexOf('pinTheManagementApiSecret();');
  const start = runner.indexOf('await service.start(');
  const mint = runner.indexOf('await mintTheManagementApiToken(');

  t.check(pin !== -1, 'it pins a management API client secret',
          'without adminApi.clientSecret the seeded client gets a secret ' +
          'minted per start that is readable only through the gated API, so ' +
          'no token can be obtained for the service at all');
  t.check(mint !== -1, 'and mints a token against the service it started',
          'this is the whole of what ./run-coverage.sh, --no-docker and a ' +
          'bare run-report.js depend on');
  t.check(start !== -1, 'and it is the thing that starts that service',
          'if this call moved, the two assertions below would be comparing ' +
          'positions of something that is no longer there');

  // The direction, and it is the assertion this file exists for.
  t.check(pin !== -1 && start !== -1 && pin < start,
          'the secret is pinned BEFORE the service starts',
          'the seeded client reads adminApi.clientSecret while it is being ' +
          'seeded, so a secret set afterwards is one the running service has ' +
          'never heard of and the mint fails naming a client secret rather ' +
          'than naming this ordering');
  t.check(mint !== -1 && start !== -1 && start < mint,
          'and the token is minted AFTER it is answering',
          'the token comes from that service\'s own /oauth2/token endpoint, ' +
          'so there is nothing to ask until it is up');

  // -----------------------------------------------------------------------
  // A HANDED-IN SERVICE IS WARNED ABOUT RATHER THAN FIXED, and that refusal
  // is deliberate enough to pin: this runner cannot know the client secret a
  // service somebody else started chose, and reading it back goes through the
  // very API that is asking for the token. Whoever started it is who can mint
  // against it. What must not happen is silence — that is the failure this
  // whole file is about, one layer along.
  // -----------------------------------------------------------------------
  t.log.info('=== and says so when it cannot ===');
  t.check(/instance\.external && !process\.env\.STS_ADMIN_API_TOKEN/
    .test(runner),
          'an external service with no token handed in is reported',
          'a --service-url run that nobody minted for reaches the jobs as ' +
          'nineteen unrelated-looking failures, which is the thing this file ' +
          'exists to keep from happening quietly');

  // The preload, which is how a job actually presents the token. A run that
  // minted one and never attached it is the same outcome as never minting.
  t.check(runner.indexOf('attach-admin-token.js') !== -1,
          'and every job is given the preload that presents it',
          'the token is carried into twenty-three jobs by that preload ' +
          'rather than by each of them growing an HTTP client of its own');
}

module.exports = {
  name: 'admin_api_token_wiring',
  describe: 'every path that runs a job arranges an /admin-api access token',
  run: run
};
