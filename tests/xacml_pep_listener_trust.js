// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/xacml_pep_listener_trust.js
//
// ===========================================================================
// A REMOTE PEP LISTENER THAT REQUIRES A CLIENT CERTIFICATE NEEDS A TRUST
// SOURCE (2026-11-16), held against `xacml/xacml_pep_listener_tuning.ts`'s
// `parse()`, which `set-pep-listener` and `set-pep-environment-tuning` both
// save through. The cluster job's listener table found the PEP's API
// listener reporting `requireClientCertificate` while it asked nobody and
// admitted everybody; the PEP now refuses that listener itself
// (STS-XPEP-0137), and this service refuses to save what it can see is
// such a listener (STS-XACML-0281):
//
//   T1. HTTPS, API, required, no anchors and trustIssuedClientCertificates
//       off: refused, the reason names both sources.
//   T2. The same with a trust anchors file: saved, and required.
//   T3. The same with trustIssuedClientCertificates on (the API default):
//       saved — whether PEP_AUTHZEN_CLIENT_CA is set is the PEP's to see.
//   T4. A reverse-proxy listener, required, no anchors: refused even with
//       trustIssuedClientCertificates on (it has no issuing CA to trust),
//       and the reason names the anchors file alone.
//   T5. Plain HTTP: the requirement is forced off, so nothing is refused.
//   T6. Not required: no trust source is needed.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({
  name: 'xacml_pep_listener_trust',
  level: process.env.LOG_LEVEL || 'info'
});

function run(t) {
  log.debug("Entering run().");
  const tuning = require('../xacml/xacml_pep_listener_tuning');
  const where = 'Listener "x"';
  const t1 = tuning.parse({ requireClientCertificate: true,
                            trustIssuedClientCertificates: false },
                          where, 'api', true);
  t.check(t1.ok === false && t1.code === 'STS-XACML-0281' &&
          /requireClientCertificate/.test(t1.why) &&
          /trustAnchorsFile/.test(t1.why) &&
          /trustIssuedClientCertificates/.test(t1.why),
          'T1. required with no trust source is refused (STS-XACML-0281)',
          JSON.stringify(t1));
  const t2 = tuning.parse({ requireClientCertificate: true,
                            trustIssuedClientCertificates: false,
                            trustAnchorsFile: '/certs/anchors.pem' },
                          where, 'api', true);
  t.check(t2.ok === true && t2.tuning.requireClientCertificate === true,
          'T2. a trust anchors file is a trust source', JSON.stringify(t2));
  const t3 = tuning.parse({ requireClientCertificate: true },
                          where, 'api', true);
  t.check(t3.ok === true && t3.tuning.trustIssuedClientCertificates === true &&
          t3.tuning.requireClientCertificate === true,
          'T3. the certificates this realm issues are one on an API listener',
          JSON.stringify(t3));
  const t4 = tuning.parse({ requireClientCertificate: true,
                            trustIssuedClientCertificates: true },
                          where, 'proxy', true);
  t.check(t4.ok === false && t4.code === 'STS-XACML-0281' &&
          /trustAnchorsFile/.test(t4.why) &&
          !/trustIssuedClientCertificates/.test(t4.why),
          'T4. a reverse-proxy listener needs a trust anchors file',
          JSON.stringify(t4));
  const t5 = tuning.parse({ requireClientCertificate: true,
                            trustIssuedClientCertificates: false },
                          where, 'api', false);
  t.check(t5.ok === true && t5.tuning.requireClientCertificate === false,
          'T5. plain HTTP forces the requirement off and refuses nothing',
          JSON.stringify(t5));
  const t6 = tuning.parse({ requireClientCertificate: false,
                            trustIssuedClientCertificates: false },
                          where, 'proxy', true);
  t.check(t6.ok === true, 'T6. not required, no trust source is needed',
          JSON.stringify(t6));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'xacml_pep_listener_trust',
  describe: 'A remote PEP listener that requires a client certificate is ' +
            'refused on save without a trust source to verify one against',
  run: run
};
