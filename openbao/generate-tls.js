'use strict';
//
// File: openbao/generate-tls.js
//
// ===========================================================================
// THE SECRET STORE'S LISTENER CERTIFICATE, MINTED BY THIS REPOSITORY'S OWN
// ENCODER (2026-09-12).
//
// The OpenBao container needs a TLS listener before anything else can happen,
// because **the client certificate authentication this stack uses is only
// reachable over TLS** — a client certificate on a plaintext listener is not a
// thing. So a server pair has to exist before the server starts, which is the
// same bootstrap `postgres/generate-tls.sh` solves for the database.
//
// **IT IS NOT `openssl`, AND THAT IS THE IMAGE RATHER THAN A PREFERENCE.**
// `openbao/openbao` is Alpine with `bao` and busybox in it: no openssl, no
// curl, no jq. The certificate therefore has to be minted somewhere else and
// left in the volume the server reads, and the obvious somewhere else is the
// image this repository already builds.
//
// **WHICH BUYS THE PROPERTY WORTH HAVING: ONE ENCODER FOR EVERY CERTIFICATE IN
// THE STACK.** `common/vendored/x509.js` is the parent project's PKI code,
// byte-identical, and it is what mints this service's own TLS pair, every
// certificate authority on /admin/pki and every assertion key pair it issues.
// The secret store's listener is now one more certificate from the same
// encoder rather than the one certificate in the stack made by a shell script
// nobody reads.
//
// **A SUBJECT ALTERNATIVE NAME IS NOT OPTIONAL.** Every current client reads
// the SAN and ignores the Common Name (RFC 6125, since 2011), and node has
// enforced that for years — so a certificate with `CN=openbao` and no SAN is
// one the service could not verify, which would leave the operator turning
// verification off and losing the point of the exercise.
//
// It writes NOTHING if a certificate is already there: the pair belongs to the
// volume, the volume outlives the container, and re-minting it on every start
// would break the pin this stack hands the service.
// ===========================================================================

const fs = require('fs');
const path = require('path');

const x509 = require('../common/vendored/x509');
const keyMaterial = require('../common/vendored/key_material');

const DIR = process.env.STS_BAO_TLS_DIR || '/openbao/file/tls';
const CERT = path.join(DIR, 'server.crt');
const KEY = path.join(DIR, 'server.key');

// The names the certificate has to answer to. `openbao` is the compose service
// name — which is what the service dials on the private bridge — and the other
// two are for anybody driving it from inside the container.
const NAMES = String(process.env.STS_BAO_TLS_NAMES || 'openbao,localhost')
  .split(',').map(function (one) { return one.trim(); }).filter(Boolean);
const IPS = String(process.env.STS_BAO_TLS_IPS || '127.0.0.1')
  .split(',').map(function (one) { return one.trim(); }).filter(Boolean);

async function main() {
  fs.mkdirSync(DIR, { recursive: true });
  // THE RAFT DIRECTORY TOO, AND IT BELONGS HERE RATHER THAN IN THE STORE'S
  // CONFIG. OpenBao's raft backend opens its bolt file inside a directory it
  // expects to EXIST; on a fresh volume it does not, and the failure is
  // `no such file or directory` naming a file nobody created. This container
  // is the one that runs as root against that volume, so it is the one that
  // can make the directory and hand it over.
  const dataDir = process.env.STS_BAO_RAFT_DIR ||
                  path.join(path.dirname(DIR), 'raft');
  fs.mkdirSync(dataDir, { recursive: true });
  try {
    fs.chownSync(dataDir, 100, 1000);
  } catch (e) {
    // Reported below with the rest; on a host bind mount this is the ordinary
    // case and the store's own entrypoint chowns what it can.
  }
  if (fs.existsSync(CERT) && fs.existsSync(KEY)) {
    console.log('sts-bao-tls: ' + CERT + ' is already there; nothing was ' +
                'minted. The pair belongs to the volume.');
    return;
  }
  const pair = await keyMaterial.generateKeyPair('rsa-2048');
  const issued = await x509.issueCertificate({
    subject: [{ name: 'CN', value: NAMES[0] || 'openbao' },
              { name: 'O', value: 'mock-sts' }],
    subjectPublicKey: pair.publicPem,
    issuerPrivateKey: pair.privatePem,
    signatureAlg: 'sha256-rsa',
    serial: '01',
    notBefore: new Date().toISOString(),
    notAfter: new Date(Date.now() + 3650 * 24 * 3600 * 1000).toISOString(),
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true,
                  usages: ['digitalSignature', 'keyEncipherment'] },
      extKeyUsage: { present: true, critical: false, usages: ['serverAuth'] },
      subjectKeyIdentifier: { present: true },
      subjectAltName: {
        present: true, critical: false,
        names: NAMES.map(function (one) { return { kind: 'dns', value: one }; })
          .concat(IPS.map(function (one) { return { kind: 'ip', value: one }; }))
      }
    }
  });
  // 0600 on the key and 0644 on the certificate: the certificate is published
  // to every client in this stack as its trust anchor, and the key is read by
  // one process in one container.
  fs.writeFileSync(KEY, pair.privatePem, { mode: 0o600 });
  fs.writeFileSync(CERT, issued.pem, { mode: 0o644 });
  // THE SERVER RUNS AS uid 100 IN THAT IMAGE and this script does not, so the
  // pair is handed over explicitly rather than left owned by whoever minted
  // it. A listener that cannot read its own key fails with a message about a
  // file, which is a long way from "the container that wrote it was root".
  try {
    fs.chownSync(KEY, 100, 1000);
    fs.chownSync(CERT, 100, 1000);
    // **AND THE DIRECTORIES ABOVE THEM, WHICH IS NOT TIDINESS.** A named
    // volume is created root-owned, and docker only copies an image's
    // ownership into one when the image HAS that path — this image does not,
    // so whichever container mounts the volume first decides. When that is
    // this one, the store's own entrypoint then finds `/openbao/file` owned by
    // root, tries to chown it, fails (it has already dropped to uid 100) and
    // the container exits 1 with `Operation not permitted` as the only
    // sentence. Handing the tree over here makes the ordering not matter.
    fs.chownSync(DIR, 100, 1000);
    fs.chownSync(path.dirname(DIR), 100, 1000);
  } catch (e) {
    // Not fatal, and it is the ordinary case on a bind mount owned by the
    // person running the stack: the server reads a 0644 certificate whoever
    // owns it, and only the key matters. Reported so that a listener that
    // will not start has this in the log above it.
    console.log('sts-bao-tls: the pair could not be chowned to the server\'s ' +
                'user (' + e.message + '). That is only a problem if the ' +
                'listener then cannot read its key.');
  }
  console.log('sts-bao-tls: minted a TLS pair for ' +
              NAMES.concat(IPS).join(', ') + ' into ' + DIR +
              ' with this repository\'s own encoder.');
}

main().catch(function (e) {
  console.error('sts-bao-tls: the listener certificate could not be minted: ' +
                (e && e.stack ? e.stack : e));
  process.exit(1);
});
