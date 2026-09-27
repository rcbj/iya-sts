'use strict';
//
// File: saml_listener_key.js
//
// ===========================================================================
// THE SAML METADATA PUBLISHES THE BACK CHANNEL'S TLS CERTIFICATE (#248).
//
// rcbj's decision on #189: both identity providers' metadata carry the
// certificate their SOAP endpoints present, so a service provider can
// authenticate artifact resolution and the attribute query from metadata
// alone. `saml/listener_keys.ts` is the rule; this file holds it:
//
//   A. THE LIBRARY: nothing while the main port is plain HTTP; every leaf
//      the socket presents while it is TLS, each a `use="signing"`
//      KeyDescriptor; a changed leaf is named at the next ask (nothing is
//      cached, so a re-issue after `build-root` is followed); another
//      cluster node's leaves beside this one's, once each; a certificate
//      that cannot be read is a document without it (STS-SAML-0097), never
//      a refusal.
//   B. THE DOCUMENTS: SAML 2.0 and SAML 1.1, per service provider, carry it
//      in the IDPSSODescriptor AND the AttributeAuthorityDescriptor — the
//      roles whose SOAP endpoints a service provider calls — LAST among the
//      KeyDescriptors, so the first signing certificate is still the XML key.
//   C. THE WORKER HAND-OFF, in a child process: a request worker answers
//      the leaves the FRONT process presents — the first and the others it
//      was handed — and follows a re-issue's bundle; a process that owns the
//      socket answers what it built, and its bundle carries the others.
//   D. THE CLUSTER, in a child process: a node's leaves ride on its join and
//      heartbeat, and every LIVE node's are read back — a node that left, or
//      whose row expired, is not.
//
// Over HTTP, `sts_saml_interop_shibboleth.js` holds the other half: the
// Shibboleth SP, handed no TLS anchor at all, resolves an artifact and runs
// both attribute queries, and refuses the back channel when the listener's
// KeyDescriptor is taken out of the metadata.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const nodeCrypto = require('crypto');
const childProcess = require('child_process');
const kit = require('./tools/saml_signing_kit');

const log = require('bunyan').createLogger({
  name: 'saml_listener_key',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_TEST_LISTENER_KEY_CHILD';

// A certificate for a fresh RSA key: `{ pem, b64 }`.
function freshCertificate(cn) {
  log.debug("Entering freshCertificate().");
  const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const cert = kit.certificateFor(pair.publicKey, cn);
  log.debug("Leaving freshCertificate().");
  return { pem: cert.pem, b64: cert.b64,
           keyPem: pair.privateKey.export({ type: 'pkcs8',
                                            format: 'pem' }).toString() };
}

// The KeyDescriptors of one role descriptor, in document order.
function roleKeys(xml, role) {
  log.debug("Entering roleKeys(). " + role);
  const body = (new RegExp('<md:' + role + '[\\s>][\\s\\S]*?</md:' + role +
                           '>').exec(xml) || [''])[0];
  const out = [];
  const re = /<md:KeyDescriptor([^>]*)>[\s\S]*?<ds:X509Certificate>([^<]+)</g;
  let m = re.exec(body);
  while (m) {
    out.push({ use: (/use="([^"]*)"/.exec(m[1]) || [])[1] || '',
               b64: m[2].replace(/\s+/g, '') });
    m = re.exec(body);
  }
  log.debug("Leaving roleKeys(). " + out.length + ".");
  return out;
}

// ---------------------------------------------------------------------------
// C and D run here, in a child, because each has to set the environment
// before a module loads or start a cluster membership — neither of which this
// process may do to the other files `run.js` runs in it.
// ---------------------------------------------------------------------------
async function childTls() {
  log.debug("Entering childTls().");
  const out = {};
  const tls = require(path.join(ROOT, 'tls/tls_server'));
  out.handed = tls.presentedCertificatePems();
  out.bundle = tls.serverCertificateBundle().extraCertPems;
  const next = JSON.parse(process.env.PROBE_NEXT);
  tls.adoptServerCertificate({ certPem: next.cert, chainPem: [],
                               anchorPem: '', extraCertPems: [next.extra] });
  out.adopted = tls.presentedCertificatePems();
  log.debug("Leaving childTls().");
  return out;
}

async function childOwner() {
  log.debug("Entering childOwner().");
  const tls = require(path.join(ROOT, 'tls/tls_server'));
  const presented = tls.presentedCertificatePems();
  log.debug("Leaving childOwner().");
  return { presented: presented,
           first: tls.serverCertificate().certPem,
           chains: tls.serverCertificateChains().map(function (one) {
             return one.certPem;
           }),
           bundle: tls.serverCertificateBundle().extraCertPems };
}

async function childCluster() {
  log.debug("Entering childCluster().");
  const cluster = require(path.join(ROOT, 'cluster/cluster'));
  const probe = JSON.parse(process.env.PROBE_CLUSTER);
  const infos = [];
  const driver = {
    setFence: function () {
      log.debug("Entering setFence().");
      log.debug("Leaving setFence().");
    },
    joinCluster: function (node) {
      log.debug("Entering joinCluster().");
      infos.push(node.info);
      log.debug("Leaving joinCluster().");
      return Promise.resolve({ joined: true, differing: [], live: 0 });
    },
    acquireLease: function () {
      log.debug("Entering acquireLease().");
      log.debug("Leaving acquireLease().");
      return Promise.resolve({ held: true, token: 7 });
    },
    heartbeat: function (nodeId, ttlMs, info) {
      log.debug("Entering heartbeat().");
      infos.push(info);
      log.debug("Leaving heartbeat().");
      return Promise.resolve({ alive: true,
                               leases: [{ name: 'service', token: 7 }] });
    },
    agreeFingerprint: function () {
      log.debug("Entering agreeFingerprint().");
      log.debug("Leaving agreeFingerprint().");
      return Promise.resolve({ differing: [] });
    },
    leaveCluster: function () {
      log.debug("Entering leaveCluster().");
      log.debug("Leaving leaveCluster().");
      return Promise.resolve(true);
    },
    clusterState: function () {
      log.debug("Entering clusterState().");
      log.debug("Leaving clusterState().");
      return Promise.resolve({ now: 1000000, leases: [], nodes: [
        { nodeId: 'self', leftAt: 0, expiresAt: 1005000,
          info: { listenerCertificates: [probe.own] } },
        { nodeId: 'live', leftAt: 0, expiresAt: 1005000,
          info: { listenerCertificates: [probe.live, probe.own] } },
        { nodeId: 'left', leftAt: 999000, expiresAt: 1005000,
          info: { listenerCertificates: [probe.left] } },
        { nodeId: 'lapsed', leftAt: 0, expiresAt: 999999,
          info: { listenerCertificates: [probe.lapsed] } }
      ] });
    }
  };
  const out = {};
  out.before = cluster.listenerCertificatesOfLiveNodes();
  cluster.reset({ exit: function () {} });
  cluster.setListenerCertificates([probe.ownPem]);
  await cluster.gate(driver);
  await cluster.beat();
  out.infos = infos.map(function (info) {
    return (info && info.listenerCertificates) || null;
  });
  await cluster.refreshState();
  out.live = cluster.listenerCertificatesOfLiveNodes();
  cluster.reset({ exit: function () {} });
  log.debug("Leaving childCluster().");
  return out;
}

function runChild(which, env) {
  log.debug("Entering runChild(). " + which);
  const childEnv = Object.assign({}, process.env, env);
  childEnv[CHILD_FLAG] = which;
  const ran = childProcess.spawnSync(process.execPath, [__filename], {
    env: childEnv, encoding: 'utf8', timeout: 120000,
    maxBuffer: 16 * 1024 * 1024 });
  const line = String(ran.stdout || '').split('\n').filter(function (l) {
    return l.indexOf('PROBE_RESULT ') === 0;
  })[0];
  log.debug("Leaving runChild(). status " + ran.status);
  if (!line) {
    return { error: 'the child printed no result (status ' + ran.status +
             '): ' + String(ran.stderr || '').slice(-1500) };
  }
  return JSON.parse(line.slice('PROBE_RESULT '.length));
}

async function run(t) {
  log.debug("Entering run().");
  const listenerKeys = require('../saml/listener_keys');
  const tlsServer = require('../tls/tls_server');
  const saml2sso = require('../saml/saml2_sso');
  const saml11sso = require('../saml/saml11_sso');
  const stsCrypto = require('../common/crypto');
  const helpers = require('../common/helpers');

  // -------------------------------------------------------------------------
  t.log.info('A. the library');
  // -------------------------------------------------------------------------
  const a = freshCertificate('listener-a');
  const b = freshCertificate('listener-b');
  const peer = freshCertificate('listener-peer');
  let https = true;
  let presented = [a.pem];
  let peers = [];
  let broken = false;
  const warnings = [];
  const keys = new listenerKeys.ListenerKeys(Object.assign(
    listenerKeys.ListenerKeys.defaultDeps(), {
      log: { debug: function () {}, warn: function (m) { warnings.push(m); } },
      config: { value: function (key) {
        return key === 'global.https' ? https : undefined;
      } },
      loadTlsServer: function () {
        if (broken) {
          throw new Error('no listener here');
        }
        return { presentedCertificatePems: function () {
          return presented.slice(0);
        } };
      },
      cluster: { listenerCertificatesOfLiveNodes: function () {
        return peers.slice(0);
      } }
    }));
  https = false;
  t.equal(JSON.stringify(keys.certificates()) + keys.keyDescriptors(), '[]',
          'global.https OFF: no certificate and no KeyDescriptor — a plain ' +
          'HTTP back channel has no certificate to authenticate');
  https = true;
  t.equal(JSON.stringify(keys.certificates()), JSON.stringify([a.b64]),
          'global.https on: the leaf the socket presents, as base64 DER');
  t.check(keys.keyDescriptors() === '<md:KeyDescriptor use="signing">' +
          '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
          '<ds:X509Data><ds:X509Certificate>' + a.b64 +
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
          '</md:KeyDescriptor>',
          'as ONE use="signing" KeyDescriptor of its own — not use omitted, ' +
          'which would offer a TLS key for encryption', keys.keyDescriptors());
  presented = [a.pem, b.pem];
  t.equal(JSON.stringify(keys.certificates()),
          JSON.stringify([a.b64, b.b64]),
          'two leaves (tls.certificateAlgorithms naming two): both, since ' +
          'OpenSSL presents whichever the client offered');
  presented = [b.pem];
  t.equal(JSON.stringify(keys.certificates()), JSON.stringify([b.b64]),
          'IT FOLLOWS THE CERTIFICATE: after a re-issue the next ask names ' +
          'the new leaf and not the old one — nothing is cached');
  peers = [peer.b64, b.b64];
  t.equal(JSON.stringify(keys.certificates()),
          JSON.stringify([b.b64, peer.b64]),
          'a cluster: every live node\'s leaves beside this one\'s, once each');
  broken = true;
  peers = [];
  let threw = '';
  try {
    t.equal(keys.keyDescriptors(), '',
            'a certificate that cannot be read: the document goes without ' +
            'it rather than failing');
  } catch (e) {
    threw = (e && e.message) || String(e);
  }
  t.check(!threw && warnings.some(function (w) {
    return /STS-SAML-0097/.test(w);
  }), 'and it is logged under STS-SAML-0097', threw || warnings.join(' | '));
  broken = false;
  const real = new listenerKeys.ListenerKeys(Object.assign(
    listenerKeys.ListenerKeys.defaultDeps(), {
      config: { value: function (key) {
        return key === 'global.https' ? true : undefined;
      } } }));
  t.equal(JSON.stringify(real.certificates()),
          JSON.stringify(tlsServer.presentedCertificatePems()
            .map(stsCrypto.stripPem)),
          'the real module answers exactly what tls/tls_server.js says the ' +
          'socket presents');

  // -------------------------------------------------------------------------
  t.log.info('B. the documents');
  // -------------------------------------------------------------------------
  presented = [a.pem];
  const deps2 = Object.assign(saml2sso.Saml2Sso.defaultDeps(),
                              { listenerKeys: keys });
  const idp2 = new saml2sso.Saml2Sso(deps2);
  const deps11 = Object.assign(saml11sso.Saml11Sso.defaultDeps(),
                               { listenerKeys: keys });
  const idp11 = new saml11sso.Saml11Sso(deps11);
  const xmlKeys = helpers.ownRsaCertificates('xml').map(function (one) {
    return stsCrypto.stripPem(one.certPem);
  });
  const sp = 'https://listener-key-' + Date.now() + '.test/sp';
  const documents = [
    ['SAML 2.0', idp2.metadataFor('https://idp.test', sp)],
    ['SAML 2.0 (unscoped)', idp2.metadataFor('https://idp.test', '')],
    ['SAML 1.1', idp11.metadataFor('https://idp.test', sp)]
  ];
  documents.forEach(function (row) {
    ['IDPSSODescriptor', 'AttributeAuthorityDescriptor'].forEach(
      function (role) {
        const found = roleKeys(row[1], role);
        const last = found[found.length - 1] || {};
        t.check(last.b64 === a.b64 && last.use === 'signing',
                row[0] + ' ' + role + ': the listener certificate is its ' +
                'LAST KeyDescriptor, use="signing"',
                JSON.stringify(found.map(function (k) {
                  return k.use + ':' + k.b64.slice(0, 16);
                })));
        t.check(found.length > 1 && xmlKeys.indexOf(found[0].b64) >= 0 &&
                found[0].use === 'signing',
                row[0] + ' ' + role + ': the FIRST signing certificate is ' +
                'still the XML key, for a consumer that takes the first');
      });
  });
  https = false;
  const plain = [idp2.metadataFor('https://idp.test', sp),
                 idp11.metadataFor('https://idp.test', sp)];
  t.check(plain.every(function (xml) {
    return xml.indexOf(a.b64) < 0;
  }), 'global.https OFF: neither document names a listener certificate');
  https = true;

  // -------------------------------------------------------------------------
  t.log.info('C. the request-worker hand-off');
  // -------------------------------------------------------------------------
  const front = freshCertificate('front-rsa');
  const extra = freshCertificate('front-ml-dsa');
  const next = freshCertificate('front-rsa-reissued');
  const nextExtra = freshCertificate('front-ml-dsa-reissued');
  const worker = runChild('tls', {
    STS_TLS_SERVER_CERT_PEM: front.pem,
    STS_TLS_SERVER_KEY_PEM: front.keyPem,
    STS_TLS_SERVER_EXTRA_CERTS_PEM: extra.pem,
    PROBE_NEXT: JSON.stringify({ cert: next.pem, extra: nextExtra.pem })
  });
  const strip = function (list) {
    log.debug("Entering strip().");
    log.debug("Leaving strip().");
    return (list || []).map(stsCrypto.stripPem);
  };
  t.equal(JSON.stringify(strip(worker.handed)),
          JSON.stringify([front.b64, extra.b64]),
          'a worker presents the FRONT process\'s leaves: the one it was ' +
          'handed and the others handed with it — never one it made itself',
          worker.error || '');
  t.equal(JSON.stringify(strip(worker.adopted)),
          JSON.stringify([next.b64, nextExtra.b64]),
          'and after a re-issue\'s bundle, the new ones', worker.error || '');
  const owner = runChild('owner', {
    STS_TLS_SERVER_CERT_PEM: '', STS_TLS_SERVER_KEY_PEM: '',
    STS_TLS_SERVER_EXTRA_CERTS_PEM: ''
  });
  t.check(!owner.error && owner.presented && owner.presented.length >= 1 &&
          owner.presented[0] === owner.first &&
          JSON.stringify(owner.presented) === JSON.stringify(owner.chains) &&
          JSON.stringify(owner.bundle) ===
            JSON.stringify(owner.presented.slice(1)),
          'a process that owns the socket presents what it built, and the ' +
          'bundle it hands a worker carries every leaf after the first',
          owner.error || '');

  // -------------------------------------------------------------------------
  t.log.info('D. the cluster');
  // -------------------------------------------------------------------------
  const own = freshCertificate('node-self');
  const probe = {
    ownPem: own.pem, own: own.b64,
    live: freshCertificate('node-live').b64,
    left: freshCertificate('node-left').b64,
    lapsed: freshCertificate('node-lapsed').b64
  };
  const clustered = runChild('cluster', {
    PROBE_CLUSTER: JSON.stringify(probe),
    STS_MODE: 'product', STS_PERSISTENCE_MODE: 'postgres',
    STS_CLUSTER_HEARTBEAT_MS: '250', STS_CLUSTER_NODE_TTL_MS: '1000'
  });
  t.equal(JSON.stringify(clustered.before), '[]',
          'no cluster: nothing is read', clustered.error || '');
  t.check(!clustered.error && (clustered.infos || []).length >= 2 &&
          clustered.infos.every(function (certs) {
            return JSON.stringify(certs) === JSON.stringify([probe.own]);
          }),
          'a node\'s leaves ride on its join AND every heartbeat',
          JSON.stringify(clustered.infos || clustered.error).slice(0, 300));
  t.equal(JSON.stringify(clustered.live),
          JSON.stringify([probe.own, probe.live]),
          'every LIVE node\'s leaves are read back, once each; a node that ' +
          'left and one whose row lapsed are not', clustered.error || '');
  log.debug("Leaving run().");
}

if (process.env[CHILD_FLAG]) {
  const which = process.env[CHILD_FLAG];
  const task = which === 'tls' ? childTls
    : which === 'owner' ? childOwner : childCluster;
  task().then(function (out) {
    process.stdout.write('PROBE_RESULT ' + JSON.stringify(out) + '\n');
    process.exit(0);
  }, function (e) {
    log.debug("Caught in the child: " + ((e && e.message) || e));
    process.stdout.write('PROBE_RESULT ' +
      JSON.stringify({ error: (e && e.stack) || String(e) }) + '\n');
    process.exit(0);
  });
}

module.exports = {
  name: 'saml_listener_key',
  describe: 'the SAML metadata publishes the back channel\'s TLS ' +
            'certificate: the library, both profiles\' documents, the ' +
            'request-worker hand-off and the cluster (#248)',
  run: run
};
