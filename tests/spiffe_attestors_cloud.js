'use strict';
//
// File: spiffe_attestors_cloud.js
//
// ===========================================================================
// THE k8s_psat, http_challenge, aws_iid, gcp_iit AND azure_imds NODE
// ATTESTORS (#40 phase three, 2026-09-21).
//
// Each is driven through `Agent.AttestAgent`'s real bidi wrapper:
//
//   * k8s_psat against a REAL HTTPS API server started here — TokenReview,
//     the pod and the node — with its CA and bearer token read from files, as
//     the attestor reads them;
//   * http_challenge against a REAL HTTP listener serving the nonce the
//     challenge carried, dialled through `fetchHttpChallenge()`;
//   * aws_iid, gcp_iit and azure_imds with FAKE CLOUD SDKs handed in through
//     the attestors' constructor dependencies (which is how SPIRE's own tests
//     stub the clouds), with the signed documents built HERE: an RSA-2048
//     PKCS#7 and an RSA-1024 signature over an identity document, a Google
//     RS256 identity token, and an Azure PKCS#7 attested document whose
//     signing certificate chains through an intermediate its AIA names. The
//     PKCS#7 is made with pkijs directly, so `crypto.js`'s verifier is not
//     only agreeing with itself.
//
// Every acceptance sits beside its refusals — a bad signature, the wrong
// nonce, a node outside the allowed set, trust on first use — and a cloud
// attestor with its SDK missing is refused with the package named.
//
// IN A CHILD PROCESS, for `spiffe_join_token.js`'s reasons; its program is
// `childMain()`, passed to `node -e` as source, which the code style exempts
// from the Entering/Leaving lines.
// ===========================================================================

const path = require('path');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'spiffe_attestors_cloud',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// RUNS IN THE CHILD (see the header).
async function childMain(packageRoot) {
  const nodeCrypto = require('crypto');
  const EventEmitter = require('events');
  const fs = require('fs');
  const os = require('os');
  const http = require('http');
  const https = require('https');
  const p = function (rel) {
    return require('path').join(packageRoot, rel);
  };
  require(p('common/app'));
  require(p('ldap/ldap_server'));
  require(p('spiffe/spiffe_server'));
  const api = require(p('spiffe/spiffe_api'));
  const ca = require(p('spiffe/spiffe_ca'));
  const config = require(p('common/config'));
  const pki = require(p('common/pki'));
  const x509 = require(p('common/vendored/x509'));
  const jwt = require('jsonwebtoken');
  const pkijs = require('pkijs');
  const asn1js = require('asn1js');
  const aws = require(p('spiffe/spiffe_attestor_aws_iid'));
  const gcp = require(p('spiffe/spiffe_attestor_gcp_iit'));
  const azure = require(p('spiffe/spiffe_attestor_azure_imds'));
  const k8s = require(p('spiffe/spiffe_attestor_k8s_psat'));
  const httpc = require(p('spiffe/spiffe_attestor_http_challenge'));
  const out = {};
  await ca.ready();
  const td = ca.trustDomain();
  const tmp = fs.mkdtempSync(require('path').join(os.tmpdir(), 'attest-'));

  // ---- certificates and signatures, made here ------------------------------
  function pemOf(key, kind) {
    return key.export({ type: kind === 'private' ? 'pkcs8' : 'spki',
                        format: 'pem' });
  }
  async function issue(subject, publicPem, issuer, profile, extras) {
    const ext = x509.defaultExtensions(profile);
    Object.assign(ext, extras || {});
    return x509.issueCertificate({
      subject: subject, subjectPublicKey: publicPem, profile: profile,
      extensions: ext, signatureAlg: issuer.alg,
      issuer: issuer.cert ? { certificatePem: issuer.cert,
                              privateKeyPem: issuer.key } : null,
      issuerPrivateKey: issuer.key });
  }
  function rsa() {
    return nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  }
  async function pkcs7(content, certDer, privateKey, embed) {
    const cert = pkijs.Certificate.fromBER(new Uint8Array(certDer));
    const key = await nodeCrypto.webcrypto.subtle.importKey('pkcs8',
      privateKey.export({ type: 'pkcs8', format: 'der' }),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
    const signed = new pkijs.SignedData({
      version: 1,
      encapContentInfo: new pkijs.EncapsulatedContentInfo({
        eContentType: '1.2.840.113549.1.7.1',
        eContent: new asn1js.OctetString({ valueHex: new Uint8Array(
          Buffer.from(content)) }) }),
      signerInfos: [new pkijs.SignerInfo({ version: 1,
        sid: new pkijs.IssuerAndSerialNumber({ issuer: cert.issuer,
          serialNumber: cert.serialNumber }) })],
      certificates: embed ? [cert] : [] });
    await signed.sign(key, 0, 'SHA-256');
    const info = new pkijs.ContentInfo({ contentType: '1.2.840.113549.1.7.2',
                                         content: signed.toSchema(true) });
    return Buffer.from(info.toSchema().toBER(false));
  }

  // ---- fake cloud SDKs -----------------------------------------------------
  const calls = [];
  function command(name) {
    return class {
      constructor(input) {
        this.input = input || {};
        this.name = name;
      }
    };
  }
  function client(handler) {
    return class {
      constructor(options) {
        this.options = options;
      }
      async send(cmd) {
        calls.push(cmd.name);
        return handler(cmd.name, cmd.input, this.options);
      }
    };
  }
  const now = new Date();
  const instances = {
    'i-good': { InstanceId: 'i-good', Tags: [{ Key: 'role', Value: 'web' }],
      SecurityGroups: [{ GroupId: 'sg-1', GroupName: 'web-sg' }],
      IamInstanceProfile: { Arn: 'arn:aws:iam::111122223333:' +
                                 'instance-profile/web-profile' },
      NetworkInterfaces: [{ Attachment: { DeviceIndex: 0, AttachTime: now } }],
      RootDeviceType: 'ebs', RootDeviceName: '/dev/xvda',
      BlockDeviceMappings: [{ DeviceName: '/dev/xvda',
                              Ebs: { AttachTime: now } }] },
    'i-moved': { InstanceId: 'i-moved', Tags: [],
      SecurityGroups: [],
      NetworkInterfaces: [{ Attachment: { DeviceIndex: 0, AttachTime: now } }],
      RootDeviceType: 'ebs', RootDeviceName: '/dev/xvda',
      BlockDeviceMappings: [{ DeviceName: '/dev/xvda', Ebs: {
        AttachTime: new Date(now.getTime() - 3600 * 1000) } }] }
  };
  const fakeAws = {
    '@aws-sdk/client-ec2': {
      EC2Client: client(function (name, input) {
        const one = instances[input.InstanceIds[0]];
        return { Reservations: one ? [{ Instances: [one] }] : [] };
      }),
      DescribeInstancesCommand: command('DescribeInstances') },
    '@aws-sdk/client-iam': {
      IAMClient: client(function () {
        return { InstanceProfile: { Roles: [
          { Arn: 'arn:aws:iam::111122223333:role/web-role' }] } };
      }),
      GetInstanceProfileCommand: command('GetInstanceProfile') },
    '@aws-sdk/client-organizations': {
      OrganizationsClient: client(function () {
        return { Accounts: [{ Id: '111122223333', Status: 'ACTIVE' }] };
      }),
      ListAccountsCommand: command('ListAccounts') },
    '@aws-sdk/client-eks': {
      EKSClient: client(function () {
        return {};
      }),
      ListNodegroupsCommand: command('ListNodegroups'),
      DescribeNodegroupCommand: command('DescribeNodegroup') },
    '@aws-sdk/client-auto-scaling': {
      AutoScalingClient: client(function () {
        return {};
      }),
      DescribeAutoScalingGroupsCommand: command('DescribeAutoScalingGroups') },
    '@aws-sdk/credential-providers': {
      fromTemporaryCredentials: function (o) {
        return { assumed: o.params.RoleArn };
      } }
  };
  const fakeGcp = { '@google-cloud/compute': {
    InstancesClient: class {
      async get() {
        return [{ tags: { items: ['http-server'] },
                  labels: { env: 'prod', secret: 'x' },
                  metadata: { items: [{ key: 'team', value: 'id' },
                                      { key: 'other', value: 'y' }] } }];
      }
    } } };
  const fakeAzure = {
    '@azure/identity': {
      DefaultAzureCredential: class {
        constructor(o) {
          this.o = o;
        }
      },
      ClientAssertionCredential: class {} },
    '@azure/arm-resourcegraph': {
      ResourceGraphClient: class {
        async resources(q) {
          if (/virtualmachines'/.test(q.query)) {
            return { totalRecords: 1, data: [{ id: '/subscriptions/sub-1/' +
              'resourceGroups/rg1/providers/Microsoft.Compute/' +
              'virtualMachines/vm1', name: 'vm1', location: 'eastus',
              resourceGroup: 'rg1', tags: { tier: 'front', hidden: 'z' } }] };
          }
          return { totalRecords: 1, data: [{ name: 'nic1',
            resourceGroup: 'rg1', securityGroup: { resourceGroup: 'rg1',
                                                   name: 'nsg1' },
            subnets: [{ vnet: 'vnet1', name: 'default' }] }] };
        }
      } },
    '@azure/arm-compute': { ComputeManagementClient: class {} }
  };
  function loader(fakes) {
    return function (pkg) {
      if (!fakes[pkg]) throw new Error('Cannot find module \'' + pkg + '\'');
      return fakes[pkg];
    };
  }

  // Test certificates for the clouds.
  const awsKey = rsa();
  const awsCert = await issue('CN=AWS test region', pemOf(awsKey.publicKey),
    { alg: 'sha256-rsa', key: pemOf(awsKey.privateKey, 'private') },
    'root-ca');
  const awsCertificate = pki.certificateFromDer(Buffer.from(awsCert.der));
  const googleKey = rsa();
  const googleCert = await issue('CN=Google test', pemOf(googleKey.publicKey),
    { alg: 'sha256-rsa', key: pemOf(googleKey.privateKey, 'private') },
    'root-ca');
  const azRootKey = rsa();
  const azRoot = await issue('CN=Azure test root', pemOf(azRootKey.publicKey),
    { alg: 'sha256-rsa', key: pemOf(azRootKey.privateKey, 'private') },
    'root-ca');
  const azIntKey = rsa();
  const azInt = await issue('CN=Azure test issuing', pemOf(azIntKey.publicKey),
    { alg: 'sha256-rsa', cert: azRoot.pem,
      key: pemOf(azRootKey.privateKey, 'private') }, 'intermediate-ca');
  const azSignerKey = rsa();
  function azSignerCert(dns, aiaUrl) {
    return issue('CN=' + dns, pemOf(azSignerKey.publicKey),
      { alg: 'sha256-rsa', cert: azInt.pem,
        key: pemOf(azIntKey.privateKey, 'private') }, 'digital-signature',
      { subjectAltName: { present: true, critical: false,
                          names: [{ kind: 'dns', value: dns }] },
        authorityInfoAccess: { present: true, critical: false, entries: [
          { method: 'caIssuers', url: aiaUrl }] } });
  }
  const azSigner = await azSignerCert('test.metadata.azure.com',
    'http://www.microsoft.com/pkiops/certs/test-issuing.crt');
  const azSignerOffDomain = await azSignerCert('evil.example.com',
    'http://www.microsoft.com/pkiops/certs/test-issuing.crt');
  const azSignerOffHost = await azSignerCert('test.metadata.azure.com',
    'http://evil.example.com/test-issuing.crt');
  const tenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47';
  const fakeOutbound = {
    requestConfigured: async function (url, options) {
      calls.push('GET ' + url + (options && options.signedArtifact
                                   ? ' (signed)' : ''));
      if (/pkiops/.test(url)) {
        return { ok: true, status: 200, body: Buffer.from(azInt.der),
                 headers: {} };
      }
      if (/openid-configuration/.test(url)) {
        return { ok: true, status: 200, headers: {}, body: Buffer.from(
          JSON.stringify({ issuer: 'https://sts.windows.net/' + tenantId +
                                   '/' })) };
      }
      if (/googleapis|gcp-certs/.test(url)) {
        return { ok: true, status: 200, headers: { expires: new Date(
          Date.now() + 3600 * 1000).toUTCString() }, body: Buffer.from(
          JSON.stringify({ 'kid-1': googleCert.pem })) };
      }
      return { ok: false, status: 404, why: 'not found', body: Buffer.alloc(0),
               headers: {} };
    }
  };

  // ---- the SpiffeApi, with the cloud attestors built on fakes --------------
  function withDeps(Class, over) {
    return { build: function () {
      return new Class(Object.assign(Class.defaultDeps(), over));
    } };
  }
  function buildApi(cloudDeps) {
    const deps = api.SpiffeApi.defaultDeps();
    deps.attestors = [
      withDeps(k8s.K8sPsatAttestor, {}),
      withDeps(httpc.HttpChallengeAttestor, {}),
      withDeps(aws.AwsIidAttestor, cloudDeps.aws),
      withDeps(gcp.GcpIitAttestor, cloudDeps.gcp),
      withDeps(azure.AzureImdsAttestor, cloudDeps.azure)
    ];
    const instance = new api.SpiffeApi(deps);
    return { instance: instance, agent: instance.buildAgentHandlers() };
  }
  const withFakes = buildApi({
    aws: { load: loader(fakeAws), pki: Object.assign({}, pki, {
      awsIidCertificate: function () {
        return awsCertificate;
      } }) },
    gcp: { load: loader(fakeGcp), outbound: fakeOutbound },
    azure: { load: loader(fakeAzure), outbound: fakeOutbound,
             pki: Object.assign({}, pki, { azureImdsRoots: function () {
               return [pki.certificateFromDer(Buffer.from(azRoot.der))];
             } }) }
  });
  const withoutSdks = buildApi({ aws: { load: loader({}) },
                                 gcp: { load: loader({}) },
                                 azure: { load: loader({}) } });
  const csrPair = nodeCrypto.generateKeyPairSync('ec',
                                                 { namedCurve: 'P-256' });
  const csrDer = Buffer.from((await x509.certificationRequest({
    subject: 'CN=agent',
    publicKeyPem: csrPair.publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: csrPair.privateKey.export({ type: 'pkcs8',
                                               format: 'pem' }) })).der);
  function attest(agent, type, payload, answer) {
    return new Promise(function (resolve) {
      const call = new EventEmitter();
      call.getPeer = function () { return '127.0.0.1:40404'; };
      call.getAuthContext = function () { return null; };
      call.metadata = { get: function () { return []; } };
      call.write = function (m) {
        if (m.challenge) {
          Promise.resolve(answer ? answer(Buffer.from(m.challenge))
                                 : Buffer.alloc(0))
            .then(function (response) {
              call.emit('data', { challenge_response: response });
            });
          return;
        }
        resolve({ ok: true, path: m.result.svid.id.path,
                  reattestable: m.result.reattestable });
      };
      call.end = function () {};
      call.on('error', function (err) {
        resolve({ ok: false, code: err.code,
                  message: err.details || err.message });
      });
      agent.AttestAgent(call);
      call.emit('data', { params: { data: { type: type,
        payload: Buffer.from(payload || '') }, params: { csr: csrDer } } });
    });
  }
  function selectorsOf(result) {
    if (!result.ok) return null;
    const found = require(p('spiffe/spiffe_registry')).agentById(
      'spiffe://' + td + result.path);
    return found ? found.selectors.map(function (s) {
      return s.type + ':' + s.value;
    }) : null;
  }
  config.setOverride('spiffe.nodeAttestors',
    'k8s_psat,http_challenge,aws_iid,gcp_iit,azure_imds');

  // ======================= k8s_psat ========================================
  const apiCaKey = rsa();
  const apiCa = await issue('CN=cluster CA', pemOf(apiCaKey.publicKey),
    { alg: 'sha256-rsa', key: pemOf(apiCaKey.privateKey, 'private') },
    'root-ca');
  const apiKey = rsa();
  const apiCert = await issue('CN=kube-apiserver', pemOf(apiKey.publicKey),
    { alg: 'sha256-rsa', cert: apiCa.pem,
      key: pemOf(apiCaKey.privateKey, 'private') }, 'tls-server',
    { subjectAltName: { present: true, critical: false,
                        names: [{ kind: 'ip', value: '127.0.0.1' }] } });
  const reviews = {
    good: { authenticated: true, audiences: ['spire-server'],
            user: { username: 'system:serviceaccount:spire:spire-agent',
              extra: { 'authentication.kubernetes.io/pod-name': ['agent-x'],
                       'authentication.kubernetes.io/pod-uid': ['uid-1'] } } },
    stale: { authenticated: true, audiences: ['spire-server'],
             user: { username: 'system:serviceaccount:spire:spire-agent',
               extra: { 'authentication.kubernetes.io/pod-name': ['agent-x'],
                        'authentication.kubernetes.io/pod-uid': ['uid-old'] }
             } },
    other: { authenticated: true, audiences: ['spire-server'],
             user: { username: 'system:serviceaccount:default:nobody',
               extra: {} } },
    bad: { authenticated: false }
  };
  let bearerSeen = '';
  const apiServer = https.createServer({
    key: pemOf(apiKey.privateKey, 'private'), cert: apiCert.pem
  }, function (req, res) {
    bearerSeen = String(req.headers.authorization || '');
    let body = '';
    req.on('data', function (c) { body += c; });
    req.on('end', function () {
      res.setHeader('Content-Type', 'application/json');
      if (req.method === 'POST' && /tokenreviews$/.test(req.url)) {
        const token = JSON.parse(body).spec.token;
        res.end(JSON.stringify({ status: reviews[token] || reviews.bad }));
      } else if (/\/pods\/agent-x$/.test(req.url)) {
        res.end(JSON.stringify({ metadata: { uid: 'uid-1',
          labels: { app: 'spire', team: 'x' } },
          spec: { nodeName: 'node-a' }, status: { hostIP: '10.0.0.7' } }));
      } else if (/\/nodes\/node-a$/.test(req.url)) {
        res.end(JSON.stringify({ metadata: { uid: 'node-uid-a',
          labels: { zone: 'z1', other: 'o' } } }));
      } else {
        res.statusCode = 404;
        res.end('{}');
      }
    });
  });
  await new Promise(function (r) { apiServer.listen(0, '127.0.0.1', r); });
  fs.writeFileSync(tmp + '/ca.crt', apiCa.pem);
  fs.writeFileSync(tmp + '/token', 'reviewer-token\n');
  config.setOverride('spiffe.k8sPsatClusters', JSON.stringify({
    prod: { serviceAccountAllowList: ['spire:spire-agent'],
            apiServer: 'https://127.0.0.1:' + apiServer.address().port,
            caFile: tmp + '/ca.crt', tokenFile: tmp + '/token',
            allowedNodeLabelKeys: ['zone'], allowedPodLabelKeys: ['app'] } }));
  function psat(token, cluster) {
    return JSON.stringify({ cluster: cluster || 'prod', token: token });
  }
  out.k8s = await attest(withFakes.agent, 'k8s_psat', psat('good'));
  out.k8sSelectors = selectorsOf(out.k8s);
  out.k8sBearer = bearerSeen;
  out.k8sStale = await attest(withFakes.agent, 'k8s_psat', psat('stale'));
  out.k8sOther = await attest(withFakes.agent, 'k8s_psat', psat('other'));
  out.k8sBad = await attest(withFakes.agent, 'k8s_psat', psat('bad'));
  out.k8sCluster = await attest(withFakes.agent, 'k8s_psat',
                                psat('good', 'staging'));
  apiServer.close();

  // ======================= http_challenge ===================================
  let served = '';
  const challengeServer = http.createServer(function (req, res) {
    res.end(/\/http_challenge\/agent1\/challenge$/.test(req.url) ? served
                                                                 : 'no');
  });
  await new Promise(function (r) {
    challengeServer.listen(0, '127.0.0.1', r);
  });
  const port = challengeServer.address().port;
  function hc(host, agentName, portNumber) {
    return JSON.stringify({ hostname: host, agentname: agentName || 'agent1',
                            port: portNumber || port });
  }
  function serveNonce(tamper) {
    return function (bytes) {
      served = JSON.parse(bytes.toString('utf8')).nonce + (tamper ? 'x' : '');
      return Buffer.from('{}');
    };
  }
  config.setOverride('spiffe.httpChallengeAllowedDnsPatterns', '');
  out.hcUnconfigured = await attest(withFakes.agent, 'http_challenge',
                                    hc('127.0.0.1'), serveNonce());
  config.setOverride('spiffe.httpChallengeAllowedDnsPatterns',
                     '^127\\.0\\.0\\.1$');
  out.hcWrongNonce = await attest(withFakes.agent, 'http_challenge',
                                  hc('127.0.0.1', 'agent1'), serveNonce(true));
  out.hc = await attest(withFakes.agent, 'http_challenge', hc('127.0.0.1'),
                        serveNonce());
  out.hcSelectors = selectorsOf(out.hc);
  out.hcAgain = await attest(withFakes.agent, 'http_challenge',
                             hc('127.0.0.1'), serveNonce());
  out.hcLocalhost = await attest(withFakes.agent, 'http_challenge',
                                 hc('localhost'), serveNonce());
  out.hcNotAllowed = await attest(withFakes.agent, 'http_challenge',
                                  hc('10.9.9.9'), serveNonce());
  out.hcBadName = await attest(withFakes.agent, 'http_challenge',
                               hc('127.0.0.1', '9bad.name'), serveNonce());
  config.setOverride('spiffe.httpChallengeAllowNonRootPorts', 'false');
  out.hcNonRoot = await attest(withFakes.agent, 'http_challenge',
                               hc('127.0.0.1'), serveNonce());
  config.clearOverride('spiffe.httpChallengeAllowNonRootPorts');
  challengeServer.close();

  // ======================= aws_iid =========================================
  function iid(instanceId, extra) {
    return JSON.stringify(Object.assign({ accountId: '111122223333',
      region: 'us-test-1', instanceId: instanceId, imageId: 'ami-1',
      availabilityZone: 'us-test-1a' }, extra || {}));
  }
  async function awsPayload(document, form) {
    if (form === 'rsa1024') {
      return JSON.stringify({ document: document, signature: nodeCrypto.sign(
        'sha256', Buffer.from(document), awsKey.privateKey)
        .toString('base64') });
    }
    const sig = await pkcs7(document, Buffer.from(awsCert.der),
                            awsKey.privateKey, false);
    return JSON.stringify({ document: document,
                            rsa2048: sig.toString('base64') });
  }
  out.aws = await attest(withFakes.agent, 'aws_iid',
                         await awsPayload(iid('i-good')));
  out.awsSelectors = selectorsOf(out.aws);
  out.awsAgain = await attest(withFakes.agent, 'aws_iid',
                              await awsPayload(iid('i-good')));
  const signedDoc = iid('i-good', { imageId: 'ami-2' });
  const forged = JSON.parse(await awsPayload(signedDoc));
  forged.document = iid('i-good', { imageId: 'ami-EVIL' });
  out.awsForged = await attest(withFakes.agent, 'aws_iid',
                               JSON.stringify(forged));
  out.awsRsa1024 = await attest(withFakes.agent, 'aws_iid',
    await awsPayload(iid('i-good', { accountId: '444455556666' }),
                     'rsa1024'));
  out.awsMoved = await attest(withFakes.agent, 'aws_iid',
                              await awsPayload(iid('i-moved')));
  config.setOverride('spiffe.awsIidVerifyOrganization',
                     JSON.stringify({ accountList: ['999999999999'] }));
  out.awsNotInOrg = await attest(withFakes.agent, 'aws_iid',
    await awsPayload(iid('i-good', { accountId: '777788889999' })));
  config.clearOverride('spiffe.awsIidVerifyOrganization');
  out.awsNoSdk = await attest(withoutSdks.agent, 'aws_iid',
                              await awsPayload(iid('i-good')));

  // ======================= gcp_iit =========================================
  config.setOverride('spiffe.gcpIitCertsUrl', 'https://gcp-certs.test/certs');
  config.setOverride('spiffe.gcpIitProjectIdAllowList', 'proj-a');
  function gcpToken(claims, key, kid) {
    return jwt.sign(Object.assign({ aud: 'spire-gcp-node-attestor',
      email: 'sa@proj-a.iam.gserviceaccount.com',
      google: { compute_engine: { project_id: 'proj-a', project_number: 42,
        zone: 'us-central1-a', instance_id: '123', instance_name: 'vm-a',
        instance_creation_timestamp: 1 } } }, claims || {}),
      pemOf(key || googleKey.privateKey, 'private'),
      { algorithm: 'RS256', keyid: kid || 'kid-1', expiresIn: 300 });
  }
  out.gcp = await attest(withFakes.agent, 'gcp_iit', gcpToken());
  out.gcpSelectors = selectorsOf(out.gcp);
  out.gcpAudience = await attest(withFakes.agent, 'gcp_iit',
    gcpToken({ aud: 'someone-else', google: { compute_engine: {
      project_id: 'proj-a', instance_id: '124', instance_name: 'vm-b' } } }));
  out.gcpProject = await attest(withFakes.agent, 'gcp_iit',
    gcpToken({ google: { compute_engine: { project_id: 'proj-z',
      instance_id: '125', instance_name: 'vm-c' } } }));
  out.gcpForged = await attest(withFakes.agent, 'gcp_iit',
    gcpToken({ google: { compute_engine: { project_id: 'proj-a',
      instance_id: '126', instance_name: 'vm-d' } } }, rsa().privateKey));
  config.setOverride('spiffe.gcpIitUseInstanceMetadata', 'true');
  config.setOverride('spiffe.gcpIitAllowedLabelKeys', 'env');
  config.setOverride('spiffe.gcpIitAllowedMetadataKeys', 'team');
  out.gcpMetadata = await attest(withFakes.agent, 'gcp_iit',
    gcpToken({ google: { compute_engine: { project_id: 'proj-a',
      zone: 'us-central1-a', instance_id: '127', instance_name: 'vm-e' } } }));
  out.gcpMetadataSelectors = selectorsOf(out.gcpMetadata);
  out.gcpNoSdk = await attest(withoutSdks.agent, 'gcp_iit', gcpToken());
  config.clearOverride('spiffe.gcpIitUseInstanceMetadata');

  // ======================= azure_imds ======================================
  config.setOverride('spiffe.azureImdsTenants', JSON.stringify({
    'contoso.onmicrosoft.com': { allowedVmTags: ['tier'],
                                 restrictToSubscriptions: ['sub-1'] } }));
  function azAnswer(signer, opts) {
    const o = opts || {};
    return async function (nonceBytes) {
      const content = JSON.stringify({ vmId: o.vmId ||
        '0a1b2c3d-1111-2222-3333-444455556666', subscriptionId:
        o.subscription || 'sub-1', nonce: o.nonce ||
        nonceBytes.toString('utf8') });
      const sig = await pkcs7(content, Buffer.from(signer.der),
                              azSignerKey.privateKey, true);
      return Buffer.from(JSON.stringify({
        document: { encoding: 'pkcs7', signature: sig.toString('base64') },
        metadata: { agentDomain: o.domain || 'contoso.onmicrosoft.com' } }));
    };
  }
  out.az = await attest(withFakes.agent, 'azure_imds', '',
                        azAnswer(azSigner));
  out.azSelectors = selectorsOf(out.az);
  out.azNonce = await attest(withFakes.agent, 'azure_imds', '',
    azAnswer(azSigner, { nonce: 'not-the-nonce',
                         vmId: '0a1b2c3d-1111-2222-3333-444455556667' }));
  out.azTenant = await attest(withFakes.agent, 'azure_imds', '',
    azAnswer(azSigner, { domain: 'fabrikam.onmicrosoft.com',
                         vmId: '0a1b2c3d-1111-2222-3333-444455556668' }));
  out.azSubscription = await attest(withFakes.agent, 'azure_imds', '',
    azAnswer(azSigner, { subscription: 'sub-9',
                         vmId: '0a1b2c3d-1111-2222-3333-444455556669' }));
  out.azDomain = await attest(withFakes.agent, 'azure_imds', '',
    azAnswer(azSignerOffDomain,
             { vmId: '0a1b2c3d-1111-2222-3333-44445555666a' }));
  out.azHost = await attest(withFakes.agent, 'azure_imds', '',
    azAnswer(azSignerOffHost,
             { vmId: '0a1b2c3d-1111-2222-3333-44445555666b' }));
  out.azNoSdk = await attest(withoutSdks.agent, 'azure_imds', '',
                             azAnswer(azSigner));
  out.calls = calls;
  out.tenantId = tenantId;
  return out;
}

function run(t) {
  log.debug("Entering run().");
  const os = require('os');
  const fs = require('fs');
  const outFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(),
                                                     'attestors-cloud-')),
                            'out.json');
  const script = 'delete process.env.CONFIG_FILE;\n(' + childMain.toString() +
    ')(' + JSON.stringify(ROOT) + ').then(function (out) {\n' +
    '  require("fs").writeFileSync(process.env.PROBE_OUT, ' +
    'JSON.stringify(out));\n  process.exit(0);\n}).catch(function (e) {\n' +
    '  require("fs").writeFileSync(process.env.PROBE_OUT, ' +
    'JSON.stringify({ threw: e.stack }));\n  process.exit(1);\n});';
  const env = Object.assign({}, process.env, {
    LOG_LEVEL: 'fatal', PROBE_OUT: outFile, SPIFFE_GRPC_PORT: '0'
  });
  delete env.CONFIG_FILE;
  const child = childProcess.spawnSync(process.execPath, ['-e', script],
    { cwd: ROOT, env: env, encoding: 'utf8', timeout: 240000 });
  let out = {};
  try {
    out = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    fs.rmSync(path.dirname(outFile), { recursive: true, force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    t.bad('the child process reported nothing',
          (child.stderr || '').slice(-2000));
    log.debug("Leaving run().");
    return;
  }
  if (out.threw) {
    t.bad('the child process threw', out.threw);
    log.debug("Leaving run().");
    return;
  }
  const INVALID_ARGUMENT = 3;
  const PERMISSION_DENIED = 7;
  const FAILED_PRECONDITION = 9;
  const INTERNAL = 13;
  function refused(result, code, pattern) {
    log.debug("Entering refused().");
    log.debug("Leaving refused().");
    return !!result && !result.ok && result.code === code &&
           (!pattern || pattern.test(result.message));
  }
  function show(value) {
    log.debug("Entering show().");
    log.debug("Leaving show().");
    return JSON.stringify(value);
  }
  function has(list, values) {
    log.debug("Entering has().");
    log.debug("Leaving has().");
    return Array.isArray(list) && values.every(function (v) {
      return list.indexOf(v) >= 0;
    });
  }

  t.log.info('=== k8s_psat ===');
  t.check(out.k8s.ok &&
          out.k8s.path === '/spire/agent/k8s_psat/prod/node-uid-a' &&
          out.k8s.reattestable === true,
          'a token the cluster\'s TokenReview authenticates is ' +
          '/spire/agent/k8s_psat/<cluster>/<node UID>', show(out.k8s));
  t.check(has(out.k8sSelectors, ['k8s_psat:cluster:prod',
    'k8s_psat:agent_ns:spire', 'k8s_psat:agent_sa:spire-agent',
    'k8s_psat:agent_pod_name:agent-x', 'k8s_psat:agent_pod_uid:uid-1',
    'k8s_psat:agent_node_ip:10.0.0.7', 'k8s_psat:agent_node_name:node-a',
    'k8s_psat:agent_node_uid:node-uid-a', 'k8s_psat:agent_node_label:zone:z1',
    'k8s_psat:agent_pod_label:app:spire']) &&
          out.k8sSelectors.indexOf('k8s_psat:agent_node_label:other:o') < 0,
          'with SPIRE\'s selectors, labels only for the allowed keys',
          show(out.k8sSelectors));
  t.equal(out.k8sBearer, 'Bearer reviewer-token',
          'the API server is asked with the bearer token from the FILE');
  t.check(refused(out.k8sStale, PERMISSION_DENIED, /pod UID mismatch/),
          'a token bound to a pod UID the named pod no longer has is refused',
          show(out.k8sStale));
  t.check(refused(out.k8sOther, PERMISSION_DENIED, /not an allowed/),
          'a service account outside the allow list is refused',
          show(out.k8sOther));
  t.check(refused(out.k8sBad, PERMISSION_DENIED, /not authenticated/),
          'a token the cluster does not authenticate is refused',
          show(out.k8sBad));
  t.check(refused(out.k8sCluster, INVALID_ARGUMENT),
          'a cluster this realm is not configured for is INVALID_ARGUMENT',
          show(out.k8sCluster));

  t.log.info('=== http_challenge ===');
  t.check(refused(out.hcUnconfigured, FAILED_PRECONDITION),
          'with no allowed host names every agent is refused — stricter than ' +
          'SPIRE, whose empty list allows any', show(out.hcUnconfigured));
  t.check(out.hc.ok &&
          out.hc.path === '/spire/agent/http_challenge/127.0.0.1' &&
          out.hc.reattestable === false,
          'the nonce served from an allowed host attests it, trust on first ' +
          'use', show(out.hc));
  t.check(has(out.hcSelectors, ['http_challenge:hostname:127.0.0.1']),
          'with the hostname selector', show(out.hcSelectors));
  t.check(refused(out.hcAgain, PERMISSION_DENIED),
          'the same host a second time is refused (TOFU)', show(out.hcAgain));
  t.check(refused(out.hcLocalhost, PERMISSION_DENIED, /localhost/),
          'localhost is refused', show(out.hcLocalhost));
  t.check(refused(out.hcNotAllowed, PERMISSION_DENIED, /not allowed/),
          'a host no pattern allows is refused without being dialled',
          show(out.hcNotAllowed));
  t.check(refused(out.hcBadName, INVALID_ARGUMENT),
          'a malformed agent name is refused', show(out.hcBadName));
  t.check(refused(out.hcNonRoot, INVALID_ARGUMENT, />= 1024/),
          'a non-root port is refused when they are not allowed',
          show(out.hcNonRoot));
  t.check(refused(out.hcWrongNonce, PERMISSION_DENIED, /expected nonce/),
          'a host serving something other than the nonce is refused',
          show(out.hcWrongNonce));

  t.log.info('=== aws_iid ===');
  t.check(out.aws.ok && out.aws.path ===
            '/spire/agent/aws_iid/111122223333/us-test-1/i-good' &&
          out.aws.reattestable === false,
          'an RSA-2048 PKCS#7-signed identity document attests the instance, ' +
          'trust on first use', show(out.aws));
  t.check(has(out.awsSelectors, ['aws_iid:account_id:111122223333',
    'aws_iid:az:us-test-1a', 'aws_iid:image:id:ami-1',
    'aws_iid:instance:id:i-good', 'aws_iid:region:us-test-1',
    'aws_iid:tag:role:web', 'aws_iid:sg:id:sg-1', 'aws_iid:sg:name:web-sg',
    'aws_iid:iamrole:arn:aws:iam::111122223333:role/web-role']),
          'with SPIRE\'s selectors, IAM role included', show(out.awsSelectors));
  t.check(refused(out.awsAgain, PERMISSION_DENIED),
          'the same instance again is refused (TOFU)', show(out.awsAgain));
  t.check(refused(out.awsForged, INVALID_ARGUMENT),
          'a document that is not the one signed is refused',
          show(out.awsForged));
  t.check(out.awsRsa1024.ok,
          'the older RSA-1024 signature form verifies too',
          show(out.awsRsa1024));
  t.check(refused(out.awsMoved, INTERNAL, /attach times/),
          'an instance whose root volume and first interface were not ' +
          'attached together is refused', show(out.awsMoved));
  t.check(refused(out.awsNotInOrg, INTERNAL, /organization/),
          'an account outside the organization is refused',
          show(out.awsNotInOrg));
  t.check(refused(out.awsNoSdk, FAILED_PRECONDITION, /@aws-sdk\/client-ec2/),
          'with the AWS SDK missing the refusal names the package',
          show(out.awsNoSdk));

  t.log.info('=== gcp_iit ===');
  t.check(out.gcp.ok && out.gcp.path === '/spire/agent/gcp_iit/proj-a/123' &&
          out.gcp.reattestable === false,
          'a Google-signed identity token attests the instance, trust on ' +
          'first use', show(out.gcp));
  t.check(has(out.gcpSelectors, ['gcp_iit:project-id:proj-a',
    'gcp_iit:zone:us-central1-a', 'gcp_iit:instance-name:vm-a',
    'gcp_iit:sa:sa@proj-a.iam.gserviceaccount.com']),
          'with SPIRE\'s selectors', show(out.gcpSelectors));
  t.check(refused(out.gcpAudience, PERMISSION_DENIED) ||
          refused(out.gcpAudience, INVALID_ARGUMENT),
          'a token for another audience is refused', show(out.gcpAudience));
  t.check(refused(out.gcpProject, PERMISSION_DENIED, /allow list/),
          'a project outside the allow list is refused', show(out.gcpProject));
  t.check(refused(out.gcpForged, INVALID_ARGUMENT, /signature/),
          'a token Google did not sign is refused', show(out.gcpForged));
  t.check(out.gcpMetadata.ok && has(out.gcpMetadataSelectors, [
    'gcp_iit:tag:http-server', 'gcp_iit:label:env:prod',
    'gcp_iit:metadata:team:id']) &&
          out.gcpMetadataSelectors.indexOf('gcp_iit:label:secret:x') < 0,
          'use_instance_metadata adds tag, label and metadata selectors for ' +
          'the allowed keys only', show(out.gcpMetadataSelectors));
  t.check(refused(out.gcpNoSdk, FAILED_PRECONDITION, /@google-cloud\/compute/),
          'with the Compute SDK missing the refusal names the package',
          show(out.gcpNoSdk));

  t.log.info('=== azure_imds ===');
  t.check(out.az.ok && out.az.path === '/spire/agent/azure_imds/' +
            out.tenantId + '/sub-1/0a1b2c3d-1111-2222-3333-444455556666' &&
          out.az.reattestable === false,
          'an attested document carrying the nonce, chaining through the ' +
          'AIA intermediate, attests the VM', show(out.az));
  t.check(has(out.azSelectors, ['azure_imds:subscription-id:sub-1',
    'azure_imds:vm-name:vm1', 'azure_imds:vm-location:eastus',
    'azure_imds:resource-group:rg1', 'azure_imds:vm-tag:tier:front',
    'azure_imds:network-security-group:rg1:nsg1',
    'azure_imds:virtual-network:vnet1',
    'azure_imds:virtual-network-subnet:vnet1:default']) &&
          out.azSelectors.indexOf('azure_imds:vm-tag:hidden:z') < 0,
          'with SPIRE\'s selectors, tags only for the allowed keys',
          show(out.azSelectors));
  t.check((out.calls || []).some(function (c) {
    return /pkiops.*\(signed\)$/.test(c);
  }), 'the intermediate is fetched as a signed artifact from the AIA URL');
  t.check(refused(out.azNonce, INVALID_ARGUMENT, /nonce/),
          'a document carrying another nonce is refused', show(out.azNonce));
  t.check(refused(out.azTenant, PERMISSION_DENIED, /not authorized/),
          'a tenant not configured is refused', show(out.azTenant));
  t.check(refused(out.azSubscription, PERMISSION_DENIED, /subscription/),
          'a subscription the tenant does not allow is refused',
          show(out.azSubscription));
  t.check(refused(out.azDomain, INVALID_ARGUMENT, /valid domain/),
          'a signing certificate outside the metadata domains is refused',
          show(out.azDomain));
  t.check(refused(out.azHost, INVALID_ARGUMENT, /does not match/),
          'an AIA URL on a host other than the allowed one is refused',
          show(out.azHost));
  t.check(refused(out.azNoSdk, FAILED_PRECONDITION, /@azure\/identity/),
          'with the Azure SDK missing the refusal names the package',
          show(out.azNoSdk));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_attestors_cloud',
  describe: 'k8s_psat, http_challenge, aws_iid, gcp_iit and azure_imds ' +
            'verify real exchanges and refuse forged ones',
  run: run
};
