'use strict';
//
// File: spiffe_attestors.js
//
// ===========================================================================
// THE x509pop, sshpop AND tpm_devid NODE ATTESTORS, EACH DRIVEN BY A CLIENT
// WRITTEN FROM THE OTHER SIDE OF THE PROTOCOL (#40 phase two, 2026-09-21).
//
// Every one of these is a challenge-response exchange with a real
// `spire-agent` on the other end, so each is driven here by a software client
// that does what the agent does — through `Agent.AttestAgent`'s real bidi
// wrapper, with a real PKCS#10 request:
//
//   * x509pop — certificates issued by the vendored engine (an ECDSA, an
//     RSA and an ML-DSA-44 leaf under one root), the challenge answered with
//     RSA-PSS, ECDSA r/s, or the post-quantum member this server adds;
//   * sshpop — an OpenSSH host certificate assembled byte by byte and signed
//     by an ECDSA P-256 authority, the challenge answered with the Ed25519
//     host key in OpenSSH's signature form;
//   * tpm_devid — a SOFTWARE TPM: EK, AK and DevID public areas as
//     TPMT_PUBLIC, a TPM2_Certify of the DevID key signed by the AK, and
//     TPM2_ActivateCredential — OAEP, KDFa, the integrity HMAC and AES-CFB —
//     written here INDEPENDENTLY of `spiffe/spiffe_tpm.ts`, so that a mistake
//     in the server's KDFa is not simply repeated by its own test. (A real
//     TPM, through swtpm and a real spire-agent, is #40's last phase.)
//
// Each attestor's refusals are asserted beside its acceptance, because an
// attestor that accepted everything would pass every positive case here.
//
// IN A CHILD PROCESS, for `spiffe_join_token.js`'s reasons. The child's
// program is `childMain()` below, passed to `node -e` as source — it runs
// in the child only, which the code style exempts from the Entering/Leaving
// lines.
// ===========================================================================

const path = require('path');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'spiffe_attestors',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// RUNS IN THE CHILD (see the header). `packageRoot` is the package root.
async function childMain(packageRoot) {
  const nodeCrypto = require('crypto');
  const EventEmitter = require('events');
  const p = function (rel) {
    return require('path').join(packageRoot, rel);
  };
  require(p('common/app'));
  require(p('ldap/ldap_server'));
  require(p('spiffe/spiffe_server'));
  const api = require(p('spiffe/spiffe_api'));
  const ca = require(p('spiffe/spiffe_ca'));
  const config = require(p('common/config'));
  const x509 = require(p('common/vendored/x509'));
  const pqc = require(p('common/vendored/pqc_x509'));
  const out = {};
  await ca.ready();
  const td = ca.trustDomain();
  const instance = new api.SpiffeApi(api.SpiffeApi.defaultDeps());
  const agent = instance.buildAgentHandlers();
  instance.nodeAttestation();

  // ---- a bidi exchange: `answer(challengeBytes)` returns the response -----
  function attest(type, payload, answer) {
    return new Promise(function (resolve) {
      const call = new EventEmitter();
      call.getPeer = function () { return '127.0.0.1:40404'; };
      call.getAuthContext = function () { return null; };
      call.metadata = { get: function () { return []; } };
      call.write = function (m) {
        if (m.challenge) {
          Promise.resolve(answer(Buffer.from(m.challenge)))
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
      call.emit('data', { params: { data: { type: type, payload: payload },
                                    params: { csr: csrDer } } });
    });
  }
  function agentSelectors(pathName) {
    const found = require(p('spiffe/spiffe_registry')).agentById(
      'spiffe://' + td + pathName);
    return found ? found.selectors.map(function (s) {
      return s.type + ':' + s.value;
    }) : null;
  }
  const csrPair = nodeCrypto.generateKeyPairSync('ec',
                                                 { namedCurve: 'P-256' });
  const csrDer = Buffer.from((await x509.certificationRequest({
    subject: 'CN=agent',
    publicKeyPem: csrPair.publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: csrPair.privateKey.export({ type: 'pkcs8',
                                               format: 'pem' }) })).der);
  function pemOf(key, kind) {
    return key.export({ type: kind === 'private' ? 'pkcs8' : 'spki',
                        format: 'pem' });
  }
  async function issue(subject, publicPem, issuer, profile, extras) {
    const ext = x509.defaultExtensions(profile);
    Object.assign(ext, extras || {});
    return x509.issueCertificate({
      subject: subject, subjectPublicKey: publicPem, profile: profile,
      extensions: ext,
      signatureAlg: issuer.alg, issuer: issuer.cert
        ? { certificatePem: issuer.cert, privateKeyPem: issuer.key } : null,
      issuerPrivateKey: issuer.key
    });
  }

  // ======================= x509pop =========================================
  const rootKey = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const root = await issue('CN=x509pop root', pemOf(rootKey.publicKey),
    { alg: 'sha256-ecdsa', key: pemOf(rootKey.privateKey, 'private') },
    'root-ca');
  const rootIssuer = { alg: 'sha256-ecdsa', cert: root.pem,
                       key: pemOf(rootKey.privateKey, 'private') };
  const sans = { subjectAltName: { present: true, critical: false, names: [
    { kind: 'uri', value: 'x509pop://' + td + '/datacenter/us-east' },
    { kind: 'ip', value: '127.0.0.1' }] } };
  const ecLeafKey = nodeCrypto.generateKeyPairSync('ec',
                                                   { namedCurve: 'P-256' });
  const ecLeaf = await issue('CN=Node-One', pemOf(ecLeafKey.publicKey),
                             rootIssuer, 'digital-signature', sans);
  const rsaLeafKey = nodeCrypto.generateKeyPairSync('rsa',
                                                    { modulusLength: 2048 });
  const rsaLeaf = await issue('CN=node-rsa', pemOf(rsaLeafKey.publicKey),
                              rootIssuer, 'digital-signature');
  const pqKey = await pqc.generateKeyPair('ML-DSA-44');
  const pqLeaf = await issue('CN=node-pq', pqc.publicPem('ML-DSA-44',
                             pqKey.pub), rootIssuer, 'digital-signature');
  const encLeafKey = nodeCrypto.generateKeyPairSync('ec',
                                                    { namedCurve: 'P-256' });
  const encLeaf = await issue('CN=node-enc', pemOf(encLeafKey.publicKey),
                              rootIssuer, 'key-encipherment');
  const strangerKey = nodeCrypto.generateKeyPairSync('ec',
                                                     { namedCurve: 'P-256' });
  const stranger = await issue('CN=stranger', pemOf(strangerKey.publicKey),
    { alg: 'sha256-ecdsa', key: pemOf(strangerKey.privateKey, 'private') },
    'root-ca');
  config.setOverride('spiffe.nodeAttestors',
                     'join_token,x509pop,sshpop,tpm_devid');
  config.setOverride('spiffe.x509popCaBundle', root.pem);
  function x509payload(leaf) {
    return Buffer.from(JSON.stringify({ certificates: [
      Buffer.from(leaf.der).toString('base64')] }));
  }
  function b(v) {
    return Buffer.from(v, 'base64');
  }
  function x509answer(kind, privateKey, tamper) {
    return async function (challengeBytes) {
      const challenge = JSON.parse(challengeBytes.toString('utf8'));
      const theirs = b((challenge.rsa_signature || challenge.ecdsa_signature ||
                        challenge.pqc_signature).nonce);
      const mine = nodeCrypto.randomBytes(32);
      const data = Buffer.concat([theirs, mine]);
      const digest = nodeCrypto.createHash('sha256').update(data).digest();
      if (tamper) mine[0] ^= 1;
      if (kind === 'rsa') {
        return Buffer.from(JSON.stringify({ rsa_signature: {
          nonce: mine.toString('base64'),
          signature: nodeCrypto.sign('sha256', data, { key: privateKey,
            padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: 32 }).toString('base64') } }));
      }
      if (kind === 'ecdsa') {
        const sig = nodeCrypto.sign('sha256', data, {
          key: privateKey, dsaEncoding: 'ieee-p1363' });
        return Buffer.from(JSON.stringify({ ecdsa_signature: {
          nonce: mine.toString('base64'),
          r: sig.subarray(0, 32).toString('base64'),
          s: sig.subarray(32).toString('base64') } }));
      }
      out.pqAlgorithmOffered = challenge.pqc_signature.algorithm;
      const sig = await x509.signBytes(x509.sigAlg('ml-dsa-44'),
        pqc.privatePem('ML-DSA-44', pqKey.priv), null, digest);
      return Buffer.from(JSON.stringify({ pqc_signature: {
        nonce: mine.toString('base64'),
        signature: Buffer.from(sig).toString('base64') } }));
    };
  }
  out.x509ec = await attest('x509pop', x509payload(ecLeaf),
                            x509answer('ecdsa', ecLeafKey.privateKey));
  out.x509ecSelectors = out.x509ec.ok ? agentSelectors(out.x509ec.path) : null;
  out.x509ecExpected = {
    path: '/spire/agent/x509pop/' + nodeCrypto.createHash('sha1')
      .update(Buffer.from(ecLeaf.der)).digest('hex'),
    rootFingerprint: nodeCrypto.createHash('sha1')
      .update(Buffer.from(root.der)).digest('hex'),
    serial: ecLeaf.serialHex.toLowerCase()
  };
  out.x509rsa = await attest('x509pop', x509payload(rsaLeaf),
                             x509answer('rsa', rsaLeafKey.privateKey));
  out.x509pq = await attest('x509pop', x509payload(pqLeaf),
                            x509answer('pqc', null));
  out.x509tampered = await attest('x509pop', x509payload(ecLeaf),
    x509answer('ecdsa', ecLeafKey.privateKey, true));
  out.x509stranger = await attest('x509pop', x509payload(stranger),
    x509answer('ecdsa', strangerKey.privateKey));
  out.x509noSign = await attest('x509pop', x509payload(encLeaf),
    x509answer('ecdsa', encLeafKey.privateKey));
  out.x509garbage = await attest('x509pop', Buffer.from('not json'),
                                 x509answer('ecdsa', ecLeafKey.privateKey));
  config.setOverride('spiffe.x509popAgentPathTemplate',
                     '/{{ .PluginName }}/{{ .Subject.CommonName | lower }}');
  out.x509template = await attest('x509pop', x509payload(ecLeaf),
    x509answer('ecdsa', ecLeafKey.privateKey));
  config.setOverride('spiffe.x509popAgentPathTemplate',
                     '/{{ if .Fingerprint }}x{{ end }}');
  out.x509badTemplate = await attest('x509pop', x509payload(ecLeaf),
    x509answer('ecdsa', ecLeafKey.privateKey));
  config.clearOverride('spiffe.x509popAgentPathTemplate');
  config.setOverride('spiffe.x509popVerifyClientIp', 'true');
  out.x509ipAllowed = await attest('x509pop', x509payload(ecLeaf),
    x509answer('ecdsa', ecLeafKey.privateKey));
  out.x509ipRefused = await attest('x509pop', x509payload(rsaLeaf),
    x509answer('rsa', rsaLeafKey.privateKey));
  config.clearOverride('spiffe.x509popVerifyClientIp');
  config.setOverride('spiffe.x509popCaBundle', '');
  out.x509unconfigured = await attest('x509pop', x509payload(ecLeaf),
    x509answer('ecdsa', ecLeafKey.privateKey));
  config.setOverride('spiffe.x509popCaBundle', root.pem);

  // ======================= sshpop ==========================================
  function sshString(buf) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(buf.length, 0);
    return Buffer.concat([len, buf]);
  }
  function sshText(s) {
    return sshString(Buffer.from(s, 'utf8'));
  }
  function mpint(buf) {
    let v = Buffer.from(buf);
    while (v.length > 1 && v[0] === 0 && !(v[1] & 0x80)) v = v.subarray(1);
    if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0]), v]);
    return sshString(v);
  }
  function u64(n) {
    const out8 = Buffer.alloc(8);
    out8.writeBigUInt64BE(BigInt(n), 0);
    return out8;
  }
  function u32(n) {
    const out4 = Buffer.alloc(4);
    out4.writeUInt32BE(n, 0);
    return out4;
  }
  const caKey = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const caJwk = caKey.publicKey.export({ format: 'jwk' });
  const caBlob = Buffer.concat([sshText('ecdsa-sha2-nistp256'),
    sshText('nistp256'), sshString(Buffer.concat([Buffer.from([4]),
      b(caJwk.x.replace(/-/g, '+').replace(/_/g, '/')),
      b(caJwk.y.replace(/-/g, '+').replace(/_/g, '/'))]))]);
  const hostKey = nodeCrypto.generateKeyPairSync('ed25519');
  const hostPub = Buffer.from(hostKey.publicKey.export({ format: 'jwk' }).x,
                              'base64url');
  function hostCert(kind, principals, after, before, signer) {
    const body = Buffer.concat([
      sshText('ssh-ed25519-cert-v01@openssh.com'),
      sshString(nodeCrypto.randomBytes(32)), sshString(hostPub),
      u64(7), u32(kind), sshText('node1'),
      sshString(Buffer.concat(principals.map(sshText))),
      u64(after), u64(before), sshString(Buffer.alloc(0)),
      sshString(Buffer.alloc(0)), sshString(Buffer.alloc(0)),
      sshString(caBlob)]);
    const raw = nodeCrypto.sign('sha256', body, { key: signer,
                                                  dsaEncoding: 'ieee-p1363' });
    const sig = Buffer.concat([mpint(raw.subarray(0, 32)),
                               mpint(raw.subarray(32))]);
    return Buffer.concat([body, sshString(Buffer.concat([
      sshText('ecdsa-sha2-nistp256'), sshString(sig)]))]);
  }
  const now = Math.floor(Date.now() / 1000);
  config.setOverride('spiffe.sshpopCertAuthorities',
                     'ecdsa-sha2-nistp256 ' + caBlob.toString('base64') +
                     ' test-ca');
  function sshPayload(cert) {
    return Buffer.from(JSON.stringify({
      Certificate: cert.toString('base64') }));
  }
  function sshAnswer(tamper) {
    return function (challengeBytes) {
      const theirs = b(JSON.parse(challengeBytes.toString('utf8')).Nonce);
      const mine = nodeCrypto.randomBytes(32);
      const digest = nodeCrypto.createHash('sha256').update(theirs)
        .update(mine).digest();
      const sig = nodeCrypto.sign(null, digest, hostKey.privateKey);
      if (tamper) sig[0] ^= 1;
      return Buffer.from(JSON.stringify({ Nonce: mine.toString('base64'),
        Signature: { Format: 'ssh-ed25519', Blob: sig.toString('base64'),
                     Rest: null } }));
    };
  }
  const goodHost = hostCert(2, ['node1.example.org'], now - 60, now + 3600,
                            caKey.privateKey);
  out.ssh = await attest('sshpop', sshPayload(goodHost), sshAnswer());
  out.sshExpectedPath = '/spire/agent/sshpop/' +
    nodeCrypto.createHash('sha256').update(goodHost).digest('base64url');
  out.sshSelectors = out.ssh.ok ? agentSelectors(out.ssh.path) : null;
  out.sshTampered = await attest('sshpop', sshPayload(goodHost),
                                 sshAnswer(true));
  out.sshUserCert = await attest('sshpop', sshPayload(hostCert(1,
    ['node1.example.org'], now - 60, now + 3600, caKey.privateKey)),
    sshAnswer());
  out.sshExpired = await attest('sshpop', sshPayload(hostCert(2,
    ['node1.example.org'], now - 7200, now - 3600, caKey.privateKey)),
    sshAnswer());
  const otherCa = nodeCrypto.generateKeyPairSync('ec',
                                                 { namedCurve: 'P-256' });
  out.sshForged = await attest('sshpop', sshPayload(hostCert(2,
    ['node1.example.org'], now - 60, now + 3600, otherCa.privateKey)),
    sshAnswer());
  config.setOverride('spiffe.sshpopCanonicalDomain', 'example.org');
  config.setOverride('spiffe.sshpopAgentPathTemplate',
                     '/{{ .PluginName }}/{{ .Hostname }}');
  out.sshHostname = await attest('sshpop', sshPayload(goodHost), sshAnswer());
  config.setOverride('spiffe.sshpopCanonicalDomain', 'example.net');
  out.sshOutsideDomain = await attest('sshpop', sshPayload(goodHost),
                                      sshAnswer());
  config.clearOverride('spiffe.sshpopCanonicalDomain');
  config.clearOverride('spiffe.sshpopAgentPathTemplate');

  // ======================= tpm_devid =======================================
  // A software TPM. Structures by TPM 2.0 Part 2; nothing borrowed from the
  // server's own spiffe_tpm.ts.
  function u16(n) {
    const out2 = Buffer.alloc(2);
    out2.writeUInt16BE(n, 0);
    return out2;
  }
  function tpm2b(buf) {
    return Buffer.concat([u16(buf.length), buf]);
  }
  function rsaPublicArea(pub, attributes, symmetric, scheme) {
    const jwk = pub.export({ format: 'jwk' });
    return Buffer.concat([u16(0x0001), u16(0x000b), u32(attributes),
      tpm2b(Buffer.alloc(0)), symmetric, scheme, u16(2048), u32(0),
      tpm2b(Buffer.from(jwk.n, 'base64url'))]);
  }
  function eccPublicArea(pub) {
    const jwk = pub.export({ format: 'jwk' });
    return Buffer.concat([u16(0x0023), u16(0x000b), u32(0x00040072),
      tpm2b(Buffer.alloc(0)), u16(0x0010), u16(0x0018), u16(0x000b),
      u16(0x0003), u16(0x0010), tpm2b(Buffer.from(jwk.x, 'base64url')),
      tpm2b(Buffer.from(jwk.y, 'base64url'))]);
  }
  function nameOf(area) {
    return Buffer.concat([u16(0x000b), nodeCrypto.createHash('sha256')
      .update(area).digest()]);
  }
  function kdfa(key, label, contextU, bits) {
    const blocks = [];
    let have = 0;
    for (let i = 1; have < bits / 8; i++) {
      const h = nodeCrypto.createHmac('sha256', key);
      h.update(u32(i));
      h.update(Buffer.from(label + '\0', 'latin1'));
      h.update(contextU);
      h.update(u32(bits));
      const block = h.digest();
      blocks.push(block);
      have += block.length;
    }
    return Buffer.concat(blocks).subarray(0, bits / 8);
  }
  const ekKey = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ekArea = rsaPublicArea(ekKey.publicKey, 0x000300b2,
    Buffer.concat([u16(0x0006), u16(128), u16(0x0043)]), u16(0x0010));
  const akKey = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const akArea = rsaPublicArea(akKey.publicKey, 0x00050072, u16(0x0010),
                               Buffer.concat([u16(0x0014), u16(0x000b)]));
  const devidKey = nodeCrypto.generateKeyPairSync('ec',
                                                  { namedCurve: 'P-256' });
  const devidArea = eccPublicArea(devidKey.publicKey);
  const mfrKey = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const mfr = await issue('CN=TPM Manufacturer', pemOf(mfrKey.publicKey),
    { alg: 'sha256-ecdsa', key: pemOf(mfrKey.privateKey, 'private') },
    'root-ca');
  const ekCert = await issue('CN=EK', pemOf(ekKey.publicKey),
    { alg: 'sha256-ecdsa', cert: mfr.pem,
      key: pemOf(mfrKey.privateKey, 'private') }, 'key-encipherment',
    { subjectAltName: { present: true, critical: true, names: [
      { kind: 'dirName', value: 'CN=tpm-model' }] } });
  const devidCaKey = nodeCrypto.generateKeyPairSync('ec',
                                                    { namedCurve: 'P-256' });
  const devidCa = await issue('CN=DevID CA', pemOf(devidCaKey.publicKey),
    { alg: 'sha256-ecdsa', key: pemOf(devidCaKey.privateKey, 'private') },
    'root-ca');
  const devidCert = await issue('CN=device-42', pemOf(devidKey.publicKey),
    { alg: 'sha256-ecdsa', cert: devidCa.pem,
      key: pemOf(devidCaKey.privateKey, 'private') }, 'digital-signature');
  function certify(certifiedArea) {
    const attest = Buffer.concat([u32(0xff544347), u16(0x8017),
      tpm2b(nameOf(akArea)), tpm2b(Buffer.alloc(0)), Buffer.alloc(17),
      Buffer.alloc(8), tpm2b(nameOf(certifiedArea)),
      tpm2b(nameOf(certifiedArea))]);
    const sig = nodeCrypto.sign('sha256', attest, { key: akKey.privateKey,
      padding: nodeCrypto.constants.RSA_PKCS1_PADDING });
    return { attest: attest,
             signature: Buffer.concat([u16(0x0014), u16(0x000b),
                                       tpm2b(sig)]) };
  }
  config.setOverride('spiffe.tpmDevidCaBundle', devidCa.pem);
  config.setOverride('spiffe.tpmEndorsementCaBundle', mfr.pem);
  function tpmPayload(overrides) {
    const c = certify(devidArea);
    return Buffer.from(JSON.stringify(Object.assign({
      DevIDCert: [Buffer.from(devidCert.der).toString('base64')],
      DevIDPub: devidArea.toString('base64'),
      EKCert: Buffer.from(ekCert.der).toString('base64'),
      EKPub: ekArea.toString('base64'),
      AKPub: akArea.toString('base64'),
      CertifiedDevID: c.attest.toString('base64'),
      CertificationSignature: c.signature.toString('base64')
    }, overrides || {})));
  }
  // TPM2_ActivateCredential, in software.
  function activate(credential, secret) {
    const seed = nodeCrypto.privateDecrypt({ key: ekKey.privateKey,
      padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256',
      oaepLabel: Buffer.from('IDENTITY\0', 'latin1') }, secret);
    const akName = nameOf(akArea);
    const hmacSize = credential.readUInt16BE(0);
    const hmac = credential.subarray(2, 2 + hmacSize);
    const encIdentity = credential.subarray(2 + hmacSize);
    const macKey = kdfa(seed, 'INTEGRITY', Buffer.alloc(0), 256);
    const expected = nodeCrypto.createHmac('sha256', macKey)
      .update(encIdentity).update(akName).digest();
    if (!expected.equals(hmac)) return null;
    const storage = kdfa(seed, 'STORAGE', akName, seed.length * 8);
    const decipher = nodeCrypto.createDecipheriv('aes-128-cfb', storage,
                                                 Buffer.alloc(16));
    const plain = Buffer.concat([decipher.update(encIdentity),
                                 decipher.final()]);
    return plain.subarray(2, 2 + plain.readUInt16BE(0));
  }
  function tpmAnswer(wrongSecret) {
    return function (challengeBytes) {
      const challenge = JSON.parse(challengeBytes.toString('utf8'));
      const recovered = activate(b(challenge.CredActivation.Credential),
                                 b(challenge.CredActivation.Secret));
      out.tpmActivated = !!recovered;
      return Buffer.from(JSON.stringify({
        DevID: nodeCrypto.sign('sha256', b(challenge.DevID),
                               devidKey.privateKey).toString('base64'),
        CredActivation: (wrongSecret ? nodeCrypto.randomBytes(32)
                                     : recovered).toString('base64')
      }));
    };
  }
  out.tpm = await attest('tpm_devid', tpmPayload(), tpmAnswer());
  out.tpmExpectedPath = '/spire/agent/tpm_devid/' +
    nodeCrypto.createHash('sha1').update(Buffer.from(devidCert.der))
      .digest('hex');
  out.tpmSelectors = out.tpm.ok ? agentSelectors(out.tpm.path) : null;
  out.tpmDevidCaFingerprint = nodeCrypto.createHash('sha1')
    .update(Buffer.from(devidCa.der)).digest('hex');
  out.tpmWrongSecret = await attest('tpm_devid', tpmPayload(),
                                    tpmAnswer(true));
  const otherArea = eccPublicArea(nodeCrypto.generateKeyPairSync('ec',
    { namedCurve: 'P-256' }).publicKey);
  const wrongCertify = certify(otherArea);
  out.tpmWrongCertify = await attest('tpm_devid', tpmPayload({
    CertifiedDevID: wrongCertify.attest.toString('base64'),
    CertificationSignature: wrongCertify.signature.toString('base64') }),
    tpmAnswer());
  const otherEk = nodeCrypto.generateKeyPairSync('rsa',
                                                 { modulusLength: 2048 });
  out.tpmEkMismatch = await attest('tpm_devid', tpmPayload({
    EKPub: rsaPublicArea(otherEk.publicKey, 0x000300b2,
      Buffer.concat([u16(0x0006), u16(128), u16(0x0043)]), u16(0x0010))
      .toString('base64') }), tpmAnswer());
  config.setOverride('spiffe.tpmEndorsementCaBundle', root.pem);
  out.tpmUntrustedEk = await attest('tpm_devid', tpmPayload(), tpmAnswer());
  config.setOverride('spiffe.tpmEndorsementCaBundle', mfr.pem);
  out.tpmTpm2b = await attest('tpm_devid', tpmPayload({
    DevIDPub: tpm2b(devidArea).toString('base64') }), tpmAnswer());
  out.state = instance.nodeAttestationState();
  return out;
}

function run(t) {
  log.debug("Entering run().");
  const os = require('os');
  const fs = require('fs');
  const outFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(),
                                                     'attestors-')),
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
    { cwd: ROOT, env: env, encoding: 'utf8', timeout: 180000 });
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
  function refused(result, code) {
    log.debug("Entering refused().");
    log.debug("Leaving refused().");
    return !!result && !result.ok && result.code === code;
  }
  function show(value) {
    log.debug("Entering show().");
    log.debug("Leaving show().");
    return JSON.stringify(value);
  }

  t.log.info('=== x509pop ===');
  t.check(out.x509ec.ok && out.x509ec.path === out.x509ecExpected.path &&
          out.x509ec.reattestable === true,
          'an ECDSA leaf chaining to the anchors proves possession and is ' +
          '/spire/agent/x509pop/<SHA-1 of the leaf>, re-attestable',
          show(out.x509ec) + ' ' + show(out.x509ecExpected));
  const sel = out.x509ecSelectors || [];
  t.check(sel.indexOf('x509pop:subject:cn:Node-One') >= 0 &&
          sel.indexOf('x509pop:ca:fingerprint:' +
                      out.x509ecExpected.rootFingerprint) >= 0 &&
          sel.indexOf('x509pop:serialnumber:' +
                      out.x509ecExpected.serial) >= 0 &&
          sel.indexOf('x509pop:san:datacenter:us-east') >= 0 &&
          !sel.some(function (s) {
            return /unverified/.test(s);
          }),
          'its selectors are SPIRE\'s: subject:cn, ca:fingerprint, ' +
          'serialnumber and the x509pop:// SAN — and nothing unverified',
          show(sel));
  t.check(out.x509rsa.ok, 'an RSA leaf proves possession with RSA-PSS',
          show(out.x509rsa));
  t.check(out.x509pq.ok && out.pqAlgorithmOffered === 'ML-DSA-44',
          'an ML-DSA-44 leaf is challenged with the post-quantum member and ' +
          'proves possession with it', show(out.x509pq) + ' ' +
          out.pqAlgorithmOffered);
  t.check(refused(out.x509tampered, PERMISSION_DENIED),
          'a response that does not sign the nonces is PERMISSION_DENIED',
          show(out.x509tampered));
  t.check(refused(out.x509stranger, PERMISSION_DENIED),
          'a certificate that does not chain to the anchors is ' +
          'PERMISSION_DENIED', show(out.x509stranger));
  t.check(refused(out.x509noSign, INTERNAL),
          'a certificate not for digitalSignature cannot be challenged ' +
          '(INTERNAL, as SPIRE)', show(out.x509noSign));
  t.check(refused(out.x509garbage, INVALID_ARGUMENT),
          'a payload that is not the attestor\'s JSON is INVALID_ARGUMENT',
          show(out.x509garbage));
  t.check(out.x509template.ok &&
          out.x509template.path === '/spire/agent/x509pop/node-one',
          'agent_path_template renders a field through a sprig function',
          show(out.x509template));
  t.check(refused(out.x509badTemplate, FAILED_PRECONDITION),
          'a template using Go syntax this server does not evaluate is ' +
          'refused, never rendered differently', show(out.x509badTemplate));
  t.check(out.x509ipAllowed.ok,
          'verify_client_ip admits the address in the leaf\'s IP SAN',
          show(out.x509ipAllowed));
  t.check(refused(out.x509ipRefused, PERMISSION_DENIED),
          'and refuses a leaf with no such SAN', show(out.x509ipRefused));
  t.check(refused(out.x509unconfigured, FAILED_PRECONDITION),
          'with no anchors configured every x509pop agent is refused',
          show(out.x509unconfigured));

  t.log.info('=== sshpop ===');
  t.check(out.ssh.ok && out.ssh.path === out.sshExpectedPath &&
          out.ssh.reattestable === true,
          'a host certificate from a configured authority, and a signature ' +
          'by its host key, is /spire/agent/sshpop/<fingerprint>',
          show(out.ssh) + ' ' + out.sshExpectedPath);
  t.check(Array.isArray(out.sshSelectors) && out.sshSelectors.length === 0,
          'with no selectors, as SPIRE\'s sshpop reports none',
          show(out.sshSelectors));
  t.check(refused(out.sshTampered, INTERNAL),
          'a bad signature over the nonces is refused', show(out.sshTampered));
  t.check(refused(out.sshUserCert, INTERNAL),
          'a USER certificate is refused', show(out.sshUserCert));
  t.check(refused(out.sshExpired, INTERNAL),
          'an expired certificate is refused', show(out.sshExpired));
  t.check(refused(out.sshForged, INTERNAL),
          'a certificate from an authority not configured is refused',
          show(out.sshForged));
  t.check(out.sshHostname.ok &&
          out.sshHostname.path === '/spire/agent/sshpop/node1',
          'canonical_domain strips the domain for the Hostname',
          show(out.sshHostname));
  t.check(refused(out.sshOutsideDomain, INTERNAL),
          'and a principal outside it is refused', show(out.sshOutsideDomain));

  t.log.info('=== tpm_devid ===');
  t.check(out.tpmActivated === true,
          'the software TPM activates the credential the server made — an ' +
          'independent KDFa, HMAC and AES-CFB agree with the server\'s');
  t.check(out.tpm.ok && out.tpm.path === out.tpmExpectedPath &&
          out.tpm.reattestable === true,
          'a TPM-resident DevID is /spire/agent/tpm_devid/<SHA-1 of the ' +
          'DevID certificate>', show(out.tpm) + ' ' + out.tpmExpectedPath);
  const tsel = out.tpmSelectors || [];
  t.check(tsel.indexOf('tpm_devid:subject:cn:device-42') >= 0 &&
          tsel.indexOf('tpm_devid:issuer:cn:DevID CA') >= 0 &&
          tsel.indexOf('tpm_devid:ca:fingerprint:' +
                       out.tpmDevidCaFingerprint) >= 0,
          'with subject:cn, issuer:cn and ca:fingerprint selectors',
          show(tsel));
  t.check(refused(out.tpmWrongSecret, INVALID_ARGUMENT),
          'a wrong credential activation secret is refused',
          show(out.tpmWrongSecret));
  t.check(refused(out.tpmWrongCertify, INVALID_ARGUMENT),
          'a certification naming another key is refused',
          show(out.tpmWrongCertify));
  t.check(refused(out.tpmEkMismatch, INVALID_ARGUMENT),
          'an EK public area that is not the EK certificate\'s key is ' +
          'refused', show(out.tpmEkMismatch));
  t.check(refused(out.tpmUntrustedEk, INVALID_ARGUMENT),
          'an EK certificate from a manufacturer not configured is refused',
          show(out.tpmUntrustedEk));
  t.check(out.tpmTpm2b.ok,
          'a DevID public area with its TPM2B size prefix is read too',
          show(out.tpmTpm2b));

  t.log.info('=== the table ===');
  const types = ((out.state || {}).attestors || []).map(function (a) {
    return a.type + (a.enabled ? '+' : '-');
  });
  t.check(['join_token+', 'sshpop+', 'tpm_devid+', 'x509pop+']
            .every(function (x) {
              return types.indexOf(x) >= 0;
            }),
          'GET /spiffe\'s nodeAttestation lists all four, enabled here',
          show(types));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_attestors',
  describe: 'x509pop, sshpop and tpm_devid verify real exchanges and refuse ' +
            'forged ones',
  run: run
};
