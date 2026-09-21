'use strict';
//
// File: spiffe_attestor_sshpop.ts
//
// ---------------------------------------------------------------------------
// THE `sshpop` NODE ATTESTOR — SSH HOST CERTIFICATE PROOF OF POSSESSION (#40,
// 2026-09-21).
//
// SPIRE's `pkg/common/plugin/sshpop/handshake.go`, which is the server half
// of the exchange a real `spire-agent` drives:
//
//   1. The payload is `{"Certificate": <base64 SSH certificate blob>}` — the
//      node's HOST certificate, from `/etc/ssh/ssh_host_*_key-cert.pub`.
//   2. It is checked as `CertChecker.CheckHostKey("<first principal>:22")`:
//      a host certificate, signed by one of `spiffe.sshpopCertAuthorities`,
//      inside its validity window, with no critical option but
//      `source-address` (`spiffe_ssh.ts`). It must name a principal.
//   3. `spiffe.sshpopVerifyClientIp`: the agent's address must be inside the
//      certificate's `source-address` critical option.
//   4. The first principal less `.<spiffe.sshpopCanonicalDomain>` is the
//      Hostname; a principal outside that domain is refused.
//   5. THE CHALLENGE: `{"Nonce": <32 bytes>}`; the agent answers
//      `{"Nonce": <its 32 bytes>, "Signature": {"Format", "Blob", "Rest"}}`,
//      signed with the host key over SHA-256(server nonce ‖ agent nonce).
//   6. The agent's id is `spiffe.sshpopAgentPathTemplate` (default
//      `/{{ .PluginName }}/{{ .Fingerprint }}`, the Fingerprint being the
//      unpadded URL-safe base64 of SHA-256 over the certificate). SPIRE's
//      sshpop reports NO selectors, and neither does this. Re-attestable.
//
// SPIRE answers most of this plugin's failures with INTERNAL rather than
// INVALID_ARGUMENT or PERMISSION_DENIED — `handshake.go` wraps them all that
// way — and a client may read the code, so this answers the same.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import net = require('net');
import helpers = require('../common/helpers');
const { log, nowSec } = helpers;
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import spiffeId = require('./spiffe_id');
import rpc = require('./spiffe_grpc');
import ssh = require('./spiffe_ssh');
import agentPath = require('./spiffe_agent_path');

type NodeAttestationContext =
  import('../types/spiffe-attestation').NodeAttestationContext;
type NodeAttestationResult =
  import('../types/spiffe-attestation').NodeAttestationResult;

const NONCE_LENGTH = 32;
const DEFAULT_TEMPLATE = '/{{ .PluginName }}/{{ .Fingerprint }}';

interface SshpopDeps {
  log: typeof log;
  nowSec: typeof nowSec;
  crypto: typeof nodeCrypto;
  net: typeof net;
  config: typeof config;
  errorCodes: typeof errorCodes;
  spiffeId: typeof spiffeId;
  rpc: typeof rpc;
  ssh: typeof ssh;
  agentPath: typeof agentPath;
}

class SshpopAttestor {
  readonly type = 'sshpop';
  readonly verifies = 'An SSH host certificate signed by one of the ' +
    'realm\'s sshpop certificate authorities, and a signature over a fresh ' +
    'challenge with its host key.';

  constructor(private readonly deps: SshpopDeps) {
    deps.log.debug("Entering SshpopAttestor.constructor().");
    deps.log.debug("Leaving SshpopAttestor.constructor().");
  }

  static defaultDeps(): SshpopDeps {
    helpers.log.debug("Entering SshpopAttestor.defaultDeps().");
    helpers.log.debug("Leaving SshpopAttestor.defaultDeps().");
    return { log: log, nowSec: nowSec, crypto: nodeCrypto, net: net,
             config: config, errorCodes: errorCodes, spiffeId: spiffeId,
             rpc: rpc, ssh: ssh, agentPath: agentPath };
  }

  json(bytes: Buffer): any {
    const { log } = this.deps;
    log.debug("Entering SshpopAttestor.json().");
    try {
      const parsed = JSON.parse(Buffer.from(bytes || []).toString('utf8'));
      log.debug("Leaving SshpopAttestor.json().");
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch (e) {
      log.debug("Caught in SshpopAttestor.json(): " + ((e && e.message) || e));
      log.debug("Leaving SshpopAttestor.json(). Not JSON.");
      return null;
    }
  }

  // Is `ip` inside a `source-address` list of addresses and CIDR ranges?
  // '' when it is, otherwise why not — Go's `checkSourceAddress()`.
  sourceAddressProblem(ip: string, list: string): string {
    const { log, net } = this.deps;
    log.debug("Entering SshpopAttestor.sourceAddressProblem().");
    const family = net.isIP(ip) === 6 ? 'ipv6' : 'ipv4';
    const entries = String(list).split(',');
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i].trim();
      if (net.isIP(entry)) {
        if (entry === ip) {
          log.debug("Leaving SshpopAttestor.sourceAddressProblem(). Match.");
          return '';
        }
        continue;
      }
      const cidr = /^(.+)\/(\d+)$/.exec(entry);
      if (!cidr || !net.isIP(cidr[1])) {
        log.debug("Leaving SshpopAttestor.sourceAddressProblem(). Bad entry.");
        return 'error parsing source-address restriction "' + entry + '"';
      }
      const block = new net.BlockList();
      block.addSubnet(cidr[1], Number(cidr[2]),
                      net.isIP(cidr[1]) === 6 ? 'ipv6' : 'ipv4');
      if (block.check(ip, family)) {
        log.debug("Leaving SshpopAttestor.sourceAddressProblem(). In range.");
        return '';
      }
    }
    log.debug("Leaving SshpopAttestor.sourceAddressProblem(). Outside.");
    return 'client IP ' + ip + ' is not allowed by source-address ' +
           'restriction';
  }

  async attest(context: NodeAttestationContext):
      Promise<NodeAttestationResult> {
    const { log, nowSec, crypto, config, errorCodes, spiffeId, rpc, ssh,
            agentPath } = this.deps;
    log.debug("Entering SshpopAttestor.attest().");
    const call = context.call;
    const status = rpc.grpc.status;
    const authorities = String(config.value('spiffe.sshpopCertAuthorities') ||
                               '').split('\n').map(function (line) {
      return ssh.parseAuthorizedKey(line);
    }).filter(Boolean);
    let template = null;
    let problem = authorities.length ? ''
      : 'spiffe.sshpopCertAuthorities holds no SSH public key';
    if (!problem) {
      try {
        template = new agentPath.AgentPathTemplate(
          String(config.value('spiffe.sshpopAgentPathTemplate') || '') ||
          DEFAULT_TEMPLATE);
      } catch (e) {
        log.debug("Caught in SshpopAttestor.attest(): " +
                  ((e && e.message) || e));
        problem = 'spiffe.sshpopAgentPathTemplate does not parse: ' +
                  e.message;
      }
    }
    if (problem) {
      log.debug("Leaving SshpopAttestor.attest(). Not configured.");
      errorCodes.mark(call, 'STS-SPIFFE-0085');
      throw rpc.statusError(status.FAILED_PRECONDITION,
                            'sshpop is not configured in this realm: ' +
                            problem + '.');
    }
    // 1. THE PAYLOAD.
    const data = this.json(context.payload);
    let cert = null;
    try {
      const parsed = ssh.parsePublicKey(Buffer.from(String(
        (data || {}).Certificate || ''), 'base64'));
      cert = (parsed as any).certType ? parsed : null;
    } catch (e) {
      log.debug("Caught in SshpopAttestor.attest(): " +
                ((e && e.message) || e));
    }
    if (!cert) {
      log.debug("Leaving SshpopAttestor.attest(). No certificate.");
      errorCodes.mark(call, 'STS-SPIFFE-0086');
      throw rpc.statusError(status.INTERNAL, 'pubkey in response is not a ' +
                            'certificate: an sshpop payload is ' +
                            '{"Certificate": <base64 SSH certificate>}');
    }
    // 2. THE HOST CERTIFICATE.
    if (!cert.principals.length) {
      log.debug("Leaving SshpopAttestor.attest(). No principal.");
      errorCodes.mark(call, 'STS-SPIFFE-0096');
      throw rpc.statusError(status.INTERNAL, 'cert has no valid principals');
    }
    const principal = cert.principals[0];
    const refused = ssh.checkHostCertificate(cert, principal, authorities,
                                             nowSec());
    if (refused) {
      log.debug("Leaving SshpopAttestor.attest(). Host key refused.");
      errorCodes.mark(call, 'STS-SPIFFE-0096');
      throw rpc.statusError(status.INTERNAL, 'failed to check host key: ' +
                            refused);
    }
    // 3. THE ADDRESS.
    if (config.value('spiffe.sshpopVerifyClientIp')) {
      const sources = cert.criticalOptions['source-address'];
      if (!sources) {
        log.debug("Leaving SshpopAttestor.attest(). No source-address.");
        errorCodes.mark(call, 'STS-SPIFFE-0090');
        throw rpc.permissionDenied('certificate has no "source-address" ' +
                                   'critical option');
      }
      if (!context.clientIp) {
        log.debug("Leaving SshpopAttestor.attest(). No address.");
        errorCodes.mark(call, 'STS-SPIFFE-0091');
        throw rpc.statusError(status.INTERNAL,
                              'client IP not available for verification');
      }
      const outside = this.sourceAddressProblem(context.clientIp, sources);
      if (outside) {
        log.debug("Leaving SshpopAttestor.attest(). Address not allowed.");
        errorCodes.mark(call, 'STS-SPIFFE-0090');
        throw rpc.permissionDenied('client IP verification failed: ' +
                                   outside);
      }
    }
    // 4. THE HOSTNAME.
    const domain = String(config.value('spiffe.sshpopCanonicalDomain') || '');
    let hostname = principal;
    if (domain) {
      const suffix = '.' + domain;
      if (principal.slice(-suffix.length) !== suffix) {
        log.debug("Leaving SshpopAttestor.attest(). Outside the domain.");
        errorCodes.mark(call, 'STS-SPIFFE-0096');
        throw rpc.statusError(status.INTERNAL, 'failed to decanonicalize ' +
          'hostname: cert principal is not in domain "' + suffix + '"');
      }
      hostname = principal.slice(0, -suffix.length);
    }
    // 5. THE CHALLENGE.
    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const answer = this.json(await context.challenge(
      Buffer.from(JSON.stringify({ Nonce: nonce.toString('base64') }),
                  'utf8')));
    const theirs = answer && typeof answer.Nonce === 'string'
      ? Buffer.from(answer.Nonce, 'base64') : null;
    const signature = answer && answer.Signature &&
      typeof answer.Signature === 'object' ? answer.Signature : null;
    if (!theirs || !signature) {
      log.debug("Leaving SshpopAttestor.attest(). Unreadable response.");
      errorCodes.mark(call, 'STS-SPIFFE-0086');
      throw rpc.statusError(status.INTERNAL, 'failed to unmarshal challenge ' +
                            'response');
    }
    if (theirs.length !== NONCE_LENGTH) {
      log.debug("Leaving SshpopAttestor.attest(). Bad nonce.");
      errorCodes.mark(call, 'STS-SPIFFE-0093');
      throw rpc.statusError(status.INTERNAL, 'failed to combine nonces: ' +
                            'invalid response nonce size');
    }
    const toBeSigned = crypto.createHash('sha256').update(nonce)
      .update(theirs).digest();
    if (!ssh.verify(cert, toBeSigned, {
      format: String(signature.Format || ''),
      blob: Buffer.from(String(signature.Blob || ''), 'base64')
    })) {
      log.debug("Leaving SshpopAttestor.attest(). Signature refused.");
      errorCodes.mark(call, 'STS-SPIFFE-0093');
      throw rpc.statusError(status.INTERNAL, 'failed to verify signature');
    }
    // 6. THE AGENT.
    const templateData = {
      PluginName: this.type,
      Fingerprint: crypto.createHash('sha256').update(cert.blob)
        .digest('base64url'),
      Hostname: hostname,
      Nonce: cert.nonce.toString('base64'),
      Serial: cert.serial.toString(),
      CertType: cert.kind,
      KeyId: cert.keyId,
      ValidPrincipals: cert.principals,
      ValidAfter: cert.validAfter.toString(),
      ValidBefore: cert.validBefore.toString(),
      Permissions: { CriticalOptions: cert.criticalOptions,
                     Extensions: cert.extensions }
    };
    let agentId = '';
    try {
      agentId = spiffeId.make(context.trustDomain,
                              '/spire/agent' + template.execute(templateData));
    } catch (e) {
      log.debug("Caught in SshpopAttestor.attest(): " +
                ((e && e.message) || e));
    }
    if (!agentId || !spiffeId.parse(agentId).ok) {
      log.debug("Leaving SshpopAttestor.attest(). No agent id.");
      errorCodes.mark(call, 'STS-SPIFFE-0095');
      throw rpc.statusError(status.INTERNAL, 'failed to create AgentID from ' +
                            'the agent path template');
    }
    log.debug("Leaving SshpopAttestor.attest(). " + agentId);
    return {
      agentId: agentId,
      selectors: [],
      canReattest: true,
      method: 'agent attestation (sshpop, ' + cert.type + ')',
      note: 'attested by proof of possession of the host key in an SSH ' +
            'host certificate for ' + principal,
      commit: function () {
        log.debug("Entering commit(). Nothing to spend.");
        log.debug("Leaving commit().");
      },
      release: function () {
        log.debug("Entering release(). Nothing to give back.");
        log.debug("Leaving release().");
      }
    };
  }
}

export = {
  SshpopAttestor: SshpopAttestor
};
