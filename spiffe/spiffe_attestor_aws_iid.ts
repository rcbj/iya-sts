'use strict';
//
// File: spiffe_attestor_aws_iid.ts
//
// ---------------------------------------------------------------------------
// THE `aws_iid` NODE ATTESTOR — AN EC2 INSTANCE IDENTITY DOCUMENT (#40
// phase three, 2026-09-21).
//
// SPIRE's `pkg/server/plugin/nodeattestor/awsiid`:
//
//   1. The payload is `{"document", "signature", "rsa2048"}` — the instance
//      identity document and AWS's signature over it, from the instance
//      metadata service.
//   2. The signature is verified with the REGION's published AWS certificate
//      (`common/pki.js`'s `awsIidCertificate()`, SPIRE's own table): the
//      RSA-2048 form is PKCS#7 with the document attached, verified by
//      `common/crypto.js`'s `verifyPkcs7SignedData()` and the content
//      compared byte for byte; the older RSA-1024 form is PKCS#1 v1.5 over
//      SHA-256. An unknown region has no RSA-2048 certificate and is refused.
//   3. With `spiffe.awsIidVerifyOrganization`, the account must be an ACTIVE
//      member of the organization (AWS Organizations, or an account list);
//      with `spiffe.awsIidEksClusterNames`, the instance must be in a node
//      group of one of those clusters.
//   4. EC2 DescribeInstances — the instance must be pending or running — and,
//      unless the account is in `spiffe.awsIidLocalValidAccountIds` or
//      `spiffe.awsIidSkipBlockDevice` is on, the root volume and the first
//      network interface must have been attached within a minute of each
//      other (what stops a document from one instance being replayed by
//      another built from its volume).
//   5. The agent is `spiffe.awsIidAgentPathTemplate` (default
//      `/{{ .PluginName }}/{{ .AccountID }}/{{ .Region }}/{{ .InstanceID }}`,
//      `.Tags` available). Selectors: tag:, sg:id:, sg:name:, iamrole: (IAM,
//      unless `spiffe.awsIidDisableInstanceProfileSelectors`), account_id:,
//      image:id:, instance:id:, region:, az:. Trust on first use.
//
// **THE AWS SDK IS AN OPTIONAL PEER DEPENDENCY** (rcbj, 2026-09-21 — the
// `common/secrets.js` arrangement): `@aws-sdk/client-ec2`, `-iam`,
// `-organizations`, `-eks`, `-auto-scaling` and
// `@aws-sdk/credential-providers`, loaded when the attestor runs, with the
// SDK's own credential chain. A realm that enables aws_iid without them is
// refused with the package named. **No access key is ever a setting.**
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import pki = require('../common/pki');
import spiffeId = require('./spiffe_id');
import rpc = require('./spiffe_grpc');
import agentPath = require('./spiffe_agent_path');

type NodeAttestationContext =
  import('../types/spiffe-attestation').NodeAttestationContext;
type NodeAttestationResult =
  import('../types/spiffe-attestation').NodeAttestationResult;

const DEFAULT_TEMPLATE = '/{{ .PluginName }}/{{ .AccountID }}/' +
  '{{ .Region }}/{{ .InstanceID }}';
const PACKAGES = ['@aws-sdk/client-ec2', '@aws-sdk/client-iam',
                  '@aws-sdk/client-organizations', '@aws-sdk/client-eks',
                  '@aws-sdk/client-auto-scaling',
                  '@aws-sdk/credential-providers'];
const MAX_ATTACH_SECONDS = 60;
const ORG_DEFAULT_REGION = 'us-west-2';
const ORG_DEFAULT_TTL_SECONDS = 180;
const ORG_MIN_TTL_SECONDS = 60;
const EKS_TTL_SECONDS = 30;
// A cache refresh on a miss, at most this many times per TTL (SPIRE's).
const REFRESH_RETRIES = 5;

interface AwsIidDeps {
  log: typeof log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  stsCrypto: typeof stsCrypto;
  pki: typeof pki;
  spiffeId: typeof spiffeId;
  rpc: typeof rpc;
  agentPath: typeof agentPath;
  load(pkg: string): any;
  now(): number;
}

class AwsIidAttestor {
  readonly type = 'aws_iid';
  readonly verifies = 'An EC2 instance identity document signed by AWS for ' +
    'its region, for a running instance that passes the block device check; ' +
    'once per instance.';
  // Account and node lists, keyed by the configuration they were read under.
  private orgCache: Record<string, any> = {};
  private eksCache: Record<string, any> = {};

  constructor(private readonly deps: AwsIidDeps) {
    deps.log.debug("Entering AwsIidAttestor.constructor().");
    deps.log.debug("Leaving AwsIidAttestor.constructor().");
  }

  static defaultDeps(): AwsIidDeps {
    helpers.log.debug("Entering AwsIidAttestor.defaultDeps().");
    helpers.log.debug("Leaving AwsIidAttestor.defaultDeps().");
    return {
      log: log, config: config, errorCodes: errorCodes, stsCrypto: stsCrypto,
      pki: pki, spiffeId: spiffeId, rpc: rpc, agentPath: agentPath,
      load: function (pkg) {
        return require(pkg);
      },
      now: function () {
        return Date.now();
      }
    };
  }

  refuse(call: any, code: string, grpcCode: number, message: string): Error {
    const { log, errorCodes, rpc } = this.deps;
    log.debug("Entering AwsIidAttestor.refuse(). " + code);
    errorCodes.mark(call, code);
    log.debug("Leaving AwsIidAttestor.refuse().");
    // error-code: none — the helper's own internals: every caller passes
    // the code, and it is marked on the line above
    return rpc.statusError(grpcCode, message);
  }

  csv(key: string): string[] {
    const { log, config } = this.deps;
    log.debug("Entering AwsIidAttestor.csv(). " + key);
    const raw = config.value(key);
    log.debug("Leaving AwsIidAttestor.csv().");
    return (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one) {
        return String(one).trim();
      }).filter(Boolean);
  }

  // The SDK modules, or the name of the first one missing.
  sdk(): { modules: Record<string, any>; missing: string } {
    const { log, load } = this.deps;
    log.debug("Entering AwsIidAttestor.sdk().");
    const modules: Record<string, any> = {};
    for (let i = 0; i < PACKAGES.length; i++) {
      try {
        modules[PACKAGES[i]] = load(PACKAGES[i]);
      } catch (e) {
        log.debug("Caught in AwsIidAttestor.sdk(): " +
                  ((e && e.message) || e));
        log.debug("Leaving AwsIidAttestor.sdk(). Missing " + PACKAGES[i]);
        return { modules: {}, missing: PACKAGES[i] };
      }
    }
    log.debug("Leaving AwsIidAttestor.sdk().");
    return { modules: modules, missing: '' };
  }

  // One client of an SDK, for a region, assuming `roleArn` when given.
  client(modules: Record<string, any>, pkg: string, ctor: string,
         region: string, roleArn: string): any {
    const { log, config } = this.deps;
    log.debug("Entering AwsIidAttestor.client(). " + ctor + "@" + region);
    const options: any = { region: region };
    const endpoint = String(config.value('spiffe.awsIidEndpoint') || '');
    if (endpoint) options.endpoint = endpoint;
    if (roleArn) {
      options.credentials = modules['@aws-sdk/credential-providers']
        .fromTemporaryCredentials({
          params: { RoleArn: roleArn, RoleSessionName: 'spire-server' },
          clientConfig: { region: region } });
    }
    log.debug("Leaving AwsIidAttestor.client().");
    return new modules[pkg][ctor](options);
  }

  // The organization check's configuration, or null when there is none.
  // Throws a sentence for one that is not usable.
  orgConfig(): any {
    const { log, config } = this.deps;
    log.debug("Entering AwsIidAttestor.orgConfig().");
    const raw = String(config.value('spiffe.awsIidVerifyOrganization') || '')
      .trim();
    if (!raw) {
      log.debug("Leaving AwsIidAttestor.orgConfig(). None.");
      return null;
    }
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed.accountList)) {
      if (parsed.managementAccountId || parsed.assumeOrgRole) {
        log.debug("Leaving AwsIidAttestor.orgConfig(). Both.");
        // error-code: none — turned into STS-SPIFFE-0085 by the caller
        throw new Error('accountList is mutually exclusive with ' +
                        'managementAccountId and assumeOrgRole');
      }
      parsed.accountList.forEach(function (id) {
        if (!/^[0-9]{12}$/.test(String(id))) {
          // error-code: none — turned into STS-SPIFFE-0085 by the caller
          throw new Error('invalid account id "' + id + '" in accountList, ' +
                          'expected a 12-digit AWS account id');
        }
      });
    } else if (!parsed.managementAccountId || !parsed.assumeOrgRole) {
      log.debug("Leaving AwsIidAttestor.orgConfig(). Incomplete.");
      // error-code: none — turned into STS-SPIFFE-0085 by the caller
      throw new Error('managementAccountId and assumeOrgRole are both ' +
                      'required, or accountList instead');
    }
    const ttl = parsed.orgAccountMapTtl === undefined
      ? ORG_DEFAULT_TTL_SECONDS : Number(parsed.orgAccountMapTtl);
    if (!(ttl >= ORG_MIN_TTL_SECONDS)) {
      log.debug("Leaving AwsIidAttestor.orgConfig(). TTL.");
      // error-code: none — turned into STS-SPIFFE-0085 by the caller
      throw new Error('orgAccountMapTtl must be at least ' +
                      ORG_MIN_TTL_SECONDS + ' seconds');
    }
    log.debug("Leaving AwsIidAttestor.orgConfig().");
    return Object.assign({ managementAccountRegion: ORG_DEFAULT_REGION },
                         parsed, { orgAccountMapTtl: ttl });
  }

  // A cached set that is reloaded when stale and, on a miss, refreshed up to
  // REFRESH_RETRIES times per TTL — SPIRE's orgValidator and eksValidator.
  async cachedMember(cache: Record<string, any>, key: string, id: string,
                     ttlSeconds: number,
                     loader: () => Promise<Set<string>>): Promise<boolean> {
    const { log, now } = this.deps;
    log.debug("Entering AwsIidAttestor.cachedMember(). " + id);
    let entry = cache[key];
    if (!entry || entry.until < now()) {
      entry = { members: await loader(), until: now() + ttlSeconds * 1000,
                retries: REFRESH_RETRIES };
      cache[key] = entry;
      log.debug("Leaving AwsIidAttestor.cachedMember(). Reloaded.");
      return entry.members.has(id);
    }
    if (!entry.members.has(id) && entry.retries > 0) {
      entry.retries--;
      entry.members = await loader();
    }
    log.debug("Leaving AwsIidAttestor.cachedMember().");
    return entry.members.has(id);
  }

  // Every ACTIVE account of the organization.
  async organizationAccounts(modules: any, org: any): Promise<Set<string>> {
    const { log } = this.deps;
    log.debug("Entering AwsIidAttestor.organizationAccounts().");
    if (Array.isArray(org.accountList)) {
      log.debug("Leaving AwsIidAttestor.organizationAccounts(). A list.");
      return new Set(org.accountList.map(String));
    }
    const partition = String(this.deps.config.value('spiffe.awsIidPartition'));
    const client = this.client(modules, '@aws-sdk/client-organizations',
      'OrganizationsClient', org.managementAccountRegion,
      'arn:' + partition + ':iam::' + org.managementAccountId + ':role/' +
      org.assumeOrgRole);
    const out = new Set<string>();
    let token = undefined;
    do {
      const page = await client.send(new modules[
        '@aws-sdk/client-organizations'].ListAccountsCommand(
        token ? { NextToken: token } : {}));
      (page.Accounts || []).forEach(function (account) {
        if (account.Status === 'ACTIVE' && account.Id) out.add(account.Id);
      });
      token = page.NextToken;
    } while (token);
    log.debug("Leaving AwsIidAttestor.organizationAccounts(). " + out.size);
    return out;
  }

  // Every instance in a node group of the configured EKS clusters.
  async eksInstances(modules: any, region: string, roleArn: string,
                     clusters: string[]): Promise<Set<string>> {
    const { log } = this.deps;
    log.debug("Entering AwsIidAttestor.eksInstances().");
    const eksSdk = modules['@aws-sdk/client-eks'];
    const asSdk = modules['@aws-sdk/client-auto-scaling'];
    const eks = this.client(modules, '@aws-sdk/client-eks', 'EKSClient',
                            region, roleArn);
    const as = this.client(modules, '@aws-sdk/client-auto-scaling',
                           'AutoScalingClient', region, roleArn);
    const out = new Set<string>();
    for (let c = 0; c < clusters.length; c++) {
      let token = undefined;
      do {
        const page = await eks.send(new eksSdk.ListNodegroupsCommand(
          { clusterName: clusters[c], nextToken: token }));
        for (const group of page.nodegroups || []) {
          const described = await eks.send(new eksSdk.DescribeNodegroupCommand(
            { clusterName: clusters[c], nodegroupName: group }));
          const groups = (((described.nodegroup || {}).resources || {})
            .autoScalingGroups || []);
          for (const asg of groups) {
            if (!asg.name) continue;
            let asToken = undefined;
            do {
              const asPage = await as.send(
                new asSdk.DescribeAutoScalingGroupsCommand({
                  AutoScalingGroupNames: [asg.name], NextToken: asToken }));
              (asPage.AutoScalingGroups || []).forEach(function (one) {
                (one.Instances || []).forEach(function (instance) {
                  if (instance.InstanceId) out.add(instance.InstanceId);
                });
              });
              asToken = asPage.NextToken;
            } while (asToken);
          }
        }
        token = page.nextToken;
      } while (token);
    }
    log.debug("Leaving AwsIidAttestor.eksInstances(). " + out.size);
    return out;
  }

  // SPIRE's `checkBlockDevice()`: '' or why not.
  blockDeviceProblem(instance: any): string {
    const { log } = this.deps;
    log.debug("Entering AwsIidAttestor.blockDeviceProblem().");
    const iface = (instance.NetworkInterfaces || []).filter(function (one) {
      return one.Attachment && Number(one.Attachment.DeviceIndex) === 0;
    })[0];
    if (!iface) {
      log.debug("Leaving AwsIidAttestor.blockDeviceProblem(). No eth0.");
      return 'the EC2 instance network interface with device index 0 is ' +
             'inaccessible';
    }
    if (instance.RootDeviceType === 'instance-store') {
      log.debug("Leaving AwsIidAttestor.blockDeviceProblem(). Instance " +
                "store.");
      return '';
    }
    const root = (instance.BlockDeviceMappings || []).filter(function (one) {
      return one.DeviceName === instance.RootDeviceName;
    })[0];
    if (!root || !root.Ebs) {
      log.debug("Leaving AwsIidAttestor.blockDeviceProblem(). No root.");
      return 'failed to locate the root device block mapping with name "' +
             instance.RootDeviceName + '"';
    }
    const disparity = Math.abs(
      Math.floor(new Date(iface.Attachment.AttachTime).getTime() / 1000) -
      Math.floor(new Date(root.Ebs.AttachTime).getTime() / 1000));
    if (disparity > MAX_ATTACH_SECONDS) {
      log.debug("Leaving AwsIidAttestor.blockDeviceProblem(). Disparity.");
      return 'failed checking the disparity device attach times, root ' +
             'BlockDeviceMapping and NetworkInterface[0] attach times differ ' +
             'by ' + disparity + ' seconds';
    }
    log.debug("Leaving AwsIidAttestor.blockDeviceProblem().");
    return '';
  }

  async attest(context: NodeAttestationContext):
      Promise<NodeAttestationResult> {
    const { log, config, stsCrypto, pki, spiffeId, rpc, agentPath } =
      this.deps;
    const self = this;
    log.debug("Entering AwsIidAttestor.attest().");
    const call = context.call;
    const status = rpc.grpc.status;
    // THE CONFIGURATION AND THE SDK.
    let template = null;
    let org = null;
    try {
      template = new agentPath.AgentPathTemplate(
        String(config.value('spiffe.awsIidAgentPathTemplate') || '') ||
        DEFAULT_TEMPLATE);
      org = this.orgConfig();
    } catch (e) {
      log.debug("Caught in AwsIidAttestor.attest(): " +
                ((e && e.message) || e));
      throw this.refuse(call, 'STS-SPIFFE-0085', status.FAILED_PRECONDITION,
                        'aws_iid is not configured in this realm: ' +
                        e.message + '.');
    }
    const sdk = this.sdk();
    if (sdk.missing) {
      log.debug("Leaving AwsIidAttestor.attest(). No SDK.");
      throw this.refuse(call, 'STS-SPIFFE-0106', status.FAILED_PRECONDITION,
        'aws_iid calls EC2 with ' + sdk.missing + ' and it is not ' +
        'installed. The AWS SDK is an optional peer dependency: run `npm ' +
        'install ' + PACKAGES.join(' ') + '` in this deployment.');
    }
    const modules = sdk.modules;
    // 1–2. THE DOCUMENT AND ITS SIGNATURE.
    let data = null;
    let doc = null;
    try {
      data = JSON.parse(Buffer.from(context.payload || []).toString('utf8'));
      doc = JSON.parse(String(data.document || ''));
    } catch (e) {
      log.debug("Caught in AwsIidAttestor.attest(): " +
                ((e && e.message) || e));
    }
    if (!data || !doc || typeof doc !== 'object') {
      log.debug("Leaving AwsIidAttestor.attest(). Unreadable.");
      throw this.refuse(call, 'STS-SPIFFE-0086', status.INVALID_ARGUMENT,
                        'failed to unmarshal the attestation data or the IID');
    }
    const rsa2048 = !!data.rsa2048;
    const signature = String(rsa2048 ? data.rsa2048 : data.signature || '');
    if (!signature) {
      log.debug("Leaving AwsIidAttestor.attest(). No signature.");
      throw this.refuse(call, 'STS-SPIFFE-0086', status.INVALID_ARGUMENT,
        'instance identity cryptographic signature is required');
    }
    const certificate = pki.awsIidCertificate(doc.region,
                                              rsa2048 ? 'rsa2048' : 'rsa1024');
    if (!certificate) {
      log.debug("Leaving AwsIidAttestor.attest(). No certificate.");
      throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
        'failed to load the AWS CA certificate for region "' + doc.region +
        '": unsupported region');
    }
    const document = Buffer.from(String(data.document), 'utf8');
    let verified = false;
    let why = 'failed to verify the cryptographic signature';
    if (rsa2048) {
      const result = await stsCrypto.verifyPkcs7SignedData(
        Buffer.from(signature.replace(/\s+/g, ''), 'base64'),
        { certificates: [certificate.der] });
      verified = result.ok && result.content.equals(document);
      why = !result.ok ? 'failed verification of instance identity ' +
        'cryptographic signature: ' + result.why
        : 'instance identity document does not match the verified PKCS7 ' +
          'content';
    } else {
      verified = await stsCrypto.verifyRawSignature(
        { family: 'rsa-pkcs1', hash: 'sha256' }, certificate.x509.publicKey,
        document, Buffer.from(signature, 'base64'));
    }
    if (!verified) {
      log.debug("Leaving AwsIidAttestor.attest(). Did not verify.");
      throw this.refuse(call, 'STS-SPIFFE-0107', status.INVALID_ARGUMENT, why);
    }
    const accountId = String(doc.accountId || '');
    const region = String(doc.region || '');
    const instanceId = String(doc.instanceId || '');
    const partition = String(config.value('spiffe.awsIidPartition'));
    const assumeRole = String(config.value('spiffe.awsIidAssumeRole') || '');
    const roleArn = assumeRole ? 'arn:' + partition + ':iam::' + accountId +
                                 ':role/' + assumeRole : '';
    // 3. THE ORGANIZATION AND THE EKS CLUSTERS.
    if (org) {
      let member = false;
      try {
        member = await this.cachedMember(this.orgCache, JSON.stringify(org),
          accountId, org.orgAccountMapTtl, function () {
            return self.organizationAccounts(modules, org);
          });
      } catch (e) {
        log.debug("Caught in AwsIidAttestor.attest(): " +
                  ((e && e.message) || e));
        throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
          'failed aws ec2 attestation, issue while verifying if nodes ' +
          'account id: ' + accountId + ' belong to org: ' + e.message);
      }
      if (!member) {
        log.debug("Leaving AwsIidAttestor.attest(). Not in the org.");
        throw this.refuse(call, 'STS-SPIFFE-0108', status.INTERNAL,
          'failed aws ec2 attestation, nodes account id: ' + accountId +
          ' is not part of configured organization or doesn\'t have ' +
          'ACTIVE status');
      }
    }
    const clusters = this.csv('spiffe.awsIidEksClusterNames');
    if (clusters.length) {
      let member = false;
      try {
        member = await this.cachedMember(this.eksCache,
          accountId + '@' + region + '|' + clusters.join(','), instanceId,
          EKS_TTL_SECONDS, function () {
            return self.eksInstances(modules, region, roleArn, clusters);
          });
      } catch (e) {
        log.debug("Caught in AwsIidAttestor.attest(): " +
                  ((e && e.message) || e));
        throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
          'failed aws eks attestation, issue while verifying if nodes id: ' +
          instanceId + ' belong to cluster: ' + e.message);
      }
      if (!member) {
        log.debug("Leaving AwsIidAttestor.attest(). Not in the clusters.");
        throw this.refuse(call, 'STS-SPIFFE-0108', status.INTERNAL,
          'failed aws eks attestation, nodes id: ' + instanceId +
          ' is not part of configured EKS cluster');
      }
    }
    // 4. THE INSTANCE.
    const ec2 = this.client(modules, '@aws-sdk/client-ec2', 'EC2Client',
                            region, roleArn);
    let described = null;
    try {
      described = await ec2.send(new modules['@aws-sdk/client-ec2']
        .DescribeInstancesCommand({
          InstanceIds: [instanceId],
          Filters: [{ Name: 'instance-state-name',
                      Values: ['pending', 'running'] }] }));
    } catch (e) {
      log.debug("Caught in AwsIidAttestor.attest(): " +
                ((e && e.message) || e));
      throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
                        'failed to describe instance: ' + e.message);
    }
    const reservations = (described && described.Reservations) || [];
    const instance = reservations.length &&
      (reservations[0].Instances || []).length
      ? reservations[0].Instances[0] : null;
    const trusted = this.csv('spiffe.awsIidLocalValidAccountIds')
      .indexOf(accountId) >= 0;
    const checkBlock = !trusted &&
      !config.value('spiffe.awsIidSkipBlockDevice');
    const templateText = String(config.value('spiffe.awsIidAgentPathTemplate')
                                || '');
    if ((checkBlock || templateText.indexOf('.Tags') >= 0) && !instance) {
      log.debug("Leaving AwsIidAttestor.attest(). No instance.");
      throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
        'failed to query AWS via describe-instances: returned no ' +
        (reservations.length ? 'instances' : 'reservations'));
    }
    if (checkBlock) {
      const problem = this.blockDeviceProblem(instance);
      if (problem) {
        log.debug("Leaving AwsIidAttestor.attest(). Block device.");
        throw this.refuse(call, 'STS-SPIFFE-0109', status.INTERNAL,
                          'failed aws ec2 attestation: ' + problem);
      }
    }
    // 5. THE AGENT AND ITS SELECTORS.
    const tags: Record<string, string> = {};
    ((instance && instance.Tags) || []).forEach(function (tag) {
      if (tag.Key !== undefined && tag.Value !== undefined) {
        tags[tag.Key] = tag.Value;
      }
    });
    let agentId = '';
    try {
      agentId = spiffeId.make(context.trustDomain, '/spire/agent' +
        template.execute({ PluginName: this.type, AccountID: accountId,
                           Region: region, InstanceID: instanceId,
                           TrustDomain: '', Tags: tags }));
    } catch (e) {
      log.debug("Caught in AwsIidAttestor.attest(): " +
                ((e && e.message) || e));
    }
    if (!agentId || !spiffeId.parse(agentId).ok) {
      log.debug("Leaving AwsIidAttestor.attest(). No agent id.");
      throw this.refuse(call, 'STS-SPIFFE-0095', status.INTERNAL,
                        'failed to create spiffe ID from the agent path ' +
                        'template');
    }
    const set = new Set<string>();
    const iam = config.value('spiffe.awsIidDisableInstanceProfileSelectors')
      ? null : this.client(modules, '@aws-sdk/client-iam', 'IAMClient',
                           region, roleArn);
    for (const reservation of reservations) {
      for (const one of reservation.Instances || []) {
        (one.Tags || []).forEach(function (tag) {
          set.add('tag:' + tag.Key + ':' + tag.Value);
        });
        (one.SecurityGroups || []).forEach(function (sg) {
          set.add('sg:id:' + sg.GroupId);
          set.add('sg:name:' + sg.GroupName);
        });
        const arn = one.IamInstanceProfile && one.IamInstanceProfile.Arn;
        if (iam && arn) {
          const match = /instance-profile[/:](.+)$/.exec(
            String(arn).split(':').slice(5).join(':'));
          if (!match) {
            log.debug("Leaving AwsIidAttestor.attest(). A bad ARN.");
            throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
                              'arn is not for an instance profile');
          }
          const name = match[1].split('/').pop();
          let profile = null;
          try {
            profile = await iam.send(new modules['@aws-sdk/client-iam']
              .GetInstanceProfileCommand({ InstanceProfileName: name }));
          } catch (e) {
            log.debug("Caught in AwsIidAttestor.attest(): " +
                      ((e && e.message) || e));
            throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
                              'failed to get intance profile: ' + e.message);
          }
          (((profile || {}).InstanceProfile || {}).Roles || [])
            .forEach(function (role) {
              if (role.Arn) set.add('iamrole:' + role.Arn);
            });
        }
      }
    }
    set.add('account_id:' + accountId);
    set.add('image:id:' + String(doc.imageId || ''));
    set.add('instance:id:' + instanceId);
    set.add('region:' + region);
    set.add('az:' + String(doc.availabilityZone || ''));
    log.debug("Leaving AwsIidAttestor.attest(). " + agentId);
    return {
      agentId: agentId,
      selectors: Array.from(set).sort().map(function (value) {
        return { type: 'aws_iid', value: value };
      }),
      canReattest: false,
      method: 'agent attestation (aws_iid)',
      note: 'attested by an AWS-signed instance identity document for ' +
            accountId + '/' + region + '/' + instanceId,
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
  AwsIidAttestor: AwsIidAttestor,
  PACKAGES: PACKAGES
};
