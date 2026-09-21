'use strict';
//
// File: spiffe_attestor_azure_imds.ts
//
// ---------------------------------------------------------------------------
// THE `azure_imds` NODE ATTESTOR — AN AZURE ATTESTED DOCUMENT (#40 phase
// three, 2026-09-21).
//
// SPIRE's `pkg/server/plugin/nodeattestor/azureimds`, which replaced
// `azure_msi`. It is the one node attestor that CHALLENGES FIRST:
//
//   1. The server sends 32 random alphanumerics; the agent asks its
//      instance metadata service for an attested document carrying that
//      nonce and answers `{"document": {"encoding", "signature"},
//      "metadata": {"agentDomain", "vmssName"}}` — the metadata being the
//      agent's own UNTRUSTED claims, used only to choose.
//   2. The document is a PKCS#7 SignedData, verified by `common/crypto.js`'s
//      `verifyPkcs7SignedData()`. Its signing certificate must name one of
//      `spiffe.azureImdsAllowedMetadataDomains` in a DNS subjectAltName, and
//      chain — through the intermediate its CA Issuers URL names, which must
//      be on `spiffe.azureImdsIntermediateHost` (www.microsoft.com), fetched
//      as a signed artifact — to the roots SPIRE embeds (`pki.js`'s
//      `azureImdsRoots()`) or `spiffe.azureImdsTrustBundle`
//      (`pki.verifyPathToAnchors()`).
//   3. The signed content must carry THIS challenge's nonce, a VM ID that is
//      a UUID, and a subscription ID.
//   4. The tenant is the one the agent named, which must be configured in
//      `spiffe.azureImdsTenants` (its ID looked up when not given); the
//      subscription must be one it allows.
//   5. The agent is `spiffe.azureImdsAgentPathTemplate` (default
//      `/{{ .PluginName }}/{{ .TenantID }}/{{ .SubscriptionID }}/{{ .VMID }}`),
//      with SPIRE's selectors from Azure Resource Graph (or the scale set's
//      VM list): subscription-id, vm-name, vm-location, resource-group,
//      vm-tag (allowed), network-security-group, virtual-network,
//      virtual-network-subnet, vmss-name. Trust on first use.
//
// **THE AZURE SDK IS AN OPTIONAL PEER DEPENDENCY** — `@azure/identity`,
// `@azure/arm-resourcegraph`, `@azure/arm-compute` — loaded when the attestor
// runs; a tenant authenticates with a federated token FILE (`tokenAuth`) or
// the SDK's default credential. **An app secret is never a setting.**
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import fs = require('fs');
import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import pki = require('../common/pki');
import spiffeId = require('./spiffe_id');
import rpc = require('./spiffe_grpc');
import agentPath = require('./spiffe_agent_path');
import outbound = require('../federation/federation_http');

type NodeAttestationContext =
  import('../types/spiffe-attestation').NodeAttestationContext;
type NodeAttestationResult =
  import('../types/spiffe-attestation').NodeAttestationResult;

const DEFAULT_TEMPLATE = '/{{ .PluginName }}/{{ .TenantID }}/' +
  '{{ .SubscriptionID }}/{{ .VMID }}';
const PACKAGES = ['@azure/identity', '@azure/arm-resourcegraph',
                  '@azure/arm-compute'];
const ALPHANUMERIC = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' +
  '0123456789';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VMSS_NAME = /^[a-zA-Z0-9._-]+$/;

interface AzureImdsDeps {
  log: typeof log;
  crypto: typeof nodeCrypto;
  fs: typeof fs;
  config: typeof config;
  errorCodes: typeof errorCodes;
  stsCrypto: typeof stsCrypto;
  pki: typeof pki;
  spiffeId: typeof spiffeId;
  rpc: typeof rpc;
  agentPath: typeof agentPath;
  outbound: { requestConfigured(url: string, options?: any): Promise<any> };
  load(pkg: string): any;
}

class AzureImdsAttestor {
  readonly type = 'azure_imds';
  readonly verifies = 'An Azure attested document carrying this server\'s ' +
    'nonce, signed under the Azure roots, for a configured tenant and ' +
    'subscription; once per VM.';
  // Tenant domain → tenant ID, looked up once.
  private tenantIds: Record<string, string> = {};

  constructor(private readonly deps: AzureImdsDeps) {
    deps.log.debug("Entering AzureImdsAttestor.constructor().");
    deps.log.debug("Leaving AzureImdsAttestor.constructor().");
  }

  static defaultDeps(): AzureImdsDeps {
    helpers.log.debug("Entering AzureImdsAttestor.defaultDeps().");
    helpers.log.debug("Leaving AzureImdsAttestor.defaultDeps().");
    return {
      log: log, crypto: nodeCrypto, fs: fs, config: config,
      errorCodes: errorCodes, stsCrypto: stsCrypto, pki: pki,
      spiffeId: spiffeId, rpc: rpc, agentPath: agentPath, outbound: outbound,
      load: function (pkg) {
        return require(pkg);
      }
    };
  }

  refuse(call: any, code: string, grpcCode: number, message: string): Error {
    const { log, errorCodes, rpc } = this.deps;
    log.debug("Entering AzureImdsAttestor.refuse(). " + code);
    errorCodes.mark(call, code);
    log.debug("Leaving AzureImdsAttestor.refuse().");
    // error-code: none — the helper's own internals: every caller passes
    // the code, and it is marked on the line above
    return rpc.statusError(grpcCode, message);
  }

  // The realm's tenants, or throws a sentence.
  tenants(): Record<string, any> {
    const { log, config } = this.deps;
    log.debug("Entering AzureImdsAttestor.tenants().");
    const raw = String(config.value('spiffe.azureImdsTenants') || '').trim();
    const parsed = raw ? JSON.parse(raw) : {};
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) ||
        !Object.keys(parsed).length) {
      log.debug("Leaving AzureImdsAttestor.tenants(). None.");
      // error-code: none — turned into STS-SPIFFE-0085 by the caller
      throw new Error('configuration must have at least one tenant ' +
                      '(spiffe.azureImdsTenants)');
    }
    Object.keys(parsed).forEach(function (domain) {
      const one = parsed[domain] || {};
      if (one.tokenAuth && (!one.tokenAuth.tokenPath || !one.tokenAuth.appId)) {
        // error-code: none — turned into STS-SPIFFE-0085 by the caller
        throw new Error('misconfigured tenant "' + domain + '": tokenAuth ' +
                        'needs tokenPath and appId');
      }
      (one.restrictToSubscriptions || []).forEach(function (sub) {
        if (!String(sub || '').trim()) {
          // error-code: none — turned into STS-SPIFFE-0085 by the caller
          throw new Error('misconfigured tenant "' + domain + '": ' +
                          'restrictToSubscriptions entries must be non-empty');
        }
      });
    });
    log.debug("Leaving AzureImdsAttestor.tenants().");
    return parsed;
  }

  csv(key: string): string[] {
    const { log, config } = this.deps;
    log.debug("Entering AzureImdsAttestor.csv(). " + key);
    const raw = config.value(key);
    log.debug("Leaving AzureImdsAttestor.csv().");
    return (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one) {
        return String(one).trim();
      }).filter(Boolean);
  }

  // A tenant domain's ID: configured, or looked up once (SPIRE's
  // `lookupTenantID()`), or throws a sentence.
  async tenantIdOf(domain: string, tenant: any): Promise<string> {
    const { log, config, outbound } = this.deps;
    log.debug("Entering AzureImdsAttestor.tenantIdOf(). " + domain);
    if (tenant.tenantId) {
      log.debug("Leaving AzureImdsAttestor.tenantIdOf(). Configured.");
      return String(tenant.tenantId);
    }
    if (this.tenantIds[domain]) {
      log.debug("Leaving AzureImdsAttestor.tenantIdOf(). Held.");
      return this.tenantIds[domain];
    }
    const base = String(config.value('spiffe.azureImdsDiscoveryUrl'))
      .replace(/\/+$/, '');
    const answer = await outbound.requestConfigured(base + '/' +
      encodeURIComponent(domain) + '/.well-known/openid-configuration');
    if (!answer.ok) {
      log.debug("Leaving AzureImdsAttestor.tenantIdOf(). Failed.");
      // error-code: none — turned into STS-SPIFFE-0099 by the caller
      throw new Error('failed to fetch tenant ID: ' + answer.why);
    }
    const issuer = String((JSON.parse(answer.body.toString('utf8')) || {})
      .issuer || '');
    const match = /^https:\/\/sts\.windows\.net\/([^/]+)\/$/.exec(issuer);
    if (!match) {
      log.debug("Leaving AzureImdsAttestor.tenantIdOf(). Malformed.");
      // error-code: none — turned into STS-SPIFFE-0099 by the caller
      throw new Error('malformed tenant ID: "' + issuer + '"');
    }
    this.tenantIds[domain] = match[1];
    log.debug("Leaving AzureImdsAttestor.tenantIdOf(). Looked up.");
    return match[1];
  }

  // SPIRE's `validateAttestedDocument()`: resolves the signed content, or
  // throws a sentence.
  async validatedContent(document: any): Promise<any> {
    const { log, config, stsCrypto, pki, outbound } = this.deps;
    log.debug("Entering AzureImdsAttestor.validatedContent().");
    if (!document || !document.signature) {
      log.debug("Leaving AzureImdsAttestor.validatedContent(). None.");
      // error-code: none — turned into STS-SPIFFE-0107 by the caller
      throw new Error('missing signature in attested document');
    }
    const verified = await stsCrypto.verifyPkcs7SignedData(
      Buffer.from(String(document.signature).replace(/\s+/g, ''), 'base64'));
    if (!verified.ok) {
      log.debug("Leaving AzureImdsAttestor.validatedContent(). Signature.");
      // error-code: none — turned into STS-SPIFFE-0107 by the caller
      throw new Error('signature verification failed: ' + verified.why);
    }
    const signer = pki.certificateFromDer(verified.signerDer);
    // The intermediate, from the host this server allows.
    const aia = /CA Issuers - URI:(\S+)/.exec(String(
      signer.x509.infoAccess || ''));
    if (!aia) {
      log.debug("Leaving AzureImdsAttestor.validatedContent(). No AIA.");
      // error-code: none — turned into STS-SPIFFE-0107 by the caller
      throw new Error('failed to get intermediate certificate: no CA ' +
                      'Issuers URL found in certificate');
    }
    const allowedHost = String(config.value(
      'spiffe.azureImdsIntermediateHost'));
    let host = '';
    try {
      host = new URL(aia[1]).host;
    } catch (e) {
      log.debug("Caught in AzureImdsAttestor.validatedContent(): " +
                ((e && e.message) || e));
    }
    if (host !== allowedHost) {
      log.debug("Leaving AzureImdsAttestor.validatedContent(). Host.");
      // error-code: none — turned into STS-SPIFFE-0107 by the caller
      throw new Error('failed to get intermediate certificate: CA Issuers ' +
                      'URL host "' + host + '" does not match expected ' +
                      'value "' + allowedHost + '"');
    }
    const fetched = await outbound.requestConfigured(aia[1],
      { signedArtifact: true, headers: { 'Accept': '*/*' } });
    if (!fetched.ok) {
      log.debug("Leaving AzureImdsAttestor.validatedContent(). Fetch.");
      // error-code: none — turned into STS-SPIFFE-0099 by the caller
      const e: any = new Error('failed to fetch intermediate certificate: ' +
                               fetched.why);
      e.unreachable = true;
      throw e;
    }
    let intermediate = pki.certificateFromDer(fetched.body);
    if (!intermediate) {
      intermediate = pki.certificateBundle(fetched.body.toString('utf8'))
        .certificates[0] || null;
    }
    if (!intermediate) {
      log.debug("Leaving AzureImdsAttestor.validatedContent(). Unreadable.");
      // error-code: none — turned into STS-SPIFFE-0107 by the caller
      throw new Error('failed to parse intermediate certificate');
    }
    // The signing certificate names an allowed metadata domain.
    const domains = this.csv('spiffe.azureImdsAllowedMetadataDomains');
    const dnsNames = (String(signer.x509.subjectAltName || '')
      .match(/DNS:[^,\s]+/g) || []).map(function (one) {
      return one.slice(4);
    });
    if (!dnsNames.some(function (name) {
      return domains.some(function (base) {
        return name === base || name.slice(-(base.length + 1)) === '.' + base;
      });
    })) {
      log.debug("Leaving AzureImdsAttestor.validatedContent(). Domain.");
      // error-code: none — turned into STS-SPIFFE-0107 by the caller
      throw new Error('signing certificate validation failed: certificate ' +
                      'does not have any valid domain in SAN (found SANs=[' +
                      dnsNames.join(' ') + '], allowed domains=[' +
                      domains.join(' ') + '])');
    }
    const roots = pki.azureImdsRoots().concat(pki.certificateBundle(String(
      config.value('spiffe.azureImdsTrustBundle') || '')).certificates);
    const path = await pki.verifyPathToAnchors(signer.der,
                                               [intermediate.der], roots);
    if (!path.ok) {
      log.debug("Leaving AzureImdsAttestor.validatedContent(). Chain.");
      // error-code: none — turned into STS-SPIFFE-0107 by the caller
      throw new Error('certificate chain validation failed: unable to ' +
                      'verify signing certificate against root CAs: ' +
                      path.reason);
    }
    log.debug("Leaving AzureImdsAttestor.validatedContent().");
    return JSON.parse(verified.content.toString('utf8'));
  }

  // The SDK credential for a tenant.
  credential(sdk: any, tenantId: string, tenant: any): any {
    const { log, fs } = this.deps;
    log.debug("Entering AzureImdsAttestor.credential().");
    if (tenant.tokenAuth) {
      const path = String(tenant.tokenAuth.tokenPath);
      log.debug("Leaving AzureImdsAttestor.credential(). Token file.");
      return new sdk.ClientAssertionCredential(tenantId,
        String(tenant.tokenAuth.appId), function () {
          return Promise.resolve(fs.readFileSync(path, 'utf8').trim());
        });
    }
    log.debug("Leaving AzureImdsAttestor.credential(). Default.");
    return new sdk.DefaultAzureCredential({ tenantId: tenantId });
  }

  // One Resource Graph query's rows.
  async graph(client: any, query: string, subscription: string):
      Promise<any[]> {
    const { log } = this.deps;
    log.debug("Entering AzureImdsAttestor.graph().");
    const answer = await client.resources({
      query: query, subscriptions: subscription ? [subscription] : undefined,
      options: { resultFormat: 'objectArray' } });
    log.debug("Leaving AzureImdsAttestor.graph().");
    return answer && Number(answer.totalRecords) > 0 &&
           Array.isArray(answer.data) ? answer.data : [];
  }

  // SPIRE's `buildSelectors()`.
  async selectors(modules: any, cred: any, tenant: any, vmssName: string,
                  vmId: string, subscription: string): Promise<string[]> {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AzureImdsAttestor.selectors().");
    const graph = new modules['@azure/arm-resourcegraph']
      .ResourceGraphClient(cred);
    const set = new Set<string>();
    let vm = null;
    if (vmssName) {
      const info = (await this.graph(graph,
        'resources | where type =~ ' +
        '\'microsoft.compute/virtualmachinescalesets\'' +
        ' | where name == \'' + vmssName + '\' | project id, name, location, ' +
        'resourceGroup, subscriptionId', subscription))[0];
      if (!info) {
        log.debug("Leaving AzureImdsAttestor.selectors(). No VMSS.");
        // error-code: none — turned into STS-SPIFFE-0099 by the caller
        throw new Error('resource not found');
      }
      const compute = new modules['@azure/arm-compute']
        .ComputeManagementClient(cred, subscription);
      for await (const instance of compute.virtualMachineScaleSetVMs.list(
        info.resourceGroup, vmssName)) {
        if (!instance || !instance.vmId || instance.vmId !== vmId) continue;
        vm = { name: instance.name, location: instance.location,
               resourceGroup: info.resourceGroup, tags: instance.tags || {},
               interfaces: self.vmssInterfaces(instance) };
        break;
      }
      if (!vm) {
        log.debug("Leaving AzureImdsAttestor.selectors(). No instance.");
        // error-code: none — turned into STS-SPIFFE-0099 by the caller
        throw new Error('VMSS instance "' + vmId + '" not found');
      }
      set.add('vmss-name:' + vmssName);
    } else {
      const row = (await this.graph(graph,
        'resources | where type =~ \'microsoft.compute/virtualmachines\'' +
        ' | where properties.vmId == \'' + vmId + '\' | project id, name, ' +
        'location, tags, vmId = properties.vmId, resourceGroup',
        subscription));
      if (row.length !== 1) {
        log.debug("Leaving AzureImdsAttestor.selectors(). Not one VM.");
        // error-code: none — turned into STS-SPIFFE-0099 by the caller
        throw new Error(row.length ? 'expected one result for resource at ' +
                                     'most' : 'resource not found');
      }
      const interfaces = await this.graph(graph,
        'Resources | where type == "microsoft.network/networkinterfaces"' +
        ' | where tolower(properties.virtualMachine.id) == tolower("' +
        row[0].id + '") | mv-expand ipConfig = properties.ipConfigurations' +
        ' | extend subnetId = tostring(ipConfig.properties.subnet.id)' +
        ' | extend vnetName = extract(@"virtualNetworks/([^/]+)", 1, ' +
        'subnetId) | extend subnetName = extract(@"subnets/([^/]+)$", 1, ' +
        'subnetId) | extend subnetObj = bag_pack("vnet", vnetName, "name", ' +
        'subnetName) | extend nsgId = tostring(properties.' +
        'networkSecurityGroup.id) | extend nsgRg = extract(@"resourceGroups/' +
        '([^/]+)",1,nsgId) | extend nsgName = extract(@"networkSecurity' +
        'Groups/([^/]+)",1,nsgId) | extend securityGroup = bag_pack(' +
        '"resourceGroup", nsgRg, "name",nsgName) | summarize subnets = ' +
        'make_list(subnetObj) by id, name, resourceGroup, securityGroup_str ' +
        '= tostring(securityGroup) | project name, resourceGroup, subnets, ' +
        'securityGroup = todynamic(securityGroup_str)', subscription);
      vm = { name: row[0].name, location: row[0].location,
             resourceGroup: row[0].resourceGroup, tags: row[0].tags || {},
             interfaces: interfaces };
    }
    set.add('subscription-id:' + subscription);
    set.add('vm-name:' + vm.name);
    set.add('vm-location:' + vm.location);
    set.add('resource-group:' + vm.resourceGroup);
    (tenant.allowedVmTags || []).forEach(function (tag) {
      const value = vm.tags[tag];
      if (value !== undefined && value !== null) {
        set.add('vm-tag:' + tag + ':' + value);
      }
    });
    (vm.interfaces || []).forEach(function (iface) {
      const sg = iface.securityGroup || {};
      if (sg.resourceGroup || sg.name) {
        set.add('network-security-group:' + (sg.resourceGroup || '') + ':' +
                (sg.name || ''));
      }
      (iface.subnets || []).forEach(function (subnet) {
        set.add('virtual-network:' + subnet.vnet);
        set.add('virtual-network-subnet:' + subnet.vnet + ':' + subnet.name);
      });
    });
    log.debug("Leaving AzureImdsAttestor.selectors().");
    return Array.from(set).sort();
  }

  // A scale set VM's network configuration as the Resource Graph rows are
  // shaped (SPIRE's `buildVirtualMachineFromVMSSInstance()`).
  vmssInterfaces(instance: any): any[] {
    const { log } = this.deps;
    log.debug("Entering AzureImdsAttestor.vmssInterfaces().");
    const configs = ((instance.networkProfileConfiguration || {})
      .networkInterfaceConfigurations) || [];
    const out = [];
    configs.forEach(function (one) {
      const nsgId = String(((one.networkSecurityGroup || {}).id) || '');
      const nsg = /^\/subscriptions\/[^/]+\/resourceGroups\/([^/]+)\/providers\/Microsoft\.Network\/networkSecurityGroups\/([^/]+)$/.exec(nsgId);
      const subnets = [];
      (one.ipConfigurations || []).forEach(function (ip) {
        const id = String(((ip.subnet || {}).id) || '');
        const m = /^\/subscriptions\/[^/]+\/resourceGroups\/([^/]+)\/providers\/Microsoft\.Network\/virtualNetworks\/([^/]+)\/subnets\/([^/]+)$/.exec(id);
        if (m) subnets.push({ vnet: m[2], name: m[3] });
      });
      out.push({ name: one.name, subnets: subnets,
                 securityGroup: nsg ? { resourceGroup: nsg[1], name: nsg[2] }
                                    : {} });
    });
    log.debug("Leaving AzureImdsAttestor.vmssInterfaces().");
    return out;
  }

  async attest(context: NodeAttestationContext):
      Promise<NodeAttestationResult> {
    const { log, crypto, config, spiffeId, rpc, agentPath, load } = this.deps;
    log.debug("Entering AzureImdsAttestor.attest().");
    const call = context.call;
    const status = rpc.grpc.status;
    let tenants = null;
    let template = null;
    try {
      tenants = this.tenants();
      template = new agentPath.AgentPathTemplate(
        String(config.value('spiffe.azureImdsAgentPathTemplate') || '') ||
        DEFAULT_TEMPLATE);
    } catch (e) {
      log.debug("Caught in AzureImdsAttestor.attest(): " +
                ((e && e.message) || e));
      throw this.refuse(call, 'STS-SPIFFE-0085', status.FAILED_PRECONDITION,
                        'azure_imds is not configured in this realm: ' +
                        e.message + '.');
    }
    const modules: Record<string, any> = {};
    for (let i = 0; i < PACKAGES.length; i++) {
      try {
        modules[PACKAGES[i]] = load(PACKAGES[i]);
      } catch (e) {
        log.debug("Caught in AzureImdsAttestor.attest(): " +
                  ((e && e.message) || e));
        throw this.refuse(call, 'STS-SPIFFE-0106', status.FAILED_PRECONDITION,
          'azure_imds calls Azure with ' + PACKAGES[i] + ' and it is not ' +
          'installed. The Azure SDK is an optional peer dependency: run ' +
          '`npm install ' + PACKAGES.join(' ') + '` in this deployment.');
      }
    }
    // 1. THE CHALLENGE FIRST.
    const random = crypto.randomBytes(32);
    let nonce = '';
    for (let i = 0; i < random.length; i++) {
      nonce += ALPHANUMERIC[random[i] % ALPHANUMERIC.length];
    }
    const answer = await context.challenge(Buffer.from(nonce, 'utf8'));
    let payload = null;
    try {
      payload = JSON.parse(answer.toString('utf8'));
    } catch (e) {
      log.debug("Caught in AzureImdsAttestor.attest(): " +
                ((e && e.message) || e));
    }
    if (!payload || typeof payload !== 'object') {
      log.debug("Leaving AzureImdsAttestor.attest(). Unreadable.");
      throw this.refuse(call, 'STS-SPIFFE-0086', status.INVALID_ARGUMENT,
                        'failed to unmarshal data payload');
    }
    // 2. THE DOCUMENT.
    let content = null;
    try {
      content = await this.validatedContent(payload.document);
    } catch (e) {
      log.debug("Caught in AzureImdsAttestor.attest(): " +
                ((e && e.message) || e));
      throw this.refuse(call, e.unreachable ? 'STS-SPIFFE-0099'
                                            : 'STS-SPIFFE-0107',
        e.unreachable ? status.INTERNAL : status.INVALID_ARGUMENT,
        'failed to validate attested document: ' + e.message);
    }
    // 3. ITS CONTENT.
    const vmId = String((content || {}).vmId || '');
    const subscription = String((content || {}).subscriptionId || '');
    const problem = !vmId ? 'missing VM ID in attested document'
      : !subscription ? 'missing subscription ID in attested document'
        : String(content.nonce || '') !== nonce ? 'nonce mismatch'
          : !UUID.test(vmId) ? 'invalid VM ID: invalid UUID format: "' +
                               vmId + '"' : '';
    if (problem) {
      log.debug("Leaving AzureImdsAttestor.attest(). " + problem);
      throw this.refuse(call, 'STS-SPIFFE-0110', status.INVALID_ARGUMENT,
                        problem);
    }
    // 4. THE TENANT AND THE SUBSCRIPTION.
    const metadata = payload.metadata || {};
    const domain = String(metadata.agentDomain || '');
    const tenant = Object.prototype.hasOwnProperty.call(tenants, domain)
      ? tenants[domain] : null;
    if (!tenant) {
      log.debug("Leaving AzureImdsAttestor.attest(). Tenant.");
      throw this.refuse(call, 'STS-SPIFFE-0108', status.PERMISSION_DENIED,
                        'tenant "' + domain + '" is not authorized');
    }
    const allowedSubs = (tenant.restrictToSubscriptions || []).map(
      function (one) {
        return String(one).trim();
      });
    if (allowedSubs.length && allowedSubs.indexOf(subscription) < 0) {
      log.debug("Leaving AzureImdsAttestor.attest(). Subscription.");
      throw this.refuse(call, 'STS-SPIFFE-0108', status.PERMISSION_DENIED,
                        'subscription "' + subscription + '" is not ' +
                        'authorized');
    }
    let tenantId = '';
    try {
      tenantId = await this.tenantIdOf(domain, tenant);
    } catch (e) {
      log.debug("Caught in AzureImdsAttestor.attest(): " +
                ((e && e.message) || e));
      throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
                        'unable to lookup tenant ID: ' + e.message);
    }
    // 5. THE AGENT AND ITS SELECTORS.
    let agentId = '';
    try {
      agentId = spiffeId.make(context.trustDomain, '/spire/agent' +
        template.execute({ PluginName: this.type, TenantID: tenantId,
                           SubscriptionID: subscription, VMID: vmId,
                           Nonce: nonce }));
    } catch (e) {
      log.debug("Caught in AzureImdsAttestor.attest(): " +
                ((e && e.message) || e));
    }
    if (!agentId || !spiffeId.parse(agentId).ok) {
      log.debug("Leaving AzureImdsAttestor.attest(). No agent id.");
      throw this.refuse(call, 'STS-SPIFFE-0095', status.INTERNAL,
                        'unable to make agent ID from the agent path ' +
                        'template');
    }
    const vmssName = metadata.vmssName === null ||
      metadata.vmssName === undefined ? '' : String(metadata.vmssName);
    if (vmssName && (vmssName.length > 64 || !VMSS_NAME.test(vmssName) ||
        !/^[a-zA-Z0-9]/.test(vmssName) || !/[a-zA-Z0-9_]$/.test(vmssName))) {
      log.debug("Leaving AzureImdsAttestor.attest(). VMSS name.");
      throw this.refuse(call, 'STS-SPIFFE-0086', status.INVALID_ARGUMENT,
                        'invalid VMSS name "' + vmssName + '"');
    }
    let selectors = [];
    try {
      const cred = this.credential(modules['@azure/identity'], tenantId,
                                   tenant);
      selectors = await this.selectors(modules, cred, tenant, vmssName, vmId,
                                       subscription);
    } catch (e) {
      log.debug("Caught in AzureImdsAttestor.attest(): " +
                ((e && e.message) || e));
      throw this.refuse(call, 'STS-SPIFFE-0099', status.INTERNAL,
                        'unable to get virtual machine: ' + e.message);
    }
    log.debug("Leaving AzureImdsAttestor.attest(). " + agentId);
    return {
      agentId: agentId,
      selectors: selectors.map(function (value) {
        return { type: 'azure_imds', value: value };
      }),
      canReattest: false,
      method: 'agent attestation (azure_imds)',
      note: 'attested by an Azure attested document for VM ' + vmId +
            ' in subscription ' + subscription,
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
  AzureImdsAttestor: AzureImdsAttestor,
  PACKAGES: PACKAGES
};
