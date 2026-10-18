// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/spiffe_targets.js
//
// ===========================================================================
// A RESTARTED NODE STAYS IN THE SPIFFE TARGET GROUPS (#323).
//
// ECS allows five target groups on a service and the node services use
// them, so the SPIFFE groups are registered by address at apply time. A
// task replaced since that apply is missing until the next apply. The
// remedy is `cluster/spiffe_targets.js`: the leader reconciles, the front
// process reconciles as it starts, and a stop deregisters only itself.
//
// IN PROCESS, on the host. The decision is which addresses are registered
// and which are removed, and a running load balancer cannot be told to
// present a stale member, an unhealthy one that must stay (#166), and a
// group that belongs to another environment. The module is JavaScript so
// a checkout can load it (#50). No AWS apply and no live health check.
// ===========================================================================

// Deleted rather than set: this file must not inherit a CONFIG_FILE.
delete process.env.CONFIG_FILE;

const fs = require('fs');
const http = require('http');
const path = require('path');

const SpiffeTargets = require('../cluster/spiffe_targets');

const log = require('bunyan').createLogger({
  name: 'spiffe_targets',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

const PREFIX = 'iya-sts-dev';
const SELF = '10.0.0.8';

function read(rel) {
  log.debug('Entering read().');
  const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
  log.debug('Leaving read().');
  return text;
}

function between(text, start, end) {
  log.debug('Entering between().');
  const at = text.indexOf(start);
  const to = text.indexOf(end, at + start.length);
  let slice = '';
  if (at >= 0 && to > at) {
    slice = text.slice(at, to);
  }
  log.debug('Leaving between().');
  return slice;
}

function resolveWith(value) {
  log.debug('Entering resolveWith().');
  log.debug('Leaving resolveWith().');
  return function () {
    return Promise.resolve(value);
  };
}

function copyTargets(targets) {
  log.debug('Entering copyTargets().');
  const out = (targets || []).map(function (member) {
    return { id: member.id, port: member.port };
  });
  log.debug('Leaving copyTargets().');
  return out;
}

// A load balancer that records every call. `health` of an ARN that was
// not listed in `healthByArn` rejects, so a group the filter should have
// skipped fails the reconcile instead of passing quietly.
function fakeElb(groups, healthByArn) {
  log.debug('Entering fakeElb().');
  const calls = { health: [], register: [], deregister: [] };
  const api = {
    calls: calls,
    listGroups: function () {
      log.debug('Entering listGroups().');
      log.debug('Leaving listGroups().');
      return Promise.resolve(groups);
    },
    health: function (arn) {
      log.debug('Entering health().');
      calls.health.push(arn);
      if (!Object.prototype.hasOwnProperty.call(healthByArn, arn)) {
        log.debug('Leaving health(). Unknown group.');
        return Promise.reject(new Error('health of ' + arn));
      }
      log.debug('Leaving health().');
      return Promise.resolve(healthByArn[arn]);
    },
    register: function (arn, targets) {
      log.debug('Entering register().');
      calls.register.push({ arn: arn, targets: copyTargets(targets) });
      log.debug('Leaving register().');
      return Promise.resolve({});
    },
    deregister: function (arn, targets) {
      log.debug('Entering deregister().');
      calls.deregister.push({
        arn: arn, targets: copyTargets(targets) });
      log.debug('Leaving deregister().');
      return Promise.resolve({});
    }
  };
  log.debug('Leaving fakeElb().');
  return api;
}

function command(name) {
  log.debug('Entering command().');
  log.debug('Leaving command().');
  return function (input) {
    this.name = name;
    this.input = input;
  };
}

function scripted(pages) {
  log.debug('Entering scripted().');
  const sent = [];
  const client = {
    sent: sent,
    send: function (cmd) {
      log.debug('Entering send().');
      sent.push(cmd);
      const page = pages.shift();
      log.debug('Leaving send().');
      return Promise.resolve(page);
    }
  };
  log.debug('Leaving scripted().');
  return client;
}

function elbSdk() {
  log.debug('Entering elbSdk().');
  const sdk = {
    DescribeTargetGroupsCommand: command('DescribeTargetGroups'),
    DescribeTargetHealthCommand: command('DescribeTargetHealth'),
    RegisterTargetsCommand: command('RegisterTargets'),
    DeregisterTargetsCommand: command('DeregisterTargets')
  };
  log.debug('Leaving elbSdk().');
  return sdk;
}

function ecsSdk() {
  log.debug('Entering ecsSdk().');
  const sdk = {
    ListTasksCommand: command('ListTasks'),
    DescribeTasksCommand: command('DescribeTasks')
  };
  log.debug('Leaving ecsSdk().');
  return sdk;
}

function taskArns(count) {
  log.debug('Entering taskArns().');
  const arns = [];
  for (let i = 0; i < count; i++) {
    arns.push('arn:aws:ecs:us-east-1:1:task/c/' + i);
  }
  log.debug('Leaving taskArns().');
  return arns;
}

function codeLines(text) {
  log.debug('Entering codeLines().');
  const n = String(text || '').split('\n').filter(function (line) {
    return line.indexOf('STS-CLUSTER-0027') >= 0;
  }).length;
  log.debug('Leaving codeLines().');
  return n;
}

// Bunyan writes the error line to stdout. The thrown Error also carries
// the code, and that text is not what this counts.
function capture(fn) {
  log.debug('Entering capture().');
  const chunks = [];
  const orig = process.stdout.write;
  process.stdout.write = function (chunk, enc, cb) {
    const text = Buffer.isBuffer(chunk) ? chunk.toString('utf8')
      : String(chunk);
    chunks.push(text);
    return orig.call(process.stdout, chunk, enc, cb);
  };
  log.debug('Leaving capture().');
  return Promise.resolve().then(fn).then(function (value) {
    process.stdout.write = orig;
    return { value: value, text: chunks.join('') };
  }, function (err) {
    log.debug('Caught in capture(): ' + ((err && err.message) || err));
    process.stdout.write = orig;
    err.captured = chunks.join('');
    throw err;
  });
}

function listen(handler) {
  log.debug('Entering listen().');
  log.debug('Leaving listen().');
  return new Promise(function (resolve, reject) {
    const server = http.createServer(handler);
    server.on('error', function (err) {
      log.debug('Caught in listen(): ' + ((err && err.message) || err));
      reject(err);
    });
    server.listen(0, '127.0.0.1', function () {
      resolve(server);
    });
  });
}

function closeServer(server) {
  log.debug('Entering closeServer().');
  log.debug('Leaving closeServer().');
  return new Promise(function (resolve) {
    server.close(function () {
      resolve();
    });
  });
}

function shapes(t) {
  log.debug('Entering shapes().');
  const names = [
    ['prefix-sp-8092', 'prefix', true],
    ['prefix-s80', 'prefix', true],
    ['prefix-s9092', 'prefix', true],
    ['prefix-sp-65535', 'prefix', true],
    ['prefix-sp-', 'prefix', false],
    ['prefix-sp-080', 'prefix', false],
    ['prefix-sp-0', 'prefix', false],
    ['prefix-sp-65536', 'prefix', false],
    ['prefix-https', 'prefix', false],
    ['prefix-ldap', 'prefix', false],
    ['prefix-ldaps', 'prefix', false],
    ['prefix-pki', 'prefix', false],
    ['prefix-kerberos', 'prefix', false],
    ['other-sp-8092', 'prefix', false],
    ['', 'prefix', false]
  ];
  names.forEach(function (row) {
    t.equal(SpiffeTargets.isSpiffeGroup(row[0], row[1]), row[2],
            'name ' + row[0] + ' against ' + row[1]);
  });
  t.equal(SpiffeTargets.isIpv4('10.0.0.2'), true, 'an address');
  t.equal(SpiffeTargets.isIpv4('0.0.0.0'), true, 'a single zero is an octet');
  t.equal(SpiffeTargets.isIpv4('10.0.0.01'), false, 'a leading zero');
  t.equal(SpiffeTargets.isIpv4('010.0.0.1'), false, 'a leading zero');
  t.equal(SpiffeTargets.isIpv4('10.0.0'), false, 'three octets');
  t.equal(SpiffeTargets.isIpv4('10.0.0.256'), false, 'an octet past 255');
  t.equal(SpiffeTargets.isIpv4(''), false, 'an empty address');
  t.equal(SpiffeTargets.clusterName(
    'arn:aws:ecs:us-east-1:1:cluster/iya-sts-dev'), PREFIX,
          'the cluster name is the ARN\'s last segment');
  t.equal(SpiffeTargets.clusterName(PREFIX), PREFIX,
          'a name that is already a name stays');
  log.debug('Leaving shapes().');
}

async function membership(t) {
  log.debug('Entering membership().');
  t.log.info('=== the groups against the running addresses ===');
  const elb = fakeElb([
    { name: PREFIX + '-sp-8092', arn: 'arn:sp8092', port: 8092 },
    { name: PREFIX + '-s9092', arn: 'arn:s9092', port: 9092 },
    { name: PREFIX + '-sp-80', arn: 'arn:bad0', port: 0 },
    { name: PREFIX + '-s81', arn: 'arn:badhi', port: 70000 },
    { name: PREFIX + '-https', arn: 'arn:https', port: 443 },
    { name: PREFIX + '-ldap', arn: 'arn:ldap', port: 389 },
    { name: PREFIX + '-ldaps', arn: 'arn:ldaps', port: 636 },
    { name: PREFIX + '-pki', arn: 'arn:pki', port: 8080 },
    { name: PREFIX + '-kerberos', arn: 'arn:krb', port: 88 },
    { name: 'other-sp-8092', arn: 'arn:other', port: 8092 }
  ], {
    'arn:sp8092': [
      { id: '10.0.0.2', port: 8092, state: 'unhealthy' },
      { id: '10.0.0.3', port: 8093, state: 'healthy' },
      { id: '10.0.0.9', port: 8092, state: 'healthy' }
    ],
    'arn:s9092': []
  });
  let summary = null;
  let err = null;
  try {
    summary = await SpiffeTargets.reconcileGroups({
      elb: elb,
      tasks: [
        { ip: '10.0.0.2' },
        { ip: '10.0.0.3' },
        { ip: '010.0.0.4' },
        '10.00.0.5'
      ],
      self: { cluster: PREFIX, ip: SELF }
    });
  } catch (e) {
    log.debug('Caught in membership(): ' + ((e && e.message) || e));
    err = e;
  }
  t.check(!err, 'the reconcile compared the groups',
          err && err.message);
  if (summary) {
    t.equal(summary.skipped, '', 'nothing was skipped');
    t.equal(summary.groups, 4, 'four SPIFFE names, two of them unusable');
    t.equal(summary.registered, 5, 'two on 8092 and three on 9092');
    t.equal(summary.deregistered, 2, 'the wrong port and the stale address');
  }
  t.equal(JSON.stringify(elb.calls.health),
          JSON.stringify(['arn:sp8092', 'arn:s9092']),
          'only the two usable SPIFFE groups are read');
  t.equal(JSON.stringify(elb.calls.register), JSON.stringify([
    { arn: 'arn:sp8092', targets: [
      { id: '10.0.0.3', port: 8092 },
      { id: SELF, port: 8092 }
    ] },
    { arn: 'arn:s9092', targets: [
      { id: '10.0.0.2', port: 9092 },
      { id: '10.0.0.3', port: 9092 },
      { id: SELF, port: 9092 }
    ] }
  ]), 'a missing address is registered on the group\'s port, ' +
      'including this task when the list omits it');
  t.equal(JSON.stringify(elb.calls.deregister), JSON.stringify([
    { arn: 'arn:sp8092', targets: [
      { id: '10.0.0.3', port: 8093 },
      { id: '10.0.0.9', port: 8092 }
    ] }
  ]), 'a wrong port is replaced and a stale address is removed');
  log.debug('Leaving membership().');
}

async function liveNoop(t) {
  log.debug('Entering liveNoop().');
  t.log.info('=== outside an ECS task ===');
  delete process.env.ECS_CONTAINER_METADATA_URI_V4;
  const summary = await SpiffeTargets.reconcileLive();
  t.equal(summary.skipped, 'not an ECS task',
          'reconcileLive does nothing without the metadata address');
  t.equal(summary.registered, 0, 'and registers nothing');
  let started = false;
  try {
    SpiffeTargets.onStart();
    started = true;
  } catch (e) {
    log.debug('Caught in liveNoop(): ' + ((e && e.message) || e));
  }
  t.check(started, 'onStart returns without throwing when it is off');
  t.equal(SpiffeTargets.whyOff(), 'not an ECS task',
          'the job is off outside ECS');
  log.debug('Leaving liveNoop().');
}

function fakeScheduler() {
  log.debug('Entering fakeScheduler().');
  const jobs = {};
  const registered = [];
  const api = {
    registered: registered,
    job: function (id) {
      log.debug('Entering job().');
      const found = jobs[id] || null;
      log.debug('Leaving job().');
      return found;
    },
    register: function (spec) {
      log.debug('Entering register().');
      jobs[spec.id] = spec;
      registered.push(spec);
      log.debug('Leaving register().');
    }
  };
  log.debug('Leaving fakeScheduler().');
  return api;
}

async function jobShape(t) {
  log.debug('Entering jobShape().');
  t.log.info('=== the scheduler job ===');
  delete process.env.ECS_CONTAINER_METADATA_URI_V4;
  SpiffeTargets.ensureJob(null);
  SpiffeTargets.ensureJob({});
  const sched = fakeScheduler();
  SpiffeTargets.ensureJob(sched);
  SpiffeTargets.ensureJob(sched);
  t.equal(sched.registered.length, 1, 'the job is registered once');
  const spec = sched.registered[0];
  t.equal(spec.id, SpiffeTargets.JOB_ID, 'the id');
  t.equal(spec.kind, 'cluster', 'a cluster job');
  t.equal(spec.scope, 'service', 'service scope');
  t.equal(spec.manual, true, 'an operator can run it');
  t.equal(spec.owner, 'cluster/spiffe_targets.js', 'the owner');
  t.equal(spec.everyMs(), SpiffeTargets.INTERVAL_MS, 'every 15 seconds');
  t.equal(spec.off(), 'not an ECS task', 'off() outside ECS');
  process.env.ECS_CONTAINER_METADATA_URI_V4 = 'http://127.0.0.1:9';
  t.equal(spec.off(), '', 'off() is empty on an ECS task');
  t.equal(SpiffeTargets.whyOff(), '', 'whyOff agrees');
  delete process.env.ECS_CONTAINER_METADATA_URI_V4;
  const ran = await spec.run();
  t.equal(ran.skipped, 'not an ECS task',
          'a run with the variable unset returns skipped');
  log.debug('Leaving jobShape().');
}

function brokenClients() {
  log.debug('Entering brokenClients().');
  const clients = {
    elb: {
      listGroups: function () {
        log.debug('Entering listGroups().');
        log.debug('Leaving listGroups().');
        return Promise.reject(new Error('denied'));
      },
      health: resolveWith([]),
      register: resolveWith({}),
      deregister: resolveWith({})
    },
    tasks: resolveWith([])
  };
  log.debug('Leaving brokenClients().');
  return clients;
}

async function oneFailure(clients) {
  log.debug('Entering oneFailure().');
  let caught = null;
  let text = '';
  try {
    const shot = await capture(function () {
      return SpiffeTargets.reconcileLive({
        self: { cluster: PREFIX, ip: SELF },
        clients: clients
      });
    });
    text = shot.text;
  } catch (e) {
    log.debug('Caught in oneFailure(): ' + ((e && e.message) || e));
    caught = e;
    text = e.captured || '';
  }
  log.debug('Leaving oneFailure().');
  return { caught: caught, text: text };
}

async function logOnce(t) {
  log.debug('Entering logOnce().');
  t.log.info('=== a failure is recorded once ===');
  SpiffeTargets.failing = false;
  const first = await oneFailure(brokenClients());
  t.check(!!first.caught, 'the first failure is thrown');
  t.check(first.caught &&
          first.caught.message.indexOf('STS-CLUSTER-0027') >= 0,
          'the thrown error carries STS-CLUSTER-0027',
          first.caught && first.caught.message);
  t.equal(codeLines(first.text), 1, 'and the log line carries it once');
  const second = await oneFailure(brokenClients());
  t.check(!!second.caught, 'the second failure is still thrown');
  t.equal(codeLines(second.text), 0,
          'the code is not logged again while it keeps failing');
  const healed = fakeElb([], {});
  const ok = await SpiffeTargets.reconcileLive({
    self: { cluster: PREFIX, ip: SELF },
    tasks: [],
    clients: { elb: healed, tasks: resolveWith([]) }
  });
  t.equal(ok.skipped, '', 'a later reconcile can succeed');
  t.equal(SpiffeTargets.failing, false, 'and that clears the outage');
  const third = await oneFailure(brokenClients());
  t.equal(codeLines(third.text), 1,
          'the next outage logs the code again');
  log.debug('Leaving logOnce().');
}

function noClients() {
  log.debug('Entering noClients().');
  log.debug('Leaving noClients().');
  return null;
}

async function missingSdk(t) {
  log.debug('Entering missingSdk().');
  t.log.info('=== the AWS clients are optional ===');
  let err = null;
  try {
    await SpiffeTargets.reconcileLive({
      self: { cluster: PREFIX, ip: SELF },
      loadClients: noClients
    });
  } catch (e) {
    log.debug('Caught in missingSdk(): ' + ((e && e.message) || e));
    err = e;
  }
  t.check(!!err && err.message.indexOf('STS-CLUSTER-0027') >= 0 &&
          err.message.indexOf('are not installed') >= 0,
          'a missing client is STS-CLUSTER-0027 and the service is told',
          err && err.message);
  log.debug('Leaving missingSdk().');
}

async function adapters(t) {
  log.debug('Entering adapters().');
  t.log.info('=== the SDK calls ===');
  const groups = scripted([
    { TargetGroups: [
      { TargetGroupName: PREFIX + '-sp-8092', TargetGroupArn: 'arn:sp',
        Port: 8092 },
      { TargetGroupName: PREFIX + '-https', TargetGroupArn: 'arn:https',
        Port: 443 }
    ], NextMarker: 'page-2' },
    { TargetGroups: [
      { TargetGroupName: PREFIX + '-s9092', TargetGroupArn: 'arn:cell',
        Port: 9092 }
    ] }
  ]);
  const listed = await SpiffeTargets.listAllGroups(groups, elbSdk());
  t.equal(groups.sent.length, 2, 'DescribeTargetGroups is paged');
  t.check(!groups.sent[0].input.Marker, 'the first page asks for no marker');
  t.equal(groups.sent[1].input.Marker, 'page-2', 'the next page sends it');
  t.equal(listed.length, 3,
          'both pages come back, SPIFFE names and the others');
  const tasks = scripted([
    { taskArns: ['arn:a'], nextToken: 'tok-2' },
    { taskArns: ['arn:b'] }
  ]);
  const arns = await SpiffeTargets.listTaskArns(tasks, ecsSdk(), PREFIX);
  t.equal(tasks.sent[0].input.desiredStatus, 'RUNNING',
          'ListTasks asks for RUNNING');
  t.equal(tasks.sent[0].input.cluster, PREFIX, 'in this cluster');
  t.check(!tasks.sent[0].input.nextToken, 'the first page has no token');
  t.equal(tasks.sent[1].input.nextToken, 'tok-2', 'the next page sends it');
  t.equal(JSON.stringify(arns), JSON.stringify(['arn:a', 'arn:b']),
          'both pages of task ARNs');
  const described = scripted([]);
  described.send = function (cmd) {
    log.debug('Entering send().');
    described.sent.push(cmd);
    const batch = cmd.input.tasks || [];
    let body;
    if (batch.length === 100) {
      body = { tasks: [
        { attachments: [{ details: [
          { name: 'privateIPv4Address', value: '010.0.0.1' }
        ] }] },
        { containers: [{ networkInterfaces: [
          { privateIpv4Address: '10.0.0.2' }
        ] }] }
      ] };
    } else {
      body = { tasks: [
        { containers: [{ networkInterfaces: [
          { privateIpv4Address: '10.1.0.1' }
        ] }] }
      ] };
    }
    log.debug('Leaving send().');
    return Promise.resolve(body);
  };
  const ips = await SpiffeTargets.describeTaskIps(
    described, ecsSdk(), PREFIX, taskArns(101));
  t.equal(described.sent.length, 2, 'DescribeTasks is a hundred at a time');
  t.equal(described.sent[0].input.tasks.length, 100, 'the first hundred');
  t.equal(described.sent[1].input.tasks.length, 1, 'then the remainder');
  t.equal(JSON.stringify(ips),
          JSON.stringify([{ ip: '10.0.0.2' }, { ip: '10.1.0.1' }]),
          'a leading-zero address is not registered');
  const changes = scripted([{}]);
  await SpiffeTargets.changeMembers(changes, elbSdk(), 'arn:g',
    [{ id: '10.0.0.2', port: 8092 }], true);
  const input = changes.sent[0].input;
  t.equal(changes.sent[0].name, 'RegisterTargets', 'the register command');
  t.equal(input.TargetGroupArn, 'arn:g', 'on that group');
  t.equal(JSON.stringify(input.Targets),
          JSON.stringify([{ Id: '10.0.0.2', Port: 8092 }]),
          'the target is the address and the port');
  t.check(!Object.prototype.hasOwnProperty.call(input, 'AvailabilityZone') &&
          !Object.prototype.hasOwnProperty.call(input.Targets[0],
            'AvailabilityZone'),
          'and no availability zone');
  const health = scripted([{ TargetHealthDescriptions: [{
    Target: { Id: '10.0.0.2', Port: 8092 },
    TargetHealth: { State: 'unhealthy' }
  }] }]);
  const members = await SpiffeTargets.groupHealth(
    health, elbSdk(), 'arn:g');
  t.equal(health.sent[0].input.TargetGroupArn, 'arn:g',
          'health names the group');
  t.equal(JSON.stringify(members), JSON.stringify([
    { id: '10.0.0.2', port: 8092, state: 'unhealthy' }
  ]), 'a member keeps its id, port and state');
  const built = [];
  function Client(opts) {
    log.debug('Entering Client().');
    built.push(opts);
    log.debug('Leaving Client().');
  }
  const sdkElb = elbSdk();
  sdkElb.ElasticLoadBalancingV2Client = Client;
  const sdkEcs = ecsSdk();
  sdkEcs.ECSClient = Client;
  const api = SpiffeTargets.clientsFromSdk(sdkElb, sdkEcs);
  t.equal(built.length, 2, 'both clients are constructed');
  t.equal(JSON.stringify(built[0]), '{}',
          'the load-balancing client takes the default chain');
  t.equal(JSON.stringify(built[1]), '{}',
          'the ecs client takes the default chain');
  t.check(typeof api.tasks === 'function' && !!api.elb,
          'the adapter exposes both');
  log.debug('Leaving adapters().');
}

async function metadata(t) {
  log.debug('Entering metadata().');
  t.log.info('=== the task metadata ===');
  const server = await listen(function (req, res) {
    if (req.url === '/task') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        Cluster: 'arn:aws:ecs:us-east-1:1:cluster/' + PREFIX,
        Containers: [{ Networks: [{ IPv4Addresses: [SELF] }] }]
      }));
      return;
    }
    res.writeHead(503);
    res.end('no');
  });
  try {
    const addr = server.address();
    const base = 'http://127.0.0.1:' + addr.port;
    const self = await SpiffeTargets.readTask(base);
    t.equal(self.cluster, PREFIX, 'the cluster is the ARN\'s last segment');
    t.equal(self.ip, SELF, 'the address is the container\'s IPv4');
    let httpsErr = null;
    try {
      await SpiffeTargets.readTask('https://127.0.0.1/task');
    } catch (e) {
      log.debug('Caught in metadata(): ' + ((e && e.message) || e));
      httpsErr = e;
    }
    t.check(!!httpsErr && httpsErr.message.indexOf('not http') >= 0,
            'an https metadata address is refused',
            httpsErr && httpsErr.message);
    let badErr = null;
    try {
      await SpiffeTargets.readTask('not a url');
    } catch (e) {
      log.debug('Caught in metadata(): ' + ((e && e.message) || e));
      badErr = e;
    }
    t.check(!!badErr && badErr.message.indexOf('not a URL') >= 0,
            'a metadata address that is not a URL is refused',
            badErr && badErr.message);
    let statusErr = null;
    try {
      await SpiffeTargets.readTask(base + '/fail');
    } catch (e) {
      log.debug('Caught in metadata(): ' + ((e && e.message) || e));
      statusErr = e;
    }
    t.check(!!statusErr && statusErr.message.indexOf('503') >= 0,
            'a metadata answer other than 200 is refused',
            statusErr && statusErr.message);
  } finally {
    await closeServer(server);
    log.debug('Leaving metadata().');
  }
}

async function stopPath(t) {
  log.debug('Entering stopPath().');
  t.log.info('=== a stop removes only this task ===');
  let registered = false;
  const hung = {
    elb: {
      listGroups: function () {
        log.debug('Entering listGroups().');
        log.debug('Leaving listGroups().');
        return new Promise(function () {});
      },
      health: resolveWith([]),
      register: function () {
        log.debug('Entering register().');
        registered = true;
        log.debug('Leaving register().');
        return Promise.resolve({});
      },
      deregister: resolveWith({})
    },
    tasks: resolveWith([{ ip: '10.0.0.2' }])
  };
  const timed = await SpiffeTargets.onStop({
    timeoutMs: 50,
    self: { cluster: PREFIX, ip: SELF },
    clients: hung
  });
  t.equal(timed.timedOut, true, 'a stop that is not answered finishes');
  t.equal(timed.skipped, 'timed out', 'and says it timed out');
  t.check(!registered, 'and registered nothing while it waited');
  const elb = fakeElb([
    { name: PREFIX + '-sp-8092', arn: 'arn:sp', port: 8092 },
    { name: PREFIX + '-https', arn: 'arn:https', port: 443 }
  ], {
    'arn:sp': [
      { id: SELF, port: 8092, state: 'healthy' },
      { id: '10.0.0.2', port: 8092, state: 'healthy' }
    ]
  });
  const summary = await SpiffeTargets.onStop({
    timeoutMs: 2000,
    self: { cluster: PREFIX, ip: SELF },
    clients: {
      elb: elb,
      tasks: resolveWith([{ ip: '10.0.0.2' }, { ip: SELF }])
    }
  });
  t.equal(summary.registered, 0, 'a stop registers nothing');
  t.equal(summary.deregistered, 1, 'and deregisters this task');
  t.equal(elb.calls.register.length, 0, 'no register call');
  t.equal(JSON.stringify(elb.calls.deregister), JSON.stringify([
    { arn: 'arn:sp', targets: [{ id: SELF, port: 8092 }] }
  ]), 'only this task\'s address, not another running task');
  t.equal(JSON.stringify(elb.calls.health), JSON.stringify(['arn:sp']),
          'the https group is not read');
  log.debug('Leaving stopPath().');
}

async function haltPath(t) {
  log.debug('Entering haltPath().');
  t.log.info('=== stopping refuses a full reconcile ===');
  delete process.env.ECS_CONTAINER_METADATA_URI_V4;
  t.equal(SpiffeTargets.whyOff(), 'not an ECS task',
          'still off before the stop flag');
  process.env.ECS_CONTAINER_METADATA_URI_V4 = 'http://127.0.0.1:9';
  t.equal(SpiffeTargets.whyOff(), '', 'on, once the address is set');
  let sawHealth = false;
  const early = await SpiffeTargets.reconcileGroups({
    elb: {
      listGroups: resolveWith([
        { name: PREFIX + '-sp-8092', arn: 'arn:sp', port: 8092 }
      ]),
      health: function () {
        log.debug('Entering health().');
        sawHealth = true;
        log.debug('Leaving health().');
        return Promise.resolve([]);
      },
      register: function () {
        log.debug('Entering register().');
        log.debug('Leaving register().');
        return Promise.reject(new Error('registered while stopping'));
      },
      deregister: resolveWith({})
    },
    tasks: [{ ip: SELF }],
    self: { cluster: PREFIX, ip: SELF },
    stopping: true
  });
  t.check(!sawHealth, 'a full reconcile that is stopping does not read');
  t.equal(early.registered, 0, 'and does not register');
  SpiffeTargets.beginStop();
  t.equal(SpiffeTargets.whyOff(), 'this process is stopping',
          'off() stays set while the metadata address is still present');
  let liveHealth = false;
  const live = await SpiffeTargets.reconcileLive({
    self: { cluster: PREFIX, ip: SELF },
    tasks: [{ ip: SELF }],
    clients: {
      elb: {
        listGroups: resolveWith([
          { name: PREFIX + '-sp-8092', arn: 'arn:sp', port: 8092 }
        ]),
        health: function () {
          log.debug('Entering health().');
          liveHealth = true;
          log.debug('Leaving health().');
          return Promise.resolve([]);
        },
        register: function () {
          log.debug('Entering register().');
          log.debug('Leaving register().');
          return Promise.reject(new Error('registered while stopping'));
        },
        deregister: resolveWith({})
      },
      tasks: resolveWith([{ ip: SELF }])
    }
  });
  t.check(!liveHealth, 'reconcileLive after beginStop does not read');
  t.equal(live.registered, 0, 'and does not register');
  const elb = fakeElb([
    { name: PREFIX + '-sp-8092', arn: 'arn:sp', port: 8092 }
  ], {
    'arn:sp': [
      { id: SELF, port: 8092, state: 'healthy' },
      { id: '10.0.0.2', port: 8092, state: 'unhealthy' }
    ]
  });
  const gone = await SpiffeTargets.reconcileLive({
    deregisterOnly: true,
    self: { cluster: PREFIX, ip: SELF },
    tasks: [{ ip: '10.0.0.2' }, { ip: SELF }],
    clients: { elb: elb, tasks: resolveWith([]) }
  });
  t.equal(gone.registered, 0, 'deregister-only still registers nothing');
  t.equal(JSON.stringify(elb.calls.deregister), JSON.stringify([
    { arn: 'arn:sp', targets: [{ id: SELF, port: 8092 }] }
  ]), 'and still removes this task after beginStop');
  log.debug('Leaving haltPath().');
}

function has(text, needle) {
  log.debug('Entering has().');
  const ok = text.indexOf(needle) >= 0;
  log.debug('Leaving has().');
  return ok;
}

function grants(t) {
  log.debug('Entering grants().');
  t.log.info('=== the task role and the workload boundary ===');
  const task = between(read('deploy/aws/environment/iam.tf'),
    'data "aws_iam_policy_document" "task"',
    'resource "aws_iam_role_policy" "task"');
  const boundary = between(read('deploy/aws/foundation/iam_deployer.tf'),
    'data "aws_iam_policy_document" "workload_boundary"',
    'resource "aws_iam_policy" "workload_boundary"');
  const actions = [
    'elasticloadbalancing:RegisterTargets',
    'elasticloadbalancing:DeregisterTargets',
    'elasticloadbalancing:DescribeTargetHealth',
    'elasticloadbalancing:DescribeTargetGroups',
    'ecs:ListTasks',
    'ecs:DescribeTasks'
  ];
  actions.forEach(function (action) {
    t.check(has(task, action), 'the task role allows ' + action);
    t.check(has(boundary, action), 'the workload boundary allows ' + action);
  });
  ['-sp-*/*', '-s??/*', '-s???/*', '-s????/*', '-s?????/*'].forEach(
    function (pattern) {
      t.check(has(task, '${local.prefix}' + pattern),
              'the task role names ' + pattern);
      t.check(has(boundary, '${var.name}-*' + pattern),
              'the workload boundary names ' + pattern);
    });
  t.check(has(task, 'cluster/${local.prefix}'),
          'the task role reads this cluster');
  t.check(has(task, 'task/${local.prefix}/*'),
          'and this cluster\'s tasks');
  t.check(has(boundary, 'cluster/${var.name}-*'),
          'the boundary reads every environment\'s cluster');
  t.check(has(boundary, 'task/${var.name}-*/*'),
          'and every environment\'s tasks');
  t.check(!has(boundary, 'targetgroup/${var.name}-*-s*/*'),
          'the boundary does not use a pattern that matches -sts');
  const ecs = read('deploy/aws/environment/ecs.tf');
  const attached = ecs.match(
    /dynamic "load_balancer" \{\n {4}for_each = local\.published_ports/g
  ) || [];
  t.equal(attached.length, 2,
          'both node services attach only published_ports');
  t.check(!has(ecs, 'aws_lb_target_group.spiffe'),
          'ecs.tf declares no SPIFFE target group');
  t.check(!has(ecs, '-sp-'), 'ecs.tf names no SPIFFE target group');
  const stack = read('common/protocol_stack.ts');
  const server = read('server.js');
  t.check(has(stack, 'require(\'../cluster/spiffe_targets\').ensureJob('),
          'every process registers the job');
  t.check(has(server, 'require(\'./cluster/spiffe_targets\').onStart()'),
          'the front process reconciles as it starts');
  t.check(has(server, 'require(\'./cluster/spiffe_targets\').beginStop()'),
          'and sets the stop flag before the scheduler stops');
  t.check(has(server, 'require(\'./cluster/spiffe_targets\').onStop()'),
          'and deregisters itself as it shuts down');
  const pkg = JSON.parse(read('package.json'));
  const deps = pkg.dependencies || {};
  ['@aws-sdk/client-elastic-load-balancing-v2',
   '@aws-sdk/client-ecs'].forEach(function (name) {
    t.check(!!pkg.peerDependencies[name], name + ' is a peer');
    t.check(pkg.peerDependenciesMeta[name] &&
            pkg.peerDependenciesMeta[name].optional === true,
            name + ' is optional');
    t.check(!deps[name], name + ' is not installed with the service');
  });
  log.debug('Leaving grants().');
}

function restore(saved) {
  log.debug('Entering restore().');
  SpiffeTargets.stopping = false;
  SpiffeTargets.failing = false;
  if (saved === undefined) {
    delete process.env.ECS_CONTAINER_METADATA_URI_V4;
  } else {
    process.env.ECS_CONTAINER_METADATA_URI_V4 = saved;
  }
  log.debug('Leaving restore().');
}

async function run(t) {
  log.debug('Entering run().');
  const saved = process.env.ECS_CONTAINER_METADATA_URI_V4;
  delete process.env.ECS_CONTAINER_METADATA_URI_V4;
  SpiffeTargets.stopping = false;
  SpiffeTargets.failing = false;
  try {
    shapes(t);
    await membership(t);
    await liveNoop(t);
    await jobShape(t);
    await logOnce(t);
    await missingSdk(t);
    await adapters(t);
    await metadata(t);
    await stopPath(t);
    grants(t);
    await haltPath(t);
  } finally {
    restore(saved);
    log.debug('Leaving run().');
  }
}

module.exports = {
  name: 'spiffe_targets',
  describe: 'A restarted node stays in the SPIFFE target groups (#323): ' +
            'the reconcile, the job, and the two IAM grants',
  run: run
};
