// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cluster/spiffe_targets.js
//
// ===========================================================================
// THE SPIFFE TARGET GROUPS, KEPT EQUAL TO THE RUNNING TASKS (#323).
//
// ECS manages at most five load-balancer target groups on a service, and a
// node's service already uses five (https, ldap, ldaps, pki, kerberos). The
// SPIFFE groups are therefore not on a `load_balancer` block. Terraform
// registers the tasks' private addresses at apply time
// (`deploy/aws/environment/spiffe_default.tf`, `deploy/aws/spiffe-realm/`),
// and an address from that snapshot goes stale when a task is replaced: the
// old address fails health checks and the new one is in no group, until the
// next apply. This module is what happens between applies.
//
// It is a CLUSTER job, `spiffe.target-reconcile`, every 15 seconds — inside
// the target group's unhealthy window (a TCP check every 10 seconds, three
// failures). The leader lists the RUNNING tasks of THIS cluster and the
// target groups whose names are this cluster's SPIFFE groups, registers each
// running private IPv4 address on the group's own port, and deregisters an
// address no running task still has. A current address is left alone whatever
// its health says: the Workload API port stays unhealthy on purpose (#166).
// A current address on the wrong port for its group is replaced.
//
// THE FRONT PROCESS ALSO RECONCILES AS IT STARTS, so a task that is not the
// leader does not wait out the interval, and so a task metadata has and
// ListTasks does not yet are still registered (this task's own address is
// unioned in). IT DEREGISTERS ONLY ITS OWN ADDRESS AS IT STOPS. An in-flight
// reconcile sees the stop before its next register and does not put the
// dying address back. A stop that never runs — an OOM kill (#320) — leaves
// the old address until the next leader's reconcile removes it.
//
// OFF WHEN THIS PROCESS IS NOT AN ECS TASK (`ECS_CONTAINER_METADATA_URI_V4`
// unset): a checkout, the tests and every other deployment call nothing.
// The cluster name is the last segment of the task's Cluster ARN, which is
// the environment's `local.prefix`, and the groups are `<prefix>-sp-<port>`
// or, for a cell, `<prefix>-s<port>` (an ELB name is 32 characters and a
// cell's prefix is already up to 27). Another environment's groups share
// the account and are not touched. No setting: there is nothing to configure
// where the metadata address is absent.
//
// A FAILURE IS RECORDED, NOT FATAL (`STS-CLUSTER-0027`). The job throws so
// the scheduler's row says failed; start and stop catch, and the listeners
// stay up. The code is logged once while it keeps failing, and again after
// a success has cleared it. The two AWS clients are optional peers, installed
// into an image only when its build names them (`deploy/aws/CLAUDE.md`). A
// task whose role was granted this before an administrator re-applied
// `foundation/` records the same failure: the workload boundary is the
// ceiling, and a role policy cannot rise above it.
//
// THIS FILE IS JAVASCRIPT ON PURPOSE. A checkout does not compile TypeScript
// (#50), and the test loads this module through `tests/harness.js` on the
// host. It is a leaf: its own logger, and it requires `error_codes` and node.
// `common/helpers.js` would pull in `common/crypto.js`, which requires a
// TypeScript file a checkout has not compiled.
//
// `environment/realm_listeners.tf` registers by address the same way and is
// not reconciled here.
// ===========================================================================

const http = require('http');
const bunyan = require('bunyan');
const errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({ name: 'sts-spiffe-targets' });

/**
 * One private address to register on a target group's port.
 * @typedef {{ ip?: string }} TaskAddress
 */

/**
 * A target group the reconcile can see.
 * @typedef {{ name?: string, arn?: string, port?: number }} TargetGroup
 */

/**
 * A current member of a target group.
 * @typedef {{ id?: string, port?: number, state?: string }} TargetMember
 */

/**
 * The load-balancing calls the reconcile makes. Tests pass a fake; the AWS
 * adapter below is the other implementation.
 * @typedef {{
 *   listGroups: () => Promise<TargetGroup[]>,
 *   health: (arn: string) => Promise<TargetMember[]>,
 *   register: (arn: string, targets: TargetMember[]) => Promise<unknown>,
 *   deregister: (arn: string, targets: TargetMember[]) => Promise<unknown>
 * }} ElbApi
 */

/**
 * @typedef {{
 *   elb: ElbApi,
 *   tasks: (cluster: string) => Promise<TaskAddress[]>
 * }} CloudClients
 */

/**
 * What one reconcile did. `skipped` is empty when it compared the groups.
 * @typedef {{
 *   skipped: string,
 *   registered: number,
 *   deregistered: number,
 *   groups: number,
 *   timedOut?: boolean,
 *   failed?: boolean
 * }} ReconcileSummary
 */

/**
 * The SPIFFE target-group reconcile (#323).
 */
class SpiffeTargets {
  /**
   * The scheduler's id. Dot-separated words, which is the id shape
   * `cluster/scheduler.ts` accepts.
   * @type {string}
   */
  static JOB_ID = 'spiffe.target-reconcile';

  /**
   * How often the leader reconciles, in milliseconds. The groups' TCP health
   * check is 10 seconds and unhealthy after 3, so a stale address is removed
   * inside that window.
   * @type {number}
   */
  static INTERVAL_MS = 15000;

  /**
   * How long a stop waits for its own address to be deregistered before the
   * rest of shutdown continues. The deregistration delay on the group is 30
   * seconds and does not need this process to stay up.
   * @type {number}
   */
  static STOP_MS = 3000;

  /**
   * How long the task-metadata read waits. The address is link-local.
   * @type {number}
   */
  static METADATA_MS = 2000;

  /**
   * The most metadata that is read. A task document is a few kilobytes.
   * @type {number}
   */
  static METADATA_MAX = 1024 * 1024;

  /**
   * True after a reconcile has failed, until one succeeds. The error code is
   * logged on the transition, not on every retry.
   * @type {boolean}
   */
  static failing = false;

  /**
   * Set by beginStop(). An in-flight reconcile does not register after this,
   * and the job's off() answers so the scheduler does not start another.
   * @type {boolean}
   */
  static stopping = false;

  /**
   * Whether `name` is one of `prefix`'s SPIFFE target groups: `<prefix>-sp-`
   * and a port, or a cell's `<prefix>-s` and a port. `-sp-` is tried first,
   * so `<prefix>-sp-8092` is not read as `-s` plus `p-8092`. `<prefix>-https`
   * and the other four service groups match neither.
   *
   * @param {string} name - the target group's name
   * @param {string} prefix - this cluster's name
   * @returns {boolean}
   */
  static isSpiffeGroup(name, prefix) {
    log.debug("Entering SpiffeTargets.isSpiffeGroup().");
    const n = String(name || '');
    const p = String(prefix || '');
    let digits = '';
    if (p && n.indexOf(p) === 0) {
      const rest = n.slice(p.length);
      if (rest.indexOf('-sp-') === 0) {
        digits = rest.slice(4);
      } else if (rest.indexOf('-s') === 0) {
        digits = rest.slice(2);
      }
    }
    const ok = SpiffeTargets.isPortToken(digits);
    log.debug("Leaving SpiffeTargets.isSpiffeGroup().");
    return ok;
  }

  /**
   * Whether `digits` is a TCP port written without a leading zero.
   *
   * @param {string} digits
   * @returns {boolean}
   */
  static isPortToken(digits) {
    log.debug("Entering SpiffeTargets.isPortToken().");
    const s = String(digits || '');
    let ok = /^[1-9][0-9]{0,4}$/.test(s);
    if (ok) {
      const n = Number(s);
      ok = n >= 1 && n <= 65535;
    }
    log.debug("Leaving SpiffeTargets.isPortToken().");
    return ok;
  }

  /**
   * Whether `value` is an IPv4 address with no leading zeros. A leading zero
   * is rejected so a metadata field that is not an address cannot be
   * registered.
   *
   * @param {unknown} value
   * @returns {boolean}
   */
  static isIpv4(value) {
    log.debug("Entering SpiffeTargets.isIpv4().");
    const s = String(value || '');
    const parts = s.split('.');
    let ok = parts.length === 4;
    if (ok) {
      ok = parts.every(function (part) {
        if (!/^[0-9]+$/.test(part)) {
          return false;
        }
        if (part.length > 1 && part.charAt(0) === '0') {
          return false;
        }
        const n = Number(part);
        return n >= 0 && n <= 255;
      });
    }
    log.debug("Leaving SpiffeTargets.isIpv4().");
    return ok;
  }

  /**
   * The cluster name from a task's Cluster field: the ARN's last segment,
   * or the field itself when it is already a name.
   *
   * @param {unknown} value
   * @returns {string}
   */
  static clusterName(value) {
    log.debug("Entering SpiffeTargets.clusterName().");
    const s = String(value || '');
    const slash = s.lastIndexOf('/');
    const name = slash >= 0 ? s.slice(slash + 1) : s;
    log.debug("Leaving SpiffeTargets.clusterName().");
    return name;
  }

  /**
   * The first private IPv4 address on a task, from an ECS attachment detail
   * or a container network interface, or from the task-metadata document's
   * `Containers[].Networks[].IPv4Addresses`.
   *
   * @param {any} task
   * @returns {string} the address, or `''`
   */
  static ipv4OfTask(task) {
    log.debug("Entering SpiffeTargets.ipv4OfTask().");
    const found = [];
    const body = task || {};
    const attachments = body.attachments || body.Attachments || [];
    attachments.forEach(function (att) {
      const details = (att && (att.details || att.Details)) || [];
      details.forEach(function (d) {
        const n = String((d && (d.name || d.Name)) || '');
        if (n === 'privateIPv4Address' || n === 'privateIpv4Address') {
          found.push(d.value || d.Value);
        }
      });
    });
    const containers = body.containers || body.Containers || [];
    containers.forEach(function (c) {
      const nets = (c && (c.networkInterfaces || c.Networks ||
                          c.networks)) || [];
      nets.forEach(function (net) {
        if (!net) {
          return;
        }
        if (net.privateIpv4Address) {
          found.push(net.privateIpv4Address);
        }
        const list = net.IPv4Addresses || net.ipv4Addresses || [];
        list.forEach(function (ip) {
          found.push(ip);
        });
      });
    });
    let ip = '';
    found.forEach(function (one) {
      if (!ip && SpiffeTargets.isIpv4(one)) {
        ip = String(one);
      }
    });
    log.debug("Leaving SpiffeTargets.ipv4OfTask().");
    return ip;
  }

  /**
   * This task's cluster and address from a metadata document.
   *
   * @param {any} body
   * @returns {{ cluster: string, ip: string }}
   */
  static selfFromMetadata(body) {
    log.debug("Entering SpiffeTargets.selfFromMetadata().");
    const doc = body || {};
    const self = {
      cluster: SpiffeTargets.clusterName(doc.Cluster || doc.cluster),
      ip: SpiffeTargets.ipv4OfTask(doc)
    };
    log.debug("Leaving SpiffeTargets.selfFromMetadata().");
    return self;
  }

  /**
   * Whether a full reconcile must not mutate. A deregister-only stop is
   * never halted: it is the call that removes this task.
   *
   * @param {boolean} deregisterOnly
   * @param {{ stopping?: boolean | (() => boolean) }} opts
   * @returns {boolean}
   */
  static halt(deregisterOnly, opts) {
    log.debug("Entering SpiffeTargets.halt().");
    let stop = false;
    if (!deregisterOnly) {
      const flag = opts && opts.stopping;
      if (typeof flag === 'function') {
        stop = !!flag();
      } else if (flag) {
        stop = true;
      } else {
        stop = !!SpiffeTargets.stopping;
      }
    }
    log.debug("Leaving SpiffeTargets.halt().");
    return stop;
  }

  /**
   * Compares `opts.elb`'s SPIFFE groups with the running addresses.
   *
   * `opts.tasks` is the addresses ListTasks returned. `opts.self.ip` is
   * unioned in, so a task the list does not have yet is still registered.
   * `opts.deregisterOnly` removes `opts.self.ip` and registers nothing.
   * `opts.stopping` true (or beginStop() having been called) makes a full
   * reconcile leave the groups alone.
   *
   * @param {{
   *   elb?: ElbApi,
   *   tasks?: Array<TaskAddress | string>,
   *   self?: { cluster?: string, ip?: string },
   *   deregisterOnly?: boolean,
   *   stopping?: boolean | (() => boolean)
   * }} opts
   * @returns {Promise<ReconcileSummary>}
   */
  static async reconcileGroups(opts) {
    log.debug("Entering SpiffeTargets.reconcileGroups().");
    const o = opts || {};
    const self = o.self || {};
    const cluster = String(self.cluster || '');
    if (!cluster) {
      log.debug("Leaving SpiffeTargets.reconcileGroups(). No cluster.");
      return { skipped: 'no cluster', registered: 0, deregistered: 0,
               groups: 0 };
    }
    if (!o.elb) {
      log.debug("Leaving SpiffeTargets.reconcileGroups(). No client.");
      return { skipped: 'no client', registered: 0, deregistered: 0,
               groups: 0 };
    }
    const deregisterOnly = !!o.deregisterOnly;
    const desired = {};
    if (!deregisterOnly) {
      (o.tasks || []).forEach(function (task) {
        const ip = task && typeof task === 'object' ? task.ip : task;
        if (SpiffeTargets.isIpv4(ip)) {
          desired[String(ip)] = true;
        }
      });
      if (SpiffeTargets.isIpv4(self.ip)) {
        desired[String(self.ip)] = true;
      }
    }
    let registered = 0;
    let deregistered = 0;
    /** @type {TargetGroup[]} */
    let groups = [];
    try {
      const listed = await o.elb.listGroups();
      groups = (listed || []).filter(function (g) {
        return !!(g && SpiffeTargets.isSpiffeGroup(
          String(g.name || ''), cluster));
      });
      for (let i = 0; i < groups.length; i++) {
        if (SpiffeTargets.halt(deregisterOnly, o)) {
          break;
        }
        const group = groups[i];
        const port = Number(group.port);
        if (!(port >= 1 && port <= 65535)) {
          continue;
        }
        const members = await o.elb.health(String(group.arn || ''));
        if (SpiffeTargets.halt(deregisterOnly, o)) {
          break;
        }
        /** @type {Record<string, boolean>} */
        const keep = {};
        /** @type {TargetMember[]} */
        const drop = [];
        (members || []).forEach(function (m) {
          if (!m || !m.id) {
            return;
          }
          const id = String(m.id);
          const mport = Number(m.port);
          if (deregisterOnly) {
            if (id === String(self.ip || '')) {
              drop.push({ id: id, port: mport });
            }
            return;
          }
          if (desired[id] && mport === port) {
            keep[id] = true;
            return;
          }
          drop.push({ id: id, port: mport });
        });
        /** @type {TargetMember[]} */
        const add = [];
        if (!deregisterOnly) {
          Object.keys(desired).forEach(function (ip) {
            if (!keep[ip]) {
              add.push({ id: ip, port: port });
            }
          });
        }
        if (add.length && !SpiffeTargets.halt(deregisterOnly, o)) {
          await o.elb.register(String(group.arn || ''), add);
          registered += add.length;
        }
        if (drop.length &&
            (deregisterOnly || !SpiffeTargets.halt(deregisterOnly, o))) {
          await o.elb.deregister(String(group.arn || ''), drop);
          deregistered += drop.length;
        }
      }
    } catch (e) {
      log.debug("Caught in SpiffeTargets.reconcileGroups(): " +
                ((e && e.message) || e));
      log.debug("Leaving SpiffeTargets.reconcileGroups(). Failed.");
      throw e;
    }
    log.debug("Leaving SpiffeTargets.reconcileGroups().");
    return { skipped: '', registered: registered,
             deregistered: deregistered, groups: groups.length };
  }

  /**
   * Reads `url` over HTTP. The task-metadata address is `http`, and the
   * socket timeout is the request's own `timeout` — a `setTimeout` call
   * here would be a timer this module does not have.
   *
   * @param {string} url
   * @returns {Promise<string>}
   */
  static readUrl(url) {
    log.debug("Entering SpiffeTargets.readUrl().");
    log.debug("Leaving SpiffeTargets.readUrl().");
    return new Promise(function (resolve, reject) {
      let settled = false;
      /**
       * @param {Error | null} err
       * @param {string} [body]
       */
      const finish = function (err, body) {
        log.debug("Entering finish().");
        if (settled) {
          log.debug("Leaving finish(). Already settled.");
          return;
        }
        settled = true;
        if (err) {
          log.debug("Leaving finish(). Failed.");
          reject(err);
        } else {
          log.debug("Leaving finish().");
          resolve(body || '');
        }
      };
      let req;
      try {
        req = http.get(url, { timeout: SpiffeTargets.METADATA_MS },
          function (res) {
            const chunks = [];
            let size = 0;
            res.setEncoding('utf8');
            res.on('data', function (chunk) {
              size += String(chunk).length;
              if (size > SpiffeTargets.METADATA_MAX) {
                req.destroy(new Error(
                  'the task metadata was larger than 1 MiB'));
                return;
              }
              chunks.push(String(chunk));
            });
            res.on('end', function () {
              if (res.statusCode !== 200) {
                finish(new Error('the task metadata answered ' +
                                 res.statusCode));
                return;
              }
              finish(null, chunks.join(''));
            });
          });
      } catch (e) {
        log.debug("Caught in SpiffeTargets.readUrl(): " +
                  ((e && e.message) || e));
        finish(/** @type {Error} */ (e));
        return;
      }
      req.on('timeout', function () {
        req.destroy(new Error(
          'the task metadata did not answer in time'));
      });
      req.on('error', function (e) {
        finish(e);
      });
    });
  }

  /**
   * This task's cluster and address from `base` + `/task`.
   *
   * @param {string} base - `ECS_CONTAINER_METADATA_URI_V4`
   * @returns {Promise<{ cluster: string, ip: string }>}
   */
  static readTask(base) {
    log.debug("Entering SpiffeTargets.readTask().");
    const root = String(base || '').replace(/\/+$/, '');
    let href = '';
    try {
      const url = new URL(root + '/task');
      if (url.protocol !== 'http:') {
        log.debug("Leaving SpiffeTargets.readTask(). Not http.");
        return Promise.reject(new Error(
          'the task metadata address is not http'));
      }
      href = url.href;
    } catch (e) {
      log.debug("Caught in SpiffeTargets.readTask(): " +
                ((e && e.message) || e));
      log.debug("Leaving SpiffeTargets.readTask(). Bad address.");
      return Promise.reject(new Error(
        'the task metadata address is not a URL'));
    }
    log.debug("Leaving SpiffeTargets.readTask().");
    return SpiffeTargets.readUrl(href).then(function (text) {
      let body;
      try {
        body = JSON.parse(text);
      } catch (e) {
        log.debug("Caught in SpiffeTargets.readTask(): " +
                  ((e && e.message) || e));
        throw new Error('the task metadata was not JSON');
      }
      return SpiffeTargets.selfFromMetadata(body);
    });
  }

  /**
   * Every page of DescribeTargetGroups. The action cannot be scoped to an
   * ARN, so the caller filters by name.
   *
   * @param {any} client
   * @param {any} sdk
   * @returns {Promise<TargetGroup[]>}
   */
  static async listAllGroups(client, sdk) {
    log.debug("Entering SpiffeTargets.listAllGroups().");
    /** @type {TargetGroup[]} */
    const groups = [];
    let marker = '';
    try {
      do {
        /** @type {any} */
        const input = {};
        if (marker) {
          input.Marker = marker;
        }
        const out = await client.send(
          new sdk.DescribeTargetGroupsCommand(input));
        (out.TargetGroups || []).forEach(function (g) {
          groups.push({
            name: g.TargetGroupName,
            arn: g.TargetGroupArn,
            port: g.Port
          });
        });
        marker = out.NextMarker || '';
      } while (marker);
    } catch (e) {
      log.debug("Caught in SpiffeTargets.listAllGroups(): " +
                ((e && e.message) || e));
      log.debug("Leaving SpiffeTargets.listAllGroups(). Failed.");
      throw e;
    }
    log.debug("Leaving SpiffeTargets.listAllGroups().");
    return groups;
  }

  /**
   * The current members of one group. Health is ignored by the reconcile;
   * it is returned so a caller can see it.
   *
   * @param {any} client
   * @param {any} sdk
   * @param {string} arn
   * @returns {Promise<TargetMember[]>}
   */
  static groupHealth(client, sdk, arn) {
    log.debug("Entering SpiffeTargets.groupHealth().");
    log.debug("Leaving SpiffeTargets.groupHealth().");
    return client.send(new sdk.DescribeTargetHealthCommand({
      TargetGroupArn: arn
    })).then(function (out) {
      return (out.TargetHealthDescriptions || []).map(function (row) {
        const target = row.Target || {};
        const health = row.TargetHealth || {};
        return {
          id: target.Id,
          port: target.Port,
          state: health.State || ''
        };
      });
    });
  }

  /**
   * Registers or deregisters. No availability zone: an IP target in this
   * VPC does not take one, and sending one would be a different target.
   *
   * @param {any} client
   * @param {any} sdk
   * @param {string} arn
   * @param {TargetMember[]} targets
   * @param {boolean} register
   * @returns {Promise<unknown>}
   */
  static changeMembers(client, sdk, arn, targets, register) {
    log.debug("Entering SpiffeTargets.changeMembers().");
    const Cmd = register ? sdk.RegisterTargetsCommand
      : sdk.DeregisterTargetsCommand;
    const input = {
      TargetGroupArn: arn,
      Targets: (targets || []).map(function (t) {
        return { Id: t.id, Port: t.port };
      })
    };
    log.debug("Leaving SpiffeTargets.changeMembers().");
    return client.send(new Cmd(input));
  }

  /**
   * The RUNNING tasks' ARNs in `cluster`. Paged.
   *
   * @param {any} client
   * @param {any} sdk
   * @param {string} cluster
   * @returns {Promise<string[]>}
   */
  static async listTaskArns(client, sdk, cluster) {
    log.debug("Entering SpiffeTargets.listTaskArns().");
    /** @type {string[]} */
    const arns = [];
    let token = '';
    try {
      do {
        /** @type {any} */
        const input = { cluster: cluster, desiredStatus: 'RUNNING' };
        if (token) {
          input.nextToken = token;
        }
        const out = await client.send(new sdk.ListTasksCommand(input));
        (out.taskArns || []).forEach(function (arn) {
          arns.push(String(arn));
        });
        token = out.nextToken || '';
      } while (token);
    } catch (e) {
      log.debug("Caught in SpiffeTargets.listTaskArns(): " +
                ((e && e.message) || e));
      log.debug("Leaving SpiffeTargets.listTaskArns(). Failed.");
      throw e;
    }
    log.debug("Leaving SpiffeTargets.listTaskArns().");
    return arns;
  }

  /**
   * The private addresses of `arns`, a hundred at a time (DescribeTasks'
   * limit). A task with no IPv4 address is skipped.
   *
   * @param {any} client
   * @param {any} sdk
   * @param {string} cluster
   * @param {string[]} arns
   * @returns {Promise<TaskAddress[]>}
   */
  static async describeTaskIps(client, sdk, cluster, arns) {
    log.debug("Entering SpiffeTargets.describeTaskIps().");
    /** @type {TaskAddress[]} */
    const ips = [];
    try {
      for (let i = 0; i < arns.length; i += 100) {
        const slice = arns.slice(i, i + 100);
        const out = await client.send(new sdk.DescribeTasksCommand({
          cluster: cluster,
          tasks: slice
        }));
        (out.tasks || []).forEach(function (task) {
          const ip = SpiffeTargets.ipv4OfTask(task);
          if (ip) {
            ips.push({ ip: ip });
          }
        });
      }
    } catch (e) {
      log.debug("Caught in SpiffeTargets.describeTaskIps(): " +
                ((e && e.message) || e));
      log.debug("Leaving SpiffeTargets.describeTaskIps(). Failed.");
      throw e;
    }
    log.debug("Leaving SpiffeTargets.describeTaskIps().");
    return ips;
  }

  /**
   * The two clients, constructed with the default credential chain.
   * `AWS_REGION` is already set on the task (`environment/ecs.tf`). Nothing
   * is called until a reconcile sends.
   *
   * @param {any} elbSdk
   * @param {any} ecsSdk
   * @returns {CloudClients}
   */
  static clientsFromSdk(elbSdk, ecsSdk) {
    log.debug("Entering SpiffeTargets.clientsFromSdk().");
    const elb = new elbSdk.ElasticLoadBalancingV2Client({});
    const ecs = new ecsSdk.ECSClient({});
    const api = {
      elb: {
        listGroups: function () {
          return SpiffeTargets.listAllGroups(elb, elbSdk);
        },
        health: function (arn) {
          return SpiffeTargets.groupHealth(elb, elbSdk, arn);
        },
        register: function (arn, targets) {
          return SpiffeTargets.changeMembers(
            elb, elbSdk, arn, targets, true);
        },
        deregister: function (arn, targets) {
          return SpiffeTargets.changeMembers(
            elb, elbSdk, arn, targets, false);
        }
      },
      tasks: function (cluster) {
        return SpiffeTargets.listTaskArns(ecs, ecsSdk, cluster)
          .then(function (arns) {
            return SpiffeTargets.describeTaskIps(
              ecs, ecsSdk, cluster, arns);
          });
      }
    };
    log.debug("Leaving SpiffeTargets.clientsFromSdk().");
    return api;
  }

  /**
   * The AWS clients, or null when either package is not installed. Both are
   * optional peers (`package.json`); an image that was not built with them
   * records STS-CLUSTER-0027 rather than failing to load.
   *
   * @returns {CloudClients | null}
   */
  static loadClients() {
    log.debug("Entering SpiffeTargets.loadClients().");
    /** @type {any} */
    let elbSdk = null;
    /** @type {any} */
    let ecsSdk = null;
    try {
      elbSdk = require('@aws-sdk/client-elastic-load-balancing-v2');
    } catch (e) {
      log.debug("Caught in SpiffeTargets.loadClients(): " +
                ((e && e.message) || e));
      elbSdk = null;
    }
    try {
      ecsSdk = require('@aws-sdk/client-ecs');
    } catch (e) {
      log.debug("Caught in SpiffeTargets.loadClients(): " +
                ((e && e.message) || e));
      ecsSdk = null;
    }
    if (!elbSdk || !ecsSdk) {
      log.debug("Leaving SpiffeTargets.loadClients(). Absent.");
      return null;
    }
    const clients = SpiffeTargets.clientsFromSdk(elbSdk, ecsSdk);
    log.debug("Leaving SpiffeTargets.loadClients().");
    return clients;
  }

  /**
   * Logs STS-CLUSTER-0027 once per outage and returns the line, which the
   * caller throws so the scheduler records the run as failed.
   *
   * @param {string} message
   * @returns {string}
   */
  static noteFailure(message) {
    log.debug("Entering SpiffeTargets.noteFailure().");
    if (!SpiffeTargets.failing) {
      SpiffeTargets.failing = true;
      log.error(errorCodes.tag('STS-CLUSTER-0027') +
                'spiffe targets: ' + message);
    } else {
      log.debug("spiffe targets: still failing: " + message);
    }
    const text = errorCodes.tag('STS-CLUSTER-0027') +
      'spiffe targets: ' + message;
    log.debug("Leaving SpiffeTargets.noteFailure().");
    return text;
  }

  /**
   * Clears the outage after a reconcile that succeeded.
   */
  static recovered() {
    log.debug("Entering SpiffeTargets.recovered().");
    if (SpiffeTargets.failing) {
      SpiffeTargets.failing = false;
      log.info('spiffe targets: reconciling the SPIFFE target groups ' +
               'is working again.');
    }
    log.debug("Leaving SpiffeTargets.recovered().");
  }

  /**
   * Why the job is off, or `''` when it should run. The metadata address is
   * set by ECS on a Fargate task and inherited by every process of it.
   *
   * @returns {string}
   */
  static whyOff() {
    log.debug("Entering SpiffeTargets.whyOff().");
    let reason = '';
    if (SpiffeTargets.stopping) {
      reason = 'this process is stopping';
    } else if (!process.env.ECS_CONTAINER_METADATA_URI_V4) {
      reason = 'not an ECS task';
    }
    log.debug("Leaving SpiffeTargets.whyOff().");
    return reason;
  }

  /**
   * Reconciles from task metadata and the AWS clients.
   *
   * With no metadata address this is a no-op and does not throw. `opts.self`,
   * `opts.clients`, `opts.tasks` and `opts.loadClients` are how a test runs
   * the same path without the network or the SDKs. A failure is logged once
   * and thrown.
   *
   * @param {{
   *   metadataUri?: string,
   *   self?: { cluster?: string, ip?: string },
   *   clients?: CloudClients,
   *   tasks?: TaskAddress[],
   *   loadClients?: () => (CloudClients | null),
   *   deregisterOnly?: boolean
   * }} [opts]
   * @returns {Promise<ReconcileSummary>}
   */
  static reconcileLive(opts) {
    log.debug("Entering SpiffeTargets.reconcileLive().");
    const o = opts || {};
    const base = o.metadataUri ||
      process.env.ECS_CONTAINER_METADATA_URI_V4 || '';
    if (!base && !o.self) {
      log.debug("Leaving SpiffeTargets.reconcileLive(). Not an ECS task.");
      return Promise.resolve({
        skipped: 'not an ECS task', registered: 0, deregistered: 0,
        groups: 0
      });
    }
    const selfPromise = o.self
      ? Promise.resolve(o.self)
      : SpiffeTargets.readTask(base);
    log.debug("Leaving SpiffeTargets.reconcileLive().");
    return selfPromise.then(function (self) {
      const load = o.loadClients || function () {
        return SpiffeTargets.loadClients();
      };
      const clients = o.clients || load();
      if (!clients) {
        throw new Error('the elastic load balancing and ecs clients ' +
                        'are not installed');
      }
      const listed = o.tasks
        ? Promise.resolve(o.tasks)
        : clients.tasks(String(self.cluster || ''));
      return listed.then(function (tasks) {
        return SpiffeTargets.reconcileGroups({
          elb: clients.elb,
          tasks: tasks,
          self: self,
          deregisterOnly: !!o.deregisterOnly,
          stopping: function () {
            return !!SpiffeTargets.stopping && !o.deregisterOnly;
          }
        });
      });
    }).then(function (summary) {
      SpiffeTargets.recovered();
      return summary;
    }, function (e) {
      log.debug("Caught in SpiffeTargets.reconcileLive(): " +
                ((e && e.message) || e));
      throw new Error(SpiffeTargets.noteFailure((e && e.message) || e));
    });
  }

  /**
   * Registers the job, once. Every process calls this (`protocol_stack.ts`);
   * registering starts nothing. A narrow test with no scheduler is ignored.
   *
   * @param {{
   *   register?: (spec: any) => any,
   *   job?: (id: string) => any
   * }} scheduler
   */
  static ensureJob(scheduler) {
    log.debug("Entering SpiffeTargets.ensureJob().");
    if (!scheduler || typeof scheduler.register !== 'function' ||
        typeof scheduler.job !== 'function') {
      log.debug("Leaving SpiffeTargets.ensureJob(). No scheduler.");
      return;
    }
    if (scheduler.job(SpiffeTargets.JOB_ID)) {
      log.debug("Leaving SpiffeTargets.ensureJob(). Already registered.");
      return;
    }
    scheduler.register({
      id: SpiffeTargets.JOB_ID,
      title: 'SPIFFE target reconcile',
      describe: 'Registers each running task\'s private address in this ' +
        'cluster\'s SPIFFE target groups and deregisters an address no ' +
        'running task still has (#323).',
      owner: 'cluster/spiffe_targets.js',
      kind: 'cluster',
      scope: 'service',
      everyMs: function () {
        return SpiffeTargets.INTERVAL_MS;
      },
      off: function () {
        return SpiffeTargets.whyOff();
      },
      manual: true,
      run: function () {
        return SpiffeTargets.reconcileLive();
      }
    });
    log.debug("Leaving SpiffeTargets.ensureJob(). Registered.");
  }

  /**
   * The front process, after its listeners are bound. A failure is caught:
   * the service is already answering, and the next job retries.
   */
  static onStart() {
    log.debug("Entering SpiffeTargets.onStart().");
    if (SpiffeTargets.whyOff()) {
      log.debug("Leaving SpiffeTargets.onStart(). Off.");
      return;
    }
    SpiffeTargets.reconcileLive().catch(function (e) {
      log.debug("Caught in SpiffeTargets.onStart(): " +
                ((e && e.message) || e));
      // reconcileLive already recorded STS-CLUSTER-0027. The listeners
      // do not wait on the target groups.
    });
    log.debug("Leaving SpiffeTargets.onStart().");
  }

  /**
   * The shutdown flag. Called before the scheduler stops, so a reconcile
   * already inside `reconcileGroups()` sees it before the next mutating call.
   */
  static beginStop() {
    log.debug("Entering SpiffeTargets.beginStop().");
    SpiffeTargets.stopping = true;
    log.debug("Leaving SpiffeTargets.beginStop().");
  }

  /**
   * Deregisters this task's address. Never rejects: shutdown is going on
   * with or without the load balancer. `opts.timeoutMs` shortens the wait,
   * which a test uses; a stop passes nothing and waits `STOP_MS`.
   *
   * The one-shot timer does not reschedule itself. The reconcile is the
   * periodic work, and it is the scheduler's job.
   *
   * @param {{
   *   timeoutMs?: number,
   *   metadataUri?: string,
   *   self?: { cluster?: string, ip?: string },
   *   clients?: CloudClients,
   *   tasks?: TaskAddress[],
   *   loadClients?: () => (CloudClients | null)
   * }} [opts]
   * @returns {Promise<ReconcileSummary>}
   */
  static onStop(opts) {
    log.debug("Entering SpiffeTargets.onStop().");
    const o = opts || {};
    const wait = typeof o.timeoutMs === 'number' ? o.timeoutMs
      : SpiffeTargets.STOP_MS;
    if (!o.metadataUri && !process.env.ECS_CONTAINER_METADATA_URI_V4 &&
        !o.self) {
      log.debug("Leaving SpiffeTargets.onStop(). Not an ECS task.");
      return Promise.resolve({
        skipped: 'not an ECS task', registered: 0, deregistered: 0,
        groups: 0
      });
    }
    /** @type {NodeJS.Timeout | null} */
    let timer = null;
    const timed = new Promise(function (resolve) {
      timer = setTimeout(function () {
        resolve({
          skipped: 'timed out', registered: 0, deregistered: 0,
          groups: 0, timedOut: true
        });
      }, wait);
    });
    const work = SpiffeTargets.reconcileLive(
      Object.assign({}, o, { deregisterOnly: true })
    ).then(function (summary) {
      if (timer) {
        clearTimeout(timer);
      }
      return summary;
    }, function (e) {
      log.debug("Caught in SpiffeTargets.onStop(): " +
                ((e && e.message) || e));
      if (timer) {
        clearTimeout(timer);
      }
      return {
        skipped: 'failed', registered: 0, deregistered: 0, groups: 0,
        failed: true
      };
    });
    log.debug("Leaving SpiffeTargets.onStop().");
    return Promise.race([work, timed]);
  }
}

module.exports = SpiffeTargets;
