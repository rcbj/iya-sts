'use strict';
//
// File: stack_network.js
//
// ===========================================================================
// NAMING A PROJECT MUST ISOLATE THE WHOLE RUN, AND THE NETWORK WAS THE THIRD
// THING TO ESCAPE THAT.
//
// ./local-run-tests.sh's own header is the record of the first two: a compose
// PROJECT scopes containers, networks and volumes, and `container_name` is
// machine-wide, so for a while `STS_TEST_COMPOSE_PROJECT=mine` isolated the
// project and handed the other run's containers straight back. That was fixed
// on 2026-09-07 by naming the containers from the project.
//
// On 2026-09-12 a realm's SPIFFE listeners needed ADDRESSES of their own —
// `spiffe.grpcHost` is a literal IP, so something has to decide which
// addresses exist and they have to be the same on every start — and both
// compose files grew a subnet written out as a literal. A NETWORK IS
// MACHINE-WIDE IN EXACTLY THE WAY A `container_name` IS. So the second run in
// this tree, however it was named, asked for the address space the first was
// holding and got
//
//     invalid pool request: Pool overlaps with other one on this address space
//
// before one container started. It reads as a docker problem, it names
// nothing in the tree, and the run reports that the service never came up.
//
// ---------------------------------------------------------------------------
// WHAT THIS FILE PINS, AND WHY EACH CLAIM IS HERE RATHER THAN LEFT TO A RUN.
//
//   1. the scan exists, is SHARED, and asks both of the questions docker
//      itself asks — every docker network, and every route on this machine,
//      because the same message is what a VPN route or a libvirt bridge
//      produces;
//   2. both launchers call it, with DIFFERENT bases, so one run of each never
//      reaches the scan at all;
//   3. a launcher's base is the base of its own compose file's default, which
//      is what makes a plain run on an idle machine take exactly the
//      addresses it always took;
//   4. every one of the four variables is named in COMPOSE_ENV — three of
//      them are addresses INSIDE the first, so a run that moved the subnet
//      and left an address behind would ask compose for an address outside
//      its own network;
//   5. and the addresses are derived from the SUBNET rather than from the
//      base, which is not the same thing: the scan hands back `172.29.1.0/24`
//      as readily as `172.29.0.0/24`.
//
// FOURTEEN MUTANTS, ALL CAUGHT — and one of them is only caught because of an
// edit this file made to itself. The scan asks docker in TWO calls, `network
// ls` for the names and `network inspect` for the subnet each one holds, and
// the first version of claim (1) accepted either. A helper with one of the two
// removed answers "nothing is in use" and hands back exactly the address space
// the other run is holding, which is indistinguishable from no scan at all —
// so the check asks for both.
//
// WHY IN PROCESS. Every claim is a comparison between FILES — two launchers,
// the helper they share and the two compose files — which no running service
// could be asked. It is teardown_bounds.js's shape and admin_api_token_
// wiring.js's before it: the only run that would catch this is the run that
// has already been lost.
// ===========================================================================

const fs = require('fs');
const path = require('path');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'stack_network',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function read(rel) {
  log.debug("Entering read().");
  log.debug("Leaving read().");
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

// The launcher, with the compose file it drives and the /16 it is expected to
// sit in. There were two until 2026-09-16, when ./local-run-tests.sh (whose
// stack sat in 172.29) was removed (#50); the list stays a list so a second
// launcher is a row rather than a rewrite.
const LAUNCHERS = [
  {
    script: 'run-tests.sh',
    compose: 'docker-compose-run-tests.yml',
    base: '172.30'
  }
];

// The four variables that MOVE TOGETHER. Three of them are addresses inside
// the first, which is the whole reason they are derived from one answer in
// one place rather than named four times in four.
const VARIABLES = [
  'STS_NETWORK_SUBNET',
  'STS_ADDRESS',
  'STS_SPIFFE_GRPC_HOST',
  'STS_EXTRA_IPS'
];

// ---------------------------------------------------------------------------
// THE SCAN ITSELF. In tests/tools/compose.sh for the reason resolveCompose()
// and docker_compose() are there: two launchers needing one answer, and two
// copies of it is two ways for them to disagree about which addresses on this
// machine are free.
// ---------------------------------------------------------------------------
function checkTheScanIsSharedAndComplete(t) {
  log.debug("Entering checkTheScanIsSharedAndComplete().");
  t.log.info('=== one subnet scan, shared by both launchers ===');
  const helper = read('tests/tools/compose.sh');

  t.check(/freeSubnet\s*\(\)/.test(helper),
          'tests/tools/compose.sh defines freeSubnet()',
          'both launchers reach docker through this file; a scan written ' +
          'into one of them would leave the other with the literal that ' +
          'refused the second run in this tree');

  // BOTH halves, because they are one question asked in two calls: `ls` names
  // the networks and `inspect` is the only thing that says what subnet each
  // one holds. A scan with either half missing answers "nothing is in use"
  // and hands back the address space the other run is already holding —
  // which is indistinguishable from no scan at all.
  t.check(/docker network ls/.test(helper) &&
          /docker network inspect/.test(helper),
          'it asks docker which subnets are already configured',
          'the overlap the daemon refuses is most often another compose ' +
          'stack on this same machine, which is exactly what `docker ' +
          'network ls` and `docker network inspect` can be asked about');

  // NOT belt and braces. The daemon checks the host routing table too, so a
  // scan that looked only at docker would keep handing back a subnet that is
  // then refused — and the caller would have no idea why.
  t.check(/ip -4 route show/.test(helper),
          'and it asks this machine which routes already exist',
          'the same refusal is what a VPN route or a libvirt bridge ' +
          'produces, so a scan that consulted only docker would loop ' +
          'through 256 candidates that are all equally refused');

  // A caller that cannot be given one is told so. A default here would move
  // the failure to `up`, which is the failure this whole file is about.
  t.check(/process\.exit\(1\)/.test(helper),
          'and it returns nothing rather than a default it cannot vouch for',
          'the point of the scan is to say what is wrong BEFORE the stack ' +
          'tries, so a fallback to the literal would be the scan handing ' +
          'back the very answer it was asked to avoid');
  log.debug("Leaving checkTheScanIsSharedAndComplete().");
}

// ---------------------------------------------------------------------------
// EVERY LAUNCHER CALLS IT, AND THE BASE EACH ONE PASSES IS ITS OWN COMPOSE
// FILE'S DEFAULT. The second half is what keeps a plain run on an idle
// machine byte-for-byte what it was: the first candidate freeSubnet() offers
// is `<base>.0.0/24`, so nothing moves unless something is in the way.
// ---------------------------------------------------------------------------
function checkBothLaunchersScan(t) {
  log.debug("Entering checkBothLaunchersScan().");
  t.log.info('=== the launcher chooses a subnet, from its own base ===');

  LAUNCHERS.forEach(function (launcher) {
    const script = read(launcher.script);
    const compose = read(launcher.compose);

    t.check(new RegExp('freeSubnet ' + launcher.base.replace('.', '\\.'))
              .test(script),
            launcher.script + ' scans from ' + launcher.base,
            'a launcher that took the compose file default would be back ' +
            'where the literal left it: correct alone and refused beside ' +
            'any other run in this tree');

    // The compose file's own default, which is what a `docker compose up` in
    // this directory gets and what the first candidate must therefore be.
    const declared = /STS_NETWORK_SUBNET:-([0-9.]+\/\d+)/.exec(compose);
    t.check(declared !== null,
            launcher.compose + ' still declares a default subnet',
            'the default is what somebody running compose by hand gets, ' +
            'and it is also the first candidate the scan offers');
    if (declared) {
      t.check(declared[1] === launcher.base + '.0.0/24',
              'and it is ' + launcher.base + '.0.0/24, which is the base ' +
                launcher.script + ' scans from',
              'if the two disagree then a plain run on an idle machine ' +
              'moves its addresses for no reason, and the compose file ' +
              'documents a subnet no run ever takes');
    }
  });

  // AND NOT IN THE /16 OF `docker compose up`'S STACK (docker-compose.yml),
  // which somebody's development service may be sitting in while the suite
  // runs. This compared two launchers until ./local-run-tests.sh — whose
  // stack WAS that compose file — was removed on 2026-09-16 (#50); the dev
  // stack is still there, so the separation still matters.
  const devDeclared = /STS_NETWORK_SUBNET:-([0-9.]+)\.0\.0\/\d+/.exec(
    read('docker-compose.yml'));
  t.check(devDeclared !== null &&
          LAUNCHERS.every(function (launcher) {
            return launcher.base !== devDeclared[1];
          }),
          'and no launcher sits in the /16 of docker-compose.yml\'s stack',
          'a development stack left up is the ordinary case, and a test run ' +
          'beside it should not depend on a scan to work; found ' +
          (devDeclared ? devDeclared[1] : 'no default'));
  log.debug("Leaving checkBothLaunchersScan().");
}

// ---------------------------------------------------------------------------
// THE FOUR VARIABLES REACH COMPOSE. Naming a subnet and leaving `STS_ADDRESS`
// to the compose file's literal is worse than naming neither: compose refuses
// a static address outside its own network, so the run fails at `up` having
// done the work of choosing.
// ---------------------------------------------------------------------------
function checkTheFourVariablesTravelTogether(t) {
  log.debug("Entering checkTheFourVariablesTravelTogether().");
  t.log.info('=== the subnet and the three addresses in it move together ===');

  LAUNCHERS.forEach(function (launcher) {
    const script = read(launcher.script);
    const compose = read(launcher.compose);

    VARIABLES.forEach(function (name) {
      t.check(new RegExp('"' + name + '=').test(script),
              launcher.script + ' names ' + name + ' to compose',
              'what a run does not name is the compose file default, and ' +
              'that default is the same literal for every run on this ' +
              'machine — which is the collision this file is about');

      t.check(new RegExp('\\$\\{' + name + ':?-').test(compose),
              launcher.compose + ' substitutes ' + name,
              'a literal written back into the compose file would be ' +
              'unreachable from the launcher, and the launcher would go on ' +
              'reporting a subnet nothing used');
    });
  });
  log.debug("Leaving checkTheFourVariablesTravelTogether().");
}

// ---------------------------------------------------------------------------
// AND THE ADDRESSES COME OFF THE SUBNET RATHER THAN OFF THE BASE. This is the
// one claim here that is not about isolation at all — it is about an edit
// that is easy to make and impossible to see: `172.29` + `.0.10` is right for
// the first candidate and wrong for all 255 others, so it survives every test
// run on an idle machine and fails only on the second run, which is the exact
// situation the scan exists for.
// ---------------------------------------------------------------------------
function checkTheAddressesComeOffTheSubnet(t) {
  log.debug("Entering checkTheAddressesComeOffTheSubnet().");
  t.log.info('=== the addresses are derived from the chosen subnet ===');

  LAUNCHERS.forEach(function (launcher) {
    const script = read(launcher.script);

    t.check(/STS_NETWORK_PREFIX="\$\{STS_NETWORK_SUBNET%\/\*\}"/.test(script),
            launcher.script + ' takes the prefix from the subnet it chose',
            'a prefix built from the base is right for `<base>.0.0/24` and ' +
            'wrong for every other candidate, which means it is right on ' +
            'every machine where the scan changes nothing');

    t.check(/STS_SERVICE_ADDRESS="\$\{STS_NETWORK_PREFIX\}\.10"/.test(script),
            'and the service address is the .10 of THAT prefix',
            'compose refuses a static address outside the network it is ' +
            'creating, so this is the difference between a second run and ' +
            'a second failure');

    t.check(/STS_NETWORK_BITS="\$\{STS_NETWORK_SUBNET##\*\/\}"/.test(script),
            'and the extra addresses carry the subnet\'s own prefix length',
            'the container adds them to its own interface with `ip addr ' +
            'add`, so a length that did not match the network would give a ' +
            'realm listener an address with the wrong idea of who is local');
  });
  log.debug("Leaving checkTheAddressesComeOffTheSubnet().");
}

function run(t) {
  log.debug("Entering run().");
  checkTheScanIsSharedAndComplete(t);
  checkBothLaunchersScan(t);
  checkTheFourVariablesTravelTogether(t);
  checkTheAddressesComeOffTheSubnet(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'stack_network',
  describe: 'that two runs in one tree get two subnets, so naming a compose ' +
            'project isolates the network as well as the containers',
  run: run
};
