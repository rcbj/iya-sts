#
# tests/tools/compose.sh — how this repository's launchers talk to docker.
#
# SOURCED, never run: it defines four functions and sets nothing.
# ./docker-run-tests.sh (which brings up the service AND the tests container
# and drives nothing itself) and ./run-coverage.sh (which runs the tests
# container alone) are its callers now; ./local-run-tests.sh (which brought up
# ONE service and drove it from this machine) was the other until it was
# removed on 2026-09-16. They needed exactly the same four answers —
# which compose command is on this machine, how to hand it the variables a
# compose file substitutes, how to stop waiting on one that has wedged, and
# which addresses on this machine are free for the stack to take — so they are
# here rather than in both.
#
# It lives in tests/tools/ for the reason everything else in this directory
# does: tools/ is NOT tests. run.js's discovery rule walks tests/*.js and would
# otherwise have to be told to skip a file, and it is a `.sh` besides.
#
# THE CONTRACT WITH A CALLER, because these functions read and write globals
# rather than taking arguments:
#
#   DOCKER_SUDO    set by resolveCompose(); "" or "yes".
#   COMPOSE_CMD    set by resolveCompose(); "docker compose" or
#                  "docker-compose".
#   COMPOSE_ENV    an ARRAY the caller fills with NAME=value strings before
#                  calling docker_compose(). May be unset; the expansions
#                  below tolerate that under `set -u`.
#
# A caller that forgets to call resolveCompose() first gets an empty
# COMPOSE_CMD and a shell error naming nothing, so every launcher calls it once
# and check its return value.
#

# Which docker compose, and does it need sudo? Both answered by RUNNING the
# thing rather than by looking for a group in `id -nG`, which is neither
# necessary (a rootless daemon needs no group) nor sufficient (a group added
# since this shell logged in is not in this shell's credentials).
resolveCompose()
{
  if docker info > /dev/null 2>&1;
  then
    DOCKER_SUDO=""
  elif sudo -n docker info > /dev/null 2>&1;
  then
    # PASSWORDLESS sudo only. An interactive `sudo` here would sit waiting for
    # a password in the middle of what a person started and walked away from,
    # and would hang a CI agent outright.
    DOCKER_SUDO="yes"
  else
    return 1
  fi

  if [ -n "${DOCKER_SUDO}" ];
  then
    if sudo -n docker compose version > /dev/null 2>&1;
    then
      COMPOSE_CMD="docker compose"
      return 0
    fi
  elif docker compose version > /dev/null 2>&1;
  then
    COMPOSE_CMD="docker compose"
    return 0
  fi
  # The v1 standalone binary, still what some machines have.
  if command -v docker-compose > /dev/null 2>&1;
  then
    COMPOSE_CMD="docker-compose"
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# One compose command, with the variables the compose file substitutes.
#
# THEY ARE NAMED ON THE COMMAND LINE RATHER THAN EXPORTED, and that is two
# decisions in one. `sudo` EMPTIES the environment, so an exported variable
# reaches compose as unset and the file substitutes its default with nothing
# said — which is how the parent project's stack spent months ignoring every
# tuning variable it was handed. And `CONFIG_FILE` is a variable the tests in
# this repository read too, so exporting the container's copy of it would
# change what every in-process job loads.
# ---------------------------------------------------------------------------
docker_compose()
{
  if [ -n "${DOCKER_SUDO}" ];
  then
    sudo ${COMPOSE_ENV[@]+"${COMPOSE_ENV[@]}"} ${COMPOSE_CMD} "$@"
    return $?
  fi
  env ${COMPOSE_ENV[@]+"${COMPOSE_ENV[@]}"} ${COMPOSE_CMD} "$@"
  return $?
}

# ---------------------------------------------------------------------------
# THE SAME COMMAND WITH A WALL CLOCK ON IT (2026-09-10), and the reason it
# exists is a CI run that PASSED and was reported as a failure.
#
# On 2026-09-10 the containerized launcher's last mode finished green — 78
# jobs, 78 passed, the report written, the runner container exited 0 — and then
# `up --abort-on-container-exit`, which stops the stack once the runner is
# done, printed `Container sts-postgres-docker-tests  Stopping` and sat there
# for TWENTY-THREE MINUTES, until the job hit its wall clock and the whole run
# was cancelled. Modes one and two had stopped the same container in under half
# a second each; a run the day before stopped it three times out of three. The
# daemon wedged, and nothing in the tree was wrong.
#
# **NO COMPOSE FLAG COVERS THAT AND IT IS WORTH SAYING WHY.** `up` already
# takes `--timeout` for a container's shutdown grace, it already defaults to
# ten seconds, and the `xacml-pep` container spends every one of them on every
# run before being killed — so SIGKILL was reached and did not land. A stop
# that outlives SIGKILL is a stuck daemon or a process the kernel will not
# interrupt, and the only lever left is to stop WAITING for it.
#
# So: a bound, and a caller that decides what a bound being reached means. It
# is never a verdict on the tree — see docker-run-tests.sh, which recovers the
# mode's real answer from the container docker has already recorded the exit
# code of.
#
# `timeout` is coreutils and is on every machine either launcher can run on;
# where it is missing this degrades to the unbounded call, which is exactly the
# behaviour that existed before. `--kill-after` because SIGTERM asks compose to
# stop the stack — the very thing that is stuck — so the ask needs a deadline
# of its own.
#
# THE VARIABLES GO THROUGH `env` HERE RATHER THAN AS BARE `NAME=value` WORDS.
# `timeout NAME=value docker compose ...` asks the kernel to execute a program
# called `NAME=value`, which is the same trap `docker_compose()` avoids by
# putting `env` in front of those words, one layer along. `sudo timeout ...
# env ...` is correct for the sudo path too: sudo empties the environment and
# `env` fills it back with exactly what the compose file substitutes.
#
# **AND COMPOSE IS KEPT OFF THE TERMINAL (2026-09-14), OR `up` FROM A TERMINAL
# NEVER STARTS.** `timeout` runs its command in a process group of its own, so
# that the kill reaches everything under it — which also makes that command a
# BACKGROUND job on the terminal. An attached `docker compose up` on a TTY
# turns on its interactive shortcut menu and reads the keyboard, the kernel
# answers a background read with SIGTTIN, and compose sits STOPPED (state `T`)
# after `Container ... Created`: no log output, the runner container never
# started, until this bound kills it and the mode is lost. CI never saw it,
# having no terminal. `COMPOSE_MENU=false` turns the menu off and stdin from
# /dev/null leaves nothing to read; each alone was enough when reproduced under
# a pseudo-terminal, and both are kept because nothing a launcher asks compose
# for reads stdin. `timeout --foreground` was not the fix: it gives up timing
# out the command's children, and the compose plugin IS a child.
# ---------------------------------------------------------------------------
docker_compose_bounded()
{
  local seconds="$1"
  shift
  local timeoutCmd
  timeoutCmd="$(command -v timeout 2> /dev/null || true)"
  if [ -z "${timeoutCmd}" ] || [ -z "${seconds}" ];
  then
    docker_compose "$@"
    return $?
  fi
  if [ -n "${DOCKER_SUDO}" ];
  then
    sudo "${timeoutCmd}" --kill-after=30s "${seconds}" \
      env ${COMPOSE_ENV[@]+"${COMPOSE_ENV[@]}"} COMPOSE_MENU=false \
      ${COMPOSE_CMD} "$@" < /dev/null
    return $?
  fi
  "${timeoutCmd}" --kill-after=30s "${seconds}" \
    env ${COMPOSE_ENV[@]+"${COMPOSE_ENV[@]}"} COMPOSE_MENU=false \
    ${COMPOSE_CMD} "$@" < /dev/null
  return $?
}

# ---------------------------------------------------------------------------
# A /24 NOBODY ELSE ON THIS MACHINE IS USING (2026-09-12), and it is here for
# the same reason the three functions above are: it was written for two
# launchers that must not answer it differently, and a second caller of it
# would be in the same position.
#
# **NAMING A PROJECT MUST ISOLATE THE WHOLE RUN, AND ON 2026-09-12 IT STOPPED
# DOING SO AGAIN.** ./local-run-tests.sh's own header (removed 2026-09-16; in
# git history) was the record of that lesson learnt once at the container
# names; the SUBNET arrived the same day a
# realm's SPIFFE listeners needed addresses of their own, went into
# docker-compose.yml as a literal `172.29.0.0/24`, and was not added to the
# list of things a project name scopes. A network is machine-wide exactly as a
# `container_name` is, so the second run in this tree — whatever project it was
# given — asked for a subnet the first run was holding and got
#
#   invalid pool request: Pool overlaps with other one on this address space
#
# before a single container started. It reads as a docker problem and is two
# runs sharing an address.
#
# THE FIRST CANDIDATE IS THE COMPOSE FILE'S OWN DEFAULT, so a plain run on an
# idle machine takes exactly the addresses it always took and nothing about
# this is visible; the scan only moves a SECOND run out of the way. The base
# is the caller's because the two launchers deliberately sat in different /16s
# — 172.29 for ./local-run-tests.sh (removed 2026-09-16) and 172.30 for the
# containerized one — so that a run of each did not need the scan at all.
#
# WHAT COUNTS AS USED IS BOTH ANSWERS DOCKER ITSELF CHECKS: every existing
# docker network's configured subnet, and every route in this machine's own
# table. The second is not belt and braces — the error above is also what a
# VPN route or a libvirt bridge produces, and a scan that looked only at
# docker would keep handing back a subnet the daemon then refuses.
#
# A CALLER GETS NOTHING BACK AND A NON-ZERO STATUS if all 256 are spoken for,
# rather than a default that would fail at `up`: the point of this is to say
# what is wrong before the stack tries.
# ---------------------------------------------------------------------------
freeSubnet()
{
  local base="$1"
  local used=""
  local ids=""
  if [ -n "${DOCKER_SUDO}" ];
  then
    ids="$(sudo -n docker network ls -q 2> /dev/null || true)"
    if [ -n "${ids}" ];
    then
      used="$(echo "${ids}" | xargs -r sudo -n docker network inspect \
        -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2> /dev/null || true)"
    fi
  else
    ids="$(docker network ls -q 2> /dev/null || true)"
    if [ -n "${ids}" ];
    then
      used="$(echo "${ids}" | xargs -r docker network inspect \
        -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2> /dev/null || true)"
    fi
  fi
  if command -v ip > /dev/null 2>&1;
  then
    used="${used} $(ip -4 route show 2> /dev/null | awk '{ print $1 }' || true)"
  fi
  node -e '
    var base = process.argv[1];
    var used = String(process.argv[2] || "").split(/\s+/).filter(Boolean);
    // A CIDR as a pair of unsigned 32-bit integers. Anything that is not one
    // is dropped rather than guessed at: `ip route` prints `default` and
    // bare addresses among the prefixes, and neither can overlap anything.
    function parse(text)
    {
      var m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(text);
      if (!m) { return null; }
      var bits = Number(m[5]);
      if (bits < 0 || bits > 32) { return null; }
      var addr = (((Number(m[1]) << 24) >>> 0) + (Number(m[2]) << 16) +
                  (Number(m[3]) << 8) + Number(m[4])) >>> 0;
      var mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      return { net: (addr & mask) >>> 0, mask: mask };
    }
    var taken = used.map(parse).filter(Boolean);
    // Two ranges overlap when either one contains the network address of the
    // other. No arithmetic about sizes is needed and none is done.
    function overlaps(a, b)
    {
      return ((a.net & b.mask) >>> 0) === b.net ||
             ((b.net & a.mask) >>> 0) === a.net;
    }
    for (var third = 0; third < 256; third += 1)
    {
      var candidate = base + "." + third + ".0/24";
      var range = parse(candidate);
      if (!range) { break; }
      var clash = taken.some(function (other) { return overlaps(range, other); });
      if (!clash)
      {
        process.stdout.write(candidate);
        process.exit(0);
      }
    }
    process.exit(1);
  ' "${base}" "${used}"
}
