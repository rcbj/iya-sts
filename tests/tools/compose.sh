#
# tests/tools/compose.sh — how this repository's two launchers talk to docker.
#
# SOURCED, never run: it defines three functions and sets nothing. Both
# ./local-run-tests.sh (which brings up ONE service and drives it from this
# machine) and ./docker-run-tests.sh (which brings up the service AND the tests
# container and drives nothing itself) need exactly the same three answers —
# which compose command is on this machine, how to hand it the variables a
# compose file substitutes, and how to stop waiting on one that has wedged — so
# they are here rather than in both.
#
# It lives in tests/tools/ for the reason everything else in this directory
# does: tools/ is NOT tests. run.js's discovery rule walks tests/*.js and would
# otherwise have to be told to skip a file, and it is a `.sh` besides.
#
# THE CONTRACT WITH A CALLER, because these two read and write globals rather
# than taking arguments:
#
#   DOCKER_SUDO    set by resolveCompose(); "" or "yes".
#   COMPOSE_CMD    set by resolveCompose(); "docker compose" or
#                  "docker-compose".
#   COMPOSE_ENV    an ARRAY the caller fills with NAME=value strings before
#                  calling docker_compose(). May be unset; the expansions
#                  below tolerate that under `set -u`.
#
# A caller that forgets to call resolveCompose() first gets an empty
# COMPOSE_CMD and a shell error naming nothing, so both launchers call it once
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
# called `NAME=value`, which is the same trap this file's header describes
# about `env docker_compose`, one layer along. `sudo timeout ... env ...` is
# correct for the sudo path too: sudo empties the environment and `env` fills
# it back with exactly what the compose file substitutes.
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
      env ${COMPOSE_ENV[@]+"${COMPOSE_ENV[@]}"} ${COMPOSE_CMD} "$@"
    return $?
  fi
  "${timeoutCmd}" --kill-after=30s "${seconds}" \
    env ${COMPOSE_ENV[@]+"${COMPOSE_ENV[@]}"} ${COMPOSE_CMD} "$@"
  return $?
}
