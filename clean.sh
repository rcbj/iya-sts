#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# Remove EVERY container, image, volume, network and build cache entry on this
# host -- not just this project's. After it runs, the next
# `CONFIG_FILE=./env/local.js docker-compose build` re-pulls and rebuilds from
# scratch.
#
# Two things this script got wrong before, and both surfaced as a docker usage
# message or a daemon conflict rather than as an explanation of what happened:
#
#   * `docker stop $(docker ps -aq)` with NOTHING to stop expands to a bare
#     `docker stop`, which exits 1 with "See 'docker stop --help' for more
#     information" -- so an ALREADY clean host reported an error for being
#     clean, and the same went for the `docker rm` line below it.
#   * `docker rmi $(docker images -q)` passes only the TAGGED images, so a
#     base image that an untagged intermediate was built FROM cannot be
#     deleted: "conflict: unable to delete <id> (cannot be forced) - image has
#     dependent child images". `--force` does not help -- that conflict is one
#     of the few docker refuses to force -- the children have to go first.
#     `docker image prune --all` does them in dependency order, which is why
#     the removals below lead with a prune rather than with `rmi`.
#
# A third trap is gone with the old volume line: `docker volume ls | awk
# '{ print $2 }'` includes the "VOLUME NAME" header, so `docker volume rm` was
# always handed the literal string NAME. `docker volume ls -q` prints ids only.

set -u

# On Windows under Cygwin the CLI is Docker Desktop's docker.exe, and two
# things differ from Linux. It prints ids with CRLF line endings, so every
# id read back from it would carry a trailing \r and docker would answer
# "No such container: <id>" for each one -- `ids` strips them. And there is
# no sudo: a daemon that does not answer is Docker Desktop not running, not
# a socket permission problem, so it is reported instead of retried.
case "$(uname -s)" in
  CYGWIN*|MINGW*|MSYS*) WINDOWS=1 ;;
  *) WINDOWS=0 ;;
esac

if command -v docker > /dev/null 2>&1; then
  DOCKER="docker"
elif command -v docker.exe > /dev/null 2>&1; then
  DOCKER="docker.exe"
else
  echo "clean.sh: no docker (or docker.exe) on PATH." >&2
  exit 1
fi

# The `rcbj` account is in the `docker` group on this machine, so sudo is only
# needed where the socket is not readable. Probe once rather than prompting for
# a password on every run.
if ! $DOCKER info > /dev/null 2>&1; then
  if [ "$WINDOWS" = 1 ] || ! command -v sudo > /dev/null 2>&1; then
    echo "clean.sh: the docker daemon does not answer -- is Docker" \
      "Desktop running?" >&2
    exit 1
  fi
  DOCKER="sudo $DOCKER"
fi

ids() {
  $DOCKER "$@" | tr -d '\r'
}

echo "== containers =="
containers=$(ids ps -aq)
if [ -n "$containers" ]; then
  $DOCKER stop $containers
  $DOCKER rm --force $containers
else
  echo "None."
fi

echo "== images =="
# Everything is unused now that the containers are gone, so --all takes the
# tagged images too, children before parents.
$DOCKER image prune --all --force
# Anything an in-flight container held on to during the prune.
images=$(ids images -q | sort -u)
if [ -n "$images" ]; then
  $DOCKER rmi --force $images
fi

echo "== volumes =="
$DOCKER volume prune --all --force
volumes=$(ids volume ls -q)
if [ -n "$volumes" ]; then
  $DOCKER volume rm --force $volumes
fi

echo "== networks =="
$DOCKER network prune --force

echo "== build cache =="
# Never reclaimed before this; it is invisible to `docker images` and is
# routinely several GB after a run of the test suite.
$DOCKER builder prune --all --force

echo "== remaining =="
$DOCKER system df
