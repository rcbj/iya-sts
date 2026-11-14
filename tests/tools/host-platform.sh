# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# tests/tools/host-platform.sh — the machine a launcher runs on: Linux, or
# Windows under Cygwin (#512).
#
# SOURCED, never run, by every script in this repository that runs on a
# person's machine rather than inside an image: ./run-tests.sh,
# ./run-coverage.sh, ./run-jsdoc.sh, ./docker-npm-test.sh, ./clean.sh, the
# four deploy/*/terraform-local.sh, the three deploy/*/bootstrap-state.sh,
# deploy/aws/run-suite.sh, deploy/aws/convert-to-cells.sh,
# tests/tools/rehearse-cell-conversion.sh and the scripts in utilities/. The
# scripts that run inside a container (every entrypoint, postgres/,
# build-typescript.sh, build-native.sh, the tests image's builders) never see
# Windows and do not source it; what they need from a Windows checkout is
# .gitattributes, which keeps their line endings LF.
#
# ON LINUX IT CHANGES NOTHING: HOST_WINDOWS is 0, hostPath() hands its
# argument back, HOST_USER_ARGS is the `--user uid:gid` the launchers always
# passed, and PATH is left alone. Everything below is about the other case.
#
# WHAT IS DIFFERENT UNDER CYGWIN, and each of these was a launcher failing
# with a message about something else:
#
#   * THE PROGRAMS ARE NATIVE WINDOWS ONES. docker.exe (Docker Desktop),
#     node.exe, aws.exe, gcloud and az know nothing of /cygdrive/c/... or of
#     Cygwin's /tmp, so a bind-mount source, a `-f` Dockerfile, an
#     `--env-file` from mktemp or a script path handed to node arrives as a
#     path that does not exist. hostPath() is `cygpath -m`: C:/Users/... ,
#     which Docker Desktop, compose and node all accept, and which needs no
#     escaping inside a `-v src:dst` the way a backslash would.
#   * THEIR OUTPUT ENDS LINES IN CRLF (clean.sh found it first, 2026-10-07:
#     "No such container: <id>" for every id it had just been given). A
#     captured `$(docker inspect -f '{{.State.Health.Status}}' ...)` is then
#     `healthy\r`, which equals nothing it is compared with, and a run waits
#     out its whole bound on a service that was up. Rather than strip it at
#     each of the hundred-odd captures, tests/tools/windows/ holds a shim per
#     program that strips it once, and this file puts that directory first on
#     PATH — so `timeout 60 docker exec`, `xargs docker` and compose.sh's
#     `env ... docker compose`, which a shell function would never reach, get
#     it too. tests/tools/windows/run-native argues the shim.
#   * THERE IS NO sudo, and no socket permission to need it for: a daemon
#     that does not answer is Docker Desktop not running.
#   * FILE OWNERSHIP DOES NOT CROSS THE BIND MOUNT. Docker Desktop writes the
#     host's files as the Windows user whoever the container ran as, so the
#     `--user "$(id -u):$(id -g)"` and the chown-back the launchers use to
#     keep root-owned files off a Linux host have nothing to fix, and Cygwin's
#     uid (197609 and up) is a user no image has. HOST_USER_ARGS is empty.
#   * MSYS AND GIT BASH REWRITE ARGUMENTS that look like paths before a native
#     program sees them, so `-w /usr/src/sts` reached docker as
#     `-w C:/Program Files/Git/usr/src/sts`. Both switches that turn that off
#     are exported; Cygwin, which never rewrites, ignores them. Git Bash is
#     not the target (#512 is Cygwin), but the detection below matches it as
#     clean.sh's always did, and without these it would be wrong silently.
#
# NOT ADDRESSED, AND SAID SO: freeSubnet() in compose.sh consults `ip route`
# for host routes that would collide with a docker network, and Cygwin has no
# `ip`. On Docker Desktop the networks live inside its own VM, where the
# Windows routing table is not the one that decides, so the scan of docker's
# own networks is the whole of the check there.
# ---------------------------------------------------------------------------

case "$(uname -s)" in
  CYGWIN*|MINGW*|MSYS*)
    HOST_WINDOWS=1
    ;;
  *)
    HOST_WINDOWS=0
    ;;
esac

# The directory this file is in, so the shims are found from any caller's cwd.
HOST_PLATFORM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${HOST_WINDOWS}" = "1" ];
then
  # Once only: a launcher that sources this and then runs another that does
  # the same would otherwise grow PATH by one entry per level.
  case ":${PATH}:" in
    *":${HOST_PLATFORM_DIR}/windows:"*)
      ;;
    *)
      PATH="${HOST_PLATFORM_DIR}/windows:${PATH}"
      ;;
  esac
  export PATH
  export MSYS_NO_PATHCONV=1
  export MSYS2_ARG_CONV_EXCL='*'
  HOST_USER_ARGS=()
else
  HOST_USER_ARGS=(--user "$(id -u):$(id -g)")
fi

# A path as a native Windows program reads it, or the path itself on Linux. A
# relative path stays relative (with forward slashes), which is what a
# program started from this shell's cwd wants.
hostPath()
{
  if [ "${HOST_WINDOWS}" = "1" ];
  then
    cygpath -m -- "$1"
    return $?
  fi
  printf '%s\n' "$1"
  return 0
}

# Open a file in whatever this desktop opens it with. Best effort, as every
# caller treats it: a headless machine has no opener and says nothing.
hostOpen()
{
  if [ "${HOST_WINDOWS}" = "1" ];
  then
    if command -v cygstart > /dev/null 2>&1;
    then
      cygstart "$1"
      return $?
    fi
    cmd.exe /d /c start "" "$(cygpath -w -- "$1")"
    return $?
  fi
  xdg-open "$1"
  return $?
}
