#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: .github/scripts/runner-host.sh
#
# ---------------------------------------------------------------------------
# WHAT EVERY tests.yml JOB THAT HOLDS A STACK DOES TO ITS RUNNER FIRST
# (2026-11-14).
#
#   .github/scripts/runner-host.sh free-disk
#   .github/scripts/runner-host.sh sample <log-file>     (in the background)
#
# A hosted runner is 4 vCPU, 16 GB and about 14 GB of free disk. The tests
# image alone is 7.8 GB, and an `openid-conformance` job died on `No space
# left on device` during its build (run 41665262618). `free-disk` removes
# the toolchains this workflow never uses (.NET, Android, GHC, CodeQL) and
# every image the runner came with, which gives back about 25-30 GB.
#
# `sample` writes the time, memory, disk and a vmstat line every thirty
# seconds until the job ends. Four `cluster` runs were lost with "the hosted
# runner lost communication with the server", and nothing in their logs could
# say whether the disk or the memory ran out; the file goes into the job's
# test-report artifact, so the next one can. Shell, not a marketplace action:
# the repository allows GitHub's own actions and three named others only.
# ---------------------------------------------------------------------------
set -uo pipefail

freeDisk()
{
  echo "Entering freeDisk()."
  df -h /
  sudo rm -rf /usr/share/dotnet /usr/local/lib/android /opt/ghc \
              /opt/hostedtoolcache/CodeQL
  docker system prune -af --volumes > /dev/null
  df -h /
  echo "Leaving freeDisk()."
}

# It never returns, so it has no Leaving line: the runner kills it with the
# job's other orphaned processes when the job ends.
sampleResources()
{
  echo "Entering sampleResources()."
  local out="$1"
  mkdir -p "$(dirname "${out}")"
  while :;
  do
    {
      echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      free -m
      df -h / /var/lib/docker 2> /dev/null
      vmstat 1 2 | tail -1
    } >> "${out}" 2>&1
    sleep 30
  done
}

case "${1:-}" in
  free-disk) freeDisk ;;
  sample)    sampleResources "${2:?usage: runner-host.sh sample <log-file>}" ;;
  *)         echo "usage: runner-host.sh free-disk | sample <log-file>" >&2
             exit 2 ;;
esac
