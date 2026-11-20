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
#   .github/scripts/runner-host.sh harden-memory
#   .github/scripts/runner-host.sh sample <log-file>     (in the background)
#   .github/scripts/runner-host.sh pulse                 (in the background)
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
# test-report artifact, so the next one can. Since the same day it also
# writes each container's memory and CPU (`docker stats`, one line a
# container: name, memory used / limit, CPU %). That was every tenth snapshot
# until 2026-11-18, and five minutes could not say which container a
# job's window belonged to: the fuzz and cluster starvation of runs #468 and
# 44070289883 had to be matched to the service, postgres or the runner's own
# processes from a handful of samples. It is every snapshot now. It costs one
# `docker stats --no-stream` a snapshot (about two seconds, bounded at
# twenty), and the lines are the format they always were.
#
# `harden-memory` (2026-11-14, run 43622250478) is for the fifth loss: the
# `cluster` runner stopped reporting 105 minutes in, in the middle of
# sts_tlsfuzzer, and was cancelled at its timeout with no later step run, so
# neither its log nor its report says why. The single-node runner beside it
# had 10 of its 16 GB in use at the same point with one node; the cluster
# runs two. It adds an 8 GB swap file to the runner's 3 GB, so a peak spills
# rather than starving the machine, stops systemd-oomd where the image runs
# it (it kills a whole cgroup on memory pressure, and the runner's is one),
# and sets oom_score_adj to -1000 on the runner's own processes, so that if
# the kernel must kill something it kills a container's process — which the
# request pool replaces, and the job's verdict names — and not the agent
# that reports the verdict. It shrinks nothing in the mode (modes.sh,
# rcbj's decision on the cluster mode: memory biting is a finding).
#
# `pulse` prints one line every two minutes to the job's own log: memory,
# swap and load. The sampler's file reaches the artifact only if the runner
# lives to upload it; the job log keeps what was streamed before it died.
#
# Shell, not a marketplace action:
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
      timeout 20 docker stats --no-stream \
        --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}}' 2> /dev/null
    } >> "${out}" 2>&1
    sleep 30
  done
}

hardenMemory()
{
  echo "Entering hardenMemory()."
  local pid
  free -m
  if sudo fallocate -l 8G /extra-swapfile &&
     sudo chmod 600 /extra-swapfile &&
     sudo mkswap /extra-swapfile > /dev/null &&
     sudo swapon /extra-swapfile;
  then
    echo "An 8 GB swap file is on."
  else
    echo "::warning::the extra swap file could not be added; the runner has" \
         "only its own swap."
  fi
  if systemctl is-active --quiet systemd-oomd 2> /dev/null;
  then
    sudo systemctl stop systemd-oomd || true
    echo "systemd-oomd stopped."
  fi
  local runner='Runner\.(Listener|Worker)|provjobd|hosted-compute-agent'
  for pid in $(pgrep -f "${runner}");
  do
    echo -1000 | sudo tee "/proc/${pid}/oom_score_adj" > /dev/null || true
  done
  free -m
  echo "Leaving hardenMemory()."
}

# It never returns either, for sampleResources()'s reason.
pulse()
{
  echo "Entering pulse()."
  while :;
  do
    sleep 120
    echo "[runner $(date -u +%H:%M:%SZ)]" \
         "$(free -m | awk '/^Mem:/ { print "mem used " $3 "M avail " $7 "M" }
                           /^Swap:/ { print "swap used " $3 "M" }' |
            paste -sd ' ')" \
         "load $(cut -d ' ' -f 1-3 /proc/loadavg)"
  done
}

case "${1:-}" in
  free-disk)     freeDisk ;;
  harden-memory) hardenMemory ;;
  sample)        sampleResources \
                   "${2:?usage: runner-host.sh sample <log-file>}" ;;
  pulse)         pulse ;;
  *)             echo "usage: runner-host.sh free-disk | harden-memory |" \
                      "sample <log-file> | pulse" >&2
                 exit 2 ;;
esac
