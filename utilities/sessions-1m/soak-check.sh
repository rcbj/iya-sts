#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# soak-check.sh — one hourly stability reading for the 1M-session soak on 8081
# (rcbj, 2026-10-22). Prints only summaries; never secrets.
cd "$(dirname "$0")"
# HOST_WINDOWS and the docker shim under Cygwin, nothing on Linux (#512).
. ../../tests/tools/host-platform.sh

# Every running process as "pid ... command line". Cygwin's ps has no -o and
# never sees a native node.exe's arguments, so on Windows they come from WMI.
commandLines() {
  if [ "$HOST_WINDOWS" = 1 ]; then
    powershell.exe -NoProfile -Command 'Get-CimInstance Win32_Process |
      ForEach-Object { "$($_.ProcessId) $($_.CommandLine)" }' | tr -d '\r'
  else
    ps -eo pid,etime,rss,args
  fi
}
# --brief: one line, OK or ALERT with the reason; the full reading otherwise.
if [ "$1" = "--brief" ]; then
  why=""
  commandLines | grep -q "[s]essions.js" || why="$why script-not-running;"
  last=$(grep "last 60 s" sessions.log | tail -1)
  age=$(( $(date +%s) - $(date -d "$(echo "$last" | cut -c1-19)" +%s 2>/dev/null || echo 0) ))
  [ "$age" -gt 300 ] && why="$why no-minute-line-for-${age}s;"
  echo "$last" | grep -q "given up 0" || why="$why given-up>0;"
  for c in sts sts-postgres; do
    docker ps --format '{{.Names}} {{.Status}}' | grep -q "^$c Up.*healthy" || why="$why $c-not-healthy;"
  done
  use=$(df --output=pcent / | tail -1 | tr -dc 0-9)
  [ "$use" -ge 95 ] && why="$why disk-${use}%;"
  signed=$(echo "$last" | grep -oE "signed in [0-9]+" | grep -oE "[0-9]+")
  echo "$(date -u +%FT%TZ) ${why:-OK} signed-in=$signed disk=${use}% $(echo "$last" | grep -oE 'failures [^|]*' | cut -c1-80)"
  exit 0
fi
echo "=== $(date -u +%FT%TZ) soak check ==="
echo "-- script process:"
commandLines | grep "[s]essions.js" | cut -c1-80 || echo "NOT RUNNING"
echo "-- last two minute lines:"
grep "last 60 s" sessions.log | tail -2 | cut -c1-330
echo "-- failure lines in the last hour of sessions.log:"
tail -n 4000 sessions.log | grep -iE "error|fail|refused|5[0-9][0-9] " | grep -v "failures 0/0" | tail -5 | cut -c1-250
echo "-- containers:"
docker ps --format '{{.Names}} {{.Status}}' | grep -E "^sts"
for c in sts sts-postgres; do
  echo "$c restarts: $(docker inspect -f '{{.RestartCount}}' $c 2>/dev/null)"
done
echo "-- memory:"
docker stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}}' | grep -E "^sts"
free -g | head -2
echo "-- disk:"
df -h / /var/lib/docker 2>/dev/null | sort -u
echo "-- 8081 warn/error codes in the last hour (count by code):"
docker logs --since 60m sts 2>&1 | grep -E '"level":(40|50|60)' \
  | grep -oE 'STS-[A-Z0-9]+-[0-9]{4}' | sort | uniq -c | sort -rn | head -12
echo "-- sign-in request phases (latest):"
docker logs --since 3m sts 2>&1 | grep "request phases" \
  | grep -E "POST /oauth2/token|POST /authn-api/pending|COMMIT through" \
  | sed 's/.*"msg":"//; s/","time".*//' | tail -3 | cut -c1-230
