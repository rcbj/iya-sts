#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# bulk-import.sh — load people into 8081 with the offline bulk import (#629),
# one LDIF file at a time, generating the next file while the current one
# imports and deleting each file once it is in.
#
#   ./bulk-import.sh FROM TO [PER_FILE] [BATCH]
#   e.g. ./bulk-import.sh 10000001 50000000            # 40 files of 1M
#
# Names continue the LDAP loader's: uid=load-26cb84b3-<n>.
# THE SERVICE MUST BE STOPPED (docker compose stop sts); the import refuses
# while any process reported into the change log in the last 60 seconds.
# Each file runs in the service's own image and environment through
# `docker compose run`, after `openbao-seed` hands out a fresh single-use
# start-up token, so the people are sealed under the same OpenBao Transit key
# as everything else. Progress and rates go to bulk-import.log; each file's
# JSON report is kept as ldif/people-<n>.report.json.
# Stop it between files with: touch ldif/STOP
set -uo pipefail
LU=$(cd "$(dirname "$0")" && pwd)
IY=$(cd "$LU/.." && pwd)
D=${LDIF_DIR:-$LU/ldif}
LOG=$LU/bulk-import.log
# hostPath() and the docker shim under Cygwin, nothing on Linux (#512).
. "$IY/tests/tools/host-platform.sh"
FROM=${1:?FROM}
TO=${2:?TO}
PER=${3:-1000000}
BATCH=${4:-5000}
STAMP=${STAMP:-26cb84b3}

say() { echo "$(date -u +%FT%TZ) $*" | tee -a "$LOG"; }

mkdir -p "$D" && chmod 777 "$D"
cd "$IY" || exit 1

if docker ps --format '{{.Names}}' | grep -qx sts; then
  say "REFUSED: the sts container is running; stop it first"
  exit 2
fi

# The directory's ceiling, read as an add reads it (STS-LDAP-0157): well
# above 200M so no import stops on it.
docker exec sts-postgres psql -U sts -d sts -v ON_ERROR_STOP=1 -qc \
  "UPDATE sts.sts_appconfig SET value='{\"raw\": 250000000}'
   WHERE key='ldap.maxEntries'" || { say "could not raise ldap.maxEntries"; exit 1; }

gen() { # gen START COUNT
  node "$(hostPath "$IY/tests/tools/generate-people-ldif.js")" --count="$2" \
    --start="$1" --stamp=$STAMP --out="$(hostPath "$D/people-$1.ldif.part")" \
    >/dev/null &&
  mv "$D/people-$1.ldif.part" "$D/people-$1.ldif"
}

count_for() { local c=$PER; [ $(( $1 + c - 1 )) -gt "$TO" ] && c=$(( TO - $1 + 1 )); echo $c; }

say "bulk import $FROM..$TO, $PER per file, batch $BATCH"
n=$FROM
gen "$n" "$(count_for "$n")" || { say "generate failed for $n"; exit 1; }
total_start=$(date +%s)
imported_total=0
while [ "$n" -le "$TO" ]; do
  [ -e "$D/STOP" ] && { say "STOP file found; stopping before $n"; exit 0; }
  cnt=$(count_for "$n")
  next=$(( n + cnt ))
  gpid=""
  if [ "$next" -le "$TO" ]; then gen "$next" "$(count_for "$next")" & gpid=$!; fi

  docker compose up --no-deps openbao-seed >/dev/null 2>&1 ||
    { say "openbao-seed failed before $n"; exit 1; }
  t0=$(date +%s)
  docker compose run --rm --no-deps -T -v "$(hostPath "$D"):/import" sts sh -c \
    'STARTUP="$(node openbao/startup-secrets.js)" || exit 1; eval "$STARTUP";
     exec setpriv --reuid=10001 --regid=10001 --clear-groups --inh-caps=-all \
       --bounding-set=-all --no-new-privs node persistence/bulk_import.js \
       --file=/import/people-'"$n"'.ldif --batch='"$BATCH"' \
       --report=/import/people-'"$n"'.report.json' \
    >> "$LU/bulk-import.out" 2>&1
  rc=$?
  t1=$(date +%s)
  secs=$(( t1 - t0 )); [ "$secs" -lt 1 ] && secs=1
  summary=$(node -e 'try{const r=require(process.argv[1]);console.log(JSON.stringify({imported:r.imported,present:r.present,taken:r.taken,refusals:r.refusals,stopped:r.stopped}))}catch(e){console.log("no report")}' "$(hostPath "$D/people-$n.report.json")")
  say "file $n (+$cnt): exit $rc in ${secs}s = $(( cnt / secs ))/s $summary"
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
    say "STOPPED: import of $n exited $rc; see bulk-import.out (resume with FROM=$n, or --skip)"
    [ -n "$gpid" ] && wait "$gpid"
    exit 1
  fi
  rm -f "$D/people-$n.ldif"
  imported_total=$(( imported_total + cnt ))
  [ -n "$gpid" ] && { wait "$gpid" || { say "generate failed for $next"; exit 1; }; }
  n=$next
done
el=$(( $(date +%s) - total_start ))
say "DONE $FROM..$TO: $imported_total records in ${el}s = $(( imported_total / (el>0?el:1) ))/s"
