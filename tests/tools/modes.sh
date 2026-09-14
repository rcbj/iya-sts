# shellcheck shell=bash
# ===========================================================================
# tests/tools/modes.sh — THE THREE CONFIGURATIONS THE SUITE IS RUN IN.
#
# `./local-run-tests.sh` and `./docker-run-tests.sh` both run the whole suite
# once per mode, and this file is the ONE place the modes are defined. Two
# copies would be two answers to "what does a green run cover", and the two
# launchers would drift apart in exactly the way that matters: the one CI runs
# would stop testing something the developer's one still did, or the reverse,
# and nothing would say so.
#
# ---------------------------------------------------------------------------
# WHY THREE, AND WHY THEY ARE NOT INTERCHANGEABLE.
#
# They differ in what SHARES state between the parts of this service, and each
# one can be green while another is red — which was not a hypothesis. On
# 2026-09-07 `sts_admin_api_operations` passed in `memory` and failed in
# `postgres`, with dispatching off in both; a suite that ran only the first
# would have called that build good.
#
#   memory    THE BASELINE, and what this suite has always run. One process,
#             nothing persisted, nothing coordinated. It is first because it is
#             the configuration every other one is a departure from, and a
#             failure here is a failure in the service rather than in anything
#             about how it was deployed.
#
#   postgres  PERSISTED AND COORDINATING, still one process. This is where a
#             write goes through the change log and comes back, so it is the
#             mode that exercises `persistence_replication.js` against every
#             protocol rather than against `tests/replication.js`'s stubs. A
#             failure here and a pass in `memory` is a persistence defect.
#
#   dispatch  THE SAME, PLUS REQUEST WORKERS. The front process proxies and N
#             children run the handlers, so this is the only mode in which the
#             routing, the affinity, the certificate forwarding and the read
#             barrier are exercised by real protocol traffic at all. A failure
#             here and a pass in `postgres` is a dispatch defect — and that
#             distinction is the whole reason the three are separate runs
#             rather than one run with more turned on.
#
# ---------------------------------------------------------------------------
# THE ORDER IS DELIBERATE: cheapest and most fundamental first, so that a break
# in the service itself is reported before twenty minutes of the two modes that
# would fail for the same reason and say something more complicated about it.
# ===========================================================================

# The mode names, in the order they run.
STS_ALL_MODES=(memory postgres dispatch)

# ---------------------------------------------------------------------------
# The environment each mode adds to the stack, one `NAME=value` per line.
#
# EVERY MODE NAMES EVERY VARIABLE IT CARES ABOUT, including the ones it wants
# OFF. Leaving a variable unset to mean "off" works exactly until a launcher
# runs two modes in one shell, at which point the second inherits the first —
# so `dispatch` would leak into a later `memory` run and the report would say a
# mode had passed that never ran. Naming them all is what makes the modes
# independent of the order they happen to run in.
#
# THERE ARE TWO SOURCES OF A DEFAULT AND THIS RULE WAS WRITTEN ABOUT ONE OF
# THEM, WHICH COST A WHOLE RUN ON 2026-09-08. An unnamed variable does not fall
# back to "off": it falls back to whatever `docker-compose.yml` says, and that
# file is not this suite's. On that day it started defaulting `STS_MODE` to
# `product` — deliberately, so that the stack somebody runs by hand is the
# hardened one — and `memory` mode, which had never mentioned `STS_MODE`
# because there had only ever been one, inherited it. Product mode requires a
# persistence store, memory mode is the absence of one, and the service refused
# to start: the launcher reported that nothing had been checked, which is the
# right report and is three modes' worth of run time after the mistake.
#
# So the rule is not "name what the other modes set". It is NAME WHAT THE STACK
# COULD OTHERWISE DECIDE FOR YOU, and `STS_MODE` is now the fourth such
# variable.
#
# `STS_DATABASE_URL` is deliberately NOT here: docker-compose.yml has the
# in-network default and the launchers do not override it. A mode that named it
# would be a second place that has to know the compose network's hostname.
# ---------------------------------------------------------------------------
stsModeEnv()
{
  case "$1" in
    memory)
      # `STS_MODE=development` IS NOT OPTIONAL HERE and is not merely this
      # mode's preference: product mode requires a persistence store and this
      # mode is defined by not having one. Compose defaults it to `product`, so
      # leaving this line out is a service that does not start at all.
      cat <<'EOF'
STS_MODE=development
STS_PERSISTENCE_MODE=memory
STS_PERSISTENCE_COORDINATE=false
STS_WORKERS_REQUEST_COUNT=0
STS_WORKERS_SURFACE_COUNT=0
STS_WORKERS_DISPATCH=
STS_WORKERS_READ_YOUR_WRITE=false
STS_KEYS_SOURCE=generated
EOF
      ;;
    postgres)
      # DEVELOPMENT MODE, THOUGH THIS ONE HAS A STORE AND COULD RUN THE OTHER —
      # and that is a decision about what this suite IS rather than an omission.
      # Product mode makes every surface that used to decide for itself whether
      # a credential was required ask `common/mode.js` instead, and the answer
      # is yes: passwords are checked, activation is required, the permissive
      # mock stops being permissive. Nearly every protocol job here signs
      # somebody in under a name it invented with no password, because that is
      # what a mock identity service is for. A `product` protocol mode would
      # therefore fail by design and teach nobody anything.
      #
      # PRODUCT MODE IS COVERED, AND IN PROCESS: `tests/keystore.js` and
      # `tests/minted_persistence.js` flip `global.mode` directly and assert the
      # things that actually differ — a signing key that survives a restart,
      # minted rows sealed under the KEK. That is the right place for it. What
      # is NOT covered by any protocol job is the shipped default stack, and
      # this comment is where a reader should learn that rather than infer it.
      cat <<'EOF'
STS_MODE=development
STS_PERSISTENCE_MODE=postgres
STS_PERSISTENCE_COORDINATE=true
STS_WORKERS_REQUEST_COUNT=0
STS_WORKERS_SURFACE_COUNT=0
STS_WORKERS_DISPATCH=
STS_WORKERS_READ_YOUR_WRITE=false
STS_KEYS_SOURCE=generated
EOF
      ;;
    dispatch)
      # THREE WORKERS rather than one, because one worker cannot show a routing
      # mistake: every request lands on it whatever the affinity says. Three is
      # the smallest number where "the wrong worker answered" is a state the
      # suite can actually reach.
      #
      # READ-YOUR-WRITE IS ON HERE AND NOWHERE ELSE. The suite is full of
      # write-then-read-it-back assertions made by cookie-less API clients,
      # which spread across workers by design — without the barrier those are
      # racing the change log, and a suite that raced would fail intermittently
      # and teach nobody anything.
      #
      # AND THE SECRET STORE IS READ HERE (2026-09-12), which is the third axis
      # this mode carries. `STS_KEYS_SOURCE=persisted` turns the keystore ON
      # WITHOUT product mode — `tests/keystore.js` records that as the reason
      # the setting exists — so the key-encryption key is really fetched, from
      # the OpenBao container the stack brings up, with the client certificate
      # that store issued and a policy that lets it read and not write.
      #
      # The DATABASE PASSWORD comes out of that store in every mode, because
      # the compose file's connection string no longer carries one at all. What
      # is particular to this mode is the KEK, which needs a keystore to be on
      # before anything reads it.
      #
      # AND THE CONSOLE AND THE PORTAL ON A POOL OF THEIR OWN (2026-09-13),
      # which is a fourth axis: `STS_WORKERS_SURFACE_COUNT=1`. ONE worker and
      # not three, and the argument above for three does not carry over. What
      # a second pool can get WRONG is the crossing — a console sign-in minted
      # in a protocol worker and read in a surface worker, and the OIDC back
      # channel reaching the protocol worker that holds the code — and one
      # surface worker is enough to cross on every sign-in. Choosing among
      # several workers WITHIN a pool is the same code the three protocol
      # workers already exercise, and every extra worker is a whole copy of the
      # service in a mode that has been killed for memory before.
      cat <<'EOF'
STS_MODE=development
STS_PERSISTENCE_MODE=postgres
STS_PERSISTENCE_COORDINATE=true
STS_WORKERS_REQUEST_COUNT=3
STS_WORKERS_SURFACE_COUNT=1
STS_WORKERS_DISPATCH=*
STS_WORKERS_READ_YOUR_WRITE=true
STS_KEYS_SOURCE=persisted
EOF
      ;;
    *)
      echo "modes.sh: there is no \"$1\" mode. There are: ${STS_ALL_MODES[*]}." >&2
      return 1
      ;;
  esac
}

# One line about a mode, for the launcher's own output. Kept beside the
# definitions so that a mode added here cannot be added without a sentence
# saying what it is for.
stsModeDescription()
{
  case "$1" in
    memory)   echo "one process, nothing persisted, nothing coordinated — the baseline" ;;
    postgres) echo "one process, persisted and coordinating through the change log" ;;
    dispatch) echo "3 request workers + 1 for the console and portal, every path dispatched, read-your-write on" ;;
    *)        echo "unknown" ;;
  esac
}

# Whether a mode needs the database container. `memory` does not, and bringing
# postgres up for it would be starting a dependency the mode exists to be
# without — which is also how the compose stack is told to skip it.
stsModeNeedsPostgres()
{
  case "$1" in
    memory) return 1 ;;
    *)      return 0 ;;
  esac
}
