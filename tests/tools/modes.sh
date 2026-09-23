# shellcheck shell=bash
# ===========================================================================
# tests/tools/modes.sh — THE CONFIGURATIONS THE SUITE IS RUN IN: THREE, AND A
# BARE `./run-tests.sh` RUNS ALL OF THEM (2026-09-21).
#
# `./run-tests.sh` runs the whole suite once per mode, and this file is
# the ONE place the modes are defined. It was written when
# `./local-run-tests.sh` did the same (it was removed on 2026-09-16): two
# copies would have been two answers to "what does a green run cover", and the
# two launchers would have drifted apart in exactly the way that matters — the
# one CI runs would stop testing something the developer's one still did, or
# the reverse, and nothing would say so. It stays a file of its own so that a
# second launcher, if one comes back, reads the same definition.
#
# ---------------------------------------------------------------------------
# WHY THESE THREE (2026-09-21), AND WHAT THEY REPLACED.
#
# Until that day there were `memory`, `postgres` (then `product`) and
# `dispatch` by default and `cluster` on request, each adding ONE axis — the
# store, product mode, request workers, a second node — so a mode red where
# the one before it was green named the axis at fault. rcbj replaced them with
# the two ways this service is actually DEPLOYED, beside the baseline:
#
#   memory       THE BASELINE. One process, development mode, nothing
#                persisted, nothing coordinated. A failure here is a failure
#                in the service rather than in anything about how it was
#                deployed, and it is first so that is reported before the
#                heavier modes fail for the same reason in more words.
#
#   single-node  A SINGLE-NODE PRODUCTION DEPLOYMENT: `global.mode=product`,
#                postgres, coordinating, the keystore under OpenBao's KEK, and
#                request workers — three protocol workers and one for the
#                console and portal, every path dispatched, read-your-write on.
#                It is `product` and `dispatch` MERGED, because product mode
#                with workers is how a node is run, and bugs that need both at
#                once (a derivation racing a clear across workers) were
#                reachable only on AWS.
#
#   cluster      A MULTI-NODE PRODUCTION DEPLOYMENT: two such nodes —
#                product, postgres, workers on BOTH — active-active behind an
#                HAProxy in TCP mode with PROXY protocol v2, on one postgres
#                and one OpenBao. A separate mode rather than a flag on
#                `single-node`, because single-node and multi-node differ in
#                too many ways to read one run's failure: what one node holds
#                that the other cannot see, two nodes deciding one thing twice,
#                a balancer between the client and the service.
#
# **WHAT THE MERGE COSTS, SAID SO NOBODY REDISCOVERS IT.** A failure in
# `single-node` and not in `memory` can be the store, product mode or the
# workers, and the job's own log has to say which — the old three-mode split
# answered that by construction. A failure in `cluster` and not in
# `single-node` is still a CROSS-NODE defect, which is the comparison worth
# keeping and why the two production modes are separate.
#
# **AND THE COST IN TIME.** `cluster` is a whole run on two nodes of five
# processes each, the heaviest stack this suite starts. CI runs it as a job
# of its own (`.github/workflows/tests.yml`) beside `memory,single-node`,
# both through `./run-tests.sh`, so each job's timeout still covers the modes
# it runs (tests/teardown_bounds.js holds that arithmetic).
#
# ---------------------------------------------------------------------------
# THE ORDER IS DELIBERATE: cheapest and most fundamental first.
# ===========================================================================

# The mode names a bare run runs, in the order they run.
STS_ALL_MODES=(memory single-node cluster)


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
# COULD OTHERWISE DECIDE FOR YOU. `STS_MODE` was the fourth such variable, and
# every arm below now names twelve.
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
STS_CLUSTER_MODE=off
STS_PROXY_PROTOCOL=off
STS_TEST_FRESH_CONNECTIONS=0
STS_TEST_CLUSTER_NODES=1
EOF
      ;;
    single-node)
      # A SINGLE-NODE PRODUCTION DEPLOYMENT (2026-09-21) — see the header.
      #
      # `STS_MODE=product` REACHES THE SERVICE ONLY BECAUSE
      # docker-compose-run-tests.yml FORWARDS IT, which it did not until the
      # day `product` became a mode: the `development` every arm had named was
      # a no-op that matched the setting's default. The launcher adds what a
      # product node is GIVEN — the pinned base URL and generated Kerberos
      # passwords — for any mode whose STS_MODE is product (run-tests.sh,
      # "THE `product` MODE" block).
      #
      # THREE PROTOCOL WORKERS rather than one, because one worker cannot show
      # a routing mistake: every request lands on it whatever the affinity
      # says. ONE surface worker for the console and portal, because what a
      # second pool can get wrong is the CROSSING — a console sign-in minted in
      # a protocol worker and read in a surface worker — and one is enough to
      # cross on every sign-in. READ-YOUR-WRITE ON, because the suite is full
      # of write-then-read-it-back assertions by cookie-less API clients that
      # spread across workers by design.
      #
      # THE KEYSTORE UNDER OPENBAO'S KEK (`persisted`), which product mode
      # requires anyway. CLUSTER OFF, explicitly: product mode on postgres
      # otherwise defaults `auto` to active-passive, which is `cluster`'s axis
      # and not this one's. PROXY PROTOCOL OFF: there is no balancer.
      cat <<'EOF'
STS_MODE=product
STS_PERSISTENCE_MODE=postgres
STS_PERSISTENCE_COORDINATE=true
STS_WORKERS_REQUEST_COUNT=3
STS_WORKERS_SURFACE_COUNT=1
STS_WORKERS_DISPATCH=*
STS_WORKERS_READ_YOUR_WRITE=true
STS_KEYS_SOURCE=persisted
STS_CLUSTER_MODE=off
STS_PROXY_PROTOCOL=off
STS_TEST_FRESH_CONNECTIONS=0
STS_TEST_CLUSTER_NODES=1
EOF
      ;;
    cluster)
      # A MULTI-NODE PRODUCTION DEPLOYMENT (2026-09-14, #46; product mode and
      # workers since 2026-09-21). The stack is
      # tests/docker-compose-run-tests-cluster.yml layered over the mode's
      # usual one; what follows is what each NODE is, and both are given
      # exactly the same — `sts2` extends `sts`, so every value here, and the
      # launcher's generated product values, reach both.
      #
      # PRODUCT MODE AND WORKERS ON BOTH NODES, BY rcbj's DECISION. It was
      # development mode with one process per node until that day, to keep
      # the cluster the one axis it added, and because two nodes of four
      # processes each had been killed for memory on the machine that runs
      # this. The mode is a production deployment now; if memory bites again,
      # that is a finding about the machine or the service, not a reason to
      # shrink the mode back.
      #
      # `active-active` named rather than left to `cluster.mode=auto`, which
      # in product on postgres is active-passive. THE KEY-ENCRYPTION KEY FROM
      # OPENBAO is not optional here: active-active refuses to start without
      # an operator key-encryption key (STS-CLUSTER-0008).
      #
      # PROXY PROTOCOL v2 ON, as behind the NLB this imitates: the balancer
      # sends a header naming the real peer and both nodes require it from the
      # balancer's address, which the launcher names as the one trusted proxy
      # (STS_TRUSTED_PROXIES, an address it pins). A launcher run with
      # STS_TEST_CLUSTER_PROXY_PROTOCOL=off turns it off for both halves, to
      # tell a PROXY-protocol failure from a cluster one.
      #
      # NOTHING IS ACCEPTED AS MISSING: no STS_CLUSTER_ACCEPT_MISSING_CAPABILITIES.
      # The gate must pass on its own, and a node that refuses is a finding.
      #
      # THE TWO `STS_TEST_*` NAMES ARE THE RUNNER'S, not the service's:
      # a new connection per request (tools/fresh-connections.js), and how many
      # nodes `sts_cluster_alternation.js` must see answer.
      cat <<'EOF'
STS_MODE=product
STS_PERSISTENCE_MODE=postgres
STS_PERSISTENCE_COORDINATE=true
STS_WORKERS_REQUEST_COUNT=3
STS_WORKERS_SURFACE_COUNT=1
STS_WORKERS_DISPATCH=*
STS_WORKERS_READ_YOUR_WRITE=true
STS_KEYS_SOURCE=persisted
STS_CLUSTER_MODE=active-active
STS_PROXY_PROTOCOL=v2
STS_TEST_FRESH_CONNECTIONS=1
STS_TEST_CLUSTER_NODES=2
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
    single-node) echo "a single-node production deployment: product mode, postgres, 3 request workers + 1 surface worker, read-your-write" ;;
    cluster)  echo "a multi-node production deployment: 2 such nodes active-active on one postgres, behind an L4 load balancer, a new connection per request" ;;
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

# ---------------------------------------------------------------------------
# How long the launcher lets a mode run before it stops the stack
# (STS_MODE_TIMEOUT, run-tests.sh), in seconds, per mode (2026-09-21).
#
# `cluster` has a bound of its own because a write there is two production
# nodes coordinating through one postgres, and the three bulk loads are 15,000
# of them: on 2026-09-21 the SCIM load alone took 22 minutes, and the mode was
# stopped at job 289 of 290 by the 50-minute bound every mode shared, with
# nothing failing. 100 minutes is that run's pace (about 80) with room;
# STS_CLUSTER_MODE_TIMEOUT overrides it, as STS_MODE_TIMEOUT does the others.
# The CI cluster job's own timeout is held above it by tests/teardown_bounds.js.
# ---------------------------------------------------------------------------
stsModeTimeout()
{
  case "$1" in
    cluster) echo "${STS_CLUSTER_MODE_TIMEOUT:-6000}" ;;
    *)       echo "${STS_BASE_MODE_TIMEOUT:-3000}" ;;
  esac
}

# ---------------------------------------------------------------------------
# Whether a mode is the TWO-NODE stack (2026-09-14). Asked by both launchers
# at every place the answer changes what they do — which compose files are
# layered, which containers come up and are logged, and which address the
# runner and the jobs are handed (the balancer's rather than a node's). One
# question here rather than `[ "${MODE}" = cluster ]` in a dozen places, so a
# second multi-node mode is one line.
# ---------------------------------------------------------------------------
stsModeIsCluster()
{
  case "$1" in
    cluster) return 0 ;;
    *)       return 1 ;;
  esac
}
