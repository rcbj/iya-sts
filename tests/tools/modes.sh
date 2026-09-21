# shellcheck shell=bash
# ===========================================================================
# tests/tools/modes.sh — THE CONFIGURATIONS THE SUITE IS RUN IN: THREE BY
# DEFAULT, AND A FOURTH (`cluster`) ON REQUEST.
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
#   product   THE SHIPPED CONFIGURATION: `global.mode=product`, PERSISTED AND
#             COORDINATING, still one process (2026-09-21 — it replaced the
#             `postgres` mode, which was this minus product mode). Passwords
#             are checked, nothing is seeded, an unregistered client or
#             address is refused, the keystore is sealed under OpenBao's KEK,
#             and every write goes through the change log and comes back —
#             so it exercises `persistence_replication.js` against every
#             protocol AND the hardened service, which until this mode no
#             protocol job saw outside AWS.
#
#             **IT WAS REFUSED HERE UNTIL 2026-09-21, AND THE REASON STOPPED
#             BEING TRUE.** The `postgres` arm said a product protocol mode
#             "would fail by design and teach nobody anything", because the
#             jobs signed people in under invented names with no password.
#             4d172a3 and d37957d (2026-09-18/19) changed the jobs so they run
#             against `testidp`, which is product mode: they ask the service
#             what it is (`tests/vendored/service_facts.js`), register real
#             clients and people with passwords and PKCE, and authenticate to
#             introspection. rcbj then asked for the swap.
#
#             **WHAT THE SWAP COSTS, SAID SO NOBODY REDISCOVERS IT.** `postgres`
#             differed from `memory` in ONE axis, so a failure there and a
#             pass in `memory` was a persistence defect by construction. This
#             mode differs in TWO — the store and the hardening — so the same
#             pair of results now says "persistence OR product mode", and the
#             job's own log has to say which. `dispatch` still runs the store
#             in development mode (with workers on top), which is the closest
#             thing left to the old single-axis comparison.
#
#   dispatch  PERSISTED AND COORDINATING IN DEVELOPMENT MODE, PLUS REQUEST
#             WORKERS. The front process proxies and N children run the
#             handlers, so this is the only mode in which the routing, the
#             affinity, the certificate forwarding and the read barrier are
#             exercised by real protocol traffic at all. A failure here and a
#             pass in `memory` is a dispatch (or persistence) defect; the
#             three are separate runs rather than one run with more turned on
#             so that each red mode names the axis it added.
#
#   cluster   TWO CONTAINERS, ACTIVE-ACTIVE, ON ONE POSTGRES AND ONE OPENBAO
#             (2026-09-14, issue #46), each a single process, behind an HAProxy
#             in TCP mode that owns every port the suite reaches. Every job's
#             client opens a new connection per request, so its requests
#             alternate between the nodes: a write on one and the read-back
#             on the other is the ordinary case rather than a race. A failure
#             here and a pass in `dispatch` is a CLUSTER defect — something a
#             node holds that the other cannot see, or two nodes deciding one
#             thing twice. tests/CLAUDE.md says what it does not cover.
#
#             NOT IN STS_ALL_MODES, and that is a decision about cost rather
#             than about importance: it is a fourth whole run of the suite and
#             two services' worth of memory, and a bare run is already an
#             hour. `--modes=cluster` asks for it; `--modes=memory,product,
#             dispatch,cluster` is everything.
#
# ---------------------------------------------------------------------------
# THE ORDER IS DELIBERATE: cheapest and most fundamental first, so that a break
# in the service itself is reported before twenty minutes of the two modes that
# would fail for the same reason and say something more complicated about it.
# ===========================================================================

# The mode names a bare run runs, in the order they run. `cluster` is defined
# below and is asked for by name — see the header.
STS_ALL_MODES=(memory product dispatch)

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
    product)
      # THE SHIPPED STACK, ONE PROCESS (2026-09-21). See the header for why it
      # replaced `postgres` and what that costs.
      #
      # `STS_MODE=product` REACHES THE SERVICE ONLY BECAUSE
      # docker-compose-run-tests.yml NOW FORWARDS IT. Until this mode existed
      # that file never passed STS_MODE to the container at all, so the
      # `development` every arm named was a no-op that happened to match
      # `global.mode`'s default. Naming `product` here without that line would
      # have run the development service and reported "product: passed".
      #
      # THE KEYSTORE UNDER OPENBAO'S KEK (`persisted`), which product mode
      # requires anyway — named because every arm names what the stack could
      # otherwise decide. Workers OFF, so a failure here and a pass in `memory`
      # is the store or the hardening and never the dispatcher. Cluster OFF
      # explicitly: product mode on postgres otherwise defaults `auto` to
      # active-passive (cluster/CLAUDE.md), which is a different axis.
      cat <<'EOF'
STS_MODE=product
STS_PERSISTENCE_MODE=postgres
STS_PERSISTENCE_COORDINATE=true
STS_WORKERS_REQUEST_COUNT=0
STS_WORKERS_SURFACE_COUNT=0
STS_WORKERS_DISPATCH=
STS_WORKERS_READ_YOUR_WRITE=false
STS_KEYS_SOURCE=persisted
STS_CLUSTER_MODE=off
STS_PROXY_PROTOCOL=off
STS_TEST_FRESH_CONNECTIONS=0
STS_TEST_CLUSTER_NODES=1
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
STS_CLUSTER_MODE=off
STS_PROXY_PROTOCOL=off
STS_TEST_FRESH_CONNECTIONS=0
STS_TEST_CLUSTER_NODES=1
EOF
      ;;
    cluster)
      # TWO NODES, ACTIVE-ACTIVE, BEHIND A LOAD BALANCER (2026-09-14, #46).
      # The stack is tests/docker-compose-cluster.yml (or its containerized
      # twin) layered over the mode's usual one; what follows is what each
      # NODE is, and both are given exactly the same.
      #
      # DEVELOPMENT MODE, and naming `active-active` rather than leaving
      # `cluster.mode=auto` to decide — auto is `off` outside product mode.
      # (It said "for the reason the `postgres` arm gives: the suite signs
      # people in with no password" until 2026-09-21; the `product` mode
      # showed the suite no longer depends on that, and this arm stays in
      # development only to keep the cluster the one axis it adds.)
      #
      # THE KEY-ENCRYPTION KEY FROM OPENBAO (`STS_KEYS_SOURCE=persisted`), as in
      # `dispatch`, and here it is not optional: active-active refuses to start
      # without an operator key-encryption key (STS-CLUSTER-0008), because a
      # key made per container is a different key on every node.
      #
      # REQUEST WORKERS OFF ON BOTH NODES. The axis under test is BETWEEN
      # containers; within one, `dispatch` already covers the workers, and two
      # nodes of four processes each is a stack this machine has been killed
      # for memory running before. So each node is one process, and anything
      # that fails here and passes in `dispatch` — the other development
      # mode on the shared store — is a cross-node defect. (It said
      # `postgres` until that mode was replaced by `product` on 2026-09-21.)
      #
      # PROXY PROTOCOL v2 ON, as behind the NLB this imitates: the balancer
      # sends a header naming the real peer and both nodes require it from the
      # balancer's address, which the launcher names as the one trusted proxy
      # (STS_TRUSTED_PROXIES, an address it pins). `off` in the other three
      # modes, which have no proxy. A launcher run with
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
STS_MODE=development
STS_PERSISTENCE_MODE=postgres
STS_PERSISTENCE_COORDINATE=true
STS_WORKERS_REQUEST_COUNT=0
STS_WORKERS_SURFACE_COUNT=0
STS_WORKERS_DISPATCH=
STS_WORKERS_READ_YOUR_WRITE=false
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
    product)  echo "one process, global.mode=product, persisted and coordinating, keystore under the KEK" ;;
    dispatch) echo "3 request workers + 1 for the console and portal, every path dispatched, read-your-write on" ;;
    cluster)  echo "2 single-process nodes active-active on one postgres, behind an L4 load balancer, a new connection per request" ;;
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
