# ===========================================================================
# THE REMOTE XACML POLICY ENFORCEMENT POINT (phase five).
#
# **THE BUILD CONTEXT IS THE REPOSITORY ROOT, NOT THIS DIRECTORY**, and that
# is the whole reason this file is worth reading. The seven engine modules are
# copied out of `xacml/` at BUILD time, so there is exactly one copy of the
# XACML evaluator in this tree and this image cannot drift from it.
#
#   docker build -f xacml-pep/Dockerfile -t rcbj/xacml-pep .
#
# `docker-compose.yml` sets `context: .` and `dockerfile: xacml-pep/Dockerfile`
# for the same reason. Building from inside this directory fails on the first
# COPY, which is the right way for it to fail: the alternative would be an
# image containing a stale, checked-in copy of the engine.
#
# ---------------------------------------------------------------------------
# WHY NOT A CHECKED-IN COPY, AND WHY NOT A PACKAGE.
#
# `engine.js`'s header argues both at length. In short: a checked-in copy is
# not like `common/vendored/`, because those are another repository's files and
# the drift is between two projects — these would be copies of files in the
# same tree, edited in the same commits, stale the first time somebody fixed a
# combining algorithm. And an npm package would put a release step between
# editing a function and watching the PEP decide differently, which is the loop
# this whole repository is arranged around.
#
# ---------------------------------------------------------------------------
# THE SEVEN MODULES ARE NAMED INDIVIDUALLY AND NOT `COPY xacml/ ./xacml/`.
#
# That looks like the fragile choice — a list to forget — and it is the safe
# one here for two reasons. A whole-directory copy would put `xacml.js`,
# `xacml_admin.js` and `xacml_pep_registry.js` in the image, and every one of
# those requires `common/app.js`, `admin-ui/admin.ts` or `common/config.js`;
# they would sit there unloadable, waiting for somebody to require one and get
# a stack trace about express in a container that has no express. And the list
# CANNOT go stale: `tests/xacml_pep.js` parses these COPY lines and asserts
# they name exactly `engine.js`'s `MODULES`, so a module added to the engine
# and not to this file fails the suite naming both.
#
# That is this repository's own version of the standing obligation CLAUDE.md
# records the parent project having for its `sts/` COPY set — enforced here
# rather than written down and remembered.
# ===========================================================================
FROM node:22-alpine

WORKDIR /usr/src/pep

# THE DEPENDENCIES FIRST, so that editing a source file below re-runs neither
# the install nor the download. Two packages: @xmldom/xmldom for the policy
# reader, bunyan for the logger the engine's style rules assume, and nothing
# else — a PEP that had pulled in the mock's dependency set would be evidence
# that the shim below is not doing its job.
COPY xacml-pep/package.json ./package.json
RUN npm install --omit=dev --no-audit --no-fund

# THE ENGINE. Seven modules, in dependency order, matching engine.js's MODULES
# exactly — see the header for what enforces that.
COPY xacml/xacml_model.js ./xacml/
COPY xacml/xacml_datatypes.js ./xacml/
COPY xacml/xacml_functions.js ./xacml/
COPY xacml/xacml_validate.js ./xacml/
COPY xacml/xacml_xml.js ./xacml/
COPY xacml/xacml_pdp.js ./xacml/
COPY xacml/xacml_json.js ./xacml/

# THE SHIM. `xacml-pep/common/helpers.js` is what `../common/helpers` resolves
# to from `/usr/src/pep/xacml/`, and it exports `log` and `xmlEscape` and
# nothing else. An engine module that grew a dependency on the mock's config
# table, crypto module or realm registry does not degrade here — it throws at
# load. That file argues why that is the point of the container rather than an
# inconvenience.
COPY xacml-pep/common/ ./common/

COPY xacml-pep/engine.js ./engine.js
COPY xacml-pep/sync.js ./sync.js
COPY xacml-pep/pip.js ./pip.js
COPY xacml-pep/pep.js ./pep.js

# ---------------------------------------------------------------------------
# THE VERSION. `common/version.js` and the repo-root `VERSION`, copied the way
# the engine is: at BUILD TIME out of the one copy in the tree, so this image
# cannot report a release the mock does not have.
#
# **THEY GO TO THE CONTAINER ROOT AND NOT INTO `./common/`, AND THAT IS THE
# WHOLE OF THE PLACEMENT DECISION.** `./common/` is the shim — one file,
# `helpers.js`, exporting `log` and `xmlEscape` — and what makes it worth
# anything is that an engine module which grew a dependency on the mock's
# config table, crypto module or realm registry THROWS AT LOAD because there is
# nothing else in that directory to resolve. `version.js` reads files and shells
# out to git. Putting it beside the shim would put I/O back into the one
# directory whose emptiness is the evidence, to give a build number to a
# container that would report it just as well from one level up.
#
# `common/version.js` finds its own root by looking for the VERSION file beside
# it, which is why it is correct here as well as in the mock — see findRoot()
# there. `pep.js` resolves it across BOTH layouts (`./version` here,
# `../common/version` in a checkout), the same two-candidate shape the parent
# project's `api/server.js` uses for its copy of this module.
COPY VERSION ./VERSION
COPY common/version.js ./version.js

# THE ERROR-CODE REGISTRY, for the same reasons and to the same place.
# `common/error_codes.js` is the one table of `STS-<SUBSYSTEM>-<NNNN>` codes,
# and every failure this container logs leads with one of its `STS-XPEP-` rows
# — so it is copied out of the tree at BUILD TIME rather than checked in twice.
#
# **TO THE CONTAINER ROOT AND NOT INTO `./common/`, ON `version.js`'S ARGUMENT
# ABOVE.** `./common/` is the shim and exactly one COPY may write into it; a
# registry beside `helpers.js` would be a second file in the one directory
# whose emptiness is the evidence. It requires nothing at module load, so it is
# safe anywhere — which is not the question. `pep.js` resolves it across both
# layouts (`./error_codes` here, `../common/error_codes` in a checkout) and a
# container missing it still starts, with a tagged line saying so.
COPY common/error_codes.js ./error_codes.js

# AND THE STAMP, for the reason the mock's own Dockerfile gives at length: the
# build number is fixed when the artifact is BUILT, so restarting this
# container does not renumber it.
#
# **THE TWO IMAGES GET DIFFERENT BUILD NUMBERS UNLESS BUILD_NUMBER IS PASSED,
# AND THAT IS CORRECT RATHER THAN A DEFECT.** They are two artifacts, built at
# two instants, and they are deployed independently — a PEP left behind across
# a release of the PDP is exactly the state the version on its console row
# exists to make visible. Pass the same BUILD_NUMBER to both to say they are
# one release; the compose files offer it.
ARG BUILD_NUMBER=
ARG GIT_COMMIT=
RUN BUILD_NUMBER="${BUILD_NUMBER}" GIT_COMMIT="${GIT_COMMIT}" \
    node version.js --stamp . && cat version.json

EXPOSE 9090
# The HTTPS listener (2026-09-13). It binds only once a certificate and key
# are readable where PEP_HTTPS_CERT and PEP_HTTPS_KEY point — the pair the
# PEP's realm issues it, written after the PEP has registered — so a container
# with no pair exposes a port nothing answers on, and says why on GET /.
EXPOSE 9443

# LIVENESS ONLY, AND IT DOES NOT ASK WHETHER THE POLICY IS CURRENT — `pep.js`
# argues that where the endpoint is: a PEP holding a stale copy is working, and
# a healthcheck that failed on staleness would turn a PDP outage into a restart
# loop, which is an outage of its own.
#
# `node -e` rather than curl, the same probe shape the mock's own compose file
# uses and for the same reason: it depends on nothing but the runtime the
# service already needs, and it fails on a non-200 rather than merely on a
# closed port.
HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=10s \
  CMD node -e "require('http').get({host:'localhost',port:process.env.PEP_PORT||9090,path:'/healthcheck'},function(r){process.exit(r.statusCode===200?0:1)}).on('error',function(){process.exit(1)})"

CMD ["node", "pep.js"]
