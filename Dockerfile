# iya-sts, the mock STS: every protocol family README.md lists, in one small Node
# service. See README.md.
#
# Pinned to Node 24.16.0 via nvm rather than an official node image, which is what
# the project this was extracted from does for all of its services.

# ---------------------------------------------------------------------------
# THE EMBEDDED PROTOCOL DEBUGGER'S BUILT TREE (2026-09-13), TAKEN FROM AN IMAGE
# AND NEVER BUILT HERE.
#
# The debugger project builds its client and api for embedding with
# `embedded/Dockerfile`, into an image whose only content is `/debugger/ui`,
# `/debugger/api` (with its own node_modules) and `/debugger/common`. This
# build copies that tree to `debugger/embedded/` and nothing else, so this
# image's dependency tree and that one's never meet — `debugger/CLAUDE.md`
# argues why that is the whole of the design.
#
# **AN IMAGE AND NOT A SECOND BUILD CONTEXT OR A SUBMODULE.** This machine's
# docker has no BuildKit, so `--build-context` is not available; and this
# repository is already a submodule of the debugger project, so the reverse
# would be a cycle. `COPY --from` an image works with the classic builder.
#
# **DEFAULTS TO A STAGE WITH AN EMPTY TREE**, so a build that names no
# debugger image succeeds exactly as it did before: the listener then reports
# the debugger as not installed on /admin/debugger and the rest of the service
# is unaffected. Pass
#   --build-arg DEBUGGER_IMAGE=rcbj/id-proto-debugger-embedded:<tag>
# to embed one. The indirection through a stage name is what lets the default
# be "nothing" under the classic builder, which cannot make a COPY optional.
# ---------------------------------------------------------------------------
ARG DEBUGGER_IMAGE=debugger-none
FROM ubuntu:latest AS debugger-none
RUN mkdir -p /debugger
FROM ${DEBUGGER_IMAGE} AS debugger

# ---------------------------------------------------------------------------
# THE TYPESCRIPT BUILD (#50, 2026-09-16): COMPILED HERE, SHIPPED WITHOUT ITS
# SOURCE.
#
# rcbj's three rules for the conversion: transpiling happens in a container
# build step, nothing compiled is ever written to the host, and the final image
# carries no `.ts`. So this stage takes the whole context, runs
# `build-typescript.sh --strip` — the type check, then `tsc` emitting each
# `x.js` beside its `x.ts`, then every `.ts`, `types/` and the tsconfig files
# deleted — and the final stage below copies THIS stage's tree where it used to
# copy the context. A layer of the final image therefore never held a `.ts`;
# deleting them in the final stage instead would have left them in an earlier
# layer of it.
#
# **AN OFFICIAL NODE IMAGE, UNLIKE THE FINAL STAGE**, which pins node through
# nvm for the parent project's reason (the header). Nothing from this stage
# runs: it only produces files, `tsc` is a native binary whose output does not
# depend on the node beside it, and the version is still 24.16.0.
#
# The installs are the final stage's (for the types of what the service
# requires) and `tests/package.json`'s (the compiler). Both `node_modules` are
# removed at the end, so the COPY below cannot replace the final stage's own.
# ---------------------------------------------------------------------------
FROM node:24.16.0-bookworm-slim AS typescript
WORKDIR /usr/src/sts
COPY package*.json .npmrc ./
COPY node-ldapjs ./node-ldapjs
RUN npm install --omit=dev --ignore-scripts && npm cache clean --force
COPY tests/package*.json ./tests/
RUN npm install --prefix ./tests && npm cache clean --force
COPY . ./
RUN STS_IN_IMAGE_BUILD=1 ./build-typescript.sh --strip \
 && rm -rf ./node_modules ./tests/node_modules ./node-ldapjs/node_modules

FROM ubuntu:latest

# replace shell with bash so we can source files
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# Create app directory
WORKDIR /usr/src/sts

RUN apt-get update
RUN apt-get -y install curl \
        jq \
        wget \
        unzip \
        util-linux \
        bsdextrautils \
        # SECONDARY IP ADDRESSES FOR THE PER-REALM SPIFFE LISTENERS (2026-09-12).
        #
        # A realm with SPIFFE turned on binds a Workload API and a SPIRE
        # Server API of its own, and what keeps two realms apart is the
        # ADDRESS rather than the port — a SPIFFE client has nowhere else to
        # name a tenant, because the gRPC method name is fixed by the
        # specification. So a container running two realms needs two
        # addresses, and `ip addr add` is how it gets them.
        #
        # ONE PACKAGE, and it is in the image rather than installed at start
        # for the ordinary reason: a container that apt-gets on the way up
        # fails to start when the network it is being given is the thing that
        # is broken.
        iproute2

# Install NVM
ENV NVM_DIR /usr/local/nvm
ENV NODE_VERSION=24.16.0
RUN mkdir -p ${NVM_DIR}
RUN set -o pipefail && curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.5/install.sh | bash

# Load NVM and install Node.js
RUN . $NVM_DIR/nvm.sh && nvm version && echo -e ". $NVM_DIR/nvm.sh\nexport PATH=\$NVM_DIR/versions/node/\$(nvm version)/bin:\$PATH" >> ~/.bashrc
RUN cat ~/.bashrc

RUN source $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default

# add node and npm to path so the commands are available
ENV NODE_PATH $NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

# confirm installation
RUN node -v
RUN npm -v

# Install dependencies (package-lock.json is optional; wildcard copies it when
# present so `npm ci`-style reproducibility works once a lock is committed).
COPY package*.json ./
# The LDAP server's library is `"ldapjs": "file:node-ldapjs"` — the git SUBMODULE,
# not a registry package — so it has to be in the build context BEFORE npm runs or
# the install fails with EUNSUPPORTEDPROTOCOL/ENOENT naming a path rather than a
# submodule. It is copied here, ahead of the source, so that editing this service
# does not invalidate the install layer.
#
# An UNINITIALISED SUBMODULE IS AN EMPTY DIRECTORY, and this is where that shows
# up: the COPY succeeds, npm installs a package with no main, and the failure
# arrives at runtime as `Cannot find module 'ldapjs'` from ldap_server.js. Run
# `git submodule update --init --recursive` — --recursive because this repository
# is itself a submodule of the parent project, and a plain --init there stops one
# level short of this one.
#
# .npmrc carries `omit=dev`, and it is load-bearing rather than tidiness: npm
# installs the devDependencies of a `file:` dependency, and ldapjs's are tap and
# eslint — some 200 packages and a dozen advisories that have nothing to do with
# this service. The flag below says the same thing twice on purpose, so that a
# build which loses the .npmrc does not quietly start shipping them.
COPY .npmrc ./
COPY node-ldapjs ./node-ldapjs
RUN npm install --omit=dev && npm cache clean --force


# THE WHOLE SOURCE TREE IN ONE LINE, and that is deliberate rather than lazy.
#
# The service is a shell: server.js requires the other modules and listens, so a
# module that never reaches the image is not a missing feature but a
# MODULE_NOT_FOUND before anything binds the port — the container never answers
# /healthcheck and every STS-backed job in the parent project's suite fails on a
# timeout that says nothing about the cause.
#
# This used to be `COPY *.js ./` plus one line each for contexts, protos and env,
# and the wildcard's comment said why: a per-file list would have to be edited
# every time a module was added, and forgetting is silent until the containerized
# run. The 2026-08-23 reorganisation moved every module into a subdirectory
# (common/, oauth-oidc/, kerberos/, ldap/, scim/, spiffe/, admin-ui/, mgmt-api/
# and the rest), which put that exact trap back one level up: a per-DIRECTORY
# list has the same failure, and a new protocol family is a likelier thing to add
# than a new sibling of server.js ever was.
#
# So the context is copied whole and .dockerignore decides what is in it. That is
# the only arrangement in which adding a directory cannot be forgotten. Three
# things ride along that are read AT REQUIRE TIME and whose absence is a service
# that does not start rather than a degraded feature, which is the reason to be
# sure they are here:
#
#   common/vendored/contexts  the JSON-LD contexts bbs2023.js loads at module
#                             scope. They are a SIBLING of that module because it
#                             is a byte-identical copy of the parent project's
#                             and resolves path.join(__dirname, 'contexts') — so
#                             they move when it moves and the file is not edited.
#   spiffe/protos             the SPIFFE project's own workloadapi.proto and the
#                             spire-api-sdk's, read by spiffe/spiffe_grpc.ts at
#                             module scope. Verbatim: the wire matching what a
#                             real client expects is the entire reason
#                             @grpc/grpc-js is a dependency here.
#   env                       the appconfig files. CONFIG_FILE selects one.
#
# node_modules, .git, the documentation and the CI definitions are excluded in
# .dockerignore; node-ldapjs is copied above, ahead of the install, and copying
# it again here is a no-op on identical content.
#
# **FROM THE `typescript` STAGE, NOT FROM THE CONTEXT, SINCE #50
# (2026-09-16)**: the same tree, with every `.ts` compiled and then removed —
# see that stage. Everything said above about what rides along still holds.
COPY --from=typescript /usr/src/sts/ ./

# ---------------------------------------------------------------------------
# THE SECRET-STORE SDK, AND WHY IT IS INSTALLED HERE RATHER THAN DECLARED AS A
# DEPENDENCY (2026-09-12).
#
# `common/secrets.js` reads the key-encryption key and the database password
# from one of five places, and four of them need somebody else's SDK. Those are
# OPTIONAL PEER dependencies on purpose — that file's header argues it at
# length: this package is installed by the debugger's suite and by CI, and
# carrying four cloud SDKs to use none of them would be a cost every one of
# those installs pays.
#
# **THE IMAGE IS THE OTHER CASE.** The stack this repository ships now brings up
# an OpenBao container and points the service at it, so the image REQUIRES the
# Vault SDK to start. It is installed here, with `--no-save`, so that the
# container has it and a checkout still does not — which is exactly the split
# the peer declaration describes.
#
# **IT IS AFTER `COPY . ./` AND THAT IS NOT A STYLE CHOICE.** Installed
# before it, the package is there at that step and GONE from the finished
# image: the copy brings the build context's own `node_modules` over the
# top of the one npm just wrote into. `.dockerignore` carries
# `**/node_modules`, which reads as though it prevents exactly that and does
# not for the tree's own top-level directory. Installing after the copy is
# the fix that does not depend on reading that pattern correctly.
#
# The three cloud SDKs are deliberately NOT installed: nothing in this stack
# dials AWS, GCP or Azure, and a deployment that does runs one `npm install` in
# its own image. `secrets.js` names the package to install when one is missing.
# **AND IT GOES IN A PREFIX OF ITS OWN, WHICH IS npm's DOING.** `npm install
# node-vault` inside this tree does NOTHING and says "up to date": the package
# is declared here as an OPTIONAL PEER, and npm treats an absent optional peer
# as a satisfied one — an explicit install request included. Every spelling of
# `--include=optional`, `--no-save` and `--force` answers the same way. So the
# SDK is installed into a prefix that has no opinion about this package.json,
# and `NODE_PATH` is what makes `require('node-vault')` find it.
RUN mkdir -p /opt/sts-sdk \
    && cd /opt/sts-sdk \
    && npm init -y > /dev/null \
    && npm install --omit=dev node-vault \
    && npm cache clean --force
ENV NODE_PATH=/opt/sts-sdk/node_modules
# ---------------------------------------------------------------------------
# A CLOUD SDK AND A DATABASE CA, FOR AN IMAGE THAT RUNS IN A CLOUD (2026-09-15).
#
# The paragraph above leaves the three cloud SDKs out, and for THIS stack that
# is still right. `deploy/aws/` (issue #51) runs the same image on ECS against
# AWS Secrets Manager and RDS, so it needs `@aws-sdk/client-secrets-manager`
# and the RDS certificate bundle — and "a deployment runs one `npm install` in
# its own image" is exactly what these two build arguments are, spelt once
# here rather than in a second Dockerfile that would drift from this one.
#
# * `STS_CLOUD_SDKS` — space-separated package names, installed into the same
#   prefix as node-vault (npm's peer rule above applies to them too). Empty by
#   default, so the image every other launcher builds is unchanged.
# * `STS_DATABASE_CA_URL` — a PEM bundle fetched into
#   /opt/sts-sdk/database-ca.pem. Node reads it through `NODE_EXTRA_CA_CERTS`,
#   which the deployment sets; this service has no CA-file setting of its own
#   for the database (`persistence/CLAUDE.md`). Fetched at BUILD time, so a
#   container never needs the network to trust its own database.
# ---------------------------------------------------------------------------
ARG STS_CLOUD_SDKS=
ARG STS_DATABASE_CA_URL=
RUN if [ -n "${STS_CLOUD_SDKS}" ]; \
    then \
      cd /opt/sts-sdk \
      && npm install --omit=dev ${STS_CLOUD_SDKS} \
      && npm cache clean --force; \
    fi \
    && if [ -n "${STS_DATABASE_CA_URL}" ]; \
    then \
      curl -fsSL "${STS_DATABASE_CA_URL}" -o /opt/sts-sdk/database-ca.pem \
      && grep -q 'BEGIN CERTIFICATE' /opt/sts-sdk/database-ca.pem; \
    fi
# ---------------------------------------------------------------------------
# AND THE SUITE BACK OUT AGAIN, WHICH .dockerignore USED TO DO.
#
# `tests/` is in the build context since 2026-08-29 and it is not here by
# choice: ONE context serves two images — this one and the test runner
# (tests/Dockerfile, built by docker-compose-run-tests.yml), which is nothing
# BUT the suite and needs the whole source tree besides, because its
# in-process jobs require this service's own modules. A context has one ignore file, and
# the per-Dockerfile ignore file that would give it two is a BuildKit feature
# that the legacy builder silently ignores. See .dockerignore, where the
# failure that taught this is written down.
#
# So the exclusion moved here, where the reason sits beside the instruction.
# The tests assert this repository's MODULE CONTRACTS by requiring the modules
# directly — they are a property of the source tree rather than of the running
# service, this image exists to run `server.js`, and nothing in it would ever
# call them. `npm test` inside this image therefore does not work, exactly as
# deliberately as before; package.json is copied for its dependency list.
#
# **`xacml-pep` GOES THE SAME WAY, SINCE 2026-09-05, AND FOR THE SAME REASON
# ONE STEP FURTHER OUT.** That directory is a SECOND CONTAINER — a remote XACML
# Policy Enforcement Point with its own Dockerfile, its own package.json and
# its own thirty-line `common/helpers.js` shim. `server.js` requires none of
# it and nothing in this image ever could. It is in the context because THAT
# image is built from this same context (its Dockerfile copies the engine out
# of `xacml/` at build time, which is what keeps one copy of the evaluator in
# the tree), and a context has one ignore file — so the exclusion belongs here
# beside its reason rather than in `.dockerignore`, where it would break the
# very build it exists for.
#
# The shim is the specific thing worth not shipping: it is a file called
# `common/helpers.js` that exports two functions, and a copy of it inside an
# image whose real `common/helpers.js` is the identity service's is a trap
# laid for whoever next reads a stack trace.
#
# **AND THREE FILES AT THE PACKAGE ROOT, SINCE 2026-09-09, FOR THE SAME REASON
# A THIRD STEP OUT.** `README.md`, `docker-compose.yml` and this Dockerfile
# were excluded in `.dockerignore` until that day, on the true grounds that
# nothing reads them at runtime. What that overlooked is that they are the
# SUBJECT of in-process jobs — tests/readme_ports.js checks the README's ports
# table against config.js and against the EXPOSE lines below it,
# tests/readme_settings.js checks its settings tables, and
# tests/postgres_schema.js checks the application role in docker-compose.yml
# against postgres/schema.sql — and those jobs run in the TESTS image, built
# from this same context, where a file the context does not carry is an ENOENT
# reported as a failing test rather than a skip. So they are in the context and
# come out here, and this image carries exactly what it did before.
#
# **AND `.github/workflows/tests.yml` JOINED THEM ON 2026-09-10**, one step
# further out again: tests/teardown_bounds.js asserts that the CI job's own
# timeout sits above the sum of the two ./run-tests.sh reaches itself,
# so the workflow is the subject of a test and has to be in the context. The
# rest of `.github` is still excluded and nothing here reads any of it.
#
# **AND `docs` AND `docker-compose-run-tests.yml` ON 2026-09-14**, for the same
# reason again: tests/error_codes.js reads docs/error-codes.md and
# docs/_config.yml, and tests/stack_network.js and tests/teardown_bounds.js
# read the test compose file. Excluded from the context, all three failed with
# ENOENT in the first ./run-tests.sh run that reached them.
# `deploy/` (2026-09-15) is Terraform and the schema-init image's files, run
# from a workstation or CI and never by the service.
RUN rm -rf ./tests ./xacml-pep ./README.md ./docker-compose.yml ./Dockerfile \
           ./.github ./docs ./docker-compose-run-tests.yml ./deploy \
           ./build-typescript.sh

# The debugger's built tree — see the stage at the top of this file. After the
# `rm` above and before the version stamp, and into the directory
# `debugger.uiDirectory` and `debugger.apiDirectory` default to.
COPY --from=debugger /debugger/ ./debugger/embedded/
# ---------------------------------------------------------------------------
# FIX THIS IMAGE'S BUILD NUMBER (M.N.O) AND SHIP IT IN version.json.
#
# The version is M.N from the repo-root VERSION file plus a build number, and
# the build number is decided HERE — at image build time — rather than at
# startup. That is the whole reason this line exists: a service that computed
# its build number when the process started would report a different one every
# time the container restarted, which makes "which build is this" unanswerable
# in exactly the situation where it is asked. See common/version.js.
#
# It runs AFTER `COPY . ./` because it needs the VERSION file and the module,
# and after the `rm` above because neither is among what that removes.
# It is the LAST layer that touches the source, so a rebuild of an unchanged
# tree still produces a new build number — which is correct: that is a
# different artifact.
#
# GIT_COMMIT is a build argument because .dockerignore excludes .git, so there
# is no history in the build context for `git rev-parse` to read. Pass it and
# the version's provenance names a commit; leave it and the commit is simply
# absent, which is a missing tooltip and nothing else. BUILD_NUMBER overrides
# the UTC build instant — a CI run number, say — and it is then the caller's
# job to keep it unique and increasing.
#
# `cat` afterwards so the record is in the build log: when somebody asks which
# build an image is, the answer is in the log of the build that made it as well
# as in the image.
ARG BUILD_NUMBER=
ARG GIT_COMMIT=
RUN BUILD_NUMBER="${BUILD_NUMBER}" GIT_COMMIT="${GIT_COMMIT}" \
    node common/version.js --stamp . && cat version.json
# The service selects its configuration (log level) with CONFIG_FILE, the same
# way api and client do. The compose files override this per stack.
#
# The path is RELATIVE and it is resolved against the package root rather than
# against the directory of whichever module read it — see common/config_file.js.
# Before the reorganisation every reader sat in the package root and that was
# true by accident; it is now true on purpose, and this string did not have to
# change.
ENV CONFIG_FILE=./env/local.js

# 8081 is the HTTP service. Most of the rest are the listeners that are NOT HTTP
# and so are not on it: 88 is the KDC (TCP and UDP), 8888 the Kerberos-protected
# test service, 389 the LDAP directory and 636 the same directory over TLS. The
# two other HTTP listeners (8082, 8444) and the SPIFFE gRPC ones are explained
# beside their own lines below.
# EXPOSE documents them; each compose file decides which it publishes.
#
# **8443 AND 9443 WERE HERE UNTIL 2026-09-16** — the TLS endpoint that asked
# for a client certificate and the one that required it. Both listeners were
# deleted and neither number is bound by anything now: a client certificate is
# presented to 8081, which asks for one and requires none. Removed rather than
# left behind, because EXPOSE is read by `docker run -P` and a mapping onto a
# port nothing listens on is a connection refused with no explanation.
#
# The four raw-socket ports were named in that sentence long before they were
# listed below it, which made the sentence false in the direction that matters:
# somebody reading the image for what it offers saw three HTTP-family ports and
# concluded the KDC and the directory were not in it. They are listed now, and
# EXPOSE is metadata only — it publishes nothing, so the compose files still
# decide, and `docker run -P` is the one command that reads it.
#
# 636 is a SEPARATE SOCKET rather than an option on 389 (ldapjs chooses between a
# net.Server and a tls.Server at construction), and the two bind independently:
# either can be up while the other is not, which is why GET
# /admin/ldap/service reports them separately. A compose file that publishes 389 and not 636 offers a directory a
# TLS client cannot reach, with nothing in the image to say why.
EXPOSE 8081
# The plain-HTTP revocation listener (2026-09-13): /pki/ only, and the
# address every certificate names for its CRL and OCSP responder.
EXPOSE 8082
EXPOSE 88/tcp
EXPOSE 88/udp
EXPOSE 389
EXPOSE 636
# 8888 IS THE KERBEROS-PROTECTED TEST SERVICE (krb5.servicePort), and it was
# missing from this list until 2026-09-07 — found by `tests/readme_ports.js`,
# which holds the README's ports table to config.js and this file to the table.
# It is a raw TCP listener like 88 and 389, it is bound on every start, and the
# sentence above enumerating "the listeners that are NOT HTTP" did not mention
# it either until then. Nothing failed, and nothing could: EXPOSE publishes nothing, so an
# omission here costs exactly one thing — `docker run -P` leaves that port
# unmapped, which is the one command that reads this.
EXPOSE 8888
# The two SPIFFE gRPC listeners over TCP: 8092 is the Workload API and 8181 the
# SPIRE Server API. 8181 rather than SPIRE's own 8081 because that is this
# service's HTTP port, so a client configured for a real spire-server has one
# thing to change and it is named on GET /spiffe.
#
# THE WORKLOAD API'S UNIX SOCKET IS NOT A PORT and cannot be EXPOSEd: it is at
# spiffe.workloadSocket (`/tmp/spire-agent/public/api.sock`, SPIRE's own path)
# INSIDE the container, and it is what SPIFFE_ENDPOINT_SOCKET means to every real
# client. To reach it from the host or from another container, mount the
# directory as a volume — publishing 8092 is the alternative, and it needs the
# client pointed at `tcp://host:8092` explicitly.
EXPOSE 8092
EXPOSE 8181
# The embedded protocol debugger's listener (debugger.port), when it is
# embedded and installed. See debugger/CLAUDE.md.
EXPOSE 8444
CMD [ "node", "server.js" ]
