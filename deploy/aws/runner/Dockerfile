# ---------------------------------------------------------------------------
# THE SUITE RUNNER FOR AN AWS ENVIRONMENT (issue #51): the tests image, plus
# the one package the task needs that the tests image does not carry — the S3
# client that uploads the report (upload-report.js).
#
# Built after tests/Dockerfile, from its tag:
#   docker build -t mock-sts-tests -f tests/Dockerfile .
#   docker build -t <repo>:runner-<tag> --build-arg TESTS_IMAGE=mock-sts-tests \
#                -f deploy/aws/runner/Dockerfile deploy/aws/runner
#
# In a directory of its own under /opt rather than the suite's node_modules,
# so nothing a job resolves changes because this image exists.
# ---------------------------------------------------------------------------
ARG TESTS_IMAGE=mock-sts-tests
FROM ${TESTS_IMAGE}

RUN mkdir -p /opt/sts-runner \
 && npm install --prefix /opt/sts-runner --no-save --omit=dev \
      @aws-sdk/client-s3@3 \
 && npm cache clean --force
