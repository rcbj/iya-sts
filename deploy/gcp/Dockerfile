# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# File: deploy/gcp/Dockerfile
#
# THE GCP TERRAFORM IMAGE (issue #95): deploy/aws/Dockerfile's arrangement —
# Terraform runs inside a container built from the repository, so a laptop
# and a workflow run the same thing — over the Google Cloud CLI instead of
# the AWS one. Terraform is pinned to AWS's version, so the two stacks'
# locks and plans agree about the language.
#
#   docker build -f deploy/gcp/Dockerfile -t iya-sts-terraform-gcp .
#
# terraform-local.sh builds and runs it; the credentials are the host's
# application-default ones, handed over through a private env file, and the
# deployer service account is IMPERSONATED with them (entrypoint.sh).
# ---------------------------------------------------------------------------
FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:slim

RUN apt-get update \
    && apt-get -y install --no-install-recommends ca-certificates curl jq unzip \
    && rm -rf /var/lib/apt/lists/*

ARG TERRAFORM_VERSION=1.16.2
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
        "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" -o /tmp/tf.zip \
    && unzip -q /tmp/tf.zip -d /usr/local/bin \
    && rm /tmp/tf.zip \
    && terraform version

COPY deploy/gcp/ /workspace/deploy/gcp/
RUN chmod +x /workspace/deploy/gcp/entrypoint.sh

RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --create-home \
        --shell /bin/bash appuser \
    && chown -R appuser:appuser /workspace

ENV HOME=/home/appuser
USER appuser
WORKDIR /workspace

ENTRYPOINT ["/workspace/deploy/gcp/entrypoint.sh"]
