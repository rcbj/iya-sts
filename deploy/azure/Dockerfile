# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# File: deploy/azure/Dockerfile
#
# THE AZURE TERRAFORM IMAGE (issue #96): deploy/aws/Dockerfile's and
# deploy/gcp/Dockerfile's arrangement — Terraform runs inside a container
# built from the repository, so a laptop and a workflow run the same thing —
# over the Azure CLI, which the provider and the state backend authenticate
# through. Terraform is pinned to AWS's and GCP's version, so the stacks'
# locks and plans agree about the language.
#
#   docker build -f deploy/azure/Dockerfile -t mock-sts-terraform-azure .
#
# terraform-local.sh builds and runs it; the credentials are the host's
# Azure CLI login, handed over through a private env file (entrypoint.sh).
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/azure-cli:latest

RUN tdnf -y install ca-certificates curl jq tar unzip shadow-utils \
    && tdnf clean all

ARG TERRAFORM_VERSION=1.16.2
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
        "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" -o /tmp/tf.zip \
    && unzip -q /tmp/tf.zip -d /usr/local/bin \
    && rm /tmp/tf.zip \
    && terraform version

COPY deploy/azure/ /workspace/deploy/azure/
RUN chmod +x /workspace/deploy/azure/entrypoint.sh

RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --create-home \
        --shell /bin/bash appuser \
    && chown -R appuser:appuser /workspace

ENV HOME=/home/appuser
USER appuser
WORKDIR /workspace

ENTRYPOINT ["/workspace/deploy/azure/entrypoint.sh"]
