# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# File: deploy/multicloud/Dockerfile
#
# THE MULTI-CLOUD TERRAFORM IMAGE (#97): deploy/aws/Dockerfile's image — the
# AWS CLI (the deployer role is assumed with it, as there), Terraform at the
# same version, jq — with every stack of both clouds copied in, because one
# multi-cloud apply runs AWS's cells and global stack, GCP's cells, and this
# directory's two, in one order (entrypoint.sh). The Google provider needs no
# CLI: it reads the application-default credentials the launcher hands over
# and impersonates the GCP deployer with them.
#
#   docker build -f deploy/multicloud/Dockerfile -t mock-sts-terraform-mc .
# ---------------------------------------------------------------------------
FROM ubuntu:latest

RUN rm /bin/sh && ln -s /bin/bash /bin/sh

WORKDIR /workspace

RUN apt-get update \
    && apt-get -y install --no-install-recommends curl \
        ca-certificates \
        jq \
        unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
        "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/aws /tmp/awscliv2.zip \
    && aws --version

ARG TERRAFORM_VERSION=1.16.2
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
        "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" -o /tmp/tf.zip \
    && unzip -q /tmp/tf.zip -d /usr/local/bin \
    && rm /tmp/tf.zip \
    && terraform version

COPY deploy/aws/ /workspace/deploy/aws/
COPY deploy/gcp/ /workspace/deploy/gcp/
COPY deploy/multicloud/ /workspace/deploy/multicloud/
RUN chmod +x /workspace/deploy/multicloud/entrypoint.sh

RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --create-home \
        --shell /bin/bash appuser \
    && chown -R appuser:appuser /workspace

ENV HOME=/home/appuser
USER appuser

ENTRYPOINT ["/workspace/deploy/multicloud/entrypoint.sh"]
