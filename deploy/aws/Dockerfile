# ---------------------------------------------------------------------------
# THE TERRAFORM AND SUITE-LAUNCHER IMAGE FOR THE AWS CLUSTER (issue #51).
#
# The parent project's `infra/Dockerfile` arrangement: Ubuntu, the AWS CLI v2
# and a pinned Terraform, running one stack for one environment through
# deploy/aws/entrypoint.sh. Used identically on a developer machine
# (deploy/aws/terraform-local.sh) and in GitHub Actions
# (.github/workflows/aws-cluster.yml), so a plan that works on one works on the
# other and neither needs Terraform or the AWS CLI installed.
#
# Beside that pair, node: deploy/aws/run-suite-in-aws.sh (the `suite` action)
# builds its ECS overrides and reads the report's summary with it, and
# reset-environment.js is node. The suite itself does NOT run here — it runs
# as a task in the environment's VPC (environment/runner.tf); this image starts
# it, waits for it and downloads its report.
#
# Built from the repository root:
#   docker build -t mock-sts-terraform -f deploy/aws/Dockerfile .
# ---------------------------------------------------------------------------
FROM ubuntu:latest

RUN rm /bin/sh && ln -s /bin/bash /bin/sh

WORKDIR /workspace

# ONE RUN, for the reason the parent's infra/Dockerfile gives: a cached
# `apt-get update` layer names package versions the archive has since dropped.
RUN apt-get update \
    && apt-get -y install --no-install-recommends curl \
        ca-certificates \
        jq \
        unzip \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# --- AWS CLI v2 (self-contained) ---
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
        "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/aws /tmp/awscliv2.zip \
    && aws --version

# --- Terraform (pinned; >= 1.11 for the S3 backend's native lock file) ---
ARG TERRAFORM_VERSION=1.16.2
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
        "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" -o /tmp/tf.zip \
    && unzip -q /tmp/tf.zip -d /usr/local/bin \
    && rm /tmp/tf.zip \
    && terraform version

# --- Node (the version the suite pins) ---
ARG NODE_VERSION=24.16.0
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
        "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" -o /tmp/node.tar.xz \
    && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 \
    && rm /tmp/node.tar.xz \
    && node --version

# --- The two stacks, the scripts, and nothing else of the repository ---
COPY deploy/aws/ /workspace/deploy/aws/
RUN chmod +x /workspace/deploy/aws/entrypoint.sh \
        /workspace/deploy/aws/run-suite-in-aws.sh

# ---------------------------------------------------------------------------
# NON-ROOT, as the parent's image is. /workspace is writable by that user
# because `terraform init` writes .terraform/ into each stack's directory;
# /workspace/report is where the `suite` action downloads a report, and a
# caller mounts a directory there to keep it. State is remote (S3).
# ---------------------------------------------------------------------------
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --create-home \
        --shell /bin/bash appuser \
    && mkdir -p /workspace/report \
    && chown -R appuser:appuser /workspace

ENV HOME=/home/appuser
USER appuser

ENTRYPOINT ["/workspace/deploy/aws/entrypoint.sh"]
