FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates curl jq python3 python3-yaml procps build-essential \
 && rm -rf /var/lib/apt/lists/*
# BUILD CONTEXT IS THE REPO ROOT, not this directory. Use build.sh.
#
# It used to be this directory, which meant every script the image needed had to be
# COPIED here first -- and `poc-normalise.py` duly drifted: the copy taken at
# 05:13 on 2026-08-24 never received the admissibility stamping added to
# pipeline/ at 05:16, so the feature existed, was tested, and had never once run in
# a pod. Sourcing straight from pipeline/ removes the class of bug rather than the
# instance (D47).
COPY infra/runner-image/cm /usr/local/bin/cm
# cm 0.5.0, which is what `--version=stable` returns (README 0b).
# When stable moves, this check FAILS the build, deliberately:
# an agent binary nobody pinned must not reach a find or verify pod. Bump the sha
# and the image TAG together -- a moved tag makes find and verify disagree about
# which agent they ran.
RUN chmod 0755 /usr/local/bin/cm \
 && echo "f38700900eb9049f0ea131c42e2766f1b9c0a7ec9647b05c9a1f9b5b7701cf9f  /usr/local/bin/cm" | sha256sum -c -
COPY infra/runner-image/config.yaml infra/runner-image/command_policy.yaml /etc/codemender/
COPY infra/runner-image/probe.sh /usr/local/bin/probe.sh
# The canary: a trivially vulnerable fixture plus a deterministic exploit for it.
# Verify pods run this BEFORE spending agent-minutes, to establish that this pod can
# execute and observe an exploit at all (D45).
COPY infra/runner-image/canary/ /opt/cm/canary/
# Verify-side helpers, straight from pipeline/ -- ONE copy, the one the tests test.
# These are read-only scripts with no credential and no cluster access: the
# runner/reconciler split (D36) is about who may write the ledger and create Jobs,
# not about who may compute.
#
# oracle-route imports gate + consolidate-dedup rather than restating their tables.
# A second copy of the CWE->class map is precisely the drift that left four of the
# five oracle routes unreachable (D47).
COPY pipeline/scrub-answer-key.py pipeline/poc-normalise.py pipeline/poc-replay.py \
     pipeline/oracle-route.py pipeline/oracle-run.py pipeline/gate.py \
     pipeline/consolidate-dedup.py pipeline/oracles.py pipeline/coverage.py /opt/cm/
# The per-target oracle specs. oracle-route says WHICH instrument a finding needs;
# these say where to point it. Without them the oracles are routed and inert, which
# is where D47 left them (D50).
COPY targets/oracle-specs/ /opt/cm/oracle-specs/
COPY infra/runner-image/app /work/app
RUN mkdir -p /home/cm && chmod -R 0777 /home/cm /work
WORKDIR /work
