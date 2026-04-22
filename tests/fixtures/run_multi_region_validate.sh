#!/usr/bin/env bash
set -euo pipefail
mkdir -p /tmp/sg-test/123456789012
cp /root/.openclaw/workspace/aws-security-groups/tests/fixtures/multi_region_account.yaml /tmp/sg-test/123456789012/security-groups.yaml
python3 /root/.openclaw/workspace/aws-security-groups/scripts/validate.py /tmp/sg-test/123456789012
