# Validation Pipeline Test Results

**Date:** 2026-02-21
**Tested by:** Rex (automated)

## Test 1: Example Account (intentionally sloppy)
**Input:** `accounts/_example/security-groups.yaml`
**Result:** ❌ FAILED (31 errors, 31 warnings)
**Expected:** FAIL — example has quad-zero egress, missing ManagedBy tags, overly broad port ranges
**Catches:**
- 0.0.0.0/0 egress blocked ✅
- Port range 0-65535 blocked ✅
- Blocked ports (23, 135, 139, 445) caught ✅
- Missing required tags (ManagedBy) caught ✅
- SSH/RDP warnings generated ✅

## Test 2: Clean Valid Account
**Input:** `accounts/999888777666/security-groups.yaml`
**Result:** ⚠️ WARNINGS ONLY (0 errors, 3 warnings)
**Expected:** PASS with warnings — all rules valid, guardrails compliant
**Notes:**
- Warnings are recommendations for additional EKS egress rules (non-blocking)
- Exit code 2 (warnings only) — would not block PR merge

## Test 3: Intentionally Bad Account
**Input:** `accounts/111222333444/security-groups.yaml`
**Result:** ❌ FAILED (14 errors, 9 warnings)
**Expected:** FAIL — every rule violates guardrails
**Catches:**
- 0.0.0.0/0 ingress blocked on all 3 rules ✅
- Port range 0-65535 ingress blocked ✅
- Blocked ports in wide range caught ✅
- SSH (22) from internet blocked ✅
- RDP (3389) from internet blocked ✅
- Missing required tags (ManagedBy, Environment, Application) ✅

## Guardrails Validated
| Guardrail | Status |
|---|---|
| Block 0.0.0.0/0 ingress | ✅ Working |
| Block overly broad port ranges (>1000) | ✅ Working |
| Block dangerous ports (23, 135, 139, 445) | ✅ Working |
| Warn on sensitive ports (22, 3389, 3306, 5432) | ✅ Working |
| Require ManagedBy tag | ✅ Working |
| Require Environment tag | ✅ Working |
| Require Application tag | ✅ Working |
| Baseline profile validation | ✅ Working |
| Account ID format (12 digits) | ✅ Working |

## Conclusion
Validation pipeline correctly blocks dangerous configurations and warns on sensitive patterns.
Pipeline is ready for production use.
