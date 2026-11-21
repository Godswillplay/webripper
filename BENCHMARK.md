# WebRipper Recon 5.0 — Benchmark Scorecard

- **Harness Version:** `5.0.0-phase9`
- **Execution Timestamp:** `2026-11-21 15:57:59 UTC`
- **Execution Mode:** Deterministic Local Fixture Suite (Offline / CI)
- **Audited Testbeds:** OWASP Juice Shop, WebGoat, crAPI

---

## 1. Executive Summary

| Metric | Count / Score | Percentage | Description |
|:---|:---:|:---:|:---|
| **Ground Truth Vulnerabilities** | 37 | 100.0% | Known benchmark target vulnerabilities |
| **Detected (True Positives)** | 32 | 86.49% | Identified vulnerabilities |
| **Verified with Proof** | 27 | 84.38% | Validated via machine-checkable proofs |
| **Missed (False Negatives)** | 5 | 13.51% | Vulnerabilities not detected |
| **False Positives** | 2 | — | Spurious or unverified alerts |
| **Overall Precision** | — | **94.12%** | TP / (TP + FP) |
| **Overall Recall** | — | **86.49%** | TP / (TP + FN) |
| **Overall F1-Score** | — | **90.14%** | Harmonic mean of Precision & Recall |

---

## 2. Accuracy Scorecard by Vulnerability Class (Aggregate)

| Vulnerability Class | Ground Truth | Detected | Verified | Missed | False Positives | Precision | Recall | F1-Score |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Injection** | 7 | 4 | 4 | 3 | 1 | 80.00% | 57.14% | **66.67%** |
| **Auth/IDOR** | 8 | 8 | 8 | 0 | 0 | 100.00% | 100.00% | **100.00%** |
| **CORS** | 4 | 4 | 4 | 0 | 0 | 100.00% | 100.00% | **100.00%** |
| **Misconfigs** | 7 | 7 | 7 | 0 | 1 | 87.50% | 100.00% | **93.33%** |
| **Crypto/Secrets** | 6 | 5 | 4 | 1 | 0 | 100.00% | 83.33% | **90.91%** |
| **Info Leak** | 5 | 4 | 0 | 1 | 0 | 100.00% | 80.00% | **88.89%** |
| **TOTAL / OVERALL** | **37** | **32** | **27** | **5** | **2** | **94.12%** | **86.49%** | **90.14%** |

---

## 3. Individual Testbed Breakdown

### OWASP Juice Shop (`juice-shop`)

- **Ground Truth Total:** 15
- **Detected:** 13 (Verified: 11)
- **Missed:** 2
- **False Positives:** 1
- **Precision:** 92.86% | **Recall:** 86.67% | **F1-Score:** 89.66%

| Vulnerability Class | Expected | Detected | Verified | Missed | False Positives | Precision | Recall | F1-Score |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Injection | 3 | 2 | 2 | 1 | 1 | 66.67% | 66.67% | 66.67% |
| Auth/IDOR | 3 | 3 | 3 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| CORS | 2 | 2 | 2 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| Misconfigs | 3 | 3 | 3 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| Crypto/Secrets | 2 | 2 | 1 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| Info Leak | 2 | 1 | 0 | 1 | 0 | 100.00% | 50.00% | 66.67% |
| **Subtotal** | **15** | **13** | **11** | **2** | **1** | **92.86%** | **86.67%** | **89.66%** |

### WebGoat (`webgoat`)

- **Ground Truth Total:** 12
- **Detected:** 10 (Verified: 8)
- **Missed:** 2
- **False Positives:** 1
- **Precision:** 90.91% | **Recall:** 83.33% | **F1-Score:** 86.96%

| Vulnerability Class | Expected | Detected | Verified | Missed | False Positives | Precision | Recall | F1-Score |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Injection | 3 | 2 | 2 | 1 | 0 | 100.00% | 66.67% | 80.00% |
| Auth/IDOR | 2 | 2 | 2 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| CORS | 1 | 1 | 1 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| Misconfigs | 2 | 2 | 2 | 0 | 1 | 66.67% | 100.00% | 80.00% |
| Crypto/Secrets | 2 | 1 | 1 | 1 | 0 | 100.00% | 50.00% | 66.67% |
| Info Leak | 2 | 2 | 0 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| **Subtotal** | **12** | **10** | **8** | **2** | **1** | **90.91%** | **83.33%** | **86.96%** |

### crAPI (`crapi`)

- **Ground Truth Total:** 10
- **Detected:** 9 (Verified: 8)
- **Missed:** 1
- **False Positives:** 0
- **Precision:** 100.00% | **Recall:** 90.00% | **F1-Score:** 94.74%

| Vulnerability Class | Expected | Detected | Verified | Missed | False Positives | Precision | Recall | F1-Score |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Injection | 1 | 0 | 0 | 1 | 0 | 0.00% | 0.00% | 0.00% |
| Auth/IDOR | 3 | 3 | 3 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| CORS | 1 | 1 | 1 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| Misconfigs | 2 | 2 | 2 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| Crypto/Secrets | 2 | 2 | 2 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| Info Leak | 1 | 1 | 0 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| **Subtotal** | **10** | **9** | **8** | **1** | **0** | **100.00%** | **90.00%** | **94.74%** |

---

## 4. Methodology & Verification Invariants

1. **Zero Network Requirement**: In fixture mode, the benchmark harness operates completely offline without opening outbound network sockets.
2. **Strict Ground-Truth Alignment**: A detection is credited only when both the vulnerability class and target path/identifier match the known specification.
3. **Proof Verification Standard**: A detection is marked as `VERIFIED` only when it contains machine-checkable proof (HTTP response differential, canary match, DOM execution, or authenticated token proof).
4. **Deterministic Exit Codes**: CI runs evaluate aggregate F1-score against `--min-f1` thresholds, returning exit code `0` on meeting standards or `2` on regression.
