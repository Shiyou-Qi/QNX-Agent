# Reverse-Engineering Analysis Report

| Field | Value |
|---|---|
| Case / artifact | [name or case ID] |
| Report date | [YYYY-MM-DD, timezone if known] |
| Analyst | Qi-NX-Agent |
| Requested scope | [questions and boundaries] |
| Analysis status | [Complete / Partial] |
| Artifact SHA-256 | [hash or Not available] |

## 1. Executive summary

[Answer the user's question directly. Summarize confirmed behavior and confidence.]

## 2. Artifact identity and integrity

| File | Size | Format / architecture | MD5 | SHA-1 | SHA-256 |
|---|---:|---|---|---|---|
| [path] | [bytes] | [format / architecture] | [value / unavailable] | [value / unavailable] | [value / unavailable] |

## 3. Scope, environment, and methodology

| Item | Details |
|---|---|
| In-scope questions | [list] |
| Exclusions | [list or None stated] |
| Environment | [OS, sandbox/VM, relevant configuration] |
| Tools run | [tool, version, purpose, result status] |
| Tools not available | [tool and consequence] |

## 4. Triage results

[Container, architecture, entry point, sections, imports, packing/compression signals, and other checks performed.]

## 5. Findings

| Finding | Severity | Confidence | Summary | Evidence IDs |
|---|---|---|---|---|
| F-001 | [Critical/High/Medium/Low/Informational] | [High/Medium/Low] | [claim] | E-001, E-002 |

### F-001 — [finding title]

- **Observation:** [directly observed fact]
- **Interpretation:** [what the observation supports]
- **Alternative explanations:** [credible alternatives]
- **Impact:** [impact or Not confirmed]
- **Confidence:** [rating and why]
- **Further evidence needed:** [what would raise confidence]

## 6. Capabilities and behavior

| Capability | Behavior observed | Evidence IDs | Confidence |
|---|---|---|---|
| [capability] | [observed behavior] | [IDs] | [rating] |

## 7. Indicators of compromise

| Type | Value | Source / offset | Context | Confidence |
|---|---|---|---|---|
| [hash/domain/path/etc.] | [value] | [evidence ID and location] | [context] | [rating] |

## 8. ATT&CK mapping (when applicable)

| Technique | Name | Evidence IDs | Confidence / caveat |
|---|---|---|---|
| [ID] | [name] | [IDs] | [rating] |

## 9. Detection and mitigation recommendations

| Priority | Recommendation | Rationale / evidence | Validation |
|---|---|---|---|
| [P1] | [action] | [IDs] | [how to verify] |

## 10. Limitations and unanswered questions

- [Checks not run, inaccessible layers, unsupported formats, missing symbols, or unresolved questions.]

## Appendix A — Evidence ledger

| Evidence | Artifact SHA-256 | Tool and version | Output field / method | Address (VA) | Image offset / RVA | Observation |
|---|---|---|---|---|---|---|
| E-001 | [hash] | [tool/version] | [field or procedure] | [address / N/A] | [offset / N/A] | [verbatim fact or concise extract] |

## Appendix B — Additional results (when useful)

[Function and callsite tables, firmware volume / file maps, protocol field maps, or bounded tool-output extracts.]

— Qi-NX-Agent (Copyright Qi-NX)
