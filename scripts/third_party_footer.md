
## Upstream projects consulted (read-only, architectural ideas only; no code copied)
| Project | URL | License as found in the repo (commit inspected 2026-10-07) |
|---|---|---|
| edr-graph | https://github.com/ticfinack/edr-graph | AGPL-3.0 (LICENSE file); README states Patent Pending (U.S. provisional 63/989,818) |
| SentryLoom / Endpointward | https://github.com/alivirgo/SentryLoom | Apache-2.0 (LICENSE + NOTICE files) |
| Fleet EDR | https://github.com/getvictor/fleet-edr | MIT (LICENSE file) |
| anomaly-behavioral-detection | https://github.com/ascendantayush/anomaly-behavioral-detection | MIT (LICENSE file) |
| JULIASIV/EDS | https://github.com/JULIASIV/EDS | README claims MIT but NO LICENSE file in repo |
| agentic-ai-threat-detection | https://github.com/Mahmoud1890/agentic-ai-threat-detection | NO license file or statement found |
| SecureAI Agent (akrishnash/anomaly-detection) | https://github.com/akrishnash/anomaly-detection | NO license file or statement found |
| OphanimEDR | https://github.com/judahx67/OphanimEDR | NO license file or statement found (tree + README only inspected) |

Because no code was copied, Apache-2.0 NOTICE retention / AGPL source-offer obligations are not triggered
today. If any code is ever adopted, add it to docs/REUSE_MATRIX.md, preserve the upstream copyright and license
text here, and obtain legal review first.

## Models and data
* Gemma 3 1B IT (GGUF Q4_K_M): Gemma Terms of Use apply; the model file is NOT bundled in this repository.
* Threat-intel feeds / YARA rule sets, if downloaded at runtime, retain their own licenses (record per feed).
