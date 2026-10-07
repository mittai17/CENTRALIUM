# License / IP notes (flag for legal review - not legal advice)

## Items needing legal review before any commercial / proprietary distribution
1. **edr-graph (AGPL-3.0, Patent Pending).** README: "Chain-Aware Ancestry Enforcement Engine ... Two-Tier Evaluation
   Engine and In-Memory Ancestry Acceleration" is patent pending (US provisional 63/989,818); the repo ships
   `patent/PROVISIONAL_PATENT_DRAFT.md` describing process-ancestry-chain-scoped allow/block rules with a two-tier
   (constant-time hash/prefix lookup + ancestry-reconstruction) evaluator. Consequences:
   * No edr-graph code is in Centralium. AGPL obligations (source offer for network use, copyleft on derivatives) are
     therefore not triggered; keep it that way unless a decision is made to adopt code.
   * **Patents are independent of copyright**: clean-room code does not remove patent exposure. Anyone implementing
     ancestry-chain-scoped rules with a two-tier evaluator (policy/allowlist owners, graph owner) should have counsel
     compare Centralium's design to the claims. Recommendation: avoid a rule language with ancestry-chain patterns and a
     two-tier "compiled lookups + chain reconstruction" evaluator until reviewed. This repo's sync and self-protection
     modules do not touch that area.
2. **Repos with no license (all rights reserved by default):** agentic-ai-threat-detection, SecureAI Agent
   (akrishnash/anomaly-detection), OphanimEDR, and JULIASIV/EDS (README says MIT but no LICENSE file). Do not copy code from them.
3. **MPL-2.0 dependencies:** certifi, pathspec (file-level copyleft; fine when unmodified, keep license texts when
   redistributing). **PSF-2.0:** typing_extensions. See THIRD_PARTY_NOTICES.md for the complete generated list; several
   packages report free-text licenses that should be double-checked before shipping a bundled binary.
4. **Gemma 3 1B IT** is under the Gemma Terms of Use (use restrictions, flow-down obligations), not an OSI license.
5. **SentryLoom (Apache-2.0)** is safe to reuse with attribution + NOTICE retention if code is adopted later; its README
   also references optional GPLv2 data (Linux Malware Detect signatures) and ClamAV/abuse.ch data, each with their own terms.
6. OphanimEDR: only tree + README were readable (full clone timed out); no license file in the tree.
7. `cryptography` is used for update verification but is not yet declared in `requirements.txt`/`pyproject.toml`; the code
   degrades to a hash-pin integrity-only mode (documented in `self_protection/updates.py`) when it is missing.

## Method
Each license above was read from the LICENSE file in the cloned repo at the inspected commit (edr-graph 30b4181,
SentryLoom e77d318, fleet-edr 9ff851e, anomaly-behavioral-detection 4091678, EDS 676985b, agentic-ai-threat-detection
6d8212d, anomaly-detection 9f88dc8; OphanimEDR via blob-filtered clone, no license file in tree) or recorded as absent.
