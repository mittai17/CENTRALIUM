---
source: rule
title: Centralium detection rules
tags: rules, epp, behavior
---
## Known-malicious short circuit
A SHA-256 match against the local hash blocklist, an IOC hit (hash, IP, domain) or a YARA match on a confirmed family marks the finding known_malicious. These events skip ML, RAG and the LLM and go straight to risk, policy and response. The LLM can never lower the risk of a known-malicious finding.

## Allowlist suppression
Allowlisted hashes, signed vendor binaries and approved paths produce a zero-score allowlist finding. Allowlisted events skip ML, RAG and LLM and trigger no response. This reduces false positives for administrative tools that look like attacker tradecraft, such as backup agents using vssadmin.

## Behavior rule family: process chains
Rules score suspicious parent-child chains: Office or PDF reader spawning a shell or script host, web server or database spawning a shell, browser spawning powershell, and system-binary proxies with network arguments. Chains raise graph score and attack-stage confidence.

## Behavior rule family: LOLBin abuse
Living-off-the-land binaries (certutil, mshta, rundll32, regsvr32, bitsadmin on Windows; curl, wget, nc, python, find on Linux) are scored by dangerous argument patterns rather than by name alone. A bare use scores low; download, decode, execute or remote-script arguments score high.

## Behavior rule family: persistence
Writes to Run keys, services, scheduled tasks, cron, systemd units, shell profiles, authorized_keys and ld.so.preload by non-installer processes emit persistence findings with the matching MITRE technique.

## Behavior rule family: ransomware
Counts file modifications and renames per process in a sliding window, extension changes, entropy of written data, ransom note names and shadow-copy deletion. Several signals together escalate to CRITICAL and recommend suspending the process.

## Behavior rule family: credential access
Detects lsass memory access, shadow file reads, bulk reads of key and token directories and password spraying patterns.

## Risk score families
The final score is a weighted combination of ML anomaly, ML classification, deterministic evidence, graph attack chain, threat intel, static malware analysis and AI assessment. Unavailable families are excluded rather than counted as zero. AI is scaled by its confidence and cannot lower the non-AI score.

## LLM gatekeeping
Only events with pre-risk above the configured gate that are novel against the baseline reach RAG and the LLM. LLM output is advisory; the policy engine decides what is allowed.
