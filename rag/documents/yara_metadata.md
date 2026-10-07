---
source: yara
title: YARA rule metadata and handling
tags: yara, malware, signatures
---
## Rule metadata fields
Each YARA rule carries rule_id, name, family, severity, source, version, enabled flag and free metadata such as author, reference and mitre technique. Rules are validated by compiling them without activating, then enabled explicitly.

## Interpreting a YARA hit
A hit on a family-specific rule with severity high is strong evidence and is treated as known malicious. Generic rules (packer, suspicious strings, high entropy) are weak evidence: they raise static-analysis score and should be combined with behavior before response.

## Webshell rules
Webshell rules match server-side script files containing eval of request parameters, base64-decoded execution or command-execution wrappers. Typical locations are web roots and upload directories. A hit plus a web-server process spawning a shell is a confirmed webshell chain.

## Packer and loader rules
Packer rules match known section names, import-table anomalies and tiny import sets with high entropy. Packing alone is not malicious; many legitimate installers are packed. Raise suspicion only with other evidence such as unsigned status or temp-directory execution.

## Ransomware family rules
Ransomware rules match ransom-note strings, embedded cryptographic constants combined with file-extension lists, and shadow-copy deletion command strings inside binaries.

## Linux ELF miner and backdoor rules
Cryptominer rules match stratum protocol strings, mining pool configuration fragments and known miner banners. Backdoor rules match hard-coded reverse-shell routines and credential-harvesting strings in ELF files.

## False positive handling
Scan results carry rule version. Disable or tune a noisy rule rather than allowlisting a file by name. Allowlist by SHA-256 when a vendor tool legitimately matches.
