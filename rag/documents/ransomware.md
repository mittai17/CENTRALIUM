---
source: ransomware
title: Ransomware behavior knowledge
tags: ransomware, impact
---
## Typical stages
Initial access through phishing or exposed services, credential theft, lateral movement, disabling security and backup tools, deleting shadow copies and snapshots, then mass encryption and a ransom note. The mass-encryption stage is fast, so prevention needs early signals.

## Encryption phase indicators
One process modifying or renaming hundreds of files per minute, new or appended extensions applied uniformly, written content with near-maximum entropy, files read then rewritten in place, traversal across documents, databases and network shares in alphabetical or random order.

## Ransom notes
Same text file or HTML page created in many directories with names such as README, DECRYPT or RESTORE. Creation of identical files in more than a handful of folders is a strong signal.

## Recovery inhibition
vssadmin delete shadows, wmic shadowcopy delete, bcdedit recoveryenabled no, wbadmin delete catalog, stopping of backup and database services, removal of Linux snapshots and backup directories. Technique T1490 and T1489.

## Linux ransomware
Targets virtual machine disks, database files and home directories; often runs as root from /tmp, stops services first, and may use find with xargs and openssl for encryption.

## False positives
Legitimate bulk operations include backup agents, archivers, disk encryption setup, mass renames by IDEs and package managers. They usually come from signed, known binaries with stable paths and without ransom notes or shadow-copy deletion.

## Response priority
Suspend the writing process first to preserve keys in memory and stop damage, then isolate the host if lateral file-share encryption is seen, and preserve evidence. Do not reboot.
