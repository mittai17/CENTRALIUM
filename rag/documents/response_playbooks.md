---
source: playbook
title: Response playbooks
tags: response, playbook
---
## Principles
The LLM recommends; the deterministic policy engine decides. Prefer the least disruptive action that stops harm. Preserve evidence. Destructive actions need sufficient severity and confidence, and are blocked for protected processes and allowlisted items. In passive or learning mode only alert.

## Suspicious script host or LOLBin download
Alert and gather the full command line, parent chain and downloaded file. If the download is executed and the hash is unknown, quarantine the file and suspend the process. Block the destination if it is not a known-good domain.

## Reverse shell
Terminate or suspend the shell process, block the outbound connection, review the parent (web app, cron, user session) for the entry point, rotate credentials the shell could access.

## Credential dumping
Suspend the accessing process, treat accounts on the host as exposed, isolate the endpoint if lateral movement indicators exist, reset credentials after containment.

## Ransomware encryption in progress
Suspend the encrypting process immediately, isolate the endpoint from the network to protect shares, keep the host powered on, quarantine the binary and note files, then restore from clean backups.

## Persistence discovered
Alert, capture the artifact and payload hash, quarantine the payload, and remove the autostart entry through an approved action. Hunt for the same hash and mechanism elsewhere.

## Webshell
Quarantine the script, restrict or isolate the web service as policy allows, review web logs for the uploading request, and check for follow-on activity from the web server account.

## Low confidence or likely false positive
Recommend ALERT or NONE, list false-positive indicators and investigation questions, and request analyst review rather than enforcement. Admin tooling with signed binaries and expected parents often explains alerts.

## Endpoint isolation
Reserved for critical, high-confidence cases with active lateral movement, mass encryption or confirmed command and control. Must keep the management channel to the agent open.
