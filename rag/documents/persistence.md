---
source: persistence
title: Persistence techniques knowledge
tags: persistence, autostart
---
## Windows persistence locations
Run and RunOnce registry keys, Winlogon shell and userinit values, Startup folders, scheduled tasks, services, WMI event subscriptions, COM hijack keys, DLL search-order hijacks and Image File Execution Options debugger values.

## Linux persistence locations
crontab spools and /etc/cron.*, systemd units and timers, rc.local and init scripts, shell startup files, authorized_keys, /etc/ld.so.preload, udev rules, and new accounts or sudoers entries.

## Judging a persistence write
Ask who wrote it, where the target points and whether it is signed. Installers writing signed targets from Program Files are normal. A script host, shell or office process writing a Run key that points at a temp, AppData or hidden path is suspicious.

## Persistence plus execution
Persistence created within minutes of a first-seen download or injection event is a strong sign of a live intrusion. Check for the same payload hash across several mechanisms, since attackers often install redundant footholds.

## Removal guidance
Collect the artifact, record its content, remove the autostart entry and then the payload; remove all redundant entries to prevent return. Investigate how the writing process was started.
