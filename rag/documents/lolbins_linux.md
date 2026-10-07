---
source: lolbin
title: Linux living-off-the-land binaries
tags: lolbin, linux
---
## curl and wget
Downloaders. Dangerous: piping output to sh or bash, saving into /tmp, /dev/shm or hidden directories then chmod +x and executing, fetching from raw IP addresses, silent flags in cron jobs. Related technique: T1105.

## bash and sh reverse shells
Dangerous: redirection to /dev/tcp/HOST/PORT, interactive flags with file descriptor duplication, shells whose parent is a web server, database or cron with no TTY. Related technique: T1059.004.

## nc, ncat and socat
Network relays used for reverse and bind shells and file transfer. Dangerous with -e or exec options, or listening on high ports on servers. Related technique: T1059.004.

## python, perl and ruby one-liners
Inline interpreters with socket and subprocess imports build reverse shells; also used to spawn a TTY. Dangerous: -c with socket, pty.spawn, base64 decode and exec. Related technique: T1059.006.

## find, awk, vim and less shell escapes
Binaries that can run commands (find -exec, awk system, editors with shell escape). When run through a SUID bit or sudo they provide privilege escalation. Related technique: T1548.003.

## base64 and openssl
Decode staged payloads (base64 -d piped to sh) or encrypt data before exfiltration. Related techniques: T1140, T1560.

## tar, zip and gzip
Archive data before exfiltration; suspicious when they pack home, ssh, cloud credential or database directories into /tmp. Related technique: T1560.

## chmod, chattr and setcap
Make payloads executable, immutable (chattr +i on cron or authorized_keys) or grant capabilities for privilege retention.

## systemctl, crontab and at
Install persistence. Dangerous: enabling a unit created moments earlier from a temp path, crontab piped from stdin. Related techniques: T1543.002, T1053.003.

## ssh and scp
Lateral movement and tunnelling: ssh -R or -D from servers, scp of data to unknown hosts. Related technique: T1021.004.

## history clearing
history -c, unset HISTFILE, truncating .bash_history. Related technique: T1070.003.
