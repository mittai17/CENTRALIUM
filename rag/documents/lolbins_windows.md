---
source: lolbin
title: Windows living-off-the-land binaries
tags: lolbin, windows
---
## certutil
Certificate utility often abused to download and decode payloads. Dangerous forms: -urlcache -f with a URL, -decode of a text file into an executable, -encode for staging. Benign use is certificate management with no URL or output executable. Related techniques: T1105, T1140.

## mshta
Runs HTA and script content. Dangerous when given an http(s) URL or inline vbscript or javascript, or when launched by a document reader or mail client. Rare in normal environments. Related technique: T1218.005.

## rundll32
Loads DLL exports. Dangerous when loading a DLL from temp, AppData or a network path, using javascript: or comsvcs.dll MiniDump for credential dumping, or when run with no arguments. Related techniques: T1218.011, T1003.001.

## regsvr32
Registers COM libraries. Dangerous with /i:URL and scrobj.dll (scriptlet fetch) or /s with an unknown DLL. Related technique: T1218.010.

## bitsadmin
Legacy BITS control tool. Dangerous with /transfer from an external URL or /SetNotifyCmdLine to run a command. Related technique: T1197.

## powershell
Scripting shell. Dangerous: -enc, -EncodedCommand, -w hidden, -nop, IEX, DownloadString, Invoke-WebRequest into a temp path, AMSI bypass strings. Parent matters: Office, browser or WMI parents are suspicious. Related technique: T1059.001.

## wmic
WMI command line. Dangerous: process call create, shadowcopy delete, remote /node execution, xsl script loading. Related techniques: T1047, T1490.

## schtasks and sc
Create persistence or remote execution: schtasks /create with SYSTEM or a temp path, sc create with binPath to a script interpreter. Related techniques: T1053.005, T1543.003.

## vssadmin, wbadmin and bcdedit
Recovery-inhibition commands: vssadmin delete shadows /all, wbadmin delete catalog, bcdedit /set recoveryenabled no. Strong ransomware precursors when not run by backup software. Related technique: T1490.

## msbuild, installutil and cscript
Compile or run attacker code from trusted binaries: msbuild with inline task XML from temp, installutil /U on a dropped assembly, cscript or wscript running scripts from downloads. Related technique: T1127 and T1059.

## forfiles, pcalua and cmstp
Obscure proxy-execution launchers that run a command indirectly. Treat unusual use with a command argument and a user-writable path as suspicious.
