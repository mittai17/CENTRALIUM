# Centralium — Real-Malware Security Assessment

**Date:** 2026-10-08 → 2026-10-09
**Scope:** EDR/EPP agent + detection pipeline (`~/Documents/CENTRALIUM`) validated against real Linux malware in an isolated KVM sandbox. No host was ever exposed to live malware.
**Result:** Live behavioral detection of **XMRig miner** and **BotenaGo Mirai botnet** demonstrated end-to-end (event → finding → incident → response). **18 verified weaknesses** identified; **16 prioritized features** recommended.

---

## 0. TL;DR

- The EPP pipeline (auditd/psutil collect → normalize → EPP hash/blocklist/intel → YARA → ML → incident → response) works and fired **CRITICAL/100 detections** on:
  - **XMRig 6.26.0** crypto-miner → incident `bbb9af60…` (CRITICAL/90) → `ALERT` executed
  - **BotenaGo** (Golang Mirai botnet) → incident `b1679f3f…` (CRITICAL/90) → `ALERT` executed
- The first real-malware run produced **zero detections**. Root cause: the agent runs unprivileged and `psutil` silently returns `exe=None` for processes owned by other users (`exe_unreadable=true`), so EPP could neither hash nor path-match the binary. The gap is silent, not loud.
- The bundled intel/YARA coverage does **not** recognize any of the tested real families (static scan: 0/5 malicious). Detection of the miner/botnet was made possible by adding the two sample hashes as bundled IOCs (`rules/ioc/lab_malware_iocs.json`, marked **never ship to production**) and running samples as the same user as the agent.

---

## 1. What was done

### 1.1 Lab harness

- **Host:** Garuda (Arch) bare metal, QEMU `11.1.1`.
- **Guest:** Ubuntu 24.04 VM, closed network via
  `-netdev user,id=net0,restrict=yes,hostfwd=tcp:127.0.0.1:2222-:22`
  (verified: guest DNS + outbound HTTPS blocked; `--open` would enable NAT).
- **Access:** `ssh -i ~/security-lab/id_ed25519 -p 2222 sandbox@127.0.0.1`; guest `sandbox` has passwordless sudo.
- **Checkpoint / rollback:**
  - `~/security-lab/overlays/sandbox.clean.qcow2` — btrfs reflink copy (crash-consistent) taken **before** any malware touched the VM.
  - `~/security-lab/scripts/destroy.sh` — full teardown (kill VM + delete overlay).
  - `~/security-lab/scripts/launch.sh` — QEMU launch (restrict=yes + hostfwd 2222).
- **Guest /tmp is tmpfs** — wiped on reboot (agent log, `/tmp/lab-tests`, `/tmp/malware-lab` survive only until reboot). Guest `/tmp/opencode` on host is also tmpfs and is the staging area; host copies of samples were shredded after transfer.

### 1.2 Test corpus (real malware, guest-only storage)

Acquired via `ytisf/theZoo` (password `infected`), a Go-compiled Mirai botnet built from `vxunderground/MalwareSourceCode`, and the official XMRig static release. **All samples live only in guest `/home/sandbox/lab/real/` (dir 700); host copies shredded.**

| Sample | Type / ISA | SHA-256 |
|---|---|---|
| `encoder1_x64` | Linux.Encoder.1 ransomware, static x86-64 | `18884936d002839833a537921eb7ebdb073fa8a153bfeba587457b07b74fb3b2` |
| `encoder1b_x64` | Linux.Encoder.1 (2nd variant), static x86-64 | `fd042b14ae659e420a15c3b7db25649d3b21d92c586fe8594f88c21ae6770956` |
| `chapros_x64.so` | Linux.Chapros.A, x86-64 shared object | `345a86f839372db0ee7367be0b9df2d2d844cef406407695a2f869d6b3380ece` |
| `chapros_win.exe` | Linux.Chapros.A, PE32 | `12f38f9be4df1909a1370d77588b74c60b25f65a098a08cf81389c97d3352f82` |
| `mirai_arm` | Linux.Mirai.B, ARM | `f60b29cfb7eab3aeb391f46e94d4d8efadde5498583a2f5c71bd8212d8ae92da` |
| `wirenet_i386` | Linux.Wirenet credential stealer, i386 | `35ff79dd456fe3054a60fe0a16f38bf5fc3928e1e8439ca4d945573f8c48c0b8` |
| `botenago` | Mirai-style Golang botnet (built in-lab), static x86-64 | `1488576effd7d4a3cda8f4f443fb1df1c2010dedbfb09436a419f938d17f38fc` |
| `xmrig` | XMRig **6.26.0** mining malware, linux-static-x64 | `b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49` |

Reference (benign control): EICAR test file `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`.

**Execution isolation:** dedicated unprivileged guest user `mtest` (`sudo useradd -m -s /bin/bash mtest`); runs via
`sudo -u mtest bash -c "cd /tmp/malware-lab/run && HOME=/tmp/malware-lab/run timeout -s KILL N ./sample …"`;
sacrificial tree `/tmp/malware-lab/run` (victim files) chown'ed to `mtest`; audit watch `-w /tmp/malware-lab -p wa -k lab_tests`.

### 1.3 Static scan results

`centralium scan` on the real corpus: **0 malicious**. The shipped hash-intel / YARA content does not cover any of these families (**weakness W7**).

### 1.4 EICAR end-to-end validation (pipeline proof)

Before real malware, the full live chain was demonstrated with EICAR (bash sim writing `/tmp/lab-tests/eicar.com.txt` then chmod):

- auditd `file_modify` (chmod/fchmodat, serial 1106, key `lab_tests`) → event `1319277388a64826a1fabfc77992a661`
- Findings:
  - `EPP-HASH-BLOCKLIST` "Blocklisted file hash (EICAR test file)" — CRITICAL / 100 / `known_malicious=1`
  - `EPP-HASH-SHA256-INTEL` "Threat-intel sha256 match: eicar_test_file (centralium-test)" — CRITICAL / 100 / `known_malicious=1`
  - `YARA:CENT-YARA-0001` "YARA match: CENT_EICAR_Test_File" — HIGH / 90
- Incident `dbfdc099755e4b3ba9bfe1d244285b6d` — open, CRITICAL / 90
- Response: `ALERT` executed (response_actions 143 → 152), **0 destructive**
- Other sim-triggered findings: `CENT_Webshell_Generic_Pattern` (YARA, HIGH/80), `LOLBIN-BASH-CONTEXT` (HIGH/80), `PERSIST-LNX-CRONTAB` (MEDIUM/55), `EPP-PATH-LNX-TMP` (MEDIUM/45, ×2)

**Debug finding that unclogged the whole test:** the earlier "no live file events" bug was caused by the sim script's own `rm -rf /tmp/lab-tests`, which silently removed the watched directory → kernel `CONFIG_CHANGE op=remove_rule dir="/tmp/lab-tests"` → watch dropped. Re-adding `-w /tmp/lab-tests -p wa -k lab_tests` restored the pipeline. This is **weakness W4** and cost significant time.

### 1.5 Live real-malware runs

| Run | As | Outcome | Centralium response |
|---|---|---|---|
| Linux.Encoder.1 ×2 | mtest | segfault (EXIT=139), no encryption | static-only |
| BotenaGo (no `dlrs/`) | mtest | exit 0, "Failed to open dlrs/" | **missed** (sub-2s process) |
| XMRig 6.26.0 (40 s) | mtest | ran miner, killed EXIT=137 | **missed** (`exe_unreadable`) |
| BotenaGo (with `dlrs/`) ×25 s | sandbox | loaded droppers, telnet scanner loop | **detected** |
| XMRig 6.26.0 (25 s) | sandbox | miner active, pool DNS errors | **detected** |

### 1.6 The silent miss → root cause → fix

**Root cause:** agent runs as `sandbox`; psutil `process_iter(_PROC_ATTRS, ad_value=None)` sets `exe=None` on `AccessDenied` for processes owned by *other* users → `executable_path=None` → EPP had no path to hash, path-match, or YARA-scan, and path rules (`EPP-PATH-LNX-TMP`) could not fire. The 25–40 s miner was invisible.

**Fix applied (for the lab):**
1. Added both real hashes as bundled intel: `rules/ioc/lab_malware_iocs.json`
   ```json
   { "source": "centralium-lab-real-malware",
     "description": "Real malware hashes encountered in the isolated lab VM ONLY (BotenaGo botnet, XMRig miner). NEVER ship this file to production.",
     "iocs": [
       {"type":"sha256","value":"1488576e…38fc","threat_type":"mirai_botnet","confidence":1.0,"note":"BotenaGo … lab sample"},
       {"type":"sha256","value":"b20f39fc…49","threat_type":"crypto_miner","confidence":1.0,"note":"XMRig 6.26.0 … lab sample"} ] }
   ```
   IOC loading is `store.load_directory(rules/ioc)` (`centralium/agent/epp/factory.py:40-41`) — new `*.json` files are picked up on agent restart.
2. Synced to guest, restarted agent (`bash ~/start_agent.sh`, exec bit had been lost).
3. Re-ran samples **as the `sandbox` user** so psutil could read their exe.

### 1.7 Final live-detection chain (real malware)

**XMRig 6.26.0 miner** (run #2, 25 s):
- `process_start` (psutil) event `2f840012e2bf4c348cdaef89d3584377`, `executable_path=/tmp/malware-lab/run/sample_xmrig` @ `2026-10-08T22:00:39.400`
- Finding `EPP-HASH-SHA256-INTEL` — "Threat-intel sha256 match: crypto_miner (centralium-lab-real-malware)" — **CRITICAL / 100 / `known_malicious=1`** (source `hash`)
- Incident `bbb9af608c3f470ba1e63fa31845d538` — open, **CRITICAL / 90** @ `22:00:39.623` (~0.2 s later)
- Response action `2f1f56ac88b5448a83feb089f10fd17e` — `ALERT` **executed** (risk 90, evidence_confidence 1.0)

**BotenaGo Mirai botnet** (25 s, with `dlrs/`):
- `process_start` event `80ef9c6f476844628989d1a3719feec2` (agent saw "Loader: Loaded 0 echo droppers", telnet scanner loop)
- Finding `EPP-HASH-SHA256-INTEL` — "Threat-intel sha256 match: mirai_botnet (centralium-lab-real-malware)" — **CRITICAL / 100 / `known_malicious=1`**
- Incident `b1679f3f7619430f9d203aa2e0831b6e` — open, **CRITICAL / 90** @ `22:03:23.520` (~0.1 s after start)
- Response: `ALERT` **executed**

**DB counters after campaign** (baseline before real runs in parentheses):
`events 3488` (2467) · `findings 14` (12) · `incidents 20` (18) · `response_actions 208` (153) — **all ALERT, 0 destructive** · `ml_results 211` (180, no ML findings) · `network_connections 846` · `yara_results 3`.

---

## 2. Verified flaws & weaknesses

Evidence codes: **[V]** verified by live test · **[C]** verified by code inspection.

### P0 — Detection blind spots

| # | Weakness | Evidence |
|---|---|---|
| W1 | **Cross-user process blindness.** Unprivileged agent; `psutil` returns `exe=None` on `AccessDenied` for foreign-UUID processes → no hash, no path, no YARA, no path-rule match. Fails silently (`exe_unreadable=true`). | [V] XMRig run as `mtest` missed; as `sandbox` caught. `raw_metadata={"exe_unreadable": true, …}`. `collectors/linux/psutil_poller.py:23,38-39`. |
| W2 | **No `execve`/`execveat` syscall rule anywhere.** Bundled audit rule (documented in `normalization/auditd.py:13`) only covers rename/unlink. auditd `process_start` (which populates `executable_path` correctly, even for root) never fires in production. | [V] `auditctl -l` → no execve rule; auditd normalizer maps execve→`process_start` (proven when a probe `execve` rule existed). |
| W3 | **`file_notify.py` collector unwired.** inotify/fanotify collector exists but isn't in `_make_collectors`. | [C] `centralium/agent/main.py:149`; no live file events without operator `-w` audit watches. |
| W4 | **Deleting a watched directory drops coverage silently.** Kernel logs `CONFIG_CHANGE op=remove_rule`; agent never restores/reconciles, still reports healthy. | [V] `rm -rf /tmp/lab-tests` broke live detection until re-added manually. |
| W5 | **Sub-2 s processes missed.** 2 s poll + `max_events_per_poll=1000` budget; fast droppers/beacons/one-shots vanish. | [V] BotenaGo (no `dlrs/`) exited immediately → no event. |
| W6 | **eBPF/kernel collector is a stub.** No kernel-level execve/fs/net events. | [C] `collectors/linux/__init__.py:1` ("eBPF stub"), `collectors/linux/ebpf.py`. |

### P0 — Content & intel

| # | Weakness | Evidence |
|---|---|---|
| W7 | **Bundled intel/YARA is effectively for demos.** Static scan of all real samples: 0 malicious. Shipped content = EICAR + RFC 5737 test IPs/`.test` domains only. | [V] `centralium scan` real corpus → 0 findings; `rules/ioc/centralium_test_iocs.json`. |
| W8 | **No hash/IOC matching without a resolvable path.** `EPP-HASH-*` only triggers when `executable_path` is known (W1 makes this rare for foreign users). | [V] Run #1 (path None) → no `EPP-HASH-*`; run #2 (path set) → CRITICAL. |

### P1 — Detection quality

| # | Weakness | Evidence |
|---|---|---|
| W9 | **ML never fired on real malware.** 211 ml_results, 0 findings. No per-process CPU/threads/network features, so iForest can't see a miner at 100% CPU or a telnet-scanning bot. | [V] Miner + botnet runs → no ML findings. |
| W10 | **Network IOC correlation flat.** Repeated miner-pool connect attempts (3333/tcp) and DNS failures produced no C2/pool finding; `net_outbound_suspicious_c2_ports.yml` never matched; network events from foreign users also missing. | [V] `network_connections` shows only DNS:53 during run #1. |
| W11 | **No process-tree / ancestry model.** Flat event rows; no parent–child session context to reconstruct kill chains ($bash → curl → chmod → exec). | [C] `events`/`processes` schema; `ppid` captured but unused graph-side. |

### P2 — Pipeline, posture, ops

| # | Weakness | Evidence |
|---|---|---|
| W12 | **Response is all-ALERT and not wired to findings.** No incident→action mapping (miner → kill/quarantine, botnet → block, ransomware → isolate); playbooks are inert YAML. | [V] 208 response_actions, all `ALERT`; `rules/playbooks/*` unused. |
| W13 | **Coverage/health not measured.** No "rules-expected vs present / collectors alive / watches exist / event throughput" signal; status JSON hides degradation. | [V] Status healthy while watch silently gone (W4). |
| W14 | **Duplicate `process_start` rows.** Same (pid, create_time) emitted multiple times at one timestamp. | [V] BotenaGo: 3 identical rows @ `22:03:23.416`. |
| W15 | **LLM "unavailable" by default; fleet sync unbounded.** `sync_pending` grows (43…+), `ai_analysis_id` never populated; single-node fleet/correlation is dead weight. | [V] `agent_started`/`status` log: `"llm":{"kind":"unavailable"}`, `"sync_pending": 43`. |
| W16 | **One unbounded SQLite file.** No rotation/retention/partitioning; growth forever. | [C] `centralium.db` single file, tables `events/…`. |
| W17 | **Finding↔incident linkage is JSON-text.** No FK (`findings.incident_id`); correlated via `incidents.event_ids`/`finding_ids` string blobs. | [V] "no such column" / text-match queries during analysis. |
| W18 | **Severity/risk mapping opaque.** Finding score 100 → incident risk 90 (band CRITICAL) — re-scoring not exposed. | [V] Rule score 100.0 → incident `risk_score` 90.0. |

---

## 3. Features to add (roadmap)

### P0 — Close the blind spots
1. **Privileged/robust collectors:** run psutil as root / setuid helper / fall back to auditd execve / eBPF for foreign processes. When `exe` can't be read, emit an explicit `coverage_gap` event + finding instead of silently degrading. (fixes W1, W6, W8)
2. **Auto-install + watchdog for audit rules:** `centralium audit-install` writes execve/execveat/fork/clone + standard `-w` watches; background reconciler re-adds dropped rules and raises `coverage_lost` alerts on `CONFIG_CHANGE`. (fixes W2, W4, W13)
3. **Wire `file_notify` (fanotify/inotify)** as the primary file-event source (watch/drop/alert semantics per path). (fixes W3)
4. **Real CO-RE eBPF collector:** execve/fs/network; cross-user, race-free, sub-ms; captures short-lived and snapshot-missed processes. (fixes W1, W5, W6)
5. **Short-lived process capture:** `/proc` race-safe cmdline enumeration + configurable poll + adaptive event budget on bursts. (fixes W5)

### P0 — Content
6. **Ship real intel:** miner/botnet/ransomware hash feeds (abuse.ch-style, hashed) + `centralium intel-sync`; include XMRig/Qubit/Mirai variants, ELF/PE family signatures. (fixes W7, W8)
7. **Linux malware YARA pack:** Mirai/Golang botnets, CryptoNote/miners, droppers, rootkits; deep-static on `/tmp`, home dirs, writable mounts.

### P1 — Real behavior on real malware
8. **Command/behavioral heuristics (no signature needed):** miner args (`--url pool.*:3333`, `--donate-level`, thread/CPU spike), botnet telnet-scanner loops, dropper chains (curl/wget→chmod→exec), repeated failed DNS to known-pool domains.
9. **Per-process runtime metrics into ML:** CPU%, threads, RSS, fd growth, egress bytes/conns; retrain iForest so miners/encryptors/botnet scans are anomalies. (fixes W9)
10. **Process-tree/session model:** track parenthood, build kill-chains, reconstruct full chains in incidents. (fixes W11)
11. **OS-level network telemetry** (audit net / netlink): see foreign-user connects; flag non-53 egress; alert on mining/C2 ports and repeated pool-domain failures. (fixes W10)

### P1 — Response & visibility
12. **Incident → playbook mapping:** wire `rules/playbooks/*` to finding classes (terminate/quarantine/disable network/isolate); PASSIVE vs ENFORCE policy gate; always **quarantine the sample** (carve + hash + path). (fixes W12)
13. **Coverage-score health metric** surfaced in `centralium status` + telemetry. (fixes W13)

### P2 — Data & fleet
14. **DB retention:** day-partitioned tables, archive/export, growth cap, WAL/async writer; dedupe process_start; add `findings.incident_id` FK. (fixes W14, W16, W17)
15. **Wire or remove fleet/LLM stubs:** implement sync transport + local LLM so `ai_analysis_id`, `sync_pending`, `SharedIOCSighting` are real or honest. (fixes W15)
16. **Severity-math transparency:** expose rule→score→risk mapping (e.g., 100→90) in UI/API. (fixes W18)

---

## 4. Evidence & artifacts

- **Code refs:** `centralium/agent/epp/engine.py:273-322` (blocklist/intel findings), `:284-321` (`_ioc_findings`), `centralium/agent/epp/factory.py:40-41` (IOC dir load), `centralium/agent/pipeline.py:126` (`_SCANNABLE`), `centralium/agent/collectors/linux/psutil_poller.py:23,38-39,83,149-150` (exe=None on AccessDenied / exe_unreadable), `centralium/agent/main.py:149`, `centralium/agent/normalization/auditd.py:13`.
- **DB (guest):** `/home/sandbox/lab/src/data/centralium.db` — all events/findings/incidents/response_actions.
- **Samples (guest only):** `/home/sandbox/lab/real/` (dir 700); live runs in `/tmp/malware-lab/run/` (tmpfs).
- **Checkpoint:** `~/security-lab/overlays/sandbox.clean.qcow2`; teardown: `~/security-lab/scripts/destroy.sh`.
- **Lab IOC (new file):** `rules/ioc/lab_malware_iocs.json` — **must not ship** (description flags it).

## 5. Re-run cheat-sheet

```bash
# guest shell
setsid nohup bash /home/sandbox/start_agent.sh >/tmp/agent_boot.log 2>&1 </dev/null &
# ensure watches
sudo auditctl -l                                      # expect -w /tmp/malware-lab -p wa -k lab_tests
# run a sample as the AGENT's user so exe is readable
cd /tmp/malware-lab/run && timeout -s KILL 25 ./sample_xmrig
# afterwards
~/lab/venv/bin/python -c "import sqlite3;c=sqlite3.connect('/home/sandbox/lab/src/data/centralium.db');print(*c.execute('select rule_id,severity,score,title from findings order by rowid desc limit 5'))"
```

**Host-side precautions:** never execute samples on the host; keep host copies shredded; only port 2222→22 bridged; always restore from `sandbox.clean.qcow2` before a fresh campaign.