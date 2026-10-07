"""Project normalized events into the derived dashboard tables.

``Repository.add_event`` only writes ``events``.  The SOC dashboard's process explorer, network
and malware pages read ``processes`` / ``network_connections`` / ``dns_events`` / ``files``;
this module fills them (parameterized SQL only, idempotent via the table keys).
"""

from __future__ import annotations

import math
from collections import Counter

from centralium.agent.models import EventType, NormalizedEvent
from centralium.agent.storage.database import Database

_FILE_EVENTS = {EventType.FILE_CREATE, EventType.FILE_MODIFY, EventType.FILE_RENAME, EventType.FILE_DELETE}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def project_event(db: Database, ev: NormalizedEvent) -> None:
    ts = ev.timestamp.isoformat()
    et = ev.event_type
    if et == EventType.PROCESS_START and ev.pid is not None:
        db.insert(
            "processes",
            {
                "host_id": ev.host_id,
                "pid": ev.pid,
                "start_time": ts,
                "ppid": ev.ppid,
                "name": ev.process_name,
                "executable_path": ev.executable_path,
                "command_line": ev.command_line,
                "user": ev.user,
                "hash_sha256": ev.hash_sha256,
                "signer": ev.signer,
                "first_event_id": ev.event_id,
            },
            on_conflict="IGNORE",
        )
    elif et == EventType.PROCESS_EXIT and ev.pid is not None:
        db.execute(
            "UPDATE processes SET end_time = ? WHERE host_id = ? AND pid = ? AND end_time IS NULL",
            (ts, ev.host_id, ev.pid),
        )
    elif et in (EventType.NETWORK_CONNECT, EventType.NETWORK_LISTEN) and ev.destination_ip:
        db.insert(
            "network_connections",
            {
                "event_id": ev.event_id,
                "timestamp": ts,
                "host_id": ev.host_id,
                "pid": ev.pid,
                "process_name": ev.process_name,
                "destination_ip": ev.destination_ip,
                "destination_port": ev.destination_port,
                "protocol": ev.protocol,
                "domain": ev.domain,
            },
        )
    elif et == EventType.DNS_QUERY and ev.domain:
        resolved = ev.raw_metadata.get("resolved_ips")
        db.insert(
            "dns_events",
            {
                "event_id": ev.event_id,
                "timestamp": ts,
                "host_id": ev.host_id,
                "pid": ev.pid,
                "domain": ev.domain,
                "resolved_ips": ",".join(str(x) for x in resolved) if isinstance(resolved, list) else None,
                "entropy": _entropy(ev.domain.split(".")[0]),
            },
        )
    elif et in _FILE_EVENTS and ev.file_path:
        ent = ev.raw_metadata.get("entropy_after", ev.raw_metadata.get("entropy"))
        db.execute(
            "INSERT INTO files (path, hash_sha256, size, entropy, file_type, first_seen, "
            "last_seen, event_id) "
            "VALUES (?, ?, NULL, ?, ?, ?, ?, ?) "
            "ON CONFLICT(path, hash_sha256) DO UPDATE SET last_seen = excluded.last_seen, "
            "event_id = excluded.event_id",
            (
                ev.file_path,
                ev.hash_sha256 or "",  # '' (not NULL) so UNIQUE(path, hash) de-duplicates
                float(ent) if isinstance(ent, (int, float)) and not isinstance(ent, bool) else None,
                et.value,
                ts,
                ts,
                ev.event_id,
            ),
        )
