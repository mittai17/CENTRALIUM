"""SQLite schema + ordered migrations. Append new migrations; never edit old ones."""

from __future__ import annotations

# Each migration is a list of SQL statements (no user data, so no parameters needed).
MIGRATIONS: list[tuple[int, str, list[str]]] = [
    (
        1,
        "initial schema",
        [
            """CREATE TABLE events (
                event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
                host_id TEXT, user TEXT, pid INTEGER, ppid INTEGER, process_name TEXT,
                executable_path TEXT, command_line TEXT, parent_process TEXT, hash_sha256 TEXT,
                signer TEXT, file_path TEXT, destination_ip TEXT, destination_port INTEGER,
                domain TEXT, protocol TEXT, registry_key TEXT, source TEXT, confidence REAL,
                raw_metadata TEXT)""",
            "CREATE INDEX idx_events_ts ON events(timestamp)",
            "CREATE INDEX idx_events_type ON events(event_type)",
            "CREATE INDEX idx_events_pid ON events(host_id, pid)",
            "CREATE INDEX idx_events_hash ON events(hash_sha256)",
            """CREATE TABLE processes (
                host_id TEXT NOT NULL, pid INTEGER NOT NULL, start_time TEXT NOT NULL,
                ppid INTEGER, name TEXT, executable_path TEXT, command_line TEXT, user TEXT,
                hash_sha256 TEXT, signer TEXT, end_time TEXT, first_event_id TEXT,
                PRIMARY KEY (host_id, pid, start_time))""",
            """CREATE TABLE files (
                file_id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT NOT NULL, hash_sha256 TEXT,
                size INTEGER, entropy REAL, file_type TEXT, first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL, event_id TEXT, UNIQUE(path, hash_sha256))""",
            """CREATE TABLE network_connections (
                conn_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, timestamp TEXT NOT NULL,
                host_id TEXT, pid INTEGER, process_name TEXT, destination_ip TEXT,
                destination_port INTEGER, protocol TEXT, domain TEXT)""",
            "CREATE INDEX idx_net_dst ON network_connections(destination_ip)",
            """CREATE TABLE dns_events (
                dns_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, timestamp TEXT NOT NULL,
                host_id TEXT, pid INTEGER, domain TEXT NOT NULL, resolved_ips TEXT, entropy REAL)""",
            "CREATE INDEX idx_dns_domain ON dns_events(domain)",
            """CREATE TABLE findings (
                finding_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, timestamp TEXT NOT NULL,
                source TEXT NOT NULL, rule_id TEXT NOT NULL, title TEXT, severity TEXT,
                score REAL, confidence REAL, known_malicious INTEGER DEFAULT 0,
                mitre_techniques TEXT, attack_stage TEXT, details TEXT, incident_id TEXT)""",
            "CREATE INDEX idx_findings_event ON findings(event_id)",
            """CREATE TABLE incidents (
                incident_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                host_id TEXT, title TEXT, status TEXT, risk_score REAL, band TEXT,
                attack_stage TEXT, mitre_techniques TEXT, event_ids TEXT, finding_ids TEXT,
                summary TEXT, ai_analysis_id TEXT, actions TEXT)""",
            """CREATE TABLE ioc_cache (
                ioc_type TEXT NOT NULL, value TEXT NOT NULL, source TEXT NOT NULL,
                threat_type TEXT, confidence REAL, first_seen TEXT, last_seen TEXT,
                expires_at TEXT, metadata TEXT, PRIMARY KEY (ioc_type, value, source))""",
            """CREATE TABLE yara_results (
                result_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, timestamp TEXT NOT NULL,
                target_path TEXT, hash_sha256 TEXT, rule_id TEXT, rule_name TEXT, family TEXT,
                severity TEXT, matched_strings TEXT)""",
            """CREATE TABLE ml_results (
                result_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL,
                timestamp TEXT NOT NULL, anomaly_score REAL, classification TEXT,
                classification_confidence REAL, top_features TEXT, model_version TEXT,
                feature_version TEXT, latency_ms REAL)""",
            """CREATE TABLE ai_analysis (
                analysis_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, timestamp TEXT NOT NULL,
                available INTEGER, role TEXT, model_name TEXT, verdict_json TEXT,
                latency_ms REAL, rag_sources TEXT, error TEXT)""",
            """CREATE TABLE response_actions (
                action_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, action TEXT NOT NULL,
                status TEXT NOT NULL, target TEXT, detail TEXT, event_id TEXT, incident_id TEXT)""",
            """CREATE TABLE policies (
                policy_id TEXT PRIMARY KEY, name TEXT NOT NULL, version INTEGER DEFAULT 1,
                enabled INTEGER DEFAULT 1, body TEXT NOT NULL, updated_at TEXT NOT NULL)""",
            """CREATE TABLE allowlist (
                entry_id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, value TEXT NOT NULL,
                reason TEXT, added_by TEXT, added_at TEXT NOT NULL, expires_at TEXT,
                UNIQUE(kind, value))""",
            """CREATE TABLE blocklist (
                entry_id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, value TEXT NOT NULL,
                reason TEXT, added_by TEXT, added_at TEXT NOT NULL, expires_at TEXT,
                UNIQUE(kind, value))""",
            """CREATE TABLE audit_log (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, actor TEXT NOT NULL,
                event_type TEXT NOT NULL, details TEXT NOT NULL, prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL)""",
            """CREATE TABLE sync_queue (
                queue_id INTEGER PRIMARY KEY AUTOINCREMENT, dedup_key TEXT UNIQUE,
                payload TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT, last_error TEXT,
                delivered_at TEXT)""",
            "CREATE INDEX idx_sync_status ON sync_queue(status, next_attempt_at)",
            """CREATE TABLE rag_metadata (
                doc_id TEXT PRIMARY KEY, source TEXT NOT NULL, title TEXT, text_sha256 TEXT,
                embedding_model TEXT, ingested_at TEXT NOT NULL, metadata TEXT)""",
        ],
    ),
    (
        2,
        "graph snapshots for the dashboard (JSON {nodes, edges})",
        [
            """CREATE TABLE graph_snapshots (
                snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT, host_id TEXT, created_at TEXT NOT NULL,
                node_count INTEGER, edge_count INTEGER, snapshot TEXT NOT NULL)""",
        ],
    ),
    (
        3,
        "analyst feedback and suggestions",
        [
            """CREATE TABLE analyst_feedback (
                feedback_id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, event_id TEXT NOT NULL,
                analyst TEXT NOT NULL, feedback_type TEXT NOT NULL, comment TEXT,
                created_at TEXT NOT NULL, rule_id TEXT, severity TEXT,
                features_snapshot TEXT, provenance TEXT, status TEXT NOT NULL DEFAULT 'recorded')""",
            "CREATE INDEX idx_feedback_finding ON analyst_feedback(finding_id)",
            "CREATE INDEX idx_feedback_event ON analyst_feedback(event_id)",
            """CREATE TABLE feedback_suggestions (
                suggestion_id TEXT PRIMARY KEY, feedback_id TEXT NOT NULL, kind TEXT NOT NULL,
                target_type TEXT NOT NULL, target_value TEXT NOT NULL, reason TEXT,
                status TEXT NOT NULL DEFAULT 'PENDING_REVIEW', created_at TEXT NOT NULL,
                applied_at TEXT, applied_by TEXT,
                FOREIGN KEY (feedback_id) REFERENCES analyst_feedback(feedback_id))""",
            "CREATE INDEX idx_suggestions_status ON feedback_suggestions(status)",
        ],
    ),
]

LATEST_VERSION: int = MIGRATIONS[-1][0]

# Tables writable through the generic repository helpers (identifier whitelist).
TABLES: frozenset[str] = frozenset(
    {
        "events",
        "processes",
        "files",
        "network_connections",
        "dns_events",
        "findings",
        "incidents",
        "ioc_cache",
        "yara_results",
        "ml_results",
        "ai_analysis",
        "response_actions",
        "policies",
        "allowlist",
        "blocklist",
        "audit_log",
        "sync_queue",
        "rag_metadata",
        "graph_snapshots",
        "analyst_feedback",
        "feedback_suggestions",
    }
)
