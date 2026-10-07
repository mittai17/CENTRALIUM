"""Windows normalizers: Sysmon, Windows Event Log (XML/JSON) and ETW-shaped dicts.

Pure parsing - these run on any OS (tests use recorded samples). XML is parsed with the
stdlib after rejecting DOCTYPE/ENTITY declarations (XXE / entity-expansion hardening).
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from centralium.agent.models import EventType, NormalizedEvent
from centralium.agent.normalization.common import (
    MAX_CMD,
    basename_any,
    canon_domain,
    canon_ip,
    canon_path,
    canon_port,
    canon_sha256,
    clean_str,
    make_event,
    parse_ts,
    pick,
    safe_meta,
    to_int,
)

MAX_XML = 1_000_000


@dataclass
class WinRecord:
    event_id: int | None
    provider: str = ""
    channel: str = ""
    computer: str | None = None
    time: Any = None
    record_id: int | None = None
    user_sid: str | None = None
    pid: int | None = None
    data: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- parsing
def _safe_xml(xml_text: str) -> ET.Element:
    if len(xml_text) > MAX_XML:
        raise ValueError("event XML too large")
    low = xml_text[:4096].lower()
    if "<!doctype" in low or "<!entity" in xml_text.lower():
        raise ValueError("DOCTYPE/ENTITY declarations rejected")
    try:
        return ET.fromstring(xml_text)  # noqa: S314 - DOCTYPE/ENTITY rejected above
    except ET.ParseError as exc:
        raise ValueError(f"malformed event XML: {exc}") from exc


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def split_event_xml(blob: str) -> list[str]:
    """Split a wevtutil multi-event XML stream into individual ``<Event>`` documents."""
    return re.findall(r"<Event[\s>].*?</Event>", blob, flags=re.DOTALL)


def parse_event_xml(xml_text: str) -> WinRecord:
    root = _safe_xml(xml_text)
    rec = WinRecord(event_id=None)
    for el in root.iter():
        tag = _local(el.tag)
        if tag == "Provider":
            rec.provider = el.get("Name", "")
        elif tag == "EventID":
            rec.event_id = to_int((el.text or "").strip())
        elif tag == "TimeCreated":
            rec.time = el.get("SystemTime")
        elif tag == "EventRecordID":
            rec.record_id = to_int((el.text or "").strip())
        elif tag == "Channel":
            rec.channel = (el.text or "").strip()
        elif tag == "Computer":
            rec.computer = (el.text or "").strip() or None
        elif tag == "Security":
            rec.user_sid = el.get("UserID")
        elif tag == "Execution":
            rec.pid = to_int(el.get("ProcessID"))
        elif tag == "Data":
            name = el.get("Name")
            if name:
                rec.data[name] = (el.text or "").strip()
    return rec


def parse_event_json(raw: dict[str, Any]) -> WinRecord:
    ev: dict[str, Any] = raw["Event"] if isinstance(raw.get("Event"), dict) else raw
    sysd: dict[str, Any] = ev["System"] if isinstance(ev.get("System"), dict) else ev
    prov = pick(sysd, "Provider", "ProviderName")
    if isinstance(prov, dict):
        prov = prov.get("Name") or prov.get("@Name") or ""
    eid = pick(sysd, "EventID", "Id", "event_id")
    if isinstance(eid, dict):
        eid = eid.get("#text") or eid.get("Value")
    tc = pick(sysd, "TimeCreated", "TimeStamp", "Timestamp")
    if isinstance(tc, dict):
        tc = tc.get("SystemTime") or tc.get("@SystemTime")
    data = pick(ev, "EventData", "data", "Data", "UserData")
    if isinstance(data, dict) and "Data" in data and isinstance(data["Data"], list):
        flat: dict[str, Any] = {}
        for d in data["Data"]:
            if isinstance(d, dict) and d.get("Name"):
                flat[d["Name"]] = d.get("#text", "")
        data = flat
    if not isinstance(data, dict):
        data = {}
        for k in ("Image", "CommandLine", "ProcessId", "NewProcessName", "TargetFilename"):
            if k in ev:
                data[k] = ev[k]
    execn: dict[str, Any] = sysd["Execution"] if isinstance(sysd.get("Execution"), dict) else {}
    return WinRecord(
        event_id=to_int(eid),
        provider=str(prov or ""),
        channel=str(pick(sysd, "Channel") or ""),
        computer=clean_str(pick(sysd, "Computer", "MachineName")),
        time=tc,
        record_id=to_int(pick(sysd, "EventRecordID", "RecordId")),
        pid=to_int(pick(execn, "ProcessID", "@ProcessID")),
        data={str(k): v for k, v in data.items()},
    )


def _user(d: dict[str, Any], *names: str) -> str | None:
    u = clean_str(pick(d, *names))
    dom = clean_str(pick(d, "SubjectDomainName", "TargetDomainName"))
    if u and "\\" not in u and dom and dom != "-" and names and names[0].startswith("Subject"):
        return f"{dom}\\{u}"
    return u


def _hash(d: dict[str, Any]) -> str | None:
    return canon_sha256(pick(d, "Hashes", "Hash", "SHA256", "FileHash"))


def _base(rec: WinRecord, host: str, source: str) -> dict[str, Any]:
    return {
        "timestamp": parse_ts(rec.time),
        "host_id": clean_str(rec.computer, 255) or host,
        "source": source,
    }


# --------------------------------------------------------------------------- Sysmon
def normalize_sysmon(rec: WinRecord, host_id: str = "localhost") -> NormalizedEvent:
    d = rec.data
    eid = rec.event_id
    base = _base(rec, host_id, "sysmon")
    ts = base["timestamp"] or parse_ts(pick(d, "UtcTime"))
    base["timestamp"] = ts
    meta: dict[str, Any] = {"sysmon_event_id": eid, "record_id": rec.record_id}
    image = canon_path(pick(d, "Image", "SourceImage"))
    proc: dict[str, Any] = {
        "user": clean_str(pick(d, "User")),
        "pid": to_int(pick(d, "ProcessId", "SourceProcessId")),
        "process_name": basename_any(image),
        "executable_path": image,
    }

    def mk(et: EventType, **kw: Any) -> NormalizedEvent:
        merged = {**base, **proc, **kw}
        merged["raw_metadata"] = safe_meta({**meta, **merged.pop("meta", {})})
        return make_event(event_type=et, **merged)

    if eid == 1:
        meta.update(
            integrity_level=pick(d, "IntegrityLevel"),
            logon_id=pick(d, "LogonId"),
            original_file_name=pick(d, "OriginalFileName"),
            parent_command_line=pick(d, "ParentCommandLine"),
            parent_pid=pick(d, "ParentProcessId"),
            parent_image=pick(d, "ParentImage"),
            company=pick(d, "Company"),
        )
        return mk(
            EventType.PROCESS_START,
            ppid=to_int(pick(d, "ParentProcessId")),
            parent_process=basename_any(canon_path(pick(d, "ParentImage"))),
            command_line=clean_str(pick(d, "CommandLine"), MAX_CMD),
            hash_sha256=_hash(d),
        )
    if eid == 5:
        return mk(EventType.PROCESS_EXIT)
    if eid == 3:
        meta.update(
            initiated=pick(d, "Initiated"), source_ip=pick(d, "SourceIp"), source_port=pick(d, "SourcePort")
        )
        return mk(
            EventType.NETWORK_CONNECT,
            destination_ip=canon_ip(pick(d, "DestinationIp")),
            destination_port=canon_port(pick(d, "DestinationPort")),
            domain=canon_domain(pick(d, "DestinationHostname")),
            protocol=clean_str(pick(d, "Protocol"), 16),
        )
    if eid == 22:
        meta["query_results"] = pick(d, "QueryResults")
        meta["query_status"] = pick(d, "QueryStatus")
        return mk(EventType.DNS_QUERY, domain=canon_domain(pick(d, "QueryName")), protocol="dns")
    if eid in (11, 15):
        return mk(
            EventType.FILE_CREATE, file_path=canon_path(pick(d, "TargetFilename")), hash_sha256=_hash(d)
        )
    if eid in (23, 26):
        meta["archived"] = pick(d, "IsExecutable")
        return mk(EventType.FILE_DELETE, file_path=canon_path(pick(d, "TargetFilename")))
    if eid in (12, 13, 14):
        sub = str(pick(d, "EventType") or "").lower()
        if "delete" in sub:
            et = EventType.REGISTRY_DELETE
        elif sub == "createkey":
            et = EventType.REGISTRY_CREATE
        else:
            et = EventType.REGISTRY_MODIFY
        meta.update(registry_action=sub, registry_value=pick(d, "Details"), new_name=pick(d, "NewName"))
        return mk(et, registry_key=clean_str(pick(d, "TargetObject"), 1024))
    if eid == 8:
        meta.update(target_image=pick(d, "TargetImage"), target_pid=pick(d, "TargetProcessId"))
        return mk(EventType.PROCESS_INJECT)
    if eid == 10:
        granted = to_int(pick(d, "GrantedAccess"), 16) or 0
        meta.update(
            target_image=pick(d, "TargetImage"),
            target_pid=pick(d, "TargetProcessId"),
            granted_access=pick(d, "GrantedAccess"),
        )
        same = pick(d, "SourceImage") == pick(d, "TargetImage")
        et = EventType.PROCESS_INJECT if (granted & 0x20) and not same else EventType.OTHER
        return mk(et, confidence=0.7)
    if eid in (6, 7):
        meta.update(signed=pick(d, "Signed"), signature_status=pick(d, "SignatureStatus"))
        signed = str(pick(d, "Signed")).lower() == "true"
        return mk(
            EventType.MODULE_LOAD,
            file_path=canon_path(pick(d, "ImageLoaded")),
            hash_sha256=_hash(d),
            signer=clean_str(pick(d, "Signature")) if signed else None,
        )
    if eid in (19, 20, 21):
        meta.update(
            wmi_operation=pick(d, "Operation"),
            wmi_name=pick(d, "Name"),
            wmi_query=pick(d, "Query"),
            wmi_consumer=pick(d, "Consumer"),
            wmi_filter=pick(d, "Filter"),
            wmi_type=pick(d, "Type"),
            persistence_kind="wmi",
        )
        return mk(
            EventType.PERSISTENCE,
            command_line=clean_str(pick(d, "Destination", "Query"), MAX_CMD),
            registry_key=None,
        )
    if eid == 25:
        meta["tamper_type"] = pick(d, "Type")
        return mk(EventType.TAMPER)
    if eid == 4:
        return mk(EventType.TAMPER, confidence=0.6)
    meta["unmapped"] = True
    return mk(EventType.OTHER, confidence=0.3)


# --------------------------------------------------------------------------- Event Log
_PROTO = {"6": "tcp", "17": "udp", "1": "icmp"}


def _task_command(content: str | None) -> str | None:
    if not content:
        return None
    cmds = re.findall(r"<Command>(.*?)</Command>", content, flags=re.DOTALL)
    args = re.findall(r"<Arguments>(.*?)</Arguments>", content, flags=re.DOTALL)
    if not cmds:
        return None
    return clean_str(" ".join(cmds[:1] + args[:1]), MAX_CMD)


def normalize_eventlog(rec: WinRecord, host_id: str = "localhost") -> NormalizedEvent:
    d = rec.data
    eid = rec.event_id
    base = _base(rec, host_id, "eventlog")
    meta: dict[str, Any] = {
        "event_log_id": eid,
        "channel": rec.channel,
        "provider": rec.provider,
        "record_id": rec.record_id,
    }

    def mk(et: EventType, **kw: Any) -> NormalizedEvent:
        merged = {**base, **kw}
        merged["raw_metadata"] = safe_meta({**meta, **merged.pop("meta", {})})
        return make_event(event_type=et, **merged)

    if eid == 4688:
        img = canon_path(pick(d, "NewProcessName"))
        parent = canon_path(pick(d, "ParentProcessName"))
        meta.update(token_elevation=pick(d, "TokenElevationType"), mandatory_label=pick(d, "MandatoryLabel"))
        return mk(
            EventType.PROCESS_START,
            user=_user(d, "SubjectUserName"),
            pid=to_int(pick(d, "NewProcessId")),
            ppid=to_int(pick(d, "ProcessId")),
            process_name=basename_any(img),
            executable_path=img,
            command_line=clean_str(pick(d, "CommandLine"), MAX_CMD),
            parent_process=basename_any(parent),
        )
    if eid == 4689:
        img = canon_path(pick(d, "ProcessName"))
        return mk(
            EventType.PROCESS_EXIT,
            user=_user(d, "SubjectUserName"),
            pid=to_int(pick(d, "ProcessId")),
            process_name=basename_any(img),
            executable_path=img,
        )
    if eid in (4624, 4625, 4648, 4634):
        meta.update(
            logon_type=pick(d, "LogonType"), success=eid != 4625, workstation=pick(d, "WorkstationName")
        )
        return mk(
            EventType.AUTH,
            user=_user(d, "TargetUserName"),
            destination_ip=canon_ip(pick(d, "IpAddress")),
            destination_port=canon_port(pick(d, "IpPort")),
            process_name=basename_any(canon_path(pick(d, "ProcessName"))),
        )
    if eid in (4672, 4673, 4674):
        meta["privileges"] = pick(d, "PrivilegeList", "Privileges")
        return mk(
            EventType.PRIVILEGE_CHANGE,
            user=_user(d, "SubjectUserName"),
            pid=to_int(pick(d, "ProcessId")),
            process_name=basename_any(canon_path(pick(d, "ProcessName"))),
        )
    if eid in (4698, 4699, 4700, 4701, 4702):
        action = {4698: "created", 4699: "deleted", 4700: "enabled", 4701: "disabled", 4702: "updated"}[eid]
        meta.update(task_name=pick(d, "TaskName"), task_action=action)
        return mk(
            EventType.SCHEDULED_TASK,
            user=_user(d, "SubjectUserName"),
            command_line=_task_command(clean_str(pick(d, "TaskContent"), 65536)),
        )
    if eid in (7045, 4697):
        meta.update(
            service_name=pick(d, "ServiceName"),
            service_type=pick(d, "ServiceType"),
            start_type=pick(d, "StartType"),
            account=pick(d, "AccountName", "ServiceAccount"),
            service_action="installed",
        )
        img = clean_str(pick(d, "ImagePathName", "ServiceFileName"), MAX_CMD)
        return mk(EventType.SERVICE_CHANGE, user=_user(d, "SubjectUserName"), command_line=img)
    if eid == 4657:
        meta.update(
            registry_value_name=pick(d, "ObjectValueName"),
            registry_new_value=pick(d, "NewValue"),
            registry_old_value=pick(d, "OldValue"),
        )
        img = canon_path(pick(d, "ProcessName"))
        return mk(
            EventType.REGISTRY_MODIFY,
            user=_user(d, "SubjectUserName"),
            pid=to_int(pick(d, "ProcessId")),
            process_name=basename_any(img),
            executable_path=img,
            registry_key=clean_str(pick(d, "ObjectName"), 1024),
        )
    if eid == 4663:
        mask = to_int(pick(d, "AccessMask"), 16) or 0
        img = canon_path(pick(d, "ProcessName"))
        if mask & 0x10000:
            et = EventType.FILE_DELETE
        elif mask & (0x2 | 0x4 | 0x40):
            et = EventType.FILE_MODIFY
        else:
            raise ValueError("4663 read-only access ignored")
        return mk(
            et,
            user=_user(d, "SubjectUserName"),
            pid=to_int(pick(d, "ProcessId")),
            process_name=basename_any(img),
            executable_path=img,
            file_path=canon_path(pick(d, "ObjectName")),
            meta={"access_mask": pick(d, "AccessMask")},
        )
    if eid == 5156:
        direction = str(pick(d, "Direction") or "")
        meta["direction"] = direction
        img = clean_str(pick(d, "Application"))
        return mk(
            EventType.NETWORK_LISTEN if "14592" in direction else EventType.NETWORK_CONNECT,
            pid=to_int(pick(d, "ProcessID", "ProcessId")),
            process_name=basename_any(img),
            executable_path=None,  # WFP gives \device\harddiskvolumeN paths: kept in metadata only
            destination_ip=canon_ip(pick(d, "DestAddress")),
            destination_port=canon_port(pick(d, "DestPort")),
            protocol=_PROTO.get(str(pick(d, "Protocol"))),
            meta={"device_path": img, "source_address": pick(d, "SourceAddress")},
        )
    if eid in (1102, 104):
        return mk(EventType.TAMPER, user=_user(d, "SubjectUserName"), meta={"tamper": "audit_log_cleared"})
    if eid in (4104, 4103):
        text = clean_str(pick(d, "ScriptBlockText", "Payload", "ContextInfo"), MAX_CMD)
        return mk(
            EventType.OTHER,
            process_name="powershell.exe",
            command_line=text,
            meta={
                "script_path": pick(d, "Path"),
                "powershell_event": eid,
                "script_block_id": pick(d, "ScriptBlockId"),
            },
        )
    meta["unmapped"] = True
    return mk(EventType.OTHER, confidence=0.3)


# --------------------------------------------------------------------------- ETW
_ETW_PROCESS_IDS = {1: EventType.PROCESS_START, 2: EventType.PROCESS_EXIT}


def normalize_etw(raw: dict[str, Any], host_id: str = "localhost") -> NormalizedEvent:
    """ETW-shaped dict (as produced by tdh/pywintrace/ETW consumers): provider + event id/name + fields."""
    provider = str(pick(raw, "provider", "providername", "provider_name") or "")
    eid = to_int(pick(raw, "event_id", "eventid", "id"))
    name = str(pick(raw, "event_name", "eventname", "task", "opcode_name", "opcode") or "").lower()
    fields_raw = pick(raw, "fields", "properties", "payload")
    f: dict[str, Any] = {**raw, **fields_raw} if isinstance(fields_raw, dict) else dict(raw)
    pl = provider.lower()
    ts = parse_ts(pick(raw, "timestamp", "time", "timecreated", "ts"))
    pid = to_int(pick(f, "processid", "pid", "process_id", "ProcessID"))
    meta = {"etw_provider": provider, "etw_event_id": eid, "etw_event_name": name}
    host = clean_str(pick(raw, "host", "computer")) or host_id

    def mk(et: EventType, **kw: Any) -> NormalizedEvent:
        return make_event(
            event_type=et,
            timestamp=ts,
            host_id=host,
            source="etw",
            pid=pid,
            raw_metadata=safe_meta(meta, **kw.pop("meta", {})),
            **kw,
        )

    if "kernel-process" in pl or ("process" in name and "kernel" in pl):
        img = canon_path(pick(f, "imagename", "image", "imagefilename", "newprocessname"))
        common: dict[str, Any] = {
            "executable_path": img,
            "process_name": basename_any(img),
            "ppid": to_int(pick(f, "parentprocessid", "parent_pid", "ppid")),
            "command_line": clean_str(pick(f, "commandline", "cmdline", "command_line"), MAX_CMD),
            "user": clean_str(pick(f, "user", "username", "usersid")),
        }
        if eid in _ETW_PROCESS_IDS or "start" in name or "stop" in name or "end" in name:
            stop = eid == 2 or "stop" in name or "end" in name
            return mk(EventType.PROCESS_EXIT if stop else EventType.PROCESS_START, **common)
    if "kernel-file" in pl:
        fn = canon_path(pick(f, "filename", "filepath", "file", "openpath"))
        if "delete" in name or eid == 26:
            return mk(EventType.FILE_DELETE, file_path=fn)
        if "rename" in name or eid == 27:
            return mk(
                EventType.FILE_RENAME,
                file_path=canon_path(pick(f, "newfilename", "newpath")) or fn,
                meta={"old_path": fn},
            )
        if "create" in name or eid == 12:
            return mk(EventType.FILE_CREATE, file_path=fn)
        if "write" in name or "setinfo" in name:
            return mk(EventType.FILE_MODIFY, file_path=fn)
    if "kernel-network" in pl or "tcpip" in pl:
        ip = canon_ip(pick(f, "daddr", "destinationip", "dest_ip", "remoteaddress"))
        port = canon_port(pick(f, "dport", "destinationport", "dest_port", "remoteport"))
        if ip or port:
            return mk(
                EventType.NETWORK_CONNECT,
                destination_ip=ip,
                destination_port=port,
                protocol=clean_str(pick(f, "protocol"), 16) or "tcp",
            )
    if "kernel-registry" in pl:
        key = clean_str(pick(f, "keyname", "key", "relativename"), 1024)
        if "delete" in name:
            return mk(EventType.REGISTRY_DELETE, registry_key=key)
        if "create" in name:
            return mk(EventType.REGISTRY_CREATE, registry_key=key)
        return mk(EventType.REGISTRY_MODIFY, registry_key=key)
    if "dns-client" in pl or "dns" in name:
        q = canon_domain(pick(f, "queryname", "name", "domain"))
        if q:
            return mk(EventType.DNS_QUERY, domain=q, protocol="dns")
    meta["unmapped"] = True
    return mk(EventType.OTHER, confidence=0.3)


def is_sysmon(rec: WinRecord) -> bool:
    return "sysmon" in rec.provider.lower() or "sysmon" in rec.channel.lower()


def record_from_raw(raw: dict[str, Any]) -> WinRecord:
    """Accept XML text (``xml``/``raw_xml``/``Xml``), JSON event dicts, or JSON text (``json``)."""
    xml = pick(raw, "xml", "raw_xml")
    if isinstance(xml, str):
        return parse_event_xml(xml)
    js = pick(raw, "json")
    if isinstance(js, str):
        try:
            parsed = json.loads(js)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed event JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("event JSON must be an object")
        raw = parsed
    return parse_event_json(raw)
