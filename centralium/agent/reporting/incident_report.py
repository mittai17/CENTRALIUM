"""Comprehensive incident report generation (Markdown and offline PDF export).

Includes executive summary, timeline, attack chain, MITRE mapping, evidence tables,
risk breakdown, response actions taken, and recommended follow-up, clearly distinguishing
[DETERMINISTIC] vs [AI-ASSISTED] parts and disclosing LLM model status (real vs mock vs unavailable).
"""
# ruff: noqa: E501

from __future__ import annotations

import contextlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from centralium.agent.models import AIAnalysis, Incident
from centralium.agent.storage import Database

log = logging.getLogger("centralium.reporting")


def generate_incident_report(
    incident: Incident,
    db: Database | None = None,
    ai_analysis: AIAnalysis | None = None,
    model_status: dict[str, Any] | None = None,
) -> str:
    """Generate a comprehensive Markdown incident report with distinct AI vs deterministic labels."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Fetch AI analysis from DB if not supplied
    if ai_analysis is None and db is not None and incident.ai_analysis_id:
        row = db.query_one("SELECT * FROM ai_analysis WHERE analysis_id = ?", (incident.ai_analysis_id,))
        if row:
            v_dict = json.loads(row["verdict"]) if row["verdict"] else None
            ai_analysis = AIAnalysis(
                analysis_id=row["analysis_id"],
                event_id=row["event_id"],
                available=bool(row["available"]),
                role=row["role"],
                model_name=row["model_name"],
                latency_ms=row["latency_ms"],
                rag_sources=json.loads(row["rag_sources"]) if row["rag_sources"] else [],
                error=row["error"],
                verdict=v_dict,
            )

    # Fetch events & findings from DB if available
    events: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []

    if db is not None:
        if incident.event_ids:
            ph = ",".join("?" for _ in incident.event_ids)
            sql_ev = f"SELECT * FROM events WHERE event_id IN ({ph}) ORDER BY timestamp ASC"  # noqa: S608
            e_rows = db.query(sql_ev, incident.event_ids)
            events = [dict(r) for r in e_rows]
        elif incident.host_id:
            e_rows = db.query(
                "SELECT * FROM events WHERE host_id = ? ORDER BY timestamp DESC LIMIT 20", (incident.host_id,)
            )
            events = [dict(r) for r in e_rows]

        if incident.finding_ids:
            ph = ",".join("?" for _ in incident.finding_ids)
            sql_find = f"SELECT * FROM findings WHERE finding_id IN ({ph}) ORDER BY timestamp ASC"  # noqa: S608
            f_rows = db.query(sql_find, incident.finding_ids)
            findings = [dict(r) for r in f_rows]

        a_rows = db.query(
            "SELECT * FROM response_actions WHERE incident_id = ? ORDER BY timestamp ASC",
            (incident.incident_id,),
        )
        actions = [dict(r) for r in a_rows]

    # Model status disclosure
    model_mode = (
        "Real Local Model"
        if model_status and model_status.get("mode") == "real"
        else (
            "Mock Test Model"
            if (ai_analysis and ai_analysis.model_name in ("mock", "none"))
            else (
                "Real Local Model"
                if (ai_analysis and ai_analysis.model_name and ai_analysis.model_name != "none")
                else "LLM Unavailable / Deterministic Only"
            )
        )
    )
    model_name = ai_analysis.model_name if ai_analysis else "N/A"

    lines: list[str] = [
        f"# Incident Report: {incident.title}",
        "",
        "## Incident Metadata [DETERMINISTIC]",
        f"- **Incident ID:** `{incident.incident_id}`",
        f"- **Host ID:** `{incident.host_id}`",
        f"- **Status:** `{incident.status}`",
        f"- **Risk Score:** **{incident.risk_score:.1f}** ({incident.band.value})",
        f"- **Created At:** {incident.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"- **Report Generated:** {now}",
        "",
        "## AI Provenance & Model Status [AI-ASSISTED]",
        f"- **Model Mode:** `{model_mode}`",
        f"- **Model Name:** `{model_name}`",
        f"- **Analysis Status:** `{'Completed' if (ai_analysis and ai_analysis.available) else 'Not Run / Unavailable'}`",
        f"- **Inference Latency:** {ai_analysis.latency_ms:.1f} ms"
        if ai_analysis
        else "- **Inference Latency:** N/A",
        f"- **RAG References Used:** {', '.join(ai_analysis.rag_sources) if ai_analysis and ai_analysis.rag_sources else 'None'}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "### Deterministic Analysis [DETERMINISTIC]",
        f"Automated pipeline recorded **{len(events)}** related events and **{len(findings)}** detection findings. "
        f"Calculated composite risk is **{incident.risk_score:.1f}** based on deterministic signatures, behavioral ML, and attack graph correlation.",
        "",
        "### AI Analyst Assessment [AI-ASSISTED]",
    ]

    if ai_analysis and ai_analysis.verdict:
        v = ai_analysis.verdict
        lines.extend(
            [
                f"**Verdict:** `{v.verdict.value}` | **Severity:** `{v.severity.value}` | **Confidence:** `{v.confidence:.2f}`",
                "",
                f"**Summary:** {v.summary}",
                "",
                "**Suspicious Indicators Identified by AI:**",
            ]
        )
        for why in v.why_suspicious[:6]:
            lines.append(f"- {why}")
    else:
        lines.append(
            "No AI analysis available for this incident. Findings rely exclusively on deterministic rules and local behavioral ML."
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## Attack Chain & Tactics [DETERMINISTIC]",
            f"- **Identified Attack Stage:** `{incident.attack_stage.value if incident.attack_stage else 'UNKNOWN'}`",
            f"- **Observed MITRE Techniques:** {', '.join(incident.mitre_techniques) if incident.mitre_techniques else 'None'}",
            "",
            "## Timeline of Events [DETERMINISTIC]",
            "",
            "| Timestamp | Event Type | Process | User | Command Line / Detail |",
            "|---|---|---|---|---|",
        ]
    )

    if events:
        for ev in events:
            cmd = ev.get("command_line") or ev.get("file_path") or ev.get("destination_ip") or ""
            lines.append(
                f"| {str(ev.get('timestamp'))[:19]} | `{ev.get('event_type')}` | `{ev.get('process_name')}` | "
                f"`{ev.get('user')}` | `{cmd[:70]}` |"
            )
    else:
        lines.append("| N/A | N/A | N/A | N/A | No detailed timeline events recorded in store |")

    lines.extend(
        [
            "",
            "## MITRE ATT&CK Mapping [DETERMINISTIC]",
            "",
            "| Technique ID | Source Detection | Severity | Finding Title |",
            "|---|---|---|---|",
        ]
    )

    if findings:
        for f in findings:
            techs = f.get("mitre_techniques")
            tech_str = techs if isinstance(techs, str) else ", ".join(techs or ["N/A"])
            lines.append(f"| `{tech_str}` | `{f.get('source')}` | `{f.get('severity')}` | {f.get('title')} |")
    else:
        lines.append("| N/A | N/A | N/A | No specific MITRE findings recorded |")

    lines.extend(
        [
            "",
            "## Response Actions Taken [DETERMINISTIC]",
            "",
            "| Action ID | Action | Status | Target | Detail |",
            "|---|---|---|---|---|",
        ]
    )

    if actions:
        for a in actions:
            target_str = (
                json.dumps(json.loads(a["target"]))
                if isinstance(a.get("target"), str)
                else str(a.get("target", {}))
            )
            lines.append(
                f"| `{a.get('action_id')}` | `{a.get('action')}` | `{a.get('status')}` | `{target_str[:40]}` | {a.get('detail')} |"
            )
    else:
        lines.append(
            "| N/A | None | N/A | N/A | No automated destructive response executed (mode passive/alert-only) |"
        )

    lines.extend(
        [
            "",
            "## Recommended Follow-up Actions [AI-ASSISTED]",
            "",
        ]
    )

    if ai_analysis and ai_analysis.verdict:
        v = ai_analysis.verdict
        lines.append(f"- **Recommended Primary Action:** `{v.recommended_action.value}`")
        if v.investigation_questions:
            lines.append("- **Suggested Investigation Questions:**")
            for q in v.investigation_questions:
                lines.append(f"  - {q}")
        if v.false_positive_indicators:
            lines.append("- **Potential False Positive Checks:**")
            for fp in v.false_positive_indicators:
                lines.append(f"  - {fp}")
    else:
        lines.extend(
            [
                "- Review parent-child process relationships for unexpected spawns.",
                "- Check network destination against internal threat intelligence.",
                "- Verify user authorization for the initiated commands.",
            ]
        )

    lines.extend(
        [
            "",
            "---",
            "*Report automatically generated by Centralium Endpoint Detection and Response.*",
        ]
    )

    return "\n".join(lines)


def export_incident_report_pdf(markdown_report: str, out_pdf_path: Path | str) -> bool:
    """Attempt to export the incident report to PDF if an offline PDF library is installed.

    Returns True if PDF export succeeded, False if unavailable.
    """
    out_path = Path(out_pdf_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Try weasyprint
    with contextlib.suppress(Exception):
        import weasyprint  # type: ignore[import-not-found]

        # Convert markdown to HTML then PDF
        html = f"<html><body><pre>{markdown_report}</pre></body></html>"
        weasyprint.HTML(string=html).write_pdf(str(out_path))
        return True

    # 2. Try reportlab
    with contextlib.suppress(Exception):
        from reportlab.lib.pagesizes import letter  # type: ignore[import-untyped]
        from reportlab.pdfgen import canvas  # type: ignore[import-untyped]

        c = canvas.Canvas(str(out_path), pagesize=letter)
        y = 750
        for line in markdown_report.splitlines():
            if y < 40:
                c.showPage()
                y = 750
            c.drawString(40, y, line[:100])
            y -= 14
        c.save()
        return True

    log.info("Offline PDF generation libraries (weasyprint/reportlab) not available; Markdown saved.")
    return False
