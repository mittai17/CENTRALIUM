"""Sigma rule loader and compiler for Centralium telemetry events.

Compiles Sigma YAML rules against the NormalizedEvent schema for:
- Process creation (Image, CommandLine, ParentImage, User, Hashes)
- File events (TargetFilename / file_path)
- Network connections (DestinationIp, DestinationPort, Domain)
- Registry modifications (TargetObject / registry_key)

Supports standard Sigma modifiers: contains, startswith, endswith, re, all.
Parses Sigma boolean conditions: and, or, not, '1 of selection*', 'all of selection*'.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from centralium.agent.models import (
    AttackStage,
    EventType,
    Finding,
    FindingSource,
    NormalizedEvent,
    Severity,
)

log = logging.getLogger("centralium.rules.sigma")

# ---------------------------------------------------------------------------
# Minimal YAML / JSON parser fallback
# ---------------------------------------------------------------------------

try:
    import yaml  # type: ignore

    def _parse_yaml_or_json(text: str) -> dict[str, Any]:
        parsed = yaml.safe_load(text)
        if not isinstance(parsed, dict):
            raise ValueError("Sigma document must be a YAML mapping")
        return parsed

except ImportError:

    def _parse_yaml_or_json(text: str) -> dict[str, Any]:
        """Pure-Python subset parser for Sigma rule YAML documents."""
        # Try JSON first
        s = text.strip()
        if s.startswith("{"):
            try:
                res = json.loads(s)
                if isinstance(res, dict):
                    return res
            except json.JSONDecodeError:
                pass

        parsed_lines: list[tuple[int, str]] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            parsed_lines.append((indent, stripped))

        if not parsed_lines:
            return {}

        res, _ = _parse_yaml_block(parsed_lines, 0, 0)
        return res if isinstance(res, dict) else {}

    def _parse_yaml_block(lines: list[tuple[int, str]], idx: int, current_indent: int) -> tuple[Any, int]:
        if idx >= len(lines):
            return {}, idx

        indent, stripped = lines[idx]
        if stripped.startswith("- "):
            # Parse list
            lst: list[Any] = []
            while idx < len(lines):
                cur_indent, cur_line = lines[idx]
                if cur_indent < indent:
                    break
                if cur_indent == indent and cur_line.startswith("- "):
                    item_text = cur_line[2:].strip()
                    if not item_text:
                        # Nested block under list item
                        nested, idx = _parse_yaml_block(lines, idx + 1, cur_indent + 1)
                        lst.append(nested)
                    elif ":" in item_text and not item_text.startswith(('"', "'")):
                        # Single-line mapping item in list e.g. "- key: val"
                        k, v = item_text.split(":", 1)
                        k = k.strip()
                        v = v.strip()
                        if not v:
                            sub, idx = _parse_yaml_block(lines, idx + 1, cur_indent + 1)
                            lst.append({k: sub})
                        else:
                            lst.append({k: _parse_scalar(v)})
                            idx += 1
                    else:
                        lst.append(_parse_scalar(item_text))
                        idx += 1
                elif cur_indent > indent:
                    # Additional lines for current item or block
                    idx += 1
                else:
                    break
            return lst, idx
        else:
            # Parse dict
            dct: dict[str, Any] = {}
            while idx < len(lines):
                cur_indent, cur_line = lines[idx]
                if cur_indent < indent:
                    break
                if cur_indent == indent:
                    if ":" not in cur_line:
                        idx += 1
                        continue
                    k, rest = cur_line.split(":", 1)
                    k = k.strip()
                    rest = rest.strip()
                    if not rest or rest.startswith("#"):
                        # Value is in subsequent nested block
                        if idx + 1 < len(lines) and lines[idx + 1][0] > cur_indent:
                            sub_val, idx = _parse_yaml_block(lines, idx + 1, lines[idx + 1][0])
                            dct[k] = sub_val
                        else:
                            dct[k] = None
                            idx += 1
                    else:
                        dct[k] = _parse_scalar(rest)
                        idx += 1
                elif cur_indent > indent:
                    idx += 1
                else:
                    break
            return dct, idx

    def _parse_scalar(val: str) -> Any:
        v = val.split(" #")[0].strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            return v[1:-1]
        lower = v.lower()
        if lower in ("true", "yes"):
            return True
        if lower in ("false", "no"):
            return False
        if lower in ("null", "none", "~"):
            return None
        if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
            try:
                return int(v)
            except ValueError:
                pass
        try:
            return float(v)
        except ValueError:
            pass
        return v


# ---------------------------------------------------------------------------
# Schema mapping and field resolvers
# ---------------------------------------------------------------------------

_FIELD_MAP: dict[str, list[str]] = {
    # Process attributes
    "image": ["executable_path", "process_name"],
    "processname": ["process_name", "executable_path"],
    "newprocessname": ["executable_path", "process_name"],
    "commandline": ["command_line"],
    "processcommandline": ["command_line"],
    "parentimage": ["parent_process"],
    "parentprocessname": ["parent_process"],
    "user": ["user"],
    "username": ["user"],
    "processid": ["pid"],
    "parentprocessid": ["ppid"],
    "hashes": ["hash_sha256"],
    "sha256": ["hash_sha256"],
    "hash": ["hash_sha256"],
    # File attributes
    "targetfilename": ["file_path"],
    "targetfilename_": ["file_path"],
    "filepath": ["file_path"],
    "filename": ["file_path"],
    # Network attributes
    "destinationip": ["destination_ip"],
    "destinationaddress": ["destination_ip"],
    "dst_ip": ["destination_ip"],
    "destinationport": ["destination_port"],
    "dst_port": ["destination_port"],
    "destinationhostname": ["domain"],
    "domain": ["domain"],
    "query": ["domain"],
    "protocol": ["protocol"],
    # Registry attributes
    "targetobject": ["registry_key"],
    "registrykey": ["registry_key"],
    "keyname": ["registry_key"],
    "valuename": ["registry_key"],
}

_CATEGORY_EVENT_TYPES: dict[str, set[EventType]] = {
    "process_creation": {EventType.PROCESS_START},
    "process_termination": {EventType.PROCESS_EXIT},
    "file_event": {
        EventType.FILE_CREATE,
        EventType.FILE_MODIFY,
        EventType.FILE_DELETE,
        EventType.FILE_RENAME,
    },
    "file_create": {EventType.FILE_CREATE},
    "file_change": {EventType.FILE_MODIFY, EventType.FILE_CREATE},
    "network_connection": {EventType.NETWORK_CONNECT, EventType.NETWORK_LISTEN},
    "firewall": {EventType.NETWORK_CONNECT, EventType.NETWORK_LISTEN},
    "dns_query": {EventType.DNS_QUERY},
    "registry_event": {
        EventType.REGISTRY_CREATE,
        EventType.REGISTRY_MODIFY,
        EventType.REGISTRY_DELETE,
    },
    "registry_set": {EventType.REGISTRY_CREATE, EventType.REGISTRY_MODIFY},
    "registry_add": {EventType.REGISTRY_CREATE},
    "registry_delete": {EventType.REGISTRY_DELETE},
}

_LEVEL_SEVERITY: dict[str, tuple[Severity, float]] = {
    "informational": (Severity.INFO, 15.0),
    "info": (Severity.INFO, 15.0),
    "low": (Severity.LOW, 30.0),
    "medium": (Severity.MEDIUM, 55.0),
    "high": (Severity.HIGH, 75.0),
    "critical": (Severity.CRITICAL, 95.0),
}

_ATTACK_TACTIC_TO_STAGE: dict[str, AttackStage] = {
    "initial_access": AttackStage.INITIAL_ACCESS,
    "execution": AttackStage.EXECUTION,
    "persistence": AttackStage.PERSISTENCE,
    "privilege_escalation": AttackStage.PRIVILEGE_ESCALATION,
    "defense_evasion": AttackStage.DEFENSE_EVASION,
    "credential_access": AttackStage.CREDENTIAL_ACCESS,
    "discovery": AttackStage.DISCOVERY,
    "lateral_movement": AttackStage.LATERAL_MOVEMENT,
    "collection": AttackStage.COLLECTION,
    "command_and_control": AttackStage.COMMAND_AND_CONTROL,
    "exfiltration": AttackStage.EXFILTRATION,
    "impact": AttackStage.IMPACT,
}


def _resolve_event_value(event: NormalizedEvent, field_name: str) -> Any:
    """Resolve an event field by standard Sigma field name or raw metadata."""
    key = field_name.lower().replace("_", "")
    targets = _FIELD_MAP.get(key, [field_name])
    for target in targets:
        if hasattr(event, target):
            val = getattr(event, target)
            if val is not None:
                return val

    # Fallback to raw_metadata
    if field_name in event.raw_metadata:
        return event.raw_metadata[field_name]
    for k, v in event.raw_metadata.items():
        if k.lower() == field_name.lower():
            return v
    return None


def _match_value(actual: Any, expected: Any, modifiers: set[str]) -> bool:
    """Match actual event field value against expected Sigma value with modifiers."""
    if actual is None:
        return False

    actual_str = str(actual).lower()

    if isinstance(expected, list):
        if "all" in modifiers:
            return all(_match_single_value(actual_str, actual, item, modifiers) for item in expected)
        return any(_match_single_value(actual_str, actual, item, modifiers) for item in expected)

    return _match_single_value(actual_str, actual, expected, modifiers)


def _match_single_value(actual_str: str, actual_raw: Any, expected: Any, modifiers: set[str]) -> bool:
    if expected is None:
        return False

    # Numeric matching if both are numeric and no string modifiers
    if (
        isinstance(actual_raw, (int, float))
        and isinstance(expected, (int, float))
        and not (modifiers & {"contains", "startswith", "endswith", "re"})
    ):
        return actual_raw == expected

    exp_str = str(expected).lower()

    if "re" in modifiers:
        try:
            return bool(re.search(exp_str, actual_str, re.IGNORECASE))
        except re.error:
            return False

    if "contains" in modifiers:
        return exp_str in actual_str

    if "startswith" in modifiers:
        return actual_str.startswith(exp_str)

    if "endswith" in modifiers:
        return actual_str.endswith(exp_str)

    # Exact comparison (case-insensitive for strings)
    return actual_str == exp_str


# ---------------------------------------------------------------------------
# Compiled Sigma Rule
# ---------------------------------------------------------------------------


class CompiledSigmaRule:
    """A compiled Sigma rule that can be evaluated against NormalizedEvent instances."""

    def __init__(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        score: float,
        mitre_techniques: list[str],
        attack_stage: AttackStage | None,
        tags: list[str],
        applicable_event_types: set[EventType] | None,
        selection_matchers: dict[str, Callable[[NormalizedEvent], bool]],
        condition: str,
        raw_rule: dict[str, Any],
    ) -> None:
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.severity = severity
        self.score = score
        self.mitre_techniques = mitre_techniques
        self.attack_stage = attack_stage
        self.tags = tags
        self.applicable_event_types = applicable_event_types
        self.selection_matchers = selection_matchers
        self.condition = condition
        self.raw_rule = raw_rule

    def matches(self, event: NormalizedEvent) -> bool:
        """Evaluate if the rule matches the given NormalizedEvent."""
        if self.applicable_event_types and event.event_type not in self.applicable_event_types:
            return False

        # Evaluate each selection
        eval_results: dict[str, bool] = {}
        for sel_name, matcher in self.selection_matchers.items():
            eval_results[sel_name] = matcher(event)

        return self._evaluate_condition(self.condition, eval_results)

    def evaluate(self, event: NormalizedEvent) -> Finding | None:
        """Evaluate and return a Finding if the rule matches, else None."""
        if not self.matches(event):
            return None

        return Finding(
            event_id=event.event_id,
            source=FindingSource.SIGMA,
            rule_id=f"sigma.{self.rule_id}",
            title=self.title,
            severity=self.severity,
            score=self.score,
            confidence=0.9,
            mitre_techniques=list(self.mitre_techniques),
            attack_stage=self.attack_stage,
            details={
                "sigma_id": self.rule_id,
                "description": self.description,
                "tags": self.tags,
                "logsource": self.raw_rule.get("logsource", {}),
            },
        )

    def _evaluate_condition(self, cond: str, results: dict[str, bool]) -> bool:
        """Evaluate condition string given selection results."""
        cond_str = cond.strip()
        if not cond_str:
            return any(results.values())

        # Simple single identifier
        if cond_str in results:
            return results[cond_str]

        # Handle '1 of selection*' / 'all of selection*'
        if " of " in cond_str:
            cond_str = self._expand_quantifiers(cond_str, results)

        # Safe token-based boolean evaluation
        tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[a-zA-Z0-9_*]+", cond_str)
        if not tokens:
            return False

        return self._eval_tokens(tokens, results)

    @staticmethod
    def _expand_quantifiers(cond: str, results: dict[str, bool]) -> str:
        # e.g., '1 of selection*' or 'all of selection*' or '1 of them'
        def replacer(m: re.Match[str]) -> str:
            quant = m.group(1).lower()
            pattern = m.group(2)
            if pattern in ("them", "*"):
                matched_keys = list(results.keys())
            else:
                regex = re.compile("^" + pattern.replace("*", ".*") + "$")
                matched_keys = [k for k in results if regex.match(k)]

            if not matched_keys:
                return "false"

            if quant == "1":
                return "(" + " or ".join(matched_keys) + ")"
            elif quant == "all":
                return "(" + " and ".join(matched_keys) + ")"
            return "(" + " or ".join(matched_keys) + ")"

        return re.sub(
            r"\b(1|all|any)\s+of\s+([a-zA-Z0-9_*]+)",
            replacer,
            cond,
            flags=re.IGNORECASE,
        )

    def _eval_tokens(self, tokens: list[str], results: dict[str, bool]) -> bool:
        # Convert tokens into Python-evaluable expression with strict boolean words
        safe_expr_parts: list[str] = []
        for t in tokens:
            t_lower = t.lower()
            if t_lower in ("and", "or", "not", "(", ")"):
                safe_expr_parts.append(t_lower)
            elif t in results:
                safe_expr_parts.append("True" if results[t] else "False")
            elif t_lower in ("true", "1"):
                safe_expr_parts.append("True")
            elif t_lower in ("false", "0"):
                safe_expr_parts.append("False")
            else:
                # Unknown identifier in condition defaults to False
                safe_expr_parts.append("False")

        expr = " ".join(safe_expr_parts)
        try:
            # Only boolean constants and operators are in expr
            return bool(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Compiler functions
# ---------------------------------------------------------------------------


def compile_sigma_rule(rule_dict: dict[str, Any]) -> CompiledSigmaRule:
    """Compile a parsed Sigma rule dictionary into a CompiledSigmaRule."""
    title = str(rule_dict.get("title") or "Unnamed Sigma Rule")
    rule_id = str(rule_dict.get("id") or re.sub(r"[^a-zA-Z0-9_]+", "_", title.lower()))
    description = str(rule_dict.get("description") or "")
    level = str(rule_dict.get("level") or "medium").lower()

    severity, score = _LEVEL_SEVERITY.get(level, (Severity.MEDIUM, 50.0))

    tags_raw = rule_dict.get("tags") or []
    tags = [str(t).lower() for t in tags_raw if isinstance(t, (str, int))]

    # Extract MITRE techniques and tactics
    mitre_techniques: list[str] = []
    attack_stage: AttackStage | None = None
    for t in tags:
        m_tech = re.match(r"^attack\.(t\d{4}(?:\.\d{3})?)$", t)
        if m_tech:
            mitre_techniques.append(m_tech.group(1).upper())
        m_tactic = re.match(r"^attack\.([a-z_]+)$", t)
        if m_tactic and m_tactic.group(1) in _ATTACK_TACTIC_TO_STAGE:
            attack_stage = _ATTACK_TACTIC_TO_STAGE[m_tactic.group(1)]

    # Determine applicable event types from logsource
    logsource = rule_dict.get("logsource") or {}
    category = str(logsource.get("category") or "").lower()
    applicable_types = _CATEGORY_EVENT_TYPES.get(category)

    # Compile detections
    detection = rule_dict.get("detection") or {}
    condition = str(detection.get("condition") or "selection")

    selection_matchers: dict[str, Callable[[NormalizedEvent], bool]] = {}

    for k, v in detection.items():
        if k == "condition":
            continue
        if isinstance(v, dict):
            selection_matchers[k] = _build_dict_matcher(v)
        elif isinstance(v, list):
            # List of alternatives or values
            selection_matchers[k] = _build_list_matcher(v)

    return CompiledSigmaRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        score=score,
        mitre_techniques=mitre_techniques,
        attack_stage=attack_stage,
        tags=tags,
        applicable_event_types=applicable_types,
        selection_matchers=selection_matchers,
        condition=condition,
        raw_rule=rule_dict,
    )


def _build_dict_matcher(selection_dict: dict[str, Any]) -> Callable[[NormalizedEvent], bool]:
    field_matchers: list[Callable[[NormalizedEvent], bool]] = []

    for field_spec, expected in selection_dict.items():
        parts = field_spec.split("|")
        field_name = parts[0]
        modifiers = {p.lower() for p in parts[1:]}

        def matcher(
            ev: NormalizedEvent,
            fn: str = field_name,
            exp: Any = expected,
            mods: set[str] = modifiers,
        ) -> bool:
            actual = _resolve_event_value(ev, fn)
            return _match_value(actual, exp, mods)

        field_matchers.append(matcher)

    return lambda ev: all(m(ev) for m in field_matchers)


def _build_list_matcher(selection_list: list[Any]) -> Callable[[NormalizedEvent], bool]:
    item_matchers: list[Callable[[NormalizedEvent], bool]] = []
    for item in selection_list:
        if isinstance(item, dict):
            item_matchers.append(_build_dict_matcher(item))
        else:
            # Fallback scalar
            item_matchers.append(lambda ev: False)
    return lambda ev: any(m(ev) for m in item_matchers)


# ---------------------------------------------------------------------------
# Loader and High-Level Engine
# ---------------------------------------------------------------------------


class SigmaRuleLoader:
    """Loads and manages compiled Sigma rules."""

    def __init__(self) -> None:
        self.rules: list[CompiledSigmaRule] = []

    def load_yaml(self, text: str) -> CompiledSigmaRule:
        rule_dict = _parse_yaml_or_json(text)
        rule = compile_sigma_rule(rule_dict)
        self.rules.append(rule)
        return rule

    def load_file(self, path: Path | str) -> CompiledSigmaRule:
        p = Path(path)
        content = p.read_text(encoding="utf-8")
        return self.load_yaml(content)

    def load_directory(self, dir_path: Path | str) -> list[CompiledSigmaRule]:
        p = Path(dir_path)
        if not p.is_dir():
            log.warning("Sigma rules directory not found: %s", dir_path)
            return []

        loaded: list[CompiledSigmaRule] = []
        for file_path in sorted(p.glob("*.y*ml")):
            try:
                rule = self.load_file(file_path)
                loaded.append(rule)
            except Exception as exc:
                log.warning("Failed to load Sigma rule from %s: %s", file_path, exc)

        return loaded

    def evaluate(self, event: NormalizedEvent) -> list[Finding]:
        """Evaluate event against all loaded Sigma rules."""
        findings: list[Finding] = []
        for rule in self.rules:
            try:
                finding = rule.evaluate(event)
                if finding is not None:
                    findings.append(finding)
            except Exception as exc:
                log.debug("Error evaluating Sigma rule %s: %s", rule.rule_id, exc)
        return findings


def load_sigma_rule(source: str | Path | dict[str, Any]) -> CompiledSigmaRule:
    """Convenience helper to compile a Sigma rule from dict, file path, or YAML string."""
    if isinstance(source, dict):
        return compile_sigma_rule(source)
    if isinstance(source, Path) or (
        isinstance(source, str) and "\n" not in source and Path(source).is_file()
    ):
        content = Path(source).read_text(encoding="utf-8")
        return compile_sigma_rule(_parse_yaml_or_json(content))
    return compile_sigma_rule(_parse_yaml_or_json(str(source)))


def load_sigma_rules_from_dir(dir_path: str | Path) -> list[CompiledSigmaRule]:
    loader = SigmaRuleLoader()
    return loader.load_directory(dir_path)
