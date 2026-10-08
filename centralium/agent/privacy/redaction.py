"""Privacy, PII, and secret redaction filter for Centralium.

Redacts API keys, JWTs, AWS credentials, private keys, passwords, bearer tokens,
credit card numbers, SSNs, email addresses, and optional IP masking.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("centralium.privacy.redaction")

# Redaction tokens
REDACTED_API_KEY = "[REDACTED:API_KEY]"
REDACTED_JWT = "[REDACTED:JWT]"
REDACTED_AWS_KEY = "[REDACTED:AWS_KEY]"
REDACTED_PRIVATE_KEY = "[REDACTED:PRIVATE_KEY]"
REDACTED_PASSWORD = "[REDACTED:PASSWORD]"  # noqa: S105
REDACTED_BEARER = "[REDACTED:BEARER_TOKEN]"
REDACTED_EMAIL = "[REDACTED:EMAIL]"
REDACTED_SSN = "[REDACTED:SSN]"
REDACTED_CREDIT_CARD = "[REDACTED:CREDIT_CARD]"
REDACTED_IP = "[REDACTED:IP]"


@dataclass
class RedactionConfig:
    """Configuration options for secret and PII redactor."""

    redact_api_keys: bool = True
    redact_jwts: bool = True
    redact_aws_keys: bool = True
    redact_private_keys: bool = True
    redact_passwords: bool = True
    redact_bearer_tokens: bool = True
    redact_pii: bool = True
    mask_ips: bool = False
    custom_patterns: list[tuple[re.Pattern[str], str]] = field(default_factory=list)


class SecretRedactor:
    """Filter that detects and masks secrets and personal identifiable information."""

    # Pre-compiled regex patterns
    _RE_PRIVATE_KEY = re.compile(
        r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----",
        re.MULTILINE,
    )
    _RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-\.\+/=]{10,}\b")
    _RE_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")
    _RE_AWS_SECRET_KEY = re.compile(
        r"(?i)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
    )
    _RE_API_KEY_PREFIX = re.compile(
        r"\b(?:sk-[a-zA-Z0-9_\-]{20,}|hf_[a-zA-Z0-9]{34,}|gh[pousr]_[a-zA-Z0-9]{20,}|glpat-[a-zA-Z0-9_\-]{20,}|xox[baprs]-[0-9a-zA-Z]{10,48}|AIza[0-9A-Za-z\-_]{35})\b"
    )
    _RE_GENERIC_SECRET_KV = re.compile(
        r"(?i)(api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,})['\"]?"
    )
    _RE_PASSWORD_KV = re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s,;&]+)['\"]?")
    _RE_BEARER = re.compile(
        r"(?i)(bearer\s+)([a-zA-Z0-9_\-\.~+/]+=*)",
    )
    _RE_BASIC_AUTH = re.compile(
        r"(?i)(basic\s+)([A-Za-z0-9+/=]{16,})",
    )
    _RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b")
    _RE_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    _RE_CREDIT_CARD = re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|"
        r"6(?:011|5[0-9]{2})[0-9]{12}|\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4})\b"
    )
    _RE_IPV4 = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    _SENSITIVE_KEY_NAMES = frozenset(
        {
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_token",
            "auth_token",
            "private_key",
            "client_secret",
        }
    )

    def __init__(self, config: RedactionConfig | None = None) -> None:
        self.config = config or RedactionConfig()

    def redact_text(self, text: str) -> str:
        """Apply all configured redaction patterns to a text string."""
        if not text:
            return text

        s = text

        # 1. Private keys
        if self.config.redact_private_keys:
            s = self._RE_PRIVATE_KEY.sub(REDACTED_PRIVATE_KEY, s)

        # 2. JWTs
        if self.config.redact_jwts:
            s = self._RE_JWT.sub(REDACTED_JWT, s)

        # 3. AWS keys
        if self.config.redact_aws_keys:
            s = self._RE_AWS_ACCESS_KEY.sub(REDACTED_AWS_KEY, s)
            s = self._RE_AWS_SECRET_KEY.sub(r"\1=" + REDACTED_AWS_KEY, s)

        # 4. API keys & well-known token formats
        if self.config.redact_api_keys:
            s = self._RE_API_KEY_PREFIX.sub(REDACTED_API_KEY, s)
            s = self._RE_GENERIC_SECRET_KV.sub(r"\1=" + REDACTED_API_KEY, s)

        # 5. Bearer & Basic auth tokens
        if self.config.redact_bearer_tokens:
            s = self._RE_BEARER.sub(r"\1" + REDACTED_BEARER, s)
            s = self._RE_BASIC_AUTH.sub(r"\1" + REDACTED_BEARER, s)

        # 6. Passwords in key-value format
        if self.config.redact_passwords:
            s = self._RE_PASSWORD_KV.sub(r"\1=" + REDACTED_PASSWORD, s)

        # 7. PII (Email, SSN, Credit Cards)
        if self.config.redact_pii:
            s = self._RE_EMAIL.sub(REDACTED_EMAIL, s)
            s = self._RE_SSN.sub(REDACTED_SSN, s)
            s = self._RE_CREDIT_CARD.sub(REDACTED_CREDIT_CARD, s)

        # 8. IP masking (if enabled)
        if self.config.mask_ips:
            s = self._RE_IPV4.sub(REDACTED_IP, s)

        # 9. Custom patterns
        for pattern, replacement in self.config.custom_patterns:
            s = pattern.sub(replacement, s)

        return s

    def redact_dict(self, data: Mapping[str, Any]) -> dict[str, Any]:
        """Recursively redact dictionary values and keys."""
        out: dict[str, Any] = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(tok in k_lower for tok in ("token", "api_key", "apikey")):
                out[str(k)] = REDACTED_API_KEY
            elif any(sens in k_lower for sens in ("password", "passwd", "pwd", "secret", "private_key")):
                out[str(k)] = REDACTED_PASSWORD
            else:
                out[str(k)] = self.redact(v)
        return out

    def redact_sequence(self, items: Sequence[Any]) -> list[Any]:
        """Recursively redact sequence items."""
        return [self.redact(item) for item in items]

    def redact(self, obj: Any) -> Any:
        """Generic redaction dispatch for any Python object."""
        if isinstance(obj, str):
            return self.redact_text(obj)
        if isinstance(obj, Mapping):
            return self.redact_dict(obj)
        if isinstance(obj, (list, tuple, set)):
            res = self.redact_sequence(list(obj))
            return type(obj)(res) if not isinstance(obj, (set, list, tuple)) else res
        return obj


# Global default instance
_DEFAULT_REDACTOR = SecretRedactor()


def redact_text(text: str, mask_ips: bool = False) -> str:
    """Convenience helper to redact secrets and PII from a text string."""
    if mask_ips:
        return SecretRedactor(RedactionConfig(mask_ips=True)).redact_text(text)
    return _DEFAULT_REDACTOR.redact_text(text)


def redact(obj: Any, mask_ips: bool = False) -> Any:
    """Convenience helper to redact secrets and PII from any object."""
    if mask_ips:
        return SecretRedactor(RedactionConfig(mask_ips=True)).redact(obj)
    return _DEFAULT_REDACTOR.redact(obj)


# ---------------------------------------------------------------------- Logging Integration
class RedactingLogFilter(logging.Filter):
    """Logging filter that redacts secrets from log record messages and arguments."""

    def __init__(self, redactor: SecretRedactor | None = None) -> None:
        super().__init__()
        self.redactor = redactor or _DEFAULT_REDACTOR

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redactor.redact_text(record.msg)
        if record.args:
            if isinstance(record.args, Mapping):
                record.args = self.redactor.redact_dict(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(self.redactor.redact(a) for a in record.args)
        return True


class RedactingFormatter(logging.Formatter):
    """Logging Formatter that redacts secrets from the final formatted log string."""

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)
        self.redactor = redactor or _DEFAULT_REDACTOR

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        return self.redactor.redact_text(formatted)


def install_log_redaction(logger: logging.Logger | None = None) -> None:
    """Attach RedactingLogFilter to root logger or specified logger and its handlers."""
    target = logger or logging.getLogger()
    flt = RedactingLogFilter()
    target.addFilter(flt)
    for handler in target.handlers:
        handler.addFilter(flt)
