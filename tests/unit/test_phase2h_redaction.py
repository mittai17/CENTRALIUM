"""Unit tests for Phase 2H: Secret and PII redaction filter."""

import logging
from io import StringIO
from pathlib import Path

from centralium.agent.llm.prompts import sanitize
from centralium.agent.privacy.redaction import (
    REDACTED_API_KEY,
    REDACTED_AWS_KEY,
    REDACTED_BEARER,
    REDACTED_CREDIT_CARD,
    REDACTED_EMAIL,
    REDACTED_IP,
    REDACTED_JWT,
    REDACTED_PASSWORD,
    REDACTED_PRIVATE_KEY,
    REDACTED_SSN,
    RedactingFormatter,
    RedactingLogFilter,
    RedactionConfig,
    SecretRedactor,
    redact,
    redact_text,
)
from centralium.agent.sync.queue import DurableSyncQueue


def test_redact_private_keys():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m4wT08y1z5c...\n-----END RSA PRIVATE KEY-----"
    res = redact_text(f"Loaded identity from {pem} successfully.")
    assert REDACTED_PRIVATE_KEY in res
    assert "MIIEow" not in res


def test_redact_jwt():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    text = f"User token: {jwt}"
    res = redact_text(text)
    assert REDACTED_JWT in res
    assert jwt not in res


def test_redact_aws_credentials():
    access_key = "AKIAIOSFODNN7EXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    line = f"AWS credentials: aws_access_key_id={access_key} aws_secret_access_key={secret_key}"
    res = redact_text(line)
    assert REDACTED_AWS_KEY in res
    assert access_key not in res
    assert secret_key not in res


def test_redact_api_keys_and_tokens():
    openai = "sk-1234567890abcdef1234567890abcdef123456"
    github = "ghp_1234567890abcdefghijklmnopqrstuv"
    line = f"Connecting using {openai} and GitHub {github}"
    res = redact_text(line)
    assert REDACTED_API_KEY in res
    assert openai not in res
    assert github not in res


def test_redact_passwords_and_bearer():
    text = "Authorization: Bearer eyJmysecrettoken1234567890 and password=SuperSecretPassword!123"
    res = redact_text(text)
    assert REDACTED_BEARER in res
    assert REDACTED_PASSWORD in res
    assert "SuperSecretPassword!123" not in res


def test_redact_pii():
    text = "Contact alice.smith@corp.example.com with SSN 123-45-6789 or CC 4532-1234-5678-9012"
    res = redact_text(text)
    assert REDACTED_EMAIL in res
    assert REDACTED_SSN in res
    assert REDACTED_CREDIT_CARD in res
    assert "alice.smith@corp.example.com" not in res
    assert "123-45-6789" not in res


def test_ip_masking():
    redactor_no_ip = SecretRedactor(RedactionConfig(mask_ips=False))
    assert "192.168.1.100" in redactor_no_ip.redact_text("Host IP 192.168.1.100")

    redactor_ip = SecretRedactor(RedactionConfig(mask_ips=True))
    masked = redactor_ip.redact_text("Host IP 192.168.1.100 connected")
    assert REDACTED_IP in masked
    assert "192.168.1.100" not in masked


def test_redact_nested_structures():
    data = {
        "user": "analyst",
        "password": "ClearTextPassword123",
        "headers": {
            "Authorization": "Bearer secret_token_value_xyz1234567890",
            "X-Custom-Token": "sk-1234567890abcdef1234567890abcdef",
        },
        "tags": ["prod", "admin_pwd=HiddenSecret123"],
    }
    redacted = redact(data)
    assert redacted["password"] == REDACTED_PASSWORD
    assert REDACTED_BEARER in redacted["headers"]["Authorization"]
    assert REDACTED_API_KEY in redacted["headers"]["X-Custom-Token"]
    assert REDACTED_PASSWORD in redacted["tags"][1]


def test_logging_redaction_integration():
    stream = StringIO()
    logger = logging.getLogger("test_redact_logger")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(RedactingFormatter("%(levelname)s: %(message)s"))
    logger.addHandler(handler)
    logger.addFilter(RedactingLogFilter())

    logger.info(
        "User logged in with password=SecretPasswordToRedact and token=ghp_1234567890abcdefghijklmnopqrstuv"
    )
    output = stream.getvalue()

    assert "SecretPasswordToRedact" not in output
    assert "ghp_12345" not in output
    assert REDACTED_PASSWORD in output or REDACTED_API_KEY in output


def test_llm_prompt_automatic_redaction():
    untrusted = (
        "curl -H 'Authorization: Bearer secret_bearer_token_123' https://malicious.org?pwd=secretpassword"
    )
    sanitized = sanitize(untrusted)
    assert "secret_bearer_token_123" not in sanitized
    assert "secretpassword" not in sanitized
    assert REDACTED_BEARER in sanitized or REDACTED_PASSWORD in sanitized


def test_sync_queue_automatic_redaction(tmp_path: Path):
    db_path = tmp_path / "sync.db"
    queue = DurableSyncQueue(db_path)

    secret_payload = {
        "event_id": "ev-secret-1",
        "api_key": "sk-1234567890abcdef1234567890abcdef123456",
        "command_line": "powershell.exe -token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl",
        "password": "SuperSecretPassWord!",
    }
    enqueued = queue.enqueue(secret_payload)
    assert enqueued is True

    # Inspect queued item
    items = queue.claim_batch(10)
    assert len(items) == 1
    stored = items[0].payload
    assert "SuperSecretPassWord!" not in str(stored)
    assert "sk-1234567890" not in str(stored)
    assert REDACTED_PASSWORD in str(stored)
