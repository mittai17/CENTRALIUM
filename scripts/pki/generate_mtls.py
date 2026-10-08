#!/usr/bin/env python3
"""PKI tooling for Centralium mutual TLS (mTLS).

Generates self-signed Root CA, server certificates, and agent client certificates
for zero-trust communication between Centralium agents and the fleet management server.
"""

from __future__ import annotations

import argparse
import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def generate_ca(
    common_name: str = "Centralium Root CA",
    organization: str = "Centralium Security",
    valid_days: int = 3650,
    key_size: int = 4096,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Generate self-signed Root Certificate Authority (CA)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        ]
    )
    now = _utc_now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )
    cert = builder.sign(private_key, hashes.SHA256())
    return cert, private_key


def generate_server_cert(
    ca_cert: x509.Certificate,
    ca_key: Any,
    common_name: str = "fleet.centralium.local",
    sans: list[str] | None = None,
    valid_days: int = 825,
    key_size: int = 2048,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Generate server TLS certificate signed by Root CA."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Centralium Fleet"),
        ]
    )
    now = _utc_now()

    san_entries: list[x509.GeneralName] = []
    host_list = sans or ["localhost", "127.0.0.1", common_name]
    for host in set(host_list):
        try:
            san_entries.append(x509.IPAddress(ip_address(host)))
        except ValueError:
            san_entries.append(x509.DNSName(host))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    return cert, private_key


def generate_client_cert(
    ca_cert: x509.Certificate,
    ca_key: Any,
    agent_id: str,
    valid_days: int = 365,
    key_size: int = 2048,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Generate agent client certificate signed by Root CA."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"agent:{agent_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Centralium Agent"),
        ]
    )
    now = _utc_now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    return cert, private_key


def cert_to_pem(cert: x509.Certificate) -> bytes:
    """Serialize X509 certificate to PEM bytes."""
    return cert.public_bytes(serialization.Encoding.PEM)


def key_to_pem(key: Any) -> bytes:
    """Serialize private key to unencrypted PEM bytes."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def save_pki_bundle(
    out_dir: Path,
    ca_cert: x509.Certificate,
    ca_key: Any,
    server_cert: x509.Certificate,
    server_key: Any,
    client_cert: x509.Certificate,
    client_key: Any,
) -> dict[str, Path]:
    """Write all generated certificates and keys to target directory."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "ca_cert": out_dir / "ca.crt",
        "ca_key": out_dir / "ca.key",
        "server_cert": out_dir / "server.crt",
        "server_key": out_dir / "server.key",
        "client_cert": out_dir / "client.crt",
        "client_key": out_dir / "client.key",
    }
    paths["ca_cert"].write_bytes(cert_to_pem(ca_cert))
    paths["ca_key"].write_bytes(key_to_pem(ca_key))
    paths["server_cert"].write_bytes(cert_to_pem(server_cert))
    paths["server_key"].write_bytes(key_to_pem(server_key))
    paths["client_cert"].write_bytes(cert_to_pem(client_cert))
    paths["client_key"].write_bytes(key_to_pem(client_key))
    return paths


def verify_certificate_signature(child_cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """Verify that child_cert was signed by issuer_cert."""
    issuer_public_key = issuer_cert.public_key()
    try:
        hash_algo = child_cert.signature_hash_algorithm
        if hash_algo is None:
            return False
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                child_cert.signature,
                child_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_algo,
            )
            return True
        if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                child_cert.signature,
                child_cert.tbs_certificate_bytes,
                ec.ECDSA(hash_algo),
            )
            return True
        return False
    except Exception:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Centralium mTLS PKI Generator")
    parser.add_argument("--out-dir", type=Path, default=Path("pki"), help="Directory to save PEM files")
    parser.add_argument("--server-hosts", nargs="+", default=["localhost", "127.0.0.1"], help="Server SANs")
    parser.add_argument("--agent-id", default="default-agent", help="Agent identifier for client cert")
    args = parser.parse_args()

    ca_cert, ca_key = generate_ca()
    server_cert, server_key = generate_server_cert(ca_cert, ca_key, sans=args.server_hosts)
    client_cert, client_key = generate_client_cert(ca_cert, ca_key, agent_id=args.agent_id)

    paths = save_pki_bundle(
        args.out_dir,
        ca_cert,
        ca_key,
        server_cert,
        server_key,
        client_cert,
        client_key,
    )
    print(f"PKI bundle created successfully in {args.out_dir}:")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    main()
