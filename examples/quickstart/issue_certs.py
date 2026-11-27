"""Quickstart TLS certificates, issued offline. issue makes a per-install CA in memory, signs one leaf for each service
that serves TLS, and discards the CA key, so revoking is rerunning with --reissue. Each service's key lands in its own
directory (one volume each), readable only by that service's group; the CA and the leaf certificates land in public.
A complete, valid set is kept on rerun; a partial or mixed set is refused. --reissue writes a new generation in every
directory and switches each one's current symlink only after every file is on disk. check fails when the set is
incomplete, does not chain, or expires within the margin, and can probe each served certificate over TLS, including
the configured upstream's when it is a server in the stack."""

from __future__ import annotations

import argparse
import contextlib
import datetime
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import sys
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERTS = Path("/var/lib/bailiff/certs")
PUBLIC = "public"
CURRENT = "current"
GENERATION = re.compile(r"gen-(\d{4,})")
DEFAULT_DAYS = 365
MARGIN_DAYS = 30
SKEW = datetime.timedelta(minutes=5)
PROBE_TIMEOUT_SECONDS = 5
RUNBOOK = (
    "the certificate set is partial or mixed; reissue it with the stack stopped: "
    "docker compose stop && docker compose run --rm certs issue --reissue && docker compose up -d"
)


@dataclass(frozen=True)
class Service:
    names: tuple[str, ...]
    gid: int


SERVICES: Mapping[str, Service] = {
    "gateway": Service(("gateway", "localhost", "127.0.0.1"), 20005),
    "stub-upstream": Service(("stub-upstream",), 20006),
    "gitea-mcp-tls": Service(("gitea-mcp-tls",), 20007),
}


class CertError(Exception):
    pass


@dataclass(frozen=True)
class Issued:
    ca: x509.Certificate
    leaves: Mapping[str, tuple[x509.Certificate, ec.EllipticCurvePrivateKey]]


def make_ca(now: datetime.datetime, days: int) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-bailiff quickstart install CA")])
    usage = dict.fromkeys(
        (
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "encipher_only",
            "decipher_only",
        ),
        False,
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - SKEW)
        .not_valid_after(now + datetime.timedelta(days=2 * days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(**usage, key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate, key


def make_leaf(
    ca: tuple[x509.Certificate, ec.EllipticCurvePrivateKey], names: Sequence[str], now: datetime.datetime, days: int
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    certificate_authority, ca_key = ca
    key = ec.generate_private_key(ec.SECP256R1())
    usage = dict.fromkeys(
        (
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "encipher_only",
            "decipher_only",
        ),
        False,
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(certificate_authority.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - SKEW)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(**usage, digital_signature=True), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([general_name(name) for name in names]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return certificate, key


def general_name(name: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(name))
    except ValueError:
        return x509.DNSName(name)


def sign_set(services: Mapping[str, Service], now: datetime.datetime, days: int) -> Issued:
    ca = make_ca(now, days)
    leaves = {name: make_leaf(ca, service.names, now, days) for name, service in services.items()}
    return Issued(ca[0], leaves)


def pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(Encoding.PEM)


def private_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def directories(certs: Path, services: Mapping[str, Service]) -> list[Path]:
    return [certs / PUBLIC, *(certs / name for name in services)]


def generations(directory: Path) -> list[int]:
    return sorted(int(match[1]) for entry in os.listdir(directory) if (match := GENERATION.fullmatch(entry)))


def current_generation(directory: Path) -> str | None:
    link = directory / CURRENT
    if not link.is_symlink():
        if link.exists():
            raise CertError(f"{link} is not a symlink")
        return None
    target = os.readlink(link)
    if not GENERATION.fullmatch(target):
        raise CertError(f"{link} points at {target!r}, not a generation")
    return target


def write_file(path: Path, data: bytes, mode: int, gid: int | None = None) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if gid is not None:
            os.fchown(fd, -1, gid)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_generation(certs: Path, services: Mapping[str, Service], issued: Issued, number: int) -> str:
    name = f"gen-{number:04d}"
    made = []
    try:
        public = certs / PUBLIC / name
        public.mkdir(mode=0o755)
        made.append(public)
        write_file(public / "ca.pem", pem(issued.ca), 0o444)
        for service in services:
            write_file(public / f"{service}.pem", pem(issued.leaves[service][0]), 0o444)
        fsync_directory(public)
        for service, settings in services.items():
            directory = certs / service / name
            directory.mkdir(mode=0o755)
            made.append(directory)
            certificate, key = issued.leaves[service]
            write_file(directory / f"{service}.pem", pem(certificate), 0o444)
            write_file(directory / f"{service}.key", private_pem(key), 0o440, settings.gid)
            fsync_directory(directory)
        for directory in made:
            fsync_directory(directory.parent)
    except BaseException:
        for directory in made:
            shutil.rmtree(directory, ignore_errors=True)
        raise
    return name


def switch(directory: Path, generation: str) -> None:
    staged = directory / f".{CURRENT}.{os.getpid()}"
    with contextlib.suppress(FileNotFoundError):
        os.unlink(staged)
    os.symlink(generation, staged)
    os.replace(staged, directory / CURRENT)
    fsync_directory(directory)


def prune(directory: Path, keep: set[str]) -> None:
    for number in generations(directory):
        name = f"gen-{number:04d}"
        if name not in keep:
            shutil.rmtree(directory / name)
    for entry in os.listdir(directory):
        if entry.startswith(f".{CURRENT}."):
            os.unlink(directory / entry)


def issue(
    certs: Path,
    services: Mapping[str, Service],
    days: int,
    *,
    reissue: bool = False,
    now: Callable[[], datetime.datetime] = lambda: datetime.datetime.now(datetime.UTC),
) -> str:
    folders = directories(certs, services)
    currents = {directory: current_generation(directory) for directory in folders}
    if not reissue and all(currents.values()):
        if len(set(currents.values())) > 1:
            raise CertError(f"the directories point at different generations; {RUNBOOK}")
        problems = check(certs, services, now(), 0, keys=True)
        if problems:
            raise CertError(f"{'; '.join(problems)}; {RUNBOOK}")
        return f"kept {currents[certs / PUBLIC]}"
    if not reissue and any(currents.values()):
        raise CertError(RUNBOOK)
    number = 1 + max((max(generations(directory), default=0) for directory in folders), default=0)
    generation = write_generation(certs, services, sign_set(services, now(), days), number)
    for directory in folders:
        switch(directory, generation)
    for directory in folders:
        prune(directory, {generation, *filter(None, [currents[directory]])})
    return f"issued {generation}"


def load_certificate(path: Path) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError) as error:
        raise CertError(f"{path} is missing or not a PEM certificate: {error}") from None


def public_bytes(key: object) -> bytes:
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise CertError("the key is not an EC key")
    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def check(
    certs: Path, services: Mapping[str, Service], now: datetime.datetime, margin_days: int, *, keys: bool = False
) -> list[str]:
    problems: list[str] = []
    deadline = now + datetime.timedelta(days=margin_days)
    public = certs / PUBLIC / CURRENT
    try:
        ca = load_certificate(public / "ca.pem")
    except CertError as error:
        return [str(error)]
    if ca.not_valid_after_utc <= deadline:
        problems.append(f"the CA expires at {ca.not_valid_after_utc.isoformat()}")
    for service in services:
        try:
            problems.extend(check_leaf(certs, service, ca, deadline, keys=keys))
        except CertError as error:
            problems.append(str(error))
    return problems


def check_leaf(
    certs: Path, service: str, ca: x509.Certificate, deadline: datetime.datetime, *, keys: bool
) -> list[str]:
    problems = []
    leaf = load_certificate(certs / PUBLIC / CURRENT / f"{service}.pem")
    try:
        leaf.verify_directly_issued_by(ca)
    except (ValueError, TypeError, InvalidSignature) as error:
        problems.append(f"{service}.pem is not signed by the install CA: {error}")
    if leaf.not_valid_after_utc <= deadline:
        problems.append(f"{service}.pem expires at {leaf.not_valid_after_utc.isoformat()}")
    if keys:
        directory = certs / service / CURRENT
        if load_certificate(directory / f"{service}.pem") != leaf:
            problems.append(f"{service}'s certificate differs from the public one")
        try:
            key = load_pem_private_key((directory / f"{service}.key").read_bytes(), None)
        except (OSError, ValueError, TypeError) as error:
            raise CertError(f"{service}.key is missing or unreadable: {error}") from None
        if public_bytes(key.public_key()) != public_bytes(leaf.public_key()):
            problems.append(f"{service}.key does not match {service}.pem")
    return problems


def probe(certs: Path, service: str, address: str) -> list[str]:
    host, _, port = address.rpartition(":")
    if not host or not port.isdigit():
        return [f"probe {address!r} is not host:port"]
    context = ssl.create_default_context(cafile=certs / PUBLIC / CURRENT / "ca.pem")
    expected = load_certificate(certs / PUBLIC / CURRENT / f"{service}.pem").public_bytes(Encoding.DER)
    try:
        with (
            socket.create_connection((host, int(port)), timeout=PROBE_TIMEOUT_SECONDS) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            served = tls.getpeercert(binary_form=True)
    except OSError as error:
        return [f"{service} at {address} failed TLS with the install CA: {error}"]
    if served != expected:
        return [f"{service} at {address} serves a certificate other than the current one; restart it"]
    return []


def upstream_probe(path: Path) -> list[tuple[str, str]]:
    try:
        url = urllib.parse.urlsplit(json.loads(path.read_text())["url"])
        port = url.port or 443
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        raise CertError(f"{path} names no upstream url: {error}") from None
    host = url.hostname
    if url.scheme != "https" or host is None or host not in SERVICES:
        return []
    return [(host, f"{host}:{port}")]


def parse_probe(value: str) -> tuple[str, str]:
    service, separator, address = value.partition("=")
    if not separator or service not in SERVICES:
        raise argparse.ArgumentTypeError(f"--probe takes SERVICE=HOST:PORT with SERVICE one of {sorted(SERVICES)}")
    return service, address


def main(argv: Sequence[str] | None = None, services: Mapping[str, Service] = SERVICES) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certs", type=Path, default=CERTS, help="directory holding public and one per service")
    commands = parser.add_subparsers(dest="command", required=True)
    issuing = commands.add_parser("issue", help="issue the set, or keep a complete one")
    issuing.add_argument("--days", type=int, default=DEFAULT_DAYS, help="leaf lifetime; the CA lives twice as long")
    issuing.add_argument("--reissue", action="store_true", help="issue a new CA and every leaf; stop the stack first")
    checking = commands.add_parser("check", help="exit 1 when the set is incomplete or expires within the margin")
    checking.add_argument("--margin-days", type=int, default=MARGIN_DAYS)
    checking.add_argument("--keys", action="store_true", help="also check each key against its certificate")
    checking.add_argument("--probe", type=parse_probe, action="append", default=[], help="SERVICE=HOST:PORT")
    checking.add_argument(
        "--probe-upstream", type=Path, help="upstream config; probe its url when a stack server serves it"
    )
    args = parser.parse_args(argv)
    try:
        print(run(args, services))
    except (CertError, OSError) as error:
        print(f"issue_certs {args.command} refused: {error}", file=sys.stderr)
        return 1
    return 0


def run(args: argparse.Namespace, services: Mapping[str, Service]) -> str:
    if args.command == "issue":
        if args.days < 1:
            raise CertError("--days must be at least 1")
        return issue(args.certs, services, args.days, reissue=args.reissue)
    problems = check(args.certs, services, datetime.datetime.now(datetime.UTC), args.margin_days, keys=args.keys)
    probes = set(args.probe)
    if args.probe_upstream is not None:
        probes.update(upstream_probe(args.probe_upstream))
    for service, address in sorted(probes):
        problems.extend(probe(args.certs, service, address))
    if problems:
        raise CertError("; ".join(problems))
    return "certificates ok"


if __name__ == "__main__":
    sys.exit(main())
