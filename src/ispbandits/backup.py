"""Online SQLite backup and rollback-safe restore helpers."""
# © 2026 ISPbandits Dev. All rights reserved.
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
import sqlite3
import tempfile
import tarfile
from datetime import datetime, timezone
from typing import Iterator

MAX_DATABASE_BYTES = 16 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def create_backup(database: Path | str, backup_dir: Path | str) -> Path:
    database, backup_dir = Path(database), Path(backup_dir)
    if not database.is_file() or database.is_symlink():
        raise FileNotFoundError(database)
    if backup_dir.is_symlink():
        raise ValueError("Backup directory must not be a symlink")
    existed = backup_dir.exists()
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not existed:
        os.chmod(backup_dir, 0o700)
    elif stat.S_IMODE(backup_dir.stat().st_mode) & 0o077:
        raise PermissionError("Backup directory must be private (mode 0700); choose a dedicated directory")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    target = backup_dir / f"ispbandits-{stamp}.tar.gz"
    with tempfile.TemporaryDirectory(dir=backup_dir) as td:
        staged = Path(td) / "database.db"
        src = sqlite3.connect(str(database), timeout=15)
        dst = sqlite3.connect(str(staged))
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        os.chmod(staged, 0o600)
        manifest = {
            "format": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "database_sha256": _sha256(staged),
        }
        manifest_path = Path(td) / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        os.chmod(manifest_path, 0o600)
        temp_archive = Path(td) / "archive.tar.gz"
        with tarfile.open(temp_archive, "w:gz") as tar:
            tar.add(staged, arcname="database.db", recursive=False)
            tar.add(manifest_path, arcname="manifest.json", recursive=False)
        os.chmod(temp_archive, 0o600)
        archive_fd = os.open(temp_archive, os.O_RDONLY)
        try:
            os.fsync(archive_fd)
        finally:
            os.close(archive_fd)
        # A hard-link publish is atomic and refuses to overwrite any existing archive.
        os.link(temp_archive, target)
        directory_fd = os.open(backup_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    os.chmod(target, 0o600)
    return target


def _validate_sqlite(path: Path) -> None:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        result = conn.execute("PRAGMA integrity_check").fetchone()
        if not result or result[0] != "ok":
            raise ValueError("Backup SQLite integrity check failed")
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'").fetchone():
            raise ValueError("Backup is missing the users table")
    finally:
        conn.close()


def _extract_validated_archive(archive: Path, staged: Path) -> None:
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        allowed = {"database.db", "manifest.json"}
        if len(members) != 2 or {member.name for member in members} != allowed:
            raise ValueError("Unexpected backup archive contents")
        if any(not member.isfile() or member.issym() or member.islnk()
               or PurePosixPath(member.name).is_absolute()
               or ".." in PurePosixPath(member.name).parts for member in members):
            raise ValueError("Unsafe backup archive member")
        sizes = {member.name: member.size for member in members}
        if sizes["database.db"] < 100 or sizes["database.db"] > MAX_DATABASE_BYTES:
            raise ValueError("Backup database size is outside the supported restore limit")
        if sizes["manifest.json"] > MAX_MANIFEST_BYTES:
            raise ValueError("Backup manifest is too large")
        db_member = tar.extractfile("database.db")
        manifest_member = tar.extractfile("manifest.json")
        if db_member is None or manifest_member is None:
            raise ValueError("Backup archive is incomplete")
        with db_member, manifest_member:
            try:
                manifest = json.loads(manifest_member.read(MAX_MANIFEST_BYTES + 1).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("Backup manifest is invalid JSON") from exc
            if not isinstance(manifest, dict) or type(manifest.get("format")) is not int or manifest["format"] != 1:
                raise ValueError("Unsupported backup format")
            expected_digest = manifest.get("database_sha256")
            if not isinstance(expected_digest, str) or not _SHA256_RE.fullmatch(expected_digest):
                raise ValueError("Backup manifest checksum is invalid")
            with staged.open("wb") as output:
                copied = 0
                while True:
                    block = db_member.read(1024 * 1024)
                    if not block:
                        break
                    copied += len(block)
                    if copied > MAX_DATABASE_BYTES:
                        raise ValueError("Backup database exceeds the supported restore limit")
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
    os.chmod(staged, 0o600)
    if _sha256(staged) != expected_digest:
        raise ValueError("Backup checksum does not match")
    _validate_sqlite(staged)


@contextmanager
def prepare_restore(archive: Path | str, database_parent: Path | str) -> Iterator[Path]:
    """Extract and validate an archive without changing the live database or services.

    The yielded candidate resides on the same filesystem as the target database,
    so a later install can be committed atomically after service writers are paused.
    """
    archive, database_parent = Path(archive), Path(database_parent)
    if not archive.is_file() or archive.is_symlink():
        raise FileNotFoundError(archive)
    if database_parent.exists() and not database_parent.is_dir():
        raise NotADirectoryError(database_parent)
    database_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ispbandits-restore-stage.", dir=database_parent) as td:
        staged = Path(td) / "database.db"
        try:
            _extract_validated_archive(archive, staged)
        except (EOFError, tarfile.TarError, OSError) as exc:
            raise ValueError("Backup archive is unreadable or truncated") from exc
        yield staged


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install_validated_restore(database: Path | str, staged: Path | str,
                              backup_dir: Path | str) -> Path | None:
    """Atomically install a previously validated SQLite file with filesystem rollback."""
    database, staged = Path(database), Path(staged)
    if not staged.is_file() or staged.is_symlink():
        raise ValueError("Validated restore candidate is unavailable")
    _validate_sqlite(staged)
    if database.is_symlink():
        raise ValueError("Refusing to replace a symlinked database")
    database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    rollback = create_backup(database, backup_dir) if database.exists() else None
    sidecars = (Path(str(database) + "-wal"), Path(str(database) + "-shm"))
    for candidate in (database, *sidecars):
        if candidate.is_symlink():
            raise ValueError(f"Refusing to replace a symlinked SQLite file: {candidate}")
        if candidate.exists() and not candidate.is_file():
            raise ValueError(f"Refusing to replace a non-regular SQLite file: {candidate}")

    with tempfile.TemporaryDirectory(prefix=f".{database.name}.restore-rollback.",
                                     dir=database.parent) as td:
        preserved_dir = Path(td)
        preserved: list[tuple[Path, Path]] = []
        fd, replacement_name = tempfile.mkstemp(prefix=f".{database.name}.restore.",
                                                 suffix=".tmp", dir=database.parent)
        replacement = Path(replacement_name)
        installed = False
        try:
            with os.fdopen(fd, "wb") as destination:
                with staged.open("rb") as source:
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        destination.write(block)
                    destination.flush()
                    os.fsync(destination.fileno())
            os.chmod(replacement, 0o600)
            for original in (database, *sidecars):
                if original.exists():
                    saved = preserved_dir / original.name
                    os.replace(original, saved)
                    preserved.append((saved, original))
            os.replace(replacement, database)
            installed = True
            _fsync_directory(database.parent)
        except Exception:
            if installed:
                database.unlink(missing_ok=True)
            for saved, original in reversed(preserved):
                if saved.exists():
                    os.replace(saved, original)
            _fsync_directory(database.parent)
            raise
        finally:
            replacement.unlink(missing_ok=True)
    return rollback


def restore_backup(database: Path | str, archive: Path | str,
                   backup_dir: Path | str) -> Path | None:
    """Validate the archive, preserve a rollback copy, then atomically restore it."""
    database = Path(database)
    with prepare_restore(archive, database.parent) as staged:
        return install_validated_restore(database, staged, backup_dir)
