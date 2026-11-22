from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from pathlib import PurePosixPath


MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_UNPACKED_BYTES = 200 * 1024 * 1024
MAX_FILES = 5_000
MAX_FILE_BYTES = 1_000_000


class ArchiveError(ValueError):
    pass


def _safe_name(name: str) -> str:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts or "\x00" in normalized:
        raise ArchiveError("Archive contains an unsafe path")
    if len(normalized) > 500 or any(part in {"", "."} for part in path.parts):
        raise ArchiveError("Archive contains an invalid path")
    return path.as_posix()


def read_zip(payload: bytes) -> dict[str, bytes]:
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise ArchiveError("ZIP file exceeds the 50 MB upload limit")
    files: dict[str, bytes] = {}
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_FILES:
                raise ArchiveError("ZIP file contains too many entries")
            for entry in entries:
                if entry.is_dir():
                    continue
                path = _safe_name(entry.filename)
                mode = (entry.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise ArchiveError("ZIP symlinks are not accepted")
                if entry.flag_bits & 0x1:
                    raise ArchiveError("Encrypted ZIP entries are not accepted")
                if entry.file_size > MAX_FILE_BYTES:
                    continue
                total += entry.file_size
                if total > MAX_UNPACKED_BYTES:
                    raise ArchiveError("Expanded ZIP exceeds the 200 MB limit")
                if entry.file_size > max(entry.compress_size, 1) * 1_000:
                    raise ArchiveError("ZIP compression ratio is too high")
                with archive.open(entry, "r") as stream:
                    content = stream.read(MAX_FILE_BYTES + 1)
                if len(content) != entry.file_size:
                    raise ArchiveError("ZIP entry size did not match its metadata")
                files[path] = content
    except (zipfile.BadZipFile, RuntimeError, OSError) as error:
        raise ArchiveError("Upload is not a readable ZIP file") from error
    return files


def read_tar_gz(payload: bytes) -> dict[str, bytes]:
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise ArchiveError("Repository archive exceeds the 50 MB limit")
    files: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            for index, entry in enumerate(archive):
                if index >= MAX_FILES:
                    raise ArchiveError("Repository archive contains too many entries")
                if not entry.isfile():
                    continue
                path = _safe_name(entry.name)
                if entry.size > MAX_FILE_BYTES:
                    continue
                total += entry.size
                if total > MAX_UNPACKED_BYTES:
                    raise ArchiveError("Expanded repository archive exceeds the 200 MB limit")
                stream = archive.extractfile(entry)
                if stream is None:
                    continue
                content = stream.read(MAX_FILE_BYTES + 1)
                if len(content) != entry.size:
                    raise ArchiveError("Repository archive entry size did not match metadata")
                files[path] = content
    except (tarfile.TarError, OSError) as error:
        raise ArchiveError("Repository archive is not readable") from error
    return files
