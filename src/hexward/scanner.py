"""File scanner: SHA-256 signatures + heuristics, multithreaded, with a clean-file cache."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import sqlite3
import sys
import time
import urllib.request
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from . import heuristics as H
from .core import IS_WINDOWS, Finding, Severity, data_dir

ENGINE_VERSION = 1
HEAD_SIZE = 4 * 1024 * 1024
CHUNK = 1024 * 1024

# FILE_ATTRIBUTE_REPARSE_POINT | OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS:
# junctions (loop risk) and cloud placeholders (reading would download them).
_SKIP_ATTRS = 0x400 | 0x1000 | 0x40000 | 0x400000


# Large media / disk-image / model-weight files cannot execute and dominate scan
# time, so the default scan checks only their header. `thorough=True` hashes them too.
MEDIA_EXTS = {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".m4v", ".mp3", ".flac", ".wav", ".ogg", ".m4a",
              ".aac", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".tif", ".tiff", ".psd", ".cr2",
              ".nef", ".vmdk", ".vdi", ".vhdx", ".qcow2", ".gguf", ".safetensors", ".onnx"}
MEDIA_SKIPPED: list = []  # sentinel returned by analyze_file (compared by identity)


# -------------------------------------------------------------- signatures

class Signatures:
    """SHA-256 blocklist. Text format: one `<sha256> [name]` per line, `#` comments."""

    BUILTIN = {
        # EICAR standard anti-malware test file (harmless by design)
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
    }

    def __init__(self):
        self.hashes: dict[bytes, str] = {}
        self._acc = 0
        for h, name in self.BUILTIN.items():
            self._add(h, name)

    def _add(self, hexdigest: str, name: str) -> bool:
        try:
            raw = bytes.fromhex(hexdigest)
        except ValueError:
            return False
        if len(raw) != 32:
            return False
        if raw not in self.hashes:
            self._acc ^= int.from_bytes(raw[:8], "big")
        self.hashes[raw] = name
        return True

    def load_file(self, path: Path) -> int:
        added = 0
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip().strip('"')
                if not line or line[0] == "#":
                    continue
                parts = line.replace(",", " ").split(None, 1)
                name = parts[1].strip().strip('"') if len(parts) > 1 else f"Blocklisted ({path.stem})"
                added += self._add(parts[0].strip('"'), name[:80])
        return added

    def load_user(self) -> None:
        sig_dir = data_dir() / "signatures"
        if sig_dir.is_dir():
            for p in sorted(sig_dir.glob("*.txt")):
                try:
                    self.load_file(p)
                except OSError:
                    pass

    @property
    def version(self) -> str:
        return f"{ENGINE_VERSION}:{len(self.hashes)}:{self._acc:x}"


def import_signatures(source: str) -> tuple[Path, int]:
    """Copy a hash list (local file or https URL) into the user signature directory."""
    sig_dir = data_dir() / "signatures"
    sig_dir.mkdir(exist_ok=True)
    if source.lower().startswith("http"):
        if not source.lower().startswith("https://"):
            raise ValueError("only https:// URLs are accepted")
        name = hashlib.sha256(source.encode()).hexdigest()[:12] + ".txt"
        tmp = sig_dir / (name + ".part")
        req = urllib.request.Request(source, headers={"User-Agent": "hexward"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(tmp, "wb") as out:
            total = 0
            while chunk := resp.read(CHUNK):
                total += len(chunk)
                if total > 512 * 1024 * 1024:
                    raise ValueError("signature list larger than 512 MB")
                out.write(chunk)
    else:
        src = Path(source)
        name = src.stem + ".txt"
        tmp = sig_dir / (name + ".part")
        tmp.write_bytes(src.read_bytes())
    probe = Signatures()
    base = len(probe.hashes)
    try:
        probe.load_file(tmp)
        count = len(probe.hashes) - base
        if count <= 0:
            raise ValueError("no SHA-256 hashes found in the source")
        dest = sig_dir / name
        os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)
    return dest, count


# ------------------------------------------------------------------- cache

class CleanCache:
    """Remembers files already found clean, keyed by path+size+mtime+signature version.

    Trade-off (documented in the README): a file whose content changes while its
    size and mtime are forged back is not rescanned. Use --no-cache for a full pass.
    """

    def __init__(self, version: str):
        self.version = version
        self.pending: list[tuple] = []
        self.db: sqlite3.Connection | None = None
        try:
            self.db = sqlite3.connect(str(data_dir() / "cache.db"), timeout=2)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=OFF")
            self.db.execute("CREATE TABLE IF NOT EXISTS clean(path TEXT PRIMARY KEY, size INTEGER,"
                            " mtime INTEGER, ver TEXT) WITHOUT ROWID")
        except sqlite3.Error:
            self.db = None

    def is_clean(self, path: str, size: int, mtime: int) -> bool:
        if self.db is None:
            return False
        try:
            row = self.db.execute("SELECT size, mtime, ver FROM clean WHERE path=?",
                                  (os.path.normcase(path),)).fetchone()
        except sqlite3.Error:
            self.db = None
            return False
        return row is not None and row == (size, mtime, self.version)

    def mark_clean(self, path: str, size: int, mtime: int) -> None:
        self.pending.append((os.path.normcase(path), size, mtime, self.version))
        if len(self.pending) >= 2000:
            self.flush()

    def flush(self) -> None:
        if self.db is None or not self.pending:
            self.pending.clear()
            return
        try:
            with self.db:
                self.db.executemany("INSERT OR REPLACE INTO clean VALUES (?,?,?,?)", self.pending)
        except sqlite3.Error:
            self.db = None
        self.pending.clear()

    def close(self) -> None:
        self.flush()
        if self.db is not None:
            self.db.close()
            self.db = None


# ---------------------------------------------------------------- analysis

def analyze_file(path: str, size: int, sigs: Signatures, thorough: bool = False) -> list[Finding]:
    """Hash and inspect one file. Raises OSError when the file cannot be read."""
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    reasons = H.name_reasons(name)
    findings: list[Finding] = []

    with open(path, "rb") as fh:
        head = fh.read(HEAD_SIZE)
        if (not thorough and size > HEAD_SIZE and ext in MEDIA_EXTS and not reasons
                and head[:2] not in (b"MZ", b"PK", b"#!") and head[:4] != b"\x7fELF"):
            return MEDIA_SKIPPED
        digest = hashlib.sha256(head)
        if size > len(head):
            while chunk := fh.read(CHUNK):
                digest.update(chunk)

        sig = sigs.hashes.get(digest.digest())
        if sig:
            return [Finding("malware-signature", Severity.CRITICAL, f"Known malware: {sig}", path,
                            [f"sha256 {digest.hexdigest()}"],
                            "Quarantine it (scan --quarantine) and check how it got there.")]

        kind = "file"
        if head[:2] == b"MZ":
            info = H.parse_pe(head)
            if info is not None:
                kind = "executable"

                def read_section(offset: int, length: int) -> bytes:
                    if offset + length <= len(head):
                        return head[offset:offset + length]
                    fh.seek(offset)
                    return fh.read(length)

                pe = H.pe_reasons(info, head, read_section)
                # a signature alone must not lower a name-based score
                if any(p > 0 for p, _ in pe):
                    reasons += pe
                if ext in H.INERT_EXTS:
                    reasons.append((4, f"Windows executable hidden behind a {ext} extension"))
        elif ext in H.SCRIPT_EXTS:
            kind = "script"
            score, why = H.score_text(H.decode_sample(head))
            reasons += [(score, "; ".join(why))] if score else []
        elif ext in (".py", ".pyw"):
            kind = "script"
            score, why = H.score_text(H.decode_sample(head), H.PYTHON_RULES)
            reasons += [(score, "; ".join(why))] if score else []

    total = sum(p for p, _ in reasons)
    if total >= 4:
        findings.append(Finding(
            "heuristic-" + kind, Severity.HIGH if total >= 6 else Severity.MEDIUM,
            f"Suspicious {kind} (heuristic score {total})", path,
            [r for _, r in reasons] + [f"sha256 {digest.hexdigest()}"],
            "Heuristics can be wrong. Look the hash up on VirusTotal before deleting anything.",
        ))
    return findings


# ----------------------------------------------------------------- walking

@dataclass
class ScanStats:
    files: int = 0
    scanned: int = 0
    cached: int = 0
    too_large: int = 0
    media: int = 0
    unreadable: int = 0
    bytes: int = 0
    seconds: float = 0.0
    interrupted: bool = False
    errors: list[str] = field(default_factory=list)

    def note(self) -> str:
        mb = self.bytes / 1e6
        rate = f", {mb / self.seconds:.0f} MB/s" if self.seconds > 0.05 else ""
        parts = [f"{self.files} files seen", f"{self.scanned} scanned ({mb:.0f} MB{rate})",
                 f"{self.cached} unchanged since last clean scan"]
        if self.media:
            parts.append(f"{self.media} large media files checked by header only")
        if self.too_large:
            parts.append(f"{self.too_large} over the size limit")
        if self.unreadable:
            parts.append(f"{self.unreadable} unreadable (locked or access denied)")
        if self.interrupted:
            parts.append("INTERRUPTED - results are partial")
        return "scan: " + ", ".join(parts) + f", {self.seconds:.1f}s"


def iter_files(roots: list[str], excludes: list[str], stats: ScanStats) -> Iterator[tuple[str, int, int]]:
    patterns = [p.replace("\\", "/").lower() for p in excludes]

    def excluded(path: str) -> bool:
        if not patterns:
            return False
        norm = path.replace("\\", "/").lower()
        return any(fnmatch.fnmatchcase(norm, p) for p in patterns)

    stack: list[str] = []
    for root in roots:
        try:
            st = os.stat(root)
        except OSError as exc:
            stats.errors.append(f"{root}: {exc.strerror or exc}")
            continue
        if os.path.isdir(root):
            stack.append(root)
        else:
            yield root, st.st_size, st.st_mtime_ns

    while stack:
        current = stack.pop()
        try:
            entries = os.scandir(current)
        except OSError:
            stats.unreadable += 1
            continue
        with entries:
            for entry in entries:
                try:
                    if entry.is_symlink() or excluded(entry.path):
                        continue
                    st = entry.stat(follow_symlinks=False)
                    if getattr(st, "st_file_attributes", 0) & _SKIP_ATTRS:
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        yield entry.path, st.st_size, st.st_mtime_ns
                except OSError:
                    stats.unreadable += 1


def scan(roots: list[str], *, use_cache: bool = True, workers: int = 0, max_size_mb: int = 256,
         excludes: list[str] | None = None, progress: bool = False,
         sigs: Signatures | None = None, thorough: bool = False) -> tuple[list[Finding], ScanStats]:
    if sigs is None:
        sigs = Signatures()
        sigs.load_user()
    stats = ScanStats()
    findings: list[Finding] = []
    cache = CleanCache(sigs.version + (":thorough" if thorough else "")) if use_cache else None
    workers = workers or min(8, (os.cpu_count() or 2))
    max_size = max_size_mb * 1024 * 1024
    started = time.perf_counter()
    last_tick = started
    in_flight: dict = {}

    def collect(done) -> None:
        for fut in done:
            path, size, mtime = in_flight.pop(fut)
            try:
                result = fut.result()
            except OSError:
                stats.unreadable += 1
                continue
            except Exception as exc:  # a parser bug must never abort the whole scan
                stats.errors.append(f"{path}: internal error {type(exc).__name__}: {exc}")
                continue
            stats.scanned += 1
            if result is MEDIA_SKIPPED:
                stats.media += 1
            else:
                stats.bytes += size
            if result:
                findings.extend(result)
            elif cache:
                cache.mark_clean(path, size, mtime)

    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan")
    try:
        for path, size, mtime in iter_files(roots, excludes or [], stats):
            stats.files += 1
            if size > max_size:
                stats.too_large += 1
                continue
            if cache and cache.is_clean(path, size, mtime):
                stats.cached += 1
                continue
            in_flight[pool.submit(analyze_file, path, size, sigs, thorough)] = (path, size, mtime)
            if len(in_flight) >= workers * 4:
                done, _ = wait(in_flight, return_when=FIRST_COMPLETED)
                collect(done)
            if progress:
                now = time.perf_counter()
                if now - last_tick > 0.5:
                    last_tick = now
                    sys.stderr.write(f"\r  {stats.files} files...")
                    sys.stderr.flush()
        collect(list(in_flight))
    except KeyboardInterrupt:
        stats.interrupted = True
        pool.shutdown(wait=False, cancel_futures=True)
    finally:
        pool.shutdown(wait=True)
        if cache:
            cache.close()
        if progress:
            sys.stderr.write("\r" + " " * 30 + "\r")
    stats.seconds = time.perf_counter() - started
    return findings, stats


# -------------------------------------------------------------- quarantine

_XOR = bytes(b ^ 0xA5 for b in range(256))


def _qdir() -> Path:
    q = data_dir() / "quarantine"
    q.mkdir(exist_ok=True)
    return q


def quarantine_file(path: str, reason: str) -> str:
    """Move a file into quarantine, stored XOR-masked so it can no longer execute."""
    src = Path(path).resolve()
    digest = hashlib.sha256()
    qid = f"{int(time.time())}-{os.urandom(3).hex()}"
    blob = _qdir() / (qid + ".bin")
    try:
        with open(src, "rb") as fin, open(blob, "wb") as fout:
            while chunk := fin.read(CHUNK):
                digest.update(chunk)
                fout.write(chunk.translate(_XOR))
        meta = {"id": qid, "path": str(src), "sha256": digest.hexdigest(), "reason": reason,
                "time": time.strftime("%Y-%m-%d %H:%M:%S")}
        (_qdir() / (qid + ".json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        src.unlink()
    except OSError:
        blob.unlink(missing_ok=True)
        (_qdir() / (qid + ".json")).unlink(missing_ok=True)
        raise
    return qid


def quarantine_list() -> list[dict]:
    items = []
    for meta in sorted(_qdir().glob("*.json")):
        try:
            items.append(json.loads(meta.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return items


def _find(qid: str) -> dict:
    if not qid or any(c in qid for c in "/\\.:"):
        raise ValueError("invalid quarantine id")
    meta = _qdir() / (qid + ".json")
    if not meta.is_file():
        raise ValueError(f"no quarantined item with id {qid}")
    return json.loads(meta.read_text(encoding="utf-8"))


def quarantine_restore(qid: str) -> str:
    meta = _find(qid)
    dest = Path(meta["path"])
    if dest.exists():
        raise ValueError(f"refusing to overwrite existing file {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    blob = _qdir() / (qid + ".bin")
    with open(blob, "rb") as fin, open(dest, "wb") as fout:
        while chunk := fin.read(CHUNK):
            fout.write(chunk.translate(_XOR))
    quarantine_delete(qid)
    return str(dest)


def quarantine_delete(qid: str) -> None:
    _find(qid)
    (_qdir() / (qid + ".bin")).unlink(missing_ok=True)
    (_qdir() / (qid + ".json")).unlink(missing_ok=True)


if IS_WINDOWS:
    def user_hotspots() -> list[str]:
        """Folders where malware most often lands; used by the quick scan."""
        home = Path.home()
        appdata = os.environ.get("APPDATA", "")
        spots = [home / "Downloads", home / "Desktop", Path(os.environ.get("TEMP", "")),
                 Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup",
                 Path(os.environ.get("PUBLIC", r"C:\Users\Public"))]
        return [str(p) for p in spots if str(p) not in ("", ".") and p.is_dir()]
else:
    def user_hotspots() -> list[str]:
        home = Path.home()
        spots = [home / "Downloads", home / "Desktop", Path("/tmp"), home / ".config/autostart",
                 home / "Library/LaunchAgents"]
        return [str(p) for p in spots if p.is_dir()]
