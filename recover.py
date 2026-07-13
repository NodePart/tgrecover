import annotations
import argparse
import csv
import gzip
import hashlib
import json
import math
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Iterable


def ensure_tgcrypto() -> None:
    try:
        import tgcrypto
        return
    except ModuleNotFoundError:
        pass

    script_dir = Path(__file__).resolve().parent
    candidates: list[Path] = []

    env_python = os.environ.get("TGARTIFACTS_PYTHON")
    if env_python:
        candidates.append(Path(env_python))

    for base in [script_dir, *script_dir.parents]:
        candidates.extend(
            [
                base / "tgartifacts_venv/bin/python",
                base / "venv/bin/python",
                base / ".venv/bin/python",
            ]
        )

    codex_root = Path.home() / "Documents/Codex"
    if codex_root.exists():
        try:
            candidates.extend(codex_root.glob("2026-*/**/tgartifacts_venv/bin/python"))
        except OSError:
            pass

    current = Path(sys.executable).resolve()
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            if candidate.resolve() == current:
                continue
            subprocess.run(
                [str(candidate), "-c", "import tgcrypto"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=5,
            )
        except Exception:
            continue
        os.execv(str(candidate), [str(candidate), *sys.argv])

    print(
        "Missing dependency: tgcrypto\n"
        "Install it with: python3 -m pip install tgcrypto\n"
        "Or run with the TGArtifacts venv Python, for example:\n"
        "  /path/to/tgartifacts_venv/bin/python telegram_recover_auto.py 11:20-11:30",
        file=sys.stderr,
    )
    sys.exit(2)


ensure_tgcrypto()
import tgcrypto 


IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif"}
VIDEO_EXTS = {".mp4", ".mov", ".m4v", ".webm", ".mkv"}
AUDIO_EXTS = {".ogg", ".opus", ".mp3", ".m4a", ".aac", ".wav", ".flac", ".amr", ".caf", ".aiff"}
DOCUMENT_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf",
}
ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"}
APP_EXTS = {".apk", ".ipa", ".dmg", ".pkg", ".exe", ".dll", ".msi", ".elf", ".macho", ".deb", ".rpm", ".jar"}
TEXT_EXTS = {".txt", ".json", ".xml", ".html", ".htm", ".csv", ".tsv", ".log", ".md", ".srt", ".ass", ".vtt"}
EBOOK_EXTS = {".epub", ".mobi", ".azw3"}
FONT_EXTS = {".ttf", ".otf", ".woff", ".woff2"}
CONTACT_EXTS = {".vcf", ".ics"}
FILE_EXTS = DOCUMENT_EXTS | ARCHIVE_EXTS | APP_EXTS | TEXT_EXTS | EBOOK_EXTS | FONT_EXTS | CONTACT_EXTS
SELECTOR_NAMES = (
    "images", "videos", "audio", "files", "voice", "stickers", "gifs", "round", "thumbnails"
)
OUTPUT_KINDS = SELECTOR_NAMES


@dataclass
class RecoveredFile:
    index: int
    status: str
    user_dir: str
    cache_mtime: str
    source_cache: str
    output_file: str
    category: str
    matches: str
    extension: str
    bytes: int
    note: str = ""


@dataclass
class Classification:
    kind: str
    selectors: set[str]
    note: str = ""


@dataclass
class UserDataInfo:
    index: int
    user_dir: Path
    account_dir: str
    dataname: str
    is_main: bool
    cache_files: int
    latest_cache: str
    window_hits: int
    user_id: str = ""
    dc_id: str = ""
    display_name: str = ""
    username: str = ""
    note: str = ""


def read_tdf(path: Path) -> tuple[int, bytes]:
    content = path.read_bytes()
    if len(content) < 24 or content[:4] != b"TDF$":
        raise ValueError(f"not a TDF file: {path}")
    version = int.from_bytes(content[4:8], "little")
    data = content[8:-16]
    stored = content[-16:]
    calculated = hashlib.md5(
        data + len(data).to_bytes(4, "little") + content[4:8] + b"TDF$"
    ).digest()
    if calculated != stored:
        raise ValueError(f"TDF checksum mismatch: {path}")
    return version, data


def read_array(data: bytes, offset: int, endian: str = "big") -> tuple[bytes | None, int]:
    if offset + 4 > len(data):
        raise ValueError("array length out of range")
    length = int.from_bytes(data[offset : offset + 4], endian)
    offset += 4
    if length == 0xFFFFFFFF:
        return None, offset
    if offset + length > len(data):
        raise ValueError(f"array payload out of range: {length}")
    return data[offset : offset + length], offset + length


def create_modern_local_key(passcode: bytes, salt: bytes) -> bytes:
    iterations = 100000 if passcode else 1
    pass_hash = hashlib.sha512(salt + passcode + salt).digest()
    return hashlib.pbkdf2_hmac("sha512", pass_hash, salt, iterations, 256)


def oldmtp_keys(auth_key: bytes, msg_key: bytes) -> tuple[bytes, bytes]:
    x = 8
    msg_key = msg_key[:16]
    sha1_a = hashlib.sha1(msg_key + auth_key[x : x + 32]).digest()
    sha1_b = hashlib.sha1(
        auth_key[x + 32 : x + 48] + msg_key + auth_key[x + 48 : x + 64]
    ).digest()
    sha1_c = hashlib.sha1(auth_key[x + 64 : x + 96] + msg_key).digest()
    sha1_d = hashlib.sha1(msg_key + auth_key[x + 96 : x + 128]).digest()
    aes_key = sha1_a[:8] + sha1_b[8:20] + sha1_c[4:16]
    aes_iv = sha1_a[8:20] + sha1_b[:8] + sha1_c[16:20] + sha1_d[:8]
    return aes_key, aes_iv


def decrypt_local(encrypted: bytes, local_key: bytes) -> bytes:
    if len(encrypted) < 32 or len(encrypted) % 16:
        raise ValueError(f"invalid encrypted local length: {len(encrypted)}")
    msg_key = encrypted[:16]
    aes_key, aes_iv = oldmtp_keys(local_key, msg_key)
    decrypted = tgcrypto.ige256_decrypt(encrypted[16:], aes_key, aes_iv)
    if hashlib.sha1(decrypted).digest()[:16] != msg_key:
        raise ValueError("local msg_key mismatch")
    return decrypted


def load_local_key(tdata: Path, passcode: str = "") -> bytes:
    _, body = read_tdf(tdata / "key_datas")
    salt, pos = read_array(body, 0, "big")
    key_encrypted, pos = read_array(body, pos, "big")
    info_encrypted, _ = read_array(body, pos, "big")
    if salt is None or key_encrypted is None or info_encrypted is None:
        raise ValueError("invalid key_datas arrays")

    passcode_key = create_modern_local_key(passcode.encode("utf-8"), salt)
    key_inner = decrypt_local(key_encrypted, passcode_key)
    key_array, _ = read_array(key_inner, 0, "little")
    if key_array is None or len(key_array) < 256:
        raise ValueError("local key array too small")
    local_key = key_array[:256]

    info = decrypt_local(info_encrypted, local_key)
    if len(info) < 8:
        raise ValueError("key info too short")
    return local_key


def decrypt_tdef(path: Path, local_key: bytes) -> bytes:
    content = path.read_bytes()
    if len(content) < 4 + 64 + 48 or content[:4] != b"TDEF":
        raise ValueError("not a TDEF cache file")
    salt = content[4:68]
    encrypted = content[68:]
    real_key = hashlib.sha256(local_key[:128] + salt[:32]).digest()
    iv = hashlib.sha256(local_key[128:] + salt[32:]).digest()[:16]
    decrypted_all = tgcrypto.ctr256_decrypt(encrypted, real_key, iv, bytes(1))
    header = decrypted_all[:48]
    payload = decrypted_all[48:]
    data_part = header[:16]
    stored_checksum = header[16:48]
    expected_checksum = hashlib.sha256(local_key + salt + data_part).digest()
    if stored_checksum != expected_checksum:
        raise ValueError("TDEF checksum mismatch")
    return payload


def parse_streaming_cache(data: bytes) -> tuple[bytes, bool]:
    if len(data) < 4:
        return data, False
    count = int.from_bytes(data[:4], "little")
    if count == 0 or count > 1000:
        return data, False
    pos = 4
    parts = []
    try:
        for _ in range(count):
            if pos + 8 > len(data):
                return data, False
            offset = int.from_bytes(data[pos : pos + 4], "little")
            size = int.from_bytes(data[pos + 4 : pos + 8], "little")
            pos += 8
            if size == 0 or pos + size > len(data):
                return data, False
            parts.append((offset, data[pos : pos + size]))
            pos += size
    except Exception:
        return data, False

    max_end = max(offset + len(chunk) for offset, chunk in parts)
    if max_end > 2 * 1024 * 1024 * 1024:
        return data, False
    assembled = bytearray(max_end)
    for offset, chunk in parts:
        assembled[offset : offset + len(chunk)] = chunk
    return bytes(assembled), True


def looks_like_text(data: bytes) -> bool:
    sample = data[:8192]
    if not sample or b"\x00" in sample:
        return False
    for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
        try:
            text = sample.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        return False
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return printable / max(1, len(text)) > 0.85


def detect_text_ext(data: bytes) -> str:
    sample = data[:8192].lstrip()
    upper = sample[:256].upper()
    if upper.startswith(b"BEGIN:VCARD"):
        return ".vcf"
    if upper.startswith(b"BEGIN:VCALENDAR"):
        return ".ics"
    if upper.startswith(b"WEBVTT"):
        return ".vtt"
    if re.match(rb"\d+\s*\r?\n\d{1,2}:\d{2}:\d{2}[,.]\d{1,3}\s*-->", sample[:512]):
        return ".srt"
    if sample.startswith((b"{", b"[")):
        return ".json"
    if sample.startswith((b"<!DOCTYPE html", b"<!doctype html", b"<html", b"<HTML")):
        return ".html"
    if sample.startswith(b"<?xml"):
        return ".xml"
    if b"\t" in sample[:2048] and b"\n" in sample[:2048]:
        return ".tsv"
    if b"," in sample[:2048] and b"\n" in sample[:2048]:
        return ".csv"
    return ".txt"


def detect_zip_ext(data: bytes) -> str:
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            names = set(zf.namelist())
            lower_names = {name.lower() for name in names}
            if "androidmanifest.xml" in lower_names or "classes.dex" in lower_names:
                return ".apk"
            if any(name.startswith("Payload/") for name in names):
                return ".ipa"
            if "word/document.xml" in lower_names:
                return ".docx"
            if "xl/workbook.xml" in lower_names:
                return ".xlsx"
            if "ppt/presentation.xml" in lower_names:
                return ".pptx"
            if "meta-inf/manifest.mf" in lower_names:
                return ".jar"
            if "mimetype" in names:
                try:
                    mimetype = zf.read("mimetype").decode("ascii", errors="ignore")
                    if mimetype == "application/epub+zip":
                        return ".epub"
                    if mimetype == "application/vnd.oasis.opendocument.text":
                        return ".odt"
                    if mimetype == "application/vnd.oasis.opendocument.spreadsheet":
                        return ".ods"
                    if mimetype == "application/vnd.oasis.opendocument.presentation":
                        return ".odp"
                except Exception:
                    pass
    except Exception:
        pass
    return ".zip"


def is_tgs_data(data: bytes) -> bool:
    if not data.startswith(b"\x1f\x8b"):
        return False
    try:
        decoded = gzip.decompress(data)
    except Exception:
        return False
    sample = decoded[:4096].lstrip()
    return sample.startswith(b"{") and b'"layers"' in sample and b'"v"' in sample


def detect_ext(data: bytes) -> str:
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return ".gif"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return ".webp"
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return ".wav"
    if data.startswith(b"OggS"):
        return ".ogg"
    if data.startswith(b"ID3") or (len(data) >= 2 and data[0] == 0xFF and data[1] & 0xE0 == 0xE0):
        return ".mp3"
    if data.startswith(b"fLaC"):
        return ".flac"
    if data.startswith(b"#!AMR"):
        return ".amr"
    if data.startswith(b"caff"):
        return ".caf"
    if data.startswith(b"FORM") and data[8:12] in (b"AIFF", b"AIFC"):
        return ".aiff"
    if data[:4] == b"\x1a\x45\xdf\xa3":
        return ".webm"
    if data.startswith(b"\x1f\x8b"):
        return ".tgs" if is_tgs_data(data) else ".gz"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return ".7z"
    if data.startswith(b"Rar!\x1a\x07"):
        return ".rar"
    if data.startswith(b"\xfd7zXZ\x00"):
        return ".xz"
    if data.startswith(b"BZh"):
        return ".bz2"
    if len(data) > 265 and data[257:262] == b"ustar":
        return ".tar"
    if data.startswith(b"MZ"):
        return ".exe"
    if data.startswith(b"\x7fELF"):
        return ".elf"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return ".macho"
    if data.startswith(b"xar!"):
        return ".pkg"
    if data.startswith(b"!<arch>"):
        return ".deb"
    if data.startswith(b"ttcf") or data[:4] in (b"\x00\x01\x00\x00", b"OTTO"):
        return ".ttf"
    if data.startswith(b"wOFF"):
        return ".woff"
    if data.startswith(b"wOF2"):
        return ".woff2"
    if len(data) >= 12 and data[4:12] in (b"ftypheic", b"ftypheix", b"ftyphevc", b"ftypmif1"):
        return ".heic"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12]
        brand_lower = brand.lower()
        if brand in (b"M4A ", b"M4B ", b"M4P "):
            return ".m4a"
        if brand_lower in (b"qt  ", b"moov"):
            return ".mov"
        return ".mp4"
    if data.startswith(b"%PDF-"):
        return ".pdf"
    if data.startswith(b"PK\x03\x04"):
        return detect_zip_ext(data)
    if looks_like_text(data):
        return detect_text_ext(data)
    guessed = mimetypes.guess_extension("application/octet-stream")
    return guessed if guessed and guessed != ".bin" else ".bin"


def image_dimensions(data: bytes, ext: str) -> tuple[int | None, int | None]:
    try:
        if ext in {".png"} and len(data) >= 24:
            return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
        if ext in {".gif"} and len(data) >= 10:
            return int.from_bytes(data[6:8], "little"), int.from_bytes(data[8:10], "little")
        if ext in {".jpg", ".jpeg"}:
            pos = 2
            while pos + 9 < len(data):
                if data[pos] != 0xFF:
                    pos += 1
                    continue
                marker = data[pos + 1]
                pos += 2
                if marker in {0xD8, 0xD9}:
                    continue
                if pos + 2 > len(data):
                    break
                length = int.from_bytes(data[pos : pos + 2], "big")
                if length < 2 or pos + length > len(data):
                    break
                if 0xC0 <= marker <= 0xCF and marker not in {0xC4, 0xC8, 0xCC} and length >= 7:
                    height = int.from_bytes(data[pos + 3 : pos + 5], "big")
                    width = int.from_bytes(data[pos + 5 : pos + 7], "big")
                    return width, height
                pos += length
        if ext == ".webp" and data.startswith(b"RIFF") and data[8:12] == b"WEBP" and len(data) >= 30:
            chunk = data[12:16]
            chunk_data = 20
            if chunk == b"VP8X" and len(data) >= 30:
                width = int.from_bytes(data[24:27] + b"\x00", "little") + 1
                height = int.from_bytes(data[27:30] + b"\x00", "little") + 1
                return width, height
            if chunk == b"VP8L" and len(data) >= 25:
                bits = int.from_bytes(data[21:25], "little")
                width = (bits & 0x3FFF) + 1
                height = ((bits >> 14) & 0x3FFF) + 1
                return width, height
            if chunk == b"VP8 " and len(data) >= chunk_data + 10:
                frame = data[chunk_data:]
                if frame[3:6] == b"\x9d\x01\x2a":
                    width = int.from_bytes(frame[6:8], "little") & 0x3FFF
                    height = int.from_bytes(frame[8:10], "little") & 0x3FFF
                    return width, height
    except Exception:
        return None, None
    return None, None


def media_probe(path: Path) -> dict[str, object]:
    ffprobe = shutil.which("ffprobe")
    if not ffprobe:
        return {}
    cmd = [
        ffprobe,
        "-v",
        "error",
        "-show_entries",
        "format=duration:stream=codec_type,codec_name,width,height,channels",
        "-of",
        "json",
        str(path),
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)
        raw = json.loads(result.stdout or "{}")
    except Exception:
        return {}
    streams = raw.get("streams") or []
    audio_streams = [s for s in streams if s.get("codec_type") == "audio"]
    video_streams = [s for s in streams if s.get("codec_type") == "video"]
    width = height = None
    if video_streams:
        width = video_streams[0].get("width")
        height = video_streams[0].get("height")
    try:
        duration = float((raw.get("format") or {}).get("duration") or 0)
    except Exception:
        duration = 0.0
    return {
        "has_audio": bool(audio_streams),
        "has_video": bool(video_streams),
        "width": int(width) if width else None,
        "height": int(height) if height else None,
        "duration": duration,
        "audio_codecs": sorted({str(s.get("codec_name")) for s in audio_streams if s.get("codec_name")}),
        "video_codecs": sorted({str(s.get("codec_name")) for s in video_streams if s.get("codec_name")}),
    }


def probe_payload(data: bytes, ext: str) -> dict[str, object]:
    if ext not in VIDEO_EXTS and ext not in AUDIO_EXTS:
        return {}
    try:
        with tempfile.NamedTemporaryFile(suffix=ext) as tmp:
            tmp.write(data)
            tmp.flush()
            return media_probe(Path(tmp.name))
    except Exception:
        return {}


def classify_payload(data: bytes, ext: str, probe: dict[str, object] | None = None) -> Classification:
    ext = ext.lower()
    probe = probe or {}
    selectors: set[str] = set()
    notes: list[str] = []
    kind = ""

    is_voice = ext in {".ogg", ".opus", ".amr"} and (
        b"OpusHead" in data[:512] or ext == ".amr"
    )

    if is_voice:
        selectors.add("voice")
        kind = "voice"
    elif ext in IMAGE_EXTS:
        selectors.add("images")
        kind = "images"
    elif ext in VIDEO_EXTS:
        selectors.add("videos")
        kind = "videos"
    elif ext in AUDIO_EXTS:
        selectors.add("audio")
        kind = "audio"
    elif ext in FILE_EXTS:
        selectors.add("files")
        kind = "files"

    if ext in TEXT_EXTS:
        selectors.add("files")
        kind = "files"

    width, height = image_dimensions(data, ext)
    duration = float(probe.get("duration") or 0)
    video_width = probe.get("width")
    video_height = probe.get("height")
    has_audio = bool(probe.get("has_audio"))

    is_thumbnail = False
    if ext in IMAGE_EXTS and width and height:
        is_thumbnail = width <= 320 and height <= 320 and len(data) <= 120_000
    if is_thumbnail:
        selectors.add("thumbnails")
        notes.append("thumbnail heuristic")
        if kind == "images":
            kind = "thumbnails"

    is_sticker = False
    if ext == ".tgs":
        is_sticker = True
    elif ext == ".webp" and width and height:
        is_sticker = width <= 512 and height <= 512 and len(data) <= 512_000
    elif ext == ".webm" and video_width and video_height:
        is_sticker = (
            int(video_width) <= 512
            and int(video_height) <= 512
            and abs(int(video_width) - int(video_height)) <= 8
            and not has_audio
            and (duration == 0 or duration <= 6)
        )
    if is_sticker:
        selectors.add("stickers")
        notes.append("sticker heuristic" if ext != ".tgs" else "tgs sticker")
        kind = "stickers"

    is_gif = ext == ".gif"
    if "stickers" not in selectors and ext in VIDEO_EXTS and not has_audio and duration and duration <= 60:
        is_gif = True
    if is_gif:
        selectors.add("gifs")
        notes.append("gif/animation heuristic" if ext != ".gif" else "gif")
        if kind in {"videos", "images"}:
            kind = "gifs"

    is_round = False
    if "stickers" not in selectors and ext in VIDEO_EXTS and video_width and video_height:
        is_round = (
            abs(int(video_width) - int(video_height)) <= 8
            and int(video_width) <= 640
            and int(video_height) <= 640
            and (has_audio or duration <= 60)
        )
    if is_round:
        selectors.add("round")
        notes.append("round video heuristic")
        if kind == "videos":
            kind = "round"

    if ext in FILE_EXTS:
        selectors.add("files")
        if not kind:
            kind = "files"

    return Classification(kind=kind, selectors=selectors, note=";".join(dict.fromkeys(notes)))


def compute_data_name_key(dataname: str) -> str:
    filekey = hashlib.md5(dataname.encode("utf-8")).digest()[:8]
    return "".join(f"{b:02X}"[::-1] for b in filekey)


def dataname_for_index(index: int) -> str:
    return "data" if index == 0 else f"data#{index + 1}"


def user_data_name_for_index(index: int) -> str:
    return "user_data" if index == 0 else f"user_data#{index + 1}"


def parse_key_datas_account_indexes(tdata: Path, local_key: bytes) -> tuple[list[int], int | None]:
    try:
        _, body = read_tdf(tdata / "key_datas")
        _salt, pos = read_array(body, 0, "big")
        _key_encrypted, pos = read_array(body, pos, "big")
        info_encrypted, _ = read_array(body, pos, "big")
        if info_encrypted is None:
            return [], None
        info = decrypt_local(info_encrypted, local_key)

        try:
            payload, _ = read_array(info, 0, "little")
        except Exception:
            payload = info
        if not payload or len(payload) < 8:
            return [], None

        count = int.from_bytes(payload[:4], "big", signed=True)
        if count < 0 or count > 32 or len(payload) < 4 + count * 4:
            return [], None
        pos = 4
        indexes = []
        for _ in range(count):
            indexes.append(int.from_bytes(payload[pos : pos + 4], "big", signed=True))
            pos += 4
        main = None
        if len(payload) >= pos + 4:
            main = int.from_bytes(payload[pos : pos + 4], "big", signed=True)
        return indexes, main
    except Exception:
        return [], None


def parse_mtp_authorization(data: bytes) -> dict[str, object]:
    if len(data) < 8:
        return {}
    pos = 0
    legacy_user_id = int.from_bytes(data[pos : pos + 4], "big", signed=True)
    pos += 4
    legacy_main_dc_id = int.from_bytes(data[pos : pos + 4], "big", signed=True)
    pos += 4

    if legacy_user_id == -1 and legacy_main_dc_id == -1 and len(data) >= pos + 12:
        user_id = int.from_bytes(data[pos : pos + 8], "big", signed=False)
        pos += 8
        main_dc_id = int.from_bytes(data[pos : pos + 4], "big", signed=True)
        pos += 4
    else:
        user_id = legacy_user_id
        main_dc_id = legacy_main_dc_id

    return {"user_id": user_id, "dc_id": main_dc_id}


def parse_account_info(tdata: Path, account_dir: str, local_key: bytes) -> dict[str, object]:
    account_file = tdata / f"{account_dir}s"
    if not account_file.exists():
        return {"success": False, "error": f"missing {account_file.name}"}

    try:
        _version, data = read_tdf(account_file)
        encrypted, _ = read_array(data, 0, "big")
        if encrypted is None:
            return {"success": False, "error": "empty encrypted account data"}
        decrypted = decrypt_local(encrypted, local_key)
        try:
            blocks, _ = read_array(decrypted, 0, "little")
        except Exception:
            blocks = decrypted
        if blocks is None:
            return {"success": False, "error": "empty account data"}

        result: dict[str, object] = {"success": True}
        pos = 0
        while pos + 4 <= len(blocks):
            block_id = int.from_bytes(blocks[pos : pos + 4], "big", signed=True)
            pos += 4

            if block_id == 0x4B: 
                if pos + 4 > len(blocks):
                    break
                length = int.from_bytes(blocks[pos : pos + 4], "big", signed=True)
                pos += 4
                if length <= 0 or pos + length > len(blocks):
                    break
                result.update(parse_mtp_authorization(blocks[pos : pos + length]))
                pos += length
            elif block_id == 0x01:
                if pos + 8 > len(blocks):
                    break
                result.setdefault("user_id", int.from_bytes(blocks[pos : pos + 4], "big", signed=True))
                pos += 4
                result.setdefault("dc_id", int.from_bytes(blocks[pos : pos + 4], "big", signed=False))
                pos += 4
            elif block_id == 0x00:
                if pos + 260 > len(blocks):
                    break
                pos += 260
            else:
                if pos + 4 > len(blocks):
                    break
                length = int.from_bytes(blocks[pos : pos + 4], "big", signed=True)
                pos += 4
                if length < 0:
                    break
                pos += min(length, max(0, len(blocks) - pos))
        return result
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def count_cache_files(user_dir: Path, start: datetime | None = None, end_exclusive: datetime | None = None) -> tuple[int, str, int]:
    count = 0
    window_hits = 0
    latest: datetime | None = None
    start_ts = start.timestamp() if start else None
    end_ts = end_exclusive.timestamp() if end_exclusive else None
    for base_name in ("cache", "media_cache"):
        base = user_dir / base_name
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.name in {".DS_Store", "binlog"}:
                continue
            try:
                mtime_ts = path.stat().st_mtime
            except OSError:
                continue
            count += 1
            mtime = datetime.fromtimestamp(mtime_ts).astimezone()
            latest = mtime if latest is None or mtime > latest else latest
            if start_ts is not None and end_ts is not None and start_ts <= mtime_ts < end_ts:
                window_hits += 1
    latest_text = latest.strftime("%Y-%m-%d %H:%M:%S") if latest else "-"
    return count, latest_text, window_hits


def collect_user_data_info(
    tdata: Path,
    local_key: bytes,
    start: datetime | None = None,
    end_exclusive: datetime | None = None,
) -> list[UserDataInfo]:
    user_dirs_by_name = {p.name: p for p in list_user_dirs(tdata)}
    account_indexes, main_index = parse_key_datas_account_indexes(tdata, local_key)
    if not account_indexes:
        account_indexes = []
        for name in sorted(user_dirs_by_name):
            if name == "user_data":
                account_indexes.append(0)
            else:
                match = re.fullmatch(r"user_data#(\d+)", name)
                if match:
                    account_indexes.append(int(match.group(1)) - 1)

    infos: list[UserDataInfo] = []
    seen_user_dirs: set[str] = set()
    for account_index in account_indexes:
        user_data_name = user_data_name_for_index(account_index)
        user_dir = user_dirs_by_name.get(user_data_name)
        if user_dir is None:
            continue
        seen_user_dirs.add(user_data_name)
        dataname = dataname_for_index(account_index)
        account_dir = compute_data_name_key(dataname)
        account_info = parse_account_info(tdata, account_dir, local_key)
        cache_files, latest_cache, window_hits = count_cache_files(user_dir, start, end_exclusive)
        note = ""
        user_id = dc_id = ""
        if account_info.get("success"):
            user_id = str(account_info.get("user_id") or "")
            dc_id = str(account_info.get("dc_id") or "")
            if user_id:
                note = "local name/username unavailable offline"
            else:
                note = "local profile unavailable"
        else:
            note = f"account parse failed: {account_info.get('error', 'unknown error')}"
        infos.append(
            UserDataInfo(
                index=account_index,
                user_dir=user_dir,
                account_dir=account_dir,
                dataname=dataname,
                is_main=(main_index == account_index),
                cache_files=cache_files,
                latest_cache=latest_cache,
                window_hits=window_hits,
                user_id=user_id,
                dc_id=dc_id,
                note=note,
            )
        )

    for name, user_dir in sorted(user_dirs_by_name.items()):
        if name in seen_user_dirs:
            continue
        cache_files, latest_cache, window_hits = count_cache_files(user_dir, start, end_exclusive)
        infos.append(
            UserDataInfo(
                index=-1,
                user_dir=user_dir,
                account_dir="",
                dataname="",
                is_main=False,
                cache_files=cache_files,
                latest_cache=latest_cache,
                window_hits=window_hits,
                note="unmapped user_data directory",
            )
        )
    return infos


def describe_user_info(info: UserDataInfo) -> str:
    main = " main" if info.is_main else ""
    who_parts = []
    if info.display_name:
        who_parts.append(f"name={info.display_name}")
    if info.username:
        who_parts.append(f"username=@{info.username}")
    if not info.display_name and not info.username:
        who_parts.append("profile=offline-unavailable")
    if info.user_id:
        who_parts.append(f"id={info.user_id}")
    if info.dc_id:
        who_parts.append(f"dc={info.dc_id}")
    who = ", ".join(who_parts)
    suffix = f" | {info.note}" if info.note else ""
    return (
        f"{info.user_dir.name}{main} | {who} | cache={info.cache_files} | "
        f"latest={info.latest_cache} | window_hits={info.window_hits}{suffix}"
    )


def choose_user_data_infos(infos: list[UserDataInfo]) -> list[UserDataInfo]:
    if not infos:
        raise ValueError("No user_data directories found in tdata")
    if len(infos) == 1:
        print(f"using: {describe_user_info(infos[0])}")
        return infos

    print("\nFound multiple Telegram local user_data directories:")
    print("  [A] all user_data directories")
    for number, info in enumerate(infos, start=1):
        print(f"  [{number}] {describe_user_info(info)}")

    while True:
        try:
            raw = input("Choose user_data to recover (number, comma-list, or A for all): ").strip()
        except EOFError as exc:
            raise ValueError("Multiple user_data directories found; run interactively and choose one") from exc
        if raw.lower() in {"a", "all", "*"}:
            return infos
        selected: list[UserDataInfo] = []
        ok = True
        for part in re.split(r"[,\\s]+", raw):
            if not part:
                continue
            if not part.isdigit():
                ok = False
                break
            number = int(part)
            if number < 1 or number > len(infos):
                ok = False
                break
            selected.append(infos[number - 1])
        if ok and selected:
            return selected
        print("Invalid choice. Example: 1 or 1,3 or A")


def requested_selectors(args: argparse.Namespace) -> set[str]:
    selected: set[str] = set()
    if args.image:
        selected.add("images")
    if args.audio:
        selected.add("audio")
    if args.video:
        selected.add("videos")
    if args.file:
        selected.add("files")
    if args.document:
        selected.add("files")
    if args.voice:
        selected.add("voice")
    if args.sticker:
        selected.add("stickers")
    if args.gif:
        selected.add("gifs")
    if args.round:
        selected.add("round")
    if args.thumbnail:
        selected.add("thumbnails")
    if args.all_types or not selected:
        return set(SELECTOR_NAMES)
    return selected


def safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.#-]+", "_", text)


def candidate_tdata_paths() -> list[Path]:
    home = Path.home()
    candidates: list[Path] = []

    if sys.platform == "darwin":
        candidates.extend(
            [
                home / "Library/Application Support/Telegram Desktop/tdata",
                home
                / "Library/Containers/ru.keepcoder.Telegram/Data/Library/Application Support/Telegram Desktop/tdata",
            ]
        )
    elif os.name == "nt":
        appdata = os.environ.get("APPDATA")
        localappdata = os.environ.get("LOCALAPPDATA")
        if appdata:
            candidates.append(Path(appdata) / "Telegram Desktop/tdata")
        if localappdata:
            candidates.append(Path(localappdata) / "Telegram Desktop/tdata")
            candidates.append(
                Path(localappdata)
                / "Packages/TelegramMessengerLLP.TelegramDesktop_t4vj0pshhgkwm/LocalCache/Roaming/Telegram Desktop/tdata"
            )
    else:
        xdg_data = Path(os.environ.get("XDG_DATA_HOME", home / ".local/share"))
        candidates.extend(
            [
                xdg_data / "TelegramDesktop/tdata",
                home / ".local/share/TelegramDesktop/tdata",
                home / "snap/telegram-desktop/current/.local/share/TelegramDesktop/tdata",
                home / ".var/app/org.telegram.desktop/data/TelegramDesktop/tdata",
            ]
        )

    env_tdata = os.environ.get("TELEGRAM_TDATA")
    if env_tdata:
        candidates.insert(0, Path(env_tdata))

    found: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        candidate = candidate.expanduser()
        if (candidate / "key_datas").exists():
            resolved = candidate.resolve()
            if resolved not in seen:
                found.append(resolved)
                seen.add(resolved)
    return found


def default_tdata_path() -> Path:
    found = candidate_tdata_paths()
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        print("Found multiple Telegram tdata directories:")
        for index, path in enumerate(found, start=1):
            print(f"  [{index}] {path}")
        while True:
            raw = input("Choose tdata directory number: ").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(found):
                return found[int(raw) - 1]
            print("Invalid choice.")
    raise FileNotFoundError(
        "Could not find Telegram Desktop tdata automatically. Use --tdata /path/to/tdata"
    )


def list_user_dirs(tdata: Path) -> list[Path]:
    dirs = [p for p in tdata.iterdir() if p.is_dir() and p.name.startswith("user_data")]
    return sorted(dirs, key=lambda p: (p.name != "user_data", p.name))


def parse_time_range(raw: str, date_text: str | None = None) -> tuple[datetime, datetime, str]:
    raw = raw.strip()
    pattern = re.compile(
        r"^\s*"
        r"(?:(?P<start_date>\d{4}-\d{1,2}-\d{1,2})\s+)?"
        r"(?P<start>\d{1,2}:\d{2}(?::\d{2})?)"
        r"\s*(?:-|~|到|至)\s*"
        r"(?:(?P<end_date>\d{4}-\d{1,2}-\d{1,2})\s+)?"
        r"(?P<end>\d{1,2}:\d{2}(?::\d{2})?)"
        r"\s*$"
    )
    match = pattern.match(raw)
    if not match:
        raise ValueError("Time range must look like 11:20-11:30 or 2026-06-20 11:20-11:30")

    start_date = match.group("start_date") or date_text or datetime.now().strftime("%Y-%m-%d")
    end_date = match.group("end_date") or start_date
    start_time = match.group("start")
    end_time = match.group("end")

    def parse_one(day: str, clock: str) -> datetime:
        fmt = "%Y-%m-%d %H:%M:%S" if clock.count(":") == 2 else "%Y-%m-%d %H:%M"
        return datetime.strptime(f"{day} {clock}", fmt).astimezone()

    start = parse_one(start_date, start_time)
    end = parse_one(end_date, end_time)
    if end < start:
        end += timedelta(days=1)

    end_exclusive = end + (timedelta(seconds=1) if end_time.count(":") == 2 else timedelta(minutes=1))
    label = f"{start.strftime('%Y%m%d_%H%M%S')}-{(end_exclusive - timedelta(seconds=1)).strftime('%Y%m%d_%H%M%S')}"
    return start, end_exclusive, label


def iter_cache_files(user_dirs: Iterable[Path], start: datetime, end_exclusive: datetime) -> Iterable[tuple[Path, Path, datetime]]:
    start_ts = start.timestamp()
    end_ts = end_exclusive.timestamp()
    for user_dir in user_dirs:
        for base_name in ("cache", "media_cache"):
            base = user_dir / base_name
            if not base.exists():
                continue
            for path in base.rglob("*"):
                if not path.is_file() or path.name in {".DS_Store", "binlog"}:
                    continue
                try:
                    mtime_ts = path.stat().st_mtime
                except OSError:
                    continue
                if start_ts <= mtime_ts < end_ts:
                    yield user_dir, path, datetime.fromtimestamp(mtime_ts).astimezone()


def link_or_copy(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        if dest.exists():
            dest.unlink()
        os.link(src, dest)
    except OSError:
        shutil.copy2(src, dest)


def write_manifest(out_dir: Path, rows: list[RecoveredFile]) -> None:
    fields = list(asdict(rows[0]).keys()) if rows else [
        "index",
        "status",
        "user_dir",
        "cache_mtime",
        "source_cache",
        "output_file",
        "category",
        "matches",
        "extension",
        "bytes",
        "note",
    ]

    with (out_dir / "manifest.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))

    (out_dir / "manifest.json").write_text(
        json.dumps([asdict(row) for row in rows], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def make_contact_sheet(out_dir: Path, image_files: list[Path]) -> str:
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        return "ffmpeg not found; skipped contact_sheet.jpg"
    if not image_files:
        return "no images; skipped contact_sheet.jpg"

    thumbs = out_dir / "_thumbs"
    thumbs.mkdir(exist_ok=True)
    thumb_files: list[Path] = []
    for index, image in enumerate(image_files, start=1):
        thumb = thumbs / f"{index:04d}.jpg"
        cmd = [
            ffmpeg,
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-i",
            str(image),
            "-vf",
            "scale=220:220:force_original_aspect_ratio=decrease,"
            "pad=220:220:(ow-iw)/2:(oh-ih)/2:white",
            "-frames:v",
            "1",
            str(thumb),
        ]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            thumb_files.append(thumb)
        except subprocess.CalledProcessError:
            continue

    if not thumb_files:
        return "thumbnail generation failed; skipped contact_sheet.jpg"

    cols = min(7, max(1, math.ceil(math.sqrt(len(thumb_files)))))
    rows = math.ceil(len(thumb_files) / cols)
    contact_sheet = out_dir / "contact_sheet.jpg"
    pattern = str(thumbs / "*.jpg")
    cmd = [
        ffmpeg,
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-pattern_type",
        "glob",
        "-i",
        pattern,
        "-vf",
        f"tile={cols}x{rows}",
        "-frames:v",
        "1",
        str(contact_sheet),
    ]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        shutil.rmtree(thumbs, ignore_errors=True)
        return f"wrote {contact_sheet.name}"
    except subprocess.CalledProcessError:
        return "contact sheet generation failed"


def recover(args: argparse.Namespace) -> int:
    tdata = Path(args.tdata).expanduser() if args.tdata else default_tdata_path()
    tdata = tdata.resolve()
    if not (tdata / "key_datas").exists():
        raise FileNotFoundError(f"key_datas not found in {tdata}")

    time_text = args.time_text or " ".join(args.time_range)
    start, end_exclusive, label = parse_time_range(time_text, args.date)
    wanted = requested_selectors(args)
    local_key = load_local_key(tdata, args.passcode or "")
    user_infos = collect_user_data_info(tdata, local_key, start, end_exclusive)
    selected_infos = choose_user_data_infos(user_infos)
    user_dirs = [info.user_dir for info in selected_infos]

    script_dir = Path(__file__).resolve().parent
    type_label = "all" if wanted == set(SELECTOR_NAMES) else "_".join(sorted(wanted))
    out_dir = script_dir / "output" / f"telegram_recovered_{type_label}_{label}"
    all_dir = out_dir / "all"
    fail_dir = out_dir / "failed"
    out_dir.mkdir(parents=True, exist_ok=True)
    all_dir.mkdir(exist_ok=True)

    print(f"tdata: {tdata}")
    print(f"time:  {start.strftime('%Y-%m-%d %H:%M:%S')} <= mtime < {end_exclusive.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"types: {', '.join(sorted(wanted))}")
    print(f"users: {', '.join(p.name for p in user_dirs)}")
    print(f"out:   {out_dir}")

    candidates = list(iter_cache_files(user_dirs, start, end_exclusive))
    print(f"candidate cache files: {len(candidates)}")

    rows: list[RecoveredFile] = []
    image_outputs: list[Path] = []
    ok = failed = partial = streaming = skipped_by_type = 0

    for index, (user_dir, src, mtime) in enumerate(candidates, start=1):
        rel_user = user_dir.name
        rel_cache = src.relative_to(tdata)
        try:
            payload = decrypt_tdef(src, local_key)
            payload, was_streaming = parse_streaming_cache(payload)
            note_parts: list[str] = []
            if was_streaming:
                streaming += 1
                note_parts.append("streaming")
            if payload.startswith(b"partial:"):
                payload = payload[8:]
                partial += 1
                note_parts.append("partial")

            ext = detect_ext(payload)
            probe = probe_payload(payload, ext)
            classification = classify_payload(payload, ext, probe)
            if not (classification.selectors & wanted):
                skipped_by_type += 1
                continue
            category = classification.kind

            base_name = (
                f"{mtime.strftime('%Y%m%d_%H%M%S')}_"
                f"{safe_name(rel_user)}_{safe_name(src.parent.name)}_{safe_name(src.name)}{ext}"
            )
            all_path = all_dir / base_name
            all_path.write_bytes(payload)

            category_path = out_dir / category / base_name
            link_or_copy(all_path, category_path)
            if "images" in classification.selectors and ext in IMAGE_EXTS:
                image_outputs.append(category_path)
            if classification.note:
                note_parts.append(classification.note)
            if probe:
                media_bits = []
                if probe.get("duration"):
                    media_bits.append(f"duration={float(probe['duration']):.3f}s")
                if probe.get("width") and probe.get("height"):
                    media_bits.append(f"size={probe['width']}x{probe['height']}")
                if probe.get("has_audio") is not None:
                    media_bits.append(f"has_audio={probe.get('has_audio')}")
                if media_bits:
                    note_parts.append(",".join(media_bits))

            rows.append(
                RecoveredFile(
                    index=index,
                    status="ok",
                    user_dir=rel_user,
                    cache_mtime=mtime.strftime("%Y-%m-%d %H:%M:%S"),
                    source_cache=str(rel_cache),
                    output_file=str(category_path.relative_to(out_dir)),
                    category=category,
                    matches=",".join(sorted(classification.selectors)),
                    extension=ext,
                    bytes=len(payload),
                    note=";".join(note_parts),
                )
            )
            ok += 1
        except Exception as exc:
            failed += 1
            fail_dir.mkdir(exist_ok=True)
            rows.append(
                RecoveredFile(
                    index=index,
                    status="failed",
                    user_dir=rel_user,
                    cache_mtime=mtime.strftime("%Y-%m-%d %H:%M:%S"),
                    source_cache=str(rel_cache),
                    output_file="",
                    category="",
                    matches="",
                    extension="",
                    bytes=0,
                    note=str(exc),
                )
            )

    write_manifest(out_dir, rows)
    contact_note = make_contact_sheet(out_dir, image_outputs)

    match_counts = {
        name: sum(name in set(filter(None, row.matches.split(","))) for row in rows)
        for name in SELECTOR_NAMES
    }
    kind_counts = {name: sum(1 for row in rows if row.category == name) for name in OUTPUT_KINDS}

    summary = {
        "tdata": str(tdata),
        "time_start": start.strftime("%Y-%m-%d %H:%M:%S"),
        "time_end_exclusive": end_exclusive.strftime("%Y-%m-%d %H:%M:%S"),
        "users": [p.name for p in user_dirs],
        "selected_user_data": [asdict(info) | {"user_dir": str(info.user_dir)} for info in selected_infos],
        "requested_types": sorted(wanted),
        "candidates": len(candidates),
        "ok": ok,
        "failed": failed,
        "skipped_by_type": skipped_by_type,
        "match_counts": match_counts,
        "output_kind_counts": kind_counts,
        "images": match_counts["images"],
        "videos": match_counts["videos"],
        "audio": match_counts["audio"],
        "files": match_counts["files"],
        "voice": match_counts["voice"],
        "stickers": match_counts["stickers"],
        "gifs": match_counts["gifs"],
        "round": match_counts["round"],
        "thumbnails": match_counts["thumbnails"],
        "streaming": streaming,
        "partial": partial,
        "contact_sheet": contact_note,
    }

    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (out_dir / "README.txt").write_text(
        "\n".join(
            [
                "Telegram recovered cache files",
                "",
                f"tdata: {tdata}",
                f"time: {summary['time_start']} <= mtime < {summary['time_end_exclusive']}",
                f"types: {', '.join(summary['requested_types'])}",
                f"users: {', '.join(summary['users'])}",
                f"candidates: {summary['candidates']}",
                f"ok: {ok}",
                f"failed: {failed}",
                f"skipped_by_type: {skipped_by_type}",
                f"images: {summary['images']}",
                f"videos: {summary['videos']}",
                f"audio: {summary['audio']}",
                f"files: {summary['files']}",
                f"voice: {summary['voice']}",
                f"stickers: {summary['stickers']}",
                f"gifs: {summary['gifs']}",
                f"round: {summary['round']}",
                f"thumbnails: {summary['thumbnails']}",
                f"contact_sheet: {contact_note}",
                "",
                "Open manifest.csv for the full source-cache to output-file mapping.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    print("\nDone")
    for key, value in summary.items():
        if key not in {"tdata", "users", "selected_user_data"}:
            print(f"{key}: {value}")
    print(f"manifest: {out_dir / 'manifest.csv'}")
    return 0 if failed == 0 else 1


def parse_message_ids(raw_values: list[str] | None) -> list[int]:
    if not raw_values:
        return []
    ids: list[int] = []
    for raw in raw_values:
        for part in re.split(r"[,\s]+", raw.strip()):
            if not part:
                continue
            if not part.isdigit() or int(part) <= 0:
                raise ValueError(f"invalid message id: {part}")
            ids.append(int(part))
    return sorted(set(ids))


def recover_chat_text(args: argparse.Namespace) -> int:
    message_ids = parse_message_ids(args.message_id)
    if not message_ids:
        raise ValueError("--text requires --message-id")

    tdata = Path(args.tdata).expanduser() if args.tdata else default_tdata_path()
    tdata = tdata.resolve()
    if not (tdata / "key_datas").exists():
        raise FileNotFoundError(f"key_datas not found in {tdata}")

    start = end_exclusive = None
    time_label = "no_time"
    time_text = args.time_text or " ".join(args.time_range)
    if time_text.strip():
        start, end_exclusive, time_label = parse_time_range(time_text, args.date)

    local_key = load_local_key(tdata, args.passcode or "")
    user_infos = collect_user_data_info(tdata, local_key, start, end_exclusive)
    selected_infos = choose_user_data_infos(user_infos)

    script_dir = Path(__file__).resolve().parent
    ids_label = "_".join(str(mid) for mid in message_ids[:8])
    if len(message_ids) > 8:
        ids_label += f"_plus{len(message_ids) - 8}"
    out_dir = script_dir / "output" / f"telegram_recovered_text_message_{ids_label}_{time_label}"
    chat_info_dir = out_dir / "chat_info"
    chat_info_dir.mkdir(parents=True, exist_ok=True)

    query = {
        "mode": "targeted_chat_text",
        "status": "target_record_created",
        "privacy": "No chat message bodies are printed to terminal or chat. This file stores only the targeted recovery criteria.",
        "tdata": str(tdata),
        "message_ids": message_ids,
        "peer_id": args.peer_id or "",
        "time_start": start.strftime("%Y-%m-%d %H:%M:%S") if start else "",
        "time_end_exclusive": end_exclusive.strftime("%Y-%m-%d %H:%M:%S") if end_exclusive else "",
        "selected_user_data": [asdict(info) | {"user_dir": str(info.user_dir)} for info in selected_infos],
        "note": (
            "Telegram text messages are not media cache files. This script prevents broad text dumps; "
            "message text extraction requires a targeted local-message parser or an explicit API-backed step."
        ),
    }

    target_file = chat_info_dir / f"message_{ids_label}.json"
    target_file.write_text(json.dumps(query, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "README.txt").write_text(
        "\n".join(
            [
                "Telegram targeted chat text recovery",
                "",
                f"tdata: {tdata}",
                f"message_ids: {', '.join(map(str, message_ids))}",
                f"peer_id: {args.peer_id or '(not specified)'}",
                f"time: {query['time_start'] or '(not specified)'} <= mtime < {query['time_end_exclusive'] or '(not specified)'}",
                "",
                "No chat body was printed. Target metadata is stored under chat_info/.",
                "Full text extraction needs a targeted message parser/API step using the message id.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"tdata: {tdata}")
    print(f"type:  text")
    print(f"message_ids: {', '.join(map(str, message_ids))}")
    if args.peer_id:
        print(f"peer_id: {args.peer_id}")
    print(f"out:   {out_dir}")
    print(f"chat_info: {target_file}")
    return 0


def print_users(tdata_arg: str | None, passcode: str = "") -> int:
    tdata = Path(tdata_arg).expanduser() if tdata_arg else default_tdata_path()
    tdata = tdata.resolve()
    local_key = load_local_key(tdata, passcode or "")
    infos = collect_user_data_info(tdata, local_key)
    print(f"tdata: {tdata}")
    for index, info in enumerate(infos, start=1):
        print(f"[{index}] {describe_user_info(info)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recover Telegram Desktop cached files by local modified time."
    )
    parser.add_argument(
        "time_range",
        nargs="*",
        help="Optional legacy time range, for example: 11:20-11:30 or '2026-06-20 11:20-11:30'",
    )
    parser.add_argument(
        "-time",
        "--time",
        dest="time_text",
        help="Time range to recover, for example: 11:20-11:30 or '2026-06-20 11:20-11:30'",
    )
    parser.add_argument("--date", help="Date to use when time_range has no date, YYYY-MM-DD")
    parser.add_argument("--tdata", help="Telegram Desktop tdata path. Default: auto-detect")
    parser.add_argument("--passcode", default="", help="Telegram local passcode if tdata is passcode-protected")
    parser.add_argument("--list-users", action="store_true", help="List available user_data directories and exit")
    parser.add_argument("--image", action="store_true", help="Export only images")
    parser.add_argument("--audio", action="store_true", help="Export only regular audio files, excluding Telegram voice messages")
    parser.add_argument("--video", action="store_true", help="Export only videos")
    parser.add_argument("--file", action="store_true", help="Export ordinary file attachments: documents, archives, apps, text, etc.")
    parser.add_argument("--document", action="store_true", help="Alias for --file")
    parser.add_argument("--voice", action="store_true", help="Export Telegram voice messages, usually OGG/Opus")
    parser.add_argument("--sticker", action="store_true", help="Export stickers: TGS, small WebP, and sticker-like WebM")
    parser.add_argument("--gif", action="store_true", help="Export GIF/animation messages, including silent short videos")
    parser.add_argument("--round", action="store_true", help="Export round-video-like messages")
    parser.add_argument("--thumbnail", action="store_true", help="Export small thumbnail/cache preview images")
    parser.add_argument("--text", action="store_true", help="Recover targeted chat text info; requires --message-id and writes chat_info only")
    parser.add_argument(
        "--message-id",
        action="append",
        help="Required with --text. Message id to target; repeat or comma-separate for multiple ids.",
    )
    parser.add_argument(
        "--peer-id",
        "--chat-id",
        dest="peer_id",
        help="Optional peer/chat id hint for targeted text recovery.",
    )
    parser.add_argument("--all", dest="all_types", action="store_true", help="Export all detected cache media/file types, excluding chat text")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.list_users:
            return print_users(args.tdata, args.passcode)
        media_flags = [
            args.image,
            args.audio,
            args.video,
            args.file,
            args.document,
            args.voice,
            args.sticker,
            args.gif,
            args.round,
            args.thumbnail,
            args.all_types,
        ]
        if args.text:
            if any(media_flags):
                parser.error("--text is targeted chat mode and cannot be combined with media/file type flags")
            if not args.message_id:
                parser.error("--text requires --message-id")
            return recover_chat_text(args)
        if not args.time_text and not args.time_range:
            parser.error("-time/--time is required unless --list-users or --text --message-id is used")
        if not any(
            media_flags
        ):
            parser.error(
                "choose a message/file type: --image, --audio, --video, --file, --voice, "
                "--sticker, --gif, --round, --thumbnail, --all, or --text --message-id"
            )
        return recover(args)
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())