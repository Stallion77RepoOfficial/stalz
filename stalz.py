#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, io, math, tarfile, struct, zlib, lzma, threading, time, ctypes, platform, tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional
from PyQt6 import QtWidgets, QtCore, QtGui

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# =========================
# ====== STALZ CORE  ======
# =========================

MAGIC = b"STALZ\x00"
VERSION = 7
ALGO_LZMA_XZ = 1
HEADER_FMT = "<6sBBBBHQII"

FLAG_ENCRYPTED = 1 << 0
FLAG_PROTOCOL_PLUS = 1 << 1

COLORS = {
    'background': '#1e1e1e',
    'surface': '#252525',
    'surface_light': '#2d2d2d',
    'border': '#404040',
    'border_focus': '#0078d4',
    'text': '#ffffff',
    'text_secondary': '#cccccc',
    'text_muted': '#999999',
    'accent': '#0078d4',
    'accent_hover': '#106ebe',
    'success': '#16c60c',
    'warning': '#ffb900',
    'error': '#d13438'
}

# =========================
# ======== Utils ==========
# =========================

def _crc32(b: bytes) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF

def _human(n: int) -> str:
    units = ["B","KB","MB","GB","TB","PB"]
    val = float(n)
    for u in units:
        if val < 1024.0: return f"{val:.2f} {u}"
        val /= 1024.0
    return f"{val:.2f} EB"

def _total_ram_bytes() -> int:
    try:
        if hasattr(os, "sysconf"):
            pg = os.sysconf_names
            if "SC_PAGE_SIZE" in pg and "SC_PHYS_PAGES" in pg:
                return int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES"))
    except Exception:
        pass
    try:
        if platform.system() == "Windows":
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            return int(stat.ullTotalPhys)
    except Exception:
        pass
    return 8*(1<<30)

# =========================
# === Encryption (AESGCM)
# =========================

def _derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode('utf-8'))

def _encrypt_chunks_aesgcm(chunks: List[bytes], password: str) -> Tuple[bytes, List[bytes]]:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    out: List[bytes] = []
    for ch in chunks:
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, ch, None)
        out.append(nonce + ct)
    return salt, out

def _decrypt_chunks_aesgcm(chunks: List[bytes], password: str, salt: bytes) -> List[bytes]:
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    out: List[bytes] = []
    for token in chunks:
        if len(token) < 12 + 16:
            raise ValueError("Encrypted chunk too short.")
        nonce, ct = token[:12], token[12:]
        out.append(aes.decrypt(nonce, ct, None))
    return out

# =========================
# ===== Compression =======
# =========================

def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0]*256
    for x in data: freq[x]+=1
    n = len(data); ent=0.0
    invn = 1.0 / n
    for c in freq:
        if c:
            p=c*invn
            ent -= p*math.log2(p)
    return ent

_TEXT_EXT = {
    ".txt",".md",".rst",".csv",".tsv",".json",".xml",".yaml",".yml",".html",".htm",".css",".js",".ts",
    ".ini",".cfg",".toml",".log",".srt",".vtt"
}
_CODE_EXT = {".c",".h",".hpp",".cpp",".cc",".java",".kt",".go",".rs",".py",".rb",".php",".sql",".sh",".bat",".ps1",".pl",".lua",".cs",".m",".mm",".swift",".scala"}
_ARCH_EXT = {".zip",".rar",".7z",".xz",".bz2",".gz",".lz",".lz4",".zst",".tar",".tgz",".tbz",".txz"}
_IMG_EXT = {".png",".jpg",".jpeg",".gif",".bmp",".tiff",".webp",".svg",".heic"}
_AUD_EXT = {".mp3",".aac",".ogg",".flac",".wav",".m4a"}
_VID_EXT = {".mp4",".mkv",".mov",".avi",".webm",".m4v"}
_DOC_EXT = {".pdf",".doc",".docx",".ppt",".pptx",".xls",".xlsx",".odt",".odp",".ods"}

def _cat_rank(path_name: str) -> int:
    ext = Path(path_name).suffix.lower()
    if ext in _TEXT_EXT: return 0
    if ext in _CODE_EXT: return 1
    if ext in {".json",".xml"}: return 2
    if ext in _DOC_EXT: return 3
    if ext in _IMG_EXT: return 5
    if ext in _AUD_EXT: return 6
    if ext in _VID_EXT: return 7
    if ext in _ARCH_EXT: return 8
    return 4

def _filters_for_profile(profile: str, plus: bool, delta_dist: int, bcj: str = "auto",
                         dict_mb: Optional[int] = None, tune: str = "default"):
    prof = (profile or "normal").lower()
    if prof == "low":
        preset = 4; dict_size = 4*(1<<20)
    elif prof == "high":
        preset = 9; dict_size = 32*(1<<20)
    elif prof == "extreme":
        preset = 9; dict_size = 64*(1<<20)
    else:
        preset = 6; dict_size = 8*(1<<20)

    if plus:
        preset |= lzma.PRESET_EXTREME
        if dict_mb is not None:
            dict_size = max(dict_size, int(dict_mb) * (1<<20))
        elif prof in ("high", "extreme"):
            dict_size = max(dict_size, 64*(1<<20))

    delta_dist = max(1, min(int(delta_dist), 256 if plus else 64))

    _bcj_candidates = [
        ("x86", "FILTER_X86"),
        ("arm", "FILTER_ARM"),
        ("armthumb", "FILTER_ARMTHUMB"),
        ("arm64", "FILTER_ARM64"),
        ("powerpc", "FILTER_POWERPC"),
        ("ia64", "FILTER_IA64"),
        ("sparc", "FILTER_SPARC"),
    ]
    bcj_map = {}
    for _name, _const in _bcj_candidates:
        _val = getattr(lzma, _const, None)
        if _val is not None:
            bcj_map[_name] = _val

    filters = []
    if plus and bcj:
        sel = bcj.lower()
        if sel == "auto":
            if "x86" in bcj_map:
                filters.append({"id": bcj_map["x86"]})
        elif sel in bcj_map:
            filters.append({"id": bcj_map[sel]})

    lzma_opts = {"preset": preset, "dict_size": dict_size}
    t = (tune or "default").lower()
    if t == "aggressive":
        lzma_opts.update({"mode": lzma.MODE_NORMAL, "mf": "bt4", "nice_len": 273, "depth": 0, "lc": 3, "lp": 0, "pb": 2})
    elif t == "fast":
        lzma_opts.update({"mode": lzma.MODE_FAST, "mf": "hc4", "nice_len": 32, "depth": 0, "lc": 3, "lp": 0, "pb": 2})

    filters.append({"id": lzma.FILTER_DELTA, "dist": delta_dist})
    filters.append({"id": lzma.FILTER_LZMA2, **lzma_opts})
    return filters

def _compress_lzma(data: bytes, filters):
    return lzma.compress(data, format=lzma.FORMAT_XZ, filters=filters)

def _decompress_lzma(data: bytes):
    return lzma.decompress(data, format=lzma.FORMAT_XZ)

def _split_chunks(buf: bytes, size: int):
    if size <= 0:
        return [buf]
    return [buf[i:i+size] for i in range(0, len(buf), size)]

class Progress:
    def __init__(self, total=100, cb=None, min_emit_ms=50):
        self.total = max(1,total)
        self.done = 0
        self.cb = cb
        self.lock = threading.Lock()
        self._last_emit_t = time.monotonic()
        self._last_pct = -1
        self._min_emit = max(0, min_emit_ms) / 1000.0
        self._start_t = time.monotonic()

    def reset(self, total):
        with self.lock:
            self.total = max(1,total); self.done=0
            self._last_emit_t = time.monotonic()
            self._last_pct = -1
            self._start_t = self._last_emit_t
        self.emit(force=True)

    def step(self, inc=1):
        with self.lock:
            self.done += inc
            if self.done > self.total:
                self.done = self.total
        self.emit()

    def emit(self, force=False):
        if not self.cb:
            return
        now = time.monotonic()
        with self.lock:
            pct = int(self.done*100/self.total)
            if force or pct != self._last_pct and (now - self._last_emit_t) >= self._min_emit:
                self._last_emit_t = now
                self._last_pct = pct
                try: self.cb(max(0,min(100,pct)))
                except: pass

_TEXT_EXT_FULL = _TEXT_EXT | _CODE_EXT

def _looks_text(sample: bytes) -> bool:
    if not sample: return False
    if b"\x00" in sample: return False
    printable = sum(32 <= b <= 126 or b in (9,10,13) for b in sample)
    return printable / max(1,len(sample)) > 0.85

def build_dictseed(paths: List[str], limit_mb: int = 8, per_file_kb: int = 64) -> bytes:
    limit = limit_mb * (1<<20)
    per_file = per_file_kb * 1024
    acc = bytearray()
    for p in paths:
        pth = Path(p)
        if pth.is_dir():
            for child in pth.rglob("*"):
                if child.is_file() and child.suffix.lower() in _TEXT_EXT_FULL:
                    try:
                        with open(child, "rb") as f:
                            chunk = f.read(per_file)
                        if _looks_text(chunk): acc.extend(chunk)
                    except Exception: pass
                    if len(acc) >= limit: return bytes(acc[:limit])
        elif pth.is_file() and pth.suffix.lower() in _TEXT_EXT_FULL:
            try:
                with open(pth, "rb") as f:
                    chunk = f.read(per_file)
                if _looks_text(chunk): acc.extend(chunk)
            except Exception: pass
            if len(acc) >= limit: return bytes(acc[:limit])
    return bytes(acc[:limit])

def make_solid_tar_from_many(paths: List[str], order="none",
                             stegpad_bytes: int = 0,
                             dictseed_bytes: Optional[bytes] = None) -> bytes:
    entries = []
    for p in paths:
        p = Path(p).resolve()
        if p.is_file():
            entries.append((p, p.name, p.stat().st_size))
        else:
            for child in p.rglob("*"):
                if child.is_file():
                    rel = str(Path(p.name, child.relative_to(p)))
                    entries.append((child, rel, child.stat().st_size))

    if order == "by-size":
        entries.sort(key=lambda t: t[2], reverse=True)
    elif order == "by-name":
        entries.sort(key=lambda t: t[1].lower())
    elif order == "by-ext":
        entries.sort(key=lambda t: (Path(t[1]).suffix.lower(), t[1].lower(), -t[2]))
    elif order == "smart":
        entries.sort(key=lambda t: (_cat_rank(t[1]), Path(t[1]).suffix.lower(), t[1].lower(), -t[2]))

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tarobj:
        if dictseed_bytes:
            info = tarfile.TarInfo(name=".dictseed")
            info.size = len(dictseed_bytes)
            info.mtime = int(time.time())
            tarobj.addfile(info, io.BytesIO(dictseed_bytes))
        for src, arcname, _ in entries:
            tarobj.add(str(src), arcname=arcname, recursive=False)
        if stegpad_bytes > 0:
            z = io.BytesIO(b"\x00" * int(stegpad_bytes))
            info = tarfile.TarInfo(name=".stegpad.bin")
            info.size = int(stegpad_bytes)
            info.mtime = int(time.time())
            tarobj.addfile(info, z)
    return buf.getvalue()

def compress_stream(data: bytes, chunk_size: int, threads: int, repeat: int,
                    entropy_thr=7.8, filters=None, progress: Progress=None,
                    cancelled_flag: Optional[List[bool]]=None,
                    force_all: bool=False):
    eff_thr = min(float(entropy_thr), 8.0)
    if filters is None:
        filters = _filters_for_profile("normal", True, 1)

    chunks = _split_chunks(data, chunk_size)
    total_phase_ticks = len(chunks) * (1 + max(1,repeat))
    if progress: progress.reset(total_phase_ticks)

    if not force_all:
        entropies = [0.0]*len(chunks)
        def _ent_job(i, ch): return (i, shannon_entropy(ch))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs=[ex.submit(_ent_job, i, ch) for i,ch in enumerate(chunks)]
            for fu in as_completed(futs):
                i,e = fu.result()
                entropies[i] = e
                if progress: progress.step(1)
                if cancelled_flag and cancelled_flag[0]: return None, None
        plan=[1 if e<eff_thr else 0 for e in entropies]
    else:
        if progress:
            progress.done += len(chunks)
            progress.emit(force=True)
        plan=[1]*len(chunks)

    cur=chunks
    for _ in range(max(1,repeat)):
        idx=[i for i,f in enumerate(plan) if f==1]
        to_comp=[cur[i] for i in idx]
        comped=[None]*len(idx)
        if to_comp:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futs={ex.submit(_compress_lzma, blk, filters): k for k,blk in enumerate(to_comp)}
                for fu in as_completed(futs):
                    k = futs[fu]; comped[k] = fu.result()
                    if progress: progress.step(1)
                    if cancelled_flag and cancelled_flag[0]: return None, None
        it=iter(comped); next_cur=[]
        idx_set = set(idx)
        for i,blk in enumerate(cur):
            if i in idx_set: next_cur.append(next(it))
            else:
                next_cur.append(blk)
                if progress: progress.step(1)
        cur=next_cur

    meta=[(1 if plan[i]==1 else 0, len(cur[i])) for i in range(len(cur))]
    return cur, meta

def decompress_stream(chunks, meta, threads, repeat, progress: Progress=None,
                      cancelled_flag: Optional[List[bool]]=None):
    if progress: progress.reset(len(meta)*max(1,repeat))
    cur=chunks
    for _ in range(max(1,repeat)):
        idx=[i for i,(fl,_) in enumerate(meta) if fl==1]
        to_de=[cur[i] for i in idx]
        out=[None]*len(idx)
        if to_de:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futs={ex.submit(_decompress_lzma, d): k for k,d in enumerate(to_de)}
                for fu in as_completed(futs):
                    k = futs[fu]; out[k] = fu.result()
                    if progress: progress.step(1)
                    if cancelled_flag and cancelled_flag[0]: return None
        it=iter(out); next_cur=[]
        idx_set = set(idx)
        for i,blk in enumerate(cur):
            if i in idx_set: next_cur.append(next(it))
            else: next_cur.append(blk)
    return b"".join(cur)

def _write_header(fh, name, orig_size, crc32, repeat, algo, chunk_count,
                  encrypted=False, protocol_plus=True, salt: Optional[bytes]=None):
    name_b = name.encode("utf-8")
    flags = 0
    if encrypted: flags |= FLAG_ENCRYPTED
    if protocol_plus: flags |= FLAG_PROTOCOL_PLUS
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, flags, algo, repeat, len(name_b), orig_size, crc32, 0) + name_b
    fh.write(header)
    fh.write(struct.pack("<I", chunk_count))
    if encrypted:
        if not salt or len(salt) != 16:
            raise ValueError("Invalid AES-GCM salt; expected 16 bytes.")
        fh.write(salt)

def _read_header(fh):
    fixed_len = struct.calcsize(HEADER_FMT)
    data = fh.read(fixed_len)
    if len(data)!=fixed_len: raise ValueError("Invalid header.")
    magic, ver, flags, algo, repeat, name_len, orig_size, crc32, _ = struct.unpack(HEADER_FMT, data)
    if magic!=MAGIC: raise ValueError("Not a STALZ archive.")
    if ver<6 or ver>VERSION: raise ValueError(f"Unsupported version: {ver}")
    encrypted = bool(flags & FLAG_ENCRYPTED)
    name_b = fh.read(name_len)
    if len(name_b)!=name_len: raise ValueError("Corrupt header name.")
    (chunk_count,) = struct.unpack("<I", fh.read(4))
    salt = None
    if encrypted:
        salt = fh.read(16)
        if len(salt) != 16: raise ValueError("Encrypted archive missing salt.")
    return {"algo":algo,"repeat":repeat,"name":name_b.decode(),"orig_size":orig_size,"crc32":crc32,"chunk_count":chunk_count,"encrypted":encrypted,"salt":salt}

def _write_chunk_table(fh, meta):
    for flag, length in meta:
        fh.write(struct.pack("<BI", flag, length))

def _read_chunk_table(fh, cnt):
    table = fh.read(cnt*5)
    if len(table)!=cnt*5: raise ValueError("Chunk table truncated.")
    meta=[]; off=0
    for _ in range(cnt):
        flag = table[off]; off+=1
        (length,) = struct.unpack_from("<I", table, off); off+=4
        meta.append((flag,length))
    return meta

def _is_within(directory: Path, target: Path) -> bool:
    try:
        return str(target.resolve()).startswith(str(directory.resolve()))
    except FileNotFoundError:
        return False

def safe_extract_tar(tar_bytes: bytes, dest_dir: Path):
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tarobj:
        for m in tarobj.getmembers():
            tgt = (dest_dir/m.name).resolve()
            if not _is_within(dest_dir, tgt):
                raise RuntimeError(f"Suspicious path: {m.name}")
            tarobj.extract(m, path=dest_dir)

def compress_cmd(paths, output_path: Path, repeat=1, threads=8, chunk_size=1<<20,
                 entropy_thr=7.8, profile="Normal", plus=True, delta=1, tar_order="none",
                 progress_cb=None, password=None, bcj="auto", dict_mb=None,
                 stegpad_mb: int = 0, dictseed_mb: int = 0,
                 cancelled_flag: Optional[List[bool]] = None,
                 force_all: bool = False, tune: str = "default"):
    dictseed_data = None
    if dictseed_mb and dictseed_mb > 0:
        dictseed_data = build_dictseed(paths, limit_mb=int(dictseed_mb), per_file_kb=64)

    stegpad_bytes = int(stegpad_mb) * (1<<20) if (stegpad_mb and stegpad_mb > 0) else 0

    data = make_solid_tar_from_many(paths, order=tar_order,
                                    stegpad_bytes=stegpad_bytes,
                                    dictseed_bytes=dictseed_data)
    orig = len(data)
    crc = _crc32(data)

    prog = Progress(cb=progress_cb, min_emit_ms=50)
    filters = _filters_for_profile(profile, plus, delta, bcj=bcj, dict_mb=dict_mb, tune=tune)

    chunks, meta = compress_stream(data, chunk_size, threads, repeat, entropy_thr, filters, prog,
                                   cancelled_flag=cancelled_flag, force_all=force_all)
    if chunks is None:
        raise RuntimeError("Operation cancelled.")

    salt = None
    if password:
        salt, enc_chunks = _encrypt_chunks_aesgcm(chunks, password)
        chunks = enc_chunks
        meta = [(fl, len(chunks[i])) for i,(fl,_) in enumerate(meta)]

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(prefix=output_path.stem + ".", suffix=".tmp", dir=str(output_path.parent))
    os.close(tmp_fd)
    try:
        with open(tmp_path, "wb") as f:
            final_name = (Path(paths[0]).resolve().parent.name + "_bundle") if len(paths)>1 else Path(paths[0]).name
            _write_header(f, final_name, orig, crc, repeat, ALGO_LZMA_XZ, len(chunks),
                          encrypted=bool(password), protocol_plus=plus, salt=salt)
            _write_chunk_table(f, meta)
            for ch in chunks: f.write(ch)
        os.replace(tmp_path, output_path)
    except Exception:
        try: os.remove(tmp_path)
        except Exception: pass
        raise

    total = sum(m[1] for m in meta) + 4 + (16 if password else 0) + len(final_name.encode()) + struct.calcsize(HEADER_FMT) + len(meta)*5
    return total, orig

def extract_cmd(archive_path: Path, dest_dir: Path=None, threads=8, progress_cb=None, password=None,
                cancelled_flag: Optional[List[bool]] = None):
    with open(archive_path, "rb") as f:
        hdr = _read_header(f)
        meta = _read_chunk_table(f, hdr["chunk_count"])
        chunks=[]
        for fl,ln in meta:
            b=f.read(ln)
            if len(b)!=ln: raise ValueError("Chunk truncated.")
            chunks.append(b)

    prog = Progress(cb=progress_cb, min_emit_ms=50)

    if hdr["encrypted"]:
        if not password:
            raise ValueError("Archive is encrypted but no password provided.")
        try:
            chunks = _decrypt_chunks_aesgcm(chunks, password, hdr["salt"])
        except Exception:
            raise ValueError("Invalid password.")

    compressed_data = decompress_stream(chunks, meta, threads, hdr["repeat"], prog, cancelled_flag=cancelled_flag)
    if compressed_data is None:
        raise RuntimeError("Operation cancelled.")

    if _crc32(compressed_data)!=hdr["crc32"]:
        raise ValueError("CRC mismatch. The archive may be corrupted or the wrong password was used.")

    out = dest_dir or Path(f"{hdr['name']}_extracted")
    safe_extract_tar(compressed_data, out)
    return out

# =========================
# ======= MODERN GUI ======
# =========================

MODERN_STYLE = f"""
QMainWindow, QWidget {{
    background-color: {COLORS['background']};
    color: {COLORS['text']};
    font-family: system-ui, -apple-system, 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-size: 14px;
}}
QGroupBox {{
    font-weight: 600;
    font-size: 15px;
    color: {COLORS['text']};
    background-color: {COLORS['surface']};
    border: 1px solid {COLORS['border']};
    border-radius: 8px;
    margin-top: 12px;
    padding: 10px 12px 12px 12px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    color: {COLORS['text']};
    font-weight: 700;
    font-size: 14px;
}}
QLineEdit, QPlainTextEdit {{
    background-color: {COLORS['surface_light']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 6px 10px;
    color: {COLORS['text']};
    font-size: 14px;
}}
QLineEdit:focus {{ border-color: {COLORS['border_focus']}; background-color: {COLORS['surface']}; }}
QSpinBox, QDoubleSpinBox, QComboBox {{
    background-color: {COLORS['surface_light']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 4px 10px;
    color: {COLORS['text']};
    font-size: 14px;
    min-height: 30px;
}}
QAbstractSpinBox {{ padding-right: 28px; }}
QPushButton {{
    background-color: {COLORS['surface']};
    color: {COLORS['text']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 9px 14px;
    font-weight: 600;
    font-size: 14px;
}}
QPushButton:hover {{ background-color: {COLORS['surface_light']}; border-color: {COLORS['accent']}; }}
QPushButton#primaryBtn {{ background-color: {COLORS['accent']}; border-color: {COLORS['accent']}; color: white; }}
QPushButton#dangerBtn {{ background-color: {COLORS['error']}; border-color: {COLORS['error']}; color: white; }}
QProgressBar {{
    background-color: {COLORS['surface']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    text-align: center;
    font-weight: 600;
    font-size: 14px;
    color: {COLORS['text']};
    min-height: 24px;
}}
QProgressBar::chunk {{ background-color: {COLORS['accent']}; border-radius: 4px; margin: 1px; }}
QTreeView {{
    background: {COLORS['surface_light']};
    border: 1px solid {COLORS['border']};
    alternate-background-color: {COLORS['surface']};
}}
QHeaderView::section {{
    background: {COLORS['surface']};
    color: {COLORS['text_secondary']};
    padding: 6px;
    border: 1px solid {COLORS['border']};
}}
"""

class PasswordDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, title="Enter Password"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedSize(400, 150)
        self._setup_ui()

    def _setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(12); layout.setContentsMargins(16,16,16,16)
        self.password_edit = QtWidgets.QLineEdit()
        self.password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Enter password...")
        button_layout = QtWidgets.QHBoxLayout()
        self.ok_btn = QtWidgets.QPushButton("OK"); self.cancel_btn = QtWidgets.QPushButton("Cancel")
        self.ok_btn.setObjectName("primaryBtn")
        self.ok_btn.clicked.connect(self.accept); self.cancel_btn.clicked.connect(self.reject)
        button_layout.addStretch(); button_layout.addWidget(self.cancel_btn); button_layout.addWidget(self.ok_btn)
        layout.addWidget(QtWidgets.QLabel("Password:")); layout.addWidget(self.password_edit); layout.addLayout(button_layout)
        self.password_edit.returnPressed.connect(self.accept)

    def get_password(self): return self.password_edit.text()

class ModernFileExplorer(QtWidgets.QDialog):
    def __init__(self, parent=None, mode="mixed"):
        super().__init__(parent)
        self.setWindowTitle("Select Files and Folders"); self.setModal(True)
        screen = QtGui.QGuiApplication.primaryScreen().availableGeometry()
        width = min(1400, int(screen.width() * 0.7)); height = min(800, int(screen.height() * 0.7))
        self.resize(width, height); self.move((screen.width() - width) // 2, (screen.height() - height) // 2)
        self.mode = mode; self._setup_ui(); self._connect_signals()

    def _setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self); layout.setSpacing(12); layout.setContentsMargins(16,16,16,16)
        header = QtWidgets.QLabel("Select Multiple Items"); header.setStyleSheet("font-size:18px;font-weight:700;"); layout.addWidget(header)
        instructions = QtWidgets.QLabel("Use Ctrl+Click or Shift+Click to select multiple files and folders. Double-click folders to navigate.")
        instructions.setStyleSheet("font-size:13px;color:#cccccc;"); instructions.setWordWrap(True); layout.addWidget(instructions)
        nav_layout = QtWidgets.QHBoxLayout(); nav_layout.setSpacing(8); nav_layout.addWidget(QtWidgets.QLabel("Path:"))
        self.path_edit = QtWidgets.QLineEdit(); self.path_edit.setText(QtCore.QDir.homePath()); self.path_edit.setMinimumHeight(30); nav_layout.addWidget(self.path_edit, 1)
        self.home_btn = QtWidgets.QPushButton("Home"); self.up_btn = QtWidgets.QPushButton("Up")
        for b in (self.home_btn, self.up_btn): b.setMinimumHeight(30)
        nav_layout.addWidget(self.home_btn); nav_layout.addWidget(self.up_btn); layout.addLayout(nav_layout)
        filter_layout = QtWidgets.QHBoxLayout(); filter_layout.setSpacing(8)
        self.filter_edit = QtWidgets.QLineEdit(); self.filter_edit.setPlaceholderText("Filter files (e.g., *.stalz, *.txt)"); self.filter_edit.setMinimumHeight(30)
        filter_layout.addWidget(self.filter_edit, 1)
        self.show_stalz_only = QtWidgets.QCheckBox("Show only .stalz files"); self.show_hidden = QtWidgets.QCheckBox("Show hidden files")
        filter_layout.addWidget(self.show_stalz_only); filter_layout.addWidget(self.show_hidden); layout.addLayout(filter_layout)
        self.model = QtGui.QFileSystemModel(self); self.model.setRootPath(QtCore.QDir.rootPath())
        self.model.setFilter(QtCore.QDir.Filter.AllEntries | QtCore.QDir.Filter.NoDotAndDotDot)
        self.tree_view = QtWidgets.QTreeView(self); self.tree_view.setModel(self.model)
        self.tree_view.setRootIndex(self.model.index(QtCore.QDir.homePath()))
        self.tree_view.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree_view.setSortingEnabled(True); self.tree_view.sortByColumn(0, QtCore.Qt.SortOrder.AscendingOrder)
        self.tree_view.setColumnWidth(0, 400); self.tree_view.setColumnWidth(1, 100); self.tree_view.setColumnWidth(2, 120); self.tree_view.setColumnWidth(3, 160)
        layout.addWidget(self.tree_view, 1)
        self.selection_info = QtWidgets.QLabel("No items selected"); self.selection_info.setStyleSheet("font-size:13px;color:#cccccc;"); layout.addWidget(self.selection_info)
        button_layout = QtWidgets.QHBoxLayout(); self.ok_btn = QtWidgets.QPushButton("Select Items"); self.ok_btn.setObjectName("primaryBtn")
        self.cancel_btn = QtWidgets.QPushButton("Cancel"); button_layout.addStretch(); button_layout.addWidget(self.cancel_btn); button_layout.addWidget(self.ok_btn); layout.addLayout(button_layout)

    def _connect_signals(self):
        self.path_edit.returnPressed.connect(self._navigate_to_path)
        self.home_btn.clicked.connect(self._go_home); self.up_btn.clicked.connect(self._go_up)
        self.filter_edit.textChanged.connect(self._apply_filters)
        self.show_stalz_only.toggled.connect(self._apply_filters); self.show_hidden.toggled.connect(self._apply_filters)
        self.tree_view.selectionModel().selectionChanged.connect(self._update_selection_info)
        self.tree_view.doubleClicked.connect(self._navigate_to_item)
        self.ok_btn.clicked.connect(self.accept); self.cancel_btn.clicked.connect(self.reject)

    def _navigate_to_path(self):
        path = self.path_edit.text().strip()
        if os.path.exists(path): self.tree_view.setRootIndex(self.model.index(path))

    def _go_home(self):
        home_path = QtCore.QDir.homePath(); self.path_edit.setText(home_path); self.tree_view.setRootIndex(self.model.index(home_path))

    def _go_up(self):
        current_path = self.path_edit.text(); parent_path = str(Path(current_path).parent)
        if parent_path != current_path:
            self.path_edit.setText(parent_path); self.tree_view.setRootIndex(self.model.index(parent_path))

    def _navigate_to_item(self, index):
        path = self.model.filePath(index)
        if os.path.isdir(path): self.path_edit.setText(path); self.tree_view.setRootIndex(index)

    def _apply_filters(self):
        filter_text = self.filter_edit.text().strip(); show_stalz = self.show_stalz_only.isChecked(); show_hidden = self.show_hidden.isChecked()
        flags = QtCore.QDir.Filter.AllEntries | QtCore.QDir.Filter.NoDotAndDotDot
        if show_hidden: flags |= QtCore.QDir.Filter.Hidden
        self.model.setFilter(flags)
        name_filters = ["*.stalz"] if (show_stalz and not filter_text) else ([filter_text] if filter_text else [])
        self.model.setNameFilters(name_filters); self.model.setNameFilterDisables(False)

    def _update_selection_info(self):
        selected_paths = self.get_selected_paths(); count = len(selected_paths)
        if count == 0: self.selection_info.setText("No items selected"); return
        files = sum(1 for p in selected_paths if os.path.isfile(p)); dirs = sum(1 for p in selected_paths if os.path.isdir(p))
        parts = [f"{count} item{'s' if count != 1 else ''} selected"]
        if files: parts.append(f"{files} file{'s' if files != 1 else ''}")
        if dirs: parts.append(f"{dirs} folder{'s' if dirs != 1 else ''}")
        self.selection_info.setText(" • ".join(parts))

    def get_selected_paths(self):
        indexes = self.tree_view.selectionModel().selectedRows(); paths=[]
        for idx in indexes:
            p = self.model.filePath(idx)
            if os.path.exists(p):
                if self.mode=="dirs" and not os.path.isdir(p): continue
                paths.append(p)
        return sorted(set(paths))

class ModernDropList(QtWidgets.QListWidget):
    pathsChanged = QtCore.pyqtSignal(list)
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setMinimumHeight(200)
        self.setAlternatingRowColors(True)
        self.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)
        self._current_paths = []
        self._placeholder_text = "Drag and drop files, folders, and STALZ archives here\n\nOr use the 'Add Items' button to browse"
        self._update_placeholder()

    def _update_placeholder(self):
        if not self._current_paths:
            self.clear()
            it = QtWidgets.QListWidgetItem(self._placeholder_text)
            it.setFlags(QtCore.Qt.ItemFlag.NoItemFlags)
            it.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            it.setData(QtCore.Qt.ItemDataRole.UserRole, "placeholder")
            font = QtGui.QFont(); font.setItalic(True); it.setFont(font)
            it.setForeground(QtGui.QColor(COLORS['text_muted']))
            self.addItem(it)

    def _show_context_menu(self, pos):
        item = self.itemAt(pos)
        if not item or item.data(QtCore.Qt.ItemDataRole.UserRole) == "placeholder": return
        menu = QtWidgets.QMenu(self)
        act_rm = menu.addAction("Remove Selected Items"); act_rm.triggered.connect(self._remove_selected)
        menu.addSeparator()
        act_cl = menu.addAction("Clear All Items"); act_cl.triggered.connect(self._clear_all)
        menu.exec(self.mapToGlobal(pos))

    def _remove_selected(self):
        sel = self.selectedItems()
        if not sel: return
        to_rm = []
        for it in sel:
            if it.data(QtCore.Qt.ItemDataRole.UserRole) != "placeholder":
                p = it.data(QtCore.Qt.ItemDataRole.UserRole)
                if p: to_rm.append(p)
        self._current_paths = [p for p in self._current_paths if p not in to_rm]
        self._refresh_display()
        if to_rm: self.pathsChanged.emit(self._current_paths)

    def _clear_all(self):
        self._current_paths = []; self._refresh_display(); self.pathsChanged.emit(self._current_paths)

    def _refresh_display(self):
        self.clear()
        if not self._current_paths: self._update_placeholder(); return
        for p in self._current_paths: self._add_path_item(p)

    def _add_path_item(self, path):
        p = Path(path); it = QtWidgets.QListWidgetItem(); it.setData(QtCore.Qt.ItemDataRole.UserRole, path)
        try:
            if p.is_dir():
                files = list(p.rglob('*')); cnt = len([f for f in files if f.is_file()])
                total = sum(f.stat().st_size for f in files if f.is_file())
                it.setText(f"Folder: {p.name}\n    Path: {path}\n    Stats: {cnt} files • {_human(total)}")
            else:
                size = p.stat().st_size; it.setText(f"File: {p.name}\n    Path: {path}\n    Size: {_human(size)}")
        except (PermissionError, OSError):
            it.setText(f"Path: {path}\n    Warning: Access restricted")
        self.addItem(it)

    def add_paths(self, paths):
        newp = [p for p in paths if p not in self._current_paths and os.path.exists(p)]
        if newp:
            self._current_paths.extend(newp); self._refresh_display(); self.pathsChanged.emit(self._current_paths)

    def dragEnterEvent(self, e): e.acceptProposedAction() if e.mimeData().hasUrls() else e.ignore()
    def dragMoveEvent(self, e): e.acceptProposedAction() if e.mimeData().hasUrls() else e.ignore()
    def dropEvent(self, e):
        urls = e.mimeData().urls(); paths = [u.toLocalFile() for u in urls if u.isLocalFile()]
        if paths: self.add_paths(paths); e.acceptProposedAction()

class ProcessingWorker(QtCore.QThread):
    progress = QtCore.pyqtSignal(int)
    status_update = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal(str, bool)

    def __init__(self, operation, paths, settings):
        super().__init__()
        self.operation = operation; self.paths = paths; self.settings = settings
        self.cancelled_flag = [False]; self._start_t = None; self._last_pct = 0

    def _progress_cb(self, pct: int):
        self.progress.emit(pct)
        now = time.monotonic()
        if self._start_t is None: self._start_t = now
        el = max(1e-3, now - self._start_t)
        speed = f"{pct/el:.2f} %/s"
        eta_s = (100 - pct) * (el / max(1e-6, pct)) if pct > 0 else 0
        if pct != self._last_pct:
            self._last_pct = pct
            eta_txt = time.strftime("%M:%S", time.gmtime(int(eta_s))) if pct>0 else "--:--"
            self.status_update.emit(f"{'Compressing' if self.operation=='compress' else 'Extracting'}… {pct}%  |  ETA {eta_txt}  |  {speed}")

    def run(self):
        try:
            if self.operation == "compress": self._run_compression()
            else: self._run_extraction()
        except Exception as e:
            import traceback
            self.finished.emit(f"Unexpected error occurred:\n{str(e)}\n\nDetails:\n{traceback.format_exc()}", False)

    def _run_compression(self):
        if not self.paths:
            self.finished.emit("No files selected for compression.", False); return
        missing = [p for p in self.paths if not os.path.exists(p)]
        if missing:
            self.finished.emit("Missing:\n" + "\n".join("• "+p for p in missing), False); return
        self.status_update.emit("Preparing compression…")
        try:
            output_path = self._get_output_path()
            self.status_update.emit(f"Creating archive: {output_path.name}")
            self.status_update.emit(f"Processing {len(self.paths)} item(s)…")
            password = self.settings.get("password")
            total_compressed, original_size = compress_cmd(
                self.paths, output_path,
                repeat=self.settings["repeat"],
                threads=self.settings["threads"],
                chunk_size=self.settings["chunk_size"],
                entropy_thr=self.settings["entropy_threshold"],
                profile=self.settings["preset"],
                plus=self.settings["protocol_plus"],
                delta=self.settings["delta_distance"],
                tar_order=self.settings["tar_order"],
                progress_cb=self._progress_cb,
                password=password,
                bcj=self.settings.get("bcj", "auto"),
                dict_mb=self.settings.get("dict_mb"),
                stegpad_mb=self.settings.get("stegpad_mb", 0),
                dictseed_mb=self.settings.get("dictseed_mb", 0),
                cancelled_flag=self.cancelled_flag,
                force_all=self.settings.get("force_all", False),
                tune=self.settings.get("tune", "default"),
            )
            if self.cancelled_flag[0]:
                self.finished.emit("Compression cancelled by user.", False); return
            ratio = ((original_size - total_compressed) / original_size * 100) if original_size > 0 else 0
            saved = original_size - total_compressed
            msg = (f"Compression completed successfully!\n\n"
                   f"Archive: {output_path}\n"
                   f"Statistics:\n"
                   f"   • Items processed: {len(self.paths)}\n"
                   f"   • Original size: {_human(original_size)}\n"
                   f"   • Compressed size: {_human(total_compressed)}\n"
                   f"   • Compression ratio: {ratio:.1f}%\n"
                   f"   • Space saved: {_human(saved)}")
            if password: msg += "\n   • Archive is encrypted (AES-GCM)"
            if self.settings.get("stegpad_mb", 0): msg += f"\n   • StegPad capacity: {self.settings['stegpad_mb']} MB"
            if self.settings.get("dictseed_mb", 0): msg += f"\n   • DictSeed: {self.settings['dictseed_mb']} MB"
            if self.settings.get("force_all", False): msg += "\n   • Forced recompress: ON"
            if self.settings.get("tune", "default") != "default": msg += f"\n   • LZMA tuning: {self.settings['tune']}"
            self.finished.emit(msg, True)
        except Exception as e:
            self.finished.emit(f"Compression failed:\n{str(e)}", False)

    def _run_extraction(self):
        if not self.paths:
            self.finished.emit("No archives selected for extraction.", False); return
        self.status_update.emit("Starting extraction…")
        results=[]; ok=0
        for i, ap in enumerate(self.paths):
            if self.cancelled_flag[0]: break
            self.status_update.emit(f"Extracting {i+1}/{len(self.paths)}: {Path(ap).name}")
            if not ap.lower().endswith('.stalz'):
                results.append(f"Skipped (not a STALZ file): {Path(ap).name}"); continue
            if not os.path.exists(ap):
                results.append(f"File not found: {ap}"); continue
            try:
                with open(ap,"rb") as f: hdr = _read_header(f)
                password = None
                if hdr["encrypted"]:
                    password = self.settings.get("passwords", {}).get(ap)
                    if not password:
                        results.append(f"Failed: {Path(ap).name}\n      Error: Archive is encrypted but no password provided")
                        continue
                dest_dir = Path(self.settings["extraction_path"]) if self.settings.get("extraction_path") else None
                out = extract_cmd(Path(ap), dest_dir=dest_dir, threads=self.settings["threads"],
                                  progress_cb=self._progress_cb, password=password, cancelled_flag=self.cancelled_flag)
                results.append(f"Extracted: {Path(ap).name}\n      → {out}"); ok += 1
            except Exception as e:
                results.append(f"Failed: {Path(ap).name}\n      Error: {str(e)}")
        if self.cancelled_flag[0]:
            self.finished.emit("Extraction cancelled by user.", False); return
        total=len(self.paths)
        if ok==total: self.finished.emit(f"All {total} archive(s) extracted successfully!\n\n" + "\n\n".join(results), True)
        elif ok>0: self.finished.emit(f"Partially successful: {ok}/{total}\n\n" + "\n\n".join(results), True)
        else: self.finished.emit("Extraction failed for all archives\n\n" + "\n\n".join(results), False)

    def _get_output_path(self):
        if len(self.paths) == 1:
            base = Path(self.paths[0])
            output = base.with_suffix('.stalz') if base.is_file() else base.parent / f"{base.name}.stalz"
        else:
            output = Path(self.paths[0]).parent / "archive.stalz"
        counter = 1; orig = output
        while output.exists():
            output = orig.parent / f"{orig.stem}_{counter}.stalz"; counter += 1
        return output

class ModernMainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker: Optional[ProcessingWorker] = None
        self._setup_window(); self._setup_ui(); self._connect_signals(); self._apply_default_settings()

    def _setup_window(self):
        self.setWindowTitle("STALZ Pro - Advanced File Compression Suite")
        base_flags = (QtCore.Qt.WindowType.Window |
                      QtCore.Qt.WindowType.WindowTitleHint |
                      QtCore.Qt.WindowType.WindowMinimizeButtonHint |
                      QtCore.Qt.WindowType.WindowCloseButtonHint)
        self.setWindowFlags(base_flags)
        self.setWindowFlag(QtCore.Qt.WindowType.WindowMaximizeButtonHint, False)
        self.setWindowFlag(QtCore.Qt.WindowType.WindowFullscreenButtonHint, False)
        screen_geo = QtGui.QGuiApplication.primaryScreen().availableGeometry()
        self.setGeometry(screen_geo)
        self.setFixedSize(screen_geo.width(), screen_geo.height())
        self.move(screen_geo.topLeft())
        self.setStyleSheet(MODERN_STYLE)

    def _setup_ui(self):
        central = QtWidgets.QWidget(); self.setCentralWidget(central)
        main = QtWidgets.QVBoxLayout(central); main.setSpacing(10); main.setContentsMargins(14, 10, 14, 10)

        head = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("STALZ Pro Compression Suite"); title.setStyleSheet("font-size:20px;font-weight:700;")
        self.theme_btn = QtWidgets.QPushButton("Dark"); self.theme_btn.setCheckable(True); self.theme_btn.setToolTip("Tema değiştir (Dark/Light)")
        head.addWidget(title); head.addStretch(); head.addWidget(self.theme_btn)
        main.addLayout(head)

        list_group = QtWidgets.QGroupBox("Selected Items")
        list_layout = QtWidgets.QVBoxLayout(list_group); list_layout.setSpacing(8); list_layout.setContentsMargins(10,14,10,10)
        self.file_list = ModernDropList(); self.file_list.pathsChanged.connect(self._on_paths_changed)
        list_layout.addWidget(self.file_list)
        main.addWidget(list_group)

        settings_layout = QtWidgets.QHBoxLayout(); settings_layout.setSpacing(10)

        comp_group = QtWidgets.QGroupBox("Compression Settings")
        form = QtWidgets.QFormLayout(comp_group)
        spacing = 8
        form.setSpacing(spacing); form.setVerticalSpacing(spacing)
        # RowWrapPolicy.DontWrap (0) — bazı PyQt yapılarında ad çözülmeyebilir, sabit değerle veriyoruz.
        form.setRowWrapPolicy(QtWidgets.QFormLayout.RowWrapPolicy(0))
        form.setFieldGrowthPolicy(QtWidgets.QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        form.setLabelAlignment(QtCore.Qt.AlignmentFlag.AlignRight | QtCore.Qt.AlignmentFlag.AlignVCenter)

        def _ensure_arrows(sp: QtWidgets.QAbstractSpinBox, plus_minus: bool=False):
            sp.setMinimumHeight(30)
            sp.setButtonSymbols(QtWidgets.QAbstractSpinBox.ButtonSymbols.PlusMinus if plus_minus
                                else QtWidgets.QAbstractSpinBox.ButtonSymbols.UpDownArrows)

        self.preset_combo = QtWidgets.QComboBox(); self.preset_combo.addItems(["Low", "Normal", "High", "Extreme"]); self.preset_combo.setCurrentText("Normal")
        self.passes_spin = QtWidgets.QSpinBox(); self.passes_spin.setRange(1,10); self.passes_spin.setValue(1); _ensure_arrows(self.passes_spin, True)
        self.protocol_plus_check = QtWidgets.QCheckBox("Enable Protocol+"); self.protocol_plus_check.setChecked(True)
        self.delta_spin = QtWidgets.QSpinBox(); self.delta_spin.setRange(1,256); self.delta_spin.setValue(1); _ensure_arrows(self.delta_spin)
        self.tar_order_combo = QtWidgets.QComboBox(); self.tar_order_combo.addItems(["none", "by-size", "by-name", "by-ext", "smart"])
        self.encryption_check = QtWidgets.QCheckBox("Enable Encryption (AES-GCM)")
        self.bcj_combo = QtWidgets.QComboBox(); self.bcj_combo.addItems(["auto", "none", "x86", "ARM", "ARMThumb", "ARM64", "PowerPC", "IA64", "SPARC"])
        self.dict_spin = QtWidgets.QSpinBox(); self.dict_spin.setRange(1,2048); self.dict_spin.setValue(64); self.dict_spin.setSuffix(" MB"); _ensure_arrows(self.dict_spin)
        self.force_all_check = QtWidgets.QCheckBox("Force Recompress All Chunks (even high-entropy)")
        self.tune_combo = QtWidgets.QComboBox(); self.tune_combo.addItems(["default", "aggressive", "fast"])
        self.steg_check = QtWidgets.QCheckBox("Embed StegPad capacity")
        self.steg_spin = QtWidgets.QSpinBox(); self.steg_spin.setRange(0, 8192); self.steg_spin.setValue(0); self.steg_spin.setSuffix(" MB"); _ensure_arrows(self.steg_spin)
        self.dictseed_check = QtWidgets.QCheckBox("Add DictSeed (text/code sampler)")
        self.dictseed_spin = QtWidgets.QSpinBox(); self.dictseed_spin.setRange(0, 64); self.dictseed_spin.setValue(0); self.dictseed_spin.setSuffix(" MB"); _ensure_arrows(self.dictseed_spin)

        form.addRow("Preset Level:", self.preset_combo)
        form.addRow("Compression Passes:", self.passes_spin)
        form.addRow("", self.protocol_plus_check)
        form.addRow("Delta Distance:", self.delta_spin)
        form.addRow("File Ordering:", self.tar_order_combo)
        form.addRow("BCJ Filter:", self.bcj_combo)
        form.addRow("Dictionary:", self.dict_spin)
        form.addRow("", self.encryption_check)
        form.addRow("Recompress:", self.force_all_check)
        form.addRow("Tuning:", self.tune_combo)
        form.addRow("StegPad:", self._h(self.steg_check, self.steg_spin))
        form.addRow("DictSeed:", self._h(self.dictseed_check, self.dictseed_spin))

        adv_group = QtWidgets.QGroupBox("Advanced Settings")
        aform = QtWidgets.QFormLayout(adv_group)
        aform.setSpacing(spacing); aform.setVerticalSpacing(spacing)
        aform.setRowWrapPolicy(QtWidgets.QFormLayout.RowWrapPolicy(0))
        aform.setFieldGrowthPolicy(QtWidgets.QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        aform.setLabelAlignment(QtCore.Qt.AlignmentFlag.AlignRight | QtCore.Qt.AlignmentFlag.AlignVCenter)
        max_threads = max(1, os.cpu_count() or 4)
        ram_bytes = _total_ram_bytes(); max_chunk_mb = min(2048, max(4, ram_bytes // (4 * 1024 * 1024)))
        self.threads_spin = QtWidgets.QSpinBox(); self.threads_spin.setRange(1, max_threads); self.threads_spin.setValue(min(8, max_threads)); _ensure_arrows(self.threads_spin)
        self.chunk_spin = QtWidgets.QSpinBox(); self.chunk_spin.setRange(1, max_chunk_mb); self.chunk_spin.setValue(8); self.chunk_spin.setSuffix(" MB"); _ensure_arrows(self.chunk_spin)
        self.entropy_spin = QtWidgets.QDoubleSpinBox(); self.entropy_spin.setRange(0.0,8.0); self.entropy_spin.setValue(7.8); self.entropy_spin.setDecimals(2); self.entropy_spin.setSingleStep(0.1)
        self.entropy_spin.setMinimumHeight(30)
        aform.addRow("CPU Threads:", self.threads_spin)
        aform.addRow("Chunk Size:", self.chunk_spin)
        aform.addRow("Entropy Threshold:", self.entropy_spin)

        ext_group = QtWidgets.QGroupBox("Extraction Settings")
        eform = QtWidgets.QFormLayout(ext_group)
        eform.setSpacing(spacing); eform.setVerticalSpacing(spacing)
        eform.setRowWrapPolicy(QtWidgets.QFormLayout.RowWrapPolicy(0))
        eform.setFieldGrowthPolicy(QtWidgets.QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        eform.setLabelAlignment(QtCore.Qt.AlignmentFlag.AlignRight | QtCore.Qt.AlignmentFlag.AlignVCenter)
        path_layout = QtWidgets.QHBoxLayout()
        self.extraction_path_edit = QtWidgets.QLineEdit(); self.extraction_path_edit.setPlaceholderText("Auto-create folder next to archive")
        self.extraction_path_edit.setMinimumHeight(30)
        self.browse_btn = QtWidgets.QPushButton("Browse"); path_layout.addWidget(self.extraction_path_edit, 1); path_layout.addWidget(self.browse_btn)
        eform.addRow("Extract to:", path_layout)

        settings_layout.addWidget(comp_group, 4)
        settings_layout.addWidget(adv_group, 3)
        settings_layout.addWidget(ext_group, 3)
        main.addLayout(settings_layout)

        pr = QtWidgets.QHBoxLayout()
        self.compress_btn = QtWidgets.QPushButton("Compress Selected Items"); self.compress_btn.setObjectName("primaryBtn"); self.compress_btn.setMinimumHeight(38)
        self.extract_btn = QtWidgets.QPushButton("Extract Selected Archives"); self.extract_btn.setMinimumHeight(38)
        self.cancel_btn = QtWidgets.QPushButton("Cancel"); self.cancel_btn.setObjectName("dangerBtn"); self.cancel_btn.setMinimumHeight(38); self.cancel_btn.setEnabled(False)
        pr.addWidget(self.compress_btn); pr.addWidget(self.extract_btn); pr.addWidget(self.cancel_btn); pr.addStretch()
        self.item_count_label = QtWidgets.QLabel("No items selected")
        self.item_count_label.setStyleSheet("font-size:13px;color:#999999;padding:6px 12px;background:#252525;border-radius:4px;")
        pr.addWidget(self.item_count_label)
        main.addLayout(pr)

        self.status_label = QtWidgets.QLabel("Ready"); self.status_label.setStyleSheet("font-size:14px;font-weight:600;color:#cccccc;padding:6px 0;")
        self.progress_bar = QtWidgets.QProgressBar(); self.progress_bar.setValue(0); self.progress_bar.setTextVisible(True); self.progress_bar.setMinimumHeight(24)
        main.addWidget(self.status_label); main.addWidget(self.progress_bar)
        self.log = QtWidgets.QPlainTextEdit(); self.log.setReadOnly(True); self.log.setMinimumHeight(120)
        self.log.setStyleSheet("background:#1a1a1a;color:#ddd;border:1px solid #404040;border-radius:6px;")
        main.addWidget(self.log, 1)

        toolbar = self.addToolBar("Main Actions"); toolbar.setMovable(False); toolbar.setToolButtonStyle(QtCore.Qt.ToolButtonStyle.ToolButtonTextOnly)
        add_action = toolbar.addAction("Add Items"); add_action.triggered.connect(self._add_items)
        toolbar.addSeparator(); clear_action = toolbar.addAction("Clear All"); clear_action.triggered.connect(self._clear_all_items)
        toolbar.addSeparator(); about_action = toolbar.addAction("About"); about_action.triggered.connect(self._show_about)
        self.browse_btn.clicked.connect(self._browse_extraction_path)

    def _h(self, w1, w2):
        box = QtWidgets.QWidget(); h = QtWidgets.QHBoxLayout(box); h.setContentsMargins(0,0,0,0); h.setSpacing(6); h.addWidget(w1); h.addWidget(w2); return box

    def _connect_signals(self):
        self.preset_combo.currentTextChanged.connect(self._on_preset_changed)
        self.compress_btn.clicked.connect(lambda: self._start_operation("compress"))
        self.extract_btn.clicked.connect(lambda: self._start_operation("extract"))
        self.cancel_btn.clicked.connect(self._cancel_op)
        self.theme_btn.toggled.connect(self._toggle_theme)

    def _apply_default_settings(self): self._on_preset_changed("Normal")

    def _toggle_theme(self, checked):
        if checked: self.setStyleSheet(""); self.theme_btn.setText("Light")
        else: self.setStyleSheet(MODERN_STYLE); self.theme_btn.setText("Dark")

    def _add_items(self):
        dlg = ModernFileExplorer(self, mode="mixed")
        if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            sel = dlg.get_selected_paths()
            if sel: self.file_list.add_paths(sel)

    def _clear_all_items(self):
        if self.file_list._current_paths:
            if QtWidgets.QMessageBox.question(self, "Clear All Items",
                f"Are you sure you want to remove all {len(self.file_list._current_paths)} items?",
                QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
                QtWidgets.QMessageBox.StandardButton.No) == QtWidgets.QMessageBox.StandardButton.Yes:
                self.file_list._clear_all()

    def _browse_extraction_path(self):
        dlg = ModernFileExplorer(self, mode="dirs"); dlg.setWindowTitle("Select Extraction Destination")
        if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            sel = dlg.get_selected_paths()
            if sel: self.extraction_path_edit.setText(sel[0])

    def _on_paths_changed(self, paths):
        c = len(paths)
        if c == 0:
            self.item_count_label.setText("No items selected"); self.compress_btn.setEnabled(False); self.extract_btn.setEnabled(False)
        else:
            files = sum(1 for p in paths if os.path.isfile(p)); dirs = sum(1 for p in paths if os.path.isdir(p)); arch = sum(1 for p in paths if p.lower().endswith('.stalz'))
            if files and dirs: self.item_count_label.setText(f"{c} items ({files} files, {dirs} folders)")
            elif files: self.item_count_label.setText(f"{files} file{'s' if files != 1 else ''}")
            else: self.item_count_label.setText(f"{dirs} folder{'s' if dirs != 1 else ''}")
            self.compress_btn.setEnabled(c > 0); self.extract_btn.setEnabled(arch > 0)

    def _on_preset_changed(self, name):
        prs = {"Low": {"chunk": 2, "passes": 1, "protocol_plus": False},
               "Normal": {"chunk": 8, "passes": 1, "protocol_plus": True},
               "High": {"chunk": 8, "passes": 2, "protocol_plus": True},
               "Extreme": {"chunk": 16, "passes": 3, "protocol_plus": True}}
        if name in prs:
            s = prs[name]; self.chunk_spin.setValue(min(s["chunk"], self.chunk_spin.maximum()))
            self.passes_spin.setValue(s["passes"]); self.protocol_plus_check.setChecked(s["protocol_plus"])

    def _start_operation(self, op):
        if self.worker and self.worker.isRunning():
            QtWidgets.QMessageBox.information(self, "Operation in Progress", "Please wait for the current operation to complete."); return
        paths = self.file_list._current_paths
        if not paths:
            QtWidgets.QMessageBox.warning(self, "No Items Selected", "Please add some files or folders first."); return
        if op == "extract":
            stalz = [p for p in paths if p.lower().endswith('.stalz')]
            if not stalz:
                QtWidgets.QMessageBox.warning(self, "No Archives Found", "Please select STALZ archive files (.stalz) for extraction."); return
            paths = stalz

        settings = self._get_current_settings(op, paths)
        self.worker = ProcessingWorker(op, paths, settings)
        self.worker.progress.connect(self.progress_bar.setValue, QtCore.Qt.ConnectionType.QueuedConnection)
        self.worker.status_update.connect(self._update_status, QtCore.Qt.ConnectionType.QueuedConnection)
        self.worker.finished.connect(self._operation_finished, QtCore.Qt.ConnectionType.QueuedConnection)
        self._set_processing_state(True); self._update_status(f"Starting {op}…"); self._log(f"Started {op} with {len(paths)} item(s).")
        self.worker.start()

    def _cancel_op(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancelled_flag[0] = True; self._update_status("Cancelling…"); self._log("Cancellation requested by user.")

    def _get_current_settings(self, op, paths):
        settings = {
            "preset": self.preset_combo.currentText(),
            "repeat": self.passes_spin.value(),
            "protocol_plus": self.protocol_plus_check.isChecked(),
            "delta_distance": self.delta_spin.value(),
            "tar_order": self.tar_order_combo.currentText(),
            "threads": self.threads_spin.value(),
            "chunk_size": self.chunk_spin.value() * 1024 * 1024,
            "entropy_threshold": self.entropy_spin.value(),
            "extraction_path": self.extraction_path_edit.text().strip() or None,
            "bcj": self.bcj_combo.currentText(),
            "dict_mb": self.dict_spin.value() if self.protocol_plus_check.isChecked() else None,
            "stegpad_mb": self.steg_spin.value() if self.steg_check.isChecked() else 0,
            "dictseed_mb": self.dictseed_spin.value() if self.dictseed_check.isChecked() else 0,
            "force_all": self.force_all_check.isChecked(),
            "tune": self.tune_combo.currentText()
        }
        if op == "compress" and self.encryption_check.isChecked():
            dlg = PasswordDialog(self, "Set Encryption Password")
            if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
                pwd = dlg.get_password()
                if pwd: settings["password"] = pwd
                else: raise ValueError("Password cannot be empty for encryption.")
            else: raise ValueError("Encryption cancelled by user.")
        elif op == "extract":
            pwds = {}
            for p in paths:
                try:
                    with open(p, "rb") as f:
                        hdr = _read_header(f)
                        if hdr["encrypted"]:
                            dlg = PasswordDialog(self, f"Password for {Path(p).name}")
                            if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
                                pwd = dlg.get_password()
                                if pwd: pwds[p] = pwd
                                else: raise ValueError(f"Password required for encrypted archive: {Path(p).name}")
                            else: raise ValueError("Password input cancelled by user.")
                except Exception: pass
            settings["passwords"] = pwds
        return settings

    def _set_processing_state(self, processing):
        self.compress_btn.setEnabled(not processing); self.extract_btn.setEnabled(not processing)
        self.cancel_btn.setEnabled(processing); self.progress_bar.setValue(0)

    def _update_status(self, message): self.status_label.setText(message)

    def _operation_finished(self, message, success):
        self._set_processing_state(False); self.status_label.setText("Ready")
        self.progress_bar.setValue(100 if success else self.progress_bar.value())
        self._log(message)
        icon = QtWidgets.QMessageBox.Icon.Information if success else QtWidgets.QMessageBox.Icon.Critical
        self._show_message("Success" if success else "Error", message, icon, detailed=True)

    def _show_message(self, title, message, icon=QtWidgets.QMessageBox.Icon.Information, detailed=False):
        box = QtWidgets.QMessageBox(self); box.setWindowTitle(title); box.setIcon(icon)
        if detailed and len(message) > 200:
            lines = message.split('\n')
            if len(lines) > 1: box.setText(lines[0]); box.setDetailedText('\n'.join(lines[1:]))
            else: box.setText(message[:200] + "…"); box.setDetailedText(message)
        else: box.setText(message)
        box.exec()

    def _show_about(self):
        html = """
        <div style='text-align:center;padding:20px;'>
            <h2 style='color:#0078d4;margin-bottom:10px;'>STALZ Pro</h2>
            <h3 style='color:#cccccc;margin-bottom:20px;'>Advanced File Compression Suite</h3>
            <p style='font-size:16px;margin-bottom:15px;'><strong>Version 3.4 Professional</strong></p>
            <p style='margin-bottom:20px;'>
                Protocol+, AES-GCM, StegPad & DictSeed, Smart ordering, Forced recompress, LZMA tuning, ETA + Cancel.
            </p>
            <p style='font-size:12px;color:#999;border-top:1px solid #404040;padding-top:15px;'>
                Built with Python 3 and PyQt6 · © 2025 STALZ Development Team
            </p>
        </div>
        """
        box = QtWidgets.QMessageBox(self); box.setWindowTitle("About STALZ Pro")
        box.setTextFormat(QtCore.Qt.TextFormat.RichText); box.setText(html)
        box.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Ok); box.exec()

    def _log(self, text: str): self.log.appendPlainText(text)

    def resizeEvent(self, e: QtGui.QResizeEvent) -> None:
        self.blockSignals(True); self.setFixedSize(self.size()); self.blockSignals(False)
        super().resizeEvent(e)

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            if QtWidgets.QMessageBox.question(self, "Confirm Exit", "An operation is currently in progress.\n\nAre you sure you want to exit?",
                                              QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
                                              QtWidgets.QMessageBox.StandardButton.No) == QtWidgets.QMessageBox.StandardButton.Yes:
                self.worker.cancelled_flag[0] = True; self.worker.wait(3000); event.accept()
            else: event.ignore()
        else: event.accept()

# =========================
# ========= main ==========
# =========================

def main():
    app = QtWidgets.QApplication(sys.argv)
    # TUTARLI GÖRÜNÜM: Fusion (spinbox okları görünür)
    try: app.setStyle("Fusion")
    except Exception: pass

    app.setApplicationName("STALZ Pro")
    app.setApplicationDisplayName("STALZ Pro - Advanced File Compression")
    app.setApplicationVersion("3.4")
    app.setOrganizationName("STALZ Development Team")
    app.setOrganizationDomain("stalz.dev")

    # Platforma göre font (Segoe zorlanmıyor)
    fam = None
    if sys.platform == "win32":
        fam = "Segoe UI"
    elif sys.platform == "darwin":
        fam = ".AppleSystemUIFont"  # sistem varsayılanı
    else:
        fam = "DejaVu Sans"
    if fam:
        f = QtGui.QFont(fam, 10); f.setStyleHint(QtGui.QFont.StyleHint.System); app.setFont(f)

    try:
        app.setAttribute(QtCore.Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
        app.setAttribute(QtCore.Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)
    except AttributeError: pass

    window = ModernMainWindow()
    window.show()
    return app.exec()

if __name__ == "__main__":
    sys.exit(main())
