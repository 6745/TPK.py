"""Shared helpers for reading and writing TPK archives."""
from __future__ import annotations

import binascii
import dataclasses
import struct
from typing import Iterator, Sequence, Tuple, Union

try:
    import lzo  # type: ignore
    HAVE_LZO = True
except ImportError:  # pragma: no cover - environment dependent
    lzo = None  # type: ignore
    HAVE_LZO = False

try:
    from Crypto.Cipher import AES  # type: ignore
    HAVE_PYCRYPTODOME = True
except ImportError:  # pragma: no cover - environment dependent
    AES = None
    HAVE_PYCRYPTODOME = False

TPK_MAGIC = 0xCEDE
HEADER_STRUCT = struct.Struct("<HHBBHI")
HEADER_SIZE = HEADER_STRUCT.size  # 12 bytes on disk
ENTRY_STRUCT = struct.Struct("<128sIIII")
ENTRY_SIZE = ENTRY_STRUCT.size  # 144 bytes interleaved with data chunks
AES_KEY = b"Shit!DontTouchMe"
BLOCK_SIZE = 16


@dataclasses.dataclass(slots=True)
class TpkHeader:
    magic: int
    version: int
    compression_flag: int
    crypto_flag: int
    entry_count: int
    meta_size: int

    @classmethod
    def parse(cls, data: bytes) -> "TpkHeader":
        if len(data) < HEADER_SIZE:
            raise ValueError("TPK header too short")
        parts = HEADER_STRUCT.unpack_from(data, 0)
        header = cls(*parts)
        if header.magic != TPK_MAGIC:
            raise ValueError(f"Invalid TPK magic 0x{header.magic:04X}")
        if header.version != 0x14:
            raise ValueError(f"Unsupported TPK version {header.version}")
        return header

    def needs_crypto(self) -> bool:
        return self.crypto_flag != 0

    def needs_compression(self) -> bool:
        return self.compression_flag != 0


@dataclasses.dataclass(slots=True)
class TpkEntry:
    path: str
    crc: int
    packed_size: int
    offset: int
    reserved: int = 0
    compressed_size: int | None = None

    def to_bytes(self) -> bytes:
        name = self.path.encode("ascii")
        if len(name) >= 128:
            raise ValueError(f"Path too long for TPK entry: {self.path}")
        name_field = name + b"\x00" * (128 - len(name))
        size_field = self.compressed_size if self.compressed_size is not None else self.packed_size
        return ENTRY_STRUCT.pack(name_field, self.crc, size_field, self.offset, self.reserved)


def decrypt_metadata(buffer: bytes) -> bytes:
    if not HAVE_PYCRYPTODOME or AES is None:
        raise RuntimeError(
            "PyCryptodome is required to decrypt metadata. Install with 'pip install pycryptodome'."
        )
    usable = len(buffer) - (len(buffer) % BLOCK_SIZE)
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(buffer[:usable])
    if usable < len(buffer):
        decrypted += buffer[usable:]
    return decrypted


def encrypt_metadata(buffer: bytes) -> bytes:
    if not HAVE_PYCRYPTODOME or AES is None:
        raise RuntimeError(
            "PyCryptodome is required to encrypt metadata. Install with 'pip install pycryptodome'."
        )
    usable = len(buffer) - (len(buffer) % BLOCK_SIZE)
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(buffer[:usable])
    if usable < len(buffer):
        encrypted += buffer[usable:]
    return encrypted


def maybe_transform_metadata(header: TpkHeader, raw_meta: bytes) -> bytes:
    if header.needs_crypto():
        return decrypt_metadata(raw_meta)
    return raw_meta


def _lzo1x_decompress(block: bytes) -> bytes:
    if not HAVE_LZO or lzo is None:
        raise RuntimeError(
            "python-lzo is required to unpack compressed chunks. Install with 'pip install lzo'."
        )
    if not block:
        return b""
    # Start with a conservative buffer and grow if decompressor requests more space.
    buf_len = max(len(block) * 8, 65536)
    while True:
        try:
            return lzo.decompress(block, False, buf_len, algorithm="LZO1X")
        except lzo.error as exc:  # type: ignore[attr-defined]
            msg = str(exc)
            if "Output overrun" in msg or "Destination not long enough" in msg:
                buf_len *= 2
                if buf_len > 64 * 1024 * 1024:  # guard against runaway allocations
                    raise RuntimeError("Compressed chunk expands beyond 64 MiB") from exc
                continue
            raise


def compute_crc32(
    data: bytes,
    *,
    seed: int = 0xFFFFFFFF,
    final_xor: int = 0xFFFFFFFF,
) -> int:
    """Compute a CRC32 using the reflected 0xEDB88320 polynomial."""
    crc = binascii.crc32(data, seed) & 0xFFFFFFFF
    return crc ^ final_xor


EntryYield = Union[Tuple[TpkEntry, bytes], Tuple[TpkEntry, bytes, bytes]]


def iter_entries(
    meta: bytes,
    entry_count: int,
    *,
    compressed: bool = False,
    include_packed: bool = False,
) -> Iterator[EntryYield]:
    cursor = 0
    consumed_payload = 0
    for idx in range(entry_count):
        if cursor + ENTRY_SIZE > len(meta):
            raise ValueError(f"Metadata truncated before entry {idx}")
        raw_entry = meta[cursor:cursor + ENTRY_SIZE]
        cursor += ENTRY_SIZE
        name_raw, crc, size, offset, reserved = ENTRY_STRUCT.unpack(raw_entry)
        path = name_raw.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        entry = TpkEntry(path=path, crc=crc, packed_size=size, offset=offset, reserved=reserved)
        if offset != consumed_payload:
            raise ValueError(
                f"Entry {idx} offset mismatch: expected {consumed_payload} got {offset}"
            )
        if cursor + size > len(meta):
            raise ValueError(f"Metadata truncated while reading payload for {path}")
        chunk = meta[cursor:cursor + size]
        cursor += size
        consumed_payload += size
        packed_chunk = chunk
        if compressed:
            decompressed = _lzo1x_decompress(chunk)
            entry = dataclasses.replace(
                entry,
                packed_size=len(decompressed),
                compressed_size=size,
            )
            chunk = decompressed
        if include_packed:
            yield entry, chunk, packed_chunk
        else:
            yield entry, chunk
    if cursor != len(meta):
        trailing = meta[cursor:]
        if any(trailing):
            raise ValueError(
                f"Metadata parsing finished with {len(trailing)} non-zero trailing bytes"
            )


def build_metadata(entries: Sequence[Tuple[TpkEntry, bytes]]) -> bytes:
    pieces: list[bytes] = []
    offset = 0
    for entry, blob in entries:
        if entry.packed_size != len(blob):
            entry = dataclasses.replace(entry, packed_size=len(blob))
        entry = dataclasses.replace(entry, offset=offset)
        pieces.append(entry.to_bytes())
        pieces.append(blob)
        offset += len(blob)
    return b"".join(pieces)
