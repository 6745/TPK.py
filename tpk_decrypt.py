from __future__ import annotations

import os
from itertools import islice
from pathlib import Path
from typing import Iterable

from tpk_format import (
    HEADER_SIZE,
    TpkHeader,
    encrypt_metadata,
    iter_entries,
    maybe_transform_metadata,
)


def describe_entries(meta: bytes, header: TpkHeader, limit: int = 3) -> None:
    preview = islice(
        iter_entries(meta, header.entry_count, compressed=header.needs_compression()),
        limit,
    )
    for idx, (entry, chunk) in enumerate(preview):
        snippet = chunk[:8].hex()
        print(
            f"  [{idx}] {entry.path} :: size={entry.packed_size} bytes, "
            f"crc=0x{entry.crc:08X}, head={snippet}"
        )


def write_sidecar(path: Path, suffix: str, payload: bytes) -> None:
    out_path = path.with_suffix(path.suffix + suffix)
    out_path.write_bytes(payload)
    print(f"[+] Wrote {len(payload)} bytes to {out_path}")


def process_tpk(path: str) -> None:
    p = Path(path)
    print(f"=== {p} ===")
    data = p.read_bytes()
    header = TpkHeader.parse(data[:HEADER_SIZE])
    print(
        f"magic=0x{header.magic:04X} version={header.version} "
        f"entries={header.entry_count} compressed={header.needs_compression()} "
        f"encrypted={header.needs_crypto()}"
    )
    print(f"metadata bytes={header.meta_size}")
    meta = data[HEADER_SIZE:HEADER_SIZE + header.meta_size]
    if len(meta) != header.meta_size:
        raise ValueError("Metadata length mismatch vs header")
    try:
        plain_meta = maybe_transform_metadata(header, meta)
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return
    describe_entries(plain_meta, header)
    write_sidecar(p, ".meta.dec", plain_meta)
    if header.needs_crypto():
        try:
            encrypted = encrypt_metadata(plain_meta)
        except RuntimeError as exc:  # pragma: no cover - optional dependency
            print(f"[!] {exc}")
        else:
            write_sidecar(p, ".meta.enc", encrypted)


def main() -> None:
    base = Path(__file__).with_name("p01")
    candidates = [base / name for name in ("c00.tpk", "d01.tpk", "g01.tpk")]
    ran_any = False
    for candidate in candidates:
        if candidate.is_file():
            ran_any = True
            process_tpk(str(candidate))
    if not ran_any:
        print("No default TPK files found. Provide a path as argument.")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            process_tpk(arg)
    else:
        main()
