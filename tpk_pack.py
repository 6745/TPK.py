#!/usr/bin/env python3
"""Work-in-progress TPK packer.

This script walks a directory tree, computes CRC32s for every resource, and
assembles a plaintext metadata blob using the recovered TPK layout. Encryption
is supported today; LZO compression will be added once we fully understand the
writer-side chunk format.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

from tpk_format import (
    HEADER_STRUCT,
    HEADER_SIZE,
    TPK_MAGIC,
    TpkEntry,
    build_metadata,
    compute_crc32,
    encrypt_metadata,
)


def _iter_resource_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def _normalize_prefix(prefix: str) -> str:
    cleaned = prefix.strip().replace("\\", "/")
    return cleaned.strip("/")


def _entry_name(prefix: str, rel_path: Path) -> str:
    rel = rel_path.as_posix()
    if prefix:
        return f"{prefix}/{rel}"
    return rel


def _collect_entries(root: Path, prefix: str) -> List[Tuple[TpkEntry, bytes]]:
    entries: List[Tuple[TpkEntry, bytes]] = []
    for file_path in _iter_resource_files(root):
        rel_path = file_path.relative_to(root)
        blob = file_path.read_bytes()
        entry_path = _entry_name(prefix, rel_path)
        crc = compute_crc32(blob)
        entry = TpkEntry(path=entry_path, crc=crc, packed_size=len(blob), offset=0)
        entries.append((entry, blob))
    if not entries:
        raise ValueError(f"No files found under {root}")
    return entries


def _preview(entries: Sequence[Tuple[TpkEntry, bytes]], limit: int = 5) -> None:
    total = len(entries)
    print(f"[*] Prepared {total} resource(s)")
    for idx, (entry, blob) in enumerate(entries[:limit]):
        print(
            f"    [{idx}] {entry.path} :: size={len(blob)} bytes, crc=0x{entry.crc:08X}"
        )
    if total > limit:
        print(f"    ... {total - limit} more")


def _build_metadata(entries: Sequence[Tuple[TpkEntry, bytes]]) -> bytes:
    return build_metadata(entries)


def _apply_encryption(metadata: bytes, encrypt: bool) -> bytes:
    if not encrypt:
        return metadata
    return encrypt_metadata(metadata)


def _write_tpk(
    output_path: Path,
    entries: Sequence[Tuple[TpkEntry, bytes]],
    *,
    encrypt: bool,
) -> None:
    meta_plain = _build_metadata(entries)
    meta_blob = _apply_encryption(meta_plain, encrypt)
    header = HEADER_STRUCT.pack(
        TPK_MAGIC,
        0x14,
        0,  # compression flag (LZO chunk writer not implemented yet)
        1 if encrypt else 0,
        len(entries),
        len(meta_blob),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(header + meta_blob)
    print(f"[+] Wrote {output_path} ({len(meta_blob) + HEADER_SIZE} bytes)")


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a plaintext TPK archive")
    parser.add_argument("input", help="Folder containing resource files")
    parser.add_argument("output", help="Destination .tpk path")
    parser.add_argument(
        "--prefix",
        default="resource",
        help="Path prefix to prepend inside the archive (default: resource)",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt metadata using the recovered AES key",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview the pack layout without writing a file",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_cli()
    args = parser.parse_args(argv)

    input_root = Path(args.input)
    if not input_root.is_dir():
        raise SystemExit(f"Input folder does not exist: {input_root}")
    output_path = Path(args.output)
    prefix = _normalize_prefix(args.prefix)

    entries = _collect_entries(input_root, prefix)
    _preview(entries)
    if args.dry_run:
        print("[!] Dry-run requested; skipping file generation")
        return

    _write_tpk(output_path, entries, encrypt=args.encrypt)


if __name__ == "__main__":
    main()
