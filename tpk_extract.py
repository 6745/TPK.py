#!/usr/bin/env python3
"""TPK + PTFF Extractor

Extracts resources from TPK pack files using the metadata layout recovered
from the game's packer. Leading "resource/" prefixes and duplicate
pack/resource/pack segments are automatically stripped so that everything
lands cleanly under the designated resource root. When a directory is
provided, every pack inside it is extracted beneath <output_dir>/resource to
keep the output tidy.

When run with ``--include-ptff`` the script also scans the source tree for
directories named ``ad``, ``ae`` or ``p02`` (configurable) and attempts to
decode the PTFF pattern blobs inside them using the ported DJMax converter.

Usage:
    python tpk_extract.py <input.tpk> <output_dir> [--include-ptff]
    python tpk_extract.py <folder> <output_dir> [--include-ptff]

Example:
    python tpk_extract.py p01/c00.tpk extracted/c00
    python tpk_extract.py p01 extracted --include-ptff
"""
from __future__ import annotations

import argparse
from collections import Counter
import os
import sys
from pathlib import Path
from typing import Iterable, Sequence, Tuple, Union

from tpk_format import (
    HEADER_SIZE,
    TpkHeader,
    compute_crc32,
    iter_entries,
    maybe_transform_metadata,
)
from ptff import convert_ptff_bytes

CRC_PROFILES: Tuple[Tuple[str, dict[str, int]], ...] = (
    ("zip", {}),  # seed=0xFFFFFFFF, final_xor=0xFFFFFFFF (default)
    ("plain", {"seed": 0, "final_xor": 0}),
)
DEFAULT_PTFF_DIRS: Tuple[str, ...] = ("ad", "ae", "p02")


def _classify_crc(entry_crc: int, unpacked: bytes, packed: bytes) -> str | None:
    for label, blob in (("unpacked", unpacked), ("packed", packed)):
        for profile, kwargs in CRC_PROFILES:
            crc = compute_crc32(blob, **kwargs)
            if crc == entry_crc:
                return f"{label}/{profile}"
    return None


def _report_crc(counter: Counter[str], mismatches: int, samples: list[Tuple[str, int]], total: int) -> None:
    if total == 0:
        return
    matched = sum(counter.values())
    detail = ", ".join(f"{label}={count}" for label, count in counter.most_common()) or "none"
    print(f"  [crc] profile hits: {detail}; mismatches={mismatches}")
    if mismatches and samples:
        for path, crc in samples:
            print(f"      mismatch sample: {path} (stored=0x{crc:08X})")


def _sanitize(name: str, fallback: str) -> str:
    cleaned = name.replace("..", "").lstrip("/\\")
    return cleaned or fallback


def _normalize_entry_path(
    name: str,
    fallback: str,
    *,
    trim_resource_prefix: bool,
    pack_name: str | None,
) -> str:
    normalized = name.replace("\\", "/")
    parts = [segment for segment in normalized.split("/") if segment]
    if trim_resource_prefix:
        while parts and parts[0].lower() == "resource":
            parts.pop(0)
    if pack_name:
        lower_pack = pack_name.lower()
        idx = 0
        while idx + 2 < len(parts):
            if (
                parts[idx].lower() == lower_pack
                and parts[idx + 1].lower() == "resource"
                and parts[idx + 2].lower() == lower_pack
            ):
                del parts[idx + 1 : idx + 3]
                continue
            idx += 1
    if not parts:
        return fallback
    return os.sep.join(parts)


def _gather_inputs(source: Path) -> Iterable[Tuple[Path, Path]]:
    if source.is_file():
        if source.suffix.lower() != ".tpk":
            raise ValueError(f"Input file must end with .tpk: {source}")
        yield source, Path()
        return
    if not source.is_dir():
        raise ValueError(f"Input path is neither file nor directory: {source}")
    candidates = sorted(p for p in source.rglob("*.tpk") if p.is_file())
    if not candidates:
        raise ValueError(f"No .tpk files found under {source}")
    for pack in candidates:
        rel = pack.relative_to(source)
        yield pack, rel.with_suffix("")


def _is_ptff_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"PTFF"
    except OSError:
        return False


def _gather_ptff_inputs(source: Path, names: Sequence[str]) -> list[Tuple[Path, Path]]:
    if not source.is_dir() or not names:
        return []
    lowered = {name.lower() for name in names}
    matches: list[Tuple[Path, Path]] = []
    seen: set[Path] = set()
    for candidate in source.rglob("*"):
        if candidate.is_dir() and candidate.name.lower() in lowered:
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            for file in sorted(candidate.rglob("*")):
                if file.is_file() and _is_ptff_file(file):
                    matches.append((file, file.relative_to(source)))
    return matches


def _extract_ptff_file(
    src_path: Path,
    rel_path: Path,
    ptff_root: Path,
    *,
    verbose: bool,
) -> bool:
    data = src_path.read_bytes()
    try:
        result = convert_ptff_bytes(data)
    except Exception as exc:
        if verbose:
            print(f"  [ptff] failed to decode {rel_path}: {exc}")
        return False
    target_rel = rel_path if rel_path.suffix else rel_path.with_suffix(".bin")
    out_path = ptff_root / target_rel
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if result.decrypted:
        out_path.write_bytes(result.data)
        status = "decoded"
    else:
        out_path.write_bytes(data)
        status = "already-plain"
    if verbose:
        print(f"  [ptff] {rel_path} -> {target_rel} ({status})")
    return True


def _process_ptff_jobs(
    jobs: Sequence[Tuple[Path, Path]],
    ptff_root: Path,
    *,
    verbose: bool,
) -> int:
    count = 0
    ptff_root.mkdir(parents=True, exist_ok=True)
    for src_path, rel_path in jobs:
        if _extract_ptff_file(src_path, rel_path, ptff_root, verbose=verbose):
            count += 1
    return count


def extract_tpk(
    tpk_path: str,
    out_root: Union[str, os.PathLike[str]],
    *,
    verbose: bool = True,
    trim_resource_prefix: bool = False,
    pack_name: str | None = None,
) -> int:
    if verbose:
        print(f"[*] Extracting {tpk_path}")
    path = Path(tpk_path)
    data = path.read_bytes()
    if len(data) < HEADER_SIZE:
        raise ValueError("File too small for TPK header")
    header = TpkHeader.parse(data[:HEADER_SIZE])
    meta = data[HEADER_SIZE:HEADER_SIZE + header.meta_size]
    if len(meta) != header.meta_size:
        raise ValueError("Metadata length mismatch vs header")
    plain_meta = maybe_transform_metadata(header, meta)
    extracted = 0
    out_root_path = Path(out_root)
    crc_hits: Counter[str] = Counter()
    crc_mismatches = 0
    crc_samples: list[Tuple[str, int]] = []
    for idx, (entry, chunk, packed_chunk) in enumerate(
        iter_entries(
            plain_meta,
            header.entry_count,
            compressed=header.needs_compression(),
            include_packed=True,
        )
    ):
        crc_label = _classify_crc(entry.crc, chunk, packed_chunk)
        if crc_label:
            crc_hits[crc_label] += 1
        else:
            crc_mismatches += 1
            if len(crc_samples) < 3:
                crc_samples.append((entry.path, entry.crc))
        safe_name = _normalize_entry_path(
            _sanitize(entry.path, f"entry_{idx:05d}"),
            f"entry_{idx:05d}",
            trim_resource_prefix=trim_resource_prefix,
            pack_name=pack_name,
        )
        out_path = out_root_path / safe_name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(chunk)
        extracted += 1
        if verbose:
            hint = ""
            head = chunk[:4]
            if head.startswith(b"\x89PNG"):
                hint = " [PNG]"
            elif head.startswith(b"DDS "):
                hint = " [DDS]"
            elif head.startswith(b"OggS"):
                hint = " [OGG]"
            elif head.startswith(b"RIFF"):
                hint = " [WAV]"
            elif head.startswith(b"<?xm"):
                hint = " [XML]"
            elif head.startswith(b"OTTO") or head.startswith(b"\x00\x01\x00\x00"):
                hint = " [TTF]"
            print(
                f"  [{extracted}/{header.entry_count}] {safe_name} "
                f"({len(chunk)} bytes){hint}"
            )
    if verbose:
        _report_crc(crc_hits, crc_mismatches, crc_samples, header.entry_count)
    if verbose:
        print(f"[+] Extracted {extracted} resources to {out_root}")
    return extracted


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="TPK file or directory to extract")
    parser.add_argument("out_dir", help="Destination folder for extracted data")
    parser.add_argument(
        "--include-ptff",
        action="store_true",
        help="Also decode PTFF blobs located in named directories (ad/ae/p02 by default)",
    )
    parser.add_argument(
        "--ptff-dirs",
        nargs="+",
        default=list(DEFAULT_PTFF_DIRS),
        metavar="DIR",
        help="Directory names to scan for PTFF blobs when --include-ptff is set (default: %(default)s)",
    )
    return parser.parse_args(argv)


def main() -> None:
    args = _parse_args(sys.argv[1:])
    source = Path(args.source)
    out_root = Path(args.out_dir)

    try:
        jobs = list(_gather_inputs(source))
    except Exception as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    multi_source = source.is_dir()
    resource_root = out_root / "resource" if multi_source else out_root
    total = 0
    for pack_path, rel_dest in jobs:
        if multi_source:
            target_root = resource_root
        else:
            target_root = out_root if rel_dest == Path() else out_root / rel_dest
        target_root.mkdir(parents=True, exist_ok=True)
        pack_hint = pack_path.stem
        try:
            extracted = extract_tpk(
                str(pack_path),
                str(target_root),
                verbose=True,
                trim_resource_prefix=True,
                pack_name=pack_hint,
            )
        except Exception as exc:  # pragma: no cover - CLI convenience
            print(f"Error while extracting {pack_path}: {exc}")
            import traceback

            traceback.print_exc()
            continue
        total += extracted

    if total == 0:
        sys.exit(1)

    print(f"[+] Completed extraction of {len(jobs)} pack(s), total files: {total}")

    if args.include_ptff and source.is_dir():
        ptff_jobs = _gather_ptff_inputs(source, args.ptff_dirs)
        if not ptff_jobs:
            print("[ptff] No PTFF files found under the requested directories.")
        else:
            ptff_root = out_root / "ptff"
            count = _process_ptff_jobs(ptff_jobs, ptff_root, verbose=True)
            print(f"[+] Decoded {count} PTFF blob(s) to {ptff_root}")

    sys.exit(0)


if __name__ == "__main__":
    main()
