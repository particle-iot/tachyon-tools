#!/usr/bin/env python3
"""
bundle_partition_filter.py

Operate on **bundles** (ZIP files) that contain:
  - manifest.json
  - images/qcm6490/edl/*.xml  (rawprogram*.xml and patch*.xml alongside image files like dtbo.img)

Commands:
  - list        : Show partitions (collapsed), total file size, min start address, and file(s).
  - validate    : Verify that every file referenced by rawprogram or patch XML exists in EDL, and that
                  there are no extra files present (with a whitelist for common Firehose loaders).
  - filter-in   : Keep ONLY the listed partitions (or slot), rewrite XMLs, and remove unreferenced EDL files.
  - filter-out  : REMOVE the listed partitions (or slot), rewrite XMLs, and remove now-unreferenced EDL files.

Matching:
  - Exact by default; supports wildcards in --partitions (fnmatch), and --slot a|b for *_a / *_b.
  - --ignore-case for case-insensitive matches.

Listing:
  - Skips patch*.xml.
  - Collapses duplicates by partition.
  - Size prefers actual file size in bundle; falls back to sector math; then size_in_kb.
  - Address best-effort: start_byte_hex or start_sector × sector_size (default 512).
"""

import argparse
import fnmatch
import io
import os
import re
import sys
import zipfile
from xml.etree import ElementTree as ET
from typing import Dict, Iterable, List, Optional, Set, Tuple

# Bundle layout constants
EDL_DIR = "images/qcm6490/edl/"

RAWPROGRAM_RE = re.compile(r'(^|/)(rawprogram.*)\.xml$', re.IGNORECASE)
PATCH_RE      = re.compile(r'(^|/)(patch.*)\.xml$', re.IGNORECASE)

PROGRAM_TAGS = {"program"}    # rawprogram*.xml
PATCH_TAGS   = {"patch"}      # patch*.xml (GPT fixups)
ERASE_TAGS   = {"erase"}      # rawprogram_unsparse*.xml contain <erase ...>

PARTITION_ATTR_CANDIDATES = ["label", "partition", "partition_name", "label_name"]

ATTR_NUM_SECTORS   = "num_partition_sectors"
ATTR_SECTOR_BYTES  = "SECTOR_SIZE_IN_BYTES"
ATTR_SIZE_KB       = "size_in_kb"

DEFAULT_EXTRA_WHITELIST = {
    "prog_firehose_ddr.elf",
    "prog_firehose_lite.elf",
    "prog_firehose.elf",
}

# ----------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------

def human_bytes(n: Optional[int]) -> str:
    if n is None:
        return "N/A"
    units = ["B","KB","MB","GB","TB","PB"]
    i = 0
    v = float(n)
    while v >= 1024.0 and i < len(units)-1:
        v /= 1024.0
        i += 1
    return f"{v:.2f} {units[i]}" if i > 0 else f"{int(v)} {units[i]}"

def parse_xml(xml_bytes: bytes) -> ET.ElementTree:
    return ET.ElementTree(ET.fromstring(xml_bytes))

def iter_bundle_xml_entries(zf: zipfile.ZipFile) -> Iterable[Tuple[str, bytes]]:
    for info in zf.infolist():
        name = info.filename
        if not name.startswith(EDL_DIR):
            continue
        if RAWPROGRAM_RE.search(name) or PATCH_RE.search(name):
            with zf.open(info, "r") as f:
                yield name, f.read()

def collect_zip_sizes(zf: zipfile.ZipFile) -> Dict[str, int]:
    return {info.filename: info.file_size for info in zf.infolist()}

def find_partition_name(attrs: Dict[str, str]) -> Optional[str]:
    lower = {k.lower(): v for k, v in attrs.items()}
    for cand in PARTITION_ATTR_CANDIDATES:
        if cand.lower() in lower:
            return lower[cand.lower()]
    return None

def compute_program_size_bytes(attrs: Dict[str, str], zip_sizes: Dict[str, int]) -> Optional[int]:
    lower = {k.lower(): v for k, v in attrs.items()}
    fname = lower.get("filename") or lower.get("file_name")
    if fname:
        edl_path = EDL_DIR + os.path.basename(fname)
        if edl_path in zip_sizes:
            return zip_sizes[edl_path]
        base = os.path.basename(fname)
        for zname, zsize in zip_sizes.items():
            if os.path.basename(zname) == base:
                return zsize
    try:
        ns = int(lower.get(ATTR_NUM_SECTORS, ""))
        sb = int(lower.get(ATTR_SECTOR_BYTES, ""))
        if ns > 0 and sb > 0:
            return ns * sb
    except ValueError:
        pass
    try:
        kb = int(lower.get(ATTR_SIZE_KB, ""))
        if kb > 0:
            return kb * 1024
    except ValueError:
        pass
    return None

def extract_referenced_files_from_rawprogram(tree: ET.ElementTree) -> Set[str]:
    ref: Set[str] = set()
    root = tree.getroot()
    for elem in root.iter():
        if elem.tag in PROGRAM_TAGS:
            fname = elem.attrib.get("filename") or elem.attrib.get("file_name")
            if fname:
                ref.add(os.path.basename(fname))
    return ref

def extract_referenced_files_from_patches(tree: ET.ElementTree) -> Set[str]:
    ref: Set[str] = set()
    root = tree.getroot()
    for elem in root.iter():
        if elem.tag in PATCH_TAGS:
            fname = elem.attrib.get("filename")
            if fname and fname.upper() != "DISK":
                ref.add(os.path.basename(fname))
    return ref

def _parse_start_address(attrs: Dict[str, str]) -> Optional[int]:
    lower = {k.lower(): v for k, v in attrs.items()}
    sb_hex = lower.get("start_byte_hex") or lower.get("start_byte")
    if sb_hex:
        try:
            return int(sb_hex, 0)
        except ValueError:
            pass
    try:
        start_sector = int(lower.get("start_sector", ""))
    except ValueError:
        start_sector = None
    try:
        sector_bytes = int(lower.get("sector_size_in_bytes", ""))
    except ValueError:
        sector_bytes = None
    if start_sector is not None:
        return start_sector * (sector_bytes or 512)
    return None

# ----------------------------------------------------------------------
# list
# ----------------------------------------------------------------------

def _split_slot(part: str) -> Tuple[str, str]:
    """Return (base, slot) where slot is 'A', 'B', or '—'."""
    if part.endswith("_a"):
        return part[:-2], "A"
    if part.endswith("_b"):
        return part[:-2], "B"
    return part, "—"

def list_partitions(bundle_zip: str, sort_by: str = "name",
                    parts: Optional[Set[str]] = None,
                    slot: Optional[str] = None,
                    ignore_case: bool = False) -> int:
    """
    List partitions from rawprogram XMLs only, optionally filtered like OTA:
      - parts: exact/wildcard partition filters (e.g., system_a,*_b)
      - slot:  'a' or 'b' to select *_a / *_b
      - ignore_case: case-insensitive matching

    Columns: Base | Slot | File Size | Addr | File
      - File Size: sum of sizes of unique referenced files for that (base,slot)
      - Addr: min start address (hex) across entries, 'N/A' if unknown
      - File: single basename if exactly one file; else '(N files)'
    """
    with zipfile.ZipFile(bundle_zip, "r") as zf:
        zip_sizes = collect_zip_sizes(zf)

        # Optional matcher (same semantics as filter-in/out)
        parts = parts or set()
        matcher = build_matcher(parts, ignore_case=ignore_case, slot=slot)

        # (base,slot) -> { files:set, total_size:int, addr_min:Optional[int] }
        agg: Dict[Tuple[str, str], Dict[str, object]] = {}

        for name, data in iter_bundle_xml_entries(zf):
            if PATCH_RE.search(name):
                continue  # list view ignores patch xmls

            try:
                tree = parse_xml(data)
            except ET.ParseError as e:
                print(f"[WARN] Skipping unparsable XML: {name}: {e}", file=sys.stderr)
                continue

            for elem in tree.getroot().iter():
                if elem.tag not in PROGRAM_TAGS:
                    continue

                part = find_partition_name(elem.attrib)
                if not part:
                    continue

                # Apply OTA-style filter (if any)
                if parts or slot:
                    if not matcher(part):
                        continue

                base_name, slot_tag = _split_slot(part)

                lower = {k.lower(): v for k, v in elem.attrib.items()}
                fname = lower.get("filename") or lower.get("file_name") or ""
                file_base = os.path.basename(fname) if fname else ""

                # Prefer actual file size from the bundle
                size_b = 0
                if file_base:
                    edl_path = EDL_DIR + file_base
                    if edl_path in zip_sizes:
                        size_b = zip_sizes[edl_path]
                    else:
                        for zname, zsize in zip_sizes.items():
                            if os.path.basename(zname) == file_base:
                                size_b = zsize
                                break

                addr_b = _parse_start_address(elem.attrib)

                key = (base_name, slot_tag)
                rec = agg.setdefault(key, {"files": set(), "total_size": 0, "addr_min": None})
                files: Set[str] = rec["files"]  # type: ignore
                if file_base and file_base not in files:
                    files.add(file_base)
                    rec["total_size"] = int(rec["total_size"]) + (size_b or 0)  # type: ignore
                if addr_b is not None:
                    if rec["addr_min"] is None or addr_b < rec["addr_min"]:  # type: ignore
                        rec["addr_min"] = addr_b  # type: ignore

        if not agg:
            print("No partitions found in rawprogram XMLs.")
            return 0

        # Build rows for printing
        rows = []
        for (base_name, slot_tag), rec in agg.items():
            files: Set[str] = rec["files"]  # type: ignore
            total_size = rec["total_size"]  # type: ignore
            addr_min = rec["addr_min"]      # type: ignore
            if len(files) == 0:
                file_display = ""
            elif len(files) == 1:
                file_display = next(iter(files))
            else:
                file_display = f"({len(files)} files)"
            rows.append((base_name, slot_tag, total_size, addr_min, file_display))

        # Sorting
        if sort_by == "addr":
            rows.sort(key=lambda r: (r[3] is None, r[3] if r[3] is not None else 1 << 64))
        else:
            # name: Base asc, then Slot order A,B,—
            slot_order = {"A": 0, "B": 1, "—": 2}
            rows.sort(key=lambda r: (r[0], slot_order.get(r[1], 3), r[4]))

        # Column widths
        size_strs = [human_bytes(r[2]) for r in rows]
        addr_strs = [f"0x{r[3]:016X}" if isinstance(r[3], int) else "N/A" for r in rows]

        col_base = max(len("Base"), max(len(r[0]) for r in rows))
        col_slot = max(len("Slot"), max(len(r[1]) for r in rows))
        col_size = max(len("File Size"), max(len(s) for s in size_strs))
        col_addr = max(len("Addr"), max(len(s) for s in addr_strs))
        col_file = max(len("File"), max(len(r[4]) for r in rows))

        # Print
        print(f"{'Base'.ljust(col_base)}  {'Slot'.ljust(col_slot)}  {'File Size'.ljust(col_size)}  {'Addr'.ljust(col_addr)}  {'File'.ljust(col_file)}")
        print(f"{'-'*col_base}  {'-'*col_slot}  {'-'*col_size}  {'-'*col_addr}  {'-'*col_file}")
        for (base_name, slot_tag, total_size, addr_min, file_display), size_s, addr_s in zip(rows, size_strs, addr_strs):
            print(f"{base_name.ljust(col_base)}  {slot_tag.ljust(col_slot)}  {size_s.ljust(col_size)}  {addr_s.ljust(col_addr)}  {file_display.ljust(col_file)}")

    return 0

# ----------------------------------------------------------------------
# validate
# ----------------------------------------------------------------------

def validate_bundle(bundle_zip: str, allow_extra: Optional[Set[str]] = None) -> int:
    allow_extra = allow_extra or set()
    with zipfile.ZipFile(bundle_zip, "r") as zf:
        edl_present: Set[str] = {
            os.path.basename(info.filename)
            for info in zf.infolist()
            if info.filename.startswith(EDL_DIR)
            and not (RAWPROGRAM_RE.search(info.filename) or PATCH_RE.search(info.filename))
            and os.path.basename(info.filename)
        }
        referenced: Set[str] = set()
        for name, data in iter_bundle_xml_entries(zf):
            try:
                tree = parse_xml(data)
            except ET.ParseError as e:
                print(f"[WARN] Skipping unparsable XML: {name}: {e}", file=sys.stderr)
                continue
            if RAWPROGRAM_RE.search(name):
                referenced |= extract_referenced_files_from_rawprogram(tree)
            elif PATCH_RE.search(name):
                referenced |= extract_referenced_files_from_patches(tree)
        extra_whitelist = set(DEFAULT_EXTRA_WHITELIST) | set(allow_extra)
        missing = referenced - edl_present
        extra   = {e for e in (edl_present - referenced) if e not in extra_whitelist}
        if not missing and not extra:
            print("Validation OK: Referenced files match EDL directory.")
            return 0
        if missing:
            print("Missing files referenced by XML:")
            for m in sorted(missing):
                print(f"  - {m}")
        if extra:
            print("Extra files present not referenced by XML:")
            for e in sorted(extra):
                print(f"  - {e}")
        return 3

# ----------------------------------------------------------------------
# filtering (patch*.xml are always kept)
# ----------------------------------------------------------------------

def build_matcher(parts: Set[str], ignore_case: bool, slot: Optional[str]):
    patterns = [p for p in parts if any(ch in p for ch in "*?[]")]
    exacts   = parts - set(patterns)
    if ignore_case:
        exacts_lc = {p.lower() for p in exacts}
        patterns_lc = [p.lower() for p in patterns]
        suffix = f"_{slot}".lower() if slot else None
        def pred(pname: Optional[str]) -> bool:
            if not pname:
                return False
            pn = pname.lower()
            if pn in exacts_lc:
                return True
            if any(fnmatch.fnmatch(pn, pat) for pat in patterns_lc):
                return True
            if suffix and pn.endswith(suffix):
                return True
            return False
    else:
        suffix = f"_{slot}" if slot else None
        def pred(pname: Optional[str]) -> bool:
            if not pname:
                return False
            if pname in exacts:
                return True
            if any(fnmatch.fnmatch(pname, pat) for pat in patterns):
                return True
            if suffix and pname.endswith(suffix):
                return True
            return False
    return pred

def filter_xml_bytes(xml_bytes: bytes, mode: str, parts: Set[str], ignore_case: bool, slot: Optional[str]) -> Tuple[bytes, Set[str], bool, Set[str]]:
    """
    Filter <program> and <erase> elements per mode. PATCH ELEMENTS ARE NEVER FILTERED.
    Returns: (new_xml_bytes, referenced_files_after_filter, is_empty_rawprogram, matched_partitions)
      - referenced_files_after_filter: basenames from remaining <program filename="...">
      - is_empty_rawprogram: True if this was a rawprogram XML and no <program> or <erase> remain
      - matched_partitions: set of partition names that matched the filter predicate
    """
    tree = parse_xml(xml_bytes)
    root = tree.getroot()
    is_match = build_matcher(parts, ignore_case=ignore_case, slot=slot)
    to_remove: List[Tuple[ET.Element, ET.Element]] = []
    matched_parts: Set[str] = set()
    for parent in root.iter():
        for child in list(parent):
            if child.tag in PROGRAM_TAGS or child.tag in ERASE_TAGS:
                pname = find_partition_name(child.attrib)
                if pname and is_match(pname):
                    matched_parts.add(pname)
                rm = (mode == "in" and not is_match(pname)) or (mode == "out" and is_match(pname))
                if rm:
                    to_remove.append((parent, child))
            # PATCH tags are never filtered
    for parent, child in to_remove:
        parent.remove(child)
    referenced_after: Set[str] = set()
    has_prog_or_erase = False
    for elem in root.iter():
        if elem.tag in PROGRAM_TAGS or elem.tag in ERASE_TAGS:
            has_prog_or_erase = True
        if elem.tag in PROGRAM_TAGS:
            fname = elem.attrib.get("filename") or elem.attrib.get("file_name")
            if fname:
                referenced_after.add(os.path.basename(fname))
    out = io.BytesIO()
    tree.write(out, encoding="utf-8", xml_declaration=True)
    is_empty_rawprogram = not has_prog_or_erase
    return out.getvalue(), referenced_after, is_empty_rawprogram, matched_parts

def rewrite_bundle_with_filter(src_zip: str, dst_zip: str, mode: str, parts: Set[str], ignore_case: bool, slot: Optional[str], strict: bool) -> None:
    try:
        if os.path.exists(dst_zip):
            os.remove(dst_zip)
    except OSError:
        pass
    all_matched: Set[str] = set()
    with zipfile.ZipFile(src_zip, "r") as zin:
        referenced_after_all: Set[str] = set()
        xml_modified: Dict[str, bytes] = {}
        xml_empty: Set[str] = set()
        for name, data in iter_bundle_xml_entries(zin):
            if PATCH_RE.search(name):
                # Always keep patch xmls, but include their referenced files in pruning
                try:
                    t = parse_xml(data)
                    referenced_after_all |= extract_referenced_files_from_patches(t)
                except ET.ParseError:
                    pass
                continue
            try:
                data_new, refs_after, is_empty_raw, matched = filter_xml_bytes(
                    data, mode=mode, parts=parts, ignore_case=ignore_case, slot=slot
                )
                xml_modified[name] = data_new
                if is_empty_raw:
                    xml_empty.add(name)
                if RAWPROGRAM_RE.search(name):
                    referenced_after_all |= refs_after
                all_matched |= matched
            except ET.ParseError:
                pass
        if parts:
            exacts = {p for p in parts if not any(ch in p for ch in "*?[]")}
            unmatched = {e for e in exacts if (e not in all_matched)}
            if unmatched:
                msg = "Warning: the following exact partition names matched nothing: " + ", ".join(sorted(unmatched))
                if strict:
                    print(msg, file=sys.stderr)
                    sys.exit(4)
                else:
                    print(msg, file=sys.stderr)
        with zipfile.ZipFile(dst_zip, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zout:
            written: Set[str] = set()
            for info in zin.infolist():
                name = info.filename
                if name.endswith("/"):
                    continue
                if name in xml_empty:
                    continue
                data = zin.read(info)
                if name in xml_modified:
                    data = xml_modified[name]
                if name.startswith(EDL_DIR) and not (RAWPROGRAM_RE.search(name) or PATCH_RE.search(name)):
                    base = os.path.basename(name)
                    if base and base not in referenced_after_all:
                        continue
                if name in written:
                    continue
                zout.writestr(name, data)
                written.add(name)
        rc = validate_bundle(dst_zip)
        if rc != 0:
            print("[ERROR] New bundle failed validation. See messages above.", file=sys.stderr)
            sys.exit(rc)

# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Filter/list/validate partitions in a bundle ZIP (images/qcm6490/edl)."
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("bundle", help="Path to the bundle ZIP file")

    # list
    sp_list = sub.add_parser("list", help="List partitions (collapsed) from rawprogram XMLs")
    add_common(sp_list)
    sp_list.add_argument(
        "--sort-by", choices=["name", "addr"], default="name",
        help="Sort results by partition name or by start address"
    )
    sp_list.add_argument(
        "--partitions", default="",
        help="Comma-separated partition names/wildcards to LIST (e.g. system_a,*_b)"
    )
    sp_list.add_argument(
        "--slot", choices=["a", "b"],
        help="Restrict list to *_a or *_b"
    )
    sp_list.add_argument(
        "--ignore-case", action="store_true",
        help="Case-insensitive partition name matching"
    )

    # validate
    sp_val = sub.add_parser("validate", help="Check referenced EDL files match actual files in the bundle")
    add_common(sp_val)
    sp_val.add_argument(
        "--allow-extra",
        help="Comma-separated basenames in EDL to ignore (whitelist)"
    )

    # filter-in
    sp_in = sub.add_parser("filter-in", help="Keep ONLY the listed partitions; remove unreferenced EDL files")
    add_common(sp_in)
    sp_in.add_argument("--partitions", default="", help="Comma-separated partition names/wildcards to KEEP")
    sp_in.add_argument("--slot", choices=["a","b"])
    sp_in.add_argument("-o", "--output", required=True, help="Path to write the new filtered bundle ZIP")
    sp_in.add_argument("--ignore-case", action="store_true")
    sp_in.add_argument("--strict", action="store_true")

    # filter-out
    sp_out = sub.add_parser("filter-out", help="REMOVE the listed partitions; remove now-unreferenced EDL files")
    add_common(sp_out)
    sp_out.add_argument("--partitions", default="", help="Comma-separated partition names/wildcards to REMOVE")
    sp_out.add_argument("--slot", choices=["a","b"])
    sp_out.add_argument("-o", "--output", required=True, help="Path to write the new filtered bundle ZIP")
    sp_out.add_argument("--ignore-case", action="store_true")
    sp_out.add_argument("--strict", action="store_true")

    args = ap.parse_args(argv)

    if args.cmd == "list":
        parts = set(s for s in (args.partitions or "").split(",") if s)
        return list_partitions(
            args.bundle,
            sort_by=args.sort_by,
            parts=parts,
            slot=getattr(args, "slot", None),
            ignore_case=getattr(args, "ignore_case", False),
        )

    if args.cmd == "validate":
        allow_extra = set(s for s in (args.allow_extra or "").split(",") if s) if args.allow_extra else None
        return validate_bundle(args.bundle, allow_extra=allow_extra)

    # filter-in/out
    parts = set(s for s in (args.partitions or "").split(",") if s)
    slot = getattr(args, "slot", None)
    mode = "in" if args.cmd == "filter-in" else "out"
    rewrite_bundle_with_filter(
        args.bundle, args.output, mode=mode,
        parts=parts, ignore_case=getattr(args, "ignore_case", False),
        slot=slot, strict=getattr(args, "strict", False)
    )
    print("Validation OK: Referenced files match EDL directory.")
    print(f"Wrote: {args.output}")
    return 0

if __name__ == "__main__":
    sys.exit(main())