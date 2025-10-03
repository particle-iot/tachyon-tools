# tachyon-tools

Utilities for working with **Tachyon** images and Qualcomm-style **bundle ZIPs** (QCM6490).  
This repo currently ships a single tool:

- `bundle_partition_filter.py` — list, validate, and filter partitions/files inside a bundle ZIP while keeping `manifest.json`, patch XMLs, and Firehose loaders correct.

---

## Table of Contents

- [What’s a “bundle ZIP”?](#whats-a-bundle-zip)  
- [Highlights](#highlights)  
- [Installation](#installation)  
- [Quick Start](#quick-start)  
- [CLI Reference](#cli-reference)  
  - [`list`](#list)  
  - [`validate`](#validate)  
  - [`filter-in` / `filter-out`](#filter-in--filter-out)  
  - [Matching (slots, wildcards, case)](#matching-slots-wildcards-case)  
- [Behavior & Implementation Notes](#behavior--implementation-notes)  
- [Examples](#examples)  
- [Exit Codes](#exit-codes)  
- [Troubleshooting](#troubleshooting)  
- [Performance Tips](#performance-tips)  
- [Contributing](#contributing)  
- [License](#license)

---

## What’s a “bundle ZIP”?

A **bundle ZIP** is a flashable archive with this layout:

manifest.json
images/qcm6490/edl/
├ rawprogram*.xml         # “program” plans for partitions
├ patch*.xml             # GPT/metadata fixups
├ prog_firehose_.elf    # Firehose programmer(s)
└ image payloads         # e.g., dtbo.img, gpt_main.bin, super.img, etc.

The tool helps you **inspect** partitions, **verify** references, and **filter** the bundle while keeping it consistent for flashing.

---

## Highlights

- **List partitions** (collapsed by base/slot), with file sizes, LUN, and address.
- **Two address modes**: LUN-relative (default) or **heuristic physical** (adds a sequential LUN base offset).
- **Validate** that XML-referenced files exist and identify extras.
- **Filter** partitions in or out (OTA-style, by slot/wildcards), and:
  - **Update `manifest.json`** to reflect kept XMLs.
  - **Keep patch XMLs** and the GPT/metadata they reference.
  - **Prune unreferenced payloads**.
  - **Always keep Firehose loaders** (`prog_firehose_ddr.elf`, `prog_firehose_lite.elf`, `prog_firehose.elf`).
- **Non-fatal sanity check**: warns if `manifest.json` lists XMLs not present.

---

## Installation

```bash
git clone <your-repo-url> tachyon-tools
cd tachyon-tools
chmod +x bundle_partition_filter.py
# optional: add to PATH
# ln -s "$PWD/bundle_partition_filter.py" /usr/local/bin/bpf

Requirements: Python 3.7+; standard library only (zipfile, xml.etree, etc.).

⸻

Quick Start

List everything in a bundle:

./bundle_partition_filter.py list tachyon-ubuntu-20.04-NA-desktop-1.0.172.zip

Keep only a subset and write a new bundle:

./bundle_partition_filter.py filter-in mybundle.zip \
  --partitions system_a,boot_a,vendor \
  -o out_minimal.zip

Remove a set (wildcards OK):

./bundle_partition_filter.py filter-out mybundle.zip \
  --partitions userdata,modem* \
  -o out_no_userdata.zip

Validate:

./bundle_partition_filter.py validate out_minimal.zip


⸻

CLI Reference

list

Show partitions (from rawprogram*.xml) collapsed by base name and slot.

bundle_partition_filter.py list <bundle.zip>
  [--sort-by name|addr]
  [--partitions P1,P2,*]
  [--slot a|b]
  [--ignore-case]
  [--print-lun]
  [--use-lun-address | --use-phy-address]

	•	Columns: Base | Slot | File Size | LUN | Addr | File
	•	--sort-by addr sorts by (LUN, address).
	•	--use-phy-address shows a heuristic physical address (adds a sequential LUN base).
	•	--print-lun prints a LUN summary table before the list.

validate

Check XML ↔ EDL file consistency. Warn if manifest.json lists XMLs not present.

bundle_partition_filter.py validate <bundle.zip>
  [--allow-extra FILE1,FILE2]

	•	Returns non-zero if:
	•	Missing: XML references a file not present.
	•	Extra: A file exists but is not referenced (unless whitelisted).
	•	--allow-extra extends the default whitelist (Firehose loaders are already whitelisted).

filter-in / filter-out

Create a filtered bundle that remains flash-consistent.

bundle_partition_filter.py filter-in  <bundle.zip> --partitions P1,P2,... -o output.zip
  [--slot a|b] [--ignore-case] [--strict]

bundle_partition_filter.py filter-out <bundle.zip> --partitions P1,P2,... -o output.zip
  [--slot a|b] [--ignore-case] [--strict]

	•	filter-in keeps only the matched partitions; filter-out removes them.
	•	Rewrites manifest.json (program_xml / patch_xml) to reflect what remains.
	•	Drops any rawprogram*.xml that becomes empty after filtering.
	•	Prunes unreferenced EDL payloads (but always keeps Firehose loaders).
	•	Runs validate on the result; non-zero exit on inconsistency.
	•	--strict: if any exact name in --partitions matched nothing, exit with error.

Matching (slots, wildcards, case)
	•	Exact names by default (system_a).
	•	Wildcards via fnmatch (modem*, *_b).
	•	--slot a|b auto-matches *_a or *_b (OTA-style).
	•	--ignore-case for case-insensitive matching.

⸻

Behavior & Implementation Notes
	•	Patch XMLs are never filtered; they stay even if you remove all data partitions.
	•	Firehose loaders are always preserved, even if unreferenced by any XML:
	•	prog_firehose_ddr.elf, prog_firehose_lite.elf, prog_firehose.elf
	•	Pruning: any images/qcm6490/edl/* payload file not referenced by remaining XMLs is removed (except Firehose).
	•	Empty rawprogram XMLs are removed from the ZIP.
	•	manifest.json synchronization:
	•	program_xml/patch_xml arrays are filtered to only list XMLs that remain.
	•	Validation emits a warning (non-fatal) if manifest.json references XMLs not found in EDL.
	•	Address display:
	•	LUN-relative is the ground truth from rawprogram XML.
	•	Physical address mode adds a heuristic cumulative LUN offset for visualization only.

⸻

Examples

List only slot A, sorted by address:

./bundle_partition_filter.py list bundle.zip --slot a --sort-by addr --print-lun

Keep a minimal set for slot A:

./bundle_partition_filter.py filter-in bundle.zip \
  --partitions system_a,boot_a,vendor,dtbo_a \
  --slot a \
  -o out_slotA_min.zip

Remove user data and modem-related partitions (case-insensitive):

./bundle_partition_filter.py filter-out bundle.zip \
  --partitions userdata,modem* \
  --ignore-case \
  -o out_nodata.zip

Whitelist an extra diagnostic blob during validation:

./bundle_partition_filter.py validate out.zip --allow-extra my_diag.bin,readme.txt

Pipe to a file / use in CI:

./bundle_partition_filter.py list bundle.zip --slot b --sort-by addr > partitions.txt


⸻

Exit Codes
	•	0 — Success.
	•	3 — Validation mismatch (missing/extra EDL files after build).
	•	4 — --strict exact-partition mismatch (one or more exact names not found).
	•	Other non-zero — generic error or parse failure.

⸻

Troubleshooting

Symptom: Flash tool says Device not responding or Firehose parse error like
Entity: line 1: parser error : Start tag expected, '<' not found.
	•	Ensure the filtered ZIP still contains a Firehose loader:

unzip -l out.zip | egrep 'images/qcm6490/edl/prog_firehose.*\.elf$'

(These are always kept by the tool; if missing, re-run filter and check the whitelist logic.)

	•	Compare programmer ELF with the original bundle:

unzip -p original.zip images/qcm6490/edl/prog_firehose_ddr.elf | shasum -a 256
unzip -p out.zip       images/qcm6490/edl/prog_firehose_ddr.elf | shasum -a 256



Symptom: validate fails with missing files.
	•	A rawprogram*.xml references a payload not present. Ensure your filter didn’t remove needed files (or they’re named consistently).
	•	Use --allow-extra for benign extras; do not whitelist missing files—fix the bundle or XML.

Symptom: validate warns that manifest.json lists XMLs not in EDL.
	•	The tool rewrites manifest.json on filter; if you edited it manually or shipped a stale manifest, re-run filtering or fix the manifest.

Device handshake flakiness (outside this tool):
	•	Verify the device is truly in EDL/9008, swap USB cable/port, avoid hubs, ensure stable power, and make sure no other process holds the interface.

⸻

Performance Tips
	•	Large bundles: run from a fast disk (SSD).
	•	Avoid in-place overwrite on the first try; write to a new file so you can diff.
	•	Use selective filters (e.g., slot + a few partitions) to reduce write time.
