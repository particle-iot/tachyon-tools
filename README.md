# tachyon-tools

Tools for use with Tachyon. 

Features:
(a) toolkit for filtering and inspecting partitions inside *bundle* ZIPs (for QTI images).  

Provides a `bundle_partition_filter.py` script to **list**, **validate**, **filter-in**, and **filter-out** partitions and their associated files in a bundle.

---

## Table of Contents

- [Overview](#overview)  
- [Features](#features)  
- [Requirements](#requirements)  
- [Installation / Setup](#installation--setup)  
- [Usage](#usage)  
  - `list`  
  - `validate`  
  - `filter-in` / `filter-out`  
  - OTA-style filtering (slots, wildcards)  
- [Examples](#examples)  
- [Behavior & Notes](#behavior--notes)  
- [Contributing](#contributing)  
- [License](#license)

---

## Overview

(a) bundle tool is designed to help you work with **bundle ZIPs** that include Qualcomm device images in the layout:

manifest.json
images/qcm6490/edl/
├ rawprogram*.xml
├ patch*.xml
└ image files (e.g. dtbo.img, gpt_mainX.bin, etc.)

The core use case is to **strip out unwanted partitions** (or only keep a subset) from the bundle, while keeping JSON/XML consistency, patch files, and GPT metadata intact.

---

## Features

- **List** partitions, along with size, address, and file references.  
- **Validate** that XML references match actual EDL files (and detect missing/extra).  
- **Filter-in / Filter-out** mode: keep or remove specific partitions.  
- Support for **OTA-style filtering**: slot `a`/`b`, wildcard matches, case-insensitive matching.  
- Automatically handles patch metadata files (e.g. GPT header updates).  
- Safely prunes image files no longer referenced.

---

## Requirements

- Python 3.7+  
- Standard library only (uses `zipfile`, `xml.etree`, `argparse`, `fnmatch`)  
- (Optional) For large bundles, ensure enough memory / disk space for zip operations

---

## Installation / Setup

Simply clone this repository:

```bash
git clone <your-repo-url> tachyon-tools
cd tachyon-tools

Make sure bundle_partition_filter.py is executable:

chmod +x bundle_partition_filter.py

You can then run it via:

./bundle_partition_filter.py <command> [options]

or via:

python3 bundle_partition_filter.py <command> [options]

⸻

Usage

list

List partitions defined in rawprogram*.xml.

bundle_partition_filter.py list <bundle.zip> [--sort-by name|addr] [--partitions P1,P2,*] [--slot a|b] [--ignore-case]

	•	--sort-by: sort by partition name (default) or start address
	•	--partitions: comma-separated names or wildcard patterns to include in the listing
	•	--slot: restrict to partitions ending in _a or _b
	•	--ignore-case: perform case-insensitive matching

validate

Check consistency between XML references and EDL files:

bundle_partition_filter.py validate <bundle.zip> [--allow-extra FILE1,FILE2]

	•	Reports missing or extra files
	•	--allow-extra: whitelist certain filenames (e.g. Firehose loaders) that are okay to ignore

filter-in / filter-out

Create a new filtered bundle ZIP:

bundle_partition_filter.py filter-in <bundle.zip> --partitions P1,P2,... [-o output.zip] [--slot a|b] [--ignore-case] [--strict]
bundle_partition_filter.py filter-out <bundle.zip> --partitions P1,P2,... [-o output.zip] [--slot a|b] [--ignore-case] [--strict]

	•	filter-in: keep only the specified partitions
	•	filter-out: remove the specified partitions
	•	-o / --output: required target ZIP path
	•	--slot: filter all partitions _a or _b automatically
	•	--ignore-case: case-insensitive matching
	•	--strict: error (non-zero exit) if an exact partition name didn’t match anything

⸻

Examples

# List everything
python3 bundle_partition_filter.py list mybundle.zip

# List only slot A partitions, sorted by address
python3 bundle_partition_filter.py list mybundle.zip --slot a --sort-by addr

# Validate a bundle
python3 bundle_partition_filter.py validate mybundle.zip

# Keep only system_a, boot_a, vendor partitions
python3 bundle_partition_filter.py filter-in mybundle.zip --partitions system_a,boot_a,vendor -o out.zip

# Remove modem and userdata partitions (wildcard)
python3 bundle_partition_filter.py filter-out mybundle.zip --partitions modem*,userdata -o stripped.zip


⸻

Behavior & Notes
	•	Patch XMLs (e.g. patch6.xml) are never deleted; their referenced GPT metadata files (e.g. gpt_main*.bin, gpt_backup*.bin) are preserved if referenced.
	•	The script supports OTA-style filtering, so specifying --slot b will match all partitions ending in _b.
	•	If after filtering a rawprogram*.xml becomes empty (i.e. no <program> or <erase> entries), it is omitted from the output.
	•	Validation occurs after writing a filtered bundle; if it fails, the script exits with an error.
	•	You can pass the same ZIP to -o to overwrite in-place (though backups are recommended).

⸻

Contributing

Contributions are welcome! To contribute:
	1.	Fork the repository
	2.	Create a feature branch: git checkout -b feature/xyz
	3.	Make changes, add tests (if applicable)
	4.	Commit and push
	5.	Open a Pull Request, describing your changes

Please ensure any additions maintain script robustness, handle edge cases (e.g. missing attributes), and preserve backwards compatibility.
