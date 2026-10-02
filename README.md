# JAMe

Just Another Method of Exploitation.

JAMe is a lightweight forensic and triage toolkit for scanning files, extracting archives, identifying likely crypto patterns, checking for stegano indicators, and surfacing candidate flags in challenge files.

## Overview

- File type detection
- Flag hunting with custom wildcard patterns
- Crypto heuristics (base64/base32/base58, XOR, Caesar, Vigenere hints, hash detection)
- Binary triage with strings, readelf, and objdump-style output
- Steganography checks for LSB, appended ZIP, EXIF anomalies, and archive-style traces
- Forensics triage for PDF, PCAP, and carved content
- Archive extraction with recursive support and depth limits

## Installation

JAMe requires Python 3.10 or newer. Install the latest published package and
register `jame` on your user PATH with:

```bash
curl -fsSL https://raw.githubusercontent.com/HungerNet/JAMe/main/install.sh | bash
```

The installer creates a dedicated environment under `$HOME/.local/share/jame`,
installs the MapRes pre-release API, `jame`, and C2E, and links the command to
`$HOME/.local/bin/jame`. It adds that directory to Bash or Zsh startup files;
open a new shell if it was not already on your current PATH.

Set `JAME_PYTHON` to select a specific Python 3.10+ executable. Set
`JAME_INSTALL_DIR` or `JAME_BIN_DIR` to change the absolute install or bin path.

## CLI

After installation, run the `jame` command from any directory:

```bash
jame --help
jame tests/files/solution.txt
```

The default command finds a flag and extracts supported archives. The explicit
`solve` form is also available:

```bash
jame tests/files/solution.txt
jame solve tests/files/solution.txt --format 'flag{*}'
```

Use `*` for any-length text and `*N` for exactly `N` characters. Repeating
unqualified asterisks does not set an exact length; for example, use `hcr{*5}`
to require five characters, not `hcr{*****}`.

Other available methods:

```bash
jame update
jame update --pre
jame find-flag tests/files/challenge.txt --format 'hcr{*4}'
jame scan tests/files/scan.txt
jame crypto tests/files/strings.txt --verbose
jame binary tests/files/strings.txt
jame stego tests/files/strings.txt
jame forensics tests/files/strings.txt
jame archive path/to/archive.zip --max-depth 2
jame file-type tests/files/strings.txt
jame strings tests/files/strings.txt
jame binwalk path/to/file.bin
jame caesar 'Khoor'
jame caesar 'Khoor' --verbose
jame caesar 'Khoor' --shift 3
```

`--verbose` prints the structured result, including analyzer details and raw
output where available. Caesar brute force prints only its highest-ranked
decoded candidate by default; `--verbose` shows the ranked candidates.
`jame update` upgrades JAMe and C2E; `jame update --pre` also upgrades MapRes
using prerelease versions. `binwalk` requires the external `binwalk` utility.

## Quickstart

### Instance API

```python
import jame

engine = jame.Jame()
result = engine.scanFile('example.bin')
print(result.summary)
```

### Module-level API

```python
import jame

result = jame.scanFile('example.bin')
print(result.summary)
```

Module-level functions use a shared singleton engine. Configuration set through
functions such as `jame.setFlagPatterns()` persists across subsequent module-level calls.

## API Reference

The camelCase API is available on `Jame` instances and as module-level functions.
Use the instance API for independent configurations, or the module-level API to
share one engine configuration.

```python
import jame

jame.scanFile('path/to/file')
jame.findFlag('path/to/file', 'hcr{*4}')
jame.autoSolve('path/to/file', format='flag{*}')
jame.cryptoAnalyze('path/to/file')
jame.binaryAnalyze('path/to/file')
jame.stegoAnalyze('path/to/file')
jame.forensicsAnalyze('path/to/file')
jame.archiveExtract('path/to/archive.zip')
jame.decodeCaesar('uryyb', 'brute')
```

## Examples

### Find a flag-like value

```python
import jame

flag = jame.findFlag('notes.txt', 'hcr{*4}')
print(flag)
```

### Run a full scan

```python
import jame

scan = jame.Jame().scanFile('challenge.bin')
print(scan.summary)
print(scan.confidence)
```

### Decode Caesar candidates

```python
import jame

result = jame.decodeCaesar('QEBJQ', 'brute') # brute is default
print(result)
```

## License

This project is licensed under the MIT License.
