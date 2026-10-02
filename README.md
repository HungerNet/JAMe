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

JAMe requires Python 3.10 or newer. From the repository root, this one-line
installer creates the virtual environment, installs JAMe, links the command
into the absolute path `$HOME/.local/bin`, and adds that directory to the
current shell and future Bash login/interactive shells:

```bash
python3 -m venv .venv && .venv/bin/pip install jame && mkdir -p "$HOME/.local/bin" && if [[ -e "$HOME/.local/bin/jame" && ! "$HOME/.local/bin/jame" -ef "$(pwd -P)/.venv/bin/jame" ]]; then printf '%s\n' 'Refusing to replace existing command at ~/.local/bin/jame' >&2; exit 1; fi && ln -sfn "$(pwd -P)/.venv/bin/jame" "$HOME/.local/bin/jame" && for rc in "$HOME/.profile" "$HOME/.bashrc"; do grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' "$rc" 2>/dev/null || printf '%s\n' 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"; done && export PATH="$HOME/.local/bin:$PATH" && jame --help
```

## CLI

From a checkout, the Bash launcher can also be run directly; it uses the active
virtual environment, the checkout's `.venv`, or `python3.10`, in that order:

```bash
./jame.sh --help
./jame.sh tests/files/solution.txt
```

The default command finds a flag and extracts supported archives. The original
path-only form remains supported:

```bash
./jame.sh tests/files/solution.txt
./jame.sh solve tests/files/solution.txt --format 'flag{*}'
```

Use `*` for any-length text and `*N` for exactly `N` characters. Repeating
unqualified asterisks does not set an exact length; for example, use `hcr{*5}`
to require five characters, not `hcr{*****}`.

Other available methods:

```bash
./jame.sh find-flag tests/files/challenge.txt --format 'hcr{*4}'
./jame.sh scan tests/files/scan.txt
./jame.sh crypto tests/files/strings.txt --verbose
./jame.sh binary tests/files/strings.txt
./jame.sh stego tests/files/strings.txt
./jame.sh forensics tests/files/strings.txt
./jame.sh archive path/to/archive.zip --max-depth 2
./jame.sh file-type tests/files/strings.txt
./jame.sh strings tests/files/strings.txt
./jame.sh binwalk path/to/file.bin
./jame.sh caesar 'Khoor' --shift 3
```

`--verbose` prints the structured result, including analyzer details and raw
output where available. `binwalk` requires the external `binwalk` utility.

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
