'''Public API for the JAMe library.'''

import os
import shutil

from jame.core.filetype import get_file_type
from jame.core.patterns import find_pattern_tokens, match_pattern
from jame.core.utils import read_file_bytes, read_file_text, safe_run_command
from jame.modules.archive import extract_archive
from jame.modules.binary import (
    detect_branches,
    extract_symbols,
    run_objdump,
    run_readelf,
    run_strings,
)
from jame.modules.crypto import (
    caesar_detect,
    detect_encoding,
    entropy_score_for_text,
    identify_hash,
    xor_bruteforce,
)
from jame.modules.forensics import (
    analyze_pdf,
    detect_carved_files,
    extract_metadata,
    triage_pcap,
)
from jame.modules.stego import (
    detect_appended_zip,
    detect_exif_anomalies,
    lsb_check,
    zsteg_scan,
)
from jame.modules.stego import extract_steghide as _detect_steghide
from jame.results.binary_result import BinaryResult, BinwalkResult
from jame.results.crypto_result import CryptoResult
from jame.results.forensics_result import ForensicsResult
from jame.results.scan_result import ScanResult
from jame.results.solve_result import SolveResult
from jame.results.stego_result import StegoResult


class Jame:
    '''Main public API for JAMe: Just Another Method of Exploitation.'''

    def __init__(self, flag_patterns: list[str] | None = None, max_depth: int = 3, verbose: bool = False):
        '''Initialize JAMe with optional flag patterns and archive settings.'''
        self.flag_patterns = flag_patterns or ['flag{*}', 'hcr{*}', 'CTFx{*}']
        self.max_depth = max_depth
        self.verbose = verbose

    def setFlagPatterns(self, patterns: list[str]) -> None:
        '''Set the flag patterns used by automatic flag discovery.'''
        self.flag_patterns = patterns

    def setMaxDepth(self, depth: int) -> None:
        '''Set the maximum recursive archive extraction depth.'''
        self.max_depth = depth if depth > 0 else 1

    def setVerbose(self, enabled: bool) -> None:
        '''Enable or disable verbose-mode configuration.'''
        self.verbose = enabled

    def getFileType(self, path: str) -> str:
        '''Return a best-effort file type label for a path.'''
        return get_file_type(path)

    def runStrings(self, path: str) -> list[str]:
        '''Extract printable strings from a file.'''
        return run_strings(path)

    def runBinwalk(self, path: str) -> BinwalkResult:
        '''Run binwalk when installed and return its structured result.'''
        if shutil.which('binwalk') is None:
            return BinwalkResult(
                file_path=path,
                available=False,
                summary='binwalk is not installed',
                raw_output={'stderr': 'binwalk not found'},
                confidence=0.0,
            )
        code, stdout, stderr = safe_run_command(['binwalk', '-e', path], timeout=20)
        extracted: list[str] = []
        if stdout:
            for line in stdout.splitlines():
                if 'extracting' in line.lower() or 'created' in line.lower():
                    extracted.append(line.strip())
        if code == 0:
            message = 'binwalk completed successfully'
            confidence = 0.9
        else:
            message = 'binwalk returned an error'
            confidence = 0.2
        return BinwalkResult(
            file_path=path,
            available=True,
            summary=message,
            extracted=extracted,
            matches=[line.strip() for line in stdout.splitlines() if line.strip()],
            raw_output={'stdout': stdout, 'stderr': stderr, 'returncode': code},
            confidence=confidence,
        )

    def scanFile(self, path: str) -> ScanResult:
        '''Run the available triage analyzers and summarize their findings.'''
        if not os.path.exists(path):
            return ScanResult(
                file_path=path,
                file_type='missing',
                summary='Target file does not exist.',
                details={'exists': False},
                confidence=0.0,
                raw_output={'error': 'missing file'},
            )

        file_type = self.getFileType(path)
        crypto_result = self.cryptoAnalyze(path)
        binary_result = self.binaryAnalyze(path)
        stego_result = self.stegoAnalyze(path)
        forensics_result = self.forensicsAnalyze(path)

        summary = (
            f'{crypto_result.summary} | {binary_result.summary} | '
            f'{stego_result.summary} | {forensics_result.summary}'
        )
        confidence = round(
            (crypto_result.confidence + binary_result.confidence + stego_result.confidence + forensics_result.confidence) / 4,
            3,
        )
        return ScanResult(
            file_path=path,
            file_type=file_type,
            summary=summary,
            details={
                'crypto': crypto_result.to_dict(),
                'binary': binary_result.to_dict(),
                'stego': stego_result.to_dict(),
                'forensics': forensics_result.to_dict(),
            },
            confidence=confidence,
            raw_output={
                'crypto': crypto_result.raw_output,
                'binary': binary_result.raw_output,
                'stego': stego_result.raw_output,
                'forensics': forensics_result.raw_output,
            },
        )

    def findFlag(self, path: str, format: str) -> str | None:
        '''Find the first brace-wrapped candidate matching a wildcard format.'''
        text = read_file_text(path, errors='replace')
        candidates = find_pattern_tokens(text)
        if not candidates:
            return None
        for candidate in candidates:
            if match_pattern(candidate, format):
                return candidate
        for pattern in self.flag_patterns:
            for candidate in candidates:
                if match_pattern(candidate, pattern):
                    return candidate
        return None

    def autoSolve(self, path: str, **ctx) -> SolveResult:
        '''Search a file for a flag and extract supported archives.'''
        format_value = str(ctx.get('format', self.flag_patterns[0]))
        max_depth = int(ctx.get('maxDepth', self.max_depth))
        verbose = bool(ctx.get('verbose', self.verbose))
        self.setVerbose(verbose)
        self.setMaxDepth(max_depth)

        flag = self.findFlag(path, format_value)
        archive_files: list[str] = []
        if os.path.exists(path):
            archive_files = self.archiveExtract(path)

        summary = 'No flag extracted.' if flag is None else f'Flag candidate found: {flag}'
        if archive_files:
            summary += f' | extracted {len(archive_files)} archive entries'
        return SolveResult(
            file_path=path,
            summary=summary,
            flag=flag,
            confidence=0.8 if flag else 0.3,
            details={
                'format': format_value,
                'max_depth': max_depth,
                'verbose': verbose,
                'archives': archive_files,
            },
            raw_output={'flag': flag, 'archives': archive_files},
        )

    def cryptoAnalyze(self, path: str) -> CryptoResult:
        '''Analyze a file for common encodings, simple ciphers, and hashes.'''
        data = read_file_bytes(path)
        text = data.decode('utf-8', errors='replace')
        encoding = detect_encoding(text)
        xor = xor_bruteforce(data)
        caesar = caesar_detect(text)
        hash_result = identify_hash(text)
        entropy = entropy_score_for_text(data)

        summary = 'No obvious crypto patterns detected.'
        confidence = 0.1
        algorithm = 'unknown'
        if encoding['encoding']:
            summary = 'Likely encoded or obfuscated data detected.'
            confidence = max(confidence, 0.8)
            algorithm = 'encoded'
        if xor:
            summary = 'XOR-bruteforce candidates present.'
            confidence = max(confidence, 0.75)
            algorithm = 'xor'
        if caesar['best'] and caesar['best']['score'] > 0:
            summary = 'Caesar-style substitution detected.'
            confidence = max(confidence, 0.7)
            algorithm = 'caesar'
        if hash_result['hash_type'] != 'unknown':
            summary = 'Hash-like value detected.'
            confidence = max(confidence, 0.9)
            algorithm = 'hash'

        return CryptoResult(
            file_path=path,
            summary=summary,
            algorithm=algorithm,
            confidence=round(confidence, 3),
            findings={
                'encoding': encoding,
                'xor': xor[:10],
                'caesar': caesar,
                'hash': hash_result,
                'entropy': round(entropy, 3),
            },
            raw_output={
                'encoding': encoding,
                'xor': xor,
                'caesar': caesar,
                'hash': hash_result,
                'entropy': entropy,
            },
        )

    def binaryAnalyze(self, path: str) -> BinaryResult:
        '''Collect printable strings, symbols, and executable indicators.'''
        strings = run_strings(path)
        objdump = run_objdump(path)
        readelf = run_readelf(path)
        symbols = extract_symbols(path)
        branch_hits = detect_branches(path)
        summary = 'Binary-like file with no obvious anomalies.'
        confidence = 0.3
        architecture = 'unknown'
        if strings:
            summary = 'Printable strings suggest a binary or packed payload.'
            confidence = 0.7
        if readelf.get('available'):
            architecture = 'ELF-like'
        if branch_hits:
            summary = 'Control-flow instructions suggest executable logic.'
            confidence = 0.8
        return BinaryResult(
            file_path=path,
            summary=summary,
            architecture=architecture,
            confidence=round(confidence, 3),
            findings={
                'strings': strings[:50],
                'symbols': symbols[:50],
                'branches': branch_hits,
                'objdump': objdump,
                'readelf': readelf,
            },
            raw_output={
                'strings': strings,
                'objdump': objdump,
                'readelf': readelf,
                'symbols': symbols,
                'branches': branch_hits,
            },
        )

    def stegoAnalyze(self, path: str) -> StegoResult:
        '''Check a file for common steganography indicators.'''
        zsteg = zsteg_scan(path)
        lsb = lsb_check(path)
        appended_zip = detect_appended_zip(path)
        exif = detect_exif_anomalies(path)
        steghide = _detect_steghide(path)
        techniques: list[str] = []
        if zsteg['findings']:
            techniques.append('zsteg')
        if lsb['likely_lsb']:
            techniques.append('lsb')
        if appended_zip['found']:
            techniques.append('appended zip')
        if exif['anomalies']:
            techniques.append('exif')
        summary = 'No steganography signals detected.' if not techniques else 'Steganography indicators detected.'
        confidence = 0.8 if techniques else 0.1
        return StegoResult(
            file_path=path,
            summary=summary,
            confidence=round(confidence, 3),
            techniques=techniques,
            findings={
                'zsteg': zsteg,
                'lsb': lsb,
                'appended_zip': appended_zip,
                'exif': exif,
                'steghide': steghide,
            },
            raw_output={
                'zsteg': zsteg,
                'lsb': lsb,
                'appended_zip': appended_zip,
                'exif': exif,
                'steghide': steghide,
            },
        )

    def forensicsAnalyze(self, path: str) -> ForensicsResult:
        '''Collect file metadata and run PDF, PCAP, and carving checks.'''
        metadata = extract_metadata(path)
        pdf = analyze_pdf(path)
        pcap = triage_pcap(path)
        carved = detect_carved_files(path)
        findings = {'pdf': pdf, 'pcap': pcap, 'carved': carved}
        summary = 'No major forensic anomalies detected.'
        confidence = 0.2
        if carved:
            summary = 'Carved file signatures detected.'
            confidence = 0.8
        if pdf.get('valid'):
            summary = 'PDF structure looks valid.'
            confidence = max(confidence, 0.7)
        return ForensicsResult(
            file_path=path,
            summary=summary,
            confidence=round(confidence, 3),
            metadata=metadata,
            findings=findings,
            raw_output={'metadata': metadata, 'pdf': pdf, 'pcap': pcap, 'carved': carved},
        )

    def archiveExtract(self, path: str) -> list[str]:
        '''Extract supported archive contents using the configured depth limit.'''
        return extract_archive(path, max_depth=self.max_depth)

    def decodeCaesar(self, text: str, shift: int | str = 'brute') -> dict:
        '''Decode one Caesar shift or return ranked candidates for all shifts.'''
        if shift == 'brute':
            return caesar_detect(text)
        if not isinstance(shift, int):
            return {'error': "shift must be an integer or 'brute'"}
        decoded = []
        for char in text:
            if 'a' <= char <= 'z':
                decoded.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                decoded.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
            else:
                decoded.append(char)
        return {'shift': shift, 'decoded': ''.join(decoded)}


def create_jame() -> Jame:
    '''Create a JAMe instance with its default configuration.'''
    return Jame()
