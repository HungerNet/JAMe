'''Module analyzers for JAMe.'''

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
    entropy_score,
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
    extract_steghide,
    lsb_check,
    zsteg_scan,
)

__all__ = [
    'analyze_pdf',
    'caesar_detect',
    'detect_appended_zip',
    'detect_branches',
    'detect_carved_files',
    'detect_encoding',
    'detect_exif_anomalies',
    'entropy_score',
    'extract_archive',
    'extract_metadata',
    'extract_steghide',
    'extract_symbols',
    'identify_hash',
    'lsb_check',
    'run_objdump',
    'run_readelf',
    'run_strings',
    'triage_pcap',
    'xor_bruteforce',
    'zsteg_scan',
]
