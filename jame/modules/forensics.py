'''Forensics and metadata analysis helpers for JAMe.'''

import hashlib
import os
import re


def extract_metadata(path: str) -> dict:
    '''Return basic metadata details for a supplied file.'''
    stat = os.stat(path)
    return {
        'size': stat.st_size,
        'mtime': stat.st_mtime,
        'sha256': hashlib.sha256(open(path, 'rb').read()).hexdigest(),
    }


def analyze_pdf(path: str) -> dict:
    '''Perform a lightweight PDF structure check.'''
    try:
        with open(path, 'rb') as handle:
            data = handle.read()
    except OSError:
        return {'valid': False, 'reason': 'missing file'}
    text = data.decode('latin1', errors='ignore')
    matches = {
        'header': text.startswith('%PDF'),
        'objects': len(re.findall(r'/Type /ObjStm|/Type /Catalog|/Root', text)),
        'trailer': '/Trailer' in text,
        'xref': '/XRef' in text,
    }
    return {'valid': matches['header'], 'structure': matches}


def triage_pcap(path: str) -> dict:
    '''Ground-truth PCAP triage with basic header checks.'''
    try:
        with open(path, 'rb') as handle:
            data = handle.read(24)
    except OSError:
        return {'valid': False, 'reason': 'missing file'}
    if len(data) < 24:
        return {'valid': False, 'reason': 'too small'}
    magic = data[:4]
    return {
        'valid': magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1'),
        'magic_hex': magic.hex(),
    }


def detect_carved_files(path: str) -> list[str]:
    '''Look for typical file signatures that may indicate carved content.'''
    try:
        with open(path, 'rb') as handle:
            data = handle.read()
    except OSError:
        return []
    signatures = [
        b'PK\x03\x04',
        b'%PDF',
        b'\x7fELF',
        b'\x89PNG',
        b'GIF8',
    ]
    hits: list[str] = []
    for sig in signatures:
        if sig in data:
            hits.append(sig.decode('latin1', errors='ignore'))
    return hits
