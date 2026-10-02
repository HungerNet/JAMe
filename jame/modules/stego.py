'''Steganography helpers for JAMe.'''

import re

from jame.core.utils import read_file_bytes, safe_run_command


def zsteg_scan(path: str) -> dict:
    '''Perform a lightweight zsteg-inspired scan on raw bytes.'''
    data = read_file_bytes(path)
    findings = []
    if b'PK' in data:
        findings.append('ZIP signature found in stream')
    if b'JFIF' in data or b'Exif' in data:
        findings.append('image metadata block present')
    if b'\x00\x01\x00\x00' in data:
        findings.append('low-bit pattern candidate in payload')
    return {'available': True, 'findings': findings}


def extract_steghide(path: str) -> dict:
    '''Attempt a steghide extraction if the tool is installed.'''
    code, stdout, stderr = safe_run_command(['steghide', 'extract', '-sf', path, '-p', ''], timeout=10)
    return {
        'available': code == 0,
        'stdout': stdout,
        'stderr': stderr,
        'returncode': code,
    }


def lsb_check(path: str) -> dict:
    '''Perform a simple LSB analysis on file bytes.'''
    data = read_file_bytes(path)
    bits = [byte & 1 for byte in data[:2048]]
    ones = sum(bits)
    return {
        'ones': ones,
        'ratio': round(ones / max(len(bits), 1), 4),
        'likely_lsb': ones / max(len(bits), 1) > 0.45,
    }


def detect_appended_zip(path: str) -> dict:
    '''Look for a ZIP signature appended near the end of a file.'''
    data = read_file_bytes(path)
    index = data.rfind(b'PK')
    return {
        'found': index != -1,
        'offset': index,
        'size': len(data) - index,
    }


def detect_exif_anomalies(path: str) -> dict:
    '''Check for suspicious EXIF or metadata markers.'''
    data = read_file_bytes(path)
    anomalies = []
    if b'Exif' in data:
        anomalies.append('EXIF metadata present')
    if data.startswith(b'\x89PNG'):
        anomalies.append('PNG image; metadata may be embedded')
    if re.search(rb'JFIF|Photoshop', data[:8192]):
        anomalies.append('image metadata strings found')
    return {'anomalies': anomalies, 'count': len(anomalies)}
