'''Binary analysis helpers for JAMe.'''

import re

from jame.core.utils import read_file_bytes, safe_run_command


def run_strings(path: str) -> list[str]:
    '''Return printable strings from a binary-like file.'''
    data = read_file_bytes(path)
    matches = re.findall(rb'[ -~]{4,}', data)
    return [item.decode('utf-8', errors='ignore') for item in matches]


def run_objdump(path: str) -> dict:
    '''Run objdump if present and return structured output.'''
    code, stdout, stderr = safe_run_command(['objdump', '-d', path], timeout=10)
    return {
        'available': code == 0,
        'output': stdout or stderr,
        'returncode': code,
    }


def run_readelf(path: str) -> dict:
    '''Run readelf if present and return structured output.'''
    code, stdout, stderr = safe_run_command(['readelf', '-h', path], timeout=10)
    return {
        'available': code == 0,
        'output': stdout or stderr,
        'returncode': code,
    }


def extract_symbols(path: str) -> list[str]:
    '''Extract symbol-like names from an ELF binary using readelf if available.'''
    result = run_readelf(path)
    output = result.get('output', '')
    matches = re.findall(r'\b[A-Za-z_][A-Za-z0-9_]+\b', output)
    return matches[:200]


def detect_branches(path: str) -> list[str]:
    '''Identify common branch patterns in disassembly output.'''
    result = run_objdump(path)
    output = result.get('output', '')
    patterns = [
        'call',
        'jmp',
        'jne',
        'je',
        'ret',
        'test',
        'cmp',
    ]
    hits: list[str] = []
    for pattern in patterns:
        if pattern in output:
            hits.append(pattern)
    return hits
