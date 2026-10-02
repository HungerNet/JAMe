'''Miscellaneous helpers used by JAMe.'''

import hashlib
import math
import os
import re
import subprocess
from pathlib import Path


def read_file_bytes(path: str) -> bytes:
    '''Read bytes from a file.'''
    with open(path, 'rb') as handle:
        return handle.read()


def read_file_text(path: str, errors: str = 'replace') -> str:
    '''Read a file as text.'''
    with open(path, 'r', encoding='utf-8', errors=errors) as handle:
        return handle.read()


def safe_run_command(command: list[str], timeout: int = 15) -> tuple[int, str, str]:
    '''Run an external command safely and capture output.'''
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout, completed.stderr
    except FileNotFoundError:
        return 127, '', 'command not found'
    except subprocess.TimeoutExpired:
        return 124, '', 'command timed out'


def entropy_score(data: bytes) -> float:
    '''Compute Shannon entropy for a byte string.'''
    if not data:
        return 0.0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def sha256_hex(data: bytes) -> str:
    '''Return the SHA256 hex digest of the supplied data.'''
    return hashlib.sha256(data).hexdigest()


def strip_ansi(value: str) -> str:
    '''Remove ANSI escape sequences from output.'''
    return re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', value)


def file_exists(path: str) -> bool:
    '''Return whether a path exists and is a file.'''
    return os.path.isfile(path)


def ensure_directory(path: str) -> str:
    '''Create a directory if needed and return the path.'''
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return str(directory)
