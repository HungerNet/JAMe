'''File type helpers for JAMe.'''

import os


def detect_file_type_from_bytes(data: bytes) -> str:
    '''Return a best-effort file type label from the file header.'''
    if len(data) >= 4 and data[:4] == b'\x7fELF':
        return 'ELF binary'
    if data.startswith(b'PK'):
        return 'ZIP archive'
    if data.startswith(b'\x1f\x8b'):
        return 'GZIP compressed data'
    if data.startswith(b'%PDF'):
        return 'PDF document'
    if data.startswith(b'\x89PNG'):
        return 'PNG image'
    if data.startswith(b'GIF8'):
        return 'GIF image'
    if data.startswith(b'RIFF') and data[8:12] == b'WAVE':
        return 'WAV audio'
    if data.startswith(b'\xff\xd8\xff'):
        return 'JPEG image'
    if data.startswith(b'#!'):
        return 'script'
    return 'unknown binary'


def get_file_type(path: str) -> str:
    '''Return a string label for a file based on extension and file header.'''
    if not os.path.exists(path):
        return 'missing'

    _, ext = os.path.splitext(path)
    ext = ext.lower()
    lookup = {
        '.zip': 'ZIP archive',
        '.jar': 'JAR archive',
        '.tar': 'TAR archive',
        '.gz': 'GZIP archive',
        '.bz2': 'BZIP2 archive',
        '.xz': 'XZ archive',
        '.pdf': 'PDF document',
        '.png': 'PNG image',
        '.jpg': 'JPEG image',
        '.jpeg': 'JPEG image',
        '.gif': 'GIF image',
        '.pcap': 'PCAP capture',
        '.pcapng': 'PCAPNG capture',
        '.exe': 'PE binary',
        '.dll': 'DLL binary',
        '.so': 'shared object',
        '.bin': 'binary blob',
        '.txt': 'text file',
        '.csv': 'CSV file',
        '.py': 'Python source',
        '.html': 'HTML document',
        '.json': 'JSON document',
        '.xml': 'XML document',
    }
    if ext in lookup:
        return lookup[ext]

    try:
        with open(path, 'rb') as handle:
            data = handle.read(256)
    except OSError:
        return 'unknown'
    return detect_file_type_from_bytes(data)
