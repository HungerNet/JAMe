'''Archive extraction helpers for JAMe.'''

import gzip
import os
import tarfile
import zipfile


def _extract_zip(path: str, output_dir: str) -> list[str]:
    extracted: list[str] = []
    with zipfile.ZipFile(path, 'r') as archive:
        archive.extractall(output_dir)
        extracted.extend([os.path.join(output_dir, item) for item in archive.namelist()])
    return extracted


def _extract_tar(path: str, output_dir: str) -> list[str]:
    extracted: list[str] = []
    with tarfile.open(path, 'r:*') as archive:
        archive.extractall(output_dir)
        for member in archive.getmembers():
            if member.isfile():
                extracted.append(os.path.join(output_dir, member.name))
    return extracted


def _extract_gzip(path: str, output_dir: str) -> list[str]:
    target = os.path.join(output_dir, os.path.basename(path).replace('.gz', ''))
    with gzip.open(path, 'rb') as source, open(target, 'wb') as destination:
        destination.write(source.read())
    return [target]


def extract_archive(path: str, max_depth: int = 3) -> list[str]:
    '''Extract a zip/tar/gzip archive, recursively until max_depth is reached.'''
    if not os.path.isfile(path):
        return []

    output_dir = os.path.join(os.path.dirname(path), '.jame_extract')
    os.makedirs(output_dir, exist_ok=True)
    extracted: list[str] = []
    stack = [(path, 0)]
    seen: set[str] = set()

    while stack:
        current_path, depth = stack.pop()
        if current_path in seen or depth > max_depth:
            continue
        seen.add(current_path)
        lower = current_path.lower()
        if lower.endswith('.zip'):
            files = _extract_zip(current_path, output_dir)
            extracted.extend(files)
        elif lower.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz')):
            files = _extract_tar(current_path, output_dir)
            extracted.extend(files)
        elif lower.endswith('.gz') and not lower.endswith('.tar.gz'):
            files = _extract_gzip(current_path, output_dir)
            extracted.extend(files)
        for item in extracted:
            if os.path.isfile(item) and item.lower().endswith(('.zip', '.tar', '.gz')):
                stack.append((item, depth + 1))
    return extracted
