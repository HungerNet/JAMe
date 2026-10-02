'''Result dataclasses for JAMe.'''

from jame.results.binary_result import BinaryResult, BinwalkResult
from jame.results.crypto_result import CryptoResult
from jame.results.forensics_result import ForensicsResult
from jame.results.scan_result import ScanResult
from jame.results.solve_result import SolveResult
from jame.results.stego_result import StegoResult

__all__ = [
    'BinaryResult',
    'BinwalkResult',
    'CryptoResult',
    'ForensicsResult',
    'ScanResult',
    'SolveResult',
    'StegoResult',
]
