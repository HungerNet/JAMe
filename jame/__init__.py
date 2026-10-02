'''JAMe package.'''

from jame.core.jame import Jame, create_jame
from jame.results.binary_result import BinaryResult, BinwalkResult
from jame.results.crypto_result import CryptoResult
from jame.results.forensics_result import ForensicsResult
from jame.results.scan_result import ScanResult
from jame.results.solve_result import SolveResult
from jame.results.stego_result import StegoResult

__version__ = '0.1.0'
_engine = Jame()


def scanFile(path: str) -> ScanResult:
	'''Scan a file using the shared JAMe engine.'''
	return _engine.scanFile(path)


def findFlag(path: str, format: str) -> str | None:
	'''Find a matching flag using the shared JAMe engine.'''
	return _engine.findFlag(path, format)


def autoSolve(path: str, **ctx: object) -> SolveResult:
	'''Run the solve workflow using the shared JAMe engine.'''
	return _engine.autoSolve(path, **ctx)


def cryptoAnalyze(path: str) -> CryptoResult:
	'''Analyze file crypto indicators using the shared JAMe engine.'''
	return _engine.cryptoAnalyze(path)


def binaryAnalyze(path: str) -> BinaryResult:
	'''Analyze binary indicators using the shared JAMe engine.'''
	return _engine.binaryAnalyze(path)


def stegoAnalyze(path: str) -> StegoResult:
	'''Analyze steganography indicators using the shared JAMe engine.'''
	return _engine.stegoAnalyze(path)


def forensicsAnalyze(path: str) -> ForensicsResult:
	'''Analyze forensic indicators using the shared JAMe engine.'''
	return _engine.forensicsAnalyze(path)


def archiveExtract(path: str) -> list[str]:
	'''Extract supported archives using the shared JAMe engine.'''
	return _engine.archiveExtract(path)


def getFileType(path: str) -> str:
	'''Return the file type using the shared JAMe engine.'''
	return _engine.getFileType(path)


def decodeCaesar(text: str, shift: int | str = 'brute') -> dict:
	'''Decode Caesar text using the shared JAMe engine.'''
	return _engine.decodeCaesar(text, shift)


def setFlagPatterns(patterns: list[str]) -> None:
	'''Set flag patterns on the shared JAMe engine.'''
	_engine.setFlagPatterns(patterns)


def setMaxDepth(depth: int) -> None:
	'''Set archive extraction depth on the shared JAMe engine.'''
	_engine.setMaxDepth(depth)


def setVerbose(enabled: bool) -> None:
	'''Set verbose mode on the shared JAMe engine.'''
	_engine.setVerbose(enabled)


def runStrings(path: str) -> list[str]:
	'''Extract printable strings using the shared JAMe engine.'''
	return _engine.runStrings(path)


def runBinwalk(path: str) -> BinwalkResult:
	'''Run binwalk using the shared JAMe engine.'''
	return _engine.runBinwalk(path)


__all__ = [
	'Jame',
	'__version__',
	'archiveExtract',
	'autoSolve',
	'binaryAnalyze',
	'create_jame',
	'cryptoAnalyze',
	'decodeCaesar',
	'findFlag',
	'forensicsAnalyze',
	'getFileType',
	'runBinwalk',
	'runStrings',
	'scanFile',
	'setFlagPatterns',
	'setMaxDepth',
	'setVerbose',
	'stegoAnalyze',
]
