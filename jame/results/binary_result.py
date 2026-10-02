'''Binary analysis results.'''

from dataclasses import dataclass, field


@dataclass
class BinaryResult:
    '''Result object for binary analysis.'''

    file_path: str
    summary: str
    architecture: str = 'unknown'
    confidence: float = 0.0
    findings: dict[str, object] = field(default_factory=dict)
    raw_output: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        '''Return this result as a plain dictionary.'''
        return {
            'file_path': self.file_path,
            'summary': self.summary,
            'architecture': self.architecture,
            'confidence': self.confidence,
            'findings': self.findings,
            'raw_output': self.raw_output,
        }


@dataclass
class BinwalkResult:
    '''Result object for binwalk tooling.'''

    file_path: str
    available: bool = False
    summary: str = ''
    extracted: list[str] = field(default_factory=list)
    matches: list[str] = field(default_factory=list)
    raw_output: dict[str, object] = field(default_factory=dict)
    confidence: float = 0.0

    def to_dict(self) -> dict[str, object]:
        '''Return this result as a plain dictionary.'''
        return {
            'file_path': self.file_path,
            'available': self.available,
            'summary': self.summary,
            'extracted': self.extracted,
            'matches': self.matches,
            'raw_output': self.raw_output,
            'confidence': self.confidence,
        }
