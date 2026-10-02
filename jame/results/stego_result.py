'''Steganography analysis results.'''

from dataclasses import dataclass, field


@dataclass
class StegoResult:
    '''Result object for stego analysis.'''

    file_path: str
    summary: str
    confidence: float = 0.0
    techniques: list[str] = field(default_factory=list)
    findings: dict[str, object] = field(default_factory=dict)
    raw_output: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        '''Return this result as a plain dictionary.'''
        return {
            'file_path': self.file_path,
            'summary': self.summary,
            'confidence': self.confidence,
            'techniques': self.techniques,
            'findings': self.findings,
            'raw_output': self.raw_output,
        }
