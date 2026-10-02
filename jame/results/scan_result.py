'''Scan results.'''

from dataclasses import dataclass, field


@dataclass
class ScanResult:
    '''Top-level scan result produced by JAMe.'''

    file_path: str
    file_type: str
    summary: str
    details: dict[str, object] = field(default_factory=dict)
    confidence: float = 0.0
    raw_output: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        '''Return this result as a plain dictionary.'''
        return {
            'file_path': self.file_path,
            'file_type': self.file_type,
            'summary': self.summary,
            'details': self.details,
            'confidence': self.confidence,
            'raw_output': self.raw_output,
        }
