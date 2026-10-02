'''Forensics analysis results.'''

from dataclasses import dataclass, field


@dataclass
class ForensicsResult:
    '''Result object for forensics analysis.'''

    file_path: str
    summary: str
    confidence: float = 0.0
    metadata: dict[str, object] = field(default_factory=dict)
    findings: dict[str, object] = field(default_factory=dict)
    raw_output: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        '''Return this result as a plain dictionary.'''
        return {
            'file_path': self.file_path,
            'summary': self.summary,
            'confidence': self.confidence,
            'metadata': self.metadata,
            'findings': self.findings,
            'raw_output': self.raw_output,
        }
