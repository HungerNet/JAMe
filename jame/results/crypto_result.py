'''Crypto analysis results.'''

from dataclasses import dataclass, field


@dataclass
class CryptoResult:
    '''Detailed result for crypto analysis.'''

    file_path: str
    summary: str
    algorithm: str = 'unknown'
    confidence: float = 0.0
    findings: dict[str, object] = field(default_factory=dict)
    raw_output: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        '''Return this result as a plain dictionary.'''
        return {
            'file_path': self.file_path,
            'summary': self.summary,
            'algorithm': self.algorithm,
            'confidence': self.confidence,
            'findings': self.findings,
            'raw_output': self.raw_output,
        }
