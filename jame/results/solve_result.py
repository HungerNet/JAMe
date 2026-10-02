'''Solve results.'''

from dataclasses import dataclass, field


@dataclass
class SolveResult:
    '''Result object for solving tasks.'''

    file_path: str
    summary: str
    flag: str | None = None
    confidence: float = 0.0
    details: dict[str, object] = field(default_factory=dict)
    raw_output: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        '''Return this result as a plain dictionary.'''
        return {
            'file_path': self.file_path,
            'summary': self.summary,
            'flag': self.flag,
            'confidence': self.confidence,
            'details': self.details,
            'raw_output': self.raw_output,
        }
