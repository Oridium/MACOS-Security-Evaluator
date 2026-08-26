from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class Finding:
    id: str
    title: str
    category: str
    status: str
    severity: str
    weight: int
    points: int
    observed: str
    recommendation: str
    evidence: Optional[str] = None

    def to_dict(self):
        return asdict(self)
