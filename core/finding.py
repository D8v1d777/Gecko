from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Finding:
    url: str
    type: str
    severity: Severity
    description: str
    evidence: str
    id: Optional[str] = None
    title: Optional[str] = None
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    context: Dict[str, Any] = field(default_factory=dict)
