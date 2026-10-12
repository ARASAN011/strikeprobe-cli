from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str  # Critical, High, Medium, Low
    confidence: str  # High, Medium, Low
    masvs_category: str  # MASVS-STORAGE, MASVS-CRYPTO, MASVS-AUTH, MASVS-NETWORK, MASVS-PLATFORM, MASVS-CODE, MASVS-RESILIENCE, MASVS-PRIVACY
    description: str
    evidence: str
    affected_file: str = "AndroidManifest.xml"
    affected_line: Optional[int] = None
    remediation: str = ""
    cwe: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    target_name: str
    target_type: str  # apk, source_zip, directory
    sha256: str
    file_size_bytes: int
    package_name: str = "N/A"
    version_name: str = "N/A"
    version_code: str = "N/A"
    min_sdk: str = "N/A"
    target_sdk: str = "N/A"
    security_score: int = 100
    grade: str = "A"
    scan_duration_sec: float = 0.0
    permissions: List[str] = field(default_factory=list)
    exported_components: List[str] = field(default_factory=list)
    discovered_endpoints: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    masvs_summary: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity_counts"] = self.severity_counts
        return data
