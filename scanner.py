from typing import Dict, Any, List
from .core import HarSanitizer

class HarSecurityScanner:
    """
    Scans a HAR file for security vulnerabilities, exposed credentials,
    and session hijacking vectors without modifying the file.
    """
    def __init__(self):
        pass

    def scan(self, har_data: Dict[str, Any]) -> Dict[str, Any]:
        sanitizer = HarSanitizer()
        _ = sanitizer.sanitize_har(har_data)
        findings = sanitizer.redaction_log

        summary = {
            "total_findings": len(findings),
            "findings_by_type": {},
            "risk_score": "LOW",
            "findings": findings
        }

        for f in findings:
            ftype = f.get("type", "UNKNOWN")
            summary["findings_by_type"][ftype] = summary["findings_by_type"].get(ftype, 0) + 1

        # Calculate Risk Score
        high_risk_types = {"HEADER_AUTH", "REGEX_JWT_TOKEN", "REGEX_AWS_KEY", "REGEX_PRIVATE_KEY_BLOCK", "POST_PARAM"}
        med_risk_types = {"COOKIE_HEADER", "SET_COOKIE_HEADER", "COOKIES_ARRAY", "QUERY_PARAM", "FORM_URLENCODED"}

        has_high = any(k in summary["findings_by_type"] for k in high_risk_types)
        has_med = any(k in summary["findings_by_type"] for k in med_risk_types)

        if has_high:
            summary["risk_score"] = "CRITICAL"
        elif has_med:
            summary["risk_score"] = "HIGH"
        elif len(findings) > 0:
            summary["risk_score"] = "MEDIUM"

        return summary
