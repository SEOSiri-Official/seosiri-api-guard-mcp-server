# src/main_server.py
import os
import sys

# Force the project root directory into the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from mcp.server.fastmcp import FastMCP
from src.core_validator import scan_universal_security
from src.profiles.hipaa import enforce_hipaa_compliance
from src.profiles.pci_dss import enforce_pci_compliance
from src.profiles.gdpr_seo import enforce_gdpr_seo_compliance
from src.profiles.biorobotics_guard import enforce_biorobotics_guard

mcp = FastMCP("SEOSiri-API-Guard")

@mcp.tool()
def sanitize_and_validate_payload(proposed_payload: str, active_profiles_csv: str = "universal") -> str:
    """
    Main Security Gatekeeper: Processes proposed payloads against universal OWASP rules 
    and activates industry-specific compliance profiles (hipaa, pci, seo, biorobotics) dynamically.
    """
    # 1. Run Universal Scan First
    scan_result = scan_universal_security(proposed_payload)
    if scan_result["status"] == "REJECTED":
        return json.dumps({
            "status": "REJECTED",
            "reason": "SECURITY_VULNERABILITY_DETECTION",
            "details": scan_result["violations"],
            "payload": scan_result["payload"]
        })
        
    profiles = [p.strip().lower() for p in active_profiles_csv.split(",")]
    current_payload = scan_result["payload"]
    triggered_violations = list(scan_result["violations"])
    active_runs = []
    dynamic_recommendations = []
    
    # 2. Run Industry Profiles
    if "hipaa" in profiles:
        res = enforce_hipaa_compliance(current_payload)
        current_payload = res["payload"]
        triggered_violations.extend(res["violations_found"])
        active_runs.append("HIPAA")
        
    if "pci" in profiles:
        res = enforce_pci_compliance(current_payload)
        current_payload = res["payload"]
        triggered_violations.extend(res["violations_found"])
        active_runs.append("PCI_DSS")
        
    if "seo" in profiles or "gdpr" in profiles:
        res = enforce_gdpr_seo_compliance(current_payload)
        current_payload = res["payload"]
        triggered_violations.extend(res["violations_found"])
        active_runs.append("GDPR_SEO_AEO")
        
    if "biorobotics" in profiles:
        res = enforce_biorobotics_guard(current_payload)
        current_payload = res["payload"]
        triggered_violations.extend(res["violations_found"])
        dynamic_recommendations.extend(res["recommendations"])
        active_runs.append("BIOROBOTICS_SAFETY_INTERLOCK")
        
    return json.dumps({
        "status": "REMEDIATED" if dynamic_recommendations else ("AUTHORIZED_WITH_REDACTIONS" if triggered_violations else "AUTHORIZED"),
        "active_profiles": active_runs,
        "violations_detected": triggered_violations,
        "remediation_recommendations": dynamic_recommendations,
        "payload": current_payload
    })

if __name__ == "__main__":
    import time
    time.sleep(0.5)
    mcp.run(transport='stdio')
