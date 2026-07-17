# tests/test_guard.py
import os
import sys
import json

# Force the project root directory into the Python path to resolve 'src' packages cleanly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core_validator import scan_universal_security
from src.profiles.pci_dss import enforce_pci_compliance
from src.profiles.gdpr_seo import enforce_gdpr_seo_compliance
from src.profiles.biorobotics_guard import enforce_biorobotics_guard

def test_universal_sql_injection():
    result = scan_universal_security("SELECT * FROM users; --")
    assert result["status"] == "REJECTED"
    assert "SQL_INJECTION_VECTOR" in result["violations"]

def test_pci_scrubbing():
    result = enforce_pci_compliance("My card number is 4242 4242 4242 4242")
    assert result["status"] == "PAN_REDACTED"
    assert "[REDACTED_PCI_PAN]" in result["payload"]

def test_seo_metadata_length_check():
    payload = json.dumps({
        "seo_meta": {
            "title": "This is an extremely long title designed to deliberately exceed sixty characters",
            "description": "Short desc",
            "canonical_url": "https://www.seosiri.com"
        }
    })
    result = enforce_gdpr_seo_compliance(payload)
    assert "SEO_AEO_TITLE_EXCEEDS_60_CHARACTERS" in result["violations_found"]

def test_biorobotics_boundary_remediation():
    result = enforce_biorobotics_guard("G1 X240.0 Y10.0 F2000")
    assert result["status"] == "REMEDIATED"
    assert "DECK_LIMIT_X_EXCEEDED" in result["violations_found"]
    assert "EXCESSIVE_VELOCITY_CAVITATION_RISK" in result["violations_found"]
    assert result["payload"] == "G1 X200.0 Y10.0 F500.0"