import json
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.core_validator import scan_universal_security
from src.profiles.pci_dss import enforce_pci_compliance
from src.profiles.gdpr_seo import enforce_gdpr_seo_compliance
from src.profiles.biorobotics_guard import enforce_biorobotics_guard
from src.policy_interceptor import enforce_hardware_policy
from src.hardware_gateway import GCodeSerialDriver
from src.audit_logger import log_to_immutable_ledger, LEDGER_PATH

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

def test_hardware_signature_forgery_blocking():
    driver = GCodeSerialDriver(mock_mode=True)
    raw_gcode = "G1 X45.0 F1000.0"
    
    # 1. Generate authorized envelope
    envelope = enforce_hardware_policy(raw_gcode)
    envelope_json = json.dumps(envelope)
    
    # Assert signature verifies and passes
    assert driver.stream_authorized_envelope(envelope_json) == "ok"
    
    # 2. Simulate Forgery (Hacker manually editing the coordinate but keeping the old signature)
    forged_envelope = envelope.copy()
    forged_envelope["command"] = "G1 X180.0 F1000.0" # Altered coordinate without re-signing
    forged_envelope_json = json.dumps(forged_envelope)
    
    # Assert Actuator cleanly detects the forgery and blocks execution
    assert driver.stream_authorized_envelope(forged_envelope_json) == "ERROR_SIGNATURE_MISMATCH"

def test_immutable_ledger_blockchain_link():
    # Clear previous logs if any
    if os.path.exists(LEDGER_PATH):
        os.remove(LEDGER_PATH)
        
    # Append two linked blocks
    hash_1 = log_to_immutable_ledger("REMEDIATED", ["BIOROBOTICS"], ["DECK_LIMIT"], "G1 X240.0", "G1 X200.0", "sig_123")
    hash_2 = log_to_immutable_ledger("AUTHORIZED", ["PCI"], [], "G1 X50.0", "G1 X50.0", "sig_456")
    
    with open(LEDGER_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()
        block_2 = json.loads(lines[1].strip())
        
        # Assert Block 2 is cryptographically chained to the hash of Block 1
        assert block_2["previous_hash"] == hash_1
        assert block_2["current_hash"] == hash_2
