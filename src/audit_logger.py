# src/audit_logger.py
import hashlib
import json
import os
from datetime import datetime, timezone

# Absolute path to the secure compliance log
LEDGER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "compliance_audit.log")

def get_last_entry_hash() -> str:
    """Reads the last entry in the ledger and returns its hash to secure the chain."""
    if not os.path.exists(LEDGER_PATH):
        return hashlib.sha256(b"seosiri_genesis_block").hexdigest()
        
    try:
        with open(LEDGER_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
            if not lines:
                return hashlib.sha256(b"seosiri_genesis_block").hexdigest()
            last_line = lines[-1].strip()
            last_entry = json.loads(last_line)
            return last_entry.get("current_hash", "")
    except Exception:
        return hashlib.sha256(b"seosiri_genesis_block").hexdigest()

def log_to_immutable_ledger(status: str, active_profiles: list, violations: list, original_payload: str, final_payload: str, signature: str = "None") -> str:
    """
    Appends a new security and compliance entry to the immutable ledger.
    Each entry is cryptographically linked to the previous entry, preventing tampering.
    """
    previous_hash = get_last_entry_hash()
    
    # Avoid Python 3.12+ utcnow() deprecation warnings by using timezone-aware objects
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    entry_data = {
        "timestamp": timestamp,
        "status": status,
        "active_profiles": active_profiles,
        "violations_detected": violations,
        "original_payload": original_payload,
        "final_payload": final_payload,
        "signature": signature,
        "previous_hash": previous_hash
    }
    
    # Generate current block hash
    serialized_entry = json.dumps(entry_data, sort_keys=True)
    current_hash = hashlib.sha256(serialized_entry.encode('utf-8')).hexdigest()
    entry_data["current_hash"] = current_hash
    
    # Append block to the file
    with open(LEDGER_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry_data) + "\n")
        
    print(f"[Ledger] New Audit Block appended. Hash: {current_hash[:10]}...")
    return current_hash
