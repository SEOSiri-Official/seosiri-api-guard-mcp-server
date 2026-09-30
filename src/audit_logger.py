
# =========================================================================
# PILLAR 2: STRICT PYDANTIC INPUT VALIDATION CONTRACTS
# =========================================================================
from pydantic import BaseModel, Field

class ValidatedToolRequest(BaseModel):
    client_id: str = Field(default="ANONYMOUS_CLIENT", min_length=1)
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    strict_mode: bool = Field(default=True)


# =========================================================================
# PILLAR 4: RESILIENCE & CIRCUIT BREAKER ENGINE
# =========================================================================
import time
from typing import Callable, Any

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 3, recovery_time: float = 10.0):
        self.failure_threshold = failure_threshold
        self.recovery_time = recovery_time
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = 'CLOSED'

    def execute(self, func: Callable, fallback_func: Callable, *args, **kwargs) -> Any:
        now = time.time()
        if self.state == 'OPEN':
            if now - self.last_failure_time > self.recovery_time:
                self.state = 'HALF_OPEN'
            else:
                return fallback_func(*args, **kwargs)
        try:
            res = func(*args, **kwargs)
            self.failure_count = 0
            self.state = 'CLOSED'
            return res
        except Exception:
            self.failure_count += 1
            self.last_failure_time = now
            if self.failure_count >= self.failure_threshold:
                self.state = 'OPEN'
            return fallback_func(*args, **kwargs)

resilience_circuit_breaker = CircuitBreaker()

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


# =========================================================================
# PILLAR 1: DUAL TRANSPORT PARITY (stdio + SSE)
# =========================================================================
if __name__ == '__main__':
    import os, sys
    transport = os.getenv('MCP_TRANSPORT', 'stdio').lower()
    if '--sse' in sys.argv or transport == 'sse':
        mcp.run(transport='sse')
    else:
        mcp.run(transport='stdio')
