# src/hardware_gateway.py
import sys
import json
import hmac
import hashlib

# Shared cryptographic secret key
POLICY_SECRET_KEY = b"seosiri_bionics_secure_key_2026"

try:
    import serial
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False

class GCodeSerialDriver:
    """
    Actuation Layer: Exposes the serial bus to the controller. Only executes 
    G-code if it is wrapped in an authorized, signed policy envelope.
    """
    def __init__(self, port: str = "COM3", baudrate: int = 115200, mock_mode: bool = True):
        self.port = port
        self.baudrate = baudrate
        self.mock_mode = mock_mode or not SERIAL_AVAILABLE
        self.connection = None
        
        if self.mock_mode:
            print(f"[Driver] INITIALIZED IN MOCK MODE.")
        else:
            try:
                self.connection = serial.Serial(self.port, self.baudrate, timeout=2)
                print(f"[Driver] Connected to active microcontroller on {self.port}")
            except Exception as e:
                print(f"[Driver] Connection failed ({e}). Defaulting to Mock Mode.")
                self.mock_mode = True

    def verify_signature(self, cmd: str, angle: float, feedrate: float, signature: str) -> bool:
        """
        On-Device Attestation Simulator: Recalculates and cryptographically 
        verifies the incoming HMAC signature using the shared secret key.
        """
        payload = f"{cmd}:{angle}:{feedrate}".encode('utf-8')
        recalculated_sig = hmac.new(POLICY_SECRET_KEY, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(recalculated_sig, signature)

    def stream_authorized_envelope(self, policy_envelope_json: str) -> str:
        """
        Actuation Layer: Verifies the cryptographic signature of the envelope. 
        Rejects the command if the signature is altered or forged.
        """
        envelope = json.loads(policy_envelope_json)
        
        if envelope.get("status") not in ["AUTHORIZED", "REMEDIATED"]:
            print(f"[Actuator Blocked] Command rejected. Status is not authorized.")
            return "ERROR_SECURITY_BLOCK"
            
        gcode_command = envelope.get("command") + "\n"
        signature = envelope.get("signature")
        angle = envelope.get("target_angle")
        feedrate = envelope.get("target_feedrate")
        
        # Active Cryptographic Attestation Check
        if not self.verify_signature(envelope.get("command"), angle, feedrate, signature):
            print(f"[Actuator Blocked] CRITICAL: Signature Verification Failed! Potential Forgery Detected.")
            return "ERROR_SIGNATURE_MISMATCH"
            
        print(f"[Actuator Approved] Cryptographic Signature Verified: {signature[:10]}... [OK]")
        
        if self.mock_mode:
            print(f"[Mock-Serial] Sent to motor: {gcode_command.strip()}")
            return "ok"
        
        try:
            self.connection.write(gcode_command.encode('utf-8'))
            response = self.connection.readline().decode('utf-8').strip()
            print(f"[Serial Response] {response}")
            return response
        except Exception as e:
            print(f"[Driver Error] Failed to stream command: {e}")
            return "ERROR"
