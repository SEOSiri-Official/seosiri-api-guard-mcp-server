# src/profiles/biorobotics_guard.py
import re
import json

# Immutable physical boundaries of the SEOSiri Biorobotics Gantry
MAX_X_LIMIT_MM = 200.0
MAX_Y_LIMIT_MM = 150.0
MAX_Z_LIMIT_MM = 100.0

def remediate_gcode_string(cmd: str, violations: list, recommendations: list) -> str:
    """Helper to scan and remediate a single raw G-code string."""
    cmd_clean = cmd.strip()
    if not cmd_clean.startswith("G1"):
        return cmd
        
    sanitized_cmd = cmd_clean

    # 1. Boundary Check: X Axis
    x_match = re.search(r"X([0-9\.]+)", cmd_clean)
    if x_match:
        x_val_str = x_match.group(1)
        x_val = float(x_val_str)
        if x_val > MAX_X_LIMIT_MM:
            violations.append("DECK_LIMIT_X_EXCEEDED")
            recommendations.append(f"Clamp X to physical boundary ({MAX_X_LIMIT_MM}mm)")
            sanitized_cmd = sanitized_cmd.replace(f"X{x_val_str}", f"X{MAX_X_LIMIT_MM}")

    # 2. Boundary Check: Y Axis
    y_match = re.search(r"Y([0-9\.]+)", cmd_clean)
    if y_match:
        y_val_str = y_match.group(1)
        y_val = float(y_val_str)
        if y_val > MAX_Y_LIMIT_MM:
            violations.append("DECK_LIMIT_Y_EXCEEDED")
            recommendations.append(f"Clamp Y to physical boundary ({MAX_Y_LIMIT_MM}mm)")
            sanitized_cmd = sanitized_cmd.replace(f"Y{y_val_str}", f"Y{MAX_Y_LIMIT_MM}")

    # 3. Boundary Check: Z Axis
    z_match = re.search(r"Z([0-9\.]+)", cmd_clean)
    if z_match:
        z_val_str = z_match.group(1)
        z_val = float(z_val_str)
        if z_val > MAX_Z_LIMIT_MM:
            violations.append("DECK_LIMIT_Z_EXCEEDED")
            recommendations.append(f"Clamp Z to physical boundary ({MAX_Z_LIMIT_MM}mm)")
            sanitized_cmd = sanitized_cmd.replace(f"Z{z_val_str}", f"Z{MAX_Z_LIMIT_MM}")

    # 4. Velocity Check: Feedrate
    f_match = re.search(r"F([0-9\.]+)", cmd_clean)
    if f_match:
        f_val_str = f_match.group(1)
        f_val = float(f_val_str)
        if f_val > 1500.0:
            violations.append("EXCESSIVE_VELOCITY_CAVITATION_RISK")
            recommendations.append("Reduce feedrate to F500.0 to prevent fluid splashing")
            sanitized_cmd = sanitized_cmd.replace(f"F{f_val_str}", "F500.0")

    return sanitized_cmd

def enforce_biorobotics_guard(payload_str: str) -> dict:
    """
    Biorobotics Safety Interlock Profile: Scans and remediates G-code commands,
    handling both raw string commands and embedded G-code inside complex JSON structures.
    """
    violations = []
    recommendations = []
    
    try:
        # Attempt to parse as JSON (Case A: Nested JSON Payload)
        data = json.loads(payload_str)
        
        def recursive_scan_and_remediate(obj):
            if isinstance(obj, dict):
                return {k: recursive_scan_and_remediate(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [recursive_scan_and_remediate(v) for v in obj]
            elif isinstance(obj, str):
                if obj.strip().startswith("G1"):
                    return remediate_gcode_string(obj, violations, recommendations)
            return obj

        remediated_data = recursive_scan_and_remediate(data)
        output_payload = json.dumps(remediated_data)
        
    except Exception:
        # Case B: Raw G-code String Payload
        output_payload = remediate_gcode_string(payload_str, violations, recommendations)

    return {
        "profile": "BIOROBOTICS_SAFETY_INTERLOCK",
        "status": "REMEDIATED" if violations else "COMPLIANT",
        "violations_found": violations,
        "recommendations": recommendations,
        "payload": output_payload
    }