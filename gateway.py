import json
import os
import re
from datetime import datetime

# --- SECURITY DATABASE: ADVERSARIAL SIGNATURES ---
# Threat intelligence patterns mimicking AI-generated system-escape attacks
MALICIOUS_SIGNATURES = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"system\s+override",
    r"you\s+are\s+now\s+an\s+unfiltered",
    r"output\s+the\s+system\s+prompt",
    r"dan\s+mode",
    r"disregard\s+above\s+guidelines"
]

TELEMETRY_LOG_FILE = "security_telemetry.json"

def emit_threat_telemetry(raw_input, classification):
    """
    AppSec Telemetry Pipeline:
    Safely captures, serializes, and appends blocked payloads to a JSON ledger.
    """
    telemetry_payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "intercepted_payload": raw_input,
        "threat_class": classification,
        "remediation": "DROP_CONNECTION"
    }

    current_logs = []
    
    # Securely read file state and handle data anomalies
    if os.path.exists(TELEMETRY_LOG_FILE):
        with open(TELEMETRY_LOG_FILE, "r") as log_ptr:
            try:
                current_logs = json.load(log_ptr)
            except json.JSONDecodeError:
                # Recover gracefully from empty or corrupted log files
                pass

    current_logs.append(telemetry_payload)
    
    with open(TELEMETRY_LOG_FILE, "w") as log_ptr:
        json.dump(current_logs, log_ptr, indent=4)
        
    print(f"[ALARM] Threat Intercepted: {classification}. Telemetry written.")

def validate_input(user_string):
    """
    Asymmetric Inspection Routing:
    Processes raw text entries across layered input validation controls.
    Returns: Cleaned string if approved; None if a security policy violation occurs.
    """
    if not user_string or not isinstance(user_string, str):
        return None
        
    # Canonicalization: Standardize input casing and whitespace to defeat basic obfuscation
    normalized_text = user_string.lower().strip()

    # LAYER 1: Boundary & Parameter Size Verification
    # Prevents massive data streams from overwhelming API system processing threads
    if len(normalized_text) > 800:
        emit_threat_telemetry(user_string[:50] + "...[TRUNCATED]", "Token_Exhaustion_Exploit")
        return None

    # LAYER 2: Signature Heuristic Pattern Matching
    # Scans text entries against known parameter tampering strings
    for pattern in MALICIOUS_SIGNATURES:
        if re.search(pattern, normalized_text):
            emit_threat_telemetry(user_string, "Prompt_Injection_Violation")
            return None

    # LAYER 3: Boundary Clear
    return user_string
