import streamlit as st
import os
import json
from gateway import validate_input, TELEMETRY_LOG_FILE

st.set_page_config(page_title="AI Security Gateway Dashboard", layout="wide")

st.title("Asymmetric AI Input Validation Gateway")
st.subheader("Interactive Application Security Sandboxing (Canvas-Exploit Mitigations)")

col1, col2 = st.columns(2)

with col1:
    st.header("Gateway Ingestion Terminal")
    st.markdown("Submit a text payload below to test the runtime input validation constraints.")
    
    user_input = st.text_area("User Prompt Input String", height=150, 
                              placeholder="Type a query or attempt an override exploit...")
    
    if st.button("Submit Payload to Core Application"):
        if user_input:
            security_check = validate_input(user_input)
            if security_check is None:
                st.error("SECURITY POLICY VIOLATION: Payload dropped by gateway middleware. Threat logged.")
            else:
                st.success("SECURITY POLICY CLEARED: Input successfully routed to the backend system.")
                st.info(f"Processed String: {security_check}")
        else:
            st.warning("Please input a string value to evaluate.")

with col2:
    st.header("Real-Time Incident Telemetry")
    st.markdown("This window displays raw contents from `security_telemetry.json` mimicking an enterprise response center.")
    
    if os.path.exists(TELEMETRY_LOG_FILE):
        with open(TELEMETRY_LOG_FILE, "r") as log_file:
            try:
                logs = json.load(log_file)
                st.json(logs[::-1]) # Display newest security incidents first
            except:
                st.info("Log file initializing or currently locked.")
    else:
        st.info("No network security anomalies logged in the current session.")
