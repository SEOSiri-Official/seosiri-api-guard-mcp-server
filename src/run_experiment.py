# src/run_experiment.py
import asyncio
import json
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from src.hardware_gateway import GCodeSerialDriver
from src.policy_interceptor import enforce_hardware_policy
from src.audit_logger import log_to_immutable_ledger

async def run_lab_experiment(gene_id: str, plate_scale: float):
    # Establish server connection via stdio
    server_params = StdioServerParameters(
        command="python",
        args=["D:/seosiri-api-guard-mcp-server/src/main_server.py"],
        env={"PYTHONPATH": "D:/seosiri-api-guard-mcp-server"}
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # 1. Fetch sequence parameter
            print(f"[Orchestrator] Retrieving target data for: {gene_id}")
            raw_sequence = await session.call_tool("fetch_genomic_data", arguments={"gene_id": gene_id})
            data = json.loads(raw_sequence.content[0].text)
            print(f"[Orchestrator] Source: {data.get('source', 'Unknown')}")
            
            # 2. Convert to Metric delta
            concentration = data["concentration_proxy"]
            print(f"[Orchestrator] Calculated metric vector concentration: {concentration}")
            raw_motion = await session.call_tool("resolve_biotech_spatial_intent", 
                                                arguments={"concentration_input": concentration, "plate_scale_mm": plate_scale})
            
            motion_data = json.loads(raw_motion.content[0].text)
            meters_delta = motion_data["vectors_meters"]["x_axis_delta"]
            print(f"[Orchestrator] Deterministic SI delta output: {meters_delta} m")
            
            # 3. Query the bionics tool (simulate microvolt scaling for testing)
            print(f"[Orchestrator] Translating physical delta to bionics target angle...")
            emg_sim = (meters_delta * 1000.0) * 10.0
            raw_bionics = await session.call_tool("translate_emg_to_actuation", 
                                                 arguments={"emg_microvolts": emg_sim, "joint_id": "elbow_servo"})
            bionics_data = json.loads(raw_bionics.content[0].text)
            raw_gcode = bionics_data["gcode_command"]
            print(f"[Orchestrator] Proposed G-code command: {raw_gcode.strip()}")
            
            # 4. Pass through the Sovereign Policy Interceptor
            print(f"[Orchestrator] Passing proposed command to Policy Interceptor...")
            envelope = enforce_hardware_policy(raw_gcode)
            envelope_json = json.dumps(envelope)
            print(f"[Orchestrator] Interceptor Status: {envelope['status']}")
            
            # Write cryptographic entry to the local immutable audit ledger
            log_to_immutable_ledger(
                status=envelope["status"],
                active_profiles=["BIOROBOTICS_SAFETY_INTERLOCK"],
                violations=envelope.get("violations", []),
                original_payload=raw_gcode,
                final_payload=envelope.get("command", raw_gcode),
                signature=envelope.get("signature", "None")
            )
            
            if envelope['status'] != "AUTHORIZED" and envelope['status'] != "REMEDIATED":
                print(f"[Orchestrator Blocked] Command failed policy validation.")
                return
            
            # 5. Stream the verified and signed envelope to the hardware gateway
            print(f"[Orchestrator] Streaming authorized envelope to hardware...")
            driver = GCodeSerialDriver(mock_mode=True)
            
            # Test case: Forgery Simulation
            # (Uncomment line below to simulate a hacker tampering with the payload)
            # envelope_json = envelope_json.replace(envelope["signature"][:5], "00000")
            
            driver.stream_authorized_envelope(envelope_json)
            print("[Orchestrator] Master Pipeline executed successfully.")

if __name__ == "__main__":
    target_gene = sys.argv[1] if len(sys.argv) > 1 else "P42212"
    asyncio.run(run_lab_experiment(target_gene, 100.0))
