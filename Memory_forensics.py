import os
import psutil
import re
import json
from datetime import datetime


# 1. Capture Memory Dump (Simulation)
def capture_memory_dump(file_name="memory_dump.txt"):
    print("[INFO] Capturing memory dump...")
    processes = []
    for proc in psutil.process_iter(attrs=['pid', 'name', 'memory_info', 'username']):
        try:
            processes.append({
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "memory": proc.info['memory_info'].rss,
                "user": proc.info['username']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    with open(file_name, "w") as f:
        json.dump(processes, f, indent=4)
    print(f"[INFO] Memory dump saved to {file_name}")


# 2. Identify Running Processes
def analyze_processes(file_name="memory_dump.txt"):
    print("[INFO] Analyzing running processes...")
    if not os.path.exists(file_name):
        print(f"[ERROR] Memory dump file {file_name} not found!")
        return

    with open(file_name, "r") as f:
        processes = json.load(f)

    print("\n[INFO] Active Processes:")
    for proc in processes:
        print(f"PID: {proc['pid']}, Name: {proc['name']}, Memory: {proc['memory']}, User: {proc['user']}")

    return processes


# 3. Detect Malicious Patterns
def detect_malicious_patterns(processes, patterns):
    print("\n[INFO] Detecting malicious patterns...")
    suspicious = []

    for proc in processes:
        for pattern in patterns:
            if re.search(pattern, proc["name"], re.IGNORECASE):
                suspicious.append(proc)

    if suspicious:
        print("\n[ALERT] Suspicious Processes Detected:")
        for proc in suspicious:
            print(f"PID: {proc['pid']}, Name: {proc['name']}")
    else:
        print("\n[INFO] No malicious patterns detected.")

    return suspicious


# 4. Extract Artifacts
def extract_artifacts(file_name="memory_dump.txt"):
    print("\n[INFO] Extracting artifacts...")
    if not os.path.exists(file_name):
        print(f"[ERROR] Memory dump file {file_name} not found!")
        return

    with open(file_name, "r") as f:
        processes = json.load(f)

    artifacts = []
    for proc in processes:
        if "browser" in proc["name"].lower():
            artifacts.append({"pid": proc["pid"], "name": proc["name"], "artifact": "Possible browser session"})

    print("[INFO] Extracted Artifacts:")
    for artifact in artifacts:
        print(artifact)

    return artifacts


# Main Execution
if __name__ == "__main__":
    print("[INFO] Memory Forensics Tool")

    # Capture memory dump
    capture_memory_dump()

    # Analyze processes
    processes = analyze_processes()

    # Malicious patterns to detect
    malicious_patterns = [r"malware", r"exploit", r"trojan"]
    if processes:
        detect_malicious_patterns(processes, malicious_patterns)

    # Extract artifacts
    extract_artifacts()
