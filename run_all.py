"""
=============================================================================
Network Intrusion Detection System (IDS) Simulation
Module: run_all.py
Purpose: One-click orchestration script to initialize database, generate dataset,
         train ML models, run test suite, and launch the Web SOC Dashboard.
=============================================================================
"""

import os
import sys
import time
import subprocess
import uvicorn

# Ensure root directory is on pythonpath
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


def main():
    print("=" * 70)
    print("    NETWORK INTRUSION DETECTION SYSTEM (IDS) SIMULATION ENGINE")
    print("=" * 70)

    # 1. Initialize Database
    print("\n[STEP 1/5] Initializing Database & SQLite Schema...")
    from backend.database import init_db
    init_db()
    print("[+] Database initialized at 'data/ids_events.db'")

    # 2. Check / Generate Synthetic Dataset
    dataset_path = os.path.join("data", "network_traffic.csv")
    if not os.path.exists(dataset_path):
        print("\n[STEP 2/5] Generating 5,000 synthetic flow records...")
        from simulator.generate_dataset import generate_synthetic_dataset
        generate_synthetic_dataset(num_records=5000, output_path=dataset_path)
    else:
        print(f"\n[STEP 2/5] Synthetic dataset exists ({dataset_path}).")

    # 3. Check / Train Machine Learning Pipeline
    model_path = os.path.join("models", "ids_models.joblib")
    if not os.path.exists(model_path):
        print("\n[STEP 3/5] Training Random Forest & Isolation Forest ML Models...")
        from ml.train_model import train_models
        train_models(data_path=dataset_path, output_model_path=model_path)
    else:
        print(f"\n[STEP 3/5] ML Model pipeline exists ({model_path}).")

    # 4. Run Automated Test Suite
    print("\n[STEP 4/5] Executing 30-Scenario Automated Verification Suite...")
    from tests.test_ids_suite import run_all_tests
    success = run_all_tests()
    if not success:
        print("[-] Warning: Some verification tests failed. Check logs above.")
    else:
        print("[+] All 30 automated verification tests passed (100%).")

    # 5. Launch FastAPI Backend Server & Dashboard
    print("\n[STEP 5/5] Launching FastAPI Backend Server & Web SOC Dashboard...")
    print("[*] Dashboard UI:    http://127.0.0.1:8000")
    print("[*] API Interactive Docs: http://127.0.0.1:8000/docs")
    print("[*] Press Ctrl+C to terminate the IDS engine server.\n")

    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
