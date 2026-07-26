import psutil
import time
import hashlib
import os
from datetime import datetime

# ==============================
# CONFIGURATION
# ==============================

SUSPICIOUS_NAMES = [
    "keylogger.exe",
    "hooklogger.exe",
    "logger.exe"
]

SCAN_INTERVAL = 5
REPORT_FILE = "report.txt"


# ==============================
# HASH CALCULATION
# ==============================

def calculate_sha256(file_path):

    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:

            for block in iter(lambda: file.read(4096), b""):
                sha256_hash.update(block)

        return sha256_hash.hexdigest()

    except Exception:
        return "Unable to calculate hash"


# ==============================
# PROCESS SCANNER
# ==============================

def scan_processes():

    suspicious_processes = []

    for process in psutil.process_iter(
        ['pid', 'name', 'exe', 'cpu_percent', 'memory_percent']
    ):

        try:

            process_name = process.info['name']

            if not process_name:
                continue

            process_name_lower = process_name.lower()

            # Check suspicious name
            if process_name_lower in SUSPICIOUS_NAMES:

                suspicious_processes.append(process)

                print("\n[ALERT] Suspicious Process Detected!")

                print(f"PID: {process.info['pid']}")
                print(f"Process Name: {process_name}")
                print(f"CPU Usage: {process.info['cpu_percent']}%")
                print(
                    f"Memory Usage: "
                    f"{process.info['memory_percent']:.2f}%"
                )

                process_path = process.info['exe']

                print(f"Path: {process_path}")

                if process_path and os.path.exists(process_path):

                    file_hash = calculate_sha256(process_path)

                    print(f"SHA-256: {file_hash}")

                print("----------------------------------------")

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):

            pass

    return suspicious_processes


# ==============================
# REPORT GENERATOR
# ==============================

def generate_report(suspicious_processes):

    with open(REPORT_FILE, "a") as report:

        report.write("\n====================================\n")

        report.write(
            f"Scan Time: "
            f"{datetime.now()}\n"
        )

        report.write(
            "KEYLOGGER DETECTION REPORT\n"
        )

        report.write(
            "====================================\n"
        )

        if not suspicious_processes:

            report.write(
                "No known suspicious process detected.\n"
            )

        else:

            for process in suspicious_processes:

                report.write(
                    f"PID: {process.info['pid']}\n"
                )

                report.write(
                    f"Process Name: "
                    f"{process.info['name']}\n"
                )

                report.write(
                    f"Process Path: "
                    f"{process.info['exe']}\n"
                )


# ==============================
# MAIN MONITORING SYSTEM
# ==============================

def main():

    print("========================================")
    print("       KEYLOGGER DETECTION SYSTEM")
    print("========================================")

    print("\nMonitoring Started...")
    print("Press CTRL + C to stop.\n")

    try:

        while True:

            suspicious_processes = scan_processes()

            generate_report(suspicious_processes)

            print(
                f"\nNext scan in "
                f"{SCAN_INTERVAL} seconds..."
            )

            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:

        print("\nMonitoring stopped by user.")


# ==============================
# PROGRAM START
# ==============================

if __name__ == "__main__":

    main()
    