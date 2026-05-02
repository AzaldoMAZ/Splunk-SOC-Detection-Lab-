# ============================================================
# SOC ENRICHMENT SCRIPT - Phase 5
# Pulls Splunk alerts, enriches IOCs with VirusTotal + AbuseIPDB
# Generates structured JSON incident report
# ============================================================

import requests
import json
import os
import time
import urllib3
from datetime import datetime

# Suppress SSL warning for Splunk localhost
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# CONFIG - edit only this block
# ============================================================
SPLUNK_HOST     = "https://localhost:8089"
SPLUNK_USER     = "azaldo"
SPLUNK_PASS     = "NiKe1234!"

VIRUSTOTAL_KEY  = "7cb28dcd779767d4b4bd736eb8602c0bace5a7671966ba639e72fa7d85af2325"
ABUSEIPDB_KEY   = "c11b21db008773ff55342a4fe468bea2b2cc06309741ef987a2bd3bd81c7109c12b4c881aa43d8"

ATTACKER_IP     = "192.168.56.101"
PAYLOAD_NAME    = "hello.exe"
C2_PORT         = 4444


# ============================================================
# FUNCTION 1 - Get Splunk Alerts
# ============================================================
def get_splunk_alerts():
    """
    Connects to Splunk REST API on port 8089 and runs the
    reverse shell detection search. Returns a list of result
    dictionaries, one per event.
    """
    # Step 1 - authenticate and get a session key
    # output_mode=json tells Splunk to respond in JSON (not XML)
    auth_url  = f"{SPLUNK_HOST}/services/auth/login"
    auth_data = {
        "username":    SPLUNK_USER,
        "password":    SPLUNK_PASS,
        "output_mode": "json"
    }

    print("[*] Authenticating with Splunk...")
    auth_response = requests.post(auth_url, data=auth_data, verify=False)

    if auth_response.status_code != 200:
        print(f"[!] Auth failed. Status: {auth_response.status_code}")
        print(f"[!] Response: {auth_response.text}")
        return []

    session_key = auth_response.json()["sessionKey"]
    print(f"[+] Authenticated. Session Key obtained.")

    # Step 2 - run the detection search via the search/jobs endpoint
    search_url   = f"{SPLUNK_HOST}/services/search/jobs"
    search_query = (
        'search index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" '
        '(EventCode=1 AND Image="*hello.exe*") '
        'OR (EventCode=3 AND Image="*hello.exe*" AND DestinationPort=4444) '
        '| table _time, Image, CommandLine, SourceIp, DestinationIp, DestinationPort, User'
    )

    headers  = {"Authorization": f"Splunk {session_key}"}
    job_data = {
        "search":         search_query,
        "output_mode":    "json",
        "earliest_time":  "-30d"
    }

    print("[*] Submitting search job to Splunk...")
    job_response = requests.post(search_url, headers=headers, data=job_data, verify=False)

    if job_response.status_code not in [200, 201]:
        print(f"[!] Search job failed. Status: {job_response.status_code}")
        print(f"[!] Response: {job_response.text}")
        return []

    sid = job_response.json()["sid"]
    print(f"[+] Search job created. SID: {sid}")

    # Step 3 - poll until job is DONE
    print("[*] Waiting for search to complete...")
    while True:
        status_response = requests.get(
            f"{SPLUNK_HOST}/services/search/jobs/{sid}",
            headers=headers,
            verify=False,
            params={"output_mode": "json"}
        )
        dispatch_state = status_response.json()["entry"][0]["content"]["dispatchState"]
        if dispatch_state == "DONE":
            print("[+] Search complete.")
            break
        time.sleep(1)

    # Step 4 - fetch results
    results_url = f"{SPLUNK_HOST}/services/search/jobs/{sid}/results"
    results_response = requests.get(
        results_url,
        headers=headers,
        verify=False,
        params={"output_mode": "json", "count": 100}
    )

    return results_response.json().get("results", [])


# ============================================================
# FUNCTION 2 - Extract IOCs
# ============================================================
def extract_iocs(results):
    """
    Parses the Splunk results to find unique IPs and Filenames.
    Returns a dictionary of found IOCs.
    """
    iocs = {
        "ips":       set(),
        "filenames": set()
    }

    print(f"[*] Processing {len(results)} events from Splunk...")

    for event in results:
        # Extract Destination IP (the C2 server / attacker machine)
        if "DestinationIp" in event and event["DestinationIp"]:
            iocs["ips"].add(event["DestinationIp"])

        # Extract Image filename (strips full path to just hello.exe)
        if "Image" in event and event["Image"]:
            filename = os.path.basename(event["Image"])
            iocs["filenames"].add(filename)

    # Convert sets to lists for JSON compatibility
    iocs["ips"]       = list(iocs["ips"])
    iocs["filenames"] = list(iocs["filenames"])

    print(f"[+] Found {len(iocs['ips'])} Unique IPs:        {iocs['ips']}")
    print(f"[+] Found {len(iocs['filenames'])} Unique Filenames: {iocs['filenames']}")

    return iocs


# ============================================================
# FUNCTION 3 - Check VirusTotal
# ============================================================
def check_virustotal(ip):
    """
    Sends the extracted IP address to VirusTotal to get a threat score.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    
    print(f"[*] Checking IP {ip} against VirusTotal...")
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            print(f"[+] VirusTotal Report for {ip}:")
            print(f"    - Malicious flags:  {malicious}")
            print(f"    - Suspicious flags: {suspicious}")
            
            if malicious > 0:
                print("    -> [!] WARNING: This IP is known to be malicious!")
            else:
                print("    -> [-] This IP is currently clean (Note: Local lab IPs are always clean)")
            return stats
        else:
            print(f"[!] VirusTotal API error. Status: {response.status_code}")
            return None
    except Exception as e:
        print(f"[!] Failed to reach VirusTotal: {e}")
        return None


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print("=" * 55)
    print("   SOC PHASE 6 - ENRICHMENT SCRIPT")
    print("=" * 55)

    # Step 1: Fetch from Splunk
    splunk_data = get_splunk_alerts()

    if not splunk_data:
        print("\n[!] No alerts found in Splunk.")
        print("[!] Make sure your reverse shell attack happened in the last 30 days.")
    else:
        # Step 2: Extract IOCs
        found_iocs = extract_iocs(splunk_data)

        print("\n--- EXTRACTED IOCS ---")
        print(f"IPs to check:   {found_iocs['ips']}")
        print(f"Files to check: {found_iocs['filenames']}")
        print("----------------------\n")
        
        # Step 3: VirusTotal Enrichment
        print("=" * 55)
        print("   STARTING VIRUSTOTAL ENRICHMENT")
        print("=" * 55)
        
        for ip in found_iocs["ips"]:
            check_virustotal(ip)
            
        print("\n[+] Phase 6 VT Enrichment Complete!")
