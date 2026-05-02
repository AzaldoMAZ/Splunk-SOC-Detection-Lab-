# Splunk-SOC-Detection-Lab-
# 🛡️ Splunk SIEM & Threat Detection Lab

**I built a mini Security Operations Center (SOC) on my laptop.** I set up a "hacker" machine and a "victim" machine, attacked myself with real offensive tools, then used Splunk to catch every single attack — just like a real SOC analyst would.

Then I went a step further: I wrote a Python script that automatically pulls alerts from Splunk and checks them against VirusTotal's threat intelligence database. No more copy-pasting IPs — the script does it for me in seconds.

---

## 🤔 What Is This Project?

Imagine a security camera system, but for computers. Instead of watching video footage for burglars, I'm watching **digital logs** for hackers.

Here's the simple version:

```
🔴 ATTACKER (Kali Linux)          🔵 DEFENDER (Windows + Splunk)
─────────────────────              ──────────────────────────────
Scans for open doors       ──►    Splunk sees the scan
Tries 1000 passwords       ──►    Splunk counts the failures  
Plants a backdoor          ──►    Splunk catches the callback
Steals credentials         ──►    Splunk logs the attempt
                                        │
                                        ▼
                                  🤖 Python Script
                                  Auto-checks the evidence
                                  against VirusTotal
```

**Every real company has this exact setup** — just at a bigger scale. I built a working version on my laptop to prove I can do the job.

---

## 🧰 Tools I Used (And What Each One Does)

| Tool | What It Does | Real-World Equivalent |
|------|-------------|----------------------|
| **Splunk Enterprise** | Collects and searches through millions of log entries | The "Google search" for security logs |
| **Sysmon** | Records every process, network connection, and file change on Windows | A detailed security camera for your computer |
| **Kali Linux** | The hacker's toolkit — comes pre-loaded with offensive tools | What penetration testers actually use |
| **VirtualBox** | Runs Kali as a virtual computer inside my real computer | Safe sandbox so nothing escapes |
| **Metasploit + SET** | Generates payloads and manages reverse shell connections | Industry-standard penetration testing framework |
| **Mimikatz** | Attempts to dump credentials from Windows memory | The most feared credential theft tool |
| **Python** | Automates the boring analyst work (checking IPs, pulling alerts) | What SOC teams build for efficiency |
| **VirusTotal API** | Checks if an IP address or file is known to be malicious | The world's largest malware database |
| **MITRE ATT&CK** | A catalogue of every known hacker technique | The "dictionary" of cyber attacks |

---

## 🏗️ How The Lab Is Set Up

```
┌──────────────────────────────────────────────────────────────┐
│                        MY LAPTOP                             │
│                                                              │
│   ┌─────────────────────┐    ┌────────────────────────────┐  │
│   │  🔴 KALI LINUX      │    │  🔵 WINDOWS 11             │  │
│   │  (Virtual Machine)  │    │  (My actual computer)      │  │
│   │                     │    │                            │  │
│   │  IP: 192.168.56.101 │    │  IP: 192.168.56.1          │  │
│   │                     │    │                            │  │
│   │  Tools:             │    │  Defenses:                 │  │
│   │  • Nmap (scanner)   │    │  • Sysmon (sensor)         │  │
│   │  • Hydra (passwords)│    │  • Splunk (SIEM)           │  │
│   │  • Metasploit (C2)  │    │  • Python (automation)     │  │
│   │  • Mimikatz (creds) │    │                            │  │
│   └──────────┬──────────┘    └──────────────┬─────────────┘  │
│              │         Private Network       │               │
│              │        192.168.56.0/24        │               │
│              └───────────────────────────────┘               │
│              (isolated — can't reach the internet)           │
└──────────────────────────────────────────────────────────────┘
```

---

## 🔧 Phase 1: Building The Lab From Scratch

### Step 1 — Creating The Attacker VM

I created a Kali Linux virtual machine in VirtualBox. This is the "hacker" machine I'll launch attacks from:

![Creating the Kali Linux VM in VirtualBox — selecting the ISO image and naming the machine](screenshots/01_VirtualBox_Creating_Kali_VM.png)

I configured the hardware — 2GB RAM and 2 CPU cores, enough to run offensive tools smoothly:

![VM hardware settings: 2048MB RAM, 2 CPUs allocated](screenshots/02_VM_Hardware_2GB_RAM_2CPUs.png)

### Step 2 — Configuring The Network

This is the critical part. I gave Kali **two network adapters**:
- **Adapter 1 (NAT):** Lets Kali access the internet (for updates and tool downloads)
- **Adapter 2 (Host-Only):** Creates a private connection between Kali and Windows (for attacks)

![VirtualBox network settings showing Adapter 2 configured as Host-Only Adapter](screenshots/03_Network_Adapters_NAT_HostOnly.png)

### Step 3 — Installing Kali Linux

I ran through the Kali installer — setting up the hostname, creating a user account, and installing the full operating system:

![Kali Linux installer running — hostname and user configuration](screenshots/04_Kali_Installer_Running.png)

Installation complete — GRUB boot loader installed successfully:

![Kali installation finished — GRUB boot loader confirmed](screenshots/05_Kali_Install_Complete_GRUB.png)

### Step 4 — Verifying Network Connectivity

After boot, I confirmed both network adapters are working. This is the money shot — `eth0` has `10.0.2.15` (internet via NAT) and `eth1` has `192.168.56.101` (private lab network):

![Kali terminal showing both networks active — 10.0.2.15 (NAT) and 192.168.56.101 (Host-Only)](screenshots/06_Both_Networks_Working_NAT_HostOnly.png)

On the Windows side, I verified the host IP configuration:

![Windows PowerShell ipconfig showing all network adapters](screenshots/07_Windows_IPConfig_All_Adapters.png)

I verified the VirtualBox Host-Only Network Manager is configured correctly at `192.168.56.1/24`:

![VirtualBox Host-Only Network Manager showing DHCP and adapter configuration](screenshots/08_VirtualBox_HostOnly_Network_Manager.png)

**The connectivity test — Kali successfully pings Windows with 0% packet loss:**

![Kali pinging 192.168.56.1 — 0% packet loss, network is live](screenshots/09_Kali_Ping_Windows_0_Percent_Loss.png)

> **Why this matters:** If these two machines can't talk to each other, none of the attacks will work. This ping proves the private network is functioning.

---

### Step 5 — Installing Sysmon (The Security Camera)

**Sysmon** is a free Microsoft tool that records extremely detailed information about everything happening on a Windows computer: every program that runs, every network connection made, every file created. Without it, Splunk would only see basic Windows logs, missing most of the interesting attack details.

I installed it with the **SwiftOnSecurity** configuration — a community-maintained ruleset that filters out noise and focuses on security-relevant events:

![PowerShell showing Sysmon v15.20 installed with SwiftOnSecurity config](screenshots/10_Sysmon_Install_SwiftOnSecurity.png)

Configuration validated and updated successfully:

![Sysmon configuration validated — "Sysmon64 started" confirmation](screenshots/11_Sysmon_Config_Validated.png)

### Step 6 — Installing & Configuring Splunk

I downloaded Splunk Enterprise and configured it to collect logs. The key step is writing `inputs.conf` — this tells Splunk exactly which log sources to monitor:

![Splunk Enterprise download via PowerShell](screenshots/12_Splunk_Download_PowerShell.png)

Configuring log source collection through the Splunk web interface:

![Splunk "Add Data" page — selecting which Windows Event Logs to ingest](screenshots/13_Splunk_Add_Data_Log_Sources.png)

Here's the `inputs.conf` I wrote — it tells Splunk to collect four log sources:

| Log Source | What It Contains |
|-----------|-----------------|
| `WinEventLog://Application` | Application crashes, software installs |
| `WinEventLog://Security` | Logins, failed logins, account changes |
| `WinEventLog://System` | Driver loads, service starts/stops |
| `WinEventLog://Microsoft-Windows-Sysmon/Operational` | **The gold mine** — process creation, network connections, file hashes |

![PowerShell showing inputs.conf configuration written to Splunk's local directory](screenshots/14_Splunk_Inputs_Conf_Written.png)

The full build chain — Sysmon + Splunk + inputs.conf all working together:

![Complete PowerShell build chain showing all components configured](screenshots/15_Full_Build_Chain_PowerShell.png)

---

## ⚔️ Phase 2: Running The Attacks

### Attack 1 — Nmap Port Scan (Reconnaissance)
**MITRE ATT&CK:** [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)

> **What Nmap does in plain English:** It knocks on every single "door" (port) on the target computer to see which ones are open. An open port means there's a service running that a hacker might be able to exploit.

I launched a comprehensive scan from Kali targeting the Windows host:

```bash
sudo nmap -A -T4 -p- 192.168.56.1
```

![Kali terminal running Nmap 7.98 scan against 192.168.56.1](screenshots/16_Nmap_Scan_From_Kali.png)

**🔍 Splunk Detection:** The scan generated **1,103 network connection events** in Splunk within seconds. That massive green spike on the timeline is impossible to miss:

```sql
index=main source="*Sysmon*" EventCode=3 | timechart span=1h count
```

![Splunk showing 1,103 Sysmon EventCode=3 events — massive green spike on the timeline from the Nmap scan](screenshots/17_Splunk_Nmap_1103_Events_Detected.png)

> **Why this matters:** A normal computer makes maybe 5-10 network connections per minute. Seeing 1,103 in a few seconds is a dead giveaway that someone is scanning your network. This is often the first thing a SOC analyst notices.

---

### Attack 2 — Brute Force (Password Guessing)
**MITRE ATT&CK:** [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)

> **What a brute force attack does in plain English:** It's like trying every single key on a keyring to see which one opens the lock. The attacker fires hundreds of password guesses at a login page until one works.

I simulated a brute force attack using PowerShell, rapidly generating failed logon attempts under a fake username "Hacker":

```powershell
1..10 | ForEach-Object { net use \\localhost\c$ /user:Hacker "FakePassword" 2>$null }
```

![PowerShell showing the brute force simulation command and Splunk service restart](screenshots/18_Brute_Force_Simulation_PowerShell.png)

**🔍 Splunk Detection:** Splunk immediately caught the `Account_Name: Hacker` across Windows Security **Event ID 4625** (Failed Logon):

```sql
index=* source="*Security*" EventCode=4625 | stats count by Account_Name
```

![Splunk catching the "Hacker" account in EventCode 4625 — the attacker's fake username is exposed](screenshots/19_Splunk_Hacker_Account_EventCode_4625.png)

I visualized the brute force data in multiple ways — the column chart shows the attack volume clearly:

![Splunk column chart visualization — brute force attempts by Account_Name](screenshots/20_Splunk_Brute_Force_Column_Chart.png)

And the pie chart shows the "Hacker" account taking up the majority of failed logins:

![Splunk pie chart — "Hacker" account dominates failed login attempts](screenshots/21_Splunk_Brute_Force_Pie_Chart.png)

> **Why this matters:** In a real SOC, seeing dozens of failed logins from the same account in rapid succession triggers an immediate alert. This is one of the most common attack patterns analysts deal with daily.

---

### Attack 3 — Reverse Shell via Metasploit + SET (Backdoor)
**MITRE ATT&CK:** [T1204.002 — Malicious File Execution](https://attack.mitre.org/techniques/T1204/002/) + [T1571 — Non-Standard Port](https://attack.mitre.org/techniques/T1571/)

> **What a reverse shell does in plain English:** The attacker tricks the victim into running a program (`hello.exe`) that secretly "phones home" to the attacker's computer. Once connected, the attacker can control the victim's computer remotely — like a puppet on strings.

This was a full attack chain. Here's every step:

**Step 1 — Launching the Social-Engineer Toolkit (SET)** to generate the payload:

![Kali terminal — SET (Social-Engineer Toolkit) main menu, option 4: Create a Payload and Listener](screenshots/22_SET_Toolkit_Payload_Menu.png)

**Step 2 — Hosting the malicious payload** on Apache. I copied `payload.exe` to `/var/www/html/hello.exe` so the victim can "download" it:

![Kali — Apache started, payload.exe renamed to hello.exe and staged in /var/www/html/](screenshots/23_Apache_Hosting_Payload_Hello_Exe.png)

**Step 3 — Setting up the Metasploit handler** to catch the incoming connections:

![Metasploit handler started — LHOST=192.168.56.101, LPORT=4444, sending stages to 192.168.56.1](screenshots/24_Metasploit_Handler_Sessions_Open.png)

**Step 4 — BOOM! 14 Meterpreter sessions opened.** The victim executed `hello.exe` and the attacker now has full remote control:

![Metasploit showing 14 active Meterpreter sessions — full shell access to the Windows host at C:\Users\azald\Downloads>](screenshots/25_Meterpreter_14_Sessions_Shell_Access.png)

> **What you're seeing:** Each "session" is a separate backdoor connection. `sessions -i 1` drops into a live shell on the victim's Windows machine. The attacker can now run any command — `whoami` confirms we're running as `AZALDO\azald`.

**🔍 Splunk Detection:** Splunk caught **3,544 Sysmon events** related to the reverse shell — every single process and network connection the backdoor made:

![Splunk search results — 3,544 Sysmon EventCode=1 events showing hello.exe process creation](screenshots/26_Splunk_Reverse_Shell_3544_Events.png)

Drilling into the event detail reveals the smoking gun — `hello.exe` connecting to `192.168.56.101` on **port 4444** (Metasploit's default):

![Splunk event detail — Image: hello.exe, DestinationIp: 192.168.56.101, DestinationPort: 4444](screenshots/27_Splunk_Hello_Exe_Port_4444_Detail.png)

> **Why port 4444 matters:** Every SOC analyst knows this is Metasploit's default port. Seeing any outbound connection to port 4444 is an immediate red flag. Real attackers use ports 443 or 80 to blend in with normal web traffic.

---

### Attack 4 — Mimikatz (Credential Theft)
**MITRE ATT&CK:** [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

> **What Mimikatz does in plain English:** It tries to read the computer's memory to find passwords stored there. Imagine someone picking a lock on a safe that holds all your keys — that's Mimikatz.

I ran Mimikatz from an elevated shell:
```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

> **Interesting finding:** Windows 11's **LSA Protection** blocked the memory dump! But Sysmon still recorded the *attempt* — and in cybersecurity, catching the attempt is just as valuable as catching a success.

**🔍 Splunk Detection:** Splunk found **9 events** related to Mimikatz, including process creation with the full command line and embedded metadata:

```sql
index=main "mimikatz"
```

![Splunk showing 9 Mimikatz-related events — Description: "mimikatz for Windows", OriginalFileName: mimikatz.exe, CommandLine visible](screenshots/28_Splunk_Mimikatz_9_Events_Detected.png)

Expanding the event detail reveals everything a forensic analyst needs:

![Splunk event detail — Product: mimikatz, Company: gentilkiwi (Benjamin DELPY), OriginalFileName: mimikatz.exe, CommandLine, Hashes, IntegrityLevel: High](screenshots/29_Splunk_Mimikatz_OriginalFileName_Detail.png)

Using the more targeted `OriginalFileName` search to catch Mimikatz even if renamed:

```sql
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 OriginalFileName="mimikatz.exe"
```

![Splunk forensic detail — CommandLine, Image path, IntegrityLevel, Source, Hashes all visible](screenshots/30_Splunk_Mimikatz_Forensic_Fields.png)

> **Pro tip:** Attackers rename `mimikatz.exe` to things like `svchost.exe` to evade basic detection. But Sysmon reads the file's **embedded metadata** (`OriginalFileName`), so it catches Mimikatz regardless of what the file is named on disk. That's why we search `OriginalFileName` instead of `Image`.

---

## 📊 Phase 3: Building The SOC Dashboard

I built a **5-panel Threat Hunting Dashboard** in Splunk that gives a bird's-eye view of all attack activity at a glance — just like what you'd see on the big screens in a real SOC.

### Building the dashboard — adding the first panel with the C2 detection SPL query:

![Splunk Dashboard Editor — "SOC Threat Detection Dashboard", adding a Line Chart panel with the reverse shell C2 query](screenshots/31_Dashboard_Adding_C2_Panel_SPL.png)

### Configuring the C2 Callbacks chart with overlay settings:

![Dashboard editor — Chart Overlay configuration for the reverse shell C2 panel](screenshots/32_Dashboard_C2_Chart_Overlay.png)

### The complete 5-panel dashboard:

![Full SOC Threat Detection Dashboard — all 5 panels visible: Reverse Shell C2 Callbacks, Network Connection Volume, Mimikatz Execution Detail, Brute Force/Failed Logon Storm, and Mimikatz Executions Detected (count: 1)](screenshots/33_Dashboard_Full_5_Panel_Overview.png)

| Panel | Chart Type | What It Shows |
|-------|-----------|---------------|
| **Reverse Shell C2 Callbacks** | Line Chart | Network traffic on port 4444 — spikes show when the backdoor was active |
| **Network Connection Volume** | Column Chart | Overall Sysmon network events — the Nmap scan creates a massive pink spike |
| **Mimikatz Execution Detail** | Table | Forensic breakdown: exact time, command used, image path, integrity level |
| **Brute Force / Failed Logon Storm** | Area Chart | Failed login spikes from the password guessing attack |
| **Mimikatz Executions Detected** | Single Value | A big number counting credential theft attempts (1) |

> **In a real SOC, dashboards like this are projected on big screens so the entire team can monitor threats in real-time.**

---

## 🤖 Phase 4: Automating The Analysis (Python SOAR Script)

> **The problem:** Every time Splunk fires an alert, a human analyst has to manually copy the IP address, go to VirusTotal.com, paste it in, wait for results, then write it all up. With hundreds of alerts per day, this is painfully slow.
>
> **My solution:** I wrote a Python script (`enrichment.py`) that does it all automatically in under 3 seconds.

### How The Script Works

```
Step 1                    Step 2                    Step 3
──────                    ──────                    ──────
Log into Splunk    ──►    Run the SPL query   ──►   Pull out the
using the REST            for reverse shell         attacker's IP
API (port 8089)           alerts                    and malware name
                                                         │
                                                         ▼
Step 4                    Step 5
──────                    ──────
Send the IP to     ──►   Print a clean
VirusTotal API            report with
for reputation            threat scores
scoring
```

### Setting up the environment

First, I installed the Python dependencies (`requests` and `urllib3`):

![PowerShell — pip install requests urllib3, all requirements satisfied](screenshots/34_Python_Pip_Install_Dependencies.png)

### Running the script — Splunk authentication and IOC extraction

After fixing the credentials, the script successfully authenticated with Splunk, processed **44 events**, and extracted the IOCs:

![Script output — Authenticated, Search job SID: 1777120934.1398, Processing 44 events, Found 1 Unique IP: 192.168.56.101, Found 1 Unique Filename: hello.exe — TEST SUCCESSFUL](screenshots/35_Script_Auth_Success_44_Events_IOCs.png)

Clean view of the extracted IOCs ready for enrichment:

![Script output — Splunk extraction complete, IPs: 192.168.56.101, Files: hello.exe, ready for VirusTotal enrichment](screenshots/36_Script_Splunk_Extracted_IOCs_Clean.png)

### Integrating VirusTotal for threat intelligence

I added VirusTotal API integration. The script now sends IOCs to VirusTotal automatically and reports the results:

![Script output — Phase 6: EXTRACTED IOCS section, STARTING VIRUSTOTAL ENRICHMENT, checking 192.168.56.101 against VirusTotal](screenshots/37_Script_VT_Enrichment_IOC_Extraction.png)

Here's the VirusTotal API dashboard showing the API key and quota (4 lookups/minute on the free tier):

![VirusTotal API Key page — showing API quota allowances, 4 lookups per minute](screenshots/38_VirusTotal_API_Key_Dashboard.png)

### The final output — complete automated enrichment

The full pipeline running end-to-end: Splunk authentication → search → IOC extraction → VirusTotal enrichment → clean report:

![Complete enrichment script output — SOC PHASE 6, Authenticated, 44 events, EXTRACTED IOCS, VirusTotal Report for 192.168.56.101: Malicious flags: 0, Suspicious flags: 0, Phase 6 VT Enrichment Complete!](screenshots/39_Script_Full_VT_Enrichment_Complete.png)

> **Why 0 malicious flags?** Because `192.168.56.101` is a private lab IP that doesn't exist on the internet. In a real SOC, this script would flag actual malicious IPs with real threat scores. The code works exactly the same either way — the logic is production-ready.

### Advanced SPL — 41,674 Sysmon process creation events

For deeper hunting, I wrote an advanced SPL query that parses through all Sysmon EventCode=1 (process creation) events with time filtering:

![Splunk search — advanced SPL with eval, table, and strptime functions, returning 41,674 events from Sysmon](screenshots/40_Splunk_Advanced_SPL_41674_Events.png)

---

## 🎯 MITRE ATT&CK Coverage

Every detection I built maps to the [MITRE ATT&CK Framework](https://attack.mitre.org/) — the industry-standard catalogue of adversary techniques:

| Attack Phase | Technique | ID | How I Detected It |
|-------------|-----------|-----|-------------------|
| **Reconnaissance** | Network Service Discovery | T1046 | Sysmon EventCode=3 spike (1,103 events) |
| **Initial Access** | Brute Force | T1110 | Windows EventCode 4625 storm |
| **Execution** | User Execution: Malicious File | T1204.002 | Sysmon process creation of `hello.exe` |
| **Command & Control** | Non-Standard Port | T1571 | Outbound connection to port 4444 |
| **Credential Access** | OS Credential Dumping: LSASS | T1003.001 | Mimikatz `OriginalFileName` detection |

---

## 📁 What's In This Repo

```
splunk-siem-detection-lab/
│
├── 📄 README.md                ← You are here
├── 🐍 enrichment.py            ← Python SOAR automation script (Splunk API + VirusTotal)
├── 📝 Splunk_Queries.txt       ← All 5 custom SPL detection queries
├── 📊 SOC_Lab_Presentation.pptx ← Project presentation slides
│
└── 📸 screenshots/             ← 40 annotated screenshots covering every phase
    ├── 01-09: Lab infrastructure & network setup
    ├── 10-15: Sysmon + Splunk installation
    ├── 16-21: Nmap & Brute Force attacks + detections
    ├── 22-27: Reverse shell full attack chain + Splunk detection
    ├── 28-30: Mimikatz credential theft + forensic analysis
    ├── 31-33: SOC Threat Detection Dashboard build
    └── 34-40: Python enrichment script + VirusTotal automation
```

---

## 💡 What I Learned

1. **Sysmon is essential.** Without it, Splunk only sees basic Windows logs and misses most attack details. The SwiftOnSecurity config filters noise while keeping the events that matter.

2. **OriginalFileName defeats evasion.** Hackers rename tools all the time. Sysmon reads the file's internal metadata, catching Mimikatz even if it's disguised as `svchost.exe`.

3. **Automation saves hours.** Manually checking one IP takes ~5 minutes. My Python script does it in 3 seconds. At enterprise scale with hundreds of alerts, that's the difference between analyst burnout and actual security.

4. **Modern Windows defenses work.** Windows 11's LSA Protection blocked Mimikatz from dumping credentials. But the *attempt* was still logged — proving detection and prevention are complementary layers.

5. **Port 4444 is low-hanging fruit.** Every analyst knows Metasploit defaults to port 4444. Real attackers use 443 or 80 to blend in with normal traffic. This lab shows why signature-based detection is a starting point, not a complete strategy.

6. **Full attack chains reveal more than single events.** Running the entire SET → Apache → Metasploit → Meterpreter chain shows how each tool leaves distinct forensic traces. Real SOC work is about connecting these dots.

---

## 👤 Author

**Azaldo** — Aspiring SOC Analyst

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat-square&logo=linkedin)](https://linkedin.com)

---

*Built entirely on a personal laptop with 8GB RAM using free, open-source tools. Total cost: $0.*
