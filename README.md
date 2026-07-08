# Splunk & SIEM Security Operations Center (SOC) Portfolio
**Author:** Pavan Kumar  
**Role:** SOC Manager / Detection Engineer  
**Contact:** [pavankumar022 (GitHub)](https://github.com/pavankumar022) | [pavankumar022 (LinkedIn)](https://www.linkedin.com/in/pavankumar022) | pavankumar797524@gmail.com

---

## Executive Summary
This portfolio demonstrates the design, deployment, and operation of a Security Information and Event Management (SIEM) environment using **Splunk Enterprise**. It showcases practical security analyst and engineering competencies across three primary projects:
1. **Active Endpoint Security Monitoring & Detection Engineering Lab:** Onboarding Windows Security and Sysmon logs, simulating credential attacks (MITRE ATT&CK T1110), and engineering noise-filtered detection rules.
2. **Linux SSH Authentication Monitoring Dashboard:** High-fidelity dashboard visualizing successful, failed, invalid, and brute-force logins with geo-location mapping.
3. **Apache Web Traffic Log Analysis Dashboard:** Operational and security dashboard tracking web requests, client/server errors, and request origin geo-locations.

---

## Project 1: SIEM Home Lab — Credential Attack Simulation & Detection Engineering
*Detailed report available in [SIEM_Brute_Force_Detection_Lab.pdf](file:///c:/Users/pavan/OneDrive/Documents/splunk/splunk_soc_projects/siem_home_lab/SIEM_Brute_Force_Detection_Lab.pdf)*

### 1. Lab Architecture & Data Pipeline
The security pipeline utilizes a physical victim machine forwarding telemetry to a virtualized Splunk SIEM instance.



* **Windows Host (BATMAN):** Monitored workstation running Sysmon (configured with SwiftOnSecurity baseline) and Splunk Universal Forwarder.
* **Splunk Enterprise (Ubuntu Server VM):** Receives forwarded logs on TCP 9997, indexes data, and runs search operations.
* **Kali Linux (Attacker VM):** Network assessment platform.

### 2. Onboarding Challenges & Log Tuning
During the onboarding phase, a critical logging issue was identified and resolved:
* **Issue:** The Universal Forwarder's `inputs.conf` initially had `renderXml = true`, rendering Sysmon logs as raw, unparsed XML blobs inside Splunk.
* **Impact:** Field-based queries (e.g., querying by `CommandLine` or `Image`) were non-functional because Splunk could not auto-extract fields.
* **Resolution:** Reconfigured `renderXml = false` in `inputs.conf` to restore standard Windows XML Event format, allowing Splunk's Sysmon sourcetype to parse fields natively.

### 3. Attack Simulation Pivot
* **Initial Plan:** Execute a remote dictionary attack using Hydra against RDP/SSH.
* **Reality:** Endpoint defenses (Windows Defender) and network-stack constraints dropped remote traffic before enough failed logons could be recorded.
* **Pivot:** Scripted a local loopback authentication attack against the local SMB stack on `BATMAN` with a rotating list of incorrect passwords.
* **SOC Significance:** This generated the exact log signature of a remote brute-force (Event Code 4625) through the Windows LSA authentication stack, ensuring realistic log generation while bypassing environment-specific blockers.

### 4. Detection Engineering & Refinement (MITRE ATT&CK T1110)
A native threshold rule of failed logons (`EventCode=4625`) was initially tested, showing high background noise:

#### Initial (Naive) Detection Rule:
```splunk
index=wineventlog EventCode=4625 
| stats count by Account_Name, Source_Network_Address 
| where count > 10
```

#### The Noise Obstacle:
Running this query returned two distinct accounts:
1. `pavan` (17 failed logon events, representing the simulated attack).
2. `BATMAN$` (11,843 failed logon events, representing background system activity).
* **Analysis:** `BATMAN$` is the local computer/machine account. Scheduled services and local processes trying to authenticate in the background created massive volumes of failures (Logon Type 8 - NetworkCleartext), completely masking the real attack.

#### Final Refined Detection Rule:
To prevent false-positive alert fatigue in a live SOC, the machine accounts (suffixed with `$`) were explicitly filtered out:
```splunk
index=wineventlog EventCode=4625 
| where NOT match(Account_Name, "\\$") 
| stats count by Account_Name, Source_Network_Address 
| where count > 10
```
This query isolated the **17 failed attempts** from the `pavan` account originating from Source Network Address `::1` (IPv6 loopback), identifying the true malicious signal.

---

## Project 2: Linux SSH Authentication Monitoring Dashboard
*Evidence and visualization configurations found in [splunk_dashbaord/](file:///c:/Users/pavan/OneDrive/Documents/splunk/splunk_soc_projects/splunk_dashbaord)*

This dashboard provides real-time visibility into SSH access attempts on Linux hosts, highlighting potential brute-force attempts and identifying geographic anomalies.

### 1. Dashboard Layout & Metrics
| Panel Title | Visualization Type | Splunk Search Query (SPL) | SOC Utility / Goal |
| :--- | :--- | :--- | :--- |
| **Total SSH Events** | Single Value | `source="ssh_logs.json" host="LinuxServer" sourcetype="_json" \| stats count AS "Total SSH Events"` | Tracks overall SSH noise and operational baseline. |
| **Successful Logins** | Single Value | `source="ssh_logs.json" host="LinuxServer" sourcetype="_json" event_type="Successful SSH Login" \| stats count AS "Successful Logins"` | Monitors authorized admin accesses. Anomalous time stamps indicate compromised accounts. |
| **Failed Logins** | Single Value | `source="ssh_logs.json" host="LinuxServer" sourcetype="_json" event_type="Failed SSH Login" \| stats count AS "Failed Logins"` | Early indicator of active scanning or dictionary attacks. |
| **Invalid User Attempts** | Single Value | `index=auth "sshd" "invalid user" \| stats count AS "Invalid User Attempts"` | Counts attempts targeting non-existent users (e.g., `admin`, `root`). High volume flags automated threat actors. |
| **Failed Logins by Username** | Bar Chart | `source="ssh_logs_new.json" host="LinuxNew" sourcetype="_json" event_type="Failed SSH Login" \| top username` | Identifies targeted accounts (e.g., specific user names). |
| **Possible Brute Force by IP** | Stats Table | `source="ssh_logs_new.json" host="LinuxNew" sourcetype="_json" event_type="Multiple Failed Authentication Attempts" \| top id.orig_h` | Groups attempts by source IP address to identify threat actors. |
| **Brute Force Geo-location** | Choropleth Map | `source="ssh_logs_new.json" host="LinuxNew" sourcetype="_json" event_type="Multiple Failed Authentication Attempts" \| table id.orig_h \| iplocation id.orig_h \| stats count by Country \| geom geo_countries featureIdField="Country"` | Maps brute-force activity to country of origin, helping analysts identify geographical risk. |

---

## Project 3: Apache Web Server Traffic Monitoring Dashboard
*Evidence and visualization configurations found in [splunk_dashbaord/](file:///c:/Users/pavan/OneDrive/Documents/splunk/splunk_soc_projects/splunk_dashbaord)*

Designed to audit external web traffic, identify application errors, detect denial-of-service (DoS) attempts, and geolocate client requests.

### 1. Dashboard Layout & Metrics
| Panel Title | Visualization Type | Splunk Search Query (SPL) | SOC Utility / Goal |
| :--- | :--- | :--- | :--- |
| **Total Web Requests** | Single Value | `source="apache_mixed_access_full (1).json" host="webserver" sourcetype="_json" \| stats count AS "Total Web Requests"` | Measures web traffic volume; flags sudden traffic spikes. |
| **Successful Responses (2xx)** | Single Value | `source="apache_mixed_access_full (1).json" host="webserver" sourcetype="_json" method=GET status=200 \| stats count AS "Successful Responses"` | Establishes the baseline for normal, operational user traffic. |
| **Client Errors (4xx)** | Single Value | `source="apache_mixed_access_full (1).json" host="webserver" sourcetype="_json" \| where status>=400 and status<500 \| stats count AS "Client Errors"` | Detects missing assets (404) or unauthorized attempts (401/403) from automated web scanners. |
| **Server Errors (5xx)** | Single Value | `source="apache_mixed_access_full (1).json" host="webserver" sourcetype="_json" \| where status>=500 and status<600 \| stats count AS "Server Errors"` | Identifies server-side application crashes, misconfigurations, or potential backend exhaustion. |
| **Top Requested URIs** | Bar Chart | `source="apache_mixed_access_full (1).json" host="webserver" sourcetype="_json" \| stats count AS "Hits" by uri` | Identifies which endpoints receive the most traffic; highlights scans for sensitive paths (e.g., `/wp-admin`, `.git`). |
| **Top Users by IP Address** | Bar Chart | `source="apache_mixed_access_full (1).json" host="webserver" sourcetype="_json" \| stats count AS IP by ip` | Identifies the most active client IPs; detects potential scraping or brute-force scanning. |
| **Web Traffic Geo-location** | Choropleth Map | `source="apache_mixed_access_full (1).json" host="webserver" sourcetype="_json" method=GET \| table ip \| iplocation ip \| stats count by Country \| geom geo_countries featureIdField="Country"` | Maps website traffic distribution globally to detect requests originating from unexpected regions. |

---

## Log Analysis & SOC Verification Principles
In this lab, several analysis rules were applied to differentiate security signals from operational noise:

1. **Event Code Distinction (4625 vs. 4648):**
   * **4625:** Explicitly indicates a *failed* login attempt.
   * **4648:** Indicates a process attempted to use alternate/explicit credentials (often normal administrative tasks or scheduled processes), which does not represent a failed login. We filter out 4648 to keep alerts clean.
2. **User vs. Machine Context:**
   * Distinguishing human failures from machine accounts (`$` suffix) prevents background noise from generating high volumes of false alerts.
3. **Logon Type Audit:**
   * **Logon Type 3 (Network):** Confirms authentication via network shares (e.g., SMB/RDP), which matches the simulated attack.
   * **Logon Type 8 (NetworkCleartext):** Common to administrative cleartext password tasks; flagged as routine environment noise in this project.
4. **Source Address Verification:**
   * Verifying source IP addresses (`::1` for loopback in the local test vs. external IPs) ensures that simulated attacks are correctly attributed to internal testing rather than external adversaries.

---

## Integration of AI in a Modern SOC (Future-Proofing)
Integrating Artificial Intelligence (AI) and Machine Learning (ML) can improve threat detection in several ways:

1. **Behavioral Anomaly Detection (Evading Thresholds):**
   * *Problem:* A simple threshold query (`count > 10`) can be bypassed by an attacker using a "low and slow" approach (e.g., 2 failed attempts per hour).
   * *AI Solution:* AI models establish a dynamic baseline for each user account. If an account suddenly logs in from a new country or at an unusual hour, the AI flags the activity as anomalous, even if it remains below static thresholds.
2. **Intelligent False-Positive Triage:**
   * *AI Solution:* A Large Language Model (LLM) agent can analyze recurring failures from machine accounts like `BATMAN$`. By cross-referencing these failures with Active Directory and change management logs, the AI can classify them as benign background noise, reducing alert fatigue.
3. **Natural Language Querying (NLIDb):**
   * *AI Solution:* Analysts can query the SIEM in natural language (e.g., *"Show me all web traffic client errors originating from Europe over the past 24 hours"*), and the AI automatically translates the request into an optimized Splunk SPL query.
4. **Automated Incident Summarization & Response (SOAR):**
   * *AI Solution:* When a brute-force attack is confirmed, AI-driven Security Orchestration, Automation, and Response (SOAR) can summarize the incident and automatically trigger defensive playbooks (e.g., block the attacking IP, isolate the compromised endpoint, or prompt the user for MFA).

---

## References & Lab Screenshots
* **Project Lab PDF Report:** [SIEM_Brute_Force_Detection_Lab.pdf](file:///c:/Users/pavan/OneDrive/Documents/splunk/splunk_soc_projects/siem_home_lab/SIEM_Brute_Force_Detection_Lab.pdf)
* **Home Lab Evidence Screenshots:** [siem_home_lab/evidence/](file:///c:/Users/pavan/OneDrive/Documents/splunk/splunk_soc_projects/siem_home_lab/evidence)
* **Splunk Dashboard Screenshots:** [splunk_dashbaord/](file:///c:/Users/pavan/OneDrive/Documents/splunk/splunk_soc_projects/splunk_dashbaord)
