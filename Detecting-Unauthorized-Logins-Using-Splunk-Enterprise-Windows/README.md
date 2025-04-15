# Detecting Unauthorized Logins Using Splunk Enterprise (Windows)

## Overview
This project focuses on setting up **Splunk Enterprise on Windows**, ingesting security logs, and analyzing login activity to detect unauthorized access.

## Key Steps & Implementation

### 1. Configure Log Ingestion
#### Enable Windows Event Logging
- Open **Event Viewer** (`Win + R` → `eventvwr.msc`).
- Navigate to **Windows Logs** → **Security**.
- Look for:
  - **Event ID 4624** (Successful Logins)
  - **Event ID 4625** (Failed Logins)
  - **Event ID 1102** (Log Cleared)

#### Add Windows Security Logs to Splunk
- Open **Splunk Web** (`http://localhost:8000`).
- Go to **Settings** → **Data inputs** → **Local Event Logs**.
- Click **New** → Select **Security Logs (`WinEventLog:Security`)**.
- Click **Save & Restart Splunk** to apply changes.

### 2. Perform Log Analysis
#### View All Login Attempts
```spl
index=main source="WinEventLog:Security" EventCode=4624 OR EventCode=4625
| table _time user src_ip EventCode
```
- `4624` → Successful Login  
- `4625` → Failed Login  

#### Detect Multiple Failed Login Attempts
```spl
index=main source="WinEventLog:Security" EventCode=4625
| bucket _time span=10m
| stats count by user, src_ip
| where count > 5
| sort -count
```
🔹 **Insight:** A high number of failed logins within a short time might indicate a brute-force attack.

#### Detect Logins from Unusual IPs
```spl
index=main source="WinEventLog:Security" EventCode=4624
| stats values(src_ip) AS ip_list by user
| mvexpand ip_list
| eventstats dc(ip_list) AS unique_ips by user
| where unique_ips > 1
```
🔹 **Insight:** If a user logs in from multiple locations in a short time, it might indicate account compromise.

### 3. Create a Splunk Dashboard
#### Failed Login Chart
- Go to **Dashboards** → **Create New Dashboard**.
- Add a **bar chart** with this query:
  ```spl
  index=main source="WinEventLog:Security" EventCode=4625
  | stats count by src_ip
  ```
- Set visualization to **Bar Chart**.

#### Login Type Pie Chart
```spl
index=main source="WinEventLog:Security" EventCode=4624 OR EventCode=4625
| stats count by EventCode
```
🔹 **Visualize the ratio of successful vs failed logins.**

#### Recent Logins Table
```spl
index=main source="WinEventLog:Security" EventCode=4624 OR EventCode=4625
| table _time user src_ip EventCode
```

### 4. Set Up Alerts (Optional)
#### Alert for Multiple Failed Logins
- Go to **Alerts** → **Create New Alert**.
- Use this trigger condition:
  ```spl
  index=main source="WinEventLog:Security" EventCode=4625
  | stats count by user, src_ip
  | where count > 5
  ```
