# Analyzing SSH Log Files Using Splunk SIEM

## Introduction

**SSH (Secure Shell) logs provide critical insights into remote access activity, including login attempts, authentication results, and session details. By analyzing these logs using Splunk, security professionals can monitor access patterns, detect unauthorized attempts, and identify potential threats such as brute-force attacks.**

## Project Overview

**This project demonstrates how to upload and analyze SSH log files in Splunk SIEM to monitor login activity, detect anomalies, and investigate suspicious behavior.**

## Prerequisites

*Before starting, ensure:*

     Splunk is installed and configured
     SSH logs (e.g., auth.log / secure logs) are available or forwarded to Splunk
     Uploading SSH Logs to Splunk

> ***1. Prepare Log Files - The file I have used was [ssh_log.txt](./SSH%20%Log%20Analysis/ssh_log.txt)***

* Collect SSH log files (e.g., .txt, auth.log)
* Ensure logs include:
* Timestamp
* Source IP
* Username
* Login status (success/failed)
* Store logs in a Splunk-accessible location

> ***2. Add Data in Splunk***

<img width="182" height="183" alt="Screenshot 2026-03-30 at 11 26 09 AM" src="https://github.com/user-attachments/assets/36a34e00-d3fc-4945-8466-c048cae57833" />


* Log in to Splunk Web
* Navigate to Settings → Add Data
* Select Upload

> ***3. Select File***

* Click Select File and upload your SSH log file

> ***4. Configure Source Type***

<img width="287" height="193" alt="Screenshot 2026-03-30 at 3 44 22 PM" src="https://github.com/user-attachments/assets/a7fc9122-31f8-476e-82a3-8cd7d9b628f6" />

* Choose an appropriate sourcetype (e.g., linux_secure, ssh, or custom)

> ***5. Review Settings***

<img width="438" height="292" alt="Screenshot 2026-03-30 at 3 44 09 PM" src="https://github.com/user-attachments/assets/243ccb4c-de6f-4d62-b75e-f2eaffdd2ca1" />

* Verify index, host, and sourcetype
* Ensure correct configuration

> ***6. Upload Data***

* Click Review → Submit to ingest logs

> ***7. Verify Upload***

     index=<your_ssh_index> sourcetype=<your_ssh_sourcetype>

## Analyzing SSH Logs

> **1. Search for SSH Events**

<img width="1360" height="532" alt="Screenshot 2026-03-30 at 4 28 20 PM" src="https://github.com/user-attachments/assets/f920f097-ac2c-483b-9130-7496592d6ad4" />

     index=* sourcetype=ssh_sample

> **2. Extract Relevant Fields**

*Focus on:*

* src_ip (source IP)
* user (username)
* status (success/failed)

<img width="1344" height="564" alt="Screenshot 2026-03-30 at 4 29 52 PM" src="https://github.com/user-attachments/assets/22240385-d39d-4050-bf3c-c880da07f857" />


*Example using regex:*

      | rex field=_raw "from (?<src_ip>\d{1,3}(\.\d{1,3}){3})"
      | rex field=_raw "for (invalid user )?(?<user>\w+)"
      | rex field=_raw "(?<status>Failed|Accepted) password"

      | eval status=case(
          status=="Failed","failed",
          status=="Accepted","success",
          match(_raw,"session opened"),"success")

      | table _time user src_ip status

> **3. Analyze Login Activity**

*Successful Logins:*

<img width="1357" height="400" alt="Screenshot 2026-03-30 at 4 35 57 PM" src="https://github.com/user-attachments/assets/9b30ce2e-82f7-4e28-b574-98239d4db137" />


      index=* sourcetype=ssh_log.txt
      | rex field=_raw "(?<status>Failed|Accepted) password"
      | eval status=if(status=="Accepted","success","failed")
      | search status=success
      | stats count by user src_ip

*Failed Logins:*

<img width="1348" height="531" alt="Screenshot 2026-03-30 at 4 36 48 PM" src="https://github.com/user-attachments/assets/4d013858-895d-4dff-beb9-0f693aaa5573" />

      index=* sourcetype=ssh_log.txt
      | rex field=_raw "(?<status>Failed|Accepted) password"
      | eval status=if(status=="Failed","failed","success")
      | search status=failed
      | stats count by user src_ip

> **4. Detect Brute Force Attacks**

<img width="1358" height="456" alt="Screenshot 2026-03-30 at 4 43 00 PM" src="https://github.com/user-attachments/assets/4ee0562c-e219-4262-b6cd-dfbd60e13f18" />


      index=* sourcetype=ssh_log.txt "Failed password"
      | stats count by src_ip
      | sort -count

***Multiple failures from same IP = brute force attempt***

> **5. Identify Suspicious Login Patterns**

<img width="1360" height="516" alt="Screenshot 2026-03-30 at 4 43 45 PM" src="https://github.com/user-attachments/assets/dcb78b14-0809-4610-a7eb-9c3b5c41340d" />


      index=* sourcetype=ssh_sample
      | stats values(user) count by src_ip
      | sort -count

***High activity from a single IP may indicate compromise***

> **6. Detect Login After Failures**

<img width="1360" height="404" alt="Screenshot 2026-03-30 at 4 45 27 PM" src="https://github.com/user-attachments/assets/f88415cd-afc7-44c9-b865-fc3e7b41e712" />


      index=* sourcetype=ssh_sample ("Failed password" OR "Accepted password")
      | transaction src_ip maxspan=5m
      | search "Failed password" "Accepted password"

***Classic attack pattern: brute force → success***

> **7. Monitor Login Trends**

<img width="1358" height="371" alt="Screenshot 2026-03-30 at 4 45 53 PM" src="https://github.com/user-attachments/assets/42a2249e-e1f7-43e3-9d98-31003eb75d2f" />


      index=* sourcetype=ssh_sample
      | timechart span=10m count

***Spikes indicate automated attacks***

