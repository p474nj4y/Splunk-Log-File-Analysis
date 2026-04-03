# FTP Threat Monitoring & Analysis Using Splunk SIEM
 ## Introduction

**FTP (File Transfer Protocol) logs provide deep visibility into file transfer operations across a network. By analyzing these logs in Splunk, security analysts can track user activity, detect suspicious transfers, and identify potential data exfiltration or unauthorized access.**

## Project Overview

**This project focuses on ingesting and analyzing FTP logs to simulate real-world SOC monitoring. It demonstrates how to:**

* Monitor file transfer behavior
* Detect anomalies and suspicious activity
* Investigate user actions and access patterns
* Identify potential security threats like data exfiltration

## Prerequisites

**Before starting, ensure:**

_Splunk is installed and properly configured
FTP logs are being forwarded or available for upload
 Uploading FTP Logs to Splunk_
 
**1. Prepare Log Files - The file that I have used here was [ftp_log.txt](ftp_log.txt) which I generated using [ftplog_gen.py](ftplog_gen.py) and this was my path - pipo/splunk_logs/ftp/ftp_log.txt**

* Collect FTP logs in .txt or similar format
* Ensure logs include:
* Timestamp
* Source IP
* Username
* Commands (GET, PUT, LOGIN, etc.)
* File paths / filenames

***Store them in a Splunk-accessible directory***

**2. Add Data in Splunk**

* Log in to Splunk Web
* Navigate to Settings → Add Data

<img width="535" height="151" alt="Screenshot 2026-03-29 at 11 23 56 PM" src="https://github.com/user-attachments/assets/82d6c4c8-14c0-4ded-a4a5-ca3792901388" />

* Choose Monitor

<img width="318" height="183" alt="Screenshot 2026-03-29 at 11 24 04 PM" src="https://github.com/user-attachments/assets/165248d2-df6f-4348-a055-8a85611a161d" />

**3. Select File**

_Click Select Files & directories and upload your FTP log file with you destined path :)_

<img width="341" height="55" alt="Screenshot 2026-03-29 at 11 24 46 PM" src="https://github.com/user-attachments/assets/cf7b79d4-8baa-4a82-a261-2a44f16f6cf6" />

**4. Configure Source Type**

* Assign a sourcetype (e.g., ftp or custom)
* Helps with accurate parsing and analysis

<img width="1356" height="338" alt="Screenshot 2026-03-29 at 11 27 47 PM" src="https://github.com/user-attachments/assets/23c165d8-2e53-4e70-bde4-c49b15eb0536" />


**5. Review Settings**
   
___Verify:___

* Index
* Host
* Sourcetype
* Ensure everything matches your dataset

<img width="395" height="210" alt="Screenshot 2026-03-29 at 11 28 18 PM" src="https://github.com/user-attachments/assets/b524eaca-d900-463e-9258-0e60129088a6" />

**7. Validate Data**

<img width="1353" height="533" alt="Screenshot 2026-03-29 at 11 40 39 PM" src="https://github.com/user-attachments/assets/1c1c3ee8-57b8-402c-abb8-0eec3a59c89f" />

    index=<your_ftp_index> sourcetype=<your_ftp_sourcetype>

# FTP Log Analysis & Threat Detection :>

> **1. Retrieve FTP Events**

<img width="1342" height="532" alt="Screenshot 2026-03-29 at 11 41 16 PM" src="https://github.com/user-attachments/assets/761bc60b-f6fc-43d3-9876-88f72c9b4f10" />

    > index=* sourcetype=ftp_sample

> **2. Extract Key Fields**

## Use regex to extract important attributes:

<img width="1343" height="557" alt="Screenshot 2026-03-29 at 11 44 52 PM" src="https://github.com/user-attachments/assets/ca12ae55-aa5b-4adc-a4f1-344523d44665" />


    | | rex "SRC_IP=(?<src_ip>\S+)"
    | rex "USER=(?<user>\S+)"
    | rex "COMMAND=(?<command>\S+)"
    | rex "FILE=(?<file>\S+)"
    | rex "STATUS=(?<status>\S+)"
    | table _time src_ip user command file status

 ### Extracted fields:

* _time - timestamp
* src_ip -	source_ip
* user -	username
* command -	command
* file -	file_path

 # SOC Use Cases & Detection Scenarios

**1.  File Transfer Activity Monitoring**

*Track volume and behavior:*

<img width="1360" height="528" alt="Screenshot 2026-03-29 at 11 53 05 PM" src="https://github.com/user-attachments/assets/8a76a685-f962-4ad5-a17f-3bf83c10c847" />


    index=* sourcetype=ftp_sample
    | stats count by username, source_ip

*Helps identify heavy users or unusual activity*

**2.  Detect Data Exfiltration**

*Look for large or frequent uploads:*

<img width="1341" height="519" alt="Screenshot 2026-03-29 at 11 56 31 PM" src="https://github.com/user-attachments/assets/383a0693-f6b5-42f1-bffb-3235ca45d37f" />

    index=* sourcetype=ftp_sample command=PUT
    | stats count by source_ip, username 
    | sort -count


**3. Detect Brute Force / Unauthorized Access**

<img width="1351" height="521" alt="Screenshot 2026-03-30 at 12 02 28 AM" src="https://github.com/user-attachments/assets/19ee6b4b-09e7-4d64-a55d-1ef79581802c" />

    index=main sourcetype=ftp_logs "FAILED"
    | stats count by SRC_IP, USER

*Multiple failed logins = possible brute-force attack*

**4. Detect Anomalies in Transfer Volume**
   <img width="1349" height="527" alt="Screenshot 2026-03-30 at 12 04 23 AM" src="https://github.com/user-attachments/assets/07fc60ae-3b40-4898-8d8b-cb871dc2d095" />

    index=main sourcetype=ftp_logs
    | timechart span=10m count as event_count

*Sudden spikes may indicate automated activity or compromise*

**5. Suspicious File Access**
  
   <img width="1342" height="520" alt="Screenshot 2026-03-30 at 12 05 32 AM" src="https://github.com/user-attachments/assets/77d5ea1b-5f1f-42ed-bfb1-ab9e635d2903" />

    index=main sourcetype=ftp_logs (FILE="*.exe" OR FILE="*.zip")
    | stats count as access_count by FILE, SRC_IP
    | sort -access_count

*Executables or archives often linked to malware/data theft*

**6. User Behavior Analysis**

<img width="1359" height="571" alt="Screenshot 2026-03-30 at 12 07 01 AM" src="https://github.com/user-attachments/assets/0e0b270e-ba92-49c0-9477-ff98154a8144" />

    index=main sourcetype=ftp_logs
    | stats values(COMMAND) as actions count as activity_count by USER
    | sort -activity_count

 *Helps identify abnormal user behavior*

