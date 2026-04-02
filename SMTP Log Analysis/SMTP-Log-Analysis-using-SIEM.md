# Analyzing SMTP Log Files Using Splunk SIEM
 
 ## Introduction

**SMTP (Simple Mail Transfer Protocol) logs provide visibility into email transmission activities, including sender/recipient details, message flow, and delivery status. By analyzing these logs using Splunk, security professionals can monitor email traffic, detect anomalies, and identify threats such as spam, phishing, or unauthorized email activity.**

## Project Overview

**This project demonstrates how to upload and analyze SMTP log files in Splunk SIEM to gain insights into email traffic patterns and detect suspicious behavior.**

## Prerequisites

**Before starting, ensure :**

**_Splunk is installed and configured_**
**_SMTP/mail server logs are available or forwarded to Splunk_**

## Uploading SMTP Logs to Splunk

> **1. Prepare Log Files - in my case the file I used was [smtp.log](./SMTP%20Log%20Analysis)**

* Collect SMTP logs (e.g., .log, .txt)
* Ensure logs include:
* Timestamp
* Sender email
* Recipient email
* Source IP
* Message status (sent, failed, deferred)
* Store logs in a Splunk-accessible location
  
> **2. Add Data in Splunk**

<img width="196" height="181" alt="Screenshot 2026-04-02 at 10 19 13 PM" src="https://github.com/user-attachments/assets/815feb85-7b09-4a82-949c-caa33860aa49" />

* Log in to Splunk Web
* Navigate to Settings → Add Data
* Select Upload
  
> **3. Select File**

***Click Select File and upload your SMTP log file***

> **4. Configure Source Type**

<img width="437" height="291" alt="Screenshot 2026-04-02 at 10 20 29 PM" src="https://github.com/user-attachments/assets/eb62570b-9d19-400b-9c58-8c63e94335a2" />

***Choose a suitable sourcetype (e.g., smtp, mail, or custom)***

> **5. Review Settings**

<img width="281" height="192" alt="Screenshot 2026-04-02 at 10 20 45 PM" src="https://github.com/user-attachments/assets/3458183b-91f2-49d7-bf42-2b008bf07130" />


* Verify index, host, and sourcetype
* Ensure correct configuration
  
> **6. Upload Data**

***Click Review → Submit to ingest logs***

> **7. Verify Upload**

    index=<your_smtp_index> sourcetype=<your_smtp_sourcetype>

> **Analyzing SMTP Logs**

> 1. Search for SMTP Events

<img width="1348" height="600" alt="Screenshot 2026-04-02 at 10 28 06 PM" src="https://github.com/user-attachments/assets/7a27b708-1c90-444a-895b-bb569181fee1" />

    index=* sourcetype=smtp_sample
    
> 2. Extract Relevant Fields

<img width="1125" height="266" alt="Screenshot 2026-04-02 at 10 21 51 PM" src="https://github.com/user-attachments/assets/d2c93b85-a300-4255-aa2f-fc205796cf6f" />

***Focus on:***

* src_ip
* sender
* recipient
* status

## Example:

<img width="1346" height="603" alt="Screenshot 2026-04-02 at 10 32 21 PM" src="https://github.com/user-attachments/assets/e7ea6ea4-5e31-408b-a9c7-6008f9bb8b8e" />

    index=* sourcetype=smtp_logs 
    | rex field=_raw "sender=(?<sender>\S+)\s+recipient=(?<recipient>\S+)\s+src_ip=(?<src_ip>\S+)\s+status=(?<status>\S+)"
    | table sender recipient src_ip status

> 3. Analyze Email Traffic Patterns

## Top Senders:

<img width="1344" height="536" alt="Screenshot 2026-04-02 at 10 33 31 PM" src="https://github.com/user-attachments/assets/5c5f43eb-a964-4cd7-a93f-468f1ef3ba6c" />


    index=* sourcetype=smtp_sample
    | stats count by sender
    | sort -count

## Top Recipients:

<img width="1348" height="540" alt="Screenshot 2026-04-02 at 10 34 10 PM" src="https://github.com/user-attachments/assets/b94bd10e-4b36-4f9a-af32-7b5f681f6805" />


    index=* sourcetype=smtp_sample
    | stats count by recipient
    | sort -count

## Message Status Distribution:

<img width="1346" height="301" alt="Screenshot 2026-04-02 at 10 34 53 PM" src="https://github.com/user-attachments/assets/c61d48ba-79b2-4a6b-bbc5-c90b3d83d976" />


    index=* sourcetype=smtp_sample
    | stats count by status
    
> 4. Detect Anomalies

## Traffic Spikes:

<img width="1347" height="307" alt="Screenshot 2026-04-02 at 10 36 01 PM" src="https://github.com/user-attachments/assets/44771bf3-17a2-4b4c-9a33-598100024efc" />


    index=* sourcetype=smtp_sample
    | timechart span=1h count

## Failed Email Deliveries:

<img width="1348" height="327" alt="Screenshot 2026-04-02 at 10 36 25 PM" src="https://github.com/user-attachments/assets/98cf4704-de4e-451e-a7e0-8720e25a6ed0" />


    index=* sourcetype=smtp_sample status=failed
    | stats count by src_ip, sender

## High failures may indicate spam attempts or misconfiguration

> 5. Monitor Suspicious Activity

## Bulk Email Sending (Spam Behavior):

<img width="1337" height="248" alt="Screenshot 2026-04-02 at 10 37 00 PM" src="https://github.com/user-attachments/assets/5fb2008c-386e-4784-a530-76ce820d2ad4" />

    index=* sourcetype=smtp_sample
    | stats count by sender
    | where count > 50

***High volume = possible spam***

## Suspicious Source IPs:

<img width="1344" height="526" alt="Screenshot 2026-04-02 at 10 37 31 PM" src="https://github.com/user-attachments/assets/dfe388b2-8dcf-4e52-ae6d-dcd180e4d459" />

    index=* sourcetype=smtp_sample
    | stats count by src_ip
    | sort -count

_Identify abnormal senders_
