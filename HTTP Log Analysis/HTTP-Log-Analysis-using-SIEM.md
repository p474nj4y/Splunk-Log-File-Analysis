# Analyzing HTTP Log Files Using Splunk SIEM

## Introduction

**HTTP (Hypertext Transfer Protocol) logs provide detailed insights into web server activity, including requests, responses, user agents, and accessed resources. By analyzing these logs using Splunk, security professionals can monitor web traffic, identify anomalies, and detect potential security threats.**

## Project Overview

**This project demonstrates how to upload and analyze HTTP log files in Splunk SIEM to gain visibility into web traffic and user behavior.**

## Prerequisites

**_Before starting, ensure:_**

**_Splunk is installed and configured_**
**_HTTP log sources are available or forwarded to Splunk_**

**Uploading HTTP Logs to Splunk:**

> **1. Prepare Log Files - The Log file that, I used was [http_log.txt](./HTTP%20Log%20Analysis/http_log.txt)**

* Obtain HTTP log files (e.g., text format)
* Ensure logs include:
* Timestamp
* Request method (GET, POST, etc.)
* URL/URI
* Response status code
* User agent
* Store the files in a location accessible to Splunk

> **2. Add Data in Splunk**

* Log in to Splunk Web
* Navigate to Settings → Add Data
* Select Upload

<img width="182" height="183" alt="Screenshot 2026-03-30 at 11 26 09 AM" src="https://github.com/user-attachments/assets/1c7d4fa2-eb93-423c-9d8e-20134e648b2d" />

> **3. Select File**

* Click Select File and upload your HTTP log file

> **4. Configure Source Type**

*Choose an appropriate sourcetype (e.g., access_combined or custom)*

<img width="351" height="170" alt="Screenshot 2026-03-30 at 11 27 29 AM" src="https://github.com/user-attachments/assets/b8973645-1919-428e-84c3-8966dcbaa6f6" />

> **5. Review Settings**

* Verify index, host, and sourcetype
* Ensure they match your dataset

<img width="289" height="191" alt="Screenshot 2026-03-30 at 11 27 38 AM" src="https://github.com/user-attachments/assets/610ccdd8-d818-49f0-8547-eadcc27331f8" />

> **6. Upload Data**

*Click Review → Submit to ingest logs*

> **7. Choose Extract Fields -> Regular expression -> Select Fields (in my case I added these fields according to my http log file : src_ip, timestamp, method, url, status, user_agent, response_size, referrer, http_version) -> Save & then jump to dashboard**

<img width="1360" height="602" alt="Screenshot 2026-03-30 at 11 48 44 AM" src="https://github.com/user-attachments/assets/e965956c-b494-40dc-8cee-924bfe006172" />


> **8. Verify Upload**

<img width="1346" height="601" alt="Screenshot 2026-03-30 at 11 56 41 AM" src="https://github.com/user-attachments/assets/9d7e60db-31c7-4c57-8946-ddd39e466d4b" />

    index=<your_http_index> sourcetype=<your_http_sourcetype>

### Analyzing HTTP Logs

> **1. Search for HTTP Events**

    index=* sourcetype=http_sample

> **2. Extract Relevant Fields**

*Identify important fields such as method, URI, status, and user agent.*

### Use regex if needed:

<img width="1358" height="581" alt="Screenshot 2026-03-30 at 11 59 08 AM" src="https://github.com/user-attachments/assets/a0ab0fa0-e3e9-4994-a971-5550d5e74537" />

    | rex field=_raw "<regex_pattern>"

> **3. Analyze Web Traffic Patterns**

*Request Methods Distribution:*

<img width="1360" height="278" alt="Screenshot 2026-03-30 at 12 00 05 PM" src="https://github.com/user-attachments/assets/2ae3c615-8705-4b51-8fa8-f4e511a393bf" />


    index=* sourcetype=http_sample
    | stats count by method

### Top Accessed URLs:

<img width="1360" height="474" alt="Screenshot 2026-03-30 at 12 02 38 PM" src="https://github.com/user-attachments/assets/4590a62d-4a1b-4cfd-a3e4-38bd04502b50" />


    index=* sourcetype=http_sample
    | top limit=10 url

### Response Status Codes:

<img width="1360" height="429" alt="Screenshot 2026-03-30 at 12 03 12 PM" src="https://github.com/user-attachments/assets/6c409884-9380-4515-aa4e-5b2a3f8f61a0" />


    index=* sourcetype=http_sample
    | stats count by status

> **4. Detect Anomalies**

### Traffic Trends:

<img width="1360" height="531" alt="Screenshot 2026-03-30 at 12 06 33 PM" src="https://github.com/user-attachments/assets/9f289362-acb9-4bdc-8668-325797797489" />


    index=* sourcetype=http_sample
    | timechart span=1h count

## Error Responses (4xx / 5xx):

<img width="1360" height="371" alt="Screenshot 2026-03-30 at 12 07 07 PM" src="https://github.com/user-attachments/assets/7c9c1ded-3eb2-4b69-80a1-0751c1696818" />


    index=* sourcetype=http_sample
    | stats count by status
    | where status >= 400

## Suspicious IP Investigation:

<img width="1360" height="359" alt="Screenshot 2026-03-30 at 12 10 57 PM" src="https://github.com/user-attachments/assets/30e8b2f9-de21-4409-81c1-558a99a66a04" />

 
    index=* sourcetype=http_sample
    | search src_ip="suspicious_ip"

> **5. Monitor User Behavior**

## Failed Login Attempts:

<img width="1360" height="376" alt="Screenshot 2026-03-30 at 12 14 22 PM" src="https://github.com/user-attachments/assets/2a57a364-fb0f-498b-98a8-86062ad002e4" />

    index=* sourcetype=http_sample url="/login" method=POST status=401
    | stats count by src_ip

## Session Analysis:

<img width="1347" height="534" alt="Screenshot 2026-03-30 at 12 16 22 PM" src="https://github.com/user-attachments/assets/44f76698-1f7d-4f86-ba01-daa7b3f56711" />


    index=* sourcetype=http_sample
    | stats earliest(_time) as start latest(_time) as end by src_ip
    | eval session_duration = end - start
    | stats avg(session_duration)
