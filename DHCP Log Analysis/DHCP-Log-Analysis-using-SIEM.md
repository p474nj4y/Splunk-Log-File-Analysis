# Analyzing DHCP Log Files Using Splunk SIEM

> **Introduction**

**DHCP (Dynamic Host Configuration Protocol) logs provide visibility into IP address allocation and network device activity. By analyzing these logs using Splunk, security professionals can track device behavior, detect anomalies, and identify potential issues such as unauthorized devices or IP conflicts.**

> **Project Overview**

***This project demonstrates how to upload and analyze DHCP log files in Splunk SIEM to monitor IP address assignments and gain insights into network activity.***

> **Prerequisites**

**Before starting, ensure:**

_Splunk is installed and configured_
_DHCP logs are available or forwarded to Splunk_

> **Uploading DHCP Logs to Splunk**

> ***1. Prepare Log Files - in my case the file I used was [dhcp.log](dhcp.log)***

* Collect DHCP log files (e.g., .log, .txt)
* Ensure logs include:
* Timestamp
* Assigned IP address
* MAC address
* Hostname
* Lease status (assigned/released)
* Store logs in a Splunk-accessible location

> ***2. Add Data in Splunk***

<img width="196" height="181" alt="Screenshot 2026-04-02 at 10 19 13 PM" src="https://github.com/user-attachments/assets/bd334b6e-5656-4334-87ce-73f133b14eee" />


* Log in to Splunk Web
* Navigate to Settings → Add Data
* Select Upload

> ***3. Select File***

* Click Select File and upload your DHCP log file

> ***4. Configure Source Type***

<img width="441" height="292" alt="Screenshot 2026-04-03 at 5 41 27 PM" src="https://github.com/user-attachments/assets/6f67cf42-b7a2-4a2f-a730-f5fe6ebda2d0" />


* Choose an appropriate sourcetype (e.g., dhcp, network_dhcp, or custom)
  
> ***5. Review Settings***

<img width="283" height="190" alt="Screenshot 2026-04-03 at 5 41 39 PM" src="https://github.com/user-attachments/assets/21cde5f6-93f0-4342-a5d2-39cfebda5780" />


* Verify index, host, and sourcetype
* Ensure correct configuration
  
> ***6. Upload Data***

* Click Review → Submit to ingest logs
  
> ***7. Verify Upload***

    index=<your_dhcp_index> sourcetype=<your_dhcp_sourcetype>

**Analyzing DHCP Logs**

* ## 1. Search for DHCP Events

<img width="1350" height="602" alt="Screenshot 2026-04-03 at 6 08 44 PM" src="https://github.com/user-attachments/assets/c432132d-a49e-4faa-962f-68d86099091e" />


      index=* sourcetype=dhcp_sample
  
* ## 2. Extract Relevant Fields

_Focus on:_

* ip_address
* mac_address
* hostname
* status

<img width="1347" height="537" alt="Screenshot 2026-04-03 at 6 13 25 PM" src="https://github.com/user-attachments/assets/40f6a95f-5b7c-401c-99a3-6fd4e1a25ff3" />


**Example:**

    index=* sourcetype=dhcp_logs
    | rex field=_raw "assigned_ip=(?<ip_address>\d{1,3}(?:\.\d{1,3}){3})"
    | rex field=_raw "mac=(?<mac_address>[A-F0-9:]+)"
    | rex field=_raw "hostname=(?<hostname>[\w\-]+)"
    | rex field=_raw "status=(?<status>[\w_]+)"
    | fillnull value="N/A" ip_address mac_address hostname status
    | table ip_address mac_address hostname status

* ## 3. Analyze IP Address Assignments

<img width="1347" height="533" alt="Screenshot 2026-04-03 at 6 15 05 PM" src="https://github.com/user-attachments/assets/e29bb55d-fbf9-4df2-82cd-776319612f27" />


      index=* sourcetype=dhcp_sample
      | stats count by ip_address

**Identify frequently assigned IPs**

* ## 4. Track Device Activity

<img width="1346" height="536" alt="Screenshot 2026-04-03 at 6 15 29 PM" src="https://github.com/user-attachments/assets/f387db26-94c6-4f55-b994-09dcc4c6d0b9" />


      index=* sourcetype=dhcp_sample
      | stats count by mac_address, hostname

**Monitor active devices on the network**

* ## 5. Detect Anomalies

**Frequent Lease Requests:**

<img width="1342" height="529" alt="Screenshot 2026-04-03 at 6 20 23 PM" src="https://github.com/user-attachments/assets/d088ee3d-c1a1-456f-8cf5-e9779fc9c6aa" />


     index=* sourcetype=dhcp_logs
     | rex field=_raw "mac=(?<mac_address>[A-F0-9:]+)"
     | stats count by mac_address
     | sort -count

**May indicate scanning or misconfiguration**

**IP Conflicts or Reassignments:**

<img width="1347" height="312" alt="Screenshot 2026-04-03 at 6 21 36 PM" src="https://github.com/user-attachments/assets/b12ba0f5-7a23-4370-9e9a-203493db17fe" />


     index=* sourcetype=dhcp_logs
     | search "IP_CONFLICT"
     | rex field=_raw "assigned_ip=(?<ip_address>\d{1,3}(?:\.\d{1,3}){3})"
     | rex field=_raw "mac=(?<mac_address>[A-F0-9:]+)"
     | rex field=_raw "hostname=(?<hostname>[\w\-]+)"
     | table ip_address mac_address hostname

**Multiple devices using same IP = suspicious**

* ## 6. Monitor Activity Over Time

<img width="1358" height="298" alt="Screenshot 2026-04-03 at 6 22 35 PM" src="https://github.com/user-attachments/assets/91e800e9-c494-4588-9545-8e87f8d14a8d" />


      index=* sourcetype=dhcp_sample
      | timechart span=1h count

**Detect spikes in DHCP activity**
