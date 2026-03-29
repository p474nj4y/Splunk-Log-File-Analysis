# <ins> Hands on DNS Log Analysis using Splunk SIEM </ins>

> Introduction

DNS (Domain Name System) logs play a vital role in understanding network behavior and uncovering potential security threats. Using Splunk SIEM, security analysts can efficiently monitor DNS activity, detect anomalies, and investigate malicious patterns in network traffic.

> Prerequisites

Before getting started, make sure the following are in place:

A properly installed and configured Splunk instance
DNS log sources configured to forward logs to Splunk


<img width="1344" height="597" alt="Screenshot 2026-03-29 at 5 00 42 PM" src="https://github.com/user-attachments/assets/9a696473-7b5e-4f1d-a4ba-cf647c2d8e37" />


 ### Uploading DNS Log Files to Splunk

> 1. Prepare Sample Logs - ( Sample file that I have used - [dns.log](dns.log) ) 

      
* Collect DNS log files (e.g., .txt format)
* Ensure logs include important fields such as:
* Source IP
* Destination IP
* Domain name (query)
* Query type
* Response code
* Store the files in a location accessible to Splunk

  

> 2. Add Data to Splunk

  
* Log in to the Splunk Web interface
* Go to Settings → Add Data


<img width="524" height="180" alt="Screenshot 2026-03-29 at 5 27 36 PM" src="https://github.com/user-attachments/assets/1958dec8-c9e9-401c-9219-d017a4ee3e2a" />


* Select Upload as the input method

  
<img width="787" height="218" alt="Screenshot 2026-03-29 at 5 26 06 PM" src="https://github.com/user-attachments/assets/fedbdd0f-94ae-471e-b553-f478e186e0ff" />


> 3. Select File
     
* Click Select File
* Choose your prepared DNS log file


> 4. Configure Source Type

  
<img width="1357" height="340" alt="Screenshot 2026-03-29 at 5 30 48 PM" src="https://github.com/user-attachments/assets/6afada98-056f-4410-9e96-a76f34302bf9" />

  
* Define the appropriate sourcetype (e.g., dns or a custom value)
* This helps Splunk correctly parse and categorize logs


> 5. Review Configuration

    
### Verify key settings:

* Index
* Host
* Sourcetype
* Ensure they align with your dataset
  

> 6. Upload Data


<img width="240" height="140" alt="Screenshot 2026-03-29 at 5 32 45 PM" src="https://github.com/user-attachments/assets/164bf9fa-d235-4380-ae36-2ee18b26fb20" />

     
* Click Review
* Confirm all configurations
* Click Submit to ingest the log


<img width="83" height="44" alt="Screenshot 2026-03-29 at 5 35 27 PM" src="https://github.com/user-attachments/assets/cb980e9a-0a46-4385-acdf-978ed50762e3" />


> 7. Validate Data Ingestion


#### Run a quick search to confirm logs are indexed:
 
      index=<your_dns_index> sourcetype=<your_dns_sourcetype>

### Analyzing DNS Logs in Splunk :


> 1. Search DNS Events


#### Retrieve DNS-related logs:

    index=* sourcetype=dns_sample


<img width="1354" height="600" alt="Screenshot 2026-03-29 at 5 45 38 PM" src="https://github.com/user-attachments/assets/85ebdeac-d619-4894-b4bf-ff43255f35b5" />


> 2. Extract Key Fields


#### Focus on important attributes such as:


* Source IP (src_ip)
* Destination IP (dest_ip)
* Domain 
* Query type

* Response code

But before that inorder to get output from specific fields you must choose an event then Event Action > Extract Fields > Choose Delimiters > Tab > Change Fields accordingly in my case all the fields that I had included were as below & one more thing change the time range to all time after updating all the fields : 

( ts, uid, src_ip, src_port, dest_ip, dest_port, proto, trans_id, query,
qclass, qclass_name, qtype, qtype_name, rcode, rcode_name,
AA, TC, RD, RA, Z, answers, TTLs, rejected ) 


<img width="1313" height="574" alt="Screenshot 2026-03-29 at 5 57 46 PM" src="https://github.com/user-attachments/assets/a1293be9-91e6-4295-a4d1-a82a5f781a3f" />


#### Example to filter DNS-related entries:

    index=* sourcetype=dns_logs | table _time src_ip dest_ip query qtype_name rcode_name

 <img width="1355" height="530" alt="Screenshot 2026-03-29 at 6 19 04 PM" src="https://github.com/user-attachments/assets/da32bb42-e4c3-48ad-b98c-8016cee1115a" />

> 3. Detect Anomalies

#### Identify unusual spikes or patterns in DNS queries:

    index=* sourcetype=dns_logs | stats count by query

<img width="1353" height="435" alt="Screenshot 2026-03-29 at 6 57 52 PM" src="https://github.com/user-attachments/assets/1fdd85a0-519c-43f1-8f97-61f8ef9bb933" />


> 4. Identify Top DNS Sources

#### Find the most active sources and queried domains:

    index=* sourcetype=dns_logs | stats count by query | sort -count


<img width="1353" height="441" alt="Screenshot 2026-03-29 at 6 19 50 PM" src="https://github.com/user-attachments/assets/e22fa63c-c30d-411f-bc10-5502a2390b2c" />

  

> 5. Investigate Suspicious Domains

#### Search for potentially malicious domains using threat intelligence sources like VirusTotal:

    index=* sourcetype=dns_logs | search query="malicious-domain.xyz" | table _time src_ip dest_ip query answers


<img width="1352" height="367" alt="Screenshot 2026-03-29 at 6 20 57 PM" src="https://github.com/user-attachments/assets/03da592e-be9a-49cf-89b5-f634455edfeb" />
