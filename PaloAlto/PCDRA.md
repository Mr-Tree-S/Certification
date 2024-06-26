# PCDRA

## Refer

> <https://www.examtopics.com/exams/palo-alto-networks/pcdra/view/>

---

## **RUSH**

### 1

Phishing belongs which of the following MITRE ATT&CK tactics?

- A. Initial Access, Persistence
- B. Persistence, Command and Control
- C. Reconnaissance, Persistence
- D. Reconnaissance, Initial Access

**```Correct Answer: D```**

### 2

When creating a BIOC rule, which XQL query can be used?

- A.

```XQL
dataset = xdr_data
| filter event_sub_type = PROCESS_START and
action_process_image_name ~= ".*?\.(?:pdf|docx)\.exe"
```

- B.

```XQL
dataset = xdr_data
| filter event_type = PROCESS and
event_sub_type = PROCESS_START and
action_process_image_name ~= "._?\.(?:pdf|docx)\.exe"
```

- C.

```XQL
dataset = xdr_data
| filter action_process_image_name ~= "._?\.(?:pdf|docx)\.exe"
| fields action_process_image
```

- D.

```XQL
dataset = xdr_data
| filter event_behavior = true
event_sub_type = PROCESS_START and
action_process_image_name ~= ".*?\.(?:pdf|docx)\.exe"
```

```text
Correct answer is: B
"The XQL query must at a minimum filter on the event_type field in order for it to be a valid BIOC rule."
```

### 3

Which built-in dashboard would be the best option for an executive, if they were looking for the Mean Time to Resolution (MTTR) metric?

- A. Security Manager Dashboard
- B. Data Ingestion Dashboard
- C. Security Admin Dashboard
- D. Incident Management Dashboard

`C`

### 4

What are two purposes of “Respond to Malicious Causality Chains” in a Cortex XDR Windows Malware profile? (Choose two.)

- A. Automatically close the connections involved in malicious traffic.
- B. Automatically kill the processes involved in malicious activity.
- C. Automatically terminate the threads involved in malicious activity.
- D. Automatically block the IP addresses involved in malicious traffic.

**```Correct Answer: A D```**

### 5

When creating a custom XQL query in a dashboard, how would a user save that XQL query to the Widget Library?

- A. Click the three dots on the widget and then choose “Save” and this will link the query to the Widget Library.
- B. This isn’t supported, you have to exit the dashboard and go into the Widget Library first to create it.
- C. Click on “Save to Action Center” in the dashboard and you will be prompted to give the query a name and description.
- D. Click on “Save to Widget Library” in the dashboard and you will be prompted to give the query a name and description.

**```Correct Answer: D```**

### 6

What license would be required for ingesting external logs from various vendors?

- A. Cortex XDR Pro per Endpoint
- B. Cortex XDR Vendor Agnostic Pro
- C. Cortex XDR Pro per TB
- D. Cortex XDR Cloud per Host

**```Correct Answer: C```**

### 7

An attacker tries to load dynamic libraries on macOS from an unsecure location. Which Cortex XDR module can prevent this attack?

- A. DDL Security
- B. Hot Patch Protection
- C. Kernel Integrity Monitor (KIM)
- D. Dylib Hijacking

**```Correct Answer: D```**

### 8

What is the purpose of the Unit 42 team?

- A. Unit 42 is responsible for automation and orchestration of products
- B. Unit 42 is responsible for the configuration optimization of the Cortex XDR server
- C. Unit 42 is responsible for threat research, malware analysis and threat hunting
- D. Unit 42 is responsible for the rapid deployment of Cortex XDR agents

**```Correct Answer: C```**

### 9

Which Type of IOC can you define in Cortex XDR?

- A. destination port
- B. e-mail address
- C. full path
- D. App-ID

**```Correct Answer: C```**

### 10

When viewing the incident directly, what is the “assigned to” field value of a new Incident that was just reported to Cortex?

- A. Pending
- B. It is blank
- C. Unassigned
- D. New

`Unassigned`

### 11

In incident-related widgets, how would you filter the display to only show incidents that were “starred”?

- A. Create a custom XQL widget
- B. This is not currently supported
- C. Create a custom report and filter on starred incidents
- D. Click the star in the widget

**```Correct Answer: D```**

### 12

Where would you view the WildFire report in an incident?

- A. next to relevant Key Artifacts in the incidents details page
- B. under Response --> Action Center
- C. under the gear icon --> Agent Audit Logs
- D. on the HUB page at apps.paloaltonetworks.com

```Answer should be - A.```

### 14

Which engine, of the following, in Cortex XDR determines the most relevant artifacts in each alert and aggregates all alerts related to an event into
an incident?

- A. Sensor Engine
- B. Causality Analysis Engine
- C. Log Stitching Engine
- D. Causality Chain Engine

**```Correct Answer: B```**

### 15 ？

Which type of BIOC rule is currently available in Cortex XDR?

- A. Threat Actor
- B. Discovery
- C. Network
- D. Dropper

**```Correct Answer: D```**

### 16

In Windows and macOS you need to prevent the Cortex XDR Agent from blocking execution of a file based on the digital signer. What is one way to
add an exception for the singer?

- A. In the Restrictions Profile, add the file name and path to the Executable Files allow list.
- B. Create a new rule exception and use the singer as the characteristic.
- C. Add the signer to the allow list in the malware profile.
- D. Add the signer to the allow list under the action center page.

**```Correct Answer: C```**

### 17

As a Malware Analyst working with Cortex XDR you notice an alert suggesting that there was a prevented attempt to download Cobalt Strike on
one of your servers. Days later, you learn about a massive ongoing supply chain attack. Using Cortex XDR you recognize that your server was
compromised by the attack and that Cortex XDR prevented it. What steps can you take to ensure that the same protection is extended to all your
servers?

- A. Create Behavioral Threat Protection (BTP) rules to recognize and prevent the activity.
- B. Enable DLL Protection on all servers but there might be some false positives.
- C. Create IOCs of the malicious files you have found to prevent their execution.
- D. Enable Behavioral Threat Protection (BTP) with cytool to prevent the attack from spreading.

**```Correct Answer: A```**

### 19

What is the purpose of targeting software vendors in a supply-chain attack?

- A. to take advantage of a trusted software delivery method.
- B. to steal users’ login credentials.
- C. to access source code.
- D. to report Zero-day vulnerabilities.

**```Correct Answer: A```**

### 20

What is the standard installation disk space recommended to install a Broker VM?

- A. 1GB disk space
- B. 2GB disk space
- C. 512GB disk space
- D. 256GB disk space

**```Correct Answer: C```**

### 21

Where can SHA256 hash values be used in Cortex XDR Malware Protection Profiles?

- A. in the macOS Malware Protection Profile to indicate allowed signers
- B. in the Linux Malware Protection Profile to indicate allowed Java libraries
- C. SHA256 hashes cannot be used in Cortex XDR Malware Protection Profiles
- D. in the Windows Malware Protection Profile to indicate allowed executables

**```Correct Answer: D```**

### 22

How does Cortex XDR agent for Windows prevent ransomware attacks from compromising the file system?

- A. by encrypting the disk first.
- B. by utilizing decoy Files.
- C. by retrieving the encryption key.
- D. by patching vulnerable applications.

**```Correct Answer: B```**

### 23

What functionality of the Broker VM would you use to ingest third-party firewall logs to the Cortex Data Lake?

- A. Netflow Collector
- B. Syslog Collector
- C. DB Collector
- D. Pathfinder

**```Correct Answer: B```**

### 24

In the deployment of which Broker VM applet are you required to install a strong cipher SHA256-based SSL certificate?

- A. Agent Proxy
- B. Agent Installer and Content Caching
- C. Syslog Collector
- D. CSV Collector

**```Correct Answer: B```**

### 25

When is the wss (WebSocket Secure) protocol used?

- A. when the Cortex XDR agent downloads new security content
- B. when the Cortex XDR agent uploads alert data
- C. when the Cortex XDR agent connects to WildFire to upload files for analysis
- D. when the Cortex XDR agent establishes a bidirectional communication channel

**```Correct Answer: D```**

### 26

With a Cortex XDR Prevent license, which objects are considered to be sensors?

- A. Syslog servers
- B. Third-Party security devices
- C. Cortex XDR agents
- D. Palo Alto Networks Next-Generation Firewalls

**```Correct Answer: C```**

### 27

Which license is required when deploying Cortex XDR agent on Kubernetes Clusters as a DaemonSet?

- A. Cortex XDR Pro per TB
- B. Host Insights
- C. Cortex XDR Pro per Endpoint
- D. Cortex XDR Cloud per Host

**```Correct Answer: D```**

### 28

What kind of the threat typically encrypts user files?

- A. ransomware
- B. SQL injection attacks
- C. Zero-day exploits
- D. supply-chain attacks

**```Correct Answer: A```**

### 29

When using the “File Search and Destroy” feature, which of the following search hash type is supported?

- A. SHA256 hash of the file
- B. AES256 hash of the file
- C. MD5 hash of the file
- D. SHA1 hash of the file

**```Correct Answer: A```**

### 30

If you have an isolated network that is prevented from connecting to the Cortex Data Lake, which type of Broker VM setup can you use to facilitate the communication?

- A. Broker VM Pathfinder
- B. Local Agent Proxy
- C. Local Agent Installer and Content Caching
- D. Broker VM Syslog Collector

```text
I believe the answer is B.
Here is the admin guide, see the second bullet: https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Activate-the-Local-Agent-Settings
Caching just means it will cache the data, but if it doesn't have the data it will try to go get it. This won't work in an isolated network so C isn't correct.
```

### 31

What is by far the most common tactic used by ransomware to shut down a victim’s operation?

- A. preventing the victim from being able to access APIs to cripple infrastructure
- B. denying traffic out of the victims network until payment is received
- C. restricting access to administrative accounts to the victim
- D. encrypting certain files to prevent access by the victim

**```Correct Answer: D```**

### 32

Cortex XDR Analytics can alert when detecting activity matching the following MITRE ATT&CKTM techniques.

- A. Exfiltration, Command and Control, Collection
- B. Exfiltration, Command and Control, Privilege Escalation
- C. Exfiltration, Command and Control, Impact
- D. Exfiltration, Command and Control, Lateral Movement

**```Correct Answer: D```**

### 33

When selecting multiple Incidents at a time, what options are available from the menu when a user right-clicks the incidents? (Choose two.)

- A. Assign incidents to an analyst in bulk.
- B. Change the status of multiple incidents.
- C. Investigate several Incidents at once.
- D. Delete the selected Incidents.
```A B```

### 34

A file is identified as malware by the Local Analysis module whereas WildFire verdict is Benign, Assuming WildFire is accurate. Which statement is
correct for the incident?

- A. It is true positive.
- B. It is false positive.
- C. It is a false negative.
- D. It is true negative.

**```Correct Answer: B```**

### 35

What is the outcome of creating and implementing an alert exclusion?

- A. The Cortex XDR agent will allow the process that was blocked to run on the endpoint.
- B. The Cortex XDR console will hide those alerts.
- C. The Cortex XDR agent will not create an alert for this event in the future.
- D. The Cortex XDR console will delete those alerts and block ingestion of them in the future.

**```Correct Answer: B```**

### 36

Which statement is true for Application Exploits and Kernel Exploits?

- A. The ultimate goal of any exploit is to reach the application.
- B. Kernel exploits are easier to prevent then application exploits.
- C. The ultimate goal of any exploit is to reach the kernel.
- D. Application exploits leverage kernel vulnerability.

**```Correct Answer: C```**

### 37

To create a BIOC rule with XQL query you must at a minimum filter on which field in order for it to be a valid BIOC rule?

- A. causality_chain
- B. endpoint_name
- C. threat_event
- D. event_type

**```Correct Answer: D```**

### 38

Which of the following is an example of a successful exploit?

- A. connecting unknown media to an endpoint that copied malware due to Autorun.
- B. a user executing code which takes advantage of a vulnerability on a local service.
- C. identifying vulnerable services on a server.
- D. executing a process executable for well-known and signed software.

```text
From documentation :
"An exploit is a piece of code or a program that takes advantage of a weakness (aka vulnerability) in an application or system."
https://www.paloaltonetworks.com/cyberpedia/malware-vs-exploits
```

### 39

Which of the following represents the correct relation of alerts to incidents?

- A. Only alerts with the same host are grouped together into one Incident in a given time frame.
- B. Alerts that occur within a three hour time frame are grouped together into one Incident.
- C. Alerts with same causality chains that occur within a given time frame are grouped together into an Incident.
- D. Every alert creates a new Incident.

```text
Alerts on the same causality chain are grouped with the same incident if an open incident already exists.
Otherwise, the new incoming alert will create a new incident.
https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Prevent-Administrator-Guide/Investigate-Incidents
```

### 40

Which of the following protection modules is checked first in the Cortex XDR Windows agent malware protection flow?

- A. Hash Verdict Determination
- B. Behavioral Threat Protection
- C. Restriction Policy
- D. Child Process Protection

```text
Correct Answer - D. Child Process Protection
https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Prevent-Administrator-Guide/File-Analysis-and-Protection-Flow
If the process tries to launch any child processes, the Cortex XDR agent first evaluates the child process protection policy.
If the parent process is a known targeted process that attempts to launch a restricted child process, the Cortex XDR agent blocks the child processes from running and reports the security event to Cortex XDR.
```

### 41

While working the alerts involved in a Cortex XDR incident, an analyst has found that every alert in this incident requires an exclusion. What will
the Cortex XDR console automatically do to this incident if all alerts contained have exclusions?

- A. mark the incident as Unresolved
- B. create a BIOC rule excluding this behavior
- C. create an exception to prevent future false positives
- D. mark the incident as Resolved – False Positive

**```Correct Answer: D```**

### 42

Network attacks follow predictable patterns. If you interfere with any portion of this pattern, the attack will be neutralized. Which of the following
statements is correct?

- A. Cortex XDR Analytics allows to interfere with the pattern as soon as it is observed on the firewall.
- B. Cortex XDR Analytics does not interfere with the pattern as soon as it is observed on the endpoint.
- C. Cortex XDR Analytics does not have to interfere with the pattern as soon as it is observed on the endpoint in order to prevent the attack.
- D. Cortex XDR Analytics allows to interfere with the pattern as soon as it is observed on the endpoint.

**```Correct Answer: A```**

### 43

After scan, how does file quarantine function work on an endpoint?

- A. Quarantine takes ownership of the files and folders and prevents execution through access control.
- B. Quarantine disables the network adapters and locks down access preventing any communications with the endpoint.
- C. Quarantine removes a specific file from its location on a local or removable drive to a protected folder and prevents it from being executed.
- D. Quarantine prevents an endpoint from communicating with anything besides the listed exceptions in the agent profile and Cortex XDR.

**```Correct Answer: C```**

### 44

Which two types of exception profiles you can create in Cortex XDR? (Choose two.)

- A. exception profiles that apply to specific endpoints
- B. agent exception profiles that apply to specific endpoints
- C. global exception profiles that apply to all endpoints
- D. role-based profiles that apply to specific endpoints

**```Correct Answer: A C```**

### 45

Which profiles can the user use to configure malware protection in the Cortex XDR console?

- A. Malware Protection profile
- B. Malware profile
- C. Malware Detection profile
- D. Anti-Malware profile

**```Correct Answer: B```**

### 46

Which module provides the best visibility to view vulnerabilities?

- A. Live Terminal module
- B. Device Control Violations module
- C. Host Insights module
- D. Forensics module

**```Correct Answer: C```**

### 47

Which of the following is NOT a precanned script provided by Palo Alto Networks?

- A. delete_file
- B. quarantine_file
- C. process_kill_name
- D. list_directories

**```Correct Answer: B```**

### 48

Live Terminal uses which type of protocol to communicate with the agent on the endpoint?

- A. NetBIOS over TCP
- B. WebSocket
- C. UDP and a random port
- D. TCP , over port 80

**```Correct Answer: B```**

### 49

You can star security events in which two ways? (Choose two.)

- A. Create an alert-starring configuration.
- B. Create an Incident-starring configuration.
- C. Manually star an alert.
- D. Manually star an Incident.

**```Correct Answer: B D```**

### 50

Where would you go to add an exception to exclude a specific file hash from examination by the Malware profile for a Windows endpoint?

- A. Find the Malware profile attached to the endpoint, Under Portable Executable and DLL Examination add the hash to the allow list.
- B. From the rules menu select new exception, fill out the criteria, choose the scope to apply it to, hit save.
- C. Find the exceptions profile attached to the endpoint, under process exceptions select local analysis, paste the hash and save.
- D. In the Action Center, choose Allow list, select new action, select add to allow list, add your hash to the list, and apply it.

```text
D: Investigate Files:
You can manage file execution on your endpoints by using file hashes that are included in your allow and block lists. 
If you trust a certain file and know it to be benign, you can add the file hash to the allow list and allow it to be executed on all your endpoints regardless of the WildFire or local analysis verdict.
Similarly, if you want to always block a file from running on any of your endpoints, you can add the associated hash to the block list.
```

### 51

As a Malware Analyst working with Cortex XDR you notice an alert suggesting that there was a prevented attempt to open a malicious Word
document. You learn from the WildFire report and AutoFocus that this document is known to have been used in Phishing campaigns since 2018.
What steps can you take to ensure that the same document is not opened by other users in your organization protected by the Cortex XDR agent?

- A. Enable DLL Protection on all endpoints but there might be some false positives.
- B. Create Behavioral Threat Protection (BTP) rules to recognize and prevent the activity.
- C. No step is required because Cortex shares IOCs with our fellow Cyber Threat Alliance members.
- D. No step is required because the malicious document is already stopped.

**```Correct Answer: B```**

### 52

When investigating security events, which feature in Cortex XDR is useful for reverting the changes on the endpoint?

- A. Remediation Automation
- B. Machine Remediation
- C. Automatic Remediation
- D. Remediation Suggestions

**```Correct Answer: D```**

### 53

What is the purpose of the Cortex Data Lake?

- A. a local storage facility where your logs and alert data can be aggregated
- B. a cloud-based storage facility where your firewall logs are stored
- C. the interface between firewalls and the Cortex XDR agents
- D. the workspace for your Cortex XDR agents to detonate potential malware files

**```Correct Answer: B```**

### 54

When creating a scheduled report which is not an option?

- A. Run weekly on a certain day and time.
- B. Run quarterly on a certain day and time.
- C. Run monthly on a certain day and time.
- D. Run daily at a certain time (selectable hours and minutes).

**```Correct Answer: B```**

### 55

Which statement regarding scripts in Cortex XDR is true?

- A. Any version of Python script can be run.
- B. The level of risk is assigned to the script upon import.
- C. Any script can be imported including Visual Basic (VB) scripts.
- D. The script is run on the machine uploading the script to ensure that it is operational.

```text
I think - B. A is wrong for sure, you need at least Python 3.7 to run scripts on your endpoint directly.
https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Run-Scripts-on-an-Endpoint
```

### 56

What is the function of WildFire for Cortex XDR?

- A. WildFire runs in the cloud and analyses alert data from the XDR agent to check for behavioural threats.
- B. WildFire is the engine that runs on the local agent and determines whether behavioural threats are occurring on the endpoint.
- C. WildFire accepts and analyses a sample to provide a verdict.
- D. WildFire runs entirely on the agent to quickly analyse samples and provide a verdict.

**```Correct Answer: C```**

### 57

A Linux endpoint with a Cortex XDR Pro per Endpoint license and Enhanced Endpoint Data enabled has reported malicious activity, resulting in the creation of a file that you wish to delete. Which action could you take to delete the file?

- A. Manually remediate the problem on the endpoint in question.
- B. Open X2go from the Cortex XDR console and delete the file via X2go.
- C. Initiate Remediate Suggestions to automatically delete the file.
- D. Open an NFS connection from the Cortex XDR console and delete the file.

```text
I think the answer is - C.
See this overview from Palo Alto: https://youtu.be/HBzxmSjHYt4?si=JqjrLZkLTXBeqXpp&t=452.
Here he talks about deleting a file through the Remediation Suggestions.
```

### 58

Which of the following best defines the Windows Registry as used by the Cortex XDR agent?

- A. a hierarchical database that stores settings for the operating system and for applications
- B. a system of files used by the operating system to commit memory that exceeds the available hardware resources. Also known as the
“swap”
- C. a central system, available via the internet, for registering officially licensed versions of software to prove ownership
- D. a ledger for maintaining accurate and up-to-date information on total disk usage and disk space remaining available to the operating
system

**```Correct Answer: A```**

### 59

Which statement best describes how Behavioral Threat Protection (BTP) works?

- A. BTP injects into known vulnerable processes to detect malicious activity.
- B. BTP runs on the Cortex XDR and distributes behavioral signatures to all agents.
- C. BTP matches EDR data with rules provided by Cortex XDR.
- D. BTP uses machine Learning to recognize malicious activity even if it is not known.

**```Correct Answer: D```**

### 60

Which of the following paths will successfully activate Remediation Suggestions?

- A. Alerts Table > Right-click on a process node > Remediation Suggestions
- B. Incident View > Actions > Remediation Suggestions
- C. Causality View > Actions > Remediation Suggestions
- D. Alerts Table > Right-click on an alert > Remediation Suggestions

```text
This should be - B. Incidents > click the 3 dots > Remediation Suggestions
C is wrong because Causality View > Actions > Live Terminal
```

### 61

In Cortex XDR management console scheduled reports can be forwarded to which of the following applications/services?

- A. Service Now
- B. Slack
- C. Salesforce
- D. Jira

**```Correct Answer: B```**

### 62

Which type of IOC can you define in Cortex XDR?

- A. Source port
- B. Destination IP Address
- C. Destination IP Address:Destination
- D. Source IP Address

**```Correct Answer: B```**

### 63

What is the action taken out by Managed Threat Hunting team for Zero Day Exploits?

- A. MTH runs queries and investigative actions and no further action is taken.
- B. MTH researches for threats in the logs and reports to engineering.
- C. MTH researches for threats in the tenant and generates a report with the findings.
- D. MTH pushes content updates to prevent against the zero day exploits.

**```Correct Answer: C```**

### 64

What is an example of an attack vector for ransomware?

- A. A URL filtering feature enabled on a firewall
- B. Phishing emails containing malicious attachments
- C. Performing DNS queries for suspicious domains
- D. Performing SSL Decryption on an endpoint

**```Correct Answer: B```**

### 65

What should you do to automatically convert leads into alerts after investigating a lead?

- A. Lead threats can't be prevented in the future because they already exist in the environment.
- B. Build a search query using Query Builder or XQL using a list of IOCs.
- C. Create IOC rules based on the set of the collected attribute-value pairs over the affected entities concluded during the lead hunting.
- D. Create BIOC rules based on the set of the collected attribute-value pairs over the affected entities concluded during the lead hunting.

```text
I believe this should be - D.
Leads are not static IOCs.
https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Research-a-Known-Threat#:~:text=Inspect%20the%20information%20again%2C%20and%20identify%20any%20characteristics%20you%20can%20use%20to%20Create%20a%20BIOC%20Rule%20or%20Create%20a%20Correlation%20Rule.
```

### 66

When reaching out to TAC for additional technical support related to a Security Event; what are two critical pieces of information you need to
collect from the Agent? (Choose two.)

- A. The prevention archive from the alert.
- B. The unique agent id.
- C. The distribution id of the agent.
- D. The agent technical support file.
E. A list of all the current exceptions applied to the agent.

**```Correct Answer:B D```**

### 67

Which function describes the removal of a specific file from its location on a local or removable drive to a protected folder to prevent the file from
being executed?

- A. Search & destroy
- B. Quarantine
- C. Isolation
- D. Flag for removal

**```Correct Answer: B```**

### 68

What is the maximum number of agents one Broker VM local agent applet can support?

- A. 10,000
- B. 15,000
- C. 5,000
- D. 20,000

**```Correct Answer: C```**

### 69

Which of the following represents a common sequence of cyber attack tactics?

- A. Actions on the objective >> Reconnaissance >> Weaponisation & Delivery >> Exploitation >> Installation >> Command & Control
- B. Installation >> Reconnaissance >> Weaponisation & Delivery >> Exploitation >> Command & Control >> Actions on the objective
- C. Reconnaissance >> Installation >> Weaponisation & Delivery >> Exploitation >> Command & Control >> Actions on the objective
- D. Reconnaissance >> Weaponisation & Delivery >> Exploitation >> Installation >> Command & Control >> Actions on the objective

**```Correct Answer: D```**

### 70

Which Exploit Protection Module (EPM) can be used to prevent attacks based on OS function?

- A. Memory Limit Heap Spray Check
- B. DLL Security
- C. UASLR
- D. JIT Mitigation

**```Correct Answer: C```**

### 72

Which search methods is supported by File Search and Destroy?

- A. File Search and Repair
- B. File Seek and Destroy
- C. File Search and Destroy
- D. File Seek and Repair

**```Correct Answer: C```**

### 73

Which of the following Live Terminal options are available for Android systems?

- A. Run Android commands.
- B. Live Terminal is not supported.
- C. Run APK scripts.
- D. Stop an app.

**```Correct Answer: B```**

### 74

What contains a logical schema in an XQL query?

- A. Field
- B. Bin
- C. Dataset
- D. Arrayexpand

**```Correct Answer: C```**

### 75

Which minimum Cortex XDR agent version is required for Kubernetes Cluster?

- A. Cortex XDR 7.4
- B. Cortex XDR 5.0
- C. Cortex XDR 7.5
- D. Cortex XDR 6.1

**```Correct Answer: C```**

### 76

In the Cortex XDR console, from which two pages are you able to manually perform the agent upgrade action? (Choose two.)

- A. Endpoint Administration
- B. Asset Management
- C. Action Center
- D. Agent Installations

**```Correct Answer: A```** C

### 77

Which version of python is used in live terminal?

- A. Python 3 with specific XDR Python libraries developed by Palo Alto Networks
- B. Python 3 with standard Python libraries
- C. Python 2 and 3 with standard Python libraries
- D. Python 2 and 3 with specific XDR Python libraries developed by Palo Alto Networks

```text
The Answer is - B.
https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Initiate-a-Live-Terminal-Session#:~:text=The%20Python%20command%20interpreter%20uses%20Unix%20command%20syntax%20and%20supports%20Python%203%20with%20standard%20Python%20libraries
```

### 78

Under which conditions is Local Analysis evoked to evaluate a file before the file is allowed to run?

- A. The endpoint is disconnected or the verdict from WildFire is of a type malware.
- B. The endpoint is disconnected or the verdict from WildFire is of a type unknown.
- C. The endpoint is disconnected or the verdict from WildFire is of a type grayware.
- D. The endpoint is disconnected or the verdict from WildFire is of a type benign.

**```Correct Answer: B```**

### 79

What is the difference between presets and datasets in XQL?

- A. A dataset is a Cortex data lake data source only; presets are built-in data source.
- B. A dataset is a database; presets is a field.
- C. A dataset is a built-in or third party source; presets group XDR data fields.
- D. A dataset is a third-party data source; presets are built-in data source.

**```Correct Answer: C```**

### 80

Cortex XDR is deployed in the enterprise and you notice a cobalt strike attack via an ongoing supply chain compromise was prevented on 1 server.
What steps can you take to ensure the same protection is extended to all your servers?

- A. Enable DLL Protection on all servers but there might be some false positives.
- B. Conduct a thorough Endpoint Malware scan.
- C. Create IOCs of the malicious files you have found to prevent their execution.
- D. Enable Behavioral Threat Protection (BTP) with cytool to prevent the attack from spreading.

**```Correct Answer: D```**

### 81

Why would one threaten to encrypt a hypervisor or, potentially, a multiple number of virtual machines running on a server?

- A. To extort a payment from a victim or potentially embarrass the owners.
- B. To gain notoriety and potentially a consulting position.
- C. To better understand the underlying virtual infrastructure.
- D. To potentially perform a Distributed Denial of Attack.

**```Correct Answer: A```**

### 82

What types of actions you can execute with live terminal session?

- A. Manage Processes, Manage Files, Run Operating System Commands, Run Python Commands and Scripts
- B. Manage Network configurations, Quarantine Files, Run Powershell scripts
- C. Apply patches, Reboot System, Send notification for end user, Run Python Commands and Scripts
- D. Manage Processes, Manage Files, Run Operating System Commands, Run Ruby Commands and Scripts

**```Correct Answer: A```**

### 83

How can you pivot within a row to Causality view and Timeline views for further investigate?

- A. Using the Open Card Only
- B. Using Open Timeline actions Only
- C. Using the Open Card and Open Timeline actions respectively
- D. You can't pivot within a row to Causality view and Timeline views

**```Correct Answer: C```**

### 84

What motivation do ransomware attackers have for returning access to systems once their victims have paid?

- A. Failure to restore access to systems undermines the scheme because others will not believe their valuables would be returned.
- B. The ransomware attackers hope to trace the financial trail back and steal more from traditional banking institutions.
- C. There is organized crime governance among attackers that requires the return of access to remain in good standing.
- D. Nation-states enforce the return of system access through the use of laws and regulation.

**```Correct Answer: A```**

### 85

What is the WildFire analysis file size limit for Windows PE files?

- A. 500MB
- B. 100MB
- C. 1GB
- D. No Limit

**```Correct Answer: B```**

### 86

Which Exploit Prevention Module (EPM) provides better entropy for randomization of memory locations?

- A. UASLR
- B. JIT Mitigation
- C. Memory Limit Heap spray check
- D. DLL Security

**```Correct Answer: A```**

### 87

To stop a network-based attack, any interference with a portion of the attack pattern is enough to prevent it from succeeding. Which statement is
correct regarding the Cortex XDR Analytics module?

- A. It interferes with the pattern as soon as it is observed on the endpoint.
- B. It does not interfere with any portion of the pattern on the endpoint.
- C. It does not need to interfere with the any portion of the pattern to prevent the attack.
- D. It interferes with the pattern as soon as it is observed by the firewall.

**```Correct Answer: B```**

### 88

The Cortex XDR console has triggered an incident, blocking a vitally important piece of software in your organization that is known to be benign.
Which of the following options would prevent Cortex XDR from blocking this software in the future, for all endpoints in your organization?

- A. Create an endpoint-specific exception.
- B. Create a global inclusion.
- C. Create an individual alert exclusion.
- D. Create a global exception.

**```Correct Answer: D```**

### 89

What kind of malware uses encryption, data theft, denial of service, and possibly harassment to take advantage of a victim?

- A. Rootkit
- B. Keylogger
- C. Ransomware
- D. Worm

**```Correct Answer: C```**

### 90

As a Malware Analyst working with Cortex XDR you notice an alert suggesting that there was a prevented attempt to open a malicious Word
document. You learn from the WildFire report and AutoFocus that this document is known to have been used in Phishing campaigns since 2018.
What steps can you take to ensure that the same document is not opened by other users in your organization protected by the Cortex XDR agent?

- A. Enable DLL Protection on all endpoints but there might be some false positives.
- B. No step is required because Cortex shares IOCs with our fellow Cyber Threat Alliance members.
- C. No step is required because the malicious document is already stopped.
- D. Install latest content updates to recognize and prevent the activity.

**```Correct Answer: D```**

### 91

Can you disable the ability to use the Live Terminal feature in Cortex XDR?

- A. Yes, via Agent Settings Profile.
- B. No, it is a required feature of the agent.
- C. No, a separate installer package without Live Terminal is required.
- D. Yes, via the Cortex XDR console or with an installation switch.

**```Correct Answer: D```**
