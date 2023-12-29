# PSE-Cortex

## Refer

> <https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Overview>

---

## **RUSH**

### 1

A Cortex XSOAR customer wants to ingest from a single mailbox. The mailbox brings in reported phishing emails and email requests from human resources (HR) to onboard new users. The customer wants to run two separate workflows from this mailbox, one for phishing and one for onboarding.

What will allow Cortex XSOAR to accomplish this in the most efficient way?

- a. Usee machine learning (ML) to determine incident type
- b. Create two instances of the email integration and classily one instance as ingesting incidents of type phishing and the other as ingesting incidents of type boarding
- c. Use an incident classifier based on field in each type of email to classify those containing "Phish Alert" in the subject as phishing and those containing “Onboard Request” as onboarding
- d. Create a playbook to process and determine incident type based on content of the email

**```Correct Answer: C```**

### 2

What allows the use of predetermined Palo Alto Networks roles to assign access rights to Cortex XDR users?

- a. Restrictions security profile
- b. Cloud identity engine (CIE)
- c. Endpoint groups
- d. role-based access control (RBAC)

**```Correct Answer: D```**

### 3

What integration allows searching and displaying Splunk results within Cortex XSOAR?

- a. Demisto App for Splunk integration
- b. SplunkPY integration
- c. Splunk integration
- d. XSOAR REST API integration

**```Correct Answer: B```**

### 4

How can Cortex XSOAR save time when a phishing incident occurs?

- a. It can automatically identify every mailbox that received the phish and create corresponding cases for them
- b. It can automatically email staff to warn them about the phishing attack and show them a copy of the email
- c. It can automatically purge the email from user mailboxes in which it has not yet opened
- d. It can automatically respond to the phishing email to unsubscribe from future emails

**```Correct Answer: A```**

### 5

Which two types of Indicators of compromise (IOCs) are available for creation in Cortex XDR?

- a. Internet Protocol (IP)
- b. Endport hostname
- c. registry entry
- d. domain

**```Correct Answer: A D```**

### 6

Which command is used to add Cortex XSOAR “User1” to an investigation from the War Room?

- a. #Invite User1
- b. @User1
- c. #User1
- d. !Invite User1

**```Correct Answer: B```**

### 7

Which component displays an entire picture of an attack, including the root cause or delivery point?

- a. Cortex XSOAR Work Plan
- b. Cortex Data Lake
- c. Cortex XDR Causality View
- d. Cortex SOC Orchestrator

**```Correct Answer: C```**

### 8

Which two items are stitched to the Cortex XDR causality chain? (Choose two.)

- a. registry set value
- b. firewall alerts
- c. security and information event management (SIEM)
- d. full uniform resource locator (URL)

**```Correct Answer: B D```**

### 9 X

A customer wants the main Cortex XSOAR server installed in one site and wants to integrate with three other technologies in a second site

What communications are required between the two sites if the customer wants to install a Cortex XSOAR engine in the second site?

- a. The Cortex XSOAR server at the first site must be able to initiate a connection to the Cortex XSOAR engine at the second site
- b. All connectivity is initiated from the Cortex XSOAR server on the first site via a managed cloud proxy
- c. Dedicated site-to-site virtual private network (VPN) is required for the Cortex XSOAR server at the first site to initiate a connection to the Cortex XSOAR engine at the second site
- d. The Cortex XSOAR engine at the first site must be able to initiate a connection to the Cortex XSOAR server at the second site

### 10

A customer agrees to do a 30-day proof of concept (POC) and wants to integrate with a product with which Cortex XSOAR is not currently integrated.

What is the appropriate response to the customer?

- a. Extend the POC window to allow the solution architects to build it
- b. Explain that custom integrations are not included in the POC
- c. Explain that it can be built by Professional Services, but it will take an additional 30 days
- d. Agree to build the integration as part of the POC

**```Correct Answer: B```**

### 11

Which service helps uncover attackers wherever they hide by combining world-class threat hunters with Cortex XDR technology that runs on integrated endpoint, network, and cloud data sources?

- a. Cloud Identity Engine (CIE)
- b. Threat Intelligence Platform (TIP)
- c. Virtual desktop infrastructure (VDI)
- d. Managed Threat Hunting (MTH)

**```Correct Answer: D```**

### 12

What is the result of creating an exception from an exploit security event?

- a. Triggered exploit protection module (EPM) for the host and process involved is disabled
- b. User is exempt from generating events for 24 hours
- c. Process from WildFire analysis is whitelisted
- d. Administrators are exempt from generating alerts for 24 hours

**```Correct Answer: A```**

### 13

Cortex XSOAR has extracted a malicious Internet Protocol (IP) address involved in command-and-control (C2) traffic

What is the best method to block this IP from communicating with endpoints without requiring a configuration change on the firewall?

- a. Have XSOAR automatically add the IP address to a deny rule in the firewall
- b. Have XSOAR automatically add the IP address to a threat intelligence management (TIM) malicious IP list to elevate priority of future alerts
- c. Have XSOAR automatically add the IP address to an external dynamic list (EDL) used by the firewall
- d. Have XSOAR automatically create a NetOps ticket requesting a configuration change to the firewall to block the IP

**```Correct Answer: C```**

### 14

What is the size of the free Cortex Data Lake instance provided to a customer who has activated a TMS tenant, but has not purchased a Cortex Data Lake instance?

- a. 10TB
- b. 1TB
- c. 100 GB
- d. 10GB

**```Correct Answer: B```**

### 15

Cortex XDR external data ingestion processes ingest data from which sources?

- a. Windows event logs only
- b. Windows event logs, syslogs, and custom external sources
- c. Windows event logs and syslogs only
- d. Syslogs only

**```Correct Answer: B```**

### 16 X

Which process is the causality chain does the Cortex XDR agent identify as triggering an event sequence?

- a. Adversary’s remote process
- b. Chain’s alert initiator
- c. Causality group owner
- d. Relevant shell

```text
Chain’s alert initiator (链的警报启动器)：
这个选项指的是在一系列事件中，最初触发警报的那个事件或进程。简单地说，就是事件链的开始。
如果你把事件链想象成一个连锁反应，那么“Chain’s alert initiator”就是这一连锁反应的第一个环节。
在故障排查或安全事件响应中，知道哪个事件最先触发可以帮助分析人员更快地找到问题的根源。

Causality group owner (因果关系组的所有者)：
这个选项可能意味着在一个有因果关系的事件组中，有一个“主要”的或“中心”的事件或进程。这个“所有者”进程可能与其他事件有直接或间接的关系。
但是，此选项并不明确指出这个“所有者”是事件链的起点。它更像是描述了这个进程在事件组中的中心地位，但不一定是第一个触发的。
在某些情况下，知道因果关系组的所有者可以帮助分析人员确定哪个进程是最关键的，但这并不等同于知道哪个进程首先触发了警报。

从描述来看，Chain’s alert initiator 更可能是 Cortex XDR agent 识别的触发事件序列的进程，因为它明确指出了该进程是警报的起始点。而 Causality group owner 描述的是一个进程在事件组中的重要性或中心地位，但没有明确说明它是触发事件的起点。
```

### 17

How do sub-playbooks affect the incident Context Data?

- a. When set to global, sub-playbook tasks do not have access to the root context
- b. When set to private, task outputs do not automatically get written to the root context
- c. When set to global, parallel task execution is allowed
- d. When set to private, task outputs are automatically written to the root context

**```Correct Answer: B```**

### 18

An adversary attempts to communicate with malware running on a network in order to control malware activities or to exfiltrate data from the network

What Cortex XDR Analytics alert will this activity most likely trigger?

- a. Uncommon local scheduled task creation
- b. Malware
- c. New administrative behavior
- d. DNS Tunneling

**```Correct Answer: D```**

### 19

Which two types of indicators of compromise (IOCs) are available for creation in Cortex XDR?

- a. Registry b. Hostname
- a. Malware
- b. Exploit
- c. Ransomware d. phishing

**```Correct Answer: C D```**

### 20

Which attack method is a result of techniques designed to gain access through vulnerabilities in the code of an operating system (OS) or application?

- a. Malware
- b. Exploit
- c. Ransomware
- d. phishing

**```Correct Answer: B```**

### 21

What is a benefit of user entity behavior analytics (UEBA) over security information and event management (SIEM)?

- a. UEBA can add trusted signers of Windows or Mac processes to a whitelist in the Endpoint Security Manager (ESM) Console
- b. UEBA establishes a secure connection in which endpoints can be routed, and it collects and forwards logs and files for analysis
- c. SIEMs have difficulty detecting unknown or advanced security threats that do not involve malware, such as credential theft
- d. SIEMs supports only agentless scanning, not agent-based workload protection across VMs, containers, Kubernetes.

**```Correct Answer: C```**

### 22

Which statement applies to a Cortex XSOAR engine that is part of a load-balancing group?

- a. It does not appear in the engine drop-down menu when configuring an integration instance
- b. It must be in a load-balancing group with at least three additional members
- c. It can be used separately as an engine only if directly connected to the XSOAR server
- d. It must have port 443 open to allow the XSOAR server to establish a connection

**```Correct Answer: A```**

### 23

Which step is required to prepare the virtual desktop infrastructure (VDI) golden image?

- a. Run the VDI conversion tool
- b. Ensure the latest content updates are installed
- c. Set the memory dumps to manual setting
- d. Review any portable executable (PE) files WildFire determined to be malicious

**```Correct Answer: D```**

### 24

Which integration allows data to be pushed from Cortex XSOAR into Splunk?

- a. SplunkUpdate integration
- b. Demisto App for Splunk integration
- c. SplunkPY integration
- d. ArcSight ESM integration

**```Correct Answer: C```**

### 25

A Cortex XDR Pro administrator is alerted to a suspicious process creation security event from multiple users who believe these events are false positives

Which two steps should be taken confirm the false positives and create an exception? (Choose two)

- a. In the Cortex XDR security event, review the specific parent process, child process, and command line arguments
- b. Contact support and ask for a security exception
- c. Within the Malware Security profile, add the specific parent process, child process, and command line argument to the child process whitelist
- d. Within the Malware Security profile, disable the Prevent Malicious Child Process Execution module

**```Correct Answer: B C```**

### 26

The Cortex XDR management service requires which other Palo Alto Networks product?

- a. Cortex Data Lake
- b. Directory Sync
- c. Panorama
- d. Cortex XSOAR

**```Correct Answer: A```**

### 27

Which Cortex XDR agent capability prevents loading malicious files from USB-connected removable equipment?

- a. Device control
- b. Agent management
- c. Agent configuration
- d. Device customization

**```Correct Answer: A```**

### 28 X

Which task setting allows context output to a specific key?

- a. Extend context
- b. Task output
- c. Stop on errors
- d. tags

### 29 X

Which two methods does the Cortex XDR agent use to identify malware during a scheduled scan? (Choose two)

- a. WildFire hash comparison
- b. Signature comparison
- c. Dynamic analysis
- d. Heuristic analysis

```text
- a. WildFire hash comparison (WildFire哈希比较)：
这个选项指的是Cortex XDR代理会将文件的哈希值与Palo Alto Networks的WildFire数据库中已知的恶意文件哈希进行比较。如果发现匹配，那么该文件将被标记为恶意的。这种方法主要依赖于已知的威胁数据库。
- b. Signature comparison (签名比较)：
签名比较是传统的恶意软件检测方法。恶意软件通常有特定的“签名”或模式，这些模式可以被捕获并存储在数据库中。通过将文件与这些已知的签名进行比较，可以确定文件是否恶意。这种方法高效地检测已知的恶意软件，但可能无法检测到新型或修改过的恶意软件。
- c. Dynamic analysis (动态分析)：
动态分析通常涉及在受控环境（如沙盒）中运行并观察可疑文件的行为，以确定其是否恶意。这种方法可以用于识别新型或修改过的恶意软件，因为它不仅仅基于已知的签名。但在预定扫描中，Cortex XDR代理本身不会在终端上运行动态分析。
- d. Heuristic analysis (启发式分析)：
启发式分析涉及到检查文件的特性和行为来识别以前未知的威胁或已知威胁的新变种。它不是基于固定的签名，而是基于文件的行为和其他特征来判断。这种方法可以帮助检测那些尚未被列入签名数据库的新型或变种恶意软件。
综上所述，Cortex XDR代理在进行预定扫描时最可能使用的两种方法是：a. WildFire哈希比较 和 b. 签名比较。
```

### 30

What are two capabilities of a War Room? (Choose two)

- a. Run ad-hoc automation commands
- b. Create widgets for an investigation
- c. Act as an audit trail for an investigation
- d. Create playbooks for orchestration

**```Correct Answer: A C```**

### 31

Which two Cortex XSOAR incident type features can be customized under Settings > Advanced > Incident Types? (Choose two)

- a. Setting reminders for an incident service level agreement (SLA)
- b. Defining whether a playbook runs automatically when an incident type is encountered
- c. Adding new fields to an incident type
- d. Dropping new incidents of the same type that contain similar information

**```Correct Answer: A B```**

### 32

Which two areas of Cortex XDR are used for threat hunting activities? (Choose two)

- a. Host insights module
- b. Indicators of compromise (IOC) rules
- c. Live terminal
- d. Query builder

**```Correct Answer: A D```**

### 33

Which two entities can be created as a behavioral indicator of compromise (BIOC)? (Choose two)

- a. Network
- b. Event alert
- c. Data
- d. process

**```Correct Answer: A D```**

### 34

Which statement applies to the malware protection flow in Cortex XDR Prevent?

- a. Hash comparisons come after local static analysis
- b. In the final step, the block list is verified
- c. Local static analysis happens before a WildFire verdict check
- d. A trusted signed file is exempt from local static analysis

**```Correct Answer: D```**

### 35 X

Which action allows Cortex XSOAR to access Docker in an air-gapped environment where the Docker page was manually installed after the Cortex XSOAR installation?

- a. Enable the Docker service
- b. Disable the Cortex XSOAR service
- c. Create a “docker” group and add the “Cortex XSOAR” or “demisto” user to this group
- d. Create a “Cortex XSOAR” or “demisto” group and add the “docker” user to this group

```text
- c. 创建一个“docker”组，并将“Cortex XSOAR”或“demisto”用户添加到这个组中
这个选项意味着我们在操作系统中创建一个名为"docker"的用户组，然后将运行Cortex XSOAR的用户（可能是"Cortex XSOAR"或"demisto"）添加到这个组中。在大多数Linux系统中，安装Docker时通常会自动创建一个名为"docker"的组。该组的成员具有与Docker daemon互动的权限。因此，将Cortex XSOAR或demisto用户添加到这个组意味着我们正在授予这个用户与Docker daemon互动的权限。

- d. 创建一个“Cortex XSOAR”或“demisto”组，并将“docker”用户添加到这个组中
这个选项建议我们创建一个以Cortex XSOAR或demisto命名的用户组，然后将docker用户添加到这个新创建的组中。这在逻辑上是没有意义的，因为Docker daemon通常作为root用户运行，并不需要被添加到任何特定的用户组中。此外，这种方式并不提供Cortex XSOAR访问Docker的权限。

简而言之，c和d的主要区别在于我们为哪个用户和哪个组授予访问权限。正确的做法是确保运行Cortex XSOAR的用户能够访问Docker，而这可以通过将其添加到"docker"组来实现。这就是为什么选项c是正确的。
```

### 36 X

What does the Cortex XSOAR “Saved by Dbot” widget calculate?

- a. Amount saved in Dollars by using Cortex XSOAR instead of other products
- b. Amount of time saved by each playbook task within an incident
- c. Amount of time saved by Dbot’s machine learning (ML) capabilities
- d. Amount saved in Dollars according to actions carried out by all users in Cortex XSOAR across all incidents

### 37 X

On a multi-tenanted v6.2 Cortex XSOAR server, which path leads to the server log for “Tenant1”?

- a. /var/lib/demisto/acc_Tenant1/server.log
- b. /var/log/demisto/Tenant1/server.log
- c. /var/log/demisto/acc_Tenant1/server.log
- d. /var/lib/demisto/server.log

### 38

What is a benefit offered by Cortex XSOAR?

- a. It enables an end-to-end view of everything in the customer environment that affects digital employee productivity
- b. It provides holistic protection across hosts and containers throughout the application lifecycle
- c. It has the ability to customize the extensible platform to scale to business needs
- d. It allows the consolidation of multiple point products into a single integrated service

**```Correct Answer: D```**

### 39

Why is reputation scoring important in the Threat Intelligence Module of Cortex XSOAR?

- a. It helps identify threat intelligence vendors with substandard content
- b. It provides a mathematical model for combining scores from multiple vendors
- c. It allows for easy comparison between open-source intelligence and paid services
- d. It deconflicts prioritization when two vendors give different scores for the same indicator

**```Correct Answer: B```**

### 40

Which solution profiles network behavior metadata, not playloads and files, allowing effective operation regardless of encrypted or unencrypted communication protocols, like HTTPS?

- a. Endpoint detection and response (EDR)
- b. Security Information and Event Management (SIEM)
- c. Endpoint protection platform (EPP)
- d. Network Detection and Response (NDR)

**```Correct Answer: D```**

### 41

Which method is used for third-party network data consumption?

- a. File reader to the /var/log/messagers file on the device
- b. Open Database Connectivity (OOBC) connection to network device database
- c. Common Event Format (CEF) via broker Syslog module
- d. Scripts library from the action center

**```Correct Answer: C```**

### 42 X

Which two playbook functionalities allow looping through a group of tasks during playbook execution? (Choose two)

- a. Sub-playbooks
- b. Playbook functions
- c. CommonPolling Playbooks
- d. Playbook tasks

### 44

Which playbook feature allows concurrent execution of tasks?

- a. Automation tasks
- b. Parallel tasks
- c. Manual tasks
- d. Conditional tasks

**```Correct Answer: A```**

### 45

Which Cortex XDR license is required for a customer that requests endpoint detection and response (EDR) data collection capabilities?

- a. Cortex XDR Prevent
- b. Cortex XDR Pro Per Endpoint
- c. Cortex XDR Endpoint
- d. Cortex XDR Pro per TB

**```Correct Answer: B```**

### 46

Where can all the relevant incidents for an indicator be viewed?

- a. Linked indicators column in incident screen
- b. Linked incidents column in indicator screen
- c. Related incidents column in indicator screen
- d. Related indicators column in incident screen

**```Correct Answer: C```**

### 47

Which type of log is ingested natively in Cortex XDR Pro per TB?

- a. Docker
- b. Microsoft Office 365
- c. Demisto
- d. Google Kubernetes Engine

**```Correct Answer: D```**

### 48

Which two manual actions are allowed on War Room entries? (Choose two)

- a. Mark as scheduled entry
- b. Mark as note
- c. Mark as artifact
- d. Mark as evidence

**```Correct Answer: B D```**

### 49

What are two reasons incident investigation is needed in Cortex XDR? (Choose two)

- a. Insider Threats may not be blocked and initial activity may go undetected
- b. Detailed reports are needed for senior management to justify the cost of XDR agent
- C. No solution will stop every attack requiring further investigation of activity
- d. Analyst need to acquire forensic artifacts of malware that has been blocked by the XDR agent

**```Correct Answer: C D```**

### 50

Which command-line interface (CLI) query would retrieve the last three Splunk events?

- a. !query using=splunk_instance_1 query=”* | last 3”
- b. !search using=splunk_instance_1 query=”* | head 3”
- c. !search using=splunk_instance_1 query=”* | last 3”
- d. !search using=splunk_instance_1 query=”* | 3”

**```Correct Answer: C```**

### 51

Which playbook functionality allows grouping of tasks to create functional building blocks?

- a. Sub-playbook
- b. Playbook features
- c. Manual tasks
- d. Conditional tasks

**```Correct Answer: A```**

### 52

Which two filter operators are available in Cortex XDR? (Choose two)

- a. =
- b. Contains
- c. Is Contained By
- d. <>

**```Correct Answer: A B```**

### 53

Which product enables the discovery, exchange, and contribution of security automation playbooks, built into Cortex XSOAR?

- a. XSOAR Marketplace
- b. XSOAR Threat Intelligence Platform (TIP)
- c. XSOAR Automated Systems
- d. XSOAR Ticketing Systems

**```Correct Answer: A```**

### 54

A Cortex XSOAR customer wants to send a survey to users asking them to input their manager’s email for a training use case so the manager can receive status reports on the employee’s training. However, the customer is concerned users will provide incorrect information to avoid sending status updates to their manager

How can Cortex XSOAR most efficiently sanitize user input prior to using the responses in the playbook?

- a. Create a task that sends the survey responses to the analyst via email. If the responses are incorrect, the analyst fills out the correct response in the survey
- b. Create a task that sends the survey responses to the analyst via email. If the responses are incorrect, the analyst fills out the correct response in the survey
- c. Create a sub-playbook and import a list of manager emails into XSOAR. Use a conditional task comparison to check if the response matches an email on the list. If no matches are found, loop the sub-playbook and send the survey back to the user until a match is found
- d. Create a conditional task comparison to check if the response contains a valid email address

**```Correct Answer: C```**

### 55

When initiated, which Cortex XDR capability allows immediate termination of the process or whole process tree on an anomalous process discovered during investigation of a security event?

- a. Live sensors
- b. File explorer
- c. Live terminal
- d. Log stitching

**```Correct Answer: C```**

### 56

Which statement applies to the differentiation of Cortex XDR from security information and event management (SIEM)?

- a. SIEM has been entirely designed and built as cloud-native, with the ability to stitch together cloud logs, on-premises logs, third-party logs, and endpoint logs
- b. Cortex XDR allows just logging into the console and out of the box the events were blocked as a proactive approach
- c. Cortex XDR requires a large and diverse team of analysts and up to several weeks for simple actions like creating an alert
- d. SIEM has access to raw logs from agents, where Cortex XDR traditionally only gets alerts

**```Correct Answer: B```**

### 57

What is used to display only file entries in a War Room?

- a. ;files from War Room CLI
- b. !files from War Room CLI
- c. Files and attachments filters
- d. Incident files section in layout builder

**```Correct Answer: C```**

## 考前忠告

1. 太绝对的词大概率错误的，例如**must/only**
2. 选跟题干**关键词**相关度高的
